// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Authority gateway engine: the two-phase enforcement boundary shared by the
// payment-authority and document-authority examples. Everything specific to one kind of
// action is behind ActionProfile. This is reference code for the examples, in one process
// with in-memory state, not a hosted service and not part of the SDK's public API.
//
// authorize(), synchronous, for every request:
//   1. recompute the action reference from the submitted request and payload
//   2. check the acting agent signed an aps:action-intent:v1 record for that action
//   3. one nonce gets one decision, and the request must fall inside the replay window
//   4. verify the whole delegation chain (signatures, narrowing, time, revocation)
//   5. the profile validates the payload and computes the target and the scope, and the
//      leaf delegation must cover that scope
//   6. the profile's own gateway-side check (for documents: the repository still holds
//      the exact bytes named in the request)
//   7. when the profile charges a budget, reserve it against every bounded delegation
//   8. sign an aps:policy-decision:v1 record, permit or deny
//
// dispatch(), once per permitted action:
//   9. consume the approval
//  10. recheck valid_until, the stored request, the chain and the profile check. If any
//      fails, sign a failed aps:action-result:v1 record and call nothing.
//  11. otherwise call the profile's executor and sign an aps:action-result:v1 record

import { createHash } from 'node:crypto'
import {
  InMemoryAuthorityBudgetLedger,
  InMemoryAuthorityRevocationStore,
  buildDecisionRefV1,
  canonicalizeJCS,
  computeActionRefV2,
  computePayloadRefV1,
  createAuthorityRevocationResolver,
  createReceiptV1,
  recordAuthorityRevocation,
  scopeGrantCovers,
  verifyAuthorityDelegationChain,
  verifyReceiptV1,
} from 'agent-passport-system'
import type {
  ActionReferenceInputV2,
  AuthorityDelegationV1,
  CoreDecisionOutputV1,
  ReceiptV1,
} from 'agent-passport-system'

export const DECISION_TTL_MS = 60_000
export const REPLAY_WINDOW_MS = 5 * 60_000
export const FUTURE_SKEW_MS = 30_000

export const sha256Hex = (s: string): string => createHash('sha256').update(s, 'utf8').digest('hex')

export type Json = string | number | boolean | null | Json[] | { [key: string]: Json }

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value)
    for (const v of Object.values(value as object)) deepFreeze(v)
  }
  return value
}

export type ExecutorResult =
  | { status: 'succeeded'; effect_id: string }
  | { status: 'failed'; error_code: string }

/** Everything that differs between one kind of action and another. */
export interface ActionProfile<P> {
  /** Recorded as policy_input.profile in every decision. */
  id: string
  actionType: string
  /** null when the payload is well formed, otherwise the refusal reason. */
  validate(payload: unknown): string | null
  target(p: P): string
  /** The one scope grant this action requires. */
  scope(p: P): string
  /** Refusal reason when the leaf delegation does not cover the scope. Default
   *  "not_in_delegated_scope". */
  scopeDenyReason?: string
  /** Refusal reason when the leaf's spend unit differs from the charge's. Default
   *  "unit_not_delegated". */
  unitDenyReason?: string
  /** Gateway-side check run at authorize and again at admission. null when it passes. */
  check?(p: P): string | null
  /** Budget charge, or null for an action that spends nothing. */
  charge?(p: P): { unit: string; amount: string } | null
  /** Policy facts recorded in the decision, without the profile id. */
  policyInput(p: P): { [key: string]: Json }
  /** Policy facts recorded when the payload failed validate(). Default: the payload
   *  reference only. */
  policyInputUnvalidated?(payload: unknown, payloadRef: string): { [key: string]: Json }
  /** The external system. Throwing means the outcome is unknown. */
  execute(call: { action_ref: string; payload: P }): Promise<ExecutorResult>
}

export interface Submission<P> {
  input: ActionReferenceInputV2
  payload: P
  intent: ReceiptV1
  chain: AuthorityDelegationV1[]
}

export interface DecisionEvidence {
  authority_state: { chain: string[]; counters: Record<string, { reserved: string; committed: string }> }
  policy_input: { [key: string]: Json }
  decision_context: { gateway: string; decided_at: string; reason: string }
  decision_output: CoreDecisionOutputV1
}

export interface Outcome {
  verdict: 'permit' | 'deny'
  reason: string
  action_ref: string | null
  decision?: ReceiptV1
  evidence?: DecisionEvidence
  result?: ReceiptV1
  dispatched?: boolean
  replay?: boolean
  /** The external system's own identifier for what it did, when it reported success.
   *  Unsigned here. The result record signs its SHA-256 as effect_ref. */
  effect_id?: string
}

export interface GatewayOptions {
  id: string
  /** The gateway's current signing key. Read at every signature, so it can rotate. */
  signingKey: () => { keyId: string; privateKey: string }
  resolveReceiptKey: (signer: string, keyId: string, issuedAt: string) => string | undefined
  resolveVerificationKey: (issuer: string, verificationMethod: string, issuedAt: string) => string | null
  trustRoot: (root: AuthorityDelegationV1) => boolean
  now: () => string
}

interface Authorized<P> {
  sub: Submission<P>
  permit: Outcome
  reserved: boolean
}

export class AuthorityGateway<P> {
  readonly id: string
  private readonly profile: ActionProfile<P>
  private readonly opts: GatewayOptions
  private readonly ledger = new InMemoryAuthorityBudgetLedger()
  private readonly revocations = new InMemoryAuthorityRevocationStore()
  private readonly resolveRevocation
  private readonly decided = new Map<string, { actionRef: string; outcome: Outcome }>()
  private readonly authorized = new Map<string, Authorized<P>>()
  private readonly finals = new Map<string, Promise<Outcome>>()

  constructor(profile: ActionProfile<P>, opts: GatewayOptions) {
    this.id = opts.id
    this.profile = profile
    this.opts = opts
    this.resolveRevocation = createAuthorityRevocationResolver(this.revocations, {
      resolveVerificationKey: opts.resolveVerificationKey,
    })
  }

  /** Delegations whose revocation status this gateway answers for. Anything not enrolled
   *  resolves as revocation-unknown and is refused. */
  enroll(chain: readonly AuthorityDelegationV1[]): void {
    for (const d of chain) this.revocations.track(d.delegation_id)
  }

  /** Limit, reserved and committed budget for one bounded delegation. */
  budget(delegation: AuthorityDelegationV1): { limit: string; reserved: string; committed: string } | null {
    const spend = delegation.authority.spend
    if (spend.mode !== 'bounded') return null
    return { limit: spend.cumulative, ...this.ledger.counter(delegation.delegation_id) }
  }

  revoke(target: AuthorityDelegationV1, revocation: unknown): { recorded: boolean; reason?: string } {
    const r = recordAuthorityRevocation(this.revocations, target, revocation, {
      resolveVerificationKey: this.opts.resolveVerificationKey,
    })
    return r.recorded ? { recorded: true } : { recorded: false, reason: r.verification.failures.map(f => f.code).join(',') }
  }

  /** Authorize and, on permit, dispatch. */
  async request(sub: Submission<P>): Promise<Outcome> {
    const a = this.authorize(sub)
    if (a.verdict !== 'permit' || a.action_ref === null) return a
    if (a.replay) return this.dispatch(a.action_ref).then(o => ({ ...o, replay: true }))
    return this.dispatch(a.action_ref)
  }

  authorize(submitted: Submission<P>): Outcome {
    const now = this.opts.now()
    let sub: Submission<P>
    try {
      sub = deepFreeze(structuredClone(submitted))
    } catch {
      return { verdict: 'deny', reason: 'submission_not_plain_data', action_ref: null }
    }
    const deny = (reason: string, actionRef: string | null = null): Outcome => ({ verdict: 'deny', reason, action_ref: actionRef })

    let actionRef: string
    try {
      if (computePayloadRefV1(sub.payload as never) !== sub.input.payload_ref) return deny('payload_ref_mismatch')
      actionRef = computeActionRefV2(sub.input)
    } catch {
      return deny('action_ref_input_invalid')
    }

    const iv = verifyReceiptV1(sub.intent, this.opts.resolveReceiptKey, { expectedReceiptType: 'aps:action-intent:v1' })
    if (iv.status !== 'valid') return deny(`intent_${iv.status}`, actionRef)
    if (sub.intent.action_ref !== actionRef) return deny('intent_action_ref_mismatch', actionRef)
    if (sub.intent.issuer !== sub.input.agent_id || sub.intent.subject_agent !== sub.input.agent_id) {
      return deny('intent_not_from_agent', actionRef)
    }

    const nonceKey = `${sub.input.agent_id}\u0000${sub.input.nonce}`
    const earlier = this.decided.get(nonceKey)
    if (earlier) {
      if (earlier.actionRef === actionRef) return { ...earlier.outcome, replay: true }
      return this.decide(sub, actionRef, now, 'deny', 'nonce_reused')
    }
    const { outcome, reserved } = this.evaluate(sub, actionRef, now)
    this.decided.set(nonceKey, { actionRef, outcome })
    if (outcome.verdict === 'permit') this.authorized.set(actionRef, { sub, permit: outcome, reserved })
    return outcome
  }

  dispatch(actionRef: string): Promise<Outcome> {
    const final = this.finals.get(actionRef)
    if (final) return final.then(o => ({ ...o, replay: true }))
    const entry = this.authorized.get(actionRef)
    if (!entry) return Promise.resolve({ verdict: 'deny', reason: 'not_authorized', action_ref: actionRef })
    this.authorized.delete(actionRef)
    const done = this.admitAndExecute(entry)
    this.finals.set(actionRef, done)
    return done
  }

  private evaluate(sub: Submission<P>, actionRef: string, now: string): { outcome: Outcome; reserved: boolean } {
    const signedDeny = (reason: string) => ({ outcome: this.decide(sub, actionRef, now, 'deny', reason), reserved: false })

    const issued = Date.parse(sub.input.issued_at)
    const at = Date.parse(now)
    if (!(issued >= at - REPLAY_WINDOW_MS && issued <= at + FUTURE_SKEW_MS)) return signedDeny('intent_outside_replay_window')

    const chain = sub.chain
    const leaf = Array.isArray(chain) ? chain.at(-1) : undefined
    if (!leaf) return signedDeny('chain_missing')
    if (leaf.subject !== sub.input.agent_id) return signedDeny('chain_leaf_not_agent')
    if (sub.intent.delegation_ref !== leaf.delegation_id) return signedDeny('intent_delegation_ref_mismatch')
    const authority = this.checkChain(chain, now)
    if (authority) return signedDeny(authority)

    const invalid = this.profile.validate(sub.payload)
    if (invalid) return signedDeny(invalid)
    const p = sub.payload
    if (sub.input.action_type !== this.profile.actionType || sub.input.target !== this.profile.target(p)) {
      return signedDeny('target_mismatch')
    }
    const scope = this.profile.scope(p)
    if (sub.input.scope_required.length !== 1 || sub.input.scope_required[0] !== scope) return signedDeny('scope_required_mismatch')
    if (!leaf.authority.scope.grants.some(g => scopeGrantCovers(g, scope))) {
      return signedDeny(this.profile.scopeDenyReason ?? 'not_in_delegated_scope')
    }

    const checked = this.profile.check?.(p) ?? null
    if (checked) return signedDeny(checked)

    const charge = this.profile.charge?.(p) ?? null
    if (charge) {
      const spend = leaf.authority.spend
      if (spend.mode !== 'bounded') return signedDeny('spend_unbounded_refused')
      if (spend.unit !== charge.unit) return signedDeny(this.profile.unitDenyReason ?? 'unit_not_delegated')
      const r = this.ledger.reserve(chain, actionRef, charge.unit, charge.amount)
      if (!r.ok || r.code !== 'RESERVED') return signedDeny(`budget_${r.code.toLowerCase()}`)
    }
    return { outcome: this.decide(sub, actionRef, now, 'permit', 'within_delegated_authority'), reserved: charge !== null }
  }

  private bindsTo(sub: Submission<P>, actionRef: string): boolean {
    try {
      return computePayloadRefV1(sub.payload as never) === sub.input.payload_ref && computeActionRefV2(sub.input) === actionRef
    } catch {
      return false
    }
  }

  private checkChain(chain: AuthorityDelegationV1[], at: string): string | null {
    const av = verifyAuthorityDelegationChain(chain, {
      now: at,
      resolveVerificationKey: this.opts.resolveVerificationKey,
      trustRoot: this.opts.trustRoot,
      resolveRevocation: this.resolveRevocation,
    })
    if (av.state === 'valid') return null
    return `authority_${av.state}:${[...new Set(av.failures.map(f => f.code))].join(',')}`
  }

  private sign(body: Parameters<typeof createReceiptV1>[0]): ReceiptV1 {
    const k = this.opts.signingKey()
    return createReceiptV1(body, [{ signer: this.id, key_id: k.keyId, private_key: k.privateKey }])
  }

  private decide(sub: Submission<P>, actionRef: string, now: string, verdict: 'permit' | 'deny', reason: string): Outcome {
    const chain = Array.isArray(sub.chain) ? sub.chain : []
    const leaf = chain.at(-1)
    const decision_output: CoreDecisionOutputV1 = {
      profile: 'aps-core-decision-output-v1',
      verdict,
      effective_authority_ref: verdict === 'permit' && leaf ? sha256Hex(canonicalizeJCS(leaf.authority)) : null,
      constraints: [],
      valid_until: verdict === 'permit' ? new Date(Date.parse(now) + DECISION_TTL_MS).toISOString() : null,
    }
    const counters: DecisionEvidence['authority_state']['counters'] = {}
    for (const d of chain) {
      if (d?.authority?.spend?.mode === 'bounded') counters[d.delegation_id] = this.ledger.counter(d.delegation_id)
    }
    const policy_input: { [key: string]: Json } = this.profile.validate(sub.payload) === null
      ? { profile: this.profile.id, ...this.profile.policyInput(sub.payload) }
      : { profile: this.profile.id, ...(this.profile.policyInputUnvalidated?.(sub.payload, sub.input.payload_ref) ?? { payload_ref: sub.input.payload_ref }) }
    const evidence: DecisionEvidence = {
      authority_state: { chain: chain.map(d => String(d?.delegation_id)), counters },
      policy_input,
      decision_context: { gateway: this.id, decided_at: now, reason },
      decision_output,
    }
    const { decision_ref } = buildDecisionRefV1({ action_ref: actionRef, ...evidence } as never)
    const decision = this.sign({
      profile: 'aps-receipt-v1', receipt_type: 'aps:policy-decision:v1', issuer: this.id,
      subject_agent: sub.input.agent_id, action_ref: actionRef, delegation_ref: sub.intent.delegation_ref,
      decision_ref, issued_at: now, evidence_refs: [], result: decision_output as never, prev: sub.intent.receipt_id,
    })
    return { verdict, reason, action_ref: actionRef, decision, evidence }
  }

  private async admitAndExecute({ sub, permit, reserved }: Authorized<P>): Promise<Outcome> {
    const actionRef = permit.action_ref!
    const now = this.opts.now()
    const validUntil = Date.parse((permit.decision!.result as { valid_until: string }).valid_until)
    const refusal = !Number.isFinite(validUntil) || Date.parse(now) >= validUntil
      ? 'approval_expired'
      : !this.bindsTo(sub, actionRef)
        ? 'authorized_request_changed'
        : this.checkChain(sub.chain, now) ?? this.profile.check?.(sub.payload) ?? null
    if (refusal) {
      if (reserved) this.ledger.cancel(actionRef)
      return { ...permit, dispatched: false, result: this.result(sub, permit, now, 'failed', `admission_refused:${refusal}`) }
    }

    if (reserved) this.ledger.markDispatched(actionRef)
    let outcome: ExecutorResult | { status: 'unknown' }
    try {
      outcome = await this.profile.execute({ action_ref: actionRef, payload: sub.payload })
    } catch {
      outcome = { status: 'unknown' }
    }
    if (outcome.status === 'succeeded' && reserved) this.ledger.commit(actionRef)
    const at = this.opts.now()
    if (outcome.status === 'succeeded') {
      return { ...permit, dispatched: true, effect_id: outcome.effect_id,
        result: this.result(sub, permit, at, 'succeeded', null, sha256Hex(outcome.effect_id)) }
    }
    const result = outcome.status === 'failed'
      ? this.result(sub, permit, at, 'failed', outcome.error_code)
      : this.result(sub, permit, at, 'unknown', null)
    return { ...permit, dispatched: true, result }
  }

  private result(
    sub: Submission<P>, permit: Outcome, at: string,
    status: 'succeeded' | 'failed' | 'unknown', errorCode: string | null, effectRef: string | null = null,
  ): ReceiptV1 {
    return this.sign({
      profile: 'aps-receipt-v1', receipt_type: 'aps:action-result:v1', issuer: this.id,
      subject_agent: sub.input.agent_id, action_ref: permit.action_ref!, delegation_ref: sub.intent.delegation_ref,
      decision_ref: permit.decision!.decision_ref, issued_at: at, evidence_refs: [],
      result: { profile: 'aps-action-result-v1', status, effect_ref: effectRef, error_code: errorCode } as never,
      prev: permit.decision!.receipt_id,
    })
  }
}
