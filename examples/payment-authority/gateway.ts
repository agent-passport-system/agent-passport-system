// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Payment authority gateway: a reference enforcement boundary for agent payments.
//
// Built only from public agent-passport-system 8.0.1 exports. One process, in-memory
// state, test keys and a mock payment executor. It is a reference example, not a
// hosted service and not a production payment integration.
//
// A payment runs in two phases.
//
// authorize(), synchronous, for every request:
//   1. recompute the action reference from the submitted request and payload
//   2. check the acting agent signed an aps:action-intent:v1 record for that action
//   3. check the agent's nonce: one nonce gets one decision, a nonce reused for a
//      different action is refused, and the request must fall inside the replay window
//   4. verify the whole delegation chain (signatures, narrowing, time, revocation) and
//      refuse anything that is not valid, including indeterminate
//   5. check the merchant is covered by the leaf delegation's scope and the currency
//      matches its spend unit
//   6. reserve the amount against every bounded delegation in the chain at once, so a
//      child's spending also counts against its parent's budget
//   7. sign an aps:policy-decision:v1 record, permit or deny
//
// dispatch(), for a permitted action, once:
//   8. consume the approval, so it can be used once only
//   9. recheck at admission that the approval has not reached valid_until, that the stored
//      request still recomputes to the approved action reference, and that the whole chain
//      is still valid (time and revocation). If any fails, release the reservation and
//      sign a failed aps:action-result:v1 record. Nothing is sent to the executor.
//  10. otherwise mark the reservation dispatched, call the executor, commit on success
//      and sign an aps:action-result:v1 record
//
// pay() runs both phases back to back.
//
// CANDIDATE PROFILE TEXT. draft-pidlisnyi-aps-04 section 5.1 says a profile defines its
// target string. For action_type "payment" this example uses
//   "https://pay.example/merchants/" + merchant + "/charges"
// and the scope grant "commerce:pay:" + merchant. No published profile defines either.

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

export const PAYMENT_ACTION_TYPE = 'payment'
export const paymentTarget = (merchant: string): string => `https://pay.example/merchants/${merchant}/charges`
export const paymentScope = (merchant: string): string => `commerce:pay:${merchant}`
export const spendUnit = (currency: string): string => `iso4217:${currency}:minor`

const CANONICAL_POSITIVE_INTEGER = /^[1-9][0-9]*$/
const MERCHANT = /^[a-z0-9][a-z0-9-]{0,62}$/
const CURRENCY = /^[A-Z]{3}$/
/** How long a permit decision may wait before dispatch. */
export const DECISION_TTL_MS = 60_000
/** A request whose issued_at is older than this, or further ahead than the skew, is refused.
 *  Nonces are remembered for at least this long, so a replay inside the window is caught
 *  by the nonce check and a replay after it by the window check. */
export const REPLAY_WINDOW_MS = 5 * 60_000
export const FUTURE_SKEW_MS = 30_000

const sha256Hex = (s: string): string => createHash('sha256').update(s, 'utf8').digest('hex')

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value)
    for (const v of Object.values(value as object)) deepFreeze(v)
  }
  return value
}

export interface PaymentPayload {
  merchant: string
  /** Amount in minor units (cents for USD) as a canonical decimal string. */
  amount_minor: string
  currency: string
}

export interface PaymentSubmission {
  input: ActionReferenceInputV2
  payload: PaymentPayload
  /** aps:action-intent:v1 signed by the acting agent for this action. */
  intent: ReceiptV1
  /** Delegation chain from the person's root grant to the acting agent. */
  chain: AuthorityDelegationV1[]
}

export type ExecutorResult =
  | { status: 'succeeded'; charge_id: string }
  | { status: 'failed'; error_code: string }

/** The payment rail. This example ships a mock; a real rail goes behind this call. */
export type PaymentExecutor = (charge: {
  action_ref: string
  merchant: string
  amount_minor: string
  currency: string
}) => Promise<ExecutorResult>

/** Everything a third party needs to check one decision, apart from public keys. */
export interface DecisionEvidence {
  authority_state: { chain: string[]; counters: Record<string, { reserved: string; committed: string }> }
  policy_input: { profile: string; merchant: string; amount_minor: string; currency: string; unit: string }
  decision_context: { gateway: string; decided_at: string; reason: string }
  decision_output: CoreDecisionOutputV1
}

export interface PaymentOutcome {
  verdict: 'permit' | 'deny'
  reason: string
  action_ref: string | null
  /** Present for every request bound to a verified agent intent: a signed decision. A
   *  request refused before that point (payload does not match, intent not signed by the
   *  agent) gets no signed record, because there is no verified request to bind one to. */
  decision?: ReceiptV1
  evidence?: DecisionEvidence
  /** Present once dispatch ran: what happened, signed. */
  result?: ReceiptV1
  /** True when the executor was called. */
  dispatched?: boolean
  /** True when this outcome was returned for a request the gateway had already decided.
   *  No second decision was made and no second charge. */
  replay?: boolean
}

export interface GatewayOptions {
  /** The gateway's own identifier, the issuer of its decision and result records. */
  id: string
  keyId: string
  privateKey: string
  /** Receipt signer keys (agents, the gateway). */
  resolveReceiptKey: (signer: string, keyId: string, issuedAt: string) => string | undefined
  /** Delegation and revocation verification-method keys. */
  resolveVerificationKey: (issuer: string, verificationMethod: string, issuedAt: string) => string | null
  /** Which root delegations this gateway accepts, normally the person's own key. */
  trustRoot: (root: AuthorityDelegationV1) => boolean
  executor: PaymentExecutor
  /** Clock, injected so tests are deterministic. Exact UTC milliseconds. */
  now: () => string
  /** Currencies this gateway accepts. */
  currencies?: readonly string[]
}

interface Authorized {
  sub: PaymentSubmission
  permit: PaymentOutcome
}

export class PaymentAuthorityGateway {
  readonly id: string
  private readonly opts: GatewayOptions
  private readonly ledger = new InMemoryAuthorityBudgetLedger()
  private readonly revocations = new InMemoryAuthorityRevocationStore()
  private readonly resolveRevocation
  /** Every decision made for a verified intent, keyed by agent and nonce. One nonce gets
   *  one decision. Entries must outlive REPLAY_WINDOW_MS; this example never prunes. */
  private readonly decided = new Map<string, { actionRef: string; outcome: PaymentOutcome }>()
  /** Permitted actions not yet dispatched. Taking an entry out is consuming the approval. */
  private readonly authorized = new Map<string, Authorized>()
  /** The final outcome of every action that went to dispatch, keyed by action_ref. */
  private readonly finals = new Map<string, Promise<PaymentOutcome>>()

  constructor(opts: GatewayOptions) {
    this.id = opts.id
    this.opts = opts
    this.resolveRevocation = createAuthorityRevocationResolver(this.revocations, {
      resolveVerificationKey: opts.resolveVerificationKey,
    })
  }

  /** Register delegations whose revocation status this gateway answers for. A delegation
   *  the gateway has not enrolled resolves as revocation-unknown and every payment under
   *  it is refused, because the gateway cannot say it was not revoked. */
  enroll(chain: readonly AuthorityDelegationV1[]): void {
    for (const d of chain) this.revocations.track(d.delegation_id)
  }

  /** Accept a signed revocation. Only a record that verifies against the target
   *  delegation's issuer is stored. It takes effect for every later authorization and
   *  for every authorized action not yet dispatched. */
  revoke(target: AuthorityDelegationV1, revocation: unknown): { recorded: boolean; reason?: string } {
    const r = recordAuthorityRevocation(this.revocations, target, revocation, {
      resolveVerificationKey: this.opts.resolveVerificationKey,
    })
    return r.recorded ? { recorded: true } : { recorded: false, reason: r.verification.failures.map(f => f.code).join(',') }
  }

  /** Limit, reserved and committed budget for one delegation, in minor units. */
  budget(delegation: AuthorityDelegationV1): { limit: string; reserved: string; committed: string } | null {
    const spend = delegation.authority.spend
    if (spend.mode !== 'bounded') return null
    return { limit: spend.cumulative, ...this.ledger.counter(delegation.delegation_id) }
  }

  /** Authorize and, on permit, dispatch. */
  async pay(sub: PaymentSubmission): Promise<PaymentOutcome> {
    const a = this.authorize(sub)
    if (a.verdict !== 'permit' || a.action_ref === null) return a
    if (a.replay) {
      // Already decided. If it was dispatched, return that outcome. If it was authorized
      // but not yet dispatched, dispatch() runs it, and only once.
      return this.dispatch(a.action_ref).then(o => ({ ...o, replay: true }))
    }
    return this.dispatch(a.action_ref)
  }

  /**
   * Phase one. Synchronous from start to finish, so two requests running at the same time
   * cannot both pass the budget check against the same remaining amount, and the nonce
   * is recorded before anything else can run.
   */
  authorize(submitted: PaymentSubmission): PaymentOutcome {
    const now = this.opts.now()
    // Every check below, the stored approval and the executor call all read this one deep
    // copy. A caller that changes its own submission object after authorize() returns
    // cannot change what is dispatched.
    let sub: PaymentSubmission
    try {
      sub = deepFreeze(structuredClone(submitted))
    } catch {
      return { verdict: 'deny', reason: 'submission_not_plain_data', action_ref: null }
    }
    const deny = (reason: string, actionRef: string | null = null): PaymentOutcome =>
      ({ verdict: 'deny', reason, action_ref: actionRef })

    // 1. Action reference, recomputed from what was submitted.
    let actionRef: string
    try {
      if (computePayloadRefV1(sub.payload) !== sub.input.payload_ref) return deny('payload_ref_mismatch')
      actionRef = computeActionRefV2(sub.input)
    } catch {
      return deny('action_ref_input_invalid')
    }

    // 2. The acting agent asked for exactly this action.
    const iv = verifyReceiptV1(sub.intent, this.opts.resolveReceiptKey, { expectedReceiptType: 'aps:action-intent:v1' })
    if (iv.status !== 'valid') return deny(`intent_${iv.status}`, actionRef)
    if (sub.intent.action_ref !== actionRef) return deny('intent_action_ref_mismatch', actionRef)
    if (sub.intent.issuer !== sub.input.agent_id || sub.intent.subject_agent !== sub.input.agent_id) {
      return deny('intent_not_from_agent', actionRef)
    }

    // 3. One nonce, one decision. input.nonce and input.issued_at are inside the action
    // reference the agent signed, so they are the agent's own.
    const nonceKey = `${sub.input.agent_id}\u0000${sub.input.nonce}`
    const earlier = this.decided.get(nonceKey)
    if (earlier) {
      if (earlier.actionRef === actionRef) return { ...earlier.outcome, replay: true }
      // A second, different action under a nonce already used. Refused with a signed
      // record, and not remembered, so it cannot displace the first decision.
      return this.decide(sub, actionRef, now, 'deny', 'nonce_reused')
    }
    const outcome = this.evaluate(sub, actionRef, now)
    this.decided.set(nonceKey, { actionRef, outcome })
    if (outcome.verdict === 'permit') this.authorized.set(actionRef, { sub, permit: outcome })
    return outcome
  }

  /**
   * Phase two. Consumes the approval for actionRef and runs it once. A second call for
   * the same action returns the first call's outcome.
   */
  dispatch(actionRef: string): Promise<PaymentOutcome> {
    const final = this.finals.get(actionRef)
    if (final) return final.then(o => ({ ...o, replay: true }))
    const entry = this.authorized.get(actionRef)
    if (!entry) return Promise.resolve({ verdict: 'deny', reason: 'not_authorized', action_ref: actionRef })
    this.authorized.delete(actionRef)
    const done = this.admitAndExecute(entry)
    this.finals.set(actionRef, done)
    return done
  }

  /** Steps 4 to 7, for a request bound to a verified intent with a fresh nonce. */
  private evaluate(sub: PaymentSubmission, actionRef: string, now: string): PaymentOutcome {
    const signedDeny = (reason: string): PaymentOutcome => this.decide(sub, actionRef, now, 'deny', reason)

    const issued = Date.parse(sub.input.issued_at)
    const at = Date.parse(now)
    if (!(issued >= at - REPLAY_WINDOW_MS && issued <= at + FUTURE_SKEW_MS)) {
      return signedDeny('intent_outside_replay_window')
    }

    // 4. Authority: the whole chain, at now, with revocation. Only valid passes.
    const chain = sub.chain
    const leaf = Array.isArray(chain) ? chain.at(-1) : undefined
    if (!leaf) return signedDeny('chain_missing')
    if (leaf.subject !== sub.input.agent_id) return signedDeny('chain_leaf_not_agent')
    if (sub.intent.delegation_ref !== leaf.delegation_id) return signedDeny('intent_delegation_ref_mismatch')
    const authority = this.checkChain(chain, now)
    if (authority) return signedDeny(authority)

    // 5. What is being paid, and whether the leaf covers it.
    const { merchant, amount_minor: amount, currency } = sub.payload
    if (typeof merchant !== 'string' || !MERCHANT.test(merchant)) return signedDeny('merchant_invalid')
    if (typeof amount !== 'string' || !CANONICAL_POSITIVE_INTEGER.test(amount)) return signedDeny('amount_not_canonical_positive_integer')
    if (typeof currency !== 'string' || !CURRENCY.test(currency)) return signedDeny('currency_invalid')
    if (!(this.opts.currencies ?? ['USD']).includes(currency)) return signedDeny('currency_not_accepted')
    if (sub.input.action_type !== PAYMENT_ACTION_TYPE || sub.input.target !== paymentTarget(merchant)) {
      return signedDeny('target_mismatch')
    }
    const scope = paymentScope(merchant)
    if (sub.input.scope_required.length !== 1 || sub.input.scope_required[0] !== scope) {
      return signedDeny('scope_required_mismatch')
    }
    if (!leaf.authority.scope.grants.some(g => scopeGrantCovers(g, scope))) return signedDeny('merchant_not_in_scope')
    const spend = leaf.authority.spend
    // A payment needs a bounded budget at the leaf. This is gateway policy, stricter than
    // the draft, which permits an unbounded spend facet.
    if (spend.mode !== 'bounded') return signedDeny('spend_unbounded_refused')
    const unit = spendUnit(currency)
    if (spend.unit !== unit) return signedDeny('currency_not_delegated')

    // 6. Reserve against every bounded delegation in the chain, atomically. The nonce
    // check above makes a second reservation for the same action unreachable, so an
    // IDEMPOTENT answer here means the ledger and this gateway disagree, and it is refused.
    const r = this.ledger.reserve(chain, actionRef, unit, amount)
    if (!r.ok || r.code !== 'RESERVED') return signedDeny(`budget_${r.code.toLowerCase()}`)

    // 7. Permit.
    return this.decide(sub, actionRef, now, 'permit', 'within_delegated_authority')
  }

  /** True when the stored request still recomputes to the action reference it was approved
   *  under. The stored copy is frozen, so this is a second line of defense. */
  private bindsTo(sub: PaymentSubmission, actionRef: string): boolean {
    try {
      return computePayloadRefV1(sub.payload) === sub.input.payload_ref && computeActionRefV2(sub.input) === actionRef
    } catch {
      return false
    }
  }

  /** null when the chain is valid at `at`, otherwise the refusal reason. */
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

  private decide(
    sub: PaymentSubmission, actionRef: string, now: string, verdict: 'permit' | 'deny', reason: string,
  ): PaymentOutcome {
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
    const p = sub.payload
    const evidence: DecisionEvidence = {
      authority_state: { chain: chain.map(d => String(d?.delegation_id)), counters },
      policy_input: {
        profile: 'aps-example-payment-authority-v0',
        merchant: String(p?.merchant), amount_minor: String(p?.amount_minor), currency: String(p?.currency),
        unit: spendUnit(String(p?.currency)),
      },
      decision_context: { gateway: this.id, decided_at: now, reason },
      decision_output,
    }
    const { decision_ref } = buildDecisionRefV1({ action_ref: actionRef, ...evidence })
    const decision = createReceiptV1({
      profile: 'aps-receipt-v1', receipt_type: 'aps:policy-decision:v1', issuer: this.id,
      subject_agent: sub.input.agent_id, action_ref: actionRef, delegation_ref: sub.intent.delegation_ref,
      decision_ref, issued_at: now, evidence_refs: [], result: decision_output as never, prev: sub.intent.receipt_id,
    }, [{ signer: this.id, key_id: this.opts.keyId, private_key: this.opts.privateKey }])
    return { verdict, reason, action_ref: actionRef, decision, evidence }
  }

  /** Steps 8 to 10. Everything before the executor call runs without awaiting, so a
   *  revocation recorded before dispatch is always seen by the admission recheck. */
  private async admitAndExecute({ sub, permit }: Authorized): Promise<PaymentOutcome> {
    const actionRef = permit.action_ref!
    const now = this.opts.now()
    // The approval is good up to, not including, valid_until. A value that does not parse
    // is treated as expired.
    const validUntil = Date.parse((permit.decision!.result as { valid_until: string }).valid_until)
    const refusal = !Number.isFinite(validUntil) || Date.parse(now) >= validUntil
      ? 'approval_expired'
      : !this.bindsTo(sub, actionRef)
        ? 'authorized_request_changed'
        : this.checkChain(sub.chain, now)
    if (refusal) {
      // Not dispatched, so the reservation can be released.
      this.ledger.cancel(actionRef)
      return { ...permit, dispatched: false, result: this.result(sub, permit, now, 'failed', `admission_refused:${refusal}`) }
    }

    this.ledger.markDispatched(actionRef)
    let outcome: ExecutorResult | { status: 'unknown' }
    try {
      const { merchant, amount_minor, currency } = sub.payload
      outcome = await this.opts.executor({ action_ref: actionRef, merchant, amount_minor, currency })
    } catch {
      // The rail did not say what happened. The reservation stays held: releasing it
      // could let a payment that did go through be spent a second time.
      outcome = { status: 'unknown' }
    }
    if (outcome.status === 'succeeded') this.ledger.commit(actionRef)
    // A failed charge after dispatch also stays reserved. The reference ledger allows
    // cancellation only before dispatch, and this example does not add a reconciliation
    // step. A production rail that can prove nothing moved needs one.
    const at = this.opts.now()
    const result = outcome.status === 'succeeded'
      ? this.result(sub, permit, at, 'succeeded', null, sha256Hex(outcome.charge_id))
      : outcome.status === 'failed'
        ? this.result(sub, permit, at, 'failed', outcome.error_code)
        : this.result(sub, permit, at, 'unknown', null)
    return { ...permit, dispatched: true, result }
  }

  private result(
    sub: PaymentSubmission, permit: PaymentOutcome, at: string,
    status: 'succeeded' | 'failed' | 'unknown', errorCode: string | null, effectRef: string | null = null,
  ): ReceiptV1 {
    return createReceiptV1({
      profile: 'aps-receipt-v1', receipt_type: 'aps:action-result:v1', issuer: this.id,
      subject_agent: sub.input.agent_id, action_ref: permit.action_ref!, delegation_ref: sub.intent.delegation_ref,
      decision_ref: permit.decision!.decision_ref, issued_at: at, evidence_refs: [],
      result: { profile: 'aps-action-result-v1', status, effect_ref: effectRef, error_code: errorCode } as never,
      prev: permit.decision!.receipt_id,
    }, [{ signer: this.id, key_id: this.opts.keyId, private_key: this.opts.privateKey }])
  }
}
