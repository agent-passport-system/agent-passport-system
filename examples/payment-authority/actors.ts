// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Test setup for the example: keys, the person's grant, the agent's sub-delegation and
// signed payment requests. Nothing here is gateway logic. Every key is generated fresh
// for each run and none of them can move real money.

import { randomBytes } from 'node:crypto'
import {
  computeActionRefV2,
  computePayloadRefV1,
  createActionReferenceInputV2,
  createReceiptV1,
  generateKeyPair,
  issueAuthorityDelegation,
  issueAuthorityRevocation,
  issueSubAuthorityDelegation,
} from 'agent-passport-system'
import type { AuthorityDelegationBodyV1, AuthorityDelegationV1 } from 'agent-passport-system'
import {
  PAYMENT_ACTION_TYPE, PaymentAuthorityGateway, paymentScope, paymentTarget, spendUnit,
} from './gateway.ts'
import type { PaymentExecutor, PaymentPayload, PaymentSubmission } from './gateway.ts'

export const PERSON = 'did:example:person'
export const AGENT_A = 'did:example:agent-a'
export const AGENT_B = 'did:example:agent-b'
export const GATEWAY = 'did:example:payment-gateway'
export const MERCHANT = 'acme-books'

// Profile identifiers of draft-pidlisnyi-aps-03 section 3.1. The 8.0.1 package root does
// not export these constants, so they are written out here.
const AUTHORITY_DELEGATION_RECORD_TYPE = 'aps:authority-delegation:v1' as const
const AUTHORITY_DELEGATION_VERSION = '1.0' as const
const SCOPE_PROFILE_V1 = 'aps-hierarchical-v1' as const
const REPUTATION_PROFILE_V1 = 'aps-score-0-100-v1' as const
const VALUES_PROFILE_V1 = 'aps-values-identifiers-v1' as const
const REVERSIBILITY_PROFILE_V1 = 'aps-tci-v1' as const

const hex16 = (): string => randomBytes(16).toString('hex')

/** A clock that only moves when told to. Exact UTC milliseconds. */
export class TestClock {
  private t: number
  constructor(start = '2026-11-11T20:00:00.000Z') { this.t = Date.parse(start) }
  now = (): string => new Date(this.t).toISOString()
  advance(ms: number): string { this.t += ms; return this.now() }
}

export interface World {
  clock: TestClock
  gateway: PaymentAuthorityGateway
  keys: Record<string, { publicKey: string; privateKey: string }>
  charges: { action_ref: string; merchant: string; amount_minor: string; currency: string }[]
  grantToA: AuthorityDelegationV1
  delegate: (parent: AuthorityDelegationV1, subject: string, cents: string, grants?: string[], enroll?: boolean) => AuthorityDelegationV1
  request: (agent: string, chain: AuthorityDelegationV1[], payload: PaymentPayload, opts?: { nonce?: string }) => PaymentSubmission
  revokeRoot: () => { recorded: boolean; reason?: string }
  /** The public keys a third-party verifier needs, and nothing else. */
  publicKeys: () => Record<string, string>
}

export function authorityBody(
  issuer: string, subject: string, parentId: string | null, issuedAt: string, notAfter: string,
  cents: string, grants: string[], depth: number,
): AuthorityDelegationBodyV1 {
  return {
    record_type: AUTHORITY_DELEGATION_RECORD_TYPE,
    version: AUTHORITY_DELEGATION_VERSION,
    parent_delegation_id: parentId,
    issuer, subject,
    verification_method: `${issuer}#key`,
    issued_at: issuedAt,
    nonce: hex16(),
    authority: {
      scope: { profile: SCOPE_PROFILE_V1, grants },
      spend: { mode: 'bounded', unit: spendUnit('USD'), per_action: cents, cumulative: cents },
      depth: { remaining: depth },
      time: { not_before: issuedAt, not_after: notAfter },
      reputation: { profile: REPUTATION_PROFILE_V1, ceiling: 100 },
      values: { profile: VALUES_PROFILE_V1, required: [] },
      reversibility: { profile: REVERSIBILITY_PROFILE_V1, ceiling: 'irreversible' },
    },
  }
}

/**
 * The scenario: a person gives Agent A permission to spend $100 at one merchant, in USD,
 * for one hour. `executor` defaults to a mock that records every charge it is asked for.
 */
export function createWorld(opts: { executor?: PaymentExecutor; rootCents?: string } = {}): World {
  const clock = new TestClock()
  const keys: Record<string, { publicKey: string; privateKey: string }> = {
    [PERSON]: generateKeyPair(),
    [AGENT_A]: generateKeyPair(),
    [AGENT_B]: generateKeyPair(),
    [GATEWAY]: generateKeyPair(),
  }
  const charges: World['charges'] = []
  const mockExecutor: PaymentExecutor = async charge => {
    charges.push(charge)
    await new Promise(resolve => setTimeout(resolve, 5))
    return { status: 'succeeded', charge_id: `ch_test_${charges.length}` }
  }
  const resolveVerificationKey = (issuer: string, method: string): string | null =>
    method === `${issuer}#key` && keys[issuer] ? keys[issuer].publicKey : null
  const resolveReceiptKey = (signer: string, keyId: string): string | undefined =>
    keyId === 'key' && keys[signer] ? keys[signer].publicKey : undefined

  const gateway = new PaymentAuthorityGateway({
    id: GATEWAY, keyId: 'key', privateKey: keys[GATEWAY].privateKey,
    resolveReceiptKey, resolveVerificationKey,
    trustRoot: root => root.issuer === PERSON && root.verification_method === `${PERSON}#key`,
    executor: opts.executor ?? mockExecutor,
    now: clock.now,
  })

  const issuedAt = clock.now()
  const oneHour = new Date(Date.parse(issuedAt) + 3_600_000).toISOString()
  const grantToA = issueAuthorityDelegation(
    authorityBody(PERSON, AGENT_A, null, issuedAt, oneHour, opts.rootCents ?? '10000', [paymentScope(MERCHANT)], 1),
    keys[PERSON].privateKey,
  )
  gateway.enroll([grantToA])

  const delegate: World['delegate'] = (parent, subject, cents, grants = parent.authority.scope.grants, enroll = true) => {
    const at = clock.advance(1)
    const child = issueSubAuthorityDelegation(
      parent,
      authorityBody(parent.subject, subject, parent.delegation_id, at, parent.authority.time.not_after,
        cents, grants, Math.max(0, parent.authority.depth.remaining - 1)),
      keys[parent.subject].privateKey,
      { now: at, resolveVerificationKey, resolveRevocation: () => 'active' },
    )
    if (enroll) gateway.enroll([child])
    return child
  }

  const request: World['request'] = (agent, chain, payload, opts = {}) => {
    const at = clock.advance(1)
    const input = createActionReferenceInputV2({
      agent_id: agent, action_type: PAYMENT_ACTION_TYPE, target: paymentTarget(payload.merchant),
      payload_ref: computePayloadRefV1(payload), scope_required: [paymentScope(payload.merchant)],
      issued_at: at, nonce: opts.nonce ?? hex16(),
    })
    const intent = createReceiptV1({
      profile: 'aps-receipt-v1', receipt_type: 'aps:action-intent:v1', issuer: agent, subject_agent: agent,
      action_ref: computeActionRefV2(input), delegation_ref: chain.at(-1)!.delegation_id, issued_at: at,
      evidence_refs: [], result: { profile: 'aps-action-intent-result-v1', status: 'declared' },
    }, [{ signer: agent, key_id: 'key', private_key: keys[agent].privateKey }])
    return { input, payload, intent, chain }
  }

  const revokeRoot: World['revokeRoot'] = () => {
    const at = clock.advance(1)
    const revocation = issueAuthorityRevocation(grantToA, {
      now: at, revoker: PERSON, verification_method: `${PERSON}#key`, reason_code: 'person_withdrew_consent', nonce: hex16(),
    }, keys[PERSON].privateKey)
    return gateway.revoke(grantToA, revocation)
  }

  const publicKeys = () => Object.fromEntries(Object.entries(keys).map(([id, k]) => [id, k.publicKey]))

  return { clock, gateway, keys, charges, grantToA, delegate, request, revokeRoot, publicKeys }
}

export const usd = (cents: number): PaymentPayload => ({ merchant: MERCHANT, amount_minor: String(cents), currency: 'USD' })
