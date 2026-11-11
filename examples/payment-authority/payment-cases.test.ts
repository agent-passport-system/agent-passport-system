// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Cases for the payment authority gateway. Every decision with a verified intent is also
// checked by verify.ts with public keys only, so a passing case means both that the
// gateway decided as expected and that a third party can check the record of it.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createReceiptV1, issueAuthorityRevocation } from 'agent-passport-system'
import { AGENT_A, AGENT_B, GATEWAY, MERCHANT, PERSON, createWorld, usd } from './actors.ts'
import { DECISION_TTL_MS, REPLAY_WINDOW_MS } from './gateway.ts'
import type { PaymentOutcome, PaymentSubmission } from './gateway.ts'
import { verifyBundle } from './verify.ts'

function checkRecords(w: ReturnType<typeof createWorld>, sub: PaymentSubmission, o: PaymentOutcome, label: string) {
  assert.ok(o.decision && o.evidence, `${label}: a verified intent always gets a signed decision`)
  const c = verifyBundle({ label, input: sub.input, payload: sub.payload, intent: sub.intent,
    decision: o.decision!, evidence: o.evidence!, result: o.result }, w.publicKeys(), GATEWAY)
  assert.deepEqual(c.errors, [], `${label}: third-party verification`)
  assert.equal(c.verdict, o.verdict)
  assert.equal(c.reason, o.reason)
}

test('P1 the main path: delegate $30, $40 denied, $20 paid, revoke, $5 denied', async () => {
  const w = createWorld()
  const b = w.delegate(w.grantToA, AGENT_B, '3000')
  const chainB = [w.grantToA, b]

  const s40 = w.request(AGENT_B, chainB, usd(4000))
  const o40 = await w.gateway.pay(s40)
  assert.equal(o40.verdict, 'deny')
  assert.equal(o40.reason, 'budget_per_action_exceeded')
  checkRecords(w, s40, o40, 'P1 $40')

  const s20 = w.request(AGENT_B, chainB, usd(2000))
  const o20 = await w.gateway.pay(s20)
  assert.equal(o20.verdict, 'permit')
  assert.equal((o20.result!.result as { status: string }).status, 'succeeded')
  checkRecords(w, s20, o20, 'P1 $20')
  assert.equal(w.charges.length, 1)

  assert.deepEqual(w.revokeRoot(), { recorded: true })
  const s5 = w.request(AGENT_B, chainB, usd(500))
  const o5 = await w.gateway.pay(s5)
  assert.equal(o5.verdict, 'deny')
  assert.equal(o5.reason, 'authority_invalid:REVOKED')
  checkRecords(w, s5, o5, 'P1 $5 after revocation')

  const sa = w.request(AGENT_A, [w.grantToA], usd(500))
  assert.equal((await w.gateway.pay(sa)).reason, 'authority_invalid:REVOKED')
  assert.equal(w.charges.length, 1, 'nothing was charged after revocation')
  assert.deepEqual(w.gateway.budget(b), { limit: '3000', reserved: '0', committed: '2000' })
  assert.deepEqual(w.gateway.budget(w.grantToA), { limit: '10000', reserved: '0', committed: '2000' })
})

test('P2 Agent A cannot give Agent B more than it holds', () => {
  const w = createWorld()
  assert.throws(() => w.delegate(w.grantToA, AGENT_B, '15000'), /SPEND_WIDENING/)
  assert.throws(() => w.delegate(w.grantToA, AGENT_B, '3000', ['commerce:pay:*']), /SCOPE_WIDENING/)
  const b = w.delegate(w.grantToA, AGENT_B, '3000')
  assert.throws(() => w.delegate(b, 'did:example:agent-c', '1000'), /DEPTH/)
})

test('P3 two simultaneous $8 payments against $10 remaining: exactly one goes through', async () => {
  const w = createWorld()
  const b = w.delegate(w.grantToA, AGENT_B, '3000')
  const chainB = [w.grantToA, b]
  assert.equal((await w.gateway.pay(w.request(AGENT_B, chainB, usd(2000)))).verdict, 'permit')

  const s1 = w.request(AGENT_B, chainB, usd(800))
  const s2 = w.request(AGENT_B, chainB, usd(800))
  const [o1, o2] = await Promise.all([w.gateway.pay(s1), w.gateway.pay(s2)])
  const verdicts = [o1.verdict, o2.verdict].sort()
  assert.deepEqual(verdicts, ['deny', 'permit'])
  const denied = o1.verdict === 'deny' ? o1 : o2
  assert.equal(denied.reason, 'budget_cumulative_exceeded')
  checkRecords(w, s1, o1, 'P3 first $8')
  checkRecords(w, s2, o2, 'P3 second $8')
  assert.equal(w.charges.length, 2)
  assert.deepEqual(w.gateway.budget(b), { limit: '3000', reserved: '0', committed: '2800' })
})

test('P4 a child spending counts against the parent budget', async () => {
  const w = createWorld()
  const b = w.delegate(w.grantToA, AGENT_B, '3000')
  assert.equal((await w.gateway.pay(w.request(AGENT_B, [w.grantToA, b], usd(3000)))).verdict, 'permit')
  const sa = w.request(AGENT_A, [w.grantToA], usd(7500))
  const oa = await w.gateway.pay(sa)
  assert.equal(oa.verdict, 'deny')
  assert.equal(oa.reason, 'budget_cumulative_exceeded')
  checkRecords(w, sa, oa, 'P4 A $75 after B $30')
  assert.equal((await w.gateway.pay(w.request(AGENT_A, [w.grantToA], usd(7000)))).verdict, 'permit')
  assert.deepEqual(w.gateway.budget(w.grantToA), { limit: '10000', reserved: '0', committed: '10000' })
})

test('P5 merchant and currency outside the grant are refused', async () => {
  const w = createWorld()
  const b = w.delegate(w.grantToA, AGENT_B, '3000')
  const chainB = [w.grantToA, b]
  const sm = w.request(AGENT_B, chainB, { merchant: 'other-shop', amount_minor: '100', currency: 'USD' })
  const om = await w.gateway.pay(sm)
  assert.equal(om.reason, 'merchant_not_in_scope')
  checkRecords(w, sm, om, 'P5 other merchant')
  const sc = w.request(AGENT_B, chainB, { merchant: MERCHANT, amount_minor: '100', currency: 'EUR' })
  assert.equal((await w.gateway.pay(sc)).reason, 'currency_not_accepted')
  for (const amount of ['0', '-100', '10.50', '0100', '1e3']) {
    const s = w.request(AGENT_B, chainB, { merchant: MERCHANT, amount_minor: amount, currency: 'USD' })
    assert.equal((await w.gateway.pay(s)).reason, 'amount_not_canonical_positive_integer', amount)
  }
  assert.equal(w.charges.length, 0)
})

test('P6 one signed request pays once: a repeated submission gets the same outcome back', async () => {
  const w = createWorld()
  const b = w.delegate(w.grantToA, AGENT_B, '3000')
  const s = w.request(AGENT_B, [w.grantToA, b], usd(1000))
  const first = await w.gateway.pay(s)
  const [again1, again2] = await Promise.all([w.gateway.pay(s), w.gateway.pay(s)])
  for (const again of [again1, again2]) {
    assert.equal(again.replay, true)
    assert.equal(again.decision!.receipt_id, first.decision!.receipt_id)
  }
  assert.equal(w.charges.length, 1)
  assert.deepEqual(w.gateway.budget(b), { limit: '3000', reserved: '0', committed: '1000' })
})

test('P7 requests the agent did not sign are refused without a charge', async () => {
  const w = createWorld()
  const b = w.delegate(w.grantToA, AGENT_B, '3000')
  const chainB = [w.grantToA, b]

  // The amount is changed after the agent signed.
  const s = w.request(AGENT_B, chainB, usd(1000))
  assert.equal((await w.gateway.pay({ ...s, payload: usd(2900) })).reason, 'payload_ref_mismatch')

  // Agent A signs an intent claiming to be Agent B.
  const { receipt_id: _id, signatures: _sigs, ...intentFields } = s.intent
  const forged = createReceiptV1(intentFields,
    [{ signer: AGENT_B, key_id: 'key', private_key: w.keys[AGENT_A].privateKey }])
  assert.equal(forged.action_ref, s.intent.action_ref)
  assert.equal((await w.gateway.pay({ ...s, intent: forged })).reason, 'intent_invalid')

  // Agent A presents Agent B's chain as its own.
  const sa = w.request(AGENT_A, chainB, usd(1000))
  assert.equal((await w.gateway.pay(sa)).reason, 'chain_leaf_not_agent')
  assert.equal(w.charges.length, 0)
})

test('P8 only the person who granted authority can revoke it', async () => {
  const w = createWorld()
  const b = w.delegate(w.grantToA, AGENT_B, '3000')
  const fake = issueAuthorityRevocation(w.grantToA, {
    now: w.clock.advance(1), revoker: PERSON, verification_method: `${PERSON}#key`,
    reason_code: 'forged', nonce: '0'.repeat(32),
  }, w.keys[AGENT_A].privateKey)
  assert.equal(w.gateway.revoke(w.grantToA, fake).recorded, false)
  assert.equal((await w.gateway.pay(w.request(AGENT_B, [w.grantToA, b], usd(100)))).verdict, 'permit')
})

test('P9 authority the gateway cannot check, or that has expired, is refused', async () => {
  const w = createWorld()
  const unenrolled = w.delegate(w.grantToA, AGENT_B, '3000', undefined, false)
  const su = w.request(AGENT_B, [w.grantToA, unenrolled], usd(100))
  const ou = await w.gateway.pay(su)
  assert.equal(ou.reason, 'authority_indeterminate:REVOCATION_UNKNOWN')
  checkRecords(w, su, ou, 'P9 unenrolled')

  const b = w.delegate(w.grantToA, AGENT_B, '3000')
  w.clock.advance(2 * 3_600_000)
  const se = w.request(AGENT_B, [w.grantToA, b], usd(100))
  assert.match((await w.gateway.pay(se)).reason, /^authority_invalid:.*EXPIRED/)
  assert.equal(w.charges.length, 0)
})

test('P10 when the rail does not answer, the amount stays reserved', async () => {
  const w = createWorld({ executor: async () => { throw new Error('rail timeout') } })
  const b = w.delegate(w.grantToA, AGENT_B, '3000')
  const s = w.request(AGENT_B, [w.grantToA, b], usd(2500))
  const o = await w.gateway.pay(s)
  assert.equal(o.verdict, 'permit')
  assert.equal((o.result!.result as { status: string }).status, 'unknown')
  checkRecords(w, s, o, 'P10 unknown outcome')
  assert.deepEqual(w.gateway.budget(b), { limit: '3000', reserved: '2500', committed: '0' })
  const next = await w.gateway.pay(w.request(AGENT_B, [w.grantToA, b], usd(1000)))
  assert.equal(next.reason, 'budget_cumulative_exceeded')
})

test('P11 a record changed after signing fails third-party verification', async () => {
  const w = createWorld()
  const b = w.delegate(w.grantToA, AGENT_B, '3000')
  const s = w.request(AGENT_B, [w.grantToA, b], usd(4000))
  const o = await w.gateway.pay(s)
  const bundle = { label: 'tampered', input: s.input, payload: s.payload, intent: s.intent, decision: o.decision!, evidence: o.evidence! }
  const reasonEdited = structuredClone(bundle)
  reasonEdited.evidence.decision_context.reason = 'within_delegated_authority'
  assert.equal(verifyBundle(reasonEdited, w.publicKeys(), GATEWAY).ok, false)
  const payloadEdited = structuredClone(bundle)
  payloadEdited.payload.amount_minor = '400'
  assert.equal(verifyBundle(payloadEdited, w.publicKeys(), GATEWAY).ok, false)
  const otherGatewayKeys = { ...w.publicKeys(), [GATEWAY]: w.publicKeys()[PERSON] }
  assert.equal(verifyBundle(bundle, otherGatewayKeys, GATEWAY).ok, false)
})

test('P12 one nonce, one action: a second action signed with the same nonce is refused', async () => {
  const w = createWorld()
  const b = w.delegate(w.grantToA, AGENT_B, '3000')
  const chainB = [w.grantToA, b]
  const nonce = 'a'.repeat(32)
  const first = w.request(AGENT_B, chainB, usd(1000), { nonce })
  assert.equal((await w.gateway.pay(first)).verdict, 'permit')
  const second = w.request(AGENT_B, chainB, usd(500), { nonce })
  const o = await w.gateway.pay(second)
  assert.equal(o.verdict, 'deny')
  assert.equal(o.reason, 'nonce_reused')
  checkRecords(w, second, o, 'P12 reused nonce')
  // The first action's decision is not displaced: resubmitting it still returns it.
  const again = await w.gateway.pay(first)
  assert.equal(again.replay, true)
  assert.equal(w.charges.length, 1)
  // A different agent may use the same nonce value: nonces are per agent.
  const sa = w.request(AGENT_A, [w.grantToA], usd(100), { nonce })
  assert.equal((await w.gateway.pay(sa)).verdict, 'permit')
})

test('P13 a request signed outside the replay window is refused', async () => {
  const w = createWorld()
  const b = w.delegate(w.grantToA, AGENT_B, '3000')
  const s = w.request(AGENT_B, [w.grantToA, b], usd(100))
  w.clock.advance(REPLAY_WINDOW_MS + 1)
  const o = await w.gateway.pay(s)
  assert.equal(o.reason, 'intent_outside_replay_window')
  checkRecords(w, s, o, 'P13 stale request')
  assert.equal(w.charges.length, 0)
})

test('P14 one signed request gets one decision, a denial included', async () => {
  const w = createWorld()
  const b = w.delegate(w.grantToA, AGENT_B, '3000', undefined, false)
  const chainB = [w.grantToA, b]
  const s = w.request(AGENT_B, chainB, usd(100))
  const first = await w.gateway.pay(s)
  assert.equal(first.reason, 'authority_indeterminate:REVOCATION_UNKNOWN')
  // The gateway now learns about the delegation. The same signed request still gets its
  // original denial back. The agent has to sign a new request.
  w.gateway.enroll([b])
  const again = await w.gateway.pay(s)
  assert.equal(again.replay, true)
  assert.equal(again.decision!.receipt_id, first.decision!.receipt_id)
  assert.equal(again.reason, first.reason)
  const fresh = await w.gateway.pay(w.request(AGENT_B, chainB, usd(100)))
  assert.equal(fresh.verdict, 'permit')
  assert.equal(w.charges.length, 1)
})

test('P15 a revocation between authorization and dispatch stops the payment', async () => {
  const w = createWorld()
  const b = w.delegate(w.grantToA, AGENT_B, '3000')
  const s = w.request(AGENT_B, [w.grantToA, b], usd(1500))
  const a = w.gateway.authorize(s)
  assert.equal(a.verdict, 'permit')
  assert.deepEqual(w.gateway.budget(b), { limit: '3000', reserved: '1500', committed: '0' })
  assert.deepEqual(w.revokeRoot(), { recorded: true })
  const o = await w.gateway.dispatch(a.action_ref!)
  assert.equal(o.dispatched, false)
  const result = o.result!.result as { status: string; error_code: string }
  assert.equal(result.status, 'failed')
  assert.equal(result.error_code, 'admission_refused:authority_invalid:REVOKED')
  checkRecords(w, s, o, 'P15 revoked before dispatch')
  assert.equal(w.charges.length, 0)
  assert.deepEqual(w.gateway.budget(b), { limit: '3000', reserved: '0', committed: '0' }, 'reservation released')
})

test('P16 an approval that waited past valid_until is not dispatched', async () => {
  const w = createWorld()
  const b = w.delegate(w.grantToA, AGENT_B, '3000')
  const s = w.request(AGENT_B, [w.grantToA, b], usd(1500))
  const a = w.gateway.authorize(s)
  assert.equal(a.verdict, 'permit')
  w.clock.advance(DECISION_TTL_MS + 1)
  const o = await w.gateway.dispatch(a.action_ref!)
  assert.equal((o.result!.result as { error_code: string }).error_code, 'admission_refused:approval_expired')
  checkRecords(w, s, o, 'P16 expired approval')
  assert.equal(w.charges.length, 0)
  assert.deepEqual(w.gateway.budget(b), { limit: '3000', reserved: '0', committed: '0' })
})

test('P17 an approval is consumed once: two dispatches of one approval charge once', async () => {
  const w = createWorld()
  const b = w.delegate(w.grantToA, AGENT_B, '3000')
  const a = w.gateway.authorize(w.request(AGENT_B, [w.grantToA, b], usd(1000)))
  const [d1, d2] = await Promise.all([w.gateway.dispatch(a.action_ref!), w.gateway.dispatch(a.action_ref!)])
  assert.equal(d1.result!.receipt_id, d2.result!.receipt_id)
  assert.equal(d2.replay, true)
  assert.equal(w.charges.length, 1)
  assert.equal((await w.gateway.dispatch('0'.repeat(64))).reason, 'not_authorized')
  assert.deepEqual(w.gateway.budget(b), { limit: '3000', reserved: '0', committed: '1000' })
})
