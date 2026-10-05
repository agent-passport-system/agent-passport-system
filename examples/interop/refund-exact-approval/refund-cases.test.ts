// Case harness: cross-system model. Approval = signed aps:policy-decision:v1 permit
// bound to the aps-action-ref-v2 of the approved refund. Fixtures here are test setup,
// the decision logic under test is admitRefund in refund-boundary.ts.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash, randomBytes } from 'node:crypto'
import {
  buildDecisionRefV1, computeActionRefV2, computePayloadRefV1,
  createActionReferenceInputV2, createReceiptV1, generateKeyPair,
} from 'agent-passport-system'
import { admitRefund, refundTarget } from './refund-boundary.ts'

const BOUNDARY = 'did:example:refund-approval-boundary'
const WORKER = 'did:example:refund-worker'
const boundaryKeys = generateKeyPair()
const workerKeys = generateKeyPair()
const keys: Record<string, string> = { [BOUNDARY]: boundaryKeys.publicKey, [WORKER]: workerKeys.publicKey }
const resolveKey = (signer: string) => keys[signer]
const sha = (s: string) => createHash('sha256').update(s).digest('hex')
const DELEGATION_REF = 'sha256:' + sha('synthetic-delegation-leaf')
const SCOPES = ['payments:refund']
const APPROVED = { payment_id: 'pay_A', amount_minor: 4000, currency: 'EUR' }

function inputFor(payload: { payment_id: string }, issued_at: string, nonce: string) {
  return createActionReferenceInputV2({
    agent_id: WORKER, action_type: 'refund', target: refundTarget(payload.payment_id),
    payload_ref: computePayloadRefV1(payload), scope_required: SCOPES, issued_at, nonce,
  })
}

/** Issue an approval for `payload`: intent record by the worker, then a permit
 *  policy-decision record by the boundary key, valid for ttlMs. */
function issueApproval(payload: typeof APPROVED, ttlMs = 60_000, signerKey = boundaryKeys.privateKey,
  verdict: 'permit' | 'narrow' = 'permit', constraints: string[] = []) {
  const issued_at = new Date().toISOString()
  const input = inputFor(payload, issued_at, randomBytes(16).toString('hex'))
  const action_ref = computeActionRefV2(input)
  const intent = createReceiptV1({
    profile: 'aps-receipt-v1', receipt_type: 'aps:action-intent:v1', issuer: WORKER, subject_agent: WORKER,
    action_ref, delegation_ref: DELEGATION_REF, issued_at, evidence_refs: [],
    result: { profile: 'aps-action-intent-result-v1', status: 'declared' },
  }, [{ signer: WORKER, key_id: 'k1', private_key: workerKeys.privateKey }])
  const valid_until = new Date(Date.parse(issued_at) + ttlMs).toISOString()
  const decision_output = {
    profile: 'aps-core-decision-output-v1' as const, verdict,
    effective_authority_ref: sha('synthetic-effective-authority'), constraints, valid_until,
  }
  const { decision_ref } = buildDecisionRefV1({
    action_ref, authority_state: { synthetic: true }, policy_input: { operator_approved: payload },
    decision_context: { run: 'refund-feasibility-2026-10-05' }, decision_output,
  })
  const approval = createReceiptV1({
    profile: 'aps-receipt-v1', receipt_type: 'aps:policy-decision:v1', issuer: BOUNDARY, subject_agent: WORKER,
    action_ref, delegation_ref: DELEGATION_REF, decision_ref, issued_at, evidence_refs: [],
    result: decision_output as any, prev: intent.receipt_id,
  }, [{ signer: BOUNDARY, key_id: 'k1', private_key: signerKey }])
  return { input, approval, issued_at, valid_until }
}

const boundary = { boundaryIdentity: BOUNDARY, resolveKey, consumed: new Set<string>() }
const now = () => new Date()
const rows: string[] = []
const record = (c: string, r: unknown) => { rows.push(`${c}\t${JSON.stringify(r)}`); console.log(`ROW ${c} ${JSON.stringify(r)}`) }

// Changed request, variant v1: the worker recomputes a consistent input object for the
// changed payload (same agent, issued_at, nonce). Variant v2: the worker keeps the approved
// input object and swaps only the payload.
function changed(c: string, payload: any) {
  const a = issueApproval(APPROVED)
  const v1 = admitRefund({ input: inputFor(payload, a.input.issued_at, a.input.nonce), payload, approval: a.approval }, boundary, now())
  record(`${c}-v1`, v1)
  assert.equal(v1.admitted, false)
  const v2 = admitRefund({ input: a.input, payload, approval: a.approval }, boundary, now())
  record(`${c}-v2`, v2)
  assert.equal(v2.admitted, false)
  return { v1, v2, a }
}

let r0: ReturnType<typeof issueApproval>
test('R0 exact request admits', () => {
  r0 = issueApproval(APPROVED)
  const r = admitRefund({ input: r0.input, payload: { ...APPROVED }, approval: r0.approval }, boundary, now())
  record('R0', r)
  assert.equal(r.admitted, true)
})
test('R1 amount 3900 refused', () => { changed('R1', { ...APPROVED, amount_minor: 3900 }) })
test('R2 amount 4100 refused', () => { changed('R2', { ...APPROVED, amount_minor: 4100 }) })
test('R3 payment pay_B refused', () => {
  const { a } = changed('R3', { ...APPROVED, payment_id: 'pay_B' })
  // v3: payload_ref recomputed for pay_B but target left at pay_A.
  const payload = { ...APPROVED, payment_id: 'pay_B' }
  const input = { ...a.input, payload_ref: computePayloadRefV1(payload) }
  const v3 = admitRefund({ input, payload, approval: a.approval }, boundary, now())
  record('R3-v3', v3)
  assert.equal(v3.admitted, false)
})
test('R4 currency USD refused', () => { changed('R4', { ...APPROVED, currency: 'USD' }) })
test('R5 approval expired at submission refused', () => {
  const a = issueApproval(APPROVED)
  const late = new Date(Date.parse(a.valid_until) + 1)
  const r = admitRefund({ input: a.input, payload: { ...APPROVED }, approval: a.approval }, boundary, late)
  record('R5', { ...r, valid_until: a.valid_until, now: late.toISOString() })
  assert.equal(r.admitted, false)
})
test('R6 second submission of the R0 approval refused', () => {
  const r = admitRefund({ input: r0.input, payload: { ...APPROVED }, approval: r0.approval }, boundary, now())
  record('R6', r)
  assert.equal(r.admitted, false)
})
test('R7 no matching approval refused', () => {
  const a = issueApproval(APPROVED)
  const none = admitRefund({ input: a.input, payload: { ...APPROVED } }, boundary, now())
  record('R7a-none', none)
  assert.equal(none.admitted, false)
  // R7b: a genuine approval, but for pay_B, presented with the pay_A request.
  const other = issueApproval({ ...APPROVED, payment_id: 'pay_B' })
  const b = admitRefund({ input: a.input, payload: { ...APPROVED }, approval: other.approval }, boundary, now())
  record('R7b-other-action', b)
  assert.equal(b.admitted, false)
  // R7c: an approval naming the boundary as issuer but signed by a key it does not hold.
  const forged = issueApproval(APPROVED, 60_000, generateKeyPair().privateKey)
  const c = admitRefund({ input: forged.input, payload: { ...APPROVED }, approval: forged.approval }, boundary, now())
  record('R7c-forged', c)
  assert.equal(c.admitted, false)
})
test('R8 informational: 4000.0 and 4e3 spellings', () => {
  for (const spelled of ['4000.0', '4e3']) {
    const raw = `{"payment_id":"pay_A","amount_minor":${spelled},"currency":"EUR"}`
    const payload = JSON.parse(raw)
    const a = issueApproval(APPROVED)
    const r = admitRefund({ input: a.input, payload, approval: a.approval }, boundary, now())
    record(`R8-${spelled}`, {
      ...r, raw, parsed_amount: payload.amount_minor, is_integer: Number.isInteger(payload.amount_minor),
      payload_ref_equal: computePayloadRefV1(payload) === computePayloadRefV1(APPROVED),
    })
  }
})

test('R9 signed narrow decision with an unenforced constraint refused (exact request)', () => {
  const a = issueApproval(APPROVED, 60_000, boundaryKeys.privateKey, 'narrow',
    ['refund:requires-second-operator-confirmation'])
  const r = admitRefund({ input: a.input, payload: APPROVED, approval: a.approval }, boundary, now())
  record('R9', r)
  assert.deepEqual(r, { admitted: false, reason: 'approval_verdict_unsupported:narrow' })
  assert.equal(boundary.consumed.has(a.approval.receipt_id), false)
})
