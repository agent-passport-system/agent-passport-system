// Candidate execution-service admission check for one exact refund approval
// (aeoess/agent-governance-vocabulary#193). Logic written for this check, not SDK code.
// Not an adapter and not a joint contract with PIC.
//
// CANDIDATE PROFILE TEXT. Section 5.1 says a profile MUST define its target string
// construction. For action_type "refund" this check uses
//   "https://payments.operator.example/v1/payments/" + payment_id + "/refunds"
// No profile defines this today. It is a candidate for this run only.
import { computeActionRefV2, computePayloadRefV1, verifyReceiptV1 } from 'agent-passport-system'
import type { ActionReferenceInputV2, ReceiptV1 } from 'agent-passport-system'

export const refundTarget = (paymentId: string): string =>
  `https://payments.operator.example/v1/payments/${paymentId}/refunds`

export interface RefundSubmission {
  input: ActionReferenceInputV2
  payload: unknown
  approval?: ReceiptV1
}

export interface RefundBoundary {
  boundaryIdentity: string
  resolveKey: (signer: string, keyId: string, issuedAt: string) => string | undefined
  consumed: Set<string> // in memory, single process: the exported SDK has no SeenSet
}

export type Admission = { admitted: true; receipt_id: string } | { admitted: false; reason: string }

export function admitRefund(sub: RefundSubmission, b: RefundBoundary, now: Date): Admission {
  const refuse = (reason: string): Admission => ({ admitted: false, reason })
  const approval = sub.approval
  if (!approval) return refuse('no_approval')
  const v = verifyReceiptV1(approval, b.resolveKey,
    { expectedReceiptType: 'aps:policy-decision:v1', boundaryIdentity: b.boundaryIdentity })
  if (v.status !== 'valid') return refuse(`approval_${v.status}:${v.errors.join(',')}`)
  const out = approval.result as { verdict: string; valid_until: string }
  // Permit only. This candidate does not evaluate constraints, so a narrow decision is
  // refused rather than admitted with its constraints ignored.
  if (out.verdict !== 'permit') return refuse(`approval_verdict_unsupported:${out.verdict}`)
  let payloadRef: string
  try { payloadRef = computePayloadRefV1(sub.payload) } catch { return refuse('payload_invalid') }
  if (payloadRef !== sub.input.payload_ref) return refuse('payload_ref_mismatch')
  const paymentId = (sub.payload as { payment_id?: unknown } | null)?.payment_id
  if (typeof paymentId !== 'string') return refuse('payload_payment_id_missing')
  if (sub.input.action_type !== 'refund' || sub.input.target !== refundTarget(paymentId)) {
    return refuse('target_mismatch')
  }
  let actionRef: string
  try { actionRef = computeActionRefV2(sub.input) } catch { return refuse('action_ref_input_invalid') }
  if (actionRef !== approval.action_ref) return refuse('action_ref_mismatch')
  // Both sides are exact UTC milliseconds, so string order is instant order.
  if (now.toISOString() > out.valid_until) return refuse('approval_expired')
  if (b.consumed.has(approval.receipt_id)) return refuse('approval_already_consumed')
  b.consumed.add(approval.receipt_id)
  return { admitted: true, receipt_id: approval.receipt_id }
}
