// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Third-party check of the gateway's records, using public keys only.
//
//   node --import tsx verify.ts out/receipts.json out/public-keys.json
//
// For every record bundle it checks that:
//   - the action reference recomputes from the submitted request and payload
//   - the agent's intent record is signed by the agent
//   - the gateway's decision record is signed by the gateway, its decision_ref binds the
//     published authority state, policy input, context (with the reason) and output
//   - the decision follows that intent (prev)
//   - the result record, when present, is signed by the gateway, binds the same decision
//     and follows the decision record (prev)
//
// What this does not establish: that a payment settled on any real rail, that the
// gateway's budget counters were correct before the decision, or that the gateway applied
// its checks honestly. It establishes what the gateway received, what it decided and why
// it says it decided that, all under its signature.

import { readFileSync } from 'node:fs'
import {
  computeActionRefV2, computePayloadRefV1, verifyReceiptV1, verifyReceiptWithDecisionV1,
} from 'agent-passport-system'
import type { ActionReferenceInputV2, ReceiptV1 } from 'agent-passport-system'
import type { DecisionEvidence, PaymentPayload } from './gateway.ts'

export interface RecordBundle {
  label: string
  input: ActionReferenceInputV2
  payload: PaymentPayload
  intent: ReceiptV1
  decision: ReceiptV1
  evidence: DecisionEvidence
  result?: ReceiptV1
}

export interface BundleCheck {
  label: string
  ok: boolean
  verdict?: string
  reason?: string
  result_status?: string
  errors: string[]
}

export function verifyBundle(b: RecordBundle, publicKeys: Record<string, string>, gatewayId: string): BundleCheck {
  const errors: string[] = []
  const resolve = (signer: string, keyId: string): string | undefined => (keyId === 'key' ? publicKeys[signer] : undefined)
  let actionRef = ''
  try {
    if (computePayloadRefV1(b.payload) !== b.input.payload_ref) errors.push('payload_ref_mismatch')
    actionRef = computeActionRefV2(b.input)
  } catch {
    errors.push('action_ref_input_invalid')
  }
  for (const [name, r] of [['intent', b.intent], ['decision', b.decision], ['result', b.result]] as const) {
    if (r && r.action_ref !== actionRef) errors.push(`${name}_action_ref_mismatch`)
  }
  const iv = verifyReceiptV1(b.intent, resolve, { expectedReceiptType: 'aps:action-intent:v1' })
  if (iv.status !== 'valid') errors.push(`intent_${iv.status}`)
  if (b.intent.issuer !== b.input.agent_id) errors.push('intent_not_from_agent')

  if (b.decision.issuer !== gatewayId) errors.push('decision_not_from_gateway')
  const dv = verifyReceiptWithDecisionV1(b.decision, b.evidence, resolve, {
    expectedReceiptType: 'aps:policy-decision:v1', boundaryIdentity: gatewayId,
  })
  if (dv.status !== 'valid') errors.push(`decision_${dv.status}`, ...dv.errors)
  if (b.decision.prev !== b.intent.receipt_id) errors.push('decision_does_not_follow_intent')

  if (b.result) {
    if (b.result.issuer !== gatewayId) errors.push('result_not_from_gateway')
    const rv = verifyReceiptWithDecisionV1(b.result, b.evidence, resolve, {
      expectedReceiptType: 'aps:action-result:v1', boundaryIdentity: gatewayId, predecessor: b.decision,
    })
    if (rv.status !== 'valid') errors.push(`result_${rv.status}`, ...rv.errors)
  }
  return {
    label: b.label,
    ok: errors.length === 0,
    verdict: (b.decision.result as { verdict?: string }).verdict,
    reason: b.evidence.decision_context.reason,
    result_status: (b.result?.result as { status?: string } | undefined)?.status,
    errors,
  }
}

function main(receiptsPath: string, keysPath: string): number {
  const { gateway, bundles } = JSON.parse(readFileSync(receiptsPath, 'utf8')) as { gateway: string; bundles: RecordBundle[] }
  const publicKeys = JSON.parse(readFileSync(keysPath, 'utf8')) as Record<string, string>
  let failed = 0
  for (const b of bundles) {
    const c = verifyBundle(b, publicKeys, gateway)
    if (!c.ok) failed++
    const tail = c.result_status ? `, result ${c.result_status}` : ''
    console.log(`${c.ok ? 'VALID  ' : 'INVALID'} ${c.label}: ${c.verdict} (${c.reason})${tail}${c.ok ? '' : ' :: ' + c.errors.join(', ')}`)
  }
  console.log(`${bundles.length - failed} of ${bundles.length} record bundles verified`)
  return failed === 0 ? 0 : 1
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [receipts, keys] = process.argv.slice(2)
  if (!receipts || !keys) {
    console.error('usage: verify.ts <receipts.json> <public-keys.json>')
    process.exit(2)
  }
  process.exit(main(receipts, keys))
}
