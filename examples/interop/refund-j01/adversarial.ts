// TEST-ONLY helper. Builds tampered copies of a J01 bundle for the adversarial cases.
// It re-signs with the test keys derived from --seed where a case needs a validly signed
// but wrong record. It is not a producer and nothing it writes is a J01 input.
//
// Usage: node_modules/.bin/tsx examples/interop/refund-j01/adversarial.ts \
//   --base <bundle> --out <dir> --seed <test seed> --case <name> --rehash-manifest <yes|no>
//
// --rehash-manifest yes models an attacker who also controls MANIFEST: file hashes and
// approval_ref / merchant_decision_id are recomputed, so check 1 passes and the semantic
// check under test is isolated. no leaves MANIFEST as produced.
import { cpSync, readFileSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { buildDecisionRefV1, createReceiptV1, computeActionRefV2 } from '../../../dist/src/index.js'
import type { ActionReferenceInputV2, CoreDecisionOutputV1, ReceiptV1 } from '../../../dist/src/index.js'
import type { JsonValue } from '../../../dist/src/v2/receipt-core/types.js'
import { parseStrictIJson, strictJCS } from '../../../dist/src/v2/receipt-core/jcs.js'
import { BOUNDARY, BOUNDARY_KEY_ID, INPUT_FILES, SUBJECT, WORKER_KEY_ID, deriveTestKey, fileRef, parseArgs } from './common.ts'

type Obj = Record<string, unknown>
const CASES = ['amount-4001', 'decision-id-replaced', 'prev-other-intent', 'verdict-deny', 'duplicate-member', 'signer-revoked', 'none'] as const

function resign(fields: ReceiptV1, signer: string, keyId: string, priv: string): ReceiptV1 {
  const { receipt_id: _id, signatures: _sigs, ...rest } = fields
  return createReceiptV1(rest, [{ signer, key_id: keyId, private_key: priv }])
}

function main(): void {
  const a = parseArgs(process.argv.slice(2))
  const kase = a.case as (typeof CASES)[number]
  if (!CASES.includes(kase)) throw new Error(`--case must be one of ${CASES.join(', ')}`)
  if (a['rehash-manifest'] !== 'yes' && a['rehash-manifest'] !== 'no') throw new Error('--rehash-manifest yes|no')
  const base = resolve(a.base), out = resolve(a.out)
  cpSync(base, out, { recursive: true, errorOnExist: true, force: false })
  const read = (p: string) => readFileSync(join(out, p), 'utf8')
  const write = (p: string, s: string) => writeFileSync(join(out, p), s)
  const boundaryKey = deriveTestKey(a.seed, 'approval-boundary')
  const workerKey = deriveTestKey(a.seed, 'acting-agent')

  if (kase === 'amount-4001') {
    write('inputs/aps-payload.json', read('inputs/aps-payload.json').replace('"amount_minor":4000', '"amount_minor":4001'))
  } else if (kase === 'duplicate-member') {
    write('inputs/aps-payload.json', '{"payment_id":"pay_A","amount_minor":4000,"amount_minor":4001,"currency":"EUR"}')
  } else if (kase === 'decision-id-replaced') {
    const ev = parseStrictIJson(read('inputs/decision-evidence.json')) as Obj
    ((ev.policy_input as Obj).merchant_decision as Obj).decision_id = 'mdec_FORGED'
    write('inputs/decision-evidence.json', strictJCS(ev))
  } else if (kase === 'prev-other-intent') {
    // A second, validly signed intent for the same action, issued 1 ms earlier, so it has a
    // different receipt_id. The approval is re-signed by the boundary test key naming it.
    // aps-intent.json stays the original intent.
    const intent = parseStrictIJson(read('inputs/aps-intent.json')) as unknown as ReceiptV1
    const other = resign({ ...intent, issued_at: new Date(Date.parse(intent.issued_at) - 1).toISOString() }, SUBJECT, WORKER_KEY_ID, workerKey.privateKey)
    const approval = parseStrictIJson(read('inputs/aps-approval.json')) as unknown as ReceiptV1
    write('inputs/aps-approval.json', strictJCS(resign({ ...approval, prev: other.receipt_id }, BOUNDARY, BOUNDARY_KEY_ID, boundaryKey.privateKey)))
  } else if (kase === 'verdict-deny') {
    const ev = parseStrictIJson(read('inputs/decision-evidence.json')) as Obj
    const deny: CoreDecisionOutputV1 = { profile: 'aps-core-decision-output-v1', verdict: 'deny', effective_authority_ref: null, constraints: [], valid_until: null }
    ev.decision_output = deny
    const action = parseStrictIJson(read('inputs/aps-action.json')) as unknown as ActionReferenceInputV2
    const { decision_ref } = buildDecisionRefV1({
      action_ref: computeActionRefV2(action), authority_state: ev.authority_state as JsonValue,
      policy_input: ev.policy_input as JsonValue, decision_context: ev.decision_context as JsonValue, decision_output: deny,
    })
    const approval = parseStrictIJson(read('inputs/aps-approval.json')) as unknown as ReceiptV1
    write('inputs/decision-evidence.json', strictJCS(ev))
    write('inputs/aps-approval.json', strictJCS(resign({ ...approval, decision_ref, result: deny as unknown as { [k: string]: JsonValue } },
      BOUNDARY, BOUNDARY_KEY_ID, boundaryKey.privateKey)))
  } else if (kase === 'signer-revoked') {
    const trust = parseStrictIJson(read('trust/aps-consumption.json')) as Obj
    for (const k of trust.keys as Obj[]) if (k.signer === BOUNDARY && k.key_id === BOUNDARY_KEY_ID) k.revoked_at = a['revoked-at'] ?? '2026-10-27T18:04:00.000Z'
    write('trust/aps-consumption.json', strictJCS(trust))
  }

  if (a['rehash-manifest'] === 'yes') {
    const m = JSON.parse(read('MANIFEST.json')) as Obj
    m.files = (INPUT_FILES as readonly string[]).map(p => {
      const b = readFileSync(join(out, p))
      return { path: p, sha256: fileRef(b), bytes: b.length }
    })
    try { m.approval_ref = (JSON.parse(read('inputs/aps-approval.json')) as Obj).receipt_id } catch { /* unparseable stays */ }
    try {
      const ev = JSON.parse(read('inputs/decision-evidence.json')) as Obj
      m.merchant_decision_id = ((ev.policy_input as Obj).merchant_decision as Obj).decision_id
    } catch { /* unparseable stays */ }
    m.adversarial_case = `${kase} (TEST-ONLY tampered copy, manifest rehashed)`
    write('MANIFEST.json', JSON.stringify(m, null, 2) + '\n')
  }
  process.stdout.write(`wrote ${out} case=${kase} rehash-manifest=${a['rehash-manifest']}\n`)
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { main() } catch (e) { process.stderr.write(`adversarial: ${e instanceof Error ? e.message : String(e)}\n`); process.exit(2) }
}
