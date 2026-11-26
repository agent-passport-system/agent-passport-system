// J01 verifier for the APS-side inputs of contract review-2026-10-23 section 3.
//
// Usage (from the worktree root, after npm run build):
//   node_modules/.bin/tsx examples/interop/refund-j01/verify.ts --bundle <dir> --at <UTC ms>
//     [--trust <path>]   default <bundle>/trust/aps-consumption.json
//
// Each file is read once into a buffer. That buffer is hashed for check 1 and decoded and
// strictly parsed for every later check, so the bytes hashed are the bytes verified.
// Every check runs and is reported on its own; a check whose inputs could not be parsed is
// reported as failed with reason not_run. Exit 0 only when all nine pass, 1 otherwise,
// 2 on a usage error.
//
// Check 9 judges time and revocation against SUPPLIED trust input at a SUPPLIED instant.
// It is not a live revocation lookup.
import { readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import {
  buildDecisionRefV1, computeActionRefV2, computePayloadRefV1, parseActionReferenceInputV2,
  validateCoreDecisionOutputV1, verifyReceiptV1, verifyReceiptWithDecisionV1,
} from '../../../dist/src/index.js'
import type { ActionReferenceInputV2, CoreDecisionOutputV1, DecisionEvidenceV1, ReceiptV1 } from '../../../dist/src/index.js'
import type { JsonValue } from '../../../dist/src/v2/receipt-core/types.js'
import { parseStrictIJson, strictJCS } from '../../../dist/src/v2/receipt-core/jcs.js'
import {
  ACTION_TYPE, BOUNDARY, INPUT_FILES, SCOPE_REQUIRED, SUBJECT, fileRef, parseArgs, parseUtcMs,
  refundSchemaViolations, refundTarget,
} from './common.ts'

export interface CheckResult { id: number; name: string; pass: boolean; details: string[] }

interface TrustKey { signer: string; key_id: string; role: string; alg: string; public_key: string; valid_from: string; valid_until: string }
interface Trust {
  expected_boundary_identity: string
  expected_subject: string
  keys: TrustKey[]
  revocation: { revoked_keys: { signer: string; key_id: string; revoked_at: string }[] }
}

const CHECK_NAMES: Record<number, string> = {
  1: 'file_hashes_match_manifest',
  2: 'strict_parse_all_inputs',
  3: 'approval_native_validity_composite',
  4: 'approval_verdict_permit',
  5: 'intent_linkage',
  6: 'action_and_payload_binding',
  7: 'decision_ref_recomputed',
  8: 'merchant_decision_id_present',
  9: 'time_and_revocation_at_instant',
}

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v)
const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e))

/** Key resolver restricted to one role, honouring key validity at the receipt's issued_at.
 *  Revocation is NOT applied here: native validity is judged at issuance, revocation at the
 *  verification instant in check 9, so the two outcomes stay separate. */
function resolverFor(trust: Trust, role: string) {
  return (signer: string, keyId: string, issuedAt: string): string | undefined => {
    const k = trust.keys.find(e => e.signer === signer && e.key_id === keyId && e.role === role && e.alg === 'Ed25519')
    if (!k) return undefined
    let t: number, from: number, until: number
    try {
      t = parseUtcMs(issuedAt, 'issued_at'); from = parseUtcMs(k.valid_from, 'valid_from'); until = parseUtcMs(k.valid_until, 'valid_until')
    } catch { return undefined }
    return from <= t && t < until ? k.public_key : undefined
  }
}

// Reads trust/aps-consumption.json in the door's hs-aps-consumption-trust/0.1 shape into the
// internal form the checks use. Any other shape returns undefined (checks report "not run").
// Roles: worker maps to acting-agent. not_after null means no upper bound. revoked_at becomes a
// supplied revocation entry.
function normalizeTrust(raw: unknown): Trust | undefined {
  if (!isObj(raw) || raw.schema !== 'hs-aps-consumption-trust/0.1' || raw.profile !== 'aps-receipt-v1') return undefined
  const keys = Array.isArray(raw.keys) ? raw.keys : []
  const out: Trust = { expected_boundary_identity: BOUNDARY, expected_subject: SUBJECT, keys: [], revocation: { revoked_keys: [] } }
  for (const k of keys) {
    if (!isObj(k) || typeof k.signer !== 'string' || typeof k.key_id !== 'string' || typeof k.public_key !== 'string' || typeof k.not_before !== 'string') return undefined
    const role = k.role === 'worker' ? 'acting-agent' : k.role === 'approval-boundary' ? 'approval-boundary' : undefined
    if (!role) return undefined
    out.keys.push({ signer: k.signer, key_id: k.key_id, role, alg: 'Ed25519', public_key: k.public_key,
      valid_from: k.not_before, valid_until: typeof k.not_after === 'string' ? k.not_after : '9999-12-31T23:59:59.999Z' })
    if (typeof k.revoked_at === 'string') out.revocation.revoked_keys.push({ signer: k.signer, key_id: k.key_id, revoked_at: k.revoked_at })
  }
  return out
}

export function verifyBundle(bundleDir: string, atArg: string, trustPath?: string): CheckResult[] {
  const results = new Map<number, CheckResult>()
  const put = (id: number, pass: boolean, details: string[]) => results.set(id, { id, name: CHECK_NAMES[id], pass, details })
  const notRun = (id: number, why: string) => put(id, false, [`not_run: ${why}`])

  // Read every file exactly once.
  const raw = new Map<string, Buffer>()
  const readErr: string[] = []
  const tPath = trustPath ? resolve(trustPath) : join(bundleDir, 'trust/aps-consumption.json')
  for (const p of INPUT_FILES) {
    const full = p === 'trust/aps-consumption.json' ? tPath : join(bundleDir, p)
    try { raw.set(p, readFileSync(full)) } catch (e) { readErr.push(`${p}: ${errMsg(e)}`) }
  }
  let manifestBuf: Buffer | undefined
  try { manifestBuf = readFileSync(join(bundleDir, 'MANIFEST.json')) } catch (e) { readErr.push(`MANIFEST.json: ${errMsg(e)}`) }

  // ---- Check 2 first in code order: decode and strictly parse the retained buffers. ----
  const decoder = new TextDecoder('utf-8', { fatal: true })
  const parsed = new Map<string, unknown>()
  const c2: string[] = [...readErr.map(e => `read failed: ${e}`)]
  let c2ok = readErr.length === 0
  const parseOne = (name: string, buf: Buffer | undefined, fn: (s: string) => unknown) => {
    if (!buf) return
    try {
      const v = fn(decoder.decode(buf))
      parsed.set(name, v)
      c2.push(`${name}: ok`)
    } catch (e) { c2ok = false; c2.push(`${name}: REJECTED ${errMsg(e)}`) }
  }
  for (const p of INPUT_FILES) {
    parseOne(p, raw.get(p), p === 'inputs/aps-action.json' ? s => parseActionReferenceInputV2(s) : s => parseStrictIJson(s))
  }
  parseOne('MANIFEST.json', manifestBuf, s => parseStrictIJson(s))
  put(2, c2ok, c2)

  const manifest = parsed.get('MANIFEST.json') as Record<string, unknown> | undefined
  const intent = parsed.get('inputs/aps-intent.json') as ReceiptV1 | undefined
  const approval = parsed.get('inputs/aps-approval.json') as ReceiptV1 | undefined
  const action = parsed.get('inputs/aps-action.json') as ActionReferenceInputV2 | undefined
  const payload = parsed.get('inputs/aps-payload.json') as unknown
  const evidence = parsed.get('inputs/decision-evidence.json') as Record<string, unknown> | undefined
  const trust = normalizeTrust(parsed.get('trust/aps-consumption.json'))

  // ---- Check 1: file hashes equal MANIFEST, and MANIFEST's identifiers match the files. ----
  if (!manifest || !Array.isArray(manifest.files)) notRun(1, 'MANIFEST.json missing or unparsed')
  else {
    const d: string[] = []
    let ok = true
    const listed = new Map<string, string>()
    for (const f of manifest.files as unknown[]) if (isObj(f) && typeof f.path === 'string' && typeof f.sha256 === 'string') listed.set(f.path, f.sha256)
    const expected = [...INPUT_FILES].sort().join(',')
    if ([...listed.keys()].sort().join(',') !== expected) { ok = false; d.push(`manifest file set differs from ${expected}`) }
    for (const p of INPUT_FILES) {
      const buf = raw.get(p)
      if (!buf) { ok = false; d.push(`${p}: missing`); continue }
      const got = fileRef(buf)
      const want = listed.get(p)
      const m = got === want
      ok &&= m
      d.push(`${p}: ${m ? 'match' : 'MISMATCH'} ${got}${m ? '' : ` (manifest ${want})`}`)
    }
    if (approval) {
      const m = manifest.approval_ref === approval.receipt_id && /^[0-9a-f]{64}$/.test(String(manifest.approval_ref))
      ok &&= m; d.push(`manifest approval_ref ${m ? 'equals' : 'DIFFERS FROM'} approval.receipt_id (64 lowercase hex, no prefix)`)
    }
    put(1, ok, d)
  }

  // ---- Check 3: composite native validity of the approval with its decision evidence. ----
  if (!approval || !evidence || !trust) notRun(3, 'approval, decision-evidence or trust unparsed')
  else {
    const d: string[] = []
    const keys = Object.keys(evidence).sort().join(',')
    let ok = keys === 'authority_state,decision_context,decision_output,policy_input'
    d.push(`decision-evidence members: ${keys}${ok ? '' : ' (MUST be exactly the four DecisionEvidenceV1 components)'}`)
    const boundaryOk = trust.expected_boundary_identity === BOUNDARY
    ok &&= boundaryOk
    d.push(`trust expected_boundary_identity ${boundaryOk ? 'equals' : 'DIFFERS FROM'} profile ${BOUNDARY}`)
    const v = verifyReceiptWithDecisionV1(approval, evidence as unknown as DecisionEvidenceV1, resolverFor(trust, 'approval-boundary'),
      { expectedReceiptType: 'aps:policy-decision:v1', boundaryIdentity: BOUNDARY })
    ok &&= v.valid && v.status === 'valid'
    d.push(`verifyReceiptWithDecisionV1 status=${v.status} valid=${v.valid}`,
      `receipt_id_valid=${v.receipt.receipt_id_valid} signer_authority=${v.receipt.signer_authority} boundary_identity=${v.stage.boundary_identity}`,
      `decision_ref_bound=${v.decision_ref_bound} decision_output_bound=${v.decision_output_bound} temporal_relation_valid=${v.temporal_relation_valid}`,
      `predecessor_bound=${v.predecessor_bound} (SDK predecessor axis covers action-result only; intent link is check 5)`)
    if (v.errors.length) d.push(`errors: ${v.errors.join(', ')}`)
    put(3, ok, d)
  }

  // ---- Check 4: verdict is permit, judged apart from native validity. ----
  if (!approval) notRun(4, 'approval unparsed')
  else {
    const verdict = isObj(approval.result) ? approval.result.verdict : undefined
    const evVerdict = evidence && isObj(evidence.decision_output) ? evidence.decision_output.verdict : undefined
    const ok = verdict === 'permit' && evVerdict === 'permit'
    put(4, ok, [`approval.result.verdict=${String(verdict)}`, `decision_output.verdict=${String(evVerdict)}`,
      'profile accepts permit only; narrow is refused because no constraint is enforced, deny is terminal'])
  }

  // ---- Check 5: approval.prev names this intent, and the intent verifies on its own. ----
  if (!approval || !intent || !trust || !action) notRun(5, 'approval, intent, action or trust unparsed')
  else {
    const d: string[] = []
    let ok = true
    const step = (cond: boolean, msg: string) => { ok &&= cond; d.push(`${cond ? 'ok' : 'FAIL'} ${msg}`) }
    const iv = verifyReceiptV1(intent, resolverFor(trust, 'acting-agent'), { expectedReceiptType: 'aps:action-intent:v1' })
    step(iv.valid && iv.status === 'valid', `intent verifyReceiptV1 status=${iv.status} receipt_id_valid=${iv.receipt_id_valid} signer_authority=${iv.signer_authority}${iv.errors.length ? ' errors=' + iv.errors.join(',') : ''}`)
    const stage = iv.stage === 'not_checked' ? 'not_checked' : iv.stage.stage
    step(intent.receipt_type === 'aps:action-intent:v1' && stage === 'action-intent', `intent stage/type ${intent.receipt_type} / ${stage}`)
    step(intent.issuer === SUBJECT && intent.subject_agent === SUBJECT, `intent issuer and subject_agent are ${SUBJECT}`)
    step(intent.signatures.some(s => s.signer === SUBJECT), 'intent carries the acting agent signature')
    step(approval.prev === intent.receipt_id, `approval.prev ${approval.prev} equals intent.receipt_id ${intent.receipt_id}`)
    step(approval.subject_agent === intent.subject_agent && approval.subject_agent === SUBJECT, 'approval.subject_agent equals intent subject')
    step(intent.action_ref === approval.action_ref, 'intent.action_ref equals approval.action_ref')
    let recomputed = ''
    try { recomputed = computeActionRefV2(action) } catch (e) { d.push(`action_ref recompute failed: ${errMsg(e)}`) }
    step(recomputed !== '' && intent.action_ref === recomputed, 'intent.action_ref equals action_ref recomputed from aps-action.json')
    step(action.agent_id === intent.subject_agent, 'aps-action.json agent_id equals intent subject')
    step(intent.delegation_ref === approval.delegation_ref, 'intent.delegation_ref equals approval.delegation_ref')
    put(5, ok, d)
  }

  // ---- Check 6: action and payload. ----
  if (!approval || !action || payload === undefined) notRun(6, 'approval, action or payload unparsed')
  else {
    const d: string[] = []
    let ok = true
    const step = (cond: boolean, msg: string) => { ok &&= cond; d.push(`${cond ? 'ok' : 'FAIL'} ${msg}`) }
    let actionRef = ''
    try { actionRef = computeActionRefV2(action) } catch (e) { d.push(`computeActionRefV2 threw: ${errMsg(e)}`) }
    step(actionRef !== '' && actionRef === approval.action_ref, `action_ref recomputed ${actionRef} equals approval.action_ref`)
    step(action.action_type === ACTION_TYPE, `action_type is "${ACTION_TYPE}"`)
    step(JSON.stringify(action.scope_required) === JSON.stringify(SCOPE_REQUIRED), `scope_required is exactly ${JSON.stringify(SCOPE_REQUIRED)}`)
    step(action.agent_id === SUBJECT, `agent_id is ${SUBJECT}`)
    const violations = refundSchemaViolations(payload)
    step(violations.length === 0, `payload closed refund schema${violations.length ? ': ' + violations.join('; ') : ''}`)
    const pid = isObj(payload) ? payload.payment_id : undefined
    step(typeof pid === 'string' && action.target === refundTarget(pid), `target equals ${typeof pid === 'string' ? refundTarget(pid) : '(no payment_id)'}`)
    let payloadRef = ''
    try { payloadRef = computePayloadRefV1(payload) } catch (e) { d.push(`computePayloadRefV1 threw: ${errMsg(e)}`) }
    step(payloadRef !== '' && payloadRef === action.payload_ref, `payload_ref computePayloadRefV1(aps-payload.json)=${payloadRef} equals action.payload_ref ${action.payload_ref}`)
    const approved = evidence && isObj(evidence.policy_input) && isObj(evidence.policy_input.merchant_decision)
      ? evidence.policy_input.merchant_decision.approved_refund : undefined
    let same = false
    try { same = approved !== undefined && strictJCS(approved) === strictJCS(payload) } catch { same = false }
    step(same, 'payload equals policy_input.merchant_decision.approved_refund (JCS)')
    put(6, ok, d)
  }

  // ---- Check 7: decision_ref recomputed from the four components. ----
  if (!approval || !evidence || !action) notRun(7, 'approval, decision-evidence or action unparsed')
  else {
    const d: string[] = []
    let ok = true
    try {
      const out: CoreDecisionOutputV1 = validateCoreDecisionOutputV1(evidence.decision_output)
      // action_ref from aps-action.json, independently of the receipt's own field.
      const { decision_ref } = buildDecisionRefV1({
        action_ref: computeActionRefV2(action),
        authority_state: evidence.authority_state as JsonValue,
        policy_input: evidence.policy_input as JsonValue,
        decision_context: evidence.decision_context as JsonValue,
        decision_output: out,
      })
      const m = decision_ref === approval.decision_ref
      ok &&= m
      d.push(`${m ? 'ok' : 'FAIL'} recomputed decision_ref ${decision_ref} ${m ? 'equals' : 'DIFFERS FROM'} approval.decision_ref ${approval.decision_ref}`)
      const outEq = strictJCS(approval.result) === strictJCS(out as unknown as JsonValue)
      ok &&= outEq
      d.push(`${outEq ? 'ok' : 'FAIL'} decision_output equals approval.result (JCS)`)
    } catch (e) { ok = false; d.push(`FAIL ${errMsg(e)}`) }
    put(7, ok, d)
  }

  // ---- Check 8: merchant decision_id at the fixed path. ----
  if (!evidence) notRun(8, 'decision-evidence unparsed')
  else {
    const md = isObj(evidence.policy_input) && isObj(evidence.policy_input.merchant_decision) ? evidence.policy_input.merchant_decision : undefined
    const id = md?.decision_id
    const present = typeof id === 'string' && id !== ''
    const d = [`policy_input.merchant_decision.decision_id = ${JSON.stringify(id)}`]
    let ok = present
    if (manifest) {
      const m = manifest.merchant_decision_id === id
      ok &&= m
      d.push(`${m ? 'equals' : 'DIFFERS FROM'} MANIFEST merchant_decision_id ${JSON.stringify(manifest.merchant_decision_id)}`)
    }
    put(8, ok, d)
  }

  // ---- Check 9: time and revocation at the supplied verification instant. ----
  if (!approval || !trust) notRun(9, 'approval or trust unparsed')
  else {
    const d: string[] = ['scope: supplied trust input at a supplied instant; NOT a live revocation check']
    let ok = true
    const step = (cond: boolean, msg: string) => { ok &&= cond; d.push(`${cond ? 'ok' : 'FAIL'} ${msg}`) }
    try {
      const at = parseUtcMs(atArg, 'verification instant')
      d.push(`verification instant ${atArg}`)
      const issued = parseUtcMs(approval.issued_at, 'approval.issued_at')
      const vu = isObj(approval.result) ? approval.result.valid_until : undefined
      if (typeof vu !== 'string') step(false, `approval.result.valid_until is ${JSON.stringify(vu)}; no validity window`)
      else {
        const until = parseUtcMs(vu, 'approval.result.valid_until')
        step(issued <= at, `issued_at ${approval.issued_at} <= instant`)
        step(at < until, `instant < valid_until ${vu} (exclusive; equality refused; full millisecond precision)`)
      }
      const sig = approval.signatures.find(s => s.signer === approval.issuer)
      const key = sig && trust.keys.find(k => k.signer === sig.signer && k.key_id === sig.key_id && k.role === 'approval-boundary')
      if (!key) step(false, 'approval signer key not in trust input')
      else {
        const from = parseUtcMs(key.valid_from, 'key.valid_from'), until = parseUtcMs(key.valid_until, 'key.valid_until')
        step(from <= at && at < until, `approval signer key ${key.key_id} valid at instant [${key.valid_from}, ${key.valid_until})`)
        const revs = (trust.revocation?.revoked_keys ?? []).filter(r => r.signer === key.signer && r.key_id === key.key_id)
        const effective = revs.filter(r => parseUtcMs(r.revoked_at, 'revoked_at') <= at)
        step(effective.length === 0, `approval signer key not revoked at instant (supplied revoked_keys entries for it: ${revs.length}, effective: ${effective.length})`)
      }
    } catch (e) { step(false, errMsg(e)) }
    put(9, ok, d)
  }

  return [...results.values()].sort((a, b) => a.id - b.id)
}

function main(): void {
  let a: Record<string, string>
  try { a = parseArgs(process.argv.slice(2)) } catch (e) { process.stderr.write(`verify: ${errMsg(e)}\n`); process.exit(2) }
  if (!a.bundle || !a.at) { process.stderr.write('verify: --bundle and --at are required\n'); process.exit(2) }
  const results = verifyBundle(resolve(a.bundle), a.at, a.trust)
  for (const r of results) {
    process.stdout.write(`[${r.pass ? 'PASS' : 'FAIL'}] ${r.id}. ${r.name}\n`)
    for (const line of r.details) process.stdout.write(`       ${line}\n`)
  }
  const failed = results.filter(r => !r.pass)
  process.stdout.write(`RESULT ${failed.length === 0 ? 'PASS' : 'FAIL'} failed_checks=${failed.map(r => r.name).join(',') || 'none'}\n`)
  process.exit(failed.length === 0 ? 0 : 1)
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) main()
