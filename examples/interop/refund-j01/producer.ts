// J01 producer: emits the APS-side native inputs of contract review-2026-10-23 section 3
// for one exact refund, plus the APS consumption trust input and a MANIFEST.
//
// OFFLINE TEST FIXTURE. Keys are test keys derived from --seed. No live payment system.
//
// Usage (from the worktree root, after npm run build):
//   node_modules/.bin/tsx examples/interop/refund-j01/producer.ts \
//     --out <dir> --run-label <label> --fixture-status <demo|final> \
//     --issued-at <UTC ms> --valid-until <UTC ms> --seed <test seed> --decision-id <id>
//     [--intent-issued-at <UTC ms>] [--key-valid-from <UTC ms>] [--key-valid-until <UTC ms>]
//
// Every file is serialized once, written once with O_EXCL (an existing file is refused),
// and hashed from the same bytes that were written.
import { mkdirSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import {
  buildDecisionRefV1, computeActionRefV2, computePayloadRefV1, createActionReferenceInputV2,
  createReceiptV1, validateCoreDecisionOutputV1,
} from '../../../dist/src/index.js'
import type { CoreDecisionOutputV1, ReceiptV1 } from '../../../dist/src/index.js'
import type { JsonValue } from '../../../dist/src/v2/receipt-core/types.js'
import { strictJCS } from '../../../dist/src/v2/receipt-core/jcs.js'
import {
  ACTION_TYPE, BOUNDARY, BOUNDARY_KEY_ID, CONTRACT_REVISION, INPUT_FILES, KEY_DERIVATION, PAYLOAD_BYTES,
  SCOPE_REQUIRED, SDK_COMMIT, SDK_TAG, SUBJECT, WORKER_KEY_ID, deriveNonce, deriveTestKey, fileRef,
  parseArgs, parseUtcMs, refundSchemaViolations, refundTarget, sha256Hex,
} from './common.ts'

export interface ProduceOptions {
  runLabel: string
  fixtureStatus: 'demo' | 'final'
  issuedAt: string
  validUntil: string
  intentIssuedAt: string
  keyValidFrom: string
  keyValidUntil: string
  seed: string
  decisionId: string
}

/** Synthetic values that the receipt format requires and this fixture does not bind to
 *  anything: no AuthorityDelegationV1 leaf exists for delegation_ref, and
 *  effective_authority_ref names no evaluated authority. Stated in the README. */
const DELEGATION_REF = 'sha256:' + sha256Hex('j01-193 synthetic delegation leaf (test fixture, no AuthorityDelegationV1 exists)')
const EFFECTIVE_AUTHORITY_REF = sha256Hex('j01-193 synthetic effective authority (test fixture)')

/** Build every artifact in memory. Pure function of the options. */
export function buildJ01(o: ProduceOptions) {
  const issuedMs = parseUtcMs(o.issuedAt, 'issued_at')
  const untilMs = parseUtcMs(o.validUntil, 'valid_until')
  const intentMs = parseUtcMs(o.intentIssuedAt, 'intent_issued_at')
  const keyFromMs = parseUtcMs(o.keyValidFrom, 'key_valid_from')
  const keyUntilMs = parseUtcMs(o.keyValidUntil, 'key_valid_until')
  if (!(untilMs > issuedMs)) throw new Error('valid_until must be later than issued_at')
  if (intentMs > issuedMs) throw new Error('intent_issued_at must not be later than issued_at')
  if (!(keyFromMs <= intentMs && untilMs <= keyUntilMs)) {
    throw new Error('test key validity must cover intent issuance through approval valid_until')
  }
  if (o.decisionId === '') throw new Error('decision_id must be nonempty')

  const boundaryKey = deriveTestKey(o.seed, 'approval-boundary')
  const workerKey = deriveTestKey(o.seed, 'acting-agent')

  const payload = JSON.parse(PAYLOAD_BYTES) as { payment_id: string; amount_minor: number; currency: string }
  const violations = refundSchemaViolations(payload)
  if (violations.length) throw new Error(`payload: ${violations.join('; ')}`)

  const action = createActionReferenceInputV2({
    agent_id: SUBJECT,
    action_type: ACTION_TYPE,
    target: refundTarget(payload.payment_id),
    payload_ref: computePayloadRefV1(payload),
    scope_required: [...SCOPE_REQUIRED],
    issued_at: o.intentIssuedAt,
    nonce: deriveNonce(o.seed, o.runLabel),
  })
  const action_ref = computeActionRefV2(action)

  const intent: ReceiptV1 = createReceiptV1({
    profile: 'aps-receipt-v1', receipt_type: 'aps:action-intent:v1', issuer: SUBJECT, subject_agent: SUBJECT,
    action_ref, delegation_ref: DELEGATION_REF, issued_at: o.intentIssuedAt, evidence_refs: [],
    result: { profile: 'aps-action-intent-result-v1', status: 'declared' },
  }, [{ signer: SUBJECT, key_id: WORKER_KEY_ID, private_key: workerKey.privateKey }])

  const decision_output: CoreDecisionOutputV1 = validateCoreDecisionOutputV1({
    profile: 'aps-core-decision-output-v1', verdict: 'permit',
    effective_authority_ref: EFFECTIVE_AUTHORITY_REF, constraints: [], valid_until: o.validUntil,
  })
  const decisionEvidence = {
    authority_state: {
      fixture: 'refund-sandbox J01 synthetic authority state',
      subject: SUBJECT,
      delegation_ref: DELEGATION_REF,
      scope_granted: [...SCOPE_REQUIRED],
    },
    policy_input: {
      merchant_decision: {
        decision_id: o.decisionId,
        approved_refund: payload,
      },
      policy: 'refund-sandbox exact refund, permit only',
    },
    decision_context: {
      contract_revision: CONTRACT_REVISION,
      case: 'J01',
      run_label: o.runLabel,
      fixture_status: o.fixtureStatus,
    },
    decision_output,
  }
  const { decision_ref } = buildDecisionRefV1({ action_ref, ...decisionEvidence } as {
    action_ref: string; authority_state: JsonValue; policy_input: JsonValue; decision_context: JsonValue
    decision_output: CoreDecisionOutputV1
  })

  const approval: ReceiptV1 = createReceiptV1({
    profile: 'aps-receipt-v1', receipt_type: 'aps:policy-decision:v1', issuer: BOUNDARY, subject_agent: SUBJECT,
    action_ref, delegation_ref: DELEGATION_REF, decision_ref, issued_at: o.issuedAt, evidence_refs: [],
    result: decision_output as unknown as { [key: string]: JsonValue }, prev: intent.receipt_id,
  }, [{ signer: BOUNDARY, key_id: BOUNDARY_KEY_ID, private_key: boundaryKey.privateKey }])

  // Trust input in the shape the HORIZON SHIELD admission door reads (hs-aps-consumption-trust/0.1,
  // adapter_aps_receipt.mjs step 1): exactly schema, profile, scope, keys; each key exactly signer,
  // key_id, role, public_key, not_before, not_after, revoked_at. Supplied state, not a live service.
  const trust = {
    schema: 'hs-aps-consumption-trust/0.1',
    profile: 'aps-receipt-v1',
    scope: [...SCOPE_REQUIRED],
    keys: [
      { signer: SUBJECT, key_id: WORKER_KEY_ID, role: 'worker', public_key: workerKey.publicKey,
        not_before: o.keyValidFrom, not_after: o.keyValidUntil, revoked_at: null },
      { signer: BOUNDARY, key_id: BOUNDARY_KEY_ID, role: 'approval-boundary', public_key: boundaryKey.publicKey,
        not_before: o.keyValidFrom, not_after: o.keyValidUntil, revoked_at: null },
    ],
  }

  // File bytes. JCS for every generated object; the payload keeps the request's literal bytes.
  const bytes: Record<(typeof INPUT_FILES)[number], Buffer> = {
    'inputs/aps-intent.json': Buffer.from(strictJCS(intent), 'utf8'),
    'inputs/aps-approval.json': Buffer.from(strictJCS(approval), 'utf8'),
    'inputs/aps-action.json': Buffer.from(strictJCS(action), 'utf8'),
    'inputs/aps-payload.json': Buffer.from(PAYLOAD_BYTES, 'utf8'),
    'inputs/decision-evidence.json': Buffer.from(strictJCS(decisionEvidence), 'utf8'),
    'trust/aps-consumption.json': Buffer.from(strictJCS(trust), 'utf8'),
  }
  return { bytes, intent, approval, action, action_ref, decision_ref, decisionEvidence }
}

export function manifestFor(o: ProduceOptions, built: ReturnType<typeof buildJ01>, command: string) {
  return {
    schema: 'aps-j01-fixture-manifest/0.1-draft',
    fixture_status: o.fixtureStatus === 'demo'
      ? 'DEMO. Not the agreed final generation. Validity window chosen by the producer for testing only.'
      : 'FINAL candidate. Validity window as supplied on the command line.',
    test_fixture_notice: 'OFFLINE TEST FIXTURE. Keys are test keys derived from the stated seed. Anyone with the seed can sign as these test identities. No live payment system.',
    contract_revision: CONTRACT_REVISION,
    case: 'J01',
    run_label: o.runLabel,
    sdk: { package: 'agent-passport-system', tag: SDK_TAG, commit: SDK_COMMIT },
    producer_command: command,
    test_key_derivation: { method: KEY_DERIVATION, seed: o.seed, boundary_key_id: BOUNDARY_KEY_ID, worker_key_id: WORKER_KEY_ID },
    approval_ref: built.approval.receipt_id,
    intent_receipt_id: built.intent.receipt_id,
    merchant_decision_id: o.decisionId,
    merchant_decision_id_path: 'policy_input.merchant_decision.decision_id',
    validity: { issued_at: o.issuedAt, valid_until: o.validUntil, intent_issued_at: o.intentIssuedAt },
    native_refs_informational: {
      action_ref: built.action_ref,
      payload_ref: built.action.payload_ref,
      decision_ref: built.decision_ref,
    },
    files: (INPUT_FILES as readonly string[]).map(path => ({
      path, sha256: fileRef(built.bytes[path as (typeof INPUT_FILES)[number]]),
      bytes: built.bytes[path as (typeof INPUT_FILES)[number]].length,
    })),
  }
}

/** Write each file exactly once. 'wx' refuses to overwrite an existing file. */
export function writeBundle(outDir: string, files: Record<string, Buffer>): void {
  mkdirSync(join(outDir, 'inputs'), { recursive: true })
  mkdirSync(join(outDir, 'trust'), { recursive: true })
  for (const [path, data] of Object.entries(files)) writeFileSync(join(outDir, path), data, { flag: 'wx' })
}

function main(): void {
  const a = parseArgs(process.argv.slice(2))
  for (const k of ['out', 'run-label', 'fixture-status', 'issued-at', 'valid-until', 'seed', 'decision-id']) {
    if (a[k] === undefined) throw new Error(`--${k} is required`)
  }
  if (a['fixture-status'] !== 'demo' && a['fixture-status'] !== 'final') throw new Error('--fixture-status must be demo or final')
  const o: ProduceOptions = {
    runLabel: a['run-label'],
    fixtureStatus: a['fixture-status'],
    issuedAt: a['issued-at'],
    validUntil: a['valid-until'],
    intentIssuedAt: a['intent-issued-at'] ?? a['issued-at'],
    keyValidFrom: a['key-valid-from'] ?? a['intent-issued-at'] ?? a['issued-at'],
    keyValidUntil: a['key-valid-until'] ?? a['valid-until'],
    seed: a['seed'],
    decisionId: a['decision-id'],
  }
  // The output directory is recorded as a placeholder: it is a local path, it does not
  // affect any file content, and recording it would make MANIFEST differ between runs.
  const argv = process.argv.slice(2)
  const command = 'node_modules/.bin/tsx examples/interop/refund-j01/producer.ts ' +
    argv.map((s, i) => (argv[i - 1] === '--out' ? '<out-dir>' : /^[A-Za-z0-9_.:\/@=+-]+$/.test(s) ? s : `'${s}'`)).join(' ')
  const built = buildJ01(o)
  const manifest = manifestFor(o, built, command)
  const outDir = resolve(a['out'])
  writeBundle(outDir, {
    ...built.bytes,
    'MANIFEST.json': Buffer.from(JSON.stringify(manifest, null, 2) + '\n', 'utf8'),
  })
  process.stdout.write(`wrote ${outDir}\napproval_ref ${built.approval.receipt_id}\nmerchant_decision_id ${o.decisionId}\n` +
    `valid ${o.issuedAt} .. ${o.validUntil}\n` +
    manifest.files.map(f => `${f.sha256}  ${f.path}`).join('\n') + '\n')
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { main() } catch (err) {
    process.stderr.write(`producer: ${err instanceof Error ? err.message : String(err)}\n`)
    process.exit(2)
  }
}
