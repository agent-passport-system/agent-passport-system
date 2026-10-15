// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Generates vectors.json: language-neutral cases for the 8.0.0 Cycles
// correspondence rule. A permit must cite the reserve envelope, and a release
// the release envelope, for the receipt's own reservation_id. Each case carries
// the signed receipt, the full envelope and the expected verdict, so another
// implementation can check itself without running this SDK.
//
// Keys are derived from fixed, published, test-only seeds. They protect nothing.
// receipt_id and issued_at come from the signer and change on every run, so
// regenerate only when the rule changes, then review the diff.
//
// Run: npx tsx tests/v2/payment-rails/cycles-correspondence-vectors/generate.ts

import { createHash } from 'node:crypto'
import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { publicKeyFromPrivate, sign } from '../../../../src/crypto/keys.js'
import { canonicalizeJCS } from '../../../../src/core/canonical-jcs.js'
import { sha256Hex } from '../../../../src/v2/payment-rails/canonicalize.js'
import {
  mapCyclesDenialToFoundation,
  signCyclesDenial,
  signCyclesPermitReceipt,
  signCyclesReleaseReceipt,
} from '../../../../src/v2/payment-rails/cycles/index.js'
import type { CyclesEvidenceEnvelopeInput, CyclesEvidenceView } from '../../../../src/v2/payment-rails/cycles/types.js'

const HERE = dirname(fileURLToPath(import.meta.url))
const FIXTURES = join(HERE, '..', 'cycles-fixtures')
const VECTORS = join(HERE, '..', 'cycles-evidence-vectors')

const seed = (label: string) => createHash('sha256').update(label).digest('hex')
const RECEIPT_KEY = seed('aps cycles correspondence vectors v0: receipt issuer (test only)')
const CYCLES_KEY = seed('aps cycles correspondence vectors v0: re-signed envelope (test only)')

const load = (dir: string, file: string) => JSON.parse(readFileSync(join(dir, file), 'utf-8'))
const reserve = (): CyclesEvidenceEnvelopeInput => load(FIXTURES, '02-reserve-allow.json')
const commit = (): CyclesEvidenceEnvelopeInput => load(VECTORS, '05-commit-success.json')
const release = (): CyclesEvidenceEnvelopeInput => load(VECTORS, '06-release-success.json')

function reservationOf(env: CyclesEvidenceEnvelopeInput): string {
  const p = env.payload as Record<string, any>
  const id = p.reserve?.response?.reservation_id ?? p.commit?.reservation_id ?? p.release?.reservation_id
  if (typeof id !== 'string') throw new Error('envelope names no reservation_id')
  return id
}

/** Re-sign an altered envelope so its hash and signature check out and the
 *  failure, if any, reaches the correspondence check. */
function resign(env: CyclesEvidenceEnvelopeInput): CyclesEvidenceEnvelopeInput {
  const signer_did = publicKeyFromPrivate(CYCLES_KEY)
  const evidence_id = sha256Hex(canonicalizeJCS({ ...env, signer_did, evidence_id: '', signature: '' }))
  const signature = sign(canonicalizeJCS({ ...env, signer_did, evidence_id, signature: '' }), CYCLES_KEY)
  return { ...env, signer_did, evidence_id, signature }
}

const common = {
  agent_id: 'agent-cycles-001',
  delegation_ref: 'aps:delegation:cycles-001',
  action_ref: 'aps:action:cycles-001',
}
const evidenceRef = (env: CyclesEvidenceEnvelopeInput) => ({
  cycles_evidence_url: 'https://cycles.example.com/v1/evidence/abc',
  cycles_evidence_id_sha256: env.evidence_id,
  action_ref: 'aps:action:cycles-test-001',
  delegation_ref: 'aps:delegation:cycles-test-001',
})

const permit = (env: CyclesEvidenceEnvelopeInput, reservation_id: string) =>
  signCyclesPermitReceipt(
    { ...common, reservation_id, reserved: { unit: 'USD_MICROCENTS', amount: 2000000 }, decision: 'ALLOW', cycles_evidence: evidenceRef(env) },
    RECEIPT_KEY,
  )
const releaseReceipt = (env: CyclesEvidenceEnvelopeInput, reservation_id: string) =>
  signCyclesReleaseReceipt(
    { ...common, reservation_id, released: { unit: 'TOKENS', amount: 8000 }, cycles_evidence: evidenceRef(env) },
    RECEIPT_KEY,
  )

type Expected =
  | { valid: true; evidence_authenticity: 'signature_valid' }
  | { valid: false; reason: string; detail_prefix?: string }
const ok: Expected = { valid: true, evidence_authenticity: 'signature_valid' }
const fail = (reason: string, detail_prefix?: string): Expected =>
  detail_prefix === undefined ? { valid: false, reason } : { valid: false, reason, detail_prefix }

const cases: Array<{
  id: string
  description: string
  verifier: 'permit' | 'release' | 'denial'
  receipt: unknown
  envelope: CyclesEvidenceEnvelopeInput
  expected: Expected
}> = []

{
  const env = reserve()
  cases.push({ id: 'permit-own-reserve', description: 'Permit citing the reserve envelope of its own reservation.', verifier: 'permit', receipt: permit(env, reservationOf(env)), envelope: env, expected: ok })
  cases.push({ id: 'permit-other-reservation', description: 'Permit naming another reservation, citing a reserve envelope.', verifier: 'permit', receipt: permit(env, 'rsv_some_other_reservation'), envelope: env, expected: fail('EVIDENCE_CORRESPONDENCE_MISMATCH', 'reservation_id') })
}
{
  const env = commit()
  cases.push({ id: 'permit-commit-envelope', description: 'Permit citing the commit envelope of the same reservation.', verifier: 'permit', receipt: permit(env, reservationOf(env)), envelope: env, expected: fail('EVIDENCE_CORRESPONDENCE_MISMATCH', 'artifact_type') })
  cases.push({ id: 'permit-wrong-reservation-commit-envelope', description: 'The reported probe: a permit naming WRONG-RESERVATION citing a commit envelope.', verifier: 'permit', receipt: permit(env, 'WRONG-RESERVATION'), envelope: env, expected: fail('EVIDENCE_CORRESPONDENCE_MISMATCH', 'artifact_type') })
}
{
  const base = reserve()
  const payload = structuredClone(base.payload) as { reserve: { response: Record<string, unknown> } }
  delete payload.reserve.response.reservation_id
  const env = resign({ ...base, payload })
  cases.push({ id: 'permit-reserve-envelope-without-reservation-id', description: 'Reserve envelope with no reservation_id, re-signed so hash and signature hold.', verifier: 'permit', receipt: permit(env, reservationOf(base)), envelope: env, expected: fail('EVIDENCE_CORRESPONDENCE_FIELD_MISSING', 'payload.reserve.response.reservation_id') })
}
{
  const base = reserve()
  const { artifact_type: _drop, ...rest } = base
  const env = resign(rest as CyclesEvidenceEnvelopeInput)
  cases.push({ id: 'permit-envelope-without-artifact-type', description: 'Envelope with no artifact_type, re-signed so hash and signature hold.', verifier: 'permit', receipt: permit(env, reservationOf(base)), envelope: env, expected: fail('EVIDENCE_CORRESPONDENCE_FIELD_MISSING', 'artifact_type') })
}
{
  const base = reserve()
  const env = resign({ ...base, payload: commit().payload })
  cases.push({ id: 'permit-reserve-type-commit-payload', description: 'artifact_type says reserve but the payload is a commit, re-signed so hash and signature hold.', verifier: 'permit', receipt: permit(env, reservationOf(base)), envelope: env, expected: fail('EVIDENCE_CORRESPONDENCE_MISMATCH', 'payload') })
}
{
  const env = release()
  cases.push({ id: 'release-own-release', description: 'Release citing the release envelope of its own reservation.', verifier: 'release', receipt: releaseReceipt(env, reservationOf(env)), envelope: env, expected: ok })
  cases.push({ id: 'release-other-reservation', description: 'Release naming another reservation, citing a release envelope.', verifier: 'release', receipt: releaseReceipt(env, 'rsv_some_other_reservation'), envelope: env, expected: fail('EVIDENCE_CORRESPONDENCE_MISMATCH', 'reservation_id') })
}
{
  const env = commit()
  cases.push({ id: 'release-commit-envelope', description: 'Release citing a commit envelope.', verifier: 'release', receipt: releaseReceipt(env, reservationOf(env)), envelope: env, expected: fail('EVIDENCE_CORRESPONDENCE_MISMATCH', 'artifact_type') })
}
{
  const base = release()
  const payload = structuredClone(base.payload) as { release: Record<string, unknown> }
  delete payload.release.reservation_id
  const env = resign({ ...base, payload })
  cases.push({ id: 'release-envelope-without-reservation-id', description: 'Release envelope with no reservation_id, re-signed so hash and signature hold.', verifier: 'release', receipt: releaseReceipt(env, reservationOf(base)), envelope: env, expected: fail('EVIDENCE_CORRESPONDENCE_FIELD_MISSING', 'payload.release.reservation_id') })
}
{
  const env = reserve()
  cases.push({ id: 'hash-check-runs-first', description: 'Tampered envelope: the hash check fails before correspondence is considered.', verifier: 'permit', receipt: permit(env, 'rsv_some_other_reservation'), envelope: { ...env, server_id: 'https://evil.example.com/v1' }, expected: fail('EVIDENCE_REF_HASH_MISMATCH') })
}
{
  const env = reserve()
  const mapping = mapCyclesDenialToFoundation(load(FIXTURES, '11-reserve-live-budget-exceeded.json') as CyclesEvidenceView)
  if (!mapping) throw new Error('denial fixture did not map')
  const denial = signCyclesDenial({ ...common, denial_reason: mapping.denial_reason, cycles: mapping.cycles, cycles_evidence: evidenceRef(env) }, RECEIPT_KEY)
  cases.push({ id: 'denial-not-checked', description: 'Denials get no correspondence check: a denial citing a reserve envelope verifies.', verifier: 'denial', receipt: denial, envelope: env, expected: ok })
}

const out = {
  name: 'cycles-correspondence-vectors',
  version: '0',
  sdk_rule_since: 'agent-passport-system 8.0.0',
  rule: 'With an envelope supplied, a permit receipt must cite a reserve envelope and a release receipt a release envelope, each naming the receipt\'s own reservation_id. Only stage and reservation are compared. Denials are not checked. The hash and envelope signature checks run first.',
  receipt_issuer_public_key: publicKeyFromPrivate(RECEIPT_KEY),
  resigned_envelope_signer: publicKeyFromPrivate(CYCLES_KEY),
  cases,
}
writeFileSync(join(HERE, 'vectors.json'), JSON.stringify(out, null, 2) + '\n')
console.log(`wrote ${cases.length} cases`)
