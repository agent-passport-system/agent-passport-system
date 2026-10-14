// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { generateKeyPair, publicKeyFromPrivate, sign } from '../../../src/crypto/keys.js'
import { canonicalizeJCS } from '../../../src/core/canonical-jcs.js'
import { sha256Hex } from '../../../src/v2/payment-rails/canonicalize.js'
import {
  mapCyclesDenialToFoundation,
  RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE,
  RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE,
  RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE,
  signCyclesDenial,
  signCyclesPermitReceipt,
  signCyclesReleaseReceipt,
  verifyCyclesDenial,
  verifyCyclesDenialWithEvidence,
  verifyCyclesPermitReceipt,
  verifyCyclesPermitReceiptWithDID,
  verifyCyclesPermitReceiptWithEvidence,
  verifyCyclesReleaseReceipt,
  verifyCyclesReleaseReceiptWithEvidence,
  verifyCyclesEvidenceSignerAuthority,
  resolveEvidenceRef,
} from '../../../src/v2/payment-rails/cycles/index.js'
import type {
  EvidenceResolver,
  FetchedCyclesEvidenceEnvelope,
} from '../../../src/v2/payment-rails/cycles/index.js'
type VerifyOptionsKeyResolver = NonNullable<import('../../../src/v2/payment-rails/cycles/types.js').VerifyCyclesOptions['cyclesKeyResolver']>
import type {
  AuthorityStateSnapshot,
  CyclesEvidenceEnvelopeInput,
  CyclesEvidenceRef,
  CyclesEvidenceView,
} from '../../../src/v2/payment-rails/cycles/types.js'

// ── Authority-state-at-admission fixture (Track B, aps#25) ────────
// The authority/revocation/expiry state APS saw at admission, carried
// inline on the permit-receipt (delegation identity is not duplicated —
// the receipt's own delegation_ref names it).

const ADMISSION_SNAPSHOT_FIXTURE: AuthorityStateSnapshot = {
  checked_at: '2026-05-30T12:00:00.000Z',
  delegation_revoked: false,
  delegation_expires_at: '2026-06-30T00:00:00.000Z',
  source: 'aps_admission',
}

// ── Test helpers ──────────────────────────────────────────────────

const FIXTURE_DIR = join(dirname(fileURLToPath(import.meta.url)), 'cycles-fixtures')

function loadFixture(filename: string): CyclesEvidenceView {
  return JSON.parse(readFileSync(join(FIXTURE_DIR, filename), 'utf-8'))
}

function evidenceRef(): CyclesEvidenceRef {
  return {
    cycles_evidence_url: 'https://cycles.example.com/v1/evidence/abc',
    cycles_evidence_id_sha256: 'a'.repeat(64),
    action_ref: 'aps:action:cycles-test-001',
    delegation_ref: 'aps:delegation:cycles-test-001',
  }
}

// ── mapCyclesDenialToFoundation: 3 golden fixtures ────────────────

test('mapCyclesDenialToFoundation: 03-reserve-dry-run-deny → spend_limit_exceeded / DecisionReasonCode / BUDGET_EXCEEDED', () => {
  const env = loadFixture('03-reserve-dry-run-deny.json')
  const r = mapCyclesDenialToFoundation(env)
  assert.ok(r, 'mapping should return non-null')
  assert.equal(r.denial_reason, 'spend_limit_exceeded')
  assert.equal(r.cycles.denial_detail.source, 'DecisionReasonCode')
  assert.equal(r.cycles.denial_detail.code, 'BUDGET_EXCEEDED')
})

test('mapCyclesDenialToFoundation: 11-reserve-live-budget-exceeded → spend_limit_exceeded / ErrorCode / BUDGET_EXCEEDED', () => {
  const env = loadFixture('11-reserve-live-budget-exceeded.json')
  const r = mapCyclesDenialToFoundation(env)
  assert.ok(r)
  assert.equal(r.denial_reason, 'spend_limit_exceeded')
  assert.equal(r.cycles.denial_detail.source, 'ErrorCode')
  assert.equal(r.cycles.denial_detail.code, 'BUDGET_EXCEEDED')
  assert.equal(r.cycles.denial_detail.http_status, 409)
})

test('mapCyclesDenialToFoundation: 12-decide-live-forbidden → no_commerce_scope / ErrorCode / FORBIDDEN', () => {
  const env = loadFixture('12-decide-live-forbidden.json')
  const r = mapCyclesDenialToFoundation(env)
  assert.ok(r)
  assert.equal(r.denial_reason, 'no_commerce_scope')
  assert.equal(r.cycles.denial_detail.source, 'ErrorCode')
  assert.equal(r.cycles.denial_detail.code, 'FORBIDDEN')
  assert.equal(r.cycles.denial_detail.http_status, 403)
})

test('mapCyclesDenialToFoundation: unknown ErrorCode → rail_error fallback', () => {
  const env: CyclesEvidenceView = {
    artifact_type: 'error',
    payload: {
      error: {
        endpoint: 'POST /v1/reservations',
        http_status: 500,
        response: {
          error: 'FUTURE_UNKNOWN_CODE',
          message: 'something new',
          request_id: 'req_x',
        },
      },
    },
  }
  const r = mapCyclesDenialToFoundation(env)
  assert.ok(r)
  assert.equal(r.denial_reason, 'rail_error')
  assert.equal(r.cycles.denial_detail.code, 'FUTURE_UNKNOWN_CODE')
})

// ── Permit receipt sign/verify round-trip ─────────────────────────

test('signCyclesPermitReceipt + verifyCyclesPermitReceipt: happy-path round-trip', () => {
  const { privateKey } = generateKeyPair()
  const receipt = signCyclesPermitReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_01HZZ8N4F8FBQX5K6TGYR0M0A3',
      reserved: { unit: 'USD_MICROCENTS', amount: 2000000 },
      decision: 'ALLOW',
      expires_at_ms: 1810000030100,
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  assert.equal(receipt.claim_type, RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE)
  assert.equal(receipt.rail_name, 'cycles')
  assert.equal(receipt.decision, 'ALLOW')
  assert.match(receipt.receipt_id, /^cycles_permit_/)
  assert.equal(receipt.signature.length, 128)
  assert.deepEqual(verifyCyclesPermitReceipt(receipt), { valid: true })
})

test('verifyCyclesPermitReceipt: tampered reservation_id → SIGNATURE_INVALID', () => {
  const { privateKey } = generateKeyPair()
  const receipt = signCyclesPermitReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_original',
      reserved: { unit: 'USD_MICROCENTS', amount: 2000000 },
      decision: 'ALLOW',
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  const tampered = { ...receipt, reservation_id: 'rsv_tampered' }
  const result = verifyCyclesPermitReceipt(tampered)
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'SIGNATURE_INVALID')
})

test('verifyCyclesPermitReceipt: missing cycles_evidence → MISSING_REQUIRED_FIELD', () => {
  const { privateKey } = generateKeyPair()
  const receipt = signCyclesPermitReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_x',
      reserved: { unit: 'USD_MICROCENTS', amount: 1000 },
      decision: 'ALLOW',
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  // Strip the join shape and re-verify (this also corrupts signature
  // but we check the missing-field path runs before signature verify).
  const broken = {
    ...receipt,
    cycles_evidence: { ...receipt.cycles_evidence, cycles_evidence_id_sha256: '' },
  }
  const result = verifyCyclesPermitReceipt(broken)
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'MISSING_REQUIRED_FIELD')
})

test('verifyCyclesPermitReceipt: wrong claim_type → INVALID_CLAIM_TYPE', () => {
  const { privateKey } = generateKeyPair()
  const release = signCyclesReleaseReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_x',
      released: { unit: 'TOKENS', amount: 8000 },
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  // Feed a release receipt to the permit verifier.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const result = verifyCyclesPermitReceipt(release as any)
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'INVALID_CLAIM_TYPE')
})

// ── Release receipt sign/verify round-trip ────────────────────────

test('signCyclesReleaseReceipt + verifyCyclesReleaseReceipt: happy-path round-trip with reason', () => {
  const { privateKey } = generateKeyPair()
  const receipt = signCyclesReleaseReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_release_001',
      released: { unit: 'USD_MICROCENTS', amount: 500000 },
      reason: 'handler_timeout',
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  assert.equal(receipt.claim_type, RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE)
  assert.equal(receipt.reason, 'handler_timeout')
  assert.match(receipt.receipt_id, /^cycles_release_/)
  assert.deepEqual(verifyCyclesReleaseReceipt(receipt), { valid: true })
})

test('verifyCyclesReleaseReceipt: tampered released amount → SIGNATURE_INVALID', () => {
  const { privateKey } = generateKeyPair()
  const receipt = signCyclesReleaseReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_release_001',
      released: { unit: 'USD_MICROCENTS', amount: 500000 },
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  const tampered = {
    ...receipt,
    released: { ...receipt.released, amount: 999999999 },
  }
  const result = verifyCyclesReleaseReceipt(tampered)
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'SIGNATURE_INVALID')
})

// ── Denial sign/verify round-trip ─────────────────────────────────

test('signCyclesDenial + verifyCyclesDenial: ErrorCode-sourced denial round-trip', () => {
  const { privateKey } = generateKeyPair()
  const env = loadFixture('11-reserve-live-budget-exceeded.json')
  const mapped = mapCyclesDenialToFoundation(env)
  assert.ok(mapped, 'mapping must succeed')
  const denial = signCyclesDenial(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      denial_reason: mapped.denial_reason,
      cycles: mapped.cycles,
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  assert.equal(denial.claim_type, RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE)
  assert.equal(denial.denial_reason, 'spend_limit_exceeded')
  assert.equal(denial.cycles.denial_detail.code, 'BUDGET_EXCEEDED')
  assert.equal(denial.cycles.denial_detail.source, 'ErrorCode')
  assert.match(denial.receipt_id, /^cycles_denial_/)
  assert.deepEqual(verifyCyclesDenial(denial), { valid: true })
})

test('signCyclesDenial + verifyCyclesDenial: DecisionReasonCode-sourced denial round-trip (dry-run)', () => {
  const { privateKey } = generateKeyPair()
  const env = loadFixture('03-reserve-dry-run-deny.json')
  const mapped = mapCyclesDenialToFoundation(env)
  assert.ok(mapped)
  const denial = signCyclesDenial(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      denial_reason: mapped.denial_reason,
      cycles: mapped.cycles,
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  assert.equal(denial.denial_reason, 'spend_limit_exceeded')
  assert.equal(denial.cycles.denial_detail.source, 'DecisionReasonCode')
  assert.deepEqual(verifyCyclesDenial(denial), { valid: true })
})

test('verifyCyclesDenial: tampered cycles.denial_detail.code → SIGNATURE_INVALID', () => {
  const { privateKey } = generateKeyPair()
  const denial = signCyclesDenial(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      denial_reason: 'spend_limit_exceeded',
      cycles: {
        denial_detail: {
          layer: 'cycles',
          source: 'ErrorCode',
          code: 'BUDGET_EXCEEDED',
          http_status: 409,
        },
      },
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  const tampered = {
    ...denial,
    cycles: {
      denial_detail: {
        ...denial.cycles.denial_detail,
        code: 'TAMPERED',
      },
    },
  }
  const result = verifyCyclesDenial(tampered)
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'SIGNATURE_INVALID')
})

// ── Signer-mismatch + expected_signer option ──────────────────────

test('verifyCyclesPermitReceipt: expected_signer mismatch → SIGNATURE_INVALID', () => {
  const { privateKey } = generateKeyPair()
  const receipt = signCyclesPermitReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_x',
      reserved: { unit: 'USD_MICROCENTS', amount: 1000 },
      decision: 'ALLOW',
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  const result = verifyCyclesPermitReceipt(receipt, {
    expected_signer: 'f'.repeat(64),
  })
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'SIGNATURE_INVALID')
})

// ── TTL / EXPIRED ─────────────────────────────────────────────────

test('verifyCyclesPermitReceipt: past-TTL → EXPIRED', () => {
  const { privateKey } = generateKeyPair()
  const receipt = signCyclesPermitReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_x',
      reserved: { unit: 'USD_MICROCENTS', amount: 1000 },
      decision: 'ALLOW',
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  const future = new Date(Date.parse(receipt.issued_at) + 48 * 60 * 60 * 1000)
  const result = verifyCyclesPermitReceipt(receipt, { now: future, ttl_seconds: 24 * 60 * 60 })
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'EXPIRED')
})

// ── rail_name invariant ───────────────────────────────────────────

test('verifyCyclesPermitReceipt: tampered rail_name → SIGNATURE_INVALID (signature catches it)', () => {
  const { privateKey } = generateKeyPair()
  const receipt = signCyclesPermitReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_x',
      reserved: { unit: 'USD_MICROCENTS', amount: 1000 },
      decision: 'ALLOW',
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  // Cast to assign a non-literal rail_name for testing the structural check.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const tampered: any = { ...receipt, rail_name: 'cycles_v2' }
  const result = verifyCyclesPermitReceipt(tampered)
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'INVALID_RAIL_NAME')
})

// ── Accountability-shape invariants ───────────────────────────────

test('verifyCyclesPermitReceipt: timestamp != issued_at → MISSING_REQUIRED_FIELD', () => {
  const { privateKey } = generateKeyPair()
  const receipt = signCyclesPermitReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_x',
      reserved: { unit: 'USD_MICROCENTS', amount: 1000 },
      decision: 'ALLOW',
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  const tampered = { ...receipt, timestamp: '2020-01-01T00:00:00.000Z' }
  const result = verifyCyclesPermitReceipt(tampered)
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'MISSING_REQUIRED_FIELD')
})

test('verifyCyclesPermitReceipt: empty scope_of_claim.asserts → MISSING_REQUIRED_FIELD', () => {
  const { privateKey } = generateKeyPair()
  const receipt = signCyclesPermitReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_x',
      reserved: { unit: 'USD_MICROCENTS', amount: 1000 },
      decision: 'ALLOW',
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  const tampered = {
    ...receipt,
    scope_of_claim: { ...receipt.scope_of_claim!, asserts: '' },
  }
  const result = verifyCyclesPermitReceipt(tampered)
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'MISSING_REQUIRED_FIELD')
})

// ── DID URI signers ───────────────────────────────────────────────

test('verifyCyclesPermitReceipt (sync): DID URI signer → DID_RESOLVER_MISSING', () => {
  const { privateKey } = generateKeyPair()
  const receipt = signCyclesPermitReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_x',
      reserved: { unit: 'USD_MICROCENTS', amount: 1000 },
      decision: 'ALLOW',
      cycles_evidence: evidenceRef(),
      issuer_agent_id: 'did:cycles:example',
      issuer_key_ref: 'key-1',
    },
    privateKey,
  )
  assert.equal(receipt.signer, 'did:cycles:example#key-1')
  const result = verifyCyclesPermitReceipt(receipt)
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'DID_RESOLVER_MISSING')
})

// ── Authority-state-at-admission (Track B, aps#25, staged, inline) ─

test('signCyclesPermitReceipt: WITH authority_state_at_admission → carries the inline object and verifies', () => {
  const { privateKey } = generateKeyPair()
  const receipt = signCyclesPermitReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-admission-001',
      action_ref: 'aps:action:cycles-admission-001',
      reservation_id: 'rsv_admission_001',
      reserved: { unit: 'USD_MICROCENTS', amount: 1500000 },
      decision: 'ALLOW',
      cycles_evidence: evidenceRef(),
      authority_state_at_admission: ADMISSION_SNAPSHOT_FIXTURE,
    },
    privateKey,
  )
  // (a) the inline snapshot is carried verbatim on the receipt...
  assert.deepEqual(receipt.authority_state_at_admission, ADMISSION_SNAPSHOT_FIXTURE)
  // ...and the receipt (with the object inside the signed body) verifies.
  assert.deepEqual(verifyCyclesPermitReceipt(receipt), { valid: true })
})

test('signCyclesPermitReceipt: tampering a field inside authority_state_at_admission → SIGNATURE_INVALID', () => {
  const { privateKey } = generateKeyPair()
  const receipt = signCyclesPermitReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-admission-001',
      action_ref: 'aps:action:cycles-admission-001',
      reservation_id: 'rsv_admission_001',
      reserved: { unit: 'USD_MICROCENTS', amount: 1500000 },
      decision: 'ALLOW',
      cycles_evidence: evidenceRef(),
      authority_state_at_admission: ADMISSION_SNAPSHOT_FIXTURE,
    },
    privateKey,
  )
  // (b) flip delegation_revoked inside the inline object — the snapshot is
  // part of the signed body, so the signature must catch it.
  const tampered = {
    ...receipt,
    authority_state_at_admission: {
      ...receipt.authority_state_at_admission!,
      delegation_revoked: true,
    },
  }
  const result = verifyCyclesPermitReceipt(tampered)
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'SIGNATURE_INVALID')
})

test('signCyclesPermitReceipt: WITHOUT the snapshot → field absent, receipt verifies unchanged', () => {
  const { privateKey } = generateKeyPair()
  const receipt = signCyclesPermitReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_no_snapshot',
      reserved: { unit: 'USD_MICROCENTS', amount: 1000 },
      decision: 'ALLOW',
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  // (c) callers that pass nothing get the field absent from the object (so
  // existing fixtures/canonical bytes are unchanged) and verify.
  assert.equal(Object.prototype.hasOwnProperty.call(receipt, 'authority_state_at_admission'), false)
  assert.deepEqual(verifyCyclesPermitReceipt(receipt), { valid: true })
})

// ── Join-integrity: receipt ↔ CyclesEvidence envelope binding ─────
// The load-bearing offline-audit guarantee (aps#25, lowkey-divine). When
// the fetched envelope is supplied, verify recomputes its content hash and
// confirms it matches BOTH the envelope's own evidence_id AND the receipt's
// cycles_evidence.cycles_evidence_id_sha256. The fixtures' evidence_id was
// derived by the Cycles server; reproducing it here proves APS's JCS +
// sha256 is byte-compatible with cycles-evidence-v0.1's normative algorithm.

/** A full CyclesEvidence envelope (with evidence_id + signature). */
function loadEnvelope(filename: string): CyclesEvidenceEnvelopeInput {
  return JSON.parse(readFileSync(join(FIXTURE_DIR, filename), 'utf-8'))
}

/** The reservation_id a reserve envelope names (payload.reserve.response). */
function reserveReservationId(env: CyclesEvidenceEnvelopeInput): string {
  const payload = env.payload as { reserve?: { response?: { reservation_id?: unknown } } }
  const id = payload.reserve?.response?.reservation_id
  if (typeof id !== 'string') throw new Error('fixture is not a reserve envelope with a reservation_id')
  return id
}

/** A permit receipt whose cycles_evidence binds to `env` by content hash.
 *  8.0.0: the permit names the envelope's own reservation_id, so these
 *  hash-binding and signature tests keep testing only what they test
 *  (correspondence has its own section below). */
function permitBoundTo(env: CyclesEvidenceEnvelopeInput, privateKey: string) {
  return signCyclesPermitReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: reserveReservationId(env),
      reserved: { unit: 'USD_MICROCENTS', amount: 2000000 },
      decision: 'ALLOW',
      cycles_evidence: { ...evidenceRef(), cycles_evidence_id_sha256: env.evidence_id },
    },
    privateKey,
  )
}

test('join-integrity: permit receipt + matching envelope → valid', () => {
  const { privateKey } = generateKeyPair()
  const env = loadEnvelope('02-reserve-allow.json')
  const receipt = permitBoundTo(env, privateKey)
  // Envelope supplied → join + envelope-signature both checked; the passing
  // result tags the unpinned authenticity state (APS#43 (a)).
  assert.deepEqual(verifyCyclesPermitReceipt(receipt, { evidence: env }), {
    valid: true,
    evidence_authenticity: 'signature_valid',
  })
})

test('join-integrity: envelope omitted → check skipped, signature-only verify still passes', () => {
  const { privateKey } = generateKeyPair()
  const env = loadEnvelope('02-reserve-allow.json')
  const receipt = permitBoundTo(env, privateKey)
  // No options.evidence → backward-compatible signature-only path.
  assert.deepEqual(verifyCyclesPermitReceipt(receipt), { valid: true })
})

test('join-integrity: tampered envelope (recomputed != evidence_id) → EVIDENCE_REF_HASH_MISMATCH', () => {
  const { privateKey } = generateKeyPair()
  const env = loadEnvelope('02-reserve-allow.json')
  const receipt = permitBoundTo(env, privateKey)
  // Mutate any signed field; evidence_id no longer matches the bytes.
  const tampered = { ...env, server_id: 'https://evil.example.com/v1' }
  const result = verifyCyclesPermitReceipt(receipt, { evidence: tampered })
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'EVIDENCE_REF_HASH_MISMATCH')
})

test('join-integrity: receipt bound to a different envelope → EVIDENCE_REF_HASH_MISMATCH', () => {
  const { privateKey } = generateKeyPair()
  const env = loadEnvelope('02-reserve-allow.json')
  // Receipt binds to the DEFAULT placeholder hash, not env.evidence_id.
  const receipt = signCyclesPermitReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_wrong_binding',
      reserved: { unit: 'USD_MICROCENTS', amount: 2000000 },
      decision: 'ALLOW',
      cycles_evidence: evidenceRef(), // cycles_evidence_id_sha256 = 'a'*64
    },
    privateKey,
  )
  const result = verifyCyclesPermitReceipt(receipt, { evidence: env })
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'EVIDENCE_REF_HASH_MISMATCH')
})

test('join-integrity: applies on the denial path too (shared core verifier)', () => {
  const { privateKey } = generateKeyPair()
  const env = loadEnvelope('11-reserve-live-budget-exceeded.json')
  const mapping = mapCyclesDenialToFoundation(loadFixture('11-reserve-live-budget-exceeded.json'))
  assert.ok(mapping)
  const denial = signCyclesDenial(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      denial_reason: mapping.denial_reason,
      cycles: mapping.cycles,
      cycles_evidence: { ...evidenceRef(), cycles_evidence_id_sha256: env.evidence_id },
    },
    privateKey,
  )
  assert.deepEqual(verifyCyclesDenial(denial, { evidence: env }), {
    valid: true,
    evidence_authenticity: 'signature_valid',
  })
  // And a mismatched binding is caught on the denial path.
  const wrong = verifyCyclesDenial(denial, {
    evidence: { ...env, server_id: 'https://evil.example.com/v1' },
  })
  assert.equal(wrong.valid, false)
  if (!wrong.valid) assert.equal(wrong.reason, 'EVIDENCE_REF_HASH_MISMATCH')
})

test('join-integrity: non-string envelope evidence_id → EVIDENCE_REF_HASH_MISMATCH', () => {
  const { privateKey } = generateKeyPair()
  const env = loadEnvelope('02-reserve-allow.json')
  const receipt = permitBoundTo(env, privateKey)
  // A malformed envelope whose evidence_id is not the canonical hex string.
  // The recompute (a 64-char lowercase hex) can never equal a non-string,
  // so the self-consistency check (a) fails closed.
  const malformed = { ...env, evidence_id: ['not', 'a', 'string'] as unknown as string }
  const result = verifyCyclesPermitReceipt(receipt, { evidence: malformed })
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'EVIDENCE_REF_HASH_MISMATCH')
})

test('join-integrity: receipt hash correct but uppercase → EVIDENCE_REF_HASH_MISMATCH (byte-exact, no case-folding)', () => {
  const { privateKey } = generateKeyPair()
  const env = loadEnvelope('02-reserve-allow.json')
  // Bind the receipt to the UPPERCASE form of the (lowercase) evidence_id.
  // The recompute is lowercase hex; the comparison is byte-exact, so an
  // otherwise-correct hash that differs only in case must be rejected.
  const receipt = signCyclesPermitReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_uppercase_hash',
      reserved: { unit: 'USD_MICROCENTS', amount: 2000000 },
      decision: 'ALLOW',
      cycles_evidence: { ...evidenceRef(), cycles_evidence_id_sha256: env.evidence_id.toUpperCase() },
    },
    privateKey,
  )
  const result = verifyCyclesPermitReceipt(receipt, { evidence: env })
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'EVIDENCE_REF_HASH_MISMATCH')
})

// ── Envelope authenticity: APS#43 (a) — envelope Ed25519 signature ─
// Beyond the hash binding, a supplied envelope's OWN signature is verified
// against its signer_did (signature emptied, evidence_id populated — the
// cycles-evidence-v0.1 "Signature derivation" canonicalization, distinct
// from the content-hash recipe). A passing verify tags evidence_authenticity:
// 'signature_valid' (bytes verify against signer_did) or 'pinned_issuer'
// (that PLUS expected_signer pinning the receipt issuer = full authenticity
// for the pinned case). Dynamic signer-AUTHORITY resolution is (b), gated on
// runcycles/cycles-protocol#103 and intentionally NOT done here.

/** Re-derive a fully self-consistent envelope signed by `privateKey`:
 *  re-points signer_did to that key, recomputes evidence_id, and re-signs.
 *  Models an envelope an arbitrary key produced (used for the (a)/(b)
 *  boundary test). */
function resignEnvelope(
  env: CyclesEvidenceEnvelopeInput,
  privateKey: string,
): CyclesEvidenceEnvelopeInput {
  const signer_did = publicKeyFromPrivate(privateKey)
  const evidence_id = sha256Hex(
    canonicalizeJCS({ ...env, signer_did, evidence_id: '', signature: '' }),
  )
  const signature = sign(
    canonicalizeJCS({ ...env, signer_did, evidence_id, signature: '' }),
    privateKey,
  )
  return { ...env, signer_did, evidence_id, signature }
}

test('envelope-authenticity: valid signature + pinned receipt issuer → pinned_issuer', () => {
  const { privateKey } = generateKeyPair()
  const env = loadEnvelope('02-reserve-allow.json')
  const receipt = permitBoundTo(env, privateKey)
  // expected_signer pins the receipt issuer (the trust anchor / manual (b)).
  const result = verifyCyclesPermitReceipt(receipt, {
    evidence: env,
    expected_signer: publicKeyFromPrivate(privateKey),
  })
  assert.deepEqual(result, { valid: true, evidence_authenticity: 'pinned_issuer' })
})

test('envelope-authenticity: hash-consistent envelope with a bad signature → EVIDENCE_SIGNATURE_INVALID', () => {
  const { privateKey } = generateKeyPair()
  const env = loadEnvelope('02-reserve-allow.json')
  const receipt = permitBoundTo(env, privateKey)
  // Zero the signature. The hash recompute empties `signature`, so the
  // binding/self-consistency check still PASSES — only the (a) signature
  // check catches it. This is the core (a) guarantee.
  const forged = { ...env, signature: '0'.repeat(128) }
  const result = verifyCyclesPermitReceipt(receipt, { evidence: forged })
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'EVIDENCE_SIGNATURE_INVALID')
})

test('envelope-authenticity: (a)/(b) boundary — attacker self-signs, signature_valid still holds (NOT authenticity)', () => {
  const { privateKey: issuerKey } = generateKeyPair()
  const { privateKey: attackerKey } = generateKeyPair()
  const env = loadEnvelope('02-reserve-allow.json')
  // Attacker re-signs the envelope with THEIR OWN key and embeds their own
  // pubkey as signer_did — a fully self-consistent forgery.
  const forged = resignEnvelope(env, attackerKey)
  const receipt = permitBoundTo(forged, issuerKey)
  // (a) alone passes: the bytes verify against the embedded signer_did. This
  // is exactly why signature_valid is NOT authenticity — it is the (b) gap
  // that did:cycles / JWKS resolution (cycles-protocol#103) closes.
  assert.deepEqual(verifyCyclesPermitReceipt(receipt, { evidence: forged }), {
    valid: true,
    evidence_authenticity: 'signature_valid',
  })
})

test('envelope-authenticity: self-consistent envelope missing signer_did → EVIDENCE_SIGNATURE_INVALID', () => {
  const { privateKey } = generateKeyPair()
  const env = loadEnvelope('02-reserve-allow.json')
  // Drop signer_did and recompute evidence_id over the reduced shape, so the
  // hash binding still passes and the missing-signer_did guard is what fires.
  const { signer_did: _omit, ...noDid } = env
  const evidence_id = sha256Hex(canonicalizeJCS({ ...noDid, evidence_id: '', signature: '' }))
  const consistent = { ...noDid, evidence_id } as unknown as CyclesEvidenceEnvelopeInput
  const receipt = permitBoundTo(consistent, privateKey)
  const result = verifyCyclesPermitReceipt(receipt, { evidence: consistent })
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'EVIDENCE_SIGNATURE_INVALID')
})

test('envelope-authenticity: empty signature (hash-consistent) → EVIDENCE_SIGNATURE_INVALID', () => {
  const { privateKey } = generateKeyPair()
  const env = loadEnvelope('02-reserve-allow.json')
  const receipt = permitBoundTo(env, privateKey)
  // `signature` is emptied during the hash recompute, so an empty signature
  // leaves the binding intact — the empty-signature guard is what fires.
  const result = verifyCyclesPermitReceipt(receipt, { evidence: { ...env, signature: '' } })
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'EVIDENCE_SIGNATURE_INVALID')
})

// ── Correspondence (8.0.0): the envelope is the event the receipt references ─
// A permit references the reserve event for its reservation, a release the
// release event for its reservation. The join already proved hash binding and
// the envelope's own signature. This section proves the third check: same
// stage and same reservation_id. Amount, unit, action and server identity are
// NOT compared. Semantic negatives use resignEnvelope so the hash and signature
// checks pass and the failure reaches the correspondence check.

const VECTOR_DIR = join(dirname(fileURLToPath(import.meta.url)), 'cycles-evidence-vectors')

function loadVector(filename: string): CyclesEvidenceEnvelopeInput {
  return JSON.parse(readFileSync(join(VECTOR_DIR, filename), 'utf-8'))
}

function permitFor(env: CyclesEvidenceEnvelopeInput, reservation_id: string, privateKey: string) {
  return signCyclesPermitReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id,
      reserved: { unit: 'USD_MICROCENTS', amount: 2000000 },
      decision: 'ALLOW',
      cycles_evidence: { ...evidenceRef(), cycles_evidence_id_sha256: env.evidence_id },
    },
    privateKey,
  )
}

function releaseFor(env: CyclesEvidenceEnvelopeInput, reservation_id: string, privateKey: string) {
  return signCyclesReleaseReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id,
      released: { unit: 'TOKENS', amount: 8000 },
      cycles_evidence: { ...evidenceRef(), cycles_evidence_id_sha256: env.evidence_id },
    },
    privateKey,
  )
}

function releaseReservationId(env: CyclesEvidenceEnvelopeInput): string {
  const payload = env.payload as { release?: { reservation_id?: unknown } }
  const id = payload.release?.reservation_id
  if (typeof id !== 'string') throw new Error('fixture is not a release envelope with a reservation_id')
  return id
}

function commitReservationId(env: CyclesEvidenceEnvelopeInput): string {
  const payload = env.payload as { commit?: { reservation_id?: unknown } }
  const id = payload.commit?.reservation_id
  if (typeof id !== 'string') throw new Error('fixture is not a commit envelope with a reservation_id')
  return id
}

function expectFailure(
  result: ReturnType<typeof verifyCyclesPermitReceipt>,
  reason: string,
  fieldPrefix: string,
) {
  assert.equal(result.valid, false)
  if (!result.valid) {
    assert.equal(result.reason, reason)
    assert.ok(result.detail?.startsWith(fieldPrefix), `detail ${String(result.detail)}`)
  }
}

function resolverFor(env: CyclesEvidenceEnvelopeInput): EvidenceResolver {
  return {
    canResolve: () => true,
    resolve: async () => ({ ok: true, envelope: env as unknown as FetchedCyclesEvidenceEnvelope }),
  }
}

test('correspondence: permit + its own reserve envelope → valid (positive control)', () => {
  const { privateKey } = generateKeyPair()
  const env = loadEnvelope('02-reserve-allow.json')
  const receipt = permitFor(env, reserveReservationId(env), privateKey)
  assert.deepEqual(verifyCyclesPermitReceipt(receipt, { evidence: env }), {
    valid: true,
    evidence_authenticity: 'signature_valid',
  })
})

test('correspondence: permit naming another reservation + reserve envelope → MISMATCH (reservation_id)', () => {
  const { privateKey } = generateKeyPair()
  const env = loadEnvelope('02-reserve-allow.json')
  const receipt = permitFor(env, 'rsv_some_other_reservation', privateKey)
  expectFailure(verifyCyclesPermitReceipt(receipt, { evidence: env }), 'EVIDENCE_CORRESPONDENCE_MISMATCH', 'reservation_id')
})

test('correspondence: permit + commit envelope of the same reservation → MISMATCH (artifact_type)', () => {
  const { privateKey } = generateKeyPair()
  const env = loadVector('05-commit-success.json')
  const receipt = permitFor(env, commitReservationId(env), privateKey)
  expectFailure(verifyCyclesPermitReceipt(receipt, { evidence: env }), 'EVIDENCE_CORRESPONDENCE_MISMATCH', 'artifact_type')
})

test('correspondence: the reported probe, permit WRONG-RESERVATION + commit envelope, pinned issuer → MISMATCH', () => {
  const { privateKey } = generateKeyPair()
  const env = loadVector('05-commit-success.json')
  const receipt = permitFor(env, 'WRONG-RESERVATION', privateKey)
  expectFailure(
    verifyCyclesPermitReceipt(receipt, { evidence: env, expected_signer: publicKeyFromPrivate(privateKey) }),
    'EVIDENCE_CORRESPONDENCE_MISMATCH',
    'artifact_type',
  )
})

test('correspondence: reserve envelope without reservation_id (hash and signature valid) → FIELD_MISSING', () => {
  const { privateKey } = generateKeyPair()
  const { privateKey: cyclesKey } = generateKeyPair()
  const base = loadEnvelope('02-reserve-allow.json')
  const payload = structuredClone(base.payload) as { reserve: { response: Record<string, unknown> } }
  delete payload.reserve.response.reservation_id
  const env = resignEnvelope({ ...base, payload }, cyclesKey)
  const receipt = permitFor(env, reserveReservationId(base), privateKey)
  expectFailure(
    verifyCyclesPermitReceipt(receipt, { evidence: env }),
    'EVIDENCE_CORRESPONDENCE_FIELD_MISSING',
    'payload.reserve.response.reservation_id',
  )
})

test('correspondence: envelope without artifact_type (hash and signature valid) → FIELD_MISSING', () => {
  const { privateKey } = generateKeyPair()
  const { privateKey: cyclesKey } = generateKeyPair()
  const base = loadEnvelope('02-reserve-allow.json')
  const { artifact_type: _drop, ...rest } = base
  const env = resignEnvelope(rest as CyclesEvidenceEnvelopeInput, cyclesKey)
  const receipt = permitFor(env, reserveReservationId(base), privateKey)
  expectFailure(verifyCyclesPermitReceipt(receipt, { evidence: env }), 'EVIDENCE_CORRESPONDENCE_FIELD_MISSING', 'artifact_type')
})

test('correspondence: artifact_type reserve but payload variant commit (hash and signature valid) → MISMATCH (payload)', () => {
  const { privateKey } = generateKeyPair()
  const { privateKey: cyclesKey } = generateKeyPair()
  const reserve = loadEnvelope('02-reserve-allow.json')
  const commit = loadVector('05-commit-success.json')
  const env = resignEnvelope({ ...reserve, payload: commit.payload }, cyclesKey)
  const receipt = permitFor(env, reserveReservationId(reserve), privateKey)
  expectFailure(verifyCyclesPermitReceipt(receipt, { evidence: env }), 'EVIDENCE_CORRESPONDENCE_MISMATCH', 'payload')
})

test('correspondence: release + its own release envelope → valid (positive control)', () => {
  const { privateKey } = generateKeyPair()
  const env = loadVector('06-release-success.json')
  const receipt = releaseFor(env, releaseReservationId(env), privateKey)
  assert.deepEqual(verifyCyclesReleaseReceipt(receipt, { evidence: env }), {
    valid: true,
    evidence_authenticity: 'signature_valid',
  })
})

test('correspondence: release naming another reservation + release envelope → MISMATCH (reservation_id)', () => {
  const { privateKey } = generateKeyPair()
  const env = loadVector('06-release-success.json')
  const receipt = releaseFor(env, 'rsv_some_other_reservation', privateKey)
  expectFailure(verifyCyclesReleaseReceipt(receipt, { evidence: env }), 'EVIDENCE_CORRESPONDENCE_MISMATCH', 'reservation_id')
})

test('correspondence: release + commit envelope → MISMATCH (artifact_type)', () => {
  const { privateKey } = generateKeyPair()
  const env = loadVector('05-commit-success.json')
  const receipt = releaseFor(env, commitReservationId(env), privateKey)
  expectFailure(verifyCyclesReleaseReceipt(receipt, { evidence: env }), 'EVIDENCE_CORRESPONDENCE_MISMATCH', 'artifact_type')
})

test('correspondence: release envelope without reservation_id (hash and signature valid) → FIELD_MISSING', () => {
  const { privateKey } = generateKeyPair()
  const { privateKey: cyclesKey } = generateKeyPair()
  const base = loadVector('06-release-success.json')
  const payload = structuredClone(base.payload) as { release: Record<string, unknown> }
  delete payload.release.reservation_id
  const env = resignEnvelope({ ...base, payload }, cyclesKey)
  const receipt = releaseFor(env, releaseReservationId(base), privateKey)
  expectFailure(
    verifyCyclesReleaseReceipt(receipt, { evidence: env }),
    'EVIDENCE_CORRESPONDENCE_FIELD_MISSING',
    'payload.release.reservation_id',
  )
})

test('correspondence: runs after the hash check, a tampered envelope still reports EVIDENCE_REF_HASH_MISMATCH', () => {
  const { privateKey } = generateKeyPair()
  const env = loadEnvelope('02-reserve-allow.json')
  const receipt = permitFor(env, 'rsv_some_other_reservation', privateKey)
  const result = verifyCyclesPermitReceipt(receipt, { evidence: { ...env, server_id: 'https://evil.example.com/v1' } })
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'EVIDENCE_REF_HASH_MISMATCH')
})

test('correspondence: denial receipts are not checked (documented boundary, behavior unchanged)', () => {
  const { privateKey } = generateKeyPair()
  const env = loadEnvelope('02-reserve-allow.json')
  const mapping = mapCyclesDenialToFoundation(loadFixture('11-reserve-live-budget-exceeded.json'))
  assert.ok(mapping)
  const denial = signCyclesDenial(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      denial_reason: mapping.denial_reason,
      cycles: mapping.cycles,
      cycles_evidence: { ...evidenceRef(), cycles_evidence_id_sha256: env.evidence_id },
    },
    privateKey,
  )
  assert.deepEqual(verifyCyclesDenial(denial, { evidence: env }), {
    valid: true,
    evidence_authenticity: 'signature_valid',
  })
})

test('correspondence: DID entry path applies the same check', async () => {
  const { privateKey } = generateKeyPair()
  const env = loadVector('05-commit-success.json')
  const receipt = permitFor(env, commitReservationId(env), privateKey)
  expectFailure(
    await verifyCyclesPermitReceiptWithDID(receipt, { evidence: env }),
    'EVIDENCE_CORRESPONDENCE_MISMATCH',
    'artifact_type',
  )
})

test('correspondence (fetched path): permit + resolved reserve envelope → matched, stage and reservation only', async () => {
  const { privateKey } = generateKeyPair()
  const env = loadEnvelope('02-reserve-allow.json')
  const receipt = permitFor(env, reserveReservationId(env), privateKey)
  const result = await verifyCyclesPermitReceiptWithEvidence(receipt, { resolveEvidence: resolverFor(env) })
  assert.equal(result.verify.valid, true)
  assert.equal(result.evidence.status, 'matched')
  assert.deepEqual(result.correspondence, {
    status: 'matched',
    stage: 'reserve',
    reservation_id: reserveReservationId(env),
    not_compared: ['amount', 'unit', 'action', 'server_id'],
  })
})

test('correspondence (fetched path): permit + resolved commit envelope → verify unchanged, correspondence mismatch', async () => {
  const { privateKey } = generateKeyPair()
  const env = loadVector('05-commit-success.json')
  const receipt = permitFor(env, 'WRONG-RESERVATION', privateKey)
  const result = await verifyCyclesPermitReceiptWithEvidence(receipt, { resolveEvidence: resolverFor(env) })
  // The receipt-only verdict keeps its meaning. Correspondence is reported beside it.
  assert.equal(result.verify.valid, true)
  assert.equal(result.evidence.status, 'matched')
  assert.equal(result.correspondence.status, 'mismatch')
  if (result.correspondence.status === 'mismatch') assert.equal(result.correspondence.field, 'artifact_type')
})

test('correspondence (fetched path): hash mismatch → not_applicable, never matched', async () => {
  const { privateKey } = generateKeyPair()
  const env = loadEnvelope('02-reserve-allow.json')
  const receipt = permitFor(env, reserveReservationId(env), privateKey)
  const tampered = { ...env, server_id: 'https://evil.example.com/v1' }
  const result = await verifyCyclesPermitReceiptWithEvidence(receipt, { resolveEvidence: resolverFor(tampered) })
  assert.equal(result.evidence.status, 'hash_mismatch')
  assert.equal(result.correspondence.status, 'not_applicable')
})

test('correspondence (fetched path): release + resolved release envelope → matched', async () => {
  const { privateKey } = generateKeyPair()
  const env = loadVector('06-release-success.json')
  const receipt = releaseFor(env, releaseReservationId(env), privateKey)
  const result = await verifyCyclesReleaseReceiptWithEvidence(receipt, { resolveEvidence: resolverFor(env) })
  assert.equal(result.correspondence.status, 'matched')
  if (result.correspondence.status === 'matched') assert.equal(result.correspondence.stage, 'release')
})

test('correspondence (fetched path): denial → not_applicable', async () => {
  const { privateKey } = generateKeyPair()
  const env = loadEnvelope('11-reserve-live-budget-exceeded.json')
  const mapping = mapCyclesDenialToFoundation(loadFixture('11-reserve-live-budget-exceeded.json'))
  assert.ok(mapping)
  const denial = signCyclesDenial(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      denial_reason: mapping.denial_reason,
      cycles: mapping.cycles,
      cycles_evidence: { ...evidenceRef(), cycles_evidence_id_sha256: env.evidence_id },
    },
    privateKey,
  )
  const result = await verifyCyclesDenialWithEvidence(denial, { resolveEvidence: resolverFor(env) })
  assert.equal(result.correspondence.status, 'not_applicable')
})

// ── Correspondence reads only the authenticated representation ────
// Each negative below carries a reservation_id that a JavaScript property
// lookup can find but the canonical bytes do not contain. Those bytes are what
// the hash and signatures cover, so the hash and signature checks pass and
// only correspondence stands between the input and acceptance. Every case
// first asserts that the canonical bytes really lack the field.

type ReserveEnvelope = CyclesEvidenceEnvelopeInput & {
  payload: { reserve: { response: Record<string, unknown> } & Record<string, unknown> }
}

/** A reserve envelope re-signed without payload.reserve.response.reservation_id,
 *  and the id it would have named. */
function reserveSignedWithoutReservationId(cyclesKey: string): { env: ReserveEnvelope; id: string } {
  const base = loadEnvelope('02-reserve-allow.json')
  const id = reserveReservationId(base)
  const payload = structuredClone(base.payload) as { reserve: { response: Record<string, unknown> } }
  delete payload.reserve.response.reservation_id
  return { env: resignEnvelope({ ...base, payload }, cyclesKey) as ReserveEnvelope, id }
}

/** Same envelope with payload.reserve.response replaced by `response`. */
function withResponse(env: ReserveEnvelope, response: object): ReserveEnvelope {
  return { ...env, payload: { reserve: { ...env.payload.reserve, response } } } as ReserveEnvelope
}

function inheritedReservationId(env: ReserveEnvelope, id: string): ReserveEnvelope {
  return withResponse(env, Object.assign(Object.create({ reservation_id: id }), env.payload.reserve.response))
}

function hiddenReservationId(env: ReserveEnvelope, id: string): ReserveEnvelope {
  const response = { ...env.payload.reserve.response }
  Object.defineProperty(response, 'reservation_id', { value: id, enumerable: false })
  return withResponse(env, response)
}

/** A Date response carrying an own enumerable reservation_id. Its canonical
 *  form is only the date string, so the envelope is re-signed over that. */
function dateResponseEnvelope(cyclesKey: string): { env: ReserveEnvelope; id: string } {
  const { env, id } = reserveSignedWithoutReservationId(cyclesKey)
  const response = Object.assign(new Date('2026-01-01T00:00:00Z'), { reservation_id: id })
  return { env: resignEnvelope(withResponse(env, response), cyclesKey) as ReserveEnvelope, id }
}

function assertFieldAbsentFromCanonicalBytes(env: CyclesEvidenceEnvelopeInput, id: string) {
  const bytes = canonicalizeJCS(env)
  assert.equal(bytes.includes(id), false, 'the reservation_id must not be in the canonical bytes')
}

test('correspondence: inherited reservation_id absent from the signed bytes → FIELD_MISSING', () => {
  const { privateKey } = generateKeyPair()
  const { privateKey: cyclesKey } = generateKeyPair()
  const { env: signed, id } = reserveSignedWithoutReservationId(cyclesKey)
  const env = inheritedReservationId(signed, id)
  assert.equal(canonicalizeJCS(env), canonicalizeJCS(signed))
  assertFieldAbsentFromCanonicalBytes(env, id)
  const receipt = permitFor(signed, id, privateKey)
  expectFailure(
    verifyCyclesPermitReceipt(receipt, { evidence: env }),
    'EVIDENCE_CORRESPONDENCE_FIELD_MISSING',
    'payload.reserve.response.reservation_id',
  )
})

test('correspondence: non-enumerable own reservation_id absent from the signed bytes → FIELD_MISSING', () => {
  const { privateKey } = generateKeyPair()
  const { privateKey: cyclesKey } = generateKeyPair()
  const { env: signed, id } = reserveSignedWithoutReservationId(cyclesKey)
  const env = hiddenReservationId(signed, id)
  assert.equal(canonicalizeJCS(env), canonicalizeJCS(signed))
  assertFieldAbsentFromCanonicalBytes(env, id)
  const receipt = permitFor(signed, id, privateKey)
  expectFailure(
    verifyCyclesPermitReceipt(receipt, { evidence: env }),
    'EVIDENCE_CORRESPONDENCE_FIELD_MISSING',
    'payload.reserve.response.reservation_id',
  )
})

test('correspondence: Date response whose canonical form is a date string → FIELD_MISSING', () => {
  const { privateKey } = generateKeyPair()
  const { privateKey: cyclesKey } = generateKeyPair()
  const { env, id } = dateResponseEnvelope(cyclesKey)
  assertFieldAbsentFromCanonicalBytes(env, id)
  const receipt = permitFor(env, id, privateKey)
  expectFailure(
    verifyCyclesPermitReceipt(receipt, { evidence: env }),
    'EVIDENCE_CORRESPONDENCE_FIELD_MISSING',
    'payload.reserve.response.reservation_id',
  )
})

test('correspondence: release envelope with non-enumerable reservation_id absent from the signed bytes → FIELD_MISSING', () => {
  const { privateKey } = generateKeyPair()
  const { privateKey: cyclesKey } = generateKeyPair()
  const base = loadVector('06-release-success.json')
  const id = releaseReservationId(base)
  const payload = structuredClone(base.payload) as { release: Record<string, unknown> }
  delete payload.release.reservation_id
  const signed = resignEnvelope({ ...base, payload }, cyclesKey)
  const release = { ...(signed.payload as { release: Record<string, unknown> }).release }
  Object.defineProperty(release, 'reservation_id', { value: id, enumerable: false })
  const env = { ...signed, payload: { release } } as CyclesEvidenceEnvelopeInput
  assert.equal(canonicalizeJCS(env), canonicalizeJCS(signed))
  assertFieldAbsentFromCanonicalBytes(env, id)
  const receipt = releaseFor(signed, id, privateKey)
  expectFailure(
    verifyCyclesReleaseReceipt(receipt, { evidence: env }),
    'EVIDENCE_CORRESPONDENCE_FIELD_MISSING',
    'payload.release.reservation_id',
  )
})

test('correspondence: receipt signed without reservation_id, inherited one added → FIELD_MISSING', () => {
  const { privateKey } = generateKeyPair()
  const env = loadEnvelope('02-reserve-allow.json')
  const id = reserveReservationId(env)
  const issued = permitFor(env, id, privateKey)
  const { signature: _sig, reservation_id: _id, ...unsigned } = issued
  const signedWithout = { ...unsigned, signature: sign(canonicalizeJCS(unsigned), privateKey) }
  const receipt = Object.assign(Object.create({ reservation_id: id }), signedWithout) as typeof issued
  assert.equal(canonicalizeJCS(receipt).includes(id), false)
  expectFailure(
    verifyCyclesPermitReceipt(receipt, { evidence: env }),
    'EVIDENCE_CORRESPONDENCE_FIELD_MISSING',
    'receipt.reservation_id',
  )
})

test('correspondence: envelope whose capture fails is rejected before any check reads it → EVIDENCE_REF_HASH_MISMATCH (envelope)', () => {
  const { privateKey } = generateKeyPair()
  const { privateKey: cyclesKey } = generateKeyPair()
  const { env: signed, id } = reserveSignedWithoutReservationId(cyclesKey)
  // The first read of `decision` throws, later reads return the signed value.
  // Capture fails. Resuming on the raw object would pass the hash and signature
  // checks and find the hidden reservation_id, so the verifier must stop.
  const response = { ...signed.payload.reserve.response }
  const decision = response.decision
  let reads = 0
  Object.defineProperty(response, 'decision', {
    enumerable: true,
    get() {
      reads += 1
      if (reads === 1) throw new Error('first read fails')
      return decision
    },
  })
  Object.defineProperty(response, 'reservation_id', { value: id, enumerable: false })
  const env = withResponse(signed, response)
  const receipt = permitFor(signed, id, privateKey)
  expectFailure(verifyCyclesPermitReceipt(receipt, { evidence: env }), 'EVIDENCE_REF_HASH_MISMATCH', 'envelope has no canonical JSON form')
  assert.equal(reads, 1, 'nothing reads the envelope after the failed capture')
})

test('correspondence: DID entry path rejects a reservation_id absent from the signed bytes', async () => {
  const { privateKey } = generateKeyPair()
  const { privateKey: cyclesKey } = generateKeyPair()
  const { env: signed, id } = reserveSignedWithoutReservationId(cyclesKey)
  const receipt = permitFor(signed, id, privateKey)
  expectFailure(
    await verifyCyclesPermitReceiptWithDID(receipt, { evidence: hiddenReservationId(signed, id) }),
    'EVIDENCE_CORRESPONDENCE_FIELD_MISSING',
    'payload.reserve.response.reservation_id',
  )
})

test('correspondence: payload with reserve and commit variants (hash and signature valid) → MISMATCH (payload)', () => {
  const { privateKey } = generateKeyPair()
  const { privateKey: cyclesKey } = generateKeyPair()
  const reserve = loadEnvelope('02-reserve-allow.json')
  const commit = loadVector('05-commit-success.json')
  const payload = { ...(reserve.payload as object), ...(commit.payload as object) }
  const env = resignEnvelope({ ...reserve, payload } as CyclesEvidenceEnvelopeInput, cyclesKey)
  const receipt = permitFor(env, reserveReservationId(reserve), privateKey)
  expectFailure(verifyCyclesPermitReceipt(receipt, { evidence: env }), 'EVIDENCE_CORRESPONDENCE_MISMATCH', 'payload')
})

test('correspondence: artifact_type commit over a reserve payload (hash and signature valid) → MISMATCH (artifact_type)', () => {
  const { privateKey } = generateKeyPair()
  const { privateKey: cyclesKey } = generateKeyPair()
  const reserve = loadEnvelope('02-reserve-allow.json')
  const env = resignEnvelope({ ...reserve, artifact_type: 'commit' } as CyclesEvidenceEnvelopeInput, cyclesKey)
  const receipt = permitFor(env, reserveReservationId(reserve), privateKey)
  expectFailure(verifyCyclesPermitReceipt(receipt, { evidence: env }), 'EVIDENCE_CORRESPONDENCE_MISMATCH', 'artifact_type')
})

for (const [label, build] of [
  ['inherited', inheritedReservationId],
  ['non-enumerable', hiddenReservationId],
] as const) {
  test(`correspondence (fetched path): ${label} reservation_id absent from the signed bytes → field_missing, never matched`, async () => {
    const { privateKey } = generateKeyPair()
    const { privateKey: cyclesKey } = generateKeyPair()
    const { env: signed, id } = reserveSignedWithoutReservationId(cyclesKey)
    const receipt = permitFor(signed, id, privateKey)
    const result = await verifyCyclesPermitReceiptWithEvidence(receipt, { resolveEvidence: resolverFor(build(signed, id)) })
    assert.equal(result.evidence.status, 'matched')
    assert.equal(result.correspondence.status, 'field_missing')
    if (result.correspondence.status === 'field_missing') {
      assert.equal(result.correspondence.field, 'payload.reserve.response.reservation_id')
    }
  })
}

test('correspondence (fetched path): Date response → field_missing, never matched', async () => {
  const { privateKey } = generateKeyPair()
  const { privateKey: cyclesKey } = generateKeyPair()
  const { env, id } = dateResponseEnvelope(cyclesKey)
  const receipt = permitFor(env, id, privateKey)
  const result = await verifyCyclesPermitReceiptWithEvidence(receipt, { resolveEvidence: resolverFor(env) })
  assert.equal(result.evidence.status, 'matched')
  assert.equal(result.correspondence.status, 'field_missing')
})

test('correspondence (fetched path): the reported envelope is the canonical JSON that was checked', async () => {
  const { privateKey } = generateKeyPair()
  const env = loadEnvelope('02-reserve-allow.json')
  const receipt = permitFor(env, reserveReservationId(env), privateKey)
  const result = await verifyCyclesPermitReceiptWithEvidence(receipt, { resolveEvidence: resolverFor(env) })
  assert.equal(result.correspondence.status, 'matched')
  assert.notEqual(result.evidence.envelope, env)
  assert.equal(Object.getPrototypeOf(result.evidence.envelope), null)
  assert.equal(canonicalizeJCS(result.evidence.envelope), canonicalizeJCS(env))
})

// ── Capture failure and ambient prototype properties ──────────────
// A failed capture must end verification with a structured rejection, never
// resume on the live object. Captured records are prototype-free, so a
// property added to Object.prototype cannot supply a field the signed bytes
// lack. Prototype changes are scoped to one test and removed in finally.

test('correspondence: claim_type getter that fails capture then changes → structured rejection, never valid', async () => {
  const { privateKey, publicKey } = generateKeyPair()
  const env = loadEnvelope('02-reserve-allow.json')
  const receipt = permitFor(env, 'WRONG-RESERVATION', privateKey)
  const control = verifyCyclesPermitReceipt(receipt, { evidence: env, expected_signer: publicKey })
  expectFailure(control, 'EVIDENCE_CORRESPONDENCE_MISMATCH', 'reservation_id')
  const permit = receipt.claim_type
  let reads = 0
  Object.defineProperty(receipt, 'claim_type', {
    enumerable: true,
    get() {
      reads += 1
      if (reads === 1) throw new Error('capture failure')
      return reads % 2 === 1 ? RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE : permit
    },
  })
  expectFailure(
    verifyCyclesPermitReceipt(receipt, { evidence: env, expected_signer: publicKey }),
    'SIGNATURE_INVALID',
    'receipt has no canonical JSON form',
  )
  reads = 0
  const fetched = await verifyCyclesPermitReceiptWithEvidence(receipt, { resolveEvidence: resolverFor(env) })
  assert.equal(fetched.verify.valid, false)
  assert.equal(fetched.evidence.status, 'malformed')
  assert.equal(fetched.authority.disposition, 'signer_resolution_failed')
  assert.equal(fetched.correspondence.status, 'field_missing')
  if (fetched.correspondence.status === 'field_missing') assert.equal(fetched.correspondence.field, 'receipt')
})

test('correspondence: receipt whose capture fails, with an inherited reservation_id → SIGNATURE_INVALID', () => {
  const { privateKey } = generateKeyPair()
  const env = loadEnvelope('02-reserve-allow.json')
  const id = reserveReservationId(env)
  const { signature: _sig, reservation_id: _id, ...unsigned } = permitFor(env, id, privateKey)
  const signedWithout = { ...unsigned, signature: sign(canonicalizeJCS(unsigned), privateKey) }
  const receipt = Object.assign(Object.create({ reservation_id: id }), signedWithout)
  const agent = receipt.agent_id
  let reads = 0
  Object.defineProperty(receipt, 'agent_id', {
    enumerable: true,
    get() {
      reads += 1
      if (reads === 1) throw new Error('capture failure')
      return agent
    },
  })
  expectFailure(verifyCyclesPermitReceipt(receipt, { evidence: env }), 'SIGNATURE_INVALID', 'receipt has no canonical JSON form')
})

test('correspondence (fetched path): envelope whose capture fails → malformed, never matched', async () => {
  const { privateKey } = generateKeyPair()
  const { privateKey: cyclesKey } = generateKeyPair()
  const { env: signed, id } = reserveSignedWithoutReservationId(cyclesKey)
  const response = { ...signed.payload.reserve.response }
  const decision = response.decision
  let reads = 0
  Object.defineProperty(response, 'decision', {
    enumerable: true,
    get() {
      reads += 1
      if (reads === 1) throw new Error('capture failure')
      return decision
    },
  })
  Object.defineProperty(response, 'reservation_id', { value: id, enumerable: false })
  const receipt = permitFor(signed, id, privateKey)
  const result = await verifyCyclesPermitReceiptWithEvidence(receipt, { resolveEvidence: resolverFor(withResponse(signed, response)) })
  assert.equal(result.evidence.status, 'malformed')
  assert.notEqual(result.correspondence.status, 'matched')
})

function withObjectPrototypeField<T>(name: string, value: unknown, run: () => T): T {
  assert.equal(Object.prototype.hasOwnProperty.call(Object.prototype, name), false)
  Object.defineProperty(Object.prototype, name, { value, enumerable: false, configurable: true })
  try {
    return run()
  } finally {
    delete (Object.prototype as Record<string, unknown>)[name]
  }
}

test('correspondence: reservation_id on Object.prototype does not supply a missing envelope field', async () => {
  const { privateKey } = generateKeyPair()
  const { privateKey: cyclesKey } = generateKeyPair()
  const { env, id } = reserveSignedWithoutReservationId(cyclesKey)
  const receipt = permitFor(env, id, privateKey)
  const sync = withObjectPrototypeField('reservation_id', id, () => verifyCyclesPermitReceipt(receipt, { evidence: env }))
  expectFailure(sync, 'EVIDENCE_CORRESPONDENCE_FIELD_MISSING', 'payload.reserve.response.reservation_id')
  // Await inside the scope, so the fetched envelope is captured while the
  // prototype field is present.
  Object.defineProperty(Object.prototype, 'reservation_id', { value: id, enumerable: false, configurable: true })
  let fetched: Awaited<ReturnType<typeof verifyCyclesPermitReceiptWithEvidence>>
  try {
    fetched = await verifyCyclesPermitReceiptWithEvidence(receipt, { resolveEvidence: resolverFor(env) })
  } finally {
    delete (Object.prototype as Record<string, unknown>).reservation_id
  }
  assert.equal(fetched.evidence.status, 'matched')
  assert.equal(fetched.correspondence.status, 'field_missing')
  assert.equal(Object.prototype.hasOwnProperty.call(Object.prototype, 'reservation_id'), false)
})

test('correspondence: reservation_id on Object.prototype does not supply a missing receipt field', () => {
  const { privateKey } = generateKeyPair()
  const env = loadEnvelope('02-reserve-allow.json')
  const id = reserveReservationId(env)
  const { signature: _sig, reservation_id: _id, ...unsigned } = permitFor(env, id, privateKey)
  const receipt = { ...unsigned, signature: sign(canonicalizeJCS(unsigned), privateKey) } as ReturnType<typeof permitFor>
  const result = withObjectPrototypeField('reservation_id', id, () => verifyCyclesPermitReceipt(receipt, { evidence: env }))
  expectFailure(result, 'EVIDENCE_CORRESPONDENCE_FIELD_MISSING', 'receipt.reservation_id')
})

// ── Caller objects are read once ──────────────────────────────────
// The options object and the resolver's result belong to the caller. Each is
// read once into a fresh value, so a getter that answers differently on a
// second read cannot hand an uncaptured envelope to a later step.

test('correspondence (fetched path): resolver result whose ok flips is read once → never matched', async () => {
  const { privateKey } = generateKeyPair()
  const { privateKey: cyclesKey } = generateKeyPair()
  const { env: signed, id } = reserveSignedWithoutReservationId(cyclesKey)
  const receipt = permitFor(signed, id, privateKey)
  let okReads = 0
  const result = {
    envelope: hiddenReservationId(signed, id) as unknown as FetchedCyclesEvidenceEnvelope,
    get ok() {
      okReads += 1
      return okReads > 1
    },
  }
  const verified = await verifyCyclesPermitReceiptWithEvidence(receipt, {
    resolveEvidence: { canResolve: () => true, resolve: async () => result as unknown as { ok: boolean } },
  })
  assert.equal(okReads, 1)
  assert.notEqual(verified.correspondence.status, 'matched')
})

test('correspondence: options whose evidence getter changes are read once → FIELD_MISSING', () => {
  const { privateKey } = generateKeyPair()
  const { privateKey: cyclesKey } = generateKeyPair()
  const { env: signed, id } = reserveSignedWithoutReservationId(cyclesKey)
  const receipt = permitFor(signed, id, privateKey)
  const env = hiddenReservationId(signed, id)
  let reads = 0
  const options = {
    get evidence() {
      reads += 1
      return reads === 1 ? env : undefined
    },
  }
  expectFailure(
    verifyCyclesPermitReceipt(receipt, options as { evidence?: CyclesEvidenceEnvelopeInput }),
    'EVIDENCE_CORRESPONDENCE_FIELD_MISSING',
    'payload.reserve.response.reservation_id',
  )
  assert.equal(reads, 1)
})

// ── Object.prototype accessors and non-object evidence refs ───────
// Accessors placed on Object.prototype must not swallow the captured options,
// and a receipt whose signed cycles_evidence is not an object must not take
// its hash or URL from a prototype. Every prototype change is scoped to one
// test, awaited inside the scope, and restored to its prior descriptor.

async function withPrototypeProps<T>(props: Record<string, PropertyDescriptor>, run: () => Promise<T> | T): Promise<T> {
  const saved = Object.keys(props).map((k) => [k, Object.getOwnPropertyDescriptor(Object.prototype, k)] as const)
  for (const [k, d] of Object.entries(props)) Object.defineProperty(Object.prototype, k, { ...d, configurable: true })
  try {
    return await run()
  } finally {
    for (const [k, d] of saved) {
      delete (Object.prototype as Record<string, unknown>)[k]
      if (d) Object.defineProperty(Object.prototype, k, d)
    }
  }
}

test('correspondence: Object.prototype evidence accessor cannot swap the captured envelope → FIELD_MISSING', async () => {
  const { privateKey } = generateKeyPair()
  const { privateKey: cyclesKey } = generateKeyPair()
  const { env, id } = reserveSignedWithoutReservationId(cyclesKey)
  const receipt = permitFor(env, id, privateKey)
  const result = await withPrototypeProps(
    { reservation_id: { value: id }, evidence: { get: () => env, set: () => {} } },
    () => verifyCyclesPermitReceipt(receipt, { evidence: env }),
  )
  expectFailure(result, 'EVIDENCE_CORRESPONDENCE_FIELD_MISSING', 'payload.reserve.response.reservation_id')
  assert.equal(Object.getOwnPropertyDescriptor(Object.prototype, 'evidence'), undefined)
})

test('correspondence (fetched path): Object.prototype resolveEvidence accessor cannot bypass the capturing resolver', async () => {
  const { privateKey } = generateKeyPair()
  const { privateKey: cyclesKey } = generateKeyPair()
  const { env, id } = reserveSignedWithoutReservationId(cyclesKey)
  const receipt = permitFor(env, id, privateKey)
  const raw = resolverFor(hiddenReservationId(env, id))
  const result = await withPrototypeProps(
    { resolveEvidence: { get: () => raw, set: () => {} } },
    () => verifyCyclesPermitReceiptWithEvidence(receipt, { resolveEvidence: raw }),
  )
  assert.equal(result.evidence.status, 'matched')
  assert.equal(result.correspondence.status, 'field_missing')
})

function permitWithArrayEvidence(privateKey: string, reservationId: string) {
  const env = loadEnvelope('02-reserve-allow.json')
  const issued = permitFor(env, reservationId, privateKey)
  const { signature: _sig, ...unsigned } = { ...issued, cycles_evidence: [] as unknown as typeof issued.cycles_evidence }
  return { env, receipt: { ...unsigned, signature: sign(canonicalizeJCS(unsigned), privateKey) } as typeof issued }
}

test('correspondence: signed cycles_evidence that is an array cannot take its hash from a prototype → MISSING_REQUIRED_FIELD', async () => {
  const { privateKey } = generateKeyPair()
  const { env, receipt } = permitWithArrayEvidence(privateKey, reserveReservationId(loadEnvelope('02-reserve-allow.json')))
  const result = await withPrototypeProps(
    { cycles_evidence_id_sha256: { value: env.evidence_id }, cycles_evidence_url: { value: 'https://cycles.example.com/e' } },
    () => verifyCyclesPermitReceipt(receipt, { evidence: env }),
  )
  expectFailure(result, 'MISSING_REQUIRED_FIELD', 'cycles_evidence')
})

test('correspondence (fetched path): signed cycles_evidence that is an array is not resolved → never matched', async () => {
  const { privateKey } = generateKeyPair()
  const { env, receipt } = permitWithArrayEvidence(privateKey, reserveReservationId(loadEnvelope('02-reserve-allow.json')))
  const result = await withPrototypeProps(
    { cycles_evidence_id_sha256: { value: env.evidence_id }, cycles_evidence_url: { value: 'https://cycles.example.com/e' } },
    () => verifyCyclesPermitReceiptWithEvidence(receipt, { resolveEvidence: resolverFor(env) }),
  )
  assert.equal(result.evidence.status, 'malformed')
  assert.notEqual(result.correspondence.status, 'matched')
})

// ── Options keep every caller constraint, inputs never throw ──────
// Each supported option is read by ordinary lookup, so a non-enumerable or
// inherited expected_signer or evidence still applies, as it did before 8.0.0.
// A receipt's scope_of_claim must be an object. Inputs too deep to capture are
// structured rejections, never exceptions.

function signedPermitFor02(privateKey: string) {
  const env = loadEnvelope('02-reserve-allow.json')
  return { env, receipt: permitFor(env, reserveReservationId(env), privateKey) }
}

test('options: non-enumerable own expected_signer still pins the issuer → SIGNATURE_INVALID', () => {
  const { privateKey } = generateKeyPair()
  const { receipt } = signedPermitFor02(privateKey)
  const options = {}
  Object.defineProperty(options, 'expected_signer', { value: generateKeyPair().publicKey })
  expectFailure(verifyCyclesPermitReceipt(receipt, options), 'SIGNATURE_INVALID', 'signer mismatch')
})

test('options: inherited expected_signer still pins the issuer → SIGNATURE_INVALID', () => {
  const { privateKey } = generateKeyPair()
  const { receipt } = signedPermitFor02(privateKey)
  const options = Object.create({ expected_signer: generateKeyPair().publicKey }) as { expected_signer?: string }
  expectFailure(verifyCyclesPermitReceipt(receipt, options), 'SIGNATURE_INVALID', 'signer mismatch')
})

test('options: non-enumerable own evidence is still checked → EVIDENCE_REF_HASH_MISMATCH', () => {
  const { privateKey } = generateKeyPair()
  const { env, receipt } = signedPermitFor02(privateKey)
  const options = {}
  Object.defineProperty(options, 'evidence', { value: { ...env, evidence_id: '0'.repeat(64) } })
  expectFailure(verifyCyclesPermitReceipt(receipt, options), 'EVIDENCE_REF_HASH_MISMATCH', 'envelope evidence_id')
})

test('receipt: scope_of_claim that is an array cannot take asserts from a prototype → MISSING_REQUIRED_FIELD', async () => {
  const { privateKey } = generateKeyPair()
  const { receipt: issued } = signedPermitFor02(privateKey)
  const { signature: _sig, ...unsigned } = { ...issued, scope_of_claim: [] as unknown as typeof issued.scope_of_claim }
  const receipt = { ...unsigned, signature: sign(canonicalizeJCS(unsigned), privateKey) } as typeof issued
  const result = await withPrototypeProps({ asserts: { value: 'reservation authorized' } }, () => verifyCyclesPermitReceipt(receipt))
  expectFailure(result, 'MISSING_REQUIRED_FIELD', 'scope_of_claim')
})

function nestedDeep<T extends object>(value: T, depth: number): T {
  const root: Record<string, unknown> = {}
  let node = root
  for (let i = 0; i < depth; i++) {
    const child: Record<string, unknown> = {}
    node.child = child
    node = child
  }
  return { ...value, extra: root }
}

test('capture: receipt too deep to capture is a structured rejection, never a throw', () => {
  const { privateKey } = generateKeyPair()
  const { receipt } = signedPermitFor02(privateKey)
  expectFailure(verifyCyclesPermitReceipt(nestedDeep(receipt, 3000)), 'SIGNATURE_INVALID', 'receipt has no')
})

test('capture: envelope too deep to capture is a structured rejection, never a throw', () => {
  const { privateKey } = generateKeyPair()
  const { env, receipt } = signedPermitFor02(privateKey)
  expectFailure(verifyCyclesPermitReceipt(receipt, { evidence: nestedDeep(env, 3000) }), 'EVIDENCE_REF_HASH_MISMATCH', 'envelope has no')
})

// ── Resolution results: failure stays failure, own envelope only ──
// A failed fetch cannot report 'matched', and neither correspondence nor
// signer authority reads an envelope the resolution result does not itself
// carry. Prototype properties here are writable, so an assignment to an
// ordinary object would create an own copy.

test('correspondence (fetched path): failed fetch with inherited status and envelope → never matched', async () => {
  const { privateKey } = generateKeyPair()
  const { env, receipt } = signedPermitFor02(privateKey)
  const fake = { artifact_type: 'reserve', payload: { reserve: { response: {} } } }
  const failing: EvidenceResolver = { canResolve: () => true, resolve: async () => ({ ok: false }) }
  const result = await withPrototypeProps(
    {
      envelope: { value: fake, writable: true },
      status: { value: 'matched', writable: true },
      reservation_id: { value: reserveReservationId(env), writable: true },
    },
    () => verifyCyclesPermitReceiptWithEvidence(receipt, { resolveEvidence: failing }),
  )
  assert.notEqual(result.evidence.status, 'matched')
  assert.equal(result.evidence.resolved, false)
  assert.notEqual(result.correspondence.status, 'matched')
})

test('authority (fetched path): an inherited envelope is never evaluated when resolution fetched none', async () => {
  const { privateKey } = generateKeyPair()
  const { privateKey: cyclesKey } = generateKeyPair()
  const { receipt } = signedPermitFor02(privateKey)
  const selfSigned = resignEnvelope(loadEnvelope('02-reserve-allow.json'), cyclesKey)
  const result = await withPrototypeProps({ envelope: { value: selfSigned, writable: true } }, () =>
    verifyCyclesPermitReceiptWithEvidence(receipt, {}),
  )
  assert.equal(result.evidence.status, 'no_resolver')
  assert.equal(result.authority.disposition, 'signer_resolution_failed')
})

test('descriptor: a resolved hash on Object.prototype is not reported for an unresolved reference', async () => {
  const { privateKey } = generateKeyPair()
  const { receipt } = signedPermitFor02(privateKey)
  const result = await withPrototypeProps({ resolved_sha256: { value: 'f'.repeat(64), writable: true } }, () =>
    verifyCyclesPermitReceiptWithEvidence(receipt, {}),
  )
  assert.equal(Object.prototype.hasOwnProperty.call(result.descriptor, 'resolved_sha256'), false)
})

// ── Resolver answers, key resolver answers, descriptor ────────────
// A resolver answer counts only through its own properties. A key resolver
// answer likewise. The descriptor is prototype-free, so a setter on
// Object.prototype cannot swallow its hash and an absent field reads undefined.

const okNoEnvelope: EvidenceResolver = { canResolve: () => true, resolve: async () => ({ ok: true }) }
const emptyAnswer: EvidenceResolver = { canResolve: () => true, resolve: async () => ({}) as { ok: boolean } }

test('resolver answer: {ok:true} without its own envelope never matches, even with one on Object.prototype', async () => {
  const { privateKey } = generateKeyPair()
  const { env, receipt } = signedPermitFor02(privateKey)
  const result = await withPrototypeProps({ envelope: { value: env, writable: true } }, () =>
    verifyCyclesPermitReceiptWithEvidence(receipt, { resolveEvidence: okNoEnvelope }),
  )
  assert.equal(result.evidence.resolved, false)
  assert.notEqual(result.evidence.status, 'matched')
  assert.notEqual(result.correspondence.status, 'matched')
})

test('resolver answer: an empty answer never matches, even with ok and envelope on Object.prototype', async () => {
  const { privateKey } = generateKeyPair()
  const { env, receipt } = signedPermitFor02(privateKey)
  const result = await withPrototypeProps(
    { ok: { value: true, writable: true }, envelope: { value: env, writable: true } },
    () => verifyCyclesPermitReceiptWithEvidence(receipt, { resolveEvidence: emptyAnswer }),
  )
  assert.equal(result.evidence.resolved, false)
  assert.notEqual(result.correspondence.status, 'matched')
})

test('resolver answer: release path and the exported resolveEvidenceRef apply the same rule', async () => {
  const { privateKey } = generateKeyPair()
  const env = loadVector('06-release-success.json')
  const receipt = releaseFor(env, releaseReservationId(env), privateKey)
  const [release, direct] = await withPrototypeProps({ envelope: { value: env, writable: true } }, async () => [
    await verifyCyclesReleaseReceiptWithEvidence(receipt, { resolveEvidence: okNoEnvelope }),
    await resolveEvidenceRef(receipt.cycles_evidence, okNoEnvelope),
  ] as const)
  assert.notEqual(release.correspondence.status, 'matched')
  assert.equal(direct.resolved, false)
  assert.notEqual(direct.status, 'matched')
})

function selfSignedEnvelope() {
  const { privateKey } = generateKeyPair()
  const env = resignEnvelope(loadEnvelope('02-reserve-allow.json'), privateKey)
  return { env, key: publicKeyFromPrivate(privateKey) }
}

test('authority: a key and success flag only on Object.prototype never make the signer authentic', async () => {
  const { env, key } = selfSignedEnvelope()
  const result = await withPrototypeProps(
    { ok: { value: true, writable: true }, publicKeyHex: { value: key, writable: true } },
    () =>
      verifyCyclesEvidenceSignerAuthority(env as unknown as FetchedCyclesEvidenceEnvelope, {
        cyclesKeyResolver: { resolve: async () => ({}) } as unknown as VerifyOptionsKeyResolver,
      }),
  )
  assert.notEqual(result.disposition, 'authentic')
})

test('authority: a null key resolver answer is a structured failure, and an own valid answer is authentic', async () => {
  const { env, key } = selfSignedEnvelope()
  const nullAnswer = await verifyCyclesEvidenceSignerAuthority(env as unknown as FetchedCyclesEvidenceEnvelope, {
    cyclesKeyResolver: { resolve: async () => null } as unknown as VerifyOptionsKeyResolver,
  })
  assert.equal(nullAnswer.disposition, 'signer_resolution_failed')
  const positive = await verifyCyclesEvidenceSignerAuthority(env as unknown as FetchedCyclesEvidenceEnvelope, {
    cyclesKeyResolver: { resolve: async () => ({ ok: true, publicKeyHex: key, kid: 'k1' }) } as unknown as VerifyOptionsKeyResolver,
  })
  assert.equal(positive.disposition, 'authentic')
  assert.equal(positive.resolvedKid, 'k1')
})

test('descriptor: a setter on Object.prototype cannot swallow the resolved hash', async () => {
  const { privateKey } = generateKeyPair()
  const { env, receipt } = signedPermitFor02(privateKey)
  const result = await withPrototypeProps(
    { resolved_sha256: { get: () => 'f'.repeat(64), set: () => {} } },
    () => verifyCyclesPermitReceiptWithEvidence(receipt, { resolveEvidence: resolverFor(env) }),
  )
  assert.equal(result.evidence.status, 'matched')
  assert.equal(result.descriptor.resolved_sha256, env.evidence_id)
})

test('descriptor: an absent resolved hash reads undefined even with one on Object.prototype', async () => {
  const { privateKey } = generateKeyPair()
  const { receipt } = signedPermitFor02(privateKey)
  const result = await withPrototypeProps({ resolved_sha256: { value: 'f'.repeat(64), writable: true } }, async () => {
    const r = await verifyCyclesPermitReceiptWithEvidence(receipt, {})
    return { read: r.descriptor.resolved_sha256, degraded: r.descriptor.degraded }
  })
  assert.equal(result.read, undefined)
  assert.equal(result.degraded, undefined)
})

test('authority: an unrelated throwing getter on the key answer is never read, still authentic', async () => {
  const { env, key } = selfSignedEnvelope()
  const answer = {
    ok: true,
    publicKeyHex: key,
    kid: 'k1',
    get diagnostic(): string {
      throw new Error('unused diagnostic getter')
    },
  }
  const result = await verifyCyclesEvidenceSignerAuthority(env as unknown as FetchedCyclesEvidenceEnvelope, {
    cyclesKeyResolver: { resolve: async () => answer } as unknown as VerifyOptionsKeyResolver,
  })
  assert.equal(result.disposition, 'authentic')
  assert.equal(result.resolvedKid, 'k1')
})

test('authority: non-enumerable own key answer fields still count, authentic', async () => {
  const { env, key } = selfSignedEnvelope()
  const answer = {}
  Object.defineProperty(answer, 'ok', { value: true })
  Object.defineProperty(answer, 'publicKeyHex', { value: key })
  Object.defineProperty(answer, 'kid', { value: 'k1' })
  const result = await verifyCyclesEvidenceSignerAuthority(env as unknown as FetchedCyclesEvidenceEnvelope, {
    cyclesKeyResolver: { resolve: async () => answer } as unknown as VerifyOptionsKeyResolver,
  })
  assert.equal(result.disposition, 'authentic')
  assert.equal(result.resolvedKid, 'k1')
})

test('authority: a throwing supported field on the key answer is a structured failure', async () => {
  const { env } = selfSignedEnvelope()
  const answer = {
    get ok(): boolean {
      throw new Error('ok accessor fails')
    },
  }
  const result = await verifyCyclesEvidenceSignerAuthority(env as unknown as FetchedCyclesEvidenceEnvelope, {
    cyclesKeyResolver: { resolve: async () => answer } as unknown as VerifyOptionsKeyResolver,
  })
  assert.equal(result.disposition, 'signer_resolution_failed')
})
