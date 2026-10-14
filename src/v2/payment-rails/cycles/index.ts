// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Cycles — APS V2 ↔ Cycles reserve/commit/release budget-authority rail
// ══════════════════════════════════════════════════════════════════
// Public functions:
//   mapCyclesDenialToFoundation(evidence)            → FoundationDenialMapping | null
//
//   signCyclesPermitReceipt(input, privateKeyHex)    → CyclesPermitReceipt
//   verifyCyclesPermitReceipt(receipt, options)      → CyclesVerifyResult       (sync)
//   verifyCyclesPermitReceiptWithDID(receipt, options) → CyclesVerifyResult     (async)
//
//   signCyclesReleaseReceipt(input, privateKeyHex)   → CyclesReleaseReceipt
//   verifyCyclesReleaseReceipt(receipt, options)     → CyclesVerifyResult       (sync)
//   verifyCyclesReleaseReceiptWithDID(receipt, options) → CyclesVerifyResult    (async)
//
//   signCyclesDenial(input, privateKeyHex)           → CyclesDenial
//   verifyCyclesDenial(denial, options)              → CyclesVerifyResult       (sync)
//   verifyCyclesDenialWithDID(denial, options)       → CyclesVerifyResult       (async)
//
// Denial mapping (constants ported byte-for-byte from the merged spec):
//   - ErrorCode → APS Tier-1: 15 v0.1.25 base values
//   - DecisionReasonCode → APS Tier-1: 6 v0.1.25 base values
//   v0.1.26 extension codes are OUT OF SCOPE for v0.1 — see file header
//   of types.ts and the merged spec's v0.2 promotion criterion.
//
// Canonical-bytes scheme: receipts use field-omission via destructuring
// to match mpp/x402 convention within this codebase. receipt_id is a
// random UUID (mppr-style), not content-addressed. (The CyclesEvidence
// envelope this receipt binds to via `cycles_evidence.cycles_evidence_id_sha256`
// IS content-addressed; the APS receipt carries its own UUID identifier.)
//
// Join-integrity (the load-bearing offline-audit guarantee):
//   When the caller passes the fetched CyclesEvidence envelope via
//   VerifyCyclesOptions.evidence, verify recomputes its content hash
//   (cycles-evidence-v0.1 normative algorithm: evidence_id + signature
//   emptied, JCS-canonicalized, sha256) and confirms it matches BOTH the
//   envelope's own evidence_id AND the receipt's
//   cycles_evidence.cycles_evidence_id_sha256 → EVIDENCE_REF_HASH_MISMATCH
//   on either failure. Omit the envelope for signature-only verification.
//
// Envelope authenticity — APS#43 (a):
//   With the same VerifyCyclesOptions.evidence, verify also checks the
//   envelope's OWN Ed25519 signature against its signer_did (signature
//   emptied, evidence_id populated — cycles-evidence-v0.1 "Signature
//   derivation") → EVIDENCE_SIGNATURE_INVALID on failure. A passing result
//   reports `evidence_authenticity`: 'signature_valid' (bytes verify against
//   signer_did) or 'pinned_issuer' (that PLUS expected_signer pinning the
//   APS receipt issuer — envelope authenticity then holds TRANSITIVELY, to
//   the extent the pinned issuer is trusted to bind only legitimate
//   envelopes; not a proof of signer_did's own authority).
//
//   Signer-AUTHORITY resolution — (b) — IS now implemented (#43): the
//   *WithEvidence paths resolve the fetched envelope's signer_did to a key via
//   a caller-supplied cyclesKeyResolver (did:cycles sha256-binding +
//   window-gated selection, or raw-hex match), re-derive evidence_id, and
//   verify the envelope's own signature, reporting `authority` as one of the
//   five dispositions (authentic / binding_only / signer_resolution_failed /
//   signer_authority_failed / signature_invalid). See `_resolveEnvelopeAuthority`
//   and `verifyCyclesEvidenceSignerAuthority`.
//
// Out of scope for this commit (TODO follow-up):
//   - preAuthorizeCyclesReserve gateway hook into PaymentRail interface
//     (gateway-flow placement — held for the AEOESS gateway-flow ADR,
//     aeoess/agent-passport-system#25).
//
// Spec refs:
//   - runcycles/cycles-protocol drafts/cycles-evidence-v0.1.yaml (#90, 61186a2)
//   - runcycles/cycles-protocol drafts/cycles-aps-denial-mapping-v0.1.md (#93, 9b0fb5e)
//   - aeoess/agent-governance-vocabulary crosswalk/cycles.yaml (#92, 3ccc17f)
//   - aeoess/agent-governance-vocabulary crosswalk/budget_reservation.yaml (#91, 161b1d4)
//   - aeoess/agent-passport-system#27 (4abd9df) — SDK PR adding the three
//     rail.budget_reservation.*.v1 claim_type literals this adapter emits.
// ══════════════════════════════════════════════════════════════════

import { randomUUID } from 'node:crypto'
import { canonicalizeJCS, canonicalizeJCSForWrite } from '../../../core/canonical-jcs.js'
import { sha256Hex } from '../canonicalize.js'
import { publicKeyFromPrivate, sign, verify as edVerify } from '../../../crypto/keys.js'
import {
  parseDidUri,
  publicKeyHexFromMethod,
  resolveVerificationMethod,
} from '../../../core/did-uri.js'
import type { DenialReason as FoundationDenialReason } from '../types.js'
import {
  CYCLES_PROTOCOL_VERSION,
  CYCLES_EVIDENCE_SCHEMA_VERSION,
  RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE,
  RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE,
  RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE,
} from './types.js'
export {
  CYCLES_PROTOCOL_VERSION,
  CYCLES_EVIDENCE_SCHEMA_VERSION,
  RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE,
  RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE,
  RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE,
} from './types.js'
import type {
  CyclesDenial,
  CyclesDenialDetail,
  CyclesEvidenceCorrespondence,
  CyclesEvidenceEnvelopeInput,
  CyclesEvidenceView,
  CyclesPermitReceipt,
  CyclesReleaseReceipt,
  CyclesResolveDidDocument,
  CyclesVerifyResult,
  ScopeOfClaim,
  SignCyclesDenialInput,
  SignCyclesPermitReceiptInput,
  SignCyclesReleaseReceiptInput,
  VerifyCyclesOptions,
} from './types.js'
import {
  readEvidenceFetchResult,
  resolveEvidenceRef,
  toEvidenceDescriptorInput,
} from './evidence-resolution.js'
import type {
  EvidenceDescriptorInput,
  EvidenceFetchResult,
  EvidenceResolutionResult,
  FetchedCyclesEvidenceEnvelope,
} from './evidence-resolution.js'
import { cyclesJwksUrl, isDIDCycles } from '../../key-resolution/index.js'
import type { KeyResolver, KeyLocator } from '../../key-resolution/index.js'

// ── Internal helpers ──────────────────────────────────────────────

function nowIso(): string {
  return new Date().toISOString()
}

/** Mirrors mpp's _mppSignerFor: either DID URI (when issuer_agent_id +
 *  issuer_key_ref both supplied) or raw hex pubkey. */
function _cyclesSignerFor(
  privateKeyHex: string,
  agentId: string | undefined,
  keyRef: string | undefined,
): string {
  if (agentId && keyRef) {
    if (!agentId.startsWith('did:')) {
      throw new Error(`signCycles*: issuer_agent_id must be a DID, got '${agentId}'`)
    }
    if (keyRef.includes('#')) {
      throw new Error("signCycles*: issuer_key_ref must not contain '#'")
    }
    return `${agentId}#${keyRef}`
  }
  return publicKeyFromPrivate(privateKeyHex)
}

// ── Default scope_of_claim assertions per artifact ─────────────────

function defaultCyclesPermitReceiptScope(): ScopeOfClaim {
  return {
    asserts:
      'aps:cycles.permit:emit — a budget reservation was authorized on the Cycles rail under the named delegation; reservation_id anchors the rail-side outcome and cycles_evidence binds to the signed CyclesEvidence envelope.',
    does_not_assert: [
      'the reservation was committed',
      'the action governed by the reservation completed',
      'live ledger state at any time after issuance',
    ],
    capture_mode: 'gateway_observed',
    completeness: 'complete',
    self_attested: false,
  }
}

function defaultCyclesReleaseReceiptScope(): ScopeOfClaim {
  return {
    asserts:
      'aps:cycles.release:emit — a budget reservation was released without commit under the named delegation; reservation_id ties to the prior permit-receipt.',
    does_not_assert: [
      'the underlying action was cancelled (the reason field, when populated, is rail-reported)',
      'no separate commit occurred on a different reservation',
    ],
    capture_mode: 'gateway_observed',
    completeness: 'complete',
    self_attested: false,
  }
}

function defaultCyclesDenialScope(): ScopeOfClaim {
  return {
    asserts:
      'aps:cycles.deny:emit — a Cycles budget-authority operation was refused with a closed-taxonomy Tier-1 denial reason; cycles.denial_detail preserves the canonical Cycles-side code Tier-2.',
    does_not_assert: [
      'the rail itself is unavailable',
      'the agent acted maliciously',
      'the underlying delegation is invalid (denial may flag a single missing constraint)',
    ],
    capture_mode: 'gateway_observed',
    completeness: 'complete',
    self_attested: false,
  }
}

// ── Denial mapping: Cycles ErrorCode → APS Tier-1 ─────────────────

const ERROR_CODE_TO_TIER1: Record<string, FoundationDenialReason> = {
  INVALID_REQUEST:          'rail_error',
  UNAUTHORIZED:             'rail_error',
  FORBIDDEN:                'no_commerce_scope',
  NOT_FOUND:                'rail_error',
  BUDGET_EXCEEDED:          'spend_limit_exceeded',
  BUDGET_FROZEN:            'wallet_revoked',
  BUDGET_CLOSED:            'wallet_revoked',
  RESERVATION_EXPIRED:      'time_window_violation',
  RESERVATION_FINALIZED:    'rail_error',
  IDEMPOTENCY_MISMATCH:     'rail_error',
  UNIT_MISMATCH:            'rail_error',
  OVERDRAFT_LIMIT_EXCEEDED: 'spend_limit_exceeded',
  DEBT_OUTSTANDING:         'wallet_revoked',
  MAX_EXTENSIONS_EXCEEDED:  'time_window_violation',
  INTERNAL_ERROR:           'rail_error',
}

// ── Denial mapping: Cycles DecisionReasonCode → APS Tier-1 ────────

const DECISION_REASON_TO_TIER1: Record<string, FoundationDenialReason> = {
  BUDGET_EXCEEDED:          'spend_limit_exceeded',
  BUDGET_FROZEN:            'wallet_revoked',
  BUDGET_CLOSED:            'wallet_revoked',
  BUDGET_NOT_FOUND:         'rail_error',
  OVERDRAFT_LIMIT_EXCEEDED: 'spend_limit_exceeded',
  DEBT_OUTSTANDING:         'wallet_revoked',
}

// ── mapCyclesDenialToFoundation ───────────────────────────────────

/**
 * Maps a Cycles denial signal (extracted from a CyclesEvidence view)
 * to an APS Tier-1 denial reason, preserving the full Cycles-side
 * detail Tier-2 in `cycles.denial_detail`.
 *
 * Returns `null` if the evidence view does not represent a denial
 * (artifact_type=decide-ALLOW, reserve-ALLOW, commit, release).
 *
 * Denial paths:
 *   (A) HTTP 4xx/5xx — artifact_type=error. ErrorCode source.
 *   (B) /v1/decide DENY — artifact_type=decide. DecisionReasonCode source.
 *   (C) dry_run=true reserve DENY — artifact_type=reserve.
 *       DecisionReasonCode source. (Non-dry reserve DENY is a wire-
 *       shape impossibility per cycles-protocol-v0.yaml:978 and is
 *       rejected at the CyclesEvidence schema layer.)
 */
export function mapCyclesDenialToFoundation(
  evidence: CyclesEvidenceView,
): { denial_reason: FoundationDenialReason; cycles: { denial_detail: CyclesDenialDetail } } | null {
  const p = evidence.payload

  if ('error' in p) {
    const e = p.error
    const code = e.response.error
    return {
      denial_reason: ERROR_CODE_TO_TIER1[code] ?? 'rail_error',
      cycles: {
        denial_detail: {
          layer: 'cycles',
          source: 'ErrorCode',
          code,
          http_status: e.http_status,
          message: e.response.message,
          request_id: e.response.request_id,
          // explicit null: keeps the shipped preimage bytes (#101); omission would change signatures
          trace_id: e.response.trace_id ?? evidence.trace_id ?? null,
        },
      },
    }
  }

  if ('decide' in p && p.decide.response.decision === 'DENY') {
    const code = p.decide.response.reason_code ?? 'UNKNOWN'
    return {
      denial_reason: DECISION_REASON_TO_TIER1[code] ?? 'rail_error',
      cycles: {
        denial_detail: {
          layer: 'cycles',
          source: 'DecisionReasonCode',
          code,
          // explicit null: keeps the shipped preimage bytes (#101); omission would change signatures
          trace_id: evidence.trace_id ?? null,
        },
      },
    }
  }

  if ('reserve' in p && p.reserve.response.decision === 'DENY') {
    const code = p.reserve.response.reason_code ?? 'UNKNOWN'
    return {
      denial_reason: DECISION_REASON_TO_TIER1[code] ?? 'rail_error',
      cycles: {
        denial_detail: {
          layer: 'cycles',
          source: 'DecisionReasonCode',
          code,
          // explicit null: keeps the shipped preimage bytes (#101); omission would change signatures
          trace_id: evidence.trace_id ?? null,
        },
      },
    }
  }

  return null
}

// ── Sign / verify: permit receipt ─────────────────────────────────

export function signCyclesPermitReceipt(
  input: SignCyclesPermitReceiptInput,
  signerPrivateKeyHex: string,
): CyclesPermitReceipt {
  const signerPub = _cyclesSignerFor(signerPrivateKeyHex, input.issuer_agent_id, input.issuer_key_ref)
  const issued_at = nowIso()
  const unsigned: Omit<CyclesPermitReceipt, 'signature'> = {
    claim_type: RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE,
    receipt_id: `cycles_permit_${randomUUID()}`,
    signer: signerPub,
    agent_id: input.agent_id,
    delegation_ref: input.delegation_ref,
    action_ref: input.action_ref,
    rail_name: 'cycles',
    reservation_id: input.reservation_id,
    reserved: input.reserved,
    decision: input.decision,
    cycles_evidence: input.cycles_evidence,
    issued_at,
    timestamp: issued_at,
    scope_of_claim: input.scope_of_claim ?? defaultCyclesPermitReceiptScope(),
  }
  if (input.expires_at_ms !== undefined) {
    unsigned.expires_at_ms = input.expires_at_ms
  }
  if (input.authority_state_at_admission !== undefined) {
    unsigned.authority_state_at_admission = input.authority_state_at_admission
  }
  if (input.trust_policy_ref !== undefined) {
    unsigned.trust_policy_ref = input.trust_policy_ref
  }
  const sigBytes = canonicalizeJCSForWrite(unsigned)
  const signature = sign(sigBytes, signerPrivateKeyHex)
  return { ...unsigned, signature }
}

/** Verify a Cycles permit receipt (sync). With `options.evidence`, also
 *  checks the receipt↔envelope hash binding and that the envelope is the
 *  referenced stage for the same reservation_id (see `_checkEvidenceJoin`).
 *  Amount, unit, action and server identity are not compared.
 *  NOTE: `valid: true` does NOT assert the envelope's own Ed25519
 *  authenticity or signer authority — that is the v0.2 item (#43). Pin
 *  `expected_signer` for issuer trust until then. */
export function verifyCyclesPermitReceipt(
  receipt: CyclesPermitReceipt,
  options: VerifyCyclesOptions = {},
): CyclesVerifyResult {
  const captured = _captureInputs(receipt, options)
  if (!captured.ok) return captured.failure
  return _verifyReceiptCore(captured.receipt, RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE, captured.options)
}

/** Verify a Cycles permit receipt (async, DID-URI signers). Join-integrity
 *  caveat as in `verifyCyclesPermitReceipt`: `valid: true` does NOT assert
 *  the envelope's own Ed25519 authenticity (v0.2 — #43). */
export async function verifyCyclesPermitReceiptWithDID(
  receipt: CyclesPermitReceipt,
  options: VerifyCyclesOptions = {},
): Promise<CyclesVerifyResult> {
  const captured = _captureInputs(receipt, options)
  if (!captured.ok) return captured.failure
  return _verifyReceiptWithDID(captured.receipt, RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE, captured.options)
}

// ── Sign / verify: release receipt ────────────────────────────────

export function signCyclesReleaseReceipt(
  input: SignCyclesReleaseReceiptInput,
  signerPrivateKeyHex: string,
): CyclesReleaseReceipt {
  const signerPub = _cyclesSignerFor(signerPrivateKeyHex, input.issuer_agent_id, input.issuer_key_ref)
  const issued_at = nowIso()
  const unsigned: Omit<CyclesReleaseReceipt, 'signature'> = {
    claim_type: RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE,
    receipt_id: `cycles_release_${randomUUID()}`,
    signer: signerPub,
    agent_id: input.agent_id,
    delegation_ref: input.delegation_ref,
    action_ref: input.action_ref,
    rail_name: 'cycles',
    reservation_id: input.reservation_id,
    released: input.released,
    cycles_evidence: input.cycles_evidence,
    issued_at,
    timestamp: issued_at,
    scope_of_claim: input.scope_of_claim ?? defaultCyclesReleaseReceiptScope(),
  }
  if (input.reason !== undefined) {
    unsigned.reason = input.reason
  }
  const sigBytes = canonicalizeJCSForWrite(unsigned)
  const signature = sign(sigBytes, signerPrivateKeyHex)
  return { ...unsigned, signature }
}

/** Verify a Cycles release receipt (sync). With `options.evidence`, also
 *  checks the receipt↔envelope hash binding and that the envelope is the
 *  referenced stage for the same reservation_id (see `_checkEvidenceJoin`).
 *  Amount, unit, action and server identity are not compared.
 *  NOTE: `valid: true` does NOT assert the envelope's own Ed25519
 *  authenticity or signer authority — that is the v0.2 item (#43). Pin
 *  `expected_signer` for issuer trust until then. */
export function verifyCyclesReleaseReceipt(
  receipt: CyclesReleaseReceipt,
  options: VerifyCyclesOptions = {},
): CyclesVerifyResult {
  const captured = _captureInputs(receipt, options)
  if (!captured.ok) return captured.failure
  return _verifyReceiptCore(captured.receipt, RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE, captured.options)
}

/** Verify a Cycles release receipt (async, DID-URI signers). Join-integrity
 *  caveat as in `verifyCyclesReleaseReceipt`: `valid: true` does NOT assert
 *  the envelope's own Ed25519 authenticity (v0.2 — #43). */
export async function verifyCyclesReleaseReceiptWithDID(
  receipt: CyclesReleaseReceipt,
  options: VerifyCyclesOptions = {},
): Promise<CyclesVerifyResult> {
  const captured = _captureInputs(receipt, options)
  if (!captured.ok) return captured.failure
  return _verifyReceiptWithDID(captured.receipt, RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE, captured.options)
}

// ── Sign / verify: denial ─────────────────────────────────────────

export function signCyclesDenial(
  input: SignCyclesDenialInput,
  signerPrivateKeyHex: string,
): CyclesDenial {
  const signerPub = _cyclesSignerFor(signerPrivateKeyHex, input.issuer_agent_id, input.issuer_key_ref)
  const issued_at = nowIso()
  const unsigned: Omit<CyclesDenial, 'signature'> = {
    claim_type: RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE,
    receipt_id: `cycles_denial_${randomUUID()}`,
    signer: signerPub,
    agent_id: input.agent_id,
    delegation_ref: input.delegation_ref,
    action_ref: input.action_ref,
    rail_name: 'cycles',
    denial_reason: input.denial_reason,
    cycles: input.cycles,
    cycles_evidence: input.cycles_evidence,
    issued_at,
    timestamp: issued_at,
    scope_of_claim: input.scope_of_claim ?? defaultCyclesDenialScope(),
  }
  const sigBytes = canonicalizeJCSForWrite(unsigned)
  const signature = sign(sigBytes, signerPrivateKeyHex)
  return { ...unsigned, signature }
}

/** Verify a Cycles denial (sync). With `options.evidence`, also checks the
 *  receipt↔envelope hash binding (see `_checkEvidenceJoin`). NOTE:
 *  `valid: true` does NOT assert the envelope's own Ed25519 authenticity or
 *  signer authority — that is the v0.2 item (#43). Pin `expected_signer`
 *  for issuer trust until then. */
export function verifyCyclesDenial(
  denial: CyclesDenial,
  options: VerifyCyclesOptions = {},
): CyclesVerifyResult {
  return _verifyReceiptCore(
    denial,
    RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE,
    options,
  )
}

/** Verify a Cycles denial (async, DID-URI signers). Join-integrity caveat
 *  as in `verifyCyclesDenial`: `valid: true` does NOT assert the envelope's
 *  own Ed25519 authenticity (v0.2 — #43). */
export async function verifyCyclesDenialWithDID(
  denial: CyclesDenial,
  options: VerifyCyclesOptions = {},
): Promise<CyclesVerifyResult> {
  return _verifyReceiptWithDID(denial, RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE, options)
}

// ── Internal verifiers (shared by all three artifact types) ───────

type AnyCyclesSigned = CyclesPermitReceipt | CyclesReleaseReceipt | CyclesDenial

/**
 * Join-integrity check: bind the APS receipt to the Cycles-side evidence
 * it references. Recomputes the fetched envelope's content hash per the
 * cycles-evidence-v0.1 normative algorithm (evidence_id + signature both
 * emptied → JCS canonicalize → sha256) and confirms it matches:
 *   (a) the envelope's own `evidence_id`  — the envelope is internally
 *                                           consistent (its id is the true
 *                                           hash of its own content);
 *   (b) the receipt's `cycles_evidence.cycles_evidence_id_sha256`
 *                                          — the receipt binds to THIS envelope.
 *
 * Returns a failing result on mismatch, or `null` when the checks pass
 * or are skipped (no envelope supplied → signature-only verification).
 *
 * Two checks, both gated on a supplied envelope:
 *
 *   1. HASH BINDING + self-consistency (recompute empties BOTH `evidence_id`
 *      and `signature`): the receipt binds to THIS envelope and the envelope
 *      is internally consistent. Mismatch → EVIDENCE_REF_HASH_MISMATCH.
 *
 *   2. ENVELOPE SIGNATURE (APS#43 (a)): the envelope's OWN Ed25519
 *      `signature` verifies against the key named in `signer_did`. The
 *      signed bytes use a DIFFERENT canonicalization — `signature` emptied
 *      but `evidence_id` POPULATED — per cycles-evidence-v0.1's normative
 *      "Signature derivation". Failure → EVIDENCE_SIGNATURE_INVALID.
 *
 *   3. CORRESPONDENCE (8.0.0, permit and release only): the envelope is the
 *      event the receipt references, same stage and same reservation_id (see
 *      `_evaluateCorrespondence`). Failure → EVIDENCE_CORRESPONDENCE_FIELD_MISSING
 *      or EVIDENCE_CORRESPONDENCE_MISMATCH. Denials are not checked here.
 *      The permit and release entry points pass captured inputs (see
 *      `_captureInputs`), so checks 1 to 3 read one value whose fields are
 *      exactly those in the hashed and signed bytes. The stage comes from the
 *      entry point's receipt kind.
 *
 * Scope boundary (the (a)/(b) split): check 2 proves the bytes were signed
 * by the key in `signer_did` — it does NOT prove that key is the legitimate
 * Cycles signer rather than an attacker key inside a self-consistent forgery.
 * That is signer-*authority* resolution (did:cycles / JWKS / rotation), the
 * v0.2 (b) work tracked at runcycles/cycles-protocol#103. The manual form of
 * (b) is pinning the receipt issuer via `options.expected_signer`; the
 * verify result reports which guarantee held via `evidence_authenticity`.
 *
 * Cross-system byte-match note: APS `canonicalizeJCS` reproduces both the
 * `evidence_id` AND the signed bytes of every cycles-protocol reference
 * fixture, so the empty-string-sentinel rules here are the SAME
 * canonicalizations the Cycles server used. Field omission would differ.
 */
function _checkEvidenceJoin(
  obj: AnyCyclesSigned,
  options: VerifyCyclesOptions,
  stage: CorrespondenceStage | undefined,
): CyclesVerifyResult | null {
  const env: CyclesEvidenceEnvelopeInput | undefined = options.evidence
  if (!env) return null

  const recomputed = sha256Hex(
    canonicalizeJCS({ ...env, evidence_id: '', signature: '' }),
  )
  if (recomputed !== env.evidence_id) {
    return {
      valid: false,
      reason: 'EVIDENCE_REF_HASH_MISMATCH',
      detail: `envelope evidence_id ${_show(env.evidence_id)} != recomputed ${recomputed}`,
    }
  }
  if (recomputed !== obj.cycles_evidence.cycles_evidence_id_sha256) {
    return {
      valid: false,
      reason: 'EVIDENCE_REF_HASH_MISMATCH',
      detail: `receipt cycles_evidence_id_sha256 ${_show(obj.cycles_evidence.cycles_evidence_id_sha256)} != envelope ${recomputed}`,
    }
  }

  // (a) Envelope authenticity: verify the envelope's own Ed25519 signature
  // against signer_did. Canonical bytes = envelope with `signature` emptied
  // and `evidence_id` left populated (the post-hash, pre-signature form).
  // Fail closed when either field is absent — a supplied envelope without a
  // verifiable self-signature is not authenticatable. (A `did:`-method
  // signer_did is not resolvable here in v0.1; that is the (b) path.)
  const signerDid = env.signer_did
  if (typeof signerDid !== 'string' || signerDid.length === 0) {
    return { valid: false, reason: 'EVIDENCE_SIGNATURE_INVALID', detail: 'envelope missing signer_did' }
  }
  if (typeof env.signature !== 'string' || env.signature.length === 0) {
    return { valid: false, reason: 'EVIDENCE_SIGNATURE_INVALID', detail: 'envelope missing signature' }
  }
  const envSigBytes = canonicalizeJCS({ ...env, signature: '' })
  if (!edVerify(envSigBytes, env.signature, signerDid)) {
    return {
      valid: false,
      reason: 'EVIDENCE_SIGNATURE_INVALID',
      detail: 'envelope Ed25519 signature does not verify against signer_did',
    }
  }

  // (c) Correspondence (permit and release): the envelope must be the event
  // the receipt references. Runs only after the hash and signature checks
  // pass, so a semantic failure is reported as such. The stage comes from
  // the entry point's receipt kind, never from a field of the input.
  if (!stage) return null
  const correspondence = _evaluateCorrespondence(stage, obj, env)
  if (correspondence.status === 'field_missing') {
    return {
      valid: false,
      reason: 'EVIDENCE_CORRESPONDENCE_FIELD_MISSING',
      detail: `${correspondence.field}: ${correspondence.detail}`,
    }
  }
  if (correspondence.status === 'mismatch') {
    return {
      valid: false,
      reason: 'EVIDENCE_CORRESPONDENCE_MISMATCH',
      detail: `${correspondence.field}: ${correspondence.detail}`,
    }
  }
  return null
}

/** Fields deliberately outside the correspondence check. No equivalence rule
 *  is defined for them yet (estimate vs reserved vs actual amounts, unit
 *  families, action naming, server identity). Reported, never compared. */
const CORRESPONDENCE_NOT_COMPARED: readonly string[] = Object.freeze([
  'amount',
  'unit',
  'action',
  'server_id',
])

function _isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

type CorrespondenceStage = 'reserve' | 'release'

/** The stage a receipt kind references. Taken from the verifier entry point,
 *  never from the input, so a changing `claim_type` cannot switch the check off. */
function _stageFor(claimType: string): CorrespondenceStage | undefined {
  if (claimType === RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE) return 'reserve'
  if (claimType === RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE) return 'release'
  return undefined
}

/** Detail text for any value. `String()` throws on a prototype-free object,
 *  so fall back to JSON. Ordinary values print exactly as before. */
function _show(v: unknown): string {
  try {
    return String(v)
  } catch {
    try {
      return JSON.stringify(v) ?? 'unprintable'
    } catch {
      return 'unprintable'
    }
  }
}

function _parseTime(v: unknown): number {
  try {
    return Date.parse(v as string)
  } catch {
    return NaN
  }
}

/** JSON.parse reviver: every object becomes a prototype-free record, so a
 *  property lookup finds own fields only, even if Object.prototype carries
 *  extra properties. Arrays stay arrays. */
function _prototypeFree(_key: string, value: unknown): unknown {
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    return Object.assign(Object.create(null), value)
  }
  return value
}

type Capture<T> = { ok: true; value: T } | { ok: false; detail: string }

/**
 * Capture an input as the data its canonical bytes encode: one JCS
 * canonicalization, parsed back into prototype-free records. Inherited,
 * non-enumerable and accessor properties and non-JSON containers such as Date
 * are absent or already reduced to their JSON form, and later reads cannot
 * change. Hashing, signature checks and correspondence on the permit and
 * release paths read only captured values.
 */
function _capture<T>(value: T): Capture<T> {
  let bytes: string
  try {
    bytes = canonicalizeJCS(value)
  } catch (err) {
    return { ok: false, detail: `has no canonical JSON form (${err instanceof Error ? err.message : _show(err)})` }
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(bytes, _prototypeFree)
  } catch (err) {
    return { ok: false, detail: `has no capturable JSON form (${err instanceof Error ? err.message : _show(err)})` }
  }
  if (!_isPlainObject(parsed)) return { ok: false, detail: 'is not a JSON object' }
  return { ok: true, value: parsed as T }
}

/** Every supported option, read by name. The check below fails the build if
 *  VerifyCyclesOptions gains a key that is not listed here. */
const VERIFY_OPTION_KEYS = [
  'now',
  'ttl_seconds',
  'expected_signer',
  'resolveDidDocument',
  'resolveEvidence',
  'evidenceFailurePolicy',
  'cyclesKeyResolver',
  'expectedEvidenceSigner',
  'maxEvidenceClockSkewMs',
  'evidence',
] as const satisfies readonly (keyof VerifyCyclesOptions)[]
type _UnlistedOptionKey = Exclude<keyof VerifyCyclesOptions, (typeof VERIFY_OPTION_KEYS)[number]>
const _allOptionKeysListed: [_UnlistedOptionKey] extends [never] ? true : never = true
void _allOptionKeysListed

/** Snapshot of the caller's options: each supported option read once by
 *  ordinary property lookup, as verification always has (own, non-enumerable
 *  or inherited), into a prototype-free object. Later reads and writes touch
 *  only this snapshot, so an accessor on Object.prototype cannot intercept
 *  them, and no constraint the caller supplied is dropped. */
function _snapshotOptions(options: VerifyCyclesOptions): VerifyCyclesOptions {
  const out = Object.create(null) as Record<string, unknown>
  for (const key of VERIFY_OPTION_KEYS) {
    const value = (options as Record<string, unknown>)[key]
    if (value !== undefined) out[key] = value
  }
  return out as VerifyCyclesOptions
}

function _isFetchFailureStatus(v: unknown): v is 'not_found' | 'unreachable' | 'malformed' {
  return v === 'not_found' || v === 'unreachable' || v === 'malformed'
}

/** The envelope a resolution result actually carries: an own property only,
 *  so a value on Object.prototype is never mistaken for a fetched envelope. */
function _ownEnvelope(evidence: EvidenceResolutionResult): EvidenceResolutionResult['envelope'] {
  return Object.prototype.hasOwnProperty.call(evidence, 'envelope') ? evidence.envelope : undefined
}

type CapturedInputs<R> =
  | { ok: true; receipt: R; options: VerifyCyclesOptions }
  | { ok: false; failure: CyclesVerifyResult; field: 'receipt' | 'envelope'; detail: string; options: VerifyCyclesOptions }

/**
 * Entry step for every permit and release verifier. Captures the receipt, the
 * supplied envelope, and (through the resolver) any fetched envelope. A failed
 * capture is a structured rejection. Verification never resumes on the
 * uncaptured object. Denial verifiers do not use this.
 */
function _captureInputs<R extends AnyCyclesSigned>(receipt: R, options: VerifyCyclesOptions): CapturedInputs<R> {
  // One read of each supported option into a prototype-free snapshot (see
  // `_snapshotOptions`). Captured values below replace the originals there.
  const out = _snapshotOptions(options)
  const supplied = out.evidence
  const inner = out.resolveEvidence
  delete out.evidence
  delete out.resolveEvidence
  const r = _capture(receipt)
  if (!r.ok) {
    const detail = `receipt ${r.detail}, so its signature cannot be checked`
    return { ok: false, field: 'receipt', detail, options: out, failure: { valid: false, reason: 'SIGNATURE_INVALID', detail } }
  }
  if (supplied) {
    const e = _capture(supplied)
    if (!e.ok) {
      const detail = `envelope ${e.detail}, so its content hash cannot be recomputed`
      return { ok: false, field: 'envelope', detail, options: out, failure: { valid: false, reason: 'EVIDENCE_REF_HASH_MISMATCH', detail } }
    }
    out.evidence = e.value
  }
  if (inner) {
    out.resolveEvidence = {
      canResolve: (url: string) => inner.canResolve(url),
      resolve: async (url: string): Promise<EvidenceFetchResult> => {
        // Read the caller's result once and return a fresh object, never the
        // caller's own, so resolution cannot re-read a changing field.
        const got = readEvidenceFetchResult(await inner.resolve(url))
        const ok = got.ok
        const envelope = got.envelope
        const status = got.status
        const reason = got.reason
        if (!ok || !envelope) {
          // A failure keeps only a status that means failure. Anything else,
          // including a value that is not the resolver's own, becomes malformed.
          const failed = Object.create(null) as EvidenceFetchResult
          failed.ok = false
          if (status !== undefined) failed.status = _isFetchFailureStatus(status) ? status : 'malformed'
          if (typeof reason === 'string') failed.reason = reason
          return failed
        }
        const e = _capture(envelope)
        return e.ok
          ? { ok: true, envelope: e.value }
          : { ok: false, status: 'malformed', reason: `envelope ${e.detail}` }
      },
    }
  }
  return { ok: true, receipt: r.value, options: out }
}

/**
 * Receipt-to-envelope correspondence (8.0.0). A permit references the reserve
 * event for its reservation, a release references the release event for its
 * reservation. Checks, in order: the receipt's reservation_id, the envelope's
 * `artifact_type`, agreement of the single payload variant with that
 * `artifact_type`, and the envelope's reservation_id at the stage path
 * (reserve: payload.reserve.response.reservation_id, release:
 * payload.release.reservation_id). A missing or malformed field is
 * `field_missing`, never a pass. Callers pass the stage from the verifier
 * entry point and captured inputs only (see `_captureInputs`).
 */
function _evaluateCorrespondence(
  stage: CorrespondenceStage,
  obj: AnyCyclesSigned,
  env: Record<string, unknown>,
): CyclesEvidenceCorrespondence {
  const receiptReservation = (obj as { reservation_id?: unknown }).reservation_id
  if (typeof receiptReservation !== 'string' || receiptReservation.length === 0) {
    return {
      status: 'field_missing',
      field: 'receipt.reservation_id',
      detail: 'absent or not a non-empty string',
    }
  }
  const artifactType = env.artifact_type
  if (typeof artifactType !== 'string' || artifactType.length === 0) {
    return { status: 'field_missing', field: 'artifact_type', detail: 'absent or not a non-empty string' }
  }
  if (artifactType !== stage) {
    return {
      status: 'mismatch',
      field: 'artifact_type',
      detail: `receipt references a ${stage} event, envelope is ${artifactType}`,
    }
  }
  const payload = env.payload
  if (!_isPlainObject(payload)) {
    return { status: 'field_missing', field: 'payload', detail: 'absent or not an object' }
  }
  const variants = Object.keys(payload)
  if (variants.length === 0) {
    return { status: 'field_missing', field: 'payload', detail: 'no payload variant' }
  }
  if (variants.length !== 1 || variants[0] !== stage) {
    return {
      status: 'mismatch',
      field: 'payload',
      detail: `payload variant [${variants.join(', ')}] does not agree with artifact_type ${stage}`,
    }
  }
  const variant = payload[stage]
  if (!_isPlainObject(variant)) {
    return { status: 'field_missing', field: `payload.${stage}`, detail: 'absent or not an object' }
  }
  const holder = stage === 'reserve' ? variant.response : variant
  const path =
    stage === 'reserve' ? 'payload.reserve.response.reservation_id' : 'payload.release.reservation_id'
  const envReservation = _isPlainObject(holder) ? holder.reservation_id : undefined
  if (typeof envReservation !== 'string' || envReservation.length === 0) {
    return { status: 'field_missing', field: path, detail: 'absent or not a non-empty string' }
  }
  if (envReservation !== receiptReservation) {
    return {
      status: 'mismatch',
      field: 'reservation_id',
      detail: `receipt ${receiptReservation} != envelope ${envReservation}`,
    }
  }
  return {
    status: 'matched',
    stage,
    reservation_id: receiptReservation,
    not_compared: CORRESPONDENCE_NOT_COMPARED,
  }
}

/**
 * Build the passing result, tagging envelope authenticity (APS#43) when an
 * envelope was supplied. Reaching here with `options.evidence` set means the
 * join check passed, i.e. the envelope's signature verified ((a) held), so
 * the tag is 'pinned_issuer' when the APS receipt issuer is pinned via
 * `expected_signer` (envelope authenticity then holds transitively through
 * the trusted issuer — not a direct proof of signer_did authority) and
 * 'signature_valid' otherwise. Omitted entirely when no envelope was passed.
 */
function _validResult(options: VerifyCyclesOptions): CyclesVerifyResult {
  if (!options.evidence) return { valid: true }
  return {
    valid: true,
    evidence_authenticity: options.expected_signer ? 'pinned_issuer' : 'signature_valid',
  }
}

function _verifyReceiptCore(
  obj: AnyCyclesSigned,
  expectedClaimType:
    | typeof RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE
    | typeof RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE
    | typeof RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE,
  options: VerifyCyclesOptions,
): CyclesVerifyResult {
  const ttl = options.ttl_seconds ?? 24 * 60 * 60

  if (obj.claim_type !== expectedClaimType) {
    return { valid: false, reason: 'INVALID_CLAIM_TYPE', detail: `expected ${expectedClaimType} got ${_show(obj.claim_type)}` }
  }
  if (!obj.receipt_id || !obj.signer || !obj.agent_id || !obj.delegation_ref || !obj.action_ref) {
    return { valid: false, reason: 'MISSING_REQUIRED_FIELD' }
  }
  if (obj.rail_name !== 'cycles') {
    return { valid: false, reason: 'INVALID_RAIL_NAME', detail: `expected 'cycles' got ${_show(obj.rail_name)}` }
  }
  // cycles_evidence must be an object. An array or other value would let its
  // fields be looked up on a prototype instead of in the signed bytes.
  if (
    !_isPlainObject(obj.cycles_evidence) ||
    !obj.cycles_evidence.cycles_evidence_url ||
    !obj.cycles_evidence.cycles_evidence_id_sha256
  ) {
    return { valid: false, reason: 'MISSING_REQUIRED_FIELD', detail: 'cycles_evidence' }
  }
  // Join-integrity: when the fetched envelope is supplied, bind it to the
  // receipt. Runs before signature/DID checks so a broken receipt↔envelope
  // join surfaces regardless of signer type (the DID path calls this core
  // first and propagates any non-DID_RESOLVER_MISSING failure unchanged).
  const joinFailure = _checkEvidenceJoin(obj, options, _stageFor(expectedClaimType))
  if (joinFailure) return joinFailure
  if (options.expected_signer && obj.signer !== options.expected_signer) {
    return { valid: false, reason: 'SIGNATURE_INVALID', detail: 'signer mismatch' }
  }

  const issuedMs = _parseTime(obj.issued_at)
  if (!Number.isFinite(issuedMs)) {
    return { valid: false, reason: 'MISSING_REQUIRED_FIELD', detail: 'issued_at' }
  }
  const nowMs = (options.now ?? new Date()).getTime()
  if (nowMs - issuedMs > ttl * 1000) {
    return { valid: false, reason: 'EXPIRED', detail: `older than ttl=${ttl}s` }
  }

  // Accountability-shape invariants (mpp convention). Cycles receipts
  // always carry the accountability fields (claim_type, timestamp,
  // scope_of_claim), so these are always checked.
  if (obj.timestamp !== obj.issued_at) {
    return { valid: false, reason: 'MISSING_REQUIRED_FIELD', detail: 'timestamp != issued_at' }
  }
  if (
    !_isPlainObject(obj.scope_of_claim) ||
    typeof obj.scope_of_claim.asserts !== 'string' ||
    obj.scope_of_claim.asserts.length === 0
  ) {
    return { valid: false, reason: 'MISSING_REQUIRED_FIELD', detail: 'scope_of_claim' }
  }

  // signature verify — strip sig, canonicalize, verify
  const { signature, ...rest } = obj
  const sigBytes = canonicalizeJCS(rest)
  if (typeof obj.signer === 'string' && obj.signer.startsWith('did:')) {
    return {
      valid: false,
      reason: 'DID_RESOLVER_MISSING',
      detail: 'use verify*WithDID for DID-URI signers',
    }
  }
  if (!edVerify(sigBytes, signature, obj.signer)) {
    return { valid: false, reason: 'SIGNATURE_INVALID', detail: 'Ed25519 verify failed' }
  }
  return _validResult(options)
}

async function _verifyReceiptWithDID(
  obj: AnyCyclesSigned,
  expectedClaimType:
    | typeof RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE
    | typeof RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE
    | typeof RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE,
  options: VerifyCyclesOptions,
): Promise<CyclesVerifyResult> {
  const sync = _verifyReceiptCore(obj, expectedClaimType, options)
  if (sync.valid) return sync
  if (sync.reason !== 'DID_RESOLVER_MISSING') return sync
  if (!options.resolveDidDocument) {
    return { valid: false, reason: 'DID_RESOLVER_MISSING' }
  }
  const parsed = parseDidUri(obj.signer)
  if (!parsed) return { valid: false, reason: 'DID_URI_INVALID' }
  const didDoc = await options.resolveDidDocument(parsed.agentId)
  if (!didDoc) return { valid: false, reason: 'DID_DOC_NOT_FOUND' }
  const issuedMs = _parseTime(obj.issued_at)
  const result = resolveVerificationMethod(
    didDoc,
    obj.signer,
    options.now ? options.now.getTime() : undefined,
    Number.isFinite(issuedMs) ? issuedMs : undefined,
  )
  if (!result) return { valid: false, reason: 'DID_KEY_NOT_IN_DOC' }
  if (result.retired) return { valid: false, reason: 'DID_KEY_RETIRED' }
  const pubHex = publicKeyHexFromMethod(result.method)
  const { signature, ...rest } = obj
  const sigBytes = canonicalizeJCS(rest)
  if (!edVerify(sigBytes, signature, pubHex)) {
    return { valid: false, reason: 'SIGNATURE_INVALID', detail: 'Ed25519 verify failed' }
  }
  return _validResult(options)
}

// ── External-evidence resolution: claimed vs resolved (W2-A2) ─────
// The sync/_WithDID paths above signature-check the receipt, which
// covers the CLAIMED cycles_evidence_id_sha256 but never fetches the
// envelope at cycles_evidence_url. These *WithEvidence paths COMPLETE
// the join-integrity check the file header flagged as a TODO: they run
// the full receipt verification first, then (when a caller-supplied
// resolver is present) fetch the envelope and recompute its content
// hash to test the claimed value. Egress lives entirely in the
// caller's resolver; the SDK reaches no global fetch.

/**
 * Combined verify + evidence-resolution result. `verify` is the existing
 * receipt verdict (signature, ttl, accountability shape - unchanged).
 * `evidence` is the claimed-vs-resolved verdict for the CyclesEvidence
 * envelope. `descriptor` is the mechanical input the W2-A1 verifier
 * descriptor consumes for the external-evidence axis.
 *
 * A green `verify` with a `signature_only` `descriptor.observation_basis`
 * is the explicit "claims an envelope at hash H, signature-checked only"
 * state. `counterparty_resolved` is "envelope at H fetched and matched".
 */
export interface CyclesVerifyWithEvidenceResult {
  verify: CyclesVerifyResult
  evidence: EvidenceResolutionResult
  descriptor: EvidenceDescriptorInput
  /** Signer-authority disposition for the FETCHED envelope's own Ed25519
   *  signature (#43): one of authentic / binding_only / signer_resolution_failed
   *  / signer_authority_failed / signature_invalid. `authentic` only when a key
   *  resolved from the server's JWK Set under the issuance-time window verifies
   *  the envelope (after its evidence_id re-derives). */
  authority: CyclesEvidenceAuthorityResult
  /** Receipt-to-envelope correspondence for the FETCHED envelope (8.0.0).
   *  Evaluated for permit and release receipts when resolution `matched`,
   *  else `not_applicable`. Additive and independent of `verify`, `evidence`
   *  and `authority`: a consumer that needs "this envelope is the event this
   *  receipt references" must read it. `matched` covers stage and
   *  reservation_id only. */
  correspondence: CyclesEvidenceCorrespondence
}

/**
 * Signer-authority verdict for a CyclesEvidence envelope. The five DISTINCT
 * dispositions of the cycles-evidence-v0.1 verification model (kept separate on
 * purpose — a forgery, an unreachable key directory, and a valid-but-unresolved
 * signature are different events):
 *
 *  - `authentic`              — signature verifies under the window-selected key
 *                               resolved from the server's JWK Set (validity AND
 *                               authority).
 *  - `binding_only`           — signature cryptographically VALID against the
 *                               named raw-hex signer, but JWKS authority was not
 *                               resolved (no resolver / v0.1 posture). Only ever
 *                               returned after a successful signature check.
 *  - `signer_resolution_failed` — the DID method / JWK Set could not be reached
 *                               or parsed (network/availability). Establishes
 *                               NOTHING about the bytes; NOT a forgery.
 *  - `signer_authority_failed`  — the set resolved, but no single authorized
 *                               key covers the envelope (hash-bind mismatch, no
 *                               window-covering key, absent, or ambiguous).
 *  - `signature_invalid`      — the envelope's `evidence_id` does not re-derive,
 *                               or the bytes do not verify under the resolved
 *                               key (tamper).
 *
 * CONTRACT — what `authentic` is NOT. `authentic` means only: signed by the
 * named signer's window-valid key. It is NOT an authorization decision (it does
 * not say the signer was permitted to issue this) and NOT a freshness guarantee
 * (a valid envelope replays as `authentic` for any `issued_at_ms` inside the
 * key window — see scope limits below). `binding_only` is weaker still: the
 * signature is self-consistent with a NAMED key that carries no resolved
 * identity or authority. The failure mode worth naming is a consumer treating
 * EITHER disposition as "trusted counterparty" — authority lives in the
 * caller's own allowed-signer set (assert the surfaced `signerDid`, or pin it
 * via `options.expectedEvidenceSigner`), never in the disposition alone.
 *
 * SCOPE LIMITS (verify-at-issuance design, stated so callers handle them):
 *   1. Replay. A valid envelope verifies as `authentic` every time within the
 *      key window — disposition carries no once-only guarantee. Callers MUST
 *      deduplicate on `evidence_id` to detect replay.
 *   2. Window, not wall clock. Key selection gates the key's
 *      `[cycles_nbf_ms, cycles_exp_ms)` against the envelope's own
 *      `issued_at_ms`, not the current time. Revocation safety therefore leans
 *      on the SERVER dropping a revoked key from its published JWK Set: a
 *      still-published key verifies for ANY backdated `issued_at_ms` inside its
 *      window. `options.maxEvidenceClockSkewMs` adds an opt-in drift bound as
 *      cheap defense-in-depth.
 */
export interface CyclesEvidenceAuthorityResult {
  disposition:
    | 'authentic'
    | 'binding_only'
    | 'signer_resolution_failed'
    | 'signer_authority_failed'
    | 'signature_invalid'
  reason?: string
  /** kid of the resolved key, when authentic. */
  resolvedKid?: string
  /** The CRYPTOGRAPHICALLY VERIFIED `signer_did` of the envelope, surfaced on
   *  `authentic` and `binding_only` (the two dispositions reached only after a
   *  passing signature check) so the caller can assert it against its own
   *  allowed-signer set. Absent on every non-verified disposition. NOTE this is
   *  the signer the bytes verified UNDER; on `binding_only` that authority is
   *  unresolved, so presence here is identity, not endorsement. */
  signerDid?: string
}

const _authority = (
  disposition: CyclesEvidenceAuthorityResult['disposition'],
  reason: string,
): CyclesEvidenceAuthorityResult => ({ disposition, reason })

/** Finalize a disposition reached AFTER a passing signature check (`authentic`
 *  or `binding_only`): surface the verified `signerDid`, then apply the
 *  caller's `expectedEvidenceSigner` pin, failing CLOSED to
 *  `signer_authority_failed` when the verified signer is not the pinned one. */
const _verified = (
  disposition: 'authentic' | 'binding_only',
  signerDid: string,
  options: VerifyCyclesOptions,
  extra: { reason?: string; resolvedKid?: string } = {},
): CyclesEvidenceAuthorityResult => {
  // Presence test, NOT truthiness: a supplied pin is honored even if it is the
  // empty string (which can never equal a verified, non-empty signer_did, so it
  // fails CLOSED). Only an omitted pin (undefined) skips the check.
  if (typeof options.expectedEvidenceSigner === 'string' && signerDid !== options.expectedEvidenceSigner) {
    return _authority(
      'signer_authority_failed',
      `verified signer_did does not match pinned expectedEvidenceSigner (got ${signerDid}) — fail closed`,
    )
  }
  return { disposition, signerDid, ...extra }
}

const RAW_HEX_KEY = /^[0-9a-fA-F]{64}$/

/** The supported fields of a key resolver answer, each read once by name and
 *  only when it is the answer's own property (enumerable or not), into a
 *  prototype-free record. No other field is read. Undefined for anything that
 *  is not an object. Callers read this inside their error guard, so a
 *  throwing accessor on a supported field becomes a structured failure. */
const KEY_ANSWER_FIELDS = ['ok', 'publicKeyHex', 'kid', 'status', 'reason'] as const
function _readKeyAnswer(value: unknown): Record<(typeof KEY_ANSWER_FIELDS)[number], unknown> | undefined {
  if (value === null || typeof value !== 'object') return undefined
  const out = Object.create(null) as Record<(typeof KEY_ANSWER_FIELDS)[number], unknown>
  for (const key of KEY_ANSWER_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(value, key)) out[key] = (value as Record<string, unknown>)[key]
  }
  return out
}

/** Map a non-ok KeyResolution status to the spec disposition. Failure to
 *  OBTAIN/parse the SET (network, or an unparseable set body) is
 *  resolution_failed; a parsed set with no single authorized key — incl. the
 *  did:cycles hash-bind mismatch (reported as not_found) and a malformed
 *  selected KEY's `x` — is authority_failed. The resolver reports both an
 *  unparseable set body AND a malformed selected key as `malformed`, so they
 *  are split by the reason text (the set-body case is the only one that
 *  mentions the missing `keys[]` array).
 *
 *  NOTE (deferred hardening, #43 review): this couples to the resolver's reason
 *  WORDING. Both outcomes map to non-authentic so it is safe, but a typed
 *  status off `KeyResolution` (e.g. `set_unparseable` vs `key_malformed`) would
 *  be sturdier than a regex on the message. Tracked as a follow-up; not changed
 *  here to keep this PR's resolver contract stable. */
function _authorityFromResolution(
  status: string,
  reason?: string,
): 'signer_resolution_failed' | 'signer_authority_failed' {
  if (status === 'unreachable') return 'signer_resolution_failed'
  if (status === 'malformed') {
    return reason && /keys\[\]|missing non-empty|not valid JSON/i.test(reason)
      ? 'signer_resolution_failed' // unparseable JWK Set body
      : 'signer_authority_failed' // malformed selected key material
  }
  return 'signer_authority_failed' // not_found / ambiguous / unsupported
}

/**
 * Resolve and verify the FETCHED envelope's own Ed25519 signature against the
 * Cycles signer's published key. RE-DERIVES `evidence_id` and byte-compares it
 * (normative recipe) BEFORE verifying the cycles signing input (JCS with
 * `signature` emptied, `evidence_id` left populated). Reports one of the five
 * distinct dispositions; `binding_only` is returned ONLY when the signature is
 * cryptographically VALID against the named raw-hex signer but JWKS authority
 * was not resolved — it never labels an unchecked or invalid signature.
 */
async function _resolveEnvelopeAuthority(
  env: FetchedCyclesEvidenceEnvelope | undefined,
  options: VerifyCyclesOptions,
): Promise<CyclesEvidenceAuthorityResult> {
  if (!env) return _authority('signer_resolution_failed', 'no envelope fetched (evidence not resolved)')
  const signerDid = typeof env.signer_did === 'string' ? env.signer_did : ''
  const serverId = typeof env.server_id === 'string' ? env.server_id : ''
  const issuedAtMs = env.issued_at_ms
  const signature = typeof env.signature === 'string' ? env.signature : ''
  if (!signerDid || !signature) {
    return _authority('signature_invalid', 'envelope has no signer_did/signature — no verifiable signature')
  }
  if (!serverId || typeof issuedAtMs !== 'number' || !Number.isInteger(issuedAtMs)) {
    return _authority('signer_authority_failed', 'envelope missing server_id / integer issued_at_ms — cannot resolve a windowed key')
  }
  // Optional freshness bound (#43 defense-in-depth): key selection gates the
  // key window against issued_at_ms, not wall clock, so a backdated timestamp
  // inside a still-published key's window verifies. When the caller sets a
  // drift bound, reject an implausible issued_at_ms (either direction) before
  // resolving the key.
  if (typeof options.maxEvidenceClockSkewMs === 'number') {
    const bound = options.maxEvidenceClockSkewMs
    const now = options.now ? options.now.getTime() : Date.now()
    // Fail CLOSED on a degenerate bound or clock — a NaN/Infinity bound or an
    // invalid `now` Date makes the drift comparison false, which would silently
    // SKIP the check (fail open). Reject instead.
    if (!Number.isFinite(bound) || bound < 0 || !Number.isFinite(now)) {
      return _authority(
        'signer_authority_failed',
        `unusable freshness bound (maxEvidenceClockSkewMs=${bound}) or clock — fail closed`,
      )
    }
    if (Math.abs(now - issuedAtMs) > bound) {
      return _authority(
        'signer_authority_failed',
        `envelope issued_at_ms drifts ${Math.abs(now - issuedAtMs)}ms from now, beyond maxEvidenceClockSkewMs=${bound} — fail closed`,
      )
    }
  }
  const isDid = isDIDCycles(signerDid)
  const isRaw = RAW_HEX_KEY.test(signerDid)
  if (!isDid && !isRaw) {
    return _authority('signer_authority_failed', 'signer_did is neither a did:cycles nor a raw 64-hex key')
  }

  // Content integrity FIRST (envelope-intrinsic, independent of the resolver):
  // re-derive evidence_id and byte-compare; a mismatch is tamper.
  let recomputedId: string
  let signingInput: string
  try {
    recomputedId = sha256Hex(canonicalizeJCS({ ...env, evidence_id: '', signature: '' }))
    // SINGLE verification form (#43 review note): the signing input is the JCS
    // with `signature` emptied and `evidence_id` LEFT POPULATED. Do not add a
    // fallback that also verifies over an `evidence_id`-blanked form — that
    // would stop `evidence_id` from being signature-covered.
    signingInput = canonicalizeJCS({ ...env, signature: '' })
  } catch (err) {
    return _authority('signature_invalid', `envelope canonicalization failed: ${err instanceof Error ? err.message : String(err)}`)
  }
  if (recomputedId !== env.evidence_id) {
    return _authority('signature_invalid', `evidence_id does not re-derive (${recomputedId} != ${_show(env.evidence_id)}) — envelope tampered`)
  }

  const resolver: KeyResolver | undefined = options.cyclesKeyResolver
  if (!resolver) {
    // No JWKS authority resolution. Raw-hex: the signer_did IS the key, so the
    // signature can be checked against it — a VALID signature is binding_only
    // (the v0.1 posture), an invalid one is signature_invalid. did:cycles: the
    // subject is a hash, so the signature is not checkable without the JWK Set.
    if (isRaw) {
      return edVerify(signingInput, signature, signerDid)
        ? _verified('binding_only', signerDid, options, { reason: 'signature valid against the named raw-hex signer; JWKS authority not resolved (no resolver)' })
        : _authority('signature_invalid', 'signature did not verify against the named raw-hex signer')
    }
    return _authority('signer_authority_failed', 'did:cycles authority requires a key resolver; signature not checkable without the JWK Set')
  }

  const locator: KeyLocator = isDid
    ? { did: signerDid, serverId, issuedAtMs }
    : { jwksUrl: cyclesJwksUrl(serverId), publicKeyHex: signerDid, issuedAtMs }

  // The verify path must never throw — a non-conformant resolver that rejects
  // is treated as a resolution failure, never authentic.
  // Read the key resolver's answer from its own supported properties only,
  // once, inside the guard. A key or success flag found only on
  // Object.prototype is not a resolution.
  let res
  try {
    res = _readKeyAnswer(await resolver.resolve(locator))
  } catch (err) {
    return _authority('signer_resolution_failed', `authority resolution threw: ${err instanceof Error ? err.message : String(err)}`)
  }
  if (!res) {
    return _authority('signer_resolution_failed', 'key resolver did not return an object')
  }
  const resStatus = typeof res.status === 'string' ? res.status : ''
  const resReason = typeof res.reason === 'string' ? res.reason : undefined
  const publicKeyHex = typeof res.publicKeyHex === 'string' ? res.publicKeyHex : ''
  if (res.ok !== true || !publicKeyHex) {
    return _authority(
      _authorityFromResolution(resStatus, resReason),
      `signer-key resolution failed (status=${resStatus || 'none'}${resReason ? `: ${resReason}` : ''})`,
    )
  }
  if (!edVerify(signingInput, signature, publicKeyHex)) {
    return _authority('signature_invalid', 'envelope signature did not verify under the resolved key')
  }
  return _verified('authentic', signerDid, options, typeof res.kid === 'string' ? { resolvedKid: res.kid } : {})
}

async function _verifyWithEvidence(
  obj: AnyCyclesSigned,
  expectedClaimType:
    | typeof RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE
    | typeof RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE
    | typeof RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE,
  options: VerifyCyclesOptions,
): Promise<CyclesVerifyWithEvidenceResult> {
  // Run the full receipt verification (DID-aware) first.
  const verify = await _verifyReceiptWithDID(obj, expectedClaimType, options)
  const stage = _stageFor(expectedClaimType)
  // Resolve the evidence ref regardless of the receipt verdict, so the
  // descriptor always reports the claimed-vs-resolved basis. Resolution
  // records failure, never throws. On the permit and release paths a ref that
  // is not an object is not read (its fields could come from a prototype).
  const evidence =
    stage && !_isPlainObject(obj.cycles_evidence)
      ? await _unreadEvidence('receipt cycles_evidence is not an object', options)
      : await resolveEvidenceRef(
          obj.cycles_evidence,
          options.resolveEvidence,
          { failurePolicy: options.evidenceFailurePolicy },
        )
  // Signer authority (#43): resolve the fetched envelope's signer key and
  // verify the envelope's own signature. Independent of the receipt verdict
  // and the hash join; reports one of the five distinct dispositions, never throws.
  const fetchedEnvelope = _ownEnvelope(evidence)
  const authority = await _resolveEnvelopeAuthority(fetchedEnvelope, options)
  // Correspondence (8.0.0) on the FETCHED envelope, reported separately so
  // verify / evidence / authority keep their meanings.
  // Stage from the entry point. The fetched envelope reaching here on the
  // permit and release paths is the captured one (see `_captureInputs`).
  const correspondence: CyclesEvidenceCorrespondence = !stage
    ? { status: 'not_applicable', reason: 'correspondence is evaluated for permit and release receipts only' }
    : evidence.resolved === true && evidence.status === 'matched' && _isPlainObject(fetchedEnvelope)
      ? _evaluateCorrespondence(stage, obj, fetchedEnvelope)
      : { status: 'not_applicable', reason: `no matched envelope (status=${evidence.status})` }
  return {
    verify,
    evidence,
    descriptor: toEvidenceDescriptorInput(evidence),
    authority,
    correspondence,
  }
}

/** The fetched-path result when capture failed. Nothing further is read from
 *  the uncaptured input: verify carries the structured rejection, the evidence
 *  reference is reported malformed and unresolved, authority is not evaluated,
 *  and correspondence names the field that could not be captured. */
/** An evidence result reported as malformed and unresolved, built without
 *  reading any caller input. */
function _unreadEvidence(detail: string, options: VerifyCyclesOptions): Promise<EvidenceResolutionResult> {
  const reason = `not read: ${detail}`
  return resolveEvidenceRef(
    { cycles_evidence_url: '', cycles_evidence_id_sha256: '', action_ref: '', delegation_ref: '' },
    { canResolve: () => true, resolve: async () => ({ ok: false, status: 'malformed', reason }) },
    { failurePolicy: options.evidenceFailurePolicy },
  )
}

async function _rejectedWithEvidence(captured: {
  failure: CyclesVerifyResult
  field: 'receipt' | 'envelope'
  detail: string
  options: VerifyCyclesOptions
}): Promise<CyclesVerifyWithEvidenceResult> {
  const evidence = await _unreadEvidence(captured.detail, captured.options)
  return {
    verify: captured.failure,
    evidence,
    descriptor: toEvidenceDescriptorInput(evidence),
    authority: _authority('signer_resolution_failed', `not evaluated: ${captured.detail}`),
    correspondence: { status: 'field_missing', field: captured.field, detail: captured.detail },
  }
}

export async function verifyCyclesPermitReceiptWithEvidence(
  receipt: CyclesPermitReceipt,
  options: VerifyCyclesOptions = {},
): Promise<CyclesVerifyWithEvidenceResult> {
  const captured = _captureInputs(receipt, options)
  if (!captured.ok) return _rejectedWithEvidence(captured)
  return _verifyWithEvidence(captured.receipt, RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE, captured.options)
}

export async function verifyCyclesReleaseReceiptWithEvidence(
  receipt: CyclesReleaseReceipt,
  options: VerifyCyclesOptions = {},
): Promise<CyclesVerifyWithEvidenceResult> {
  const captured = _captureInputs(receipt, options)
  if (!captured.ok) return _rejectedWithEvidence(captured)
  return _verifyWithEvidence(captured.receipt, RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE, captured.options)
}

/**
 * Verify a FETCHED CyclesEvidence envelope's own signer authority directly
 * (#43), independent of any APS receipt. Resolves `signer_did` to a public key
 * via the caller-supplied `cyclesKeyResolver` (did:cycles sha256-binding +
 * window-gated selection, or raw-hex match), re-derives `evidence_id`, and
 * verifies the envelope's Ed25519 signature, returning one of the five
 * dispositions (authentic / binding_only / signer_resolution_failed /
 * signer_authority_failed / signature_invalid). The conformance surface a
 * consumer (e.g. against the Cycles golden vectors) runs.
 */
export async function verifyCyclesEvidenceSignerAuthority(
  envelope: FetchedCyclesEvidenceEnvelope,
  options: VerifyCyclesOptions = {},
): Promise<CyclesEvidenceAuthorityResult> {
  return _resolveEnvelopeAuthority(envelope, options)
}

export async function verifyCyclesDenialWithEvidence(
  denial: CyclesDenial,
  options: VerifyCyclesOptions = {},
): Promise<CyclesVerifyWithEvidenceResult> {
  return _verifyWithEvidence(denial, RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE, options)
}

/** Re-export the resolver type for callers wiring the async paths. */
export type { CyclesResolveDidDocument } from './types.js'

// ── External-evidence resolution surface (W2-A2) ──────────────────
export {
  resolveEvidenceRef,
  recomputeEvidenceContentHash,
  toEvidenceDescriptorInput,
} from './evidence-resolution.js'
export type {
  EvidenceResolver,
  EvidenceFetchResult,
  EvidenceResolutionResult,
  EvidenceResolutionStatus,
  EvidenceFailurePolicy,
  ResolveEvidenceConfig,
  FetchedCyclesEvidenceEnvelope,
  EvidenceDescriptorInput,
  EvidenceObservationBasis,
} from './evidence-resolution.js'
