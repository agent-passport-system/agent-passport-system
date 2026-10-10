// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Deterministic generator for the `aps.agent-passport` 2.0 vector family.
//
//   npx tsx fixtures/agent-passport-v2/generate-fixtures.ts
//
// Nothing here reads a clock or a random source. Every input is fixed:
//
//   - Ed25519 seeds are sha256 of a published label, so anybody can re-derive
//     them from this file's text alone (see SEED_LABEL_PREFIX below).
//   - issued_at, expires_at, nonce, display_name and capabilities are constants.
//   - The verification instant `now` is a constant per case.
//   - The historical key resolver is a table written into the vector file, so
//     the resolver a consumer runs is the resolver this generator ran.
//
// Ed25519 signing is deterministic (RFC 8032), so two runs emit byte-identical
// output. `git diff` after a second run is the check that matters.
//
// Every expected verification outcome below is OBSERVED: the generator runs the
// merged verifier (src/v2/identity-binding/passport.ts) and writes down what it
// returned. Each case also declares the result it expects, and the generator
// refuses to write the file if the verifier disagrees, so a behaviour change
// surfaces here rather than being silently re-baselined into the vector.
//
// Spec: draft-pidlisnyi-aps-04 section 3.1 (Agent Passport) and 3.2 (Agent
// Identifiers). The draft fixes the wire shape, the two domain-separated
// constructions, the validity interval issued_at <= now < expires_at, and the
// rule that proof of possession is reported separately from key authority. It
// does not fix the code strings a verifier returns, a reporting schema, or an
// order of checks. `verification` on every case is what this SDK returned at the
// pinned commit. `layers` is this fixture family's own diagnostic schema: it
// describes which checks this run reached and what they found. It is not a
// format or a check order that draft-04 requires.

import { createHash } from 'node:crypto'
import { writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { publicKeyFromPrivate, sign } from '../../src/crypto/keys.js'
import { canonicalizeJCS } from '../../src/core/canonical-jcs.js'
import { hexToMultibase } from '../../src/core/did.js'
import {
  defaultVerificationMethod,
  didKeyFromPublicKey,
} from '../../src/v2/identity-binding/did-aps.js'
import { issuePassportV2, verifyPassportV2 } from '../../src/v2/identity-binding/passport.js'
import type {
  HistoricalKeyResolutionRequest,
  HistoricalKeyResolutionResult,
  IdentityVerificationResult,
  PassportV2,
} from '../../src/v2/identity-binding/types.js'

// ── the SDK this file's outcomes were produced by ─────────────────────────────
// The commit whose src/ tree the generator ran against. The vector files
// themselves are added on top of it, so the repository HEAD that carries this
// file is a later commit. What this SHA pins is the implementation, not the
// fixture.
const SDK_COMMIT = 'c31d94aad86713ae9b2e4cbc811deeab4b5d91ed'
const SDK_RELEASE = 'main after the v7.2.1 tag (git describe: v7.2.1-14-gc31d94a), unreleased'
const GENERATED_AT = '2026-10-10'

// ── the two domain tags, draft-04 section 3.1 ─────────────────────────────────
// Re-typed here rather than imported: passport.ts keeps them module-private, and
// the generator checks its own copies against the SDK's output below (a
// passport_id or signature that does not recompute from these tags would make
// the generator refuse to write).
const ID_DOMAIN = 'APS-PASSPORT-ID-V2\u0000'
const SIGNATURE_DOMAIN = 'APS-PASSPORT-SIG-V2\u0000'

// ── keys: seeds derived from published labels ─────────────────────────────────
// Any 32 bytes is a valid Ed25519 seed, and src/crypto/keys.ts takes the seed as
// 64 lowercase hex. Deriving it from a label means the vector carries no opaque
// constant: sha256 of the label string IS the private key, re-derivable in any
// language. These are test keys published in a public repository and control
// nothing.
const SEED_LABEL_PREFIX = 'agent-passport-system:agent-passport-vector:'

function seedFromLabel(label: string): string {
  return createHash('sha256').update(SEED_LABEL_PREFIX + label, 'utf8').digest('hex')
}

const KEY_LABELS = ['agent-key', 'other-key', 'web-agent-key'] as const
type KeyLabel = (typeof KEY_LABELS)[number]

const PRIVATE = Object.fromEntries(
  KEY_LABELS.map(label => [label, seedFromLabel(label)]),
) as Record<KeyLabel, string>
const PUBLIC = Object.fromEntries(
  KEY_LABELS.map(label => [label, publicKeyFromPrivate(PRIVATE[label])]),
) as Record<KeyLabel, string>

// ── identifiers ───────────────────────────────────────────────────────────────
// did:key is self-certifying: the identifier commits to the signing key
// (section 3.2). did:web is not: key authority needs a resolver.
const AGENT_DID_KEY = didKeyFromPublicKey(PUBLIC['agent-key'])
const OTHER_DID_KEY = didKeyFromPublicKey(PUBLIC['other-key'])
const WEB_AGENT = 'did:web:agents.example'
const WEB_AGENT_VM = `${WEB_AGENT}#key-1`
const WEB_UNKNOWN = 'did:web:unknown.example'
const WEB_UNKNOWN_VM = `${WEB_UNKNOWN}#key-1`
const WEB_OFFLINE = 'did:web:offline.example'
const WEB_OFFLINE_VM = `${WEB_OFFLINE}#key-1`

// ── fixed times and nonces ────────────────────────────────────────────────────
const ISSUED_AT = '2026-10-01T00:00:00.000Z'
const EXPIRES_AT = '2027-10-01T00:00:00.000Z'
const NOW = '2026-10-10T12:00:00.000Z'
const NOW_BEFORE_ISSUE = '2026-09-30T23:59:59.999Z'
const NOW_AT_EXPIRY = '2027-10-01T00:00:00.000Z'
const NONCE_A = '00112233445566778899aabbccddeeff'
const NONCE_B = 'ffeeddccbbaa99887766554433221100'
const NONCE_C = '0123456789abcdef0123456789abcdef'
const DISPLAY_NAME = 'Vector Agent'
const CAPABILITIES = ['commerce:checkout', 'data:read']

// ── the historical key resolver, as data ──────────────────────────────────────
// draft-04 section 3.1: for an identifier that is not self-certifying, key
// authority is verified by resolving verification_method at issued_at under the
// identifier's own method. passport.ts hands the resolver
// { controller: agent_id, verification_method, at: issued_at }.
//
// The did:web entry has no validity window, so no retirement boundary exists and
// the outcome does not depend on when the key is resolved. Section 3.4 does not
// let an issuer's issued_at claim alone select a retired key, and this file
// carries no timestamp evidence, so retired-key selection is deliberately not
// exercised. The generator records every request the verifier makes and refuses
// to write the file unless `at` equals the passport's issued_at, and the test
// asserts the same, so resolving at the verification instant is still caught.

interface ResolverEntry {
  controller: string
  verification_method: string
  outcome: HistoricalKeyResolutionResult['state']
  public_key_hex?: string
  key_label?: KeyLabel
}

const RESOLVER_ENTRIES: ResolverEntry[] = [
  {
    controller: WEB_AGENT,
    verification_method: WEB_AGENT_VM,
    outcome: 'resolved',
    public_key_hex: PUBLIC['web-agent-key'],
    key_label: 'web-agent-key',
  },
  {
    controller: WEB_OFFLINE,
    verification_method: WEB_OFFLINE_VM,
    outcome: 'unreachable',
  },
]

/**
 * The resolver over the table above. A (controller, verification_method) pair
 * the table does not carry answers not_found. An entry whose outcome is not
 * `resolved` answers that outcome with no key. A consumer of this vector
 * reimplements exactly this function.
 */
function resolveKey(request: HistoricalKeyResolutionRequest): HistoricalKeyResolutionResult {
  const entry = RESOLVER_ENTRIES.find(
    item =>
      item.controller === request.controller &&
      item.verification_method === request.verification_method,
  )
  if (!entry) return { state: 'not_found' }
  if (entry.outcome !== 'resolved') return { state: entry.outcome }
  return { state: 'resolved', public_key_hex: entry.public_key_hex }
}

// ── passports ─────────────────────────────────────────────────────────────────
function issue(
  label: KeyLabel,
  overrides: Partial<Parameters<typeof issuePassportV2>[0]> = {},
): PassportV2 {
  return issuePassportV2({
    public_key_hex: PUBLIC[label],
    private_key_hex: PRIVATE[label],
    issued_at: ISSUED_AT,
    expires_at: EXPIRES_AT,
    nonce: NONCE_A,
    ...overrides,
  })
}

// did:key, nothing self-asserted beyond the required empty capabilities array.
const minimal = issue('agent-key')
// did:key, with display_name and two sorted capabilities.
const withSelfAsserted = issue('agent-key', {
  nonce: NONCE_B,
  display_name: DISPLAY_NAME,
  capabilities: CAPABILITIES,
})
// did:web, key authority comes from the resolver table.
const webPassport = issue('web-agent-key', {
  agent_id: WEB_AGENT,
  verification_method: WEB_AGENT_VM,
  nonce: NONCE_C,
})

// ── helpers ───────────────────────────────────────────────────────────────────
const hex = (value: string): string => Buffer.from(value, 'utf8').toString('hex')
const sha256hex = (value: string): string =>
  createHash('sha256').update(value, 'utf8').digest('hex')

type MutableRecord = Record<string, unknown>

/** A plain-JSON clone, so a mutated case never aliases the record it came from. */
function asMutable(passport: unknown): MutableRecord {
  return JSON.parse(JSON.stringify(passport)) as MutableRecord
}

function without(value: MutableRecord, drop: string[]): MutableRecord {
  const out: MutableRecord = {}
  for (const [key, entry] of Object.entries(value)) if (!drop.includes(key)) out[key] = entry
  return out
}

/** The section 3.1 constructions, computed here from the two re-typed tags. */
function passportIdOf(record: MutableRecord): string {
  return sha256hex(ID_DOMAIN + canonicalizeJCS(without(record, ['passport_id', 'signature'])))
}
function signatureOf(record: MutableRecord, privateKeyHex: string): string {
  return sign(SIGNATURE_DOMAIN + canonicalizeJCS(without(record, ['signature'])), privateKeyHex)
}

// The generator's own copies of the tags must reproduce what the SDK emitted.
for (const [name, passport] of [['minimal', minimal], ['with-self-asserted', withSelfAsserted], ['web', webPassport]] as const) {
  const record = asMutable(passport)
  if (passportIdOf(record) !== passport.passport_id) {
    throw new Error(`${name}: ID_DOMAIN in this generator does not reproduce the SDK's passport_id`)
  }
  const label: KeyLabel = name === 'web' ? 'web-agent-key' : 'agent-key'
  if (signatureOf(record, PRIVATE[label]) !== passport.signature) {
    throw new Error(`${name}: SIGNATURE_DOMAIN in this generator does not reproduce the SDK's signature`)
  }
}

// ── this family's diagnostic layers ──────────────────────────────────────────
// A local schema for comparing outcomes without adopting SDK code strings. It is
// not a reporting format or check order that draft-04 requires. `not_checked`
// means this run made no determination about that layer.
interface Layers {
  structure: 'ok' | 'rejected'
  passport_id: 'ok' | 'mismatch' | 'not_checked'
  signature: 'ok' | 'invalid' | 'not_checked'
  validity_window: 'ok' | 'not_current' | 'not_checked'
  proof_of_possession: boolean
  key_authority: 'verified' | 'rejected' | 'unresolved' | 'not_checked'
}

/**
 * Map an SDK result to the layers. This is a reading of passport.ts at
 * SDK_COMMIT: the verifier stops at the first failing layer, and
 * proof_of_possession is true exactly when the signature verified.
 */
function layersOf(result: IdentityVerificationResult): Layers {
  switch (result.code) {
    case 'PASSPORT_MALFORMED':
      return { structure: 'rejected', passport_id: 'not_checked', signature: 'not_checked', validity_window: 'not_checked', proof_of_possession: false, key_authority: 'not_checked' }
    case 'PASSPORT_ID_MISMATCH':
      return { structure: 'ok', passport_id: 'mismatch', signature: 'not_checked', validity_window: 'not_checked', proof_of_possession: false, key_authority: 'not_checked' }
    case 'PASSPORT_SIGNATURE_INVALID':
      return { structure: 'ok', passport_id: 'ok', signature: 'invalid', validity_window: 'not_checked', proof_of_possession: false, key_authority: 'not_checked' }
    case 'PASSPORT_NOT_CURRENT':
      return { structure: 'ok', passport_id: 'ok', signature: 'ok', validity_window: 'not_current', proof_of_possession: true, key_authority: 'not_checked' }
    case 'OK':
      return { structure: 'ok', passport_id: 'ok', signature: 'ok', validity_window: 'ok', proof_of_possession: true, key_authority: 'verified' }
    case 'PASSPORT_KEY_AUTHORITY_REJECTED':
      return { structure: 'ok', passport_id: 'ok', signature: 'ok', validity_window: 'ok', proof_of_possession: true, key_authority: 'rejected' }
    case 'PASSPORT_KEY_AUTHORITY_UNRESOLVED':
    case 'PASSPORT_KEY_NOT_FOUND':
    case 'PASSPORT_KEY_AMBIGUOUS':
    case 'PASSPORT_KEY_MALFORMED':
    case 'PASSPORT_KEY_UNSUPPORTED':
    case 'PASSPORT_KEY_UNREACHABLE':
      return { structure: 'ok', passport_id: 'ok', signature: 'ok', validity_window: 'ok', proof_of_possession: true, key_authority: 'unresolved' }
    default:
      throw new Error(`layersOf: unknown code ${result.code}`)
  }
}

// ── cases ─────────────────────────────────────────────────────────────────────
interface Case {
  name: string
  description: string
  passport: MutableRecord
  now: string
  resolver: 'none' | 'table'
  expect: Pick<IdentityVerificationResult, 'state' | 'code' | 'proof_of_possession' | 'key_authority'>
  /** Present where the recorded SDK output goes beyond what draft-04 requires. */
  sdk_observation?: string
}

const SDK_OBSERVATION_KEY_AUTHORITY_AFTER_WINDOW =
  'key_authority "rejected" is what the SDK at the pinned commit returns when it stops at the validity window. It made no key authority determination (layers.key_authority is not_checked). Draft-04 does not require this output. An implementation that reports unresolved or not evaluated here is not nonconforming on this vector alone.'
const SDK_OBSERVATION_KEY_NOT_FOUND =
  'invalid / PASSPORT_KEY_NOT_FOUND with key_authority "rejected" is what the SDK at the pinned commit returns when the resolver finds no key. Draft-04 section 3.5 maps a key that is not found to indeterminate for external and evidence signers, and section 3.1 assigns no outcome for the agent\'s own key. An implementation that reports indeterminate here is not nonconforming on this vector alone. layers.key_authority is unresolved: no key was resolved.'
const SDK_OBSERVATION_UNKNOWN_PROFILE =
  'invalid / PASSPORT_MALFORMED is what the SDK at the pinned commit returns for an unrecognised record_type or version. Draft-04 section 3.1 does not assign an outcome to an unrecognised profile, and other draft-04 record families report unsupported in this situation. An implementation that reports unsupported here is not nonconforming on this vector alone. What this vector does establish is that the record must not be admitted.'

// 4 — one field changed, passport_id and signature left as minted.
const tamperedStale = asMutable(withSelfAsserted)
;(tamperedStale.self_asserted as MutableRecord).display_name = 'Vector Agent (renamed)'

// 5 — the same tamper with passport_id recomputed. passport_id sits inside the
//     signature preimage, so the minted signature no longer covers these bytes.
const tamperedIdRepaired = asMutable(tamperedStale)
tamperedIdRepaired.passport_id = passportIdOf(tamperedIdRepaired)

// 6 — body identical to the minimal passport, signature made with another key.
const signedByOtherKey = asMutable(minimal)
signedByOtherKey.signature = signatureOf(signedByOtherKey, PRIVATE['other-key'])

// 7 — agent_id and verification_method name key A, public_key_multibase carries
//     key B, and B signed. passport_id and signature both recompute. The only
//     defect is that the key in the record is not the key the identifier commits
//     to, which is exactly what key authority is for.
const keyNotTheDid = asMutable(minimal)
keyNotTheDid.public_key_multibase = hexToMultibase(PUBLIC['other-key'])
keyNotTheDid.passport_id = passportIdOf(keyNotTheDid)
keyNotTheDid.signature = signatureOf(keyNotTheDid, PRIVATE['other-key'])

// 11 — a did:web passport whose signing key is not the one the registry holds.
const webOtherKey = issue('other-key', {
  agent_id: WEB_AGENT,
  verification_method: WEB_AGENT_VM,
  nonce: NONCE_C,
})
// 12, 13 — did:web identifiers the table answers not_found and unreachable for.
const webUnknown = issue('web-agent-key', {
  agent_id: WEB_UNKNOWN,
  verification_method: WEB_UNKNOWN_VM,
  nonce: NONCE_C,
})
const webOffline = issue('web-agent-key', {
  agent_id: WEB_OFFLINE,
  verification_method: WEB_OFFLINE_VM,
  nonce: NONCE_C,
})

// Structural defects. Each is one edit, then re-sealed: passport_id recomputed
// and the signature made again with the agent key over the edited record. Only
// the structural rule is broken, so a reader that skipped structure would admit
// these passports on identifier and signature alone.
function reseal(record: MutableRecord, label: KeyLabel): MutableRecord {
  record.passport_id = passportIdOf(record)
  record.signature = signatureOf(record, PRIVATE[label])
  return record
}
const versionChanged = asMutable(minimal)
versionChanged.version = '2.1'
reseal(versionChanged, 'agent-key')
const recordTypeChanged = asMutable(minimal)
recordTypeChanged.record_type = 'aps.passport'
reseal(recordTypeChanged, 'agent-key')
const capabilitiesUnsorted = asMutable(withSelfAsserted)
;(capabilitiesUnsorted.self_asserted as MutableRecord).capabilities = ['data:read', 'commerce:checkout']
reseal(capabilitiesUnsorted, 'agent-key')
const principalMember = asMutable(minimal)
principalMember.principal_id = 'did:example:owner'
reseal(principalMember, 'agent-key')
const secondsTimestamp = asMutable(minimal)
secondsTimestamp.issued_at = '2026-10-01T00:00:00Z'
reseal(secondsTimestamp, 'agent-key')

// passport_id that is not the hash of the body, with a valid signature over the
// record that carries it. Only the identifier rule is broken.
const idWrongResigned = asMutable(minimal)
idWrongResigned.passport_id = sha256hex('not the passport_id preimage')
idWrongResigned.signature = signatureOf(idWrongResigned, PRIVATE['agent-key'])

const cases: Case[] = [
  {
    name: 'valid-did-key-minimal',
    description: 'A did:key passport with no display_name and an empty capabilities array, verified inside its validity window. The identifier commits to the signing key, so key authority is verified without a resolver.',
    passport: asMutable(minimal),
    now: NOW,
    resolver: 'none',
    expect: { state: 'valid', code: 'OK', proof_of_possession: true, key_authority: 'verified' },
  },
  {
    name: 'valid-did-key-with-self-asserted',
    description: 'A did:key passport carrying display_name and two capabilities in UTF-8 byte order. Same outcome as the minimal case. This one pins the self_asserted shape and a non-empty capabilities array.',
    passport: asMutable(withSelfAsserted),
    now: NOW,
    resolver: 'none',
    expect: { state: 'valid', code: 'OK', proof_of_possession: true, key_authority: 'verified' },
  },
  {
    name: 'valid-did-web-resolved',
    description: `A did:web passport. The identifier is not self-certifying, so key authority comes from the resolver table, which answers ${WEB_AGENT_VM} with the signing key and has no retirement boundary. resolver_requests records the request the SDK made, at issued_at (${ISSUED_AT}).`,
    passport: asMutable(webPassport),
    now: NOW,
    resolver: 'table',
    expect: { state: 'valid', code: 'OK', proof_of_possession: true, key_authority: 'verified' },
  },
  {
    name: 'valid-at-issued-at',
    description: `The minimal passport verified at now = issued_at (${ISSUED_AT}). The interval is issued_at <= now < expires_at, so the first instant is inside it. Complements expired (now = expires_at) and not-yet-valid (one millisecond before issued_at).`,
    passport: asMutable(minimal),
    now: ISSUED_AT,
    resolver: 'none',
    expect: { state: 'valid', code: 'OK', proof_of_possession: true, key_authority: 'verified' },
  },
  {
    name: 'tampered-display-name-stale-id',
    description: 'display_name changed after issuance, passport_id and signature left as minted. The identifier is recomputed over the body before the signature is checked, so the mismatch is caught first and nothing about possession is established.',
    passport: tamperedStale,
    now: NOW,
    resolver: 'none',
    expect: { state: 'invalid', code: 'PASSPORT_ID_MISMATCH', proof_of_possession: false, key_authority: 'rejected' },
  },
  {
    name: 'tampered-display-name-id-repaired',
    description: 'The same display_name tamper with passport_id recomputed over the tampered body, carrying the signature minted for the original. passport_id is inside the signature preimage, so the identifier check passes and the signature fails.',
    passport: tamperedIdRepaired,
    now: NOW,
    resolver: 'none',
    expect: { state: 'invalid', code: 'PASSPORT_SIGNATURE_INVALID', proof_of_possession: false, key_authority: 'rejected' },
  },
  {
    name: 'passport-id-wrong-signature-valid',
    description: 'passport_id replaced with a value that is not the hash of the body, then the record re-signed with the agent key, so the signature is valid over the record as presented. Only the identifier rule is broken. A reader that checked the signature but not passport_id would admit it.',
    passport: idWrongResigned,
    now: NOW,
    resolver: 'none',
    expect: { state: 'invalid', code: 'PASSPORT_ID_MISMATCH', proof_of_possession: false, key_authority: 'rejected' },
  },
  {
    name: 'signed-by-other-key',
    description: 'Body identical to valid-did-key-minimal, signature produced with other-key. The public key in the record is the one the signature is checked against, so the signature fails.',
    passport: signedByOtherKey,
    now: NOW,
    resolver: 'none',
    expect: { state: 'invalid', code: 'PASSPORT_SIGNATURE_INVALID', proof_of_possession: false, key_authority: 'rejected' },
  },
  {
    name: 'public-key-not-the-did-key',
    description: `agent_id and verification_method name ${AGENT_DID_KEY.slice(0, 24)}... (agent-key) while public_key_multibase carries other-key, which also signed. passport_id and signature both recompute and proof of possession holds for other-key. The did:key identifier commits to agent-key, so key authority is rejected. This is the case a verifier that checks only the signature gets wrong.`,
    passport: keyNotTheDid,
    now: NOW,
    resolver: 'none',
    expect: { state: 'invalid', code: 'PASSPORT_KEY_AUTHORITY_REJECTED', proof_of_possession: true, key_authority: 'rejected' },
  },
  {
    name: 'expired',
    description: `The minimal passport verified at now = expires_at (${NOW_AT_EXPIRY}). The interval is issued_at <= now < expires_at, so the boundary instant is outside it. Signature verified, so possession is reported, and key authority is not reached.`,
    passport: asMutable(minimal),
    now: NOW_AT_EXPIRY,
    resolver: 'none',
    expect: { state: 'invalid', code: 'PASSPORT_NOT_CURRENT', proof_of_possession: true, key_authority: 'rejected' },
    sdk_observation: SDK_OBSERVATION_KEY_AUTHORITY_AFTER_WINDOW,
  },
  {
    name: 'not-yet-valid',
    description: `The minimal passport verified one millisecond before issued_at (${NOW_BEFORE_ISSUE}). Same outcome as expired.`,
    passport: asMutable(minimal),
    now: NOW_BEFORE_ISSUE,
    resolver: 'none',
    expect: { state: 'invalid', code: 'PASSPORT_NOT_CURRENT', proof_of_possession: true, key_authority: 'rejected' },
    sdk_observation: SDK_OBSERVATION_KEY_AUTHORITY_AFTER_WINDOW,
  },
  {
    name: 'did-web-no-resolver',
    description: 'The same passport as valid-did-web-resolved, verified with no resolver supplied. Possession holds. Key authority cannot be established either way, so the outcome is indeterminate, never valid and never invalid.',
    passport: asMutable(webPassport),
    now: NOW,
    resolver: 'none',
    expect: { state: 'indeterminate', code: 'PASSPORT_KEY_AUTHORITY_UNRESOLVED', proof_of_possession: true, key_authority: 'unresolved' },
  },
  {
    name: 'did-web-resolver-answers-other-key',
    description: `A did:web passport for ${WEB_AGENT} signed with other-key, which is also the key in the record, so passport_id and signature recompute. The resolver answers ${WEB_AGENT_VM} with web-agent-key, which is not the key in the record. Key authority is rejected.`,
    passport: asMutable(webOtherKey),
    now: NOW,
    resolver: 'table',
    expect: { state: 'invalid', code: 'PASSPORT_KEY_AUTHORITY_REJECTED', proof_of_possession: true, key_authority: 'rejected' },
  },
  {
    name: 'did-web-resolver-not-found',
    description: `A self-consistent did:web passport for ${WEB_UNKNOWN}, which the resolver table does not carry. The resolver answers not_found. The SDK reports invalid (see sdk_observation).`,
    passport: asMutable(webUnknown),
    now: NOW,
    resolver: 'table',
    expect: { state: 'invalid', code: 'PASSPORT_KEY_NOT_FOUND', proof_of_possession: true, key_authority: 'rejected' },
    sdk_observation: SDK_OBSERVATION_KEY_NOT_FOUND,
  },
  {
    name: 'did-web-resolver-unreachable',
    description: `A self-consistent did:web passport for ${WEB_OFFLINE}. The resolver answers unreachable. Nothing was learned about the key, so the outcome is indeterminate, not invalid.`,
    passport: asMutable(webOffline),
    now: NOW,
    resolver: 'table',
    expect: { state: 'indeterminate', code: 'PASSPORT_KEY_UNREACHABLE', proof_of_possession: true, key_authority: 'unresolved' },
  },
  {
    name: 'version-changed',
    description: 'version changed to 2.1 on the minimal passport, then re-sealed (passport_id recomputed, re-signed by the agent key). The SDK at this commit reports a profile it does not recognise as malformed. Nothing past the schema is judged.',
    passport: versionChanged,
    now: NOW,
    resolver: 'none',
    expect: { state: 'invalid', code: 'PASSPORT_MALFORMED', proof_of_possession: false, key_authority: 'rejected' },
    sdk_observation: SDK_OBSERVATION_UNKNOWN_PROFILE,
  },
  {
    name: 'record-type-changed',
    description: 'record_type changed to aps.passport, then re-sealed. Same early stop as version-changed.',
    passport: recordTypeChanged,
    now: NOW,
    resolver: 'none',
    expect: { state: 'invalid', code: 'PASSPORT_MALFORMED', proof_of_possession: false, key_authority: 'rejected' },
    sdk_observation: SDK_OBSERVATION_UNKNOWN_PROFILE,
  },
  {
    name: 'capabilities-unsorted',
    description: 'self_asserted.capabilities in the wrong order on the with-self-asserted passport, then re-sealed. Section 3.1 requires a UTF-8-byte-sorted unique array, so the record is malformed although its identifier and signature recompute.',
    passport: capabilitiesUnsorted,
    now: NOW,
    resolver: 'none',
    expect: { state: 'invalid', code: 'PASSPORT_MALFORMED', proof_of_possession: false, key_authority: 'rejected' },
  },
  {
    name: 'principal-member-present',
    description: 'A principal_id member added to the minimal passport, then re-sealed. Section 3.1 says a principal or owner identifier is not a passport member, and the wire object is closed, so the extra member is malformed although identifier and signature recompute.',
    passport: principalMember,
    now: NOW,
    resolver: 'none',
    expect: { state: 'invalid', code: 'PASSPORT_MALFORMED', proof_of_possession: false, key_authority: 'rejected' },
  },
  {
    name: 'timestamp-without-milliseconds',
    description: 'issued_at written as 2026-10-01T00:00:00Z, then re-sealed. Section 3.1 fixes the exact UTC millisecond form YYYY-MM-DDTHH:MM:SS.sssZ, so a seconds-precision timestamp is malformed although identifier and signature recompute.',
    passport: secondsTimestamp,
    now: NOW,
    resolver: 'none',
    expect: { state: 'invalid', code: 'PASSPORT_MALFORMED', proof_of_possession: false, key_authority: 'rejected' },
  },
]

// ── run the merged verifier and write down what it returned ───────────────────
async function observe(
  item: Case,
): Promise<{ result: IdentityVerificationResult; requests: HistoricalKeyResolutionRequest[] }> {
  const requests: HistoricalKeyResolutionRequest[] = []
  const recording = (request: HistoricalKeyResolutionRequest): HistoricalKeyResolutionResult => {
    requests.push({ ...request })
    return resolveKey(request)
  }
  const result = await verifyPassportV2(item.passport, {
    now: item.now,
    ...(item.resolver === 'table' ? { resolve_key: recording } : {}),
  })
  // Section 3.1: key authority for a non-self-certifying identifier is resolved
  // at issued_at. Refuse to write the file if the SDK asked for anything else.
  for (const request of requests) {
    if (
      request.at !== item.passport.issued_at ||
      request.controller !== item.passport.agent_id ||
      request.verification_method !== item.passport.verification_method
    ) {
      throw new Error(`${item.name}: resolver asked ${JSON.stringify(request)}, expected issued_at, agent_id and verification_method of the passport`)
    }
  }
  return { result, requests }
}

interface ObservedCase {
  name: string
  description: string
  now: string
  resolver: Case['resolver']
  passport: MutableRecord
  verification: IdentityVerificationResult
  layers: Layers
  resolver_requests?: HistoricalKeyResolutionRequest[]
  sdk_observation?: string
}

const observed: ObservedCase[] = []
for (const item of cases) {
  const { result, requests } = await observe(item)
  if (item.resolver === 'table' && requests.length === 0) {
    throw new Error(`${item.name}: a table case must reach the resolver`)
  }
  for (const field of ['state', 'code', 'proof_of_possession', 'key_authority'] as const) {
    if (result[field] !== item.expect[field]) {
      throw new Error(
        `${item.name}: expected ${field} ${String(item.expect[field])}, the verifier returned ${String(result[field])}`,
      )
    }
  }
  observed.push({
    name: item.name,
    description: item.description,
    now: item.now,
    resolver: item.resolver,
    passport: item.passport,
    verification: result,
    layers: layersOf(result),
    ...(item.resolver === 'table' ? { resolver_requests: requests } : {}),
    ...(item.sdk_observation ? { sdk_observation: item.sdk_observation } : {}),
  })
}

// ── preimages for the three valid passports ───────────────────────────────────
function preimages(passport: PassportV2, label: KeyLabel) {
  const record = asMutable(passport)
  return {
    passport_id_preimage_hex: hex(ID_DOMAIN + canonicalizeJCS(without(record, ['passport_id', 'signature']))),
    passport_id_preimage_source: 'passport_id domain tag + JCS(passport without passport_id and signature)',
    signature_preimage_hex: hex(SIGNATURE_DOMAIN + canonicalizeJCS(without(record, ['signature']))),
    signature_preimage_source: 'signature domain tag + JCS(passport without signature). passport_id IS inside these bytes',
    derived: {
      passport_id: passport.passport_id,
      signature: passport.signature,
      public_key_hex: PUBLIC[label],
      signing_key_label: label,
    },
  }
}

const out = {
  family: 'agent-passport',
  version: 'v2',
  record_type: 'aps.agent-passport',
  record_version: '2.0',
  spec: 'draft-pidlisnyi-aps-04 section 3.1 (Agent Passport) and 3.2 (Agent Identifiers)',
  module: 'src/v2/identity-binding/passport.ts',
  generated_at: GENERATED_AT,
  sdk_reference: {
    repository: 'aeoess/agent-passport-system',
    release: SDK_RELEASE,
    commit: SDK_COMMIT,
    note: 'Every value under cases[].verification was produced by the TypeScript reference implementation at this commit. The identity binding, canonicalization, crypto and type sources are unchanged between the v7.2.1 tag and this commit. The vector files are added on top of that commit, so the repository HEAD carrying them is a later one. At this commit issuePassportV2 and verifyPassportV2 are in-repo and tested but not exported from the package entry.',
  },
  canonicalization: 'RFC 8785 JCS (src/core/canonical-jcs.ts): keys sorted as UTF-16 code unit sequences, no insignificant whitespace, an absent OPTIONAL member (display_name) omitted rather than written as null.',
  signature_algorithm: 'Ed25519 (RFC 8032), deterministic, over the UTF-8 bytes of the domain-tagged preimage. Raw 64-byte signature as 128 lowercase hex.',
  public_key_encoding: 'multibase base58btc (z prefix) of multicodec 0xed01 followed by the 32-byte Ed25519 public key. did:key identifiers are did:key: followed by the same multibase string.',
  preimage_encoding: 'hex of the UTF-8 bytes. Each domain tag ends in one NUL byte, which is why these are recorded as hex rather than as text.',
  validity_interval: 'issued_at <= now < expires_at, compared as canonical UTC millisecond strings.',
  determinism: `Ed25519 signing is deterministic and nothing here reads a clock or a random source, so re-running fixtures/agent-passport-v2/generate-fixtures.ts reproduces this file byte for byte. Keys are sha256 of "${SEED_LABEL_PREFIX}<label>".`,
  domain_tags: {
    passport_id: { text: 'APS-PASSPORT-ID-V2\\0', hex: hex(ID_DOMAIN) },
    signature: { text: 'APS-PASSPORT-SIG-V2\\0', hex: hex(SIGNATURE_DOMAIN) },
  },
  keys: KEY_LABELS.map(label => ({
    label,
    seed_label: SEED_LABEL_PREFIX + label,
    seed_derivation: 'sha256(utf8(seed_label)), the 32 bytes ARE the Ed25519 seed',
    private_key_hex: PRIVATE[label],
    public_key_hex: PUBLIC[label],
    public_key_multibase: hexToMultibase(PUBLIC[label]),
    did_key: didKeyFromPublicKey(PUBLIC[label]),
  })),
  key_resolver: {
    description: 'The resolver input the did:web cases were generated against, as data. Section 3.1 resolves verification_method at issued_at, and the SDK asks for { controller: agent_id, verification_method, at: issued_at } (recorded per case under resolver_requests). Look up the (controller, verification_method) pair. When no entry matches, answer not_found. When the entry\'s outcome is not resolved, answer that outcome with no key. When the entry has a window and at is outside valid_from <= at < valid_until, answer not_found. Otherwise answer public_key_hex. The did:web key window contains issued_at and not the verification instant, so resolving at the wrong time changes the outcome. Cases with resolver "none" are verified with no resolver supplied at all.',
    outcome_vocabulary: ['resolved', 'not_found', 'ambiguous', 'malformed', 'unreachable', 'unsupported'],
    entries: RESOLVER_ENTRIES,
  },
  layers_legend: {
    description: '`verification` records the SDK output at the pinned commit. `layers` is this fixture family\'s diagnostic schema. It describes the checks reached in this run and is not a reporting format or check order required by draft-04. not_checked means this run made no determination about that layer. Where layers.key_authority is not_checked, the key_authority value under verification is an SDK output produced without a key authority determination.',
    conformance_use: 'A reader can compare its own outcome with `layers` without adopting the SDK code strings. Cases that carry sdk_observation record SDK outputs that draft-04 does not require, and an implementation that reports differently there is not nonconforming on these vectors alone. What every rejection or indeterminate case does establish is that the passport must not be admitted as valid.',
    structure: 'the closed wire shape of section 3.1, including record_type, version, timestamp form, nonce length, DID syntax, verification_method prefix and the sorted unique capabilities array',
    passport_id: 'sha256 of the passport_id domain tag and JCS(passport without passport_id and signature) equals passport_id',
    signature: 'Ed25519 over the signature domain tag and JCS(passport without signature) verifies under public_key_multibase',
    validity_window: 'issued_at <= now < expires_at',
    proof_of_possession: 'true exactly when the signature verified',
    key_authority: 'verified when the identifier commits to the key in the record (did:key) or the resolver returned that key. rejected when the identifier commits to, or the resolver returned, a different key. unresolved when no key was resolved for the method (no resolver supplied, or a resolver failure outcome such as not_found or unreachable). not_checked when this run stopped earlier.',
  },
  valid_cases_preimages: {
    'valid-did-key-minimal': preimages(minimal, 'agent-key'),
    'valid-did-key-with-self-asserted': preimages(withSelfAsserted, 'agent-key'),
    'valid-did-web-resolved': preimages(webPassport, 'web-agent-key'),
  },
  cases: observed,
  not_covered: [
    'Legacy did:aps identifiers. Section 3.2 lets a compatibility verifier read them and says conforming new-write paths do not emit them. None is minted here.',
    'Key rotation under an update-capable DID method (section 3.2 versionId or versionTime). The resolver table has one key per method and no validity window.',
    'Selection of a retired key. Section 3.4 requires acceptable timestamp evidence before a retired key is selected, and an issuer\'s issued_at claim alone does not satisfy it. Without that evidence the outcome is indeterminate, reported as KEY_AMBIGUOUS. At the pinned commit verifyPassportV2 has no evidence input and admits whatever key the resolver returns for issued_at, so a resolver that returned a retired key would be accepted on the claim alone. No vector here exercises that case.',
    'Principal binding and its revocation (sections 3.3 and following). Those are separate records with their own constructions.',
    'JCS escaping of non-ASCII and control characters. Every string here is printable ASCII on purpose. Escaping is pinned by tests/cross-impl/jcs-test-vectors.json.',
    'Small-order Ed25519 key material. src/crypto/keys.ts refuses it before the platform primitive runs. That is a property of the SDK verifier, not of these bytes.',
  ],
}

const dir = dirname(fileURLToPath(import.meta.url))
const path = join(dir, 'agent-passport-vectors-v2.json')
writeFileSync(path, JSON.stringify(out, null, 2) + '\n')
process.stdout.write(`wrote ${observed.length} cases -> ${path}\n`)
