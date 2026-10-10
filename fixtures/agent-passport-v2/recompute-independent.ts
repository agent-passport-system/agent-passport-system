// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Independent recompute of the `aps.agent-passport` 2.0 vector family.
//
//   npx tsx fixtures/agent-passport-v2/recompute-independent.ts
//
// THIS FILE IMPORTS NOTHING FROM src/. Its only imports are node:crypto and
// node:fs. Everything the SDK would have supplied is re-stated here from
// draft-pidlisnyi-aps-04 sections 3.1 and 3.2:
//
//   - RFC 8785 JCS for the JSON this record is made of (strings, one array of
//     strings, one nested object, no numbers anywhere).
//   - The two domain tags, re-typed as literals and checked against the hex the
//     vector publishes, so a tag that drifted would be caught rather than
//     silently agreed with.
//   - multibase base58btc and the 0xed01 multicodec prefix, for
//     public_key_multibase and did:key.
//   - SHA-256 and Ed25519 from the platform.
//
// What it checks, from the vector file alone:
//
//   1. For the three valid passports: both preimages byte for byte, the
//      passport_id they hash to, and an Ed25519 verification of the signature
//      under the published public key.
//   2. For every case: a separate verifier with no SDK imports, walking the
//      family's diagnostic layers in the order structure, passport_id,
//      signature, validity window, key authority, must reach the same `layers`
//      the vector records. The SDK's code strings are not consulted.
//
// What this does and does not show. It recomputes the bytes, identifiers and
// signatures independently of the SDK code. The order of checks and the
// structural predicates re-state the same reading of section 3.1 as the
// generator, and both use Node's Ed25519, so agreement here is not evidence that
// draft-04 mandates that reading.
//
// Exits non-zero on the first disagreement.

import { createHash, createPublicKey, verify as ed25519Verify } from 'node:crypto'
import { readFileSync } from 'node:fs'

// ── the frozen domain tags, each terminated by one NUL byte ───────────────────
const ID_DOMAIN = 'APS-PASSPORT-ID-V2\u0000'
const SIGNATURE_DOMAIN = 'APS-PASSPORT-SIG-V2\u0000'

// ── RFC 8785 ──────────────────────────────────────────────────────────────────
function jcsString(value: string): string {
  let out = '"'
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
    if (code === 0x22) out += '\\"'
    else if (code === 0x5c) out += '\\\\'
    else if (code === 0x08) out += '\\b'
    else if (code === 0x0c) out += '\\f'
    else if (code === 0x0a) out += '\\n'
    else if (code === 0x0d) out += '\\r'
    else if (code === 0x09) out += '\\t'
    else if (code < 0x20) out += '\\u' + code.toString(16).padStart(4, '0')
    else if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(i + 1)
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new Error('lone high surrogate')
      out += value[i] + value[i + 1]
      i++
    } else if (code >= 0xdc00 && code <= 0xdfff) throw new Error('lone low surrogate')
    else out += value[i]
  }
  return out + '"'
}

/** JCS over the value kinds a passport contains. Numbers are refused on purpose. */
function jcs(value: unknown): string {
  if (value === null) return 'null'
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  if (typeof value === 'string') return jcsString(value)
  if (Array.isArray(value)) return '[' + value.map(jcs).join(',') + ']'
  if (typeof value === 'object') {
    const record = value as Record<string, unknown>
    // RFC 8785 section 3.2.3: sort by UTF-16 code units, which is what the
    // default string comparison does.
    const keys = Object.keys(record).sort()
    return '{' + keys.map(key => jcsString(key) + ':' + jcs(record[key])).join(',') + '}'
  }
  throw new Error(`jcs: unsupported value of type ${typeof value}`)
}

// ── multibase base58btc ───────────────────────────────────────────────────────
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

function base58Decode(text: string): Uint8Array {
  const bytes: number[] = []
  for (const char of text) {
    let carry = B58.indexOf(char)
    if (carry < 0) throw new Error('not base58')
    for (let i = 0; i < bytes.length; i++) {
      carry += bytes[i] * 58
      bytes[i] = carry & 0xff
      carry >>= 8
    }
    while (carry > 0) {
      bytes.push(carry & 0xff)
      carry >>= 8
    }
  }
  for (const char of text) {
    if (char !== '1') break
    bytes.push(0)
  }
  return Uint8Array.from(bytes.reverse())
}

function base58Encode(bytes: Uint8Array): string {
  const digits: number[] = [0]
  for (const byte of bytes) {
    let carry = byte
    for (let i = 0; i < digits.length; i++) {
      carry += digits[i] << 8
      digits[i] = carry % 58
      carry = (carry / 58) | 0
    }
    while (carry > 0) {
      digits.push(carry % 58)
      carry = (carry / 58) | 0
    }
  }
  let out = ''
  for (const byte of bytes) {
    if (byte !== 0) break
    out += '1'
  }
  for (let i = digits.length - 1; i >= 0; i--) out += B58[digits[i]]
  return out
}

/** z + base58btc(0xed 0x01 || key) -> 64 lowercase hex, or null when malformed. */
function publicKeyFromMultibase(value: string): string | null {
  if (typeof value !== 'string' || !value.startsWith('z')) return null
  let bytes: Uint8Array
  try {
    bytes = base58Decode(value.slice(1))
  } catch {
    return null
  }
  if (bytes.length !== 34 || bytes[0] !== 0xed || bytes[1] !== 0x01) return null
  return Buffer.from(bytes.subarray(2)).toString('hex')
}

function didKeyOf(publicKeyHex: string): string {
  const bytes = Uint8Array.from([0xed, 0x01, ...Buffer.from(publicKeyHex, 'hex')])
  return 'did:key:z' + base58Encode(bytes)
}

// ── platform primitives ───────────────────────────────────────────────────────
const sha256hex = (value: string): string => createHash('sha256').update(value, 'utf8').digest('hex')
const utf8hex = (value: string): string => Buffer.from(value, 'utf8').toString('hex')

function ed25519VerifyRaw(preimage: string, signatureHex: string, publicKeyHex: string): boolean {
  const spki = Buffer.concat([
    Buffer.from('302a300506032b6570032100', 'hex'),
    Buffer.from(publicKeyHex, 'hex'),
  ])
  const key = createPublicKey({ key: spki, format: 'der', type: 'spki' })
  try {
    return ed25519Verify(null, Buffer.from(preimage, 'utf8'), key, Buffer.from(signatureHex, 'hex'))
  } catch {
    return false
  }
}

// ── the vector file ───────────────────────────────────────────────────────────
interface Layers {
  structure: 'ok' | 'rejected'
  passport_id: 'ok' | 'mismatch' | 'not_checked'
  signature: 'ok' | 'invalid' | 'not_checked'
  validity_window: 'ok' | 'not_current' | 'not_checked'
  proof_of_possession: boolean
  key_authority: 'verified' | 'rejected' | 'unresolved' | 'not_checked'
}

interface ResolverEntry {
  controller: string
  verification_method: string
  outcome: string
  public_key_hex?: string
}

interface VectorFile {
  domain_tags: { passport_id: { hex: string }; signature: { hex: string } }
  key_resolver: { entries: ResolverEntry[] }
  valid_cases_preimages: Record<string, {
    passport_id_preimage_hex: string
    signature_preimage_hex: string
    derived: { passport_id: string; signature: string; public_key_hex: string }
  }>
  cases: Array<{
    name: string
    now: string
    resolver: 'none' | 'table'
    passport: Record<string, unknown>
    layers: Layers
  }>
}

const path = new URL('./agent-passport-vectors-v2.json', import.meta.url)
const vector = JSON.parse(readFileSync(path, 'utf8')) as VectorFile

let failures = 0
function check(label: string, actual: unknown, expected: unknown): void {
  const same = JSON.stringify(actual) === JSON.stringify(expected)
  if (!same) {
    failures++
    process.stdout.write(`FAIL ${label}\n  expected ${JSON.stringify(expected)}\n  actual   ${JSON.stringify(actual)}\n`)
  } else {
    process.stdout.write(`ok   ${label}\n`)
  }
}

// ── 0. the tags ───────────────────────────────────────────────────────────────
check('domain tag passport_id', utf8hex(ID_DOMAIN), vector.domain_tags.passport_id.hex)
check('domain tag signature', utf8hex(SIGNATURE_DOMAIN), vector.domain_tags.signature.hex)

// ── 1. bytes of the valid passports ───────────────────────────────────────────
function without(record: Record<string, unknown>, drop: string[]): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(record)) if (!drop.includes(key)) out[key] = value
  return out
}

for (const [name, expected] of Object.entries(vector.valid_cases_preimages)) {
  const item = vector.cases.find(entry => entry.name === name)
  if (!item) throw new Error(`${name}: no case`)
  const idPreimage = ID_DOMAIN + jcs(without(item.passport, ['passport_id', 'signature']))
  const sigPreimage = SIGNATURE_DOMAIN + jcs(without(item.passport, ['signature']))
  check(`${name}: passport_id preimage bytes`, utf8hex(idPreimage), expected.passport_id_preimage_hex)
  check(`${name}: passport_id`, sha256hex(idPreimage), expected.derived.passport_id)
  check(`${name}: signature preimage bytes`, utf8hex(sigPreimage), expected.signature_preimage_hex)
  check(`${name}: public key in record`, publicKeyFromMultibase(String(item.passport.public_key_multibase)), expected.derived.public_key_hex)
  check(`${name}: signature verifies`, ed25519VerifyRaw(sigPreimage, expected.derived.signature, expected.derived.public_key_hex), true)
  check(`${name}: signature field`, item.passport.signature, expected.derived.signature)
}

// ── 2. a verifier from the draft text, compared layer by layer ────────────────
const MEMBERS = [
  'record_type', 'version', 'passport_id', 'agent_id', 'verification_method',
  'public_key_multibase', 'issued_at', 'expires_at', 'nonce', 'self_asserted', 'signature',
]
const UTC_MS = /^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\d\.\d{3}Z$/
const HEX = (length: number) => new RegExp(`^[0-9a-f]{${length}}$`)

function utcMilliseconds(value: unknown): value is string {
  if (typeof value !== 'string' || !UTC_MS.test(value)) return false
  const parsed = new Date(value)
  return !Number.isNaN(parsed.getTime()) && parsed.toISOString() === value
}

function utf8Compare(a: string, b: string): number {
  return Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'))
}

/** Section 3.1 wire shape. True when every structural rule holds. */
function structureOk(p: Record<string, unknown>): boolean {
  if (typeof p !== 'object' || p === null || Array.isArray(p)) return false
  const keys = Object.keys(p).sort()
  if (JSON.stringify(keys) !== JSON.stringify([...MEMBERS].sort())) return false
  if (p.record_type !== 'aps.agent-passport' || p.version !== '2.0') return false
  if (typeof p.passport_id !== 'string' || !HEX(64).test(p.passport_id)) return false
  if (typeof p.signature !== 'string' || !HEX(128).test(p.signature)) return false
  if (typeof p.nonce !== 'string' || !HEX(32).test(p.nonce)) return false
  if (typeof p.agent_id !== 'string' || !/^did:[a-z0-9]+:.+$/.test(p.agent_id)) return false
  if (typeof p.verification_method !== 'string' || !p.verification_method.startsWith(`${p.agent_id}#`)) return false
  if (publicKeyFromMultibase(String(p.public_key_multibase)) === null) return false
  if (!utcMilliseconds(p.issued_at) || !utcMilliseconds(p.expires_at)) return false
  if (p.issued_at >= p.expires_at) return false
  const sa = p.self_asserted
  if (typeof sa !== 'object' || sa === null || Array.isArray(sa)) return false
  const saKeys = Object.keys(sa as object).sort()
  if (!(JSON.stringify(saKeys) === JSON.stringify(['capabilities']) || JSON.stringify(saKeys) === JSON.stringify(['capabilities', 'display_name']))) return false
  const caps = (sa as Record<string, unknown>).capabilities
  if (!Array.isArray(caps)) return false
  for (const cap of caps) if (typeof cap !== 'string' || cap.length === 0) return false
  for (let i = 1; i < caps.length; i++) if (utf8Compare(caps[i - 1] as string, caps[i] as string) >= 0) return false
  const dn = (sa as Record<string, unknown>).display_name
  if (dn !== undefined && typeof dn !== 'string') return false
  return true
}

// Section 3.1: resolve verification_method at issued_at.
function resolve(controller: string, verificationMethod: string, at: string): { state: string; public_key_hex?: string } {
  const entry = vector.key_resolver.entries.find(
    item => item.controller === controller && item.verification_method === verificationMethod,
  )
  if (!entry) return { state: 'not_found' }
  if (entry.outcome !== 'resolved') return { state: entry.outcome }
  // The table has no validity window, so `at` does not change the answer here.
  void at
  return { state: 'resolved', public_key_hex: entry.public_key_hex }
}

function verifyFromDraft(p: Record<string, unknown>, now: string, resolver: 'none' | 'table'): Layers {
  const stop: Layers = {
    structure: 'rejected', passport_id: 'not_checked', signature: 'not_checked',
    validity_window: 'not_checked', proof_of_possession: false, key_authority: 'not_checked',
  }
  if (!structureOk(p)) return stop
  stop.structure = 'ok'
  const idPreimage = ID_DOMAIN + jcs(without(p, ['passport_id', 'signature']))
  if (sha256hex(idPreimage) !== p.passport_id) return { ...stop, passport_id: 'mismatch' }
  stop.passport_id = 'ok'
  const publicKey = publicKeyFromMultibase(String(p.public_key_multibase)) as string
  const sigPreimage = SIGNATURE_DOMAIN + jcs(without(p, ['signature']))
  if (!ed25519VerifyRaw(sigPreimage, String(p.signature), publicKey)) return { ...stop, signature: 'invalid' }
  stop.signature = 'ok'
  stop.proof_of_possession = true
  const issuedAt = String(p.issued_at)
  const expiresAt = String(p.expires_at)
  if (!(issuedAt <= now && now < expiresAt)) return { ...stop, validity_window: 'not_current' }
  stop.validity_window = 'ok'
  const agentId = String(p.agent_id)
  if (agentId.startsWith('did:key:')) {
    const committed = publicKeyFromMultibase(agentId.slice('did:key:'.length))
    if (committed === null || didKeyOf(committed) !== agentId) return { ...stop, key_authority: 'rejected' }
    return { ...stop, key_authority: committed === publicKey ? 'verified' : 'rejected' }
  }
  if (resolver === 'none') return { ...stop, key_authority: 'unresolved' }
  const answer = resolve(agentId, String(p.verification_method), issuedAt)
  // Any resolver failure outcome leaves key authority unresolved in these layers.
  if (answer.state !== 'resolved' || !answer.public_key_hex) return { ...stop, key_authority: 'unresolved' }
  return { ...stop, key_authority: answer.public_key_hex === publicKey ? 'verified' : 'rejected' }
}

for (const item of vector.cases) {
  check(`${item.name}: layers`, verifyFromDraft(item.passport, item.now, item.resolver), item.layers)
}

if (failures > 0) {
  process.stdout.write(`\n${failures} disagreement(s)\n`)
  process.exit(1)
}
process.stdout.write(`\nall checks agree across ${vector.cases.length} cases\n`)
