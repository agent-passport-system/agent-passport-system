// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Separate recompute of the legacy Action Receipt v1.1 vector family.
//
//   npx tsx fixtures/action-receipt-v1.1/recompute-independent.ts
//
// THIS FILE IMPORTS NOTHING FROM src/. Its only imports are node:crypto and
// node:fs. It re-states, from the SDK at the pinned commit and
// docs/CANONICAL-SPEC.md:
//
//   - APS canonical JSON: keys sorted by UTF-16 code units, object members whose
//     value is null or undefined omitted, array nulls kept, no whitespace.
//   - Ed25519 over the UTF-8 bytes of the canonical record without `signature`,
//     no domain tag.
//   - The predicates of subDelegate and createReceipt that these fixtures
//     exercise: the pre-draft scopeCovers rule, spend against the remaining
//     budget, the depth increment, and the parent or supplied delegation passing
//     the single-record check. The inputs are read from each `issuance` record.
//
// What it checks, from the vector file alone:
//
//   1. The four published preimages, byte for byte.
//   2. For every delegation case: signature under delegatedBy, expiry and
//      notBefore against the file's verification_instant, currentDepth >
//      maxDepth when maxDepth is present, compared with verification.
//   3. For every receipt case: signature under the named key and version "1.1",
//      compared with verification.
//   4. For every case that carries an `issuance` record: the predicates above
//      over its recorded inputs, compared with issuance.accepted.
//   5. That no case claims to establish authorization.
//
// It is not a complete implementation of subDelegate or createReceipt. It
// leaves out derivation_rights, spend units other than the default, revocation
// and parse errors, none of which these fixtures exercise. The rules it applies
// are re-stated from the same reading of the SDK as the generator, so agreement
// shows the file is internally consistent, not that the rules are right. Exits
// non-zero when any check disagrees.

import { createHash, createPublicKey, verify as ed25519Verify } from 'node:crypto'
import { readFileSync } from 'node:fs'

// ── APS canonical JSON ────────────────────────────────────────────────────────
function canonical(value: unknown): string {
  if (value === null || value === undefined) return 'null'
  if (typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']'
  const record = value as Record<string, unknown>
  const parts: string[] = []
  for (const key of Object.keys(record).sort()) {
    const member = record[key]
    if (member === null || member === undefined) continue
    parts.push(JSON.stringify(key) + ':' + canonical(member))
  }
  return '{' + parts.join(',') + '}'
}

function ed25519VerifyRaw(preimage: string, signatureHex: unknown, publicKeyHex: string): boolean {
  if (typeof signatureHex !== 'string' || !/^[0-9a-f]{128}$/.test(signatureHex)) return false
  if (!/^[0-9a-f]{64}$/.test(publicKeyHex)) return false
  const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(publicKeyHex, 'hex')])
  const key = createPublicKey({ key: spki, format: 'der', type: 'spki' })
  try {
    return ed25519Verify(null, Buffer.from(preimage, 'utf8'), key, Buffer.from(signatureHex, 'hex'))
  } catch {
    return false
  }
}

const utf8hex = (v: string): string => Buffer.from(v, 'utf8').toString('hex')
const sha256hex = (v: string): string => createHash('sha256').update(v, 'utf8').digest('hex')
void sha256hex

// ── the pre-draft scope rule, re-stated from SPEC-v1.1 and the scopeCovers comment ──
function scopeCovers(granted: string, required: string): boolean {
  if (granted === required) return true
  if (granted === '*') return true
  if (required.startsWith(granted + ':')) return true
  if (granted.endsWith(':*')) {
    const prefix = granted.slice(0, -2)
    if (required === prefix || required.startsWith(prefix + ':')) return true
  }
  return false
}

// ── the vector file ───────────────────────────────────────────────────────────
type Rec = Record<string, unknown>
interface Issuance { function: string; inputs: Rec; accepted: boolean; error: string | null }
interface VectorFile {
  verification_instant: string
  keys: Array<{ label: string; public_key_hex: string }>
  preimages: Record<string, { signature_preimage_hex: string }>
  delegation_cases: Array<{ name: string; record: Rec; verification_scope: { establishes_authorization: boolean }; verification: { valid: boolean; errors: string[]; depthExceeded: boolean; expired: boolean }; issuance?: Issuance }>
  receipt_cases: Array<{ name: string; record: Rec; verify_with_key: string; verification_scope: { establishes_authorization: boolean }; verification: { valid: boolean; errors: string[] }; issuance?: Issuance }>
}
const vector = JSON.parse(readFileSync(new URL('./action-receipt-vectors-v1.1.json', import.meta.url), 'utf8')) as VectorFile
const keyOf = (label: string): string => {
  const k = vector.keys.find(item => item.label === label)
  if (!k) throw new Error(`no key ${label}`)
  return k.public_key_hex
}

// The instant the SDK run was frozen at, read from the vector file.
const NOW = vector.verification_instant

let failures = 0
function check(label: string, actual: unknown, expected: unknown): void {
  if (JSON.stringify(actual) === JSON.stringify(expected)) process.stdout.write(`ok   ${label}\n`)
  else {
    failures++
    process.stdout.write(`FAIL ${label}\n  expected ${JSON.stringify(expected)}\n  actual   ${JSON.stringify(actual)}\n`)
  }
}
function without(record: Rec, drop: string[]): Rec {
  const out: Rec = {}
  for (const [k, v] of Object.entries(record)) if (!drop.includes(k)) out[k] = v
  return out
}

// ── 1. preimages ──────────────────────────────────────────────────────────────
for (const [name, expected] of Object.entries(vector.preimages)) {
  const item = [...vector.delegation_cases, ...vector.receipt_cases].find(c => c.name === name)
  if (!item) throw new Error(`${name}: no case`)
  check(`${name}: preimage bytes`, utf8hex(canonical(without(item.record, ['signature']))), expected.signature_preimage_hex)
}

// ── 2. delegations ────────────────────────────────────────────────────────────
function delegationValid(d: Rec): { valid: boolean; expired: boolean; depthExceeded: boolean } {
  const sig = ed25519VerifyRaw(canonical(without(d, ['signature'])), d.signature, String(d.delegatedBy))
  // The legacy verifier reports expired only when expiresAt < the instant.
  const expired = String(d.expiresAt) < NOW
  const notYetValid = typeof d.notBefore === 'string' && d.notBefore > NOW
  const depthExceeded = typeof d.maxDepth === 'number' && Number(d.currentDepth) > d.maxDepth
  return { valid: sig && !expired && !notYetValid && !depthExceeded, expired, depthExceeded }
}
for (const item of vector.delegation_cases) {
  const mine = delegationValid(item.record)
  check(`${item.name}: valid`, mine.valid, item.verification.valid)
  check(`${item.name}: expired`, mine.expired, item.verification.expired)
  check(`${item.name}: depthExceeded`, mine.depthExceeded, item.verification.depthExceeded)
}

// ── 3. receipts ───────────────────────────────────────────────────────────────
for (const item of vector.receipt_cases) {
  const sig = ed25519VerifyRaw(canonical(without(item.record, ['signature'])), item.record.signature, keyOf(item.verify_with_key))
  const valid = sig && item.record.version === '1.1'
  check(`${item.name}: valid`, valid, item.verification.valid)
  check(`${item.name}: signature`, sig, !(item.verification.errors as string[]).includes('Invalid receipt signature'))
}
for (const item of [...vector.delegation_cases, ...vector.receipt_cases]) {
  check(`${item.name}: establishes_authorization`, item.verification_scope.establishes_authorization, false)
}

// ── 4. issuance predicates, over the recorded inputs ─────────────────────────
const byId = new Map(vector.delegation_cases.map(c => [String(c.record.delegationId), c.record]))
const delegationById = (id: unknown): Rec => {
  const d = byId.get(String(id))
  if (!d) throw new Error(`no delegation ${String(id)} in the file`)
  return d
}
const remainingOf = (d: Rec): number => (d.spendLimit === undefined ? Infinity : Number(d.spendLimit)) - Number(d.spentAmount ?? 0)

// subDelegate: depth, scope, spend against the parent, the parent unexpired,
// then the parent passing the single-record check.
function subDelegateAccepts(inputs: Rec): boolean {
  const parent = delegationById(inputs.parent)
  const depthOk = Number(parent.currentDepth) + 1 <= Number(parent.maxDepth)
  const scopeOk = (inputs.scope as string[]).every(s => (parent.scope as string[]).some(g => scopeCovers(g, s)))
  const spendOk = inputs.spendLimit === undefined || Number(inputs.spendLimit) <= remainingOf(parent)
  return depthOk && scopeOk && spendOk && delegationValid(parent).valid
}
// createReceipt: the supplied delegation passing the single-record check, then
// scope and spend against it. It does not look at delegationChain, and neither
// does this.
function createReceiptAccepts(inputs: Rec): boolean {
  const d = delegationById(inputs.delegation)
  const action = inputs.action as Rec
  const scopeOk = (d.scope as string[]).some(g => scopeCovers(g, String(action.scopeUsed)))
  const spend = action.spend as { amount: number } | undefined
  const spendOk = spend === undefined || spend.amount <= remainingOf(d)
  return delegationValid(d).valid && scopeOk && spendOk
}
for (const item of vector.delegation_cases) {
  if (item.issuance) check(`${item.name}: ${item.issuance.function} accepted`, subDelegateAccepts(item.issuance.inputs), item.issuance.accepted)
}
for (const item of vector.receipt_cases) {
  if (item.issuance) check(`${item.name}: ${item.issuance.function} accepted`, createReceiptAccepts(item.issuance.inputs), item.issuance.accepted)
}

if (failures > 0) {
  process.stdout.write(`\n${failures} disagreement(s)\n`)
  process.exit(1)
}
process.stdout.write(`\nall checks agree across ${vector.delegation_cases.length + vector.receipt_cases.length} cases\n`)
