// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// The committed `aps.agent-passport` 2.0 vector family, run against the merged
// verifier.
//
// Source of the vectors: fixtures/agent-passport-v2/. Nothing is minted here.
// Every passport, preimage and signature is read out of the JSON, and the
// assertions are that the SDK still produces exactly what the file records. A
// change in this suite that is "fixed" by regenerating the vector is a change to
// the wire format or to what the verifier reports, and the vector's
// sdk_reference.commit is what says which implementation the recorded outcomes
// came from.

import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { canonicalizeJCS } from '../../src/core/canonical-jcs.js'
import { verifyPassportV2 } from '../../src/v2/identity-binding/passport.js'
import type {
  HistoricalKeyResolutionRequest,
  HistoricalKeyResolutionResult,
  IdentityVerificationResult,
} from '../../src/v2/identity-binding/types.js'

interface ResolverEntry {
  controller: string
  verification_method: string
  outcome: HistoricalKeyResolutionResult['state']
  public_key_hex?: string
}

interface VectorFile {
  record_type: string
  record_version: string
  sdk_reference: { commit: string }
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
    verification: IdentityVerificationResult
    resolver_requests?: HistoricalKeyResolutionRequest[]
  }>
}

const vector = JSON.parse(readFileSync(
  new URL('../../fixtures/agent-passport-v2/agent-passport-vectors-v2.json', import.meta.url),
  'utf8',
)) as VectorFile

/** The resolver the vector file describes, rebuilt from its own committed table. */
function resolveKey(request: HistoricalKeyResolutionRequest): HistoricalKeyResolutionResult {
  const entry = vector.key_resolver.entries.find(
    item =>
      item.controller === request.controller &&
      item.verification_method === request.verification_method,
  )
  if (!entry) return { state: 'not_found' }
  if (entry.outcome !== 'resolved') return { state: entry.outcome }
  return { state: 'resolved', public_key_hex: entry.public_key_hex }
}

const utf8Hex = (value: string): string => Buffer.from(value, 'utf8').toString('hex')
const tagText = (hex: string): string => Buffer.from(hex, 'hex').toString('utf8')

function without(record: Record<string, unknown>, drop: string[]): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(record)) if (!drop.includes(key)) out[key] = value
  return out
}

test('vector file names the record this suite verifies', () => {
  assert.equal(vector.record_type, 'aps.agent-passport')
  assert.equal(vector.record_version, '2.0')
  assert.match(vector.sdk_reference.commit, /^[0-9a-f]{40}$/)
  assert.equal(vector.cases.length, 20)
})

test('the SDK canonicalization reproduces the recorded preimage bytes', () => {
  const idTag = tagText(vector.domain_tags.passport_id.hex)
  const sigTag = tagText(vector.domain_tags.signature.hex)
  assert.equal(idTag, 'APS-PASSPORT-ID-V2\u0000')
  assert.equal(sigTag, 'APS-PASSPORT-SIG-V2\u0000')
  for (const [name, expected] of Object.entries(vector.valid_cases_preimages)) {
    const item = vector.cases.find(entry => entry.name === name)
    assert.ok(item, `${name}: case present`)
    assert.equal(
      utf8Hex(idTag + canonicalizeJCS(without(item.passport, ['passport_id', 'signature']))),
      expected.passport_id_preimage_hex,
      `${name}: passport_id preimage`,
    )
    assert.equal(
      utf8Hex(sigTag + canonicalizeJCS(without(item.passport, ['signature']))),
      expected.signature_preimage_hex,
      `${name}: signature preimage`,
    )
    assert.equal(item.passport.passport_id, expected.derived.passport_id, `${name}: passport_id`)
    assert.equal(item.passport.signature, expected.derived.signature, `${name}: signature`)
  }
})

for (const item of vector.cases) {
  test(`case ${item.name}`, async () => {
    const requests: HistoricalKeyResolutionRequest[] = []
    const recording = (request: HistoricalKeyResolutionRequest): HistoricalKeyResolutionResult => {
      requests.push({ ...request })
      return resolveKey(request)
    }
    const observed = await verifyPassportV2(item.passport, {
      now: item.now,
      ...(item.resolver === 'table' ? { resolve_key: recording } : {}),
    })
    assert.deepEqual(observed, item.verification)
    if (item.resolver === 'table') {
      assert.deepEqual(requests, item.resolver_requests, `${item.name}: resolver requests`)
      for (const request of requests) assert.equal(request.at, item.passport.issued_at, `${item.name}: resolved at issued_at`)
    }
  })
}

test('every case carries a complete recorded verification', () => {
  for (const item of vector.cases) {
    assert.ok(['valid', 'invalid', 'indeterminate', 'unsupported'].includes(item.verification.state), item.name)
    assert.equal(typeof item.verification.code, 'string', item.name)
    assert.equal(typeof item.verification.proof_of_possession, 'boolean', item.name)
    assert.ok(['verified', 'unresolved', 'rejected'].includes(item.verification.key_authority), item.name)
  }
})
