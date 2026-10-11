// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// The second revision of the `aps.agent-passport` 2.0 vector family
// (fixtures/agent-passport-v2/agent-passport-vectors-v2-r2.json), run against the
// merged verifier. Every case must reproduce exactly what the file records, with no
// exceptions table. The first revision stays frozen and is checked by
// agent-passport-vectors.test.ts.

import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { verifyPassportV2 } from '../../src/v2/identity-binding/passport.js'
import type {
  HistoricalKeyResolutionRequest,
  HistoricalKeyResolutionResult,
  IdentityVerificationResult,
} from '../../src/v2/identity-binding/types.js'

interface Case {
  name: string
  now: string
  resolver: 'none' | 'table'
  passport: Record<string, unknown>
  verification: IdentityVerificationResult
  resolver_requests?: HistoricalKeyResolutionRequest[]
  sdk_observation?: string
}

const dir = new URL('../../fixtures/agent-passport-v2/', import.meta.url)
const frozenBytes = readFileSync(new URL('agent-passport-vectors-v2.json', dir))
const frozen = JSON.parse(frozenBytes.toString('utf8'))
const r2 = JSON.parse(readFileSync(new URL('agent-passport-vectors-v2-r2.json', dir), 'utf8'))

function resolveKey(request: HistoricalKeyResolutionRequest): HistoricalKeyResolutionResult {
  const entry = r2.key_resolver.entries.find(
    (item: { controller: string; verification_method: string }) =>
      item.controller === request.controller && item.verification_method === request.verification_method,
  )
  if (!entry) return { state: 'not_found' }
  if (entry.outcome !== 'resolved') return { state: entry.outcome }
  return { state: 'resolved', public_key_hex: entry.public_key_hex }
}

test('r2 names its revision and the frozen file it supersedes, which is unchanged', () => {
  assert.equal(r2.family_revision, 2)
  assert.equal(r2.supersedes.sha256, createHash('sha256').update(frozenBytes).digest('hex'))
  assert.equal(frozen.family_revision, undefined)
})

test('r2 and the frozen file share passports, preimages, keys and resolver table', () => {
  assert.deepEqual(r2.keys, frozen.keys)
  assert.deepEqual(r2.key_resolver, frozen.key_resolver)
  assert.deepEqual(r2.valid_cases_preimages, frozen.valid_cases_preimages)
  assert.deepEqual(r2.cases.map((c: Case) => c.name), frozen.cases.map((c: Case) => c.name))
  for (const [i, item] of r2.cases.entries()) {
    assert.deepEqual(item.passport, frozen.cases[i].passport, item.name)
    assert.deepEqual(item.resolver_requests, frozen.cases[i].resolver_requests, item.name)
  }
})

test('only the three named cases changed their recorded verification', () => {
  const changed = r2.cases
    .filter((c: Case, i: number) => JSON.stringify(c.verification) !== JSON.stringify(frozen.cases[i].verification))
    .map((c: Case) => c.name)
  assert.deepEqual(changed, ['did-web-resolver-not-found', 'version-changed', 'record-type-changed'])
})

for (const item of r2.cases as Case[]) {
  test(`r2 case ${item.name}`, async () => {
    const requests: HistoricalKeyResolutionRequest[] = []
    const observed = await verifyPassportV2(item.passport, {
      now: item.now,
      ...(item.resolver === 'table' ? { resolve_key: (r: HistoricalKeyResolutionRequest) => { requests.push({ ...r }); return resolveKey(r) } } : {}),
    })
    assert.deepEqual(observed, item.verification)
    if (item.resolver === 'table') assert.deepEqual(requests, item.resolver_requests, `${item.name}: resolver requests`)
  })
}
