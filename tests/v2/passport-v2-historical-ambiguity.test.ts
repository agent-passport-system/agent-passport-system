// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// verifyPassportV2 when the historical key resolver answers `ambiguous`.
// Draft-04 section 3.4: a key-selection boundary the evidence cannot settle is
// reported through the ambiguous outcome of section 3.5 (KEY_AMBIGUOUS) and the
// key-authority result is indeterminate, even with a valid signature.
//
// The passport is the valid-did-web-resolved case of the frozen family in
// fixtures/agent-passport-v2/. That file records the SDK at c31d94a and is not
// changed here, because no frozen case uses an ambiguous resolver.

import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { verifyPassportV2 } from '../../src/v2/identity-binding/passport.js'
import type { HistoricalKeyResolutionResult } from '../../src/v2/identity-binding/types.js'

const vector = JSON.parse(readFileSync(
  new URL('../../fixtures/agent-passport-v2/agent-passport-vectors-v2.json', import.meta.url),
  'utf8',
))
const item = vector.cases.find((c: { name: string }) => c.name === 'valid-did-web-resolved')
const keyHex: string = vector.key_resolver.entries.find((e: { controller: string }) => e.controller === item.passport.agent_id).public_key_hex

const run = (answer: HistoricalKeyResolutionResult) =>
  verifyPassportV2(item.passport, { now: item.now, resolve_key: () => answer })

test('resolved key control: valid', async () => {
  assert.deepEqual(await run({ state: 'resolved', public_key_hex: keyHex }), {
    state: 'valid', code: 'OK', proof_of_possession: true, key_authority: 'verified',
  })
})

test('ambiguous resolution: indeterminate, key authority unresolved', async () => {
  assert.deepEqual(await run({ state: 'ambiguous' }), {
    state: 'indeterminate', code: 'PASSPORT_KEY_AMBIGUOUS', proof_of_possession: true, key_authority: 'unresolved',
  })
})

test('ambiguous with a key attached is still not admitted', async () => {
  const out = await run({ state: 'ambiguous', public_key_hex: keyHex })
  assert.equal(out.state, 'indeterminate')
  assert.equal(out.key_authority, 'unresolved')
})

test('the other unsuccessful outcomes keep their mapping and never admit', async () => {
  assert.equal((await run({ state: 'unreachable' })).state, 'indeterminate')
  for (const state of ['not_found', 'malformed', 'unsupported'] as const) {
    const out = await run({ state })
    assert.equal(out.state, 'invalid', state)
    assert.equal(out.key_authority, 'rejected', state)
  }
})
