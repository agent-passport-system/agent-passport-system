// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Outcome mapping of verifyPassportV2 and verifyPrincipalBindingV1 when key resolution
// does not produce a usable key, and when a passport names a profile this verifier does
// not implement.
//
// Resolution: draft-04 section 3.5 maps an unsupported identifier scheme to unsupported
// and not found, ambiguous, malformed key material and unreachability to indeterminate.
// The same mapping is applied to the agent's own key and to the principal's key. A key
// that resolves and differs is still an established failure (invalid).
//
// Profile: a string record_type or version other than "aps.agent-passport" / "2.0" is
// unsupported and is not judged against the 2.0 schema, the rule draft-04 states for the
// delegation and revocation record families. A missing or non-string discriminator stays
// malformed, and so does a supported profile with a broken shape.
//
// None of these results admits the record. Acceptance requires state === 'valid'.

import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { generateKeyPair } from '../../src/crypto/keys.js'
import { verifyPassportV2 } from '../../src/v2/identity-binding/passport.js'
import {
  issuePrincipalBindingV1,
  verifyPrincipalBindingV1,
} from '../../src/v2/identity-binding/principal-binding.js'
import { didKeyFromPublicKey } from '../../src/v2/identity-binding/did-aps.js'
import type { HistoricalKeyResolutionResult } from '../../src/v2/identity-binding/types.js'

const vector = JSON.parse(readFileSync(
  new URL('../../fixtures/agent-passport-v2/agent-passport-vectors-v2.json', import.meta.url),
  'utf8',
))
const byName = (name: string) => vector.cases.find((c: { name: string }) => c.name === name)
const webCase = byName('valid-did-web-resolved')
const webKey: string = vector.key_resolver.entries.find(
  (e: { controller: string }) => e.controller === webCase.passport.agent_id,
).public_key_hex
const otherKey: string = vector.keys.find((k: { label: string; public_key_hex: string }) => k.label !== 'web-agent-key' && k.public_key_hex !== webKey).public_key_hex

const passportWith = (answer: unknown) =>
  verifyPassportV2(webCase.passport, { now: webCase.now, resolve_key: () => answer as HistoricalKeyResolutionResult })

// ── Passport: key resolution ──

test('passport resolution control: resolved key verifies', async () => {
  assert.deepEqual(await passportWith({ state: 'resolved', public_key_hex: webKey }), {
    state: 'valid', code: 'OK', proof_of_possession: true, key_authority: 'verified',
  })
})

test('passport resolution control: an uppercase resolved key is the same key', async () => {
  assert.equal((await passportWith({ state: 'resolved', public_key_hex: webKey.toUpperCase() })).state, 'valid')
})

test('passport: a resolved key that differs stays invalid, key authority rejected', async () => {
  assert.deepEqual(await passportWith({ state: 'resolved', public_key_hex: otherKey }), {
    state: 'invalid', code: 'PASSPORT_KEY_AUTHORITY_REJECTED', proof_of_possession: true, key_authority: 'rejected',
  })
})

for (const [state, code] of [
  ['not_found', 'PASSPORT_KEY_NOT_FOUND'],
  ['ambiguous', 'PASSPORT_KEY_AMBIGUOUS'],
  ['malformed', 'PASSPORT_KEY_MALFORMED'],
  ['unreachable', 'PASSPORT_KEY_UNREACHABLE'],
] as const) {
  test(`passport: resolver ${state} is indeterminate, key authority unresolved`, async () => {
    assert.deepEqual(await passportWith({ state }), {
      state: 'indeterminate', code, proof_of_possession: true, key_authority: 'unresolved',
    })
  })
}

test('passport: resolver unsupported scheme is unsupported, key authority unresolved', async () => {
  assert.deepEqual(await passportWith({ state: 'unsupported' }), {
    state: 'unsupported', code: 'PASSPORT_KEY_UNSUPPORTED', proof_of_possession: true, key_authority: 'unresolved',
  })
})

test('passport: a key attached to a failed resolution is ignored', async () => {
  for (const state of ['not_found', 'ambiguous', 'malformed', 'unreachable'] as const) {
    assert.equal((await passportWith({ state, public_key_hex: webKey })).state, 'indeterminate', state)
  }
  assert.equal((await passportWith({ state: 'unsupported', public_key_hex: webKey })).state, 'unsupported')
})

test('passport: resolved without usable key material is malformed key material, not a key mismatch', async () => {
  for (const answer of [
    { state: 'resolved' },
    { state: 'resolved', public_key_hex: '' },
    { state: 'resolved', public_key_hex: webKey.slice(2) },
    { state: 'resolved', public_key_hex: 'zz' + webKey.slice(2) },
  ]) {
    assert.deepEqual(await passportWith(answer), {
      state: 'indeterminate', code: 'PASSPORT_KEY_MALFORMED', proof_of_possession: true, key_authority: 'unresolved',
    }, JSON.stringify(answer))
  }
})

test('passport: an answer outside the resolver contract is indeterminate', async () => {
  for (const answer of [{ state: 'revoked' }, {}, null, 'resolved']) {
    assert.deepEqual(await passportWith(answer), {
      state: 'indeterminate', code: 'PASSPORT_KEY_RESOLUTION_FAILED', proof_of_possession: true, key_authority: 'unresolved',
    }, JSON.stringify(answer))
  }
})

test('passport: a resolver that throws is indeterminate, not an exception', async () => {
  const out = await verifyPassportV2(webCase.passport, { now: webCase.now, resolve_key: () => { throw new Error('boom') } })
  assert.deepEqual(out, {
    state: 'indeterminate', code: 'PASSPORT_KEY_RESOLUTION_FAILED', proof_of_possession: true, key_authority: 'unresolved',
  })
  const rejected = await verifyPassportV2(webCase.passport, { now: webCase.now, resolve_key: () => Promise.reject(new Error('boom')) })
  assert.equal(rejected.code, 'PASSPORT_KEY_RESOLUTION_FAILED')
})

// ── Passport: profile ──

const unsupportedType = { state: 'unsupported', code: 'PASSPORT_UNSUPPORTED_RECORD_TYPE', proof_of_possession: false, key_authority: 'unresolved' }
const unsupportedVersion = { state: 'unsupported', code: 'PASSPORT_UNSUPPORTED_VERSION', proof_of_possession: false, key_authority: 'unresolved' }
const malformed = { state: 'invalid', code: 'PASSPORT_MALFORMED', proof_of_possession: false, key_authority: 'rejected' }

test('passport: the frozen record-type-changed and version-changed cases are unsupported', async () => {
  const rt = byName('record-type-changed')
  const v = byName('version-changed')
  assert.deepEqual(await verifyPassportV2(rt.passport, { now: rt.now }), unsupportedType)
  assert.deepEqual(await verifyPassportV2(v.passport, { now: v.now }), unsupportedVersion)
})

test('passport: an unrecognised record_type is reported before an unrecognised version', async () => {
  const both = { ...webCase.passport, record_type: 'aps.agent-passport-x', version: '3.0' }
  assert.deepEqual(await verifyPassportV2(both, { now: webCase.now }), unsupportedType)
})

test('passport: an unrecognised profile is not judged against the 2.0 schema', async () => {
  const extra = { ...webCase.passport, version: '3.0', principal_id: 'did:example:p', nonce: 'short' }
  assert.deepEqual(await verifyPassportV2(extra, { now: webCase.now }), unsupportedVersion)
  const minimal = { record_type: 'aps.agent-passport', version: '9.9' }
  assert.deepEqual(await verifyPassportV2(minimal), unsupportedVersion)
})

test('passport: an unrecognised record_type is unsupported whatever the version member holds', async () => {
  const { version: _v, ...noVersion } = webCase.passport
  assert.deepEqual(await verifyPassportV2({ ...noVersion, record_type: 'other.record' }, { now: webCase.now }), unsupportedType)
  assert.deepEqual(await verifyPassportV2({ ...webCase.passport, record_type: 'other.record', version: 2 }, { now: webCase.now }), unsupportedType)
})

test('passport: an unsupported profile never reaches the key resolver', async () => {
  let calls = 0
  const resolve_key = () => { calls += 1; return { state: 'resolved', public_key_hex: webKey } as HistoricalKeyResolutionResult }
  await verifyPassportV2({ ...webCase.passport, version: '2.1' }, { now: webCase.now, resolve_key })
  await verifyPassportV2({ ...webCase.passport, record_type: 'other.record' }, { now: webCase.now, resolve_key })
  assert.equal(calls, 0)
})

test('passport: a legacy v1 passport shape (version, no record_type) is malformed', async () => {
  const legacy = { agentId: 'agent-x', version: '1.0.0', publicKey: webKey, signature: '00'.repeat(64) }
  assert.deepEqual(await verifyPassportV2(legacy), malformed)
})

test('passport: an accessor discriminator is malformed and is read at most once', async () => {
  let reads = 0
  const tricky = { ...webCase.passport }
  Object.defineProperty(tricky, 'version', { enumerable: true, get: () => { reads += 1; return reads === 1 ? '2.0' : '9.9' } })
  assert.deepEqual(await verifyPassportV2(tricky, { now: webCase.now }), malformed)
  assert.equal(reads, 0)
  const trickyType = { ...webCase.passport }
  Object.defineProperty(trickyType, 'record_type', { enumerable: true, get: () => 'aps.agent-passport' })
  assert.deepEqual(await verifyPassportV2(trickyType, { now: webCase.now }), malformed)
})

test('passport: a missing or non-string discriminator stays malformed', async () => {
  const { record_type: _rt, ...noType } = webCase.passport
  const { version: _v, ...noVersion } = webCase.passport
  for (const candidate of [
    noType,
    noVersion,
    { ...webCase.passport, record_type: 7 },
    { ...webCase.passport, version: 2 },
    { ...webCase.passport, version: null },
    null,
    [],
    'aps.agent-passport',
  ]) {
    assert.deepEqual(await verifyPassportV2(candidate, { now: webCase.now }), malformed, JSON.stringify(candidate))
  }
})

test('passport: the supported profile with a broken shape stays malformed', async () => {
  const extra = { ...webCase.passport, principal_id: 'did:example:p' }
  assert.deepEqual(await verifyPassportV2(extra, { now: webCase.now }), malformed)
})

test('passport: a bad signature on the supported profile stays invalid', async () => {
  const c = byName('signed-by-other-key')
  const out = await verifyPassportV2(c.passport, { now: c.now })
  assert.equal(out.state, 'invalid')
  assert.equal(out.code, 'PASSPORT_SIGNATURE_INVALID')
})

// ── Principal binding: key resolution ──

const principal = generateKeyPair()
const stranger = generateKeyPair()
const principalId = didKeyFromPublicKey(principal.publicKey)
const binding = issuePrincipalBindingV1({
  agent_id: didKeyFromPublicKey(generateKeyPair().publicKey),
  principal_id: principalId,
  verification_method: `${principalId}#${principalId.slice('did:key:'.length)}`,
  audiences: ['https://mcp.example'],
  authority_profiles: ['aps-authority-delegation-v1'],
  status_uri: 'https://principal.example/aps/status/binding-1',
  issued_at: '2026-07-16T18:00:00.000Z',
  expires_at: '2026-07-19T18:00:00.000Z',
  nonce: '03'.repeat(16),
  principal_private_key_hex: principal.privateKey,
})
const bindingWith = (answer: unknown) =>
  verifyPrincipalBindingV1(binding, { now: '2026-07-17T00:00:00.000Z', resolve_key: () => answer as HistoricalKeyResolutionResult })

test('principal binding control: resolved key verifies', async () => {
  assert.equal((await bindingWith({ state: 'resolved', public_key_hex: principal.publicKey })).state, 'valid')
})

test('principal binding: a resolved key that differs stays invalid (signature checked and failed)', async () => {
  assert.deepEqual(await bindingWith({ state: 'resolved', public_key_hex: stranger.publicKey }), {
    state: 'invalid', code: 'PRINCIPAL_BINDING_SIGNATURE_INVALID', proof_of_possession: false, key_authority: 'rejected',
  })
})

for (const [state, code, expected] of [
  ['not_found', 'PRINCIPAL_BINDING_KEY_NOT_FOUND', 'indeterminate'],
  ['ambiguous', 'PRINCIPAL_BINDING_KEY_AMBIGUOUS', 'indeterminate'],
  ['malformed', 'PRINCIPAL_BINDING_KEY_MALFORMED', 'indeterminate'],
  ['unreachable', 'PRINCIPAL_BINDING_KEY_UNREACHABLE', 'indeterminate'],
  ['unsupported', 'PRINCIPAL_BINDING_KEY_UNSUPPORTED', 'unsupported'],
] as const) {
  test(`principal binding: resolver ${state} is ${expected}, key authority unresolved`, async () => {
    assert.deepEqual(await bindingWith({ state }), {
      state: expected, code, proof_of_possession: false, key_authority: 'unresolved',
    })
  })
}

test('principal binding: resolved without usable key material is malformed key material', async () => {
  assert.deepEqual(await bindingWith({ state: 'resolved', public_key_hex: 'abc' }), {
    state: 'indeterminate', code: 'PRINCIPAL_BINDING_KEY_MALFORMED', proof_of_possession: false, key_authority: 'unresolved',
  })
})

test('principal binding: a resolver that throws is indeterminate, not an exception', async () => {
  const out = await verifyPrincipalBindingV1(binding, { now: '2026-07-17T00:00:00.000Z', resolve_key: () => { throw new Error('boom') } })
  assert.deepEqual(out, {
    state: 'indeterminate', code: 'PRINCIPAL_BINDING_KEY_RESOLUTION_FAILED', proof_of_possession: false, key_authority: 'unresolved',
  })
})

// ── Principal binding: profile ──
//
// The same recognition rule as the passport, for aps.principal-binding 1.0. These records
// used to be PRINCIPAL_BINDING_MALFORMED.

const pbUnsupportedType = { state: 'unsupported', code: 'PRINCIPAL_BINDING_UNSUPPORTED_RECORD_TYPE', proof_of_possession: false, key_authority: 'unresolved' }
const pbUnsupportedVersion = { state: 'unsupported', code: 'PRINCIPAL_BINDING_UNSUPPORTED_VERSION', proof_of_possession: false, key_authority: 'unresolved' }
const pbMalformed = { state: 'invalid', code: 'PRINCIPAL_BINDING_MALFORMED', proof_of_possession: false, key_authority: 'rejected' }
const pbNow = { now: '2026-07-17T00:00:00.000Z' }
const pbResolve = () => ({ state: 'resolved', public_key_hex: principal.publicKey }) as HistoricalKeyResolutionResult

test('principal binding: an unrecognised record_type or version is unsupported', async () => {
  assert.deepEqual(await verifyPrincipalBindingV1({ ...binding, record_type: 'aps.principal-binding-x' }, { ...pbNow, resolve_key: pbResolve }), pbUnsupportedType)
  assert.deepEqual(await verifyPrincipalBindingV1({ ...binding, version: '2.0' }, { ...pbNow, resolve_key: pbResolve }), pbUnsupportedVersion)
})

test('principal binding: an unrecognised record_type is reported before an unrecognised version', async () => {
  const both = { ...binding, record_type: 'other.record', version: '9.9' }
  assert.deepEqual(await verifyPrincipalBindingV1(both, { ...pbNow, resolve_key: pbResolve }), pbUnsupportedType)
})

test('principal binding: an unrecognised profile is not judged against the 1.0 schema', async () => {
  const extra = { ...binding, version: '1.1', delegation_id: 'x', nonce: 'short' }
  assert.deepEqual(await verifyPrincipalBindingV1(extra, { ...pbNow, resolve_key: pbResolve }), pbUnsupportedVersion)
  assert.deepEqual(await verifyPrincipalBindingV1({ record_type: 'aps.principal-binding', version: '9.9' }, { resolve_key: pbResolve }), pbUnsupportedVersion)
})

test('principal binding: an unsupported profile never reaches the key resolver', async () => {
  let calls = 0
  const resolve_key = () => { calls += 1; return pbResolve() }
  await verifyPrincipalBindingV1({ ...binding, version: '1.1' }, { ...pbNow, resolve_key })
  await verifyPrincipalBindingV1({ ...binding, record_type: 'other.record' }, { ...pbNow, resolve_key })
  assert.equal(calls, 0)
})

test('principal binding: an accessor discriminator is malformed and is read at most once', async () => {
  let reads = 0
  const tricky = { ...binding }
  Object.defineProperty(tricky, 'version', { enumerable: true, get: () => { reads += 1; return reads === 1 ? '1.0' : '9.9' } })
  assert.deepEqual(await verifyPrincipalBindingV1(tricky, { ...pbNow, resolve_key: pbResolve }), pbMalformed)
  assert.equal(reads, 0)
})

test('principal binding: a missing or non-string discriminator stays malformed', async () => {
  const { record_type: _rt, ...noType } = binding
  const { version: _v, ...noVersion } = binding
  for (const candidate of [noType, noVersion, { ...binding, record_type: 7 }, { ...binding, version: 1 }, { ...binding, version: null }, null, []]) {
    assert.deepEqual(await verifyPrincipalBindingV1(candidate, { ...pbNow, resolve_key: pbResolve }), pbMalformed, JSON.stringify(candidate))
  }
})

test('a proxy whose prototype or descriptor trap throws is malformed, never an exception', async () => {
  // Before the shared guard, verifyPassportV2 threw on both (since #221) and the reordered
  // verifyPrincipalBindingV1 did too.
  const hostile = [
    new Proxy({}, { getPrototypeOf() { throw new Error('boom') } }),
    new Proxy({}, { getOwnPropertyDescriptor() { throw new Error('boom') } }),
    new Proxy({ ...binding }, { getOwnPropertyDescriptor() { throw new Error('boom') } }),
  ]
  for (const candidate of hostile) {
    assert.deepEqual(await verifyPassportV2(candidate), malformed)
    assert.deepEqual(await verifyPrincipalBindingV1(candidate, { ...pbNow, resolve_key: pbResolve }), pbMalformed)
  }
})

test('principal binding: an unrecognised record_type is unsupported even with no version member', async () => {
  const { version: _v, ...noVersion } = binding
  assert.deepEqual(await verifyPrincipalBindingV1({ ...noVersion, record_type: 'other.record' }, { ...pbNow, resolve_key: pbResolve }), pbUnsupportedType)
})

test('principal binding: the supported profile with a broken shape stays malformed', async () => {
  assert.deepEqual(await verifyPrincipalBindingV1({ ...binding, extra: 1 }, { ...pbNow, resolve_key: pbResolve }), pbMalformed)
})

// ── Resolver answers that try to answer twice or throw while being read ──

function hostileAnswers(key: string): Array<[string, () => unknown]> {
  return [
    ['state getter throws', () => Object.defineProperty({}, 'state', { enumerable: true, get() { throw new Error('boom') } })],
    ['key getter throws', () => Object.defineProperty({ state: 'resolved' }, 'public_key_hex', { enumerable: true, get() { throw new Error('boom') } })],
    ['state getter flips', () => {
      let n = 0
      return Object.defineProperty({ public_key_hex: key }, 'state', { enumerable: true, get() { n += 1; return n === 1 ? 'resolved' : 'not_found' } })
    }],
    ['key getter flips', () => {
      let n = 0
      return Object.defineProperty({ state: 'resolved' }, 'public_key_hex', { enumerable: true, get() { n += 1; return n === 1 ? key : '00'.repeat(32) } })
    }],
    ['proxy trap throws', () => new Proxy({}, { getOwnPropertyDescriptor() { throw new Error('boom') }, get() { throw new Error('boom') } })],
  ]
}

for (const [label, make] of hostileAnswers(webKey)) {
  test(`passport: resolver answer where ${label} is RESOLUTION_FAILED, never an exception`, async () => {
    assert.deepEqual(await passportWith(make()), {
      state: 'indeterminate', code: 'PASSPORT_KEY_RESOLUTION_FAILED', proof_of_possession: true, key_authority: 'unresolved',
    })
  })
}

for (const [label, make] of hostileAnswers(principal.publicKey)) {
  test(`principal binding: resolver answer where ${label} is RESOLUTION_FAILED, never an exception`, async () => {
    assert.deepEqual(await bindingWith(make()), {
      state: 'indeterminate', code: 'PRINCIPAL_BINDING_KEY_RESOLUTION_FAILED', proof_of_possession: false, key_authority: 'unresolved',
    })
  })
}
