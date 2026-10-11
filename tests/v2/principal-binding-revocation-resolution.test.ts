// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// verifyPrincipalBindingRevocationV1 when key resolution does not produce a usable key.
// The same draft-04 section 3.5 mapping verifyPassportV2 and verifyPrincipalBindingV1
// apply: unsupported identifier scheme is unsupported, not found, ambiguous, malformed key
// material and unreachability are indeterminate, and key authority is unresolved. A resolved
// key that does not verify the signature stays invalid. A resolver that throws, rejects or
// answers outside the contract is indeterminate / RESOLUTION_FAILED, never an exception.
// None of these results verifies the revocation, and none is evidence the binding stays in force.

import test from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair } from '../../src/crypto/keys.js'
import { didKeyFromPublicKey } from '../../src/v2/identity-binding/did-aps.js'
import {
  issuePrincipalBindingRevocationV1,
  verifyPrincipalBindingRevocationV1,
} from '../../src/v2/identity-binding/revocation.js'
import type { HistoricalKeyResolutionResult, HistoricalKeyResolver } from '../../src/v2/identity-binding/types.js'

const principal = generateKeyPair()
const stranger = generateKeyPair()
const principalId = didKeyFromPublicKey(principal.publicKey)
const verificationMethod = `${principalId}#${principalId.slice('did:key:'.length)}`
const revocation = issuePrincipalBindingRevocationV1({
  binding_id: 'ab'.repeat(32),
  principal_id: principalId,
  verification_method: verificationMethod,
  revoked_at: '2026-07-17T01:00:00.000Z',
  reason_code: 'principal_request',
  nonce: '04'.repeat(16),
  principal_private_key_hex: principal.privateKey,
})
const withAnswer = (answer: unknown) =>
  verifyPrincipalBindingRevocationV1(revocation, (() => answer as HistoricalKeyResolutionResult) as HistoricalKeyResolver)
const unresolved = (state: string, code: string) => ({
  state, code, proof_of_possession: false, key_authority: 'unresolved',
})

test('control: the resolved principal key verifies', async () => {
  assert.deepEqual(await withAnswer({ state: 'resolved', public_key_hex: principal.publicKey }), {
    state: 'valid', code: 'OK', proof_of_possession: true, key_authority: 'verified',
  })
})

test('the resolver is asked for the principal key at revoked_at', async () => {
  const requests: unknown[] = []
  await verifyPrincipalBindingRevocationV1(revocation, (request) => {
    requests.push(request)
    return { state: 'resolved', public_key_hex: principal.publicKey }
  })
  assert.deepEqual(requests, [{ controller: principalId, verification_method: verificationMethod, at: '2026-07-17T01:00:00.000Z' }])
})

test('a resolved key that does not verify the signature stays invalid', async () => {
  assert.deepEqual(await withAnswer({ state: 'resolved', public_key_hex: stranger.publicKey }), {
    state: 'invalid', code: 'PRINCIPAL_BINDING_REVOCATION_SIGNATURE_INVALID', proof_of_possession: false, key_authority: 'rejected',
  })
})

for (const [state, code, expected] of [
  ['not_found', 'PRINCIPAL_BINDING_REVOCATION_KEY_NOT_FOUND', 'indeterminate'],
  ['ambiguous', 'PRINCIPAL_BINDING_REVOCATION_KEY_AMBIGUOUS', 'indeterminate'],
  ['malformed', 'PRINCIPAL_BINDING_REVOCATION_KEY_MALFORMED', 'indeterminate'],
  ['unreachable', 'PRINCIPAL_BINDING_REVOCATION_KEY_UNREACHABLE', 'indeterminate'],
  ['unsupported', 'PRINCIPAL_BINDING_REVOCATION_KEY_UNSUPPORTED', 'unsupported'],
] as const) {
  test(`resolver ${state} is ${expected}, key authority unresolved`, async () => {
    assert.deepEqual(await withAnswer({ state }), unresolved(expected, code))
  })
}

test('resolved without usable key material is malformed key material', async () => {
  assert.deepEqual(await withAnswer({ state: 'resolved', public_key_hex: 'abc' }),
    unresolved('indeterminate', 'PRINCIPAL_BINDING_REVOCATION_KEY_MALFORMED'))
  assert.deepEqual(await withAnswer({ state: 'resolved' }),
    unresolved('indeterminate', 'PRINCIPAL_BINDING_REVOCATION_KEY_MALFORMED'))
})

const failed = unresolved('indeterminate', 'PRINCIPAL_BINDING_REVOCATION_KEY_RESOLUTION_FAILED')

test('a resolver that throws or rejects is RESOLUTION_FAILED, never an exception', async () => {
  assert.deepEqual(await verifyPrincipalBindingRevocationV1(revocation, () => { throw new Error('boom') }), failed)
  assert.deepEqual(await verifyPrincipalBindingRevocationV1(revocation, () => Promise.reject(new Error('boom'))), failed)
})

for (const [label, answer] of [
  ['undefined', () => undefined],
  ['null', () => null],
  ['no state', () => ({ public_key_hex: principal.publicKey })],
  ['unknown state', () => ({ state: 'revoked' })],
  ['state getter throws', () => Object.defineProperty({}, 'state', { enumerable: true, get() { throw new Error('boom') } })],
  ['key getter flips', () => {
    let n = 0
    return Object.defineProperty({ state: 'resolved' }, 'public_key_hex', { enumerable: true, get() { n += 1; return n === 1 ? principal.publicKey : stranger.publicKey } })
  }],
  ['proxy trap throws', () => new Proxy({}, { getOwnPropertyDescriptor() { throw new Error('boom') }, get() { throw new Error('boom') } })],
  ['non-plain object carrying the right key (#228)', () => Object.assign(new Date(0), { state: 'resolved', public_key_hex: principal.publicKey })],
  ['class instance carrying the right key (#228)', () => Object.assign(new (class Answer {})(), { state: 'resolved', public_key_hex: principal.publicKey })],
  ['getPrototypeOf trap throws (#228)', () => new Proxy({ state: 'resolved', public_key_hex: principal.publicKey }, { getPrototypeOf() { throw new Error('boom') } })],
] as Array<[string, () => unknown]>) {
  test(`resolver answer ${label} is RESOLUTION_FAILED, never an exception`, async () => {
    assert.deepEqual(await withAnswer(answer()), failed)
  })
}

test('an unresolved key is checked before the signature and never calls it established', async () => {
  const tampered = { ...revocation, signature: '00'.repeat(64) }
  const out = await verifyPrincipalBindingRevocationV1(tampered, () => ({ state: 'not_found' }))
  assert.deepEqual(out, unresolved('indeterminate', 'PRINCIPAL_BINDING_REVOCATION_KEY_NOT_FOUND'))
})

test('a null-prototype resolver answer is still a plain answer (#228 control)', async () => {
  const answer = Object.assign(Object.create(null), { state: 'resolved', public_key_hex: principal.publicKey })
  assert.equal((await withAnswer(answer)).state, 'valid')
})
