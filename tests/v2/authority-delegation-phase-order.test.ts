// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

// draft-pidlisnyi-aps-04 section 4.3: verification is phase-major, and the first phase
// in which any member fails decides the returned state and reason. A child whose
// not_before predates its issued_at fails in the child issuance time phase, after
// signature, root trust and linkage. An earlier-phase fault in the same chain decides
// first, including one whose state is indeterminate.

import test from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair } from '../../src/crypto/keys.js'
import {
  AUTHORITY_DELEGATION_RECORD_TYPE,
  AUTHORITY_DELEGATION_VERSION,
  REPUTATION_PROFILE_V1,
  REVERSIBILITY_PROFILE_V1,
  SCOPE_PROFILE_V1,
  VALUES_PROFILE_V1,
  computeAuthorityDelegationId,
  issueAuthorityDelegation,
  signAuthorityDelegation,
  validateAuthorityDelegationShape,
  verifyAuthorityDelegationChain,
} from '../../src/v2/authority-delegation/index.js'
import type {
  AuthorityChainVerificationOptions,
  AuthorityDelegationBodyV1,
  AuthorityDelegationV1,
  AuthorityVectorV1,
} from '../../src/v2/authority-delegation/index.js'

const rootKeys = generateKeyPair()
const childKeys = generateKeyPair()
const at = (minute: string) => `2026-07-18T22:${minute}:00.000Z`

function authority(notBefore: string, notAfter: string, remaining: number): AuthorityVectorV1 {
  return {
    scope: { profile: SCOPE_PROFILE_V1, grants: ['commerce:*'] },
    spend: { mode: 'unbounded' },
    depth: { remaining },
    time: { not_before: notBefore, not_after: notAfter },
    reputation: { profile: REPUTATION_PROFILE_V1, ceiling: 80 },
    values: { profile: VALUES_PROFILE_V1, required: [] },
    reversibility: { profile: REVERSIBILITY_PROFILE_V1, ceiling: 'compensable' },
  }
}

function rootRecord(issuedAt: string, notBefore: string): AuthorityDelegationV1 {
  return issueAuthorityDelegation({
    record_type: AUTHORITY_DELEGATION_RECORD_TYPE,
    version: AUTHORITY_DELEGATION_VERSION,
    parent_delegation_id: null,
    issuer: 'did:example:root',
    subject: 'did:example:a',
    verification_method: 'did:example:root#key-1',
    issued_at: issuedAt,
    nonce: '00112233445566778899aabbccddeeff',
    authority: authority(notBefore, at('59'), 3),
  }, rootKeys.privateKey)
}

// Signed directly: the issuance helper refuses a child that breaks the issuance time
// rule, and this test needs one to reach the verifier.
function childIssuedAfterItsNotBefore(parent: AuthorityDelegationV1, remaining = 2, notAfter = at('50')): AuthorityDelegationV1 {
  const body: AuthorityDelegationBodyV1 = {
    record_type: AUTHORITY_DELEGATION_RECORD_TYPE,
    version: AUTHORITY_DELEGATION_VERSION,
    parent_delegation_id: parent.delegation_id,
    issuer: parent.subject,
    subject: 'did:example:b',
    verification_method: 'did:example:a#key-1',
    issued_at: at('10'),
    nonce: '102132435465768798a9bacbdcedfe0f',
    authority: authority(at('05'), notAfter, remaining),
  }
  const unsigned = { ...body, delegation_id: computeAuthorityDelegationId(body) }
  return { ...unsigned, signature: signAuthorityDelegation(unsigned, childKeys.privateKey) }
}

const root = rootRecord(at('00'), at('00'))
const child = childIssuedAfterItsNotBefore(root)
const keys = new Map([[root.verification_method, rootKeys.publicKey], [child.verification_method, childKeys.publicKey]])
const options: AuthorityChainVerificationOptions = {
  now: at('20'),
  resolveVerificationKey: (_issuer, method) => keys.get(method) ?? null,
  trustRoot: () => true,
  resolveRevocation: () => 'active',
}

test('a child not_before before its issued_at alone is invalid in the child issuance time phase', () => {
  const result = verifyAuthorityDelegationChain([root, child], options)
  assert.equal(result.state, 'invalid')
  assert.deepEqual(result.failures.map(f => [f.code, f.index]), [['SCHEMA_INVALID', 1]])
})

test('an unreachable signing key in an earlier phase decides first: indeterminate, not invalid', () => {
  const result = verifyAuthorityDelegationChain([root, child], {
    ...options,
    resolveVerificationKey: (_issuer, method) =>
      method === root.verification_method ? { outcome: 'unreachable' } : keys.get(method) ?? null,
  })
  assert.equal(result.state, 'indeterminate')
  assert.deepEqual(result.failures.map(f => [f.code, f.index]), [['KEY_UNREACHABLE', 0]])
})

test('an untrusted root in an earlier phase decides first', () => {
  const result = verifyAuthorityDelegationChain([root, child], { ...options, trustRoot: () => false })
  assert.equal(result.state, 'invalid')
  assert.deepEqual(result.failures.map(f => [f.code, f.index]), [['ROOT_UNTRUSTED', 0]])
})

test('a trust policy that cannot decide in an earlier phase decides first: indeterminate', () => {
  const result = verifyAuthorityDelegationChain([root, child], {
    ...options,
    trustRoot: () => { throw new Error('policy store down') },
  })
  assert.equal(result.state, 'indeterminate')
  assert.deepEqual(result.failures.map(f => [f.code, f.index]), [['ROOT_UNTRUSTED', 0]])
})

test('a later-phase attenuation fault does not decide first: the issuance time rule does', () => {
  // Child depth 3 under a parent with 3 remaining widens depth (phase 9).
  const widened = childIssuedAfterItsNotBefore(root, 3)
  const result = verifyAuthorityDelegationChain([root, widened], options)
  assert.equal(result.state, 'invalid')
  assert.deepEqual(result.failures.map(f => [f.code, f.index]), [['SCHEMA_INVALID', 1]])
})

test('a later-phase expiry does not decide first: the issuance time rule does', () => {
  // now 22:55 is after the child's not_after 22:50 (phase 10).
  const result = verifyAuthorityDelegationChain([root, child], { ...options, now: at('55') })
  assert.equal(result.state, 'invalid')
  assert.deepEqual(result.failures.map(f => [f.code, f.index]), [['SCHEMA_INVALID', 1]])
})

test('a root may take effect before its own issued_at', () => {
  const early = rootRecord(at('10'), at('00'))
  const result = verifyAuthorityDelegationChain([early], { ...options, now: at('05') })
  assert.equal(result.state, 'valid')
})

test('standalone shape validation still reports the rule unless the caller defers it', () => {
  assert.deepEqual(validateAuthorityDelegationShape(child).map(f => f.code), ['SCHEMA_INVALID'])
  assert.deepEqual(validateAuthorityDelegationShape(child, { childIssuanceTime: false }), [])
})
