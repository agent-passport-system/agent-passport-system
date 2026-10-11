// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// A signed legacy Delegation without maxDepth. Verification and minting are separate.
// verifyDelegation applies no ceiling (docs/SPEC-v1.1.md section 4.1), and the frozen
// vector delegation-without-max-depth-at-depth-64 pins that. A null maxDepth signs to the
// same bytes and is read the same way. subDelegate refuses to mint a child under a parent
// without a non-negative integer maxDepth. Before, it minted a child with maxDepth 1 and
// currentDepth parent + 1, which failed its own depth check from parent depth 1 up.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair, createDelegation, subDelegate, verifyDelegation } from '../src/index.js'
import { canonicalize } from '../src/core/canonical.js'
import { sign } from '../src/crypto/keys.js'
import type { Delegation } from '../src/types/passport.js'

function resigned(d: Delegation, changes: Record<string, unknown>, drop: string[], privateKey: string): Delegation {
  const out: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(d)) if (k !== 'signature' && !drop.includes(k)) out[k] = v
  Object.assign(out, changes)
  out.signature = sign(canonicalize(out), privateKey)
  return out as unknown as Delegation
}

function parentWithout(changes: Record<string, unknown> = {}) {
  const granter = generateKeyPair()
  const agent = generateKeyPair()
  const base = createDelegation({
    delegatedBy: granter.publicKey, delegatedTo: agent.publicKey,
    scope: ['data:read'], spendLimit: 100, maxDepth: 3, privateKey: granter.privateKey,
  })
  return { parent: resigned(base, changes, ['maxDepth'], granter.privateKey), agent }
}

describe('legacy Delegation without maxDepth', () => {
  it('verifies with no depth ceiling at depth 64', () => {
    const { parent } = parentWithout({ currentDepth: 64 })
    assert.equal('maxDepth' in parent, false)
    const status = verifyDelegation(parent)
    assert.equal(status.depthExceeded, false)
    assert.equal(status.valid, true, status.errors.join(', '))
  })

  it('subDelegate refuses to mint a child under it', () => {
    for (const depth of [0, 64]) {
      const { parent, agent } = parentWithout({ currentDepth: depth })
      assert.throws(
        () => subDelegate({ parentDelegation: parent, delegatedTo: generateKeyPair().publicKey, scope: ['data:read'], privateKey: agent.privateKey }),
        /integer maxDepth/,
        `currentDepth ${depth}`,
      )
    }
  })

  it('subDelegate with an explicit parent maxDepth is unchanged', () => {
    const granter = generateKeyPair()
    const agent = generateKeyPair()
    const parent = createDelegation({
      delegatedBy: granter.publicKey, delegatedTo: agent.publicKey,
      scope: ['data:read'], spendLimit: 100, maxDepth: 2, privateKey: granter.privateKey,
    })
    const child = subDelegate({ parentDelegation: parent, delegatedTo: generateKeyPair().publicKey, scope: ['data:read'], privateKey: agent.privateKey })
    assert.equal(child.maxDepth, 2)
    assert.equal(child.currentDepth, 1)
    assert.equal(verifyDelegation(child).valid, true)
  })

  it('maxDepth null and maxDepth absent carry the same signature and the same verdict', () => {
    const { parent } = parentWithout({ currentDepth: 2 })
    const withNull = { ...parent, maxDepth: null } as unknown as Delegation
    assert.equal(canonicalize(withNull), canonicalize(parent))
    const a = verifyDelegation(parent)
    const b = verifyDelegation(withNull)
    assert.equal(a.valid, true, a.errors.join(', '))
    assert.deepEqual(b, a)
  })

  it('explicit limits are unchanged, including the boundary', () => {
    const granter = generateKeyPair()
    const agent = generateKeyPair()
    const base = createDelegation({
      delegatedBy: granter.publicKey, delegatedTo: agent.publicKey,
      scope: ['data:read'], spendLimit: 100, maxDepth: 1, privateKey: granter.privateKey,
    })
    const at = resigned(base, { currentDepth: 1 }, [], granter.privateKey)
    const over = resigned(base, { currentDepth: 2 }, [], granter.privateKey)
    assert.equal(verifyDelegation(at).valid, true)
    assert.equal(verifyDelegation(over).depthExceeded, true)
  })

  it('subDelegate refuses a non-integer or negative parent ceiling or depth', () => {
    for (const changes of [{ maxDepth: null }, { maxDepth: '2' }, { maxDepth: 1.5 }, { maxDepth: -1 }, { maxDepth: 2, currentDepth: 0.5 }]) {
      const granter = generateKeyPair()
      const agent = generateKeyPair()
      const base = createDelegation({
        delegatedBy: granter.publicKey, delegatedTo: agent.publicKey,
        scope: ['data:read'], spendLimit: 100, maxDepth: 3, privateKey: granter.privateKey,
      })
      const parent = resigned(base, changes, [], granter.privateKey)
      assert.throws(
        () => subDelegate({ parentDelegation: parent, delegatedTo: generateKeyPair().publicKey, scope: ['data:read'], privateKey: agent.privateKey }),
        /non-negative integer/,
        JSON.stringify(changes),
      )
    }
  })
})
