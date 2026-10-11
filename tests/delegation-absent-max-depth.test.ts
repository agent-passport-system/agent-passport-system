// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// A signed legacy Delegation without maxDepth. Verification and minting are separate.
// verifyDelegation applies no ceiling (docs/SPEC-v1.1.md section 4.1), and the frozen
// vector delegation-without-max-depth-at-depth-64 pins that. subDelegate refuses to mint
// a child under such a parent. Before, it minted a child with maxDepth 1 and currentDepth
// parent + 1, which then failed its own depth check.

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
        /numeric maxDepth/,
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
})
