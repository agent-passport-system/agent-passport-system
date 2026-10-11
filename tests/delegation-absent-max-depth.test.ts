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
    for (const changes of [{ maxDepth: null }, { maxDepth: '2' }, { maxDepth: true }, { maxDepth: 1.5 }, { maxDepth: -1 }, { maxDepth: 2 ** 53 }, { maxDepth: 2, currentDepth: 0.5 }, { maxDepth: 2, currentDepth: true }]) {
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

// #223. A present maxDepth that is not a non-negative safe integer is inside the signed
// bytes, so only the issuer can produce it. The comparison used to coerce it ("1" acted as
// 1, true as 1) while the Python verifier skipped it, so one record got two verdicts. It is
// now invalid in both, and no depth result is claimed for it.
describe('legacy Delegation with a malformed maxDepth', () => {
  function signedWith(changes: Record<string, unknown>): Delegation {
    const granter = generateKeyPair()
    const agent = generateKeyPair()
    const base = createDelegation({
      delegatedBy: granter.publicKey, delegatedTo: agent.publicKey,
      scope: ['data:read'], spendLimit: 100, maxDepth: 1, privateKey: granter.privateKey,
    })
    return resigned(base, changes, [], granter.privateKey)
  }

  it('is invalid at depth 0 and above, without a depth result', () => {
    for (const value of ['1', '0', true, false, 1.5, -1, 2 ** 53, [1], { n: 1 }]) {
      for (const depth of [0, 2]) {
        const status = verifyDelegation(signedWith({ maxDepth: value, currentDepth: depth }))
        const label = `${JSON.stringify(value)} at ${depth}`
        assert.equal(status.valid, false, label)
        assert.equal(status.depthExceeded, false, label)
        assert.ok(status.errors.some(e => e.startsWith('Malformed maxDepth')), label)
      }
    }
  })

  it('null is still read as absent', () => {
    const status = verifyDelegation(signedWith({ maxDepth: null, currentDepth: 3 }))
    assert.equal(status.valid, true, status.errors.join(', '))
    assert.equal(status.depthExceeded, false)
  })

  it('a malformed currentDepth is invalid, with or without a ceiling', () => {
    for (const value of ['5', '0', true, 0.5, -1, 2 ** 53, [1]]) {
      for (const maxDepth of [1, null]) {
        const status = verifyDelegation(signedWith({ maxDepth, currentDepth: value }))
        const label = `currentDepth ${JSON.stringify(value)}, maxDepth ${maxDepth}`
        assert.equal(status.valid, false, label)
        assert.equal(status.depthExceeded, false, label)
        assert.ok(status.errors.some(e => e.startsWith('Malformed currentDepth')), label)
      }
    }
  })

  it('an absent or null currentDepth is not compared', () => {
    const granter = generateKeyPair()
    const agent = generateKeyPair()
    const base = createDelegation({
      delegatedBy: granter.publicKey, delegatedTo: agent.publicKey,
      scope: ['data:read'], spendLimit: 100, maxDepth: 0, privateKey: granter.privateKey,
    })
    for (const record of [resigned(base, {}, ['currentDepth'], granter.privateKey), resigned(base, { currentDepth: null }, [], granter.privateKey)]) {
      const status = verifyDelegation(record)
      assert.equal(status.valid, true, status.errors.join(', '))
      assert.equal(status.depthExceeded, false)
    }
  })
})

// #223, writer side. createDelegation refuses to sign a depth its own verifier reports
// malformed, so the SDK cannot hand back a signed record it would then refuse.
describe('createDelegation refuses a malformed depth', () => {
  const g = generateKeyPair()
  const a = generateKeyPair()
  const create = (extra: Record<string, unknown>) => createDelegation({
    delegatedBy: g.publicKey, delegatedTo: a.publicKey, scope: ['data:read'], spendLimit: 1,
    privateKey: g.privateKey, ...extra,
  } as Parameters<typeof createDelegation>[0])

  it('throws for a maxDepth or currentDepth that is not a non-negative safe integer', () => {
    for (const value of [1.5, -1, 2 ** 53, Number.NaN, Number.POSITIVE_INFINITY, '1', true]) {
      assert.throws(() => create({ maxDepth: value }), /maxDepth must be a non-negative integer/, `maxDepth ${String(value)}`)
      assert.throws(() => create({ currentDepth: value }), /currentDepth must be a non-negative integer/, `currentDepth ${String(value)}`)
    }
  })

  it('signs the boundary values and the defaults, and they verify', () => {
    for (const extra of [{}, { maxDepth: 0 }, { maxDepth: 2 ** 53 - 1, currentDepth: 2 ** 53 - 1 }, { maxDepth: null }]) {
      const d = create(extra)
      assert.equal(verifyDelegation(d).valid, true, JSON.stringify(extra))
    }
    assert.equal(create({}).maxDepth, 1)
    assert.equal(create({ maxDepth: null }).maxDepth, 1)
  })
})
