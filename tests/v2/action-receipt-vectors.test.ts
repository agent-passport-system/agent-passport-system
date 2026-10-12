// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// The committed legacy Action Receipt v1.1 vector family, run against the
// merged functions. Source: fixtures/action-receipt-v1.1/. Nothing is minted
// here. The assertions are that verifyDelegation, verifyReceipt, subDelegate and
// createReceipt still return exactly what the file records for the inputs it
// records, with Date.now() fixed at the file's verification_instant, that an
// accepted createReceipt returns the case record's members and input values,
// and that createDelegation writes maxDepth 1 when the caller omits it. The surface is frozen, so a change
// that is "fixed" by regenerating the vector is a change to what
// already-signed records mean.

import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { canonicalize } from '../../src/core/canonical.js'
import { createDelegation, createReceipt, subDelegate, verifyDelegation, verifyReceipt } from '../../src/core/delegation.js'
import type { ActionReceipt, Delegation } from '../../src/types/passport.js'

type Rec = Record<string, unknown>
interface Issuance { function: string; inputs: Rec; accepted: boolean; error: string | null }
interface SubDelegateInputs { parent: string; delegatedTo: string; scope: string[]; spendLimit: number; signer_key: string }
interface CreateReceiptInputs { delegation: string; agentId: string; action: ActionReceipt['action']; result: ActionReceipt['result']; delegationChain: string[]; signer_key: string }
interface Scope { function: string; establishes_authorization: boolean }
interface VectorFile {
  sdk_reference: { commit: string }
  verification_instant: string
  keys: Array<{ label: string; public_key_hex: string; private_key_hex: string }>
  preimages: Record<string, { signature_preimage_hex: string }>
  delegation_cases: Array<{ name: string; record: Rec; verification_scope: Scope; verification: Rec; issuance?: Issuance }>
  receipt_cases: Array<{ name: string; record: Rec; verify_with_key: string; verification_scope: Scope; verification: Rec; issuance?: Issuance }>
}

const vector = JSON.parse(readFileSync(
  new URL('../../fixtures/action-receipt-v1.1/action-receipt-vectors-v1.1.json', import.meta.url),
  'utf8',
)) as VectorFile

const instantMs = Date.parse(vector.verification_instant)
function atInstant<T>(fn: () => T): T {
  const real = Date.now
  Date.now = () => instantMs
  try {
    return fn()
  } finally {
    Date.now = real
  }
}

const key = (label: string) => vector.keys.find(k => k.label === label)!
const utf8Hex = (v: string): string => Buffer.from(v, 'utf8').toString('hex')
function without(record: Rec, drop: string[]): Rec {
  const out: Rec = {}
  for (const [k, v] of Object.entries(record)) if (!drop.includes(k)) out[k] = v
  return out
}

test('vector file names the implementation and the instant', () => {
  assert.match(vector.sdk_reference.commit, /^[0-9a-f]{40}$/)
  assert.equal(vector.verification_instant, '2026-10-10T12:00:00.000Z')
  assert.equal(vector.delegation_cases.length, 12)
  assert.equal(vector.receipt_cases.length, 10)
})

test('no case claims to establish authorization', () => {
  for (const item of [...vector.delegation_cases, ...vector.receipt_cases]) {
    assert.equal(item.verification_scope.establishes_authorization, false, item.name)
  }
})

test('the SDK canonicalization reproduces the recorded preimage bytes', () => {
  for (const [name, expected] of Object.entries(vector.preimages)) {
    const item = [...vector.delegation_cases, ...vector.receipt_cases].find(c => c.name === name)
    assert.ok(item, name)
    assert.equal(utf8Hex(canonicalize(without(item.record, ['signature']))), expected.signature_preimage_hex, name)
  }
})

for (const item of vector.delegation_cases) {
  test(`delegation ${item.name}`, () => {
    assert.equal(item.verification_scope.function, 'verifyDelegation')
    const observed = atInstant(() => verifyDelegation(item.record as unknown as Delegation))
    // JSON round trip: the live status carries revokedAt: undefined, which the
    // vector file cannot represent and which means the same thing as absent.
    assert.deepEqual(JSON.parse(JSON.stringify(observed)), item.verification)
  })
}

for (const item of vector.receipt_cases) {
  test(`receipt ${item.name}`, () => {
    assert.equal(item.verification_scope.function, 'verifyReceipt')
    const observed = atInstant(() => verifyReceipt(item.record as unknown as ActionReceipt, key(item.verify_with_key).public_key_hex))
    assert.deepEqual(observed, item.verification)
  })
}

const DELEGATIONS_BY_ID: Record<string, Delegation> = Object.fromEntries(
  vector.delegation_cases.map(c => [String(c.record.delegationId), c.record as unknown as Delegation]),
)
const delegation = (id: string): Delegation => {
  const d = DELEGATIONS_BY_ID[id]
  assert.ok(d, `no delegation ${id} in the file`)
  return d
}

function attempt(run: () => unknown): { accepted: boolean; error: string | null; output: Rec | null } {
  try {
    const output = JSON.parse(JSON.stringify(atInstant(run))) as Rec
    return { accepted: true, error: null, output }
  } catch (e) {
    return { accepted: false, error: (e as Error).message, output: null }
  }
}

// Members createReceipt takes from its inputs. receiptId, timestamp and the
// signature come from a uuid, the clock and the key.
const RECEIPT_MEMBERS_FROM_INPUTS = ['version', 'agentId', 'delegationId', 'action', 'result', 'delegationChain']

for (const item of vector.delegation_cases) {
  if (!item.issuance) continue
  test(`issuance ${item.name}: ${item.issuance.function}`, () => {
    assert.equal(item.issuance!.function, 'subDelegate')
    const inputs = item.issuance!.inputs as unknown as SubDelegateInputs
    const outcome = attempt(() => subDelegate({
      parentDelegation: delegation(inputs.parent),
      delegatedTo: inputs.delegatedTo,
      scope: inputs.scope,
      spendLimit: inputs.spendLimit,
      privateKey: key(inputs.signer_key).private_key_hex,
    }))
    assert.equal(outcome.accepted, item.issuance!.accepted)
    assert.equal(outcome.error, item.issuance!.error)
  })
}

for (const item of vector.receipt_cases) {
  if (!item.issuance) continue
  test(`issuance ${item.name}: ${item.issuance.function}`, () => {
    assert.equal(item.issuance!.function, 'createReceipt')
    const inputs = item.issuance!.inputs as unknown as CreateReceiptInputs
    const outcome = attempt(() => createReceipt({
      agentId: inputs.agentId,
      delegationId: inputs.delegation,
      delegation: delegation(inputs.delegation),
      action: inputs.action,
      result: inputs.result,
      delegationChain: inputs.delegationChain,
      privateKey: key(inputs.signer_key).private_key_hex,
    }))
    assert.equal(outcome.accepted, item.issuance!.accepted)
    assert.equal(outcome.error, item.issuance!.error)
    if (!outcome.accepted) return
    // The returned receipt carries the case record's member names, and its
    // values for every member taken from the inputs, the chain included.
    const out = outcome.output!
    assert.deepEqual(Object.keys(out).sort(), Object.keys(item.record).sort())
    for (const m of RECEIPT_MEMBERS_FROM_INPUTS) assert.deepEqual(out[m], item.record[m], m)
    assert.deepEqual(out.delegationChain, inputs.delegationChain)
  })
}

test('createDelegation writes maxDepth 1 when the caller omits it', () => {
  const written = atInstant(() => createDelegation({
    delegatedBy: key('principal-key').public_key_hex,
    delegatedTo: key('agent-key').public_key_hex,
    scope: ['data:read'],
    expiresAt: '2027-10-01T00:00:00.000Z',
    privateKey: key('principal-key').private_key_hex,
  }))
  assert.equal(written.maxDepth, 1)
})
