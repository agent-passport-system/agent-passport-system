// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Interop: Motebit ExecutionReceipt consumer, pinned to motebit fed97862ddca5990eeba817918decf7099c22b50
//
// Claim ceiling. A passing receipt here establishes: the integrity of the signed
// canonical bytes under the embedded `public_key`, the signed `task_id`, and the
// declared `suite` identifier. It does NOT establish who controls the signer, or
// that the reported task actually occurred. Identity binding, meaning that the
// embedded `public_key` belongs to a specific, known device or principal, stays on
// Motebit's side. This consumer treats `public_key` as whatever the receipt
// embeds and checks only that the signature over the canonical body matches it.
//
// Verification recipe below is built from Motebit's published verifier
// (examples/python-receipt-verifier/verify.py) and spec (execution-ledger-v1.md
// §11) at the pinned commit, read only. No Motebit code is executed. This test
// uses the SDK's own canonicalizeJCS (RFC 8785) and node:crypto Ed25519.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto'
import { canonicalizeJCS } from '../../src/index.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const FIXTURES_DIR = join(__dirname, '../../examples/interop/motebit')

const SUITE_ID = 'motebit-jcs-ed25519-b64-v1'

// Ed25519 SubjectPublicKeyInfo DER prefix for a raw 32-byte public key.
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')

const PINNED = {
  'example-receipt.json': {
    sha256: '130af372ceb2923b0c7753d1daa2be991e7cf251bb3b50cc66a1686734dd6b67',
    canonicalBodySha256: '445407920cb8e5011b146bc7ba8b5a3c66ae0218e02bb2f5c5d1f87e94b3f880',
  },
  'sovereign-receipt.json': {
    sha256: '220409fa0a02d35cf17093019c124daa2f079da817d74473f290f70d59b0312c',
  },
} as const

function loadRaw(name: keyof typeof PINNED): Buffer {
  return readFileSync(join(FIXTURES_DIR, name))
}

function loadReceipt(name: keyof typeof PINNED): Record<string, unknown> {
  return JSON.parse(loadRaw(name).toString('utf8'))
}

function base64urlDecode(s: string): Buffer {
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64')
}

/** Motebit §11.2/§11.3: strip `signature`, JCS-canonicalize the rest, Ed25519-verify
 *  the canonical bytes against the hex-decoded embedded `public_key`. */
function verifyReceiptSignature(receipt: Record<string, unknown>): boolean {
  const { signature, ...body } = receipt
  const canonical = canonicalizeJCS(body)
  const sigBytes = base64urlDecode(signature as string)
  const pkBytes = Buffer.from(receipt.public_key as string, 'hex')
  const keyObject = createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, pkBytes]),
    format: 'der',
    type: 'spki',
  })
  return cryptoVerify(null, Buffer.from(canonical, 'utf8'), keyObject, sigBytes)
}

function canonicalBodySha256(receipt: Record<string, unknown>): string {
  const { signature, ...body } = receipt
  return createHash('sha256').update(canonicalizeJCS(body), 'utf8').digest('hex')
}

/** Consumer policy, separate from signature verification. A receipt can carry a
 *  valid Ed25519 signature under a suite this consumer never agreed to interpret
 *  that way; accepting it anyway would mean verifying bytes under a recipe other
 *  than the one that was declared. */
function acceptsSuite(receipt: Record<string, unknown>): boolean {
  return receipt.suite === SUITE_ID
}

describe('Motebit ExecutionReceipt consumer (fixture drift pins)', () => {
  it('example-receipt.json SHA-256 matches the pinned value', () => {
    const actual = createHash('sha256').update(loadRaw('example-receipt.json')).digest('hex')
    assert.equal(actual, PINNED['example-receipt.json'].sha256)
  })

  it('sovereign-receipt.json SHA-256 matches the pinned value', () => {
    const actual = createHash('sha256').update(loadRaw('sovereign-receipt.json')).digest('hex')
    assert.equal(actual, PINNED['sovereign-receipt.json'].sha256)
  })
})

describe('Motebit ExecutionReceipt consumer (signature verification)', () => {
  it('example-receipt.json verifies under the embedded key over the canonical signed bytes', () => {
    const receipt = loadReceipt('example-receipt.json')
    assert.equal(verifyReceiptSignature(receipt), true)
  })

  it('sovereign-receipt.json verifies under the embedded key over the canonical signed bytes', () => {
    const receipt = loadReceipt('sovereign-receipt.json')
    assert.equal(verifyReceiptSignature(receipt), true)
  })

  it("example-receipt.json canonical body SHA-256 starts with Motebit's reported prefix 445407920cb8", () => {
    const receipt = loadReceipt('example-receipt.json')
    const hash = canonicalBodySha256(receipt)
    assert.equal(hash, PINNED['example-receipt.json'].canonicalBodySha256)
    assert.ok(hash.startsWith('445407920cb8'))
  })

  it('changing `result` makes example-receipt.json fail verification', () => {
    const receipt = loadReceipt('example-receipt.json')
    receipt.result = 'tampered result'
    assert.equal(verifyReceiptSignature(receipt), false)
  })

  it('changing `result` makes sovereign-receipt.json fail verification', () => {
    const receipt = loadReceipt('sovereign-receipt.json')
    receipt.result = 'tampered result'
    assert.equal(verifyReceiptSignature(receipt), false)
  })

  it('changing `task_id` makes example-receipt.json fail verification', () => {
    const receipt = loadReceipt('example-receipt.json')
    receipt.task_id = '00000000-0000-0000-0000-000000000000'
    assert.equal(verifyReceiptSignature(receipt), false)
  })

  it('changing `task_id` makes sovereign-receipt.json fail verification', () => {
    const receipt = loadReceipt('sovereign-receipt.json')
    receipt.task_id = '00000000-0000-0000-0000-000000000000'
    assert.equal(verifyReceiptSignature(receipt), false)
  })
})

describe('Motebit ExecutionReceipt consumer policy (suite allowlist)', () => {
  it('accepts suite motebit-jcs-ed25519-b64-v1 for both fixtures', () => {
    assert.equal(acceptsSuite(loadReceipt('example-receipt.json')), true)
    assert.equal(acceptsSuite(loadReceipt('sovereign-receipt.json')), true)
  })

  it('refuses any other suite value, independent of signature validity', () => {
    const receipt = loadReceipt('example-receipt.json')
    receipt.suite = 'motebit-jcs-ed25519-b64-v2'
    assert.equal(acceptsSuite(receipt), false)
    // The signature check is independent of the policy check. A tampered suite
    // value also breaks the signature, since `suite` is part of the signed body.
    assert.equal(verifyReceiptSignature(receipt), false)
  })
})
