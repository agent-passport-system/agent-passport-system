// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Runs the language-neutral Cycles correspondence vectors against this SDK.
// The vectors are data: a receipt, the envelope it cites, and the verdict any
// implementation should reach. See cycles-correspondence-vectors/README.md.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import {
  verifyCyclesDenial,
  verifyCyclesPermitReceipt,
  verifyCyclesReleaseReceipt,
} from '../../../src/v2/payment-rails/cycles/index.js'

const FILE = join(dirname(fileURLToPath(import.meta.url)), 'cycles-correspondence-vectors', 'vectors.json')
const vectors = JSON.parse(readFileSync(FILE, 'utf-8')) as {
  cases: Array<{
    id: string
    verifier: 'permit' | 'release' | 'denial'
    receipt: any
    envelope: any
    expected: { valid: boolean; evidence_authenticity?: string; reason?: string; detail_prefix?: string }
  }>
}

const verifiers = {
  permit: verifyCyclesPermitReceipt,
  release: verifyCyclesReleaseReceipt,
  denial: verifyCyclesDenial,
} as const

test('cycles correspondence vectors: the file carries the expected cases', () => {
  assert.equal(vectors.cases.length, 13)
  assert.equal(new Set(vectors.cases.map(c => c.id)).size, vectors.cases.length)
})

for (const c of vectors.cases) {
  test(`cycles correspondence vector: ${c.id}`, () => {
    const result = verifiers[c.verifier](c.receipt, { evidence: c.envelope }) as any
    if (c.expected.valid) {
      assert.deepEqual(result, { valid: true, evidence_authenticity: c.expected.evidence_authenticity })
      return
    }
    assert.equal(result.valid, false)
    assert.equal(result.reason, c.expected.reason)
    if (c.expected.detail_prefix !== undefined) {
      assert.ok(
        typeof result.detail === 'string' && result.detail.startsWith(c.expected.detail_prefix),
        `detail ${String(result.detail)} does not start with ${c.expected.detail_prefix}`,
      )
    }
  })
}
