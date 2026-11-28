// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Settlement, AP2 and clock-skew decisions read timestamps as real instants.
// A value that matches the timestamp shape but names no instant (seconds 99,
// month 13, day 32, February 30) is refused, never compared as NaN.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  aggregateAttributionPrimitives,
  verifySettlementRecord,
} from '../../src/index.js'
import {
  apsToAp2CartMandate,
  apsToAp2IntentMandate,
  signAp2Mandate,
  verifyAp2Mandate,
} from '../../src/v2/payment-rails/ap2/index.js'
import { checkClockSkew } from '../../src/v2/verifier-hardening/index.js'
import { generateKeyPair } from '../../src/crypto/keys.js'
import type { V2Delegation } from '../../src/v2/types.js'

const FIXTURE_DIR = join(dirname(fileURLToPath(import.meta.url)), 'fixtures/build-c')
const fixture = JSON.parse(readFileSync(join(FIXTURE_DIR, readdirSync(FIXTURE_DIR).filter((f) => f.endsWith('.json')).sort()[0]), 'utf8'))

const NOT_INSTANTS = [
  '2026-01-01T00:00:99.000Z',
  '2026-13-01T00:00:00.000Z',
  '2026-01-32T00:00:00.000Z',
  '2026-02-30T00:00:00.000Z',
  '2026-01-01T24:00:00.000Z',
  '2026-06-30T23:59:60.000Z',
]

describe('attribution settlement refuses timestamps that name no instant', () => {
  const opts = { gateway_did: fixture.gateway_did, issued_at: fixture.expected_record.issued_at }

  it('the pinned fixture still aggregates', () => {
    assert.doesNotThrow(() => aggregateAttributionPrimitives(fixture.input_receipts, fixture.period, opts))
  })

  for (const bad of NOT_INSTANTS) {
    it(`aggregate refuses period.t0 ${bad}`, () => {
      assert.throws(() => aggregateAttributionPrimitives(fixture.input_receipts, { ...fixture.period, t0: bad }, opts), /real instant/)
    })
    it(`aggregate refuses period.t1 ${bad}`, () => {
      assert.throws(() => aggregateAttributionPrimitives(fixture.input_receipts, { ...fixture.period, t1: bad }, opts), /real instant/)
    })
    it(`aggregate refuses a receipt timestamp ${bad}, with skipOutOfPeriod false`, () => {
      const receipts = fixture.input_receipts.map((r: any, i: number) => (i === 0 ? { ...r, timestamp: bad } : r))
      assert.throws(() => aggregateAttributionPrimitives(receipts, fixture.period, { ...opts, skipOutOfPeriod: false }), /real instant/)
    })
    it(`verify refuses a record period.t0 ${bad}`, () => {
      const record = { ...fixture.expected_record, period: { ...fixture.expected_record.period, t0: bad } }
      const v = verifySettlementRecord(record, { gatewayPublicKeyHex: fixture.gateway_public_key, inputReceipts: fixture.input_receipts })
      assert.equal(v.valid, false)
    })
    it(`verify refuses an input receipt timestamp ${bad}`, () => {
      const receipts = fixture.input_receipts.map((r: any, i: number) => (i === 0 ? { ...r, timestamp: bad } : r))
      const v = verifySettlementRecord(fixture.expected_record, { gatewayPublicKeyHex: fixture.gateway_public_key, inputReceipts: receipts })
      assert.equal(v.valid, false)
    })
  }

  it('the pinned record still verifies', () => {
    const v = verifySettlementRecord(fixture.expected_record, { gatewayPublicKeyHex: fixture.gateway_public_key, inputReceipts: fixture.input_receipts })
    assert.equal(v.valid, true, JSON.stringify(v))
  })
})

function intent(window: { valid_from?: string; valid_until?: string } = {}): V2Delegation {
  return {
    id: 'del_ts', version: 1, supersedes: null, supersession_justification: null,
    delegator: 'did:aps:user', delegatee: 'did:aps:agent',
    scope: { action_categories: ['commerce.checkout'], resource_limits: { 'commerce.spend_limit': 50000 }, constraints: {} },
    policy_context: {
      policy_version: '2.0.0', values_floor_version: '1.0.0', trust_epoch: 1, issuer_id: 'did:aps:user',
      created_at: '2026-05-04T00:00:00.000Z',
      valid_from: window.valid_from ?? '2026-05-04T00:00:00.000Z',
      valid_until: window.valid_until ?? '2026-12-31T23:59:59.000Z',
    },
    signature: 'stub', status: 'active', renewal_reason: null, expansion_reviewer: null,
    expansion_review_sig: null, assurance_class: 'mechanically_enforceable',
  } as V2Delegation
}

describe('AP2 conversion refuses an unreadable lifetime bound instead of dropping it', () => {
  it('a readable window keeps iat and exp', () => {
    const m = apsToAp2IntentMandate(intent(), { currency: 'USD' }) as { iat?: number; exp?: number }
    assert.equal(typeof m.iat, 'number')
    assert.equal(typeof m.exp, 'number')
  })
  for (const bad of ['not-a-date', ...NOT_INSTANTS]) {
    it(`valid_until ${bad} throws`, () => {
      assert.throws(() => apsToAp2IntentMandate(intent({ valid_until: bad }), { currency: 'USD' }), /valid_until is not an RFC 3339 instant/)
    })
    it(`valid_from ${bad} throws`, () => {
      assert.throws(() => apsToAp2IntentMandate(intent({ valid_from: bad }), { currency: 'USD' }), /valid_from is not an RFC 3339 instant/)
    })
  }
  it('the cart converter refuses it too', () => {
    assert.throws(() => apsToAp2CartMandate(intent({ valid_until: 'not-a-date' }) as any, {} as any), /valid_until is not an RFC 3339 instant|policy_context/)
  })
})

describe('verifyAp2Mandate refuses a present iat or exp that is not an integer', () => {
  const kp = generateKeyPair()
  const now = new Date('2026-06-01T00:00:00.000Z')
  const base = () => apsToAp2IntentMandate(intent(), { currency: 'USD' })

  it('a well-formed mandate verifies', () => {
    assert.equal(verifyAp2Mandate(signAp2Mandate(base(), kp.privateKey), { now }).valid, true)
  })
  for (const [name, v] of [['exp', 'never'], ['exp', null], ['iat', 'soon'], ['exp', 1.5]] as const) {
    it(`${name} = ${String(v)} is refused`, () => {
      const m: any = base()
      m[name] = v
      const r = verifyAp2Mandate(signAp2Mandate(m, kp.privateKey), { now })
      assert.equal(r.valid, false)
      assert.match(r.detail ?? '', new RegExp(`${name} must be an integer`))
    })
  }
})

describe('AP2 signing cannot carry a NaN bound', () => {
  it('JCS refuses NaN before a signature exists', () => {
    const m: any = apsToAp2IntentMandate(intent(), { currency: 'USD' })
    m.exp = Number.NaN
    assert.throws(() => signAp2Mandate(m, generateKeyPair().privateKey), /NaN/)
  })
})

describe('checkClockSkew refuses an unreadable bound or clock', () => {
  const now = new Date('2026-06-01T00:00:00.000Z')
  it('readable bounds still pass', () => {
    assert.equal(checkClockSkew({ iat: '2026-06-01T00:00:00.000Z', exp: '2026-06-02T00:00:00.000Z', now }).verdict, 'valid')
  })
  for (const bad of ['not-a-date', ...NOT_INSTANTS]) {
    it(`exp ${bad} is malformed`, () => assert.equal(checkClockSkew({ exp: bad, now }).verdict, 'malformed'))
    it(`iat ${bad} is malformed`, () => assert.equal(checkClockSkew({ iat: bad, now }).verdict, 'malformed'))
  }
  it('an Invalid Date clock is malformed', () => {
    assert.equal(checkClockSkew({ exp: '2026-06-02T00:00:00.000Z', now: new Date('x') }).verdict, 'malformed')
  })
  it('a NaN numeric bound is malformed', () => assert.equal(checkClockSkew({ exp: Number.NaN, now }).verdict, 'malformed'))
})
