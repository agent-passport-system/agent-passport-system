// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

// A time bound that cannot be read must deny, never widen acceptance. Each rail gate
// is checked with a positive control (a valid future bound allows), a structurally
// valid expired bound (denies), and a bound that does not parse as RFC 3339 (denies).
// Delegations are really signed, and the delegation validator is run on the same
// record to show what an integrator who validates first would see.

import test from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair } from '../../../src/crypto/keys.js'
import { createV2Delegation, validateV2Delegation } from '../../../src/v2/delegation-v2.js'
import { preAuthorizeMppPayment } from '../../../src/v2/payment-rails/mpp/index.js'
import { preAuthorizeAcpCheckout } from '../../../src/v2/payment-rails/acp/index.js'
import { preAuthorize } from '../../../src/v2/payment-rails/hooks.js'
import { delegationToView } from '../../../src/v2/payment-rails/stripe-issuing/index.js'
import { createPolicyContext } from '../../../src/v2/bridge.js'
import type { V2Delegation } from '../../../src/v2/types.js'
import type { MppPaymentChallenge } from '../../../src/v2/payment-rails/mpp/types.js'
import type { PaymentRail } from '../../../src/v2/payment-rails/types.js'

const NOW = new Date('2026-11-27T12:00:00.000Z')
// ACP has no injectable clock, so its bounds sit far from any real run time.
const FAR_PAST = '2020-01-01T00:00:00.000Z'
const FAR_FUTURE = '2099-01-01T00:00:00.000Z'
const VALID_FROM = '2026-11-27T11:00:00.000Z'
const EXPIRED_FROM = '2026-06-01T00:00:00.000Z'
const EXPIRED_UNTIL = '2026-06-30T23:59:59.000Z'
const FUTURE_UNTIL = '2026-12-27T00:00:00.000Z'
// Unreadable expiry values. The month-end :60 value is also in the past.
const UNREADABLE = ['not-a-date', '', '2026-06-30T23:59:60.000Z', '2026-02-30T00:00:00.000Z', '31/12/2026']

const keys = generateKeyPair()

function signed(categories: string[], validFrom: string, validUntil: string): V2Delegation {
  return createV2Delegation({
    delegator: keys.publicKey,
    delegatee: 'agent-002',
    scope: {
      action_categories: categories,
      resource_limits: { spend_limit_cents: 5000 },
      constraints: { allowed_payment_methods: 'card', allowed_currencies: 'usd' },
    },
    policy_context: {
      policy_version: '2.0.0', values_floor_version: '1.0.0', trust_epoch: 1,
      issuer_id: 'agent-001', created_at: validFrom, valid_from: validFrom, valid_until: validUntil,
    },
    delegator_private_key: keys.privateKey,
  })
}

function challenge(expiresAt: string): MppPaymentChallenge {
  return {
    challenge_id: 'mpc', required_amount: '1500', currency: 'usd', nonce: 'n',
    resource: 'https://api.example.com/x', expires_at: expiresAt,
    methods: [{ method_type: 'card', network: 'visa', currency: 'usd', max_amount: '5000' }],
  } as unknown as MppPaymentChallenge
}

const acpRequest = { items: [{ id: 'item_1', quantity: 1 }], buyer: { first_name: 'A', last_name: 'B', email: 'a@b.com' } } as never
const rail = { name: 'test', isWalletRevoked: () => false } as unknown as PaymentRail

test('delegation validator: controls and unreadable valid_until', () => {
  assert.equal(validateV2Delegation(signed(['payment'], VALID_FROM, FUTURE_UNTIL), NOW).valid, true)
  assert.equal(validateV2Delegation(signed(['payment'], EXPIRED_FROM, EXPIRED_UNTIL), NOW).valid, false)
  for (const bad of UNREADABLE) {
    assert.equal(validateV2Delegation(signed(['payment'], VALID_FROM, bad), NOW).valid, false, bad)
  }
})

test('MPP: delegation valid_until', () => {
  const fresh = challenge('2026-11-27T12:05:00.000Z')
  assert.deepEqual(preAuthorizeMppPayment(fresh, signed(['payment'], VALID_FROM, FUTURE_UNTIL), { now: NOW }), { allow: true })
  assert.equal(preAuthorizeMppPayment(fresh, signed(['payment'], EXPIRED_FROM, EXPIRED_UNTIL), { now: NOW }).allow, false)
  for (const bad of UNREADABLE) {
    const r = preAuthorizeMppPayment(fresh, signed(['payment'], VALID_FROM, bad), { now: NOW })
    assert.equal(r.allow, false, `valid_until=${JSON.stringify(bad)}`)
    assert.equal(r.allow === false && r.reason, 'delegation_expired')
  }
})

test('MPP: challenge expires_at', () => {
  const d = signed(['payment'], VALID_FROM, FUTURE_UNTIL)
  assert.equal(preAuthorizeMppPayment(challenge('2026-11-27T11:59:00.000Z'), d, { now: NOW }).allow, false)
  for (const bad of UNREADABLE) {
    const r = preAuthorizeMppPayment(challenge(bad), d, { now: NOW })
    assert.equal(r.allow, false, `expires_at=${JSON.stringify(bad)}`)
    assert.equal(r.allow === false && r.reason, 'challenge_expired')
  }
})

test('ACP: delegation valid_until', () => {
  assert.equal(preAuthorizeAcpCheckout(acpRequest, signed(['commerce'], FAR_PAST, FAR_FUTURE), 'usd').allow, true)
  assert.equal(preAuthorizeAcpCheckout(acpRequest, signed(['commerce'], '2019-01-01T00:00:00.000Z', FAR_PAST), 'usd').allow, false)
  for (const bad of UNREADABLE) {
    const r = preAuthorizeAcpCheckout(acpRequest, signed(['commerce'], FAR_PAST, bad), 'usd')
    assert.equal(r.allow, false, `valid_until=${JSON.stringify(bad)}`)
  }
})

test('foundation gate through delegationToView: not_after and not_before', () => {
  const input = (d: V2Delegation) => ({
    delegation: delegationToView(d, 'usd', 'w1'), required_scope: 'commerce.purchase',
    amount_base_units: '100', currency: 'usd', now: NOW,
  })
  assert.equal(preAuthorize(input(signed(['commerce.purchase'], VALID_FROM, FUTURE_UNTIL)), rail).ok, true)
  assert.equal(preAuthorize(input(signed(['commerce.purchase'], EXPIRED_FROM, EXPIRED_UNTIL)), rail).ok, false)
  for (const bad of UNREADABLE) {
    const until = preAuthorize(input(signed(['commerce.purchase'], VALID_FROM, bad)), rail)
    assert.equal(until.ok, false, `not_after=${JSON.stringify(bad)}`)
    const from = preAuthorize(input(signed(['commerce.purchase'], bad, FUTURE_UNTIL)), rail)
    assert.equal(from.ok, false, `not_before=${JSON.stringify(bad)}`)
  }
})

test('createPolicyContext refuses an unreadable valid_until', () => {
  const base = { policy_version: '2', values_floor_version: '1', trust_epoch: 1, issuer_id: 'i' }
  assert.doesNotThrow(() => createPolicyContext({ ...base, valid_until: FUTURE_UNTIL, valid_from: VALID_FROM } as never))
  for (const bad of UNREADABLE.filter(v => v !== '')) {
    assert.throws(() => createPolicyContext({ ...base, valid_until: bad } as never), undefined, bad)
  }
})
