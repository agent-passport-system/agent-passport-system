// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// x402 payment rail — adapter behavior tests with mock facilitator.
//
// No real network I/O; the facilitator /verify and /settle endpoints
// are caller-supplied closures the test file injects per scenario.
//
// Coverage:
//   - createInvoice produces valid X402PaymentRequirements
//   - submitPayment happy path (facilitator verifies + settles → receipt
//     with on-chain tx hash)
//   - submitPayment verify-fail → denial with rail_error
//   - preAuthorize gate failures (no_commerce_scope, spend_limit_exceeded)
//     before invoice creation
//   - revokeWallet halts subsequent createInvoice → preAuthorize chain
//   - verifyTransaction resolves settled tx hashes
//   - sendPayment throws UnsupportedOperation
//   - canonicalize+verify round-trip on receipt and denial
//   - byte-parity check on the four shipped fixtures

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  emitDenial,
  emitReceipt,
  preAuthorize,
  verifyPaymentDenial,
  verifyPaymentReceipt,
} from '../../../src/v2/payment-rails/index.js'
import type {
  DelegationView,
  PaymentDenial,
  PaymentReceipt,
} from '../../../src/v2/payment-rails/index.js'
import {
  DEFAULT_FACILITATOR_URL,
  USDC_BASE_MAINNET,
  X402PaymentRail,
  createX402Rail,
} from '../../../src/v2/payment-rails/x402/index.js'
import type {
  X402AttemptOutcome,
  X402AttemptStore,
  X402SettlementAttempt,
} from '../../../src/v2/payment-rails/x402/index.js'
import {
  X402_VERSION,
  type EIP3009Authorization,
  type X402PaymentPayload,
  type X402SettleResponse,
  type X402VerifyResponse,
} from '../../../src/v2/payment-rails/x402/types.js'
import { publicKeyFromPrivate } from '../../../src/crypto/keys.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const FIXTURE_DIR = join(
  __dirname,
  '..',
  '..',
  '..',
  'src',
  'v2',
  'payment-rails',
  'x402',
  'fixtures',
)

const ISSUER_PRIV = '99'.repeat(32)
const ISSUER_PUB = publicKeyFromPrivate(ISSUER_PRIV)

const PAY_TO = '0x000000000000000000000000000000000000beef'
const PAYER = '0x000000000000000000000000000000000000cafe'
const TX_HASH = '0x' + '1'.repeat(64)

// ── Mock facilitators ─────────────────────────────────────────────

function alwaysVerify(payer = PAYER) {
  return async (): Promise<X402VerifyResponse> => ({
    isValid: true,
    payer,
  })
}

function neverVerify(reason = 'invalid_signature') {
  return async (): Promise<X402VerifyResponse> => ({
    isValid: false,
    invalidReason: reason,
    payer: PAYER,
  })
}

function alwaysSettle(txHash = TX_HASH, payer = PAYER) {
  return async (): Promise<X402SettleResponse> => ({
    success: true,
    payer,
    transaction: txHash,
    network: 'base',
  })
}

function neverSettle(reason = 'insufficient_funds') {
  return async (): Promise<X402SettleResponse> => ({
    success: false,
    errorReason: reason,
    payer: PAYER,
    transaction: '',
    network: 'base',
  })
}

function _rail(overrides: Partial<{
  verify: ReturnType<typeof alwaysVerify>
  settle: ReturnType<typeof alwaysSettle>
}> = {}): X402PaymentRail {
  return createX402Rail({
    payTo: PAY_TO,
    asset: USDC_BASE_MAINNET,
    network: 'base',
    resource: 'https://example.com/api/premium',
    description: 'Test endpoint',
    facilitatorVerify: overrides.verify ?? alwaysVerify(),
    facilitatorSettle: overrides.settle ?? alwaysSettle(),
  })
}

function _delegation(overrides: Partial<DelegationView> = {}): DelegationView {
  return {
    receipt_id: 'd'.repeat(64),
    scope: ['commerce.purchase'],
    spend_limit_base_units: '5000000', // 5 USDC
    wallet_id: 'wallet-x402-001',
    currency: 'USDC',
    ...overrides,
  }
}

function _authorization(overrides: Partial<EIP3009Authorization> = {}): EIP3009Authorization {
  return {
    from: PAYER,
    to: PAY_TO,
    value: '1000000',
    validAfter: '0',
    validBefore: '1893456000',
    nonce: '0x' + '0'.repeat(64),
    ...overrides,
  }
}

function _payload(overrides: Partial<X402PaymentPayload> = {}): X402PaymentPayload {
  return {
    x402Version: X402_VERSION,
    scheme: 'exact',
    network: 'base',
    payload: {
      signature: '0x' + 'a'.repeat(130),
      authorization: _authorization(),
    },
    ...overrides,
  }
}

// ── createInvoice ─────────────────────────────────────────────────

describe('X402PaymentRail — createInvoice', () => {
  it('builds an invoice with the configured rail name and currency', async () => {
    const rail = _rail()
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    assert.equal(invoice.rail_name, 'x402-base-USDC')
    assert.equal(invoice.currency, 'USDC')
    assert.equal(invoice.amount_base_units, '1000000')
    assert.equal(invoice.amount_human, '1 USDC')
    assert.equal(invoice.destination, PAY_TO)
    assert.equal(invoice.status, 'pending')
  })

  it('formats sub-unit amounts via assetDecimals (USDC default 6)', async () => {
    const rail = _rail()
    const tenCents = await rail.createInvoice({ amount_base_units: '100000' })
    assert.equal(tenCents.amount_human, '0.1 USDC')
    const hundredth = await rail.createInvoice({ amount_base_units: '10000' })
    assert.equal(hundredth.amount_human, '0.01 USDC')
  })

  it('caches PaymentRequirements retrievable via getRequirements()', async () => {
    const rail = _rail()
    const invoice = await rail.createInvoice({ amount_base_units: '2000000' })
    const req = rail.getRequirements(invoice.invoice_id)
    assert.notEqual(req, undefined)
    assert.equal(req?.scheme, 'exact')
    assert.equal(req?.network, 'base')
    assert.equal(req?.maxAmountRequired, '2000000')
    assert.equal(req?.asset, USDC_BASE_MAINNET)
    assert.equal(req?.payTo, PAY_TO)
    assert.equal(req?.resource, 'https://example.com/api/premium')
    assert.equal(req?.description, 'Test endpoint')
    assert.equal(req?.maxTimeoutSeconds, 60)
  })

  it('expires_in_seconds overrides defaultMaxTimeoutSeconds', async () => {
    const rail = createX402Rail({
      payTo: PAY_TO,
      asset: USDC_BASE_MAINNET,
      network: 'base',
      resource: 'https://example.com/r',
      defaultMaxTimeoutSeconds: 60,
      facilitatorVerify: alwaysVerify(),
      facilitatorSettle: alwaysSettle(),
    })
    const invoice = await rail.createInvoice({
      amount_base_units: '1000000',
      expires_in_seconds: 300,
    })
    const req = rail.getRequirements(invoice.invoice_id)
    assert.equal(req?.maxTimeoutSeconds, 300)
  })
})

// ── submitPayment happy path ──────────────────────────────────────

describe('X402PaymentRail — submitPayment happy path', () => {
  it('verifies + settles, returns tx hash, marks invoice confirmed', async () => {
    const rail = _rail()
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    const outcome = await rail.submitPayment(invoice.invoice_id, _payload())

    assert.equal(outcome.verified, true)
    assert.equal(outcome.settled, true)
    assert.equal(outcome.transaction, TX_HASH)
    assert.equal(outcome.payer, PAYER)

    const after = await rail.checkStatus(invoice.invoice_id)
    assert.equal(after.status, 'confirmed')
  })

  it('full pipeline: preAuth → submitPayment → emitReceipt → verify', async () => {
    const rail = _rail()
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })

    const preAuth = preAuthorize(
      {
        delegation: _delegation(),
        required_scope: 'commerce.purchase',
        amount_base_units: '1000000',
        currency: 'USDC',
      },
      rail,
    )
    assert.equal(preAuth.ok, true)

    const outcome = await rail.submitPayment(invoice.invoice_id, _payload())
    assert.equal(outcome.verified && outcome.settled, true)

    const receipt = emitReceipt(
      {
        delegation_ref: _delegation().receipt_id,
        action_ref: 'a'.repeat(64),
        rail_name: rail.name,
        amount_base_units: invoice.amount_base_units,
        currency: invoice.currency,
        tx_proof: outcome.transaction!,
        invoice_id: invoice.invoice_id,
      },
      ISSUER_PRIV,
    )

    assert.equal(receipt.rail_name, 'x402-base-USDC')
    assert.equal(receipt.tx_proof, TX_HASH)
    assert.equal(receipt.signer_did, ISSUER_PUB)

    const verified = verifyPaymentReceipt(receipt)
    assert.equal(verified.valid, true)
  })
})

describe('X402PaymentRail — concurrent submitPayment on one invoice', () => {
  it('runs verify and settle once when two calls overlap', async () => {
    let verifyCalls = 0
    let settleCalls = 0
    let release: () => void = () => {}
    const gate = new Promise<void>((r) => { release = r })
    const rail = _rail({
      verify: async () => {
        verifyCalls++
        await gate
        return { isValid: true, payer: PAYER }
      },
      settle: async () => {
        settleCalls++
        return { success: true, payer: PAYER, transaction: TX_HASH, network: 'base' }
      },
    })
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    const first = rail.submitPayment(invoice.invoice_id, _payload())
    const second = rail.submitPayment(
      invoice.invoice_id,
      _payload({ payload: { signature: '0x' + 'b'.repeat(130), authorization: _authorization({ nonce: '0x' + '1'.repeat(64) }) } }),
    )
    const both = Promise.allSettled([first, second])
    await new Promise((r) => setImmediate(r))
    release()
    const [a, b] = await both
    assert.equal(settleCalls, 1)
    assert.equal(verifyCalls, 1)
    assert.equal(a.status, 'fulfilled')
    assert.equal(a.status === 'fulfilled' && a.value.settled, true)
    assert.equal(b.status, 'rejected')
    assert.match(String(b.status === 'rejected' && b.reason), /already has a submitPayment in progress/)
    const after = await rail.checkStatus(invoice.invoice_id)
    assert.equal(after.status, 'confirmed')
  })

  it('refuses a later call once the first has settled', async () => {
    const rail = _rail()
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    await rail.submitPayment(invoice.invoice_id, _payload())
    await assert.rejects(rail.submitPayment(invoice.invoice_id, _payload()), /not pending/)
  })
})

describe('X402PaymentRail — settle call throws, result unknown', () => {
  const throwingSettle = async (): Promise<X402SettleResponse> => {
    throw new Error('socket hang up')
  }

  it('records settlement_unknown, not failed, and refuses a second submit', async () => {
    let settleCalls = 0
    const rail = _rail({
      settle: async () => {
        settleCalls++
        throw new Error('socket hang up')
      },
    })
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    const outcome = await rail.submitPayment(invoice.invoice_id, _payload())

    assert.equal(outcome.verified, true)
    assert.equal(outcome.settled, undefined)
    assert.equal(outcome.settlementUnknown, true)
    assert.match(outcome.settleErrorReason ?? '', /^facilitator_settle_threw: socket hang up/)

    const after = await rail.checkStatus(invoice.invoice_id)
    assert.equal(after.status, 'settlement_unknown')

    await assert.rejects(rail.submitPayment(invoice.invoice_id, _payload()), /not pending/)
    assert.equal(settleCalls, 1)
  })

  it('stays unknown past the invoice expiry time', async () => {
    const rail = _rail({ settle: throwingSettle })
    const invoice = await rail.createInvoice({ amount_base_units: '1000000', expires_in_seconds: 1 })
    await rail.submitPayment(invoice.invoice_id, _payload())
    await new Promise((r) => setTimeout(r, 1100))
    const after = await rail.checkStatus(invoice.invoice_id)
    assert.equal(after.status, 'settlement_unknown')
  })

  it('resolveSettlement(settled) confirms the invoice and indexes the transaction', async () => {
    const rail = _rail({ settle: throwingSettle })
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    await rail.submitPayment(invoice.invoice_id, _payload())

    const resolved = rail.resolveSettlement(invoice.invoice_id, {
      settled: true,
      transaction: TX_HASH,
      payer: PAYER,
    })
    assert.equal(resolved.status, 'confirmed')
    const v = await rail.verifyTransaction(TX_HASH, '1000000')
    assert.equal(v.verified, true)
  })

  it('resolveSettlement(not settled) marks the invoice failed', async () => {
    const rail = _rail({ settle: throwingSettle })
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    await rail.submitPayment(invoice.invoice_id, _payload())

    const resolved = rail.resolveSettlement(invoice.invoice_id, {
      settled: false,
      reason: 'authorization_expired_unused',
    })
    assert.equal(resolved.status, 'failed')
    await assert.rejects(rail.submitPayment(invoice.invoice_id, _payload()), /not pending/)
  })

  it('resolveSettlement refuses an invoice that is not unknown', async () => {
    const rail = _rail()
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    assert.throws(
      () => rail.resolveSettlement(invoice.invoice_id, { settled: false, reason: 'x' }),
      /not in settlement_unknown/,
    )
    await rail.submitPayment(invoice.invoice_id, _payload())
    assert.throws(
      () => rail.resolveSettlement(invoice.invoice_id, { settled: false, reason: 'x' }),
      /not in settlement_unknown/,
    )
    const after = await rail.checkStatus(invoice.invoice_id)
    assert.equal(after.status, 'confirmed')
  })

  it('checkStatus asks the configured resolver and applies a definite answer', async () => {
    let answer: { settled: true; transaction: string; payer: string } | undefined
    let asked = 0
    const rail = createX402Rail({
      payTo: PAY_TO,
      asset: USDC_BASE_MAINNET,
      network: 'base',
      resource: 'https://example.com/r',
      facilitatorVerify: alwaysVerify(),
      facilitatorSettle: throwingSettle,
      settlementResolver: async () => {
        asked++
        return answer
      },
    })
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    await rail.submitPayment(invoice.invoice_id, _payload())

    const first = await rail.checkStatus(invoice.invoice_id)
    assert.equal(first.status, 'settlement_unknown')
    answer = { settled: true, transaction: TX_HASH, payer: PAYER }
    const second = await rail.checkStatus(invoice.invoice_id)
    assert.equal(second.status, 'confirmed')
    await rail.checkStatus(invoice.invoice_id)
    assert.equal(asked, 2)
  })

  it('a resolver that throws leaves the invoice unknown', async () => {
    const rail = createX402Rail({
      payTo: PAY_TO,
      asset: USDC_BASE_MAINNET,
      network: 'base',
      resource: 'https://example.com/r',
      facilitatorVerify: alwaysVerify(),
      facilitatorSettle: throwingSettle,
      settlementResolver: async () => {
        throw new Error('rpc down')
      },
    })
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    await rail.submitPayment(invoice.invoice_id, _payload())
    const after = await rail.checkStatus(invoice.invoice_id)
    assert.equal(after.status, 'settlement_unknown')
  })

  it('a manual resolution wins over a resolver answer that arrives later', async () => {
    let release: (v: { settled: false; reason: string }) => void = () => {}
    const pendingLookup = new Promise<{ settled: false; reason: string }>((r) => { release = r })
    const rail = createX402Rail({
      payTo: PAY_TO,
      asset: USDC_BASE_MAINNET,
      network: 'base',
      resource: 'https://example.com/r',
      facilitatorVerify: alwaysVerify(),
      facilitatorSettle: throwingSettle,
      settlementResolver: async () => pendingLookup,
    })
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    await rail.submitPayment(invoice.invoice_id, _payload())

    const poll = rail.checkStatus(invoice.invoice_id)
    await new Promise((r) => setImmediate(r))
    rail.resolveSettlement(invoice.invoice_id, { settled: true, transaction: TX_HASH, payer: PAYER })
    release({ settled: false, reason: 'stale_lookup' })
    const polled = await poll

    assert.equal(polled.status, 'confirmed')
    const after = await rail.checkStatus(invoice.invoice_id)
    assert.equal(after.status, 'confirmed')
    assert.equal((await rail.verifyTransaction(TX_HASH, '1000000')).verified, true)
  })

  it('two overlapping polls: the first definite answer stands', async () => {
    const releases: Array<(v: { settled: true; transaction: string; payer: string } | { settled: false; reason: string }) => void> = []
    const rail = createX402Rail({
      payTo: PAY_TO,
      asset: USDC_BASE_MAINNET,
      network: 'base',
      resource: 'https://example.com/r',
      facilitatorVerify: alwaysVerify(),
      facilitatorSettle: throwingSettle,
      settlementResolver: () => new Promise((r) => { releases.push(r) }),
    })
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    await rail.submitPayment(invoice.invoice_id, _payload())

    const a = rail.checkStatus(invoice.invoice_id)
    const b = rail.checkStatus(invoice.invoice_id)
    await new Promise((r) => setImmediate(r))
    assert.equal(releases.length, 2)
    releases[1]({ settled: true, transaction: TX_HASH, payer: PAYER })
    assert.equal((await b).status, 'confirmed')
    releases[0]({ settled: false, reason: 'stale_lookup' })
    assert.equal((await a).status, 'confirmed')
    assert.equal((await rail.checkStatus(invoice.invoice_id)).status, 'confirmed')
  })

  it('a resolution cannot attribute a transaction that belongs to another invoice', async () => {
    // first invoice settles with TX_HASH, the second on the same rail ends unknown
    let fail = true
    const rail2 = _rail({
      settle: async () => {
        if (fail) throw new Error('socket hang up')
        return { success: true, payer: PAYER, transaction: TX_HASH, network: 'base' }
      },
    })
    const first = await rail2.createInvoice({ amount_base_units: '1000000' })
    fail = false
    await rail2.submitPayment(first.invoice_id, _payload())
    fail = true
    const second = await rail2.createInvoice({ amount_base_units: '1000000' })
    await rail2.submitPayment(second.invoice_id, _payload())

    assert.throws(
      () => rail2.resolveSettlement(second.invoice_id, { settled: true, transaction: TX_HASH, payer: PAYER }),
      /transaction_already_attributed/,
    )
    assert.equal((await rail2.checkStatus(second.invoice_id)).status, 'settlement_unknown')
    const v = await rail2.verifyTransaction(TX_HASH, '1000000')
    assert.equal(v.verified, true)
    assert.equal((await rail2.checkStatus(first.invoice_id)).status, 'confirmed')
  })

  it('two successful settle answers with the same transaction: the second stays unknown', async () => {
    const rail = _rail()
    const a = await rail.createInvoice({ amount_base_units: '1000000' })
    const b = await rail.createInvoice({ amount_base_units: '2000000' })
    const first = await rail.submitPayment(a.invoice_id, _payload())
    const second = await rail.submitPayment(b.invoice_id, _payload())

    assert.equal(first.settlement, 'settled')
    assert.equal(second.settlement, 'unknown')
    assert.equal(second.settled, undefined)
    assert.match(second.settleErrorReason ?? '', /^transaction_already_attributed: /)
    assert.equal((await rail.checkStatus(a.invoice_id)).status, 'confirmed')
    const bAfter = await rail.checkStatus(b.invoice_id)
    assert.equal(bAfter.status, 'settlement_unknown')
    assert.equal(bAfter.metadata?.reported_tx_hash, TX_HASH)
    assert.equal((await rail.verifyTransaction(TX_HASH, '1000000')).verified, true)
    assert.equal((await rail.verifyTransaction(TX_HASH, '2000000')).verified, false)
    await assert.rejects(rail.submitPayment(b.invoice_id, _payload()), /not pending/)
  })

  it('a successful settle answer without a transaction stays unknown', async () => {
    const rail = _rail({ settle: alwaysSettle('') })
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    const outcome = await rail.submitPayment(invoice.invoice_id, _payload())
    assert.equal(outcome.settlement, 'unknown')
    assert.equal(outcome.settleErrorReason, 'settle_success_without_transaction')
    assert.equal((await rail.checkStatus(invoice.invoice_id)).status, 'settlement_unknown')
  })

  it('the same hash in a different letter case is the same transaction', async () => {
    const lower = '0x' + 'ab'.repeat(32)
    const upper = '0x' + 'AB'.repeat(32)
    let n = 0
    const rail = _rail({
      settle: async () => ({ success: true, payer: PAYER, transaction: n++ === 0 ? lower : upper, network: 'base' }),
    })
    const a = await rail.createInvoice({ amount_base_units: '1000000' })
    const b = await rail.createInvoice({ amount_base_units: '2000000' })
    const first = await rail.submitPayment(a.invoice_id, _payload())
    const second = await rail.submitPayment(b.invoice_id, _payload())

    assert.equal(first.settlement, 'settled')
    assert.equal(first.transaction, lower)
    assert.equal(second.settlement, 'unknown')
    assert.match(second.settleErrorReason ?? '', /^transaction_already_attributed: /)
    assert.equal((await rail.checkStatus(b.invoice_id)).status, 'settlement_unknown')
    assert.equal((await rail.verifyTransaction(upper, '1000000')).verified, true)
    assert.equal((await rail.verifyTransaction(lower, '1000000')).verified, true)
    assert.equal((await rail.verifyTransaction(upper, '2000000')).verified, false)
    assert.throws(
      () => rail.resolveSettlement(b.invoice_id, { settled: true, transaction: upper, payer: PAYER }),
      /transaction_already_attributed/,
    )
  })

  it('a success answer with a missing or unusable transaction field stays unknown', async () => {
    const answers: unknown[] = [undefined, null, '   ', '0x1234', 'not-a-hash', 42]
    for (const value of answers) {
      const rail = _rail({
        settle: async () =>
          ({ success: true, payer: PAYER, transaction: value, network: 'base' }) as unknown as X402SettleResponse,
      })
      const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
      const outcome = await rail.submitPayment(invoice.invoice_id, _payload())
      assert.equal(outcome.settlement, 'unknown', `value ${String(value)}`)
      assert.equal(outcome.settled, undefined)
      assert.match(outcome.settleErrorReason ?? '', /^settle_success_(without|with_unusable)_transaction$/)
      assert.equal((await rail.checkStatus(invoice.invoice_id)).status, 'settlement_unknown')
    }
  })

  it('resolveSettlement refuses an unusable transaction value', async () => {
    const rail = _rail({ settle: throwingSettle })
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    await rail.submitPayment(invoice.invoice_id, _payload())
    assert.throws(
      () => rail.resolveSettlement(invoice.invoice_id, { settled: true, transaction: '0xabc', payer: PAYER }),
      /settle_success_with_unusable_transaction/,
    )
    assert.equal((await rail.checkStatus(invoice.invoice_id)).status, 'settlement_unknown')
  })

  it('resolveSettlement refuses a settled resolution without a transaction', async () => {
    const rail = _rail({ settle: throwingSettle })
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    await rail.submitPayment(invoice.invoice_id, _payload())
    assert.throws(
      () => rail.resolveSettlement(invoice.invoice_id, { settled: true, transaction: '', payer: PAYER }),
      /settle_success_without_transaction/,
    )
    assert.equal((await rail.checkStatus(invoice.invoice_id)).status, 'settlement_unknown')
  })

  it('an invoice with a settlement in flight is not reported expired', async () => {
    let release: () => void = () => {}
    const gate = new Promise<void>((r) => { release = r })
    const rail = _rail({
      settle: async () => {
        await gate
        return { success: true, payer: PAYER, transaction: TX_HASH, network: 'base' }
      },
    })
    const invoice = await rail.createInvoice({ amount_base_units: '1000000', expires_in_seconds: 1 })
    const submitting = rail.submitPayment(invoice.invoice_id, _payload())
    await new Promise((r) => setTimeout(r, 1100))

    const during = await rail.checkStatus(invoice.invoice_id)
    assert.equal(during.status, 'pending')
    release()
    const outcome = await submitting
    assert.equal(outcome.settlement, 'settled')
    assert.equal((await rail.checkStatus(invoice.invoice_id)).status, 'confirmed')
  })

  it('the outcome names each settlement result', async () => {
    const settledRail = _rail()
    const i1 = await settledRail.createInvoice({ amount_base_units: '1000000' })
    assert.equal((await settledRail.submitPayment(i1.invoice_id, _payload())).settlement, 'settled')

    const refusedRail = _rail({ settle: neverSettle('insufficient_funds') })
    const i2 = await refusedRail.createInvoice({ amount_base_units: '1000000' })
    assert.equal((await refusedRail.submitPayment(i2.invoice_id, _payload())).settlement, 'refused')

    const unknownRail = _rail({ settle: throwingSettle })
    const i3 = await unknownRail.createInvoice({ amount_base_units: '1000000' })
    assert.equal((await unknownRail.submitPayment(i3.invoice_id, _payload())).settlement, 'unknown')

    const invalidRail = _rail({ verify: neverVerify('expired_authorization') })
    const i4 = await invalidRail.createInvoice({ amount_base_units: '1000000' })
    assert.equal((await invalidRail.submitPayment(i4.invoice_id, _payload())).settlement, 'not_attempted')
  })

  it('a definite settle refusal is still a failure', async () => {
    const rail = _rail({ settle: neverSettle('insufficient_funds') })
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    const outcome = await rail.submitPayment(invoice.invoice_id, _payload())
    assert.equal(outcome.settled, false)
    assert.equal(outcome.settlementUnknown, undefined)
    const after = await rail.checkStatus(invoice.invoice_id)
    assert.equal(after.status, 'failed')
  })
})

// ── submitPayment verify-fail → denial ────────────────────────────

describe('X402PaymentRail — submitPayment failure → rail_error denial', () => {
  it('verify-fail produces invalidReason, no settle attempted', async () => {
    let settleCalls = 0
    const rail = createX402Rail({
      payTo: PAY_TO,
      asset: USDC_BASE_MAINNET,
      network: 'base',
      resource: 'https://example.com/r',
      facilitatorVerify: neverVerify('invalid_signature'),
      facilitatorSettle: async () => {
        settleCalls += 1
        return alwaysSettle()()
      },
    })
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    const outcome = await rail.submitPayment(invoice.invoice_id, _payload())

    assert.equal(outcome.verified, false)
    assert.equal(outcome.invalidReason, 'invalid_signature')
    assert.equal(settleCalls, 0)

    const after = await rail.checkStatus(invoice.invoice_id)
    assert.equal(after.status, 'failed')
  })

  it('verify-fail caller emits PaymentDenial with rail_error + invalidReason detail', async () => {
    const rail = _rail({ verify: neverVerify('expired_authorization') })
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    const outcome = await rail.submitPayment(invoice.invoice_id, _payload())

    assert.equal(outcome.verified, false)
    const denial = emitDenial(
      {
        delegation_ref: _delegation().receipt_id,
        action_ref: 'a'.repeat(64),
        rail_name: rail.name,
        amount_base_units: invoice.amount_base_units,
        currency: invoice.currency,
        denial_reason: 'rail_error',
        reason_detail: `facilitator: ${outcome.invalidReason}`,
      },
      ISSUER_PRIV,
    )

    assert.equal(denial.denial_reason, 'rail_error')
    assert.match(denial.reason_detail ?? '', /expired_authorization/)
    assert.equal(verifyPaymentDenial(denial).valid, true)
  })

  it('settle-fail (verify ok) reports settleErrorReason; invoice marked failed', async () => {
    const rail = _rail({ settle: neverSettle('insufficient_funds') })
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    const outcome = await rail.submitPayment(invoice.invoice_id, _payload())

    assert.equal(outcome.verified, true)
    assert.equal(outcome.settled, false)
    assert.equal(outcome.settleErrorReason, 'insufficient_funds')

    const after = await rail.checkStatus(invoice.invoice_id)
    assert.equal(after.status, 'failed')
  })

  it('facilitator throws → outcome carries threw-prefix; invoice failed', async () => {
    const rail = createX402Rail({
      payTo: PAY_TO,
      asset: USDC_BASE_MAINNET,
      network: 'base',
      resource: 'https://example.com/r',
      facilitatorVerify: async () => {
        throw new Error('connect ECONNREFUSED')
      },
      facilitatorSettle: alwaysSettle(),
    })
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    const outcome = await rail.submitPayment(invoice.invoice_id, _payload())

    assert.equal(outcome.verified, false)
    assert.match(outcome.invalidReason ?? '', /facilitator_verify_threw/)
    assert.match(outcome.invalidReason ?? '', /ECONNREFUSED/)
  })
})

// ── preAuthorize gating ───────────────────────────────────────────

describe('X402PaymentRail — preAuthorize gates spend before submitPayment', () => {
  it('no_commerce_scope when delegation lacks commerce.purchase', () => {
    const rail = _rail()
    const result = preAuthorize(
      {
        delegation: _delegation({ scope: ['commerce.refund'] }),
        required_scope: 'commerce.purchase',
        amount_base_units: '1000000',
        currency: 'USDC',
      },
      rail,
    )
    assert.equal(result.ok, false)
    if (result.ok) return
    assert.equal(result.denial_reason, 'no_commerce_scope')
  })

  it('spend_limit_exceeded when amount > delegation budget', () => {
    const rail = _rail()
    const result = preAuthorize(
      {
        delegation: _delegation({ spend_limit_base_units: '500000' }), // 0.5 USDC
        required_scope: 'commerce.purchase',
        amount_base_units: '1000000', // 1 USDC
        currency: 'USDC',
      },
      rail,
    )
    assert.equal(result.ok, false)
    if (result.ok) return
    assert.equal(result.denial_reason, 'spend_limit_exceeded')
  })

  it('caller emits signed PaymentDenial when preAuth fails', () => {
    const rail = _rail()
    const result = preAuthorize(
      {
        delegation: _delegation({ scope: [] }),
        required_scope: 'commerce.purchase',
        amount_base_units: '1000000',
        currency: 'USDC',
      },
      rail,
    )
    assert.equal(result.ok, false)
    if (result.ok) return

    const denial = emitDenial(
      {
        delegation_ref: _delegation().receipt_id,
        action_ref: 'a'.repeat(64),
        rail_name: rail.name,
        amount_base_units: '1000000',
        currency: 'USDC',
        denial_reason: result.denial_reason,
        reason_detail: result.reason_detail,
      },
      ISSUER_PRIV,
    )
    assert.equal(denial.denial_reason, 'no_commerce_scope')
    assert.equal(verifyPaymentDenial(denial).valid, true)
  })
})

// ── revokeWallet ──────────────────────────────────────────────────

describe('X402PaymentRail — revokeWallet halts subsequent authorization', () => {
  it('preAuthorize denies wallet_revoked after revokeWallet', async () => {
    const rail = _rail()
    await rail.revokeWallet('wallet-x402-001')
    assert.equal(rail.isWalletRevoked('wallet-x402-001'), true)

    const result = preAuthorize(
      {
        delegation: _delegation(),
        required_scope: 'commerce.purchase',
        amount_base_units: '1000000',
        currency: 'USDC',
      },
      rail,
    )
    assert.equal(result.ok, false)
    if (result.ok) return
    assert.equal(result.denial_reason, 'wallet_revoked')
  })

  it('createInvoice still succeeds after revoke, but caller MUST gate via preAuth', async () => {
    // The rail's createInvoice intentionally does not consult the
    // revocation set — it just builds a request object. The
    // governance gate lives at preAuthorize. This test pins that
    // separation: revoking does not break invoice creation; it
    // breaks the pre-auth pipeline that wraps it.
    const rail = _rail()
    await rail.revokeWallet('wallet-x402-001')
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    assert.equal(invoice.status, 'pending')
  })

  it('revokeWallet is idempotent', async () => {
    const rail = _rail()
    assert.equal(await rail.revokeWallet('w1'), true)
    assert.equal(await rail.revokeWallet('w1'), true)
    assert.equal(rail.isWalletRevoked('w1'), true)
  })
})

// ── verifyTransaction ─────────────────────────────────────────────

describe('X402PaymentRail — verifyTransaction', () => {
  it('resolves a settled tx hash to the cached invoice state', async () => {
    const rail = _rail()
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    await rail.submitPayment(invoice.invoice_id, _payload())

    const result = await rail.verifyTransaction(TX_HASH, '1000000')
    assert.equal(result.verified, true)
    assert.equal(result.amount_base_units, '1000000')
    assert.equal(result.sender, PAYER)
    assert.equal(result.receiver, PAY_TO)
  })

  it('returns verified=false for unknown tx hash', async () => {
    const rail = _rail()
    const result = await rail.verifyTransaction('0xdeadbeef', '1000000')
    assert.equal(result.verified, false)
    assert.match(result.error ?? '', /not associated/)
  })

  it('returns verified=false on amount mismatch even when tx is known', async () => {
    const rail = _rail()
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    await rail.submitPayment(invoice.invoice_id, _payload())

    const result = await rail.verifyTransaction(TX_HASH, '999999')
    assert.equal(result.verified, false)
  })
})

// ── sendPayment unsupported ───────────────────────────────────────

describe('X402PaymentRail — sendPayment unsupported', () => {
  it('throws with a clear message that x402 is pull-only', async () => {
    const rail = _rail()
    await assert.rejects(
      () =>
        rail.sendPayment({
          destination: PAY_TO,
          amount_base_units: '1000000',
        }),
      /x402 rail does not support sendPayment/,
    )
  })
})

// ── Receipt + denial canonicalize round-trip ──────────────────────

describe('X402PaymentRail — signed receipt/denial round-trip', () => {
  it('PaymentReceipt round-trips canonicalize+verify', () => {
    const receipt = emitReceipt(
      {
        delegation_ref: 'd'.repeat(64),
        action_ref: 'a'.repeat(64),
        rail_name: 'x402-base-USDC',
        amount_base_units: '1000000',
        currency: 'USDC',
        tx_proof: TX_HASH,
        invoice_id: 'inv-x402-roundtrip',
      },
      ISSUER_PRIV,
    )
    assert.equal(verifyPaymentReceipt(receipt).valid, true)

    const tampered = { ...receipt, tx_proof: '0xdeadbeef' }
    assert.equal(verifyPaymentReceipt(tampered).valid, false)
  })

  it('PaymentDenial round-trips canonicalize+verify', () => {
    const denial = emitDenial(
      {
        delegation_ref: 'd'.repeat(64),
        action_ref: 'a'.repeat(64),
        rail_name: 'x402-base-USDC',
        amount_base_units: '1000000',
        currency: 'USDC',
        denial_reason: 'rail_error',
        reason_detail: 'facilitator: invalid_signature',
      },
      ISSUER_PRIV,
    )
    assert.equal(verifyPaymentDenial(denial).valid, true)

    const tampered = { ...denial, reason_detail: 'tampered' }
    assert.equal(verifyPaymentDenial(tampered).valid, false)
  })
})

// ── Fixture byte-parity ───────────────────────────────────────────

describe('X402PaymentRail — fixture byte-parity', () => {
  it('settled-receipt fixture verifies', () => {
    const text = readFileSync(join(FIXTURE_DIR, 'settled-receipt.fixture.json'), 'utf8')
    const receipt: PaymentReceipt = JSON.parse(text)
    assert.equal(verifyPaymentReceipt(receipt).valid, true)
    assert.equal(receipt.rail_name, 'x402-base-USDC')
    assert.equal(receipt.currency, 'USDC')
  })

  it('denied-receipt fixture verifies', () => {
    const text = readFileSync(join(FIXTURE_DIR, 'denied-receipt.fixture.json'), 'utf8')
    const denial: PaymentDenial = JSON.parse(text)
    assert.equal(verifyPaymentDenial(denial).valid, true)
    assert.equal(denial.denial_reason, 'rail_error')
  })

  it('payment-requirements fixture parses with required v1 fields', () => {
    const text = readFileSync(
      join(FIXTURE_DIR, 'payment-requirements.fixture.json'),
      'utf8',
    )
    const req = JSON.parse(text)
    assert.equal(req.scheme, 'exact')
    assert.equal(req.network, 'base')
    assert.equal(typeof req.maxAmountRequired, 'string')
    assert.equal(typeof req.maxTimeoutSeconds, 'number')
  })

  it('payment-payload fixture parses with required v1 envelope + EIP-3009 fields', () => {
    const text = readFileSync(join(FIXTURE_DIR, 'payment-payload.fixture.json'), 'utf8')
    const p: X402PaymentPayload = JSON.parse(text)
    assert.equal(p.x402Version, X402_VERSION)
    assert.equal(p.scheme, 'exact')
    assert.equal(p.network, 'base')
    const inner = p.payload as { signature: string; authorization: EIP3009Authorization }
    assert.match(inner.signature, /^0x[0-9a-fA-F]+$/)
    assert.match(inner.authorization.from, /^0x/)
    assert.match(inner.authorization.to, /^0x/)
    assert.equal(typeof inner.authorization.value, 'string')
    assert.equal(typeof inner.authorization.validAfter, 'string')
    assert.equal(typeof inner.authorization.validBefore, 'string')
    assert.match(inner.authorization.nonce, /^0x/)
  })
})

// ── Default exports / pinned constants ────────────────────────────

describe('X402PaymentRail — default constants', () => {
  it('exports the Coinbase CDP facilitator URL pin', () => {
    assert.equal(DEFAULT_FACILITATOR_URL, 'https://api.cdp.coinbase.com/platform/v2/x402')
  })

  it('exports USDC contract addresses for Base mainnet and Sepolia', () => {
    assert.equal(USDC_BASE_MAINNET, '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913')
  })
})

// ── Attempt store (issue #273) ────────────────────────────────────

/** A store that keeps records as JSON text, the way a database row or
 *  a file would, so a test fails if the rail depends on object
 *  identity surviving storage. `log` records the order of calls. */
function memoryStore(log: string[] = []) {
  const open = new Map<string, string>()
  const closed = new Map<string, X402AttemptOutcome>()
  let failRecord = false
  let failClose = false
  const store: X402AttemptStore = {
    async recordAttempt(attempt: X402SettlementAttempt) {
      log.push('record')
      if (failRecord) throw new Error('disk full')
      open.set(attempt.invoiceId, JSON.stringify(attempt))
    },
    async closeAttempt(invoiceId: string, outcome: X402AttemptOutcome) {
      log.push('close')
      if (failClose) throw new Error('store offline')
      open.delete(invoiceId)
      closed.set(invoiceId, outcome)
    },
    async listOpenAttempts() {
      return [...open.values()].map((t) => JSON.parse(t) as X402SettlementAttempt)
    },
  }
  return {
    store,
    open,
    closed,
    failRecord: (v: boolean) => { failRecord = v },
    failClose: (v: boolean) => { failClose = v },
  }
}

function storeRail(
  store: X402AttemptStore,
  extra: Partial<Parameters<typeof createX402Rail>[0]> = {},
): X402PaymentRail {
  return createX402Rail({
    payTo: PAY_TO,
    asset: USDC_BASE_MAINNET,
    network: 'base',
    resource: 'https://example.com/r',
    facilitatorVerify: alwaysVerify(),
    facilitatorSettle: alwaysSettle(),
    attemptStore: store,
    ...extra,
  })
}

/** A rail with a store that has completed its startup recovery. */
async function readyRail(
  store: X402AttemptStore,
  extra: Partial<Parameters<typeof createX402Rail>[0]> = {},
): Promise<X402PaymentRail> {
  const rail = storeRail(store, extra)
  await rail.recoverOpenAttempts()
  return rail
}

describe('X402PaymentRail — attempt store', () => {
  it('records the attempt after verify and before the settle call', async () => {
    const log: string[] = []
    const m = memoryStore(log)
    const rail = await readyRail(m.store, {
      facilitatorVerify: async () => { log.push('verify'); return { isValid: true, payer: PAYER } },
      facilitatorSettle: async () => {
        log.push('settle')
        assert.equal(m.open.size, 1, 'the record is stored before settle runs')
        return { success: true, payer: PAYER, transaction: TX_HASH, network: 'base' }
      },
    })
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    const out = await rail.submitPayment(invoice.invoice_id, _payload())
    assert.equal(out.settlement, 'settled')
    assert.deepEqual(log, ['verify', 'record', 'settle', 'close'])
    assert.equal(m.open.size, 0)
    assert.deepEqual(m.closed.get(invoice.invoice_id), {
      status: 'confirmed',
      transaction: TX_HASH,
      payer: PAYER,
    })
  })

  it('does not record an attempt when verify fails', async () => {
    const log: string[] = []
    const m = memoryStore(log)
    const rail = await readyRail(m.store, { facilitatorVerify: neverVerify() })
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    await rail.submitPayment(invoice.invoice_id, _payload())
    assert.deepEqual(log, [])
  })

  it('does not call settle when the record cannot be stored, and the invoice stays pending', async () => {
    const m = memoryStore()
    let settleCalls = 0
    const rail = await readyRail(m.store, {
      facilitatorSettle: async () => {
        settleCalls++
        return { success: true, payer: PAYER, transaction: TX_HASH, network: 'base' }
      },
    })
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    m.failRecord(true)
    await assert.rejects(
      rail.submitPayment(invoice.invoice_id, _payload()),
      /could not be recorded \(disk full\); settle was not called/,
    )
    assert.equal(settleCalls, 0)
    assert.equal((await rail.checkStatus(invoice.invoice_id)).status, 'pending')

    // The same invoice can be submitted again once the store works.
    m.failRecord(false)
    const out = await rail.submitPayment(invoice.invoice_id, _payload())
    assert.equal(out.settlement, 'settled')
    assert.equal(settleCalls, 1)
  })

  it('closes the attempt as failed when the facilitator refuses', async () => {
    const m = memoryStore()
    const rail = await readyRail(m.store, { facilitatorSettle: neverSettle('insufficient_funds') })
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    await rail.submitPayment(invoice.invoice_id, _payload())
    assert.equal(m.open.size, 0)
    assert.deepEqual(m.closed.get(invoice.invoice_id), {
      status: 'failed',
      reason: 'insufficient_funds',
    })
  })

  it('leaves the attempt open when the settle result is unknown', async () => {
    const m = memoryStore()
    const rail = await readyRail(m.store, {
      facilitatorSettle: async () => { throw new Error('socket hang up') },
    })
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    const out = await rail.submitPayment(invoice.invoice_id, _payload())
    assert.equal(out.settlement, 'unknown')
    assert.equal(m.open.size, 1)
    assert.equal(m.closed.size, 0)
  })

  it('a second instance recovers an attempt whose process stopped during settle', async () => {
    const m = memoryStore()
    // First process: the settle call never returns, as when the process
    // is killed while the request is on the wire.
    const first = await readyRail(m.store, { facilitatorSettle: () => new Promise(() => {}) })
    const invoice = await first.createInvoice({ amount_base_units: '1000000', memo: 'order 7' })
    void first.submitPayment(invoice.invoice_id, _payload())
    await new Promise((r) => setImmediate(r))
    assert.equal(m.open.size, 1)

    // Second process: same store, empty memory, a resolver that knows
    // the payment settled.
    let settleCalls = 0
    let asked: { invoiceId: string; payer: string } | undefined
    const second = storeRail(m.store, {
      facilitatorSettle: async () => {
        settleCalls++
        return { success: true, payer: PAYER, transaction: TX_HASH, network: 'base' }
      },
      settlementResolver: async (q) => {
        asked = { invoiceId: q.invoiceId, payer: q.paymentPayload.payload.authorization.from }
        return { settled: true, transaction: TX_HASH, payer: PAYER }
      },
    })
    await assert.rejects(second.checkStatus(invoice.invoice_id), /not found/)

    const recovered = await second.recoverOpenAttempts()
    assert.deepEqual(recovered, [invoice.invoice_id])
    assert.equal(settleCalls, 0, 'recovery makes no settle call')
    await assert.rejects(
      second.submitPayment(invoice.invoice_id, _payload()),
      /not pending \(status=settlement_unknown\)/,
    )

    const after = await second.checkStatus(invoice.invoice_id)
    assert.equal(after.status, 'confirmed')
    assert.equal(after.memo, 'order 7')
    assert.equal(after.metadata?.settlement_attempt_recovered, true)
    assert.deepEqual(asked, { invoiceId: invoice.invoice_id, payer: PAYER })
    assert.equal(settleCalls, 0)
    assert.equal(m.open.size, 0)
    const verified = await second.verifyTransaction(TX_HASH, '1000000')
    assert.equal(verified.verified, true)
  })

  it('a recovered attempt with no resolver stays unknown until resolveSettlement', async () => {
    const m = memoryStore()
    const first = await readyRail(m.store, { facilitatorSettle: () => new Promise(() => {}) })
    const invoice = await first.createInvoice({ amount_base_units: '1000000' })
    void first.submitPayment(invoice.invoice_id, _payload())
    await new Promise((r) => setImmediate(r))

    const second = storeRail(m.store)
    await second.recoverOpenAttempts()
    assert.equal((await second.checkStatus(invoice.invoice_id)).status, 'settlement_unknown')
    const resolved = second.resolveSettlement(invoice.invoice_id, { settled: false, reason: 'authorization_expired' })
    assert.equal(resolved.status, 'failed')
    assert.deepEqual(m.closed.get(invoice.invoice_id), {
      status: 'failed',
      reason: 'authorization_expired',
    })
    assert.equal(m.open.size, 0)
  })

  it('recovery skips invoices this instance already knows and can run twice', async () => {
    const m = memoryStore()
    const rail = await readyRail(m.store, {
      facilitatorSettle: async () => { throw new Error('timeout') },
    })
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    await rail.submitPayment(invoice.invoice_id, _payload())
    assert.deepEqual(await rail.recoverOpenAttempts(), [])

    const second = storeRail(m.store)
    assert.deepEqual(await second.recoverOpenAttempts(), [invoice.invoice_id])
    assert.deepEqual(await second.recoverOpenAttempts(), [])
  })

  it('a store that fails on close leaves the result in place and the attempt open', async () => {
    const m = memoryStore()
    m.failClose(true)
    const rail = await readyRail(m.store)
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    const out = await rail.submitPayment(invoice.invoice_id, _payload())
    assert.equal(out.settlement, 'settled')
    await new Promise((r) => setImmediate(r))
    const after = await rail.checkStatus(invoice.invoice_id)
    assert.equal(after.status, 'confirmed')
    assert.equal(after.metadata?.settlement_attempt_close_error, 'store offline')
    assert.equal(m.open.size, 1)
  })

  it('settle and the stored record carry the payload verify saw, even if the caller changes it during the store write', async () => {
    let releaseWrite: () => void = () => {}
    const stored: X402SettlementAttempt[] = []
    const slow: X402AttemptStore = {
      recordAttempt(attempt) {
        stored.push(JSON.parse(JSON.stringify(attempt)) as X402SettlementAttempt)
        return new Promise<void>((r) => { releaseWrite = r })
      },
      async closeAttempt() {},
      async listOpenAttempts() { return stored },
    }
    const seen: Record<string, string> = {}
    const rail = await readyRail(slow, {
      facilitatorVerify: async (req) => {
        seen.verify = req.paymentPayload.payload.authorization.nonce
        return { isValid: true, payer: PAYER }
      },
      facilitatorSettle: async (req) => {
        seen.settle = req.paymentPayload.payload.authorization.nonce
        throw new Error('timeout')
      },
    })
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    const original = '0x' + 'a'.repeat(64)
    const callerPayload = _payload({
      payload: { signature: '0x' + '2'.repeat(130), authorization: _authorization({ nonce: original }) },
    })
    const pending = rail.submitPayment(invoice.invoice_id, callerPayload)
    // Wait until the store write is pending, then change the caller's object.
    for (let i = 0; stored.length === 0; i++) {
      assert.ok(i < 1000, 'the store write never started')
      await new Promise((r) => setImmediate(r))
    }
    callerPayload.payload.authorization.nonce = '0x' + 'b'.repeat(64)
    callerPayload.payload.authorization.value = '999999999'
    releaseWrite()
    const out = await pending
    assert.equal(out.settlement, 'unknown')
    assert.equal(seen.verify, original)
    assert.equal(seen.settle, original)
    assert.equal(stored[0]!.paymentPayload.payload.authorization.nonce, original)

    // After a restart the resolver is asked about the authorization that was sent.
    let askedNonce = ''
    let askedValue = ''
    const second = storeRail(slow, {
      settlementResolver: async (q) => {
        askedNonce = q.paymentPayload.payload.authorization.nonce
        askedValue = q.paymentPayload.payload.authorization.value
        return undefined
      },
    })
    await second.recoverOpenAttempts()
    await second.checkStatus(invoice.invoice_id)
    assert.equal(askedNonce, original)
    assert.equal(askedValue, '1000000')
  })

  it('a facilitator that changes the request it was given does not change what settle sends', async () => {
    const m = memoryStore()
    let settleNonce = ''
    let settlePayTo = ''
    const rail = await readyRail(m.store, {
      facilitatorVerify: async (req) => {
        req.paymentPayload.payload.authorization.nonce = '0x' + 'c'.repeat(64)
        req.paymentRequirements.payTo = '0x' + 'd'.repeat(40)
        return { isValid: true, payer: PAYER }
      },
      facilitatorSettle: async (req) => {
        settleNonce = req.paymentPayload.payload.authorization.nonce
        settlePayTo = req.paymentRequirements.payTo
        return { success: true, payer: PAYER, transaction: TX_HASH, network: 'base' }
      },
    })
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    const original = '0x' + 'a'.repeat(64)
    await rail.submitPayment(
      invoice.invoice_id,
      _payload({ payload: { signature: '0x' + '2'.repeat(130), authorization: _authorization({ nonce: original }) } }),
    )
    assert.equal(settleNonce, original)
    assert.equal(settlePayTo, PAY_TO)
    assert.equal(rail.getRequirements(invoice.invoice_id)?.payTo, PAY_TO)
  })

  it('refuses a stored record that is not a settlement attempt', async () => {
    const bad: X402AttemptStore = {
      async recordAttempt() {},
      async closeAttempt() {},
      async listOpenAttempts() {
        return [{ invoiceId: 'x' } as unknown as X402SettlementAttempt]
      },
    }
    const rail = storeRail(bad)
    await assert.rejects(rail.recoverOpenAttempts(), /not a settlement attempt/)
  })

  it('with a store, submitPayment is refused until recoverOpenAttempts has completed', async () => {
    const m = memoryStore()
    let settleCalls = 0
    const rail = storeRail(m.store, {
      facilitatorSettle: async () => {
        settleCalls++
        return { success: true, payer: PAYER, transaction: TX_HASH, network: 'base' }
      },
    })
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    await assert.rejects(
      rail.submitPayment(invoice.invoice_id, _payload()),
      /recoverOpenAttempts\(\) has not completed/,
    )
    assert.equal(settleCalls, 0)
    assert.equal((await rail.checkStatus(invoice.invoice_id)).status, 'pending')
    await rail.recoverOpenAttempts()
    assert.equal((await rail.submitPayment(invoice.invoice_id, _payload())).settlement, 'settled')
  })

  it('a recovery that fails keeps submitPayment refused', async () => {
    let listFails = true
    const m = memoryStore()
    const flaky: X402AttemptStore = {
      recordAttempt: (a) => m.store.recordAttempt(a),
      closeAttempt: (id, o) => m.store.closeAttempt(id, o),
      async listOpenAttempts() {
        if (listFails) throw new Error('store unreachable')
        return m.store.listOpenAttempts()
      },
    }
    const rail = storeRail(flaky)
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    await assert.rejects(rail.recoverOpenAttempts(), /store unreachable/)
    await assert.rejects(
      rail.submitPayment(invoice.invoice_id, _payload()),
      /recoverOpenAttempts\(\) has not completed/,
    )
    listFails = false
    await rail.recoverOpenAttempts()
    assert.equal((await rail.submitPayment(invoice.invoice_id, _payload())).settlement, 'settled')
  })

  it('a write that is stored and then rejects: the retry replaces the record and recovery returns what was sent', async () => {
    const m = memoryStore()
    let loseAck = true
    const lossy: X402AttemptStore = {
      async recordAttempt(a) {
        await m.store.recordAttempt(a)
        if (loseAck) throw new Error('acknowledgement lost')
      },
      closeAttempt: (id, o) => m.store.closeAttempt(id, o),
      listOpenAttempts: () => m.store.listOpenAttempts(),
    }
    let settleNonce = ''
    const rail = await readyRail(lossy, {
      facilitatorSettle: async (req) => {
        settleNonce = req.paymentPayload.payload.authorization.nonce
        throw new Error('timeout')
      },
    })
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    const nonceA = '0x' + 'a'.repeat(64)
    const nonceB = '0x' + 'b'.repeat(64)
    const withNonce = (nonce: string) =>
      _payload({ payload: { signature: '0x' + '2'.repeat(130), authorization: _authorization({ nonce }) } })

    await assert.rejects(rail.submitPayment(invoice.invoice_id, withNonce(nonceA)), /could not be recorded/)
    assert.equal(settleNonce, '', 'settle was not called for the first write')
    assert.equal(m.open.size, 1, 'the first record was stored')

    loseAck = false
    const out = await rail.submitPayment(invoice.invoice_id, withNonce(nonceB))
    assert.equal(out.settlement, 'unknown')
    assert.equal(settleNonce, nonceB)
    assert.equal(m.open.size, 1, 'one open record per invoice')

    let askedNonce = ''
    const second = storeRail(lossy, {
      settlementResolver: async (q) => {
        askedNonce = q.paymentPayload.payload.authorization.nonce
        return undefined
      },
    })
    assert.deepEqual(await second.recoverOpenAttempts(), [invoice.invoice_id])
    await second.checkStatus(invoice.invoice_id)
    assert.equal(askedNonce, nonceB)
  })

  it('a stored record whose settle was never sent is recovered as unknown and blocks a new submit', async () => {
    const m = memoryStore()
    const lossy: X402AttemptStore = {
      async recordAttempt(a) {
        await m.store.recordAttempt(a)
        throw new Error('acknowledgement lost')
      },
      closeAttempt: (id, o) => m.store.closeAttempt(id, o),
      listOpenAttempts: () => m.store.listOpenAttempts(),
    }
    const first = await readyRail(lossy)
    const invoice = await first.createInvoice({ amount_base_units: '1000000' })
    await assert.rejects(first.submitPayment(invoice.invoice_id, _payload()), /could not be recorded/)

    const second = storeRail(m.store)
    await second.recoverOpenAttempts()
    assert.equal((await second.checkStatus(invoice.invoice_id)).status, 'settlement_unknown')
    await assert.rejects(second.submitPayment(invoice.invoice_id, _payload()), /not pending/)
    second.resolveSettlement(invoice.invoice_id, { settled: false, reason: 'never_sent' })
    assert.equal(m.open.size, 0)
  })

  it('recovery refuses inconsistent records, loads nothing, and keeps submitPayment refused', async () => {
    const m = memoryStore()
    const src = await readyRail(m.store, { facilitatorSettle: async () => { throw new Error('timeout') } })
    const invoice = await src.createInvoice({ amount_base_units: '1000000' })
    const other = await src.createInvoice({ amount_base_units: '1000000' })
    await src.submitPayment(invoice.invoice_id, _payload())
    const good = (await m.store.listOpenAttempts())[0]!
    const clone = (): X402SettlementAttempt => JSON.parse(JSON.stringify(good)) as X402SettlementAttempt

    const cases: Array<[string, X402SettlementAttempt[], RegExp]> = []
    const wrongId = clone(); wrongId.invoiceId = other.invoice_id
    cases.push(['invoice id mismatch', [wrongId], /invoice\.invoice_id does not match invoiceId/])
    const noNonce = clone()
    delete (noNonce.paymentPayload.payload.authorization as Partial<EIP3009Authorization>).nonce
    cases.push(['missing nonce', [noNonce], /authorization\.nonce missing/])
    const badTime = clone(); badTime.startedAt = 'yesterday'
    cases.push(['bad timestamp', [badTime], /startedAt is not a timestamp/])
    const noPayTo = clone()
    delete (noPayTo.paymentRequirements as Partial<typeof noPayTo.paymentRequirements>).payTo
    cases.push(['missing payTo', [noPayTo], /paymentRequirements\.payTo missing/])
    const conflicting = clone()
    conflicting.paymentPayload.payload.authorization.nonce = '0x' + 'f'.repeat(64)
    cases.push(['conflicting duplicates', [clone(), conflicting], /two different open records/])
    // A bad record after a good one: the good one is not loaded either.
    cases.push(['good then bad', [clone(), badTime], /startedAt is not a timestamp/])

    for (const [name, records, pattern] of cases) {
      const store: X402AttemptStore = {
        async recordAttempt() {},
        async closeAttempt() {},
        async listOpenAttempts() { return records },
      }
      const rail = storeRail(store)
      await assert.rejects(rail.recoverOpenAttempts(), pattern, name)
      await assert.rejects(rail.checkStatus(invoice.invoice_id), /not found/, `${name}: nothing loaded`)
      const fresh = await rail.createInvoice({ amount_base_units: '1000000' })
      await assert.rejects(
        rail.submitPayment(fresh.invoice_id, _payload()),
        /recoverOpenAttempts\(\) has not completed/,
        `${name}: submit stays refused`,
      )
    }

    // The same record twice is one attempt.
    const dup: X402AttemptStore = {
      async recordAttempt() {},
      async closeAttempt() {},
      async listOpenAttempts() { return [clone(), clone()] },
    }
    assert.deepEqual(await storeRail(dup).recoverOpenAttempts(), [invoice.invoice_id])
  })

  it('changing the object getRequirements returned does not change what is settled or reconciled', async () => {
    let releaseWrite: () => void = () => {}
    let writing = false
    const m = memoryStore()
    const slow: X402AttemptStore = {
      async recordAttempt(a) {
        await m.store.recordAttempt(a)
        writing = true
        await new Promise<void>((r) => { releaseWrite = r })
      },
      closeAttempt: (id, o) => m.store.closeAttempt(id, o),
      listOpenAttempts: () => m.store.listOpenAttempts(),
    }
    let settlePayTo = ''
    const asked: string[] = []
    const rail = await readyRail(slow, {
      facilitatorSettle: async (req) => {
        settlePayTo = req.paymentRequirements.payTo
        throw new Error('timeout')
      },
      settlementResolver: async (q) => {
        asked.push(`${q.paymentRequirements.payTo}|${q.paymentPayload.payload.authorization.nonce}`)
        // A resolver that changes what it was given.
        q.paymentRequirements.payTo = '0x' + 'e'.repeat(40)
        q.paymentPayload.payload.authorization.nonce = '0x' + 'e'.repeat(64)
        return undefined
      },
    })
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    const attacker = '0x' + 'd'.repeat(40)

    // Before submit.
    rail.getRequirements(invoice.invoice_id)!.payTo = attacker
    const pending = rail.submitPayment(invoice.invoice_id, _payload())
    for (let i = 0; !writing; i++) {
      assert.ok(i < 1000, 'the store write never started')
      await new Promise((r) => setImmediate(r))
    }
    // While the store write is pending.
    rail.getRequirements(invoice.invoice_id)!.payTo = attacker
    releaseWrite()
    await pending

    assert.equal(settlePayTo, PAY_TO)
    await rail.checkStatus(invoice.invoice_id)
    await rail.checkStatus(invoice.invoice_id)
    const expected = `${PAY_TO}|${_authorization().nonce}`
    assert.deepEqual(asked, [expected, expected])
    assert.equal(rail.getRequirements(invoice.invoice_id)?.payTo, PAY_TO)
  })

  it('without a store, recoverOpenAttempts returns nothing and submitPayment is unchanged', async () => {
    const rail = _rail()
    assert.deepEqual(await rail.recoverOpenAttempts(), [])
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    const out = await rail.submitPayment(invoice.invoice_id, _payload())
    assert.equal(out.settlement, 'settled')
  })
})
