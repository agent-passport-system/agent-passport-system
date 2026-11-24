// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// x402 payment rail — public reference adapter (Base + USDC)
// ══════════════════════════════════════════════════════════════════
// Implements PaymentRail over the x402 v1 protocol on Base mainnet
// with USDC as the asset. Settlement runs through a caller-supplied
// facilitator (the Coinbase CDP facilitator at
// https://api.cdp.coinbase.com/platform/v2/x402, or any compatible
// implementation).
//
// Flow:
//   1. createInvoice(opts) builds an X402PaymentRequirements suitable
//      for the resource server's 402 response body and caches it.
//   2. The resource server returns the requirements to the client.
//   3. The client signs an EIP-3009 transferWithAuthorization, sends
//      back the X-PAYMENT header carrying an X402PaymentPayload.
//   4. The resource server passes (invoice_id, payload) to
//      submitPayment(); the rail calls facilitator /verify, then
//      /settle, then resolves the X402SubmitOutcome.
//   5. Caller switches on X402SubmitOutcome.settlement:
//      - 'settled': emit a signed APS PaymentReceipt with tx_proof set
//        to X402SubmitOutcome.transaction (the on-chain tx hash).
//      - 'not_attempted' or 'refused': emit a signed PaymentDenial with
//        denial_reason 'rail_error' and reason_detail carrying the
//        facilitator's invalidReason or errorReason.
//      - 'unknown': the payment may have settled. Emit neither a
//        receipt nor a denial, keep any budget reservation, issue no
//        replacement invoice, and resolve the result with
//        resolveSettlement() or the configured settlementResolver.
//
// Rail does NOT:
//   - Sign EIP-3009 authorizations (sender does that off-chain)
//   - Submit on-chain transactions directly (facilitator does at /settle)
//   - Send outbound payments (sendPayment throws UnsupportedOperation —
//     x402 is a pull protocol from the resource server's perspective)
//   - Implement the HTTP transport (X-PAYMENT header encoding, base64
//     framing). Resource servers wire that themselves; the rail
//     produces and consumes the schema-typed bodies.
// ══════════════════════════════════════════════════════════════════

import { randomUUID } from 'node:crypto'
import type {
  CreateInvoiceOpts,
  PaymentInvoice,
  PaymentRail,
  SendPaymentOpts,
  VerifyTransactionResult,
} from '../types.js'
import {
  X402_VERSION,
  type X402Network,
  type X402PaymentPayload,
  type X402PaymentRequirements,
  type X402Scheme,
  type X402SettleRequest,
  type X402SettleResponse,
  type X402SettlementResolution,
  type X402SubmitOutcome,
  type X402VerifyRequest,
  type X402VerifyResponse,
} from './types.js'

// ── Caller-injected facilitator I/O ───────────────────────────────

/** Caller wraps the facilitator HTTP /verify call. */
export type FacilitatorVerify = (
  req: X402VerifyRequest,
) => Promise<X402VerifyResponse>

/** Caller wraps the facilitator HTTP /settle call.
 *
 *  Contract the rail relies on: return `success: false` only when the
 *  facilitator answered that it did not settle and will not settle
 *  this payment. When the result is not known (timeout, dropped
 *  connection, 5xx, an answer that cannot be parsed), throw. The rail
 *  then keeps the invoice in `settlement_unknown`. An adapter that
 *  maps a timeout to `success: false` makes the rail record a failure
 *  for a payment that may have settled. */
export type FacilitatorSettle = (
  req: X402SettleRequest,
) => Promise<X402SettleResponse>

// ── Configuration ─────────────────────────────────────────────────

export type SettlementResolver = (query: {
  invoiceId: string
  paymentPayload: X402PaymentPayload
  paymentRequirements: X402PaymentRequirements
}) => Promise<X402SettlementResolution | undefined>

/** One settlement attempt as an attempt store keeps it. It holds what a
 *  restarted process needs to rebuild the invoice in
 *  `settlement_unknown` and to ask a resolver about it. */
export interface X402SettlementAttempt {
  invoiceId: string
  /** The invoice as it was when the attempt started. */
  invoice: PaymentInvoice
  paymentRequirements: X402PaymentRequirements
  paymentPayload: X402PaymentPayload
  startedAt: string
}

/** The definite result that closes a recorded attempt. */
export type X402AttemptOutcome =
  | { status: 'confirmed'; transaction: string; payer: string }
  | { status: 'failed'; reason: string }

/** Caller-supplied storage for settlement attempts. The rail keeps its
 *  state in memory, so without a store a process that stops during a
 *  settle call leaves no record that the call was made.
 *
 *  What a store must guarantee:
 *  - One open record per invoice id. `recordAttempt` for an invoice id
 *    that already has an open record replaces that record as a whole.
 *    A write can be stored and still reject, for example when the
 *    acknowledgement is lost, and the rail then writes again for the
 *    same invoice, possibly with a different payload.
 *  - Once `recordAttempt` resolves, `listOpenAttempts` returns exactly
 *    the record that was passed in, until it is closed.
 *
 *  The record holds a signed payment authorization that a facilitator
 *  can still execute until it expires. Keep it out of logs, restrict
 *  who can read the store, and delete closed records when your
 *  retention rules allow. */
export interface X402AttemptStore {
  /** Called after verify and before the settle request is sent. The
   *  record must be stored when the promise resolves. If it rejects,
   *  the rail does not call settle. */
  recordAttempt(attempt: X402SettlementAttempt): Promise<void>
  /** Called when the invoice reaches `confirmed` or `failed`. An attempt
   *  whose result is unknown is not closed. */
  closeAttempt(invoiceId: string, outcome: X402AttemptOutcome): Promise<void>
  /** Attempts that were recorded and not closed. */
  listOpenAttempts(): Promise<X402SettlementAttempt[]>
}

export interface X402RailConfig {
  /** Recipient wallet address used as PaymentRequirements.payTo. */
  payTo: string
  /** Token contract address (USDC by default). */
  asset: string
  /** Network identifier per x402 v1. */
  network: X402Network
  /** Default scheme. Currently only 'exact' is widely deployed. */
  scheme?: X402Scheme
  /** Default protected-resource URL. createInvoice can override per
   *  invoice via opts. */
  resource: string
  /** Default human-readable description. createInvoice can override. */
  description?: string
  /** Default maxTimeoutSeconds applied to every invoice unless
   *  the caller-supplied expires_in_seconds overrides it. */
  defaultMaxTimeoutSeconds?: number
  /** Optional currency code displayed in PaymentInvoice.amount_human
   *  and recorded on PaymentReceipt.currency. Defaults to 'USDC'. */
  currency?: string
  /** Decimals on the configured asset; used only to format
   *  amount_human. Defaults to 6 (USDC). The wire-level atomic units
   *  (maxAmountRequired, value) are always integer strings. */
  assetDecimals?: number
  /** Optional rail name override. Defaults to
   *  'x402-{network}-{currency}'. */
  name?: string
  /** Optional EIP-712 domain extra (passed through to PaymentRequirements.extra). */
  extra?: Record<string, unknown>
  /** Caller-supplied facilitator /verify implementation. */
  facilitatorVerify: FacilitatorVerify
  /** Caller-supplied facilitator /settle implementation. */
  facilitatorSettle: FacilitatorSettle
  /** Optional. Looks up the definite result of a settlement whose
   *  answer was lost. checkStatus calls it for an invoice in
   *  `settlement_unknown`. Return undefined while the result is still
   *  not known. */
  settlementResolver?: SettlementResolver
  /** Optional. Records each settlement attempt before the settle call,
   *  so `recoverOpenAttempts` can find attempts a stopped process left
   *  behind. With a store configured, `submitPayment` throws until
   *  `recoverOpenAttempts` has completed once on this instance. */
  attemptStore?: X402AttemptStore
}

// ── Cached invoice ────────────────────────────────────────────────

interface CachedInvoice extends PaymentInvoice {
  /** The X402PaymentRequirements served back to the client. */
  requirements: X402PaymentRequirements
  /** PaymentPayload received via submitPayment, when present. */
  receivedPayload?: X402PaymentPayload
  /** The requirements that went to the facilitator with that payload.
   *  Together they are the attempt a resolver is asked about. */
  submittedRequirements?: X402PaymentRequirements
  /** Settle response, when settled. */
  settled?: X402SettleResponse
}

// ── Rail ──────────────────────────────────────────────────────────

export class X402PaymentRail implements PaymentRail {
  readonly name: string
  readonly currency: string

  private readonly config: X402RailConfig
  private readonly invoices = new Map<string, CachedInvoice>()
  /** Tx hash → invoice id, populated on settle. Lets verifyTransaction
   *  resolve a previously-settled invoice from a tx hash. */
  private readonly txIndex = new Map<string, string>()
  private readonly revokedWallets = new Set<string>()
  /** Invoices with a submitPayment call between its pending check and
   *  its final status. A second concurrent call for the same invoice is
   *  refused, so verify and settle run at most once per invoice. */
  private readonly inFlight = new Set<string>()
  /** True once recoverOpenAttempts has completed on this instance. */
  private recoveryDone = false

  constructor(config: X402RailConfig) {
    this.config = config
    this.currency = config.currency ?? 'USDC'
    this.name = config.name ?? `x402-${config.network}-${this.currency}`
  }

  // ── PaymentRail surface ─────────────────────────────────────────

  async createInvoice(opts: CreateInvoiceOpts): Promise<PaymentInvoice> {
    const scheme = this.config.scheme ?? 'exact'
    const decimals = this.config.assetDecimals ?? 6
    const maxTimeoutSeconds =
      opts.expires_in_seconds ?? this.config.defaultMaxTimeoutSeconds ?? 60

    const requirements: X402PaymentRequirements = {
      scheme,
      network: this.config.network,
      maxAmountRequired: opts.amount_base_units,
      asset: this.config.asset,
      payTo: this.config.payTo,
      resource: this.config.resource,
      description: this.config.description ?? this.config.resource,
      maxTimeoutSeconds,
    }
    if (this.config.extra !== undefined) {
      requirements.extra = structuredClone(this.config.extra)
    }

    const invoiceId = randomUUID()
    const now = new Date()
    const expiresAt = new Date(now.getTime() + maxTimeoutSeconds * 1000).toISOString()

    const metadata: Record<string, unknown> = {
      // A copy for display. The rail verifies and settles against its
      // own `requirements`, which no public object refers to.
      x402_requirements: structuredClone(requirements),
      x402_version: X402_VERSION,
    }
    if (opts.settlement_id !== undefined) metadata.settlement_id = opts.settlement_id
    if (opts.agent_id !== undefined) metadata.agent_id = opts.agent_id

    const invoice: PaymentInvoice = {
      invoice_id: invoiceId,
      rail_name: this.name,
      amount_base_units: opts.amount_base_units,
      amount_human: `${_formatAtomic(opts.amount_base_units, decimals)} ${this.currency}`,
      currency: this.currency,
      destination: this.config.payTo,
      status: 'pending',
      created_at: now.toISOString(),
      expires_at: expiresAt,
      metadata,
    }
    if (opts.memo !== undefined) invoice.memo = opts.memo

    const cached: CachedInvoice = { ...invoice, requirements }
    this.invoices.set(invoiceId, cached)
    return _stripInternal(cached)
  }

  async checkStatus(invoiceId: string): Promise<PaymentInvoice> {
    const cached = this.invoices.get(invoiceId)
    if (cached === undefined) {
      throw new Error(`invoice ${invoiceId} not found in adapter cache`)
    }

    // A pending invoice with a submitPayment in progress is not expired:
    // its settlement can still complete.
    if (
      cached.status === 'pending' &&
      cached.expires_at !== undefined &&
      !this.inFlight.has(invoiceId)
    ) {
      if (new Date(cached.expires_at) < new Date()) {
        cached.status = 'expired'
        this.invoices.set(invoiceId, cached)
      }
    }

    // An unknown settlement never expires on its own. It stays unknown
    // until the resolver, or resolveSettlement, gives a definite result.
    if (
      cached.status === 'settlement_unknown' &&
      this.config.settlementResolver !== undefined &&
      cached.receivedPayload !== undefined
    ) {
      let resolution: X402SettlementResolution | undefined
      try {
        // Copies of the attempt that was submitted, on every lookup. A
        // resolver that changes what it is given changes only its copy.
        resolution = await this.config.settlementResolver({
          invoiceId,
          paymentPayload: structuredClone(cached.receivedPayload),
          paymentRequirements: structuredClone(
            cached.submittedRequirements ?? cached.requirements,
          ),
        })
      } catch {
        resolution = undefined
      }
      // The lookup ran while other calls could resolve this invoice.
      // _applyResolution rechecks the status, and the first result wins.
      const current = this.invoices.get(invoiceId)
      if (resolution !== undefined && current !== undefined) {
        try {
          this._applyResolution(invoiceId, current, resolution)
        } catch {
          // An answer that cannot be attributed leaves the invoice unknown.
        }
      }
      return _stripInternal(current ?? cached)
    }

    return _stripInternal(cached)
  }

  async verifyTransaction(
    txProof: string,
    expectedAmountBaseUnits?: string,
  ): Promise<VerifyTransactionResult> {
    // x402's facilitator /verify takes a PaymentPayload, not a tx hash;
    // the on-chain transaction itself comes from /settle. Verification
    // by tx hash here resolves the cached settled invoice and confirms
    // the tx hash matches.
    // Same normalization as attribution, so a hash verifies whatever
    // letter case the caller holds it in.
    const normalizedProof = _normalizeTxHash(txProof)
    const invoiceId = normalizedProof === undefined ? undefined : this.txIndex.get(normalizedProof)
    if (invoiceId === undefined) {
      return {
        verified: false,
        amount_base_units: '0',
        error: `tx ${txProof} not associated with any settled invoice on this rail`,
      }
    }
    const cached = this.invoices.get(invoiceId)
    if (cached === undefined || cached.settled === undefined) {
      return {
        verified: false,
        amount_base_units: '0',
        error: `invoice ${invoiceId} no longer cached or never settled`,
      }
    }

    let amountMatches = true
    if (expectedAmountBaseUnits !== undefined) {
      try {
        amountMatches =
          BigInt(cached.amount_base_units) === BigInt(expectedAmountBaseUnits)
      } catch {
        amountMatches = false
      }
    }

    return {
      verified: amountMatches && cached.settled.success,
      amount_base_units: cached.amount_base_units,
      sender: cached.settled.payer,
      // The recipient the facilitator was given for this settlement.
      receiver: (cached.submittedRequirements ?? cached.requirements).payTo,
      timestamp: cached.created_at,
    }
  }

  async revokeWallet(walletId: string): Promise<boolean> {
    this.revokedWallets.add(walletId)
    return true
  }

  isWalletRevoked(walletId: string): boolean {
    return this.revokedWallets.has(walletId)
  }

  // ── x402-specific extras ────────────────────────────────────────

  /** x402 is a pull protocol from the resource server's perspective:
   *  the server collects payment by serving 402 + requirements, then
   *  settling the client's signed authorization. There is no outbound
   *  send. Callers that try this on x402 are misusing the rail. */
  async sendPayment(_opts: SendPaymentOpts): Promise<never> {
    throw new Error(
      'x402 rail does not support sendPayment: the protocol settles ' +
        'client-signed EIP-3009 authorizations through the facilitator ' +
        '(pull). Use submitPayment(invoiceId, payload) on the resource ' +
        'server when an X-PAYMENT header arrives.',
    )
  }

  /**
   * Drive verify-then-settle for a PaymentPayload that arrived on
   * the resource server (decoded from X-PAYMENT). On success, the
   * cached invoice flips to 'confirmed' with the on-chain tx hash
   * recorded; the caller passes outcome.transaction to emitReceipt
   * as tx_proof. On verification failure, the invoice flips to
   * 'failed' and outcome.invalidReason carries the facilitator's
   * reason; caller passes that to emitDenial with denial_reason
   * 'rail_error'.
   *
   * The rail does not sign or emit APS receipts itself — that stays
   * the caller's responsibility, so the issuer key never leaves the
   * caller's process.
   */
  async submitPayment(
    invoiceId: string,
    payload: X402PaymentPayload,
  ): Promise<X402SubmitOutcome> {
    const cached = this.invoices.get(invoiceId)
    if (cached === undefined) {
      throw new Error(`invoice ${invoiceId} not found in adapter cache`)
    }
    if (this.config.attemptStore !== undefined && !this.recoveryDone) {
      throw new Error(
        'an attempt store is configured and recoverOpenAttempts() has not completed; ' +
          'submitPayment is refused until it has, so attempts a stopped process ' +
          'left behind are loaded before any new settlement',
      )
    }
    if (cached.status !== 'pending') {
      throw new Error(
        `invoice ${invoiceId} not pending (status=${cached.status}); ` +
          'submitPayment expects a fresh invoice',
      )
    }
    if (this.inFlight.has(invoiceId)) {
      throw new Error(
        `invoice ${invoiceId} already has a submitPayment in progress; ` +
          'submitPayment runs verify and settle at most once per invoice',
      )
    }
    this.inFlight.add(invoiceId)
    try {
      return await this._verifyAndSettle(invoiceId, cached, payload)
    } finally {
      this.inFlight.delete(invoiceId)
    }
  }

  private async _verifyAndSettle(
    invoiceId: string,
    cached: CachedInvoice,
    callerPayload: X402PaymentPayload,
  ): Promise<X402SubmitOutcome> {
    // Taken before the first await. The caller keeps its own object and
    // can change it while verify or the store write is pending, so the
    // rail works from its own copies. Verify, the stored record and
    // settle each get a separate copy of the same values, and none of
    // them can change what the others see.
    const payload = structuredClone(callerPayload)
    const requirements = structuredClone(cached.requirements)
    cached.submittedRequirements = requirements

    // Verify
    const verifyReq: X402VerifyRequest = {
      x402Version: X402_VERSION,
      paymentPayload: structuredClone(payload),
      paymentRequirements: structuredClone(requirements),
    }
    let verifyResp: X402VerifyResponse
    try {
      verifyResp = await this.config.facilitatorVerify(verifyReq)
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e)
      cached.status = 'failed'
      cached.receivedPayload = payload
      this.invoices.set(invoiceId, cached)
      return {
        verified: false,
        settlement: 'not_attempted',
        invalidReason: `facilitator_verify_threw: ${msg}`,
      }
    }
    if (!verifyResp.isValid) {
      cached.status = 'failed'
      cached.receivedPayload = payload
      this.invoices.set(invoiceId, cached)
      const out: X402SubmitOutcome = {
        verified: false,
        settlement: 'not_attempted',
        invalidReason: verifyResp.invalidReason ?? 'invalid_payment_payload',
      }
      if (verifyResp.payer !== undefined) out.payer = verifyResp.payer
      return out
    }

    // Record the attempt before the settle request leaves the process.
    // A store that cannot take the record stops the attempt here, with
    // the invoice still pending, because a settle call with no record
    // is the case the store exists to prevent.
    const store = this.config.attemptStore
    if (store !== undefined) {
      try {
        await store.recordAttempt({
          invoiceId,
          invoice: _stripInternal(cached),
          paymentRequirements: structuredClone(requirements),
          paymentPayload: structuredClone(payload),
          startedAt: new Date().toISOString(),
        })
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e)
        throw new Error(
          `invoice ${invoiceId}: the settlement attempt could not be recorded ` +
            `(${msg}); settle was not called and the invoice is still pending`,
        )
      }
    }

    // Settle
    const settleReq: X402SettleRequest = {
      x402Version: X402_VERSION,
      paymentPayload: structuredClone(payload),
      paymentRequirements: structuredClone(requirements),
    }
    let settleResp: X402SettleResponse
    try {
      settleResp = await this.config.facilitatorSettle(settleReq)
    } catch (e) {
      // The request may have reached the facilitator before the call
      // failed, so the payment may have settled. Not a failure.
      const msg = e instanceof Error ? e.message : String(e)
      cached.status = 'settlement_unknown'
      cached.receivedPayload = payload
      this.invoices.set(invoiceId, cached)
      const out: X402SubmitOutcome = {
        verified: true,
        settlement: 'unknown',
        settlementUnknown: true,
        settleErrorReason: `facilitator_settle_threw: ${msg}`,
      }
      if (verifyResp.payer !== undefined) out.payer = verifyResp.payer
      return out
    }

    if (!settleResp.success) {
      cached.status = 'failed'
      cached.receivedPayload = payload
      this.invoices.set(invoiceId, cached)
      this._closeAttempt(invoiceId, cached, {
        status: 'failed',
        reason: settleResp.errorReason ?? 'settlement_failed',
      })
      const out: X402SubmitOutcome = {
        verified: true,
        settlement: 'refused',
        settled: false,
        settleErrorReason: settleResp.errorReason ?? 'settlement_failed',
        payer: settleResp.payer,
      }
      return out
    }

    // The facilitator reports success. Confirm only when the transaction
    // it names can be attributed to this invoice. A missing transaction,
    // or one already attributed to another invoice, leaves the invoice
    // unresolved: money may have moved, so it is not a failure either.
    const attribution = this._attribute(settleResp.transaction, invoiceId)
    if ('problem' in attribution) {
      cached.status = 'settlement_unknown'
      cached.receivedPayload = payload
      cached.metadata = {
        ...cached.metadata,
        settlement_attribution_problem: attribution.problem,
        reported_tx_hash: settleResp.transaction ?? null,
        reported_payer: settleResp.payer,
      }
      this.invoices.set(invoiceId, cached)
      return {
        verified: true,
        settlement: 'unknown',
        settlementUnknown: true,
        settleErrorReason: attribution.problem,
        payer: settleResp.payer,
      }
    }
    const txHash = attribution.tx

    // Confirmed
    cached.status = 'confirmed'
    cached.receivedPayload = payload
    cached.settled = { ...settleResp, transaction: txHash }
    cached.metadata = {
      ...cached.metadata,
      tx_hash: txHash,
      payer: settleResp.payer,
      confirmed_at: new Date().toISOString(),
    }
    this.invoices.set(invoiceId, cached)
    this.txIndex.set(txHash, invoiceId)
    this._closeAttempt(invoiceId, cached, {
      status: 'confirmed',
      transaction: txHash,
      payer: settleResp.payer,
    })
    return {
      verified: true,
      settlement: 'settled',
      settled: true,
      transaction: txHash,
      payer: settleResp.payer,
    }
  }

  /** Records the definite result of a settlement that submitPayment
   *  left in `settlement_unknown`. The caller establishes the result
   *  from the facilitator or from the chain. Throws for an invoice in
   *  any other status, so a confirmed or failed invoice is never
   *  rewritten. */
  resolveSettlement(invoiceId: string, resolution: X402SettlementResolution): PaymentInvoice {
    const cached = this.invoices.get(invoiceId)
    if (cached === undefined) {
      throw new Error(`invoice ${invoiceId} not found in adapter cache`)
    }
    if (cached.status !== 'settlement_unknown') {
      throw new Error(
        `invoice ${invoiceId} is not in settlement_unknown (status=${cached.status})`,
      )
    }
    this._applyResolution(invoiceId, cached, resolution)
    return _stripInternal(cached)
  }

  /** Local transaction attribution. Returns the normalized hash when
   *  the reported transaction can be attributed to this invoice, or the
   *  reason it cannot. The value crosses a runtime boundary (an HTTP
   *  adapter), so its type is not trusted: it must be a 32-byte hex
   *  hash, and it is compared in lowercase. The rail keeps one invoice
   *  per transaction hash, and the first attribution stays. This does
   *  not check the chain. */
  private _attribute(tx: unknown, invoiceId: string): { tx: string } | { problem: string } {
    if (tx === undefined || tx === null || tx === '') {
      return { problem: 'settle_success_without_transaction' }
    }
    const normalized = _normalizeTxHash(tx)
    if (normalized === undefined) {
      return { problem: 'settle_success_with_unusable_transaction' }
    }
    const existing = this.txIndex.get(normalized)
    if (existing !== undefined && existing !== invoiceId) {
      return { problem: `transaction_already_attributed: ${normalized} belongs to invoice ${existing}` }
    }
    return { tx: normalized }
  }

  private _applyResolution(
    invoiceId: string,
    cached: CachedInvoice,
    resolution: X402SettlementResolution,
  ): void {
    // Checked here, at the write, because callers await before they get
    // here. An invoice that is no longer unknown is never rewritten.
    if (cached.status !== 'settlement_unknown') return
    if (resolution.settled) {
      const attribution = this._attribute(resolution.transaction, invoiceId)
      if ('problem' in attribution) {
        throw new Error(`cannot resolve invoice ${invoiceId} as settled: ${attribution.problem}`)
      }
      const txHash = attribution.tx
      cached.status = 'confirmed'
      cached.settled = {
        success: true,
        payer: resolution.payer,
        transaction: txHash,
        network: this.config.network,
      }
      cached.metadata = {
        ...cached.metadata,
        tx_hash: txHash,
        payer: resolution.payer,
        confirmed_at: new Date().toISOString(),
        settlement_resolved_after_unknown: true,
      }
      this.txIndex.set(txHash, invoiceId)
      this.invoices.set(invoiceId, cached)
      this._closeAttempt(invoiceId, cached, {
        status: 'confirmed',
        transaction: txHash,
        payer: resolution.payer,
      })
    } else {
      cached.status = 'failed'
      cached.metadata = {
        ...cached.metadata,
        settlement_resolved_after_unknown: true,
        settlement_failure_reason: resolution.reason,
      }
      this.invoices.set(invoiceId, cached)
      this._closeAttempt(invoiceId, cached, { status: 'failed', reason: resolution.reason })
    }
  }

  /** Tells the attempt store that an invoice has a definite result. The
   *  invoice status is already written when this runs. A store that
   *  fails here leaves the attempt open, and a later recovery then
   *  treats it as unknown and asks the resolver again, which is the
   *  safe direction. The failure is noted on the invoice. */
  private _closeAttempt(
    invoiceId: string,
    cached: CachedInvoice,
    outcome: X402AttemptOutcome,
  ): void {
    const store = this.config.attemptStore
    if (store === undefined) return
    const note = (e: unknown): void => {
      const msg = e instanceof Error ? e.message : String(e)
      cached.metadata = { ...cached.metadata, settlement_attempt_close_error: msg }
      this.invoices.set(invoiceId, cached)
    }
    try {
      store.closeAttempt(invoiceId, outcome).catch(note)
    } catch (e) {
      note(e)
    }
  }

  /** Loads the attempts the store holds open and that this instance
   *  does not know, and puts each invoice in `settlement_unknown`. Call
   *  it once at startup, before serving requests: with a store
   *  configured, submitPayment throws until this has completed. If it
   *  throws, nothing was loaded and submitPayment stays refused. It
   *  makes no settle call. checkStatus with a settlementResolver, or
   *  resolveSettlement, then gives each one its definite result.
   *  Returns the invoice ids it loaded. */
  async recoverOpenAttempts(): Promise<string[]> {
    const store = this.config.attemptStore
    if (store === undefined) return []
    const open = await store.listOpenAttempts()
    if (!Array.isArray(open)) {
      throw new Error('attempt store did not return a list of settlement attempts')
    }
    // Check every record before loading any, so a store with one bad
    // record loads nothing and submitPayment stays refused.
    const byInvoice = new Map<string, { attempt: X402SettlementAttempt; text: string }>()
    for (const attempt of open) {
      const problem = _attemptProblem(attempt)
      if (problem !== undefined) {
        throw new Error(`attempt store returned a record that is not a settlement attempt: ${problem}`)
      }
      const text = JSON.stringify(attempt)
      const seen = byInvoice.get(attempt.invoiceId)
      if (seen === undefined) {
        byInvoice.set(attempt.invoiceId, { attempt, text })
      } else if (seen.text !== text) {
        throw new Error(
          `attempt store returned two different open records for invoice ${attempt.invoiceId}`,
        )
      }
    }
    // Build every invoice first. Copying a record can throw, and a
    // recovery that throws must leave the live cache untouched.
    const built = new Map<string, CachedInvoice>()
    for (const { attempt } of byInvoice.values()) {
      if (this.invoices.has(attempt.invoiceId)) continue
      const requirements = structuredClone(attempt.paymentRequirements)
      built.set(attempt.invoiceId, {
        ...structuredClone(attempt.invoice),
        status: 'settlement_unknown',
        metadata: {
          ...structuredClone(attempt.invoice.metadata ?? {}),
          settlement_attempt_recovered: true,
          settlement_attempt_started_at: attempt.startedAt,
        },
        requirements,
        submittedRequirements: structuredClone(requirements),
        receivedPayload: structuredClone(attempt.paymentPayload),
      })
    }
    // Nothing below throws or awaits, so the cache changes as a whole.
    const recovered: string[] = []
    for (const [invoiceId, invoice] of built) {
      if (this.invoices.has(invoiceId)) continue
      this.invoices.set(invoiceId, invoice)
      recovered.push(invoiceId)
    }
    this.recoveryDone = true
    return recovered
  }

  /** Returns the X402PaymentRequirements cached for an invoice. Used
   *  by the resource server to assemble the 402 response body. */
  getRequirements(invoiceId: string): X402PaymentRequirements | undefined {
    // A copy: the caller serializes it into the 402 response, and a
    // change to the returned object must not change what the rail
    // verifies and settles against.
    const requirements = this.invoices.get(invoiceId)?.requirements
    return requirements === undefined ? undefined : structuredClone(requirements)
  }
}

// ── Helpers ───────────────────────────────────────────────────────

/** A 32-byte EVM transaction hash in lowercase, or undefined when the
 *  value is not one. The reference adapter settles EIP-3009 transfers
 *  on EVM networks only. */
function _normalizeTxHash(tx: unknown): string | undefined {
  if (typeof tx !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(tx)) return undefined
  return tx.toLowerCase()
}

/** The reason a stored record cannot be loaded as a settlement attempt,
 *  or undefined when it can. The store is trusted for content. This
 *  checks that the record is whole and refers to one invoice. */
function _attemptProblem(attempt: unknown): string | undefined {
  const isObj = (v: unknown): v is Record<string, unknown> =>
    v !== null && typeof v === 'object' && !Array.isArray(v)
  const isText = (v: unknown): v is string => typeof v === 'string' && v !== ''
  if (!isObj(attempt)) return 'not an object'
  if (!isText(attempt.invoiceId)) return 'invoiceId missing'
  const id = attempt.invoiceId
  if (!isObj(attempt.invoice)) return `invoice missing (${id})`
  if (attempt.invoice.invoice_id !== id) {
    return `invoice.invoice_id does not match invoiceId (${id})`
  }
  if (!isText(attempt.startedAt) || Number.isNaN(Date.parse(attempt.startedAt))) {
    return `startedAt is not a timestamp (${id})`
  }
  const req = attempt.paymentRequirements
  if (!isObj(req)) return `paymentRequirements missing (${id})`
  for (const k of ['scheme', 'network', 'maxAmountRequired', 'payTo', 'asset']) {
    if (!isText(req[k])) return `paymentRequirements.${k} missing (${id})`
  }
  const pay = attempt.paymentPayload
  if (!isObj(pay) || !isObj(pay.payload)) return `paymentPayload missing (${id})`
  if (!isText(pay.payload.signature)) return `paymentPayload signature missing (${id})`
  const auth = pay.payload.authorization
  if (!isObj(auth)) return `paymentPayload authorization missing (${id})`
  for (const k of ['from', 'to', 'value', 'validAfter', 'validBefore', 'nonce']) {
    if (!isText(auth[k])) return `authorization.${k} missing (${id})`
  }
  return undefined
}

function _stripInternal(c: CachedInvoice): PaymentInvoice {
  const {
    requirements: _r,
    receivedPayload: _p,
    submittedRequirements: _q,
    settled: _s,
    ...rest
  } = c
  // Detached: a caller that changes an invoice it was given, including
  // its metadata, does not change the rail's own state.
  return structuredClone(rest)
}

/** Format an atomic-units string as a decimal string with `decimals`
 *  fractional digits. Trailing zeros stripped. Used only for human
 *  display in PaymentInvoice.amount_human. */
function _formatAtomic(atomic: string, decimals: number): string {
  if (decimals <= 0) return atomic
  const big = BigInt(atomic)
  const div = BigInt(10) ** BigInt(decimals)
  const whole = big / div
  const frac = big % div
  if (frac === 0n) return whole.toString()
  const fracStr = frac.toString().padStart(decimals, '0').replace(/0+$/, '')
  return `${whole}.${fracStr}`
}

// ── Factory ───────────────────────────────────────────────────────

export function createX402Rail(config: X402RailConfig): X402PaymentRail {
  return new X402PaymentRail(config)
}

/** Coinbase CDP facilitator base URL, as documented in the CDP x402
 *  docs (verify, settle and supported live under this base). The CDP
 *  facilitator requires CDP API keys, so the caller wires the
 *  authorization headers inside their FacilitatorVerify /
 *  FacilitatorSettle implementations. For keyless testnet use, the
 *  x402.org facilitator is an alternative. The rail accepts any
 *  compatible facilitator URL. Pin it via the closure, do not embed
 *  it in the rail. This rail builds x402 version 1 payloads, and this
 *  constant does not by itself make the rail speak x402 version 2. */
export const DEFAULT_FACILITATOR_URL = 'https://api.cdp.coinbase.com/platform/v2/x402'

/** USDC contract on Base mainnet (eip155:8453). */
export const USDC_BASE_MAINNET = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'

/** USDC contract on Base Sepolia. */
export const USDC_BASE_SEPOLIA = '0x036CbD53842c5426634e7929541eC2318f3dCF7e'
