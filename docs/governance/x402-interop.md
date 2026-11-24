# x402 v1 interop

This module binds APS V2 governance to x402 — Coinbase's HTTP-native payments protocol that turns the long-dormant `402 Payment Required` status into a working machine-payments rail. The pin lives in `X402_VERSION = 1` (see `src/v2/payment-rails/x402/types.ts`). Bump it when the wire shapes change.

Reference: [github.com/coinbase/x402](https://github.com/coinbase/x402), `specs/x402-specification-v1.md`.

## What x402 is

x402 is a 402-challenge / EIP-3009-authorization / on-chain-settlement round-trip carried over HTTP. A resource server returns `402 Payment Required` with a body that lists one or more `PaymentRequirements` (scheme, network, asset, amount, payTo). The client signs an EIP-3009 `transferWithAuthorization` off-chain and resends the request with an `X-PAYMENT` header. A facilitator service `/verify`s the signature and `/settle`s the on-chain transfer; the resource server records the resulting transaction hash.

The deployed surface is narrow today: scheme `'exact'`, networks `base`/`base-sepolia` (plus a few additions per the open `X402Network` union), asset USDC. The protocol is forward-compatible with new schemes and assets via the open string union — new networks bolt on without an SDK upgrade.

## x402 vs other rails

x402 sits below the AP2/ACP/MPP layer. Where AP2 carries a mandate, ACP runs a checkout session, and MPP is method-agnostic at the HTTP-auth layer, x402 commits to a specific settlement substrate (EIP-3009 stablecoin transfer through a facilitator). It is the chain-rooted leaf in the rails stack — useful when the resource server wants the strongest possible audit trail (an actual on-chain tx) at the cost of locking in to EVM + facilitator trust.

APS treats x402 like any other binding rail: gate the requirements against a delegation, sign the receipt over the settled transaction. The crosswalk is narrower than MPP's because x402's wire shape exposes fewer governance hooks.

## Boundary

This adapter binds APS V2 governance at the rail surface:

- **Invoice creation** (`createInvoice`): build an `X402PaymentRequirements` valid as a 402 response body. Caches it under an invoice id so the resource server can reassemble the wire body.
- **Verify-then-settle** (`submitPayment`): drive the facilitator `/verify` and `/settle` calls in sequence; flip the cached invoice to `confirmed`, `failed` or `settlement_unknown`; return an `X402SubmitOutcome` for caller-side receipt or denial minting. Switch on `outcome.settlement` (`settled`, `refused`, `unknown`, `not_attempted`). `unknown` means the settle call threw and the payment may have settled: mint no denial, release no budget reservation and issue no replacement invoice until `resolveSettlement` or the configured `settlementResolver` gives a definite result. The facilitator adapter must throw when it does not know the result and return `success: false` only for a definite refusal. Invoice state is in memory, so an attempt in progress is lost on restart.
- **Wallet revocation** (`revokeWallet`): tracks revoked wallet ids in-memory.

The adapter does NOT run the facilitator, sign EIP-3009 authorizations, submit on-chain transactions, implement the X-PAYMENT header transport, or persist invoice state. Those are caller and facilitator responsibilities.

## Surface

```ts
createX402Rail(config)                                 // → X402PaymentRail
rail.createInvoice(opts)                               // → PaymentInvoice
rail.checkStatus(invoiceId)                            // → PaymentInvoice
rail.submitPayment(invoiceId, payload)                 // → X402SubmitOutcome
rail.verifyTransaction(txHash, expectedAmount?)        // → VerifyTransactionResult
rail.revokeWallet(walletId)                            // → boolean
rail.getRequirements(invoiceId)                        // → X402PaymentRequirements | undefined
```

Constants exposed for grounding: `DEFAULT_FACILITATOR_URL` (Coinbase CDP facilitator base URL, requires CDP API keys), `USDC_BASE_MAINNET`, `USDC_BASE_SEPOLIA`.

## V2Delegation → x402 crosswalk

x402 has no native authorization envelope analogous to AP2 mandates or MPP allowed-methods — `PaymentRequirements` is a server-issued amount-and-recipient quote. The crosswalk is therefore minimal: the rail maps a delegation's spend cap into the per-invoice `maxAmountRequired`, and the caller is responsible for clamping `createInvoice({ amount_base_units })` to whatever cap `resolveSpendLimitCents(delegation)` reports.

| APS `V2Delegation` field | x402 surface | Notes |
|---|---|---|
| `scope.action_categories` | gate input — caller checks for `'commerce'` / `'commerce.payment'` before invoice mint | not enforced inside the rail; gating is caller responsibility |
| `scope.resource_limits.spend_limit_cents` (number) | invoice `amount_base_units` cap | tier-1: canonical numeric (resolver default) |
| `scope.resource_limits['commerce.spend_limit']` (number) | invoice `amount_base_units` cap | tier-2: AP2-mandate alias, honored via `resolveSpendLimitCents` |
| `scope.constraints.spend_limit_cents` (string) | invoice `amount_base_units` cap | tier-3: string fallback, parsed via `Number()` |
| `scope.constraints.allowed_currencies` (CSV) | rail-level check against `config.currency` | currency pinning lives in the rail config, not per-invoice |
| `policy_context.valid_until` (ISO 8601) | caller compares against invoice `expires_at` and `requirements.maxTimeoutSeconds` | rail does not auto-derive expiry from delegation |

`resolveSpendLimitCents` is the single source of truth — see `src/v2/payment-rails/scope-resolution.ts`. The same three-tier resolver chain is used by AP2, ACP, MPP, and Stripe-Issuing, so a delegation that satisfies one rail's cap satisfies x402's cap.

## Denial vocabulary

x402 inherits the foundation Tier-1 denial taxonomy (see `docs/governance/payment-rails-denial-vocabulary.md`): `delegation_expired`, `spend_limit_exceeded`, `currency_mismatch`, `wallet_revoked`, `rail_error`. There is no Tier-2 x402 extension yet — verify/settle failures surface as the foundation `rail_error` reason with the facilitator's `invalidReason` or `errorReason` echoed in `reason_detail`. If x402 grows its own first-class failure semantics (e.g. distinct `nonce_already_used` vs `insufficient_funds` taxonomies on the APS side), a Tier-2 extension lands here.

## Signing

Ed25519 over RFC 8785 JCS canonical bytes, identical to AP2 / ACP / MPP / Stripe-Issuing conventions. The rail itself does not sign APS receipts — `submitPayment` returns an `X402SubmitOutcome` and the caller mints the signed `PaymentReceipt` (with `tx_proof` set to `outcome.transaction`) or `PaymentDenial` (with `denial_reason: 'rail_error'`) so the issuer key never leaves the caller's process.

The wire-level x402 signature is the EIP-712 / EIP-3009 signature over the transfer authorization; that's a secp256k1 signature owned by the payer's wallet, orthogonal to the APS Ed25519 audit signature.

## Limitations

| Limitation | Why | Workaround |
|---|---|---|
| Settlement is asynchronous and facilitator-trusted | The rail returns success after `/settle` reports `success=true`, but on-chain finality lags. | Caller waits for chain finality before downstream actions that depend on irreversibility. |
| Single facilitator per rail instance | `config.facilitatorVerify` / `config.facilitatorSettle` are pinned at construction; no automatic failover. | Caller wraps multiple facilitators with their own routing/fallback inside the closures. |
| In-memory invoice cache | Invoice → requirements lookup is `Map`-based and process-local. | Gateway product swaps in a persistent store; the SDK reference adapter is single-process. |
| `sendPayment` is unsupported | x402 is a pull protocol from the resource server's perspective. | Outbound payments use a different rail (nano, MPP, etc.); calling `sendPayment` throws. |
| No native multi-network policy | The rail is pinned to a single `network` per instance. | Construct one rail per network and route at the gateway layer. |
| EIP-3009 signature shape is fixed | Only the `'exact'` scheme is wired. | New schemes (`upto`, etc., when standardized) require an `X402_VERSION` bump and a scheme dispatch in `submitPayment`. |

## Pinned version

```ts
export const X402_VERSION = 1 as const
```

Defined in `src/v2/payment-rails/x402/types.ts`. Carried into every `X402VerifyRequest` / `X402SettleRequest` and into the fixture `META.json` (`x402_version: 1`). Bump when the wire shapes change incompatibly.

## Out of scope

These all live in the private gateway integration layer or in community tooling.

- Facilitator implementation (`/verify` and `/settle` HTTP endpoints).
- On-chain settlement primitive (the rail talks to a facilitator; it does not broadcast transactions itself).
- Smart-wallet flows (ERC-4337 paymasters, session keys, batched settlement).
- X-PAYMENT header HTTP transport (base64 framing, encoding, decoding).
- EIP-3009 authorization signing (the payer's wallet does that off-chain).
- Multi-rail routing and cost optimization.
- Dispute, refund, and chargeback orchestration.
