// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Payment authority gateway: a reference enforcement boundary for agent payments.
//
// Built only from public agent-passport-system 8.0.1 exports and the shared engine in
// ../authority-engine. One process, in-memory state, test keys and a mock payment
// executor. It is a reference example, not a hosted service and not a production payment
// integration.
//
// The engine runs every payment in two phases.
//
// authorize(), synchronous, for every request:
//   1. recompute the action reference from the submitted request and payload
//   2. check the acting agent signed an aps:action-intent:v1 record for that action
//   3. check the agent's nonce: one nonce gets one decision, a nonce reused for a
//      different action is refused, and the request must fall inside the replay window
//   4. verify the whole delegation chain (signatures, narrowing, time, revocation) and
//      refuse anything that is not valid, including indeterminate
//   5. check the merchant is covered by the leaf delegation's scope and the currency
//      matches its spend unit
//   6. reserve the amount against every bounded delegation in the chain at once, so a
//      child's spending also counts against its parent's budget
//   7. sign an aps:policy-decision:v1 record, permit or deny
//
// dispatch(), for a permitted action, once:
//   8. consume the approval, so it can be used once only
//   9. recheck at admission that the approval has not reached valid_until, that the stored
//      request still recomputes to the approved action reference, and that the whole chain
//      is still valid (time and revocation). If any fails, release the reservation and
//      sign a failed aps:action-result:v1 record. Nothing is sent to the executor.
//  10. otherwise mark the reservation dispatched, call the executor, commit on success
//      and sign an aps:action-result:v1 record
//
// pay() runs both phases back to back.
//
// This file supplies the payment profile: what a payment payload is, its target, scope
// and spend unit, the refusal reasons, and the call to the payment executor.
//
// CANDIDATE PROFILE TEXT. draft-pidlisnyi-aps-04 section 5.1 says a profile defines its
// target string. For action_type "payment" this example uses
//   "https://pay.example/merchants/" + merchant + "/charges"
// and the scope grant "commerce:pay:" + merchant. No published profile defines either.

import { AuthorityGateway } from 'aps-example-authority-engine/engine.ts'
import type { ActionProfile, Outcome, Submission } from 'aps-example-authority-engine/engine.ts'
import type { AuthorityDelegationV1 } from 'agent-passport-system'

export { DECISION_TTL_MS, FUTURE_SKEW_MS, REPLAY_WINDOW_MS } from 'aps-example-authority-engine/engine.ts'
export type { DecisionEvidence } from 'aps-example-authority-engine/engine.ts'

export const PAYMENT_ACTION_TYPE = 'payment'
export const PAYMENT_PROFILE = 'aps-example-payment-authority-v0'
export const paymentTarget = (merchant: string): string => `https://pay.example/merchants/${merchant}/charges`
export const paymentScope = (merchant: string): string => `commerce:pay:${merchant}`
export const spendUnit = (currency: string): string => `iso4217:${currency}:minor`

const CANONICAL_POSITIVE_INTEGER = /^[1-9][0-9]*$/
const MERCHANT = /^[a-z0-9][a-z0-9-]{0,62}$/
const CURRENCY = /^[A-Z]{3}$/

export interface PaymentPayload {
  merchant: string
  /** Amount in minor units (cents for USD) as a canonical decimal string. */
  amount_minor: string
  currency: string
}

export type PaymentSubmission = Submission<PaymentPayload>

export type ExecutorResult =
  | { status: 'succeeded'; charge_id: string }
  | { status: 'failed'; error_code: string }

/** The payment rail. This example ships a mock; a real rail goes behind this call. */
export type PaymentExecutor = (charge: {
  action_ref: string
  merchant: string
  amount_minor: string
  currency: string
}) => Promise<ExecutorResult>

export type PaymentOutcome = Outcome

export interface GatewayOptions {
  /** The gateway's own identifier, the issuer of its decision and result records. */
  id: string
  keyId: string
  privateKey: string
  /** Receipt signer keys (agents, the gateway). */
  resolveReceiptKey: (signer: string, keyId: string, issuedAt: string) => string | undefined
  /** Delegation and revocation verification-method keys. */
  resolveVerificationKey: (issuer: string, verificationMethod: string, issuedAt: string) => string | null
  /** Which root delegations this gateway accepts, normally the person's own key. */
  trustRoot: (root: AuthorityDelegationV1) => boolean
  executor: PaymentExecutor
  /** Clock, injected so tests are deterministic. Exact UTC milliseconds. */
  now: () => string
  /** Currencies this gateway accepts. */
  currencies?: readonly string[]
}

/** The policy facts a decision records. The same shape whether or not the payload is valid. */
function paymentPolicyInput(payload: unknown) {
  const p = (payload ?? {}) as Partial<Record<keyof PaymentPayload, unknown>>
  return {
    merchant: String(p.merchant), amount_minor: String(p.amount_minor), currency: String(p.currency),
    unit: spendUnit(String(p.currency)),
  }
}

export function paymentProfile(opts: Pick<GatewayOptions, 'executor' | 'currencies'>): ActionProfile<PaymentPayload> {
  const accepted = opts.currencies ?? ['USD']
  return {
    id: PAYMENT_PROFILE,
    actionType: PAYMENT_ACTION_TYPE,
    validate: payload => {
      const { merchant, amount_minor: amount, currency } = (payload ?? {}) as Partial<PaymentPayload>
      if (typeof merchant !== 'string' || !MERCHANT.test(merchant)) return 'merchant_invalid'
      if (typeof amount !== 'string' || !CANONICAL_POSITIVE_INTEGER.test(amount)) return 'amount_not_canonical_positive_integer'
      if (typeof currency !== 'string' || !CURRENCY.test(currency)) return 'currency_invalid'
      if (!accepted.includes(currency)) return 'currency_not_accepted'
      return null
    },
    target: p => paymentTarget(p.merchant),
    scope: p => paymentScope(p.merchant),
    scopeDenyReason: 'merchant_not_in_scope',
    // A payment needs a bounded budget at the leaf. That is gateway policy, stricter than
    // the draft, which permits an unbounded spend facet. The engine refuses an unbounded
    // leaf for any profile that charges.
    charge: p => ({ unit: spendUnit(p.currency), amount: p.amount_minor }),
    unitDenyReason: 'currency_not_delegated',
    policyInput: paymentPolicyInput,
    policyInputUnvalidated: paymentPolicyInput,
    execute: async ({ action_ref, payload }) => {
      const { merchant, amount_minor, currency } = payload
      const r = await opts.executor({ action_ref, merchant, amount_minor, currency })
      return r.status === 'succeeded' ? { status: 'succeeded', effect_id: r.charge_id } : r
    },
  }
}

export class PaymentAuthorityGateway {
  readonly id: string
  private readonly engine: AuthorityGateway<PaymentPayload>

  constructor(opts: GatewayOptions) {
    this.id = opts.id
    this.engine = new AuthorityGateway(paymentProfile(opts), {
      id: opts.id,
      signingKey: () => ({ keyId: opts.keyId, privateKey: opts.privateKey }),
      resolveReceiptKey: opts.resolveReceiptKey,
      resolveVerificationKey: opts.resolveVerificationKey,
      trustRoot: opts.trustRoot,
      now: opts.now,
    })
  }

  /** Register delegations whose revocation status this gateway answers for. A delegation
   *  the gateway has not enrolled resolves as revocation-unknown and every payment under
   *  it is refused, because the gateway cannot say it was not revoked. */
  enroll(chain: readonly AuthorityDelegationV1[]): void { this.engine.enroll(chain) }

  /** Accept a signed revocation. Only a record that verifies against the target
   *  delegation's issuer is stored. It takes effect for every later authorization and
   *  for every authorized action not yet dispatched. */
  revoke(target: AuthorityDelegationV1, revocation: unknown): { recorded: boolean; reason?: string } {
    return this.engine.revoke(target, revocation)
  }

  /** Limit, reserved and committed budget for one delegation, in minor units. */
  budget(delegation: AuthorityDelegationV1): { limit: string; reserved: string; committed: string } | null {
    return this.engine.budget(delegation)
  }

  /** Authorize and, on permit, dispatch. */
  pay(sub: PaymentSubmission): Promise<PaymentOutcome> { return this.engine.request(sub) }

  /** Phase one. Synchronous from start to finish. */
  authorize(sub: PaymentSubmission): PaymentOutcome { return this.engine.authorize(sub) }

  /** Phase two. Consumes the approval for actionRef and runs it once. */
  dispatch(actionRef: string): Promise<PaymentOutcome> { return this.engine.dispatch(actionRef) }
}

