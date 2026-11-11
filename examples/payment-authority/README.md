# Payment authority gateway

A person gives an agent permission to spend. The agent passes part of it to another
agent. A gateway checks every payment before it happens and refuses anything outside the
permission. For every request the agent signed, the gateway signs a record of its decision
that anyone with the public keys can check afterwards. When the person withdraws the
permission, the next payment is refused, including one already authorized but not yet sent.

This example builds that gateway from the public `agent-passport-system` 8.0.1 package.
It runs in one process with test keys and a mock payment executor. It moves no money.

## Run

```sh
cd examples/payment-authority
npm install
npm run demo      # the walkthrough below, writes signed records to out/
npm run verify    # checks out/receipts.json using only out/public-keys.json
npm test          # 17 cases
```

`npm run typecheck` needs the development dependencies (`npm install --include=dev` if
your environment sets `NODE_ENV=production`).

## What the demo shows

| Step | Outcome |
|---|---|
| A person gives Agent A $100 at one merchant, USD only, for one hour | issued |
| Agent A tries to give Agent B $150 | refused when it is issued, `SPEND_WIDENING` |
| Agent A gives Agent B $30 | issued |
| Agent B spends $40 | denied, `budget_per_action_exceeded` |
| Agent B spends $20 | paid |
| Agent B sends two $8 payments at the same moment with $10 left | one paid, one denied, `budget_cumulative_exceeded` |
| Agent A spends $75 after Agent B has spent $28 of the person's $100 | denied, `budget_cumulative_exceeded` |
| The person revokes Agent A's permission | recorded |
| Agent B tries to spend $5 | denied, `authority_invalid:REVOKED` |

Agent B's spending counts against the person's $100 as well as against its own $30,
because the gateway reserves every payment against every bounded delegation in the chain
at once. Revoking the person's grant to Agent A also ends Agent B's permission, because the
gateway checks revocation for every delegation in the chain.

## What the gateway checks, in order

A payment runs in two phases. `authorize()` decides and reserves. `dispatch()` admits the
approved action once and sends it to the executor. `pay()` runs both.

Authorization:

1. The action reference recomputes from the submitted request and payload.
2. The acting agent signed an `aps:action-intent:v1` record for that exact action. A request
   that fails here or at step 1 gets an unsigned refusal, because there is no verified
   request to bind a signed record to.
3. One nonce, one decision. The agent's nonce and timestamp are inside the action reference
   it signed. A request already decided gets its first decision back, a denial included,
   and the agent has to sign a new request to try again. A different action under a nonce
   already used is refused with `nonce_reused`. A request signed more than five minutes ago
   is refused with `intent_outside_replay_window`.
4. The delegation chain verifies at the current time: signatures, narrowing at each step,
   time windows and revocation. Anything other than `valid` is refused, including
   `indeterminate`, so a delegation the gateway cannot check is treated as not granted.
5. The merchant is covered by the leaf delegation's scope and the currency matches its
   spend unit.
6. The amount is reserved against the whole chain.
7. The gateway signs an `aps:policy-decision:v1` record, permit or deny, with the reason.

Authorization runs without awaiting anything, so two payments arriving together cannot
both pass against the same remaining budget.

Dispatch:

8. The approval is consumed. A second dispatch of the same action returns the first
   outcome and is never charged again.
9. The approval's `valid_until` and the whole chain, time and revocation included, are
   checked again. If either fails, the reservation is released and the gateway signs a
   failed `aps:action-result:v1` record with `admission_refused:<reason>`. The executor is
   not called.
10. Otherwise the reservation is marked dispatched, the executor is called, the reservation
    is committed on success and the gateway signs an `aps:action-result:v1` record.

## What a record proves and what it does not

`npm run verify` checks that each record is signed by the party it names, that the decision
binds the authority state, the policy input, the reason and the output it carries, and
that intent, decision and result follow each other. It shows what the gateway received,
what it decided and the reason it gave, under the gateway's key.

It does not show that a payment settled on any real rail. It does not show that the
gateway's budget counters were right, or that the gateway applied its checks honestly. A
record is evidence of a signed decision, not of the facts behind it.

## What comes from the SDK and what is written here

From `agent-passport-system` 8.0.1, unmodified: delegation issuance and chain verification
(`issueAuthorityDelegation`, `issueSubAuthorityDelegation`,
`verifyAuthorityDelegationChain`), the reference budget ledger
(`InMemoryAuthorityBudgetLedger`), revocation (`issueAuthorityRevocation`,
`InMemoryAuthorityRevocationStore`, `recordAuthorityRevocation`,
`createAuthorityRevocationResolver`), action references (`createActionReferenceInputV2`,
`computeActionRefV2`, `computePayloadRefV1`) and signed records (`createReceiptV1`,
`verifyReceiptV1`, `buildDecisionRefV1`, `verifyReceiptWithDecisionV1`).

Written for this example, in `gateway.ts`: the order of the checks, the mapping from a
payment to a scope grant, a target and a spend unit, the refusal reasons, the replay
handling and the call to the executor. The SDK records alone do not enforce any of this.
The enforcement point is the gateway.

## Limits

- Nonces are kept in memory and never pruned. A long-running gateway keeps each nonce for
  at least the five-minute replay window and can drop it after that.
- One process, in memory. The reference ledger is linearizable inside one JavaScript
  process. Several gateway instances need a shared store with the same all-ancestors
  atomic reservation.
- Revocation takes effect for the next request because the gateway that records it is the
  one that checks it. Gateways that learn about revocations from elsewhere need declared
  freshness rules, and this example does not define them.
- A charge that fails after it was sent to the executor stays reserved. The reference
  ledger allows cancellation only before dispatch, and this example adds no
  reconciliation step. When the executor does not answer, the result is recorded as
  `unknown` and the amount stays reserved, so a payment that may have gone through cannot
  be spent again.
- Payments need a bounded spend facet at the leaf. That is this gateway's policy and is
  stricter than the draft, which also permits `unbounded`.
- The target `https://pay.example/merchants/<merchant>/charges` and the grant
  `commerce:pay:<merchant>` are candidate profile text for this example. No published
  profile defines them.
- The 8.0.1 package root does not export the profile identifier constants
  (`aps:authority-delegation:v1`, `aps-hierarchical-v1` and the others), so `actors.ts`
  writes them out.
- No mapping to AP2 or ACP mandates is included.

## Cases

| Case | What it checks |
|---|---|
| P1 | The main path above, with every record checked by `verify.ts` |
| P2 | A sub-delegation wider than its parent in spend, scope or depth is refused when issued |
| P3 | Two simultaneous $8 payments against $10 remaining: exactly one is charged |
| P4 | A child's spending counts against its parent's budget |
| P5 | Another merchant, another currency and non-canonical amounts are refused |
| P6 | A repeated submission, also two at once, returns the first outcome and charges once |
| P7 | A changed payload, an intent signed with the wrong key and a borrowed chain are refused |
| P8 | A revocation not signed by the person who granted the authority is not recorded |
| P9 | A delegation the gateway has not enrolled, and an expired one, are refused |
| P10 | When the executor does not answer, the result is `unknown` and the amount stays reserved |
| P11 | An edited reason, an edited payload or the wrong gateway key fails verification |
| P12 | A second action signed with an already used nonce is refused, and the first decision stands |
| P13 | A request signed outside the replay window is refused |
| P14 | A denied request resubmitted gets the same signed denial, even after the cause is gone |
| P15 | A revocation between authorization and dispatch stops the payment and releases the reservation |
| P16 | An approval that waited past `valid_until` is not dispatched |
| P17 | Two dispatches of one approval charge once |
