# Exact refund approval: candidate APS admission check

A candidate check for the refund workflow proposed in
[aeoess/agent-governance-vocabulary#193](https://github.com/aeoess/agent-governance-vocabulary/issues/193).
An operator approves one exact refund. A delegated worker submits a refund request. An execution service
admits the request only if it is exactly the approved one, the approval has not expired and the approval has
not been used before.

This is a local candidate. It has no operator, no PIC integration and no refund provider. It is not an adapter
and not a joint contract with PIC.

## Profile choice

The approval is read as one exact refund: payment `pay_A`, amount 4000 in minor units, currency `EUR`. It is
not a ceiling of up to EUR 40.00, so EUR 39.00 is refused as well as EUR 41.00. A ceiling would be a different
profile with different cases.

The target string `https://payments.operator.example/v1/payments/<payment_id>/refunds` is candidate profile
text for this check only. draft-pidlisnyi-aps-04 section 5.1 requires a profile to define its target
construction, and no published profile defines this one.

## What comes from the SDK and what does not

From `agent-passport-system` 7.2.1, unmodified: `createActionReferenceInputV2`, `computePayloadRefV1` and
`computeActionRefV2` (the -04 section 5.1 action input and its payload and action digests), `createReceiptV1` and `verifyReceiptV1` (signed
`aps:policy-decision:v1` records and their signature check), `buildDecisionRefV1` and `generateKeyPair`.

Written for this check, in `refund-boundary.ts` (`admitRefund`): recomputing the digests from the submitted
request and comparing them with the approval, the target comparison, the expiry check and the consumption of
the approval id. Draft -04 sections 5.3 and 7.3.2 require an enforcement boundary to admit an approval only
once and refuse an expired one. This file is one way to do that. The SDK records alone do not enforce it.

The approval is accepted only with verdict `permit`. A `narrow` decision is refused, because this check does
not evaluate constraints.

## Cases

| case | request or approval | result |
|---|---|---|
| R0 | exact request, valid approval | admitted, approval consumed |
| R1 | amount 3900 | refused |
| R2 | amount 4100 | refused |
| R3 | payment `pay_B` | refused |
| R4 | currency `USD` | refused |
| R5 | approval expired at submission | refused |
| R6 | the R0 approval submitted again | refused, already consumed |
| R7 | no approval, an approval for another payment, or a forged signature | refused |
| R8 | amount written as `4000.0` or `4e3` | admitted, informational (section 5.1 makes number spelling irrelevant to the digest) |
| R9 | signed `narrow` decision with a constraint this check does not enforce | refused, approval not consumed |

R1 to R4 run twice, once with the worker recomputing a consistent request and once with the worker keeping the
approved request and swapping only the payload. R3 runs a third time with the payload digest recomputed and the
target left at `pay_A`. The refusal reason is printed for every case.

## Run

```sh
cd examples/interop/refund-exact-approval
npm install
npm test
```

Expected: 10 tests, 10 pass, exit 0. Each case prints a `ROW` line with its result.

## What this does not establish

- No operator, refund provider or PIC verifier is involved. The operator's approval is test input.
- Idempotent execution of the refund itself after a timeout or a crash is the execution service's job and is
  not covered. This check covers reuse of the same approval only.
- Consumption is held in an in-memory set, so it covers one process. A restart forgets it, and two instances
  would each admit once.
- Revocation is not rechecked at consumption, there is no per-agent nonce ledger, the action-intent record is
  not verified and the delegation reference is synthetic. Draft -04 requires the first two at a real boundary.
- Request bodies are parsed with `JSON.parse`, which does not refuse duplicate member names as section 5.1
  requires.
- Who signs the approval in a joint APS and PIC workflow is not decided here.
