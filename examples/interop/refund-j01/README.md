# J01 producer and verifier, bounded refund sandbox

Offline test fixture for case J01 of contract `refund-sandbox-contract/review-2026-10-23`, section 3
([aeoess/agent-governance-vocabulary#193](https://github.com/aeoess/agent-governance-vocabulary/issues/193)).
It emits the APS-side native inputs for one exact refund and checks them. Built on
`agent-passport-system` v8.0.1, commit `56e7b293c6cce232eff0b2891ddf7af85bfe01e3`.

This is a test fixture. Keys are test keys derived from a stated seed. Anyone with the seed can sign as
these test identities. Nothing here talks to a payment system, a revocation service or PIC.

## Run

From the repository root, after `npm ci` and `npm run build`. The files import the built SDK from
`dist/`, so they test this commit and not a published package.

```
node_modules/.bin/tsx examples/interop/refund-j01/producer.ts \
  --out <dir> --run-label <label> --fixture-status demo|final \
  --issued-at 2026-10-27T18:00:00.250Z --valid-until 2026-10-27T18:10:00.900Z \
  --seed <test seed> --decision-id mdec_J01
  [--intent-issued-at <t>] [--key-valid-from <t>] [--key-valid-until <t>]

node_modules/.bin/tsx examples/interop/refund-j01/verify.ts --bundle <dir> --at <instant>

examples/interop/refund-j01/run-cases.sh <bundle> <seed> <at> <after-expiry> <work-dir>
```

All times are exact UTC milliseconds, `YYYY-MM-DDTHH:MM:SS.sssZ`, seconds 00 to 59. Second 60 is refused
even where the SDK would accept a conforming leap second. The producer refuses to overwrite an existing
file. The same arguments give byte-identical output, MANIFEST included (`--out` is recorded as a
placeholder).

`npx` is not used because npm 11 refuses this repository's `devEngines` (npm ^10.8.2).

## Output

| File | Contents |
|---|---|
| inputs/aps-intent.json | `aps:action-intent:v1`, issuer and subject `did:example:refund-worker`, signed by the worker test key |
| inputs/aps-approval.json | `aps:policy-decision:v1`, issuer `did:example:refund-approval-boundary`, `prev` = intent `receipt_id`, verdict permit, window from the arguments |
| inputs/aps-action.json | `ActionReferenceInputV2`, action_type `refund`, scope `["payments:refund"]`, the section 3 target, `payload_ref = computePayloadRefV1(payload)` |
| inputs/aps-payload.json | the literal bytes `{"payment_id":"pay_A","amount_minor":4000,"currency":"EUR"}` |
| inputs/decision-evidence.json | `DecisionEvidenceV1`, exactly authority_state, policy_input, decision_context, decision_output. Merchant decision at `policy_input.merchant_decision.decision_id` |
| trust/aps-consumption.json | worker and approval boundary public keys in the `hs-aps-consumption-trust/0.1` shape the HORIZON SHIELD admission door reads: `schema`, `profile`, `scope`, and per key `signer`, `key_id`, `role`, `public_key`, `not_before`, `not_after`, `revoked_at` |
| MANIFEST.json | `sha256:<hex>` of each file's exact bytes, approval_ref (bare 64 hex), merchant decision_id, validity, SDK commit, producer command, key derivation and seed |

Generated objects are written as RFC 8785 JCS bytes with no trailing newline. The payload keeps the
request's member order, which is not JCS order. `payload_ref` is computed over JCS and does not depend on it.

Test keys: private key = `sha256("APS-J01-193-TEST-KEY-V1" || 0x00 || seed || 0x00 || role)`, used as the
Ed25519 seed. No private key file is written.

## Checks

Each runs and is reported separately. Exit 0 only if all nine pass.

1. File hashes equal MANIFEST, MANIFEST approval_ref equals approval `receipt_id`.
2. Strict parse of every file from the same bytes that were hashed (`parseStrictIJson`, `parseActionReferenceInputV2`). Duplicate members rejected.
3. `verifyReceiptWithDecisionV1` on approval and decision evidence, role-restricted key resolver from the trust file, expected boundary identity from the profile.
4. Verdict permit, judged apart from 3.
5. Intent link. Intent verifies alone (signature, receipt_id, stage), issuer and subject are the worker, `approval.prev` equals its receipt_id, action_ref, subject and delegation_ref agree. The SDK's predecessor option covers action-result records only, so this is done here.
6. action_ref recomputed from aps-action.json, profile fields, closed payload schema, target, `payload_ref`, payload equals the merchant's approved refund.
7. decision_ref recomputed from the four components and the recomputed action_ref, decision_output equals approval.result.
8. Merchant decision_id present at the fixed path and equal to MANIFEST.
9. At the supplied instant: `issued_at <= t < valid_until` at millisecond precision (equality refused), approval key valid, no supplied revocation effective. This reads supplied trust input. It is not a live revocation check.

## What this does not establish

That `delegation_ref` or `effective_authority_ref` name a real delegation (they are synthetic). Merchant
legitimacy. Live revocation. Anything about PIC, admission, consumption, handoff or execution.

`parseStrictIJson` is not a package root export at v8.0.1, so it is imported from `dist/src/v2/receipt-core/jcs.js`.
