# Cycles correspondence vectors

Language-neutral cases for the receipt to envelope correspondence rule that `agent-passport-system` 8.0.0 applies to Cycles permit and release receipts.

The rule: when an envelope is supplied, a permit receipt must cite a reserve envelope and a release receipt must cite a release envelope, and the envelope must name the receipt's own `reservation_id`. Only stage and reservation are compared. Amount, unit, action and server identity are not. Denial receipts get no correspondence check. The hash binding and the envelope's own signature are checked first, so a tampered envelope reports `EVIDENCE_REF_HASH_MISMATCH`, not a correspondence result.

## Format

`vectors.json` holds `cases`. Each case has:

- `id` and `description`
- `verifier`: `permit`, `release` or `denial`
- `receipt`: the signed APS receipt
- `envelope`: the full Cycles evidence envelope, passed to the verifier as the supplied evidence
- `expected`: `{ "valid": true, "evidence_authenticity": "signature_valid" }`, or `{ "valid": false, "reason": "...", "detail_prefix": "..." }` where `detail_prefix` is how the failure detail starts (the field that failed)

The reasons are `EVIDENCE_CORRESPONDENCE_MISMATCH`, `EVIDENCE_CORRESPONDENCE_FIELD_MISSING` and `EVIDENCE_REF_HASH_MISMATCH`.

The unaltered envelopes come from `../cycles-fixtures/02-reserve-allow.json`, `../cycles-evidence-vectors/05-commit-success.json` and `../cycles-evidence-vectors/06-release-success.json`, signed by the Cycles server. Cases that alter an envelope re-sign it with a test-only key, so the hash and signature checks pass and the failure reaches the correspondence check. Both keys are derived from fixed seeds in `generate.ts`, are published, and protect nothing.

## Use

`../cycles-correspondence-vectors.test.ts` runs every case against this SDK. Another implementation can load `vectors.json` and compare its own verdicts. Regenerate with `npx tsx tests/v2/payment-rails/cycles-correspondence-vectors/generate.ts` only when the rule changes. `receipt_id` and `issued_at` change on every run, so review the diff.
