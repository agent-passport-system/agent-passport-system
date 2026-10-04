# Motebit ExecutionReceipt: APS-side consumer

An APS-side consumer for two fixtures from Motebit's
[`examples/python-receipt-verifier/fixtures/`](https://github.com/motebit/motebit/tree/fed97862ddca5990eeba817918decf7099c22b50/examples/python-receipt-verifier/fixtures),
pinned to commit [`fed97862ddca5990eeba817918decf7099c22b50`](https://github.com/motebit/motebit/tree/fed97862ddca5990eeba817918decf7099c22b50).
It verifies both fixtures with `agent-passport-system` primitives, `canonicalizeJCS` for the RFC 8785
canonical bytes and `node:crypto` Ed25519, and never runs Motebit's own TypeScript or Python code. The test
(`tests/interop/motebit-receipts.test.ts`) builds its own verification path from Motebit's published
verifier (`examples/python-receipt-verifier/verify.py` at the same commit) and spec section
(`spec/execution-ledger-v1.md` §11), reading those sources only, never executing them.

## Source

| fixture | path | git blob SHA-1 | SHA-256 |
|---|---|---|---|
| `example-receipt.json` | `examples/python-receipt-verifier/fixtures/example-receipt.json` | `183b1a539ed08c2ce8e575df822313b33461ea41` | `130af372ceb2923b0c7753d1daa2be991e7cf251bb3b50cc66a1686734dd6b67` |
| `sovereign-receipt.json` | `examples/python-receipt-verifier/fixtures/sovereign-receipt.json` | `f77d29ae1bf9ac0b8c76260d11f37b44517be83e` | `220409fa0a02d35cf17093019c124daa2f079da817d74473f290f70d59b0312c` |

Both blob hashes were confirmed against the pinned commit with `git hash-object` before these copies
were made. Fixture bytes here are byte-for-byte identical to the source.

## Verification recipe (per Motebit's `verify.py` and suite `motebit-jcs-ed25519-b64-v1`)

1. Strip the `signature` field from the receipt object.
2. Canonicalize the remaining body with RFC 8785 JCS.
3. base64url-decode (no padding) the `signature` field.
4. Ed25519-verify the canonical bytes against the hex-decoded embedded `public_key`.

For `example-receipt.json`, the canonical body's SHA-256 is
`445407920cb8e5011b146bc7ba8b5a3c66ae0218e02bb2f5c5d1f87e94b3f880`. Motebit's Python verifier reported
the prefix `445407920cb8` for the same fixture, and the test checks that prefix.

## Expected verdicts

| fixture | signature valid | suite | notes |
|---|---|---|---|
| `example-receipt.json` | true | `motebit-jcs-ed25519-b64-v1` | `status: completed` |
| `sovereign-receipt.json` | true | `motebit-jcs-ed25519-b64-v1` | `status: completed` |

## What this does not establish

This consumer verifies the integrity of the signed canonical bytes under the embedded key, the signed
`task_id`, and the declared `suite` identifier. It does not establish who controls the signer, or that
the reported task actually occurred. Identity binding (that the embedded `public_key` belongs to a
specific, known device or principal) stays on Motebit's side. This consumer treats `public_key` as
whatever the receipt embeds and checks only that the signature over the canonical body matches it.

Motebit owns the fixtures and the spec they implement. APS owns this consumer.
