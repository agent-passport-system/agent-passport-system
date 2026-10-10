# Action Receipt v1.1 (legacy): frozen vectors

The pre-draft `Delegation` and `ActionReceipt` records of `src/core/delegation.ts`,
described by `docs/SPEC-v1.1.md`. This surface is deprecated and frozen (README,
"Two delegation records ship"). It is not on the draft-pidlisnyi-aps path. The
draft-path records are `AuthorityDelegationV1` (`aps:authority-delegation:v1`,
`fixtures/authority-revocation/` covers its revocation) and receipt-core v1.

This family records what individual TypeScript SDK functions return at the
pinned commit for fixed records and inputs: the wire shape, the canonical bytes,
the signature, and the results of `verifyReceipt`, `verifyDelegation`,
`subDelegate` and `createReceipt`. Where `docs/SPEC-v1.1.md` and the code
disagree, the vectors record the code, because the code signed the bytes. The
document carries a dated errata section listing those points. Neither the
vectors nor the errata change the requirements of the document, and other
implementations, the Python SDK included, may differ.

No case establishes that an action was authorized.

## Files

| file | what it is |
|---|---|
| `action-receipt-vectors-v1.1.json` | the vectors |
| `generate-fixtures.ts` | deterministic generator |
| `recompute-independent.ts` | a separate recompute of selected checks, with no SDK imports |

The TypeScript reference run lives in `tests/v2/action-receipt-vectors.test.ts`
and is wired into `npm test`.

## How to read a case

Every case carries the record, the SDK function's result under `verification`,
and `verification_scope`, which names the function, lists what that function
checks and does not check, and sets `establishes_authorization: false`. The
lists describe the function at the pinned commit. They are not traces of the
checks reached by each recorded call, and a refusal can happen before later
listed checks run.

Cases that also carry `issuance` record the inputs given to `subDelegate` or
`createReceipt`, by delegation id and key label, and whether the function
accepted them. When `createReceipt` accepts, the receipt it returned is compared
with the case record: the same member names, and equal values for `version`,
`agentId`, `delegationId`, `action`, `result` and `delegationChain`. Its
`receiptId`, `timestamp` and `signature` come from a uuid, the clock and the key,
and are not compared.

A `valid: true` is that one function's result. It is not an authorization
verdict, and a consumer of the JSON should not read it as one.

## Read this first

1. **Member names are camelCase on the wire and inside the signed bytes.** The
   SDK at the pinned commit emits and signs `receiptId`, `agentId`,
   `delegationId`, `action.scopeUsed`, `delegationChain`, and on a delegation
   `delegatedTo`, `delegatedBy`, `spendLimit`, `maxDepth`, `currentDepth`,
   `expiresAt`. The `docs/SPEC-v1.1.md` section 1.1 and 3.2 examples use other
   names. Renaming the members of a signed record without re-signing
   invalidates its signature (`receipt-snake-case-spelling`). `verifyReceipt`
   does not check member names, so that case does not show that snake_case is
   rejected as such. The camelCase names `createReceipt` emits are pinned by the
   output comparison on `valid-receipt-under-root`.
2. **`verifyReceipt` checks the signature under the supplied key and that
   `version` is `1.1`.** Nothing else (`receipt-version-1.0` isolates the
   version gate with a valid signature).
3. **`createReceipt` checks the supplied delegation, the action's scope and the
   remaining budget. It does not validate `delegationChain`.** It copies the
   supplied chain into the receipt. `receipt-chain-not-validated` records that
   it accepts an unrelated chain, and the output comparison asserts that the
   returned receipt carries that chain unchanged. Neither `verifyReceipt` nor
   `createReceipt` validates the receipt chain. A relying party needs a
   separate chain check.
4. **`verifyDelegation` verifies one record alone.** Signature under
   `delegatedBy`, `expiresAt` and `notBefore` against the clock, `currentDepth >
   maxDepth` when `maxDepth` is present, revocation evidence if the caller
   supplies some. It does not consult the parent, so a self-consistent child
   wider than its parent verifies on its own
   (`delegation-scope-wider-than-parent`).
5. **`subDelegate` checks a proposed child against its parent.** In code order:
   depth, scope, spend unit, spend, the parent's expiry, then the parent itself
   through `verifyDelegation`. `delegation-grandchild-beyond-depth` and
   `delegation-signed-by-other-key` record its depth and invalid-parent
   refusals.

## Cases

Delegations (`verifyDelegation`, with `Date.now()` fixed at the file's
`verification_instant`):

| name | valid | note |
|---|---|---|
| `valid-root-delegation` | true | principal to agent, maxDepth 1, 500 USD |
| `valid-child-delegation` | true | agent to subagent, narrower, depth 1 of 1, `subDelegate` accepts |
| `delegation-expired` | false | signature valid, expired |
| `delegation-expires-at-verification-instant` | true | expired only when `expiresAt` < instant |
| `delegation-not-yet-valid` | false | `notBefore` one millisecond after the instant |
| `delegation-not-before-at-verification-instant` | true | not yet valid only when `notBefore` > instant |
| `delegation-signed-by-other-key` | false | another key signed, `subDelegate` from it refuses |
| `delegation-depth-exceeded` | false | currentDepth 2, maxDepth 1 |
| `delegation-grandchild-beyond-depth` | false | under the child at depth 2, `subDelegate` from the child refuses |
| `delegation-scope-wider-than-parent` | true | record alone verifies, `subDelegate` refuses |
| `delegation-spend-wider-than-parent` | true | record alone verifies, `subDelegate` refuses |
| `delegation-without-max-depth-at-depth-64` | true | signed without maxDepth, no ceiling applied |

Receipts (`verifyReceipt` with the named key):

| name | valid | note |
|---|---|---|
| `valid-receipt-under-root` | true | commerce:checkout, 120 USD, `createReceipt` accepts, output compared |
| `valid-receipt-under-child` | true | data:read under the child, three-entry chain |
| `receipt-tampered-spend` | false | amount changed after signing |
| `receipt-signed-by-other-key` | false | |
| `receipt-version-1.0` | false | re-signed, only the version gate fails |
| `receipt-snake-case-spelling` | false | section 1.1 member names, signature over the camelCase record |
| `receipt-scope-not-delegated` | true | `verifyReceipt` returns valid, `createReceipt` refuses |
| `receipt-spend-over-budget` | true | `verifyReceipt` returns valid, `createReceipt` refuses |
| `receipt-under-expired-delegation` | true | `verifyReceipt` returns valid, `createReceipt` refuses |
| `receipt-chain-not-validated` | true | unrelated chain entry, `createReceipt` accepts and copies it, output compared |

The scope-widening, budget-widening and missing-maxDepth delegation cases, and
the scope, budget, expired-delegation and chain receipt cases, keep `true`
results to show where each function's checks stop. They are function results
recorded as observed.

## Canonicalization and signatures

APS canonical JSON (`src/core/canonical.ts`, `docs/CANONICAL-SPEC.md`): keys
sorted by UTF-16 code units, object members whose value is `null` or
`undefined` omitted, array nulls kept, no whitespace. This is not RFC 8785,
since the null omission rule differs. Ed25519 over the UTF-8 bytes of the
canonical record without `signature`, no domain tag. Raw 64-byte signatures as
128 lowercase hex, raw 32-byte public keys as 64 lowercase hex. A receipt is
signed by the executing agent and `verifyReceipt` takes that key as a
parameter. A delegation is signed by `delegatedBy` and `verifyDelegation` reads
the key from the record.

## max_depth

`createDelegation` writes `maxDepth: 1` when the caller omits it, and the field
is signed. The generator and a test in the vector test file both check this.
`verifyDelegation` applies no depth ceiling to a signed record without
`maxDepth`. `delegation-without-max-depth-at-depth-64` is a record signed
without the field at `currentDepth` 64, and it verifies. The writer default and
the reader behaviour of the TypeScript SDK are not equivalent. The Python SDK
reads an absent `maxDepth` as 0 (see the errata). This is how the TypeScript SDK
behaves at the pinned commit, recorded as such. It is not a claim about what the
sections of `docs/SPEC-v1.1.md` originally intended.

## Validity window

`verifyDelegation` reports a record expired only when `expiresAt` is earlier
than the verification instant, and not yet valid only when `notBefore` is later
than it. Both boundaries are inside the window
(`delegation-expires-at-verification-instant`,
`delegation-not-before-at-verification-instant`). A record whose `notBefore`
is one millisecond after the instant is refused (`delegation-not-yet-valid`). The passport
2.0 interval of draft-04 section 3.1 is exclusive at `expires_at`. The two
surfaces differ here, and this family records the legacy behaviour as observed.

## SDK reference

Generated against `aeoess/agent-passport-system` at
`c31d94aad86713ae9b2e4cbc811deeab4b5d91ed`, on main after the v7.2.1 tag
(`git describe`: `v7.2.1-14-gc31d94a`) and not a release. The delegation,
canonicalization, crypto and type sources are unchanged between the tag and
that commit. Recorded in the JSON under `sdk_reference`.

## Determinism

`createDelegation` and `createReceipt` read a clock and a random source. The
records here are assembled with the write-boundary primitives those functions
use, `canonicalizeForWrite` and `sign`, over fixed identifiers and timestamps.
The generator compares the assembled child with the child `subDelegate` mints
from the root under the same options: the same members, with equal values apart
from `delegationId`, `createdAt`, `expiresAt` and `signature`. The fixture is
assembled and signed separately. It is not the exact record returned by
`subDelegate`.

`verifyDelegation` compares against `Date.now()`, so every SDK call in the
generator and in the test runs with `Date.now()` fixed at
`verification_instant`, which is written into the file. Ed25519 seeds are
`sha256(utf8("agent-passport-system:action-receipt-vector:<label>"))`. Two
generator runs are byte identical.

```
npx tsx fixtures/action-receipt-v1.1/generate-fixtures.ts
npx tsx fixtures/action-receipt-v1.1/recompute-independent.ts
```

## Separate recompute

`recompute-independent.ts` imports nothing from `src/`. It recomputes the
canonical bytes, the signatures and the selected predicates these fixtures
exercise, reading the issuance inputs from the file and checking the parent or
supplied delegation before an issuance predicate. It is not a complete
implementation of `subDelegate` or `createReceipt`: derivation rights, spend
units other than the default, revocation and parse errors are left out, and no
case here exercises them. The rules come from the same reading of the SDK as
the generator, so agreement shows the file is internally consistent, not that
the rules are right.

## Not covered

- Revocation. The SDK holds no revocation registry. `verifyDelegation` takes
  cached state as an option, with `fail_open` as the default policy, and the
  gateway store does live checks. No revocation case is pinned.
- Chain verification as one operation (`store.validateChain`, gateway).
- `subDelegate` refusals for derivation rights and spend unit changes.
- The draft path. Different records, different wire formats, their own
  families.
- The optional receipt members (`previousReceiptHash`, `witnessSignature`,
  `sequenceNumber` and the rest). None is set here.
