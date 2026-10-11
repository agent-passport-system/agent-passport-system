# `aps.agent-passport` 2.0 vectors

The Agent Passport record of draft-pidlisnyi-aps-04 section 3.1, generated from
the merged TypeScript implementation under `src/v2/identity-binding/`.

This family exists so a relying party can check a 2.0 passport without running
APS code: the exact preimage bytes, the identifier they hash to, the signature
over them, and the verification outcome the SDK returns for four valid cases
and sixteen rejection, indeterminate or unsupported cases. Pin the JSON by sha256 and run
your reader over it. This is a limited initial corpus, not complete coverage of
passport admission.

## Files

| file | what it is |
|---|---|
| `agent-passport-vectors-v2-r2.json` | the vectors, revision 2, recording the SDK at `6a11df9` |
| `agent-passport-vectors-v2.json` | revision 1, frozen, recording the SDK at `c31d94a` (sha256 `9fce76db...5ac5`) |
| `generate-fixtures.ts` | deterministic generator, writes revision 2 |
| `recompute-independent.ts` | a separate implementation with no SDK imports, run over every case |

The TypeScript reference runs live in `tests/v2/agent-passport-vectors-r2.test.ts`
(revision 2, every case exact) and `tests/v2/agent-passport-vectors.test.ts`
(revision 1, frozen, with the three superseded outputs checked against both the
file and the current verifier). Both are wired into `npm test`.

## Revisions

Revision 1 (`agent-passport-vectors-v2.json`, commit `407ca2d5`) is frozen and
stays in the repository unchanged, because outside readers pin it by sha256.
Revision 2 (`agent-passport-vectors-v2-r2.json`) records the verifier after #221.
The passports, preimages, keys, resolver table and resolver requests are
identical. Three cases changed:

| case | revision 1 | revision 2 |
|---|---|---|
| `did-web-resolver-not-found` | invalid / `PASSPORT_KEY_NOT_FOUND`, key authority rejected | indeterminate / `PASSPORT_KEY_NOT_FOUND`, key authority unresolved |
| `version-changed` | invalid / `PASSPORT_MALFORMED`, structure rejected | unsupported / `PASSPORT_UNSUPPORTED_VERSION`, structure unsupported |
| `record-type-changed` | invalid / `PASSPORT_MALFORMED`, structure rejected | unsupported / `PASSPORT_UNSUPPORTED_RECORD_TYPE`, structure unsupported |

Draft-04 assigns no passport outcome for these three, so both revisions are
acceptable readings and neither admits the record. Revision 2 records what the
SDK reports now. To reproduce revision 1 byte for byte, run `generate-fixtures.ts`
as it was at `407ca2d5`.

## What a case pins

Every case carries the passport as presented, the verification instant `now`,
whether a key resolver was supplied (`resolver`: `none` or `table`), and the
outcome twice:

- `verification` records the SDK output at the pinned commit: `state`, `code`,
  `proof_of_possession`, `key_authority`.
- `layers` is this fixture family's diagnostic schema: `structure`,
  `passport_id`, `signature`, `validity_window`, `proof_of_possession` and
  `key_authority`. It describes the checks reached in this run and is not a
  reporting format or check order required by draft-04. `not_checked` means
  this run made no determination about that layer.

Five cases also carry `sdk_observation`, where the recorded SDK output goes
beyond what draft-04 requires (see below). An implementation that reports
differently on those points is not nonconforming on these vectors alone. Every
rejection or indeterminate case does establish that the passport must not be
admitted as valid.

For the three distinct valid passports, `valid_cases_preimages` adds the two preimages as
hex of their UTF-8 bytes (hex rather than text because each domain tag ends in
one NUL byte), the `passport_id` they hash to, the signature, and the signing
public key.

The key resolver the did:web cases were generated against is in the file as
data. Its did:web entry has no end date, so the outcome does not depend on when
the key is resolved. Section 3.4 does not let the issuer's `issued_at` claim
alone select a retired key, and this file carries no timestamp evidence, so
retired-key selection is not covered. Each did:web case records the request the
SDK made under `resolver_requests`, and the generator and the test both check
that `at` equals the passport's `issued_at`.

## Cases

Revision 2:

| name | state | code | possession | key authority |
|---|---|---|---|---|
| `valid-did-key-minimal` | valid | `OK` | true | verified |
| `valid-did-key-with-self-asserted` | valid | `OK` | true | verified |
| `valid-did-web-resolved` | valid | `OK` | true | verified |
| `valid-at-issued-at` | valid | `OK` | true | verified |
| `tampered-display-name-stale-id` | invalid | `PASSPORT_ID_MISMATCH` | false | rejected |
| `tampered-display-name-id-repaired` | invalid | `PASSPORT_SIGNATURE_INVALID` | false | rejected |
| `passport-id-wrong-signature-valid` | invalid | `PASSPORT_ID_MISMATCH` | false | rejected |
| `signed-by-other-key` | invalid | `PASSPORT_SIGNATURE_INVALID` | false | rejected |
| `public-key-not-the-did-key` | invalid | `PASSPORT_KEY_AUTHORITY_REJECTED` | true | rejected |
| `expired` | invalid | `PASSPORT_NOT_CURRENT` | true | rejected |
| `not-yet-valid` | invalid | `PASSPORT_NOT_CURRENT` | true | rejected |
| `did-web-no-resolver` | indeterminate | `PASSPORT_KEY_AUTHORITY_UNRESOLVED` | true | unresolved |
| `did-web-resolver-answers-other-key` | invalid | `PASSPORT_KEY_AUTHORITY_REJECTED` | true | rejected |
| `did-web-resolver-not-found` | indeterminate | `PASSPORT_KEY_NOT_FOUND` | true | unresolved |
| `did-web-resolver-unreachable` | indeterminate | `PASSPORT_KEY_UNREACHABLE` | true | unresolved |
| `version-changed` | unsupported | `PASSPORT_UNSUPPORTED_VERSION` | false | unresolved |
| `record-type-changed` | unsupported | `PASSPORT_UNSUPPORTED_RECORD_TYPE` | false | unresolved |
| `capabilities-unsorted` | invalid | `PASSPORT_MALFORMED` | false | rejected |
| `principal-member-present` | invalid | `PASSPORT_MALFORMED` | false | rejected |
| `timestamp-without-milliseconds` | invalid | `PASSPORT_MALFORMED` | false | rejected |

Five points are worth reading before porting:

- `public-key-not-the-did-key` is the case a signature-only reader gets wrong.
  `passport_id` and the signature both recompute, and proof of possession holds
  for the key in the record. The did:key identifier commits to a different key,
  so key authority is rejected. Section 3.1 requires the two conclusions to be
  reported separately, and this case is where they differ.
- `did-web-no-resolver` and `did-web-resolver-unreachable` are `indeterminate`,
  never `invalid`. Nothing was learned about the key, so saying the passport is
  forged would be saying more than the verifier knows.
- `did-web-resolver-not-found` records the SDK's `indeterminate`. The SDK applies
  the draft-04 section 3.5 mapping, written for external signers, to the agent's
  own key, and section 3.1 assigns no outcome there. A reader that reports
  invalid here is not nonconforming on this vector alone. Its
  `layers.key_authority` is `unresolved`, because no key was resolved.
- `expired` and `not-yet-valid` report `proof_of_possession: true`. The signature
  verified, so possession is a fact about these bytes whatever the clock says.
  `key_authority: rejected` in `verification` is an SDK output produced without
  a key authority determination, and `layers.key_authority` says `not_checked`.
  An implementation that reports unresolved or not evaluated there is not
  nonconforming on these vectors alone. `valid-at-issued-at` pins the other end
  of the interval, where `now` equal to `issued_at` is inside it.
- `version-changed` and `record-type-changed` record `unsupported`, the rule
  draft-04 states for the delegation and revocation record families. Section 3.1
  does not assign an outcome to an unrecognised profile, so an implementation
  that reports invalid or malformed is not nonconforming on these vectors alone.
  What they establish is that the record is not admitted. `layers.structure` is
  `unsupported` and nothing past the profile is judged.

The five structural cases and `passport-id-wrong-signature-valid` are re-sealed.
Their `passport_id` and signature recompute over the record as presented, so
only the named rule is broken and a reader that skipped that rule would admit
them.

## SDK reference

Revision 2 was generated against `6a11df9ee51e63efcad1c2c30e236090cef14db7`, main
after #221 and #222 and not itself a release. The identity binding sources are
unchanged since the #221 merge (`f2b3c98`).

Revision 1 was generated against `aeoess/agent-passport-system` at
`c31d94aad86713ae9b2e4cbc811deeab4b5d91ed`, main after the v7.2.1 tag and not
itself a release (`git describe`: `v7.2.1-14-gc31d94a`). The identity binding,
canonicalization, crypto and type sources are unchanged since v7.2.1. The
commit is recorded in the JSON under `sdk_reference.commit`. That SHA pins the **implementation** the
outcomes came from. The vector files themselves land on a later commit. At that
commit `issuePassportV2` and `verifyPassportV2` are in-repo and tested but not
exported from the package entry, which is one reason these vectors exist.

## Determinism

Nothing in the generator reads a clock or a random source. The verification
instant is passed to the verifier as `now` on every case:

- Ed25519 seeds are `sha256(utf8("agent-passport-system:agent-passport-vector:<label>"))`.
  The 32 bytes are the seed, so anybody can re-derive the keys from the label
  alone. They are test keys in a public repository and control nothing.
- `now`, every timestamp, every nonce, `display_name`, `capabilities` and the
  resolver table are constants in the generator.
- Ed25519 signing is deterministic (RFC 8032).

Regenerate revision 2:

```
npx tsx fixtures/agent-passport-v2/generate-fixtures.ts
# or: npm run fixtures:agent-passport-v2
```

Two runs produce a byte-identical file, and `git diff` after a regeneration is
the check. The generator also re-runs the merged verifier over every case and
refuses to write the file if an outcome no longer matches the one that case
declares, so a behaviour change surfaces at generation rather than being
silently re-baselined.

## Separate recompute

```
npx tsx fixtures/agent-passport-v2/recompute-independent.ts
# or: npm run fixtures:agent-passport-v2:recompute
# revision 1:
npx tsx fixtures/agent-passport-v2/recompute-independent.ts fixtures/agent-passport-v2/agent-passport-vectors-v2.json
```

With no argument it reads revision 2. It takes the profile rule from the file's
`family_revision`: from revision 2, an unrecognised string profile is
`structure: unsupported`.

`recompute-independent.ts` imports nothing from `src/`. Its only imports are
`node:crypto` and `node:fs`. It re-states RFC 8785 JCS for the JSON a passport
is made of, re-types the two domain tags as literals and checks them against
the hex the vector publishes, decodes multibase base58btc and the `0xed01`
multicodec prefix itself, and uses the platform's SHA-256 and Ed25519. From the
vector file alone it rebuilds both preimages of the three distinct valid
passports and verifies their signatures, then runs its own verifier over all
twenty cases, resolving at `issued_at`, and compares the result with `layers`,
case by case.

What that shows and what it does not. The bytes, identifiers and signatures are
recomputed without the SDK code. The order of checks and the structural
predicates re-state the same reading of section 3.1 as the generator, and both
use Node's Ed25519, so agreement is not evidence that draft-04 mandates that
reading.

`src/crypto/keys.ts` also refuses small-order Ed25519 key material before it
calls the platform primitive. The recompute leaves that out on purpose because
it is a property of the SDK verifier, not of these bytes.

## Not covered

- Legacy `did:aps` identifiers. Section 3.2 lets a compatibility verifier read
  them and says conforming new-write paths do not emit them. None is minted
  here.
- Key rotation under an update-capable DID method (section 3.2 `versionId` or
  `versionTime`). The resolver table has one key per method and no validity
  window.
- Selection of a retired key. Section 3.4 requires acceptable timestamp
  evidence before a retired key is selected, and the issuer's `issued_at` claim
  alone does not satisfy it. Without that evidence the outcome is indeterminate,
  reported as `KEY_AMBIGUOUS`. `verifyPassportV2` has no evidence input.
  `HistoricalKeyResolutionResult` documents that `resolved` means the key
  authorized at `issued_at` and that a resolver that cannot select by time
  answers `ambiguous`, so the evidence check rests with the resolver. No vector
  here exercises that case.
- Principal binding and its revocation (section 3.3 and following). Those are
  separate records with their own constructions.
- JCS escaping of non-ASCII and control characters. Every string here is
  printable ASCII on purpose. Escaping is pinned by
  `tests/cross-impl/jcs-test-vectors.json`.
