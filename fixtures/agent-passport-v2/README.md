# `aps.agent-passport` 2.0: frozen vectors

The Agent Passport record of draft-pidlisnyi-aps-04 section 3.1, generated from
the merged TypeScript implementation under `src/v2/identity-binding/`.

This family exists so a relying party can check a 2.0 passport without running
APS code: the exact preimage bytes, the identifier they hash to, the signature
over them, and the verification outcome the SDK returns for four valid cases
and sixteen rejection or indeterminate cases. Pin the JSON by sha256 and run
your reader over it. This is a limited initial corpus, not complete coverage of
passport admission.

## Files

| file | what it is |
|---|---|
| `agent-passport-vectors-v2.json` | the vectors |
| `generate-fixtures.ts` | deterministic generator |
| `recompute-independent.ts` | a separate implementation with no SDK imports, run over every case |

The TypeScript reference run lives in `tests/v2/agent-passport-vectors.test.ts`
and is wired into `npm test`.

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
| `did-web-resolver-not-found` | invalid | `PASSPORT_KEY_NOT_FOUND` | true | rejected |
| `did-web-resolver-unreachable` | indeterminate | `PASSPORT_KEY_UNREACHABLE` | true | unresolved |
| `version-changed` | invalid | `PASSPORT_MALFORMED` | false | rejected |
| `record-type-changed` | invalid | `PASSPORT_MALFORMED` | false | rejected |
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
- `did-web-resolver-not-found` records the SDK's `invalid`. Draft-04 section 3.5
  maps a key that is not found to indeterminate for external signers, and
  section 3.1 assigns no outcome for the agent's own key. A reader that reports
  indeterminate here is not nonconforming on this vector alone. Its
  `layers.key_authority` is `unresolved`, because no key was resolved.
- `expired` and `not-yet-valid` report `proof_of_possession: true`. The signature
  verified, so possession is a fact about these bytes whatever the clock says.
  `key_authority: rejected` in `verification` is an SDK output produced without
  a key authority determination, and `layers.key_authority` says `not_checked`.
  An implementation that reports unresolved or not evaluated there is not
  nonconforming on these vectors alone. `valid-at-issued-at` pins the other end
  of the interval, where `now` equal to `issued_at` is inside it.
- `version-changed` and `record-type-changed` record `invalid` /
  `PASSPORT_MALFORMED`, the SDK's output for an unrecognised profile. Section
  3.1 does not assign an outcome to an unrecognised profile, and other draft-04
  record families report unsupported there. An implementation that reports
  unsupported is not nonconforming on these vectors alone. What they establish
  is that the record is not admitted.

The five structural cases and `passport-id-wrong-signature-valid` are re-sealed.
Their `passport_id` and signature recompute over the record as presented, so
only the named rule is broken and a reader that skipped that rule would admit
them.

## SDK reference

Generated against `aeoess/agent-passport-system` at
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

Regenerate:

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
```

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
  reported as `KEY_AMBIGUOUS`. At the pinned commit `verifyPassportV2` has no
  evidence input and admits whatever key the resolver returns for `issued_at`,
  so a resolver that returned a retired key would be accepted on the claim
  alone. No vector here exercises that case.
- Principal binding and its revocation (section 3.3 and following). Those are
  separate records with their own constructions.
- JCS escaping of non-ASCII and control characters. Every string here is
  printable ASCII on purpose. Escaping is pinned by
  `tests/cross-impl/jcs-test-vectors.json`.
