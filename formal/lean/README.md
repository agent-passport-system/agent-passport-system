# APS formal model (Lean 4)

Machine-checked proofs of the authority properties specified in draft-pidlisnyi-aps
section 4.2, written against the TypeScript implementation in
`src/v2/authority-delegation`, plus executable cross-checks against that
implementation. This is not formal verification of the SDK.

Lean 4.14.0, no Mathlib. Build from this directory:

    lake build

Every theorem ends with `#print axioms`. CI fails on `sorry` or on any axiom other
than `propext`, `Quot.sound` and `Classical.choice`.

## What is modelled

| Module | Facet | Machine-checked theorems |
|---|---|---|
| `APSFormal/Scope.lean` | scope grants (`*`, exact, `prefix:*`) | coverage is reflexive, transitive and antisymmetric. List containment is reflexive and transitive, and antisymmetric on irredundant sorted lists. The fast checks in `scopeNarrows` and `grantsAreCanonical` equal their pairwise definitions |
| `APSFormal/Spend.lean` | spend (`unbounded`, bounded unit and two limits) | partial order, unbounded is greatest, unit change is incomparable |
| `APSFormal/Facets.lean` | depth, time, reputation, values, reversibility | each is a partial order. Depth containment is reflexive and kept apart from the strict delegation step, and an identical depth cannot be delegated |
| `APSFormal/Authority.lean` | the seven-facet vector, one step, chains | containment is a partial order on canonical vectors. A valid step implies containment, and no record is a valid step from itself. In a chain of valid steps every record is contained in every ancestor, depth falls at least one per hop, and the chain has at most 256 records, a bound a constructed 256-record chain reaches |
| `APSFormal/Revocation.lean` | current validity and revocation of every member | given that the earlier verification phases passed, the result is valid exactly when every member is current and active. A revoked or unknown member anywhere means never valid, though the reported code can be an earlier failure or REVOCATION_UNKNOWN rather than REVOKED |

`Spend.lean` and `Facets.lean` have a DISAGREEMENTS block that records where the
TypeScript code or the draft text differs from the model. A disagreement is recorded,
not resolved by changing the model to match the code.

## What the proofs do not establish

- A partial order, not a lattice. Nothing here shows that every pair of authority
  vectors has a greatest lower bound or least upper bound, and some do not: two
  bounded spends in different units have no common lower bound, and neither do two
  disjoint time windows.
- Antisymmetry holds on the modelled canonical domain only: scope grants irredundant
  and strictly sorted, values identifiers sorted and unique, recognised profiles.
  It says nothing about arbitrary wire representations or unsupported profiles.
- `Revocation.lean` abstracts the earlier phases of `verifyAuthorityDelegationChain`
  (shape, identifiers, signatures, trust root, parent linkage, attenuation) as one
  pass or fail input. Current and active members alone do not make a chain valid.
- The 256-record bound is a mathematical consequence of remaining depth at most 255
  and a strict decrease per hop. It is separate from the verifier's own 256-record
  ceiling, which the implementation reports as indeterminate when exceeded. The two
  happen to be equal.
- Wire decoding (string splitting, decimal quantities, timestamp syntax and order),
  signatures, identifiers and parent linkage are outside the model. Action admission
  is a later case.

## Spend ledger (`Ledger.lean`)

Proved for every sequence of reserve, dispatch, commit and cancel calls from an empty
ledger, under one fixed limit table (`ledger_safe`):

- Budget ceiling: at every delegation id, reserved plus committed stays at or below the
  cumulative limit (`ceiling`).
- Accounting consistency: each id's reserved counter equals the sum of its reserved and
  dispatched reservations, and its committed counter equals the sum of its committed
  ones (`conservation`). This is what "conservation" names in the file. It is not itself
  a budget ceiling, which is the theorem above.
- A failed call changes nothing (`step_fail`). A newly completed reserve, commit or cancel
  changes exactly the reservation's ancestors (`reserve_all_or_none`,
  `commit_all_or_none`, `cancel_all_or_none`). Commit keeps reserved plus committed
  unchanged (`commit_preserves_charged`). The natural-number subtraction in commit and
  cancel never truncates on a reachable ledger (`reachable_holds`).

What the ledger proofs do not establish:

- That the ids passed to reserve are the right ones. The model charges the list it is
  given. Omitting a governing ancestor keeps both invariants true while that ancestor goes
  uncharged. The SDK derives the list from a verified chain, and that step is outside the
  model.
- The SDK's quantity domain. Amounts are unbounded naturals here, where the SDK accepts
  canonical decimals up to 2^63 - 1.
- Behaviour on a ledger that was not built by these calls. Counters always exist in the
  model, while the SDK keeps them in a map and rejects a missing entry. Restore, import or
  external corruption is outside the model.
- Releasing a dispatched reservation on trusted evidence that it was never executed.
  Draft-04 section 4.4 allows it. Neither the SDK nor the model exposes that transition.
- Anything beyond one sequential ledger: distributed linearizability, persistence, crash
  recovery, approval consumption or exactly-once execution of the external effect.

## Correspondence with the TypeScript code

`Vectors.lean` uses executable deciders, each shown in Lean to equal its declarative
relation by a Lean theorem, except the string sort check, to generate
`tests/v2/fixtures/lean-correspondence.json`. It includes 720 two-record step cases
that the test signs and runs through `verifyAuthorityDelegationChain`. The test
`tests/v2/authority-lean-correspondence.test.ts` runs the SDK on every case.

The corpus covers a small universe exhaustively. A pass means the SDK and the model
agree on those cases, which is executable evidence, not a proof that they agree on
every input.

    lake env lean --run Vectors.lean > ../../tests/v2/fixtures/lean-correspondence.json
