# APS formal model (Lean 4)

A machine-checked model of the authority containment rules in draft-pidlisnyi-aps
section 4.2, written against the TypeScript implementation in
`src/v2/authority-delegation`.

Lean 4.14.0, no Mathlib. Build from this directory:

    lake build

Every theorem ends with `#print axioms`. CI fails on `sorry` or on any axiom other
than `propext`, `Quot.sound` and `Classical.choice`.

## What is modelled

| Module | Facet | Proved |
|---|---|---|
| `APSFormal/Scope.lean` | scope grants (`*`, exact, `prefix:*`) | coverage is reflexive, transitive and antisymmetric. List containment is reflexive and transitive, and antisymmetric on irredundant sorted lists. The fast checks in `scopeNarrows` and `grantsAreCanonical` equal their pairwise definitions |
| `APSFormal/Spend.lean` | spend (`unbounded`, bounded unit and two limits) | partial order, unbounded is greatest, unit change is incomparable |
| `APSFormal/Facets.lean` | depth, time, reputation, values, reversibility | each is a partial order. Depth containment is reflexive and kept apart from the strict delegation step, and an identical depth cannot be delegated |
| `APSFormal/Authority.lean` | the seven-facet vector, one step, chains | containment is a partial order (antisymmetric on canonical vectors). A valid step implies containment, and no record is a valid step from itself. In a valid chain every record is contained in every ancestor, depth falls at least one per hop, and a chain has at most 256 records, a bound a 256-record chain reaches |

Each file has a DISAGREEMENTS block that records where the TypeScript code or the
draft text differs from the model. A disagreement is recorded, not resolved by
changing the model to match the code.

## What is not modelled

Wire decoding (string splitting, decimal quantities, timestamp syntax) is outside the
model. Signatures, chain linkage, revocation, the spend ledger and action admission
are later cases.

## Correspondence with the TypeScript code

`Vectors.lean` uses the executable deciders, each proved equal to its declarative
relation, to generate `tests/v2/fixtures/lean-correspondence.json`. The test
`tests/v2/authority-lean-correspondence.test.ts` runs the SDK on every case. The
corpus covers a small universe exhaustively. A pass means the SDK and the model agree
on those cases, not that they agree on every input.

    lake env lean --run Vectors.lean > ../../tests/v2/fixtures/lean-correspondence.json
