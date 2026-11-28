/-
Differential corpus generator. Run from formal/lean:
  lake env lean --run Vectors.lean > ../../tests/v2/fixtures/lean-correspondence.json
Every expected value is computed by the executable deciders in APSFormal, each of which
is proved equal to its declarative relation (covers?_iff, le?_iff). The corpus is
exhaustive over a small universe, not random: it detects disagreements with the
TypeScript SDK in these cases only.
-/
import Lean.Data.Json
import APSFormal.Scope
import APSFormal.Spend

open Lean APS

namespace Gen

def segs : List String := ["a", "b"]

def paths : List (List String) :=
  (segs.map fun x => [x]) ++ (segs.flatMap fun x => segs.map fun y => [x, y])

def grants : List Scope.Grant :=
  [.any] ++ paths.map .exact ++ paths.map .sub

def render : Scope.Grant → String
  | .any => "*"
  | .exact p => ":".intercalate p
  | .sub p => ":".intercalate p ++ ":*"

def withinB (child parent : List Scope.Grant) : Bool :=
  child.all fun c => parent.any fun p => Scope.covers? p c

/-- Pairwise irredundant, matching Scope.Irredundant. -/
def irredundantB (l : List Scope.Grant) : Bool :=
  l.all fun a => l.all fun b => !(Scope.covers? a b) || a == b

/-- Strictly sorted by the rendered string, as grantsAreCanonical requires. -/
def sortedB : List String → Bool
  | x :: y :: rest => decide (x < y) && sortedB (y :: rest)
  | _ => true

def canonicalB (l : List Scope.Grant) : Bool :=
  sortedB (l.map render) && irredundantB l

def lists : List (List Scope.Grant) :=
  [[]] ++ grants.map (fun g => [g]) ++ (grants.flatMap fun g => grants.map fun h => [g, h])

def strs (l : List Scope.Grant) : Json := Json.arr (l.map (fun g => Json.str (render g))).toArray

def coversCases : List Json :=
  grants.flatMap fun p => grants.map fun c =>
    Json.mkObj [("parent", render p), ("child", render c), ("covers", Json.bool (Scope.covers? p c))]

def canonicalCases : List Json :=
  lists.map fun l => Json.mkObj [("grants", strs l), ("canonical", Json.bool (canonicalB l))]

def canonicalLists : List (List Scope.Grant) := lists.filter canonicalB

def narrowsCases : List Json :=
  canonicalLists.flatMap fun p => canonicalLists.map fun c =>
    Json.mkObj [("parent", strs p), ("child", strs c), ("narrows", Json.bool (withinB c p))]

def spends : List Spend.Spend :=
  [.unbounded] ++ (["usd", "eur"].flatMap fun u =>
    [(0, 0), (0, 1), (0, 2), (1, 1), (1, 2), (2, 2)].map fun (p, c) => .bounded u p c)

def spendJson : Spend.Spend → Json
  | .unbounded => Json.mkObj [("mode", "unbounded")]
  | .bounded u p c => Json.mkObj [("mode", "bounded"), ("unit", u),
      ("per_action", toString p), ("cumulative", toString c)]

def spendCases : List Json :=
  spends.flatMap fun parent => spends.map fun child =>
    Json.mkObj [("parent", spendJson parent), ("child", spendJson child),
      ("contained", Json.bool (Spend.le? child parent))]

end Gen

def main : IO Unit := do
  let out := Json.mkObj [
    ("generator", "formal/lean/Vectors.lean"),
    ("note", "Expected values come from deciders proved equal to the declarative relations in APSFormal. Exhaustive over a small universe, not a proof about the TypeScript code."),
    ("scope_covers", Json.arr Gen.coversCases.toArray),
    ("scope_canonical", Json.arr Gen.canonicalCases.toArray),
    ("scope_narrows", Json.arr Gen.narrowsCases.toArray),
    ("spend", Json.arr Gen.spendCases.toArray)]
  IO.println out.pretty
