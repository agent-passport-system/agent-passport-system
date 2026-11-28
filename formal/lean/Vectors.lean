/-
Differential corpus generator. Run from formal/lean:
  lake env lean --run Vectors.lean > ../../tests/v2/fixtures/lean-correspondence.json

Expected values come from these deciders, each proved equal to its relation:
  covers?      Scope.covers?_iff      (single grant coverage)
  within?      Scope.within?_iff      (list containment)
  irredundant? Scope.irredundant?_iff (no grant covers another in the same list)
  Spend.le?    Spend.le?_iff
The one unproved piece is `sortedB`, the strict adjacent string order used as the
sorting half of grantsAreCanonical. The string rendering of a grant is also a
correspondence obligation, not a theorem.

The corpus is exhaustive over a small universe. Segments "a", "b", "ab" and "A" catch
character-prefix matching without a colon boundary and case handling. Paths of depth
three catch implementations that check only the first and the full prefix. A pass means
the SDK agrees with the model on these cases, not on every input.
-/
import Lean.Data.Json
import APSFormal.Scope
import APSFormal.Spend

open Lean APS

namespace Gen

def render : Scope.Grant → String
  | .any => "*"
  | .exact p => ":".intercalate p
  | .sub p => ":".intercalate p ++ ":*"

def grantsOf (paths : List (List String)) : List Scope.Grant :=
  [.any] ++ paths.map .exact ++ paths.map .sub

/-- Wide universe for single-grant coverage. -/
def wideSegs : List String := ["a", "b", "ab", "A"]

def widePaths : List (List String) :=
  (wideSegs.map fun x => [x]) ++ (wideSegs.flatMap fun x => wideSegs.map fun y => [x, y]) ++
  [["a", "b", "a"], ["a", "b", "ab"], ["ab", "a", "b"], ["a", "a", "a"]]

def wideGrants : List Scope.Grant := grantsOf widePaths

/-- Small universe for lists. -/
def smallSegs : List String := ["a", "b"]

def smallPaths : List (List String) :=
  (smallSegs.map fun x => [x]) ++ (smallSegs.flatMap fun x => smallSegs.map fun y => [x, y])

def smallGrants : List Scope.Grant := grantsOf smallPaths

/-- Strictly increasing by string order. Not proved equal to List.Pairwise. -/
def sortedB : List String → Bool
  | x :: y :: rest => decide (x < y) && sortedB (y :: rest)
  | _ => true

def canonicalB (l : List Scope.Grant) : Bool :=
  sortedB (l.map render) && Scope.irredundant? l

def smallLists : List (List Scope.Grant) :=
  [[]] ++ smallGrants.map (fun g => [g]) ++
    (smallGrants.flatMap fun g => smallGrants.map fun h => [g, h])

/-- Targeted lists of three, so a loop that stops early over child grants is caught. -/
def tripleLists : List (List Scope.Grant) :=
  [ [.exact ["a"], .exact ["b", "a"], .exact ["b", "b"]],
    [.exact ["a"], .sub ["b", "a"], .exact ["b", "b"]],
    [.sub ["a"], .exact ["b", "a"], .sub ["b", "b"]],
    [.exact ["a", "a"], .exact ["a", "b"], .exact ["b"]] ]

def lists : List (List Scope.Grant) := smallLists ++ tripleLists

def canonicalLists : List (List Scope.Grant) := lists.filter canonicalB

def strs (l : List Scope.Grant) : Json := Json.arr (l.map (fun g => Json.str (render g))).toArray

def coversCases : List Json :=
  wideGrants.flatMap fun p => wideGrants.map fun c =>
    Json.mkObj [("parent", render p), ("child", render c), ("covers", Json.bool (Scope.covers? p c))]

def canonicalCases : List Json :=
  lists.map fun l => Json.mkObj [("grants", strs l), ("canonical", Json.bool (canonicalB l))]

/-- Parents are canonical, as on the verifier path. Children are every list, canonical or
not, since fastNarrows_iff needs only well-formed parent grants. -/
def narrowsCases : List Json :=
  canonicalLists.flatMap fun p => lists.map fun c =>
    Json.mkObj [("parent", strs p), ("child", strs c),
      ("child_canonical", Json.bool (canonicalB c)), ("narrows", Json.bool (Scope.within? c p))]

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
    ("note", "Expected values come from deciders proved equal to their relations in APSFormal (covers?, within?, irredundant?, Spend.le?), except the string sort check. Exhaustive over a small universe, not a proof about the TypeScript code."),
    ("scope_covers", Json.arr Gen.coversCases.toArray),
    ("scope_canonical", Json.arr Gen.canonicalCases.toArray),
    ("scope_narrows", Json.arr Gen.narrowsCases.toArray),
    ("spend", Json.arr Gen.spendCases.toArray)]
  IO.println out.compress
