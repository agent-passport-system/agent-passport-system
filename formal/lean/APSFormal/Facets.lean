import Init

/-!
# Remaining authority facets

Sources inspected locally (line numbers refer to this mirror):
* ~/agent-passport-system/src/v2/authority-delegation/compare.ts, lines 59-93
* Adjacent schema.ts, lines 26-27, 29-37, 60-78, 161-185, 297-346
* Adjacent types.ts, lines 9-11 and 30-55
* draft-pidlisnyi-aps-04.txt, sections 4.2 and 4.3, lines 1818-1964

DISAGREEMENTS
* compare.ts:59-63 implements a strict depth issuance step, not the reflexive
  containment order claimed by section 4.2's closing paragraph. Depth.Le uses
  child.remaining <= parent.remaining. Step.DepthStep separately consumes a hop.
* Section 4.2's time issuance conditions depend on issued_at, not just the time
  facet. Neither is part of Time.Le. compare.ts:65-68 also compares only bounds.
  schema.ts:308-309 checks not_before against issued_at only for non-roots.
* schema.ts:161-173 admits second 60 at 23:59 on a month's last day, whereas
  section 4.3:1936-1940 requires seconds 00-59 and rejects 60 without consulting
  a leap-second table. This is a wire validation disagreement, not a change to Le.
No other disagreement in the non-scope, non-spend containment comparisons on
decoded values represented here. Lean arguments are child then parent. TS uses
parent then child. These are facet comparisons, not a complete chain verifier.

Nat models decoded nonnegative integers and abstract timestamp instants. Exact
JSON keys, number integrality, timestamp syntax/calendar validity and preservation
of canonical timestamp string order by decoding are correspondence obligations.
Lean Char excludes surrogates. WellFormed checks decoded I-JSON noncharacters for
values identifiers. Values canonical ordering uses explicit UTF-16 code units to
model schema.ts:333's JavaScript string comparison, including supplementary chars.
Profile strings remain explicit so that profile changes are incomparable. Schema
validation recognizes only each v1 profile. Reversibility has exactly three
decoded constructors, so malformed/unknown wire ceilings are outside its type.

Le and le? do not perform schema validation. Their order laws need no WellFormed
hypotheses except Values antisymmetry as list equality, which needs canonical
ordering on both lists. Time's interpretation as interval-set containment needs
a nonempty child. Bounds comparison itself is a partial order on all bound pairs.
-/

namespace APS.Facets

namespace Depth

/-- Decoded further-hop ceiling (types.ts:30-33). -/
structure Value where
  remaining : Nat
  deriving DecidableEq, Repr

/-- schema.ts:297-299 restricts remaining to the inclusive range 0-255. -/
def WellFormed (d : Value) : Prop := d.remaining ≤ 255

/-- Reflexive containment, distinct from consuming a delegation hop. -/
-- TS failures: DEPTH_EXHAUSTED and DEPTH_WIDENING, compare.ts:59-63.
-- Those failures decide Step.DepthStep, not this Le (see DISAGREEMENTS).
def Le (child parent : Value) : Prop := child.remaining ≤ parent.remaining

def le? (child parent : Value) : Bool := decide (child.remaining ≤ parent.remaining)

theorem le?_iff (a b : Value) : le? a b = true ↔ Le a b := by
  simp [le?, Le]

theorem le_refl (a : Value) : Le a a := Nat.le_refl _

theorem le_trans {a b c : Value} (hab : Le a b) (hbc : Le b c) : Le a c :=
  Nat.le_trans hab hbc

/-- The range bound is irrelevant to equality from mutual numeric containment. -/
theorem le_antisymm {a b : Value} (hab : Le a b) (hba : Le b a) : a = b := by
  cases a; cases b
  congr
  exact Nat.le_antisymm hab hba

end Depth

namespace Time

/-- Abstract instants, representing the half-open interval [not_before, not_after). -/
structure Value where
  not_before : Nat
  not_after : Nat
  deriving DecidableEq, Repr

/-- schema.ts:306-307 explicitly rejects empty and reversed intervals.
The issued_at check at 308-309 belongs to record issuance, not facet well-formedness. -/
def WellFormed (t : Value) : Prop := t.not_before < t.not_after

/-- Endpoint containment. On nonempty child intervals this is set containment. -/
-- TS failure: TIME_WIDENING, compare.ts:65-68, exactly the negation of these bounds.
def Le (child parent : Value) : Prop :=
  parent.not_before ≤ child.not_before ∧ child.not_after ≤ parent.not_after

def le? (child parent : Value) : Bool :=
  decide (parent.not_before ≤ child.not_before ∧ child.not_after ≤ parent.not_after)

theorem le?_iff (a b : Value) : le? a b = true ↔ Le a b := by
  simp [le?, Le]

theorem le_refl (a : Value) : Le a a := ⟨Nat.le_refl _, Nat.le_refl _⟩

theorem le_trans {a b c : Value} (hab : Le a b) (hbc : Le b c) : Le a c :=
  ⟨Nat.le_trans hbc.1 hab.1, Nat.le_trans hab.2 hbc.2⟩

/-- Endpoint equality needs no nonemptiness assumption. -/
theorem le_antisymm {a b : Value} (hab : Le a b) (hba : Le b a) : a = b := by
  cases a; cases b
  have h₁ := Nat.le_antisymm hba.1 hab.1
  have h₂ := Nat.le_antisymm hab.2 hba.2
  cases h₁; cases h₂
  rfl

/-- Membership is lower-inclusive and upper-exclusive. -/
def Contains (t : Value) (instant : Nat) : Prop :=
  t.not_before ≤ instant ∧ instant < t.not_after

/-- No parent well-formedness is needed. A nonempty child is necessary for the
reverse implication because an empty interval is a subset regardless of bounds. -/
theorem le_iff_interval_subset {child parent : Value} (hc : WellFormed child) :
    Le child parent ↔ ∀ n, Contains child n → Contains parent n := by
  constructor
  · intro h n hn
    exact ⟨Nat.le_trans h.1 hn.1, Nat.lt_of_lt_of_le hn.2 h.2⟩
  · intro h
    have hlo := h child.not_before ⟨Nat.le_refl _, hc⟩
    have hhi := h (child.not_after - 1) (by
      unfold Contains WellFormed at *
      omega)
    unfold Le Contains at *
    omega

/-- Empty intervals are excluded by WellFormed. Endpoint comparison deliberately
does not identify every empty interval, unlike the order on interval sets. -/
theorem empty_interval_case :
    ¬ WellFormed ⟨7, 7⟩ ∧
    (∀ n, Contains ⟨7, 7⟩ n → Contains ⟨0, 5⟩ n) ∧
    ¬ Le ⟨7, 7⟩ ⟨0, 5⟩ := by
  simp [WellFormed, Contains, Le]
  omega

end Time

namespace Reputation

/-- Signed reputation ceiling, not a floor or a resolved reputation score. -/
structure Value where
  profile : String
  ceiling : Nat
  deriving DecidableEq, Repr

/-- schema.ts:312-320 and types.ts:9 recognize the v1 score profile and 0-100. -/
def WellFormed (r : Value) : Prop :=
  r.profile = "aps-score-0-100-v1" ∧ r.ceiling ≤ 100

/-- compare.ts:72 rejects "child.reputation.ceiling > parent.reputation.ceiling".
Section 4.2:1858-1862 likewise says the child ceiling MUST NOT exceed its parent.
The runtime lesser-of-score-and-ceiling rule is separate from containment. -/
-- TS failures: UNSUPPORTED_PROFILE (70-71), REPUTATION_WIDENING (72-73).
def Le (child parent : Value) : Prop :=
  child.profile = parent.profile ∧ child.ceiling ≤ parent.ceiling

def le? (child parent : Value) : Bool :=
  decide (child.profile = parent.profile ∧ child.ceiling ≤ parent.ceiling)

theorem le?_iff (a b : Value) : le? a b = true ↔ Le a b := by
  simp [le?, Le]

theorem le_refl (a : Value) : Le a a := ⟨rfl, Nat.le_refl _⟩

theorem le_trans {a b c : Value} (hab : Le a b) (hbc : Le b c) : Le a c :=
  ⟨hab.1.trans hbc.1, Nat.le_trans hab.2 hbc.2⟩

/-- Neither recognized profiles nor the 100 ceiling are needed for this law. -/
theorem le_antisymm {a b : Value} (hab : Le a b) (hba : Le b a) : a = b := by
  cases a; cases b
  have hp := hab.1
  have hc := Nat.le_antisymm hab.2 hba.2
  cases hp; cases hc
  rfl

end Reputation

namespace Values

/-- Required identifiers, kept as a list to retain canonical representation. -/
structure Value where
  profile : String
  required : List String
  deriving DecidableEq, Repr

/-- JavaScript compares strings lexicographically by UTF-16 code units. -/
def utf16Units (s : String) : List Nat :=
  s.toList.flatMap fun ch =>
    let n := ch.toNat
    if n < 0x10000 then [n]
    else [0xD800 + (n - 0x10000) / 0x400, 0xDC00 + (n - 0x10000) % 0x400]

/-- Nonempty I-JSON identifier, schema.ts:26-27 and record-wide check at 60-78. -/
def IdentifierWellFormed (s : String) : Prop :=
  s ≠ "" ∧ ∀ ch ∈ s.toList,
    ¬ (0xFDD0 ≤ ch.toNat ∧ ch.toNat ≤ 0xFDEF) ∧
    ch.toNat % 0x10000 < 0xFFFE

/-- schema.ts:323-335 requires the recognized profile, admissible identifiers,
and strict sorted uniqueness. No identifier grammar beyond nonempty I-JSON. -/
def WellFormed (v : Value) : Prop :=
  v.profile = "aps-values-identifiers-v1" ∧
  (∀ s ∈ v.required, IdentifierWellFormed s) ∧
  v.required.Pairwise (fun a b => utf16Units a < utf16Units b)

/-- Reverse inclusion of requirements. compare.ts:79-81 rejects a parent identifier
missing from the child. Section 4.2:1864-1868 says a child MAY add identifiers.
This preserves requirements, not evidence of compliance with them. -/
-- TS failures: UNSUPPORTED_PROFILE (76-77), VALUES_WEAKENING (79-81).
def Le (child parent : Value) : Prop :=
  child.profile = parent.profile ∧ ∀ s ∈ parent.required, s ∈ child.required

/-- Mirrors TS's parent.some(!childSet.has) test with list membership. -/
def le? (child parent : Value) : Bool :=
  (child.profile == parent.profile) &&
    parent.required.all (fun s => child.required.contains s)

theorem le?_iff (a b : Value) : le? a b = true ↔ Le a b := by
  simp [le?, Le, List.all_eq_true]

theorem le_refl (a : Value) : Le a a := ⟨rfl, fun _ h => h⟩

theorem le_trans {a b c : Value} (hab : Le a b) (hbc : Le b c) : Le a c :=
  ⟨hab.1.trans hbc.1, fun s hs => hab.2 s (hbc.2 s hs)⟩

/-- Sorted lists with identical members are equal. Only asymmetry of their common
sorting relation is needed, not an injectivity theorem for the string encoding. -/
private theorem eq_of_sorted_mem {r : String → String → Prop}
    (hasymm : ∀ x y, r x y → ¬ r y x) :
    ∀ {a b : List String}, a.Pairwise r → b.Pairwise r →
      (∀ x, x ∈ a ↔ x ∈ b) → a = b
  | [], [], _, _, _ => rfl
  | [], y :: _, _, _, h => by simpa using (h y).2 (List.mem_cons_self y _)
  | x :: _, [], _, _, h => by simpa using (h x).1 (List.mem_cons_self x _)
  | x :: xs, y :: ys, ha, hb, h => by
      rw [List.pairwise_cons] at ha hb
      have hirr : ∀ z, ¬ r z z := fun z hz => hasymm z z hz hz
      have hxy : x = y := by
        by_cases hxy : x = y
        · exact hxy
        · exfalso
          have hx := (h x).1 (List.mem_cons_self x _)
          have hy := (h y).2 (List.mem_cons_self y _)
          rcases List.mem_cons.mp hx with hx | hx
          · exact hxy hx
          rcases List.mem_cons.mp hy with hy | hy
          · exact hxy hy.symm
          exact hasymm y x (hb.1 x hx) (ha.1 y hy)
      subst hxy
      have htail : ∀ z, z ∈ xs ↔ z ∈ ys := by
        intro z
        constructor
        · intro hz
          rcases List.mem_cons.mp ((h z).1 (List.mem_cons_of_mem _ hz)) with e | e
          · subst e; exact absurd (ha.1 z hz) (hirr z)
          · exact e
        · intro hz
          rcases List.mem_cons.mp ((h z).2 (List.mem_cons_of_mem _ hz)) with e | e
          · subst e; exact absurd (hb.1 z hz) (hirr z)
          · exact e
      rw [eq_of_sorted_mem hasymm ha.2 hb.2 htail]

/-- Canonical order on both lists is essential for equality, since TS's set test
ignores permutations and duplicates. Other WellFormed clauses are not used. -/
theorem le_antisymm {a b : Value} (ha : WellFormed a) (hb : WellFormed b)
    (hab : Le a b) (hba : Le b a) : a = b := by
  have hasymm : ∀ x y : String,
      utf16Units x < utf16Units y → ¬ utf16Units y < utf16Units x := by
    intro x y hxy hyx
    exact List.lt_irrefl Nat.lt_irrefl _
      (List.lt_trans Nat.lt_trans (by omega) hxy hyx)
  have hr : a.required = b.required :=
    eq_of_sorted_mem hasymm ha.2.2 hb.2.2 fun s => ⟨hba.2 s, hab.2 s⟩
  cases a; cases b
  have hp := hab.1
  cases hp; cases hr
  rfl

/-- Without canonicality, mutual containment alone does not give list equality. -/
theorem noncanonical_counterexample :
    Le ⟨"aps-values-identifiers-v1", ["a", "a"]⟩ ⟨"aps-values-identifiers-v1", ["a"]⟩ ∧
    Le ⟨"aps-values-identifiers-v1", ["a"]⟩ ⟨"aps-values-identifiers-v1", ["a", "a"]⟩ ∧
    (Value.mk "aps-values-identifiers-v1" ["a", "a"] ≠
      Value.mk "aps-values-identifiers-v1" ["a"]) := by
  simp [Le]

end Values

namespace Reversibility

/-- Closed wire classes, types.ts:50, ordered narrowest to widest. -/
inductive Class where
  | tentative
  | compensable
  | irreversible
  deriving DecidableEq, Repr

def rank : Class → Nat
  | .tentative => 0
  | .compensable => 1
  | .irreversible => 2

structure Value where
  profile : String
  ceiling : Class
  deriving DecidableEq, Repr

/-- schema.ts:338-346 recognizes aps-tci-v1 and exactly the three constructors. -/
def WellFormed (r : Value) : Prop := r.profile = "aps-tci-v1"

/-- compare.ts:14-18 and 88-91 order tentative < compensable < irreversible,
as does section 4.2:1870-1875. Unknown action classifications being treated as
irreversible is a runtime rule, not permission for unknown signed ceilings. -/
-- TS failures: UNSUPPORTED_PROFILE (85-86), REVERSIBILITY_WIDENING (88-91).
-- Null ranks in TS reject malformed wire ceilings, outside this decoded type.
def Le (child parent : Value) : Prop :=
  child.profile = parent.profile ∧ rank child.ceiling ≤ rank parent.ceiling

def le? (child parent : Value) : Bool :=
  decide (child.profile = parent.profile ∧ rank child.ceiling ≤ rank parent.ceiling)

theorem le?_iff (a b : Value) : le? a b = true ↔ Le a b := by
  simp [le?, Le]

theorem le_refl (a : Value) : Le a a := ⟨rfl, Nat.le_refl _⟩

theorem le_trans {a b c : Value} (hab : Le a b) (hbc : Le b c) : Le a c :=
  ⟨hab.1.trans hbc.1, Nat.le_trans hab.2 hbc.2⟩

/-- Distinct decoded classes have distinct ranks. No profile validation is needed. -/
theorem le_antisymm {a b : Value} (hab : Le a b) (hba : Le b a) : a = b := by
  have hr := Nat.le_antisymm hab.2 hba.2
  have hc : a.ceiling = b.ceiling := by
    cases ha : a.ceiling <;> cases hb : b.ceiling <;> simp_all [rank]
  cases a; cases b
  have hp := hab.1
  cases hp; cases hc
  rfl

end Reversibility

namespace Step

/-- Strict issuance condition, kept separate from reflexive Depth.Le. -/
def DepthStep (child parent : Depth.Value) : Prop :=
  0 < parent.remaining ∧ child.remaining + 1 ≤ parent.remaining

theorem depthStep_implies_le {child parent : Depth.Value}
    (h : DepthStep child parent) : Depth.Le child parent := by
  unfold DepthStep Depth.Le at *
  omega

/-- An identical depth facet cannot be delegated, even though it contains itself. -/
theorem not_depthStep_self (d : Depth.Value) : ¬ DepthStep d d := by
  unfold DepthStep
  omega

/-- Successful TS depth comparison: parent is nonzero, child <= parent - 1.
Nat subtraction matches that branch only after its nonzero-parent guard. -/
theorem depthStep_iff_ts (child parent : Depth.Value) :
    DepthStep child parent ↔
      parent.remaining ≠ 0 ∧ child.remaining ≤ parent.remaining - 1 := by
  unfold DepthStep
  omega

end Step
end APS.Facets

#print axioms APS.Facets.Depth.le?_iff
#print axioms APS.Facets.Depth.le_refl
#print axioms APS.Facets.Depth.le_trans
#print axioms APS.Facets.Depth.le_antisymm
#print axioms APS.Facets.Time.le?_iff
#print axioms APS.Facets.Time.le_refl
#print axioms APS.Facets.Time.le_trans
#print axioms APS.Facets.Time.le_antisymm
#print axioms APS.Facets.Time.le_iff_interval_subset
#print axioms APS.Facets.Time.empty_interval_case
#print axioms APS.Facets.Reputation.le?_iff
#print axioms APS.Facets.Reputation.le_refl
#print axioms APS.Facets.Reputation.le_trans
#print axioms APS.Facets.Reputation.le_antisymm
#print axioms APS.Facets.Values.le?_iff
#print axioms APS.Facets.Values.le_refl
#print axioms APS.Facets.Values.le_trans
#print axioms APS.Facets.Values.le_antisymm
#print axioms APS.Facets.Values.noncanonical_counterexample
#print axioms APS.Facets.Reversibility.le?_iff
#print axioms APS.Facets.Reversibility.le_refl
#print axioms APS.Facets.Reversibility.le_trans
#print axioms APS.Facets.Reversibility.le_antisymm
#print axioms APS.Facets.Step.depthStep_implies_le
#print axioms APS.Facets.Step.not_depthStep_self
#print axioms APS.Facets.Step.depthStep_iff_ts
