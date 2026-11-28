import Init

/-!
# Spend containment

Sources inspected locally:
* ~/agent-passport-system/src/v2/authority-delegation/compare.ts,
  compareAuthority's spend branch
* The adjacent schema.ts (spend validation, isCanonicalQuantity,
  isAdmissibleIdentifier, and isIJSONString) and types.ts (SpendFacetV1)
* draft-pidlisnyi-aps-04.txt, section 4.2, Spend

DISAGREEMENTS
None in the spend containment comparison on values represented by this model.
Lean takes child then parent. TypeScript compareAuthority takes parent then child.
The actual unit failure code is SPEND_UNIT_CHANGE, not UNIT_MISMATCH (the latter
belongs to budget operations). Unit mismatch takes precedence over limit widening.

This is a model of decoded spend values, not a verified JSON decoder or a proof
about TypeScript execution. Nat represents unsigned amounts. WellFormed captures
the quantity ceiling, per-action/cumulative invariant, nonempty unit, and I-JSON
noncharacter exclusions. Lean Char already excludes surrogate code points.
The wire layer must enforce canonical decimal strings matching (0|[1-9][0-9]*),
correct JSON types, exact object keys, recognized mode tags, and valid Unicode
decoding. The inspected schema imposes no further unit grammar or normalization.
Unit equality here is exact string equality, with no conversion.

Le and le? intentionally do not validate WellFormed, just as compareAuthority's
spend branch does not validate the schema. Malformed wire values, including
strings on which BigInt throws, are outside this representation. These theorems
do not establish live accounting, reservations, or subtree budget enforcement.
-/

namespace APS.Spend

/-- Decoded spend ceiling. Bounded amounts are expressed in one exact unit. -/
inductive Spend where
  | unbounded
  | bounded (unit : String) (perAction cumulative : Nat)
  deriving DecidableEq

open Spend

/-- Schema invariants expressible on decoded spend values. -/
def WellFormed : Spend → Prop
  | unbounded => True
  | bounded unit perAction cumulative =>
      unit ≠ "" ∧
      (∀ ch ∈ unit.toList,
        ¬ (0xFDD0 ≤ ch.toNat ∧ ch.toNat ≤ 0xFDEF) ∧
        ch.toNat % 0x10000 < 0xFFFE) ∧
      perAction ≤ cumulative ∧
      perAction ≤ 9223372036854775807 ∧
      cumulative ≤ 9223372036854775807

/-- Child containment, independent of schema validation. Unbounded is greatest. -/
def Le : Spend → Spend → Prop
  | _, unbounded => True
  | unbounded, bounded _ _ _ => False
  | bounded u p c, bounded v q d => u = v ∧ p ≤ q ∧ c ≤ d

/-- Executable spend comparison, in child/parent order, following the TS branches. -/
def le? : Spend → Spend → Bool
  | _, unbounded => true
  | unbounded, bounded _ _ _ => false
  | bounded u p c, bounded v q d =>
      if u ≠ v then false
      else if p > q ∨ c > d then false
      else true

/-- The executable comparison decides precisely the containment proposition. -/
-- TS failure cases: SPEND_WIDENING for unbounded under bounded or larger limits,
-- SPEND_UNIT_CHANGE for unequal bounded units, checked before numeric widening.
theorem le?_iff (a b : Spend) : le? a b = true ↔ Le a b := by
  cases a <;> cases b <;> simp [le?, Le, Nat.not_lt]

/-- Every ceiling contains itself, including ceilings outside the schema bounds. -/
-- TS spend branch: no failure for identical child and parent.
theorem le_refl (a : Spend) : Le a a := by
  cases a <;> simp [Le]

/-- Containment composes along a chain. -/
-- TS spend branch: no failure for the composed comparison when both premises hold.
theorem le_trans {a b c : Spend} (hab : Le a b) (hbc : Le b c) : Le a c := by
  cases a with
  | unbounded =>
      cases b <;> cases c <;> simp_all [Le]
  | bounded u p x =>
      cases b with
      | unbounded => cases c <;> simp_all [Le]
      | bounded v q y =>
          cases c with
          | unbounded => trivial
          | bounded w r z =>
              exact ⟨hab.1.trans hbc.1,
                Nat.le_trans hab.2.1 hbc.2.1, Nat.le_trans hab.2.2 hbc.2.2⟩

/-- Mutual containment implies equality. No WellFormed hypotheses are needed. -/
-- TS spend branch: two successful directions force identical decoded ceilings.
theorem le_antisymm {a b : Spend} (hab : Le a b) (hba : Le b a) : a = b := by
  cases a with
  | unbounded => cases b <;> simp_all [Le]
  | bounded u p c =>
      cases b with
      | unbounded => exact False.elim hba
      | bounded v q d =>
          have hu : u = v := hab.1
          have hp : p = q := Nat.le_antisymm hab.2.1 hba.2.1
          have hc : c = d := Nat.le_antisymm hab.2.2 hba.2.2
          cases hu
          cases hp
          cases hc
          rfl

/-- Every spend ceiling is contained in an unbounded parent. -/
-- TS spend branch: no failure, since an unbounded parent bypasses all spend checks.
theorem unbounded_top (s : Spend) : Le s unbounded := by
  cases s <;> trivial

/-- An unbounded child widens every bounded parent. -/
-- TS failure code: SPEND_WIDENING.
theorem unbounded_not_le_bounded (u : String) (p c : Nat) :
    ¬ Le unbounded (bounded u p c) := by
  exact id

/-- Different bounded units are incomparable, regardless of their numeric limits. -/
-- TS failure code: SPEND_UNIT_CHANGE, even when a numeric limit also widens.
theorem unit_mismatch {u v : String} {p c q d : Nat} (h : u ≠ v) :
    ¬ Le (bounded u p c) (bounded v q d) := by
  intro hle
  exact h hle.1

/-- In a common unit, increasing either limit violates containment. -/
-- TS failure code: SPEND_WIDENING (the units here are equal).
theorem limit_widening {u : String} {p c q d : Nat} (h : q < p ∨ d < c) :
    ¬ Le (bounded u p c) (bounded u q d) := by
  intro hle
  cases h with
  | inl hp => exact (Nat.not_lt_of_ge hle.2.1) hp
  | inr hc => exact (Nat.not_lt_of_ge hle.2.2) hc

end APS.Spend

#print axioms APS.Spend.le?_iff
#print axioms APS.Spend.le_refl
#print axioms APS.Spend.le_trans
#print axioms APS.Spend.le_antisymm
#print axioms APS.Spend.unbounded_top
#print axioms APS.Spend.unbounded_not_le_bounded
#print axioms APS.Spend.unit_mismatch
#print axioms APS.Spend.limit_widening
