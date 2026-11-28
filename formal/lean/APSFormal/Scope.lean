/-
APS formal model, F1a: the Scope facet.

Mirrors agent-passport-system src/v2/authority-delegation/scope.ts (isValidScopeGrant,
scopeGrantCovers, grantsAreCanonical, scopeNarrows) and draft-pidlisnyi-aps-04 section 4.2.

Abstraction. A grant string is modelled after it is split on ':'.
  "*"        -> Grant.any
  "a:b"      -> Grant.exact ["a", "b"]
  "a:b:*"    -> Grant.sub   ["a", "b"]
The wire layer (ASCII check, no empty segment, no '*' inside a segment, split and join
on ':') is a correspondence obligation for the differential tests, not proved here.
Because a valid segment never contains ':', the TS string test
"C starts with P + ':'" is the list test "P is a whole-segment prefix of C". That
equivalence is also left to the wire layer.

What is proved here, without sorry and with no extra axioms:
  1. coverage between single grants is reflexive, transitive and antisymmetric
  2. the executable `covers?` agrees with `Covers`
  3. list containment (every child grant covered by some parent grant) is reflexive
     and transitive on any lists
  4. on irredundant lists (no grant covers a different grant of the same list) list
     containment is antisymmetric up to membership, and on lists that are also strictly
     sorted by any asymmetric order it is antisymmetric as list equality. This answers
     the open question in the 2026-11-27 section 4.2 memo for the abstract model.
  5. the fast candidate-prefix check of scopeNarrows agrees with the pairwise
     definition whenever every parent grant is well formed. Unlike the TS comment, this
     needs no canonical form on either list.
-/

namespace APS.Scope

inductive Grant where
  | any
  | exact (p : List String)
  | sub (p : List String)
  deriving DecidableEq, Repr

/-- Well formed: an exact or subtree grant has at least one segment. -/
def Grant.WF : Grant → Prop
  | .any => True
  | .exact p => p ≠ []
  | .sub p => p ≠ []

/-- Whole-segment prefix. -/
def Pre (p c : List String) : Prop := ∃ t, c = p ++ t

/-- The segments a covering subtree grant is compared against. TS: the child with a
trailing ":*" removed. The bare wildcard has none, so no subtree grant covers it. -/
def Grant.path? : Grant → Option (List String)
  | .any => none
  | .exact p => some p
  | .sub p => some p

/-- scopeGrantCovers(parent, child). -/
def Covers : Grant → Grant → Prop
  | .any, _ => True
  | .exact p, c => c = .exact p
  | .sub p, c => ∃ q, c.path? = some q ∧ Pre p q

/-! ### Prefix lemmas -/

theorem pre_refl (p : List String) : Pre p p := ⟨[], by simp⟩

theorem pre_trans {a b c : List String} : Pre a b → Pre b c → Pre a c := by
  rintro ⟨t, rfl⟩ ⟨s, rfl⟩
  exact ⟨t ++ s, by simp⟩

theorem pre_antisymm {a b : List String} : Pre a b → Pre b a → a = b := by
  rintro ⟨t, rfl⟩ ⟨s, h⟩
  have hl := congrArg List.length h
  simp only [List.length_append] at hl
  have ht : t = [] := List.eq_nil_of_length_eq_zero (by omega)
  simp [ht]

def pre? : List String → List String → Bool
  | [], _ => true
  | _ :: _, [] => false
  | x :: xs, y :: ys => x == y && pre? xs ys

theorem pre?_iff : ∀ (p c : List String), pre? p c = true ↔ Pre p c
  | [], c => by simp [pre?, Pre]
  | x :: xs, [] => by
      simp [pre?, Pre]
  | x :: xs, y :: ys => by
      simp only [pre?, Bool.and_eq_true, beq_iff_eq, pre?_iff xs ys, Pre]
      constructor
      · rintro ⟨rfl, t, rfl⟩; exact ⟨t, rfl⟩
      · rintro ⟨t, h⟩
        simp at h
        exact ⟨h.1.symm, t, h.2⟩

/-! ### Single grant coverage -/

theorem covers_refl : ∀ g : Grant, Covers g g
  | .any => trivial
  | .exact _ => rfl
  | .sub p => ⟨p, rfl, pre_refl p⟩

theorem covers_trans : ∀ {a b c : Grant}, Covers a b → Covers b c → Covers a c
  | .any, _, _, _, _ => trivial
  | .exact p, b, c, hab, hbc => by
      simp only [Covers] at hab; subst hab; exact hbc
  | .sub p, .any, c, hab, _ => by
      obtain ⟨q, hq, _⟩ := hab; simp [Grant.path?] at hq
  | .sub p, .exact q, c, hab, hbc => by
      simp only [Covers] at hbc; subst hbc; exact hab
  | .sub p, .sub q, c, hab, hbc => by
      obtain ⟨q', hq', hpq⟩ := hab
      simp [Grant.path?] at hq'; subst hq'
      obtain ⟨r, hr, hqr⟩ := hbc
      exact ⟨r, hr, pre_trans hpq hqr⟩

theorem covers_antisymm : ∀ {a b : Grant}, Covers a b → Covers b a → a = b
  | .any, .any, _, _ => rfl
  | .any, .exact _, _, h => by simp [Covers] at h
  | .any, .sub _, _, h => by obtain ⟨q, hq, _⟩ := h; simp [Grant.path?] at hq
  | .exact _, _, h, _ => by simp only [Covers] at h; exact h.symm
  | .sub _, .any, h, _ => by obtain ⟨q, hq, _⟩ := h; simp [Grant.path?] at hq
  | .sub _, .exact _, _, h => by simp [Covers] at h
  | .sub p, .sub q, h1, h2 => by
      obtain ⟨q', hq', hpq⟩ := h1
      obtain ⟨p', hp', hqp⟩ := h2
      simp [Grant.path?] at hq' hp'
      subst hq'; subst hp'
      rw [pre_antisymm hpq hqp]

def covers? : Grant → Grant → Bool
  | .any, _ => true
  | .exact p, c => c == .exact p
  | .sub p, c => match c.path? with
      | none => false
      | some q => pre? p q

theorem covers?_iff (a b : Grant) : covers? a b = true ↔ Covers a b := by
  cases a with
  | any => simp [covers?, Covers]
  | exact p => simp [covers?, Covers]
  | sub p =>
    cases b with
    | any => simp [covers?, Covers, Grant.path?]
    | exact q => simp [covers?, Covers, Grant.path?, pre?_iff]
    | sub q => simp [covers?, Covers, Grant.path?, pre?_iff]

instance (a b : Grant) : Decidable (Covers a b) :=
  decidable_of_iff _ (covers?_iff a b)

/-! ### Grant lists -/

/-- scopeNarrows read pairwise: every child grant is covered by some parent grant. -/
def Within (child parent : List Grant) : Prop :=
  ∀ c ∈ child, ∃ p ∈ parent, Covers p c

theorem within_refl (l : List Grant) : Within l l :=
  fun c hc => ⟨c, hc, covers_refl c⟩

theorem within_trans {a b c : List Grant} : Within a b → Within b c → Within a c := by
  intro hab hbc x hx
  obtain ⟨y, hy, hyx⟩ := hab x hx
  obtain ⟨z, hz, hzy⟩ := hbc y hy
  exact ⟨z, hz, covers_trans hzy hyx⟩

/-- No grant in the list covers a different grant of the same list
(the antichain part of grantsAreCanonical). -/
def Irredundant (l : List Grant) : Prop :=
  ∀ a ∈ l, ∀ b ∈ l, Covers a b → a = b

theorem within_antisymm_mem {a b : List Grant} (ha : Irredundant a)
    (hab : Within a b) (hba : Within b a) : ∀ x, x ∈ a → x ∈ b := by
  intro x hx
  obtain ⟨y, hy, hyx⟩ := hab x hx
  obtain ⟨x', hx', hx'y⟩ := hba y hy
  have hx'x : Covers x' x := covers_trans hx'y hyx
  have : x' = x := ha x' hx' x hx hx'x
  subst this
  have : y = x' := covers_antisymm hyx hx'y
  subst this
  exact hy

/-- Two lists, each strictly sorted by the same asymmetric relation, with the same
members, are equal. TS sorts grants by string order. -/
theorem eq_of_sorted_mem {r : Grant → Grant → Prop} (hasymm : ∀ x y, r x y → ¬ r y x) :
    ∀ {a b : List Grant}, a.Pairwise r → b.Pairwise r → (∀ x, x ∈ a ↔ x ∈ b) → a = b
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
          have hx : x ∈ y :: ys := (h x).1 (List.mem_cons_self x _)
          have hy : y ∈ x :: xs := (h y).2 (List.mem_cons_self y _)
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

/-- Antisymmetry of scope containment on canonical lists: irredundant and strictly
sorted by an asymmetric order. -/
theorem within_antisymm {r : Grant → Grant → Prop} (hasymm : ∀ x y, r x y → ¬ r y x)
    {a b : List Grant} (sa : a.Pairwise r) (sb : b.Pairwise r)
    (ia : Irredundant a) (ib : Irredundant b)
    (hab : Within a b) (hba : Within b a) : a = b :=
  eq_of_sorted_mem hasymm sa sb fun x =>
    ⟨within_antisymm_mem ia hab hba x, within_antisymm_mem ib hba hab x⟩

/-- The counterexample from the consult: without irredundancy, ["a", "a:*"] and ["a:*"]
contain each other but differ. -/
example : Within [.exact ["a"], .sub ["a"]] [.sub ["a"]] ∧
    Within [.sub ["a"]] [.exact ["a"], .sub ["a"]] ∧
    ([Grant.exact ["a"], .sub ["a"]] ≠ [.sub ["a"]]) := by
  refine ⟨?_, ?_, by decide⟩
  · intro c hc
    simp at hc
    rcases hc with rfl | rfl
    · exact ⟨.sub ["a"], by simp, ["a"], rfl, pre_refl _⟩
    · exact ⟨.sub ["a"], by simp, ["a"], rfl, pre_refl _⟩
  · intro c hc
    simp at hc; subst hc
    exact ⟨.sub ["a"], by simp, ["a"], rfl, pre_refl _⟩

/-! ### The fast check in scopeNarrows -/

/-- One child grant, checked the way scopeNarrows does: the parent holds "*", or the
child itself, or "Q:*" for a whole-segment prefix Q of the child's path with at least
one segment. -/
def FastCovered (parent : List Grant) (c : Grant) : Prop :=
  Grant.any ∈ parent ∨ c ∈ parent ∨
    ∃ q, c.path? = some q ∧ ∃ m, 1 ≤ m ∧ m ≤ q.length ∧ Grant.sub (q.take m) ∈ parent

theorem fast_iff (parent : List Grant) (hwf : ∀ p ∈ parent, p.WF) (c : Grant) :
    FastCovered parent c ↔ ∃ p ∈ parent, Covers p c := by
  constructor
  · rintro (h | h | ⟨q, hq, m, _, hm, hsub⟩)
    · exact ⟨.any, h, trivial⟩
    · exact ⟨c, h, covers_refl c⟩
    · refine ⟨.sub (q.take m), hsub, q, hq, q.drop m, ?_⟩
      simp
  · rintro ⟨p, hp, hpc⟩
    cases p with
    | any => exact Or.inl hp
    | exact p =>
      simp only [Covers] at hpc; subst hpc
      exact Or.inr (Or.inl hp)
    | sub p =>
      obtain ⟨q, hq, t, rfl⟩ := hpc
      have hne : p ≠ [] := hwf _ hp
      have hlen : 1 ≤ p.length := by
        cases p with
        | nil => exact absurd rfl hne
        | cons _ _ => simp
      refine Or.inr (Or.inr ⟨p ++ t, hq, p.length, hlen, by simp, ?_⟩)
      simpa using hp

/-- Whole-list form: the fast scopeNarrows check equals the pairwise definition when
every parent grant is well formed. -/
theorem fastNarrows_iff (parent child : List Grant) (hwf : ∀ p ∈ parent, p.WF) :
    (∀ c ∈ child, FastCovered parent c) ↔ Within child parent := by
  constructor
  · intro h c hc; exact (fast_iff parent hwf c).1 (h c hc)
  · intro h c hc; exact (fast_iff parent hwf c).2 (h c hc)

/-! ### The fast redundancy check in grantsAreCanonical -/

/-- grantsAreCanonical's redundancy pass: for every grant other than "*", the list does
not hold "*", and every candidate "Q:*" built from a whole-segment prefix Q of the
grant's path that is in the list is the grant itself. -/
def FastIrredundant (l : List Grant) : Prop :=
  ∀ g ∈ l, g ≠ .any →
    Grant.any ∉ l ∧ ∀ q, g.path? = some q → ∀ m, 1 ≤ m → m ≤ q.length →
      Grant.sub (q.take m) ∈ l → Grant.sub (q.take m) = g

theorem fastIrredundant_iff (l : List Grant) (hwf : ∀ g ∈ l, g.WF) :
    FastIrredundant l ↔ Irredundant l := by
  constructor
  · intro h a ha b hb hab
    cases a with
    | any =>
      by_cases hb' : b = .any
      · exact hb'.symm
      · exact absurd ha (h b hb hb').1
    | exact p =>
      simp only [Covers] at hab; exact hab.symm
    | sub p =>
      obtain ⟨q, hq, t, rfl⟩ := hab
      have hbany : b ≠ .any := by intro e; subst e; simp [Grant.path?] at hq
      have hne : p ≠ [] := hwf _ ha
      have hlen : 1 ≤ p.length := by
        cases p with
        | nil => exact absurd rfl hne
        | cons _ _ => simp
      have := (h b hb hbany).2 (p ++ t) hq p.length hlen (by simp) (by simpa using ha)
      simpa using this
  · intro h g hg hgany
    refine ⟨fun hany => hgany (h _ hany g hg trivial).symm, ?_⟩
    intro q hq m _ hm hmem
    exact h _ hmem g hg ⟨q, hq, q.drop m, by simp⟩

/-! ### Executable list checks used by the corpus generator -/

def within? (child parent : List Grant) : Bool :=
  child.all fun c => parent.any fun p => covers? p c

theorem within?_iff (child parent : List Grant) : within? child parent = true ↔ Within child parent := by
  simp [within?, Within, List.all_eq_true, List.any_eq_true, covers?_iff]

def irredundant? (l : List Grant) : Bool :=
  l.all fun a => l.all fun b => !(covers? a b) || a == b

theorem irredundant?_iff (l : List Grant) : irredundant? l = true ↔ Irredundant l := by
  simp only [irredundant?, Irredundant, List.all_eq_true, Bool.or_eq_true, Bool.not_eq_true',
    beq_iff_eq]
  constructor
  · intro h a ha b hb hab
    rcases h a ha b hb with h' | h'
    · rw [(covers?_iff a b).2 hab] at h'; exact absurd h' (by decide)
    · exact h'
  · intro h a ha b hb
    by_cases hc : covers? a b = true
    · exact Or.inr (h a ha b hb ((covers?_iff a b).1 hc))
    · exact Or.inl (by simpa using hc)

end APS.Scope

#print axioms APS.Scope.within?_iff
#print axioms APS.Scope.irredundant?_iff
#print axioms APS.Scope.fastIrredundant_iff
#print axioms APS.Scope.covers_refl
#print axioms APS.Scope.covers_trans
#print axioms APS.Scope.covers_antisymm
#print axioms APS.Scope.covers?_iff
#print axioms APS.Scope.within_refl
#print axioms APS.Scope.within_trans
#print axioms APS.Scope.within_antisymm
#print axioms APS.Scope.fastNarrows_iff
