/-
APS formal model, F2, F4 and F3: the seven-facet authority vector, one delegation
step, and chains of steps.

Mirrors draft-pidlisnyi-aps-04 section 4.2 and agent-passport-system
src/v2/authority-delegation (compare.ts compareAuthority, verify.ts
verifyAuthorityDelegationChain structural phases).

F2. Containment of authority vectors (`Le`) is the componentwise product of the
reflexive facet orders. It is reflexive and transitive, and antisymmetric on
canonical vectors (scope grants irredundant and strictly sorted, values well formed).

F4. A valid delegation step (`ValidStep`) uses the strict depth step and the time
issuance conditions instead of reflexive depth. A valid step implies containment.
Containment does not imply a valid step: no record is a valid step from itself.
This is the distinction the 2026-11-27 section 4.2 memo asks draft-05 to state.

F3. In a chain where every adjacent pair is a valid step, every later record is
contained in every earlier one, and depth falls by at least one per hop, so a chain
has at most root.remaining + 1 records. With remaining at most 255 (schema.ts) that
is at most 256 records, the verifier's ceiling in verify.ts, and a 256-record chain
exists.

Not modelled here: signatures, identifiers, parent linkage by delegation_id,
current validity at verification time, revocation (F5), the spend ledger (F7) and
action admission (F6).
-/
import APSFormal.Scope
import APSFormal.Spend
import APSFormal.Facets

namespace APS.Authority

open APS.Facets

structure ScopeFacet where
  profile : String
  grants : List Scope.Grant

structure Value where
  scope : ScopeFacet
  spend : Spend.Spend
  depth : Depth.Value
  time : Time.Value
  reputation : Reputation.Value
  values : Values.Value
  reversibility : Reversibility.Value

/-- Every facet except depth, shared by containment and by a valid step.
compare.ts checks the scope profile first (SCOPE_PROFILE_CHANGE), then coverage. -/
def LeExceptDepth (child parent : Value) : Prop :=
  child.scope.profile = parent.scope.profile ∧
  Scope.Within child.scope.grants parent.scope.grants ∧
  Spend.Le child.spend parent.spend ∧
  Time.Le child.time parent.time ∧
  Reputation.Le child.reputation parent.reputation ∧
  Values.Le child.values parent.values ∧
  Reversibility.Le child.reversibility parent.reversibility

/-- F2. Authority containment: the reflexive product order. -/
def Le (child parent : Value) : Prop :=
  LeExceptDepth child parent ∧ Depth.Le child.depth parent.depth

theorem leExceptDepth_refl (a : Value) : LeExceptDepth a a :=
  ⟨rfl, Scope.within_refl _, Spend.le_refl _, Time.le_refl _, Reputation.le_refl _,
    Values.le_refl _, Reversibility.le_refl _⟩

theorem leExceptDepth_trans {a b c : Value} (hab : LeExceptDepth a b)
    (hbc : LeExceptDepth b c) : LeExceptDepth a c :=
  ⟨hab.1.trans hbc.1, Scope.within_trans hab.2.1 hbc.2.1,
    Spend.le_trans hab.2.2.1 hbc.2.2.1, Time.le_trans hab.2.2.2.1 hbc.2.2.2.1,
    Reputation.le_trans hab.2.2.2.2.1 hbc.2.2.2.2.1,
    Values.le_trans hab.2.2.2.2.2.1 hbc.2.2.2.2.2.1,
    Reversibility.le_trans hab.2.2.2.2.2.2 hbc.2.2.2.2.2.2⟩

theorem le_refl (a : Value) : Le a a := ⟨leExceptDepth_refl a, Depth.le_refl _⟩

theorem le_trans {a b c : Value} (hab : Le a b) (hbc : Le b c) : Le a c :=
  ⟨leExceptDepth_trans hab.1 hbc.1, Depth.le_trans hab.2 hbc.2⟩

/-- Canonical form needed for antisymmetry, given an asymmetric order `r` on grants
(the TS string order). Scope grants must be irredundant and strictly sorted, and the
values facet well formed (sorted and unique), as schema validation requires. -/
def Canonical (r : Scope.Grant → Scope.Grant → Prop) (a : Value) : Prop :=
  Scope.Irredundant a.scope.grants ∧ a.scope.grants.Pairwise r ∧ Values.WellFormed a.values

theorem le_antisymm {r : Scope.Grant → Scope.Grant → Prop} (hasymm : ∀ x y, r x y → ¬ r y x)
    {a b : Value} (ca : Canonical r a) (cb : Canonical r b)
    (hab : Le a b) (hba : Le b a) : a = b := by
  obtain ⟨⟨pa, ga⟩, sa, da, ta, ra, va, xa⟩ := a
  obtain ⟨⟨pb, gb⟩, sb, db, tb, rb, vb, xb⟩ := b
  obtain ⟨⟨hp, hs, hsp, ht, hrep, hv, hrev⟩, hd⟩ := hab
  obtain ⟨⟨_, hs', hsp', ht', hrep', hv', hrev'⟩, hd'⟩ := hba
  obtain ⟨ia, oa, wa⟩ := ca
  obtain ⟨ib, ob, wb⟩ := cb
  have e1 : ga = gb := Scope.within_antisymm hasymm oa ob ia ib hs hs'
  have e2 : sa = sb := Spend.le_antisymm hsp hsp'
  have e3 : da = db := Depth.le_antisymm hd hd'
  have e4 : ta = tb := Time.le_antisymm ht ht'
  have e5 : ra = rb := Reputation.le_antisymm hrep hrep'
  have e6 : va = vb := Values.le_antisymm wa wb hv hv'
  have e7 : xa = xb := Reversibility.le_antisymm hrev hrev'
  have e0 : pa = pb := hp
  subst e0 e1 e2 e3 e4 e5 e6 e7
  rfl

/-! ### F4: one delegation step -/

/-- The parts of a delegation record the step rules read. Times are abstract instants. -/
structure Record where
  authority : Value
  issuedAt : Nat

/-- A valid step from `parent` to `child`. compare.ts gives every facet failure,
including DEPTH_EXHAUSTED and DEPTH_WIDENING for the strict depth step. schema.ts
checks not_before against issued_at for a non-root. Section 4.2 requires the child
to be issued while the parent is valid, read here as issued_at inside the parent's
half-open interval. -/
def ValidStep (parent child : Record) : Prop :=
  LeExceptDepth child.authority parent.authority ∧
  Step.DepthStep child.authority.depth parent.authority.depth ∧
  child.issuedAt ≤ child.authority.time.not_before ∧
  parent.authority.time.not_before ≤ child.issuedAt ∧
  child.issuedAt < parent.authority.time.not_after

theorem validStep_le {parent child : Record} (h : ValidStep parent child) :
    Le child.authority parent.authority :=
  ⟨h.1, Step.depthStep_implies_le h.2.1⟩

theorem validStep_depth {parent child : Record} (h : ValidStep parent child) :
    child.authority.depth.remaining + 1 ≤ parent.authority.depth.remaining :=
  h.2.1.2

/-- No record is a valid step from itself, though every authority contains itself. -/
theorem not_validStep_self (r : Record) : ¬ ValidStep r r :=
  fun h => Step.not_depthStep_self _ h.2.1

theorem le_not_imp_validStep :
    ∃ r : Record, Le r.authority r.authority ∧ ¬ ValidStep r r :=
  ⟨⟨⟨⟨"p", []⟩, .unbounded, ⟨1⟩, ⟨0, 1⟩, ⟨"p", 0⟩, ⟨"p", []⟩, ⟨"p", .tentative⟩⟩, 0⟩,
    le_refl _, not_validStep_self _⟩

/-! ### F3: chains -/

/-- A chain listed root first, every adjacent pair a valid step. -/
def ValidChain : List Record → Prop
  | [] => True
  | [_] => True
  | p :: c :: rest => ValidStep p c ∧ ValidChain (c :: rest)

/-- Every record in a valid chain is contained in its root. -/
theorem chain_le_root : ∀ (root : Record) (rest : List Record),
    ValidChain (root :: rest) → ∀ x ∈ rest, Le x.authority root.authority
  | _, [], _, x, hx => by simp at hx
  | root, c :: rest, h, x, hx => by
      have hc : Le c.authority root.authority := validStep_le h.1
      rcases List.mem_cons.mp hx with e | e
      · subst e; exact hc
      · exact le_trans (chain_le_root c rest h.2 x e) hc

/-- Every later record is contained in every earlier one: for a valid chain split as
`pre ++ a :: post`, every record of `post` is contained in `a`, and `a` and every
record of `post` are contained in every record of `pre`. -/
theorem chain_le_ancestor : ∀ (pre : List Record) (a : Record) (post : List Record),
    ValidChain (pre ++ a :: post) →
      (∀ x ∈ post, Le x.authority a.authority) ∧
      (∀ p ∈ pre, ∀ x ∈ a :: post, Le x.authority p.authority)
  | [], a, post, h => ⟨chain_le_root a post h, by simp⟩
  | p :: pre, a, post, h => by
      have hrest : ValidChain (pre ++ a :: post) := by
        cases pre with
        | nil => exact h.2
        | cons q pre => exact h.2
      obtain ⟨h1, h2⟩ := chain_le_ancestor pre a post hrest
      refine ⟨h1, ?_⟩
      intro p' hp' x hx
      have hall := chain_le_root p (pre ++ a :: post) h
      rcases List.mem_cons.mp hp' with e | e
      · subst e; exact hall x (by simp_all)
      · exact h2 p' e x hx

/-- Depth falls by at least one per hop: leaf.remaining + hops ≤ root.remaining. -/
theorem chain_depth : ∀ (root : Record) (rest : List Record),
    ValidChain (root :: rest) →
      ∀ leaf, (root :: rest).getLast? = some leaf →
        leaf.authority.depth.remaining + rest.length ≤ root.authority.depth.remaining
  | root, [], _, leaf, hl => by simp at hl; subst hl; simp
  | root, c :: rest, h, leaf, hl => by
      have ih := chain_depth c rest h.2 leaf (by simpa [List.getLast?_cons_cons] using hl)
      have hs := validStep_depth h.1
      simp only [List.length_cons]
      omega

/-- With remaining at most 255 at the root, a valid chain has at most 256 records. -/
theorem chain_length_le (root : Record) (rest : List Record)
    (hroot : Depth.WellFormed root.authority.depth) (h : ValidChain (root :: rest)) :
    (root :: rest).length ≤ 256 := by
  have hl : (root :: rest).getLast? = some ((root :: rest).getLast (by simp)) :=
    List.getLast?_eq_getLast _ _
  have := chain_depth root rest h _ hl
  unfold Depth.WellFormed at hroot
  simp only [List.length_cons]
  omega

/-! The bound is reached: a valid chain of 256 records, remaining 255 down to 0. -/

def witnessAuthority (d : Nat) : Value :=
  ⟨⟨"p", []⟩, .unbounded, ⟨d⟩, ⟨0, 1⟩, ⟨"p", 0⟩, ⟨"p", []⟩, ⟨"p", .tentative⟩⟩

def witnessRecord (d : Nat) : Record := ⟨witnessAuthority d, 0⟩

/-- Records with remaining n, n-1, ..., 0. -/
def witnessChain : Nat → List Record
  | 0 => [witnessRecord 0]
  | n + 1 => witnessRecord (n + 1) :: witnessChain n

theorem witnessChain_head (n : Nat) : ∃ rest, witnessChain n = witnessRecord n :: rest := by
  cases n <;> exact ⟨_, rfl⟩

theorem witnessChain_length (n : Nat) : (witnessChain n).length = n + 1 := by
  induction n with
  | zero => rfl
  | succ n ih => simp [witnessChain, ih]

theorem witness_step (n : Nat) : ValidStep (witnessRecord (n + 1)) (witnessRecord n) :=
  ⟨leExceptDepth_refl _, ⟨by simp [witnessRecord, witnessAuthority],
      by simp [witnessRecord, witnessAuthority]⟩,
    by simp [witnessRecord, witnessAuthority, Time.Value.not_before],
    by simp [witnessRecord, witnessAuthority],
    by simp [witnessRecord, witnessAuthority]⟩

theorem witnessChain_valid : ∀ n, ValidChain (witnessChain n)
  | 0 => trivial
  | n + 1 => by
      obtain ⟨rest, hr⟩ := witnessChain_head n
      have ih := witnessChain_valid n
      rw [witnessChain, hr]
      rw [hr] at ih
      exact ⟨witness_step n, ih⟩

theorem chain_length_tight :
    ∃ chain : List Record, ValidChain chain ∧ chain.length = 256 ∧
      ∃ root rest, chain = root :: rest ∧ Depth.WellFormed root.authority.depth :=
  ⟨witnessChain 255, witnessChain_valid 255, witnessChain_length 255,
    witnessRecord 255, witnessChain 254, rfl, by simp [Depth.WellFormed, witnessRecord, witnessAuthority]⟩

/-- Executable valid-step check on decoded records. Like ValidStep, this does not
check interval well-formedness, signatures, linkage, current validity or revocation. -/
def validStep? (parent child : Record) : Bool :=
  (decide (child.authority.scope.profile = parent.authority.scope.profile) &&
    Scope.within? child.authority.scope.grants parent.authority.scope.grants &&
    Spend.le? child.authority.spend parent.authority.spend &&
    Time.le? child.authority.time parent.authority.time &&
    Reputation.le? child.authority.reputation parent.authority.reputation &&
    Values.le? child.authority.values parent.authority.values &&
    Reversibility.le? child.authority.reversibility parent.authority.reversibility) &&
  decide (0 < parent.authority.depth.remaining ∧
    child.authority.depth.remaining + 1 ≤ parent.authority.depth.remaining) &&
  decide (child.issuedAt ≤ child.authority.time.not_before) &&
  decide (parent.authority.time.not_before ≤ child.issuedAt) &&
  decide (child.issuedAt < parent.authority.time.not_after)

theorem validStep?_iff (parent child : Record) :
    validStep? parent child = true ↔ ValidStep parent child := by
  simp only [validStep?, Bool.and_eq_true, decide_eq_true_eq,
    Scope.within?_iff, Spend.le?_iff, Time.le?_iff, Reputation.le?_iff,
    Values.le?_iff, Reversibility.le?_iff, ValidStep, LeExceptDepth, Step.DepthStep,
    and_assoc]

end APS.Authority

#print axioms APS.Authority.le_refl
#print axioms APS.Authority.le_trans
#print axioms APS.Authority.le_antisymm
#print axioms APS.Authority.validStep_le
#print axioms APS.Authority.not_validStep_self
#print axioms APS.Authority.le_not_imp_validStep
#print axioms APS.Authority.chain_le_root
#print axioms APS.Authority.chain_le_ancestor
#print axioms APS.Authority.chain_depth
#print axioms APS.Authority.chain_length_le
#print axioms APS.Authority.chain_length_tight
#print axioms APS.Authority.validStep?_iff
