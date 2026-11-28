/-
APS formal model, F7a/F7b: the cumulative spend ledger.

Mirrors agent-passport-system src/v2/authority-delegation/budget.ts
InMemoryAuthorityBudgetLedger (reserve, markDispatched, commit, cancel) and
draft-pidlisnyi-aps-04 section 4.4, including the section 4.4 rule that a changed
footprint under a cancelled action_ref conflicts.

Abstraction.
- A delegation is its delegation_id. The limits of a bounded delegation (unit,
  per_action, cumulative) are a function `lim` of its id, because the id is the hash
  of the signed record. Unbounded ancestors never appear in a reservation, as in TS.
- `reserve` takes the bounded ancestor ids of a chain that the caller verified. Chain
  validation inside reserve (shape, id recomputation, linkage) is abstracted to the
  duplicate id check it implies.
- The model is sequential: each operation is one atomic transition. It says nothing
  about whether a distributed store is linearizable. TS documents the in-memory ledger
  as one synchronous critical section per mutation and requires a replacement store
  to give the same all-ancestors atomicity.

Proved:
  1. ceiling: reserved + committed never exceeds the cumulative limit of any bounded
     delegation, from the empty ledger, across any sequence of reserve, retry,
     conflict, dispatch, cancel and commit
  2. every failed operation leaves the whole ledger unchanged
  3. a successful reserve adds the amount to every bounded ancestor and changes no
     other counter (all or none), commit moves the amount from reserved to committed
     on every ancestor, cancel releases it from every ancestor
  4. siblings share: two reservations that both draw on one ancestor together fit
     inside that ancestor's single cumulative limit
  5. reservation identity: under an existing action_ref only the same footprint is
     accepted, before and after cancellation
-/

namespace APS.Ledger

abbrev Id := Nat
abbrev Ref := Nat

structure Limit where
  unit : String
  perAction : Nat
  cumulative : Nat

structure Counter where
  reserved : Nat
  committed : Nat
  deriving DecidableEq, Repr

inductive State where
  | reserved
  | dispatched
  | committed
  | cancelled
  deriving DecidableEq, Repr

structure Reservation where
  unit : String
  amount : Nat
  ids : List Id
  state : State

structure Ledger where
  counters : Id → Counter
  res : Ref → Option Reservation
  refs : List Ref

/-- Insert once. Historical refs remain after cancellation and settlement. -/
def remember (r : Ref) (refs : List Ref) : List Ref :=
  if r ∈ refs then refs else r :: refs

def empty : Ledger := ⟨fun _ => ⟨0, 0⟩, fun _ => none, []⟩

inductive Code where
  | reserved | idempotent | conflict | unitMismatch | perActionExceeded
  | cumulativeExceeded | notFound | invalidState | dispatched | committed | cancelled
  deriving DecidableEq, Repr

/-- The same set of bounded ancestor ids. Section 4.4 calls it a set. -/
def sameSet (a b : List Id) : Bool := a.all (b.contains ·) && b.all (a.contains ·)

def sameFootprint (r : Reservation) (unit : String) (amount : Nat) (ids : List Id) : Bool :=
  r.unit == unit && r.amount == amount && sameSet r.ids ids

/-- The limit checks of reserve, ancestor by ancestor, first failure wins. -/
def limitCheck (lim : Id → Limit) (c : Id → Counter) (unit : String) (amount : Nat) :
    List Id → Option Code
  | [] => none
  | d :: ds =>
      if (lim d).unit ≠ unit then some .unitMismatch
      else if (lim d).perAction < amount then some .perActionExceeded
      else if (lim d).cumulative < (c d).reserved + (c d).committed + amount then
        some .cumulativeExceeded
      else limitCheck lim c unit amount ds

def addReserved (c : Id → Counter) (ids : List Id) (amount : Nat) : Id → Counter :=
  fun d => if d ∈ ids then ⟨(c d).reserved + amount, (c d).committed⟩ else c d

def setRes (f : Ref → Option Reservation) (r : Ref) (v : Reservation) : Ref → Option Reservation :=
  fun x => if x = r then some v else f x

def fresh (lim : Id → Limit) (L : Ledger) (r : Ref) (unit : String) (amount : Nat)
    (ids : List Id) : Code × Ledger :=
  match limitCheck lim L.counters unit amount ids with
  | some e => (e, L)
  | none => (.reserved, ⟨addReserved L.counters ids amount,
      setRes L.res r ⟨unit, amount, ids, .reserved⟩, remember r L.refs⟩)

def reserve (lim : Id → Limit) (L : Ledger) (r : Ref) (unit : String) (amount : Nat)
    (ids : List Id) : Code × Ledger :=
  if ¬ ids.Nodup then (.conflict, L) else
  match L.res r with
  | some p =>
      if sameFootprint p unit amount ids = false then (.conflict, L)
      else if p.state = .cancelled then fresh lim L r unit amount ids
      else (.idempotent, L)
  | none => fresh lim L r unit amount ids

def dispatch (L : Ledger) (r : Ref) : Code × Ledger :=
  match L.res r with
  | none => (.notFound, L)
  | some p =>
      if p.state = .dispatched then (.idempotent, L)
      else if p.state ≠ .reserved then (.invalidState, L)
      else (.dispatched, ⟨L.counters, setRes L.res r { p with state := .dispatched }, remember r L.refs⟩)

/-- Every ancestor counter still holds the reserved amount. -/
def holds (c : Id → Counter) (p : Reservation) : Bool :=
  p.ids.all fun d => decide (p.amount ≤ (c d).reserved)

def moveCommitted (c : Id → Counter) (ids : List Id) (amount : Nat) : Id → Counter :=
  fun d => if d ∈ ids then ⟨(c d).reserved - amount, (c d).committed + amount⟩ else c d

def release (c : Id → Counter) (ids : List Id) (amount : Nat) : Id → Counter :=
  fun d => if d ∈ ids then ⟨(c d).reserved - amount, (c d).committed⟩ else c d

def commit (L : Ledger) (r : Ref) : Code × Ledger :=
  match L.res r with
  | none => (.notFound, L)
  | some p =>
      if p.state = .committed then (.idempotent, L)
      else if p.state ≠ .reserved ∧ p.state ≠ .dispatched then (.invalidState, L)
      else if holds L.counters p = false then (.invalidState, L)
      else (.committed, ⟨moveCommitted L.counters p.ids p.amount,
        setRes L.res r { p with state := .committed }, remember r L.refs⟩)

def cancel (L : Ledger) (r : Ref) : Code × Ledger :=
  match L.res r with
  | none => (.notFound, L)
  | some p =>
      if p.state = .cancelled then (.idempotent, L)
      else if p.state ≠ .reserved then (.invalidState, L)
      else if holds L.counters p = false then (.invalidState, L)
      else (.cancelled, ⟨release L.counters p.ids p.amount,
        setRes L.res r { p with state := .cancelled }, remember r L.refs⟩)

/-! ### 1. The ceiling invariant -/

/-- reserved + committed fits the cumulative limit of every delegation. -/
def Inv (lim : Id → Limit) (L : Ledger) : Prop :=
  ∀ d, (L.counters d).reserved + (L.counters d).committed ≤ (lim d).cumulative

theorem inv_empty (lim : Id → Limit) : Inv lim empty := by
  intro d; simp [empty]

theorem limitCheck_none {lim : Id → Limit} {c : Id → Counter} {unit : String} {amount : Nat} :
    ∀ {ids : List Id}, limitCheck lim c unit amount ids = none →
      ∀ d ∈ ids, (c d).reserved + (c d).committed + amount ≤ (lim d).cumulative ∧
        (lim d).unit = unit ∧ amount ≤ (lim d).perAction
  | [], _, d, hd => by simp at hd
  | x :: xs, h, d, hd => by
      simp only [limitCheck] at h
      split at h; · simp at h
      split at h; · simp at h
      split at h; · simp at h
      rename_i h1 h2 h3
      rcases List.mem_cons.mp hd with e | e
      · subst e; exact ⟨by omega, by simpa using h1, by omega⟩
      · exact limitCheck_none h d e

theorem fresh_inv {lim : Id → Limit} {L : Ledger} {r : Ref} {unit : String} {amount : Nat}
    {ids : List Id} (hI : Inv lim L) : Inv lim (fresh lim L r unit amount ids).2 := by
  unfold fresh
  cases h : limitCheck lim L.counters unit amount ids with
  | some e => exact hI
  | none =>
    intro d
    simp only [addReserved]
    split
    · rename_i hd
      have := (limitCheck_none h d hd).1
      simp only; omega
    · exact hI d

theorem reserve_inv (lim : Id → Limit) (L : Ledger) (r : Ref) (unit : String) (amount : Nat)
    (ids : List Id) (hI : Inv lim L) : Inv lim (reserve lim L r unit amount ids).2 := by
  unfold reserve
  split; · exact hI
  split
  · split; · exact hI
    split
    · exact fresh_inv hI
    · exact hI
  · exact fresh_inv hI

theorem dispatch_inv (lim : Id → Limit) (L : Ledger) (r : Ref) (hI : Inv lim L) :
    Inv lim (dispatch L r).2 := by
  unfold dispatch
  split; · exact hI
  split; · exact hI
  split; · exact hI
  exact hI

theorem holds_true {c : Id → Counter} {p : Reservation} (h : holds c p = true) :
    ∀ d ∈ p.ids, p.amount ≤ (c d).reserved := by
  intro d hd
  simp only [holds, List.all_eq_true, decide_eq_true_eq] at h
  exact h d hd

theorem commit_inv (lim : Id → Limit) (L : Ledger) (r : Ref) (hI : Inv lim L) :
    Inv lim (commit L r).2 := by
  unfold commit
  split; · exact hI
  rename_i p _
  split; · exact hI
  split; · exact hI
  split; · exact hI
  rename_i hh
  have hh' : holds L.counters p = true := by simpa using hh
  intro d
  simp only [moveCommitted]
  split
  · rename_i hd
    have h1 := holds_true hh' d hd
    have h2 := hI d
    simp only; omega
  · exact hI d

theorem cancel_inv (lim : Id → Limit) (L : Ledger) (r : Ref) (hI : Inv lim L) :
    Inv lim (cancel L r).2 := by
  unfold cancel
  split; · exact hI
  split; · exact hI
  split; · exact hI
  split; · exact hI
  intro d
  simp only [release]
  split
  · have h2 := hI d
    simp only; omega
  · exact hI d

/-- Any operation the ledger offers. -/
inductive Op where
  | reserve (r : Ref) (unit : String) (amount : Nat) (ids : List Id)
  | dispatch (r : Ref)
  | commit (r : Ref)
  | cancel (r : Ref)

def step (lim : Id → Limit) (L : Ledger) : Op → Code × Ledger
  | .reserve r u a ids => reserve lim L r u a ids
  | .dispatch r => dispatch L r
  | .commit r => commit L r
  | .cancel r => cancel L r

def run (lim : Id → Limit) : Ledger → List Op → Ledger
  | L, [] => L
  | L, o :: os => run lim (step lim L o).2 os

theorem step_inv (lim : Id → Limit) (L : Ledger) (o : Op) (hI : Inv lim L) :
    Inv lim (step lim L o).2 := by
  cases o with
  | reserve r u a ids => exact reserve_inv lim L r u a ids hI
  | dispatch r => exact dispatch_inv lim L r hI
  | commit r => exact commit_inv lim L r hI
  | cancel r => exact cancel_inv lim L r hI

theorem run_inv (lim : Id → Limit) : ∀ (L : Ledger) (ops : List Op), Inv lim L → Inv lim (run lim L ops)
  | _, [], h => h
  | L, o :: os, h => run_inv lim _ os (step_inv lim L o h)

/-- 1. From the empty ledger, after any sequence of operations, no delegation's
reserved plus committed exceeds its cumulative limit. -/
theorem ceiling (lim : Id → Limit) (ops : List Op) (d : Id) :
    ((run lim empty ops).counters d).reserved + ((run lim empty ops).counters d).committed
      ≤ (lim d).cumulative :=
  run_inv lim empty ops (inv_empty lim) d

/-! ### 2. Failed operations change nothing -/

def succeeded : Code → Bool
  | .reserved | .idempotent | .dispatched | .committed | .cancelled => true
  | _ => false

theorem fresh_fail {lim : Id → Limit} {L : Ledger} {r : Ref} {unit : String} {amount : Nat}
    {ids : List Id} (h : succeeded (fresh lim L r unit amount ids).1 = false) :
    (fresh lim L r unit amount ids).2 = L := by
  unfold fresh at *
  cases hc : limitCheck lim L.counters unit amount ids with
  | some e => simp [hc]
  | none => simp [hc, succeeded] at h

theorem step_fail (lim : Id → Limit) (L : Ledger) (o : Op)
    (h : succeeded (step lim L o).1 = false) : (step lim L o).2 = L := by
  cases o <;> simp only [step, reserve, dispatch, commit, cancel] at h ⊢ <;>
    (repeat' split) <;>
    first
    | rfl
    | exact fresh_fail (by simp_all)
    | simp_all [succeeded]

/-! ### 3. All or none -/

theorem limitCheck_not_reserved {lim : Id → Limit} {c : Id → Counter} {unit : String}
    {amount : Nat} : ∀ {ids : List Id} {e : Code}, limitCheck lim c unit amount ids = some e →
      e ≠ .reserved
  | [], _, h => by simp [limitCheck] at h
  | x :: xs, e, h => by
      simp only [limitCheck] at h
      split at h
      · cases h; simp
      · split at h
        · cases h; simp
        · split at h
          · cases h; simp
          · exact limitCheck_not_reserved h

theorem fresh_reserved_counters {lim : Id → Limit} {L : Ledger} {r : Ref} {unit : String}
    {amount : Nat} {ids : List Id} (h : (fresh lim L r unit amount ids).1 = .reserved) :
    (fresh lim L r unit amount ids).2.counters = addReserved L.counters ids amount := by
  unfold fresh at *
  cases hc : limitCheck lim L.counters unit amount ids with
  | some e => rw [hc] at h; exact absurd h (limitCheck_not_reserved hc)
  | none => rfl

/-- 3. A reserve that newly reserves (code `reserved`) adds the amount to every bounded
ancestor counter and changes no other counter. An idempotent retry is also counted as
success by `succeeded` but changes nothing. -/
theorem reserve_all_or_none (lim : Id → Limit) (L : Ledger) (r : Ref) (unit : String)
    (amount : Nat) (ids : List Id) (h : (reserve lim L r unit amount ids).1 = .reserved) :
    (reserve lim L r unit amount ids).2.counters = addReserved L.counters ids amount := by
  unfold reserve at *
  split at h; · simp at h
  rename_i hn
  simp only [hn, if_false] at *
  split at h
  · split at h; · simp at h
    split at h
    · simp only [*]; exact fresh_reserved_counters h
    · simp at h
  · exact fresh_reserved_counters h

/-! ### 4. Siblings share one ancestor budget -/

/-- Two successful reservations, for example by two sibling delegations, that both
draw on ancestor `d` fit together inside `d`'s one cumulative limit. -/
theorem siblings_share (lim : Id → Limit) (L : Ledger) (hI : Inv lim L)
    (r1 r2 : Ref) (u1 u2 : String) (a1 a2 : Nat) (ids1 ids2 : List Id) (d : Id)
    (h1 : (reserve lim L r1 u1 a1 ids1).1 = .reserved)
    (h2 : (reserve lim (reserve lim L r1 u1 a1 ids1).2 r2 u2 a2 ids2).1 = .reserved)
    (hd1 : d ∈ ids1) (hd2 : d ∈ ids2) :
    a1 + a2 ≤ (lim d).cumulative := by
  have hI1 := reserve_inv lim L r1 u1 a1 ids1 hI
  have hI2 := reserve_inv lim _ r2 u2 a2 ids2 hI1 d
  rw [reserve_all_or_none lim _ r2 u2 a2 ids2 h2] at hI2
  simp only [addReserved, hd2, if_true] at hI2
  rw [reserve_all_or_none lim L r1 u1 a1 ids1 h1] at hI2
  simp only [addReserved, hd1, if_true] at hI2
  omega

/-! ### 5. Reservation identity -/

/-- Under an action_ref that already has a reservation, in any state including
cancelled, reserve succeeds only for the same footprint. -/
theorem reserve_same_footprint (lim : Id → Limit) (L : Ledger) (r : Ref) (unit : String)
    (amount : Nat) (ids : List Id) (p : Reservation) (hp : L.res r = some p)
    (h : succeeded (reserve lim L r unit amount ids).1 = true) :
    sameFootprint p unit amount ids = true := by
  unfold reserve at h
  split at h; · simp [succeeded] at h
  rw [hp] at h
  simp only at h
  cases hf : sameFootprint p unit amount ids
  · simp [hf, succeeded] at h
  · rfl

/-! ### 6. Finite accounting, F7b

Contribution brief. The ceiling alone permits ghost counters, so it does not show
that a live reservation can settle. Track each historical ref once, sum the current
map entries, and preserve exact accounting through each transition. This extends
Claude's F7a model in the lane assigned by Tima. No SDK or wire-validation change
is made here. Validation is kernel checking with Lean 4.14.0, without Mathlib.
-/

/-- Sum a contribution from the current reservation at each historical ref. -/
def total (refs : List Ref) (f : Ref → Option Reservation)
    (weight : Option Reservation → Nat) : Nat :=
  match refs with
  | [] => 0
  | r :: rs => weight (f r) + total rs f weight

/-- A live reservation holds its amount at each bounded ancestor, including zero. -/
def reservedWeight (d : Id) : Option Reservation → Nat
  | none => 0
  | some p => if d ∈ p.ids ∧ (p.state = .reserved ∨ p.state = .dispatched)
      then p.amount else 0

/-- Only settled reservations contribute to committed spend. -/
def committedWeight (d : Id) : Option Reservation → Nat
  | none => 0
  | some p => if d ∈ p.ids ∧ p.state = .committed then p.amount else 0

/-- The carrier is unique and complete, and both counters equal their map sums. -/
structure Accounting (L : Ledger) : Prop where
  unique : L.refs.Nodup
  complete : ∀ r p, L.res r = some p → r ∈ L.refs
  reserved : ∀ d, (L.counters d).reserved = total L.refs L.res (reservedWeight d)
  committed : ∀ d, (L.counters d).committed = total L.refs L.res (committedWeight d)

theorem remember_mem (r x : Ref) (rs : List Ref) :
    x ∈ remember r rs ↔ x = r ∨ x ∈ rs := by
  unfold remember
  split <;> simp_all [List.mem_cons]

theorem remember_unique (r : Ref) (rs : List Ref) (h : rs.Nodup) :
    (remember r rs).Nodup := by
  unfold remember
  split <;> simp_all

theorem total_outside (rs : List Ref) (f : Ref → Option Reservation)
    (w : Option Reservation → Nat) (r : Ref) (p : Reservation) (h : r ∉ rs) :
    total rs (setRes f r p) w = total rs f w := by
  induction rs with
  | nil => rfl
  | cons x xs ih =>
    simp only [List.mem_cons, not_or] at h
    simp [total, setRes, Ne.symm h.1, ih h.2]

/-- Replacing one entry changes a finite sum by exactly that entry's contribution.
The additive form avoids truncated subtraction in the bookkeeping lemma. -/
theorem total_replace (rs : List Ref) (f : Ref → Option Reservation)
    (w : Option Reservation → Nat) (r : Ref) (p : Reservation)
    (hn : rs.Nodup) (hr : r ∈ rs) :
    total rs (setRes f r p) w + w (f r) = total rs f w + w (some p) := by
  induction rs with
  | nil => simp at hr
  | cons x xs ih =>
    have hnx := List.nodup_cons.mp hn
    rcases List.mem_cons.mp hr with he | he
    · subst x
      simp [total, setRes, total_outside xs f w r p hnx.1, Nat.add_comm, Nat.add_left_comm, Nat.add_assoc]
    · by_cases hx : x = r
      · subst x
        exact False.elim (hnx.1 he)
      · have hi := ih hnx.2 he
        simp only [total, setRes, if_neg hx]
        simp only [setRes] at hi
        omega

theorem total_remember_replace (L : Ledger) (h : Accounting L)
    (w : Option Reservation → Nat) (hw : w none = 0) (r : Ref) (p : Reservation) :
    total (remember r L.refs) (setRes L.res r p) w + w (L.res r) =
      total L.refs L.res w + w (some p) := by
  unfold remember
  split
  · exact total_replace L.refs L.res w r p h.unique (by assumption)
  · rename_i hr
    have hf : L.res r = none := by
      cases he : L.res r with
      | none => rfl
      | some q => exact False.elim (hr (h.complete r q he))
    simp [total, setRes, total_outside L.refs L.res w r p hr, hf, hw, Nat.add_comm]

/-- One map replacement preserves accounting when the counters make the same move. -/
theorem accounting_write (L : Ledger) (h : Accounting L) (r : Ref) (p : Reservation)
    (c : Id → Counter)
    (hr : ∀ d, (c d).reserved + reservedWeight d (L.res r) =
      (L.counters d).reserved + reservedWeight d (some p))
    (hc : ∀ d, (c d).committed + committedWeight d (L.res r) =
      (L.counters d).committed + committedWeight d (some p)) :
    Accounting ⟨c, setRes L.res r p, remember r L.refs⟩ := by
  refine ⟨remember_unique r L.refs h.unique, ?_, ?_, ?_⟩
  · intro x q hx
    apply (remember_mem r x L.refs).2
    by_cases he : x = r
    · exact Or.inl he
    · exact Or.inr (h.complete x q (by simpa [setRes, he] using hx))
  · intro d
    have ht := total_remember_replace L h (reservedWeight d) rfl r p
    have hh := hr d
    rw [← h.reserved d] at ht
    dsimp only
    omega
  · intro d
    have ht := total_remember_replace L h (committedWeight d) rfl r p
    have hh := hc d
    rw [← h.committed d] at ht
    dsimp only
    omega

theorem accounting_empty : Accounting empty := by
  constructor <;> simp [empty, total]

/-- Fresh reserve is used only for an absent or cancelled map entry. -/
theorem fresh_accounting (lim : Id → Limit) (L : Ledger) (h : Accounting L)
    (r : Ref) (u : String) (a : Nat) (ids : List Id)
    (hp : L.res r = none ∨ ∃ p, L.res r = some p ∧ p.state = .cancelled) :
    Accounting (fresh lim L r u a ids).2 := by
  unfold fresh
  split
  · exact h
  · apply accounting_write L h
    · intro d
      rcases hp with he | ⟨p, he, hs⟩ <;>
        simp_all [reservedWeight, addReserved] <;> split <;> simp_all
    · intro d
      rcases hp with he | ⟨p, he, hs⟩ <;>
        simp_all [committedWeight, addReserved] <;> split <;> simp_all

theorem reserve_accounting (lim : Id → Limit) (L : Ledger) (h : Accounting L)
    (r : Ref) (u : String) (a : Nat) (ids : List Id) :
    Accounting (reserve lim L r u a ids).2 := by
  unfold reserve
  split; · exact h
  split
  · rename_i p hp
    split; · exact h
    split
    · exact fresh_accounting lim L h r u a ids (Or.inr ⟨p, hp, by assumption⟩)
    · exact h
  · exact fresh_accounting lim L h r u a ids (Or.inl (by assumption))

theorem dispatch_accounting (L : Ledger) (h : Accounting L) (r : Ref) :
    Accounting (dispatch L r).2 := by
  unfold dispatch
  split; · exact h
  rename_i p hp
  split; · exact h
  split; · exact h
  rename_i hs
  have hs' : p.state = .reserved := by simpa using hs
  apply accounting_write L h <;> intro d <;>
    simp [hp, reservedWeight, committedWeight, hs']

theorem commit_accounting (L : Ledger) (h : Accounting L) (r : Ref) :
    Accounting (commit L r).2 := by
  unfold commit
  split; · exact h
  rename_i p hp
  split; · exact h
  split; · exact h
  rename_i hs
  split; · exact h
  rename_i hh
  have live : p.state = .reserved ∨ p.state = .dispatched := by
    cases he : p.state <;> simp_all
  have held : holds L.counters p = true := by simpa using hh
  apply accounting_write L h
  · intro d
    by_cases hd : d ∈ p.ids
    · have ha := holds_true held d hd
      simp only [moveCommitted, hd, if_true, hp, reservedWeight, live, and_self]
      simp only [if_true, reduceCtorEq, or_self, and_false, if_false]
      omega
    · simp [moveCommitted, hd, hp, reservedWeight]
  · intro d
    rcases live with hs | hs <;>
      simp [moveCommitted, hp, committedWeight, hs] <;> split <;> simp_all

theorem cancel_accounting (L : Ledger) (h : Accounting L) (r : Ref) :
    Accounting (cancel L r).2 := by
  unfold cancel
  split; · exact h
  rename_i p hp
  split; · exact h
  split; · exact h
  rename_i hs
  split; · exact h
  rename_i hh
  have hs' : p.state = .reserved := by simpa using hs
  have held : holds L.counters p = true := by simpa using hh
  apply accounting_write L h
  · intro d
    by_cases hd : d ∈ p.ids
    · have ha := holds_true held d hd
      simp [release, hd, hp, reservedWeight, hs']
      omega
    · simp [release, hd, hp, reservedWeight]
  · intro d
    simp [release, hp, committedWeight, hs'] <;> split <;> rfl

theorem step_accounting (lim : Id → Limit) (L : Ledger) (o : Op) (h : Accounting L) :
    Accounting (step lim L o).2 := by
  cases o with
  | reserve r u a ids => exact reserve_accounting lim L h r u a ids
  | dispatch r => exact dispatch_accounting L h r
  | commit r => exact commit_accounting L h r
  | cancel r => exact cancel_accounting L h r

theorem run_accounting (lim : Id → Limit) : ∀ (L : Ledger) (ops : List Op),
    Accounting L → Accounting (run lim L ops)
  | _, [], h => h
  | L, o :: os, h => run_accounting lim _ os (step_accounting lim L o h)

/-- Exact conservation, including carrier uniqueness and completeness, for every
operation sequence from empty. No well-formedness hypothesis on the operations. -/
theorem conservation (lim : Id → Limit) (ops : List Op) :
    Accounting (run lim empty ops) :=
  run_accounting lim empty ops accounting_empty

/-- The requested two equalities, explicitly at every delegation id. -/
theorem conservation_counters (lim : Id → Limit) (ops : List Op) (d : Id) :
    let L := run lim empty ops
    (L.counters d).reserved = total L.refs L.res (reservedWeight d) ∧
    (L.counters d).committed = total L.refs L.res (committedWeight d) :=
  ⟨(conservation lim ops).reserved d, (conservation lim ops).committed d⟩

/-- Every summand is bounded by the whole nonnegative finite sum. -/
theorem total_member_le (rs : List Ref) (f : Ref → Option Reservation)
    (w : Option Reservation → Nat) (r : Ref) (hr : r ∈ rs) :
    w (f r) ≤ total rs f w := by
  induction rs with
  | nil => simp at hr
  | cons x xs ih =>
    rcases List.mem_cons.mp hr with he | he
    · subst x; simp [total]
    · have hi := ih he
      simp only [total]
      omega

/-- Accounting rules out the insufficient-counter branch for any live entry. -/
theorem accounting_holds (L : Ledger) (h : Accounting L) (r : Ref) (p : Reservation)
    (hp : L.res r = some p) (live : p.state = .reserved ∨ p.state = .dispatched) :
    holds L.counters p = true := by
  simp only [holds, List.all_eq_true, decide_eq_true_eq]
  intro d hd
  have ht := total_member_le L.refs L.res (reservedWeight d) r (h.complete r p hp)
  rw [← h.reserved d] at ht
  simpa [hp, reservedWeight, hd, live] using ht

/-- From empty, every reserved or dispatched reservation passes the holds check. -/
theorem reachable_holds (lim : Id → Limit) (ops : List Op) (r : Ref) (p : Reservation)
    (hp : (run lim empty ops).res r = some p)
    (live : p.state = .reserved ∨ p.state = .dispatched) :
    holds (run lim empty ops).counters p = true :=
  accounting_holds _ (conservation lim ops) r p hp live

/-- A live commit returns COMMITTED, so INVALID_STATE cannot arise from counters. -/
theorem reachable_commit (lim : Id → Limit) (ops : List Op) (r : Ref) (p : Reservation)
    (hp : (run lim empty ops).res r = some p)
    (live : p.state = .reserved ∨ p.state = .dispatched) :
    (commit (run lim empty ops) r).1 = .committed := by
  have hh := reachable_holds lim ops r p hp live
  rcases live with hs | hs <;> simp [commit, hp, hs, hh]

/-- A pre-dispatch cancel returns CANCELLED. Dispatched entries still cannot cancel. -/
theorem reachable_cancel (lim : Id → Limit) (ops : List Op) (r : Ref) (p : Reservation)
    (hp : (run lim empty ops).res r = some p) (hs : p.state = .reserved) :
    (cancel (run lim empty ops) r).1 = .cancelled := by
  have hh := reachable_holds lim ops r p hp (Or.inl hs)
  simp [cancel, hp, hs, hh]

/-- A newly completed commit (code `committed`, not an idempotent retry) moves the amount
on every ancestor and no other counter. -/
theorem commit_all_or_none (L : Ledger) (r : Ref) (p : Reservation)
    (hp : L.res r = some p) (h : (commit L r).1 = .committed) :
    (commit L r).2.counters = moveCommitted L.counters p.ids p.amount := by
  unfold commit at h ⊢
  simp only [hp] at h ⊢
  repeat' split
  all_goals simp_all

/-- A newly completed cancel (code `cancelled`, not an idempotent retry) releases the
amount on every ancestor and no other counter. -/
theorem cancel_all_or_none (L : Ledger) (r : Ref) (p : Reservation)
    (hp : L.res r = some p) (h : (cancel L r).1 = .cancelled) :
    (cancel L r).2.counters = release L.counters p.ids p.amount := by
  unfold cancel at h ⊢
  simp only [hp] at h ⊢
  repeat' split
  all_goals simp_all

/-- Historical refs never disappear, including on failed calls and cancellation. -/
theorem step_refs_mono (lim : Id → Limit) (L : Ledger) (o : Op) (r : Ref)
    (hr : r ∈ L.refs) : r ∈ (step lim L o).2.refs := by
  cases o <;> simp only [step, reserve, dispatch, commit, cancel, fresh] <;>
    (repeat' split) <;> first
    | exact hr
    | exact (remember_mem _ _ _).2 (Or.inr hr)

/-- Inductive historical-carrier growth for any suffix of an execution. -/
theorem run_refs_mono (lim : Id → Limit) : ∀ (L : Ledger) (ops : List Op) (r : Ref),
    r ∈ L.refs → r ∈ (run lim L ops).refs
  | _, [], _, h => h
  | L, o :: os, r, h => run_refs_mono lim _ os r (step_refs_mono lim L o r h)

/-- Budget ceiling and accounting consistency on the same reachable ledgers: the F7a
ceiling and the F7b accounting equalities hold together for every operation sequence
from empty, under the same fixed limits and the same `step`. -/
theorem ledger_safe (lim : Id → Limit) (ops : List Op) :
    Accounting (run lim empty ops) ∧
      ∀ d, ((run lim empty ops).counters d).reserved + ((run lim empty ops).counters d).committed
        ≤ (lim d).cumulative :=
  ⟨conservation lim ops, fun d => ceiling lim ops d⟩

/-- A newly completed commit keeps charged capacity, reserved plus committed, unchanged at
every delegation id. The subtraction in `moveCommitted` never truncates, because commit
only completes when the reservation's amount is held at each of its ancestors. -/
theorem commit_preserves_charged (L : Ledger) (r : Ref) (p : Reservation)
    (hp : L.res r = some p) (h : (commit L r).1 = .committed) (d : Id) :
    ((commit L r).2.counters d).reserved + ((commit L r).2.counters d).committed
      = (L.counters d).reserved + (L.counters d).committed := by
  have hh : holds L.counters p = true := by
    cases hb : holds L.counters p
    · unfold commit at h
      simp only [hp] at h
      repeat' split at h
      all_goals simp_all
    · rfl
  rw [commit_all_or_none L r p hp h]
  unfold moveCommitted
  by_cases hd : d ∈ p.ids
  · have hle := holds_true hh d hd
    simp only [hd, if_true]
    omega
  · simp [hd]

end APS.Ledger

#print axioms APS.Ledger.ceiling
#print axioms APS.Ledger.run_inv
#print axioms APS.Ledger.step_fail
#print axioms APS.Ledger.reserve_all_or_none
#print axioms APS.Ledger.siblings_share
#print axioms APS.Ledger.reserve_same_footprint

#print axioms APS.Ledger.inv_empty

#print axioms APS.Ledger.limitCheck_none

#print axioms APS.Ledger.fresh_inv

#print axioms APS.Ledger.reserve_inv

#print axioms APS.Ledger.dispatch_inv

#print axioms APS.Ledger.holds_true

#print axioms APS.Ledger.commit_inv

#print axioms APS.Ledger.cancel_inv

#print axioms APS.Ledger.step_inv

#print axioms APS.Ledger.fresh_fail

#print axioms APS.Ledger.limitCheck_not_reserved

#print axioms APS.Ledger.fresh_reserved_counters

#print axioms APS.Ledger.remember_mem

#print axioms APS.Ledger.remember_unique

#print axioms APS.Ledger.total_outside

#print axioms APS.Ledger.total_replace

#print axioms APS.Ledger.total_remember_replace

#print axioms APS.Ledger.accounting_write

#print axioms APS.Ledger.accounting_empty

#print axioms APS.Ledger.fresh_accounting

#print axioms APS.Ledger.reserve_accounting

#print axioms APS.Ledger.dispatch_accounting

#print axioms APS.Ledger.commit_accounting

#print axioms APS.Ledger.cancel_accounting

#print axioms APS.Ledger.step_accounting

#print axioms APS.Ledger.run_accounting

#print axioms APS.Ledger.conservation

#print axioms APS.Ledger.conservation_counters

#print axioms APS.Ledger.total_member_le

#print axioms APS.Ledger.accounting_holds

#print axioms APS.Ledger.reachable_holds

#print axioms APS.Ledger.reachable_commit

#print axioms APS.Ledger.reachable_cancel

#print axioms APS.Ledger.commit_all_or_none

#print axioms APS.Ledger.cancel_all_or_none

#print axioms APS.Ledger.step_refs_mono

#print axioms APS.Ledger.run_refs_mono

#print axioms APS.Ledger.ledger_safe

#print axioms APS.Ledger.commit_preserves_charged
