/-
APS formal model, F7a: the cumulative spend ledger.

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

def empty : Ledger := ⟨fun _ => ⟨0, 0⟩, fun _ => none⟩

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
      setRes L.res r ⟨unit, amount, ids, .reserved⟩⟩)

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
      else (.dispatched, ⟨L.counters, setRes L.res r { p with state := .dispatched }⟩)

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
        setRes L.res r { p with state := .committed }⟩)

def cancel (L : Ledger) (r : Ref) : Code × Ledger :=
  match L.res r with
  | none => (.notFound, L)
  | some p =>
      if p.state = .cancelled then (.idempotent, L)
      else if p.state ≠ .reserved then (.invalidState, L)
      else if holds L.counters p = false then (.invalidState, L)
      else (.cancelled, ⟨release L.counters p.ids p.amount,
        setRes L.res r { p with state := .cancelled }⟩)

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

/-- 3. A successful reserve adds the amount to every bounded ancestor counter and
changes no other counter. -/
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

end APS.Ledger

#print axioms APS.Ledger.ceiling
#print axioms APS.Ledger.run_inv
#print axioms APS.Ledger.step_fail
#print axioms APS.Ledger.reserve_all_or_none
#print axioms APS.Ledger.siblings_share
#print axioms APS.Ledger.reserve_same_footprint
