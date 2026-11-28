/-
APS formal model, F5: current validity and revocation of every chain member.

Mirrors agent-passport-system src/v2/authority-delegation/verify.ts
verifyAuthorityDelegationChain, phase 10 (current validity of every member at `now`,
NOT_YET_VALID and EXPIRED) and phase 11 (revocation state of every member, REVOKED
and REVOCATION_UNKNOWN), after the structural phases, which are abstracted here as an
optional first failure. A resolver that throws or answers anything other than active
or revoked is unknown, as in verify.ts.

Proved:
  1. the result is valid exactly when the structural phases pass, every member is
     inside its half-open window at `now`, and every member is active
  2. a revoked or unknown member anywhere in the chain means the result is never valid.
     It is not always REVOKED: an earlier unknown member gives REVOCATION_UNKNOWN, and
     an earlier failing phase gives its own failure
  3. revoking a member never turns a non-valid result into a valid one
  4. with F3: a valid result over a valid chain means every member is current and
     active and the leaf is contained in every ancestor
-/
import APSFormal.Authority

namespace APS.Revocation

open APS.Authority

inductive Status where
  | active
  | revoked
  | unknown
  deriving DecidableEq, Repr

inductive Code where
  | structural
  | notYetValid
  | expired
  | revoked
  | revocationUnknown
  deriving DecidableEq, Repr

inductive Outcome where
  | valid
  | invalid (code : Code) (index : Nat)
  | indeterminate (code : Code) (index : Nat)
  deriving DecidableEq, Repr

structure Member where
  record : Record
  status : Status

def Current (now : Nat) (m : Member) : Prop :=
  m.record.authority.time.not_before ≤ now ∧ now < m.record.authority.time.not_after

/-- Phase 10, first failing member. -/
def currentPhase (now : Nat) : Nat → List Member → Option Outcome
  | _, [] => none
  | i, m :: ms =>
      if now < m.record.authority.time.not_before then some (.invalid .notYetValid i)
      else if m.record.authority.time.not_after ≤ now then some (.invalid .expired i)
      else currentPhase now (i + 1) ms

/-- Phase 11, first member that is not active. -/
def revocationPhase : Nat → List Member → Option Outcome
  | _, [] => none
  | i, m :: ms =>
      match m.status with
      | .revoked => some (.invalid .revoked i)
      | .unknown => some (.indeterminate .revocationUnknown i)
      | .active => revocationPhase (i + 1) ms

/-- The verifier after its structural phases. `structural` is the index of the first
structural failure, if any. -/
def verify (structural : Option Nat) (now : Nat) (chain : List Member) : Outcome :=
  match structural with
  | some i => .invalid .structural i
  | none =>
    match currentPhase now 0 chain with
    | some o => o
    | none =>
      match revocationPhase 0 chain with
      | some o => o
      | none => .valid

theorem currentPhase_none (now : Nat) : ∀ (i : Nat) (l : List Member),
    currentPhase now i l = none ↔ ∀ m ∈ l, Current now m
  | _, [] => by simp [currentPhase]
  | i, m :: ms => by
      simp only [currentPhase, List.mem_cons, forall_eq_or_imp, Current]
      by_cases h1 : now < m.record.authority.time.not_before
      · simp [h1]; omega
      · by_cases h2 : m.record.authority.time.not_after ≤ now
        · simp [h1, h2]; omega
        · simp only [h1, h2, if_false]
          rw [currentPhase_none now (i + 1) ms]
          simp only [Current]
          constructor
          · intro h; exact ⟨⟨by omega, by omega⟩, h⟩
          · intro h; exact h.2

theorem revocationPhase_none : ∀ (i : Nat) (l : List Member),
    revocationPhase i l = none ↔ ∀ m ∈ l, m.status = .active
  | _, [] => by simp [revocationPhase]
  | i, m :: ms => by
      simp only [revocationPhase, List.mem_cons, forall_eq_or_imp]
      cases h : m.status with
      | revoked => simp
      | unknown => simp
      | active => simp [revocationPhase_none (i + 1) ms]

theorem currentPhase_not_valid (now : Nat) : ∀ (i : Nat) (l : List Member) (o : Outcome),
    currentPhase now i l = some o → o ≠ .valid
  | _, [], _, h => by simp [currentPhase] at h
  | i, m :: ms, o, h => by
      simp only [currentPhase] at h
      split at h
      · cases h; simp
      · split at h
        · cases h; simp
        · exact currentPhase_not_valid now (i + 1) ms o h

theorem revocationPhase_not_valid : ∀ (i : Nat) (l : List Member) (o : Outcome),
    revocationPhase i l = some o → o ≠ .valid
  | _, [], _, h => by simp [revocationPhase] at h
  | i, m :: ms, o, h => by
      simp only [revocationPhase] at h
      split at h
      · cases h; simp
      · cases h; simp
      · exact revocationPhase_not_valid (i + 1) ms o h

/-- 1. Exactly when the result is valid. -/
theorem verify_valid_iff (structural : Option Nat) (now : Nat) (chain : List Member) :
    verify structural now chain = .valid ↔
      structural = none ∧ (∀ m ∈ chain, Current now m) ∧ (∀ m ∈ chain, m.status = .active) := by
  unfold verify
  cases structural with
  | some i => simp
  | none =>
    simp only [true_and]
    cases hc : currentPhase now 0 chain with
    | some o =>
      have hne := currentPhase_not_valid now 0 chain o hc
      have : ¬ ∀ m ∈ chain, Current now m := by
        rw [← currentPhase_none now 0 chain, hc]; simp
      simp only [hne, false_iff]
      exact fun h => this h.1
    | none =>
      have hcur := (currentPhase_none now 0 chain).1 hc
      cases hr : revocationPhase 0 chain with
      | some o =>
        have hne := revocationPhase_not_valid 0 chain o hr
        have : ¬ ∀ m ∈ chain, m.status = .active := by
          rw [← revocationPhase_none 0 chain, hr]; simp
        simp only [hne, false_iff]
        exact fun h => this h.2
      | none =>
        constructor
        · intro _; exact ⟨hcur, (revocationPhase_none 0 chain).1 hr⟩
        · intro _; simp

/-- 2. A revoked or unknown member anywhere means never valid. -/
theorem not_active_never_valid (structural : Option Nat) (now : Nat) (chain : List Member)
    (m : Member) (hm : m ∈ chain) (hs : m.status ≠ .active) :
    verify structural now chain ≠ .valid := by
  intro h
  exact hs (((verify_valid_iff structural now chain).1 h).2.2 m hm)

/-- 2, continued. The failure is not always REVOKED: an unknown member before a revoked
one gives REVOCATION_UNKNOWN at the earlier index. -/
example : verify none 0
    [⟨witnessRecord 1, .unknown⟩, ⟨witnessRecord 0, .revoked⟩] =
      .indeterminate .revocationUnknown 0 := by
  decide

/-- 3. Revoking a member never turns a non-valid result into a valid one. -/
theorem revoke_monotone (structural : Option Nat) (now : Nat) (pre post : List Member)
    (m : Member) :
    verify structural now (pre ++ ⟨m.record, .revoked⟩ :: post) ≠ .valid :=
  not_active_never_valid structural now _ ⟨m.record, .revoked⟩ (by simp) (by simp)

/-- 4. With F3: a valid result over a valid chain means every member is current and
active and every later record is contained in every earlier one. -/
theorem valid_current_authority (now : Nat) (pre : List Member) (a : Member)
    (post : List Member)
    (hchain : ValidChain ((pre ++ a :: post).map Member.record))
    (hv : verify none now (pre ++ a :: post) = .valid) :
    (∀ m ∈ pre ++ a :: post, Current now m ∧ m.status = .active) ∧
    (∀ p ∈ pre, Le a.record.authority p.record.authority) ∧
    (∀ x ∈ post, Le x.record.authority a.record.authority) := by
  obtain ⟨_, hcur, hact⟩ := (verify_valid_iff none now _).1 hv
  rw [List.map_append, List.map_cons] at hchain
  obtain ⟨h1, h2⟩ := chain_le_ancestor _ _ _ hchain
  refine ⟨fun m hm => ⟨hcur m hm, hact m hm⟩, ?_, ?_⟩
  · intro p hp
    exact h2 p.record (List.mem_map_of_mem _ hp) a.record (List.mem_cons_self _ _)
  · intro x hx
    exact h1 x.record (List.mem_map_of_mem _ hx)

end APS.Revocation

#print axioms APS.Revocation.verify_valid_iff
#print axioms APS.Revocation.not_active_never_valid
#print axioms APS.Revocation.revoke_monotone
#print axioms APS.Revocation.valid_current_authority
