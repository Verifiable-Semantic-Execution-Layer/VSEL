/-
  VSEL Composition — Assume-Guarantee Contract Definitions
  Mirrors: protocol/crates/vsel-composition/src/contracts.rs
  Requirements: 9.6, 11.1, 11.2, 11.7

  Each subsystem defines a contract:
    Contract(M) = {Assumes, Guarantees, Effects, Forbids}

  Composition rule (Requirement 11.2):
    COMPOSE(M_A, M_B) is valid ⟺
      G(M_A) ⊇ A(M_B) ∧ G(M_B) ⊇ A(M_A)
      ∧ Eff(M_A) ∩ F(M_B) = ∅ ∧ Eff(M_B) ∩ F(M_A) = ∅

  Backward-compatible upgrades (Requirement 11.7):
    A(M^v2) ⊆ A(M^v1)  — new version assumes less
    G(M^v2) ⊇ G(M^v1)  — new version guarantees more
-/

import VSEL.Foundations.State
import VSEL.Foundations.Input
import VSEL.Foundations.Transition
import VSEL.Foundations.Invariants

namespace VSEL.Composition

open VSEL.Foundations

-- =========================================================================
-- SubsystemContract — assume-guarantee contract for a subsystem
-- =========================================================================

/-- Assume-guarantee contract for a subsystem.

    Contract(M) = {Assumes, Guarantees, Effects, Forbids}

    - `assumes`:    property IDs the subsystem requires from its environment
    - `guarantees`: property IDs the subsystem provides to its environment
    - `effects`:    state effects (mutations) the subsystem may perform
    - `forbids`:    interactions the subsystem prohibits

    Property IDs are modeled as `List String` for simplicity. The Rust
    implementation uses `BTreeSet<String>` for deduplication; here we
    use list-based subset and disjointness predicates. -/
structure SubsystemContract where
  assumes    : List String
  guarantees : List String
  effects    : List String
  forbids    : List String
  deriving DecidableEq, Repr

-- =========================================================================
-- List predicates — subset and disjointness
-- =========================================================================

/-- List subset: every element of `xs` is a member of `ys`. -/
def List.Subset (xs ys : List String) : Prop :=
  ∀ x, x ∈ xs → x ∈ ys

/-- List disjointness: no element belongs to both `xs` and `ys`. -/
def List.Disjoint (xs ys : List String) : Prop :=
  ∀ x, x ∈ xs → x ∉ ys

-- =========================================================================
-- ContractSatisfied — a state satisfies a contract
-- =========================================================================

/-- Predicate: a state satisfies a contract if all global invariants hold.

    A subsystem satisfies its contract when the state it produces meets
    all guaranteed properties. Since guaranteed properties map to global
    invariants in the VSEL model, we require `GlobalInvariantsHold` as
    the concrete satisfaction condition.

    The `guarantees` field documents which property IDs are covered;
    the actual enforcement is through the invariant system. -/
def ContractSatisfied (s : State) (_contract : SubsystemContract) : Prop :=
  GlobalInvariantsHold s

-- =========================================================================
-- CompositionValid — the composition rule
-- =========================================================================

/-- Predicate: two contracts can be validly composed.

    COMPOSE(M_A, M_B) is valid ⟺
      G(M_A) ⊇ A(M_B)           — guarantees of A cover assumptions of B
      ∧ G(M_B) ⊇ A(M_A)         — guarantees of B cover assumptions of A
      ∧ Eff(M_A) ∩ F(M_B) = ∅   — effects of A don't conflict with forbids of B
      ∧ Eff(M_B) ∩ F(M_A) = ∅   — effects of B don't conflict with forbids of A

    Requirement: 11.2 -/
def CompositionValid (a b : SubsystemContract) : Prop :=
  List.Subset b.assumes a.guarantees
  ∧ List.Subset a.assumes b.guarantees
  ∧ List.Disjoint a.effects b.forbids
  ∧ List.Disjoint b.effects a.forbids

-- =========================================================================
-- BackwardCompatible — upgrade compatibility
-- =========================================================================

/-- Predicate: a new contract version is backward-compatible with the old.

    A(M^v2) ⊆ A(M^v1)  — new version assumes no more than old
    G(M^v2) ⊇ G(M^v1)  — new version guarantees at least as much as old

    Requirement: 11.7 -/
def BackwardCompatible (old new_ : SubsystemContract) : Prop :=
  List.Subset new_.assumes old.assumes
  ∧ List.Subset old.guarantees new_.guarantees

-- =========================================================================
-- Basic properties of composition
-- =========================================================================

/-- Composition validity is symmetric: if (A, B) compose validly,
    then (B, A) compose validly. -/
theorem composition_symmetric (a b : SubsystemContract) :
    CompositionValid a b → CompositionValid b a := by
  intro ⟨h1, h2, h3, h4⟩
  exact ⟨h2, h1, h4, h3⟩

/-- Backward compatibility is reflexive: every contract is compatible
    with itself. -/
theorem backward_compatible_refl (c : SubsystemContract) :
    BackwardCompatible c c := by
  constructor
  · intro x hx; exact hx
  · intro x hx; exact hx

end VSEL.Composition
