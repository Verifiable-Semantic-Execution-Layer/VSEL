/-
  VSEL Composition — Compositional Soundness Proofs
  Mirrors: protocol/crates/vsel-composition/src/cross_invariants.rs,
           protocol/crates/vsel-composition/src/proof_compose.rs
  Requirements: 9.6, 11.5, 11.10

  This file states the key compositional soundness theorems:

  - TP-14: Compositional soundness — if both subsystems satisfy their
    contracts and the composition is valid, then the composed system
    preserves all global invariants.

  - TP-15: Cross-invariant preservation — if composition is valid and
    both systems preserve their invariants, then cross-system invariants
    (CI-1 through CI-5) are preserved after transitions.

  Since the concrete implementations are in Rust and the composition
  semantics involve cross-system interaction, these properties are
  stated as axioms. They are validated by:
  - Property-based tests in Rust (proof_tests.rs, composition tests)
  - TLA+ model checking (Composition.tla)
  - Cross-invariant checks in Rust (cross_invariants.rs)
-/

import VSEL.Composition.Contract
import VSEL.Foundations.Invariants

namespace VSEL.Composition

open VSEL.Foundations

-- =========================================================================
-- Cross-system invariants — CI-1 through CI-5
-- =========================================================================

/-- CI-1: Resource conservation across two systems.
    Total_A + Total_B = constant.
    The combined total supply across both systems is preserved. -/
def CI1_ResourceConservation (s_a s_b : State) (total : Nat) : Prop :=
  let supply_a := s_a.canonical.accounts.foldl (fun acc (_, a) => acc + a.balance) 0
  let supply_b := s_b.canonical.accounts.foldl (fun acc (_, a) => acc + a.balance) 0
  supply_a + supply_b = total

/-- CI-2: Shared state consistency.
    Shared storage keys have identical values in both systems.
    Modeled as: for all keys in the shared set, lookup in both systems agrees. -/
def CI2_SharedStateConsistency (s_a s_b : State)
    (shared_keys : List StorageKey) : Prop :=
  ∀ k, k ∈ shared_keys →
    s_a.canonical.storage.lookup k = s_b.canonical.storage.lookup k
  where
    -- Association list lookup helper
    List.lookup {α : Type} [DecidableEq α] {β : Type}
        (xs : List (α × β)) (key : α) : Option β :=
      match xs.find? (fun p => p.1 == key) with
      | some (_, v) => some v
      | none => none

/-- CI-3: Authorization transitivity.
    Both systems independently verify authorization for cross-system
    operations. Modeled as a predicate over boolean authorization results. -/
def CI3_AuthorizationTransitivity (auth_a_valid auth_b_valid : Prop) : Prop :=
  auth_a_valid ∧ auth_b_valid

/-- CI-4: Causal consistency.
    Timestamps are consistent across systems — neither system is ahead
    of the other by more than a bounded drift. -/
def CI4_CausalConsistency (s_a s_b : State) (max_drift : Nat) : Prop :=
  let ts_a := s_a.environment.timestamp
  let ts_b := s_b.environment.timestamp
  (if ts_a ≥ ts_b then ts_a - ts_b else ts_b - ts_a) ≤ max_drift

/-- CI-5: Version compatibility.
    Major protocol versions must match for composition. -/
def CI5_VersionCompatibility (s_a s_b : State) : Prop :=
  s_a.canonical.systemData.protocolVersion.major
    = s_b.canonical.systemData.protocolVersion.major

-- =========================================================================
-- CrossInvariantsHold — aggregate cross-system invariant predicate
-- =========================================================================

/-- Configuration for cross-invariant checks. -/
structure CrossInvariantConfig where
  expectedTotal : Nat
  sharedKeys    : List StorageKey
  maxDrift      : Nat
  deriving DecidableEq, Repr

/-- All cross-system invariants (CI-1 through CI-5) hold between two states.

    This bundles CI-1 (resource conservation), CI-4 (causal consistency),
    and CI-5 (version compatibility) as the structurally checkable
    cross-invariants. CI-2 (shared state) requires a shared key set,
    and CI-3 (authorization) requires external authorization evidence. -/
def CrossInvariantsHold (s_a s_b : State) (config : CrossInvariantConfig) : Prop :=
  CI1_ResourceConservation s_a s_b config.expectedTotal
  ∧ CI2_SharedStateConsistency s_a s_b config.sharedKeys
  ∧ CI4_CausalConsistency s_a s_b config.maxDrift
  ∧ CI5_VersionCompatibility s_a s_b

-- =========================================================================
-- TP-14: Compositional Soundness
-- =========================================================================

/-- TP-14: Compositional soundness.

    If both subsystems satisfy their contracts and the composition is valid,
    then the composed system preserves all global invariants after a
    transition in subsystem A.

    Valid(M_A) ∧ Valid(M_B) ∧ Compatible(M_A, M_B) ⟹ Valid(M_A ∘ M_B)

    Axiomatized because:
    - Apply is opaque (concrete implementation in Rust)
    - Contract satisfaction involves cross-system reasoning
    - Validated by property-based tests and TLA+ model checking

    Requirement: 11.5 -/
axiom compositional_soundness
    (s_a : State) (contract_a : SubsystemContract)
    (s_b : State) (contract_b : SubsystemContract)
    (sigma : Input) :
  ContractSatisfied s_a contract_a
  → ContractSatisfied s_b contract_b
  → CompositionValid contract_a contract_b
  → GlobalInvariantsHold s_a
  → GlobalInvariantsHold s_b
  → GlobalInvariantsHold (Apply s_a sigma)

-- =========================================================================
-- TP-15: Cross-Invariant Preservation
-- =========================================================================

/-- TP-15: Cross-invariant preservation.

    If composition is valid and both systems preserve their invariants,
    then cross-system invariants (CI-1 through CI-5) are preserved
    after transitions in both subsystems.

    CompositionValid(A, B) ∧ CrossInvariantsHold(s_a, s_b)
      ∧ GlobalInvariantsHold(s_a) ∧ GlobalInvariantsHold(s_b)
      ⟹ CrossInvariantsHold(Apply(s_a, σ_a), Apply(s_b, σ_b))

    Axiomatized because:
    - Apply is opaque (concrete implementation in Rust)
    - Cross-invariant preservation depends on contract enforcement
    - Validated by cross-invariant checks in Rust and TLA+ model checking

    Requirement: 11.10 -/
axiom cross_invariant_preservation
    (contract_a contract_b : SubsystemContract)
    (s_a s_b : State)
    (sigma_a sigma_b : Input)
    (config : CrossInvariantConfig) :
  CompositionValid contract_a contract_b
  → CrossInvariantsHold s_a s_b config
  → GlobalInvariantsHold s_a
  → GlobalInvariantsHold s_b
  → CrossInvariantsHold (Apply s_a sigma_a) (Apply s_b sigma_b) config

-- =========================================================================
-- Derived theorems from TP-14 and TP-15
-- =========================================================================

/-- Corollary: Compositional soundness extends to sequential transitions.
    If the composed system is sound for one transition, it remains sound
    for a second transition (by re-applying TP-14). -/
theorem compositional_soundness_sequential
    (s_a : State) (contract_a : SubsystemContract)
    (s_b : State) (contract_b : SubsystemContract)
    (sigma₁ sigma₂ : Input)
    (h_sat_a : ContractSatisfied s_a contract_a)
    (h_sat_b : ContractSatisfied s_b contract_b)
    (h_comp : CompositionValid contract_a contract_b)
    (h_inv_a : GlobalInvariantsHold s_a)
    (h_inv_b : GlobalInvariantsHold s_b) :
    GlobalInvariantsHold (Apply (Apply s_a sigma₁) sigma₂) := by
  have h_step1 := compositional_soundness s_a contract_a s_b contract_b sigma₁
    h_sat_a h_sat_b h_comp h_inv_a h_inv_b
  -- Apply s_a sigma₁ preserves global invariants, so it satisfies the contract
  have h_sat_a' : ContractSatisfied (Apply s_a sigma₁) contract_a := h_step1
  exact compositional_soundness (Apply s_a sigma₁) contract_a s_b contract_b sigma₂
    h_sat_a' h_sat_b h_comp h_step1 h_inv_b

/-- Corollary: Backward-compatible upgrades preserve composition validity.
    If (old_a, b) compose validly and new_a is backward-compatible with old_a,
    then (new_a, b) compose validly — provided b's guarantees still cover
    new_a's (possibly reduced) assumptions. -/
theorem backward_compatible_preserves_composition
    (old_a new_a b : SubsystemContract)
    (h_compat : BackwardCompatible old_a new_a)
    (h_comp : CompositionValid old_a b) :
    List.Subset b.assumes new_a.guarantees
    → List.Disjoint new_a.effects b.forbids
    → List.Disjoint b.effects new_a.forbids
    → CompositionValid new_a b := by
  intro h_ga h_ef h_bf
  obtain ⟨_, h_old_sub_b, _, _⟩ := h_comp
  obtain ⟨h_new_sub_old, _⟩ := h_compat
  constructor
  · exact h_ga
  constructor
  · -- A(new_a) ⊆ A(old_a) ⊆ G(b)
    intro x hx
    exact h_old_sub_b x (h_new_sub_old x hx)
  constructor
  · exact h_ef
  · exact h_bf

end VSEL.Composition
