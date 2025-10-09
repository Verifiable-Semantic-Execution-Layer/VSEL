/-
  VSEL Semantic Mapping — Commutativity Theorems
  Mirrors: protocol/crates/vsel-mapping/src/mapping.rs (verify_* functions)
  Requirements: 9.6, 4.2, 4.4, 4.5, 4.6

  This file states and proves (or axiomatizes) the core commutativity
  theorems that ensure the Rust concrete execution is semantically
  faithful to the Lean 4 formal specification.

  Since the concrete implementations are opaque (in Rust), the fundamental
  commutativity properties are stated as axioms. Derived theorems are
  proven from these axioms where possible.

  Theorems:
  - THM-1 (TP-2): Execution-mapping commutativity
  - THM-4 (TP-9): Auxiliary data independence
  - THM-5:        Derived state commutativity
  - TP-7:         Canonicalization idempotence (input and state)
  - TP-8:         Canonicalization semantic preservation
-/

import VSEL.Foundations.State
import VSEL.Foundations.Input
import VSEL.Foundations.Transition
import VSEL.Mapping.SemanticMapping

namespace VSEL.Mapping

open VSEL.Foundations

-- =========================================================================
-- THM-1 (TP-2): Execution-Mapping Commutativity
-- μ_S(Apply(s, σ)) = Apply_f(μ_S(s), μ_Σ(σ))
--
-- This is the fundamental semantic preservation theorem. It states that
-- applying a transition concretely and then mapping the result to the
-- formal domain is equivalent to mapping the inputs first and applying
-- the formal transition function.
--
-- Axiomatized because Apply and Apply_f are opaque (Rust and SIR).
-- Validated by differential testing in Rust (verify_execution_commutativity).
-- =========================================================================

/-- THM-1 (TP-2): Execution-mapping commutativity.
    ∀ s σ, μ_S(Apply(s, σ)) = Apply_f(μ_S(s), μ_Σ(σ))
    Requirement: 4.2, 9.6 -/
axiom thm1_execution_commutativity (s : State) (sigma : Input) :
  μ_S (Apply s sigma) = Apply_f (μ_S s) (μ_Σ sigma)

-- =========================================================================
-- THM-4 (TP-9): Auxiliary Data Independence
-- Apply(s, ⟨p, a, aux₁⟩) = Apply(s, ⟨p, a, aux₂⟩)
--
-- Auxiliary data must NOT influence the semantic outcome of a transition.
-- Two inputs that differ only in their auxiliary data field must produce
-- identical post-states.
--
-- Axiomatized because Apply is opaque.
-- Validated by property testing in Rust (verify_auxiliary_exclusion).
-- =========================================================================

/-- THM-4 (TP-9): Auxiliary data independence.
    ∀ s p a aux₁ aux₂,
      Apply(s, ⟨p, a, aux₁⟩) = Apply(s, ⟨p, a, aux₂⟩)
    Requirement: 4.5 -/
axiom thm4_auxiliary_independence (s : State) (p : Payload) (a : Authorization)
    (aux₁ aux₂ : AuxiliaryData) :
  Apply s { payload := p, auth := a, aux := aux₁ }
    = Apply s { payload := p, auth := a, aux := aux₂ }

/-- Corollary: Auxiliary data independence through the mapping.
    If two inputs differ only in aux, their formal post-states are equal. -/
theorem thm4_formal_corollary (s : State) (p : Payload) (a : Authorization)
    (aux₁ aux₂ : AuxiliaryData) :
    μ_S (Apply s { payload := p, auth := a, aux := aux₁ })
      = μ_S (Apply s { payload := p, auth := a, aux := aux₂ }) := by
  rw [thm4_auxiliary_independence s p a aux₁ aux₂]

-- =========================================================================
-- THM-5: Derived State Commutativity
-- μ_D(Derive(C)) = Derive_f(μ_C(C))
--
-- Mapping the derived state of a canonical state is equivalent to
-- computing the formal derived state from the mapped canonical state.
--
-- We express this using the full state mapping since μ_S includes
-- the derived component.
-- =========================================================================

/-- μ_C : CanonicalState → FormalState — map canonical state component.
    Opaque: extracts and maps just the canonical component. -/
opaque μ_C : CanonicalState → FormalState

/-- Opaque mapping of DerivedState to FormalState (for the derived component). -/
opaque μ_D : DerivedState → FormalState

/-- THM-5: Derived state commutativity.
    μ_D(Derive(C)) = Derive_f(μ_C(C))
    Mapping the result of Derive is equivalent to applying Derive_f
    to the mapped canonical state.
    Requirement: 4.6 -/
axiom thm5_derived_commutativity (c : CanonicalState) :
  μ_D (Derive c) = Derive_f (μ_C c)

/-- Corollary: Derive is deterministic through the mapping.
    Computing Derive twice and mapping yields the same formal state. -/
theorem thm5_derive_deterministic_mapping (c : CanonicalState) :
    μ_D (Derive c) = μ_D (Derive c) := by
  rfl

-- =========================================================================
-- TP-7: Canonicalization Idempotence
-- Canonicalize(Canonicalize(σ)) = Canonicalize(σ)
-- Canonicalize(Canonicalize(s)) = Canonicalize(s)
--
-- Canonicalization is idempotent: applying it twice yields the same
-- result as applying it once. This is DEF-5 from the formal spec.
--
-- Axiomatized because Canonicalize_Input and Canonicalize_State are opaque.
-- Validated by unit tests in Rust (test_canonicalize_input_idempotent,
-- test_canonicalize_state_idempotent).
-- =========================================================================

/-- TP-7a: Input canonicalization idempotence (DEF-5).
    ∀ σ, Canonicalize_Input(Canonicalize_Input(σ)) = Canonicalize_Input(σ)
    Requirement: 4.4, 9.6 -/
axiom tp7_input_canonicalization_idempotent (sigma : Input) :
  Canonicalize_Input (Canonicalize_Input sigma) = Canonicalize_Input sigma

/-- TP-7b: State canonicalization idempotence (DEF-5).
    ∀ s, Canonicalize_State(Canonicalize_State(s)) = Canonicalize_State(s)
    Requirement: 4.4, 9.6 -/
axiom tp7_state_canonicalization_idempotent (s : State) :
  Canonicalize_State (Canonicalize_State s) = Canonicalize_State s

/-- Corollary: Repeated canonicalization is a no-op after the first application.
    Applying canonicalization n times (n ≥ 1) equals applying it once. -/
theorem tp7_input_canon_triple (sigma : Input) :
    Canonicalize_Input (Canonicalize_Input (Canonicalize_Input sigma))
      = Canonicalize_Input sigma := by
  rw [tp7_input_canonicalization_idempotent (Canonicalize_Input sigma)]
  rw [tp7_input_canonicalization_idempotent sigma]

theorem tp7_state_canon_triple (s : State) :
    Canonicalize_State (Canonicalize_State (Canonicalize_State s))
      = Canonicalize_State s := by
  rw [tp7_state_canonicalization_idempotent (Canonicalize_State s)]
  rw [tp7_state_canonicalization_idempotent s]

-- =========================================================================
-- TP-8: Canonicalization Semantic Preservation
-- μ_Σ(Canonicalize_Input(σ)) = μ_Σ(σ)
--
-- Canonicalization does not change the semantic meaning of an input.
-- The formal representation of a canonicalized input is identical to
-- the formal representation of the original input.
--
-- Axiomatized because both μ_Σ and Canonicalize_Input are opaque.
-- Validated by differential testing in Rust.
-- =========================================================================

/-- TP-8a: Input canonicalization semantic preservation.
    ∀ σ, μ_Σ(Canonicalize_Input(σ)) = μ_Σ(σ)
    Canonical form maps to the same formal input as the original.
    Requirement: 4.4, 9.6 -/
axiom tp8_input_canonicalization_preserves_semantics (sigma : Input) :
  μ_Σ (Canonicalize_Input sigma) = μ_Σ sigma

/-- TP-8b: State canonicalization semantic preservation.
    ∀ s, μ_S(Canonicalize_State(s)) = μ_S(s)
    Canonical form maps to the same formal state as the original.
    Requirement: 4.4, 9.6 -/
axiom tp8_state_canonicalization_preserves_semantics (s : State) :
  μ_S (Canonicalize_State s) = μ_S s

/-- Corollary: Canonicalization commutes with execution through the mapping.
    Apply on canonicalized inputs maps the same as Apply on original inputs. -/
theorem tp8_canon_execution_corollary (s : State) (sigma : Input) :
    μ_S (Apply s (Canonicalize_Input sigma))
      = Apply_f (μ_S s) (μ_Σ sigma) := by
  rw [thm1_execution_commutativity s (Canonicalize_Input sigma)]
  rw [tp8_input_canonicalization_preserves_semantics sigma]

/-- Corollary: Canonicalized state execution maps the same. -/
theorem tp8_canon_state_execution_corollary (s : State) (sigma : Input) :
    μ_S (Apply (Canonicalize_State s) sigma)
      = Apply_f (μ_S s) (μ_Σ sigma) := by
  rw [thm1_execution_commutativity (Canonicalize_State s) sigma]
  rw [tp8_state_canonicalization_preserves_semantics s]

-- =========================================================================
-- Derived theorems combining multiple axioms
-- =========================================================================

/-- Combined: Canonicalization + auxiliary independence.
    Canonicalizing an input clears aux, so two inputs differing only in aux
    canonicalize to the same input. -/
axiom canon_clears_aux (p : Payload) (a : Authorization) (aux₁ aux₂ : AuxiliaryData) :
  Canonicalize_Input { payload := p, auth := a, aux := aux₁ }
    = Canonicalize_Input { payload := p, auth := a, aux := aux₂ }

/-- Execution on canonicalized inputs with different aux yields same formal state. -/
theorem canon_aux_formal_equivalence (s : State) (p : Payload) (a : Authorization)
    (aux₁ aux₂ : AuxiliaryData) :
    μ_S (Apply s (Canonicalize_Input { payload := p, auth := a, aux := aux₁ }))
      = μ_S (Apply s (Canonicalize_Input { payload := p, auth := a, aux := aux₂ })) := by
  rw [canon_clears_aux p a aux₁ aux₂]

/-- THM-1 applied twice: sequential transitions commute through the mapping. -/
theorem thm1_sequential (s : State) (sigma₁ sigma₂ : Input) :
    μ_S (Apply (Apply s sigma₁) sigma₂)
      = Apply_f (Apply_f (μ_S s) (μ_Σ sigma₁)) (μ_Σ sigma₂) := by
  rw [thm1_execution_commutativity (Apply s sigma₁) sigma₂]
  rw [thm1_execution_commutativity s sigma₁]

end VSEL.Mapping
