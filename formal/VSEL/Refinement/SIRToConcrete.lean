/-
  VSEL Refinement — R₁₂: SIR → Concrete Execution
  Requirements: 9.2, 9.6

  Proves that the Rust concrete execution is a faithful refinement of the SIR.
  Uses semantic mapping functions mu_S, mu_Sigma from `VSEL.Mapping.SemanticMapping`
  and the commutativity theorems from `VSEL.Mapping.Commutativity`.

  Proof obligations:
  - R12-1: mu_S totality
  - R12-2: mu_S determinism
  - R12-3: Execution-mapping commutativity (THM-1 / TP-2)
  - R12-4: Observable commutativity (THM-2)
  - R12-5: Encoding injectivity (DEF-2)
  - R12-6: Derived state determinism (DEF-1)
  - TP-2:  Concrete refines SIR (composite)
  - TP-11: Encoding injectivity
-/

import VSEL.Foundations.State
import VSEL.Foundations.Input
import VSEL.Foundations.Transition
import VSEL.Mapping.SemanticMapping
import VSEL.Mapping.Commutativity
import VSEL.Mapping.Observable

namespace VSEL.Refinement

open VSEL.Foundations
open VSEL.Mapping

-- =========================================================================
-- R12-1: mu_S totality — automatic for Lean functions, stated for documentation
-- =========================================================================

/-- R12-1: mu_S is total — defined for all states.
    Automatic for Lean functions (all functions are total).
    Stated explicitly for documentation and cross-reference with Requirement 9.2. -/
theorem r12_mu_S_total (s : State) : ∃ f, mu_S s = f ∧ ∀ y, mu_S s = y → y = f := by
  exact ⟨mu_S s, rfl, fun _ h => h.symm⟩

-- =========================================================================
-- R12-2: mu_S determinism — automatic for Lean functions
-- =========================================================================

/-- R12-2: mu_S is deterministic — same input always produces same output.
    Automatic for Lean functions (pure, no side effects).
    Requirement: 9.2 -/
theorem r12_mu_S_deterministic (s : State) : mu_S s = mu_S s := by rfl

-- =========================================================================
-- R12-3: Execution-mapping commutativity (THM-1 / TP-2)
-- mu_S(Apply_c(s, sigma)) = Apply_f(mu_S(s), mu_Sigma(sigma))
-- =========================================================================

/-- R12-3: Execution-mapping commutativity (THM-1 / TP-2).
    mu_S(Apply(s, sigma)) = Apply_f(mu_S(s), mu_Sigma(sigma))
    Re-stated from Commutativity.lean as the R₁₂ refinement obligation.
    Requirement: 9.2, 9.6 -/
theorem r12_execution_commutativity (s : State) (sigma : Input) :
    mu_S (Apply s sigma) = Apply_f (mu_S s) (mu_Sigma sigma) :=
  thm1_execution_commutativity s sigma

-- =========================================================================
-- R12-4: Observable commutativity (THM-2)
-- mu_O(Obs_c(s, sigma, s')) = Obs_f(mu_S(s), mu_Sigma(sigma), mu_S(s'))
-- =========================================================================

/-- R12-4: Observable commutativity (THM-2).
    mu_O(Obs(s, sigma, s')) = Obs_f(mu_S(s), mu_Sigma(sigma), mu_S(s'))
    Re-stated from Observable.lean as the R₁₂ refinement obligation.
    Axiomatized because Obs, Obs_f, mu_O, mu_S, mu_Sigma are all opaque.
    Requirement: 9.2, 9.6 -/
theorem r12_observable_commutativity (s : State) (sigma : Input) (s' : State) :
    mu_O (Obs s sigma s') = Obs_f (mu_S s) (mu_Sigma sigma) (mu_S s') :=
  thm2_observable_commutativity s sigma s'

-- =========================================================================
-- R12-5: Encoding injectivity (DEF-2)
-- Encode(s₁) = Encode(s₂) ⟹ s₁ = s₂
-- =========================================================================

/-- Encode: State → List UInt8 — canonical state encoding.
    Opaque: concrete encoding is in Rust (deterministic serialization). -/
opaque Encode : State → List UInt8

/-- R12-5 / TP-11: Encoding injectivity (DEF-2).
    Encode(s₁) = Encode(s₂) ⟹ s₁ = s₂
    Two states with the same encoding are identical.
    Axiomatized because Encode is opaque (Rust implementation).
    Requirement: 9.2, 9.6 -/
axiom r12_encoding_injectivity (s₁ s₂ : State) :
  Encode s₁ = Encode s₂ → s₁ = s₂

-- =========================================================================
-- R12-6: Derived state determinism (DEF-1)
-- D = Derive(C) is deterministic — automatic for Lean functions
-- =========================================================================

/-- R12-6: Derived state determinism (DEF-1).
    Derive is a function, so D = Derive(C) is deterministic.
    Requirement: 9.2 -/
theorem r12_derived_determinism (c : CanonicalState) :
    Derive c = Derive c := by rfl

/-- R12-6 stronger: Derive produces exactly one result. -/
theorem r12_derived_unique (c : CanonicalState) :
    ∃ d, Derive c = d ∧ ∀ y, Derive c = y → y = d := by
  exact ⟨Derive c, rfl, fun _ h => h.symm⟩

-- =========================================================================
-- TP-2: Concrete refines SIR through the mapping (composite)
-- Combining R12-3 with TP-1 gives the full refinement chain
-- =========================================================================

/-- TP-2: Concrete refines SIR through the semantic mapping.
    The fundamental commutativity theorem ensures that concrete execution
    and formal execution agree when mediated by the mapping functions.
    Requirement: 9.2, 9.6 -/
theorem tp2_concrete_refines_sir (s : State) (sigma : Input) :
    mu_S (Apply s sigma) = Apply_f (mu_S s) (mu_Sigma sigma) :=
  r12_execution_commutativity s sigma

/-- TP-2 with observable: Both execution and observable commutativity hold. -/
theorem tp2_with_observable (s : State) (sigma : Input) :
    mu_S (Apply s sigma) = Apply_f (mu_S s) (mu_Sigma sigma)
    ∧ mu_O (Obs s sigma (Apply s sigma))
        = Obs_f (mu_S s) (mu_Sigma sigma) (Apply_f (mu_S s) (mu_Sigma sigma)) := by
  constructor
  · exact r12_execution_commutativity s sigma
  · rw [r12_observable_commutativity s sigma (Apply s sigma)]
    rw [r12_execution_commutativity s sigma]

-- =========================================================================
-- TP-11: Encoding injectivity (re-stated from R12-5 for theorem catalog)
-- =========================================================================

/-- TP-11: Encoding injectivity.
    Encode(s₁) = Encode(s₂) ⟹ s₁ = s₂
    Identical encodings imply identical states.
    Requirement: 9.4, 9.6 -/
theorem tp11_encoding_injectivity (s₁ s₂ : State) :
    Encode s₁ = Encode s₂ → s₁ = s₂ :=
  r12_encoding_injectivity s₁ s₂

/-- TP-11 contrapositive: Different states have different encodings. -/
theorem tp11_encoding_injectivity_contra (s₁ s₂ : State) :
    s₁ ≠ s₂ → Encode s₁ ≠ Encode s₂ := by
  intro h_neq h_enc
  exact h_neq (r12_encoding_injectivity s₁ s₂ h_enc)

-- =========================================================================
-- Derived theorems combining R₁₂ obligations
-- =========================================================================

/-- Sequential commutativity through R₁₂: two-step execution commutes. -/
theorem r12_sequential (s : State) (sigma₁ sigma₂ : Input) :
    mu_S (Apply (Apply s sigma₁) sigma₂)
      = Apply_f (Apply_f (mu_S s) (mu_Sigma sigma₁)) (mu_Sigma sigma₂) :=
  thm1_sequential s sigma₁ sigma₂

/-- Canonicalization preserves R₁₂ commutativity. -/
theorem r12_canon_preserves (s : State) (sigma : Input) :
    mu_S (Apply s (Canonicalize_Input sigma))
      = Apply_f (mu_S s) (mu_Sigma sigma) :=
  tp8_canon_execution_corollary s sigma

end VSEL.Refinement
