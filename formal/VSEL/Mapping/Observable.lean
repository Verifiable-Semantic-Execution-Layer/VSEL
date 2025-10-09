/-
  VSEL Semantic Mapping — Observable Commutativity
  Mirrors: protocol/crates/vsel-mapping/src/mapping.rs (verify_observable_commutativity)
  Requirements: 9.6, 4.3

  This file states and proves (or axiomatizes) the observable commutativity
  theorem (THM-2 / TP-10), which ensures that computing observables
  concretely and then mapping them to the formal domain is equivalent to
  computing observables directly in the formal domain.

  Theorems:
  - THM-2 (TP-10): Observable commutativity
  - Observable determinism
  - Observable consistency with transition classification
-/

import VSEL.Foundations.State
import VSEL.Foundations.Input
import VSEL.Foundations.Transition
import VSEL.Mapping.SemanticMapping
import VSEL.Mapping.Commutativity

namespace VSEL.Mapping

open VSEL.Foundations

-- =========================================================================
-- THM-2 (TP-10): Observable Commutativity
-- μ_O(Obs(s, σ, s')) = Obs_f(μ_S(s), μ_Σ(σ), μ_S(s'))
--
-- Computing the observable concretely and mapping it to the formal domain
-- is equivalent to mapping the state and input first and computing the
-- formal observable.
--
-- Axiomatized because Obs, Obs_f, μ_O, μ_S, μ_Σ are all opaque.
-- Validated by differential testing in Rust (verify_observable_commutativity).
-- =========================================================================

/-- THM-2 (TP-10): Observable commutativity.
    ∀ s σ s', μ_O(Obs(s, σ, s')) = Obs_f(μ_S(s), μ_Σ(σ), μ_S(s'))
    Requirement: 4.3, 9.6 -/
axiom thm2_observable_commutativity (s : State) (sigma : Input) (s' : State) :
  μ_O (Obs s sigma s') = Obs_f (μ_S s) (μ_Σ sigma) (μ_S s')

-- =========================================================================
-- Observable determinism
-- =========================================================================

/-- Observable determinism: Obs is a function (automatic for Lean functions,
    stated explicitly for documentation). -/
theorem obs_deterministic (s : State) (sigma : Input) (s' : State) :
    ∃! o, Obs s sigma s' = o := by
  exact ⟨Obs s sigma s', rfl, fun _ h => h.symm⟩

/-- Formal observable determinism: Obs_f is a function. -/
theorem obs_f_deterministic (sf : FormalState) (sigf : FormalInput) (sf' : FormalState) :
    ∃! o, Obs_f sf sigf sf' = o := by
  exact ⟨Obs_f sf sigf sf', rfl, fun _ h => h.symm⟩

-- =========================================================================
-- Derived theorems
-- =========================================================================

/-- Corollary: Observable commutativity with Apply.
    When s' = Apply(s, σ), the observable commutes through the mapping. -/
theorem thm2_with_apply (s : State) (sigma : Input) :
    μ_O (Obs s sigma (Apply s sigma))
      = Obs_f (μ_S s) (μ_Σ sigma) (Apply_f (μ_S s) (μ_Σ sigma)) := by
  rw [thm2_observable_commutativity s sigma (Apply s sigma)]
  rw [thm1_execution_commutativity s sigma]

/-- Corollary: Observable commutativity with canonicalized input.
    Canonicalizing the input does not change the formal observable
    (combining TP-8 and THM-2). -/
theorem thm2_canon_input (s : State) (sigma : Input) :
    μ_O (Obs s (Canonicalize_Input sigma) (Apply s (Canonicalize_Input sigma)))
      = Obs_f (μ_S s) (μ_Σ sigma)
          (Apply_f (μ_S s) (μ_Σ sigma)) := by
  rw [thm2_observable_commutativity s (Canonicalize_Input sigma)
        (Apply s (Canonicalize_Input sigma))]
  rw [thm1_execution_commutativity s (Canonicalize_Input sigma)]
  rw [tp8_input_canonicalization_preserves_semantics sigma]

/-- Axiom: μ_Σ ignores auxiliary data.
    The formal input representation does not depend on auxiliary data.
    This is the mapping-level consequence of THM-4. -/
axiom μ_Σ_ignores_aux (p : Payload) (a : Authorization) (aux₁ aux₂ : AuxiliaryData) :
  μ_Σ { payload := p, auth := a, aux := aux₁ }
    = μ_Σ { payload := p, auth := a, aux := aux₂ }

/-- Corollary: Auxiliary data does not influence observables.
    Two inputs differing only in aux produce the same formal observable.
    Proven from THM-2, THM-1, and μ_Σ_ignores_aux. -/
theorem obs_auxiliary_independence (s : State) (p : Payload) (a : Authorization)
    (aux₁ aux₂ : AuxiliaryData) :
    let σ₁ : Input := { payload := p, auth := a, aux := aux₁ }
    let σ₂ : Input := { payload := p, auth := a, aux := aux₂ }
    μ_O (Obs s σ₁ (Apply s σ₁)) = μ_O (Obs s σ₂ (Apply s σ₂)) := by
  simp only
  rw [thm2_observable_commutativity s
        { payload := p, auth := a, aux := aux₁ }
        (Apply s { payload := p, auth := a, aux := aux₁ })]
  rw [thm2_observable_commutativity s
        { payload := p, auth := a, aux := aux₂ }
        (Apply s { payload := p, auth := a, aux := aux₂ })]
  rw [thm1_execution_commutativity s { payload := p, auth := a, aux := aux₁ }]
  rw [thm1_execution_commutativity s { payload := p, auth := a, aux := aux₂ }]
  rw [μ_Σ_ignores_aux p a aux₁ aux₂]

/-- Sequential observable commutativity: observables of a two-step execution
    commute through the mapping. -/
theorem thm2_sequential (s : State) (sigma₁ sigma₂ : Input) :
    let s₁ := Apply s sigma₁
    let s₂ := Apply s₁ sigma₂
    μ_O (Obs s₁ sigma₂ s₂)
      = Obs_f (Apply_f (μ_S s) (μ_Σ sigma₁)) (μ_Σ sigma₂)
          (Apply_f (Apply_f (μ_S s) (μ_Σ sigma₁)) (μ_Σ sigma₂)) := by
  simp only
  rw [thm2_observable_commutativity (Apply s sigma₁) sigma₂
        (Apply (Apply s sigma₁) sigma₂)]
  rw [thm1_execution_commutativity (Apply s sigma₁) sigma₂]
  rw [thm1_execution_commutativity s sigma₁]

end VSEL.Mapping
