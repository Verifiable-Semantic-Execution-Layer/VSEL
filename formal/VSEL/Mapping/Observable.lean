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
-- mu_O(Obs(s, sigma, s')) = Obs_f(mu_S(s), mu_Sigma(sigma), mu_S(s'))
--
-- Computing the observable concretely and mapping it to the formal domain
-- is equivalent to mapping the state and input first and computing the
-- formal observable.
--
-- Axiomatized because Obs, Obs_f, mu_O, mu_S, mu_Sigma are all opaque.
-- Validated by differential testing in Rust (verify_observable_commutativity).
-- =========================================================================

/-- THM-2 (TP-10): Observable commutativity.
    ∀ s sigma s', mu_O(Obs(s, sigma, s')) = Obs_f(mu_S(s), mu_Sigma(sigma), mu_S(s'))
    Requirement: 4.3, 9.6 -/
axiom thm2_observable_commutativity (s : State) (sigma : Input) (s' : State) :
  mu_O (Obs s sigma s') = Obs_f (mu_S s) (mu_Sigma sigma) (mu_S s')

-- =========================================================================
-- Observable determinism
-- =========================================================================

/-- Observable determinism: Obs is a function (automatic for Lean functions,
    stated explicitly for documentation). -/
theorem obs_deterministic (s : State) (sigma : Input) (s' : State) :
    ∃ o, Obs s sigma s' = o ∧ ∀ y, Obs s sigma s' = y → y = o := by
  exact ⟨Obs s sigma s', rfl, fun _ h => h.symm⟩

/-- Formal observable determinism: Obs_f is a function. -/
theorem obs_f_deterministic (sf : FormalState) (sigf : FormalInput) (sf' : FormalState) :
    ∃ o, Obs_f sf sigf sf' = o ∧ ∀ y, Obs_f sf sigf sf' = y → y = o := by
  exact ⟨Obs_f sf sigf sf', rfl, fun _ h => h.symm⟩

-- =========================================================================
-- Derived theorems
-- =========================================================================

/-- Corollary: Observable commutativity with Apply.
    When s' = Apply(s, sigma), the observable commutes through the mapping. -/
theorem thm2_with_apply (s : State) (sigma : Input) :
    mu_O (Obs s sigma (Apply s sigma))
      = Obs_f (mu_S s) (mu_Sigma sigma) (Apply_f (mu_S s) (mu_Sigma sigma)) := by
  rw [thm2_observable_commutativity s sigma (Apply s sigma)]
  rw [thm1_execution_commutativity s sigma]

/-- Corollary: Observable commutativity with canonicalized input.
    Canonicalizing the input does not change the formal observable
    (combining TP-8 and THM-2). -/
theorem thm2_canon_input (s : State) (sigma : Input) :
    mu_O (Obs s (Canonicalize_Input sigma) (Apply s (Canonicalize_Input sigma)))
      = Obs_f (mu_S s) (mu_Sigma sigma)
          (Apply_f (mu_S s) (mu_Sigma sigma)) := by
  rw [thm2_observable_commutativity s (Canonicalize_Input sigma)
        (Apply s (Canonicalize_Input sigma))]
  rw [thm1_execution_commutativity s (Canonicalize_Input sigma)]
  rw [tp8_input_canonicalization_preserves_semantics sigma]

/-- Axiom: mu_Sigma ignores auxiliary data.
    The formal input representation does not depend on auxiliary data.
    This is the mapping-level consequence of THM-4. -/
axiom mu_Sigma_ignores_aux (p : Payload) (a : Authorization) (aux₁ aux₂ : AuxiliaryData) :
  mu_Sigma { payload := p, auth := a, aux := aux₁ }
    = mu_Sigma { payload := p, auth := a, aux := aux₂ }

/-- Corollary: Auxiliary data does not influence observables.
    Two inputs differing only in aux produce the same formal observable.
    Proven from THM-2, THM-1, and mu_Sigma_ignores_aux. -/
theorem obs_auxiliary_independence (s : State) (p : Payload) (a : Authorization)
    (aux₁ aux₂ : AuxiliaryData) :
    let sigma₁ : Input := { payload := p, auth := a, aux := aux₁ }
    let sigma₂ : Input := { payload := p, auth := a, aux := aux₂ }
    mu_O (Obs s sigma₁ (Apply s sigma₁)) = mu_O (Obs s sigma₂ (Apply s sigma₂)) := by
  simp only
  rw [thm2_observable_commutativity s
        { payload := p, auth := a, aux := aux₁ }
        (Apply s { payload := p, auth := a, aux := aux₁ })]
  rw [thm2_observable_commutativity s
        { payload := p, auth := a, aux := aux₂ }
        (Apply s { payload := p, auth := a, aux := aux₂ })]
  rw [thm1_execution_commutativity s { payload := p, auth := a, aux := aux₁ }]
  rw [thm1_execution_commutativity s { payload := p, auth := a, aux := aux₂ }]
  rw [mu_Sigma_ignores_aux p a aux₁ aux₂]

/-- Sequential observable commutativity: observables of a two-step execution
    commute through the mapping. -/
theorem thm2_sequential (s : State) (sigma₁ sigma₂ : Input) :
    let s₁ := Apply s sigma₁
    let s₂ := Apply s₁ sigma₂
    mu_O (Obs s₁ sigma₂ s₂)
      = Obs_f (Apply_f (mu_S s) (mu_Sigma sigma₁)) (mu_Sigma sigma₂)
          (Apply_f (Apply_f (mu_S s) (mu_Sigma sigma₁)) (mu_Sigma sigma₂)) := by
  simp only
  rw [thm2_observable_commutativity (Apply s sigma₁) sigma₂
        (Apply (Apply s sigma₁) sigma₂)]
  rw [thm1_execution_commutativity (Apply s sigma₁) sigma₂]
  rw [thm1_execution_commutativity s sigma₁]

end VSEL.Mapping
