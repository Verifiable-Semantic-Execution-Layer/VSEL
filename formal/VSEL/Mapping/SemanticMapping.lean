/-
  VSEL Semantic Mapping — μ_S, μ_Σ, μ_T, μ_O definitions
  Mirrors: protocol/crates/vsel-mapping/src/mapping.rs
  Requirements: 9.6, 4.1

  Semantic mapping functions map concrete Rust types to formal Lean types.
  All mapping functions are:
  - **Total**: defined for all inputs (Lean functions are total by default)
  - **Deterministic**: same input always produces the same output (automatic)
  - **Pure**: no side effects (Lean is purely functional)

  Since the concrete implementations live in Rust, the Lean side defines
  opaque formal types and opaque mapping functions, then states axioms
  for the key properties that the Rust implementation must satisfy.
-/

import VSEL.Foundations.State
import VSEL.Foundations.Input
import VSEL.Foundations.Transition

namespace VSEL.Mapping

open VSEL.Foundations

-- =========================================================================
-- Formal types — targets of the semantic mapping
-- =========================================================================

/-- Formal state — the target of μ_S.
    Opaque: represents the SIR-level state representation. -/
opaque FormalState : Type

/-- Formal input — the target of μ_Σ.
    Opaque: represents the SIR-level input representation. -/
opaque FormalInput : Type

/-- Formal observable — the target of μ_O.
    Opaque: represents the SIR-level observable representation. -/
opaque FormalObservable : Type

/-- Formal transition — a triple (pre_f, σ_f, post_f) in the formal domain. -/
structure FormalTransition where
  pre : FormalState
  input : FormalInput
  post : FormalState

-- =========================================================================
-- Semantic mapping functions — μ_S, μ_Σ, μ_T, μ_O
-- =========================================================================

/-- μ_S : State → FormalState — map concrete state to formal state.
    Opaque: mirrors `map_state` in Rust (mapping.rs).
    Total and deterministic (Requirement 4.1). -/
opaque μ_S : State → FormalState

/-- μ_Σ : Input → FormalInput — map concrete input to formal input.
    Opaque: mirrors `map_input` in Rust (mapping.rs).
    Total and deterministic (Requirement 4.1). -/
opaque μ_Σ : Input → FormalInput

/-- μ_O : Observable → FormalObservable — map concrete observable to formal observable.
    Opaque: mirrors `map_observable` in Rust (mapping.rs).
    Total and deterministic (Requirement 4.1). -/
opaque μ_O : Observable → FormalObservable

/-- μ_T : State × Input × State → FormalTransition — map concrete transition triple.
    Defined as composition of μ_S and μ_Σ (mirrors `map_transition` in Rust). -/
def μ_T (pre : State) (sigma : Input) (post : State) : FormalTransition :=
  { pre := μ_S pre, input := μ_Σ sigma, post := μ_S post }

-- =========================================================================
-- Formal-side execution functions (opaque)
-- =========================================================================

/-- Apply_f : FormalState → FormalInput → FormalState
    The formal-side transition function.
    Opaque: this is the SIR-level Apply. -/
opaque Apply_f : FormalState → FormalInput → FormalState

/-- Obs_f : FormalState → FormalInput → FormalState → FormalObservable
    The formal-side observable function.
    Opaque: this is the SIR-level Obs. -/
opaque Obs_f : FormalState → FormalInput → FormalState → FormalObservable

/-- Derive_f : FormalState → FormalState
    The formal-side derived state computation.
    Opaque: this is the SIR-level Derive. -/
opaque Derive_f : FormalState → FormalState

-- =========================================================================
-- Canonicalization functions (opaque — implementation in Rust)
-- =========================================================================

/-- Canonicalize_Input : Input → Input
    Normalize a concrete input into canonical form.
    Opaque: mirrors `canonicalize_input` in Rust (canonicalization.rs).
    Must be idempotent (DEF-5). -/
opaque Canonicalize_Input : Input → Input

/-- Canonicalize_State : State → State
    Normalize a concrete state into canonical form.
    Opaque: mirrors `canonicalize_state` in Rust (canonicalization.rs).
    Must be idempotent (DEF-5). -/
opaque Canonicalize_State : State → State

-- =========================================================================
-- Totality and determinism
-- =========================================================================

/-- μ_S is deterministic — automatic for Lean functions, stated explicitly
    for documentation and cross-reference with Requirement 4.1. -/
theorem μ_S_deterministic (s : State) : ∃! f, μ_S s = f := by
  exact ⟨μ_S s, rfl, fun _ h => h.symm⟩

/-- μ_Σ is deterministic — automatic for Lean functions. -/
theorem μ_Σ_deterministic (sigma : Input) : ∃! f, μ_Σ sigma = f := by
  exact ⟨μ_Σ sigma, rfl, fun _ h => h.symm⟩

/-- μ_O is deterministic — automatic for Lean functions. -/
theorem μ_O_deterministic (obs : Observable) : ∃! f, μ_O obs = f := by
  exact ⟨μ_O obs, rfl, fun _ h => h.symm⟩

/-- μ_T composes μ_S and μ_Σ correctly. -/
theorem μ_T_composition (pre : State) (sigma : Input) (post : State) :
    μ_T pre sigma post = { pre := μ_S pre, input := μ_Σ sigma, post := μ_S post } := by
  rfl

end VSEL.Mapping
