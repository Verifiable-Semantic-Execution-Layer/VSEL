/-
  VSEL Semantic Mapping — mu_S, mu_Sigma, mu_T, mu_O definitions
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

/-- Formal state — the target of mu_S.
    Opaque: represents the SIR-level state representation. -/
structure FormalState where
  data : List (String × List UInt8)
  deriving DecidableEq, Repr, Inhabited

/-- Formal input — the target of mu_Sigma.
    Opaque: represents the SIR-level input representation. -/
structure FormalInput where
  data : List (String × List UInt8)
  deriving DecidableEq, Repr, Inhabited

/-- Formal observable — the target of mu_O.
    Opaque: represents the SIR-level observable representation. -/
structure FormalObservable where
  data : List (String × List UInt8)
  deriving DecidableEq, Repr, Inhabited

/-- Formal transition — a triple (pre_f, sigma_f, post_f) in the formal domain. -/
structure FormalTransition where
  pre : FormalState
  input : FormalInput
  post : FormalState
  deriving DecidableEq, Repr, Inhabited

-- =========================================================================
-- Semantic mapping functions — mu_S, mu_Sigma, mu_T, mu_O
-- =========================================================================

/-- mu_S : State -> FormalState — map concrete state to formal state.
    Opaque: mirrors `map_state` in Rust (mapping.rs).
    Total and deterministic (Requirement 4.1). -/
opaque mu_S : State → FormalState

/-- mu_Sigma : Input -> FormalInput — map concrete input to formal input.
    Opaque: mirrors `map_input` in Rust (mapping.rs).
    Total and deterministic (Requirement 4.1). -/
opaque mu_Sigma : Input → FormalInput

/-- mu_O : Observable -> FormalObservable — map concrete observable to formal observable.
    Opaque: mirrors `map_observable` in Rust (mapping.rs).
    Total and deterministic (Requirement 4.1). -/
opaque mu_O : Observable → FormalObservable

/-- mu_T : State x Input x State -> FormalTransition — map concrete transition triple.
    Defined as composition of mu_S and mu_Sigma (mirrors `map_transition` in Rust). -/
def mu_T (pre : State) (sigma : Input) (post : State) : FormalTransition :=
  { pre := mu_S pre, input := mu_Sigma sigma, post := mu_S post }

-- =========================================================================
-- Formal-side execution functions (opaque)
-- =========================================================================

/-- Apply_f : FormalState -> FormalInput -> FormalState
    The formal-side transition function.
    Opaque: this is the SIR-level Apply. -/
opaque Apply_f : FormalState → FormalInput → FormalState

/-- Obs_f : FormalState -> FormalInput -> FormalState -> FormalObservable
    The formal-side observable function.
    Opaque: this is the SIR-level Obs. -/
opaque Obs_f : FormalState → FormalInput → FormalState → FormalObservable

/-- Derive_f : FormalState -> FormalState
    The formal-side derived state computation.
    Opaque: this is the SIR-level Derive. -/
opaque Derive_f : FormalState → FormalState

-- =========================================================================
-- Canonicalization functions (opaque — implementation in Rust)
-- =========================================================================

/-- Canonicalize_Input : Input -> Input
    Normalize a concrete input into canonical form.
    Opaque: mirrors `canonicalize_input` in Rust (canonicalization.rs).
    Must be idempotent (DEF-5). -/
instance : Inhabited Input where
  default := {
    payload := { payloadType := "", data := [] }
    auth := { classicalSig := [], pqcSig := [], publicKey := { classical := [], pqc := [] }, nonce := 0, domain := { hash := default } }
    aux := { data := [] }
  }

opaque Canonicalize_Input : Input → Input

/-- Canonicalize_State : State -> State
    Normalize a concrete state into canonical form.
    Opaque: mirrors `canonicalize_state` in Rust (canonicalization.rs).
    Must be idempotent (DEF-5). -/
opaque Canonicalize_State : State → State

-- =========================================================================
-- Totality and determinism
-- =========================================================================

/-- mu_S is deterministic — automatic for Lean functions, stated explicitly
    for documentation and cross-reference with Requirement 4.1. -/
theorem mu_S_deterministic (s : State) :
    ∃ f, mu_S s = f ∧ ∀ g, mu_S s = g → g = f := by
  exact ⟨mu_S s, rfl, fun _ h => h.symm⟩

/-- mu_Sigma is deterministic — automatic for Lean functions. -/
theorem mu_Sigma_deterministic (sigma : Input) :
    ∃ f, mu_Sigma sigma = f ∧ ∀ g, mu_Sigma sigma = g → g = f := by
  exact ⟨mu_Sigma sigma, rfl, fun _ h => h.symm⟩

/-- mu_O is deterministic — automatic for Lean functions. -/
theorem mu_O_deterministic (obs : Observable) :
    ∃ f, mu_O obs = f ∧ ∀ g, mu_O obs = g → g = f := by
  exact ⟨mu_O obs, rfl, fun _ h => h.symm⟩

/-- mu_T composes mu_S and mu_Sigma correctly. -/
theorem mu_T_composition (pre : State) (sigma : Input) (post : State) :
    mu_T pre sigma post = { pre := mu_S pre, input := mu_Sigma sigma, post := mu_S post } := by
  rfl

end VSEL.Mapping
