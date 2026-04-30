/-
  VSEL Foundation Types — Transition Model
  Mirrors: protocol/crates/vsel-core/src/transition.rs
  Requirements: 9.6, 9.8, 14.7

  Transition classes partition the input space with strict priority ordering:
    T_REJECT > T_INIT > T_ERROR > T_BATCH > T_UPDATE > T_NOOP

  The Apply function is deterministic (AX-1) and total — it always returns
  a valid state (AX-2). Invalid inputs produce an error state with all
  invariants preserved (LEM-7).
-/

import VSEL.Foundations.State
import VSEL.Foundations.Input

namespace VSEL.Foundations

-- ---------------------------------------------------------------------------
-- Transition classes — STATE_MACHINE.md §5, TRANSITION_PARTITIONING.md
-- ---------------------------------------------------------------------------

/-- Transition classes with priority ordering.
    Lower numeric value = higher priority.
    Reject (0) is highest priority, Noop (5) is lowest. -/
inductive TransitionClass where
  | reject   -- 0: Malformed input/state (highest priority)
  | init     -- 1: Initialization
  | error    -- 2: Explicit error condition
  | batch    -- 3: Batch processing
  | update   -- 4: Standard state update
  | noop     -- 5: No-op / rejection (lowest priority)
  deriving DecidableEq, Repr

-- ---------------------------------------------------------------------------
-- Priority ordering
-- ---------------------------------------------------------------------------

/-- Numeric priority of a transition class. Lower = higher priority. -/
def TransitionClass.priority : TransitionClass → Nat
  | .reject => 0
  | .init   => 1
  | .error  => 2
  | .batch  => 3
  | .update => 4
  | .noop   => 5

/-- Higher priority: tc₁ has higher priority than tc₂ iff its numeric value is lower. -/
def TransitionClass.hasHigherPriority (tc₁ tc₂ : TransitionClass) : Prop :=
  tc₁.priority < tc₂.priority

instance : LT TransitionClass where
  lt tc₁ tc₂ := tc₁.priority < tc₂.priority

instance : LE TransitionClass where
  le tc₁ tc₂ := tc₁.priority ≤ tc₂.priority

instance (tc₁ tc₂ : TransitionClass) : Decidable (tc₁ < tc₂) :=
  inferInstanceAs (Decidable (tc₁.priority < tc₂.priority))

instance (tc₁ tc₂ : TransitionClass) : Decidable (tc₁ ≤ tc₂) :=
  inferInstanceAs (Decidable (tc₁.priority ≤ tc₂.priority))

-- ---------------------------------------------------------------------------
-- Classification — guard system (opaque)
-- ---------------------------------------------------------------------------

/-- Classify a (state, input) pair into exactly one TransitionClass.
    Guards are evaluated in priority order (highest first). The first
    matching guard determines the class, guaranteeing exhaustiveness
    and disjointness.
    Opaque: concrete guard logic is in Rust. -/
instance : Inhabited TransitionClass where
  default := .noop

opaque Classify (s : State) (sigma : Input) : TransitionClass

-- ---------------------------------------------------------------------------
-- Apply — deterministic transition function (AX-1, AX-2)
-- ---------------------------------------------------------------------------

/-- Apply a transition: Apply(s, σ) → s'.
    This function is:
    - Deterministic (AX-1): identical inputs always produce identical output.
    - Total/Closed (AX-2): always returns a valid state in S.
    - Error-safe (LEM-7): invalid inputs produce an error state with
      invariants preserved.
    Opaque: concrete transition logic is in Rust. -/
instance : Inhabited State where
  default := {
    canonical := { accounts := [], storage := [], systemData := { protocolVersion := { major := 0, minor := 0, patch := 0 }, totalSupply := 0, parameters := [] } }
    derived := default
    environment := { timestamp := 0, blockHeight := 0, executionDomain := { hash := default } }
    economic := default
    metadata := { sequenceIndex := 0, previousCommitment := default, epoch := 0, timestamp := 0 }
  }

opaque Apply (s : State) (sigma : Input) : State

-- ---------------------------------------------------------------------------
-- Axioms — fundamental properties of the transition system
-- ---------------------------------------------------------------------------

/-- AX-1: Determinism — Apply is a function (automatic for Lean functions,
    but stated explicitly for documentation). For all s, σ:
    Apply(s, σ) produces exactly one result. -/
theorem apply_deterministic (s : State) (sigma : Input) :
    ∃ s', Apply s sigma = s' ∧ ∀ s'', Apply s sigma = s'' → s'' = s' := by
  exact ⟨Apply s sigma, rfl, fun _ h => h.symm⟩

/-- AX-2: Closure — Apply always returns a valid state.
    ∀ s ∈ S, σ ∈ Σ: ValidState(s) → ValidState(Apply(s, σ)). -/
axiom apply_closure (s : State) (sigma : Input) :
  ValidState s → ValidState (Apply s sigma)

/-- AX-3: Initial state validity — initial states satisfy genesis constraints.
    For the initial state s₀ with sequence_index = 0:
    ValidState(s₀) ∧ D(s₀) = Derive(C(s₀)). -/
axiom initial_state_valid (s₀ : State) :
  s₀.metadata.sequenceIndex = 0
  → s₀.metadata.previousCommitment = zeroHash
  → ValidState s₀

/-- LEM-7: Error handling preserves invariants.
    Apply(s, σ_invalid) = s_error where ValidState(s_error). -/
axiom error_preserves_invariants (s : State) (sigma : Input) :
  ValidState s → ¬ValidInput sigma → ValidState (Apply s sigma)

-- ---------------------------------------------------------------------------
-- Transition observable status
-- ---------------------------------------------------------------------------

/-- Status of a transition outcome. -/
inductive TransitionStatus where
  | success
  | rejected
  | error
  deriving DecidableEq, Repr

/-- Observable — externally visible output of a transition. -/
structure Observable where
  transitionClass : TransitionClass
  outputs : List OutputEvent
  gasUsed : Nat
  status : TransitionStatus
  deriving DecidableEq, Repr

/-- Obs: S × Σ × S → O — deterministic observable function (DEF-4).
    Opaque: concrete implementation is in Rust. -/
instance : Inhabited Observable where
  default := { transitionClass := .noop, outputs := [], gasUsed := 0, status := .success }

opaque Obs (s : State) (sigma : Input) (s' : State) : Observable

end VSEL.Foundations
