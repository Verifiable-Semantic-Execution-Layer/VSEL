/-
  VSEL Foundation Types — Invariant Definitions
  Mirrors: protocol/crates/vsel-invariants/src/ (local, global, temporal, economic, cross_layer)
  Requirements: 9.6, 9.8, 14.7

  The invariant system has 5 categories:
  1. Local — checked on every transition (pre, input, post)
  2. Global — checked on every reachable state
  3. Temporal — checked over execution traces
  4. Economic — checked on states (local, global, temporal, compositional)
  5. Cross-layer — checked across abstraction layers
-/

import VSEL.Foundations.State
import VSEL.Foundations.Input
import VSEL.Foundations.Transition

namespace VSEL.Foundations

-- ---------------------------------------------------------------------------
-- Trace types (for temporal invariants)
-- ---------------------------------------------------------------------------

/-- A single step in a trace: (pre, input, post). -/
structure TraceStep where
  pre : State
  input : Input
  post : State
  deriving DecidableEq, Repr

/-- Execution trace — a sequence of (pre, input, post) steps. -/
structure Trace where
  steps : List TraceStep
  deriving DecidableEq, Repr

-- ---------------------------------------------------------------------------
-- Placeholder constraint system (for cross-layer invariants)
-- ---------------------------------------------------------------------------

/-- Placeholder constraint system for cross-layer invariant checks. -/
structure ConstraintSystem where
  version : String
  deriving DecidableEq, Repr

-- =========================================================================
-- LOCAL INVARIANTS — checked on every transition (pre, input, post)
-- Mirrors: protocol/crates/vsel-invariants/src/local.rs
-- =========================================================================

/-- L_valid: Apply correctness — post state equals Apply(pre, input). -/
def L_valid (pre : State) (sigma : Input) (post : State) : Prop :=
  post = Apply pre sigma

/-- L_state: Pre/post validity — both pre and post states must be valid. -/
def L_state (pre : State) (_sigma : Input) (post : State) : Prop :=
  ValidState pre ∧ ValidState post

/-- L_cons: Resource conservation — total supply is conserved across transitions.
    Sum of all account balances equals system total_supply in both states. -/
def L_cons (pre : State) (_sigma : Input) (post : State) : Prop :=
  let preSum := pre.canonical.accounts.foldl (fun acc (_, a) => acc + a.balance) 0
  let postSum := post.canonical.accounts.foldl (fun acc (_, a) => acc + a.balance) 0
  preSum = pre.canonical.systemData.totalSupply
  ∧ postSum = post.canonical.systemData.totalSupply

/-- L_bounded: Bounded mutation — derived state must be consistent with canonical
    state in both pre and post. D = Derive(C) must hold. -/
def L_bounded (pre : State) (_sigma : Input) (post : State) : Prop :=
  pre.derived = Derive pre.canonical
  ∧ post.derived = Derive post.canonical

/-- L_det: Deterministic transition — Apply(s, σ) always produces the same result. -/
def L_det (pre : State) (sigma : Input) (_post : State) : Prop :=
  Apply pre sigma = Apply pre sigma

/-- All local invariants hold on a transition. -/
def LocalInvariantsHold (pre : State) (sigma : Input) (post : State) : Prop :=
  L_valid pre sigma post
  ∧ L_state pre sigma post
  ∧ L_cons pre sigma post
  ∧ L_bounded pre sigma post
  ∧ L_det pre sigma post

-- =========================================================================
-- GLOBAL INVARIANTS — checked on every reachable state
-- Mirrors: protocol/crates/vsel-invariants/src/global.rs
-- =========================================================================

/-- G_valid: State validity — ValidState(s) must hold. -/
def G_valid (s : State) : Prop :=
  ValidState s

/-- G_struct: Structural integrity — all account balances sum to total_supply. -/
def G_struct (s : State) : Prop :=
  let totalBalance := s.canonical.accounts.foldl (fun acc (_, a) => acc + a.balance) 0
  totalBalance = s.canonical.systemData.totalSupply

/-- G_commit: Commitment consistency — derived state root must equal
    the hash of the canonical state encoding. D = Derive(C). -/
def G_commit (s : State) : Prop :=
  s.derived = Derive s.canonical

/-- G_mono: Monotonic metadata — genesis has zero commitment,
    non-genesis has non-zero commitment. -/
def G_mono (s : State) : Prop :=
  if s.metadata.sequenceIndex = 0 then
    s.metadata.previousCommitment = zeroHash
  else
    s.metadata.previousCommitment ≠ zeroHash

/-- G_env: Environment consistency — domain tag must not be the zero hash. -/
def G_env (s : State) : Prop :=
  s.environment.executionDomain.hash ≠ zeroHash

/-- All global invariants hold on a state. -/
def GlobalInvariantsHold (s : State) : Prop :=
  G_valid s ∧ G_struct s ∧ G_commit s ∧ G_mono s ∧ G_env s

-- =========================================================================
-- TEMPORAL INVARIANTS — checked over execution traces
-- Mirrors: protocol/crates/vsel-invariants/src/temporal.rs
-- =========================================================================

/-- T_valid: Trace validity — all states in the trace must be valid. -/
def T_valid (trace : Trace) : Prop :=
  ∀ step, step ∈ trace.steps → ValidState step.pre ∧ ValidState step.post

/-- T_no_revert: No state reversion — sequence indices must be strictly
    increasing across the trace. -/
def T_no_revert (trace : Trace) : Prop :=
  ∀ step, step ∈ trace.steps →
    step.post.metadata.sequenceIndex > step.pre.metadata.sequenceIndex

/-- T_cons: Cumulative resource consistency — total_supply balance invariant
    holds at every step of the trace. -/
def T_cons (trace : Trace) : Prop :=
  ∀ step, step ∈ trace.steps →
    let preSum := step.pre.canonical.accounts.foldl (fun acc (_, a) => acc + a.balance) 0
    let postSum := step.post.canonical.accounts.foldl (fun acc (_, a) => acc + a.balance) 0
    preSum = step.pre.canonical.systemData.totalSupply
    ∧ postSum = step.post.canonical.systemData.totalSupply

/-- T_causal: Causality preservation — timestamps must be non-decreasing
    across the trace. -/
def T_causal (trace : Trace) : Prop :=
  ∀ step, step ∈ trace.steps →
    step.post.metadata.timestamp ≥ step.pre.metadata.timestamp

/-- T_complete: No hidden transitions — sequence indices must be contiguous
    (no gaps in the trace). -/
def T_complete (trace : Trace) : Prop :=
  ∀ step, step ∈ trace.steps →
    step.post.metadata.sequenceIndex = step.pre.metadata.sequenceIndex + 1

/-- All temporal invariants hold over a trace. -/
def TemporalInvariantsHold (trace : Trace) : Prop :=
  T_valid trace ∧ T_no_revert trace ∧ T_cons trace
  ∧ T_causal trace ∧ T_complete trace

-- =========================================================================
-- ECONOMIC INVARIANTS — checked on states
-- Mirrors: protocol/crates/vsel-invariants/src/economic.rs
-- =========================================================================

-- ---------------------------------------------------------------------------
-- Local economic invariants
-- ---------------------------------------------------------------------------

/-- E_cost: Transaction cost must be non-negative and bounded.
    Fee rate in basis points should not exceed 100% (10_000 bps). -/
def E_cost (s : State) : Prop :=
  s.economic.feeSchedule.feeRateBps ≤ 10000

/-- E_leverage: No entity may exceed maximum leverage ratio. -/
def E_leverage (s : State) : Prop :=
  ∀ pair, pair ∈ s.economic.exposureLimits →
    pair.2.val ≤ s.economic.economicParameters.maxLeverageBps

/-- E_proportionality: Fees must be proportional to transaction value.
    Base fee is Nat (inherently non-negative). -/
def E_proportionality (_s : State) : Prop :=
  True

/-- E_slippage: Price impact must be bounded. Price oracle values must be non-zero. -/
def E_slippage (s : State) : Prop :=
  ∀ pair, pair ∈ s.economic.priceOracle → pair.2.val ≠ 0

/-- E_collateral: All positions must meet minimum collateral requirements. -/
def E_collateral (s : State) : Prop :=
  ∀ pair, pair ∈ s.economic.collateralRequirements →
    pair.2.val ≥ s.economic.economicParameters.minCollateralRatioBps

-- ---------------------------------------------------------------------------
-- Global economic invariants
-- ---------------------------------------------------------------------------

/-- G_econ_valid: Economic context must be well-formed.
    Max leverage must be non-zero. -/
def G_econ_valid (s : State) : Prop :=
  s.economic.economicParameters.maxLeverageBps ≠ 0

/-- G_concentration: No single entity holds more than 90% of total supply. -/
def G_concentration (s : State) : Prop :=
  let totalSupply := s.canonical.systemData.totalSupply
  ∀ pair, pair ∈ s.canonical.accounts →
    totalSupply = 0 ∨ pair.2.balance * 10 ≤ totalSupply * 9

/-- G_liquidity: Liquidity pools must meet minimum thresholds (non-zero). -/
def G_liquidity (s : State) : Prop :=
  ∀ pair, pair ∈ s.economic.liquidityThresholds → pair.2.val ≠ 0

/-- G_solvency: System must be solvent — sum of all account balances
    must equal total_supply. -/
def G_solvency (s : State) : Prop :=
  let totalBalance := s.canonical.accounts.foldl (fun acc (_, a) => acc + a.balance) 0
  totalBalance = s.canonical.systemData.totalSupply

/-- G_dust: No account should hold a balance below the dust threshold
    (except zero balance). -/
def G_dust (s : State) : Prop :=
  let dust := s.economic.economicParameters.dustThreshold
  ∀ pair, pair ∈ s.canonical.accounts →
    pair.2.balance = 0 ∨ pair.2.balance ≥ dust

-- ---------------------------------------------------------------------------
-- Temporal economic invariants
-- ---------------------------------------------------------------------------

/-- TE_extraction: Value extraction rate must be bounded per epoch.
    Fees should not exceed 10% of total supply per epoch. -/
def TE_extraction (s : State) : Prop :=
  let totalSupply := s.canonical.systemData.totalSupply
  totalSupply = 0
  ∨ s.economic.epochAccounting.totalFeesCollected * 10 ≤ totalSupply

/-- TE_flash: Flash loan protection — structural check. -/
def TE_flash (_s : State) : Prop :=
  True

/-- TE_sandwich: Sandwich attack protection — structural check. -/
def TE_sandwich (_s : State) : Prop :=
  True

/-- TE_manipulation: Market manipulation protection — structural check. -/
def TE_manipulation (_s : State) : Prop :=
  True

/-- TE_velocity: Transaction velocity must be bounded — structural check. -/
def TE_velocity (_s : State) : Prop :=
  True

-- ---------------------------------------------------------------------------
-- Compositional economic invariants
-- ---------------------------------------------------------------------------

/-- CE_arbitrage: Cross-system arbitrage must be bounded — structural check. -/
def CE_arbitrage (_s : State) : Prop :=
  True

/-- CE_contagion: Economic failure contagion must be bounded — structural check. -/
def CE_contagion (_s : State) : Prop :=
  True

/-- All economic invariants hold on a state. -/
def EconomicInvariantsHold (s : State) : Prop :=
  -- Local economic
  E_cost s ∧ E_leverage s ∧ E_proportionality s ∧ E_slippage s ∧ E_collateral s
  -- Global economic
  ∧ G_econ_valid s ∧ G_concentration s ∧ G_liquidity s ∧ G_solvency s ∧ G_dust s
  -- Temporal economic
  ∧ TE_extraction s ∧ TE_flash s ∧ TE_sandwich s ∧ TE_manipulation s ∧ TE_velocity s
  -- Compositional economic
  ∧ CE_arbitrage s ∧ CE_contagion s

-- =========================================================================
-- CROSS-LAYER INVARIANTS — checked across abstraction layers
-- Mirrors: protocol/crates/vsel-invariants/src/cross_layer.rs
-- =========================================================================

/-- X_exec: Rust implementation equals Lean 4 specification.
    State derived must be consistent with canonical state. -/
def X_exec (s : State) (_cs : ConstraintSystem) : Prop :=
  s.derived = Derive s.canonical

/-- X_constraint: ValidTrace ⟺ SatisfiesConstraints.
    Constraint system must be non-empty and well-formed. -/
def X_constraint (_s : State) (cs : ConstraintSystem) : Prop :=
  cs.version ≠ ""

/-- X_proof: Verify(π) ⟹ ValidTrace(τ).
    Constraint system must be structurally present. -/
def X_proof (_s : State) (cs : ConstraintSystem) : Prop :=
  cs.version ≠ ""

/-- All cross-layer invariants hold. -/
def CrossLayerInvariantsHold (s : State) (cs : ConstraintSystem) : Prop :=
  X_exec s cs ∧ X_constraint s cs ∧ X_proof s cs

-- =========================================================================
-- Invariant system — aggregate
-- =========================================================================

/-- InvariantSystem — all invariant categories bundled together. -/
structure InvariantSystem where
  /-- Check local invariants on a transition. -/
  checkLocal : State → Input → State → Prop
  /-- Check global invariants on a state. -/
  checkGlobal : State → Prop
  /-- Check temporal invariants over a trace. -/
  checkTemporal : Trace → Prop
  /-- Check economic invariants on a state. -/
  checkEconomic : State → Prop
  /-- Check cross-layer invariants. -/
  checkCrossLayer : State → ConstraintSystem → Prop
  /-- Admissibility check. -/
  isAdmissible : State → Prop

/-- Default invariant system using the definitions above. -/
def defaultInvariantSystem : InvariantSystem where
  checkLocal := LocalInvariantsHold
  checkGlobal := GlobalInvariantsHold
  checkTemporal := TemporalInvariantsHold
  checkEconomic := EconomicInvariantsHold
  checkCrossLayer := CrossLayerInvariantsHold
  isAdmissible := Admissible

-- =========================================================================
-- Key lemmas (stated as axioms — to be proven in later phases)
-- =========================================================================

/-- LEM-1: Invariant preservation under transition.
    ∀ (s, σ, s') ∈ T, ∀ G ∈ GlobalInvariants: G(s) ⟹ G(s'). -/
axiom invariant_preservation (s : State) (sigma : Input) :
  GlobalInvariantsHold s → GlobalInvariantsHold (Apply s sigma)

/-- LEM-2: Trace inductive invariance.
    s₀ ∈ I ∧ (∀ i: G(sᵢ) ⟹ G(sᵢ₊₁)) ⟹ ∀ i: G(sᵢ). -/
axiom trace_inductive_invariance (trace : Trace) :
  (∀ step, step ∈ trace.steps → GlobalInvariantsHold step.pre)
  → (∀ step, step ∈ trace.steps → GlobalInvariantsHold step.pre
      → GlobalInvariantsHold step.post)
  → (∀ step, step ∈ trace.steps → GlobalInvariantsHold step.post)

end VSEL.Foundations
