//! vsel-invariants: Invariant system — local, global, temporal, economic, cross-layer.
//!
//! Derived from: INVARIANTS.md, ECONOMIC_INVARIANTS.md.
//! Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8
//!
//! The invariant system has 5 categories:
//! 1. Local — checked on every transition (pre, input, post)
//! 2. Global — checked on every reachable state
//! 3. Temporal — checked over execution traces
//! 4. Economic — checked on states (local, global, temporal, compositional)
//! 5. Cross-layer — checked across abstraction layers

pub mod cross_layer;
pub mod economic;
pub mod global;
pub mod local;
pub mod temporal;

use vsel_core::input::Input;
use vsel_core::state::{valid_state, State};
use vsel_core::types::Severity;

// ---------------------------------------------------------------------------
// Invariant result types
// ---------------------------------------------------------------------------

/// Result of an invariant check.
#[derive(Clone, Debug)]
pub struct InvariantResult {
    /// Whether all checked invariants hold.
    pub valid: bool,
    /// List of violations found (empty if valid).
    pub violations: Vec<InvariantViolation>,
}

impl InvariantResult {
    /// Create a passing result with no violations.
    pub fn ok() -> Self {
        Self {
            valid: true,
            violations: Vec::new(),
        }
    }

    /// Create a failing result with a single violation.
    pub fn violation(v: InvariantViolation) -> Self {
        Self {
            valid: false,
            violations: vec![v],
        }
    }
}

/// A single invariant violation.
#[derive(Clone, Debug)]
pub struct InvariantViolation {
    /// Identifier of the violated invariant (e.g. "L_valid", "G_struct").
    pub invariant_id: String,
    /// Category of the invariant.
    pub category: InvariantCategory,
    /// Human-readable description of the violation.
    pub description: String,
    /// Severity of the violation.
    pub severity: Severity,
}

/// Category of an invariant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvariantCategory {
    /// Local — checked on every transition.
    Local,
    /// Global — checked on every reachable state.
    Global,
    /// Temporal — checked over execution traces.
    Temporal,
    /// Economic — checked on states.
    Economic,
    /// Cross-layer — checked across abstraction layers.
    CrossLayer,
}

// ---------------------------------------------------------------------------
// Trace type — minimal definition for temporal invariants
// ---------------------------------------------------------------------------

/// A single step in a trace: (pre, input, post).
#[derive(Clone, Debug)]
pub struct TraceStep {
    pub pre: State,
    pub input: Input,
    pub post: State,
}

/// Execution trace — a sequence of (pre, input, post) steps.
///
/// This is a minimal definition for use by temporal invariants.
/// The full trace engine (vsel-trace) will provide a richer model.
#[derive(Clone, Debug)]
pub struct Trace {
    pub steps: Vec<TraceStep>,
}

// ---------------------------------------------------------------------------
// Constraint system placeholder
// ---------------------------------------------------------------------------

/// Placeholder constraint system for cross-layer invariant checks.
///
/// The full constraint system is defined in vsel-constraints.
#[derive(Clone, Debug)]
pub struct ConstraintSystem {
    /// Version string — empty means uninitialized.
    pub version: String,
}

impl ConstraintSystem {
    /// Create a placeholder constraint system.
    pub fn placeholder() -> Self {
        Self {
            version: "0.1.0-placeholder".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Admissible predicate
// ---------------------------------------------------------------------------

/// Admissible(s) ≡ ValidState(s) ∧ EconomicallyValid(s)
///
/// A state that is structurally valid but economically inadmissible is rejected.
/// Requirements: 3.5
pub fn admissible(s: &State) -> bool {
    valid_state(s) && economic::economically_valid(s)
}

// ---------------------------------------------------------------------------
// InvariantSystem trait
// ---------------------------------------------------------------------------

/// Invariant system trait — checks all invariant categories.
///
/// Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8
pub trait InvariantSystem {
    /// Check local invariants on a transition.
    /// L_valid, L_state, L_cons, L_bounded, L_det
    fn check_local(&self, pre: &State, input: &Input, post: &State) -> InvariantResult;

    /// Check global invariants on a state.
    /// G_valid, G_struct, G_commit, G_mono, G_env
    fn check_global(&self, state: &State) -> InvariantResult;

    /// Check temporal invariants over a trace.
    /// T_valid, T_no_revert, T_cons, T_causal, T_complete
    fn check_temporal(&self, trace: &Trace) -> InvariantResult;

    /// Check economic invariants on a state.
    /// E_cost, E_leverage, E_proportionality, E_slippage, E_collateral,
    /// G_econ_valid, G_concentration, G_liquidity, G_solvency, G_dust,
    /// TE_extraction, TE_flash, TE_sandwich, TE_manipulation, TE_velocity,
    /// CE_arbitrage, CE_contagion
    fn check_economic(&self, state: &State) -> InvariantResult;

    /// Check cross-layer invariants.
    /// X_exec, X_constraint, X_proof
    fn check_cross_layer(&self, state: &State, constraints: &ConstraintSystem) -> InvariantResult;

    /// Admissibility — ValidState(s) ∧ EconomicallyValid(s)
    fn is_admissible(&self, state: &State) -> bool;
}

// ---------------------------------------------------------------------------
// Default implementation
// ---------------------------------------------------------------------------

/// Default invariant system implementation that delegates to the
/// individual invariant modules.
pub struct DefaultInvariantSystem;

impl InvariantSystem for DefaultInvariantSystem {
    fn check_local(&self, pre: &State, input: &Input, post: &State) -> InvariantResult {
        local::check_all_local(pre, input, post)
    }

    fn check_global(&self, state: &State) -> InvariantResult {
        global::check_all_global(state)
    }

    fn check_temporal(&self, trace: &Trace) -> InvariantResult {
        temporal::check_all_temporal(trace)
    }

    fn check_economic(&self, state: &State) -> InvariantResult {
        economic::check_all_economic(state)
    }

    fn check_cross_layer(&self, state: &State, constraints: &ConstraintSystem) -> InvariantResult {
        cross_layer::check_all_cross_layer(state, constraints)
    }

    fn is_admissible(&self, state: &State) -> bool {
        admissible(state)
    }
}
