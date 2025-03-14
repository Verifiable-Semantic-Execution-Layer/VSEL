//! Cross-layer invariants — checked across abstraction layers.
//!
//! Derived from: INVARIANTS.md, REFINEMENT_STRATEGY.md.
//! Requirements: 3.6
//!
//! Cross-layer invariants:
//! - X_exec: Rust implementation equals Lean 4 specification
//! - X_constraint: ValidTrace ⟺ SatisfiesConstraints
//! - X_proof: Verify(π) ⟹ ValidTrace(τ)

use vsel_core::state::State;

use crate::{
    ConstraintSystem, InvariantCategory, InvariantResult, InvariantViolation, Severity,
};

/// X_exec: Rust implementation equals Lean 4 specification.
///
/// At the foundational level, this checks that the state is structurally
/// consistent with what the formal specification expects. Full verification
/// requires the semantic mapping layer (vsel-mapping) and differential testing.
pub fn x_exec(state: &State, _constraints: &ConstraintSystem) -> InvariantResult {
    // Structural check: state must have consistent derived state
    let expected_derived = vsel_core::state::derive(&state.canonical);
    if state.derived != expected_derived {
        return InvariantResult::violation(InvariantViolation {
            invariant_id: "X_exec".to_string(),
            category: InvariantCategory::CrossLayer,
            description: "State derived != Derive(canonical) — execution layer inconsistency"
                .to_string(),
            severity: Severity::Critical,
        });
    }
    InvariantResult::ok()
}

/// X_constraint: ValidTrace ⟺ SatisfiesConstraints.
///
/// At the foundational level, this is a structural placeholder. Full
/// verification requires the constraint compiler (vsel-constraints).
/// Checks that the constraint system is non-empty and well-formed.
pub fn x_constraint(_state: &State, constraints: &ConstraintSystem) -> InvariantResult {
    if !constraints.version.is_empty() {
        InvariantResult::ok()
    } else {
        InvariantResult::violation(InvariantViolation {
            invariant_id: "X_constraint".to_string(),
            category: InvariantCategory::CrossLayer,
            description: "Constraint system has empty version — may be uninitialized".to_string(),
            severity: Severity::Medium,
        })
    }
}

/// X_proof: Verify(π) ⟹ ValidTrace(τ).
///
/// At the foundational level, this is a structural placeholder. Full
/// verification requires the proof system (vsel-proof).
/// Checks that the constraint system is structurally present.
pub fn x_proof(_state: &State, constraints: &ConstraintSystem) -> InvariantResult {
    // Structural: constraint system must exist for proof verification to be meaningful
    if constraints.version.is_empty() {
        return InvariantResult::violation(InvariantViolation {
            invariant_id: "X_proof".to_string(),
            category: InvariantCategory::CrossLayer,
            description: "No constraint system available for proof verification".to_string(),
            severity: Severity::Medium,
        });
    }
    InvariantResult::ok()
}

/// Check all cross-layer invariants.
pub fn check_all_cross_layer(
    state: &State,
    constraints: &ConstraintSystem,
) -> InvariantResult {
    let checks = [
        x_exec(state, constraints),
        x_constraint(state, constraints),
        x_proof(state, constraints),
    ];

    let mut violations = Vec::new();
    for check in checks {
        violations.extend(check.violations);
    }

    InvariantResult {
        valid: violations.is_empty(),
        violations,
    }
}
