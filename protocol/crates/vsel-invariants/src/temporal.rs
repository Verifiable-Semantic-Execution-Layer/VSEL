//! Temporal invariants — checked over execution traces.
//!
//! Derived from: INVARIANTS.md, EXECUTION_TRACE_MODEL.md.
//! Requirements: 3.3
//!
//! Temporal invariants:
//! - T_valid: Trace validity — all entries form valid transitions
//! - T_no_revert: No state reversion — sequence indices are strictly increasing
//! - T_cons: Cumulative resource consistency — total_supply is consistent across trace
//! - T_causal: Causality preservation — timestamps are non-decreasing
//! - T_complete: No hidden transitions — sequence indices are contiguous

use vsel_core::state::valid_state;

use crate::{InvariantCategory, InvariantResult, InvariantViolation, Severity, Trace};

/// T_valid: Trace validity — all states in the trace must be valid.
pub fn t_valid(trace: &Trace) -> InvariantResult {
    let mut violations = Vec::new();

    for (i, step) in trace.steps.iter().enumerate() {
        if !valid_state(&step.pre) {
            violations.push(InvariantViolation {
                invariant_id: "T_valid".to_string(),
                category: InvariantCategory::Temporal,
                description: format!("Trace step {} pre-state is invalid", i),
                severity: Severity::Critical,
            });
        }
        if !valid_state(&step.post) {
            violations.push(InvariantViolation {
                invariant_id: "T_valid".to_string(),
                category: InvariantCategory::Temporal,
                description: format!("Trace step {} post-state is invalid", i),
                severity: Severity::Critical,
            });
        }
    }

    InvariantResult {
        valid: violations.is_empty(),
        violations,
    }
}

/// T_no_revert: No state reversion — sequence indices must be strictly increasing
/// across the trace.
pub fn t_no_revert(trace: &Trace) -> InvariantResult {
    let mut violations = Vec::new();

    for (i, step) in trace.steps.iter().enumerate() {
        if step.post.metadata.sequence_index <= step.pre.metadata.sequence_index {
            violations.push(InvariantViolation {
                invariant_id: "T_no_revert".to_string(),
                category: InvariantCategory::Temporal,
                description: format!(
                    "Trace step {}: post seq ({}) <= pre seq ({})",
                    i, step.post.metadata.sequence_index, step.pre.metadata.sequence_index
                ),
                severity: Severity::Critical,
            });
        }

        // Check consecutive steps: post of step i should match pre of step i+1
        if i + 1 < trace.steps.len() {
            let next = &trace.steps[i + 1];
            if step.post.metadata.sequence_index != next.pre.metadata.sequence_index {
                violations.push(InvariantViolation {
                    invariant_id: "T_no_revert".to_string(),
                    category: InvariantCategory::Temporal,
                    description: format!(
                        "Trace step {} post seq ({}) != step {} pre seq ({})",
                        i,
                        step.post.metadata.sequence_index,
                        i + 1,
                        next.pre.metadata.sequence_index
                    ),
                    severity: Severity::Critical,
                });
            }
        }
    }

    InvariantResult {
        valid: violations.is_empty(),
        violations,
    }
}

/// T_cons: Cumulative resource consistency — total_supply balance invariant
/// holds at every step of the trace.
pub fn t_cons(trace: &Trace) -> InvariantResult {
    let mut violations = Vec::new();

    for (i, step) in trace.steps.iter().enumerate() {
        let pre_sum: u128 = step.pre.canonical.accounts.values().map(|a| a.balance).sum();
        if pre_sum != step.pre.canonical.system_data.total_supply {
            violations.push(InvariantViolation {
                invariant_id: "T_cons".to_string(),
                category: InvariantCategory::Temporal,
                description: format!(
                    "Trace step {} pre: balance sum ({}) != total_supply ({})",
                    i, pre_sum, step.pre.canonical.system_data.total_supply
                ),
                severity: Severity::Critical,
            });
        }

        let post_sum: u128 = step.post.canonical.accounts.values().map(|a| a.balance).sum();
        if post_sum != step.post.canonical.system_data.total_supply {
            violations.push(InvariantViolation {
                invariant_id: "T_cons".to_string(),
                category: InvariantCategory::Temporal,
                description: format!(
                    "Trace step {} post: balance sum ({}) != total_supply ({})",
                    i, post_sum, step.post.canonical.system_data.total_supply
                ),
                severity: Severity::Critical,
            });
        }
    }

    InvariantResult {
        valid: violations.is_empty(),
        violations,
    }
}

/// T_causal: Causality preservation — timestamps must be non-decreasing
/// across the trace.
pub fn t_causal(trace: &Trace) -> InvariantResult {
    let mut violations = Vec::new();

    for (i, step) in trace.steps.iter().enumerate() {
        if step.post.metadata.timestamp < step.pre.metadata.timestamp {
            violations.push(InvariantViolation {
                invariant_id: "T_causal".to_string(),
                category: InvariantCategory::Temporal,
                description: format!(
                    "Trace step {}: post timestamp ({}) < pre timestamp ({})",
                    i, step.post.metadata.timestamp, step.pre.metadata.timestamp
                ),
                severity: Severity::High,
            });
        }
    }

    InvariantResult {
        valid: violations.is_empty(),
        violations,
    }
}

/// T_complete: No hidden transitions — sequence indices must be contiguous
/// (no gaps in the trace).
pub fn t_complete(trace: &Trace) -> InvariantResult {
    let mut violations = Vec::new();

    for (i, step) in trace.steps.iter().enumerate() {
        let expected_post_seq = step.pre.metadata.sequence_index + 1;
        if step.post.metadata.sequence_index != expected_post_seq {
            violations.push(InvariantViolation {
                invariant_id: "T_complete".to_string(),
                category: InvariantCategory::Temporal,
                description: format!(
                    "Trace step {}: post seq ({}) != pre seq + 1 ({})",
                    i, step.post.metadata.sequence_index, expected_post_seq
                ),
                severity: Severity::Critical,
            });
        }
    }

    InvariantResult {
        valid: violations.is_empty(),
        violations,
    }
}

/// Check all temporal invariants over a trace.
pub fn check_all_temporal(trace: &Trace) -> InvariantResult {
    let checks = [
        t_valid(trace),
        t_no_revert(trace),
        t_cons(trace),
        t_causal(trace),
        t_complete(trace),
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
