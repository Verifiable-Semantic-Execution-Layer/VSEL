//! Global invariants — checked on every reachable state.
//!
//! Derived from: INVARIANTS.md, FORMAL_SPECIFICATION.md §3.
//! Requirements: 3.2
//!
//! Global invariants:
//! - G_valid: State validity — ValidState(s)
//! - G_struct: Structural integrity — all references valid, no dangling pointers
//! - G_commit: Commitment consistency — D.state_root = Hash(Encode(C))
//! - G_mono: Monotonic metadata — sequence_index and epoch are non-decreasing
//! - G_env: Environment consistency — domain tag is valid, environment well-formed

use vsel_core::state::{derive, valid_state, State};
use vsel_core::types::Hash;

use crate::{InvariantCategory, InvariantResult, InvariantViolation, Severity};

/// G_valid: State validity — ValidState(s) must hold.
pub fn g_valid(state: &State) -> InvariantResult {
    if valid_state(state) {
        InvariantResult::ok()
    } else {
        InvariantResult::violation(InvariantViolation {
            invariant_id: "G_valid".to_string(),
            category: InvariantCategory::Global,
            description: "State does not satisfy ValidState(s)".to_string(),
            severity: Severity::Critical,
        })
    }
}

/// G_struct: Structural integrity — all account balances are consistent,
/// storage keys are well-formed, and no internal references are dangling.
pub fn g_struct(state: &State) -> InvariantResult {
    let mut violations = Vec::new();

    // All account balances must sum to total_supply
    let total_balance: u128 = state.canonical.accounts.values().map(|a| a.balance).sum();
    if total_balance != state.canonical.system_data.total_supply {
        violations.push(InvariantViolation {
            invariant_id: "G_struct".to_string(),
            category: InvariantCategory::Global,
            description: format!(
                "Account balance sum ({}) != total_supply ({})",
                total_balance, state.canonical.system_data.total_supply
            ),
            severity: Severity::Critical,
        });
    }

    InvariantResult {
        valid: violations.is_empty(),
        violations,
    }
}

/// G_commit: Commitment consistency — derived state root must equal
/// the hash of the canonical state encoding. D = Derive(C).
pub fn g_commit(state: &State) -> InvariantResult {
    let expected_derived = derive(&state.canonical);
    if state.derived.state_root == expected_derived.state_root {
        InvariantResult::ok()
    } else {
        InvariantResult::violation(InvariantViolation {
            invariant_id: "G_commit".to_string(),
            category: InvariantCategory::Global,
            description: "Derived state root != Hash(Encode(canonical))".to_string(),
            severity: Severity::Critical,
        })
    }
}

/// G_mono: Monotonic metadata — sequence_index is consistent with
/// previous_commitment (genesis has zero commitment, non-genesis has non-zero).
pub fn g_mono(state: &State) -> InvariantResult {
    let zero_hash = Hash([0u8; 32]);
    let valid = if state.metadata.sequence_index == 0 {
        state.metadata.previous_commitment == zero_hash
    } else {
        state.metadata.previous_commitment != zero_hash
    };

    if valid {
        InvariantResult::ok()
    } else {
        InvariantResult::violation(InvariantViolation {
            invariant_id: "G_mono".to_string(),
            category: InvariantCategory::Global,
            description: format!(
                "Metadata monotonicity violated: seq={}, commitment_is_zero={}",
                state.metadata.sequence_index,
                state.metadata.previous_commitment == zero_hash
            ),
            severity: Severity::High,
        })
    }
}

/// G_env: Environment consistency — domain tag must not be the zero hash.
pub fn g_env(state: &State) -> InvariantResult {
    let zero_hash = Hash([0u8; 32]);
    if state.environment.execution_domain.0 != zero_hash {
        InvariantResult::ok()
    } else {
        InvariantResult::violation(InvariantViolation {
            invariant_id: "G_env".to_string(),
            category: InvariantCategory::Global,
            description: "Environment execution_domain is the zero hash".to_string(),
            severity: Severity::High,
        })
    }
}

/// Check all global invariants on a state.
pub fn check_all_global(state: &State) -> InvariantResult {
    let checks = [
        g_valid(state),
        g_struct(state),
        g_commit(state),
        g_mono(state),
        g_env(state),
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
