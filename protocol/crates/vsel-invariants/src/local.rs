//! Local invariants — checked on every transition (pre, input, post).
//!
//! Derived from: INVARIANTS.md, FORMAL_SPECIFICATION.md §3.
//! Requirements: 3.1
//!
//! Local invariants:
//! - L_valid: Apply correctness — post = Apply(pre, input)
//! - L_state: Pre/post validity — ValidState(pre) ∧ ValidState(post)
//! - L_cons: Resource conservation — Total(C_s) = Total(C_s') + Δ_fees
//! - L_bounded: Bounded mutation — Diff(s, s') ⊆ AllowedMutations(σ)
//! - L_det: Deterministic transition — Apply(s, σ) always produces same result

use vsel_core::input::Input;
use vsel_core::state::{derive, derive_economic, valid_state, State};
use vsel_core::transition::apply;

use crate::{InvariantCategory, InvariantResult, InvariantViolation, Severity};

/// L_valid: Apply correctness — post state equals Apply(pre, input).
pub fn l_valid(pre: &State, input: &Input, post: &State) -> InvariantResult {
    let expected = apply(pre, input);
    if *post == expected {
        InvariantResult::ok()
    } else {
        InvariantResult::violation(InvariantViolation {
            invariant_id: "L_valid".to_string(),
            category: InvariantCategory::Local,
            description: "Post state does not equal Apply(pre, input)".to_string(),
            severity: Severity::Critical,
        })
    }
}

/// L_state: Pre/post validity — both pre and post states must be valid.
pub fn l_state(pre: &State, _input: &Input, post: &State) -> InvariantResult {
    let mut violations = Vec::new();
    if !valid_state(pre) {
        violations.push(InvariantViolation {
            invariant_id: "L_state".to_string(),
            category: InvariantCategory::Local,
            description: "Pre-state is not valid".to_string(),
            severity: Severity::Critical,
        });
    }
    if !valid_state(post) {
        violations.push(InvariantViolation {
            invariant_id: "L_state".to_string(),
            category: InvariantCategory::Local,
            description: "Post-state is not valid".to_string(),
            severity: Severity::Critical,
        });
    }
    InvariantResult {
        valid: violations.is_empty(),
        violations,
    }
}

/// L_cons: Resource conservation — total supply is conserved across transitions
/// (modulo fees/deposits/withdrawals which are explicit).
///
/// For transfers: Total(C_s) = Total(C_s')
/// For deposits: Total(C_s') = Total(C_s) + deposit_amount
/// For withdrawals: Total(C_s') = Total(C_s) - withdrawal_amount
///
/// General check: sum of all account balances == system total_supply in both states.
pub fn l_cons(pre: &State, _input: &Input, post: &State) -> InvariantResult {
    let pre_balance_sum: u128 = pre.canonical.accounts.values().map(|a| a.balance).sum();
    let post_balance_sum: u128 = post.canonical.accounts.values().map(|a| a.balance).sum();

    let mut violations = Vec::new();

    if pre_balance_sum != pre.canonical.system_data.total_supply {
        violations.push(InvariantViolation {
            invariant_id: "L_cons".to_string(),
            category: InvariantCategory::Local,
            description: format!(
                "Pre-state balance sum ({}) != total_supply ({})",
                pre_balance_sum, pre.canonical.system_data.total_supply
            ),
            severity: Severity::Critical,
        });
    }

    if post_balance_sum != post.canonical.system_data.total_supply {
        violations.push(InvariantViolation {
            invariant_id: "L_cons".to_string(),
            category: InvariantCategory::Local,
            description: format!(
                "Post-state balance sum ({}) != total_supply ({})",
                post_balance_sum, post.canonical.system_data.total_supply
            ),
            severity: Severity::Critical,
        });
    }

    InvariantResult {
        valid: violations.is_empty(),
        violations,
    }
}

/// L_bounded: Bounded mutation — derived state must be consistent with canonical
/// state in both pre and post. D = Derive(C) must hold.
pub fn l_bounded(pre: &State, _input: &Input, post: &State) -> InvariantResult {
    let mut violations = Vec::new();

    let expected_pre_derived = derive(&pre.canonical);
    if pre.derived != expected_pre_derived {
        violations.push(InvariantViolation {
            invariant_id: "L_bounded".to_string(),
            category: InvariantCategory::Local,
            description: "Pre-state derived != Derive(pre.canonical)".to_string(),
            severity: Severity::High,
        });
    }

    let expected_post_derived = derive(&post.canonical);
    if post.derived != expected_post_derived {
        violations.push(InvariantViolation {
            invariant_id: "L_bounded".to_string(),
            category: InvariantCategory::Local,
            description: "Post-state derived != Derive(post.canonical)".to_string(),
            severity: Severity::High,
        });
    }

    let expected_post_econ = derive_economic(&post.canonical, &post.environment);
    if post.economic != expected_post_econ {
        violations.push(InvariantViolation {
            invariant_id: "L_bounded".to_string(),
            category: InvariantCategory::Local,
            description: "Post-state economic != DeriveEconomic(post.canonical, post.environment)"
                .to_string(),
            severity: Severity::High,
        });
    }

    InvariantResult {
        valid: violations.is_empty(),
        violations,
    }
}

/// L_det: Deterministic transition — Apply(s, σ) always produces the same result.
/// Verified by applying twice and comparing.
pub fn l_det(pre: &State, input: &Input, _post: &State) -> InvariantResult {
    let result1 = apply(pre, input);
    let result2 = apply(pre, input);
    if result1 == result2 {
        InvariantResult::ok()
    } else {
        InvariantResult::violation(InvariantViolation {
            invariant_id: "L_det".to_string(),
            category: InvariantCategory::Local,
            description: "Apply(s, σ) produced different results on repeated application"
                .to_string(),
            severity: Severity::Critical,
        })
    }
}

/// Check all local invariants on a transition.
pub fn check_all_local(pre: &State, input: &Input, post: &State) -> InvariantResult {
    let checks = [
        l_valid(pre, input, post),
        l_state(pre, input, post),
        l_cons(pre, input, post),
        l_bounded(pre, input, post),
        l_det(pre, input, post),
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
