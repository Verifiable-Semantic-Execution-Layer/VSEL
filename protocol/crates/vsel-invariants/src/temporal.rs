//! Temporal invariants — checked over execution traces.
//!
//! Derived from: INVARIANTS.md, EXECUTION_TRACE_MODEL.md, ECONOMIC_INVARIANTS.md.
//! Requirements: 3.3, 3.4
//!
//! Temporal invariants:
//! - T_valid: Trace validity — all entries form valid transitions
//! - T_no_revert: No state reversion — sequence indices are strictly increasing (SAFE-5),
//!   nonces are monotonically increasing per account
//! - T_cons: Cumulative resource consistency — total_supply is consistent across trace
//! - T_causal: Causality preservation — timestamps and block_heights are non-decreasing,
//!   reordering attack detection
//! - T_complete: No hidden transitions — sequence indices are contiguous
//!
//! Temporal economic invariants (trace-level):
//! - TE_extraction_trace: Detect disproportionate value extraction over a window
//! - TE_flash_trace: Detect flash loan patterns (balance spike and return)
//! - TE_sandwich_trace: Detect sandwich attack patterns in transaction ordering
//! - TE_manipulation_trace: Detect price manipulation patterns across trace steps
//! - TE_velocity_trace: Detect excessive transaction velocity per account

use std::collections::BTreeMap;

use vsel_core::state::valid_state;
use vsel_core::types::AccountId;

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
/// across the trace (SAFE-5). Additionally, per-account nonces must be
/// monotonically non-decreasing across the trace.
pub fn t_no_revert(trace: &Trace) -> InvariantResult {
    let mut violations = Vec::new();

    // Track the highest nonce seen per account across the trace
    let mut account_nonces: BTreeMap<AccountId, u64> = BTreeMap::new();

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

        // SAFE-5 enhancement: verify per-account nonce monotonicity
        // Check that no account's nonce decreases across the trace
        for (account_id, account_data) in &step.post.canonical.accounts {
            let current_nonce = account_data.nonce;
            if let Some(&prev_nonce) = account_nonces.get(account_id) {
                if current_nonce < prev_nonce {
                    violations.push(InvariantViolation {
                        invariant_id: "T_no_revert".to_string(),
                        category: InvariantCategory::Temporal,
                        description: format!(
                            "Trace step {}: account {:?} nonce decreased from {} to {}",
                            i, account_id, prev_nonce, current_nonce
                        ),
                        severity: Severity::Critical,
                    });
                }
            }
            account_nonces.insert(account_id.clone(), current_nonce);
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
        let pre_sum: u128 = step
            .pre
            .canonical
            .accounts
            .values()
            .map(|a| a.balance)
            .sum();
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

        let post_sum: u128 = step
            .post
            .canonical
            .accounts
            .values()
            .map(|a| a.balance)
            .sum();
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

/// T_causal: Causality preservation — timestamps and block_heights must be
/// non-decreasing across the trace. Also detects reordering attacks by
/// verifying that if step i has a causal dependency on step j (j < i),
/// the ordering is preserved.
pub fn t_causal(trace: &Trace) -> InvariantResult {
    let mut violations = Vec::new();

    for (i, step) in trace.steps.iter().enumerate() {
        // Timestamp must be non-decreasing within a step
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

        // Block height must be non-decreasing within a step
        if step.post.environment.block_height < step.pre.environment.block_height {
            violations.push(InvariantViolation {
                invariant_id: "T_causal".to_string(),
                category: InvariantCategory::Temporal,
                description: format!(
                    "Trace step {}: post block_height ({}) < pre block_height ({})",
                    i, step.post.environment.block_height, step.pre.environment.block_height
                ),
                severity: Severity::High,
            });
        }

        // Reordering attack detection across consecutive steps:
        // If step i+1 exists, verify that its pre-state environment is
        // causally consistent with step i's post-state environment.
        if i + 1 < trace.steps.len() {
            let next = &trace.steps[i + 1];

            // Timestamp of next pre must be >= current post timestamp
            if next.pre.metadata.timestamp < step.post.metadata.timestamp {
                violations.push(InvariantViolation {
                    invariant_id: "T_causal".to_string(),
                    category: InvariantCategory::Temporal,
                    description: format!(
                        "Trace step {}->{}: next pre timestamp ({}) < current post timestamp ({}) — possible reordering attack",
                        i, i + 1, next.pre.metadata.timestamp, step.post.metadata.timestamp
                    ),
                    severity: Severity::High,
                });
            }

            // Block height of next pre must be >= current post block_height
            if next.pre.environment.block_height < step.post.environment.block_height {
                violations.push(InvariantViolation {
                    invariant_id: "T_causal".to_string(),
                    category: InvariantCategory::Temporal,
                    description: format!(
                        "Trace step {}->{}: next pre block_height ({}) < current post block_height ({}) — possible reordering attack",
                        i, i + 1, next.pre.environment.block_height, step.post.environment.block_height
                    ),
                    severity: Severity::High,
                });
            }
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
        // Temporal economic invariants over traces
        te_extraction_trace(trace),
        te_flash_trace(trace),
        te_sandwich_trace(trace),
        te_manipulation_trace(trace),
        te_velocity_trace(trace),
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

// ---------------------------------------------------------------------------
// Temporal economic invariants — trace-level pattern detection
// Requirements: 3.4
// ---------------------------------------------------------------------------

/// Window size for temporal economic analysis (number of trace steps).
const TE_WINDOW_SIZE: usize = 10;

/// Maximum fraction of total supply a single account may gain in a window
/// (numerator / denominator). 50% = disproportionate extraction.
const TE_EXTRACTION_THRESHOLD_NUM: u128 = 50;
const TE_EXTRACTION_THRESHOLD_DEN: u128 = 100;

/// Maximum number of transactions per account in a window before flagging velocity.
const TE_VELOCITY_THRESHOLD: usize = 8;

/// TE_extraction_trace: Detect value extraction patterns over a window of trace steps.
/// Flags if any single account gains more than the extraction threshold of total supply
/// within a sliding window.
pub fn te_extraction_trace(trace: &Trace) -> InvariantResult {
    let mut violations = Vec::new();

    if trace.steps.is_empty() {
        return InvariantResult::ok();
    }

    let window = TE_WINDOW_SIZE.min(trace.steps.len());

    for start in 0..=trace.steps.len().saturating_sub(window) {
        let end = (start + window).min(trace.steps.len()) - 1;

        let pre_state = &trace.steps[start].pre;
        let post_state = &trace.steps[end].post;

        let total_supply = post_state.canonical.system_data.total_supply;
        if total_supply == 0 {
            continue;
        }

        // Compare balances at window start vs window end
        for (account_id, post_account) in &post_state.canonical.accounts {
            let pre_balance = pre_state
                .canonical
                .accounts
                .get(account_id)
                .map(|a| a.balance)
                .unwrap_or(0);

            let post_balance = post_account.balance;

            // Check if account gained disproportionate value
            if post_balance > pre_balance {
                let gain = post_balance - pre_balance;
                // gain > (total_supply * threshold_num / threshold_den)
                // Rearranged to avoid overflow: gain * den > total_supply * num
                if gain.saturating_mul(TE_EXTRACTION_THRESHOLD_DEN)
                    > total_supply.saturating_mul(TE_EXTRACTION_THRESHOLD_NUM)
                {
                    violations.push(InvariantViolation {
                        invariant_id: "TE_extraction_trace".to_string(),
                        category: InvariantCategory::Temporal,
                        description: format!(
                            "Account {:?} gained {} over window [{}, {}] (total_supply={})",
                            account_id, gain, start, end, total_supply
                        ),
                        severity: Severity::High,
                    });
                }
            }
        }
    }

    InvariantResult {
        valid: violations.is_empty(),
        violations,
    }
}

/// TE_flash_trace: Detect flash loan patterns — an account's balance spikes
/// and returns to near-original within a small window.
/// A flash pattern is: balance at step i, significantly higher at step j,
/// then back to near-original at step k, where k - i <= window.
pub fn te_flash_trace(trace: &Trace) -> InvariantResult {
    let mut violations = Vec::new();

    if trace.steps.len() < 3 {
        return InvariantResult::ok();
    }

    let window = TE_WINDOW_SIZE.min(trace.steps.len());

    // Collect all account IDs that appear in the trace
    let mut all_accounts: std::collections::BTreeSet<AccountId> = std::collections::BTreeSet::new();
    for step in &trace.steps {
        for id in step.pre.canonical.accounts.keys() {
            all_accounts.insert(id.clone());
        }
        for id in step.post.canonical.accounts.keys() {
            all_accounts.insert(id.clone());
        }
    }

    for account_id in &all_accounts {
        // Build a balance timeline for this account from post-states
        let balances: Vec<u128> = trace
            .steps
            .iter()
            .map(|step| {
                step.post
                    .canonical
                    .accounts
                    .get(account_id)
                    .map(|a| a.balance)
                    .unwrap_or(0)
            })
            .collect();

        // Scan for flash patterns within windows
        for start in 0..balances.len().saturating_sub(2) {
            let end = (start + window).min(balances.len());
            let initial_balance = balances[start];

            if initial_balance == 0 {
                continue;
            }

            // Look for a spike (>= 2x initial) followed by return to near-original
            let mut found_spike = false;
            let mut spike_balance = 0u128;

            for j in (start + 1)..end {
                if !found_spike && balances[j] >= initial_balance.saturating_mul(2) {
                    found_spike = true;
                    spike_balance = balances[j];
                } else if found_spike {
                    // Check if balance returned to near-original (within 10%)
                    let tolerance = initial_balance / 10;
                    let lower = initial_balance.saturating_sub(tolerance);
                    let upper = initial_balance.saturating_add(tolerance);
                    if balances[j] >= lower && balances[j] <= upper {
                        violations.push(InvariantViolation {
                            invariant_id: "TE_flash_trace".to_string(),
                            category: InvariantCategory::Temporal,
                            description: format!(
                                "Account {:?} flash pattern: balance {} -> {} -> {} in window [{}, {}]",
                                account_id, initial_balance, spike_balance, balances[j], start, j
                            ),
                            severity: Severity::High,
                        });
                        break; // One violation per window per account is sufficient
                    }
                }
            }
        }
    }

    InvariantResult {
        valid: violations.is_empty(),
        violations,
    }
}

/// TE_sandwich_trace: Detect sandwich attack patterns — suspicious ordering
/// where an account's transactions bracket another account's transaction.
/// Pattern: account A transacts, then account B transacts, then account A
/// transacts again within a small window, and A profits from the sequence.
pub fn te_sandwich_trace(trace: &Trace) -> InvariantResult {
    let mut violations = Vec::new();

    if trace.steps.len() < 3 {
        return InvariantResult::ok();
    }

    // For each window of 3 consecutive steps, check for sandwich patterns.
    // A sandwich is detected when:
    // 1. An account's nonce increases at step i (account A acts)
    // 2. A different account's nonce increases at step i+1 (account B acts)
    // 3. Account A's nonce increases again at step i+2
    // 4. Account A's balance increased over the 3-step window
    for i in 0..trace.steps.len().saturating_sub(2) {
        let step_0 = &trace.steps[i];
        let step_1 = &trace.steps[i + 1];
        let step_2 = &trace.steps[i + 2];

        // Find accounts whose nonce changed in each step
        let changed_0 = accounts_with_nonce_change(&step_0.pre, &step_0.post);
        let changed_1 = accounts_with_nonce_change(&step_1.pre, &step_1.post);
        let changed_2 = accounts_with_nonce_change(&step_2.pre, &step_2.post);

        // Look for pattern: A acts, B acts, A acts again
        for a_id in &changed_0 {
            if !changed_2.contains(a_id) {
                continue;
            }
            // A acted in step 0 and step 2
            for b_id in &changed_1 {
                if b_id == a_id {
                    continue;
                }
                // B acted in step 1, different from A

                // Check if A profited over the 3-step window
                let a_balance_before = step_0
                    .pre
                    .canonical
                    .accounts
                    .get(a_id)
                    .map(|a| a.balance)
                    .unwrap_or(0);
                let a_balance_after = step_2
                    .post
                    .canonical
                    .accounts
                    .get(a_id)
                    .map(|a| a.balance)
                    .unwrap_or(0);

                if a_balance_after > a_balance_before {
                    let profit = a_balance_after - a_balance_before;
                    violations.push(InvariantViolation {
                        invariant_id: "TE_sandwich_trace".to_string(),
                        category: InvariantCategory::Temporal,
                        description: format!(
                            "Possible sandwich: account {:?} brackets account {:?} at steps [{}, {}, {}], profit={}",
                            a_id, b_id, i, i + 1, i + 2, profit
                        ),
                        severity: Severity::Medium,
                    });
                }
            }
        }
    }

    InvariantResult {
        valid: violations.is_empty(),
        violations,
    }
}

/// TE_manipulation_trace: Detect price manipulation patterns — suspicious
/// changes in economic context (price oracle) across trace steps.
/// Flags if any price changes by more than 50% within a window.
pub fn te_manipulation_trace(trace: &Trace) -> InvariantResult {
    let mut violations = Vec::new();

    if trace.steps.is_empty() {
        return InvariantResult::ok();
    }

    let window = TE_WINDOW_SIZE.min(trace.steps.len());

    for start in 0..=trace.steps.len().saturating_sub(window) {
        let end = (start + window).min(trace.steps.len()) - 1;

        let pre_oracle = &trace.steps[start].pre.economic.price_oracle;
        let post_oracle = &trace.steps[end].post.economic.price_oracle;

        // If either oracle is empty, no manipulation to detect
        if pre_oracle.is_empty() || post_oracle.is_empty() {
            continue;
        }

        // Check each asset pair for suspicious price changes
        for (pair, pre_price) in pre_oracle {
            if let Some(post_price) = post_oracle.get(pair) {
                if pre_price.0 == 0 {
                    continue;
                }
                // Check if price changed by more than 50%
                let diff = if post_price.0 > pre_price.0 {
                    post_price.0 - pre_price.0
                } else {
                    pre_price.0 - post_price.0
                };
                // diff > pre_price * 50 / 100 → diff * 100 > pre_price * 50
                if diff.saturating_mul(100) > pre_price.0.saturating_mul(50) {
                    violations.push(InvariantViolation {
                        invariant_id: "TE_manipulation_trace".to_string(),
                        category: InvariantCategory::Temporal,
                        description: format!(
                            "Price manipulation: {}/{} changed from {} to {} over window [{}, {}]",
                            pair.base, pair.quote, pre_price.0, post_price.0, start, end
                        ),
                        severity: Severity::High,
                    });
                }
            }
        }
    }

    InvariantResult {
        valid: violations.is_empty(),
        violations,
    }
}

/// TE_velocity_trace: Detect excessive transaction velocity — check that no
/// account transacts more than a threshold number of times in a window.
/// An account "transacts" when its nonce increases between pre and post states.
pub fn te_velocity_trace(trace: &Trace) -> InvariantResult {
    let mut violations = Vec::new();

    if trace.steps.is_empty() {
        return InvariantResult::ok();
    }

    let window = TE_WINDOW_SIZE.min(trace.steps.len());

    // For each window, count per-account nonce changes
    for start in 0..=trace.steps.len().saturating_sub(window) {
        let end = (start + window).min(trace.steps.len());

        let mut account_tx_count: BTreeMap<AccountId, usize> = BTreeMap::new();

        for step in &trace.steps[start..end] {
            for (account_id, post_account) in &step.post.canonical.accounts {
                let pre_nonce = step
                    .pre
                    .canonical
                    .accounts
                    .get(account_id)
                    .map(|a| a.nonce)
                    .unwrap_or(0);
                if post_account.nonce > pre_nonce {
                    *account_tx_count.entry(account_id.clone()).or_insert(0) += 1;
                }
            }
        }

        for (account_id, count) in &account_tx_count {
            if *count > TE_VELOCITY_THRESHOLD {
                violations.push(InvariantViolation {
                    invariant_id: "TE_velocity_trace".to_string(),
                    category: InvariantCategory::Temporal,
                    description: format!(
                        "Account {:?} transacted {} times in window [{}, {}] (threshold={})",
                        account_id,
                        count,
                        start,
                        end - 1,
                        TE_VELOCITY_THRESHOLD
                    ),
                    severity: Severity::Medium,
                });
            }
        }
    }

    InvariantResult {
        valid: violations.is_empty(),
        violations,
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Returns the set of account IDs whose nonce changed between pre and post states.
fn accounts_with_nonce_change(
    pre: &vsel_core::state::State,
    post: &vsel_core::state::State,
) -> Vec<AccountId> {
    let mut changed = Vec::new();
    for (id, post_account) in &post.canonical.accounts {
        let pre_nonce = pre.canonical.accounts.get(id).map(|a| a.nonce).unwrap_or(0);
        if post_account.nonce > pre_nonce {
            changed.push(id.clone());
        }
    }
    changed
}
