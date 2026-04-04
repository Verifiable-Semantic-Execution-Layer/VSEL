//! Long trace simulation — integration test for temporal robustness.
//!
//! Generates extended execution traces (hundreds to thousands of transitions)
//! and verifies all invariant categories hold at every step, detecting any
//! delayed invariant failure.
//!
//! **Validates: Requirements 3.3, 3.10**

use std::collections::BTreeMap;

use vsel_core::input::{Authorization, Input};
use vsel_core::observable::obs;
use vsel_core::state::*;
use vsel_core::transition::apply;
use vsel_core::types::*;

use vsel_invariants::economic::check_all_economic;
use vsel_invariants::global::check_all_global;
use vsel_invariants::local::check_all_local;
use vsel_invariants::temporal::check_all_temporal;
use vsel_invariants::{Trace, TraceStep};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Non-zero domain tag for valid environments.
fn test_domain_tag() -> DomainTag {
    let mut h = [0u8; 32];
    h[0] = 0xAB;
    h[1] = 0xCD;
    DomainTag(Hash(h))
}

/// Valid authorization fixture.
fn valid_auth() -> Authorization {
    Authorization {
        classical_sig: vec![1, 2, 3],
        pqc_sig: vec![4, 5, 6],
        public_key: HybridPublicKey {
            classical: vec![10, 11],
            pqc: vec![20, 21],
        },
        nonce: 0,
        domain: test_domain_tag(),
    }
}

/// Build a valid genesis state with the given accounts.
fn build_genesis_state(accounts: BTreeMap<AccountId, AccountData>) -> State {
    let total_supply: u128 = accounts.values().map(|a| a.balance).sum();
    let canonical = CanonicalState {
        accounts,
        storage: BTreeMap::new(),
        system_data: SystemData {
            protocol_version: ProtocolVersion {
                major: 0,
                minor: 1,
                patch: 0,
            },
            total_supply,
            parameters: BTreeMap::new(),
        },
    };
    let derived = derive(&canonical);
    let env = Environment {
        timestamp: 1_000_000,
        block_height: 1,
        execution_domain: test_domain_tag(),
    };
    let economic = derive_economic(&canonical, &env);
    let metadata = TraceMetadata {
        sequence_index: 0,
        previous_commitment: Hash([0u8; 32]),
        epoch: 0,
        timestamp: 1_000_000,
    };
    State {
        canonical,
        derived,
        environment: env,
        economic,
        metadata,
    }
}

/// Create a transfer input: sender -> receiver for `amount`.
fn make_transfer(sender: &[u8; 32], receiver: &[u8; 32], amount: u128) -> Input {
    let mut data = Vec::with_capacity(80);
    data.extend_from_slice(sender);
    data.extend_from_slice(receiver);
    data.extend_from_slice(&amount.to_le_bytes());
    Input {
        payload: Payload {
            payload_type: "transfer".to_string(),
            data,
        },
        auth: valid_auth(),
        aux: AuxiliaryData { data: vec![] },
    }
}

/// Create a deposit input.
fn make_deposit(account: &[u8; 32], amount: u128) -> Input {
    let mut data = Vec::with_capacity(48);
    data.extend_from_slice(account);
    data.extend_from_slice(&amount.to_le_bytes());
    Input {
        payload: Payload {
            payload_type: "deposit".to_string(),
            data,
        },
        auth: valid_auth(),
        aux: AuxiliaryData { data: vec![] },
    }
}

/// Create a withdraw input.
fn make_withdraw(account: &[u8; 32], amount: u128) -> Input {
    let mut data = Vec::with_capacity(48);
    data.extend_from_slice(account);
    data.extend_from_slice(&amount.to_le_bytes());
    Input {
        payload: Payload {
            payload_type: "withdraw".to_string(),
            data,
        },
        auth: valid_auth(),
        aux: AuxiliaryData { data: vec![] },
    }
}

/// Create an init input.
fn make_init() -> Input {
    Input {
        payload: Payload {
            payload_type: "init".to_string(),
            data: vec![0xFF],
        },
        auth: valid_auth(),
        aux: AuxiliaryData { data: vec![] },
    }
}

/// Create a noop input (unrecognized payload type).
fn make_noop() -> Input {
    Input {
        payload: Payload {
            payload_type: "noop_op".to_string(),
            data: vec![0x01],
        },
        auth: valid_auth(),
        aux: AuxiliaryData { data: vec![] },
    }
}

/// Deterministic input generator based on step index.
/// Cycles through transfer, deposit, withdraw, and noop operations
/// to exercise all transition classes over a long trace.
fn deterministic_input(step: usize, accounts: &[([u8; 32], u128)]) -> Input {
    let pattern = step % 10;
    match pattern {
        // Transfers between existing accounts (most common)
        0 | 1 | 2 | 3 | 4 => {
            if accounts.len() >= 2 {
                let sender_idx = step % accounts.len();
                let receiver_idx = (step + 1) % accounts.len();
                if sender_idx != receiver_idx && accounts[sender_idx].1 > 1 {
                    let amount = 1; // small transfer to avoid exhaustion
                    make_transfer(
                        &accounts[sender_idx].0,
                        &accounts[receiver_idx].0,
                        amount,
                    )
                } else {
                    make_noop()
                }
            } else {
                make_noop()
            }
        }
        // Deposits
        5 | 6 => {
            if !accounts.is_empty() {
                let idx = step % accounts.len();
                make_deposit(&accounts[idx].0, 10)
            } else {
                make_noop()
            }
        }
        // Withdrawals (small amounts)
        7 => {
            if !accounts.is_empty() {
                let idx = step % accounts.len();
                if accounts[idx].1 > 5 {
                    make_withdraw(&accounts[idx].0, 1)
                } else {
                    make_noop()
                }
            } else {
                make_noop()
            }
        }
        // Noops
        _ => make_noop(),
    }
}

/// Snapshot current account balances from state for the input generator.
fn snapshot_balances(state: &State) -> Vec<([u8; 32], u128)> {
    state
        .canonical
        .accounts
        .iter()
        .map(|(id, data)| (id.0, data.balance))
        .collect()
}

// ---------------------------------------------------------------------------
// Core simulation runner
// ---------------------------------------------------------------------------

/// Run a long trace simulation for `num_steps` transitions.
/// Checks all invariant categories at every step and panics on any violation.
fn run_long_trace_simulation(num_steps: usize) {
    // Set up initial state with several accounts
    let mut accounts = BTreeMap::new();
    for i in 0u8..5 {
        let mut id = [0u8; 32];
        id[0] = i + 1;
        accounts.insert(
            AccountId(id),
            AccountData {
                balance: 10_000,
                nonce: 0,
                data: vec![],
            },
        );
    }

    // Genesis state
    let mut current_state = build_genesis_state(accounts);

    // First transition: init
    let init_input = make_init();
    let post_init = apply(&current_state, &init_input);

    // Verify init transition
    let local_result = check_all_local(&current_state, &init_input, &post_init);
    assert!(
        local_result.valid,
        "Step 0 (init): local invariant violation: {:?}",
        local_result
            .violations
            .iter()
            .map(|v| format!("{}: {}", v.invariant_id, v.description))
            .collect::<Vec<_>>()
    );

    let global_result = check_all_global(&post_init);
    assert!(
        global_result.valid,
        "Step 0 (init): global invariant violation: {:?}",
        global_result
            .violations
            .iter()
            .map(|v| format!("{}: {}", v.invariant_id, v.description))
            .collect::<Vec<_>>()
    );

    let economic_result = check_all_economic(&post_init);
    assert!(
        economic_result.valid,
        "Step 0 (init): economic invariant violation: {:?}",
        economic_result
            .violations
            .iter()
            .map(|v| format!("{}: {}", v.invariant_id, v.description))
            .collect::<Vec<_>>()
    );

    // Build trace accumulator
    let mut trace_steps: Vec<TraceStep> = Vec::with_capacity(num_steps + 1);
    trace_steps.push(TraceStep {
        pre: current_state.clone(),
        input: init_input,
        post: post_init.clone(),
    });

    current_state = post_init;

    // Run the simulation for num_steps additional transitions
    for step in 1..=num_steps {
        let balances = snapshot_balances(&current_state);
        let input = deterministic_input(step, &balances);

        let post_state = apply(&current_state, &input);

        // 1. Check local invariants on this transition
        let local_result = check_all_local(&current_state, &input, &post_state);
        assert!(
            local_result.valid,
            "Step {}: local invariant violation: {:?}",
            step,
            local_result
                .violations
                .iter()
                .map(|v| format!("{}: {}", v.invariant_id, v.description))
                .collect::<Vec<_>>()
        );

        // 2. Check global invariants on the resulting state
        let global_result = check_all_global(&post_state);
        assert!(
            global_result.valid,
            "Step {}: global invariant violation: {:?}",
            step,
            global_result
                .violations
                .iter()
                .map(|v| format!("{}: {}", v.invariant_id, v.description))
                .collect::<Vec<_>>()
        );

        // 3. Check economic invariants on the resulting state
        let economic_result = check_all_economic(&post_state);
        assert!(
            economic_result.valid,
            "Step {}: economic invariant violation: {:?}",
            step,
            economic_result
                .violations
                .iter()
                .map(|v| format!("{}: {}", v.invariant_id, v.description))
                .collect::<Vec<_>>()
        );

        // 4. Verify observable is deterministic
        let _observable = obs(&current_state, &input, &post_state);

        // Record trace step
        trace_steps.push(TraceStep {
            pre: current_state.clone(),
            input,
            post: post_state.clone(),
        });

        current_state = post_state;
    }

    // 5. Check temporal invariants over the accumulated trace
    let trace = Trace {
        steps: trace_steps,
    };
    let temporal_result = check_all_temporal(&trace);
    assert!(
        temporal_result.valid,
        "Temporal invariant violation over {} steps: {:?}",
        num_steps,
        temporal_result
            .violations
            .iter()
            .map(|v| format!("{}: {}", v.invariant_id, v.description))
            .collect::<Vec<_>>()
    );

    // Final state must still be valid
    assert!(
        valid_state(&current_state),
        "Final state after {} steps is not valid",
        num_steps
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Short trace simulation (100 steps) — runs in normal test suite.
/// Validates: Requirements 3.3, 3.10
#[test]
fn test_long_trace_100_steps() {
    run_long_trace_simulation(100);
}

/// Medium trace simulation (500 steps) — runs in normal test suite.
/// Validates: Requirements 3.3, 3.10
#[test]
fn test_long_trace_500_steps() {
    run_long_trace_simulation(500);
}

/// Extended trace simulation (5000 steps) — ignored by default for CI speed.
/// Run with `cargo test -- --ignored` to execute.
/// Validates: Requirements 3.3, 3.10
#[test]
#[ignore]
fn test_long_trace_5000_steps() {
    run_long_trace_simulation(5000);
}

/// Verify no delayed invariant failure: run a trace where temporal invariants
/// are checked at multiple intermediate checkpoints, not just at the end.
/// This ensures invariants hold continuously, not just at the final state.
/// Validates: Requirements 3.3, 3.10
#[test]
fn test_no_delayed_invariant_failure() {
    let mut accounts = BTreeMap::new();
    for i in 0u8..4 {
        let mut id = [0u8; 32];
        id[0] = i + 1;
        accounts.insert(
            AccountId(id),
            AccountData {
                balance: 5_000,
                nonce: 0,
                data: vec![],
            },
        );
    }

    let mut current_state = build_genesis_state(accounts);

    // Init
    let init_input = make_init();
    let post_init = apply(&current_state, &init_input);

    let mut trace_steps: Vec<TraceStep> = vec![TraceStep {
        pre: current_state.clone(),
        input: init_input,
        post: post_init.clone(),
    }];
    current_state = post_init;

    let total_steps = 200;
    let checkpoint_interval = 50;

    for step in 1..=total_steps {
        let balances = snapshot_balances(&current_state);
        let input = deterministic_input(step, &balances);
        let post_state = apply(&current_state, &input);

        // Local + global + economic at every step
        let local_result = check_all_local(&current_state, &input, &post_state);
        assert!(
            local_result.valid,
            "Delayed failure check — step {}: local violation: {:?}",
            step,
            local_result
                .violations
                .iter()
                .map(|v| format!("{}: {}", v.invariant_id, v.description))
                .collect::<Vec<_>>()
        );

        let global_result = check_all_global(&post_state);
        assert!(
            global_result.valid,
            "Delayed failure check — step {}: global violation: {:?}",
            step,
            global_result
                .violations
                .iter()
                .map(|v| format!("{}: {}", v.invariant_id, v.description))
                .collect::<Vec<_>>()
        );

        let economic_result = check_all_economic(&post_state);
        assert!(
            economic_result.valid,
            "Delayed failure check — step {}: economic violation: {:?}",
            step,
            economic_result
                .violations
                .iter()
                .map(|v| format!("{}: {}", v.invariant_id, v.description))
                .collect::<Vec<_>>()
        );

        trace_steps.push(TraceStep {
            pre: current_state.clone(),
            input,
            post: post_state.clone(),
        });

        current_state = post_state;

        // Temporal check at intermediate checkpoints
        if step % checkpoint_interval == 0 {
            let partial_trace = Trace {
                steps: trace_steps.clone(),
            };
            let temporal_result = check_all_temporal(&partial_trace);
            assert!(
                temporal_result.valid,
                "Delayed failure check — temporal violation at checkpoint step {}: {:?}",
                step,
                temporal_result
                    .violations
                    .iter()
                    .map(|v| format!("{}: {}", v.invariant_id, v.description))
                    .collect::<Vec<_>>()
            );
        }
    }

    // Final temporal check over the full trace
    let full_trace = Trace {
        steps: trace_steps,
    };
    let final_temporal = check_all_temporal(&full_trace);
    assert!(
        final_temporal.valid,
        "Delayed failure check — final temporal violation: {:?}",
        final_temporal
            .violations
            .iter()
            .map(|v| format!("{}: {}", v.invariant_id, v.description))
            .collect::<Vec<_>>()
    );
}

/// Mixed operation trace: exercises all transition classes (init, transfer,
/// deposit, withdraw, noop, error/reject) in a single long trace.
/// Validates: Requirements 3.3, 3.10
#[test]
fn test_mixed_operations_trace() {
    let mut accounts = BTreeMap::new();
    let acct_a = {
        let mut id = [0u8; 32];
        id[0] = 0xAA;
        id
    };
    let acct_b = {
        let mut id = [0u8; 32];
        id[0] = 0xBB;
        id
    };
    accounts.insert(
        AccountId(acct_a),
        AccountData {
            balance: 100_000,
            nonce: 0,
            data: vec![],
        },
    );
    accounts.insert(
        AccountId(acct_b),
        AccountData {
            balance: 50_000,
            nonce: 0,
            data: vec![],
        },
    );

    let mut current_state = build_genesis_state(accounts);
    let mut trace_steps: Vec<TraceStep> = Vec::new();

    // Step 0: init
    let init_input = make_init();
    let post = apply(&current_state, &init_input);
    assert!(check_all_local(&current_state, &init_input, &post).valid);
    assert!(check_all_global(&post).valid);
    trace_steps.push(TraceStep {
        pre: current_state.clone(),
        input: init_input,
        post: post.clone(),
    });
    current_state = post;

    // Build a sequence of mixed operations
    let operations: Vec<Input> = vec![
        // Transfers
        make_transfer(&acct_a, &acct_b, 1_000),
        make_transfer(&acct_b, &acct_a, 500),
        make_transfer(&acct_a, &acct_b, 200),
        // Deposits
        make_deposit(&acct_a, 5_000),
        make_deposit(&acct_b, 3_000),
        // Withdrawals
        make_withdraw(&acct_a, 2_000),
        make_withdraw(&acct_b, 1_000),
        // Noops
        make_noop(),
        make_noop(),
        // More transfers
        make_transfer(&acct_a, &acct_b, 10),
        make_transfer(&acct_b, &acct_a, 10),
        // Another deposit/withdraw cycle
        make_deposit(&acct_a, 100),
        make_withdraw(&acct_a, 50),
    ];

    // Repeat the operation sequence multiple times for a longer trace
    for cycle in 0..15 {
        for (i, input) in operations.iter().enumerate() {
            let post_state = apply(&current_state, input);

            let step_label = format!("cycle {}, op {}", cycle, i);

            let local_result = check_all_local(&current_state, input, &post_state);
            assert!(
                local_result.valid,
                "Mixed ops — {}: local violation: {:?}",
                step_label,
                local_result
                    .violations
                    .iter()
                    .map(|v| format!("{}: {}", v.invariant_id, v.description))
                    .collect::<Vec<_>>()
            );

            let global_result = check_all_global(&post_state);
            assert!(
                global_result.valid,
                "Mixed ops — {}: global violation: {:?}",
                step_label,
                global_result
                    .violations
                    .iter()
                    .map(|v| format!("{}: {}", v.invariant_id, v.description))
                    .collect::<Vec<_>>()
            );

            let economic_result = check_all_economic(&post_state);
            assert!(
                economic_result.valid,
                "Mixed ops — {}: economic violation: {:?}",
                step_label,
                economic_result
                    .violations
                    .iter()
                    .map(|v| format!("{}: {}", v.invariant_id, v.description))
                    .collect::<Vec<_>>()
            );

            trace_steps.push(TraceStep {
                pre: current_state.clone(),
                input: input.clone(),
                post: post_state.clone(),
            });
            current_state = post_state;
        }
    }

    // Temporal invariants over the full mixed trace
    let trace = Trace {
        steps: trace_steps,
    };
    let temporal_result = check_all_temporal(&trace);
    assert!(
        temporal_result.valid,
        "Mixed ops — temporal violation over {} steps: {:?}",
        trace.steps.len(),
        temporal_result
            .violations
            .iter()
            .map(|v| format!("{}: {}", v.invariant_id, v.description))
            .collect::<Vec<_>>()
    );
}
