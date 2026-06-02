//! Full-system fuzzing — proptest-based fuzzer for the entire VSEL execution layer.
//!
//! Derived from: THREAT_MODEL.md, FORMAL_SPECIFICATION.md, STATE_MACHINE.md.
//! Requirements: 18.6 (adversarial testing under invalid inputs, edge-case
//! transitions, adversarial compositions, and worst-case execution scenarios).
//!
//! This module fuzzes the complete execution path:
//!   random state × random input → classify → apply → invariant checks
//!
//! Properties verified:
//! - AX-2 (closure): apply() always produces a valid state in S.
//! - AX-1 (determinism): apply(s, σ) is deterministic.
//! - LEM-7 (error safety): error states preserve all invariants.
//! - No panics: the execution engine handles all edge cases without panicking.
//! - Failure recovery: after an error transition, valid inputs still succeed.
//! - Cascading error resilience: consecutive errors don't corrupt state.

use std::collections::BTreeMap;

use proptest::prelude::*;

use vsel_core::input::*;
use vsel_core::observable::obs;
use vsel_core::state::*;
use vsel_core::transition::*;
use vsel_core::types::*;
use vsel_engine::engine::{DefaultExecutionEngine, ExecutionEngine};
use vsel_invariants::global::*;
use vsel_invariants::local::*;

// ===========================================================================
// Shared test helpers
// ===========================================================================

fn test_domain_tag() -> DomainTag {
    let mut h = [0u8; 32];
    h[0] = 0xAB;
    DomainTag(Hash(h))
}

fn valid_auth() -> Authorization {
    Authorization {
        classical_sig: vec![1, 2, 3],
        pqc_sig: vec![4, 5, 6],
        public_key: HybridPublicKey {
            classical: vec![10, 11],
            pqc: vec![20, 21],
        },
        nonce: 42,
        domain: test_domain_tag(),
    }
}

fn minimal_canonical() -> CanonicalState {
    CanonicalState {
        accounts: BTreeMap::new(),
        storage: BTreeMap::new(),
        system_data: SystemData {
            protocol_version: ProtocolVersion {
                major: 0,
                minor: 1,
                patch: 0,
            },
            total_supply: 0,
            parameters: BTreeMap::new(),
        },
    }
}

fn build_valid_state(c: CanonicalState, seq: u64) -> State {
    let d = derive(&c);
    let env = Environment {
        timestamp: 1_000_000,
        block_height: 1,
        execution_domain: test_domain_tag(),
    };
    let econ = derive_economic(&c, &env);
    let commitment = if seq == 0 {
        Hash([0u8; 32])
    } else {
        Hash([0xABu8; 32])
    };
    let meta = TraceMetadata {
        sequence_index: seq,
        previous_commitment: commitment,
        epoch: 0,
        timestamp: 1_000_000,
    };
    State {
        canonical: c,
        derived: d,
        environment: env,
        economic: econ,
        metadata: meta,
    }
}

fn make_input(payload_type: &str, data: Vec<u8>) -> Input {
    Input {
        payload: Payload {
            payload_type: payload_type.to_string(),
            data,
        },
        auth: valid_auth(),
        aux: AuxiliaryData { data: vec![] },
    }
}

fn make_deposit_input(account_id: [u8; 32], amount: u128) -> Input {
    let mut data = vec![];
    data.extend_from_slice(&account_id);
    data.extend_from_slice(&amount.to_le_bytes());
    make_input("deposit", data)
}

fn make_transfer_input(sender: [u8; 32], receiver: [u8; 32], amount: u128) -> Input {
    let mut data = vec![];
    data.extend_from_slice(&sender);
    data.extend_from_slice(&receiver);
    data.extend_from_slice(&amount.to_le_bytes());
    make_input("transfer", data)
}

fn make_withdraw_input(account_id: [u8; 32], amount: u128) -> Input {
    let mut data = vec![];
    data.extend_from_slice(&account_id);
    data.extend_from_slice(&amount.to_le_bytes());
    make_input("withdraw", data)
}

/// Build a canonical state with a single account whose balance equals total_supply.
fn canonical_with_account(id: [u8; 32], balance: u128) -> CanonicalState {
    let mut c = minimal_canonical();
    c.accounts.insert(
        AccountId(id),
        AccountData {
            balance,
            nonce: 0,
            data: vec![],
        },
    );
    c.system_data.total_supply = balance;
    c
}

// ===========================================================================
// Proptest strategies — generate random states and inputs
// ===========================================================================

/// Generate a random valid CanonicalState with 0-4 accounts.
fn arb_canonical_state() -> impl Strategy<Value = CanonicalState> {
    prop::collection::vec(
        (
            prop::array::uniform32(any::<u8>()), // account id
            0u128..=10_000u128,                  // balance
            0u64..=1_000u64,                     // nonce
        ),
        0..=4,
    )
    .prop_map(|accounts| {
        let mut c = minimal_canonical();
        let mut total: u128 = 0;
        for (id_bytes, balance, nonce) in accounts {
            // Deduplicate by just inserting — BTreeMap handles it.
            c.accounts.insert(
                AccountId(id_bytes),
                AccountData {
                    balance,
                    nonce,
                    data: vec![],
                },
            );
            total = total.saturating_add(balance);
        }
        // Recompute total_supply to match actual sum (accounts may have been
        // deduplicated by BTreeMap, so recalculate).
        let actual_total: u128 = c.accounts.values().map(|a| a.balance).sum();
        c.system_data.total_supply = actual_total;
        c
    })
}

/// Generate a random valid State at a given sequence index.
fn arb_valid_state() -> impl Strategy<Value = State> {
    (arb_canonical_state(), 0u64..=100u64).prop_map(|(c, seq)| build_valid_state(c, seq))
}

/// Generate a random Input covering all transition classes.
fn arb_input() -> impl Strategy<Value = Input> {
    prop_oneof![
        // Valid deposit
        (prop::array::uniform32(any::<u8>()), 1u128..=5_000u128)
            .prop_map(|(id, amount)| make_deposit_input(id, amount)),
        // Valid withdraw
        (prop::array::uniform32(any::<u8>()), 1u128..=5_000u128)
            .prop_map(|(id, amount)| make_withdraw_input(id, amount)),
        // Valid transfer
        (
            prop::array::uniform32(any::<u8>()),
            prop::array::uniform32(any::<u8>()),
            1u128..=5_000u128,
        )
            .prop_map(|(s, r, a)| make_transfer_input(s, r, a)),
        // Init
        prop::collection::vec(any::<u8>(), 1..=32).prop_map(|data| make_input("init", data)),
        // Batch
        prop::collection::vec(any::<u8>(), 1..=32).prop_map(|data| make_input("batch", data)),
        // Noop (unrecognized payload type)
        "[a-z]{3,8}".prop_map(|name| make_input(&format!("noop_{}", name), vec![0x01])),
        // Invalid input (empty payload type — triggers Reject)
        Just(Input {
            payload: Payload {
                payload_type: String::new(),
                data: vec![]
            },
            auth: valid_auth(),
            aux: AuxiliaryData { data: vec![] },
        }),
        // Invalid input (empty data — triggers Reject)
        Just(Input {
            payload: Payload {
                payload_type: "deposit".to_string(),
                data: vec![]
            },
            auth: Authorization {
                classical_sig: vec![],
                pqc_sig: vec![],
                public_key: HybridPublicKey {
                    classical: vec![],
                    pqc: vec![]
                },
                nonce: 0,
                domain: DomainTag(Hash([0u8; 32])),
            },
            aux: AuxiliaryData { data: vec![] },
        }),
    ]
}

/// Generate a sequence of random inputs for multi-step fuzzing.
fn arb_input_sequence(max_len: usize) -> impl Strategy<Value = Vec<Input>> {
    prop::collection::vec(arb_input(), 1..=max_len)
}

// ===========================================================================
// Property 1: AX-2 Closure — apply() always produces a valid state
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// **Validates: Requirements 18.6**
    ///
    /// AX-2 (closure): For all s ∈ S and σ ∈ Σ, Apply(s, σ) ∈ S.
    /// The post-state must always satisfy valid_state() and all global
    /// invariants (G_valid, G_struct, G_commit, G_mono, G_env).
    #[test]
    fn fuzz_ax2_closure_all_states_and_inputs(
        state in arb_valid_state(),
        input in arb_input(),
    ) {
        let post = apply(&state, &input);

        // AX-2: post-state must be valid.
        prop_assert!(
            valid_state(&post),
            "AX-2 violated: apply() produced an invalid state.\n\
             Transition class: {:?}\n\
             Pre valid_state: {}\n\
             Post valid_state: {}",
            classify(&state, &input),
            valid_state(&state),
            valid_state(&post),
        );

        // Derived state must be consistent: D = Derive(C).
        let expected_derived = derive(&post.canonical);
        prop_assert!(
            post.derived == expected_derived,
            "AX-2/DEF-1 violated: post.derived != Derive(post.canonical)"
        );

        // Economic context must be consistent.
        let expected_econ = derive_economic(&post.canonical, &post.environment);
        prop_assert!(
            post.economic == expected_econ,
            "AX-2 violated: post.economic != DeriveEconomic(post.canonical, post.environment)"
        );

        // Global invariants must hold on the post-state.
        let global_result = check_all_global(&post);
        prop_assert!(
            global_result.valid,
            "AX-2 violated: global invariants failed on post-state.\n\
             Violations: {:?}",
            global_result.violations.iter().map(|v| &v.invariant_id).collect::<Vec<_>>()
        );
    }
}

// ===========================================================================
// Property 2: AX-1 Determinism — apply() is deterministic
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// **Validates: Requirements 18.6**
    ///
    /// AX-1 (determinism): Apply(s, σ) produces identical output for
    /// identical inputs. Verified by applying twice and comparing.
    #[test]
    fn fuzz_ax1_determinism_all_transitions(
        state in arb_valid_state(),
        input in arb_input(),
    ) {
        let post1 = apply(&state, &input);
        let post2 = apply(&state, &input);

        prop_assert_eq!(
            post1, post2,
            "AX-1 violated: apply() produced different results for identical inputs.\n\
             Transition class: {:?}",
            classify(&state, &input),
        );
    }
}

// ===========================================================================
// Property 3: LEM-7 Error safety — error states preserve invariants
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// **Validates: Requirements 18.6**
    ///
    /// LEM-7 (error safety): Apply(s, σ_invalid) = s_error where s_error ∈ S
    /// and all invariants are preserved. For Reject, Error, and Noop transitions,
    /// the canonical state must be unchanged.
    #[test]
    fn fuzz_lem7_error_states_preserve_invariants(
        state in arb_valid_state(),
        input in arb_input(),
    ) {
        let class = classify(&state, &input);
        let post = apply(&state, &input);

        // For error-class transitions, canonical state must be unchanged.
        match class {
            TransitionClass::Reject | TransitionClass::Error | TransitionClass::Noop => {
                prop_assert!(
                    state.canonical == post.canonical,
                    "LEM-7 violated: {:?} transition changed canonical state",
                    class,
                );
            }
            _ => {
                // Update, Init, Batch may change canonical state — that's fine.
            }
        }

        // All global invariants must hold on the post-state regardless of class.
        let global_result = check_all_global(&post);
        prop_assert!(
            global_result.valid,
            "LEM-7 violated: global invariants failed after {:?} transition.\n\
             Violations: {:?}",
            class,
            global_result.violations.iter().map(|v| &v.invariant_id).collect::<Vec<_>>()
        );

        // Local invariants must hold for the transition.
        let local_result = check_all_local(&state, &input, &post);
        prop_assert!(
            local_result.valid,
            "LEM-7 violated: local invariants failed for {:?} transition.\n\
             Violations: {:?}",
            class,
            local_result.violations.iter().map(|v| &v.invariant_id).collect::<Vec<_>>()
        );

        // Metadata must advance (sequence_index increments by 1).
        prop_assert!(
            post.metadata.sequence_index == state.metadata.sequence_index + 1,
            "LEM-7 violated: metadata did not advance for {:?} transition. \
             Expected seq={}, got seq={}",
            class,
            state.metadata.sequence_index + 1,
            post.metadata.sequence_index,
        );
    }
}

// ===========================================================================
// Property 4: All transition classes fuzzed — no panics
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// **Validates: Requirements 18.6**
    ///
    /// Fuzz all transition classes: Init, Update, Noop, Error, Batch, Reject.
    /// The execution engine must handle all edge cases without panicking.
    /// This test exercises the DefaultExecutionEngine which runs the full
    /// 7-step pipeline with bounded mutation checks.
    #[test]
    fn fuzz_all_transition_classes_no_panics(
        state in arb_valid_state(),
        input in arb_input(),
    ) {
        let engine = DefaultExecutionEngine;

        // The engine may return Ok or Err — both are acceptable.
        // What matters is that it does NOT panic.
        let result = engine.execute(&state, &input);

        match result {
            Ok(er) => {
                // If the engine succeeded, verify the result is consistent.
                let class = er.transition_class;

                // Post-state must be valid.
                prop_assert!(
                    valid_state(&er.post_state),
                    "Engine produced invalid post-state for {:?} transition",
                    class,
                );

                // Derived state must be consistent.
                let expected_derived = derive(&er.post_state.canonical);
                prop_assert_eq!(
                    er.post_state.derived, expected_derived,
                    "Engine post-state derived != Derive(canonical) for {:?}",
                    class,
                );
            }
            Err(_) => {
                // Engine returned an error — this is acceptable for malformed
                // inputs, precondition failures, etc. The important thing is
                // that it didn't panic.
            }
        }
    }
}

// ===========================================================================
// Property 5: Failure recovery — after error, system continues processing
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    /// **Validates: Requirements 18.6**
    ///
    /// Failure recovery: after an error transition (Reject, Error, Noop),
    /// the system can continue processing valid inputs. The error must not
    /// leave the state in a condition that prevents future valid transitions.
    #[test]
    fn fuzz_failure_recovery_after_error(
        initial_balance in 100u128..=10_000u128,
        error_input_kind in 0u8..=2u8,
    ) {
        let account_id = [1u8; 32];
        let c = canonical_with_account(account_id, initial_balance);
        let state = build_valid_state(c, 1);

        // Step 1: Apply an error-inducing input.
        let error_input = match error_input_kind {
            0 => {
                // Reject: structurally invalid input.
                Input {
                    payload: Payload { payload_type: String::new(), data: vec![] },
                    auth: valid_auth(),
                    aux: AuxiliaryData { data: vec![] },
                }
            }
            1 => {
                // Error: precondition failure (transfer from non-existent account).
                let non_existent = [0xFFu8; 32];
                make_transfer_input(non_existent, account_id, 100)
            }
            _ => {
                // Noop: unrecognized payload type.
                make_input("unknown_operation", vec![0x01])
            }
        };

        let error_class = classify(&state, &error_input);
        let error_state = apply(&state, &error_input);

        // Verify the error state is valid.
        prop_assert!(
            valid_state(&error_state),
            "Error state is invalid after {:?} transition",
            error_class,
        );

        // Step 2: Apply a valid deposit after the error.
        let recovery_input = make_deposit_input(account_id, 500);
        let recovered_state = apply(&error_state, &recovery_input);

        // Verify recovery succeeded.
        prop_assert!(
            valid_state(&recovered_state),
            "Recovery state is invalid after deposit following {:?} error",
            error_class,
        );

        // Verify the deposit was actually applied.
        let recovered_balance = recovered_state
            .canonical
            .accounts
            .get(&AccountId(account_id))
            .map(|a| a.balance)
            .unwrap_or(0);
        prop_assert_eq!(
            recovered_balance,
            initial_balance + 500,
            "Deposit not applied correctly after {:?} error recovery",
            error_class,
        );

        // Verify total supply is consistent.
        prop_assert_eq!(
            recovered_state.canonical.system_data.total_supply,
            initial_balance + 500,
            "Total supply inconsistent after error recovery",
        );

        // Verify global invariants hold on the recovered state.
        let global_result = check_all_global(&recovered_state);
        prop_assert!(
            global_result.valid,
            "Global invariants failed after error recovery from {:?}.\n\
             Violations: {:?}",
            error_class,
            global_result.violations.iter().map(|v| &v.invariant_id).collect::<Vec<_>>()
        );
    }
}

// ===========================================================================
// Property 6: Cascading error resilience — consecutive errors don't corrupt
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    /// **Validates: Requirements 18.6**
    ///
    /// Cascading error resilience: multiple consecutive error transitions
    /// must not corrupt state. After N errors, the canonical state must
    /// remain unchanged and the system must still accept valid inputs.
    #[test]
    fn fuzz_cascading_error_resilience(
        initial_balance in 100u128..=10_000u128,
        num_errors in 2u8..=10u8,
    ) {
        let account_id = [1u8; 32];
        let c = canonical_with_account(account_id, initial_balance);
        let mut state = build_valid_state(c, 1);

        let original_canonical = state.canonical.clone();

        // Apply N consecutive error-inducing inputs.
        let error_inputs: Vec<Input> = (0..num_errors)
            .map(|i| match i % 3 {
                0 => Input {
                    payload: Payload { payload_type: String::new(), data: vec![] },
                    auth: valid_auth(),
                    aux: AuxiliaryData { data: vec![] },
                },
                1 => {
                    let non_existent = [0xFFu8; 32];
                    make_transfer_input(non_existent, account_id, 100)
                }
                _ => make_input("unknown_operation", vec![0x01]),
            })
            .collect();

        for (i, error_input) in error_inputs.iter().enumerate() {
            let class = classify(&state, error_input);
            state = apply(&state, error_input);

            // After each error, canonical state must be unchanged.
            prop_assert!(
                state.canonical == original_canonical,
                "Canonical state corrupted after error {} ({:?})",
                i + 1,
                class,
            );

            // After each error, state must be valid.
            prop_assert!(
                valid_state(&state),
                "State invalid after error {} ({:?})",
                i + 1,
                class,
            );

            // Global invariants must hold.
            let global_result = check_all_global(&state);
            prop_assert!(
                global_result.valid,
                "Global invariants failed after error {} ({:?}).\n\
                 Violations: {:?}",
                i + 1,
                class,
                global_result.violations.iter().map(|v| &v.invariant_id).collect::<Vec<_>>()
            );
        }

        // After all errors, apply a valid deposit and verify recovery.
        let recovery_input = make_deposit_input(account_id, 1_000);
        let recovered = apply(&state, &recovery_input);

        prop_assert!(
            valid_state(&recovered),
            "State invalid after recovery from {} cascading errors",
            num_errors,
        );

        let recovered_balance = recovered
            .canonical
            .accounts
            .get(&AccountId(account_id))
            .map(|a| a.balance)
            .unwrap_or(0);
        prop_assert_eq!(
            recovered_balance,
            initial_balance + 1_000,
            "Deposit not applied correctly after {} cascading errors",
            num_errors,
        );
    }
}

// ===========================================================================
// Property 7: Multi-step trace fuzzing — random input sequences
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    /// **Validates: Requirements 18.6**
    ///
    /// Multi-step trace fuzzing: apply a random sequence of inputs and verify
    /// that every intermediate state satisfies all invariants. This tests the
    /// system under realistic multi-step execution scenarios.
    #[test]
    fn fuzz_multi_step_trace_all_invariants(
        initial_balance in 0u128..=5_000u128,
        inputs in arb_input_sequence(8),
    ) {
        let account_id = [1u8; 32];
        let c = canonical_with_account(account_id, initial_balance);
        let mut state = build_valid_state(c, 1);

        for (step, input) in inputs.iter().enumerate() {
            let pre = state.clone();
            let class = classify(&pre, input);
            state = apply(&pre, input);

            // AX-2: post-state must be valid.
            prop_assert!(
                valid_state(&state),
                "Step {}: AX-2 violated after {:?} transition",
                step,
                class,
            );

            // Global invariants must hold.
            let global_result = check_all_global(&state);
            prop_assert!(
                global_result.valid,
                "Step {}: global invariants failed after {:?}.\n\
                 Violations: {:?}",
                step,
                class,
                global_result.violations.iter().map(|v| &v.invariant_id).collect::<Vec<_>>()
            );

            // Local invariants must hold for this transition.
            let local_result = check_all_local(&pre, input, &state);
            prop_assert!(
                local_result.valid,
                "Step {}: local invariants failed for {:?}.\n\
                 Violations: {:?}",
                step,
                class,
                local_result.violations.iter().map(|v| &v.invariant_id).collect::<Vec<_>>()
            );

            // Metadata must advance monotonically.
            prop_assert_eq!(
                state.metadata.sequence_index,
                pre.metadata.sequence_index + 1,
                "Step {}: metadata did not advance for {:?}",
                step,
                class,
            );
        }
    }
}

// ===========================================================================
// Property 8: Resource conservation across all transition classes
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// **Validates: Requirements 18.6**
    ///
    /// Resource conservation (L_cons): for every transition, the sum of all
    /// account balances must equal system total_supply in both pre and post
    /// states. This is a critical economic invariant.
    #[test]
    fn fuzz_resource_conservation_all_classes(
        state in arb_valid_state(),
        input in arb_input(),
    ) {
        let post = apply(&state, &input);

        // Pre-state conservation.
        let pre_balance_sum: u128 = state.canonical.accounts.values().map(|a| a.balance).sum();
        prop_assert_eq!(
            pre_balance_sum,
            state.canonical.system_data.total_supply,
            "Pre-state: balance sum != total_supply",
        );

        // Post-state conservation.
        let post_balance_sum: u128 = post.canonical.accounts.values().map(|a| a.balance).sum();
        prop_assert_eq!(
            post_balance_sum,
            post.canonical.system_data.total_supply,
            "Post-state: balance sum != total_supply after {:?} transition",
            classify(&state, &input),
        );
    }
}

// ===========================================================================
// Property 9: Observable determinism — obs() is deterministic
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// **Validates: Requirements 18.6**
    ///
    /// Observable determinism (DEF-4): Obs(s, σ, s') is deterministic and
    /// derivable entirely from (s, σ, s') with no hidden side effects.
    #[test]
    fn fuzz_observable_determinism(
        state in arb_valid_state(),
        input in arb_input(),
    ) {
        let post = apply(&state, &input);

        let obs1 = obs(&state, &input, &post);
        let obs2 = obs(&state, &input, &post);

        prop_assert!(
            obs1 == obs2,
            "Observable is not deterministic for {:?} transition",
            classify(&state, &input),
        );

        // Observable transition class must match classification.
        prop_assert!(
            obs1.transition_class == classify(&state, &input),
            "Observable transition class mismatch: got {:?}, expected {:?}",
            obs1.transition_class,
            classify(&state, &input),
        );
    }
}

// ===========================================================================
// Property 10: Environment immutability across transitions
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// **Validates: Requirements 18.6**
    ///
    /// Environment immutability: the environment must never change during
    /// a transition. apply() must preserve the environment exactly.
    #[test]
    fn fuzz_environment_immutability(
        state in arb_valid_state(),
        input in arb_input(),
    ) {
        let post = apply(&state, &input);

        prop_assert!(
            state.environment == post.environment,
            "Environment changed during {:?} transition",
            classify(&state, &input),
        );
    }
}
