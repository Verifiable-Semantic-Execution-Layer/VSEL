#![allow(clippy::all)]
//! Property-based tests for VSEL Enhanced Temporal Robustness.
//!
//! Uses `proptest` to verify enhanced temporal invariants added in tasks 19.2/19.3.
//! This file is DIFFERENT from `temporal_invariant_tests.rs` — that file tests
//! the basic temporal invariants. This file tests:
//!
//! - Enhanced T_causal: block_height non-decreasing, reordering attack detection
//! - Enhanced T_no_revert (SAFE-5): per-account nonce monotonicity
//! - TE_extraction_trace: disproportionate value extraction detection
//! - TE_flash_trace: flash loan pattern detection
//! - TE_velocity_trace: excessive transaction velocity detection
//! - Replay resistance: proof replay guard, trace replay detector
//!
//! **Property 12: Temporal Invariant Preservation** — all temporal invariants
//! (including temporal economic invariants) hold over valid traces.
//! **Validates: Requirements 3.3**

use std::collections::BTreeMap;

use proptest::prelude::*;
use proptest::collection::btree_map;

use vsel_core::input::*;
use vsel_core::state::*;
use vsel_core::types::*;

use vsel_invariants::{Trace, TraceStep};
use vsel_invariants::temporal::{
    check_all_temporal, t_causal, t_no_revert,
    te_extraction_trace, te_flash_trace, te_velocity_trace,
};

use vsel_proof::prover::{DefaultProver, Prover};
use vsel_proof::replay::{ReplayGuard, ReplayRejection};

use vsel_trace::replay::{TraceReplayDetector, TraceReplayRejection};

// ---------------------------------------------------------------------------
// Arbitrary strategies (reused from temporal_invariant_tests.rs patterns)
// ---------------------------------------------------------------------------

fn arb_bytes32() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

fn arb_account_id() -> impl Strategy<Value = AccountId> {
    arb_bytes32().prop_map(AccountId)
}

fn arb_account_data() -> impl Strategy<Value = AccountData> {
    (
        0u128..=1_000_000u128,
        0u64..=1_000_000u64,
        prop::collection::vec(any::<u8>(), 0..32),
    )
        .prop_map(|(balance, nonce, data)| AccountData {
            balance,
            nonce,
            data,
        })
}

fn arb_protocol_version() -> impl Strategy<Value = ProtocolVersion> {
    (0u32..10, 0u32..100, 0u32..100).prop_map(|(major, minor, patch)| ProtocolVersion {
        major,
        minor,
        patch,
    })
}

fn arb_canonical_state() -> impl Strategy<Value = CanonicalState> {
    (
        btree_map(arb_account_id(), arb_account_data(), 0..5),
        arb_protocol_version(),
    )
        .prop_map(|(accounts, protocol_version)| {
            let total_supply: u128 = accounts.values().map(|a| a.balance).sum();
            CanonicalState {
                accounts,
                storage: BTreeMap::new(),
                system_data: SystemData {
                    protocol_version,
                    total_supply,
                    parameters: BTreeMap::new(),
                },
            }
        })
}

fn arb_domain_tag() -> impl Strategy<Value = DomainTag> {
    arb_bytes32()
        .prop_filter("domain tag must not be all zeros", |b| {
            b.iter().any(|&x| x != 0)
        })
        .prop_map(|b| DomainTag(Hash(b)))
}

fn arb_environment() -> impl Strategy<Value = Environment> {
    (1u64..=u64::MAX, 0u64..=1_000_000u64, arb_domain_tag()).prop_map(
        |(timestamp, block_height, execution_domain)| Environment {
            timestamp,
            block_height,
            execution_domain,
        },
    )
}

fn arb_valid_authorization() -> impl Strategy<Value = Authorization> {
    (
        prop::collection::vec(any::<u8>(), 1..64),
        prop::collection::vec(any::<u8>(), 1..64),
        prop::collection::vec(any::<u8>(), 1..64),
        prop::collection::vec(any::<u8>(), 1..64),
        any::<u64>(),
        arb_domain_tag(),
    )
        .prop_map(|(classical_sig, pqc_sig, classical_pk, pqc_pk, nonce, domain)| {
            Authorization {
                classical_sig,
                pqc_sig,
                public_key: HybridPublicKey {
                    classical: classical_pk,
                    pqc: pqc_pk,
                },
                nonce,
                domain,
            }
        })
}

fn arb_valid_input() -> impl Strategy<Value = Input> {
    (
        "[a-z]{1,20}",
        prop::collection::vec(any::<u8>(), 1..128),
        arb_valid_authorization(),
        prop::collection::vec(any::<u8>(), 0..64),
    )
        .prop_map(|(payload_type, data, auth, aux_data)| Input {
            payload: Payload {
                payload_type,
                data,
            },
            auth,
            aux: AuxiliaryData { data: aux_data },
        })
}

// ---------------------------------------------------------------------------
// Helper: build a valid State at a given sequence index and timestamp
// ---------------------------------------------------------------------------

fn build_valid_state_at(
    canonical: &CanonicalState,
    environment: &Environment,
    seq_index: u64,
    timestamp: u64,
) -> State {
    let derived = derive(canonical);
    let economic = derive_economic(canonical, environment);
    let previous_commitment = if seq_index == 0 {
        Hash([0u8; 32])
    } else {
        let mut h = [0u8; 32];
        let bytes = seq_index.to_le_bytes();
        h[..8].copy_from_slice(&bytes);
        h[8] = 0xFF;
        Hash(h)
    };
    State {
        canonical: canonical.clone(),
        derived,
        environment: environment.clone(),
        economic,
        metadata: TraceMetadata {
            sequence_index: seq_index,
            previous_commitment,
            epoch: 0,
            timestamp,
        },
    }
}

/// Generate a valid trace with 1..=max_steps steps.
fn arb_valid_trace(max_steps: usize) -> impl Strategy<Value = Trace> {
    (
        arb_canonical_state(),
        arb_environment(),
        arb_valid_input(),
        1..=max_steps,
        0u64..=1_000u64,
        0u64..=100u64,
    )
        .prop_flat_map(|(canonical, env, input, num_steps, base_ts, base_seq)| {
            let ts_increments = prop::collection::vec(0u64..=100u64, num_steps);
            ts_increments.prop_map(move |increments| {
                let mut steps = Vec::with_capacity(num_steps);
                let mut current_ts = base_ts;

                for i in 0..num_steps {
                    let pre_seq = base_seq + i as u64;
                    let post_seq = pre_seq + 1;
                    let pre_ts = current_ts;
                    let post_ts = pre_ts + increments[i];

                    let pre = build_valid_state_at(&canonical, &env, pre_seq, pre_ts);
                    let post = build_valid_state_at(&canonical, &env, post_seq, post_ts);

                    steps.push(TraceStep {
                        pre,
                        input: input.clone(),
                        post,
                    });

                    current_ts = post_ts;
                }

                Trace { steps }
            })
        })
}

// ---------------------------------------------------------------------------
// Property 12 (enhanced): All temporal invariants (including temporal economic)
// hold over valid traces generated by arb_valid_trace.
// **Validates: Requirements 3.3**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property 12 (enhanced): Valid traces satisfy ALL temporal invariants,
    /// including the temporal economic invariants (TE_extraction, TE_flash,
    /// TE_velocity, etc.) added in task 19.2.
    #[test]
    fn prop_valid_traces_satisfy_all_enhanced_temporal_invariants(
        trace in arb_valid_trace(5),
    ) {
        let result = check_all_temporal(&trace);
        prop_assert!(
            result.valid,
            "All enhanced temporal invariants should hold on a valid trace, violations: {:?}",
            result.violations.iter().map(|v| format!("{}: {}", v.invariant_id, v.description)).collect::<Vec<_>>()
        );
    }
}

// ---------------------------------------------------------------------------
// T_causal enhanced: Block height non-decreasing
// **Validates: Requirements 3.3**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// T_causal enhanced: Corrupting block_height to decrease within a step
    /// is detected by t_causal.
    #[test]
    fn prop_t_causal_detects_block_height_decrease(
        trace in arb_valid_trace(5),
        corrupt_idx in 0usize..5usize,
    ) {
        prop_assume!(corrupt_idx < trace.steps.len());
        prop_assume!(trace.steps[corrupt_idx].pre.environment.block_height > 0);

        let mut corrupted = trace.clone();
        corrupted.steps[corrupt_idx].post.environment.block_height =
            corrupted.steps[corrupt_idx].pre.environment.block_height - 1;

        let result = t_causal(&corrupted);
        prop_assert!(
            !result.valid,
            "t_causal should detect block_height decrease at step {}",
            corrupt_idx
        );
        let has_violation = result.violations.iter().any(|v| v.invariant_id == "T_causal");
        prop_assert!(has_violation, "Violation should be T_causal");
    }
}

// ---------------------------------------------------------------------------
// T_causal enhanced: Reordering attack detection
// **Validates: Requirements 3.3**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// T_causal enhanced: If consecutive steps have inconsistent timestamps
    /// (next pre timestamp < current post timestamp), t_causal detects it
    /// as a possible reordering attack.
    #[test]
    fn prop_t_causal_detects_reordering_attack(
        trace in arb_valid_trace(5),
        corrupt_idx in 0usize..4usize,
    ) {
        prop_assume!(corrupt_idx + 1 < trace.steps.len());
        // We need the current post timestamp to be > 0 so we can make next pre < it
        prop_assume!(trace.steps[corrupt_idx].post.metadata.timestamp > 0);

        let mut corrupted = trace.clone();
        // Set next step's pre timestamp to be less than current step's post timestamp
        corrupted.steps[corrupt_idx + 1].pre.metadata.timestamp =
            corrupted.steps[corrupt_idx].post.metadata.timestamp - 1;

        let result = t_causal(&corrupted);
        prop_assert!(
            !result.valid,
            "t_causal should detect reordering attack between steps {} and {}",
            corrupt_idx, corrupt_idx + 1
        );
        let has_reorder_violation = result.violations.iter().any(|v| {
            v.invariant_id == "T_causal" && v.description.contains("reordering")
        });
        prop_assert!(
            has_reorder_violation,
            "Violation should mention reordering attack"
        );
    }
}

// ---------------------------------------------------------------------------
// T_no_revert enhanced (SAFE-5): Nonce monotonicity
// **Validates: Requirements 3.3**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// T_no_revert enhanced (SAFE-5): If an account's nonce decreases across
    /// the trace, t_no_revert detects it.
    #[test]
    fn prop_t_no_revert_detects_nonce_decrease(
        trace in arb_valid_trace(5),
        corrupt_idx in 1usize..5usize,
    ) {
        prop_assume!(corrupt_idx < trace.steps.len());
        // We need at least one account in the trace to corrupt
        prop_assume!(!trace.steps[corrupt_idx].post.canonical.accounts.is_empty());

        let mut corrupted = trace.clone();

        // Pick the first account and set its nonce to a high value in an earlier step,
        // then a lower value in the corrupt step.
        let account_id = corrupted.steps[corrupt_idx]
            .post
            .canonical
            .accounts
            .keys()
            .next()
            .unwrap()
            .clone();

        // Set a high nonce in an earlier step's post state
        let earlier_idx = corrupt_idx - 1;
        corrupted.steps[earlier_idx]
            .post
            .canonical
            .accounts
            .entry(account_id.clone())
            .or_insert_with(|| AccountData {
                balance: 0,
                nonce: 0,
                data: vec![],
            })
            .nonce = 100;

        // Set a lower nonce in the corrupt step's post state
        corrupted.steps[corrupt_idx]
            .post
            .canonical
            .accounts
            .get_mut(&account_id)
            .unwrap()
            .nonce = 50;

        let result = t_no_revert(&corrupted);
        prop_assert!(
            !result.valid,
            "t_no_revert should detect nonce decrease for account at step {}",
            corrupt_idx
        );
        let has_nonce_violation = result.violations.iter().any(|v| {
            v.invariant_id == "T_no_revert" && v.description.contains("nonce")
        });
        prop_assert!(
            has_nonce_violation,
            "Violation should mention nonce decrease"
        );
    }
}

// ---------------------------------------------------------------------------
// TE_extraction_trace: Extraction detection
// **Validates: Requirements 3.3**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// TE_extraction_trace: Construct a trace where one account gains >50%
    /// of total supply in a window, verify it's detected.
    #[test]
    fn prop_te_extraction_detects_disproportionate_gain(
        env in arb_environment(),
        input in arb_valid_input(),
        base_ts in 0u64..=1_000u64,
        base_seq in 0u64..=100u64,
    ) {
        // Create a trace with a single account that gains >50% of total supply.
        // Pre-state: account has 100, total_supply = 1000
        // Post-state: account has 700, total_supply = 1000
        // gain = 600, threshold check: 600 * 100 = 60000 > 1000 * 50 = 50000 ✓
        let account_id = AccountId([1u8; 32]);
        let other_id = AccountId([2u8; 32]);

        let mut pre_canonical = CanonicalState {
            accounts: BTreeMap::new(),
            storage: BTreeMap::new(),
            system_data: SystemData {
                protocol_version: ProtocolVersion { major: 1, minor: 0, patch: 0 },
                total_supply: 1000,
                parameters: BTreeMap::new(),
            },
        };
        pre_canonical.accounts.insert(
            account_id.clone(),
            AccountData { balance: 100, nonce: 0, data: vec![] },
        );
        pre_canonical.accounts.insert(
            other_id.clone(),
            AccountData { balance: 900, nonce: 0, data: vec![] },
        );

        let mut post_canonical = pre_canonical.clone();
        // Gain of 600 (from 100 to 700) which is >50% of total_supply 1000
        post_canonical.accounts.get_mut(&account_id).unwrap().balance = 700;
        post_canonical.accounts.get_mut(&other_id).unwrap().balance = 300;

        let pre = build_valid_state_at(&pre_canonical, &env, base_seq, base_ts);
        let post = build_valid_state_at(&post_canonical, &env, base_seq + 1, base_ts + 1);

        let trace = Trace {
            steps: vec![TraceStep {
                pre,
                input: input.clone(),
                post,
            }],
        };

        let result = te_extraction_trace(&trace);
        prop_assert!(
            !result.valid,
            "te_extraction_trace should detect >50% gain"
        );
        let has_extraction = result.violations.iter().any(|v| {
            v.invariant_id == "TE_extraction_trace"
        });
        prop_assert!(has_extraction, "Violation should be TE_extraction_trace");
    }
}

// ---------------------------------------------------------------------------
// TE_flash_trace: Flash loan detection
// **Validates: Requirements 3.3**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// TE_flash_trace: Construct a trace where an account's balance spikes
    /// to 2x+ and returns to near-original, verify it's detected.
    /// The balance timeline is built from post-states, so we need:
    /// post[0]=1000 (initial), post[1]=3000 (spike >=2x), post[2]=1000 (return).
    #[test]
    fn prop_te_flash_detects_spike_and_return(
        env in arb_environment(),
        input in arb_valid_input(),
        base_ts in 0u64..=1_000u64,
        base_seq in 0u64..=100u64,
    ) {
        let account_id = AccountId([1u8; 32]);
        let other_id = AccountId([2u8; 32]);
        let total_supply = 5000u128;

        // Step 0: pre has 500, post has 1000 (initial balance in timeline)
        let mut canonical_pre0 = CanonicalState {
            accounts: BTreeMap::new(),
            storage: BTreeMap::new(),
            system_data: SystemData {
                protocol_version: ProtocolVersion { major: 1, minor: 0, patch: 0 },
                total_supply,
                parameters: BTreeMap::new(),
            },
        };
        canonical_pre0.accounts.insert(
            account_id.clone(),
            AccountData { balance: 500, nonce: 0, data: vec![] },
        );
        canonical_pre0.accounts.insert(
            other_id.clone(),
            AccountData { balance: 4500, nonce: 0, data: vec![] },
        );

        let mut canonical_post0 = canonical_pre0.clone();
        canonical_post0.accounts.get_mut(&account_id).unwrap().balance = 1000;
        canonical_post0.accounts.get_mut(&other_id).unwrap().balance = 4000;

        // Step 1: post has 3000 (spike: 3x of 1000)
        let canonical_pre1 = canonical_post0.clone();
        let mut canonical_post1 = canonical_pre1.clone();
        canonical_post1.accounts.get_mut(&account_id).unwrap().balance = 3000;
        canonical_post1.accounts.get_mut(&other_id).unwrap().balance = 2000;

        // Step 2: post has 1000 (return to near-original)
        let canonical_pre2 = canonical_post1.clone();
        let mut canonical_post2 = canonical_pre2.clone();
        canonical_post2.accounts.get_mut(&account_id).unwrap().balance = 1000;
        canonical_post2.accounts.get_mut(&other_id).unwrap().balance = 4000;

        let step0 = TraceStep {
            pre: build_valid_state_at(&canonical_pre0, &env, base_seq, base_ts),
            input: input.clone(),
            post: build_valid_state_at(&canonical_post0, &env, base_seq + 1, base_ts + 1),
        };
        let step1 = TraceStep {
            pre: build_valid_state_at(&canonical_pre1, &env, base_seq + 1, base_ts + 1),
            input: input.clone(),
            post: build_valid_state_at(&canonical_post1, &env, base_seq + 2, base_ts + 2),
        };
        let step2 = TraceStep {
            pre: build_valid_state_at(&canonical_pre2, &env, base_seq + 2, base_ts + 2),
            input: input.clone(),
            post: build_valid_state_at(&canonical_post2, &env, base_seq + 3, base_ts + 3),
        };

        let trace = Trace {
            steps: vec![step0, step1, step2],
        };

        let result = te_flash_trace(&trace);
        prop_assert!(
            !result.valid,
            "te_flash_trace should detect flash loan pattern (spike to 3x and return)"
        );
        let has_flash = result.violations.iter().any(|v| {
            v.invariant_id == "TE_flash_trace"
        });
        prop_assert!(has_flash, "Violation should be TE_flash_trace");
    }
}

// ---------------------------------------------------------------------------
// TE_velocity_trace: Velocity detection
// **Validates: Requirements 3.3**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// TE_velocity_trace: Construct a trace where an account transacts >8
    /// times in a window, verify it's detected.
    #[test]
    fn prop_te_velocity_detects_excessive_transactions(
        env in arb_environment(),
        input in arb_valid_input(),
        base_ts in 0u64..=1_000u64,
        base_seq in 0u64..=100u64,
    ) {
        let account_id = AccountId([1u8; 32]);

        // Build 10 steps where the account's nonce increases each step
        // (>8 transactions in a window of 10 = velocity violation)
        let mut steps = Vec::new();
        let total_supply = 10_000u128;

        for i in 0..10u64 {
            let mut pre_canonical = CanonicalState {
                accounts: BTreeMap::new(),
                storage: BTreeMap::new(),
                system_data: SystemData {
                    protocol_version: ProtocolVersion { major: 1, minor: 0, patch: 0 },
                    total_supply,
                    parameters: BTreeMap::new(),
                },
            };
            pre_canonical.accounts.insert(
                account_id.clone(),
                AccountData { balance: total_supply, nonce: i, data: vec![] },
            );

            let mut post_canonical = pre_canonical.clone();
            post_canonical.accounts.get_mut(&account_id).unwrap().nonce = i + 1;

            let pre = build_valid_state_at(&pre_canonical, &env, base_seq + i, base_ts + i);
            let post = build_valid_state_at(&post_canonical, &env, base_seq + i + 1, base_ts + i + 1);

            steps.push(TraceStep {
                pre,
                input: input.clone(),
                post,
            });
        }

        let trace = Trace { steps };

        let result = te_velocity_trace(&trace);
        prop_assert!(
            !result.valid,
            "te_velocity_trace should detect >8 transactions in a window"
        );
        let has_velocity = result.violations.iter().any(|v| {
            v.invariant_id == "TE_velocity_trace"
        });
        prop_assert!(has_velocity, "Violation should be TE_velocity_trace");
    }
}

// ---------------------------------------------------------------------------
// Replay resistance: Proof replay guard
// **Validates: Requirements 3.3**
// ---------------------------------------------------------------------------

// Helper: build test infrastructure for replay guard tests
fn test_domain_tag() -> DomainTag {
    let mut h = [0u8; 32];
    h[0] = 0xAB;
    DomainTag(Hash(h))
}

fn test_version() -> ProtocolVersion {
    ProtocolVersion {
        major: 1,
        minor: 0,
        patch: 0,
    }
}

fn minimal_canonical() -> CanonicalState {
    CanonicalState {
        accounts: BTreeMap::new(),
        storage: BTreeMap::new(),
        system_data: SystemData {
            protocol_version: test_version(),
            total_supply: 0,
            parameters: BTreeMap::new(),
        },
    }
}

fn test_state() -> State {
    let c = minimal_canonical();
    let d = derive(&c);
    let env = Environment {
        timestamp: 1_000_000,
        block_height: 1,
        execution_domain: test_domain_tag(),
    };
    let econ = derive_economic(&c, &env);
    let meta = TraceMetadata {
        sequence_index: 0,
        previous_commitment: Hash([0u8; 32]),
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

fn test_input_for_trace() -> Input {
    Input {
        payload: Payload {
            payload_type: "transfer".to_string(),
            data: vec![1, 2, 3],
        },
        auth: Authorization {
            classical_sig: vec![1; 64],
            pqc_sig: vec![2; 128],
            public_key: HybridPublicKey {
                classical: vec![3; 32],
                pqc: vec![4; 64],
            },
            nonce: 1,
            domain: test_domain_tag(),
        },
        aux: AuxiliaryData {
            data: vec![0xAA, 0xBB],
        },
    }
}

fn test_observable() -> vsel_core::observable::Observable {
    use vsel_core::observable::{Observable, TransitionStatus};
    use vsel_core::transition::TransitionClass;
    Observable {
        transition_class: TransitionClass::Update,
        outputs: vec![OutputEvent {
            event_type: "balance_change".to_string(),
            data: vec![1, 2, 3],
        }],
        gas_used: 21_000,
        status: TransitionStatus::Success,
    }
}

fn build_engine_trace(num_entries: usize) -> vsel_trace::engine::Trace {
    use vsel_trace::engine::{Trace as EngineTrace, TraceEntry};

    let initial_state = test_state();
    let init_commit = commit(&initial_state.canonical);
    let mut entries = Vec::new();

    for i in 0..num_entries {
        let pre_commit = if i == 0 {
            init_commit.clone()
        } else {
            let mut h = [0u8; 32];
            h[0] = i as u8;
            Hash(h)
        };
        let mut post_hash = [0u8; 32];
        post_hash[0] = (i + 1) as u8;
        let mut chain = [0u8; 32];
        chain[0] = (i + 100) as u8;

        entries.push(TraceEntry {
            index: i as u64,
            pre_state_commitment: pre_commit,
            input: test_input_for_trace(),
            post_state_commitment: Hash(post_hash),
            observable: test_observable(),
            environment: initial_state.environment.clone(),
            chain_hash: Hash(chain),
        });
    }

    let final_commitment = if let Some(last) = entries.last() {
        last.chain_hash.clone()
    } else {
        Hash([0u8; 32])
    };

    EngineTrace {
        entries,
        initial_state,
        commitment: final_commitment,
    }
}

fn test_constraint_system() -> vsel_constraints::ConstraintSystem {
    use vsel_constraints::{Constraint, ConstraintCategory, ConstraintExpr, ConstraintId};
    let mut cs = vsel_constraints::ConstraintSystem::new("1.0.0");
    cs.add_constraint(Constraint {
        id: ConstraintId(0),
        expr: ConstraintExpr::BoolConstant(true),
        category: ConstraintCategory::Structural,
        description: "test constraint".to_string(),
    });
    cs
}

fn make_proof_with_timestamp(ts: u64) -> vsel_proof::prover::Proof {
    let prover = DefaultProver::new("0.1.0-test");
    let trace = build_engine_trace(2);
    let cs = test_constraint_system();
    let mut proof = prover.prove(&trace, &cs).expect("proof generation");
    proof.metadata.timestamp = ts;
    proof
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Replay resistance: Duplicate proofs are always rejected by ReplayGuard.
    /// After accepting a proof, submitting the same proof again must yield
    /// DuplicateCommitment rejection.
    #[test]
    fn prop_replay_guard_rejects_duplicate_proofs(
        ref_ts in 1_000_000u64..=2_000_000u64,
        max_age in 3600u64..=86400u64,
    ) {
        let mut guard = ReplayGuard::new(test_domain_tag(), max_age, ref_ts);
        let proof = make_proof_with_timestamp(ref_ts);

        // First check should pass
        let first_check = guard.check_proof(&proof);
        prop_assert!(first_check.is_ok(), "First proof check should pass");

        // Accept the proof
        guard.accept_proof(&proof);

        // Second check should fail with DuplicateCommitment
        let second_check = guard.check_proof(&proof);
        prop_assert_eq!(
            second_check,
            Err(ReplayRejection::DuplicateCommitment),
            "Duplicate proof must be rejected"
        );
    }
}

// ---------------------------------------------------------------------------
// Replay resistance: Trace replay detector
// **Validates: Requirements 3.3**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Replay resistance: Duplicate traces are always rejected by
    /// TraceReplayDetector. After accepting a trace, submitting the same
    /// trace again must yield DuplicateCommitment rejection.
    #[test]
    fn prop_trace_replay_detector_rejects_duplicate_traces(
        extra_entries in 2usize..=5usize,
    ) {
        // Use min_epoch=0 since our test traces have epoch 0
        let mut detector = TraceReplayDetector::new(test_domain_tag(), 0);
        let trace = build_engine_trace(extra_entries);

        // First check should pass
        let first_check = detector.check_trace(&trace);
        prop_assert!(first_check.is_ok(), "First trace check should pass: {:?}", first_check);

        // Accept the trace
        detector.accept_trace(&trace);

        // Second check should fail with DuplicateCommitment
        let second_check = detector.check_trace(&trace);
        prop_assert_eq!(
            second_check,
            Err(TraceReplayRejection::DuplicateCommitment),
            "Duplicate trace must be rejected"
        );
    }
}
