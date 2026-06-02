//! Property-based tests for VSEL Temporal Invariants.
//!
//! Uses `proptest` to verify correctness properties derived from
//! INVARIANTS.md, EXECUTION_TRACE_MODEL.md.
//!
//! Properties tested:
//! - Property 12: Temporal Invariant Preservation — all temporal invariants hold over valid traces
//!   **Validates: Requirements 3.3**

use std::collections::BTreeMap;

use proptest::collection::btree_map;
use proptest::prelude::*;

use vsel_core::input::*;
use vsel_core::state::*;
use vsel_core::types::*;

use vsel_invariants::temporal::{check_all_temporal, t_causal, t_complete, t_cons, t_no_revert};
use vsel_invariants::{DefaultInvariantSystem, InvariantSystem, Trace, TraceStep};

// ---------------------------------------------------------------------------
// Arbitrary strategies for generating valid trace components
// ---------------------------------------------------------------------------

/// Generate a random 32-byte array.
fn arb_bytes32() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

/// Generate a random AccountId.
fn arb_account_id() -> impl Strategy<Value = AccountId> {
    arb_bytes32().prop_map(AccountId)
}

/// Generate a random AccountData with bounded values.
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

/// Generate a random StorageKey.
fn arb_storage_key() -> impl Strategy<Value = StorageKey> {
    prop::collection::vec(any::<u8>(), 1..64).prop_map(StorageKey)
}

/// Generate a random StorageValue.
fn arb_storage_value() -> impl Strategy<Value = StorageValue> {
    prop::collection::vec(any::<u8>(), 0..128).prop_map(StorageValue)
}

/// Generate a random ProtocolVersion.
fn arb_protocol_version() -> impl Strategy<Value = ProtocolVersion> {
    (0u32..10, 0u32..100, 0u32..100).prop_map(|(major, minor, patch)| ProtocolVersion {
        major,
        minor,
        patch,
    })
}

/// Generate a random CanonicalState with total_supply matching sum of balances.
fn arb_canonical_state() -> impl Strategy<Value = CanonicalState> {
    (
        btree_map(arb_account_id(), arb_account_data(), 0..5),
        btree_map(arb_storage_key(), arb_storage_value(), 0..5),
        arb_protocol_version(),
    )
        .prop_map(|(accounts, storage, protocol_version)| {
            let total_supply: u128 = accounts.values().map(|a| a.balance).sum();
            CanonicalState {
                accounts,
                storage,
                system_data: SystemData {
                    protocol_version,
                    total_supply,
                    parameters: BTreeMap::new(),
                },
            }
        })
}

/// Generate a non-zero DomainTag (required for valid environment).
fn arb_domain_tag() -> impl Strategy<Value = DomainTag> {
    arb_bytes32()
        .prop_filter("domain tag must not be all zeros", |b| {
            b.iter().any(|&x| x != 0)
        })
        .prop_map(|b| DomainTag(Hash(b)))
}

/// Generate a valid Environment.
fn arb_environment() -> impl Strategy<Value = Environment> {
    (1u64..=u64::MAX, 0u64..=1_000_000u64, arb_domain_tag()).prop_map(
        |(timestamp, block_height, execution_domain)| Environment {
            timestamp,
            block_height,
            execution_domain,
        },
    )
}

/// Generate a valid Authorization.
fn arb_valid_authorization() -> impl Strategy<Value = Authorization> {
    (
        prop::collection::vec(any::<u8>(), 1..64),
        prop::collection::vec(any::<u8>(), 1..64),
        prop::collection::vec(any::<u8>(), 1..64),
        prop::collection::vec(any::<u8>(), 1..64),
        any::<u64>(),
        arb_domain_tag(),
    )
        .prop_map(
            |(classical_sig, pqc_sig, classical_pk, pqc_pk, nonce, domain)| Authorization {
                classical_sig,
                pqc_sig,
                public_key: HybridPublicKey {
                    classical: classical_pk,
                    pqc: pqc_pk,
                },
                nonce,
                domain,
            },
        )
}

/// Generate a structurally valid Input.
fn arb_valid_input() -> impl Strategy<Value = Input> {
    (
        "[a-z]{1,20}",
        prop::collection::vec(any::<u8>(), 1..128),
        arb_valid_authorization(),
        prop::collection::vec(any::<u8>(), 0..64),
    )
        .prop_map(|(payload_type, data, auth, aux_data)| Input {
            payload: Payload { payload_type, data },
            auth,
            aux: AuxiliaryData { data: aux_data },
        })
}

// ---------------------------------------------------------------------------
// Strategy for generating valid traces
// ---------------------------------------------------------------------------

/// Build a valid State at a given sequence index and timestamp.
/// For sequence_index == 0, previous_commitment is the zero hash (genesis).
/// For sequence_index > 0, previous_commitment is a non-zero hash.
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
        // Deterministic non-zero commitment based on seq_index
        let mut h = [0u8; 32];
        let bytes = seq_index.to_le_bytes();
        h[..8].copy_from_slice(&bytes);
        h[8] = 0xFF; // ensure non-zero
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
/// Each step has:
/// - pre.metadata.sequence_index = base_seq + i
/// - post.metadata.sequence_index = base_seq + i + 1
/// - post.metadata.timestamp >= pre.metadata.timestamp
/// - pre and post are valid states (total_supply == sum of balances, derived = derive(canonical))
/// - Consecutive steps chain: post of step i has same seq as pre of step i+1
fn arb_valid_trace(max_steps: usize) -> impl Strategy<Value = Trace> {
    (
        arb_canonical_state(),
        arb_environment(),
        arb_valid_input(),
        1..=max_steps,
        0u64..=1_000u64, // base timestamp
        0u64..=100u64,   // base sequence index
    )
        .prop_flat_map(|(canonical, env, input, num_steps, base_ts, base_seq)| {
            // Generate timestamp increments for each step (non-decreasing)
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
// Property 12a: Valid traces satisfy all temporal invariants
// **Validates: Requirements 3.3**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property 12a: For any valid trace (constructed with proper monotonic
    /// sequence indices, non-decreasing timestamps, contiguous indices, and
    /// consistent total_supply), check_all_temporal returns valid.
    #[test]
    fn prop_valid_traces_satisfy_all_temporal_invariants(
        trace in arb_valid_trace(5),
    ) {
        let result = check_all_temporal(&trace);
        prop_assert!(
            result.valid,
            "All temporal invariants should hold on a valid trace, violations: {:?}",
            result.violations.iter().map(|v| format!("{}: {}", v.invariant_id, v.description)).collect::<Vec<_>>()
        );

        // Also verify via the DefaultInvariantSystem trait
        let system = DefaultInvariantSystem;
        let trait_result = system.check_temporal(&trace);
        prop_assert!(
            trait_result.valid,
            "DefaultInvariantSystem.check_temporal should also pass on valid trace"
        );
    }
}

// ---------------------------------------------------------------------------
// Property 12b: T_no_revert detects sequence regression
// **Validates: Requirements 3.3**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property 12b: For any valid trace, if we corrupt a post-state's
    /// sequence_index to be <= pre-state's, t_no_revert detects the violation.
    #[test]
    fn prop_t_no_revert_detects_sequence_regression(
        trace in arb_valid_trace(5),
        corrupt_idx in 0usize..5usize,
    ) {
        // Only corrupt if the index is within bounds
        prop_assume!(corrupt_idx < trace.steps.len());

        let mut corrupted = trace.clone();
        // Set post seq_index to be equal to pre seq_index (regression)
        corrupted.steps[corrupt_idx].post.metadata.sequence_index =
            corrupted.steps[corrupt_idx].pre.metadata.sequence_index;

        let result = t_no_revert(&corrupted);
        prop_assert!(
            !result.valid,
            "t_no_revert should detect sequence regression at step {}",
            corrupt_idx
        );
        let has_violation = result.violations.iter().any(|v| v.invariant_id == "T_no_revert");
        prop_assert!(
            has_violation,
            "Violation should be T_no_revert"
        );
    }
}

// ---------------------------------------------------------------------------
// Property 12c: T_causal detects timestamp regression
// **Validates: Requirements 3.3**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property 12c: For any valid trace, if we corrupt a post-state's
    /// timestamp to be < pre-state's, t_causal detects the violation.
    #[test]
    fn prop_t_causal_detects_timestamp_regression(
        trace in arb_valid_trace(5),
        corrupt_idx in 0usize..5usize,
    ) {
        prop_assume!(corrupt_idx < trace.steps.len());
        // Only corrupt if pre timestamp > 0 so we can make post < pre
        prop_assume!(trace.steps[corrupt_idx].pre.metadata.timestamp > 0);

        let mut corrupted = trace.clone();
        // Set post timestamp to be strictly less than pre timestamp
        corrupted.steps[corrupt_idx].post.metadata.timestamp =
            corrupted.steps[corrupt_idx].pre.metadata.timestamp - 1;

        let result = t_causal(&corrupted);
        prop_assert!(
            !result.valid,
            "t_causal should detect timestamp regression at step {}",
            corrupt_idx
        );
        let has_violation = result.violations.iter().any(|v| v.invariant_id == "T_causal");
        prop_assert!(
            has_violation,
            "Violation should be T_causal"
        );
    }
}

// ---------------------------------------------------------------------------
// Property 12d: T_complete detects sequence gaps
// **Validates: Requirements 3.3**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property 12d: For any valid trace, if we corrupt a post-state's
    /// sequence_index to skip a value (gap), t_complete detects the violation.
    #[test]
    fn prop_t_complete_detects_sequence_gaps(
        trace in arb_valid_trace(5),
        corrupt_idx in 0usize..5usize,
        gap in 2u64..=10u64,
    ) {
        prop_assume!(corrupt_idx < trace.steps.len());

        let mut corrupted = trace.clone();
        // Set post seq_index to pre + gap (skipping values, creating a gap)
        corrupted.steps[corrupt_idx].post.metadata.sequence_index =
            corrupted.steps[corrupt_idx].pre.metadata.sequence_index + gap;

        let result = t_complete(&corrupted);
        prop_assert!(
            !result.valid,
            "t_complete should detect sequence gap at step {} (gap={})",
            corrupt_idx, gap
        );
        let has_violation = result.violations.iter().any(|v| v.invariant_id == "T_complete");
        prop_assert!(
            has_violation,
            "Violation should be T_complete"
        );
    }
}

// ---------------------------------------------------------------------------
// Property 12e: T_cons detects resource inconsistency
// **Validates: Requirements 3.3**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property 12e: For any valid trace, if we corrupt a post-state's
    /// total_supply to not match the balance sum, t_cons detects the violation.
    #[test]
    fn prop_t_cons_detects_resource_inconsistency(
        trace in arb_valid_trace(5),
        corrupt_idx in 0usize..5usize,
        extra in 1u128..=1_000_000u128,
    ) {
        prop_assume!(corrupt_idx < trace.steps.len());

        let mut corrupted = trace.clone();
        // Corrupt total_supply by adding extra to it, breaking balance sum invariant
        corrupted.steps[corrupt_idx].post.canonical.system_data.total_supply += extra;

        let result = t_cons(&corrupted);
        prop_assert!(
            !result.valid,
            "t_cons should detect resource inconsistency at step {} (extra={})",
            corrupt_idx, extra
        );
        let has_violation = result.violations.iter().any(|v| v.invariant_id == "T_cons");
        prop_assert!(
            has_violation,
            "Violation should be T_cons"
        );
    }
}
