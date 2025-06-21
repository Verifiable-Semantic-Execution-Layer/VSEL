//! Property-based tests for the VSEL Trace Engine.
//!
//! Uses `proptest` to verify correctness properties derived from
//! EXECUTION_TRACE_MODEL.md, TRACE_SUFFICIENCY.md, Requirement 6.
//!
//! Properties tested:
//! - Property 25: Trace Recording Completeness (Req 6.1, 6.3, 6.7)
//! - Property 26: Trace Commitment Chain Integrity (Req 6.2)
//! - Property 27: Trace Replay Round-Trip / LEM-10 (Req 6.4, 6.6)
//! - Property 28: Trace Sufficiency (Req 6.5)
//! - Property 29: Trace Compression Round-Trip / THM-11 (Req 6.9)
//! - Property 30: Trace Temporal Consistency (Req 6.10)
//! - Property 31: Partial Trace Verification (Req 6.8)

use std::collections::BTreeMap;

use proptest::prelude::*;

use vsel_core::input::{Authorization, Input};
use vsel_core::observable::obs;
use vsel_core::state::*;
use vsel_core::transition::apply;
use vsel_core::types::*;

use vsel_trace::commitment::check_temporal_consistency;
use vsel_trace::compression::{compress, decompress};
use vsel_trace::engine::*;
use vsel_trace::reconstruction::reconstruct;

// ---------------------------------------------------------------------------
// Arbitrary strategies
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

fn arb_domain_tag() -> impl Strategy<Value = DomainTag> {
    arb_bytes32()
        .prop_filter("domain tag must not be all zeros", |b| {
            b.iter().any(|&x| x != 0)
        })
        .prop_map(|b| DomainTag(Hash(b)))
}

fn arb_canonical_state() -> impl Strategy<Value = CanonicalState> {
    (
        proptest::collection::btree_map(arb_account_id(), arb_account_data(), 0..3),
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

fn arb_protocol_version() -> impl Strategy<Value = ProtocolVersion> {
    (0u32..10, 0u32..100, 0u32..100).prop_map(|(major, minor, patch)| ProtocolVersion {
        major,
        minor,
        patch,
    })
}

fn arb_environment() -> impl Strategy<Value = Environment> {
    (1u64..=1_000_000u64, 1u64..=1_000_000u64, arb_domain_tag()).prop_map(
        |(timestamp, block_height, execution_domain)| Environment {
            timestamp,
            block_height,
            execution_domain,
        },
    )
}

/// Build a valid state at sequence 0 (genesis) or > 0.
fn build_state_at_seq(c: CanonicalState, seq: u64, env: Environment) -> State {
    let d = derive(&c);
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
        timestamp: env.timestamp,
    };
    State {
        canonical: c,
        derived: d,
        environment: env,
        economic: econ,
        metadata: meta,
    }
}

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

/// Generate a small sequence of valid inputs for trace testing.
/// Uses "deposit" operations which always succeed on any state.
fn arb_input_sequence(max_len: usize) -> impl Strategy<Value = Vec<Input>> {
    prop::collection::vec(
        (arb_bytes32(), 1u128..=10_000u128).prop_map(|(account, amount)| {
            let mut data = Vec::new();
            data.extend_from_slice(&account);
            data.extend_from_slice(&amount.to_le_bytes());
            make_input("deposit", data)
        }),
        1..=max_len,
    )
}

// ---------------------------------------------------------------------------
// Property 25: Trace Recording Completeness
// Every state transition produces a complete trace entry.
// **Validates: Requirements 6.1, 6.3, 6.7**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property 25: Every transition recorded via the trace engine produces
    /// a complete entry with all required fields populated.
    #[test]
    fn prop_trace_recording_completeness(
        c in arb_canonical_state(),
        env in arb_environment(),
    ) {
        let state = build_state_at_seq(c, 1, env);
        let mut data = Vec::new();
        data.extend_from_slice(&[1u8; 32]);
        data.extend_from_slice(&500u128.to_le_bytes());
        let input = make_input("deposit", data);

        let post = apply(&state, &input);
        let observable = obs(&state, &input, &post);

        let mut engine = TraceEngine::new();
        let entry = engine.record_transition(&state, &input, &post, &observable);

        // Verify all fields are populated
        prop_assert_eq!(entry.index, 0);
        prop_assert_eq!(entry.pre_state_commitment, commit(&state.canonical));
        prop_assert_eq!(entry.post_state_commitment, commit(&post.canonical));
        prop_assert_eq!(entry.input, input);
        prop_assert_eq!(entry.observable, observable);
        prop_assert_eq!(entry.environment, post.environment);
        // Chain hash must not be zero (it's computed from content)
        prop_assert_ne!(entry.chain_hash, Hash([0u8; 32]));
    }
}

// ---------------------------------------------------------------------------
// Property 26: Trace Commitment Chain Integrity
// Any modification to a trace entry invalidates the chain hash.
// **Validates: Requirements 6.2**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property 26: Modifying any entry in a trace invalidates the chain.
    #[test]
    fn prop_trace_commitment_chain_integrity(
        c in arb_canonical_state(),
        env in arb_environment(),
        tamper_byte in 1u8..=255u8,
    ) {
        let state = build_state_at_seq(c, 1, env);

        // Build a 3-entry trace
        let mut current = state.clone();
        let mut engine = TraceEngine::new();
        let mut entries = Vec::new();

        for i in 0u8..3 {
            let mut data = Vec::new();
            data.extend_from_slice(&[i + 1; 32]);
            data.extend_from_slice(&((i as u128 + 1) * 100).to_le_bytes());
            let input = make_input("deposit", data);
            let post = apply(&current, &input);
            let observable = obs(&current, &input, &post);
            let entry = engine.record_transition(&current, &input, &post, &observable);
            entries.push(entry);
            current = post;
        }

        let trace = Trace {
            entries: entries.clone(),
            initial_state: state.clone(),
            commitment: engine.current_chain_hash().clone(),
        };

        // Original trace must verify
        prop_assert!(verify_trace(&trace), "original trace must verify");

        // Tamper with the second entry's post_state_commitment
        let mut tampered_entries = entries.clone();
        tampered_entries[1].post_state_commitment.0[0] =
            tampered_entries[1].post_state_commitment.0[0].wrapping_add(tamper_byte);

        let tampered_trace = Trace {
            entries: tampered_entries,
            initial_state: state,
            commitment: engine.current_chain_hash().clone(),
        };

        // Tampered trace must NOT verify
        prop_assert!(!verify_trace(&tampered_trace), "tampered trace must not verify");
    }
}

// ---------------------------------------------------------------------------
// Property 27: Trace Replay Round-Trip (LEM-10)
// reconstruct(s₀, inputs) = τ
// **Validates: Requirements 6.4, 6.6**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    /// Property 27: Reconstructing a trace from the same initial state and
    /// inputs produces an identical trace (deterministic replay).
    #[test]
    fn prop_trace_replay_round_trip(
        c in arb_canonical_state(),
        env in arb_environment(),
        inputs in arb_input_sequence(5),
    ) {
        let state = build_state_at_seq(c, 1, env);

        let trace1 = reconstruct(&state, &inputs);
        let trace2 = reconstruct(&state, &inputs);

        // Both traces must have the same number of entries
        prop_assert_eq!(trace1.entries.len(), trace2.entries.len());

        // Every entry must be identical
        for (e1, e2) in trace1.entries.iter().zip(trace2.entries.iter()) {
            prop_assert_eq!(e1, e2, "replay must produce identical entries");
        }

        // Final commitments must match
        prop_assert_eq!(trace1.commitment, trace2.commitment);
    }
}

// ---------------------------------------------------------------------------
// Property 28: Trace Sufficiency
// Trace commitment uniquely determines semantic execution.
// **Validates: Requirements 6.5**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    /// Property 28: Two traces with the same commitment must have identical
    /// observables (the commitment uniquely determines semantic execution).
    #[test]
    fn prop_trace_sufficiency(
        c in arb_canonical_state(),
        env in arb_environment(),
        inputs in arb_input_sequence(5),
    ) {
        let state = build_state_at_seq(c, 1, env);

        let trace1 = reconstruct(&state, &inputs);
        let trace2 = reconstruct(&state, &inputs);

        // Same commitment
        prop_assert_eq!(&trace1.commitment, &trace2.commitment);

        // Same observables (sufficiency: commitment determines semantics)
        for (e1, e2) in trace1.entries.iter().zip(trace2.entries.iter()) {
            prop_assert_eq!(
                &e1.observable, &e2.observable,
                "traces with same commitment must have identical observables"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Property 29: Trace Compression Round-Trip (THM-11)
// obs(decompress(compress(τ))) = obs(τ)
// **Validates: Requirements 6.9**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    /// Property 29: Compressing and decompressing a trace preserves all
    /// observables: obs(decompress(compress(τ))) = obs(τ).
    #[test]
    fn prop_trace_compression_round_trip(
        c in arb_canonical_state(),
        env in arb_environment(),
        inputs in arb_input_sequence(5),
    ) {
        let state = build_state_at_seq(c, 1, env);
        let original = reconstruct(&state, &inputs);

        let compressed = compress(&original);
        let decompressed = decompress(&compressed);

        // Same number of entries
        prop_assert_eq!(original.entries.len(), decompressed.entries.len());

        // Observables must be identical (THM-11)
        for (orig, decomp) in original.entries.iter().zip(decompressed.entries.iter()) {
            prop_assert_eq!(
                &orig.observable, &decomp.observable,
                "obs(decompress(compress(τ))) must equal obs(τ) (THM-11)"
            );
        }

        // Chain hashes must also match
        for (orig, decomp) in original.entries.iter().zip(decompressed.entries.iter()) {
            prop_assert_eq!(
                &orig.chain_hash, &decomp.chain_hash,
                "chain hashes must survive compression round-trip"
            );
        }

        // Final commitment must match
        prop_assert_eq!(
            original.commitment, decompressed.commitment,
            "trace commitment must survive compression round-trip"
        );
    }
}

// ---------------------------------------------------------------------------
// Property 30: Trace Temporal Consistency
// meta_{i+1}.time >= meta_i.time and monotonic sequence numbers.
// **Validates: Requirements 6.10**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property 30: Temporal consistency is enforced — timestamps are
    /// non-decreasing and sequence numbers are strictly increasing.
    #[test]
    fn prop_trace_temporal_consistency(
        c in arb_canonical_state(),
        env in arb_environment(),
        inputs in arb_input_sequence(5),
    ) {
        let state = build_state_at_seq(c, 1, env);
        let trace = reconstruct(&state, &inputs);

        for i in 1..trace.entries.len() {
            let prev = &trace.entries[i - 1];
            let curr = &trace.entries[i];

            // Timestamps must be non-decreasing
            prop_assert!(
                curr.environment.timestamp >= prev.environment.timestamp,
                "timestamps must be non-decreasing: {} >= {}",
                curr.environment.timestamp,
                prev.environment.timestamp
            );

            // Sequence numbers must be strictly increasing
            prop_assert_eq!(
                curr.index,
                prev.index + 1,
                "sequence numbers must be strictly increasing"
            );

            // check_temporal_consistency helper must agree
            prop_assert!(
                check_temporal_consistency(
                    prev.environment.timestamp,
                    prev.index,
                    curr.environment.timestamp,
                    curr.index,
                ),
                "check_temporal_consistency must pass for consecutive entries"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Property 31: Partial Trace Verification
// Valid segments verify, tampered segments fail.
// **Validates: Requirements 6.8**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    /// Property 31: A valid segment of a trace verifies correctly,
    /// and a tampered segment fails verification.
    #[test]
    fn prop_partial_trace_verification(
        c in arb_canonical_state(),
        env in arb_environment(),
        inputs in arb_input_sequence(5),
        tamper_byte in 1u8..=255u8,
    ) {
        let state = build_state_at_seq(c, 1, env);
        let trace = reconstruct(&state, &inputs);

        if trace.entries.len() >= 3 {
            // Extract a segment from the middle
            let start = 1;
            let end = trace.entries.len() - 1;
            let segment: Vec<TraceEntry> = trace.entries[start..end].to_vec();

            let predecessor = trace.entries[start - 1].chain_hash.clone();
            let successor = trace.entries[end - 1].chain_hash.clone();

            let proof = TraceSegmentProof {
                entries: segment.clone(),
                predecessor_chain_hash: predecessor.clone(),
                successor_chain_hash: successor.clone(),
            };

            // Valid segment must verify
            prop_assert!(
                verify_trace_segment(&proof),
                "valid segment must verify"
            );

            // Tamper with an entry in the segment
            let mut tampered_segment = segment;
            tampered_segment[0].post_state_commitment.0[0] =
                tampered_segment[0].post_state_commitment.0[0].wrapping_add(tamper_byte);

            let tampered_proof = TraceSegmentProof {
                entries: tampered_segment,
                predecessor_chain_hash: predecessor,
                successor_chain_hash: successor,
            };

            // Tampered segment must NOT verify
            prop_assert!(
                !verify_trace_segment(&tampered_proof),
                "tampered segment must not verify"
            );
        }
    }
}
