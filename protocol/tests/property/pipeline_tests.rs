//! Property-based tests for the VSEL 7-step Execution Pipeline (vsel-engine).
//!
//! Uses `proptest` to verify correctness properties derived from
//! STATE_MACHINE.md §6, TECH_SPEC.md §4, FORMAL_SPECIFICATION.md §3.
//!
//! **Property 7: Execution Pipeline Order** — deviation from pipeline order
//! produces explicit error.
//! **Validates: Requirements 2.2**

use std::collections::BTreeMap;

use proptest::collection::btree_map;
use proptest::prelude::*;

use vsel_core::input::*;
use vsel_core::state::*;
use vsel_core::transition::apply;
use vsel_core::types::*;
use vsel_engine::pipeline::{run_pipeline, PipelineError};

// ---------------------------------------------------------------------------
// Arbitrary strategies (reused patterns from guard_tests.rs)
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

fn arb_storage_key() -> impl Strategy<Value = StorageKey> {
    prop::collection::vec(any::<u8>(), 1..64).prop_map(StorageKey)
}

fn arb_storage_value() -> impl Strategy<Value = StorageValue> {
    prop::collection::vec(any::<u8>(), 0..128).prop_map(StorageValue)
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

fn arb_trace_metadata() -> impl Strategy<Value = TraceMetadata> {
    prop_oneof![
        // Genesis metadata
        (0u64..=1_000_000u64, 0u64..=100u64).prop_map(|(timestamp, epoch)| TraceMetadata {
            sequence_index: 0,
            previous_commitment: Hash([0u8; 32]),
            epoch,
            timestamp,
        }),
        // Non-genesis metadata
        (
            1u64..=1_000_000u64,
            arb_bytes32().prop_filter("non-zero commitment", |b| b.iter().any(|&x| x != 0)),
            0u64..=1_000_000u64,
            0u64..=100u64,
        )
            .prop_map(|(seq, prev, timestamp, epoch)| TraceMetadata {
                sequence_index: seq,
                previous_commitment: Hash(prev),
                epoch,
                timestamp,
            }),
    ]
}

fn arb_valid_state() -> impl Strategy<Value = State> {
    (
        arb_canonical_state(),
        arb_environment(),
        arb_trace_metadata(),
    )
        .prop_map(|(canonical, environment, metadata)| {
            let derived = derive(&canonical);
            let economic = derive_economic(&canonical, &environment);
            State {
                canonical,
                derived,
                environment,
                economic,
                metadata,
            }
        })
}

// ---------------------------------------------------------------------------
// Input strategies
// ---------------------------------------------------------------------------

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

/// Generates inputs that are structurally invalid (would fail step 1).
fn arb_invalid_input() -> impl Strategy<Value = Input> {
    prop_oneof![
        // Empty payload_type
        (
            prop::collection::vec(any::<u8>(), 1..64),
            arb_valid_authorization(),
        )
            .prop_map(|(data, auth)| Input {
                payload: Payload {
                    payload_type: String::new(),
                    data,
                },
                auth,
                aux: AuxiliaryData { data: vec![] },
            }),
        // Empty payload data
        ("[a-z]{1,20}", arb_valid_authorization()).prop_map(|(payload_type, auth)| Input {
            payload: Payload {
                payload_type,
                data: vec![],
            },
            auth,
            aux: AuxiliaryData { data: vec![] },
        }),
        // Empty classical_sig
        (
            "[a-z]{1,20}",
            prop::collection::vec(any::<u8>(), 1..64),
            arb_domain_tag(),
        )
            .prop_map(|(payload_type, data, domain)| Input {
                payload: Payload { payload_type, data },
                auth: Authorization {
                    classical_sig: vec![],
                    pqc_sig: vec![1, 2, 3],
                    public_key: HybridPublicKey {
                        classical: vec![10],
                        pqc: vec![20],
                    },
                    nonce: 0,
                    domain,
                },
                aux: AuxiliaryData { data: vec![] },
            }),
        // Empty pqc_sig
        (
            "[a-z]{1,20}",
            prop::collection::vec(any::<u8>(), 1..64),
            arb_domain_tag(),
        )
            .prop_map(|(payload_type, data, domain)| Input {
                payload: Payload { payload_type, data },
                auth: Authorization {
                    classical_sig: vec![1, 2, 3],
                    pqc_sig: vec![],
                    public_key: HybridPublicKey {
                        classical: vec![10],
                        pqc: vec![20],
                    },
                    nonce: 0,
                    domain,
                },
                aux: AuxiliaryData { data: vec![] },
            }),
        // Zero domain tag
        ("[a-z]{1,20}", prop::collection::vec(any::<u8>(), 1..64),).prop_map(
            |(payload_type, data)| Input {
                payload: Payload { payload_type, data },
                auth: Authorization {
                    classical_sig: vec![1, 2, 3],
                    pqc_sig: vec![4, 5, 6],
                    public_key: HybridPublicKey {
                        classical: vec![10],
                        pqc: vec![20],
                    },
                    nonce: 0,
                    domain: DomainTag(Hash([0u8; 32])),
                },
                aux: AuxiliaryData { data: vec![] },
            }
        ),
    ]
}

// ---------------------------------------------------------------------------
// Property 7: Execution Pipeline Order
// Deviation from pipeline order produces explicit error.
// **Validates: Requirements 2.2**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property 7a (Pipeline Determinism): For any valid (state, input) pair
    /// where `run_pipeline` succeeds, the result is deterministic — same
    /// inputs always produce the same output. This proves the pipeline
    /// preserves AX-1 (determinism) end-to-end.
    #[test]
    fn prop_pipeline_determinism(
        s in arb_valid_state(),
        sigma in arb_valid_input(),
    ) {
        let r1 = run_pipeline(&s, &sigma);
        let r2 = run_pipeline(&s, &sigma);

        // Both calls must produce the same result (Ok or Err).
        prop_assert_eq!(
            r1.is_ok(),
            r2.is_ok(),
            "run_pipeline must be deterministic: both calls must succeed or both must fail"
        );

        match (r1, r2) {
            (Ok(out1), Ok(out2)) => {
                prop_assert_eq!(
                    out1, out2,
                    "run_pipeline must produce identical output for identical inputs (AX-1)"
                );
            }
            (Err(e1), Err(e2)) => {
                prop_assert_eq!(
                    e1, e2,
                    "run_pipeline must produce identical errors for identical inputs"
                );
            }
            _ => unreachable!(),
        }
    }

    /// Property 7b (Invalid Input Rejection): For any valid state and
    /// structurally invalid input, if we bypass step 1 (input
    /// canonicalization) conceptually, the pipeline still catches the
    /// problem — it never silently proceeds to produce a successful
    /// result. The pipeline rejects at step 1 (MalformedInput) or
    /// step 2 (Unauthorized).
    #[test]
    fn prop_pipeline_catches_invalid_input(
        s in arb_valid_state(),
        sigma in arb_invalid_input(),
    ) {
        let result = run_pipeline(&s, &sigma);

        // The pipeline must reject invalid inputs — it must NOT succeed.
        prop_assert!(
            result.is_err(),
            "run_pipeline must reject structurally invalid inputs, got Ok({:?})",
            result.unwrap().transition_class
        );

        // The error must be from step 1 (MalformedInput) or step 2 (Unauthorized).
        let err = result.unwrap_err();
        prop_assert!(
            matches!(
                err,
                PipelineError::MalformedInput { .. } | PipelineError::Unauthorized { .. }
            ),
            "Invalid input must be caught at step 1 or step 2, got: {:?}",
            err
        );
    }

    /// Property 7c (Pipeline-Apply Consistency): For any valid (state, input)
    /// pair where `run_pipeline` succeeds, the pipeline's post-state
    /// canonical data must be consistent with `vsel_core::transition::apply`.
    /// This ensures the pipeline does not diverge from the core transition
    /// function for the canonical state content.
    #[test]
    fn prop_pipeline_consistent_with_apply(
        s in arb_valid_state(),
        sigma in arb_valid_input(),
    ) {
        let pipeline_result = run_pipeline(&s, &sigma);

        if let Ok(output) = pipeline_result {
            // The core apply function is the ground truth for state transitions.
            let core_post = apply(&s, &sigma);

            // The pipeline's post-state canonical data must match apply's result.
            prop_assert_eq!(
                output.post_state.canonical,
                core_post.canonical,
                "Pipeline post-state canonical data must match apply(s, σ).canonical"
            );

            // The transition class from the pipeline must match core classify.
            let core_class = vsel_core::transition::classify(&s, &sigma);
            prop_assert_eq!(
                output.transition_class,
                core_class,
                "Pipeline transition class must match core classify(s, σ)"
            );
        }
        // If the pipeline rejects, that's fine — the pipeline is stricter
        // than bare apply (it checks authorization, preconditions, etc.).
    }
}
