//! Property-based tests for the VSEL Execution Engine (vsel-engine).
//!
//! Uses `proptest` to verify correctness properties derived from
//! STATE_MACHINE.md §6, TECH_SPEC.md §4, FORMAL_SPECIFICATION.md §3.
//!
//! **Property 1: Execution Determinism** — `execute(s, σ)` produces identical
//! output for identical inputs (AX-1).
//! **Validates: Requirements 1.4, 2.3**
//!
//! **Property 5: Bounded State Mutation** — `Diff(s, s') ⊆ AllowedMutations(σ)`
//! (SAFE-3).
//! **Validates: Requirements 2.4, 5.8, 18.9**

use std::collections::BTreeMap;

use proptest::collection::btree_map;
use proptest::prelude::*;

use vsel_core::input::*;
use vsel_core::state::*;
use vsel_core::types::*;
use vsel_engine::engine::{DefaultExecutionEngine, ExecutionEngine};

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
    (arb_canonical_state(), arb_environment(), arb_trace_metadata()).prop_map(
        |(canonical, environment, metadata)| {
            let derived = derive(&canonical);
            let economic = derive_economic(&canonical, &environment);
            State {
                canonical,
                derived,
                environment,
                economic,
                metadata,
            }
        },
    )
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
                payload: Payload {
                    payload_type,
                    data,
                },
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
                payload: Payload {
                    payload_type,
                    data,
                },
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
        (
            "[a-z]{1,20}",
            prop::collection::vec(any::<u8>(), 1..64),
        )
            .prop_map(|(payload_type, data)| Input {
                payload: Payload {
                    payload_type,
                    data,
                },
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
            }),
    ]
}

fn arb_any_input() -> impl Strategy<Value = Input> {
    prop_oneof![arb_valid_input(), arb_invalid_input(),]
}

// ---------------------------------------------------------------------------
// Property 1: Execution Determinism
// For any (s, σ), engine.execute(s, σ) produces identical results when
// called twice with the same inputs. Both Ok and Err results must be
// identical.
// **Validates: Requirements 1.4, 2.3**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property 1a (Determinism — valid inputs): For any arbitrary
    /// (state, valid_input) pair, `engine.execute(s, σ)` called twice
    /// produces identical results. If both succeed, the ExecutionResult
    /// (pre_state, post_state, observable, transition_class, trace_entry)
    /// must be equal. If both fail, the ExecutionError must be equal.
    /// This proves AX-1 holds at the engine level.
    #[test]
    fn prop_execution_determinism_valid_input(
        s in arb_valid_state(),
        sigma in arb_valid_input(),
    ) {
        let engine = DefaultExecutionEngine;

        let r1 = engine.execute(&s, &sigma);
        let r2 = engine.execute(&s, &sigma);

        // Both calls must agree on success/failure.
        prop_assert_eq!(
            r1.is_ok(),
            r2.is_ok(),
            "engine.execute must be deterministic: both calls must succeed or both must fail"
        );

        match (r1, r2) {
            (Ok(er1), Ok(er2)) => {
                prop_assert_eq!(
                    er1, er2,
                    "engine.execute must produce identical ExecutionResult for identical inputs (AX-1)"
                );
            }
            (Err(e1), Err(e2)) => {
                prop_assert_eq!(
                    e1, e2,
                    "engine.execute must produce identical ExecutionError for identical inputs"
                );
            }
            _ => unreachable!(),
        }
    }

    /// Property 1b (Determinism — any inputs including invalid): For any
    /// arbitrary (state, input) pair including structurally invalid inputs,
    /// `engine.execute(s, σ)` called twice produces identical results.
    /// This extends determinism to the full input space.
    #[test]
    fn prop_execution_determinism_any_input(
        s in arb_valid_state(),
        sigma in arb_any_input(),
    ) {
        let engine = DefaultExecutionEngine;

        let r1 = engine.execute(&s, &sigma);
        let r2 = engine.execute(&s, &sigma);

        prop_assert_eq!(
            r1.is_ok(),
            r2.is_ok(),
            "engine.execute must be deterministic for all inputs"
        );

        match (r1, r2) {
            (Ok(er1), Ok(er2)) => {
                prop_assert_eq!(
                    er1, er2,
                    "engine.execute must produce identical Ok results for identical inputs (AX-1)"
                );
            }
            (Err(e1), Err(e2)) => {
                prop_assert_eq!(
                    e1, e2,
                    "engine.execute must produce identical Err results for identical inputs"
                );
            }
            _ => unreachable!(),
        }
    }
}

// ---------------------------------------------------------------------------
// Property 5: Bounded State Mutation
// For any (s, σ) where engine.execute succeeds, Diff(s, s') ⊆
// AllowedMutations(σ) (SAFE-3).
// **Validates: Requirements 2.4, 5.8, 18.9**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property 5a (Environment immutability): For any (state, input) pair
    /// where `engine.execute` succeeds, the environment must be unchanged
    /// between pre-state and post-state. Environment is external context
    /// and must never be mutated by a transition.
    #[test]
    fn prop_bounded_mutation_environment_unchanged(
        s in arb_valid_state(),
        sigma in arb_valid_input(),
    ) {
        let engine = DefaultExecutionEngine;

        if let Ok(result) = engine.execute(&s, &sigma) {
            prop_assert_eq!(
                result.pre_state.environment,
                result.post_state.environment,
                "Environment must be unchanged between pre and post state"
            );
        }
    }

    /// Property 5b (Reject/Error/Noop canonical preservation): For any
    /// (state, input) pair where `engine.execute` succeeds and the
    /// transition class is Reject, Error, or Noop, the canonical state
    /// must be unchanged.
    #[test]
    fn prop_bounded_mutation_non_mutating_classes(
        s in arb_valid_state(),
        sigma in arb_valid_input(),
    ) {
        let engine = DefaultExecutionEngine;

        if let Ok(result) = engine.execute(&s, &sigma) {
            match result.transition_class {
                vsel_core::transition::TransitionClass::Reject
                | vsel_core::transition::TransitionClass::Error
                | vsel_core::transition::TransitionClass::Noop => {
                    prop_assert_eq!(
                        result.pre_state.canonical,
                        result.post_state.canonical,
                        "{:?} transition must not mutate canonical state",
                        result.transition_class
                    );
                }
                _ => {
                    // Update, Batch, Init may mutate — checked by other sub-properties.
                }
            }
        }
    }

    /// Property 5c (Init bounded mutation): For any (state, input) pair
    /// where `engine.execute` succeeds and the transition class is Init,
    /// accounts and storage must be unchanged — only system_data.parameters
    /// may change.
    #[test]
    fn prop_bounded_mutation_init_class(
        s in arb_valid_state(),
        sigma in arb_valid_input(),
    ) {
        let engine = DefaultExecutionEngine;

        if let Ok(result) = engine.execute(&s, &sigma) {
            if result.transition_class == vsel_core::transition::TransitionClass::Init {
                prop_assert_eq!(
                    result.pre_state.canonical.accounts,
                    result.post_state.canonical.accounts,
                    "Init transition must not mutate accounts"
                );
                prop_assert_eq!(
                    result.pre_state.canonical.storage,
                    result.post_state.canonical.storage,
                    "Init transition must not mutate storage"
                );
            }
        }
    }

    /// Property 5d (Protocol version immutability): For any (state, input)
    /// pair where `engine.execute` succeeds, the protocol_version must be
    /// unchanged regardless of transition class.
    #[test]
    fn prop_bounded_mutation_protocol_version_unchanged(
        s in arb_valid_state(),
        sigma in arb_valid_input(),
    ) {
        let engine = DefaultExecutionEngine;

        if let Ok(result) = engine.execute(&s, &sigma) {
            prop_assert_eq!(
                result.pre_state.canonical.system_data.protocol_version,
                result.post_state.canonical.system_data.protocol_version,
                "protocol_version must be unchanged across all transition classes"
            );
        }
    }

    /// Property 5e (Derived state consistency): For any (state, input) pair
    /// where `engine.execute` succeeds, the post-state derived state must
    /// be consistent with derive(canonical) — D' = derive(C').
    #[test]
    fn prop_bounded_mutation_derived_consistent(
        s in arb_valid_state(),
        sigma in arb_valid_input(),
    ) {
        let engine = DefaultExecutionEngine;

        if let Ok(result) = engine.execute(&s, &sigma) {
            let expected_derived = derive(&result.post_state.canonical);
            prop_assert_eq!(
                result.post_state.derived,
                expected_derived,
                "Post-state derived must equal derive(canonical) — D' = derive(C')"
            );
        }
    }
}
