//! Property-based tests for the VSEL Guard System (vsel-engine).
//!
//! Uses `proptest` to verify correctness properties derived from
//! STATE_MACHINE.md §5, TRANSITION_PARTITIONING.md,
//! FORMAL_SPECIFICATION.md §3.
//!
//! **Property 4: Guard Exhaustiveness and Disjointness** — every (s, σ) pair
//! matches exactly one guard after priority resolution.
//! **Validates: Requirements 2.1, 2.7**

use std::collections::BTreeMap;

use proptest::collection::btree_map;
use proptest::prelude::*;

use vsel_core::input::*;
use vsel_core::state::*;
use vsel_core::transition::{classify, TransitionClass};
use vsel_core::types::*;
use vsel_engine::guards::{classify_transition, guards_in_priority_order};

// ---------------------------------------------------------------------------
// Arbitrary strategies (reused patterns from transition_tests.rs)
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
// Property 4: Guard Exhaustiveness and Disjointness
// For any (s, σ), classify_transition(s, σ) returns exactly one
// TransitionClass, matching the first guard in priority order.
// **Validates: Requirements 2.1, 2.7**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property 4a (Exhaustiveness): For any arbitrary (state, input) pair,
    /// `classify_transition` returns exactly one of the 6 defined
    /// TransitionClass variants. This proves the guard system is total —
    /// no (s, σ) pair is left unhandled.
    #[test]
    fn prop_guard_exhaustiveness(
        s in arb_valid_state(),
        sigma in arb_any_input(),
    ) {
        let class = classify_transition(&s, &sigma);
        prop_assert!(
            matches!(
                class,
                TransitionClass::Reject
                    | TransitionClass::Init
                    | TransitionClass::Error
                    | TransitionClass::Batch
                    | TransitionClass::Update
                    | TransitionClass::Noop
            ),
            "classify_transition must return one of the 6 defined TransitionClass variants, got {:?}",
            class
        );
    }

    /// Property 4b (Disjointness after priority resolution): For any arbitrary
    /// (state, input) pair, the result of `classify_transition` matches the
    /// first guard in priority order that returns true. This proves that
    /// priority ordering resolves any overlap — only the highest-priority
    /// matching guard fires.
    #[test]
    fn prop_guard_disjointness_priority(
        s in arb_valid_state(),
        sigma in arb_any_input(),
    ) {
        let guards = guards_in_priority_order();

        // Find the first guard that matches (highest priority)
        let first_match = guards
            .iter()
            .find(|g| g.matches(&s, &sigma))
            .map(|g| g.class());

        let classified = classify_transition(&s, &sigma);

        // The classified result must equal the first matching guard's class
        prop_assert_eq!(
            first_match,
            Some(classified),
            "classify_transition must return the first matching guard's class in priority order"
        );
    }

    /// Property 4c (Consistency with vsel-core): For any arbitrary (state, input)
    /// pair, `classify_transition` (engine guard system) produces the same
    /// result as `vsel_core::transition::classify`. This ensures the engine's
    /// guard-based classification is semantically equivalent to the core
    /// classification logic.
    #[test]
    fn prop_guard_consistent_with_core(
        s in arb_valid_state(),
        sigma in arb_any_input(),
    ) {
        let engine_class = classify_transition(&s, &sigma);
        let core_class = classify(&s, &sigma);

        prop_assert_eq!(
            engine_class, core_class,
            "Engine guard classification must match core classify for all (s, σ) pairs"
        );
    }
}
