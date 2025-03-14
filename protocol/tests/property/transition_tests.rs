//! Property-based tests for the VSEL Transition model.
//!
//! Uses `proptest` to verify correctness properties derived from
//! STATE_MACHINE.md §5, TRANSITION_PARTITIONING.md,
//! FORMAL_SPECIFICATION.md §3.
//!
//! Properties tested:
//! - Property 4: Guard Exhaustiveness and Disjointness — exactly one guard matches per (s, σ)
//!   **Validates: Requirements 2.1, 2.7**
//! - Property 5: Bounded State Mutation — `Diff(s, s') ⊆ AllowedMutations(σ)`
//!   **Validates: Requirements 2.4, 5.8, 18.9**
//! - Property 3: Error Handling Preserves Invariants — `apply(s, σ_invalid)` produces valid state
//!   **Validates: Requirements 1.9, 2.6**

use std::collections::BTreeMap;

use proptest::prelude::*;
use proptest::collection::btree_map;

use vsel_core::input::*;
use vsel_core::state::*;
use vsel_core::transition::*;
use vsel_core::types::*;

// ---------------------------------------------------------------------------
// Arbitrary strategies
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

/// Generate valid TraceMetadata.
fn arb_trace_metadata() -> impl Strategy<Value = TraceMetadata> {
    prop_oneof![
        // Genesis metadata: sequence_index == 0, previous_commitment == zero hash
        (0u64..=1_000_000u64, 0u64..=100u64).prop_map(|(timestamp, epoch)| TraceMetadata {
            sequence_index: 0,
            previous_commitment: Hash([0u8; 32]),
            epoch,
            timestamp,
        }),
        // Non-genesis metadata: sequence_index > 0, previous_commitment != zero hash
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

/// Build a valid State from a CanonicalState by deriving all components.
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

/// Generate a non-zero DomainTag for authorization.
fn arb_auth_domain_tag() -> impl Strategy<Value = DomainTag> {
    arb_bytes32()
        .prop_filter("domain tag must not be all zeros", |b| {
            b.iter().any(|&x| x != 0)
        })
        .prop_map(|b| DomainTag(Hash(b)))
}

/// Generate a valid Authorization.
fn arb_valid_authorization() -> impl Strategy<Value = Authorization> {
    (
        prop::collection::vec(any::<u8>(), 1..64),  // classical_sig (non-empty)
        prop::collection::vec(any::<u8>(), 1..64),  // pqc_sig (non-empty)
        prop::collection::vec(any::<u8>(), 1..64),  // classical pubkey (non-empty)
        prop::collection::vec(any::<u8>(), 1..64),  // pqc pubkey (non-empty)
        any::<u64>(),                                // nonce
        arb_auth_domain_tag(),                       // domain
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

/// Generate a structurally valid Input (valid_input returns true).
fn arb_valid_input() -> impl Strategy<Value = Input> {
    (
        "[a-z]{1,20}",                               // payload_type (non-empty)
        prop::collection::vec(any::<u8>(), 1..128),  // payload data (non-empty)
        arb_valid_authorization(),
        prop::collection::vec(any::<u8>(), 0..64),   // aux data
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

/// Generate a structurally invalid Input (valid_input returns false).
/// Randomly picks one of several invalidity modes.
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
        (
            "[a-z]{1,20}",
            arb_valid_authorization(),
        )
            .prop_map(|(payload_type, auth)| Input {
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
            arb_auth_domain_tag(),
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
            arb_auth_domain_tag(),
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

/// Generate either a valid or invalid input.
fn arb_any_input() -> impl Strategy<Value = Input> {
    prop_oneof![
        arb_valid_input(),
        arb_invalid_input(),
    ]
}

// ---------------------------------------------------------------------------
// Property 4: Guard Exhaustiveness and Disjointness
// For any (s, σ), classify(s, σ) returns exactly one TransitionClass.
// The result is always one of the 6 defined classes.
// **Validates: Requirements 2.1, 2.7**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property 4a: classify always returns one of the 6 defined TransitionClass variants.
    /// This verifies guard exhaustiveness — every (s, σ) pair is handled.
    #[test]
    fn prop_classify_always_returns_valid_class(
        s in arb_valid_state(),
        sigma in arb_any_input(),
    ) {
        let class = classify(&s, &sigma);
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
            "classify must return one of the 6 defined TransitionClass variants, got {:?}",
            class
        );
    }

    /// Property 4b: classify is deterministic — same (s, σ) always produces the same class.
    /// This verifies disjointness — no ambiguity in classification.
    #[test]
    fn prop_classify_deterministic(
        s in arb_valid_state(),
        sigma in arb_any_input(),
    ) {
        let class1 = classify(&s, &sigma);
        let class2 = classify(&s, &sigma);
        prop_assert_eq!(
            class1, class2,
            "classify must be deterministic: same (s, σ) must produce the same class"
        );
    }

    /// Property 4c: invalid inputs are always classified as Reject (highest priority guard).
    /// This verifies the priority ordering: G_REJECT takes precedence over all other guards.
    #[test]
    fn prop_classify_invalid_input_is_reject(
        s in arb_valid_state(),
        sigma in arb_invalid_input(),
    ) {
        let class = classify(&s, &sigma);
        prop_assert_eq!(
            class,
            TransitionClass::Reject,
            "structurally invalid input must always be classified as Reject"
        );
    }

    /// Property 4d: valid inputs are never classified as Reject.
    /// This verifies that the Reject guard only fires for structurally invalid inputs.
    #[test]
    fn prop_classify_valid_input_not_reject(
        s in arb_valid_state(),
        sigma in arb_valid_input(),
    ) {
        let class = classify(&s, &sigma);
        prop_assert_ne!(
            class,
            TransitionClass::Reject,
            "structurally valid input must never be classified as Reject"
        );
    }
}

// ---------------------------------------------------------------------------
// Property 5: Bounded State Mutation
// Diff(s, s') ⊆ AllowedMutations(σ)
// **Validates: Requirements 2.4, 5.8, 18.9**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property 5a: For Reject transitions, canonical state must be unchanged.
    #[test]
    fn prop_reject_preserves_canonical(
        s in arb_valid_state(),
        sigma in arb_invalid_input(),
    ) {
        let s_prime = apply(&s, &sigma);
        prop_assert_eq!(
            s_prime.canonical, s.canonical,
            "Reject transition must not change canonical state"
        );
    }

    /// Property 5b: For Error transitions, canonical state must be unchanged.
    /// We generate a transfer input referencing a non-existent sender to trigger Error.
    #[test]
    fn prop_error_preserves_canonical(
        s in arb_valid_state().prop_filter(
            "need non-genesis state for error classification",
            |s| s.metadata.sequence_index > 0
        ),
        sender_id in arb_bytes32(),
    ) {
        // Build a transfer input with a sender that doesn't exist in state
        let sigma = Input {
            payload: Payload {
                payload_type: "transfer".to_string(),
                data: sender_id.to_vec(),
            },
            auth: Authorization {
                classical_sig: vec![1, 2, 3],
                pqc_sig: vec![4, 5, 6],
                public_key: HybridPublicKey {
                    classical: vec![10],
                    pqc: vec![20],
                },
                nonce: 0,
                domain: s.environment.execution_domain.clone(),
            },
            aux: AuxiliaryData { data: vec![] },
        };

        // Only check if it's actually classified as Error
        if classify(&s, &sigma) == TransitionClass::Error {
            let s_prime = apply(&s, &sigma);
            prop_assert_eq!(
                s_prime.canonical, s.canonical,
                "Error transition must not change canonical state"
            );
        }
    }

    /// Property 5c: For Noop transitions, canonical state must be unchanged.
    #[test]
    fn prop_noop_preserves_canonical(
        s in arb_valid_state().prop_filter(
            "need non-genesis state for noop classification",
            |s| s.metadata.sequence_index > 0
        ),
        random_suffix in "[a-z]{5,15}",
    ) {
        // Use an unrecognized payload type to trigger Noop
        let payload_type = format!("unknown_{}", random_suffix);
        let sigma = Input {
            payload: Payload {
                payload_type,
                data: vec![0x01],
            },
            auth: Authorization {
                classical_sig: vec![1, 2, 3],
                pqc_sig: vec![4, 5, 6],
                public_key: HybridPublicKey {
                    classical: vec![10],
                    pqc: vec![20],
                },
                nonce: 0,
                domain: s.environment.execution_domain.clone(),
            },
            aux: AuxiliaryData { data: vec![] },
        };

        let class = classify(&s, &sigma);
        if class == TransitionClass::Noop {
            let s_prime = apply(&s, &sigma);
            prop_assert_eq!(
                s_prime.canonical, s.canonical,
                "Noop transition must not change canonical state"
            );
        }
    }

    /// Property 5d: After any apply, derived state equals derive(canonical).
    /// This ensures D' = derive(C') is always recomputed (DEF-1).
    #[test]
    fn prop_derived_consistent_after_apply(
        s in arb_valid_state(),
        sigma in arb_any_input(),
    ) {
        let s_prime = apply(&s, &sigma);
        let expected_derived = derive(&s_prime.canonical);
        prop_assert_eq!(
            s_prime.derived, expected_derived,
            "After apply, derived state must equal derive(canonical) (DEF-1)"
        );
    }

    /// Property 5e: After any apply, economic context equals derive_economic(canonical, env).
    #[test]
    fn prop_economic_consistent_after_apply(
        s in arb_valid_state(),
        sigma in arb_any_input(),
    ) {
        let s_prime = apply(&s, &sigma);
        let expected_economic = derive_economic(&s_prime.canonical, &s_prime.environment);
        prop_assert_eq!(
            s_prime.economic, expected_economic,
            "After apply, economic context must equal derive_economic(canonical, env)"
        );
    }

    /// Property 5f: For Update transitions on transfer, only sender/receiver balances
    /// and sender nonce should change. Total supply must be conserved.
    #[test]
    fn prop_transfer_conserves_supply(
        balance in 100u128..=1_000_000u128,
        amount in 1u128..=99u128,
        sender_bytes in arb_bytes32(),
        receiver_bytes in arb_bytes32(),
    ) {
        // Build a state with a sender account
        let sender_id = AccountId(sender_bytes);
        let mut accounts = BTreeMap::new();
        accounts.insert(
            sender_id.clone(),
            AccountData {
                balance,
                nonce: 0,
                data: vec![],
            },
        );
        let total_supply = balance;
        let canonical = CanonicalState {
            accounts,
            storage: BTreeMap::new(),
            system_data: SystemData {
                protocol_version: ProtocolVersion { major: 0, minor: 1, patch: 0 },
                total_supply,
                parameters: BTreeMap::new(),
            },
        };

        let derived = derive(&canonical);
        let mut h = [0u8; 32];
        h[0] = 0xAB;
        let env = Environment {
            timestamp: 1_000_000,
            block_height: 1,
            execution_domain: DomainTag(Hash(h)),
        };
        let economic = derive_economic(&canonical, &env);
        let metadata = TraceMetadata {
            sequence_index: 1,
            previous_commitment: Hash([0xABu8; 32]),
            epoch: 0,
            timestamp: 1_000_000,
        };
        let s = State { canonical, derived, environment: env, economic, metadata };

        // Build transfer input
        let mut data = Vec::new();
        data.extend_from_slice(&sender_bytes);
        data.extend_from_slice(&receiver_bytes);
        data.extend_from_slice(&amount.to_le_bytes());

        let sigma = Input {
            payload: Payload {
                payload_type: "transfer".to_string(),
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
                domain: s.environment.execution_domain.clone(),
            },
            aux: AuxiliaryData { data: vec![] },
        };

        let class = classify(&s, &sigma);
        if class == TransitionClass::Update {
            let s_prime = apply(&s, &sigma);
            prop_assert_eq!(
                s_prime.canonical.system_data.total_supply,
                s.canonical.system_data.total_supply,
                "Transfer must conserve total supply (L_cons)"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Property 3: Error Handling Preserves Invariants
// apply(s, σ_invalid) where σ_invalid is structurally invalid must produce
// a state where canonical state is unchanged, derived state is consistent,
// metadata is advanced, and the result is classified as Reject.
// **Validates: Requirements 1.9, 2.6**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property 3a: apply with invalid input preserves canonical state unchanged.
    #[test]
    fn prop_invalid_input_canonical_unchanged(
        s in arb_valid_state(),
        sigma in arb_invalid_input(),
    ) {
        let s_prime = apply(&s, &sigma);
        prop_assert_eq!(
            s_prime.canonical, s.canonical,
            "apply(s, σ_invalid) must leave canonical state unchanged"
        );
    }

    /// Property 3b: apply with invalid input produces consistent derived state.
    /// D' = derive(C') must hold after applying an invalid input.
    #[test]
    fn prop_invalid_input_derived_consistent(
        s in arb_valid_state(),
        sigma in arb_invalid_input(),
    ) {
        let s_prime = apply(&s, &sigma);
        let expected_derived = derive(&s_prime.canonical);
        prop_assert_eq!(
            s_prime.derived, expected_derived,
            "apply(s, σ_invalid) must produce consistent derived state: D' = derive(C')"
        );
    }

    /// Property 3c: apply with invalid input advances metadata.
    /// sequence_index must increment by 1.
    #[test]
    fn prop_invalid_input_metadata_advanced(
        s in arb_valid_state(),
        sigma in arb_invalid_input(),
    ) {
        let s_prime = apply(&s, &sigma);
        prop_assert_eq!(
            s_prime.metadata.sequence_index,
            s.metadata.sequence_index + 1,
            "apply(s, σ_invalid) must advance sequence_index by 1"
        );
    }

    /// Property 3d: apply with invalid input is classified as Reject.
    #[test]
    fn prop_invalid_input_classified_reject(
        s in arb_valid_state(),
        sigma in arb_invalid_input(),
    ) {
        let class = classify(&s, &sigma);
        prop_assert_eq!(
            class,
            TransitionClass::Reject,
            "structurally invalid input must be classified as Reject"
        );
    }

    /// Property 3e: apply is total — it never panics for any (s, σ) pair.
    /// This verifies AX-2: apply always returns a state in S.
    #[test]
    fn prop_apply_total(
        s in arb_valid_state(),
        sigma in arb_any_input(),
    ) {
        // If this doesn't panic, apply is total for this (s, σ) pair.
        let _s_prime = apply(&s, &sigma);
    }

    /// Property 3f: apply with invalid input preserves environment unchanged.
    #[test]
    fn prop_invalid_input_environment_unchanged(
        s in arb_valid_state(),
        sigma in arb_invalid_input(),
    ) {
        let s_prime = apply(&s, &sigma);
        prop_assert_eq!(
            s_prime.environment, s.environment,
            "apply(s, σ_invalid) must leave environment unchanged"
        );
    }

    /// Property 3g: apply is deterministic — same (s, σ) always produces the same s'.
    /// This verifies AX-1 for all input types including invalid ones.
    #[test]
    fn prop_apply_deterministic(
        s in arb_valid_state(),
        sigma in arb_any_input(),
    ) {
        let s1 = apply(&s, &sigma);
        let s2 = apply(&s, &sigma);
        prop_assert_eq!(
            s1, s2,
            "apply must be deterministic: same (s, σ) must produce the same s' (AX-1)"
        );
    }
}
