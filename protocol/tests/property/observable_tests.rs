//! Property-based tests for the VSEL Observable model.
//!
//! Uses `proptest` to verify correctness properties derived from
//! FORMAL_SPECIFICATION.md §3 (DEF-4), STATE_MACHINE.md §5,
//! SEMANTIC_MAPPING.md §5.
//!
//! Properties tested:
//! - Property 56: Observable Determinism (DEF-4) — `obs(s, σ, s')` is deterministic
//!   and derivable from state
//!   **Validates: Requirements 1.7**

use std::collections::BTreeMap;

use proptest::collection::btree_map;
use proptest::prelude::*;

use vsel_core::input::*;
use vsel_core::observable::*;
use vsel_core::state::*;
use vsel_core::transition::*;
use vsel_core::types::*;

// ---------------------------------------------------------------------------
// Arbitrary strategies (reused from transition_tests.rs patterns)
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
        prop::collection::vec(any::<u8>(), 1..64), // classical_sig (non-empty)
        prop::collection::vec(any::<u8>(), 1..64), // pqc_sig (non-empty)
        prop::collection::vec(any::<u8>(), 1..64), // classical pubkey (non-empty)
        prop::collection::vec(any::<u8>(), 1..64), // pqc pubkey (non-empty)
        any::<u64>(),                              // nonce
        arb_auth_domain_tag(),                     // domain
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

/// Generate a structurally valid Input (valid_input returns true).
fn arb_valid_input() -> impl Strategy<Value = Input> {
    (
        "[a-z]{1,20}",                              // payload_type (non-empty)
        prop::collection::vec(any::<u8>(), 1..128), // payload data (non-empty)
        arb_valid_authorization(),
        prop::collection::vec(any::<u8>(), 0..64), // aux data
    )
        .prop_map(|(payload_type, data, auth, aux_data)| Input {
            payload: Payload { payload_type, data },
            auth,
            aux: AuxiliaryData { data: aux_data },
        })
}

/// Generate a structurally invalid Input (valid_input returns false).
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
        ("[a-z]{1,20}", arb_valid_authorization(),).prop_map(|(payload_type, auth)| Input {
            payload: Payload {
                payload_type,
                data: vec![],
            },
            auth,
            aux: AuxiliaryData { data: vec![] },
        }),
    ]
}

/// Generate either a valid or invalid input.
fn arb_any_input() -> impl Strategy<Value = Input> {
    prop_oneof![arb_valid_input(), arb_invalid_input(),]
}

// ---------------------------------------------------------------------------
// Property 56: Observable Determinism (DEF-4)
// obs(s, σ, s') is deterministic and derivable from state.
// For any (s, σ), compute s' = apply(s, σ), then:
//   - obs(s, σ, s') called twice must produce identical results
//   - obs must return a valid TransitionStatus
//   - obs must return a TransitionClass matching classify(s, σ)
//   - gas_used is non-negative (always true for u64)
//   - For Reject/Error/Noop: outputs should be empty
//   - For Success: outputs should be derivable from state diff
// **Validates: Requirements 1.7**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property 56a: obs is deterministic — identical (s, σ, s') always produces
    /// identical Observable output.
    #[test]
    fn prop_obs_deterministic(
        s in arb_valid_state(),
        sigma in arb_any_input(),
    ) {
        let s_prime = apply(&s, &sigma);
        let o1 = obs(&s, &sigma, &s_prime);
        let o2 = obs(&s, &sigma, &s_prime);
        prop_assert_eq!(
            o1, o2,
            "obs must be deterministic: identical (s, σ, s') must produce identical Observable (DEF-4)"
        );
    }

    /// Property 56b: obs returns a TransitionClass that matches classify(s, σ).
    #[test]
    fn prop_obs_class_matches_classify(
        s in arb_valid_state(),
        sigma in arb_any_input(),
    ) {
        let s_prime = apply(&s, &sigma);
        let o = obs(&s, &sigma, &s_prime);
        let expected_class = classify(&s, &sigma);
        prop_assert_eq!(
            o.transition_class, expected_class,
            "obs.transition_class must match classify(s, σ)"
        );
    }

    /// Property 56c: obs returns a valid TransitionStatus consistent with the
    /// transition class.
    /// - Reject → Rejected
    /// - Error → Error
    /// - Noop → Rejected
    /// - Init/Batch/Update → Success
    #[test]
    fn prop_obs_status_consistent_with_class(
        s in arb_valid_state(),
        sigma in arb_any_input(),
    ) {
        let s_prime = apply(&s, &sigma);
        let o = obs(&s, &sigma, &s_prime);
        let expected_status = match o.transition_class {
            TransitionClass::Reject => TransitionStatus::Rejected,
            TransitionClass::Error => TransitionStatus::Error,
            TransitionClass::Noop => TransitionStatus::Rejected,
            TransitionClass::Init | TransitionClass::Batch | TransitionClass::Update => {
                TransitionStatus::Success
            }
        };
        prop_assert_eq!(
            o.status, expected_status,
            "obs.status must be consistent with transition_class: {:?} → {:?}",
            o.transition_class, expected_status
        );
    }

    /// Property 56d: For Reject/Error/Noop transitions, outputs must be empty.
    /// Only successful transitions (Init/Batch/Update) produce output events.
    #[test]
    fn prop_obs_non_success_empty_outputs(
        s in arb_valid_state(),
        sigma in arb_any_input(),
    ) {
        let s_prime = apply(&s, &sigma);
        let o = obs(&s, &sigma, &s_prime);
        if matches!(
            o.transition_class,
            TransitionClass::Reject | TransitionClass::Error | TransitionClass::Noop
        ) {
            prop_assert!(
                o.outputs.is_empty(),
                "Reject/Error/Noop transitions must produce empty outputs, got {} events for {:?}",
                o.outputs.len(),
                o.transition_class
            );
        }
    }

    /// Property 56e: For successful transitions (Init/Batch/Update), outputs are
    /// derivable from the state diff — every output event corresponds to a real
    /// change between s and s'.
    #[test]
    fn prop_obs_success_outputs_derivable_from_diff(
        s in arb_valid_state(),
        sigma in arb_any_input(),
    ) {
        let s_prime = apply(&s, &sigma);
        let o = obs(&s, &sigma, &s_prime);
        if matches!(
            o.transition_class,
            TransitionClass::Init | TransitionClass::Batch | TransitionClass::Update
        ) {
            for event in &o.outputs {
                match event.event_type.as_str() {
                    "balance_change" => {
                        // A balance_change event must correspond to an account whose
                        // balance actually changed between s and s'.
                        prop_assert!(
                            event.data.len() >= 48,
                            "balance_change event data must be at least 48 bytes (32 id + 16 balance)"
                        );
                        let mut id_bytes = [0u8; 32];
                        id_bytes.copy_from_slice(&event.data[..32]);
                        let account_id = AccountId(id_bytes);
                        let old_balance = s.canonical.accounts.get(&account_id).map(|a| a.balance);
                        let new_balance = s_prime.canonical.accounts.get(&account_id).map(|a| a.balance);
                        prop_assert_ne!(
                            old_balance, new_balance,
                            "balance_change event must correspond to an actual balance change for account {:?}",
                            account_id
                        );
                    }
                    "account_created" => {
                        // An account_created event must correspond to an account that
                        // exists in s' but not in s.
                        prop_assert!(
                            event.data.len() >= 48,
                            "account_created event data must be at least 48 bytes"
                        );
                        let mut id_bytes = [0u8; 32];
                        id_bytes.copy_from_slice(&event.data[..32]);
                        let account_id = AccountId(id_bytes);
                        prop_assert!(
                            !s.canonical.accounts.contains_key(&account_id),
                            "account_created event must be for an account not in pre-state"
                        );
                        prop_assert!(
                            s_prime.canonical.accounts.contains_key(&account_id),
                            "account_created event must be for an account present in post-state"
                        );
                    }
                    "param_change" => {
                        // A param_change event must correspond to a system parameter
                        // that actually changed between s and s'.
                        // The data format is: key_bytes + 0x00 separator + value_bytes
                        let separator_pos = event.data.iter().position(|&b| b == 0x00);
                        prop_assert!(
                            separator_pos.is_some(),
                            "param_change event must contain a 0x00 separator"
                        );
                        let sep = separator_pos.unwrap();
                        let key = std::str::from_utf8(&event.data[..sep]);
                        prop_assert!(
                            key.is_ok(),
                            "param_change key must be valid UTF-8"
                        );
                        let key = key.unwrap();
                        let new_val = &event.data[sep + 1..];
                        let old_val = s.canonical.system_data.parameters.get(key);
                        let changed = match old_val {
                            Some(ov) => ov.as_slice() != new_val,
                            None => true,
                        };
                        prop_assert!(
                            changed,
                            "param_change event must correspond to an actual parameter change for key '{}'",
                            key
                        );
                    }
                    other => {
                        // Unknown event types should not appear
                        prop_assert!(
                            false,
                            "unexpected output event type: '{}'",
                            other
                        );
                    }
                }
            }
        }
    }

    /// Property 56f: gas_used is always at least BASE_GAS (21_000) for any transition.
    /// Since gas_used is u64, it is inherently non-negative.
    #[test]
    fn prop_obs_gas_non_negative_and_bounded(
        s in arb_valid_state(),
        sigma in arb_any_input(),
    ) {
        let s_prime = apply(&s, &sigma);
        let o = obs(&s, &sigma, &s_prime);
        // gas_used is u64, so always >= 0. Verify it includes at least the base cost.
        prop_assert!(
            o.gas_used >= 21_000,
            "gas_used must be at least BASE_GAS (21_000), got {}",
            o.gas_used
        );
    }
}
