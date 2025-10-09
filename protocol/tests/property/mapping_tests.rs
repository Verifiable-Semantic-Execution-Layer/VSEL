//! Property-based tests for the VSEL Semantic Mapping functions.
//!
//! Uses `proptest` to verify correctness properties derived from
//! SEMANTIC_MAPPING.md, Requirement 4.1.
//!
//! Properties tested:
//! - Property 15: Semantic Mapping Totality and Determinism —
//!   μ_S, μ_Σ, μ_Tr, μ_O each produce exactly one formal artifact
//!   **Validates: Requirements 4.1**

use std::collections::BTreeMap;

use proptest::prelude::*;
use proptest::collection::btree_map;

use vsel_core::input::*;
use vsel_core::observable::*;
use vsel_core::state::*;
use vsel_core::transition::TransitionClass;
use vsel_core::types::*;
use vsel_mapping::mapping::*;
use vsel_trace::engine::{Trace, TraceEntry};

// ---------------------------------------------------------------------------
// Arbitrary strategies
// ---------------------------------------------------------------------------

/// Generate a random 32-byte array.
fn arb_bytes32() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

/// Generate a random Hash.
fn arb_hash() -> impl Strategy<Value = Hash> {
    arb_bytes32().prop_map(Hash)
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
        .prop_filter("domain tag must not be all zeros", |b| b.iter().any(|&x| x != 0))
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

/// Build a valid State from components by deriving D and Ω.
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

/// Generate a valid Authorization.
fn arb_authorization() -> impl Strategy<Value = Authorization> {
    (
        prop::collection::vec(any::<u8>(), 1..64),
        prop::collection::vec(any::<u8>(), 1..64),
        prop::collection::vec(any::<u8>(), 1..64),
        prop::collection::vec(any::<u8>(), 1..64),
        any::<u64>(),
        arb_domain_tag(),
    )
        .prop_map(|(classical_sig, pqc_sig, pk_classical, pk_pqc, nonce, domain)| {
            Authorization {
                classical_sig,
                pqc_sig,
                public_key: HybridPublicKey {
                    classical: pk_classical,
                    pqc: pk_pqc,
                },
                nonce,
                domain,
            }
        })
}

/// Generate a valid Input.
fn arb_input() -> impl Strategy<Value = Input> {
    (
        "[a-z]{1,16}",
        prop::collection::vec(any::<u8>(), 1..128),
        arb_authorization(),
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

/// Generate a random TransitionClass.
fn arb_transition_class() -> impl Strategy<Value = TransitionClass> {
    prop_oneof![
        Just(TransitionClass::Reject),
        Just(TransitionClass::Init),
        Just(TransitionClass::Error),
        Just(TransitionClass::Batch),
        Just(TransitionClass::Update),
        Just(TransitionClass::Noop),
    ]
}

/// Generate a random TransitionStatus.
fn arb_transition_status() -> impl Strategy<Value = TransitionStatus> {
    prop_oneof![
        Just(TransitionStatus::Success),
        Just(TransitionStatus::Rejected),
        Just(TransitionStatus::Error),
    ]
}

/// Generate a random OutputEvent.
fn arb_output_event() -> impl Strategy<Value = OutputEvent> {
    (
        "[a-z_]{1,20}",
        prop::collection::vec(any::<u8>(), 0..64),
    )
        .prop_map(|(event_type, data)| OutputEvent { event_type, data })
}

/// Generate a random Observable.
fn arb_observable() -> impl Strategy<Value = Observable> {
    (
        arb_transition_class(),
        prop::collection::vec(arb_output_event(), 0..5),
        0u64..=1_000_000u64,
        arb_transition_status(),
    )
        .prop_map(|(transition_class, outputs, gas_used, status)| Observable {
            transition_class,
            outputs,
            gas_used,
            status,
        })
}

/// Generate a random TraceEntry.
fn arb_trace_entry() -> impl Strategy<Value = TraceEntry> {
    (
        0u64..=1_000u64,
        arb_hash(),
        arb_input(),
        arb_hash(),
        arb_observable(),
        arb_environment(),
        arb_hash(),
    )
        .prop_map(
            |(index, pre_state_commitment, input, post_state_commitment, observable, environment, chain_hash)| {
                TraceEntry {
                    index,
                    pre_state_commitment,
                    input,
                    post_state_commitment,
                    observable,
                    environment,
                    chain_hash,
                }
            },
        )
}

/// Generate a random Trace with a valid initial state and arbitrary entries.
fn arb_trace() -> impl Strategy<Value = Trace> {
    (
        arb_valid_state(),
        prop::collection::vec(arb_trace_entry(), 0..5),
        arb_hash(),
    )
        .prop_map(|(initial_state, entries, commitment)| Trace {
            entries,
            initial_state,
            commitment,
        })
}

// ---------------------------------------------------------------------------
// Property 15: Semantic Mapping Totality and Determinism
// μ_S, μ_Σ, μ_Tr, μ_O each produce exactly one formal artifact
// **Validates: Requirements 4.1**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    // -- map_state totality and determinism --

    /// Property 15a: map_state is total — never panics for any valid State.
    /// Totality: the function completes without panic for all inputs.
    #[test]
    fn prop_map_state_total(s in arb_valid_state()) {
        // If this completes without panic, totality holds.
        let _formal = map_state(&s);
    }

    /// Property 15b: map_state is deterministic — same input produces same output.
    /// Determinism: f(x) == f(x) for all x.
    #[test]
    fn prop_map_state_deterministic(s in arb_valid_state()) {
        let f1 = map_state(&s);
        let f2 = map_state(&s);
        prop_assert_eq!(
            f1, f2,
            "map_state must be deterministic: same State must produce same FormalState"
        );
    }

    // -- map_input totality and determinism --

    /// Property 15c: map_input is total — never panics for any valid Input.
    #[test]
    fn prop_map_input_total(input in arb_input()) {
        let _formal = map_input(&input);
    }

    /// Property 15d: map_input is deterministic — same input produces same output.
    #[test]
    fn prop_map_input_deterministic(input in arb_input()) {
        let f1 = map_input(&input);
        let f2 = map_input(&input);
        prop_assert_eq!(
            f1, f2,
            "map_input must be deterministic: same Input must produce same FormalInput"
        );
    }

    // -- map_observable totality and determinism --

    /// Property 15e: map_observable is total — never panics for any Observable.
    #[test]
    fn prop_map_observable_total(obs in arb_observable()) {
        let _formal = map_observable(&obs);
    }

    /// Property 15f: map_observable is deterministic — same input produces same output.
    #[test]
    fn prop_map_observable_deterministic(obs in arb_observable()) {
        let f1 = map_observable(&obs);
        let f2 = map_observable(&obs);
        prop_assert_eq!(
            f1, f2,
            "map_observable must be deterministic: same Observable must produce same FormalObservable"
        );
    }

    // -- map_trace totality and determinism --

    /// Property 15g: map_trace is total — never panics for any Trace.
    #[test]
    fn prop_map_trace_total(trace in arb_trace()) {
        let _formal = map_trace(&trace);
    }

    /// Property 15h: map_trace is deterministic — same input produces same output.
    #[test]
    fn prop_map_trace_deterministic(trace in arb_trace()) {
        let f1 = map_trace(&trace);
        let f2 = map_trace(&trace);
        prop_assert_eq!(
            f1, f2,
            "map_trace must be deterministic: same Trace must produce same FormalTrace"
        );
    }
}

// ---------------------------------------------------------------------------
// Property 18: Canonicalization Idempotence (DEF-5)
// canonical(canonical(σ)) = canonical(σ)
// **Validates: Requirements 4.4**
// ---------------------------------------------------------------------------

use vsel_mapping::canonicalization::{canonicalize_input, canonicalize_state};
use vsel_core::state::derive;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    // -- 18a: Input canonicalization idempotence --

    /// Property 18a: For any valid input σ, canonicalize_input(canonicalize_input(σ)) = canonicalize_input(σ).
    /// Applying canonicalization twice gives the same result as once (DEF-5).
    #[test]
    fn prop_input_canonicalization_idempotent(input in arb_input()) {
        let once = canonicalize_input(&input);
        if let Ok(canonical_once) = once {
            let twice = canonicalize_input(&canonical_once);
            prop_assert!(
                twice.is_ok(),
                "If canonicalization succeeds once, it must succeed again on the canonical form"
            );
            let canonical_twice = twice.unwrap();
            prop_assert_eq!(
                canonical_once, canonical_twice,
                "DEF-5: canonical(canonical(σ)) must equal canonical(σ)"
            );
        }
        // If first canonicalization fails (malformed input), idempotence is vacuously satisfied.
    }

    // -- 18b: State canonicalization idempotence --

    /// Property 18b: For any valid state s, canonicalize_state(canonicalize_state(s)) = canonicalize_state(s).
    /// Applying state canonicalization twice gives the same result as once (DEF-5).
    #[test]
    fn prop_state_canonicalization_idempotent(state in arb_valid_state()) {
        let once = canonicalize_state(&state);
        if let Ok(canonical_once) = once {
            let twice = canonicalize_state(&canonical_once);
            prop_assert!(
                twice.is_ok(),
                "If state canonicalization succeeds once, it must succeed again on the canonical form"
            );
            let canonical_twice = twice.unwrap();
            prop_assert_eq!(
                canonical_once, canonical_twice,
                "DEF-5: canonicalize_state(canonicalize_state(s)) must equal canonicalize_state(s)"
            );
        }
    }

    // -- 18c: Input canonicalization clears aux data (THM-4) --

    /// Property 18c: For any valid input, the canonicalized form has empty auxiliary data.
    /// THM-4: auxiliary data must not influence semantics, so canonicalization clears it.
    #[test]
    fn prop_input_canonicalization_clears_aux(input in arb_input()) {
        if let Ok(canonical) = canonicalize_input(&input) {
            prop_assert!(
                canonical.aux.data.is_empty(),
                "THM-4: canonicalized input must have empty aux data, got {} bytes",
                canonical.aux.data.len()
            );
        }
    }

    // -- 18d: Input canonicalization normalizes payload_type --

    /// Property 18d: The canonicalized payload_type is lowercase and trimmed.
    /// Canonicalization normalizes payload_type by trimming whitespace and lowercasing.
    #[test]
    fn prop_input_canonicalization_normalizes_payload_type(input in arb_input()) {
        if let Ok(canonical) = canonicalize_input(&input) {
            let pt = &canonical.payload.payload_type;
            prop_assert_eq!(
                pt, &pt.trim().to_lowercase(),
                "Canonicalized payload_type must be lowercase and trimmed, got {:?}",
                pt
            );
        }
    }

    // -- 18e: State canonicalization recomputes derived state --

    /// Property 18e: The canonicalized state has D = derive(C).
    /// Canonicalization recomputes derived state from canonical state.
    #[test]
    fn prop_state_canonicalization_recomputes_derived(state in arb_valid_state()) {
        if let Ok(canonical) = canonicalize_state(&state) {
            let expected_derived = derive(&canonical.canonical);
            prop_assert_eq!(
                canonical.derived, expected_derived,
                "Canonicalized state must have D = derive(C)"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Property 16: Execution-Mapping Commutativity (THM-1)
// μ_S(apply_c(s, σ)) = apply_f(μ_S(s), μ_Σ(σ))
// **Validates: Requirements 4.2, 13.9**
// ---------------------------------------------------------------------------
// Property 17: Observable Commutativity (THM-2)
// μ_O(obs_c) = obs_f(μ_S, μ_Σ, μ_S)
// **Validates: Requirements 4.3**
// ---------------------------------------------------------------------------
// Property 19: Auxiliary Data Exclusion (THM-4)
// apply(s, (p, a, aux₁)) = apply(s, (p, a, aux₂))
// **Validates: Requirements 4.5**
// ---------------------------------------------------------------------------
// Property 20: Derived State Commutativity (THM-5)
// μ_D(derive_c(C_c)) = derive_f(μ_C(C_c))
// **Validates: Requirements 4.6**
// ---------------------------------------------------------------------------
// Property 21: Trace Mapping Preserves Validity (THM-6)
// valid_trace_f(μ_Tr(τ_c))
// **Validates: Requirements 4.7**
// ---------------------------------------------------------------------------
// Property 22: Error and No-op Commutativity (THM-14, THM-15)
// error/no-op transitions commute through mapping
// **Validates: Requirements 4.8**
// ---------------------------------------------------------------------------

/// Generate an input that classifies as Noop: unrecognized payload type.
/// Uses a payload type that is NOT in the recognized set (transfer, init, batch, deposit, withdraw, update).
fn arb_noop_input() -> impl Strategy<Value = Input> {
    (
        // Payload types that are NOT recognized — will classify as Noop
        prop_oneof![
            Just("unknown_op".to_string()),
            Just("foo".to_string()),
            Just("noop_action".to_string()),
            Just("query".to_string()),
        ],
        prop::collection::vec(any::<u8>(), 1..64),
        arb_authorization(),
        prop::collection::vec(any::<u8>(), 0..32),
    )
        .prop_map(|(payload_type, data, auth, aux_data)| Input {
            payload: Payload { payload_type, data },
            auth,
            aux: AuxiliaryData { data: aux_data },
        })
}

/// Generate a (state, input) pair where the input classifies as Error.
/// Error = valid input but precondition failure (transfer with non-existent sender).
fn arb_error_state_and_input() -> impl Strategy<Value = (State, Input)> {
    (
        arb_canonical_state(),
        arb_environment(),
        arb_authorization(),
        prop::collection::vec(any::<u8>(), 0..32),
    )
        .prop_map(|(canonical, environment, auth, aux_data)| {
            // Build a valid state at seq > 0 (non-genesis)
            let derived = derive(&canonical);
            let economic = derive_economic(&canonical, &environment);
            let metadata = TraceMetadata {
                sequence_index: 1,
                previous_commitment: Hash([0xABu8; 32]),
                epoch: 0,
                timestamp: 1_000_000,
            };
            let state = State {
                canonical,
                derived,
                environment,
                economic,
                metadata,
            };

            // Build a transfer input with a sender that does NOT exist in state.
            // Use a fixed sender ID that is extremely unlikely to be in the random state.
            let sender_id = [0xFFu8; 32];
            let input = Input {
                payload: Payload {
                    payload_type: "transfer".to_string(),
                    data: sender_id.to_vec(),
                },
                auth,
                aux: AuxiliaryData { data: aux_data },
            };

            (state, input)
        })
        .prop_filter(
            "input must classify as Error",
            |(state, input)| {
                use vsel_core::transition::classify;
                classify(state, input) == TransitionClass::Error
            },
        )
}

/// Build a well-formed trace by actually executing transitions from an initial state.
fn arb_executed_trace() -> impl Strategy<Value = Trace> {
    (arb_valid_state(), prop::collection::vec(arb_input(), 0..4))
        .prop_map(|(initial_state, inputs)| {
            use vsel_core::observable::obs;
            use vsel_core::state::commit;
            use vsel_core::transition::apply;
            use vsel_trace::commitment::compute_chain_hash;
            use vsel_trace::engine::commit_entry;

            let mut entries = Vec::new();
            let mut current_state = initial_state.clone();
            let mut chain_hash = Hash([0u8; 32]);

            for (i, input) in inputs.iter().enumerate() {
                let post = apply(&current_state, input);
                let observable = obs(&current_state, input, &post);
                let pre_commit = commit(&current_state.canonical);
                let post_commit = commit(&post.canonical);
                let entry_commit = commit_entry(
                    i as u64,
                    &pre_commit,
                    input,
                    &post_commit,
                    &observable,
                    &post.environment,
                );
                chain_hash = compute_chain_hash(&chain_hash, &entry_commit);

                entries.push(TraceEntry {
                    index: i as u64,
                    pre_state_commitment: pre_commit,
                    input: input.clone(),
                    post_state_commitment: post_commit,
                    observable,
                    environment: post.environment.clone(),
                    chain_hash: chain_hash.clone(),
                });

                current_state = post;
            }

            Trace {
                entries,
                initial_state,
                commitment: chain_hash,
            }
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    // -- Property 16: Execution-Mapping Commutativity (THM-1) --

    /// Property 16: For any valid state s and input σ, execution-mapping commutativity holds:
    /// μ_S(apply_c(s, σ)) is consistent with the formal transition (μ_S(s), μ_Σ(σ), μ_S(s')).
    /// **Validates: Requirements 4.2, 13.9**
    #[test]
    fn prop_execution_mapping_commutativity(s in arb_valid_state(), sigma in arb_input()) {
        prop_assert!(
            verify_execution_commutativity(&s, &sigma),
            "THM-1: execution-mapping commutativity must hold for all (s, σ)"
        );
    }

    // -- Property 17: Observable Commutativity (THM-2) --

    /// Property 17: For any valid state s and input σ, observable commutativity holds:
    /// μ_O(obs_c(s, σ, s')) is consistent with obs_f(μ_S(s), μ_Σ(σ), μ_S(s')).
    /// **Validates: Requirements 4.3**
    #[test]
    fn prop_observable_commutativity(s in arb_valid_state(), sigma in arb_input()) {
        prop_assert!(
            verify_observable_commutativity(&s, &sigma),
            "THM-2: observable commutativity must hold for all (s, σ)"
        );
    }

    // -- Property 19: Auxiliary Data Exclusion (THM-4) --

    /// Property 19: For any valid state s and input σ, changing auxiliary data does not
    /// change the Apply result: apply(s, (p, a, aux₁)) = apply(s, (p, a, aux₂)).
    /// **Validates: Requirements 4.5**
    #[test]
    fn prop_auxiliary_data_exclusion(s in arb_valid_state(), sigma in arb_input()) {
        prop_assert!(
            verify_auxiliary_exclusion(&s, &sigma),
            "THM-4: auxiliary data must not influence semantic outcome"
        );
    }

    // -- Property 20: Derived State Commutativity (THM-5) --

    /// Property 20: For any canonical state C, derived state commutativity holds:
    /// μ_D(derive_c(C_c)) = derive_f(μ_C(C_c)).
    /// **Validates: Requirements 4.6**
    #[test]
    fn prop_derived_state_commutativity(canonical in arb_canonical_state()) {
        prop_assert!(
            verify_derived_commutativity(&canonical),
            "THM-5: derived state commutativity must hold for all canonical states"
        );
    }

    // -- Property 21: Trace Mapping Preserves Validity (THM-6) --

    /// Property 21: For any well-formed trace τ, the mapped formal trace is valid:
    /// valid_trace_f(μ_Tr(τ_c)).
    /// **Validates: Requirements 4.7**
    #[test]
    fn prop_trace_mapping_preserves_validity(trace in arb_executed_trace()) {
        prop_assert!(
            verify_trace_mapping_validity(&trace),
            "THM-6: trace mapping must preserve validity for all well-formed traces"
        );
    }

    // -- Property 22: Error and No-op Commutativity (THM-14, THM-15) --

    /// Property 22a: Error transitions commute through the mapping (THM-14).
    /// **Validates: Requirements 4.8**
    #[test]
    fn prop_error_commutativity((s, sigma) in arb_error_state_and_input()) {
        prop_assert!(
            verify_error_commutativity(&s, &sigma),
            "THM-14: error transitions must commute through the mapping"
        );
    }

    /// Property 22b: No-op transitions commute through the mapping (THM-15).
    /// Uses a non-genesis state with an unrecognized payload type to trigger Noop classification.
    /// **Validates: Requirements 4.8**
    #[test]
    fn prop_noop_commutativity(
        canonical in arb_canonical_state(),
        env in arb_environment(),
        sigma in arb_noop_input(),
    ) {
        // Build a non-genesis state (seq > 0) so "init" doesn't match
        let derived = derive(&canonical);
        let economic = derive_economic(&canonical, &env);
        let s = State {
            canonical,
            derived,
            environment: env,
            economic,
            metadata: TraceMetadata {
                sequence_index: 1,
                previous_commitment: Hash([0xABu8; 32]),
                epoch: 0,
                timestamp: 1_000_000,
            },
        };
        prop_assert!(
            verify_noop_commutativity(&s, &sigma),
            "THM-15: no-op transitions must commute through the mapping"
        );
    }
}
