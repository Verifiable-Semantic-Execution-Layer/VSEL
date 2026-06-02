//! Property-based tests for the VSEL Invariant system.
//!
//! Uses `proptest` to verify correctness properties derived from
//! INVARIANTS.md, ECONOMIC_INVARIANTS.md, FORMAL_SPECIFICATION.md §3.
//!
//! Properties tested:
//! - Property 10: Local Invariant Preservation — all local invariants hold on every transition
//!   **Validates: Requirements 3.1**
//! - Property 11: Global Invariant Preservation — all global invariants hold on every reachable state
//!   **Validates: Requirements 3.2**
//! - Property 13: Economic Invariant Enforcement — structurally valid but economically inadmissible states rejected
//!   **Validates: Requirements 3.4, 3.5**

use std::collections::BTreeMap;

use proptest::collection::btree_map;
use proptest::prelude::*;

use vsel_core::input::*;
use vsel_core::state::*;
use vsel_core::transition::*;
use vsel_core::types::*;

use vsel_invariants::admissible;
use vsel_invariants::economic::{check_all_economic, economically_valid};
use vsel_invariants::global::check_all_global;
use vsel_invariants::local::check_all_local;

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

/// Generate a CanonicalState that satisfies economic invariants:
/// - No single account holds >90% of total supply (G_concentration)
/// - total_supply > 0 requires at least 2 accounts with balanced distribution
/// Uses multiple accounts with equal balances to avoid concentration.
fn arb_economically_valid_canonical() -> impl Strategy<Value = CanonicalState> {
    prop_oneof![
        // Empty state — trivially economically valid
        (
            btree_map(arb_storage_key(), arb_storage_value(), 0..3),
            arb_protocol_version(),
        )
            .prop_map(|(storage, protocol_version)| {
                CanonicalState {
                    accounts: BTreeMap::new(),
                    storage,
                    system_data: SystemData {
                        protocol_version,
                        total_supply: 0,
                        parameters: BTreeMap::new(),
                    },
                }
            }),
        // Multiple accounts with equal balances — no concentration violation
        (
            prop::collection::vec(arb_account_id(), 2..=5),
            1u128..=100_000u128,
            btree_map(arb_storage_key(), arb_storage_value(), 0..3),
            arb_protocol_version(),
        )
            .prop_map(|(ids, per_account_balance, storage, protocol_version)| {
                let mut accounts = BTreeMap::new();
                for id in &ids {
                    accounts.insert(
                        id.clone(),
                        AccountData {
                            balance: per_account_balance,
                            nonce: 0,
                            data: vec![],
                        },
                    );
                }
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
            }),
    ]
}

/// Build a valid State that also satisfies economic invariants.
fn arb_economically_valid_state() -> impl Strategy<Value = State> {
    (
        arb_economically_valid_canonical(),
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
        prop::collection::vec(any::<u8>(), 1..64),
        prop::collection::vec(any::<u8>(), 1..64),
        prop::collection::vec(any::<u8>(), 1..64),
        prop::collection::vec(any::<u8>(), 1..64),
        any::<u64>(),
        arb_auth_domain_tag(),
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

/// Generate a structurally invalid Input.
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
// Property 10: Local Invariant Preservation
// All local invariants hold on every transition: L_valid, L_state, L_cons,
// L_bounded, L_det.
// **Validates: Requirements 3.1**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property 10a: All local invariants hold when applying any input to a valid state.
    /// check_all_local(pre, input, post) must pass when post = apply(pre, input).
    #[test]
    fn prop_local_invariants_hold_on_any_transition(
        pre in arb_valid_state(),
        sigma in arb_any_input(),
    ) {
        let post = apply(&pre, &sigma);
        let result = check_all_local(&pre, &sigma, &post);
        prop_assert!(
            result.valid,
            "Local invariants violated on transition: {:?}",
            result.violations.iter().map(|v| &v.invariant_id).collect::<Vec<_>>()
        );
    }

    /// Property 10b: Local invariants hold for valid inputs specifically.
    /// This ensures L_valid, L_state, L_cons, L_bounded, L_det all pass
    /// for structurally valid inputs.
    #[test]
    fn prop_local_invariants_hold_on_valid_input(
        pre in arb_valid_state(),
        sigma in arb_valid_input(),
    ) {
        let post = apply(&pre, &sigma);
        let result = check_all_local(&pre, &sigma, &post);
        prop_assert!(
            result.valid,
            "Local invariants violated on valid input transition: {:?}",
            result.violations.iter().map(|v| format!("{}: {}", v.invariant_id, v.description)).collect::<Vec<_>>()
        );
    }

    /// Property 10c: Local invariants hold for invalid (rejected) inputs.
    /// Even rejected transitions must preserve all local invariants.
    #[test]
    fn prop_local_invariants_hold_on_rejected_input(
        pre in arb_valid_state(),
        sigma in arb_invalid_input(),
    ) {
        let post = apply(&pre, &sigma);
        let result = check_all_local(&pre, &sigma, &post);
        prop_assert!(
            result.valid,
            "Local invariants violated on rejected input: {:?}",
            result.violations.iter().map(|v| format!("{}: {}", v.invariant_id, v.description)).collect::<Vec<_>>()
        );
    }
}

// ---------------------------------------------------------------------------
// Property 11: Global Invariant Preservation
// All global invariants hold on every reachable state: G_valid, G_struct,
// G_commit, G_mono, G_env.
// **Validates: Requirements 3.2**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property 11a: Global invariants hold on every valid state.
    /// check_all_global(state) must pass for any properly constructed state.
    #[test]
    fn prop_global_invariants_hold_on_valid_state(
        state in arb_valid_state(),
    ) {
        let result = check_all_global(&state);
        prop_assert!(
            result.valid,
            "Global invariants violated on valid state: {:?}",
            result.violations.iter().map(|v| format!("{}: {}", v.invariant_id, v.description)).collect::<Vec<_>>()
        );
    }

    /// Property 11b: Global invariants hold on post-state after any transition.
    /// Applying any input to a valid state must produce a state where
    /// all global invariants still hold (LEM-1 preservation).
    #[test]
    fn prop_global_invariants_preserved_after_transition(
        pre in arb_valid_state(),
        sigma in arb_any_input(),
    ) {
        let post = apply(&pre, &sigma);
        let result = check_all_global(&post);
        prop_assert!(
            result.valid,
            "Global invariants violated on post-state after transition: {:?}",
            result.violations.iter().map(|v| format!("{}: {}", v.invariant_id, v.description)).collect::<Vec<_>>()
        );
    }

    /// Property 11c: Global invariants hold after a chain of two transitions.
    /// This tests inductive preservation: if G(s) holds and we apply two
    /// transitions, G(s'') still holds.
    #[test]
    fn prop_global_invariants_preserved_after_two_transitions(
        pre in arb_valid_state(),
        sigma1 in arb_any_input(),
        sigma2 in arb_any_input(),
    ) {
        let mid = apply(&pre, &sigma1);
        let post = apply(&mid, &sigma2);
        let result = check_all_global(&post);
        prop_assert!(
            result.valid,
            "Global invariants violated after two transitions: {:?}",
            result.violations.iter().map(|v| format!("{}: {}", v.invariant_id, v.description)).collect::<Vec<_>>()
        );
    }
}

// ---------------------------------------------------------------------------
// Property 13: Economic Invariant Enforcement
// Structurally valid but economically inadmissible states are rejected.
// **Validates: Requirements 3.4, 3.5**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property 13a: Economic invariants hold on every valid state that is
    /// economically well-formed (no concentration violations).
    /// States with well-distributed balances should pass all economic checks.
    #[test]
    fn prop_economic_invariants_hold_on_well_distributed_state(
        state in arb_economically_valid_state(),
    ) {
        let result = check_all_economic(&state);
        prop_assert!(
            result.valid,
            "Economic invariants violated on well-distributed state: {:?}",
            result.violations.iter().map(|v| format!("{}: {}", v.invariant_id, v.description)).collect::<Vec<_>>()
        );
    }

    /// Property 13b: Admissible(s) holds for all economically well-formed states.
    /// Admissible(s) ≡ ValidState(s) ∧ EconomicallyValid(s)
    #[test]
    fn prop_admissible_holds_on_well_distributed_state(
        state in arb_economically_valid_state(),
    ) {
        prop_assert!(
            admissible(&state),
            "State should be admissible: valid_state={}, economically_valid={}",
            valid_state(&state),
            economically_valid(&state)
        );
    }

    /// Property 13c: A state with fee_rate_bps > 10000 (exceeding 100%) is
    /// detected as an economic violation by E_cost.
    /// This tests that structurally valid but economically inadmissible states
    /// are rejected.
    #[test]
    fn prop_excessive_fee_rate_detected(
        base_state in arb_valid_state(),
        fee_rate in 10_001u128..=100_000u128,
    ) {
        // Inject an excessive fee_rate_bps into system parameters
        let mut state = base_state;
        state.canonical.system_data.parameters.insert(
            "fee_rate_bps".to_string(),
            fee_rate.to_le_bytes().to_vec(),
        );
        // Recompute total_supply to keep canonical valid
        let total_supply: u128 = state.canonical.accounts.values().map(|a| a.balance).sum();
        state.canonical.system_data.total_supply = total_supply;
        // Recompute derived and economic
        state.derived = derive(&state.canonical);
        state.economic = derive_economic(&state.canonical, &state.environment);

        let result = check_all_economic(&state);
        prop_assert!(
            !result.valid,
            "Economic invariants should detect fee_rate_bps={} > 10000",
            fee_rate
        );
        // Verify E_cost is specifically violated
        let has_e_cost = result.violations.iter().any(|v| v.invariant_id == "E_cost");
        prop_assert!(
            has_e_cost,
            "E_cost invariant should be violated for fee_rate_bps={}",
            fee_rate
        );
    }

    /// Property 13d: A state with max_leverage_bps == 0 is detected as an
    /// economic violation by G_econ_valid.
    #[test]
    fn prop_zero_max_leverage_detected(
        base_state in arb_valid_state(),
    ) {
        let mut state = base_state;
        // Set max_leverage_bps to 0 via system parameters
        state.canonical.system_data.parameters.insert(
            "max_leverage_bps".to_string(),
            0u128.to_le_bytes().to_vec(),
        );
        // Recompute total_supply to keep canonical valid
        let total_supply: u128 = state.canonical.accounts.values().map(|a| a.balance).sum();
        state.canonical.system_data.total_supply = total_supply;
        // Recompute derived and economic
        state.derived = derive(&state.canonical);
        state.economic = derive_economic(&state.canonical, &state.environment);

        let result = check_all_economic(&state);
        prop_assert!(
            !result.valid,
            "Economic invariants should detect max_leverage_bps=0"
        );
        let has_g_econ = result.violations.iter().any(|v| v.invariant_id == "G_econ_valid");
        prop_assert!(
            has_g_econ,
            "G_econ_valid invariant should be violated for max_leverage_bps=0"
        );
    }

    /// Property 13e: Admissible rejects economically invalid states.
    /// A state that is structurally valid (valid_state) but economically
    /// inadmissible (!economically_valid) must have admissible() == false.
    #[test]
    fn prop_admissible_rejects_economically_invalid(
        base_state in arb_valid_state(),
        fee_rate in 10_001u128..=100_000u128,
    ) {
        let mut state = base_state;
        state.canonical.system_data.parameters.insert(
            "fee_rate_bps".to_string(),
            fee_rate.to_le_bytes().to_vec(),
        );
        let total_supply: u128 = state.canonical.accounts.values().map(|a| a.balance).sum();
        state.canonical.system_data.total_supply = total_supply;
        state.derived = derive(&state.canonical);
        state.economic = derive_economic(&state.canonical, &state.environment);

        // State should be structurally valid
        prop_assert!(
            valid_state(&state),
            "State should be structurally valid"
        );
        // But economically invalid
        prop_assert!(
            !economically_valid(&state),
            "State should be economically invalid with fee_rate_bps={}",
            fee_rate
        );
        // Therefore not admissible
        prop_assert!(
            !admissible(&state),
            "Admissible should reject economically invalid state"
        );
    }

    /// Property 13f: Economic invariants are preserved after transitions
    /// on states with well-distributed balances (no concentration violations).
    #[test]
    fn prop_economic_invariants_preserved_after_transition(
        pre in arb_economically_valid_state(),
        sigma in arb_any_input(),
    ) {
        let post = apply(&pre, &sigma);
        let result = check_all_economic(&post);
        prop_assert!(
            result.valid,
            "Economic invariants violated after transition: {:?}",
            result.violations.iter().map(|v| format!("{}: {}", v.invariant_id, v.description)).collect::<Vec<_>>()
        );
    }
}
