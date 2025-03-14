//! Property-based tests for the VSEL State model.
//!
//! Uses `proptest` to verify correctness properties derived from
//! FORMAL_SPECIFICATION.md §3, STATE_MACHINE.md §2, TECH_SPEC.md §3.2.
//!
//! Properties tested:
//! - Property 1: Execution Determinism — derive(C₁) = derive(C₂) when C₁ = C₂
//!   **Validates: Requirements 1.4, 2.3**
//! - Property 2: State Closure Under Transition — valid_state(s) rejects all structurally invalid states
//!   **Validates: Requirements 1.5, 3.2**
//! - Property 9: Derived State Consistency — derive(C) is deterministic for identical inputs
//!   **Validates: Requirements 2.9**

use std::collections::BTreeMap;

use proptest::prelude::*;
use proptest::collection::btree_map;

use vsel_core::state::*;
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
// Property 1: Execution Determinism
// derive(C₁) = derive(C₂) when C₁ = C₂
// **Validates: Requirements 1.4, 2.3**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property 1: Execution Determinism — derive is a pure function.
    /// For any canonical state C, derive(C) always produces the same DerivedState.
    #[test]
    fn prop_derive_deterministic(c in arb_canonical_state()) {
        let d1 = derive(&c);
        let d2 = derive(&c);
        prop_assert_eq!(d1, d2, "derive must be deterministic: derive(C) called twice must be equal");
    }
}

// ---------------------------------------------------------------------------
// Property 2: State Closure Under Transition
// valid_state(s) rejects all structurally invalid states
// **Validates: Requirements 1.5, 3.2**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property 2a: valid_state accepts all correctly constructed states.
    #[test]
    fn prop_valid_state_accepts_correct(s in arb_valid_state()) {
        prop_assert!(
            valid_state(&s),
            "valid_state must accept a state built from derive() and derive_economic()"
        );
    }

    /// Property 2b: valid_state rejects states with mismatched total_supply.
    #[test]
    fn prop_valid_state_rejects_bad_total_supply(
        s in arb_valid_state(),
        delta in 1u128..=1_000_000u128,
    ) {
        let mut bad = s.clone();
        // Corrupt total_supply so it doesn't match sum of balances
        bad.canonical.system_data.total_supply =
            bad.canonical.system_data.total_supply.wrapping_add(delta);
        // Re-derive to keep D consistent with the corrupted C
        bad.derived = derive(&bad.canonical);
        prop_assert!(
            !valid_state(&bad),
            "valid_state must reject state with total_supply != sum(balances)"
        );
    }

    /// Property 2c: valid_state rejects states with corrupted derived state.
    #[test]
    fn prop_valid_state_rejects_bad_derived(
        s in arb_valid_state(),
        corrupt_byte in any::<u8>(),
    ) {
        let mut bad = s.clone();
        // Corrupt the state_root hash
        bad.derived.state_root.0[0] = bad.derived.state_root.0[0].wrapping_add(corrupt_byte.max(1));
        prop_assert!(
            !valid_state(&bad),
            "valid_state must reject state with corrupted derived state root"
        );
    }

    /// Property 2d: valid_state rejects states with zero domain tag.
    #[test]
    fn prop_valid_state_rejects_zero_domain(s in arb_valid_state()) {
        let mut bad = s.clone();
        bad.environment.execution_domain = DomainTag(Hash([0u8; 32]));
        prop_assert!(
            !valid_state(&bad),
            "valid_state must reject state with zero domain tag"
        );
    }

    /// Property 2e: valid_state rejects genesis metadata with non-zero previous commitment.
    #[test]
    fn prop_valid_state_rejects_bad_genesis_metadata(
        s in arb_valid_state(),
        nonzero_byte in 1u8..=255u8,
    ) {
        let mut bad = s.clone();
        bad.metadata.sequence_index = 0;
        let mut commitment = [0u8; 32];
        commitment[0] = nonzero_byte;
        bad.metadata.previous_commitment = Hash(commitment);
        prop_assert!(
            !valid_state(&bad),
            "valid_state must reject genesis (seq=0) with non-zero previous_commitment"
        );
    }

    /// Property 2f: valid_state rejects non-genesis metadata with zero previous commitment.
    #[test]
    fn prop_valid_state_rejects_nongenesis_zero_commitment(
        s in arb_valid_state(),
        seq in 1u64..=1_000_000u64,
    ) {
        let mut bad = s.clone();
        bad.metadata.sequence_index = seq;
        bad.metadata.previous_commitment = Hash([0u8; 32]);
        prop_assert!(
            !valid_state(&bad),
            "valid_state must reject non-genesis (seq>0) with zero previous_commitment"
        );
    }
}

// ---------------------------------------------------------------------------
// Property 9: Derived State Consistency
// derive(C) is deterministic for identical inputs
// **Validates: Requirements 2.9**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property 9a: Two clones of the same canonical state produce identical derived states.
    #[test]
    fn prop_derived_state_consistency_identical(c in arb_canonical_state()) {
        let c_clone = c.clone();
        let d1 = derive(&c);
        let d2 = derive(&c_clone);
        prop_assert_eq!(
            d1, d2,
            "derive must produce identical results for cloned canonical states"
        );
    }

    /// Property 9b: Different canonical states produce different derived states (with high probability).
    /// Two independently generated canonical states should (almost certainly) produce different state roots.
    #[test]
    fn prop_derived_state_different_inputs(
        c1 in arb_canonical_state(),
        c2 in arb_canonical_state(),
    ) {
        let d1 = derive(&c1);
        let d2 = derive(&c2);
        // If the canonical states are equal, derived states must be equal.
        // If they differ, derived states should differ (collision resistance).
        if c1 == c2 {
            prop_assert_eq!(d1, d2, "equal canonical states must produce equal derived states");
        } else {
            prop_assert_ne!(
                d1.state_root, d2.state_root,
                "different canonical states should produce different state roots (SHA3-256 collision resistance)"
            );
        }
    }

    /// Property 9c: derive_economic is deterministic — same (C, E) produces same Ω.
    #[test]
    fn prop_derive_economic_deterministic(
        c in arb_canonical_state(),
        e in arb_environment(),
    ) {
        let econ1 = derive_economic(&c, &e);
        let econ2 = derive_economic(&c, &e);
        prop_assert_eq!(
            econ1, econ2,
            "derive_economic must be deterministic for identical (C, E)"
        );
    }

    /// Property 9d: Aggregates in derived state are consistent with canonical state.
    #[test]
    fn prop_derived_aggregates_consistent(c in arb_canonical_state()) {
        let d = derive(&c);
        let expected_total: u128 = c.accounts.values().map(|a| a.balance).sum();
        let expected_count = c.accounts.len() as u128;
        prop_assert_eq!(
            d.aggregates.get("total_balance").copied(),
            Some(expected_total),
            "total_balance aggregate must match sum of account balances"
        );
        prop_assert_eq!(
            d.aggregates.get("account_count").copied(),
            Some(expected_count),
            "account_count aggregate must match number of accounts"
        );
    }
}
