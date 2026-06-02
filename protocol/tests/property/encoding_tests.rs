//! Property-based tests for VSEL canonical encoding (DEF-2, DEF-3).
//!
//! Uses `proptest` to verify encoding correctness properties derived from
//! FORMAL_SPECIFICATION.md §3, TECH_SPEC.md §3.2.
//!
//! Properties tested:
//! - Property 8: Encoding Injectivity — distinct states produce distinct encodings (DEF-2)
//!   **Validates: Requirements 2.8**

use std::collections::BTreeMap;

use proptest::collection::btree_map;
use proptest::prelude::*;

use vsel_core::state::*;
use vsel_core::types::*;

// ---------------------------------------------------------------------------
// Arbitrary strategies (reused from state_tests.rs patterns)
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
// Property 8: Encoding Injectivity (DEF-2)
// encode(s₁) = encode(s₂) ⟹ s₁ = s₂
// Equivalently: s₁ ≠ s₂ ⟹ encode(s₁) ≠ encode(s₂)
// **Validates: Requirements 2.8**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property 8a: encode is deterministic — same state always produces same encoding.
    #[test]
    fn prop_encode_deterministic(s in arb_valid_state()) {
        let enc1 = encode(&s);
        let enc2 = encode(&s);
        prop_assert_eq!(
            enc1, enc2,
            "encode must be deterministic: same state → same bytes"
        );
    }

    /// Property 8b: Encoding injectivity — distinct states produce distinct encodings.
    /// For any two independently generated states s1 and s2:
    /// if encode(s1) == encode(s2) then s1 == s2.
    #[test]
    fn prop_encode_injective(s1 in arb_valid_state(), s2 in arb_valid_state()) {
        let enc1 = encode(&s1);
        let enc2 = encode(&s2);
        if s1 != s2 {
            prop_assert_ne!(
                enc1, enc2,
                "distinct states must produce distinct encodings (DEF-2 injectivity)"
            );
        } else {
            prop_assert_eq!(
                enc1, enc2,
                "equal states must produce equal encodings"
            );
        }
    }

    /// Property 8c: encode produces non-empty output for any valid state.
    #[test]
    fn prop_encode_nonempty(s in arb_valid_state()) {
        let enc = encode(&s);
        prop_assert!(
            !enc.is_empty(),
            "encode must produce non-empty output for any state"
        );
    }

    /// Property 8d: encode output starts with the domain separator.
    /// The encoding format prefixes with a length-prefixed domain separator.
    #[test]
    fn prop_encode_starts_with_domain_separator(s in arb_valid_state()) {
        let enc = encode(&s);
        let domain = b"VSEL-STATE-ENCODING-V1";
        let len_bytes = (domain.len() as u64).to_le_bytes();
        // First 8 bytes are the length prefix, then the domain separator bytes
        prop_assert!(
            enc.len() >= 8 + domain.len(),
            "encoding must be at least as long as the domain separator prefix"
        );
        prop_assert_eq!(
            &enc[..8], &len_bytes,
            "encoding must start with the domain separator length prefix"
        );
        prop_assert_eq!(
            &enc[8..8 + domain.len()], domain.as_slice(),
            "encoding must contain the domain separator after the length prefix"
        );
    }

    /// Property 8e: commit is deterministic — same canonical state always produces same hash.
    #[test]
    fn prop_commit_deterministic(c in arb_canonical_state()) {
        let h1 = commit(&c);
        let h2 = commit(&c);
        prop_assert_eq!(
            h1, h2,
            "commit must be deterministic: same canonical state → same hash"
        );
    }

    /// Property 8f: commit produces a non-zero hash for any canonical state.
    #[test]
    fn prop_commit_nonzero(c in arb_canonical_state()) {
        let h = commit(&c);
        prop_assert_ne!(
            h, Hash([0u8; 32]),
            "commit must produce a non-zero hash for any canonical state"
        );
    }

    /// Property 8g: commit produces different hashes for different canonical states.
    #[test]
    fn prop_commit_injective(c1 in arb_canonical_state(), c2 in arb_canonical_state()) {
        let h1 = commit(&c1);
        let h2 = commit(&c2);
        if c1 != c2 {
            prop_assert_ne!(
                h1, h2,
                "different canonical states must produce different commit hashes (collision resistance)"
            );
        } else {
            prop_assert_eq!(
                h1, h2,
                "equal canonical states must produce equal commit hashes"
            );
        }
    }
}
