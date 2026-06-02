//! Property-based tests for PoseidonGoldilocks domain separation and injective encoding.
//!
//! Uses `proptest` to verify correctness properties derived from the
//! production-readiness design document.
//!
//! Properties tested:
//! - Property 11: Poseidon Domain Separation
//!   **Validates: Requirements 5.6**
//! - Property 12: Poseidon Injective Encoding
//!   **Validates: Requirements 5.7**

// Feature: production-readiness, Property 11: Poseidon Domain Separation

use proptest::prelude::*;

use vsel_core::types::DomainTag;
use vsel_crypto::domain::create_domain_tag;
use vsel_crypto::poseidon_goldilocks::PoseidonGoldilocks;
use vsel_crypto::GoldilocksField;

const MODULUS: u64 = GoldilocksField::MODULUS;

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

/// Generator for GoldilocksField elements used as hash input data.
/// Weights boundary values alongside uniformly random field elements.
fn arb_goldilocks() -> impl Strategy<Value = GoldilocksField> {
    prop_oneof![
        2 => Just(GoldilocksField::ZERO),
        2 => Just(GoldilocksField::ONE),
        2 => Just(GoldilocksField(MODULUS - 1)),
        2 => Just(GoldilocksField(MODULUS - 2)),
        12 => (0u64..MODULUS).prop_map(GoldilocksField),
    ]
}

/// Generator for a small vector of GoldilocksField elements (0..=16 elements).
fn arb_field_elements() -> impl Strategy<Value = Vec<GoldilocksField>> {
    prop::collection::vec(arb_goldilocks(), 0..=16)
}

/// Generator for a pair of distinct domain tags.
///
/// Creates two domain tags from distinct byte sequences. The byte sequences
/// are guaranteed to differ because they are generated independently and
/// filtered via `prop_filter`. We use short byte vectors (1..=32 bytes)
/// to keep generation efficient while covering diverse domain contexts.
fn arb_distinct_domain_tags() -> impl Strategy<Value = (DomainTag, DomainTag)> {
    (
        prop::collection::vec(any::<u8>(), 1..=32),
        prop::collection::vec(any::<u8>(), 1..=32),
    )
        .prop_filter("domain tag byte sequences must differ", |(a, b)| a != b)
        .prop_map(|(bytes_a, bytes_b)| (create_domain_tag(&bytes_a), create_domain_tag(&bytes_b)))
}

// ---------------------------------------------------------------------------
// Property 11: Poseidon Domain Separation
// For any data and distinct domain tags tag_a ≠ tag_b,
// hash_with_domain(tag_a, data) != hash_with_domain(tag_b, data)
// **Validates: Requirements 5.6**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(
        std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(100)
    ))]

    /// Property 11: For any data and distinct domain tags, domain-separated
    /// hashes must differ. This ensures cross-domain replay prevention at
    /// the Poseidon level.
    #[test]
    fn prop_poseidon_domain_separation(
        (tag_a, tag_b) in arb_distinct_domain_tags(),
        data in arb_field_elements(),
    ) {
        let poseidon = PoseidonGoldilocks::new();

        let hash_a = poseidon.hash_with_domain(&tag_a, &data);
        let hash_b = poseidon.hash_with_domain(&tag_b, &data);

        prop_assert_ne!(
            hash_a,
            hash_b,
            "hash_with_domain must produce different outputs for distinct domain tags: \
             tag_a={:?}, tag_b={:?}, data_len={}",
            tag_a, tag_b, data.len()
        );
    }
}

// ---------------------------------------------------------------------------
// Property 12: Poseidon Injective Encoding
// For any two distinct byte sequences data_a ≠ data_b,
// hash_bytes(data_a) != hash_bytes(data_b)
// This validates the injective encoding indirectly — if the encoding
// were not injective, there would exist distinct inputs that hash to
// the same output.
// **Validates: Requirements 5.7**
// ---------------------------------------------------------------------------

// Feature: production-readiness, Property 12: Poseidon Injective Encoding

proptest! {
    #![proptest_config(ProptestConfig::with_cases(
        std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(100)
    ))]

    /// Property 12: For any two distinct byte sequences, hash_bytes must
    /// produce different outputs. This validates the injective encoding
    /// used internally by hash_bytes — distinct byte inputs must never
    /// collide through the field element encoding and Poseidon sponge.
    #[test]
    fn prop_poseidon_injective_encoding(
        data_a in prop::collection::vec(any::<u8>(), 0..=64),
        data_b in prop::collection::vec(any::<u8>(), 0..=64),
    ) {
        prop_assume!(data_a != data_b);

        let poseidon = PoseidonGoldilocks::new();

        let hash_a = poseidon.hash_bytes(&data_a);
        let hash_b = poseidon.hash_bytes(&data_b);

        prop_assert_ne!(
            hash_a,
            hash_b,
            "hash_bytes must produce different outputs for distinct byte sequences: \
             data_a_len={}, data_b_len={}, data_a={:?}, data_b={:?}",
            data_a.len(), data_b.len(), &data_a[..data_a.len().min(16)], &data_b[..data_b.len().min(16)]
        );
    }
}
