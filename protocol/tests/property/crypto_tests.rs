//! Property-based tests for VSEL cryptographic module.
//!
//! Uses `proptest` to verify cryptographic correctness properties derived from
//! CRYPTOGRAPHIC_MODEL.md, LONG_TERM_SECURITY_MODEL.md.
//!
//! Properties tested:
//! - Property 44: Hybrid Signature Verification — both classical and PQC must verify
//!   **Validates: Requirements 10.1**
//! - Property 45: Hybrid Key Exchange — shared secret requires compromise of both components
//!   **Validates: Requirements 10.2**
//! - Property 46: Cryptographic Domain Separation — hash(d₁ | data) ≠ hash(d₂ | data)
//!   **Validates: Requirements 10.3**
//! - Property 47: State Commitment Determinism — commit(C) is deterministic
//!   **Validates: Requirements 10.4**

use std::collections::BTreeMap;

use proptest::collection::btree_map;
use proptest::prelude::*;

use vsel_core::state::{AccountData, CanonicalState};
use vsel_core::types::*;
use vsel_crypto::domain::{create_domain_tag, domain_hash, domain_hash_blake3};
use vsel_crypto::hash::{commit_canonical_state, domain_hash_with_algorithm, HashAlgorithm};
use vsel_crypto::signatures::{
    combine_shared_secrets, generate_hybrid_keypair, hybrid_key_exchange, hybrid_sign,
    hybrid_verify,
};

// ---------------------------------------------------------------------------
// Arbitrary strategies
// ---------------------------------------------------------------------------

/// Generate a random message (0..256 bytes).
fn arb_message() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..256)
}

/// Generate a non-empty domain context (1..64 bytes).
fn arb_domain_context() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 1..64)
}

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

/// Generate a random non-empty secret key (1..64 bytes).
fn arb_secret() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 1..64)
}

// ---------------------------------------------------------------------------
// Property 44: Hybrid Signature Verification
// Both classical AND PQC must verify for acceptance.
// **Validates: Requirements 10.1**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property 44a: Hybrid sign/verify round-trip — a valid signature verifies.
    #[test]
    fn prop_hybrid_signature_roundtrip(msg in arb_message()) {
        let kp = generate_hybrid_keypair();
        let domain = create_domain_tag(b"VSEL::v1::test::signature");

        let sig = hybrid_sign(&kp.signing_key, &msg, &domain).unwrap();
        let ok = hybrid_verify(&kp.public_key, &msg, &sig, &domain).unwrap();
        prop_assert!(ok, "valid hybrid signature must verify");
    }

    /// Property 44b: Corrupted classical signature must fail verification.
    /// Both components must verify — corrupting classical alone must reject.
    #[test]
    fn prop_hybrid_reject_corrupted_classical(msg in arb_message()) {
        let kp = generate_hybrid_keypair();
        let domain = create_domain_tag(b"VSEL::v1::test::signature");

        let mut sig = hybrid_sign(&kp.signing_key, &msg, &domain).unwrap();
        // Corrupt classical signature bytes
        if !sig.classical_sig.is_empty() {
            sig.classical_sig[0] ^= 0xff;
            if sig.classical_sig.len() > 1 {
                sig.classical_sig[1] ^= 0xff;
            }
        }

        let ok = hybrid_verify(&kp.public_key, &msg, &sig, &domain).unwrap();
        prop_assert!(!ok, "corrupted classical signature must fail verification");
    }

    /// Property 44c: Corrupted PQC signature must fail verification.
    /// Both components must verify — corrupting PQC alone must reject.
    #[test]
    fn prop_hybrid_reject_corrupted_pqc(msg in arb_message()) {
        let kp = generate_hybrid_keypair();
        let domain = create_domain_tag(b"VSEL::v1::test::signature");

        let mut sig = hybrid_sign(&kp.signing_key, &msg, &domain).unwrap();
        // Corrupt PQC signature by changing its length (invalid HMAC output)
        sig.pqc_sig = vec![0u8; 16]; // wrong length — not 32 bytes

        let ok = hybrid_verify(&kp.public_key, &msg, &sig, &domain).unwrap();
        prop_assert!(!ok, "corrupted PQC signature must fail verification");
    }

    /// Property 44d: Signature under wrong domain must fail verification.
    /// Domain separation ensures cross-context replay prevention.
    #[test]
    fn prop_hybrid_reject_wrong_domain(msg in arb_message()) {
        let kp = generate_hybrid_keypair();
        let domain_a = create_domain_tag(b"VSEL::v1::domain_alpha");
        let domain_b = create_domain_tag(b"VSEL::v1::domain_beta");

        let sig = hybrid_sign(&kp.signing_key, &msg, &domain_a).unwrap();
        let ok = hybrid_verify(&kp.public_key, &msg, &sig, &domain_b).unwrap();
        prop_assert!(!ok, "signature from domain_a must not verify under domain_b");
    }
}

// ---------------------------------------------------------------------------
// Property 45: Hybrid Key Exchange
// Shared secret requires compromise of both components.
// **Validates: Requirements 10.2**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property 45a: Key exchange is deterministic — same inputs produce same shared secret.
    #[test]
    fn prop_key_exchange_deterministic(secret in arb_secret()) {
        let kp = generate_hybrid_keypair();

        let ss1 = hybrid_key_exchange(&secret, &kp.public_key).unwrap();
        let ss2 = hybrid_key_exchange(&secret, &kp.public_key).unwrap();
        prop_assert_eq!(ss1, ss2, "key exchange must be deterministic for same inputs");
    }

    /// Property 45b: Different public keys produce different shared secrets.
    /// Changing the full public key changes the result.
    #[test]
    fn prop_key_exchange_different_keys(secret in arb_secret()) {
        let kp1 = generate_hybrid_keypair();
        let kp2 = generate_hybrid_keypair();

        let ss1 = hybrid_key_exchange(&secret, &kp1.public_key).unwrap();
        let ss2 = hybrid_key_exchange(&secret, &kp2.public_key).unwrap();
        prop_assert_ne!(
            ss1, ss2,
            "different public keys must produce different shared secrets"
        );
    }

    /// Property 45c: Changing only the classical component changes the shared secret.
    /// This demonstrates that compromise of PQC alone is insufficient.
    #[test]
    fn prop_key_exchange_classical_component_matters(
        classical_a in prop::collection::vec(any::<u8>(), 1..64),
        classical_b in prop::collection::vec(any::<u8>(), 1..64),
        pqc_shared in prop::collection::vec(any::<u8>(), 1..64),
    ) {
        prop_assume!(classical_a != classical_b);

        let ss1 = combine_shared_secrets(&classical_a, &pqc_shared);
        let ss2 = combine_shared_secrets(&classical_b, &pqc_shared);
        prop_assert_ne!(
            ss1, ss2,
            "different classical secrets must produce different combined secrets"
        );
    }

    /// Property 45d: Changing only the PQC component changes the shared secret.
    /// This demonstrates that compromise of classical alone is insufficient.
    #[test]
    fn prop_key_exchange_pqc_component_matters(
        classical_shared in prop::collection::vec(any::<u8>(), 1..64),
        pqc_a in prop::collection::vec(any::<u8>(), 1..64),
        pqc_b in prop::collection::vec(any::<u8>(), 1..64),
    ) {
        prop_assume!(pqc_a != pqc_b);

        let ss1 = combine_shared_secrets(&classical_shared, &pqc_a);
        let ss2 = combine_shared_secrets(&classical_shared, &pqc_b);
        prop_assert_ne!(
            ss1, ss2,
            "different PQC secrets must produce different combined secrets"
        );
    }
}

// ---------------------------------------------------------------------------
// Property 46: Cryptographic Domain Separation
// hash(d₁ | data) ≠ hash(d₂ | data) for distinct domains.
// **Validates: Requirements 10.3**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property 46a: Domain-separated SHA3 hashes differ for distinct domains.
    #[test]
    fn prop_domain_separation_sha3(
        data in arb_message(),
        ctx_a in arb_domain_context(),
        ctx_b in arb_domain_context(),
    ) {
        prop_assume!(ctx_a != ctx_b);

        let tag_a = create_domain_tag(&ctx_a);
        let tag_b = create_domain_tag(&ctx_b);

        let h1 = domain_hash(&tag_a, &data);
        let h2 = domain_hash(&tag_b, &data);
        prop_assert_ne!(
            h1, h2,
            "same data under different domains must produce different SHA3 hashes"
        );
    }

    /// Property 46b: Domain-separated BLAKE3 hashes differ for distinct domains.
    #[test]
    fn prop_domain_separation_blake3(
        data in arb_message(),
        ctx_a in arb_domain_context(),
        ctx_b in arb_domain_context(),
    ) {
        prop_assume!(ctx_a != ctx_b);

        let tag_a = create_domain_tag(&ctx_a);
        let tag_b = create_domain_tag(&ctx_b);

        let h1 = domain_hash_blake3(&tag_a, &data);
        let h2 = domain_hash_blake3(&tag_b, &data);
        prop_assert_ne!(
            h1, h2,
            "same data under different domains must produce different BLAKE3 hashes"
        );
    }

    /// Property 46c: Domain-separated hashing with all algorithm choices
    /// produces different results for distinct domains.
    #[test]
    fn prop_domain_separation_all_algorithms(
        data in arb_message(),
        ctx_a in arb_domain_context(),
        ctx_b in arb_domain_context(),
    ) {
        prop_assume!(ctx_a != ctx_b);

        let tag_a = create_domain_tag(&ctx_a);
        let tag_b = create_domain_tag(&ctx_b);

        for algo in [HashAlgorithm::Sha3_256, HashAlgorithm::Blake3, HashAlgorithm::Poseidon] {
            let h1 = domain_hash_with_algorithm(algo, &tag_a, &data);
            let h2 = domain_hash_with_algorithm(algo, &tag_b, &data);
            prop_assert_ne!(
                h1, h2,
                "{:?}: same data under different domains must produce different hashes",
                algo
            );
        }
    }

    /// Property 46d: Domain tags created from distinct contexts are always distinct.
    #[test]
    fn prop_domain_tags_distinct(
        ctx_a in arb_domain_context(),
        ctx_b in arb_domain_context(),
    ) {
        prop_assume!(ctx_a != ctx_b);

        let tag_a = create_domain_tag(&ctx_a);
        let tag_b = create_domain_tag(&ctx_b);
        prop_assert_ne!(
            tag_a, tag_b,
            "distinct context strings must produce distinct domain tags"
        );
    }
}

// ---------------------------------------------------------------------------
// Property 47: State Commitment Determinism
// commit(C) is deterministic for identical canonical state.
// **Validates: Requirements 10.4**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property 47a: commit_canonical_state is deterministic — same state always
    /// produces the same commitment hash.
    #[test]
    fn prop_state_commitment_deterministic(c in arb_canonical_state()) {
        let h1 = commit_canonical_state(&c);
        let h2 = commit_canonical_state(&c);
        prop_assert_eq!(
            h1, h2,
            "commit_canonical_state must be deterministic: same state → same hash"
        );
    }

    /// Property 47b: Different canonical states produce different commitments
    /// (collision resistance).
    #[test]
    fn prop_state_commitment_injective(c1 in arb_canonical_state(), c2 in arb_canonical_state()) {
        let h1 = commit_canonical_state(&c1);
        let h2 = commit_canonical_state(&c2);
        if c1 != c2 {
            prop_assert_ne!(
                h1, h2,
                "different canonical states must produce different commitments (collision resistance)"
            );
        } else {
            prop_assert_eq!(
                h1, h2,
                "equal canonical states must produce equal commitments"
            );
        }
    }

    /// Property 47c: State commitment produces a non-zero hash.
    #[test]
    fn prop_state_commitment_nonzero(c in arb_canonical_state()) {
        let h = commit_canonical_state(&c);
        prop_assert_ne!(
            h, Hash([0u8; 32]),
            "commit_canonical_state must produce a non-zero hash"
        );
    }
}
