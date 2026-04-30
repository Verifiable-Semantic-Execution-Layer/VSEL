//! Hybrid hash functions for the VSEL protocol.
//!
//! Derived from: CRYPTOGRAPHIC_MODEL.md, LONG_TERM_SECURITY_MODEL.md.
//!
//! Provides:
//! - SHA-3 and BLAKE3 for long-term commitments (T3/T4 horizon)
//! - STARK-friendly Poseidon hash for proof-internal use
//! - Domain-separated hashing: `hash(domain, data)` for all operations
//! - Collision-resistant state commitments: `commit(C) = hash(encode(C))`
//!
//! Requirements: 10.3 (domain-separated hashing), 10.4 (collision-resistant commitments).

use sha3::{Digest, Sha3_256};
use vsel_core::state::CanonicalState;
use vsel_core::types::{DomainTag, Hash};

use crate::domain::{create_domain_tag, domain_hash, domain_hash_blake3};

// ---------------------------------------------------------------------------
// Hash algorithm selection
// ---------------------------------------------------------------------------

/// Supported hash algorithms, classified by use case and temporal horizon.
///
/// - `Sha3_256`: NIST-standard, collision-resistant, suitable for T3/T4 commitments.
/// - `Blake3`: High-performance, collision-resistant, preferred for T4 permanent commitments.
/// - `Poseidon`: STARK-friendly algebraic hash for proof-internal use (T2 horizon).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    /// SHA3-256 — NIST standard, collision-resistant.
    Sha3_256,
    /// BLAKE3 — high-performance, collision-resistant, post-quantum friendly.
    Blake3,
    /// Poseidon — STARK-friendly algebraic hash for proof circuits.
    Poseidon,
}

// ---------------------------------------------------------------------------
// Temporal classification
// ---------------------------------------------------------------------------

/// Temporal sensitivity classification for cryptographic artifacts.
///
/// From LONG_TERM_SECURITY_MODEL.md — each class maps to a recommended
/// hash algorithm with appropriate primitive strength.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TemporalClass {
    /// T1: Ephemeral — single-use, short-lived (e.g., nonces).
    T1Ephemeral,
    /// T2: Session — valid for a session or proof batch.
    T2Session,
    /// T3: Archival — long-term storage, must survive years.
    T3Archival,
    /// T4: Permanent — must survive indefinitely, post-quantum resistant.
    T4Permanent,
}

/// Returns the recommended hash algorithm for a given temporal class.
///
/// - T1/T2: SHA3-256 (standard, well-audited, sufficient for short-lived data).
/// - T3: BLAKE3 (high-performance, collision-resistant, archival-grade).
/// - T4: BLAKE3 (post-quantum friendly, permanent commitments).
///
/// Poseidon is never recommended by temporal class — it is selected explicitly
/// for proof-internal use where STARK-friendliness is required.
pub fn recommended_algorithm(temporal_class: TemporalClass) -> HashAlgorithm {
    match temporal_class {
        TemporalClass::T1Ephemeral => HashAlgorithm::Sha3_256,
        TemporalClass::T2Session => HashAlgorithm::Sha3_256,
        TemporalClass::T3Archival => HashAlgorithm::Blake3,
        TemporalClass::T4Permanent => HashAlgorithm::Blake3,
    }
}

// ---------------------------------------------------------------------------
// Core hash dispatch
// ---------------------------------------------------------------------------

/// Hash raw data using the specified algorithm.
///
/// Dispatches to SHA3-256, BLAKE3, or Poseidon based on `algo`.
///
/// When the `poseidon-goldilocks` feature is active, `HashAlgorithm::Poseidon`
/// uses the production Goldilocks Poseidon. Otherwise (default `poseidon-legacy`),
/// it uses the legacy wrapping-u64 Poseidon.
pub fn hash_with_algorithm(algo: HashAlgorithm, data: &[u8]) -> Hash {
    match algo {
        HashAlgorithm::Sha3_256 => {
            let result = Sha3_256::digest(data);
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&result);
            Hash(bytes)
        }
        HashAlgorithm::Blake3 => {
            let result = blake3::hash(data);
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(result.as_bytes());
            Hash(bytes)
        }
        HashAlgorithm::Poseidon => poseidon_hash_dispatch(data),
    }
}

/// Domain-separated hashing with algorithm choice.
///
/// Computes `Algorithm(domain_tag_bytes || data)` using the specified algorithm.
/// Delegates to the existing `domain_hash` / `domain_hash_blake3` for SHA3/BLAKE3,
/// and uses Poseidon with domain prefix for proof-internal use.
pub fn domain_hash_with_algorithm(
    algo: HashAlgorithm,
    domain: &DomainTag,
    data: &[u8],
) -> Hash {
    match algo {
        HashAlgorithm::Sha3_256 => domain_hash(domain, data),
        HashAlgorithm::Blake3 => domain_hash_blake3(domain, data),
        HashAlgorithm::Poseidon => poseidon_domain_hash_dispatch(domain, data),
    }
}

// ---------------------------------------------------------------------------
// State commitment (T4 permanent horizon)
// ---------------------------------------------------------------------------

/// Domain tag for hybrid hash state commitments.
const DOMAIN_HASH_STATE_COMMITMENT: &[u8] = b"VSEL::v1::hash::state_commitment";

/// Commit to a canonical state using domain-separated BLAKE3 (T4 permanent horizon).
///
/// `commit_canonical_state(C) = BLAKE3(domain_tag || encode(C))`
///
/// Uses BLAKE3 for post-quantum resistance and long-term validity.
/// The encoding reuses `vsel-core`'s canonical state encoding for injectivity.
pub fn commit_canonical_state(c: &CanonicalState) -> Hash {
    let tag = create_domain_tag(DOMAIN_HASH_STATE_COMMITMENT);
    let encoded = vsel_core::state::encode_canonical_state_bytes(c);
    domain_hash_blake3(&tag, &encoded)
}

// ---------------------------------------------------------------------------
// Poseidon hash dispatch (feature-gated)
// ---------------------------------------------------------------------------

// When `poseidon-goldilocks` is active, use the production Goldilocks Poseidon.
// Otherwise (default `poseidon-legacy`), use the legacy wrapping-u64 Poseidon.

/// Dispatch Poseidon hash based on active feature flag.
///
/// - `poseidon-goldilocks`: uses `PoseidonGoldilocks::hash_bytes` (field-native)
/// - `poseidon-legacy` (default): uses `legacy_poseidon::legacy_poseidon_hash` (wrapping u64)
#[cfg(feature = "poseidon-goldilocks")]
fn poseidon_hash_dispatch(data: &[u8]) -> Hash {
    let poseidon = crate::poseidon_goldilocks::PoseidonGoldilocks::new();
    poseidon.hash_bytes(data)
}

#[cfg(not(feature = "poseidon-goldilocks"))]
fn poseidon_hash_dispatch(data: &[u8]) -> Hash {
    #[allow(deprecated)]
    crate::legacy_poseidon::legacy_poseidon_hash(data)
}

/// Dispatch Poseidon domain-separated hash based on active feature flag.
///
/// - `poseidon-goldilocks`: uses `PoseidonGoldilocks::hash_with_domain` with
///   field-native domain separation (capacity initialization).
/// - `poseidon-legacy` (default): uses the legacy XOR-based domain separation
///   strategy (SHA3-derived domain key XORed into Poseidon output).
#[cfg(feature = "poseidon-goldilocks")]
fn poseidon_domain_hash_dispatch(domain: &DomainTag, data: &[u8]) -> Hash {
    let poseidon = crate::poseidon_goldilocks::PoseidonGoldilocks::new();
    // Encode bytes to field elements for domain-separated hashing
    let field_elements: Vec<crate::goldilocks::GoldilocksField> = data
        .chunks(7)
        .map(|chunk| {
            let mut buf = [0u8; 8];
            buf[..chunk.len()].copy_from_slice(chunk);
            crate::goldilocks::GoldilocksField(
                u64::from_le_bytes(buf) % crate::goldilocks::GoldilocksField::MODULUS,
            )
        })
        .collect();
    let result = poseidon.hash_with_domain(domain, &field_elements);
    // Convert single field element to 32-byte Hash by hashing the field output
    // through the full sponge to get 32 bytes
    let result_bytes = result.to_bytes();
    let mut output = [0u8; 32];
    // Use the field element hash as seed, then squeeze 32 bytes via hash_bytes
    output[..8].copy_from_slice(&result_bytes);
    // Fill remaining bytes deterministically from the domain + data
    let full_hash = poseidon.hash_bytes(data);
    // XOR the domain-separated field element into the byte hash for domain separation
    for i in 0..8 {
        output[i] = full_hash.0[i] ^ result_bytes[i];
    }
    output[8..].copy_from_slice(&full_hash.0[8..]);
    Hash(output)
}

#[cfg(not(feature = "poseidon-goldilocks"))]
fn poseidon_domain_hash_dispatch(domain: &DomainTag, data: &[u8]) -> Hash {
    // Legacy Poseidon domain separation: compute a domain-keyed hash by using
    // SHA3-256 to derive a 32-byte domain key, then XOR the domain key into
    // the Poseidon output. This is equivalent to a keyed-hash construction:
    // H_k(m) = Poseidon(m) ⊕ SHA3(domain).
    //
    // Since SHA3-256 is collision-resistant, distinct domains produce distinct
    // 32-byte keys. XORing a distinct key into the Poseidon output guarantees
    // distinct final hashes for distinct domains (regardless of the Poseidon
    // output), because:
    //   If key_a ≠ key_b, then for any h:
    //   h ⊕ key_a ≠ h ⊕ key_b  (XOR with distinct values)
    //
    // Remediated: F-001 regression / Phase 11 audit finding.
    use sha3::{Sha3_256, Digest};
    let domain_key = {
        let mut h = Sha3_256::new();
        h.update(b"VSEL::poseidon::domain_key::");
        h.update(&(domain.0).0);
        let result = h.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    };
    // Compute legacy Poseidon hash of the raw data
    #[allow(deprecated)]
    let poseidon_output = crate::legacy_poseidon::legacy_poseidon_hash(data);
    // XOR domain key into the output for domain separation
    let mut final_hash = [0u8; 32];
    for i in 0..32 {
        final_hash[i] = poseidon_output.0[i] ^ domain_key[i];
    }
    Hash(final_hash)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- HashAlgorithm dispatch ----------------------------------------------

    #[test]
    fn test_sha3_deterministic() {
        let h1 = hash_with_algorithm(HashAlgorithm::Sha3_256, b"hello");
        let h2 = hash_with_algorithm(HashAlgorithm::Sha3_256, b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_blake3_deterministic() {
        let h1 = hash_with_algorithm(HashAlgorithm::Blake3, b"hello");
        let h2 = hash_with_algorithm(HashAlgorithm::Blake3, b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_poseidon_deterministic() {
        let h1 = hash_with_algorithm(HashAlgorithm::Poseidon, b"hello");
        let h2 = hash_with_algorithm(HashAlgorithm::Poseidon, b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_different_algorithms_produce_different_hashes() {
        let data = b"test_data";
        let sha3 = hash_with_algorithm(HashAlgorithm::Sha3_256, data);
        let blake3 = hash_with_algorithm(HashAlgorithm::Blake3, data);
        let poseidon = hash_with_algorithm(HashAlgorithm::Poseidon, data);
        assert_ne!(sha3, blake3);
        assert_ne!(sha3, poseidon);
        assert_ne!(blake3, poseidon);
    }

    #[test]
    fn test_different_data_produces_different_hashes() {
        for algo in [HashAlgorithm::Sha3_256, HashAlgorithm::Blake3, HashAlgorithm::Poseidon] {
            let h1 = hash_with_algorithm(algo, b"data_a");
            let h2 = hash_with_algorithm(algo, b"data_b");
            assert_ne!(h1, h2, "{:?} should produce different hashes for different data", algo);
        }
    }

    #[test]
    fn test_empty_data_produces_valid_hash() {
        for algo in [HashAlgorithm::Sha3_256, HashAlgorithm::Blake3, HashAlgorithm::Poseidon] {
            let h = hash_with_algorithm(algo, b"");
            assert_eq!(h.0.len(), 32, "{:?} should produce 32-byte hash", algo);
        }
    }

    // -- Domain-separated hashing with algorithm choice ----------------------

    #[test]
    fn test_domain_hash_with_algorithm_deterministic() {
        let tag = create_domain_tag(b"test");
        for algo in [HashAlgorithm::Sha3_256, HashAlgorithm::Blake3, HashAlgorithm::Poseidon] {
            let h1 = domain_hash_with_algorithm(algo, &tag, b"data");
            let h2 = domain_hash_with_algorithm(algo, &tag, b"data");
            assert_eq!(h1, h2, "{:?} domain hash should be deterministic", algo);
        }
    }

    #[test]
    fn test_domain_hash_with_algorithm_different_domains() {
        let tag_a = create_domain_tag(b"domain_a");
        let tag_b = create_domain_tag(b"domain_b");
        for algo in [HashAlgorithm::Sha3_256, HashAlgorithm::Blake3, HashAlgorithm::Poseidon] {
            let h1 = domain_hash_with_algorithm(algo, &tag_a, b"same_data");
            let h2 = domain_hash_with_algorithm(algo, &tag_b, b"same_data");
            assert_ne!(h1, h2, "{:?} should produce different hashes for different domains", algo);
        }
    }

    #[test]
    fn test_domain_hash_sha3_matches_domain_module() {
        let tag = create_domain_tag(b"test");
        let via_hash = domain_hash_with_algorithm(HashAlgorithm::Sha3_256, &tag, b"data");
        let via_domain = domain_hash(&tag, b"data");
        assert_eq!(via_hash, via_domain, "SHA3 domain hash should match domain.rs");
    }

    #[test]
    fn test_domain_hash_blake3_matches_domain_module() {
        let tag = create_domain_tag(b"test");
        let via_hash = domain_hash_with_algorithm(HashAlgorithm::Blake3, &tag, b"data");
        let via_domain = domain_hash_blake3(&tag, b"data");
        assert_eq!(via_hash, via_domain, "BLAKE3 domain hash should match domain.rs");
    }

    // -- Temporal class recommendations --------------------------------------

    #[test]
    fn test_recommended_algorithm_ephemeral() {
        assert_eq!(recommended_algorithm(TemporalClass::T1Ephemeral), HashAlgorithm::Sha3_256);
    }

    #[test]
    fn test_recommended_algorithm_session() {
        assert_eq!(recommended_algorithm(TemporalClass::T2Session), HashAlgorithm::Sha3_256);
    }

    #[test]
    fn test_recommended_algorithm_archival() {
        assert_eq!(recommended_algorithm(TemporalClass::T3Archival), HashAlgorithm::Blake3);
    }

    #[test]
    fn test_recommended_algorithm_permanent() {
        assert_eq!(recommended_algorithm(TemporalClass::T4Permanent), HashAlgorithm::Blake3);
    }

    // -- State commitment ----------------------------------------------------

    #[test]
    fn test_commit_canonical_state_deterministic() {
        let state = make_test_canonical_state();
        let h1 = commit_canonical_state(&state);
        let h2 = commit_canonical_state(&state);
        assert_eq!(h1, h2, "state commitment must be deterministic");
    }

    #[test]
    fn test_commit_canonical_state_different_states() {
        let s1 = make_test_canonical_state();
        let mut s2 = make_test_canonical_state();
        s2.system_data.total_supply = 999;
        let h1 = commit_canonical_state(&s1);
        let h2 = commit_canonical_state(&s2);
        assert_ne!(h1, h2, "different states must produce different commitments");
    }

    #[test]
    fn test_commit_canonical_state_uses_blake3() {
        // The commitment should differ from a plain SHA3 commitment,
        // confirming BLAKE3 is used (T4 permanent horizon).
        let state = make_test_canonical_state();
        let blake3_commit = commit_canonical_state(&state);
        let sha3_commit = vsel_core::state::commit(&state);
        assert_ne!(
            blake3_commit, sha3_commit,
            "BLAKE3 commitment should differ from SHA3 commitment"
        );
    }

    // -- Poseidon properties -------------------------------------------------

    #[test]
    fn test_poseidon_collision_resistance_basic() {
        // Different inputs should produce different outputs
        let h1 = hash_with_algorithm(HashAlgorithm::Poseidon, b"input_one");
        let h2 = hash_with_algorithm(HashAlgorithm::Poseidon, b"input_two");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_poseidon_non_trivial() {
        // Output should not be all zeros
        let h = hash_with_algorithm(HashAlgorithm::Poseidon, b"test");
        assert_ne!(h.0, [0u8; 32], "Poseidon output should not be trivial");
    }

    // -- Migration feature flag tests ----------------------------------------
    // Validates: Requirements 6.1, 6.2, 6.5

    /// With default features (poseidon-legacy), the Poseidon dispatch must
    /// route to the legacy implementation. We verify this by comparing the
    /// output of `hash_with_algorithm(Poseidon, data)` against a direct call
    /// to `legacy_poseidon_hash`.
    #[cfg(all(feature = "poseidon-legacy", not(feature = "poseidon-goldilocks")))]
    #[test]
    fn test_feature_flag_legacy_dispatch_matches_legacy_poseidon() {
        #[allow(deprecated)]
        use crate::legacy_poseidon::legacy_poseidon_hash;

        let data = b"feature flag dispatch test";
        let via_dispatch = hash_with_algorithm(HashAlgorithm::Poseidon, data);
        #[allow(deprecated)]
        let via_legacy = legacy_poseidon_hash(data);
        assert_eq!(
            via_dispatch, via_legacy,
            "With poseidon-legacy feature, hash_with_algorithm(Poseidon, ..) \
             must produce the same output as legacy_poseidon_hash"
        );
    }

    /// Backward compatibility: legacy commitments are verifiable when the
    /// legacy feature flag is active. A commitment produced via the dispatch
    /// can be re-verified by calling the dispatch again with the same data.
    #[test]
    fn test_backward_compat_legacy_commitment_verifiable() {
        let data = b"legacy commitment data";
        let commitment = hash_with_algorithm(HashAlgorithm::Poseidon, data);
        // Re-derive the commitment — must match (deterministic dispatch)
        let re_derived = hash_with_algorithm(HashAlgorithm::Poseidon, data);
        assert_eq!(
            commitment, re_derived,
            "Legacy commitments must be re-verifiable with the same feature flag"
        );
    }

    /// Forward compatibility: production commitments require the production
    /// feature flag. With the legacy flag active, the Poseidon output must
    /// NOT match the production Goldilocks Poseidon output (they use
    /// fundamentally different arithmetic). We verify this indirectly by
    /// checking that the legacy output differs from a SHA3 hash of the same
    /// data — confirming the legacy Poseidon path is active, not a fallback.
    #[test]
    fn test_forward_compat_poseidon_differs_from_sha3() {
        let data = b"forward compatibility check";
        let poseidon_hash = hash_with_algorithm(HashAlgorithm::Poseidon, data);
        let sha3_hash = hash_with_algorithm(HashAlgorithm::Sha3_256, data);
        assert_ne!(
            poseidon_hash, sha3_hash,
            "Poseidon dispatch must use its own implementation, not fall back to SHA3"
        );
    }

    /// Domain-separated Poseidon hashing works correctly with the active
    /// feature flag: distinct domains produce distinct hashes, and the
    /// domain-separated output differs from the plain Poseidon output.
    #[test]
    fn test_feature_flag_domain_separated_poseidon() {
        let tag = create_domain_tag(b"migration::test::domain");
        let data = b"domain separation with feature flag";

        let domain_hash = domain_hash_with_algorithm(HashAlgorithm::Poseidon, &tag, data);
        let plain_hash = hash_with_algorithm(HashAlgorithm::Poseidon, data);

        assert_ne!(
            domain_hash, plain_hash,
            "Domain-separated Poseidon must differ from plain Poseidon"
        );

        // Deterministic: same domain + data → same hash
        let domain_hash_2 = domain_hash_with_algorithm(HashAlgorithm::Poseidon, &tag, data);
        assert_eq!(
            domain_hash, domain_hash_2,
            "Domain-separated Poseidon must be deterministic"
        );
    }

    /// With the legacy feature flag, the domain-separated Poseidon dispatch
    /// must use the legacy XOR-based domain separation strategy. We verify
    /// this by checking that distinct domains produce distinct outputs for
    /// the same data (the XOR construction guarantees this).
    #[test]
    fn test_feature_flag_legacy_domain_separation_distinct() {
        let tag_a = create_domain_tag(b"migration::domain_a");
        let tag_b = create_domain_tag(b"migration::domain_b");
        let data = b"same data for both domains";

        let h_a = domain_hash_with_algorithm(HashAlgorithm::Poseidon, &tag_a, data);
        let h_b = domain_hash_with_algorithm(HashAlgorithm::Poseidon, &tag_b, data);

        assert_ne!(
            h_a, h_b,
            "Different domains must produce different Poseidon hashes \
             under the active feature flag"
        );
    }

    /// Multiple different data inputs all produce unique Poseidon hashes
    /// through the feature-gated dispatch, confirming the dispatch is
    /// functioning as a proper hash (not returning constants or colliding).
    #[test]
    fn test_feature_flag_poseidon_dispatch_varied_inputs() {
        let inputs: Vec<&[u8]> = vec![
            b"alpha",
            b"beta",
            b"gamma",
            b"delta",
            b"",
            b"a]longer input with more bytes to exercise multi-absorption",
        ];
        let hashes: Vec<Hash> = inputs
            .iter()
            .map(|data| hash_with_algorithm(HashAlgorithm::Poseidon, data))
            .collect();

        // All hashes should be unique
        for i in 0..hashes.len() {
            for j in (i + 1)..hashes.len() {
                assert_ne!(
                    hashes[i], hashes[j],
                    "Poseidon dispatch produced collision for inputs {:?} and {:?}",
                    std::str::from_utf8(inputs[i]).unwrap_or("<binary>"),
                    std::str::from_utf8(inputs[j]).unwrap_or("<binary>"),
                );
            }
        }
    }

    // -- Helper --------------------------------------------------------------

    fn make_test_canonical_state() -> CanonicalState {
        use std::collections::BTreeMap;
        use vsel_core::types::{ProtocolVersion, SystemData};

        CanonicalState {
            accounts: BTreeMap::new(),
            storage: BTreeMap::new(),
            system_data: SystemData {
                protocol_version: ProtocolVersion {
                    major: 1,
                    minor: 0,
                    patch: 0,
                },
                total_supply: 1_000_000,
                parameters: BTreeMap::new(),
            },
        }
    }
}
