//! Domain separation for all cryptographic operations.
//!
//! Derived from: CRYPTOGRAPHIC_MODEL.md, LONG_TERM_SECURITY_MODEL.md.
//!
//! Domain separation prevents cross-protocol replay by ensuring that
//! `Hash(domain | data)` produces distinct outputs for distinct contexts,
//! even when the raw `data` is identical.
//!
//! Requirements: 7.4 (PROOF-3 domain separation), 10.3 (domain-separated hashing).

use sha3::{Digest, Sha3_256};
use vsel_core::types::{DomainTag, Hash};

// ---------------------------------------------------------------------------
// Well-known domain tags — unique per cryptographic context
// ---------------------------------------------------------------------------

/// Domain tag for state commitment operations: `Commit(C) = Hash(Encode(C))`.
pub const DOMAIN_STATE_COMMITMENT: &[u8] = b"VSEL::v1::state_commitment";

/// Domain tag for trace commitment chain: `h_{i+1} = Hash(h_i | Commit(e_i))`.
pub const DOMAIN_TRACE_COMMITMENT: &[u8] = b"VSEL::v1::trace_commitment";

/// Domain tag for proof generation and verification.
pub const DOMAIN_PROOF: &[u8] = b"VSEL::v1::proof";

/// Domain tag for hybrid signature operations.
pub const DOMAIN_SIGNATURE: &[u8] = b"VSEL::v1::signature";

/// Domain tag for key derivation.
pub const DOMAIN_KEY_DERIVATION: &[u8] = b"VSEL::v1::key_derivation";

/// Domain tag for witness binding.
pub const DOMAIN_WITNESS: &[u8] = b"VSEL::v1::witness";

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/// Create a domain tag by hashing the context string.
///
/// `DomainTag(SHA3-256(context))` — unique and non-reusable across contexts.
/// Two distinct context byte-strings always produce distinct tags (collision
/// resistance of SHA3-256).
pub fn create_domain_tag(context: &[u8]) -> DomainTag {
    let mut hasher = Sha3_256::new();
    hasher.update(context);
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    DomainTag(Hash(bytes))
}

/// Domain-separated hashing using SHA3-256.
///
/// Computes `SHA3-256(domain_tag_bytes || data)`.
/// This is the default hash used for most protocol operations.
pub fn domain_hash(domain: &DomainTag, data: &[u8]) -> Hash {
    let mut hasher = Sha3_256::new();
    hasher.update(&(domain.0).0);
    hasher.update(data);
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    Hash(bytes)
}

/// Domain-separated hashing using BLAKE3.
///
/// Computes `BLAKE3(domain_tag_bytes || data)`.
/// Preferred for long-term commitments (archival / T3-T4 horizon).
pub fn domain_hash_blake3(domain: &DomainTag, data: &[u8]) -> Hash {
    let mut input = Vec::with_capacity(32 + data.len());
    input.extend_from_slice(&(domain.0).0);
    input.extend_from_slice(data);
    let result = blake3::hash(&input);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(result.as_bytes());
    Hash(bytes)
}

/// Verify that two domain tags are distinct.
///
/// Returns `true` when the tags differ — i.e. the two contexts are properly
/// separated. This is the building block for cross-protocol replay prevention:
/// if `verify_domain_separation(tag_a, tag_b)` returns `true`, data hashed
/// under `tag_a` cannot be confused with data hashed under `tag_b`.
pub fn verify_domain_separation(tag1: &DomainTag, tag2: &DomainTag) -> bool {
    tag1 != tag2
}

// ---------------------------------------------------------------------------
// Lazy well-known tag constructors (convenience)
// ---------------------------------------------------------------------------

/// Pre-built domain tag for state commitments.
pub fn state_commitment_tag() -> DomainTag {
    create_domain_tag(DOMAIN_STATE_COMMITMENT)
}

/// Pre-built domain tag for trace commitments.
pub fn trace_commitment_tag() -> DomainTag {
    create_domain_tag(DOMAIN_TRACE_COMMITMENT)
}

/// Pre-built domain tag for proofs.
pub fn proof_tag() -> DomainTag {
    create_domain_tag(DOMAIN_PROOF)
}

/// Pre-built domain tag for signatures.
pub fn signature_tag() -> DomainTag {
    create_domain_tag(DOMAIN_SIGNATURE)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- create_domain_tag ---------------------------------------------------

    #[test]
    fn test_create_domain_tag_deterministic() {
        let tag1 = create_domain_tag(b"context_a");
        let tag2 = create_domain_tag(b"context_a");
        assert_eq!(tag1, tag2, "same context must produce same tag");
    }

    #[test]
    fn test_create_domain_tag_distinct_contexts() {
        let tag_a = create_domain_tag(b"context_a");
        let tag_b = create_domain_tag(b"context_b");
        assert_ne!(
            tag_a, tag_b,
            "different contexts must produce different tags"
        );
    }

    #[test]
    fn test_create_domain_tag_empty_context() {
        let tag = create_domain_tag(b"");
        // Must still produce a valid 32-byte hash.
        assert_eq!((tag.0).0.len(), 32);
    }

    // -- domain_hash (SHA3-256) ----------------------------------------------

    #[test]
    fn test_domain_hash_deterministic() {
        let tag = create_domain_tag(b"test");
        let h1 = domain_hash(&tag, b"data");
        let h2 = domain_hash(&tag, b"data");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_domain_hash_different_data() {
        let tag = create_domain_tag(b"test");
        let h1 = domain_hash(&tag, b"data_a");
        let h2 = domain_hash(&tag, b"data_b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_domain_hash_different_domains() {
        let tag_a = create_domain_tag(b"domain_a");
        let tag_b = create_domain_tag(b"domain_b");
        let h1 = domain_hash(&tag_a, b"same_data");
        let h2 = domain_hash(&tag_b, b"same_data");
        assert_ne!(h1, h2, "same data under different domains must differ");
    }

    // -- domain_hash_blake3 --------------------------------------------------

    #[test]
    fn test_domain_hash_blake3_deterministic() {
        let tag = create_domain_tag(b"test");
        let h1 = domain_hash_blake3(&tag, b"data");
        let h2 = domain_hash_blake3(&tag, b"data");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_domain_hash_blake3_different_domains() {
        let tag_a = create_domain_tag(b"domain_a");
        let tag_b = create_domain_tag(b"domain_b");
        let h1 = domain_hash_blake3(&tag_a, b"same_data");
        let h2 = domain_hash_blake3(&tag_b, b"same_data");
        assert_ne!(
            h1, h2,
            "same data under different domains must differ (blake3)"
        );
    }

    #[test]
    fn test_sha3_and_blake3_differ() {
        let tag = create_domain_tag(b"test");
        let sha = domain_hash(&tag, b"data");
        let blk = domain_hash_blake3(&tag, b"data");
        assert_ne!(sha, blk, "SHA3 and BLAKE3 must produce different outputs");
    }

    // -- verify_domain_separation --------------------------------------------

    #[test]
    fn test_verify_domain_separation_distinct() {
        let tag_a = create_domain_tag(b"alpha");
        let tag_b = create_domain_tag(b"beta");
        assert!(verify_domain_separation(&tag_a, &tag_b));
    }

    #[test]
    fn test_verify_domain_separation_identical() {
        let tag = create_domain_tag(b"same");
        assert!(!verify_domain_separation(&tag, &tag));
    }

    // -- cross-protocol replay prevention ------------------------------------

    #[test]
    fn test_cross_protocol_replay_prevention() {
        // A proof hash from one domain must not be valid in another.
        let proof_tag = create_domain_tag(DOMAIN_PROOF);
        let sig_tag = create_domain_tag(DOMAIN_SIGNATURE);
        assert!(verify_domain_separation(&proof_tag, &sig_tag));

        let payload = b"important_payload";
        let h_proof = domain_hash(&proof_tag, payload);
        let h_sig = domain_hash(&sig_tag, payload);
        assert_ne!(h_proof, h_sig, "cross-domain hashes must differ");
    }

    // -- well-known tags are all distinct ------------------------------------

    #[test]
    fn test_well_known_tags_all_distinct() {
        let tags = [
            state_commitment_tag(),
            trace_commitment_tag(),
            proof_tag(),
            signature_tag(),
            create_domain_tag(DOMAIN_KEY_DERIVATION),
            create_domain_tag(DOMAIN_WITNESS),
        ];
        for i in 0..tags.len() {
            for j in (i + 1)..tags.len() {
                assert!(
                    verify_domain_separation(&tags[i], &tags[j]),
                    "well-known tags {} and {} must be distinct",
                    i,
                    j,
                );
            }
        }
    }

    // -- empty data ----------------------------------------------------------

    #[test]
    fn test_domain_hash_empty_data() {
        let tag = create_domain_tag(b"test");
        let h = domain_hash(&tag, b"");
        assert_eq!(h.0.len(), 32);
    }

    #[test]
    fn test_domain_hash_blake3_empty_data() {
        let tag = create_domain_tag(b"test");
        let h = domain_hash_blake3(&tag, b"");
        assert_eq!(h.0.len(), 32);
    }
}
