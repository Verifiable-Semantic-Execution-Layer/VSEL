//! Commitment chain — incremental hash chaining for trace integrity.
//!
//! Derived from: EXECUTION_TRACE_MODEL.md §4, TRACE_SUFFICIENCY.md §6.
//! Requirements: 6.2, 6.10
//!
//! The commitment chain ensures sequential integrity:
//!   h_{i+1} = Hash(h_i | Commit(e_i))
//!
//! Properties:
//! - No insertion: inserting an entry changes all subsequent chain hashes
//! - No removal: removing an entry breaks the chain
//! - No reordering: swapping entries changes chain hashes
//! - Temporal consistency: monotonic timestamps and sequence numbers

use sha3::{Digest, Sha3_256};

use vsel_core::types::Hash;

// ---------------------------------------------------------------------------
// Chain hash computation
// ---------------------------------------------------------------------------

/// Compute the next chain hash: `h_{i+1} = Hash(h_i | Commit(e_i))`.
///
/// This is the core primitive for incremental commitment chaining.
/// The `entry_commitment` is the hash of the trace entry's content
/// (computed by `commit_entry` in engine.rs).
///
/// Requirement 6.2: incremental commitment chaining with sequential integrity.
pub fn compute_chain_hash(previous_chain_hash: &Hash, entry_commitment: &Hash) -> Hash {
    let mut hasher = Sha3_256::new();

    // Domain separator for chain hash computation
    hasher.update(b"VSEL-CHAIN-HASH-V1");

    // Previous chain hash (h_i)
    hasher.update(&previous_chain_hash.0);

    // Entry commitment (Commit(e_i))
    hasher.update(&entry_commitment.0);

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    Hash(hash)
}

/// The genesis chain hash — the starting point for the commitment chain.
///
/// For the first entry (index 0), the previous chain hash is the zero hash.
pub fn genesis_chain_hash() -> Hash {
    Hash([0u8; 32])
}

// ---------------------------------------------------------------------------
// Temporal consistency checks
// ---------------------------------------------------------------------------

/// Verify temporal consistency between consecutive trace entries.
///
/// Requirement 6.10:
/// - `meta_{i+1}.time >= meta_i.time` (monotonic timestamps)
/// - `entry_{i+1}.index == entry_i.index + 1` (monotonic sequence numbers)
pub fn check_temporal_consistency(
    prev_timestamp: u64,
    prev_index: u64,
    curr_timestamp: u64,
    curr_index: u64,
) -> bool {
    curr_timestamp >= prev_timestamp && curr_index == prev_index + 1
}

// ---------------------------------------------------------------------------
// Chain verification
// ---------------------------------------------------------------------------

/// Verify a sequence of chain hashes given entry commitments.
///
/// Starting from `genesis` (zero hash), recomputes each chain hash
/// and compares against the expected values.
///
/// Returns `true` if all chain hashes match.
pub fn verify_chain(entry_commitments: &[Hash], expected_chain_hashes: &[Hash]) -> bool {
    if entry_commitments.len() != expected_chain_hashes.len() {
        return false;
    }

    let mut chain_hash = genesis_chain_hash();

    for (entry_commit, expected) in entry_commitments.iter().zip(expected_chain_hashes.iter()) {
        chain_hash = compute_chain_hash(&chain_hash, entry_commit);
        if chain_hash != *expected {
            return false;
        }
    }

    true
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_hash_deterministic() {
        let prev = Hash([0u8; 32]);
        let entry = Hash([1u8; 32]);
        let h1 = compute_chain_hash(&prev, &entry);
        let h2 = compute_chain_hash(&prev, &entry);
        assert_eq!(h1, h2, "chain hash must be deterministic");
    }

    #[test]
    fn test_chain_hash_changes_with_previous() {
        let entry = Hash([1u8; 32]);
        let h1 = compute_chain_hash(&Hash([0u8; 32]), &entry);
        let h2 = compute_chain_hash(&Hash([2u8; 32]), &entry);
        assert_ne!(
            h1, h2,
            "different previous hashes must produce different chain hashes"
        );
    }

    #[test]
    fn test_chain_hash_changes_with_entry() {
        let prev = Hash([0u8; 32]);
        let h1 = compute_chain_hash(&prev, &Hash([1u8; 32]));
        let h2 = compute_chain_hash(&prev, &Hash([2u8; 32]));
        assert_ne!(
            h1, h2,
            "different entry commitments must produce different chain hashes"
        );
    }

    #[test]
    fn test_genesis_chain_hash_is_zero() {
        assert_eq!(genesis_chain_hash(), Hash([0u8; 32]));
    }

    #[test]
    fn test_temporal_consistency_valid() {
        assert!(check_temporal_consistency(100, 0, 200, 1));
        assert!(check_temporal_consistency(100, 0, 100, 1)); // equal timestamps OK
    }

    #[test]
    fn test_temporal_consistency_invalid_timestamp() {
        assert!(!check_temporal_consistency(200, 0, 100, 1)); // timestamp decreased
    }

    #[test]
    fn test_temporal_consistency_invalid_index() {
        assert!(!check_temporal_consistency(100, 0, 200, 0)); // index didn't advance
        assert!(!check_temporal_consistency(100, 0, 200, 2)); // index skipped
    }

    #[test]
    fn test_verify_chain_empty() {
        assert!(verify_chain(&[], &[]));
    }

    #[test]
    fn test_verify_chain_single() {
        let entry = Hash([42u8; 32]);
        let expected = compute_chain_hash(&genesis_chain_hash(), &entry);
        assert!(verify_chain(&[entry], &[expected]));
    }

    #[test]
    fn test_verify_chain_multiple() {
        let e1 = Hash([1u8; 32]);
        let e2 = Hash([2u8; 32]);
        let e3 = Hash([3u8; 32]);

        let h1 = compute_chain_hash(&genesis_chain_hash(), &e1);
        let h2 = compute_chain_hash(&h1, &e2);
        let h3 = compute_chain_hash(&h2, &e3);

        assert!(verify_chain(&[e1, e2, e3], &[h1, h2, h3]));
    }

    #[test]
    fn test_verify_chain_tampered() {
        let e1 = Hash([1u8; 32]);
        let e2 = Hash([2u8; 32]);

        let h1 = compute_chain_hash(&genesis_chain_hash(), &e1);
        let h2 = compute_chain_hash(&h1, &e2);

        // Tamper with first chain hash
        let tampered_h1 = Hash([0xFFu8; 32]);
        assert!(!verify_chain(&[e1, e2], &[tampered_h1, h2]));
    }

    #[test]
    fn test_verify_chain_length_mismatch() {
        let e1 = Hash([1u8; 32]);
        let h1 = compute_chain_hash(&genesis_chain_hash(), &e1);
        assert!(!verify_chain(&[e1], &[h1.clone(), h1]));
    }
}
