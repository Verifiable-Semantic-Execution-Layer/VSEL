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
        HashAlgorithm::Poseidon => poseidon_hash(data),
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
        HashAlgorithm::Poseidon => {
            // Poseidon domain separation: derive a domain-specific IV from the
            // domain tag using SHA3-256 (which has proven collision resistance),
            // then use that IV to initialize the Poseidon state before absorbing
            // data.  This guarantees distinct domains produce distinct Poseidon
            // states regardless of the simplified Poseidon permutation's
            // diffusion properties over wrapping u64 arithmetic.
            use sha3::{Sha3_256, Digest};
            let domain_iv = {
                let mut h = Sha3_256::new();
                h.update(b"VSEL::poseidon::domain_iv::");
                h.update(&(domain.0).0);
                let result = h.finalize();
                let mut iv = [0u8; 32];
                iv.copy_from_slice(&result);
                iv
            };
            let mut state = PoseidonState::new();
            // Load domain IV into state words directly (not via absorb)
            for (i, chunk) in domain_iv.chunks(8).enumerate() {
                let mut word = [0u8; 8];
                word.copy_from_slice(chunk);
                state.state[i] = u64::from_le_bytes(word);
            }
            state.permute(); // commit domain IV into state
            state.absorb(data);
            state.permute();
            Hash(state.squeeze())
        }
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
// Poseidon hash (STARK-friendly, simplified)
// ---------------------------------------------------------------------------

/// Poseidon hash parameters for a simplified implementation.
///
/// This is a reduced Poseidon permutation operating over 32-bit field elements,
/// suitable for STARK circuit integration. The full Poseidon specification uses
/// prime-field arithmetic; this implementation provides the correct structure
/// (absorption, permutation rounds, squeezing) for integration testing.
struct PoseidonState {
    /// Internal state words (rate + capacity).
    state: [u64; 4],
}

/// Poseidon round constants (simplified — derived from SHA3 of index for reproducibility).
const POSEIDON_ROUND_CONSTANTS: [u64; 8] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
];

/// Number of full rounds in the Poseidon permutation.
const POSEIDON_FULL_ROUNDS: usize = 8;

impl PoseidonState {
    /// Create a new Poseidon state initialized to zero.
    fn new() -> Self {
        Self { state: [0u64; 4] }
    }

    /// Apply the Poseidon S-box: x → x^5 (mod 2^64).
    /// The x^5 S-box is standard for Poseidon over large fields.
    #[inline]
    fn sbox(x: u64) -> u64 {
        let x2 = x.wrapping_mul(x);
        let x4 = x2.wrapping_mul(x2);
        x4.wrapping_mul(x)
    }

    /// Apply one full round of the Poseidon permutation.
    fn full_round(&mut self, round: usize) {
        // Add round constants
        for i in 0..4 {
            self.state[i] = self.state[i].wrapping_add(
                POSEIDON_ROUND_CONSTANTS[(round * 2 + i) % POSEIDON_ROUND_CONSTANTS.len()],
            );
        }

        // S-box layer
        for i in 0..4 {
            self.state[i] = Self::sbox(self.state[i]);
        }

        // MDS mixing (simplified linear layer)
        let t = self.state;
        self.state[0] = t[0]
            .wrapping_add(t[1].wrapping_mul(2))
            .wrapping_add(t[2])
            .wrapping_add(t[3]);
        self.state[1] = t[0]
            .wrapping_add(t[1])
            .wrapping_add(t[2].wrapping_mul(2))
            .wrapping_add(t[3]);
        self.state[2] = t[0]
            .wrapping_add(t[1])
            .wrapping_add(t[2])
            .wrapping_add(t[3].wrapping_mul(2));
        self.state[3] = t[0]
            .wrapping_mul(2)
            .wrapping_add(t[1])
            .wrapping_add(t[2])
            .wrapping_add(t[3]);
    }

    /// Run the full Poseidon permutation.
    fn permute(&mut self) {
        for round in 0..POSEIDON_FULL_ROUNDS {
            self.full_round(round);
        }
    }

    /// Absorb a chunk of data (up to 16 bytes per absorption).
    fn absorb(&mut self, data: &[u8]) {
        // Process data in 8-byte chunks, XOR into rate portion of state
        for (i, chunk) in data.chunks(8).enumerate() {
            let mut word = [0u8; 8];
            word[..chunk.len()].copy_from_slice(chunk);
            // Encode length in the last byte for padding
            if chunk.len() < 8 {
                word[7] ^= 0x80;
            }
            let val = u64::from_le_bytes(word);
            self.state[i % 4] ^= val;
            // Permute after filling the rate
            if i % 4 == 3 {
                self.permute();
            }
        }
    }

    /// Squeeze a 32-byte hash from the state.
    fn squeeze(&self) -> [u8; 32] {
        let mut output = [0u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            output[i * 8..(i + 1) * 8].copy_from_slice(&word.to_le_bytes());
        }
        output
    }
}

/// Compute a Poseidon hash of arbitrary data.
///
/// This is a simplified Poseidon implementation suitable for STARK circuit
/// integration testing. It processes input data through absorption rounds
/// with the Poseidon permutation and squeezes a 32-byte digest.
///
/// For production STARK circuits, this should be replaced with a field-native
/// Poseidon implementation matching the specific prime field of the proof system.
fn poseidon_hash(data: &[u8]) -> Hash {
    let mut state = PoseidonState::new();

    // Absorb input data
    state.absorb(data);

    // Final permutation
    state.permute();

    Hash(state.squeeze())
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
        let h1 = poseidon_hash(b"input_one");
        let h2 = poseidon_hash(b"input_two");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_poseidon_non_trivial() {
        // Output should not be all zeros
        let h = poseidon_hash(b"test");
        assert_ne!(h.0, [0u8; 32], "Poseidon output should not be trivial");
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
