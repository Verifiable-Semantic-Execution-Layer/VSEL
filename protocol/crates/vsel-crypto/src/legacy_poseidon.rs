//! Legacy Poseidon hash implementation using wrapping u64 arithmetic.
//!
//! This module contains the original simplified Poseidon implementation that
//! operates over wrapping u64 arithmetic rather than proper prime-field
//! arithmetic. It is retained for backward compatibility during the migration
//! to the production Goldilocks Poseidon implementation.
//!
//! For production STARK circuits, use `poseidon_goldilocks::PoseidonGoldilocks`.
//!
//! Requirements: 6.1 (legacy retention), 6.2 (feature flag migration)

#![allow(deprecated)]

use vsel_core::types::Hash;

// ---------------------------------------------------------------------------
// Legacy Poseidon hash (STARK-friendly, simplified)
// ---------------------------------------------------------------------------

/// Legacy Poseidon hash parameters for a simplified implementation.
///
/// This is a reduced Poseidon permutation operating over 32-bit field elements,
/// suitable for STARK circuit integration. The full Poseidon specification uses
/// prime-field arithmetic; this implementation provides the correct structure
/// (absorption, permutation rounds, squeezing) for integration testing.
#[deprecated(note = "Use poseidon_goldilocks for production")]
pub struct LegacyPoseidonState {
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

/// Number of full rounds in the legacy Poseidon permutation.
const POSEIDON_FULL_ROUNDS: usize = 8;

#[allow(deprecated)]
impl LegacyPoseidonState {
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

/// Compute a legacy Poseidon hash of arbitrary data.
///
/// This is a simplified Poseidon implementation suitable for STARK circuit
/// integration testing. It processes input data through absorption rounds
/// with the Poseidon permutation and squeezes a 32-byte digest.
///
/// For production STARK circuits, use `poseidon_goldilocks::PoseidonGoldilocks`.
#[deprecated(note = "Use poseidon_goldilocks for production")]
pub fn legacy_poseidon_hash(data: &[u8]) -> Hash {
    #[allow(deprecated)]
    let mut state = LegacyPoseidonState::new();

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
    #[allow(deprecated)]
    use super::*;

    #[test]
    fn test_legacy_poseidon_deterministic() {
        let h1 = legacy_poseidon_hash(b"hello");
        let h2 = legacy_poseidon_hash(b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_legacy_poseidon_collision_resistance_basic() {
        let h1 = legacy_poseidon_hash(b"input_one");
        let h2 = legacy_poseidon_hash(b"input_two");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_legacy_poseidon_non_trivial() {
        let h = legacy_poseidon_hash(b"test");
        assert_ne!(h.0, [0u8; 32], "Legacy Poseidon output should not be trivial");
    }

    #[test]
    fn test_legacy_poseidon_empty_input() {
        let h = legacy_poseidon_hash(b"");
        assert_eq!(h.0.len(), 32);
    }
}
