//! Production Poseidon hash over the Goldilocks field.
//!
//! Implements the Poseidon hash function (Grassi et al., 2021) with field-native
//! arithmetic over the Goldilocks prime p = 2^64 − 2^32 + 1.
//!
//! Parameters for 128-bit security:
//! - State width t = 12 (rate r = 8, capacity c = 4)
//! - Full rounds R_f = 8 (4 at start, 4 at end)
//! - Partial rounds R_p = 22
//! - S-box: x^7 over GoldilocksField
//! - MDS: 12×12 Cauchy matrix over GoldilocksField
//! - Round constants: NUMS construction via SHA-256
//!
//! Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 5.8, 5.9, 5.10

use sha2::{Digest, Sha256};
use vsel_core::types::{DomainTag, Hash};

use crate::goldilocks::GoldilocksField;

// ---------------------------------------------------------------------------
// Poseidon parameters
// ---------------------------------------------------------------------------

/// State width: t = 12 field elements.
pub const STATE_WIDTH: usize = 12;

/// Rate: number of field elements absorbed per permutation cycle.
pub const RATE: usize = 8;

/// Capacity: security margin (c = t - r = 4).
pub const CAPACITY: usize = 4;

/// Number of full rounds at the beginning of the permutation.
pub const HALF_FULL_ROUNDS: usize = 4;

/// Number of partial rounds in the middle of the permutation.
pub const PARTIAL_ROUNDS: usize = 22;

/// Total number of rounds: R_f + R_p = 8 + 22 = 30.
pub const TOTAL_ROUNDS: usize = HALF_FULL_ROUNDS * 2 + PARTIAL_ROUNDS;

// ---------------------------------------------------------------------------
// PoseidonGoldilocks
// ---------------------------------------------------------------------------

/// Poseidon hash over the Goldilocks field.
///
/// Provides a field-native Poseidon implementation suitable for STARK circuit
/// integration. All arithmetic is performed over the Goldilocks prime field
/// (p = 2^64 − 2^32 + 1) with proper modular reduction.
///
/// The struct holds precomputed MDS matrix and round constants, generated
/// deterministically from NUMS (nothing-up-my-sleeve) constructions.
pub struct PoseidonGoldilocks {
    /// 12×12 MDS (Maximum Distance Separable) Cauchy matrix.
    mds_matrix: [[GoldilocksField; STATE_WIDTH]; STATE_WIDTH],
    /// Round constants: one array of STATE_WIDTH elements per round.
    round_constants: Vec<[GoldilocksField; STATE_WIDTH]>,
}

impl PoseidonGoldilocks {
    /// Create a new PoseidonGoldilocks instance with precomputed parameters.
    ///
    /// Generates the MDS matrix and round constants deterministically using
    /// NUMS constructions. This is typically called once and reused.
    pub fn new() -> Self {
        let mds_matrix = generate_mds_matrix();
        let round_constants = generate_round_constants();
        Self {
            mds_matrix,
            round_constants,
        }
    }

    /// Apply the Poseidon permutation to a state of STATE_WIDTH field elements.
    ///
    /// The permutation consists of:
    /// 1. HALF_FULL_ROUNDS full rounds (S-box on all elements)
    /// 2. PARTIAL_ROUNDS partial rounds (S-box on first element only)
    /// 3. HALF_FULL_ROUNDS full rounds (S-box on all elements)
    pub fn permute(&self, state: &mut [GoldilocksField; STATE_WIDTH]) {
        let mut round_idx = 0;

        // First half of full rounds
        for _ in 0..HALF_FULL_ROUNDS {
            self.full_round(state, round_idx);
            round_idx += 1;
        }

        // Partial rounds
        for _ in 0..PARTIAL_ROUNDS {
            self.partial_round(state, round_idx);
            round_idx += 1;
        }

        // Second half of full rounds
        for _ in 0..HALF_FULL_ROUNDS {
            self.full_round(state, round_idx);
            round_idx += 1;
        }
    }

    /// Hash field elements directly (for STARK circuit use).
    ///
    /// Uses the sponge construction: absorb rate-sized chunks of input
    /// elements, permute after each absorption, squeeze the first element.
    ///
    /// Requirements: 5.9
    pub fn hash_field(&self, elements: &[GoldilocksField]) -> GoldilocksField {
        let mut state = [GoldilocksField::ZERO; STATE_WIDTH];

        // Absorb input in rate-sized chunks (Req 5.10: multi-absorption)
        for chunk in elements.chunks(RATE) {
            for (i, &elem) in chunk.iter().enumerate() {
                state[i] = state[i].add(elem);
            }
            self.permute(&mut state);
        }

        // If input was empty, still permute once for a valid hash
        if elements.is_empty() {
            self.permute(&mut state);
        }

        // Squeeze: return the first element of the state
        state[0]
    }

    /// Hash arbitrary bytes with injective encoding to field elements.
    ///
    /// Encoding scheme (injective):
    /// 1. Prepend the byte length as a field element (ensures distinct lengths
    ///    produce distinct field element sequences).
    /// 2. Pack bytes into field elements: each field element holds up to 7 bytes
    ///    (56 bits), ensuring the value is always < p. The 7-byte limit guarantees
    ///    injectivity since 2^56 < p.
    /// 3. Hash the resulting field element sequence via `hash_field`.
    ///
    /// The output is a 32-byte Hash constructed from 4 squeeze operations.
    ///
    /// Requirements: 5.7
    pub fn hash_bytes(&self, data: &[u8]) -> Hash {
        let field_elements = encode_bytes_to_field_elements(data);

        // Use sponge to produce enough output for a 32-byte hash.
        // We need 4 field elements (each contributes 8 bytes).
        let mut state = [GoldilocksField::ZERO; STATE_WIDTH];

        // Absorb
        for chunk in field_elements.chunks(RATE) {
            for (i, &elem) in chunk.iter().enumerate() {
                state[i] = state[i].add(elem);
            }
            self.permute(&mut state);
        }

        // If no elements were absorbed (empty input still has length prefix),
        // this case is handled by encode_bytes_to_field_elements always
        // producing at least one element (the length prefix).

        // Squeeze 4 field elements to produce 32 bytes
        let mut output = [0u8; 32];
        for i in 0..4 {
            let bytes = state[i].to_bytes();
            output[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
        }

        Hash(output)
    }

    /// Domain-separated hash over field elements.
    ///
    /// Initializes the sponge capacity with the domain tag, then absorbs
    /// the input elements through the rate portion. This ensures that
    /// different domains produce different hashes for the same input.
    ///
    /// Requirements: 5.6
    pub fn hash_with_domain(
        &self,
        domain: &DomainTag,
        elements: &[GoldilocksField],
    ) -> GoldilocksField {
        let mut state = [GoldilocksField::ZERO; STATE_WIDTH];

        // Initialize capacity with domain tag.
        // Convert the 32-byte domain tag into 4 field elements and place
        // them in the capacity portion of the state (indices RATE..STATE_WIDTH).
        let domain_bytes = &(domain.0).0;
        for i in 0..CAPACITY {
            let start = i * 8;
            let end = start + 8;
            state[RATE + i] = GoldilocksField::from_bytes(&domain_bytes[start..end]);
        }

        // Permute once to mix the domain into the state
        self.permute(&mut state);

        // Absorb input in rate-sized chunks (Req 5.10: multi-absorption)
        for chunk in elements.chunks(RATE) {
            for (i, &elem) in chunk.iter().enumerate() {
                state[i] = state[i].add(elem);
            }
            self.permute(&mut state);
        }

        // If input was empty, the domain-initialized state was already permuted
        if elements.is_empty() {
            self.permute(&mut state);
        }

        // Squeeze
        state[0]
    }

    // -----------------------------------------------------------------------
    // Internal round functions
    // -----------------------------------------------------------------------

    /// Apply a full round: add round constants, S-box on ALL elements, MDS mix.
    #[inline]
    fn full_round(&self, state: &mut [GoldilocksField; STATE_WIDTH], round: usize) {
        // Add round constants
        for i in 0..STATE_WIDTH {
            state[i] = state[i].add(self.round_constants[round][i]);
        }

        // S-box on all elements: x^7
        for i in 0..STATE_WIDTH {
            state[i] = state[i].sbox();
        }

        // MDS matrix multiplication
        self.mds_mix(state);
    }

    /// Apply a partial round: add round constants, S-box on FIRST element only, MDS mix.
    #[inline]
    fn partial_round(&self, state: &mut [GoldilocksField; STATE_WIDTH], round: usize) {
        // Add round constants
        for i in 0..STATE_WIDTH {
            state[i] = state[i].add(self.round_constants[round][i]);
        }

        // S-box on first element only: x^7
        state[0] = state[0].sbox();

        // MDS matrix multiplication
        self.mds_mix(state);
    }

    /// Multiply the state by the MDS matrix.
    #[inline]
    fn mds_mix(&self, state: &mut [GoldilocksField; STATE_WIDTH]) {
        let old = *state;
        for i in 0..STATE_WIDTH {
            let mut acc = GoldilocksField::ZERO;
            for j in 0..STATE_WIDTH {
                acc = acc.add(self.mds_matrix[i][j].mul(old[j]));
            }
            state[i] = acc;
        }
    }
}

impl Default for PoseidonGoldilocks {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// MDS matrix generation — Cauchy matrix construction
// ---------------------------------------------------------------------------

/// Generate the 12×12 MDS Cauchy matrix over GoldilocksField.
///
/// A Cauchy matrix is defined as M[i][j] = 1 / (x_i + y_j) where x_i and y_j
/// are distinct field elements with x_i + y_j ≠ 0 for all i, j.
///
/// We choose x_i = i + 1 and y_j = STATE_WIDTH + j + 1 to ensure all sums
/// are distinct and non-zero.
///
/// Requirements: 5.3
fn generate_mds_matrix() -> [[GoldilocksField; STATE_WIDTH]; STATE_WIDTH] {
    let mut matrix = [[GoldilocksField::ZERO; STATE_WIDTH]; STATE_WIDTH];

    for i in 0..STATE_WIDTH {
        for j in 0..STATE_WIDTH {
            // x_i = i + 1, y_j = STATE_WIDTH + j + 1
            let x_i = GoldilocksField((i + 1) as u64);
            let y_j = GoldilocksField((STATE_WIDTH + j + 1) as u64);
            let sum = x_i.add(y_j);
            // M[i][j] = 1 / (x_i + y_j)
            // sum is always non-zero since x_i ∈ [1,12] and y_j ∈ [13,24],
            // so sum ∈ [14,36], all non-zero in the Goldilocks field.
            matrix[i][j] = sum.inv().expect("MDS Cauchy matrix: sum must be non-zero");
        }
    }

    matrix
}

// ---------------------------------------------------------------------------
// Round constant generation — NUMS construction via SHA-256
// ---------------------------------------------------------------------------

/// Generate round constants using the NUMS (Nothing-Up-My-Sleeve) construction.
///
/// For each round r and element index i:
///   SHA-256("PoseidonGoldilocks_RC_" || r || "_" || i)
///   → take first 8 bytes as little-endian u64
///   → reduce mod p
///
/// This produces TOTAL_ROUNDS arrays of STATE_WIDTH field elements.
///
/// Requirements: 5.4
fn generate_round_constants() -> Vec<[GoldilocksField; STATE_WIDTH]> {
    let mut constants = Vec::with_capacity(TOTAL_ROUNDS);

    for round in 0..TOTAL_ROUNDS {
        let mut round_consts = [GoldilocksField::ZERO; STATE_WIDTH];
        for elem in 0..STATE_WIDTH {
            let input = format!("PoseidonGoldilocks_RC_{}_{}", round, elem);
            let hash = Sha256::digest(input.as_bytes());
            // Take first 8 bytes as little-endian u64, reduce mod p
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&hash[..8]);
            let val = u64::from_le_bytes(bytes);
            round_consts[elem] = GoldilocksField(val % GoldilocksField::MODULUS);
        }
        constants.push(round_consts);
    }

    constants
}

// ---------------------------------------------------------------------------
// Injective byte encoding
// ---------------------------------------------------------------------------

/// Encode bytes into field elements with injective encoding.
///
/// Encoding scheme:
/// 1. First element: byte length as a field element (length prefix).
/// 2. Subsequent elements: pack up to 7 bytes per field element (little-endian).
///    Using 7 bytes (56 bits) ensures the value is always < p ≈ 2^64,
///    guaranteeing a unique field element for each 7-byte chunk.
///
/// This encoding is injective: distinct byte sequences always produce
/// distinct field element sequences, because:
/// - Different lengths → different first element
/// - Same length, different bytes → different packing in some element
///
/// Requirements: 5.7
fn encode_bytes_to_field_elements(data: &[u8]) -> Vec<GoldilocksField> {
    let mut elements = Vec::new();

    // Length prefix
    elements.push(GoldilocksField(data.len() as u64));

    // Pack bytes into field elements, 7 bytes at a time
    for chunk in data.chunks(7) {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        let val = u64::from_le_bytes(buf);
        // val < 2^56 < p, so no reduction needed, but be safe
        elements.push(GoldilocksField(val % GoldilocksField::MODULUS));
    }

    elements
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::create_domain_tag;

    // -- Construction --------------------------------------------------------

    #[test]
    fn test_poseidon_new_does_not_panic() {
        let _poseidon = PoseidonGoldilocks::new();
    }

    #[test]
    fn test_poseidon_default_equals_new() {
        let p1 = PoseidonGoldilocks::new();
        let p2 = PoseidonGoldilocks::default();
        // Both should produce the same hash for the same input
        let input = [GoldilocksField(42)];
        assert_eq!(p1.hash_field(&input), p2.hash_field(&input));
    }

    // -- Parameters ----------------------------------------------------------

    #[test]
    fn test_parameters() {
        assert_eq!(STATE_WIDTH, 12);
        assert_eq!(RATE, 8);
        assert_eq!(CAPACITY, 4);
        assert_eq!(HALF_FULL_ROUNDS, 4);
        assert_eq!(PARTIAL_ROUNDS, 22);
        assert_eq!(TOTAL_ROUNDS, 30);
        assert_eq!(STATE_WIDTH, RATE + CAPACITY);
    }

    // -- MDS matrix ----------------------------------------------------------

    #[test]
    fn test_mds_matrix_all_nonzero() {
        let mds = generate_mds_matrix();
        for i in 0..STATE_WIDTH {
            for j in 0..STATE_WIDTH {
                assert_ne!(
                    mds[i][j],
                    GoldilocksField::ZERO,
                    "MDS[{}][{}] must be non-zero",
                    i,
                    j
                );
            }
        }
    }

    #[test]
    fn test_mds_matrix_deterministic() {
        let mds1 = generate_mds_matrix();
        let mds2 = generate_mds_matrix();
        for i in 0..STATE_WIDTH {
            for j in 0..STATE_WIDTH {
                assert_eq!(mds1[i][j], mds2[i][j]);
            }
        }
    }

    // -- Round constants -----------------------------------------------------

    #[test]
    fn test_round_constants_correct_count() {
        let rc = generate_round_constants();
        assert_eq!(rc.len(), TOTAL_ROUNDS);
    }

    #[test]
    fn test_round_constants_deterministic() {
        let rc1 = generate_round_constants();
        let rc2 = generate_round_constants();
        for r in 0..TOTAL_ROUNDS {
            for i in 0..STATE_WIDTH {
                assert_eq!(rc1[r][i], rc2[r][i]);
            }
        }
    }

    #[test]
    fn test_round_constants_in_field() {
        let rc = generate_round_constants();
        for r in 0..TOTAL_ROUNDS {
            for i in 0..STATE_WIDTH {
                assert!(
                    rc[r][i].0 < GoldilocksField::MODULUS,
                    "Round constant [{}][{}] must be < MODULUS",
                    r,
                    i
                );
            }
        }
    }

    // -- Permutation ---------------------------------------------------------

    #[test]
    fn test_permute_deterministic() {
        let poseidon = PoseidonGoldilocks::new();
        let mut state1 = [GoldilocksField::ZERO; STATE_WIDTH];
        let mut state2 = [GoldilocksField::ZERO; STATE_WIDTH];
        poseidon.permute(&mut state1);
        poseidon.permute(&mut state2);
        assert_eq!(state1, state2);
    }

    #[test]
    fn test_permute_changes_state() {
        let poseidon = PoseidonGoldilocks::new();
        let mut state = [GoldilocksField::ZERO; STATE_WIDTH];
        let original = state;
        poseidon.permute(&mut state);
        assert_ne!(state, original, "Permutation must change the state");
    }

    #[test]
    fn test_permute_different_inputs_different_outputs() {
        let poseidon = PoseidonGoldilocks::new();
        let mut state1 = [GoldilocksField::ZERO; STATE_WIDTH];
        state1[0] = GoldilocksField(1);
        let mut state2 = [GoldilocksField::ZERO; STATE_WIDTH];
        state2[0] = GoldilocksField(2);
        poseidon.permute(&mut state1);
        poseidon.permute(&mut state2);
        assert_ne!(state1, state2);
    }

    #[test]
    fn test_permute_output_in_field() {
        let poseidon = PoseidonGoldilocks::new();
        let mut state = [GoldilocksField::ZERO; STATE_WIDTH];
        state[0] = GoldilocksField(123456789);
        poseidon.permute(&mut state);
        for (i, elem) in state.iter().enumerate() {
            assert!(
                elem.0 < GoldilocksField::MODULUS,
                "State[{}] must be < MODULUS after permutation",
                i
            );
        }
    }

    // -- hash_field ----------------------------------------------------------

    #[test]
    fn test_hash_field_deterministic() {
        let poseidon = PoseidonGoldilocks::new();
        let input = [GoldilocksField(1), GoldilocksField(2), GoldilocksField(3)];
        let h1 = poseidon.hash_field(&input);
        let h2 = poseidon.hash_field(&input);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_field_different_inputs() {
        let poseidon = PoseidonGoldilocks::new();
        let h1 = poseidon.hash_field(&[GoldilocksField(1)]);
        let h2 = poseidon.hash_field(&[GoldilocksField(2)]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hash_field_empty_input() {
        let poseidon = PoseidonGoldilocks::new();
        let h = poseidon.hash_field(&[]);
        assert!(h.0 < GoldilocksField::MODULUS);
    }

    #[test]
    fn test_hash_field_output_in_field() {
        let poseidon = PoseidonGoldilocks::new();
        let input: Vec<GoldilocksField> = (0..20).map(|i| GoldilocksField(i)).collect();
        let h = poseidon.hash_field(&input);
        assert!(h.0 < GoldilocksField::MODULUS);
    }

    #[test]
    fn test_hash_field_multi_absorption() {
        // Input exceeding rate capacity triggers multi-absorption (Req 5.10)
        let poseidon = PoseidonGoldilocks::new();
        let input: Vec<GoldilocksField> = (0..20).map(|i| GoldilocksField(i + 1)).collect();
        let h = poseidon.hash_field(&input);
        assert!(h.0 < GoldilocksField::MODULUS);

        // Different long inputs should produce different hashes
        let input2: Vec<GoldilocksField> = (0..20).map(|i| GoldilocksField(i + 100)).collect();
        let h2 = poseidon.hash_field(&input2);
        assert_ne!(h, h2);
    }

    // -- hash_bytes ----------------------------------------------------------

    #[test]
    fn test_hash_bytes_deterministic() {
        let poseidon = PoseidonGoldilocks::new();
        let h1 = poseidon.hash_bytes(b"hello world");
        let h2 = poseidon.hash_bytes(b"hello world");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_bytes_different_inputs() {
        let poseidon = PoseidonGoldilocks::new();
        let h1 = poseidon.hash_bytes(b"input_a");
        let h2 = poseidon.hash_bytes(b"input_b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hash_bytes_empty_input() {
        let poseidon = PoseidonGoldilocks::new();
        let h = poseidon.hash_bytes(b"");
        assert_eq!(h.0.len(), 32);
    }

    #[test]
    fn test_hash_bytes_long_input() {
        let poseidon = PoseidonGoldilocks::new();
        let data = vec![0xABu8; 1000];
        let h = poseidon.hash_bytes(&data);
        assert_eq!(h.0.len(), 32);
    }

    #[test]
    fn test_hash_bytes_produces_32_bytes() {
        let poseidon = PoseidonGoldilocks::new();
        let h = poseidon.hash_bytes(b"test");
        assert_eq!(h.0.len(), 32);
    }

    // -- hash_with_domain ----------------------------------------------------

    #[test]
    fn test_hash_with_domain_deterministic() {
        let poseidon = PoseidonGoldilocks::new();
        let tag = create_domain_tag(b"test_domain");
        let input = [GoldilocksField(42)];
        let h1 = poseidon.hash_with_domain(&tag, &input);
        let h2 = poseidon.hash_with_domain(&tag, &input);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_with_domain_different_domains() {
        let poseidon = PoseidonGoldilocks::new();
        let tag_a = create_domain_tag(b"domain_a");
        let tag_b = create_domain_tag(b"domain_b");
        let input = [GoldilocksField(42)];
        let h1 = poseidon.hash_with_domain(&tag_a, &input);
        let h2 = poseidon.hash_with_domain(&tag_b, &input);
        assert_ne!(h1, h2, "Different domains must produce different hashes");
    }

    #[test]
    fn test_hash_with_domain_different_data() {
        let poseidon = PoseidonGoldilocks::new();
        let tag = create_domain_tag(b"test_domain");
        let h1 = poseidon.hash_with_domain(&tag, &[GoldilocksField(1)]);
        let h2 = poseidon.hash_with_domain(&tag, &[GoldilocksField(2)]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hash_with_domain_empty_input() {
        let poseidon = PoseidonGoldilocks::new();
        let tag = create_domain_tag(b"test_domain");
        let h = poseidon.hash_with_domain(&tag, &[]);
        assert!(h.0 < GoldilocksField::MODULUS);
    }

    #[test]
    fn test_hash_with_domain_differs_from_plain_hash() {
        let poseidon = PoseidonGoldilocks::new();
        let tag = create_domain_tag(b"some_domain");
        let input = [GoldilocksField(42)];
        let domain_hash = poseidon.hash_with_domain(&tag, &input);
        let plain_hash = poseidon.hash_field(&input);
        assert_ne!(
            domain_hash, plain_hash,
            "Domain-separated hash must differ from plain hash"
        );
    }

    // -- Injective encoding --------------------------------------------------

    #[test]
    fn test_injective_encoding_different_lengths() {
        let enc1 = encode_bytes_to_field_elements(b"abc");
        let enc2 = encode_bytes_to_field_elements(b"abcd");
        // Length prefix differs
        assert_ne!(enc1[0], enc2[0]);
    }

    #[test]
    fn test_injective_encoding_different_content() {
        let enc1 = encode_bytes_to_field_elements(b"abc");
        let enc2 = encode_bytes_to_field_elements(b"abd");
        // Same length prefix, but different data elements
        assert_eq!(enc1[0], enc2[0]); // same length
        assert_ne!(enc1[1], enc2[1]); // different content
    }

    #[test]
    fn test_injective_encoding_empty() {
        let enc = encode_bytes_to_field_elements(b"");
        // Should have exactly one element: the length prefix (0)
        assert_eq!(enc.len(), 1);
        assert_eq!(enc[0], GoldilocksField(0));
    }

    #[test]
    fn test_injective_encoding_values_in_field() {
        let data = vec![0xFFu8; 100];
        let enc = encode_bytes_to_field_elements(&data);
        for (i, elem) in enc.iter().enumerate() {
            assert!(
                elem.0 < GoldilocksField::MODULUS,
                "Encoded element {} must be < MODULUS",
                i
            );
        }
    }
}
