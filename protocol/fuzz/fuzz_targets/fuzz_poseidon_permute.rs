//! Fuzz target: Poseidon permutation over Goldilocks field.
//!
//! Accepts arbitrary bytes, interprets as [GoldilocksField; 12] state,
//! runs permute(), and asserts determinism (same input → same output).
//!
//! Requirements: 6.1(e), 6.2

#![no_main]

use libfuzzer_sys::fuzz_target;
use vsel_crypto::GoldilocksField;
use vsel_crypto::poseidon_goldilocks::{PoseidonGoldilocks, STATE_WIDTH};

/// The Goldilocks prime modulus.
const P: u64 = GoldilocksField::MODULUS;

fuzz_target!(|data: &[u8]| {
    // Need 12 * 8 = 96 bytes for a full state.
    if data.len() < STATE_WIDTH * 8 {
        return;
    }

    let poseidon = PoseidonGoldilocks::new();

    // Build state from input bytes.
    let mut state = [GoldilocksField::ZERO; STATE_WIDTH];
    for i in 0..STATE_WIDTH {
        let offset = i * 8;
        let val = u64::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        // Reduce to canonical range.
        state[i] = GoldilocksField(val % P);
    }

    // First permutation.
    let mut state1 = state;
    poseidon.permute(&mut state1);

    // Assert all outputs are in [0, p).
    for (i, elem) in state1.iter().enumerate() {
        assert!(
            elem.0 < P,
            "permute output[{}] = {} >= p",
            i,
            elem.0
        );
    }

    // Second permutation with same input — determinism check.
    let mut state2 = state;
    poseidon.permute(&mut state2);

    // Outputs must be identical.
    for i in 0..STATE_WIDTH {
        assert_eq!(
            state1[i].0, state2[i].0,
            "non-deterministic permute: output[{}] differs ({} vs {})",
            i, state1[i].0, state2[i].0
        );
    }
});
