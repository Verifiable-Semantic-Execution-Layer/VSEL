//! Fuzz target: Poseidon hash_bytes over arbitrary byte slices.
//!
//! Accepts arbitrary byte slices, runs hash_bytes(), and asserts
//! determinism and correct output length.
//!
//! Requirements: 6.1(f), 6.2

#![no_main]

use libfuzzer_sys::fuzz_target;
use vsel_crypto::poseidon_goldilocks::PoseidonGoldilocks;

fuzz_target!(|data: &[u8]| {
    let poseidon = PoseidonGoldilocks::new();

    // First hash.
    let hash1 = poseidon.hash_bytes(data);

    // Output should be 32 bytes (Hash is Hash([u8; 32])).
    assert_eq!(
        hash1.0.len(),
        32,
        "hash_bytes output length {} != 32",
        hash1.0.len()
    );

    // Second hash with same input — determinism check.
    let hash2 = poseidon.hash_bytes(data);

    assert_eq!(
        hash1, hash2,
        "non-deterministic hash_bytes: different outputs for same input (len={})",
        data.len()
    );
});
