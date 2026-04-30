//! Fuzz target: GoldilocksField arithmetic operations.
//!
//! Accepts arbitrary byte input, interprets as u64 pairs, and exercises
//! add, sub, mul, inv, pow, sbox. Panics if any result is outside [0, p).
//!
//! Requirements: 6.1(d), 6.2

#![no_main]

use libfuzzer_sys::fuzz_target;
use vsel_crypto::GoldilocksField;

/// The Goldilocks prime modulus.
const P: u64 = GoldilocksField::MODULUS;

fuzz_target!(|data: &[u8]| {
    // Need at least 16 bytes for two u64 values.
    if data.len() < 16 {
        return;
    }

    // Interpret first 8 bytes as u64 a, next 8 as u64 b.
    let a_raw = u64::from_le_bytes([
        data[0], data[1], data[2], data[3],
        data[4], data[5], data[6], data[7],
    ]);
    let b_raw = u64::from_le_bytes([
        data[8], data[9], data[10], data[11],
        data[12], data[13], data[14], data[15],
    ]);

    // Reduce to canonical field elements in [0, p).
    let a = GoldilocksField(a_raw % P);
    let b = GoldilocksField(b_raw % P);

    // --- add ---
    let sum = a.add(b);
    assert!(sum.0 < P, "add result {} >= p", sum.0);

    // --- sub ---
    let diff = a.sub(b);
    assert!(diff.0 < P, "sub result {} >= p", diff.0);

    // --- mul ---
    let prod = a.mul(b);
    assert!(prod.0 < P, "mul result {} >= p", prod.0);

    // --- inv ---
    if a.0 != 0 {
        if let Some(inv_a) = a.inv() {
            assert!(inv_a.0 < P, "inv result {} >= p", inv_a.0);
            // Verify a * a^(-1) == 1
            let check = a.mul(inv_a);
            assert_eq!(check.0, 1, "a * inv(a) != 1 for a = {}", a.0);
        }
    }

    // --- pow ---
    // Use b_raw truncated to a small exponent to keep runtime bounded.
    let exp = (b_raw % 128) as u64;
    let pow_result = a.pow(exp);
    assert!(pow_result.0 < P, "pow result {} >= p", pow_result.0);

    // --- sbox (x^7) ---
    let sbox_result = a.sbox();
    assert!(sbox_result.0 < P, "sbox result {} >= p", sbox_result.0);

    // Cross-check: sbox should equal pow(7)
    let pow7 = a.pow(7);
    assert_eq!(
        sbox_result.0, pow7.0,
        "sbox({}) != pow({}, 7): sbox={}, pow7={}",
        a.0, a.0, sbox_result.0, pow7.0
    );
});
