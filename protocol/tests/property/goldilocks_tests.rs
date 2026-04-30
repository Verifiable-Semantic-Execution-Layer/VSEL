//! Property-based tests for GoldilocksField arithmetic.
//!
//! Uses `proptest` to verify correctness properties derived from the
//! production-readiness design document.
//!
//! Properties tested:
//! - Property 10: Goldilocks Field Arithmetic Correctness
//!   **Validates: Requirements 5.1, 5.2**

// Feature: production-readiness, Property 10: Goldilocks Field Arithmetic Correctness

#[path = "../generators/mod.rs"]
mod generators;

use proptest::prelude::*;

use generators::{arb_goldilocks, arb_goldilocks_nonzero};
use vsel_crypto::GoldilocksField;

const MODULUS: u64 = GoldilocksField::MODULUS;

// ---------------------------------------------------------------------------
// Property 10a: Addition result is in [0, MODULUS)
// For any a, b ∈ GoldilocksField, a.add(b).0 < MODULUS
// **Validates: Requirements 5.1, 5.2**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(
        std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(100)
    ))]

    /// Property 10a: Addition always produces a result in [0, MODULUS).
    #[test]
    fn prop_goldilocks_add_in_range(a in arb_goldilocks(), b in arb_goldilocks()) {
        let result = a.add(b);
        prop_assert!(
            result.0 < MODULUS,
            "a.add(b) must be < MODULUS: a={}, b={}, result={}",
            a.0, b.0, result.0
        );
    }
}

// ---------------------------------------------------------------------------
// Property 10b: Subtraction result is in [0, MODULUS)
// For any a, b ∈ GoldilocksField, a.sub(b).0 < MODULUS
// **Validates: Requirements 5.1, 5.2**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(
        std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(100)
    ))]

    /// Property 10b: Subtraction always produces a result in [0, MODULUS).
    #[test]
    fn prop_goldilocks_sub_in_range(a in arb_goldilocks(), b in arb_goldilocks()) {
        let result = a.sub(b);
        prop_assert!(
            result.0 < MODULUS,
            "a.sub(b) must be < MODULUS: a={}, b={}, result={}",
            a.0, b.0, result.0
        );
    }
}

// ---------------------------------------------------------------------------
// Property 10c: Multiplication result is in [0, MODULUS)
// For any a, b ∈ GoldilocksField, a.mul(b).0 < MODULUS
// **Validates: Requirements 5.1, 5.2**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(
        std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(100)
    ))]

    /// Property 10c: Multiplication always produces a result in [0, MODULUS).
    #[test]
    fn prop_goldilocks_mul_in_range(a in arb_goldilocks(), b in arb_goldilocks()) {
        let result = a.mul(b);
        prop_assert!(
            result.0 < MODULUS,
            "a.mul(b) must be < MODULUS: a={}, b={}, result={}",
            a.0, b.0, result.0
        );
    }
}

// ---------------------------------------------------------------------------
// Property 10d: Multiplicative inverse correctness
// For any non-zero a, a.mul(a.inv().unwrap()) == GoldilocksField::ONE
// **Validates: Requirements 5.1, 5.2**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(
        std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(100)
    ))]

    /// Property 10d: For any non-zero element, a * a^(-1) == 1.
    #[test]
    fn prop_goldilocks_mul_inv_identity(a in arb_goldilocks_nonzero()) {
        let a_inv = a.inv().expect("non-zero element must have an inverse");
        let product = a.mul(a_inv);
        prop_assert_eq!(
            product,
            GoldilocksField::ONE,
            "a * a^(-1) must equal ONE: a={}, a_inv={}, product={}",
            a.0, a_inv.0, product.0
        );
    }
}

// ---------------------------------------------------------------------------
// Property 10e: S-box equals x^7
// For any a, a.sbox() == a.pow(7)
// **Validates: Requirements 5.1, 5.2**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(
        std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(100)
    ))]

    /// Property 10e: The S-box function equals x^7 for all field elements.
    #[test]
    fn prop_goldilocks_sbox_equals_pow7(a in arb_goldilocks()) {
        let sbox_result = a.sbox();
        let pow7_result = a.pow(7);
        prop_assert_eq!(
            sbox_result,
            pow7_result,
            "a.sbox() must equal a.pow(7): a={}, sbox={}, pow7={}",
            a.0, sbox_result.0, pow7_result.0
        );
    }
}
