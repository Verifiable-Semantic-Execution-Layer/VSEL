//! Cryptographic verification tests for GoldilocksField and reduce128.
//!
//! This file implements Tasks 1.2–1.5 from the Cryptographic Hardening spec:
//!
//! - Task 1.2: Exhaustive boundary tests for `reduce128`
//! - Task 1.3: Property test for reduce128 algebraic identity (Property 5)
//! - Task 1.4: Property test for field operations canonical range (Property 6)
//! - Task 1.5: Property test for field axioms (Property 7)
//!
//! All tests verify correctness against the Goldilocks prime p = 2^64 − 2^32 + 1.

use vsel_crypto::{reduce128, GoldilocksField};

const P: u64 = GoldilocksField::MODULUS; // 0xFFFFFFFF00000001
const P128: u128 = P as u128;

/// Reference modular reduction using u128 arithmetic.
/// Computes x mod p using Rust's native u128 modulo.
fn reference_mod_p(x: u128) -> u64 {
    (x % P128) as u64
}

// ===========================================================================
// Task 1.2: Exhaustive boundary tests for reduce128
// Requirements: 4.2, 4.3
// ===========================================================================

/// Helper: verify reduce128(x) ≡ x (mod p) AND reduce128(x) < p.
fn assert_reduce128_correct(x: u128) {
    let result = reduce128(x);
    let expected = reference_mod_p(x);
    assert!(
        result < P,
        "reduce128({x:#x}) = {result} is not in [0, p): result >= p ({P})"
    );
    assert_eq!(
        result, expected,
        "reduce128({x:#x}) = {result}, expected {expected} (x mod p)"
    );
}

// --- Zero region ---

#[test]
fn test_reduce128_zero() {
    assert_reduce128_correct(0);
}

#[test]
fn test_reduce128_one() {
    assert_reduce128_correct(1);
}

#[test]
fn test_reduce128_p_minus_1() {
    assert_reduce128_correct(P128 - 1);
}

#[test]
fn test_reduce128_p_minus_2() {
    assert_reduce128_correct(P128 - 2);
}

// --- Modulus boundary ---

#[test]
fn test_reduce128_p() {
    assert_reduce128_correct(P128);
}

#[test]
fn test_reduce128_p_plus_1() {
    assert_reduce128_correct(P128 + 1);
}

#[test]
fn test_reduce128_2p_minus_1() {
    assert_reduce128_correct(2 * P128 - 1);
}

#[test]
fn test_reduce128_2p() {
    assert_reduce128_correct(2 * P128);
}

#[test]
fn test_reduce128_2p_plus_1() {
    assert_reduce128_correct(2 * P128 + 1);
}

// --- 32-bit boundary ---

#[test]
fn test_reduce128_2pow32_minus_1() {
    assert_reduce128_correct((1u128 << 32) - 1);
}

#[test]
fn test_reduce128_2pow32() {
    assert_reduce128_correct(1u128 << 32);
}

#[test]
fn test_reduce128_2pow32_plus_1() {
    assert_reduce128_correct((1u128 << 32) + 1);
}

// --- 64-bit boundary ---

#[test]
fn test_reduce128_2pow64_minus_1() {
    assert_reduce128_correct((1u128 << 64) - 1);
}

#[test]
fn test_reduce128_2pow64() {
    assert_reduce128_correct(1u128 << 64);
}

#[test]
fn test_reduce128_2pow64_plus_1() {
    assert_reduce128_correct((1u128 << 64) + 1);
}

// --- Mixed boundary (second reduction trigger) ---

#[test]
fn test_reduce128_2pow64_plus_2pow32_minus_1() {
    assert_reduce128_correct((1u128 << 64) + (1u128 << 32) - 1);
}

#[test]
fn test_reduce128_2pow64_plus_2pow32() {
    assert_reduce128_correct((1u128 << 64) + (1u128 << 32));
}

#[test]
fn test_reduce128_2pow96() {
    assert_reduce128_correct(1u128 << 96);
}

// --- Maximum ---

#[test]
fn test_reduce128_max() {
    assert_reduce128_correct(u128::MAX);
}

#[test]
fn test_reduce128_max_minus_1() {
    assert_reduce128_correct(u128::MAX - 1);
}

// --- Squares (multiplication outputs) ---

#[test]
fn test_reduce128_p_squared() {
    assert_reduce128_correct(P128 * P128);
}

#[test]
fn test_reduce128_p_squared_minus_1() {
    assert_reduce128_correct(P128 * P128 - 1);
}

#[test]
fn test_reduce128_p_minus_1_squared() {
    assert_reduce128_correct((P128 - 1) * (P128 - 1));
}

// --- Second-reduction trigger values (s_hi > 0) ---
// These are values where x_hi > 0 in the first pass, causing sum > 2^64,
// which triggers the second reduction step.

#[test]
fn test_reduce128_second_reduction_trigger_small_hi() {
    // x_hi = 1, x_lo = 0 → sum = 1 * (2^32 - 1) = 2^32 - 1
    // This stays in u64, no second reduction needed.
    assert_reduce128_correct(1u128 << 64);
}

#[test]
fn test_reduce128_second_reduction_trigger_large_hi() {
    // x_hi = 2^32, x_lo = 0 → sum = 2^32 * (2^32 - 1) = 2^64 - 2^32
    // sum fits in u64 (just barely), s_hi = 0
    assert_reduce128_correct((1u128 << 32) << 64);
}

#[test]
fn test_reduce128_second_reduction_trigger_overflow() {
    // x_hi = 2^32 + 1, x_lo = u64::MAX
    // sum = u64::MAX + (2^32 + 1) * (2^32 - 1) = u64::MAX + 2^64 - 1
    // This overflows u64, triggering second reduction (s_hi > 0)
    let x_hi = (1u128 << 32) + 1;
    let x_lo = u64::MAX as u128;
    let x = (x_hi << 64) | x_lo;
    assert_reduce128_correct(x);
}

#[test]
fn test_reduce128_second_reduction_max_hi() {
    // x_hi = u64::MAX → maximum possible x_hi
    // This definitely triggers second reduction
    let x = (u64::MAX as u128) << 64 | (u64::MAX as u128);
    assert_reduce128_correct(x); // This is u128::MAX
}

#[test]
fn test_reduce128_second_reduction_hi_equals_p() {
    // x_hi = p, x_lo = 0
    let x = P128 << 64;
    assert_reduce128_correct(x);
}

#[test]
fn test_reduce128_second_reduction_hi_equals_p_lo_max() {
    // x_hi = p, x_lo = p - 1
    let x = (P128 << 64) | (P128 - 1);
    assert_reduce128_correct(x);
}

/// Sweep values around each critical boundary to catch off-by-one errors.
#[test]
fn test_reduce128_boundary_sweep() {
    let boundaries: Vec<u128> = vec![
        0,
        1,
        P128 - 1,
        P128,
        P128 + 1,
        2 * P128 - 1,
        2 * P128,
        2 * P128 + 1,
        (1u128 << 32) - 1,
        1u128 << 32,
        (1u128 << 32) + 1,
        (1u128 << 64) - 1,
        1u128 << 64,
        (1u128 << 64) + 1,
        (1u128 << 64) + (1u128 << 32) - 1,
        (1u128 << 64) + (1u128 << 32),
        1u128 << 96,
        u128::MAX,
        P128 * P128,
        P128 * P128 - 1,
        (P128 - 1) * (P128 - 1),
    ];

    for &b in &boundaries {
        assert_reduce128_correct(b);
        // Also test b ± 1 where valid
        if b > 0 {
            assert_reduce128_correct(b - 1);
        }
        if b < u128::MAX {
            assert_reduce128_correct(b + 1);
        }
    }
}

/// Test multiples of p to verify they all reduce to 0.
#[test]
fn test_reduce128_multiples_of_p() {
    for k in 0u128..=100 {
        let x = k * P128;
        if x <= u128::MAX {
            let result = reduce128(x);
            assert!(result < P, "reduce128({k}*p) = {result} >= p");
            assert_eq!(result, 0, "reduce128({k}*p) = {result}, expected 0");
        }
    }
}

/// Test values of the form k*p + r for small r to verify remainder is preserved.
#[test]
fn test_reduce128_multiples_of_p_plus_remainder() {
    for k in 0u128..=50 {
        for r in 0u64..=10 {
            let x = k * P128 + r as u128;
            if x <= u128::MAX {
                let result = reduce128(x);
                assert!(result < P, "reduce128({k}*p + {r}) = {result} >= p");
                assert_eq!(
                    result, r,
                    "reduce128({k}*p + {r}) = {result}, expected {r}"
                );
            }
        }
    }
}


// ===========================================================================
// Task 1.3: Property test for reduce128 algebraic identity (Property 5)
// **Validates: Requirements 4.3**
// ===========================================================================

mod property_reduce128 {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(
            std::env::var("PROPTEST_CASES")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(100_000)
        ))]

        /// Property 5: reduce128 algebraic identity.
        ///
        /// For any random u128 value x:
        ///   (a) reduce128(x) ≡ x (mod p)
        ///   (b) reduce128(x) < p
        ///
        /// **Validates: Requirements 4.3**
        #[test]
        fn prop_reduce128_algebraic_identity(x in any::<u128>()) {
            let result = reduce128(x);
            let expected = reference_mod_p(x);

            // (b) Result is in canonical range [0, p)
            prop_assert!(
                result < P,
                "reduce128({:#x}) = {} is not < p ({})", x, result, P
            );

            // (a) Result is congruent to x mod p
            prop_assert_eq!(
                result,
                expected,
                "reduce128({:#x}) = {}, expected {} (x mod p)", x, result, expected
            );
        }
    }
}

// ===========================================================================
// Task 1.4: Property test for field operations canonical range (Property 6)
// **Validates: Requirements 4.4**
// ===========================================================================

mod property_field_ops_range {
    use super::*;
    use proptest::prelude::*;

    /// Strategy producing a GoldilocksField element uniformly in [0, p).
    fn arb_field_element() -> impl Strategy<Value = GoldilocksField> {
        (0u64..P).prop_map(GoldilocksField)
    }

    /// Strategy producing a non-zero GoldilocksField element in [1, p).
    fn arb_field_element_nonzero() -> impl Strategy<Value = GoldilocksField> {
        (1u64..P).prop_map(GoldilocksField)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(
            std::env::var("PROPTEST_CASES")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(100_000)
        ))]

        /// Property 6: Field operations canonical range.
        ///
        /// For any two GoldilocksField elements a, b in [0, p), all operations
        /// produce results in [0, p).
        ///
        /// **Validates: Requirements 4.4**
        #[test]
        fn prop_field_ops_canonical_range(
            a in arb_field_element(),
            b in arb_field_element()
        ) {
            // add
            let sum = a.add(b);
            prop_assert!(
                sum.0 < P,
                "add({}, {}) = {} >= p", a.0, b.0, sum.0
            );

            // sub
            let diff = a.sub(b);
            prop_assert!(
                diff.0 < P,
                "sub({}, {}) = {} >= p", a.0, b.0, diff.0
            );

            // mul
            let prod = a.mul(b);
            prop_assert!(
                prod.0 < P,
                "mul({}, {}) = {} >= p", a.0, b.0, prod.0
            );

            // sbox (unary, on a)
            let sbox_a = a.sbox();
            prop_assert!(
                sbox_a.0 < P,
                "sbox({}) = {} >= p", a.0, sbox_a.0
            );

            // pow with small exponent
            let pow_a = a.pow(7);
            prop_assert!(
                pow_a.0 < P,
                "pow({}, 7) = {} >= p", a.0, pow_a.0
            );
        }

        /// Property 6 (inv): Inversion produces canonical results.
        ///
        /// For any non-zero GoldilocksField element a in [1, p),
        /// inv(a) produces a result in [0, p).
        ///
        /// **Validates: Requirements 4.4**
        #[test]
        fn prop_field_inv_canonical_range(a in arb_field_element_nonzero()) {
            let inv_a = a.inv().expect("non-zero element must have inverse");
            prop_assert!(
                inv_a.0 < P,
                "inv({}) = {} >= p", a.0, inv_a.0
            );
        }

        /// Property 6 (pow): Power with random exponent produces canonical results.
        ///
        /// **Validates: Requirements 4.4**
        #[test]
        fn prop_field_pow_canonical_range(
            a in arb_field_element(),
            exp in any::<u64>()
        ) {
            let result = a.pow(exp);
            prop_assert!(
                result.0 < P,
                "pow({}, {}) = {} >= p", a.0, exp, result.0
            );
        }
    }
}

// ===========================================================================
// Task 1.5: Property test for field axioms (Property 7)
// **Validates: Requirements 4.5**
// ===========================================================================

mod property_field_axioms {
    use super::*;
    use proptest::prelude::*;

    /// Strategy producing a GoldilocksField element uniformly in [0, p).
    fn arb_field_element() -> impl Strategy<Value = GoldilocksField> {
        (0u64..P).prop_map(GoldilocksField)
    }

    /// Strategy producing a non-zero GoldilocksField element in [1, p).
    fn arb_field_element_nonzero() -> impl Strategy<Value = GoldilocksField> {
        (1u64..P).prop_map(GoldilocksField)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(
            std::env::var("PROPTEST_CASES")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(100_000)
        ))]

        /// Property 7: Field axioms — commutativity, associativity, distributivity.
        ///
        /// For any three GoldilocksField elements a, b, c in [0, p), verify:
        /// - Additive commutativity: a + b == b + a
        /// - Multiplicative commutativity: a * b == b * a
        /// - Additive associativity: (a + b) + c == a + (b + c)
        /// - Multiplicative associativity: (a * b) * c == a * (b * c)
        /// - Distributivity: a * (b + c) == a*b + a*c
        /// - Additive identity: a + 0 == a
        /// - Multiplicative identity: a * 1 == a
        ///
        /// **Validates: Requirements 4.5**
        #[test]
        fn prop_field_axioms_core(
            a in arb_field_element(),
            b in arb_field_element(),
            c in arb_field_element()
        ) {
            // Additive commutativity: a + b == b + a
            prop_assert_eq!(
                a.add(b), b.add(a),
                "Additive commutativity failed: {}.add({}) != {}.add({})",
                a.0, b.0, b.0, a.0
            );

            // Multiplicative commutativity: a * b == b * a
            prop_assert_eq!(
                a.mul(b), b.mul(a),
                "Multiplicative commutativity failed: {}.mul({}) != {}.mul({})",
                a.0, b.0, b.0, a.0
            );

            // Additive associativity: (a + b) + c == a + (b + c)
            prop_assert_eq!(
                a.add(b).add(c), a.add(b.add(c)),
                "Additive associativity failed for a={}, b={}, c={}",
                a.0, b.0, c.0
            );

            // Multiplicative associativity: (a * b) * c == a * (b * c)
            prop_assert_eq!(
                a.mul(b).mul(c), a.mul(b.mul(c)),
                "Multiplicative associativity failed for a={}, b={}, c={}",
                a.0, b.0, c.0
            );

            // Distributivity: a * (b + c) == a*b + a*c
            prop_assert_eq!(
                a.mul(b.add(c)), a.mul(b).add(a.mul(c)),
                "Distributivity failed for a={}, b={}, c={}",
                a.0, b.0, c.0
            );

            // Additive identity: a + 0 == a
            prop_assert_eq!(
                a.add(GoldilocksField::ZERO), a,
                "Additive identity failed for a={}", a.0
            );

            // Multiplicative identity: a * 1 == a
            prop_assert_eq!(
                a.mul(GoldilocksField::ONE), a,
                "Multiplicative identity failed for a={}", a.0
            );
        }

        /// Property 7: Additive inverse.
        ///
        /// For any non-zero a in [1, p), a + (p - a) == 0.
        ///
        /// **Validates: Requirements 4.5**
        #[test]
        fn prop_field_additive_inverse(a in arb_field_element_nonzero()) {
            let neg_a = GoldilocksField(P - a.0);
            prop_assert_eq!(
                a.add(neg_a), GoldilocksField::ZERO,
                "Additive inverse failed: {}.add({}) != 0",
                a.0, neg_a.0
            );
        }

        /// Property 7: Multiplicative inverse.
        ///
        /// For any non-zero a in [1, p), a * a^(-1) == 1.
        ///
        /// **Validates: Requirements 4.5**
        #[test]
        fn prop_field_multiplicative_inverse(a in arb_field_element_nonzero()) {
            let a_inv = a.inv().expect("non-zero element must have inverse");
            prop_assert_eq!(
                a.mul(a_inv), GoldilocksField::ONE,
                "Multiplicative inverse failed: {}.mul({}) != 1",
                a.0, a_inv.0
            );
        }
    }
}
