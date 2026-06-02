//! Goldilocks prime field arithmetic.
//!
//! Implements field elements over the Goldilocks prime p = 2^64 - 2^32 + 1.
//! This field is native to Plonky3 STARKs and chosen for efficient 64-bit
//! modular reduction.

use serde::{Deserialize, Serialize};

/// Goldilocks prime field element: p = 2^64 - 2^32 + 1.
///
/// All arithmetic is modular over the Goldilocks prime. The internal
/// representation is a `u64` in the canonical range `[0, p-1]`.
///
/// # Field properties
/// - Modulus: p = 0xFFFFFFFF00000001 = 18446744069414584321
/// - Efficient reduction: the special form allows fast modular reduction
/// - Plonky3 native: the field Plonky3 STARKs operate over
/// - S-box exponent: 7 (used in Poseidon hash)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GoldilocksField(pub u64);

impl GoldilocksField {
    /// The Goldilocks prime modulus: p = 2^64 - 2^32 + 1.
    pub const MODULUS: u64 = 0xFFFFFFFF00000001;

    /// The additive identity.
    pub const ZERO: Self = Self(0);

    /// The multiplicative identity.
    pub const ONE: Self = Self(1);

    /// Modular addition: (a + b) mod p.
    ///
    /// Uses a single conditional subtraction after overflow-checked addition.
    #[inline]
    pub fn add(self, rhs: Self) -> Self {
        let (sum, carry) = self.0.overflowing_add(rhs.0);
        // If carry occurred or sum >= MODULUS, subtract MODULUS.
        // When carry is true, the mathematical sum is sum + 2^64, which is
        // always >= MODULUS (since MODULUS < 2^64), so we subtract MODULUS.
        let (reduced, borrow) = sum.overflowing_sub(Self::MODULUS);
        // Use reduced if there was a carry (overflow in add) or no borrow
        // (meaning sum >= MODULUS).
        if carry || !borrow {
            Self(reduced)
        } else {
            Self(sum)
        }
    }

    /// Modular subtraction: (a - b) mod p.
    ///
    /// If a < b, wraps around by adding p.
    #[inline]
    pub fn sub(self, rhs: Self) -> Self {
        let (diff, borrow) = self.0.overflowing_sub(rhs.0);
        if borrow {
            // a < b in unsigned terms, so add MODULUS to wrap.
            Self(diff.wrapping_add(Self::MODULUS))
        } else {
            Self(diff)
        }
    }

    /// Modular multiplication: (a * b) mod p using 128-bit intermediate.
    ///
    /// Computes the full 128-bit product and reduces mod p using the
    /// special structure of the Goldilocks prime.
    #[inline]
    pub fn mul(self, rhs: Self) -> Self {
        let product = (self.0 as u128) * (rhs.0 as u128);
        Self(reduce128(product))
    }

    /// Modular inversion: a^(-1) mod p via Fermat's little theorem.
    ///
    /// Returns `None` if `self` is zero (zero has no multiplicative inverse).
    /// For non-zero a, computes a^(p-2) mod p.
    pub fn inv(self) -> Option<Self> {
        if self.0 == 0 {
            return None;
        }
        // By Fermat's little theorem, a^(-1) = a^(p-2) mod p.
        Some(self.pow(Self::MODULUS - 2))
    }

    /// Modular exponentiation: a^exp mod p via square-and-multiply.
    pub fn pow(self, exp: u64) -> Self {
        if exp == 0 {
            return Self::ONE;
        }

        let mut base = self;
        let mut result = Self::ONE;
        let mut e = exp;

        while e > 0 {
            if e & 1 == 1 {
                result = result.mul(base);
            }
            e >>= 1;
            if e > 0 {
                base = base.mul(base);
            }
        }

        result
    }

    /// S-box for Poseidon: x^7 mod p.
    ///
    /// Computed as x^7 = x^4 · x^2 · x using three multiplications.
    #[inline]
    pub fn sbox(self) -> Self {
        let x2 = self.mul(self);
        let x4 = x2.mul(x2);
        let x3 = x2.mul(self);
        x4.mul(x3)
    }

    /// Convert from little-endian bytes to a field element, reduced mod p.
    ///
    /// Reads up to 8 bytes as a little-endian u64. If fewer than 8 bytes
    /// are provided, the remaining high bytes are treated as zero.
    /// The result is reduced mod p.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut buf = [0u8; 8];
        let len = bytes.len().min(8);
        buf[..len].copy_from_slice(&bytes[..len]);
        let val = u64::from_le_bytes(buf);
        Self(val % Self::MODULUS)
    }

    /// Convert to little-endian bytes.
    pub fn to_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }
}

/// Reduce a 128-bit value modulo the Goldilocks prime.
///
/// Uses the special structure of p = 2^64 - 2^32 + 1:
///   x mod p where x = x_hi * 2^64 + x_lo
///   Since 2^64 ≡ 2^32 - 1 (mod p), we have:
///   x ≡ x_lo + x_hi * (2^32 - 1) (mod p)
///
/// This may require a second reduction step since the intermediate
/// result can still exceed p.
///
/// # Output guarantee
///
/// The result is always in the canonical range `[0, p)`.
///
/// # Algorithm comparison with Plonky3
///
/// Plonky3's `reduce128` splits `x_hi` into two 32-bit halves and uses
/// the identity `2^96 ≡ -1 (mod p)` to stay within `u64` arithmetic
/// (single-pass, non-canonical output). Our implementation treats `x_hi`
/// as a single 64-bit value and uses `u128` intermediates, which may
/// require a second reduction pass but always produces canonical output.
/// Both are mathematically equivalent — see `docs/GOLDILOCKS_CROSS_REFERENCE.md`
/// for the formal equivalence proof.
///
/// # Correctness bounds
///
/// - First pass: `sum = x_lo + x_hi * (2^32 - 1) < 2^96`, so `s_hi < 2^32`.
/// - Second pass: `result = s_lo + s_hi * (2^32 - 1) ≤ 2^65 - 2^33 < 2p`.
/// - Therefore a single final subtraction of `p` suffices.
#[inline]
pub fn reduce128(x: u128) -> u64 {
    let x_lo = x as u64;
    let x_hi = (x >> 64) as u64;

    // 2^64 ≡ 2^32 - 1 (mod p)
    // So x = x_lo + x_hi * 2^64 ≡ x_lo + x_hi * (2^32 - 1) (mod p)
    //
    // x_hi * (2^32 - 1) = x_hi * 2^32 - x_hi
    let hi_shifted = (x_hi as u128) << 32;
    let adjustment = hi_shifted - (x_hi as u128);

    // Now compute x_lo + adjustment, which may overflow u64.
    // Maximum value: 2^64 + 2^96 - 2^64 = 2^96, so sum < 2^96.
    let sum = (x_lo as u128) + adjustment;

    // Reduce again if needed: sum might be up to ~2^96, so we repeat.
    let s_lo = sum as u64;
    let s_hi = (sum >> 64) as u64;

    if s_hi == 0 {
        // Simple case: result fits in u64, just check if >= MODULUS.
        if s_lo >= GoldilocksField::MODULUS {
            s_lo - GoldilocksField::MODULUS
        } else {
            s_lo
        }
    } else {
        // s_hi < 2^32 (since sum < 2^96). Apply the same identity again:
        // sum = s_lo + s_hi * 2^64 ≡ s_lo + s_hi * (2^32 - 1) (mod p)
        let hi_shifted2 = (s_hi as u128) << 32;
        let adjustment2 = hi_shifted2 - (s_hi as u128);
        let result = (s_lo as u128) + adjustment2;

        // Bound: result ≤ (2^64 - 1) + (2^32 - 1)^2 = 2^65 - 2^33 < 2p.
        // So result is in [0, 2p), and a single subtraction of p suffices.
        let r = result as u64;
        if r >= GoldilocksField::MODULUS || result >= (1u128 << 64) {
            // If result >= 2^64, then r = result mod 2^64 and the true value
            // is r + 2^64 ≡ r + (2^32 - 1) (mod p). wrapping_sub(p) computes
            // r - p mod 2^64 = r + 2^64 - p = r + (2^32 - 1), which is correct.
            // If result < 2^64 but r >= p, this is a simple canonical reduction.
            r.wrapping_sub(GoldilocksField::MODULUS)
        } else {
            r
        }
    }
}

impl std::fmt::Display for GoldilocksField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_one_constants() {
        assert_eq!(GoldilocksField::ZERO.0, 0);
        assert_eq!(GoldilocksField::ONE.0, 1);
    }

    #[test]
    fn test_add_basic() {
        let a = GoldilocksField(3);
        let b = GoldilocksField(5);
        assert_eq!(a.add(b), GoldilocksField(8));
    }

    #[test]
    fn test_add_wraps_at_modulus() {
        let p_minus_1 = GoldilocksField(GoldilocksField::MODULUS - 1);
        let one = GoldilocksField::ONE;
        assert_eq!(p_minus_1.add(one), GoldilocksField::ZERO);
    }

    #[test]
    fn test_sub_basic() {
        let a = GoldilocksField(10);
        let b = GoldilocksField(3);
        assert_eq!(a.sub(b), GoldilocksField(7));
    }

    #[test]
    fn test_sub_wraps() {
        let a = GoldilocksField::ZERO;
        let b = GoldilocksField::ONE;
        assert_eq!(a.sub(b), GoldilocksField(GoldilocksField::MODULUS - 1));
    }

    #[test]
    fn test_mul_basic() {
        let a = GoldilocksField(3);
        let b = GoldilocksField(7);
        assert_eq!(a.mul(b), GoldilocksField(21));
    }

    #[test]
    fn test_mul_large() {
        // (p-1) * (p-1) should reduce correctly
        let p_minus_1 = GoldilocksField(GoldilocksField::MODULUS - 1);
        let result = p_minus_1.mul(p_minus_1);
        assert!(result.0 < GoldilocksField::MODULUS);
        // (p-1)^2 = p^2 - 2p + 1 ≡ 1 (mod p)
        assert_eq!(result, GoldilocksField::ONE);
    }

    #[test]
    fn test_inv_zero_returns_none() {
        assert_eq!(GoldilocksField::ZERO.inv(), None);
    }

    #[test]
    fn test_inv_one() {
        assert_eq!(GoldilocksField::ONE.inv(), Some(GoldilocksField::ONE));
    }

    #[test]
    fn test_inv_roundtrip() {
        let a = GoldilocksField(42);
        let a_inv = a.inv().unwrap();
        assert_eq!(a.mul(a_inv), GoldilocksField::ONE);
    }

    #[test]
    fn test_pow_zero_exp() {
        let a = GoldilocksField(42);
        assert_eq!(a.pow(0), GoldilocksField::ONE);
    }

    #[test]
    fn test_pow_one_exp() {
        let a = GoldilocksField(42);
        assert_eq!(a.pow(1), a);
    }

    #[test]
    fn test_sbox_equals_pow7() {
        let a = GoldilocksField(123456789);
        assert_eq!(a.sbox(), a.pow(7));
    }

    #[test]
    fn test_sbox_zero() {
        assert_eq!(GoldilocksField::ZERO.sbox(), GoldilocksField::ZERO);
    }

    #[test]
    fn test_sbox_one() {
        assert_eq!(GoldilocksField::ONE.sbox(), GoldilocksField::ONE);
    }

    #[test]
    fn test_from_bytes_to_bytes_roundtrip() {
        let a = GoldilocksField(0xDEADBEEF);
        let bytes = a.to_bytes();
        let b = GoldilocksField::from_bytes(&bytes);
        assert_eq!(a, b);
    }

    #[test]
    fn test_from_bytes_reduces_mod_p() {
        // Value >= MODULUS should be reduced
        let val = GoldilocksField::MODULUS + 5;
        let bytes = val.to_le_bytes();
        let result = GoldilocksField::from_bytes(&bytes);
        assert_eq!(result, GoldilocksField(5));
    }

    #[test]
    fn test_from_bytes_short_input() {
        let bytes = [0x01, 0x00];
        let result = GoldilocksField::from_bytes(&bytes);
        assert_eq!(result, GoldilocksField::ONE);
    }

    #[test]
    fn test_all_results_in_range() {
        let a = GoldilocksField(GoldilocksField::MODULUS - 1);
        let b = GoldilocksField(GoldilocksField::MODULUS - 2);

        assert!(a.add(b).0 < GoldilocksField::MODULUS);
        assert!(a.sub(b).0 < GoldilocksField::MODULUS);
        assert!(a.mul(b).0 < GoldilocksField::MODULUS);
        assert!(a.sbox().0 < GoldilocksField::MODULUS);
    }

    // --- Task 1.3: Edge case tests for identity elements ---
    // Requirements: 5.1, 5.2

    #[test]
    fn test_add_zero_identity() {
        // Zero is the additive identity: a + 0 = a, 0 + a = a
        let a = GoldilocksField(999);
        assert_eq!(a.add(GoldilocksField::ZERO), a);
        assert_eq!(GoldilocksField::ZERO.add(a), a);

        // Also verify with boundary value p-1
        let p_minus_1 = GoldilocksField(GoldilocksField::MODULUS - 1);
        assert_eq!(p_minus_1.add(GoldilocksField::ZERO), p_minus_1);
        assert_eq!(GoldilocksField::ZERO.add(p_minus_1), p_minus_1);
    }

    #[test]
    fn test_sub_zero_identity() {
        // Subtracting zero is identity: a - 0 = a
        let a = GoldilocksField(999);
        assert_eq!(a.sub(GoldilocksField::ZERO), a);

        // Also verify with boundary value p-1
        let p_minus_1 = GoldilocksField(GoldilocksField::MODULUS - 1);
        assert_eq!(p_minus_1.sub(GoldilocksField::ZERO), p_minus_1);
    }

    #[test]
    fn test_mul_one_identity() {
        // One is the multiplicative identity: a * 1 = a, 1 * a = a
        let a = GoldilocksField(999);
        assert_eq!(a.mul(GoldilocksField::ONE), a);
        assert_eq!(GoldilocksField::ONE.mul(a), a);

        // Also verify with boundary value p-1
        let p_minus_1 = GoldilocksField(GoldilocksField::MODULUS - 1);
        assert_eq!(p_minus_1.mul(GoldilocksField::ONE), p_minus_1);
        assert_eq!(GoldilocksField::ONE.mul(p_minus_1), p_minus_1);
    }

    #[test]
    fn test_mul_zero_annihilates() {
        // Zero annihilates multiplication: a * 0 = 0, 0 * a = 0
        let a = GoldilocksField(999);
        assert_eq!(a.mul(GoldilocksField::ZERO), GoldilocksField::ZERO);
        assert_eq!(GoldilocksField::ZERO.mul(a), GoldilocksField::ZERO);

        // Also verify with boundary value p-1
        let p_minus_1 = GoldilocksField(GoldilocksField::MODULUS - 1);
        assert_eq!(p_minus_1.mul(GoldilocksField::ZERO), GoldilocksField::ZERO);
        assert_eq!(GoldilocksField::ZERO.mul(p_minus_1), GoldilocksField::ZERO);
    }

    #[test]
    fn test_from_bytes_to_bytes_roundtrip_boundary() {
        // Round-trip at boundary values
        let zero = GoldilocksField::ZERO;
        assert_eq!(GoldilocksField::from_bytes(&zero.to_bytes()), zero);

        let one = GoldilocksField::ONE;
        assert_eq!(GoldilocksField::from_bytes(&one.to_bytes()), one);

        let p_minus_1 = GoldilocksField(GoldilocksField::MODULUS - 1);
        assert_eq!(
            GoldilocksField::from_bytes(&p_minus_1.to_bytes()),
            p_minus_1
        );
    }
}
