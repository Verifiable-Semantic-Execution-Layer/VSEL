# Goldilocks `reduce128` Cross-Reference Analysis

**Document**: `GOLDILOCKS_CROSS_REFERENCE.md`
**Validates**: Requirements 4.1, 4.6
**Date**: 2025-07-14
**Status**: COMPLETE — Algorithmic differences identified and formally analyzed

## Executive Summary

This document cross-references the VSEL `reduce128` implementation in
`protocol/crates/vsel-crypto/src/goldilocks.rs` against the Plonky3 reference
implementation in `p3-goldilocks/src/goldilocks.rs` (Plonky3 monorepo, `main`
branch) and the Plonky2 predecessor in `0xPolygonZero/plonky2` for additional
context.

**Verdict**: The VSEL implementation uses a **different algorithmic strategy**
from Plonky3. Both are mathematically correct for all inputs in `[0, 2^128)`,
but they differ in structure, intermediate representation, output guarantees,
and performance characteristics. A formal equivalence proof is provided below.

---

## 1. Reference Implementations

### 1.1 Plonky3 `reduce128` (Canonical Reference)

Source: [`Plonky3/Plonky3`](https://github.com/Plonky3/Plonky3), file
`goldilocks/src/goldilocks.rs`.

The Plonky3 implementation uses the identity `2^64 ≡ 2^32 - 1 (mod p)` where
`2^32 - 1 = EPSILON = NEG_ORDER`. It decomposes `x_hi` (the upper 64 bits)
into two 32-bit halves and applies the reduction in a single pass:

```
reduce128(x: u128) -> Goldilocks:
    (x_lo, x_hi) = split(x)          // x_lo = x mod 2^64, x_hi = x >> 64
    x_hi_hi = x_hi >> 32             // upper 32 bits of x_hi
    x_hi_lo = x_hi & NEG_ORDER       // lower 32 bits of x_hi (masked with 0xFFFFFFFF)

    (t0, borrow) = x_lo.overflowing_sub(x_hi_hi)
    if borrow:
        t0 -= NEG_ORDER              // t0 -= (2^32 - 1), cannot underflow

    t1 = x_hi_lo * NEG_ORDER         // x_hi_lo * (2^32 - 1)
    t2 = add_no_canonicalize(t0, t1) // t0 + t1, with carry → add NEG_ORDER
    return Goldilocks(t2)
```

**Key properties**:
- Output is **NOT necessarily canonical**: result may be in `[0, 2^64)`, i.e.,
  it can be in `[p, 2^64)`. Canonicalization happens lazily via
  `as_canonical_u64()`.
- Uses **non-canonical internal representation** — the `Goldilocks` struct
  stores any `u64`, and equality checks go through `as_canonical_u64()`.
- Single-pass reduction with no recursion.
- Uses `add_no_canonicalize_trashing_input` which exploits x86-64 `sbb`
  instruction for branchless carry handling.

### 1.2 Plonky2 `reduce128` (Predecessor Reference)

Source: [`0xPolygonZero/plonky2`](https://github.com/0xPolygonZero/plonky2),
file `field/src/goldilocks_field.rs`.

The Plonky2 implementation is **algorithmically identical** to Plonky3's
`reduce128`. The same decomposition, same subtraction of `x_hi_hi`, same
multiplication of `x_hi_lo * EPSILON`, same `add_no_canonicalize` final step.
Plonky3 inherited this algorithm from Plonky2.

### 1.3 VSEL `reduce128` (Our Implementation)

Source: `protocol/crates/vsel-crypto/src/goldilocks.rs`.

```
reduce128(x: u128) -> u64:
    x_lo = x as u64                  // lower 64 bits
    x_hi = (x >> 64) as u64          // upper 64 bits

    // 2^64 ≡ 2^32 - 1 (mod p)
    // x_hi * (2^32 - 1) = x_hi * 2^32 - x_hi
    hi_shifted = (x_hi as u128) << 32
    adjustment = hi_shifted - (x_hi as u128)

    sum = (x_lo as u128) + adjustment

    s_lo = sum as u64
    s_hi = (sum >> 64) as u64

    if s_hi == 0:
        if s_lo >= MODULUS: return s_lo - MODULUS
        else: return s_lo
    else:
        // Second reduction pass
        hi_shifted2 = (s_hi as u128) << 32
        adjustment2 = hi_shifted2 - (s_hi as u128)
        result = (s_lo as u128) + adjustment2
        r = result as u64
        if r >= MODULUS || result >= 2^64:
            return r.wrapping_sub(MODULUS)
        else:
            return r
```

**Key properties**:
- Output is **always canonical**: result is guaranteed in `[0, p)`.
- Uses **canonical internal representation** — `GoldilocksField(u64)` always
  stores a value in `[0, p)`.
- Two-pass reduction: first pass may produce a value exceeding `u64`, requiring
  a second pass.
- All arithmetic uses `u128` intermediates — no platform-specific assembly.
- Returns a bare `u64`, not a wrapper struct.

---

## 2. Algorithmic Differences

### Difference 1: Decomposition Strategy

| Aspect | Plonky3 | VSEL |
|--------|---------|------|
| `x_hi` handling | Splits `x_hi` into `x_hi_hi` (upper 32) and `x_hi_lo` (lower 32) | Treats `x_hi` as a single 64-bit value |
| Core identity | `x_hi * 2^64 = x_hi_hi * 2^96 + x_hi_lo * 2^64` then applies `2^64 ≡ ε (mod p)` and `2^96 ≡ -1 (mod p)` separately | `x_hi * 2^64 ≡ x_hi * (2^32 - 1) (mod p)` directly |
| Intermediate width | Stays in `u64` throughout (with careful overflow handling) | Widens to `u128` for intermediate computation |

**Mathematical equivalence**: Both exploit the same fundamental identity
`2^64 ≡ 2^32 - 1 (mod p)`. Plonky3 further decomposes using
`2^96 ≡ -(2^32 - 1)·(2^32) ≡ -1 (mod p)` (since `2^96 = 2^64 · 2^32 ≡ (2^32 - 1) · 2^32 = 2^64 - 2^32 ≡ -1 (mod p)`).
This allows Plonky3 to avoid widening to `u128` in the reduction itself.

### Difference 2: Output Canonicality

| Aspect | Plonky3 | VSEL |
|--------|---------|------|
| Output range | `[0, 2^64)` — may exceed `p` | `[0, p)` — always canonical |
| Canonicalization | Deferred to `as_canonical_u64()` | Performed inline |
| Equality semantics | `PartialEq` calls `as_canonical_u64()` on both sides | `PartialEq` compares raw `u64` values directly |

**Impact**: Plonky3's lazy canonicalization is a deliberate performance
optimization — it avoids a conditional subtraction on every reduction, deferring
it to comparison/hashing/display. VSEL's eager canonicalization is simpler and
safer (no risk of accidentally comparing non-canonical values) but performs one
extra conditional branch per reduction.

### Difference 3: Overflow Handling

| Aspect | Plonky3 | VSEL |
|--------|---------|------|
| Subtraction overflow | `x_lo.overflowing_sub(x_hi_hi)` with conditional `t0 -= EPSILON` | No subtraction — uses `u128` addition instead |
| Addition overflow | `add_no_canonicalize_trashing_input` (x86 asm or portable fallback) | Checks `s_hi` after `u128` addition; if nonzero, applies second pass |
| Second reduction | Not needed — single pass always sufficient | Required when `sum > 2^64` |

**Why Plonky3 needs only one pass**: By splitting `x_hi` into two 32-bit
halves, Plonky3 ensures that:
- `x_hi_hi` is at most 32 bits, so `x_lo - x_hi_hi` fits in `u64` (with at
  most one borrow).
- `x_hi_lo * EPSILON` is at most `(2^32 - 1)^2 < 2^64`, so it fits in `u64`.
- `t0 + t1` is at most `~2^64 + 2^64 - 2 < 2^65`, handled by
  `add_no_canonicalize`.

VSEL computes `x_hi * (2^32 - 1)` as a single `u128` multiplication, which can
produce values up to `~2^96`, requiring a second reduction pass.

### Difference 4: Platform-Specific Optimization

| Aspect | Plonky3 | VSEL |
|--------|---------|------|
| x86-64 | Inline assembly (`add` + `sbb`) for carry handling | Pure Rust, no assembly |
| aarch64 | NEON SIMD packed operations | Pure Rust |
| AVX2/AVX512 | Packed field operations | Not applicable |
| Portability | Platform-specific fast paths with generic fallback | Fully portable |

### Difference 5: Inversion Algorithm

| Aspect | Plonky3 | VSEL |
|--------|---------|------|
| Method | Binary GCD (inspired by [eprint 2020/972](https://eprint.iacr.org/2020/972.pdf)) | Fermat's little theorem: `a^(p-2) mod p` |
| Complexity | ~126 iterations of GCD inner loop | 63 squarings + 63 multiplications (square-and-multiply) |
| Performance | Significantly faster (avoids expensive field multiplications) | Simpler but slower |

Note: Plonky2 uses Fermat's little theorem with an optimized addition chain
(72 multiplications). VSEL uses generic square-and-multiply which requires more
operations.

### Difference 6: Addition and Subtraction

| Aspect | Plonky3 | VSEL |
|--------|---------|------|
| Non-canonical inputs | Handles inputs in `[0, 2^64)` — may need double-overflow correction | Assumes inputs in `[0, p)` — single overflow/borrow suffices |
| Double overflow | Explicit handling with `assume` hints and `branch_hint` | Not needed (inputs are canonical) |
| Carry correction | Adds `NEG_ORDER = 2^32 - 1` on overflow | Subtracts `MODULUS` on overflow |

**Mathematical equivalence**: Adding `NEG_ORDER = 2^32 - 1` is equivalent to
subtracting `MODULUS = 2^64 - 2^32 + 1` modulo `2^64`, since
`2^64 - MODULUS = 2^32 - 1 = NEG_ORDER`. Both approaches produce the same
result.

---

## 3. Formal Equivalence Proof

### Theorem: For all `x ∈ [0, 2^128)`, `VSEL_reduce128(x) ≡ Plonky3_reduce128(x) (mod p)`.

More precisely: `VSEL_reduce128(x) = Plonky3_reduce128(x).as_canonical_u64()`.

**Proof**:

Let `p = 2^64 - 2^32 + 1` and `ε = 2^32 - 1`.

Write `x = x_lo + x_hi · 2^64` where `x_lo, x_hi ∈ [0, 2^64)`.

**Plonky3 reduction**:

Write `x_hi = x_hi_hi · 2^32 + x_hi_lo` where `x_hi_hi ∈ [0, 2^32)` and
`x_hi_lo ∈ [0, 2^32)`.

Then:
```
x = x_lo + (x_hi_hi · 2^32 + x_hi_lo) · 2^64
  = x_lo + x_hi_hi · 2^96 + x_hi_lo · 2^64
```

Since `2^64 ≡ ε (mod p)` and `2^96 = 2^64 · 2^32 ≡ ε · 2^32 = 2^64 - 2^32 ≡ -1 (mod p)`:

```
x ≡ x_lo - x_hi_hi + x_hi_lo · ε  (mod p)
```

Plonky3 computes `t0 = x_lo - x_hi_hi` (with borrow correction via `ε`) and
`t1 = x_hi_lo · ε`, then `t2 = t0 + t1` (with carry correction via `ε`).

The result `t2` satisfies `t2 ≡ x (mod p)` and `t2 ∈ [0, 2^64)`.

**VSEL reduction**:

```
x ≡ x_lo + x_hi · (2^32 - 1)  (mod p)
  = x_lo + x_hi · 2^32 - x_hi
```

VSEL computes `adjustment = x_hi · 2^32 - x_hi` (as `u128`) and
`sum = x_lo + adjustment` (as `u128`).

Since `x_hi · (2^32 - 1) ≡ x_hi_hi · 2^32 · (2^32 - 1) + x_hi_lo · (2^32 - 1)`:

Expanding: `x_hi · (2^32 - 1) = (x_hi_hi · 2^32 + x_hi_lo) · (2^32 - 1)`
`= x_hi_hi · (2^64 - 2^32) + x_hi_lo · (2^32 - 1)`
`= x_hi_hi · (p - 1) + x_hi_lo · ε`
`≡ -x_hi_hi + x_hi_lo · ε  (mod p)`

This is the same congruence as Plonky3. ∎

**Bound analysis for VSEL's second pass**:

`sum = x_lo + x_hi · (2^32 - 1)`

Maximum value: `x_lo < 2^64`, `x_hi < 2^64`, so
`sum < 2^64 + 2^64 · (2^32 - 1) = 2^64 + 2^96 - 2^64 = 2^96`.

Thus `s_hi = sum >> 64 < 2^32`.

In the second pass: `adjustment2 = s_hi · 2^32 - s_hi = s_hi · (2^32 - 1)`.
Maximum: `(2^32 - 1) · (2^32 - 1) = 2^64 - 2^33 + 1 < 2^64`.

`result = s_lo + adjustment2 < 2^64 + 2^64 = 2^65`.

After the final conditional subtraction of `p`, the result is in `[0, p)`. ∎

---

## 4. Correctness Analysis

### 4.1 VSEL `reduce128` Correctness

The VSEL implementation is **mathematically correct** for all inputs in
`[0, 2^128)`:

1. **First pass**: Computes `sum ≡ x (mod p)` with `sum < 2^96`.
2. **Second pass** (when `s_hi > 0`): Computes `result ≡ sum (mod p)` with
   `result < 2^65`.
3. **Final canonicalization**: Subtracts `p` if `result ≥ p` or `result ≥ 2^64`,
   yielding a value in `[0, p)`.

**Potential concern in the final branch**:

```rust
if r >= GoldilocksField::MODULUS || result >= (1u128 << 64) {
    r.wrapping_sub(GoldilocksField::MODULUS)
}
```

This is correct because:
- If `result ≥ 2^64`, then `r = result mod 2^64` and the true value is
  `r + 2^64 ≡ r + ε (mod p)`. Since `r + ε < 2^64 + ε < 2p`, subtracting `p`
  once yields a value in `[0, p)`. But we use `wrapping_sub(MODULUS)` which
  computes `r - p mod 2^64 = r + 2^64 - p = r + ε`, which is the correct
  canonical representative... **Wait** — this needs careful analysis.

  Actually: `r.wrapping_sub(MODULUS)` computes `(r - p) mod 2^64`. If the true
  mathematical value is `r + 2^64` (because `result ≥ 2^64`), then we need
  `(r + 2^64) mod p`. Since `2^64 ≡ ε (mod p)`, this equals `(r + ε) mod p`.
  And `r.wrapping_sub(p) = r + 2^64 - p = r + ε`. Since `r < 2^64` and
  `ε = 2^32 - 1`, we have `r + ε < 2^64 + 2^32 - 1`. But we need the result
  to be `< p`. Is `r + ε < p` guaranteed?

  From the second pass: `result = s_lo + adjustment2` where `s_lo < 2^64` and
  `adjustment2 < 2^64`. If `result ≥ 2^64`, then `r = result - 2^64` and the
  true value mod p is `r + ε`. We need `r + ε < p`, i.e.,
  `result - 2^64 + 2^32 - 1 < 2^64 - 2^32 + 1`, i.e.,
  `result < 2^65 - 2^33 + 2 = 2(2^64 - 2^32 + 1) = 2p`.

  Since `result < 2^65` (proven above) and `2p = 2^65 - 2^33 + 2 < 2^65`,
  we need `result < 2p`. This holds because `result = s_lo + adjustment2`
  where `s_lo < 2^64` and `adjustment2 = s_hi · (2^32 - 1) < 2^32 · (2^32 - 1) = 2^64 - 2^32`.
  So `result < 2^64 + 2^64 - 2^32 = 2^65 - 2^32`. And `2p = 2^65 - 2^33 + 2`.
  We need `2^65 - 2^32 ≤ 2p`? That's `2^65 - 2^32 ≤ 2^65 - 2^33 + 2`, i.e.,
  `-2^32 ≤ -2^33 + 2`, i.e., `2^33 - 2 ≤ 2^32`, which is **false** for
  large values.

  **Tighter bound needed**: `s_hi < 2^32` and `adjustment2 = s_hi · (2^32 - 1)`.
  Also `s_lo < 2^64`. But we also know `sum = s_lo + s_hi · 2^64 ≡ x (mod p)`
  and `sum < 2^96`. The second pass computes
  `result = s_lo + s_hi · (2^32 - 1) ≡ sum (mod p)`.

  Maximum of `result`: `s_lo ≤ 2^64 - 1`, `s_hi ≤ 2^32 - 1` (since
  `sum < 2^96` means `s_hi < 2^32`). So
  `result ≤ (2^64 - 1) + (2^32 - 1)(2^32 - 1) = 2^64 - 1 + 2^64 - 2^33 + 1 = 2^65 - 2^33`.

  Is `2^65 - 2^33 < 2p = 2^65 - 2^33 + 2`? Yes! `2^65 - 2^33 < 2^65 - 2^33 + 2`. ✓

  Therefore `result < 2p`, and a single subtraction of `p` suffices. ✓

### 4.2 Plonky3 `reduce128` Correctness

The Plonky3 implementation is correct by construction — it is the canonical
reference used by the Polygon team and has been extensively tested and audited.

The key insight is that by splitting `x_hi` into 32-bit halves, all
intermediate values stay within `u64` range (with at most one carry/borrow),
eliminating the need for `u128` arithmetic in the reduction itself.

---

## 5. Summary of All Differences

| # | Aspect | Plonky3 | VSEL | Severity |
|---|--------|---------|------|----------|
| 1 | Decomposition | Splits `x_hi` into 32-bit halves | Treats `x_hi` as single 64-bit value | Algorithmic — no correctness impact |
| 2 | Output range | `[0, 2^64)` (non-canonical) | `[0, p)` (canonical) | Design choice — VSEL is stricter |
| 3 | Internal representation | Non-canonical `u64` | Canonical `u64` | Design choice — affects all operations |
| 4 | Number of passes | Single pass | Up to two passes | Performance — VSEL slightly slower |
| 5 | Intermediate width | `u64` throughout | Widens to `u128` | Performance — Plonky3 avoids widening |
| 6 | Platform optimization | x86-64 asm, NEON, AVX2/512 | Pure Rust | Performance — Plonky3 faster on x86 |
| 7 | Inversion | Binary GCD | Fermat's little theorem | Performance — Plonky3 faster |
| 8 | Addition carry | Adds `NEG_ORDER` on overflow | Subtracts `MODULUS` on overflow | Equivalent modulo `2^64` |
| 9 | Double overflow | Handled (non-canonical inputs) | Not needed (canonical inputs) | Correctness — both correct for their invariants |

---

## 6. Risk Assessment

### 6.1 Risks in VSEL Implementation

**LOW RISK**: The VSEL implementation is mathematically correct and produces
canonical output. The main risks are:

1. **Performance**: The two-pass reduction and `u128` arithmetic are slower than
   Plonky3's single-pass `u64` approach. This is acceptable for the current use
   case but may become a bottleneck under heavy proof generation load.

2. **Final branch complexity**: The `if r >= MODULUS || result >= (1u128 << 64)`
   condition in the second pass is correct but non-obvious. The proof above
   confirms it handles all cases, but the logic would benefit from additional
   inline documentation.

### 6.2 Risks if Aligning with Plonky3

If we were to adopt Plonky3's non-canonical representation:
- All field operations (`add`, `sub`, `mul`, `inv`, `pow`, `sbox`) would need
  to be updated to handle non-canonical inputs.
- `PartialEq` would need to canonicalize before comparison.
- Serialization would need canonicalization.
- The change would be pervasive and high-risk.

### 6.3 Recommendation

**Do not align implementations**. The VSEL canonical representation is a valid
design choice that trades performance for simplicity and safety. The formal
equivalence proof above demonstrates that both implementations compute the same
mathematical function. The VSEL approach eliminates an entire class of bugs
(comparing non-canonical values) at the cost of one extra conditional branch
per reduction.

When Plonky3 is integrated as a dependency (Workstream D), the Plonky3 crate's
own `Goldilocks` type will be used for STARK proof generation. The VSEL
`GoldilocksField` will be used for VSEL-internal computation (hashing, state
encoding). Conversion between the two types is a simple `u64` extraction +
canonicalization.

---

## 7. Equivalence Verification Plan

The formal equivalence proof in Section 3 establishes mathematical equivalence.
To provide defense-in-depth, the following tests are implemented in
`protocol/crates/vsel-crypto/tests/goldilocks_verification.rs`:

1. **Boundary value tests** (Task 1.2): Test `reduce128` at all boundary
   categories from the design document, verifying `reduce128(x) ≡ x (mod p)`
   and `reduce128(x) < p`.

2. **Property test P5** (Task 1.3): For 100,000+ random `u128` values, verify
   the algebraic identity `reduce128(x) ≡ x (mod p)` and `reduce128(x) < p`.

3. **Cross-implementation differential test**: For all boundary values and
   random samples, verify that `VSEL_reduce128(x) == Plonky3_reduce128(x) mod p`
   (to be implemented when Plonky3 dependency is added in Workstream D).

---

## 8. Appendix: Full Source Comparison

### Plonky3 `reduce128` (verbatim structure, paraphrased for compliance)

The Plonky3 function splits the 128-bit input into `(x_lo, x_hi)`, then
further splits `x_hi` into upper and lower 32-bit halves. It subtracts the
upper half from `x_lo` (with borrow correction by subtracting `NEG_ORDER`),
multiplies the lower half by `NEG_ORDER`, and adds the two results using a
specialized addition function that handles carry by adding `NEG_ORDER`. The
result may not be canonical.

### VSEL `reduce128` (verbatim structure)

The VSEL function splits the 128-bit input into `(x_lo, x_hi)`, computes
`x_hi * (2^32 - 1)` as a `u128`, adds it to `x_lo` as a `u128`, then checks
if the result exceeds 64 bits. If so, it applies a second reduction pass using
the same identity. The final result is canonicalized to `[0, p)`.

### Metal GPU `reduce128` (additional reference)

The Metal GPU implementation (by Carter Feldman, public domain) follows the
same algorithm as Plonky3/Plonky2: split `x_hi` into 32-bit halves, subtract
upper half from `x_lo`, multiply lower half by `0xFFFFFFFF`, add results with
carry correction. This confirms the Plonky3 approach is the industry-standard
algorithm for Goldilocks reduction.

---

## 9. Conclusion

The VSEL `reduce128` implementation is **correct** and **equivalent** to the
Plonky3 reference for all inputs in `[0, 2^128)`. The algorithmic differences
are deliberate design choices (canonical vs. non-canonical representation) that
do not affect mathematical correctness. No implementation alignment is required.

The formal equivalence proof (Section 3) and the bound analysis (Section 4.1)
provide the mathematical foundation. Property-based tests (Tasks 1.3-1.5) and
boundary tests (Task 1.2) provide empirical verification.
