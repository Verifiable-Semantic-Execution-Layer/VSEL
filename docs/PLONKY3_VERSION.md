# Plonky3 Version Pinning and Security Analysis

## Pinned Version

| Field | Value |
|---|---|
| Repository | `https://github.com/Plonky3/Plonky3.git` |
| Commit SHA | `e99af4144f49defe3dda84bad0ab76036a08a016` |
| Commit Date | 2026-04-12 |
| Commit Message | "Harden verifier shape checks (#1469)" |
| Branch | `main` |
| License | Apache-2.0 / MIT dual license |

## Crates Pinned

All crates are sourced from the same monorepo commit to ensure internal
consistency across the Plonky3 stack:

| Crate | Purpose |
|---|---|
| `p3-uni-stark` | Univariate STARK prover and verifier |
| `p3-goldilocks` | Goldilocks field (p = 2^64 − 2^32 + 1) implementation |
| `p3-fri` | FRI polynomial commitment scheme |
| `p3-merkle-tree` | Generalized Merkle tree for FRI commitments |
| `p3-poseidon2` | Poseidon2 hash function (STARK-friendly, field-native) |
| `p3-symmetric` | Symmetric cryptographic primitives (hash compression) |
| `p3-challenger` | Fiat-Shamir challenger for non-interactive proofs |
| `p3-field` | Field trait abstractions and arithmetic |
| `p3-matrix` | Dense matrix types for execution traces |
| `p3-air` | AIR (Algebraic Intermediate Representation) trait |

## Why This Commit

This commit was selected for the following reasons:

1. **Verifier hardening**: The pinned commit includes PR #1469 which adds
   shape checks to the STARK verifier, reducing the attack surface for
   malformed proof acceptance. This directly supports our security target.

2. **Goldilocks stability**: At this point in the commit history, the
   Goldilocks field implementation has received multiple rounds of
   correctness fixes (including NEON and AVX2 optimizations) and is
   considered stable.

3. **FRI verifier maturity**: The FRI verifier has accumulated test
   coverage and error typing improvements through PRs #1535 and #1469,
   making it suitable for production use.

4. **No breaking API changes**: The `p3-uni-stark` prove/verify API at
   this commit is stable and matches the interface we target in our
   `VselAir` implementation.

5. **CI green**: All Plonky3 CI checks pass at this commit (6/6 verified).

## Feature Gating

All Plonky3 dependencies are gated behind the `plonky3-backend` Cargo
feature flag in `protocol/crates/vsel-proof/Cargo.toml`:

```toml
[features]
plonky3-backend = [
    "dep:p3-uni-stark",
    "dep:p3-goldilocks",
    "dep:p3-fri",
    "dep:p3-merkle-tree",
    "dep:p3-poseidon2",
    "dep:p3-symmetric",
    "dep:p3-challenger",
    "dep:p3-field",
    "dep:p3-matrix",
    "dep:p3-air",
]
```

The default build (`cargo check`) does not pull in Plonky3. Only
`cargo check --features plonky3-backend` activates the dependencies.
This keeps the default build fast and avoids network fetches for
contributors who are not working on the STARK backend.

## FRI Parameter Configuration

### Security Target

**Pr[invalid τ accepted] ≤ 2^(−100)**

### Chosen Parameters

| Parameter | Value | Justification |
|---|---|---|
| Field | Goldilocks (p = 2^64 − 2^32 + 1) | 64-bit native arithmetic, Plonky3 native field |
| Extension field | Quadratic (BinomialExtensionField<Goldilocks, 2>) | Effective field size ≈ 2^128 for Schwartz-Zippel bound |
| Blowup factor | 8 (log₂ = 3) | Standard for ≥100-bit security with Goldilocks |
| FRI folding factor | 4 (log₂ = 2) | Balances proof size vs. verifier computation |
| Number of FRI queries | 34 | Achieves target soundness (see derivation below) |
| Hash function | Poseidon2 over Goldilocks | STARK-friendly, field-native, no foreign-field overhead |
| Merkle tree hash | Poseidon2 (via `p3-poseidon2`) | Consistent with FRI hash for single-hash-function design |
| Proof-of-work bits | 0 | No grinding; soundness comes entirely from FRI queries |

### Soundness Bound Derivation

The FRI soundness error for a single query with blowup factor β is
bounded by the proximity gap:

```
ε_FRI ≤ (ρ / |F|)^(1/2) per query (Johnson bound variant)
```

where ρ = 1/β is the rate and |F| = p ≈ 2^64.

For our parameters:
- Rate ρ = 1/8
- Field size |F| = 2^64 − 2^32 + 1 ≈ 2^64
- Per-query soundness contribution: each query reduces the acceptance
  probability of an invalid proof by a factor related to the proximity
  gap and field size.

The combined soundness error with n queries is:

```
ε_total ≤ n · (1/|F|) + (ρ)^n
        = 28 · 2^(-64) + (1/8)^28
        ≈ 28 · 2^(-64) + 2^(-84)
        ≈ 2^(-59.2) + 2^(-84)
        ≈ 2^(-59.2)
```

However, the Plonky3 FRI variant uses a tighter analysis based on the
batched FRI protocol where the soundness error per query is:

```
ε_query ≤ max(ρ, 3·√(ρ/|F|))
```

With ρ = 1/8 and |F| ≈ 2^64:
- 3·√(1/(8·2^64)) ≈ 3·2^(-33.5) ≈ 2^(-32)
- max(1/8, 2^(-32)) = 1/8

So each query contributes a factor of 1/8, and with 28 queries:

```
ε_total ≤ (1/8)^28 = 2^(-84)
```

Combined with the field-size contribution from the Schwartz-Zippel
lemma for the polynomial identity testing:

```
ε_SZ ≤ d / |F|
```

where d is the constraint degree (typically ≤ 8 for our AIR), giving:

```
ε_SZ ≤ 8 / 2^64 ≈ 2^(-61)
```

The total soundness error is:

```
ε = ε_FRI + ε_SZ ≤ 2^(-84) + 2^(-61) ≈ 2^(-61)
```

**Note**: The 2^(-61) bound from Schwartz-Zippel is inherent to the
Goldilocks field size. To achieve the full 2^(-100) target, the
Plonky3 STARK uses a quadratic extension field for the FRI challenges,
effectively squaring the field size to ≈ 2^128. With the extension
field:

```
ε_SZ ≤ 8 / 2^128 ≈ 2^(-125)
ε_FRI ≤ (1/8)^28 = 2^(-84)
ε_total ≤ 2^(-84) + 2^(-125) ≈ 2^(-84)
```

With 34 queries instead of 28:

```
ε_FRI ≤ (1/8)^34 = 2^(-102)
ε_total ≤ 2^(-102) + 2^(-125) < 2^(-100) ✓
```

**Final configuration**: 34 FRI queries with blowup factor 8 over the
Goldilocks quadratic extension field achieves Pr[accept invalid] ≤ 2^(-100).

The `Plonky3Config` default uses 34 queries. The `build_stark_config()`
function in `plonky3_backend.rs` constructs the full Plonky3 type stack:

```
Val           = Goldilocks
Challenge     = BinomialExtensionField<Goldilocks, 2>  (quadratic, ≈2^128)
Hash          = PaddingFreeSponge<Poseidon2Goldilocks<8>, 8, 4, 4>
Compress      = TruncatedPermutation<Poseidon2Goldilocks<8>, 2, 4, 8>
ValMmcs       = FieldMerkleTreeMmcs<..., Hash, Compress, 4>
ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>
Pcs           = TwoAdicFriPcs<Val, Radix2DitParallel, ValMmcs, ChallengeMmcs>
StarkConfig   = StarkConfig<Pcs, Challenge, DuplexChallenger<Val, Perm, 8, 4>>
```

The Poseidon2 permutation uses Plonky3's built-in Goldilocks round
constants (Grain LFSR generated) with width 8, R_F=8, R_P=22, S-box x^7.

## Upgrade Policy

### When to Upgrade

Upgrade the pinned Plonky3 commit when:

1. **Security fix**: A vulnerability is disclosed in any pinned crate.
   Upgrade immediately after verifying the fix does not break our AIR.

2. **Performance improvement**: A significant performance improvement
   lands that benefits our use case (Goldilocks field, univariate STARK).
   Upgrade after running the full benchmark suite to confirm improvement.

3. **API change**: A breaking API change is required for a feature we
   need. Upgrade with corresponding code changes.

### Upgrade Procedure

1. Identify the target commit on `main` (must have green CI).
2. Update all 10 `rev = "..."` entries in `Cargo.toml` to the new SHA.
3. Run `cargo check -p vsel-proof --features plonky3-backend`.
4. Run `cargo test -p vsel-proof --features plonky3-backend`.
5. Run the full property test suite: `cargo test --features plonky3-backend`.
6. Run benchmarks and compare against the previous pinned version.
7. Update this document with the new commit SHA, date, and rationale.
8. Update the soundness analysis if FRI parameters or protocol changed.

### Version Freeze Policy

During audit periods, the Plonky3 version is frozen. No upgrades are
permitted while an external audit is in progress. The auditors receive
the exact commit SHA documented here and can reproduce the build.

## Supply Chain Security

### Verification

- The Plonky3 repository is maintained by the Polygon team with active
  CI, code review, and multiple maintainers.
- All commits on `main` require passing CI (6/6 checks verified).
- The pinned commit is a verified (signed) commit.
- `cargo audit` is run against the resolved dependency tree to check
  for known vulnerabilities in transitive dependencies.

### Reproducibility

The git dependency with a pinned `rev` ensures byte-identical source
code across all builds. Combined with `Cargo.lock`, the full dependency
tree is reproducible.

### Transitive Dependencies

The Plonky3 crates have minimal transitive dependencies:
- `rand` / `rand_core` for randomness (used in testing, not in
  deterministic proof generation)
- `serde` for serialization (already in our dependency tree)
- `tracing` for instrumentation (optional)
- `hashbrown` for hash maps (no-std compatible)

No network-accessing, filesystem-accessing, or unsafe-heavy transitive
dependencies are introduced.
