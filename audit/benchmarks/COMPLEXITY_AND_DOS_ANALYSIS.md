# Worst-Case Complexity and DoS Vector Analysis

**Document**: VSEL Cryptographic Hardening — Requirement 7.2, 7.3
**Date**: 2025-07-15 (updated with empirical measurements from Plonky3-path benchmarks)
**Status**: Active — empirical data from `audit/benchmarks/BENCHMARK_RESULTS.md` §3 and §5

## 1. Worst-Case Time Complexity

### 1.1 Proof Generation

Two backends are measured: the hash-backend (SHA3-256 simulation) and the real Plonky3 STARK backend. The Plonky3 backend is the security-relevant code path for DoS analysis.

**Hash Backend (Simulation)**

| Operation | Input Size Parameter | Complexity Class | Constant Factor | Source | Notes |
|---|---|---|---|---|---|
| `prove()` — single trace | N = trace entries | O(N log N) | 5.56 µs | Measured | SHA3-256 hash-based simulation |
| `prove()` — 10-entry trace | N = 10 | O(N log N) | 24.39 µs | Measured | ~4.4× for 10× input (sub-linear) |
| `prove()` — 100-entry trace | N = 100 | O(N log N) | 295.02 µs | Measured | ~53× for 100× input (sub-linear) |

**Plonky3 STARK Backend (Real)**

| Operation | Input Size Parameter | Complexity Class | Constant Factor | Source | Notes |
|---|---|---|---|---|---|
| `prove()` — single trace | N = trace entries | O(N log N) | 111.58 µs | Measured | Real STARK proof via `p3_uni_stark::prove()` |
| `prove()` — 10-entry trace | N = 10 | O(N log N) | 642.58 µs | Measured | ~5.8× for 10× input (sub-linear) |
| `prove()` — 100-entry trace | N = 100 | O(N log N) | 6.95 ms | Measured | ~62× for 100× input (sub-linear) |

**Performance ratio**: Plonky3 proof generation is ~20–27× slower than the hash-backend simulation. The previous theoretical estimates (~50ms per entry, ~500ms for 10 entries, ~8s for 100 entries) were **3–4 orders of magnitude too high** — real Plonky3 STARK proving is far more efficient than estimated.

### 1.2 Proof Verification

Two backends are measured. Plonky3 STARK verification is the security-relevant code path.

| Operation | Input Size Parameter | Complexity Class | Constant Factor | Source | Notes |
|---|---|---|---|---|---|
| `verify()` — hash backend | Q = FRI queries (34) | O(Q × log T) | 934.76 ns (~0.001 ms) | Measured | SHA3-256 structural check only |
| `verify()` — Plonky3 STARK | Q = FRI queries (34) | O(Q × log T) | 812.43 µs (~0.81 ms) | Measured | Real FRI query verification + Merkle path checks |

Verification is sublinear in trace size — this is the key STARK advantage for DoS resistance.

**DoS threshold check**: Plonky3 STARK verification at 812.43 µs is **~123× below the 100ms DoS resistance threshold** (R5.5). ✅ PASS.

**Performance ratio**: Plonky3 verification is ~891× slower than the hash-backend simulation (812.43 µs vs 934.76 ns). The previous theoretical estimate (~5ms) was ~6× higher than the actual measurement — real Plonky3 STARK verification is more efficient than estimated.

### 1.3 Recursive Proof Composition

Composition currently uses **semantic composition** (SHA3-256 hash-based state chaining), not circuit-level recursion via `RecursiveVerifierAir`. See `docs/PROOF_LAYER.md` §Composition Architecture Status.

| Operation | Input Size Parameter | Complexity Class | Constant Factor | Source | Notes |
|---|---|---|---|---|---|
| `compose_proofs()` — 2 proofs | N = 2 | O(N × V) | 2.94 µs | Measured | Semantic (hash-based) binary composition |
| `compose_proofs()` — 5 proofs | N = 5 | O(N × V) | 4.82 µs | Measured | Linear in number of proofs |
| `compose_proofs()` — 10 proofs | N = 10 | O(N × V) | 6.49 µs | Measured | Linear scaling confirmed |
| `compose_incremental()` | 1 (constant) | O(V) | ~3 µs | Estimated | Single binary composition step (extrapolated from 2-proof measurement) |

**Note**: These measurements reflect the hash-backend semantic composition path. When circuit-level recursion is integrated (v1.1), composition cost will increase significantly because each step will involve a real STARK proof over the `RecursiveVerifierAir` circuit. The previous theoretical estimates (~100ms for 2 proofs, ~500ms for 10 proofs) assumed circuit-level recursion and are not applicable to the current semantic composition architecture.

### 1.4 Poseidon Permutation

| Operation | Input Size Parameter | Complexity Class | Constant Factor | Source | Notes |
|---|---|---|---|---|---|
| `permute()` | Fixed (t=12) | O(1) | 8.85 µs | Measured | 30 rounds × 12 elements × field ops |
| `hash_bytes()` — 1KB | B = 1024 bytes | O(B/r) | 169.49 µs | Measured | r = rate = 8 field elements; 5.76 MiB/s |
| `hash_bytes()` — 10KB | B = 10240 bytes | O(B/r) | 1.63 ms | Measured | 5.99 MiB/s; linear scaling |
| `hash_bytes()` — 100KB | B = 102400 bytes | O(B/r) | 16.31 ms | Measured | 5.99 MiB/s; linear scaling confirmed |
| `hash_bytes()` — 1MB | B = 1048576 bytes | O(B/r) | 168.12 ms | Measured | 5.95 MiB/s; linear scaling confirmed |

### 1.5 GoldilocksField Operations

| Operation | Input Size Parameter | Complexity Class | Constant Factor | Source | Notes |
|---|---|---|---|---|---|
| `add(a, b)` | Fixed | O(1) | 656.62 ps | Measured | Single u64 add + conditional subtract |
| `sub(a, b)` | Fixed | O(1) | 621.45 ps | Measured | Single u64 sub + conditional add |
| `mul(a, b)` | Fixed | O(1) | 1.20 ns | Measured | u128 multiply + reduce128 |
| `inv(a)` | Fixed | O(log p) | 354.54 ns | Measured | Fermat's little theorem: a^(p-2) |
| `pow(a, e)` | e = exponent bits | O(log e) | ~200ns for 64-bit e | Estimated | Square-and-multiply (not directly benchmarked) |
| `sbox(a)` | Fixed | O(1) | 7.87 ns | Measured | a^7 = a × a² × a⁴ (3 multiplications) |

### 1.6 Constraint System Compilation

| Operation | Input Size Parameter | Complexity Class | Constant Factor | Source | Notes |
|---|---|---|---|---|---|
| `compile()` — small SIR (3 transitions) | T = transitions | O(T × I) | 34.40 µs | Measured | I = invariants |
| `compile()` — medium SIR (10 transitions) | T = 10 | O(T × I) | 99.42 µs | Measured | ~2.9× for 3.3× input (linear) |
| `compile()` — large SIR (30 transitions) | T = 30 | O(T × I) | 289.38 µs | Measured | ~8.4× for 10× input (linear) |

### 1.7 Witness Construction

Witness construction is backend-agnostic (same `construct_witness` function). Plonky3-path measurements are shown; hash-backend results are within ~1% (see BENCHMARK_RESULTS.md §5.2).

| Operation | Input Size Parameter | Complexity Class | Constant Factor | Source | Notes |
|---|---|---|---|---|---|
| `construct_witness()` — 1 entry | N = trace entries | O(N) | 827.93 ns | Measured | Linear scan of trace |
| `construct_witness()` — 10 entries | N = 10 | O(N) | 9.54 µs | Measured | Linear scaling |
| `construct_witness()` — 100 entries | N = 100 | O(N) | 86.02 µs | Measured | Linear scaling confirmed |

## 2. DoS Vector Identification

### 2.1 Maximum Proof Size

**Vector**: An adversary submits an extremely large proof for verification.

- **Maximum acceptable size**: 10 MB
- **Rationale**: A legitimate STARK proof for a 100-entry trace is ~50KB. Even with recursive composition of 100 proofs, the proof size should not exceed 1MB. A 10MB limit provides 10× headroom.
- **Enforcement**: `verify()` and `deserialize_proof()` reject proofs > 10MB before parsing.
- **Impact if unmitigated**: Memory exhaustion during deserialization, CPU exhaustion during verification.

### 2.2 Maximum Constraint System Size

**Vector**: An adversary submits a constraint system with millions of constraints.

- **Maximum acceptable size**: 1,000,000 constraints
- **Rationale**: The largest legitimate VSEL constraint system (30 transitions × 10 invariants × 5 state fields) produces ~5,000 constraints. A 1M limit provides 200× headroom.
- **Enforcement**: `prove()` rejects constraint systems with > 1,000,000 constraints before AIR compilation.
- **Impact if unmitigated**: O(N log N) proof generation with N = 10^6 would take hours.

### 2.3 Maximum Witness Size

**Vector**: An adversary submits a witness with millions of intermediate states.

- **Maximum acceptable size**: 100,000 intermediate states
- **Rationale**: A legitimate witness for a 100-entry trace has ~100 intermediate states. A 100K limit provides 1000× headroom.
- **Enforcement**: `prove()` rejects witnesses with > 100,000 intermediate states before trace generation.
- **Impact if unmitigated**: Memory exhaustion during trace matrix construction.

### 2.4 Maximum Recursion Depth

**Vector**: An adversary requests recursive composition with extreme depth.

- **Maximum acceptable depth**: 100 levels
- **Rationale**: Each recursion level adds ~10K-50K constraints for the verifier circuit. At depth 100, the outer proof would have ~5M constraints — already at the edge of tractability.
- **Enforcement**: `compose_proofs()` rejects sequences with > 100 proofs.
- **Impact if unmitigated**: Exponential growth in proof generation time and memory.

### 2.5 Adversarial Inputs Maximizing Verification Time

**Vector**: Crafted proofs that maximize FRI query verification time.

- **Attack surface**: The verifier performs Q = 34 FRI queries, each requiring a Merkle path verification of depth log₂(T) where T is the trace length.
- **Worst case**: Maximum trace length with maximum Merkle tree depth.
- **Mitigation**: Verification time is O(Q × log T) which is bounded by the proof size limit (10MB). Empirical measurement shows Plonky3 STARK verification at 812.43 µs (~0.81 ms) for a 10-entry trace proof — well under the 100ms threshold. Even with maximum-size proofs, verification is bounded by the proof size limit.
- **Enforcement**: Proof size limit (10MB) implicitly bounds verification time. Measured verification time (812.43 µs) provides ~123× headroom below the 100ms DoS threshold.

## 3. Resource Bound Summary

| Resource | Maximum | Error on Violation | Enforcement Point |
|---|---|---|---|
| Constraint system size | 1,000,000 constraints | `ProofGenerationFailed("constraint system exceeds maximum: N > 1000000")` | `prove()` entry |
| Witness intermediate states | 100,000 states | `ProofGenerationFailed("witness exceeds maximum: N > 100000")` | `prove()` entry |
| Proof size for verification | 10 MB (10,485,760 bytes) | `DeserializationFailed("proof exceeds maximum size: N > 10485760")` | `verify()` / `deserialize_proof()` entry |
| Recursion depth | 100 proofs | `ProofGenerationFailed("recursion depth exceeds maximum: N > 100")` | `compose_proofs()` entry |

## 4. Mitigation Strategy

1. **Input validation first**: All resource bounds are checked before any expensive computation begins.
2. **Explicit errors**: Each bound violation returns a specific error message identifying the violated bound and the actual input size.
3. **Defense in depth**: Even if one bound is bypassed, the others provide independent protection.
4. **Monitoring**: Benchmark results establish baseline performance. Any operation exceeding 2× the baseline on reference hardware should trigger investigation.

## 5. Reference Hardware

Benchmark results are collected on the following reference configuration:

- **CPU**: Apple M4 Pro
- **RAM**: 24 GB (25,769,803,776 bytes)
- **OS**: macOS 26.3.1 (Build 25D771280a)
- **Rust version**: rustc 1.96.0-nightly (20f19f461 2026-03-21)

See `audit/benchmarks/BENCHMARK_RESULTS.md` for actual measurements.
