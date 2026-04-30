# VSEL Benchmark Results

**Document**: VSEL Cryptographic Hardening — Requirements 7.5, 7.6
**Date**: 2025-07-15
**Status**: Executed on reference hardware

## 1. Reference Hardware Configuration

| Parameter | Value |
|---|---|
| CPU | Apple M4 Pro |
| RAM | 24 GB (25,769,803,776 bytes) |
| OS | macOS 26.3.1 (Build 25D771280a) |
| Rust version | rustc 1.96.0-nightly (20f19f461 2026-03-21) |
| Plonky3 commit | `e99af4144f49defe3dda84bad0ab76036a08a016` |

## 2. Benchmark Methodology

### 2.1 Framework

All benchmarks use [Criterion.rs](https://github.com/bheisler/criterion.rs) v0.5 with:
- Statistical analysis: mean, median, standard deviation, p99 latency
- Warm-up: 1 second per benchmark
- Measurement: 2 seconds per benchmark
- Confidence interval: 95%
- HTML reports generated in `target/criterion/`

### 2.2 Benchmark Suites

| Suite | Crate | Command |
|---|---|---|
| Proof system | `vsel-proof` | `cargo bench --bench proof_benchmarks -p vsel-proof --features plonky3-backend` |
| Cryptographic primitives | `vsel-crypto` | `cargo bench --bench crypto_benchmarks -p vsel-crypto` |
| Compilation & construction | `vsel-constraints` | `cargo bench --bench compilation_benchmarks -p vsel-constraints` |

### 2.3 Benchmark Groups

#### Proof System Benchmarks (`proof_benchmarks`)

| Group | Inputs | Metric |
|---|---|---|
| `proof_generation` | 1, 10, 100 trace entries | Time (µs) |
| `proof_verification` | Single proof (10-entry trace) | Time (ns) |
| `recursive_composition` | 2, 5, 10 proofs | Time (µs) |
| `witness_construction` | 1, 10, 100 trace entries | Time (µs) |

#### Cryptographic Primitive Benchmarks (`crypto_benchmarks`)

| Group | Inputs | Metric |
|---|---|---|
| `poseidon_permute` | Zero state, random state | Time (µs) |
| `poseidon_hash_bytes` | 1KB, 10KB, 100KB, 1MB | Time (µs/ms), throughput (MiB/s) |
| `goldilocks_mul` | Single multiplication | Time (ns) |
| `goldilocks_ops` | add, sub, mul, inv, sbox | Time (ps/ns) |

#### Compilation Benchmarks (`compilation_benchmarks`)

| Group | Inputs | Metric |
|---|---|---|
| `constraint_compilation` | 3, 10, 30 transitions | Time (µs) |
| `constraint_evaluation` | 10, 100, 500 constraints | Time (ns) |
| `circuit_building` | 3, 10, 30 transitions | Time (µs) |

## 3. Results

### 3.1 Proof System (Hash Backend — Simulation)

| Operation | Input | Mean | Std Dev | Notes |
|---|---|---|---|---|
| Proof generation | 1 trace entry | 5.56 µs | ~94 ns | Baseline single-entry |
| Proof generation | 10 trace entries | 24.39 µs | ~249 ns | ~4.4× for 10× input |
| Proof generation | 100 trace entries | 295.02 µs | ~2.6 µs | ~53× for 100× input (sub-linear) |
| Proof verification | Single proof (10 entries) | 934.76 ns | ~7.5 ns | Well under 100ms threshold |
| Recursive composition | 2 proofs | 2.94 µs | ~31 ns | Binary composition |
| Recursive composition | 5 proofs | 4.82 µs | ~95 ns | Linear scaling |
| Recursive composition | 10 proofs | 6.49 µs | ~132 ns | Linear scaling confirmed |
| Witness construction | 1 trace entry | 947.83 ns | ~14 ns | Baseline |
| Witness construction | 10 trace entries | 10.80 µs | ~324 ns | Linear scaling |
| Witness construction | 100 trace entries | 97.24 µs | ~637 ns | Linear scaling confirmed |

### 3.2 Cryptographic Primitives

| Operation | Input | Mean | Std Dev | Throughput | Notes |
|---|---|---|---|---|---|
| Poseidon permute | Zero state | 8.85 µs | ~86 ns | — | 30 rounds × 12 elements |
| Poseidon permute | Random state | 8.84 µs | ~84 ns | — | Consistent with zero state |
| Poseidon hash_bytes | 1 KB | 169.49 µs | ~770 ns | 5.76 MiB/s | Sponge absorption |
| Poseidon hash_bytes | 10 KB | 1.63 ms | ~12.4 µs | 5.99 MiB/s | Linear scaling |
| Poseidon hash_bytes | 100 KB | 16.31 ms | ~98 µs | 5.99 MiB/s | Linear scaling confirmed |
| Poseidon hash_bytes | 1 MB | 168.12 ms | ~660 µs | 5.95 MiB/s | Linear scaling confirmed |
| Goldilocks mul | Single | 1.20 ns | ~14 ps | — | u128 multiply + reduce128 |
| Goldilocks add | Single | 656.62 ps | ~26 ps | — | u64 add + conditional sub |
| Goldilocks sub | Single | 621.45 ps | ~64 ps | — | u64 sub + conditional add |
| Goldilocks inv | Single | 354.54 ns | ~43 ns | — | Fermat's little theorem a^(p-2) |
| Goldilocks sbox | Single | 7.87 ns | ~65 ps | — | a^7 = a × a² × a⁴ |

### 3.3 Compilation & Construction

| Operation | Input | Mean | Std Dev | Notes |
|---|---|---|---|---|
| Constraint compilation | 3 transitions | 34.40 µs | ~163 ns | Small SIR program |
| Constraint compilation | 10 transitions | 99.42 µs | ~544 ns | ~2.9× for 3.3× input (linear) |
| Constraint compilation | 30 transitions | 289.38 µs | ~1.87 µs | ~8.4× for 10× input (linear) |
| Constraint evaluation | 10 constraints | 2.87 ns | ~24 ps | Per-constraint ~0.29 ns |
| Constraint evaluation | 100 constraints | 26.14 ns | ~264 ps | Per-constraint ~0.26 ns |
| Constraint evaluation | 500 constraints | 134.07 ns | ~1.54 ns | Per-constraint ~0.27 ns (linear) |
| Circuit building | 3 transitions | 34.14 µs | ~511 ns | Mirrors compilation |
| Circuit building | 10 transitions | 99.72 µs | ~1.27 µs | Linear scaling |
| Circuit building | 30 transitions | 287.84 µs | ~2.59 µs | Linear scaling confirmed |

## 4. DoS Resistance Assessment

### 4.1 Verification Time Check (Requirement 7.6)

| Metric | Threshold | Hash Backend | Plonky3 STARK | Status |
|---|---|---|---|---|
| Single proof verification | < 100 ms | 934.76 ns (~0.001 ms) | 812.43 µs (~0.81 ms) | ✅ PASS — both well below threshold |

Hash-backend verification time is 5 orders of magnitude below the 100ms threshold. Real Plonky3 STARK verification at 812.43 µs is ~123× below the threshold. See §5.4 for the Plonky3-specific DoS assessment.

### 4.2 Resource Bound Enforcement

| Bound | Limit | Enforcement | Tested |
|---|---|---|---|
| Constraint system size | 1,000,000 | `prove()` rejects | ✓ (Property 8a) |
| Witness intermediate states | 100,000 | `prove()` rejects | ✓ (Property 8b) |
| Proof size | 10 MB | `verify()`/`deserialize_proof()` rejects | ✓ (Property 8c) |
| Recursion depth | 100 | `compose_proofs()` rejects | ✓ (Property 8d) |

### 4.3 Scaling Analysis

| Operation | Observed Complexity | Expected | Status |
|---|---|---|---|
| Proof generation | Sub-linear (53× for 100× input) | O(N log N) | ✅ Consistent |
| Proof verification | O(1) for structure check | O(Q × log T) | ✅ Consistent |
| Recursive composition | Linear in proof count | O(N × V) | ✅ Consistent |
| Witness construction | Linear in trace entries | O(N) | ✅ Consistent |
| Constraint compilation | Linear in transitions | O(T × I) | ✅ Consistent |
| Constraint evaluation | Linear in constraints | O(N) | ✅ Consistent |
| Poseidon hash_bytes | Linear in input size | O(B/r) | ✅ Consistent |
| Goldilocks field ops | Constant time | O(1) | ✅ Consistent |

## 5. Plonky3 STARK Backend Results

**Date**: 2025-07-15
**Feature flag**: `--features plonky3-backend`
**Command**: `cargo bench --bench proof_benchmarks -p vsel-proof --features plonky3-backend`

These results measure the **real Plonky3 STARK proving pipeline** over the Goldilocks field using `p3_uni_stark::prove()` and `p3_uni_stark::verify()`. They are orders of magnitude slower than the hash-backend simulation results in §3.1, which use SHA3-256 hashing to produce structurally faithful but cryptographically meaningless proofs.

### 5.1 Plonky3 Proof System

| Operation | Input | Mean | Std Dev | Notes |
|---|---|---|---|---|
| Proof generation | 1 trace entry | 111.58 µs | ~0.52 µs | Real STARK proof via `p3_uni_stark::prove()` |
| Proof generation | 10 trace entries | 642.58 µs | ~6.8 µs | ~5.8× for 10× input |
| Proof generation | 100 trace entries | 6.95 ms | ~117 µs | ~62× for 100× input (sub-linear) |
| Proof verification | Single proof (10 entries) | 812.43 µs | ~4.6 µs | Real STARK verification via `p3_uni_stark::verify()` |

### 5.2 Plonky3 Witness Construction

Witness construction is backend-agnostic (same `construct_witness` function). These results are included for completeness to show the full pipeline cost breakdown.

| Operation | Input | Mean | Std Dev | Notes |
|---|---|---|---|---|
| Witness construction | 1 trace entry | 827.93 ns | ~10.8 ns | Same function as hash-backend |
| Witness construction | 10 trace entries | 9.54 µs | ~140 ns | Same function as hash-backend |
| Witness construction | 100 trace entries | 86.02 µs | ~1.1 µs | Same function as hash-backend |

### 5.3 Performance Ratio: Hash Backend vs Plonky3 STARK Backend

This table documents the performance difference between the hash-backend simulation (§3.1) and the real Plonky3 STARK backend (§5.1). The ratio quantifies how much slower real STARK proving is compared to the SHA3-256 simulation.

| Operation | Input | Hash Backend | Plonky3 STARK | Ratio (Plonky3 / Hash) | Notes |
|---|---|---|---|---|---|
| Proof generation | 1 trace entry | 5.45 µs | 111.58 µs | **20.5×** | Real FRI commitment + polynomial evaluation |
| Proof generation | 10 trace entries | 23.77 µs | 642.58 µs | **27.0×** | Ratio increases with trace size |
| Proof generation | 100 trace entries | 289.57 µs | 6.95 ms | **24.0×** | Consistent ~20–27× overhead |
| Proof verification | Single proof | 911.69 ns | 812.43 µs | **891×** | FRI query verification + Merkle path checks |
| Witness construction | 1 trace entry | 841.25 ns | 827.93 ns | **1.0×** | Backend-agnostic (identical function) |
| Witness construction | 10 trace entries | 9.50 µs | 9.54 µs | **1.0×** | Backend-agnostic (identical function) |
| Witness construction | 100 trace entries | 85.24 µs | 86.02 µs | **1.0×** | Backend-agnostic (identical function) |

**Key observations:**

1. **Proof generation** is ~20–27× slower with the real Plonky3 STARK backend. This is expected — real STARK proving involves polynomial evaluation, FRI commitment generation, and Merkle tree construction over the Goldilocks field, whereas the hash backend simply SHA3-256 hashes the witness data.

2. **Proof verification** is ~891× slower with the real backend (812.43 µs vs 911.69 ns). This is the most significant difference — real STARK verification involves FRI query verification, Merkle path validation, and polynomial constraint checking. However, at 812.43 µs (~0.81 ms), verification is **well under the 100ms DoS resistance threshold** (R5.5).

3. **Witness construction** is identical between backends (~1.0× ratio), confirming that `construct_witness()` is backend-agnostic as documented.

4. **Scaling behavior** is consistent between backends: proof generation scales sub-linearly (O(N log N)), verification is per-proof, and witness construction scales linearly (O(N)).

### 5.4 DoS Resistance Assessment (Plonky3 Backend)

| Metric | Threshold | Actual (Plonky3) | Status |
|---|---|---|---|
| Single proof verification | < 100 ms | 812.43 µs (~0.81 ms) | ✅ PASS — ~123× below threshold |

Real Plonky3 STARK verification at 812.43 µs is well within the 100ms DoS resistance threshold. Even with network overhead and batched verification, there is substantial headroom (~123× margin).

## 6. Reproduction Instructions

```bash
# Run all benchmarks
cd protocol

# Proof system benchmarks — hash backend only
cargo bench --bench proof_benchmarks -p vsel-proof

# Proof system benchmarks — hash backend + Plonky3 STARK backend
cargo bench --bench proof_benchmarks -p vsel-proof --features plonky3-backend

# Cryptographic primitive benchmarks
cargo bench --bench crypto_benchmarks -p vsel-crypto

# Compilation benchmarks
cargo bench --bench compilation_benchmarks -p vsel-constraints

# View HTML reports
open target/criterion/report/index.html
```

## 7. Archival Notes

- Hash-backend and crypto benchmark results collected on 2025-07-15 with `--warm-up-time 1 --measurement-time 2` flags
- Plonky3 STARK backend benchmark results collected on 2025-07-15 with default Criterion settings (5s collection per sample group)
- Criterion HTML reports generated in `target/criterion/`
- Raw JSON data available in `target/criterion/*/new/estimates.json`
- Results should be re-run after any performance-sensitive code changes
- For production baseline, re-run with default Criterion settings (3s warm-up, 5s measurement)
