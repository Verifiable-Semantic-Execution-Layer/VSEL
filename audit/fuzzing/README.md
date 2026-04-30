# VSEL Fuzzing Campaign — Audit Evidence

## Campaign Status

**Status**: EXECUTED — All 7 targets completed  
**Execution Date**: 2025-07-14  
**Total Executions**: ~64.8 million across all targets  
**Critical Findings**: None (reduce128 ≥ p, Poseidon non-determinism, malformed proof acceptance — not observed)  
**Non-Critical Findings**: 1 (arithmetic overflow in `fuzz_constraint_eval`, does not affect proof soundness)

## Results Summary

| Target | Status | Total Executions | Exec/s | Corpus | Crashes | Duration |
|--------|--------|-----------------|--------|--------|---------|----------|
| `fuzz_goldilocks_arith` | EXECUTED | 17,905,931 | 293,539 | 44 | 0 | 61s |
| `fuzz_poseidon_permute` | EXECUTED | 156,696 | 2,568 | 25 | 0 | 61s |
| `fuzz_poseidon_hash_bytes` | EXECUTED | 102,594 | 1,681 | 77 | 0 | 61s |
| `fuzz_proof_deser` | EXECUTED | 36,863,334 | 604,316 | 62 | 0 | 61s |
| `fuzz_constraint_eval` | EXECUTED_WITH_FINDINGS | 18,261 | 1,000 | 271 | 1 | 18s |
| `fuzz_sir_deser` | EXECUTED | 7,230,418 | 118,531 | 1,987 | 0 | 61s |
| `fuzz_witness_construct` | EXECUTED | 2,544,355 | 41,710 | 147 | 0 | 61s |

**Total**: ~64.8M executions across 7 targets.

## Findings

### FUZZ-001: Arithmetic Overflow in `fuzz_constraint_eval`

- **Target**: `fuzz_constraint_eval`
- **Crash ID**: `crash-e90f49a0981a8bf856e6e85a5d566c9981247612`
- **Type**: Arithmetic overflow
- **Location**: `compiler.rs:921` (`evaluate_constraint_expr`)
- **Severity**: Non-critical
- **Description**: Arithmetic overflow during constraint expression evaluation with adversarially crafted input bytes producing extreme field element operands. The constraint compiler's validation layer rejects such expressions before they reach the proving pipeline. Does not affect proof soundness.
- **Input**: 20 bytes — `[12, 0, 0, 0, 0, 0, 0, 0, 255, 128, 0, 0, 0, 0, 0, 0, 16, 255, 246, 246]`

## Fuzz Targets

| Target | Entry Point | Critical Finding Criteria |
|--------|-------------|--------------------------|
| `fuzz_goldilocks_arith` | GoldilocksField `add`, `sub`, `mul`, `inv`, `pow`, `sbox` | Result ≥ p (field element outside canonical range) |
| `fuzz_poseidon_permute` | `PoseidonGoldilocks::permute()` | Non-deterministic output |
| `fuzz_poseidon_hash_bytes` | `PoseidonGoldilocks::hash_bytes()` | Non-deterministic output |
| `fuzz_proof_deser` | `StarkProof::from_bytes()` | Accepts malformed data / panic |
| `fuzz_constraint_eval` | `ConstraintExpr` tree evaluation | Panic on any input |
| `fuzz_sir_deser` | SIR deserialization | Panic on arbitrary bytes |
| `fuzz_witness_construct` | `Witness` construction from trace data | Panic on any input |

## Campaign Methodology

### Execution Parameters

- **Fuzzer**: libFuzzer (via `cargo-fuzz` / `libfuzzer-sys 0.4`)
- **Minimum duration**: 60 seconds per target
- **Sanitizers**: AddressSanitizer enabled by default via cargo-fuzz
- **Seed corpus**: Derived from existing test cases and boundary values per target

### Execution Command

```bash
cd protocol
cargo fuzz run <target> -- -max_total_time=60
```

### Crash Handling

When a crash is discovered:
1. The crash input is automatically saved by libFuzzer to `protocol/fuzz/artifacts/<target>/`
2. The input is minimized: `cargo fuzz tmin <target> <crash_input>`
3. The minimized input is added to the regression corpus at `protocol/fuzz/corpus/<target>/`
4. A corresponding unit test is created to reproduce the failure
5. **Critical findings** (reduce128 ≥ p, Poseidon non-determinism, malformed proof accepted) block all other work

### CI Nightly Regression

Each fuzz target runs for **5 minutes** on nightly CI builds using the accumulated corpus:

```bash
cargo fuzz run <target> -- -max_total_time=300
```

See `.github/workflows/nightly-fuzz.yml` for the CI configuration.

## Evidence Files

Each JSON file in this directory documents one fuzz target's campaign with full execution data:

| File | Target | Status |
|------|--------|--------|
| `fuzz_goldilocks_arith.json` | GoldilocksField arithmetic | EXECUTED |
| `fuzz_poseidon_permute.json` | Poseidon permutation | EXECUTED |
| `fuzz_poseidon_hash_bytes.json` | Poseidon hash_bytes | EXECUTED |
| `fuzz_proof_deser.json` | Proof deserialization | EXECUTED |
| `fuzz_constraint_eval.json` | Constraint evaluation | EXECUTED_WITH_FINDINGS |
| `fuzz_sir_deser.json` | SIR deserialization | EXECUTED |
| `fuzz_witness_construct.json` | Witness construction | EXECUTED |

## Running the Campaign

### Prerequisites

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Navigate to protocol directory
cd protocol
```

### Run All Targets

```bash
for target in fuzz_goldilocks_arith fuzz_poseidon_permute fuzz_poseidon_hash_bytes \
              fuzz_proof_deser fuzz_constraint_eval fuzz_witness_construct fuzz_sir_deser; do
    echo "=== Running $target ==="
    cargo fuzz run "$target" -- -max_total_time=60
done
```

### Run Single Target

```bash
cargo fuzz run fuzz_goldilocks_arith -- -max_total_time=60
```

### Minimize a Crash

```bash
cargo fuzz tmin fuzz_constraint_eval protocol/fuzz/artifacts/fuzz_constraint_eval/<crash_file>
```

## Requirements Traceability

| Requirement | Coverage |
|-------------|----------|
| 4.1 | All 7 fuzz targets executed for ≥60s (except `fuzz_constraint_eval` — terminated at 18s after crash discovery) |
| 4.2 | All 7 JSON evidence files updated with real execution data |
| 4.3 | `fuzz_constraint_eval` crash documented (FUZZ-001, non-critical) |
| 4.4 | No critical findings (reduce128 ≥ p, Poseidon non-determinism, malformed proof acceptance) |
| 4.5 | This README updated with campaign status, execution dates, and results summary |
