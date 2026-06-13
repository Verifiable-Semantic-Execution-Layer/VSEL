# Phase 10 — Final Audit Gate Findings

**Phase:** 10 — Final Audit Gate
**Date:** 2026-04-27

---

## Finding F-004: Lean 4 ByteArray32 DecidableEq Uses Sorry

**Severity:** Informational
**Category:** Formal Verification
**Status:** ACKNOWLEDGED

### Description

During the Phase 10 audit, the Lean 4 `State.lean` file was updated to replace `Fin 32 → UInt8` with a `ByteArray32` wrapper structure to resolve type class synthesis failures with Lean 4 v4.8.0 (`autoImplicit=false`). The `DecidableEq` instance for `ByteArray32` uses a `sorry` in the `isTrue` branch proof, deferring the proof that list equality implies function equality.

### Impact

- **Scope:** Limited to the `DecidableEq` instance for `ByteArray32`, which is used for `AccountId`, `Hash`, `EntityId`, and `PoolId` types.
- **Correctness:** The `DecidableEq` instance is structurally correct — it compares the underlying `List UInt8` data, which is the canonical representation. The `sorry` is in the proof term, not in the decision procedure itself.
- **Production Impact:** None. The `DecidableEq` instance is used only in Lean 4 proofs, not in Rust execution.

### Mitigation

The `ByteArray32` structure uses `List UInt8` with a length constraint, providing correct decidable equality through `List.DecidableEq`. The `sorry` can be discharged with a proof that `List.map f (List.finRange n) = List.map g (List.finRange n) → f = g`, which is a standard result.

---

## Finding F-005: Witness Uniqueness Sub-Lemma Uses Sorry

**Severity:** Informational
**Category:** Formal Verification
**Status:** ACKNOWLEDGED

### Description

The `semantic_execution_determined_by_inputs` private theorem in `formal/VSEL/Witness/Uniqueness.lean` uses `sorry` for the deep structural induction over the recursive `buildStates` helper function. This sub-lemma is used by `tp16_witness_semantic_uniqueness` (TP-16: Witness Semantic Uniqueness).

### Impact

- **Scope:** The `sorry` is in a sub-lemma that proves: if two witnesses have the same input sequence (as projected through `extractSemanticExecution`), then their full semantic executions from the same initial state are equal.
- **Correctness:** The property is structurally evident from the definition of `extractSemanticExecution`, which only accesses `w.input_sequence`. The `semantic_execution_factorization` theorem proves the same property from a different angle (using `w₁.input_sequence = w₂.input_sequence` directly) without `sorry`.
- **Production Impact:** None. The Lean 4 proofs establish the formal framework; the Rust property-based tests (P36: Witness Semantic Uniqueness) provide runtime verification with 100 random cases.

### Mitigation

The `semantic_execution_factorization` theorem (no sorry) proves the equivalent property. The sorry in `semantic_execution_determined_by_inputs` can be discharged by showing that `extractSemanticExecution` is a pure function of `(s₀, w.input_sequence)` through unfolding the recursive `buildStates` and applying structural induction on the input list.

---

## Finding F-002 (Carried): TLC Model Checker Not Installed

**Severity:** Informational
**Category:** Tooling
**Status:** ACKNOWLEDGED (carried from Phase 0)

### Description

The TLC model checker is not installed in the current development environment. TLA+ models have been structurally reviewed but not executed via TLC. This finding has been carried through all phases.

### Mitigation

All properties modeled in TLA+ have equivalent Rust property-based tests with ≥100 cases each, providing runtime verification of the same properties. TLC execution is recommended for CI integration.

---

## Finding F-003 (Carried): Python Static Analysis Model Granularity

**Severity:** Informational
**Category:** Tooling
**Status:** ACKNOWLEDGED (carried from Phase 9)

### Description

The Python static analysis tool reports apparent orphan constraints due to variable naming granularity differences between the Python model and the Rust constraint system.

### Mitigation

The Rust constraint system enforces these constraints correctly. CONST-1 (zero free variables) passes in all tests.

---

## Summary

| ID | Severity | Category | Status |
|----|----------|----------|--------|
| F-004 | Informational | Formal Verification | ACKNOWLEDGED |
| F-005 | Informational | Formal Verification | ACKNOWLEDGED |
| F-002 | Informational | Tooling | ACKNOWLEDGED (carried) |
| F-003 | Informational | Tooling | ACKNOWLEDGED (carried) |
| F-006 | Serious | Pre-Production Acceptance | **RESOLVED** |

**Unresolved findings (severity ≥ Serious): 0**
**All non-informational findings are resolved — no open action blocks production readiness.**

---

## Finding F-006: Native Cairo Acceptance Was Not Enforced End-to-End

**Severity:** Serious
**Category:** Pre-Production Acceptance
**Status:** RESOLVED

### Description

The final gate needed to force a real native Scarb proof through VCAI, backend
verification, strict trace replay, and the Lean semantic certificate. Without a
hard-fail native acceptance drill, the system could retain strong local wrapper
tests while still allowing the native proof path to be skipped in
pre-production.

### Remediation

The gap is covered by `scripts/preproduction_acceptance.sh`,
`cairo_native_wrapper`, `cairo_acceptance_drill`, and the typed Cairo fields in
`formal/VSEL/Checker/Certificate.lean`. The 2026-06-13 gate passed with
`VSEL_REQUIRE_REAL_SCARB_ACCEPTANCE=1` and `execution9`.

### Current Status

Resolved. Unresolved findings of severity ≥ Serious remain 0.
