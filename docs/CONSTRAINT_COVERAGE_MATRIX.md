**Verifiable Semantic Execution Layer (VSEL)**

# CONSTRAINT COVERAGE MATRIX

## 1. Purpose

This document provides the traceability link between semantic properties and their constraint encodings.

Without this matrix, the system has constraints and it has properties, but no proof that one enforces the other.

> A constraint without traceability to a semantic property is noise. A property without traceability to a constraint is a wish.

---

## 2. Matrix Structure

The matrix relates three dimensions:

1. **Semantic Properties** (invariants, safety properties, transition rules)
2. **Transition Classes** (init, update, noop, error, batch)
3. **Constraint Identifiers** (specific constraints in the derived system)

Each cell answers: "Which constraints enforce this property for this transition class?"

Coverage status:
- **Full**: Property is completely enforced by identified constraints
- **Partial**: Property is partially enforced; gap identified
- **None**: Property has no constraint coverage for this class
- **N/A**: Property is not applicable to this class

---

## 3. Invariant × Transition Coverage

### 3.1 Local Invariants

| Invariant | T_init | T_update | T_noop | T_error | T_batch |
|-----------|--------|----------|--------|---------|---------|
| L_valid (Apply correctness) | [constraints] | [constraints] | [constraints] | [constraints] | [constraints] |
| L_state (pre/post validity) | [constraints] | [constraints] | [constraints] | [constraints] | [constraints] |
| L_cons (resource conservation) | N/A | [constraints] | N/A (no change) | [constraints] | [constraints] |
| L_bounded (bounded mutation) | N/A | [constraints] | Full (Δ=0) | [constraints] | [constraints] |
| L_det (determinism) | [structural] | [structural] | [structural] | [structural] | [structural] |

For each [constraints] cell, the specific constraint IDs must be listed when the constraint system is implemented.

### 3.2 Global Invariants

| Invariant | T_init | T_update | T_noop | T_error | T_batch |
|-----------|--------|----------|--------|---------|---------|
| G_valid (state validity) | [constraints] | [constraints] | [constraints] | [constraints] | [constraints] |
| G_struct (structural integrity) | [constraints] | [constraints] | [constraints] | [constraints] | [constraints] |
| G_commit (commitment consistency) | [constraints] | [constraints] | [constraints] | [constraints] | [constraints] |
| G_mono (monotonic metadata) | [constraints] | [constraints] | [constraints] | [constraints] | [constraints] |
| G_env (environment consistency) | [constraints] | [constraints] | [constraints] | [constraints] | [constraints] |

### 3.3 Temporal Invariants

| Invariant | Enforcement Mechanism | Constraint Coverage |
|-----------|----------------------|-------------------|
| T_valid (trace validity) | Per-transition constraints + chain linking | [constraints] |
| T_no_revert (no rollback) | Monotonicity constraints on τ | [constraints] |
| T_cons (cumulative conservation) | Per-step conservation + inductive argument | [constraints] |
| T_causal (causality) | Ordering constraints on trace entries | [constraints] |
| T_complete (completeness) | Trace commitment structure | [constraints] |

### 3.4 Cross-Layer Invariants

| Invariant | Enforcement Mechanism | Constraint Coverage |
|-----------|----------------------|-------------------|
| X_exec (impl = spec) | Semantic mapping commutativity | THM-1 discharge |
| X_constraint (valid ⟺ satisfies) | Soundness + completeness | LEM-4, LEM-5 |
| X_proof (verify ⟹ valid) | Proof binding + constraint soundness | THM-8 |

---

## 4. State Field × Transition Coverage

For each field in the state, document which constraints govern it under each transition class.

### 4.1 Canonical State Fields

| Field | T_init | T_update | T_noop | T_error | T_batch |
|-------|--------|----------|--------|---------|---------|
| accounts.balance | Genesis constraint | Transfer/update constraint | Equality to prior | Equality to prior | Per-item constraint |
| accounts.nonce | Zero constraint | Increment constraint | Equality to prior | Equality to prior | Multi-increment |
| storage[key] | Genesis constraint | Write constraint | Equality to prior | Equality to prior | Per-item write |
| system_data | Genesis constraint | Update constraint | Equality to prior | Equality to prior | Aggregate update |

**Rule**: Every cell must have an identified constraint. Empty cell = unconstrained field = vulnerability.

### 4.2 Derived State Fields

| Field | Derivation Constraint | Recomputation Enforced? |
|-------|----------------------|------------------------|
| state_root | Merkle computation from canonical | [yes/no + constraint ID] |
| auxiliary_roots | Computation from relevant canonical subset | [yes/no + constraint ID] |
| aggregates | Computation from canonical data | [yes/no + constraint ID] |

**Rule**: Every derived field must have a constraint enforcing D = Derive(C). Trusting cached derived values is forbidden.

### 4.3 Non-Mutated Field Carry-Over

For each transition class, list fields that should NOT change and verify explicit equality constraints exist:

| Transition Class | Non-Mutated Fields | Equality Constraints Present? |
|-----------------|-------------------|------------------------------|
| T_update (transfer) | All accounts except sender/receiver | [constraint IDs] |
| T_update (storage write) | All accounts, all storage except target key | [constraint IDs] |
| T_noop | ALL fields | [constraint IDs] |
| T_error | ALL fields (or explicit error state) | [constraint IDs] |

**This is the carry-over table. It is the most commonly missing constraint family in ZK systems.**

---

## 5. Proof Obligation × Constraint Coverage

| Proof Obligation | Required Constraints | Status |
|-----------------|---------------------|--------|
| AX-1 (determinism) | Structural (single Apply path) | [status] |
| AX-2 (closure) | Post-state validity constraints | [status] |
| DEF-1 (derived = Derive(canonical)) | Derivation constraints | [status] |
| DEF-2 (encoding injectivity) | Encoding constraints | [status] |
| DEF-3 (commitment binding) | Hash constraints | [status] |
| LEM-1 (invariant preservation) | All invariant constraints | [status] |
| LEM-3 (mapping commutativity) | Semantic mapping constraints | [status] |
| LEM-4 (constraint soundness) | ALL constraints (meta-property) | [status] |
| LEM-5 (constraint completeness) | ALL constraints (meta-property) | [status] |
| LEM-6 (witness uniqueness) | Sufficient constraints for unique determination | [status] |
| LEM-7 (error invariant preservation) | Error-path invariant constraints | [status] |
| LEM-9 (batch equivalence) | Batch decomposition constraints | [status] |
| SAFE-1 (no invalid states) | State validity constraints | [status] |
| SAFE-2 (resource conservation) | Conservation constraints | [status] |
| SAFE-3 (no hidden mutation) | Carry-over constraints | [status] |

---

## 6. Gap Analysis Protocol

When a gap is identified (property without full constraint coverage):

```
Gap Report:
  Property: [ID]
  Transition Class: [class]
  Missing Coverage: [description]
  Impact: [what can go wrong]
  Severity: [catastrophic / critical / serious]
  Required Constraint: [what needs to be added]
  Status: [open / in-progress / resolved]
  Resolution Evidence: [constraint ID when added]
```

---

## 7. Coverage Completeness Criteria

The matrix is complete when:

1. Every invariant has Full coverage for every applicable transition class
2. Every state field has an identified constraint for every transition class
3. Every non-mutated field has an explicit carry-over constraint
4. Every derived field has a recomputation constraint
5. Every proof obligation maps to specific constraints
6. No gaps remain open

---

## 8. Maintenance

This matrix must be updated whenever:
- A new invariant is added
- A new transition class is defined
- A constraint is added, modified, or removed
- A new state field is introduced

Staleness of this matrix is itself a vulnerability.

---

## 9. Closing Statement

This matrix is the audit trail between intent and enforcement.

Without it, you have a pile of constraints and a pile of properties, and faith that they are related.

Faith is not a security property.
