**Verifiable Semantic Execution Layer (VSEL)**

# REFINEMENT STRATEGY

## 1. Purpose

This document formalizes the chain of refinement between VSEL's abstraction levels.

VSEL is not "several coherent documents." It is a chain of refinements where each level preserves the semantics of the level above it. If this chain is not formally justified, the system is a collection of related artifacts, not a verified pipeline.

> Refinement is the proof that the concrete system is a faithful realization of the abstract system. Without it, "derived from the spec" is a social claim, not a mathematical one.

---

## 2. Refinement Levels

VSEL defines five refinement levels:

```
Level 0: Abstract Specification (FORMAL_SPECIFICATION.md)
  ↓ refinement R₀₁
Level 1: Semantic Intermediate Representation (SIR)
  ↓ refinement R₁₂
Level 2: Concrete State Machine (STATE_MACHINE.md)
  ↓ refinement R₂₃
Level 3: Constraint Model (CONSTRAINT_DERIVATION.md)
  ↓ refinement R₃₄
Level 4: Proof Statement (PROOF_LAYER.md)
```

Each refinement R_{i,i+1} must be formally justified.

---

## 3. Refinement Relations

A refinement relation between levels L_i and L_{i+1} is a relation:

```
R: States(L_{i+1}) → States(L_i)
```

Such that:

### 3.1 Simulation Condition

```
∀ s_c, σ_c, s'_c at level L_{i+1}:
  Apply_{i+1}(s_c, σ_c) = s'_c
  ⟹
  Apply_i(R(s_c), R_σ(σ_c)) = R(s'_c)
```

Every concrete transition corresponds to an abstract transition.

### 3.2 Invariant Preservation

```
∀ G_i at level L_i:
  G_i(R(s_c)) holds whenever G_{i+1}(s_c) holds
```

Concrete invariants imply abstract invariants through the refinement map.

### 3.3 Observable Preservation

```
∀ transitions at L_{i+1}:
  Obs_i(R(s_c), R_σ(σ_c), R(s'_c)) = R_O(Obs_{i+1}(s_c, σ_c, s'_c))
```

Observables are preserved through refinement.

---

## 4. Refinement R₀₁: Abstract Spec → SIR

### Abstract Level (L0)
- State: s = (C, D, E, τ) as mathematical objects
- Transitions: Apply as mathematical function
- Invariants: predicates over mathematical objects

### SIR Level (L1)
- State: typed data structures
- Transitions: deterministic programs
- Invariants: computable predicates

### Refinement Map

```
R₀₁: SIR_State → Formal_State
```

Must show:
- Every SIR state maps to a valid formal state
- Every SIR transition corresponds to a formal transition
- SIR does not introduce behaviors not in the formal model
- SIR does not lose behaviors that are in the formal model

### Proof Obligations for R₀₁

```
R01-1: ∀ s_sir: ValidSIR(s_sir) ⟹ ValidFormal(R₀₁(s_sir))
R01-2: ∀ (s, σ, s') in SIR: (R₀₁(s), R₀₁_σ(σ), R₀₁(s')) ∈ T_formal
R01-3: ∀ G_formal: G_formal(R₀₁(s)) ⟺ G_sir(s) [invariant correspondence]
R01-4: SIR is deterministic (no nondeterminism introduced)
R01-5: SIR is complete (no formal behavior lost)
```

### Risk Areas
- Type system of SIR may not capture all formal constraints
- SIR may introduce implicit behavior through language features
- Formal model may have behaviors that SIR cannot express

---

## 5. Refinement R₁₂: SIR → Concrete State Machine

### SIR Level (L1)
- Typed, deterministic programs
- No implicit behavior

### Concrete Level (L2)
- Actual data structures (maps, arrays, bytes)
- Actual computation (arithmetic, hashing, encoding)
- Actual execution pipeline

### Refinement Map

```
R₁₂: Concrete_State → SIR_State
```

This is essentially the semantic mapping μ_S from SEMANTIC_MAPPING.md.

### Proof Obligations for R₁₂

```
R12-1: μ_S is total over accepted concrete states
R12-2: μ_S is deterministic
R12-3: THM-1 holds (execution-mapping commutativity)
R12-4: THM-2 holds (observable commutativity)
R12-5: Concrete encoding is injective (DEF-2)
R12-6: Derived state is functionally determined (DEF-1)
```

### Risk Areas
- Encoding differences (endianness, padding, field representation)
- Arithmetic differences (overflow, rounding, precision)
- Error handling differences (concrete may have more error paths)
- Performance optimizations that alter execution order

---

## 6. Refinement R₂₃: Concrete State Machine → Constraint Model

### Concrete Level (L2)
- Actual state transitions
- Full execution pipeline

### Constraint Level (L3)
- Algebraic constraints over field elements
- Witness variables
- Public inputs

### Refinement Map

```
R₂₃: Constraint_Satisfaction → Concrete_Execution
```

This refinement is inverted: we go from constraint satisfaction to concrete execution validity.

```
SatisfiesConstraints(τ) ⟹ ValidConcreteTrace(τ)  [soundness]
ValidConcreteTrace(τ) ⟹ SatisfiesConstraints(τ)  [completeness]
```

### Proof Obligations for R₂₃

```
R23-1: LEM-4 (constraint soundness)
R23-2: LEM-5 (constraint completeness)
R23-3: CONST-1 (no unconstrained variables)
R23-4: CONST-2 (no unused witness inputs)
R23-5: CONST-3 (branch completeness)
R23-6: CONST-4 (derivation determinism)
R23-7: Every state field is constrained (UNDERCONSTRAINT_ANALYSIS)
R23-8: Every invariant is encoded (CONSTRAINT_COVERAGE_MATRIX)
```

### Risk Areas
- Field arithmetic vs integer arithmetic differences
- Constraint system may not express all concrete operations
- Optimization may remove or weaken constraints
- Witness generation may introduce freedom not present in concrete execution

---

## 7. Refinement R₃₄: Constraint Model → Proof Statement

### Constraint Level (L3)
- Algebraic constraint system
- Witness assignment

### Proof Level (L4)
- Cryptographic proof object
- Public inputs
- Verification procedure

### Refinement Map

```
R₃₄: Proof_Verification → Constraint_Satisfaction
```

```
Verify(π) ⟹ SatisfiesConstraints(τ)
```

### Proof Obligations for R₃₄

```
R34-1: Proof system soundness (AX-4)
R34-2: PROOF-1 (full trace binding)
R34-3: PROOF-2 (observable binding)
R34-4: PROOF-3 (domain separation)
R34-5: PROOF-4 (knowledge soundness)
R34-6: LEM-6 (witness semantic uniqueness)
```

### Risk Areas
- Proof system implementation bugs
- Trusted setup compromise (for SNARKs)
- Insufficient public inputs (proof doesn't bind to enough)
- Witness malleability (WITNESS_UNIQUENESS_AND_NON_MALLEABILITY)

---

## 8. End-to-End Refinement Chain

The composition of all refinements gives:

```
R = R₃₄ ∘ R₂₃ ∘ R₁₂ ∘ R₀₁
```

End-to-end guarantee:

```
Verify(π) ⟹ ValidFormalTrace(τ_formal)
```

This is the master theorem of VSEL.

### Proof Structure

```
Verify(π)
  ⟹ SatisfiesConstraints(τ)     [R₃₄: proof soundness]
  ⟹ ValidConcreteTrace(τ_c)     [R₂₃: constraint soundness]
  ⟹ ValidSIRTrace(τ_sir)        [R₁₂: mapping commutativity]
  ⟹ ValidFormalTrace(τ_f)       [R₀₁: SIR-to-formal correspondence]
```

Each implication must be independently justified.

---

## 9. Refinement Verification Methods

| Refinement | Primary Method | Secondary Method |
|-----------|---------------|-----------------|
| R₀₁ | Theorem proving (Coq/Lean) | Manual review |
| R₁₂ | Differential testing + theorem proving | Model checking |
| R₂₃ | Constraint analysis + symbolic execution | Adversarial fuzzing |
| R₃₄ | Cryptographic reduction | Implementation testing |

---

## 10. Refinement Failure Modes

### RFAIL-1: Abstraction Gap

Level L_i has behaviors that Level L_{i+1} cannot represent.

Impact: Formal model describes fantasies.

### RFAIL-2: Implementation Surplus

Level L_{i+1} has behaviors not present in Level L_i.

Impact: Unspecified behavior in implementation.

### RFAIL-3: Invariant Loss

Invariant holds at L_i but is not preserved at L_{i+1}.

Impact: Concrete system violates abstract guarantees.

### RFAIL-4: Observable Divergence

Observables differ between levels.

Impact: External consumers see different behavior than formal model predicts.

### RFAIL-5: Refinement Composition Failure

Individual refinements are correct but their composition is not.

Impact: End-to-end guarantee fails despite per-level correctness.

This is rare but devastating. It occurs when refinement maps are not truly composable (e.g., R₁₂ assumes properties that R₀₁ does not guarantee).

---

## 11. Refinement Maintenance

When any level changes:
1. Identify which refinement relations are affected
2. Re-verify affected refinement obligations
3. Re-verify end-to-end chain
4. Update this document

Refinement is not a one-time proof. It is a continuous obligation.

---

## 12. Closing Statement

VSEL without refinement proofs is a collection of documents that agree with each other in spirit.

VSEL with refinement proofs is a chain of mathematical guarantees that error cannot cross without detection.

The difference is the difference between architecture and engineering.
