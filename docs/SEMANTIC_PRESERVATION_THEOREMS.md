**Verifiable Semantic Execution Layer (VSEL)**

# SEMANTIC PRESERVATION THEOREMS

## 1. Purpose

This document formalizes the commutativity obligations that bind VSEL's layers together.

It does not describe mappings. It states theorems.

Each theorem is a diagram that must commute. If the diagram does not commute, the system has semantic drift, and semantic drift under proof is indistinguishable from a formally verified lie.

> The purpose of this document is to make semantic drift provably detectable.

---

## 2. Notation

- S_c, Σ_c, Tr_c: concrete state, input, trace spaces
- S_f, Σ_f, Tr_f: formal state, input, trace spaces
- μ_S, μ_Σ, μ_T, μ_Tr, μ_O: semantic mapping functions
- Apply_c: concrete transition function
- Apply_f: formal transition function
- Obs_c, Obs_f: concrete and formal observable functions
- Canonical: canonicalization function
- Derive: derived state computation
- Encode: state encoding function
- Commit: commitment function
- D: SIR → Constraint derivation
- Compress: trace compression function

---

## 3. Core Commutativity Theorems

### THM-1: Execution-Mapping Commutativity (The Fundamental Theorem)

```
For all admissible (s_c, σ_c):

  μ_S(Apply_c(s_c, σ_c)) = Apply_f(μ_S(s_c), μ_Σ(σ_c))
```

Diagram:
```
  s_c ──Apply_c──→ s'_c
   |                  |
  μ_S               μ_S
   ↓                  ↓
  s_f ──Apply_f──→ s'_f
```

This square MUST commute for every admissible concrete transition.

Failure mode: Concrete execution diverges from formal model. Proof validates the wrong thing.

Proof strategy: Per-transition-class verification. For each class K:
- Show μ_S(Apply_c^K(s_c, σ_c)) = Apply_f^K(μ_S(s_c), μ_Σ(σ_c))
- Cover all fields of state independently
- Pay special attention to derived state, metadata, and environment propagation

Dependencies: DEF-1 (derived state), DEF-5 (canonicalization idempotence), AX-1 (determinism)

---

### THM-2: Observable Commutativity

```
For all admissible (s_c, σ_c, s'_c):

  μ_O(Obs_c(s_c, σ_c, s'_c)) = Obs_f(μ_S(s_c), μ_Σ(σ_c), μ_S(s'_c))
```

Diagram:
```
  (s_c, σ_c, s'_c) ──Obs_c──→ o_c
        |                        |
       μ_T                     μ_O
        ↓                        ↓
  (s_f, σ_f, s'_f) ──Obs_f──→ o_f
```

Failure mode: External consumers see different behavior than what the formal model predicts.

Proof strategy: Show observable function commutes with mapping for each observable type.

---

### THM-3: Canonicalization Semantic Neutrality

```
For all σ_c:

  Apply_c(s_c, σ_c) = Apply_c(s_c, Canonical(σ_c))
  whenever SemanticEquiv(σ_c, Canonical(σ_c))
```

And more precisely:

```
  μ_Σ(σ_c) = μ_Σ(Canonical(σ_c))
```

Canonicalization must not alter semantic content.

Failure mode: Canonicalization silently changes the meaning of an input.

Proof strategy:
- Show Canonical is idempotent (DEF-5)
- Show Canonical preserves semantic equivalence class
- Show no field transformation in Canonical alters μ_Σ output

---

### THM-4: Auxiliary Data Exclusion

```
For all σ_c = (payload, auth, aux₁) and σ'_c = (payload, auth, aux₂):

  μ_Σ(σ_c) = μ_Σ(σ'_c)
  Apply_c(s_c, σ_c) = Apply_c(s_c, σ'_c)
```

Auxiliary data must not influence semantic outcome.

Failure mode: Proving hints, optimization flags, or metadata change execution result.

Proof strategy: Parameterize over aux. Show Apply_c is independent of aux component.

---

### THM-5: Derived State Commutativity

```
For all s_c with canonical component C_c:

  μ_D(Derive_c(C_c)) = Derive_f(μ_C(C_c))
```

Diagram:
```
  C_c ──Derive_c──→ D_c
   |                  |
  μ_C               μ_D
   ↓                  ↓
  C_f ──Derive_f──→ D_f
```

Derived state computation must commute with mapping.

Failure mode: Concrete derived state (Merkle roots, aggregates) diverges from formal derived state.

---

### THM-6: Trace Mapping Preserves Validity

```
For all concrete traces τ_c accepted by the system:

  ValidTrace_f(μ_Tr(τ_c))
```

And conversely, for all realizable formal traces τ_f:

```
  ∃ τ_c: μ_Tr(τ_c) = τ_f ∧ AcceptedConcreteTrace(τ_c)
```

Proof strategy: Induction over trace length using THM-1 as inductive step.

---

### THM-7: Constraint Derivation Preserves Semantics

```
For all SIR programs P and traces τ:

  ValidTrace(τ) ⟺ Satisfies(τ, D(P))
```

Where D is the constraint derivation function.

This is the conjunction of LEM-4 (soundness) and LEM-5 (completeness).

Diagram:
```
  SIR ──D──→ Constraints
   |              |
  defines      encodes
   ↓              ↓
  ValidTrace ⟺ Satisfies
```

Failure mode: Constraints are a lossy projection of semantics.

---

### THM-8: Proof Semantic Binding

```
For all proofs π:

  Verify(π) ⟹ ∃ τ: ValidTrace(τ) ∧ π attests τ
```

Combined with THM-7:

```
  Verify(π) ⟹ ∃ τ: Satisfies(τ, D(SIR)) ∧ ValidTrace(τ)
```

This is the end-to-end semantic guarantee.

Diagram:
```
  Execution ──trace──→ τ ──constraints──→ Satisfies
                        |                      |
                      proof                  verify
                        ↓                      ↓
                        π ────────────→ Accept/Reject
```

---

## 4. Composition Theorems

### THM-9: Compositional Commutativity

```
For composed systems A, B with cross-transition (s_A, s_B, σ_cross) → (s'_A, s'_B):

  μ_S^A(s'_A) = Apply_f^A(μ_S^A(s_A), μ_Σ^A(σ_A))
  μ_S^B(s'_B) = Apply_f^B(μ_S^B(s_B), μ_Σ^B(σ_B))
  G_cross(μ_S^A(s'_A), μ_S^B(s'_B))
```

Each subsystem's commutativity must hold independently AND cross-invariants must be preserved.

---

### THM-10: Proof Composition Preserves Semantics

```
For composed proof π_AB = Combine(π_A, π_B, π_cross):

  Verify(π_AB) ⟹ ValidTrace_A(τ_A) ∧ ValidTrace_B(τ_B) ∧ G_cross holds
```

Composition of proofs must not weaken individual guarantees.

---

## 5. Compression and Aggregation Theorems

### THM-11: Trace Compression Preserves Observable Language

```
For all traces τ:

  Obs(Decompress(Compress(τ))) = Obs(τ)
```

Compression must preserve the observable behavior of the trace.

Failure mode: Compression loses causal ordering, intermediate observables, or state dependencies.

Conditions for validity:
- Compression must be lossless with respect to observables
- Causal ordering must be recoverable
- Intermediate state commitments must be verifiable or reconstructible

---

### THM-12: Batching Semantic Equivalence

```
For all s, [σ₁, ..., σₙ]:

  Apply(s, [σ₁, ..., σₙ]) = Apply(Apply(...Apply(s, σ₁)...), σₙ)

  IF AND ONLY IF:

  ∀ i: Pre(sᵢ, σᵢ) holds where sᵢ = Apply(sᵢ₋₁, σᵢ₋₁)
```

Batching is equivalent to sequential application ONLY when all intermediate preconditions are satisfied.

Failure mode: Batch skips intermediate precondition checks, allowing transitions that would fail sequentially.

This theorem has a critical "if and only if" that most systems ignore.

---

### THM-13: Recursive Proof Preservation

```
For recursive proof π_outer containing verification of π_inner:

  Verify(π_outer) ⟹ Verify(π_inner) ∧ ValidTrace(τ_inner) ∧ ValidTrace(τ_outer)
```

Recursive verification must not weaken inner proof guarantees.

---

## 6. Error Handling Theorems

### THM-14: Error Commutativity

```
For all (s_c, σ_c) where σ_c is invalid:

  μ_S(Apply_c(s_c, σ_c)) = Apply_f(μ_S(s_c), μ_Σ(σ_c)) = s_error_f
  G(s_error_f)
```

Error handling must commute with mapping AND preserve invariants.

---

### THM-15: No-Op Commutativity

```
For all (s_c, σ_c) producing no-op:

  μ_S(Apply_c(s_c, σ_c)) = μ_S(s_c)
  Obs_f(μ_S(s_c), μ_Σ(σ_c), μ_S(s_c)) = ⊥_observable
```

No-op in concrete must map to no-op in formal, with null observable.

---

## 7. Temporal Theorems

### THM-16: Temporal Invariant Preservation Under Mapping

```
For all concrete traces τ_c:

  TInv_c(τ_c) ⟹ TInv_f(μ_Tr(τ_c))
```

Temporal properties of concrete traces must be preserved in formal traces.

---

### THM-17: Monotonicity Preservation

```
For all traces τ_c:

  ∀ i < j: τ_c(sᵢ).sequence < τ_c(sⱼ).sequence
  ⟹
  ∀ i < j: μ_Tr(τ_c)(sᵢ).sequence < μ_Tr(τ_c)(sⱼ).sequence
```

Ordering must be preserved through mapping.

---

## 8. Theorem Dependencies

```
THM-1 (fundamental) ← AX-1, DEF-1, DEF-5, DEF-6
THM-2 (observable) ← THM-1, DEF-4
THM-3 (canonicalization) ← DEF-5, DEF-6
THM-4 (auxiliary exclusion) ← mapping definition
THM-5 (derived state) ← DEF-1, THM-1
THM-6 (trace validity) ← THM-1 (induction)
THM-7 (constraint semantics) ← LEM-4, LEM-5
THM-8 (proof binding) ← THM-7, PROOF-1, PROOF-4
THM-9 (composition) ← THM-1 per subsystem + COMP-1..3
THM-10 (proof composition) ← THM-8, THM-9
THM-11 (compression) ← THM-2
THM-12 (batching) ← THM-1, LEM-9
THM-13 (recursion) ← THM-8
THM-14 (error) ← THM-1, LEM-7
THM-15 (no-op) ← THM-1, LEM-8
THM-16 (temporal) ← THM-6
THM-17 (monotonicity) ← THM-16
```

---

## 9. Discharge Requirements

Each theorem must be discharged by one of:

- **Formal proof** in Coq/Lean/Isabelle (strongest)
- **Model checking** in TLA+ (for finite instances)
- **Differential testing** (empirical, weakest but necessary)

No theorem may remain undischarged at production gate (Phase 10).

---

## 10. Closing Statement

These theorems are the skeleton of trust in VSEL.

Every diagram that commutes is a boundary where error cannot hide.
Every diagram that does not commute is a boundary where error already lives.

The system is as strong as its weakest uncommuted diagram.
