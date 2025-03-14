**Verifiable Semantic Execution Layer (VSEL)**

# THEOREM PROVING PLAN

## 1. Purpose

This document defines what goes to mechanized theorem proving, why, and with which tools.

Model checking finds counterexamples in bounded instances. Theorem proving establishes universal truths. They are complementary, not interchangeable.

> Model checking asks "is there a counterexample in this finite space?" Theorem proving asks "can there ever be a counterexample, anywhere, ever?"

---

## 2. Tool Selection

| Tool | Strength | Use Case in VSEL |
|------|----------|-----------------|
| Coq | Strongest guarantees, extraction to code | Core refinement proofs, invariant preservation |
| Lean 4 | Modern, good automation, growing ecosystem | Semantic mapping theorems, algebraic properties |
| Isabelle/HOL | Strong automation, large library | Composition theorems, protocol properties |

Primary: Lean 4 (modern tooling, good balance of automation and expressiveness)
Secondary: Coq (for highest-assurance components)

---

## 3. What Requires Theorem Proving

Theorem proving is required for properties that:
- Must hold universally (not just for bounded instances)
- Involve parameterized systems (arbitrary number of accounts, arbitrary trace length)
- Require structural induction over unbounded data
- Cannot be expressed in finite model checking

### 3.1 Priority Classification

| Priority | Category | Rationale |
|----------|----------|-----------|
| P0 | Refinement relations | Core system guarantee |
| P0 | Invariant preservation (universal) | Cannot be bounded |
| P1 | Semantic mapping commutativity | Parameterized over all states |
| P1 | Constraint soundness/completeness | Structural property of derivation |
| P2 | Composition theorems | Parameterized over system pairs |
| P2 | Witness uniqueness | Structural property of constraints |

---

## 4. Theorems to Prove

### 4.1 Refinement Theorems (P0)

#### TP-1: SIR Refines Formal Specification

```
∀ s_sir, σ_sir:
  Apply_sir(s_sir, σ_sir) = s'_sir
  ⟹
  Apply_formal(R₀₁(s_sir), R₀₁_σ(σ_sir)) = R₀₁(s'_sir)
```

Tool: Lean 4
Method: Define formal spec and SIR as inductive types. Prove simulation relation.
Difficulty: Medium. Requires careful type alignment.

#### TP-2: Concrete Refines SIR (Semantic Mapping)

```
∀ s_c, σ_c:
  μ_S(Apply_c(s_c, σ_c)) = Apply_sir(μ_S(s_c), μ_Σ(σ_c))
```

This is THM-1 (the fundamental theorem).

Tool: Lean 4 or Coq
Method: Per-transition-class proof. Structural induction over transition classes.
Difficulty: High. Requires modeling concrete arithmetic and encoding.

#### TP-3: Constraints Refine Concrete Execution

```
∀ τ: SatisfiesConstraints(τ) ⟹ ValidConcreteTrace(τ)
∀ τ: ValidConcreteTrace(τ) ⟹ SatisfiesConstraints(τ)
```

Tool: Coq (highest assurance)
Method: Structural proof over constraint derivation function.
Difficulty: Very high. Requires formalizing constraint derivation.

### 4.2 Invariant Theorems (P0)

#### TP-4: Global Invariant Preservation

```
∀ G ∈ GlobalInvariants, ∀ (s, σ, s') ∈ T:
  G(s) ⟹ G(s')
```

Tool: Lean 4
Method: Per-invariant, per-transition-class proof.
Difficulty: Medium per case, high in aggregate (many combinations).

#### TP-5: Inductive Invariance Over Traces

```
∀ τ = (s₀, ..., sₙ):
  s₀ ∈ I ∧ (∀ i: G(sᵢ) ⟹ G(sᵢ₊₁))
  ⟹ ∀ i: G(sᵢ)
```

Tool: Lean 4
Method: Induction over trace length. Uses TP-4 as inductive step.
Difficulty: Low (standard induction, given TP-4).

#### TP-6: Resource Conservation (Universal)

```
∀ (s, σ, s') ∈ T:
  Total(C_s) = Total(C_s') + Δ_fees(σ)
```

Tool: Lean 4
Method: Arithmetic proof per transition class.
Difficulty: Medium. Requires careful handling of arithmetic.

### 4.3 Semantic Mapping Theorems (P1)

#### TP-7: Canonicalization Idempotence

```
∀ σ: Canonical(Canonical(σ)) = Canonical(σ)
```

Tool: Lean 4
Method: Structural proof over canonicalization function.
Difficulty: Low.

#### TP-8: Canonicalization Semantic Preservation

```
∀ σ₁, σ₂: SemanticEquiv(σ₁, σ₂) ⟹ Canonical(σ₁) = Canonical(σ₂)
```

Tool: Lean 4
Method: Proof over equivalence relation and canonicalization.
Difficulty: Medium.

#### TP-9: Auxiliary Data Independence

```
∀ s, σ = (payload, auth, aux₁), σ' = (payload, auth, aux₂):
  Apply(s, σ) = Apply(s, σ')
```

Tool: Lean 4
Method: Structural proof showing Apply does not reference aux.
Difficulty: Low (if Apply is well-structured).

#### TP-10: Observable Commutativity

```
∀ (s_c, σ_c, s'_c):
  μ_O(Obs_c(s_c, σ_c, s'_c)) = Obs_f(μ_S(s_c), μ_Σ(σ_c), μ_S(s'_c))
```

Tool: Lean 4
Method: Per-observable-type proof.
Difficulty: Medium.

### 4.4 Structural Theorems (P1)

#### TP-11: Encoding Injectivity

```
∀ s₁, s₂: Encode(s₁) = Encode(s₂) ⟹ s₁ = s₂
```

Tool: Lean 4
Method: Structural proof over encoding scheme.
Difficulty: Medium (depends on encoding complexity).

#### TP-12: Transition Guard Exhaustiveness

```
∀ s, σ: ∃ K: Guard_K(s, σ)
```

Tool: Lean 4
Method: Case analysis over guard conditions.
Difficulty: Low-Medium.

#### TP-13: Transition Guard Disjointness (After Priority)

```
∀ s, σ: |{K : Guard_K(s, σ) ∧ HighestPriority(K)}| = 1
```

Tool: Lean 4
Method: Priority ordering proof.
Difficulty: Medium.

### 4.5 Composition Theorems (P2)

#### TP-14: Compositional Soundness

```
Valid(M_A) ∧ Valid(M_B) ∧ Compatible(M_A, M_B) ⟹ Valid(M_A ∘ M_B)
```

Tool: Isabelle/HOL (strong automation for protocol properties)
Method: Assume-guarantee reasoning formalization.
Difficulty: High.

#### TP-15: Cross-Invariant Preservation

```
∀ G_cross, ∀ cross-transition:
  G_cross(s_A, s_B) ⟹ G_cross(s'_A, s'_B)
```

Tool: Lean 4
Method: Per-cross-invariant proof.
Difficulty: Medium-High.

### 4.6 Witness Theorems (P2)

#### TP-16: Witness Semantic Uniqueness

```
∀ W₁, W₂ satisfying constraints with same Pub:
  SemanticExecution(W₁) = SemanticExecution(W₂)
```

Tool: Coq (highest assurance for this critical property)
Method: Proof that constraints uniquely determine semantic variables.
Difficulty: Very high.

---

## 5. Proof Architecture

### 5.1 Library Structure

```
vsel-proofs/
├── Foundations/
│   ├── State.lean          -- State type definitions
│   ├── Input.lean          -- Input type definitions
│   ├── Transition.lean     -- Transition function
│   └── Invariants.lean     -- Invariant definitions
├── Refinement/
│   ├── FormalToSIR.lean    -- R₀₁ refinement
│   ├── SIRToConcrete.lean  -- R₁₂ refinement
│   └── ConcreteToConstraint.lean -- R₂₃ refinement
├── Mapping/
│   ├── SemanticMapping.lean -- μ_S, μ_Σ definitions
│   ├── Commutativity.lean  -- THM-1 proof
│   └── Observable.lean     -- THM-2 proof
├── Invariants/
│   ├── Local.lean          -- Local invariant proofs
│   ├── Global.lean         -- Global invariant proofs
│   └── Temporal.lean       -- Temporal invariant proofs
├── Composition/
│   ├── Contract.lean       -- Assume-guarantee definitions
│   └── Soundness.lean      -- Compositional soundness
└── Witness/
    └── Uniqueness.lean     -- Witness uniqueness proof
```

### 5.2 Dependency Order

```
Foundations → Invariants → Mapping → Refinement → Composition → Witness
```

Each layer depends only on layers to its left.

---

## 6. Proof Effort Estimation

| Theorem | Estimated Effort | Dependencies |
|---------|-----------------|-------------|
| TP-1 (SIR refines formal) | 3-4 weeks | Foundations |
| TP-2 (concrete refines SIR) | 4-6 weeks | TP-1, Mapping |
| TP-3 (constraints refine concrete) | 6-8 weeks | TP-2, Constraint formalization |
| TP-4 (invariant preservation) | 2-3 weeks per invariant | Foundations |
| TP-5 (inductive invariance) | 1 week | TP-4 |
| TP-6 (resource conservation) | 2-3 weeks | Foundations |
| TP-7-9 (mapping properties) | 1-2 weeks each | Mapping |
| TP-10 (observable commutativity) | 2-3 weeks | TP-2 |
| TP-11-13 (structural) | 1-2 weeks each | Foundations |
| TP-14-15 (composition) | 4-6 weeks | All above |
| TP-16 (witness uniqueness) | 4-6 weeks | Constraint formalization |

Total estimated: 6-9 months with dedicated proof engineer.

---

## 7. Separation from Model Checking

| Aspect | Model Checking (TLA+) | Theorem Proving (Lean/Coq) |
|--------|----------------------|---------------------------|
| Scope | Bounded instances | Universal |
| Output | Counterexamples | Proofs |
| Strength | Finds bugs | Proves absence of bugs |
| Limitation | Finite state space | Requires human guidance |
| Best for | Finding violations | Establishing guarantees |

Both are required. Neither is sufficient alone.

---

## 8. Proof Maintenance

When the system changes:
1. Identify which theorems are affected
2. Re-prove affected theorems
3. Verify proof dependencies still hold
4. Update proof library

Proof maintenance is a continuous cost. Budget for it.

---

## 9. Closing Statement

Theorem proving is expensive, slow, and demanding.

It is also the only way to make universal claims about system behavior with mathematical certainty.

VSEL's ambition requires it. The alternative is claiming universal correctness based on finite testing, which is the formal methods equivalent of claiming immortality because you haven't died yet.
