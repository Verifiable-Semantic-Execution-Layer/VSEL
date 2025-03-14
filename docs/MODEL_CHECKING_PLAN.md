**Verifiable Semantic Execution Layer (VSEL)**

# MODEL CHECKING PLAN

## 1. Purpose

This document defines exactly which parts of VSEL will be subjected to model checking, with which abstractions, which properties, which fairness assumptions, and which counterexample traces must be preserved as evidence.

This is not "we will use formal methods." This is the operational plan for systematic falsification of the model.

> Model checking does not prove correctness. It searches for counterexamples. The value is in what it fails to find.

---

## 2. Tool Selection

Primary tool: TLA+ with TLC model checker
Secondary: Alloy (for structural properties), SPIN (for protocol-level properties)

TLA+ is chosen because:
- Native support for state machines and temporal logic
- Exhaustive state space exploration
- Counterexample trace generation
- Industry-proven for distributed systems

---

## 3. Model Scope

### 3.1 What Will Be Model Checked

| Component | Abstraction Level | Priority |
|-----------|------------------|----------|
| State machine transitions | Full (all classes) | P0 |
| Invariant system | Full (all invariants) | P0 |
| Transition partitioning | Full (guard analysis) | P0 |
| Trace construction | Simplified (bounded traces) | P1 |
| Composition model | Two-system composition | P1 |
| Error handling | Full (all error paths) | P0 |
| Batch semantics | Bounded batch size | P1 |
| Temporal invariants | Bounded trace length | P1 |
| Reachability analysis | Full state space | P0 |

### 3.2 What Will NOT Be Model Checked (and why)

| Component | Reason | Alternative |
|-----------|--------|-------------|
| Cryptographic primitives | Not expressible in TLA+ | Cryptographic proofs |
| Constraint derivation | Too low-level for model checking | Theorem proving + testing |
| Proof system internals | Cryptographic, not state-based | Cryptographic reduction |
| Field arithmetic | Infinite domain | Bounded testing + theorem proving |

---

## 4. State Space Abstractions

### 4.1 State Abstraction

```
AbstractState = [
  accounts: SUBSET AccountID → AbstractBalance,
  storage: SUBSET Key → AbstractValue,
  metadata: [sequence: Nat, epoch: Nat],
  error_flag: BOOLEAN
]
```

Where:
- AbstractBalance ∈ {0, LOW, MED, HIGH, MAX} (5-value abstraction)
- AbstractValue ∈ {EMPTY, SET} (2-value abstraction)
- AccountID ∈ {A1, A2, A3} (3 accounts)
- Key ∈ {K1, K2} (2 storage keys)

This gives a finite state space while preserving essential semantic structure.

### 4.2 Input Abstraction

```
AbstractInput = [
  type: {TRANSFER, STORE, NOOP, ERROR, BATCH},
  from: AccountID,
  to: AccountID,
  amount: {0, LOW, MED, HIGH, MAX},
  auth: {VALID, INVALID, EXPIRED},
  batch_size: {0, 1, 2, 3}
]
```

### 4.3 Abstraction Soundness

The abstraction must be conservative:

```
If abstract model finds no counterexample,
  concrete model may still have counterexamples (abstraction may hide them)

If abstract model finds counterexample,
  concrete model definitely has a corresponding counterexample
```

This means: counterexamples found are real. Absence of counterexamples is not proof.

---

## 5. Properties to Check

### 5.1 Safety Properties (Invariants)

```
INVARIANT StateValidity ==
  ∀ a ∈ DOMAIN accounts: accounts[a] ≥ 0

INVARIANT ResourceConservation ==
  SumAll(accounts) + accumulated_fees = INITIAL_TOTAL

INVARIANT DerivedConsistency ==
  derived_root = ComputeRoot(accounts, storage)

INVARIANT MonotonicMetadata ==
  metadata.sequence' > metadata.sequence

INVARIANT NoInvalidStateReachable ==
  ¬(error_flag = FALSE ∧ ¬ValidState(state))
```

### 5.2 Temporal Properties (LTL)

```
PROPERTY NoRollback ==
  □(metadata.sequence' ≥ metadata.sequence)

PROPERTY EventualProgress ==
  □◇(∃ σ: Apply(state, σ) ≠ state)

PROPERTY CausalOrdering ==
  □(i < j ⟹ trace[i].sequence < trace[j].sequence)

PROPERTY NoHiddenTransitions ==
  □(state' ≠ state ⟹ ∃ trace_entry recording the change)
```

### 5.3 Transition Partitioning Properties

```
PROPERTY GuardExhaustiveness ==
  ∀ s, σ: ∃ class K: Guard_K(s, σ)

PROPERTY GuardDisjointness ==
  ∀ s, σ: |{K : Guard_K(s, σ)}| ≤ 1
  (after priority resolution)

PROPERTY TransitionDeterminism ==
  ∀ s, σ: |{s' : Apply(s, σ) = s'}| = 1
```

### 5.4 Composition Properties

```
PROPERTY CrossSystemConservation ==
  Total_A + Total_B = CONSTANT

PROPERTY SharedStateConsistency ==
  shared_A = shared_B at synchronization points

PROPERTY NoCompositionEscape ==
  ∀ reachable (s_A, s_B): ValidState_A(s_A) ∧ ValidState_B(s_B)
```

---

## 6. Fairness Assumptions

### 6.1 Weak Fairness

```
WF(Apply): If Apply is continuously enabled, it eventually executes.
```

Used for: Liveness properties (no deadlock).

### 6.2 Strong Fairness

```
SF(CrossTransition): If cross-system transitions are infinitely often enabled, they eventually execute.
```

Used for: Composition liveness.

### 6.3 No Fairness (Adversarial)

For safety properties, no fairness assumptions. The adversary can choose any enabled action at any time.

---

## 7. State Space Bounds

### 7.1 Bounded Model Checking Parameters

| Parameter | Bound | Justification |
|-----------|-------|---------------|
| Number of accounts | 3 | Minimum for meaningful interaction |
| Balance levels | 5 | Captures zero, low, medium, high, max |
| Storage keys | 2 | Minimum for key interaction |
| Trace length | 20 | Sufficient for temporal property detection |
| Batch size | 3 | Captures empty, single, multi |
| Composition systems | 2 | Minimum for composition |

### 7.2 Estimated State Space

```
States ≈ 5³ × 2² × 20 × 2 = 5000 (per system)
Composed: ≈ 25,000,000
With trace: bounded by trace length
```

Feasible for exhaustive TLC exploration.

---

## 8. Counterexample Preservation

Every counterexample found must be preserved as a formal artifact:

```
Counterexample Record:
  ID: CEX-MC-[number]
  Property Violated: [property name]
  Trace: [full state sequence]
  Initial State: [s₀]
  Input Sequence: [σ₀, ..., σₙ]
  Violation Point: [step number]
  Root Cause: [analysis]
  Resolution: [fix applied]
  Re-check Result: [pass/fail after fix]
  Date: [timestamp]
```

Counterexamples are evidence. They must be archived permanently.

---

## 9. Model Checking Phases

### Phase 0 (Foundations)
- Model: Abstract state machine with all transition classes
- Properties: All safety invariants, guard partitioning
- Goal: Find undefined behavior, contradictory invariants

### Phase 1 (Execution)
- Model: Add trace construction, replay semantics
- Properties: Trace completeness, determinism, replay fidelity
- Goal: Find trace gaps, non-determinism

### Phase 2 (Semantic Alignment)
- Model: Add semantic mapping (abstract version)
- Properties: Commutativity (THM-1 abstract version)
- Goal: Find mapping inconsistencies

### Phase 6 (Composition)
- Model: Two-system composition
- Properties: Cross-invariants, shared state consistency
- Goal: Find composition failures

### Phase 8 (Temporal)
- Model: Extended trace length
- Properties: Temporal invariants over long traces
- Goal: Find delayed failures

---

## 10. Integration with Other Documents

- Counterexamples found → added to COUNTEREXAMPLE_CATALOG.md
- Properties checked → mapped to PROOF_OBLIGATIONS.md
- Guard analysis → validates TRANSITION_PARTITIONING.md
- Composition checking → validates ASSUME_GUARANTEE_MODEL.md
- Temporal checking → validates temporal invariants in INVARIANTS.md

---

## 11. Closing Statement

Model checking is not verification.

It is organized, exhaustive, adversarial search.

Its value is not in the properties it confirms, but in the counterexamples it produces. Every counterexample is a bug that would have been found later, more expensively, and more painfully.

Or not found at all.
