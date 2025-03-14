**Verifiable Semantic Execution Layer (VSEL)**

# TRANSITION PARTITIONING

## 1. Purpose

This document proves that the set of transition classes in VSEL is:

* **exhaustive**: every possible (state, input) pair is handled by exactly one class
* **disjoint**: no (state, input) pair triggers two classes simultaneously

Without these properties, the system has masked non-determinism — the most dangerous kind, because it looks deterministic until it isn't.

> If two transition classes can accept the same input in the same state, the system is a coin flip wearing a formal suit.

---

## 2. Transition Classes

VSEL defines the following transition classes (from STATE_MACHINE.md):

| Class | Symbol | Guard (Precondition) |
|-------|--------|---------------------|
| Initialization | T_init | NoPriorState(s) |
| State Update | T_update | ValidInput(σ) ∧ Auth(σ) ∧ Pre(s, σ) |
| No-Op | T_noop | ¬ValidInput(σ) ∨ ¬Auth(σ) ∨ ¬Pre(s, σ) |
| Error | T_error | ExplicitError(s, σ) |
| Batch | T_batch | IsBatch(σ) ∧ ValidBatch(s, σ) |

---

## 3. Exhaustiveness Obligation

### PART-1: Total Coverage

```
∀ s ∈ S, σ ∈ Σ:
  Guard_init(s, σ) ∨ Guard_update(s, σ) ∨ Guard_noop(s, σ) ∨ Guard_error(s, σ) ∨ Guard_batch(s, σ)
```

Every possible (s, σ) pair must be accepted by at least one guard.

Proof strategy:
- Guard_noop is defined as the negation of Guard_update conditions
- Guard_noop ∨ Guard_update covers all cases where NoPriorState is false and IsBatch is false
- Guard_init covers the genesis case
- Guard_batch covers batch inputs
- Guard_error covers explicit error conditions

The critical question: Is there a (s, σ) that falls through all guards?

Potential gaps:
- σ that is neither single nor batch (malformed structure)
- s that is neither initial nor established (corrupted metadata)
- σ that partially satisfies Auth but not fully (ambiguous authorization)

Resolution: Define a catch-all rejection class T_reject for structurally malformed inputs:

```
Guard_reject(s, σ) ≡ ¬WellFormed(σ) ∨ ¬WellFormed(s)
```

With T_reject producing explicit error state.

### PART-1 Theorem:

```
∀ s, σ: Guard_reject(s,σ) ∨ Guard_init(s,σ) ∨ Guard_update(s,σ) ∨ Guard_noop(s,σ) ∨ Guard_error(s,σ) ∨ Guard_batch(s,σ)
```

Discharge: Proof by case analysis over WellFormed(σ), NoPriorState(s), IsBatch(σ), ValidInput(σ), Auth(σ), Pre(s,σ).

---

## 4. Disjointness Obligations

### PART-2: Pairwise Guard Disjointness

For each pair of classes (K₁, K₂) where K₁ ≠ K₂:

```
∀ s ∈ S, σ ∈ Σ: ¬(Guard_K₁(s, σ) ∧ Guard_K₂(s, σ))
```

#### PART-2a: Init vs Update

```
Guard_init requires NoPriorState(s)
Guard_update requires ValidInput(σ) ∧ Auth(σ) ∧ Pre(s, σ)
Pre(s, σ) requires established state (¬NoPriorState(s))
```

Disjoint by: NoPriorState(s) ∧ ¬NoPriorState(s) = ⊥ ✓

#### PART-2b: Update vs No-Op

```
Guard_update = ValidInput(σ) ∧ Auth(σ) ∧ Pre(s, σ)
Guard_noop = ¬ValidInput(σ) ∨ ¬Auth(σ) ∨ ¬Pre(s, σ)
```

Disjoint by: Guard_noop = ¬Guard_update (by definition) ✓

**WARNING**: This only holds if Guard_noop is EXACTLY ¬Guard_update. If Guard_noop has additional conditions, overlap or gap may exist.

#### PART-2c: Update vs Error

```
Guard_update requires Pre(s, σ) = true
Guard_error requires ExplicitError(s, σ)
```

Disjointness requires: ¬(Pre(s, σ) ∧ ExplicitError(s, σ))

**CRITICAL QUESTION**: Can a (s, σ) satisfy both Pre and ExplicitError?

If ExplicitError is defined as a subset of ¬Pre, disjoint. ✓
If ExplicitError can overlap with Pre, NOT disjoint. ✗

**Resolution required**: ExplicitError must be formally defined as:

```
ExplicitError(s, σ) ⟹ ¬Pre(s, σ) ∨ ErrorDuringApply(s, σ)
```

If ErrorDuringApply is possible (error discovered during transition, not during precondition check), then the pipeline must be: check Pre first, attempt Apply, catch error. This creates a sequential dependency, not a guard overlap.

#### PART-2d: Single vs Batch

```
Guard_update requires ¬IsBatch(σ)  [implicit: σ is single input]
Guard_batch requires IsBatch(σ)
```

Disjoint by: IsBatch(σ) ∧ ¬IsBatch(σ) = ⊥ ✓

**CRITICAL QUESTION**: Is IsBatch decidable and unambiguous? Can an input be interpreted as both single and batch?

Potential issue: An input containing exactly one operation — is it single or batch-of-one?

**Resolution required**: Define IsBatch structurally, not semantically:

```
IsBatch(σ) ≡ σ.type = BATCH
```

Not:

```
IsBatch(σ) ≡ |σ.operations| > 1  // WRONG: batch-of-one is ambiguous
```

#### PART-2e: No-Op vs Error

```
Guard_noop = ¬ValidInput(σ) ∨ ¬Auth(σ) ∨ ¬Pre(s, σ)
Guard_error = ExplicitError(s, σ)
```

Can both be true? Yes, if ExplicitError(s, σ) ∧ (¬ValidInput(σ) ∨ ...).

**Resolution**: Define priority ordering:

```
If ExplicitError(s, σ): apply T_error (takes precedence)
Else if ¬ValidInput(σ) ∨ ¬Auth(σ) ∨ ¬Pre(s, σ): apply T_noop
```

This converts potential overlap into deterministic priority.

**Obligation**: Prove that T_error and T_noop produce equivalent semantic outcomes when both guards are satisfied, OR enforce strict priority.

---

## 5. Guard Priority Resolution

When guards overlap, a strict priority ordering resolves ambiguity:

```
Priority (highest to lowest):
1. T_reject (malformed input/state)
2. T_init (genesis)
3. T_error (explicit error condition)
4. T_batch (batch input)
5. T_update (valid single transition)
6. T_noop (catch-all rejection)
```

**Obligation**: Prove that for any (s, σ), the highest-priority matching guard produces the unique correct semantic outcome.

---

## 6. Reachability Analysis

### 6.1 State Space Regions

The reachable state space is partitioned into:

| Region | Definition | Properties |
|--------|-----------|------------|
| S_init | I (initial states) | Genesis constraints satisfied |
| S_valid | Reachable(I, T) ∩ S | All invariants hold |
| S_error | Error states reachable from S_valid | Invariants hold, error flag set |
| S_syntactic | {s : ValidState(s)} \ Reachable(I, T) | Structurally valid but unreachable |
| S_invalid | {s : ¬ValidState(s)} | Must be empty in reachable space |

### 6.2 Reachability Obligations

#### REACH-1: Invalid State Unreachability

```
Reachable(I, T) ∩ S_invalid = ∅
```

No sequence of valid transitions from initial states reaches an invalid state.
Discharge: Model checking + SAFE-1.

#### REACH-2: Syntactic-Only State Unreachability

```
S_syntactic ∩ Reachable(I, T) = ∅
```

States that satisfy structural predicates but have no legitimate history must not be reachable.

**Why this matters**: If the constraint system accepts proofs over states in S_syntactic, an adversary can fabricate state histories. The state "looks valid" but was never legitimately produced.

Discharge: Reachability analysis. For each state satisfying ValidState, verify existence of path from I.

#### REACH-3: Error State Boundedness

```
∀ s_error ∈ S_error: ∃ recovery path from s_error to S_valid
  OR s_error is terminal with explicit semantics
```

Error states must not be black holes.

#### REACH-4: No Orphan States

```
∀ s ∈ Reachable(I, T) \ I: ∃ s_prev, σ: Apply(s_prev, σ) = s
```

Every reachable state (except initial) has a predecessor.

### 6.3 Transition Coverage

For each state region, enumerate which transition classes are applicable:

| Region | Applicable Classes |
|--------|-------------------|
| S_init | T_init only (first transition) |
| S_valid | T_update, T_noop, T_error, T_batch |
| S_error | T_noop (recovery), T_update (if recovery defined) |

**Obligation**: Verify no transition class is applicable in a region where it should not be.

---

## 7. Edge Cases in Partitioning

### EDGE-1: Empty Input

```
σ = ∅ or σ = default
```

Which class handles this? Must be explicitly defined.
If ValidInput(∅) = false → T_noop.
If ∅ is not in Σ → T_reject.

### EDGE-2: Authorization Without Semantic Content

```
σ = (∅_payload, valid_auth, ∅_aux)
```

Valid authorization but no semantic command. Must map to T_noop, not T_update.

### EDGE-3: Batch of Zero

```
σ = Batch([])
```

IsBatch = true, but no operations. Must be explicitly handled.
Options: T_noop (preferred) or T_error.

### EDGE-4: Batch of One

```
σ = Batch([σ₁])
```

Must produce identical result to single σ₁ (THM-12 / LEM-9).

### EDGE-5: Recursive Batch

```
σ = Batch([Batch([σ₁, σ₂]), σ₃])
```

Must be explicitly forbidden or explicitly defined with flattening semantics.

### EDGE-6: Input at State Boundary

```
s at maximum capacity, σ requesting resource allocation
```

Pre(s, σ) may be ambiguous at exact boundary. Must be strictly defined.

### EDGE-7: Concurrent Guard Satisfaction Under Composition

In composed systems, a cross-system input may satisfy guards in both systems simultaneously. The composition model must define which system processes first, or define atomic cross-transition semantics.

---

## 8. Formal Verification Plan

### Model Checking (TLA+)

Properties to check:
- Exhaustiveness: no (s, σ) pair without applicable class
- Disjointness: no (s, σ) pair with multiple applicable classes (after priority)
- Reachability: S_invalid unreachable from I
- Coverage: every transition class exercised from every applicable region

### Theorem Proving (Coq/Lean)

Theorems to prove:
- Guard_noop = ¬Guard_update (structural)
- Priority ordering produces unique class for all (s, σ)
- IsBatch is decidable and unambiguous
- ExplicitError ⟹ ¬Pre (or priority resolution is semantically safe)

---

## 9. Closing Statement

Transition partitioning is not bookkeeping.

It is the proof that the system's response to any situation is unique and predetermined.

If two rules can fire on the same input, you don't have a state machine.
You have a suggestion engine.
