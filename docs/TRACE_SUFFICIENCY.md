**Verifiable Semantic Execution Layer (VSEL)**

# TRACE SUFFICIENCY

## 1. Purpose

This document proves that the execution trace in VSEL contains everything semantically necessary and nothing whose absence creates irrecoverable ambiguity.

The question is deceptively simple:

> Given only the trace and the committed initial state, does there exist exactly one admissible semantic class of executions?

If the answer is "more or less," the trace is insufficient and the system is unverifiable regardless of proof strength.

---

## 2. Sufficiency Definition

A trace τ is sufficient if and only if:

```
∀ τ₁, τ₂ compatible with Commit(τ):
  Semantics(τ₁) = Semantics(τ₂)
```

Where "compatible with Commit(τ)" means: τ₁ and τ₂ produce the same trace commitment.

In other words: the trace commitment uniquely determines the semantic execution.

---

## 3. Sufficiency Conditions

### SUFF-1: State Determinism

```
∀ i: s_{i+1} is uniquely determined by (s_i, σ_i)
```

Given by AX-1 (determinism of Apply). If the trace records (s₀, σ₀, σ₁, ..., σ_{n-1}), the entire state sequence is determined.

But: the trace must actually record enough to reconstruct. If only commitments are recorded (not full states), reconstruction requires:
- Full initial state s₀ (or ability to retrieve it from commitment)
- All inputs σ₀, ..., σ_{n-1} (or ability to retrieve them)
- Deterministic re-execution capability

### SUFF-2: Input Completeness

```
∀ i: σ_i is fully recorded in trace entry e_i
```

If any input is omitted or summarized, the trace is insufficient because:
- Re-execution cannot reproduce the transition
- The semantic meaning of the transition is ambiguous

Threats:
- Inputs recorded as hashes only (commitment without content)
- Auxiliary data omitted (acceptable only if THM-4 holds: aux doesn't affect semantics)
- Authorization evidence omitted (acceptable only if authorization is independently verifiable)

### SUFF-3: Observable Completeness

```
∀ i: o_i = Obs(s_i, σ_i, s_{i+1}) is recorded or derivable from trace
```

If observables are not recorded, external consumers cannot verify the trace's external effects.

### SUFF-4: Ordering Completeness

```
∀ i, j: i < j ⟹ Order(e_i, e_j) is deterministic and recorded
```

If ordering is ambiguous, the trace represents multiple possible execution sequences.

### SUFF-5: Environment Completeness

```
∀ i: E_i is recorded or deterministically derivable
```

If environment context (timestamp, block height) is not recorded, re-execution may produce different results under different environment assumptions.

### SUFF-6: No Hidden Transitions

```
∀ state changes: ∃ corresponding trace entry
```

If a state change occurs without a trace entry, the trace is incomplete and the gap is semantically unrecoverable.

---

## 4. Sufficiency Theorems

### THM-SUFF-1: Trace Determines Execution

```
Given s₀ and τ = (σ₀, σ₁, ..., σ_{n-1}):
  ∃! execution (s₀, s₁, ..., s_n) such that ∀ i: s_{i+1} = Apply(s_i, σ_i)
```

Proof: Direct from AX-1 (determinism). Each Apply produces unique s'.

Corollary: If the trace records s₀ and all inputs, the full state sequence is determined.

### THM-SUFF-2: Commitment Determines Trace (Under Collision Resistance)

```
Given Commit(τ₁) = Commit(τ₂):
  τ₁ = τ₂ (with overwhelming probability)
```

Proof: From commitment chain structure and AX-5 (collision resistance).

The commitment chain h_{i+1} = Hash(h_i | Commit(e_i)) ensures that any modification to any entry changes the final commitment.

### THM-SUFF-3: Trace Sufficiency for Semantic Reconstruction

```
Given trace τ with full entries:
  The semantic execution is uniquely determined
  All observables are derivable
  All invariants are checkable
  The formal trace μ_Tr(τ) is uniquely determined
```

Proof: Combines THM-SUFF-1 (execution determination) with THM-2 (observable commutativity) and THM-6 (trace mapping preserves validity).

---

## 5. Insufficiency Scenarios

### INSUFF-1: Commitment-Only Trace

Trace records only state commitments, not full states or inputs.

```
τ_weak = (Commit(s₀), Commit(s₁), ..., Commit(s_n))
```

Problem: Cannot reconstruct inputs. Cannot verify transitions. Cannot check invariants on intermediate states.

Sufficiency: FAILS unless full state and input data is available elsewhere.

### INSUFF-2: Summarized Inputs

Trace records input hashes instead of full inputs.

```
e_i = (i, Commit(s_i), Hash(σ_i), Commit(s_{i+1}))
```

Problem: Cannot re-execute transitions. Cannot verify semantic content of inputs.

Sufficiency: FAILS for semantic reconstruction. Acceptable only for commitment verification (weaker guarantee).

### INSUFF-3: Missing Environment

Trace does not record environment context.

Problem: Re-execution under different environment may produce different results.

Sufficiency: FAILS if any transition depends on environment.

### INSUFF-4: Omitted Error Transitions

Error transitions (no-ops, rejections) not recorded in trace.

Problem: Trace appears to show only successful transitions. The absence of rejected inputs is semantically relevant (it proves certain inputs were not processed).

Sufficiency: PARTIAL — sufficient for positive execution but insufficient for completeness proof.

### INSUFF-5: Compressed Trace Without Decompression Guarantee

Trace is compressed and decompression is lossy.

Problem: Causal ordering, intermediate states, or observables may be lost.

Sufficiency: FAILS unless compression is provably lossless for semantic content (THM-11).

---

## 6. Minimal Sufficient Trace

The minimal trace that achieves full sufficiency contains:

```
For each transition i:
  e_i = {
    index: i,                          // ordering
    pre_state_commitment: Commit(s_i), // state binding
    input: σ_i (full canonical form),  // input completeness
    post_state_commitment: Commit(s_{i+1}), // state binding
    observable: o_i,                   // observable completeness
    environment: E_i,                  // environment completeness
    chain_hash: h_i                    // integrity
  }
```

Plus:
- Full initial state s₀ (or retrievable from commitment)
- Trace commitment: final chain hash h_n

Optional but recommended:
- Full intermediate states (enables verification without re-execution)
- Authorization evidence (enables independent auth verification)

---

## 7. Sufficiency Under Partial Verification

For light verification (without full re-execution):

### Level 1: Commitment Verification Only
Requires: trace commitments + proof
Verifies: proof is valid over committed trace
Does NOT verify: semantic content of transitions

### Level 2: Transition Verification
Requires: full trace entries + proof
Verifies: each transition is valid, invariants hold
Verifies: semantic content

### Level 3: Full Reconstruction
Requires: initial state + full inputs + environment
Verifies: complete re-execution matches trace
Strongest guarantee

Each level requires different trace content. The trace must be sufficient for the strongest verification level the system claims to support.

---

## 8. Trace Sufficiency for Composition

When traces from multiple systems are composed:

```
τ_AB = Merge(τ_A, τ_B)
```

Sufficiency requires:
- Both τ_A and τ_B are individually sufficient
- Cross-system transitions are fully recorded in both traces
- Shared state changes appear consistently in both traces
- Ordering across traces is deterministic and recorded

Additional entries needed:
- Cross-system synchronization points
- Shared state commitments at interaction boundaries
- Cross-invariant verification data

---

## 9. Trace Sufficiency for Temporal Properties

Temporal invariants require trace-level information:

```
T_no_revert: requires full ordering + state commitments at every step
T_cons: requires resource values at every step
T_causal: requires causal dependency information
T_complete: requires proof of no gaps (commitment chain)
```

If any of these are not derivable from the trace, the corresponding temporal invariant is uncheckable.

---

## 10. Adversarial Sufficiency Testing

### Test 1: Reconstruction Test

Given trace τ, reconstruct full execution from s₀ and inputs.
Compare reconstructed states with recorded commitments.
Any mismatch = trace is inconsistent.

### Test 2: Ambiguity Test

Given trace commitment Commit(τ), attempt to construct τ' ≠ τ with same commitment.
If successful = commitment scheme is broken or trace structure is ambiguous.

### Test 3: Omission Test

Remove one trace entry. Attempt to reconstruct full execution.
If reconstruction succeeds with different semantics = trace has redundancy gaps.
If reconstruction fails = trace entry was necessary (good).

### Test 4: Environment Sensitivity Test

Replay trace under different environment parameters.
If results differ = environment must be recorded in trace.
If results are same = environment recording is optional for this transition type.

---

## 11. Closing Statement

Trace sufficiency is the foundation of verifiability.

A proof attests to a trace. A trace represents an execution. If the trace is insufficient to uniquely determine the execution, the proof is a statement about an ambiguous reality.

The trace must contain exactly enough information to eliminate all semantic ambiguity, and the proof that it does so must be as rigorous as the proof of execution itself.
