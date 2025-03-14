**Verifiable Semantic Execution Layer (VSEL)**

# INVALID EXECUTION WITNESS SUITE

## 1. Purpose

This document defines families of invalid witnesses that the constraint system MUST reject.

This is not a test suite. It is a systematic construction of the adversary's toolkit.

For each family, we describe:
- The structural shape of the invalid witness
- Why it is semantically invalid
- Which constraint should catch it
- What happens if the constraint is missing

> The goal is not to prove valid executions work. The goal is to prove invalid executions are impossible.

---

## 2. Witness Families

### Family W1: State Violation Witnesses

Invalid witnesses where intermediate states violate validity predicates.

#### W1.1: Negative Balance State

```
Witness: s_i where accounts[A].balance < 0
Semantic violation: Resource underflow
Expected rejection: Canonical state validity constraint (C ∈ ValidC)
If missed: Adversary can drain accounts below zero
```

#### W1.2: Inconsistent Derived State

```
Witness: s_i where D ≠ Derive(C)
Semantic violation: Derived state inconsistency (G_commit)
Expected rejection: D = Derive(C) constraint
If missed: Proofs validate over phantom state roots
```

#### W1.3: Invalid Environment

```
Witness: s_i where E contains impossible values (negative timestamp, future block)
Semantic violation: Environment validity (G_env)
Expected rejection: Environment validity constraint
If missed: Transitions execute under impossible conditions
```

#### W1.4: Metadata Regression

```
Witness: s_i where τ.sequence < τ_{i-1}.sequence
Semantic violation: Monotonicity (G_mono)
Expected rejection: Metadata monotonicity constraint
If missed: Trace ordering can be violated
```

#### W1.5: Unreachable but Valid-Looking State

```
Witness: s_i where ValidState(s_i) but s_i ∉ Reachable(I, T)
Semantic violation: State has no legitimate history
Expected rejection: Transition linking constraints (s_i = Apply(s_{i-1}, σ_{i-1}))
If missed: Adversary can inject fabricated states into proof
```

---

### Family W2: Transition Violation Witnesses

Invalid witnesses where transitions do not follow Apply.

#### W2.1: Arbitrary State Jump

```
Witness: (s_i, σ_i, s_{i+1}) where s_{i+1} ≠ Apply(s_i, σ_i)
Semantic violation: Transition correctness
Expected rejection: Transition constraint (s' = Apply(s, σ))
If missed: Any state can follow any other state
```

#### W2.2: Hidden Field Mutation

```
Witness: (s_i, σ_i, s_{i+1}) where Diff(s_i, s_{i+1}) ⊄ AllowedMutations(σ_i)
Semantic violation: Mutation scope (SAFE-3)
Expected rejection: Carry-over constraints for non-mutated fields
If missed: Adversary can change any field during any transition
```

#### W2.3: Resource Creation

```
Witness: (s_i, σ_i, s_{i+1}) where Total(C_{i+1}) > Total(C_i) + incoming
Semantic violation: Resource conservation (L_cons)
Expected rejection: Conservation constraint
If missed: Adversary can create resources from nothing
```

#### W2.4: Resource Destruction

```
Witness: (s_i, σ_i, s_{i+1}) where Total(C_{i+1}) < Total(C_i) - fees
Semantic violation: Resource conservation (L_cons)
Expected rejection: Conservation constraint
If missed: Resources disappear without accounting
```

#### W2.5: Unauthorized Transition

```
Witness: (s_i, σ_i, s_{i+1}) where Auth(σ_i) = false but transition proceeds
Semantic violation: Authorization requirement
Expected rejection: Authorization constraint
If missed: Anyone can execute any operation
```

#### W2.6: Precondition-Violating Transition

```
Witness: (s_i, σ_i, s_{i+1}) where ¬Pre(s_i, σ_i) but transition proceeds as T_update
Semantic violation: Precondition enforcement
Expected rejection: Precondition constraint
If missed: Invalid operations execute as if valid
```

---

### Family W3: Trace Structure Violation Witnesses

Invalid witnesses where trace structure is malformed.

#### W3.1: Broken Chain Linking

```
Witness: Trace where s_{i+1} in entry e_i ≠ s_i in entry e_{i+1}
Semantic violation: Trace continuity
Expected rejection: State linking constraint
If missed: Trace entries can be from different executions
```

#### W3.2: Missing Transition

```
Witness: Trace where (s_i, s_{i+2}) with no entry for s_{i+1}
Semantic violation: Trace completeness (T_complete)
Expected rejection: Sequential indexing constraint
If missed: Transitions can be hidden
```

#### W3.3: Reordered Entries

```
Witness: Trace where entry indices are not monotonically increasing
Semantic violation: Trace ordering
Expected rejection: Index ordering constraint
If missed: Causal ordering can be violated
```

#### W3.4: Duplicate Entries

```
Witness: Trace with two entries having same index
Semantic violation: Trace uniqueness
Expected rejection: Index uniqueness constraint
If missed: Transitions can be duplicated
```

#### W3.5: Invalid Initial State

```
Witness: Trace where s₀ ∉ I
Semantic violation: Initial state validity
Expected rejection: Genesis constraint
If missed: Execution can start from arbitrary state
```

---

### Family W4: Observable Manipulation Witnesses

Invalid witnesses where observables don't match transitions.

#### W4.1: Fabricated Observable

```
Witness: (s_i, σ_i, s_{i+1}, o_i) where o_i ≠ Obs(s_i, σ_i, s_{i+1})
Semantic violation: Observable correctness
Expected rejection: Observable computation constraint
If missed: External consumers receive false information
```

#### W4.2: Missing Observable

```
Witness: Transition with no observable recorded
Semantic violation: Observable completeness
Expected rejection: Observable existence constraint
If missed: Semantically relevant effects are invisible
```

#### W4.3: No-Op with Non-Null Observable

```
Witness: No-op transition producing meaningful observable
Semantic violation: No-op semantic neutrality (LEM-8)
Expected rejection: No-op observable constraint
If missed: No-ops can fake real transitions to external observers
```

---

### Family W5: Authorization Manipulation Witnesses

#### W5.1: Signature Over Wrong Payload

```
Witness: Valid signature but covering different data than semantic payload
Semantic violation: Authorization binding
Expected rejection: Signature-payload binding constraint
If missed: Signatures can authorize unintended operations
```

#### W5.2: Replayed Authorization

```
Witness: Authorization evidence from previous epoch reused
Semantic violation: Replay resistance
Expected rejection: Nonce/epoch constraint
If missed: Old authorizations can be replayed
```

#### W5.3: Cross-Domain Authorization

```
Witness: Authorization from Domain_A used in Domain_B
Semantic violation: Domain separation
Expected rejection: Domain tag in authorization constraint
If missed: Cross-domain privilege escalation
```

---

### Family W6: Batch Manipulation Witnesses

#### W6.1: Batch with Reordered Operations

```
Witness: Batch [σ₁, σ₂] executed as [σ₂, σ₁]
Semantic violation: Batch ordering
Expected rejection: Batch ordering constraint
If missed: Adversary controls execution order within batch
```

#### W6.2: Batch Skipping Intermediate Validation

```
Witness: Batch where intermediate state after σ₁ violates precondition of σ₂, but batch succeeds
Semantic violation: Batch decomposition equivalence (LEM-9)
Expected rejection: Per-step precondition constraint within batch
If missed: Batches can bypass precondition checks
```

#### W6.3: Batch with Phantom Operations

```
Witness: Batch claiming 3 operations but only constraining 2
Semantic violation: Batch completeness
Expected rejection: Batch size constraint + per-operation constraints
If missed: Operations can be hidden within batches
```

---

### Family W7: Commitment Manipulation Witnesses

#### W7.1: Commitment to Wrong State

```
Witness: Commit(s_i) ≠ Hash(Encode(s_i))
Semantic violation: Commitment correctness
Expected rejection: Commitment computation constraint
If missed: Proofs bind to wrong states
```

#### W7.2: Chain Hash Manipulation

```
Witness: h_{i+1} ≠ Hash(h_i | Commit(e_i))
Semantic violation: Chain integrity
Expected rejection: Chain hash constraint
If missed: Trace entries can be inserted or removed
```

---

### Family W8: Cross-System Witnesses (Composition)

#### W8.1: Inconsistent Shared State

```
Witness: Cross-transition where shared_A ≠ shared_B after transition
Semantic violation: Shared state consistency (CI-2)
Expected rejection: Shared state equality constraint
If missed: Systems diverge on shared state
```

#### W8.2: Cross-System Resource Creation

```
Witness: Cross-transition where Total_A + Total_B increases
Semantic violation: Cross-system conservation (CI-1)
Expected rejection: Cross-system conservation constraint
If missed: Resources created at system boundary
```

---

## 3. Construction Protocol

For each witness family:

### Step 1: Construct Minimal Invalid Witness
Build the simplest witness that exhibits the specific invalidity.

### Step 2: Verify Constraint Rejection
Submit to constraint checker. Verify rejection.

### Step 3: Identify Rejecting Constraint
Determine which specific constraint(s) cause rejection.

### Step 4: Remove Rejecting Constraint
Temporarily remove the constraint. Verify the invalid witness now passes.
This confirms the constraint is necessary.

### Step 5: Document

```
Witness ID: W[family].[number]
Invalid Witness: [description]
Rejecting Constraints: [constraint IDs]
Necessity Confirmed: [yes/no — does removing constraint allow witness?]
Semantic Impact: [what goes wrong if accepted]
```

---

## 4. Coverage Requirement

Every constraint in the system must be the rejecting constraint for at least one invalid witness family.

If a constraint rejects no invalid witness, it is either:
- Redundant (can be removed without weakening security)
- Incorrectly analyzed (its rejection target has not been identified)

Both cases require investigation.

---

## 5. Closing Statement

This suite is the adversary's playbook, written by the defense.

Every family here is a specific way to lie to the proof system. The constraint system's job is to make every lie detectable.

If any family passes the constraints, the system has a vulnerability. Not a theoretical one. A constructible one.
