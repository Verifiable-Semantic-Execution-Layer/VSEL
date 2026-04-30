**Verifiable Semantic Execution Layer (VSEL)**

## 1. Purpose

This document defines the **concrete operational state machine** of VSEL.

While `FORMAL_SPECIFICATION.md` defines correctness at an abstract level, this document specifies:

* concrete state representation
* transition classes
* execution rules
* preconditions and postconditions
* error semantics

This is the bridge between:

> “what is correct”
> and
> “what actually runs”

If this document diverges from the formal specification, the implementation is wrong.

---

## 2. State Structure

A concrete state ( s \in S ) is defined as:

[
s = (C, D, E, \tau)
]

Where:

### 2.1 Canonical State ( C )

Represents the minimal semantic state:

* account balances / resources
* ownership mappings
* contract storage
* system-defined data structures

Properties:

* fully deterministic
* minimal representation
* sufficient to reconstruct all semantics

---

### 2.2 Derived State ( D )

Computed from ( C ):

* Merkle roots
* aggregate values
* indexing structures

Constraint:

[
D = Derive(C)
]

Derived state must not introduce new semantics.

---

### 2.3 Environment ( E )

Represents external context:

* timestamp
* block height
* execution domain
* randomness (if modeled)

All environmental influence must be explicit.

---

### 2.4 Trace Metadata ( \tau )

Includes:

* sequence index
* previous state commitment
* execution epoch

Ensures ordering and trace consistency.

---

## 3. State Encoding

State encoding must satisfy:

* canonical serialization
* deterministic hashing
* structural integrity

Let:

[
Encode: S \rightarrow Bytes
]

[
Hash: Bytes \rightarrow Commitment
]

Requirement:

[
Hash(Encode(s)) = Commitment(s)
]

Any mismatch invalidates the state.

---

## 4. Transition Model

A transition is defined as:

[
(s, \sigma) \rightarrow s'
]

Where:

* ( s ) is current state
* ( \sigma ) is input
* ( s' ) is resulting state

Transitions are deterministic:

[
(s, \sigma) \Rightarrow s' \text{ is unique}
]

---

## 5. Transition Classes

Transitions are categorized into explicit classes.

No implicit transition types are allowed.

---

### 5.1 Initialization Transition

[
Init \rightarrow s_0
]

Creates a valid initial state.

Preconditions:

* no prior state

Postconditions:

* ( s_0 \in I )

---

### 5.2 State Update Transition

[
(s, \sigma_{update}) \rightarrow s'
]

Represents standard state mutation.

Preconditions:

* input is valid
* authorization passes
* invariants hold on ( s )

Postconditions:

* invariants hold on ( s' )
* state updated deterministically

---

### 5.3 No-Op Transition

[
(s, \sigma_{noop}) \rightarrow s
]

Used for:

* invalid input handling
* rejected operations

Preconditions:

* input fails validation

Postconditions:

* state unchanged
* rejection observable emitted

---

### 5.4 Error Transition

[
(s, \sigma_{error}) \rightarrow s_{error}
]

Explicit error state handling.

Constraint:

* ( s_{error} \in S )
* invariants must still hold

No undefined behavior allowed.

---

### 5.5 Batch Transition

[
(s, [\sigma_1, ..., \sigma_n]) \rightarrow s'
]

Equivalent to sequential application:

[
Apply(s, \sigma_1, ..., \sigma_n)
]

Constraint:

* ordering must be preserved
* no implicit reordering

#### 5.5.1 Batch Intermediate Invariant Policy

Batch execution is sequential application with **per-step invariant validation**.
Each input σ_i in the batch is executed through the full 7-step pipeline
(§6), including postcondition validation (step 5) and derived state
recalculation (step 6). If any intermediate state s_i violates any
invariant, the entire batch is rejected — no partial application is
committed.

Formally:

[
\forall i \in [1, n]: \text{Invariants}(s_i) \text{ must hold}
]

If there exists any i such that the intermediate state s_i produced by
applying σ_i violates an invariant, then:

[
\text{execute\_batch}(s, [\sigma_1, ..., \sigma_n]) = \text{Error}
]

even if the final state s_n would restore the invariant. This policy
prevents transient invariant violations from being masked by subsequent
operations within the same batch.

This is a deliberate design choice: batch execution provides no
"transaction-level" invariant relaxation. Every intermediate state must
be independently valid.

---

## 6. Transition Execution Pipeline

Each transition follows a strict pipeline:

### Step 1: Input Canonicalization

[
\sigma_c \rightarrow \sigma_{canonical}
]

Reject if ambiguous or malformed.

---

### Step 2: Authorization Check

[
Auth(\sigma) = true
]

Reject otherwise.

---

### Step 3: Precondition Validation

[
Pre(s, \sigma) = true
]

Examples:

* sufficient balance
* valid references
* invariant preconditions

---

### Step 4: State Transformation

[
s' = Apply(s, \sigma)
]

Deterministic function.

---

### Step 5: Postcondition Validation

[
Post(s, \sigma, s') = true
]

Includes:

* invariant preservation
* structural validation

---

### Step 6: Derived State Recalculation

[
D' = Derive(C')
]

Must match computed derived state.

---

### Step 7: Commitment Update

[
\tau' = Update(\tau, s')
]

Ensures trace continuity.

---

## 7. Determinism Enforcement

The system must guarantee:

[
Apply(s, \sigma) = s'
]

for exactly one ( s' ).

Sources of nondeterminism must be:

* eliminated, or
* explicitly modeled in ( E )

Hidden nondeterminism is treated as a security failure.

---

## 8. State Mutation Constraints

Let:

[
\Delta(s, s') = Diff(s, s')
]

Constraints:

* only allowed fields may change
* mutation must be minimal and justified
* unrelated state must remain unchanged

---

## 9. Error Semantics

Errors must be:

* explicit
* deterministic
* semantically valid

No silent failures.

No partial state updates.

Two acceptable behaviors:

* revert to ( s ) (no-op)
* transition to defined error state

---

## 10. Ordering Guarantees

Execution order must be:

* total within a trace
* preserved across mapping

If partial ordering is allowed, it must be formally defined.

---

## 11. Replay Semantics

Given identical:

* initial state
* input sequence
* environment

The system must produce identical:

* state sequence
* observables

[
Replay(\tau) = \tau
]

---

## 12. Trace Construction

A trace is constructed as:

[
\tau = (s_0, \sigma_0, s_1, ..., s_n)
]

Requirements:

* every transition recorded
* no hidden state changes
* commitments chained

---

## 13. Cross-Layer Consistency

### 13.1 Execution ↔ Specification

[
Apply_{impl} = Apply_{spec}
]

---

### 13.2 Execution ↔ Semantic Mapping

[
\mu_S(s') = Apply_f(\mu_S(s), \mu_\Sigma(\sigma))
]

---

### 13.3 Execution ↔ Constraints

[
Apply(s, \sigma) \Rightarrow SatisfiesConstraints(s, \sigma, s')
]

---

## 14. Invalid State Prevention

The system must enforce:

[
\neg \exists (s, \sigma): Apply(s, \sigma) = s' \land s' \notin S
]

Invalid states must be unreachable.

---

## 15. State Transition Completeness

Every possible execution path must be covered by:

* defined transition classes
* explicit rules

If a transition occurs that is not defined here, the system is incomplete.

---

## 16. Failure Modes

### 16.1 Undefined Transition

A transition occurs with no defined behavior.

---

### 16.2 Partial State Mutation

State changes without full validation.

---

### 16.3 Hidden State Change

State changes outside trace.

---

### 16.4 Derived State Drift

[
D \neq Derive(C)
]

---

### 16.5 Non-Deterministic Outcome

Same input produces different results.

---

## 17. Minimal Validation Conditions

A valid execution must satisfy:

* all preconditions
* deterministic transformation
* all postconditions
* invariant preservation
* correct trace recording

---

## 18. Closing Statement

This document removes ambiguity from execution.

If the implementation does anything not described here, it is not “an edge case.”

It is a violation.
