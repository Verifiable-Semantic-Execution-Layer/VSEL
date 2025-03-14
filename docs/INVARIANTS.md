**Verifiable Semantic Execution Layer (VSEL)**

## 1. Purpose

This document defines the invariant system of VSEL.

Invariants are the formal properties that must hold:

* at every state
* across every transition
* over complete execution traces

They define the **true correctness surface** of the system.

> If an invariant can be violated, the system is incorrect, regardless of proof validity.

---

## 2. Invariant Taxonomy

VSEL classifies invariants into three categories:

* **Local Invariants**: properties of individual transitions
* **Global Invariants**: properties of system state
* **Temporal Invariants**: properties over execution traces

Each invariant must be:

* formally defined
* enforceable
* testable
* derivable into constraints

---

## 3. Notation

Let:

* ( s \in S ): state
* ( \sigma \in \Sigma ): input
* ( (s, \sigma, s') \in T ): transition
* ( \tau = (s_0, ..., s_n) ): execution trace

---

## 4. Local Invariants

Local invariants apply to every transition.

[
\forall (s, \sigma, s') \in T: L_i(s, \sigma, s')
]

---

### 4.1 Transition Validity

[
L_{valid}(s, \sigma, s') \equiv Apply(s, \sigma) = s'
]

Ensures:

* no undefined transitions
* no implicit behavior

---

### 4.2 State Preservation

[
L_{state}(s, s') \equiv ValidState(s) \land ValidState(s')
]

No transition may produce an invalid state.

---

### 4.3 Resource Conservation

[
L_{cons}(s, s') \equiv
Total(C_s) = Total(C_{s'}) + \Delta_{fees}
]

Where:

* ( Total(C) ) is total conserved resource (e.g. value)
* ( \Delta_{fees} ) is explicitly modeled

No hidden creation or destruction.

---

### 4.4 Bounded State Mutation

[
L_{bounded}(s, s') \equiv
|Diff(s, s')| \leq \delta_{max}
]

Prevents:

* unbounded or arbitrary state mutation

---

### 4.5 Deterministic Transition

[
L_{det}(s, \sigma) \equiv \exists! s'
]

Guarantees:

* exactly one valid next state

---

## 5. Global Invariants

Global invariants apply to every reachable state.

[
\forall s \in S: G_i(s)
]

---

### 5.1 State Validity

[
G_{valid}(s) \equiv ValidState(s)
]

Structural and semantic correctness.

---

### 5.2 Structural Integrity

[
G_{struct}(s) \equiv
ConsistentEncoding(s) \land
WellFormed(s)
]

Ensures:

* no malformed data
* no invalid encodings

---

### 5.3 Commitment Consistency

[
G_{commit}(s) \equiv
Commit(C) = D.commitment
]

Derived state must match canonical state.

---

### 5.4 Monotonic Metadata

[
G_{mono}(s) \equiv
\tau_{current} \geq \tau_{previous}
]

Prevents rollback or reordering.

---

### 5.5 Environment Consistency

[
G_{env}(s) \equiv ValidEnv(E)
]

Ensures:

* environment assumptions are valid and explicit

---

## 6. Temporal Invariants

Temporal invariants apply over execution traces.

[
\forall \tau: TInv_i(\tau)
]

---

### 6.1 Trace Validity

[
T_{valid}(\tau) \equiv
\forall i: (s_i, \sigma_i, s_{i+1}) \in T
]

---

### 6.2 No State Reversion

[
T_{no_revert}(\tau) \equiv
\neg \exists i < j: s_i = s_j \land rollback(i, j)
]

Prevents rollback attacks.

---

### 6.3 Cumulative Resource Consistency

[
T_{cons}(\tau) \equiv
\sum_{i} Total(C_{s_i}) = constant + \sum Fees
]

Ensures conservation over time.

---

### 6.4 Causality Preservation

[
T_{causal}(\tau) \equiv
Order(\sigma_i) \Rightarrow Order(s_i)
]

Prevents:

* reordering attacks
* causal violations

---

### 6.5 No Hidden Transitions

[
T_{complete}(\tau) \equiv
AllTransitionsRecorded(\tau)
]

Every state change must be observable.

---

## 7. Cross-Layer Invariants

These enforce consistency between layers.

---

### 7.1 Execution ↔ Specification

[
X_{exec}(s, \sigma, s') \equiv
Apply_{impl}(s, \sigma) = Apply_{spec}(s, \sigma)
]

---

### 7.2 Specification ↔ Constraints

[
X_{constraint}(\tau) \equiv
ValidTrace(\tau) \Leftrightarrow SatisfiesConstraints(\tau)
]

Critical for soundness and completeness.

---

### 7.3 Execution ↔ Proof

[
X_{proof}(\tau, \pi) \equiv
Verify(\pi) \Rightarrow ValidTrace(\tau)
]

---

## 8. Composition Invariants

For composed systems ( A ) and ( B ):

---

### 8.1 Shared State Integrity

[
C_{shared}^A = C_{shared}^B
]

---

### 8.2 Cross-System Conservation

[
Total_A + Total_B = constant
]

---

### 8.3 Boundary Validity

[
Inputs_{A \rightarrow B} \in \Sigma_B
]

No invalid cross-system inputs.

---

## 9. Invariant Violations

A violation occurs if:

[
\exists s, \sigma, s' \text{ such that } \neg L(s, \sigma, s')
]

or:

[
\exists s \in S: \neg G(s)
]

or:

[
\exists \tau: \neg TInv(\tau)
]

---

## 10. Enforcement Requirements

Every invariant must be:

* encoded in formal specification
* represented in SIR
* enforced in constraints
* testable in execution

If an invariant is not enforced in **all layers**, it is not real.

---

## 11. Minimal Invariant Completeness

The invariant set is complete if:

> No semantically invalid execution satisfies all invariants.

If such an execution exists:

* invariants are incomplete
* system is vulnerable

---

## 11.1 Economic Invariants

Economic invariants are a fourth invariant category, orthogonal to structural invariants but equally mandatory. They are fully defined in `ECONOMIC_INVARIANTS.md`.

Summary:

**Local economic** (per transition): E_cost (non-zero acquisition cost), E_leverage (bounded leverage), E_proportionality (fee proportionality), E_slippage (bounded price impact), E_collateral (collateral sufficiency).

**Global economic** (per state): G_econ_valid (economic state validity), G_concentration (bounded concentration), G_liquidity (minimum liquidity), G_solvency (system solvency), G_dust (bounded minimum balance).

**Temporal economic** (per trace): TE_extraction (bounded epoch extraction), TE_flash (flash operation collateral), TE_sandwich (anti-sandwich), TE_manipulation (price manipulation resistance), TE_velocity (economic velocity bounds).

**Compositional economic**: CE_arbitrage (cross-system arbitrage bounds), CE_contagion (economic contagion isolation).

The admissibility condition becomes:

```
Admissible(s) ≡ ValidState(s) ∧ EconomicallyValid(s)
AdmissibleTrace(τ) ≡ ValidTrace(τ) ∧ ∀ s_i ∈ τ: EconomicallyValid(s_i) ∧ ∀ TE_econ: TE_econ(τ)
```

Economic invariants follow the same enforcement requirements: expressible in FSL, preserved in SIR, enforced in CDL, testable in execution.

---

## 12. Failure Classification

Violations are classified as:

* **Local failure**: transition-level inconsistency
* **Global failure**: invalid state reachable
* **Temporal failure**: trace-level inconsistency
* **Cross-layer failure**: semantic mismatch

---

## 13. Closing Statement

Invariants are not constraints you add later.

They are the system.

If your invariants are weak, your proofs will be strong and useless at the same time.
