**Verifiable Semantic Execution Layer (VSEL)**

# ASSUME-GUARANTEE COMPOSITION MODEL

## 1. Purpose

This document replaces informal compatibility with formal contractual composition.

Each VSEL subsystem is defined not just by what it does, but by:
- what it assumes about its environment
- what it guarantees to its consumers
- what it exposes as observable interface
- what it forbids as interaction

Composition is valid if and only if the guarantees of each subsystem satisfy the assumptions of every other subsystem it interacts with, without opening regions of state where neither subsystem maintains semantic closure.

> "Compatible" is not a feeling. It is a theorem.

---

## 2. Subsystem Contract Structure

Each subsystem M defines a formal contract:

```
Contract(M) = {
  Assumes:     A(M)    — properties M requires from its environment
  Guarantees:  G(M)    — properties M provides to its consumers
  Exports:     E(M)    — observable outputs and state commitments
  Effects:     Eff(M)  — state changes visible to other systems
  Forbids:     F(M)    — interactions that violate M's semantic closure
  Temporal:    Temp(M) — temporal obligations M imposes on interaction ordering
}
```

---

## 3. Assume-Guarantee Composition Rule

Two systems M_A and M_B can be composed if and only if:

```
COMPOSE(M_A, M_B) is valid ⟺

  (1) G(M_A) ⊇ A(M_B)          — A's guarantees satisfy B's assumptions
  (2) G(M_B) ⊇ A(M_A)          — B's guarantees satisfy A's assumptions
  (3) Eff(M_A) ∩ F(M_B) = ∅    — A's effects don't violate B's forbidden set
  (4) Eff(M_B) ∩ F(M_A) = ∅    — B's effects don't violate A's forbidden set
  (5) Temp(M_A) ∧ Temp(M_B)    — temporal obligations are jointly satisfiable
  (6) ¬∃ s ∈ Reachable(M_A ∘ M_B): s ∉ S_A × S_B  — no escape from valid state space
```

If any condition fails, composition is rejected.

---

## 4. Contract Components in Detail

### 4.1 Assumptions (A)

Assumptions are properties the subsystem requires but does not enforce.

Examples:
- "Inputs arrive in causal order"
- "Shared state is consistent at interaction boundary"
- "Environment parameters are within valid range"
- "Cross-system resource total is conserved by the other party"
- "Authorization tokens are valid and non-replayed"

**Critical rule**: Every assumption must be explicitly stated. Implicit assumptions are the primary source of composition failure.

Classification:
- **State assumptions**: properties of shared state at interaction point
- **Input assumptions**: properties of cross-system inputs
- **Temporal assumptions**: ordering and timing requirements
- **Resource assumptions**: conservation expectations
- **Authorization assumptions**: permission and identity requirements

### 4.2 Guarantees (G)

Guarantees are properties the subsystem enforces unconditionally (given its assumptions hold).

Examples:
- "All state transitions preserve invariants G₁, G₂, G₃"
- "Resource conservation holds within this system"
- "All outputs are deterministically derived from inputs and state"
- "No state mutation occurs outside the declared effect set"
- "All observables are semantically faithful"

**Critical rule**: A guarantee is only valid under the stated assumptions. If assumptions are violated, guarantees may not hold. This must be explicit.

### 4.3 Exports (E)

Exports define the observable interface:

```
E(M) = {
  state_commitments: [Commit(s) at each interaction point],
  observables: [Obs(τ) for each transition],
  proof_artifacts: [π for each proven segment],
  metadata: [version, domain, epoch]
}
```

Exports must be:
- Sufficient for the consuming system to verify interaction
- Minimal (no unnecessary information leakage)
- Deterministic (same execution produces same exports)

### 4.4 Effects (Eff)

Effects are state changes visible to other systems:

```
Eff(M) = {
  shared_state_mutations: [fields modified in shared state],
  cross_system_messages: [outputs consumed by other systems],
  resource_transfers: [resources moved across boundaries]
}
```

Every effect must be:
- Declared in the contract
- Constrained by the system's invariants
- Observable in the trace

Undeclared effects are contract violations.

### 4.5 Forbidden Interactions (F)

Forbidden interactions are patterns that would break the subsystem's semantic closure:

```
F(M) = {
  concurrent_shared_state_write,
  resource_creation_without_corresponding_debit,
  input_replay_across_epochs,
  state_rollback_of_committed_transitions,
  authorization_bypass_via_cross_system_path
}
```

### 4.6 Temporal Obligations (Temp)

Temporal obligations define ordering and timing requirements:

```
Temp(M) = {
  "Cross-system transitions must be totally ordered",
  "Shared state reads must see latest committed write",
  "Resource transfers must be atomic (debit and credit in same logical step)",
  "Proof verification must occur before state acceptance"
}
```

---

## 5. Composition Verification Protocol

### Step 1: Contract Extraction

For each subsystem, extract the full contract from its specification.

### Step 2: Assumption-Guarantee Matching

For each pair (M_A, M_B):

```
For each assumption a ∈ A(M_B):
  Verify: ∃ guarantee g ∈ G(M_A) such that g ⟹ a
  If not: COMPOSITION REJECTED — unmet assumption
```

### Step 3: Effect-Forbidden Checking

```
For each effect e ∈ Eff(M_A):
  Verify: e ∉ F(M_B)
  If not: COMPOSITION REJECTED — forbidden interaction
```

### Step 4: Temporal Compatibility

```
Verify: Temp(M_A) ∧ Temp(M_B) is satisfiable
If not: COMPOSITION REJECTED — temporal conflict
```

### Step 5: State Space Closure

```
Verify: Reachable(M_A ∘ M_B) ⊆ S_A × S_B
```

No composed execution reaches a state outside both systems' valid state spaces.

### Step 6: Cross-Invariant Derivation

From the composition, derive new invariants G_cross that must hold:

```
G_cross = {
  resource_conservation_across_systems,
  shared_state_consistency,
  causal_ordering_preservation,
  authorization_consistency
}
```

Verify: G_cross is enforceable given G(M_A) ∧ G(M_B).

---

## 6. Contract Failure Modes

### FAIL-1: Unmet Assumption

System B assumes property P. System A does not guarantee P.

Impact: B operates under false assumption. Invariants may break.

Example: B assumes inputs are canonicalized. A sends non-canonical inputs.

### FAIL-2: Forbidden Effect

System A produces effect E. System B forbids E.

Impact: B's semantic closure is violated.

Example: A writes to shared state concurrently. B requires exclusive access.

### FAIL-3: Temporal Incompatibility

System A requires strict ordering. System B allows reordering.

Impact: Causal violations. State inconsistency.

### FAIL-4: Guarantee Weakening Under Composition

System A guarantees G in isolation. Under composition with B, G no longer holds.

Impact: Properties proven in isolation are invalid in composition.

Example: A guarantees resource conservation. B introduces a cross-system transfer that A's conservation constraint doesn't account for.

### FAIL-5: Semantic Closure Escape

Composed state reaches region where neither A nor B maintains semantic validity.

Impact: Undefined behavior in composed system.

Example: Cross-system transition produces shared state that is valid for A but invalid for B, or vice versa.

---

## 7. Cross-System Invariant Catalog

### CI-1: Resource Conservation

```
∀ cross-transition: Total_A + Total_B = constant
```

Assumes: Both systems use compatible resource accounting.
Guarantees: No resource creation or destruction across boundaries.

### CI-2: Shared State Consistency

```
∀ synchronization points: View_A(shared) = View_B(shared)
```

Assumes: Atomic shared state updates.
Guarantees: No divergent views of shared state.

### CI-3: Authorization Transitivity

```
∀ cross-system inputs σ:
  Auth_A(σ) ∧ Auth_B(σ) — both systems must independently verify authorization
```

Assumes: Authorization is not delegated implicitly across boundaries.

### CI-4: Causal Consistency

```
∀ cross-system transitions t₁, t₂:
  Causes(t₁, t₂) ⟹ Order(t₁) < Order(t₂) in both systems
```

### CI-5: Version Compatibility

```
∀ composed (M_A^v1, M_B^v2):
  Contract(M_A^v1) compatible with Contract(M_B^v2)
```

Version mismatches must be explicitly handled.

---

## 8. Composition Proof Obligations

### COMP-PROOF-1: Assumption Satisfaction

```
∀ a ∈ A(M_B): G(M_A) ⊢ a
```

Each assumption of B is provable from guarantees of A.

### COMP-PROOF-2: Effect Safety

```
∀ e ∈ Eff(M_A): e ∉ F(M_B)
```

### COMP-PROOF-3: Cross-Invariant Preservation

```
∀ G_cross: ValidTrace_{AB}(τ) ⟹ G_cross(τ)
```

### COMP-PROOF-4: Compositional Soundness

```
Valid(M_A) ∧ Valid(M_B) ∧ ContractsCompatible(M_A, M_B) ⟹ Valid(M_A ∘ M_B)
```

This is the master composition theorem.

---

## 9. Upgrade and Evolution

When a subsystem upgrades from version v1 to v2:

```
Contract(M^v2) must be backward-compatible with Contract(M^v1):
  A(M^v2) ⊆ A(M^v1)     — new version assumes less or equal
  G(M^v2) ⊇ G(M^v1)     — new version guarantees more or equal
  F(M^v2) ⊆ F(M^v1)     — new version forbids less or equal
```

If backward compatibility is broken:
- All composed systems must be re-verified
- Migration protocol must be defined
- Transition period must be formally modeled

---

## 10. Anti-Patterns

### Anti-Pattern 1: Implicit Trust

"System A trusts System B to be correct."

This is not a contract. This is hope.

### Anti-Pattern 2: Shared State Without Protocol

"Both systems access shared state."

Without atomic access protocol, this is a race condition.

### Anti-Pattern 3: Unversioned Composition

"Systems A and B are composed."

Without version pinning, this is a moving target.

### Anti-Pattern 4: One-Way Verification

"System A verifies B's proofs."

Without B also verifying A's guarantees, the composition is asymmetric and fragile.

---

## 11. Closing Statement

Composition without contracts is collaboration without agreements.

It works until it doesn't, and when it doesn't, nobody knows whose fault it is, because nobody wrote down whose responsibility it was.

VSEL requires that composition be a provable act, not a hopeful one.
