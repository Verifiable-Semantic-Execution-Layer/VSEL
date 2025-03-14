**Verifiable Semantic Execution Layer (VSEL)**

# UNDERCONSTRAINT ANALYSIS

## 1. Purpose

This document systematically identifies and eliminates underconstraint in VSEL's constraint derivation pipeline.

Underconstraint is the condition where the constraint system accepts executions that the formal specification rejects. It is the single most exploitable class of vulnerability in any ZK-based system.

> An underconstrained system is a system that proves things it should not. It does so silently, confidently, and with full cryptographic backing.

This document exists to make that impossible.

---

## 2. Underconstraint Taxonomy

### Type U1: Free Variable

A witness variable that is not referenced by any constraint.

Impact: Adversary can set it to any value.
Detection: Static analysis of constraint graph.

### Type U2: Weakly Constrained Variable

A variable referenced by constraints, but whose value is not uniquely determined by public inputs and other constrained values.

Impact: Multiple valid witness assignments exist with different semantic meanings.
Detection: Degree-of-freedom analysis. SAT solving with variable relaxation.

### Type U3: Missing Branch Constraint

A conditional path in SIR that does not generate constraints for one or more branches.

Impact: Adversary can force execution down unconstrained branch.
Detection: SIR → constraint template coverage analysis.

### Type U4: Structural-Only Constraint

A constraint that enforces format/type but not semantic meaning.

Impact: Structurally valid but semantically wrong values pass.
Detection: Semantic review against intended invariant.

### Type U5: Orphan Constraint

A constraint that references variables not connected to the main constraint graph.

Impact: Constraint exists but does not actually restrict execution.
Detection: Constraint graph connectivity analysis.

### Type U6: Range Cosmetic

A range constraint that bounds a variable but does not prevent the semantically dangerous values within the range.

Impact: False sense of security. Value is "in range" but still exploitable.
Detection: Adversarial value selection within allowed range.

### Type U7: Temporal Underconstraint

Constraints that hold per-step but fail to enforce properties across steps.

Impact: Each transition is valid, but the sequence is not.
Detection: Multi-step constraint analysis. Trace-level constraint verification.

### Type U8: Composition Underconstraint

Constraints that hold within a single system but fail to enforce cross-system properties.

Impact: Locally valid, globally exploitable.
Detection: Cross-system constraint analysis under composition.

---

## 3. Per-Template Threat Analysis

For each constraint template derived from SIR, the following must be documented:

### Template Analysis Record

```
Template: [name/ID]
SIR Construct: [which SIR element generates this]
Constraint Type: [equality / arithmetic / boolean / range / commitment]
Variables Constrained: [list]
Semantic Intent: [what property this is supposed to enforce]
Underconstraint Threat: [specific U-type threats]
Free Variables If Removed: [which variables become free]
Fields Alterable Without Detection: [which state fields can change]
Branches Covered: [which execution paths]
Branches NOT Covered: [which paths are missing]
Dependent Constraints: [which other constraints this works with]
Standalone Sufficiency: [does this constraint alone enforce its intent?]
```

---

## 4. State Constraint Analysis

### 4.1 Canonical State Validity

```
Constraint: C ∈ ValidC
```

Threats:
- U4: Structural validity (correct types, non-negative) without semantic validity (correct ownership, valid references)
- U6: Balance constrained to [0, MAX] but not constrained to reflect actual resource flow

Required sub-constraints:
- Each account balance is the result of a deterministic computation from prior state + input
- No balance appears from nowhere (conservation)
- All references (account IDs, storage keys) point to existing entities

### 4.2 Derived State Consistency

```
Constraint: D = Derive(C)
```

Threats:
- U2: If Derive is complex, intermediate values may be weakly constrained
- U1: Auxiliary values in Derive computation may be free

Required: Every intermediate value in Derive computation must be constrained. Merkle tree computation must constrain all nodes, not just root.

### 4.3 Environment Validity

```
Constraint: E ∈ ValidE
```

Threats:
- U4: Timestamp constrained to be positive but not constrained to be monotonically increasing relative to prior state
- U6: Block height in valid range but not linked to actual chain state

Required: Environment constraints must reference prior state metadata for temporal consistency.

### 4.4 Metadata Consistency

```
Constraint: τ_{i+1} = Update(τ_i)
```

Threats:
- U2: If Update is not fully constrained, metadata can drift
- U7: Per-step metadata valid but sequence-level properties (monotonicity) not enforced in constraints

---

## 5. Input Constraint Analysis

### 5.1 Canonical Form

```
Constraint: σ = Canonical(σ)
```

Threats:
- U4: Canonicalization checks format but not semantic content
- U2: Multiple canonical forms possible if canonicalization is not injective

### 5.2 Authorization

```
Constraint: Auth(σ) = true
```

Threats:
- U4: Signature verified but signer identity not linked to authorized set
- U1: Authorization evidence present but not connected to semantic payload (signature covers wrong data)

Critical sub-constraint: The data signed must be exactly the canonical semantic payload, not a subset or superset.

### 5.3 Domain Validity

```
Constraint: σ ∈ Σ
```

Threats:
- U6: Input in valid type range but not in valid semantic range for current state
- U3: Some input types not covered by domain check

---

## 6. Transition Constraint Analysis

### 6.1 Functional Correctness

```
Constraint: s' = Apply(s, σ)
```

This is the most complex and most vulnerable constraint family.

Threats:
- U1: Fields of s' not explicitly constrained (assumed to carry over from s)
- U2: Fields constrained by equality to expressions that themselves contain free variables
- U3: Conditional logic in Apply with unconstrained branches
- U6: Arithmetic constraints that allow overflow/underflow within field range

Per-field analysis required:

```
For each field f in s':
  - Is f explicitly constrained? [yes/no]
  - Is f's constraint sufficient to determine its value uniquely? [yes/no]
  - Can f be altered without violating any constraint? [yes/no]
  - What is the maximum freedom in f's value? [range/set]
```

### 6.2 Mutation Scope

```
Constraint: Diff(s, s') ⊆ AllowedMutations(σ)
```

Threats:
- U1: Non-mutated fields not explicitly constrained to remain unchanged
- This is the "carry-over" problem: if a field is not mentioned in constraints, is it constrained to be equal to its prior value?

**CRITICAL**: In most constraint systems, unmentioned variables are FREE, not carried over. Every field that should remain unchanged MUST have an explicit equality constraint:

```
∀ f ∉ AllowedMutations(σ): s'.f = s.f
```

If this is missing, the adversary can change any unmentioned field.

### 6.3 No Implicit State

Threats:
- U1: Internal computation variables (loop counters, temporary values) not constrained
- U5: Constraints reference internal variables not connected to state or input

---

## 7. Invariant Constraint Analysis

### 7.1 Local Invariants

For each local invariant L:

```
Invariant: L(s, σ, s')
Constraint encoding: [specific constraints]
Threats:
  - Is L fully encoded or partially?
  - Can L be satisfied by invalid (s, σ, s')?
  - Does L depend on other constraints being present?
```

### 7.2 Global Invariants

For each global invariant G:

```
Invariant: G(s)
Constraint encoding: [specific constraints]
Threats:
  - Is G checked on both pre-state and post-state?
  - Can G hold on post-state while being violated "between" states?
  - Does G depend on derived state being correct?
```

### 7.3 Temporal Invariants

```
Invariant: TInv(τ)
Constraint encoding: [specific constraints]
Threats:
  - U7: Per-step constraints exist but no cross-step linking
  - Temporal invariants often require constraints that span multiple trace entries
  - If proof covers single transition, temporal invariants may be unenforceable in constraints
```

Resolution: Temporal invariants must be encoded either:
- In the trace commitment structure (verifier checks)
- In recursive proof composition (each proof carries forward temporal state)
- In explicit cross-step constraint linking

---

## 8. Witness Freedom Analysis

For the complete constraint system, perform:

### 8.1 Variable Census

```
Total witness variables: [count]
Variables in at least one constraint: [count]
Variables in zero constraints: [count] ← MUST BE ZERO
Variables uniquely determined: [count]
Variables with degree of freedom: [count] ← MUST BE ZERO for semantic variables
```

### 8.2 Degree of Freedom Map

For each variable with any freedom:

```
Variable: [name]
Freedom: [range of possible values]
Semantic impact: [what changes if this variable changes]
Exploitability: [can adversary benefit from choosing a specific value?]
Resolution: [add constraint / prove benign / document as acceptable]
```

### 8.3 Alternate Witness Search

For each proof instance:

```
Given public inputs P and valid witness W₁:
  Search for W₂ ≠ W₁ such that Satisfies(W₂, C, P)
  If found:
    Compare Semantics(W₁) vs Semantics(W₂)
    If different: CRITICAL VULNERABILITY
    If same: document as acceptable equivalence class
```

---

## 9. Constraint Coverage Matrix

### 9.1 Transition × Invariant Coverage

For each transition class T_k and each invariant I_j:

```
| Transition | Invariant | Constraints Enforcing | Coverage | Gap |
|-----------|-----------|----------------------|----------|-----|
| T_update  | L_cons    | C_12, C_15, C_18     | Full     | -   |
| T_update  | G_commit  | C_22                  | Partial  | Missing intermediate commitment |
| T_batch   | L_cons    | C_12, C_15            | Gap      | Per-item conservation not enforced |
| T_error   | G_valid   | C_30                  | Full     | -   |
| ...       | ...       | ...                   | ...      | ... |
```

Every cell must be "Full". Every "Partial" or "Gap" is a finding.

### 9.2 Field × Constraint Coverage

For each state field and each transition class:

```
| Field | T_update | T_batch | T_error | T_noop |
|-------|----------|---------|---------|--------|
| balance | C_12 (=) | C_40 (=) | C_30 (=s) | C_50 (=s) |
| storage | C_14 (=) | C_42 (=) | C_30 (=s) | C_50 (=s) |
| nonce | C_16 (+1) | C_44 (+n) | C_30 (=s) | C_50 (=s) |
| ...   | ...      | ...     | ...     | ...    |
```

(=) means constrained to computed value
(=s) means constrained to equal prior value
(+1) means constrained to increment
Empty cell = UNCONSTRAINED FIELD = VULNERABILITY

---

## 10. Adversarial Constraint Testing Protocol

### Phase 1: Static Analysis
- Variable census
- Constraint graph connectivity
- Branch coverage enumeration
- Carry-over constraint verification

### Phase 2: Symbolic Analysis
- SAT/SMT solving for alternate witnesses
- Degree of freedom computation
- Range analysis for each variable

### Phase 3: Adversarial Fuzzing
- Generate random invalid traces
- Check if any satisfy constraints
- Mutate valid witnesses and check satisfaction
- Target specific U-types with crafted inputs

### Phase 4: Semantic Review
- For each constraint, verify it enforces its intended semantic property
- For each semantic property, verify it has sufficient constraint coverage
- For each transition class, verify all fields are accounted for

---

## 11. Constraint Coupling Analysis

Some constraints only enforce their semantic intent when combined with others.

```
Constraint Group: [C_12, C_15, C_18]
Individual sufficiency: None (each alone is insufficient)
Combined sufficiency: Enforces resource conservation
Coupling risk: If any one is removed, conservation breaks
```

For each coupled group:
- Document the coupling
- Verify no single constraint removal breaks the semantic property
- Verify no constraint in the group is redundant (each contributes)

---

## 12. Known Dangerous Patterns

### Pattern D1: The Carry-Over Assumption
Assuming unchanged fields are constrained when they are not.
Fix: Explicit equality constraints for all non-mutated fields.

### Pattern D2: The Range Illusion
Constraining a value to a valid range without constraining its derivation.
Fix: Constrain the computation, not just the result.

### Pattern D3: The Branch Blindspot
Constraining the "happy path" but not error/edge paths.
Fix: Every SIR branch must generate constraints.

### Pattern D4: The Commitment Shortcut
Constraining the final commitment but not intermediate steps.
Fix: Constrain the full computation tree, not just the root.

### Pattern D5: The Temporal Gap
Constraining each step but not the relationship between steps.
Fix: Cross-step linking constraints or recursive proof state.

### Pattern D6: The Authorization Disconnect
Verifying a signature exists without constraining what it signs.
Fix: Signature must cover exactly the canonical semantic payload.

---

## 13. Closing Statement

Underconstraint analysis is not optional hardening.

It is the difference between a proof system and a proof theater.

Every unconstrained variable is a degree of freedom gifted to the adversary.
Every missing constraint is a door left open with a sign that says "please don't enter."

The adversary does not read signs.
