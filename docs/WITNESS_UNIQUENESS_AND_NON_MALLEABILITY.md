**Verifiable Semantic Execution Layer (VSEL)**

# WITNESS UNIQUENESS AND NON-MALLEABILITY

## 1. Purpose

This document formalizes when and why the witness in VSEL's proof system must be unique, when equivalence classes are acceptable, and when ambiguity destroys guarantees.

The statement "the witness must correspond to a single valid execution trace" is necessary but insufficient. This document specifies:

* what "single" means across different components
* where equivalence classes are safe
* where they are catastrophic
* how to detect and prevent witness malleability

> A malleable witness is a proof that says "something happened" without committing to what.

---

## 2. Witness Structure

The witness W in VSEL encodes:

```
W = (S_intermediate, Σ_sequence, Aux_computation)
```

Where:
- S_intermediate: all intermediate states s₁, ..., s_{n-1}
- Σ_sequence: all inputs σ₀, ..., σ_{n-1}
- Aux_computation: auxiliary values needed for constraint satisfaction (Merkle paths, intermediate arithmetic, etc.)

Public inputs:
```
Pub = (Commit(s₀), Commit(s_n), Obs(τ), Domain)
```

---

## 3. Uniqueness Levels

### Level 1: Semantic Uniqueness (REQUIRED)

```
∀ W₁, W₂ satisfying constraints with same Pub:
  Semantics(W₁) = Semantics(W₂)
```

The semantic execution represented by any valid witness must be identical.

This means: the sequence of formal transitions, the semantic state changes, and the observable effects must be the same regardless of which valid witness is used.

### Level 2: Structural Uniqueness (DESIRED)

```
∀ W₁, W₂ satisfying constraints with same Pub:
  W₁ = W₂
```

Only one witness satisfies the constraints for given public inputs.

This is stronger than Level 1 and may not always be achievable (e.g., different Merkle path representations for same tree).

### Level 3: Computational Uniqueness (IDEAL)

```
∀ W₁, W₂ satisfying constraints with same Pub:
  W₁ = W₂ (bit-for-bit)
```

Strongest form. Requires canonical encoding of all witness components.

---

## 4. Where Uniqueness is Critical

### 4.1 State Transitions (Level 1 REQUIRED, Level 2 DESIRED)

The intermediate states in the witness must represent the same semantic execution.

If two witnesses encode different state sequences but produce the same initial/final commitments:
- The proof is ambiguous about what actually happened
- An adversary can claim one execution occurred while another did
- Observable outputs may be correct while internal state is wrong

**Obligation**: For each intermediate state s_i in the witness, the constraints must uniquely determine s_i given s_{i-1} and σ_{i-1} (follows from AX-1 determinism + constraint completeness).

### 4.2 Input Sequence (Level 1 REQUIRED)

The input sequence must be semantically determined.

If two different input sequences can produce the same state transition:
- The proof does not attest which inputs were processed
- Authorization may be ambiguous (which signer authorized which action?)

**Obligation**: Inputs must be committed in the proof or uniquely determined by state transitions.

### 4.3 Observable Outputs (Level 1 REQUIRED, Level 3 DESIRED)

Observables must be identical across all valid witnesses.

If different witnesses produce different observables for the same proof:
- External consumers receive inconsistent information
- Settlement effects become ambiguous

**Obligation**: Observables must be public inputs or uniquely derived from public inputs.

### 4.4 Authorization Evidence (Level 1 REQUIRED)

The authorization evidence (signatures, permissions) must correspond to the actual semantic payload.

If a witness can substitute different authorization evidence:
- A valid signature on one payload could be used to authorize a different payload
- This is a classic malleability attack

**Obligation**: Authorization constraints must bind signature to exact canonical payload.

---

## 5. Where Equivalence Classes Are Acceptable

### 5.1 Auxiliary Computation Values

Intermediate arithmetic values, Merkle authentication paths, and other auxiliary computation data may have multiple valid representations IF:

- All representations produce the same semantic state
- All representations produce the same commitments
- No representation allows a semantically different execution

Example: Different orderings of Merkle sibling nodes that produce the same root.

**Condition**: Auxiliary equivalence is safe IFF it does not affect any semantic variable.

### 5.2 Encoding Variants

If the encoding scheme allows multiple representations of the same semantic value (e.g., leading zeros, field element representation), equivalence is acceptable IF:

- Canonicalization is enforced before semantic interpretation
- All variants map to the same canonical form
- No variant allows different semantic interpretation

### 5.3 Proof Artifacts

Different valid proofs for the same statement are acceptable (proof non-uniqueness is normal in ZK systems). What matters is witness semantic uniqueness, not proof uniqueness.

---

## 6. Malleability Attack Classes

### MAL-1: State Substitution

Attack: Replace intermediate state s_i with s'_i where s_i ≠ s'_i but both satisfy constraints.

Impact: Proof validates but represents different execution history.

Prevention: Constraints must uniquely determine each s_i from (s_{i-1}, σ_{i-1}).

Detection: Alternate witness search for intermediate states.

### MAL-2: Input Substitution

Attack: Replace input σ_i with σ'_i where both produce valid transitions from s_i.

Impact: Proof validates but represents different input sequence.

Prevention: Inputs must be committed or uniquely determined by (s_i, s_{i+1}).

Detection: Check if multiple inputs can produce same state transition.

**Critical case**: If Apply(s, σ₁) = Apply(s, σ₂) for σ₁ ≠ σ₂, the witness is malleable on inputs. This is acceptable ONLY if σ₁ and σ₂ are semantically equivalent (same canonical form).

### MAL-3: Observable Manipulation

Attack: Produce witness where observables differ from actual execution.

Impact: External consumers receive false information.

Prevention: Observables must be constrained as Obs(s, σ, s') = o, with o as public input.

### MAL-4: Authorization Rebinding

Attack: Use authorization evidence from one input to authorize a different input.

Impact: Unauthorized execution appears authorized.

Prevention: Signature must cover exact canonical payload. Constraint must enforce: Verify(sig, Hash(Canonical(payload))) = true.

### MAL-5: Temporal Reordering

Attack: Reorder witness entries to represent a different execution sequence.

Impact: Causal relationships violated.

Prevention: Strict indexing constraints. Commitment chain linking.

### MAL-6: Cross-Proof Witness Sharing

Attack: Use witness components from one proof in another proof's context.

Impact: Domain separation violated.

Prevention: Domain tags in all witness commitments. Cross-proof witness incompatibility.

---

## 7. Formal Uniqueness Conditions

### Condition U1: Transition Determinism in Constraints

```
∀ (s, σ) constrained in witness:
  The constraints uniquely determine s' = Apply(s, σ)
```

This requires: for each field f of s', there exists a constraint C_f such that C_f(s, σ, s'.f) has exactly one solution for s'.f given (s, σ).

### Condition U2: Input Commitment

```
∀ σ_i in witness:
  σ_i is either a public input OR uniquely determined by (s_i, s_{i+1}) under constraints
```

If neither holds, the witness is malleable on inputs.

### Condition U3: Observable Determination

```
∀ o_i in witness:
  o_i = Obs(s_i, σ_i, s_{i+1}) is enforced by constraints
  AND o_i is a public input or derived from public inputs
```

### Condition U4: Auxiliary Independence

```
∀ aux variables in witness:
  Changing aux does not change any semantic variable (state, input, observable)
```

This must be proven, not assumed.

---

## 8. Verification Protocol

### Step 1: Variable Classification

Classify every witness variable as:
- **Semantic**: directly represents state, input, or observable
- **Auxiliary**: supports computation but does not represent semantic content
- **Derived**: computed from semantic variables

### Step 2: Semantic Variable Uniqueness

For each semantic variable, verify:
- It is uniquely determined by public inputs and prior semantic variables
- No alternate value satisfies all constraints

Method: SAT/SMT analysis with variable relaxation.

### Step 3: Auxiliary Variable Independence

For each auxiliary variable, verify:
- Changing its value does not change any semantic variable
- All valid auxiliary values produce the same semantic outcome

Method: Parameterized constraint analysis.

### Step 4: Adversarial Witness Construction

Attempt to construct:
- Two witnesses with same public inputs but different semantic content
- Witnesses with valid structure but invalid semantic meaning
- Witnesses that satisfy constraints but represent impossible executions

Method: Adversarial fuzzing + symbolic analysis.

---

## 9. Non-Malleability Enforcement

### Enforcement E1: Canonical Witness Form

Define a canonical form for witnesses:
```
CanonicalWitness(W) = (Canonical(S_intermediate), Canonical(Σ_sequence), Canonical(Aux))
```

Require: constraints are satisfied by canonical form if and only if satisfied by original.

### Enforcement E2: Witness Commitment

Include witness commitment in proof:
```
Commit(W) ∈ PublicInputs OR Commit(W) is bound to proof
```

This prevents witness substitution after proof generation.

### Enforcement E3: Semantic Binding Constraints

For each semantic variable v:
```
∃ constraint set C_v such that:
  C_v(Pub, v) has exactly one solution for v
  OR
  All solutions for v are semantically equivalent
```

---

## 10. Relationship to Other Documents

- **PROOF_OBLIGATIONS.md**: LEM-6 (Witness Semantic Uniqueness) is discharged by this analysis
- **UNDERCONSTRAINT_ANALYSIS.md**: Free variables (U1, U2) directly cause witness malleability
- **COUNTEREXAMPLE_CATALOG.md**: CEX-P2 (Witness Semantic Ambiguity) is the primary counterexample
- **CONSTRAINT_COVERAGE_MATRIX.md**: Coverage gaps enable malleability

---

## 11. Closing Statement

Witness uniqueness is not a nice-to-have property.

It is the difference between a proof that says "this specific thing happened" and a proof that says "something consistent with these outputs happened, but we're not sure what."

The first is a guarantee.
The second is a horoscope with math.
