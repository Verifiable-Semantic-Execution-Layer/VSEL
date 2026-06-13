**Verifiable Semantic Execution Layer (VSEL)**

## 1. Purpose

This document defines the responsibilities, guarantees, and behavior of the verification layer in VSEL.

The verification layer is responsible for:

* validating proofs
* enforcing semantic correctness guarantees only on the strict final-acceptance path
* binding proofs to actual system state and context

The core requirement is:

> If the strict verifier emits `FullyVerified`, the corresponding execution must be semantically valid under the formal specification.

`CryptographicallyConsistent` is not an acceptance result for semantic validity.

---

## 2. Verification Objective

Given:

* proof ( \pi )
* public inputs ( Pub )
* witness ( W )
* constraint system ( C )
* complete execution trace ( \tau )
* authoritative semantic evidence ( E_{sem} )

Verification must ensure:

[
StrictTraceVerify(\pi, Pub, W, C, \tau, E_{sem}) = FullyVerified \Rightarrow ValidTrace(\tau)
]

Where ( \tau ) is the complete execution trace supplied to the final semantic verifier. Commitments alone are not sufficient for deterministic semantic replay. The Lean-backed semantic path checks a canonical semantic certificate with `lake env lean --run VSEL/Checker/Main.lean`; compiling the Lean library is necessary evidence of spec elaboration, but not sufficient evidence of trace validity.

The verifier does not trust:

* the prover
* the execution layer
* the constraint system implicitly

It only trusts:

* cryptographic assumptions
* formally defined verification logic
* executable semantic-certificate checking bound to the same proof context

For STARK claims, proof generation and verification must both use a concrete backend-backed path: `BackendProver<B>` emits backend-native proof bytes and `BackendCryptographicVerifier<B>` verifies those bytes against the same backend id and canonical constraint commitment. `GenericProver<HashBackend>` and `GenericVerifier<HashBackend>` remain legacy cryptographic-consistency paths and cannot satisfy STARK final acceptance by metadata relabeling. Cairo/STARK artifacts are accepted only through `CairoStarkBackend<A>` with a concrete `cairo-stark/<adapter-id>` backend id. The VCAI/v1 artifact and adapter certificate must bind verifier version/hash, canonical Cairo source-manifest hash, Sierra hash, CASM hash, executable program hash, Cairo semantic-binding report hash, Cairo trace hash, public input hash, constraint commitment, statement hash, proof hash, and verifier transcript. The Lean semantic certificate requires that `cairo_source_manifest_hash` equals the Cairo program commitment, that `cairo_semantic_binding_hash` equals the native verifier certificate value, and that both `cairo:source_manifest_binding` and `cairo:semantic_binding_report_binding` are discharged. The native verifier command must also emit a `VSEL_CAIRO_NATIVE_CONTEXT_ATTESTATION_V1` binding those statement fields after native acceptance; a raw native verifier that ignores VSEL environment fields is not sufficient evidence. Bare `cairo-stark` and legacy textual envelopes are invalid. The opt-in `cairo-stark-backend` feature exposes fail-closed Stone/Stwo/Scarb pinned command adapter constructors only after configured prover/verifier commands match their pinned version and SHA3-256 digests; missing native commands, digest mismatch, context-attestation drift, certificate version drift, and certificate verifier-binary drift are verification blockers, not skipped tests or mock acceptance.

---

## 3. Verification Inputs

The verifier operates on:

[
Inputs = (\pi, Pub, W, C, E_{sem}, Context)
]

Where:

* ( \pi ): proof object
* ( Pub ): public inputs
* ( W ): witness bound to the proof witness commitment
* ( C ): constraint system bound to the proof constraint commitment
* ( E_{sem} ): executable or mechanized semantic evidence
* ( Context ): system-level parameters

---

### 3.1 Public Inputs

Must include:

* initial state commitment
* final state commitment
* observable outputs
* domain identifier

Optional:

* trace length
* execution metadata

---

### 3.2 Context

Defines:

* system version
* constraint system version
* verification parameters
* domain separation values

Verification must fail if context mismatch occurs.

---

## 4. Verification Procedure

The verification process is strictly defined.

---

### Step 1: Domain Validation

[
Domain(Pub) = ExpectedDomain(Context)
]

Prevents:

* cross-system replay
* proof reuse

---

### Step 2: Structural Validation

Check:

* proof format
* encoding correctness
* parameter consistency

Reject malformed proofs immediately.

---

### Step 3: Commitment Validation

Ensure:

[
root_{init}, root_{final} \in ValidCommitments
]

Optional:

* check against known state
* verify chain linkage

---

### Step 4: Cryptographic Verification

[
Verify_{crypto}(\pi, Pub) = true
]

Includes:

* polynomial commitments
* query checks
* consistency checks

---

### Step 5: Semantic Binding Validation

Ensure that:

* public inputs correspond to semantic observables
* state commitments correspond to valid states

In the strict path this step contributes to:

[
StrictTraceVerify(\pi, Pub, W, C, \tau, E_{sem}) \Rightarrow ValidTrace(\tau)
]

It is not satisfied by:

[
Verify_{crypto}(\pi, Pub) \Rightarrow SatisfiesConstraints(W, C)
]

---

### Step 6: Invariant Enforcement

If invariants are partially externalized:

* verify invariant commitments
* check invariant proofs

---

### Step 7: Final Acceptance

[
FullyVerified(\pi, Pub, W, C, \tau, E_{sem}) \iff \text{all trace-strict checks pass}
]

---

## 5. Verification Guarantees

If a proof is `FullyVerified`, the verifier guarantees:

* execution trace is valid
* invariants are preserved
* state transitions are correct
* observables are accurate

If any of these are not guaranteed, verification must return a non-final status.

---

## 6. Stateless vs Stateful Verification

### 6.1 Stateless Verification

Verifier checks:

* proof validity
* internal consistency

Does not track system state.

Risk:

* cannot detect invalid state transitions across proofs

---

### 6.2 Stateful Verification

Verifier maintains:

* latest state commitment
* trace continuity

Checks:

[
root_{prev} = root_{expected}
]

Provides stronger guarantees.

---

## 7. Verification Modes

### 7.1 Full Verification

* full proof validation
* invariant enforcement
* trace consistency

---

### 7.2 Light Verification

* partial checks
* optimized performance

Must explicitly define reduced guarantees.

---

### 7.3 Recursive Verification

Verifier checks proofs that include verification of prior proofs.

Ensures:

* scalability
* composability

---

## 8. Cross-Layer Validation

### 8.1 Proof ↔ Constraints

[
StrictTraceVerify(\pi, Pub, W, C, \tau, E_{sem}) \Rightarrow SatisfiesConstraints(W, C)
]

---

### 8.2 Constraints ↔ Semantics

[
SatisfiesConstraints(W, C) \land DeterministicReplay(\tau) \land Authoritative(E_{sem}) \Rightarrow ValidTrace(\tau)
]

---

### 8.3 Combined Guarantee

[
StrictTraceVerify(\pi, Pub, W, C, \tau, E_{sem}) \Rightarrow ValidTrace(\tau)
]

This chain must hold end-to-end.

---

## 9. Failure Modes

### 9.1 Partial Verification

Verifier skips required checks.

---

### 9.2 Weak Binding

Proof not fully bound to public inputs.

---

### 9.3 Context Mismatch

Proof verified under wrong parameters.

---

### 9.4 Replay Acceptance

Proof reused across domains.

---

### 9.5 State Desynchronization

Verifier accepts invalid state transitions.

---

### 9.6 Constraint-Semantic Drift

Verifier accepts proof that satisfies constraints but violates semantics.

This is the most dangerous failure mode.

---

## 10. Adversarial Considerations

The verifier must assume:

* prover is malicious
* inputs may be adversarial
* proofs may be malformed or crafted

Verification must be:

* deterministic
* complete
* strict

No “best effort” validation.

---

## 11. Minimal Correctness Condition

A verifier is correct if:

[
FullyVerified(\pi, Pub, W, C, \tau, E_{sem}) \Rightarrow ValidTrace(\tau)
]

If there exists:

[
\pi \text{ such that } FullyVerified(\pi, Pub, W, C, \tau, E_{sem}) \land \neg ValidTrace(\tau)
]

then the verifier is broken.

---

## 12. Performance Constraints

Verification must balance:

* computational cost
* security guarantees

Optimizations must not weaken:

* semantic binding
* invariant enforcement

---

## 13. Upgrade and Versioning

Verification must enforce:

* version compatibility
* explicit upgrades

Old proofs must not be accepted under new semantics unless explicitly allowed.

---

## 14. Observability

Verification outcomes must be:

* explicit (accept/reject)
* auditable
* reproducible

Optional:

* proof logs
* verification traces

---

## 15. Closing Statement

The verifier is the final authority.

If it accepts something invalid, the system is broken, no matter how elegant the proof system or how rigorous the specification.

VSEL requires that verification enforces:

> semantic correctness, not just cryptographic validity.
