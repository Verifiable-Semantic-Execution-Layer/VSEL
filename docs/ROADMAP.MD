**Verifiable Semantic Execution Layer (VSEL)**

## 1. Purpose

This roadmap defines the **only acceptable path to production** for VSEL.

It enforces:

* phase-gated progression
* adversarial validation at each step
* formal correctness before integration
* zero tolerance for unresolved ambiguity

Core rule:

> No phase progresses unless it reaches 100% formal, semantic, and adversarial compliance.

---

## 2. Global Execution Rules

1. Every phase is blocked by audit
2. Every audit produces a **formal artifact**
3. Every failure must be:

   * explained
   * fixed
   * re-audited
4. No partial acceptance
5. No “good enough”

---

## 3. Audit Doctrine

Each phase must include a full audit:

* Formal Methods Review
* Formal Verification Validation
* Adversarial Analysis
* Constraint Completeness Check
* Invariant Exhaustiveness Check
* Trace Integrity Check

Each audit produces:

```id="auditdoc"
PHASE_X_AUDIT.md
PHASE_X_FINDINGS.md
PHASE_X_REMEDIATION.md
PHASE_X_COMPLIANCE.md
```

Progression condition:

```id="compliancecond"
All findings resolved AND 100% compliance achieved
```

---

## 4. Phase 0 — Foundations of Truth

### Objective

Define what “correct” even means.

---

### Microphases

#### 0.1 Formal Specification Completion

* finalize state space ( S )
* define inputs ( \Sigma )
* define transitions ( T )
* define observables ( O )

No ambiguity tolerated.

---

#### 0.2 Invariant System Definition

* define all invariants ( G )
* classify (local/global/temporal)
* prove non-contradiction

---

#### 0.3 Semantic Mapping Definition

* define ( \mu_S, \mu_\Sigma )
* ensure totality and determinism

---

#### 0.4 State Machine Finalization

* define transition graph
* validate reachability
* eliminate undefined states

---

### Audit (Phase 0)

Attack goals:

* find undefined behavior
* find contradictory invariants
* find incomplete mappings

Failure here = system is conceptually invalid.

---

## 5. Phase 1 — Execution Ground Truth

### Objective

Ensure execution matches semantics exactly.

---

### Microphases

#### 1.1 Execution Engine Implementation

* deterministic execution
* strict pipeline enforcement

---

#### 1.2 Trace Model Implementation

* full trace capture
* canonical encoding
* hash chaining

---

#### 1.3 Replay System

* reconstruct execution from trace
* enforce determinism

---

### Audit (Phase 1)

Attack goals:

* non-deterministic execution
* hidden state mutation
* incomplete trace capture

If replay fails even once, phase fails.

---

## 6. Phase 2 — Semantic Alignment

### Objective

Ensure implementation equals formal model.

---

### Microphases

#### 2.1 Mapping Enforcement Layer

* implement ( \mu_S, \mu_\Sigma )
* enforce mapping consistency

---

#### 2.2 Differential Execution Framework

* run implementation vs formal model
* detect divergence

---

#### 2.3 Canonicalization Enforcement

* normalize all inputs and states

---

### Audit (Phase 2)

Attack goals:

* semantic drift
* mapping ambiguity
* inconsistent outputs

Any mismatch = immediate rejection.

---

## 7. Phase 3 — Constraint Integrity

### Objective

Encode semantics into constraints without loss.

---

### Microphases

#### 3.1 Constraint Generator

* derive constraints from SIR
* eliminate manual constraints

---

#### 3.2 Constraint Coverage Validation

* ensure full transition coverage

---

#### 3.3 Constraint Soundness Testing

* verify no invalid execution satisfies constraints

---

### Audit (Phase 3)

Attack goals:

* underconstrained variables
* missing constraints
* satisfiable invalid traces

If any invalid trace satisfies constraints, restart phase.

---

## 8. Phase 4 — Proof System Binding

### Objective

Bind execution truth to cryptographic proof.

---

### Microphases

#### 4.1 Proof Construction

* bind proof to full trace
* enforce witness uniqueness

---

#### 4.2 Public Input Definition

* define minimal, sufficient inputs

---

#### 4.3 Domain Separation Enforcement

* prevent cross-proof reuse

---

### Audit (Phase 4)

Attack goals:

* proof reuse
* ambiguous witness
* partial trace proof

If proof can validate incorrect trace, phase fails.

---

## 9. Phase 5 — Verification Authority

### Objective

Ensure verifier enforces correctness completely.

---

### Microphases

#### 5.1 Verifier Implementation

* strict validation pipeline

---

#### 5.2 Verification Completeness

* verify all constraints
* verify commitments
* verify invariants

---

#### 5.3 Failure Handling

* reject invalid proofs deterministically

---

### Audit (Phase 5)

Attack goals:

* verifier shortcuts
* partial validation
* acceptance of invalid proofs

Verifier must be adversarial by design.

---

## 10. Phase 6 — Composition Survival

### Objective

Ensure correctness survives interaction.

---

### Microphases

#### 6.1 Cross-System State Model

* define shared state

---

#### 6.2 Cross-Invariant Definition

* enforce global constraints

---

#### 6.3 Cross-Trace Composition

* merge traces correctly

---

### Audit (Phase 6)

Attack goals:

* cross-system inconsistency
* invariant break across boundaries
* ordering mismatch

Local correctness is irrelevant if global correctness fails.

---

## 11. Phase 7 — Cryptographic Resilience

### Objective

Ensure long-term security.

---

### Microphases

#### 7.1 Hybrid Cryptography Integration

* classical + PQC

---

#### 7.2 Key Lifecycle Implementation

* generation, rotation, revocation

---

#### 7.3 Commitment Integrity

* enforce collision resistance

---

### Audit (Phase 7)

Attack goals:

* key compromise
* signature forgery
* proof forgery under PQC assumptions

---

## 12. Phase 8 — Temporal Robustness

### Objective

Ensure correctness holds over time.

---

### Microphases

#### 8.1 Long Trace Simulation

* extended execution

---

#### 8.2 Temporal Invariant Enforcement

* sequence-based constraints

---

#### 8.3 Replay Resistance

* prevent reuse attacks

---

### Audit (Phase 8)

Attack goals:

* delayed invariant failure
* replay exploits
* time-based inconsistencies

---

## 13. Phase 9 — System Hardening

### Objective

Prepare system for hostile environment.

---

### Microphases

#### 9.1 Full-System Fuzzing

* all inputs
* all states

---

#### 9.2 Adversarial Scenario Simulation

* worst-case execution

---

#### 9.3 Failure Recovery Testing

* deterministic recovery

---

### Audit (Phase 9)

Attack goals:

* emergent failures
* undefined behavior
* cascading errors

---

## 14. Phase 10 — Pre-Production Gate

### Objective

Final validation.

---

### Requirements

* all phases passed
* all audits resolved
* zero unresolved findings

---

### Final Audit

Full-system adversarial audit:

* semantic correctness
* cryptographic integrity
* compositional validity
* temporal robustness

---

## 15. Deliverables per Phase

Each phase must produce:

* formal artifacts
* test results
* audit reports
* remediation documentation
* compliance certification

---

## 16. Non-Negotiable Rule

If any phase fails:

* rollback
* fix
* re-audit
* re-certify

No exceptions.

---

## 17. Closing Statement

This roadmap is intentionally brutal.

It is designed so that:

* weak assumptions fail early
* incomplete thinking is exposed
* correctness is enforced, not assumed

---

## 18. v1.1 — Circuit-Level Recursive Composition

### Objective

Replace semantic (SHA3-256 hash-based) proof composition with circuit-level recursion, so that composed proofs carry cryptographic evidence that each inner proof was independently valid — not just hash-chained.

### Background

In v1.0, `compose_binary()` in `plonky3_backend.rs` assembles composed proofs using SHA3-256 hashing of inner proofs' FRI commitments. The `RecursiveVerifierAir` struct exists in `recursive_air.rs` with correct AIR constraints and 33 passing unit tests, but it is assigned to `_recursive_air` (unused) in the composition pipeline. See `docs/PROOF_LAYER.md` §Composition Architecture Status for the full v1.0 architecture description and security analysis.

### Integration Plan

#### 18.1 Replace Hash Composition with Recursive Proving

* Replace SHA3-256 hash composition in `compose_binary()` with `p3_uni_stark::prove()` over `RecursiveVerifierAir`
* The outer STARK proof encodes `Verify(π_inner)` as AIR constraints, so the verifier cryptographically enforces the recursive trust chain instead of relying on runtime hash checks
* Remove the `_recursive_air` dead assignment and wire `RecursiveVerifierAir` into the proving call

#### 18.2 Execution Trace Generation for Recursive Verifier

* Generate the execution trace for the recursive verifier from inner proof data:
  * **FRI commitments → Merkle path witness columns**: encode each Merkle authentication path as witness rows, with path indices, sibling hashes, and root commitments as column values
  * **Query responses → FRI folding witness columns**: encode FRI query-response pairs as witness rows, with evaluation points, folded values, and consistency checks as column values
* The trace must be deterministic given the inner proof — no external randomness in witness generation

#### 18.3 Composed Proof Verification

* Verify composed proofs using `p3_uni_stark::verify()` with the recursive verifier AIR
* The verifier checks that the outer proof satisfies `RecursiveVerifierAir` constraints, which encode the inner proof's FRI verification as polynomial identities
* This eliminates the trust assumption that the composer honestly ran the inner prover — the STARK proof itself is the evidence

#### 18.4 Inline Poseidon2 as Degree-7 AIR Constraints

* Inline Poseidon2 hash evaluation as degree-7 AIR constraints within `RecursiveVerifierAir` for defense-in-depth (addressing audit Finding 5)
* This ensures the Merkle path verification inside the recursive circuit uses the same hash function as the outer STARK, preventing hash-function mismatch attacks
* Degree-7 constraints are compatible with the Plonky3 AIR framework's constraint degree budget

### Estimated Effort

2–4 weeks engineering time, covering:

* Witness generation from inner proof data (~1 week)
* Integration of `RecursiveVerifierAir` into `compose_binary()` proving path (~1 week)
* Inline Poseidon2 constraint implementation and testing (~0.5–1 week)
* End-to-end integration testing and benchmark validation (~0.5–1 week)

### Dependencies

* **Plonky3 recursive proving API stability**: The integration depends on `p3_uni_stark::prove()` and `p3_uni_stark::verify()` maintaining their current interface. If the Plonky3 team introduces breaking changes to the proving API or AIR trait bounds, the integration timeline extends.
* **v1.0 completion**: All v1.0 documentation, fuzzing, and benchmark tasks must be complete before v1.1 work begins.

### Audit Requirement

Circuit-level recursion introduces new attack surface:

* Underconstrained witness columns in the recursive verifier trace
* Degree overflow in Poseidon2 inline constraints
* Soundness loss from incorrect FRI folding encoding

A dedicated Phase 6.1 audit is required before v1.1 ships, with attack goals targeting recursive proof forgery, witness malleability in the recursive trace, and Poseidon2 constraint completeness.
