**Verifiable Semantic Execution Layer (VSEL)**

# EDGE CASE ATLAS

## 1. Purpose

This document is a structured taxonomy of edge cases organized by structural class, not a lazy list of "things that might go wrong."

Each edge case family represents a class of inputs, states, or execution patterns that live at the boundary of the system's semantic definition — where invariants are most likely to be insufficient, constraints most likely to be incomplete, and implementations most likely to diverge from specification.

> Edge cases are not exceptions. They are the places where the system's definition of correctness is tested most severely.

---

## 2. Family 1: Canonical/Derived State Boundary

The boundary between canonical state C and derived state D is where inconsistency hides most elegantly.

### EC-1.1: Derived State Computed from Stale Canonical

Scenario: D is computed from C at time t₁, but C is updated at t₂ without recomputing D.
Impact: G_commit violated (D ≠ Derive(C)).
Trigger: Any optimization that caches derived state.
Test: Modify C, check D without explicit recomputation.

### EC-1.2: Canonical State Semantically Invalid but Structurally Valid

Scenario: C passes all structural checks (types, ranges, encoding) but represents an impossible semantic state (e.g., account with negative balance represented as large unsigned integer via overflow).
Impact: State appears valid, invariants hold structurally, but semantic meaning is wrong.
Trigger: Arithmetic overflow/underflow in balance computation.
Test: Construct states at arithmetic boundaries. Verify semantic interpretation.

### EC-1.3: Derived State Correct but Canonical State Corrupted

Scenario: D happens to match Derive(C') for some C' ≠ C, where C is the actual canonical state.
Impact: Commitment verification passes but over wrong canonical state.
Trigger: Hash collision (extremely unlikely but must be modeled).
Test: Verify commitment binding is to actual C, not just any C producing same D.

### EC-1.4: Empty Canonical State

Scenario: C contains no accounts, no storage, no data.
Impact: Is this a valid state? If yes, what invariants hold? If no, is it reachable?
Trigger: System initialization edge case, or complete resource drain.
Test: Construct empty C. Verify all invariants. Verify reachability.

---

## 3. Family 2: Input Semantic Payload vs Authorization

### EC-2.1: Valid Authorization, Semantically Null Payload

Scenario: Input has valid signature but payload is empty or no-op.
Impact: Should this be T_update or T_noop? Authorization cost without semantic effect.
Trigger: User signs empty transaction.
Test: Submit authorized empty payload. Verify classification and resource accounting.

### EC-2.2: Valid Authorization, Semantically Contradictory Payload

Scenario: Input is authorized but payload requests impossible operation (transfer more than balance).
Impact: Must be caught by precondition check, not by authorization.
Trigger: Authorized user attempting invalid operation.
Test: Submit authorized but precondition-failing inputs for each transition class.

### EC-2.3: Authorization Covering Wrong Data

Scenario: Signature is valid but covers different data than the semantic payload.
Impact: Authorization appears valid but does not actually authorize the operation.
Trigger: Signature computed over non-canonical form, or over subset of payload.
Test: Construct inputs where signature covers Canonical(payload) vs payload vs Hash(payload). Verify constraint catches mismatch.

### EC-2.4: Expired or Future Authorization

Scenario: Authorization was valid at time t₁ but is submitted at time t₂ where it's no longer valid (key rotated, permission revoked).
Impact: Temporal authorization validity.
Trigger: Key rotation between signing and submission.
Test: Submit authorization signed with revoked key.

### EC-2.5: Multi-Signer Authorization Partial Validity

Scenario: Multi-sig input where some signatures are valid and some are not.
Impact: Depends on threshold model. Partial authorization may be accepted or rejected.
Trigger: One signer's key compromised or rotated.
Test: Submit multi-sig with various combinations of valid/invalid signatures.

---

## 4. Family 3: Error and No-Op Transitions

### EC-3.1: Error That Preserves State But Changes Metadata

Scenario: Error transition returns to same canonical state but increments nonce or updates metadata.
Impact: Is this a no-op or a state update? Metadata change may affect temporal invariants.
Trigger: Error handling that updates counters.
Test: Verify error transitions produce exactly s or s_error, with explicit metadata handling.

### EC-3.2: Cascading Errors in Batch

Scenario: Batch where first operation fails, causing subsequent operations to also fail.
Impact: Batch result depends on error propagation model.
Trigger: First operation in batch depletes resource needed by subsequent operations.
Test: Construct batches with early failure. Verify cascade behavior matches specification.

### EC-3.3: Error Producing State Indistinguishable from Valid Transition

Scenario: Error transition produces s_error that looks identical to a valid state transition result.
Impact: Cannot distinguish error from success by examining state alone.
Trigger: Error handling that produces "reasonable" state changes.
Test: Verify error transitions produce distinguishable observables.

### EC-3.4: Infinite Error Loop

Scenario: Error state triggers another error on any input, creating an inescapable error cycle.
Impact: Liveness violation (LIVE-1).
Trigger: Error state where all inputs fail preconditions.
Test: From each error state, verify at least one valid transition exists.

---

## 5. Family 4: Batching

### EC-4.1: Order-Dependent Batch

Scenario: Batch [σ₁, σ₂] produces different result than [σ₂, σ₁].
Impact: If batch ordering is not enforced, result is non-deterministic.
Trigger: Operations that modify overlapping state.
Test: For each pair of operation types, verify commutativity or enforce ordering.

### EC-4.2: Batch Where Intermediate State Violates Invariant

Scenario: After σ₁, intermediate state violates invariant, but after σ₂, invariant is restored.
Impact: Should the batch be accepted? Invariant was temporarily violated.
Trigger: Transfer that temporarily overdrafts, followed by deposit.
Test: Construct batches with intermediate invariant violations. Verify batch semantics.

### EC-4.3: Batch of One vs Single Input

Scenario: Batch([σ]) must produce identical result to single σ.
Impact: If batch processing has different code path, results may diverge.
Trigger: Batch wrapper adding overhead or different validation.
Test: Differential testing: Batch([σ]) vs σ for all input types.

### EC-4.4: Maximum Size Batch

Scenario: Batch with maximum allowed operations.
Impact: Resource exhaustion, constraint system size limits, proof generation limits.
Trigger: Adversary submitting maximum-size batch.
Test: Generate maximum batch. Verify processing, constraint generation, and proof generation.

### EC-4.5: Batch with Duplicate Operations

Scenario: Batch containing the same operation twice.
Impact: Should both execute? Is this idempotent or double-execution?
Trigger: Network retry causing duplicate inclusion.
Test: Submit batch with duplicates. Verify behavior matches specification.

### EC-4.6: Batch Atomicity Failure

Scenario: Batch partially executes before system failure.
Impact: If batch is not atomic, partial state update may violate invariants.
Trigger: System crash mid-batch.
Test: Simulate failure at each point in batch execution. Verify rollback or atomic completion.

---

## 6. Family 5: Trace Compression and Proving Aggregation

### EC-5.1: Compression Losing Causal Information

Scenario: Compressed trace preserves state roots but loses ordering between concurrent transitions.
Impact: Causal invariants (T_causal) become uncheckable.
Trigger: Compression that aggregates multiple transitions into single entry.
Test: Compress trace with concurrent transitions. Decompress. Verify causal ordering preserved.

### EC-5.2: Aggregated Proof Hiding Invalid Intermediate

Scenario: Proof aggregation proves initial→final state but does not bind to intermediates.
Impact: Invalid intermediate state goes undetected.
Trigger: Recursive proof that only checks endpoints.
Test: Construct execution with invalid intermediate. Attempt to prove via aggregation.

### EC-5.3: Compression Ratio vs Sufficiency Tradeoff

Scenario: Higher compression loses more semantic information.
Impact: At some compression level, trace becomes insufficient (TRACE_SUFFICIENCY).
Trigger: Aggressive compression for storage/bandwidth optimization.
Test: Compress at various levels. Verify sufficiency conditions at each level.

---

## 7. Family 6: Composition and Cross-Version

### EC-6.1: Cross-System Resource Double-Count

Scenario: Resource exists in system A's state and system B's state simultaneously.
Impact: Total resource exceeds conservation invariant.
Trigger: Cross-system transfer where debit in A and credit in B are not atomic.
Test: Simulate non-atomic cross-system transfer. Verify conservation.

### EC-6.2: Shared State Write Conflict

Scenario: Systems A and B both write to shared state in the same logical step.
Impact: Final shared state depends on write ordering.
Trigger: Concurrent cross-system transitions affecting same shared field.
Test: Simulate concurrent writes. Verify deterministic resolution.

### EC-6.3: Version Mismatch in Composition

Scenario: System A at version v1 composed with System B at version v2, where v1 and v2 have different invariant sets.
Impact: Cross-invariants may not hold across versions.
Trigger: System upgrade without coordinated composition update.
Test: Compose systems at different versions. Verify cross-invariants.

### EC-6.4: Upgrade Invalidating Historical Proofs

Scenario: System upgrade changes constraint system. Historical proofs no longer verify under new verifier.
Impact: Historical execution becomes unverifiable.
Trigger: Constraint system version mismatch.
Test: Generate proof under v1. Upgrade to v2. Attempt verification.

### EC-6.5: Cross-System Authorization Escalation

Scenario: Authorization valid in system A used to authorize action in system B.
Impact: Privilege escalation across system boundaries.
Trigger: Shared authorization model without domain separation.
Test: Use A's authorization token in B's context. Verify rejection.

---

## 8. Family 7: Temporal and Replay

### EC-7.1: Replay of Valid Trace Segment

Scenario: Valid trace segment from epoch E₁ resubmitted in epoch E₂.
Impact: If accepted, state transitions are duplicated.
Trigger: Network replay, adversarial resubmission.
Test: Record valid trace segment. Resubmit. Verify rejection.

### EC-7.2: Slow Accumulation Invariant Violation

Scenario: Each transition introduces tiny invariant drift (e.g., rounding error in conservation). After N transitions, drift exceeds tolerance.
Impact: Temporal invariant T_cons violated after long execution.
Trigger: Floating-point-like arithmetic, fee rounding, precision limits.
Test: Run N=10⁶ transitions with worst-case rounding. Check conservation.

### EC-7.3: Monotonicity Overflow

Scenario: Monotonic counter reaches maximum value.
Impact: Next increment overflows, violating G_mono.
Trigger: Very long-running system.
Test: Set counter to MAX-1. Execute transition. Verify handling.

### EC-7.4: Time-Based Condition at Exact Boundary

Scenario: Time-locked operation where current time equals exact unlock time.
Impact: Is the operation valid at exactly the boundary? Off-by-one in temporal condition.
Trigger: Timestamp exactly matching condition threshold.
Test: Submit time-locked operation at exact boundary. Verify consistent handling.

---

## 9. Family 8: Economically Absurd but Formally Valid

### EC-8.1: Zero-Value Transfer

Scenario: Transfer of zero resources between accounts.
Impact: Formally valid (conservation holds, invariants hold) but economically meaningless. May be used for state bloat or gas griefing.
Trigger: Adversary submitting zero-value operations.
Test: Submit zero-value transfers. Verify handling and resource accounting.

### EC-8.2: Self-Transfer

Scenario: Account transfers resources to itself.
Impact: Formally valid but economically null. May interact unexpectedly with fee model.
Trigger: User or adversary self-transferring.
Test: Submit self-transfers. Verify state change (should be no-op except fees).

### EC-8.3: Dust Accumulation

Scenario: Many tiny transfers creating accounts with negligible balances.
Impact: State bloat. Each account is formally valid but economically worthless.
Trigger: Adversary creating many dust accounts.
Test: Create many minimum-balance accounts. Verify system handles state growth.

### EC-8.4: Fee Exceeding Value

Scenario: Transaction fee exceeds the value being transferred.
Impact: Formally valid (conservation holds) but economically irrational.
Trigger: Small transfers with high fees.
Test: Submit transactions where fee > value. Verify handling.

### EC-8.5: Maximum Value Operations

Scenario: Operations involving maximum representable values.
Impact: Overflow risk, conservation arithmetic at boundaries.
Trigger: Adversary using maximum field values.
Test: Submit operations with MAX values. Verify arithmetic correctness.

---

## 10. Family 9: Cryptographic Edge Cases

### EC-9.1: Domain Tag Collision

Scenario: Two different contexts produce the same domain separation tag.
Impact: Cross-domain proof replay becomes possible.
Trigger: Insufficient entropy in domain tag construction.
Test: Enumerate domain tag construction. Verify uniqueness.

### EC-9.2: Signature Over Empty Message

Scenario: Signature computed over empty payload.
Impact: May be reusable across contexts if domain separation is insufficient.
Trigger: Signing empty canonical form.
Test: Generate signature over empty message. Attempt use in different contexts.

### EC-9.3: Commitment to Empty State

Scenario: Commit(∅) — commitment to empty canonical state.
Impact: If predictable, adversary can forge proofs over empty state.
Trigger: System initialization or complete state drain.
Test: Compute Commit(∅). Verify it's not a special value exploitable elsewhere.

---

## 11. Atlas Maintenance

Each edge case family must be:
- Tested during the corresponding roadmap phase
- Covered by constraints (verified via CONSTRAINT_COVERAGE_MATRIX)
- Addressed by counterexamples (linked to COUNTEREXAMPLE_CATALOG)
- Reviewed during each audit cycle

New edge cases discovered during testing or audit must be added to this atlas.

---

## 12. Closing Statement

Edge cases are not the periphery of the system.

They are the system's immune response test.

A system that handles the center well and the edges poorly is a system that works until it doesn't, and the "until" is always shorter than anyone expects.
