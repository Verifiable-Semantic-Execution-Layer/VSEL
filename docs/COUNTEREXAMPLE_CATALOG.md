**Verifiable Semantic Execution Layer (VSEL)**

# COUNTEREXAMPLE CATALOG

## 1. Purpose

This document defines the explicit space of expected failures.

For every critical property in VSEL, this catalog describes:

* the family of states, inputs, and traces that would destroy the property if found
* the structural shape of the counterexample
* the layer where it would manifest
* the detection method required

> A property without a counterexample target is a prayer, not a guarantee.

This catalog exists so that:
- verification efforts know exactly what they are hunting
- auditors know exactly what to try to construct
- the system's correctness is defined by the non-existence of these artifacts

---

## 2. Counterexample Structure

Each entry follows:

```
CEX-[ID]
Target Property: [which obligation/invariant this destroys]
Shape: [structural description of the counterexample]
Layer: [where it manifests]
Construction Strategy: [how an adversary would attempt to build it]
Detection Method: [how the system should catch it]
Severity: [catastrophic / critical / serious / moderate]
```

---

## 3. State Space Counterexamples

### CEX-S1: Syntactically Valid, Semantically Unreachable State

Target: SAFE-1 (Unreachability of Invalid States)
Shape: State s where ValidState(s) = true but s ∉ Reachable(I, T)
Layer: FSL / EL
Construction: Construct state satisfying all structural predicates P_C, P_D, P_E, P_τ but not reachable from any initial state via any valid transition sequence.
Detection: Reachability analysis via model checking. Enumerate states satisfying ValidState and verify reachability from I.
Severity: Critical — such states may be injected via composition or external manipulation.

Why this matters: If the constraint system accepts proofs over unreachable states, an adversary can prove transitions that never could have happened. The state is "valid" in isolation but has no legitimate history.

---

### CEX-S2: Derived State Inconsistency

Target: DEF-1 (Derived State Functional Dependence), G_commit
Shape: State s where D ≠ Derive(C) but Commit(s) passes verification
Layer: EL / CDL
Construction: Modify D independently of C. Check if any downstream component trusts D without recomputation.
Detection: Enforce D = Derive(C) at every state observation point. Fuzz with inconsistent (C, D) pairs.
Severity: Catastrophic — if derived state is trusted, proofs can validate over phantom state.

---

### CEX-S3: State Encoding Collision

Target: DEF-2 (Canonical Encoding Injectivity)
Shape: s₁ ≠ s₂ but Encode(s₁) = Encode(s₂)
Layer: EL / CDL
Construction: Search for encoding collisions in state serialization. Focus on edge cases: empty vs zero, null vs absent, default values, padding.
Detection: Property-based testing with random state generation. Formal proof of encoding injectivity.
Severity: Catastrophic — collapses distinct states into one, destroying semantic distinction.

---

### CEX-S4: Valid State with Economically Absurd Semantics

Target: Economic Admissibility (ECONOMIC_INVARIANTS.md)
Shape: State s where ValidState(s) ∧ G(s) but ¬EconomicallyValid(s)
Layer: FSL / EL
Construction: Search for states satisfying all structural invariants but violating economic intent.
Detection: Economic invariant predicates. Adversarial state construction.
Severity: Critical — formally correct, economically catastrophic.

This is expanded into a full family below.

---

## 3.1 Economic Counterexample Family

### CEX-ECON1: Zero-Cost Resource Acquisition

Target: E_cost (Non-Zero Acquisition Cost)
Shape: Transition (s, σ, s') where entity gains resources but Cost(σ) = 0
Layer: EL / CDL
Construction: Find transition paths where resources are acquired without payment. Focus on: fee rounding to zero for small amounts, batch operations where per-item fee rounds down, error recovery paths that credit without debit, initialization transitions that grant resources.
Detection: For every transition where ResourceAcquired > 0, verify Cost > 0.
Severity: Catastrophic — enables infinite resource extraction at zero cost.

---

### CEX-ECON2: Infinite Leverage via Rounding

Target: E_leverage (Bounded Leverage)
Shape: State s' where EffectiveLeverage(s', entity) > MaxLeverage(Ω) achieved through rounding exploitation
Layer: EL / CDL
Construction: Construct sequence of small position adjustments where each step's rounding error slightly increases leverage. After N steps, leverage exceeds bound while each individual step appears to preserve the invariant.
Detection: Check EffectiveLeverage after every transition. Verify rounding always rounds conservatively.
Severity: Critical — accumulated rounding can create unbounded exposure.

---

### CEX-ECON3: Fee Extraction via Dust

Target: E_proportionality (Fee Proportionality), G_dust (Bounded Minimum Balance)
Shape: Trace where adversary creates thousands of minimum-balance accounts generating micro-transactions costing less in fees than the state storage cost they impose
Layer: EL
Construction: Create N accounts with minimum balance. Execute micro-transfers. Each is valid, fees paid, conservation holds. But aggregate state bloat cost exceeds aggregate fees.
Detection: Verify Fee(σ) ≥ MinFee including state growth cost. Enforce G_dust.
Severity: Serious — economic denial of service.

---

### CEX-ECON4: Flash Loan Exploitation

Target: TE_flash (Flash Operation Collateral), TE_extraction (Bounded Epoch Extraction)
Shape: Atomic trace (borrow, manipulate_price, trade_at_manipulated_price, repay) where each transition is valid but sequence extracts value
Layer: EL / FSL
Construction: Borrow uncollateralized → move price → trade at manipulated price → repay. Each step preserves conservation. Attacker profits; LPs lose.
Detection: TE_flash: bound uncollateralized exposure at every intermediate state. TE_extraction: bound net extraction per epoch.
Severity: Catastrophic — risk-free value extraction.

---

### CEX-ECON5: Sandwich Attack

Target: TE_sandwich (Anti-Sandwich)
Shape: Trace containing (σ_front, σ_victim, σ_back) where front-runner profits at victim's expense
Layer: EL / FSL
Construction: Insert σ_front before victim (buy, raise price). Victim executes at worse price. Insert σ_back after (sell at inflated price). Each transaction valid. Conservation holds.
Detection: TE_sandwich invariant with causal dependency and profit attribution.
Severity: Critical — systematic value extraction from users.

---

### CEX-ECON6: Price Manipulation via Thin Liquidity

Target: E_slippage, TE_manipulation
Shape: Small trade moves price disproportionately due to low liquidity, enabling profit from price movement
Layer: EL
Construction: In low-liquidity pool, execute trade moving price significantly. Profit in related market.
Detection: E_slippage relative to pool depth. G_liquidity minimum requirements.
Severity: Critical.

---

### CEX-ECON7: Concentration Attack

Target: G_concentration (Bounded Concentration)
Shape: Single entity controls majority of resource via sequence of individually valid acquisitions
Layer: FSL / EL
Construction: Acquire in small increments, each below per-transaction limit. Over time, concentration exceeds bound.
Detection: G_concentration checked at every state.
Severity: Critical — monopolistic control and governance attacks.

---

### CEX-ECON8: Velocity Wash Trading

Target: TE_velocity (Economic Velocity Bounds)
Shape: Resources circulate rapidly between colluding accounts creating artificial volume
Layer: EL
Construction: A₁→A₂→...→Aₙ→A₁ rapidly. Each transfer valid, fees paid. Velocity is artificial.
Detection: TE_velocity bounds on turnover per epoch.
Severity: Serious — manipulates volume-dependent mechanisms.

---

### CEX-ECON9: Cross-System Arbitrage Exploitation

Target: CE_arbitrage (Cross-System Arbitrage Bounds)
Shape: Cross-system transition exploiting price discrepancy for unbounded profit
Layer: CL
Construction: Buy in cheaper system, sell in expensive system, repeat.
Detection: CE_arbitrage invariant bounding per-transaction and per-epoch arbitrage.
Severity: Critical — unbounded extraction at composition boundary.

---

### CEX-ECON10: Economic Contagion

Target: CE_contagion (Economic Contagion Isolation)
Shape: Economic failure in system A propagating to system B through shared obligations
Layer: CL
Construction: System A becomes insolvent. Shared obligations cause B to also become insolvent.
Detection: CE_contagion invariant bounding cross-system impact.
Severity: Catastrophic — cascading economic failure.

---

## 4. Transition Counterexamples

### CEX-T1: Non-Deterministic Transition

Target: AX-1 (Determinism of Apply)
Shape: (s, σ) producing s'₁ ≠ s'₂ on different executions
Layer: EL
Construction: Introduce hidden randomness, timing dependency, or floating-point arithmetic. Test with identical inputs under different execution contexts.
Detection: Replay testing. Execute same (s, σ) N times, compare all outputs byte-for-byte.
Severity: Catastrophic — destroys all proof guarantees.

---

### CEX-T2: Transition Producing Invalid State

Target: AX-2 (Closure of State Space)
Shape: (s, σ) → s' where s' ∉ S
Layer: EL
Construction: Craft inputs that push state fields beyond valid ranges. Focus on overflow, underflow, empty collections, maximum sizes.
Detection: Postcondition validation. Fuzz with extreme inputs.
Severity: Catastrophic.

---

### CEX-T3: Hidden State Mutation

Target: SAFE-3 (No Hidden State Mutation)
Shape: Transition where Diff(s, s') ⊄ AllowedMutations(σ)
Layer: EL
Construction: Examine all fields modified by each transition class. Look for side effects: cache updates, counter increments, log mutations, metadata changes not in the allowed set.
Detection: Field-level diff analysis per transition. Whitelist enforcement.
Severity: Critical — hidden mutations escape constraint coverage.

---

### CEX-T4: Guard Overlap Between Transition Classes

Target: (New) Transition Partitioning
Shape: (s, σ) where Pre_classA(s, σ) ∧ Pre_classB(s, σ) and classA, classB produce different s'
Layer: FSL / STATE_MACHINE
Construction: Find inputs satisfying preconditions of multiple transition classes simultaneously. Check if different classes would produce different results.
Detection: Formal proof of guard disjointness. Model checking for overlapping preconditions.
Severity: Critical — masked non-determinism.

---

### CEX-T5: Error Transition Breaking Invariant

Target: LEM-7 (Error State Invariant Preservation)
Shape: Apply(s, σ_invalid) = s_error where ¬G(s_error)
Layer: EL / FSL
Construction: Craft invalid inputs for each error path. Verify all global invariants hold on resulting error state. Focus on resource conservation during error handling.
Detection: Per-error-path invariant verification.
Severity: Critical.

---

### CEX-T6: Batch Non-Equivalence to Sequential

Target: LEM-9 (Batch Decomposition Equivalence)
Shape: Apply(s, [σ₁, σ₂]) ≠ Apply(Apply(s, σ₁), σ₂)
Layer: EL
Construction: Create batches where intermediate state after σ₁ violates preconditions of σ₂, but batch processing skips intermediate validation. Also: batches where order matters but is not enforced.
Detection: Differential testing: batch vs sequential for all input combinations.
Severity: Critical — batch processing is a common source of semantic divergence.

Specific sub-cases:
- σ₁ depletes resource, σ₂ requires it: batch succeeds, sequential fails
- σ₁ and σ₂ modify same field: order-dependent result
- σ₁ triggers error, σ₂ is valid: batch behavior vs sequential error-then-continue

---

## 5. Invariant Counterexamples

### CEX-I1: Local Invariant Holds, Global Breaks

Target: LEM-1 (Invariant Preservation Under Transition)
Shape: Transition where L(s, σ, s') holds for all local invariants but ∃ G: G(s) ∧ ¬G(s')
Layer: FSL
Construction: Find transitions that satisfy all per-transition checks but accumulate into global violation. Classic example: each transfer preserves local balance but total supply drifts due to rounding.
Detection: Global invariant checking after every transition in model checking.
Severity: Catastrophic.

---

### CEX-I2: Temporal Invariant Violation via Accumulation

Target: T_cons, T_causal, T_no_revert
Shape: Trace τ where ∀ i: L(sᵢ, σᵢ, sᵢ₊₁) but TInv(τ) fails
Layer: FSL
Construction: Long traces where small per-step deviations accumulate. Focus on: rounding errors in conservation, monotonicity violations via overflow, causal ordering violations via concurrent composition.
Detection: Long-trace simulation with temporal invariant monitoring.
Severity: Critical — invisible in short traces.

---

### CEX-I3: Invariant Satisfied by Invalid Execution

Target: Invariant Completeness
Shape: Execution τ where ∀ G: G holds, ∀ L: L holds, ∀ TInv: TInv holds, but τ is semantically invalid
Layer: FSL
Construction: This is the hardest and most important counterexample. It means the invariant set is incomplete. Search for executions that "feel wrong" but satisfy all defined properties. Examples: unauthorized state changes that happen to preserve all balances; transitions that skip authorization but produce valid-looking state.
Detection: Adversarial red-teaming. Semantic review. Economic analysis.
Severity: Catastrophic — the system's definition of correctness is wrong.

---

## 6. Semantic Mapping Counterexamples

### CEX-M1: Mapping Non-Commutativity

Target: LEM-3 (Semantic Mapping Commutativity)
Shape: μ_S(Apply_c(s_c, σ_c)) ≠ Apply_f(μ_S(s_c), μ_Σ(σ_c))
Layer: SIR / EL
Construction: Execute concrete transition, map result. Separately map pre-state and input, apply formal transition. Compare. Focus on: rounding differences, encoding differences, error handling differences, metadata handling.
Detection: Differential execution framework (Phase 2).
Severity: Catastrophic — proof validates wrong semantics.

---

### CEX-M2: Ambiguous State Mapping

Target: Mapping Determinism
Shape: s_c where μ_S(s_c) could be interpreted as s_f₁ or s_f₂
Layer: SIR
Construction: Find concrete states with ambiguous canonical extraction. Focus on: optional fields, default values, encoding variants, type coercions.
Detection: Canonicalization testing. Property: μ_S must be a function, not a relation.
Severity: Critical.

---

### CEX-M3: Auxiliary Data Influencing Semantics

Target: Mapping Principle 3.4 (No Hidden Meaning)
Shape: Two executions with identical (payload, auth) but different aux, producing different semantic outcomes
Layer: EL / SIR
Construction: Vary auxiliary data (proving hints, optimization flags, metadata) and check if semantic outcome changes.
Detection: Witness independence testing.
Severity: Critical — auxiliary data is supposed to be semantically inert.

---

### CEX-M4: Canonicalization Altering Semantics

Target: (New) Canonicalization Semantic Preservation
Shape: σ where Canonical(σ) produces different semantic effect than σ
Layer: SIR / EL
Construction: Find inputs where canonicalization changes semantic payload. Focus on: normalization that truncates, reorders, or reinterprets fields.
Detection: Property: Apply(s, σ) must equal Apply(s, Canonical(σ)) for all semantically equivalent σ.
Severity: Critical.

---

## 7. Constraint Counterexamples

### CEX-C1: Underconstrained Variable

Target: CONST-1
Shape: Witness variable v that can take multiple values without violating any constraint
Layer: CDL
Construction: For each witness variable, attempt to find two valid assignments that differ on v but satisfy all constraints.
Detection: Symbolic analysis. SAT/SMT solving with variable freedom queries.
Severity: Critical — free variables are adversary playgrounds.

---

### CEX-C2: Invalid Trace Satisfying Constraints

Target: LEM-4 (Constraint Soundness)
Shape: τ where SatisfiesConstraints(τ) but ¬ValidTrace(τ)
Layer: CDL
Construction: Adversarial witness generation. Construct semantically invalid executions and check if they satisfy the constraint system. Focus on: transitions not in T, states not in S, traces with wrong ordering.
Detection: Constraint fuzzing with invalid trace injection.
Severity: Catastrophic — the proof system proves lies.

---

### CEX-C3: Valid Trace Failing Constraints

Target: LEM-5 (Constraint Completeness)
Shape: τ where ValidTrace(τ) but ¬SatisfiesConstraints(τ)
Layer: CDL
Construction: Generate valid traces and attempt to prove them. Focus on: edge-case transitions, boundary values, maximum-length traces, error transitions.
Detection: Proof generation testing over valid trace corpus.
Severity: Critical — valid executions become unprovable.

---

### CEX-C4: Branch Constraint Gap

Target: CONST-3 (Branch Completeness)
Shape: Conditional in SIR where one branch is unconstrained
Layer: CDL
Construction: Enumerate all conditionals in SIR. For each, verify both branches produce constraints. Focus on: error branches, early returns, default cases.
Detection: SIR → constraint coverage analysis.
Severity: Critical.

---

### CEX-C5: Structural Equality Masquerading as Semantic

Target: (New) Constraint Semantic Fidelity
Shape: Constraint that enforces structural property (e.g., field format) but not semantic property (e.g., field meaning)
Layer: CDL
Construction: Find constraints that pass with structurally valid but semantically wrong values. Example: balance field constrained to be non-negative but not constrained to reflect actual resource ownership.
Detection: Semantic review of each constraint against its intended invariant.
Severity: Serious.

---

## 8. Proof and Verification Counterexamples

### CEX-P1: Proof Over Partial Trace

Target: PROOF-1 (Full Trace Binding)
Shape: π that validates without committing to all intermediate states
Layer: PL
Construction: Attempt to construct proof binding only to initial and final state, skipping intermediates. Check if verifier accepts.
Detection: Commitment structure analysis. Verify intermediate state commitments are required.
Severity: Catastrophic — allows arbitrary intermediate behavior.

---

### CEX-P2: Witness Semantic Ambiguity

Target: LEM-6 (Witness Semantic Uniqueness)
Shape: Two witnesses W₁, W₂ for same proof π where Semantics(W₁) ≠ Semantics(W₂)
Layer: PL / CDL
Construction: For a given proof, search for alternate witness assignments. Check if they represent different semantic executions but produce same public outputs.
Detection: Alternate witness search. Observable completeness analysis.
Severity: Catastrophic — proof means nothing if it could represent multiple realities.

---

### CEX-P3: Cross-Domain Proof Replay

Target: PROOF-3 (Domain Separation), SAFE-6
Shape: π generated for Domain_A accepted by verifier in Domain_B
Layer: VL
Construction: Take valid proof from one domain, submit to verifier of another. Check domain tag validation.
Detection: Cross-domain proof injection testing.
Severity: Critical.

---

### CEX-P4: Verifier Accepting Invalid Proof

Target: Verification Correctness
Shape: π where ¬ValidTrace(τ) but Verify(π) = true
Layer: VL
Construction: Craft malformed proofs. Mutate valid proofs. Submit proofs with wrong public inputs. Submit proofs with correct structure but invalid cryptographic content.
Detection: Adversarial proof injection. Mutation testing of proof artifacts.
Severity: Catastrophic.

---

## 9. Composition Counterexamples

### CEX-COMP1: Local Validity, Global Invalidity

Target: COMP-3 (Compositional Invariant Preservation)
Shape: Systems A, B both locally valid, but composed state violates G_cross
Layer: CL
Construction: Design two systems that individually preserve all invariants but whose interaction creates resource duplication, state inconsistency, or ordering violation.
Detection: Composition stress testing with adversarial interaction patterns.
Severity: Catastrophic.

---

### CEX-COMP2: Double-Spend Across Domains

Target: COMP-1 (Cross-System Resource Conservation)
Shape: Resource consumed in A but still available in B
Layer: CL
Construction: Execute cross-system transition. Verify resource is properly debited in source and credited in destination. Focus on: timing gaps, partial failures, rollback asymmetry.
Detection: Cross-system resource accounting verification.
Severity: Catastrophic.

---

### CEX-COMP3: Ordering Mismatch Across Systems

Target: Cross-system causal consistency
Shape: System A observes transitions in order (t₁, t₂), System B observes (t₂, t₁)
Layer: CL
Construction: Concurrent cross-system transitions with shared state dependencies. Check if ordering guarantees hold.
Detection: Concurrent composition testing with ordering verification.
Severity: Critical.

---

## 10. Trace Counterexamples

### CEX-TR1: Missing Transition in Trace

Target: T_complete (No Hidden Transitions)
Shape: State change occurs but no trace entry records it
Layer: TE
Construction: Introduce state mutation outside the traced execution pipeline. Check if trace reconstruction detects the gap.
Detection: Compare trace-reconstructed state sequence with actual state sequence.
Severity: Catastrophic — untraced transitions are unverifiable.

---

### CEX-TR2: Trace Commitment Chain Break

Target: Trace Commitment Integrity
Shape: Trace where h_{i+1} ≠ Hash(h_i | Commit(e_i))
Layer: TE
Construction: Modify a trace entry after commitment. Verify chain validation catches it.
Detection: Chain verification. Mutation testing of trace entries.
Severity: Critical.

---

### CEX-TR3: Non-Deterministic Replay

Target: Trace Determinism
Shape: Replay(τ) ≠ τ
Layer: TE / EL
Construction: Replay trace from initial state with recorded inputs. Compare resulting states byte-for-byte. Focus on: environment differences, timestamp handling, randomness sources.
Detection: Replay testing under controlled environment.
Severity: Catastrophic.

---

### CEX-TR4: Trace Compression Losing Causality

Target: (New) Trace Compression Semantic Preservation
Shape: Compressed trace τ_c where Decompress(τ_c) loses causal ordering information
Layer: TE
Construction: Compress trace. Decompress. Verify causal relationships between transitions are preserved. Focus on: concurrent transitions, batched operations, aggregated proofs.
Detection: Causal ordering verification post-decompression.
Severity: Serious.

---

## 11. Temporal Counterexamples

### CEX-TEMP1: Delayed Invariant Failure

Target: Temporal Invariants
Shape: Trace where all invariants hold for first N steps but fail at step N+1 due to accumulated drift
Layer: FSL
Construction: Long-running traces with small per-step deviations. Focus on: precision loss, counter overflow, resource drift, metadata accumulation.
Detection: Extended simulation with invariant monitoring at every step.
Severity: Critical — invisible in bounded model checking.

---

### CEX-TEMP2: Replay Attack

Target: Replay Resistance
Shape: Valid trace segment resubmitted and accepted as new execution
Layer: TE / VL
Construction: Record valid trace segment. Resubmit as new execution. Check if system detects replay.
Detection: Nonce/sequence verification. Domain separation per execution epoch.
Severity: Critical.

---

### CEX-TEMP3: Cross-Version Semantic Drift

Target: (New) Upgrade Semantic Preservation
Shape: Trace valid under version V₁ that becomes invalid under V₂, or vice versa, without explicit migration
Layer: All
Construction: Execute trace under V₁. Upgrade system to V₂. Verify trace validity. Focus on: changed invariants, modified transition rules, altered encoding.
Detection: Cross-version trace validation testing.
Severity: Critical — upgrade paths are invariant graveyards.

---

## 12. Cryptographic Counterexamples

### CEX-CRYPTO1: Commitment Collision

Target: DEF-3, AX-5
Shape: s₁ ≠ s₂ but Commit(s₁) = Commit(s₂)
Layer: All
Construction: Birthday attack on commitment scheme. Focus on: weak hash functions, insufficient domain separation, short commitment lengths.
Detection: Cryptographic analysis. Parameter validation.
Severity: Catastrophic.

---

### CEX-CRYPTO2: Signature Forgery Under PQC

Target: Cryptographic Model
Shape: Valid signature on unauthorized input under quantum adversary
Layer: EL / PL
Construction: Quantum attack on classical signature scheme. Check if hybrid scheme prevents acceptance.
Detection: Hybrid signature verification (both classical and PQC must verify).
Severity: Catastrophic.

---

## 13. Catalog Maintenance

This catalog is a living document.

Every new property added to the system must come with its counterexample family.
Every audit must attempt to construct entries from this catalog.
Every successful construction is a system failure that must be resolved before progression.

> The catalog is complete when every property has a counterexample family, and every counterexample family has been shown to be empty.

---

## 14. Closing Statement

This document exists to make optimism expensive.

Every entry here is a specific way the system could fail while looking correct.

If you cannot construct these counterexamples, good.
If you have not tried, that is not the same thing.
