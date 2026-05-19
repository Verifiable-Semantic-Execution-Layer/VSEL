# VSEL Semantic Intent Adversarial Testing

## Stage 3: Semantic Gap Attack Surface Analysis

### Document Purpose

This document enumerates adversarial attack vectors targeting the semantic intent model of VSEL. The fundamental thesis is that **correct execution does not imply correct intent**, and **valid proofs do not imply semantic faithfulness**.

The semantic gap between specification and implementation represents the primary attack surface for sophisticated adversaries who understand that cryptographic soundness is worthless when the underlying semantics are ambiguous, incomplete, or misaligned with protocol intent.

This audit targets the seven-way verification boundary:

```
What the code did
    ↕
What the protocol intended
    ↕
What the policy allowed
    ↕
What the invariant required
    ↕
What the trace recorded
    ↕
What the verifier checked
    ↕
What the proof actually proved
```

Any divergence between these seven interpretations constitutes a semantic vulnerability exploitable by adversaries who understand that verification theater is more profitable than cryptographic breakage.

---

## Attack Taxonomy

The following ten attack classes represent systematic adversarial strategies against semantic preservation in VSEL. Each attack demonstrates how execution correctness, proof validity, and specification compliance can coexist with semantic failure.

---

## Attack 1: Execution Success with Semantic Failure

### Title
**Phantom Success: When Code Executes Correctly but Implements Wrong Intent**

### Description

This attack exploits the fundamental confusion between operational success and semantic correctness. The concrete execution layer produces a successful transition (no runtime errors, valid state transition, proof generation succeeds), but the resulting state does not correspond to the intended protocol semantics.

The attack succeeds when implementation details diverge from specification intent in ways that preserve local invariants while violating global protocol meaning.

### Preconditions

1. Implementation layer contains behavioral logic not fully captured in formal specification
2. Formal invariants are insufficiently strong to enforce intended semantics
3. Proof system validates structural correctness but not intent preservation
4. Semantic mapping μ_T allows multiple formal interpretations of the same concrete execution

### Attack Path

1. **Adversary identifies underspecified transition**: Finds T ∈ ConcreteTransitions where Apply_c(s_c, σ_c) = s'_c produces valid state, but multiple μ_T interpretations exist.

2. **Adversary selects non-intended interpretation**: Chooses formal interpretation μ'_T ≠ intended μ_T that:
   - Satisfies all encoded constraints
   - Passes invariant checks
   - Produces valid proof π
   - Violates protocol intent I

3. **Execution proceeds with semantic substitution**: Concrete execution produces valid trace τ_c where:
   ```
   ValidConcreteTrace(τ_c) = true
   ValidTrace(μ_T(τ_c)) = true
   IntendedBehavior(μ_T(τ_c)) = false
   ```

4. **Proof binds to wrong semantics**: Generated proof π attests to execution validity under formal model, but formal model does not capture intent.

### Broken Assumption

The assumption that `ValidConcreteTrace ∧ ValidTrace(μ(τ))` implies semantic correctness. This ignores the possibility that both validity conditions hold for the wrong semantic interpretation.

### Expected Failure

System accepts execution that satisfies all technical validity conditions while violating protocol intent. Adversary achieves semantically incorrect outcome with full proof of "correctness."

### Severity
**CRITICAL** — This attack renders the entire verification stack meaningless by separating proof from intent.

### Mitigation

1. **Intent-Aware Specification**: Extend formal specification to explicitly encode intent predicates:
   ```
   IntentPreserved(s, σ, s') ≡ IntendedOutcome(s, σ) = s'
   ```

2. **Differential Semantic Testing**: For each concrete transition, verify against multiple semantic interpretations and reject ambiguous cases.

3. **Intent Witness Requirements**: Require explicit intent witnesses in proofs:
   ```
   Verify(π_intent) ∧ Verify(π_execution) ⟹ Accept
   ```

4. **Semantic Mapping Uniqueness**: Enforce that μ_T is injective — no two distinct formal interpretations map from the same concrete trace.

### Suggested Regression Test

```rust
#[test]
fn test_execution_intent_alignment() {
    // Generate all valid concrete transitions
    for (s_c, sigma_c, s_prime_c) in valid_concrete_transitions() {
        // Map to formal semantics
        let formal_trace = semantic_map_trace(s_c, sigma_c, s_prime_c);
        
        // Check against intent oracle
        let intent_satisfied = check_intent_oracle(s_c, sigma_c, s_prime_c);
        
        // This should fail if semantic mapping is ambiguous
        assert!(intent_satisfied, 
            "Transition satisfies formal validity but violates intent");
        
        // Verify uniqueness: no alternative interpretation exists
        let alternative_interpretations = 
            find_alternative_semantic_mappings(s_c, sigma_c, s_prime_c);
        assert_eq!(alternative_interpretations.len(), 0,
            "Multiple semantic interpretations for same concrete trace");
    }
}
```

---

## Attack 2: Policy-Permitted Invariant Violation

### Title
**Policy Override: When Governance Permits What Invariants Forbid**

### Description

Governance mechanisms in distributed systems frequently evolve faster than formal specifications. This attack exploits temporal divergence between:
- Policy commitments approved through social consensus (voting, multisig, etc.)
- Protocol invariants encoded in formal specification
- Constraint systems enforcing those invariants

When a policy change is ratified that conflicts with embedded invariants, the system enters a paradox state where socially-approved behavior is technically forbidden, or where invariant enforcement is bypassed through "emergency" governance paths.

### Preconditions

1. Policy approval mechanism exists outside formal specification (social consensus)
2. Invariants are hardcoded in constraints or formal proofs
3. Policy updates can be committed without corresponding invariant updates
4. Emergency governance paths exist with elevated privileges

### Attack Path

1. **Adversary gains policy influence**: Controls sufficient voting power, multisig keys, or governance tokens to approve policy changes.

2. **Adversary proposes policy violating invariant**: Proposes policy P_new where:
   ```
   PolicyApproved(P_new) = true
   ∃ s: InvariantViolated(s) under P_new
   ```

3. **Policy committed without invariant update**: Governance system commits P_new to policy registry, but:
   - Formal specification still requires old invariants
   - Constraint system still enforces old invariants
   - OR: Emergency path bypasses invariant checks

4. **Execution proceeds under conflicting regimes**:
   ```
   PolicyAllows(σ) = true (governance)
   InvariantRequires(s, σ, s') = false (specification)
   ConstraintEnforces(s, σ) = false (if emergency)
   ```

5. **Invariant violation with social legitimacy**: Resulting state violates invariants but is "governance-approved."

### Broken Assumption

The assumption that governance and formal specification are consistent. This ignores the reality that governance is social and specifications are technical — they can and do diverge.

### Expected Failure

Socially-approved execution violates formal invariants, creating:
- Forks between validator subsets (some enforce invariants, some follow policy)
- Valid proofs of invalid states (proof attests to execution, not invariant preservation)
- Economic attacks exploiting the divergence

### Severity
**HIGH** — Creates fundamental contradiction in system correctness definition.

### Mitigation

1. **Invariant-Governance Binding**: Require that policy changes include corresponding invariant updates:
   ```
   CommitPolicy(P) requires ∃ I': InvariantUpdate(I, I', P)
   ```

2. **Specification-First Governance**: Governance proposals must include formal proof of invariant preservation:
   ```
   PolicyProposal(P) includes Proof(∀s: Invariants(s) ⟹ Invariants(ApplyPolicy(P, s)))
   ```

3. **Emergency Path Constraints**: Emergency governance paths cannot bypass economic or safety invariants, only operational ones.

4. **Invariant Registry Authority**: Separate invariant registry with higher threshold for modification than operational policy.

### Suggested Regression Test

```rust
#[test]
fn test_policy_invariant_consistency() {
    let policy_space = generate_all_possible_policies();
    
    for policy in policy_space {
        // Check policy against all invariants
        let violations = check_policy_against_invariants(&policy);
        
        // Policy should either:
        // 1. Satisfy all invariants, OR
        // 2. Include explicit invariant updates
        if !violations.is_empty() {
            assert!(policy.includes_invariant_updates(),
                "Policy violates invariants without updating them: {:?}", 
                violations);
            
            // Verify updates are sufficient
            for invariant in &violations {
                assert!(policy.updates_sufficient(invariant),
                    "Policy claims to update invariant but insufficient");
            }
        }
    }
}
```

---

## Attack 3: Technically True but Semantically Vacuous Invariants

### Title
**Vacuous Truth: Invariants That Hold Because They Mean Nothing**

### Description

Formal verification systems are vulnerable to vacuous satisfaction — properties that are technically true because they are too weak to exclude any behavior, or because their preconditions are never satisfiable.

This attack exploits the gap between "provably true invariant" and "meaningful security guarantee." An adversary can satisfy the letter of verification while violating its spirit by ensuring that invariants are technically preserved but semantically empty.

### Preconditions

1. Invariants are formally verified but not semantically validated
2. Invariant definitions contain underspecified predicates
3. Verification focuses on proof discharge rather than property meaning
4. Test coverage does not include adversarial semantic analysis

### Attack Path

1. **Adversary analyzes invariant strength**: Reviews invariants I = {G₁, G₂, ..., Gₙ} to identify weak or vacuous properties.

2. **Adversary identifies vacuous invariant**: Finds G_vacuous where:
   ```
   ∀s: G_vacuous(s) = true (trivially satisfied)
   OR
   {s : G_vacuous(s)} = S (all states satisfy it)
   OR
   Precondition(G_vacuous) is unsatisfiable
   ```

3. **Adversary constructs semantically invalid but invariant-satisfying execution**: Creates trace τ where:
   ```
   ∀G ∈ Invariants: G(τ) = true
   SemanticallyInvalid(τ) = true
   ```

4. **Proof validates vacuously**: Generates proof π where Verify(π) = true because all invariants are satisfied.

5. **System accepts semantically invalid execution**: Verification succeeds, attack succeeds.

### Broken Assumption

The assumption that verified invariants imply semantic security. This ignores the possibility of vacuous, weak, or misaligned invariants.

### Expected Failure

Formal verification provides false confidence. System is "provably secure" against meaningless threats while remaining vulnerable to real attacks.

### Severity
**CRITICAL** — Undermines entire verification methodology.

### Mitigation

1. **Invariant Semantic Validation**: For each invariant, require:
   ```
   Meaningful(I) ≡ ∃s: ¬I(s) (invariant excludes some states)
   ∧ ∃s: I(s) (invariant is satisfiable)
   ∧ I captures security-relevant property
   ```

2. **Adversarial Invariant Testing**: Attempt to construct semantically invalid executions that satisfy all invariants (this document's purpose).

3. **Invariant Strength Metrics**: Quantify invariant strength:
   ```
   Strength(I) = |{s : ¬I(s)}| / |S|
   ```
   Reject invariants with strength below threshold.

4. **Semantic Witness Requirements**: Require witnesses showing invariants exclude real attack scenarios.

### Suggested Regression Test

```rust
#[test]
fn test_invariant_semantic_strength() {
    for invariant in &system_invariants {
        // Check invariant is satisfiable
        let satisfying_states = find_satisfying_states(invariant);
        assert!(!satisfying_states.is_empty(),
            "Invariant {} is unsatisfiable (contradiction)", invariant.name);
        
        // Check invariant excludes some states
        let violating_states = find_violating_states(invariant);
        assert!(!violating_states.is_empty(),
            "Invariant {} is vacuously true (excludes nothing)", invariant.name);
        
        // Check invariant excludes semantically invalid states
        let semantic_invalid_satisfying = semantic_invalid_states()
            .intersection(&satisfying_states);
        assert!(semantic_invalid_satisfying.is_empty(),
            "Invariant {} permits semantically invalid states", invariant.name);
        
        // Calculate and verify strength
        let strength = calculate_invariant_strength(invariant);
        assert!(strength >= MIN_INVARIANT_STRENGTH,
            "Invariant {} too weak: strength {}", invariant.name, strength);
    }
}
```

---

## Attack 4: Incomplete Semantic Mapping

### Title
**Mapping Shadows: When Concrete Behavior Escapes Formal Model**

### Description

The semantic mapping layer (μ_S, μ_Σ, μ_T) translates between concrete execution and formal semantics. This attack exploits incompleteness in this mapping — concrete behaviors that are accepted by the execution layer but fall outside the domain of the semantic mapping functions.

When such behaviors occur, the system has no formal interpretation for them, creating a semantic shadow where execution proceeds without specification coverage.

### Preconditions

1. Concrete execution layer has code paths not covered by semantic mapping
2. Mapping functions μ are partial (not total over S_c × Σ_c)
3. Execution accepts inputs where μ_Σ is undefined
4. Constraint system does not enforce totality of semantic mapping

### Attack Path

1. **Adversary maps semantic mapping coverage**: Identifies concrete inputs σ_c where:
   ```
   Defined(μ_Σ(σ_c)) = false
   ExecutionAccepts(σ_c) = true
   ```

2. **Adversary constructs unmapped execution**: Creates trace τ_c containing transitions where μ_T is undefined.

3. **Execution proceeds in semantic shadow**: System executes but:
   ```
   Apply_c(s_c, σ_c) = s'_c (valid concrete transition)
   μ_T(s_c, σ_c, s'_c) = ⊥ (undefined)
   ```

4. **Proof system handles undefined case incorrectly**: Either:
   - Rejects valid execution (liveness failure), OR
   - Accepts execution without semantic validation (safety failure), OR
   - Maps to arbitrary formal state (correctness failure)

5. **System enters undefined semantic territory**: Behavior is accepted but not covered by formal model, allowing arbitrary semantic violations.

### Broken Assumption

The assumption that AcceptedConcreteArtifact ⊆ Domain(μ). This assumes semantic mapping covers all accepted behavior.

### Expected Failure

Accepted executions with no formal meaning, allowing any semantic property to be violated without detection.

### Severity
**CRITICAL** — Creates execution outside trusted compute base.

### Mitigation

1. **Totality Enforcement**: Require semantic mapping be total over accepted concrete space:
   ```
   ∀s_c ∈ AcceptedConcreteStates: Defined(μ_S(s_c))
   ∀σ_c ∈ AcceptedConcreteInputs: Defined(μ_Σ(σ_c))
   ```

2. **Domain Boundary Verification**: Verify that execution layer cannot produce values outside semantic mapping domain:
   ```
   EL_Domain ⊆ Domain(μ)
   ```

3. **Undefined Behavior Rejection**: Any accepted concrete artifact where μ is undefined must trigger rejection:
   ```
   Defined(μ(x)) = false ⟹ Reject(x)
   ```

4. **Coverage Analysis**: Automated verification that semantic mapping covers all execution paths.

### Suggested Regression Test

```rust
#[test]
fn test_semantic_mapping_completeness() {
    // Enumerate all concrete execution paths (or sample exhaustively)
    let execution_paths = enumerate_concrete_execution_paths();
    
    for path in execution_paths {
        // Extract states and inputs from path
        for (state, input) in path.transitions() {
            // Verify state mapping is defined
            assert!(semantic_map_state_defined(&state),
                "State escapes semantic mapping: {:?}", state);
            
            // Verify input mapping is defined
            assert!(semantic_map_input_defined(&input),
                "Input escapes semantic mapping: {:?}", input);
            
            // Execute and verify transition mapping
            let next_state = execute_concrete(state, input);
            assert!(semantic_map_transition_defined(&state, &input, &next_state),
                "Transition escapes semantic mapping: ({:?}, {:?}) -> {:?}", 
                state, input, next_state);
        }
    }
}

#[test]
fn test_undefined_semantic_rejection() {
    // Generate concrete artifacts at semantic boundary
    let boundary_states = generate_boundary_concrete_states();
    let boundary_inputs = generate_boundary_concrete_inputs();
    
    for state in boundary_states {
        if !semantic_map_state_defined(&state) {
            assert!(system_rejects(&state),
                "System accepts state outside semantic domain");
        }
    }
    
    for input in boundary_inputs {
        if !semantic_map_input_defined(&input) {
            assert!(system_rejects_input(&input),
                "System accepts input outside semantic domain");
        }
    }
}
```

---

## Attack 5: Semantic Collapse — Multiple Interpretations, Same Trace

### Title
**Interpretation Collision: When One Trace Carries Many Meanings**

### Description

Semantic mapping determinism requires that each concrete trace map to exactly one formal trace. This attack exploits non-injective semantic mappings where multiple distinct formal interpretations correspond to the same concrete execution.

This ambiguity allows adversaries to execute once and claim multiple conflicting semantic meanings, or to have executions interpreted differently by different verifiers.

### Preconditions

1. Semantic mapping μ_T is not injective (many-to-one from formal to concrete)
2. Multiple valid μ_T⁻¹ exist for some concrete traces
3. Different interpretations lead to different security conclusions
4. Proof system does not commit to unique interpretation

### Attack Path

1. **Adversary identifies ambiguous trace**: Finds concrete trace τ_c where:
   ```
   |μ_T⁻¹(τ_c)| > 1
   ∃ τ_f₁, τ_f₂ ∈ μ_T⁻¹(τ_c): τ_f₁ ≠ τ_f₂
   ```

2. **Adversary selects favorable interpretation**: Chooses τ_f* ∈ μ_T⁻¹(τ_c) that:
   - Satisfies proof requirements
   - Maximizes adversary's objective
   - Minimizes adversary's obligations

3. **Adversary presents interpretation-dependent proof**: Generates proof π where:
   ```
   Verify(π) = true
   π attests to τ_f* (chosen interpretation)
   But concrete execution could equally attest to τ_f' (alternative)
   ```

4. **Different verifiers see different semantics**: Depending on which μ_T⁻¹ they apply:
   - Verifier A sees valid, intended execution
   - Verifier B sees valid, unintended execution
   - Verifier C sees invalid execution (if they apply different mapping)

5. **Consensus failure or selective interpretation**: System cannot agree on what execution meant.

### Broken Assumption

The assumption that ValidConcreteTrace(τ_c) ⟹ ∃! τ_f: μ_Tr(τ_c) = τ_f. This assumes semantic determinism that may not hold.

### Expected Failure

Same execution interpreted differently by different parties, enabling:
- Double-spending via interpretation divergence
- Selective disclosure (revealing favorable interpretation)
- Consensus failures between nodes with different mapping implementations

### Severity
**HIGH** — Breaks determinism, a foundational property of distributed systems.

### Mitigation

1. **Semantic Mapping Injectivity Proof**: Prove that μ_T is injective:
   ```
   μ_T(τ_c₁) = μ_T(τ_c₂) ⟹ τ_c₁ = τ_c₂
   ```

2. **Canonical Trace Representation**: Define canonical form for formal traces such that all equivalent interpretations collapse to single representation.

3. **Interpretation Commitment**: Require execution to commit to semantic interpretation, not just concrete trace:
   ```
   Commitment = H(τ_c, τ_f) where τ_f = chosen interpretation
   ```

4. **Deterministic Canonicalization**: Concrete traces must be canonicalized before semantic interpretation to eliminate structural ambiguity.

### Suggested Regression Test

```rust
#[test]
fn test_semantic_mapping_injectivity() {
    // Generate pairs of distinct formal traces
    let formal_trace_pairs = generate_distinct_formal_trace_pairs();
    
    for (trace_a, trace_b) in formal_trace_pairs {
        // Find concrete preimages (if any)
        let concrete_a = find_concrete_preimage(&trace_a);
        let concrete_b = find_concrete_preimage(&trace_b);
        
        // If both have concrete preimages, they must be different
        if let (Some(c_a), Some(c_b)) = (concrete_a, concrete_b) {
            assert_ne!(c_a, c_b,
                "Different formal traces map to same concrete trace: \
                 {:?} and {:?} both → {:?}", trace_a, trace_b, c_a);
        }
    }
}

#[test]
fn test_concrete_trace_uniqueness() {
    // For each concrete trace, verify unique formal interpretation
    let concrete_traces = sample_concrete_traces();
    
    for trace_c in concrete_traces {
        let interpretations = find_all_formal_interpretations(&trace_c);
        
        assert_eq!(interpretations.len(), 1,
            "Concrete trace has {} interpretations: {:?}",
            interpretations.len(), trace_c);
        
        // Verify interpretation is deterministic
        let interpretation_1 = semantic_map_trace(&trace_c);
        let interpretation_2 = semantic_map_trace(&trace_c);
        assert_eq!(interpretation_1, interpretation_2,
            "Semantic mapping non-deterministic");
    }
}
```

---

## Attack 6: Semantic Divergence — One Intent, Multiple Behaviors

### Title
**Intent Schism: When Specification Maps to Incompatible Executions**

### Description

This is the dual of Attack 5: a single formal semantic intent maps to multiple mutually incompatible concrete execution behaviors. This indicates non-determinism or underspecification in the formal-to-concrete refinement.

When the same formal intent can be realized through different concrete behaviors, the system lacks predictability, and adversaries can select favorable realizations while claiming compliance with specification.

### Preconditions

1. Formal specification defines intent I
2. Multiple concrete executions E₁, E₂ both satisfy I (formally)
3. E₁ and E₂ have different security or economic properties
4. Execution layer can realize both E₁ and E₂

### Attack Path

1. **Adversary identifies semantic underspecification**: Finds formal intent I where:
   ```
   μ_T⁻¹(I) = {E₁, E₂, ..., Eₙ} (multiple concrete realizations)
   ∃ i, j: SecurityProperties(E_i) ≠ SecurityProperties(E_j)
   ```

2. **Adversary selects favorable realization**: Given input σ intended to produce outcome I, adversary arranges execution environment to realize E_adv where:
   ```
   Semantics(E_adv) = I (satisfies specification)
   AdversaryAdvantage(E_adv) > AdversaryAdvantage(E_intended)
   ```

3. **Execution produces selected realization**: Through control over:
   - Execution ordering
   - Environmental parameters
   - Timing
   - Auxiliary inputs

4. **Proof attests to specification compliance**: Proof π shows:
   ```
   Verify(π) = true
   Semantics(E_adv) = I (as specified)
   ```

5. **Adversary gains advantage while remaining compliant**: System cannot distinguish intended from adversarial realization because both satisfy formal specification.

### Broken Assumption

The assumption that formal specification uniquely determines concrete behavior. This ignores implementation non-determinism and underspecification.

### Expected Failure

Adversary exploits "compliant" behavior that formal specification permits but protocol intent forbids. Specification is technically satisfied, intent is violated.

### Severity
**HIGH** — Allows adversarial selection among specification-compliant behaviors.

### Mitigation

1. **Deterministic Realization Requirement**: Formal specification must map to unique concrete behavior:
   ```
   |μ_T⁻¹(τ_f)| = 1
   ```

2. **Implementation Conformance Verification**: Verify that concrete implementation is deterministic and matches intended realization:
   ```
   ∀ τ_f: Realize(τ_f) = IntendedRealization(τ_f)
   ```

3. **Canonical Execution Path**: Define canonical execution path for each formal transition, reject non-canonical realizations.

4. **Environmental Determinism**: Environmental parameters that affect realization must be fixed or committed before execution.

### Suggested Regression Test

```rust
#[test]
fn test_semantic_realization_uniqueness() {
    // For each formal transition
    for formal_transition in all_formal_transitions() {
        // Find all possible concrete realizations
        let realizations = find_concrete_realizations(&formal_transition);
        
        // Must be exactly one
        assert_eq!(realizations.len(), 1,
            "Formal transition {} has {} realizations",
            formal_transition.id, realizations.len());
        
        // Verify realization is deterministic
        let realization_1 = realize_concretely(&formal_transition);
        let realization_2 = realize_concretely(&formal_transition);
        assert_eq!(realization_1, realization_2,
            "Non-deterministic realization");
    }
}

#[test]
fn test_adversarial_realization_selection() {
    // Simulate adversary with environmental control
    let adversary = AdversarialEnvironmentController::new();
    
    for intent in security_critical_intents() {
        // Adversary attempts to find alternative realization
        let alternative = adversary.find_alternative_realization(&intent);
        
        assert!(alternative.is_none(),
            "Adversary found alternative realization for intent {}: {:?}",
            intent, alternative);
    }
}
```

---

## Attack 7: Semantic Mutation via Protocol Upgrade

### Title
**Invariant Drift: Upgrades That Change Meaning Without Changing Names**

### Description

Protocol upgrades introduce new code, but often fail to recognize that semantic meaning evolves with implementation. This attack exploits upgrades that preserve invariant names while changing their semantic content.

When invariant I retains its identifier but its meaning shifts from M₁ to M₂, existing proofs and specifications become ambiguous. Proofs generated under M₁ may be incorrectly interpreted under M₂, or vice versa.

### Preconditions

1. Protocol upgrade changes implementation semantics
2. Invariant names remain unchanged
3. Formal specification not fully updated to reflect new semantics
4. Old and new proofs coexist in verification context

### Attack Path

1. **Adversary identifies semantic shift**: Analyzes upgrade diff to find invariant I where:
   ```
   Name(I_v1) = Name(I_v2) = "I"
   Meaning(I_v1) ≠ Meaning(I_v2)
   ```

2. **Adversary exploits proof ambiguity**: Uses proof π generated under I_v1 semantics but verified under I_v2:
   ```
   Prove(I_v1, execution) = π
   Verify(I_v2, π) = true (same name)
   But I_v2(execution) may be false!
   ```

3. **Adversary constructs cross-version attack**: Creates execution where:
   ```
   I_v1(execution) = true (satisfies old invariant)
   I_v2(execution) = false (violates new invariant)
   But system accepts due to name confusion
   ```

4. **System accepts semantically invalid execution**: Verification succeeds because proof binds to invariant name, not meaning.

### Broken Assumption

The assumption that invariant names uniquely identify invariant meanings across protocol versions.

### Expected Failure

Proofs from different protocol versions conflated, allowing outdated proofs to validate upgraded protocol states or vice versa.

### Severity
**HIGH** — Breaks proof-verification binding across upgrades.

### Mitigation

1. **Semantic Versioning**: Invariants include semantic hash, not just name:
   ```
   I = (name, semantic_hash, predicate)
   ```

2. **Epoch-Bound Proofs**: Proofs commit to protocol version/epoch:
   ```
   π binds to (execution, protocol_version)
   Verify rejects π from wrong epoch
   ```

3. **Invariant Migration Verification**: Upgrades must prove semantic compatibility or explicit transformation:
   ```
   Upgrade includes Proof(∀s: I_v1(s) ⟹ I_v2(s)) OR explicit migration
   ```

4. **Proof Epoch Checking**: Verifiers reject proofs from incompatible epochs.

### Suggested Regression Test

```rust
#[test]
fn test_invariant_semantic_stability() {
    let versions = get_all_protocol_versions();
    
    for i in 0..versions.len() {
        for j in (i+1)..versions.len() {
            let v1 = &versions[i];
            let v2 = &versions[j];
            
            // Compare invariants with same name
            for inv_name in v1.invariant_names() {
                if let (Some(inv1), Some(inv2)) = 
                    (v1.get_invariant(&inv_name), v2.get_invariant(&inv_name)) {
                    
                    // Check semantic equivalence
                    let semantic_eq = check_semantic_equivalence(&inv1, &inv2);
                    
                    if !semantic_eq {
                        // If meanings differ, verify explicit migration exists
                        assert!(v2.has_migration_for(&inv_name, v1.version),
                            "Invariant {} changed meaning from {} to {} without migration",
                            inv_name, v1.version, v2.version);
                        
                        // Verify migration correctness
                        let migration = v2.get_migration(&inv_name, v1.version);
                        assert!(verify_migration_correct(&migration, &inv1, &inv2),
                            "Migration for {} from {} to {} is incorrect",
                            inv_name, v1.version, v2.version);
                    }
                }
            }
        }
    }
}

#[test]
fn test_cross_version_proof_rejection() {
    let old_version = ProtocolVersion::V1;
    let new_version = ProtocolVersion::V2;
    
    // Generate proof on old version
    let execution = create_test_execution();
    let old_proof = generate_proof(&old_version, &execution);
    
    // Verification on new version should fail (or use migration)
    let result = verify_proof(&new_version, &old_proof);
    
    // Should either reject or apply explicit migration
    assert!(!result.accepted_without_migration(),
        "Cross-version proof accepted without migration");
}
```

---

## Attack 8: Policy Commitment Weakening

### Title
**Commitment Substitution: When Bound Policy Is Weaker Than Approved Policy**

### Description

Governance processes often involve social discussion of policy P_social, followed by technical implementation of policy commitment P_commit. This attack exploits divergence between socially-approved intent and technically-bound commitment.

When P_commit is a weakening of P_social — technically valid but semantically weaker — the system enforces less than was approved, allowing adversarial behavior that would be socially rejected but is technically permitted.

### Preconditions

1. Social governance process approves policy P_social
2. Technical implementation commits to P_commit
3. P_commit ⊂ P_social (P_commit is weaker, permits superset of behaviors)
4. Commitment verification only checks P_commit, not P_social

### Attack Path

1. **Adversary influences technical implementation**: Ensures that committed policy is weakening of social intent:
   ```
   SocialApproval(P_social) = true
   TechnicalCommitment(P_commit) where P_commit ⊂ P_social
   ```

2. **Adversary constructs P_commit-satisfying execution**: Creates σ where:
   ```
   P_commit(σ) = true (technically permitted)
   P_social(σ) = false (socially rejected)
   ```

3. **Execution passes all checks**: System verifies:
   ```
   PolicyCommitmentValid(P_commit) = true
   P_commit(σ) = true
   Accept(σ) // despite violating social intent
   ```

4. **Social intent violated with technical legitimacy**: Governance approved P_social, system enforces P_commit, adversary exploits gap.

### Broken Assumption

The assumption that committed policy equals approved policy. This ignores technical weakening during implementation.

### Expected Failure

System permits behavior that would fail social governance but passes technical checks.

### Severity
**MEDIUM-HIGH** — Governance bypass via technical substitution.

### Mitigation

1. **Policy Commitment Verification**: Verify that committed policy matches approved policy:
   ```
   CommitPolicy(P_commit) requires P_commit = P_approved
   ```

2. **Commitment Semantic Check**: Verify P_commit is not weakening of P_social:
   ```
   ¬Weaker(P_commit, P_social)
   ```

3. **Governance Transparency**: Public derivation showing P_commit captures all of P_social intent.

4. **Policy Equivalence Proof**: Formal proof that committed policy is equivalent to approved policy:
   ```
   Proof(∀σ: P_social(σ) ⟺ P_commit(σ))
   ```

### Suggested Regression Test

```rust
#[test]
fn test_policy_commitment_fidelity() {
    // Simulate governance approval
    let social_policy = get_socially_approved_policy();
    
    // Get technically committed policy
    let committed_policy = get_committed_policy();
    
    // Verify committed policy is not weaker
    let weakening = find_weakening(&social_policy, &committed_policy);
    assert!(weakening.is_none(),
        "Committed policy is weaker than social policy: {:?}",
        weakening);
    
    // Verify semantic equivalence
    let equivalence = prove_policy_equivalence(&social_policy, &committed_policy);
    assert!(equivalence.valid,
        "Policies not equivalent: {}", equivalence.counterexample);
}

#[test]
fn test_policy_adversarial_weakening() {
    let social_policy = create_test_policy();
    
    // Attempt to weaken policy
    let weakening_attempts = generate_weakenings(&social_policy);
    
    for weakened in weakening_attempts {
        // System should reject commitment of weakened policy
        let commitment_result = attempt_policy_commitment(&weakened);
        
        // If weakened policy is different, rejection should occur
        if weakened != social_policy {
            assert!(!commitment_result.accepted || 
                    commitment_result.requires_explicit_approval,
                "Weakened policy accepted without explicit approval");
        }
    }
}
```

---

## Attack 9: Execution Verification Without Intent Preservation

### Title
**Execution Theater: Proofs That Verify Steps But Not Goals**

### Description

Zero-knowledge proofs excel at verifying that execution followed specific steps (operational correctness), but often fail to verify that those steps achieved intended goals (semantic correctness). This attack exploits proofs that validate execution traces without validating that traces achieve stated objectives.

The adversary constructs a valid execution that technically follows all steps but semantically achieves different goals than claimed.

### Preconditions

1. Proof system verifies execution trace τ
2. Proof system does not verify intent achievement I(τ)
3. Multiple intents can be realized through similar execution patterns
4. Verifier accepts proof without intent validation

### Attack Path

1. **Adversary identifies intent-execution gap**: Finds where:
   ```
   ValidTrace(τ₁) ∧ ValidTrace(τ₂)
   Obs(τ₁) ≈ Obs(τ₂) (similar observables)
   Intent(τ₁) ≠ Intent(τ₂)
   ```

2. **Adversary executes τ_adv achieving Intent_B**: Runs execution achieving unintended intent.

3. **Adversary claims Intent_A**: Presents proof claiming:
   ```
   π claims: "This proves execution achieving Intent_A"
   But actually: Execution achieves Intent_B
   ```

4. **Proof verifies operationally**: Proof verification checks:
   ```
   Verify(π) = Check(ValidTrace(τ_adv)) = true
   // But does NOT check Intent_A(τ_adv)
   ```

5. **System accepts wrong intent**: Verifier accepts proof of Intent_A execution, but actual execution achieved Intent_B.

### Broken Assumption

The assumption that verifying execution steps verifies execution intent. This confuses operational correctness with semantic correctness.

### Expected Failure

Proofs attest to intents not achieved by execution, enabling fraud via technically valid proofs.

### Severity
**CRITICAL** — Core failure of proof semantics.

### Mitigation

1. **Intent-Aware Proof Statements**: Proof statement includes intent predicate:
   ```
   π = Proof(τ, I) where I is claimed intent
   Verify(π) checks ValidTrace(τ) ∧ I(τ)
   ```

2. **Observable-Intent Binding**: Intent must be bound to observables:
   ```
   I(τ) ≡ Obs(τ) ∈ AcceptableObservables(I)
   ```

3. **Intent Witness Requirements**: Proof must include intent witness:
   ```
   π includes W_I where W_I proves I(τ)
   ```

4. **Semantic Proof Obligations**: Proof obligations explicitly encode intent preservation.

### Suggested Regression Test

```rust
#[test]
fn test_proof_intent_preservation() {
    // Create execution with clear intent
    let intended_outcome = Intent::Transfer{from: A, to: B, amount: 100};
    let execution = create_execution_achieving(&intended_outcome);
    
    // Generate proof claiming intent
    let proof = generate_intent_proof(&execution, &intended_outcome);
    
    // Verify proof binds intent to execution
    let verified_intent = extract_verified_intent(&proof);
    assert_eq!(verified_intent, intended_outcome,
        "Proof intent does not match claimed intent");
    
    // Verify execution actually achieves intent
    let actual_outcome = extract_actual_outcome(&execution);
    assert_eq!(actual_outcome, intended_outcome,
        "Execution does not achieve claimed intent");
}

#[test]
fn test_adversarial_intent_substitution() {
    // Create execution achieving Intent_A
    let intent_a = Intent::Transfer{from: X, to: Y, amount: 1000};
    let execution_a = create_execution_achieving(&intent_a);
    
    // Attempt to generate proof claiming Intent_B
    let intent_b = Intent::Transfer{from: A, to: B, amount: 100};
    let malicious_proof = attempt_intent_proof(&execution_a, &intent_b);
    
    // Proof should fail verification (execution achieves A, claims B)
    let verification = verify_intent_proof(&malicious_proof);
    assert!(!verification.accepted,
        "Proof verified despite intent mismatch");
}

#[test]
fn test_execution_intent_decoupling() {
    // Find executions where steps are valid but intent is wrong
    let test_intents = generate_test_intents();
    
    for intent in test_intents {
        // Find executions with valid steps but wrong intent
        let wrong_intent_executions = find_executions_with_valid_steps_but_wrong_intent(&intent);
        
        for execution in wrong_intent_executions {
            // Verify system rejects proof of intent
            let proof = generate_intent_proof(&execution, &intent);
            assert!(!verify_intent_proof(&proof).accepted,
                "Accepted proof of intent not achieved by execution");
        }
    }
}
```

---

## Attack 10: Syntactically Complete but Semantically Incomplete Traces

### Title
**Trace Shadows: When All Steps Are Recorded But Meaning Is Lost**

### Description

Execution traces capture state transitions and inputs, but may fail to capture semantic context necessary for intent verification. This attack exploits traces that are syntactically complete (all state changes recorded) but semantically incomplete (context for interpreting changes is missing).

The adversary constructs execution where trace τ records what happened but not why it happened, preventing verification that execution matched intent.

### Preconditions

1. Trace format captures (s, σ, s') transitions
2. Trace format does not capture semantic context C
3. Interpretation of transition requires C
4. Multiple interpretations of same (s, σ, s') exist depending on C

### Attack Path

1. **Adversary identifies context-dependent transitions**: Finds transitions where:
   ```
   Same(s₁, σ, s'₁) and Same(s₂, σ, s'₂) structurally
   But SemanticMeaning(s₁, σ, s'₁) ≠ SemanticMeaning(s₂, σ, s'₂)
   Due to different contexts C₁ ≠ C₂
   ```

2. **Adversary executes in favorable context**: Executes σ in context C_adv where interpretation is favorable.

3. **Trace records without context**: Trace captures:
   ```
   τ = (s, σ, s')  // but NOT C
   ```

4. **Verification lacks context**: Verifier sees:
   ```
   Verify(τ) sees structural validity
   Cannot determine if C was C_intended or C_adv
   ```

5. **Interpretation ambiguity**: Same trace could represent:
   - Intended execution (if C = C_intended)
   - Adversarial execution (if C = C_adv)

6. **System cannot distinguish**: Acceptance depends on interpretation, but trace doesn't record which interpretation applies.

### Broken Assumption

The assumption that trace completeness implies semantic verifiability. This ignores that traces require context for interpretation.

### Expected Failure

Traces accepted as complete verification evidence despite lacking semantic context for correct interpretation.

### Severity
**HIGH** — Incomplete verification basis.

### Mitigation

1. **Context-Aware Tracing**: Traces include semantic context:
   ```
   τ = (s, σ, s', C) where C is interpretation context
   ```

2. **Context Commitment**: Context committed to and verified:
   ```
   Verify includes Check(C committed ∧ C valid)
   ```

3. **Canonical Context Derivation**: Context derivable from trace alone, or explicitly ruled out.

4. **Trace Interpretation Uniqueness**: For any trace, interpretation must be unique without additional context.

### Suggested Regression Test

```rust
#[test]
fn test_trace_semantic_completeness() {
    // Generate executions with different contexts
    let executions = generate_context_dependent_executions();
    
    for (exec_a, exec_b) in executions.pairs() {
        // Verify traces are syntactically different
        let trace_a = generate_trace(&exec_a);
        let trace_b = generate_trace(&exec_b);
        
        // Traces should differ if contexts differ
        assert_ne!(trace_a, trace_b,
            "Different contexts produce same trace");
        
        // Verify semantic reconstruction
        let reconstructed_a = reconstruct_from_trace(&trace_a);
        let reconstructed_b = reconstruct_from_trace(&trace_b);
        
        assert_eq!(reconstructed_a.context, exec_a.context,
            "Trace context reconstruction failed");
        assert_eq!(reconstructed_b.context, exec_b.context,
            "Trace context reconstruction failed");
    }
}

#[test]
fn test_context_dependent_verification() {
    // Find context-dependent transitions
    let transitions = find_context_dependent_transitions();
    
    for transition in transitions {
        let contexts = generate_relevant_contexts(&transition);
        
        for context in contexts {
            // Execute with specific context
            let execution = execute_with_context(&transition, &context);
            let trace = generate_trace(&execution);
            
            // Verification must include context check
            let result = verify_with_context(&trace, &context);
            assert!(result.valid,
                "Context-aware verification failed");
            
            // Verification with wrong context should fail
            for wrong_context in contexts.iter().filter(|c| c != &context) {
                let wrong_result = verify_with_context(&trace, wrong_context);
                assert!(!wrong_result.valid,
                    "Verification succeeded with wrong context");
            }
        }
    }
}

#[test]
fn test_trace_interpretation_uniqueness() {
    let traces = sample_complete_traces();
    
    for trace in traces {
        // Attempt multiple interpretations
        let interpretations = attempt_interpretations(&trace);
        
        // Should be exactly one valid interpretation
        let valid_interpretations: Vec<_> = interpretations
            .into_iter()
            .filter(|i| i.valid)
            .collect();
        
        assert_eq!(valid_interpretations.len(), 1,
            "Trace has {} valid interpretations, expected 1",
            valid_interpretations.len());
    }
}
```

---

## Cross-Cutting Attack Patterns

### Pattern A: Multi-Layer Semantic Collapse

Attacks 1, 5, and 6 can be combined: non-injective mapping (5) allows multiple formal interpretations, one of which maps to adversarial concrete behavior (6), and execution succeeds while semantic intent fails (1).

**Defense**: Ensure μ_T is bijective (both injective and surjective) between concrete and formal domains.

### Pattern B: Temporal Semantic Drift

Attacks 7 and 8 combine across time: upgrades change invariant meaning (7) while governance weakens policy commitments (8), creating multi-epoch semantic confusion.

**Defense**: Epoch-aware semantic versioning with explicit migration validation.

### Pattern C: Proof-Intent Decoupling

Attacks 2, 3, and 9 combine: weak invariants (3) allow policy-permitted violations (2) that proofs verify without intent preservation (9).

**Defense**: Intent-aware proof generation with semantic validity requirements.

---

## Mitigation Hierarchy

### Level 1: Specification Correctness
- Complete formal specification covering all semantic intent
- Explicit intent predicates, not implicit in code
- Semantic mapping totality and injectivity proofs

### Level 2: Implementation Fidelity
- Differential testing against specification
- Semantic mapping coverage analysis
- Trace completeness verification

### Level 3: Proof Alignment
- Intent-aware proof statements
- Semantic proof obligations
- Cross-version proof compatibility

### Level 4: Governance Integration
- Policy-invariant consistency verification
- Semantic versioning for upgrades
- Technical-social policy alignment

---

## Residual Risk Assessment

Even with all mitigations, residual semantic risks include:

1. **Specification Incompleteness**: Formal model cannot capture all real-world intent
2. **Interpretation Divergence**: Different stakeholders interpret specification differently
3. **Emergent Semantics**: Composition of verified components produces unverified emergent behavior
4. **Meta-Semantic Attacks**: Attacks on the semantic mapping layer itself

These risks are fundamental to any formal verification system and can only be managed, not eliminated.

---

## Validation Requirements

Each attack in this document must be addressed through:

1. **Formal Counterargument**: Proof that attack is impossible in current system design, OR
2. **Mitigation Implementation**: Code implementing mitigations described, OR
3. **Explicit Acceptance**: Documentation accepting risk with justification

Unaddressed attacks constitute active vulnerabilities.

---

## Closing Statement

Semantic intent attacks represent the most sophisticated threat model for formally verified systems. They exploit the fundamental gap between mathematical truth and human meaning, between what is proven and what is intended.

The ten attacks in this document are not implementation bugs. They are architectural challenges inherent to any system that attempts to bridge formal specification and concrete execution. Addressing them requires not just better code, but better semantic architecture — explicit mappings, intent preservation, and recognition that verification without meaning is theater.

If your system passes all cryptographic checks, all invariant validations, and all proof verifications, but still permits semantically incorrect behavior, you have not built a secure system. You have built a convincing simulation of one.

The adversary understands this distinction. The question is whether the defenders do.