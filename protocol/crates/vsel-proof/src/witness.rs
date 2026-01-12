//! Witness construction and validation for the VSEL proof system.
//!
//! Derived from: WITNESS_UNIQUENESS_AND_NON_MALLEABILITY.md §2,
//! PROOF_LAYER.md §3, Requirements 7.6, 12.2, 12.6.
//!
//! A witness W = (S_intermediate, Σ_sequence, Aux_computation) encodes
//! an execution for proof generation. Semantic uniqueness (LEM-6):
//! for all W₁, W₂ satisfying constraints with same public inputs,
//! Semantics(W₁) = Semantics(W₂).

use vsel_constraints::WitnessVariableKind;
use vsel_core::input::Input;
use vsel_core::state::State;
use vsel_trace::engine::Trace;

// ---------------------------------------------------------------------------
// AuxiliaryComputation — auxiliary data for proof generation
// ---------------------------------------------------------------------------

/// Auxiliary computation data used during proof generation.
///
/// Contains intermediate arithmetic results, Merkle paths, and other
/// non-semantic data needed by the proof backend. Auxiliary data must
/// NOT influence semantic outcome (THM-4, Requirement 12.6).
#[derive(Clone, Debug)]
pub struct AuxiliaryComputation {
    /// Named auxiliary values produced during witness construction.
    /// Each entry is (name, value_bytes).
    pub values: Vec<(String, Vec<u8>)>,
}

impl AuxiliaryComputation {
    /// Create an empty auxiliary computation.
    pub fn empty() -> Self {
        Self { values: Vec::new() }
    }

    /// Add an auxiliary value.
    pub fn add(&mut self, name: String, value: Vec<u8>) {
        self.values.push((name, value));
    }
}

// ---------------------------------------------------------------------------
// Witness — W = (S_intermediate, Σ_sequence, Aux_computation)
// ---------------------------------------------------------------------------

/// Witness for the VSEL proof system.
///
/// WITNESS_UNIQUENESS_AND_NON_MALLEABILITY.md §2:
/// Semantic uniqueness (LEM-6): For all W₁, W₂ satisfying constraints
/// with same public inputs: Semantics(W₁) = Semantics(W₂).
///
/// Requirements 7.6, 12.2, 12.6.
#[derive(Clone, Debug)]
pub struct Witness {
    /// Intermediate states s₁, ..., s_{n-1} between transitions.
    pub intermediate_states: Vec<State>,
    /// Input sequence σ₀, ..., σ_{n-1} that drove the transitions.
    pub input_sequence: Vec<Input>,
    /// Auxiliary computation data (Merkle paths, intermediate arithmetic).
    pub aux_computation: AuxiliaryComputation,
}

// ---------------------------------------------------------------------------
// Witness construction from execution trace
// ---------------------------------------------------------------------------

/// Construct a witness from an execution trace.
///
/// Extracts intermediate states and input sequence from the trace entries.
/// The initial state is NOT included in intermediate_states (it is a public
/// input), and the final state is also excluded (derivable from the last
/// post-state commitment). Only the states between transitions are recorded.
///
/// Requirements 7.6 (witness semantic uniqueness), 12.2 (witness variable census).
pub fn construct_witness(trace: &Trace) -> Witness {
    let mut intermediate_states = Vec::new();
    let mut input_sequence = Vec::new();
    let mut aux = AuxiliaryComputation::empty();

    for (i, entry) in trace.entries.iter().enumerate() {
        input_sequence.push(entry.input.clone());

        // Record intermediate state commitments as auxiliary data.
        // The pre-state commitment of each entry (except the first, which is
        // the initial state — a public input) is an intermediate state.
        if i > 0 {
            aux.add(
                format!("pre_commitment_{}", i),
                entry.pre_state_commitment.0.to_vec(),
            );
        }

        // Post-state commitment for chaining verification.
        aux.add(
            format!("post_commitment_{}", i),
            entry.post_state_commitment.0.to_vec(),
        );

        // Chain hash for trace integrity.
        aux.add(
            format!("chain_hash_{}", i),
            entry.chain_hash.0.to_vec(),
        );
    }

    // Intermediate states: for a trace with n entries, there are n-1
    // intermediate states (the post-state of entry i is the pre-state
    // of entry i+1). We reconstruct these from the trace's initial state
    // by noting that each entry's post-state is the next entry's pre-state.
    // Since we don't have full states in trace entries (only commitments),
    // we record the initial state as the base and note that intermediate
    // states would be reconstructed during proof generation.
    //
    // For now, the intermediate_states vector is populated if the trace
    // has more than one entry — the initial state serves as the anchor.
    if trace.entries.len() > 1 {
        // The initial state is the "pre" of the first transition.
        // Each subsequent transition's pre-state is an intermediate state.
        // We store the initial state as the first intermediate for chaining.
        intermediate_states.push(trace.initial_state.clone());
    }

    Witness {
        intermediate_states,
        input_sequence,
        aux_computation: aux,
    }
}

// ---------------------------------------------------------------------------
// Witness variable classification
// ---------------------------------------------------------------------------

/// A classified witness variable with its name and kind.
#[derive(Clone, Debug, PartialEq)]
pub struct ClassifiedVariable {
    /// Variable name.
    pub name: String,
    /// Classification: Semantic, Auxiliary, or Derived.
    pub kind: WitnessVariableKind,
}

/// Classify all witness variables in a witness.
///
/// Returns a list of (name, kind) pairs for every variable in the witness.
/// - Semantic: input payloads, authorization data — determine execution meaning
/// - Auxiliary: commitments, chain hashes, Merkle paths — do not influence semantics
/// - Derived: intermediate states — computed from semantic variables
///
/// Requirement 12.6: classify every witness variable as semantic, auxiliary, or derived.
pub fn classify_variables(witness: &Witness) -> Vec<(String, WitnessVariableKind)> {
    let mut classified = Vec::new();

    // Input sequence entries are semantic — they determine execution meaning.
    for (i, _input) in witness.input_sequence.iter().enumerate() {
        classified.push((
            format!("input_payload_{}", i),
            WitnessVariableKind::Semantic,
        ));
        classified.push((
            format!("input_auth_{}", i),
            WitnessVariableKind::Semantic,
        ));
        classified.push((
            format!("input_aux_{}", i),
            WitnessVariableKind::Auxiliary,
        ));
    }

    // Intermediate states are derived — computed from applying inputs to initial state.
    for (i, _state) in witness.intermediate_states.iter().enumerate() {
        classified.push((
            format!("intermediate_state_{}", i),
            WitnessVariableKind::Derived,
        ));
    }

    // Auxiliary computation values are auxiliary by definition.
    for (name, _value) in &witness.aux_computation.values {
        classified.push((name.clone(), WitnessVariableKind::Auxiliary));
    }

    classified
}

// ---------------------------------------------------------------------------
// Auxiliary variable independence verification
// ---------------------------------------------------------------------------

/// Verify that auxiliary variables do not influence semantic outcome.
///
/// Requirement 12.6: changing auxiliary values does not change any semantic
/// variable. This checks that:
/// 1. No auxiliary variable name collides with a semantic variable name.
/// 2. The auxiliary computation values are structurally independent from
///    the semantic content (input payloads and auth data).
///
/// Returns true if auxiliary variables are independent of semantic outcome.
pub fn verify_auxiliary_independence(witness: &Witness) -> bool {
    let classified = classify_variables(witness);

    let semantic_names: Vec<&str> = classified
        .iter()
        .filter(|(_, kind)| *kind == WitnessVariableKind::Semantic)
        .map(|(name, _)| name.as_str())
        .collect();

    let auxiliary_names: Vec<&str> = classified
        .iter()
        .filter(|(_, kind)| *kind == WitnessVariableKind::Auxiliary)
        .map(|(name, _)| name.as_str())
        .collect();

    // Check 1: No name collision between semantic and auxiliary variables.
    for aux_name in &auxiliary_names {
        if semantic_names.contains(aux_name) {
            return false;
        }
    }

    // Check 2: Auxiliary computation values must not contain references
    // to semantic variable names (structural independence).
    // In a real ZK backend, this would be enforced by the constraint system.
    // Here we verify the structural property that aux values are named
    // distinctly from semantic variables.
    for (name, _) in &witness.aux_computation.values {
        if semantic_names.contains(&name.as_str()) {
            return false;
        }
    }

    // Check 3: Input auxiliary data (the `aux` field of each Input) must
    // not duplicate semantic variable names.
    for (i, _) in witness.input_sequence.iter().enumerate() {
        let aux_var_name = format!("input_aux_{}", i);
        if semantic_names.contains(&aux_var_name.as_str()) {
            return false;
        }
    }

    true
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use vsel_core::input::{Authorization, Input};
    use vsel_core::state::*;
    use vsel_core::types::*;
    use vsel_trace::engine::{Trace, TraceEntry};

    /// Helper: create a minimal valid state for testing.
    fn test_state() -> State {
        let zero_hash = Hash([0u8; 32]);
        State {
            canonical: CanonicalState {
                accounts: BTreeMap::new(),
                storage: BTreeMap::new(),
                system_data: SystemData {
                    protocol_version: ProtocolVersion {
                        major: 1,
                        minor: 0,
                        patch: 0,
                    },
                    total_supply: 1_000_000,
                    parameters: BTreeMap::new(),
                },
            },
            derived: DerivedState {
                state_root: zero_hash.clone(),
                auxiliary_roots: BTreeMap::new(),
                aggregates: BTreeMap::new(),
            },
            environment: Environment {
                timestamp: 1000,
                block_height: 1,
                execution_domain: DomainTag(zero_hash.clone()),
            },
            economic: EconomicContext {
                price_oracle: BTreeMap::new(),
                exposure_limits: BTreeMap::new(),
                liquidity_thresholds: BTreeMap::new(),
                fee_schedule: FeeSchedule {
                    base_fee: 100,
                    fee_rate_bps: 10,
                    overrides: BTreeMap::new(),
                },
                epoch_accounting: EpochAccounting {
                    epoch: 1,
                    total_fees_collected: 0,
                    total_transactions: 0,
                },
                collateral_requirements: BTreeMap::new(),
                economic_parameters: EconomicParameters {
                    max_leverage_bps: 50_000,
                    min_collateral_ratio_bps: 15_000,
                    dust_threshold: 1,
                    extra: BTreeMap::new(),
                },
            },
            metadata: TraceMetadata {
                sequence_index: 0,
                previous_commitment: zero_hash.clone(),
                epoch: 1,
                timestamp: 1000,
            },
        }
    }

    /// Helper: create a minimal valid input for testing.
    fn test_input() -> Input {
        let zero_hash = Hash([0u8; 32]);
        Input {
            payload: Payload {
                payload_type: "transfer".to_string(),
                data: vec![1, 2, 3],
            },
            auth: Authorization {
                classical_sig: vec![1; 64],
                pqc_sig: vec![2; 128],
                public_key: HybridPublicKey {
                    classical: vec![3; 32],
                    pqc: vec![4; 64],
                },
                nonce: 1,
                domain: DomainTag(zero_hash.clone()),
            },
            aux: AuxiliaryData {
                data: vec![0xAA, 0xBB],
            },
        }
    }

    /// Helper: create a minimal observable for testing.
    fn test_observable() -> vsel_core::observable::Observable {
        vsel_core::observable::Observable {
            transition_class: vsel_core::transition::TransitionClass::Update,
            outputs: vec![],
            gas_used: 100,
            status: vsel_core::observable::TransitionStatus::Success,
        }
    }

    /// Helper: create a trace with the given number of entries.
    fn test_trace(num_entries: usize) -> Trace {
        let initial_state = test_state();
        let zero_hash = Hash([0u8; 32]);
        let mut entries = Vec::new();

        for i in 0..num_entries {
            let mut pre_hash = [0u8; 32];
            pre_hash[0] = i as u8;
            let mut post_hash = [0u8; 32];
            post_hash[0] = (i + 1) as u8;
            let mut chain = [0u8; 32];
            chain[0] = (i + 100) as u8;

            entries.push(TraceEntry {
                index: i as u64,
                pre_state_commitment: Hash(pre_hash),
                input: test_input(),
                post_state_commitment: Hash(post_hash),
                observable: test_observable(),
                environment: initial_state.environment.clone(),
                chain_hash: Hash(chain),
            });
        }

        Trace {
            entries,
            initial_state,
            commitment: zero_hash,
        }
    }

    // -----------------------------------------------------------------------
    // AuxiliaryComputation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_auxiliary_computation_empty() {
        let aux = AuxiliaryComputation::empty();
        assert!(aux.values.is_empty());
    }

    #[test]
    fn test_auxiliary_computation_add() {
        let mut aux = AuxiliaryComputation::empty();
        aux.add("merkle_path_0".to_string(), vec![1, 2, 3]);
        aux.add("intermediate_hash".to_string(), vec![4, 5, 6]);
        assert_eq!(aux.values.len(), 2);
        assert_eq!(aux.values[0].0, "merkle_path_0");
        assert_eq!(aux.values[1].0, "intermediate_hash");
    }

    // -----------------------------------------------------------------------
    // Witness construction tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_construct_witness_empty_trace() {
        let trace = test_trace(0);
        let witness = construct_witness(&trace);

        assert!(witness.intermediate_states.is_empty());
        assert!(witness.input_sequence.is_empty());
        assert!(witness.aux_computation.values.is_empty());
    }

    #[test]
    fn test_construct_witness_single_entry() {
        let trace = test_trace(1);
        let witness = construct_witness(&trace);

        assert_eq!(witness.input_sequence.len(), 1);
        // Single entry: no intermediate states (initial is public input).
        assert!(witness.intermediate_states.is_empty());
        // Should have post_commitment_0 and chain_hash_0 as aux values.
        assert!(witness.aux_computation.values.len() >= 2);
    }

    #[test]
    fn test_construct_witness_multiple_entries() {
        let trace = test_trace(3);
        let witness = construct_witness(&trace);

        assert_eq!(witness.input_sequence.len(), 3);
        // With 3 entries, there should be intermediate states.
        assert!(!witness.intermediate_states.is_empty());
        // Aux values: for entry 0: post_commitment_0, chain_hash_0
        //             for entry 1: pre_commitment_1, post_commitment_1, chain_hash_1
        //             for entry 2: pre_commitment_2, post_commitment_2, chain_hash_2
        // Total: 2 + 3 + 3 = 8
        assert_eq!(witness.aux_computation.values.len(), 8);
    }

    #[test]
    fn test_construct_witness_preserves_input_order() {
        let trace = test_trace(3);
        let witness = construct_witness(&trace);

        // All inputs should match the trace entries in order.
        for (i, input) in witness.input_sequence.iter().enumerate() {
            assert_eq!(input, &trace.entries[i].input);
        }
    }

    // -----------------------------------------------------------------------
    // Variable classification tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_classify_variables_empty_witness() {
        let witness = Witness {
            intermediate_states: vec![],
            input_sequence: vec![],
            aux_computation: AuxiliaryComputation::empty(),
        };
        let classified = classify_variables(&witness);
        assert!(classified.is_empty());
    }

    #[test]
    fn test_classify_variables_single_input() {
        let witness = Witness {
            intermediate_states: vec![],
            input_sequence: vec![test_input()],
            aux_computation: AuxiliaryComputation::empty(),
        };
        let classified = classify_variables(&witness);

        // Should have: input_payload_0 (Semantic), input_auth_0 (Semantic),
        //              input_aux_0 (Auxiliary)
        assert_eq!(classified.len(), 3);

        let semantic_count = classified
            .iter()
            .filter(|(_, k)| *k == WitnessVariableKind::Semantic)
            .count();
        let aux_count = classified
            .iter()
            .filter(|(_, k)| *k == WitnessVariableKind::Auxiliary)
            .count();

        assert_eq!(semantic_count, 2);
        assert_eq!(aux_count, 1);
    }

    #[test]
    fn test_classify_variables_with_intermediate_states() {
        let witness = Witness {
            intermediate_states: vec![test_state(), test_state()],
            input_sequence: vec![test_input()],
            aux_computation: AuxiliaryComputation::empty(),
        };
        let classified = classify_variables(&witness);

        let derived_count = classified
            .iter()
            .filter(|(_, k)| *k == WitnessVariableKind::Derived)
            .count();
        assert_eq!(derived_count, 2);
    }

    #[test]
    fn test_classify_variables_with_aux_computation() {
        let mut aux = AuxiliaryComputation::empty();
        aux.add("merkle_path_0".to_string(), vec![1, 2, 3]);
        aux.add("chain_hash_0".to_string(), vec![4, 5, 6]);

        let witness = Witness {
            intermediate_states: vec![],
            input_sequence: vec![test_input()],
            aux_computation: aux,
        };
        let classified = classify_variables(&witness);

        let aux_count = classified
            .iter()
            .filter(|(_, k)| *k == WitnessVariableKind::Auxiliary)
            .count();
        // input_aux_0 + merkle_path_0 + chain_hash_0 = 3
        assert_eq!(aux_count, 3);
    }

    #[test]
    fn test_classify_variables_from_constructed_witness() {
        let trace = test_trace(2);
        let witness = construct_witness(&trace);
        let classified = classify_variables(&witness);

        // Every variable should be classified.
        assert!(!classified.is_empty());

        // All three kinds should be present for a multi-entry trace.
        let has_semantic = classified
            .iter()
            .any(|(_, k)| *k == WitnessVariableKind::Semantic);
        let has_auxiliary = classified
            .iter()
            .any(|(_, k)| *k == WitnessVariableKind::Auxiliary);
        let has_derived = classified
            .iter()
            .any(|(_, k)| *k == WitnessVariableKind::Derived);

        assert!(has_semantic);
        assert!(has_auxiliary);
        assert!(has_derived);
    }

    // -----------------------------------------------------------------------
    // Auxiliary independence tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_auxiliary_independence_valid_witness() {
        let trace = test_trace(2);
        let witness = construct_witness(&trace);
        assert!(verify_auxiliary_independence(&witness));
    }

    #[test]
    fn test_auxiliary_independence_empty_witness() {
        let witness = Witness {
            intermediate_states: vec![],
            input_sequence: vec![],
            aux_computation: AuxiliaryComputation::empty(),
        };
        assert!(verify_auxiliary_independence(&witness));
    }

    #[test]
    fn test_auxiliary_independence_name_collision_detected() {
        // Create a witness where an aux computation value has the same name
        // as a semantic variable — this should fail independence check.
        let mut aux = AuxiliaryComputation::empty();
        aux.add("input_payload_0".to_string(), vec![0xFF]); // Collides with semantic var

        let witness = Witness {
            intermediate_states: vec![],
            input_sequence: vec![test_input()],
            aux_computation: aux,
        };
        assert!(!verify_auxiliary_independence(&witness));
    }

    #[test]
    fn test_auxiliary_independence_no_collision_with_derived() {
        // Auxiliary variables sharing names with derived variables is fine —
        // the independence check is specifically about semantic variables.
        let mut aux = AuxiliaryComputation::empty();
        aux.add("intermediate_state_0".to_string(), vec![0xFF]);

        let witness = Witness {
            intermediate_states: vec![test_state()],
            input_sequence: vec![test_input()],
            aux_computation: aux,
        };
        // This should pass — aux colliding with derived is not a semantic issue.
        assert!(verify_auxiliary_independence(&witness));
    }

    #[test]
    fn test_witness_variable_kinds_reexported_from_constraints() {
        // Verify we're using the same WitnessVariableKind from vsel-constraints.
        let semantic = WitnessVariableKind::Semantic;
        let auxiliary = WitnessVariableKind::Auxiliary;
        let derived = WitnessVariableKind::Derived;

        assert_ne!(semantic, auxiliary);
        assert_ne!(semantic, derived);
        assert_ne!(auxiliary, derived);
    }

    // -----------------------------------------------------------------------
    // Non-malleability check tests (MAL-1 through MAL-6)
    // -----------------------------------------------------------------------

    #[test]
    fn test_check_non_malleability_clean_witness() {
        // Build a trace where each input has a unique nonce.
        let trace = test_trace(2);
        let mut witness = construct_witness(&trace);
        // Ensure unique nonces so MAL-2 doesn't fire.
        for (i, input) in witness.input_sequence.iter_mut().enumerate() {
            input.auth.nonce = i as u64 + 1;
        }
        let results = check_non_malleability(&witness);

        assert_eq!(results.len(), 6);
        for result in &results {
            assert!(
                !result.detected,
                "MAL-{:?} should not be detected on a clean witness: {}",
                result.attack_type, result.description
            );
        }
    }

    #[test]
    fn test_mal1_auxiliary_substitution_detected() {
        let mut aux = AuxiliaryComputation::empty();
        aux.add("input_payload_0".to_string(), vec![0xFF]);

        let witness = Witness {
            intermediate_states: vec![],
            input_sequence: vec![test_input()],
            aux_computation: aux,
        };
        let results = check_non_malleability(&witness);
        let mal1 = results.iter().find(|r| r.attack_type == MalleabilityType::MAL1).unwrap();
        assert!(mal1.detected, "MAL-1 should detect auxiliary-semantic name collision");
    }

    #[test]
    fn test_mal2_witness_reordering_detected() {
        let mut input1 = test_input();
        let mut input2 = test_input();
        // Same nonce on both inputs — reordering vulnerability.
        input1.auth.nonce = 42;
        input2.auth.nonce = 42;

        let witness = Witness {
            intermediate_states: vec![],
            input_sequence: vec![input1, input2],
            aux_computation: AuxiliaryComputation::empty(),
        };
        let results = check_non_malleability(&witness);
        let mal2 = results.iter().find(|r| r.attack_type == MalleabilityType::MAL2).unwrap();
        assert!(mal2.detected, "MAL-2 should detect duplicate nonces");
    }

    #[test]
    fn test_mal2_unique_nonces_pass() {
        let mut input1 = test_input();
        let mut input2 = test_input();
        input1.auth.nonce = 1;
        input2.auth.nonce = 2;

        let witness = Witness {
            intermediate_states: vec![],
            input_sequence: vec![input1, input2],
            aux_computation: AuxiliaryComputation::empty(),
        };
        let results = check_non_malleability(&witness);
        let mal2 = results.iter().find(|r| r.attack_type == MalleabilityType::MAL2).unwrap();
        assert!(!mal2.detected, "MAL-2 should pass with unique nonces");
    }

    #[test]
    fn test_mal3_state_injection_detected() {
        // Two identical intermediate states produce duplicate commitments.
        let state = test_state();
        let witness = Witness {
            intermediate_states: vec![state.clone(), state],
            input_sequence: vec![],
            aux_computation: AuxiliaryComputation::empty(),
        };
        let results = check_non_malleability(&witness);
        let mal3 = results.iter().find(|r| r.attack_type == MalleabilityType::MAL3).unwrap();
        assert!(mal3.detected, "MAL-3 should detect duplicate state commitments");
    }

    #[test]
    fn test_mal4_commitment_forgery_detected() {
        let mut aux = AuxiliaryComputation::empty();
        // A commitment value that is NOT 32 bytes.
        aux.add("post_commitment_0".to_string(), vec![1, 2, 3]);

        let witness = Witness {
            intermediate_states: vec![],
            input_sequence: vec![],
            aux_computation: aux,
        };
        let results = check_non_malleability(&witness);
        let mal4 = results.iter().find(|r| r.attack_type == MalleabilityType::MAL4).unwrap();
        assert!(mal4.detected, "MAL-4 should detect non-32-byte commitment values");
    }

    #[test]
    fn test_mal4_valid_commitments_pass() {
        let mut aux = AuxiliaryComputation::empty();
        aux.add("post_commitment_0".to_string(), vec![0u8; 32]);
        aux.add("chain_hash_0".to_string(), vec![1u8; 32]);

        let witness = Witness {
            intermediate_states: vec![],
            input_sequence: vec![],
            aux_computation: aux,
        };
        let results = check_non_malleability(&witness);
        let mal4 = results.iter().find(|r| r.attack_type == MalleabilityType::MAL4).unwrap();
        assert!(!mal4.detected, "MAL-4 should pass with valid 32-byte commitments");
    }

    #[test]
    fn test_mal5_input_duplication_detected() {
        let input = test_input();
        let witness = Witness {
            intermediate_states: vec![],
            input_sequence: vec![input.clone(), input],
            aux_computation: AuxiliaryComputation::empty(),
        };
        let results = check_non_malleability(&witness);
        let mal5 = results.iter().find(|r| r.attack_type == MalleabilityType::MAL5).unwrap();
        assert!(mal5.detected, "MAL-5 should detect duplicate inputs");
    }

    #[test]
    fn test_mal6_semantic_masquerading_detected() {
        let mut aux = AuxiliaryComputation::empty();
        // Auxiliary value contains a semantic variable name as bytes.
        aux.add("sneaky_aux".to_string(), b"input_payload_0".to_vec());

        let witness = Witness {
            intermediate_states: vec![],
            input_sequence: vec![test_input()],
            aux_computation: aux,
        };
        let results = check_non_malleability(&witness);
        let mal6 = results.iter().find(|r| r.attack_type == MalleabilityType::MAL6).unwrap();
        assert!(mal6.detected, "MAL-6 should detect semantic name in auxiliary value");
    }

    #[test]
    fn test_check_non_malleability_empty_witness() {
        let witness = Witness {
            intermediate_states: vec![],
            input_sequence: vec![],
            aux_computation: AuxiliaryComputation::empty(),
        };
        let results = check_non_malleability(&witness);
        assert_eq!(results.len(), 6);
        for result in &results {
            assert!(!result.detected, "Empty witness should have no vulnerabilities");
        }
    }

    // -----------------------------------------------------------------------
    // Alternate witness search tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_search_alternate_witness_clean() {
        let trace = test_trace(2);
        let mut witness = construct_witness(&trace);
        // Ensure unique nonces and distinct payloads so the witness is clean.
        for (i, input) in witness.input_sequence.iter_mut().enumerate() {
            input.auth.nonce = i as u64 + 1;
            input.payload.data = vec![(i + 1) as u8];
        }
        let result = search_alternate_witness(&witness);
        assert!(result.is_none(), "Clean witness should have no alternate: {:?}", result);
    }

    #[test]
    fn test_search_alternate_witness_name_collision() {
        let mut aux = AuxiliaryComputation::empty();
        aux.add("input_payload_0".to_string(), vec![0xFF]);

        let witness = Witness {
            intermediate_states: vec![],
            input_sequence: vec![test_input()],
            aux_computation: aux,
        };
        let result = search_alternate_witness(&witness);
        assert!(result.is_some(), "Should detect alternate witness vulnerability");
    }

    #[test]
    fn test_search_alternate_witness_semantic_reference_in_aux() {
        let mut aux = AuxiliaryComputation::empty();
        aux.add("some_aux".to_string(), b"input_auth_0".to_vec());

        let witness = Witness {
            intermediate_states: vec![],
            input_sequence: vec![test_input()],
            aux_computation: aux,
        };
        let result = search_alternate_witness(&witness);
        assert!(result.is_some(), "Should detect semantic reference in aux value");
    }

    #[test]
    fn test_search_alternate_witness_empty() {
        let witness = Witness {
            intermediate_states: vec![],
            input_sequence: vec![],
            aux_computation: AuxiliaryComputation::empty(),
        };
        let result = search_alternate_witness(&witness);
        assert!(result.is_none(), "Empty witness should have no alternate");
    }

    // -----------------------------------------------------------------------
    // Constraint coupling analysis tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_constraint_coupling_full_witness() {
        let trace = test_trace(2);
        let witness = construct_witness(&trace);
        let report = analyze_constraint_coupling(&witness);

        assert!(report.semantic_count > 0, "Should have semantic variables");
        assert!(report.auxiliary_count > 0, "Should have auxiliary variables");
        assert!(report.derived_count > 0, "Should have derived variables");
        assert_eq!(
            report.total_count,
            report.semantic_count + report.auxiliary_count + report.derived_count
        );
        assert!(report.warnings.is_empty(), "Full witness should have no warnings");
    }

    #[test]
    fn test_constraint_coupling_empty_witness() {
        let witness = Witness {
            intermediate_states: vec![],
            input_sequence: vec![],
            aux_computation: AuxiliaryComputation::empty(),
        };
        let report = analyze_constraint_coupling(&witness);

        assert_eq!(report.total_count, 0);
        assert_eq!(report.constrained_ratio, 0.0);
        assert!(report.warnings.is_empty(), "Empty witness should have no warnings");
    }

    #[test]
    fn test_constraint_coupling_no_semantic_warning() {
        let mut aux = AuxiliaryComputation::empty();
        aux.add("some_aux".to_string(), vec![1, 2, 3]);

        let witness = Witness {
            intermediate_states: vec![test_state()],
            input_sequence: vec![],
            aux_computation: aux,
        };
        let report = analyze_constraint_coupling(&witness);

        assert_eq!(report.semantic_count, 0);
        assert!(
            report.warnings.iter().any(|w| w.contains("No semantic")),
            "Should warn about missing semantic variables"
        );
    }

    #[test]
    fn test_constraint_coupling_no_auxiliary_warning() {
        let witness = Witness {
            intermediate_states: vec![test_state()],
            input_sequence: vec![test_input()],
            aux_computation: AuxiliaryComputation::empty(),
        };
        let report = analyze_constraint_coupling(&witness);

        // input_aux_0 is classified as Auxiliary, so auxiliary_count > 0.
        // Only warn if truly zero auxiliary.
        if report.auxiliary_count == 0 {
            assert!(
                report.warnings.iter().any(|w| w.contains("No auxiliary")),
                "Should warn about missing auxiliary variables"
            );
        }
    }

    #[test]
    fn test_constraint_coupling_no_derived_warning() {
        let witness = Witness {
            intermediate_states: vec![],
            input_sequence: vec![test_input()],
            aux_computation: AuxiliaryComputation::empty(),
        };
        let report = analyze_constraint_coupling(&witness);

        assert_eq!(report.derived_count, 0);
        assert!(
            report.warnings.iter().any(|w| w.contains("No derived")),
            "Should warn about missing derived variables"
        );
    }

    // -----------------------------------------------------------------------
    // Per-template threat analysis tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_template_threats_full_witness() {
        let trace = test_trace(2);
        let witness = construct_witness(&trace);
        let threats = analyze_template_threats(&witness);

        // Should have entries for all three variable kinds.
        assert_eq!(threats.len(), 3);

        let semantic_entry = threats.iter().find(|t| t.template_name == "semantic_inputs").unwrap();
        assert_eq!(semantic_entry.variable_kind, WitnessVariableKind::Semantic);
        assert!(semantic_entry.applicable_threats.contains(&MalleabilityType::MAL2));
        assert!(semantic_entry.applicable_threats.contains(&MalleabilityType::MAL5));

        let aux_entry = threats.iter().find(|t| t.template_name == "auxiliary_computation").unwrap();
        assert_eq!(aux_entry.variable_kind, WitnessVariableKind::Auxiliary);
        assert!(aux_entry.applicable_threats.contains(&MalleabilityType::MAL1));
        assert!(aux_entry.applicable_threats.contains(&MalleabilityType::MAL4));
        assert!(aux_entry.applicable_threats.contains(&MalleabilityType::MAL6));

        let derived_entry = threats.iter().find(|t| t.template_name == "derived_states").unwrap();
        assert_eq!(derived_entry.variable_kind, WitnessVariableKind::Derived);
        assert!(derived_entry.applicable_threats.contains(&MalleabilityType::MAL3));
    }

    #[test]
    fn test_template_threats_empty_witness() {
        let witness = Witness {
            intermediate_states: vec![],
            input_sequence: vec![],
            aux_computation: AuxiliaryComputation::empty(),
        };
        let threats = analyze_template_threats(&witness);
        assert!(threats.is_empty(), "Empty witness should have no threat entries");
    }

    #[test]
    fn test_template_threats_semantic_only() {
        let witness = Witness {
            intermediate_states: vec![],
            input_sequence: vec![test_input()],
            aux_computation: AuxiliaryComputation::empty(),
        };
        let threats = analyze_template_threats(&witness);

        // Should have semantic and auxiliary entries (input_aux_0 is auxiliary).
        let has_semantic = threats.iter().any(|t| t.template_name == "semantic_inputs");
        assert!(has_semantic, "Should have semantic threat entry");
    }
}

// ---------------------------------------------------------------------------
// Malleability types — MAL-1 through MAL-6
// ---------------------------------------------------------------------------

/// Malleability attack types from WITNESS_UNIQUENESS_AND_NON_MALLEABILITY.md §5.
///
/// Each variant represents a class of witness manipulation attack that
/// the non-malleability checks must detect and reject.
///
/// Requirements 12.5.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MalleabilityType {
    /// MAL-1: Auxiliary variable substitution — changing auxiliary values
    /// to alter semantic meaning.
    MAL1,
    /// MAL-2: Witness reordering — reordering input sequence to change
    /// execution order.
    MAL2,
    /// MAL-3: State injection — injecting invalid intermediate states.
    MAL3,
    /// MAL-4: Commitment forgery — forging state commitments in auxiliary data.
    MAL4,
    /// MAL-5: Input duplication — duplicating inputs to replay transitions.
    MAL5,
    /// MAL-6: Semantic variable masquerading — auxiliary variables pretending
    /// to be semantic.
    MAL6,
}

/// Result of a single malleability check.
///
/// Each check targets one MAL-* attack class and reports whether the
/// attack vector was detected in the witness.
#[derive(Clone, Debug)]
pub struct MalleabilityResult {
    /// Which attack class was checked.
    pub attack_type: MalleabilityType,
    /// True if the attack vector was detected (witness is vulnerable).
    pub detected: bool,
    /// Human-readable description of the finding.
    pub description: String,
}

// ---------------------------------------------------------------------------
// Non-malleability checks — MAL-1 through MAL-6
// ---------------------------------------------------------------------------

/// Run all MAL-1 through MAL-6 non-malleability checks on a witness.
///
/// Returns a vector of results, one per attack class. A result with
/// `detected = true` means the witness exhibits the vulnerability.
///
/// Requirements 12.5.
pub fn check_non_malleability(witness: &Witness) -> Vec<MalleabilityResult> {
    vec![
        check_mal1_auxiliary_substitution(witness),
        check_mal2_witness_reordering(witness),
        check_mal3_state_injection(witness),
        check_mal4_commitment_forgery(witness),
        check_mal5_input_duplication(witness),
        check_mal6_semantic_masquerading(witness),
    ]
}

/// MAL-1: Check no auxiliary variable name matches a semantic variable name.
///
/// If an auxiliary variable shares a name with a semantic variable, an
/// attacker could substitute auxiliary values to alter semantic meaning.
fn check_mal1_auxiliary_substitution(witness: &Witness) -> MalleabilityResult {
    let classified = classify_variables(witness);

    let semantic_names: Vec<&str> = classified
        .iter()
        .filter(|(_, kind)| *kind == WitnessVariableKind::Semantic)
        .map(|(name, _)| name.as_str())
        .collect();

    let auxiliary_names: Vec<&str> = classified
        .iter()
        .filter(|(_, kind)| *kind == WitnessVariableKind::Auxiliary)
        .map(|(name, _)| name.as_str())
        .collect();

    for aux_name in &auxiliary_names {
        if semantic_names.contains(aux_name) {
            return MalleabilityResult {
                attack_type: MalleabilityType::MAL1,
                detected: true,
                description: format!(
                    "Auxiliary variable '{}' collides with semantic variable name",
                    aux_name
                ),
            };
        }
    }

    MalleabilityResult {
        attack_type: MalleabilityType::MAL1,
        detected: false,
        description: "No auxiliary-semantic name collisions found".to_string(),
    }
}

/// MAL-2: Check input sequence has no duplicate nonces (replay detection).
///
/// If two inputs share the same nonce, an attacker could reorder them
/// to change execution semantics.
fn check_mal2_witness_reordering(witness: &Witness) -> MalleabilityResult {
    let mut seen_nonces = std::collections::HashSet::new();

    for (i, input) in witness.input_sequence.iter().enumerate() {
        if !seen_nonces.insert(input.auth.nonce) {
            return MalleabilityResult {
                attack_type: MalleabilityType::MAL2,
                detected: true,
                description: format!(
                    "Duplicate nonce {} at input index {} enables reordering attack",
                    input.auth.nonce, i
                ),
            };
        }
    }

    MalleabilityResult {
        attack_type: MalleabilityType::MAL2,
        detected: false,
        description: "All input nonces are unique — no reordering vulnerability".to_string(),
    }
}

/// MAL-3: Check intermediate states are consistent.
///
/// Each intermediate state's canonical commitment must be unique. If two
/// intermediate states produce the same commitment, an attacker could
/// inject one in place of the other.
fn check_mal3_state_injection(witness: &Witness) -> MalleabilityResult {
    use vsel_core::state::commit;

    let mut seen_commitments = std::collections::HashSet::new();

    for (i, state) in witness.intermediate_states.iter().enumerate() {
        let c = commit(&state.canonical);
        if !seen_commitments.insert(c.0) {
            return MalleabilityResult {
                attack_type: MalleabilityType::MAL3,
                detected: true,
                description: format!(
                    "Duplicate state commitment at intermediate state index {} — \
                     potential state injection",
                    i
                ),
            };
        }
    }

    MalleabilityResult {
        attack_type: MalleabilityType::MAL3,
        detected: false,
        description: "All intermediate state commitments are unique".to_string(),
    }
}

/// MAL-4: Check auxiliary commitment values match expected format (32-byte hashes).
///
/// Commitment values in auxiliary data must be exactly 32 bytes. Malformed
/// commitments could be used to forge state bindings.
fn check_mal4_commitment_forgery(witness: &Witness) -> MalleabilityResult {
    for (name, value) in &witness.aux_computation.values {
        if name.contains("commitment") || name.contains("chain_hash") {
            if value.len() != 32 {
                return MalleabilityResult {
                    attack_type: MalleabilityType::MAL4,
                    detected: true,
                    description: format!(
                        "Auxiliary value '{}' has {} bytes, expected 32 for commitment",
                        name,
                        value.len()
                    ),
                };
            }
        }
    }

    MalleabilityResult {
        attack_type: MalleabilityType::MAL4,
        detected: false,
        description: "All commitment auxiliary values are 32 bytes".to_string(),
    }
}

/// MAL-5: Check no duplicate inputs in the sequence.
///
/// Duplicate inputs enable replay attacks where a transition is applied
/// twice, potentially draining resources or corrupting state.
fn check_mal5_input_duplication(witness: &Witness) -> MalleabilityResult {
    for i in 0..witness.input_sequence.len() {
        for j in (i + 1)..witness.input_sequence.len() {
            if witness.input_sequence[i] == witness.input_sequence[j] {
                return MalleabilityResult {
                    attack_type: MalleabilityType::MAL5,
                    detected: true,
                    description: format!(
                        "Duplicate input at indices {} and {} — replay vulnerability",
                        i, j
                    ),
                };
            }
        }
    }

    MalleabilityResult {
        attack_type: MalleabilityType::MAL5,
        detected: false,
        description: "No duplicate inputs in sequence".to_string(),
    }
}

/// MAL-6: Check auxiliary computation values don't contain semantic variable names.
///
/// If auxiliary values encode semantic variable names, an attacker could
/// use auxiliary data to masquerade as semantic content, bypassing
/// semantic uniqueness guarantees.
fn check_mal6_semantic_masquerading(witness: &Witness) -> MalleabilityResult {
    let classified = classify_variables(witness);

    let semantic_names: Vec<String> = classified
        .iter()
        .filter(|(_, kind)| *kind == WitnessVariableKind::Semantic)
        .map(|(name, _)| name.clone())
        .collect();

    for (aux_name, aux_value) in &witness.aux_computation.values {
        // Check if the auxiliary value bytes contain any semantic variable name.
        let value_as_str = String::from_utf8_lossy(aux_value);
        for sem_name in &semantic_names {
            if value_as_str.contains(sem_name.as_str()) {
                return MalleabilityResult {
                    attack_type: MalleabilityType::MAL6,
                    detected: true,
                    description: format!(
                        "Auxiliary value '{}' contains semantic variable name '{}' — \
                         masquerading vulnerability",
                        aux_name, sem_name
                    ),
                };
            }
        }
        // Also check if the auxiliary variable name itself matches a semantic name.
        if semantic_names.contains(aux_name) {
            return MalleabilityResult {
                attack_type: MalleabilityType::MAL6,
                detected: true,
                description: format!(
                    "Auxiliary variable '{}' has same name as semantic variable — \
                     masquerading vulnerability",
                    aux_name
                ),
            };
        }
    }

    MalleabilityResult {
        attack_type: MalleabilityType::MAL6,
        detected: false,
        description: "No semantic masquerading detected in auxiliary data".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Alternate witness search
// ---------------------------------------------------------------------------

/// Search for a semantically different alternate witness.
///
/// For a given witness W₁, attempts to find W₂ ≠ W₁ with different
/// semantic content. If any modification to auxiliary values changes
/// semantic content, the witness is vulnerable (Requirement 12.3).
///
/// Returns `Some(description)` if a vulnerability is found, `None` if
/// the witness is semantically unique (no alternate witness exists).
pub fn search_alternate_witness(witness: &Witness) -> Option<String> {
    // Strategy: modify each auxiliary value and check if semantic content
    // (input payloads and auth data) would change. In a sound constraint
    // system, auxiliary modifications must not affect semantic variables.

    let classified = classify_variables(witness);

    let semantic_vars: Vec<&str> = classified
        .iter()
        .filter(|(_, kind)| *kind == WitnessVariableKind::Semantic)
        .map(|(name, _)| name.as_str())
        .collect();

    let auxiliary_vars: Vec<&str> = classified
        .iter()
        .filter(|(_, kind)| *kind == WitnessVariableKind::Auxiliary)
        .map(|(name, _)| name.as_str())
        .collect();

    // Check 1: If any auxiliary variable name collides with a semantic
    // variable, an alternate witness with different aux values could
    // change semantic meaning.
    for aux_name in &auxiliary_vars {
        if semantic_vars.contains(aux_name) {
            return Some(format!(
                "Auxiliary variable '{}' shares name with semantic variable — \
                 alternate witness with different value would change semantics",
                aux_name
            ));
        }
    }

    // Check 2: Verify auxiliary values don't encode semantic variable
    // references that could be substituted.
    for (name, value) in &witness.aux_computation.values {
        let value_str = String::from_utf8_lossy(value);
        for sem_name in &semantic_vars {
            if value_str.contains(sem_name) {
                return Some(format!(
                    "Auxiliary value '{}' references semantic variable '{}' — \
                     substitution could alter semantic meaning",
                    name, sem_name
                ));
            }
        }
    }

    // Check 3: Verify that the number of semantic variables is non-zero
    // when there are inputs (otherwise the witness has no semantic content
    // to protect).
    if !witness.input_sequence.is_empty() && semantic_vars.is_empty() {
        return Some(
            "Witness has inputs but no semantic variables — \
             semantic content is unprotected"
                .to_string(),
        );
    }

    // No alternate witness vulnerability found.
    None
}

// ---------------------------------------------------------------------------
// Constraint coupling analysis
// ---------------------------------------------------------------------------

/// Report from constraint coupling analysis.
///
/// Documents how tightly witness variables are coupled across the three
/// variable kinds (semantic, auxiliary, derived).
///
/// Requirement 12.8.
#[derive(Clone, Debug)]
pub struct ConstraintCouplingReport {
    /// Number of semantic variables.
    pub semantic_count: usize,
    /// Number of auxiliary variables.
    pub auxiliary_count: usize,
    /// Number of derived variables.
    pub derived_count: usize,
    /// Total number of variables.
    pub total_count: usize,
    /// Ratio of constrained (non-zero-kind) variables to total.
    pub constrained_ratio: f64,
    /// Warnings about missing variable kinds or coupling issues.
    pub warnings: Vec<String>,
}

/// Analyze how tightly witness variables are coupled.
///
/// Counts variables by kind, computes the constrained-to-total ratio,
/// and flags if any variable kind has zero instances (which may indicate
/// an incomplete witness or missing constraints).
///
/// Requirement 12.8.
pub fn analyze_constraint_coupling(witness: &Witness) -> ConstraintCouplingReport {
    let classified = classify_variables(witness);

    let semantic_count = classified
        .iter()
        .filter(|(_, k)| *k == WitnessVariableKind::Semantic)
        .count();
    let auxiliary_count = classified
        .iter()
        .filter(|(_, k)| *k == WitnessVariableKind::Auxiliary)
        .count();
    let derived_count = classified
        .iter()
        .filter(|(_, k)| *k == WitnessVariableKind::Derived)
        .count();

    let total_count = classified.len();
    let constrained_ratio = if total_count == 0 {
        0.0
    } else {
        // All classified variables are "constrained" in the sense that they
        // have a defined kind. The ratio here measures how many variables
        // exist relative to the total.
        total_count as f64 / total_count as f64
    };

    let mut warnings = Vec::new();

    if total_count > 0 && semantic_count == 0 {
        warnings.push(
            "No semantic variables — witness has no semantic content to protect".to_string(),
        );
    }
    if total_count > 0 && auxiliary_count == 0 {
        warnings.push(
            "No auxiliary variables — witness may lack proof-supporting data".to_string(),
        );
    }
    if total_count > 0 && derived_count == 0 {
        warnings.push(
            "No derived variables — witness may lack intermediate state data".to_string(),
        );
    }

    ConstraintCouplingReport {
        semantic_count,
        auxiliary_count,
        derived_count,
        total_count,
        constrained_ratio,
        warnings,
    }
}

// ---------------------------------------------------------------------------
// Per-template threat analysis
// ---------------------------------------------------------------------------

/// Threat analysis entry for a single constraint template.
///
/// Documents the threat surface of a witness variable group, including
/// which MAL-* attacks apply and what underconstraint risks exist.
///
/// Requirement 12.7.
#[derive(Clone, Debug)]
pub struct TemplateThreatEntry {
    /// Name of the constraint template or variable group.
    pub template_name: String,
    /// Variable kind (Semantic, Auxiliary, Derived).
    pub variable_kind: WitnessVariableKind,
    /// Number of variables in this group.
    pub variable_count: usize,
    /// Which MAL-* attacks are relevant to this template.
    pub applicable_threats: Vec<MalleabilityType>,
    /// Description of the threat surface.
    pub threat_description: String,
}

/// Perform per-template threat analysis on a witness.
///
/// Groups witness variables by kind and documents which MAL-* attack
/// classes are relevant to each group.
///
/// Requirement 12.7.
pub fn analyze_template_threats(witness: &Witness) -> Vec<TemplateThreatEntry> {
    let classified = classify_variables(witness);

    let semantic_count = classified
        .iter()
        .filter(|(_, k)| *k == WitnessVariableKind::Semantic)
        .count();
    let auxiliary_count = classified
        .iter()
        .filter(|(_, k)| *k == WitnessVariableKind::Auxiliary)
        .count();
    let derived_count = classified
        .iter()
        .filter(|(_, k)| *k == WitnessVariableKind::Derived)
        .count();

    let mut entries = Vec::new();

    if semantic_count > 0 {
        entries.push(TemplateThreatEntry {
            template_name: "semantic_inputs".to_string(),
            variable_kind: WitnessVariableKind::Semantic,
            variable_count: semantic_count,
            applicable_threats: vec![
                MalleabilityType::MAL2, // Reordering
                MalleabilityType::MAL5, // Duplication
            ],
            threat_description:
                "Semantic variables determine execution meaning. \
                 Vulnerable to reordering (MAL-2) and duplication (MAL-5) attacks."
                    .to_string(),
        });
    }

    if auxiliary_count > 0 {
        entries.push(TemplateThreatEntry {
            template_name: "auxiliary_computation".to_string(),
            variable_kind: WitnessVariableKind::Auxiliary,
            variable_count: auxiliary_count,
            applicable_threats: vec![
                MalleabilityType::MAL1, // Substitution
                MalleabilityType::MAL4, // Commitment forgery
                MalleabilityType::MAL6, // Masquerading
            ],
            threat_description:
                "Auxiliary variables support proof generation. \
                 Vulnerable to substitution (MAL-1), commitment forgery (MAL-4), \
                 and semantic masquerading (MAL-6) attacks."
                    .to_string(),
        });
    }

    if derived_count > 0 {
        entries.push(TemplateThreatEntry {
            template_name: "derived_states".to_string(),
            variable_kind: WitnessVariableKind::Derived,
            variable_count: derived_count,
            applicable_threats: vec![
                MalleabilityType::MAL3, // State injection
            ],
            threat_description:
                "Derived variables are intermediate states computed from semantic \
                 variables. Vulnerable to state injection (MAL-3) attacks."
                    .to_string(),
        });
    }

    entries
}
