//! Property-based tests for the VSEL Composition Layer (vsel-composition).
//!
//! Uses `proptest` to verify correctness properties derived from
//! COMPOSITION_MODEL.md, ASSUME_GUARANTEE_MODEL.md, Requirements 11.
//!
//! **Property 48: Compositional Soundness (TP-14)** —
//!   `Valid(M_A) ∧ Valid(M_B) ∧ Compatible(M_A, M_B) ⟹ Valid(M_A ∘ M_B)`
//! **Validates: Requirements 11.2, 11.5**
//!
//! **Property 49: Cross-System Invariant Preservation** —
//!   `Total_A + Total_B = constant` (CI-1)
//! **Validates: Requirements 11.3, 11.9**
//!
//! **Property 50: Trace Composition Ordering** —
//!   ordering preserved within each trace
//! **Validates: Requirements 11.6**
//!
//! **Property 51: Proof Composition Validity** —
//!   `verify(π_ab) ⟹ valid_trace_a ∧ valid_trace_b ∧ G_cross`
//! **Validates: Requirements 11.4**
//!
//! **Property 52: Backward-Compatible Upgrades** —
//!   `A(M^v2) ⊆ A(M^v1)`, `G(M^v2) ⊇ G(M^v1)`
//! **Validates: Requirements 11.7**

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use proptest::prelude::*;

use vsel_composition::contracts::{
    check_backward_compatibility, define_contract, verify_composition, CompatibilityResult,
    CompatibilityViolationKind, CompositionResult, ContractProperty, SubsystemContract,
    SystemDefinition,
};
use vsel_composition::cross_invariants::{
    check_all_cross_invariants, check_ci1_resource_conservation, CrossInvariantConfig,
};
use vsel_composition::proof_compose::compose_proofs;
use vsel_composition::trace_merge::merge_traces;
use vsel_core::input::*;
use vsel_core::observable::{Observable, TransitionStatus};
use vsel_core::state::*;
use vsel_core::transition::TransitionClass;
use vsel_core::types::*;
use vsel_crypto::domain::proof_tag;
use vsel_proof::prover::{Proof, ProofCommitments, ProofMetadata};
use vsel_proof::public_inputs::PublicInputs;
use vsel_trace::engine::{Trace, TraceEntry};

// ===========================================================================
// Arbitrary strategies
// ===========================================================================

/// Generate a set of property ID strings from a fixed pool.
fn arb_property_set(max_size: usize) -> impl Strategy<Value = BTreeSet<String>> {
    let pool = vec![
        "valid_state",
        "determinism",
        "closure",
        "resource_conservation",
        "encoding_injectivity",
        "trace_completeness",
        "bounded_mutation",
        "authorization",
        "invariant_preservation",
        "semantic_mapping",
        "constraint_soundness",
        "proof_binding",
    ];
    prop::collection::btree_set(
        prop::sample::select(pool).prop_map(|s| s.to_string()),
        0..=max_size,
    )
}

/// Generate an arbitrary SubsystemContract.
fn arb_contract() -> impl Strategy<Value = SubsystemContract> {
    (
        arb_property_set(5),
        arb_property_set(5),
        arb_property_set(3),
        arb_property_set(3),
        arb_property_set(3),
    )
        .prop_map(|(assumes, guarantees, exports, effects, forbids)| {
            SubsystemContract {
                assumes,
                guarantees,
                exports,
                effects,
                forbids,
                temporal: vec![],
            }
        })
}

/// Generate a pair of compatible contracts where G(A) ⊇ A(B), G(B) ⊇ A(A),
/// Eff(A) ∩ F(B) = ∅, Eff(B) ∩ F(A) = ∅.
fn arb_compatible_contracts() -> impl Strategy<Value = (SubsystemContract, SubsystemContract)> {
    // Use disjoint pools for effects/forbids to guarantee no conflicts.
    let effect_pool_a = vec!["eff_a1", "eff_a2", "eff_a3"];
    let effect_pool_b = vec!["eff_b1", "eff_b2", "eff_b3"];
    let shared_pool: Vec<&str> = vec![
        "valid_state",
        "determinism",
        "closure",
        "resource_conservation",
    ];

    (
        prop::collection::btree_set(
            prop::sample::select(shared_pool.clone()).prop_map(|s| s.to_string()),
            0..=3,
        ),
        prop::collection::btree_set(
            prop::sample::select(shared_pool).prop_map(|s| s.to_string()),
            0..=3,
        ),
        prop::collection::btree_set(
            prop::sample::select(effect_pool_a).prop_map(|s| s.to_string()),
            0..=2,
        ),
        prop::collection::btree_set(
            prop::sample::select(effect_pool_b).prop_map(|s| s.to_string()),
            0..=2,
        ),
    )
        .prop_map(|(assumes_a, assumes_b, effects_a, effects_b)| {
            // A guarantees everything B assumes, and vice versa.
            let guarantees_a = assumes_b.clone();
            let guarantees_b = assumes_a.clone();
            // Forbids are from the OTHER system's effect pool (disjoint from own effects).
            let a = SubsystemContract {
                assumes: assumes_a,
                guarantees: guarantees_a,
                exports: BTreeSet::new(),
                effects: effects_a,
                forbids: BTreeSet::new(), // no forbids on B's effects
                temporal: vec![],
            };
            let b = SubsystemContract {
                assumes: assumes_b,
                guarantees: guarantees_b,
                exports: BTreeSet::new(),
                effects: effects_b,
                forbids: BTreeSet::new(),
                temporal: vec![],
            };
            (a, b)
        })
}

fn _arb_bytes32() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

fn _arb_hash() -> impl Strategy<Value = Hash> {
    _arb_bytes32().prop_map(Hash)
}

fn test_domain_tag() -> DomainTag {
    let mut h = [0u8; 32];
    h[0] = 0xAB;
    DomainTag(Hash(h))
}

fn test_version() -> ProtocolVersion {
    ProtocolVersion {
        major: 1,
        minor: 0,
        patch: 0,
    }
}

fn minimal_canonical(total_supply: u128) -> CanonicalState {
    CanonicalState {
        accounts: BTreeMap::new(),
        storage: BTreeMap::new(),
        system_data: SystemData {
            protocol_version: test_version(),
            total_supply,
            parameters: BTreeMap::new(),
        },
    }
}

fn build_state(total_supply: u128, timestamp: u64) -> State {
    let c = minimal_canonical(total_supply);
    let d = derive(&c);
    let env = Environment {
        timestamp,
        block_height: 1,
        execution_domain: test_domain_tag(),
    };
    let econ = derive_economic(&c, &env);
    let meta = TraceMetadata {
        sequence_index: 0,
        previous_commitment: Hash([0u8; 32]),
        epoch: 0,
        timestamp,
    };
    State {
        canonical: c,
        derived: d,
        environment: env,
        economic: econ,
        metadata: meta,
    }
}

fn make_hash(seed: u8) -> Hash {
    let mut h = [0u8; 32];
    h[0] = seed;
    Hash(h)
}

fn make_observable(gas: u64) -> Observable {
    Observable {
        transition_class: TransitionClass::Update,
        outputs: vec![],
        gas_used: gas,
        status: TransitionStatus::Success,
    }
}

fn make_proof(root_init: Hash, root_final: Hash, gas: u64) -> Proof {
    Proof {
        commitments: ProofCommitments {
            trace_commitment: make_hash(0x10),
            witness_commitment: make_hash(0x20),
            constraint_commitment: make_hash(0x30),
        },
        proof_data: vec![0xDE, 0xAD],
        public_inputs: PublicInputs {
            root_init,
            root_final,
            observables: vec![make_observable(gas)],
            domain: test_domain_tag(),
            version: test_version(),
        },
        metadata: ProofMetadata {
            prover_version: "0.1.0-test".to_string(),
            timestamp: 0,
            domain: proof_tag(),
            proof_system: "stark-placeholder".to_string(),
        },
    }
}

fn test_input() -> Input {
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
            domain: test_domain_tag(),
        },
        aux: AuxiliaryData {
            data: vec![0xAA, 0xBB],
        },
    }
}

fn test_observable() -> Observable {
    Observable {
        transition_class: TransitionClass::Update,
        outputs: vec![],
        gas_used: 21_000,
        status: TransitionStatus::Success,
    }
}

fn make_trace(timestamps: &[u64], seed: u8) -> Trace {
    let initial_ts = timestamps.first().copied().unwrap_or(1000);
    let initial_state = build_state(0, initial_ts);
    let init_commit = commit(&initial_state.canonical);
    let mut entries = Vec::new();

    for (i, &ts) in timestamps.iter().enumerate() {
        let pre_commit = if i == 0 {
            init_commit.clone()
        } else {
            let mut h = [0u8; 32];
            h[0] = seed.wrapping_add(i as u8);
            Hash(h)
        };
        let mut post_hash = [0u8; 32];
        post_hash[0] = seed.wrapping_add((i + 1) as u8);
        let mut chain = [0u8; 32];
        chain[0] = seed.wrapping_add((i + 100) as u8);

        entries.push(TraceEntry {
            index: i as u64,
            pre_state_commitment: pre_commit,
            input: test_input(),
            post_state_commitment: Hash(post_hash),
            observable: test_observable(),
            environment: Environment {
                timestamp: ts,
                block_height: (i + 1) as u64,
                execution_domain: test_domain_tag(),
            },
            chain_hash: Hash(chain),
        });
    }

    let final_commitment = entries
        .last()
        .map(|e| e.chain_hash.clone())
        .unwrap_or(Hash([0u8; 32]));

    Trace {
        entries,
        initial_state,
        commitment: final_commitment,
    }
}

// ===========================================================================
// Property 48: Compositional Soundness (TP-14)
//   Valid(M_A) ∧ Valid(M_B) ∧ Compatible(M_A, M_B) ⟹ Valid(M_A ∘ M_B)
// Validates: Requirements 11.2, 11.5
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Compatible contracts always compose successfully.
    #[test]
    fn prop48_compatible_contracts_compose_validly(
        (a, b) in arb_compatible_contracts()
    ) {
        let result = verify_composition(&a, &b);
        prop_assert_eq!(
            result,
            CompositionResult::Valid,
            "Compatible contracts must compose: A={:?}, B={:?}",
            a, b
        );
    }

    /// Composition is valid iff all four conditions hold:
    ///   G(A) ⊇ A(B), G(B) ⊇ A(A), Eff(A) ∩ F(B) = ∅, Eff(B) ∩ F(A) = ∅
    #[test]
    fn prop48_composition_validity_matches_conditions(
        a in arb_contract(),
        b in arb_contract(),
    ) {
        let g_a_covers_a_b = b.assumes.is_subset(&a.guarantees);
        let g_b_covers_a_a = a.assumes.is_subset(&b.guarantees);
        let eff_a_disjoint_f_b = a.effects.is_disjoint(&b.forbids);
        let eff_b_disjoint_f_a = b.effects.is_disjoint(&a.forbids);

        let all_conditions = g_a_covers_a_b
            && g_b_covers_a_a
            && eff_a_disjoint_f_b
            && eff_b_disjoint_f_a;

        let result = verify_composition(&a, &b);

        if all_conditions {
            // No temporal obligations in arb_contract, so all conditions ⟹ Valid.
            prop_assert_eq!(result, CompositionResult::Valid);
        } else {
            // At least one condition fails ⟹ Invalid.
            match result {
                CompositionResult::Invalid { violations } => {
                    prop_assert!(!violations.is_empty());
                }
                CompositionResult::Valid => {
                    // This can only happen if temporal checks pass despite
                    // structural failures — but our arb_contract has no
                    // temporal obligations, so this should not occur.
                    prop_assert!(false, "Expected Invalid but got Valid");
                }
            }
        }
    }

    /// define_contract round-trips: the contract's assumes/guarantees match
    /// the system definition's property IDs.
    #[test]
    fn prop48_define_contract_preserves_property_ids(
        assumed_ids in arb_property_set(5),
        guaranteed_ids in arb_property_set(5),
    ) {
        let system = SystemDefinition {
            name: "test".to_string(),
            assumed_properties: assumed_ids
                .iter()
                .map(|id| ContractProperty {
                    id: id.clone(),
                    description: "test".to_string(),
                })
                .collect(),
            guaranteed_properties: guaranteed_ids
                .iter()
                .map(|id| ContractProperty {
                    id: id.clone(),
                    description: "test".to_string(),
                })
                .collect(),
            exported_interfaces: vec![],
            state_effects: vec![],
            forbidden_interactions: vec![],
            temporal_obligations: vec![],
        };

        let contract = define_contract(&system);
        prop_assert_eq!(&contract.assumes, &assumed_ids);
        prop_assert_eq!(&contract.guarantees, &guaranteed_ids);
    }

    /// Composition with self: a contract composes with itself iff
    /// G(A) ⊇ A(A) and Eff(A) ∩ F(A) = ∅.
    #[test]
    fn prop48_self_composition_consistency(
        a in arb_contract(),
    ) {
        let result = verify_composition(&a, &a);
        let self_compatible = a.assumes.is_subset(&a.guarantees)
            && a.effects.is_disjoint(&a.forbids);

        if self_compatible {
            prop_assert_eq!(result, CompositionResult::Valid);
        } else {
            match result {
                CompositionResult::Invalid { .. } => { /* expected */ }
                CompositionResult::Valid => {
                    prop_assert!(false, "Expected Invalid for self-composition");
                }
            }
        }
    }
}

// ===========================================================================
// Property 49: Cross-System Invariant Preservation
//   Total_A + Total_B = constant (CI-1)
// Validates: Requirements 11.3, 11.9
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// CI-1: resource conservation holds when total supplies sum to expected.
    #[test]
    fn prop49_resource_conservation_holds(
        supply_a in 0u128..=500_000u128,
        timestamp in 1000u64..=2000u64,
    ) {
        let supply_b = 1_000_000u128 - supply_a;
        let state_a = build_state(supply_a, timestamp);
        let state_b = build_state(supply_b, timestamp);

        let result = check_ci1_resource_conservation(&state_a, &state_b, 1_000_000);
        prop_assert!(result.valid, "CI-1 should hold: {} + {} = 1_000_000", supply_a, supply_b);
    }

    /// CI-1: resource conservation fails when total supplies don't match.
    #[test]
    fn prop49_resource_conservation_detects_violation(
        supply_a in 0u128..=500_000u128,
        supply_b in 0u128..=500_000u128,
        expected in 1_000_001u128..=2_000_000u128,
    ) {
        let state_a = build_state(supply_a, 1000);
        let state_b = build_state(supply_b, 1000);
        let actual = supply_a + supply_b;

        // actual <= 1_000_000 < expected, so always a violation.
        let result = check_ci1_resource_conservation(&state_a, &state_b, expected);
        prop_assert!(!result.valid, "CI-1 should fail: {} + {} = {} != {}", supply_a, supply_b, actual, expected);
    }

    /// All cross-invariants pass for well-formed symmetric states.
    #[test]
    fn prop49_all_cross_invariants_pass_for_balanced_states(
        supply in 0u128..=500_000u128,
        timestamp in 1000u64..=2000u64,
    ) {
        let state_a = build_state(supply, timestamp);
        let state_b = build_state(supply, timestamp);
        let config = CrossInvariantConfig {
            expected_total: supply * 2,
            shared_keys: vec![],
            max_timestamp_drift: 300,
            max_exposure_ratio: 6000, // 60%
        };

        let result = check_all_cross_invariants(&state_a, &state_b, &config);
        prop_assert!(
            result.valid,
            "All cross-invariants should pass for balanced states: violations={:?}",
            result.violations
        );
    }
}

// ===========================================================================
// Property 50: Trace Composition Ordering
//   Ordering preserved within each trace after merge.
// Validates: Requirements 11.6
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Merged trace preserves both original traces intact.
    #[test]
    fn prop50_merge_preserves_original_traces(
        len_a in 0usize..=5,
        len_b in 0usize..=5,
    ) {
        let ts_a: Vec<u64> = (0..len_a).map(|i| 1000 + (i as u64) * 100).collect();
        let ts_b: Vec<u64> = (0..len_b).map(|i| 1050 + (i as u64) * 100).collect();

        let trace_a = make_trace(&ts_a, 0x10);
        let trace_b = make_trace(&ts_b, 0x20);
        let composed = merge_traces(&trace_a, &trace_b);

        prop_assert_eq!(composed.trace_a.entries.len(), trace_a.entries.len());
        prop_assert_eq!(composed.trace_b.entries.len(), trace_b.entries.len());
        prop_assert_eq!(composed.trace_a.commitment, trace_a.commitment);
        prop_assert_eq!(composed.trace_b.commitment, trace_b.commitment);
    }

    /// Entry ordering within each trace is preserved (indices are sequential).
    #[test]
    fn prop50_merge_preserves_entry_ordering(
        len_a in 1usize..=6,
        len_b in 1usize..=6,
    ) {
        let ts_a: Vec<u64> = (0..len_a).map(|i| 1000 + (i as u64) * 100).collect();
        let ts_b: Vec<u64> = (0..len_b).map(|i| 1050 + (i as u64) * 100).collect();

        let trace_a = make_trace(&ts_a, 0x10);
        let trace_b = make_trace(&ts_b, 0x20);
        let composed = merge_traces(&trace_a, &trace_b);

        // Verify sequential indices in trace A.
        for (i, entry) in composed.trace_a.entries.iter().enumerate() {
            prop_assert_eq!(entry.index, i as u64);
        }
        // Verify sequential indices in trace B.
        for (i, entry) in composed.trace_b.entries.iter().enumerate() {
            prop_assert_eq!(entry.index, i as u64);
        }
    }

    /// Merged commitment is deterministic for identical inputs.
    #[test]
    fn prop50_merge_commitment_deterministic(
        len_a in 1usize..=4,
        len_b in 1usize..=4,
    ) {
        let ts_a: Vec<u64> = (0..len_a).map(|i| 1000 + (i as u64) * 100).collect();
        let ts_b: Vec<u64> = (0..len_b).map(|i| 1050 + (i as u64) * 100).collect();

        let trace_a = make_trace(&ts_a, 0x10);
        let trace_b = make_trace(&ts_b, 0x20);

        let c1 = merge_traces(&trace_a, &trace_b);
        let c2 = merge_traces(&trace_a, &trace_b);

        prop_assert_eq!(c1.merged_commitment, c2.merged_commitment);
    }

    /// Sync points have sequential indices.
    #[test]
    fn prop50_sync_point_indices_sequential(
        len in 1usize..=5,
    ) {
        // Use identical timestamps to guarantee sync points.
        let ts: Vec<u64> = (0..len).map(|i| 1000 + (i as u64) * 100).collect();
        let trace_a = make_trace(&ts, 0x10);
        let trace_b = make_trace(&ts, 0x20);
        let composed = merge_traces(&trace_a, &trace_b);

        for (i, sp) in composed.sync_points.iter().enumerate() {
            prop_assert_eq!(sp.index, i as u64);
        }
    }
}

// ===========================================================================
// Property 51: Proof Composition Validity
//   verify(π_ab) ⟹ valid_trace_a ∧ valid_trace_b ∧ G_cross
// Validates: Requirements 11.4
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Composed proof preserves root_init from proof_a and root_final from proof_b.
    #[test]
    fn prop51_composed_proof_preserves_endpoints(
        seed_init in any::<u8>(),
        seed_mid in any::<u8>(),
        seed_final in any::<u8>(),
        gas_a in 1u64..=100_000,
        gas_b in 1u64..=100_000,
        gas_cross in 1u64..=100_000,
    ) {
        let root_init = make_hash(seed_init);
        let root_mid = make_hash(seed_mid);
        let root_final = make_hash(seed_final);

        let proof_a = make_proof(root_init.clone(), root_mid.clone(), gas_a);
        let proof_b = make_proof(root_mid, root_final.clone(), gas_b);
        let proof_cross = make_proof(root_init.clone(), root_final.clone(), gas_cross);

        let composed = compose_proofs(&proof_a, &proof_b, &proof_cross)
            .expect("composition should succeed");

        prop_assert_eq!(&composed.public_inputs.root_init, &root_init);
        prop_assert_eq!(&composed.public_inputs.root_final, &root_final);
    }

    /// Composed proof concatenates observables from all three proofs in order.
    #[test]
    fn prop51_composed_proof_concatenates_observables(
        gas_a in 1u64..=100_000,
        gas_b in 1u64..=100_000,
        gas_cross in 1u64..=100_000,
    ) {
        let proof_a = make_proof(make_hash(0), make_hash(1), gas_a);
        let proof_b = make_proof(make_hash(1), make_hash(2), gas_b);
        let proof_cross = make_proof(make_hash(0), make_hash(2), gas_cross);

        let composed = compose_proofs(&proof_a, &proof_b, &proof_cross)
            .expect("composition should succeed");

        prop_assert_eq!(composed.public_inputs.observables.len(), 3);
        prop_assert_eq!(composed.public_inputs.observables[0].gas_used, gas_a);
        prop_assert_eq!(composed.public_inputs.observables[1].gas_used, gas_b);
        prop_assert_eq!(composed.public_inputs.observables[2].gas_used, gas_cross);
    }

    /// Composed proof is deterministic — same inputs produce same output.
    #[test]
    fn prop51_composed_proof_deterministic(
        gas_a in 1u64..=100_000,
        gas_b in 1u64..=100_000,
    ) {
        let proof_a = make_proof(make_hash(0), make_hash(1), gas_a);
        let proof_b = make_proof(make_hash(1), make_hash(2), gas_b);
        let proof_cross = make_proof(make_hash(0), make_hash(2), 50);

        let c1 = compose_proofs(&proof_a, &proof_b, &proof_cross).expect("c1");
        let c2 = compose_proofs(&proof_a, &proof_b, &proof_cross).expect("c2");

        prop_assert_eq!(c1.commitments, c2.commitments);
        prop_assert_eq!(c1.proof_data, c2.proof_data);
        prop_assert_eq!(c1.public_inputs, c2.public_inputs);
    }

    /// Domain mismatch between any pair of proofs causes rejection.
    #[test]
    fn prop51_domain_mismatch_rejected(
        seed in any::<u8>(),
    ) {
        let proof_a = make_proof(make_hash(0), make_hash(1), 100);
        let proof_b = make_proof(make_hash(1), make_hash(2), 200);
        let mut proof_cross = make_proof(make_hash(0), make_hash(2), 50);

        // Tamper with cross proof's domain.
        let mut bad_domain = [0u8; 32];
        bad_domain[0] = seed;
        bad_domain[31] = 0xFF; // ensure different from test_domain_tag
        proof_cross.public_inputs.domain = DomainTag(Hash(bad_domain));

        let result = compose_proofs(&proof_a, &proof_b, &proof_cross);
        prop_assert!(result.is_err());
    }

    /// Empty proof data in any proof causes rejection.
    #[test]
    fn prop51_empty_proof_data_rejected(
        which in 0u8..3,
    ) {
        let mut proof_a = make_proof(make_hash(0), make_hash(1), 100);
        let mut proof_b = make_proof(make_hash(1), make_hash(2), 200);
        let mut proof_cross = make_proof(make_hash(0), make_hash(2), 50);

        match which {
            0 => proof_a.proof_data = vec![],
            1 => proof_b.proof_data = vec![],
            _ => proof_cross.proof_data = vec![],
        }

        let result = compose_proofs(&proof_a, &proof_b, &proof_cross);
        prop_assert!(result.is_err());
    }
}

// ===========================================================================
// Property 52: Backward-Compatible Upgrades
//   A(M^v2) ⊆ A(M^v1), G(M^v2) ⊇ G(M^v1)
// Validates: Requirements 11.7
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// A contract that assumes a subset and guarantees a superset is compatible.
    #[test]
    fn prop52_subset_assumes_superset_guarantees_compatible(
        base_assumes in arb_property_set(4),
        base_guarantees in arb_property_set(4),
        extra_guarantees in arb_property_set(3),
    ) {
        let v1 = SubsystemContract {
            assumes: base_assumes.clone(),
            guarantees: base_guarantees.clone(),
            exports: BTreeSet::new(),
            effects: BTreeSet::new(),
            forbids: BTreeSet::new(),
            temporal: vec![],
        };

        // v2 assumes a subset (possibly same) and guarantees a superset.
        let mut v2_guarantees = base_guarantees;
        v2_guarantees.extend(extra_guarantees);

        let v2 = SubsystemContract {
            assumes: base_assumes, // same assumes (subset of itself)
            guarantees: v2_guarantees,
            exports: BTreeSet::new(),
            effects: BTreeSet::new(),
            forbids: BTreeSet::new(),
            temporal: vec![],
        };

        let result = check_backward_compatibility(&v1, &v2);
        prop_assert_eq!(
            result,
            CompatibilityResult::Compatible,
            "v2 with same/fewer assumes and more guarantees must be compatible"
        );
    }

    /// Adding new assumptions makes the upgrade incompatible.
    #[test]
    fn prop52_expanded_assumptions_incompatible(
        base_assumes in arb_property_set(3),
        base_guarantees in arb_property_set(3),
        extra_assume in "[a-z]{4,8}",
    ) {
        // Ensure extra_assume is genuinely new.
        prop_assume!(!base_assumes.contains(&extra_assume));

        let v1 = SubsystemContract {
            assumes: base_assumes.clone(),
            guarantees: base_guarantees.clone(),
            exports: BTreeSet::new(),
            effects: BTreeSet::new(),
            forbids: BTreeSet::new(),
            temporal: vec![],
        };

        let mut v2_assumes = base_assumes;
        v2_assumes.insert(extra_assume.clone());

        let v2 = SubsystemContract {
            assumes: v2_assumes,
            guarantees: base_guarantees,
            exports: BTreeSet::new(),
            effects: BTreeSet::new(),
            forbids: BTreeSet::new(),
            temporal: vec![],
        };

        let result = check_backward_compatibility(&v1, &v2);
        match result {
            CompatibilityResult::Incompatible { violations } => {
                let found = violations.iter().any(|v| {
                    v.kind == CompatibilityViolationKind::AssumptionsExpanded
                        && v.properties.contains(&extra_assume)
                });
                prop_assert!(found, "Expected AssumptionsExpanded violation");
            }
            CompatibilityResult::Compatible => {
                prop_assert!(false, "Expected incompatible when assumptions expand");
            }
        }
    }

    /// Dropping guarantees makes the upgrade incompatible.
    #[test]
    fn prop52_reduced_guarantees_incompatible(
        base_assumes in arb_property_set(3),
        base_guarantees in arb_property_set(3),
    ) {
        prop_assume!(base_guarantees.len() >= 2);

        let v1 = SubsystemContract {
            assumes: base_assumes.clone(),
            guarantees: base_guarantees.clone(),
            exports: BTreeSet::new(),
            effects: BTreeSet::new(),
            forbids: BTreeSet::new(),
            temporal: vec![],
        };

        // v2 drops the first guarantee.
        let dropped = base_guarantees.iter().next().unwrap().clone();
        let mut v2_guarantees = base_guarantees;
        v2_guarantees.remove(&dropped);

        let v2 = SubsystemContract {
            assumes: base_assumes,
            guarantees: v2_guarantees,
            exports: BTreeSet::new(),
            effects: BTreeSet::new(),
            forbids: BTreeSet::new(),
            temporal: vec![],
        };

        let result = check_backward_compatibility(&v1, &v2);
        match result {
            CompatibilityResult::Incompatible { violations } => {
                let found = violations.iter().any(|v| {
                    v.kind == CompatibilityViolationKind::GuaranteesReduced
                        && v.properties.contains(&dropped)
                });
                prop_assert!(found, "Expected GuaranteesReduced violation");
            }
            CompatibilityResult::Compatible => {
                prop_assert!(false, "Expected incompatible when guarantees reduced");
            }
        }
    }

    /// A contract is always backward-compatible with itself.
    #[test]
    fn prop52_self_backward_compatible(
        a in arb_contract(),
    ) {
        let result = check_backward_compatibility(&a, &a);
        prop_assert_eq!(result, CompatibilityResult::Compatible);
    }
}
