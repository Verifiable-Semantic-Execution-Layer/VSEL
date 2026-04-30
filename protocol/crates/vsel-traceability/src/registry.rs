//! Traceability registry — populates the full traceability matrix with all
//! VSEL invariants, SIR constructs, Rust modules, constraints, proof
//! obligations, and NIST controls.
//!
//! This is the canonical source of the derivation chain mapping.
//!
//! Requirements: 16.1

use crate::matrix::{
    InvariantCategory, Layer, ObligationCategory, ProofObligationEntry, TraceabilityEntry,
    TraceabilityMatrix,
};

// ---------------------------------------------------------------------------
// Transition classes (all six)
// ---------------------------------------------------------------------------

/// All transition classes in the VSEL state machine.
const ALL_TRANSITION_CLASSES: &[&str] = &[
    "Reject", "Init", "Error", "Batch", "Update", "Noop",
];

// ---------------------------------------------------------------------------
// Build the complete traceability matrix
// ---------------------------------------------------------------------------

/// Build the complete VSEL traceability matrix.
///
/// Populates all L0 invariants with their derivation chain through
/// L1 SIR/IR, L2 Rust, L3 constraints, L4 proof obligations, and
/// NIST controls.
///
/// Requirements: 16.1
pub fn build_traceability_matrix() -> TraceabilityMatrix {
    let mut matrix = TraceabilityMatrix::new();

    // Register all invariants.
    register_local_invariants(&mut matrix);
    register_global_invariants(&mut matrix);
    register_temporal_invariants(&mut matrix);
    register_economic_local_invariants(&mut matrix);
    register_economic_global_invariants(&mut matrix);
    register_economic_temporal_invariants(&mut matrix);
    register_economic_compositional_invariants(&mut matrix);
    register_cross_layer_invariants(&mut matrix);

    // Register all proof obligations.
    register_axioms(&mut matrix);
    register_definitions(&mut matrix);
    register_lemmas(&mut matrix);
    register_safety_properties(&mut matrix);
    register_liveness_properties(&mut matrix);
    register_constraint_obligations(&mut matrix);
    register_proof_obligations(&mut matrix);
    register_composition_obligations(&mut matrix);
    register_economic_obligations(&mut matrix);

    matrix
}

// ---------------------------------------------------------------------------
// Local invariants (L_valid, L_state, L_cons, L_bounded, L_det)
// ---------------------------------------------------------------------------

fn register_local_invariants(matrix: &mut TraceabilityMatrix) {
    matrix.add_entry(TraceabilityEntry {
        l0_invariant_id: "L_valid".to_string(),
        category: InvariantCategory::Local,
        l0_lean_source: "formal/VSEL/Foundations/Invariants.lean::L_valid".to_string(),
        l1_sir_constructs: vec!["SirTransition.postconditions".to_string()],
        l2_rust_modules: vec![
            "vsel-invariants/src/local.rs::check_l_valid".to_string(),
            "vsel-engine/src/pipeline.rs::postcondition_validation".to_string(),
        ],
        l2_transition_classes: ALL_TRANSITION_CLASSES.iter().map(|s| s.to_string()).collect(),
        l3_constraint_ids: vec!["semantic-apply-correctness".to_string()],
        l4_proof_obligations: vec!["LEM-1".to_string(), "SAFE-1".to_string()],
        nist_controls: vec!["PW.1".to_string(), "PW.8".to_string()],
    });

    matrix.add_entry(TraceabilityEntry {
        l0_invariant_id: "L_state".to_string(),
        category: InvariantCategory::Local,
        l0_lean_source: "formal/VSEL/Foundations/Invariants.lean::L_state".to_string(),
        l1_sir_constructs: vec!["SirTransition.preconditions".to_string()],
        l2_rust_modules: vec![
            "vsel-invariants/src/local.rs::check_l_state".to_string(),
            "vsel-engine/src/pipeline.rs::precondition_validation".to_string(),
        ],
        l2_transition_classes: ALL_TRANSITION_CLASSES.iter().map(|s| s.to_string()).collect(),
        l3_constraint_ids: vec!["structural-state-validity".to_string()],
        l4_proof_obligations: vec!["AX-2".to_string(), "LEM-1".to_string()],
        nist_controls: vec!["PW.1".to_string(), "PW.8".to_string()],
    });

    matrix.add_entry(TraceabilityEntry {
        l0_invariant_id: "L_cons".to_string(),
        category: InvariantCategory::Local,
        l0_lean_source: "formal/VSEL/Foundations/Invariants.lean::L_cons".to_string(),
        l1_sir_constructs: vec!["SirInvariant(L_cons)".to_string()],
        l2_rust_modules: vec![
            "vsel-invariants/src/local.rs::check_l_cons".to_string(),
        ],
        l2_transition_classes: ALL_TRANSITION_CLASSES.iter().map(|s| s.to_string()).collect(),
        l3_constraint_ids: vec!["invariant-L_cons".to_string()],
        l4_proof_obligations: vec!["SAFE-2".to_string(), "LEM-1".to_string()],
        nist_controls: vec!["PW.1".to_string(), "PW.8".to_string(), "PR".to_string()],
    });

    matrix.add_entry(TraceabilityEntry {
        l0_invariant_id: "L_bounded".to_string(),
        category: InvariantCategory::Local,
        l0_lean_source: "formal/VSEL/Foundations/Invariants.lean::L_bounded".to_string(),
        l1_sir_constructs: vec!["SirTransition.allowed_mutations".to_string()],
        l2_rust_modules: vec![
            "vsel-invariants/src/local.rs::check_l_bounded".to_string(),
            "vsel-engine/src/engine.rs::bounded_mutation".to_string(),
        ],
        l2_transition_classes: ALL_TRANSITION_CLASSES.iter().map(|s| s.to_string()).collect(),
        l3_constraint_ids: vec!["carry-over-equality".to_string()],
        l4_proof_obligations: vec!["SAFE-3".to_string(), "LEM-1".to_string()],
        nist_controls: vec!["PW.1".to_string(), "PR".to_string()],
    });

    matrix.add_entry(TraceabilityEntry {
        l0_invariant_id: "L_det".to_string(),
        category: InvariantCategory::Local,
        l0_lean_source: "formal/VSEL/Foundations/Invariants.lean::L_det".to_string(),
        l1_sir_constructs: vec!["SirTransition (deterministic body)".to_string()],
        l2_rust_modules: vec![
            "vsel-invariants/src/local.rs::check_l_det".to_string(),
            "vsel-engine/src/engine.rs::execute".to_string(),
        ],
        l2_transition_classes: ALL_TRANSITION_CLASSES.iter().map(|s| s.to_string()).collect(),
        l3_constraint_ids: vec!["CONST-4".to_string()],
        l4_proof_obligations: vec!["AX-1".to_string()],
        nist_controls: vec!["PW.1".to_string(), "PW.8".to_string()],
    });
}

// ---------------------------------------------------------------------------
// Global invariants (G_valid, G_struct, G_commit, G_mono, G_env)
// ---------------------------------------------------------------------------

fn register_global_invariants(matrix: &mut TraceabilityMatrix) {
    matrix.add_entry(TraceabilityEntry {
        l0_invariant_id: "G_valid".to_string(),
        category: InvariantCategory::Global,
        l0_lean_source: "formal/VSEL/Foundations/Invariants.lean::G_valid".to_string(),
        l1_sir_constructs: vec!["SirStateSchema (validity)".to_string()],
        l2_rust_modules: vec![
            "vsel-invariants/src/global.rs::check_g_valid".to_string(),
            "vsel-core/src/state.rs::valid_state".to_string(),
        ],
        l2_transition_classes: ALL_TRANSITION_CLASSES.iter().map(|s| s.to_string()).collect(),
        l3_constraint_ids: vec!["structural-state-validity".to_string()],
        l4_proof_obligations: vec!["LEM-1".to_string(), "LEM-2".to_string(), "SAFE-1".to_string()],
        nist_controls: vec!["PW.1".to_string(), "PW.8".to_string()],
    });

    matrix.add_entry(TraceabilityEntry {
        l0_invariant_id: "G_struct".to_string(),
        category: InvariantCategory::Global,
        l0_lean_source: "formal/VSEL/Foundations/Invariants.lean::G_struct".to_string(),
        l1_sir_constructs: vec!["SirInvariant(G_struct)".to_string()],
        l2_rust_modules: vec![
            "vsel-invariants/src/global.rs::check_g_struct".to_string(),
        ],
        l2_transition_classes: ALL_TRANSITION_CLASSES.iter().map(|s| s.to_string()).collect(),
        l3_constraint_ids: vec!["invariant-G_struct".to_string()],
        l4_proof_obligations: vec!["LEM-1".to_string(), "SAFE-2".to_string()],
        nist_controls: vec!["PW.1".to_string(), "PR".to_string()],
    });

    matrix.add_entry(TraceabilityEntry {
        l0_invariant_id: "G_commit".to_string(),
        category: InvariantCategory::Global,
        l0_lean_source: "formal/VSEL/Foundations/Invariants.lean::G_commit".to_string(),
        l1_sir_constructs: vec!["SirStateSchema.derived".to_string()],
        l2_rust_modules: vec![
            "vsel-invariants/src/global.rs::check_g_commit".to_string(),
            "vsel-core/src/state.rs::derive".to_string(),
        ],
        l2_transition_classes: ALL_TRANSITION_CLASSES.iter().map(|s| s.to_string()).collect(),
        l3_constraint_ids: vec!["commitment-consistency".to_string()],
        l4_proof_obligations: vec!["DEF-1".to_string(), "DEF-3".to_string()],
        nist_controls: vec!["PW.1".to_string(), "PS.1".to_string()],
    });

    matrix.add_entry(TraceabilityEntry {
        l0_invariant_id: "G_mono".to_string(),
        category: InvariantCategory::Global,
        l0_lean_source: "formal/VSEL/Foundations/Invariants.lean::G_mono".to_string(),
        l1_sir_constructs: vec!["SirStateSchema.metadata".to_string()],
        l2_rust_modules: vec![
            "vsel-invariants/src/global.rs::check_g_mono".to_string(),
        ],
        l2_transition_classes: ALL_TRANSITION_CLASSES.iter().map(|s| s.to_string()).collect(),
        l3_constraint_ids: vec!["metadata-monotonicity".to_string()],
        l4_proof_obligations: vec!["SAFE-4".to_string()],
        nist_controls: vec!["PW.1".to_string(), "DE".to_string()],
    });

    matrix.add_entry(TraceabilityEntry {
        l0_invariant_id: "G_env".to_string(),
        category: InvariantCategory::Global,
        l0_lean_source: "formal/VSEL/Foundations/Invariants.lean::G_env".to_string(),
        l1_sir_constructs: vec!["SirStateSchema.environment".to_string()],
        l2_rust_modules: vec![
            "vsel-invariants/src/global.rs::check_g_env".to_string(),
        ],
        l2_transition_classes: ALL_TRANSITION_CLASSES.iter().map(|s| s.to_string()).collect(),
        l3_constraint_ids: vec!["environment-consistency".to_string()],
        l4_proof_obligations: vec!["AX-6".to_string()],
        nist_controls: vec!["PW.1".to_string(), "ID".to_string()],
    });
}

// ---------------------------------------------------------------------------
// Temporal invariants (T_valid, T_no_revert, T_cons, T_causal, T_complete)
// ---------------------------------------------------------------------------

fn register_temporal_invariants(matrix: &mut TraceabilityMatrix) {
    matrix.add_entry(TraceabilityEntry {
        l0_invariant_id: "T_valid".to_string(),
        category: InvariantCategory::Temporal,
        l0_lean_source: "formal/VSEL/Foundations/Invariants.lean::T_valid".to_string(),
        l1_sir_constructs: vec!["SirTransition (trace-level)".to_string()],
        l2_rust_modules: vec![
            "vsel-invariants/src/temporal.rs::check_t_valid".to_string(),
            "vsel-trace/src/engine.rs::verify_trace".to_string(),
        ],
        l2_transition_classes: ALL_TRANSITION_CLASSES.iter().map(|s| s.to_string()).collect(),
        l3_constraint_ids: vec!["trace-validity".to_string()],
        l4_proof_obligations: vec!["LEM-2".to_string(), "SAFE-1".to_string()],
        nist_controls: vec!["PW.8".to_string(), "DE".to_string()],
    });

    matrix.add_entry(TraceabilityEntry {
        l0_invariant_id: "T_no_revert".to_string(),
        category: InvariantCategory::Temporal,
        l0_lean_source: "formal/VSEL/Foundations/Invariants.lean::T_no_revert".to_string(),
        l1_sir_constructs: vec!["SirStateSchema.metadata.sequence_index".to_string()],
        l2_rust_modules: vec![
            "vsel-invariants/src/temporal.rs::check_t_no_revert".to_string(),
        ],
        l2_transition_classes: ALL_TRANSITION_CLASSES.iter().map(|s| s.to_string()).collect(),
        l3_constraint_ids: vec!["sequence-monotonicity".to_string()],
        l4_proof_obligations: vec!["SAFE-4".to_string(), "SAFE-5".to_string()],
        nist_controls: vec!["PR".to_string(), "DE".to_string()],
    });

    matrix.add_entry(TraceabilityEntry {
        l0_invariant_id: "T_cons".to_string(),
        category: InvariantCategory::Temporal,
        l0_lean_source: "formal/VSEL/Foundations/Invariants.lean::T_cons".to_string(),
        l1_sir_constructs: vec!["SirInvariant(L_cons) (trace-level)".to_string()],
        l2_rust_modules: vec![
            "vsel-invariants/src/temporal.rs::check_t_cons".to_string(),
        ],
        l2_transition_classes: ALL_TRANSITION_CLASSES.iter().map(|s| s.to_string()).collect(),
        l3_constraint_ids: vec!["cumulative-resource-conservation".to_string()],
        l4_proof_obligations: vec!["SAFE-2".to_string(), "LEM-2".to_string()],
        nist_controls: vec!["PR".to_string(), "PW.8".to_string()],
    });

    matrix.add_entry(TraceabilityEntry {
        l0_invariant_id: "T_causal".to_string(),
        category: InvariantCategory::Temporal,
        l0_lean_source: "formal/VSEL/Foundations/Invariants.lean::T_causal".to_string(),
        l1_sir_constructs: vec!["SirStateSchema.metadata.timestamp".to_string()],
        l2_rust_modules: vec![
            "vsel-invariants/src/temporal.rs::check_t_causal".to_string(),
        ],
        l2_transition_classes: ALL_TRANSITION_CLASSES.iter().map(|s| s.to_string()).collect(),
        l3_constraint_ids: vec!["timestamp-monotonicity".to_string()],
        l4_proof_obligations: vec!["SAFE-4".to_string()],
        nist_controls: vec!["DE".to_string(), "PR".to_string()],
    });

    matrix.add_entry(TraceabilityEntry {
        l0_invariant_id: "T_complete".to_string(),
        category: InvariantCategory::Temporal,
        l0_lean_source: "formal/VSEL/Foundations/Invariants.lean::T_complete".to_string(),
        l1_sir_constructs: vec!["SirStateSchema.metadata.sequence_index".to_string()],
        l2_rust_modules: vec![
            "vsel-invariants/src/temporal.rs::check_t_complete".to_string(),
            "vsel-trace/src/engine.rs::record_transition".to_string(),
        ],
        l2_transition_classes: ALL_TRANSITION_CLASSES.iter().map(|s| s.to_string()).collect(),
        l3_constraint_ids: vec!["sequence-contiguity".to_string()],
        l4_proof_obligations: vec!["PROOF-1".to_string()],
        nist_controls: vec!["DE".to_string(), "PW.8".to_string()],
    });
}

// ---------------------------------------------------------------------------
// Economic local invariants
// ---------------------------------------------------------------------------

fn register_economic_local_invariants(matrix: &mut TraceabilityMatrix) {
    let econ_local = vec![
        ("E_cost", "E_cost", "Fee rate bounded"),
        ("E_leverage", "E_leverage", "Leverage ratio bounded"),
        ("E_proportionality", "E_proportionality", "Fee proportionality"),
        ("E_slippage", "E_slippage", "Price impact bounded"),
        ("E_collateral", "E_collateral", "Collateral requirements met"),
    ];

    for (id, lean_def, _desc) in econ_local {
        matrix.add_entry(TraceabilityEntry {
            l0_invariant_id: id.to_string(),
            category: InvariantCategory::EconomicLocal,
            l0_lean_source: format!(
                "formal/VSEL/Foundations/Invariants.lean::{}",
                lean_def
            ),
            l1_sir_constructs: vec![format!("SirInvariant({})", id)],
            l2_rust_modules: vec![format!(
                "vsel-invariants/src/economic.rs::check_{}",
                id.to_lowercase()
            )],
            l2_transition_classes: ALL_TRANSITION_CLASSES
                .iter()
                .map(|s| s.to_string())
                .collect(),
            l3_constraint_ids: vec![format!("invariant-{}", id)],
            l4_proof_obligations: vec!["ECON-1".to_string()],
            nist_controls: vec!["PW.1".to_string(), "PR".to_string()],
        });
    }
}

// ---------------------------------------------------------------------------
// Economic global invariants
// ---------------------------------------------------------------------------

fn register_economic_global_invariants(matrix: &mut TraceabilityMatrix) {
    let econ_global = vec![
        ("G_econ_valid", "G_econ_valid", "Economic context well-formed"),
        ("G_concentration", "G_concentration", "Concentration limit"),
        ("G_liquidity", "G_liquidity", "Liquidity threshold"),
        ("G_solvency", "G_solvency", "System solvency"),
        ("G_dust", "G_dust", "Dust threshold"),
    ];

    for (id, lean_def, _desc) in econ_global {
        matrix.add_entry(TraceabilityEntry {
            l0_invariant_id: id.to_string(),
            category: InvariantCategory::EconomicGlobal,
            l0_lean_source: format!(
                "formal/VSEL/Foundations/Invariants.lean::{}",
                lean_def
            ),
            l1_sir_constructs: vec![format!("SirInvariant({})", id)],
            l2_rust_modules: vec![format!(
                "vsel-invariants/src/economic.rs::check_{}",
                id.to_lowercase()
            )],
            l2_transition_classes: ALL_TRANSITION_CLASSES
                .iter()
                .map(|s| s.to_string())
                .collect(),
            l3_constraint_ids: vec![format!("invariant-{}", id)],
            l4_proof_obligations: vec!["ECON-1".to_string(), "ECON-2".to_string()],
            nist_controls: vec!["PW.1".to_string(), "PR".to_string(), "ID".to_string()],
        });
    }
}

// ---------------------------------------------------------------------------
// Economic temporal invariants
// ---------------------------------------------------------------------------

fn register_economic_temporal_invariants(matrix: &mut TraceabilityMatrix) {
    let econ_temporal = vec![
        ("TE_extraction", "TE_extraction", "Value extraction bounded"),
        ("TE_flash", "TE_flash", "Flash loan protection"),
        ("TE_sandwich", "TE_sandwich", "Sandwich attack protection"),
        ("TE_manipulation", "TE_manipulation", "Market manipulation protection"),
        ("TE_velocity", "TE_velocity", "Transaction velocity bounded"),
    ];

    for (id, lean_def, _desc) in econ_temporal {
        matrix.add_entry(TraceabilityEntry {
            l0_invariant_id: id.to_string(),
            category: InvariantCategory::EconomicTemporal,
            l0_lean_source: format!(
                "formal/VSEL/Foundations/Invariants.lean::{}",
                lean_def
            ),
            l1_sir_constructs: vec![format!("SirInvariant({})", id)],
            l2_rust_modules: vec![format!(
                "vsel-invariants/src/economic.rs::check_{}",
                id.to_lowercase()
            )],
            l2_transition_classes: ALL_TRANSITION_CLASSES
                .iter()
                .map(|s| s.to_string())
                .collect(),
            l3_constraint_ids: vec![format!("invariant-{}", id)],
            l4_proof_obligations: vec!["ECON-3".to_string()],
            nist_controls: vec!["PR".to_string(), "DE".to_string()],
        });
    }
}

// ---------------------------------------------------------------------------
// Economic compositional invariants
// ---------------------------------------------------------------------------

fn register_economic_compositional_invariants(matrix: &mut TraceabilityMatrix) {
    let econ_comp = vec![
        ("CE_arbitrage", "CE_arbitrage", "Cross-system arbitrage bounded"),
        ("CE_contagion", "CE_contagion", "Economic contagion bounded"),
    ];

    for (id, lean_def, _desc) in econ_comp {
        matrix.add_entry(TraceabilityEntry {
            l0_invariant_id: id.to_string(),
            category: InvariantCategory::EconomicCompositional,
            l0_lean_source: format!(
                "formal/VSEL/Foundations/Invariants.lean::{}",
                lean_def
            ),
            l1_sir_constructs: vec![format!("SirInvariant({})", id)],
            l2_rust_modules: vec![
                format!(
                    "vsel-invariants/src/economic.rs::check_{}",
                    id.to_lowercase()
                ),
                "vsel-composition/src/cross_invariants.rs".to_string(),
            ],
            l2_transition_classes: ALL_TRANSITION_CLASSES
                .iter()
                .map(|s| s.to_string())
                .collect(),
            l3_constraint_ids: vec![format!("invariant-{}", id)],
            l4_proof_obligations: vec!["COMP-3".to_string(), "ECON-5".to_string()],
            nist_controls: vec!["PR".to_string(), "ID".to_string()],
        });
    }
}

// ---------------------------------------------------------------------------
// Cross-layer invariants (X_exec, X_constraint, X_proof)
// ---------------------------------------------------------------------------

fn register_cross_layer_invariants(matrix: &mut TraceabilityMatrix) {
    matrix.add_entry(TraceabilityEntry {
        l0_invariant_id: "X_exec".to_string(),
        category: InvariantCategory::CrossLayer,
        l0_lean_source: "formal/VSEL/Foundations/Invariants.lean::X_exec".to_string(),
        l1_sir_constructs: vec!["SIR/IR pipeline (Lean→Rust)".to_string()],
        l2_rust_modules: vec![
            "vsel-invariants/src/cross_layer.rs::check_x_exec".to_string(),
            "vsel-mapping/src/differential.rs".to_string(),
        ],
        l2_transition_classes: ALL_TRANSITION_CLASSES.iter().map(|s| s.to_string()).collect(),
        l3_constraint_ids: vec!["cross-layer-exec".to_string()],
        l4_proof_obligations: vec!["LEM-3".to_string()],
        nist_controls: vec!["PW.1".to_string(), "PW.4".to_string(), "PW.8".to_string()],
    });

    matrix.add_entry(TraceabilityEntry {
        l0_invariant_id: "X_constraint".to_string(),
        category: InvariantCategory::CrossLayer,
        l0_lean_source: "formal/VSEL/Foundations/Invariants.lean::X_constraint".to_string(),
        l1_sir_constructs: vec!["SIR/IR → Constraint derivation".to_string()],
        l2_rust_modules: vec![
            "vsel-invariants/src/cross_layer.rs::check_x_constraint".to_string(),
            "vsel-constraints/src/compiler.rs::compile".to_string(),
        ],
        l2_transition_classes: ALL_TRANSITION_CLASSES.iter().map(|s| s.to_string()).collect(),
        l3_constraint_ids: vec!["cross-layer-constraint".to_string()],
        l4_proof_obligations: vec!["LEM-4".to_string(), "LEM-5".to_string()],
        nist_controls: vec!["PW.1".to_string(), "PW.8".to_string(), "RV.1".to_string()],
    });

    matrix.add_entry(TraceabilityEntry {
        l0_invariant_id: "X_proof".to_string(),
        category: InvariantCategory::CrossLayer,
        l0_lean_source: "formal/VSEL/Foundations/Invariants.lean::X_proof".to_string(),
        l1_sir_constructs: vec!["Proof system binding".to_string()],
        l2_rust_modules: vec![
            "vsel-invariants/src/cross_layer.rs::check_x_proof".to_string(),
            "vsel-proof/src/verifier.rs::verify".to_string(),
        ],
        l2_transition_classes: ALL_TRANSITION_CLASSES.iter().map(|s| s.to_string()).collect(),
        l3_constraint_ids: vec!["cross-layer-proof".to_string()],
        l4_proof_obligations: vec![
            "PROOF-1".to_string(),
            "PROOF-2".to_string(),
            "PROOF-3".to_string(),
            "PROOF-4".to_string(),
        ],
        nist_controls: vec!["PW.8".to_string(), "PS.1".to_string()],
    });
}

// ---------------------------------------------------------------------------
// Proof obligations — Axioms
// ---------------------------------------------------------------------------

fn register_axioms(matrix: &mut TraceabilityMatrix) {
    matrix.add_obligation(ProofObligationEntry {
        obligation_id: "AX-1".to_string(),
        category: ObligationCategory::Axiom,
        layer: Layer::L0Formal,
        constraint_ids: vec!["CONST-4".to_string()],
        invariant_dependencies: vec!["L_det".to_string()],
        nist_controls: vec!["PW.1".to_string()],
    });

    matrix.add_obligation(ProofObligationEntry {
        obligation_id: "AX-2".to_string(),
        category: ObligationCategory::Axiom,
        layer: Layer::L0Formal,
        constraint_ids: vec!["structural-state-validity".to_string()],
        invariant_dependencies: vec!["L_state".to_string(), "G_valid".to_string()],
        nist_controls: vec!["PW.1".to_string()],
    });

    matrix.add_obligation(ProofObligationEntry {
        obligation_id: "AX-3".to_string(),
        category: ObligationCategory::Axiom,
        layer: Layer::L0Formal,
        constraint_ids: vec!["genesis-constraints".to_string()],
        invariant_dependencies: vec!["G_valid".to_string()],
        nist_controls: vec!["PW.1".to_string()],
    });

    matrix.add_obligation(ProofObligationEntry {
        obligation_id: "AX-4".to_string(),
        category: ObligationCategory::External,
        layer: Layer::L4Proof,
        constraint_ids: vec!["proof-system-soundness".to_string()],
        invariant_dependencies: vec!["X_proof".to_string()],
        nist_controls: vec!["PS.1".to_string()],
    });

    matrix.add_obligation(ProofObligationEntry {
        obligation_id: "AX-5".to_string(),
        category: ObligationCategory::External,
        layer: Layer::L2Rust,
        constraint_ids: vec!["hash-collision-resistance".to_string()],
        invariant_dependencies: vec!["G_commit".to_string()],
        nist_controls: vec!["PS.1".to_string()],
    });

    matrix.add_obligation(ProofObligationEntry {
        obligation_id: "AX-6".to_string(),
        category: ObligationCategory::External,
        layer: Layer::L2Rust,
        constraint_ids: vec!["environment-faithfulness".to_string()],
        invariant_dependencies: vec!["G_env".to_string()],
        nist_controls: vec!["ID".to_string()],
    });
}

// ---------------------------------------------------------------------------
// Proof obligations — Definitions
// ---------------------------------------------------------------------------

fn register_definitions(matrix: &mut TraceabilityMatrix) {
    let defs = vec![
        ("DEF-1", Layer::L0Formal, vec!["derived-state-determinism"], vec!["G_commit", "L_bounded"], vec!["PW.1"]),
        ("DEF-2", Layer::L2Rust, vec!["encoding-injectivity"], vec!["G_commit"], vec!["PW.1", "PS.1"]),
        ("DEF-3", Layer::L2Rust, vec!["commitment-binding"], vec!["G_commit"], vec!["PS.1"]),
        ("DEF-4", Layer::L0Formal, vec!["observable-determinism"], vec!["L_det"], vec!["PW.1"]),
        ("DEF-5", Layer::L2Rust, vec!["canonicalization-idempotence"], vec!["L_state"], vec!["PW.1"]),
        ("DEF-6", Layer::L2Rust, vec!["canonicalization-semantic-preservation"], vec!["L_state"], vec!["PW.1"]),
    ];

    for (id, layer, constraints, invariants, nist) in defs {
        matrix.add_obligation(ProofObligationEntry {
            obligation_id: id.to_string(),
            category: ObligationCategory::Definition,
            layer,
            constraint_ids: constraints.iter().map(|s| s.to_string()).collect(),
            invariant_dependencies: invariants.iter().map(|s| s.to_string()).collect(),
            nist_controls: nist.iter().map(|s| s.to_string()).collect(),
        });
    }
}

// ---------------------------------------------------------------------------
// Proof obligations — Lemmas
// ---------------------------------------------------------------------------

fn register_lemmas(matrix: &mut TraceabilityMatrix) {
    let lemmas = vec![
        ("LEM-1", Layer::L0Formal, vec!["invariant-preservation"], vec!["L_valid", "L_state", "L_cons", "L_bounded", "G_valid", "G_struct"], vec!["PW.1", "PW.8"]),
        ("LEM-2", Layer::L0Formal, vec!["trace-inductive-invariance"], vec!["T_valid", "G_valid"], vec!["PW.1", "PW.8"]),
        ("LEM-3", Layer::L1Sir, vec!["semantic-mapping-commutativity"], vec!["X_exec"], vec!["PW.1", "PW.4"]),
        ("LEM-4", Layer::L3Constraint, vec!["constraint-soundness"], vec!["X_constraint"], vec!["PW.8", "RV.1"]),
        ("LEM-5", Layer::L3Constraint, vec!["constraint-completeness"], vec!["X_constraint"], vec!["PW.8", "RV.1"]),
        ("LEM-6", Layer::L4Proof, vec!["witness-semantic-uniqueness"], vec!["X_proof"], vec!["PS.1"]),
        ("LEM-7", Layer::L0Formal, vec!["error-state-invariant-preservation"], vec!["L_state", "G_valid"], vec!["PW.1"]),
        ("LEM-8", Layer::L0Formal, vec!["noop-semantic-neutrality"], vec!["L_det"], vec!["PW.1"]),
        ("LEM-9", Layer::L2Rust, vec!["batch-decomposition-equivalence"], vec!["L_det"], vec!["PW.8"]),
        ("LEM-10", Layer::L2Rust, vec!["trace-reconstruction-fidelity"], vec!["T_valid", "T_complete"], vec!["PW.8", "RC"]),
    ];

    for (id, layer, constraints, invariants, nist) in lemmas {
        matrix.add_obligation(ProofObligationEntry {
            obligation_id: id.to_string(),
            category: ObligationCategory::Lemma,
            layer,
            constraint_ids: constraints.iter().map(|s| s.to_string()).collect(),
            invariant_dependencies: invariants.iter().map(|s| s.to_string()).collect(),
            nist_controls: nist.iter().map(|s| s.to_string()).collect(),
        });
    }
}

// ---------------------------------------------------------------------------
// Proof obligations — Safety properties
// ---------------------------------------------------------------------------

fn register_safety_properties(matrix: &mut TraceabilityMatrix) {
    let safety = vec![
        ("SAFE-1", Layer::L0Formal, vec!["unreachable-invalid-states"], vec!["G_valid", "L_state"], vec!["PW.1", "PR"]),
        ("SAFE-2", Layer::L0Formal, vec!["resource-conservation"], vec!["L_cons", "G_struct", "T_cons"], vec!["PW.1", "PR"]),
        ("SAFE-3", Layer::L2Rust, vec!["no-hidden-state-mutation"], vec!["L_bounded"], vec!["PW.1", "PR"]),
        ("SAFE-4", Layer::L0Formal, vec!["temporal-monotonicity"], vec!["T_no_revert", "T_causal", "G_mono"], vec!["PW.1", "DE"]),
        ("SAFE-5", Layer::L2Rust, vec!["no-rollback"], vec!["T_no_revert"], vec!["PR", "DE"]),
        ("SAFE-6", Layer::L4Proof, vec!["domain-isolation"], vec!["X_proof"], vec!["PS.1", "PR"]),
    ];

    for (id, layer, constraints, invariants, nist) in safety {
        matrix.add_obligation(ProofObligationEntry {
            obligation_id: id.to_string(),
            category: ObligationCategory::Safety,
            layer,
            constraint_ids: constraints.iter().map(|s| s.to_string()).collect(),
            invariant_dependencies: invariants.iter().map(|s| s.to_string()).collect(),
            nist_controls: nist.iter().map(|s| s.to_string()).collect(),
        });
    }
}

// ---------------------------------------------------------------------------
// Proof obligations — Liveness properties
// ---------------------------------------------------------------------------

fn register_liveness_properties(matrix: &mut TraceabilityMatrix) {
    matrix.add_obligation(ProofObligationEntry {
        obligation_id: "LIVE-1".to_string(),
        category: ObligationCategory::Liveness,
        layer: Layer::L0Formal,
        constraint_ids: vec!["no-deadlock".to_string()],
        invariant_dependencies: vec!["G_valid".to_string()],
        nist_controls: vec!["PW.1".to_string()],
    });

    matrix.add_obligation(ProofObligationEntry {
        obligation_id: "LIVE-2".to_string(),
        category: ObligationCategory::Liveness,
        layer: Layer::L4Proof,
        constraint_ids: vec!["provability-of-valid-traces".to_string()],
        invariant_dependencies: vec!["X_constraint".to_string(), "X_proof".to_string()],
        nist_controls: vec!["PW.8".to_string()],
    });
}

// ---------------------------------------------------------------------------
// Proof obligations — Constraint-layer (CONST-1 through CONST-4)
// ---------------------------------------------------------------------------

fn register_constraint_obligations(matrix: &mut TraceabilityMatrix) {
    let consts = vec![
        ("CONST-1", vec!["no-unconstrained-variables"], vec!["X_constraint"], vec!["RV.1"]),
        ("CONST-2", vec!["no-unused-witness-inputs"], vec!["X_constraint"], vec!["RV.1"]),
        ("CONST-3", vec!["branch-completeness"], vec!["X_constraint"], vec!["RV.1", "PW.8"]),
        ("CONST-4", vec!["constraint-derivation-determinism"], vec!["L_det", "X_constraint"], vec!["PW.1", "RV.1"]),
    ];

    for (id, constraints, invariants, nist) in consts {
        matrix.add_obligation(ProofObligationEntry {
            obligation_id: id.to_string(),
            category: ObligationCategory::Constraint,
            layer: Layer::L3Constraint,
            constraint_ids: constraints.iter().map(|s| s.to_string()).collect(),
            invariant_dependencies: invariants.iter().map(|s| s.to_string()).collect(),
            nist_controls: nist.iter().map(|s| s.to_string()).collect(),
        });
    }
}

// ---------------------------------------------------------------------------
// Proof obligations — Proof-layer (PROOF-1 through PROOF-4)
// ---------------------------------------------------------------------------

fn register_proof_obligations(matrix: &mut TraceabilityMatrix) {
    let proofs = vec![
        ("PROOF-1", vec!["full-trace-binding"], vec!["X_proof", "T_complete"], vec!["PS.1", "PW.8"]),
        ("PROOF-2", vec!["observable-binding"], vec!["X_proof"], vec!["PS.1", "PW.8"]),
        ("PROOF-3", vec!["domain-separation"], vec!["X_proof"], vec!["PS.1"]),
        ("PROOF-4", vec!["knowledge-soundness"], vec!["X_proof"], vec!["PS.1"]),
    ];

    for (id, constraints, invariants, nist) in proofs {
        matrix.add_obligation(ProofObligationEntry {
            obligation_id: id.to_string(),
            category: ObligationCategory::Proof,
            layer: Layer::L4Proof,
            constraint_ids: constraints.iter().map(|s| s.to_string()).collect(),
            invariant_dependencies: invariants.iter().map(|s| s.to_string()).collect(),
            nist_controls: nist.iter().map(|s| s.to_string()).collect(),
        });
    }
}

// ---------------------------------------------------------------------------
// Proof obligations — Composition (COMP-1 through COMP-3)
// ---------------------------------------------------------------------------

fn register_composition_obligations(matrix: &mut TraceabilityMatrix) {
    let comps = vec![
        ("COMP-1", vec!["cross-system-resource-conservation"], vec!["L_cons", "CE_arbitrage"], vec!["PR"]),
        ("COMP-2", vec!["shared-state-consistency"], vec!["G_valid", "CE_contagion"], vec!["PR"]),
        ("COMP-3", vec!["compositional-invariant-preservation"], vec!["CE_arbitrage", "CE_contagion"], vec!["PR", "PW.8"]),
    ];

    for (id, constraints, invariants, nist) in comps {
        matrix.add_obligation(ProofObligationEntry {
            obligation_id: id.to_string(),
            category: ObligationCategory::Composition,
            layer: Layer::L2Rust,
            constraint_ids: constraints.iter().map(|s| s.to_string()).collect(),
            invariant_dependencies: invariants.iter().map(|s| s.to_string()).collect(),
            nist_controls: nist.iter().map(|s| s.to_string()).collect(),
        });
    }
}

// ---------------------------------------------------------------------------
// Proof obligations — Economic (ECON-1 through ECON-5)
// ---------------------------------------------------------------------------

fn register_economic_obligations(matrix: &mut TraceabilityMatrix) {
    let econs = vec![
        ("ECON-1", Layer::L0Formal, vec!["economic-invariant-preservation"], vec!["E_cost", "E_leverage", "E_proportionality", "E_slippage", "E_collateral"], vec!["PR", "PW.1"]),
        ("ECON-2", Layer::L0Formal, vec!["initial-state-economic-validity"], vec!["G_econ_valid", "G_solvency"], vec!["PW.1"]),
        ("ECON-3", Layer::L0Formal, vec!["temporal-economic-enforcement"], vec!["TE_extraction", "TE_flash", "TE_sandwich", "TE_manipulation", "TE_velocity"], vec!["PR", "DE"]),
        ("ECON-4", Layer::L0Formal, vec!["economic-context-determinism"], vec!["G_econ_valid"], vec!["PW.1"]),
        ("ECON-5", Layer::L0Formal, vec!["economic-admissibility-completeness"], vec!["CE_arbitrage", "CE_contagion"], vec!["PR", "RV.1"]),
    ];

    for (id, layer, constraints, invariants, nist) in econs {
        matrix.add_obligation(ProofObligationEntry {
            obligation_id: id.to_string(),
            category: ObligationCategory::Economic,
            layer,
            constraint_ids: constraints.iter().map(|s| s.to_string()).collect(),
            invariant_dependencies: invariants.iter().map(|s| s.to_string()).collect(),
            nist_controls: nist.iter().map(|s| s.to_string()).collect(),
        });
    }
}
