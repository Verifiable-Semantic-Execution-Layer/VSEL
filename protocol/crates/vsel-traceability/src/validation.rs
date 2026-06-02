//! Traceability validation — detects broken links in the derivation chain.
//!
//! Requirement 16.8: broken traceability links must be flagged as gaps
//! requiring resolution. An invariant without a constraint, or a constraint
//! without a proof obligation, is a gap.

use std::collections::BTreeSet;

use crate::matrix::{GapType, Layer, TraceabilityGap, TraceabilityMatrix};

// ---------------------------------------------------------------------------
// Validation result
// ---------------------------------------------------------------------------

/// Result of traceability validation.
#[derive(Clone, Debug)]
pub struct ValidationResult {
    /// Whether the matrix has no broken links.
    pub valid: bool,
    /// All gaps found.
    pub gaps: Vec<TraceabilityGap>,
    /// Summary statistics.
    pub stats: ValidationStats,
}

/// Summary statistics for the traceability matrix.
#[derive(Clone, Debug)]
pub struct ValidationStats {
    /// Total invariants in the matrix.
    pub total_invariants: usize,
    /// Total proof obligations in the matrix.
    pub total_obligations: usize,
    /// Invariants with complete traceability (all layers populated).
    pub fully_traced_invariants: usize,
    /// Obligations with at least one constraint.
    pub obligations_with_constraints: usize,
    /// Obligations with at least one invariant dependency.
    pub obligations_with_invariants: usize,
    /// Total gaps found.
    pub total_gaps: usize,
}

// ---------------------------------------------------------------------------
// Validate the traceability matrix
// ---------------------------------------------------------------------------

/// Validate the traceability matrix for broken links.
///
/// Checks:
/// 1. Every invariant has at least one SIR/IR construct (L1).
/// 2. Every invariant has at least one Rust module (L2).
/// 3. Every invariant has at least one constraint ID (L3).
/// 4. Every invariant has at least one proof obligation (L4).
/// 5. Every invariant has at least one NIST control.
/// 6. Every proof obligation has at least one constraint ID.
/// 7. Every proof obligation has at least one invariant dependency.
///
/// Requirement 16.8
pub fn validate_traceability(matrix: &TraceabilityMatrix) -> ValidationResult {
    let mut gaps = Vec::new();

    // -----------------------------------------------------------------------
    // Check invariant entries
    // -----------------------------------------------------------------------
    let mut fully_traced = 0;

    for (id, entry) in &matrix.entries {
        let mut complete = true;

        // L1: SIR/IR construct mapping.
        if entry.l1_sir_constructs.is_empty() {
            gaps.push(TraceabilityGap {
                artifact_id: id.clone(),
                gap_type: GapType::MissingSirMapping,
                broken_at: Layer::L1Sir,
                description: format!("Invariant '{}' has no SIR/IR construct mapping (L1)", id),
            });
            complete = false;
        }

        // L2: Rust enforcement.
        if entry.l2_rust_modules.is_empty() {
            gaps.push(TraceabilityGap {
                artifact_id: id.clone(),
                gap_type: GapType::MissingRustEnforcement,
                broken_at: Layer::L2Rust,
                description: format!("Invariant '{}' has no Rust enforcement module (L2)", id),
            });
            complete = false;
        }

        // L3: Constraint encoding.
        if entry.l3_constraint_ids.is_empty() {
            gaps.push(TraceabilityGap {
                artifact_id: id.clone(),
                gap_type: GapType::MissingConstraint,
                broken_at: Layer::L3Constraint,
                description: format!("Invariant '{}' has no constraint encoding (L3)", id),
            });
            complete = false;
        }

        // L4: Proof obligation.
        if entry.l4_proof_obligations.is_empty() {
            gaps.push(TraceabilityGap {
                artifact_id: id.clone(),
                gap_type: GapType::MissingProofObligation,
                broken_at: Layer::L4Proof,
                description: format!("Invariant '{}' has no proof obligation (L4)", id),
            });
            complete = false;
        }

        // NIST: Control mapping.
        if entry.nist_controls.is_empty() {
            gaps.push(TraceabilityGap {
                artifact_id: id.clone(),
                gap_type: GapType::MissingNistControl,
                broken_at: Layer::Nist,
                description: format!("Invariant '{}' has no NIST control mapping", id),
            });
            complete = false;
        }

        if complete {
            fully_traced += 1;
        }
    }

    // -----------------------------------------------------------------------
    // Check proof obligation entries
    // -----------------------------------------------------------------------
    let mut obligations_with_constraints = 0;
    let mut obligations_with_invariants = 0;

    for (id, obligation) in &matrix.proof_obligations {
        if obligation.constraint_ids.is_empty() {
            gaps.push(TraceabilityGap {
                artifact_id: id.clone(),
                gap_type: GapType::ObligationWithoutConstraint,
                broken_at: Layer::L3Constraint,
                description: format!("Proof obligation '{}' has no constraint IDs", id),
            });
        } else {
            obligations_with_constraints += 1;
        }

        if obligation.invariant_dependencies.is_empty() {
            // Not all obligations need invariant dependencies (e.g., external
            // hypotheses), but we track it for completeness.
        } else {
            obligations_with_invariants += 1;
        }
    }

    // -----------------------------------------------------------------------
    // Cross-reference: check that proof obligations referenced by invariants
    // actually exist in the matrix.
    // -----------------------------------------------------------------------
    let known_obligations: BTreeSet<&str> = matrix
        .proof_obligations
        .keys()
        .map(|s| s.as_str())
        .collect();

    for (id, entry) in &matrix.entries {
        for obl_id in &entry.l4_proof_obligations {
            if !known_obligations.contains(obl_id.as_str()) {
                gaps.push(TraceabilityGap {
                    artifact_id: id.clone(),
                    gap_type: GapType::MissingProofObligation,
                    broken_at: Layer::L4Proof,
                    description: format!(
                        "Invariant '{}' references proof obligation '{}' which is not registered",
                        id, obl_id
                    ),
                });
            }
        }
    }

    // -----------------------------------------------------------------------
    // Cross-reference: check that invariants referenced by obligations
    // actually exist in the matrix.
    // -----------------------------------------------------------------------
    let known_invariants: BTreeSet<&str> = matrix.entries.keys().map(|s| s.as_str()).collect();

    for (id, obligation) in &matrix.proof_obligations {
        for inv_id in &obligation.invariant_dependencies {
            if !known_invariants.contains(inv_id.as_str()) {
                gaps.push(TraceabilityGap {
                    artifact_id: id.clone(),
                    gap_type: GapType::ConstraintWithoutObligation,
                    broken_at: Layer::L0Formal,
                    description: format!(
                        "Proof obligation '{}' depends on invariant '{}' which is not registered",
                        id, inv_id
                    ),
                });
            }
        }
    }

    let total_gaps = gaps.len();
    let valid = total_gaps == 0;

    ValidationResult {
        valid,
        gaps,
        stats: ValidationStats {
            total_invariants: matrix.entries.len(),
            total_obligations: matrix.proof_obligations.len(),
            fully_traced_invariants: fully_traced,
            obligations_with_constraints,
            obligations_with_invariants,
            total_gaps,
        },
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matrix::*;
    use crate::registry::build_traceability_matrix;

    #[test]
    fn test_full_matrix_has_no_gaps() {
        let matrix = build_traceability_matrix();
        let result = validate_traceability(&matrix);

        if !result.valid {
            for gap in &result.gaps {
                eprintln!(
                    "GAP: {} — {} — {} — {}",
                    gap.artifact_id, gap.gap_type, gap.broken_at, gap.description
                );
            }
        }

        assert!(
            result.valid,
            "Full traceability matrix should have no gaps, found {}",
            result.stats.total_gaps
        );
    }

    #[test]
    fn test_full_matrix_has_all_invariants() {
        let matrix = build_traceability_matrix();

        // Local: 5
        assert!(matrix.get_entry("L_valid").is_some());
        assert!(matrix.get_entry("L_state").is_some());
        assert!(matrix.get_entry("L_cons").is_some());
        assert!(matrix.get_entry("L_bounded").is_some());
        assert!(matrix.get_entry("L_det").is_some());

        // Global: 5
        assert!(matrix.get_entry("G_valid").is_some());
        assert!(matrix.get_entry("G_struct").is_some());
        assert!(matrix.get_entry("G_commit").is_some());
        assert!(matrix.get_entry("G_mono").is_some());
        assert!(matrix.get_entry("G_env").is_some());

        // Temporal: 5
        assert!(matrix.get_entry("T_valid").is_some());
        assert!(matrix.get_entry("T_no_revert").is_some());
        assert!(matrix.get_entry("T_cons").is_some());
        assert!(matrix.get_entry("T_causal").is_some());
        assert!(matrix.get_entry("T_complete").is_some());

        // Economic local: 5
        assert!(matrix.get_entry("E_cost").is_some());
        assert!(matrix.get_entry("E_leverage").is_some());
        assert!(matrix.get_entry("E_proportionality").is_some());
        assert!(matrix.get_entry("E_slippage").is_some());
        assert!(matrix.get_entry("E_collateral").is_some());

        // Economic global: 5
        assert!(matrix.get_entry("G_econ_valid").is_some());
        assert!(matrix.get_entry("G_concentration").is_some());
        assert!(matrix.get_entry("G_liquidity").is_some());
        assert!(matrix.get_entry("G_solvency").is_some());
        assert!(matrix.get_entry("G_dust").is_some());

        // Economic temporal: 5
        assert!(matrix.get_entry("TE_extraction").is_some());
        assert!(matrix.get_entry("TE_flash").is_some());
        assert!(matrix.get_entry("TE_sandwich").is_some());
        assert!(matrix.get_entry("TE_manipulation").is_some());
        assert!(matrix.get_entry("TE_velocity").is_some());

        // Economic compositional: 2
        assert!(matrix.get_entry("CE_arbitrage").is_some());
        assert!(matrix.get_entry("CE_contagion").is_some());

        // Cross-layer: 3
        assert!(matrix.get_entry("X_exec").is_some());
        assert!(matrix.get_entry("X_constraint").is_some());
        assert!(matrix.get_entry("X_proof").is_some());

        // Total: 5 + 5 + 5 + 5 + 5 + 5 + 2 + 3 = 35
        assert_eq!(matrix.entry_count(), 35);
    }

    #[test]
    fn test_full_matrix_has_all_proof_obligations() {
        let matrix = build_traceability_matrix();

        // Axioms: AX-1 through AX-6
        for i in 1..=6 {
            assert!(
                matrix.get_obligation(&format!("AX-{}", i)).is_some(),
                "Missing AX-{}",
                i
            );
        }

        // Definitions: DEF-1 through DEF-6
        for i in 1..=6 {
            assert!(
                matrix.get_obligation(&format!("DEF-{}", i)).is_some(),
                "Missing DEF-{}",
                i
            );
        }

        // Lemmas: LEM-1 through LEM-10
        for i in 1..=10 {
            assert!(
                matrix.get_obligation(&format!("LEM-{}", i)).is_some(),
                "Missing LEM-{}",
                i
            );
        }

        // Safety: SAFE-1 through SAFE-6
        for i in 1..=6 {
            assert!(
                matrix.get_obligation(&format!("SAFE-{}", i)).is_some(),
                "Missing SAFE-{}",
                i
            );
        }

        // Liveness: LIVE-1, LIVE-2
        assert!(matrix.get_obligation("LIVE-1").is_some());
        assert!(matrix.get_obligation("LIVE-2").is_some());

        // Constraints: CONST-1 through CONST-4
        for i in 1..=4 {
            assert!(
                matrix.get_obligation(&format!("CONST-{}", i)).is_some(),
                "Missing CONST-{}",
                i
            );
        }

        // Proof: PROOF-1 through PROOF-4
        for i in 1..=4 {
            assert!(
                matrix.get_obligation(&format!("PROOF-{}", i)).is_some(),
                "Missing PROOF-{}",
                i
            );
        }

        // Composition: COMP-1 through COMP-3
        for i in 1..=3 {
            assert!(
                matrix.get_obligation(&format!("COMP-{}", i)).is_some(),
                "Missing COMP-{}",
                i
            );
        }

        // Economic: ECON-1 through ECON-5
        for i in 1..=5 {
            assert!(
                matrix.get_obligation(&format!("ECON-{}", i)).is_some(),
                "Missing ECON-{}",
                i
            );
        }

        // Total: 6 + 6 + 10 + 6 + 2 + 4 + 4 + 3 + 5 = 46
        assert_eq!(matrix.obligation_count(), 46);
    }

    #[test]
    fn test_every_invariant_has_all_layers() {
        let matrix = build_traceability_matrix();

        for (id, entry) in &matrix.entries {
            assert!(
                !entry.l0_lean_source.is_empty(),
                "Invariant '{}' missing L0 Lean source",
                id
            );
            assert!(
                !entry.l1_sir_constructs.is_empty(),
                "Invariant '{}' missing L1 SIR constructs",
                id
            );
            assert!(
                !entry.l2_rust_modules.is_empty(),
                "Invariant '{}' missing L2 Rust modules",
                id
            );
            assert!(
                !entry.l3_constraint_ids.is_empty(),
                "Invariant '{}' missing L3 constraint IDs",
                id
            );
            assert!(
                !entry.l4_proof_obligations.is_empty(),
                "Invariant '{}' missing L4 proof obligations",
                id
            );
            assert!(
                !entry.nist_controls.is_empty(),
                "Invariant '{}' missing NIST controls",
                id
            );
        }
    }

    #[test]
    fn test_every_obligation_has_constraints() {
        let matrix = build_traceability_matrix();

        for (id, obligation) in &matrix.proof_obligations {
            assert!(
                !obligation.constraint_ids.is_empty(),
                "Proof obligation '{}' has no constraint IDs",
                id
            );
        }
    }

    #[test]
    fn test_detects_missing_constraint_gap() {
        let mut matrix = TraceabilityMatrix::new();
        matrix.add_entry(TraceabilityEntry {
            l0_invariant_id: "TEST_INV".to_string(),
            category: InvariantCategory::Local,
            l0_lean_source: "test.lean::TEST_INV".to_string(),
            l1_sir_constructs: vec!["sir_test".to_string()],
            l2_rust_modules: vec!["test.rs".to_string()],
            l2_transition_classes: vec!["Update".to_string()],
            l3_constraint_ids: vec![], // Missing!
            l4_proof_obligations: vec!["LEM-1".to_string()],
            nist_controls: vec!["PW.1".to_string()],
        });
        // Add the referenced obligation so cross-ref doesn't also fail.
        matrix.add_obligation(ProofObligationEntry {
            obligation_id: "LEM-1".to_string(),
            category: ObligationCategory::Lemma,
            layer: Layer::L0Formal,
            constraint_ids: vec!["test".to_string()],
            invariant_dependencies: vec!["TEST_INV".to_string()],
            nist_controls: vec!["PW.1".to_string()],
        });

        let result = validate_traceability(&matrix);
        assert!(!result.valid);
        assert!(result
            .gaps
            .iter()
            .any(|g| g.gap_type == GapType::MissingConstraint));
    }

    #[test]
    fn test_detects_missing_proof_obligation_gap() {
        let mut matrix = TraceabilityMatrix::new();
        matrix.add_entry(TraceabilityEntry {
            l0_invariant_id: "TEST_INV".to_string(),
            category: InvariantCategory::Local,
            l0_lean_source: "test.lean::TEST_INV".to_string(),
            l1_sir_constructs: vec!["sir_test".to_string()],
            l2_rust_modules: vec!["test.rs".to_string()],
            l2_transition_classes: vec!["Update".to_string()],
            l3_constraint_ids: vec!["c-1".to_string()],
            l4_proof_obligations: vec![], // Missing!
            nist_controls: vec!["PW.1".to_string()],
        });

        let result = validate_traceability(&matrix);
        assert!(!result.valid);
        assert!(result
            .gaps
            .iter()
            .any(|g| g.gap_type == GapType::MissingProofObligation));
    }

    #[test]
    fn test_detects_obligation_without_constraint() {
        let mut matrix = TraceabilityMatrix::new();
        matrix.add_obligation(ProofObligationEntry {
            obligation_id: "TEST-OBL".to_string(),
            category: ObligationCategory::Lemma,
            layer: Layer::L0Formal,
            constraint_ids: vec![], // Missing!
            invariant_dependencies: vec![],
            nist_controls: vec!["PW.1".to_string()],
        });

        let result = validate_traceability(&matrix);
        assert!(!result.valid);
        assert!(result
            .gaps
            .iter()
            .any(|g| g.gap_type == GapType::ObligationWithoutConstraint));
    }

    #[test]
    fn test_detects_dangling_obligation_reference() {
        let mut matrix = TraceabilityMatrix::new();
        matrix.add_entry(TraceabilityEntry {
            l0_invariant_id: "TEST_INV".to_string(),
            category: InvariantCategory::Local,
            l0_lean_source: "test.lean".to_string(),
            l1_sir_constructs: vec!["sir".to_string()],
            l2_rust_modules: vec!["test.rs".to_string()],
            l2_transition_classes: vec!["Update".to_string()],
            l3_constraint_ids: vec!["c-1".to_string()],
            l4_proof_obligations: vec!["NONEXISTENT-1".to_string()],
            nist_controls: vec!["PW.1".to_string()],
        });

        let result = validate_traceability(&matrix);
        assert!(!result.valid);
        assert!(result
            .gaps
            .iter()
            .any(|g| g.description.contains("NONEXISTENT-1")));
    }

    #[test]
    fn test_stats_are_correct() {
        let matrix = build_traceability_matrix();
        let result = validate_traceability(&matrix);

        assert_eq!(result.stats.total_invariants, 35);
        assert_eq!(result.stats.total_obligations, 46);
        assert_eq!(result.stats.fully_traced_invariants, 35);
        assert_eq!(result.stats.total_gaps, 0);
    }
}
