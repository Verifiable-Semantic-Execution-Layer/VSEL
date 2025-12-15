//! Constraint coverage matrix — maps invariants, fields, and proof obligations
//! to constraint IDs across transition classes.
//!
//! Derived from: CONSTRAINT_COVERAGE_MATRIX.md, design.md Component 6.
//!
//! Requirements: 5.9 (constraint coverage), 12.9 (coverage matrix completeness),
//! 12.10 (coverage gap detection).
//!
//! The coverage matrix ensures every (invariant × transition class),
//! (field × transition class), and proof obligation cell is covered by
//! at least one constraint. Any gap or partial coverage is a finding.

use std::collections::BTreeMap;

use crate::compiler::{
    Constraint, ConstraintCategory, ConstraintId, ConstraintSystem,
};
use vsel_sir::types::SirProgram;

// ---------------------------------------------------------------------------
// Coverage level
// ---------------------------------------------------------------------------

/// Coverage level for a single cell in the coverage matrix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoverageLevel {
    /// All expected constraints are present.
    Full,
    /// Some constraints are present but coverage is incomplete.
    Partial,
    /// No constraints cover this cell.
    Gap,
}

// ---------------------------------------------------------------------------
// Coverage cell
// ---------------------------------------------------------------------------

/// A single cell in the coverage matrix — holds constraint IDs and level.
#[derive(Clone, Debug, PartialEq)]
pub struct CoverageCell {
    /// Constraint IDs that cover this cell.
    pub constraint_ids: Vec<ConstraintId>,
    /// Coverage level for this cell.
    pub level: CoverageLevel,
}

impl CoverageCell {
    /// Create a new coverage cell from constraint IDs.
    ///
    /// Level is determined by the number of constraints:
    /// - 0 constraints → Gap
    /// - ≥1 constraints → Full
    fn from_ids(ids: Vec<ConstraintId>) -> Self {
        let level = if ids.is_empty() {
            CoverageLevel::Gap
        } else {
            CoverageLevel::Full
        };
        Self {
            constraint_ids: ids,
            level,
        }
    }
}

// ---------------------------------------------------------------------------
// Finding types
// ---------------------------------------------------------------------------

/// Type of coverage finding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FindingType {
    /// No constraints cover this cell — critical gap.
    Gap,
    /// Some constraints present but coverage is incomplete.
    Partial,
}

/// A coverage finding — produced when a cell is not at Full coverage.
#[derive(Clone, Debug, PartialEq)]
pub struct CoverageFinding {
    /// Type of finding (Gap or Partial).
    pub finding_type: FindingType,
    /// Dimension of the finding (e.g., "invariant", "field", "proof_obligation").
    pub dimension: String,
    /// Key identifying the cell (e.g., "L_cons × Update").
    pub key: String,
    /// Human-readable description of the finding.
    pub description: String,
}

// ---------------------------------------------------------------------------
// Coverage matrix
// ---------------------------------------------------------------------------

/// The full constraint coverage matrix.
///
/// Maps three dimensions to constraint IDs:
/// 1. invariant_name × transition_class → constraint IDs
/// 2. field_name × transition_class → constraint IDs
/// 3. proof_obligation → constraint IDs
#[derive(Clone, Debug)]
pub struct CoverageMatrix {
    /// Invariant × transition class → coverage cell.
    pub invariant_coverage: BTreeMap<(String, String), CoverageCell>,
    /// Field × transition class → coverage cell.
    pub field_coverage: BTreeMap<(String, String), CoverageCell>,
    /// Proof obligation → coverage cell.
    pub proof_obligation_coverage: BTreeMap<String, CoverageCell>,
}

impl CoverageMatrix {
    /// Validate the coverage matrix — every cell must be at Full coverage.
    ///
    /// Returns findings for any Gap or Partial cells.
    pub fn validate(&self) -> Vec<CoverageFinding> {
        let mut findings = Vec::new();

        // Check invariant coverage.
        for ((invariant, transition_class), cell) in &self.invariant_coverage {
            match cell.level {
                CoverageLevel::Full => {}
                CoverageLevel::Partial => {
                    findings.push(CoverageFinding {
                        finding_type: FindingType::Partial,
                        dimension: "invariant".to_string(),
                        key: format!("{} × {}", invariant, transition_class),
                        description: format!(
                            "Partial coverage for invariant '{}' on transition class '{}': \
                             only {} constraint(s) found",
                            invariant,
                            transition_class,
                            cell.constraint_ids.len()
                        ),
                    });
                }
                CoverageLevel::Gap => {
                    findings.push(CoverageFinding {
                        finding_type: FindingType::Gap,
                        dimension: "invariant".to_string(),
                        key: format!("{} × {}", invariant, transition_class),
                        description: format!(
                            "Gap: no constraints cover invariant '{}' on transition class '{}'",
                            invariant, transition_class
                        ),
                    });
                }
            }
        }

        // Check field coverage.
        for ((field, transition_class), cell) in &self.field_coverage {
            match cell.level {
                CoverageLevel::Full => {}
                CoverageLevel::Partial => {
                    findings.push(CoverageFinding {
                        finding_type: FindingType::Partial,
                        dimension: "field".to_string(),
                        key: format!("{} × {}", field, transition_class),
                        description: format!(
                            "Partial coverage for field '{}' on transition class '{}': \
                             only {} constraint(s) found",
                            field,
                            transition_class,
                            cell.constraint_ids.len()
                        ),
                    });
                }
                CoverageLevel::Gap => {
                    findings.push(CoverageFinding {
                        finding_type: FindingType::Gap,
                        dimension: "field".to_string(),
                        key: format!("{} × {}", field, transition_class),
                        description: format!(
                            "Gap: no constraints cover field '{}' on transition class '{}'",
                            field, transition_class
                        ),
                    });
                }
            }
        }

        // Check proof obligation coverage.
        for (obligation, cell) in &self.proof_obligation_coverage {
            match cell.level {
                CoverageLevel::Full => {}
                CoverageLevel::Partial => {
                    findings.push(CoverageFinding {
                        finding_type: FindingType::Partial,
                        dimension: "proof_obligation".to_string(),
                        key: obligation.clone(),
                        description: format!(
                            "Partial coverage for proof obligation '{}': \
                             only {} constraint(s) found",
                            obligation,
                            cell.constraint_ids.len()
                        ),
                    });
                }
                CoverageLevel::Gap => {
                    findings.push(CoverageFinding {
                        finding_type: FindingType::Gap,
                        dimension: "proof_obligation".to_string(),
                        key: obligation.clone(),
                        description: format!(
                            "Gap: no constraints cover proof obligation '{}'",
                            obligation
                        ),
                    });
                }
            }
        }

        findings
    }
}

// ---------------------------------------------------------------------------
// Standard proof obligations
// ---------------------------------------------------------------------------

/// Standard proof obligation identifiers.
///
/// - CONST-1: No unconstrained witness variables.
/// - CONST-2: No unused witness inputs.
/// - CONST-3: Branch completeness — all conditional branches constrained.
/// - CONST-4: Deterministic constraint generation.
const PROOF_OBLIGATIONS: &[&str] = &["CONST-1", "CONST-2", "CONST-3", "CONST-4"];

// ---------------------------------------------------------------------------
// Constraint analysis helpers
// ---------------------------------------------------------------------------

/// Extract the invariant name from a constraint description, if it references one.
///
/// Invariant constraints have descriptions like:
///   "invariant 'L_cons' (category: local) must hold"
fn extract_invariant_name(constraint: &Constraint) -> Option<String> {
    if constraint.category != ConstraintCategory::Invariant {
        return None;
    }
    // Parse invariant name from description pattern: "invariant '<name>' ..."
    let desc = &constraint.description;
    let prefix = "invariant '";
    let idx = desc.find(prefix)?;
    let after_prefix = &desc[idx + prefix.len()..];
    let end = after_prefix.find('\'')?;
    Some(after_prefix[..end].to_string())
}

/// Extract field names referenced by a constraint expression.
///
/// Looks for FieldAccess patterns and carry-over descriptions.
fn extract_field_names(constraint: &Constraint) -> Vec<String> {
    let mut fields = Vec::new();

    // Carry-over constraints reference fields in their description:
    //   "carry-over: s'.data = s.data (field not in AllowedMutations)"
    if constraint.category == ConstraintCategory::CarryOver {
        if let Some(start) = constraint.description.find("s'.") {
            let rest = &constraint.description[start + 3..];
            if let Some(end) = rest.find(' ') {
                fields.push(rest[..end].to_string());
            }
        }
        return fields;
    }

    // For structural/semantic constraints, extract field names from the expression.
    extract_fields_from_expr(&constraint.expr, &mut fields);
    fields.sort();
    fields.dedup();
    fields
}

/// Recursively extract field names from a constraint expression.
fn extract_fields_from_expr(expr: &crate::compiler::ConstraintExpr, fields: &mut Vec<String>) {
    use crate::compiler::ConstraintExpr;
    match expr {
        ConstraintExpr::FieldAccess(_, field) => {
            fields.push(field.clone());
        }
        ConstraintExpr::Eq(l, r)
        | ConstraintExpr::Neq(l, r)
        | ConstraintExpr::Lt(l, r)
        | ConstraintExpr::Le(l, r)
        | ConstraintExpr::Gt(l, r)
        | ConstraintExpr::Ge(l, r)
        | ConstraintExpr::Add(l, r)
        | ConstraintExpr::Sub(l, r)
        | ConstraintExpr::Mul(l, r)
        | ConstraintExpr::And(l, r)
        | ConstraintExpr::Or(l, r) => {
            extract_fields_from_expr(l, fields);
            extract_fields_from_expr(r, fields);
        }
        ConstraintExpr::IfThenElse(c, t, e) => {
            extract_fields_from_expr(c, fields);
            extract_fields_from_expr(t, fields);
            extract_fields_from_expr(e, fields);
        }
        ConstraintExpr::Constant(_)
        | ConstraintExpr::BoolConstant(_)
        | ConstraintExpr::WitnessRef(_)
        | ConstraintExpr::PublicInputRef(_) => {}
    }
}

/// Determine which transition class a constraint belongs to based on its description.
///
/// Transition constraints have descriptions like:
///   "precondition 0 for transition 'deposit'"
///   "body constraint for transition 'deposit'"
///   "carry-over: s'.nonce = s.nonce ..."
fn extract_transition_name(constraint: &Constraint) -> Option<String> {
    let desc = &constraint.description;
    // Pattern: "... for transition '<name>'"
    if let Some(idx) = desc.find("for transition '") {
        let after = &desc[idx + "for transition '".len()..];
        if let Some(end) = after.find('\'') {
            return Some(after[..end].to_string());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Build coverage matrix
// ---------------------------------------------------------------------------

/// Build the constraint coverage matrix from a SIR program and its compiled
/// constraint system.
///
/// Analyzes the constraint system to map each constraint to its relevant
/// invariant, field, and transition class. Produces a matrix where every
/// cell should be at Full coverage.
///
/// Requirements: 5.9, 12.9, 12.10
pub fn build_coverage_matrix(
    program: &SirProgram,
    system: &ConstraintSystem,
) -> CoverageMatrix {
    // Collect all transition classes from the program.
    let transition_classes: Vec<String> = program
        .transitions
        .iter()
        .map(|t| t.class.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();

    // Build a map from transition name → transition class.
    let transition_name_to_class: BTreeMap<String, String> = program
        .transitions
        .iter()
        .map(|t| (t.name.clone(), t.class.clone()))
        .collect();

    // Collect all invariant names from the program.
    let invariant_names: Vec<String> = program
        .invariants
        .iter()
        .map(|inv| inv.name.clone())
        .collect();

    // Collect all field names from the state schema.
    let field_names: Vec<String> = program
        .state_schema
        .fields
        .iter()
        .map(|f| f.name.clone())
        .collect();

    // -----------------------------------------------------------------------
    // 1. Invariant coverage: (invariant_name, transition_class) → constraint IDs
    // -----------------------------------------------------------------------
    let mut invariant_coverage: BTreeMap<(String, String), Vec<ConstraintId>> = BTreeMap::new();

    // Initialize all cells.
    for inv_name in &invariant_names {
        for tc in &transition_classes {
            invariant_coverage.insert((inv_name.clone(), tc.clone()), Vec::new());
        }
    }

    // Map invariant constraints to their cells.
    // Invariant constraints apply to ALL transition classes (they must hold
    // on every transition).
    for constraint in &system.constraints {
        if let Some(inv_name) = extract_invariant_name(constraint) {
            for tc in &transition_classes {
                if let Some(ids) = invariant_coverage.get_mut(&(inv_name.clone(), tc.clone())) {
                    ids.push(constraint.id.clone());
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // 2. Field coverage: (field_name, transition_class) → constraint IDs
    // -----------------------------------------------------------------------
    let mut field_coverage: BTreeMap<(String, String), Vec<ConstraintId>> = BTreeMap::new();

    // Initialize all cells.
    for field_name in &field_names {
        for tc in &transition_classes {
            field_coverage.insert((field_name.clone(), tc.clone()), Vec::new());
        }
    }

    // Build a set of (field, transition_class) pairs that have carry-over
    // constraints, derived from the program structure. For each transition,
    // fields NOT in allowed_mutations get carry-over constraints.
    let mut carry_over_fields: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for transition in &program.transitions {
        let allowed: std::collections::BTreeSet<&str> = transition
            .allowed_mutations
            .iter()
            .map(|s| s.as_str())
            .collect();
        for field in &field_names {
            if !allowed.contains(field.as_str()) {
                carry_over_fields
                    .entry(field.clone())
                    .or_default()
                    .push(transition.class.clone());
            }
        }
    }

    // Map constraints to field × transition class cells.
    for constraint in &system.constraints {
        let fields = extract_field_names(constraint);
        let transition_class = extract_transition_name(constraint)
            .and_then(|name| transition_name_to_class.get(&name).cloned());

        for field in &fields {
            if !field_names.contains(field) {
                continue;
            }

            if constraint.category == ConstraintCategory::CarryOver {
                // Carry-over constraints don't embed the transition name in
                // their description. Use the program structure to assign them
                // to the correct transition classes.
                if let Some(classes) = carry_over_fields.get(field) {
                    for tc in classes {
                        if let Some(ids) = field_coverage.get_mut(&(field.clone(), tc.clone())) {
                            ids.push(constraint.id.clone());
                        }
                    }
                }
            } else if let Some(ref tc) = transition_class {
                // Constraint is associated with a specific transition class.
                if let Some(ids) = field_coverage.get_mut(&(field.clone(), tc.clone())) {
                    ids.push(constraint.id.clone());
                }
            } else if constraint.category == ConstraintCategory::Invariant {
                // Invariant constraints apply to all transition classes.
                for tc in &transition_classes {
                    if let Some(ids) = field_coverage.get_mut(&(field.clone(), tc.clone())) {
                        ids.push(constraint.id.clone());
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // 3. Proof obligation coverage: obligation → constraint IDs
    // -----------------------------------------------------------------------
    let mut proof_obligation_coverage: BTreeMap<String, Vec<ConstraintId>> = BTreeMap::new();

    for obligation in PROOF_OBLIGATIONS {
        proof_obligation_coverage.insert(obligation.to_string(), Vec::new());
    }

    for constraint in &system.constraints {
        // CONST-1: No unconstrained witness variables.
        // Every witness variable must be referenced by at least one constraint.
        // Structural and semantic constraints contribute to CONST-1.
        if constraint.category == ConstraintCategory::Structural
            || constraint.category == ConstraintCategory::Semantic
        {
            if let Some(ids) = proof_obligation_coverage.get_mut("CONST-1") {
                ids.push(constraint.id.clone());
            }
        }

        // CONST-2: No unused witness inputs.
        // Semantic constraints (pre/postconditions) that reference inputs
        // contribute to CONST-2.
        if constraint.category == ConstraintCategory::Semantic
            || constraint.category == ConstraintCategory::CarryOver
        {
            if let Some(ids) = proof_obligation_coverage.get_mut("CONST-2") {
                ids.push(constraint.id.clone());
            }
        }

        // CONST-3: Branch completeness.
        // Branch constraints from conditionals (If, Match) contribute.
        if constraint.category == ConstraintCategory::Branch {
            if let Some(ids) = proof_obligation_coverage.get_mut("CONST-3") {
                ids.push(constraint.id.clone());
            }
        }

        // CONST-4: Deterministic constraint generation.
        // All constraints contribute to CONST-4 (the entire system is
        // deterministically generated).
        if let Some(ids) = proof_obligation_coverage.get_mut("CONST-4") {
            ids.push(constraint.id.clone());
        }
    }

    // -----------------------------------------------------------------------
    // Convert to CoverageCell
    // -----------------------------------------------------------------------
    let invariant_coverage = invariant_coverage
        .into_iter()
        .map(|(key, ids)| (key, CoverageCell::from_ids(ids)))
        .collect();

    let field_coverage = field_coverage
        .into_iter()
        .map(|(key, ids)| (key, CoverageCell::from_ids(ids)))
        .collect();

    let proof_obligation_coverage = proof_obligation_coverage
        .into_iter()
        .map(|(key, ids)| (key, CoverageCell::from_ids(ids)))
        .collect();

    CoverageMatrix {
        invariant_coverage,
        field_coverage,
        proof_obligation_coverage,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::{compile, reset_constraint_id_counter};
    use vsel_sir::types::*;

    fn make_test_program() -> SirProgram {
        SirProgram {
            version: "0.1.0".into(),
            state_schema: SirStateSchema {
                fields: vec![
                    SirFieldSchema {
                        name: "balance".into(),
                        field_type: "Int".into(),
                    },
                    SirFieldSchema {
                        name: "nonce".into(),
                        field_type: "Int".into(),
                    },
                ],
            },
            input_schema: SirInputSchema {
                fields: vec![SirFieldSchema {
                    name: "amount".into(),
                    field_type: "Int".into(),
                }],
            },
            transitions: vec![SirTransition {
                name: "deposit".into(),
                class: "Update".into(),
                preconditions: vec![SirExpr::BinOp {
                    op: "gt".into(),
                    left: Box::new(SirExpr::FieldAccess {
                        expr: Box::new(SirExpr::Var {
                            name: "input".into(),
                        }),
                        field: "amount".into(),
                    }),
                    right: Box::new(SirExpr::Literal {
                        value: SirValue::Int { value: 0 },
                    }),
                }],
                postconditions: vec![],
                body: SirExpr::BinOp {
                    op: "add".into(),
                    left: Box::new(SirExpr::FieldAccess {
                        expr: Box::new(SirExpr::Var {
                            name: "state".into(),
                        }),
                        field: "balance".into(),
                    }),
                    right: Box::new(SirExpr::FieldAccess {
                        expr: Box::new(SirExpr::Var {
                            name: "input".into(),
                        }),
                        field: "amount".into(),
                    }),
                },
                allowed_mutations: vec!["balance".to_string()],
            }],
            invariants: vec![SirInvariant {
                name: "L_cons".into(),
                category: "local".into(),
                expr: SirExpr::BinOp {
                    op: "ge".into(),
                    left: Box::new(SirExpr::FieldAccess {
                        expr: Box::new(SirExpr::Var {
                            name: "state".into(),
                        }),
                        field: "balance".into(),
                    }),
                    right: Box::new(SirExpr::Literal {
                        value: SirValue::Int { value: 0 },
                    }),
                },
            }],
            observables: vec![],
        }
    }

    #[test]
    fn test_build_coverage_matrix_invariant_coverage() {
        let program = make_test_program();
        let system = compile(&program);
        let matrix = build_coverage_matrix(&program, &system);

        // L_cons should be covered for the "Update" transition class.
        let cell = matrix
            .invariant_coverage
            .get(&("L_cons".to_string(), "Update".to_string()));
        assert!(cell.is_some(), "invariant coverage cell must exist");
        let cell = cell.unwrap();
        assert_eq!(
            cell.level,
            CoverageLevel::Full,
            "L_cons × Update should be Full"
        );
        assert!(
            !cell.constraint_ids.is_empty(),
            "must have constraint IDs"
        );
    }

    #[test]
    fn test_build_coverage_matrix_field_coverage() {
        let program = make_test_program();
        let system = compile(&program);
        let matrix = build_coverage_matrix(&program, &system);

        // "nonce" field should have carry-over coverage for "Update".
        let cell = matrix
            .field_coverage
            .get(&("nonce".to_string(), "Update".to_string()));
        assert!(cell.is_some(), "field coverage cell must exist for nonce × Update");
        let cell = cell.unwrap();
        assert_eq!(
            cell.level,
            CoverageLevel::Full,
            "nonce × Update should be Full (carry-over)"
        );
    }

    #[test]
    fn test_build_coverage_matrix_field_coverage_balance() {
        let program = make_test_program();
        let system = compile(&program);
        let matrix = build_coverage_matrix(&program, &system);

        // "balance" field should have coverage for "Update" (body + invariant).
        let cell = matrix
            .field_coverage
            .get(&("balance".to_string(), "Update".to_string()));
        assert!(cell.is_some(), "field coverage cell must exist for balance × Update");
        let cell = cell.unwrap();
        assert_eq!(
            cell.level,
            CoverageLevel::Full,
            "balance × Update should be Full"
        );
    }

    #[test]
    fn test_build_coverage_matrix_proof_obligations() {
        let program = make_test_program();
        let system = compile(&program);
        let matrix = build_coverage_matrix(&program, &system);

        // CONST-1 should be covered (structural + semantic constraints exist).
        let cell = matrix.proof_obligation_coverage.get("CONST-1");
        assert!(cell.is_some());
        assert_eq!(cell.unwrap().level, CoverageLevel::Full);

        // CONST-2 should be covered (semantic + carry-over constraints exist).
        let cell = matrix.proof_obligation_coverage.get("CONST-2");
        assert!(cell.is_some());
        assert_eq!(cell.unwrap().level, CoverageLevel::Full);

        // CONST-4 should be covered (all constraints contribute).
        let cell = matrix.proof_obligation_coverage.get("CONST-4");
        assert!(cell.is_some());
        assert_eq!(cell.unwrap().level, CoverageLevel::Full);
    }

    #[test]
    fn test_validate_full_coverage_no_findings() {
        let program = make_test_program();
        let system = compile(&program);
        let matrix = build_coverage_matrix(&program, &system);
        let findings = matrix.validate();

        // Filter out CONST-3 findings — the test program has no conditionals
        // in transitions, so CONST-3 (branch completeness) may be a gap.
        let non_const3_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.key != "CONST-3")
            .collect();

        // All other cells should be Full.
        for finding in &non_const3_findings {
            panic!(
                "unexpected finding: {:?} — {} — {}",
                finding.finding_type, finding.key, finding.description
            );
        }
    }

    #[test]
    fn test_validate_detects_gap_for_missing_branch_constraints() {
        // A program with no conditionals should have a CONST-3 gap.
        let program = SirProgram {
            version: "0.1.0".into(),
            state_schema: SirStateSchema {
                fields: vec![SirFieldSchema {
                    name: "x".into(),
                    field_type: "Int".into(),
                }],
            },
            input_schema: SirInputSchema {
                fields: vec![SirFieldSchema {
                    name: "v".into(),
                    field_type: "Int".into(),
                }],
            },
            transitions: vec![SirTransition {
                name: "set".into(),
                class: "Update".into(),
                preconditions: vec![],
                postconditions: vec![],
                body: SirExpr::Var {
                    name: "input.v".into(),
                },
                allowed_mutations: vec!["x".to_string()],
            }],
            invariants: vec![],
            observables: vec![],
        };
        let system = compile(&program);
        let matrix = build_coverage_matrix(&program, &system);
        let findings = matrix.validate();

        let const3_gap = findings
            .iter()
            .find(|f| f.key == "CONST-3" && f.finding_type == FindingType::Gap);
        assert!(
            const3_gap.is_some(),
            "should detect CONST-3 gap when no branch constraints exist"
        );
    }

    #[test]
    fn test_validate_detects_gap_for_empty_system() {
        let program = SirProgram {
            version: "0.1.0".into(),
            state_schema: SirStateSchema { fields: vec![] },
            input_schema: SirInputSchema { fields: vec![] },
            transitions: vec![],
            invariants: vec![],
            observables: vec![],
        };
        let system = compile(&program);
        let matrix = build_coverage_matrix(&program, &system);
        let findings = matrix.validate();

        // With no transitions or invariants, proof obligations should have gaps.
        let gaps: Vec<_> = findings
            .iter()
            .filter(|f| f.finding_type == FindingType::Gap)
            .collect();
        assert!(
            !gaps.is_empty(),
            "empty system should produce gap findings for proof obligations"
        );
    }

    #[test]
    fn test_coverage_cell_from_ids_gap() {
        let cell = CoverageCell::from_ids(vec![]);
        assert_eq!(cell.level, CoverageLevel::Gap);
        assert!(cell.constraint_ids.is_empty());
    }

    #[test]
    fn test_coverage_cell_from_ids_full() {
        let cell = CoverageCell::from_ids(vec![ConstraintId(0), ConstraintId(1)]);
        assert_eq!(cell.level, CoverageLevel::Full);
        assert_eq!(cell.constraint_ids.len(), 2);
    }

    #[test]
    fn test_extract_invariant_name() {
        reset_constraint_id_counter();
        let constraint = Constraint {
            id: ConstraintId(0),
            expr: crate::compiler::ConstraintExpr::BoolConstant(true),
            category: ConstraintCategory::Invariant,
            description: "invariant 'L_cons' (category: local) must hold".to_string(),
        };
        assert_eq!(
            extract_invariant_name(&constraint),
            Some("L_cons".to_string())
        );
    }

    #[test]
    fn test_extract_invariant_name_non_invariant() {
        let constraint = Constraint {
            id: ConstraintId(0),
            expr: crate::compiler::ConstraintExpr::BoolConstant(true),
            category: ConstraintCategory::Structural,
            description: "structural constraint".to_string(),
        };
        assert_eq!(extract_invariant_name(&constraint), None);
    }

    #[test]
    fn test_extract_transition_name() {
        let constraint = Constraint {
            id: ConstraintId(0),
            expr: crate::compiler::ConstraintExpr::BoolConstant(true),
            category: ConstraintCategory::Semantic,
            description: "precondition 0 for transition 'deposit'".to_string(),
        };
        assert_eq!(
            extract_transition_name(&constraint),
            Some("deposit".to_string())
        );
    }

    #[test]
    fn test_coverage_with_branch_constraints() {
        // Program with a conditional in the transition body.
        let program = SirProgram {
            version: "0.1.0".into(),
            state_schema: SirStateSchema {
                fields: vec![SirFieldSchema {
                    name: "balance".into(),
                    field_type: "Int".into(),
                }],
            },
            input_schema: SirInputSchema {
                fields: vec![SirFieldSchema {
                    name: "amount".into(),
                    field_type: "Int".into(),
                }],
            },
            transitions: vec![SirTransition {
                name: "conditional_deposit".into(),
                class: "Update".into(),
                preconditions: vec![],
                postconditions: vec![],
                body: SirExpr::If {
                    cond: Box::new(SirExpr::BinOp {
                        op: "gt".into(),
                        left: Box::new(SirExpr::Var {
                            name: "input.amount".into(),
                        }),
                        right: Box::new(SirExpr::Literal {
                            value: SirValue::Int { value: 0 },
                        }),
                    }),
                    then_: Box::new(SirExpr::BinOp {
                        op: "add".into(),
                        left: Box::new(SirExpr::Var {
                            name: "state.balance".into(),
                        }),
                        right: Box::new(SirExpr::Var {
                            name: "input.amount".into(),
                        }),
                    }),
                    else_: Box::new(SirExpr::Var {
                        name: "state.balance".into(),
                    }),
                },
                allowed_mutations: vec!["balance".to_string()],
            }],
            invariants: vec![],
            observables: vec![],
        };
        let system = compile(&program);
        let matrix = build_coverage_matrix(&program, &system);

        // CONST-3 should now be covered.
        let cell = matrix.proof_obligation_coverage.get("CONST-3");
        assert!(cell.is_some());
        assert_eq!(
            cell.unwrap().level,
            CoverageLevel::Full,
            "CONST-3 should be Full when branch constraints exist"
        );
    }
}
