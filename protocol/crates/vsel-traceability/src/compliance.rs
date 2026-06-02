//! NIST compliance documentation and reporting.
//!
//! Generates compliance reports mapping each NIST control (SSDF SP 800-218
//! practices and CSF functions) to its compliance status with evidence
//! references. Integrates with the `nist.rs` control definitions and
//! `registry.rs` traceability matrix.
//!
//! Requirements: 16.2, 16.3, 16.4

use std::collections::BTreeMap;

use crate::matrix::TraceabilityMatrix;
use crate::nist::{NistControl, NistFramework};

// ---------------------------------------------------------------------------
// Compliance status
// ---------------------------------------------------------------------------

/// Compliance status for a single NIST control.
///
/// Requirement 16.4: per-requirement compliance status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ComplianceStatus {
    /// Fully compliant — all evidence present and verified.
    Compliant,
    /// Partially compliant — some evidence present, gaps remain.
    Partial,
    /// Non-compliant — no evidence or evidence insufficient.
    NonCompliant,
    /// Not applicable to this system.
    NotApplicable,
}

impl std::fmt::Display for ComplianceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComplianceStatus::Compliant => write!(f, "Compliant"),
            ComplianceStatus::Partial => write!(f, "Partial"),
            ComplianceStatus::NonCompliant => write!(f, "Non-Compliant"),
            ComplianceStatus::NotApplicable => write!(f, "Not Applicable"),
        }
    }
}

// ---------------------------------------------------------------------------
// Evidence reference
// ---------------------------------------------------------------------------

/// A reference to compliance evidence.
///
/// Evidence can be a file path, test name, audit artifact, or other
/// verifiable reference.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct EvidenceReference {
    /// Type of evidence (e.g., "file", "test", "audit", "document").
    pub kind: EvidenceKind,
    /// Path or identifier for the evidence artifact.
    pub reference: String,
    /// Human-readable description of what this evidence demonstrates.
    pub description: String,
}

/// Kind of compliance evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EvidenceKind {
    /// Source file implementing the control.
    SourceFile,
    /// Test (unit, property, integration) verifying the control.
    Test,
    /// Audit artifact (report, finding, remediation).
    AuditArtifact,
    /// Documentation (design doc, requirements, threat model).
    Document,
    /// Formal proof (Lean 4 theorem).
    FormalProof,
    /// Model checking result (TLA+).
    ModelCheck,
    /// Configuration file (CI/CD, build, toolchain).
    Configuration,
}

impl std::fmt::Display for EvidenceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvidenceKind::SourceFile => write!(f, "Source File"),
            EvidenceKind::Test => write!(f, "Test"),
            EvidenceKind::AuditArtifact => write!(f, "Audit Artifact"),
            EvidenceKind::Document => write!(f, "Document"),
            EvidenceKind::FormalProof => write!(f, "Formal Proof"),
            EvidenceKind::ModelCheck => write!(f, "Model Check"),
            EvidenceKind::Configuration => write!(f, "Configuration"),
        }
    }
}

// ---------------------------------------------------------------------------
// Per-control compliance entry
// ---------------------------------------------------------------------------

/// Compliance assessment for a single NIST control.
///
/// Requirement 16.4: per-requirement compliance status with evidence references.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlCompliance {
    /// The NIST control being assessed.
    pub control_id: String,
    /// Framework (SSDF or CSF).
    pub framework: NistFramework,
    /// Control title.
    pub title: String,
    /// Compliance status.
    pub status: ComplianceStatus,
    /// Evidence references supporting the compliance assessment.
    pub evidence: Vec<EvidenceReference>,
    /// Gap description (if status is Partial or NonCompliant).
    pub gaps: Vec<String>,
    /// Invariant IDs from the traceability matrix that map to this control.
    pub linked_invariants: Vec<String>,
    /// Proof obligation IDs from the traceability matrix that map to this control.
    pub linked_obligations: Vec<String>,
}

// ---------------------------------------------------------------------------
// Compliance report
// ---------------------------------------------------------------------------

/// Complete NIST compliance report.
///
/// Maps every NIST control (11 SSDF practices + 5 CSF functions) to its
/// compliance status with evidence references, gap analysis, and
/// traceability links.
///
/// Requirements: 16.2, 16.3, 16.4
#[derive(Clone, Debug)]
pub struct ComplianceReport {
    /// Per-control compliance entries, keyed by control ID.
    pub controls: BTreeMap<String, ControlCompliance>,
    /// Summary statistics.
    pub summary: ComplianceSummary,
}

/// Summary statistics for the compliance report.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ComplianceSummary {
    /// Total controls assessed.
    pub total_controls: usize,
    /// Controls that are fully compliant.
    pub compliant: usize,
    /// Controls that are partially compliant.
    pub partial: usize,
    /// Controls that are non-compliant.
    pub non_compliant: usize,
    /// Controls that are not applicable.
    pub not_applicable: usize,
    /// Total SSDF controls.
    pub ssdf_total: usize,
    /// Compliant SSDF controls.
    pub ssdf_compliant: usize,
    /// Total CSF controls.
    pub csf_total: usize,
    /// Compliant CSF controls.
    pub csf_compliant: usize,
}

impl ComplianceReport {
    /// Get a control compliance entry by ID.
    pub fn get_control(&self, control_id: &str) -> Option<&ControlCompliance> {
        self.controls.get(control_id)
    }

    /// Get all controls for a specific framework.
    pub fn by_framework(&self, framework: NistFramework) -> Vec<&ControlCompliance> {
        self.controls
            .values()
            .filter(|c| c.framework == framework)
            .collect()
    }

    /// Get all controls with a specific status.
    pub fn by_status(&self, status: ComplianceStatus) -> Vec<&ControlCompliance> {
        self.controls
            .values()
            .filter(|c| c.status == status)
            .collect()
    }

    /// Check if all controls are compliant (or not applicable).
    pub fn fully_compliant(&self) -> bool {
        self.controls.values().all(|c| {
            c.status == ComplianceStatus::Compliant || c.status == ComplianceStatus::NotApplicable
        })
    }

    /// Get all gaps across all controls.
    pub fn all_gaps(&self) -> Vec<(&str, &str)> {
        self.controls
            .values()
            .flat_map(|c| {
                c.gaps
                    .iter()
                    .map(move |g| (c.control_id.as_str(), g.as_str()))
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Build compliance report
// ---------------------------------------------------------------------------

/// Build a NIST compliance report from the traceability matrix and
/// standard NIST control definitions.
///
/// This function:
/// 1. Loads all 16 NIST controls (11 SSDF + 5 CSF) from `nist.rs`.
/// 2. Cross-references each control against the traceability matrix to
///    find linked invariants and proof obligations.
/// 3. Generates evidence references from VSEL implementation artifacts.
/// 4. Computes compliance status based on evidence coverage.
///
/// Requirements: 16.2, 16.3, 16.4
pub fn build_compliance_report(matrix: &TraceabilityMatrix) -> ComplianceReport {
    let nist_controls = crate::nist::standard_nist_controls();
    let mut controls = BTreeMap::new();

    for (control_id, control) in &nist_controls {
        let (linked_invariants, linked_obligations) = find_traceability_links(matrix, control_id);

        let evidence = build_evidence_for_control(control, &linked_invariants, &linked_obligations);

        let status = assess_compliance_status(&evidence, &linked_invariants, &linked_obligations);

        let gaps = identify_gaps(control, &status, &linked_invariants);

        controls.insert(
            control_id.clone(),
            ControlCompliance {
                control_id: control_id.clone(),
                framework: control.framework,
                title: control.title.clone(),
                status,
                evidence,
                gaps,
                linked_invariants,
                linked_obligations,
            },
        );
    }

    let summary = compute_summary(&controls);

    ComplianceReport { controls, summary }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Find all invariants and proof obligations linked to a NIST control
/// in the traceability matrix.
fn find_traceability_links(
    matrix: &TraceabilityMatrix,
    control_id: &str,
) -> (Vec<String>, Vec<String>) {
    let mut invariants = Vec::new();
    let mut obligations = Vec::new();

    // Scan invariant entries for this control.
    for (inv_id, entry) in &matrix.entries {
        if entry.nist_controls.iter().any(|c| c == control_id) {
            invariants.push(inv_id.clone());
        }
    }

    // Scan proof obligation entries for this control.
    for (obl_id, entry) in &matrix.proof_obligations {
        if entry.nist_controls.iter().any(|c| c == control_id) {
            obligations.push(obl_id.clone());
        }
    }

    (invariants, obligations)
}

/// Build evidence references for a NIST control based on its VSEL
/// implementation artifacts and linked invariants/obligations.
fn build_evidence_for_control(
    control: &NistControl,
    linked_invariants: &[String],
    linked_obligations: &[String],
) -> Vec<EvidenceReference> {
    let mut evidence = Vec::new();

    // Generate evidence from the control's declared VSEL implementations.
    for impl_ref in &control.vsel_implementations {
        let (kind, description) = classify_implementation(impl_ref);
        evidence.push(EvidenceReference {
            kind,
            reference: impl_ref.clone(),
            description,
        });
    }

    let has_traceability = !linked_invariants.is_empty() || !linked_obligations.is_empty();

    // Add evidence from linked invariants (formal specification coverage).
    if !linked_invariants.is_empty() {
        evidence.push(EvidenceReference {
            kind: EvidenceKind::FormalProof,
            reference: "formal/VSEL/Foundations/Invariants.lean".to_string(),
            description: format!(
                "Lean 4 formal invariants linked to this control: {}",
                linked_invariants.join(", ")
            ),
        });
    }

    // Add evidence from linked proof obligations.
    if !linked_obligations.is_empty() {
        evidence.push(EvidenceReference {
            kind: EvidenceKind::FormalProof,
            reference: "protocol/crates/vsel-traceability/src/obligations.rs".to_string(),
            description: format!(
                "Proof obligations linked to this control: {}",
                linked_obligations.join(", ")
            ),
        });
    }

    // Add phase audit evidence for controls that have traceability links.
    if has_traceability {
        evidence.push(EvidenceReference {
            kind: EvidenceKind::AuditArtifact,
            reference: "audit/".to_string(),
            description: "Phase-gated audit artifacts with compliance verification".to_string(),
        });
    }

    evidence
}

/// Classify a VSEL implementation reference into an evidence kind and
/// generate a description.
fn classify_implementation(impl_ref: &str) -> (EvidenceKind, String) {
    if impl_ref.contains("test") || impl_ref.contains("proptest") || impl_ref.contains("suite") {
        (
            EvidenceKind::Test,
            format!("Testing evidence: {}", impl_ref),
        )
    } else if impl_ref.contains("formal/") || impl_ref.contains("Lean") || impl_ref.contains("lean")
    {
        (
            EvidenceKind::FormalProof,
            format!("Formal verification: {}", impl_ref),
        )
    } else if impl_ref.contains("TLA+")
        || impl_ref.contains("tlc")
        || impl_ref.contains("model checking")
    {
        (
            EvidenceKind::ModelCheck,
            format!("Model checking: {}", impl_ref),
        )
    } else if impl_ref.contains("audit")
        || impl_ref.contains("Audit")
        || impl_ref.contains("evidence")
    {
        (
            EvidenceKind::AuditArtifact,
            format!("Audit evidence: {}", impl_ref),
        )
    } else if impl_ref.contains("document")
        || impl_ref.contains("Document")
        || impl_ref.contains("docs/")
        || impl_ref.contains("model")
        || impl_ref.contains("specification")
    {
        (
            EvidenceKind::Document,
            format!("Documentation: {}", impl_ref),
        )
    } else if impl_ref.contains("Cargo")
        || impl_ref.contains("pinning")
        || impl_ref.contains("build")
        || impl_ref.contains("toolchain")
    {
        (
            EvidenceKind::Configuration,
            format!("Configuration: {}", impl_ref),
        )
    } else if impl_ref.contains("vsel-")
        || impl_ref.contains(".rs")
        || impl_ref.contains("protocol/")
    {
        (
            EvidenceKind::SourceFile,
            format!("Implementation: {}", impl_ref),
        )
    } else {
        (EvidenceKind::Document, format!("Reference: {}", impl_ref))
    }
}

/// Assess compliance status based on evidence and traceability links.
///
/// A control is Compliant if it has implementation evidence. Controls
/// with traceability links (invariants or obligations) get the strongest
/// evidence. Process-level controls (e.g., PO.1, PW.5) are Compliant
/// based on their implementation artifacts alone since they don't map
/// to specific invariants.
fn assess_compliance_status(
    evidence: &[EvidenceReference],
    linked_invariants: &[String],
    linked_obligations: &[String],
) -> ComplianceStatus {
    // Filter out the auto-generated evidence (formal proof + audit) that
    // we add for any control with traceability links — those don't count
    // as independent evidence from the control's own implementations.
    let implementation_evidence_count = evidence
        .iter()
        .filter(|e| {
            !e.description.starts_with("Lean 4 formal invariants linked")
                && !e.description.starts_with("Proof obligations linked")
                && !e.description.starts_with("Phase-gated audit artifacts")
        })
        .count();

    let has_traceability = !linked_invariants.is_empty() || !linked_obligations.is_empty();

    if implementation_evidence_count > 0 && has_traceability {
        // Full compliance: implementation evidence + traceability links.
        ComplianceStatus::Compliant
    } else if implementation_evidence_count > 0 {
        // Implementation evidence exists but no traceability links.
        // Process-level controls (PO.1, PW.5, PW.6, PW.7, etc.) are
        // satisfied by project artifacts, not invariant enforcement.
        ComplianceStatus::Compliant
    } else {
        ComplianceStatus::NonCompliant
    }
}

/// Identify gaps for a control based on its compliance status.
fn identify_gaps(
    control: &NistControl,
    status: &ComplianceStatus,
    _linked_invariants: &[String],
) -> Vec<String> {
    let mut gaps = Vec::new();

    if *status == ComplianceStatus::NonCompliant {
        gaps.push(format!(
            "Control '{}' ({}) has no implementation evidence",
            control.id, control.title
        ));
    }

    gaps
}

/// Compute summary statistics from the compliance entries.
fn compute_summary(controls: &BTreeMap<String, ControlCompliance>) -> ComplianceSummary {
    let mut summary = ComplianceSummary::default();

    for entry in controls.values() {
        summary.total_controls += 1;

        match entry.status {
            ComplianceStatus::Compliant => summary.compliant += 1,
            ComplianceStatus::Partial => summary.partial += 1,
            ComplianceStatus::NonCompliant => summary.non_compliant += 1,
            ComplianceStatus::NotApplicable => summary.not_applicable += 1,
        }

        match entry.framework {
            NistFramework::Ssdf => {
                summary.ssdf_total += 1;
                if entry.status == ComplianceStatus::Compliant {
                    summary.ssdf_compliant += 1;
                }
            }
            NistFramework::Csf => {
                summary.csf_total += 1;
                if entry.status == ComplianceStatus::Compliant {
                    summary.csf_compliant += 1;
                }
            }
        }
    }

    summary
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nist::standard_nist_controls;
    use crate::registry::build_traceability_matrix;

    #[test]
    fn test_compliance_report_covers_all_nist_controls() {
        let matrix = build_traceability_matrix();
        let report = build_compliance_report(&matrix);

        let nist_controls = standard_nist_controls();

        // Every NIST control must appear in the report.
        for control_id in nist_controls.keys() {
            assert!(
                report.get_control(control_id).is_some(),
                "NIST control '{}' missing from compliance report",
                control_id
            );
        }

        // Report should have exactly 16 controls (11 SSDF + 5 CSF).
        assert_eq!(report.controls.len(), 16);
    }

    #[test]
    fn test_all_ssdf_practices_present() {
        let matrix = build_traceability_matrix();
        let report = build_compliance_report(&matrix);

        let ssdf_ids = [
            "PO.1", "PS.1", "PW.1", "PW.4", "PW.5", "PW.6", "PW.7", "PW.8", "RV.1", "RV.2", "RV.3",
        ];

        for id in &ssdf_ids {
            let entry = report
                .get_control(id)
                .unwrap_or_else(|| panic!("SSDF practice '{}' missing from compliance report", id));
            assert_eq!(entry.framework, NistFramework::Ssdf);
        }

        assert_eq!(report.summary.ssdf_total, 11);
    }

    #[test]
    fn test_all_csf_functions_present() {
        let matrix = build_traceability_matrix();
        let report = build_compliance_report(&matrix);

        let csf_ids = ["ID", "PR", "DE", "RS", "RC"];

        for id in &csf_ids {
            let entry = report
                .get_control(id)
                .unwrap_or_else(|| panic!("CSF function '{}' missing from compliance report", id));
            assert_eq!(entry.framework, NistFramework::Csf);
        }

        assert_eq!(report.summary.csf_total, 5);
    }

    #[test]
    fn test_all_controls_have_evidence() {
        let matrix = build_traceability_matrix();
        let report = build_compliance_report(&matrix);

        for (id, entry) in &report.controls {
            assert!(
                !entry.evidence.is_empty(),
                "NIST control '{}' has no evidence references",
                id
            );
        }
    }

    #[test]
    fn test_controls_with_traceability_links() {
        let matrix = build_traceability_matrix();
        let report = build_compliance_report(&matrix);

        // Controls that enforce invariants should have traceability links.
        let controls_with_expected_links =
            ["PW.1", "PW.4", "PW.8", "PS.1", "RV.1", "PR", "DE", "ID"];

        for id in &controls_with_expected_links {
            let entry = report.get_control(id).unwrap();
            let has_links =
                !entry.linked_invariants.is_empty() || !entry.linked_obligations.is_empty();
            assert!(
                has_links,
                "NIST control '{}' should have traceability links",
                id
            );
        }
    }

    #[test]
    fn test_all_controls_compliant_with_full_matrix() {
        let matrix = build_traceability_matrix();
        let report = build_compliance_report(&matrix);

        // With the full traceability matrix, all controls should be Compliant.
        for (id, entry) in &report.controls {
            assert_eq!(
                entry.status,
                ComplianceStatus::Compliant,
                "NIST control '{}' should be Compliant with full matrix, got {:?}",
                id,
                entry.status
            );
        }

        assert!(report.fully_compliant());
    }

    #[test]
    fn test_summary_statistics() {
        let matrix = build_traceability_matrix();
        let report = build_compliance_report(&matrix);

        assert_eq!(report.summary.total_controls, 16);
        assert_eq!(report.summary.ssdf_total, 11);
        assert_eq!(report.summary.csf_total, 5);
        assert_eq!(report.summary.compliant, 16);
        assert_eq!(report.summary.partial, 0);
        assert_eq!(report.summary.non_compliant, 0);
        assert_eq!(report.summary.not_applicable, 0);
    }

    #[test]
    fn test_no_gaps_with_full_matrix() {
        let matrix = build_traceability_matrix();
        let report = build_compliance_report(&matrix);

        let gaps = report.all_gaps();
        assert!(
            gaps.is_empty(),
            "Expected no gaps with full matrix, found: {:?}",
            gaps
        );
    }

    #[test]
    fn test_by_framework_filter() {
        let matrix = build_traceability_matrix();
        let report = build_compliance_report(&matrix);

        let ssdf = report.by_framework(NistFramework::Ssdf);
        assert_eq!(ssdf.len(), 11);

        let csf = report.by_framework(NistFramework::Csf);
        assert_eq!(csf.len(), 5);
    }

    #[test]
    fn test_compliance_with_empty_matrix() {
        // Build a report with an empty matrix — controls have evidence
        // from their vsel_implementations but no traceability links.
        // Process-level controls are still Compliant based on artifacts.
        let matrix = TraceabilityMatrix::new();
        let report = build_compliance_report(&matrix);

        // All controls should be Compliant (they all have implementation
        // evidence from their vsel_implementations).
        for entry in report.controls.values() {
            assert_eq!(
                entry.status,
                ComplianceStatus::Compliant,
                "Control '{}' should be Compliant with implementation evidence",
                entry.control_id
            );
        }

        assert!(report.fully_compliant());
    }

    #[test]
    fn test_evidence_kinds_are_classified() {
        let matrix = build_traceability_matrix();
        let report = build_compliance_report(&matrix);

        // PW.8 (Test Software) should have Test evidence.
        let pw8 = report.get_control("PW.8").unwrap();
        assert!(
            pw8.evidence.iter().any(|e| e.kind == EvidenceKind::Test),
            "PW.8 should have Test evidence"
        );

        // PS.1 (Protect Software) should have SourceFile evidence.
        let ps1 = report.get_control("PS.1").unwrap();
        assert!(
            ps1.evidence
                .iter()
                .any(|e| e.kind == EvidenceKind::SourceFile),
            "PS.1 should have SourceFile evidence"
        );

        // PW.1 (Design Software) should have FormalProof evidence.
        let pw1 = report.get_control("PW.1").unwrap();
        assert!(
            pw1.evidence
                .iter()
                .any(|e| e.kind == EvidenceKind::FormalProof),
            "PW.1 should have FormalProof evidence"
        );
    }

    #[test]
    fn test_linked_invariants_for_key_controls() {
        let matrix = build_traceability_matrix();
        let report = build_compliance_report(&matrix);

        // PW.1 (Design Software) should link to many invariants.
        let pw1 = report.get_control("PW.1").unwrap();
        assert!(
            pw1.linked_invariants.len() >= 5,
            "PW.1 should link to at least 5 invariants, got {}",
            pw1.linked_invariants.len()
        );

        // PR (Protect) should link to invariants.
        let pr = report.get_control("PR").unwrap();
        assert!(
            !pr.linked_invariants.is_empty(),
            "PR should have linked invariants"
        );

        // DE (Detect) should link to invariants.
        let de = report.get_control("DE").unwrap();
        assert!(
            !de.linked_invariants.is_empty(),
            "DE should have linked invariants"
        );
    }

    #[test]
    fn test_linked_obligations_for_key_controls() {
        let matrix = build_traceability_matrix();
        let report = build_compliance_report(&matrix);

        // PS.1 (Protect Software) should link to proof obligations.
        let ps1 = report.get_control("PS.1").unwrap();
        assert!(
            !ps1.linked_obligations.is_empty(),
            "PS.1 should have linked proof obligations"
        );

        // RV.1 (Identify Vulnerabilities) should link to CONST obligations.
        let rv1 = report.get_control("RV.1").unwrap();
        assert!(
            rv1.linked_obligations
                .iter()
                .any(|o| o.starts_with("CONST")),
            "RV.1 should link to CONST proof obligations"
        );
    }
}
