//! Audit evidence system — structured evidence per AUDIT_EVIDENCE_MODEL.
//!
//! Implements the complete audit evidence lifecycle:
//!   Discovery → Documentation → Triage → Remediation → Verification → Closure
//!
//! Evidence categories CAT-1 through CAT-6:
//!   CAT-1: Formal verification (Lean 4 proofs)
//!   CAT-2: Model checking (TLA+ results)
//!   CAT-3: Test execution (Rust test results)
//!   CAT-4: Property test (proptest results)
//!   CAT-5: Security scan (cargo-audit, CodeQL)
//!   CAT-6: Compliance (SBOM, version info)
//!
//! Requirements: 15.4, 15.5, 15.6, 15.10

use std::collections::BTreeMap;
use std::fmt;

use sha3::{Digest, Sha3_256};

// ---------------------------------------------------------------------------
// Evidence category (CAT-1 through CAT-6)
// ---------------------------------------------------------------------------

/// Evidence category per AUDIT_EVIDENCE_MODEL §3.
///
/// Requirement 15.4
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EvidenceCategory {
    /// CAT-1: Formal verification evidence (Lean 4 proofs).
    FormalVerification,
    /// CAT-2: Model checking evidence (TLA+ results).
    ModelChecking,
    /// CAT-3: Test execution evidence (Rust test results).
    TestExecution,
    /// CAT-4: Property test evidence (proptest results).
    PropertyTest,
    /// CAT-5: Security scan evidence (cargo-audit, CodeQL).
    SecurityScan,
    /// CAT-6: Compliance evidence (SBOM, version info).
    Compliance,
}

impl fmt::Display for EvidenceCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvidenceCategory::FormalVerification => write!(f, "CAT-1: Formal Verification"),
            EvidenceCategory::ModelChecking => write!(f, "CAT-2: Model Checking"),
            EvidenceCategory::TestExecution => write!(f, "CAT-3: Test Execution"),
            EvidenceCategory::PropertyTest => write!(f, "CAT-4: Property Test"),
            EvidenceCategory::SecurityScan => write!(f, "CAT-5: Security Scan"),
            EvidenceCategory::Compliance => write!(f, "CAT-6: Compliance"),
        }
    }
}

// ---------------------------------------------------------------------------
// Severity classification
// ---------------------------------------------------------------------------

/// Severity classification per AUDIT_EVIDENCE_MODEL §4.
///
/// Requirement 15.10
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Immediate halt. Full remediation. Re-audit.
    Catastrophic,
    /// Block phase progression. Remediate. Re-audit.
    Critical,
    /// Remediate before phase completion.
    Serious,
    /// Track. Remediate within next phase.
    Moderate,
    /// Document. No immediate action required.
    Informational,
}

impl Severity {
    /// Returns `true` if this severity blocks phase progression.
    ///
    /// Requirement 15.10: no "accepted risk" for Catastrophic findings.
    /// Catastrophic and Critical block phase progression.
    pub fn blocks_phase(&self) -> bool {
        matches!(self, Severity::Catastrophic | Severity::Critical)
    }

    /// Returns `true` if this severity requires remediation before phase
    /// completion (Catastrophic, Critical, or Serious).
    pub fn requires_remediation(&self) -> bool {
        matches!(
            self,
            Severity::Catastrophic | Severity::Critical | Severity::Serious
        )
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Catastrophic => write!(f, "Catastrophic"),
            Severity::Critical => write!(f, "Critical"),
            Severity::Serious => write!(f, "Serious"),
            Severity::Moderate => write!(f, "Moderate"),
            Severity::Informational => write!(f, "Informational"),
        }
    }
}

// ---------------------------------------------------------------------------
// Evidence lifecycle
// ---------------------------------------------------------------------------

/// Evidence lifecycle stage per AUDIT_EVIDENCE_MODEL §5.
///
/// Discovery → Documentation → Triage → Remediation → Verification → Closure
///
/// Requirement 15.6
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LifecycleStage {
    /// Finding identified during audit activity.
    Discovery,
    /// Full evidence record created with reproducibility instructions.
    Documentation,
    /// Severity assigned, responsible party identified, timeline set.
    Triage,
    /// Fix implemented and documented.
    Remediation,
    /// Fix independently verified, original check re-run.
    Verification,
    /// Status set to Verified, evidence chain complete.
    Closure,
}

impl LifecycleStage {
    /// Returns the next stage in the lifecycle, or `None` if already at Closure.
    pub fn next(&self) -> Option<LifecycleStage> {
        match self {
            LifecycleStage::Discovery => Some(LifecycleStage::Documentation),
            LifecycleStage::Documentation => Some(LifecycleStage::Triage),
            LifecycleStage::Triage => Some(LifecycleStage::Remediation),
            LifecycleStage::Remediation => Some(LifecycleStage::Verification),
            LifecycleStage::Verification => Some(LifecycleStage::Closure),
            LifecycleStage::Closure => None,
        }
    }

    /// Returns `true` if transitioning from `self` to `target` is valid.
    ///
    /// Transitions must follow the strict ordering:
    /// Discovery → Documentation → Triage → Remediation → Verification → Closure
    pub fn can_transition_to(&self, target: LifecycleStage) -> bool {
        self.next() == Some(target)
    }
}

impl fmt::Display for LifecycleStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LifecycleStage::Discovery => write!(f, "Discovery"),
            LifecycleStage::Documentation => write!(f, "Documentation"),
            LifecycleStage::Triage => write!(f, "Triage"),
            LifecycleStage::Remediation => write!(f, "Remediation"),
            LifecycleStage::Verification => write!(f, "Verification"),
            LifecycleStage::Closure => write!(f, "Closure"),
        }
    }
}

// ---------------------------------------------------------------------------
// Verification method
// ---------------------------------------------------------------------------

/// How the evidence was produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VerificationMethod {
    /// Model checking (TLA+, bounded exploration).
    ModelCheck,
    /// Theorem proving (Lean 4, universal guarantee).
    TheoremProve,
    /// Automated test execution (Rust unit/integration/property tests).
    Test,
    /// Reasoned argument (manual review, design analysis).
    Argument,
    /// Security scanning (cargo-audit, CodeQL, SAST).
    SecurityScan,
    /// Compliance assessment (SBOM, version audit).
    ComplianceAudit,
}

impl fmt::Display for VerificationMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerificationMethod::ModelCheck => write!(f, "Model Check"),
            VerificationMethod::TheoremProve => write!(f, "Theorem Prove"),
            VerificationMethod::Test => write!(f, "Test"),
            VerificationMethod::Argument => write!(f, "Argument"),
            VerificationMethod::SecurityScan => write!(f, "Security Scan"),
            VerificationMethod::ComplianceAudit => write!(f, "Compliance Audit"),
        }
    }
}

// ---------------------------------------------------------------------------
// Audit result
// ---------------------------------------------------------------------------

/// Result of an audit check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuditResult {
    /// The check passed — no finding.
    Pass,
    /// The check failed — finding exists.
    Fail,
    /// The check was inconclusive — further investigation needed.
    Inconclusive,
}

impl fmt::Display for AuditResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuditResult::Pass => write!(f, "Pass"),
            AuditResult::Fail => write!(f, "Fail"),
            AuditResult::Inconclusive => write!(f, "Inconclusive"),
        }
    }
}

// ---------------------------------------------------------------------------
// Evidence integrity — committed, timestamped, immutable
// ---------------------------------------------------------------------------

/// SHA-256 commitment hash for evidence integrity.
///
/// Requirement 15.5: evidence must be committed (hashed).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EvidenceHash(pub [u8; 32]);

impl EvidenceHash {
    /// Compute SHA3-256 hash of the given content.
    pub fn compute(content: &[u8]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(content);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        EvidenceHash(hash)
    }

    /// Returns the hash as a hex string.
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

impl fmt::Display for EvidenceHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

// ---------------------------------------------------------------------------
// Audit evidence artifact
// ---------------------------------------------------------------------------

/// A single audit evidence artifact per AUDIT_EVIDENCE_MODEL §2.
///
/// Once committed (hash computed), the evidence is immutable. Any
/// correction creates a new artifact referencing the original.
///
/// Requirements: 15.4, 15.5
#[derive(Clone, Debug)]
pub struct AuditEvidence {
    /// Unique identifier: AE-{phase}-{number}.
    pub id: String,
    /// Roadmap phase (0–10).
    pub phase: u32,
    /// Evidence category (CAT-1 through CAT-6).
    pub category: EvidenceCategory,
    /// What was being tested/verified.
    pub hypothesis: String,
    /// How it was tested.
    pub method: VerificationMethod,
    /// Which document/code/component was evaluated.
    pub artifact_evaluated: String,
    /// What class of failure was targeted.
    pub failure_class_sought: String,
    /// Pass / Fail / Inconclusive.
    pub result: AuditResult,
    /// Description if Fail or Inconclusive.
    pub finding: Option<String>,
    /// Severity if finding exists.
    pub severity: Option<Severity>,
    /// Reference to reproducible evidence artifact.
    pub evidence_artifact: String,
    /// How to reproduce the result.
    pub reproducibility: String,
    /// Who performed the audit.
    pub auditor: String,
    /// Unix timestamp (seconds since epoch).
    pub timestamp: u64,
    /// SHA3-256 commitment hash — computed once, then immutable.
    commitment: Option<EvidenceHash>,
}

impl AuditEvidence {
    /// Create a new evidence artifact. The artifact is uncommitted until
    /// [`commit`] is called.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        phase: u32,
        category: EvidenceCategory,
        hypothesis: impl Into<String>,
        method: VerificationMethod,
        artifact_evaluated: impl Into<String>,
        failure_class_sought: impl Into<String>,
        result: AuditResult,
        evidence_artifact: impl Into<String>,
        reproducibility: impl Into<String>,
        auditor: impl Into<String>,
        timestamp: u64,
    ) -> Self {
        Self {
            id: id.into(),
            phase,
            category,
            hypothesis: hypothesis.into(),
            method,
            artifact_evaluated: artifact_evaluated.into(),
            failure_class_sought: failure_class_sought.into(),
            result,
            finding: None,
            severity: None,
            evidence_artifact: evidence_artifact.into(),
            reproducibility: reproducibility.into(),
            auditor: auditor.into(),
            timestamp,
            commitment: None,
        }
    }

    /// Attach a finding with severity.
    pub fn with_finding(mut self, finding: impl Into<String>, severity: Severity) -> Self {
        self.finding = Some(finding.into());
        self.severity = Some(severity);
        self
    }

    /// Compute the commitment hash over the canonical content of this
    /// evidence artifact. Once committed, the evidence is immutable.
    ///
    /// Requirement 15.5: committed (hashed), immutable.
    pub fn commit(&mut self) {
        let canonical = self.canonical_bytes();
        self.commitment = Some(EvidenceHash::compute(&canonical));
    }

    /// Returns the commitment hash, or `None` if not yet committed.
    pub fn commitment(&self) -> Option<&EvidenceHash> {
        self.commitment.as_ref()
    }

    /// Returns `true` if this evidence has been committed (hashed).
    pub fn is_committed(&self) -> bool {
        self.commitment.is_some()
    }

    /// Verify that the commitment hash matches the current content.
    ///
    /// Returns `false` if the evidence has been tampered with after
    /// commitment, or if it was never committed.
    ///
    /// Requirement 15.5: evidence integrity verification.
    pub fn verify_integrity(&self) -> bool {
        match &self.commitment {
            Some(stored_hash) => {
                let recomputed = EvidenceHash::compute(&self.canonical_bytes());
                *stored_hash == recomputed
            }
            None => false,
        }
    }

    /// Produce a deterministic byte representation for hashing.
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.id.as_bytes());
        buf.extend_from_slice(&self.phase.to_le_bytes());
        buf.extend_from_slice(&(self.category as u8).to_le_bytes());
        buf.extend_from_slice(self.hypothesis.as_bytes());
        buf.extend_from_slice(&(self.method as u8).to_le_bytes());
        buf.extend_from_slice(self.artifact_evaluated.as_bytes());
        buf.extend_from_slice(self.failure_class_sought.as_bytes());
        buf.extend_from_slice(&(self.result as u8).to_le_bytes());
        if let Some(ref finding) = self.finding {
            buf.push(1);
            buf.extend_from_slice(finding.as_bytes());
        } else {
            buf.push(0);
        }
        if let Some(severity) = self.severity {
            buf.push(1);
            buf.extend_from_slice(&(severity as u8).to_le_bytes());
        } else {
            buf.push(0);
        }
        buf.extend_from_slice(self.evidence_artifact.as_bytes());
        buf.extend_from_slice(self.reproducibility.as_bytes());
        buf.extend_from_slice(self.auditor.as_bytes());
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf
    }
}

// ---------------------------------------------------------------------------
// Finding — tracks a discovered issue through the lifecycle
// ---------------------------------------------------------------------------

/// A finding discovered during audit, tracked through the evidence lifecycle.
///
/// Requirements: 15.6, 15.10
#[derive(Clone, Debug)]
pub struct Finding {
    /// Unique finding identifier: F-{phase}-{number}.
    pub id: String,
    /// Roadmap phase where the finding was discovered.
    pub phase: u32,
    /// Severity classification.
    pub severity: Severity,
    /// Human-readable description of the finding.
    pub description: String,
    /// Current lifecycle stage.
    pub stage: LifecycleStage,
    /// Evidence IDs that document this finding.
    pub evidence_ids: Vec<String>,
    /// Remediation description (populated at Remediation stage).
    pub remediation: Option<String>,
    /// Whether the remediation has been independently verified.
    pub remediation_verified: bool,
    /// Unix timestamp of discovery.
    pub discovered_at: u64,
    /// Unix timestamp of last stage transition.
    pub last_updated: u64,
    /// Responsible party for remediation.
    pub assignee: Option<String>,
}

impl Finding {
    /// Create a new finding at the Discovery stage.
    pub fn new(
        id: impl Into<String>,
        phase: u32,
        severity: Severity,
        description: impl Into<String>,
        discovered_at: u64,
    ) -> Self {
        Self {
            id: id.into(),
            phase,
            severity,
            description: description.into(),
            stage: LifecycleStage::Discovery,
            evidence_ids: Vec::new(),
            remediation: None,
            remediation_verified: false,
            discovered_at,
            last_updated: discovered_at,
            assignee: None,
        }
    }

    /// Link an evidence artifact to this finding.
    pub fn add_evidence(&mut self, evidence_id: impl Into<String>) {
        self.evidence_ids.push(evidence_id.into());
    }

    /// Advance the finding to the next lifecycle stage.
    ///
    /// Returns `Err` if the transition is invalid (e.g., skipping stages
    /// or advancing past Closure).
    ///
    /// Requirement 15.6: strict lifecycle ordering.
    pub fn advance(&mut self, timestamp: u64) -> Result<(), EvidenceError> {
        match self.stage.next() {
            Some(next) => {
                self.stage = next;
                self.last_updated = timestamp;
                Ok(())
            }
            None => Err(EvidenceError::InvalidLifecycleTransition {
                finding_id: self.id.clone(),
                from: self.stage,
                to: self.stage, // already at Closure
            }),
        }
    }

    /// Advance the finding to a specific target stage.
    ///
    /// The target must be the immediate next stage.
    ///
    /// Requirement 15.6: strict lifecycle ordering.
    pub fn advance_to(
        &mut self,
        target: LifecycleStage,
        timestamp: u64,
    ) -> Result<(), EvidenceError> {
        if !self.stage.can_transition_to(target) {
            return Err(EvidenceError::InvalidLifecycleTransition {
                finding_id: self.id.clone(),
                from: self.stage,
                to: target,
            });
        }
        self.stage = target;
        self.last_updated = timestamp;
        Ok(())
    }

    /// Set the remediation description. Only valid at or after the
    /// Remediation stage.
    pub fn set_remediation(&mut self, remediation: impl Into<String>) -> Result<(), EvidenceError> {
        if self.stage < LifecycleStage::Remediation {
            return Err(EvidenceError::PrematureRemediation {
                finding_id: self.id.clone(),
                current_stage: self.stage,
            });
        }
        self.remediation = Some(remediation.into());
        Ok(())
    }

    /// Mark the remediation as verified. Only valid at or after the
    /// Verification stage.
    pub fn verify_remediation(&mut self) -> Result<(), EvidenceError> {
        if self.stage < LifecycleStage::Verification {
            return Err(EvidenceError::PrematureVerification {
                finding_id: self.id.clone(),
                current_stage: self.stage,
            });
        }
        self.remediation_verified = true;
        Ok(())
    }

    /// Returns `true` if this finding is fully resolved (Closure stage
    /// with verified remediation).
    pub fn is_resolved(&self) -> bool {
        self.stage == LifecycleStage::Closure && self.remediation_verified
    }

    /// Returns `true` if this finding blocks phase progression.
    ///
    /// Requirement 15.10: Catastrophic and Critical block phase.
    pub fn blocks_phase(&self) -> bool {
        self.severity.blocks_phase() && !self.is_resolved()
    }
}

// ---------------------------------------------------------------------------
// Evidence store — manages evidence artifacts and findings
// ---------------------------------------------------------------------------

/// Central store for audit evidence artifacts and findings.
///
/// Enforces:
/// - Evidence immutability after commitment
/// - Finding lifecycle ordering
/// - Phase progression gating
///
/// Requirements: 15.4, 15.5, 15.6, 15.10
#[derive(Clone, Debug, Default)]
pub struct EvidenceStore {
    /// Evidence artifacts keyed by ID.
    evidence: BTreeMap<String, AuditEvidence>,
    /// Findings keyed by ID.
    findings: BTreeMap<String, Finding>,
    /// Next evidence sequence number per phase.
    evidence_seq: BTreeMap<u32, u32>,
    /// Next finding sequence number per phase.
    finding_seq: BTreeMap<u32, u32>,
}

impl EvidenceStore {
    /// Create an empty evidence store.
    pub fn new() -> Self {
        Self::default()
    }

    // -- Evidence management ------------------------------------------------

    /// Generate the next evidence ID for a phase.
    pub fn next_evidence_id(&mut self, phase: u32) -> String {
        let seq = self.evidence_seq.entry(phase).or_insert(0);
        *seq += 1;
        format!("AE-{}-{:03}", phase, seq)
    }

    /// Add an evidence artifact to the store.
    ///
    /// The evidence must have a unique ID. If the evidence is not yet
    /// committed, it will be committed automatically.
    pub fn add_evidence(&mut self, mut evidence: AuditEvidence) -> Result<(), EvidenceError> {
        if self.evidence.contains_key(&evidence.id) {
            return Err(EvidenceError::DuplicateId(evidence.id.clone()));
        }
        if !evidence.is_committed() {
            evidence.commit();
        }
        self.evidence.insert(evidence.id.clone(), evidence);
        Ok(())
    }

    /// Get an evidence artifact by ID.
    pub fn get_evidence(&self, id: &str) -> Option<&AuditEvidence> {
        self.evidence.get(id)
    }

    /// Get all evidence artifacts for a phase.
    pub fn evidence_for_phase(&self, phase: u32) -> Vec<&AuditEvidence> {
        self.evidence
            .values()
            .filter(|e| e.phase == phase)
            .collect()
    }

    /// Get all evidence artifacts for a category.
    pub fn evidence_by_category(&self, category: EvidenceCategory) -> Vec<&AuditEvidence> {
        self.evidence
            .values()
            .filter(|e| e.category == category)
            .collect()
    }

    /// Total number of evidence artifacts.
    pub fn evidence_count(&self) -> usize {
        self.evidence.len()
    }

    /// Verify integrity of all committed evidence.
    ///
    /// Returns IDs of any evidence artifacts that fail integrity checks.
    pub fn verify_all_integrity(&self) -> Vec<String> {
        self.evidence
            .values()
            .filter(|e| !e.verify_integrity())
            .map(|e| e.id.clone())
            .collect()
    }

    // -- Finding management -------------------------------------------------

    /// Generate the next finding ID for a phase.
    pub fn next_finding_id(&mut self, phase: u32) -> String {
        let seq = self.finding_seq.entry(phase).or_insert(0);
        *seq += 1;
        format!("F-{}-{:03}", phase, seq)
    }

    /// Add a finding to the store.
    pub fn add_finding(&mut self, finding: Finding) -> Result<(), EvidenceError> {
        if self.findings.contains_key(&finding.id) {
            return Err(EvidenceError::DuplicateId(finding.id.clone()));
        }
        self.findings.insert(finding.id.clone(), finding);
        Ok(())
    }

    /// Get a finding by ID.
    pub fn get_finding(&self, id: &str) -> Option<&Finding> {
        self.findings.get(id)
    }

    /// Get a mutable reference to a finding by ID.
    pub fn get_finding_mut(&mut self, id: &str) -> Option<&mut Finding> {
        self.findings.get_mut(id)
    }

    /// Get all findings for a phase.
    pub fn findings_for_phase(&self, phase: u32) -> Vec<&Finding> {
        self.findings
            .values()
            .filter(|f| f.phase == phase)
            .collect()
    }

    /// Get all unresolved findings with severity ≥ the given threshold.
    pub fn unresolved_findings_at_or_above(&self, min_severity: Severity) -> Vec<&Finding> {
        self.findings
            .values()
            .filter(|f| f.severity <= min_severity && !f.is_resolved())
            .collect()
    }

    /// Total number of findings.
    pub fn finding_count(&self) -> usize {
        self.findings.len()
    }

    // -- Phase gating -------------------------------------------------------

    /// Check whether a phase can progress.
    ///
    /// Phase progression requires:
    /// - 0 unresolved findings with severity ≥ Serious
    /// - No finding closed without verified remediation evidence
    ///
    /// Requirements: 15.6, 15.10
    pub fn can_progress_phase(&self, phase: u32) -> PhaseGateResult {
        let phase_findings: Vec<&Finding> = self
            .findings
            .values()
            .filter(|f| f.phase == phase)
            .collect();

        let blocking: Vec<String> = phase_findings
            .iter()
            .filter(|f| f.severity.requires_remediation() && !f.is_resolved())
            .map(|f| f.id.clone())
            .collect();

        let unverified_closures: Vec<String> = phase_findings
            .iter()
            .filter(|f| f.stage == LifecycleStage::Closure && !f.remediation_verified)
            .map(|f| f.id.clone())
            .collect();

        let can_progress = blocking.is_empty() && unverified_closures.is_empty();

        PhaseGateResult {
            phase,
            can_progress,
            blocking_findings: blocking,
            unverified_closures,
            total_findings: phase_findings.len(),
            resolved_findings: phase_findings.iter().filter(|f| f.is_resolved()).count(),
        }
    }
}

/// Result of a phase gate check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PhaseGateResult {
    /// Phase being checked.
    pub phase: u32,
    /// Whether the phase can progress.
    pub can_progress: bool,
    /// Finding IDs that block progression.
    pub blocking_findings: Vec<String>,
    /// Finding IDs closed without verified remediation.
    pub unverified_closures: Vec<String>,
    /// Total findings for this phase.
    pub total_findings: usize,
    /// Resolved findings for this phase.
    pub resolved_findings: usize,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from the evidence system.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EvidenceError {
    /// Duplicate evidence or finding ID.
    #[error("duplicate ID: {0}")]
    DuplicateId(String),

    /// Invalid lifecycle stage transition.
    #[error("invalid lifecycle transition for finding '{finding_id}': {from} → {to}")]
    InvalidLifecycleTransition {
        finding_id: String,
        from: LifecycleStage,
        to: LifecycleStage,
    },

    /// Attempted to set remediation before the Remediation stage.
    #[error("cannot set remediation for finding '{finding_id}' at stage {current_stage}")]
    PrematureRemediation {
        finding_id: String,
        current_stage: LifecycleStage,
    },

    /// Attempted to verify remediation before the Verification stage.
    #[error("cannot verify remediation for finding '{finding_id}' at stage {current_stage}")]
    PrematureVerification {
        finding_id: String,
        current_stage: LifecycleStage,
    },
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Helper --------------------------------------------------------------

    fn sample_evidence(id: &str, phase: u32, category: EvidenceCategory) -> AuditEvidence {
        AuditEvidence::new(
            id,
            phase,
            category,
            "Test hypothesis",
            VerificationMethod::Test,
            "src/lib.rs",
            "Semantic gap",
            AuditResult::Pass,
            "evidence/test.json",
            "cargo test --lib",
            "self-audit",
            1_700_000_000,
        )
    }

    fn sample_finding(id: &str, phase: u32, severity: Severity) -> Finding {
        Finding::new(
            id,
            phase,
            severity,
            "Test finding description",
            1_700_000_000,
        )
    }

    // -- EvidenceCategory ----------------------------------------------------

    #[test]
    fn test_evidence_category_display() {
        assert_eq!(
            EvidenceCategory::FormalVerification.to_string(),
            "CAT-1: Formal Verification"
        );
        assert_eq!(
            EvidenceCategory::ModelChecking.to_string(),
            "CAT-2: Model Checking"
        );
        assert_eq!(
            EvidenceCategory::TestExecution.to_string(),
            "CAT-3: Test Execution"
        );
        assert_eq!(
            EvidenceCategory::PropertyTest.to_string(),
            "CAT-4: Property Test"
        );
        assert_eq!(
            EvidenceCategory::SecurityScan.to_string(),
            "CAT-5: Security Scan"
        );
        assert_eq!(
            EvidenceCategory::Compliance.to_string(),
            "CAT-6: Compliance"
        );
    }

    // -- Severity ------------------------------------------------------------

    #[test]
    fn test_severity_blocks_phase() {
        assert!(Severity::Catastrophic.blocks_phase());
        assert!(Severity::Critical.blocks_phase());
        assert!(!Severity::Serious.blocks_phase());
        assert!(!Severity::Moderate.blocks_phase());
        assert!(!Severity::Informational.blocks_phase());
    }

    #[test]
    fn test_severity_requires_remediation() {
        assert!(Severity::Catastrophic.requires_remediation());
        assert!(Severity::Critical.requires_remediation());
        assert!(Severity::Serious.requires_remediation());
        assert!(!Severity::Moderate.requires_remediation());
        assert!(!Severity::Informational.requires_remediation());
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(Severity::Catastrophic.to_string(), "Catastrophic");
        assert_eq!(Severity::Critical.to_string(), "Critical");
        assert_eq!(Severity::Serious.to_string(), "Serious");
        assert_eq!(Severity::Moderate.to_string(), "Moderate");
        assert_eq!(Severity::Informational.to_string(), "Informational");
    }

    // -- LifecycleStage ------------------------------------------------------

    #[test]
    fn test_lifecycle_ordering() {
        let stages = [
            LifecycleStage::Discovery,
            LifecycleStage::Documentation,
            LifecycleStage::Triage,
            LifecycleStage::Remediation,
            LifecycleStage::Verification,
            LifecycleStage::Closure,
        ];

        for i in 0..stages.len() - 1 {
            assert_eq!(stages[i].next(), Some(stages[i + 1]));
            assert!(stages[i].can_transition_to(stages[i + 1]));
        }

        // Closure has no next stage.
        assert_eq!(LifecycleStage::Closure.next(), None);
    }

    #[test]
    fn test_lifecycle_rejects_skip() {
        // Cannot skip from Discovery to Triage.
        assert!(!LifecycleStage::Discovery.can_transition_to(LifecycleStage::Triage));
        // Cannot skip from Documentation to Remediation.
        assert!(!LifecycleStage::Documentation.can_transition_to(LifecycleStage::Remediation));
        // Cannot go backwards.
        assert!(!LifecycleStage::Triage.can_transition_to(LifecycleStage::Discovery));
    }

    // -- EvidenceHash --------------------------------------------------------

    #[test]
    fn test_evidence_hash_deterministic() {
        let data = b"test content for hashing";
        let h1 = EvidenceHash::compute(data);
        let h2 = EvidenceHash::compute(data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_evidence_hash_different_inputs() {
        let h1 = EvidenceHash::compute(b"input A");
        let h2 = EvidenceHash::compute(b"input B");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_evidence_hash_hex() {
        let h = EvidenceHash::compute(b"test");
        let hex = h.to_hex();
        assert_eq!(hex.len(), 64); // 32 bytes = 64 hex chars
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // -- AuditEvidence -------------------------------------------------------

    #[test]
    fn test_evidence_creation_uncommitted() {
        let ev = sample_evidence("AE-0-001", 0, EvidenceCategory::FormalVerification);
        assert!(!ev.is_committed());
        assert!(ev.commitment().is_none());
    }

    #[test]
    fn test_evidence_commit_and_verify() {
        let mut ev = sample_evidence("AE-0-001", 0, EvidenceCategory::FormalVerification);
        ev.commit();
        assert!(ev.is_committed());
        assert!(ev.commitment().is_some());
        assert!(ev.verify_integrity());
    }

    #[test]
    fn test_evidence_with_finding() {
        let mut ev = sample_evidence("AE-0-002", 0, EvidenceCategory::TestExecution)
            .with_finding("Missing constraint for field X", Severity::Critical);
        ev.commit();

        assert_eq!(ev.result, AuditResult::Pass);
        assert_eq!(
            ev.finding.as_deref(),
            Some("Missing constraint for field X")
        );
        assert_eq!(ev.severity, Some(Severity::Critical));
        assert!(ev.verify_integrity());
    }

    #[test]
    fn test_evidence_integrity_fails_on_tamper() {
        let mut ev = sample_evidence("AE-0-003", 0, EvidenceCategory::ModelChecking);
        ev.commit();
        assert!(ev.verify_integrity());

        // Tamper with the hypothesis after commitment.
        ev.hypothesis = "tampered hypothesis".to_string();
        assert!(!ev.verify_integrity());
    }

    #[test]
    fn test_evidence_uncommitted_fails_verify() {
        let ev = sample_evidence("AE-0-004", 0, EvidenceCategory::Compliance);
        assert!(!ev.verify_integrity());
    }

    // -- Finding lifecycle ---------------------------------------------------

    #[test]
    fn test_finding_creation() {
        let f = sample_finding("F-0-001", 0, Severity::Critical);
        assert_eq!(f.stage, LifecycleStage::Discovery);
        assert!(!f.is_resolved());
        assert!(f.blocks_phase());
    }

    #[test]
    fn test_finding_full_lifecycle() {
        let mut f = sample_finding("F-0-001", 0, Severity::Serious);
        let mut ts = 1_700_000_000u64;

        // Discovery → Documentation
        ts += 100;
        assert!(f.advance(ts).is_ok());
        assert_eq!(f.stage, LifecycleStage::Documentation);

        // Documentation → Triage
        ts += 100;
        assert!(f.advance(ts).is_ok());
        assert_eq!(f.stage, LifecycleStage::Triage);

        // Triage → Remediation
        ts += 100;
        assert!(f.advance(ts).is_ok());
        assert_eq!(f.stage, LifecycleStage::Remediation);
        assert!(f.set_remediation("Applied fix X").is_ok());

        // Remediation → Verification
        ts += 100;
        assert!(f.advance(ts).is_ok());
        assert_eq!(f.stage, LifecycleStage::Verification);
        assert!(f.verify_remediation().is_ok());

        // Verification → Closure
        ts += 100;
        assert!(f.advance(ts).is_ok());
        assert_eq!(f.stage, LifecycleStage::Closure);

        assert!(f.is_resolved());
        assert!(!f.blocks_phase());
    }

    #[test]
    fn test_finding_advance_past_closure_fails() {
        let mut f = sample_finding("F-0-001", 0, Severity::Informational);
        // Advance through all stages to Closure.
        for _ in 0..5 {
            f.advance(1_700_000_100).unwrap();
        }
        assert_eq!(f.stage, LifecycleStage::Closure);

        // Cannot advance past Closure.
        assert!(f.advance(1_700_000_200).is_err());
    }

    #[test]
    fn test_finding_advance_to_rejects_skip() {
        let mut f = sample_finding("F-0-001", 0, Severity::Moderate);
        // Cannot skip from Discovery to Triage.
        let result = f.advance_to(LifecycleStage::Triage, 1_700_000_100);
        assert!(result.is_err());
        assert_eq!(f.stage, LifecycleStage::Discovery);
    }

    #[test]
    fn test_finding_premature_remediation() {
        let mut f = sample_finding("F-0-001", 0, Severity::Moderate);
        // Cannot set remediation at Discovery stage.
        let result = f.set_remediation("fix");
        assert!(result.is_err());
    }

    #[test]
    fn test_finding_premature_verification() {
        let mut f = sample_finding("F-0-001", 0, Severity::Moderate);
        // Cannot verify remediation at Discovery stage.
        let result = f.verify_remediation();
        assert!(result.is_err());
    }

    #[test]
    fn test_informational_finding_does_not_block() {
        let f = sample_finding("F-0-001", 0, Severity::Informational);
        assert!(!f.blocks_phase());
    }

    #[test]
    fn test_moderate_finding_does_not_block() {
        let f = sample_finding("F-0-001", 0, Severity::Moderate);
        assert!(!f.blocks_phase());
    }

    #[test]
    fn test_serious_finding_does_not_block_phase_but_requires_remediation() {
        let f = sample_finding("F-0-001", 0, Severity::Serious);
        // Serious does not block phase (only Catastrophic/Critical do),
        // but it requires remediation before phase completion.
        assert!(!f.blocks_phase());
        assert!(f.severity.requires_remediation());
    }

    // -- EvidenceStore -------------------------------------------------------

    #[test]
    fn test_store_add_and_retrieve_evidence() {
        let mut store = EvidenceStore::new();
        let ev = sample_evidence("AE-0-001", 0, EvidenceCategory::FormalVerification);
        store.add_evidence(ev).unwrap();

        assert_eq!(store.evidence_count(), 1);
        let retrieved = store.get_evidence("AE-0-001").unwrap();
        assert!(retrieved.is_committed());
        assert!(retrieved.verify_integrity());
    }

    #[test]
    fn test_store_rejects_duplicate_evidence() {
        let mut store = EvidenceStore::new();
        let ev1 = sample_evidence("AE-0-001", 0, EvidenceCategory::FormalVerification);
        let ev2 = sample_evidence("AE-0-001", 0, EvidenceCategory::TestExecution);
        store.add_evidence(ev1).unwrap();
        assert!(store.add_evidence(ev2).is_err());
    }

    #[test]
    fn test_store_auto_commits_evidence() {
        let mut store = EvidenceStore::new();
        let ev = sample_evidence("AE-0-001", 0, EvidenceCategory::FormalVerification);
        assert!(!ev.is_committed());
        store.add_evidence(ev).unwrap();

        let stored = store.get_evidence("AE-0-001").unwrap();
        assert!(stored.is_committed());
    }

    #[test]
    fn test_store_evidence_for_phase() {
        let mut store = EvidenceStore::new();
        store
            .add_evidence(sample_evidence(
                "AE-0-001",
                0,
                EvidenceCategory::FormalVerification,
            ))
            .unwrap();
        store
            .add_evidence(sample_evidence(
                "AE-0-002",
                0,
                EvidenceCategory::TestExecution,
            ))
            .unwrap();
        store
            .add_evidence(sample_evidence(
                "AE-1-001",
                1,
                EvidenceCategory::ModelChecking,
            ))
            .unwrap();

        assert_eq!(store.evidence_for_phase(0).len(), 2);
        assert_eq!(store.evidence_for_phase(1).len(), 1);
        assert_eq!(store.evidence_for_phase(2).len(), 0);
    }

    #[test]
    fn test_store_evidence_by_category() {
        let mut store = EvidenceStore::new();
        store
            .add_evidence(sample_evidence(
                "AE-0-001",
                0,
                EvidenceCategory::FormalVerification,
            ))
            .unwrap();
        store
            .add_evidence(sample_evidence(
                "AE-0-002",
                0,
                EvidenceCategory::FormalVerification,
            ))
            .unwrap();
        store
            .add_evidence(sample_evidence(
                "AE-0-003",
                0,
                EvidenceCategory::TestExecution,
            ))
            .unwrap();

        assert_eq!(
            store
                .evidence_by_category(EvidenceCategory::FormalVerification)
                .len(),
            2
        );
        assert_eq!(
            store
                .evidence_by_category(EvidenceCategory::TestExecution)
                .len(),
            1
        );
        assert_eq!(
            store
                .evidence_by_category(EvidenceCategory::SecurityScan)
                .len(),
            0
        );
    }

    #[test]
    fn test_store_verify_all_integrity() {
        let mut store = EvidenceStore::new();
        store
            .add_evidence(sample_evidence(
                "AE-0-001",
                0,
                EvidenceCategory::FormalVerification,
            ))
            .unwrap();
        store
            .add_evidence(sample_evidence(
                "AE-0-002",
                0,
                EvidenceCategory::TestExecution,
            ))
            .unwrap();

        let failures = store.verify_all_integrity();
        assert!(failures.is_empty());
    }

    #[test]
    fn test_store_next_evidence_id() {
        let mut store = EvidenceStore::new();
        assert_eq!(store.next_evidence_id(0), "AE-0-001");
        assert_eq!(store.next_evidence_id(0), "AE-0-002");
        assert_eq!(store.next_evidence_id(1), "AE-1-001");
        assert_eq!(store.next_evidence_id(0), "AE-0-003");
    }

    // -- Finding store -------------------------------------------------------

    #[test]
    fn test_store_add_and_retrieve_finding() {
        let mut store = EvidenceStore::new();
        let f = sample_finding("F-0-001", 0, Severity::Critical);
        store.add_finding(f).unwrap();

        assert_eq!(store.finding_count(), 1);
        let retrieved = store.get_finding("F-0-001").unwrap();
        assert_eq!(retrieved.severity, Severity::Critical);
    }

    #[test]
    fn test_store_rejects_duplicate_finding() {
        let mut store = EvidenceStore::new();
        let f1 = sample_finding("F-0-001", 0, Severity::Critical);
        let f2 = sample_finding("F-0-001", 0, Severity::Moderate);
        store.add_finding(f1).unwrap();
        assert!(store.add_finding(f2).is_err());
    }

    #[test]
    fn test_store_findings_for_phase() {
        let mut store = EvidenceStore::new();
        store
            .add_finding(sample_finding("F-0-001", 0, Severity::Critical))
            .unwrap();
        store
            .add_finding(sample_finding("F-0-002", 0, Severity::Moderate))
            .unwrap();
        store
            .add_finding(sample_finding("F-1-001", 1, Severity::Serious))
            .unwrap();

        assert_eq!(store.findings_for_phase(0).len(), 2);
        assert_eq!(store.findings_for_phase(1).len(), 1);
    }

    #[test]
    fn test_store_next_finding_id() {
        let mut store = EvidenceStore::new();
        assert_eq!(store.next_finding_id(0), "F-0-001");
        assert_eq!(store.next_finding_id(0), "F-0-002");
        assert_eq!(store.next_finding_id(1), "F-1-001");
    }

    // -- Phase gating --------------------------------------------------------

    #[test]
    fn test_phase_gate_no_findings() {
        let store = EvidenceStore::new();
        let result = store.can_progress_phase(0);
        assert!(result.can_progress);
        assert!(result.blocking_findings.is_empty());
    }

    #[test]
    fn test_phase_gate_blocks_on_critical() {
        let mut store = EvidenceStore::new();
        store
            .add_finding(sample_finding("F-0-001", 0, Severity::Critical))
            .unwrap();

        let result = store.can_progress_phase(0);
        assert!(!result.can_progress);
        assert_eq!(result.blocking_findings, vec!["F-0-001"]);
    }

    #[test]
    fn test_phase_gate_blocks_on_catastrophic() {
        let mut store = EvidenceStore::new();
        store
            .add_finding(sample_finding("F-0-001", 0, Severity::Catastrophic))
            .unwrap();

        let result = store.can_progress_phase(0);
        assert!(!result.can_progress);
        assert_eq!(result.blocking_findings, vec!["F-0-001"]);
    }

    #[test]
    fn test_phase_gate_blocks_on_serious() {
        let mut store = EvidenceStore::new();
        store
            .add_finding(sample_finding("F-0-001", 0, Severity::Serious))
            .unwrap();

        let result = store.can_progress_phase(0);
        assert!(!result.can_progress);
        assert_eq!(result.blocking_findings, vec!["F-0-001"]);
    }

    #[test]
    fn test_phase_gate_allows_moderate() {
        let mut store = EvidenceStore::new();
        store
            .add_finding(sample_finding("F-0-001", 0, Severity::Moderate))
            .unwrap();

        let result = store.can_progress_phase(0);
        assert!(result.can_progress);
    }

    #[test]
    fn test_phase_gate_allows_informational() {
        let mut store = EvidenceStore::new();
        store
            .add_finding(sample_finding("F-0-001", 0, Severity::Informational))
            .unwrap();

        let result = store.can_progress_phase(0);
        assert!(result.can_progress);
    }

    #[test]
    fn test_phase_gate_resolved_critical_allows_progress() {
        let mut store = EvidenceStore::new();
        let mut f = sample_finding("F-0-001", 0, Severity::Critical);

        // Walk through full lifecycle.
        let mut ts = 1_700_000_000u64;
        for _ in 0..3 {
            ts += 100;
            f.advance(ts).unwrap();
        }
        // Now at Remediation.
        f.set_remediation("Applied fix").unwrap();
        ts += 100;
        f.advance(ts).unwrap(); // → Verification
        f.verify_remediation().unwrap();
        ts += 100;
        f.advance(ts).unwrap(); // → Closure

        assert!(f.is_resolved());
        store.add_finding(f).unwrap();

        let result = store.can_progress_phase(0);
        assert!(result.can_progress);
        assert_eq!(result.resolved_findings, 1);
    }

    #[test]
    fn test_phase_gate_unverified_closure_blocks() {
        let mut store = EvidenceStore::new();
        let mut f = sample_finding("F-0-001", 0, Severity::Moderate);

        // Walk to Closure without verifying remediation.
        let mut ts = 1_700_000_000u64;
        for _ in 0..5 {
            ts += 100;
            f.advance(ts).unwrap();
        }
        assert_eq!(f.stage, LifecycleStage::Closure);
        assert!(!f.remediation_verified);

        store.add_finding(f).unwrap();

        let result = store.can_progress_phase(0);
        assert!(!result.can_progress);
        assert_eq!(result.unverified_closures, vec!["F-0-001"]);
    }

    #[test]
    fn test_phase_gate_different_phase_not_affected() {
        let mut store = EvidenceStore::new();
        // Critical finding in phase 1 should not block phase 0.
        store
            .add_finding(sample_finding("F-1-001", 1, Severity::Critical))
            .unwrap();

        let result = store.can_progress_phase(0);
        assert!(result.can_progress);
    }

    // -- All six categories present ------------------------------------------

    #[test]
    fn test_all_six_categories() {
        let mut store = EvidenceStore::new();
        let categories = [
            EvidenceCategory::FormalVerification,
            EvidenceCategory::ModelChecking,
            EvidenceCategory::TestExecution,
            EvidenceCategory::PropertyTest,
            EvidenceCategory::SecurityScan,
            EvidenceCategory::Compliance,
        ];

        for (i, cat) in categories.iter().enumerate() {
            let id = format!("AE-0-{:03}", i + 1);
            store.add_evidence(sample_evidence(&id, 0, *cat)).unwrap();
        }

        assert_eq!(store.evidence_count(), 6);
        for cat in &categories {
            assert_eq!(store.evidence_by_category(*cat).len(), 1);
        }
    }

    // -- Finding with evidence linking ---------------------------------------

    #[test]
    fn test_finding_evidence_linking() {
        let mut f = sample_finding("F-0-001", 0, Severity::Critical);
        f.add_evidence("AE-0-001");
        f.add_evidence("AE-0-002");
        assert_eq!(f.evidence_ids.len(), 2);
        assert_eq!(f.evidence_ids[0], "AE-0-001");
        assert_eq!(f.evidence_ids[1], "AE-0-002");
    }
}
