//! Proof obligation tracking system.
//!
//! Tracks all 46 proof obligations from PROOF_OBLIGATIONS.md with:
//! - Status: unresolved / in-progress / discharged / failed
//! - Discharge method: model-check / theorem-prove / test / argument
//! - Tool: Lean 4 / TLA+ / Rust test / Python
//! - Evidence artifact reference
//! - Last verified date
//! - Reviewer
//!
//! Requirements: 16.5, 16.7

use std::collections::BTreeMap;

use crate::matrix::ObligationCategory;

// ---------------------------------------------------------------------------
// Obligation status
// ---------------------------------------------------------------------------

/// Status of a proof obligation.
///
/// Requirement 16.5: track status as unresolved / in-progress / discharged / failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObligationStatus {
    /// Not yet addressed.
    Unresolved,
    /// Work in progress — partially discharged or under review.
    InProgress,
    /// Fully discharged with evidence.
    Discharged,
    /// Discharge attempt failed — requires remediation.
    Failed,
}

impl std::fmt::Display for ObligationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ObligationStatus::Unresolved => write!(f, "Unresolved"),
            ObligationStatus::InProgress => write!(f, "In-Progress"),
            ObligationStatus::Discharged => write!(f, "Discharged"),
            ObligationStatus::Failed => write!(f, "Failed"),
        }
    }
}

// ---------------------------------------------------------------------------
// Discharge method
// ---------------------------------------------------------------------------

/// Method used to discharge a proof obligation.
///
/// Requirement 16.5: method (model-check / theorem-prove / test / argument).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DischargeMethod {
    /// Discharged via model checking (TLA+).
    ModelCheck,
    /// Discharged via theorem proving (Lean 4).
    TheoremProve,
    /// Discharged via testing (Rust proptest, integration tests).
    Test,
    /// Discharged via informal argument (documented reasoning).
    Argument,
}

impl std::fmt::Display for DischargeMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DischargeMethod::ModelCheck => write!(f, "Model-Check"),
            DischargeMethod::TheoremProve => write!(f, "Theorem-Prove"),
            DischargeMethod::Test => write!(f, "Test"),
            DischargeMethod::Argument => write!(f, "Argument"),
        }
    }
}

// ---------------------------------------------------------------------------
// Verification tool
// ---------------------------------------------------------------------------

/// Tool used to verify a proof obligation.
///
/// Requirement 16.5: tool (Lean 4 / TLA+ / Rust test / Python).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VerificationTool {
    /// Lean 4 theorem prover.
    Lean4,
    /// TLA+ model checker.
    TlaPlus,
    /// Rust test (unit, property, integration).
    RustTest,
    /// Python adversarial tooling.
    Python,
}

impl std::fmt::Display for VerificationTool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerificationTool::Lean4 => write!(f, "Lean 4"),
            VerificationTool::TlaPlus => write!(f, "TLA+"),
            VerificationTool::RustTest => write!(f, "Rust Test"),
            VerificationTool::Python => write!(f, "Python"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tracked proof obligation
// ---------------------------------------------------------------------------

/// A tracked proof obligation with full audit metadata.
///
/// Requirement 16.5: status, method, tool, evidence, last verified, reviewer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrackedObligation {
    /// Obligation ID (e.g., "AX-1", "LEM-4", "CONST-1").
    pub obligation_id: String,
    /// Obligation category.
    pub category: ObligationCategory,
    /// Human-readable statement of the obligation.
    pub statement: String,
    /// Current status.
    pub status: ObligationStatus,
    /// Discharge method (if any work has been done).
    pub method: Option<DischargeMethod>,
    /// Verification tool used.
    pub tool: Option<VerificationTool>,
    /// Evidence artifact reference (file path or URI).
    pub evidence: Option<String>,
    /// Last verified date (ISO 8601 string, e.g., "2025-01-15").
    pub last_verified: Option<String>,
    /// Reviewer who last verified.
    pub reviewer: Option<String>,
    /// IDs of obligations this one depends on (upstream).
    pub dependencies: Vec<String>,
    /// Falsification target — what would disprove this obligation.
    pub falsification_target: String,
}

// ---------------------------------------------------------------------------
// Obligation tracker
// ---------------------------------------------------------------------------

/// Proof obligation tracker.
///
/// Tracks all proof obligations with status, method, tool, evidence,
/// last verified date, and reviewer. Supports querying by status,
/// category, and dependency analysis.
///
/// Requirements: 16.5, 16.7
#[derive(Clone, Debug)]
pub struct ObligationTracker {
    /// All tracked obligations, keyed by obligation ID.
    obligations: BTreeMap<String, TrackedObligation>,
}

impl ObligationTracker {
    /// Create a new empty tracker.
    pub fn new() -> Self {
        Self {
            obligations: BTreeMap::new(),
        }
    }

    /// Register a proof obligation for tracking.
    pub fn register(&mut self, obligation: TrackedObligation) {
        self.obligations
            .insert(obligation.obligation_id.clone(), obligation);
    }

    /// Get a tracked obligation by ID.
    pub fn get(&self, obligation_id: &str) -> Option<&TrackedObligation> {
        self.obligations.get(obligation_id)
    }

    /// Get a mutable reference to a tracked obligation by ID.
    pub fn get_mut(&mut self, obligation_id: &str) -> Option<&mut TrackedObligation> {
        self.obligations.get_mut(obligation_id)
    }

    /// Total number of tracked obligations.
    pub fn count(&self) -> usize {
        self.obligations.len()
    }

    /// All obligation IDs.
    pub fn obligation_ids(&self) -> Vec<&str> {
        self.obligations.keys().map(|s| s.as_str()).collect()
    }

    /// All tracked obligations.
    pub fn all(&self) -> impl Iterator<Item = &TrackedObligation> {
        self.obligations.values()
    }

    // -----------------------------------------------------------------------
    // Status transitions — explicit and auditable
    // -----------------------------------------------------------------------

    /// Transition an obligation to in-progress.
    ///
    /// Returns `Err` if the obligation is not found.
    pub fn start_work(
        &mut self,
        obligation_id: &str,
        method: DischargeMethod,
        tool: VerificationTool,
        reviewer: &str,
    ) -> Result<(), TrackerError> {
        let obl = self
            .obligations
            .get_mut(obligation_id)
            .ok_or_else(|| TrackerError::ObligationNotFound(obligation_id.to_string()))?;

        obl.status = ObligationStatus::InProgress;
        obl.method = Some(method);
        obl.tool = Some(tool);
        obl.reviewer = Some(reviewer.to_string());
        Ok(())
    }

    /// Discharge an obligation with evidence.
    ///
    /// Returns `Err` if the obligation is not found.
    pub fn discharge(
        &mut self,
        obligation_id: &str,
        evidence: &str,
        verified_date: &str,
        reviewer: &str,
    ) -> Result<(), TrackerError> {
        let obl = self
            .obligations
            .get_mut(obligation_id)
            .ok_or_else(|| TrackerError::ObligationNotFound(obligation_id.to_string()))?;

        obl.status = ObligationStatus::Discharged;
        obl.evidence = Some(evidence.to_string());
        obl.last_verified = Some(verified_date.to_string());
        obl.reviewer = Some(reviewer.to_string());
        Ok(())
    }

    /// Mark an obligation as failed.
    ///
    /// Returns `Err` if the obligation is not found.
    pub fn mark_failed(
        &mut self,
        obligation_id: &str,
        evidence: &str,
        verified_date: &str,
        reviewer: &str,
    ) -> Result<(), TrackerError> {
        let obl = self
            .obligations
            .get_mut(obligation_id)
            .ok_or_else(|| TrackerError::ObligationNotFound(obligation_id.to_string()))?;

        obl.status = ObligationStatus::Failed;
        obl.evidence = Some(evidence.to_string());
        obl.last_verified = Some(verified_date.to_string());
        obl.reviewer = Some(reviewer.to_string());
        Ok(())
    }

    /// Reset an obligation to unresolved (e.g., after upstream change).
    ///
    /// Returns `Err` if the obligation is not found.
    pub fn reset(&mut self, obligation_id: &str) -> Result<(), TrackerError> {
        let obl = self
            .obligations
            .get_mut(obligation_id)
            .ok_or_else(|| TrackerError::ObligationNotFound(obligation_id.to_string()))?;

        obl.status = ObligationStatus::Unresolved;
        // Preserve method/tool/evidence for audit trail, but clear reviewer.
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Queries
    // -----------------------------------------------------------------------

    /// Get all obligations with a given status.
    pub fn by_status(&self, status: ObligationStatus) -> Vec<&TrackedObligation> {
        self.obligations
            .values()
            .filter(|o| o.status == status)
            .collect()
    }

    /// Get all obligations in a given category.
    pub fn by_category(&self, category: ObligationCategory) -> Vec<&TrackedObligation> {
        self.obligations
            .values()
            .filter(|o| o.category == category)
            .collect()
    }

    /// Count obligations by status.
    pub fn status_summary(&self) -> StatusSummary {
        let mut summary = StatusSummary::default();
        for obl in self.obligations.values() {
            match obl.status {
                ObligationStatus::Unresolved => summary.unresolved += 1,
                ObligationStatus::InProgress => summary.in_progress += 1,
                ObligationStatus::Discharged => summary.discharged += 1,
                ObligationStatus::Failed => summary.failed += 1,
            }
        }
        summary.total = self.obligations.len();
        summary
    }

    /// Check if all obligations are discharged.
    pub fn all_discharged(&self) -> bool {
        self.obligations
            .values()
            .all(|o| o.status == ObligationStatus::Discharged)
    }

    /// Get all obligations that are not discharged (unresolved, in-progress, or failed).
    pub fn outstanding(&self) -> Vec<&TrackedObligation> {
        self.obligations
            .values()
            .filter(|o| o.status != ObligationStatus::Discharged)
            .collect()
    }
}

impl Default for ObligationTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Status summary
// ---------------------------------------------------------------------------

/// Summary of obligation statuses.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StatusSummary {
    pub total: usize,
    pub unresolved: usize,
    pub in_progress: usize,
    pub discharged: usize,
    pub failed: usize,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from the obligation tracker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrackerError {
    /// Obligation ID not found in the tracker.
    ObligationNotFound(String),
}

impl std::fmt::Display for TrackerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrackerError::ObligationNotFound(id) => {
                write!(f, "Obligation '{}' not found in tracker", id)
            }
        }
    }
}

impl std::error::Error for TrackerError {}

// ---------------------------------------------------------------------------
// Builder — populate tracker from the traceability matrix
// ---------------------------------------------------------------------------

/// Build a fully populated obligation tracker from the traceability matrix.
///
/// Registers all 46 proof obligations (AX-1..AX-6, DEF-1..DEF-6,
/// LEM-1..LEM-10, SAFE-1..SAFE-6, LIVE-1..LIVE-2, CONST-1..CONST-4,
/// PROOF-1..PROOF-4, COMP-1..COMP-3, ECON-1..ECON-5) with initial
/// status `Unresolved`.
///
/// Requirements: 16.5, 16.7
pub fn build_obligation_tracker(matrix: &crate::matrix::TraceabilityMatrix) -> ObligationTracker {
    let mut tracker = ObligationTracker::new();

    // Obligation statements keyed by ID.
    let statements = obligation_statements();

    // Dependency graph keyed by ID.
    let deps = obligation_dependencies();

    // Falsification targets keyed by ID.
    let falsification = falsification_targets();

    for (id, entry) in &matrix.proof_obligations {
        let statement = statements.get(id.as_str()).cloned().unwrap_or_default();
        let dependencies = deps.get(id.as_str()).cloned().unwrap_or_default();
        let falsification_target = falsification.get(id.as_str()).cloned().unwrap_or_default();

        tracker.register(TrackedObligation {
            obligation_id: id.clone(),
            category: entry.category,
            statement,
            status: ObligationStatus::Unresolved,
            method: None,
            tool: None,
            evidence: None,
            last_verified: None,
            reviewer: None,
            dependencies,
            falsification_target,
        });
    }

    tracker
}

/// Human-readable statements for each proof obligation.
fn obligation_statements() -> BTreeMap<&'static str, String> {
    let mut m = BTreeMap::new();

    // Axioms
    m.insert(
        "AX-1",
        "Determinism: Apply(s, σ) produces exactly one s' for every (s, σ) pair".to_string(),
    );
    m.insert(
        "AX-2",
        "Closure: for all s ∈ S and σ ∈ Σ, Apply(s, σ) ∈ S".to_string(),
    );
    m.insert("AX-3", "Genesis: initial states satisfy genesis constraints with D(s₀) = Derive(C(s₀)) and τ(s₀) = 0".to_string());
    m.insert(
        "AX-4",
        "Proof system soundness: the underlying proof system is sound".to_string(),
    );
    m.insert(
        "AX-5",
        "Hash collision resistance: the hash function is collision-resistant".to_string(),
    );
    m.insert(
        "AX-6",
        "Environment faithfulness: environment data is accurate".to_string(),
    );

    // Definitions
    m.insert(
        "DEF-1",
        "Derived state determinism: D = Derive(C) is deterministic".to_string(),
    );
    m.insert(
        "DEF-2",
        "Encoding injectivity: Encode(s₁) = Encode(s₂) ⟹ s₁ = s₂".to_string(),
    );
    m.insert(
        "DEF-3",
        "Commitment binding: Commit(C) = D.commitment".to_string(),
    );
    m.insert(
        "DEF-4",
        "Observable determinism: Obs(s, σ, s') is deterministic".to_string(),
    );
    m.insert(
        "DEF-5",
        "Canonicalization idempotence: Canonical(Canonical(σ)) = Canonical(σ)".to_string(),
    );
    m.insert(
        "DEF-6",
        "Canonicalization semantic preservation: semantics preserved through canonicalization"
            .to_string(),
    );

    // Lemmas
    m.insert(
        "LEM-1",
        "Invariant preservation: ∀ (s, σ, s') ∈ T, ∀ G ∈ GlobalInvariants: G(s) ⟹ G(s')"
            .to_string(),
    );
    m.insert(
        "LEM-2",
        "Trace inductive invariance: s₀ ∈ I ∧ (∀ i: G(sᵢ) ⟹ G(sᵢ₊₁)) ⟹ ∀ i: G(sᵢ)".to_string(),
    );
    m.insert(
        "LEM-3",
        "Semantic mapping commutativity: μ_S(Apply_c(s, σ)) = Apply_f(μ_S(s), μ_Σ(σ))".to_string(),
    );
    m.insert(
        "LEM-4",
        "Constraint soundness: SatisfiesConstraints(τ) ⟹ ValidTrace(τ)".to_string(),
    );
    m.insert(
        "LEM-5",
        "Constraint completeness: ValidTrace(τ) ⟹ SatisfiesConstraints(τ)".to_string(),
    );
    m.insert(
        "LEM-6",
        "Witness semantic uniqueness: same public inputs ⟹ same semantic execution".to_string(),
    );
    m.insert(
        "LEM-7",
        "Error state invariant preservation: Apply(s, σ_invalid) = s_error preserves invariants"
            .to_string(),
    );
    m.insert(
        "LEM-8",
        "Noop semantic neutrality: noop transitions do not change semantic state".to_string(),
    );
    m.insert(
        "LEM-9",
        "Batch decomposition equivalence: Apply(s, [σ₁..σₙ]) = sequential application".to_string(),
    );
    m.insert(
        "LEM-10",
        "Trace reconstruction fidelity: Reconstruct(s₀, σ₀..σₙ₋₁) = τ".to_string(),
    );

    // Safety
    m.insert(
        "SAFE-1",
        "Unreachable invalid states: no reachable state is invalid".to_string(),
    );
    m.insert(
        "SAFE-2",
        "Resource conservation: Total(C_s) = Total(C_s') + Δ_fees".to_string(),
    );
    m.insert(
        "SAFE-3",
        "No hidden state mutation: Diff(s, s') ⊆ AllowedMutations(σ)".to_string(),
    );
    m.insert(
        "SAFE-4",
        "Temporal monotonicity: metadata is monotonically increasing".to_string(),
    );
    m.insert(
        "SAFE-5",
        "No rollback: state cannot revert to a previous state".to_string(),
    );
    m.insert(
        "SAFE-6",
        "Domain isolation: proofs are domain-separated".to_string(),
    );

    // Liveness
    m.insert(
        "LIVE-1",
        "No deadlock: the system always has a valid transition".to_string(),
    );
    m.insert("LIVE-2", "Provability: ValidTrace(τ) ⟹ ∃ π".to_string());

    // Constraints
    m.insert(
        "CONST-1",
        "No unconstrained variables: every witness variable is referenced by ≥1 constraint"
            .to_string(),
    );
    m.insert(
        "CONST-2",
        "No unused witness inputs: every witness input influences ≥1 constraint output".to_string(),
    );
    m.insert(
        "CONST-3",
        "Branch completeness: every conditional generates constraints for both branches"
            .to_string(),
    );
    m.insert(
        "CONST-4",
        "Constraint derivation determinism: same SIR/IR ⟹ same constraint system".to_string(),
    );

    // Proof
    m.insert(
        "PROOF-1",
        "Full trace binding: proof binds to complete trace including intermediates".to_string(),
    );
    m.insert(
        "PROOF-2",
        "Observable binding: all observables included in or derivable from public inputs"
            .to_string(),
    );
    m.insert(
        "PROOF-3",
        "Domain separation: Domain(π) is unique and non-reusable across contexts".to_string(),
    );
    m.insert(
        "PROOF-4",
        "Knowledge soundness: prover must know a valid witness".to_string(),
    );

    // Composition
    m.insert(
        "COMP-1",
        "Cross-system resource conservation: Total_A + Total_B = constant".to_string(),
    );
    m.insert(
        "COMP-2",
        "Shared state consistency: cross-system shared state is consistent".to_string(),
    );
    m.insert(
        "COMP-3",
        "Compositional invariant preservation: composed system preserves invariants".to_string(),
    );

    // Economic
    m.insert(
        "ECON-1",
        "Economic invariant preservation: economic invariants preserved under transition"
            .to_string(),
    );
    m.insert(
        "ECON-2",
        "Initial state economic validity: genesis state is economically valid".to_string(),
    );
    m.insert(
        "ECON-3",
        "Temporal economic enforcement: temporal economic invariants enforced".to_string(),
    );
    m.insert(
        "ECON-4",
        "Economic context determinism: Ω = DeriveEconomic(C, E) is deterministic".to_string(),
    );
    m.insert(
        "ECON-5",
        "Economic admissibility completeness: admissibility check is complete".to_string(),
    );

    m
}

/// Dependency graph for proof obligations.
///
/// Requirement 16.7: AX → DEF → LEM → SAFE → LIVE → COMP → ECON → CONST → PROOF
/// Unresolved nodes make everything downstream suspect.
fn obligation_dependencies() -> BTreeMap<&'static str, Vec<String>> {
    let mut m: BTreeMap<&str, Vec<String>> = BTreeMap::new();

    // Axioms have no upstream dependencies (they are foundational).
    for i in 1..=6 {
        m.insert(leak_str(&format!("AX-{}", i)), vec![]);
    }

    // Definitions depend on axioms.
    m.insert("DEF-1", vec!["AX-2".into()]);
    m.insert("DEF-2", vec!["AX-1".into()]);
    m.insert("DEF-3", vec!["AX-5".into()]);
    m.insert("DEF-4", vec!["AX-1".into()]);
    m.insert("DEF-5", vec!["AX-1".into()]);
    m.insert("DEF-6", vec!["DEF-5".into()]);

    // Lemmas depend on axioms and definitions.
    m.insert("LEM-1", vec!["AX-1".into(), "AX-2".into()]);
    m.insert("LEM-2", vec!["LEM-1".into(), "AX-3".into()]);
    m.insert("LEM-3", vec!["AX-1".into(), "DEF-4".into()]);
    m.insert("LEM-4", vec!["LEM-1".into(), "DEF-2".into()]);
    m.insert("LEM-5", vec!["LEM-4".into()]);
    m.insert("LEM-6", vec!["LEM-4".into(), "LEM-5".into()]);
    m.insert("LEM-7", vec!["AX-2".into(), "LEM-1".into()]);
    m.insert("LEM-8", vec!["AX-1".into()]);
    m.insert("LEM-9", vec!["AX-1".into(), "LEM-1".into()]);
    m.insert("LEM-10", vec!["AX-1".into(), "DEF-1".into()]);

    // Safety depends on lemmas.
    m.insert("SAFE-1", vec!["LEM-1".into(), "LEM-2".into()]);
    m.insert("SAFE-2", vec!["LEM-1".into()]);
    m.insert("SAFE-3", vec!["LEM-1".into()]);
    m.insert("SAFE-4", vec!["LEM-2".into()]);
    m.insert("SAFE-5", vec!["SAFE-4".into()]);
    m.insert("SAFE-6", vec!["AX-4".into()]);

    // Liveness depends on safety and lemmas.
    m.insert("LIVE-1", vec!["AX-2".into(), "LEM-1".into()]);
    m.insert("LIVE-2", vec!["LEM-4".into(), "LEM-5".into()]);

    // Constraints depend on lemmas.
    m.insert("CONST-1", vec!["LEM-4".into()]);
    m.insert("CONST-2", vec!["LEM-4".into()]);
    m.insert("CONST-3", vec!["LEM-5".into()]);
    m.insert("CONST-4", vec!["AX-1".into(), "DEF-4".into()]);

    // Proof depends on constraints and safety.
    m.insert("PROOF-1", vec!["LEM-4".into(), "LEM-5".into()]);
    m.insert("PROOF-2", vec!["DEF-4".into(), "PROOF-1".into()]);
    m.insert("PROOF-3", vec!["AX-4".into()]);
    m.insert("PROOF-4", vec!["AX-4".into(), "LEM-6".into()]);

    // Composition depends on safety and lemmas.
    m.insert("COMP-1", vec!["SAFE-2".into()]);
    m.insert("COMP-2", vec!["LEM-1".into()]);
    m.insert("COMP-3", vec!["COMP-1".into(), "COMP-2".into()]);

    // Economic depends on lemmas and safety.
    m.insert("ECON-1", vec!["LEM-1".into()]);
    m.insert("ECON-2", vec!["AX-3".into()]);
    m.insert("ECON-3", vec!["LEM-2".into()]);
    m.insert("ECON-4", vec!["AX-1".into(), "DEF-1".into()]);
    m.insert("ECON-5", vec!["ECON-1".into(), "COMP-3".into()]);

    m
}

/// Falsification targets for each proof obligation.
fn falsification_targets() -> BTreeMap<&'static str, String> {
    let mut m = BTreeMap::new();

    m.insert("AX-1", "Find (s, σ) producing two different s'".to_string());
    m.insert("AX-2", "Find (s, σ) where Apply(s, σ) ∉ S".to_string());
    m.insert(
        "AX-3",
        "Find initial state violating genesis constraints".to_string(),
    );
    m.insert(
        "AX-4",
        "Find invalid proof accepted by verifier".to_string(),
    );
    m.insert("AX-5", "Find hash collision".to_string());
    m.insert("AX-6", "Find environment data inconsistency".to_string());

    m.insert(
        "DEF-1",
        "Find C where Derive(C) is nondeterministic".to_string(),
    );
    m.insert(
        "DEF-2",
        "Find s₁ ≠ s₂ where Encode(s₁) = Encode(s₂)".to_string(),
    );
    m.insert("DEF-3", "Find C where Commit(C) ≠ D.commitment".to_string());
    m.insert("DEF-4", "Find nondeterministic observable".to_string());
    m.insert(
        "DEF-5",
        "Find σ where Canonical(Canonical(σ)) ≠ Canonical(σ)".to_string(),
    );
    m.insert(
        "DEF-6",
        "Find σ where canonicalization changes semantics".to_string(),
    );

    m.insert(
        "LEM-1",
        "Find transition violating a global invariant".to_string(),
    );
    m.insert(
        "LEM-2",
        "Find trace where inductive invariance fails".to_string(),
    );
    m.insert(
        "LEM-3",
        "Find commutativity violation in semantic mapping".to_string(),
    );
    m.insert(
        "LEM-4",
        "Find invalid trace satisfying constraints".to_string(),
    );
    m.insert(
        "LEM-5",
        "Find valid trace not satisfying constraints".to_string(),
    );
    m.insert(
        "LEM-6",
        "Find two witnesses with same public inputs but different semantics".to_string(),
    );
    m.insert(
        "LEM-7",
        "Find error transition violating invariants".to_string(),
    );
    m.insert(
        "LEM-8",
        "Find noop transition changing semantic state".to_string(),
    );
    m.insert(
        "LEM-9",
        "Find batch not equivalent to sequential application".to_string(),
    );
    m.insert(
        "LEM-10",
        "Find trace not reconstructible from initial state and inputs".to_string(),
    );

    m.insert("SAFE-1", "Find reachable invalid state".to_string());
    m.insert(
        "SAFE-2",
        "Find transition violating resource conservation".to_string(),
    );
    m.insert(
        "SAFE-3",
        "Find hidden state mutation outside AllowedMutations".to_string(),
    );
    m.insert("SAFE-4", "Find non-monotonic metadata".to_string());
    m.insert("SAFE-5", "Find state rollback".to_string());
    m.insert("SAFE-6", "Find cross-domain proof acceptance".to_string());

    m.insert("LIVE-1", "Find deadlocked state".to_string());
    m.insert(
        "LIVE-2",
        "Find valid trace without provable proof".to_string(),
    );

    m.insert("CONST-1", "Find unconstrained witness variable".to_string());
    m.insert("CONST-2", "Find unused witness input".to_string());
    m.insert(
        "CONST-3",
        "Find conditional with missing branch constraints".to_string(),
    );
    m.insert(
        "CONST-4",
        "Find nondeterministic constraint derivation".to_string(),
    );

    m.insert(
        "PROOF-1",
        "Find proof not binding to full trace".to_string(),
    );
    m.insert(
        "PROOF-2",
        "Find observable not derivable from public inputs".to_string(),
    );
    m.insert("PROOF-3", "Find cross-context proof replay".to_string());
    m.insert(
        "PROOF-4",
        "Find proof forgery without valid witness".to_string(),
    );

    m.insert(
        "COMP-1",
        "Find cross-system resource creation/destruction".to_string(),
    );
    m.insert("COMP-2", "Find inconsistent shared state".to_string());
    m.insert(
        "COMP-3",
        "Find composed system violating invariants".to_string(),
    );

    m.insert(
        "ECON-1",
        "Find transition violating economic invariants".to_string(),
    );
    m.insert(
        "ECON-2",
        "Find economically invalid genesis state".to_string(),
    );
    m.insert(
        "ECON-3",
        "Find temporal economic invariant violation".to_string(),
    );
    m.insert(
        "ECON-4",
        "Find nondeterministic economic context derivation".to_string(),
    );
    m.insert("ECON-5", "Find incomplete admissibility check".to_string());

    m
}

/// Helper: leak a formatted string to get a `&'static str`.
///
/// Used only during static initialization of the dependency map.
/// The leaked memory is tiny (a few hundred bytes total for 6 axiom IDs)
/// and lives for the program lifetime.
fn leak_str(s: &str) -> &'static str {
    // For the axiom IDs we know at compile time, we use string literals
    // directly in the caller. This function is a fallback.
    Box::leak(s.into())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::build_traceability_matrix;

    #[test]
    fn test_build_tracker_has_all_46_obligations() {
        let matrix = build_traceability_matrix();
        let tracker = build_obligation_tracker(&matrix);
        assert_eq!(tracker.count(), 46);
    }

    #[test]
    fn test_all_obligations_start_unresolved() {
        let matrix = build_traceability_matrix();
        let tracker = build_obligation_tracker(&matrix);

        for obl in tracker.all() {
            assert_eq!(
                obl.status,
                ObligationStatus::Unresolved,
                "Obligation '{}' should start as Unresolved",
                obl.obligation_id
            );
        }
    }

    #[test]
    fn test_all_obligation_ids_present() {
        let matrix = build_traceability_matrix();
        let tracker = build_obligation_tracker(&matrix);

        // AX-1 through AX-6
        for i in 1..=6 {
            assert!(
                tracker.get(&format!("AX-{}", i)).is_some(),
                "Missing AX-{}",
                i
            );
        }
        // DEF-1 through DEF-6
        for i in 1..=6 {
            assert!(
                tracker.get(&format!("DEF-{}", i)).is_some(),
                "Missing DEF-{}",
                i
            );
        }
        // LEM-1 through LEM-10
        for i in 1..=10 {
            assert!(
                tracker.get(&format!("LEM-{}", i)).is_some(),
                "Missing LEM-{}",
                i
            );
        }
        // SAFE-1 through SAFE-6
        for i in 1..=6 {
            assert!(
                tracker.get(&format!("SAFE-{}", i)).is_some(),
                "Missing SAFE-{}",
                i
            );
        }
        // LIVE-1, LIVE-2
        assert!(tracker.get("LIVE-1").is_some());
        assert!(tracker.get("LIVE-2").is_some());
        // CONST-1 through CONST-4
        for i in 1..=4 {
            assert!(
                tracker.get(&format!("CONST-{}", i)).is_some(),
                "Missing CONST-{}",
                i
            );
        }
        // PROOF-1 through PROOF-4
        for i in 1..=4 {
            assert!(
                tracker.get(&format!("PROOF-{}", i)).is_some(),
                "Missing PROOF-{}",
                i
            );
        }
        // COMP-1 through COMP-3
        for i in 1..=3 {
            assert!(
                tracker.get(&format!("COMP-{}", i)).is_some(),
                "Missing COMP-{}",
                i
            );
        }
        // ECON-1 through ECON-5
        for i in 1..=5 {
            assert!(
                tracker.get(&format!("ECON-{}", i)).is_some(),
                "Missing ECON-{}",
                i
            );
        }
    }

    #[test]
    fn test_status_transitions() {
        let matrix = build_traceability_matrix();
        let mut tracker = build_obligation_tracker(&matrix);

        // Start work on AX-1.
        tracker
            .start_work(
                "AX-1",
                DischargeMethod::TheoremProve,
                VerificationTool::Lean4,
                "alice",
            )
            .unwrap();
        assert_eq!(
            tracker.get("AX-1").unwrap().status,
            ObligationStatus::InProgress
        );

        // Discharge AX-1.
        tracker
            .discharge(
                "AX-1",
                "formal/VSEL/Foundations/Transition.lean",
                "2025-01-15",
                "alice",
            )
            .unwrap();
        let ax1 = tracker.get("AX-1").unwrap();
        assert_eq!(ax1.status, ObligationStatus::Discharged);
        assert_eq!(
            ax1.evidence.as_deref(),
            Some("formal/VSEL/Foundations/Transition.lean")
        );
        assert_eq!(ax1.last_verified.as_deref(), Some("2025-01-15"));
        assert_eq!(ax1.reviewer.as_deref(), Some("alice"));

        // Mark LEM-4 as failed.
        tracker
            .start_work(
                "LEM-4",
                DischargeMethod::Test,
                VerificationTool::RustTest,
                "bob",
            )
            .unwrap();
        tracker
            .mark_failed("LEM-4", "test failure log", "2025-01-16", "bob")
            .unwrap();
        assert_eq!(
            tracker.get("LEM-4").unwrap().status,
            ObligationStatus::Failed
        );

        // Reset LEM-4.
        tracker.reset("LEM-4").unwrap();
        assert_eq!(
            tracker.get("LEM-4").unwrap().status,
            ObligationStatus::Unresolved
        );
    }

    #[test]
    fn test_status_summary() {
        let matrix = build_traceability_matrix();
        let mut tracker = build_obligation_tracker(&matrix);

        let summary = tracker.status_summary();
        assert_eq!(summary.total, 46);
        assert_eq!(summary.unresolved, 46);
        assert_eq!(summary.discharged, 0);

        tracker
            .discharge("AX-1", "evidence", "2025-01-15", "alice")
            .unwrap();
        tracker
            .start_work(
                "AX-2",
                DischargeMethod::ModelCheck,
                VerificationTool::TlaPlus,
                "bob",
            )
            .unwrap();

        let summary = tracker.status_summary();
        assert_eq!(summary.discharged, 1);
        assert_eq!(summary.in_progress, 1);
        assert_eq!(summary.unresolved, 44);
    }

    #[test]
    fn test_by_category() {
        let matrix = build_traceability_matrix();
        let tracker = build_obligation_tracker(&matrix);

        // AX-1..AX-3 are Axiom; AX-4..AX-6 are External.
        assert_eq!(tracker.by_category(ObligationCategory::Axiom).len(), 3);
        assert_eq!(tracker.by_category(ObligationCategory::External).len(), 3);
        assert_eq!(tracker.by_category(ObligationCategory::Definition).len(), 6);
        assert_eq!(tracker.by_category(ObligationCategory::Lemma).len(), 10);
        assert_eq!(tracker.by_category(ObligationCategory::Safety).len(), 6);
        assert_eq!(tracker.by_category(ObligationCategory::Liveness).len(), 2);
        assert_eq!(tracker.by_category(ObligationCategory::Constraint).len(), 4);
        assert_eq!(tracker.by_category(ObligationCategory::Proof).len(), 4);
        assert_eq!(
            tracker.by_category(ObligationCategory::Composition).len(),
            3
        );
        assert_eq!(tracker.by_category(ObligationCategory::Economic).len(), 5);
    }

    #[test]
    fn test_outstanding_and_all_discharged() {
        let matrix = build_traceability_matrix();
        let mut tracker = build_obligation_tracker(&matrix);

        assert!(!tracker.all_discharged());
        assert_eq!(tracker.outstanding().len(), 46);

        // Collect IDs first to avoid borrow conflict.
        let ids: Vec<String> = tracker
            .obligation_ids()
            .iter()
            .map(|s| s.to_string())
            .collect();

        // Discharge all.
        for id in &ids {
            tracker
                .discharge(id, "evidence", "2025-01-15", "reviewer")
                .unwrap();
        }

        assert!(tracker.all_discharged());
        assert_eq!(tracker.outstanding().len(), 0);
    }

    #[test]
    fn test_error_on_unknown_obligation() {
        let mut tracker = ObligationTracker::new();
        assert_eq!(
            tracker.start_work(
                "NONEXISTENT",
                DischargeMethod::Test,
                VerificationTool::RustTest,
                "x"
            ),
            Err(TrackerError::ObligationNotFound("NONEXISTENT".to_string()))
        );
        assert_eq!(
            tracker.discharge("NONEXISTENT", "e", "d", "r"),
            Err(TrackerError::ObligationNotFound("NONEXISTENT".to_string()))
        );
    }

    #[test]
    fn test_all_obligations_have_statements() {
        let matrix = build_traceability_matrix();
        let tracker = build_obligation_tracker(&matrix);

        for obl in tracker.all() {
            assert!(
                !obl.statement.is_empty(),
                "Obligation '{}' has no statement",
                obl.obligation_id
            );
        }
    }

    #[test]
    fn test_all_obligations_have_falsification_targets() {
        let matrix = build_traceability_matrix();
        let tracker = build_obligation_tracker(&matrix);

        for obl in tracker.all() {
            assert!(
                !obl.falsification_target.is_empty(),
                "Obligation '{}' has no falsification target",
                obl.obligation_id
            );
        }
    }

    #[test]
    fn test_axioms_have_no_dependencies() {
        let matrix = build_traceability_matrix();
        let tracker = build_obligation_tracker(&matrix);

        for i in 1..=6 {
            let obl = tracker.get(&format!("AX-{}", i)).unwrap();
            assert!(
                obl.dependencies.is_empty(),
                "AX-{} should have no dependencies, found {:?}",
                i,
                obl.dependencies
            );
        }
    }

    #[test]
    fn test_downstream_obligations_have_dependencies() {
        let matrix = build_traceability_matrix();
        let tracker = build_obligation_tracker(&matrix);

        // LEM-1 depends on AX-1 and AX-2.
        let lem1 = tracker.get("LEM-1").unwrap();
        assert!(lem1.dependencies.contains(&"AX-1".to_string()));
        assert!(lem1.dependencies.contains(&"AX-2".to_string()));

        // SAFE-1 depends on LEM-1 and LEM-2.
        let safe1 = tracker.get("SAFE-1").unwrap();
        assert!(safe1.dependencies.contains(&"LEM-1".to_string()));
        assert!(safe1.dependencies.contains(&"LEM-2".to_string()));

        // PROOF-4 depends on AX-4 and LEM-6.
        let proof4 = tracker.get("PROOF-4").unwrap();
        assert!(proof4.dependencies.contains(&"AX-4".to_string()));
        assert!(proof4.dependencies.contains(&"LEM-6".to_string()));
    }
}
