//! Traceability matrix data model.
//!
//! The matrix maps the complete derivation chain:
//!   L0 (Lean 4 invariant) → L1 (SIR/IR construct) → L2 (Rust transition)
//!   → L3 (constraint ID) → L4 (proof obligation) → NIST control
//!
//! Requirements: 16.1, 16.8

use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Layer identifiers
// ---------------------------------------------------------------------------

/// Abstraction layer in the VSEL derivation chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Layer {
    /// L0 — Lean 4 formal specification (source of truth).
    L0Formal,
    /// L1 — SIR/IR semantic intermediate representation.
    L1Sir,
    /// L2 — Rust concrete execution (state machine transitions).
    L2Rust,
    /// L3 — Constraint system (compiled from SIR/IR).
    L3Constraint,
    /// L4 — Proof system (proof obligations).
    L4Proof,
    /// NIST — Compliance controls (SSDF SP 800-218, CSF).
    Nist,
}

impl std::fmt::Display for Layer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Layer::L0Formal => write!(f, "L0-Formal"),
            Layer::L1Sir => write!(f, "L1-SIR/IR"),
            Layer::L2Rust => write!(f, "L2-Rust"),
            Layer::L3Constraint => write!(f, "L3-Constraint"),
            Layer::L4Proof => write!(f, "L4-Proof"),
            Layer::Nist => write!(f, "NIST"),
        }
    }
}

// ---------------------------------------------------------------------------
// Invariant category
// ---------------------------------------------------------------------------

/// Category of a formal invariant (mirrors vsel-invariants).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InvariantCategory {
    Local,
    Global,
    Temporal,
    EconomicLocal,
    EconomicGlobal,
    EconomicTemporal,
    EconomicCompositional,
    CrossLayer,
}

impl std::fmt::Display for InvariantCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InvariantCategory::Local => write!(f, "Local"),
            InvariantCategory::Global => write!(f, "Global"),
            InvariantCategory::Temporal => write!(f, "Temporal"),
            InvariantCategory::EconomicLocal => write!(f, "Economic-Local"),
            InvariantCategory::EconomicGlobal => write!(f, "Economic-Global"),
            InvariantCategory::EconomicTemporal => write!(f, "Economic-Temporal"),
            InvariantCategory::EconomicCompositional => write!(f, "Economic-Compositional"),
            InvariantCategory::CrossLayer => write!(f, "Cross-Layer"),
        }
    }
}

// ---------------------------------------------------------------------------
// Traceability entry — one row in the matrix
// ---------------------------------------------------------------------------

/// A single row in the traceability matrix.
///
/// Maps one L0 invariant through all layers to NIST controls.
/// Any missing link is a gap (Requirement 16.8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceabilityEntry {
    /// L0: Lean 4 invariant identifier (e.g., "L_valid", "G_struct").
    pub l0_invariant_id: String,
    /// Category of the invariant.
    pub category: InvariantCategory,
    /// L0: Lean 4 source file and definition name.
    pub l0_lean_source: String,
    /// L1: SIR/IR construct(s) that encode this invariant.
    pub l1_sir_constructs: Vec<String>,
    /// L2: Rust module(s) and function(s) that enforce this invariant.
    pub l2_rust_modules: Vec<String>,
    /// L2: Transition classes where this invariant is checked.
    pub l2_transition_classes: Vec<String>,
    /// L3: Constraint IDs that encode this invariant.
    pub l3_constraint_ids: Vec<String>,
    /// L4: Proof obligation IDs that depend on this invariant.
    pub l4_proof_obligations: Vec<String>,
    /// NIST: Control identifiers (SSDF + CSF) this invariant supports.
    pub nist_controls: Vec<String>,
}

// ---------------------------------------------------------------------------
// Gap finding
// ---------------------------------------------------------------------------

/// Type of traceability gap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum GapType {
    /// Invariant has no SIR/IR construct mapping.
    MissingSirMapping,
    /// Invariant has no Rust enforcement.
    MissingRustEnforcement,
    /// Invariant has no constraint encoding.
    MissingConstraint,
    /// Invariant has no proof obligation.
    MissingProofObligation,
    /// Invariant has no NIST control mapping.
    MissingNistControl,
    /// Constraint exists without a proof obligation.
    ConstraintWithoutObligation,
    /// Proof obligation exists without a constraint.
    ObligationWithoutConstraint,
}

impl std::fmt::Display for GapType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GapType::MissingSirMapping => write!(f, "Missing SIR/IR mapping"),
            GapType::MissingRustEnforcement => write!(f, "Missing Rust enforcement"),
            GapType::MissingConstraint => write!(f, "Missing constraint"),
            GapType::MissingProofObligation => write!(f, "Missing proof obligation"),
            GapType::MissingNistControl => write!(f, "Missing NIST control"),
            GapType::ConstraintWithoutObligation => {
                write!(f, "Constraint without proof obligation")
            }
            GapType::ObligationWithoutConstraint => {
                write!(f, "Proof obligation without constraint")
            }
        }
    }
}

/// A traceability gap — a broken link in the derivation chain.
///
/// Requirement 16.8: broken links must be flagged for resolution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceabilityGap {
    /// The invariant or artifact with the broken link.
    pub artifact_id: String,
    /// Type of gap.
    pub gap_type: GapType,
    /// The layer where the link is broken.
    pub broken_at: Layer,
    /// Human-readable description.
    pub description: String,
}

// ---------------------------------------------------------------------------
// Traceability matrix
// ---------------------------------------------------------------------------

/// The complete traceability matrix.
///
/// Maps L0 Lean 4 invariants through all layers to NIST controls.
/// Requirement 16.1: full derivation chain mapping.
/// Requirement 16.8: no broken links.
#[derive(Clone, Debug)]
pub struct TraceabilityMatrix {
    /// All traceability entries, keyed by L0 invariant ID.
    pub entries: BTreeMap<String, TraceabilityEntry>,
    /// Standalone proof obligations not directly tied to a single invariant.
    pub proof_obligations: BTreeMap<String, ProofObligationEntry>,
}

/// A proof obligation entry in the traceability matrix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofObligationEntry {
    /// Obligation ID (e.g., "AX-1", "LEM-4", "CONST-1").
    pub obligation_id: String,
    /// Obligation category.
    pub category: ObligationCategory,
    /// Layer where this obligation lives.
    pub layer: Layer,
    /// Constraint IDs that support this obligation.
    pub constraint_ids: Vec<String>,
    /// Invariant IDs this obligation depends on.
    pub invariant_dependencies: Vec<String>,
    /// NIST controls this obligation supports.
    pub nist_controls: Vec<String>,
}

/// Proof obligation category (mirrors PROOF_OBLIGATIONS.md §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObligationCategory {
    Axiom,
    Definition,
    Lemma,
    Safety,
    Liveness,
    External,
    Constraint,
    Proof,
    Economic,
    Composition,
}

impl std::fmt::Display for ObligationCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ObligationCategory::Axiom => write!(f, "Axiom"),
            ObligationCategory::Definition => write!(f, "Definition"),
            ObligationCategory::Lemma => write!(f, "Lemma"),
            ObligationCategory::Safety => write!(f, "Safety"),
            ObligationCategory::Liveness => write!(f, "Liveness"),
            ObligationCategory::External => write!(f, "External"),
            ObligationCategory::Constraint => write!(f, "Constraint"),
            ObligationCategory::Proof => write!(f, "Proof"),
            ObligationCategory::Economic => write!(f, "Economic"),
            ObligationCategory::Composition => write!(f, "Composition"),
        }
    }
}

impl TraceabilityMatrix {
    /// Create a new empty traceability matrix.
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            proof_obligations: BTreeMap::new(),
        }
    }

    /// Add a traceability entry.
    pub fn add_entry(&mut self, entry: TraceabilityEntry) {
        self.entries.insert(entry.l0_invariant_id.clone(), entry);
    }

    /// Add a proof obligation entry.
    pub fn add_obligation(&mut self, entry: ProofObligationEntry) {
        self.proof_obligations
            .insert(entry.obligation_id.clone(), entry);
    }

    /// Count total entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Count total proof obligations.
    pub fn obligation_count(&self) -> usize {
        self.proof_obligations.len()
    }

    /// Get all invariant IDs.
    pub fn invariant_ids(&self) -> Vec<&str> {
        self.entries.keys().map(|s| s.as_str()).collect()
    }

    /// Get all proof obligation IDs.
    pub fn obligation_ids(&self) -> Vec<&str> {
        self.proof_obligations.keys().map(|s| s.as_str()).collect()
    }

    /// Look up an entry by invariant ID.
    pub fn get_entry(&self, invariant_id: &str) -> Option<&TraceabilityEntry> {
        self.entries.get(invariant_id)
    }

    /// Look up a proof obligation by ID.
    pub fn get_obligation(&self, obligation_id: &str) -> Option<&ProofObligationEntry> {
        self.proof_obligations.get(obligation_id)
    }
}

impl Default for TraceabilityMatrix {
    fn default() -> Self {
        Self::new()
    }
}
