//! Compliance evidence chains — linked, tamper-evident evidence artifacts.
//!
//! Implements the full verification pipeline as a chain of evidence:
//!   Execution → Trace → Proof → Verification → Attestation
//!
//! Each link in the chain:
//! - References the previous link's hash (tamper-evident chaining)
//! - Has a timestamp and signer identity
//! - Has an explicit validity period (start/end timestamps)
//! - Is committed via SHA3-256 hash
//!
//! Evidence validity periods exceed regulatory retention requirements
//! (minimum 7 years, configurable).
//!
//! Requirements: 16.9, 16.10

use crate::evidence::EvidenceHash;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Minimum regulatory retention period in seconds (7 years).
///
/// Requirement 16.10: evidence validity periods exceeding regulatory
/// retention requirements. 7 years ≈ 220,752,000 seconds.
pub const MIN_RETENTION_SECS: u64 = 7 * 365 * 24 * 3600;

/// Default validity period in seconds (10 years).
///
/// Exceeds the 7-year minimum to provide margin.
pub const DEFAULT_VALIDITY_SECS: u64 = 10 * 365 * 24 * 3600;

// ---------------------------------------------------------------------------
// Evidence chain stage
// ---------------------------------------------------------------------------

/// Stage in the compliance evidence pipeline.
///
/// The pipeline follows a strict ordering:
///   Execution → Trace → Proof → Verification → Attestation
///
/// Requirement 16.9
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChainStage {
    /// State machine execution result.
    Execution,
    /// Trace recording and commitment.
    Trace,
    /// Proof generation.
    Proof,
    /// Proof verification result.
    Verification,
    /// Final compliance attestation.
    Attestation,
}

impl ChainStage {
    /// Returns the next stage in the pipeline, or `None` if at Attestation.
    pub fn next(self) -> Option<ChainStage> {
        match self {
            ChainStage::Execution => Some(ChainStage::Trace),
            ChainStage::Trace => Some(ChainStage::Proof),
            ChainStage::Proof => Some(ChainStage::Verification),
            ChainStage::Verification => Some(ChainStage::Attestation),
            ChainStage::Attestation => None,
        }
    }

    /// Returns the expected index of this stage in a complete chain.
    pub fn index(self) -> usize {
        match self {
            ChainStage::Execution => 0,
            ChainStage::Trace => 1,
            ChainStage::Proof => 2,
            ChainStage::Verification => 3,
            ChainStage::Attestation => 4,
        }
    }

    /// All stages in pipeline order.
    pub fn all() -> &'static [ChainStage] {
        &[
            ChainStage::Execution,
            ChainStage::Trace,
            ChainStage::Proof,
            ChainStage::Verification,
            ChainStage::Attestation,
        ]
    }
}

impl std::fmt::Display for ChainStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainStage::Execution => write!(f, "Execution"),
            ChainStage::Trace => write!(f, "Trace"),
            ChainStage::Proof => write!(f, "Proof"),
            ChainStage::Verification => write!(f, "Verification"),
            ChainStage::Attestation => write!(f, "Attestation"),
        }
    }
}

// ---------------------------------------------------------------------------
// Validity period
// ---------------------------------------------------------------------------

/// Explicit validity period for evidence artifacts.
///
/// Requirement 16.10: evidence validity periods exceeding regulatory
/// retention requirements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidityPeriod {
    /// Start of validity (Unix timestamp, seconds since epoch).
    pub not_before: u64,
    /// End of validity (Unix timestamp, seconds since epoch).
    pub not_after: u64,
}

impl ValidityPeriod {
    /// Create a validity period from explicit start and end timestamps.
    ///
    /// Returns `None` if `not_after <= not_before`.
    pub fn new(not_before: u64, not_after: u64) -> Option<Self> {
        if not_after > not_before {
            Some(Self {
                not_before,
                not_after,
            })
        } else {
            None
        }
    }

    /// Create a validity period starting at `start` with the default
    /// duration (10 years), exceeding the 7-year regulatory minimum.
    pub fn with_default_duration(start: u64) -> Self {
        Self {
            not_before: start,
            not_after: start + DEFAULT_VALIDITY_SECS,
        }
    }

    /// Create a validity period starting at `start` with a custom
    /// duration in seconds.
    ///
    /// Returns `None` if `duration_secs` is zero.
    pub fn with_duration(start: u64, duration_secs: u64) -> Option<Self> {
        if duration_secs == 0 {
            return None;
        }
        Some(Self {
            not_before: start,
            not_after: start + duration_secs,
        })
    }

    /// Duration of the validity period in seconds.
    pub fn duration_secs(&self) -> u64 {
        self.not_after - self.not_before
    }

    /// Returns `true` if this validity period meets or exceeds the
    /// minimum regulatory retention requirement.
    ///
    /// Requirement 16.10
    pub fn meets_retention_requirement(&self) -> bool {
        self.duration_secs() >= MIN_RETENTION_SECS
    }

    /// Returns `true` if the given timestamp falls within this validity
    /// period (inclusive of `not_before`, exclusive of `not_after`).
    pub fn is_valid_at(&self, timestamp: u64) -> bool {
        timestamp >= self.not_before && timestamp < self.not_after
    }
}

// ---------------------------------------------------------------------------
// Chain link
// ---------------------------------------------------------------------------

/// A single link in the compliance evidence chain.
///
/// Each link represents one stage of the verification pipeline and
/// references the previous link's hash to form a tamper-evident chain.
///
/// Requirement 16.9: timestamped, signed, and committed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainLink {
    /// Stage in the pipeline.
    pub stage: ChainStage,
    /// Description of the evidence at this stage.
    pub description: String,
    /// Reference to the evidence artifact (file path, ID, etc.).
    pub artifact_ref: String,
    /// Unix timestamp when this link was created.
    pub timestamp: u64,
    /// Identity of the signer (e.g., auditor name, key fingerprint).
    pub signer: String,
    /// Validity period for this evidence link.
    pub validity: ValidityPeriod,
    /// Hash of the previous link (`None` for the first link).
    pub prev_hash: Option<EvidenceHash>,
    /// Commitment hash of this link (computed on finalization).
    commitment: Option<EvidenceHash>,
}

impl ChainLink {
    /// Create a new chain link. The link is uncommitted until the chain
    /// is built.
    pub fn new(
        stage: ChainStage,
        description: impl Into<String>,
        artifact_ref: impl Into<String>,
        timestamp: u64,
        signer: impl Into<String>,
        validity: ValidityPeriod,
    ) -> Self {
        Self {
            stage,
            description: description.into(),
            artifact_ref: artifact_ref.into(),
            timestamp,
            signer: signer.into(),
            validity,
            prev_hash: None,
            commitment: None,
        }
    }

    /// Returns the commitment hash, or `None` if not yet committed.
    pub fn commitment(&self) -> Option<&EvidenceHash> {
        self.commitment.as_ref()
    }

    /// Returns `true` if this link has been committed.
    pub fn is_committed(&self) -> bool {
        self.commitment.is_some()
    }

    /// Compute the commitment hash over the canonical content of this link.
    fn commit(&mut self) {
        let canonical = self.canonical_bytes();
        self.commitment = Some(EvidenceHash::compute(&canonical));
    }

    /// Verify that the commitment hash matches the current content.
    pub fn verify_integrity(&self) -> bool {
        match &self.commitment {
            Some(stored) => {
                let recomputed = EvidenceHash::compute(&self.canonical_bytes());
                *stored == recomputed
            }
            None => false,
        }
    }

    /// Produce a deterministic byte representation for hashing.
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // Stage
        buf.push(self.stage as u8);
        // Description
        let desc_bytes = self.description.as_bytes();
        buf.extend_from_slice(&(desc_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(desc_bytes);
        // Artifact reference
        let art_bytes = self.artifact_ref.as_bytes();
        buf.extend_from_slice(&(art_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(art_bytes);
        // Timestamp
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        // Signer
        let signer_bytes = self.signer.as_bytes();
        buf.extend_from_slice(&(signer_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(signer_bytes);
        // Validity period
        buf.extend_from_slice(&self.validity.not_before.to_le_bytes());
        buf.extend_from_slice(&self.validity.not_after.to_le_bytes());
        // Previous hash
        match &self.prev_hash {
            Some(h) => {
                buf.push(1);
                buf.extend_from_slice(&h.0);
            }
            None => {
                buf.push(0);
            }
        }
        buf
    }
}

// ---------------------------------------------------------------------------
// Compliance evidence chain
// ---------------------------------------------------------------------------

/// Errors from the evidence chain system.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    /// Chain is empty — no links to verify.
    #[error("evidence chain is empty")]
    EmptyChain,

    /// Chain is incomplete — missing one or more required stages.
    #[error("evidence chain is incomplete: missing stage {0}")]
    IncompleteChain(ChainStage),

    /// Stage ordering violation — links are not in pipeline order.
    #[error("stage ordering violation: expected {expected}, got {actual}")]
    StageOrderViolation {
        expected: ChainStage,
        actual: ChainStage,
    },

    /// Duplicate stage in the chain.
    #[error("duplicate stage in chain: {0}")]
    DuplicateStage(ChainStage),

    /// Hash chain integrity failure at the given stage.
    #[error("hash chain integrity failure at stage {0}")]
    IntegrityFailure(ChainStage),

    /// Validity period does not meet regulatory retention requirements.
    #[error("validity period at stage {stage} is {actual_secs}s, minimum is {min_secs}s")]
    InsufficientRetention {
        stage: ChainStage,
        actual_secs: u64,
        min_secs: u64,
    },

    /// Timestamp ordering violation — a link's timestamp is before the
    /// previous link's timestamp.
    #[error(
        "timestamp ordering violation at stage {stage}: {timestamp} < previous {prev_timestamp}"
    )]
    TimestampOrderViolation {
        stage: ChainStage,
        timestamp: u64,
        prev_timestamp: u64,
    },
}

/// A complete compliance evidence chain.
///
/// Represents the full verification pipeline as a linked, tamper-evident
/// chain of evidence artifacts:
///   Execution → Trace → Proof → Verification → Attestation
///
/// Each link references the previous link's hash, forming a chain
/// similar to trace commitment chaining. The chain is immutable once
/// built.
///
/// Requirements: 16.9, 16.10
#[derive(Clone, Debug)]
pub struct ComplianceEvidenceChain {
    /// Unique identifier for this chain.
    pub id: String,
    /// The ordered links in the chain.
    links: Vec<ChainLink>,
}

impl ComplianceEvidenceChain {
    /// Returns the links in the chain.
    pub fn links(&self) -> &[ChainLink] {
        &self.links
    }

    /// Returns the number of links in the chain.
    pub fn len(&self) -> usize {
        self.links.len()
    }

    /// Returns `true` if the chain has no links.
    pub fn is_empty(&self) -> bool {
        self.links.is_empty()
    }

    /// Returns `true` if the chain contains all five stages.
    pub fn is_complete(&self) -> bool {
        self.links.len() == 5
            && self
                .links
                .iter()
                .enumerate()
                .all(|(i, link)| link.stage.index() == i)
    }

    /// Get the link for a specific stage.
    pub fn get_stage(&self, stage: ChainStage) -> Option<&ChainLink> {
        self.links.iter().find(|l| l.stage == stage)
    }

    /// Returns the final commitment hash (the attestation link's hash),
    /// which serves as the chain's root commitment.
    pub fn root_commitment(&self) -> Option<&EvidenceHash> {
        self.links.last().and_then(|l| l.commitment())
    }

    /// Verify the integrity of the entire chain.
    ///
    /// Checks:
    /// 1. All links are committed and their hashes are valid.
    /// 2. Each link's `prev_hash` matches the previous link's commitment.
    /// 3. Stages are in correct pipeline order.
    /// 4. Timestamps are monotonically non-decreasing.
    /// 5. All validity periods meet regulatory retention requirements.
    ///
    /// Requirements: 16.9, 16.10
    pub fn verify(&self) -> Result<(), ChainError> {
        if self.links.is_empty() {
            return Err(ChainError::EmptyChain);
        }

        let mut prev_commitment: Option<&EvidenceHash> = None;
        let mut prev_timestamp: Option<u64> = None;

        for (i, link) in self.links.iter().enumerate() {
            // Stage ordering.
            let expected_stage = ChainStage::all()[i];
            if link.stage != expected_stage {
                return Err(ChainError::StageOrderViolation {
                    expected: expected_stage,
                    actual: link.stage,
                });
            }

            // Commitment integrity.
            if !link.verify_integrity() {
                return Err(ChainError::IntegrityFailure(link.stage));
            }

            // Hash chain: first link has no prev_hash, subsequent links
            // must reference the previous link's commitment.
            match (i, &link.prev_hash, prev_commitment) {
                (0, None, _) => { /* OK: genesis link */ }
                (0, Some(_), _) => {
                    return Err(ChainError::IntegrityFailure(link.stage));
                }
                (_, None, _) => {
                    return Err(ChainError::IntegrityFailure(link.stage));
                }
                (_, Some(prev_h), Some(expected)) => {
                    if prev_h != expected {
                        return Err(ChainError::IntegrityFailure(link.stage));
                    }
                }
                (_, Some(_), None) => {
                    return Err(ChainError::IntegrityFailure(link.stage));
                }
            }

            // Timestamp ordering.
            if let Some(prev_ts) = prev_timestamp {
                if link.timestamp < prev_ts {
                    return Err(ChainError::TimestampOrderViolation {
                        stage: link.stage,
                        timestamp: link.timestamp,
                        prev_timestamp: prev_ts,
                    });
                }
            }

            // Validity period meets retention requirement.
            if !link.validity.meets_retention_requirement() {
                return Err(ChainError::InsufficientRetention {
                    stage: link.stage,
                    actual_secs: link.validity.duration_secs(),
                    min_secs: MIN_RETENTION_SECS,
                });
            }

            prev_commitment = link.commitment();
            prev_timestamp = Some(link.timestamp);
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Chain builder
// ---------------------------------------------------------------------------

/// Builder for constructing a compliance evidence chain.
///
/// Links are added in pipeline order. The builder commits each link
/// and chains their hashes automatically.
///
/// Requirement 16.9
#[derive(Debug)]
pub struct ChainBuilder {
    id: String,
    links: Vec<ChainLink>,
}

impl ChainBuilder {
    /// Create a new chain builder with the given chain ID.
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            links: Vec::new(),
        }
    }

    /// Add a link to the chain.
    ///
    /// Links must be added in pipeline order (Execution, Trace, Proof,
    /// Verification, Attestation). The builder automatically sets the
    /// `prev_hash` and commits each link.
    pub fn add_link(mut self, mut link: ChainLink) -> Result<Self, ChainError> {
        let expected_index = self.links.len();
        if expected_index >= ChainStage::all().len() {
            return Err(ChainError::DuplicateStage(link.stage));
        }

        let expected_stage = ChainStage::all()[expected_index];
        if link.stage != expected_stage {
            return Err(ChainError::StageOrderViolation {
                expected: expected_stage,
                actual: link.stage,
            });
        }

        // Check timestamp ordering.
        if let Some(prev) = self.links.last() {
            if link.timestamp < prev.timestamp {
                return Err(ChainError::TimestampOrderViolation {
                    stage: link.stage,
                    timestamp: link.timestamp,
                    prev_timestamp: prev.timestamp,
                });
            }
        }

        // Set prev_hash from the last committed link.
        link.prev_hash = self.links.last().and_then(|l| l.commitment().cloned());

        // Commit this link.
        link.commit();

        self.links.push(link);
        Ok(self)
    }

    /// Build the final chain.
    ///
    /// The chain does not need to be complete (all 5 stages) to build,
    /// but `verify()` on an incomplete chain will still validate what
    /// exists.
    pub fn build(self) -> ComplianceEvidenceChain {
        ComplianceEvidenceChain {
            id: self.id,
            links: self.links,
        }
    }

    /// Build a complete chain, returning an error if any stage is missing.
    pub fn build_complete(self) -> Result<ComplianceEvidenceChain, ChainError> {
        if self.links.len() < 5 {
            let missing_index = self.links.len();
            return Err(ChainError::IncompleteChain(
                ChainStage::all()[missing_index],
            ));
        }
        Ok(self.build())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Helpers -------------------------------------------------------------

    const BASE_TS: u64 = 1_700_000_000;

    fn default_validity(ts: u64) -> ValidityPeriod {
        ValidityPeriod::with_default_duration(ts)
    }

    fn make_link(stage: ChainStage, ts: u64) -> ChainLink {
        ChainLink::new(
            stage,
            format!("{} evidence", stage),
            format!("artifact/{}", stage),
            ts,
            "auditor-key-0x1234",
            default_validity(ts),
        )
    }

    fn build_full_chain() -> ComplianceEvidenceChain {
        let mut ts = BASE_TS;
        let mut builder = ChainBuilder::new("CEC-001");
        for &stage in ChainStage::all() {
            builder = builder.add_link(make_link(stage, ts)).unwrap();
            ts += 100;
        }
        builder.build_complete().unwrap()
    }

    // -- ChainStage ----------------------------------------------------------

    #[test]
    fn test_stage_ordering() {
        let stages = ChainStage::all();
        assert_eq!(stages.len(), 5);
        assert_eq!(stages[0], ChainStage::Execution);
        assert_eq!(stages[4], ChainStage::Attestation);
    }

    #[test]
    fn test_stage_next() {
        assert_eq!(ChainStage::Execution.next(), Some(ChainStage::Trace));
        assert_eq!(ChainStage::Trace.next(), Some(ChainStage::Proof));
        assert_eq!(ChainStage::Proof.next(), Some(ChainStage::Verification));
        assert_eq!(
            ChainStage::Verification.next(),
            Some(ChainStage::Attestation)
        );
        assert_eq!(ChainStage::Attestation.next(), None);
    }

    #[test]
    fn test_stage_index() {
        for (i, &stage) in ChainStage::all().iter().enumerate() {
            assert_eq!(stage.index(), i);
        }
    }

    #[test]
    fn test_stage_display() {
        assert_eq!(ChainStage::Execution.to_string(), "Execution");
        assert_eq!(ChainStage::Trace.to_string(), "Trace");
        assert_eq!(ChainStage::Proof.to_string(), "Proof");
        assert_eq!(ChainStage::Verification.to_string(), "Verification");
        assert_eq!(ChainStage::Attestation.to_string(), "Attestation");
    }

    // -- ValidityPeriod ------------------------------------------------------

    #[test]
    fn test_validity_period_new() {
        let vp = ValidityPeriod::new(100, 200).unwrap();
        assert_eq!(vp.not_before, 100);
        assert_eq!(vp.not_after, 200);
        assert_eq!(vp.duration_secs(), 100);
    }

    #[test]
    fn test_validity_period_rejects_invalid() {
        assert!(ValidityPeriod::new(200, 100).is_none());
        assert!(ValidityPeriod::new(100, 100).is_none());
    }

    #[test]
    fn test_validity_period_default_duration() {
        let vp = ValidityPeriod::with_default_duration(BASE_TS);
        assert_eq!(vp.not_before, BASE_TS);
        assert_eq!(vp.duration_secs(), DEFAULT_VALIDITY_SECS);
        assert!(vp.meets_retention_requirement());
    }

    #[test]
    fn test_validity_period_custom_duration() {
        let vp = ValidityPeriod::with_duration(BASE_TS, MIN_RETENTION_SECS).unwrap();
        assert!(vp.meets_retention_requirement());

        let short = ValidityPeriod::with_duration(BASE_TS, 1000).unwrap();
        assert!(!short.meets_retention_requirement());
    }

    #[test]
    fn test_validity_period_zero_duration_rejected() {
        assert!(ValidityPeriod::with_duration(BASE_TS, 0).is_none());
    }

    #[test]
    fn test_validity_period_is_valid_at() {
        let vp = ValidityPeriod::new(100, 200).unwrap();
        assert!(!vp.is_valid_at(99));
        assert!(vp.is_valid_at(100));
        assert!(vp.is_valid_at(150));
        assert!(vp.is_valid_at(199));
        assert!(!vp.is_valid_at(200));
    }

    #[test]
    fn test_min_retention_exceeds_seven_years() {
        let seven_years_secs = 7 * 365 * 24 * 3600;
        assert_eq!(MIN_RETENTION_SECS, seven_years_secs);
        assert!(DEFAULT_VALIDITY_SECS > MIN_RETENTION_SECS);
    }

    // -- ChainLink -----------------------------------------------------------

    #[test]
    fn test_link_creation_uncommitted() {
        let link = make_link(ChainStage::Execution, BASE_TS);
        assert!(!link.is_committed());
        assert!(link.commitment().is_none());
        assert!(!link.verify_integrity());
    }

    #[test]
    fn test_link_commit_and_verify() {
        let mut link = make_link(ChainStage::Execution, BASE_TS);
        link.commit();
        assert!(link.is_committed());
        assert!(link.commitment().is_some());
        assert!(link.verify_integrity());
    }

    #[test]
    fn test_link_integrity_fails_on_tamper() {
        let mut link = make_link(ChainStage::Execution, BASE_TS);
        link.commit();
        assert!(link.verify_integrity());

        link.description = "tampered".to_string();
        assert!(!link.verify_integrity());
    }

    #[test]
    fn test_link_hash_deterministic() {
        let mut l1 = make_link(ChainStage::Execution, BASE_TS);
        let mut l2 = make_link(ChainStage::Execution, BASE_TS);
        l1.commit();
        l2.commit();
        assert_eq!(l1.commitment(), l2.commitment());
    }

    #[test]
    fn test_link_hash_differs_by_stage() {
        let mut l1 = make_link(ChainStage::Execution, BASE_TS);
        let mut l2 = make_link(ChainStage::Trace, BASE_TS);
        l1.commit();
        l2.commit();
        assert_ne!(l1.commitment(), l2.commitment());
    }

    // -- ChainBuilder --------------------------------------------------------

    #[test]
    fn test_builder_full_chain() {
        let chain = build_full_chain();
        assert_eq!(chain.len(), 5);
        assert!(chain.is_complete());
        assert!(!chain.is_empty());
    }

    #[test]
    fn test_builder_rejects_wrong_order() {
        let builder = ChainBuilder::new("CEC-ERR");
        let result = builder.add_link(make_link(ChainStage::Trace, BASE_TS));
        assert!(result.is_err());
        match result.unwrap_err() {
            ChainError::StageOrderViolation { expected, actual } => {
                assert_eq!(expected, ChainStage::Execution);
                assert_eq!(actual, ChainStage::Trace);
            }
            e => panic!("unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_builder_rejects_timestamp_regression() {
        let builder = ChainBuilder::new("CEC-ERR")
            .add_link(make_link(ChainStage::Execution, BASE_TS + 1000))
            .unwrap();
        let result = builder.add_link(make_link(ChainStage::Trace, BASE_TS));
        assert!(result.is_err());
        match result.unwrap_err() {
            ChainError::TimestampOrderViolation { stage, .. } => {
                assert_eq!(stage, ChainStage::Trace);
            }
            e => panic!("unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_builder_allows_same_timestamp() {
        let builder = ChainBuilder::new("CEC-SAME-TS")
            .add_link(make_link(ChainStage::Execution, BASE_TS))
            .unwrap();
        // Same timestamp is allowed (non-decreasing).
        let result = builder.add_link(make_link(ChainStage::Trace, BASE_TS));
        assert!(result.is_ok());
    }

    #[test]
    fn test_builder_rejects_duplicate_stage() {
        let mut ts = BASE_TS;
        let mut builder = ChainBuilder::new("CEC-DUP");
        for &stage in ChainStage::all() {
            builder = builder.add_link(make_link(stage, ts)).unwrap();
            ts += 100;
        }
        // Adding a 6th link should fail.
        let result = builder.add_link(make_link(ChainStage::Execution, ts));
        assert!(result.is_err());
    }

    #[test]
    fn test_builder_build_incomplete() {
        let builder = ChainBuilder::new("CEC-PARTIAL")
            .add_link(make_link(ChainStage::Execution, BASE_TS))
            .unwrap();
        // build() succeeds for partial chains.
        let chain = builder.build();
        assert_eq!(chain.len(), 1);
        assert!(!chain.is_complete());
    }

    #[test]
    fn test_builder_build_complete_rejects_incomplete() {
        let builder = ChainBuilder::new("CEC-PARTIAL")
            .add_link(make_link(ChainStage::Execution, BASE_TS))
            .unwrap();
        let result = builder.build_complete();
        assert!(result.is_err());
        match result.unwrap_err() {
            ChainError::IncompleteChain(stage) => {
                assert_eq!(stage, ChainStage::Trace);
            }
            e => panic!("unexpected error: {:?}", e),
        }
    }

    // -- Chain verification --------------------------------------------------

    #[test]
    fn test_verify_full_chain() {
        let chain = build_full_chain();
        assert!(chain.verify().is_ok());
    }

    #[test]
    fn test_verify_empty_chain() {
        let chain = ComplianceEvidenceChain {
            id: "CEC-EMPTY".to_string(),
            links: vec![],
        };
        assert_eq!(chain.verify().unwrap_err(), ChainError::EmptyChain);
    }

    #[test]
    fn test_verify_detects_tampered_link() {
        let mut chain = build_full_chain();
        // Tamper with the second link's description.
        chain.links[1].description = "tampered".to_string();
        let err = chain.verify().unwrap_err();
        assert_eq!(err, ChainError::IntegrityFailure(ChainStage::Trace));
    }

    #[test]
    fn test_verify_detects_broken_hash_chain() {
        let mut chain = build_full_chain();
        // Replace the prev_hash of the third link with garbage.
        chain.links[2].prev_hash = Some(EvidenceHash::compute(b"garbage"));
        // Re-commit so the link's own integrity passes, but the chain
        // link is broken.
        chain.links[2].commit();
        let err = chain.verify().unwrap_err();
        assert_eq!(err, ChainError::IntegrityFailure(ChainStage::Proof));
    }

    #[test]
    fn test_verify_detects_insufficient_retention() {
        // Build a chain where one link has a short validity period.
        let short_validity = ValidityPeriod::with_duration(BASE_TS, 1000).unwrap();
        let mut link = ChainLink::new(
            ChainStage::Execution,
            "exec evidence",
            "artifact/exec",
            BASE_TS,
            "auditor",
            short_validity,
        );
        link.commit();

        let chain = ComplianceEvidenceChain {
            id: "CEC-SHORT".to_string(),
            links: vec![link],
        };

        let err = chain.verify().unwrap_err();
        match err {
            ChainError::InsufficientRetention { stage, .. } => {
                assert_eq!(stage, ChainStage::Execution);
            }
            e => panic!("unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_chain_hash_chaining() {
        let chain = build_full_chain();
        let links = chain.links();

        // First link has no prev_hash.
        assert!(links[0].prev_hash.is_none());

        // Each subsequent link's prev_hash matches the previous commitment.
        for i in 1..links.len() {
            assert_eq!(
                links[i].prev_hash.as_ref(),
                links[i - 1].commitment(),
                "prev_hash mismatch at stage {}",
                links[i].stage
            );
        }
    }

    #[test]
    fn test_chain_all_links_committed() {
        let chain = build_full_chain();
        for link in chain.links() {
            assert!(link.is_committed(), "link at {} not committed", link.stage);
            assert!(
                link.verify_integrity(),
                "link at {} fails integrity",
                link.stage
            );
        }
    }

    #[test]
    fn test_chain_root_commitment() {
        let chain = build_full_chain();
        let root = chain.root_commitment().unwrap();
        // Root commitment is the attestation link's hash.
        let attestation = chain.get_stage(ChainStage::Attestation).unwrap();
        assert_eq!(Some(root), attestation.commitment());
    }

    #[test]
    fn test_chain_get_stage() {
        let chain = build_full_chain();
        for &stage in ChainStage::all() {
            let link = chain.get_stage(stage).unwrap();
            assert_eq!(link.stage, stage);
        }
    }

    #[test]
    fn test_chain_all_validity_periods_meet_retention() {
        let chain = build_full_chain();
        for link in chain.links() {
            assert!(
                link.validity.meets_retention_requirement(),
                "validity at {} does not meet retention",
                link.stage
            );
        }
    }

    #[test]
    fn test_chain_timestamps_monotonic() {
        let chain = build_full_chain();
        let links = chain.links();
        for i in 1..links.len() {
            assert!(
                links[i].timestamp >= links[i - 1].timestamp,
                "timestamp regression at stage {}",
                links[i].stage
            );
        }
    }

    #[test]
    fn test_chain_signers_present() {
        let chain = build_full_chain();
        for link in chain.links() {
            assert!(
                !link.signer.is_empty(),
                "signer missing at stage {}",
                link.stage
            );
        }
    }

    // -- Partial chain -------------------------------------------------------

    #[test]
    fn test_partial_chain_verifies() {
        // A partial chain (just Execution) should verify if it meets
        // all per-link requirements.
        let builder = ChainBuilder::new("CEC-PARTIAL")
            .add_link(make_link(ChainStage::Execution, BASE_TS))
            .unwrap();
        let chain = builder.build();
        assert!(chain.verify().is_ok());
        assert!(!chain.is_complete());
    }

    // -- Error display -------------------------------------------------------

    #[test]
    fn test_error_display() {
        let err = ChainError::EmptyChain;
        assert_eq!(err.to_string(), "evidence chain is empty");

        let err = ChainError::IncompleteChain(ChainStage::Proof);
        assert_eq!(
            err.to_string(),
            "evidence chain is incomplete: missing stage Proof"
        );

        let err = ChainError::IntegrityFailure(ChainStage::Trace);
        assert_eq!(
            err.to_string(),
            "hash chain integrity failure at stage Trace"
        );
    }
}
