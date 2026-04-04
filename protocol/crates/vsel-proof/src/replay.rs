//! Replay resistance for the VSEL proof system.
//!
//! Derived from: THREAT_MODEL.md (temporal attacks), Requirement 18.2.
//!
//! Prevents:
//! - Proof reuse across contexts (domain binding)
//! - Proof replay (duplicate commitment tracking)
//! - Stale proof acceptance (time-window validation)
//!
//! The `ReplayGuard` tracks seen proof commitments and rejects duplicates,
//! enforces time-based consistency, and validates domain binding.

use std::collections::BTreeSet;

use vsel_core::types::{DomainTag, Hash};
use vsel_crypto::domain::proof_tag;

use crate::prover::Proof;

// ---------------------------------------------------------------------------
// ReplayRejection — reasons a proof may be rejected as a replay
// ---------------------------------------------------------------------------

/// Reasons a proof may be rejected by the replay guard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplayRejection {
    /// The proof's trace commitment has already been accepted.
    DuplicateCommitment,
    /// The proof's timestamp is too old relative to the reference timestamp.
    ProofTooOld,
    /// The proof's timestamp is in the future relative to the reference timestamp.
    ProofInFuture,
    /// The proof's domain does not match the expected domain.
    DomainMismatch,
}

// ---------------------------------------------------------------------------
// ReplayGuard — tracks seen proof commitments and prevents reuse
// ---------------------------------------------------------------------------

/// ReplayGuard — tracks seen proof commitments and prevents reuse.
///
/// Enforces three replay resistance properties:
/// 1. **Duplicate detection**: A proof whose trace commitment has already
///    been accepted is rejected.
/// 2. **Time-window validation**: A proof whose timestamp falls outside
///    `[reference_timestamp - max_proof_age_secs, reference_timestamp]`
///    is rejected.
/// 3. **Domain binding**: A proof whose metadata domain does not match
///    the expected proof domain tag is rejected.
///
/// Requirement 18.2: defend against temporal attacks.
pub struct ReplayGuard {
    /// Set of seen trace commitments (from accepted proofs).
    seen_commitments: BTreeSet<Hash>,
    /// Maximum age (in seconds) for a proof to be accepted.
    max_proof_age_secs: u64,
    /// Current reference timestamp for time-based validation.
    reference_timestamp: u64,
    /// Expected domain tag — proofs from other domains are rejected.
    expected_domain: DomainTag,
}

impl ReplayGuard {
    /// Create a new `ReplayGuard`.
    ///
    /// - `expected_domain`: the domain tag that all accepted proofs must match.
    /// - `max_proof_age_secs`: maximum age in seconds for a proof to be valid.
    /// - `reference_timestamp`: the current reference time (unix epoch seconds).
    pub fn new(
        expected_domain: DomainTag,
        max_proof_age_secs: u64,
        reference_timestamp: u64,
    ) -> Self {
        Self {
            seen_commitments: BTreeSet::new(),
            max_proof_age_secs,
            reference_timestamp,
            expected_domain,
        }
    }

    /// Check whether a proof is a replay.
    ///
    /// Returns `Ok(())` if the proof passes all replay checks, or
    /// `Err(ReplayRejection)` with the specific rejection reason.
    ///
    /// Checks (in order):
    /// 1. Domain binding — proof metadata domain must match expected domain.
    /// 2. Duplicate detection — trace commitment must not have been seen before.
    /// 3. Time-window validation — proof timestamp must be within bounds.
    pub fn check_proof(&self, proof: &Proof) -> Result<(), ReplayRejection> {
        // 1. Domain binding
        let expected_proof_domain = proof_tag();
        if proof.metadata.domain != expected_proof_domain {
            return Err(ReplayRejection::DomainMismatch);
        }
        if proof.public_inputs.domain != self.expected_domain {
            return Err(ReplayRejection::DomainMismatch);
        }

        // 2. Duplicate detection
        if self.is_duplicate(&proof.commitments.trace_commitment) {
            return Err(ReplayRejection::DuplicateCommitment);
        }

        // 3. Time-window validation
        let ts = proof.metadata.timestamp;
        if ts > self.reference_timestamp {
            return Err(ReplayRejection::ProofInFuture);
        }
        if self.reference_timestamp.saturating_sub(ts) > self.max_proof_age_secs {
            return Err(ReplayRejection::ProofTooOld);
        }

        Ok(())
    }

    /// Record a proof's trace commitment as seen.
    ///
    /// Call this after a proof has been verified and accepted.
    /// Subsequent calls to `check_proof` with the same trace commitment
    /// will return `Err(ReplayRejection::DuplicateCommitment)`.
    pub fn accept_proof(&mut self, proof: &Proof) {
        self.seen_commitments
            .insert(proof.commitments.trace_commitment.clone());
    }

    /// Advance the reference timestamp.
    ///
    /// The new timestamp must be >= the current reference timestamp
    /// (monotonic advancement). If `ts < reference_timestamp`, this
    /// is a no-op.
    pub fn update_timestamp(&mut self, ts: u64) {
        if ts > self.reference_timestamp {
            self.reference_timestamp = ts;
        }
    }

    /// Check whether a commitment has already been seen.
    pub fn is_duplicate(&self, commitment: &Hash) -> bool {
        self.seen_commitments.contains(commitment)
    }

    /// Get the number of seen commitments.
    pub fn seen_count(&self) -> usize {
        self.seen_commitments.len()
    }

    /// Get the current reference timestamp.
    pub fn reference_timestamp(&self) -> u64 {
        self.reference_timestamp
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::{DefaultProver, Prover};
    use std::collections::BTreeMap;
    use vsel_constraints::{Constraint, ConstraintCategory, ConstraintExpr, ConstraintId};
    use vsel_core::input::{Authorization, Input};
    use vsel_core::observable::{Observable, TransitionStatus};
    use vsel_core::state::*;
    use vsel_core::transition::TransitionClass;
    use vsel_core::types::*;
    use vsel_trace::engine::{Trace, TraceEntry};

    // -- Test helpers --

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

    fn minimal_canonical() -> CanonicalState {
        CanonicalState {
            accounts: BTreeMap::new(),
            storage: BTreeMap::new(),
            system_data: SystemData {
                protocol_version: test_version(),
                total_supply: 0,
                parameters: BTreeMap::new(),
            },
        }
    }

    fn test_state() -> State {
        let c = minimal_canonical();
        let d = derive(&c);
        let env = Environment {
            timestamp: 1_000_000,
            block_height: 1,
            execution_domain: test_domain_tag(),
        };
        let econ = derive_economic(&c, &env);
        let meta = TraceMetadata {
            sequence_index: 0,
            previous_commitment: Hash([0u8; 32]),
            epoch: 0,
            timestamp: 1_000_000,
        };
        State {
            canonical: c,
            derived: d,
            environment: env,
            economic: econ,
            metadata: meta,
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
            outputs: vec![OutputEvent {
                event_type: "balance_change".to_string(),
                data: vec![1, 2, 3],
            }],
            gas_used: 21_000,
            status: TransitionStatus::Success,
        }
    }

    fn test_trace(num_entries: usize) -> Trace {
        let initial_state = test_state();
        let init_commit = commit(&initial_state.canonical);
        let mut entries = Vec::new();

        for i in 0..num_entries {
            let pre_commit = if i == 0 {
                init_commit.clone()
            } else {
                let mut h = [0u8; 32];
                h[0] = i as u8;
                Hash(h)
            };
            let mut post_hash = [0u8; 32];
            post_hash[0] = (i + 1) as u8;
            let mut chain = [0u8; 32];
            chain[0] = (i + 100) as u8;

            entries.push(TraceEntry {
                index: i as u64,
                pre_state_commitment: pre_commit,
                input: test_input(),
                post_state_commitment: Hash(post_hash),
                observable: test_observable(),
                environment: initial_state.environment.clone(),
                chain_hash: Hash(chain),
            });
        }

        let final_commitment = if let Some(last) = entries.last() {
            last.chain_hash.clone()
        } else {
            Hash([0u8; 32])
        };

        Trace {
            entries,
            initial_state,
            commitment: final_commitment,
        }
    }

    fn test_constraint_system() -> vsel_constraints::ConstraintSystem {
        let mut cs = vsel_constraints::ConstraintSystem::new("1.0.0");
        cs.add_constraint(Constraint {
            id: ConstraintId(0),
            expr: ConstraintExpr::BoolConstant(true),
            category: ConstraintCategory::Structural,
            description: "test constraint".to_string(),
        });
        cs
    }

    /// Generate a valid proof with a specific timestamp.
    fn make_proof_with_timestamp(ts: u64) -> crate::prover::Proof {
        let prover = DefaultProver::new("0.1.0-test");
        let trace = test_trace(2);
        let cs = test_constraint_system();
        let mut proof = prover.prove(&trace, &cs).expect("proof generation");
        proof.metadata.timestamp = ts;
        proof
    }

    fn default_guard() -> ReplayGuard {
        ReplayGuard::new(
            test_domain_tag(),
            3600, // 1 hour max age
            1_000_000,
        )
    }

    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_replay_guard_new() {
        let guard = default_guard();
        assert_eq!(guard.seen_count(), 0);
        assert_eq!(guard.reference_timestamp(), 1_000_000);
    }

    // -----------------------------------------------------------------------
    // Valid proof passes check
    // -----------------------------------------------------------------------

    #[test]
    fn test_valid_proof_passes_check() {
        let guard = default_guard();
        let proof = make_proof_with_timestamp(1_000_000);
        assert_eq!(guard.check_proof(&proof), Ok(()));
    }

    // -----------------------------------------------------------------------
    // Duplicate detection
    // -----------------------------------------------------------------------

    #[test]
    fn test_duplicate_proof_rejected() {
        let mut guard = default_guard();
        let proof = make_proof_with_timestamp(1_000_000);

        assert_eq!(guard.check_proof(&proof), Ok(()));
        guard.accept_proof(&proof);

        assert_eq!(
            guard.check_proof(&proof),
            Err(ReplayRejection::DuplicateCommitment)
        );
    }

    #[test]
    fn test_different_proofs_not_duplicate() {
        let mut guard = default_guard();
        let proof1 = make_proof_with_timestamp(1_000_000);
        guard.accept_proof(&proof1);

        // Create a proof with different trace content
        let prover = DefaultProver::new("0.1.0-test");
        let trace = test_trace(3); // different number of entries
        let cs = test_constraint_system();
        let mut proof2 = prover.prove(&trace, &cs).expect("proof");
        proof2.metadata.timestamp = 1_000_000;

        assert_eq!(guard.check_proof(&proof2), Ok(()));
    }

    // -----------------------------------------------------------------------
    // Time-window validation
    // -----------------------------------------------------------------------

    #[test]
    fn test_proof_too_old_rejected() {
        let guard = default_guard(); // ref_ts = 1_000_000, max_age = 3600
        let proof = make_proof_with_timestamp(990_000); // 10_000 seconds old
        assert_eq!(
            guard.check_proof(&proof),
            Err(ReplayRejection::ProofTooOld)
        );
    }

    #[test]
    fn test_proof_in_future_rejected() {
        let guard = default_guard();
        let proof = make_proof_with_timestamp(2_000_000);
        assert_eq!(
            guard.check_proof(&proof),
            Err(ReplayRejection::ProofInFuture)
        );
    }

    #[test]
    fn test_proof_at_boundary_accepted() {
        let guard = default_guard(); // ref_ts = 1_000_000, max_age = 3600
        // Exactly at the boundary: 1_000_000 - 3600 = 996_400
        let proof = make_proof_with_timestamp(996_400);
        assert_eq!(guard.check_proof(&proof), Ok(()));
    }

    #[test]
    fn test_proof_just_past_boundary_rejected() {
        let guard = default_guard();
        let proof = make_proof_with_timestamp(996_399);
        assert_eq!(
            guard.check_proof(&proof),
            Err(ReplayRejection::ProofTooOld)
        );
    }

    // -----------------------------------------------------------------------
    // Domain binding
    // -----------------------------------------------------------------------

    #[test]
    fn test_wrong_domain_rejected() {
        let guard = default_guard();
        let mut proof = make_proof_with_timestamp(1_000_000);
        // Tamper with the public inputs domain
        proof.public_inputs.domain = DomainTag(Hash([0xFF; 32]));
        assert_eq!(
            guard.check_proof(&proof),
            Err(ReplayRejection::DomainMismatch)
        );
    }

    #[test]
    fn test_wrong_metadata_domain_rejected() {
        let guard = default_guard();
        let mut proof = make_proof_with_timestamp(1_000_000);
        proof.metadata.domain = DomainTag(Hash([0xFF; 32]));
        assert_eq!(
            guard.check_proof(&proof),
            Err(ReplayRejection::DomainMismatch)
        );
    }

    // -----------------------------------------------------------------------
    // Timestamp advancement
    // -----------------------------------------------------------------------

    #[test]
    fn test_update_timestamp_advances() {
        let mut guard = default_guard();
        guard.update_timestamp(2_000_000);
        assert_eq!(guard.reference_timestamp(), 2_000_000);
    }

    #[test]
    fn test_update_timestamp_no_regression() {
        let mut guard = default_guard();
        guard.update_timestamp(500_000); // less than current
        assert_eq!(guard.reference_timestamp(), 1_000_000);
    }

    // -----------------------------------------------------------------------
    // Accept then check flow
    // -----------------------------------------------------------------------

    #[test]
    fn test_accept_increments_seen_count() {
        let mut guard = default_guard();
        let proof = make_proof_with_timestamp(1_000_000);
        assert_eq!(guard.seen_count(), 0);
        guard.accept_proof(&proof);
        assert_eq!(guard.seen_count(), 1);
    }

    #[test]
    fn test_is_duplicate_after_accept() {
        let mut guard = default_guard();
        let proof = make_proof_with_timestamp(1_000_000);
        let commitment = proof.commitments.trace_commitment.clone();
        assert!(!guard.is_duplicate(&commitment));
        guard.accept_proof(&proof);
        assert!(guard.is_duplicate(&commitment));
    }
}
