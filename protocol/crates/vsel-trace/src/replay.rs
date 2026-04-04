//! Replay resistance for the VSEL trace system.
//!
//! Derived from: THREAT_MODEL.md (temporal attacks), Requirement 18.2.
//!
//! Prevents:
//! - Trace replay (duplicate commitment tracking)
//! - Stale trace acceptance (epoch-based validation)
//! - Cross-domain trace injection (domain binding)
//!
//! The `TraceReplayDetector` tracks seen trace final commitments and
//! rejects duplicates, enforces epoch-based freshness, and validates
//! domain binding for all trace entries.

use std::collections::BTreeSet;

use vsel_core::types::{DomainTag, Hash};

use crate::engine::Trace;

// ---------------------------------------------------------------------------
// TraceReplayRejection — reasons a trace may be rejected as a replay
// ---------------------------------------------------------------------------

/// Reasons a trace may be rejected by the replay detector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TraceReplayRejection {
    /// The trace's final commitment has already been accepted.
    DuplicateCommitment,
    /// The trace contains entries from an epoch older than the minimum.
    EpochTooOld,
    /// The trace contains entries with a domain that does not match
    /// the expected execution domain.
    DomainMismatch,
    /// The trace is empty and cannot be validated.
    EmptyTrace,
}

// ---------------------------------------------------------------------------
// TraceReplayDetector — tracks seen trace commitments and prevents replay
// ---------------------------------------------------------------------------

/// TraceReplayDetector — tracks seen trace commitments and prevents replay.
///
/// Enforces three replay resistance properties:
/// 1. **Duplicate detection**: A trace whose final commitment has already
///    been accepted is rejected.
/// 2. **Epoch-based freshness**: Traces containing entries from epochs
///    older than `min_epoch` are rejected.
/// 3. **Domain binding**: All trace entries must belong to the expected
///    execution domain.
///
/// Requirement 18.2: defend against temporal attacks.
pub struct TraceReplayDetector {
    /// Set of seen trace final commitments.
    seen_commitments: BTreeSet<Hash>,
    /// Minimum acceptable epoch for traces.
    min_epoch: u64,
    /// Expected execution domain.
    expected_domain: DomainTag,
}

impl TraceReplayDetector {
    /// Create a new `TraceReplayDetector`.
    ///
    /// - `expected_domain`: the execution domain that all trace entries must match.
    /// - `min_epoch`: the minimum acceptable epoch for trace entries.
    pub fn new(expected_domain: DomainTag, min_epoch: u64) -> Self {
        Self {
            seen_commitments: BTreeSet::new(),
            min_epoch,
            expected_domain,
        }
    }

    /// Check whether a trace is a replay.
    ///
    /// Returns `Ok(())` if the trace passes all replay checks, or
    /// `Err(TraceReplayRejection)` with the specific rejection reason.
    ///
    /// Checks (in order):
    /// 1. Non-empty — trace must have at least one entry.
    /// 2. Duplicate detection — final commitment must not have been seen.
    /// 3. Domain binding — all entries must match the expected domain.
    /// 4. Epoch freshness — all entries must be from an epoch >= min_epoch.
    pub fn check_trace(&self, trace: &Trace) -> Result<(), TraceReplayRejection> {
        // 1. Non-empty
        if trace.entries.is_empty() {
            return Err(TraceReplayRejection::EmptyTrace);
        }

        // 2. Duplicate detection
        if self.seen_commitments.contains(&trace.commitment) {
            return Err(TraceReplayRejection::DuplicateCommitment);
        }

        // 3. Domain binding — check all entries
        for entry in &trace.entries {
            if entry.environment.execution_domain != self.expected_domain {
                return Err(TraceReplayRejection::DomainMismatch);
            }
        }

        // 4. Epoch freshness — derive epoch from the initial state metadata
        // and check that the trace's epoch is not below the minimum.
        let trace_epoch = trace.initial_state.metadata.epoch;
        if trace_epoch < self.min_epoch {
            return Err(TraceReplayRejection::EpochTooOld);
        }

        Ok(())
    }

    /// Record a trace's final commitment as seen.
    ///
    /// Call this after a trace has been verified and accepted.
    /// Subsequent calls to `check_trace` with the same final commitment
    /// will return `Err(TraceReplayRejection::DuplicateCommitment)`.
    pub fn accept_trace(&mut self, trace: &Trace) {
        self.seen_commitments.insert(trace.commitment.clone());
    }

    /// Advance the minimum acceptable epoch.
    ///
    /// Traces from epochs older than `epoch` will be rejected.
    /// The epoch only advances forward — if `epoch < min_epoch`,
    /// this is a no-op.
    pub fn advance_epoch(&mut self, epoch: u64) {
        if epoch > self.min_epoch {
            self.min_epoch = epoch;
        }
    }

    /// Get the number of seen commitments.
    pub fn seen_count(&self) -> usize {
        self.seen_commitments.len()
    }

    /// Get the current minimum epoch.
    pub fn min_epoch(&self) -> u64 {
        self.min_epoch
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::TraceEntry;
    use std::collections::BTreeMap;
    use vsel_core::input::{Authorization, Input};
    use vsel_core::observable::{Observable, TransitionStatus};
    use vsel_core::state::*;
    use vsel_core::transition::TransitionClass;
    use vsel_core::types::*;

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

    fn test_state_with_epoch(epoch: u64) -> State {
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
            epoch,
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

    fn test_trace_with_epoch(num_entries: usize, epoch: u64) -> Trace {
        let initial_state = test_state_with_epoch(epoch);
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

    fn default_detector() -> TraceReplayDetector {
        TraceReplayDetector::new(test_domain_tag(), 5)
    }

    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_detector_new() {
        let detector = default_detector();
        assert_eq!(detector.seen_count(), 0);
        assert_eq!(detector.min_epoch(), 5);
    }

    // -----------------------------------------------------------------------
    // Valid trace passes check
    // -----------------------------------------------------------------------

    #[test]
    fn test_valid_trace_passes_check() {
        let detector = default_detector();
        let trace = test_trace_with_epoch(2, 10);
        assert_eq!(detector.check_trace(&trace), Ok(()));
    }

    // -----------------------------------------------------------------------
    // Empty trace rejected
    // -----------------------------------------------------------------------

    #[test]
    fn test_empty_trace_rejected() {
        let detector = default_detector();
        let trace = test_trace_with_epoch(0, 10);
        assert_eq!(
            detector.check_trace(&trace),
            Err(TraceReplayRejection::EmptyTrace)
        );
    }

    // -----------------------------------------------------------------------
    // Duplicate detection
    // -----------------------------------------------------------------------

    #[test]
    fn test_duplicate_trace_rejected() {
        let mut detector = default_detector();
        let trace = test_trace_with_epoch(2, 10);

        assert_eq!(detector.check_trace(&trace), Ok(()));
        detector.accept_trace(&trace);

        assert_eq!(
            detector.check_trace(&trace),
            Err(TraceReplayRejection::DuplicateCommitment)
        );
    }

    #[test]
    fn test_different_traces_not_duplicate() {
        let mut detector = default_detector();
        let trace1 = test_trace_with_epoch(2, 10);
        detector.accept_trace(&trace1);

        let trace2 = test_trace_with_epoch(3, 10); // different entry count
        assert_eq!(detector.check_trace(&trace2), Ok(()));
    }

    // -----------------------------------------------------------------------
    // Epoch-based freshness
    // -----------------------------------------------------------------------

    #[test]
    fn test_old_epoch_rejected() {
        let detector = default_detector(); // min_epoch = 5
        let trace = test_trace_with_epoch(2, 3); // epoch 3 < 5
        assert_eq!(
            detector.check_trace(&trace),
            Err(TraceReplayRejection::EpochTooOld)
        );
    }

    #[test]
    fn test_epoch_at_boundary_accepted() {
        let detector = default_detector(); // min_epoch = 5
        let trace = test_trace_with_epoch(2, 5); // epoch == min_epoch
        assert_eq!(detector.check_trace(&trace), Ok(()));
    }

    // -----------------------------------------------------------------------
    // Domain binding
    // -----------------------------------------------------------------------

    #[test]
    fn test_wrong_domain_rejected() {
        let detector = default_detector();
        let mut trace = test_trace_with_epoch(2, 10);
        // Tamper with the first entry's domain
        trace.entries[0].environment.execution_domain = DomainTag(Hash([0xFF; 32]));
        assert_eq!(
            detector.check_trace(&trace),
            Err(TraceReplayRejection::DomainMismatch)
        );
    }

    #[test]
    fn test_partial_domain_mismatch_rejected() {
        let detector = default_detector();
        let mut trace = test_trace_with_epoch(3, 10);
        // Only tamper with the last entry's domain
        trace.entries[2].environment.execution_domain = DomainTag(Hash([0xFF; 32]));
        assert_eq!(
            detector.check_trace(&trace),
            Err(TraceReplayRejection::DomainMismatch)
        );
    }

    // -----------------------------------------------------------------------
    // Epoch advancement
    // -----------------------------------------------------------------------

    #[test]
    fn test_advance_epoch() {
        let mut detector = default_detector();
        detector.advance_epoch(10);
        assert_eq!(detector.min_epoch(), 10);
    }

    #[test]
    fn test_advance_epoch_no_regression() {
        let mut detector = default_detector(); // min_epoch = 5
        detector.advance_epoch(3); // less than current
        assert_eq!(detector.min_epoch(), 5);
    }

    #[test]
    fn test_advance_epoch_rejects_previously_valid() {
        let mut detector = default_detector(); // min_epoch = 5
        let trace = test_trace_with_epoch(2, 7);
        assert_eq!(detector.check_trace(&trace), Ok(()));

        detector.advance_epoch(8);
        assert_eq!(
            detector.check_trace(&trace),
            Err(TraceReplayRejection::EpochTooOld)
        );
    }

    // -----------------------------------------------------------------------
    // Accept increments seen count
    // -----------------------------------------------------------------------

    #[test]
    fn test_accept_increments_seen_count() {
        let mut detector = default_detector();
        let trace = test_trace_with_epoch(2, 10);
        assert_eq!(detector.seen_count(), 0);
        detector.accept_trace(&trace);
        assert_eq!(detector.seen_count(), 1);
    }
}
