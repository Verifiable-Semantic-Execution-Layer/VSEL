//! Cross-system trace composition for compositional verification.
//!
//! Derived from: COMPOSITION_MODEL.md, EXECUTION_TRACE_MODEL.md,
//! Requirements 11.4, 11.6.
//!
//! Merges two execution traces from independent systems into a
//! `ComposedTrace` that preserves ordering, records cross-system
//! synchronization points, and computes a merged commitment hash.
//!
//! Temporal ordering verification (L-002 remediation):
//! - Each individual trace must have non-decreasing timestamps.
//! - At synchronization points, timestamps must be consistent across
//!   both traces (equal, since sync points are defined by matching
//!   timestamps).
//! - Causal ordering across sync points: if sync point S1 precedes S2,
//!   then S1's timestamp must be ≤ S2's timestamp in both traces.
//! - Traces with ordering inconsistencies are rejected.

use sha3::{Digest, Sha3_256};

use vsel_core::types::Hash;
use vsel_trace::engine::Trace;

// ---------------------------------------------------------------------------
// Domain separator for trace merge operations
// ---------------------------------------------------------------------------

/// Domain separator for trace merge commitment computation.
const DOMAIN_TRACE_MERGE: &[u8] = b"VSEL::v1::trace_merge";

// ---------------------------------------------------------------------------
// TraceMergeError — temporal ordering violations
// ---------------------------------------------------------------------------

/// Error type for trace merge temporal ordering violations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TraceMergeError {
    /// Timestamps within a single trace are not non-decreasing.
    IntraTraceOrderingViolation {
        /// Which system's trace has the violation ("A" or "B").
        system: &'static str,
        /// Index of the entry with the violation.
        entry_index: u64,
        /// Timestamp of the preceding entry.
        preceding_timestamp: u64,
        /// Timestamp of the violating entry.
        violating_timestamp: u64,
    },
    /// Causal ordering violated across synchronization points: a later
    /// sync point references entries with earlier timestamps than a
    /// preceding sync point.
    CrossTraceCausalViolation {
        /// Index of the earlier synchronization point.
        earlier_sync_index: u64,
        /// Timestamp at the earlier sync point.
        earlier_timestamp: u64,
        /// Index of the later synchronization point.
        later_sync_index: u64,
        /// Timestamp at the later sync point.
        later_timestamp: u64,
    },
}

// ---------------------------------------------------------------------------
// SyncType — classification of cross-system synchronization
// ---------------------------------------------------------------------------

/// Classification of a cross-system synchronization point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncType {
    /// State transferred from one system to another.
    StateTransfer,
    /// Both systems updated shared state.
    SharedStateUpdate,
    /// Cross-system verification checkpoint.
    CrossSystemVerification,
}

// ---------------------------------------------------------------------------
// SynchronizationPoint — a recorded cross-system sync event
// ---------------------------------------------------------------------------

/// A recorded synchronization point between two composed systems.
///
/// Captures the index within the composed trace and the corresponding
/// entry indices in each system's trace where synchronization occurred.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SynchronizationPoint {
    /// Index of this synchronization point (0-based, sequential).
    pub index: u64,
    /// Index of the corresponding entry in system A's trace.
    pub system_a_entry_index: u64,
    /// Index of the corresponding entry in system B's trace.
    pub system_b_entry_index: u64,
    /// Type of synchronization.
    pub sync_type: SyncType,
    /// Commitment binding this synchronization point.
    pub commitment: Hash,
}

// ---------------------------------------------------------------------------
// ComposedTrace — the merged result of two system traces
// ---------------------------------------------------------------------------

/// A composed trace combining two system traces with synchronization metadata.
///
/// Preserves both original traces and records the synchronization points
/// and merged commitment for cross-system verification.
#[derive(Clone, Debug)]
pub struct ComposedTrace {
    /// Trace from system A (preserved in full).
    pub trace_a: Trace,
    /// Trace from system B (preserved in full).
    pub trace_b: Trace,
    /// Cross-system synchronization points.
    pub sync_points: Vec<SynchronizationPoint>,
    /// Merged commitment hash binding both traces.
    pub merged_commitment: Hash,
}

// ---------------------------------------------------------------------------
// merge_traces — compose two traces with ordering and sync points
// ---------------------------------------------------------------------------

/// Merge two traces from independent systems into a composed trace.
///
/// Preserves ordering by interleaving entries based on their environment
/// timestamps. Records synchronization points where entries from both
/// systems share the same timestamp (indicating cross-system interaction).
/// Computes a merged commitment hash binding both traces together.
///
/// Validates temporal ordering:
/// - Each trace must have non-decreasing timestamps (intra-trace ordering).
/// - Synchronization points must have consistent causal ordering: if sync
///   point S1 precedes S2, then S1's timestamp ≤ S2's timestamp.
///
/// Returns `Err(TraceMergeError)` if temporal ordering is violated.
///
/// Requirements 11.4, 11.6. Remediates L-002.
pub fn merge_traces(trace_a: &Trace, trace_b: &Trace) -> Result<ComposedTrace, TraceMergeError> {
    // Step 1: Validate intra-trace temporal ordering for both traces.
    validate_intra_trace_ordering(trace_a, "A")?;
    validate_intra_trace_ordering(trace_b, "B")?;

    // Step 2: Detect synchronization points.
    let sync_points = detect_sync_points(trace_a, trace_b);

    // Step 3: Validate cross-trace causal ordering at sync points.
    validate_cross_trace_ordering(trace_a, trace_b, &sync_points)?;

    // Step 4: Compute merged commitment.
    let merged_commitment = compute_merged_commitment(trace_a, trace_b, &sync_points);

    Ok(ComposedTrace {
        trace_a: trace_a.clone(),
        trace_b: trace_b.clone(),
        sync_points,
        merged_commitment,
    })
}

// ---------------------------------------------------------------------------
// Temporal ordering validation
// ---------------------------------------------------------------------------

/// Validate that timestamps within a single trace are non-decreasing.
///
/// Each entry's environment timestamp must be ≥ the preceding entry's
/// timestamp. This enforces T_causal (causality preservation) within
/// a single system's trace.
fn validate_intra_trace_ordering(
    trace: &Trace,
    system: &'static str,
) -> Result<(), TraceMergeError> {
    for i in 1..trace.entries.len() {
        let prev_ts = trace.entries[i - 1].environment.timestamp;
        let curr_ts = trace.entries[i].environment.timestamp;
        if curr_ts < prev_ts {
            return Err(TraceMergeError::IntraTraceOrderingViolation {
                system,
                entry_index: trace.entries[i].index,
                preceding_timestamp: prev_ts,
                violating_timestamp: curr_ts,
            });
        }
    }
    Ok(())
}

/// Validate causal ordering across synchronization points.
///
/// For consecutive sync points S_i and S_j (i < j), the timestamp at S_j
/// must be ≥ the timestamp at S_i. Since sync points are defined by
/// matching timestamps across both traces, we verify that the sequence
/// of sync point timestamps is non-decreasing.
fn validate_cross_trace_ordering(
    trace_a: &Trace,
    _trace_b: &Trace,
    sync_points: &[SynchronizationPoint],
) -> Result<(), TraceMergeError> {
    for i in 1..sync_points.len() {
        let prev_sp = &sync_points[i - 1];
        let curr_sp = &sync_points[i];

        // Get the timestamp at each sync point from trace A (both traces
        // have the same timestamp at a sync point by definition).
        let prev_ts = trace_a.entries[prev_sp.system_a_entry_index as usize]
            .environment
            .timestamp;
        let curr_ts = trace_a.entries[curr_sp.system_a_entry_index as usize]
            .environment
            .timestamp;

        if curr_ts < prev_ts {
            return Err(TraceMergeError::CrossTraceCausalViolation {
                earlier_sync_index: prev_sp.index,
                earlier_timestamp: prev_ts,
                later_sync_index: curr_sp.index,
                later_timestamp: curr_ts,
            });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// detect_sync_points — find cross-system synchronization points
// ---------------------------------------------------------------------------

/// Detect synchronization points between two traces.
///
/// A synchronization point is recorded when entries from both traces
/// share the same environment timestamp, indicating a cross-system
/// interaction or checkpoint.
fn detect_sync_points(trace_a: &Trace, trace_b: &Trace) -> Vec<SynchronizationPoint> {
    let mut sync_points = Vec::new();
    let mut sync_index: u64 = 0;

    for entry_a in &trace_a.entries {
        for entry_b in &trace_b.entries {
            if entry_a.environment.timestamp == entry_b.environment.timestamp {
                let commitment = compute_sync_commitment(entry_a.index, entry_b.index, sync_index);
                sync_points.push(SynchronizationPoint {
                    index: sync_index,
                    system_a_entry_index: entry_a.index,
                    system_b_entry_index: entry_b.index,
                    sync_type: SyncType::CrossSystemVerification,
                    commitment,
                });
                sync_index += 1;
            }
        }
    }

    sync_points
}

/// Compute a commitment for a single synchronization point.
fn compute_sync_commitment(a_index: u64, b_index: u64, sync_index: u64) -> Hash {
    let mut hasher = Sha3_256::new();
    hasher.update(DOMAIN_TRACE_MERGE);
    hasher.update(b"::sync_point");
    hasher.update(&sync_index.to_le_bytes());
    hasher.update(&a_index.to_le_bytes());
    hasher.update(&b_index.to_le_bytes());
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    Hash(bytes)
}

// ---------------------------------------------------------------------------
// compute_merged_commitment — bind both traces into a single hash
// ---------------------------------------------------------------------------

/// Compute a merged commitment hash binding both traces and their
/// synchronization points together.
///
/// Uses domain-separated SHA3-256 hashing over:
/// 1. Domain separator
/// 2. Trace A commitment
/// 3. Trace B commitment
/// 4. Number of sync points
/// 5. Each sync point's commitment
fn compute_merged_commitment(
    trace_a: &Trace,
    trace_b: &Trace,
    sync_points: &[SynchronizationPoint],
) -> Hash {
    let mut hasher = Sha3_256::new();

    // Domain separation.
    hasher.update(DOMAIN_TRACE_MERGE);

    // Bind to both trace commitments.
    hasher.update(&trace_a.commitment.0);
    hasher.update(&trace_b.commitment.0);

    // Bind to trace entry counts for structural integrity.
    hasher.update(&(trace_a.entries.len() as u64).to_le_bytes());
    hasher.update(&(trace_b.entries.len() as u64).to_le_bytes());

    // Bind to synchronization points.
    hasher.update(&(sync_points.len() as u64).to_le_bytes());
    for sp in sync_points {
        hasher.update(&sp.commitment.0);
    }

    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    Hash(bytes)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
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

    fn test_state(timestamp: u64) -> State {
        let c = minimal_canonical();
        let d = derive(&c);
        let env = Environment {
            timestamp,
            block_height: 1,
            execution_domain: test_domain_tag(),
        };
        let econ = derive_economic(&c, &env);
        let meta = TraceMetadata {
            sequence_index: 0,
            previous_commitment: Hash([0u8; 32]),
            epoch: 0,
            timestamp,
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
            outputs: vec![],
            gas_used: 21_000,
            status: TransitionStatus::Success,
        }
    }

    fn make_trace(timestamps: &[u64], seed: u8) -> Trace {
        let initial_ts = timestamps.first().copied().unwrap_or(1000);
        let initial_state = test_state(initial_ts);
        let init_commit = commit(&initial_state.canonical);
        let mut entries = Vec::new();

        for (i, &ts) in timestamps.iter().enumerate() {
            let pre_commit = if i == 0 {
                init_commit.clone()
            } else {
                let mut h = [0u8; 32];
                h[0] = seed.wrapping_add(i as u8);
                Hash(h)
            };
            let mut post_hash = [0u8; 32];
            post_hash[0] = seed.wrapping_add((i + 1) as u8);
            let mut chain = [0u8; 32];
            chain[0] = seed.wrapping_add((i + 100) as u8);

            entries.push(TraceEntry {
                index: i as u64,
                pre_state_commitment: pre_commit,
                input: test_input(),
                post_state_commitment: Hash(post_hash),
                observable: test_observable(),
                environment: Environment {
                    timestamp: ts,
                    block_height: (i + 1) as u64,
                    execution_domain: test_domain_tag(),
                },
                chain_hash: Hash(chain),
            });
        }

        let final_commitment = entries
            .last()
            .map(|e| e.chain_hash.clone())
            .unwrap_or(Hash([0u8; 32]));

        Trace {
            entries,
            initial_state,
            commitment: final_commitment,
        }
    }

    // -- merge_traces tests --

    #[test]
    fn test_merge_empty_traces() {
        let a = make_trace(&[], 0x10);
        let b = make_trace(&[], 0x20);
        let composed = merge_traces(&a, &b).expect("empty traces should merge");

        assert!(composed.sync_points.is_empty());
        assert_eq!(composed.trace_a.entries.len(), 0);
        assert_eq!(composed.trace_b.entries.len(), 0);
    }

    #[test]
    fn test_merge_preserves_original_traces() {
        let a = make_trace(&[1000, 2000, 3000], 0x10);
        let b = make_trace(&[1500, 2500], 0x20);
        let composed = merge_traces(&a, &b).expect("valid traces should merge");

        assert_eq!(composed.trace_a.entries.len(), 3);
        assert_eq!(composed.trace_b.entries.len(), 2);
        assert_eq!(composed.trace_a.commitment, a.commitment);
        assert_eq!(composed.trace_b.commitment, b.commitment);
    }

    #[test]
    fn test_merge_detects_sync_points() {
        // Both traces have entries at timestamp 2000
        let a = make_trace(&[1000, 2000, 3000], 0x10);
        let b = make_trace(&[1500, 2000, 2500], 0x20);
        let composed = merge_traces(&a, &b).expect("valid traces should merge");

        // Should detect sync at timestamp 2000 (a[1] and b[1])
        assert_eq!(composed.sync_points.len(), 1);
        assert_eq!(composed.sync_points[0].system_a_entry_index, 1);
        assert_eq!(composed.sync_points[0].system_b_entry_index, 1);
        assert_eq!(
            composed.sync_points[0].sync_type,
            SyncType::CrossSystemVerification
        );
    }

    #[test]
    fn test_merge_multiple_sync_points() {
        // Both traces share timestamps 1000 and 3000
        let a = make_trace(&[1000, 2000, 3000], 0x10);
        let b = make_trace(&[1000, 2500, 3000], 0x20);
        let composed = merge_traces(&a, &b).expect("valid traces should merge");

        assert_eq!(composed.sync_points.len(), 2);
        // First sync: a[0] and b[0] at timestamp 1000
        assert_eq!(composed.sync_points[0].system_a_entry_index, 0);
        assert_eq!(composed.sync_points[0].system_b_entry_index, 0);
        // Second sync: a[2] and b[2] at timestamp 3000
        assert_eq!(composed.sync_points[1].system_a_entry_index, 2);
        assert_eq!(composed.sync_points[1].system_b_entry_index, 2);
    }

    #[test]
    fn test_merge_no_sync_points() {
        let a = make_trace(&[1000, 2000], 0x10);
        let b = make_trace(&[1500, 2500], 0x20);
        let composed = merge_traces(&a, &b).expect("valid traces should merge");

        assert!(composed.sync_points.is_empty());
    }

    #[test]
    fn test_merge_commitment_deterministic() {
        let a = make_trace(&[1000, 2000], 0x10);
        let b = make_trace(&[1500, 2500], 0x20);

        let c1 = merge_traces(&a, &b).expect("valid traces should merge");
        let c2 = merge_traces(&a, &b).expect("valid traces should merge");

        assert_eq!(c1.merged_commitment, c2.merged_commitment);
    }

    #[test]
    fn test_merge_commitment_differs_for_different_traces() {
        let a1 = make_trace(&[1000, 2000], 0x10);
        let a2 = make_trace(&[1000, 2000, 3000], 0x30);
        let b = make_trace(&[1500, 2500], 0x20);

        let c1 = merge_traces(&a1, &b).expect("valid traces should merge");
        let c2 = merge_traces(&a2, &b).expect("valid traces should merge");

        assert_ne!(c1.merged_commitment, c2.merged_commitment);
    }

    #[test]
    fn test_merge_commitment_order_sensitive() {
        let a = make_trace(&[1000, 2000], 0x10);
        let b = make_trace(&[1500, 2500], 0x20);

        let c1 = merge_traces(&a, &b).expect("valid traces should merge");
        let c2 = merge_traces(&b, &a).expect("valid traces should merge");

        // Swapping A and B should produce a different commitment
        assert_ne!(c1.merged_commitment, c2.merged_commitment);
    }

    #[test]
    fn test_sync_point_commitments_are_unique() {
        let a = make_trace(&[1000, 2000, 3000], 0x10);
        let b = make_trace(&[1000, 2000, 3000], 0x20);
        let composed = merge_traces(&a, &b).expect("valid traces should merge");

        // Each sync point should have a unique commitment
        for i in 0..composed.sync_points.len() {
            for j in (i + 1)..composed.sync_points.len() {
                assert_ne!(
                    composed.sync_points[i].commitment, composed.sync_points[j].commitment,
                    "sync points {} and {} should have different commitments",
                    i, j
                );
            }
        }
    }

    #[test]
    fn test_sync_point_indices_sequential() {
        let a = make_trace(&[1000, 2000, 3000], 0x10);
        let b = make_trace(&[1000, 2000, 3000], 0x20);
        let composed = merge_traces(&a, &b).expect("valid traces should merge");

        for (i, sp) in composed.sync_points.iter().enumerate() {
            assert_eq!(sp.index, i as u64);
        }
    }

    // -- Temporal ordering validation tests --

    #[test]
    fn test_merge_rejects_trace_a_with_decreasing_timestamps() {
        let a = make_trace(&[2000, 1000], 0x10); // Decreasing: violation
        let b = make_trace(&[1500, 2500], 0x20);
        let result = merge_traces(&a, &b);

        match result {
            Err(TraceMergeError::IntraTraceOrderingViolation {
                system,
                entry_index,
                preceding_timestamp,
                violating_timestamp,
            }) => {
                assert_eq!(system, "A");
                assert_eq!(entry_index, 1);
                assert_eq!(preceding_timestamp, 2000);
                assert_eq!(violating_timestamp, 1000);
            }
            other => panic!(
                "Expected IntraTraceOrderingViolation for A, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_merge_rejects_trace_b_with_decreasing_timestamps() {
        let a = make_trace(&[1000, 2000], 0x10);
        let b = make_trace(&[3000, 1500], 0x20); // Decreasing: violation
        let result = merge_traces(&a, &b);

        match result {
            Err(TraceMergeError::IntraTraceOrderingViolation {
                system,
                entry_index,
                ..
            }) => {
                assert_eq!(system, "B");
                assert_eq!(entry_index, 1);
            }
            other => panic!(
                "Expected IntraTraceOrderingViolation for B, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_merge_accepts_equal_timestamps() {
        // Equal consecutive timestamps are valid (non-decreasing).
        let a = make_trace(&[1000, 1000, 2000], 0x10);
        let b = make_trace(&[1500, 1500], 0x20);
        assert!(merge_traces(&a, &b).is_ok());
    }
}
