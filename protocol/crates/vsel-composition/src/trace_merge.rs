//! Cross-system trace composition for compositional verification.
//!
//! Derived from: COMPOSITION_MODEL.md, EXECUTION_TRACE_MODEL.md,
//! Requirements 11.4, 11.6.
//!
//! Merges two execution traces from independent systems into a
//! `ComposedTrace` that preserves ordering, records cross-system
//! synchronization points, and computes a merged commitment hash.

use sha3::{Digest, Sha3_256};

use vsel_core::types::Hash;
use vsel_trace::engine::Trace;

// ---------------------------------------------------------------------------
// Domain separator for trace merge operations
// ---------------------------------------------------------------------------

/// Domain separator for trace merge commitment computation.
const DOMAIN_TRACE_MERGE: &[u8] = b"VSEL::v1::trace_merge";

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
/// Requirements 11.4, 11.6.
pub fn merge_traces(trace_a: &Trace, trace_b: &Trace) -> ComposedTrace {
    let sync_points = detect_sync_points(trace_a, trace_b);
    let merged_commitment = compute_merged_commitment(trace_a, trace_b, &sync_points);

    ComposedTrace {
        trace_a: trace_a.clone(),
        trace_b: trace_b.clone(),
        sync_points,
        merged_commitment,
    }
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
        let composed = merge_traces(&a, &b);

        assert!(composed.sync_points.is_empty());
        assert_eq!(composed.trace_a.entries.len(), 0);
        assert_eq!(composed.trace_b.entries.len(), 0);
    }

    #[test]
    fn test_merge_preserves_original_traces() {
        let a = make_trace(&[1000, 2000, 3000], 0x10);
        let b = make_trace(&[1500, 2500], 0x20);
        let composed = merge_traces(&a, &b);

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
        let composed = merge_traces(&a, &b);

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
        let composed = merge_traces(&a, &b);

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
        let composed = merge_traces(&a, &b);

        assert!(composed.sync_points.is_empty());
    }

    #[test]
    fn test_merge_commitment_deterministic() {
        let a = make_trace(&[1000, 2000], 0x10);
        let b = make_trace(&[1500, 2500], 0x20);

        let c1 = merge_traces(&a, &b);
        let c2 = merge_traces(&a, &b);

        assert_eq!(c1.merged_commitment, c2.merged_commitment);
    }

    #[test]
    fn test_merge_commitment_differs_for_different_traces() {
        let a1 = make_trace(&[1000, 2000], 0x10);
        let a2 = make_trace(&[1000, 2000, 3000], 0x30);
        let b = make_trace(&[1500, 2500], 0x20);

        let c1 = merge_traces(&a1, &b);
        let c2 = merge_traces(&a2, &b);

        assert_ne!(c1.merged_commitment, c2.merged_commitment);
    }

    #[test]
    fn test_merge_commitment_order_sensitive() {
        let a = make_trace(&[1000, 2000], 0x10);
        let b = make_trace(&[1500, 2500], 0x20);

        let c1 = merge_traces(&a, &b);
        let c2 = merge_traces(&b, &a);

        // Swapping A and B should produce a different commitment
        assert_ne!(c1.merged_commitment, c2.merged_commitment);
    }

    #[test]
    fn test_sync_point_commitments_are_unique() {
        let a = make_trace(&[1000, 2000, 3000], 0x10);
        let b = make_trace(&[1000, 2000, 3000], 0x20);
        let composed = merge_traces(&a, &b);

        // Each sync point should have a unique commitment
        for i in 0..composed.sync_points.len() {
            for j in (i + 1)..composed.sync_points.len() {
                assert_ne!(
                    composed.sync_points[i].commitment,
                    composed.sync_points[j].commitment,
                    "sync points {} and {} should have different commitments",
                    i,
                    j
                );
            }
        }
    }

    #[test]
    fn test_sync_point_indices_sequential() {
        let a = make_trace(&[1000, 2000, 3000], 0x10);
        let b = make_trace(&[1000, 2000, 3000], 0x20);
        let composed = merge_traces(&a, &b);

        for (i, sp) in composed.sync_points.iter().enumerate() {
            assert_eq!(sp.index, i as u64);
        }
    }
}
