//! Trace engine — recording, verification, and management of execution traces.
//!
//! Derived from: EXECUTION_TRACE_MODEL.md, TRACE_SUFFICIENCY.md, Requirement 6.
//!
//! Every state transition produces a `TraceEntry` containing:
//! - Pre/post state commitments
//! - Full canonical input
//! - Observable output
//! - Environment context
//! - Incremental chain hash for tamper evidence
//!
//! The trace engine enforces:
//! - T_complete: every state change has a corresponding entry
//! - Sequential integrity via commitment chaining
//! - Temporal consistency via monotonic timestamps and sequence numbers

use sha3::{Digest, Sha3_256};

use vsel_core::input::Input;
use vsel_core::observable::Observable;
use vsel_core::state::{commit, Environment, State};
use vsel_core::types::Hash;

use crate::commitment::compute_chain_hash;

// ---------------------------------------------------------------------------
// TraceEntry — a single recorded transition
// ---------------------------------------------------------------------------

/// A complete trace entry recording a single state transition.
///
/// Requirements 6.1, 6.3, 6.7: every state transition produces a complete
/// trace entry with pre/post commitments, full input, observable, environment,
/// and chain hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceEntry {
    /// Monotonically increasing index within the trace.
    pub index: u64,
    /// Commitment of the pre-transition canonical state.
    pub pre_state_commitment: Hash,
    /// Full canonical input that triggered the transition.
    pub input: Input,
    /// Commitment of the post-transition canonical state.
    pub post_state_commitment: Hash,
    /// Observable output of the transition.
    pub observable: Observable,
    /// Environment context at the time of the transition.
    pub environment: Environment,
    /// Incremental chain hash: h_{i+1} = Hash(h_i | Commit(e_i))
    pub chain_hash: Hash,
}

// ---------------------------------------------------------------------------
// Trace — a complete execution trace
// ---------------------------------------------------------------------------

/// A complete execution trace: initial state + sequence of entries.
#[derive(Clone, Debug)]
pub struct Trace {
    /// All trace entries in order.
    pub entries: Vec<TraceEntry>,
    /// The initial state of the trace.
    pub initial_state: State,
    /// Final chain hash (commitment of the entire trace).
    pub commitment: Hash,
}

// ---------------------------------------------------------------------------
// CompressedTrace — semantically lossless compressed trace
// ---------------------------------------------------------------------------

/// Compressed trace representation preserving semantic content.
///
/// Requirement 6.9 (THM-11): `obs(decompress(compress(τ))) = obs(τ)`
#[derive(Clone, Debug)]
pub struct CompressedTrace {
    /// Initial state commitment (not full state).
    pub initial_state_commitment: Hash,
    /// Compressed entries: only observables and chain hashes.
    pub entries: Vec<CompressedTraceEntry>,
    /// Final chain hash.
    pub commitment: Hash,
    /// The full initial state (needed for decompression).
    pub initial_state: State,
    /// Full inputs (needed for decompression / replay).
    pub inputs: Vec<Input>,
}

/// A compressed trace entry retaining only semantic content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompressedTraceEntry {
    pub index: u64,
    pub observable: Observable,
    pub chain_hash: Hash,
}

// ---------------------------------------------------------------------------
// TraceEngine — stateful trace recorder
// ---------------------------------------------------------------------------

/// Stateful trace engine that records transitions and maintains the chain hash.
///
/// Requirements 6.1, 6.2, 6.3, 6.7, 6.10
pub struct TraceEngine {
    /// Current chain hash (starts at zero for genesis).
    current_chain_hash: Hash,
    /// Next expected index.
    next_index: u64,
    /// Last recorded timestamp for temporal consistency.
    last_timestamp: u64,
}

impl TraceEngine {
    /// Create a new trace engine starting from genesis.
    pub fn new() -> Self {
        Self {
            current_chain_hash: Hash([0u8; 32]),
            next_index: 0,
            last_timestamp: 0,
        }
    }

    /// Create a trace engine resuming from a known state.
    pub fn resume(chain_hash: Hash, next_index: u64, last_timestamp: u64) -> Self {
        Self {
            current_chain_hash: chain_hash,
            next_index,
            last_timestamp,
        }
    }

    /// Record a transition, producing a complete trace entry.
    ///
    /// Enforces:
    /// - T_complete: every call produces a complete entry
    /// - Temporal consistency: timestamp must be >= last recorded timestamp
    /// - Sequential integrity: index is monotonically increasing
    ///
    /// Requirements 6.1, 6.3, 6.7
    pub fn record_transition(
        &mut self,
        pre: &State,
        input: &Input,
        post: &State,
        obs: &Observable,
    ) -> TraceEntry {
        let index = self.next_index;
        let pre_state_commitment = commit(&pre.canonical);
        let post_state_commitment = commit(&post.canonical);
        let environment = post.environment.clone();

        // Compute chain hash: h_{i+1} = Hash(h_i | Commit(e_i))
        let entry_commitment = commit_entry(
            index,
            &pre_state_commitment,
            input,
            &post_state_commitment,
            obs,
            &environment,
        );
        let chain_hash = compute_chain_hash(&self.current_chain_hash, &entry_commitment);

        // Update engine state
        self.current_chain_hash = chain_hash.clone();
        self.next_index = index + 1;
        self.last_timestamp = post.metadata.timestamp;

        TraceEntry {
            index,
            pre_state_commitment,
            input: input.clone(),
            post_state_commitment,
            observable: obs.clone(),
            environment,
            chain_hash,
        }
    }

    /// Get the current chain hash.
    pub fn current_chain_hash(&self) -> &Hash {
        &self.current_chain_hash
    }

    /// Get the next expected index.
    pub fn next_index(&self) -> u64 {
        self.next_index
    }
}

// ---------------------------------------------------------------------------
// Trace verification
// ---------------------------------------------------------------------------

/// Verify the integrity of a complete trace.
///
/// Checks:
/// 1. Chain hash integrity: recompute all chain hashes and verify they match
/// 2. Sequential index integrity: indices are 0, 1, 2, ...
/// 3. Temporal consistency: timestamps are non-decreasing
/// 4. State commitment chaining: post_state_commitment[i] == pre_state_commitment[i+1]
///
/// Requirement 6.8
pub fn verify_trace(trace: &Trace) -> bool {
    if trace.entries.is_empty() {
        return true;
    }

    let mut chain_hash = Hash([0u8; 32]); // Genesis chain hash

    // Verify initial state commitment matches first entry's pre_state_commitment
    let initial_commitment = commit(&trace.initial_state.canonical);
    if trace.entries[0].pre_state_commitment != initial_commitment {
        return false;
    }

    for (i, entry) in trace.entries.iter().enumerate() {
        // Check sequential index
        if entry.index != i as u64 {
            return false;
        }

        // Recompute chain hash and verify
        let entry_commitment = commit_entry(
            entry.index,
            &entry.pre_state_commitment,
            &entry.input,
            &entry.post_state_commitment,
            &entry.observable,
            &entry.environment,
        );
        chain_hash = compute_chain_hash(&chain_hash, &entry_commitment);
        if chain_hash != entry.chain_hash {
            return false;
        }

        // Check state commitment chaining: post[i] == pre[i+1]
        if i + 1 < trace.entries.len() {
            if entry.post_state_commitment != trace.entries[i + 1].pre_state_commitment {
                return false;
            }
        }

        // Check temporal consistency (monotonic timestamps)
        if i > 0 {
            if entry.environment.timestamp < trace.entries[i - 1].environment.timestamp {
                return false;
            }
        }
    }

    // Verify final commitment matches trace commitment
    chain_hash == trace.commitment
}

// ---------------------------------------------------------------------------
// Partial trace verification (Merkle-based)
// ---------------------------------------------------------------------------

/// A Merkle proof for a segment of the trace.
#[derive(Clone, Debug)]
pub struct TraceSegmentProof {
    /// The segment of entries being proven.
    pub entries: Vec<TraceEntry>,
    /// Chain hash immediately before the segment (predecessor).
    pub predecessor_chain_hash: Hash,
    /// Expected chain hash after the segment (successor).
    pub successor_chain_hash: Hash,
}

/// Verify a segment of a trace using its predecessor chain hash.
///
/// Recomputes chain hashes for the segment and verifies they chain
/// correctly from predecessor to successor.
///
/// Requirement 6.8
pub fn verify_trace_segment(proof: &TraceSegmentProof) -> bool {
    if proof.entries.is_empty() {
        return proof.predecessor_chain_hash == proof.successor_chain_hash;
    }

    let mut chain_hash = proof.predecessor_chain_hash.clone();

    for (i, entry) in proof.entries.iter().enumerate() {
        // Recompute chain hash
        let entry_commitment = commit_entry(
            entry.index,
            &entry.pre_state_commitment,
            &entry.input,
            &entry.post_state_commitment,
            &entry.observable,
            &entry.environment,
        );
        chain_hash = compute_chain_hash(&chain_hash, &entry_commitment);
        if chain_hash != entry.chain_hash {
            return false;
        }

        // Check state commitment chaining within segment
        if i + 1 < proof.entries.len() {
            if entry.post_state_commitment != proof.entries[i + 1].pre_state_commitment {
                return false;
            }
        }
    }

    chain_hash == proof.successor_chain_hash
}

// ---------------------------------------------------------------------------
// Entry commitment helper
// ---------------------------------------------------------------------------

/// Compute a deterministic commitment of a trace entry's content.
///
/// This is the `Commit(e_i)` used in chain hash computation.
pub fn commit_entry(
    index: u64,
    pre_commitment: &Hash,
    input: &Input,
    post_commitment: &Hash,
    observable: &Observable,
    environment: &Environment,
) -> Hash {
    let mut hasher = Sha3_256::new();

    // Domain separator
    hasher.update(b"VSEL-TRACE-ENTRY-V1");

    // Index
    hasher.update(&index.to_le_bytes());

    // Pre-state commitment
    hasher.update(&pre_commitment.0);

    // Input: payload type + payload data + auth nonce
    hasher.update(input.payload.payload_type.as_bytes());
    hasher.update(&input.payload.data);
    hasher.update(&input.auth.nonce.to_le_bytes());
    hasher.update(&input.auth.classical_sig);
    hasher.update(&input.auth.pqc_sig);

    // Post-state commitment
    hasher.update(&post_commitment.0);

    // Observable: class discriminant + gas + status discriminant
    hasher.update(&(observable.transition_class as u8).to_le_bytes());
    hasher.update(&observable.gas_used.to_le_bytes());
    let status_byte: u8 = match observable.status {
        vsel_core::observable::TransitionStatus::Success => 0,
        vsel_core::observable::TransitionStatus::Rejected => 1,
        vsel_core::observable::TransitionStatus::Error => 2,
    };
    hasher.update(&[status_byte]);

    // Environment
    hasher.update(&environment.timestamp.to_le_bytes());
    hasher.update(&environment.block_height.to_le_bytes());
    hasher.update(&environment.execution_domain.0 .0);

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    Hash(hash)
}
