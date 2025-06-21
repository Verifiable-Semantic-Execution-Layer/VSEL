//! Trace compression — semantically lossless compression and decompression.
//!
//! Derived from: EXECUTION_TRACE_MODEL.md §7, Requirement 6.9.
//!
//! Semantic preservation (THM-11):
//!   `obs(decompress(compress(τ))) = obs(τ)`
//!
//! Compression retains:
//! - Initial state (for replay)
//! - All inputs (for replay)
//! - Observables and chain hashes (for verification without replay)
//!
//! Decompression replays the trace from the initial state and inputs,
//! reconstructing full trace entries.

use vsel_core::state::commit;

use crate::engine::{CompressedTrace, CompressedTraceEntry, Trace};
use crate::reconstruction::reconstruct;

// ---------------------------------------------------------------------------
// Compress
// ---------------------------------------------------------------------------

/// Compress a trace, retaining semantic content losslessly.
///
/// The compressed form stores:
/// - Initial state (needed for decompression/replay)
/// - All inputs (needed for decompression/replay)
/// - Observables and chain hashes per entry (for verification)
///
/// Requirement 6.9: `obs(decompress(compress(τ))) = obs(τ)` (THM-11)
pub fn compress(trace: &Trace) -> CompressedTrace {
    let initial_state_commitment = commit(&trace.initial_state.canonical);

    let entries: Vec<CompressedTraceEntry> = trace
        .entries
        .iter()
        .map(|e| CompressedTraceEntry {
            index: e.index,
            observable: e.observable.clone(),
            chain_hash: e.chain_hash.clone(),
        })
        .collect();

    let inputs: Vec<_> = trace.entries.iter().map(|e| e.input.clone()).collect();

    CompressedTrace {
        initial_state_commitment,
        entries,
        commitment: trace.commitment.clone(),
        initial_state: trace.initial_state.clone(),
        inputs,
    }
}

// ---------------------------------------------------------------------------
// Decompress
// ---------------------------------------------------------------------------

/// Decompress a compressed trace by replaying from initial state + inputs.
///
/// Reconstructs the full trace using `reconstruct`, which replays each
/// input through `apply` and `obs`.
///
/// Requirement 6.9: `obs(decompress(compress(τ))) = obs(τ)` (THM-11)
pub fn decompress(compressed: &CompressedTrace) -> Trace {
    reconstruct(&compressed.initial_state, &compressed.inputs)
}
