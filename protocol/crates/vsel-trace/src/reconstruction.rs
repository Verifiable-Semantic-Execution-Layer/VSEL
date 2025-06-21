//! Trace reconstruction — replay execution to reconstruct a full trace.
//!
//! Derived from: EXECUTION_TRACE_MODEL.md §5, Requirement 6.
//!
//! Given an initial state s₀ and input sequence σ₀...σ_{n-1}, the full
//! trace is reconstructible: `Reconstruct(s₀, σ₀...σ_{n-1}) = τ` (LEM-10).
//!
//! Trace determinism: identical initial state + inputs + environment = identical trace.
//! Requirements: 6.4, 6.6

use vsel_core::input::Input;
use vsel_core::observable::obs;
use vsel_core::state::State;
use vsel_core::transition::apply;

use crate::engine::{Trace, TraceEngine};

// ---------------------------------------------------------------------------
// Trace reconstruction (LEM-10)
// ---------------------------------------------------------------------------

/// Reconstruct a complete trace from initial state and input sequence.
///
/// Replays each input through `apply` and `obs`, recording each transition
/// via the trace engine. The result is a deterministic trace identical to
/// what would have been produced during live execution.
///
/// `Reconstruct(s₀, σ₀...σ_{n-1}) = τ` (LEM-10)
///
/// Requirements 6.4, 6.6
pub fn reconstruct(initial_state: &State, inputs: &[Input]) -> Trace {
    let mut engine = TraceEngine::new();
    let mut entries = Vec::with_capacity(inputs.len());
    let mut current_state = initial_state.clone();

    for input in inputs {
        let post_state = apply(&current_state, input);
        let observable = obs(&current_state, input, &post_state);

        let entry = engine.record_transition(&current_state, input, &post_state, &observable);
        entries.push(entry);

        current_state = post_state;
    }

    let commitment = engine.current_chain_hash().clone();

    Trace {
        entries,
        initial_state: initial_state.clone(),
        commitment,
    }
}
