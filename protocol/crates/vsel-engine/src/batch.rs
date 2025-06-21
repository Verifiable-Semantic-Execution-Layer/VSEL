//! Batch processing for the VSEL execution engine.
//!
//! Derived from: STATE_MACHINE.md §5, FORMAL_SPECIFICATION.md §3,
//! Requirements: 2.5
//!
//! Batch semantics enforce sequential equivalence (LEM-9, THM-12):
//!   Apply(s, [σ₁, ..., σₙ]) = Apply(Apply(...Apply(s, σ₁)...), σₙ)
//!
//! All intermediate preconditions are checked. Ordering is preserved —
//! no implicit reordering. If any individual execution fails, the batch
//! halts and returns the error (no partial application).

use vsel_core::input::Input;
use vsel_core::observable::Observable;
use vsel_core::state::{commit, State};
use vsel_core::transition::TransitionClass;

use crate::engine::{
    DefaultExecutionEngine, ExecutionEngine, ExecutionError, ExecutionResult, TraceEntry,
};

// ---------------------------------------------------------------------------
// BatchResult — successful batch execution output
// ---------------------------------------------------------------------------

/// Result of a successful batch execution.
///
/// Contains the overall pre/post state, combined observable, and
/// individual results for each input in the batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchResult {
    /// The original state before any inputs were applied.
    pub pre_state: State,
    /// The final state after all inputs were applied.
    pub post_state: State,
    /// Combined observable from all transitions.
    pub observable: Observable,
    /// The transition class for the overall batch.
    pub transition_class: TransitionClass,
    /// Trace entry for the overall batch execution.
    pub trace_entry: TraceEntry,
    /// Individual execution results for each input, in order.
    pub intermediate_results: Vec<ExecutionResult>,
}

// ---------------------------------------------------------------------------
// execute_batch — standalone batch processing function
// ---------------------------------------------------------------------------

/// Execute a batch of inputs sequentially against a state.
///
/// Enforces sequential equivalence (LEM-9, THM-12):
///   `apply(s, [σ₁, ..., σₙ]) = apply(apply(...apply(s, σ₁)...), σₙ)`
///
/// - All intermediate preconditions are checked via the engine's `execute`.
/// - Ordering is preserved — inputs are applied in slice order.
/// - If any individual execution fails, the batch halts immediately and
///   returns the error. No partial application is committed.
///
/// For an empty input slice, returns a batch result with unchanged state
/// and no intermediate results.
///
/// Requirements: 2.5
pub fn execute_batch(
    state: &State,
    inputs: &[Input],
) -> Result<BatchResult, ExecutionError> {
    let engine = DefaultExecutionEngine;
    let original_state = state.clone();
    let mut current_state = state.clone();
    let mut intermediate_results = Vec::with_capacity(inputs.len());

    // Apply each input sequentially, preserving order (LEM-9).
    for input in inputs {
        let result = engine.execute(&current_state, input)?;
        current_state = result.post_state.clone();
        intermediate_results.push(result);
    }

    // Build combined observable from all intermediate results.
    let observable = combine_observables(&intermediate_results);

    // Build overall trace entry for the batch.
    let trace_entry = TraceEntry {
        index: current_state.metadata.sequence_index,
        pre_state_commitment: commit(&original_state.canonical),
        post_state_commitment: commit(&current_state.canonical),
        transition_class: TransitionClass::Batch,
    };

    Ok(BatchResult {
        pre_state: original_state,
        post_state: current_state,
        observable,
        transition_class: TransitionClass::Batch,
        trace_entry,
        intermediate_results,
    })
}

// ---------------------------------------------------------------------------
// Observable combination
// ---------------------------------------------------------------------------

/// Combine observables from a sequence of execution results into a single
/// batch observable.
///
/// - `transition_class` is always `Batch`.
/// - `outputs` are concatenated in order (preserving ordering).
/// - `gas_used` is the sum of all individual gas costs.
/// - `status` is `Success` if all succeeded, otherwise the first non-success.
fn combine_observables(results: &[ExecutionResult]) -> Observable {
    use vsel_core::observable::TransitionStatus;

    let mut all_outputs = Vec::new();
    let mut total_gas: u64 = 0;
    let mut combined_status = TransitionStatus::Success;

    for result in results {
        all_outputs.extend(result.observable.outputs.clone());
        total_gas = total_gas.saturating_add(result.observable.gas_used);

        // First non-success status wins.
        if combined_status == TransitionStatus::Success
            && result.observable.status != TransitionStatus::Success
        {
            combined_status = result.observable.status;
        }
    }

    Observable {
        transition_class: TransitionClass::Batch,
        outputs: all_outputs,
        gas_used: total_gas,
        status: combined_status,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use vsel_core::input::Authorization;
    use vsel_core::observable::TransitionStatus;
    use vsel_core::state::{
        derive, derive_economic, CanonicalState, Environment, TraceMetadata,
    };
    use vsel_core::transition::apply;
    use vsel_core::types::*;

    // -- Test helpers --

    fn test_domain_tag() -> DomainTag {
        let mut h = [0u8; 32];
        h[0] = 0xAB;
        DomainTag(Hash(h))
    }

    fn valid_auth() -> Authorization {
        Authorization {
            classical_sig: vec![1, 2, 3],
            pqc_sig: vec![4, 5, 6],
            public_key: HybridPublicKey {
                classical: vec![10, 11],
                pqc: vec![20, 21],
            },
            nonce: 42,
            domain: test_domain_tag(),
        }
    }

    fn minimal_canonical() -> CanonicalState {
        CanonicalState {
            accounts: BTreeMap::new(),
            storage: BTreeMap::new(),
            system_data: SystemData {
                protocol_version: ProtocolVersion {
                    major: 0,
                    minor: 1,
                    patch: 0,
                },
                total_supply: 0,
                parameters: BTreeMap::new(),
            },
        }
    }

    fn build_state_at_seq(c: CanonicalState, seq: u64) -> State {
        let d = derive(&c);
        let env = Environment {
            timestamp: 1_000_000,
            block_height: 1,
            execution_domain: test_domain_tag(),
        };
        let econ = derive_economic(&c, &env);
        let commitment = if seq == 0 {
            Hash([0u8; 32])
        } else {
            Hash([0xABu8; 32])
        };
        let meta = TraceMetadata {
            sequence_index: seq,
            previous_commitment: commitment,
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

    fn make_input(payload_type: &str, data: Vec<u8>) -> Input {
        Input {
            payload: Payload {
                payload_type: payload_type.to_string(),
                data,
            },
            auth: valid_auth(),
            aux: AuxiliaryData { data: vec![] },
        }
    }

    fn make_deposit_input(account_id: [u8; 32], amount: u128) -> Input {
        let mut data = vec![];
        data.extend_from_slice(&account_id);
        data.extend_from_slice(&amount.to_le_bytes());
        make_input("deposit", data)
    }

    fn make_transfer_input(sender: [u8; 32], receiver: [u8; 32], amount: u128) -> Input {
        let mut data = vec![];
        data.extend_from_slice(&sender);
        data.extend_from_slice(&receiver);
        data.extend_from_slice(&amount.to_le_bytes());
        make_input("transfer", data)
    }

    // -----------------------------------------------------------------------
    // Empty batch
    // -----------------------------------------------------------------------

    #[test]
    fn test_batch_empty_inputs() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        let result = execute_batch(&s, &[]);
        assert!(result.is_ok());
        let batch = result.unwrap();
        assert_eq!(batch.pre_state.canonical, s.canonical);
        assert_eq!(batch.post_state.canonical, s.canonical);
        assert_eq!(batch.transition_class, TransitionClass::Batch);
        assert!(batch.intermediate_results.is_empty());
    }

    // -----------------------------------------------------------------------
    // Single input batch
    // -----------------------------------------------------------------------

    #[test]
    fn test_batch_single_input() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        let deposit = make_deposit_input([1u8; 32], 500);

        let result = execute_batch(&s, &[deposit.clone()]);
        assert!(result.is_ok());
        let batch = result.unwrap();

        assert_eq!(batch.intermediate_results.len(), 1);
        assert_eq!(batch.transition_class, TransitionClass::Batch);
        assert_eq!(
            batch.post_state.canonical.accounts[&AccountId([1u8; 32])].balance,
            500
        );
    }

    // -----------------------------------------------------------------------
    // Sequential equivalence (LEM-9)
    // -----------------------------------------------------------------------

    #[test]
    fn test_batch_sequential_equivalence() {
        // Verify: apply(s, [σ₁, σ₂]) = apply(apply(s, σ₁), σ₂)
        let s = build_state_at_seq(minimal_canonical(), 1);
        let deposit1 = make_deposit_input([1u8; 32], 500);
        let deposit2 = make_deposit_input([2u8; 32], 300);

        // Batch execution
        let batch_result = execute_batch(&s, &[deposit1.clone(), deposit2.clone()]).unwrap();

        // Sequential execution via apply
        let s1 = apply(&s, &deposit1);
        let s2 = apply(&s1, &deposit2);

        // The canonical states must match (sequential equivalence).
        assert_eq!(
            batch_result.post_state.canonical, s2.canonical,
            "Batch must be equivalent to sequential application (LEM-9)"
        );
    }

    // -----------------------------------------------------------------------
    // Multiple deposits
    // -----------------------------------------------------------------------

    #[test]
    fn test_batch_multiple_deposits() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        let deposit1 = make_deposit_input([1u8; 32], 100);
        let deposit2 = make_deposit_input([1u8; 32], 200);
        let deposit3 = make_deposit_input([2u8; 32], 300);

        let result = execute_batch(&s, &[deposit1, deposit2, deposit3]).unwrap();

        assert_eq!(result.intermediate_results.len(), 3);
        assert_eq!(
            result.post_state.canonical.accounts[&AccountId([1u8; 32])].balance,
            300
        );
        assert_eq!(
            result.post_state.canonical.accounts[&AccountId([2u8; 32])].balance,
            300
        );
        assert_eq!(result.post_state.canonical.system_data.total_supply, 600);
    }

    // -----------------------------------------------------------------------
    // Deposit then transfer
    // -----------------------------------------------------------------------

    #[test]
    fn test_batch_deposit_then_transfer() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        let deposit = make_deposit_input([1u8; 32], 1000);
        let transfer = make_transfer_input([1u8; 32], [2u8; 32], 400);

        let result = execute_batch(&s, &[deposit, transfer]).unwrap();

        assert_eq!(result.intermediate_results.len(), 2);
        assert_eq!(
            result.post_state.canonical.accounts[&AccountId([1u8; 32])].balance,
            600
        );
        assert_eq!(
            result.post_state.canonical.accounts[&AccountId([2u8; 32])].balance,
            400
        );
        // Total supply conserved: deposit added 1000, transfer conserves.
        assert_eq!(result.post_state.canonical.system_data.total_supply, 1000);
    }

    // -----------------------------------------------------------------------
    // Failure halts batch — no partial application
    // -----------------------------------------------------------------------

    #[test]
    fn test_batch_halts_on_failure() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        let deposit = make_deposit_input([1u8; 32], 500);
        // Invalid input: empty payload type
        let invalid = Input {
            payload: Payload {
                payload_type: String::new(),
                data: vec![],
            },
            auth: valid_auth(),
            aux: AuxiliaryData { data: vec![] },
        };
        let deposit2 = make_deposit_input([2u8; 32], 300);

        // The invalid input is second — batch should fail there.
        let result = execute_batch(&s, &[deposit, invalid, deposit2]);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ExecutionError::MalformedInput(_)
        ));
    }

    // -----------------------------------------------------------------------
    // Ordering preserved
    // -----------------------------------------------------------------------

    #[test]
    fn test_batch_preserves_ordering() {
        // Deposit to account 1, then transfer from 1 to 2.
        // If order were reversed, transfer would fail (no balance).
        let s = build_state_at_seq(minimal_canonical(), 1);
        let deposit = make_deposit_input([1u8; 32], 1000);
        let transfer = make_transfer_input([1u8; 32], [2u8; 32], 500);

        let result = execute_batch(&s, &[deposit, transfer]);
        assert!(result.is_ok(), "Correct order should succeed");

        // Reversed order: transfer first (should fail precondition).
        let transfer2 = make_transfer_input([1u8; 32], [2u8; 32], 500);
        let deposit2 = make_deposit_input([1u8; 32], 1000);
        let result_reversed = execute_batch(&s, &[transfer2, deposit2]);
        assert!(
            result_reversed.is_err(),
            "Reversed order should fail — ordering must be preserved"
        );
    }

    // -----------------------------------------------------------------------
    // Combined observable
    // -----------------------------------------------------------------------

    #[test]
    fn test_batch_combined_observable() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        let deposit1 = make_deposit_input([1u8; 32], 100);
        let deposit2 = make_deposit_input([2u8; 32], 200);

        let result = execute_batch(&s, &[deposit1, deposit2]).unwrap();

        assert_eq!(result.observable.transition_class, TransitionClass::Batch);
        assert_eq!(result.observable.status, TransitionStatus::Success);
        // Gas should be sum of individual gas costs.
        let individual_gas_sum: u64 = result
            .intermediate_results
            .iter()
            .map(|r| r.observable.gas_used)
            .sum();
        assert_eq!(result.observable.gas_used, individual_gas_sum);
        // Outputs should be concatenation of individual outputs.
        let individual_output_count: usize = result
            .intermediate_results
            .iter()
            .map(|r| r.observable.outputs.len())
            .sum();
        assert_eq!(result.observable.outputs.len(), individual_output_count);
    }

    // -----------------------------------------------------------------------
    // Trace entry
    // -----------------------------------------------------------------------

    #[test]
    fn test_batch_trace_entry() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        let deposit = make_deposit_input([1u8; 32], 500);

        let result = execute_batch(&s, &[deposit]).unwrap();

        assert_eq!(
            result.trace_entry.pre_state_commitment,
            commit(&s.canonical)
        );
        assert_eq!(
            result.trace_entry.post_state_commitment,
            commit(&result.post_state.canonical)
        );
        assert_eq!(
            result.trace_entry.transition_class,
            TransitionClass::Batch
        );
    }

    // -----------------------------------------------------------------------
    // Pre-state preserved in result
    // -----------------------------------------------------------------------

    #[test]
    fn test_batch_pre_state_is_original() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        let deposit = make_deposit_input([1u8; 32], 500);

        let result = execute_batch(&s, &[deposit]).unwrap();

        assert_eq!(
            result.pre_state, s,
            "pre_state must be the original state before any inputs"
        );
    }

    // -----------------------------------------------------------------------
    // Intermediate results match sequential execution
    // -----------------------------------------------------------------------

    #[test]
    fn test_batch_intermediate_results_match_sequential() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        let deposit1 = make_deposit_input([1u8; 32], 100);
        let deposit2 = make_deposit_input([2u8; 32], 200);

        let batch = execute_batch(&s, &[deposit1.clone(), deposit2.clone()]).unwrap();

        // Execute sequentially via engine
        let engine = DefaultExecutionEngine;
        let r1 = engine.execute(&s, &deposit1).unwrap();
        let r2 = engine.execute(&r1.post_state, &deposit2).unwrap();

        assert_eq!(batch.intermediate_results.len(), 2);
        assert_eq!(batch.intermediate_results[0], r1);
        assert_eq!(batch.intermediate_results[1], r2);
    }
}
