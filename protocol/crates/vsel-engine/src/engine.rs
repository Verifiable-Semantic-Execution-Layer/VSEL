//! Execution Engine — main public API wrapping the 7-step pipeline.
//!
//! Derived from: STATE_MACHINE.md §6, TECH_SPEC.md §4,
//! FORMAL_SPECIFICATION.md §3.
//! Requirements: 2.1, 2.3, 2.4
//!
//! The `ExecutionEngine` trait is the top-level entry point for executing
//! state transitions. It wraps `run_pipeline`, the guard system, and adds
//! bounded state mutation verification.
//!
//! Bounded state mutation (Req 2.4):
//!   After `run_pipeline` succeeds, verify that `Diff(s, s') ⊆ AllowedMutations(σ)`.
//!   Fields not expected to change must be equal.

use std::fmt;

use vsel_core::input::Input;
use vsel_core::observable::Observable;
use vsel_core::state::{commit, State};
use vsel_core::transition::TransitionClass;
use vsel_core::types::Hash;

use crate::pipeline::{run_pipeline, PipelineError, PipelineOutput};

// ---------------------------------------------------------------------------
// TraceEntry — lightweight trace entry for engine results
// ---------------------------------------------------------------------------

/// Lightweight trace entry produced by the execution engine.
///
/// This is a minimal struct for engine-level results, not the full
/// trace engine's `TraceEntry` (which lives in `vsel-trace`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceEntry {
    /// Monotonically increasing index.
    pub index: u64,
    /// Commitment of the pre-state canonical data.
    pub pre_state_commitment: Hash,
    /// Commitment of the post-state canonical data.
    pub post_state_commitment: Hash,
    /// The transition class that was applied.
    pub transition_class: TransitionClass,
}

// ---------------------------------------------------------------------------
// ExecutionResult
// ---------------------------------------------------------------------------

/// Successful result of executing a transition through the engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionResult {
    /// The state before the transition.
    pub pre_state: State,
    /// The state after the transition.
    pub post_state: State,
    /// Observable output of the transition.
    pub observable: Observable,
    /// The transition class that was applied.
    pub transition_class: TransitionClass,
    /// Lightweight trace entry for this transition.
    pub trace_entry: TraceEntry,
}

// ---------------------------------------------------------------------------
// ExecutionError
// ---------------------------------------------------------------------------

/// Error type for the execution engine.
///
/// Wraps `PipelineError` and adds bounded mutation violation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecutionError {
    /// Input is structurally malformed.
    MalformedInput(String),
    /// Authorization check failed.
    Unauthorized(String),
    /// State-dependent precondition violated.
    PreconditionViolation(String),
    /// Postcondition / invariant violated on result state.
    PostconditionViolation(String),
    /// Derived state does not match recomputed value.
    DerivedStateMismatch(String),
    /// Pipeline steps executed out of order.
    PipelineOrderViolation(String),
    /// An invariant was violated during execution.
    InvariantViolation(String),
    /// Nondeterminism detected — same inputs produced different outputs.
    NondeterminismDetected(String),
    /// Bounded state mutation violated: Diff(s, s') ⊄ AllowedMutations(σ).
    BoundedMutationViolation(String),
}

impl fmt::Display for ExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedInput(r) => write!(f, "Malformed input: {r}"),
            Self::Unauthorized(r) => write!(f, "Unauthorized: {r}"),
            Self::PreconditionViolation(r) => write!(f, "Precondition violation: {r}"),
            Self::PostconditionViolation(r) => write!(f, "Postcondition violation: {r}"),
            Self::DerivedStateMismatch(r) => write!(f, "Derived state mismatch: {r}"),
            Self::PipelineOrderViolation(r) => write!(f, "Pipeline order violation: {r}"),
            Self::InvariantViolation(r) => write!(f, "Invariant violation: {r}"),
            Self::NondeterminismDetected(r) => write!(f, "Nondeterminism detected: {r}"),
            Self::BoundedMutationViolation(r) => write!(f, "Bounded mutation violation: {r}"),
        }
    }
}

impl From<PipelineError> for ExecutionError {
    fn from(e: PipelineError) -> Self {
        match e {
            PipelineError::MalformedInput { reason } => Self::MalformedInput(reason),
            PipelineError::Unauthorized { reason } => Self::Unauthorized(reason),
            PipelineError::PreconditionViolation { reason } => Self::PreconditionViolation(reason),
            PipelineError::PostconditionViolation { reason } => {
                Self::PostconditionViolation(reason)
            }
            PipelineError::DerivedStateMismatch { reason } => Self::DerivedStateMismatch(reason),
            PipelineError::PipelineOrderViolation { reason } => {
                Self::PipelineOrderViolation(reason)
            }
            PipelineError::InvariantViolation { details } => Self::InvariantViolation(details),
            PipelineError::NondeterminismDetected { reason } => {
                Self::NondeterminismDetected(reason)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ExecutionEngine trait
// ---------------------------------------------------------------------------

/// Core execution engine trait — deterministic, total.
///
/// This is the main public API for executing state transitions.
/// It wraps the 7-step pipeline, guard system, and bounded mutation checks.
///
/// Requirements: 2.1, 2.3, 2.4
pub trait ExecutionEngine {
    /// Execute a single transition through the 7-step pipeline.
    ///
    /// Steps:
    /// 1. Run the full pipeline (`run_pipeline`).
    /// 2. Verify bounded state mutation: `Diff(s, s') ⊆ AllowedMutations(σ)`.
    /// 3. Build and return `ExecutionResult` with trace entry.
    fn execute(&self, state: &State, input: &Input) -> Result<ExecutionResult, ExecutionError>;
}

// ---------------------------------------------------------------------------
// DefaultExecutionEngine
// ---------------------------------------------------------------------------

/// Default implementation of the `ExecutionEngine` trait.
///
/// Delegates to `run_pipeline` for the 7-step pipeline, then performs
/// bounded state mutation verification.
pub struct DefaultExecutionEngine;

impl ExecutionEngine for DefaultExecutionEngine {
    fn execute(&self, state: &State, input: &Input) -> Result<ExecutionResult, ExecutionError> {
        // Run the full 7-step pipeline.
        let PipelineOutput {
            post_state,
            observable,
            transition_class: pipeline_class,
        } = run_pipeline(state, input)?;

        // Verify bounded state mutation: Diff(s, s') ⊆ AllowedMutations(σ).
        check_bounded_mutation(state, &post_state, pipeline_class)?;

        // Build lightweight trace entry.
        let trace_entry = TraceEntry {
            index: post_state.metadata.sequence_index,
            pre_state_commitment: commit(&state.canonical),
            post_state_commitment: commit(&post_state.canonical),
            transition_class: pipeline_class,
        };

        Ok(ExecutionResult {
            pre_state: state.clone(),
            post_state,
            observable,
            transition_class: pipeline_class,
            trace_entry,
        })
    }
}

// ---------------------------------------------------------------------------
// Bounded state mutation check (Req 2.4)
// ---------------------------------------------------------------------------

/// Verify that `Diff(s, s') ⊆ AllowedMutations(σ)`.
///
/// For each transition class, only specific fields are allowed to change.
/// All other fields must remain equal between pre-state and post-state.
///
/// Allowed mutations per class:
/// - **Reject / Error / Noop**: canonical state unchanged, only metadata advances.
/// - **Init**: canonical.system_data.parameters may change, metadata advances.
/// - **Update / Batch**: canonical.accounts, canonical.storage, canonical.system_data
///   may change, metadata advances.
///
/// In all cases:
/// - `environment` must be unchanged (environment is external context).
/// - `derived` and `economic` are recomputed (checked by pipeline step 6).
/// - `metadata` is expected to advance (sequence_index increments).
fn check_bounded_mutation(
    pre: &State,
    post: &State,
    class: TransitionClass,
) -> Result<(), ExecutionError> {
    // Environment must never change during a transition.
    if pre.environment != post.environment {
        return Err(ExecutionError::BoundedMutationViolation(
            "Environment changed during transition — environment is immutable within a transition"
                .to_string(),
        ));
    }

    match class {
        TransitionClass::Reject | TransitionClass::Error | TransitionClass::Noop => {
            // Canonical state must be unchanged.
            if pre.canonical != post.canonical {
                return Err(ExecutionError::BoundedMutationViolation(format!(
                    "{:?} transition must not mutate canonical state",
                    class
                )));
            }
        }
        TransitionClass::Init => {
            // Init may change system_data.parameters but accounts and storage
            // should remain unchanged (init sets up parameters only).
            if pre.canonical.accounts != post.canonical.accounts {
                return Err(ExecutionError::BoundedMutationViolation(
                    "Init transition must not mutate accounts".to_string(),
                ));
            }
            if pre.canonical.storage != post.canonical.storage {
                return Err(ExecutionError::BoundedMutationViolation(
                    "Init transition must not mutate storage".to_string(),
                ));
            }
            // system_data.protocol_version must not change.
            if pre.canonical.system_data.protocol_version
                != post.canonical.system_data.protocol_version
            {
                return Err(ExecutionError::BoundedMutationViolation(
                    "Init transition must not change protocol version".to_string(),
                ));
            }
        }
        TransitionClass::Update | TransitionClass::Batch => {
            // Update and Batch may mutate accounts, storage, and system_data.
            // protocol_version must not change within a transition.
            if pre.canonical.system_data.protocol_version
                != post.canonical.system_data.protocol_version
            {
                return Err(ExecutionError::BoundedMutationViolation(
                    "Update/Batch transition must not change protocol version".to_string(),
                ));
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use vsel_core::input::Authorization;
    use vsel_core::state::{
        derive, derive_economic, AccountData, CanonicalState, Environment, TraceMetadata,
    };
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

    fn make_invalid_input() -> Input {
        Input {
            payload: Payload {
                payload_type: String::new(),
                data: vec![],
            },
            auth: valid_auth(),
            aux: AuxiliaryData { data: vec![] },
        }
    }

    // -- ExecutionEngine tests --

    #[test]
    fn test_execute_init_succeeds() {
        let engine = DefaultExecutionEngine;
        let s = build_state_at_seq(minimal_canonical(), 0);
        let sigma = make_input("init", vec![0xFF]);
        let result = engine.execute(&s, &sigma);
        assert!(result.is_ok());
        let er = result.unwrap();
        assert_eq!(er.transition_class, TransitionClass::Init);
        assert_eq!(er.pre_state, s);
        assert_eq!(
            er.post_state
                .canonical
                .system_data
                .parameters
                .get("initialized"),
            Some(&vec![1u8])
        );
    }

    #[test]
    fn test_execute_deposit_succeeds() {
        let engine = DefaultExecutionEngine;
        let s = build_state_at_seq(minimal_canonical(), 1);
        let mut data = vec![];
        data.extend_from_slice(&[1u8; 32]);
        data.extend_from_slice(&500u128.to_le_bytes());
        let sigma = make_input("deposit", data);
        let result = engine.execute(&s, &sigma);
        assert!(result.is_ok());
        let er = result.unwrap();
        assert_eq!(er.transition_class, TransitionClass::Update);
        assert_eq!(
            er.post_state.canonical.accounts[&AccountId([1u8; 32])].balance,
            500
        );
    }

    #[test]
    fn test_execute_transfer_succeeds() {
        let engine = DefaultExecutionEngine;
        let mut c = minimal_canonical();
        let sender_id = AccountId([1u8; 32]);
        let receiver_id = AccountId([2u8; 32]);
        c.accounts.insert(
            sender_id,
            AccountData {
                balance: 1000,
                nonce: 0,
                data: vec![],
            },
        );
        c.accounts.insert(
            receiver_id,
            AccountData {
                balance: 500,
                nonce: 0,
                data: vec![],
            },
        );
        c.system_data.total_supply = 1500;
        let s = build_state_at_seq(c, 1);

        let mut data = vec![];
        data.extend_from_slice(&[1u8; 32]);
        data.extend_from_slice(&[2u8; 32]);
        data.extend_from_slice(&100u128.to_le_bytes());
        let sigma = make_input("transfer", data);

        let result = engine.execute(&s, &sigma);
        assert!(result.is_ok());
        let er = result.unwrap();
        assert_eq!(er.transition_class, TransitionClass::Update);
        assert_eq!(
            er.post_state.canonical.system_data.total_supply, 1500,
            "transfer must conserve total supply"
        );
    }

    #[test]
    fn test_execute_invalid_input_fails() {
        let engine = DefaultExecutionEngine;
        let s = build_state_at_seq(minimal_canonical(), 1);
        let sigma = make_invalid_input();
        let result = engine.execute(&s, &sigma);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ExecutionError::MalformedInput(_)
        ));
    }

    #[test]
    fn test_execute_precondition_failure() {
        let engine = DefaultExecutionEngine;
        let s = build_state_at_seq(minimal_canonical(), 1);
        let sigma = make_input("transfer", vec![1u8; 32]);
        let result = engine.execute(&s, &sigma);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ExecutionError::PreconditionViolation(_)
        ));
    }

    #[test]
    fn test_execute_noop_succeeds() {
        let engine = DefaultExecutionEngine;
        let s = build_state_at_seq(minimal_canonical(), 1);
        let sigma = make_input("unknown_op", vec![0x01]);
        let result = engine.execute(&s, &sigma);
        assert!(result.is_ok());
        let er = result.unwrap();
        assert_eq!(er.transition_class, TransitionClass::Noop);
        assert_eq!(er.pre_state.canonical, er.post_state.canonical);
    }

    #[test]
    fn test_execute_batch_succeeds() {
        let engine = DefaultExecutionEngine;
        let s = build_state_at_seq(minimal_canonical(), 1);
        let sigma = make_input("batch", vec![0x01]);
        let result = engine.execute(&s, &sigma);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().transition_class, TransitionClass::Batch);
    }

    #[test]
    fn test_execute_deterministic() {
        let engine = DefaultExecutionEngine;
        let s = build_state_at_seq(minimal_canonical(), 0);
        let sigma = make_input("init", vec![0xFF]);
        let r1 = engine.execute(&s, &sigma);
        let r2 = engine.execute(&s, &sigma);
        assert!(r1.is_ok());
        assert!(r2.is_ok());
        assert_eq!(r1.unwrap(), r2.unwrap(), "Engine must be deterministic");
    }

    #[test]
    fn test_trace_entry_commitments() {
        let engine = DefaultExecutionEngine;
        let s = build_state_at_seq(minimal_canonical(), 0);
        let sigma = make_input("init", vec![0xFF]);
        let result = engine.execute(&s, &sigma).unwrap();

        let expected_pre = commit(&s.canonical);
        let expected_post = commit(&result.post_state.canonical);
        assert_eq!(result.trace_entry.pre_state_commitment, expected_pre);
        assert_eq!(result.trace_entry.post_state_commitment, expected_post);
        assert_eq!(result.trace_entry.transition_class, TransitionClass::Init);
    }

    #[test]
    fn test_trace_entry_index() {
        let engine = DefaultExecutionEngine;
        let s = build_state_at_seq(minimal_canonical(), 0);
        let sigma = make_input("init", vec![0xFF]);
        let result = engine.execute(&s, &sigma).unwrap();
        // The trace entry index should be the post-state sequence_index.
        assert_eq!(
            result.trace_entry.index,
            result.post_state.metadata.sequence_index
        );
    }

    // -- Bounded mutation tests --

    #[test]
    fn test_bounded_mutation_reject_preserves_canonical() {
        // Reject transitions must not change canonical state.
        // This is implicitly tested via the pipeline, but we verify
        // the engine's bounded mutation check would catch violations.
        let pre = build_state_at_seq(minimal_canonical(), 1);
        let post = build_state_at_seq(minimal_canonical(), 1);
        // Same canonical state → should pass.
        assert!(check_bounded_mutation(&pre, &post, TransitionClass::Reject).is_ok());
    }

    #[test]
    fn test_bounded_mutation_reject_detects_violation() {
        let pre = build_state_at_seq(minimal_canonical(), 1);
        let mut c2 = minimal_canonical();
        c2.system_data
            .parameters
            .insert("rogue".to_string(), vec![1]);
        let mut post = build_state_at_seq(c2, 1);
        post.environment = pre.environment.clone();
        assert!(check_bounded_mutation(&pre, &post, TransitionClass::Reject).is_err());
    }

    #[test]
    fn test_bounded_mutation_environment_immutable() {
        let pre = build_state_at_seq(minimal_canonical(), 1);
        let mut post = pre.clone();
        post.environment.timestamp = 999_999;
        assert!(check_bounded_mutation(&pre, &post, TransitionClass::Update).is_err());
    }

    #[test]
    fn test_bounded_mutation_init_no_account_change() {
        let pre = build_state_at_seq(minimal_canonical(), 0);
        let mut post = pre.clone();
        post.canonical.accounts.insert(
            AccountId([1u8; 32]),
            AccountData {
                balance: 100,
                nonce: 0,
                data: vec![],
            },
        );
        assert!(check_bounded_mutation(&pre, &post, TransitionClass::Init).is_err());
    }

    #[test]
    fn test_bounded_mutation_update_no_version_change() {
        let pre = build_state_at_seq(minimal_canonical(), 1);
        let mut post = pre.clone();
        post.canonical.system_data.protocol_version.major = 99;
        assert!(check_bounded_mutation(&pre, &post, TransitionClass::Update).is_err());
    }

    // -- ExecutionError Display --

    #[test]
    fn test_execution_error_display() {
        let err = ExecutionError::BoundedMutationViolation("test".to_string());
        assert!(err.to_string().contains("Bounded mutation violation"));
    }

    // -- From<PipelineError> --

    #[test]
    fn test_pipeline_error_conversion() {
        let pe = PipelineError::MalformedInput {
            reason: "bad".to_string(),
        };
        let ee: ExecutionError = pe.into();
        assert!(matches!(ee, ExecutionError::MalformedInput(_)));
    }
}
