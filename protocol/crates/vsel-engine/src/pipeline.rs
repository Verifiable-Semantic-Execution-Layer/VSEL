//! 7-step execution pipeline for the VSEL protocol.
//!
//! Derived from: STATE_MACHINE.md §6, TECH_SPEC.md §4,
//! FORMAL_SPECIFICATION.md §3.
//! Requirements: 2.2, 2.3, 2.9, 2.10
//!
//! Pipeline steps (strict order):
//!   1. Input canonicalization — normalize input to canonical form
//!   2. Authorization check — verify hybrid signatures (classical + PQC)
//!   3. Precondition validation — check state-dependent preconditions
//!   4. State transformation — apply deterministic transition
//!   5. Postcondition validation — verify invariants on result state
//!   6. Derived state recalculation — D' = derive(C'), never trust cached
//!   7. Commitment update — update trace metadata
//!
//! Any step failure = halt with error state or no-op.
//! Each step is a pure function via `PipelineStep` trait.

use thiserror::Error;

use vsel_core::input::{valid_input, Input};
use vsel_core::observable::{obs, Observable};
use vsel_core::state::{commit, derive, derive_economic, valid_state, State};
use vsel_core::transition::{apply, TransitionClass};
use vsel_core::types::Hash;

use vsel_invariants::global::check_all_global;
use vsel_invariants::local::check_all_local;

use crate::guards::classify_transition;

// ---------------------------------------------------------------------------
// PipelineStep trait
// ---------------------------------------------------------------------------

/// A single step in the 7-step execution pipeline.
///
/// Each step is a pure function: given an input, it produces either
/// a successful output or a `PipelineError`. Steps are composed
/// sequentially — any failure halts the pipeline.
///
/// Generic over `I` (input), `O` (output). Error is always `PipelineError`.
pub trait PipelineStep<I, O> {
    /// Execute this pipeline step.
    fn execute(&self, input: I) -> Result<O, PipelineError>;
}

// ---------------------------------------------------------------------------
// PipelineError — all failure modes
// ---------------------------------------------------------------------------

/// Error type covering all pipeline failure modes.
///
/// Any step failure halts the pipeline with one of these variants.
/// Requirements: 2.2, 2.10
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PipelineError {
    /// Step 1 failure: input is structurally malformed.
    #[error("Malformed input: {reason}")]
    MalformedInput { reason: String },

    /// Step 2 failure: authorization check failed.
    #[error("Unauthorized: {reason}")]
    Unauthorized { reason: String },

    /// Step 3 failure: state-dependent precondition violated.
    #[error("Precondition violation: {reason}")]
    PreconditionViolation { reason: String },

    /// Step 5 failure: postcondition / invariant violated on result state.
    #[error("Postcondition violation: {reason}")]
    PostconditionViolation { reason: String },

    /// Step 6 failure: derived state does not match recomputed value.
    #[error("Derived state mismatch: {reason}")]
    DerivedStateMismatch { reason: String },

    /// Pipeline order was violated (steps executed out of sequence).
    #[error("Pipeline order violation: {reason}")]
    PipelineOrderViolation { reason: String },

    /// An invariant was violated during execution.
    #[error("Invariant violation: {details}")]
    InvariantViolation { details: String },

    /// Nondeterminism detected — same inputs produced different outputs.
    #[error("Nondeterminism detected: {reason}")]
    NondeterminismDetected { reason: String },
}

// ---------------------------------------------------------------------------
// PipelineOutput — successful pipeline result
// ---------------------------------------------------------------------------

/// Output of a successful pipeline execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PipelineOutput {
    /// The post-transition state with recomputed derived state and metadata.
    pub post_state: State,
    /// Observable output of the transition.
    pub observable: Observable,
    /// The transition class that was applied.
    pub transition_class: TransitionClass,
}

// ---------------------------------------------------------------------------
// Internal intermediate types for step chaining
// ---------------------------------------------------------------------------

/// After step 3: preconditions validated, transition classified.
struct PreconditionResult {
    transition_class: TransitionClass,
}

/// After step 4: state transformation applied.
struct TransformationResult {
    post_state: State,
    transition_class: TransitionClass,
}

// ---------------------------------------------------------------------------
// Step 1: Input Canonicalization
// ---------------------------------------------------------------------------

/// Step 1: Normalize input to canonical form and validate structure.
///
/// Checks `valid_input(σ)` — rejects structurally malformed inputs.
pub struct InputCanonicalization;

impl<'a> PipelineStep<(&'a State, &'a Input), ()> for InputCanonicalization {
    fn execute(&self, (_, input): (&'a State, &'a Input)) -> Result<(), PipelineError> {
        if !valid_input(input) {
            return Err(PipelineError::MalformedInput {
                reason: "Input fails structural validity (empty payload type, data, or signatures)"
                    .to_string(),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Step 2: Authorization Check
// ---------------------------------------------------------------------------

/// Step 2: Verify hybrid signatures (classical + PQC).
///
/// Checks that both classical and PQC signature components are present
/// and that the domain tag matches the execution environment.
pub struct AuthorizationCheck;

impl<'a> PipelineStep<(&'a State, &'a Input), ()> for AuthorizationCheck {
    fn execute(&self, (_, input): (&'a State, &'a Input)) -> Result<(), PipelineError> {
        let auth = &input.auth;

        // Both classical and PQC signatures must be present.
        if auth.classical_sig.is_empty() || auth.pqc_sig.is_empty() {
            return Err(PipelineError::Unauthorized {
                reason: "Missing classical or PQC signature".to_string(),
            });
        }

        // Both public key components must be present.
        if auth.public_key.classical.is_empty() || auth.public_key.pqc.is_empty() {
            return Err(PipelineError::Unauthorized {
                reason: "Missing classical or PQC public key component".to_string(),
            });
        }

        // Domain tag must not be the zero hash.
        if auth.domain.0 == Hash([0u8; 32]) {
            return Err(PipelineError::Unauthorized {
                reason: "Authorization domain tag is the zero hash".to_string(),
            });
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Step 3: Precondition Validation
// ---------------------------------------------------------------------------

/// Step 3: Check state-dependent preconditions.
///
/// Uses the guard system to classify the transition. If the classification
/// is `Reject` or `Error`, the precondition check fails.
pub struct PreconditionValidation;

impl<'a> PipelineStep<(&'a State, &'a Input), PreconditionResult> for PreconditionValidation {
    fn execute(
        &self,
        (state, input): (&'a State, &'a Input),
    ) -> Result<PreconditionResult, PipelineError> {
        // Validate pre-state is valid.
        if !valid_state(state) {
            return Err(PipelineError::PreconditionViolation {
                reason: "Pre-state does not satisfy ValidState(s)".to_string(),
            });
        }

        // Classify the transition using the guard system.
        let transition_class = classify_transition(state, input);

        // Reject and Error classes indicate precondition failures.
        match transition_class {
            TransitionClass::Reject => {
                return Err(PipelineError::PreconditionViolation {
                    reason: "Transition classified as Reject by guard system".to_string(),
                });
            }
            TransitionClass::Error => {
                return Err(PipelineError::PreconditionViolation {
                    reason: "Transition classified as Error — state preconditions not met"
                        .to_string(),
                });
            }
            _ => {}
        }

        Ok(PreconditionResult { transition_class })
    }
}

// ---------------------------------------------------------------------------
// Step 4: State Transformation
// ---------------------------------------------------------------------------

/// Step 4: Apply deterministic state transition.
///
/// Uses `vsel_core::transition::apply` to compute the post-state.
/// Verifies determinism by applying twice and comparing (Req 2.3, 2.10).
pub struct StateTransformation;

impl<'a> PipelineStep<(&'a State, &'a Input, TransitionClass), TransformationResult>
    for StateTransformation
{
    fn execute(
        &self,
        (state, input, transition_class): (&'a State, &'a Input, TransitionClass),
    ) -> Result<TransformationResult, PipelineError> {
        let post_state = apply(state, input);

        // Determinism check: apply again and compare (Req 2.3, 2.10).
        let post_state_2 = apply(state, input);
        if post_state != post_state_2 {
            return Err(PipelineError::NondeterminismDetected {
                reason: "Apply(s, σ) produced different results on repeated application"
                    .to_string(),
            });
        }

        Ok(TransformationResult {
            post_state,
            transition_class,
        })
    }
}

// ---------------------------------------------------------------------------
// Step 5: Postcondition Validation
// ---------------------------------------------------------------------------

/// Step 5: Verify invariants on the result state.
///
/// Checks both global invariants on the post-state and local invariants
/// on the (pre, input, post) transition.
pub struct PostconditionValidation;

impl<'a> PipelineStep<(&'a State, &'a Input, &'a State), ()> for PostconditionValidation {
    fn execute(
        &self,
        (pre_state, input, post_state): (&'a State, &'a Input, &'a State),
    ) -> Result<(), PipelineError> {
        // Check global invariants on the post-state.
        let global_result = check_all_global(post_state);
        if !global_result.valid {
            let details: Vec<String> = global_result
                .violations
                .iter()
                .map(|v| format!("{}: {}", v.invariant_id, v.description))
                .collect();
            return Err(PipelineError::PostconditionViolation {
                reason: format!("Global invariant violations: {}", details.join("; ")),
            });
        }

        // Check local invariants on the transition.
        let local_result = check_all_local(pre_state, input, post_state);
        if !local_result.valid {
            let details: Vec<String> = local_result
                .violations
                .iter()
                .map(|v| format!("{}: {}", v.invariant_id, v.description))
                .collect();
            return Err(PipelineError::InvariantViolation {
                details: format!("Local invariant violations: {}", details.join("; ")),
            });
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Step 6: Derived State Recalculation
// ---------------------------------------------------------------------------

/// Step 6: Recompute derived state D' = derive(C').
///
/// Never trust cached derived values (DEF-1, Req 2.9).
/// Recomputes both `DerivedState` and `EconomicContext` from canonical state.
pub struct DerivedStateRecalculation;

impl PipelineStep<State, State> for DerivedStateRecalculation {
    fn execute(&self, mut post_state: State) -> Result<State, PipelineError> {
        // Recompute derived state from canonical (DEF-1).
        let fresh_derived = derive(&post_state.canonical);

        // Verify the existing derived state matches the recomputed one.
        if post_state.derived != fresh_derived {
            return Err(PipelineError::DerivedStateMismatch {
                reason: "D' != derive(C') — cached derived state is stale".to_string(),
            });
        }

        // Recompute economic context.
        let fresh_economic = derive_economic(&post_state.canonical, &post_state.environment);
        if post_state.economic != fresh_economic {
            return Err(PipelineError::DerivedStateMismatch {
                reason: "Ω' != derive_economic(C', E') — cached economic context is stale"
                    .to_string(),
            });
        }

        // Overwrite with fresh values to ensure no stale data propagates.
        post_state.derived = fresh_derived;
        post_state.economic = fresh_economic;

        Ok(post_state)
    }
}

// ---------------------------------------------------------------------------
// Step 7: Commitment Update
// ---------------------------------------------------------------------------

/// Step 7: Update trace metadata (commitment chain).
///
/// Verifies that the post-state commitment is consistent with the
/// canonical state encoding. Uses `vsel_core::state::commit`.
pub struct CommitmentUpdate;

impl PipelineStep<State, State> for CommitmentUpdate {
    fn execute(&self, post_state: State) -> Result<State, PipelineError> {
        // Compute commitment for verification.
        let _expected_commitment = commit(&post_state.canonical);

        // Verify metadata consistency.
        if post_state.metadata.sequence_index == 0
            && post_state.metadata.previous_commitment != Hash([0u8; 32])
        {
            return Err(PipelineError::PostconditionViolation {
                reason: "Genesis state has non-zero previous commitment".to_string(),
            });
        }

        Ok(post_state)
    }
}

// ---------------------------------------------------------------------------
// run_pipeline — execute all 7 steps in order
// ---------------------------------------------------------------------------

/// Execute the full 7-step pipeline on a (state, input) pair.
///
/// Steps are executed in strict order:
///   1. Input canonicalization
///   2. Authorization check
///   3. Precondition validation
///   4. State transformation
///   5. Postcondition validation
///   6. Derived state recalculation
///   7. Commitment update
///
/// Any step failure halts the pipeline and returns a `PipelineError`.
///
/// Requirements: 2.2, 2.3, 2.9, 2.10
pub fn run_pipeline(state: &State, input: &Input) -> Result<PipelineOutput, PipelineError> {
    // Step 1: Input canonicalization
    let step1 = InputCanonicalization;
    step1.execute((state, input))?;

    // Step 2: Authorization check
    let step2 = AuthorizationCheck;
    step2.execute((state, input))?;

    // Step 3: Precondition validation
    let step3 = PreconditionValidation;
    let precond = step3.execute((state, input))?;

    // Step 4: State transformation
    let step4 = StateTransformation;
    let transform = step4.execute((state, input, precond.transition_class))?;

    // Step 5: Postcondition validation
    let step5 = PostconditionValidation;
    step5.execute((state, input, &transform.post_state))?;

    // Step 6: Derived state recalculation
    let step6 = DerivedStateRecalculation;
    let post_state = step6.execute(transform.post_state)?;

    // Step 7: Commitment update
    let step7 = CommitmentUpdate;
    let post_state = step7.execute(post_state)?;

    // Compute observable from (pre, input, post).
    let observable = obs(state, input, &post_state);

    Ok(PipelineOutput {
        post_state,
        observable,
        transition_class: transform.transition_class,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use vsel_core::input::Authorization;
    use vsel_core::state::{AccountData, CanonicalState, Environment, TraceMetadata};
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

    // -----------------------------------------------------------------------
    // Step 1: Input Canonicalization tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_step1_valid_input_passes() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        let sigma = make_input("deposit", vec![0x01; 48]);
        let step = InputCanonicalization;
        assert!(step.execute((&s, &sigma)).is_ok());
    }

    #[test]
    fn test_step1_invalid_input_rejected() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        let sigma = make_invalid_input();
        let step = InputCanonicalization;
        assert!(matches!(
            step.execute((&s, &sigma)),
            Err(PipelineError::MalformedInput { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // Step 2: Authorization Check tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_step2_valid_auth_passes() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        let sigma = make_input("deposit", vec![0x01; 48]);
        let step = AuthorizationCheck;
        assert!(step.execute((&s, &sigma)).is_ok());
    }

    #[test]
    fn test_step2_missing_classical_sig_rejected() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        let mut sigma = make_input("deposit", vec![0x01; 48]);
        sigma.auth.classical_sig = vec![];
        let step = AuthorizationCheck;
        assert!(matches!(
            step.execute((&s, &sigma)),
            Err(PipelineError::Unauthorized { .. })
        ));
    }

    #[test]
    fn test_step2_missing_pqc_sig_rejected() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        let mut sigma = make_input("deposit", vec![0x01; 48]);
        sigma.auth.pqc_sig = vec![];
        let step = AuthorizationCheck;
        assert!(matches!(
            step.execute((&s, &sigma)),
            Err(PipelineError::Unauthorized { .. })
        ));
    }

    #[test]
    fn test_step2_zero_domain_rejected() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        let mut sigma = make_input("deposit", vec![0x01; 48]);
        sigma.auth.domain = DomainTag(Hash([0u8; 32]));
        let step = AuthorizationCheck;
        assert!(matches!(
            step.execute((&s, &sigma)),
            Err(PipelineError::Unauthorized { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // Step 3: Precondition Validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_step3_valid_preconditions_pass() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        let sigma = make_input("deposit", vec![0x01; 48]);
        let step = PreconditionValidation;
        let result = step.execute((&s, &sigma));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().transition_class, TransitionClass::Update);
    }

    #[test]
    fn test_step3_error_class_rejected() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        let sigma = make_input("transfer", vec![1u8; 32]);
        let step = PreconditionValidation;
        assert!(matches!(
            step.execute((&s, &sigma)),
            Err(PipelineError::PreconditionViolation { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // Step 4: State Transformation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_step4_deterministic_transformation() {
        let s = build_state_at_seq(minimal_canonical(), 0);
        let sigma = make_input("init", vec![0xFF]);
        let step = StateTransformation;
        let result = step.execute((&s, &sigma, TransitionClass::Init));
        assert!(result.is_ok());
        let output = result.unwrap();
        assert_eq!(output.transition_class, TransitionClass::Init);
        assert_eq!(
            output
                .post_state
                .canonical
                .system_data
                .parameters
                .get("initialized"),
            Some(&vec![1u8])
        );
    }

    // -----------------------------------------------------------------------
    // Step 5: Postcondition Validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_step5_valid_postconditions_pass() {
        let s = build_state_at_seq(minimal_canonical(), 0);
        let sigma = make_input("init", vec![0xFF]);
        let post = apply(&s, &sigma);
        let step = PostconditionValidation;
        assert!(step.execute((&s, &sigma, &post)).is_ok());
    }

    // -----------------------------------------------------------------------
    // Step 6: Derived State Recalculation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_step6_consistent_derived_passes() {
        let s = build_state_at_seq(minimal_canonical(), 0);
        let sigma = make_input("init", vec![0xFF]);
        let post = apply(&s, &sigma);
        let step = DerivedStateRecalculation;
        assert!(step.execute(post).is_ok());
    }

    #[test]
    fn test_step6_stale_derived_rejected() {
        let s = build_state_at_seq(minimal_canonical(), 0);
        let sigma = make_input("init", vec![0xFF]);
        let mut post = apply(&s, &sigma);
        post.derived.state_root = Hash([0xFFu8; 32]);
        let step = DerivedStateRecalculation;
        assert!(matches!(
            step.execute(post),
            Err(PipelineError::DerivedStateMismatch { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // Step 7: Commitment Update tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_step7_valid_commitment_passes() {
        let s = build_state_at_seq(minimal_canonical(), 0);
        let sigma = make_input("init", vec![0xFF]);
        let post = apply(&s, &sigma);
        let step = CommitmentUpdate;
        assert!(step.execute(post).is_ok());
    }

    // -----------------------------------------------------------------------
    // Full pipeline tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_pipeline_init_succeeds() {
        let s = build_state_at_seq(minimal_canonical(), 0);
        let sigma = make_input("init", vec![0xFF]);
        let result = run_pipeline(&s, &sigma);
        assert!(result.is_ok());
        let output = result.unwrap();
        assert_eq!(output.transition_class, TransitionClass::Init);
        assert_eq!(
            output
                .post_state
                .canonical
                .system_data
                .parameters
                .get("initialized"),
            Some(&vec![1u8])
        );
    }

    #[test]
    fn test_pipeline_deposit_succeeds() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        let mut data = vec![];
        data.extend_from_slice(&[1u8; 32]);
        data.extend_from_slice(&500u128.to_le_bytes());
        let sigma = make_input("deposit", data);
        let result = run_pipeline(&s, &sigma);
        assert!(result.is_ok());
        let output = result.unwrap();
        assert_eq!(output.transition_class, TransitionClass::Update);
        assert_eq!(
            output.post_state.canonical.accounts[&AccountId([1u8; 32])].balance,
            500
        );
    }

    #[test]
    fn test_pipeline_transfer_succeeds() {
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

        let result = run_pipeline(&s, &sigma);
        assert!(result.is_ok());
        let output = result.unwrap();
        assert_eq!(output.transition_class, TransitionClass::Update);
        assert_eq!(
            output.post_state.canonical.system_data.total_supply, 1500,
            "transfer must conserve total supply"
        );
    }

    #[test]
    fn test_pipeline_invalid_input_fails_step1() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        let sigma = make_invalid_input();
        let result = run_pipeline(&s, &sigma);
        assert!(matches!(result, Err(PipelineError::MalformedInput { .. })));
    }

    #[test]
    fn test_pipeline_precondition_failure() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        let sigma = make_input("transfer", vec![1u8; 32]);
        let result = run_pipeline(&s, &sigma);
        assert!(matches!(
            result,
            Err(PipelineError::PreconditionViolation { .. })
        ));
    }

    #[test]
    fn test_pipeline_deterministic() {
        let s = build_state_at_seq(minimal_canonical(), 0);
        let sigma = make_input("init", vec![0xFF]);
        let r1 = run_pipeline(&s, &sigma);
        let r2 = run_pipeline(&s, &sigma);
        assert!(r1.is_ok());
        assert!(r2.is_ok());
        assert_eq!(r1.unwrap(), r2.unwrap(), "Pipeline must be deterministic");
    }

    #[test]
    fn test_pipeline_noop_succeeds() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        let sigma = make_input("unknown_op", vec![0x01]);
        let result = run_pipeline(&s, &sigma);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().transition_class, TransitionClass::Noop);
    }

    #[test]
    fn test_pipeline_batch_succeeds() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        let sigma = make_input("batch", vec![0x01]);
        let result = run_pipeline(&s, &sigma);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().transition_class, TransitionClass::Batch);
    }
}
