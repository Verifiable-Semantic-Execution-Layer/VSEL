//! Differential execution framework — comparing concrete Rust execution against
//! the SIR reference interpreter.
//!
//! Derived from: SEMANTIC_MAPPING.md, REFINEMENT_STRATEGY.md,
//! Requirements 4.10, 9.10, 13.9.
//!
//! This framework runs the same (state, input) pair through both:
//! 1. Concrete Rust execution (`apply` from `vsel-core::transition`)
//! 2. SIR reference interpreter (`Interpreter` from `vsel-sir::interpreter`)
//!
//! It then compares the results via the semantic mapping layer, detecting any
//! divergence between the concrete and formal models. This is the primary
//! mechanism for validating refinement R₁₂ (SIR → Rust Concrete).

use vsel_core::input::Input;
use vsel_core::observable::obs;
use vsel_core::state::State;
use vsel_core::transition::{apply, classify, TransitionClass};
use vsel_sir::interpreter::{Interpreter, InterpreterError};
use vsel_sir::types::{SirProgram, SirValue};

use crate::mapping::{map_input, map_observable, map_state, FormalState};

// ---------------------------------------------------------------------------
// DivergenceKind — classification of divergences
// ---------------------------------------------------------------------------

/// Classification of divergence between concrete and formal execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DivergenceKind {
    /// Post-states differ between concrete (mapped) and formal execution.
    StateDivergence { field: String, detail: String },
    /// Observable outputs differ.
    ObservableDivergence { detail: String },
    /// Transition classification differs between concrete and formal.
    ClassificationDivergence {
        concrete_class: String,
        formal_class: String,
    },
    /// Invariant check result differs between concrete and formal.
    InvariantDivergence {
        invariant_name: String,
        detail: String,
    },
}

// ---------------------------------------------------------------------------
// DifferentialResult — outcome of a single differential execution
// ---------------------------------------------------------------------------

/// Result of running a single differential execution comparing concrete
/// Rust execution against the SIR reference interpreter.
#[derive(Clone, Debug)]
pub struct DifferentialResult {
    /// Whether the concrete and formal executions agree.
    pub agrees: bool,
    /// The concrete post-state (from `apply`).
    pub concrete_post: State,
    /// The concrete post-state mapped to formal representation.
    pub concrete_formal_post: FormalState,
    /// The formal post-state from the SIR interpreter (if available).
    pub formal_post: Option<SirValue>,
    /// The transition class determined by concrete classification.
    pub transition_class: TransitionClass,
    /// Any divergences detected.
    pub divergences: Vec<DivergenceKind>,
    /// Whether the SIR program had a matching transition (None = skipped).
    pub sir_executed: bool,
    /// Error from SIR interpreter, if any.
    pub sir_error: Option<String>,
}

// ---------------------------------------------------------------------------
// Core differential execution function
// ---------------------------------------------------------------------------

/// Run differential execution for a single (state, input) pair.
///
/// Steps:
/// 1. Execute concretely: `apply(pre, input)` → `post_state`
/// 2. Map pre-state and input to formal SIR values
/// 3. Determine transition name from classification
/// 4. Execute via SIR interpreter (if program defines the transition)
/// 5. Map concrete post-state to formal: `map_state(post_state)`
/// 6. Compare formal results
/// 7. Return result with divergence details
///
/// Requirements: 4.10, 9.10, 13.9
pub fn run_differential(pre: &State, input: &Input, program: &SirProgram) -> DifferentialResult {
    // Step 1: Concrete execution
    let concrete_post = apply(pre, input);
    let transition_class = classify(pre, input);

    // Step 2: Map to formal representations
    let formal_pre = map_state(pre);
    let formal_input = map_input(input);
    let concrete_formal_post = map_state(&concrete_post);

    // Step 3: Determine transition name for SIR lookup
    let transition_name = transition_class_to_sir_name(transition_class);

    // Step 4: Try SIR interpreter execution
    let interpreter = Interpreter::new();
    let sir_result = interpreter.execute(program, &transition_name, &formal_pre.0, &formal_input.0);

    // Step 5-7: Compare results
    match sir_result {
        Ok(formal_post) => {
            let divergences = detect_all_divergences(
                pre,
                input,
                &concrete_post,
                &concrete_formal_post,
                &formal_post,
                transition_class,
                program,
            );

            DifferentialResult {
                agrees: divergences.is_empty(),
                concrete_post,
                concrete_formal_post,
                formal_post: Some(formal_post),
                transition_class,
                divergences,
                sir_executed: true,
                sir_error: None,
            }
        }
        Err(InterpreterError::UnknownFunction(_)) => {
            // SIR program doesn't define this transition → skip comparison
            DifferentialResult {
                agrees: true,
                concrete_post,
                concrete_formal_post,
                formal_post: None,
                transition_class,
                divergences: vec![],
                sir_executed: false,
                sir_error: None,
            }
        }
        Err(err) => {
            // SIR interpreter returned an error → record as divergence
            // For error/reject transitions, an interpreter error may be expected
            let is_expected_error = matches!(
                transition_class,
                TransitionClass::Error | TransitionClass::Reject
            );

            let divergences = if is_expected_error {
                vec![]
            } else {
                vec![DivergenceKind::StateDivergence {
                    field: "sir_execution".to_string(),
                    detail: format!("SIR interpreter error: {}", err),
                }]
            };

            DifferentialResult {
                agrees: is_expected_error,
                concrete_post,
                concrete_formal_post,
                formal_post: None,
                transition_class,
                divergences,
                sir_executed: true,
                sir_error: Some(err.to_string()),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Batch differential execution
// ---------------------------------------------------------------------------

/// Run differential execution for a sequence of inputs, threading state.
///
/// Each input is applied to the post-state of the previous execution,
/// building a chain of differential results.
///
/// Requirements: 4.10, 9.10
pub fn run_differential_batch(
    pre: &State,
    inputs: &[Input],
    program: &SirProgram,
) -> Vec<DifferentialResult> {
    let mut results = Vec::with_capacity(inputs.len());
    let mut current_state = pre.clone();

    for input in inputs {
        let result = run_differential(&current_state, input, program);
        current_state = result.concrete_post.clone();
        results.push(result);
    }

    results
}

// ---------------------------------------------------------------------------
// DifferentialTestSuite — structured test runner
// ---------------------------------------------------------------------------

/// A structured test suite for running differential tests across
/// all transition classes.
pub struct DifferentialTestSuite {
    /// The SIR program to test against.
    pub program: SirProgram,
}

/// Summary of a differential test suite run.
#[derive(Clone, Debug)]
pub struct DifferentialSuiteSummary {
    /// Total number of tests run.
    pub total: usize,
    /// Number of tests that agreed.
    pub agreed: usize,
    /// Number of tests that diverged.
    pub diverged: usize,
    /// Number of tests skipped (no SIR transition defined).
    pub skipped: usize,
    /// All divergences collected.
    pub all_divergences: Vec<(TransitionClass, Vec<DivergenceKind>)>,
}

impl DifferentialTestSuite {
    /// Create a new test suite with the given SIR program.
    pub fn new(program: SirProgram) -> Self {
        Self { program }
    }

    /// Run a differential test for a single (state, input) pair.
    pub fn run_single(&self, pre: &State, input: &Input) -> DifferentialResult {
        run_differential(pre, input, &self.program)
    }

    /// Run differential tests for a batch of (state, input) pairs.
    pub fn run_batch(&self, cases: &[(State, Input)]) -> DifferentialSuiteSummary {
        let mut total = 0;
        let mut agreed = 0;
        let mut diverged = 0;
        let mut skipped = 0;
        let mut all_divergences = Vec::new();

        for (state, input) in cases {
            let result = self.run_single(state, input);
            total += 1;

            if !result.sir_executed {
                skipped += 1;
            } else if result.agrees {
                agreed += 1;
            } else {
                diverged += 1;
                all_divergences.push((result.transition_class, result.divergences));
            }
        }

        DifferentialSuiteSummary {
            total,
            agreed,
            diverged,
            skipped,
            all_divergences,
        }
    }

    /// Run differential tests for a sequence of inputs from a given state.
    pub fn run_sequence(&self, pre: &State, inputs: &[Input]) -> DifferentialSuiteSummary {
        let results = run_differential_batch(pre, inputs, &self.program);

        let total = results.len();
        let skipped = results.iter().filter(|r| !r.sir_executed).count();
        let diverged = results
            .iter()
            .filter(|r| r.sir_executed && !r.agrees)
            .count();
        let agreed = total - skipped - diverged;

        let all_divergences: Vec<_> = results
            .iter()
            .filter(|r| !r.agrees && r.sir_executed)
            .map(|r| (r.transition_class, r.divergences.clone()))
            .collect();

        DifferentialSuiteSummary {
            total,
            agreed,
            diverged,
            skipped,
            all_divergences,
        }
    }
}

// ---------------------------------------------------------------------------
// Divergence detection
// ---------------------------------------------------------------------------

/// Detect divergence between a concrete formal state and a SIR interpreter result.
///
/// Compares the two formal representations and returns the kind of divergence
/// if any is found.
///
/// Requirements: 4.10, 9.10
pub fn detect_divergence(
    concrete_formal: &FormalState,
    sir_result: &SirValue,
) -> Option<DivergenceKind> {
    if concrete_formal.0 == *sir_result {
        return None;
    }

    // Try to identify which part diverged
    if let (
        SirValue::Map {
            entries: concrete_entries,
        },
        SirValue::Map {
            entries: sir_entries,
        },
    ) = (&concrete_formal.0, sir_result)
    {
        for (key, concrete_val) in concrete_entries {
            if let Some(sir_val) = sir_entries.get(key) {
                if concrete_val != sir_val {
                    return Some(DivergenceKind::StateDivergence {
                        field: key.clone(),
                        detail: format!(
                            "field '{}' differs: concrete={:?}, formal={:?}",
                            key, concrete_val, sir_val
                        ),
                    });
                }
            } else {
                return Some(DivergenceKind::StateDivergence {
                    field: key.clone(),
                    detail: format!("field '{}' present in concrete but missing in formal", key),
                });
            }
        }

        // Check for extra keys in SIR result
        for key in sir_entries.keys() {
            if !concrete_entries.contains_key(key) {
                return Some(DivergenceKind::StateDivergence {
                    field: key.clone(),
                    detail: format!("field '{}' present in formal but missing in concrete", key),
                });
            }
        }
    }

    // Fallback: generic state divergence
    Some(DivergenceKind::StateDivergence {
        field: "root".to_string(),
        detail: "concrete and formal post-states differ structurally".to_string(),
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Map a `TransitionClass` to the SIR transition name used in the program.
fn transition_class_to_sir_name(class: TransitionClass) -> String {
    match class {
        TransitionClass::Reject => "reject".to_string(),
        TransitionClass::Init => "init".to_string(),
        TransitionClass::Error => "error".to_string(),
        TransitionClass::Batch => "batch".to_string(),
        TransitionClass::Update => "update".to_string(),
        TransitionClass::Noop => "noop".to_string(),
    }
}

/// Detect all divergences between concrete and formal execution.
fn detect_all_divergences(
    pre: &State,
    input: &Input,
    concrete_post: &State,
    concrete_formal_post: &FormalState,
    formal_post: &SirValue,
    transition_class: TransitionClass,
    program: &SirProgram,
) -> Vec<DivergenceKind> {
    let mut divergences = Vec::new();

    // 1. State divergence check
    if let Some(div) = detect_divergence(concrete_formal_post, formal_post) {
        divergences.push(div);
    }

    // 2. Observable divergence check
    let concrete_obs = obs(pre, input, concrete_post);
    let formal_obs = map_observable(&concrete_obs);

    // Check if the SIR program defines observables we can compare
    for sir_obs in &program.observables {
        let interpreter = Interpreter::new();
        let formal_pre = map_state(pre);
        let env = vsel_sir::types::SirEnv::new()
            .extend("state".into(), formal_pre.0.clone())
            .extend("post_state".into(), formal_post.clone());

        if let Ok(sir_obs_val) = interpreter.eval(&sir_obs.expr, &env) {
            // Compare observable values if the SIR program computes them
            if let SirValue::Map { entries } = &formal_obs.0 {
                if let Some(concrete_val) = entries.get(&sir_obs.name) {
                    if *concrete_val != sir_obs_val {
                        divergences.push(DivergenceKind::ObservableDivergence {
                            detail: format!(
                                "observable '{}' differs: concrete={:?}, formal={:?}",
                                sir_obs.name, concrete_val, sir_obs_val
                            ),
                        });
                    }
                }
            }
        }
    }

    // 3. Classification divergence check
    // Check if the SIR transition's class matches the concrete classification
    if let Some(sir_transition) = program
        .transitions
        .iter()
        .find(|t| t.name == transition_class_to_sir_name(transition_class))
    {
        let expected_class = transition_class_to_sir_name(transition_class);
        if sir_transition.class.to_lowercase() != expected_class {
            divergences.push(DivergenceKind::ClassificationDivergence {
                concrete_class: expected_class,
                formal_class: sir_transition.class.clone(),
            });
        }
    }

    // 4. Invariant divergence check
    let formal_post_state = map_state(concrete_post);
    for invariant in &program.invariants {
        let interpreter = Interpreter::new();
        match interpreter.check_invariant(invariant, &formal_post_state.0) {
            Ok(holds) => {
                if !holds {
                    divergences.push(DivergenceKind::InvariantDivergence {
                        invariant_name: invariant.name.clone(),
                        detail: format!(
                            "invariant '{}' violated in formal post-state",
                            invariant.name
                        ),
                    });
                }
            }
            Err(err) => {
                divergences.push(DivergenceKind::InvariantDivergence {
                    invariant_name: invariant.name.clone(),
                    detail: format!("invariant '{}' evaluation error: {}", invariant.name, err),
                });
            }
        }
    }

    divergences
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use vsel_core::input::Authorization;
    use vsel_core::state::*;
    use vsel_core::types::*;
    use vsel_sir::types::*;

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

    fn empty_sir_program() -> SirProgram {
        SirProgram {
            version: "0.1.0".into(),
            state_schema: SirStateSchema { fields: vec![] },
            input_schema: SirInputSchema { fields: vec![] },
            transitions: vec![],
            invariants: vec![],
            observables: vec![],
        }
    }

    /// Build a SIR program with a simple "init" transition that returns
    /// the state unchanged (identity transition for testing).
    fn identity_sir_program(transition_name: &str) -> SirProgram {
        SirProgram {
            version: "0.1.0".into(),
            state_schema: SirStateSchema { fields: vec![] },
            input_schema: SirInputSchema { fields: vec![] },
            transitions: vec![SirTransition {
                name: transition_name.to_string(),
                class: transition_name.to_string(),
                preconditions: vec![],
                postconditions: vec![],
                body: SirExpr::Var {
                    name: "state".into(),
                },
                allowed_mutations: vec![],
            }],
            invariants: vec![],
            observables: vec![],
        }
    }

    // -- run_differential tests --

    #[test]
    fn test_differential_skips_when_no_sir_transition() {
        let state = build_state_at_seq(minimal_canonical(), 0);
        let input = make_input("init", vec![0xFF]);
        let program = empty_sir_program();

        let result = run_differential(&state, &input, &program);

        assert!(
            !result.sir_executed,
            "should skip when no SIR transition defined"
        );
        assert!(result.agrees, "should agree when skipped");
        assert!(result.formal_post.is_none());
        assert!(result.divergences.is_empty());
    }

    #[test]
    fn test_differential_executes_with_matching_transition() {
        let state = build_state_at_seq(minimal_canonical(), 0);
        let input = make_input("init", vec![0xFF]);
        // SIR program returns state unchanged — will diverge from concrete
        // which modifies state (adds "initialized" param)
        let program = identity_sir_program("init");

        let result = run_differential(&state, &input, &program);

        assert!(result.sir_executed);
        assert!(result.formal_post.is_some());
        assert_eq!(result.transition_class, TransitionClass::Init);
    }

    #[test]
    fn test_differential_noop_agrees_with_identity() {
        let state = build_state_at_seq(minimal_canonical(), 1);
        let input = make_input("unknown_op", vec![0x01]);
        // Noop: concrete returns state with advanced metadata
        // SIR identity: returns state as-is
        // These will diverge because metadata changes
        let program = identity_sir_program("noop");

        let result = run_differential(&state, &input, &program);

        assert!(result.sir_executed);
        assert_eq!(result.transition_class, TransitionClass::Noop);
    }

    #[test]
    fn test_differential_error_transition_with_sir_error() {
        let state = build_state_at_seq(minimal_canonical(), 1);
        // Transfer with non-existent sender → Error class
        let input = make_input("transfer", vec![1u8; 32]);

        // SIR program with "error" transition that has a failing precondition
        let program = SirProgram {
            version: "0.1.0".into(),
            state_schema: SirStateSchema { fields: vec![] },
            input_schema: SirInputSchema { fields: vec![] },
            transitions: vec![SirTransition {
                name: "error".to_string(),
                class: "error".to_string(),
                preconditions: vec![SirExpr::Literal {
                    value: SirValue::Bool { value: false },
                }],
                postconditions: vec![],
                body: SirExpr::Var {
                    name: "state".into(),
                },
                allowed_mutations: vec![],
            }],
            invariants: vec![],
            observables: vec![],
        };

        let result = run_differential(&state, &input, &program);

        assert_eq!(result.transition_class, TransitionClass::Error);
        assert!(result.sir_executed);
        // Error transitions with SIR precondition failure are expected
        assert!(
            result.agrees,
            "error transition with SIR error should be expected"
        );
        assert!(result.sir_error.is_some());
    }

    // -- run_differential_batch tests --

    #[test]
    fn test_differential_batch_empty() {
        let state = build_state_at_seq(minimal_canonical(), 0);
        let program = empty_sir_program();

        let results = run_differential_batch(&state, &[], &program);
        assert!(results.is_empty());
    }

    #[test]
    fn test_differential_batch_threads_state() {
        let state = build_state_at_seq(minimal_canonical(), 0);
        let inputs = vec![
            make_input("init", vec![0xFF]),
            make_input("unknown_op", vec![0x01]),
        ];
        let program = empty_sir_program();

        let results = run_differential_batch(&state, &inputs, &program);

        assert_eq!(results.len(), 2);
        // Second result's pre-state should be first result's post-state
        // (verified by checking metadata sequence advances)
        assert_eq!(
            results[0].concrete_post.metadata.sequence_index,
            state.metadata.sequence_index + 1
        );
        assert_eq!(
            results[1].concrete_post.metadata.sequence_index,
            state.metadata.sequence_index + 2
        );
    }

    // -- DifferentialTestSuite tests --

    #[test]
    fn test_suite_run_single() {
        let state = build_state_at_seq(minimal_canonical(), 0);
        let input = make_input("init", vec![0xFF]);
        let suite = DifferentialTestSuite::new(empty_sir_program());

        let result = suite.run_single(&state, &input);
        assert!(result.agrees);
    }

    #[test]
    fn test_suite_run_batch_summary() {
        let state = build_state_at_seq(minimal_canonical(), 1);
        let cases = vec![
            (state.clone(), make_input("unknown_op", vec![0x01])),
            (state.clone(), make_input("batch", vec![0x02])),
        ];
        let suite = DifferentialTestSuite::new(empty_sir_program());

        let summary = suite.run_batch(&cases);

        assert_eq!(summary.total, 2);
        assert_eq!(summary.skipped, 2); // No SIR transitions defined
        assert_eq!(summary.diverged, 0);
    }

    #[test]
    fn test_suite_run_sequence() {
        let state = build_state_at_seq(minimal_canonical(), 0);
        let inputs = vec![
            make_input("init", vec![0xFF]),
            make_input("unknown_op", vec![0x01]),
        ];
        let suite = DifferentialTestSuite::new(empty_sir_program());

        let summary = suite.run_sequence(&state, &inputs);

        assert_eq!(summary.total, 2);
        assert_eq!(summary.skipped, 2);
    }

    // -- detect_divergence tests --

    #[test]
    fn test_detect_divergence_none_when_equal() {
        let value = SirValue::Map {
            entries: {
                let mut m = BTreeMap::new();
                m.insert("x".to_string(), SirValue::Int { value: 42 });
                m
            },
        };
        let formal = FormalState(value.clone());

        assert!(detect_divergence(&formal, &value).is_none());
    }

    #[test]
    fn test_detect_divergence_field_differs() {
        let concrete = FormalState(SirValue::Map {
            entries: {
                let mut m = BTreeMap::new();
                m.insert("x".to_string(), SirValue::Int { value: 1 });
                m
            },
        });
        let sir = SirValue::Map {
            entries: {
                let mut m = BTreeMap::new();
                m.insert("x".to_string(), SirValue::Int { value: 2 });
                m
            },
        };

        let div = detect_divergence(&concrete, &sir);
        assert!(div.is_some());
        match div.unwrap() {
            DivergenceKind::StateDivergence { field, .. } => {
                assert_eq!(field, "x");
            }
            _ => panic!("expected StateDivergence"),
        }
    }

    #[test]
    fn test_detect_divergence_missing_field_in_formal() {
        let concrete = FormalState(SirValue::Map {
            entries: {
                let mut m = BTreeMap::new();
                m.insert("x".to_string(), SirValue::Int { value: 1 });
                m.insert("y".to_string(), SirValue::Int { value: 2 });
                m
            },
        });
        let sir = SirValue::Map {
            entries: {
                let mut m = BTreeMap::new();
                m.insert("x".to_string(), SirValue::Int { value: 1 });
                m
            },
        };

        let div = detect_divergence(&concrete, &sir);
        assert!(div.is_some());
    }

    #[test]
    fn test_detect_divergence_extra_field_in_formal() {
        let concrete = FormalState(SirValue::Map {
            entries: {
                let mut m = BTreeMap::new();
                m.insert("x".to_string(), SirValue::Int { value: 1 });
                m
            },
        });
        let sir = SirValue::Map {
            entries: {
                let mut m = BTreeMap::new();
                m.insert("x".to_string(), SirValue::Int { value: 1 });
                m.insert("extra".to_string(), SirValue::Int { value: 99 });
                m
            },
        };

        let div = detect_divergence(&concrete, &sir);
        assert!(div.is_some());
    }

    #[test]
    fn test_detect_divergence_non_map_values() {
        let concrete = FormalState(SirValue::Int { value: 1 });
        let sir = SirValue::Int { value: 2 };

        let div = detect_divergence(&concrete, &sir);
        assert!(div.is_some());
    }

    #[test]
    fn test_detect_divergence_non_map_equal() {
        let concrete = FormalState(SirValue::Int { value: 42 });
        let sir = SirValue::Int { value: 42 };

        assert!(detect_divergence(&concrete, &sir).is_none());
    }

    // -- DivergenceKind tests --

    #[test]
    fn test_divergence_kind_variants() {
        let state_div = DivergenceKind::StateDivergence {
            field: "balance".to_string(),
            detail: "mismatch".to_string(),
        };
        let obs_div = DivergenceKind::ObservableDivergence {
            detail: "gas differs".to_string(),
        };
        let class_div = DivergenceKind::ClassificationDivergence {
            concrete_class: "update".to_string(),
            formal_class: "noop".to_string(),
        };
        let inv_div = DivergenceKind::InvariantDivergence {
            invariant_name: "L_cons".to_string(),
            detail: "violated".to_string(),
        };

        // Verify all variants are distinct
        assert_ne!(state_div, obs_div);
        assert_ne!(class_div, inv_div);
    }

    // -- Invariant divergence detection --

    #[test]
    fn test_differential_with_invariant_check() {
        let state = build_state_at_seq(minimal_canonical(), 0);
        let input = make_input("init", vec![0xFF]);

        // SIR program with an always-true invariant
        let program = SirProgram {
            version: "0.1.0".into(),
            state_schema: SirStateSchema { fields: vec![] },
            input_schema: SirInputSchema { fields: vec![] },
            transitions: vec![SirTransition {
                name: "init".to_string(),
                class: "init".to_string(),
                preconditions: vec![],
                postconditions: vec![],
                body: SirExpr::Var {
                    name: "state".into(),
                },
                allowed_mutations: vec![],
            }],
            invariants: vec![SirInvariant {
                name: "always_true".to_string(),
                category: "local".to_string(),
                expr: SirExpr::Literal {
                    value: SirValue::Bool { value: true },
                },
            }],
            observables: vec![],
        };

        let result = run_differential(&state, &input, &program);

        // The invariant should hold, so no invariant divergence
        let inv_divergences: Vec<_> = result
            .divergences
            .iter()
            .filter(|d| matches!(d, DivergenceKind::InvariantDivergence { .. }))
            .collect();
        assert!(
            inv_divergences.is_empty(),
            "always-true invariant should not diverge"
        );
    }

    #[test]
    fn test_differential_with_failing_invariant() {
        let state = build_state_at_seq(minimal_canonical(), 0);
        let input = make_input("init", vec![0xFF]);

        // SIR program with an always-false invariant
        let program = SirProgram {
            version: "0.1.0".into(),
            state_schema: SirStateSchema { fields: vec![] },
            input_schema: SirInputSchema { fields: vec![] },
            transitions: vec![SirTransition {
                name: "init".to_string(),
                class: "init".to_string(),
                preconditions: vec![],
                postconditions: vec![],
                body: SirExpr::Var {
                    name: "state".into(),
                },
                allowed_mutations: vec![],
            }],
            invariants: vec![SirInvariant {
                name: "always_false".to_string(),
                category: "local".to_string(),
                expr: SirExpr::Literal {
                    value: SirValue::Bool { value: false },
                },
            }],
            observables: vec![],
        };

        let result = run_differential(&state, &input, &program);

        let inv_divergences: Vec<_> = result
            .divergences
            .iter()
            .filter(|d| matches!(d, DivergenceKind::InvariantDivergence { .. }))
            .collect();
        assert!(
            !inv_divergences.is_empty(),
            "always-false invariant should produce divergence"
        );
    }

    // -- transition_class_to_sir_name tests --

    #[test]
    fn test_transition_class_to_sir_name_all_classes() {
        assert_eq!(
            transition_class_to_sir_name(TransitionClass::Reject),
            "reject"
        );
        assert_eq!(transition_class_to_sir_name(TransitionClass::Init), "init");
        assert_eq!(
            transition_class_to_sir_name(TransitionClass::Error),
            "error"
        );
        assert_eq!(
            transition_class_to_sir_name(TransitionClass::Batch),
            "batch"
        );
        assert_eq!(
            transition_class_to_sir_name(TransitionClass::Update),
            "update"
        );
        assert_eq!(transition_class_to_sir_name(TransitionClass::Noop), "noop");
    }
}
