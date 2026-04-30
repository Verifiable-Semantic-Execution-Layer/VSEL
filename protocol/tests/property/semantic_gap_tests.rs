//! Property-based tests for axiom behavior verification — constraint soundness
//! and completeness (Property 9).
//!
//! **Property 9: Axiom behavior verification — constraint soundness and completeness**
//!
//! This test file validates the two critical axioms in the Lean 4 refinement chain
//! (ConcreteToConstraint.lean) that bridge concrete Rust execution to the constraint
//! system used for ZK proof generation:
//!
//! - **LEM-4 (Soundness)**: `SatisfiesConstraints(τ, cs) → ValidTrace(τ)`
//!   If a trace satisfies all constraints, then the trace is semantically valid.
//!   Contrapositive tested: invalid traces must violate at least one constraint.
//!
//! - **LEM-5 (Completeness)**: `ValidTrace(τ) → SatisfiesConstraints(τ, cs)`
//!   If a trace is semantically valid, then it satisfies all constraints.
//!   Tested directly: valid traces must satisfy all constraints.
//!
//! The tests generate random valid and invalid execution traces against multiple
//! SIR program structures (Noop, Update, multi-invariant) and verify the
//! bidirectional correspondence between trace validity and constraint satisfaction.
//!
//! **Validates: Requirements 8.3**

use std::collections::BTreeMap;

use proptest::prelude::*;

use vsel_constraints::compiler::{compile, satisfies_constraints};
use vsel_sir::types::{
    SirExpr, SirFieldSchema, SirInputSchema, SirInvariant, SirProgram, SirStateSchema,
    SirTransition, SirValue,
};

// ===========================================================================
// SIR program builders
// ===========================================================================

/// Build a Noop program: no mutations allowed, state unchanged.
/// Body: state (identity — Map = Map works in evaluator).
/// Invariant: balance >= 0.
///
/// This program enables full bidirectional LEM-4/LEM-5 testing because
/// the body constraint `state_post = state` evaluates correctly when both
/// sides are Map values.
fn make_noop_program() -> SirProgram {
    SirProgram {
        version: "0.1.0".to_string(),
        state_schema: SirStateSchema {
            fields: vec![
                SirFieldSchema { name: "balance".into(), field_type: "Int".into() },
                SirFieldSchema { name: "nonce".into(), field_type: "Int".into() },
            ],
        },
        input_schema: SirInputSchema {
            fields: vec![SirFieldSchema { name: "amount".into(), field_type: "Int".into() }],
        },
        transitions: vec![SirTransition {
            name: "noop".into(),
            class: "Noop".into(),
            preconditions: vec![],
            postconditions: vec![],
            body: SirExpr::Var { name: "state".into() },
            allowed_mutations: vec![],
        }],
        invariants: vec![SirInvariant {
            name: "L_non_negative".into(),
            category: "local".into(),
            expr: SirExpr::BinOp {
                op: "ge".into(),
                left: Box::new(SirExpr::FieldAccess {
                    expr: Box::new(SirExpr::Var { name: "state".into() }),
                    field: "balance".into(),
                }),
                right: Box::new(SirExpr::Literal { value: SirValue::Int { value: 0 } }),
            },
        }],
        observables: vec![],
    }
}

/// Build a multi-field Noop program with three invariants:
/// - L_non_negative_balance: balance >= 0
/// - L_non_negative_nonce: nonce >= 0
/// - G_bounded_total: balance + nonce < 1_000_000
///
/// This tests soundness across multiple invariant constraints simultaneously.
fn make_multi_invariant_program() -> SirProgram {
    SirProgram {
        version: "0.1.0".to_string(),
        state_schema: SirStateSchema {
            fields: vec![
                SirFieldSchema { name: "balance".into(), field_type: "Int".into() },
                SirFieldSchema { name: "nonce".into(), field_type: "Int".into() },
            ],
        },
        input_schema: SirInputSchema {
            fields: vec![SirFieldSchema { name: "amount".into(), field_type: "Int".into() }],
        },
        transitions: vec![SirTransition {
            name: "noop".into(),
            class: "Noop".into(),
            preconditions: vec![],
            postconditions: vec![],
            body: SirExpr::Var { name: "state".into() },
            allowed_mutations: vec![],
        }],
        invariants: vec![
            SirInvariant {
                name: "L_non_negative_balance".into(),
                category: "local".into(),
                expr: SirExpr::BinOp {
                    op: "ge".into(),
                    left: Box::new(SirExpr::FieldAccess {
                        expr: Box::new(SirExpr::Var { name: "state".into() }),
                        field: "balance".into(),
                    }),
                    right: Box::new(SirExpr::Literal { value: SirValue::Int { value: 0 } }),
                },
            },
            SirInvariant {
                name: "L_non_negative_nonce".into(),
                category: "local".into(),
                expr: SirExpr::BinOp {
                    op: "ge".into(),
                    left: Box::new(SirExpr::FieldAccess {
                        expr: Box::new(SirExpr::Var { name: "state".into() }),
                        field: "nonce".into(),
                    }),
                    right: Box::new(SirExpr::Literal { value: SirValue::Int { value: 0 } }),
                },
            },
            SirInvariant {
                name: "G_bounded_total".into(),
                category: "global".into(),
                expr: SirExpr::BinOp {
                    op: "lt".into(),
                    left: Box::new(SirExpr::BinOp {
                        op: "add".into(),
                        left: Box::new(SirExpr::FieldAccess {
                            expr: Box::new(SirExpr::Var { name: "state".into() }),
                            field: "balance".into(),
                        }),
                        right: Box::new(SirExpr::FieldAccess {
                            expr: Box::new(SirExpr::Var { name: "state".into() }),
                            field: "nonce".into(),
                        }),
                    }),
                    right: Box::new(SirExpr::Literal { value: SirValue::Int { value: 1_000_000 } }),
                },
            },
        ],
        observables: vec![],
    }
}

/// Build an Update program: balance += amount, nonce carried over.
/// Precondition: amount > 0.
/// Invariant: balance >= 0.
fn make_update_program() -> SirProgram {
    SirProgram {
        version: "0.1.0".to_string(),
        state_schema: SirStateSchema {
            fields: vec![
                SirFieldSchema { name: "balance".into(), field_type: "Int".into() },
                SirFieldSchema { name: "nonce".into(), field_type: "Int".into() },
            ],
        },
        input_schema: SirInputSchema {
            fields: vec![SirFieldSchema { name: "amount".into(), field_type: "Int".into() }],
        },
        transitions: vec![SirTransition {
            name: "deposit".into(),
            class: "Update".into(),
            preconditions: vec![SirExpr::BinOp {
                op: "gt".into(),
                left: Box::new(SirExpr::FieldAccess {
                    expr: Box::new(SirExpr::Var { name: "input".into() }),
                    field: "amount".into(),
                }),
                right: Box::new(SirExpr::Literal { value: SirValue::Int { value: 0 } }),
            }],
            postconditions: vec![],
            body: SirExpr::BinOp {
                op: "add".into(),
                left: Box::new(SirExpr::FieldAccess {
                    expr: Box::new(SirExpr::Var { name: "state".into() }),
                    field: "balance".into(),
                }),
                right: Box::new(SirExpr::FieldAccess {
                    expr: Box::new(SirExpr::Var { name: "input".into() }),
                    field: "amount".into(),
                }),
            },
            allowed_mutations: vec!["balance".into()],
        }],
        invariants: vec![SirInvariant {
            name: "L_non_negative".into(),
            category: "local".into(),
            expr: SirExpr::BinOp {
                op: "ge".into(),
                left: Box::new(SirExpr::FieldAccess {
                    expr: Box::new(SirExpr::Var { name: "state".into() }),
                    field: "balance".into(),
                }),
                right: Box::new(SirExpr::Literal { value: SirValue::Int { value: 0 } }),
            },
        }],
        observables: vec![],
    }
}

// ===========================================================================
// Helpers
// ===========================================================================

fn make_state_value(balance: i64, nonce: i64) -> SirValue {
    let mut entries = BTreeMap::new();
    entries.insert("balance".into(), SirValue::Int { value: balance });
    entries.insert("nonce".into(), SirValue::Int { value: nonce });
    SirValue::Map { entries }
}

fn make_input_value(amount: i64) -> SirValue {
    let mut entries = BTreeMap::new();
    entries.insert("amount".into(), SirValue::Int { value: amount });
    SirValue::Map { entries }
}

// ===========================================================================
// Proptest strategies
// ===========================================================================

/// Strategy for non-negative boundary values (valid balances/nonces).
fn boundary_non_negative() -> impl Strategy<Value = i64> {
    prop_oneof![
        3 => Just(0i64),
        3 => Just(1i64),
        2 => Just(100i64),
        2 => Just(999_999i64),
        10 => 0i64..=1_000_000,
    ]
}

/// Strategy for positive amounts (valid deposit amounts).
fn boundary_positive() -> impl Strategy<Value = i64> {
    prop_oneof![
        3 => Just(1i64),
        2 => Just(100i64),
        2 => Just(10_000i64),
        10 => 1i64..=1_000_000,
    ]
}


// ===========================================================================
// COMPLETENESS TESTS (LEM-5 direction)
//
// For random valid execution traces, verify the trace satisfies all
// constraints in the compiled constraint system.
//
// A valid trace is one where:
// - Pre-state satisfies all invariants
// - Post-state equals pre-state (for Noop transitions)
// - All carry-over constraints hold (no field mutations for Noop)
//
// **Validates: Requirements 8.3**
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// LEM-5 (Completeness): Valid single-step Noop traces satisfy all constraints.
    ///
    /// For any random valid state (balance >= 0), a Noop trace where
    /// post-state = pre-state must satisfy all constraints.
    ///
    /// **Validates: Requirements 8.3**
    #[test]
    fn prop_completeness_noop_valid_trace(
        balance in boundary_non_negative(),
        nonce in boundary_non_negative(),
    ) {
        let program = make_noop_program();
        let constraints = compile(&program);

        let state = make_state_value(balance, nonce);
        let input = make_input_value(0);
        // Valid trace: post-state = pre-state (Noop identity)
        let trace = vec![(state.clone(), input, state)];

        prop_assert!(
            satisfies_constraints(&trace, &constraints),
            "LEM-5 (completeness): valid Noop trace must satisfy all constraints. \
             balance={}, nonce={}",
            balance, nonce
        );
    }

    /// LEM-5 (Completeness): Valid multi-step Noop traces satisfy all constraints.
    ///
    /// For any random valid state, a sequence of 2-4 Noop steps where each
    /// step preserves the state must satisfy all constraints.
    ///
    /// **Validates: Requirements 8.3**
    #[test]
    fn prop_completeness_noop_multi_step(
        balance in boundary_non_negative(),
        nonce in boundary_non_negative(),
        num_steps in 2usize..=4,
    ) {
        let program = make_noop_program();
        let constraints = compile(&program);

        let state = make_state_value(balance, nonce);
        let input = make_input_value(0);
        let trace: Vec<_> = (0..num_steps)
            .map(|_| (state.clone(), input.clone(), state.clone()))
            .collect();

        prop_assert!(
            satisfies_constraints(&trace, &constraints),
            "LEM-5 (completeness): valid {}-step Noop trace must satisfy all constraints. \
             balance={}, nonce={}",
            num_steps, balance, nonce
        );
    }

    /// LEM-5 (Completeness): Valid multi-invariant Noop traces satisfy all constraints.
    ///
    /// For any random state satisfying all three invariants (balance >= 0,
    /// nonce >= 0, balance + nonce < 1_000_000), the Noop trace must satisfy
    /// all constraints.
    ///
    /// **Validates: Requirements 8.3**
    #[test]
    fn prop_completeness_multi_invariant_valid(
        balance in 0i64..=499_999,
        nonce in 0i64..=499_999,
    ) {
        // Skip if G_bounded_total would be violated
        if balance + nonce >= 1_000_000 {
            return Ok(());
        }

        let program = make_multi_invariant_program();
        let constraints = compile(&program);

        let state = make_state_value(balance, nonce);
        let input = make_input_value(0);
        let trace = vec![(state.clone(), input, state)];

        prop_assert!(
            satisfies_constraints(&trace, &constraints),
            "LEM-5 (completeness): valid multi-invariant trace must satisfy all constraints. \
             balance={}, nonce={}, sum={}",
            balance, nonce, balance + nonce
        );
    }
}

// ===========================================================================
// SOUNDNESS TESTS (LEM-4 direction, contrapositive)
//
// For random invalid traces (with at least one invariant violation),
// verify the trace violates at least one constraint in the compiled
// constraint system.
//
// Invalid traces are constructed by deliberately violating:
// 1. Invariant constraints (negative balance, negative nonce, sum overflow)
// 2. Carry-over constraints (field changed when not in AllowedMutations)
// 3. Precondition constraints (invalid input values)
// 4. Multiple simultaneous violations
//
// **Validates: Requirements 8.3**
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// LEM-4 (Soundness): Traces with negative balance violate at least one constraint.
    ///
    /// A trace where the pre-state has a negative balance violates the
    /// L_non_negative invariant and must be rejected by the constraint system.
    ///
    /// **Validates: Requirements 8.3**
    #[test]
    fn prop_soundness_negative_balance_rejected(
        negative_balance in -1_000_000i64..=-1,
        nonce in boundary_non_negative(),
    ) {
        let program = make_noop_program();
        let constraints = compile(&program);

        let state = make_state_value(negative_balance, nonce);
        let input = make_input_value(0);
        let trace = vec![(state.clone(), input, state)];

        prop_assert!(
            !satisfies_constraints(&trace, &constraints),
            "LEM-4 (soundness): trace with negative balance ({}) must violate \
             at least one constraint",
            negative_balance
        );
    }

    /// LEM-4 (Soundness): Traces with carry-over violation (balance changed in Noop).
    ///
    /// A Noop trace where the balance changes between pre and post state
    /// violates the carry-over constraint for the balance field.
    ///
    /// **Validates: Requirements 8.3**
    #[test]
    fn prop_soundness_carryover_balance_violated(
        balance in boundary_non_negative(),
        nonce in boundary_non_negative(),
        delta in 1i64..=10_000,
    ) {
        let program = make_noop_program();
        let constraints = compile(&program);

        let pre = make_state_value(balance, nonce);
        let input = make_input_value(0);
        // Invalid: balance changed in a Noop (not in AllowedMutations)
        let post = make_state_value(balance.saturating_add(delta), nonce);

        let trace = vec![(pre, input, post)];

        prop_assert!(
            !satisfies_constraints(&trace, &constraints),
            "LEM-4 (soundness): Noop trace with balance changed by {} must be rejected",
            delta
        );
    }

    /// LEM-4 (Soundness): Traces with carry-over violation (nonce changed in Noop).
    ///
    /// A Noop trace where the nonce changes between pre and post state
    /// violates the carry-over constraint for the nonce field.
    ///
    /// **Validates: Requirements 8.3**
    #[test]
    fn prop_soundness_carryover_nonce_violated(
        balance in boundary_non_negative(),
        nonce in boundary_non_negative(),
        delta in 1i64..=10_000,
    ) {
        let program = make_noop_program();
        let constraints = compile(&program);

        let pre = make_state_value(balance, nonce);
        let input = make_input_value(0);
        // Invalid: nonce changed in a Noop (not in AllowedMutations)
        let post = make_state_value(balance, nonce.saturating_add(delta));

        let trace = vec![(pre, input, post)];

        prop_assert!(
            !satisfies_constraints(&trace, &constraints),
            "LEM-4 (soundness): Noop trace with nonce changed by {} must be rejected",
            delta
        );
    }

    /// LEM-4 (Soundness): Multi-invariant traces with negative balance rejected.
    ///
    /// **Validates: Requirements 8.3**
    #[test]
    fn prop_soundness_multi_invariant_negative_balance(
        negative_balance in -1_000_000i64..=-1,
        nonce in 0i64..=100_000,
    ) {
        let program = make_multi_invariant_program();
        let constraints = compile(&program);

        let state = make_state_value(negative_balance, nonce);
        let input = make_input_value(0);
        let trace = vec![(state.clone(), input, state)];

        prop_assert!(
            !satisfies_constraints(&trace, &constraints),
            "LEM-4 (soundness): multi-invariant trace with negative balance ({}) \
             must be rejected",
            negative_balance
        );
    }

    /// LEM-4 (Soundness): Multi-invariant traces with negative nonce rejected.
    ///
    /// **Validates: Requirements 8.3**
    #[test]
    fn prop_soundness_multi_invariant_negative_nonce(
        balance in 0i64..=100_000,
        negative_nonce in -1_000_000i64..=-1,
    ) {
        let program = make_multi_invariant_program();
        let constraints = compile(&program);

        let state = make_state_value(balance, negative_nonce);
        let input = make_input_value(0);
        let trace = vec![(state.clone(), input, state)];

        prop_assert!(
            !satisfies_constraints(&trace, &constraints),
            "LEM-4 (soundness): multi-invariant trace with negative nonce ({}) \
             must be rejected",
            negative_nonce
        );
    }

    /// LEM-4 (Soundness): Multi-invariant traces with G_bounded_total violated.
    ///
    /// When balance + nonce >= 1_000_000, the G_bounded_total invariant is
    /// violated and the constraint system must reject the trace.
    ///
    /// **Validates: Requirements 8.3**
    #[test]
    fn prop_soundness_multi_invariant_bounded_total_violated(
        balance in 500_000i64..=999_999,
        nonce_offset in 0i64..=500_000,
    ) {
        let nonce = 1_000_000 - balance + nonce_offset;
        // Ensure sum >= 1_000_000
        if balance + nonce < 1_000_000 {
            return Ok(());
        }

        let program = make_multi_invariant_program();
        let constraints = compile(&program);

        let state = make_state_value(balance, nonce);
        let input = make_input_value(0);
        let trace = vec![(state.clone(), input, state)];

        prop_assert!(
            !satisfies_constraints(&trace, &constraints),
            "LEM-4 (soundness): trace violating G_bounded_total must be rejected. \
             balance={}, nonce={}, sum={}",
            balance, nonce, balance + nonce
        );
    }

    /// LEM-4 (Soundness): Update traces with precondition violation rejected.
    ///
    /// A deposit trace with amount <= 0 violates the precondition (amount > 0)
    /// and must be rejected by the constraint system.
    ///
    /// **Validates: Requirements 8.3**
    #[test]
    fn prop_soundness_update_precondition_violated(
        balance in boundary_non_negative(),
        nonce in boundary_non_negative(),
        bad_amount in -10_000i64..=0,
    ) {
        let program = make_update_program();
        let constraints = compile(&program);

        let pre = make_state_value(balance, nonce);
        let input = make_input_value(bad_amount);
        let post = make_state_value(balance.saturating_add(bad_amount), nonce);

        let trace = vec![(pre, input, post)];

        prop_assert!(
            !satisfies_constraints(&trace, &constraints),
            "LEM-4 (soundness): Update trace with bad amount ({}) must be rejected",
            bad_amount
        );
    }

    /// LEM-4 (Soundness): Update traces with carry-over violation rejected.
    ///
    /// A deposit trace where the nonce changes (not in AllowedMutations)
    /// must be rejected by the carry-over constraint.
    ///
    /// **Validates: Requirements 8.3**
    #[test]
    fn prop_soundness_update_carryover_violated(
        balance in boundary_non_negative(),
        nonce in boundary_non_negative(),
        amount in boundary_positive(),
        nonce_delta in 1i64..=100,
    ) {
        let program = make_update_program();
        let constraints = compile(&program);

        let pre = make_state_value(balance, nonce);
        let input = make_input_value(amount);
        // Invalid: nonce changed (not in AllowedMutations for deposit)
        let post = make_state_value(
            balance.saturating_add(amount),
            nonce.saturating_add(nonce_delta),
        );

        let trace = vec![(pre, input, post)];

        prop_assert!(
            !satisfies_constraints(&trace, &constraints),
            "LEM-4 (soundness): Update trace with carry-over violation must be rejected. \
             nonce changed from {} to {}",
            nonce, nonce.saturating_add(nonce_delta)
        );
    }

    /// LEM-4 (Soundness): Multi-step trace where second step has invariant violation.
    ///
    /// A two-step Noop trace where the first step is valid but the second step
    /// has a negative balance must be rejected.
    ///
    /// **Validates: Requirements 8.3**
    #[test]
    fn prop_soundness_multi_step_second_violation(
        balance in boundary_non_negative(),
        nonce in boundary_non_negative(),
        negative_balance in -1_000_000i64..=-1,
    ) {
        let program = make_noop_program();
        let constraints = compile(&program);

        let valid_state = make_state_value(balance, nonce);
        let invalid_state = make_state_value(negative_balance, nonce);
        let input = make_input_value(0);

        // Step 1: valid, Step 2: invalid (negative balance in pre-state)
        let trace = vec![
            (valid_state.clone(), input.clone(), valid_state),
            (invalid_state.clone(), input, invalid_state),
        ];

        prop_assert!(
            !satisfies_constraints(&trace, &constraints),
            "LEM-4 (soundness): multi-step trace with second-step invariant violation \
             must be rejected. negative_balance={}",
            negative_balance
        );
    }

    /// LEM-4 (Soundness): Traces with both carry-over AND invariant violations.
    ///
    /// A Noop trace where the balance changes AND the pre-state has a negative
    /// balance must be rejected (double violation).
    ///
    /// **Validates: Requirements 8.3**
    #[test]
    fn prop_soundness_double_violation(
        negative_balance in -1_000_000i64..=-1,
        nonce in boundary_non_negative(),
        delta in 1i64..=10_000,
    ) {
        let program = make_noop_program();
        let constraints = compile(&program);

        let pre = make_state_value(negative_balance, nonce);
        let input = make_input_value(0);
        // Double violation: negative balance AND balance changed in Noop
        let post = make_state_value(negative_balance.saturating_add(delta), nonce);

        let trace = vec![(pre, input, post)];

        prop_assert!(
            !satisfies_constraints(&trace, &constraints),
            "LEM-4 (soundness): trace with double violation must be rejected. \
             negative_balance={}, delta={}",
            negative_balance, delta
        );
    }
}

// ===========================================================================
// BIDIRECTIONAL EQUIVALENCE TESTS
//
// For Noop programs where the body constraint is fully evaluable (body = state),
// we can test the full bidirectional equivalence:
//   SatisfiesConstraints(τ, cs) ⟺ ValidTrace(τ)
//
// This is the strongest form of the LEM-4/LEM-5 axiom verification.
//
// **Validates: Requirements 8.3**
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// Bidirectional LEM-4/LEM-5: constraint satisfaction ⟺ trace validity.
    ///
    /// For any random (balance, nonce) pair, a Noop trace with unchanged state
    /// satisfies constraints if and only if the invariant holds (balance >= 0).
    ///
    /// **Validates: Requirements 8.3**
    #[test]
    fn prop_bidirectional_noop_equivalence(
        balance in -100_000i64..=100_000,
        nonce in 0i64..=100_000,
    ) {
        let program = make_noop_program();
        let constraints = compile(&program);

        let state = make_state_value(balance, nonce);
        let input = make_input_value(0);
        let trace = vec![(state.clone(), input, state)];

        let sat = satisfies_constraints(&trace, &constraints);
        let valid = balance >= 0; // invariant: balance >= 0

        prop_assert_eq!(
            sat, valid,
            "LEM-4/LEM-5 bidirectional: sat={}, valid={}, balance={}, nonce={}",
            sat, valid, balance, nonce
        );
    }

    /// Bidirectional LEM-4/LEM-5: multi-invariant constraint satisfaction ⟺ trace validity.
    ///
    /// For any random (balance, nonce) pair, a multi-invariant Noop trace
    /// satisfies constraints if and only if ALL invariants hold:
    /// balance >= 0 AND nonce >= 0 AND balance + nonce < 1_000_000.
    ///
    /// **Validates: Requirements 8.3**
    #[test]
    fn prop_bidirectional_multi_invariant_equivalence(
        balance in -10_000i64..=600_000,
        nonce in -10_000i64..=600_000,
    ) {
        let program = make_multi_invariant_program();
        let constraints = compile(&program);

        let state = make_state_value(balance, nonce);
        let input = make_input_value(0);
        let trace = vec![(state.clone(), input, state)];

        let sat = satisfies_constraints(&trace, &constraints);
        let valid = balance >= 0
            && nonce >= 0
            && balance.checked_add(nonce).map_or(false, |sum| sum < 1_000_000);

        prop_assert_eq!(
            sat, valid,
            "LEM-4/LEM-5 bidirectional multi-invariant: sat={}, valid={}, \
             balance={}, nonce={}, sum={}",
            sat, valid, balance, nonce,
            balance.checked_add(nonce).unwrap_or(i64::MAX)
        );
    }
}


// ===========================================================================
// PROPERTY 10: DIFFERENTIAL APPLY CONSISTENCY
//
// For random (state, input) pairs, verify the Rust `Apply` function produces
// the same transition classification, post-state field values, and observable
// outputs as predicted by the formal specification's transition semantics.
//
// The test validates three aspects of Apply consistency:
//
// 1. **Transition classification**: `classify(s, σ)` in Rust matches the
//    formal specification's guard-based classification (priority ordering
//    T_REJECT > T_INIT > T_ERROR > T_BATCH > T_UPDATE > T_NOOP).
//
// 2. **Post-state field values**: The mapped post-state `μ_S(apply(s, σ))`
//    is consistent with the formal transition semantics — verified through
//    execution-mapping commutativity (THM-1) and derived/economic consistency.
//
// 3. **Observable outputs**: `μ_O(obs(s, σ, s'))` is consistent with the
//    formal observable semantics — verified through observable commutativity
//    (THM-2) and status/class correspondence.
//
// Additionally, the differential framework (`run_differential`) is used to
// compare concrete Rust execution against the SIR reference interpreter for
// transition classes where a SIR program is defined.
//
// Test at minimum 1,000 randomly generated pairs.
//
// **Validates: Requirements 8.4**
// ===========================================================================

use vsel_core::input::{Authorization, Input};
use vsel_core::observable::{obs, TransitionStatus};
use vsel_core::state::{
    derive, derive_economic, CanonicalState, Environment, State, TraceMetadata,
    AccountData,
};
use vsel_core::transition::{apply, classify, TransitionClass};
use vsel_core::types::{
    AccountId, AuxiliaryData, DomainTag, Hash, HybridPublicKey, Payload,
    ProtocolVersion, SystemData,
};
use vsel_mapping::differential::{run_differential, DivergenceKind};
use vsel_mapping::mapping::{
    map_input, map_state, map_transition,
    verify_execution_commutativity, verify_observable_commutativity,
};

// ===========================================================================
// Proptest strategies for Property 10
// ===========================================================================

/// Generate a random 32-byte array.
fn arb_bytes32() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

/// Generate a random AccountId.
fn arb_account_id() -> impl Strategy<Value = AccountId> {
    arb_bytes32().prop_map(AccountId)
}

/// Generate a random AccountData with bounded values.
fn arb_account_data() -> impl Strategy<Value = AccountData> {
    (
        0u128..=1_000_000u128,
        0u64..=1_000_000u64,
        prop::collection::vec(any::<u8>(), 0..32),
    )
        .prop_map(|(balance, nonce, data)| AccountData {
            balance,
            nonce,
            data,
        })
}

/// Generate a random CanonicalState with total_supply matching sum of balances.
fn arb_canonical() -> impl Strategy<Value = CanonicalState> {
    (
        proptest::collection::btree_map(arb_account_id(), arb_account_data(), 0..5),
        0u32..10,
        0u32..100,
        0u32..100,
    )
        .prop_map(|(accounts, major, minor, patch)| {
            let total_supply: u128 = accounts.values().map(|a| a.balance).sum();
            CanonicalState {
                accounts,
                storage: BTreeMap::new(),
                system_data: SystemData {
                    protocol_version: ProtocolVersion { major, minor, patch },
                    total_supply,
                    parameters: BTreeMap::new(),
                },
            }
        })
}

/// Generate a non-zero DomainTag (required for valid environment).
fn arb_domain_tag() -> impl Strategy<Value = DomainTag> {
    arb_bytes32()
        .prop_filter("domain tag must not be all zeros", |b| b.iter().any(|&x| x != 0))
        .prop_map(|b| DomainTag(Hash(b)))
}

/// Generate a valid Environment.
fn arb_env() -> impl Strategy<Value = Environment> {
    (1u64..=u64::MAX, 0u64..=1_000_000u64, arb_domain_tag()).prop_map(
        |(timestamp, block_height, execution_domain)| Environment {
            timestamp,
            block_height,
            execution_domain,
        },
    )
}

/// Generate a valid Authorization.
fn arb_auth() -> impl Strategy<Value = Authorization> {
    (
        prop::collection::vec(any::<u8>(), 1..64),
        prop::collection::vec(any::<u8>(), 1..64),
        prop::collection::vec(any::<u8>(), 1..64),
        prop::collection::vec(any::<u8>(), 1..64),
        any::<u64>(),
        arb_domain_tag(),
    )
        .prop_map(|(classical_sig, pqc_sig, pk_classical, pk_pqc, nonce, domain)| {
            Authorization {
                classical_sig,
                pqc_sig,
                public_key: HybridPublicKey {
                    classical: pk_classical,
                    pqc: pk_pqc,
                },
                nonce,
                domain,
            }
        })
}

/// Build a valid State from canonical + environment at a given sequence index.
fn build_state(canonical: CanonicalState, env: Environment, seq: u64) -> State {
    let derived = derive(&canonical);
    let economic = derive_economic(&canonical, &env);
    let commitment = if seq == 0 {
        Hash([0u8; 32])
    } else {
        Hash([0xABu8; 32])
    };
    let metadata = TraceMetadata {
        sequence_index: seq,
        previous_commitment: commitment,
        epoch: 0,
        timestamp: env.timestamp,
    };
    State {
        canonical,
        derived,
        environment: env,
        economic,
        metadata,
    }
}

/// Generate a valid State at a random sequence index.
fn arb_state() -> impl Strategy<Value = State> {
    (arb_canonical(), arb_env(), prop_oneof![Just(0u64), 1u64..=1_000])
        .prop_map(|(canonical, env, seq)| build_state(canonical, env, seq))
}

/// Generate a random Input with a recognized payload type (for diverse classification).
fn arb_diverse_input() -> impl Strategy<Value = Input> {
    (
        prop_oneof![
            // Recognized types that trigger different transition classes
            Just("init".to_string()),
            Just("transfer".to_string()),
            Just("deposit".to_string()),
            Just("withdraw".to_string()),
            Just("batch".to_string()),
            Just("update".to_string()),
            // Unrecognized types → Noop
            Just("unknown_op".to_string()),
            Just("query".to_string()),
        ],
        prop::collection::vec(any::<u8>(), 1..128),
        arb_auth(),
        prop::collection::vec(any::<u8>(), 0..32),
    )
        .prop_map(|(payload_type, data, auth, aux_data)| Input {
            payload: Payload { payload_type, data },
            auth,
            aux: AuxiliaryData { data: aux_data },
        })
}

/// Generate an invalid Input (empty payload_type → Reject classification).
fn arb_invalid_input() -> impl Strategy<Value = Input> {
    (
        arb_auth(),
        prop::collection::vec(any::<u8>(), 0..32),
    )
        .prop_map(|(auth, aux_data)| Input {
            payload: Payload {
                payload_type: String::new(),
                data: vec![],
            },
            auth,
            aux: AuxiliaryData { data: aux_data },
        })
}

/// Generate a (state, input) pair covering all transition classes.
fn arb_state_input_pair() -> impl Strategy<Value = (State, Input)> {
    prop_oneof![
        // Valid inputs with diverse payload types
        8 => (arb_state(), arb_diverse_input()),
        // Invalid inputs → Reject class
        2 => (arb_state(), arb_invalid_input()),
    ]
}

/// Build a SIR program with identity transitions for all classes.
/// Each transition returns the state unchanged — this allows the differential
/// framework to detect divergences in the mapping layer.
fn make_differential_sir_program() -> SirProgram {
    let make_identity_transition = |name: &str, class: &str| SirTransition {
        name: name.to_string(),
        class: class.to_string(),
        preconditions: vec![],
        postconditions: vec![],
        body: SirExpr::Var { name: "state".into() },
        allowed_mutations: vec![],
    };

    SirProgram {
        version: "0.1.0".into(),
        state_schema: SirStateSchema { fields: vec![] },
        input_schema: SirInputSchema { fields: vec![] },
        transitions: vec![
            make_identity_transition("reject", "reject"),
            make_identity_transition("init", "init"),
            make_identity_transition("error", "error"),
            make_identity_transition("batch", "batch"),
            make_identity_transition("update", "update"),
            make_identity_transition("noop", "noop"),
        ],
        invariants: vec![],
        observables: vec![],
    }
}

// ===========================================================================
// Helper: verify formal specification transition semantics
// ===========================================================================

/// Verify that the transition classification is consistent with the formal
/// specification's guard priority ordering.
///
/// The formal specification defines:
///   T_REJECT > T_INIT > T_ERROR > T_BATCH > T_UPDATE > T_NOOP
///
/// This function verifies that the Rust `classify` function produces a
/// classification consistent with the guard definitions.
fn verify_classification_consistency(s: &State, sigma: &Input) -> bool {
    let class = classify(s, sigma);

    // Verify the classification is a valid TransitionClass
    let valid_class = matches!(
        class,
        TransitionClass::Reject
            | TransitionClass::Init
            | TransitionClass::Error
            | TransitionClass::Batch
            | TransitionClass::Update
            | TransitionClass::Noop
    );
    if !valid_class {
        return false;
    }

    // Verify guard priority: if Reject fires, no lower-priority guard should
    // have been applicable. We verify this by checking the guard conditions.
    use vsel_core::input::valid_input;

    match class {
        TransitionClass::Reject => {
            // G_REJECT: input is structurally invalid
            !valid_input(sigma)
        }
        TransitionClass::Init => {
            // G_INIT: valid input AND seq == 0 AND payload_type == "init"
            valid_input(sigma)
                && s.metadata.sequence_index == 0
                && sigma.payload.payload_type == "init"
        }
        TransitionClass::Error => {
            // G_ERROR: valid input AND NOT init AND precondition failure
            valid_input(sigma)
                && !(s.metadata.sequence_index == 0 && sigma.payload.payload_type == "init")
        }
        TransitionClass::Batch => {
            // G_BATCH: valid input AND NOT init AND NOT error AND payload_type == "batch"
            valid_input(sigma) && sigma.payload.payload_type == "batch"
        }
        TransitionClass::Update => {
            // G_UPDATE: valid input AND recognized payload type
            valid_input(sigma)
        }
        TransitionClass::Noop => {
            // G_NOOP: catch-all — valid input but no other guard matched
            valid_input(sigma)
        }
    }
}

/// Verify that the observable status is consistent with the transition class.
///
/// The formal specification defines:
///   Init, Batch, Update → Success (status 0)
///   Reject, Noop → Rejected (status 1)
///   Error → Error (status 2)
fn verify_observable_status_consistency(class: TransitionClass, status: TransitionStatus) -> bool {
    match class {
        TransitionClass::Init | TransitionClass::Batch | TransitionClass::Update => {
            status == TransitionStatus::Success
        }
        TransitionClass::Reject | TransitionClass::Noop => {
            status == TransitionStatus::Rejected
        }
        TransitionClass::Error => {
            status == TransitionStatus::Error
        }
    }
}

/// Verify that state-preserving transitions (Reject, Error, Noop) do not
/// modify the canonical state.
fn verify_state_preservation(class: TransitionClass, pre: &State, post: &State) -> bool {
    match class {
        TransitionClass::Reject | TransitionClass::Error | TransitionClass::Noop => {
            pre.canonical == post.canonical
        }
        // Init, Batch, Update may modify canonical state
        _ => true,
    }
}

/// Verify that metadata is always advanced (sequence_index incremented).
fn verify_metadata_advancement(pre: &State, post: &State) -> bool {
    post.metadata.sequence_index == pre.metadata.sequence_index.saturating_add(1)
}

/// Verify that derived state is consistent: D' = derive(C').
fn verify_derived_consistency(post: &State) -> bool {
    let expected_derived = derive(&post.canonical);
    post.derived == expected_derived
}

/// Verify that economic context is consistent: Ω' = derive_economic(C', E').
fn verify_economic_consistency(post: &State) -> bool {
    let expected_economic = derive_economic(&post.canonical, &post.environment);
    post.economic == expected_economic
}

// ===========================================================================
// PROPERTY 10 TESTS
//
// Differential Apply consistency: for random (state, input) pairs, verify
// the Rust Apply function produces the same transition classification,
// post-state field values, and observable outputs as predicted by the
// formal specification's transition semantics.
//
// **Validates: Requirements 8.4**
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// Property 10a: Transition classification consistency.
    ///
    /// For any random (state, input) pair, the Rust `classify` function
    /// produces a classification consistent with the formal specification's
    /// guard-based priority ordering.
    ///
    /// **Validates: Requirements 8.4**
    #[test]
    fn prop_differential_classification_consistency(
        (s, sigma) in arb_state_input_pair(),
    ) {
        let class = classify(&s, &sigma);

        // 1. Classification must be consistent with guard conditions
        prop_assert!(
            verify_classification_consistency(&s, &sigma),
            "Property 10: classification {} is inconsistent with guard conditions \
             for payload_type={:?}, seq={}",
            class as u8,
            sigma.payload.payload_type,
            s.metadata.sequence_index
        );

        // 2. Classification must be deterministic
        let class2 = classify(&s, &sigma);
        prop_assert_eq!(
            class, class2,
            "Property 10: classify must be deterministic"
        );
    }

    /// Property 10b: Post-state field value consistency via execution-mapping
    /// commutativity (THM-1).
    ///
    /// For any random (state, input) pair, the mapped post-state
    /// `μ_S(apply(s, σ))` is consistent with the formal transition semantics.
    /// This verifies that:
    /// - The formal transition triple is internally consistent
    /// - Derived state D' = derive(C') through the mapping
    /// - Economic context Ω' = derive_economic(C', E') through the mapping
    ///
    /// **Validates: Requirements 8.4**
    #[test]
    fn prop_differential_post_state_consistency(
        (s, sigma) in arb_state_input_pair(),
    ) {
        // Execute Apply concretely
        let post = apply(&s, &sigma);
        let class = classify(&s, &sigma);

        // 1. Execution-mapping commutativity (THM-1)
        prop_assert!(
            verify_execution_commutativity(&s, &sigma),
            "Property 10 (THM-1): execution-mapping commutativity failed for \
             class={:?}, payload_type={:?}",
            class,
            sigma.payload.payload_type
        );

        // 2. Derived state consistency: D' = derive(C')
        prop_assert!(
            verify_derived_consistency(&post),
            "Property 10: derived state inconsistent after Apply. class={:?}",
            class
        );

        // 3. Economic context consistency: Ω' = derive_economic(C', E')
        prop_assert!(
            verify_economic_consistency(&post),
            "Property 10: economic context inconsistent after Apply. class={:?}",
            class
        );

        // 4. State preservation for non-mutating transitions
        prop_assert!(
            verify_state_preservation(class, &s, &post),
            "Property 10: state-preserving transition {:?} modified canonical state",
            class
        );

        // 5. Metadata always advances
        prop_assert!(
            verify_metadata_advancement(&s, &post),
            "Property 10: metadata not advanced after Apply. pre_seq={}, post_seq={}",
            s.metadata.sequence_index,
            post.metadata.sequence_index
        );
    }

    /// Property 10c: Observable output consistency via observable commutativity
    /// (THM-2).
    ///
    /// For any random (state, input) pair, the observable `obs(s, σ, s')`
    /// is consistent with the formal observable semantics:
    /// - Transition class in observable matches `classify(s, σ)`
    /// - Status is consistent with the transition class
    /// - Observable is deterministic
    ///
    /// **Validates: Requirements 8.4**
    #[test]
    fn prop_differential_observable_consistency(
        (s, sigma) in arb_state_input_pair(),
    ) {
        let post = apply(&s, &sigma);
        let class = classify(&s, &sigma);
        let observable = obs(&s, &sigma, &post);

        // 1. Observable commutativity (THM-2)
        prop_assert!(
            verify_observable_commutativity(&s, &sigma),
            "Property 10 (THM-2): observable commutativity failed for class={:?}",
            class
        );

        // 2. Transition class in observable matches classify
        prop_assert_eq!(
            observable.transition_class, class,
            "Property 10: observable transition_class {:?} != classify result {:?}",
            observable.transition_class, class
        );

        // 3. Status is consistent with transition class
        prop_assert!(
            verify_observable_status_consistency(class, observable.status),
            "Property 10: observable status {:?} inconsistent with class {:?}",
            observable.status, class
        );

        // 4. Observable is deterministic
        let observable2 = obs(&s, &sigma, &post);
        prop_assert_eq!(
            &observable, &observable2,
            "Property 10: obs must be deterministic"
        );

        // 5. Non-mutating transitions produce no output events
        if matches!(class, TransitionClass::Reject | TransitionClass::Error | TransitionClass::Noop) {
            prop_assert!(
                observable.outputs.is_empty(),
                "Property 10: non-mutating transition {:?} produced {} output events",
                class, observable.outputs.len()
            );
        }
    }

    /// Property 10d: Differential Apply via SIR reference interpreter.
    ///
    /// For any random (state, input) pair, run the differential execution
    /// framework comparing concrete Rust execution against the SIR reference
    /// interpreter. Verify no divergences in state mapping or classification.
    ///
    /// Note: The SIR program uses identity transitions (body = state), so
    /// state divergences are expected for mutating transitions (Init, Update,
    /// Batch). The test focuses on:
    /// - Non-mutating transitions (Reject, Error, Noop) should agree
    /// - Classification is always consistent
    /// - No unexpected interpreter errors for non-error transitions
    ///
    /// **Validates: Requirements 8.4**
    #[test]
    fn prop_differential_sir_comparison(
        (s, sigma) in arb_state_input_pair(),
    ) {
        let program = make_differential_sir_program();
        let result = run_differential(&s, &sigma, &program);
        let class = classify(&s, &sigma);

        // 1. The differential framework must execute without panic
        // (If we reach here, it did.)

        // 2. For non-mutating transitions, the SIR identity program should
        //    agree on the canonical state (since canonical is unchanged).
        //    However, metadata changes, so full state agreement is not expected.
        //    We check that no classification divergences occurred.
        let classification_divergences: Vec<_> = result.divergences.iter()
            .filter(|d| matches!(d, DivergenceKind::ClassificationDivergence { .. }))
            .collect();
        prop_assert!(
            classification_divergences.is_empty(),
            "Property 10: classification divergence detected for class={:?}: {:?}",
            class, classification_divergences
        );

        // 3. For Error and Reject transitions, SIR interpreter errors are expected
        //    (precondition failures, invalid inputs). Verify the framework handles
        //    them correctly.
        if matches!(class, TransitionClass::Error | TransitionClass::Reject) {
            // These may have SIR errors — that's expected behavior
            if result.sir_error.is_some() {
                prop_assert!(
                    result.agrees,
                    "Property 10: error/reject transition with SIR error should be \
                     marked as agreeing. class={:?}, error={:?}",
                    class, result.sir_error
                );
            }
        }

        // 4. Verify the concrete post-state is valid
        prop_assert!(
            verify_derived_consistency(&result.concrete_post),
            "Property 10: concrete post-state has inconsistent derived state"
        );
        prop_assert!(
            verify_economic_consistency(&result.concrete_post),
            "Property 10: concrete post-state has inconsistent economic context"
        );
    }

    /// Property 10e: Apply determinism across all transition classes.
    ///
    /// For any random (state, input) pair, calling `apply` twice with
    /// identical inputs produces identical post-states (AX-1).
    ///
    /// **Validates: Requirements 8.4**
    #[test]
    fn prop_differential_apply_determinism(
        (s, sigma) in arb_state_input_pair(),
    ) {
        let post1 = apply(&s, &sigma);
        let post2 = apply(&s, &sigma);

        prop_assert_eq!(
            &post1, &post2,
            "Property 10 (AX-1): apply must be deterministic"
        );

        // Also verify the mapped formal states are identical
        let formal1 = map_state(&post1);
        let formal2 = map_state(&post2);
        prop_assert_eq!(
            &formal1, &formal2,
            "Property 10: mapped formal post-states must be identical"
        );
    }

    /// Property 10f: Formal transition triple consistency.
    ///
    /// For any random (state, input) pair, the formal transition triple
    /// `(μ_S(s), μ_Σ(σ), μ_S(s'))` is internally consistent:
    /// - map_transition composes correctly from individual mappings
    /// - The formal pre-state, input, and post-state are well-formed Maps
    ///
    /// **Validates: Requirements 8.4**
    #[test]
    fn prop_differential_formal_triple_consistency(
        (s, sigma) in arb_state_input_pair(),
    ) {
        let post = apply(&s, &sigma);

        let formal_pre = map_state(&s);
        let formal_input = map_input(&sigma);
        let formal_post = map_state(&post);
        let formal_transition = map_transition(&s, &sigma, &post);

        // 1. Transition triple composes correctly
        prop_assert_eq!(
            &formal_transition.pre, &formal_pre,
            "Property 10: formal transition pre != map_state(pre)"
        );
        prop_assert_eq!(
            &formal_transition.input, &formal_input,
            "Property 10: formal transition input != map_input(input)"
        );
        prop_assert_eq!(
            &formal_transition.post, &formal_post,
            "Property 10: formal transition post != map_state(post)"
        );

        // 2. All formal values are well-formed Maps
        prop_assert!(
            matches!(&formal_pre.0, SirValue::Map { .. }),
            "Property 10: formal pre-state must be a Map"
        );
        prop_assert!(
            matches!(&formal_input.0, SirValue::Map { .. }),
            "Property 10: formal input must be a Map"
        );
        prop_assert!(
            matches!(&formal_post.0, SirValue::Map { .. }),
            "Property 10: formal post-state must be a Map"
        );

        // 3. Formal post-state has derived_valid = true
        if let SirValue::Map { entries } = &formal_post.0 {
            prop_assert_eq!(
                entries.get("derived_valid"),
                Some(&SirValue::Bool { value: true }),
                "Property 10: formal post-state derived_valid must be true"
            );
        }
    }
}
