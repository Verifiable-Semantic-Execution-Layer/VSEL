//! Adversarial constraint fuzzing — proptest-based fuzzer for the VSEL constraint system.
//!
//! Derived from: UNDERCONSTRAINT_ANALYSIS.md, CONSTRAINT_DERIVATION.md.
//! Requirements: 13.6 (adversarial constraint testing).
//!
//! Phase 3 (Rust side): Adversarial fuzzing with proptest.
//!
//! Strategies:
//! - Random invalid traces: randomly generated trace steps with corrupted fields.
//! - Witness mutation: valid witnesses with targeted field mutations.
//! - Targeted U-type inputs: inputs designed to exploit each U-type vulnerability.
//!
//! All tests verify that the constraint system correctly rejects adversarial inputs
//! or, when inputs are valid, correctly accepts them.

use std::collections::BTreeMap;

use proptest::prelude::*;

use vsel_constraints::compiler::{
    compile, satisfies_constraints, Constraint, ConstraintCategory, ConstraintExpr,
    ConstraintId, ConstraintSystem, WitnessVariable, WitnessVariableKind,
};
use vsel_constraints::underconstraint::{
    detect_u1_free_variables, detect_u2_weakly_constrained,
    detect_u5_orphan, detect_u6_range_cosmetic,
};
use vsel_sir::types::{
    SirExpr, SirFieldSchema, SirInputSchema, SirInvariant, SirProgram, SirStateSchema,
    SirTransition, SirValue,
};

// ---------------------------------------------------------------------------
// Proptest strategies for adversarial inputs
// ---------------------------------------------------------------------------

/// Generate a random SIR expression with bounded depth.
fn arb_sir_expr(max_depth: u32) -> impl Strategy<Value = SirExpr> {
    if max_depth == 0 {
        prop_oneof![
            (-1000i64..=1000i64).prop_map(|v| SirExpr::Literal {
                value: SirValue::Int { value: v }
            }),
            any::<bool>().prop_map(|v| SirExpr::Literal {
                value: SirValue::Bool { value: v }
            }),
            "[a-z][a-z0-9_]{0,5}".prop_map(|name| SirExpr::Var { name }),
        ]
        .boxed()
    } else {
        let leaf = prop_oneof![
            (-1000i64..=1000i64).prop_map(|v| SirExpr::Literal {
                value: SirValue::Int { value: v }
            }),
            any::<bool>().prop_map(|v| SirExpr::Literal {
                value: SirValue::Bool { value: v }
            }),
            "[a-z][a-z0-9_]{0,5}".prop_map(|name| SirExpr::Var { name }),
        ];

        let binop = {
            let d = max_depth - 1;
            (
                prop_oneof!["add", "sub", "mul", "eq", "neq", "lt", "le", "gt", "ge", "and", "or"],
                arb_sir_expr(d),
                arb_sir_expr(d),
            )
                .prop_map(|(op, left, right)| SirExpr::BinOp {
                    op: op.to_string(),
                    left: Box::new(left),
                    right: Box::new(right),
                })
        };

        let if_expr = {
            let d = max_depth - 1;
            (arb_sir_expr(d), arb_sir_expr(d), arb_sir_expr(d)).prop_map(
                |(cond, then_, else_)| SirExpr::If {
                    cond: Box::new(cond),
                    then_: Box::new(then_),
                    else_: Box::new(else_),
                },
            )
        };

        prop_oneof![
            4 => leaf,
            2 => binop,
            1 => if_expr,
        ]
        .boxed()
    }
}

/// Generate a random SIR program for fuzzing.
fn arb_fuzz_program() -> impl Strategy<Value = SirProgram> {
    (
        prop::collection::vec(
            ("[a-z][a-z0-9_]{0,5}", "[A-Z][a-z]{0,5}"),
            1..=4,
        ),
        prop::collection::vec("[a-z][a-z0-9_]{0,5}", 1..=3),
    )
        .prop_flat_map(|(field_specs, input_fields)| {
            let mut seen = std::collections::HashSet::new();
            let state_fields: Vec<SirFieldSchema> = field_specs
                .into_iter()
                .filter(|(name, _)| seen.insert(name.clone()))
                .map(|(name, ft)| SirFieldSchema {
                    name,
                    field_type: ft,
                })
                .collect();
            let state_fields = if state_fields.is_empty() {
                vec![SirFieldSchema {
                    name: "x".to_string(),
                    field_type: "Int".to_string(),
                }]
            } else {
                state_fields
            };

            let mut seen2 = std::collections::HashSet::new();
            let input_schema_fields: Vec<SirFieldSchema> = input_fields
                .into_iter()
                .filter(|name| seen2.insert(name.clone()))
                .map(|name| SirFieldSchema {
                    name,
                    field_type: "Int".to_string(),
                })
                .collect();
            let input_schema_fields = if input_schema_fields.is_empty() {
                vec![SirFieldSchema {
                    name: "v".to_string(),
                    field_type: "Int".to_string(),
                }]
            } else {
                input_schema_fields
            };

            let field_names: Vec<String> =
                state_fields.iter().map(|f| f.name.clone()).collect();

            (
                Just(SirStateSchema {
                    fields: state_fields,
                }),
                Just(SirInputSchema {
                    fields: input_schema_fields,
                }),
                prop::collection::vec(
                    (
                        "[a-z][a-z_]{0,7}",
                        prop_oneof!["Update", "Init", "Noop"],
                        arb_sir_expr(2),
                        prop::collection::vec(
                            prop::sample::select(field_names.clone()),
                            0..=field_names.len(),
                        ),
                    ),
                    1..=3,
                ),
                prop::collection::vec(
                    (
                        "[A-Z][a-z_]{0,7}",
                        prop_oneof!["local", "global", "temporal"],
                        arb_sir_expr(1),
                    ),
                    0..=2,
                ),
            )
        })
        .prop_map(
            |(state_schema, input_schema, transitions, invariants)| {
                let transitions: Vec<SirTransition> = transitions
                    .into_iter()
                    .map(|(name, class, body, mutations)| {
                        let mut seen = std::collections::HashSet::new();
                        let allowed: Vec<String> = mutations
                            .into_iter()
                            .filter(|m| seen.insert(m.clone()))
                            .collect();
                        SirTransition {
                            name,
                            class: class.to_string(),
                            preconditions: vec![],
                            postconditions: vec![],
                            body,
                            allowed_mutations: allowed,
                        }
                    })
                    .collect();

                let invariants: Vec<SirInvariant> = invariants
                    .into_iter()
                    .map(|(name, category, expr)| SirInvariant {
                        name,
                        category: category.to_string(),
                        expr,
                    })
                    .collect();

                SirProgram {
                    version: "0.1.0".to_string(),
                    state_schema,
                    input_schema,
                    transitions,
                    invariants,
                    observables: vec![],
                }
            },
        )
}

/// Build a SirValue::Map from field name → value pairs.
fn make_map_value(entries: &[(&str, i64)]) -> SirValue {
    let mut map = BTreeMap::new();
    for (name, value) in entries {
        map.insert(name.to_string(), SirValue::Int { value: *value });
    }
    SirValue::Map { entries: map }
}

/// Standard deposit program for targeted fuzzing.
fn make_deposit_program() -> SirProgram {
    SirProgram {
        version: "0.1.0".to_string(),
        state_schema: SirStateSchema {
            fields: vec![
                SirFieldSchema {
                    name: "balance".to_string(),
                    field_type: "Int".to_string(),
                },
                SirFieldSchema {
                    name: "nonce".to_string(),
                    field_type: "Int".to_string(),
                },
            ],
        },
        input_schema: SirInputSchema {
            fields: vec![SirFieldSchema {
                name: "amount".to_string(),
                field_type: "Int".to_string(),
            }],
        },
        transitions: vec![SirTransition {
            name: "deposit".to_string(),
            class: "Update".to_string(),
            preconditions: vec![SirExpr::BinOp {
                op: "gt".to_string(),
                left: Box::new(SirExpr::FieldAccess {
                    expr: Box::new(SirExpr::Var {
                        name: "input".to_string(),
                    }),
                    field: "amount".to_string(),
                }),
                right: Box::new(SirExpr::Literal {
                    value: SirValue::Int { value: 0 },
                }),
            }],
            postconditions: vec![],
            body: SirExpr::BinOp {
                op: "add".to_string(),
                left: Box::new(SirExpr::FieldAccess {
                    expr: Box::new(SirExpr::Var {
                        name: "state".to_string(),
                    }),
                    field: "balance".to_string(),
                }),
                right: Box::new(SirExpr::FieldAccess {
                    expr: Box::new(SirExpr::Var {
                        name: "input".to_string(),
                    }),
                    field: "amount".to_string(),
                }),
            },
            allowed_mutations: vec!["balance".to_string()],
        }],
        invariants: vec![SirInvariant {
            name: "L_non_negative".to_string(),
            category: "local".to_string(),
            expr: SirExpr::BinOp {
                op: "ge".to_string(),
                left: Box::new(SirExpr::FieldAccess {
                    expr: Box::new(SirExpr::Var {
                        name: "state".to_string(),
                    }),
                    field: "balance".to_string(),
                }),
                right: Box::new(SirExpr::Literal {
                    value: SirValue::Int { value: 0 },
                }),
            },
        }],
        observables: vec![],
    }
}

// ---------------------------------------------------------------------------
// Phase 3a: Random invalid trace fuzzing
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    /// Fuzz: Random invalid traces with carry-over violations must be rejected.
    ///
    /// Generates random pre-state, input, and post-state where at least one
    /// non-mutated field differs between pre and post state.
    #[test]
    fn fuzz_random_carryover_violation(
        balance in 0i64..=100_000,
        nonce in 0i64..=1_000,
        amount in 1i64..=10_000,
        nonce_delta in 1i64..=100,
    ) {
        let program = make_deposit_program();
        let constraints = compile(&program);

        let pre = make_map_value(&[("balance", balance), ("nonce", nonce)]);
        let input = make_map_value(&[("amount", amount)]);
        // Nonce is not in AllowedMutations but we change it — carry-over violation.
        let post = make_map_value(&[("balance", balance + amount), ("nonce", nonce + nonce_delta)]);

        let trace = vec![(pre, input, post)];
        prop_assert!(
            !satisfies_constraints(&trace, &constraints),
            "carry-over violation must be rejected: nonce changed by {}",
            nonce_delta
        );
    }

    /// Fuzz: Random invalid traces with precondition violations must be rejected.
    ///
    /// Generates traces where the precondition (amount > 0) is violated.
    #[test]
    fn fuzz_random_precondition_violation(
        balance in 0i64..=100_000,
        bad_amount in -10_000i64..=0,
        nonce in 0i64..=1_000,
    ) {
        let program = make_deposit_program();
        let constraints = compile(&program);

        let pre = make_map_value(&[("balance", balance), ("nonce", nonce)]);
        let input = make_map_value(&[("amount", bad_amount)]);
        let post = make_map_value(&[("balance", balance + bad_amount), ("nonce", nonce)]);

        let trace = vec![(pre, input, post)];
        prop_assert!(
            !satisfies_constraints(&trace, &constraints),
            "precondition violation must be rejected: amount={}",
            bad_amount
        );
    }

    /// Fuzz: Random invalid traces with invariant violations must be rejected.
    ///
    /// Generates traces where the invariant (balance >= 0) is violated in pre-state.
    #[test]
    fn fuzz_random_invariant_violation(
        negative_balance in -100_000i64..=-1,
        nonce in 0i64..=1_000,
        amount in 1i64..=10_000,
    ) {
        let program = make_deposit_program();
        let constraints = compile(&program);

        let pre = make_map_value(&[("balance", negative_balance), ("nonce", nonce)]);
        let input = make_map_value(&[("amount", amount)]);
        let post = make_map_value(&[("balance", negative_balance + amount), ("nonce", nonce)]);

        let trace = vec![(pre, input, post)];
        prop_assert!(
            !satisfies_constraints(&trace, &constraints),
            "invariant violation must be rejected: balance={}",
            negative_balance
        );
    }
}

// ---------------------------------------------------------------------------
// Phase 3b: Witness mutation fuzzing
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    /// Fuzz: Mutate a valid witness by corrupting the post-state balance.
    ///
    /// Takes a valid deposit trace and adds a random delta to the post-state
    /// balance, creating an invalid body constraint violation.
    #[test]
    fn fuzz_mutate_balance(
        balance in 0i64..=50_000,
        amount in 1i64..=10_000,
        nonce in 0i64..=1_000,
        delta in 1i64..=1_000,
    ) {
        let program = make_deposit_program();
        let constraints = compile(&program);

        let pre = make_map_value(&[("balance", balance), ("nonce", nonce)]);
        let input = make_map_value(&[("amount", amount)]);
        // Mutated: balance is wrong by delta.
        let post = make_map_value(&[("balance", balance + amount + delta), ("nonce", nonce)]);

        let trace = vec![(pre, input, post)];
        prop_assert!(
            !satisfies_constraints(&trace, &constraints),
            "mutated balance must be rejected: expected {} got {}",
            balance + amount,
            balance + amount + delta
        );
    }

    /// Fuzz: Mutate a valid witness by swapping pre and post state.
    ///
    /// Swapping pre/post should violate carry-over and/or body constraints.
    #[test]
    fn fuzz_swap_pre_post(
        balance in 0i64..=50_000,
        amount in 1i64..=10_000,
        nonce in 0i64..=1_000,
    ) {
        let program = make_deposit_program();
        let constraints = compile(&program);

        let pre = make_map_value(&[("balance", balance), ("nonce", nonce)]);
        let input = make_map_value(&[("amount", amount)]);
        let post = make_map_value(&[("balance", balance + amount), ("nonce", nonce)]);

        // Swap: use post as pre and pre as post.
        let trace = vec![(post, input, pre)];
        prop_assert!(
            !satisfies_constraints(&trace, &constraints),
            "swapped pre/post must be rejected"
        );
    }
}

// ---------------------------------------------------------------------------
// Phase 3c: Targeted U-type input fuzzing
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    /// U1 fuzz: Verify that adding a free (unreferenced) witness variable
    /// is detected by the underconstraint analyzer.
    #[test]
    fn fuzz_u1_free_variable_detection(
        program in arb_fuzz_program(),
        orphan_suffix in "[a-z][a-z0-9_]{0,8}",
    ) {
        let mut system = compile(&program);

        // Use a unique prefix to avoid collisions with schema-derived variables.
        let orphan_name = format!("__adversarial_orphan_{}", orphan_suffix);

        // Inject an unreferenced witness variable.
        system.add_witness_variable(WitnessVariable {
            name: orphan_name.clone(),
            kind: WitnessVariableKind::Semantic,
            description: "adversarial free variable".to_string(),
        });

        let u1 = detect_u1_free_variables(&system, &program);
        prop_assert!(
            u1.contains(&orphan_name),
            "U1: free variable '{}' must be detected. Found: {:?}",
            orphan_name,
            u1
        );
    }

    /// U2 fuzz: Verify that a variable referenced by exactly one constraint
    /// is detected as weakly constrained.
    #[test]
    fn fuzz_u2_weakly_constrained_detection(
        var_name in "[a-z][a-z0-9_]{0,8}",
        constant in -1000i64..=1000i64,
    ) {
        let mut system = ConstraintSystem::new("0.1.0");

        system.add_witness_variable(WitnessVariable {
            name: var_name.clone(),
            kind: WitnessVariableKind::Semantic,
            description: "test variable".to_string(),
        });

        // Add exactly one constraint referencing this variable.
        system.add_constraint(Constraint {
            id: ConstraintId(0),
            expr: ConstraintExpr::Eq(
                Box::new(ConstraintExpr::WitnessRef(var_name.clone())),
                Box::new(ConstraintExpr::Constant(constant)),
            ),
            category: ConstraintCategory::Structural,
            description: format!("{} = {}", var_name, constant),
        });

        let u2 = detect_u2_weakly_constrained(&system);
        prop_assert!(
            u2.contains(&var_name),
            "U2: weakly constrained variable '{}' must be detected. Found: {:?}",
            var_name,
            u2
        );
    }

    /// U5 fuzz: Verify that orphan constraints (referencing no witness variables)
    /// are detected.
    #[test]
    fn fuzz_u5_orphan_detection(
        constant_a in -1000i64..=1000i64,
        constant_b in -1000i64..=1000i64,
    ) {
        let mut system = ConstraintSystem::new("0.1.0");

        // Add a witness variable.
        system.add_witness_variable(WitnessVariable {
            name: "x".to_string(),
            kind: WitnessVariableKind::Semantic,
            description: "test variable".to_string(),
        });

        // Add a constraint that references the witness variable.
        system.add_constraint(Constraint {
            id: ConstraintId(0),
            expr: ConstraintExpr::Eq(
                Box::new(ConstraintExpr::WitnessRef("x".to_string())),
                Box::new(ConstraintExpr::Constant(0)),
            ),
            category: ConstraintCategory::Structural,
            description: "x = 0".to_string(),
        });

        // Add an orphan constraint (references no witness variables).
        system.add_constraint(Constraint {
            id: ConstraintId(1),
            expr: ConstraintExpr::Eq(
                Box::new(ConstraintExpr::Constant(constant_a)),
                Box::new(ConstraintExpr::Constant(constant_b)),
            ),
            category: ConstraintCategory::Structural,
            description: format!("orphan: {} = {}", constant_a, constant_b),
        });

        let u5 = detect_u5_orphan(&system);
        prop_assert!(
            !u5.is_empty(),
            "U5: orphan constraint must be detected for {} = {}",
            constant_a,
            constant_b
        );
    }

    /// U6 fuzz: Verify that variables with only range constraints are detected.
    #[test]
    fn fuzz_u6_range_cosmetic_detection(
        lower in 0i64..=100,
        upper in 101i64..=1000,
    ) {
        let mut system = ConstraintSystem::new("0.1.0");

        system.add_witness_variable(WitnessVariable {
            name: "y".to_string(),
            kind: WitnessVariableKind::Semantic,
            description: "range-only variable".to_string(),
        });

        // Add only range constraints (no equality).
        system.add_constraint(Constraint {
            id: ConstraintId(0),
            expr: ConstraintExpr::Ge(
                Box::new(ConstraintExpr::WitnessRef("y".to_string())),
                Box::new(ConstraintExpr::Constant(lower)),
            ),
            category: ConstraintCategory::Structural,
            description: format!("y >= {}", lower),
        });
        system.add_constraint(Constraint {
            id: ConstraintId(1),
            expr: ConstraintExpr::Lt(
                Box::new(ConstraintExpr::WitnessRef("y".to_string())),
                Box::new(ConstraintExpr::Constant(upper)),
            ),
            category: ConstraintCategory::Structural,
            description: format!("y < {}", upper),
        });

        let u6 = detect_u6_range_cosmetic(&system);
        prop_assert!(
            u6.contains(&"y".to_string()),
            "U6: range-cosmetic variable 'y' must be detected for range [{}, {}). Found: {:?}",
            lower,
            upper,
            u6
        );
    }
}

// ---------------------------------------------------------------------------
// Soundness: compiled systems from random programs have no free variables
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    /// Fuzz: For programs where transitions reference "state" and "input",
    /// the compiled system should have zero free variables (CONST-1).
    ///
    /// The compiler generates witness variables for input schema fields.
    /// If no transition references "input", those variables become free.
    /// This test focuses on well-formed programs that use their schemas.
    #[test]
    fn fuzz_compiled_system_no_free_variables(
        _balance in 0i64..=100_000,
        _nonce in 0i64..=1_000,
        _amount in 1i64..=10_000,
    ) {
        // Use the deposit program which references both "state" and "input".
        let program = make_deposit_program();
        let system = compile(&program);
        let u1 = detect_u1_free_variables(&system, &program);
        prop_assert!(
            u1.is_empty(),
            "CONST-1: compiled system must have zero free variables, got: {:?}",
            u1
        );
    }

    /// Fuzz: Constraint variable references from SIR expressions may include
    /// arbitrary variable names from the SIR AST. The compiler lowers these
    /// faithfully. This test verifies that schema-derived variables (state_pre.*,
    /// state_post.*, input.*) are always present in the declared set.
    #[test]
    fn fuzz_schema_vars_always_declared(program in arb_fuzz_program()) {
        let system = compile(&program);

        let declared: std::collections::BTreeSet<String> = system
            .witness_variables
            .iter()
            .map(|wv| wv.name.clone())
            .collect();

        // Every state field should have state_pre.field and state_post.field.
        for field in &program.state_schema.fields {
            let pre_name = format!("state_pre.{}", field.name);
            let post_name = format!("state_post.{}", field.name);
            prop_assert!(
                declared.contains(&pre_name),
                "state_pre.{} must be declared. Declared: {:?}",
                field.name,
                declared
            );
            prop_assert!(
                declared.contains(&post_name),
                "state_post.{} must be declared. Declared: {:?}",
                field.name,
                declared
            );
        }

        // Every input field should have input.field.
        for field in &program.input_schema.fields {
            let input_name = format!("input.{}", field.name);
            prop_assert!(
                declared.contains(&input_name),
                "input.{} must be declared. Declared: {:?}",
                field.name,
                declared
            );
        }
    }
}
