//! Property-based tests for the SIR/IR Pipeline (vsel-sir).
//!
//! Uses `proptest` to verify correctness properties derived from
//! REFINEMENT_STRATEGY.md, TECH_SPEC.md, design.md Component 10.
//!
//! **Property 43: SIR/IR Pipeline Consistency** — export tooling produces
//! deterministic IR, Rust deserialization is faithful.
//! **Validates: Requirements 9.7**

use proptest::collection::{btree_map, vec as arb_vec};
use proptest::prelude::*;

use vsel_sir::deserialize::*;
use vsel_sir::types::*;

// ---------------------------------------------------------------------------
// Arbitrary strategies for SIR types
// ---------------------------------------------------------------------------

/// Generate an arbitrary SirValue (bounded depth to avoid infinite recursion).
fn arb_sir_value(depth: u32) -> BoxedStrategy<SirValue> {
    if depth == 0 {
        // Leaf values only at max depth
        prop_oneof![
            any::<i64>().prop_map(|v| SirValue::Int { value: v }),
            any::<bool>().prop_map(|v| SirValue::Bool { value: v }),
            arb_vec(any::<u8>(), 0..16).prop_map(|v| SirValue::Bytes { value: v }),
            Just(SirValue::Unit),
        ]
        .boxed()
    } else {
        prop_oneof![
            // Leaf variants
            any::<i64>().prop_map(|v| SirValue::Int { value: v }),
            any::<bool>().prop_map(|v| SirValue::Bool { value: v }),
            arb_vec(any::<u8>(), 0..16).prop_map(|v| SirValue::Bytes { value: v }),
            Just(SirValue::Unit),
            // Recursive variants
            arb_vec(arb_sir_value(depth - 1), 0..4)
                .prop_map(|elements| SirValue::List { elements }),
            btree_map("[a-z]{1,8}", arb_sir_value(depth - 1), 0..4)
                .prop_map(|entries| SirValue::Map { entries }),
            arb_vec(arb_sir_value(depth - 1), 0..4)
                .prop_map(|elements| SirValue::Tuple { elements }),
        ]
        .boxed()
    }
}

/// Generate an arbitrary SirExpr (bounded depth).
fn arb_sir_expr(depth: u32) -> BoxedStrategy<SirExpr> {
    if depth == 0 {
        // Leaf expressions only
        prop_oneof![
            arb_sir_value(0).prop_map(|value| SirExpr::Literal { value }),
            "[a-z_]{1,12}".prop_map(|name| SirExpr::Var { name }),
        ]
        .boxed()
    } else {
        prop_oneof![
            // Leaf variants
            arb_sir_value(1).prop_map(|value| SirExpr::Literal { value }),
            "[a-z_]{1,12}".prop_map(|name| SirExpr::Var { name }),
            // Recursive variants
            (
                arb_sir_expr(depth - 1),
                arb_vec(arb_sir_expr(depth - 1), 0..3)
            )
                .prop_map(|(func, args)| SirExpr::Apply {
                    func: Box::new(func),
                    args,
                }),
            (
                "[a-z_]{1,12}",
                arb_sir_expr(depth - 1),
                arb_sir_expr(depth - 1),
            )
                .prop_map(|(name, value, body)| SirExpr::Let {
                    name,
                    value: Box::new(value),
                    body: Box::new(body),
                }),
            (
                arb_sir_expr(depth - 1),
                arb_sir_expr(depth - 1),
                arb_sir_expr(depth - 1),
            )
                .prop_map(|(cond, then_, else_)| SirExpr::If {
                    cond: Box::new(cond),
                    then_: Box::new(then_),
                    else_: Box::new(else_),
                }),
            (arb_sir_expr(depth - 1), "[a-z_]{1,12}").prop_map(|(expr, field)| {
                SirExpr::FieldAccess {
                    expr: Box::new(expr),
                    field,
                }
            }),
            (
                prop_oneof!["add", "sub", "mul", "eq", "gt", "ge", "lt", "le"],
                arb_sir_expr(depth - 1),
                arb_sir_expr(depth - 1),
            )
                .prop_map(|(op, left, right)| SirExpr::BinOp {
                    op: op.to_string(),
                    left: Box::new(left),
                    right: Box::new(right),
                }),
            (
                arb_sir_expr(depth - 1),
                arb_vec(arb_sir_match_arm(depth - 1), 1..3),
            )
                .prop_map(|(scrutinee, arms)| SirExpr::Match {
                    scrutinee: Box::new(scrutinee),
                    arms,
                }),
        ]
        .boxed()
    }
}

/// Generate an arbitrary SirMatchArm.
fn arb_sir_match_arm(depth: u32) -> BoxedStrategy<SirMatchArm> {
    (arb_sir_pattern(), arb_sir_expr(depth))
        .prop_map(|(pattern, body)| SirMatchArm { pattern, body })
        .boxed()
}

/// Generate an arbitrary SirPattern.
fn arb_sir_pattern() -> BoxedStrategy<SirPattern> {
    prop_oneof![
        arb_sir_value(0).prop_map(|value| SirPattern::Literal { value }),
        "[a-z_]{1,12}".prop_map(|name| SirPattern::Var { name }),
    ]
    .boxed()
}

/// Generate an arbitrary SirFieldSchema.
fn arb_sir_field_schema() -> impl Strategy<Value = SirFieldSchema> {
    (
        "[a-z_]{1,12}",
        prop_oneof!["Int", "Bool", "Bytes", "Map", "List"],
    )
        .prop_map(|(name, field_type)| SirFieldSchema {
            name,
            field_type: field_type.to_string(),
        })
}

/// Generate an arbitrary SirTransition.
fn arb_sir_transition() -> impl Strategy<Value = SirTransition> {
    (
        "[a-z_]{1,12}",
        prop_oneof!["Init", "Update", "Noop", "Error"],
        arb_vec(arb_sir_expr(1), 0..3),
        arb_vec(arb_sir_expr(1), 0..3),
        arb_sir_expr(1),
        arb_vec("[a-z_]{1,12}".prop_map(|s| s.to_string()), 0..4),
    )
        .prop_map(
            |(name, class, preconditions, postconditions, body, allowed_mutations)| SirTransition {
                name: name.to_string(),
                class: class.to_string(),
                preconditions,
                postconditions,
                body,
                allowed_mutations,
            },
        )
}

/// Generate an arbitrary SirInvariant.
fn arb_sir_invariant() -> impl Strategy<Value = SirInvariant> {
    (
        "[a-z_]{1,12}",
        prop_oneof!["local", "global", "temporal", "economic"],
        arb_sir_expr(1),
    )
        .prop_map(|(name, category, expr)| SirInvariant {
            name: name.to_string(),
            category: category.to_string(),
            expr,
        })
}

/// Generate an arbitrary SirObservable.
fn arb_sir_observable() -> impl Strategy<Value = SirObservable> {
    ("[a-z_]{1,12}", arb_sir_expr(1)).prop_map(|(name, expr)| SirObservable {
        name: name.to_string(),
        expr,
    })
}

/// Generate an arbitrary valid SirProgram.
fn arb_sir_program() -> impl Strategy<Value = SirProgram> {
    (
        prop_oneof!["0.1.0", "0.2.0", "1.0.0"],
        arb_vec(arb_sir_field_schema(), 1..5),
        arb_vec(arb_sir_field_schema(), 1..5),
        arb_vec(arb_sir_transition(), 1..4),
        arb_vec(arb_sir_invariant(), 1..4),
        arb_vec(arb_sir_observable(), 0..3),
    )
        .prop_map(
            |(version, state_fields, input_fields, transitions, invariants, observables)| {
                SirProgram {
                    version: version.to_string(),
                    state_schema: SirStateSchema {
                        fields: state_fields,
                    },
                    input_schema: SirInputSchema {
                        fields: input_fields,
                    },
                    transitions,
                    invariants,
                    observables,
                }
            },
        )
}

// ---------------------------------------------------------------------------
// Property 43: SIR/IR Pipeline Consistency
// Export tooling produces deterministic IR, Rust deserialization is faithful.
// **Validates: Requirements 9.7**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    // -----------------------------------------------------------------------
    // 43a: Deserialization determinism
    // Deserializing the same JSON always produces the same Rust types.
    // -----------------------------------------------------------------------

    /// Property 43a: SirValue deserialization is deterministic — the same JSON
    /// always produces the same Rust value.
    #[test]
    fn prop_sir_value_deserialization_deterministic(v in arb_sir_value(2)) {
        let json = serde_json::to_string(&v).unwrap();
        let v1: SirValue = serde_json::from_str(&json).unwrap();
        let v2: SirValue = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(
            &v1, &v2,
            "Deserializing the same JSON must always produce the same SirValue"
        );
    }

    /// Property 43a: SirExpr deserialization is deterministic.
    #[test]
    fn prop_sir_expr_deserialization_deterministic(e in arb_sir_expr(2)) {
        let json = serde_json::to_string(&e).unwrap();
        let e1: SirExpr = serde_json::from_str(&json).unwrap();
        let e2: SirExpr = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(
            &e1, &e2,
            "Deserializing the same JSON must always produce the same SirExpr"
        );
    }

    /// Property 43a: SirProgram deserialization is deterministic.
    #[test]
    fn prop_sir_program_deserialization_deterministic(p in arb_sir_program()) {
        let json = serde_json::to_string(&p).unwrap();
        let p1 = deserialize_program(&json).unwrap();
        let p2 = deserialize_program(&json).unwrap();
        prop_assert_eq!(
            p1, p2,
            "Deserializing the same JSON must always produce the same SirProgram"
        );
    }

    // -----------------------------------------------------------------------
    // 43b: Round-trip consistency (CONST-4)
    // Deserialize → Serialize → Deserialize produces identical structures.
    // -----------------------------------------------------------------------

    /// Property 43b: SirValue round-trip — serialize → deserialize → serialize
    /// produces identical structures.
    #[test]
    fn prop_sir_value_round_trip(v in arb_sir_value(2)) {
        let json1 = serde_json::to_string(&v).unwrap();
        let deserialized: SirValue = serde_json::from_str(&json1).unwrap();
        let json2 = serde_json::to_string(&deserialized).unwrap();
        let round_tripped: SirValue = serde_json::from_str(&json2).unwrap();
        prop_assert_eq!(
            &v, &deserialized,
            "SirValue must survive serialize → deserialize"
        );
        prop_assert_eq!(
            &deserialized, &round_tripped,
            "SirValue must survive deserialize → serialize → deserialize"
        );
    }

    /// Property 43b: SirExpr round-trip consistency.
    #[test]
    fn prop_sir_expr_round_trip(e in arb_sir_expr(2)) {
        let json1 = serde_json::to_string(&e).unwrap();
        let deserialized: SirExpr = serde_json::from_str(&json1).unwrap();
        let json2 = serde_json::to_string(&deserialized).unwrap();
        let round_tripped: SirExpr = serde_json::from_str(&json2).unwrap();
        prop_assert_eq!(
            &e, &deserialized,
            "SirExpr must survive serialize → deserialize"
        );
        prop_assert_eq!(
            &deserialized, &round_tripped,
            "SirExpr must survive deserialize → serialize → deserialize"
        );
    }

    /// Property 43b: SirProgram round-trip consistency.
    #[test]
    fn prop_sir_program_round_trip(p in arb_sir_program()) {
        let json1 = serde_json::to_string(&p).unwrap();
        let p1 = deserialize_program(&json1).unwrap();
        let json2 = serde_json::to_string(&p1).unwrap();
        let p2 = deserialize_program(&json2).unwrap();
        prop_assert_eq!(
            &p, &p1,
            "SirProgram must survive serialize → deserialize"
        );
        prop_assert_eq!(
            &p1, &p2,
            "SirProgram must survive deserialize → serialize → deserialize (CONST-4)"
        );
    }

    // -----------------------------------------------------------------------
    // 43d: Schema field coverage
    // All SIR types can be round-tripped through JSON serialization.
    // -----------------------------------------------------------------------

    /// Property 43d: SirTransition round-trip — all fields preserved.
    #[test]
    fn prop_sir_transition_round_trip(t in arb_sir_transition()) {
        let json = serde_json::to_string(&t).unwrap();
        let deserialized: SirTransition = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(
            t, deserialized,
            "SirTransition must round-trip through JSON faithfully"
        );
    }

    /// Property 43d: SirInvariant round-trip — all fields preserved.
    #[test]
    fn prop_sir_invariant_round_trip(inv in arb_sir_invariant()) {
        let json = serde_json::to_string(&inv).unwrap();
        let deserialized: SirInvariant = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(
            inv, deserialized,
            "SirInvariant must round-trip through JSON faithfully"
        );
    }

    /// Property 43d: SirPattern round-trip — both Literal and Var variants.
    #[test]
    fn prop_sir_pattern_round_trip(pat in arb_sir_pattern()) {
        let json = serde_json::to_string(&pat).unwrap();
        let deserialized: SirPattern = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(
            pat, deserialized,
            "SirPattern must round-trip through JSON faithfully"
        );
    }

    /// Property 43d: SirMatchArm round-trip.
    #[test]
    fn prop_sir_match_arm_round_trip(arm in arb_sir_match_arm(1)) {
        let json = serde_json::to_string(&arm).unwrap();
        let deserialized: SirMatchArm = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(
            arm, deserialized,
            "SirMatchArm must round-trip through JSON faithfully"
        );
    }

    /// Property 43d: SirFieldSchema round-trip.
    #[test]
    fn prop_sir_field_schema_round_trip(fs in arb_sir_field_schema()) {
        let json = serde_json::to_string(&fs).unwrap();
        let deserialized: SirFieldSchema = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(
            fs, deserialized,
            "SirFieldSchema must round-trip through JSON faithfully"
        );
    }

    /// Property 43d: SirObservable round-trip.
    #[test]
    fn prop_sir_observable_round_trip(obs in arb_sir_observable()) {
        let json = serde_json::to_string(&obs).unwrap();
        let deserialized: SirObservable = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(
            obs, deserialized,
            "SirObservable must round-trip through JSON faithfully"
        );
    }

    /// Property 43b: Byte-level serialization determinism — serializing the same
    /// SirProgram always produces identical JSON bytes.
    #[test]
    fn prop_sir_program_serialization_deterministic(p in arb_sir_program()) {
        let json1 = serde_json::to_string(&p).unwrap();
        let json2 = serde_json::to_string(&p).unwrap();
        prop_assert_eq!(
            json1, json2,
            "Serializing the same SirProgram must always produce identical JSON"
        );
    }
}

// ---------------------------------------------------------------------------
// 43c: Example artifact validity (standard tests)
// All example IR files in sir/examples/ deserialize successfully.
// ---------------------------------------------------------------------------

/// Helper to resolve the path to sir/examples/ relative to the workspace root.
/// CARGO_MANIFEST_DIR points to the crate root (protocol/crates/vsel-sir/),
/// so we go up three levels to reach the workspace root.
fn sir_example_path(filename: &str) -> std::path::PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set");
    std::path::Path::new(&manifest_dir)
        .join("../../..") // up from protocol/crates/vsel-sir/ to workspace root
        .join("sir/examples")
        .join(filename)
}

fn read_sir_example(filename: &str) -> String {
    let path = sir_example_path(filename);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e))
}

#[test]
fn test_example_full_program_deserializes() {
    let json = read_sir_example("full_program.json");
    let program = deserialize_program(&json).expect("full_program.json must deserialize");
    assert_eq!(program.version, "0.1.0");
    assert!(!program.transitions.is_empty(), "must have transitions");
    assert!(!program.invariants.is_empty(), "must have invariants");
    assert!(
        !program.state_schema.fields.is_empty(),
        "must have state fields"
    );
    assert!(
        !program.input_schema.fields.is_empty(),
        "must have input fields"
    );
}

#[test]
fn test_example_update_transition_deserializes() {
    let json = read_sir_example("update_transition.json");
    let transition: SirTransition =
        serde_json::from_str(&json).expect("update_transition.json must deserialize");
    assert_eq!(transition.name, "deposit");
    assert_eq!(transition.class, "Update");
    assert!(
        !transition.preconditions.is_empty(),
        "must have preconditions"
    );
    assert!(
        !transition.postconditions.is_empty(),
        "must have postconditions"
    );
}

#[test]
fn test_example_init_transition_deserializes() {
    let json = read_sir_example("init_transition.json");
    let transition: SirTransition =
        serde_json::from_str(&json).expect("init_transition.json must deserialize");
    assert_eq!(transition.name, "genesis");
    assert_eq!(transition.class, "Init");
    assert!(
        transition.preconditions.is_empty(),
        "init has no preconditions"
    );
    assert!(
        !transition.postconditions.is_empty(),
        "must have postconditions"
    );
}

#[test]
fn test_example_invariants_deserializes() {
    let json = read_sir_example("invariants.json");
    let invariants: Vec<SirInvariant> =
        serde_json::from_str(&json).expect("invariants.json must deserialize");
    assert_eq!(invariants.len(), 4);
    // Verify all categories are present
    let categories: Vec<&str> = invariants.iter().map(|i| i.category.as_str()).collect();
    assert!(categories.contains(&"local"), "must have local invariant");
    assert!(categories.contains(&"global"), "must have global invariant");
    assert!(
        categories.contains(&"economic"),
        "must have economic invariant"
    );
}

#[test]
fn test_example_full_program_round_trip() {
    // CONST-4: deserialize then re-serialize produces identical structures
    let json = read_sir_example("full_program.json");
    let program = deserialize_program(&json).unwrap();
    let reserialized = serde_json::to_string_pretty(&program).unwrap();
    let program2 = deserialize_program(&reserialized).unwrap();
    assert_eq!(
        program, program2,
        "full_program.json must survive round-trip (CONST-4)"
    );
}

#[test]
fn test_all_example_artifacts_consistent() {
    // Verify that the full program's transitions and invariants are consistent
    // with the individual example files
    let full_json = read_sir_example("full_program.json");
    let program = deserialize_program(&full_json).unwrap();

    let update_json = read_sir_example("update_transition.json");
    let update: SirTransition = serde_json::from_str(&update_json).unwrap();

    let init_json = read_sir_example("init_transition.json");
    let init: SirTransition = serde_json::from_str(&init_json).unwrap();

    // The full program must contain transitions matching the individual examples
    let program_transition_names: Vec<&str> = program
        .transitions
        .iter()
        .map(|t| t.name.as_str())
        .collect();
    assert!(
        program_transition_names.contains(&update.name.as_str()),
        "full program must contain the update transition '{}'",
        update.name
    );
    assert!(
        program_transition_names.contains(&init.name.as_str()),
        "full program must contain the init transition '{}'",
        init.name
    );
}
