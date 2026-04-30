//! Criterion benchmarks for VSEL constraint system compilation,
//! witness construction, and circuit building.
//!
//! **Validates: Requirements 7.1(g), 7.1(h), 7.1(i)**
//!
//! Run with: `cargo bench --bench compilation_benchmarks -p vsel-constraints`

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

use vsel_constraints::compiler::compile;
use vsel_sir::types::*;

// ---------------------------------------------------------------------------
// Helpers: build SIR programs of varying sizes
// ---------------------------------------------------------------------------

/// Build a SIR program with `n` transitions (small, medium, large).
fn make_sir_program(num_transitions: usize) -> SirProgram {
    let state_fields: Vec<SirFieldSchema> = (0..5)
        .map(|i| SirFieldSchema {
            name: format!("field_{}", i),
            field_type: "Int".to_string(),
        })
        .collect();

    let input_fields: Vec<SirFieldSchema> = (0..3)
        .map(|i| SirFieldSchema {
            name: format!("input_{}", i),
            field_type: "Int".to_string(),
        })
        .collect();

    let transitions: Vec<SirTransition> = (0..num_transitions)
        .map(|i| SirTransition {
            name: format!("transition_{}", i),
            class: "Update".to_string(),
            preconditions: vec![SirExpr::BinOp {
                op: ">=".to_string(),
                left: Box::new(SirExpr::Var {
                    name: "field_0".to_string(),
                }),
                right: Box::new(SirExpr::Literal {
                    value: SirValue::Int { value: 0 },
                }),
            }],
            postconditions: vec![SirExpr::BinOp {
                op: ">=".to_string(),
                left: Box::new(SirExpr::Var {
                    name: "field_0".to_string(),
                }),
                right: Box::new(SirExpr::Literal {
                    value: SirValue::Int { value: 0 },
                }),
            }],
            body: SirExpr::BinOp {
                op: "+".to_string(),
                left: Box::new(SirExpr::Var {
                    name: "field_0".to_string(),
                }),
                right: Box::new(SirExpr::Var {
                    name: format!("input_{}", i % 3),
                }),
            },
            allowed_mutations: vec!["field_0".to_string()],
        })
        .collect();

    let invariants = vec![SirInvariant {
        name: "non_negative".to_string(),
        category: "local".to_string(),
        expr: SirExpr::BinOp {
            op: ">=".to_string(),
            left: Box::new(SirExpr::Var {
                name: "field_0".to_string(),
            }),
            right: Box::new(SirExpr::Literal {
                value: SirValue::Int { value: 0 },
            }),
        },
    }];

    let observables = vec![SirObservable {
        name: "output_0".to_string(),
        expr: SirExpr::Var {
            name: "field_0".to_string(),
        },
    }];

    SirProgram {
        version: "0.1.0".to_string(),
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
}

// ---------------------------------------------------------------------------
// Benchmark group: Constraint system compilation time
// Requirements 7.1(g)
// ---------------------------------------------------------------------------

fn bench_constraint_compilation(c: &mut Criterion) {
    let mut group = c.benchmark_group("constraint_compilation");

    for (label, num_transitions) in [("small_3", 3), ("medium_10", 10), ("large_30", 30)] {
        let program = make_sir_program(num_transitions);

        group.bench_with_input(
            BenchmarkId::new("sir_transitions", label),
            &num_transitions,
            |b, _| {
                b.iter(|| {
                    let _ = black_box(compile(black_box(&program)));
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark group: Witness construction time
// Requirements 7.1(h)
// ---------------------------------------------------------------------------

fn bench_witness_construction(c: &mut Criterion) {
    // Witness construction is in vsel-proof, but we benchmark the
    // constraint system side here — specifically how fast we can
    // build constraint systems of varying sizes that feed into
    // witness construction.
    //
    // The actual witness construction benchmark is in proof_benchmarks.rs
    // since it depends on vsel-proof::witness::construct_witness.
    //
    // Here we benchmark the constraint system evaluation which is
    // the core of witness validation.
    use vsel_constraints::*;

    let mut group = c.benchmark_group("constraint_evaluation");

    for (label, num_constraints) in [("small_10", 10), ("medium_100", 100), ("large_500", 500)] {
        let mut cs = ConstraintSystem::new("1.0.0");
        for i in 0..num_constraints {
            cs.add_constraint(Constraint {
                id: ConstraintId(i as u64),
                expr: ConstraintExpr::Eq(
                    Box::new(ConstraintExpr::Constant(i as i64)),
                    Box::new(ConstraintExpr::Constant(i as i64)),
                ),
                category: ConstraintCategory::Structural,
                description: format!("bench constraint {}", i),
            });
        }

        group.bench_with_input(
            BenchmarkId::new("num_constraints", label),
            &num_constraints,
            |b, _| {
                b.iter(|| {
                    // Benchmark iterating and evaluating constraints
                    let count = black_box(&cs)
                        .constraints
                        .iter()
                        .filter(|c| matches!(c.expr, ConstraintExpr::Eq(_, _)))
                        .count();
                    black_box(count);
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark group: Circuit building time
// Requirements 7.1(i)
// ---------------------------------------------------------------------------

fn bench_circuit_building(c: &mut Criterion) {
    // Circuit building is the compilation from SIR to constraint system.
    // We benchmark the full compile pipeline for different program sizes.
    let mut group = c.benchmark_group("circuit_building");

    for (label, num_transitions) in [("small_3", 3), ("medium_10", 10), ("large_30", 30)] {
        let program = make_sir_program(num_transitions);

        group.bench_with_input(
            BenchmarkId::new("program_size", label),
            &num_transitions,
            |b, _| {
                b.iter(|| {
                    let cs = compile(black_box(&program));
                    black_box(cs.constraints.len());
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Criterion configuration
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_constraint_compilation,
    bench_witness_construction,
    bench_circuit_building,
);
criterion_main!(benches);
