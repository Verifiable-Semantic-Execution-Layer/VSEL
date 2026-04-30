//! Criterion benchmarks for the VSEL proof system.
//!
//! Benchmarks proof generation, verification, and recursive composition
//! using the Plonky3 STARK backend over the Goldilocks field.
//!
//! **Validates: Requirements 7.1(a), 7.1(b), 7.1(c)**
//!
//! Run with: `cargo bench --bench proof_benchmarks -p vsel-proof`
//!
//! Note: These benchmarks use the DefaultProver (hash-based backend).
//! For real Plonky3 STARK benchmarks, enable the `plonky3-backend` feature.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Benchmark helpers — construct test data for proof benchmarks
// ---------------------------------------------------------------------------

/// Create a minimal valid state for benchmarking.
fn bench_state() -> vsel_core::state::State {
    use vsel_core::state::*;
    use vsel_core::types::*;

    let zero_hash = Hash([0u8; 32]);
    State {
        canonical: CanonicalState {
            accounts: BTreeMap::new(),
            storage: BTreeMap::new(),
            system_data: SystemData {
                protocol_version: ProtocolVersion {
                    major: 1,
                    minor: 0,
                    patch: 0,
                },
                total_supply: 1_000_000,
                parameters: BTreeMap::new(),
            },
        },
        derived: DerivedState {
            state_root: zero_hash.clone(),
            auxiliary_roots: BTreeMap::new(),
            aggregates: BTreeMap::new(),
        },
        environment: Environment {
            timestamp: 1000,
            block_height: 1,
            execution_domain: DomainTag(zero_hash.clone()),
        },
        economic: EconomicContext {
            price_oracle: BTreeMap::new(),
            exposure_limits: BTreeMap::new(),
            liquidity_thresholds: BTreeMap::new(),
            fee_schedule: FeeSchedule {
                base_fee: 100,
                fee_rate_bps: 10,
                overrides: BTreeMap::new(),
            },
            epoch_accounting: EpochAccounting {
                epoch: 1,
                total_fees_collected: 0,
                total_transactions: 0,
            },
            collateral_requirements: BTreeMap::new(),
            economic_parameters: EconomicParameters {
                max_leverage_bps: 50_000,
                min_collateral_ratio_bps: 15_000,
                dust_threshold: 1,
                extra: BTreeMap::new(),
            },
        },
        metadata: TraceMetadata {
            sequence_index: 0,
            previous_commitment: zero_hash,
            epoch: 1,
            timestamp: 1000,
        },
    }
}

/// Create a minimal valid input for benchmarking.
fn bench_input() -> vsel_core::input::Input {
    use vsel_core::input::*;
    use vsel_core::types::*;

    let zero_hash = Hash([0u8; 32]);
    Input {
        payload: Payload {
            payload_type: "transfer".to_string(),
            data: vec![1, 2, 3, 4],
        },
        auth: Authorization {
            classical_sig: vec![1; 64],
            pqc_sig: vec![2; 128],
            public_key: HybridPublicKey {
                classical: vec![3; 32],
                pqc: vec![4; 64],
            },
            nonce: 1,
            domain: DomainTag(zero_hash),
        },
        aux: AuxiliaryData {
            data: vec![0xAA, 0xBB],
        },
    }
}

/// Create a minimal observable for benchmarking.
fn bench_observable() -> vsel_core::observable::Observable {
    vsel_core::observable::Observable {
        transition_class: vsel_core::transition::TransitionClass::Update,
        outputs: vec![],
        gas_used: 100,
        status: vsel_core::observable::TransitionStatus::Success,
    }
}

/// Build a trace with `n` entries for benchmarking.
fn bench_trace(n: usize) -> vsel_trace::engine::Trace {
    use sha3::{Digest, Sha3_256};
    use vsel_core::types::Hash;
    use vsel_trace::engine::{Trace, TraceEntry};

    let initial_state = bench_state();
    let mut entries = Vec::with_capacity(n);
    let mut prev_chain = Hash([0u8; 32]);

    for i in 0..n {
        let mut pre_hash = [0u8; 32];
        pre_hash[0] = i as u8;
        pre_hash[1] = (i >> 8) as u8;
        let mut post_hash = [0u8; 32];
        post_hash[0] = (i + 1) as u8;
        post_hash[1] = ((i + 1) >> 8) as u8;

        let mut chain_data = Vec::new();
        chain_data.extend_from_slice(&prev_chain.0);
        chain_data.extend_from_slice(&pre_hash);
        chain_data.extend_from_slice(&post_hash);
        chain_data.extend_from_slice(&(i as u64).to_le_bytes());
        let chain_hash = {
            let mut hasher = Sha3_256::new();
            hasher.update(&chain_data);
            let result = hasher.finalize();
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&result);
            Hash(bytes)
        };

        entries.push(TraceEntry {
            index: i as u64,
            pre_state_commitment: Hash(pre_hash),
            input: bench_input(),
            post_state_commitment: Hash(post_hash),
            observable: bench_observable(),
            environment: initial_state.environment.clone(),
            chain_hash: chain_hash.clone(),
        });

        prev_chain = chain_hash;
    }

    let final_commitment = entries
        .last()
        .map(|e| e.chain_hash.clone())
        .unwrap_or(Hash([0u8; 32]));

    Trace {
        entries,
        initial_state,
        commitment: final_commitment,
    }
}

/// Build a minimal constraint system for benchmarking.
fn bench_constraint_system() -> vsel_constraints::ConstraintSystem {
    use vsel_constraints::*;

    let mut cs = ConstraintSystem::new("1.0.0");
    cs.add_constraint(Constraint {
        id: ConstraintId(0),
        expr: ConstraintExpr::BoolConstant(true),
        category: ConstraintCategory::Structural,
        description: "bench constraint".to_string(),
    });
    cs
}

// ---------------------------------------------------------------------------
// Benchmark group: Proof generation time
// Requirements 7.1(a)
// ---------------------------------------------------------------------------

fn bench_proof_generation(c: &mut Criterion) {
    use vsel_proof::prover::{DefaultProver, Prover};

    let prover = DefaultProver::new("1.0.0-bench");
    let cs = bench_constraint_system();

    let mut group = c.benchmark_group("proof_generation");

    for trace_size in [1, 10, 100] {
        let trace = bench_trace(trace_size);
        group.bench_with_input(
            BenchmarkId::new("trace_entries", trace_size),
            &trace_size,
            |b, _| {
                b.iter(|| {
                    let _ = black_box(prover.prove(&trace, &cs));
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark group: Proof verification time
// Requirements 7.1(b)
// ---------------------------------------------------------------------------

fn bench_proof_verification(c: &mut Criterion) {
    use vsel_core::types::*;
    use vsel_proof::prover::{DefaultProver, Prover};
    use vsel_proof::verifier::{DefaultVerifier, Verifier};

    let prover = DefaultProver::new("1.0.0-bench");
    let cs = bench_constraint_system();
    let trace = bench_trace(10);
    let proof = prover.prove(&trace, &cs).expect("proof generation must succeed");

    let verifier = DefaultVerifier::new(
        ProtocolVersion { major: 1, minor: 0, patch: 0 },
    );

    c.bench_function("proof_verification", |b| {
        b.iter(|| {
            let _ = black_box(verifier.verify(
                black_box(&proof),
                black_box(&proof.public_inputs),
            ));
        });
    });
}

// ---------------------------------------------------------------------------
// Benchmark group: Recursive proof composition time
// Requirements 7.1(c)
// ---------------------------------------------------------------------------

fn bench_recursive_composition(c: &mut Criterion) {
    use vsel_proof::prover::{DefaultProver, Prover};
    use vsel_proof::recursive::compose;

    let prover = DefaultProver::new("1.0.0-bench");
    let cs = bench_constraint_system();

    let mut group = c.benchmark_group("recursive_composition");

    for num_proofs in [2, 5, 10] {
        // Build a chain of proofs with valid state chaining.
        let mut proofs = Vec::with_capacity(num_proofs);
        for _i in 0..num_proofs {
            let trace = bench_trace(2);
            let proof = prover.prove(&trace, &cs).expect("proof must succeed");
            proofs.push(proof);
        }

        // Fix up state chaining: proof[i].root_final = proof[i+1].root_init
        for i in 0..proofs.len().saturating_sub(1) {
            proofs[i].public_inputs.root_final =
                proofs[i + 1].public_inputs.root_init.clone();
        }

        // Ensure domain and version consistency.
        let domain = proofs[0].public_inputs.domain.clone();
        let version = proofs[0].public_inputs.version.clone();
        for proof in &mut proofs {
            proof.public_inputs.domain = domain.clone();
            proof.public_inputs.version = version.clone();
        }

        group.bench_with_input(
            BenchmarkId::new("num_proofs", num_proofs),
            &num_proofs,
            |b, _| {
                b.iter(|| {
                    let _ = black_box(compose(black_box(&proofs)));
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
    use vsel_proof::witness::construct_witness;

    let mut group = c.benchmark_group("witness_construction");

    for trace_size in [1, 10, 100] {
        let trace = bench_trace(trace_size);
        group.bench_with_input(
            BenchmarkId::new("trace_entries", trace_size),
            &trace_size,
            |b, _| {
                b.iter(|| {
                    let _ = black_box(construct_witness(black_box(&trace)));
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
    bench_proof_generation,
    bench_proof_verification,
    bench_recursive_composition,
    bench_witness_construction,
);
criterion_main!(benches);
