//! Criterion benchmarks for the VSEL proof system.
//!
//! Benchmarks proof generation, verification, and recursive composition.
//!
//! **Validates: Requirements 5.1, 5.2, 7.1(a), 7.1(b), 7.1(c)**
//!
//! ## Hash Backend (simulation)
//!
//! The default benchmark groups use `DefaultProver` (SHA3-256 hash-based
//! backend). These are fast (~µs) but do NOT measure real STARK proving.
//!
//! Run with: `cargo bench --bench proof_benchmarks -p vsel-proof`
//!
//! ## Plonky3 STARK Backend (real)
//!
//! When the `plonky3-backend` feature is enabled, additional benchmark
//! groups measure real Plonky3 STARK proof generation, verification, and
//! witness construction over the Goldilocks field.
//!
//! Run with: `cargo bench --bench proof_benchmarks -p vsel-proof --features plonky3-backend`

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
// Benchmark group: Hash Backend — Proof generation time (simulation)
// Requirements 7.1(a)
// ---------------------------------------------------------------------------

fn bench_hash_backend_proof_generation(c: &mut Criterion) {
    use vsel_proof::prover::{DefaultProver, Prover};

    let prover = DefaultProver::new("1.0.0-bench");
    let cs = bench_constraint_system();

    let mut group = c.benchmark_group("hash_backend_proof_generation");

    for trace_size in [1, 10, 100] {
        let trace = bench_trace(trace_size);
        group.bench_with_input(
            BenchmarkId::new("Hash Backend (simulation)/trace_entries", trace_size),
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
// Benchmark group: Hash Backend — Proof verification time (simulation)
// Requirements 7.1(b)
// ---------------------------------------------------------------------------

fn bench_hash_backend_proof_verification(c: &mut Criterion) {
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

    c.bench_function("hash_backend_proof_verification", |b| {
        b.iter(|| {
            let _ = black_box(verifier.verify(
                black_box(&proof),
                black_box(&proof.public_inputs),
            ));
        });
    });
}

// ---------------------------------------------------------------------------
// Benchmark group: Hash Backend — Recursive proof composition time (simulation)
// Requirements 7.1(c)
// ---------------------------------------------------------------------------

fn bench_hash_backend_recursive_composition(c: &mut Criterion) {
    use vsel_proof::prover::{DefaultProver, Prover};
    use vsel_proof::recursive::compose;

    let prover = DefaultProver::new("1.0.0-bench");
    let cs = bench_constraint_system();

    let mut group = c.benchmark_group("hash_backend_recursive_composition");

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
// Benchmark group: Hash Backend — Witness construction time (simulation)
// Requirements 7.1(h)
// ---------------------------------------------------------------------------

fn bench_hash_backend_witness_construction(c: &mut Criterion) {
    use vsel_proof::witness::construct_witness;

    let mut group = c.benchmark_group("hash_backend_witness_construction");

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
// Plonky3 STARK Backend — Real benchmark groups
// Requirements 5.1, 5.2
//
// These benchmarks use the real Plonky3Backend (STARK proofs over
// Goldilocks field) and are gated behind the `plonky3-backend` feature.
// ---------------------------------------------------------------------------

/// Compute constraint commitment using domain-separated SHA3-256 hashing.
///
/// This matches the commitment scheme used by the prover pipeline:
/// `SHA3-256(b"vsel-constraint-system-v1" || bincode::serialize(cs))`.
#[cfg(feature = "plonky3-backend")]
fn compute_constraint_commitment(
    cs: &vsel_constraints::ConstraintSystem,
) -> vsel_core::types::Hash {
    use sha3::{Digest, Sha3_256};
    let cs_bytes = bincode::serialize(cs).unwrap();
    let mut hasher = Sha3_256::new();
    hasher.update(b"vsel-constraint-system-v1");
    hasher.update(&cs_bytes);
    let hash = hasher.finalize();
    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(&hash);
    vsel_core::types::Hash(commitment)
}

// ---------------------------------------------------------------------------
// Plonky3 STARK Backend — Proof generation (real)
// Requirements 5.1(a)
// ---------------------------------------------------------------------------

#[cfg(feature = "plonky3-backend")]
fn bench_plonky3_proof_generation(c: &mut Criterion) {
    use vsel_proof::backend::ZkBackend;
    use vsel_proof::plonky3_backend::Plonky3Backend;
    use vsel_proof::public_inputs::PublicInputs;
    use vsel_proof::witness::construct_witness;

    let backend = Plonky3Backend::new();
    let cs = bench_constraint_system();

    let mut group = c.benchmark_group("plonky3_proof_generation");

    for trace_size in [1, 10, 100] {
        let trace = bench_trace(trace_size);
        let witness = construct_witness(&trace);
        let public_inputs = PublicInputs::from_trace(&trace);

        group.bench_with_input(
            BenchmarkId::new("Plonky3 STARK (real)/trace_entries", trace_size),
            &trace_size,
            |b, _| {
                b.iter(|| {
                    let _ = black_box(backend.prove(
                        black_box(&witness),
                        black_box(&cs),
                        black_box(&public_inputs),
                    ));
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Plonky3 STARK Backend — Proof verification (real)
// Requirements 5.1(b)
// ---------------------------------------------------------------------------

#[cfg(feature = "plonky3-backend")]
fn bench_plonky3_proof_verification(c: &mut Criterion) {
    use vsel_proof::backend::ZkBackend;
    use vsel_proof::plonky3_backend::Plonky3Backend;
    use vsel_proof::public_inputs::PublicInputs;
    use vsel_proof::witness::construct_witness;

    let backend = Plonky3Backend::new();
    let cs = bench_constraint_system();
    let trace = bench_trace(10);
    let witness = construct_witness(&trace);
    let public_inputs = PublicInputs::from_trace(&trace);
    let constraint_commitment = compute_constraint_commitment(&cs);

    let proof = backend
        .prove(&witness, &cs, &public_inputs)
        .expect("Plonky3 proof generation must succeed for verification benchmark");

    c.bench_function("plonky3_proof_verification", |b| {
        b.iter(|| {
            let _ = black_box(backend.verify(
                black_box(&proof),
                black_box(&public_inputs),
                black_box(&constraint_commitment),
            ));
        });
    });
}

// ---------------------------------------------------------------------------
// Plonky3 STARK Backend — Witness construction
// Requirements 5.1(c)
//
// Note: Witness construction is backend-agnostic (same `construct_witness`
// function), but we benchmark it in the Plonky3 group to provide a
// complete picture of the real proving pipeline cost breakdown.
// ---------------------------------------------------------------------------

#[cfg(feature = "plonky3-backend")]
fn bench_plonky3_witness_construction(c: &mut Criterion) {
    use vsel_proof::witness::construct_witness;

    let mut group = c.benchmark_group("plonky3_witness_construction");

    for trace_size in [1, 10, 100] {
        let trace = bench_trace(trace_size);
        group.bench_with_input(
            BenchmarkId::new("Plonky3 pipeline/trace_entries", trace_size),
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

// Hash Backend benchmark groups (always available).
criterion_group!(
    hash_backend_benches,
    bench_hash_backend_proof_generation,
    bench_hash_backend_proof_verification,
    bench_hash_backend_recursive_composition,
    bench_hash_backend_witness_construction,
);

// Plonky3 STARK Backend benchmark groups (only with `plonky3-backend` feature).
#[cfg(feature = "plonky3-backend")]
criterion_group!(
    plonky3_benches,
    bench_plonky3_proof_generation,
    bench_plonky3_proof_verification,
    bench_plonky3_witness_construction,
);

#[cfg(feature = "plonky3-backend")]
criterion_main!(hash_backend_benches, plonky3_benches);

#[cfg(not(feature = "plonky3-backend"))]
criterion_main!(hash_backend_benches);
