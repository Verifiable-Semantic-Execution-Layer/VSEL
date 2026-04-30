//! Criterion benchmarks for VSEL cryptographic primitives.
//!
//! Benchmarks Poseidon permutation, Poseidon hash_bytes, and
//! GoldilocksField multiplication over the Goldilocks field.
//!
//! **Validates: Requirements 7.1(d), 7.1(e), 7.1(f)**
//!
//! Run with: `cargo bench --bench crypto_benchmarks -p vsel-crypto`

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use vsel_crypto::goldilocks::GoldilocksField;
use vsel_crypto::poseidon_goldilocks::PoseidonGoldilocks;

// ---------------------------------------------------------------------------
// Benchmark group: Poseidon permutation time
// Requirements 7.1(d)
// ---------------------------------------------------------------------------

fn bench_poseidon_permutation(c: &mut Criterion) {
    let poseidon = PoseidonGoldilocks::new();

    // Zero state permutation
    let state_zero = [GoldilocksField(0); 12];

    c.bench_function("poseidon_permute/zero_state", |b| {
        b.iter(|| {
            let mut s = state_zero;
            poseidon.permute(black_box(&mut s));
            black_box(s);
        });
    });

    // Random state permutation
    let state_random: [GoldilocksField; 12] = [
        GoldilocksField(0x1234567890ABCDEF),
        GoldilocksField(0xFEDCBA0987654321),
        GoldilocksField(0x0000000100000000),
        GoldilocksField(0xFFFFFFFF00000000),
        GoldilocksField(42),
        GoldilocksField(1),
        GoldilocksField(0),
        GoldilocksField(0xDEADBEEFCAFEBABE % GoldilocksField::MODULUS),
        GoldilocksField(0x0102030405060708),
        GoldilocksField(0x0807060504030201),
        GoldilocksField(GoldilocksField::MODULUS - 1),
        GoldilocksField(GoldilocksField::MODULUS - 2),
    ];

    c.bench_function("poseidon_permute/random_state", |b| {
        b.iter(|| {
            let mut s = state_random;
            poseidon.permute(black_box(&mut s));
            black_box(s);
        });
    });
}

// ---------------------------------------------------------------------------
// Benchmark group: Poseidon hash_bytes time
// Requirements 7.1(e)
// ---------------------------------------------------------------------------

fn bench_poseidon_hash_bytes(c: &mut Criterion) {
    let poseidon = PoseidonGoldilocks::new();

    let mut group = c.benchmark_group("poseidon_hash_bytes");

    for (label, size) in [
        ("1KB", 1_024),
        ("10KB", 10_240),
        ("100KB", 102_400),
        ("1MB", 1_048_576),
    ] {
        let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("size", label), &data, |b, data| {
            b.iter(|| {
                let _ = black_box(poseidon.hash_bytes(black_box(data)));
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark group: GoldilocksField multiplication time
// Requirements 7.1(f)
// ---------------------------------------------------------------------------

fn bench_goldilocks_multiplication(c: &mut Criterion) {
    let a = GoldilocksField(0x1234567890ABCDEF % GoldilocksField::MODULUS);
    let b = GoldilocksField(0xFEDCBA0987654321 % GoldilocksField::MODULUS);

    c.bench_function("goldilocks_mul", |b_iter| {
        b_iter.iter(|| {
            let _ = black_box(black_box(a).mul(black_box(b)));
        });
    });

    // Also benchmark add, sub, inv, sbox for completeness
    let mut group = c.benchmark_group("goldilocks_ops");

    group.bench_function("add", |b_iter| {
        b_iter.iter(|| {
            let _ = black_box(black_box(a).add(black_box(b)));
        });
    });

    group.bench_function("sub", |b_iter| {
        b_iter.iter(|| {
            let _ = black_box(black_box(a).sub(black_box(b)));
        });
    });

    group.bench_function("mul", |b_iter| {
        b_iter.iter(|| {
            let _ = black_box(black_box(a).mul(black_box(b)));
        });
    });

    let non_zero = GoldilocksField(42);
    group.bench_function("inv", |b_iter| {
        b_iter.iter(|| {
            let _ = black_box(black_box(non_zero).inv());
        });
    });

    group.bench_function("sbox", |b_iter| {
        b_iter.iter(|| {
            let _ = black_box(black_box(a).sbox());
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Criterion configuration
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_poseidon_permutation,
    bench_poseidon_hash_bytes,
    bench_goldilocks_multiplication,
);
criterion_main!(benches);
