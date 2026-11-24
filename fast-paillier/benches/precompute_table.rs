use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use fast_paillier::{precomputed_table::PrecomputeTable, AnyEncryptionKey, EncryptionKey};
use std::time::Duration;

fn calculate_precompute_table(c: &mut Criterion) {
    let ek = EncryptionKey::sample_128();
    let pow_size = 512;

    let mut group = c.benchmark_group("precompute_table");

    group
        .sample_size(10)
        .measurement_time(Duration::from_secs(336));

    group.bench_function(
        BenchmarkId::new("caculate_precompute_table_17_512", "sample_128"),
        |b| {
            b.iter(|| {
                let base = ek.h_pow_n().clone();
                let modulo = ek.nn().clone();
                let _ = PrecomputeTable::new_dp(base, 17, pow_size, modulo);
            })
        },
    );

    group.bench_function(
        BenchmarkId::new("caculate_precompute_table_15_512", "sample_128"),
        |b| {
            b.iter(|| {
                let base = ek.h_pow_n().clone();
                let modulo = ek.nn().clone();
                let _ = PrecomputeTable::new_dp(base, 15, pow_size, modulo);
            })
        },
    );

    group.finish();
}

criterion_group!(benches, calculate_precompute_table);
criterion_main!(benches);
