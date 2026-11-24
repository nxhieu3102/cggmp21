use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use fast_paillier::DecryptionKey;
use rand_dev::DevRng;

fn build_precompute_table(c: &mut Criterion) {
    let mut rng = DevRng::new();
    let dk = DecryptionKey::generate(&mut rng, 3072, 512).unwrap();
    let ek = dk.encryption_key();

    let mut group = c.benchmark_group("precompute_table");
    group.sample_size(10);
    for block_size in [4, 6, 8] {
        group.bench_function(BenchmarkId::new("build", block_size), |b| {
            b.iter(|| ek.precompute_table(block_size).unwrap())
        });
    }
    group.finish();
}

criterion_group!(benches, build_precompute_table);
criterion_main!(benches);
