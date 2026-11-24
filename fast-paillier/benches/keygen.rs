use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use fast_paillier::DecryptionKey;
use rand_dev::DevRng;

fn keygen(c: &mut Criterion) {
    let mut rng = DevRng::new();
    let mut group = c.benchmark_group("keygen");
    group.sample_size(10);
    for (n_size, a_size) in [(2048, 448), (3072, 512)] {
        group.bench_function(
            BenchmarkId::new("generate", format!("{n_size}-{a_size}")),
            |b| {
                b.iter(|| DecryptionKey::generate(&mut rng, n_size, a_size).unwrap());
            },
        );
    }
    group.finish();
}

criterion_group!(benches, keygen);
criterion_main!(benches);
