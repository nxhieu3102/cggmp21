use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use fast_paillier::DecryptionKey;
use rand;
use std::time::Duration;
fn keygen(c: &mut Criterion) {
    let n_size = 3072;
    let a_size = 512;
    let mut rng = rand::thread_rng();

    let mut group = c.benchmark_group("keygen");
    group
        .sample_size(100)
        .measurement_time(Duration::from_secs(3077));

    group.bench_function(BenchmarkId::new("keygen", "3072bit"), |b| {
        b.iter(|| {
            let _ = DecryptionKey::generate(&mut rng, n_size, a_size).unwrap();
        });
    });

    group.finish();
}

criterion_group!(benches, keygen);
criterion_main!(benches);
