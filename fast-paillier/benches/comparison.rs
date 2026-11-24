use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use fast_paillier::precomputed_table::PrecomputeTable;
use fast_paillier::{utils, DecryptionKey};
use num_bigint::RandBigInt;
use rand_dev::DevRng;

fn key(rng: &mut DevRng) -> DecryptionKey {
    DecryptionKey::generate(rng, 3072, 512).unwrap()
}

fn encryption(c: &mut Criterion) {
    let mut rng = DevRng::new();
    let dk = key(&mut rng);
    let ek = dk.encryption_key();
    let table = ek
        .precompute_table(PrecomputeTable::DEFAULT_BLOCK_SIZE)
        .unwrap();
    let mut group = c.benchmark_group("Encrypt");

    let mut inputs = || {
        let x = rng.gen_bigint_range(ek.neg_half_n(), ek.half_n());
        let nonce = utils::sample_with_size(&mut rng, ek.nounce_size());
        (x, nonce)
    };
    group.bench_function("EncryptionKey", |b| {
        b.iter_batched(
            &mut inputs,
            |(x, nonce)| ek.encrypt_with(&x, &nonce).unwrap(),
            BatchSize::SmallInput,
        )
    });
    group.bench_function("DecryptionKey (CRT)", |b| {
        b.iter_batched(
            &mut inputs,
            |(x, nonce)| dk.encrypt_with(&x, &nonce).unwrap(),
            BatchSize::SmallInput,
        )
    });
    let mut bench_rng = DevRng::new();
    group.bench_function("EncryptionKey with precompute table", |b| {
        b.iter_batched(
            &mut inputs,
            |(x, nonce)| {
                ek.encrypt_with_precompute_table(&mut bench_rng, &table, &x, Some(&nonce))
                    .unwrap()
            },
            BatchSize::SmallInput,
        )
    });
}

fn decryption(c: &mut Criterion) {
    let mut rng = DevRng::new();
    let dk = key(&mut rng);
    let ek = dk.encryption_key();

    let mut group = c.benchmark_group("Decrypt");
    let mut inputs = || {
        let x = rng.gen_bigint_range(ek.neg_half_n(), ek.half_n());
        ek.encrypt_with_random(&mut rng, &x).unwrap().0
    };
    group.bench_function("Decrypt (CRT)", |b| {
        b.iter_batched(
            &mut inputs,
            |c| dk.decrypt(&c).unwrap(),
            BatchSize::SmallInput,
        )
    });
}

fn omul(c: &mut Criterion) {
    let mut rng = DevRng::new();
    let dk = key(&mut rng);
    let ek = dk.encryption_key();

    let mut group = c.benchmark_group("OMul");
    let mut inputs = || {
        let scalar = rng.gen_bigint_range(&-ek.n(), ek.n());
        let c = utils::sample_in_mult_group(&mut rng, ek.nn());
        (scalar, c)
    };
    group.bench_function("with CRT", |b| {
        b.iter_batched(
            &mut inputs,
            |(scalar, c)| dk.omul(&scalar, &c).unwrap(),
            BatchSize::SmallInput,
        )
    });
    group.bench_function("without CRT", |b| {
        b.iter_batched(
            &mut inputs,
            |(scalar, c)| ek.omul(&scalar, &c).unwrap(),
            BatchSize::SmallInput,
        )
    });
}

fn safe_primes(c: &mut Criterion) {
    let mut rng = DevRng::new();
    let mut group = c.benchmark_group("Safe primes");
    group.sample_size(10);
    for bits in [256, 512] {
        group.bench_function(format!("{bits}"), |b| {
            b.iter(|| utils::generate_safe_prime(&mut rng, bits))
        });
    }
}

criterion_group!(benches, encryption, decryption, omul, safe_primes);
criterion_main!(benches);
