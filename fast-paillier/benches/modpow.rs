//! `fast_paillier::mont` against num-bigint's `modpow` for Paillier-sized operands: a 3072-bit
//! exponent modulo N (3072 bits) and modulo N² (6144 bits).

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use fast_paillier::mont::{pow_mod, Montgomery};
use num_bigint::{BigUint, RandBigInt};

fn random_odd(rng: &mut impl rand::Rng, bits: u64) -> BigUint {
    let mut m = rng.gen_biguint(bits);
    m.set_bit(bits - 1, true);
    m.set_bit(0, true);
    m
}

fn modpow(c: &mut Criterion) {
    let mut rng = rand_dev::DevRng::new();
    let exp_bits = 3072;

    let mut group = c.benchmark_group("modpow");
    group.sample_size(20);
    for mod_bits in [3072u64, 6144] {
        let m = random_odd(&mut rng, mod_bits);
        let ctx = Montgomery::new(&m).unwrap();
        let (b1, b2) = (rng.gen_biguint_below(&m), rng.gen_biguint_below(&m));
        let (e1, e2) = (rng.gen_biguint(exp_bits), rng.gen_biguint(exp_bits));
        let id = |name: &str| BenchmarkId::new(name, mod_bits);

        group.bench_function(id("num-bigint"), |b| b.iter(|| b1.modpow(&e1, &m)));
        group.bench_function(id("pow"), |b| b.iter(|| ctx.pow(&b1, &e1)));
        group.bench_function(id("pow_vartime"), |b| b.iter(|| ctx.pow_vartime(&b1, &e1)));
        group.bench_function(id("pow_mod"), |b| b.iter(|| pow_mod(&b1, &e1, &m).unwrap()));
        group.bench_function(id("num-bigint x2"), |b| {
            b.iter(|| b1.modpow(&e1, &m) * b2.modpow(&e2, &m) % &m)
        });
        group.bench_function(id("multi_pow x2"), |b| {
            b.iter(|| ctx.multi_pow(&[(&b1, &e1), (&b2, &e2)]))
        });
    }
    group.finish();
}

criterion_group!(benches, modpow);
criterion_main!(benches);
