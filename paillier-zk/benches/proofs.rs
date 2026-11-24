//! Prove/verify timings of the proofs used by cggmp21, at `SecurityLevel128` sizes
//! (3072-bit Paillier keys and ring-Pedersen modulus, M = 128, ℓ = 256, ℓ' = 848, ε = 230,
//! q = 2^128, t = 128, batch size 2).
//!
//! Run with `cargo bench -p paillier-zk --features serde --bench proofs`.

use std::time::{Duration, Instant};

use fast_paillier::DecryptionKey;
use generic_ec::{curves::Secp256k1 as E, Point, Scalar};
use num_bigint::{BigInt, RandBigInt};
use num_integer::Integer;
use paillier_zk::{
    batch_paillier_affine_operation_in_range as aff,
    batch_paillier_encryption_in_range_with_el_gamal as enc_elg,
    no_small_factor::non_interactive as fac, paillier_blum_modulus as pmod, BigIntExt,
};

type D = sha2::Sha256;
const M: usize = 128;
const ELL: usize = 256;
const ELL_PRIME: usize = 848;
const EPSILON: usize = 230;
const T: usize = 128;

fn keys() -> Vec<DecryptionKey> {
    #[derive(serde::Deserialize)]
    struct Keys {
        paillier_keys: Vec<DecryptionKey>,
    }
    let json = include_str!("../../test-data/precomputed_paillier_keys.json");
    serde_json::from_str::<Keys>(json)
        .expect("parse keys")
        .paillier_keys
}

fn aux(
    dk: &DecryptionKey,
    rng: &mut impl rand_core::RngCore,
    crt: bool,
) -> paillier_zk::no_small_factor::Aux {
    let n = dk.n().clone();
    let phi = (dk.p() - 1u8) * (dk.q() - 1u8);
    let r = BigInt::gen_invertible(&n, rng);
    let lambda = rng.gen_bigint_range(&BigInt::from(0), &phi);
    let t = (&r * &r).mod_floor(&n);
    let s = t.modpow(&lambda, &n);
    paillier_zk::no_small_factor::Aux {
        s,
        t,
        rsa_modulo: n,
        multiexp: None,
        crt: if crt {
            fast_paillier::utils::CrtExp::build_n(dk.p(), dk.q())
        } else {
            None
        },
    }
}

fn time<T>(name: &str, iters: u32, mut f: impl FnMut() -> T) -> T {
    let mut out = None;
    let mut total = Duration::ZERO;
    for _ in 0..iters {
        let start = Instant::now();
        out = Some(f());
        total += start.elapsed();
    }
    println!(
        "{name:<32} {:>10.1} ms",
        total.as_secs_f64() * 1000. / f64::from(iters)
    );
    out.expect("iters > 0")
}

fn main() {
    let mut rng = rand_dev::DevRng::new();
    let keys = keys();
    let prover = &keys[0];
    let verifier = &keys[1];
    let aux_plain = aux(verifier, &mut rng, false);
    let aux_crt = aux(verifier, &mut rng, true);
    // Prover's view of the verifier's aux with a multiexp table, sized as in cggmp21
    // (`security_level::max_exponents_size`)
    let x_bits = (ELL_PRIME + EPSILON + 2 * T + 8) as u64;
    let table = time("multiexp table build", 1, || {
        paillier_zk::multiexp::MultiexpTable::build(
            &aux_plain.s,
            &aux_plain.t,
            x_bits,
            x_bits + 3072,
            aux_plain.rsa_modulo.clone(),
        )
        .unwrap()
    });
    let aux_table = paillier_zk::no_small_factor::Aux {
        multiexp: Some(std::sync::Arc::new(table)),
        ..aux_plain.clone()
    };
    let q = BigInt::from(1) << 128_u32;
    let shared_state = "bench";

    // Πmod
    {
        let data = pmod::Data {
            n: prover.n().clone(),
        };
        let pdata = pmod::PrivateData {
            p: prover.p().clone(),
            q: prover.q().clone(),
        };
        let (comm, proof) = time("pi_mod prove", 2, || {
            pmod::non_interactive::prove::<M, D>(&shared_state, &data, &pdata, &mut rng).unwrap()
        });
        time("pi_mod verify", 3, || {
            pmod::non_interactive::verify::<M, D>(&shared_state, &data, &comm, &proof).unwrap()
        });
        time("  of which is_prime(N)", 3, || {
            fast_paillier::utils::is_prime(prover.n())
        });
    }

    // Πfac
    {
        let n = prover.n();
        let n_root = n.sqrt();
        let data = fac::Data { n, n_root: &n_root };
        let security = fac::SecurityParams {
            l: ELL,
            epsilon: EPSILON,
            q: q.clone(),
        };
        let pdata = fac::PrivateData {
            p: prover.p(),
            q: prover.q(),
        };
        let proof = time("pi_fac prove", 3, || {
            fac::prove::<D>(&shared_state, &aux_plain, data, pdata, &security, &mut rng).unwrap()
        });
        time("pi_fac verify", 3, || {
            fac::verify::<D>(&shared_state, &aux_plain, data, &security, &proof).unwrap()
        });
        time("pi_fac prove (multiexp table)", 3, || {
            fac::prove::<D>(&shared_state, &aux_table, data, pdata, &security, &mut rng).unwrap()
        });
        let proof =
            fac::prove::<D>(&shared_state, &aux_crt, data, pdata, &security, &mut rng).unwrap();
        time("pi_fac verify (crt)", 3, || {
            fac::verify::<D>(&shared_state, &aux_crt, data, &security, &proof).unwrap()
        });
    }

    // batch aff-g, prover's own key is `key1`, `key0` belongs to the verifier
    {
        let ek0 = verifier.encryption_key();
        let security = aff::SecurityParams {
            l_x: ELL,
            l_y: ELL_PRIME,
            epsilon: EPSILON,
            q: q.clone(),
            t: T,
        };
        let k = BigInt::from_rng_pm(&(BigInt::from(1) << ELL), &mut rng);
        let (k_ct, _) = ek0.encrypt_with_random(&mut rng, &k).unwrap();
        let xs: Vec<BigInt> = (0..2)
            .map(|_| BigInt::from_rng_pm(&(BigInt::from(1) << ELL), &mut rng))
            .collect();
        let ys: Vec<BigInt> = (0..2)
            .map(|_| BigInt::from_rng_pm(&(BigInt::from(1) << ELL_PRIME), &mut rng))
            .collect();
        let mut nonces = vec![];
        let mut nonces_y = vec![];
        let mut batch = vec![];
        for (x, y) in xs.iter().zip(&ys) {
            let (y_enc0, rho) = ek0.encrypt_with_random(&mut rng, y).unwrap();
            let d = ek0.oadd(&ek0.omul(x, &k_ct).unwrap(), &y_enc0).unwrap();
            let (y_enc1, rho_y) = prover.encrypt_with_random(&mut rng, y).unwrap();
            nonces.push(rho);
            nonces_y.push(rho_y);
            batch.push(aff::PublicElement {
                c: k_ct.clone(),
                x: Point::<E>::generator() * x.to_scalar::<E>(),
                d,
                y: y_enc1,
            });
        }
        let data = aff::PublicData {
            key0: ek0,
            key1: prover,
            batch,
        };
        let pdata = aff::PrivateData {
            batch: (0..2)
                .map(|i| aff::PrivateElement {
                    x: &xs[i],
                    y: &ys[i],
                    nonce: &nonces[i],
                    nonce_y: &nonces_y[i],
                })
                .collect(),
        };
        let data_v = aff::PublicData {
            key0: verifier,
            key1: prover.encryption_key(),
            batch: data.batch.clone(),
        };
        let (comm, proof) = time("aff-g batch prove", 3, || {
            aff::non_interactive::prove::<E, D>(
                &shared_state,
                &aux_plain,
                data.clone(),
                pdata.clone(),
                &security,
                &mut rng,
            )
            .unwrap()
        });
        time("aff-g batch verify", 3, || {
            aff::non_interactive::verify::<E, D>(
                &shared_state,
                &aux_plain,
                data_v.clone(),
                &comm,
                &security,
                &proof,
            )
            .unwrap()
        });
        time("aff-g batch prove (multiexp table)", 3, || {
            aff::non_interactive::prove::<E, D>(
                &shared_state,
                &aux_table,
                data.clone(),
                pdata.clone(),
                &security,
                &mut rng,
            )
            .unwrap()
        });
        let (comm, proof) = aff::non_interactive::prove::<E, D>(
            &shared_state,
            &aux_crt,
            data.clone(),
            pdata.clone(),
            &security,
            &mut rng,
        )
        .unwrap();
        time("aff-g batch verify (crt)", 3, || {
            aff::non_interactive::verify::<E, D>(
                &shared_state,
                &aux_crt,
                data_v.clone(),
                &comm,
                &security,
                &proof,
            )
            .unwrap()
        });
    }

    // batch enc-elg, prover encrypts under its own key
    {
        let security = enc_elg::SecurityParams {
            l: ELL,
            epsilon: EPSILON,
            q: q.clone(),
            t: T,
        };
        let a = Scalar::<E>::random(&mut rng);
        let a_point = Point::generator() * a;
        let xs: Vec<BigInt> = (0..2)
            .map(|_| BigInt::from_rng_pm(&(BigInt::from(1) << ELL), &mut rng))
            .collect();
        let bs: Vec<Scalar<E>> = (0..2).map(|_| Scalar::random(&mut rng)).collect();
        let mut nonces = vec![];
        let mut batch = vec![];
        for (x, b) in xs.iter().zip(&bs) {
            let (ciphertext, nonce) = prover.encrypt_with_random(&mut rng, x).unwrap();
            nonces.push(nonce);
            batch.push(enc_elg::PublicElement {
                ciphertext,
                b: Point::generator() * b,
                x: Point::generator() * (a * b + x.to_scalar::<E>()),
            });
        }
        let private: Vec<_> = (0..2)
            .map(|i| enc_elg::PrivateElement {
                plaintext: &xs[i],
                nonce: &nonces[i],
                b: &bs[i],
            })
            .collect();
        let data = enc_elg::PublicData {
            key: prover,
            batch: &batch,
            a: &a_point,
        };
        let data_v = enc_elg::PublicData {
            key: prover.encryption_key(),
            batch: &batch,
            a: &a_point,
        };
        let pdata = enc_elg::PrivateData { batch: &private };
        let (comm, proof) = time("enc-elg batch prove", 3, || {
            enc_elg::non_interactive::prove::<E, D>(
                &shared_state,
                &aux_plain,
                data,
                pdata,
                &security,
                &mut rng,
            )
            .unwrap()
        });
        time("enc-elg batch verify", 3, || {
            enc_elg::non_interactive::verify::<E, D>(
                &shared_state,
                &aux_plain,
                data_v,
                &comm,
                &proof,
                &security,
            )
            .unwrap()
        });
        time("enc-elg batch prove (multiexp table)", 3, || {
            enc_elg::non_interactive::prove::<E, D>(
                &shared_state,
                &aux_table,
                data,
                pdata,
                &security,
                &mut rng,
            )
            .unwrap()
        });
        let (comm, proof) = enc_elg::non_interactive::prove::<E, D>(
            &shared_state,
            &aux_crt,
            data,
            pdata,
            &security,
            &mut rng,
        )
        .unwrap();
        time("enc-elg batch verify (crt)", 3, || {
            enc_elg::non_interactive::verify::<E, D>(
                &shared_state,
                &aux_crt,
                data_v,
                &comm,
                &proof,
                &security,
            )
            .unwrap()
        });
    }
}
