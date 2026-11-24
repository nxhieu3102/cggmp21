use fast_paillier::{
    utils, AnyEncryptionKey, AnyEncryptionKeyExt, DecryptionKey, EncryptionKey, KeygenProgress,
};
use num_bigint::{BigInt, RandBigInt};
use num_integer::Integer;
use num_traits::{One, Signed, Zero};
use rand_core::RngCore;
use rand_dev::DevRng;

/// Generated small keys, plus the 3072-bit fixture keys when `serde` is enabled
fn test_keys(rng: &mut DevRng) -> Vec<DecryptionKey> {
    let keys = vec![
        DecryptionKey::generate(rng, 512, 64).unwrap(),
        DecryptionKey::generate(rng, 1024, 256).unwrap(),
    ];
    #[cfg(feature = "serde")]
    let keys = {
        let mut keys = keys;
        keys.push(fixtures::keys().swap_remove(0));
        keys
    };
    keys
}

/// Takes `x mod n` and maps result to `{-N/2, .., N/2}`
fn signed_modulo(x: &BigInt, n: &BigInt) -> BigInt {
    let x = x.mod_floor(n);
    if &x * 2 > *n {
        x - n
    } else {
        x
    }
}

fn random_plaintext(rng: &mut DevRng, ek: &EncryptionKey) -> BigInt {
    rng.gen_bigint_range(ek.neg_half_n(), &(ek.half_n() + 1))
}

fn random_signed(rng: &mut DevRng, bits: u64) -> BigInt {
    let x = BigInt::from(rng.gen_biguint(bits));
    if rng.next_u32().is_multiple_of(2) {
        -x
    } else {
        x
    }
}

/// Textbook decryption with plain num-bigint arithmetic (no CRT, no Montgomery kernel)
fn reference_decrypt(dk: &DecryptionKey, c: &BigInt) -> BigInt {
    let ek = dk.encryption_key();
    let two_alpha: BigInt = dk.alpha() * 2;
    let u = c.mod_floor(ek.nn()).modpow(&two_alpha, ek.nn());
    let l: BigInt = (u - 1) / ek.n();
    let m: BigInt = (l * two_alpha.modinv(ek.n()).unwrap()).mod_floor(ek.n());
    signed_modulo(&m, ek.n())
}

/// Textbook encryption with plain num-bigint arithmetic
fn reference_encrypt(ek: &EncryptionKey, x: &BigInt, nonce: &BigInt) -> BigInt {
    let b = if nonce.is_negative() {
        ek.h_pow_n()
            .modinv(ek.nn())
            .unwrap()
            .modpow(&-nonce, ek.nn())
    } else {
        ek.h_pow_n().modpow(nonce, ek.nn())
    };
    ((BigInt::one() + x * ek.n()) * b).mod_floor(ek.nn())
}

#[test]
fn encrypt_decrypt() {
    let mut rng = DevRng::new();
    for dk in test_keys(&mut rng) {
        let ek = dk.encryption_key();
        for _ in 0..20 {
            let x = random_plaintext(&mut rng, ek);
            let (c, nonce) = ek.encrypt_with_random(&mut rng, &x).unwrap();
            assert_eq!(nonce.bits(), u64::from(ek.nounce_size()));
            assert_eq!(dk.decrypt(&c).unwrap(), x);
            let (c, _) = dk.encrypt_with_random(&mut rng, &x).unwrap();
            assert_eq!(dk.decrypt(&c).unwrap(), x);
            // trait method samples the nonce from Z*_N
            let (c, _) = AnyEncryptionKeyExt::encrypt_with_random(&dk, &mut rng, &x).unwrap();
            assert_eq!(dk.decrypt(&c).unwrap(), x);
        }

        let half = ek.half_n().clone();
        for x in [
            -half.clone(),
            -&half + 1,
            BigInt::zero(),
            BigInt::from(-1),
            BigInt::one(),
            &half - 1,
            half.clone(),
        ] {
            let (c, _) = ek.encrypt_with_random(&mut rng, &x).unwrap();
            assert_eq!(dk.decrypt(&c).unwrap(), x);
        }

        for x in [-&half - 1, -&half - 2, &half + 1, ek.n().clone()] {
            assert!(ek.encrypt_with_random(&mut rng, &x).is_err());
            assert!(dk.encrypt_with_random(&mut rng, &x).is_err());
            assert!(ek.encrypt_with(&x, &BigInt::one()).is_err());
            assert!(dk.encrypt_with(&x, &BigInt::one()).is_err());
        }
    }
}

#[test]
fn homomorphic_ops() {
    let mut rng = DevRng::new();
    for dk in test_keys(&mut rng) {
        let ek = dk.encryption_key();
        let n = ek.n();
        for _ in 0..10 {
            let a = random_plaintext(&mut rng, ek);
            let b = random_plaintext(&mut rng, ek);
            let (enc_a, _) = ek.encrypt_with_random(&mut rng, &a).unwrap();
            let (enc_b, _) = ek.encrypt_with_random(&mut rng, &b).unwrap();

            let sum = ek.oadd(&enc_a, &enc_b).unwrap();
            assert_eq!(dk.decrypt(&sum).unwrap(), signed_modulo(&(&a + &b), n));

            let diff = ek.osub(&enc_a, &enc_b).unwrap();
            assert_eq!(dk.decrypt(&diff).unwrap(), signed_modulo(&(&a - &b), n));

            let neg = ek.oneg(&enc_a).unwrap();
            assert_eq!(dk.decrypt(&neg).unwrap(), signed_modulo(&-&a, n));

            for scalar in [
                a.clone(),
                -a.clone(),
                BigInt::from(-1),
                BigInt::from(-3),
                random_signed(&mut rng, 256),
            ] {
                let expected = signed_modulo(&(&scalar * &b), n);
                let prod = ek.omul(&scalar, &enc_b).unwrap();
                assert_eq!(dk.decrypt(&prod).unwrap(), expected);
                let prod_crt = dk.omul(&scalar, &enc_b).unwrap();
                assert_eq!(prod_crt, prod);
                let prod_any = AnyEncryptionKey::omul(&dk, &scalar, &enc_b).unwrap();
                assert_eq!(prod_any, prod);
            }
        }
    }
}

#[test]
fn crt_paths_equal_plain_paths() {
    let mut rng = DevRng::new();
    for dk in test_keys(&mut rng) {
        let ek = dk.encryption_key();
        let n_bits = ek.n().bits();
        for _ in 0..20 {
            let x = random_plaintext(&mut rng, ek);
            let nonce = match rng.next_u32() % 4 {
                0 => random_signed(&mut rng, u64::from(ek.nounce_size())),
                1 => random_signed(&mut rng, 3 * n_bits),
                2 => utils::sample_in_mult_group(&mut rng, ek.n()),
                _ => BigInt::zero(),
            };
            let c = ek.encrypt_with(&x, &nonce).unwrap();
            assert_eq!(c, reference_encrypt(ek, &x, &nonce));
            assert_eq!(dk.encrypt_with(&x, &nonce).unwrap(), c);
            assert_eq!(dk.decrypt(&c).unwrap(), reference_decrypt(&dk, &c));
            assert_eq!(dk.decrypt(&c).unwrap(), x);

            // omul on arbitrary units of Z*_{N^2}, scalars of any size and sign
            let c = utils::sample_in_mult_group(&mut rng, ek.nn());
            let bits = [1, 64, n_bits, 2 * n_bits + 7][rng.next_u32() as usize % 4];
            let scalar = random_signed(&mut rng, bits);
            let plain = ek.omul(&scalar, &c);
            let crt = dk.omul(&scalar, &c);
            match (plain, crt) {
                (Ok(plain), Ok(crt)) => assert_eq!(plain, crt),
                (Err(_), Err(_)) => {}
                (plain, crt) => panic!("mismatch: {plain:?} vs {crt:?}"),
            }
        }

        // omul rejects the same inputs on both paths
        let c = ek.encrypt_with(&BigInt::one(), &BigInt::from(5)).unwrap();
        let p_multiple: BigInt = dk.p() * 3;
        for (scalar, ciphertext) in [
            (BigInt::zero(), c.clone()),
            (p_multiple.clone(), c.clone()),
            (-dk.q().clone(), c.clone()),
            (BigInt::from(7), p_multiple.clone()),
            (BigInt::from(7), BigInt::zero()),
            (BigInt::from(7), -c.clone()),
        ] {
            assert!(ek.omul(&scalar, &ciphertext).is_err());
            assert!(dk.omul(&scalar, &ciphertext).is_err());
        }
        assert!(ek.oadd(&c, &p_multiple).is_err());
        assert!(ek.oadd(&-c.clone(), &c).is_err());
        assert!(ek.osub(&p_multiple, &c).is_err());
        assert!(ek.oneg(&p_multiple).is_err());
    }
}

#[test]
fn decrypt_rejects_invalid_ciphertexts() {
    let mut rng = DevRng::new();
    for dk in test_keys(&mut rng) {
        let ek = dk.encryption_key();
        for c in [BigInt::zero(), dk.p().clone(), dk.q() * 5, ek.n().clone()] {
            assert!(dk.decrypt(&c).is_err());
        }
        // a random unit of Z*_{N^2} is almost never in the image of encryption
        let mut rejected = 0;
        for _ in 0..10 {
            let c = utils::sample_in_mult_group(&mut rng, ek.nn());
            match dk.decrypt(&c) {
                Ok(m) => assert_eq!(m, reference_decrypt(&dk, &c)),
                Err(_) => rejected += 1,
            }
        }
        assert!(rejected >= 9);
        // non-canonical representatives of valid ciphertexts decrypt like the canonical one
        let (c, _) = ek
            .encrypt_with_random(&mut rng, &BigInt::from(-77))
            .unwrap();
        assert_eq!(dk.decrypt(&(&c + ek.nn())).unwrap(), BigInt::from(-77));
        assert_eq!(dk.decrypt(&(&c - ek.nn())).unwrap(), BigInt::from(-77));
    }
}

#[test]
fn precompute_table_encryption_equals_plain() {
    let mut rng = DevRng::new();
    let keys = test_keys(&mut rng);
    for (i, dk) in keys.iter().enumerate() {
        let ek = dk.encryption_key();
        for block_size in [1, 4, 6, 9] {
            let table = ek.precompute_table(block_size).unwrap();
            assert_eq!(table.pow_size(), ek.nounce_size() as usize);
            for _ in 0..5 {
                let m = random_plaintext(&mut rng, ek);
                let nonce = BigInt::from(rng.gen_biguint(u64::from(ek.nounce_size())));
                let c = ek
                    .encrypt_with_precompute_table(&mut rng, &table, &m, Some(&nonce))
                    .unwrap();
                assert_eq!(c, ek.encrypt_with(&m, &nonce).unwrap());
                let c = ek
                    .encrypt_with_precompute_table(&mut rng, &table, &m, None)
                    .unwrap();
                assert_eq!(dk.decrypt(&c).unwrap(), m);
            }
            let zero = BigInt::zero();
            assert_eq!(
                ek.encrypt_with_precompute_table(&mut rng, &table, &zero, Some(&zero))
                    .unwrap(),
                BigInt::one()
            );

            let too_long = BigInt::one() << ek.nounce_size();
            let m = BigInt::from(5);
            assert!(ek
                .encrypt_with_precompute_table(&mut rng, &table, &m, Some(&too_long))
                .is_err());
            assert!(ek
                .encrypt_with_precompute_table(&mut rng, &table, &m, Some(&BigInt::from(-1)))
                .is_err());
            let out_of_range = ek.half_n() + 1;
            assert!(ek
                .encrypt_with_precompute_table(&mut rng, &table, &out_of_range, None)
                .is_err());
            let other = keys[(i + 1) % keys.len()].encryption_key();
            assert!(other
                .encrypt_with_precompute_table(&mut rng, &table, &m, None)
                .is_err());
        }
    }
}

#[test]
fn keygen_invariants() {
    let mut rng = DevRng::new();
    for (n_size, a_size) in [(512u32, 64u32), (768, 128), (1024, 256), (1030, 250)] {
        for _ in 0..3 {
            let mut events = vec![];
            let dk = DecryptionKey::generate_with_progress(&mut rng, n_size, a_size, &mut |e| {
                events.push(e)
            })
            .unwrap();
            check_key_invariants(&dk, n_size, a_size);
            for which in [0, 1] {
                assert!(events.contains(&KeygenProgress::DivisorPrimeFound { which }));
                assert!(events.iter().any(
                    |e| matches!(e, KeygenProgress::PrimeFound { which: w, attempts } if *w == which && *attempts > 0)
                ));
            }

            let ek = dk.encryption_key();
            let x = random_plaintext(&mut rng, ek);
            let (c, _) = ek.encrypt_with_random(&mut rng, &x).unwrap();
            assert_eq!(dk.decrypt(&c).unwrap(), x);
        }
    }

    for (n_size, a_size) in [(0, 0), (10, 4), (100, 200), (512, 4), (70, 64)] {
        assert!(DecryptionKey::generate(&mut rng, n_size, a_size).is_err());
    }
}

fn check_key_invariants(dk: &DecryptionKey, n_size: u32, a_size: u32) {
    let (p, q, alpha) = (dk.p(), dk.q(), dk.alpha());
    let ek = dk.encryption_key();
    let n = ek.n();
    assert_eq!(&(p * q), n);
    assert!(utils::is_prime(p) && utils::is_prime(q));
    assert_eq!(p.mod_floor(&BigInt::from(4)), BigInt::from(3));
    assert_eq!(q.mod_floor(&BigInt::from(4)), BigInt::from(3));
    let (p1, q1): (BigInt, BigInt) = (p - 1, q - 1);
    assert_eq!(p1.gcd(&q1), BigInt::from(2));

    // alpha = div_p · div_q with div_p | p - 1, div_q | q - 1 safe primes of a_size/2 bits
    let div_p = alpha.gcd(&p1);
    let div_q = alpha.gcd(&q1);
    assert_eq!(&(&div_p * &div_q), alpha);
    for div in [&div_p, &div_q] {
        assert_eq!(div.bits(), u64::from(a_size / 2));
        assert!(utils::is_prime(div));
        assert!(utils::is_prime(&((div - 1) / 2)));
    }
    let phi_quarter: BigInt = &p1 * &q1 / 4;
    assert!((&phi_quarter % alpha).is_zero());
    let beta = &phi_quarter / alpha;
    assert!(alpha.gcd(&beta).is_one());

    // sizes accepted by cggmp21 (EPSILON_N_SIZE = 3, EPSILON_A_SIZE = 1)
    assert!(n.bits() <= u64::from(n_size) && n.bits() >= u64::from(n_size) - 3);
    assert!(alpha.bits() <= u64::from(a_size) && alpha.bits() >= u64::from(a_size) - 1);

    assert_eq!(ek.n_size(), n_size);
    assert_eq!(ek.a_size(), a_size);
    assert_eq!(ek.nounce_size(), a_size);
    // h = -(y^(2·beta) mod n) has order dividing 2·alpha
    assert!(ek.h().is_negative() && -ek.h() < *n);
    assert!(ek.h().mod_floor(n).modpow(&(alpha * 2), n).is_one());
    assert!(ek.verify_h_pow_n());
    assert_eq!(ek.h_pow_n(), &ek.h().mod_floor(ek.nn()).modpow(n, ek.nn()));
}

#[test]
fn encryption_key_new_rejects_bad_modulus() {
    let b = BigInt::from;
    for (h, n) in [
        (b(-4), b(0)),
        (b(-4), b(1)),
        (b(-4), b(-15)),
        (b(-3), b(16)),
        (b(3), b(15)), // h not invertible
        (b(0), b(15)),
    ] {
        assert!(EncryptionKey::new(8, 4, h, n).is_err());
    }
    assert!(EncryptionKey::new(8, 0, b(2), b(15)).is_err());
    let ek = EncryptionKey::new(8, 4, b(-4), b(15)).unwrap();
    assert!(ek.verify_h_pow_n());
    assert_eq!(
        ek.h_pow_n(),
        &b(-4).mod_floor(&b(225)).modpow(&b(15), &b(225))
    );
}

#[test]
fn decryption_key_new_validates() {
    let mut rng = DevRng::new();
    let dk = DecryptionKey::generate(&mut rng, 512, 64).unwrap();
    let ek = dk.encryption_key().clone();
    let (p, q, alpha) = (dk.p().clone(), dk.q().clone(), dk.alpha().clone());
    assert!(DecryptionKey::new(ek.clone(), p.clone(), q.clone(), alpha.clone()).is_ok());
    assert!(DecryptionKey::new(ek.clone(), q.clone(), p.clone(), alpha.clone()).is_ok());
    assert!(DecryptionKey::new(ek.clone(), p.clone() + 2, q.clone(), alpha.clone()).is_err());
    assert!(DecryptionKey::new(ek.clone(), ek.n().clone(), BigInt::one(), alpha.clone()).is_err());
    assert!(DecryptionKey::new(ek.clone(), -p.clone(), -q.clone(), alpha.clone()).is_err());
    assert!(DecryptionKey::new(ek.clone(), p.clone(), q.clone(), BigInt::zero()).is_err());
    assert!(DecryptionKey::new(ek.clone(), p.clone(), q.clone(), &alpha + 2).is_err());
    let other = DecryptionKey::generate(&mut rng, 512, 64).unwrap();
    assert!(DecryptionKey::new(other.encryption_key().clone(), p, q, alpha).is_err());
    // the factorization never shows up in Debug output
    let debug = format!("{dk:?}");
    assert!(!debug.contains(&dk.p().to_string()) && !debug.contains("alpha"));
}

#[cfg(feature = "serde")]
mod fixtures {
    use fast_paillier::DecryptionKey;

    pub const KEYS_JSON: &str = include_str!("fixtures/paillier_keys_3072.json");

    pub fn keys_json() -> Vec<serde_json::Value> {
        let value: serde_json::Value = serde_json::from_str(KEYS_JSON).unwrap();
        value["paillier_keys"].as_array().unwrap().clone()
    }

    pub fn keys() -> Vec<DecryptionKey> {
        keys_json()
            .into_iter()
            .map(|k| serde_json::from_value(k).unwrap())
            .collect()
    }
}

#[cfg(feature = "serde")]
mod serde_tests {
    use super::*;
    use serde_json::{json, Value};

    #[test]
    fn fixture_keys_load_and_round_trip() {
        let mut rng = DevRng::new();
        for json in fixtures::keys_json() {
            let dk: DecryptionKey = serde_json::from_value(json.clone()).unwrap();
            assert_eq!(serde_json::to_value(&dk).unwrap(), json);
            let ek: EncryptionKey = serde_json::from_value(json["ek"].clone()).unwrap();
            assert_eq!(serde_json::to_value(&ek).unwrap(), json["ek"]);
            assert!(ek.verify_h_pow_n());
            assert_eq!(ek.n_size(), 3072);
            assert_eq!(ek.a_size(), 512);

            let x = random_plaintext(&mut rng, &ek);
            let (c, _) = ek.encrypt_with_random(&mut rng, &x).unwrap();
            assert_eq!(dk.decrypt(&c).unwrap(), x);

            let dk2 = DecryptionKey::from_json(&dk.to_json().unwrap()).unwrap();
            assert_eq!(dk2.p(), dk.p());
            let ek2 = EncryptionKey::from_json(&ek.to_json().unwrap()).unwrap();
            assert_eq!(ek2.h_pow_n(), ek.h_pow_n());
        }
    }

    #[test]
    fn generated_key_round_trip() {
        let mut rng = DevRng::new();
        let dk = DecryptionKey::generate(&mut rng, 512, 64).unwrap();
        let json = serde_json::to_string(&dk).unwrap();
        let dk2: DecryptionKey = serde_json::from_str(&json).unwrap();
        assert_eq!(serde_json::to_string(&dk2).unwrap(), json);
        let x = BigInt::from(-1234);
        let c = dk.encrypt_with(&x, &BigInt::from(99)).unwrap();
        assert_eq!(dk2.decrypt(&c).unwrap(), x);
    }

    fn tampered_ek(field: &str, value: Value) -> Value {
        let mut ek = fixtures::keys_json()[0]["ek"].clone();
        ek[field] = value;
        ek
    }

    #[test]
    fn malformed_encryption_keys_are_errors() {
        let ek = fixtures::keys_json()[0]["ek"].clone();
        let n = ek["n"].as_str().unwrap().to_owned();
        let nn = ek["nn"].as_str().unwrap().to_owned();
        let even_n = format!("{}0", &n[..n.len() - 1]);
        for (field, value) in [
            ("n", json!("0")),
            ("n", json!("1")),
            ("n", json!("")),
            ("n", json!("-")),
            ("n", json!("xyz")),
            ("n", json!(format!("-{n}"))),
            ("n", json!(even_n)),
            ("n", json!(12345)),
            ("nn", json!("ff")),
            ("half_n", json!("1")),
            ("neg_half_n", json!(n)),
            ("h_pow_n", json!(nn)),
            ("h_pow_n", json!("-1")),
            ("h_pow_n", json!("0")),
            ("h_pow_n", json!(n)),
            ("h", json!("not hex")),
            ("nounce_size", json!(511)),
            ("a_size", json!(0)),
        ] {
            let tampered = tampered_ek(field, value.clone());
            assert!(
                serde_json::from_value::<EncryptionKey>(tampered).is_err(),
                "{field} = {value}"
            );
        }
        let mut missing = ek.clone();
        missing.as_object_mut().unwrap().remove("h_pow_n");
        assert!(serde_json::from_value::<EncryptionKey>(missing).is_err());
        assert!(EncryptionKey::from_json("{}").is_err());
        assert!(EncryptionKey::from_json("").is_err());

        // h_pow_n is trusted on load; a forged value is caught by verify_h_pow_n
        let forged =
            serde_json::from_value::<EncryptionKey>(tampered_ek("h_pow_n", json!("1"))).unwrap();
        assert!(!forged.verify_h_pow_n());
        let forged =
            serde_json::from_value::<EncryptionKey>(tampered_ek("h", json!("-2"))).unwrap();
        assert!(!forged.verify_h_pow_n());
    }

    #[test]
    fn malformed_decryption_keys_are_errors() {
        let dk = fixtures::keys_json()[0].clone();
        let other = fixtures::keys_json()[1].clone();
        let p = dk["p"].as_str().unwrap().to_owned();
        let tampered = |field: &str, value: Value| {
            let mut dk = dk.clone();
            dk[field] = value;
            dk
        };
        for (i, json) in [
            tampered("p", json!("3")),
            tampered("q", json!(p)),
            tampered("p", json!("")),
            tampered("alpha", json!("0")),
            tampered("alpha", json!("-1")),
            tampered("alpha", json!("3")),
            tampered("ek", other["ek"].clone()),
            // h_pow_n outside the subgroup of order dividing 2·alpha
            tampered("ek", tampered_ek("h_pow_n", json!("2"))),
        ]
        .into_iter()
        .enumerate()
        {
            assert!(
                serde_json::from_value::<DecryptionKey>(json).is_err(),
                "case {i}"
            );
        }
        assert!(DecryptionKey::from_json(r#"{"ek":{}}"#).is_err());

        // h_pow_n = 1 has order dividing 2·alpha, so it loads (it's trusted, like for
        // EncryptionKey); verify_h_pow_n catches it
        let forged: DecryptionKey =
            serde_json::from_value(tampered("ek", tampered_ek("h_pow_n", json!("1")))).unwrap();
        assert!(!forged.encryption_key().verify_h_pow_n());
    }

    #[test]
    fn crt_exp_serde() {
        let mut rng = DevRng::new();
        let dk = DecryptionKey::generate(&mut rng, 512, 64).unwrap();
        let crt = utils::CrtExp::build_n(dk.p(), dk.q()).unwrap();
        let mut json = serde_json::to_value(&crt).unwrap();
        let crt2: utils::CrtExp = serde_json::from_value(json.clone()).unwrap();
        let x = BigInt::from(12345);
        let e = crt.prepare_exponent(&BigInt::from(-987654321));
        assert_eq!(crt.exp(&x, &e), crt2.exp(&x, &e));
        let e_json = serde_json::to_value(&e).unwrap();
        let e2: utils::Exponent = serde_json::from_value(e_json).unwrap();
        assert_eq!(crt.exp(&x, &e), crt.exp(&x, &e2));

        json["beta"] = json!({"radix": 16, "value": "2"});
        assert!(serde_json::from_value::<utils::CrtExp>(json.clone()).is_err());
        json["n1"] = json!({"radix": 16, "value": "0"});
        assert!(serde_json::from_value::<utils::CrtExp>(json).is_err());
    }
}
