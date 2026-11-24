//! Pregenerates aux data and keys
//!
//! This example shows how aux data can be generated to set up proofs. Generated data is used by doctests.
//!
//! Because this example generates some keys, it will take a while to run.
//!
//! You can run this example with the following command:
//!
//! ```bash
//! cargo run --release -p paillier-zk --example pregenerate --features=__internal_doctest
//! ```
//!
//! The generated keys will be saved in the `test-data` directory.

use anyhow::{Context, Result};
use num_bigint::{BigInt, RandBigInt};
use num_integer::Integer;

use paillier_zk::BigIntExt;

fn main() -> Result<()> {
    let mut rng = rand_core::OsRng;

    // Generate Verifier's aux data
    {
        let p = fast_paillier::utils::generate_safe_prime(&mut rng, 1024);
        let q = fast_paillier::utils::generate_safe_prime(&mut rng, 1024);
        let n = &p * &q;

        let (s, t) = {
            let phi_n = (&p - 1u8) * (&q - 1u8);
            let r = BigInt::gen_invertible(&n, &mut rng);
            let lambda = rng.gen_bigint_range(&BigInt::from(0), &phi_n);

            let t = (&r * &r).mod_floor(&n);
            let s = t.modpow_ext(&lambda, &n).context("modpow")?;

            (s, t)
        };

        let aux = paillier_zk::paillier_encryption_in_range::Aux {
            s,
            t,
            rsa_modulo: n,
            multiexp: None,
            crt: None,
        };

        let aux_json = serde_json::to_vec_pretty(&aux).context("serialize aux")?;
        std::fs::write("./test-data/verifier_aux.json", aux_json).context("save aux")?;
    }

    // Generate a bunch of paillier keys
    generate_paillier_key(
        &mut rng,
        Some("./test-data/prover_decryption_key.json".as_ref()),
        Some("./test-data/prover_encryption_key.json".as_ref()),
    )?;
    generate_paillier_key(
        &mut rng,
        None, // "someone's" secret decryption key remains unknown
        Some("./test-data/someone_encryption_key0.json".as_ref()),
    )?;
    generate_paillier_key(
        &mut rng,
        None, // "someone's" secret decryption key remains unknown
        Some("./test-data/someone_encryption_key1.json".as_ref()),
    )?;

    Ok(())
}

fn generate_paillier_key(
    rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
    output_dk: Option<&std::path::Path>,
    output_ek: Option<&std::path::Path>,
) -> Result<()> {
    // paillier key achieve 128 bits security
    let n_size = 3072;
    let a_size = 512;

    let dk = fast_paillier::DecryptionKey::generate(rng, n_size, a_size)?;
    let ek = dk.encryption_key();

    if let Some(path) = output_dk {
        let dk_json = serde_json::to_vec_pretty(&dk).context("serialize decryption key")?;
        std::fs::write(path, dk_json).context("save decryption key")?;
    }

    if let Some(path) = output_ek {
        let ek_json = serde_json::to_vec_pretty(&ek).context("serialize encryption key")?;
        std::fs::write(path, ek_json).context("save encryption key")?;
    }

    Ok(())
}
