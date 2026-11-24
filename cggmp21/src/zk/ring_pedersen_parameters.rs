//! Пprm or Rprm in the paper. Proof that s ⋮ t modulo N. Non-interactive
//! version only.
use digest::Digest;
use num_bigint::{BigInt, BigUint, RandBigInt};
use num_integer::Integer as _;
use num_traits::Zero;
use paillier_zk::fast_paillier::{mont::Montgomery, utils::CrtExp};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use thiserror::Error;

struct Challenge<const M: usize> {
    es: [bool; M],
}

/// Data to construct proof about
#[derive(Clone, Copy, udigest::Digestable)]
pub struct Data<'a> {
    #[udigest(as = &crate::utils::encoding::Integer)]
    pub N: &'a BigInt,
    #[udigest(as = &crate::utils::encoding::Integer)]
    pub s: &'a BigInt,
    #[udigest(as = &crate::utils::encoding::Integer)]
    pub t: &'a BigInt,
}

/// Ring-Pedersen parameters `s`, `t` for modulus `N = pq`, along with the witness `λ`
/// such that $s = t^λ \mod N$
pub struct Params {
    pub s: BigInt,
    pub t: BigInt,
    /// Secret witness
    pub lambda: BigInt,
}

impl Params {
    /// Samples `r ← Z_N^*`, `λ ← [0; φ(N))` and computes $t = r^2$, $s = t^λ \mod N$
    pub fn generate(
        rng: &mut (impl RngCore + CryptoRng),
        p: &BigInt,
        q: &BigInt,
    ) -> Result<Self, ZkError> {
        let n = p * q;
        let phi = (p - 1u8) * (q - 1u8);
        let crt = CrtExp::build_n(p, q).ok_or(Reason::Crt)?;

        let r = paillier_zk::fast_paillier::utils::sample_in_mult_group(rng, &n);
        let lambda = rng.gen_bigint_range(&BigInt::zero(), &phi);
        let t = (&r * &r).mod_floor(&n);
        let s = crt
            .exp(&t, &crt.prepare_exponent(&lambda))
            .ok_or(Reason::PowMod)?;
        Ok(Self { s, t, lambda })
    }
}

/// The ZK proof. Computed by [`prove`].
///
/// Parameter `M` is security level. The probability of an adversary generating
/// a correct proof for incorrect data is $2^{-M}$. You can use M defined here
/// as [`SECURITY`]
#[serde_as]
#[derive(Clone, Serialize, Deserialize, udigest::Digestable)]
pub struct Proof<const M: usize> {
    #[serde_as(as = "[crate::utils::SerdeBigInt; M]")]
    #[udigest(as = [crate::utils::encoding::Integer; M])]
    pub commitment: [BigInt; M],
    #[serde_as(as = "[crate::utils::SerdeBigInt; M]")]
    #[udigest(as = [crate::utils::encoding::Integer; M])]
    pub zs: [BigInt; M],
}

fn derive_challenge<const M: usize, D: Digest>(
    shared_state: &impl udigest::Digestable,
    data: Data,
    commitment: &[BigInt; M],
) -> Challenge<M> {
    #[derive(udigest::Digestable)]
    #[udigest(tag = "dfns.ring_pedersen_parameters.seed")]
    struct Seed<'a, S: udigest::Digestable, const M: usize> {
        shared_state: &'a S,
        data: Data<'a>,
        #[udigest(as = &[crate::utils::encoding::Integer; M])]
        commitment: &'a [BigInt; M],
    }

    let mut rng = rand_hash::HashRng::<D, _>::from_seed(Seed::<_, M> {
        shared_state,
        data,
        commitment,
    });

    // generate bools by hand since we don't have rand
    let mut es = [false; M];
    let mut current = rng.next_u32();
    let mut bits_generated = 0;
    for e_ref in es.iter_mut() {
        if bits_generated == 32 {
            current = rng.next_u32();
            bits_generated = 0;
        }
        *e_ref = (current & 1) == 1;
        current >>= 1;
    }
    Challenge { es }
}

/// Compute the proof for the given data, producing random commitment and
/// deriving deterministic challenge based on `shared_state` and `data`
///
/// - `p`, `q` - factorization of `N`
/// - `lambda` - λ such that $s = t^λ$
pub fn prove<const M: usize, D: Digest>(
    shared_state: &impl udigest::Digestable,
    rng: &mut (impl RngCore + CryptoRng),
    data: Data,
    p: &BigInt,
    q: &BigInt,
    lambda: &BigInt,
) -> Result<Proof<M>, ZkError> {
    let phi = (p - 1u8) * (q - 1u8);
    let crt = CrtExp::build_n(p, q).ok_or(Reason::Crt)?;
    let private_commitment = [(); M].map(|()| rng.gen_bigint_range(&BigInt::zero(), &phi));

    let mut commitment: [BigInt; M] = [(); M].map(|()| BigInt::zero());
    for (a, commitment_i) in private_commitment.iter().zip(&mut commitment) {
        *commitment_i = crt
            .exp(data.t, &crt.prepare_exponent(a))
            .ok_or(Reason::PowMod)?;
    }

    let challenge: Challenge<M> = derive_challenge::<M, D>(shared_state, data, &commitment);

    let mut zs = private_commitment;
    for (z_ref, e) in zs.iter_mut().zip(&challenge.es) {
        if *e {
            *z_ref = (&*z_ref + lambda).mod_floor(&phi);
        }
    }
    Ok(Proof { commitment, zs })
}

/// Verify the proof. Derives determenistic challenge based on `shared_state`
/// and `data`.
pub fn verify<const M: usize, D: Digest>(
    shared_state: &impl udigest::Digestable,
    data: Data,
    proof: &Proof<M>,
) -> Result<(), InvalidProof> {
    let n = data.N.to_biguint().ok_or(InvalidProof)?;
    let to_residue = |x: &BigInt| -> Result<BigUint, InvalidProof> {
        x.to_biguint().filter(|x| *x < n).ok_or(InvalidProof)
    };
    let s = to_residue(data.s)?;
    let t = to_residue(data.t)?;
    let ctx = Montgomery::new(&n).ok_or(InvalidProof)?;

    let challenge: Challenge<M> = derive_challenge::<M, D>(shared_state, data, &proof.commitment);
    for ((z, a), e) in proof.zs.iter().zip(&proof.commitment).zip(&challenge.es) {
        let z = z.to_biguint().ok_or(InvalidProof)?;
        let a = to_residue(a)?;
        let lhs = ctx.pow_vartime(&t, &z);
        let rhs = if *e { (&s * &a) % &n } else { a };
        if lhs != rhs {
            return Err(InvalidProof);
        }
    }
    Ok(())
}

#[derive(Debug, Error)]
#[error(transparent)]
pub struct ZkError(#[from] Reason);

#[derive(Debug, Error)]
enum Reason {
    #[error("pow mod undefined")]
    PowMod,
    #[error("couldn't build CRT parameters")]
    Crt,
}

/// Witness that proof is invalid
#[derive(Debug)]
pub struct InvalidProof;

#[cfg(test)]
mod test {
    use num_bigint::BigInt;
    use num_traits::{One, Zero};

    use crate::utils;

    type D = sha2::Sha256;

    struct Setup {
        p: BigInt,
        q: BigInt,
        n: BigInt,
        lambda: BigInt,
        t: BigInt,
        s: BigInt,
    }

    fn setup(rng: &mut rand_dev::DevRng) -> Setup {
        let p = utils::generate_blum_prime(rng, 256);
        let q = utils::generate_blum_prime(rng, 256);
        let n = &p * &q;
        let super::Params { s, t, lambda } = super::Params::generate(rng, &p, &q).unwrap();
        assert_eq!(t.modpow(&lambda, &n), s, "s = t^lambda mod N");
        Setup {
            p,
            q,
            n,
            lambda,
            t,
            s,
        }
    }

    #[test]
    fn passing() {
        let mut rng = rand_dev::DevRng::new();
        let Setup {
            p,
            q,
            n,
            lambda,
            t,
            s,
        } = setup(&mut rng);
        let data = super::Data {
            N: &n,
            s: &s,
            t: &t,
        };

        let proof: super::Proof<16> =
            super::prove::<16, D>(&"shared state", &mut rng, data, &p, &q, &lambda).unwrap();
        super::verify::<16, D>(&"shared state", data, &proof).expect("proof should pass");
        assert!(
            super::verify::<16, D>(&"other state", data, &proof).is_err(),
            "proof must be bound to shared state"
        );
    }

    #[test]
    fn wrong_s_is_rejected() {
        let mut rng = rand_dev::DevRng::new();
        let Setup {
            p,
            q,
            n,
            lambda,
            t,
            s,
        } = setup(&mut rng);
        let s = (s + 1u8) % &n;
        let data = super::Data {
            N: &n,
            s: &s,
            t: &t,
        };

        let proof: super::Proof<16> =
            super::prove::<16, D>(&"shared state", &mut rng, data, &p, &q, &lambda).unwrap();
        assert!(super::verify::<16, D>(&"shared state", data, &proof).is_err());
    }

    #[test]
    fn malformed_proof_is_rejected_without_panic() {
        let mut rng = rand_dev::DevRng::new();
        let Setup {
            p,
            q,
            n,
            lambda,
            t,
            s,
        } = setup(&mut rng);
        let data = super::Data {
            N: &n,
            s: &s,
            t: &t,
        };
        let proof: super::Proof<16> =
            super::prove::<16, D>(&"shared state", &mut rng, data, &p, &q, &lambda).unwrap();

        let mut negative_z = proof.clone();
        negative_z.zs[0] = -BigInt::one();
        assert!(super::verify::<16, D>(&"shared state", data, &negative_z).is_err());

        let mut unreduced_commitment = proof.clone();
        unreduced_commitment.commitment[0] += &n;
        assert!(super::verify::<16, D>(&"shared state", data, &unreduced_commitment).is_err());

        let zero_modulus = BigInt::zero();
        let bad_data = super::Data {
            N: &zero_modulus,
            ..data
        };
        assert!(super::verify::<16, D>(&"shared state", bad_data, &proof).is_err());
    }
}
