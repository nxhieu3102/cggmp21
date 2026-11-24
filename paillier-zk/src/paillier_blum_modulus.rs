//! ZK-proof of Paillier-Blum modulus. Called Пmod or Rmod in the CGGMP21 paper.
//!
//! ## Description
//! A party P has a modulus `N = pq`, with p and q being Blum primes, and
//! `gcd(N, phi(N)) = 1`. P wants to prove that those equalities about N hold,
//! without disclosing p and q.
//!
//! ## Example
//! ```rust
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut rng = rand_core::OsRng;
//! # let mut rng = rand_dev::DevRng::new();
//!
//! // 0. Prover P derives two Blum primes and makes a Paillier-Blum modulus
//! let p = fast_paillier::utils::generate_safe_prime(&mut rng, 256);
//! let q = fast_paillier::utils::generate_safe_prime(&mut rng, 256);
//! let n = &p * &q;
//!
//! // 1. P computes a non-interactive proof that `n` is a Paillier-Blum modulus:
//! use paillier_zk::paillier_blum_modulus as p;
//!
//! // Security parameter
//! const SECURITY: usize = 33;
//! // Verifier and prover share the same state
//! let shared_state = "some shared state";
//!
//! let data = p::Data { n };
//! let pdata = p::PrivateData { p, q };
//!
//! let (commitment, proof) =
//!     p::non_interactive::prove::<{SECURITY}, sha2::Sha256>(
//!         &shared_state,
//!         &data,
//!         &pdata,
//!         &mut rng,
//!     )?;
//!
//! // 2. P sends `data, commitment, proof` to the verifier V
//!
//! # fn send(_: &p::Data, _: &p::Commitment, _: &p::Proof<{SECURITY}>) { }
//! send(&data, &commitment, &proof);
//!
//! // 3. V receives and verifies the proof:
//!
//! # let recv = || (data, commitment, proof);
//! let (data, commitment, proof) = recv();
//!
//! p::non_interactive::verify::<{SECURITY}, sha2::Sha256>(
//!     &shared_state,
//!     &data,
//!     &commitment,
//!     &proof,
//! )?;
//! # Ok(()) }
//! ```
//! If the verification succeeded, V can continue communication with P

#[cfg(feature = "serde")]
use fast_paillier::utils::serde_wrapper::serializable_bigint;
use num_bigint::BigInt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Public data that both parties know: the Paillier-Blum modulus
#[derive(Debug, Clone, udigest::Digestable)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Data {
    #[udigest(as = crate::common::encoding::BigInt)]
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub n: BigInt,
}

/// Private data of prover
#[derive(Clone)]
pub struct PrivateData {
    pub p: BigInt,
    pub q: BigInt,
}

/// Prover's first message, obtained by [`interactive::commit`]
#[derive(Debug, Clone, udigest::Digestable)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Commitment {
    #[udigest(as = crate::common::encoding::BigInt)]
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub w: BigInt,
}

/// Verifier's challenge to prover. Can be obtained deterministically by
/// [`non_interactive::challenge`] or randomly by [`interactive::challenge`]
///
/// Consists of `M` singular challenges
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Challenge<const M: usize> {
    pub ys: [BigInt; M],
}

/// A part of proof. Having enough of those guarantees security
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ProofPoint {
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub x: BigInt,
    pub a: bool,
    pub b: bool,
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub z: BigInt,
}

/// The ZK proof. Computed by [`interactive::prove`] or
/// [`non_interactive::prove`]. Consists of M proofs for each challenge
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Proof<const M: usize> {
    #[cfg_attr(
        // A trick to serialize arbitrary size arrays
        feature = "serde",
        serde(with = "serde_with::As::<[serde_with::Same; M]>")
    )]
    pub points: [ProofPoint; M],
}

/// Samples `M` challenges uniformly from `[0; n)`. A modulus `n <= 1` is rejected by the
/// verifier, the challenge is all zeroes in this case.
fn sample_challenge<const M: usize>(n: &BigInt, rng: &mut impl rand_core::RngCore) -> Challenge<M> {
    use num_bigint::RandBigInt;
    let ys = if *n > BigInt::from(1) {
        [(); M].map(|()| rng.gen_bigint_range(&BigInt::ZERO, n))
    } else {
        [(); M].map(|()| BigInt::ZERO)
    };
    Challenge { ys }
}

/// The interactive version of the ZK proof. Should be completed in 3 rounds:
/// prover commits to data, verifier responds with a random challenge, and
/// prover gives proof with commitment and challenge.
pub mod interactive {
    use fast_paillier::mont::Montgomery;
    use num_bigint::{BigInt, BigUint};
    use num_integer::Integer;
    use num_traits::One;
    use rand_core::RngCore;

    use crate::common::sqrt::{find_residue, sample_neg_jacobi};
    use crate::{Error, ErrorReason, InvalidProof, InvalidProofReason};

    use super::{Challenge, Commitment, Data, PrivateData, Proof, ProofPoint};

    /// Create random commitment
    ///
    /// `n` must be an odd modulus that is not a perfect square, otherwise the function doesn't
    /// terminate.
    pub fn commit<R: RngCore>(Data { ref n }: &Data, rng: &mut R) -> Commitment {
        Commitment {
            w: sample_neg_jacobi(n, rng),
        }
    }

    /// Exponentiation modulo a prime factor with exponents reduced modulo `p - 1`
    struct PrimeCtx {
        mont: Montgomery,
        /// `N^-1 mod (p-1)`
        n_inv: BigUint,
        /// `e^2 mod (p-1)` where `e = (phi(N) + 4) / 8` is the principal square root exponent
        fourth_root: BigUint,
    }

    impl PrimeCtx {
        fn new(p: &BigInt, n: &BigInt, fourth_root: &BigInt) -> Option<Self> {
            let p_minus_1 = p - 1u8;
            Some(Self {
                mont: Montgomery::new(p.magnitude())?,
                n_inv: n.mod_floor(&p_minus_1).modinv(&p_minus_1)?.into_parts().1,
                fourth_root: fourth_root.mod_floor(&p_minus_1).into_parts().1,
            })
        }
        fn reduce(&self, x: &BigInt) -> BigUint {
            x.mod_floor(&BigInt::from(self.mont.modulus().clone()))
                .into_parts()
                .1
        }
    }

    /// Compute proof for given data and prior protocol values
    ///
    /// The prover knows the factorization, so every exponentiation is done modulo `p` and
    /// `q` separately with exponents reduced modulo `p-1` and `q-1`, and recombined with CRT.
    pub fn prove<const M: usize>(
        Data { ref n }: &Data,
        PrivateData { ref p, ref q }: &PrivateData,
        Commitment { ref w }: &Commitment,
        challenge: &Challenge<M>,
    ) -> Result<Proof<M>, Error> {
        if *p <= BigInt::one() || *q <= BigInt::one() || &(p * q) != n {
            return Err(ErrorReason::InvalidPrivateData.into());
        }
        // Exponent of the principal square root in a Blum modulus ring, see [Handbook of
        // Applied cryptography, p. 75, Fact 2.160](https://cacr.uwaterloo.ca/hac/about/chap2.pdf).
        // The principal fourth root is obtained by applying it twice, i.e. with exponent `e^2`.
        // If p, q are not Blum primes, the result is bogus and the proof doesn't verify.
        let e = ((p - 1u8) * (q - 1u8) + 4u8) >> 3u8;
        let e_squared = &e * &e;
        let ctx_p = PrimeCtx::new(p, n, &e_squared).ok_or(ErrorReason::Invert)?;
        let ctx_q = PrimeCtx::new(q, n, &e_squared).ok_or(ErrorReason::Invert)?;
        let q_inv_p = q.modinv(p).ok_or(ErrorReason::Invert)?;

        // x = x_q + q * ((x_p - x_q) * q^-1 mod p)
        let crt = |x_p: BigUint, x_q: BigUint| -> BigInt {
            let (x_p, x_q) = (BigInt::from(x_p), BigInt::from(x_q));
            ((x_p - &x_q) * &q_inv_p).mod_floor(p) * q + x_q
        };
        let pow = |y: &BigInt, f: fn(&PrimeCtx) -> &BigUint| {
            crt(
                ctx_p.mont.pow(&ctx_p.reduce(y), f(&ctx_p)),
                ctx_q.mont.pow(&ctx_q.reduce(y), f(&ctx_q)),
            )
        };

        // We do an extra allocation as workaround while `array::try_map` is not stable
        let points = challenge
            .ys
            .iter()
            .map(|y| {
                let z = pow(y, |ctx| &ctx.n_inv);
                let (a, b, y_) = find_residue(y, w, p, q, n).ok_or(ErrorReason::FindResidue)?;
                let x = pow(&y_, |ctx| &ctx.fourth_root);
                Ok(ProofPoint { x, a, b, z })
            })
            .collect::<Result<Vec<_>, ErrorReason>>()?
            .try_into()
            .map_err(|_| ErrorReason::Length)?;
        Ok(Proof { points })
    }

    /// Verify the proof. If this succeeds, the relation Rmod holds with chance
    /// `1/2^M`
    pub fn verify<const M: usize>(
        data: &Data,
        commitment: &Commitment,
        challenge: &Challenge<M>,
        proof: &Proof<M>,
    ) -> Result<(), InvalidProof> {
        let n = &data.n;
        if *n <= BigInt::one() {
            return Err(InvalidProofReason::ModulusTooSmall.into());
        }
        if n.is_even() {
            return Err(InvalidProofReason::ModulusIsEven.into());
        }
        if fast_paillier::utils::is_prime(n) {
            return Err(InvalidProofReason::ModulusIsPrime.into());
        }
        let mont = Montgomery::new(n.magnitude()).ok_or(InvalidProofReason::ModulusIsEven)?;
        let reduce = |x: &BigInt| x.mod_floor(n).into_parts().1;
        let w = commitment.w.mod_floor(n);

        for (point, y) in proof.points.iter().zip(challenge.ys.iter()) {
            // Exponent `N` is public
            let z_to_n = mont.pow_vartime(&reduce(&point.z), n.magnitude());
            if BigInt::from(z_to_n) != *y {
                return Err(InvalidProofReason::IncorrectNthRoot.into());
            }
            let y = if point.a { n - y } else { y.clone() };
            let y = if point.b { (y * &w).mod_floor(n) } else { y };
            let x = reduce(&point.x);
            let x_sq = (&x * &x) % n.magnitude();
            let x_4 = (&x_sq * &x_sq) % n.magnitude();
            if BigInt::from(x_4) != y {
                return Err(InvalidProofReason::IncorrectFourthRoot.into());
            }
        }
        Ok(())
    }

    /// Generate random challenge
    ///
    /// `data` parameter is used to generate challenge in correct range
    pub fn challenge<const M: usize, R: RngCore>(data: &Data, rng: &mut R) -> Challenge<M> {
        super::sample_challenge(&data.n, rng)
    }
}

/// The non-interactive version of proof. Completed in one round, for example
/// see the documentation of parent module.
pub mod non_interactive {
    use digest::Digest;

    use crate::{Error, InvalidProof};

    use super::{Challenge, Commitment, Data, PrivateData, Proof};

    /// Compute proof for the given data, producing random commitment and
    /// deriving determenistic challenge.
    ///
    /// Obtained from the above interactive proof via Fiat-Shamir heuristic.
    pub fn prove<const M: usize, D: Digest>(
        shared_state: &impl udigest::Digestable,
        data: &Data,
        pdata: &PrivateData,
        rng: &mut impl rand_core::RngCore,
    ) -> Result<(Commitment, Proof<M>), Error> {
        let commitment = super::interactive::commit(data, rng);
        let challenge = challenge::<M, D>(shared_state, data, &commitment);
        let proof = super::interactive::prove(data, pdata, &commitment, &challenge)?;
        Ok((commitment, proof))
    }

    /// Verify the proof, deriving challenge independently from same data
    pub fn verify<const M: usize, D: Digest>(
        shared_state: &impl udigest::Digestable,
        data: &Data,
        commitment: &Commitment,
        proof: &Proof<M>,
    ) -> Result<(), InvalidProof> {
        let challenge = challenge::<M, D>(shared_state, data, commitment);
        super::interactive::verify(data, commitment, &challenge, proof)
    }

    /// Deterministically compute challenge based on prior known values in protocol
    pub fn challenge<const M: usize, D: Digest>(
        shared_state: &impl udigest::Digestable,
        data: &Data,
        commitment: &Commitment,
    ) -> Challenge<M> {
        let tag = "paillier_zk.blum_modulus.ni_challenge";
        let seed = udigest::inline_struct!(tag {
            shared_state,
            data,
            commitment,
        });
        let mut rng = rand_hash::HashRng::<D, _>::from_seed(seed);
        super::sample_challenge(&data.n, &mut rng)
    }
}

#[cfg(test)]
mod test {
    use num_bigint::BigInt;
    use num_traits::Num;

    use crate::common::test::generate_blum_prime;
    use crate::common::InvalidProofReason;

    type D = sha2::Sha256;
    const M: usize = 65;

    fn blum_modulus() -> (super::Data, super::PrivateData) {
        let mut rng = rand_dev::DevRng::new();
        let p = generate_blum_prime(&mut rng, 256);
        let q = generate_blum_prime(&mut rng, 256);
        let n = &p * &q;
        (super::Data { n }, super::PrivateData { p, q })
    }

    fn verify(
        data: &super::Data,
        commitment: &super::Commitment,
        proof: &super::Proof<M>,
    ) -> Result<(), InvalidProofReason> {
        super::non_interactive::verify::<M, D>(&"shared state", data, commitment, proof)
            .map_err(|e| e.reason())
    }

    #[test]
    fn passing() {
        let mut rng = rand_dev::DevRng::new();
        let (data, pdata) = blum_modulus();
        let (commitment, proof) =
            super::non_interactive::prove::<M, D>(&"shared state", &data, &pdata, &mut rng)
                .unwrap();
        verify(&data, &commitment, &proof).unwrap();

        // Responses are the principal roots, same as computing without CRT
        let challenge =
            super::non_interactive::challenge::<M, D>(&"shared state", &data, &commitment);
        let n = &data.n;
        let phi = (&pdata.p - 1u8) * (&pdata.q - 1u8);
        let n_inv = n.modinv(&phi).unwrap();
        let e = (&phi + 4u8) / 8u8;
        for (point, y) in proof.points.iter().zip(&challenge.ys) {
            assert_eq!(point.z, y.modpow(&n_inv, n));
            let (_, _, y_) =
                crate::common::sqrt::find_residue(y, &commitment.w, &pdata.p, &pdata.q, n).unwrap();
            assert_eq!(point.x, y_.modpow(&e, n).modpow(&e, n));
        }
    }

    #[test]
    fn tampered_proof_or_transcript() {
        let mut rng = rand_dev::DevRng::new();
        let (data, pdata) = blum_modulus();
        let (commitment, proof) =
            super::non_interactive::prove::<M, D>(&"shared state", &data, &pdata, &mut rng)
                .unwrap();

        // Different commitment changes the challenge (Fiat-Shamir binding)
        let mut bad_commitment = commitment.clone();
        bad_commitment.w += 1;
        assert!(verify(&data, &bad_commitment, &proof).is_err());

        // Different shared state
        assert!(
            super::non_interactive::verify::<M, D>(&"other", &data, &commitment, &proof).is_err()
        );

        let mut bad = proof.clone();
        bad.points[M - 1].z += 1;
        assert_eq!(
            verify(&data, &commitment, &bad),
            Err(InvalidProofReason::IncorrectNthRoot)
        );

        let mut bad = proof.clone();
        bad.points[3].x = -bad.points[3].x.clone();
        // (-x)^4 = x^4, still a valid fourth root
        assert_eq!(verify(&data, &commitment, &bad), Ok(()));
        bad.points[3].x += 1;
        assert_eq!(
            verify(&data, &commitment, &bad),
            Err(InvalidProofReason::IncorrectFourthRoot)
        );

        let mut bad = proof.clone();
        bad.points[0].a = !bad.points[0].a;
        assert!(verify(&data, &commitment, &bad).is_err());
    }

    #[test]
    fn non_blum_modulus() {
        let mut rng = rand_dev::DevRng::new();
        let p = generate_blum_prime(&mut rng, 256);
        let q = BigInt::from_str_radix(
            "83068444371047794141187595475503751543138564039474151978032204006692380162693",
            10,
        )
        .unwrap();
        assert!(fast_paillier::utils::is_prime(&q));
        assert_ne!(&q % 4, BigInt::from(3u8));

        let n = &p * &q;
        let data = super::Data { n };
        let pdata = super::PrivateData { p, q };

        let (commitment, proof) =
            super::non_interactive::prove::<M, D>(&"shared state", &data, &pdata, &mut rng)
                .unwrap();
        assert!(verify(&data, &commitment, &proof).is_err());
    }

    #[test]
    fn bad_moduli() {
        let mut rng = rand_dev::DevRng::new();
        let (data, pdata) = blum_modulus();
        let (commitment, proof) =
            super::non_interactive::prove::<M, D>(&"shared state", &data, &pdata, &mut rng)
                .unwrap();

        // Prime modulus is rejected
        let prime = super::Data { n: pdata.p.clone() };
        assert_eq!(
            verify(&prime, &commitment, &proof),
            Err(InvalidProofReason::ModulusIsPrime)
        );
        // Even modulus is rejected
        let even = super::Data { n: &data.n * 2 };
        assert_eq!(
            verify(&even, &commitment, &proof),
            Err(InvalidProofReason::ModulusIsEven)
        );
        // Degenerate moduli don't panic and are rejected
        for n in [-5, -1, 0, 1] {
            let data = super::Data { n: BigInt::from(n) };
            assert_eq!(
                verify(&data, &commitment, &proof),
                Err(InvalidProofReason::ModulusTooSmall)
            );
        }

        // Prover refuses inconsistent private data
        let wrong = super::PrivateData {
            p: pdata.p.clone(),
            q: pdata.p.clone(),
        };
        assert!(
            super::non_interactive::prove::<M, D>(&"shared state", &data, &wrong, &mut rng)
                .is_err()
        );
    }
}
