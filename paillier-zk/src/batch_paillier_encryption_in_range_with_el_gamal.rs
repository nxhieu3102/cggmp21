//! Zero-Knowledge Proof of Paillier Encryption in Range using ElGamal Commitment.
//!
//! This protocol—referred to as Π_enc-elg or R_enc-elg in the CGGMP24 paper—proves in
//! zero knowledge that a Paillier-encrypted BigInt lies within a specific range.
//!
//! ## Overview
//!
//! The proof demonstrates that a Paillier-encrypted plaintext lies within the interval
//! $[-2^\ell, 2^\ell]$, while hiding the plaintext. It leverages ElGamal commitments over
//! an elliptic curve to bind randomness and secret values used in the encryption.
//!
//! ### Public Inputs
//! - Verifier’s [`Aux`] data (used for homomorphic commitments).
//! - [`SecurityParams`] containing $\ell$, $\varepsilon$, $q$, and $t$.
//! - An elliptic curve implementing the [`Curve`] trait.
//! - Paillier public encryption key (`key`).
//! - A batch of [`Ciphertext`] values and corresponding elliptic curve points $B$ and $X$,
//!   and a point $A = a \cdot G$ shared by the batch:
//!     - $B_i = b_i \cdot G$
//!     - $X_i = (a b_i + \text{plaintext}_i) \cdot G$
//!
//! ### Prover’s Secret Inputs
//! - `plaintext_i` in range $[-2^\ell, 2^\ell]$
//! - `nonce_i` used in Paillier encryption
//! - Scalars `b_i` used in computing ElGamal-style commitments
//!
//! ### Batching
//! Each element gets its own ring-Pedersen commitment `S_i = s^x_i t^μ_i` and its own,
//! independently sampled, challenge `e_i`; responses are aggregated
//! (`z1 = α + Σ e_i x_i`, ...). Since challenges are independent, rewinding a single `e_j`
//! extracts `x_j`, so every plaintext is range-bound individually (not only their sum).
//!
//! ### Guarantees
//! The proof guarantees that every `plaintext_i` ∈ $[-2^{\ell + \varepsilon + t}, 2^{\ell + \varepsilon + t}]$.
//! Challenges are sampled from $[-q, q]$, the parameters must satisfy $q \le 2^t$.
//!
//! ### Zero-knowledge
//! A mask uniform in $\pm 2^{k + t + \varepsilon}$ hides a sum of `n` terms $e_i \cdot v_i$ with
//! $|v_i| < 2^k$ up to statistical distance $n \cdot 2^{-\varepsilon}$:
//! - $\alpha \gets \pm 2^{\ell+\varepsilon+t}$ for $z_1$, $\gamma \gets \pm 2^{\ell+\varepsilon+t} \hat N$
//!   for $z_3$ (with $\mu_i \gets \pm 2^\ell \hat N$)
//! - $r \gets \pm 2^{b+t+\varepsilon}$ for $z_2$ where $b$ is the size of the largest nonce
//!   (at least `key.nounce_size()`): the forked Paillier encrypts as $(1+N)^x (h^N)^\rho$, nonce
//!   responses are computed over the integers.
#[cfg(feature = "serde")]
use fast_paillier::utils::serde_wrapper::{serializable_bigint, serializable_vec_bigint};
use fast_paillier::{AnyEncryptionKey, Ciphertext, Nonce, Plaintext};
use generic_ec::{Curve, Point, Scalar};
use num_bigint::BigInt;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::common::encoding;
pub use crate::common::Aux;
pub use crate::common::InvalidProof;

/// Security parameters for proof. Choosing the values is a tradeoff between
/// security, speed and correctness
#[derive(Debug, Clone, udigest::Digestable)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SecurityParams {
    /// $\ell$ in paper
    pub l: usize,
    /// $\varepsilon$ in paper, slackness parameter
    pub epsilon: usize,
    /// q in paper. Security parameter for challenge, challenges are sampled from `[-q; q]`
    #[udigest(as = encoding::BigInt)]
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub q: BigInt,
    /// t is size of challenge in bits, `q <= 2^t`
    pub t: usize,
}

/// Single element in a batch proof
#[derive(Debug, Clone, udigest::Digestable)]
#[udigest(bound = "")]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct PublicElement<C: Curve> {
    /// $C$ in paper
    #[udigest(as = encoding::BigInt)]
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub ciphertext: Ciphertext,
    /// $B = g^b = g_1^b$ - b is the prover's secret scalar (random)
    pub b: Point<C>,
    /// $X = g^{a b + x} = g_1^x * g_2^b$ - x is the plaintext (secret)
    pub x: Point<C>,
}

/// Public data that both parties know
#[derive(Debug, Clone, Copy, udigest::Digestable)]
#[udigest(bound = "")]
pub struct PublicData<'a, C: Curve> {
    /// $N_0$ in paper
    #[udigest(as = encoding::AnyEncryptionKey)]
    pub key: &'a dyn AnyEncryptionKey,
    /// Batch elements containing ciphertext, b and x values. Batch size is `batch.len()`
    pub batch: &'a Vec<PublicElement<C>>,
    /// $A = g^a$ is El-Gamal commitment generator ~ g_2 (Batch Range Proof)
    /// g_1 is curve's generator
    pub a: &'a Point<C>,
}

/// Single private element in a batch proof
#[derive(Clone)]
pub struct PrivateElement<'a, E: Curve> {
    /// $x$ in paper
    pub plaintext: &'a Plaintext,
    /// $\rho$ in paper
    pub nonce: &'a Nonce,
    /// $b$ in paper
    pub b: &'a Scalar<E>,
}

/// Private data of prover
#[derive(Clone, Copy)]
pub struct PrivateData<'a, E: Curve> {
    /// Batch of private elements
    pub batch: &'a Vec<PrivateElement<'a, E>>,
}

/// Prover's public commitment
#[derive(Debug, Clone, udigest::Digestable)]
#[udigest(bound = "")]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct Commitment<E: Curve> {
    /// `s[0] = s^α t^γ`, `s[i] = s^x_i t^μ_i` for `i` in `1..=batch.len()`
    #[udigest(as = Vec<encoding::BigInt>)]
    #[cfg_attr(feature = "serde", serde(with = "serializable_vec_bigint"))]
    pub s: Vec<BigInt>,
    /// `D = Enc(α, r)`
    #[udigest(as = encoding::BigInt)]
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub d: BigInt,
    /// `Y = A^β g^α`
    pub y: Point<E>,
    /// `Z = g^β`
    pub z: Point<E>,
}

/// Prover's secret commitment nonce
#[derive(Clone)]
pub struct PrivateCommitment<E: Curve> {
    pub alpha: BigInt,
    pub mu: Vec<BigInt>,
    pub r: BigInt,
    pub beta: Scalar<E>,
    pub gamma: BigInt,
}

/// Verifier's challenge to prover: one independent challenge per batch element. Can be obtained
/// deterministically by [`non_interactive::challenge`] or randomly by [`interactive::challenge`]
pub type Challenge = Vec<BigInt>;

/// Range Proof with El-Gamal commitment
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct Proof<E: Curve> {
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub z1: BigInt,
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub z2: BigInt,
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub z3: BigInt,
    pub w: Scalar<E>,
}

/// The interactive version of the ZK proof. Should be completed in 3 rounds:
/// prover commits to data, verifier responds with a random challenge, and
/// prover gives proof with commitment and challenge.
pub mod interactive {
    use generic_ec::{Curve, Point, Scalar};
    use num_bigint::BigInt;
    use num_traits::One;
    use rand_core::RngCore;

    use crate::common::{fail_if, fail_if_ne, BigIntExt, InvalidProof, InvalidProofReason};
    use crate::{Error, ErrorReason};

    use super::{
        Aux, Challenge, Commitment, PrivateCommitment, PrivateData, Proof, PublicData,
        SecurityParams,
    };

    /// Create random commitment
    pub fn commit<E: Curve>(
        aux: &Aux,
        data: PublicData<E>,
        pdata: PrivateData<E>,
        security: &SecurityParams,
        rng: &mut impl RngCore,
    ) -> Result<(Commitment<E>, PrivateCommitment<E>), Error> {
        let n = data.batch.len();
        if n == 0 || pdata.batch.len() != n {
            return Err(ErrorReason::Length.into());
        }
        let two_to_l_e_t = BigInt::one() << (security.l + security.epsilon + security.t);
        let hat_n_at_two_to_l = (BigInt::one() << security.l) * &aux.rsa_modulo;
        let hat_n_at_two_to_l_e_t = &two_to_l_e_t * &aux.rsa_modulo;
        let nonce_bits = pdata
            .batch
            .iter()
            .map(|e| e.nonce.bits())
            .fold(u64::from(data.key.nounce_size()), u64::max);
        let two_to_r_bits = BigInt::one() << (nonce_bits as usize + security.t + security.epsilon);

        let alpha = BigInt::from_rng_pm(&two_to_l_e_t, rng);
        let gamma = BigInt::from_rng_pm(&hat_n_at_two_to_l_e_t, rng);
        let mu: Vec<BigInt> = (0..n)
            .map(|_| BigInt::from_rng_pm(&hat_n_at_two_to_l, rng))
            .collect();
        let beta = Scalar::random(rng);
        let r = BigInt::from_rng_pm(&two_to_r_bits, rng);

        let mut s = Vec::with_capacity(n + 1);
        s.push(aux.combine(&alpha, &gamma)?);
        for (element, mu_i) in pdata.batch.iter().zip(&mu) {
            s.push(aux.combine(element.plaintext, mu_i)?);
        }
        let d = data.key.encrypt_with(&alpha, &r)?;
        let y = data.a * beta + Point::<E>::generator() * alpha.to_scalar();
        let z = Point::<E>::generator() * beta;

        Ok((
            Commitment { s, d, y, z },
            PrivateCommitment {
                alpha,
                mu,
                r,
                beta,
                gamma,
            },
        ))
    }

    /// Compute proof for given data and prior protocol values
    pub fn prove<E: Curve>(
        _data: PublicData<E>,
        pdata: PrivateData<E>,
        private_commitment: &PrivateCommitment<E>,
        challenge: &Challenge,
    ) -> Result<Proof<E>, Error> {
        let n = pdata.batch.len();
        if challenge.len() != n || private_commitment.mu.len() != n {
            return Err(ErrorReason::Length.into());
        }
        let elements = || challenge.iter().zip(pdata.batch.iter());
        let z1 = elements().fold(private_commitment.alpha.clone(), |acc, (e, elem)| {
            acc + e * elem.plaintext
        });
        let z2 = elements().fold(private_commitment.r.clone(), |acc, (e, elem)| {
            acc + e * elem.nonce
        });
        let z3 = challenge
            .iter()
            .zip(&private_commitment.mu)
            .fold(private_commitment.gamma.clone(), |acc, (e, mu_i)| {
                acc + e * mu_i
            });
        let w = elements().fold(private_commitment.beta, |acc, (e, elem)| {
            acc + e.to_scalar() * elem.b
        });

        Ok(Proof { z1, z2, z3, w })
    }

    /// Verify the proof
    pub fn verify<E: Curve>(
        aux: &Aux,
        data: PublicData<E>,
        commitment: &Commitment<E>,
        security: &SecurityParams,
        challenge: &Challenge,
        proof: &Proof<E>,
    ) -> Result<(), InvalidProof> {
        let n = data.batch.len();
        fail_if(
            InvalidProofReason::Length,
            n > 0 && challenge.len() == n && commitment.s.len() == n + 1,
        )?;
        // Range check is cheap, do it first
        fail_if(
            InvalidProofReason::RangeCheck(5),
            proof
                .z1
                .is_in_pm(&(BigInt::one() << (security.l + security.epsilon + security.t))),
        )?;

        let e_scalars: Vec<Scalar<E>> = challenge.iter().map(|e| e.to_scalar()).collect();
        // A^w g^z1 = Y · Π X_i^e_i
        {
            let lhs = data.a * proof.w + Point::<E>::generator() * proof.z1.to_scalar();
            let rhs = data
                .batch
                .iter()
                .zip(&e_scalars)
                .fold(commitment.y, |acc, (elem, e)| acc + elem.x * e);
            fail_if_ne(InvalidProofReason::EqualityCheck(2), lhs, rhs)?;
        }
        // g^w = Z · Π B_i^e_i
        {
            let lhs = Point::<E>::generator() * proof.w;
            let rhs = data
                .batch
                .iter()
                .zip(&e_scalars)
                .fold(commitment.z, |acc, (elem, e)| acc + elem.b * e);
            fail_if_ne(InvalidProofReason::EqualityCheck(3), lhs, rhs)?;
        }
        // Enc(z1, z2) = D · Π C_i^e_i
        {
            let lhs = data
                .key
                .encrypt_with(&proof.z1, &proof.z2)
                .map_err(|_| InvalidProofReason::PaillierEnc)?;
            let rhs = challenge
                .iter()
                .zip(data.batch.iter())
                .try_fold(commitment.d.clone(), |acc, (e, elem)| {
                    let c_at_e = data.key.omul(e, &elem.ciphertext)?;
                    data.key.oadd(&acc, &c_at_e)
                })
                .map_err(|_| InvalidProofReason::PaillierOp)?;
            fail_if_ne(InvalidProofReason::EqualityCheck(1), lhs, rhs)?;
        }
        // s^z1 t^z3 = S_0 · Π S_i^e_i, evaluated as s^z1 t^z3 Π S_i^-e_i = S_0
        {
            let neg_e: Vec<BigInt> = challenge.iter().map(|e| -e).collect();
            let mut pairs = Vec::with_capacity(n + 2);
            pairs.push((&aux.s, &proof.z1));
            pairs.push((&aux.t, &proof.z3));
            pairs.extend(commitment.s[1..].iter().zip(&neg_e));
            let lhs = aux.multi_pow(&pairs)?;
            fail_if_ne(InvalidProofReason::EqualityCheck(4), &lhs, &commitment.s[0])?;
        }

        Ok(())
    }

    /// Generate random challenge: `batch_size` independent integers from `[-q; q]`
    ///
    /// `security` parameter is used to generate challenge in correct range
    pub fn challenge<R: RngCore>(
        security: &SecurityParams,
        rng: &mut R,
        batch_size: usize,
    ) -> Challenge {
        (0..batch_size)
            .map(|_| BigInt::from_rng_pm(&security.q, rng))
            .collect()
    }
}

/// The non-interactive version of proof. Completed in one round, for example
/// see the documentation of parent module.
pub mod non_interactive {
    use digest::Digest;
    use generic_ec::Curve;

    use crate::{Error, InvalidProof};

    use super::{Aux, Challenge, Commitment, PrivateData, Proof, PublicData, SecurityParams};

    /// Compute proof for the given data, producing random commitment and
    /// deriving deterministic challenge.
    ///
    /// Obtained from the above interactive proof via Fiat-Shamir heuristic.
    pub fn prove<E: Curve, D: Digest>(
        shared_state: &impl udigest::Digestable,
        aux: &Aux,
        data: PublicData<E>,
        pdata: PrivateData<E>,
        security: &SecurityParams,
        rng: &mut impl rand_core::RngCore,
    ) -> Result<(Commitment<E>, Proof<E>), Error> {
        let (comm, pcomm) = super::interactive::commit(aux, data, pdata, security, rng)?;
        let challenge = challenge::<E, D>(shared_state, aux, data, &comm, security);
        let proof = super::interactive::prove(data, pdata, &pcomm, &challenge)?;
        Ok((comm, proof))
    }

    /// Verify the proof, deriving challenge independently from same data
    pub fn verify<E: Curve, D: Digest>(
        shared_state: &impl udigest::Digestable,
        aux: &Aux,
        data: PublicData<E>,
        commitment: &Commitment<E>,
        proof: &Proof<E>,
        security: &SecurityParams,
    ) -> Result<(), InvalidProof> {
        let challenge = challenge::<E, D>(shared_state, aux, data, commitment, security);
        super::interactive::verify(aux, data, commitment, security, &challenge, proof)
    }

    /// Deterministically compute challenge based on prior known values in protocol
    ///
    /// The challenge has one element per element of `data.batch`
    pub fn challenge<E: Curve, D: Digest>(
        shared_state: &impl udigest::Digestable,
        aux: &Aux,
        data: PublicData<E>,
        commitment: &Commitment<E>,
        security: &SecurityParams,
    ) -> Challenge {
        let tag = "paillier_zk.encryption_in_range_with_el_gamal.ni_challenge";
        let seed = udigest::inline_struct!(tag {
            shared_state,
            aux: aux.digest_public_data(),
            security,
            data,
            commitment,
        });
        let mut rng = rand_hash::HashRng::<D, _>::from_seed(seed);
        super::interactive::challenge(security, &mut rng, data.batch.len())
    }
}

#[cfg(test)]
mod test {
    use generic_ec::{Curve, Point, Scalar};
    use num_bigint::BigInt;

    use crate::common::{BigIntExt, InvalidProofReason};

    type D = sha2::Sha256;
    type E = generic_ec::curves::Secp256r1;

    /// cggmp21 `SecurityLevel128`
    fn security() -> super::SecurityParams {
        super::SecurityParams {
            l: 256,
            epsilon: 230,
            q: BigInt::from(1) << 128_u32,
            t: 128,
        }
    }

    struct Setup<C: Curve> {
        aux: super::Aux,
        key: fast_paillier::DecryptionKey,
        a_point: Point<C>,
        plaintexts: Vec<BigInt>,
        nonces: Vec<BigInt>,
        bs: Vec<Scalar<C>>,
        batch: Vec<super::PublicElement<C>>,
    }

    impl<C: Curve> Setup<C> {
        fn new(plaintexts: Vec<BigInt>) -> Self {
            let mut rng = rand_dev::DevRng::new();
            let key = crate::common::test::sample_key();
            let a = Scalar::<C>::random(&mut rng);
            let mut nonces = vec![];
            let mut bs = vec![];
            let mut batch = vec![];
            for x in &plaintexts {
                let (ciphertext, nonce) = key.encrypt_with_random(&mut rng, x).unwrap();
                let b = Scalar::<C>::random(&mut rng);
                batch.push(super::PublicElement {
                    ciphertext,
                    b: Point::generator() * b,
                    x: Point::generator() * (a * b + x.to_scalar::<C>()),
                });
                nonces.push(nonce);
                bs.push(b);
            }
            Self {
                aux: crate::common::test::aux(&mut rng),
                key,
                a_point: Point::generator() * a,
                plaintexts,
                nonces,
                bs,
                batch,
            }
        }
        fn data<'a>(&'a self, batch: &'a Vec<super::PublicElement<C>>) -> super::PublicData<'a, C> {
            super::PublicData {
                key: self.key.encryption_key(),
                batch,
                a: &self.a_point,
            }
        }
        fn prove(&self) -> (super::Commitment<C>, super::Proof<C>) {
            let mut rng = rand_dev::DevRng::new();
            let private: Vec<_> = (0..self.plaintexts.len())
                .map(|i| super::PrivateElement {
                    plaintext: &self.plaintexts[i],
                    nonce: &self.nonces[i],
                    b: &self.bs[i],
                })
                .collect();
            // The prover encrypts under its own key
            let data = super::PublicData {
                key: &self.key,
                batch: &self.batch,
                a: &self.a_point,
            };
            super::non_interactive::prove::<C, D>(
                &"shared state",
                &self.aux,
                data,
                super::PrivateData { batch: &private },
                &security(),
                &mut rng,
            )
            .unwrap()
        }
        fn verify_with(
            &self,
            data: super::PublicData<C>,
            commitment: &super::Commitment<C>,
            proof: &super::Proof<C>,
        ) -> Result<(), InvalidProofReason> {
            super::non_interactive::verify::<C, D>(
                &"shared state",
                &self.aux,
                data,
                commitment,
                proof,
                &security(),
            )
            .map_err(|e| e.reason())
        }
        fn verify(
            &self,
            commitment: &super::Commitment<C>,
            proof: &super::Proof<C>,
        ) -> Result<(), InvalidProofReason> {
            self.verify_with(self.data(&self.batch), commitment, proof)
        }
    }

    fn in_range(n: usize) -> Vec<BigInt> {
        let mut rng = rand_dev::DevRng::new();
        (0..n)
            .map(|_| BigInt::from_rng_pm(&(BigInt::from(1) << security().l), &mut rng))
            .collect()
    }

    fn passing_test<C: Curve>() {
        let setup = Setup::<C>::new(in_range(2));
        let (commitment, proof) = setup.prove();
        setup.verify(&commitment, &proof).unwrap();
        let fast_aux = crate::common::test::with_optimizations(&setup.aux);
        super::non_interactive::verify::<C, D>(
            &"shared state",
            &fast_aux,
            setup.data(&setup.batch),
            &commitment,
            &proof,
            &security(),
        )
        .unwrap();
    }

    #[test]
    fn passing_p256() {
        passing_test::<E>()
    }
    #[test]
    fn passing_million() {
        passing_test::<crate::curve::C>()
    }
    #[test]
    fn passing_single_and_larger_batches() {
        for n in [1, 3] {
            let setup = Setup::<E>::new(in_range(n));
            let (commitment, proof) = setup.prove();
            setup.verify(&commitment, &proof).unwrap();
        }
    }

    #[test]
    fn failing_out_of_range() {
        let s = security();
        let mut rng = rand_dev::DevRng::new();
        let big = BigInt::from_rng_pm(&(BigInt::from(1) << (s.l + s.epsilon + s.t + 4)), &mut rng)
            + (BigInt::from(1) << (s.l + s.epsilon + s.t + 4));
        let setup = Setup::<E>::new(vec![big.clone(), big]);
        let (commitment, proof) = setup.prove();
        assert_eq!(
            setup.verify(&commitment, &proof),
            Err(InvalidProofReason::RangeCheck(5))
        );
    }

    /// `k` is out of range but offset by `γ` so that `k + γ` is in range. Would pass with a
    /// challenge shared by all elements.
    #[test]
    fn failing_on_offset_plaintexts() {
        let s = security();
        let offset = BigInt::from(1) << (s.l + s.epsilon + s.t + 10);
        let small = in_range(2);
        let setup = Setup::<E>::new(vec![&small[0] + &offset, &small[1] - &offset]);
        let (commitment, proof) = setup.prove();
        assert_eq!(
            setup.verify(&commitment, &proof),
            Err(InvalidProofReason::RangeCheck(5))
        );
    }

    #[test]
    fn fiat_shamir_binds_statement_and_commitment() {
        let setup = Setup::<E>::new(in_range(2));
        let (commitment, proof) = setup.prove();

        for i in 0..4 {
            let mut batch = setup.batch.clone();
            match i {
                0 => batch[0].ciphertext += 1,
                1 => batch[1].b += Point::generator(),
                2 => batch[0].x += Point::generator(),
                _ => batch.swap(0, 1),
            }
            assert!(
                setup
                    .verify_with(setup.data(&batch), &commitment, &proof)
                    .is_err(),
                "statement tamper {i}"
            );
        }
        let other_a = setup.a_point + Point::generator();
        let data = super::PublicData {
            a: &other_a,
            ..setup.data(&setup.batch)
        };
        assert!(setup.verify_with(data, &commitment, &proof).is_err());
        let other_key = crate::common::test::sample_other_key();
        let data = super::PublicData {
            key: &other_key,
            ..setup.data(&setup.batch)
        };
        assert!(setup.verify_with(data, &commitment, &proof).is_err());

        for i in 0..5 {
            let mut bad = commitment.clone();
            match i {
                0 => bad.s[0] += 1,
                1 => bad.s[2] += 1,
                2 => bad.d += 1,
                3 => bad.y += Point::generator(),
                _ => bad.z += Point::generator(),
            }
            assert!(setup.verify(&bad, &proof).is_err(), "commitment tamper {i}");
        }
        for i in 0..4 {
            let mut bad = proof.clone();
            match i {
                0 => bad.z1 += 1,
                1 => bad.z2 += 1,
                2 => bad.z3 += 1,
                _ => bad.w += Scalar::one(),
            }
            assert!(setup.verify(&commitment, &bad).is_err(), "proof tamper {i}");
        }
    }

    #[test]
    fn wrong_lengths_are_rejected_without_panic() {
        let setup = Setup::<E>::new(in_range(2));
        let (commitment, proof) = setup.prove();

        for s_len in [0, 1, 2, 4] {
            let mut bad = commitment.clone();
            bad.s.resize(s_len, BigInt::from(1));
            assert_eq!(setup.verify(&bad, &proof), Err(InvalidProofReason::Length));
        }
        let mut batch = setup.batch.clone();
        batch.push(batch[0].clone());
        assert_eq!(
            setup.verify_with(setup.data(&batch), &commitment, &proof),
            Err(InvalidProofReason::Length)
        );
        let batch = vec![];
        assert_eq!(
            setup.verify_with(setup.data(&batch), &commitment, &proof),
            Err(InvalidProofReason::Length)
        );
        let challenge = vec![BigInt::from(1)];
        assert!(super::interactive::verify(
            &setup.aux,
            setup.data(&setup.batch),
            &commitment,
            &security(),
            &challenge,
            &proof
        )
        .is_err());
    }

    #[test]
    fn malformed_values_are_rejected_without_panic() {
        let setup = Setup::<E>::new(in_range(2));
        let (commitment, proof) = setup.prove();
        let n = setup.key.n().clone();

        for value in [
            BigInt::from(0),
            BigInt::from(-1),
            setup.aux.rsa_modulo.clone(),
        ] {
            let mut bad = commitment.clone();
            bad.s = vec![value.clone(); 3];
            assert!(setup.verify(&bad, &proof).is_err());
        }
        for value in [BigInt::from(0), BigInt::from(-1), n.clone(), &n * &n * 2] {
            let mut bad = commitment.clone();
            bad.d = value.clone();
            assert!(setup.verify(&bad, &proof).is_err());
            let mut batch = setup.batch.clone();
            batch[1].ciphertext = value;
            assert!(setup
                .verify_with(setup.data(&batch), &commitment, &proof)
                .is_err());
        }
        let mut bad = proof.clone();
        bad.z2 = -bad.z2.clone();
        assert!(setup.verify(&commitment, &bad).is_err());
    }
}
