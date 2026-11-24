//! ZK-proof of paillier encryption in range. Called Пenc or Renc in the CGGMP21
//! paper.
//!
//! ## Description
//!
//! A party P has `key`, `pkey` - public and private keys in paillier
//! cryptosystem. P also has `plaintext`, `nonce`, and
//! `ciphertext = key.encrypt_with(plaintext, nonce)`.
//!
//! P wants to prove that `plaintext` is at most `l` bits, without disclosing
//! it, the `pkey`, and `nonce`

//! ## Example
//!
//! ```
//! use paillier_zk::{paillier_encryption_in_range as p, BigIntExt};
//! use num_bigint::BigInt;
//! # mod pregenerated {
//! #     use super::*;
//! #     paillier_zk::load_pregenerated_data!(
//! #         verifier_aux: p::Aux,
//! #         prover_decryption_key: fast_paillier::DecryptionKey,
//! #     );
//! # }
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//!
//! let shared_state = "some shared state";
//!
//! let mut rng = rand_core::OsRng;
//! # let mut rng = rand_dev::DevRng::new();
//!
//! // 0. Setup: prover and verifier share common Ring-Pedersen parameters:
//!
//! let aux: p::Aux = pregenerated::verifier_aux();
//! let security = p::SecurityParams {
//!     l: 1024,
//!     epsilon: 128,
//!     q: BigInt::from(1) << 128_u32,
//! };
//!
//! // 1. Setup: prover prepares the paillier keys
//!
//! let private_key: fast_paillier::DecryptionKey =
//!     pregenerated::prover_decryption_key();
//! let key = private_key.encryption_key();
//!
//! // 2. Setup: prover has some plaintext and encrypts it
//!
//! let plaintext = BigInt::from_rng_pm(&(BigInt::from(1) << security.l), &mut rng);
//! let (ciphertext, nonce) = key.encrypt_with_random(&mut rng, &plaintext)?;
//!
//! // 3. Prover computes a non-interactive proof that plaintext is at most 1024 bits:
//!
//! let data = p::Data { key, ciphertext: &ciphertext };
//! let (commitment, proof) = p::non_interactive::prove::<sha2::Sha256>(
//!     &shared_state,
//!     &aux,
//!     data,
//!     p::PrivateData {
//!         plaintext: &plaintext,
//!         nonce: &nonce,
//!     },
//!     &security,
//!     &mut rng,
//! )?;
//!
//! // 4. Prover sends this data to verifier
//!
//! # fn send(_: &p::Data, _: &p::Commitment, _: &p::Proof) {  }
//! send(&data, &commitment, &proof);
//!
//! // 5. Verifier receives the data and the proof and verifies it
//!
//! # let recv = || (data, commitment, proof);
//! let (data, commitment, proof) = recv();
//! p::non_interactive::verify::<sha2::Sha256>(
//!     &shared_state,
//!     &aux,
//!     data,
//!     &commitment,
//!     &security,
//!     &proof,
//! )?;
//! # Ok(()) }
//! ```
//!
//! If the verification succeeded, verifier can continue communication with prover

#[cfg(feature = "serde")]
use fast_paillier::utils::serde_wrapper::serializable_bigint;
use fast_paillier::{AnyEncryptionKey, Ciphertext, Nonce};
use num_bigint::BigInt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub use crate::common::Aux;
pub use crate::common::InvalidProof;

/// Security parameters for proof. Choosing the values is a tradeoff between
/// speed and chance of rejecting a valid proof or accepting an invalid proof
#[derive(Debug, Clone, udigest::Digestable)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SecurityParams {
    /// l in paper, security parameter for bit size of plaintext: it needs to
    /// be in range [-2^l; 2^l] or equivalently 2^l
    pub l: usize,
    /// Epsilon in paper, slackness parameter
    pub epsilon: usize,
    /// q in paper. Security parameter for challenge
    #[udigest(as = crate::common::encoding::BigInt)]
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub q: BigInt,
}

/// Public data that both parties know
#[derive(Debug, Clone, Copy, udigest::Digestable)]
pub struct Data<'a> {
    /// N0 in paper, public key that k -> K was encrypted on
    #[udigest(as = crate::common::encoding::AnyEncryptionKey)]
    pub key: &'a dyn AnyEncryptionKey,
    /// K in paper
    #[udigest(as = &crate::common::encoding::BigInt)]
    pub ciphertext: &'a Ciphertext,
}

/// Private data of prover
#[derive(Clone, Copy)]
pub struct PrivateData<'a> {
    /// k in paper, plaintext of K
    pub plaintext: &'a BigInt,
    /// rho in paper, nonce of encryption k -> K
    pub nonce: &'a Nonce,
}

// As described in cggmp21 at page 33
/// Prover's first message, obtained by [`interactive::commit`]
#[derive(Debug, Clone, udigest::Digestable)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Commitment {
    #[udigest(as = crate::common::encoding::BigInt)]
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub s: BigInt,
    #[udigest(as = crate::common::encoding::BigInt)]
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub a: BigInt,
    #[udigest(as = crate::common::encoding::BigInt)]
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub c: BigInt,
}

/// Prover's data accompanying the commitment. Kept as state between rounds in
/// the interactive protocol.
#[derive(Clone)]
pub struct PrivateCommitment {
    pub alpha: BigInt,
    pub mu: BigInt,
    pub r: BigInt,
    pub gamma: BigInt,
}

/// Verifier's challenge to prover. Can be obtained deterministically by
/// [`non_interactive::challenge`] or randomly by [`interactive::challenge`]
pub type Challenge = BigInt;

// As described in cggmp21 at page 33
/// The ZK proof. Computed by [`interactive::prove`] or
/// [`non_interactive::prove`]
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Proof {
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub z1: BigInt,
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub z2: BigInt,
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub z3: BigInt,
}

/// The interactive version of the ZK proof. Should be completed in 3 rounds:
/// prover commits to data, verifier responds with a random challenge, and
/// prover gives proof with commitment and challenge.
pub mod interactive {
    use crate::common::{BigIntExt, InvalidProof};
    use crate::{
        common::{fail_if, fail_if_ne, InvalidProofReason},
        Error,
    };
    use num_bigint::BigInt;
    use num_integer::Integer;
    use num_traits::One;
    use rand_core::RngCore;

    use super::{
        Aux, Challenge, Commitment, Data, PrivateCommitment, PrivateData, Proof, SecurityParams,
    };

    /// Create random commitment
    pub fn commit<R: RngCore>(
        aux: &Aux,
        data: Data,
        pdata: PrivateData,
        security: &SecurityParams,
        rng: &mut R,
    ) -> Result<(Commitment, PrivateCommitment), Error> {
        let two_to_l_plus_e = BigInt::from(1) << (security.l + security.epsilon);
        let hat_n_at_two_to_l = (BigInt::from(1) << security.l) * &aux.rsa_modulo;
        let hat_n_at_two_to_l_plus_e = &two_to_l_plus_e * &aux.rsa_modulo;

        let alpha = BigInt::from_rng_pm(&two_to_l_plus_e, rng);
        let mu = BigInt::from_rng_pm(&hat_n_at_two_to_l, rng);
        let gamma = BigInt::from_rng_pm(&hat_n_at_two_to_l_plus_e, rng);
        // The nonce enters the ciphertext as `h^(N * nonce)`, so the response `z2 = r + e nonce`
        // is computed over the integers. `|e nonce| < 2^(nonce_bits + |q|)`, a mask of
        // `nonce_bits + |q| + ε` bits hides it with statistical distance `2^-ε`.
        let nonce_bits = u64::from(data.key.nounce_size()).max(pdata.nonce.bits());
        let r_bits = nonce_bits + security.q.bits() + security.epsilon as u64;
        let r = BigInt::from_rng_pm(&(BigInt::one() << r_bits), rng);

        let s = aux.combine(pdata.plaintext, &mu)?;
        let a = data.key.encrypt_with(&alpha, &r)?;
        let c = aux.combine(&alpha, &gamma)?;

        Ok((
            Commitment { s, a, c },
            PrivateCommitment {
                alpha,
                mu,
                r,
                gamma,
            },
        ))
    }

    /// Compute proof for given data and prior protocol values
    pub fn prove(
        _data: Data,
        pdata: PrivateData,
        private_commitment: &PrivateCommitment,
        challenge: &Challenge,
    ) -> Result<Proof, Error> {
        let z1 = &private_commitment.alpha + (challenge * pdata.plaintext);
        let z2 = &private_commitment.r + (challenge * pdata.nonce);
        let z3 = &private_commitment.gamma + (challenge * &private_commitment.mu);
        Ok(Proof { z1, z2, z3 })
    }

    /// Verify the proof
    pub fn verify(
        aux: &Aux,
        data: Data,
        commitment: &Commitment,
        security: &SecurityParams,
        challenge: &Challenge,
        proof: &Proof,
    ) -> Result<(), InvalidProof> {
        fail_if(
            InvalidProofReason::RangeCheck(4),
            proof
                .z1
                .is_in_pm(&(BigInt::from(1) << (security.l + security.epsilon))),
        )?;
        fail_if_ne(
            InvalidProofReason::EqualityCheck(1),
            data.ciphertext.gcd(data.key.n()),
            BigInt::one(),
        )?;
        {
            let lhs = data
                .key
                .encrypt_with(&proof.z1, &proof.z2)
                .map_err(|_| InvalidProofReason::PaillierEnc)?;
            let rhs = {
                let e_at_k = data
                    .key
                    .omul(challenge, data.ciphertext)
                    .map_err(|_| InvalidProofReason::PaillierOp)?;
                data.key
                    .oadd(&commitment.a, &e_at_k)
                    .map_err(|_| InvalidProofReason::PaillierOp)?
            };
            fail_if_ne(InvalidProofReason::EqualityCheck(2), lhs, rhs)?;
        }
        {
            // s^z1 t^z3 = C S^e, evaluated as s^z1 t^z3 S^-e = C
            let neg_e = -challenge;
            let lhs = aux.multi_pow(&[
                (&aux.s, &proof.z1),
                (&aux.t, &proof.z3),
                (&commitment.s, &neg_e),
            ])?;
            fail_if_ne(InvalidProofReason::EqualityCheck(3), &lhs, &commitment.c)?;
        }

        Ok(())
    }

    /// Generate random challenge
    ///
    /// `security` parameter is used to generate challenge in correct range
    pub fn challenge<R: RngCore>(security: &SecurityParams, rng: &mut R) -> Challenge {
        BigInt::from_rng_pm(&security.q, rng)
    }
}

/// The non-interactive version of proof. Completed in one round, for example
/// see the documentation of parent module.
pub mod non_interactive {
    use digest::Digest;

    use crate::{Error, InvalidProof};

    use super::{Aux, Challenge, Commitment, Data, PrivateData, Proof, SecurityParams};

    /// Compute proof for the given data, producing random commitment and
    /// deriving determenistic challenge.
    ///
    /// Obtained from the above interactive proof via Fiat-Shamir heuristic.
    pub fn prove<D: Digest>(
        shared_state: &impl udigest::Digestable,
        aux: &Aux,
        data: Data,
        pdata: PrivateData,
        security: &SecurityParams,
        rng: &mut impl rand_core::RngCore,
    ) -> Result<(Commitment, Proof), Error> {
        let (comm, pcomm) = super::interactive::commit(aux, data, pdata, security, rng)?;
        let challenge = challenge::<D>(shared_state, aux, data, &comm, security);
        let proof = super::interactive::prove(data, pdata, &pcomm, &challenge)?;
        Ok((comm, proof))
    }

    /// Deterministically compute challenge based on prior known values in protocol
    pub fn challenge<D: Digest>(
        shared_state: &impl udigest::Digestable,
        aux: &Aux,
        data: Data,
        commitment: &Commitment,
        security: &SecurityParams,
    ) -> Challenge {
        let tag = "paillier_zk.encryption_in_range.ni_challenge";
        let seed = udigest::inline_struct!(tag {
            shared_state,
            aux: aux.digest_public_data(),
            security,
            data,
            commitment,
        });
        let mut rng = rand_hash::HashRng::<D, _>::from_seed(seed);
        super::interactive::challenge(security, &mut rng)
    }

    /// Verify the proof, deriving challenge independently from same data
    pub fn verify<D: Digest>(
        shared_state: &impl udigest::Digestable,
        aux: &Aux,
        data: Data,
        commitment: &Commitment,
        security: &SecurityParams,
        proof: &Proof,
    ) -> Result<(), InvalidProof> {
        let challenge = challenge::<D>(shared_state, aux, data, commitment, security);
        super::interactive::verify(aux, data, commitment, security, &challenge, proof)
    }
}

#[cfg(test)]
mod test {
    use num_bigint::BigInt;

    use crate::common::{BigIntExt, InvalidProofReason};

    type D = sha2::Sha256;

    fn security() -> super::SecurityParams {
        super::SecurityParams {
            l: 1024,
            epsilon: 256,
            q: (BigInt::from(1) << 128_u32) - 1,
        }
    }

    struct Setup {
        aux: super::Aux,
        key: fast_paillier::DecryptionKey,
        plaintext: BigInt,
        ciphertext: BigInt,
        nonce: BigInt,
    }

    impl Setup {
        fn new(plaintext: BigInt) -> Self {
            let mut rng = rand_dev::DevRng::new();
            let aux = crate::common::test::aux(&mut rng);
            let key = crate::common::test::sample_key();
            let (ciphertext, nonce) = key
                .encryption_key()
                .encrypt_with_random(&mut rng, &plaintext)
                .unwrap();
            Self {
                aux,
                key,
                plaintext,
                ciphertext,
                nonce,
            }
        }
        fn data(&self) -> super::Data<'_> {
            super::Data {
                key: self.key.encryption_key(),
                ciphertext: &self.ciphertext,
            }
        }
        fn prove(&self) -> (super::Commitment, super::Proof) {
            let mut rng = rand_dev::DevRng::new();
            let pdata = super::PrivateData {
                plaintext: &self.plaintext,
                nonce: &self.nonce,
            };
            super::non_interactive::prove::<D>(
                &"shared state",
                &self.aux,
                self.data(),
                pdata,
                &security(),
                &mut rng,
            )
            .unwrap()
        }
        fn verify(
            &self,
            data: super::Data,
            commitment: &super::Commitment,
            proof: &super::Proof,
        ) -> Result<(), InvalidProofReason> {
            super::non_interactive::verify::<D>(
                &"shared state",
                &self.aux,
                data,
                commitment,
                &security(),
                proof,
            )
            .map_err(|e| e.reason())
        }
    }

    #[test]
    fn passing() {
        let mut rng = rand_dev::DevRng::new();
        let plaintext = BigInt::from_rng_pm(&(BigInt::from(1) << security().l), &mut rng);
        let setup = Setup::new(plaintext);
        let (commitment, proof) = setup.prove();
        setup.verify(setup.data(), &commitment, &proof).unwrap();

        let fast_aux = crate::common::test::with_optimizations(&setup.aux);
        super::non_interactive::verify::<D>(
            &"shared state",
            &fast_aux,
            setup.data(),
            &commitment,
            &security(),
            &proof,
        )
        .unwrap();
    }

    #[test]
    fn failing() {
        let s = security();
        let plaintext = (BigInt::from(1) << (s.l + s.epsilon)) + 1;
        let setup = Setup::new(plaintext);
        let (commitment, proof) = setup.prove();
        assert!(matches!(
            setup.verify(setup.data(), &commitment, &proof),
            Err(InvalidProofReason::RangeCheck(_))
        ));
    }

    #[test]
    fn tampering_is_rejected() {
        let mut rng = rand_dev::DevRng::new();
        let plaintext = BigInt::from_rng_pm(&(BigInt::from(1) << security().l), &mut rng);
        let setup = Setup::new(plaintext);
        let (commitment, proof) = setup.prove();

        // Statement: other ciphertext and other key
        let other_ct = setup
            .key
            .encryption_key()
            .omul(&BigInt::from(2), &setup.ciphertext)
            .unwrap();
        let data = super::Data {
            key: setup.key.encryption_key(),
            ciphertext: &other_ct,
        };
        assert!(setup.verify(data, &commitment, &proof).is_err());
        let other_key = crate::common::test::sample_other_key();
        let data = super::Data {
            key: &other_key,
            ciphertext: &setup.ciphertext,
        };
        assert!(setup.verify(data, &commitment, &proof).is_err());

        // Commitment
        for i in 0..3 {
            let mut bad = commitment.clone();
            match i {
                0 => bad.s += 1,
                1 => bad.a += 1,
                _ => bad.c = BigInt::from(0),
            }
            assert!(setup.verify(setup.data(), &bad, &proof).is_err());
        }
        let mut bad = commitment.clone();
        bad.s = BigInt::from(0);
        assert!(setup.verify(setup.data(), &bad, &proof).is_err());

        // Proof
        for i in 0..3 {
            let mut bad = proof.clone();
            match i {
                0 => bad.z1 += 1,
                1 => bad.z2 += 1,
                _ => bad.z3 += 1,
            }
            assert!(setup.verify(setup.data(), &commitment, &bad).is_err());
        }

        // Malformed ciphertext
        let n = setup.key.n().clone();
        for ct in [BigInt::from(0), n.clone(), -BigInt::from(1), &n * &n * 3] {
            let data = super::Data {
                key: setup.key.encryption_key(),
                ciphertext: &ct,
            };
            assert!(setup.verify(data, &commitment, &proof).is_err());
        }
    }
}
