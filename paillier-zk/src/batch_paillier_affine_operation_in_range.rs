//! Zero-knowledge proof of a Paillier affine operation with range bounds and group commitment.
//!
//! This module implements a batched version of the Π_aff-g protocol (called Raff-g in the CGGMP21 paper).
//! It allows a prover to efficiently prove knowledge of multiple plaintexts `x_i`, `y_i` used in encrypted
//! affine computations of the form:
//!
//! ```text
//!     D_i = C_i * x_i + Enc(y_i)
//! ```
//!
//! where:
//! - `C_i` is an encrypted value under public key `key0`,
//! - `Y_i = Enc_key1(y_i)` is `y_i` encrypted under a separate key `key1`,
//! - `X_i = g * x_i` is a group commitment to `x_i` using generator `g` of a group of order `q`,
//! - `D_i` is computed using Paillier homomorphic operations on `C_i` and `Enc_key0(y_i)`.
//!
//! The goal is to prove in zero-knowledge that all `x_i` and `y_i` are within known bitlength bounds (`l_x`, `l_y`),
//! without revealing their values.
//!
//! ## Batched Proof
//!
//! Every element of the batch gets its own commitment (`s_i`, `e_i`, `t_i`, `b_x_i`) and its own,
//! independently sampled, challenge `e_i`. The equations that involve `y_i` are aggregated:
//! `z2 = β + Σ e_i y_i`, `w = r + Σ e_i ρ_i`, `w_y = r_y + Σ e_i ρ_y_i`, `z4 = δ + Σ e_i μ_i`.
//! Since the challenges are independent, rewinding a single `e_j` extracts `x_j` and `y_j`
//! individually, so the proof implies a range bound for every element, not just for their sum.
//!
//! ## Proves
//!
//! For each i-th element in the batch:
//! - `|x_i| < 2^(l_x + ε + t)`
//! - `|y_i| < 2^(l_y + ε + t)`
//!
//! given that the prover knows `|x_i| < 2^l_x`, `|y_i| < 2^l_y`. The challenges are sampled from
//! `[-q; q]`, the security parameters must satisfy `q <= 2^t`.
//!
//! ## Zero-knowledge
//!
//! Every mask hides a term `e_i * secret` with `|e_i| <= 2^t`: a mask uniform in
//! `[-2^(k + t + ε); 2^(k + t + ε)]` hides a value of at most `k + t` bits with statistical
//! distance `2^-ε`, aggregated responses with `n` terms have distance at most `n * 2^-ε`:
//! - `α_i ← ±2^(l_x+ε+t)` for `z1_i = α_i + e_i x_i`, `γ_i ← ±2^(l_x+ε+t)·N̂` for `z3_i = γ_i + e_i m_i` (`m_i ← ±2^l_x·N̂`)
//! - `β ← ±2^(l_y+ε+t)` for `z2`, `δ ← ±2^(l_y+ε+t)·N̂` for `z4` (`μ_i ← ±2^l_y·N̂`)
//! - `r ← ±2^(b0+t+ε)` for `w`, where `b0` is the size of the largest nonce used with `key0`
//!   (at least `key0.nounce_size()`); `r_y` likewise for `key1`. The forked Paillier encrypts as
//!   `(1+N)^x · (h^N)^ρ mod N²`, so nonce responses are computed over the integers.
#[cfg(feature = "serde")]
use fast_paillier::utils::serde_wrapper::{serializable_bigint, serializable_vec_bigint};
use fast_paillier::{AnyEncryptionKey, Ciphertext, Nonce};
use generic_ec::{Curve, Point};
use num_bigint::BigInt;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::common::encoding;
pub use crate::common::{Aux, InvalidProof};

/// Security parameters for proof. Choosing the values is a tradeoff between
/// speed and chance of rejecting a valid proof or accepting an invalid proof
#[derive(Debug, Clone, udigest::Digestable)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SecurityParams {
    /// l in paper, bit size of +-x
    pub l_x: usize,
    /// l' in paper, bit size of +-y
    pub l_y: usize,
    /// Epsilon in paper, slackness parameter
    pub epsilon: usize,
    /// q in paper. Security parameter for challenge, challenges are sampled from `[-q; q]`
    #[udigest(as = encoding::BigInt)]
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub q: BigInt,
    /// Size of challenge in bits, `q <= 2^t`
    pub t: usize,
}

/// Public statement of a single element in the batch
#[derive(Debug, Clone, udigest::Digestable)]
#[udigest(bound = "")]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct PublicElement<C: Curve> {
    /// `C_i`, ciphertext under `key0`
    #[udigest(as = encoding::BigInt)]
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub c: Ciphertext,
    /// `X_i = g^x_i`
    pub x: Point<C>,
    /// `D_i = C_i^x_i · Enc_key0(y_i)`
    #[udigest(as = encoding::BigInt)]
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub d: Ciphertext,
    /// `Y_i = Enc_key1(y_i)`
    #[udigest(as = encoding::BigInt)]
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub y: Ciphertext,
}

/// Public data that both parties know
#[derive(Debug, Clone, udigest::Digestable)]
#[udigest(bound = "")]
pub struct PublicData<'a, C: Curve> {
    /// N0 in paper, public key that C was encrypted on
    #[udigest(as = encoding::AnyEncryptionKey)]
    pub key0: &'a dyn AnyEncryptionKey,
    /// N1 in paper, public key that y -> Y was encrypted on
    #[udigest(as = encoding::AnyEncryptionKey)]
    pub key1: &'a dyn AnyEncryptionKey,
    /// Statements, batch size is `batch.len()`
    pub batch: Vec<PublicElement<C>>,
}

/// Secret witness of a single element in the batch
#[derive(Debug, Clone)]
pub struct PrivateElement<'a> {
    pub x: &'a BigInt,
    pub y: &'a BigInt,
    /// Nonce of `Enc_key0(y)`
    pub nonce: &'a Nonce,
    /// Nonce of `Enc_key1(y)`
    pub nonce_y: &'a Nonce,
}

/// Private data of prover
#[derive(Debug, Clone)]
pub struct PrivateData<'a> {
    pub batch: Vec<PrivateElement<'a>>,
}

/// Prover's first message, obtained by [`interactive::commit`]
#[derive(Debug, Clone, udigest::Digestable)]
#[udigest(bound = "")]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct Commitment<C: Curve> {
    /// `A = Enc_key0(β, r) · Π C_i^α_i`
    #[udigest(as = encoding::BigInt)]
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub a: Ciphertext,
    /// `S_i = s^x_i t^m_i`
    #[udigest(as = Vec<encoding::BigInt>)]
    #[cfg_attr(feature = "serde", serde(with = "serializable_vec_bigint"))]
    pub s: Vec<BigInt>,
    /// `E_i = s^α_i t^γ_i`
    #[udigest(as = Vec<encoding::BigInt>)]
    #[cfg_attr(feature = "serde", serde(with = "serializable_vec_bigint"))]
    pub e: Vec<BigInt>,
    /// `F = s^β t^δ`
    #[udigest(as = encoding::BigInt)]
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub f: BigInt,
    /// `T_i = s^y_i t^μ_i`
    #[udigest(as = Vec<encoding::BigInt>)]
    #[cfg_attr(feature = "serde", serde(with = "serializable_vec_bigint"))]
    pub t: Vec<BigInt>,
    /// `B_x_i = g^α_i`
    pub b_x: Vec<Point<C>>,
    /// `B_y = Enc_key1(β, r_y)`
    #[udigest(as = encoding::BigInt)]
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub b_y: BigInt,
}

/// Prover's data accompanying the commitment. Kept as state between rounds in
/// the interactive protocol.
#[derive(Clone)]
pub struct PrivateCommitment {
    pub m: Vec<BigInt>,
    pub mu: Vec<BigInt>,
    pub alpha: Vec<BigInt>,
    pub gamma: Vec<BigInt>,
    pub beta: BigInt,
    pub r: BigInt,
    pub delta: BigInt,
    pub r_y: BigInt,
}

/// Verifier's challenge to prover: one independent challenge per batch element. Can be obtained
/// deterministically by [`non_interactive::challenge`] or randomly by [`interactive::challenge`]
pub type Challenge = Vec<BigInt>;

/// The ZK proof. Computed by [`interactive::prove`] or
/// [`non_interactive::prove`]
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Proof {
    #[cfg_attr(feature = "serde", serde(with = "serializable_vec_bigint"))]
    pub z1: Vec<BigInt>,
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub z2: BigInt,
    #[cfg_attr(feature = "serde", serde(with = "serializable_vec_bigint"))]
    pub z3: Vec<BigInt>,
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub z4: BigInt,
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub w: BigInt,
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    pub w_y: BigInt,
}

/// The interactive version of the ZK proof. Should be completed in 3 rounds:
/// prover commits to data, verifier responds with a random challenge, and
/// prover gives proof with commitment and challenge.
pub mod interactive {
    use generic_ec::{Curve, Point};
    use num_bigint::BigInt;
    use num_traits::One;
    use rand_core::RngCore;

    use super::*;
    use crate::common::{fail_if, fail_if_ne, BigIntExt, InvalidProof, InvalidProofReason};
    use crate::{Error, ErrorReason};

    /// Create random commitment
    pub fn commit<C: Curve, R: RngCore>(
        aux: &Aux,
        data: PublicData<C>,
        pdata: PrivateData,
        security: &SecurityParams,
        mut rng: R,
    ) -> Result<(Commitment<C>, PrivateCommitment), Error> {
        commit_ref(aux, &data, &pdata, security, &mut rng)
    }

    /// Bit size of the mask for the aggregated nonce response, see module docs
    fn nonce_mask_bits<'a>(
        key: &dyn AnyEncryptionKey,
        nonces: impl Iterator<Item = &'a BigInt>,
        security: &SecurityParams,
    ) -> u64 {
        let nonce_bits = nonces
            .map(BigInt::bits)
            .fold(u64::from(key.nounce_size()), u64::max);
        nonce_bits + (security.t + security.epsilon) as u64
    }

    pub(super) fn commit_ref<C: Curve>(
        aux: &Aux,
        data: &PublicData<C>,
        pdata: &PrivateData,
        security: &SecurityParams,
        rng: &mut impl RngCore,
    ) -> Result<(Commitment<C>, PrivateCommitment), Error> {
        let n = data.batch.len();
        if n == 0 || pdata.batch.len() != n {
            return Err(ErrorReason::Length.into());
        }
        let pow2 = |bits: usize| BigInt::one() << bits;
        let two_to_l_x = pow2(security.l_x);
        let two_to_l_y = pow2(security.l_y);
        let two_to_l_x_e_t = pow2(security.l_x + security.epsilon + security.t);
        let two_to_l_y_e_t = pow2(security.l_y + security.epsilon + security.t);
        let hat_n = &aux.rsa_modulo;
        let hat_n_at_two_to_l_x = hat_n * &two_to_l_x;
        let hat_n_at_two_to_l_y = hat_n * &two_to_l_y;
        let hat_n_at_two_to_l_x_e_t = hat_n * &two_to_l_x_e_t;
        let hat_n_at_two_to_l_y_e_t = hat_n * &two_to_l_y_e_t;

        // Fresh masks for every element
        let mut sample = |range: &BigInt| -> Vec<BigInt> {
            (0..n).map(|_| BigInt::from_rng_pm(range, rng)).collect()
        };
        let m = sample(&hat_n_at_two_to_l_x);
        let mu = sample(&hat_n_at_two_to_l_y);
        let alpha = sample(&two_to_l_x_e_t);
        let gamma = sample(&hat_n_at_two_to_l_x_e_t);
        let beta = BigInt::from_rng_pm(&two_to_l_y_e_t, rng);
        let delta = BigInt::from_rng_pm(&hat_n_at_two_to_l_y_e_t, rng);
        let r_bits = nonce_mask_bits(data.key0, pdata.batch.iter().map(|e| e.nonce), security);
        let r = BigInt::from_rng_pm(&pow2(r_bits as usize), rng);
        let r_y_bits = nonce_mask_bits(data.key1, pdata.batch.iter().map(|e| e.nonce_y), security);
        let r_y = BigInt::from_rng_pm(&pow2(r_y_bits as usize), rng);

        // A = Enc_key0(β, r) · Π C_i^α_i
        let a = data.batch.iter().zip(&alpha).try_fold(
            data.key0.encrypt_with(&beta, &r)?,
            |acc, (element, alpha_i)| {
                let c_at_a = data.key0.omul(alpha_i, &element.c)?;
                data.key0.oadd(&acc, &c_at_a)
            },
        )?;

        let s = pdata
            .batch
            .iter()
            .zip(&m)
            .map(|(element, m_i)| aux.combine(element.x, m_i))
            .collect::<Result<_, _>>()?;
        let e = alpha
            .iter()
            .zip(&gamma)
            .map(|(alpha_i, gamma_i)| aux.combine(alpha_i, gamma_i))
            .collect::<Result<_, _>>()?;
        let f = aux.combine(&beta, &delta)?;
        let t = pdata
            .batch
            .iter()
            .zip(&mu)
            .map(|(element, mu_i)| aux.combine(element.y, mu_i))
            .collect::<Result<_, _>>()?;
        let b_x = alpha
            .iter()
            .map(|alpha_i| Point::<C>::generator() * alpha_i.to_scalar())
            .collect();
        let b_y = data.key1.encrypt_with(&beta, &r_y)?;

        let commitment = Commitment {
            a,
            s,
            e,
            f,
            t,
            b_x,
            b_y,
        };
        let private_commitment = PrivateCommitment {
            m,
            mu,
            alpha,
            gamma,
            beta,
            r,
            delta,
            r_y,
        };
        Ok((commitment, private_commitment))
    }

    /// Compute proof for given data and prior protocol values
    pub fn prove<C: Curve>(
        _data: PublicData<C>,
        pdata: PrivateData,
        pcomm: &PrivateCommitment,
        challenge: &Challenge,
    ) -> Result<Proof, Error> {
        prove_ref(&pdata, pcomm, challenge)
    }

    pub(super) fn prove_ref(
        pdata: &PrivateData,
        pcomm: &PrivateCommitment,
        challenge: &Challenge,
    ) -> Result<Proof, Error> {
        let n = pdata.batch.len();
        if [
            challenge.len(),
            pcomm.m.len(),
            pcomm.mu.len(),
            pcomm.alpha.len(),
            pcomm.gamma.len(),
        ]
        .iter()
        .any(|len| *len != n)
        {
            return Err(ErrorReason::Length.into());
        }
        let elements = || pdata.batch.iter().zip(challenge);

        let z1 = pcomm
            .alpha
            .iter()
            .zip(elements())
            .map(|(alpha_i, (element, e_i))| alpha_i + e_i * element.x)
            .collect();
        let z2 = elements().fold(pcomm.beta.clone(), |acc, (element, e_i)| {
            acc + e_i * element.y
        });
        let z3 = pcomm
            .gamma
            .iter()
            .zip(challenge)
            .zip(&pcomm.m)
            .map(|((gamma_i, e_i), m_i)| gamma_i + e_i * m_i)
            .collect();
        let z4 = pcomm
            .mu
            .iter()
            .zip(challenge)
            .fold(pcomm.delta.clone(), |acc, (mu_i, e_i)| acc + e_i * mu_i);
        let w = elements().fold(pcomm.r.clone(), |acc, (element, e_i)| {
            acc + e_i * element.nonce
        });
        let w_y = elements().fold(pcomm.r_y.clone(), |acc, (element, e_i)| {
            acc + e_i * element.nonce_y
        });

        Ok(Proof {
            z1,
            z2,
            z3,
            z4,
            w,
            w_y,
        })
    }

    /// Verify the proof
    pub fn verify<C: Curve>(
        aux: &Aux,
        data: PublicData<C>,
        commitment: &Commitment<C>,
        security: &SecurityParams,
        challenge: &Challenge,
        proof: &Proof,
    ) -> Result<(), InvalidProof> {
        verify_ref(aux, &data, commitment, security, challenge, proof)
    }

    pub(super) fn verify_ref<C: Curve>(
        aux: &Aux,
        data: &PublicData<C>,
        commitment: &Commitment<C>,
        security: &SecurityParams,
        challenge: &Challenge,
        proof: &Proof,
    ) -> Result<(), InvalidProof> {
        let n = data.batch.len();
        fail_if(
            InvalidProofReason::Length,
            n > 0
                && [
                    challenge.len(),
                    commitment.s.len(),
                    commitment.e.len(),
                    commitment.t.len(),
                    commitment.b_x.len(),
                    proof.z1.len(),
                    proof.z3.len(),
                ]
                .iter()
                .all(|len| *len == n),
        )?;

        // Range checks are cheap, do them first
        let z1_bound = BigInt::one() << (security.l_x + security.epsilon + security.t);
        fail_if(
            InvalidProofReason::RangeCheck(6),
            proof.z1.iter().all(|z1_i| z1_i.is_in_pm(&z1_bound)),
        )?;
        let z2_bound = BigInt::one() << (security.l_y + security.epsilon + security.t);
        fail_if(
            InvalidProofReason::RangeCheck(7),
            proof.z2.is_in_pm(&z2_bound),
        )?;

        // g^z1_i = B_x_i · X_i^e_i
        for (((z1_i, b_x_i), element), e_i) in proof
            .z1
            .iter()
            .zip(&commitment.b_x)
            .zip(&data.batch)
            .zip(challenge)
        {
            let lhs = Point::<C>::generator() * z1_i.to_scalar();
            let rhs = b_x_i + element.x * e_i.to_scalar();
            fail_if_ne(InvalidProofReason::EqualityCheck(2), lhs, rhs)?;
        }

        // Enc_key0(z2, w) · Π C_i^z1_i = A · Π D_i^e_i
        {
            let key0 = data.key0;
            let lhs = proof.z1.iter().zip(&data.batch).try_fold(
                key0.encrypt_with(&proof.z2, &proof.w)
                    .map_err(|_| InvalidProofReason::PaillierEnc)?,
                |acc, (z1_i, element)| {
                    let c_at_z1 = key0.omul(z1_i, &element.c)?;
                    key0.oadd(&acc, &c_at_z1)
                },
            );
            let rhs = data.batch.iter().zip(challenge).try_fold(
                commitment.a.clone(),
                |acc, (element, e_i)| {
                    let d_at_e = key0.omul(e_i, &element.d)?;
                    key0.oadd(&acc, &d_at_e)
                },
            );
            let (lhs, rhs) = (
                lhs.map_err(|_| InvalidProofReason::PaillierOp)?,
                rhs.map_err(|_| InvalidProofReason::PaillierOp)?,
            );
            fail_if_ne(InvalidProofReason::EqualityCheck(1), lhs, rhs)?;
        }

        // Enc_key1(z2, w_y) = B_y · Π Y_i^e_i
        {
            let key1 = data.key1;
            let lhs = key1
                .encrypt_with(&proof.z2, &proof.w_y)
                .map_err(|_| InvalidProofReason::PaillierEnc)?;
            let rhs = data
                .batch
                .iter()
                .zip(challenge)
                .try_fold(commitment.b_y.clone(), |acc, (element, e_i)| {
                    let y_at_e = key1.omul(e_i, &element.y)?;
                    key1.oadd(&acc, &y_at_e)
                })
                .map_err(|_| InvalidProofReason::PaillierOp)?;
            fail_if_ne(InvalidProofReason::EqualityCheck(3), lhs, rhs)?;
        }

        // s^z1_i t^z3_i = E_i · S_i^e_i, evaluated as s^z1_i t^z3_i S_i^-e_i = E_i
        for ((((z1_i, z3_i), s_i), e_commit_i), e_i) in proof
            .z1
            .iter()
            .zip(&proof.z3)
            .zip(&commitment.s)
            .zip(&commitment.e)
            .zip(challenge)
        {
            let neg_e_i = -e_i;
            let lhs = aux.multi_pow(&[(&aux.s, z1_i), (&aux.t, z3_i), (s_i, &neg_e_i)])?;
            fail_if_ne(InvalidProofReason::EqualityCheck(4), &lhs, e_commit_i)?;
        }

        // s^z2 t^z4 = F · Π T_i^e_i, evaluated as s^z2 t^z4 Π T_i^-e_i = F
        {
            let neg_e: Vec<BigInt> = challenge.iter().map(|e_i| -e_i).collect();
            let mut pairs = Vec::with_capacity(n + 2);
            pairs.push((&aux.s, &proof.z2));
            pairs.push((&aux.t, &proof.z4));
            pairs.extend(commitment.t.iter().zip(&neg_e));
            let lhs = aux.multi_pow(&pairs)?;
            fail_if_ne(InvalidProofReason::EqualityCheck(5), &lhs, &commitment.f)?;
        }

        Ok(())
    }

    /// Generate random challenge: `batch_size` independent integers from `[-q; q]`
    pub fn challenge<R>(security: &SecurityParams, rng: &mut R, batch_size: usize) -> Challenge
    where
        R: RngCore,
    {
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
    /// deriving determenistic challenge.
    ///
    /// Obtained from the above interactive proof via Fiat-Shamir heuristic.
    pub fn prove<C: Curve, D: Digest>(
        shared_state: &impl udigest::Digestable,
        aux: &Aux,
        data: PublicData<C>,
        pdata: PrivateData,
        security: &SecurityParams,
        rng: &mut impl rand_core::RngCore,
    ) -> Result<(Commitment<C>, Proof), Error> {
        let (comm, pcomm) = super::interactive::commit_ref(aux, &data, &pdata, security, rng)?;
        let challenge = challenge_ref::<C, D>(shared_state, aux, &data, &comm, security);
        let proof = super::interactive::prove_ref(&pdata, &pcomm, &challenge)?;
        Ok((comm, proof))
    }

    /// Verify the proof, deriving challenge independently from same data
    pub fn verify<C: Curve, D: Digest>(
        shared_state: &impl udigest::Digestable,
        aux: &Aux,
        data: PublicData<C>,
        commitment: &Commitment<C>,
        security: &SecurityParams,
        proof: &Proof,
    ) -> Result<(), InvalidProof> {
        let challenge = challenge_ref::<C, D>(shared_state, aux, &data, commitment, security);
        super::interactive::verify_ref(aux, &data, commitment, security, &challenge, proof)
    }

    /// Deterministically compute challenge based on prior known values in protocol
    ///
    /// The challenge has one element per element of `data.batch`
    pub fn challenge<C: Curve, D: Digest>(
        shared_state: &impl udigest::Digestable,
        aux: &Aux,
        data: PublicData<C>,
        commitment: &Commitment<C>,
        security: &SecurityParams,
    ) -> Challenge {
        challenge_ref::<C, D>(shared_state, aux, &data, commitment, security)
    }

    fn challenge_ref<C: Curve, D: Digest>(
        shared_state: &impl udigest::Digestable,
        aux: &Aux,
        data: &PublicData<C>,
        commitment: &Commitment<C>,
        security: &SecurityParams,
    ) -> Challenge {
        let tag = "paillier_zk.batch_paillier_affine_operation_in_range.ni_challenge";
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
    use generic_ec::{Curve, Point};
    use num_bigint::BigInt;

    use crate::common::test::{sample_key, sample_other_key};
    use crate::common::{BigIntExt, InvalidProofReason};

    type D = sha2::Sha256;

    /// cggmp21 `SecurityLevel128`
    fn security() -> super::SecurityParams {
        super::SecurityParams {
            l_x: 256,
            l_y: 848,
            epsilon: 230,
            q: BigInt::from(1) << 128_u32,
            t: 128,
        }
    }

    /// Batch of 2 elements in cggmp21 MtA setting: `key0` is the verifier's key and both
    /// elements share the same `C`
    struct Setup {
        aux: super::Aux,
        key0: fast_paillier::EncryptionKey,
        key1: fast_paillier::DecryptionKey,
        xs: Vec<BigInt>,
        ys: Vec<BigInt>,
        nonces: Vec<BigInt>,
        nonces_y: Vec<BigInt>,
        batch: Vec<super::PublicElement<generic_ec::curves::Secp256r1>>,
    }

    type E = generic_ec::curves::Secp256r1;

    impl Setup {
        /// `x_offsets`/`y_offsets` are added to the plaintexts used in `D_i`/`Y_i`, but not to the
        /// prover's witness
        fn new(xs: Vec<BigInt>, ys: Vec<BigInt>, x_offsets: [i64; 2], y_offsets: [i64; 2]) -> Self {
            let mut rng = rand_dev::DevRng::new();
            let key0 = sample_other_key();
            let key1 = sample_key();
            let k = BigInt::from_rng_pm(key0.half_n(), &mut rng);
            let (c, _) = key0.encrypt_with_random(&mut rng, &k).unwrap();
            let mut nonces = vec![];
            let mut nonces_y = vec![];
            let mut batch = vec![];
            for i in 0..2 {
                let x = &xs[i] + x_offsets[i];
                let y = &ys[i] + y_offsets[i];
                let (y_enc0, rho) = key0.encrypt_with_random(&mut rng, &ys[i]).unwrap();
                let d = key0.oadd(&key0.omul(&x, &c).unwrap(), &y_enc0).unwrap();
                let (y_enc1, rho_y) = key1.encrypt_with_random(&mut rng, &y).unwrap();
                nonces.push(rho);
                nonces_y.push(rho_y);
                batch.push(super::PublicElement {
                    c: c.clone(),
                    x: Point::generator() * xs[i].to_scalar::<E>(),
                    d,
                    y: y_enc1,
                });
            }
            Self {
                aux: crate::common::test::aux(&mut rng),
                key0,
                key1,
                xs,
                ys,
                nonces,
                nonces_y,
                batch,
            }
        }
        fn honest() -> Self {
            let mut rng = rand_dev::DevRng::new();
            let s = security();
            let xs = (0..2)
                .map(|_| BigInt::from_rng_pm(&(BigInt::from(1) << s.l_x), &mut rng))
                .collect();
            let ys = (0..2)
                .map(|_| BigInt::from_rng_pm(&(BigInt::from(1) << s.l_y), &mut rng))
                .collect();
            Self::new(xs, ys, [0; 2], [0; 2])
        }
        fn data(&self) -> super::PublicData<'_, E> {
            super::PublicData {
                key0: &self.key0,
                key1: &self.key1,
                batch: self.batch.clone(),
            }
        }
        fn prove(&self) -> (super::Commitment<E>, super::Proof) {
            let mut rng = rand_dev::DevRng::new();
            let pdata = super::PrivateData {
                batch: (0..2)
                    .map(|i| super::PrivateElement {
                        x: &self.xs[i],
                        y: &self.ys[i],
                        nonce: &self.nonces[i],
                        nonce_y: &self.nonces_y[i],
                    })
                    .collect(),
            };
            super::non_interactive::prove::<E, D>(
                &"shared state",
                &self.aux,
                self.data(),
                pdata,
                &security(),
                &mut rng,
            )
            .unwrap()
        }
        fn verify_with(
            &self,
            data: super::PublicData<E>,
            commitment: &super::Commitment<E>,
            proof: &super::Proof,
        ) -> Result<(), InvalidProofReason> {
            super::non_interactive::verify::<E, D>(
                &"shared state",
                &self.aux,
                data,
                commitment,
                &security(),
                proof,
            )
            .map_err(|e| e.reason())
        }
        fn verify(
            &self,
            commitment: &super::Commitment<E>,
            proof: &super::Proof,
        ) -> Result<(), InvalidProofReason> {
            self.verify_with(self.data(), commitment, proof)
        }
    }

    #[test]
    fn passing() {
        let setup = Setup::honest();
        let (commitment, proof) = setup.prove();
        setup.verify(&commitment, &proof).unwrap();

        // Verifier with CRT and multiexp tables
        let fast_aux = crate::common::test::with_optimizations(&setup.aux);
        super::non_interactive::verify::<E, D>(
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
    fn passing_on_other_curve() {
        passing_generic::<crate::curve::C>()
    }

    fn passing_generic<C: Curve>() {
        let mut rng = rand_dev::DevRng::new();
        let key0 = sample_other_key();
        let key1 = sample_key();
        let s = security();
        let x = BigInt::from_rng_pm(&(BigInt::from(1) << s.l_x), &mut rng);
        let y = BigInt::from_rng_pm(&(BigInt::from(1) << s.l_y), &mut rng);
        let (c, _) = key0
            .encrypt_with_random(&mut rng, &BigInt::from(7))
            .unwrap();
        let (y_enc0, rho) = key0.encrypt_with_random(&mut rng, &y).unwrap();
        let d = key0.oadd(&key0.omul(&x, &c).unwrap(), &y_enc0).unwrap();
        let (y_enc1, rho_y) = key1.encrypt_with_random(&mut rng, &y).unwrap();
        let element = super::PublicElement::<C> {
            c,
            x: Point::generator() * x.to_scalar::<C>(),
            d,
            y: y_enc1,
        };
        let data = super::PublicData {
            key0: &key0,
            key1: &key1,
            batch: vec![element],
        };
        let pdata = super::PrivateData {
            batch: vec![super::PrivateElement {
                x: &x,
                y: &y,
                nonce: &rho,
                nonce_y: &rho_y,
            }],
        };
        let aux = crate::common::test::aux(&mut rng);
        let (commitment, proof) =
            super::non_interactive::prove::<C, D>(&"s", &aux, data.clone(), pdata, &s, &mut rng)
                .unwrap();
        super::non_interactive::verify::<C, D>(&"s", &aux, data, &commitment, &s, &proof).unwrap();
    }

    #[test]
    fn failing_on_additive() {
        let mut rng = rand_dev::DevRng::new();
        let s = security();
        let xs = (0..2)
            .map(|_| BigInt::from_rng_pm(&(BigInt::from(1) << s.l_x), &mut rng))
            .collect();
        let y: BigInt = (BigInt::from(1) << (s.l_y + s.epsilon + s.t + 5)) + 1;
        let setup = Setup::new(xs, vec![y.clone(), y], [0; 2], [0; 2]);
        let (commitment, proof) = setup.prove();
        assert_eq!(
            setup.verify(&commitment, &proof),
            Err(InvalidProofReason::RangeCheck(7))
        );
    }

    #[test]
    fn failing_on_multiplicative() {
        let mut rng = rand_dev::DevRng::new();
        let s = security();
        // Large enough that `e * x` is out of range for any non-zero challenge
        let x: BigInt = (BigInt::from(1) << (s.l_x + s.epsilon + s.t + 5)) + 1;
        let ys = (0..2)
            .map(|_| BigInt::from_rng_pm(&(BigInt::from(1) << s.l_y), &mut rng))
            .collect();
        let setup = Setup::new(vec![x.clone(), x], ys, [0; 2], [0; 2]);
        let (commitment, proof) = setup.prove();
        assert_eq!(
            setup.verify(&commitment, &proof),
            Err(InvalidProofReason::RangeCheck(6))
        );
    }

    /// Only one `x_i` is out of range: every `z1_i` must be range-checked
    #[test]
    fn failing_when_one_element_out_of_range() {
        let mut rng = rand_dev::DevRng::new();
        let s = security();
        let x_ok = BigInt::from_rng_pm(&(BigInt::from(1) << s.l_x), &mut rng);
        let x_bad: BigInt = BigInt::from(1) << (s.l_x + s.epsilon + s.t + 10);
        let ys: Vec<BigInt> = (0..2)
            .map(|_| BigInt::from_rng_pm(&(BigInt::from(1) << s.l_y), &mut rng))
            .collect();
        for xs in [vec![x_ok.clone(), x_bad.clone()], vec![x_bad, x_ok]] {
            let setup = Setup::new(xs, ys.clone(), [0; 2], [0; 2]);
            let (commitment, proof) = setup.prove();
            assert_eq!(
                setup.verify(&commitment, &proof),
                Err(InvalidProofReason::RangeCheck(6))
            );
        }
    }

    /// `D_1` and `D_2` (resp. `Y_1`, `Y_2`) are shifted against each other: their product is
    /// consistent with the witness, but each of them isn't. Would pass with a shared challenge.
    #[test]
    fn failing_on_shifted_statements() {
        let mut rng = rand_dev::DevRng::new();
        let s = security();
        let xs: Vec<BigInt> = (0..2)
            .map(|_| BigInt::from_rng_pm(&(BigInt::from(1) << s.l_x), &mut rng))
            .collect();
        let ys: Vec<BigInt> = (0..2)
            .map(|_| BigInt::from_rng_pm(&(BigInt::from(1) << s.l_y), &mut rng))
            .collect();

        let setup = Setup::new(xs.clone(), ys.clone(), [1000, -1000], [0; 2]);
        let (commitment, proof) = setup.prove();
        assert_eq!(
            setup.verify(&commitment, &proof),
            Err(InvalidProofReason::EqualityCheck(1))
        );

        let setup = Setup::new(xs, ys, [0; 2], [1000, -1000]);
        let (commitment, proof) = setup.prove();
        assert_eq!(
            setup.verify(&commitment, &proof),
            Err(InvalidProofReason::EqualityCheck(3))
        );
    }

    #[test]
    fn fiat_shamir_binds_statement_and_commitment() {
        let setup = Setup::honest();
        let (commitment, proof) = setup.prove();

        // Tampered statement
        for i in 0..5 {
            let mut data = setup.data();
            match i {
                0 => data.batch[0].c += 1,
                1 => data.batch[1].d += 1,
                2 => data.batch[0].y += 1,
                3 => data.batch[1].x += Point::generator(),
                _ => data.batch.swap(0, 1),
            }
            assert!(
                setup.verify_with(data, &commitment, &proof).is_err(),
                "statement tamper {i}"
            );
        }
        let other = sample_other_key();
        let data = super::PublicData {
            key1: &other,
            ..setup.data()
        };
        assert!(setup.verify_with(data, &commitment, &proof).is_err());

        // Tampered commitment
        for i in 0..7 {
            let mut bad = commitment.clone();
            match i {
                0 => bad.a += 1,
                1 => bad.s[1] += 1,
                2 => bad.e[0] += 1,
                3 => bad.f += 1,
                4 => bad.t[1] += 1,
                5 => bad.b_x[0] += Point::generator(),
                _ => bad.b_y += 1,
            }
            assert!(setup.verify(&bad, &proof).is_err(), "commitment tamper {i}");
        }

        // Tampered proof
        for i in 0..6 {
            let mut bad = proof.clone();
            match i {
                0 => bad.z1[1] += 1,
                1 => bad.z2 += 1,
                2 => bad.z3[0] += 1,
                3 => bad.z4 += 1,
                4 => bad.w += 1,
                _ => bad.w_y += 1,
            }
            assert!(setup.verify(&commitment, &bad).is_err(), "proof tamper {i}");
        }
    }

    #[test]
    fn wrong_lengths_are_rejected_without_panic() {
        let setup = Setup::honest();
        let (commitment, proof) = setup.prove();

        let commitment_tampers: [fn(&mut super::Commitment<E>); 8] = [
            |c| c.s.truncate(1),
            |c| c.e.push(c.e[0].clone()),
            |c| c.t.clear(),
            |c| c.b_x.truncate(1),
            |c| c.s.clear(),
            |c| c.e.clear(),
            |c| c.b_x.push(c.b_x[0]),
            |c| c.t.push(BigInt::from(1)),
        ];
        for tamper in commitment_tampers {
            let mut bad = commitment.clone();
            tamper(&mut bad);
            assert_eq!(setup.verify(&bad, &proof), Err(InvalidProofReason::Length));
        }
        let proof_tampers: [fn(&mut super::Proof); 4] = [
            |p| p.z1.truncate(1),
            |p| p.z1.push(BigInt::from(0)),
            |p| p.z3.clear(),
            |p| p.z3.push(BigInt::from(0)),
        ];
        for tamper in proof_tampers {
            let mut bad = proof.clone();
            tamper(&mut bad);
            assert_eq!(
                setup.verify(&commitment, &bad),
                Err(InvalidProofReason::Length)
            );
        }

        // Statement of other size
        let mut data = setup.data();
        data.batch.push(data.batch[0].clone());
        assert_eq!(
            setup.verify_with(data, &commitment, &proof),
            Err(InvalidProofReason::Length)
        );
        let mut data = setup.data();
        data.batch.clear();
        assert_eq!(
            setup.verify_with(data, &commitment, &proof),
            Err(InvalidProofReason::Length)
        );

        // Interactive verifier with a short challenge
        let data = setup.data();
        let challenge = vec![BigInt::from(1)];
        assert!(super::interactive::verify(
            &setup.aux,
            data,
            &commitment,
            &security(),
            &challenge,
            &proof
        )
        .is_err());
    }

    #[test]
    fn malformed_values_are_rejected_without_panic() {
        let setup = Setup::honest();
        let (commitment, proof) = setup.prove();
        let n0 = setup.key0.n().clone();

        for value in [
            BigInt::from(0),
            BigInt::from(-1),
            setup.aux.rsa_modulo.clone(),
        ] {
            let mut bad = commitment.clone();
            bad.s = vec![value.clone(), value.clone()];
            bad.t = vec![value.clone(), value.clone()];
            assert!(setup.verify(&bad, &proof).is_err());
        }
        for value in [BigInt::from(0), BigInt::from(-1), n0.clone(), &n0 * &n0 * 2] {
            let mut bad = commitment.clone();
            bad.a = value.clone();
            bad.b_y = value.clone();
            assert!(setup.verify(&bad, &proof).is_err());

            let mut data = setup.data();
            data.batch[0].c = value.clone();
            data.batch[1].d = value.clone();
            assert!(setup.verify_with(data, &commitment, &proof).is_err());
        }
        // Responses outside of the plaintext space
        let mut bad = proof.clone();
        bad.w = -bad.w.clone();
        bad.w_y = BigInt::from(0);
        assert!(setup.verify(&commitment, &bad).is_err());
    }
}
