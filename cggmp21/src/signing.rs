//! Signing protocol
#![allow(unused_extern_crates)]

pub mod signing_stateful;
use digest::Digest;
use futures::SinkExt;
use generic_ec::{coords::AlwaysHasAffineX, Curve, NonZero, Point, Scalar, SecretScalar};
use generic_ec_zkp::polynomial::lagrange_coefficient_at_zero;

use num_bigint::{BigInt, RandBigInt};
use paillier_zk::fast_paillier;
use paillier_zk::{
    batch_paillier_affine_operation_in_range as pi_aff_batch,
    batch_paillier_encryption_in_range_with_el_gamal as pi_enc_el_gamal_batch,
    dlog_with_el_gamal_commitment as pi_elog, BigIntExt,
};
use rand_core::{CryptoRng, RngCore};
use round_based::{
    rounds_router::{simple_store::RoundInput, RoundsRouter},
    runtime::AsyncRuntime,
    Delivery, Mpc, MpcParty, MsgId, Outgoing, PartyIndex,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::errors::IoError;
use crate::key_share::{KeyShare, PartyAux, VssSetup};
use crate::progress::Tracer;
use crate::{key_share::InvalidKeyShare, security_level::SecurityLevel, utils, ExecutionId};

use birkhoff::birkhoff_coefficient::birkhoff_coefficient;

use self::msg::*;

/// A (prehashed) data to be signed
///
/// `DataToSign` holds a scalar that represents data to be signed. Different ECDSA schemes define different
/// ways to map an original data to be signed (slice of bytes) into the scalar, but it always must involve
/// cryptographic hash functions. Most commonly, original data is hashed using SHA2-256, then output is parsed
/// as big-endian integer and taken modulo curve order. This exact functionality is implemented in
/// [DataToSign::digest] and [DataToSign::from_digest] constructors.
#[derive(Debug, Clone, Copy)]
pub struct DataToSign<E: Curve>(Scalar<E>);

impl<E: Curve> DataToSign<E> {
    /// Construct a `DataToSign` by hashing `data` with algorithm `D`
    ///
    /// `data_to_sign = hash(data) mod q`
    pub fn digest<D: Digest>(data: &[u8]) -> Self {
        DataToSign(Scalar::from_be_bytes_mod_order(D::digest(data)))
    }

    /// Constructs a `DataToSign` from output of given digest
    ///
    /// `data_to_sign = hash(data) mod q`
    pub fn from_digest<D: Digest>(hash: D) -> Self {
        DataToSign(Scalar::from_be_bytes_mod_order(hash.finalize()))
    }

    /// Constructs a `DataToSign` from scalar
    ///
    /// ** Note: [DataToSign::digest] and [DataToSign::from_digest] are preferred way to construct the `DataToSign` **
    ///
    /// `scalar` must be output of cryptographic hash function applied to original message to be signed
    pub fn from_scalar(scalar: Scalar<E>) -> Self {
        Self(scalar)
    }

    /// Returns a scalar that represents a data to be signed
    pub fn to_scalar(self) -> Scalar<E> {
        self.0
    }
}

/// Presignature, can be used to issue a [partial signature](PartialSignature) without interacting with other signers
///
/// [Threshold](crate::key_share::AnyKeyShare::min_signers) amount of partial signatures (from different signers) can be [combined](PartialSignature::combine) into regular signature
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]

// let delta_inv = delta.invert().ok_or(Bug::ZeroDelta)?;
// let hat_k_i = k_i * delta_inv;
// let hat_chi_i = chi_i * delta_inv;
// let hat_Delta_j = round3_msgs.iter().map(|m| m.Delta_i * delta_inv).collect::<Vec<_>>();
// let hat_S_j = round3_msgs.iter().map(|m| m.S_i * delta_inv).collect::<Vec<_>>();

pub struct Presignature<E: Curve> {
    /// $\Gamma$ component, where $\Gamma = G \cdot \gamma$
    pub Gamma: NonZero<Point<E>>,
    /// Scaled secret share of $k_i$: $k_i \cdot \delta^{-1}$
    pub hat_k_i: Scalar<E>,
    /// Scaled secret share of $\chi_i$: $\chi_i \cdot \delta^{-1}$
    pub hat_chi_i: Scalar<E>,
    /// Vector of scaled $\Delta_j$ points: $\Delta_j \cdot \delta^{-1}$
    pub hat_Delta_j: Vec<Point<E>>,
    /// Vector of scaled $S_j$ points: $S_j \cdot \delta^{-1}$
    pub hat_S_j: Vec<Point<E>>,
}

/// Partial signature issued by signer for given message
///
/// Can be obtained using [`Presignature::issue_partial_signature`]. Partial signature doesn't carry any sensitive inforamtion.
///
/// Threshold amount of partial signatures can be combined into a regular signature using [`PartialSignature::combine`]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct PartialSignature<E: Curve> {
    /// $r$ component of partial signature
    pub r: Scalar<E>,
    /// $\sigma$ component of partial signature
    pub sigma_i: Scalar<E>,
}

/// ECDSA signature
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Debug)]
#[serde(bound = "")]
pub struct Signature<E: Curve> {
    /// $r$ component of signature
    pub r: NonZero<Scalar<E>>,
    /// $s$ component of signature
    pub s: NonZero<Scalar<E>>,
}

macro_rules! prefixed {
    ($name:tt) => {
        concat!("dfns.cggmp21.signing.", $name)
    };
}

#[doc = include_str!("../docs/mpc_message.md")]
pub mod msg {
    use digest::Digest;
    use generic_ec::Curve;
    use generic_ec::{Point, Scalar};
    use paillier_zk::fast_paillier::utils::{
        serializable_array_bigint, serializable_bigint, serializable_vec_bigint,
    };

    use paillier_zk::fast_paillier;
    use paillier_zk::{
        batch_paillier_affine_operation_in_range as pi_aff_batch,
        batch_paillier_encryption_in_range_with_el_gamal as pi_enc_el_gamal_batch,
        dlog_with_el_gamal_commitment as pi_elog,
    };
    use round_based::ProtocolMessage;
    use serde::{Deserialize, Serialize};

    use crate::utils;

    /// Signing protocol message
    ///
    /// Enumerates messages from all rounds
    #[derive(Clone, ProtocolMessage, Serialize, Deserialize)]
    #[serde(bound = "")]
    #[allow(clippy::large_enum_variant)]
    pub enum Msg<E: Curve, D: Digest> {
        /// Round 1a message
        Round1a(MsgRound1a<E>),
        /// Round 1b message
        Round1b(MsgRound1b<E>),
        /// Round 2 message
        Round2(MsgRound2<E>),
        /// Round 3 message
        Round3(MsgRound3<E>),
        /// Round 4 message
        Round4(MsgRound4<E>),
        /// Reliability check message (optional additional round)
        ReliabilityCheck(MsgReliabilityCheck<D>),
    }

    /// Message from round 1a
    #[derive(Clone, Serialize, Deserialize, udigest::Digestable)]
    #[serde(bound = "")]
    #[udigest(bound = "")]
    #[udigest(tag = prefixed!("round1"))]
    pub struct MsgRound1a<E: Curve> {
        /// $K_i = enc(k_i, rho_i)$
        #[serde(with = "serializable_bigint")]
        #[udigest(as = utils::encoding::BigInt)]
        pub K_i: fast_paillier::Ciphertext,
        /// $G_i = enc(gamma_i, nu_i)$
        #[serde(with = "serializable_bigint")]
        #[udigest(as = utils::encoding::BigInt)]
        pub G_i: fast_paillier::Ciphertext,
        /// $Y_i$: EC point
        pub Y_i: Point<E>,
        /// $A_{i,1} = g^{a_i}$
        pub A_i1: Point<E>,
        /// $A_{i,2} = Y_i^{a_i} * g^{k_i}$
        pub A_i2: Point<E>,
        /// $B_{i,1} = g^{b_i}$
        pub B_i1: Point<E>,
        /// $B_{i,2} = Y_i^{b_i} * g^{gamma_i}$
        pub B_i2: Point<E>,
    }

    /// Message from round 1b
    #[derive(Clone, Serialize, Deserialize)]
    #[serde(bound = "")]
    pub struct MsgRound1b<E: Curve> {
        /// $\psi^0_{j,i}$: pi_enc_el_gamal provement for K_i
        pub psi_enc_ji: (
            pi_enc_el_gamal_batch::Commitment<E>,
            pi_enc_el_gamal_batch::Proof<E>,
        ),
        // $\psi^1_{j,i}$: pi_enc_el_gamal provement for G_i
        // pub psi1_ji: (pi_enc_el_gamal::Commitment<E>, pi_enc_el_gamal::Proof<E>),
    }

    /// Message from round 2
    #[derive(Clone, Serialize, Deserialize)]
    #[serde(bound = "")]
    pub struct MsgRound2<E: Curve> {
        /// $\Gamma_i = g^{gamma_i}$
        pub Gamma_i: Point<E>,
        /// $\psi_{j,i}$: pi_elog provement for $Gamma_i$
        pub psi_i: (pi_elog::Commitment<E>, pi_elog::Proof<E>),
        /// $D_{j,i} = enc(gamma_i * k_j - beta_ij)$
        #[serde(with = "serializable_bigint")]
        pub D_ji: fast_paillier::Ciphertext,
        /// $F_{j,i} = enc(-beta_ij, r_ij)$
        #[serde(with = "serializable_bigint")]
        pub F_ji: fast_paillier::Ciphertext,
        /// $\hat D_{j,i} = enc(x_i * k_j - hat_beta_ij)$
        #[serde(with = "serializable_bigint")]
        pub hat_D_ji: fast_paillier::Ciphertext,
        /// $\hat F_{j,i} = enc(-hat_beta_ij, r_ij)$
        #[serde(with = "serializable_bigint")]
        pub hat_F_ji: fast_paillier::Ciphertext,
        /// $\psi_{j,i}$: pi_aff_g provement for $Gamma_i$
        pub psi_aff_ji: (pi_aff_batch::Commitment<E>, pi_aff_batch::Proof),
    }

    /// Message from round 3
    #[derive(Clone, Serialize, Deserialize)]
    #[serde(bound = "")]
    pub struct MsgRound3<E: Curve> {
        /// $\delta_i$
        pub delta_i: Scalar<E>,
        /// $S_i$
        pub S_i: Point<E>,
        /// $\Delta_i$
        pub Delta_i: Point<E>,
        /// $\psi''_{j,i}$
        pub hat_psi_i: (pi_elog::Commitment<E>, pi_elog::Proof<E>),
    }

    /// Message from round 4
    #[derive(Clone, Serialize, Deserialize)]
    #[serde(bound = "")]
    pub struct MsgRound4<E: Curve> {
        /// $\sigma_i$
        pub sigma_i: Scalar<E>,
    }

    /// Message from auxiliary round for reliability check
    #[derive(Clone, Serialize, Deserialize)]
    #[serde(bound = "")]
    pub struct MsgReliabilityCheck<D: Digest>(pub digest::Output<D>);
}

mod unambiguous {
    use crate::ExecutionId;
    use generic_ec::Curve;

    #[derive(udigest::Digestable)]
    #[udigest(tag = prefixed!("proof_enc"))]
    pub struct ProofEnc<'a> {
        pub sid: ExecutionId<'a>,
        pub prover: u16,
    }

    #[derive(udigest::Digestable)]
    #[udigest(tag = prefixed!("proof_psi"))]
    pub struct ProofPsi<'a> {
        pub sid: ExecutionId<'a>,
        pub prover: u16,
        pub hat: bool,
    }

    #[derive(udigest::Digestable)]
    #[udigest(tag = prefixed!("proof_log"))]
    pub struct ProofLog<'a> {
        pub sid: ExecutionId<'a>,
        pub prover: u16,
        pub prime_prime: bool,
    }

    #[derive(udigest::Digestable)]
    #[udigest(bound = "")]
    #[udigest(tag = prefixed!("echo_round"))]
    pub struct Echo<'a, E: Curve> {
        pub sid: ExecutionId<'a>,
        pub msg: &'a super::MsgRound1a<E>,
    }
}

/// Signing entry point
pub struct SigningBuilder<
    'r,
    E,
    L = crate::default_choice::SecurityLevel,
    D = crate::default_choice::Digest,
> where
    E: Curve,
    L: SecurityLevel,
    D: Digest,
{
    i: PartyIndex,
    parties_indexes_at_keygen: &'r [PartyIndex],
    key_share: &'r KeyShare<E, L>,
    execution_id: ExecutionId<'r>,
    tracer: Option<&'r mut dyn Tracer>,
    enforce_reliable_broadcast: bool,
    _digest: std::marker::PhantomData<D>,

    #[cfg(feature = "hd-wallet")]
    additive_shift: Option<Scalar<E>>,

    /// Cached precompute tables for benchmarking purposes
    cached_precompute_tables: Option<Vec<fast_paillier::precomputed_table::PrecomputeTable>>,
}

impl<'r, E, L, D> SigningBuilder<'r, E, L, D>
where
    E: Curve,
    NonZero<Point<E>>: AlwaysHasAffineX<E>,
    L: SecurityLevel,
    D: Digest<OutputSize = digest::typenum::U32> + Clone + 'static,
{
    /// Construct a signing builder
    pub fn new(
        eid: ExecutionId<'r>,
        i: PartyIndex,
        parties_indexes_at_keygen: &'r [PartyIndex],
        secret_key_share: &'r KeyShare<E, L>,
    ) -> Self {
        Self {
            i,
            parties_indexes_at_keygen,
            key_share: secret_key_share,
            execution_id: eid,
            tracer: None,
            enforce_reliable_broadcast: true,
            _digest: std::marker::PhantomData,
            #[cfg(feature = "hd-wallet")]
            additive_shift: None,
            cached_precompute_tables: None,
        }
    }

    /// Specifies another hash function to use
    pub fn set_digest<D2>(self) -> SigningBuilder<'r, E, L, D2>
    where
        D2: Digest,
    {
        SigningBuilder {
            i: self.i,
            parties_indexes_at_keygen: self.parties_indexes_at_keygen,
            key_share: self.key_share,
            tracer: self.tracer,
            enforce_reliable_broadcast: self.enforce_reliable_broadcast,
            execution_id: self.execution_id,
            _digest: std::marker::PhantomData,
            #[cfg(feature = "hd-wallet")]
            additive_shift: self.additive_shift,
            cached_precompute_tables: self.cached_precompute_tables,
        }
    }

    /// Specifies a tracer that tracks progress of protocol execution
    pub fn set_progress_tracer(mut self, tracer: &'r mut dyn Tracer) -> Self {
        self.tracer = Some(tracer);
        self
    }

    #[doc = include_str!("../docs/enforce_reliable_broadcast.md")]
    pub fn enforce_reliable_broadcast(self, v: bool) -> Self {
        Self {
            enforce_reliable_broadcast: v,
            ..self
        }
    }

    /// Specifies HD derivation path
    ///
    /// Note: when generating a presignature, derivation path doesn't need to be known in advance. Instead
    /// of using this method, [`Presignature::set_derivation_path`] could be used to set derivation path
    /// after presignature was generated.
    ///
    /// ## Example
    /// Set derivation path to m/1/999
    ///
    /// ```rust,no_run
    /// # let eid = cggmp21::ExecutionId::new(b"protocol nonce");
    /// # let (i, parties_indexes_at_keygen, key_share): (u16, Vec<u16>, cggmp21::KeyShare<cggmp21::supported_curves::Secp256k1>)
    /// # = unimplemented!();
    /// cggmp21::signing(eid, i, &parties_indexes_at_keygen, &key_share)
    ///     .set_derivation_path([1, 999])?
    /// # ; Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// ## Derivation algorithm
    /// This method uses [`hd_wallet::Slip10`] derivation algorithm, which can only be used with secp256k1
    /// and secp256r1 curves. If you need to use another one, see
    /// [`set_derivation_path_with_algo`](Self::set_derivation_path_with_algo)
    #[cfg(all(feature = "hd-wallet", feature = "hd-slip10"))]
    pub fn set_derivation_path<Index>(
        self,
        path: impl IntoIterator<Item = Index>,
    ) -> Result<
        Self,
        crate::key_share::HdError<<Index as TryInto<hd_wallet::NonHardenedIndex>>::Error>,
    >
    where
        hd_wallet::Slip10: hd_wallet::HdWallet<E>,
        hd_wallet::NonHardenedIndex: TryFrom<Index>,
    {
        self.set_derivation_path_with_algo::<hd_wallet::Slip10, _>(path)
    }

    /// Specifies HD derivation path, using HD derivation algorithm [`hd_wallet::HdWallet`]
    ///
    /// Note: when generating a presignature, derivation path doesn't need to be known in advance. Instead
    /// of using this method, [`Presignature::set_derivation_path`] could be used to set derivation path
    /// after presignature was generated.
    #[cfg(feature = "hd-wallet")]
    pub fn set_derivation_path_with_algo<Hd: hd_wallet::HdWallet<E>, Index>(
        mut self,
        path: impl IntoIterator<Item = Index>,
    ) -> Result<
        Self,
        crate::key_share::HdError<<Index as TryInto<hd_wallet::NonHardenedIndex>>::Error>,
    >
    where
        hd_wallet::NonHardenedIndex: TryFrom<Index>,
    {
        use crate::key_share::HdError;
        let public_key = self
            .key_share
            .extended_public_key()
            .ok_or(HdError::DisabledHd)?;
        self.additive_shift = Some(
            derive_additive_shift::<E, Hd, _>(public_key, path).map_err(HdError::InvalidPath)?,
        );
        Ok(self)
    }

    /// Sets cached precompute tables for benchmarking purposes
    ///
    /// When cached precompute tables are provided, they will be used instead of creating
    /// new tables during signing, which can significantly improve performance in benchmarks.
    pub fn set_cached_precompute_tables(
        mut self,
        tables: Vec<fast_paillier::precomputed_table::PrecomputeTable>,
    ) -> Self {
        self.cached_precompute_tables = Some(tables);
        self
    }

    /// Starts presignature generation protocol
    pub async fn generate_presignature<R, M>(
        self,
        rng: &mut R,
        party: M,
    ) -> Result<Presignature<E>, SigningError>
    where
        R: RngCore + CryptoRng,
        M: Mpc<ProtocolMessage = Msg<E, D>>,
    {
        let cached_tables = self.cached_precompute_tables.as_deref();
        match signing_t_out_of_n(
            self.tracer,
            rng,
            party,
            self.execution_id,
            self.i,
            self.key_share,
            self.parties_indexes_at_keygen,
            None,
            self.enforce_reliable_broadcast,
            #[cfg(feature = "hd-wallet")]
            self.additive_shift,
            #[cfg(not(feature = "hd-wallet"))]
            None,
            cached_tables,
        )
        .await?
        {
            ProtocolOutput::Presignature(presig) => Ok(presig),
            ProtocolOutput::Signature(_) => Err(Bug::UnexpectedProtocolOutput.into()),
        }
    }

    /// Returns a state machine that can be used to carry out the presignature generation protocol
    ///
    /// See [`round_based::state_machine`] for details on how that can be done.
    #[cfg(feature = "state-machine")]
    pub fn generate_presignature_sync<R>(
        self,
        rng: &'r mut R,
    ) -> impl round_based::state_machine::StateMachine<
        Output = Result<Presignature<E>, SigningError>,
        Msg = Msg<E, D>,
    > + 'r
    where
        R: RngCore + CryptoRng,
    {
        round_based::state_machine::wrap_protocol(|party| self.generate_presignature(rng, party))
    }

    /// Starts signing protocol
    pub async fn sign<R, M>(
        self,
        rng: &mut R,
        party: M,
        message_to_sign: DataToSign<E>,
    ) -> Result<Signature<E>, SigningError>
    where
        R: RngCore + CryptoRng,
        M: Mpc<ProtocolMessage = Msg<E, D>>,
    {
        std::println!("Start signing...");
        let cached_tables = self.cached_precompute_tables.as_deref();
        std::println!("cached_tables null: {:?}", cached_tables.is_none());
        match signing_t_out_of_n(
            self.tracer,
            rng,
            party,
            self.execution_id,
            self.i,
            self.key_share,
            self.parties_indexes_at_keygen,
            Some(message_to_sign),
            self.enforce_reliable_broadcast,
            #[cfg(feature = "hd-wallet")]
            self.additive_shift,
            #[cfg(not(feature = "hd-wallet"))]
            None,
            cached_tables,
        )
        .await?
        {
            ProtocolOutput::Signature(sig) => Ok(sig),
            ProtocolOutput::Presignature(_) => Err(Bug::UnexpectedProtocolOutput.into()),
        }
    }

    /// Returns a state machine that can be used to carry out the signing protocol
    ///
    /// See [`round_based::state_machine`] for details on how that can be done.
    #[cfg(feature = "state-machine")]
    pub fn sign_sync<R>(
        self,
        rng: &'r mut R,
        message_to_sign: DataToSign<E>,
    ) -> impl round_based::state_machine::StateMachine<
        Output = Result<Signature<E>, SigningError>,
        Msg = Msg<E, D>,
    > + 'r
    where
        R: RngCore + CryptoRng,
    {
        round_based::state_machine::wrap_protocol(move |party| {
            self.sign(rng, party, message_to_sign)
        })
    }
}

/// t-out-of-n signing
///
/// CGGMP paper doesn't support threshold signing out of the box. However, threshold signing
/// can be easily implemented on top of CGGMP's [`signing_n_out_of_n`] by converting polynomial
/// (VSS) key shares into additive (by multiplying at lagrange coefficient for tss, or by
/// multiplying at birkhoff coefficient for htss) and calling t-out-of-t protocol.
/// The trick is described in more details in the spec.
///
/// S: vector of parties' original indexes, who take part in signing
/// i: index of the party in signing group (after mapping)
/// key_share: key share of the party
/// message_to_sign: message to sign
/// enforce_reliable_broadcast: whether to enforce reliable broadcast
/// additive_shift: additive shift for the key
/// cached_precompute_tables: optional cached precompute tables for benchmarking
#[allow(clippy::too_many_arguments)]
async fn signing_t_out_of_n<M, E, L, D, R>(
    mut tracer: Option<&mut dyn Tracer>,
    rng: &mut R,
    party: M,
    sid: ExecutionId<'_>,
    i: PartyIndex,
    key_share: &KeyShare<E, L>,
    S: &[PartyIndex],
    message_to_sign: Option<DataToSign<E>>,
    enforce_reliable_broadcast: bool,
    additive_shift: Option<Scalar<E>>,
    cached_precompute_tables: Option<&[fast_paillier::precomputed_table::PrecomputeTable]>,
) -> Result<ProtocolOutput<E>, SigningError>
where
    M: Mpc<ProtocolMessage = Msg<E, D>>,
    E: Curve,
    L: SecurityLevel,
    D: Digest<OutputSize = digest::typenum::U32> + Clone + 'static,
    R: RngCore + CryptoRng,
    NonZero<Point<E>>: AlwaysHasAffineX<E>,
{
    tracer.protocol_begins();
    tracer.stage("Map t-out-of-n protocol to t-out-of-t");

    std::println!("signing_t_out_of_n: 1");

    // Validate arguments
    let n: u16 = key_share
        .aux
        .parties
        .len()
        .try_into()
        .map_err(|_| Bug::PartiesNumberExceedsU16)?;
    let t = key_share
        .core
        .vss_setup
        .as_ref()
        .map(|s| s.min_signers)
        .unwrap_or(n);
    if S.len() < usize::from(t) {
        return Err(InvalidArgs::MismatchedAmountOfParties.into());
    }
    if !((i as usize) < S.len()) {
        return Err(InvalidArgs::SignerIndexOutOfBounds.into());
    }
    // S_j is the index of the party in the original group
    // It means S[i] is the original index of the current party
    if S.iter().any(|&S_j| S_j >= n) {
        return Err(InvalidArgs::InvalidSubIndex.into());
    }

    std::println!("signing_t_out_of_n: 2");

    // Assemble x_i and \vec X
    // x_i: new shares (additive shares), X: vector of public shares
    let (mut x_i, mut X) = if let Some(VssSetup { I, ranks, .. }) = &key_share.core.vss_setup {
        if let Some(ref ranks) = ranks {
            // HTSS

            // validate ranks
            if ranks.iter().any(|&r| r >= t) {
                return Err(InvalidArgs::InvalidRanks.into());
            }

            // I: vector of indexes (x-coordinates) of the parties, who take part in signing
            let I = utils::subset(S, I).ok_or(Bug::Subset)?;

            // X: vector of old public shares of the parties, who take part in signing
            // corresponding to lagrange/birkhoff shares
            let X = utils::subset(S, &key_share.core.public_shares).ok_or(Bug::Subset)?;

            // ranks: vector of ranks of the parties, who take part in signing
            let ranks = utils::subset(S, ranks).ok_or(Bug::Subset)?;

            // Convert birkhoff shares into additive shares for HTSS
            let birkhoff = birkhoff_coefficient(t, &I, &ranks).map_err(|_| Bug::BirkhoffCoef)?;
            assert_eq!(birkhoff.len(), S.len());

            let birkhoff_i = birkhoff.get(usize::from(i)).ok_or(Bug::BirkhoffCoef)?;
            let x_i = (birkhoff_i * &key_share.core.x).into_secret();

            let X = birkhoff
                .iter()
                .zip(&X)
                .map(|(birkhoff_j, X_j)| Some(birkhoff_j * X_j))
                .collect::<Option<Vec<_>>>()
                .ok_or(Bug::BirkhoffCoef)?;

            (x_i, X)
        } else {
            // TSS

            // I: vector of indexes (x-coordinates) of the parties, who take part in signing
            let I = utils::subset(S, I).ok_or(Bug::Subset)?;

            // X: vector of old public shares of the parties, who take part in signing
            // corresponding to lagrange/birkhoff shares
            let X = utils::subset(S, &key_share.core.public_shares).ok_or(Bug::Subset)?;

            // Convert lagrange shares into additive shares for TSS
            let lambda_i =
                lagrange_coefficient_at_zero(usize::from(i), &I).ok_or(Bug::LagrangeCoef)?;
            let x_i = (lambda_i * &key_share.core.x).into_secret();

            let lambda = (0..S.len()).map(|j| lagrange_coefficient_at_zero(j, &I));
            let X = lambda
                .zip(&X)
                .map(|(lambda_j, X_j)| Some(lambda_j? * X_j))
                .collect::<Option<Vec<_>>>()
                .ok_or(Bug::LagrangeCoef)?;

            (x_i, X)
        }
    } else {
        // For n-out-of-n keys generated using original CGGMP DKG
        let X = utils::subset(S, &key_share.core.public_shares).ok_or(Bug::Subset)?;
        (key_share.core.x.clone(), X)
    };
    debug_assert_eq!(key_share.core.shared_public_key, X.iter().sum::<Point<E>>());

    std::println!("signing_t_out_of_n: 3");

    // Apply additive shift
    let shift = additive_shift.unwrap_or(Scalar::zero());
    let Shift = Point::generator() * shift;

    X[0] = NonZero::from_point(X[0] + Shift).ok_or(Bug::DerivedChildKeyZero)?;
    if i == 0 {
        x_i = NonZero::from_scalar(x_i + shift)
            .ok_or(Bug::DerivedChildShareZero)?
            .into_secret();
    }
    debug_assert_eq!(
        key_share.core.shared_public_key + Shift,
        X.iter().sum::<Point<E>>()
    );

    std::println!("signing_t_out_of_n: 4");

    // Assemble rest of the data
    let dec_i = &key_share.aux.dec;
    let R = utils::subset(S, &key_share.aux.parties).ok_or(Bug::Subset)?;

    std::println!("signing_t_out_of_n: 5");

    // t-out-of-t signing
    signing_n_out_of_n::<_, _, L, _, _>(
        tracer,
        rng,
        party,
        sid,
        i,
        S.len() as u16,
        &x_i,
        &X,
        key_share.core.shared_public_key + Shift,
        dec_i,
        &R,
        message_to_sign,
        enforce_reliable_broadcast,
        cached_precompute_tables,
        false,
    )
    .await
}

/// Original CGGMP n-out-of-n signing
///
/// Implementation has very little differences compared to original CGGMP protocol: we added broadcast
/// reliability check, fixed some typos in CGGMP, etc. Differences are covered in the specs.
use fast_paillier::precomputed_table;

use paillier_zk::fast_paillier::AnyEncryptionKey;
async fn signing_n_out_of_n<M, E, L, D, R>(
    mut tracer: Option<&mut dyn Tracer>,
    rng: &mut R,
    party: M,
    sid: ExecutionId<'_>,
    i: PartyIndex,
    n: u16,
    x_i: &NonZero<SecretScalar<E>>,
    X: &[NonZero<Point<E>>],
    pk: Point<E>,
    dec_i: &fast_paillier::DecryptionKey,
    R: &[PartyAux],
    message_to_sign: Option<DataToSign<E>>,
    enforce_reliable_broadcast: bool,
    cached_precompute_tables: Option<&[fast_paillier::precomputed_table::PrecomputeTable]>,
    enable_precompute_table: bool,
) -> Result<ProtocolOutput<E>, SigningError>
where
    M: Mpc<ProtocolMessage = Msg<E, D>>,
    E: Curve,
    L: SecurityLevel,
    D: Digest<OutputSize = digest::typenum::U32> + Clone + 'static,
    R: RngCore + CryptoRng,
    NonZero<Point<E>>: AlwaysHasAffineX<E>,
{
    std::println!("enable_precompute_table: {}", enable_precompute_table);
    let MpcParty {
        delivery, runtime, ..
    } = party.into_party();
    let (incomings, mut outgoings) = delivery.split();

    tracer.stage("Retrieve auxiliary data");
    let R_i = &R[usize::from(i)];
    let N_i = &R_i.N;

    tracer.stage("Precompute execution id and security params");
    let security_params = crate::utils::SecurityParams::new::<L>();

    std::println!("signing_n_out_of_n: 3");

    tracer.stage("Setup networking");
    let mut rounds = RoundsRouter::<Msg<E, D>>::builder();
    let round1a = rounds.add_round(RoundInput::<MsgRound1a<E>>::broadcast(i, n));
    let round1b = rounds.add_round(RoundInput::<MsgRound1b<E>>::p2p(i, n));
    let round1a_sync = rounds.add_round(RoundInput::<MsgReliabilityCheck<D>>::broadcast(i, n));
    let round2 = rounds.add_round(RoundInput::<MsgRound2<E>>::p2p(i, n));
    let round3 = rounds.add_round(RoundInput::<MsgRound3<E>>::p2p(i, n));
    let round4 = rounds.add_round(RoundInput::<MsgRound4<E>>::broadcast(i, n));
    let mut rounds = rounds.listen(incomings);

    std::println!("signing_n_out_of_n: 4");

    // Round 1
    tracer.round_begins();

    tracer.stage("Generate local ephemeral secrets (k_i, gamma_i, rho_i, nu_i)");
    // k_i, gamma_i in F_q
    let k_i = Scalar::<E>::random(rng);
    let gamma_i = Scalar::<E>::random(rng);

    // rho_i, nu_i in Z_{N_i}*
    // let rho_i = BigInt::gen_invertible(N_i, rng);
    // let nu_i = BigInt::gen_invertible(N_i, rng);
    let rho_i = fast_paillier::utils::sample_with_size(rng, dec_i.nounce_size());
    let nu_i = fast_paillier::utils::sample_with_size(rng, dec_i.nounce_size());
    std::println!("signing_n_out_of_n: 5");

    tracer.stage("Encrypt k_i and gamma_i");
    // K_i = enc_i(k_i, rho_i)

    let ek_i = dec_i.encryption_key();

    tracer.stage("Encrypt k_i and gamma_i");

    let (K_i, G_i, precompute_dec_i) = if enable_precompute_table {
        // Use cached precompute table if available, otherwise create a new one
        let precomputable = if let Some(cached_tables) = cached_precompute_tables {
            if let Some(cached_table) = cached_tables.get(usize::from(i)) {
                std::println!("cached_tables not null: {:?}", i);
                cached_table.clone()
            } else {
                std::println!("cached_tables null: {:?}", i);
                // Fallback to creating a new table if not enough cached tables
                let h_pow_n = ek_i.h_pow_n().clone();
                let nn = ek_i.nn().clone();
                let a_size = ek_i.a_size() as usize;
                precomputed_table::PrecomputeTable::new_dp(h_pow_n, 10, a_size, nn)
            }
        } else {
            // No cached tables available, create a new one
            std::println!("cached_tables null: {:?}", i);
            let h_pow_n = ek_i.h_pow_n().clone();
            let nn = ek_i.nn().clone();
            let a_size = ek_i.a_size() as usize;
            precomputed_table::PrecomputeTable::new_dp(h_pow_n, 10, a_size, nn)
        };

        let K_i = ek_i
            .encrypt_with_precompute_table(
                rng,
                &precomputable,
                &utils::scalar_to_bignumber(&k_i),
                Some(&rho_i),
            )
            .map_err(|e| Bug::PaillierEnc(BugSource::K_i, e))?;
        // G_i = enc_i(gamma_i, nu_i)
        let G_i = ek_i
            .encrypt_with_precompute_table(
                rng,
                &precomputable,
                &utils::scalar_to_bignumber(&gamma_i),
                Some(&nu_i),
            )
            .map_err(|e| Bug::PaillierEnc(BugSource::G_i, e))?;
        (K_i, G_i, Some(precomputable))
    } else {
        std::println!("encrypt without precompute table");
        let K_i = ek_i
            .encrypt_with(&utils::scalar_to_bignumber(&k_i), &rho_i)
            .map_err(|e| Bug::PaillierEnc(BugSource::K_i, e))?;
        let G_i = ek_i
            .encrypt_with(&utils::scalar_to_bignumber(&gamma_i), &nu_i)
            .map_err(|e| Bug::PaillierEnc(BugSource::G_i, e))?;
        (K_i, G_i, None)
    };

    // TODO: sample Y_i <- G; a_i, b_i <- F_q (G is elliptic curve point, F_q is field element) (DONE)
    let Y_i = Point::generator() * Scalar::<E>::random(rng);

    let a_i = Scalar::random(rng);
    let b_i = Scalar::random(rng);
    // Set (A_{i,1}, A_{i,2}) = (g^{a_i}, Y_i^{a_i}.g^{k_i})
    // Set (B_{i,1}, B_{i,2}) = (g^{b_i}, Y_i^{b_i}.g^{gamma_i})

    // NOTE: elg commit
    let (A_i1, A_i2) = (
        Point::generator() * &a_i,
        Y_i * &a_i + Point::generator() * &k_i,
    );
    let (B_i1, B_i2) = (
        Point::generator() * &b_i,
        Y_i * &b_i + Point::generator() * &gamma_i,
    );

    // TODO: broadcast (Y_i, A_{i,1}, A_{i,2}, B_{i,1}, B_{i,2}) (DONE)
    std::println!("signing_n_out_of_n: 6");

    tracer.send_msg();
    outgoings
        .feed(Outgoing::broadcast(Msg::Round1a(MsgRound1a {
            K_i: K_i.clone(),
            G_i: G_i.clone(),
            Y_i: Y_i.clone(),
            A_i1: A_i1.clone(),
            A_i2: A_i2.clone(),
            B_i1: B_i1.clone(),
            B_i2: B_i2.clone(),
        })))
        .await
        .map_err(IoError::send_message)?;
    tracer.msg_sent();

    std::println!("signing_n_out_of_n: 7");

    for j in utils::iter_peers(i, n) {
        tracer.stage("Prove ψ_ji");
        let R_j = &R[usize::from(j)];

        // TODO: replace pi_enc with pi_enc_elg (DONE)
        // TODO: Batch proof
        let psi_enc_ji = pi_enc_el_gamal_batch::non_interactive::prove::<E, D>(
            &unambiguous::ProofEnc { sid, prover: i },
            &R_j.into(),
            pi_enc_el_gamal_batch::PublicData {
                // TODO: Does decryption key leak any serious information if it is stored in Data
                // CGGMP21 does not pass key into Data
                key: dec_i,
                a: &Y_i,
                batch: &Vec::from([
                    pi_enc_el_gamal_batch::PublicElement {
                        ciphertext: K_i.clone(),
                        b: A_i1,
                        x: A_i2,
                    },
                    pi_enc_el_gamal_batch::PublicElement {
                        ciphertext: G_i.clone(),
                        b: B_i1,
                        x: B_i2,
                    },
                ]),
            },
            pi_enc_el_gamal_batch::PrivateData {
                batch: &Vec::from([
                    pi_enc_el_gamal_batch::PrivateElement {
                        plaintext: &utils::scalar_to_bignumber(&k_i),
                        nonce: &rho_i,
                        b: &a_i,
                    },
                    pi_enc_el_gamal_batch::PrivateElement {
                        plaintext: &utils::scalar_to_bignumber(&gamma_i),
                        nonce: &nu_i,
                        b: &b_i,
                    },
                ]),
            },
            &security_params.pi_enc_el_gamal_batch,
            &mut *rng,
            2,
        )
        .map_err(|e| Bug::PiEncElgGamalBatch(BugSource::psi_ji, e))?;

        tracer.send_msg();
        outgoings
            .feed(Outgoing::p2p(j, Msg::Round1b(MsgRound1b { psi_enc_ji })))
            .await
            .map_err(IoError::send_message)?;
        tracer.msg_sent();
    }
    tracer.send_msg();
    outgoings.flush().await.map_err(IoError::send_message)?;
    tracer.msg_sent();

    std::println!("signing_n_out_of_n: 8");

    // Round 2
    tracer.round_begins();

    tracer.receive_msgs();
    // Contains G_j, K_j sent by other parties
    // TODO: round 1a not only contains ciphertexts, it also contains Y_i, A_{i,1}, A_{i,2}, B_{i,1}, B_{i,2} (DONE)
    let round1a_msgs = rounds
        .complete(round1a)
        .await
        .map_err(IoError::receive_message)?;

    // TODO: (psi0_ji, psi1_ji) --> psi_ji (batch proof of enc-elg)
    let round1b_msgs = rounds
        .complete(round1b)
        .await
        .map_err(IoError::receive_message)?;
    tracer.msgs_received();

    std::println!("signing_n_out_of_n: 9");
    // Reliability check (if enabled)
    if enforce_reliable_broadcast {
        tracer.stage("Hash received msgs (reliability check)");
        let h_i = udigest::hash_iter::<D>(
            round1a_msgs
                .iter_including_me(&MsgRound1a {
                    // TODO: round 1a not only contains K_i, G_i (DONE)
                    K_i: K_i.clone(),
                    G_i: G_i.clone(),
                    Y_i: Y_i.clone(),
                    A_i1: A_i1.clone(),
                    A_i2: A_i2.clone(),
                    B_i1: B_i1.clone(),
                    B_i2: B_i2.clone(),
                })
                .map(|msg| unambiguous::Echo { sid, msg }),
        );

        tracer.send_msg();
        outgoings
            .send(Outgoing::broadcast(Msg::ReliabilityCheck(
                MsgReliabilityCheck(h_i),
            )))
            .await
            .map_err(IoError::send_message)?;
        tracer.msg_sent();

        tracer.round_begins();

        tracer.receive_msgs();
        let round1a_hashes = rounds
            .complete(round1a_sync)
            .await
            .map_err(IoError::receive_message)?;
        tracer.msgs_received();
        tracer.stage("Assert other parties hashed messages (reliability check)");
        let parties_have_different_hashes = round1a_hashes
            .into_iter_indexed()
            .filter(|(_j, _msg_id, hash)| hash.0 != h_i)
            .map(|(j, msg_id, _)| (j, msg_id))
            .collect::<Vec<_>>();
        if !parties_have_different_hashes.is_empty() {
            return Err(SigningAborted::Round1aNotReliable(parties_have_different_hashes).into());
        }
    }
    std::println!("signing_n_out_of_n: 10");
    // Step 1. Verify proofs
    // TODO: pi_enc --> pi_enc_elg (DONE)
    // TODO: batch proof
    tracer.stage("Verify psi_ji proofs");
    {
        let mut faulty_parties = vec![];
        for ((j, msg1a_id, round1a_msg), (_, msg1b_id, round1b_msg)) in
            round1a_msgs.iter_indexed().zip(round1b_msgs.iter_indexed())
        {
            let R_j = &R[usize::from(j)];
            // TODO: pi_enc --> pi_enc_elg (DONE)
            // TODO: batch proof
            let verify_psi_enc_ji = pi_enc_el_gamal_batch::non_interactive::verify::<E, D>(
                &unambiguous::ProofEnc { sid, prover: j },
                &R_i.into(),
                pi_enc_el_gamal_batch::PublicData {
                    a: &round1a_msg.Y_i,
                    key: &R_j.enc.clone(),
                    batch: &Vec::from([
                        pi_enc_el_gamal_batch::PublicElement {
                            ciphertext: round1a_msg.K_i.clone(),
                            b: round1a_msg.A_i1,
                            x: round1a_msg.A_i2,
                        },
                        pi_enc_el_gamal_batch::PublicElement {
                            ciphertext: round1a_msg.G_i.clone(),
                            b: round1a_msg.B_i1,
                            x: round1a_msg.B_i2,
                        },
                    ]),
                    // data of party j (from round1a_msg and round1b_msg)
                },
                &round1b_msg.psi_enc_ji.0,
                &round1b_msg.psi_enc_ji.1,
                &security_params.pi_enc_el_gamal_batch,
                2,
            );
            match verify_psi_enc_ji {
                Ok(_) => {}
                Err(e) => faulty_parties.push((j, msg1a_id, msg1b_id, e)),
            }

            if !faulty_parties.is_empty() {
                return Err(SigningAborted::EncElgGamalBatchProofOfKorG(faulty_parties).into());
            }
        }
    }
    runtime.yield_now().await;

    // Step 2
    // Gamma_i = G * gamma_i
    let Gamma_i = Point::generator() * &gamma_i;
    let J = BigInt::from(1) << L::ELL_PRIME;

    // TODO: psi_i = pi_elog::prove(Data: (Gamma_i, g, B_{i,1}, B_{i,2}, Y_i), PrivateData: (gamma_i, b_i))) (DONE)
    let psi_i = pi_elog::non_interactive::prove::<E, D>(
        &unambiguous::ProofLog {
            sid,
            prover: i,
            prime_prime: false,
        },
        pi_elog::Data {
            l: &B_i1,
            m: &B_i2,
            x: &Y_i,
            y: &Gamma_i,
            h: &Point::<E>::generator().to_point(),
        },
        pi_elog::PrivateData {
            y: &gamma_i,
            lambda: &b_i,
        },
        &mut *rng,
    )
    .map_err(|e| Bug::PiELog(BugSource::psi_i, e))?;
    // J = 2^{ell}

    // Q: what are beta_sum, hat_beta_sum?
    let mut beta_sum = Scalar::zero();
    let mut hat_beta_sum = Scalar::zero();

    // Create precompute table for dec_i (used for encryption)
    let dec_i_ek = dec_i.encryption_key();

    // Create precompute tables for all enc_j upfront
    
    let mut precompute_tables_j = if enable_precompute_table {
        let mut precompute_tables_j = std::collections::HashMap::new();
        for (j, _, _) in round1a_msgs.iter_indexed() {
            let R_j = &R[usize::from(j)];
            let enc_j = &R_j.enc;
    
            // Use cached precompute table if available, otherwise create a new one
            let precompute_enc_j = if let Some(cached_tables) = cached_precompute_tables {
                if let Some(cached_table) = cached_tables.get(usize::from(j)) {
                    cached_table.clone()
                } else {
                    // Fallback to creating a new table if not enough cached tables
                    precomputed_table::PrecomputeTable::new_dp(
                        enc_j.h_pow_n().clone(),
                        5,
                        enc_j.a_size() as usize,
                        enc_j.nn().clone(),
                    )
                }
            } else {
                // No cached tables available, create a new one
                precomputed_table::PrecomputeTable::new_dp(
                    enc_j.h_pow_n().clone(),
                    5,
                    enc_j.a_size() as usize,
                    enc_j.nn().clone(),
                )
            };
    
            precompute_tables_j.insert(j, precompute_enc_j);
        }
        precompute_tables_j
    } else {
        std::collections::HashMap::new()
    };

    for (j, _, round1a_msg) in round1a_msgs.iter_indexed() {
        tracer.stage("Sample random r, hat_r, s, hat_s, beta, hat_beta");
        let R_j = &R[usize::from(j)];
        let enc_j = &R_j.enc.clone();

        // Get the precomputed table for this party j

        // r_ij, hat_r_ij, s_ij, hat_s_ij in Z_Nj
        // TODO: N_j or N_i here => N_i (DONE)
        // let r_ij = rng.gen_bigint_range(&BigInt::from(0), &N_i);
        let r_ij = fast_paillier::utils::sample_with_size(rng, dec_i.nounce_size());
        // let hat_r_ij = rng.gen_bigint_range(&BigInt::from(0), &N_i);
        let hat_r_ij = fast_paillier::utils::sample_with_size(rng, dec_i.nounce_size());
        // let s_ij = rng.gen_bigint_range(&BigInt::from(0), &N_i);
        let s_ij = fast_paillier::utils::sample_with_size(rng, dec_i.nounce_size());
        // let hat_s_ij = rng.gen_bigint_range(&BigInt::from(0), &N_i);
        let hat_s_ij = fast_paillier::utils::sample_with_size(rng, dec_i.nounce_size());

        // 0 <= beta_ij, hat_beta_ij < J
        let beta_ij = BigInt::from_rng_pm(&J, rng);
        let hat_beta_ij = BigInt::from_rng_pm(&J, rng);

        beta_sum += beta_ij.to_scalar();
        hat_beta_sum += hat_beta_ij.to_scalar();

        tracer.stage("Encrypt D_ji");
        
        let gamma_i_times_K_j = enc_j
            .omul(&utils::scalar_to_bignumber(&gamma_i), &round1a_msg.K_i)
            .map_err(|e| Bug::PaillierOp(BugSource::gamma_i_times_K_j, e))?;

        let D_ji = if enable_precompute_table {
            let precompute_enc_j = &precompute_tables_j[&j];
            // enc_j(-beta_ij, s_ij) using precompute table
            let neg_beta_ij_enc = enc_j
                .encrypt_with_precompute_table(rng, precompute_enc_j, &(-&beta_ij), Some(&s_ij))
                .map_err(|e| Bug::PaillierEnc(BugSource::neg_beta_ij_enc, e))?;
            // D_ji = gamma_i * K_j + enc_j(-beta_ij, s_ij) ~ ciphertext + ciphertext
            enc_j
                .oadd(&gamma_i_times_K_j, &neg_beta_ij_enc)
                .map_err(|e| Bug::PaillierOp(BugSource::D_ji, e))?
        } else {
            std::println!("encrypt without precompute table");
            let neg_beta_ij_enc = enc_j
                .encrypt_with(&(-&beta_ij), &s_ij)
                .map_err(|e| Bug::PaillierEnc(BugSource::neg_beta_ij_enc, e))?;
            // D_ji = gamma_i * K_j + enc_j(-beta_ij, s_ij) ~ ciphertext + ciphertext
            enc_j
                .oadd(&gamma_i_times_K_j, &neg_beta_ij_enc)
                .map_err(|e| Bug::PaillierOp(BugSource::D_ji, e))?
        };
        
        std::println!("signing_n_out_of_n: 11");

        tracer.stage("Encrypt F_ji");
        // F_ji = enc_i(beta_ij, r_ij) using precompute table
        let F_ji = if enable_precompute_table {
            if let Some(ref precompute_dec_i) = precompute_dec_i {
                dec_i_ek
                    .encrypt_with_precompute_table(rng, precompute_dec_i, &(-&beta_ij), Some(&r_ij))
                    .map_err(|e| Bug::PaillierEnc(BugSource::F_ji, e))?
            } else {
                dec_i_ek
                    .encrypt_with(&(-&beta_ij), &r_ij)
                    .map_err(|e| Bug::PaillierEnc(BugSource::F_ji, e))?
            }
        } else {
            std::println!("encrypt without precompute table");
            dec_i_ek
                .encrypt_with(&(-&beta_ij), &r_ij)
                .map_err(|e| Bug::PaillierEnc(BugSource::F_ji, e))?
        };

        tracer.stage("Encrypt hat_D_ji");
        // Dˆ_ji = (x_i * K_j) + enc_j(-hat_beta_ij, hat_s_ij)
        let hat_D_ji = {
            // x_i * K_j ~ scalar * ciphertext
            let x_i_times_K_j = enc_j
                .omul(&utils::scalar_to_bignumber(x_i), &round1a_msg.K_i)
                .map_err(|e| Bug::PaillierOp(BugSource::x_i_times_K_j, e))?;
            // enc_j(-hat_beta_ij, hat_s_ij) using precompute table
            let neg_hat_beta_ij_enc = if let Some(precompute_enc_j) = precompute_tables_j.get(&j) {
                enc_j
                    .encrypt_with_precompute_table(
                        rng,
                        precompute_enc_j,
                        &(-&hat_beta_ij),
                        Some(&hat_s_ij),
                    )
                    .map_err(|e| Bug::PaillierEnc(BugSource::neg_hat_beta_ij_enc, e))?
            } else {
                enc_j
                    .encrypt_with(&(-&hat_beta_ij), &hat_s_ij)
                    .map_err(|e| Bug::PaillierEnc(BugSource::neg_hat_beta_ij_enc, e))?
            };
            // hat_D_ji = x_i * K_j + enc_j(-hat_beta_ij, hat_s_ij) ~ ciphertext + ciphertext
            enc_j
                .oadd(&x_i_times_K_j, &neg_hat_beta_ij_enc)
                .map_err(|e| Bug::PaillierOp(BugSource::hat_D_ji, e))?
        };
        runtime.yield_now().await;

        tracer.stage("Encrypt hat_F_ji");
        // Fˆ_ji = enc_i(hat_beta_ij, hat_r_ij) using precompute table
        let hat_F_ji = if let Some(ref precompute_dec_i) = precompute_dec_i {
            dec_i_ek
                .encrypt_with_precompute_table(
                    rng,
                    precompute_dec_i,
                    &(-&hat_beta_ij),
                    Some(&hat_r_ij),
                )
                .map_err(|e| Bug::PaillierEnc(BugSource::hat_F_ji, e))?
        } else {
            dec_i_ek
                .encrypt_with(&(-&hat_beta_ij), &hat_r_ij)
                .map_err(|e| Bug::PaillierEnc(BugSource::hat_F_ji, e))?
        };

        tracer.stage("Prove psi_ji");
        // TODO: batch pi_aff_g (psi_ji, hat_psi_ji)
        let psi_aff_ji = pi_aff_batch::non_interactive::prove::<E, D>(
            &unambiguous::ProofPsi {
                sid,
                prover: i,
                hat: false,
            },
            &R_j.into(),
            pi_aff_batch::PublicData {
                key0: enc_j,
                key1: dec_i,
                batch: vec![
                    pi_aff_batch::PublicElement {
                        c: round1a_msg.K_i.clone(), // K_j
                        d: D_ji.clone(),
                        y: F_ji.clone(),
                        x: Gamma_i.clone(), // MtA(k, gamma)
                    },
                    pi_aff_batch::PublicElement {
                        c: round1a_msg.K_i.clone(), // K_j
                        d: hat_D_ji.clone(),
                        y: hat_F_ji.clone(),
                        x: *(Point::generator() * x_i.clone()), // MtA(k, x)},
                    },
                ],
            },
            pi_aff_batch::PrivateData {
                batch: vec![
                    pi_aff_batch::PrivateElement {
                        x: &utils::scalar_to_bignumber(&gamma_i),
                        y: &(-&beta_ij),
                        nonce: &s_ij,
                        nonce_y: &r_ij,
                    },
                    pi_aff_batch::PrivateElement {
                        x: &utils::scalar_to_bignumber(x_i),
                        y: &(-&hat_beta_ij),
                        nonce: &hat_s_ij,
                        nonce_y: &hat_r_ij,
                    },
                ],
            },
            &security_params.pi_aff_batch,
            &mut *rng,
            2,
        )
        .map_err(|e| Bug::PiAffG(BugSource::psi_ji, e))?;
        runtime.yield_now().await;

        tracer.send_msg();
        outgoings
            .feed(Outgoing::p2p(
                j,
                Msg::Round2(MsgRound2 {
                    // remove psi_prime
                    // add psi(elog)
                    Gamma_i,
                    psi_i: psi_i.clone(),
                    D_ji,
                    F_ji,
                    hat_D_ji,
                    hat_F_ji,
                    psi_aff_ji,
                }),
            ))
            .await
            .map_err(IoError::send_message)?;
        tracer.msg_sent();
    }
    tracer.send_msg();
    outgoings.flush().await.map_err(IoError::send_message)?;
    tracer.msg_sent();

    // Round 3
    tracer.round_begins();

    // Step 1
    tracer.receive_msgs();
    let round2_msgs = rounds
        .complete(round2)
        .await
        .map_err(IoError::receive_message)?;
    tracer.msgs_received();

    let mut faulty_parties = vec![];
    for ((j, msg_id, msg), (_, round1a_msg_id, round1a_msg)) in
        round2_msgs.iter_indexed().zip(round1a_msgs.iter_indexed())
    {
        tracer.stage("Retrieve auxiliary data");
        let X_j = X[usize::from(j)];
        let R_j = &R[usize::from(j)];
        let enc_j = R_j.enc.clone();

        // TODO: batch verify pi_aff_g
        tracer.stage("Validate psi_ji");
        let psi_aff_ji_invalid = pi_aff_batch::non_interactive::verify::<E, D>(
            &unambiguous::ProofPsi {
                sid,
                prover: j,
                hat: false,
            },
            &R_i.into(),
            pi_aff_batch::PublicData {
                key0: dec_i,  // verifier key
                key1: &enc_j, // prover key
                batch: vec![
                    pi_aff_batch::PublicElement {
                        c: K_i.clone(), // from verifier
                        d: msg.D_ji.clone(),
                        y: msg.F_ji.clone(),
                        x: msg.Gamma_i.clone(),
                    },
                    pi_aff_batch::PublicElement {
                        c: K_i.clone(), // from verifier
                        d: msg.hat_D_ji.clone(),
                        y: msg.hat_F_ji.clone(),
                        x: *X_j.clone(),
                    },
                ],
            },
            &msg.psi_aff_ji.0,
            &security_params.pi_aff_batch,
            &msg.psi_aff_ji.1,
            2,
        )
        .err();

        // TODO: replace with validate psi(elog)
        tracer.stage("Validate psi_j");
        let psi_j_invalid = pi_elog::non_interactive::verify::<E, D>(
            &unambiguous::ProofLog {
                sid,
                prover: j,
                prime_prime: false,
            },
            pi_elog::Data {
                l: &round1a_msg.B_i1,
                m: &round1a_msg.B_i2,
                x: &round1a_msg.Y_i,
                y: &msg.Gamma_i,
                h: &Point::<E>::generator().to_point(),
            },
            &msg.psi_i.0,
            &msg.psi_i.1,
        )
        .err();

        if psi_aff_ji_invalid.is_some() || psi_j_invalid.is_some() {
            faulty_parties.push((
                j,
                round1a_msg_id,
                msg_id,
                (psi_aff_ji_invalid, psi_j_invalid),
            ))
        }
        runtime.yield_now().await;
    }

    if !faulty_parties.is_empty() {
        return Err(SigningAborted::InvalidPsi(faulty_parties).into());
    }

    std::println!("signing_n_out_of_n: 12");

    // Step 2
    tracer.stage("Compute Gamma, Delta_i, delta_i, chi_i");
    // Gamma = sum(Gamma_i)
    let Gamma = Gamma_i + round2_msgs.iter().map(|msg| msg.Gamma_i).sum::<Point<E>>();
    // Delta_i = Gamma * k_i
    let Delta_i = Gamma * &k_i;

    // (gamma_i, k_j) --MtA--> (alpha_ij, beta_ij)
    // gamma_i * k_j = alpha_ij + beta_ij
    // => alpha_ij = gamma_i * k_j - beta_ij = dec_j(D_ji)
    // D_ji = enc_j(gamma_i * k_j - beta_ij)
    // alpha_sum = sum(dec_j(D_ji)) = sum(alpha_ij)
    let alpha_sum =
        round2_msgs
            .iter()
            .map(|msg| &msg.D_ji)
            .try_fold(Scalar::<E>::zero(), |sum, D_ij| {
                let alpha_ij = dec_i
                    .decrypt(D_ij)
                    .map_err(|e| Bug::PaillierDec(BugSource::alpha_ij, e))?;
                Ok::<_, Bug>(sum + alpha_ij.to_scalar())
            })?;

    // (x_i, k_j) --MtA--> (hat_alpha_ij, hat_beta_ij)
    // x_i * k_j = hat_alpha_ij + hat_beta_ij
    // => hat_alpha_ij = x_i * k_j - hat_beta_ij = dec_j(hat_D_ji)
    // hat_D_ji = enc_j(x_i * k_j - hat_beta_ij)
    // hat_alpha_sum = sum(dec_j(hat_D_ji)) = sum(hat_alpha_ij)
    let hat_alpha_sum =
        round2_msgs
            .iter()
            .map(|msg| &msg.hat_D_ji)
            .try_fold(Scalar::zero(), |sum, hat_D_ij| {
                let hat_alpha_ij = dec_i
                    .decrypt(hat_D_ij)
                    .map_err(|e| Bug::PaillierDec(BugSource::hat_alpha_ij, e))?;
                Ok::<_, Bug>(sum + hat_alpha_ij.to_scalar())
            })?;

    // delta_i = gamma_i * k_i + alpha_sum + beta_sum
    let delta_i = gamma_i.as_ref() * k_i.as_ref() + alpha_sum + beta_sum;
    // chi_i = x_i * k_i + hat_alpha_sum + hat_beta_sum
    let chi_i = x_i * k_i.as_ref() + hat_alpha_sum + hat_beta_sum;
    // TODO: S_i = Gamma^{chi_i} (DONE)
    let S_i = Gamma * chi_i;
    runtime.yield_now().await;

    // TODO: pi_elog::prove(Data: (Delta_i, Gamma, A_{i,1}, A_{i,2}, Y_i), PrivateData: (k_i, a_i)) (DONE)
    // TODO: remove Prove psi_prime_prime (DONE)
    std::println!("signing_n_out_of_n: 13");
    for j in utils::iter_peers(i, n) {
        tracer.stage("Prove hat_psi_i");
        // pi_log: prove K_i = enc(k_i, rho_i) and Delta_i = Gamma * k_i = G * sum(gamma_j) * k_i
        let hat_psi_i = pi_elog::non_interactive::prove::<E, D>(
            &unambiguous::ProofLog {
                sid,
                prover: i,
                prime_prime: false,
            },
            pi_elog::Data {
                l: &A_i1,
                m: &A_i2,
                x: &Y_i,
                y: &Delta_i,
                h: &Gamma,
            },
            pi_elog::PrivateData {
                y: &k_i,
                lambda: &a_i,
            },
            &mut *rng,
        )
        .map_err(|e| Bug::PiELog(BugSource::hat_psi_i, e))?;

        // TODO: send message p2p: (delta_i, S_i, Delta_i, psi_i) (DONE)
        tracer.send_msg();
        outgoings
            .feed(Outgoing::p2p(
                j,
                Msg::Round3(MsgRound3 {
                    // TODO: (delta_i, S_i, Delta_i, hat_psi_i) (DONE)
                    delta_i,
                    S_i,
                    Delta_i,
                    hat_psi_i,
                }),
            ))
            .await
            .map_err(IoError::send_message)?;
        tracer.msg_sent();
    }
    tracer.send_msg();
    outgoings.flush().await.map_err(IoError::send_message)?;
    tracer.msg_sent();
    std::println!("signing_n_out_of_n: 14");
    // Output
    tracer.named_round_begins("Presig output");

    // Step 1
    tracer.receive_msgs();
    let round3_msgs = rounds
        .complete(round3)
        .await
        .map_err(IoError::receive_message)?;
    tracer.msgs_received();

    // TODO: replace by validate elog (DONE)
    tracer.stage("Validate hat_psi_j");
    let mut faulty_parties = vec![];
    for ((j, msg_id, msg_j), (_, round1a_msg_id, round1a_msg)) in
        round3_msgs.iter_indexed().zip(round1a_msgs.iter_indexed())
    {
        let data = pi_elog::Data {
            l: &round1a_msg.A_i1,
            m: &round1a_msg.A_i2,
            x: &round1a_msg.Y_i,
            y: &msg_j.Delta_i,
            h: &Gamma,
        };

        if pi_elog::non_interactive::verify::<E, D>(
            &unambiguous::ProofLog {
                sid,
                prover: j,
                prime_prime: false,
            },
            data,
            &msg_j.hat_psi_i.0,
            &msg_j.hat_psi_i.1,
        )
        .is_err()
        {
            faulty_parties.push((j, round1a_msg_id, msg_id))
        }
    }
    runtime.yield_now().await;

    // TODO: error here (DONE)
    if !faulty_parties.is_empty() {
        return Err(SigningAborted::InvalidHatPsi(faulty_parties).into());
    }
    std::println!("signing_n_out_of_n: 15");
    // Step 2
    tracer.stage("Calculate presignature");
    // delta = delta_i + sum(delta_j) = gamma * k
    let delta = delta_i + round3_msgs.iter().map(|m| m.delta_i).sum::<Scalar<E>>();
    // Delta = Gamma * k = G * gamma * k
    let Delta = Delta_i + round3_msgs.iter().map(|m| m.Delta_i).sum::<Point<E>>();

    if Point::generator() * delta != Delta {
        // Following the protocol, party should broadcast additional proofs
        // to convince others it didn't cheat. However, since identifiable
        // abort is not implemented yet, this part of the protocol is missing
        return Err(SigningAborted::MismatchedDelta.into());
    }

    // TODO: check X^delta = pi(S_j) = (S1 * S2 * S3 ... * Sn) (DONE)
    // X is public key
    let X = pk;
    let S = S_i + round3_msgs.iter().map(|m| m.S_i).sum::<Point<E>>();
    if X * delta != S {
        return Err(SigningAborted::MismatchedS.into());
    }

    // TODO: presignature (Gamma, k_i / delta, Chi_i / delta, (Delta_j^(delta^{-1}), S_j^{delta^{-1}})j \in P) (DONE)

    let delta_inv = delta.invert().ok_or(Bug::ZeroDelta)?;
    let hat_k_i = k_i * delta_inv;
    let hat_chi_i = chi_i * delta_inv;
    let mut hat_Delta_j = round3_msgs
        .iter()
        .map(|m| m.Delta_i * delta_inv)
        .collect::<Vec<_>>();

    hat_Delta_j.insert(i as usize, Delta_i * delta_inv);

    let mut hat_S_j = round3_msgs
        .iter()
        .map(|m| m.S_i * delta_inv)
        .collect::<Vec<_>>();
    hat_S_j.insert(i as usize, S_i * delta_inv);

    let presig = Presignature {
        Gamma: NonZero::from_point(Gamma).ok_or(Bug::ZeroGamma)?,
        hat_k_i,
        hat_chi_i,
        hat_Delta_j,
        hat_S_j,
    };

    // If message is not specified, protocol terminates here and outputs partial
    // signature
    let Some(message_to_sign) = message_to_sign else {
        tracer.protocol_ends();
        return Ok(ProtocolOutput::Presignature(presig));
    };
    std::println!("signing_n_out_of_n: 16");
    // Signing
    tracer.named_round_begins("Partial signing");

    // Round 1
    // TODO: calculate partial_sigature (DONE)
    let partial_sigature = presig.clone().issue_partial_signature(message_to_sign)?;

    tracer.send_msg();
    outgoings
        .send(Outgoing::broadcast(Msg::Round4(MsgRound4 {
            // sigma_i = k_i * m + r_i * chi_i
            sigma_i: partial_sigature.sigma_i,
        })))
        .await
        .map_err(IoError::send_message)?;
    tracer.msg_sent();

    // TODO: erase (Gamma, hat_k_i, hat_Chi_i) from memory
    // Output
    tracer.named_round_begins("Signature reconstruction");

    tracer.receive_msgs();
    let partial_sigs = rounds
        .complete(round4)
        .await
        .map_err(IoError::receive_message)?;
    tracer.msgs_received();

    // TODO: check Gamma^{sigma_j} = hat_Delta_j^m * hat_S_j^r (for all j in P)
    for (j, _msg_id, msg_j) in partial_sigs.iter_indexed() {
        let presig_clone = presig.clone();
        let Gamma = presig_clone.Gamma;
        let hat_Delta_j = presig_clone.hat_Delta_j[usize::from(j)];
        let hat_S_j = presig_clone.hat_S_j[usize::from(j)];
        let sigma_j = msg_j.sigma_i;
        let m = message_to_sign.to_scalar();
        let r = partial_sigature.r;
        if Gamma * sigma_j != hat_Delta_j * m + hat_S_j * r {
            return Err(SigningAborted::SignatureInvalid.into());
        }
    }

    std::println!("signing_n_out_of_n: 17");
    let sig = {
        let r = NonZero::from_scalar(partial_sigature.r);
        let s = NonZero::from_scalar(
            // s = sigma = sum(sigma_j)
            partial_sigature.sigma_i + partial_sigs.iter().map(|m| m.sigma_i).sum::<Scalar<E>>(),
        );
        Option::zip(r, s).map(|(r, s)| Signature { r, s }.normalize_s())
    };

    // NOTICE: This check wasn't in the original paper
    let sig_invalid = match &sig {
        Some(sig) => sig.verify(&pk, &message_to_sign).is_err(),
        None => true,
    };
    if sig_invalid {
        // Following the protocol, party should broadcast additional proofs
        // to convince others it didn't cheat. However, since identifiable
        // abort is not implemented yet, this part of the protocol is missing
        return Err(SigningAborted::SignatureInvalid.into());
    }
    let sig = sig.ok_or(SigningAborted::SignatureInvalid)?;

    std::println!("signing_n_out_of_n: 18");
    tracer.protocol_ends();
    Ok(ProtocolOutput::Signature(sig))
}

impl<E> Presignature<E>
where
    E: Curve,
    NonZero<Point<E>>: AlwaysHasAffineX<E>,
{
    /// Issues partial signature for given message
    ///
    /// **Never reuse presignatures!** If you use the same presignatures to sign two different
    /// messages, it leaks the private key!
    pub fn issue_partial_signature(
        self,
        message_to_sign: DataToSign<E>,
    ) -> Result<PartialSignature<E>, Bug> {
        let r = self.Gamma.x().to_scalar();
        let m = message_to_sign.to_scalar();
        let sigma_i = self.hat_k_i * m + r * self.hat_chi_i;
        Ok(PartialSignature { r, sigma_i })
    }
}

impl<E: Curve> Presignature<E> {
    /// Specifies HD derivation path
    ///
    /// Outputs a presignature that can be used to sign a message with a child
    /// key derived from master `epub` using `derivation_path`. Note that all
    /// signers need to set the same derivation path, otherwise output signature
    /// will be invalid.
    ///
    /// `epub` must be an [extended public
    /// key](crate::key_share::DirtyIncompleteKeyShare::extended_public_key)
    /// assoicated with the key share that was used to generate presignature.
    /// Using wrong `epub` will simply lead to invalid signature.
    ///
    /// ## Derivation algorithm
    /// This method uses [`hd_wallet::Slip10`] derivation algorithm, which can only be used with secp256k1
    /// and secp256r1 curves. If you need to use another one, see
    /// [`set_derivation_path_with_algo`](Self::set_derivation_path_with_algo)
    #[cfg(all(feature = "hd-wallet", feature = "hd-slip10"))]
    pub fn set_derivation_path<Index>(
        self,
        epub: hd_wallet::ExtendedPublicKey<E>,
        derivation_path: impl IntoIterator<Item = Index>,
    ) -> Result<Self, <Index as TryInto<hd_wallet::NonHardenedIndex>>::Error>
    where
        hd_wallet::Slip10: hd_wallet::HdWallet<E>,
        hd_wallet::NonHardenedIndex: TryFrom<Index>,
    {
        self.set_derivation_path_with_algo::<hd_wallet::Slip10, _>(epub, derivation_path)
    }

    /// Specifies HD derivation path
    ///
    /// Outputs a presignature that can be used to sign a message with a child
    /// key derived from master `epub` using `derivation_path`. Note that all
    /// signers need to set the same derivation path, otherwise output signature
    /// will be invalid.
    ///
    /// `epub` must be an [extended public
    /// key](crate::key_share::DirtyIncompleteKeyShare::extended_public_key)
    /// assoicated with the key share that was used to generate presignature.
    /// Using wrong `epub` will simply lead to invalid signature.
    #[cfg(feature = "hd-wallet")]
    pub fn set_derivation_path_with_algo<Hd: hd_wallet::HdWallet<E>, Index>(
        mut self,
        epub: hd_wallet::ExtendedPublicKey<E>,
        derivation_path: impl IntoIterator<Item = Index>,
    ) -> Result<Self, <Index as TryInto<hd_wallet::NonHardenedIndex>>::Error>
    where
        hd_wallet::NonHardenedIndex: TryFrom<Index>,
    {
        let additive_shift = derive_additive_shift::<E, Hd, _>(epub, derivation_path)?;

        let mut chi = self.chi + additive_shift * &self.k;
        self.chi = SecretScalar::new(&mut chi);

        Ok(self)
    }
}

#[cfg(feature = "hd-wallet")]
fn derive_additive_shift<E: Curve, Hd: hd_wallet::HdWallet<E>, Index>(
    mut epub: hd_wallet::ExtendedPublicKey<E>,
    path: impl IntoIterator<Item = Index>,
) -> Result<Scalar<E>, <Index as TryInto<hd_wallet::NonHardenedIndex>>::Error>
where
    hd_wallet::NonHardenedIndex: TryFrom<Index>,
{
    let mut additive_shift = Scalar::<E>::zero();

    for child_index in path {
        let child_index: hd_wallet::NonHardenedIndex = child_index.try_into()?;
        let shift = Hd::derive_public_shift(&epub, child_index);

        additive_shift += shift.shift;
        epub = shift.child_public_key;
    }

    Ok(additive_shift)
}

impl<E: Curve> PartialSignature<E> {
    /// Combines threshold amount of partial signatures into regular signature
    ///
    /// Returns `None` if input is malformed.
    ///
    /// `combine` may return a signature that's invalid for public key and message it was issued for.
    /// This would mean that some of signers cheated and aborted the protocol. You need to validate
    /// resulting signature to be sure that no one aborted the protocol.
    pub fn combine(partial_signatures: &[PartialSignature<E>]) -> Option<Signature<E>> {
        if partial_signatures.is_empty() {
            None
        } else {
            let r = NonZero::from_scalar(partial_signatures[0].r)?;
            let s = NonZero::from_scalar(partial_signatures.iter().map(|s| s.sigma_i).sum())?;
            Some(Signature { r, s }.normalize_s())
        }
    }
}

impl<E: Curve> Signature<E>
where
    NonZero<Point<E>>: AlwaysHasAffineX<E>,
{
    /// Verifies that signature matches specified public key and message
    pub fn verify(
        &self,
        public_key: &Point<E>,
        message: &DataToSign<E>,
    ) -> Result<(), InvalidSignature> {
        let r = (Point::generator() * message.to_scalar() + public_key * self.r) * self.s.invert();
        let r = NonZero::from_point(r).ok_or(InvalidSignature)?;

        if *self.r == r.x().to_scalar() {
            Ok(())
        } else {
            Err(InvalidSignature)
        }
    }
}

impl<E: Curve> Signature<E> {
    /// Create signature struct from `r` and `s` values
    pub fn from_raw_parts(r: NonZero<Scalar<E>>, s: NonZero<Scalar<E>>) -> Self {
        Self { r, s }
    }
    /// Normilizes the signature
    ///
    /// Given that $(r, s)$ is valid signature, $(r, -s)$ is also a valid signature. Some applications (like Bitcoin)
    /// remove this ambiguity by restricting $s$ to be in lower half. This method normailizes the signature by picking
    /// $s$ that is in lower half.
    ///
    /// Note that signing protocol implemented within this crate ouputs normalized signature by default.
    pub fn normalize_s(self) -> Self {
        let neg_s = -self.s;
        if neg_s < self.s {
            Signature { s: neg_s, ..self }
        } else {
            self
        }
    }

    /// Writes serialized signature to the bytes buffer
    ///
    /// Bytes buffer size must be at least [`Signature::serialized_len()`], otherwise content
    /// of output buffer is unspecified.
    pub fn write_to_slice(&self, out: &mut [u8]) {
        if out.len() < Self::serialized_len() {
            return;
        }
        let scalar_size = Scalar::<E>::serialized_len();
        out[0..scalar_size].copy_from_slice(&self.r.to_be_bytes());
        out[scalar_size..2 * scalar_size].copy_from_slice(&self.s.to_be_bytes());
    }

    /// Reads serialized signature from the bytes buffer.
    ///
    /// Bytes buffer size must be equal to [`Signature::serialized_len()`] and
    /// none of the signature parts should be 0. If this doesn't hold, returns
    /// `None`
    pub fn read_from_slice(inp: &[u8]) -> Option<Self> {
        if inp.len() != Self::serialized_len() {
            return None;
        }
        let r_bytes = &inp[0..inp.len() / 2];
        let s_bytes = &inp[inp.len() / 2..];
        let r = generic_ec::Scalar::from_be_bytes(r_bytes)
            .ok()?
            .try_into()
            .ok()?;
        let s = generic_ec::Scalar::from_be_bytes(s_bytes)
            .ok()?
            .try_into()
            .ok()?;
        Some(Self::from_raw_parts(r, s))
    }

    /// Returns size of bytes buffer that can fit serialized signature
    pub fn serialized_len() -> usize {
        2 * Scalar::<E>::serialized_len()
    }
}

enum ProtocolOutput<E: Curve> {
    Presignature(Presignature<E>),
    Signature(Signature<E>),
}

/// Error indicating that signing protocol failed
#[derive(Debug, Error)]
#[error("signing protocol failed")]
pub struct SigningError(#[source] Reason);

crate::errors::impl_from! {
    impl From for SigningError {
        err: InvalidArgs => SigningError(Reason::InvalidArgs(err)),
        err: InvalidKeyShare => SigningError(Reason::InvalidKeyShare(err)),
        err: SigningAborted => SigningError(Reason::Aborted(err)),
        err: IoError => SigningError(Reason::IoError(err)),
        err: Bug => SigningError(Reason::Bug(err)),
    }
}

/// Error indicating that signing failed
#[derive(Debug, Error)]
enum Reason {
    #[error("invalid arguments")]
    InvalidArgs(
        #[from]
        #[source]
        InvalidArgs,
    ),
    #[error("provided key share is not valid")]
    InvalidKeyShare(
        #[from]
        #[source]
        InvalidKeyShare,
    ),
    /// Signing protocol was maliciously aborted by another party
    #[error("protocol was maliciously aborted by another party")]
    Aborted(
        #[source]
        #[from]
        SigningAborted,
    ),
    #[error("i/o error")]
    IoError(#[source] IoError),
    /// Bug occurred
    #[error("bug occurred")]
    Bug(Bug),
}

/// Error indicating that protocol was aborted by malicious party
///
/// It _can be_ cryptographically proven, but we do not support it yet.
#[allow(clippy::type_complexity)]
#[derive(Debug, Error)]
enum SigningAborted {
    #[error("pi_enc_el_gamal_batch::verify(K) failed")]
    EncElgGamalBatchProofOfKorG(Vec<(PartyIndex, MsgId, MsgId, paillier_zk::InvalidProof)>),
    #[error("ψ, ψˆ, or ψ' proofs are invalid")]
    InvalidPsi(
        Vec<(
            PartyIndex,
            MsgId,
            MsgId,
            (
                Option<paillier_zk::InvalidProof>,
                Option<paillier_zk::InvalidProof>,
            ),
        )>,
    ),
    #[error("hat ψ' proof is invalid")]
    InvalidHatPsi(Vec<(PartyIndex, MsgId, MsgId)>),
    #[error("Delta != G * delta")]
    MismatchedDelta,
    #[error("pk * delta != S")]
    MismatchedS,
    #[error("resulting signature is not valid")]
    SignatureInvalid,
    #[error("other parties received different broadcast messages at round1a")]
    Round1aNotReliable(Vec<(PartyIndex, MsgId)>),
}

#[derive(Debug, Error)]
enum InvalidArgs {
    #[error("at least `threshold` amount of parties should take part in signing")]
    MismatchedAmountOfParties,
    #[error("signer index `i` is out of bounds (must be < n)")]
    SignerIndexOutOfBounds,
    #[error("party index in S is out of bounds (must be < n)")]
    InvalidSubIndex,
    #[error("ranks are invalid (must be < t)")]
    InvalidRanks,
}

/// Bugs while signing
#[derive(Debug, Error)]
pub enum Bug {
    /// invalid key share: number of parties exceeds u16
    #[error("invalid key share: number of parties exceeds u16")]
    PartiesNumberExceedsU16,

    /// couldn't encrypt a scalar with paillier encryption key
    #[error("couldn't encrypt a scalar with paillier encryption key: {0:?}")]
    PaillierEnc(BugSource, paillier_zk::fast_paillier::Error),
    /// couldn't decrypt a message
    #[error("couldn't decrypt a message: {0:?}")]
    PaillierDec(BugSource, paillier_zk::fast_paillier::Error),
    /// paillier addition/multiplication failed
    #[error("paillier addition/multiplication failed: {0:?}")]
    PaillierOp(BugSource, paillier_zk::fast_paillier::Error),

    /// π enc-elg failed to prove statement
    #[error("π enc-elg failed to prove statement {0:?}: {1:?}")]
    PiEncElg(BugSource, paillier_zk::Error),
    /// π enc-elg-gamal-batch failed to prove statement
    #[error("π enc-elg-gamal-batch failed to prove statement {0:?}: {1:?}")]
    PiEncElgGamalBatch(BugSource, paillier_zk::Error),
    /// π aff-g failed to prove statement
    #[error("π aff-g failed to prove statement {0:?}: {1:?}")]
    PiAffG(BugSource, paillier_zk::Error),
    /// pi_elog::prove failed to prove statement
    #[error("pi_elog::prove failed to prove statement: {0:?}")]
    PiELog(BugSource, paillier_zk::Error),

    /// delta is zero
    #[error("delta is zero")]
    ZeroDelta,
    /// Gamma is zero
    #[error("Gamma is zero")]
    ZeroGamma,

    /// unexpected protocol output
    #[error("unexpected protocol output")]
    UnexpectedProtocolOutput,

    /// derive lagrange coef
    #[error("derive lagrange coef")]
    LagrangeCoef,
    /// derive birkhoff coef
    #[error("derive birkhoff coef")]
    BirkhoffCoef,

    /// subset function returned error
    #[error("subset function returned error")]
    Subset,

    /// derived child key is zero - probability of that is negligible
    #[error("derived child key is zero - probability of that is negligible")]
    DerivedChildKeyZero,
    /// derived child share is zero - probability of that is negligible
    #[error("derived child share is zero - probability of that is negligible")]
    DerivedChildShareZero,
}

/// Bug source in signing protocol
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum BugSource {
    /// $K_i$ from round 1
    K_i,
    /// $G_i$ from round 1
    G_i,
    /// $psi_i$ from round 2
    psi_i,
    /// $gamma_i_times_K_j$ from round 2
    gamma_i_times_K_j,
    /// $neg_beta_ij_enc$ from round 2
    neg_beta_ij_enc,
    /// $D_ji$ from round 2
    D_ji,
    /// $F_ji$ from round 2
    F_ji,
    /// $x_i_times_K_j$ from round 2
    x_i_times_K_j,
    /// $neg_hat_beta_ij_enc$ from round 2
    neg_hat_beta_ij_enc,
    /// $hat_D_ji$ from round 2
    hat_D_ji,
    /// $hat_F_ji$ from round 2
    hat_F_ji,
    /// $psi_ji$ from round 2
    psi_ji,
    /// $hat_psi_ji$ from round 2
    hat_psi_ji,
    /// $alpha_ij$ from round 3
    alpha_ij,
    /// $hat_psi_i$ from round 3
    hat_psi_i,
    /// $hat_alpha_ij$ from round 3
    hat_alpha_ij,
}

/// Error indicating that signature is not valid for given public key and message
#[derive(Debug, Error)]
#[error("signature is not valid")]
pub struct InvalidSignature;

#[cfg(test)]
mod test {
    fn read_write_signature<E: generic_ec::Curve>() {
        let mut rng = rand_dev::DevRng::new();
        for _ in 0..10 {
            let r = generic_ec::NonZero::<generic_ec::Scalar<E>>::random(&mut rng);
            let s = generic_ec::NonZero::<generic_ec::Scalar<E>>::random(&mut rng);
            let signature = super::Signature::from_raw_parts(r, s);
            let mut bytes = vec![0; super::Signature::<E>::serialized_len()];
            signature.write_to_slice(&mut bytes);
            let signature2 = super::Signature::read_from_slice(&bytes).unwrap();
            assert!(signature == signature2, "signatures equal");
        }
    }

    #[test]
    fn read_write_signature_secp256k1() {
        read_write_signature::<generic_ec::curves::Secp256k1>()
    }
    // #[test]
    // fn read_write_signature_secp256r1() {
    //     read_write_signature::<generic_ec::curves::Secp256r1>()
    // }
    #[test]
    fn read_write_signature_stark() {
        read_write_signature::<generic_ec::curves::Stark>()
    }
}
