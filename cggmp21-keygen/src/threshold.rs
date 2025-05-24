use alloc::vec::Vec;

use digest::Digest;
use generic_ec::{Curve, NonZero, Point, Scalar, SecretScalar};
use generic_ec_zkp::{polynomial::Polynomial, schnorr_pok};
use rand_core::{CryptoRng, RngCore};
use round_based::{
    rounds_router::simple_store::RoundInput, rounds_router::RoundsRouter,
    Delivery, Mpc, MpcParty, Outgoing, ProtocolMessage, SinkExt,
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::progress::Tracer;
use crate::{
    errors::IoError,
    key_share::{CoreKeyShare, DirtyCoreKeyShare, DirtyKeyInfo, Validate, VssSetup},
    security_level::SecurityLevel,
    utils, ExecutionId,
};

use super::{Bug, KeygenAborted, KeygenError};

macro_rules! prefixed {
    ($name:tt) => {
        concat!("dfns.cggmp21.keygen.threshold.", $name)
    };
}

/// Message of key generation protocol
#[derive(ProtocolMessage, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub enum Msg<E: Curve, L: SecurityLevel, D: Digest> {
    /// Round 1 message
    Round1(MsgRound1<D>),
    /// Round 2a message
    Round2Broad(MsgRound2Broad<E, L>),
    /// Round 2b message
    Round2Uni(MsgRound2Uni<E>),
    /// Round 3 message
    Round3(MsgRound3<E>),
    /// Reliability check message (optional additional round)
    ReliabilityCheck(MsgReliabilityCheck<D>),
}

/// Message from round 1
#[derive(Clone, Serialize, Deserialize, udigest::Digestable)]
#[serde(bound = "")]
#[udigest(bound = "")]
#[udigest(tag = prefixed!("round1"))]
pub struct MsgRound1<D: Digest> {
    /// $V_i$
    #[udigest(as_bytes)]
    pub commitment: digest::Output<D>,
}
/// Message from round 2 broadcasted to everyone
#[serde_as]
#[derive(Clone, Serialize, Deserialize, udigest::Digestable)]
#[serde(bound = "")]
#[udigest(bound = "")]
#[udigest(tag = prefixed!("round2_broad"))]
pub struct MsgRound2Broad<E: Curve, L: SecurityLevel> {
    /// `rid_i`
    #[serde_as(as = "utils::HexOrBin")]
    #[udigest(as_bytes)]
    pub rid: L::Rid,
    /// $\vec S_i$
    pub F: Polynomial<Point<E>>,
    /// $A_i$
    pub sch_commit: schnorr_pok::Commit<E>,
    /// Party contribution to chain code
    #[cfg(feature = "hd-wallet")]
    #[serde_as(as = "Option<utils::HexOrBin>")]
    #[udigest(as = Option<udigest::Bytes>)]
    pub chain_code: Option<hd_wallet::ChainCode>,
    /// $u_i$
    #[serde(with = "hex::serde")]
    #[udigest(as_bytes)]
    pub decommit: L::Rid,
}
/// Message from round 2 unicasted to each party
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgRound2Uni<E: Curve> {
    /// $\sigma_{i,j}$
    pub sigma: Scalar<E>,
}
/// Message from round 3
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgRound3<E: Curve> {
    /// $\psi_i$
    pub sch_proof: schnorr_pok::Proof<E>,
}
/// Message parties exchange to ensure reliability of broadcast channel
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgReliabilityCheck<D: Digest>(pub digest::Output<D>);

mod unambiguous {
    use generic_ec::{Curve, NonZero, Point};

    use crate::{ExecutionId, SecurityLevel};

    #[derive(udigest::Digestable)]
    #[udigest(tag = prefixed!("hash_commitment"))]
    #[udigest(bound = "")]
    pub struct HashCom<'a, E: Curve, L: SecurityLevel> {
        pub sid: ExecutionId<'a>,
        pub party_index: u16,
        pub decommitment: &'a super::MsgRound2Broad<E, L>,
    }

    #[derive(udigest::Digestable)]
    #[udigest(tag = prefixed!("schnorr_pok"))]
    #[udigest(bound = "")]
    pub struct SchnorrPok<'a, E: Curve> {
        pub sid: ExecutionId<'a>,
        pub prover: u16,
        #[udigest(as_bytes)]
        pub rid: &'a [u8],
        pub y: NonZero<Point<E>>,
        pub h: Point<E>,
    }

    #[derive(udigest::Digestable)]
    #[udigest(tag = prefixed!("echo_round"))]
    #[udigest(bound = "")]
    pub struct Echo<'a, D: digest::Digest> {
        pub sid: ExecutionId<'a>,
        pub commitment: &'a super::MsgRound1<D>,
    }
}

/// Runs the threshold key generation protocol
pub async fn run_threshold_keygen<E, R, M, L, D>(
    mut tracer: Option<&mut dyn Tracer>,
    i: u16,
    t: u16,
    n: u16,
    reliable_broadcast_enforced: bool,
    sid: ExecutionId<'_>,
    rng: &mut R,
    party: M,
    #[cfg(feature = "hd-wallet")] hd_enabled: bool,
) -> Result<CoreKeyShare<E>, KeygenError>
where
    E: Curve,
    L: SecurityLevel,
    D: Digest + Clone + 'static,
    R: RngCore + CryptoRng,
    M: Mpc<ProtocolMessage = Msg<E, L, D>>,
{
    // Note 1: the challenge includes y_i and h_i
    //         y_i: public share of party i
    //         h_i: ephemeral secret * G
    // Why the non-threshold keygen does not include y_i and h_i in the challenge?

    tracer.protocol_begins();

    tracer.stage("Setup networking");
    let MpcParty { delivery, .. } = party.into_party();
    let (incomings, mut outgoings) = delivery.split();

    let mut rounds = RoundsRouter::<Msg<E, L, D>>::builder();
    let round1 = rounds.add_round(RoundInput::<MsgRound1<D>>::broadcast(i, n));
    let round1_sync = rounds.add_round(RoundInput::<MsgReliabilityCheck<D>>::broadcast(i, n));
    let round2_broad = rounds.add_round(RoundInput::<MsgRound2Broad<E, L>>::broadcast(i, n));
    let round2_uni = rounds.add_round(RoundInput::<MsgRound2Uni<E>>::p2p(i, n));
    let round3 = rounds.add_round(RoundInput::<MsgRound3<E>>::broadcast(i, n));
    let mut rounds = rounds.listen(incomings);

    // Round 1
    tracer.round_begins();

    tracer.stage("Sample rid_i, schnorr commitment, polynomial, chain_code");
    let mut rid = L::Rid::default();
    rng.fill_bytes(rid.as_mut());

    // r ~ tau_i, h ~ A_i
    let (r, h) = schnorr_pok::prover_commits_ephemeral_secret::<E, _>(rng);

    let f = Polynomial::<SecretScalar<E>>::sample(rng, usize::from(t) - 1);
    // F_i = f_i * G = sum(a_{i,k} * x^k) * G
    // F_i = sum((a_{i,k} * G) * x^k ) = sum(A_{i,k} * x^k)
    let F = &f * &Point::generator();
    let sigmas = (0..n)
        .map(|j| {
            let x = Scalar::from(j + 1);
            f.value(&x)
        })
        .collect::<Vec<_>>();
    debug_assert_eq!(sigmas.len(), usize::from(n));

    #[cfg(feature = "hd-wallet")]
    let chain_code_local = if hd_enabled {
        let mut chain_code = hd_wallet::ChainCode::default();
        rng.fill_bytes(&mut chain_code);
        Some(chain_code)
    } else {
        None
    };

    tracer.stage("Commit to public data");
    let my_decommitment = MsgRound2Broad {
        rid,
        F: F.clone(),
        sch_commit: h,
        #[cfg(feature = "hd-wallet")]
        chain_code: chain_code_local,
        decommit: {
            let mut nonce = L::Rid::default();
            rng.fill_bytes(nonce.as_mut());
            nonce
        },
    };
    let hash_commit = udigest::hash::<D>(&unambiguous::HashCom {
        sid,
        party_index: i,
        decommitment: &my_decommitment,
    });

    tracer.send_msg();
    let my_commitment = MsgRound1 {
        commitment: hash_commit,
    };
    outgoings
        .send(Outgoing::broadcast(Msg::Round1(my_commitment.clone())))
        .await
        .map_err(IoError::send_message)?;
    tracer.msg_sent();

    // Round 2
    tracer.round_begins();

    tracer.receive_msgs();
    let commitments = rounds
        .complete(round1)
        .await
        .map_err(IoError::receive_message)?;
    tracer.msgs_received();

    // Optional reliability check
    if reliable_broadcast_enforced {
        tracer.stage("Hash received msgs (reliability check)");
        let h_i = udigest::hash_iter::<D>(
            commitments
                .iter_including_me(&my_commitment)
                .map(|commitment| unambiguous::Echo { sid, commitment }),
        );

        tracer.send_msg();
        outgoings
            .send(Outgoing::broadcast(Msg::ReliabilityCheck(
                MsgReliabilityCheck(h_i.clone()),
            )))
            .await
            .map_err(IoError::send_message)?;
        tracer.msg_sent();

        tracer.round_begins();

        tracer.receive_msgs();
        let hashes = rounds
            .complete(round1_sync)
            .await
            .map_err(IoError::receive_message)?;
        tracer.msgs_received();

        tracer.stage("Assert other parties hashed messages (reliability check)");
        let parties_have_different_hashes = hashes
            .into_iter_indexed()
            .filter(|(_j, _msg_id, h_j)| h_i != h_j.0)
            .map(|(j, msg_id, _)| (j, msg_id))
            .collect::<Vec<_>>();
        if !parties_have_different_hashes.is_empty() {
            return Err(KeygenAborted::Round1NotReliable(parties_have_different_hashes).into());
        }
    }

    tracer.send_msg();
    // broadcast public data
    outgoings
        .feed(Outgoing::broadcast(Msg::Round2Broad(
            my_decommitment.clone(),
        )))
        .await
        .map_err(IoError::send_message)?;

    // p2p sigma_j to party_j
    let sigmas_clone = sigmas.clone();
    let messages = utils::iter_peers(i, n).map(move |j| {
        let message = MsgRound2Uni {
            sigma: sigmas_clone[usize::from(j)],
        };
        Outgoing::p2p(j, Msg::Round2Uni(message))
    });
    
    outgoings
        .send_all(&mut futures_util::stream::iter(messages.map(Ok)))
        .await
        .map_err(IoError::send_message)?;
    tracer.msg_sent();

    // Round 3
    tracer.round_begins();

    tracer.receive_msgs();
    let decommitments = rounds
        .complete(round2_broad)
        .await
        .map_err(IoError::receive_message)?;
    // receive sigmas value of party i, which are generated by other parties
    let sigmas_msg = rounds
        .complete(round2_uni)
        .await
        .map_err(IoError::receive_message)?;
    tracer.msgs_received();

    tracer.stage("Validate decommitments");
    let blame = utils::collect_blame(&commitments, &decommitments, |j, com, decom| {
        let com_expected = udigest::hash::<D>(&unambiguous::HashCom {
            sid,
            party_index: j,
            decommitment: decom,
        });
        com.commitment != com_expected
    });
    if !blame.is_empty() {
        return Err(KeygenAborted::InvalidDecommitment(blame).into());
    }

    // validate the polynomial degree with threshold t
    // blame will contain the parties id that have invalid polynomial degree
    tracer.stage("Validate data size");
    let blame = decommitments
        .iter_indexed()
        .filter(|(_, _, d)| d.F.degree() + 1 != usize::from(t))
        .map(|t| t.0)
        .collect::<Vec<_>>();
    if !blame.is_empty() {
        return Err(KeygenAborted::InvalidDataSize { parties: blame }.into());
    }

    tracer.stage("Validate Feldmann VSS");
    let blame = decommitments
        .iter_indexed()
        .zip(sigmas_msg.iter())
        .filter(|((_, _, d), s)| {
            d.F.value::<_, Point<_>>(&Scalar::from(i + 1)) != Point::generator() * s.sigma
        })
        .map(|t| t.0 .0)
        .collect::<Vec<_>>();
    if !blame.is_empty() {
        return Err(KeygenAborted::FeldmanVerificationFailed { parties: blame }.into());
    }

    tracer.stage("Compute rid");
    // compute challenge rho
    let rid = decommitments
        .iter_including_me(&my_decommitment)
        .map(|d| &d.rid)
        .fold(L::Rid::default(), utils::xor_array);
    #[cfg(feature = "hd-wallet")]
    let chain_code = if hd_enabled {
        tracer.stage("Compute chain_code");
        let blame = utils::collect_simple_blame(&decommitments, |decom| decom.chain_code.is_none());
        if !blame.is_empty() {
            return Err(KeygenAborted::MissingChainCode(blame).into());
        }
        Some(decommitments.iter_including_me(&my_decommitment).try_fold(
            hd_wallet::ChainCode::default(),
            |acc, decom| {
                Ok::<_, Bug>(utils::xor_array(
                    acc,
                    decom.chain_code.ok_or(Bug::NoChainCode)?,
                ))
            },
        )?)
    } else {
        None
    };
    tracer.stage("Compute Ys");
    // F = F_1 + F_2 + ... + F_n
    let polynomial_sum = decommitments
        .iter_including_me(&my_decommitment)
        .map(|d| &d.F)
        .sum::<Polynomial<_>>();
    // ys = [y_j = F(j + 1) for j in 0..n]
    // y_j is the public share of party j
    // y_j = sigma_j * G, where sigma_j is the secret share of party j
    let ys = (0..n)
        .map(|l| polynomial_sum.value(&Scalar::from(l + 1)))
        .map(|y_j: Point<E>| NonZero::from_point(y_j).ok_or(Bug::ZeroShare))
        .collect::<Result<Vec<_>, _>>()?;
    tracer.stage("Compute sigma");
    // sigma = sigma_1 + sigma_2 + ... + sigma_n
    // sigma is the secret share of party i
    let sigma: Scalar<E> = sigmas_msg.iter().map(|msg| msg.sigma).sum();
    let mut sigma = sigma + sigmas[usize::from(i)];
    let sigma = NonZero::from_secret_scalar(SecretScalar::new(&mut sigma)).ok_or(Bug::ZeroShare)?;
    debug_assert_eq!(Point::generator() * &sigma, ys[usize::from(i)]);

    tracer.stage("Calculate challenge");
    let challenge = Scalar::from_hash::<D>(&unambiguous::SchnorrPok {
        sid,
        prover: i,
        rid: rid.as_ref(),
        // add y_i and h_i to the challenge
        y: ys[usize::from(i)],
        // h_i = A_i = ephemeral_secret * G
        h: my_decommitment.sch_commit.0,
    });
    let challenge = schnorr_pok::Challenge { nonce: challenge };

    tracer.stage("Prove knowledge of `sigma_i`");
    let z = schnorr_pok::prove(&r, &challenge, &sigma);

    tracer.send_msg();
    let my_sch_proof = MsgRound3 { sch_proof: z };
    outgoings
        .send(Outgoing::broadcast(Msg::Round3(my_sch_proof.clone())))
        .await
        .map_err(IoError::send_message)?;
    tracer.msg_sent();

    // Output round
    tracer.round_begins();

    tracer.receive_msgs();
    let sch_proofs = rounds
        .complete(round3)
        .await
        .map_err(IoError::receive_message)?;
    tracer.msgs_received();

    tracer.stage("Validate schnorr proofs");
    let blame = utils::collect_blame(&decommitments, &sch_proofs, |j, decom, sch_proof| {
        let challenge = Scalar::from_hash::<D>(&unambiguous::SchnorrPok {
            sid,
            prover: j,
            rid: rid.as_ref(),
            y: ys[usize::from(j)],
            h: decom.sch_commit.0,
        });
        let challenge = schnorr_pok::Challenge { nonce: challenge };
        sch_proof
            .sch_proof
            .verify(&decom.sch_commit, &challenge, &ys[usize::from(j)])
            .is_err()
    });
    if !blame.is_empty() {
        return Err(KeygenAborted::InvalidSchnorrProof(blame).into());
    }

    tracer.stage("Derive resulting public key and other data");
    // y = F_1(0) + F_2(0) + ... + F_n(0) = public key
    let y: Point<E> = decommitments
        .iter_including_me(&my_decommitment)
        .map(|d| d.F.coefs()[0])
        .sum();
    // key_shares_indexes = [1, 2, ..., n]
    let key_shares_indexes = (1..=n)
        .map(|i| NonZero::from_scalar(Scalar::from(i)))
        .collect::<Option<Vec<_>>>()
        .ok_or(Bug::NonZeroScalar)?;

    tracer.protocol_ends();

    Ok(DirtyCoreKeyShare {
        i,
        key_info: DirtyKeyInfo {
            curve: Default::default(),
            shared_public_key: NonZero::from_point(y).ok_or(Bug::ZeroPk)?,
            public_shares: ys,
            vss_setup: Some(VssSetup {
                min_signers: t,
                I: key_shares_indexes,
                ranks: None,
            }),
            #[cfg(feature = "hd-wallet")]
            chain_code,
        },
        x: sigma,
    }
    .validate()
    .map_err(|err| Bug::InvalidKeyShare(err.into_error()))?)
}

// pub async fn setup_rounds<E, R, M, L, D>(
//     mut tracer: Option<&mut dyn Tracer>,
//     i: u16,
//     t: u16,
//     n: u16,
//     reliable_broadcast_enforced: bool,
//     sid: ExecutionId<'_>,
//     rng: &mut R,
//     party: M,
//     #[cfg(feature = "hd-wallet")] hd_enabled: bool,
// ) -> (
//     RoundsRouter<Msg<E, L, D>, <<M as Mpc>::Delivery as Delivery<Msg<E, L, D>>>::Receive>,
//     Round<RoundInput<MsgRound1<D>>>,
//     Round<RoundInput<MsgReliabilityCheck<D>>>,
//     Round<RoundInput<MsgRound2Broad<E, L>>>,
//     Round<RoundInput<MsgRound2Uni<E>>>,
//     Round<RoundInput<MsgRound3<E>>>,
// )
// where
//     E: Curve,
//     L: SecurityLevel,
//     D: Digest + Clone + 'static,
//     R: RngCore + CryptoRng,
//     M: Mpc<ProtocolMessage = Msg<E, L, D>>,
// {
//     // Note 1: the challenge includes y_i and h_i
//     //         y_i: public share of party i
//     //         h_i: ephemeral secret * G
//     // Why the non-threshold keygen does not include y_i and h_i in the challenge?

//     tracer.protocol_begins();

//     tracer.stage("Setup networking");
//     let MpcParty { delivery, .. } = party.into_party();
//     let (incomings, mut outgoings) = delivery.split();

//     let mut rounds = RoundsRouter::<Msg<E, L, D>>::builder();
//     let round1 = rounds.add_round(RoundInput::<MsgRound1<D>>::broadcast(i, n));
//     let round1_sync = rounds.add_round(RoundInput::<MsgReliabilityCheck<D>>::broadcast(i, n));
//     let round2_broad = rounds.add_round(RoundInput::<MsgRound2Broad<E, L>>::broadcast(i, n));
//     let round2_uni = rounds.add_round(RoundInput::<MsgRound2Uni<E>>::p2p(i, n));
//     let round3 = rounds.add_round(RoundInput::<MsgRound3<E>>::broadcast(i, n));
//     let mut rounds = rounds.listen(incomings);

//     (
//         rounds,
//         round1,
//         round1_sync,
//         round2_broad,
//         round2_uni,
//         round3,
//     )
// }

/// Creates a message for round 1 of the threshold key generation protocol
pub fn create_message_round_1<E, R, L, D>(
    rng: &mut R,
    i: u16,
    t: u16,
    n: u16,
    sid: ExecutionId<'_>,
) -> MsgRound1<D>
where
    E: Curve,
    L: SecurityLevel,
    D: Digest + Clone + 'static,
    R: RngCore + CryptoRng,
{
    let mut rid = L::Rid::default();
    rng.fill_bytes(rid.as_mut());
    let (_, h) = schnorr_pok::prover_commits_ephemeral_secret::<E, _>(rng);

    let f = Polynomial::<SecretScalar<E>>::sample(rng, usize::from(t) - 1);
    // F_i = f_i * G = sum(a_{i,k} * x^k) * G
    // F_i = sum((a_{i,k} * G) * x^k ) = sum(A_{i,k} * x^k)
    let F = &f * &Point::generator();
    let sigmas: Vec<Scalar<E>> = (0..n)
        .map(|j| {
            let x: Scalar<E> = Scalar::from(j + 1);
            f.value(&x)
        })
        .collect::<Vec<_>>();
    debug_assert_eq!(sigmas.len(), usize::from(n));

    let my_decommitment: MsgRound2Broad<_, L> = MsgRound2Broad {
        rid,
        F: F.clone(),
        sch_commit: h,
        #[cfg(feature = "hd-wallet")]
        chain_code: chain_code_local,
        decommit: {
            let mut nonce = L::Rid::default();
            rng.fill_bytes(nonce.as_mut());
            nonce
        },
    };
    let hash_commit = udigest::hash::<D>(&unambiguous::HashCom {
        sid,
        party_index: i,
        decommitment: &my_decommitment,
    });

    let my_commitment = MsgRound1 {
        commitment: hash_commit,
    };

    my_commitment
}

use round_based::rounds_router::simple_store::RoundMsgs;

/// Creates a reliability check message for the threshold key generation protocol
pub fn create_message_round_reliability_check<D>(
    sid: ExecutionId<'_>,
    commitments: RoundMsgs<MsgRound1<D>>,
    my_commitment: MsgRound1<D>,
) -> MsgReliabilityCheck<D>
where
    D: Digest + Clone + 'static,
{
    let h_i = udigest::hash_iter::<D>(
        commitments
            .iter_including_me(&my_commitment)
            .map(|commitment| unambiguous::Echo { sid, commitment }),
    );
    MsgReliabilityCheck(h_i.clone())
}

use digest::generic_array::GenericArray;
use digest::OutputSizeUser;

/// Checks if all parties have matching reliability check hashes.
/// Returns false if any party has a different hash, true otherwise.
pub fn check_message_round_reliability_check<D>(
    hashes: RoundMsgs<MsgReliabilityCheck<D>>,
    h_i: GenericArray<u8, <D as OutputSizeUser>::OutputSize>,
) -> bool
where
    D: Digest + Clone + 'static,
{
    let parties_have_different_hashes = hashes
        .into_iter_indexed()
        .filter(|(_j, _msg_id, h_j)| h_i != h_j.0)
        .map(|(j, msg_id, _)| (j, msg_id))
        .collect::<Vec<_>>();
    if !parties_have_different_hashes.is_empty() {
        return false;
    }

    true
}

use core::iter::Map;
use generic_ec_zkp::schnorr_pok::ProverSecret;
/// Creates round 2 unicast messages containing sigma shares for each peer.
pub fn create_message_round_2_uni<E, L, D>(
    i: u16,
    n: u16,
    sigmas: Vec<Scalar<E>>,
) -> Map<impl Iterator<Item = u16>, impl FnMut(u16) -> Outgoing<Msg<E, L, D>>>
where
    E: Curve,
    L: SecurityLevel,
    D: Digest + Clone + 'static,
{
    let sigmas_clone = sigmas.clone();
    let messages = utils::iter_peers(i, n).map(move |j| {
        let message = MsgRound2Uni {
            sigma: sigmas_clone[usize::from(j)],
        };
        Outgoing::p2p(j, Msg::Round2Uni(message))
    });

    messages
}

/// Creates round 3 message containing Schnorr proof of knowledge.
pub fn create_message_round_3<E, L, D>(
    commitments: &RoundMsgs<MsgRound1<D>>,
    decommitments: &RoundMsgs<MsgRound2Broad<E, L>>,
    sigmas_msg: &RoundMsgs<MsgRound2Uni<E>>,
    sid: &ExecutionId<'_>,
    my_decommitment: &MsgRound2Broad<E, L>,
    n: u16,
    t: u16,
    i: u16,
    r: &ProverSecret<E>,
    sigmas: &Vec<Scalar<E>>,
) -> Result<MsgRound3<E>, Bug>
where
    E: Curve,
    L: SecurityLevel,
    D: Digest + Clone + 'static,
{
    let blame = utils::collect_blame(&commitments, &decommitments, |j, com, decom| {
        let com_expected = udigest::hash::<D>(&unambiguous::HashCom {
            sid: *sid,
            party_index: j,
            decommitment: decom,
        });
        com.commitment != com_expected
    });
    if !blame.is_empty() {
        // return Err(KeygenAborted::InvalidDecommitment(blame).into());
    }

    // validate the polynomial degree with threshold t
    // blame will contain the parties id that have invalid polynomial degree
    let blame = decommitments
        .iter_indexed()
        .filter(|(_, _, d)| d.F.degree() + 1 != usize::from(t))
        .map(|t| t.0)
        .collect::<Vec<_>>();
    if !blame.is_empty() {
        // return Err(KeygenAborted::InvalidDataSize { parties: blame }.into());
    }

    let blame = decommitments
        .iter_indexed()
        .zip(sigmas_msg.iter())
        .filter(|((_, _, d), s)| {
            d.F.value::<_, Point<_>>(&Scalar::from(i + 1)) != Point::generator() * s.sigma
        })
        .map(|t| t.0 .0)
        .collect::<Vec<_>>();
    if !blame.is_empty() {
        // return Err(KeygenAborted::FeldmanVerificationFailed { parties: blame }.into());
    }

    // compute challenge rho
    let rid = decommitments
        .iter_including_me(&my_decommitment)
        .map(|d| &d.rid)
        .fold(L::Rid::default(), utils::xor_array);
    #[cfg(feature = "hd-wallet")]
    let chain_code = if hd_enabled {
        tracer.stage("Compute chain_code");
        let blame = utils::collect_simple_blame(&decommitments, |decom| decom.chain_code.is_none());
        if !blame.is_empty() {
            return Err(KeygenAborted::MissingChainCode(blame).into());
        }
        Some(decommitments.iter_including_me(&my_decommitment).try_fold(
            hd_wallet::ChainCode::default(),
            |acc, decom| {
                Ok::<_, Bug>(utils::xor_array(
                    acc,
                    decom.chain_code.ok_or(Bug::NoChainCode)?,
                ))
            },
        )?)
    } else {
        None
    };
    // F = F_1 + F_2 + ... + F_n
    let polynomial_sum = decommitments
        .iter_including_me(&my_decommitment)
        .map(|d| &d.F)
        .sum::<Polynomial<_>>();
    // ys = [y_j = F(j + 1) for j in 0..n]
    // y_j is the public share of party j
    // y_j = sigma_j * G, where sigma_j is the secret share of party j
    let ys = (0..n)
        .map(|l| polynomial_sum.value(&Scalar::from(l + 1)))
        .map(|y_j: Point<E>| NonZero::from_point(y_j).ok_or(Bug::ZeroShare))
        .collect::<Result<Vec<_>, _>>()?;
    // sigma = sigma_1 + sigma_2 + ... + sigma_n
    // sigma is the secret share of party i
    let sigma: Scalar<E> = sigmas_msg.iter().map(|msg| msg.sigma).sum();
    let mut sigma = sigma + sigmas[usize::from(i)];
    let sigma = NonZero::from_secret_scalar(SecretScalar::new(&mut sigma)).ok_or(Bug::ZeroShare)?;
    debug_assert_eq!(Point::generator() * &sigma, ys[usize::from(i)]);

    let challenge = Scalar::from_hash::<D>(&unambiguous::SchnorrPok {
        sid: *sid,
        prover: i,
        rid: rid.as_ref(),
        // add y_i and h_i to the challenge
        y: ys[usize::from(i)],
        // h_i = A_i = ephemeral_secret * G
        h: my_decommitment.sch_commit.0,
    });
    let challenge = schnorr_pok::Challenge { nonce: challenge };

    let z = schnorr_pok::prove(&r, &challenge, &sigma);

    let my_sch_proof = MsgRound3 { sch_proof: z };

    Ok(my_sch_proof)
}

/// hehe
pub fn create_key_share<E, L, D>(
    sch_proofs: &RoundMsgs<MsgRound3<E>>,
    decommitments: &RoundMsgs<MsgRound2Broad<E, L>>,
    sid: &ExecutionId<'_>,
    rid: &L::Rid,
    my_decommitment: &MsgRound2Broad<E, L>,
    i: u16,
    n: u16,
    t: u16,
    sigma: &NonZero<SecretScalar<E>>,
) -> Result<CoreKeyShare<E>, KeygenError>
where
    E: Curve,
    L: SecurityLevel,
    D: Digest + Clone + 'static,
{

    let polynomial_sum = decommitments
        .iter_including_me(&my_decommitment)
        .map(|d| &d.F)
        .sum::<Polynomial<_>>();
    // ys = [y_j = F(j + 1) for j in 0..n]
    // y_j is the public share of party j
    // y_j = sigma_j * G, where sigma_j is the secret share of party j
    let ys = (0..n)
        .map(|l| polynomial_sum.value(&Scalar::from(l + 1)))
        .map(|y_j: Point<E>| NonZero::from_point(y_j).ok_or(Bug::ZeroShare))
        .collect::<Result<Vec<_>, _>>()?;

    let blame = utils::collect_blame(&decommitments, &sch_proofs, |j, decom, sch_proof| {
        let challenge = Scalar::from_hash::<D>(&unambiguous::SchnorrPok {
            sid: *sid,
            prover: j,
            rid: rid.as_ref(),
            y: ys[usize::from(j)],
            h: decom.sch_commit.0,
        });
        let challenge = schnorr_pok::Challenge { nonce: challenge };
        sch_proof
            .sch_proof
            .verify(&decom.sch_commit, &challenge, &ys[usize::from(j)])
            .is_err()
    });
    if !blame.is_empty() {
        return Err(KeygenAborted::InvalidSchnorrProof(blame).into());
    }

    // y = F_1(0) + F_2(0) + ... + F_n(0) = public key
    let y: Point<E> = decommitments
        .iter_including_me(&my_decommitment)
        .map(|d| d.F.coefs()[0])
        .sum();
    // key_shares_indexes = [1, 2, ..., n]
    let key_shares_indexes = (1..=n)
        .map(|i| NonZero::from_scalar(Scalar::from(i)))
        .collect::<Option<Vec<_>>>()
        .ok_or(Bug::NonZeroScalar)?;

    Ok(DirtyCoreKeyShare {
        i,
        key_info: DirtyKeyInfo {
            curve: Default::default(),
            shared_public_key: NonZero::from_point(y).ok_or(Bug::ZeroPk)?,
            public_shares: ys.clone(),
            vss_setup: Some(VssSetup {
                min_signers: t,
                I: key_shares_indexes,
                ranks: None,
            }),
            #[cfg(feature = "hd-wallet")]
            chain_code,
        },
        x: sigma.clone(),
    }
    .validate()
    .map_err(|err| Bug::InvalidKeyShare(err.into_error()))?)
}
