use digest::Digest;
use futures::SinkExt;
use paillier_zk::{
    fast_paillier, no_small_factor::non_interactive as π_fac, paillier_blum_modulus as π_mod,
    BigIntExt,
    fast_paillier::utils::{serializable_bigint}
};
use rand_core::{CryptoRng, RngCore};
use round_based::{
    rounds_router::{simple_store::RoundInput, RoundsRouter},
    Delivery, Mpc, MpcParty, Outgoing, ProtocolMessage,
};
use serde::{Deserialize, Serialize};

use crate::{
    errors::IoError,
    key_share::{AuxInfo, DirtyAuxInfo, PartyAux, Validate},
    progress::Tracer,
    security_level::SecurityLevel,
    utils,
    utils::{collect_blame, AbortBlame},
    zk::ring_pedersen_parameters as π_prm,
    ExecutionId,
};

use num_bigint::{BigInt, RandBigInt};

use super::{Bug, KeyRefreshError, PregeneratedPaillierKey, ProtocolAborted};
use round_based::rounds_router::simple_store::RoundMsgs;

macro_rules! prefixed {
    ($name:tt) => {
        concat!("dfns.cggmp21.aux_gen.", $name)
    };
}

/// Message of key refresh protocol
#[derive(ProtocolMessage, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
// 3 kilobytes for the largest option, and 2.5 kilobytes for second largest
#[allow(clippy::large_enum_variant)]
pub enum Msg<D: Digest, L: SecurityLevel> {
    /// Round 1 message
    Round1(MsgRound1<D>),
    /// Round 2 message
    Round2(MsgRound2<L>),
    /// Round 3 message
    Round3(MsgRound3),
    /// Reliability check message (optional additional round)
    ReliabilityCheck(MsgReliabilityCheck<D>),
}

/// Message from round 1
#[derive(Clone, Serialize, Deserialize, udigest::Digestable)]
#[udigest(tag = prefixed!("round1"))]
#[udigest(bound = "")]
#[serde(bound = "")]
pub struct MsgRound1<D: Digest> {
    /// $V_i$
    #[udigest(as_bytes)]
    pub commitment: digest::Output<D>,
}
/// Message from round 2
#[derive(Clone, Serialize, Deserialize, udigest::Digestable)]
#[udigest(tag = prefixed!("round2"))]
#[udigest(bound = "")]
#[serde(bound = "")]
pub struct MsgRound2<L: SecurityLevel> {
    /// $N_i$
    #[udigest(as = utils::encoding::BigInt)]
    #[serde(with = "serializable_bigint")]
    pub N: BigInt,
    /// $Paillier enc$
    #[udigest(as = utils::encoding::EncryptionKey)]
    pub enc: fast_paillier::EncryptionKey,
    /// $s_i$
    #[udigest(as = utils::encoding::BigInt)]
    #[serde(with = "serializable_bigint")]
    pub s: BigInt,
    /// $t_i$
    #[udigest(as = utils::encoding::BigInt)]
    #[serde(with = "serializable_bigint")]
    pub t: BigInt,
    /// $\hat \psi_i$
    // this should be L::M instead, but no rustc support yet
    pub params_proof: π_prm::Proof<{ crate::security_level::M }>,
    /// $\rho_i$
    // ideally it would be [u8; L::SECURITY_BYTES], but no rustc support yet
    #[serde(with = "hex")]
    #[udigest(as_bytes)]
    pub rho_bytes: L::Rid,
    /// $u_i$
    #[serde(with = "hex")]
    #[udigest(as_bytes)]
    pub decommit: L::Rid,
}
/// Unicast message of round 3, sent to each participant
#[derive(Clone, Serialize, Deserialize)]
pub struct MsgRound3 {
    /// $\psi_i$
    // this should be L::M instead, but no rustc support yet
    pub mod_proof: (
        π_mod::Commitment,
        π_mod::Proof<{ crate::security_level::M }>,
    ),
    /// $\phi_i^j$
    pub fac_proof: π_fac::Proof,
}

/// Message from an optional round that enforces reliability check
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgReliabilityCheck<D: Digest>(pub digest::Output<D>);

mod unambiguous {
    use digest::Digest;

    use crate::{ExecutionId, SecurityLevel};

    #[derive(udigest::Digestable)]
    #[udigest(tag = prefixed!("proof_prm"))]
    pub struct ProofPrm<'a> {
        pub sid: ExecutionId<'a>,
        pub prover: u16,
    }

    #[derive(udigest::Digestable)]
    #[udigest(tag = prefixed!("proof_mod"))]
    pub struct ProofMod<'a> {
        pub sid: ExecutionId<'a>,
        #[udigest(as_bytes)]
        pub rho: &'a [u8],
        pub prover: u16,
    }

    #[derive(udigest::Digestable)]
    #[udigest(tag = prefixed!("proof_fac"))]
    #[udigest(bound = "")]
    pub struct ProofFac<'a> {
        pub sid: ExecutionId<'a>,
        #[udigest(as_bytes)]
        pub rho: &'a [u8],
        pub prover: u16,
    }

    #[derive(udigest::Digestable)]
    #[udigest(tag = prefixed!("hash_commitment"))]
    #[udigest(bound = "")]
    pub struct HashCom<'a, L: SecurityLevel> {
        pub sid: ExecutionId<'a>,
        pub prover: u16,
        pub decommitment: &'a super::MsgRound2<L>,
    }

    #[derive(udigest::Digestable)]
    #[udigest(tag = prefixed!("echo_round"))]
    #[udigest(bound = "")]
    pub struct Echo<'a, D: Digest> {
        pub sid: ExecutionId<'a>,
        pub commitment: &'a super::MsgRound1<D>,
    }
}

/// Runs the auxiliary generation protocol
pub async fn run_aux_gen<R, M, L, D>(
    i: u16,
    n: u16,
    mut rng: &mut R,
    party: M,
    sid: ExecutionId<'_>,
    pregenerated: PregeneratedPaillierKey<L>,
    mut tracer: Option<&mut dyn Tracer>,
    reliable_broadcast_enforced: bool,
    compute_multiexp_table: bool,
    compute_crt: bool,
) -> Result<AuxInfo<L>, KeyRefreshError>
where
    R: RngCore + CryptoRng,
    M: Mpc<ProtocolMessage = Msg<D, L>>,
    L: SecurityLevel,
    D: Digest<OutputSize = digest::typenum::U32> + Clone + 'static,
{
    // Generate Paillier and Pedersen parameters
    // Prove they are well-formed
    // -------------
    // Paillier: N = p * q, p and q are prime
    // Pedersen: (N, s, t) is Ring Pedersen Parameters
    // -------------
    // Pi_prm: prove s mod t = 0 (mod N) - ring pedersen parameters
    // Pi_fac: N can be factored into two factors no larger than sqrt(N).2^{l + epsilon}.
    // Pi_mod: prove N = pq, with p and q being Blum primes, and gcd(N, phi(N)) = 1 without disclosing p and q.
    // -------------
    tracer.protocol_begins();

    std::println!("run_aux_gen: 1");

    tracer.stage("Retrieve auxiliary data");

    tracer.stage("Setup networking");
    let MpcParty { delivery, .. } = party.into_party();
    let (incomings, mut outgoings) = delivery.split();

    let mut rounds = RoundsRouter::<Msg<D, L>>::builder();
    let round1 = rounds.add_round(RoundInput::<MsgRound1<D>>::broadcast(i, n));
    let round1_sync = rounds.add_round(RoundInput::<MsgReliabilityCheck<D>>::broadcast(i, n));
    let round2 = rounds.add_round(RoundInput::<MsgRound2<L>>::broadcast(i, n));
    let round3 = rounds.add_round(RoundInput::<MsgRound3>::p2p(i, n));
    let mut rounds = rounds.listen(incomings);

    // Round 1
    tracer.round_begins();

    std::println!("run_aux_gen: 2");

    // 2 primes p and q
    // N = p * q
    // phi_N = (p - 1) * (q - 1)
    tracer.stage("Retrieve data from paillier decryption key");
    // TODO: prove optimized Paillier decryption key
    let PregeneratedPaillierKey { dec, .. } = pregenerated;
    let p = dec.p();
    let q = dec.q();

    std::println!("run_aux_gen: 3");
    let N = (p * q);
    let phi_N = (p - 1u8) * (q - 1u8);

    std::println!("run_aux_gen: 4");

    tracer.stage("Generate auxiliary params r, λ, t, s");
    // r in Z_N*
    let r = BigInt::gen_invertible(&N, rng);
    // 0 <= lambda < phi_N
    let lambda = rng.gen_bigint_range(&BigInt::from(0), &phi_N);
    // t = r^2 mod N
    let t = r.modpow(&BigInt::from(2), &N);
    // s = t^lambda mod N
    let s = t.modpow(&lambda, &N);

    std::println!("run_aux_gen: 5");

    tracer.stage("Prove Πprm (ψˆ_i)");
    // (N, s, t) is Ring Pedersen Parameters
    // ψˆ_i: proof s mod (t mod N) = 0
    let hat_psi = π_prm::prove::<{ crate::security_level::M }, D>(
        &unambiguous::ProofPrm { sid, prover: i },
        &mut rng,
        π_prm::Data {
            N: &N,
            s: &s,
            t: &t,
        },
        &phi_N,
        &lambda,
    )
    .map_err(Bug::PiPrm)?;

    std::println!("run_aux_gen: 6");

    tracer.stage("Sample random bytes");
    // rho_i in paper, this signer's share of bytes
    let mut rho_bytes = L::Rid::default();
    rng.fill_bytes(rho_bytes.as_mut());

    tracer.stage("Compute hash commitment and sample decommitment");

    std::println!("run_aux_gen: 7");

    // V_i and u_i in paper
    let decommitment = MsgRound2 {
        N: N.clone(),
        enc: dec.encryption_key().clone(),
        s: s.clone(),
        t: t.clone(),
        params_proof: hat_psi,
        rho_bytes: rho_bytes.clone(),
        decommit: {
            let mut nonce = L::Rid::default();
            rng.fill_bytes(nonce.as_mut());
            nonce
        },
    };
    let hash_commit = udigest::hash::<D>(&unambiguous::HashCom {
        sid,
        prover: i,
        decommitment: &decommitment,
    });

    std::println!("run_aux_gen: 8");

    tracer.send_msg();
    let commitment = MsgRound1 {
        commitment: hash_commit,
    };
    outgoings
        .send(Outgoing::broadcast(Msg::Round1(commitment.clone())))
        .await
        .map_err(IoError::send_message)?;
    tracer.msg_sent();

    std::println!("run_aux_gen: 9");

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
                .iter_including_me(&commitment)
                .map(|commitment| unambiguous::Echo { sid, commitment }),
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
        let hashes = rounds
            .complete(round1_sync)
            .await
            .map_err(IoError::receive_message)?;
        tracer.msgs_received();

        tracer.stage("Assert other parties hashed messages (reliability check)");
        let parties_have_different_hashes = hashes
            .into_iter_indexed()
            .filter(|(_j, _msg_id, h_j)| h_i != h_j.0)
            .map(|(j, msg_id, _)| AbortBlame::new(j, msg_id, msg_id))
            .collect::<Vec<_>>();
        if !parties_have_different_hashes.is_empty() {
            return Err(ProtocolAborted::round1_not_reliable(parties_have_different_hashes).into());
        }
    }

    std::println!("run_aux_gen: 9");
    tracer.send_msg();
    outgoings
        .send(Outgoing::broadcast(Msg::Round2(decommitment.clone())))
        .await
        .map_err(IoError::send_message)?;
    tracer.msg_sent();

    // Round 3
    tracer.round_begins();

    tracer.receive_msgs();
    let decommitments = rounds
        .complete(round2)
        .await
        .map_err(IoError::receive_message)?;
    tracer.msgs_received();

    std::println!("run_aux_gen: 10");
    // validate decommitments
    tracer.stage("Validate round 1 decommitments");
    let blame = collect_blame(&decommitments, &commitments, |j, decomm, comm| {
        let com_expected = udigest::hash::<D>(&unambiguous::HashCom {
            sid,
            prover: j,
            decommitment: decomm,
        });
        com_expected != comm.commitment
    });
    if !blame.is_empty() {
        return Err(ProtocolAborted::invalid_decommitment(blame).into());
    }

    std::println!("run_aux_gen: 11");
    // validate parameters and param_proofs
    tracer.stage("Validate П_prm (ψ_i)");
    let blame = collect_blame(&decommitments, &decommitments, |j, d, _| {
        if !crate::security_level::validate_public_paillier_key_size::<L>(&d.N) {
            true
        } else {
            let data = π_prm::Data {
                N: &d.N,
                s: &d.s,
                t: &d.t,
            };
            π_prm::verify::<{ crate::security_level::M }, D>(
                &unambiguous::ProofPrm { sid, prover: j },
                data,
                &d.params_proof,
            )
            .is_err()
        }
    });
    if !blame.is_empty() {
        return Err(ProtocolAborted::invalid_ring_pedersen_parameters(blame).into());
    }

    std::println!("run_aux_gen: 12");

    tracer.stage("Add together shared random bytes");
    // rho in paper, collective random bytes
    let rho_bytes = decommitments
        .iter()
        .map(|d| &d.rho_bytes)
        .fold(rho_bytes, utils::xor_array);

    // common data for messages

    std::println!("run_aux_gen: 13");

    tracer.stage("Compute П_mod (ψ_i)");
    let psi = π_mod::non_interactive::prove::<{ crate::security_level::M }, D>(
        &unambiguous::ProofMod {
            sid,
            rho: rho_bytes.as_ref(),
            prover: i,
        },
        &π_mod::Data { n: N.clone() },
        &π_mod::PrivateData {
            p: p.clone(),
            q: q.clone(),
        },
        &mut rng,
    )
    .map_err(Bug::PiMod)?;

    std::println!("run_aux_gen: 14");
    tracer.stage("Assemble security params for П_fac (ф_i)");
    let π_fac_security = π_fac::SecurityParams {
        l: L::ELL,
        epsilon: L::EPSILON,
        q: L::q(),
    };
    let n_sqrt = utils::sqrt(&N);

    std::println!("run_aux_gen: 15");
    // message to each party
    for (j, _, d) in decommitments.iter_indexed() {
        tracer.send_msg();

        tracer.stage("Compute П_fac (ф_i^j)");
        let phi = π_fac::prove::<D>(
            &unambiguous::ProofFac {
                sid,
                rho: rho_bytes.as_ref(),
                prover: i,
            },
            &π_fac::Aux {
                s: d.s.clone(),
                t: d.t.clone(),
                rsa_modulo: d.N.clone(),
                multiexp: None,
                crt: None,
            },
            π_fac::Data {
                n: &N,
                n_root: &n_sqrt,
            },
            π_fac::PrivateData { p: &p, q: &q },
            &π_fac_security,
            &mut rng,
        )
        .map_err(Bug::PiFac)?;

        tracer.send_msg();
        let msg = MsgRound3 {
            mod_proof: psi.clone(),
            fac_proof: phi.clone(),
        };
        outgoings
            .feed(Outgoing::p2p(j, Msg::Round3(msg)))
            .await
            .map_err(IoError::send_message)?;
        tracer.msg_sent();
    }

    tracer.send_msg();
    outgoings.flush().await.map_err(IoError::send_message)?;
    tracer.msg_sent();

    // Output

    std::println!("run_aux_gen: 16");
    tracer.round_begins();

    tracer.receive_msgs();
    let shares_msg_b = rounds
        .complete(round3)
        .await
        .map_err(IoError::receive_message)?;
    tracer.msgs_received();

    tracer.stage("Validate ψ_j (П_mod)");

    std::println!("run_aux_gen: 17");
    // verify mod proofs
    let blame = collect_blame(
        &decommitments,
        &shares_msg_b,
        |j, decommitment, proof_msg| {
            let data = π_mod::Data {
                n: decommitment.N.clone(),
            };
            let (comm, proof) = &proof_msg.mod_proof;
            π_mod::non_interactive::verify::<{ crate::security_level::M }, D>(
                &unambiguous::ProofMod {
                    sid,
                    rho: rho_bytes.as_ref(),
                    prover: j,
                },
                &data,
                comm,
                proof,
            )
            .is_err()
        },
    );
    if !blame.is_empty() {
        return Err(ProtocolAborted::invalid_mod_proof(blame).into());
    }

    std::println!("run_aux_gen: 18");
    tracer.stage("Validate ф_j (П_fac)");
    // verify fac proofs

    let crt = if compute_crt {
        // note: `crt` contains private information
        Some(paillier_zk::fast_paillier::utils::CrtExp::build_n(&p, &q).ok_or(Bug::BuildCrt)?)
    } else {
        None
    };
    let phi_common_aux = π_fac::Aux {
        s: s.clone(),
        t: t.clone(),
        rsa_modulo: N.clone(),
        multiexp: None,
        crt: crt.clone(),
    };

    std::println!("run_aux_gen: 19");
    let blame = collect_blame(
        &decommitments,
        &shares_msg_b,
        |j, decommitment, proof_msg| {
            π_fac::verify::<D>(
                &unambiguous::ProofFac {
                    sid,
                    rho: rho_bytes.as_ref(),
                    prover: j,
                },
                &phi_common_aux,
                π_fac::Data {
                    n: &decommitment.N,
                    n_root: &utils::sqrt(&decommitment.N),
                },
                &π_fac_security,
                &proof_msg.fac_proof,
            )
            .is_err()
        },
    );
    if !blame.is_empty() {
        return Err(ProtocolAborted::invalid_fac_proof(blame).into());
    }

    // verifications passed, compute final key shares

    std::println!("run_aux_gen: 20");
    tracer.stage("Assemble auxiliary info");
    let mut party_auxes = decommitments
        .iter_including_me(&decommitment)
        .map(|d| PartyAux {
            N: d.N.clone(),
            enc: d.enc.clone(),
            s: d.s.clone(),
            t: d.t.clone(),
            multiexp: None,
            crt: None,
        })
        .collect::<Vec<_>>();
    party_auxes[usize::from(i)].crt = crt;
    let mut aux = DirtyAuxInfo {
        dec,
        parties: party_auxes,
        security_level: std::marker::PhantomData,
    };

    if compute_multiexp_table {
        tracer.stage("Precompute multiexp tables");

        aux.precompute_multiexp_tables()
            .map_err(Bug::BuildMultiexpTables)?;
    }

    std::println!("run_aux_gen: 21");
    let aux = aux
        .validate()
        .map_err(|err| Bug::InvalidShareGenerated(err.into_error()))?;

    std::println!("run_aux_gen: 22");
    tracer.protocol_ends();

    std::println!("run_aux_gen: 23");
    Ok(aux)
}

/// Creates a commitment for round 1 of the auxiliary generation protocol
pub fn create_message_round_1<R, D, L>(
    rng: &mut R,
    sid: ExecutionId<'_>,
    i: u16,
    pregenerated: &PregeneratedPaillierKey<L>,
) -> Result<
    (
        MsgRound1<D>,
        MsgRound2<L>,
        BigInt,
        BigInt,
        π_prm::Proof<{ crate::security_level::M }>,
        L::Rid,
    ),
    Bug,
>
where
    R: RngCore + CryptoRng,
    D: Digest<OutputSize = digest::typenum::U32> + Clone + 'static,
    L: SecurityLevel,
{
    // Retrieve data from paillier decryption key
    let dec = &pregenerated.dec;
    let p = dec.p();
    let q = dec.q();

    let N = (p * q);
    let phi_N = (p - 1u8) * (q - 1u8);

    // Generate auxiliary params r, λ, t, s
    // r in Z_N*
    let r = BigInt::gen_invertible(&N, rng);
    // 0 <= lambda < phi_N
    let lambda = rng.gen_bigint_range(&BigInt::from(0), &phi_N);
    // t = r^2 mod N
    let t = r.modpow(&BigInt::from(2), &N);
    // s = t^lambda mod N
    let s = t.modpow(&lambda, &N);

    // Prove Πprm (ψˆ_i)
    // (N, s, t) is Ring Pedersen Parameters
    // ψˆ_i: proof s mod (t mod N) = 0
    let hat_psi = π_prm::prove::<{ crate::security_level::M }, D>(
        &unambiguous::ProofPrm { sid, prover: i },
        rng,
        π_prm::Data {
            N: &N,
            s: &s,
            t: &t,
        },
        &phi_N,
        &lambda,
    )
    .map_err(Bug::PiPrm)?;

    // Sample random bytes
    // rho_i in paper, this signer's share of bytes
    let mut rho_bytes = L::Rid::default();
    rng.fill_bytes(rho_bytes.as_mut());

    // Compute hash commitment and sample decommitment
    let decommitment = MsgRound2 {
        N: N.clone(),
        enc: dec.encryption_key().clone(),
        s: s.clone(),
        t: t.clone(),
        params_proof: hat_psi.clone(),
        rho_bytes: rho_bytes.clone(),
        decommit: {
            let mut nonce = L::Rid::default();
            rng.fill_bytes(nonce.as_mut());
            nonce
        },
    };

    let hash_commit = udigest::hash::<D>(&unambiguous::HashCom {
        sid,
        prover: i,
        decommitment: &decommitment,
    });

    let commitment = MsgRound1 {
        commitment: hash_commit,
    };

    Ok((commitment, decommitment, N, phi_N, hat_psi, rho_bytes))
}

/// Creates a reliability check message for round 1 of the auxiliary generation protocol
pub fn create_message_reliability_check<D>(
    commitments: &RoundMsgs<MsgRound1<D>>,
    commitment: &MsgRound1<D>,
    sid: ExecutionId<'_>,
) -> MsgReliabilityCheck<D>
where
    D: Digest<OutputSize = digest::typenum::U32> + Clone + 'static,
{
    let h_i = udigest::hash_iter::<D>(
        commitments
            .iter_including_me(commitment)
            .map(|commitment| unambiguous::Echo { sid, commitment }),
    );

    MsgReliabilityCheck(h_i)
}

/// Validates decommitments from round 2
pub fn validate_decommitments<D, L>(
    decommitments: &RoundMsgs<MsgRound2<L>>,
    commitments: &RoundMsgs<MsgRound1<D>>,
    sid: ExecutionId<'_>,
) -> Result<Vec<AbortBlame>, ()>
where
    D: Digest<OutputSize = digest::typenum::U32> + Clone + 'static,
    L: SecurityLevel,
{
    let blame = collect_blame(decommitments, commitments, |j, decomm, comm| {
        let com_expected = udigest::hash::<D>(&unambiguous::HashCom {
            sid,
            prover: j,
            decommitment: decomm,
        });
        com_expected != comm.commitment
    });

    Ok(blame)
}

/// Validates ring pedersen parameters (Π_prm)
pub fn validate_ring_pedersen_parameters<D, L>(
    decommitments: &RoundMsgs<MsgRound2<L>>,
    sid: ExecutionId<'_>,
) -> Result<Vec<AbortBlame>, ()>
where
    D: Digest<OutputSize = digest::typenum::U32> + Clone + 'static,
    L: SecurityLevel,
{
    let blame = collect_blame(decommitments, decommitments, |j, d, _| {
        if !crate::security_level::validate_public_paillier_key_size::<L>(&d.N) {
            true
        } else {
            let data = π_prm::Data {
                N: &d.N,
                s: &d.s,
                t: &d.t,
            };
            π_prm::verify::<{ crate::security_level::M }, D>(
                &unambiguous::ProofPrm { sid, prover: j },
                data,
                &d.params_proof,
            )
            .is_err()
        }
    });

    Ok(blame)
}

/// Combines the random bytes from all parties
pub fn combine_random_bytes<L>(
    decommitments: &RoundMsgs<MsgRound2<L>>,
    my_rho_bytes: &L::Rid,
    my_decommitment: &MsgRound2<L>,
) -> L::Rid
where
    L: SecurityLevel,
{
    decommitments
        .iter_including_me(my_decommitment)
        .map(|d| &d.rho_bytes)
        .fold(my_rho_bytes.clone(), utils::xor_array)
}

/// Creates proofs for round 3 of the auxiliary generation protocol
pub fn create_message_round_3<R, D, L>(
    rng: &mut R,
    sid: ExecutionId<'_>,
    i: u16,
    p: &BigInt,
    q: &BigInt,
    N: &BigInt,
    rho_bytes: &L::Rid,
    decommitments: &RoundMsgs<MsgRound2<L>>,
) -> Result<Vec<(u16, MsgRound3)>, Bug>
where
    R: RngCore + CryptoRng,
    D: Digest<OutputSize = digest::typenum::U32> + Clone + 'static,
    L: SecurityLevel,
{
    // Compute П_mod (ψ_i)
    let psi = π_mod::non_interactive::prove::<{ crate::security_level::M }, D>(
        &unambiguous::ProofMod {
            sid,
            rho: rho_bytes.as_ref(),
            prover: i,
        },
        &π_mod::Data { n: N.clone() },
        &π_mod::PrivateData {
            p: p.clone(),
            q: q.clone(),
        },
        rng,
    )
    .map_err(Bug::PiMod)?;

    // Assemble security params for П_fac (ф_i)
    let π_fac_security = π_fac::SecurityParams {
        l: L::ELL,
        epsilon: L::EPSILON,
        q: L::q(),
    };

    let n_sqrt = utils::sqrt(N);

    let mut messages = Vec::new();

    // Create a message for each party
    for (j, _, d) in decommitments.iter_indexed() {
        // Compute П_fac (ф_i^j)
        let phi = π_fac::prove::<D>(
            &unambiguous::ProofFac {
                sid,
                rho: rho_bytes.as_ref(),
                prover: i,
            },
            &π_fac::Aux {
                s: d.s.clone(),
                t: d.t.clone(),
                rsa_modulo: d.N.clone(),
                multiexp: None,
                crt: None,
            },
            π_fac::Data {
                n: N,
                n_root: &n_sqrt,
            },
            π_fac::PrivateData { p, q },
            &π_fac_security,
            rng,
        )
        .map_err(Bug::PiFac)?;

        let msg = MsgRound3 {
            mod_proof: psi.clone(),
            fac_proof: phi,
        };

        messages.push((j, msg));
    }

    Ok(messages)
}

/// Validates proofs from round 3
pub fn validate_proofs_round_3<D, L>(
    decommitments: &RoundMsgs<MsgRound2<L>>,
    round3_msgs: &RoundMsgs<MsgRound3>,
    rho_bytes: &L::Rid,
    sid: ExecutionId<'_>,
    phi_common_aux: &π_fac::Aux,
) -> Result<(), Bug>
where
    D: Digest<OutputSize = digest::typenum::U32> + Clone + 'static,
    L: SecurityLevel,
{
    // Security parameters for П_fac
    let π_fac_security = π_fac::SecurityParams {
        l: L::ELL,
        epsilon: L::EPSILON,
        q: L::q(),
    };

    // Validate mod proofs
    let mod_blame = collect_blame(decommitments, round3_msgs, |j, decommitment, proof_msg| {
        let data = π_mod::Data {
            n: decommitment.N.clone(),
        };
        let (comm, proof) = &proof_msg.mod_proof;
        π_mod::non_interactive::verify::<{ crate::security_level::M }, D>(
            &unambiguous::ProofMod {
                sid,
                rho: rho_bytes.as_ref(),
                prover: j,
            },
            &data,
            comm,
            proof,
        )
        .is_err()
    });

    if !mod_blame.is_empty() {
        return Err(Bug::InvalidModProof.into());
    }

    // Validate fac proofs
    let fac_blame = collect_blame(decommitments, round3_msgs, |j, decommitment, proof_msg| {
        π_fac::verify::<D>(
            &unambiguous::ProofFac {
                sid,
                rho: rho_bytes.as_ref(),
                prover: j,
            },
            phi_common_aux,
            π_fac::Data {
                n: &decommitment.N,
                n_root: &utils::sqrt(&decommitment.N),
            },
            &π_fac_security,
            &proof_msg.fac_proof,
        )
        .is_err()
    });

    if !fac_blame.is_empty() {
        return Err(Bug::InvalidFacProof.into());
    }

    Ok(())
}

/// Assembles auxiliary info from validated proofs
pub fn assemble_aux_info<L>(
    decommitments: &RoundMsgs<MsgRound2<L>>,
    my_decommitment: &MsgRound2<L>,
    i: u16,
    dec: fast_paillier::DecryptionKey,
    crt: Option<paillier_zk::fast_paillier::utils::CrtExp>,
    compute_multiexp_table: bool,
) -> Result<AuxInfo<L>, Bug>
where
    L: SecurityLevel,
{
    let mut party_auxes = decommitments
        .iter_including_me(my_decommitment)
        .map(|d| PartyAux {
            N: d.N.clone(),
            enc: d.enc.clone(),
            s: d.s.clone(),
            t: d.t.clone(),
            multiexp: None,
            crt: None,
        })
        .collect::<Vec<_>>();

    party_auxes[usize::from(i)].crt = crt;

    let mut aux = DirtyAuxInfo {
        dec,
        parties: party_auxes,
        security_level: std::marker::PhantomData,
    };

    if compute_multiexp_table {
        aux.precompute_multiexp_tables();
    }

    let aux = aux
        .validate()
        .map_err(|err| Bug::InvalidShareGenerated(err.into_error()))?;

    Ok(aux)
}
