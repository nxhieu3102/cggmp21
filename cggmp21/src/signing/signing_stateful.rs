//! Stateful signing protocol implementation
//! 
//! This module provides a stateful implementation of the CGGMP21 signing protocol
//! that allows for step-by-step execution of each round, suitable for WASM integration.

use digest::Digest;
use generic_ec::{coords::AlwaysHasAffineX, Curve, NonZero, Point, Scalar, SecretScalar};
use generic_ec_zkp::polynomial::lagrange_coefficient_at_zero;

use paillier_zk::{
    batch_paillier_affine_operation_in_range as pi_aff_batch,
    batch_paillier_encryption_in_range_with_el_gamal as pi_enc_el_gamal_batch,
    dlog_with_el_gamal_commitment as pi_elog, BigIntExt
};
use num_bigint::{BigInt, RandBigInt};
use paillier_zk::fast_paillier;
use paillier_zk::fast_paillier::precomputed_table;
use rand_core::{CryptoRng, RngCore};
use round_based::rounds_router::simple_store::RoundMsgs;
use thiserror::Error;

use crate::key_share::{KeyShare, PartyAux, VssSetup};
use crate::{security_level::SecurityLevel, utils, ExecutionId};
use crate::signing::{
    DataToSign, Presignature, Signature, 
    msg::{MsgRound1a, MsgRound1b, MsgRound2, MsgRound3, MsgRound4, MsgReliabilityCheck}
};

use birkhoff::birkhoff_coefficient::birkhoff_coefficient;

/// Error during signing protocol execution
#[derive(Debug, Error)]
#[error("signing protocol failed")]
pub struct SigningError(#[source] SigningErrorReason);

#[derive(Debug, Error)]
enum SigningErrorReason {
    #[error("invalid arguments: {0}")]
    InvalidArgs(String),
    #[error("protocol was maliciously aborted: {0}")]
    Aborted(String),
    #[error("internal bug: {0}")]
    Bug(String),
}

/// Error during SigningProtocol parameter validation
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SigningParameterError {
    /// Party index is invalid
    #[error("Party index {i} must be less than the number of parties {n}")]
    InvalidPartyIndex { 
        /// Party index
        i: u16, 
        /// Number of parties
        n: u16 
    },
    /// Too few parties for the protocol
    #[error("Number of parties must be at least 2, got {0}")]
    TooFewParties(u16),
    /// Mismatched amount of parties for threshold
    #[error("At least threshold amount of parties should take part in signing")]
    MismatchedAmountOfParties,
    /// Invalid sub-index
    #[error("Party index in S is out of bounds (must be < n)")]
    InvalidSubIndex,
}

/// State for the signing protocol
pub struct SigningState<E: Curve, L: SecurityLevel, D: Digest + Clone + 'static> {
    /// Party index in signing group
    pub i: u16,
    /// Indexes of parties participating in signing
    pub signing_parties: Vec<u16>,
    /// Protocol execution ID
    pub sid: ExecutionId<'static>,
    /// Whether to enforce reliable broadcast
    pub reliable_broadcast_enforced: bool,
    /// Message to sign (None for presignature generation)
    pub message_to_sign: Option<DataToSign<E>>,
    
    // Round 1 data
    /// Local ephemeral secrets
    pub k_i: Option<Scalar<E>>,
    /// Local ephemeral secret gamma_i
    pub gamma_i: Option<Scalar<E>>,
    /// Random nonce rho_i
    pub rho_i: Option<BigInt>,
    /// Random nonce nu_i
    pub nu_i: Option<BigInt>,
    /// Encrypted values
    pub K_i: Option<fast_paillier::Ciphertext>,
    /// Encrypted G_i value
    pub G_i: Option<fast_paillier::Ciphertext>,
    /// ElGamal commitment values
    pub Y_i: Option<Point<E>>,
    /// ElGamal commitment A_i1
    pub A_i1: Option<Point<E>>,
    /// ElGamal commitment A_i2
    pub A_i2: Option<Point<E>>,
    /// ElGamal commitment B_i1
    pub B_i1: Option<Point<E>>,
    /// ElGamal commitment B_i2
    pub B_i2: Option<Point<E>>,
    /// Random value a_i
    pub a_i: Option<Scalar<E>>,
    /// Random value b_i
    pub b_i: Option<Scalar<E>>,
    /// My round 1a message
    pub my_round1a: Option<MsgRound1a<E>>,
    
    // Round 1b data  
    /// Round 1a messages from other parties
    pub round1a_msgs: Option<RoundMsgs<MsgRound1a<E>>>,
    /// My reliability check message
    pub my_reliability_check: Option<MsgReliabilityCheck<D>>,
    
    // Round 2 data
    /// Round 1b messages from other parties
    pub round1b_msgs: Option<RoundMsgs<MsgRound1b<E>>>,
    /// Gamma_i point
    pub Gamma_i: Option<Point<E>>,
    /// Sum of beta values
    pub beta_sum: Option<Scalar<E>>,
    /// Sum of hat_beta values
    pub hat_beta_sum: Option<Scalar<E>>,
    
    // Round 3 data  
    /// Round 2 messages from other parties
    pub round2_msgs: Option<RoundMsgs<MsgRound2<E>>>,
    /// Delta_i value
    pub delta_i: Option<Scalar<E>>,
    /// Chi_i value
    pub chi_i: Option<Scalar<E>>,
    /// S_i point
    pub S_i: Option<Point<E>>,
    /// Delta_i point
    pub Delta_i: Option<Point<E>>,
    
    // Round 4 data
    /// Round 3 messages from other parties
    pub round3_msgs: Option<RoundMsgs<MsgRound3<E>>>,
    /// Generated presignature
    pub presignature: Option<Presignature<E>>,
    
    // Final output
    /// Round 4 messages from other parties
    pub round4_msgs: Option<RoundMsgs<MsgRound4<E>>>,
    /// Final signature
    pub signature: Option<Signature<E>>,
    
    // Phantom data for unused type parameters
    _phantom: std::marker::PhantomData<L>,
}

/// Protocol implementation for signing
pub struct SigningProtocol<
    E: Curve,
    R: RngCore + CryptoRng,
    L: SecurityLevel,
    D: Digest + Clone + 'static,
> {
    /// Internal protocol state
    pub state: SigningState<E, L, D>,
    /// Random number generator
    pub rng: R,
    /// Key share for this party
    pub key_share: KeyShare<E, L>,
    /// Derived key data for signing
    pub x_i: NonZero<SecretScalar<E>>,
    /// Public key shares
    pub X: Vec<NonZero<Point<E>>>,
    /// Shared public key
    pub shared_public_key: Point<E>,
    /// Party auxiliary data
    pub R: Vec<PartyAux>,
    /// Cached precompute tables for benchmarking purposes
    pub cached_precompute_tables: Option<Vec<precomputed_table::PrecomputeTable>>,
}

impl<
    E: Curve,
    R: RngCore + CryptoRng,
    L: SecurityLevel,
    D: Digest<OutputSize = digest::typenum::U32> + Clone + 'static,
> SigningProtocol<E, R, L, D>
where
    NonZero<Point<E>>: AlwaysHasAffineX<E>,
{
    /// Validates signing parameters
    fn validate_parameters(
        i: u16,
        signing_parties: &[u16],
        key_share: &KeyShare<E, L>,
    ) -> Result<(), SigningParameterError> {
        let n: u16 = key_share
            .aux
            .parties
            .len()
            .try_into()
            .map_err(|_| SigningParameterError::TooFewParties(0))?;
        let t = key_share
            .core
            .vss_setup
            .as_ref()
            .map(|s| s.min_signers)
            .unwrap_or(n);
        
        if signing_parties.len() < usize::from(t) {
            return Err(SigningParameterError::MismatchedAmountOfParties);
        }
        if !((i as usize) < signing_parties.len()) {
            return Err(SigningParameterError::InvalidPartyIndex { 
                i, 
                n: signing_parties.len() as u16 
            });
        }
        if signing_parties.iter().any(|&S_j| S_j >= n) {
            return Err(SigningParameterError::InvalidSubIndex);
        }

        Ok(())
    }

    /// Create a new signing protocol instance
    pub fn new(
        i: u16,
        signing_parties: Vec<u16>,
        key_share: KeyShare<E, L>,
        sid: ExecutionId<'static>,
        rng: R,
        message_to_sign: Option<DataToSign<E>>,
        reliable_broadcast_enforced: bool,
        additive_shift: Option<Scalar<E>>,
        cached_precompute_tables: Option<Vec<precomputed_table::PrecomputeTable>>,
    ) -> Result<Self, SigningParameterError> {
        Self::validate_parameters(i, &signing_parties, &key_share)?;

        // Convert t-out-of-n to t-out-of-t (same logic as in original signing.rs)
        let n: u16 = key_share.aux.parties.len() as u16;
        let t = key_share
            .core
            .vss_setup
            .as_ref()
            .map(|s| s.min_signers)
            .unwrap_or(n);

        let (mut x_i, mut X) = if let Some(VssSetup { I, ranks, .. }) = &key_share.core.vss_setup {
            if let Some(ref ranks) = ranks {
                // HTSS - Birkhoff interpolation
                let I = utils::subset(&signing_parties, I).unwrap();
                let X = utils::subset(&signing_parties, &key_share.core.public_shares).unwrap();
                let ranks = utils::subset(&signing_parties, ranks).unwrap();

                let birkhoff = birkhoff_coefficient(t, &I, &ranks).unwrap();
                let birkhoff_i = birkhoff.get(usize::from(i)).unwrap();
                let x_i = (birkhoff_i * &key_share.core.x).into_secret();

                let X = birkhoff
                    .iter()
                    .zip(&X)
                    .map(|(birkhoff_j, X_j)| birkhoff_j * X_j)
                    .collect::<Vec<_>>();

                (x_i, X)
            } else {
                // TSS - Lagrange interpolation
                let I = utils::subset(&signing_parties, I).unwrap();
                let X = utils::subset(&signing_parties, &key_share.core.public_shares).unwrap();

                let lambda_i = lagrange_coefficient_at_zero(usize::from(i), &I).unwrap();
                let x_i = (lambda_i * &key_share.core.x).into_secret();

                let lambda = (0..signing_parties.len()).map(|j| lagrange_coefficient_at_zero(j, &I));
                let X = lambda
                    .zip(&X)
                    .map(|(lambda_j, X_j)| lambda_j.unwrap() * X_j)
                    .collect::<Vec<_>>();

                (x_i, X)
            }
        } else {
            // n-out-of-n keys
            let X = utils::subset(&signing_parties, &key_share.core.public_shares).unwrap();
            (key_share.core.x.clone(), X)
        };

        // Apply additive shift
        let shift = additive_shift.unwrap_or(Scalar::zero());
        let Shift = Point::generator() * shift;

        X[0] = NonZero::from_point(X[0] + Shift).unwrap();
        if i == 0 {
            x_i = NonZero::from_scalar(x_i + shift).unwrap().into_secret();
        }

        let shared_public_key = key_share.core.shared_public_key + Shift;
        let R = utils::subset(&signing_parties, &key_share.aux.parties).unwrap();

        Ok(Self {
            state: SigningState {
                i,
                signing_parties: signing_parties.clone(),
                sid,
                reliable_broadcast_enforced,
                message_to_sign,
                k_i: None,
                gamma_i: None,
                rho_i: None,
                nu_i: None,
                K_i: None,
                G_i: None,
                Y_i: None,
                A_i1: None,
                A_i2: None,
                B_i1: None,
                B_i2: None,
                a_i: None,
                b_i: None,
                my_round1a: None,
                round1a_msgs: None,
                my_reliability_check: None,
                round1b_msgs: None,
                Gamma_i: None,
                beta_sum: None,
                hat_beta_sum: None,
                round2_msgs: None,
                delta_i: None,
                chi_i: None,
                S_i: None,
                Delta_i: None,
                round3_msgs: None,
                presignature: None,
                round4_msgs: None,
                signature: None,
                _phantom: std::marker::PhantomData,
            },
            rng,
            key_share,
            x_i,
            X,
            shared_public_key,
            R,
            cached_precompute_tables,
        })
    }

    /// Generate round 1a message
    pub fn round1a_generate_message(&mut self) -> Result<MsgRound1a<E>, SigningError> {
        // Generate local ephemeral secrets
        let k_i = Scalar::<E>::random(&mut self.rng);
        let gamma_i = Scalar::<E>::random(&mut self.rng);

        let R_i = &self.R[usize::from(self.state.i)];
        let N_i = &R_i.N;
        let rho_i = BigInt::gen_invertible(N_i, &mut self.rng);
        let nu_i = BigInt::gen_invertible(N_i, &mut self.rng);

        // Encrypt k_i and gamma_i
        let dec_i = &self.key_share.aux.dec;
        let ek_i = dec_i.encryption_key();
        
        // Use cached precompute table if available, otherwise create a new one
        let precomputable = if let Some(ref cached_tables) = self.cached_precompute_tables {
            if let Some(cached_table) = cached_tables.get(usize::from(self.state.i)) {
                cached_table.clone()
            } else {
                // Fallback to creating a new table if not enough cached tables
                let h_pow_n = ek_i.h_pow_n().clone();
                let nn = ek_i.nn().clone();
                let a_size = ek_i.a_size() as usize;
                precomputed_table::PrecomputeTable::new_dp(h_pow_n, 10, a_size, nn)
            }
        } else {
            // No cached tables available, create a new one
            let h_pow_n = ek_i.h_pow_n().clone();
            let nn = ek_i.nn().clone();
            let a_size = ek_i.a_size() as usize;
            precomputed_table::PrecomputeTable::new_dp(h_pow_n, 10, a_size, nn)
        };
        
        let K_i = ek_i
            .encrypt_with_precompute_table(&mut self.rng, &precomputable, &utils::scalar_to_bignumber(&k_i), Some(&rho_i))
            .map_err(|e| SigningError(SigningErrorReason::Bug(format!("Failed to encrypt K_i: {:?}", e))))?;
        let G_i = ek_i
            .encrypt_with_precompute_table(&mut self.rng, &precomputable, &utils::scalar_to_bignumber(&gamma_i), Some(&nu_i))
            .map_err(|e| SigningError(SigningErrorReason::Bug(format!("Failed to encrypt G_i: {:?}", e))))?;

        // Generate ElGamal commitment values
        let Y_i = Point::generator() * Scalar::<E>::random(&mut self.rng);
        let a_i = Scalar::random(&mut self.rng);
        let b_i = Scalar::random(&mut self.rng);

        let (A_i1, A_i2) = (
            Point::generator() * &a_i,
            Y_i * &a_i + Point::generator() * &k_i,
        );
        let (B_i1, B_i2) = (
            Point::generator() * &b_i,
            Y_i * &b_i + Point::generator() * &gamma_i,
        );

        let msg = MsgRound1a {
            K_i: K_i.clone(),
            G_i: G_i.clone(),
            Y_i,
            A_i1,
            A_i2,
            B_i1,
            B_i2,
        };

        // Store state
        self.state.k_i = Some(k_i);
        self.state.gamma_i = Some(gamma_i);
        self.state.rho_i = Some(rho_i);
        self.state.nu_i = Some(nu_i);
        self.state.K_i = Some(K_i);
        self.state.G_i = Some(G_i);
        self.state.Y_i = Some(Y_i);
        self.state.A_i1 = Some(A_i1);
        self.state.A_i2 = Some(A_i2);
        self.state.B_i1 = Some(B_i1);
        self.state.B_i2 = Some(B_i2);
        self.state.a_i = Some(a_i);
        self.state.b_i = Some(b_i);
        self.state.my_round1a = Some(msg.clone());

        Ok(msg)
    }

    /// Set round 1a messages from other parties
    pub fn set_round1a_messages(
        &mut self,
        messages: Vec<MsgRound1a<E>>,
        ids: Vec<u64>,
    ) -> Result<(), SigningError> {
        let round_msgs = RoundMsgs::new(self.state.i, ids, messages);
        self.state.round1a_msgs = Some(round_msgs);
        Ok(())
    }

    /// Create reliability check message
    pub fn create_reliability_check(&mut self) -> Result<MsgReliabilityCheck<D>, SigningError> {
        let round1a_msgs = self
            .state
            .round1a_msgs
            .as_ref()
            .ok_or_else(|| SigningError(SigningErrorReason::Bug("Round 1a messages not set".to_string())))?;

        let my_round1a = self
            .state
            .my_round1a
            .as_ref()
            .ok_or_else(|| SigningError(SigningErrorReason::Bug("My round 1a message not generated".to_string())))?;

        // Use same Echo struct as in original signing.rs
        #[derive(udigest::Digestable)]
        #[udigest(tag = "dfns.cggmp21.signing.echo_round")]
        #[udigest(bound = "")]
        struct Echo<'a, E: Curve> {
            sid: ExecutionId<'a>,
            msg: &'a MsgRound1a<E>,
        }

        let h_i = udigest::hash_iter::<D>(
            round1a_msgs
                .iter_including_me(my_round1a)
                .map(|msg| Echo { sid: self.state.sid, msg }),
        );

        let reliability_check = MsgReliabilityCheck(h_i);
        self.state.my_reliability_check = Some(reliability_check.clone());

        Ok(reliability_check)
    }

    /// Generate round 1b messages for each peer
    pub fn round1b_generate_messages(&mut self) -> Result<Vec<(u16, MsgRound1b<E>)>, SigningError> {
        let round1a_msgs = self
            .state
            .round1a_msgs
            .as_ref()
            .ok_or_else(|| SigningError(SigningErrorReason::Bug("Round 1a messages not set".to_string())))?;

        let k_i = self.state.k_i.as_ref().unwrap();
        let gamma_i = self.state.gamma_i.as_ref().unwrap();
        let rho_i = self.state.rho_i.as_ref().unwrap();
        let nu_i = self.state.nu_i.as_ref().unwrap();
        let a_i = self.state.a_i.as_ref().unwrap();
        let b_i = self.state.b_i.as_ref().unwrap();
        let Y_i = self.state.Y_i.as_ref().unwrap();
        let A_i1 = self.state.A_i1.as_ref().unwrap();
        let A_i2 = self.state.A_i2.as_ref().unwrap();
        let B_i1 = self.state.B_i1.as_ref().unwrap();
        let B_i2 = self.state.B_i2.as_ref().unwrap();
        let K_i = self.state.K_i.as_ref().unwrap();
        let G_i = self.state.G_i.as_ref().unwrap();

        let security_params = crate::utils::SecurityParams::new::<L>();
        let dec_i = &self.key_share.aux.dec;

        let mut messages = Vec::new();

        for (j, _, round1a_msg) in round1a_msgs.iter_indexed() {
            let R_j = &self.R[usize::from(j)];

            // Prove π_enc_el_gamal_batch
            #[derive(udigest::Digestable)]
            #[udigest(tag = "dfns.cggmp21.signing.proof_enc")]
            struct ProofEnc<'a> {
                sid: ExecutionId<'a>,
                prover: u16,
            }

            let psi_enc_ji = pi_enc_el_gamal_batch::non_interactive::prove::<E, D>(
                &ProofEnc { sid: self.state.sid, prover: self.state.i },
                &R_j.into(),
                pi_enc_el_gamal_batch::PublicData {
                    key: dec_i,
                    a: &Y_i,
                    batch: &Vec::from([
                        pi_enc_el_gamal_batch::PublicElement {
                            ciphertext: K_i.clone(),
                            b: *A_i1,
                            x: *A_i2,
                        },
                        pi_enc_el_gamal_batch::PublicElement {
                            ciphertext: G_i.clone(),
                            b: *B_i1,
                            x: *B_i2,
                        },
                    ]),
                },
                pi_enc_el_gamal_batch::PrivateData {
                    batch: &Vec::from([
                        pi_enc_el_gamal_batch::PrivateElement {
                            plaintext: &utils::scalar_to_bignumber(k_i),
                            nonce: rho_i,
                            b: a_i,
                        },
                        pi_enc_el_gamal_batch::PrivateElement {
                            plaintext: &utils::scalar_to_bignumber(gamma_i),
                            nonce: nu_i,
                            b: b_i,
                        },
                    ]),
                },
                &security_params.pi_enc_el_gamal_batch,
                &mut self.rng,
                2,
            )
            .map_err(|e| SigningError(SigningErrorReason::Bug(format!("Failed to prove psi_enc_ji: {:?}", e))))?;

            let msg = MsgRound1b { psi_enc_ji };
            messages.push((j, msg));
        }

        Ok(messages)
    }

    /// Set round 1b messages from other parties
    pub fn set_round1b_messages(
        &mut self,
        messages: Vec<MsgRound1b<E>>,
        ids: Vec<u64>,
    ) -> Result<(), SigningError> {
        let round_msgs = RoundMsgs::new(self.state.i, ids, messages);
        self.state.round1b_msgs = Some(round_msgs);
        Ok(())
    }

    /// Validate round 1b proofs
    pub fn validate_round1b_proofs(&mut self) -> Result<(), SigningError> {
        let round1a_msgs = self.state.round1a_msgs.as_ref().unwrap();
        let round1b_msgs = self.state.round1b_msgs.as_ref().unwrap();
        let security_params = crate::utils::SecurityParams::new::<L>();

        for ((j, _, round1a_msg), (_, _, round1b_msg)) in
            round1a_msgs.iter_indexed().zip(round1b_msgs.iter_indexed())
        {
            let R_j = &self.R[usize::from(j)];
            let R_i = &self.R[usize::from(self.state.i)];

            #[derive(udigest::Digestable)]
            #[udigest(tag = "dfns.cggmp21.signing.proof_enc")]
            struct ProofEnc<'a> {
                sid: ExecutionId<'a>,
                prover: u16,
            }

            pi_enc_el_gamal_batch::non_interactive::verify::<E, D>(
                &ProofEnc { sid: self.state.sid, prover: j },
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
                },
                &round1b_msg.psi_enc_ji.0,
                &round1b_msg.psi_enc_ji.1,
                &security_params.pi_enc_el_gamal_batch,
                2,
            )
            .map_err(|e| SigningError(SigningErrorReason::Aborted(format!("Invalid enc-elg proof from party {}: {:?}", j, e))))?;
        }

        Ok(())
    }

    /// Generate round 2 messages
    pub fn round2_generate_messages(&mut self) -> Result<Vec<(u16, MsgRound2<E>)>, SigningError> {
        let round1a_msgs = self.state.round1a_msgs.as_ref().unwrap();
        let gamma_i = self.state.gamma_i.as_ref().unwrap();
        let b_i = self.state.b_i.as_ref().unwrap();
        let Y_i = self.state.Y_i.as_ref().unwrap();
        let B_i1 = self.state.B_i1.as_ref().unwrap();
        let B_i2 = self.state.B_i2.as_ref().unwrap();

        // Gamma_i = G * gamma_i
        let Gamma_i = Point::generator() * gamma_i;
        self.state.Gamma_i = Some(Gamma_i);

        // Generate π_elog proof
        #[derive(udigest::Digestable)]
        #[udigest(tag = "dfns.cggmp21.signing.proof_log")]
        struct ProofLog<'a> {
            sid: ExecutionId<'a>,
            prover: u16,
            prime_prime: bool,
        }

        let psi_i = pi_elog::non_interactive::prove::<E, D>(
            &ProofLog {
                sid: self.state.sid,
                prover: self.state.i,
                prime_prime: false,
            },
            pi_elog::Data {
                l: B_i1,
                m: B_i2,
                x: Y_i,
                y: &Gamma_i,
                h: &Point::<E>::generator().to_point(),
            },
            pi_elog::PrivateData {
                y: gamma_i,
                lambda: b_i,
            },
            &mut self.rng,
        )
        .map_err(|e| SigningError(SigningErrorReason::Bug(format!("Failed to prove psi_i: {:?}", e))))?;

        let security_params = crate::utils::SecurityParams::new::<L>();
        let J = BigInt::from(1) << L::ELL_PRIME;
        
        let mut beta_sum = Scalar::zero();
        let mut hat_beta_sum = Scalar::zero();
        let mut messages = Vec::new();

        // Create precompute table for dec_i (used for encryption)
        let dec_i = &self.key_share.aux.dec;
        let dec_i_ek = dec_i.encryption_key();
        let precompute_dec_i = if let Some(ref cached_tables) = self.cached_precompute_tables {
            if let Some(cached_table) = cached_tables.get(usize::from(self.state.i)) {
                cached_table.clone()
            } else {
                precomputed_table::PrecomputeTable::new_dp(
                    dec_i_ek.h_pow_n().clone(),
                    10,
                    dec_i_ek.a_size() as usize,
                    dec_i_ek.nn().clone(),
                )
            }
        } else {
            precomputed_table::PrecomputeTable::new_dp(
                dec_i_ek.h_pow_n().clone(),
                10,
                dec_i_ek.a_size() as usize,
                dec_i_ek.nn().clone(),
            )
        };
        
        // Create precompute tables for all enc_j upfront
        let mut precompute_tables_j = std::collections::HashMap::new();
        for (j, _, _) in round1a_msgs.iter_indexed() {
            let R_j = &self.R[usize::from(j)];
            let enc_j = &R_j.enc;
            
            // Use cached precompute table if available, otherwise create a new one
            let precompute_enc_j = if let Some(ref cached_tables) = self.cached_precompute_tables {
                if let Some(cached_table) = cached_tables.get(usize::from(j)) {
                    cached_table.clone()
                } else {
                    precomputed_table::PrecomputeTable::new_dp(
                        enc_j.h_pow_n().clone(),
                        5,
                        enc_j.a_size() as usize,
                        enc_j.nn().clone(),
                    )
                }
            } else {
                precomputed_table::PrecomputeTable::new_dp(
                    enc_j.h_pow_n().clone(),
                    5,
                    enc_j.a_size() as usize,
                    enc_j.nn().clone(),
                )
            };
            
            precompute_tables_j.insert(j, precompute_enc_j);
        }

        for (j, _, round1a_msg) in round1a_msgs.iter_indexed() {
            let R_j = &self.R[usize::from(j)];
            let R_i = &self.R[usize::from(self.state.i)];
            let enc_j = &R_j.enc.clone();
            let N_i = &R_i.N;

            // Generate random values
            let r_ij = self.rng.gen_bigint_range(&BigInt::from(0), N_i);
            let hat_r_ij = self.rng.gen_bigint_range(&BigInt::from(0), N_i);
            let s_ij = self.rng.gen_bigint_range(&BigInt::from(0), N_i);
            let hat_s_ij = self.rng.gen_bigint_range(&BigInt::from(0), N_i);

            let beta_ij = BigInt::from_rng_pm(&J, &mut self.rng);
            let hat_beta_ij = BigInt::from_rng_pm(&J, &mut self.rng);

            beta_sum += beta_ij.to_scalar();
            hat_beta_sum += hat_beta_ij.to_scalar();

            // Get precompute tables for this specific party j
            let precompute_enc_j = precompute_tables_j.get(&j).unwrap();
            
            // Compute D_ji, F_ji, hat_D_ji, hat_F_ji using precompute tables
            let D_ji = {
                let gamma_i_times_K_j = enc_j
                    .omul(&utils::scalar_to_bignumber(gamma_i), &round1a_msg.K_i)
                    .map_err(|e| SigningError(SigningErrorReason::Bug(format!("Failed to compute gamma_i * K_j: {:?}", e))))?;
                let neg_beta_ij_enc = enc_j
                    .encrypt_with_precompute_table(&mut self.rng, precompute_enc_j, &(-&beta_ij), Some(&s_ij))
                    .map_err(|e| SigningError(SigningErrorReason::Bug(format!("Failed to encrypt -beta_ij: {:?}", e))))?;
                enc_j
                    .oadd(&gamma_i_times_K_j, &neg_beta_ij_enc)
                    .map_err(|e| SigningError(SigningErrorReason::Bug(format!("Failed to compute D_ji: {:?}", e))))?
            };

            let F_ji = dec_i.encryption_key()
                .encrypt_with_precompute_table(&mut self.rng, &precompute_dec_i, &(-&beta_ij), Some(&r_ij))
                .map_err(|e| SigningError(SigningErrorReason::Bug(format!("Failed to encrypt F_ji: {:?}", e))))?;

            let hat_D_ji = {
                let x_i_times_K_j = enc_j
                    .omul(&utils::scalar_to_bignumber(&self.x_i), &round1a_msg.K_i)
                    .map_err(|e| SigningError(SigningErrorReason::Bug(format!("Failed to compute x_i * K_j: {:?}", e))))?;
                let neg_hat_beta_ij_enc = enc_j
                    .encrypt_with_precompute_table(&mut self.rng, precompute_enc_j, &(-&hat_beta_ij), Some(&hat_s_ij))
                    .map_err(|e| SigningError(SigningErrorReason::Bug(format!("Failed to encrypt -hat_beta_ij: {:?}", e))))?;
                enc_j
                    .oadd(&x_i_times_K_j, &neg_hat_beta_ij_enc)
                    .map_err(|e| SigningError(SigningErrorReason::Bug(format!("Failed to compute hat_D_ji: {:?}", e))))?
            };

            let hat_F_ji = dec_i.encryption_key()
                .encrypt_with_precompute_table(&mut self.rng, &precompute_dec_i, &(-&hat_beta_ij), Some(&hat_r_ij))
                .map_err(|e| SigningError(SigningErrorReason::Bug(format!("Failed to encrypt hat_F_ji: {:?}", e))))?;

            // Generate π_aff_batch proof
            #[derive(udigest::Digestable)]
            #[udigest(tag = "dfns.cggmp21.signing.proof_psi")]
            struct ProofPsi<'a> {
                sid: ExecutionId<'a>,
                prover: u16,
                hat: bool,
            }

            let psi_aff_ji = pi_aff_batch::non_interactive::prove::<E, D>(
                &ProofPsi {
                    sid: self.state.sid,
                    prover: self.state.i,
                    hat: false,
                },
                &R_j.into(),
                pi_aff_batch::PublicData {
                    key0: enc_j,
                    key1: dec_i,
                    batch: vec![
                        pi_aff_batch::PublicElement {
                            c: round1a_msg.K_i.clone(),
                            d: D_ji.clone(),
                            y: F_ji.clone(),
                            x: Gamma_i.clone(),
                        },
                        pi_aff_batch::PublicElement {
                            c: round1a_msg.K_i.clone(),
                            d: hat_D_ji.clone(),
                            y: hat_F_ji.clone(),
                            x: *(Point::generator() * &self.x_i),
                        },
                    ],
                },
                pi_aff_batch::PrivateData {
                    batch: vec![
                        pi_aff_batch::PrivateElement {
                            x: &utils::scalar_to_bignumber(gamma_i),
                            y: &(-&beta_ij),
                            nonce: &s_ij,
                            nonce_y: &r_ij,
                        },
                        pi_aff_batch::PrivateElement {
                            x: &utils::scalar_to_bignumber(&self.x_i),
                            y: &(-&hat_beta_ij),
                            nonce: &hat_s_ij,
                            nonce_y: &hat_r_ij,
                        },
                    ],
                },
                &security_params.pi_aff_batch,
                &mut self.rng,
                2,
            )
            .map_err(|e| SigningError(SigningErrorReason::Bug(format!("Failed to prove psi_aff_ji: {:?}", e))))?;

            let msg = MsgRound2 {
                Gamma_i,
                psi_i: psi_i.clone(),
                D_ji,
                F_ji,
                hat_D_ji,
                hat_F_ji,
                psi_aff_ji,
            };

            messages.push((j, msg));
        }

        self.state.beta_sum = Some(beta_sum);
        self.state.hat_beta_sum = Some(hat_beta_sum);

        Ok(messages)
    }

    /// Set round 2 messages from other parties
    pub fn set_round2_messages(
        &mut self,
        messages: Vec<MsgRound2<E>>,
        ids: Vec<u64>,
    ) -> Result<(), SigningError> {
        let round_msgs = RoundMsgs::new(self.state.i, ids, messages);
        self.state.round2_msgs = Some(round_msgs);
        Ok(())
    }

    /// Validate round 2 proofs and generate round 3 messages
    pub fn round3_generate_messages(&mut self) -> Result<Vec<(u16, MsgRound3<E>)>, SigningError> {
        let round1a_msgs = self.state.round1a_msgs.as_ref().unwrap();
        let round2_msgs = self.state.round2_msgs.as_ref().unwrap();
        let security_params = crate::utils::SecurityParams::new::<L>();

        // Validate round 2 proofs
        for ((j, _, round1a_msg), (_, _, round2_msg)) in
            round1a_msgs.iter_indexed().zip(round2_msgs.iter_indexed())
        {
            let X_j = self.X[usize::from(j)];
            let R_j = &self.R[usize::from(j)];
            let R_i = &self.R[usize::from(self.state.i)];
            let enc_j = R_j.enc.clone();
            let dec_i = &self.key_share.aux.dec;

            // Validate π_aff_batch proof
            #[derive(udigest::Digestable)]
            #[udigest(tag = "dfns.cggmp21.signing.proof_psi")]
            struct ProofPsi<'a> {
                sid: ExecutionId<'a>,
                prover: u16,
                hat: bool,
            }

            pi_aff_batch::non_interactive::verify::<E, D>(
                &ProofPsi {
                    sid: self.state.sid,
                    prover: j,
                    hat: false,
                },
                &R_i.into(),
                pi_aff_batch::PublicData {
                    key0: dec_i,
                    key1: &enc_j,
                    batch: vec![
                        pi_aff_batch::PublicElement {
                            c: self.state.K_i.as_ref().unwrap().clone(),
                            d: round2_msg.D_ji.clone(),
                            y: round2_msg.F_ji.clone(),
                            x: round2_msg.Gamma_i.clone(),
                        },
                        pi_aff_batch::PublicElement {
                            c: self.state.K_i.as_ref().unwrap().clone(),
                            d: round2_msg.hat_D_ji.clone(),
                            y: round2_msg.hat_F_ji.clone(),
                            x: *X_j.clone(),
                        },
                    ],
                },
                &round2_msg.psi_aff_ji.0,
                &security_params.pi_aff_batch,
                &round2_msg.psi_aff_ji.1,
                2,
            )
            .map_err(|e| SigningError(SigningErrorReason::Aborted(format!("Invalid aff proof from party {}: {:?}", j, e))))?;

            // Validate π_elog proof
            #[derive(udigest::Digestable)]
            #[udigest(tag = "dfns.cggmp21.signing.proof_log")]
            struct ProofLog<'a> {
                sid: ExecutionId<'a>,
                prover: u16,
                prime_prime: bool,
            }

            pi_elog::non_interactive::verify::<E, D>(
                &ProofLog {
                    sid: self.state.sid,
                    prover: j,
                    prime_prime: false,
                },
                pi_elog::Data {
                    l: &round1a_msg.B_i1,
                    m: &round1a_msg.B_i2,
                    x: &round1a_msg.Y_i,
                    y: &round2_msg.Gamma_i,
                    h: &Point::<E>::generator().to_point(),
                },
                &round2_msg.psi_i.0,
                &round2_msg.psi_i.1,
            )
            .map_err(|e| SigningError(SigningErrorReason::Aborted(format!("Invalid elog proof from party {}: {:?}", j, e))))?;
        }

        // Compute Gamma, Delta_i, delta_i, chi_i
        let Gamma_i = self.state.Gamma_i.as_ref().unwrap();
        let Gamma = *Gamma_i + round2_msgs.iter().map(|msg| msg.Gamma_i).sum::<Point<E>>();
        let k_i = self.state.k_i.as_ref().unwrap();
        let Delta_i = Gamma * k_i;

        let dec_i = &self.key_share.aux.dec;

        // Compute alpha_sum and hat_alpha_sum
        let alpha_sum = round2_msgs
            .iter()
            .map(|msg| &msg.D_ji)
            .try_fold(Scalar::<E>::zero(), |sum, D_ij| {
                let alpha_ij = dec_i
                    .decrypt(D_ij)
                    .map_err(|e| SigningError(SigningErrorReason::Bug(format!("Failed to decrypt alpha_ij: {:?}", e))))?;
                Ok::<_, SigningError>(sum + alpha_ij.to_scalar())
            })?;

        let hat_alpha_sum = round2_msgs
            .iter()
            .map(|msg| &msg.hat_D_ji)
            .try_fold(Scalar::zero(), |sum, hat_D_ij| {
                let hat_alpha_ij = dec_i
                    .decrypt(hat_D_ij)
                    .map_err(|e| SigningError(SigningErrorReason::Bug(format!("Failed to decrypt hat_alpha_ij: {:?}", e))))?;
                Ok::<_, SigningError>(sum + hat_alpha_ij.to_scalar())
            })?;

        let gamma_i = self.state.gamma_i.as_ref().unwrap();
        let beta_sum = self.state.beta_sum.as_ref().unwrap();
        let hat_beta_sum = self.state.hat_beta_sum.as_ref().unwrap();

        let delta_i = gamma_i.as_ref() * k_i.as_ref() + alpha_sum + beta_sum;
        let chi_i = &self.x_i * k_i.as_ref() + hat_alpha_sum + hat_beta_sum;
        let S_i = Gamma * chi_i;

        // Store computed values
        self.state.delta_i = Some(delta_i);
        self.state.chi_i = Some(chi_i);
        self.state.S_i = Some(S_i);
        self.state.Delta_i = Some(Delta_i);

        // Generate proofs for round 3
        let a_i = self.state.a_i.as_ref().unwrap();
        let Y_i = self.state.Y_i.as_ref().unwrap();
        let A_i1 = self.state.A_i1.as_ref().unwrap();
        let A_i2 = self.state.A_i2.as_ref().unwrap();

        let mut messages = Vec::new();

        for j in utils::iter_peers(self.state.i, self.state.signing_parties.len() as u16) {
            // Generate π_elog proof for Delta_i
            #[derive(udigest::Digestable)]
            #[udigest(tag = "dfns.cggmp21.signing.proof_log")]
            struct ProofLog<'a> {
                sid: ExecutionId<'a>,
                prover: u16,
                prime_prime: bool,
            }

            let hat_psi_i = pi_elog::non_interactive::prove::<E, D>(
                &ProofLog {
                    sid: self.state.sid,
                    prover: self.state.i,
                    prime_prime: false,
                },
                pi_elog::Data {
                    l: A_i1,
                    m: A_i2,
                    x: Y_i,
                    y: &Delta_i,
                    h: &Gamma,
                },
                pi_elog::PrivateData {
                    y: k_i,
                    lambda: a_i,
                },
                &mut self.rng,
            )
            .map_err(|e| SigningError(SigningErrorReason::Bug(format!("Failed to prove hat_psi_i: {:?}", e))))?;

            let msg = MsgRound3 {
                delta_i,
                S_i,
                Delta_i,
                hat_psi_i,
            };

            messages.push((j, msg));
        }

        Ok(messages)
    }

    /// Set round 3 messages from other parties
    pub fn set_round3_messages(
        &mut self,
        messages: Vec<MsgRound3<E>>,
        ids: Vec<u64>,
    ) -> Result<(), SigningError> {
        let round_msgs = RoundMsgs::new(self.state.i, ids, messages);
        self.state.round3_msgs = Some(round_msgs);
        Ok(())
    }

    /// Generate presignature from round 3 results
    pub fn generate_presignature(&mut self) -> Result<Presignature<E>, SigningError> {
        let round1a_msgs = self.state.round1a_msgs.as_ref().unwrap();
        let round3_msgs = self.state.round3_msgs.as_ref().unwrap();

        // Validate round 3 proofs
        let Gamma = self.state.Gamma_i.as_ref().unwrap() 
            + self.state.round2_msgs.as_ref().unwrap().iter().map(|msg| msg.Gamma_i).sum::<Point<E>>();

        for ((j, _, round1a_msg), (_, _, round3_msg)) in
            round1a_msgs.iter_indexed().zip(round3_msgs.iter_indexed())
        {
            #[derive(udigest::Digestable)]
            #[udigest(tag = "dfns.cggmp21.signing.proof_log")]
            struct ProofLog<'a> {
                sid: ExecutionId<'a>,
                prover: u16,
                prime_prime: bool,
            }

            let data = pi_elog::Data {
                l: &round1a_msg.A_i1,
                m: &round1a_msg.A_i2,
                x: &round1a_msg.Y_i,
                y: &round3_msg.Delta_i,
                h: &Gamma,
            };

            pi_elog::non_interactive::verify::<E, D>(
                &ProofLog {
                    sid: self.state.sid,
                    prover: j,
                    prime_prime: false,
                },
                data,
                &round3_msg.hat_psi_i.0,
                &round3_msg.hat_psi_i.1,
            )
            .map_err(|e| SigningError(SigningErrorReason::Aborted(format!("Invalid hat_psi proof from party {}: {:?}", j, e))))?;
        }

        // Calculate presignature
        let delta_i = self.state.delta_i.as_ref().unwrap();
        let delta = *delta_i + round3_msgs.iter().map(|m| m.delta_i).sum::<Scalar<E>>();
        
        let Delta_i = self.state.Delta_i.as_ref().unwrap();
        let Delta = *Delta_i + round3_msgs.iter().map(|m| m.Delta_i).sum::<Point<E>>();

        if Point::generator() * delta != Delta {
            return Err(SigningError(SigningErrorReason::Aborted("Mismatched delta".to_string())));
        }

        // Check X^delta = S
        let S_i = self.state.S_i.as_ref().unwrap();
        let S = *S_i + round3_msgs.iter().map(|m| m.S_i).sum::<Point<E>>();
        if self.shared_public_key * delta != S {
            return Err(SigningError(SigningErrorReason::Aborted("Mismatched S".to_string())));
        }

        // Generate presignature
        let delta_inv = delta.invert().ok_or_else(|| 
            SigningError(SigningErrorReason::Bug("Zero delta".to_string())))?;
        
        let k_i = self.state.k_i.as_ref().unwrap();
        let chi_i = self.state.chi_i.as_ref().unwrap();
        let hat_k_i = k_i * delta_inv;
        let hat_chi_i = chi_i * delta_inv;
        
        let mut hat_Delta_j = round3_msgs
            .iter()
            .map(|m| m.Delta_i * delta_inv)
            .collect::<Vec<_>>();
        hat_Delta_j.insert(self.state.i as usize, *Delta_i * delta_inv);

        let mut hat_S_j = round3_msgs
            .iter()
            .map(|m| m.S_i * delta_inv)
            .collect::<Vec<_>>();
        hat_S_j.insert(self.state.i as usize, *S_i * delta_inv);

        let presignature = Presignature {
            Gamma: NonZero::from_point(Gamma).ok_or_else(|| 
                SigningError(SigningErrorReason::Bug("Zero Gamma".to_string())))?,
            hat_k_i,
            hat_chi_i,
            hat_Delta_j,
            hat_S_j,
        };

        self.state.presignature = Some(presignature.clone());
        Ok(presignature)
    }

    /// Generate round 4 message (partial signature)
    pub fn round4_generate_message(&mut self) -> Result<Option<MsgRound4<E>>, SigningError> {
        let presignature = self
            .state
            .presignature
            .as_ref()
            .ok_or_else(|| SigningError(SigningErrorReason::Bug("Presignature not generated".to_string())))?;

        // If no message to sign, return None (presignature only)
        let Some(message_to_sign) = self.state.message_to_sign else {
            return Ok(None);
        };

        let partial_signature = presignature
            .clone()
            .issue_partial_signature(message_to_sign)
            .map_err(|e| SigningError(SigningErrorReason::Bug(format!("Failed to issue partial signature: {:?}", e))))?;

        let msg = MsgRound4 {
            sigma_i: partial_signature.sigma_i,
        };

        Ok(Some(msg))
    }

    /// Set round 4 messages from other parties
    pub fn set_round4_messages(
        &mut self,
        messages: Vec<MsgRound4<E>>,
        ids: Vec<u64>,
    ) -> Result<(), SigningError> {
        let round_msgs = RoundMsgs::new(self.state.i, ids, messages);
        self.state.round4_msgs = Some(round_msgs);
        Ok(())
    }

    /// Generate final signature from round 4 results
    pub fn generate_signature(&mut self, my_partial_sig: MsgRound4<E>) -> Result<Signature<E>, SigningError> {
        let round4_msgs = self
            .state
            .round4_msgs
            .as_ref()
            .ok_or_else(|| SigningError(SigningErrorReason::Bug("Round 4 messages not set".to_string())))?;

        let presignature = self
            .state
            .presignature
            .as_ref()
            .ok_or_else(|| SigningError(SigningErrorReason::Bug("Presignature not generated".to_string())))?;

        let message_to_sign = self
            .state
            .message_to_sign
            .ok_or_else(|| SigningError(SigningErrorReason::Bug("No message to sign".to_string())))?;

        // Validate partial signatures
        for (j, _, msg_j) in round4_msgs.iter_indexed() {
            let Gamma = presignature.Gamma;
            let hat_Delta_j = presignature.hat_Delta_j[usize::from(j)];
            let hat_S_j = presignature.hat_S_j[usize::from(j)];
            let sigma_j = msg_j.sigma_i;
            let m = message_to_sign.to_scalar();
            let r = presignature.Gamma.x().to_scalar();
            
            if Gamma * sigma_j != hat_Delta_j * m + hat_S_j * r {
                return Err(SigningError(SigningErrorReason::Aborted(format!("Invalid partial signature from party {}", j))));
            }
        }

        let r = NonZero::from_scalar(presignature.Gamma.x().to_scalar());
        let s = NonZero::from_scalar(
            my_partial_sig.sigma_i + round4_msgs.iter().map(|m| m.sigma_i).sum::<Scalar<E>>(),
        );

        let sig = Option::zip(r, s)
            .map(|(r, s)| Signature { r, s }.normalize_s())
            .ok_or_else(|| SigningError(SigningErrorReason::Bug("Invalid signature components".to_string())))?;

        // Verify signature
        sig.verify(&self.shared_public_key, &message_to_sign)
            .map_err(|_| SigningError(SigningErrorReason::Aborted("Invalid final signature".to_string())))?;

        self.state.signature = Some(sig);
        Ok(sig)
    }

    /// Set cached precompute tables for benchmarking purposes
    pub fn set_cached_precompute_tables(&mut self, tables: Vec<precomputed_table::PrecomputeTable>) {
        self.cached_precompute_tables = Some(tables);
    }

    /// Generate precompute tables for all parties participating in signing
    /// This creates tables for encryption with each party's encryption key
    pub fn generate_precompute_tables(&self) -> Vec<precomputed_table::PrecomputeTable> {
        let mut tables = Vec::new();
        
        for (party_idx, _) in self.state.signing_parties.iter().enumerate() {
            let party_i = self.state.signing_parties[party_idx];
            let R_i = &self.R[usize::from(party_i)];
            let enc_i = &R_i.enc;
            
            // Create precompute table for this party's encryption key
            let table = precomputed_table::PrecomputeTable::new_dp(
                enc_i.h_pow_n().clone(),
                5, // depth for signing operations
                enc_i.a_size() as usize,
                enc_i.nn().clone(),
            );
            
            tables.push(table);
        }
        
        tables
    }

    /// Generate precompute table for a specific party's encryption key
    /// This is useful for WASM where we might want to generate tables on-demand
    pub fn generate_precompute_table_for_party(&self, party_index: u16) -> Result<precomputed_table::PrecomputeTable, SigningError> {
        let party_pos = self.state.signing_parties.iter().position(|&p| p == party_index)
            .ok_or_else(|| SigningError(SigningErrorReason::InvalidArgs(
                format!("Party {} is not in signing parties list", party_index)
            )))?;
        
        let R_party = &self.R[party_pos];
        let enc_party = &R_party.enc;
        
        let table = precomputed_table::PrecomputeTable::new_dp(
            enc_party.h_pow_n().clone(),
            5, // depth for signing operations
            enc_party.a_size() as usize,
            enc_party.nn().clone(),
        );
        
        Ok(table)
    }

    /// Get the current state for debugging/inspection
    pub fn get_state(&self) -> &SigningState<E, L, D> {
        &self.state
    }
} 
