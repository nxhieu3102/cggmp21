use generic_ec::Curve;
use crate::KeyShare;
use digest::Digest;
use paillier_zk::{
    fast_paillier, no_small_factor::non_interactive as π_fac, paillier_blum_modulus as π_mod,
    integer_ext::IntegerExt,
};
use key_share::CoreKeyShare;
use std::marker::PhantomData;

use crate::{
    errors::IoError,
    key_refresh::{
        aux_only::{
            assemble_aux_info, combine_random_bytes, create_message_reliability_check,
            create_message_round_1, create_message_round_3, validate_decommitments,
            validate_proofs_round_3, validate_ring_pedersen_parameters, Msg, MsgReliabilityCheck,
            MsgRound1, MsgRound2, MsgRound3,
        },
        Bug, KeyRefreshError, PregeneratedPaillierKey, ProtocolAborted,
    },
    key_share::{AuxInfo, DirtyAuxInfo, PartyAux},
    security_level::SecurityLevel,
    utils::{self, AbortBlame},
    ExecutionId,
};
use malachite::Integer;
use paillier_zk::fast_paillier::utils::CrtExp;
use rand_core::{CryptoRng, RngCore};
use round_based::rounds_router::simple_store::RoundMsgs;

/// Error during auxiliary generation protocol execution
#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum AuxGenError {
    /// Internal error: {0}
    #[displaydoc("Internal error: {0}")]
    Bug(&'static str),
    /// Abort error: {0}
    #[displaydoc("Abort error: {0}")]
    Abort(ProtocolAborted),
}

impl From<Bug> for AuxGenError {
    fn from(bug: Bug) -> Self {
        Self::Bug(match bug {
            Bug::PowMod => "Power modulo calculation failed",
            Bug::PiPrm(_) => "Ring pedersen proof generation failed",
            Bug::PiMod(_) => "Blum modulus proof generation failed",
            Bug::PiFac(_) => "No small factor proof generation failed",
            Bug::BuildCrt => "CRT construction failed",
            Bug::BuildMultiexpTables(_) => "Multiexp table construction failed",
            Bug::InvalidShareGenerated(_) => "Invalid share generated",
            _ => "Unexpected internal error",
        })
    }
}

impl From<ProtocolAborted> for AuxGenError {
    fn from(abort: ProtocolAborted) -> Self {
        Self::Abort(abort)
    }
}

/// State for the auxiliary generation protocol
pub struct AuxGenState<L: SecurityLevel, D: Digest + Clone + 'static> {
    /// Party index
    pub i: u16,
    /// Total number of parties
    pub n: u16,
    /// Protocol execution ID
    pub sid: ExecutionId<'static>,
    /// Whether to enforce reliable broadcast
    pub reliable_broadcast_enforced: bool,
    /// Whether to compute multiexp tables
    pub compute_multiexp_table: bool,
    /// Whether to compute CRT parameters
    pub compute_crt: bool,
    /// Pregenerated Paillier key
    pub pregenerated: PregeneratedPaillierKey<L>,
    /// CRT parameters
    pub crt: Option<CrtExp>,
    // Round 1 data
    /// My commitment for round 1
    pub my_commitment: Option<MsgRound1<D>>,
    /// My decommitment for round 2
    pub my_decommitment: Option<MsgRound2<L>>,
    /// My reliability check message
    pub my_reliability_check: Option<MsgReliabilityCheck<D>>,
    /// N - RSA modulus
    pub N: Option<Integer>,
    /// phi_N - Euler's totient of N
    pub phi_N: Option<Integer>,
    /// My random bytes
    pub my_rho_bytes: Option<L::Rid>,
    /// Round 1 commitments from other parties
    pub commitments: Option<RoundMsgs<MsgRound1<D>>>,

    // Round 2 data
    /// Round 2 decommitments from other parties
    pub decommitments: Option<RoundMsgs<MsgRound2<L>>>,
    /// Combined random bytes from all parties
    pub combined_rho_bytes: Option<L::Rid>,
    /// Round 3 messages from other parties
    pub round3_msgs: Option<RoundMsgs<MsgRound3>>,

    // Final output
    /// Assembled auxiliary info
    pub aux_info: Option<AuxInfo<L>>,
}

/// Protocol implementation for auxiliary generation
pub struct AuxGenProtocol<R: RngCore + CryptoRng, L: SecurityLevel, D: Digest + Clone + 'static, E: Curve> {
    /// Internal protocol state
    pub state: AuxGenState<L, D>,
    /// Random number generator
    pub rng: R,
    /// Phantom data for curve type
    _curve: PhantomData<E>,
}

/// Error during AuxGenProtocol parameter validation
#[derive(Debug, displaydoc::Display, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum AuxGenParameterError {
    /// Party index must be less than the number of parties
    #[displaydoc("Party index {i} must be less than the number of parties {n}")]
    InvalidPartyIndex {
        /// Party index
        i: u16,
        /// Number of parties
        n: u16,
    },
    /// Number of parties must be at least 2
    #[displaydoc("Number of parties must be at least 2, got {0}")]
    TooFewParties(u16),
}

impl<
        R: RngCore + CryptoRng,
        L: SecurityLevel,
        D: Digest<OutputSize = digest::typenum::U32> + Clone + 'static,
        E: Curve,
    > AuxGenProtocol<R, L, D, E>
{
    /// Validates auxiliary generation parameters
    fn validate_parameters(i: u16, n: u16) -> Result<(), AuxGenParameterError> {
        if i >= n {
            return Err(AuxGenParameterError::InvalidPartyIndex { i, n });
        }
        if n < 2 {
            return Err(AuxGenParameterError::TooFewParties(n));
        }
        Ok(())
    }

    /// Create a new auxiliary generation protocol instance
    pub fn new(
        i: u16,
        n: u16,
        sid: ExecutionId<'static>,
        rng: R,
        pregenerated: PregeneratedPaillierKey<L>,
        reliable_broadcast_enforced: bool,
        compute_multiexp_table: bool,
        compute_crt: bool,
    ) -> Result<Self, AuxGenParameterError> {
        Self::validate_parameters(i, n)?;

        Ok(Self {
            state: AuxGenState {
                i,
                n,
                sid,
                reliable_broadcast_enforced,
                compute_multiexp_table,
                compute_crt,
                pregenerated,
                my_commitment: None,
                my_decommitment: None,
                my_reliability_check: None,
                N: None,
                phi_N: None,
                my_rho_bytes: None,
                commitments: None,
                decommitments: None,
                combined_rho_bytes: None,
                round3_msgs: None,
                aux_info: None,
                crt: None,
            },
            rng,
            _curve: PhantomData,
        })
    }

    /// Generates a commitment for round 1 of the auxiliary generation protocol
    pub fn round1_generate_commitment(&mut self) -> Result<MsgRound1<D>, AuxGenError> {
        let (commitment, decommitment, N, phi_N, _hat_psi, rho_bytes) = create_message_round_1(
            &mut self.rng,
            self.state.sid,
            self.state.i,
            &self.state.pregenerated,
        )?;

        // Store state
        self.state.my_commitment = Some(commitment.clone());
        self.state.my_decommitment = Some(decommitment);
        self.state.N = Some(N);
        self.state.phi_N = Some(phi_N);
        self.state.my_rho_bytes = Some(rho_bytes);

        Ok(commitment)
    }

    /// Sets the round 1 commitments from other parties
    pub fn set_round1_commitments(
        &mut self,
        commitments: Vec<MsgRound1<D>>,
        ids: Vec<u64>,
    ) -> Result<(), AuxGenError> {
        let round_msgs = RoundMsgs::new(self.state.i, ids, commitments);
        self.state.commitments = Some(round_msgs);
        Ok(())
    }

    /// Creates a reliability check message for round 1
    pub fn create_reliability_check(&mut self) -> Result<MsgReliabilityCheck<D>, AuxGenError> {
        let commitments = self
            .state
            .commitments
            .as_ref()
            .ok_or_else(|| AuxGenError::Bug("Round 1 commitments not set"))?;

        let my_commitment = self
            .state
            .my_commitment
            .as_ref()
            .ok_or_else(|| AuxGenError::Bug("My commitment not generated"))?;

        let reliability_check =
            create_message_reliability_check(commitments, my_commitment, self.state.sid);

        self.state.my_reliability_check = Some(reliability_check.clone());

        Ok(reliability_check)
    }

    /// Gets the decommitment for round 2
    pub fn round2_get_decommitment(&self) -> Result<MsgRound2<L>, AuxGenError> {
        self.state
            .my_decommitment
            .clone()
            .ok_or_else(|| AuxGenError::Bug("Round 2 decommitment not generated"))
    }

    /// Sets the round 2 decommitments from other parties
    pub fn set_round2_decommitments(
        &mut self,
        decommitments: Vec<MsgRound2<L>>,
        ids: Vec<u64>,
    ) -> Result<(), AuxGenError> {
        let round_msgs = RoundMsgs::new(self.state.i, ids, decommitments);
        self.state.decommitments = Some(round_msgs);
        Ok(())
    }

    /// Validates round 2 decommitments
    pub fn validate_round2_decommitments(&mut self) -> Result<(), AuxGenError> {
        let decommitments = self
            .state
            .decommitments
            .as_ref()
            .ok_or_else(|| AuxGenError::Bug("Round 2 decommitments not set"))?;

        let commitments = self
            .state
            .commitments
            .as_ref()
            .ok_or_else(|| AuxGenError::Bug("Round 1 commitments not set"))?;

        // Validate decommitments
        let blame = validate_decommitments(decommitments, commitments, self.state.sid)
            .map_err(|_| AuxGenError::Bug("Decommitment validation failed"))?;
        if !blame.is_empty() {
            return Err(ProtocolAborted::invalid_decommitment(blame).into());
        }

        // Validate ring pedersen parameters
        let blame = validate_ring_pedersen_parameters::<D, L>(decommitments, self.state.sid)
            .map_err(|_| AuxGenError::Bug("Ring pedersen parameter validation failed"))?;
        if !blame.is_empty() {
            return Err(ProtocolAborted::invalid_ring_pedersen_parameters(blame).into());
        }

        // Compute combined random bytes
        let my_rho_bytes = self
            .state
            .my_rho_bytes
            .as_ref()
            .ok_or_else(|| AuxGenError::Bug("My random bytes not generated"))?;

        let my_decommitment = self
            .state
            .my_decommitment
            .as_ref()
            .ok_or_else(|| AuxGenError::Bug("My decommitment not generated"))?;

        let combined_rho_bytes = combine_random_bytes(decommitments, my_rho_bytes, my_decommitment);

        self.state.combined_rho_bytes = Some(combined_rho_bytes);

        Ok(())
    }

    /// Creates messages for round 3
    pub fn round3_create_messages(&mut self) -> Result<Vec<(u16, MsgRound3)>, AuxGenError> {
        let p = self.state.pregenerated.dec.p();
        let q = self.state.pregenerated.dec.q();

        let N = self
            .state
            .N
            .as_ref()
            .ok_or_else(|| AuxGenError::Bug("N not generated"))?;

        let rho_bytes = self
            .state
            .combined_rho_bytes
            .as_ref()
            .ok_or_else(|| AuxGenError::Bug("Combined random bytes not computed"))?;

        let decommitments = self
            .state
            .decommitments
            .as_ref()
            .ok_or_else(|| AuxGenError::Bug("Round 2 decommitments not set"))?;

        create_message_round_3::<R, D, L>(
            &mut self.rng,
            self.state.sid,
            self.state.i,
            &p,
            &q,
            N,
            rho_bytes,
            decommitments,
        )
        .map_err(Into::into)
    }

    /// Sets the round 3 messages from other parties
    pub fn set_round3_messages(
        &mut self,
        messages: Vec<MsgRound3>,
        ids: Vec<u64>,
    ) -> Result<(), AuxGenError> {
        let round_msgs = RoundMsgs::new(self.state.i, ids, messages);
        self.state.round3_msgs = Some(round_msgs);
        Ok(())
    }

    /// Validates round 3 proofs and generates the final output
    pub fn validate_proofs_round_3(&mut self) -> Result<(), AuxGenError> {
        let decommitments = self
            .state
            .decommitments
            .as_ref()
            .ok_or_else(|| AuxGenError::Bug("Round 2 decommitments not set"))?;

        let round3_msgs = self
            .state
            .round3_msgs
            .as_ref()
            .ok_or_else(|| AuxGenError::Bug("Round 3 messages not set"))?;

        let rho_bytes = self
            .state
            .combined_rho_bytes
            .as_ref()
            .ok_or_else(|| AuxGenError::Bug("Combined random bytes not computed"))?;

        let my_decommitment = self
            .state
            .my_decommitment
            .as_ref()
            .ok_or_else(|| AuxGenError::Bug("My decommitment not generated"))?;

        // Prepare common data for verification
        let s = &my_decommitment.s;
        let t = &my_decommitment.t;
        let N = self
            .state
            .N
            .as_ref()
            .ok_or_else(|| AuxGenError::Bug("N not generated"))?;

        // Create CRT if requested
        let crt = if self.state.compute_crt {
            let p = self.state.pregenerated.dec.p();
            let q = self.state.pregenerated.dec.q();
            paillier_zk::fast_paillier::utils::CrtExp::build_n(&p, &q)
        } else {
            None
        };

        self.state.crt = crt.clone();

        let phi_common_aux = π_fac::Aux {
            s: s.clone(),
            t: t.clone(),
            rsa_modulo: N.clone(),
            multiexp: None,
            crt: crt.clone(),
        };

        validate_proofs_round_3::<D, L>(
            decommitments,
            round3_msgs,
            rho_bytes,
            self.state.sid,
            &phi_common_aux,
        )
        .map_err(|_| AuxGenError::Bug("Round 3 proof validation failed"))?;

        Ok(())
    }

    /// Creates the auxiliary info
    pub fn create_aux_info(&self) -> Result<AuxInfo<L>, AuxGenError> {
        let decommitments = self
            .state
            .decommitments
            .as_ref()
            .ok_or_else(|| AuxGenError::Bug("Round 2 decommitments not set"))?;
        let my_decommitment = self
            .state
            .my_decommitment
            .as_ref()
            .ok_or_else(|| AuxGenError::Bug("My decommitment not generated"))?;

        let aux = assemble_aux_info::<L>(
            decommitments,
            my_decommitment,
            self.state.i,
            self.state.pregenerated.dec.clone(),
            self.state.crt.clone(),
            self.state.compute_multiexp_table,
        )
        .map_err(|_| AuxGenError::Bug("Auxiliary info assembly failed"))?;

        Ok(aux)
    }

    /// Creates a key share from the core share and auxiliary info
    pub fn create_key_share(&self, core_share: CoreKeyShare<E>) -> Result<KeyShare<E, L>, AuxGenError> {
        let aux = self.create_aux_info()?;
        let key_share = KeyShare::from_parts((core_share, aux))
            .map_err(|_| AuxGenError::Bug("Key share assembly failed"))?;
        Ok(key_share)
    }
}


