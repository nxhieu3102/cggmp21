use super::{Bug, KeygenAborted, KeygenError};
use crate::threshold::{create_key_share, create_message_round_3};
use crate::{
    key_share::CoreKeyShare,
    security_level::SecurityLevel,
    threshold::{Msg, MsgReliabilityCheck, MsgRound1, MsgRound2Broad, MsgRound2Uni, MsgRound3},
    utils, ExecutionId,
};
use alloc::vec::Vec;
use digest::Digest;
use generic_ec::{Curve, NonZero, Point, Scalar, SecretScalar};
use generic_ec_zkp::{polynomial::Polynomial, schnorr_pok};
use rand_core::{CryptoRng, RngCore};
use round_based::rounds_router::simple_store::RoundMsgs;
use round_based::Outgoing;
use udigest;

/// Error during key generation protocol execution
#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum ThresholdKeygenError {
    /// Internal error: {0}
    #[displaydoc("Internal error: {0}")]
    KeyShareError(KeygenError),
    /// Internal error: {0}
    #[displaydoc("Internal error: {0}")]
    Round3Error(&'static str),
    /// Internal error: {0}
    #[displaydoc("Internal error: {0}")]
    Round2BroadError(&'static str),
    /// Internal error: {0}
    #[displaydoc("Internal error: {0}")]
    Round2UniError(&'static str),
}

/// Holds the state of the threshold key generation protocol
pub struct KeygenState<E: Curve, L: SecurityLevel, D: Digest + Clone + 'static> {
    // Party information
    /// Party index
    pub i: u16,
    /// Threshold - minimum number of parties required to sign
    pub t: u16,
    /// Total number of parties
    pub n: u16,
    /// Protocol execution ID
    pub sid: ExecutionId<'static>,
    /// Whether to enforce reliable broadcast
    pub reliable_broadcast_enforced: bool,
    /// Whether HD wallet is enabled
    #[cfg(feature = "hd-wallet")]
    pub hd_enabled: bool,

    // Round 1 data
    /// Schnorr ephemeral secret
    pub schnorr_secret_r: Option<schnorr_pok::ProverSecret<E>>,
    /// Polynomial for secret sharing
    pub polynomial_f: Option<Polynomial<SecretScalar<E>>>,
    /// Polynomial evaluations (shares to be distributed)
    pub f_i_evaluations_sigmas_ij: Option<Vec<Scalar<E>>>,
    /// My commitment for round 1
    pub my_commitment: Option<MsgRound1<D>>,

    // Round 2 data
    /// My decommitment for round 2
    pub my_decommitment_msg_round2broad: Option<MsgRound2Broad<E, L>>,
    /// Commitments received from other parties in round 1
    pub commitments_from_r1_store: Option<RoundMsgs<MsgRound1<D>>>,
    /// My reliability check message (if reliable broadcast is enforced)
    pub my_reliability_check: Option<MsgReliabilityCheck<D>>,

    // Round 3 data
    /// Combined random ID from all parties
    pub combined_rid: Option<L::Rid>,
    /// Combined chain code (if HD wallet is enabled)
    #[cfg(feature = "hd-wallet")]
    pub combined_chain_code: Option<hd_wallet::ChainCode>,
    /// Public shares for all parties
    pub all_public_shares_ys: Option<Vec<NonZero<Point<E>>>>,
    /// My secret share
    pub my_secret_share_sigma_i: Option<NonZero<SecretScalar<E>>>,
    /// My Schnorr proof for round 3
    pub my_schnorr_proof: Option<MsgRound3<E>>,

    // Final output
    /// Decommitments received from other parties
    pub decommitments_from_r2: Option<RoundMsgs<MsgRound2Broad<E, L>>>,
    /// Sigma shares received from other parties
    pub sigmas_from_r2: Option<RoundMsgs<MsgRound2Uni<E>>>,
    /// Schnorr proofs received from other parties
    pub schnorr_proofs_from_r3: Option<RoundMsgs<MsgRound3<E>>>,
}

/// Error during KeygenProtocol parameter validation
#[derive(Debug, displaydoc::Display, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum KeygenParameterError {
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
    /// Threshold must be at least 1
    #[displaydoc("Threshold must be at least 1, got {0}")]
    ThresholdTooSmall(u16),
    /// Threshold must not exceed the number of parties
    #[displaydoc("Threshold {t} must not exceed the number of parties {n}")]
    ThresholdTooLarge {
        /// Threshold
        t: u16,
        /// Number of parties
        n: u16,
    },
}

/// Protocol implementation for threshold key generation
pub struct KeygenProtocol<
    E: Curve,
    R: RngCore + CryptoRng,
    L: SecurityLevel,
    D: Digest + Clone + 'static,
> {
    /// Internal protocol state
    pub state: KeygenState<E, L, D>,
    /// Random number generator
    pub rng: R,
}

impl<E: Curve, R: RngCore + CryptoRng, L: SecurityLevel, D: Digest + Clone + 'static>
    KeygenProtocol<E, R, L, D>
{
    /// Validates key generation parameters
    fn validate_parameters(i: u16, t: u16, n: u16) -> Result<(), KeygenParameterError> {
        if i >= n {
            return Err(KeygenParameterError::InvalidPartyIndex { i, n });
        }
        if n < 2 {
            return Err(KeygenParameterError::TooFewParties(n));
        }
        if t < 1 {
            return Err(KeygenParameterError::ThresholdTooSmall(t));
        }
        if t > n {
            return Err(KeygenParameterError::ThresholdTooLarge { t, n });
        }
        Ok(())
    }

    /// Create a new key generation protocol instance
    ///
    /// # Parameters
    /// * `i` - Party index (0-indexed)
    /// * `t` - Threshold (minimum number of parties required to sign)
    /// * `n` - Total number of parties
    /// * `sid` - Protocol execution ID
    /// * `reliable_broadcast_enforced` - Whether to enforce reliable broadcast
    /// * `rng` - Random number generator
    /// * `hd_enabled` - Whether HD wallet is enabled (if feature is enabled)
    ///
    /// # Returns
    /// A new `KeygenProtocol` instance or an error if parameters are invalid.
    pub fn new(
        i: u16,
        t: u16,
        n: u16,
        sid: ExecutionId<'static>,
        reliable_broadcast_enforced: bool,
        rng: R,
        #[cfg(feature = "hd-wallet")] hd_enabled: bool,
    ) -> Result<Self, KeygenParameterError> {
        Self::validate_parameters(i, t, n)?;

        Ok(Self {
            state: KeygenState {
                i,
                t,
                n,
                sid,
                reliable_broadcast_enforced,
                #[cfg(feature = "hd-wallet")]
                hd_enabled,
                schnorr_secret_r: None,
                polynomial_f: None,
                f_i_evaluations_sigmas_ij: None,
                my_commitment: None,
                my_decommitment_msg_round2broad: None,
                commitments_from_r1_store: None,
                my_reliability_check: None,
                combined_rid: None,
                #[cfg(feature = "hd-wallet")]
                combined_chain_code: None,
                all_public_shares_ys: None,
                my_secret_share_sigma_i: None,
                my_schnorr_proof: None,
                decommitments_from_r2: None,
                sigmas_from_r2: None,
                schnorr_proofs_from_r3: None,
            },
            rng,
        })
    }

    /// Generates a commitment for round 1 of the key generation protocol
    ///
    /// This method:
    /// 1. Samples random values for the protocol (rid, Schnorr commitment, polynomial, etc.)
    /// 2. Creates a commitment to these values
    /// 3. Updates the protocol state with the generated values
    /// 4. Returns the commitment message to be broadcast to all parties
    ///
    /// # Returns
    /// A `MsgRound1<D>` containing the commitment to be broadcast to all parties.
    pub fn round1_generate_commitment(&mut self) -> Result<MsgRound1<D>, ThresholdKeygenError>
    where
        D: Clone,
    {
        // Generate random identifier for this party
        let mut rid = L::Rid::default();
        self.rng.fill_bytes(rid.as_mut());

        // Generate Schnorr proof components: r (secret), h (commitment)
        let (r, h) = schnorr_pok::prover_commits_ephemeral_secret::<E, _>(&mut self.rng);

        // Generate a polynomial for Shamir's secret sharing (degree t-1)
        let f = Polynomial::<SecretScalar<E>>::sample(&mut self.rng, usize::from(self.state.t) - 1);

        // Calculate the public polynomial F = f * G
        let F = &f * &Point::generator();

        // Evaluate the polynomial at each party's index to get their secret shares
        let sigmas = (0..self.state.n)
            .map(|j| {
                let x = Scalar::from(j + 1);
                f.value(&x)
            })
            .collect::<Vec<_>>();
        debug_assert_eq!(sigmas.len(), usize::from(self.state.n));

        // Generate chain code if HD wallet is enabled
        #[cfg(feature = "hd-wallet")]
        let chain_code_local = if self.state.hd_enabled {
            let mut chain_code = hd_wallet::ChainCode::default();
            self.rng.fill_bytes(&mut chain_code);
            Some(chain_code)
        } else {
            None
        };

        // Create decommitment for round 2
        let my_decommitment = MsgRound2Broad {
            rid,
            F: F.clone(),
            sch_commit: h,
            #[cfg(feature = "hd-wallet")]
            chain_code: chain_code_local,
            decommit: {
                let mut nonce = L::Rid::default();
                self.rng.fill_bytes(nonce.as_mut());
                nonce
            },
        };

        // Create a HashCom struct to be hashed with unambiguous digest
        #[derive(udigest::Digestable)]
        #[udigest(tag = "dfns.cggmp21.keygen.threshold.hash_commitment")]
        #[udigest(bound = "")]
        struct HashCom<'a, E: Curve, L: SecurityLevel> {
            sid: ExecutionId<'a>,
            party_index: u16,
            decommitment: &'a MsgRound2Broad<E, L>,
        }

        // Hash the decommitment to create the commitment
        let hash_commit = udigest::hash::<D>(&HashCom {
            sid: self.state.sid,
            party_index: self.state.i,
            decommitment: &my_decommitment,
        });

        // Create the round 1 commitment message
        let my_commitment = MsgRound1 {
            commitment: hash_commit,
        };

        // Store generated values in the protocol state
        self.state.schnorr_secret_r = Some(r);
        self.state.polynomial_f = Some(f);
        self.state.f_i_evaluations_sigmas_ij = Some(sigmas);
        self.state.my_decommitment_msg_round2broad = Some(my_decommitment);
        self.state.my_commitment = Some(my_commitment.clone());

        Ok(my_commitment)
    }

    /// hehe
    pub fn run_round_2_uni(&mut self) -> Result<Vec<Outgoing<Msg<E, L, D>>>, ThresholdKeygenError> {
        let sigmas = self.state.f_i_evaluations_sigmas_ij.as_ref().unwrap();
        let messages_iter = utils::iter_peers(self.state.i, self.state.n).map(move |j| {
            let message = MsgRound2Uni {
                sigma: sigmas[usize::from(j)],
            };
            Outgoing::p2p(j, Msg::Round2Uni::<E, L, D>(message))
        });

        let messages: Vec<_> = messages_iter.collect();
        Ok(messages)
    }

    /// hehe
    pub fn run_round_2_broad(&mut self) -> Result<MsgRound2Broad<E, L>, ThresholdKeygenError> {
        let message = self.state.my_decommitment_msg_round2broad.as_ref().unwrap();
        Ok(message.clone())
    }

    /// hehe
    pub fn set_commitments_from_r1_store(
        &mut self,
        commitments: Vec<MsgRound1<D>>,
        ids: Vec<u64>,
    ) -> Result<(), ThresholdKeygenError> {
        let roundMsgs = RoundMsgs::new(self.state.i, ids, commitments);
        self.state.commitments_from_r1_store = Some(roundMsgs);
        Ok(())
    }

    /// hehe
    pub fn set_decommitments_from_r2_store(
        &mut self,
        decommitments: Vec<MsgRound2Broad<E, L>>,
        ids: Vec<u64>,
    ) -> Result<(), ThresholdKeygenError> {
        let roundMsgs = RoundMsgs::new(self.state.i, ids, decommitments);
        self.state.decommitments_from_r2 = Some(roundMsgs);
        Ok(())
    }

    /// hehe
    pub fn set_sigmas_from_r2_store(
        &mut self,
        sigmas: Vec<MsgRound2Uni<E>>,
        ids: Vec<u64>,
    ) -> Result<(), ThresholdKeygenError> {
        let roundMsgs = RoundMsgs::new(self.state.i, ids, sigmas);
        self.state.sigmas_from_r2 = Some(roundMsgs);
        Ok(())
    }

    /// hehe
    pub fn run_round_3(&mut self) -> Result<MsgRound3<E>, ThresholdKeygenError> {
        let commitments = self
            .state
            .commitments_from_r1_store
            .as_ref()
            .expect("Commitments from round 1 must exist");
        let decommitments = self
            .state
            .decommitments_from_r2
            .as_ref()
            .expect("Decommitments from round 2 must exist");
        let sigmas_msg = self
            .state
            .sigmas_from_r2
            .as_ref()
            .expect("Sigmas from round 2 must exist");
        let sid = self.state.sid;
        let my_decommitment = self.state.my_decommitment_msg_round2broad.as_ref().unwrap();
        let n = self.state.n;
        let t = self.state.t;
        let i = self.state.i;
        let r = self.state.schnorr_secret_r.as_ref().unwrap();
        let sigmas = self.state.f_i_evaluations_sigmas_ij.as_ref().unwrap();

        let msg = create_message_round_3(
            commitments,
            decommitments,
            sigmas_msg,
            &sid,
            my_decommitment,
            n,
            t,
            i,
            r,
            sigmas,
        );

        match msg {
            Ok(msgg) => {
                self.state.my_schnorr_proof = Some(msgg.clone());
                Ok(msgg)
            }
            Err(e) => Err(ThresholdKeygenError::Round3Error(
                "Failed to create message for round 3",
            )),
        }
    }

    /// hehe
    pub fn set_commitments_from_r3_store(
        &mut self,
        schnorrs: Vec<MsgRound3<E>>,
        ids: Vec<u64>,
    ) -> Result<(), ThresholdKeygenError> {
        let roundMsgs = RoundMsgs::new(self.state.i, ids, schnorrs);
        self.state.schnorr_proofs_from_r3 = Some(roundMsgs);
        Ok(())
    }

    /// hehe
    pub fn run_round_key_share(&mut self) -> Result<CoreKeyShare<E>, ThresholdKeygenError> {
        let sch_proofs = self
            .state
            .schnorr_proofs_from_r3
            .as_ref()
            .expect("Schnorr proofs from round 3 must exist");
        let decommitments = self
            .state
            .decommitments_from_r2
            .as_ref()
            .expect("Decommitments from round 2 must exist");
        let my_decommitment = self.state.my_decommitment_msg_round2broad.as_ref().unwrap();
        let sid = self.state.sid;

        self.state.combined_rid = {
            let d = decommitments
                .iter_including_me(&my_decommitment)
                .map(|d| &d.rid)
                .fold(L::Rid::default(), utils::xor_array);

            Some(d)
        };

        let rid = self.state.combined_rid.as_ref().unwrap();
        let i = self.state.i;
        let n = self.state.n;
        let t = self.state.t;
        let sigmas_msg = self.state.sigmas_from_r2.as_ref().unwrap();
        let sigmas = self.state.f_i_evaluations_sigmas_ij.as_ref().unwrap();
        let sigma: Scalar<E> = sigmas_msg.iter().map(|msg| msg.sigma).sum();
        let mut sigma = sigma + sigmas[usize::from(i)];
        let sigma = NonZero::from_secret_scalar(SecretScalar::new(&mut sigma))
            .ok_or(Bug::ZeroShare)
            .map_err(|_| ThresholdKeygenError::Round3Error("Zero share"))?;

        let msg = create_key_share::<E, L, D>(
            sch_proofs,
            decommitments,
            &sid,
            &rid,
            my_decommitment,
            i,
            n,
            t,
            &sigma,
        );

        match msg {
            Ok(msg) => Ok(msg),
            Err(e) => Err(ThresholdKeygenError::KeyShareError(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security_level::SecurityLevel128;
    use generic_ec::curves::Secp256k1;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use sha2::Sha256;

    #[test]
    fn test_keygen_protocol_new_valid_parameters() {
        let i = 0;
        let t = 2;
        let n = 3;
        let _sid = ExecutionId::new(b"test_session");
        let sid_static = ExecutionId::new_static(b"test_session");
        let rng = ChaCha20Rng::seed_from_u64(0);

        let protocol = KeygenProtocol::<Secp256k1, ChaCha20Rng, SecurityLevel128, Sha256>::new(
            i,
            t,
            n,
            sid_static,
            true,
            rng,
            #[cfg(feature = "hd-wallet")]
            true,
        );

        assert!(protocol.is_ok());
        let protocol = protocol.unwrap();
        assert_eq!(protocol.state.i, i);
        assert_eq!(protocol.state.t, t);
        assert_eq!(protocol.state.n, n);
        assert_eq!(protocol.state.reliable_broadcast_enforced, true);
        #[cfg(feature = "hd-wallet")]
        assert_eq!(protocol.state.hd_enabled, true);
    }

    #[test]
    fn test_keygen_protocol_new_invalid_party_index() {
        let i = 3; // Invalid: i >= n
        let t = 2;
        let n = 3;
        let sid_static = ExecutionId::new_static(b"test_session");
        let rng = ChaCha20Rng::seed_from_u64(0);

        let result = KeygenProtocol::<Secp256k1, ChaCha20Rng, SecurityLevel128, Sha256>::new(
            i,
            t,
            n,
            sid_static,
            true,
            rng,
            #[cfg(feature = "hd-wallet")]
            true,
        );

        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap(),
            KeygenParameterError::InvalidPartyIndex { i, n }
        );
    }

    #[test]
    fn test_keygen_protocol_new_threshold_too_large() {
        let i = 0;
        let t = 4; // Invalid: t > n
        let n = 3;
        let sid_static = ExecutionId::new_static(b"test_session");
        let rng = ChaCha20Rng::seed_from_u64(0);

        let result = KeygenProtocol::<Secp256k1, ChaCha20Rng, SecurityLevel128, Sha256>::new(
            i,
            t,
            n,
            sid_static,
            true,
            rng,
            #[cfg(feature = "hd-wallet")]
            true,
        );

        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap(),
            KeygenParameterError::ThresholdTooLarge { t, n }
        );
    }

    #[test]
    fn test_keygen_protocol_new_threshold_too_small() {
        let i = 0;
        let t = 0; // Invalid: t < 1
        let n = 3;
        let sid_static = ExecutionId::new_static(b"test_session");
        let rng = ChaCha20Rng::seed_from_u64(0);

        let result = KeygenProtocol::<Secp256k1, ChaCha20Rng, SecurityLevel128, Sha256>::new(
            i,
            t,
            n,
            sid_static,
            true,
            rng,
            #[cfg(feature = "hd-wallet")]
            true,
        );

        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap(),
            KeygenParameterError::ThresholdTooSmall(t)
        );
    }

    #[test]
    fn test_keygen_protocol_new_too_few_parties() {
        let i = 0;
        let t = 1;
        let n = 1; // Invalid: n < 2
        let sid_static = ExecutionId::new_static(b"test_session");
        let rng = ChaCha20Rng::seed_from_u64(0);

        let result = KeygenProtocol::<Secp256k1, ChaCha20Rng, SecurityLevel128, Sha256>::new(
            i,
            t,
            n,
            sid_static,
            true,
            rng,
            #[cfg(feature = "hd-wallet")]
            true,
        );

        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap(),
            KeygenParameterError::TooFewParties(n)
        );
    }

    #[test]
    fn test_round1_generate_commitment() {
        let i = 0;
        let t = 2;
        let n = 3;
        let sid_static = ExecutionId::new_static(b"test_session");
        let rng = ChaCha20Rng::seed_from_u64(0);

        let mut protocol = KeygenProtocol::<Secp256k1, ChaCha20Rng, SecurityLevel128, Sha256>::new(
            i,
            t,
            n,
            sid_static,
            true,
            rng,
            #[cfg(feature = "hd-wallet")]
            true,
        )
        .unwrap();

        // Generate round 1 commitment
        let result = protocol.round1_generate_commitment();
        assert!(result.is_ok());

        let commitment = result.unwrap();

        // Verify state was updated
        assert!(protocol.state.schnorr_secret_r.is_some());
        assert!(protocol.state.polynomial_f.is_some());
        assert!(protocol.state.f_i_evaluations_sigmas_ij.is_some());
        assert!(protocol.state.my_decommitment_msg_round2broad.is_some());
        assert!(protocol.state.my_commitment.is_some());

        // Verify the state contains what we expect
        let sigmas = protocol.state.f_i_evaluations_sigmas_ij.as_ref().unwrap();
        assert_eq!(sigmas.len(), n as usize);

        // Verify the commitment matches what's stored in state
        assert_eq!(
            commitment.commitment,
            protocol.state.my_commitment.as_ref().unwrap().commitment
        );
    }
}
