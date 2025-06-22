use super::{Bug, KeygenError};
use crate::{
    key_share::{CoreKeyShare, DirtyCoreKeyShare, DirtyKeyInfo, Validate, VssSetup},
    security_level::SecurityLevel,
    utils, ExecutionId,
};
use alloc::{vec, vec::Vec, string::String, format};
use digest::Digest;
use generic_ec::{Curve, NonZero, Point, Scalar, SecretScalar};
use generic_ec_zkp::{polynomial::Polynomial, schnorr_pok};
use rand_core::{CryptoRng, RngCore};
use round_based::rounds_router::simple_store::RoundMsgs;
use birkhoff::polynomial::Derivative;

// Re-export the message types from the main hierarchical_threshold module
pub use super::hierarchical_threshold::{
    Msg, MsgRound1, MsgRound2Broad, MsgRound2Uni, MsgRound3, MsgReliabilityCheck,
};

/// Error during hierarchical threshold key generation protocol execution
#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum HierarchicalThresholdKeygenError {
    /// Internal error: {0}
    #[displaydoc("Internal error: {0}")]
    KeyShareError(KeygenError),
    /// Internal error: {0}
    #[displaydoc("Internal error: {0}")]
    Bug(&'static str),
    /// Protocol aborted: {0}
    #[displaydoc("Protocol aborted: {0}")]
    Aborted(String),
}

impl From<KeygenError> for HierarchicalThresholdKeygenError {
    fn from(err: KeygenError) -> Self {
        Self::KeyShareError(err)
    }
}

impl From<Bug> for HierarchicalThresholdKeygenError {
    fn from(bug: Bug) -> Self {
        Self::Bug(match bug {
            Bug::ZeroShare => "Zero share generated",
            Bug::ZeroPk => "Zero public key generated", 
            Bug::NonZeroScalar => "Non-zero scalar error",
            Bug::InvalidKeyShare(_) => "Invalid key share generated",
        })
    }
}

/// Holds the state of the hierarchical threshold key generation protocol
pub struct HierarchicalThresholdKeygenState<E: Curve, L: SecurityLevel, D: Digest + Clone + 'static> {
    // Party information
    /// Party index
    pub i: u16,
    /// Threshold - minimum number of parties required to sign
    pub t: u16,
    /// Ranks of all parties (including this party)
    pub ranks: Vec<u16>,
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
    /// Random identifier for this party
    pub rid: Option<L::Rid>,
    /// Schnorr ephemeral secret
    pub schnorr_secret_r: Option<schnorr_pok::ProverSecret<E>>,
    /// Polynomial for secret sharing
    pub polynomial_f: Option<Polynomial<SecretScalar<E>>>,
    /// Public polynomial F = f * G
    pub public_polynomial_F: Option<Polynomial<Point<E>>>,
    /// Polynomial evaluations (shares to be distributed using ranks)
    pub sigma_shares: Option<Vec<Scalar<E>>>,
    /// Chain code contribution (if HD wallet enabled)
    #[cfg(feature = "hd-wallet")]
    pub chain_code_local: Option<hd_wallet::ChainCode>,
    /// My commitment for round 1
    pub my_commitment: Option<MsgRound1<D>>,
    /// My decommitment for round 2
    pub my_decommitment: Option<MsgRound2Broad<E, L>>,

    // Round 2 data
    /// Commitments received from other parties in round 1
    pub commitments_from_r1: Option<RoundMsgs<MsgRound1<D>>>,
    /// My reliability check message (if reliable broadcast is enforced)
    pub my_reliability_check: Option<MsgReliabilityCheck<D>>,

    // Round 3 data
    /// Decommitments received from other parties in round 2
    pub decommitments_from_r2: Option<RoundMsgs<MsgRound2Broad<E, L>>>,
    /// Sigma shares received from other parties in round 2
    pub sigmas_from_r2: Option<RoundMsgs<MsgRound2Uni<E>>>,
    /// Combined random ID from all parties
    pub combined_rid: Option<L::Rid>,
    /// Combined chain code (if HD wallet is enabled)
    #[cfg(feature = "hd-wallet")]
    pub combined_chain_code: Option<hd_wallet::ChainCode>,
    /// Public shares for all parties (computed from polynomial sum)
    pub all_public_shares_ys: Option<Vec<NonZero<Point<E>>>>,
    /// My secret share
    pub my_secret_share_sigma: Option<NonZero<SecretScalar<E>>>,
    /// My Schnorr proof for round 3
    pub my_schnorr_proof: Option<MsgRound3<E>>,

    // Final output
    /// Schnorr proofs received from other parties in round 3
    pub schnorr_proofs_from_r3: Option<RoundMsgs<MsgRound3<E>>>,
    /// Final generated key share
    pub key_share: Option<CoreKeyShare<E>>,
}

/// Error during HierarchicalThresholdKeygenProtocol parameter validation
#[derive(Debug, displaydoc::Display, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum HierarchicalThresholdKeygenParameterError {
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
    /// Ranks vector must have exactly n elements
    #[displaydoc("Ranks vector must have exactly {n} elements, got {len}")]
    InvalidRanksLength {
        /// Expected length
        n: u16,
        /// Actual length
        len: usize,
    },
    /// All ranks must be less than t
    #[displaydoc("All ranks must be less than {t}, found rank {rank}")]
    InvalidRank {
        /// Threshold
        t: u16,
        /// Invalid rank
        rank: u16,
    },
}

/// Protocol implementation for hierarchical threshold key generation
pub struct HierarchicalThresholdKeygenProtocol<
    E: Curve,
    R: RngCore + CryptoRng,
    L: SecurityLevel,
    D: Digest + Clone + 'static,
> {
    /// Internal protocol state
    pub state: HierarchicalThresholdKeygenState<E, L, D>,
    /// Random number generator
    pub rng: R,
}

impl<E: Curve, R: RngCore + CryptoRng, L: SecurityLevel, D: Digest + Clone + 'static>
    HierarchicalThresholdKeygenProtocol<E, R, L, D>
{
    /// Validates hierarchical threshold key generation parameters
    fn validate_parameters(i: u16, t: u16, ranks: &[u16], n: u16) -> Result<(), HierarchicalThresholdKeygenParameterError> {
        if i >= n {
            return Err(HierarchicalThresholdKeygenParameterError::InvalidPartyIndex { i, n });
        }
        if n < 2 {
            return Err(HierarchicalThresholdKeygenParameterError::TooFewParties(n));
        }
        if t < 1 {
            return Err(HierarchicalThresholdKeygenParameterError::ThresholdTooSmall(t));
        }
        if t > n {
            return Err(HierarchicalThresholdKeygenParameterError::ThresholdTooLarge { t, n });
        }
        if ranks.len() != n as usize {
            return Err(HierarchicalThresholdKeygenParameterError::InvalidRanksLength { 
                n, 
                len: ranks.len() 
            });
        }
        for &rank in ranks {
            if rank >= t {
                return Err(HierarchicalThresholdKeygenParameterError::InvalidRank { t, rank });
            }
        }
        Ok(())
    }

    /// Create a new hierarchical threshold key generation protocol instance
    ///
    /// # Parameters
    /// * `i` - Party index (0-indexed)
    /// * `t` - Threshold (minimum number of parties required to sign)
    /// * `ranks` - Ranks of all parties (each rank must be < t)
    /// * `n` - Total number of parties
    /// * `sid` - Protocol execution ID
    /// * `reliable_broadcast_enforced` - Whether to enforce reliable broadcast
    /// * `rng` - Random number generator
    /// * `hd_enabled` - Whether HD wallet is enabled (if feature is enabled)
    ///
    /// # Returns
    /// A new `HierarchicalThresholdKeygenProtocol` instance or an error if parameters are invalid.
    pub fn new(
        i: u16,
        t: u16,
        ranks: Vec<u16>,
        n: u16,
        sid: ExecutionId<'static>,
        reliable_broadcast_enforced: bool,
        rng: R,
        #[cfg(feature = "hd-wallet")] hd_enabled: bool,
    ) -> Result<Self, HierarchicalThresholdKeygenParameterError> {
        Self::validate_parameters(i, t, &ranks, n)?;

        Ok(Self {
            state: HierarchicalThresholdKeygenState {
                i,
                t,
                ranks,
                n,
                sid,
                reliable_broadcast_enforced,
                #[cfg(feature = "hd-wallet")]
                hd_enabled,
                rid: None,
                schnorr_secret_r: None,
                polynomial_f: None,
                public_polynomial_F: None,
                sigma_shares: None,
                #[cfg(feature = "hd-wallet")]
                chain_code_local: None,
                my_commitment: None,
                my_decommitment: None,
                commitments_from_r1: None,
                my_reliability_check: None,
                decommitments_from_r2: None,
                sigmas_from_r2: None,
                combined_rid: None,
                #[cfg(feature = "hd-wallet")]
                combined_chain_code: None,
                all_public_shares_ys: None,
                my_secret_share_sigma: None,
                my_schnorr_proof: None,
                schnorr_proofs_from_r3: None,
                key_share: None,
            },
            rng,
        })
    }

    /// Generates a commitment for round 1 of the hierarchical threshold key generation protocol
    ///
    /// This method:
    /// 1. Samples random values for the protocol (rid, Schnorr commitment, polynomial, etc.)
    /// 2. Evaluates the polynomial using nth_derivative_at with ranks (hierarchical threshold)
    /// 3. Creates a commitment to these values including the party's rank
    /// 4. Updates the protocol state with the generated values
    /// 5. Returns the commitment message to be broadcast to all parties
    ///
    /// # Returns
    /// A `MsgRound1<D>` containing the commitment to be broadcast to all parties.
    pub fn round1_generate_commitment(&mut self) -> Result<MsgRound1<D>, HierarchicalThresholdKeygenError>
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

        // Evaluate the polynomial at each party's index using their rank (hierarchical threshold)
        // This is the key difference from regular threshold: use nth_derivative_at with rank
        let sigmas = self.state.ranks
            .iter()
            .enumerate()
            .map(|(j, rank)| {
                let x = Scalar::from(j + 1);
                f.nth_derivative_at(&x, *rank)
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
            rid: rid.clone(),
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
        // Note: includes rank for hierarchical threshold
        #[derive(udigest::Digestable)]
        #[udigest(tag = "dfns.cggmp21.keygen.threshold.hash_commitment")]
        #[udigest(bound = "")]
        struct HashCom<'a, E: Curve, L: SecurityLevel> {
            sid: ExecutionId<'a>,
            party_index: u16,
            rank: u16,
            decommitment: &'a MsgRound2Broad<E, L>,
        }

        // Hash the decommitment to create the commitment (including this party's rank)
        let hash_commit = udigest::hash::<D>(&HashCom {
            sid: self.state.sid,
            party_index: self.state.i,
            rank: self.state.ranks[usize::from(self.state.i)],
            decommitment: &my_decommitment,
        });

        // Create the round 1 commitment message
        let my_commitment = MsgRound1 {
            commitment: hash_commit,
        };

        // Store generated values in the protocol state
        self.state.rid = Some(rid);
        self.state.schnorr_secret_r = Some(r);
        self.state.polynomial_f = Some(f);
        self.state.public_polynomial_F = Some(F);
        self.state.sigma_shares = Some(sigmas);
        #[cfg(feature = "hd-wallet")]
        {
            self.state.chain_code_local = chain_code_local;
        }
        self.state.my_decommitment = Some(my_decommitment);
        self.state.my_commitment = Some(my_commitment.clone());

        Ok(my_commitment)
    }

    /// Sets the round 1 commitments from other parties
    ///
    /// # Parameters
    /// * `commitments` - Vector of commitments from other parties
    /// * `ids` - Vector of message IDs corresponding to each commitment
    pub fn set_round1_commitments(
        &mut self,
        commitments: Vec<MsgRound1<D>>,
        ids: Vec<u64>,
    ) -> Result<(), HierarchicalThresholdKeygenError> {
        let round_msgs = RoundMsgs::new(self.state.i, ids, commitments);
        self.state.commitments_from_r1 = Some(round_msgs);
        Ok(())
    }

    /// Creates a reliability check message (optional, only if reliable broadcast is enforced)
    ///
    /// # Returns
    /// A `MsgReliabilityCheck<D>` containing the hash of all round 1 commitments
    pub fn create_reliability_check(&mut self) -> Result<MsgReliabilityCheck<D>, HierarchicalThresholdKeygenError> {
        if !self.state.reliable_broadcast_enforced {
            return Err(HierarchicalThresholdKeygenError::Bug("Reliability check not enforced"));
        }

        let commitments = self
            .state
            .commitments_from_r1
            .as_ref()
            .ok_or_else(|| HierarchicalThresholdKeygenError::Bug("Round 1 commitments not set"))?;

        let my_commitment = self
            .state
            .my_commitment
            .as_ref()
            .ok_or_else(|| HierarchicalThresholdKeygenError::Bug("My commitment not generated"))?;

        #[derive(udigest::Digestable)]
        #[udigest(tag = "dfns.cggmp21.keygen.threshold.echo_round")]
        #[udigest(bound = "")]
        struct Echo<'a, D: digest::Digest> {
            sid: ExecutionId<'a>,
            commitment: &'a MsgRound1<D>,
        }

        let h_i = udigest::hash_iter::<D>(
            commitments
                .iter_including_me(my_commitment)
                .map(|commitment| Echo { 
                    sid: self.state.sid, 
                    commitment 
                }),
        );

        let reliability_check = MsgReliabilityCheck(h_i);
        self.state.my_reliability_check = Some(reliability_check.clone());

        Ok(reliability_check)
    }

    /// Gets the decommitment for round 2 broadcast
    ///
    /// # Returns
    /// A `MsgRound2Broad<E, L>` containing the decommitment to be broadcast to all parties
    pub fn round2_get_decommitment(&self) -> Result<MsgRound2Broad<E, L>, HierarchicalThresholdKeygenError> {
        self.state
            .my_decommitment
            .clone()
            .ok_or_else(|| HierarchicalThresholdKeygenError::Bug("Round 2 decommitment not generated"))
    }

    /// Gets the unicast messages for round 2
    ///
    /// # Returns
    /// A vector of (party_index, message) pairs to be sent to each party individually
    pub fn round2_get_unicast_messages(&self) -> Result<Vec<(u16, MsgRound2Uni<E>)>, HierarchicalThresholdKeygenError> {
        let sigmas = self.state.sigma_shares.as_ref()
            .ok_or_else(|| HierarchicalThresholdKeygenError::Bug("Sigma shares not generated"))?;

        let messages = utils::iter_peers(self.state.i, self.state.n).map(|j| {
            let message = MsgRound2Uni {
                sigma: sigmas[usize::from(j)],
            };
            (j, message)
        }).collect();

        Ok(messages)
    }

    /// Sets the round 2 decommitments from other parties
    ///
    /// # Parameters
    /// * `decommitments` - Vector of decommitments from other parties
    /// * `ids` - Vector of message IDs corresponding to each decommitment
    pub fn set_round2_decommitments(
        &mut self,
        decommitments: Vec<MsgRound2Broad<E, L>>,
        ids: Vec<u64>,
    ) -> Result<(), HierarchicalThresholdKeygenError> {
        let round_msgs = RoundMsgs::new(self.state.i, ids, decommitments);
        self.state.decommitments_from_r2 = Some(round_msgs);
        Ok(())
    }

    /// Sets the round 2 sigma shares from other parties
    ///
    /// # Parameters
    /// * `sigmas` - Vector of sigma shares from other parties
    /// * `ids` - Vector of message IDs corresponding to each sigma share
    pub fn set_round2_sigmas(
        &mut self,
        sigmas: Vec<MsgRound2Uni<E>>,
        ids: Vec<u64>,
    ) -> Result<(), HierarchicalThresholdKeygenError> {
        let round_msgs = RoundMsgs::new(self.state.i, ids, sigmas);
        self.state.sigmas_from_r2 = Some(round_msgs);
        Ok(())
    }

    /// Validates round 2 data and prepares for round 3
    ///
    /// This method validates:
    /// 1. Decommitments match the original commitments (including ranks)
    /// 2. Polynomial degree is correct
    /// 3. Feldman VSS verification using nth_derivative_at with ranks
    /// 4. Computes combined values (rid, chain_code, public shares, secret share)
    pub fn validate_round2_and_prepare_round3(&mut self) -> Result<(), HierarchicalThresholdKeygenError> {
        let commitments = self.state.commitments_from_r1.as_ref()
            .ok_or_else(|| HierarchicalThresholdKeygenError::Bug("Round 1 commitments not set"))?;
        let decommitments = self.state.decommitments_from_r2.as_ref()
            .ok_or_else(|| HierarchicalThresholdKeygenError::Bug("Round 2 decommitments not set"))?;
        let sigmas_msg = self.state.sigmas_from_r2.as_ref()
            .ok_or_else(|| HierarchicalThresholdKeygenError::Bug("Round 2 sigmas not set"))?;
        let my_decommitment = self.state.my_decommitment.as_ref()
            .ok_or_else(|| HierarchicalThresholdKeygenError::Bug("My decommitment not generated"))?;

        // Validate decommitments (including rank in hash)
        #[derive(udigest::Digestable)]
        #[udigest(tag = "dfns.cggmp21.keygen.threshold.hash_commitment")]
        #[udigest(bound = "")]
        struct HashCom<'a, E: Curve, L: SecurityLevel> {
            sid: ExecutionId<'a>,
            party_index: u16,
            rank: u16,
            decommitment: &'a MsgRound2Broad<E, L>,
        }

        let blame = utils::collect_blame(commitments, decommitments, |j, com, decom| {
            let com_expected = udigest::hash::<D>(&HashCom {
                sid: self.state.sid,
                party_index: j,
                rank: self.state.ranks[usize::from(j)],
                decommitment: decom,
            });
            com.commitment != com_expected
        });
        if !blame.is_empty() {
            return Err(HierarchicalThresholdKeygenError::Aborted(
                format!("Invalid decommitment from parties: {:?}", blame)
            ));
        }

        // Validate data size
        let blame = decommitments
            .iter_indexed()
            .filter(|(_, _, d)| d.F.degree() + 1 != usize::from(self.state.t))
            .map(|(j, _, _)| j)
            .collect::<Vec<_>>();
        if !blame.is_empty() {
            return Err(HierarchicalThresholdKeygenError::Aborted(
                format!("Invalid data size from parties: {:?}", blame)
            ));
        }

        // Validate Feldman VSS using hierarchical threshold (nth_derivative_at with rank)
        let blame = decommitments
            .iter_indexed()
            .zip(sigmas_msg.iter())
            .filter(|((_, _, d), s)| {
                let x = Scalar::from(self.state.i + 1);
                let rank = self.state.ranks[usize::from(self.state.i)];
                d.F.nth_derivative_at(&x, rank) != Point::generator() * s.sigma
            })
            .map(|((j, _, _), _)| j)
            .collect::<Vec<_>>();
        if !blame.is_empty() {
            return Err(HierarchicalThresholdKeygenError::Aborted(
                format!("Feldman verification failed for parties: {:?}", blame)
            ));
        }

        // Compute combined rid
        let combined_rid = decommitments
            .iter_including_me(my_decommitment)
            .map(|d| &d.rid)
            .fold(L::Rid::default(), utils::xor_array);
        self.state.combined_rid = Some(combined_rid);

        // Compute combined chain code (if HD wallet enabled)
        #[cfg(feature = "hd-wallet")]
        if self.state.hd_enabled {
            let blame = utils::collect_simple_blame(decommitments, |decom| decom.chain_code.is_none());
            if !blame.is_empty() {
                return Err(HierarchicalThresholdKeygenError::Aborted(
                    format!("Missing chain code from parties: {:?}", blame)
                ));
            }
            let combined_chain_code = decommitments.iter_including_me(my_decommitment).try_fold(
                hd_wallet::ChainCode::default(),
                |acc, decom| {
                    match decom.chain_code {
                        Some(chain_code) => Ok(utils::xor_array(acc, chain_code)),
                        None => Err(HierarchicalThresholdKeygenError::Bug("Missing chain code")),
                    }
                },
            )?;
            self.state.combined_chain_code = Some(combined_chain_code);
        }

        // Compute public shares using hierarchical threshold (nth_derivative_at with ranks)
        let polynomial_sum = decommitments
            .iter_including_me(my_decommitment)
            .map(|d| &d.F)
            .sum::<Polynomial<_>>();

        let ys = (0..self.state.n)
            .map(|l| {
                let rank = self.state.ranks[usize::from(l)];
                polynomial_sum.nth_derivative_at(&Scalar::from(l + 1), rank)
            })
            .map(|y_j: Point<E>| NonZero::from_point(y_j).ok_or(Bug::ZeroShare))
            .collect::<Result<Vec<_>, _>>()?;
        self.state.all_public_shares_ys = Some(ys);

        // Compute my secret share
        let sigmas = self.state.sigma_shares.as_ref().unwrap();
        let sigma: Scalar<E> = sigmas_msg.iter().map(|msg| msg.sigma).sum();
        let mut sigma = sigma + sigmas[usize::from(self.state.i)];
        let sigma = NonZero::from_secret_scalar(SecretScalar::new(&mut sigma))
            .ok_or(Bug::ZeroShare)?;
        self.state.my_secret_share_sigma = Some(sigma);

        Ok(())
    }

    /// Generates the Schnorr proof for round 3
    ///
    /// # Returns
    /// A `MsgRound3<E>` containing the Schnorr proof to be broadcast to all parties
    pub fn round3_generate_proof(&mut self) -> Result<MsgRound3<E>, HierarchicalThresholdKeygenError> {
        let combined_rid = self.state.combined_rid.as_ref()
            .ok_or_else(|| HierarchicalThresholdKeygenError::Bug("Combined rid not computed"))?;
        let ys = self.state.all_public_shares_ys.as_ref()
            .ok_or_else(|| HierarchicalThresholdKeygenError::Bug("Public shares not computed"))?;
        let sigma = self.state.my_secret_share_sigma.as_ref()
            .ok_or_else(|| HierarchicalThresholdKeygenError::Bug("My secret share not computed"))?;
        let r = self.state.schnorr_secret_r.as_ref()
            .ok_or_else(|| HierarchicalThresholdKeygenError::Bug("Schnorr secret not generated"))?;
        let my_decommitment = self.state.my_decommitment.as_ref()
            .ok_or_else(|| HierarchicalThresholdKeygenError::Bug("My decommitment not generated"))?;

        // Calculate challenge (including rank for hierarchical threshold)
        #[derive(udigest::Digestable)]
        #[udigest(tag = "dfns.cggmp21.keygen.threshold.schnorr_pok")]
        #[udigest(bound = "")]
        struct SchnorrPok<'a, E: Curve> {
            sid: ExecutionId<'a>,
            prover: u16,
            rank: u16,
            #[udigest(as_bytes)]
            rid: &'a [u8],
            y: NonZero<Point<E>>,
            h: Point<E>,
        }

        let challenge = Scalar::from_hash::<D>(&SchnorrPok {
            sid: self.state.sid,
            prover: self.state.i,
            rank: self.state.ranks[usize::from(self.state.i)],
            rid: combined_rid.as_ref(),
            y: ys[usize::from(self.state.i)],
            h: my_decommitment.sch_commit.0,
        });
        let challenge = schnorr_pok::Challenge { nonce: challenge };

        // Generate Schnorr proof
        let z = schnorr_pok::prove(r, &challenge, sigma);

        let my_schnorr_proof = MsgRound3 { sch_proof: z };
        self.state.my_schnorr_proof = Some(my_schnorr_proof.clone());

        Ok(my_schnorr_proof)
    }

    /// Sets the round 3 Schnorr proofs from other parties
    ///
    /// # Parameters
    /// * `schnorr_proofs` - Vector of Schnorr proofs from other parties
    /// * `ids` - Vector of message IDs corresponding to each proof
    pub fn set_round3_schnorr_proofs(
        &mut self,
        schnorr_proofs: Vec<MsgRound3<E>>,
        ids: Vec<u64>,
    ) -> Result<(), HierarchicalThresholdKeygenError> {
        let round_msgs = RoundMsgs::new(self.state.i, ids, schnorr_proofs);
        self.state.schnorr_proofs_from_r3 = Some(round_msgs);
        Ok(())
    }

    /// Validates round 3 proofs and generates the final key share
    ///
    /// This method:
    /// 1. Validates all Schnorr proofs (including ranks in the challenge)
    /// 2. Computes the final shared public key
    /// 3. Creates the hierarchical threshold key share with ranks
    ///
    /// # Returns
    /// The generated `CoreKeyShare<E>` for hierarchical threshold cryptography
    pub fn finalize_key_generation(&mut self) -> Result<CoreKeyShare<E>, HierarchicalThresholdKeygenError> {
        let decommitments = self.state.decommitments_from_r2.as_ref()
            .ok_or_else(|| HierarchicalThresholdKeygenError::Bug("Round 2 decommitments not set"))?;
        let sch_proofs = self.state.schnorr_proofs_from_r3.as_ref()
            .ok_or_else(|| HierarchicalThresholdKeygenError::Bug("Round 3 proofs not set"))?;
        let my_decommitment = self.state.my_decommitment.as_ref()
            .ok_or_else(|| HierarchicalThresholdKeygenError::Bug("My decommitment not generated"))?;
        let combined_rid = self.state.combined_rid.as_ref()
            .ok_or_else(|| HierarchicalThresholdKeygenError::Bug("Combined rid not computed"))?;
        let ys = self.state.all_public_shares_ys.as_ref()
            .ok_or_else(|| HierarchicalThresholdKeygenError::Bug("Public shares not computed"))?;
        let sigma = self.state.my_secret_share_sigma.as_ref()
            .ok_or_else(|| HierarchicalThresholdKeygenError::Bug("My secret share not computed"))?;

        // Validate Schnorr proofs (including ranks)
        #[derive(udigest::Digestable)]
        #[udigest(tag = "dfns.cggmp21.keygen.threshold.schnorr_pok")]
        #[udigest(bound = "")]
        struct SchnorrPok<'a, E: Curve> {
            sid: ExecutionId<'a>,
            prover: u16,
            rank: u16,
            #[udigest(as_bytes)]
            rid: &'a [u8],
            y: NonZero<Point<E>>,
            h: Point<E>,
        }

        let blame = utils::collect_blame(decommitments, sch_proofs, |j, decom, sch_proof| {
            let challenge = Scalar::from_hash::<D>(&SchnorrPok {
                sid: self.state.sid,
                prover: j,
                rank: self.state.ranks[usize::from(j)],
                rid: combined_rid.as_ref(),
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
            return Err(HierarchicalThresholdKeygenError::Aborted(
                format!("Invalid Schnorr proof from parties: {:?}", blame)
            ));
        }

        // Derive resulting public key
        let y: Point<E> = decommitments
            .iter_including_me(my_decommitment)
            .map(|d| d.F.coefs()[0])
            .sum();

        // Create key share indexes
        let key_shares_indexes = (1..=self.state.n)
            .map(|i| NonZero::from_scalar(Scalar::from(i)))
            .collect::<Option<Vec<_>>>()
            .ok_or(Bug::NonZeroScalar)?;

        // Create the hierarchical threshold key share
        let key_share = DirtyCoreKeyShare {
            i: self.state.i,
            key_info: DirtyKeyInfo {
                curve: Default::default(),
                shared_public_key: NonZero::from_point(y).ok_or(Bug::ZeroPk)?,
                public_shares: ys.clone(),
                vss_setup: Some(VssSetup {
                    min_signers: self.state.t,
                    I: key_shares_indexes,
                    ranks: Some(self.state.ranks.clone()), // Include ranks for hierarchical threshold
                }),
                #[cfg(feature = "hd-wallet")]
                chain_code: self.state.combined_chain_code,
            },
            x: sigma.clone(),
        }
        .validate()
        .map_err(|err| Bug::InvalidKeyShare(err.into_error()))?;

        self.state.key_share = Some(key_share.clone());
        Ok(key_share)
    }

    /// Get the current state for debugging/inspection
    pub fn get_state(&self) -> &HierarchicalThresholdKeygenState<E, L, D> {
        &self.state
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
    fn test_hierarchical_threshold_keygen_protocol_new_valid_parameters() {
        let i = 0;
        let t = 2;
        let ranks = vec![0, 1, 1, 0]; // Valid ranks for t=2 (all ranks < 2)
        let n = 4;
        let sid_static = ExecutionId::new_static(b"test_session");
        let rng = ChaCha20Rng::seed_from_u64(0);

        let protocol = HierarchicalThresholdKeygenProtocol::<Secp256k1, ChaCha20Rng, SecurityLevel128, Sha256>::new(
            i,
            t,
            ranks.clone(),
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
        assert_eq!(protocol.state.ranks, ranks);
        assert_eq!(protocol.state.n, n);
        assert_eq!(protocol.state.reliable_broadcast_enforced, true);
        #[cfg(feature = "hd-wallet")]
        assert_eq!(protocol.state.hd_enabled, true);
    }

    #[test]
    fn test_hierarchical_threshold_keygen_protocol_invalid_ranks_length() {
        let i = 0;
        let t = 2;
        let ranks = vec![0, 1]; // Invalid: should have n=4 elements
        let n = 4;
        let sid_static = ExecutionId::new_static(b"test_session");
        let rng = ChaCha20Rng::seed_from_u64(0);

        let result = HierarchicalThresholdKeygenProtocol::<Secp256k1, ChaCha20Rng, SecurityLevel128, Sha256>::new(
            i,
            t,
            ranks,
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
            HierarchicalThresholdKeygenParameterError::InvalidRanksLength { n, len: 2 }
        );
    }

    #[test]
    fn test_hierarchical_threshold_keygen_protocol_invalid_rank() {
        let i = 0;
        let t = 2;
        let ranks = vec![0, 1, 2, 0]; // Invalid: rank 2 >= t=2
        let n = 4;
        let sid_static = ExecutionId::new_static(b"test_session");
        let rng = ChaCha20Rng::seed_from_u64(0);

        let result = HierarchicalThresholdKeygenProtocol::<Secp256k1, ChaCha20Rng, SecurityLevel128, Sha256>::new(
            i,
            t,
            ranks,
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
            HierarchicalThresholdKeygenParameterError::InvalidRank { t, rank: 2 }
        );
    }

    #[test]
    fn test_round1_generate_commitment() {
        let i = 0;
        let t = 2;
        let ranks = vec![0, 1, 1, 0];
        let n = 4;
        let sid_static = ExecutionId::new_static(b"test_session");
        let rng = ChaCha20Rng::seed_from_u64(0);

        let mut protocol = HierarchicalThresholdKeygenProtocol::<Secp256k1, ChaCha20Rng, SecurityLevel128, Sha256>::new(
            i,
            t,
            ranks,
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
        assert!(protocol.state.rid.is_some());
        assert!(protocol.state.schnorr_secret_r.is_some());
        assert!(protocol.state.polynomial_f.is_some());
        assert!(protocol.state.public_polynomial_F.is_some());
        assert!(protocol.state.sigma_shares.is_some());
        assert!(protocol.state.my_decommitment.is_some());
        assert!(protocol.state.my_commitment.is_some());

        // Verify the state contains what we expect
        let sigmas = protocol.state.sigma_shares.as_ref().unwrap();
        assert_eq!(sigmas.len(), n as usize);

        // Verify the commitment matches what's stored in state
        assert_eq!(
            commitment.commitment,
            protocol.state.my_commitment.as_ref().unwrap().commitment
        );
    }
} 
