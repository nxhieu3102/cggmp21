//! Sessions for every protocol and the non-interactive helpers around them

use std::collections::BTreeSet;

use cggmp21::fast_paillier::{DecryptionKey, KeygenProgress};
use cggmp21::generic_ec::{NonZero, Point};
use cggmp21::key_share::{AnyKeyShare, AuxInfo, IncompleteKeyShare, KeyShare};
use cggmp21::security_level::SecurityLevel;
use cggmp21::signing::msg::Msg as SigningMsg;
use cggmp21::{
    DataToSign, ExecutionId, PartialSignature, PregeneratedPaillierKey, Presignature, Signature,
};
use rand_core::{CryptoRng, RngCore};
use round_based::state_machine::{wrap_protocol, MpcParty};
use serde::{Deserialize, Serialize};

use crate::blob::{self, BlobKind};
use crate::session::{now_ms, Driver, Envelope, Step, TraceLog};
use crate::{Error, D, E, L};

type ThresholdKeygenMsg = cggmp21::keygen::msg::threshold::Msg<E, L, D>;
type HierarchicalKeygenMsg = cggmp21::keygen::msg::hierarchical_threshold::Msg<E, L, D>;
type AuxMsg = cggmp21::key_refresh::AuxOnlyMsg<D, L>;

macro_rules! session_api {
    ($session:ident, $output:ty) => {
        impl $session {
            /// Starts the protocol, returns the first outgoing messages
            pub fn start(&mut self) -> Result<Step<$output>, Error> {
                self.driver.start()
            }

            /// Processes a message received from another party
            ///
            /// Messages received before [`start`](Self::start) are queued. A rejected message
            /// ([`Error::InvalidMessage`]) leaves the session usable; any other error
            /// terminates it.
            pub fn handle_incoming(&mut self, envelope: &Envelope) -> Result<Step<$output>, Error> {
                self.driver.handle_incoming(envelope)
            }

            /// Whether the protocol output was already returned
            pub fn is_finished(&self) -> bool {
                self.driver.is_finished()
            }
        }
    };
}

fn check_eid(eid: &[u8]) -> Result<(), Error> {
    if eid.is_empty() {
        return Err(Error::InvalidInput("execution id must not be empty"));
    }
    Ok(())
}

fn encode_point(point: &NonZero<Point<E>>) -> Vec<u8> {
    point.to_bytes(true).as_bytes().to_vec()
}

fn encode_signature(sig: &Signature<E>) -> Vec<u8> {
    let mut out = vec![0u8; Signature::<E>::serialized_len()];
    sig.write_to_slice(&mut out);
    out
}

// ---------------------------------------------------------------------------------------------
// Key generation

/// Configuration of a [`KeygenSession`]
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeygenConfig {
    /// Execution ID, the same for all parties and unique for every protocol run
    #[serde(with = "serde_bytes")]
    pub execution_id: Vec<u8>,
    /// Index of this party, `0 <= i < n`
    pub i: u16,
    /// Number of parties
    pub n: u16,
    /// Threshold: number of parties required to sign, `2 <= t <= n`
    pub t: u16,
    /// Ranks of all `n` parties for hierarchical threshold keygen (HTSS), each `< t`; `None` for
    /// plain threshold keygen
    #[serde(default)]
    pub ranks: Option<Vec<u16>>,
}

/// Output of [`KeygenSession`]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeygenOutput {
    /// [`BlobKind::IncompleteKeyShare`] blob. **Secret.** Complete it with aux info via
    /// [`complete_key_share`] before signing.
    #[serde(with = "serde_bytes")]
    pub key_share: Vec<u8>,
    /// Shared public key, SEC1 compressed (33 bytes)
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
}

/// Threshold (or hierarchical threshold) distributed key generation
pub struct KeygenSession {
    driver: Driver<KeygenOutput>,
}

impl KeygenSession {
    /// Creates a session; the protocol starts with [`start`](Self::start)
    pub fn new<R>(config: KeygenConfig, mut rng: R) -> Result<Self, Error>
    where
        R: RngCore + CryptoRng + 'static,
    {
        let KeygenConfig {
            execution_id,
            i,
            n,
            t,
            ranks,
        } = config;
        check_eid(&execution_id)?;
        if n < 2 || i >= n {
            return Err(Error::InvalidInput("need n >= 2 and i < n"));
        }
        if t < 2 || t > n {
            return Err(Error::InvalidInput("need 2 <= t <= n"));
        }
        let trace = TraceLog::default();
        let mut tracer = trace.clone();
        let driver = match ranks {
            None => Driver::new(
                i,
                n,
                trace,
                wrap_protocol(move |party: MpcParty<ThresholdKeygenMsg>| async move {
                    let share = cggmp21::keygen::<E>(ExecutionId::new(&execution_id), i, n)
                        .set_threshold(t)
                        .set_progress_tracer(&mut tracer)
                        .start(&mut rng, party)
                        .await
                        .map_err(|e| Error::protocol(&e))?;
                    keygen_output(&share)
                }),
            ),
            Some(ranks) => {
                if ranks.len() != usize::from(n) || ranks.iter().any(|&r| r >= t) {
                    return Err(Error::InvalidInput("need n ranks, each < t"));
                }
                Driver::new(
                    i,
                    n,
                    trace,
                    wrap_protocol(move |party: MpcParty<HierarchicalKeygenMsg>| async move {
                        let share = cggmp21::keygen::<E>(ExecutionId::new(&execution_id), i, n)
                            .set_hierarchical_threshold(t, ranks)
                            .set_progress_tracer(&mut tracer)
                            .start(&mut rng, party)
                            .await
                            .map_err(|e| Error::protocol(&e))?;
                        keygen_output(&share)
                    }),
                )
            }
        };
        Ok(Self { driver })
    }
}
session_api!(KeygenSession, KeygenOutput);

fn keygen_output(share: &IncompleteKeyShare<E>) -> Result<KeygenOutput, Error> {
    Ok(KeygenOutput {
        key_share: blob::encode(BlobKind::IncompleteKeyShare, share)?,
        public_key: encode_point(&share.shared_public_key()),
    })
}

// ---------------------------------------------------------------------------------------------
// Paillier key and aux info generation

/// Progress of [`generate_paillier_key`] (contains no secret values)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum PaillierProgress {
    /// A small prime divisor of `p - 1` (`which = 0`) or `q - 1` (`which = 1`) was found
    DivisorPrimeFound {
        /// 0 for p, 1 for q
        which: u8,
    },
    /// Candidates tested so far while searching p or q
    CandidateTested {
        /// 0 for p, 1 for q
        which: u8,
        /// Candidates tested so far for this prime
        attempts: u64,
    },
    /// p or q was found
    PrimeFound {
        /// 0 for p, 1 for q
        which: u8,
        /// Candidates tested for this prime
        attempts: u64,
    },
}

/// Generates the Paillier key a party needs for [`AuxInfoSession`]
///
/// Takes a while (seconds natively, longer in a browser). It can run ahead of time, before the
/// parties meet. `progress` receives events at most every `min_interval_ms` milliseconds for
/// [`PaillierProgress::CandidateTested`]; other events are always delivered.
///
/// Returns a [`BlobKind::PaillierKey`] blob. **Secret**; use it for one aux info generation only.
pub fn generate_paillier_key<R: RngCore + CryptoRng>(
    rng: &mut R,
    min_interval_ms: f64,
    progress: &mut dyn FnMut(PaillierProgress),
) -> Result<Vec<u8>, Error> {
    let mut last_report = f64::NEG_INFINITY;
    let mut on_progress = |event: KeygenProgress| {
        let event = match event {
            KeygenProgress::DivisorPrimeFound { which } => {
                PaillierProgress::DivisorPrimeFound { which }
            }
            KeygenProgress::CandidateTested { which, attempts } => {
                let now = now_ms();
                if now - last_report < min_interval_ms {
                    return;
                }
                last_report = now;
                PaillierProgress::CandidateTested { which, attempts }
            }
            KeygenProgress::PrimeFound { which, attempts } => {
                PaillierProgress::PrimeFound { which, attempts }
            }
            _ => return,
        };
        progress(event)
    };
    let dec = DecryptionKey::generate_with_progress(rng, L::N_SIZE, L::A_SIZE, &mut on_progress)
        .map_err(|_| Error::Internal("paillier key generation failed"))?;
    let key = PregeneratedPaillierKey::<L>::new(dec).ok_or(Error::Internal(
        "generated paillier key has unexpected size",
    ))?;
    blob::encode(BlobKind::PaillierKey, &key)
}

/// Configuration of an [`AuxInfoSession`]
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuxInfoConfig {
    /// Execution ID, the same for all parties and unique for every protocol run
    #[serde(with = "serde_bytes")]
    pub execution_id: Vec<u8>,
    /// Index of this party; must equal its index in the key share the aux info will complete
    pub i: u16,
    /// Number of parties; must equal the number of parties sharing the key
    pub n: u16,
    /// [`BlobKind::PaillierKey`] blob from [`generate_paillier_key`]
    #[serde(with = "serde_bytes")]
    pub paillier_key: Vec<u8>,
}

/// Output of [`AuxInfoSession`]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuxInfoOutput {
    /// [`BlobKind::AuxInfo`] blob. **Secret** (contains the Paillier decryption key).
    #[serde(with = "serde_bytes")]
    pub aux_info: Vec<u8>,
}

/// Auxiliary info generation (Paillier keys and ring-Pedersen parameters with their ZK proofs)
pub struct AuxInfoSession {
    driver: Driver<AuxInfoOutput>,
}

impl AuxInfoSession {
    /// Creates a session; the protocol starts with [`start`](Self::start)
    pub fn new<R>(config: AuxInfoConfig, mut rng: R) -> Result<Self, Error>
    where
        R: RngCore + CryptoRng + 'static,
    {
        let AuxInfoConfig {
            execution_id,
            i,
            n,
            paillier_key,
        } = config;
        check_eid(&execution_id)?;
        if n < 2 || i >= n {
            return Err(Error::InvalidInput("need n >= 2 and i < n"));
        }
        let key: PregeneratedPaillierKey<L> = blob::decode(BlobKind::PaillierKey, &paillier_key)?;
        // `new` enforces the key size required by the security level
        let key =
            PregeneratedPaillierKey::<L>::new(key.dec().clone()).ok_or(Error::InvalidBlob {
                expected: BlobKind::PaillierKey.tag(),
            })?;
        let trace = TraceLog::default();
        let mut tracer = trace.clone();
        let driver = Driver::new(
            i,
            n,
            trace,
            wrap_protocol(move |party: MpcParty<AuxMsg>| async move {
                let aux: AuxInfo<L> =
                    cggmp21::aux_info_gen(ExecutionId::new(&execution_id), i, n, key)
                        .set_progress_tracer(&mut tracer)
                        .start(&mut rng, party)
                        .await
                        .map_err(|e| Error::protocol(&e))?;
                Ok(AuxInfoOutput {
                    aux_info: blob::encode(BlobKind::AuxInfo, &aux)?,
                })
            }),
        );
        Ok(Self { driver })
    }
}
session_api!(AuxInfoSession, AuxInfoOutput);

/// Combines the outputs of key generation and aux info generation of the same party into a key
/// share usable for signing ([`BlobKind::KeyShare`] blob, **secret**)
pub fn complete_key_share(incomplete_key_share: &[u8], aux_info: &[u8]) -> Result<Vec<u8>, Error> {
    let core: IncompleteKeyShare<E> =
        blob::decode(BlobKind::IncompleteKeyShare, incomplete_key_share)?;
    let aux: AuxInfo<L> = blob::decode(BlobKind::AuxInfo, aux_info)?;
    let share = KeyShare::<E, L>::from_parts((core, aux))
        .map_err(|_| Error::InvalidInput("key share and aux info do not match"))?;
    blob::encode(BlobKind::KeyShare, &share)
}

/// Public information about a key share blob (complete or incomplete)
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyShareInfo {
    /// Whether the share is complete (usable for signing)
    pub complete: bool,
    /// Index of the party at keygen
    pub i: u16,
    /// Number of parties
    pub n: u16,
    /// Threshold
    pub t: u16,
    /// Ranks of parties for HTSS key shares
    pub ranks: Option<Vec<u16>>,
    /// Shared public key, SEC1 compressed (33 bytes)
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
}

/// Reads public information from a key share blob
pub fn key_share_info(key_share: &[u8]) -> Result<KeyShareInfo, Error> {
    fn info(complete: bool, share: &impl AnyKeyShare<E>) -> KeyShareInfo {
        let core: &IncompleteKeyShare<E> = share.as_ref();
        KeyShareInfo {
            complete,
            i: core.i,
            n: share.n(),
            t: share.min_signers(),
            ranks: core.vss_setup.as_ref().and_then(|s| s.ranks.clone()),
            public_key: encode_point(&share.shared_public_key()),
        }
    }
    match blob::kind_of(key_share)? {
        BlobKind::KeyShare => {
            let share: KeyShare<E, L> = blob::decode(BlobKind::KeyShare, key_share)?;
            Ok(info(true, &share))
        }
        BlobKind::IncompleteKeyShare => {
            let share: IncompleteKeyShare<E> =
                blob::decode(BlobKind::IncompleteKeyShare, key_share)?;
            Ok(info(false, &share))
        }
        _ => Err(Error::InvalidInput("not a key share blob")),
    }
}

// ---------------------------------------------------------------------------------------------
// Signing

/// Configuration of a [`SigningSession`] or [`PresigningSession`]
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningConfig {
    /// Execution ID, the same for all signers and unique for every protocol run
    #[serde(with = "serde_bytes")]
    pub execution_id: Vec<u8>,
    /// Index of this party among `signers` (the index used in envelopes)
    pub i: u16,
    /// Keygen indices of the parties taking part in signing (at least `t`, distinct)
    pub signers: Vec<u16>,
    /// [`BlobKind::KeyShare`] blob of this party
    #[serde(with = "serde_bytes")]
    pub key_share: Vec<u8>,
    /// Message to sign (hashed with SHA-256); required by [`SigningSession`], must be absent
    /// for [`PresigningSession`]
    #[serde(default, with = "serde_bytes")]
    pub message: Option<Vec<u8>>,
}

impl SigningConfig {
    fn validate(&self) -> Result<KeyShare<E, L>, Error> {
        check_eid(&self.execution_id)?;
        let share: KeyShare<E, L> = blob::decode(BlobKind::KeyShare, &self.key_share)?;
        let distinct: BTreeSet<_> = self.signers.iter().collect();
        if distinct.len() != self.signers.len() || self.signers.iter().any(|&j| j >= share.n()) {
            return Err(Error::InvalidInput(
                "signers must be distinct keygen indices",
            ));
        }
        if self.signers.len() < usize::from(share.min_signers()) {
            return Err(Error::InvalidInput("fewer signers than the threshold"));
        }
        if usize::from(self.i) >= self.signers.len()
            || self.signers[usize::from(self.i)] != share.core.i
        {
            return Err(Error::InvalidInput(
                "signers[i] must be the keygen index of this key share",
            ));
        }
        Ok(share)
    }
}

/// Output of [`SigningSession`]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureOutput {
    /// `r || s`, 32 bytes each, big-endian, `s` normalized to the lower half
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    /// Shared public key, SEC1 compressed (33 bytes)
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
}

/// Interactive signing of a message
pub struct SigningSession {
    driver: Driver<SignatureOutput>,
}

impl SigningSession {
    /// Creates a session; the protocol starts with [`start`](Self::start)
    pub fn new<R>(config: SigningConfig, mut rng: R) -> Result<Self, Error>
    where
        R: RngCore + CryptoRng + 'static,
    {
        let share = config.validate()?;
        let message = config
            .message
            .ok_or(Error::InvalidInput("message to sign is required"))?;
        let SigningConfig {
            execution_id,
            i,
            signers,
            ..
        } = config;
        let n = signers.len() as u16;
        let trace = TraceLog::default();
        let mut tracer = trace.clone();
        let driver = Driver::new(
            i,
            n,
            trace,
            wrap_protocol(move |party: MpcParty<SigningMsg<E, D>>| async move {
                let data = DataToSign::digest::<D>(&message);
                let sig = cggmp21::signing(ExecutionId::new(&execution_id), i, &signers, &share)
                    .set_progress_tracer(&mut tracer)
                    .sign(&mut rng, party, data)
                    .await
                    .map_err(|e| Error::protocol(&e))?;
                Ok(SignatureOutput {
                    signature: encode_signature(&sig),
                    public_key: encode_point(&share.shared_public_key()),
                })
            }),
        );
        Ok(Self { driver })
    }
}
session_api!(SigningSession, SignatureOutput);

/// Output of [`PresigningSession`]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PresignatureOutput {
    /// [`BlobKind::Presignature`] blob. **Secret; use at most once** — two partial signatures
    /// from the same presignature leak the key.
    #[serde(with = "serde_bytes")]
    pub presignature: Vec<u8>,
}

/// Interactive presignature generation; signing then takes one non-interactive step per signer
/// ([`issue_partial_signature`]) and [`combine_partial_signatures`]
pub struct PresigningSession {
    driver: Driver<PresignatureOutput>,
}

impl PresigningSession {
    /// Creates a session; the protocol starts with [`start`](Self::start)
    pub fn new<R>(config: SigningConfig, mut rng: R) -> Result<Self, Error>
    where
        R: RngCore + CryptoRng + 'static,
    {
        let share = config.validate()?;
        if config.message.is_some() {
            return Err(Error::InvalidInput("presigning does not take a message"));
        }
        let SigningConfig {
            execution_id,
            i,
            signers,
            ..
        } = config;
        let n = signers.len() as u16;
        let trace = TraceLog::default();
        let mut tracer = trace.clone();
        let driver = Driver::new(
            i,
            n,
            trace,
            wrap_protocol(move |party: MpcParty<SigningMsg<E, D>>| async move {
                let presig: Presignature<E> =
                    cggmp21::signing(ExecutionId::new(&execution_id), i, &signers, &share)
                        .set_progress_tracer(&mut tracer)
                        .generate_presignature(&mut rng, party)
                        .await
                        .map_err(|e| Error::protocol(&e))?;
                Ok(PresignatureOutput {
                    presignature: blob::encode(BlobKind::Presignature, &presig)?,
                })
            }),
        );
        Ok(Self { driver })
    }
}
session_api!(PresigningSession, PresignatureOutput);

/// Issues this signer's partial signature of `message` (hashed with SHA-256)
///
/// **Never use a presignature twice**: the caller must delete the presignature blob after this
/// call. Returns a [`BlobKind::PartialSignature`] blob (public).
pub fn issue_partial_signature(presignature: &[u8], message: &[u8]) -> Result<Vec<u8>, Error> {
    let presig: Presignature<E> = blob::decode(BlobKind::Presignature, presignature)?;
    let partial = presig
        .issue_partial_signature(DataToSign::digest::<D>(message))
        .map_err(|_| Error::Internal("issuing partial signature failed"))?;
    blob::encode(BlobKind::PartialSignature, &partial)
}

/// Combines the partial signatures of all signers of a presigning session and verifies the result
///
/// Returns `r || s` (64 bytes). Fails if the combined signature is not valid for `public_key`
/// and `message`, which means a signer misbehaved.
pub fn combine_partial_signatures<'a>(
    public_key: &[u8],
    message: &[u8],
    partial_signatures: impl IntoIterator<Item = &'a [u8]>,
) -> Result<Vec<u8>, Error> {
    let public_key = decode_public_key(public_key)?;
    let partials = partial_signatures
        .into_iter()
        .map(|p| blob::decode::<PartialSignature<E>>(BlobKind::PartialSignature, p))
        .collect::<Result<Vec<_>, _>>()?;
    let sig = PartialSignature::combine(&partials)
        .ok_or(Error::InvalidInput("no or degenerate partial signatures"))?;
    sig.verify(&public_key, &DataToSign::digest::<D>(message))
        .map_err(|_| Error::Protocol("combined signature is invalid".into()))?;
    Ok(encode_signature(&sig))
}

fn decode_public_key(public_key: &[u8]) -> Result<Point<E>, Error> {
    Point::<E>::from_bytes(public_key).map_err(|_| Error::InvalidInput("malformed public key"))
}

/// Verifies an ECDSA signature `r || s` (64 bytes) of `message` (hashed with SHA-256) under a
/// SEC1-encoded public key
///
/// Returns `Ok(false)` for a well-formed but invalid signature and an error for malformed input.
pub fn verify_signature(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, Error> {
    let public_key = decode_public_key(public_key)?;
    let sig = Signature::<E>::read_from_slice(signature)
        .ok_or(Error::InvalidInput("malformed signature"))?;
    Ok(sig
        .verify(&public_key, &DataToSign::digest::<D>(message))
        .is_ok())
}
