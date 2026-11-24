//! Message-driven party sessions for CGGMP21 threshold ECDSA, built for WebAssembly.
//!
//! Each protocol of [`cggmp21`] (threshold and hierarchical-threshold key generation,
//! auxiliary info generation, signing and presigning) is driven through
//! [`round_based::state_machine`]: this crate does not re-implement any protocol round, it
//! only moves serialized messages in and out of the original async protocols.
//!
//! A session is used the same way for every protocol:
//! 1. `Session::new(config, rng)` with an execution ID that all parties agreed on for this
//!    protocol run;
//! 2. [`start`](KeygenSession::start) returns the first outgoing messages;
//! 3. every message received from the network goes to
//!    [`handle_incoming`](KeygenSession::handle_incoming), which returns more outgoing messages
//!    and, once the protocol completes, its output.
//!
//! Messages are [`Envelope`]s: sender, recipient (`None` = broadcast) and a CBOR payload.
//! Transport is the caller's job. **The envelope's `sender` is trusted**: a real deployment must
//! deliver messages over authenticated and encrypted channels (p2p messages of key generation
//! carry secret shares), and broadcast messages must reach every party.
//!
//! Key shares, aux info, presignatures and pregenerated Paillier keys are returned as opaque
//! serialized blobs (see [`blob`]). **Blobs of key shares, aux info, Paillier keys and
//! presignatures contain secrets**: store them encrypted, never log them, never send them to
//! other parties.
//!
//! Fixed parameters: curve secp256k1, security level [`SecurityLevel128`](cggmp21::security_level::SecurityLevel128),
//! digest SHA-256; messages to be signed are hashed with SHA-256.
//!
//! With the `wasm32` target the crate also exports a JavaScript API (see the `wasm` module and
//! `demo/` in the repository).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod blob;
mod error;
mod protocols;
mod session;
#[cfg(target_arch = "wasm32")]
mod wasm;

pub use self::{
    error::Error,
    protocols::{
        combine_partial_signatures, complete_key_share, generate_paillier_key,
        issue_partial_signature, key_share_info, verify_signature, AuxInfoConfig, AuxInfoOutput,
        AuxInfoSession, KeyShareInfo, KeygenConfig, KeygenOutput, KeygenSession, PaillierProgress,
        PresignatureOutput, PresigningSession, SignatureOutput, SigningConfig, SigningSession,
    },
    session::{Envelope, Step, TraceEvent, TraceKind},
};

/// Curve used by every session
pub type E = cggmp21::supported_curves::Secp256k1;
/// Security level used by every session
pub type L = cggmp21::security_level::SecurityLevel128;
/// Digest used by every session and for hashing messages to be signed
pub type D = sha2::Sha256;
