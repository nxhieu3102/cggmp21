//! Opaque serialized blobs handed to the caller for storage
//!
//! A blob is CBOR of `{"format": "cggmp21-wasm/1", "kind": <kind>, "data": <value>}` where
//! `<value>` is the serde representation of the corresponding `cggmp21` type. The kind tag makes
//! it impossible to pass, say, aux info where a key share is expected.
//!
//! **Security:** every kind except [`BlobKind::PartialSignature`] contains secret material. Store
//! such blobs encrypted, never log them and never send them to other parties.

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::Error;

/// Format tag written into every blob
pub const FORMAT: &str = "cggmp21-wasm/1";

/// What a blob contains
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobKind {
    /// Output of key generation: [`cggmp21::IncompleteKeyShare`] (secret)
    IncompleteKeyShare,
    /// Output of aux info generation: [`cggmp21::key_share::AuxInfo`] (secret)
    AuxInfo,
    /// Key share usable for signing: [`cggmp21::KeyShare`] (secret)
    KeyShare,
    /// Pregenerated Paillier key: [`cggmp21::PregeneratedPaillierKey`] (secret)
    PaillierKey,
    /// [`cggmp21::Presignature`] (secret, must be used at most once)
    Presignature,
    /// [`cggmp21::PartialSignature`] (public)
    PartialSignature,
}

impl BlobKind {
    /// Tag stored in the blob
    pub const fn tag(self) -> &'static str {
        match self {
            BlobKind::IncompleteKeyShare => "incomplete-key-share",
            BlobKind::AuxInfo => "aux-info",
            BlobKind::KeyShare => "key-share",
            BlobKind::PaillierKey => "paillier-key",
            BlobKind::Presignature => "presignature",
            BlobKind::PartialSignature => "partial-signature",
        }
    }

    fn from_tag(tag: &str) -> Option<Self> {
        [
            BlobKind::IncompleteKeyShare,
            BlobKind::AuxInfo,
            BlobKind::KeyShare,
            BlobKind::PaillierKey,
            BlobKind::Presignature,
            BlobKind::PartialSignature,
        ]
        .into_iter()
        .find(|k| k.tag() == tag)
    }
}

#[derive(Serialize)]
struct BlobRef<'a, T> {
    format: &'static str,
    kind: &'static str,
    data: &'a T,
}

#[derive(Deserialize)]
struct Header {
    format: String,
    kind: String,
}

#[derive(Deserialize)]
struct BlobOwned<T> {
    data: T,
}

/// Serializes `data` as a blob of given kind
pub fn encode<T: Serialize>(kind: BlobKind, data: &T) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    ciborium::into_writer(
        &BlobRef {
            format: FORMAT,
            kind: kind.tag(),
            data,
        },
        &mut out,
    )
    .map_err(|_| Error::Internal("blob serialization failed"))?;
    Ok(out)
}

/// Returns the kind of a blob without decoding its content
pub fn kind_of(bytes: &[u8]) -> Result<BlobKind, Error> {
    let header: Header =
        ciborium::from_reader(bytes).map_err(|_| Error::InvalidInput("not a blob"))?;
    if header.format != FORMAT {
        return Err(Error::InvalidInput("unsupported blob format"));
    }
    BlobKind::from_tag(&header.kind).ok_or(Error::InvalidInput("unknown blob kind"))
}

/// Deserializes a blob, checking that it has the expected kind
///
/// Values that implement validation in `cggmp21` (key shares, aux info) are validated during
/// deserialization.
pub fn decode<T: DeserializeOwned>(kind: BlobKind, bytes: &[u8]) -> Result<T, Error> {
    let invalid = || Error::InvalidBlob {
        expected: kind.tag(),
    };
    if kind_of(bytes).map_err(|_| invalid())? != kind {
        return Err(invalid());
    }
    let blob: BlobOwned<T> = ciborium::from_reader(bytes).map_err(|_| invalid())?;
    Ok(blob.data)
}
