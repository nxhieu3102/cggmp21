//! Serde support for [`EncryptionKey`] and [`DecryptionKey`]
//!
//! Format (unchanged from earlier versions, so stored keys keep loading): integers are hex
//! strings, e.g.
//! `{"n_size":3072,"a_size":512,"nounce_size":512,"h":"-1182..","n":"..","nn":"..",
//! "h_pow_n":"..","half_n":"..","neg_half_n":"-.."}` and
//! `{"ek":{..},"p":"..","q":"..","alpha":".."}`.
//!
//! Deserialization never panics. It checks the cheap invariants (`n > 1` odd, `nn = n²`,
//! `half_n`/`neg_half_n` derived from `n`, `nounce_size = a_size`, `h_pow_n` a reduced unit) and
//! *trusts* `h_pow_n` without recomputing it: keys received from other parties must be checked
//! with [`EncryptionKey::verify_h_pow_n`]. A decryption key is additionally checked by
//! [`DecryptionKey::new`].

use crate::{DecryptionKey, EncryptionKey, Error, Reason};
use num_bigint::BigInt;
use num_traits::Num;
use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Serialize)]
struct EncryptionKeyRef<'a> {
    n_size: u32,
    a_size: u32,
    nounce_size: u32,
    h: Hex<'a>,
    n: Hex<'a>,
    nn: Hex<'a>,
    h_pow_n: Hex<'a>,
    half_n: Hex<'a>,
    neg_half_n: Hex<'a>,
}

#[derive(Deserialize)]
struct EncryptionKeyRepr {
    n_size: u32,
    a_size: u32,
    nounce_size: u32,
    h: String,
    n: String,
    nn: String,
    h_pow_n: String,
    half_n: String,
    neg_half_n: String,
}

#[derive(Serialize)]
struct DecryptionKeyRef<'a> {
    ek: EncryptionKeyRef<'a>,
    p: Hex<'a>,
    q: Hex<'a>,
    alpha: Hex<'a>,
}

#[derive(Deserialize)]
struct DecryptionKeyRepr {
    ek: EncryptionKeyRepr,
    p: String,
    q: String,
    alpha: String,
}

/// Serializes a `BigInt` as a (signed) lowercase hex string
struct Hex<'a>(&'a BigInt);

impl Serialize for Hex<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&format_args!("{:x}", self.0))
    }
}

fn parse_hex<E: de::Error>(field: &'static str, hex: &str) -> Result<BigInt, E> {
    BigInt::from_str_radix(hex, 16)
        .map_err(|_| E::custom(format_args!("field `{field}` is not a hex integer")))
}

impl<'a> EncryptionKeyRef<'a> {
    fn new(ek: &'a EncryptionKey) -> Self {
        Self {
            n_size: ek.n_size(),
            a_size: ek.a_size(),
            nounce_size: ek.nounce_size(),
            h: Hex(ek.h()),
            n: Hex(ek.n()),
            nn: Hex(ek.nn()),
            h_pow_n: Hex(ek.h_pow_n()),
            half_n: Hex(ek.half_n()),
            neg_half_n: Hex(ek.neg_half_n()),
        }
    }
}

impl EncryptionKeyRepr {
    fn into_key<E: de::Error>(self) -> Result<EncryptionKey, E> {
        let h = parse_hex("h", &self.h)?;
        let n = parse_hex("n", &self.n)?;
        let nn = parse_hex("nn", &self.nn)?;
        let h_pow_n = parse_hex("h_pow_n", &self.h_pow_n)?;
        let half_n = parse_hex("half_n", &self.half_n)?;
        let neg_half_n = parse_hex("neg_half_n", &self.neg_half_n)?;

        if self.nounce_size != self.a_size {
            return Err(E::custom("nounce_size must be equal to a_size"));
        }
        let ek = EncryptionKey::from_parts(self.n_size, self.a_size, h, n, h_pow_n)
            .map_err(E::custom)?;
        if *ek.nn() != nn || *ek.half_n() != half_n || *ek.neg_half_n() != neg_half_n {
            return Err(E::custom("inconsistent encryption key"));
        }
        Ok(ek)
    }
}

impl Serialize for EncryptionKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        EncryptionKeyRef::new(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for EncryptionKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        EncryptionKeyRepr::deserialize(deserializer)?.into_key()
    }
}

impl Serialize for DecryptionKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        DecryptionKeyRef {
            ek: EncryptionKeyRef::new(self.encryption_key()),
            p: Hex(self.p()),
            q: Hex(self.q()),
            alpha: Hex(self.alpha()),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DecryptionKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let repr = DecryptionKeyRepr::deserialize(deserializer)?;
        let ek = repr.ek.into_key()?;
        let p = parse_hex("p", &repr.p)?;
        let q = parse_hex("q", &repr.q)?;
        let alpha = parse_hex("alpha", &repr.alpha)?;
        DecryptionKey::new(ek, p, q, alpha).map_err(de::Error::custom)
    }
}

impl EncryptionKey {
    /// Serialize the EncryptionKey to a JSON string
    pub fn to_json(&self) -> Result<String, Error> {
        serde_json::to_string(self).map_err(|_| Error::from(Reason::Serde))
    }

    /// Deserialize an EncryptionKey from a JSON string
    pub fn from_json(json: &str) -> Result<Self, Error> {
        serde_json::from_str(json).map_err(|_| Error::from(Reason::Serde))
    }
}

impl DecryptionKey {
    /// Serialize the DecryptionKey to a JSON string
    pub fn to_json(&self) -> Result<String, Error> {
        serde_json::to_string(self).map_err(|_| Error::from(Reason::Serde))
    }

    /// Deserialize a DecryptionKey from a JSON string
    pub fn from_json(json: &str) -> Result<Self, Error> {
        serde_json::from_str(json).map_err(|_| Error::from(Reason::Serde))
    }
}
