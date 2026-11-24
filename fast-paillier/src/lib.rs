#![doc = include_str!("../README.md")]
#![forbid(missing_docs)]

/// Common types and functions
pub mod common;
/// Module for decryption key functionality
pub mod decryption_key;
/// Module for encryption key functionality
pub mod encryption_key;
/// Module for precomputed table optimization
pub mod precomputed_table;
/// Utility functions for the Paillier cryptosystem
pub mod utils;

#[cfg(feature = "serde")]
mod serde;

use std::fmt;

use num_bigint::BigInt;
use rand_core::{CryptoRng, RngCore};

/// Paillier ciphertext
pub type Ciphertext = BigInt;
/// Paillier plaintext
pub type Plaintext = BigInt;
/// Paillier nonce
pub type Nonce = BigInt;

pub use self::{decryption_key::DecryptionKey, encryption_key::EncryptionKey};

/// Error type used in the library
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct Error(#[from] Reason);

#[derive(Debug, thiserror::Error)]
enum Reason {
    #[error("encryption error")]
    Encrypt,
    #[error("homomorphic operation failed: invalid inputs")]
    Ops,
    #[error("bug occurred")]
    Bug(#[source] Bug),
    #[error("invalid pow mod")]
    InvalidPowMod,
}

#[derive(Debug, thiserror::Error)]
enum Bug {
    #[error("pow mod undefined")]
    PowModUndef,
    #[error("invert undefined")]
    InvertUndef,
}

impl From<Bug> for Error {
    fn from(err: Bug) -> Self {
        Error(Reason::Bug(err))
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for crate::EncryptionKey {}
    impl Sealed for crate::DecryptionKey {}
}

/// Any key capable of encryption
///
/// Both encryption and decryption keys can be used to carry out encryption. Moreover, encryption
/// using decryption key is faster.
///
/// ## Example
/// This trait can be used, for instance, to accept an encryption key as an argument to the function
/// and benefit from faster encryption if decryption key is provided.
///
/// ```rust
/// use fast_paillier::{AnyEncryptionKey, Error};
/// use rug::Integer;
///
/// // This function accepts both encryption and decryption key. If decryption key is provided,
/// // it'll be more efficient
/// fn some_function(ek: &dyn AnyEncryptionKey) -> Result<Integer, Error> {
///     // ...
/// # let x = Integer::from(123); let r = Integer::from(321);
///     let ciphertext = ek.encrypt_with(&x, &r)?;
///     Ok(ciphertext)
/// }
/// ```
///
pub trait AnyEncryptionKey: sealed::Sealed {
    /// Returns the size of `N` in bits
    fn n_size(&self) -> u32;
    /// Returns the size of `a` in bits
    fn a_size(&self) -> u32;
    /// Returns the size of nonce in bits
    fn nounce_size(&self) -> u32;
    /// Returns `N`
    fn n(&self) -> &BigInt;
    /// Returns `N^2`
    fn nn(&self) -> &BigInt;
    /// Returns `N/2`
    fn half_n(&self) -> &BigInt;
    /// Return -`N/2`
    fn neg_half_n(&self) -> &BigInt;
    /// Returns h
    fn h(&self) -> &BigInt;
    /// Return h^n
    fn h_pow_n(&self) -> &BigInt;

    /// Encrypts the plaintext `x` in `{-N/2, .., N_2}` with `nonce` in `Z*_n`
    ///
    /// Returns error if inputs are not in specified range
    fn encrypt_with(&self, x: &Plaintext, nonce: &Nonce) -> Result<Ciphertext, Error>;

    /// Homomorphic addition of two ciphertexts
    ///
    /// ```text
    /// oadd(Enc(a1), Enc(a2)) = Enc(a1 + a2)
    /// ```
    fn oadd(&self, c1: &Ciphertext, c2: &Ciphertext) -> Result<Ciphertext, Error>;
    /// Homomorphic subtraction of two ciphertexts
    ///
    /// ```text
    /// osub(Enc(a1), Enc(a2)) = Enc(a1 - a2)
    /// ```
    fn osub(&self, c1: &Ciphertext, c2: &Ciphertext) -> Result<Ciphertext, Error>;
    /// Homomorphic multiplication of scalar at ciphertext
    ///
    /// ```text
    /// omul(a, Enc(c)) = Enc(a * c)
    /// ```
    fn omul(&self, scalar: &BigInt, ciphertext: &Ciphertext) -> Result<Ciphertext, Error>;
    /// Homomorphic negation of a ciphertext
    ///
    /// ```text
    /// oneg(Enc(a)) = Enc(-a)
    /// ```
    fn oneg(&self, ciphertext: &Ciphertext) -> Result<Ciphertext, Error>;

    /// Checks whether `x` is `{-N/2, .., N/2}`
    fn in_signed_group(&self, x: &BigInt) -> bool;
}

/// Additional functionality implemented for [AnyEncryptionKey]
pub trait AnyEncryptionKeyExt: AnyEncryptionKey {
    /// Encrypts the plaintext `x` in `{-N/2, .., N_2}`
    ///
    /// Nonce is sampled randomly using `rng`.
    ///
    /// Returns error if plaintext is not in specified range
    fn encrypt_with_random(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        x: &Plaintext,
    ) -> Result<(Ciphertext, Nonce), Error>;
}

impl<E: AnyEncryptionKey> AnyEncryptionKeyExt for E {
    fn encrypt_with_random(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        x: &Plaintext,
    ) -> Result<(Ciphertext, Nonce), Error> {
        let nonce = utils::sample_in_mult_group(rng, self.n());
        let ciphertext = self.encrypt_with(x, &nonce)?;
        Ok((ciphertext, nonce))
    }
}

impl AnyEncryptionKey for EncryptionKey {
    fn n_size(&self) -> u32 {
        self.n_size()
    }

    fn a_size(&self) -> u32 {
        self.a_size()
    }

    fn nounce_size(&self) -> u32 {
        self.nounce_size()
    }

    fn n(&self) -> &BigInt {
        self.n()
    }

    fn nn(&self) -> &BigInt {
        self.nn()
    }

    fn half_n(&self) -> &BigInt {
        self.half_n()
    }

    fn neg_half_n(&self) -> &BigInt {
        self.neg_half_n()
    }

    fn h(&self) -> &BigInt {
        self.h()
    }

    fn h_pow_n(&self) -> &BigInt {
        self.h_pow_n()
    }

    fn encrypt_with(&self, x: &Plaintext, nonce: &Nonce) -> Result<Ciphertext, Error> {
        self.encrypt_with(x, nonce)
    }

    fn oadd(&self, c1: &Ciphertext, c2: &Ciphertext) -> Result<Ciphertext, Error> {
        self.oadd(c1, c2)
    }

    fn osub(&self, c1: &Ciphertext, c2: &Ciphertext) -> Result<Ciphertext, Error> {
        self.osub(c1, c2)
    }

    fn omul(&self, scalar: &BigInt, ciphertext: &Ciphertext) -> Result<Ciphertext, Error> {
        self.omul(scalar, ciphertext)
    }

    fn oneg(&self, ciphertext: &Ciphertext) -> Result<Ciphertext, Error> {
        self.oneg(ciphertext)
    }

    fn in_signed_group(&self, x: &BigInt) -> bool {
        self.in_signed_group(x)
    }
}

impl AnyEncryptionKey for DecryptionKey {
    fn n_size(&self) -> u32 {
        self.encryption_key().n_size()
    }

    fn a_size(&self) -> u32 {
        self.encryption_key().a_size()
    }

    fn nounce_size(&self) -> u32 {
        self.encryption_key().nounce_size()
    }

    fn n(&self) -> &BigInt {
        self.encryption_key().n()
    }

    fn nn(&self) -> &BigInt {
        self.encryption_key().nn()
    }

    fn half_n(&self) -> &BigInt {
        self.encryption_key().half_n()
    }

    fn neg_half_n(&self) -> &BigInt {
        self.encryption_key().neg_half_n()
    }

    fn h(&self) -> &BigInt {
        self.encryption_key().h()
    }

    fn h_pow_n(&self) -> &BigInt {
        self.encryption_key().h_pow_n()
    }

    fn encrypt_with(&self, x: &Plaintext, nonce: &Nonce) -> Result<Ciphertext, Error> {
        self.encrypt_with(x, nonce)
    }

    fn oadd(&self, c1: &Ciphertext, c2: &Ciphertext) -> Result<Ciphertext, Error> {
        self.encryption_key().oadd(c1, c2)
    }

    fn osub(&self, c1: &Ciphertext, c2: &Ciphertext) -> Result<Ciphertext, Error> {
        self.encryption_key().osub(c1, c2)
    }

    fn omul(&self, scalar: &BigInt, ciphertext: &Ciphertext) -> Result<Ciphertext, Error> {
        self.omul(scalar, ciphertext)
    }

    fn oneg(&self, ciphertext: &Ciphertext) -> Result<Ciphertext, Error> {
        self.encryption_key().oneg(ciphertext)
    }

    fn in_signed_group(&self, x: &BigInt) -> bool {
        self.encryption_key().in_signed_group(x)
    }
}

impl fmt::Debug for dyn AnyEncryptionKey + '_ {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaillierEncKey")
            .field("N", self.n())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use crate::{decryption_key::DecryptionKey, utils};
    use num_bigint::BigInt;
    #[test]
    fn test_enc_dec() {
        let mut rng = rand::thread_rng();

        let dk = DecryptionKey::sample_128();
        let ek = dk.encryption_key();

        let plaintext = BigInt::from(10);
        let (ciphertext, nonce) = ek.encrypt_with_random(&mut rng, &plaintext).unwrap();
        match dk.decrypt(&ciphertext) {
            Ok(decrypted) => {
                assert_eq!(decrypted, plaintext);
                assert!(ek.in_signed_group(&decrypted));
                assert!(utils::in_mult_group(&decrypted, ek.nn()));
                assert_eq!(ek.nounce_size() as u64, nonce.bits());
            }
            Err(_) => {
                panic!("Decryption failed");
            }
        }
    }
}
