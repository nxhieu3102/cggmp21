use crate::mont::Montgomery;
use crate::precomputed_table::PrecomputeTable;
use crate::{utils, Ciphertext, Nonce, Plaintext};
use crate::{Error, Reason};
use num_bigint::{BigInt, BigUint, Sign};
use num_integer::Integer;
use num_traits::One;
use rand_core::{CryptoRng, RngCore};

/// Paillier encryption key
///
/// Invariants (checked by every constructor and by deserialization): `n > 1` is odd,
/// `nn = n²`, `0 <= h_pow_n < nn` and `h_pow_n` is invertible modulo `nn`, `a_size > 0`.
///
/// Keys built with [`EncryptionKey::new`] compute `h_pow_n = h^n mod n²` themselves.
/// Deserialization instead *trusts* the serialized `h_pow_n` (recomputing it costs a
/// `|n|`-bit exponentiation modulo `n²`). A key received from another party must therefore be
/// checked with [`EncryptionKey::verify_h_pow_n`] before use.
#[derive(Clone, Debug)]
pub struct EncryptionKey {
    /// n size (number bits of n)
    n_size: u32,

    /// alpha size in decryption key
    a_size: u32,

    /// nounce (random) in encryption have size a_size (follow the paper)
    nounce_size: u32,

    /// generator of nounce space (G)
    /// h = -y^(2*beta) mod n
    h: BigInt,

    /// n = q * p (q,p are primes)
    n: BigInt,

    /// nn = n * n
    /// modulo in Paillier scheme
    nn: BigInt,

    /// h_pow_n = (h^n) mod nn
    /// a constant in encryption
    h_pow_n: BigInt,

    /// half_n = n / 2
    /// use in validate plaintext (-n/2 <= p <= n/2)
    half_n: BigInt,

    /// neg_half_n = - (n / 2)
    /// use in validate plaintext (-n/2 <= p <= n/2)
    neg_half_n: BigInt,

    /// Montgomery context for `nn`
    nn_ctx: Montgomery,
}

impl EncryptionKey {
    /// Constructs an encryption key, computing `h_pow_n = h^n mod n²`
    ///
    /// Returns an error if `n <= 1`, `n` is even, `a_size == 0`, or `h` is not invertible modulo
    /// `n`.
    pub fn new(n_size: u32, a_size: u32, h: BigInt, n: BigInt) -> Result<Self, Error> {
        let (nn, nn_ctx) = Self::check_modulus(&n, a_size)?;
        let h_pow_n = utils::pow_signed_mont(&nn_ctx, &h, &n).ok_or(Reason::InvalidKey)?;
        Self::assemble(n_size, a_size, h, n, nn, BigInt::from(h_pow_n), nn_ctx)
    }

    /// Constructs an encryption key from all its parts without recomputing `h_pow_n`
    ///
    /// Only cheap invariants are checked; see [`EncryptionKey::verify_h_pow_n`].
    pub(crate) fn from_parts(
        n_size: u32,
        a_size: u32,
        h: BigInt,
        n: BigInt,
        h_pow_n: BigInt,
    ) -> Result<Self, Error> {
        let (nn, nn_ctx) = Self::check_modulus(&n, a_size)?;
        if h_pow_n.sign() == Sign::Minus || h_pow_n >= nn {
            return Err(Reason::InvalidKey.into());
        }
        Self::assemble(n_size, a_size, h, n, nn, h_pow_n, nn_ctx)
    }

    fn check_modulus(n: &BigInt, a_size: u32) -> Result<(BigInt, Montgomery), Error> {
        if a_size == 0 || n.sign() != Sign::Plus {
            return Err(Reason::InvalidKey.into());
        }
        let nn = n * n;
        // `None` if `n` is even or `n <= 1`
        let nn_ctx = Montgomery::new(nn.magnitude()).ok_or(Reason::InvalidKey)?;
        Ok((nn, nn_ctx))
    }

    fn assemble(
        n_size: u32,
        a_size: u32,
        h: BigInt,
        n: BigInt,
        nn: BigInt,
        h_pow_n: BigInt,
        nn_ctx: Montgomery,
    ) -> Result<Self, Error> {
        // `h_pow_n` must be a unit, so that every ciphertext is a unit and negative nonces work
        if !(&h_pow_n % &n).gcd(&n).is_one() {
            return Err(Reason::InvalidKey.into());
        }
        let half_n = &n >> 1u32;
        let neg_half_n = -half_n.clone();
        Ok(Self {
            n_size,
            a_size,
            nounce_size: a_size,
            h,
            n,
            nn,
            h_pow_n,
            half_n,
            neg_half_n,
            nn_ctx,
        })
    }

    /// Checks that `h_pow_n == h^n mod n²`
    ///
    /// Deserialization trusts the stored `h_pow_n`. Call this on every key received from another
    /// party: a forged `h_pow_n` (e.g. `1`) would make encryptions under the key non-hiding.
    /// Costs one `|n|`-bit exponentiation modulo `n²`.
    pub fn verify_h_pow_n(&self) -> bool {
        utils::pow_signed_mont(&self.nn_ctx, &self.h, &self.n)
            .is_some_and(|expected| expected == *self.h_pow_n.magnitude())
    }

    /// Returns `n_size`
    pub fn n_size(&self) -> u32 {
        self.n_size
    }

    /// Returns `a_size`
    pub fn a_size(&self) -> u32 {
        self.a_size
    }

    /// Returns `nounce_size`
    pub fn nounce_size(&self) -> u32 {
        self.nounce_size
    }

    /// Returns `h`
    pub fn h(&self) -> &BigInt {
        &self.h
    }

    /// Returns `N`
    pub fn n(&self) -> &BigInt {
        &self.n
    }

    /// Returns `N^2`
    pub fn nn(&self) -> &BigInt {
        &self.nn
    }

    /// Returns `h^N mod N^2`
    pub fn h_pow_n(&self) -> &BigInt {
        &self.h_pow_n
    }

    /// Returns `N/2`
    pub fn half_n(&self) -> &BigInt {
        &self.half_n
    }

    /// Returns `-N/2`
    pub fn neg_half_n(&self) -> &BigInt {
        &self.neg_half_n
    }
}

impl EncryptionKey {
    /// Checks whether `x` is `{-N/2, .., N/2}`
    pub fn in_signed_group(&self, x: &BigInt) -> bool {
        self.neg_half_n <= *x && *x <= self.half_n
    }

    /// Checks that `c` is a non-negative integer coprime with `N` (same as
    /// `utils::in_mult_group(c, nn)`, but the gcd runs on `|N|`-bit numbers)
    fn is_unit(&self, c: &BigInt) -> bool {
        c.sign() != Sign::Minus && (c % &self.n).gcd(&self.n).is_one()
    }

    /// `(1 + N)^x = 1 + x·N mod N²`
    pub(crate) fn g_pow(&self, x: &Plaintext) -> BigInt {
        (BigInt::one() + x * &self.n).mod_floor(&self.nn)
    }
}

impl EncryptionKey {
    /// Encrypts the plaintext `x` in `{-N/2, .., N_2}` with `nonce`, an arbitrary integer
    /// (negative nonces are allowed)
    ///
    /// Encrypt: Enc(x) = (1 + N)^x.(h^r mod N)^N mod N^2
    ///                 = (1 + x.N).(h^N mod N^2)^r mod N^2
    ///                 = (1 + x.N).h_pow_n^r mod N^2 (h_pow_n = h^N mod N^2)
    ///
    /// Returns error if `x` is not in the specified range
    pub fn encrypt_with(&self, x: &Plaintext, nonce: &Nonce) -> Result<Ciphertext, Error> {
        if !self.in_signed_group(x) {
            return Err(Reason::Encrypt.into());
        }
        let b =
            utils::pow_signed_mont(&self.nn_ctx, &self.h_pow_n, nonce).ok_or(Reason::Encrypt)?;
        Ok((self.g_pow(x) * BigInt::from(b)).mod_floor(&self.nn))
    }

    /// Encrypts the plaintext `x` in `{-N/2, .., N_2}`
    ///
    /// Nonce is sampled randomly using `rng`.
    ///
    /// Returns error if plaintext is not in specified range
    pub fn encrypt_with_random(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        x: &Plaintext,
    ) -> Result<(Ciphertext, Nonce), Error> {
        let nonce = utils::sample_with_size(rng, self.nounce_size());
        let ciphertext = self.encrypt_with(x, &nonce)?;
        Ok((ciphertext, nonce))
    }
}

impl EncryptionKey {
    /// Homomorphic addition of two ciphertexts
    ///
    /// ```text
    /// oadd(Enc(a1), Enc(a2)) = Enc(a1 + a2)
    /// ```
    pub fn oadd(&self, c1: &Ciphertext, c2: &Ciphertext) -> Result<Ciphertext, Error> {
        if !self.is_unit(c1) || !self.is_unit(c2) {
            return Err(Reason::Ops.into());
        }
        Ok((c1 * c2).mod_floor(self.nn()))
    }

    /// Homomorphic subtraction of two ciphertexts
    ///
    /// ```text
    /// osub(Enc(a1), Enc(a2)) = Enc(a1 - a2)
    /// ```
    pub fn osub(&self, c1: &Ciphertext, c2: &Ciphertext) -> Result<Ciphertext, Error> {
        if !self.is_unit(c1) {
            return Err(Reason::Ops.into());
        }
        let c2 = self.oneg(c2)?;
        Ok((c1 * c2).mod_floor(self.nn()))
    }

    /// Homomorphic multiplication of scalar at ciphertext
    ///
    /// ```text
    /// omul(a, Enc(c)) = Enc(a * c)
    /// ```
    ///
    /// Returns an error if `scalar` is not coprime with `N` (in particular for `scalar = 0`) or
    /// if `ciphertext` is not in `Z*_{N²}`.
    pub fn omul(&self, scalar: &BigInt, ciphertext: &Ciphertext) -> Result<Ciphertext, Error> {
        if !utils::in_mult_group_abs(scalar, self.n()) || !self.is_unit(ciphertext) {
            return Err(Reason::Ops.into());
        }
        utils::pow_signed_mont(&self.nn_ctx, ciphertext, scalar)
            .map(BigInt::from)
            .ok_or(Reason::Ops.into())
    }

    /// Homomorphic negation of a ciphertext
    ///
    /// ```text
    /// oneg(Enc(a)) = Enc(-a)
    /// ```
    pub fn oneg(&self, ciphertext: &Ciphertext) -> Result<Ciphertext, Error> {
        Ok(ciphertext.modinv(self.nn()).ok_or(Reason::Ops)?)
    }
}

impl EncryptionKey {
    /// Builds a [`PrecomputeTable`] for fast encryption under this key
    ///
    /// The table covers nonces of up to `nounce_size` bits. See [`PrecomputeTable`] for the
    /// memory/speed trade-off of `block_size`; [`PrecomputeTable::DEFAULT_BLOCK_SIZE`] is a good
    /// default.
    pub fn precompute_table(&self, block_size: usize) -> Result<PrecomputeTable, Error> {
        PrecomputeTable::new(
            self.h_pow_n.clone(),
            block_size,
            self.nounce_size as usize,
            self.nn.clone(),
        )
    }

    /// Encrypts the plaintext `m` in `{-N/2, .., N/2}` using a precomputed table of powers of
    /// `h_pow_n`
    ///
    /// If `nonce` is `None`, a fresh `nounce_size`-bit nonce is sampled from `rng`. The result is
    /// identical to [`encrypt_with`](Self::encrypt_with) with the same nonce.
    ///
    /// Returns an error if `m` is out of range, the nonce is negative or longer than the table's
    /// `pow_size`, or the table was not built for this key (`table[0][1] != h_pow_n` or
    /// `modulo != nn`).
    pub fn encrypt_with_precompute_table(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        precompute_table: &PrecomputeTable,
        m: &Plaintext,
        nonce: Option<&Nonce>,
    ) -> Result<Ciphertext, Error> {
        if !self.in_signed_group(m) {
            return Err(Reason::Encrypt.into());
        }
        if precompute_table.modulo() != &self.nn
            || precompute_table.table()[0].get(1) != Some(&self.h_pow_n)
        {
            return Err(Reason::PrecomputeTable.into());
        }
        let sampled;
        let r = match nonce {
            Some(nonce) => nonce,
            None => {
                sampled = utils::sample_with_size(rng, self.nounce_size());
                &sampled
            }
        };
        if r.sign() == Sign::Minus {
            return Err(Reason::Encrypt.into());
        }
        // h_pow_rn = (h^n)^r mod n^2
        let h_pow_rn: BigUint = precompute_table.pow(r.magnitude()).ok_or(Reason::Encrypt)?;
        Ok((self.g_pow(m) * BigInt::from(h_pow_rn)).mod_floor(&self.nn))
    }
}
