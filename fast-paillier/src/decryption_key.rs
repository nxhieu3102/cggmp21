use std::fmt;

use num_bigint::{BigInt, BigUint, Sign};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand_core::{CryptoRng, RngCore};

use crate::mont::Montgomery;
use crate::utils::{self, reduce};
use crate::{Ciphertext, EncryptionKey, Error, Nonce, Plaintext, Reason};

/// Paillier decryption key
///
/// Holds the factorization `n = p·q` and `alpha`, plus constants derived from them (Montgomery
/// contexts for `p²`, `q²` and CRT coefficients) that are rebuilt on construction and never
/// serialized. Decryption, [`encrypt_with`](Self::encrypt_with) and [`omul`](Self::omul) work
/// modulo `p²` and `q²` and recombine with the CRT.
#[derive(Clone)]
pub struct DecryptionKey {
    /// encryption key
    ek: EncryptionKey,

    /// prime (n = p * q)
    p: BigInt,
    /// prime (n = p * q)
    q: BigInt,

    /// (p-1)(q-1)/4 mod alpha = 0
    alpha: BigInt,

    crt: Crt,
}

/// Constants derived from `p`, `q`, `alpha`, `h_pow_n`
#[derive(Clone)]
struct Crt {
    p: BigUint,
    q: BigUint,
    /// Montgomery context for `p²`
    pp: Montgomery,
    /// Montgomery context for `q²`
    qq: Montgomery,
    /// `phi(p²) = p(p - 1)`
    phi_pp: BigUint,
    /// `phi(q²) = q(q - 1)`
    phi_qq: BigUint,
    /// `2·alpha`
    two_alpha: BigInt,
    /// `(2·alpha·q)^-1 mod p`
    dec_p: BigUint,
    /// `(2·alpha·p)^-1 mod q`
    dec_q: BigUint,
    /// `p^-1 mod q`
    p_inv_q: BigUint,
    /// `(p²)^-1 mod q²`
    pp_inv_qq: BigUint,
}

/// `h_pow_n mod p²`, `h_pow_n mod q²`
#[derive(Clone)]
struct HPowN {
    pp: BigUint,
    qq: BigUint,
}

impl Crt {
    fn new(p: &BigInt, q: &BigInt, alpha: &BigInt) -> Option<Self> {
        if p.sign() != Sign::Plus || q.sign() != Sign::Plus || alpha.sign() != Sign::Plus {
            return None;
        }
        let (p, q) = (p.magnitude(), q.magnitude());
        let pp = Montgomery::new(&(p * p))?;
        let qq = Montgomery::new(&(q * q))?;
        let two_alpha: BigUint = alpha.magnitude() << 1u8;
        let dec_p = ((&two_alpha * q) % p).modinv(p)?;
        let dec_q = ((&two_alpha * p) % q).modinv(q)?;
        let p_inv_q = (p % q).modinv(q)?;
        let pp_inv_qq = (pp.modulus() % qq.modulus()).modinv(qq.modulus())?;
        Some(Self {
            phi_pp: pp.modulus() - p,
            phi_qq: qq.modulus() - q,
            p: p.clone(),
            q: q.clone(),
            pp,
            qq,
            two_alpha: BigInt::from(two_alpha),
            dec_p,
            dec_q,
            p_inv_q,
            pp_inv_qq,
        })
    }

    /// Given `x mod p²` and `x mod q²`, returns `x mod n²`
    fn combine_nn(&self, x_pp: BigUint, x_qq: BigUint) -> BigInt {
        let (pp, qq) = (self.pp.modulus(), self.qq.modulus());
        // t = (x_qq - x_pp) · pp^-1 mod qq
        let diff = (x_qq + qq - (&x_pp % qq)) % qq;
        let t = (diff * &self.pp_inv_qq) % qq;
        BigInt::from(t * pp + x_pp)
    }

    /// `base^exp mod m` for a unit `base` modulo the prime square `m = ctx.modulus()` with
    /// `phi(m) = phi`. Large or negative exponents are reduced modulo `phi`; small negative ones
    /// invert the base instead.
    fn pow_unit(ctx: &Montgomery, phi: &BigUint, base: &BigInt, exp: &BigInt) -> Option<BigUint> {
        if exp.bits() > phi.bits() {
            let exp = reduce(exp, phi);
            Some(ctx.pow(&reduce(base, ctx.modulus()), &exp))
        } else {
            utils::pow_signed_mont(ctx, base, exp)
        }
    }
}

/// Progress of [`DecryptionKey::generate_with_progress`]. Carries no secret values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeygenProgress {
    /// The small safe-prime factor of `p - 1` (`which = 0`) or `q - 1` (`which = 1`) was found
    DivisorPrimeFound {
        /// `0` for `p`, `1` for `q`
        which: u8,
    },
    /// Emitted every 64 candidates while searching `p` (`which = 0`) or `q` (`which = 1`)
    CandidateTested {
        /// `0` for `p`, `1` for `q`
        which: u8,
        /// Candidates tested so far for this prime
        attempts: u64,
    },
    /// `p` (`which = 0`) or `q` (`which = 1`) was found
    PrimeFound {
        /// `0` for `p`, `1` for `q`
        which: u8,
        /// Number of candidates tested for this prime
        attempts: u64,
    },
}

impl DecryptionKey {
    /// Returns a (public) encryption key corresponding to the (secret) decryption key
    pub fn encryption_key(&self) -> &EncryptionKey {
        &self.ek
    }

    /// The Paillier modulus
    pub fn n(&self) -> &BigInt {
        self.ek.n()
    }

    /// Prime `p`
    pub fn p(&self) -> &BigInt {
        &self.p
    }
    /// Prime `q`
    pub fn q(&self) -> &BigInt {
        &self.q
    }

    /// alpha | (p - 1)(q - 1)/4
    pub fn alpha(&self) -> &BigInt {
        &self.alpha
    }

    /// Bits length of smaller prime (`p` or `q`)
    pub fn bits_length(&self) -> u32 {
        self.p.bits().min(self.q.bits()) as u32
    }
}

impl DecryptionKey {
    /// Generates a paillier key
    ///
    /// QR_N: set of all quadratic residues in Z*_N
    /// QR_N = {x^2 mod N | x in Z*_N}
    ///
    /// N = Q * P
    /// Then, QR_N is a cyclic group of order phi(N)/4 = (P -1)(Q - 1)/4
    ///
    /// If: alpha * beta = (P - 1)(Q - 1)/4
    /// QR_N = QR^alpha_N * QR^beta_N
    /// QR^alpha_N = {x^(2.alpha) mod N | x in Z*_N} of size beta
    /// QR^beta_N  = {x^(2.beta)  mod N | x in Z*_N} of size alpha
    ///
    /// Random space: G = QR^beta_N * <-1> of Z*_N, cyclic group of order 2.alpha
    /// h is a generator of G -> h^(2.alpha) = 1 mod N
    /// We can chose: h = -y^(2*beta) mod N, where y is a random element of Z*_N
    ///
    /// Construction:
    /// * `div_p`, `div_q`: distinct random safe primes of `a_size / 2` bits
    /// * `p = 2·div_p·other_div_p + 1`, `q = 2·div_q·other_div_q + 1` primes, where
    ///   `other_div_p`, `other_div_q` are odd integers of exactly `(n_size - a_size)/2 - 1` bits
    /// * `div_p`, `div_q`, `other_div_p`, `other_div_q` pairwise coprime
    ///
    /// Hence `p = q = 3 (mod 4)`, `gcd(p - 1, q - 1) = 2`, `gcd(alpha, beta) = 1` with
    /// `alpha = div_p·div_q`, `beta = other_div_p·other_div_q = (p - 1)(q - 1)/(4·alpha)`,
    /// and `n = p·q`, `h = -(y^(2·beta) mod n)`.
    ///
    /// `p` and `q` are searched independently: the cofactor is resampled until `p` is prime
    /// (trial division, then Miller–Rabin), then the same for `q`.
    ///
    /// Returns an error if `a_size / 2 < 8` or `(n_size - a_size)/2 - 1 < 16`: smaller
    /// parameters leave too few candidates for the search to be guaranteed to terminate.
    pub fn generate(
        rng: &mut (impl RngCore + CryptoRng),
        n_size: u32,
        a_size: u32,
    ) -> Result<Self, Error> {
        Self::generate_with_progress(rng, n_size, a_size, &mut |_| {})
    }

    /// Same as [`generate`](Self::generate), reporting progress through `progress`
    pub fn generate_with_progress(
        rng: &mut (impl RngCore + CryptoRng),
        n_size: u32,
        a_size: u32,
        progress: &mut dyn FnMut(KeygenProgress),
    ) -> Result<Self, Error> {
        let div_bits = a_size / 2;
        let other_bits = (n_size.checked_sub(a_size).ok_or(Reason::KeyGen)? / 2)
            .checked_sub(1)
            .ok_or(Reason::KeyGen)?;
        if div_bits < 8 || other_bits < 16 {
            return Err(Reason::KeyGen.into());
        }
        let other_bits = u64::from(other_bits);

        let div_p = utils::generate_safe_prime(rng, div_bits).into_parts().1;
        progress(KeygenProgress::DivisorPrimeFound { which: 0 });
        let div_q = loop {
            let div_q = utils::generate_safe_prime(rng, div_bits).into_parts().1;
            if div_q != div_p {
                break div_q;
            }
        };
        progress(KeygenProgress::DivisorPrimeFound { which: 1 });

        let coprime_with_divs = |k: &BigUint| !(k % &div_p).is_zero() && !(k % &div_q).is_zero();

        let mut attempts = 0;
        let (p, other_p) =
            utils::search_prime_with_cofactor(rng, &div_p, other_bits, coprime_with_divs, |a| {
                attempts = a;
                if a % 64 == 0 {
                    progress(KeygenProgress::CandidateTested {
                        which: 0,
                        attempts: a,
                    });
                }
            });
        progress(KeygenProgress::PrimeFound { which: 0, attempts });

        let mut attempts = 0;
        let (q, other_q) = utils::search_prime_with_cofactor(
            rng,
            &div_q,
            other_bits,
            |k| coprime_with_divs(k) && k.gcd(&other_p).is_one(),
            |a| {
                attempts = a;
                if a % 64 == 0 {
                    progress(KeygenProgress::CandidateTested {
                        which: 1,
                        attempts: a,
                    });
                }
            },
        );
        progress(KeygenProgress::PrimeFound { which: 1, attempts });

        let alpha = BigInt::from(&div_p * &div_q);
        let n = BigInt::from(&p * &q);
        let p = BigInt::from(p);
        let q = BigInt::from(q);
        let crt = Crt::new(&p, &q, &alpha).ok_or(Reason::KeyGen)?;

        // h = -(y^(2·beta) mod n), beta = other_p·other_q, y random in Z*_n
        let two_beta = BigInt::from((other_p * other_q) << 1u8);
        let y = utils::sample_in_mult_group(rng, &n);
        let h = -utils::pow_mod_signed(&y, &two_beta, &n).ok_or(Reason::KeyGen)?;

        // h_pow_n = h^n mod n² via CRT
        let h_pow_n = crt.combine_nn(
            crt.pp
                .pow(&reduce(&h, crt.pp.modulus()), &reduce(&n, &crt.phi_pp)),
            crt.qq
                .pow(&reduce(&h, crt.qq.modulus()), &reduce(&n, &crt.phi_qq)),
        );
        let ek = EncryptionKey::from_parts(n_size, a_size, h, n, h_pow_n)?;
        Self::from_crt(ek, p, q, alpha, crt)
    }

    /// Return a decryption key from the encryption key, p, q, alpha
    ///
    /// Checks that `p·q = n`, that `alpha > 0` and `2·alpha` is invertible modulo `n`, and that
    /// `h_pow_n^(2·alpha) = 1 (mod n²)` (i.e. that the nonce space has order dividing `2·alpha`,
    /// which decryption relies on). Primality of `p`, `q` is not checked.
    pub fn new(ek: EncryptionKey, p: BigInt, q: BigInt, alpha: BigInt) -> Result<Self, Error> {
        if &p * &q != *ek.n() {
            return Err(Reason::InvalidKey.into());
        }
        let crt = Crt::new(&p, &q, &alpha).ok_or(Reason::InvalidKey)?;
        Self::from_crt(ek, p, q, alpha, crt)
    }

    fn from_crt(
        ek: EncryptionKey,
        p: BigInt,
        q: BigInt,
        alpha: BigInt,
        crt: Crt,
    ) -> Result<Self, Error> {
        let h = HPowN {
            pp: reduce(ek.h_pow_n(), crt.pp.modulus()),
            qq: reduce(ek.h_pow_n(), crt.qq.modulus()),
        };
        let two_alpha = crt.two_alpha.magnitude();
        if !crt.pp.pow(&h.pp, two_alpha).is_one() || !crt.qq.pow(&h.qq, two_alpha).is_one() {
            return Err(Reason::InvalidKey.into());
        }
        Ok(Self {
            ek,
            p,
            q,
            alpha,
            crt,
        })
    }

    fn h_pow_n_residues(&self) -> HPowN {
        HPowN {
            pp: reduce(self.ek.h_pow_n(), self.crt.pp.modulus()),
            qq: reduce(self.ek.h_pow_n(), self.crt.qq.modulus()),
        }
    }
}

impl DecryptionKey {
    /// Decrypts the ciphertext, returns plaintext in `{-N/2, .., N_2}`
    ///
    /// plaintext = L(c^(2*alpha) mod N^2, N) * (2*alpha)^{-1} mod N
    /// where: L(u, N) = (u - 1) / N
    ///
    /// computed modulo `p²` and `q²`: `m = L_p(c^(2α) mod p²)·(2α·q)^-1 mod p` (same for `q`),
    /// then CRT. Returns an error if `c^(2α) ≠ 1 (mod n)`, i.e. if `c` is not an encryption
    /// under this key (this includes `c` not coprime with `n`).
    pub fn decrypt(&self, c: &Ciphertext) -> Result<Plaintext, Error> {
        let crt = &self.crt;
        let m_p = Self::decrypt_factor(&crt.pp, &crt.p, &crt.dec_p, &crt.two_alpha, c)?;
        let m_q = Self::decrypt_factor(&crt.qq, &crt.q, &crt.dec_q, &crt.two_alpha, c)?;
        // m = m_p + p·((m_q - m_p)·p^-1 mod q)
        let diff = (m_q + &crt.q - (&m_p % &crt.q)) % &crt.q;
        let m = BigInt::from((diff * &crt.p_inv_q) % &crt.q * &crt.p + m_p);
        if m > *self.ek.half_n() {
            Ok(m - self.ek.n())
        } else {
            Ok(m)
        }
    }

    /// `L_p(c^(2α) mod p²)·(2α·q)^-1 mod p`
    fn decrypt_factor(
        pp: &Montgomery,
        p: &BigUint,
        dec_p: &BigUint,
        two_alpha: &BigInt,
        c: &BigInt,
    ) -> Result<BigUint, Error> {
        let u = pp.pow(&reduce(c, pp.modulus()), two_alpha.magnitude());
        if u.is_zero() {
            return Err(Reason::Decrypt.into());
        }
        let (l, rem) = (u - 1u8).div_rem(p);
        if !rem.is_zero() {
            return Err(Reason::Decrypt.into());
        }
        Ok((l * dec_p) % p)
    }

    /// Encrypts a plaintext `x` in `{-N/2, .., N/2}` with `nonce` (any integer, negative allowed)
    ///
    /// It uses the factorization of `N`: the nonce is reduced modulo `2·alpha` (the order of
    /// `h_pow_n` divides it) and the exponentiation runs modulo `p²` and `q²`. The result is
    /// identical to [`EncryptionKey::encrypt_with`].
    ///
    /// Returns error if `x` is not in the specified range
    pub fn encrypt_with(&self, x: &Plaintext, nonce: &Nonce) -> Result<Ciphertext, Error> {
        if !self.ek.in_signed_group(x) {
            return Err(Reason::Encrypt.into());
        }
        let crt = &self.crt;
        let e = reduce(nonce, crt.two_alpha.magnitude());
        let h = self.h_pow_n_residues();
        let g = BigInt::one() + x * self.ek.n();
        let (pp, qq) = (crt.pp.modulus(), crt.qq.modulus());
        let c_pp = (reduce(&g, pp) * crt.pp.pow(&h.pp, &e)) % pp;
        let c_qq = (reduce(&g, qq) * crt.qq.pow(&h.qq, &e)) % qq;
        Ok(crt.combine_nn(c_pp, c_qq))
    }

    /// Encrypts the plaintext `x` in `{-N/2, .., N_2}`
    ///
    /// It's uses the fact that factorization of `N` is known to speed up encryption.
    ///
    /// Nonce is sampled randomly using `rng`.
    ///
    /// Returns error if plaintext is not in specified range
    pub fn encrypt_with_random(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        x: &Plaintext,
    ) -> Result<(Ciphertext, Nonce), Error> {
        let nonce = utils::sample_with_size(rng, self.ek.nounce_size());
        let ciphertext = self.encrypt_with(x, &nonce)?;
        Ok((ciphertext, nonce))
    }

    /// Homomorphic multiplication of scalar at ciphertext
    ///
    /// It uses the fact that factorization of `N` is known to speed up an operation. Accepts and
    /// rejects exactly the same inputs as [`EncryptionKey::omul`] and returns the same result.
    ///
    /// ```text
    /// omul(a, Enc(c)) = Enc(a * c)
    /// ```
    pub fn omul(&self, scalar: &BigInt, ciphertext: &Ciphertext) -> Result<Ciphertext, Error> {
        let crt = &self.crt;
        let is_unit = |x: &BigInt| !reduce(x, &crt.p).is_zero() && !reduce(x, &crt.q).is_zero();
        if !is_unit(scalar) || ciphertext.sign() == Sign::Minus || !is_unit(ciphertext) {
            return Err(Reason::Ops.into());
        }
        let c_pp = Crt::pow_unit(&crt.pp, &crt.phi_pp, ciphertext, scalar).ok_or(Reason::Ops)?;
        let c_qq = Crt::pow_unit(&crt.qq, &crt.phi_qq, ciphertext, scalar).ok_or(Reason::Ops)?;
        Ok(crt.combine_nn(c_pp, c_qq))
    }
}

impl fmt::Debug for DecryptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // never print the factorization
        f.debug_struct("DecryptionKey")
            .field("ek", &self.ek)
            .finish_non_exhaustive()
    }
}
