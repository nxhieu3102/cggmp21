pub mod sqrt;

use std::sync::Arc;

use fast_paillier::mont::Montgomery;
use generic_ec::Scalar;
use num_bigint::{BigInt, BigUint, RandBigInt, Sign};
use num_integer::Integer;
use num_traits::{One, Signed};

/// Auxiliary data known to both prover and verifier
#[cfg_attr(
    feature = "__internal_doctest",
    derive(serde::Serialize, serde::Deserialize)
)]
#[derive(Clone, Debug)]
pub struct Aux {
    /// ring-pedersen parameter
    #[cfg_attr(
        feature = "__internal_doctest",
        serde(with = "fast_paillier::utils::serde_wrapper::serializable_bigint")
    )]
    pub s: BigInt,
    /// ring-pedersen parameter
    #[cfg_attr(
        feature = "__internal_doctest",
        serde(with = "fast_paillier::utils::serde_wrapper::serializable_bigint")
    )]
    pub t: BigInt,
    /// N^ in paper
    #[cfg_attr(
        feature = "__internal_doctest",
        serde(with = "fast_paillier::utils::serde_wrapper::serializable_bigint")
    )]
    pub rsa_modulo: BigInt,
    /// Precomuted table for computing `s^x t^y mod rsa_modulo` faster
    ///
    /// If absent, optimization is disabled.
    #[cfg_attr(feature = "__internal_doctest", serde(skip))]
    pub multiexp: Option<Arc<crate::multiexp::MultiexpTable>>,
    /// Factorization of `rsa_modulo`, if known (i.e. when `Aux` belongs to the verifier).
    /// Speeds up all exponentiations modulo `rsa_modulo`.
    ///
    /// Must be built for `rsa_modulo`, e.g. via [`CrtExp::build_n`](fast_paillier::utils::CrtExp::build_n).
    #[cfg_attr(feature = "__internal_doctest", serde(skip))]
    pub crt: Option<fast_paillier::utils::CrtExp>,
}

impl Aux {
    /// Returns `s^x t^y mod rsa_modulo`
    pub fn combine(&self, x: &BigInt, y: &BigInt) -> Result<BigInt, BadExponent> {
        if let Some(res) = self
            .multiexp
            .as_ref()
            .and_then(|table| table.prod_exp(x, y))
        {
            return Ok(res);
        }
        // The table doesn't cover exponents of that size (or there's no table)
        self.multi_pow(&[(&self.s, x), (&self.t, y)])
    }

    /// Returns `x^e mod rsa_modulo`
    pub fn pow_mod(&self, x: &BigInt, e: &BigInt) -> Result<BigInt, BadExponent> {
        self.multi_pow(&[(x, e)])
    }

    /// Returns `prod_i base_i^exp_i mod rsa_modulo`. Exponents may be negative.
    ///
    /// Uses CRT if the factorization of `rsa_modulo` is known.
    pub fn multi_pow(&self, pairs: &[(&BigInt, &BigInt)]) -> Result<BigInt, BadExponent> {
        match &self.crt {
            Some(crt) => {
                let exps: Vec<_> = pairs.iter().map(|(_, e)| crt.prepare_exponent(e)).collect();
                let pairs: Vec<_> = pairs.iter().zip(&exps).map(|((b, _), e)| (*b, e)).collect();
                crt.multi_exp(&pairs)
            }
            None => multi_pow_signed(&self.rsa_modulo, pairs),
        }
        .ok_or_else(BadExponent::undefined)
    }

    /// Returns a stripped version of `Aux` that contains only public data which can be digested
    /// via [`udigest::Digestable`]
    pub fn digest_public_data(&self) -> impl udigest::Digestable + '_ {
        #[derive(udigest::Digestable)]
        #[udigest(tag = "paillier_zk.aux")]
        struct AuxDigest<'a> {
            #[udigest(as = &encoding::BigInt)]
            s: &'a BigInt,
            #[udigest(as = &encoding::BigInt)]
            t: &'a BigInt,
            #[udigest(as = &encoding::BigInt)]
            rsa_modulo: &'a BigInt,
        }
        AuxDigest {
            s: &self.s,
            t: &self.t,
            rsa_modulo: &self.rsa_modulo,
        }
    }
}

/// Error indicating that proof is invalid
#[derive(Debug, Clone, thiserror::Error)]
#[error("invalid proof")]
pub struct InvalidProof(
    #[source]
    #[from]
    InvalidProofReason,
);

/// Reason for failure. If the proof failes, you should only be interested in a
/// reason for debugging purposes
#[derive(Debug, PartialEq, Eq, Clone, Copy, thiserror::Error)]
pub enum InvalidProofReason {
    /// One equality doesn't hold. Parameterized by equality index
    #[error("equality check failed {0}")]
    EqualityCheck(usize),
    /// One range check doesn't hold. Parameterized by check index
    #[error("range check failed {0}")]
    RangeCheck(usize),
    /// Encryption of supplied data failed when attempting to verify
    #[error("encryption failed")]
    Encryption,
    /// Paillier encryption of the proof's response failed
    #[error("paillier encryption failed")]
    PaillierEnc,
    /// Paillier homomorphic operation on the statement or commitment failed
    #[error("paillier homomorphic op failed")]
    PaillierOp,
    /// Failed to evaluate powmod
    #[error("powmod failed")]
    ModPow,
    /// Paillier-Blum modulus is prime
    #[error("modulus is prime")]
    ModulusIsPrime,
    /// Paillier-Blum modulus is even
    #[error("modulus is even")]
    ModulusIsEven,
    /// Proof's z value in n-th power does not equal commitment value
    #[error("incorrect nth root")]
    IncorrectNthRoot,
    /// Proof's x value in 4-th power does not equal commitment value
    #[error("incorrect 4th root")]
    IncorrectFourthRoot,
    /// Statement, commitment or proof has wrong number of elements
    #[error("unexpected number of elements")]
    Length,
    /// Paillier-Blum modulus is less than 2
    #[error("modulus is too small")]
    ModulusTooSmall,
}

impl InvalidProof {
    #[cfg(test)]
    pub(crate) fn reason(&self) -> InvalidProofReason {
        self.0
    }
}

impl From<BadExponent> for InvalidProof {
    fn from(_err: BadExponent) -> Self {
        InvalidProofReason::ModPow.into()
    }
}

impl From<PaillierError> for InvalidProof {
    fn from(_err: PaillierError) -> Self {
        InvalidProof(InvalidProofReason::Encryption)
    }
}

/// Error indicating that encryption failed
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("paillier encryption failed")]
pub struct PaillierError;

/// Big integer operations used by the proofs
pub trait BigIntExt: Sized {
    /// Generate element in Zm*. Does so by trial.
    fn gen_invertible<R: rand_core::RngCore>(modulo: &Self, rng: &mut R) -> Self;

    /// Compute `l^le * r^re` modulo self. Exponents may be negative.
    fn combine(&self, l: &Self, le: &Self, r: &Self, re: &Self) -> Result<Self, BadExponent>;

    /// Embed BigInt into chosen scalar type
    fn to_scalar<C: generic_ec::Curve>(&self) -> Scalar<C>;

    /// Returns prime order of curve C
    fn curve_order<C: generic_ec::Curve>() -> Self;

    /// Generates a random integer in interval `[-range; range]`
    fn from_rng_pm<R: rand_core::RngCore>(range: &Self, rng: &mut R) -> Self;

    /// Checks whether `self` is in interval `[-range; range]`
    fn is_in_pm(&self, range: &Self) -> bool;

    /// Returns `self smod n`
    ///
    /// For odd `n`, result is in `{-n/2, .., n/2}`. For even `n`, result is in
    /// `{-n/2, .., n/2 - 1}`
    fn signed_modulo(&self, n: &Self) -> Self;

    /// Returns `self` as a tuple of `(sign, digits)`
    fn to_bytes_be(&self) -> (Sign, Vec<u8>);

    /// Returns `self ^ exp mod modulo`. Negative exponent requires `self` to be invertible.
    ///
    /// Returns `None` if `modulo <= 0` or the inverse doesn't exist.
    fn modpow_ext(&self, exp: &Self, modulo: &Self) -> Option<Self>;
}

impl BigIntExt for BigInt {
    fn gen_invertible<R: rand_core::RngCore>(modulo: &BigInt, rng: &mut R) -> Self {
        fast_paillier::utils::sample_in_mult_group(rng, modulo)
    }

    fn combine(&self, l: &Self, le: &Self, r: &Self, re: &Self) -> Result<Self, BadExponent> {
        multi_pow_signed(self, &[(l, le), (r, re)]).ok_or_else(BadExponent::undefined)
    }

    fn to_scalar<C: generic_ec::Curve>(&self) -> Scalar<C> {
        let s = Scalar::<C>::from_be_bytes_mod_order(self.magnitude().to_bytes_be());
        if self.is_negative() {
            -s
        } else {
            s
        }
    }

    fn curve_order<C: generic_ec::Curve>() -> Self {
        let order_minus_one = -Scalar::<C>::one();
        let bytes_be = order_minus_one.to_be_bytes();
        BigInt::from_bytes_be(Sign::Plus, &bytes_be) + 1
    }

    fn from_rng_pm<R: rand_core::RngCore>(range: &Self, rng: &mut R) -> Self {
        let upper = range + 1u8;
        rng.gen_bigint_range(&-range, &upper)
    }

    fn is_in_pm(&self, range: &Self) -> bool {
        !range.is_negative() && self.magnitude() <= range.magnitude()
    }

    fn signed_modulo(&self, n: &Self) -> Self {
        let self_mod_n = self.mod_floor(n);
        let half_n = n >> 1_u32;
        if half_n.is_odd() && self_mod_n <= half_n || self_mod_n < half_n {
            self_mod_n
        } else {
            self_mod_n - n
        }
    }

    fn to_bytes_be(&self) -> (Sign, Vec<u8>) {
        BigInt::to_bytes_be(self)
    }

    fn modpow_ext(&self, exp: &Self, modulo: &Self) -> Option<Self> {
        fast_paillier::utils::pow_mod_signed(self, exp, modulo)
    }
}

/// Computes `prod_i base_i^exp_i mod m` by simultaneous exponentiation
///
/// Exponents may be negative: such a base is inverted once. Returns `None` if `m <= 1` or a
/// required inverse doesn't exist.
pub fn multi_pow_signed(m: &BigInt, pairs: &[(&BigInt, &BigInt)]) -> Option<BigInt> {
    if *m <= BigInt::one() {
        return None;
    }
    let Some(ctx) = Montgomery::new(m.magnitude()) else {
        // Even modulus: not used by any proof, kept for completeness of `BigIntExt::combine`
        return pairs.iter().try_fold(BigInt::one(), |acc, (b, e)| {
            Some((acc * fast_paillier::utils::pow_mod_signed(b, e, m)?).mod_floor(m))
        });
    };
    let bases = pairs
        .iter()
        .map(|(b, e)| {
            let b = if e.is_negative() {
                b.modinv(m)?
            } else {
                b.mod_floor(m)
            };
            Some(b.into_parts().1)
        })
        .collect::<Option<Vec<BigUint>>>()?;
    let pairs: Vec<(&BigUint, &BigUint)> = bases
        .iter()
        .zip(pairs)
        .map(|(b, (_, e))| (b, e.magnitude()))
        .collect();
    Some(BigInt::from(ctx.multi_pow(&pairs)))
}

/// Error indicating that computation cannot be evaluated because of bad exponent
///
/// Returned by [`BigIntExt::modpow_ext`]-based functions that do exponentiation internally
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("exponent is undefined")]
pub struct BadExponent(());

impl BadExponent {
    /// Constructs an error that exponent is undefined
    pub fn undefined() -> Self {
        Self(())
    }
}

/// Returns `Err(err)` if `assertion` is false
pub fn fail_if<E>(err: E, assertion: bool) -> Result<(), E> {
    if assertion {
        Ok(())
    } else {
        Err(err)
    }
}

/// Returns `Err(err)` if `lhs != rhs`
pub fn fail_if_ne<T: PartialEq, E>(err: E, lhs: T, rhs: T) -> Result<(), E> {
    if lhs == rhs {
        Ok(())
    } else {
        Err(err)
    }
}

/// Canonical encodings of big integers and keys for Fiat-Shamir transcripts ([`udigest`])
///
/// Every proof of this crate digests integers via [`encoding::BigInt`](BigInt), so the
/// transcript is injective: an integer is encoded as a sign byte (`0` for zero, `1` for
/// positive, `2` for negative) followed by the big-endian magnitude without leading zeroes
/// (zero has an empty magnitude).
pub mod encoding {
    use num_bigint::Sign;

    /// Digests a big integer (sign-aware, canonical)
    pub struct BigInt;
    impl udigest::DigestAs<num_bigint::BigInt> for BigInt {
        fn digest_as<B: udigest::Buffer>(
            value: &num_bigint::BigInt,
            encoder: udigest::encoding::EncodeValue<B>,
        ) {
            let sign: u8 = match value.sign() {
                Sign::NoSign => 0,
                Sign::Plus => 1,
                Sign::Minus => 2,
            };
            let leaf = encoder.encode_leaf().chain([sign]);
            if value.sign() == Sign::NoSign {
                leaf.finish()
            } else {
                leaf.chain(value.magnitude().to_bytes_be()).finish()
            }
        }
    }

    /// Digests any encryption key: its public modulus `N` and nonce generator `h`
    pub struct AnyEncryptionKey;
    impl udigest::DigestAs<&dyn fast_paillier::AnyEncryptionKey> for AnyEncryptionKey {
        fn digest_as<B: udigest::Buffer>(
            value: &&dyn fast_paillier::AnyEncryptionKey,
            encoder: udigest::encoding::EncodeValue<B>,
        ) {
            let mut s = encoder.encode_struct();
            BigInt::digest_as(value.n(), s.add_field("n"));
            BigInt::digest_as(value.h(), s.add_field("h"));
            s.finish()
        }
    }
}

/// A common logic shared across tests
#[cfg(test)]
pub mod test {
    use super::BigIntExt;
    use num_bigint::BigInt;
    use num_bigint::RandBigInt;
    use num_integer::Integer;
    use num_traits::Num;

    fn hex(v: &serde_json::Value) -> BigInt {
        BigInt::from_str_radix(v.as_str().unwrap(), 16).unwrap()
    }

    fn encryption_key(v: &serde_json::Value) -> fast_paillier::EncryptionKey {
        fast_paillier::EncryptionKey::new(
            v["n_size"].as_u64().unwrap().try_into().unwrap(),
            v["a_size"].as_u64().unwrap().try_into().unwrap(),
            hex(&v["h"]),
            hex(&v["n"]),
        )
        .unwrap()
    }

    /// 3072-bit decryption key (`test-data/prover_decryption_key.json`)
    pub fn sample_key() -> fast_paillier::DecryptionKey {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../test-data/prover_decryption_key.json")).unwrap();
        fast_paillier::DecryptionKey::new(
            encryption_key(&v["ek"]),
            hex(&v["p"]),
            hex(&v["q"]),
            hex(&v["alpha"]),
        )
        .unwrap()
    }

    /// 3072-bit encryption key of someone else (`test-data/someone_encryption_key0.json`)
    pub fn sample_other_key() -> fast_paillier::EncryptionKey {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../test-data/someone_encryption_key0.json"))
                .unwrap();
        encryption_key(&v)
    }

    /// Hardcoded Blum primes, generating primes is slow
    fn aux_primes() -> (BigInt, BigInt) {
        let p = BigInt::from_str_radix("119718298173119878105125282170952301903604788836137192672971085086931697454850578932741977173627414449815867352984108049440807338548948797578442102781940057113712352026131358062988204403634623787863403524694314770165787749649165099519120341381625516324331282224170802953909133093459522735120382898061575755427", 10).unwrap();
        let q = BigInt::from_str_radix("90684028399912762319968138686204104120379010978734483157509623196436980870215927551569968173582391210838773744285614231471344350473494545770380636071402624403290484788376380599113518289534999987953418185019079958140799840748557330172676687793563591522131283238279656530154885714292887606570952169867532646327", 10).unwrap();
        (p, q)
    }

    /// Ring-Pedersen parameters of a verifier (without CRT and multiexp tables)
    pub fn aux<R: rand_core::RngCore>(rng: &mut R) -> super::Aux {
        let (p, q) = aux_primes();
        let n = &p * &q;

        let (s, t) = {
            let phi_n = (&p - 1u8) * (&q - 1u8);
            let r = BigInt::gen_invertible(&n, rng);
            let lambda = rng.gen_bigint_range(&BigInt::ZERO, &phi_n);

            let t = (&r * &r).mod_floor(&n);
            let s = t.modpow(&lambda, &n);

            (s, t)
        };

        super::Aux {
            s,
            t,
            rsa_modulo: n,
            multiexp: None,
            crt: None,
        }
    }

    /// Same `aux` with all optimizations enabled: CRT and multiexp table
    pub fn with_optimizations(aux: &super::Aux) -> super::Aux {
        let (p, q) = aux_primes();
        let table = crate::multiexp::MultiexpTable::build(
            &aux.s,
            &aux.t,
            1100,
            1100 + 2048,
            aux.rsa_modulo.clone(),
        )
        .unwrap();
        super::Aux {
            multiexp: Some(std::sync::Arc::new(table)),
            crt: Some(fast_paillier::utils::CrtExp::build_n(&p, &q).unwrap()),
            ..aux.clone()
        }
    }

    pub fn generate_blum_prime(rng: &mut impl rand_core::RngCore, bits_size: u32) -> BigInt {
        loop {
            let n = fast_paillier::utils::generate_safe_prime(rng, bits_size);
            if &n % 4 == BigInt::from(3) {
                break n;
            }
        }
    }
}

#[cfg(test)]
mod _test {
    use num_bigint::{BigInt, RandBigInt};
    use num_integer::Integer;
    use num_traits::Signed;

    use super::{multi_pow_signed, BigIntExt};

    #[test]
    fn multi_pow_matches_reference() {
        let mut rng = rand_dev::DevRng::new();
        for bits in [64u64, 1024, 2048] {
            let m = rng.gen_bigint(bits).abs() | BigInt::from(1);
            let b1 = BigInt::gen_invertible(&m, &mut rng);
            let b2 = -BigInt::gen_invertible(&m, &mut rng);
            let e1 = rng.gen_bigint(bits + 100);
            let e2 = rng.gen_bigint(bits / 2);
            let reference = |b: &BigInt, e: &BigInt| {
                if e.sign() == num_bigint::Sign::Minus {
                    b.modinv(&m).unwrap().modpow(&-e, &m)
                } else {
                    b.modpow(e, &m)
                }
            };
            let expected = (reference(&b1, &e1) * reference(&b2, &e2)).mod_floor(&m);
            assert_eq!(
                multi_pow_signed(&m, &[(&b1, &e1), (&b2, &e2)]),
                Some(expected.clone())
            );
            assert_eq!(m.combine(&b1, &e1, &b2, &e2).unwrap(), expected);
        }
        // non-invertible base with negative exponent
        let m = BigInt::from(15);
        assert_eq!(
            multi_pow_signed(&m, &[(&BigInt::from(5), &BigInt::from(-1))]),
            None
        );
        assert_eq!(multi_pow_signed(&BigInt::from(1), &[]), None);
        assert_eq!(multi_pow_signed(&BigInt::from(-7), &[]), None);
    }

    #[test]
    fn aux_crt_and_table_agree_with_plain() {
        let mut rng = rand_dev::DevRng::new();
        let plain = super::test::aux(&mut rng);
        let fast = super::test::with_optimizations(&plain);
        for (xb, yb) in [(10u64, 10u64), (1000, 3000), (2000, 4000)] {
            for _ in 0..3 {
                let x = rng.gen_bigint(xb);
                let y = rng.gen_bigint(yb);
                assert_eq!(
                    plain.combine(&x, &y).unwrap(),
                    fast.combine(&x, &y).unwrap()
                );
                assert_eq!(
                    plain.pow_mod(&plain.s, &y).unwrap(),
                    fast.pow_mod(&plain.s, &y).unwrap()
                );
            }
        }
        assert!(plain.pow_mod(&BigInt::from(0), &BigInt::from(-1)).is_err());
        assert!(fast.pow_mod(&BigInt::from(0), &BigInt::from(-1)).is_err());
    }

    #[test]
    fn digest_encoding_is_injective() {
        let digest = |x: i64| {
            #[derive(udigest::Digestable)]
            struct W(#[udigest(as = super::encoding::BigInt)] BigInt);
            udigest::hash::<sha2::Sha256>(&W(BigInt::from(x)))
        };
        let values = [0i64, 1, -1, 255, -255, 256, 65535];
        for (i, a) in values.iter().enumerate() {
            for b in &values[i + 1..] {
                assert_ne!(digest(*a), digest(*b), "{a} vs {b}");
            }
        }
    }

    #[test]
    fn range_helpers() {
        let r = BigInt::from(10);
        assert!(BigInt::from(10).is_in_pm(&r));
        assert!(BigInt::from(-10).is_in_pm(&r));
        assert!(!BigInt::from(11).is_in_pm(&r));
        assert!(!BigInt::from(-11).is_in_pm(&r));
        assert!(!BigInt::from(0).is_in_pm(&BigInt::from(-1)));
        let mut rng = rand_dev::DevRng::new();
        let mut seen = [false; 3];
        for _ in 0..200 {
            let x = BigInt::from_rng_pm(&BigInt::from(1), &mut rng);
            assert!(x.is_in_pm(&BigInt::from(1)));
            seen[usize::try_from(x + 1).unwrap()] = true;
        }
        assert_eq!(seen, [true; 3]);
    }
}
