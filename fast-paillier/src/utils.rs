//! Various utilities: sampling, primality testing, safe-prime generation, signed modular
//! exponentiation and CRT-accelerated exponentiation.

/// Serde adapters for big integers
#[cfg(feature = "serde")]
pub mod serde_wrapper;
mod small_primes;

#[cfg(feature = "serde")]
pub use serde_wrapper::*;

use std::fmt;

use num_bigint::{BigInt, BigUint, RandBigInt, Sign};
use num_integer::Integer;
use num_traits::{One, ToPrimitive, Zero};
use rand_core::RngCore;

use crate::mont::{self, Montgomery};
use small_primes::SMALL_PRIMES;

/// Checks that `x` is in Z*_n
#[inline(always)]
pub fn in_mult_group(x: &BigInt, n: &BigInt) -> bool {
    x.sign() != Sign::Minus && in_mult_group_abs(x, n)
}

/// Checks that `abs(x)` is in Z*_n
#[inline(always)]
pub fn in_mult_group_abs(x: &BigInt, n: &BigInt) -> bool {
    x.gcd(n).is_one()
}

/// Samples `x` uniformly from Z*_n
///
/// # Panics
/// Panics if `n <= 0`.
pub fn sample_in_mult_group(rng: &mut impl RngCore, n: &BigInt) -> BigInt {
    loop {
        let x = rng.gen_bigint_range(&BigInt::ZERO, n);
        if in_mult_group(&x, n) {
            return x;
        }
    }
}

/// Samples a uniform non-negative integer of exactly `bits` bits (the top bit is always set)
///
/// # Panics
/// Panics if `bits == 0`.
pub fn sample_with_size(rng: &mut impl RngCore, bits: u32) -> BigInt {
    BigInt::from(sample_uint_with_size(rng, bits.into()))
}

/// Samples an odd integer of exactly `bits` bits
///
/// # Panics
/// Panics if `bits == 0`.
pub fn sample_odd_with_size(rng: &mut impl RngCore, bits: u32) -> BigInt {
    let mut x = sample_uint_with_size(rng, bits.into());
    x.set_bit(0, true);
    BigInt::from(x)
}

fn sample_uint_with_size(rng: &mut impl RngCore, bits: u64) -> BigUint {
    assert!(bits > 0, "bit size must be positive");
    let mut x = rng.gen_biguint(bits);
    x.set_bit(bits - 1, true);
    x
}

/// Computes `base^exp mod m` for signed operands
///
/// * a negative `base` is reduced with `mod_floor`, i.e. the result is the same as for
///   `base.mod_floor(m)`
/// * a negative `exp` means exponentiation of the modular inverse of `base`
///
/// Returns `None` if `m <= 0`, or if `exp < 0` and `base` is not invertible modulo `m`.
/// The result is always in `[0, m)`.
///
/// This is the single signed modular exponentiation used across the stack. It runs on top of
/// [`crate::mont`]: odd moduli take the regular (constant-time table selection) Montgomery
/// ladder, which makes it suitable for secret exponents.
pub fn pow_mod_signed(base: &BigInt, exp: &BigInt, m: &BigInt) -> Option<BigInt> {
    if m.sign() != Sign::Plus {
        return None;
    }
    let m = m.magnitude();
    if m.is_one() {
        return Some(BigInt::ZERO);
    }
    let base = reduce(base, m);
    let base = if exp.sign() == Sign::Minus {
        base.modinv(m)?
    } else {
        base
    };
    mont::pow_mod(&base, exp.magnitude(), m).map(BigInt::from)
}

/// Same as [`pow_mod_signed`] but with a cached Montgomery context. The result is in
/// `[0, ctx.modulus())`.
pub(crate) fn pow_signed_mont(ctx: &Montgomery, base: &BigInt, exp: &BigInt) -> Option<BigUint> {
    let m = ctx.modulus();
    let base = reduce(base, m);
    if exp.sign() == Sign::Minus {
        Some(ctx.pow(&base.modinv(m)?, exp.magnitude()))
    } else {
        Some(ctx.pow(&base, exp.magnitude()))
    }
}

/// `x mod m` in `[0, m)` (floor semantics for negative `x`). `m` must be non-zero.
pub(crate) fn reduce(x: &BigInt, m: &BigUint) -> BigUint {
    let r = x.magnitude() % m;
    if x.sign() == Sign::Minus && !r.is_zero() {
        m - r
    } else {
        r
    }
}

/// Checks whether `x` is a prime
///
/// Returns `false` for `x < 2` (including negative numbers); never panics.
///
/// The test is: exact trial division for `x < 1223²`; otherwise trial division by the first 200
/// primes, a Miller–Rabin round to base 2, and further Miller–Rabin rounds with bases derived
/// deterministically from `x`. The total number of rounds follows FIPS 186-5 Table B.1 (4 rounds
/// for ≥1536-bit numbers, 5 for ≥1024 bits, 44 below that), which bounds the error probability
/// for *random* candidates by 2^-112 or better. All randomness used by the library comes from the
/// caller's RNG; no hidden RNG is used here.
///
/// For adversarially chosen inputs the deterministic bases give no worst-case guarantee beyond
/// the generic bound of 4^-rounds per composite. This is acceptable for how the stack uses
/// `is_prime` on peer data: it only checks that a peer's modulus `N` is *not* prime, so a false
/// "prime" verdict makes the verifier reject an honest-looking proof, never accept a bad one.
pub fn is_prime(x: &BigInt) -> bool {
    match x.sign() {
        Sign::Plus => is_prime_uint(x.magnitude()),
        Sign::Minus | Sign::NoSign => false,
    }
}

fn is_prime_uint(x: &BigUint) -> bool {
    match trial_division(x, SMALL_PRIMES.len()) {
        TrialDivision::Prime => true,
        TrialDivision::Composite => false,
        TrialDivision::Unknown => passes_miller_rabin(x),
    }
}

enum TrialDivision {
    /// `x` is proven prime
    Prime,
    /// `x` is proven composite (or `< 2`)
    Composite,
    /// `x` has no factor among the tested small primes, and it's too big to conclude primality
    Unknown,
}

/// Trial division of `x` by the first `amount` primes. `x < (largest tested prime)^2` gets an
/// exact verdict.
fn trial_division(x: &BigUint, amount: usize) -> TrialDivision {
    let primes = &SMALL_PRIMES[..amount.clamp(1, SMALL_PRIMES.len())];
    #[allow(clippy::expect_used)]
    let largest = u64::from(*primes.last().expect("non-empty"));
    if let Some(small) = x.to_u64() {
        if small < 2 {
            return TrialDivision::Composite;
        }
        for &r in primes {
            let r = u64::from(r);
            if r * r > small {
                return TrialDivision::Prime;
            }
            if small % r == 0 {
                return TrialDivision::Composite;
            }
        }
        if small < largest * largest {
            return TrialDivision::Prime;
        }
    }
    // Here `x > largest`, so any small prime factor makes it composite
    let mut composite = false;
    for_each_small_residue(x, primes, |_, residue| {
        composite |= residue == 0;
    });
    if composite {
        TrialDivision::Composite
    } else {
        TrialDivision::Unknown
    }
}

/// Calls `f(prime, x mod prime)` for every prime in `primes`, computing the residues with one
/// single-limb division per group of primes whose product fits in `u32`.
fn for_each_small_residue(x: &BigUint, primes: &[u32], mut f: impl FnMut(u32, u32)) {
    let mut start = 0;
    while start < primes.len() {
        let mut product = u64::from(primes[start]);
        let mut end = start + 1;
        while end < primes.len() && product * u64::from(primes[end]) <= u64::from(u32::MAX) {
            product *= u64::from(primes[end]);
            end += 1;
        }
        // `product <= u32::MAX` by construction
        let rem = (x % product as u32).to_u32().unwrap_or(0);
        for &r in &primes[start..end] {
            f(r, rem % r);
        }
        start = end;
    }
}

/// Number of Miller–Rabin rounds for a random candidate of `bits` bits (FIPS 186-5, Table B.1)
fn miller_rabin_rounds(bits: u64) -> usize {
    if bits >= 1536 {
        4
    } else if bits >= 1024 {
        5
    } else {
        44
    }
}

/// Miller–Rabin test of an odd `x > 1223²`: base 2 first, then deterministic pseudo-random bases
fn passes_miller_rabin(x: &BigUint) -> bool {
    let Some(mr) = MillerRabin::new(x) else {
        return false;
    };
    if !mr.round(&BigUint::from(2u8)) {
        return false;
    }
    let rounds = miller_rabin_rounds(x.bits());
    let mut bases = DerivedBases::new(x);
    (1..rounds).all(|_| mr.round(&bases.next_base(x)))
}

struct MillerRabin<'a> {
    ctx: Montgomery,
    x: &'a BigUint,
    x_minus_1: BigUint,
    d: BigUint,
    s: u64,
}

impl<'a> MillerRabin<'a> {
    /// `x` must be odd and > 3
    fn new(x: &'a BigUint) -> Option<Self> {
        let ctx = Montgomery::new(x)?;
        let x_minus_1 = x - 1u8;
        let s = x_minus_1.trailing_zeros()?;
        let d = &x_minus_1 >> s;
        Some(Self {
            ctx,
            x,
            x_minus_1,
            d,
            s,
        })
    }

    /// One round with `base` in `[2, x - 2]`. Returns `false` if `base` witnesses compositeness.
    fn round(&self, base: &BigUint) -> bool {
        let mut y = self.ctx.pow(base, &self.d);
        if y.is_one() || y == self.x_minus_1 {
            return true;
        }
        for _ in 1..self.s {
            y = (&y * &y) % self.x;
            if y == self.x_minus_1 {
                return true;
            }
            if y.is_one() {
                return false;
            }
        }
        false
    }
}

/// Deterministic Miller–Rabin bases in `[2, x - 2]` derived from `x` (SplitMix64 seeded with a
/// fold of the limbs of `x`)
struct DerivedBases {
    state: u64,
}

impl DerivedBases {
    fn new(x: &BigUint) -> Self {
        let state = x.iter_u64_digits().fold(x.bits(), |acc, limb| {
            (acc ^ limb)
                .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                .rotate_left(29)
        });
        Self { state }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// `x > 4` required
    fn next_base(&mut self, x: &BigUint) -> BigUint {
        let limbs = x.bits().div_ceil(64) + 1;
        let digits = (0..limbs)
            .flat_map(|_| {
                let v = self.next_u64();
                [v as u32, (v >> 32) as u32]
            })
            .collect();
        BigUint::new(digits) % (x - 3u8) + 2u8
    }
}

/// Validate each pair of elements in vector is coprime
pub fn check_coprime(v: &[&BigInt]) -> bool {
    for i in 0..v.len() {
        for j in (i + 1)..v.len() {
            if !v[i].gcd(v[j]).is_one() {
                return false;
            }
        }
    }
    true
}

/// Generates a random safe prime `p = 2q + 1` (`q` prime) of exactly `bits` bits
///
/// # Panics
/// Panics if `bits < 3` (there are no smaller safe primes).
pub fn generate_safe_prime(rng: &mut impl RngCore, bits: u32) -> BigInt {
    sieve_generate_safe_primes(rng, bits, 135)
}

/// Generates a random safe prime of exactly `bits` bits, sieving candidates with the first
/// `amount` primes (clamped to the built-in table of 200 primes) before running Miller–Rabin.
///
/// # Panics
/// Panics if `bits < 3` (there are no smaller safe primes).
pub fn sieve_generate_safe_primes(rng: &mut impl RngCore, bits: u32, amount: usize) -> BigInt {
    assert!(bits >= 3, "there are no safe primes of less than 3 bits");
    let bits = u64::from(bits);
    // skip 2: candidates are odd
    let sieve = &SMALL_PRIMES[1..amount.clamp(2, SMALL_PRIMES.len())];
    #[allow(clippy::expect_used)]
    let largest = u64::from(*sieve.last().expect("non-empty"));
    'candidate: loop {
        // q has `bits - 1` bits and is odd; p = 2q + 1 has `bits` bits
        let mut q = sample_uint_with_size(rng, bits - 1);
        q.set_bit(0, true);

        if q > BigUint::from(largest) {
            // reject q ≡ 0 (q composite) and q ≡ (r-1)/2 (r | 2q + 1)
            let mut reject = false;
            for_each_small_residue(&q, sieve, |r, residue| {
                reject |= residue == 0 || residue == (r - 1) / 2;
            });
            if reject {
                continue 'candidate;
            }
        }

        let p: BigUint = (&q << 1u8) + 1u8;
        if is_prime_uint(&q) && is_prime_uint(&p) {
            return BigInt::from(p);
        }
    }
}

/// Searches a prime `p = 2·div·k + 1` where `k` is a random odd integer of exactly `k_bits` bits
/// accepted by `accept_k`. Returns `(p, k)`.
///
/// Every candidate is a fresh sample. Candidates are sieved by trial division before
/// Miller–Rabin. `on_candidate` is called with the number of candidates tried so far.
pub(crate) fn search_prime_with_cofactor(
    rng: &mut impl RngCore,
    div: &BigUint,
    k_bits: u64,
    mut accept_k: impl FnMut(&BigUint) -> bool,
    mut on_candidate: impl FnMut(u64),
) -> (BigUint, BigUint) {
    let two_div: BigUint = div << 1u8;
    let mut attempts = 0u64;
    loop {
        attempts += 1;
        on_candidate(attempts);
        let mut k = sample_uint_with_size(rng, k_bits);
        k.set_bit(0, true);
        let p = &two_div * &k + 1u8;
        let verdict = trial_division(&p, SMALL_PRIMES.len());
        if matches!(verdict, TrialDivision::Composite) || !accept_k(&k) {
            continue;
        }
        if matches!(verdict, TrialDivision::Unknown) && !passes_miller_rabin(&p) {
            continue;
        }
        return (p, k);
    }
}

/// Faster algorithm for modular exponentiation based on Chinese remainder theorem when modulo factorization is known
///
/// `CrtExp` makes exponentation modulo `n` faster when factorization `n = n1 * n2` is known as well as `phi(n1)` and `phi(n2)`
/// (note that `n1` and `n2` don't need to be primes). In this case, you can [build](Self::build) a `CrtExp` and use provided
/// [exponentiation algorithm](Self::exp).
///
/// Serialization stores `n, n1, phi_n1, n2, phi_n2, beta`; deserialization rebuilds the
/// structure from `n1, phi_n1, n2, phi_n2` and rejects inconsistent `n` / `beta`.
#[derive(Clone)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(try_from = "CrtExpRepr", into = "CrtExpRepr")
)]
pub struct CrtExp {
    n1: BigInt,
    phi_n1: BigInt,
    n2: BigInt,
    phi_n2: BigInt,
    /// `n1^-1 mod n2`
    beta: BigInt,
    ctx1: Option<Montgomery>,
    ctx2: Option<Montgomery>,
}

#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
struct CrtExpRepr {
    #[serde(with = "serializable_bigint")]
    n: BigInt,
    #[serde(with = "serializable_bigint")]
    n1: BigInt,
    #[serde(with = "serializable_bigint")]
    phi_n1: BigInt,
    #[serde(with = "serializable_bigint")]
    n2: BigInt,
    #[serde(with = "serializable_bigint")]
    phi_n2: BigInt,
    #[serde(with = "serializable_bigint")]
    beta: BigInt,
}

#[cfg(feature = "serde")]
impl From<CrtExp> for CrtExpRepr {
    fn from(crt: CrtExp) -> Self {
        Self {
            n: &crt.n1 * &crt.n2,
            n1: crt.n1,
            phi_n1: crt.phi_n1,
            n2: crt.n2,
            phi_n2: crt.phi_n2,
            beta: crt.beta,
        }
    }
}

#[cfg(feature = "serde")]
impl TryFrom<CrtExpRepr> for CrtExp {
    type Error = &'static str;
    fn try_from(repr: CrtExpRepr) -> Result<Self, Self::Error> {
        let crt = CrtExp::build(repr.n1, repr.phi_n1, repr.n2, repr.phi_n2)
            .ok_or("invalid CRT parameters")?;
        if repr.n != &crt.n1 * &crt.n2 || crt.beta != repr.beta {
            return Err("inconsistent CRT parameters");
        }
        Ok(crt)
    }
}

/// Exponent for [modular exponentiation](CrtExp::exp) via [`CrtExp`]
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Exponent {
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    e_mod_phi_pp: BigInt,
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    e_mod_phi_qq: BigInt,
    is_negative: bool,
}

impl CrtExp {
    /// Builds a `CrtExp` for exponentation modulo `n = n1 * n2`
    ///
    /// `phi_n1 = phi(n1)` and `phi_n2 = phi(n2)` need to be known. For instance, if `p` is a prime,
    /// then `phi(p) = p - 1` and `phi(p^2) = p * (p - 1)`.
    ///
    /// [`CrtExp::build_n`] and [`CrtExp::build_nn`] can be used when `n1` and `n2` are primes or
    /// square of primes.
    pub fn build(n1: BigInt, phi_n1: BigInt, n2: BigInt, phi_n2: BigInt) -> Option<Self> {
        if n1 <= BigInt::ZERO
            || n2 <= BigInt::ZERO
            || phi_n1 <= BigInt::ZERO
            || phi_n2 <= BigInt::ZERO
            || phi_n1 >= n1
            || phi_n2 >= n2
        {
            return None;
        }

        let beta = n1.modinv(&n2)?;
        Some(Self {
            ctx1: Montgomery::new(n1.magnitude()),
            ctx2: Montgomery::new(n2.magnitude()),
            n1,
            phi_n1,
            n2,
            phi_n2,
            beta,
        })
    }

    /// Builds a `CrtExp` for exponentiation modulo `n = p * q` where `p`, `q` are primes
    pub fn build_n(p: &BigInt, q: &BigInt) -> Option<Self> {
        let phi_p = p - 1u8;
        let phi_q = q - 1u8;
        Self::build(p.clone(), phi_p, q.clone(), phi_q)
    }

    /// Builds a `CrtExp` for exponentiation modulo `nn = (p * q)^2` where `p`, `q` are primes
    pub fn build_nn(p: &BigInt, q: &BigInt) -> Option<Self> {
        let pp = p * p;
        let qq = q * q;
        let phi_pp = &pp - p;
        let phi_qq = &qq - q;
        Self::build(pp, phi_pp, qq, phi_qq)
    }

    /// Prepares exponent to perform [modular exponentiation](Self::exp)
    pub fn prepare_exponent(&self, e: &BigInt) -> Exponent {
        let abs_e = BigInt::from(e.magnitude().clone());
        Exponent {
            e_mod_phi_pp: abs_e.mod_floor(&self.phi_n1),
            e_mod_phi_qq: abs_e.mod_floor(&self.phi_n2),
            is_negative: e.sign() == Sign::Minus,
        }
    }

    /// Performs exponentiation modulo `n`
    ///
    /// Exponent needs to be output of [`CrtExp::prepare_exponent`]. Returns `None` if the exponent
    /// is negative and `x` is not invertible modulo `n`.
    pub fn exp(&self, x: &BigInt, e: &Exponent) -> Option<BigInt> {
        self.multi_exp(&[(x, e)])
    }

    /// Computes `prod_i x_i^{e_i} mod n`
    ///
    /// Each prime-power factor is handled with a single interleaved multi-exponentiation and the
    /// results are CRT-recombined once. Bases with a negative exponent are inverted first; returns
    /// `None` if such a base is not invertible modulo `n`. Empty input gives `1 mod n`.
    pub fn multi_exp(&self, pairs: &[(&BigInt, &Exponent)]) -> Option<BigInt> {
        let r1 = Self::multi_exp_factor(
            &self.ctx1,
            self.n1.magnitude(),
            pairs
                .iter()
                .map(|(x, e)| (*x, &e.e_mod_phi_pp, e.is_negative)),
        )?;
        let r2 = Self::multi_exp_factor(
            &self.ctx2,
            self.n2.magnitude(),
            pairs
                .iter()
                .map(|(x, e)| (*x, &e.e_mod_phi_qq, e.is_negative)),
        )?;
        Some(self.combine(r1, r2))
    }

    fn multi_exp_factor<'a>(
        ctx: &Option<Montgomery>,
        m: &BigUint,
        pairs: impl Iterator<Item = (&'a BigInt, &'a BigInt, bool)>,
    ) -> Option<BigUint> {
        let mut bases = Vec::new();
        let mut exps = Vec::new();
        for (x, e, negative) in pairs {
            let x = reduce(x, m);
            bases.push(if negative { x.modinv(m)? } else { x });
            exps.push(e.magnitude());
        }
        match ctx {
            Some(ctx) => {
                let pairs: Vec<_> = bases.iter().zip(exps).collect();
                Some(ctx.multi_pow(&pairs))
            }
            None => bases
                .iter()
                .zip(exps)
                .try_fold(BigUint::one() % m, |acc, (b, e)| {
                    Some(acc * mont::pow_mod(b, e, m)? % m)
                }),
        }
    }

    /// Given `r1 mod n1` and `r2 mod n2`, returns the unique `r mod n`
    fn combine(&self, r1: BigUint, r2: BigUint) -> BigInt {
        let r1 = BigInt::from(r1);
        let t = ((BigInt::from(r2) - &r1) * &self.beta).mod_floor(&self.n2);
        t * &self.n1 + r1
    }
}

impl fmt::Debug for CrtExp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // CRT likely contains secret data (such as factorization) so we make sure none of it
        // is leaked through `fmt::Debug`
        f.write_str("CrtExp")
    }
}

impl fmt::Debug for Exponent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Exponent may contain secret data, so we make sure none of it is leaked through
        // `fmt::Debug`
        f.write_str("CrtExponent")
    }
}

#[cfg(test)]
mod test {
    use num_bigint::{BigInt, RandBigInt};
    use num_integer::Integer;
    use num_traits::{One, Signed};
    use rand_core::RngCore;

    use super::{is_prime, small_primes::SMALL_PRIMES};

    fn rng() -> rand_dev::DevRng {
        rand_dev::DevRng::new()
    }

    /// Reference implementation using plain num-bigint
    fn reference_pow(base: &BigInt, exp: &BigInt, m: &BigInt) -> Option<BigInt> {
        let base = base.mod_floor(m);
        if exp.is_negative() {
            Some(base.modinv(m)?.modpow(&-exp, m))
        } else {
            Some(base.modpow(exp, m))
        }
    }

    #[test]
    fn pow_mod_signed_matches_reference() {
        let mut rng = rng();
        for bits in [8u64, 64, 65, 300, 1024] {
            for _ in 0..20 {
                let mut m: BigInt = BigInt::from(rng.gen_biguint(bits)) + 2;
                if rng.next_u32().is_multiple_of(3) {
                    // even moduli take the fallback path
                    m.set_bit(0, false);
                    m += 2;
                }
                let base = rng.gen_bigint(bits + 10);
                let exp = rng.gen_bigint(bits);
                assert_eq!(
                    super::pow_mod_signed(&base, &exp, &m),
                    reference_pow(&base, &exp, &m),
                    "base={base} exp={exp} m={m}"
                );
            }
        }
    }

    #[test]
    fn pow_mod_signed_edge_cases() {
        let b = BigInt::from;
        assert_eq!(super::pow_mod_signed(&b(3), &b(5), &b(0)), None);
        assert_eq!(super::pow_mod_signed(&b(3), &b(5), &b(-7)), None);
        assert_eq!(super::pow_mod_signed(&b(3), &b(5), &b(1)), Some(b(0)));
        assert_eq!(super::pow_mod_signed(&b(3), &b(0), &b(7)), Some(b(1)));
        assert_eq!(super::pow_mod_signed(&b(-3), &b(1), &b(7)), Some(b(4)));
        // 3^-1 mod 7 = 5
        assert_eq!(super::pow_mod_signed(&b(3), &b(-1), &b(7)), Some(b(5)));
        // 2 is not invertible mod 8
        assert_eq!(super::pow_mod_signed(&b(2), &b(-1), &b(8)), None);
        assert_eq!(super::pow_mod_signed(&b(6), &b(-1), &b(9)), None);
    }

    #[test]
    fn is_prime_small_values() {
        for x in -5i64..2 {
            assert!(!is_prime(&BigInt::from(x)), "{x}");
        }
        // compare with a sieve up to 20000 (covers the exact trial division range boundaries)
        let limit = 20_000usize;
        let mut sieve = vec![true; limit];
        sieve[0] = false;
        sieve[1] = false;
        for i in 2..limit {
            if sieve[i] {
                for j in (i * i..limit).step_by(i) {
                    sieve[j] = false;
                }
            }
        }
        for (x, &expected) in sieve.iter().enumerate() {
            assert_eq!(is_prime(&BigInt::from(x)), expected, "{x}");
        }
        for &p in &SMALL_PRIMES {
            assert!(is_prime(&BigInt::from(p)));
        }
    }

    #[test]
    fn is_prime_known_values() {
        let b = |s: &str| BigInt::parse_bytes(s.as_bytes(), 10).unwrap();
        let primes = [
            b("1495727"),                                          // largest prime below 1223^2
            b("1495751"),                                          // smallest prime above 1223^2
            b("2147483647"),                                       // 2^31 - 1
            b("18446744073709551557"),                             // largest 64-bit prime
            b("170141183460469231731687303715884105727"),          // 2^127 - 1
            b("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151"), // 2^521 - 1
        ];
        for p in &primes {
            assert!(is_prime(p), "{p}");
            assert!(!is_prime(&-p), "-{p}");
        }

        let composites = [
            b("1495729"),                   // 1223^2, first value past exact trial division
            b("3215031751"),                // strong pseudoprime to bases 2, 3, 5, 7
            b("2047"),                      // strong pseudoprime to base 2
            b("3277"),                      // strong pseudoprime to base 2
            b("4033"),                      // strong pseudoprime to base 2
            b("561"),                       // Carmichael
            b("41041"),                     // Carmichael
            b("825265"),                    // Carmichael
            b("321197185"),                 // Carmichael
            b("5394826801"),                // Carmichael
            b("232250619601"),              // Carmichael
            b("9746347772161"),             // Carmichael
            b("3825123056546413051"),       // strong pseudoprime to bases 2..23
            b("318665857834031151167461"),  // strong pseudoprime to bases 2..37
            b("3317044064679887385961981"), // strong pseudoprime to bases 2..41
        ];
        for c in &composites {
            assert!(!is_prime(c), "{c}");
        }
        // products of two random primes of various sizes
        let mut rng = rng();
        for bits in [40u32, 128, 512] {
            let p = super::sample_odd_with_size(&mut rng, bits);
            let p = next_prime(p);
            let q = next_prime(super::sample_odd_with_size(&mut rng, bits));
            assert!(!is_prime(&(&p * &q)));
            assert!(!is_prime(&(&p * &p)));
        }
    }

    fn next_prime(mut x: BigInt) -> BigInt {
        while !is_prime(&x) {
            x += 2;
        }
        x
    }

    #[test]
    fn is_prime_agrees_with_trial_division_on_random_values() {
        let mut rng = rng();
        for _ in 0..2000 {
            let x = rng.next_u64() >> 34; // < 2^30
            let expected = x >= 2
                && (2..)
                    .take_while(|d| d * d <= x)
                    .all(|d| !x.is_multiple_of(d));
            assert_eq!(is_prime(&BigInt::from(x)), expected, "{x}");
        }
    }

    #[test]
    fn safe_prime_size() {
        let mut rng = rng();
        for size in [3u32, 4, 10, 64, 65, 256, 512] {
            let prime = super::generate_safe_prime(&mut rng, size);
            assert_eq!(prime.bits(), u64::from(size));
            assert!(is_prime(&prime));
            let q: BigInt = (&prime - 1u8) >> 1u8;
            assert!(is_prime(&q));
        }
    }

    #[test]
    fn sample_with_size() {
        let mut rng = rng();
        for size in [1u32, 2, 799, 1279, 3455] {
            let integer = super::sample_with_size(&mut rng, size);
            assert_eq!(integer.bits(), u64::from(size));
            let odd = super::sample_odd_with_size(&mut rng, size);
            assert_eq!(odd.bits(), u64::from(size));
            assert!(odd.is_odd());
        }
    }

    #[test]
    fn test_coprime() {
        let a = BigInt::from(3);
        let b = BigInt::from(4);
        let c = BigInt::from(5);
        assert!(super::check_coprime(&[&a, &b, &c]));
        let d = BigInt::from(6);
        assert!(!super::check_coprime(&[&a, &b, &c, &d]));
    }

    fn crt_cases(rng: &mut impl RngCore) -> Vec<(BigInt, BigInt, BigInt, super::CrtExp)> {
        let p = super::generate_safe_prime(rng, 256);
        let q = super::generate_safe_prime(rng, 256);
        let n = &p * &q;
        let nn = &n * &n;
        vec![
            (
                p.clone(),
                q.clone(),
                n,
                super::CrtExp::build_n(&p, &q).unwrap(),
            ),
            (
                p.clone(),
                q.clone(),
                nn,
                super::CrtExp::build_nn(&p, &q).unwrap(),
            ),
        ]
    }

    #[test]
    fn crt_exp_matches_reference() {
        let mut rng = rng();
        for (_, _, modulus, crt) in crt_cases(&mut rng) {
            for _ in 0..30 {
                let x = BigInt::from(rng.gen_biguint_below(modulus.magnitude()));
                let mut e = BigInt::from(rng.gen_biguint(1100));
                if rng.next_u32().is_multiple_of(2) {
                    e = -e;
                }
                let expected = reference_pow(&x, &e, &modulus);
                assert_eq!(crt.exp(&x, &crt.prepare_exponent(&e)), expected);
            }
        }
    }

    #[test]
    fn crt_multi_exp_matches_reference() {
        let mut rng = rng();
        for (_, _, modulus, crt) in crt_cases(&mut rng) {
            for len in 0..4 {
                let xs: Vec<BigInt> = (0..len)
                    .map(|_| BigInt::from(rng.gen_biguint_below(modulus.magnitude())))
                    .collect();
                let es: Vec<BigInt> = (0..len)
                    .map(|_| {
                        let e = BigInt::from(rng.gen_biguint(700));
                        if rng.next_u32().is_multiple_of(2) {
                            -e
                        } else {
                            e
                        }
                    })
                    .collect();
                let prepared: Vec<_> = es.iter().map(|e| crt.prepare_exponent(e)).collect();
                let pairs: Vec<_> = xs.iter().zip(&prepared).collect();
                let expected = xs.iter().zip(&es).try_fold(BigInt::one(), |acc, (x, e)| {
                    Some(acc * reference_pow(x, e, &modulus)? % &modulus)
                });
                assert_eq!(crt.multi_exp(&pairs), expected);
            }
        }
    }

    #[test]
    fn crt_negative_exponent_of_non_unit() {
        let mut rng = rng();
        for (p, _, _, crt) in crt_cases(&mut rng) {
            let e = crt.prepare_exponent(&BigInt::from(-5));
            assert_eq!(crt.exp(&p, &e), None);
            let e = crt.prepare_exponent(&BigInt::from(5));
            assert!(crt.exp(&p, &e).is_some());
        }
    }

    #[test]
    fn crt_build_rejects_invalid() {
        let b = BigInt::from;
        assert!(super::CrtExp::build(b(0), b(1), b(7), b(6)).is_none());
        assert!(super::CrtExp::build(b(5), b(5), b(7), b(6)).is_none());
        assert!(super::CrtExp::build(b(6), b(2), b(9), b(6)).is_none()); // not coprime
                                                                         // even modulus works through the fallback path
        let crt = super::CrtExp::build(b(8), b(4), b(9), b(6)).unwrap();
        let e = crt.prepare_exponent(&b(-7));
        assert_eq!(crt.exp(&b(5), &e), reference_pow(&b(5), &b(-7), &b(72)));
    }
}
