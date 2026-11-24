//! Various utilities

mod serde_wrapper;
mod small_primes;

use num_bigint::Sign;
use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt};
use num_integer::Integer;
use num_prime::nt_funcs;
use num_traits::identities::One;
use num_traits::Zero;
use rand::RngCore;
pub use serde_wrapper::*;
use std::fmt;

/// Checks that `x` is in Z*_n
#[inline(always)]
pub fn in_mult_group(x: &BigInt, n: &BigInt) -> bool {
    *x >= BigInt::ZERO && in_mult_group_abs(x, n)
}

/// Checks that `abs(x)` is in Z*_n
#[inline(always)]
pub fn in_mult_group_abs(x: &BigInt, n: &BigInt) -> bool {
    x.gcd(n).is_one()
}

/// Samples `x` in Z*_n
pub fn sample_in_mult_group(rng: &mut impl RngCore, n: &BigInt) -> BigInt {
    loop {
        let x = rng.gen_bigint_range(&BigInt::ZERO, n);
        if in_mult_group(&x, n) {
            return x;
        }
    }
}

/// Samples with size = bits
pub fn sample_with_size(rng: &mut impl RngCore, bits: u32) -> BigInt {
    let mut x = rng.gen_bigint(bits as u64);
    if x.sign() == Sign::Minus {
        x = -x;
    }
    x.set_bit(bits as u64 - 1, true);
    if x.sign() == Sign::Minus {
        x = -x;
    }
    x
}

/// Samples an odd integer with size = bits
pub fn sample_odd_with_size(rng: &mut impl RngCore, bits: u32) -> BigInt {
    let mut x = sample_with_size(rng, bits);

    // make sure the number is odd
    x.set_bit(0, true);

    x
}

/// Check if `x` is a prime
pub fn is_prime(x: &BigInt) -> bool {
    // make sure the number is odd
    if !x.is_odd() {
        return false;
    }

    // make sure x does not divide any of the small primes
    for &small_prime in &small_primes::SMALL_PRIMES[0..small_primes::SMALL_PRIMES.len()] {
        if BigInt::from(small_prime) >= *x {
            break;
        }

        let mod_result = x % small_prime;
        if mod_result.is_zero() {
            return false;
        }
    }

    // TODO: recheck `nt_funcs::is_prime` to remove redundant checks and loop
    // Current: the `nt_funcs::is_prime` only allows blum primes
    // Target: allow any prime
    for _ in 0..25 {
        if let num_prime::Primality::Yes | num_prime::Primality::Probable(_) =
            nt_funcs::is_prime(&x.to_biguint().unwrap(), None)
        {
            return true;
        }
    }

    false
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

/// Generates a random safe prime
/// Currently: this function will generate a safe and blum prime
///
pub fn generate_safe_prime(rng: &mut impl RngCore, bits: u32) -> BigInt {
    sieve_generate_safe_primes(rng, bits, 135)
}

/// Generate a random safe prime with a given sieve parameter.
///
/// For different bit sizes, different parameter value will give fastest
/// generation, the higher bit size - the higher the sieve parameter.
/// The best way to select the parameter is by trial. The one used by
/// [`generate_safe_prime`] is indistinguishable from optimal for 500-1700 bit
/// lengths.
pub fn sieve_generate_safe_primes(rng: &mut impl RngCore, bits: u32, amount: usize) -> BigInt {
    let amount = amount.min(small_primes::SMALL_PRIMES.len());
    // let mut rng = external_rand(rng);
    // let mut x = BigInt::new();
    println!("bits: {}", bits);
    'trial: loop {
        // generate an odd number of length `bits - 2`
        let mut x = rng.gen_biguint(bits as u64 - 2);
        // x.assign(Integer::random_bits(bits - 1, &mut rng));
        // `random_bits` is guaranteed to not set `bits-1`-th bit, but not
        // guaranteed to set the `bits-2`-th
        x.set_bit(bits as u64 - 2, true);
        x |= BigUint::from(1u8);
        for &small_prime in &small_primes::SMALL_PRIMES[0..amount] {
            let x_clone = x.clone();
            let small_prime_bi = BigUint::from(small_prime);
            if small_prime_bi >= x_clone {
                break;
            }
            let mod_result = x_clone % small_prime_bi.clone();
            if mod_result == (small_prime_bi - 1u8) / 2u8 {
                continue 'trial;
            }
        }

        // TODO: recheck `nt_funcs::is_prime` to add more checks and loop if needed
        if let num_prime::Primality::Yes | num_prime::Primality::Probable(_) =
            nt_funcs::is_prime(&x, None)
        {
            x <<= 1;
            x += 1u8;
            if let num_prime::Primality::Yes | num_prime::Primality::Probable(_) =
                nt_funcs::is_prime(&x, None)
            {
                return x.to_bigint().unwrap();
            }
        }
    }
}

/// Faster algorithm for modular exponentiation based on Chinese remainder theorem when modulo factorization is known
///
/// `CrtExp` makes exponentation modulo `n` faster when factorization `n = n1 * n2` is known as well as `phi(n1)` and `phi(n2)`
/// (note that `n1` and `n2` don't need to be primes). In this case, you can [build](Self::build) a `CrtExp` and use provided
/// [exponentiation algorithm](Self::exp).
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CrtExp {
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

/// Exponent for [modular exponentiation](CrtExp::exp) via [`CrtExp`]
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Exponent {
    #[serde(with = "serializable_bigint")]
    e_mod_phi_pp: BigInt,
    #[serde(with = "serializable_bigint")]
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
            n: (&n1 * &n2),
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
        let phi_pp = pp.clone() - p.clone();
        let phi_qq = qq.clone() - q.clone();
        Self::build(pp, phi_pp, qq, phi_qq)
    }

    /// Prepares exponent to perform [modular exponentiation](Self::exp)
    pub fn prepare_exponent(&self, e: &BigInt) -> Exponent {
        let neg_e = -e;
        let is_negative = e < &BigInt::ZERO;
        let e = if is_negative { &neg_e } else { e };
        let e_mod_phi_pp = e.mod_floor(&self.phi_n1);
        let e_mod_phi_qq = e.mod_floor(&self.phi_n2);
        Exponent {
            e_mod_phi_pp,
            e_mod_phi_qq,
            is_negative,
        }
    }

    /// Performs exponentiation modulo `n`
    ///
    /// Exponent needs to be output of [`CrtExp::prepare_exponent`]
    pub fn exp(&self, x: &BigInt, e: &Exponent) -> Option<BigInt> {
        let s1 = x.mod_floor(&self.n1);
        let s2 = x.mod_floor(&self.n2);

        // `e_mod_phi_pp` and `e_mod_phi_qq` are guaranteed to be non-negative by construction
        #[allow(clippy::expect_used)]
        let r1 = s1.modpow(&e.e_mod_phi_pp, &self.n1);
        #[allow(clippy::expect_used)]
        let r2 = s2.modpow(&e.e_mod_phi_qq, &self.n2);

        let result = ((r2 - &r1) * &self.beta).mod_floor(&self.n2) * &self.n1 + &r1;

        if e.is_negative {
            result.modinv(&self.n)
        } else {
            Some(result)
        }
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
    use num_bigint::BigInt;
    use num_integer::Integer;
    use num_traits::One;
    use rand;
    use std::vec;

    #[test]
    fn safe_prime_size() {
        println!("safe_prime_size");
        let mut rng = rand::thread_rng();
        for size in [10, 500, 512, 513, 514, 2048] {
            let mut prime = super::generate_safe_prime(&mut rng, size);
            prime >>= size - 1;
            assert_eq!(prime, BigInt::one());
        }
    }

    #[test]
    fn sample_with_size() {
        let mut rng = rand::thread_rng();
        for size in [799, 1279, 3455] {
            let integer = super::sample_with_size(&mut rng, size);

            // make sure the number size is `bits`
            // rug doesn't have bit length operations, so
            assert_eq!(integer.bits(), size as u64);
        }
    }

    #[test]
    fn sample_odd_with_size() {
        let mut rng = rand::thread_rng();
        for size in [799, 1279, 3455] {
            let odd = super::sample_odd_with_size(&mut rng, size);

            // make sure the number size is `bits`
            // rug doesn't have bit length operations, so
            assert_eq!(odd.bits(), size as u64);

            // make sure the number is odd
            assert_eq!(odd.is_odd(), true);
        }
    }

    #[test]
    fn test_coprime() {
        let a = BigInt::from(3);
        let b = BigInt::from(4);
        let c = BigInt::from(5);
        let vec = vec![&a, &b, &c];

        assert_eq!(super::check_coprime(&vec), true);

        let d = BigInt::from(6);
        let vec = vec![&a, &b, &c, &d];
        assert_eq!(super::check_coprime(&vec), false);
    }
}
