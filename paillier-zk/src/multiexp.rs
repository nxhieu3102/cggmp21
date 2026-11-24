//! Optimized multiexponentiation with precomputations
//!
//! Many ZK proofs often require computing `s^x t^y mod N` with s, t, and N being known in advance.
//! This module provides [`MultiexpTable`] that can compute multiexponent faster.

#![allow(non_snake_case)]

use crate::common::BigIntExt;
#[cfg(feature = "serde")]
use fast_paillier::utils::serde_wrapper::{serializable_bigint, serializable_vec_bigint};
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{One, Signed};

/// Precomputed table for performing faster multiexponentiation
///
/// Stores `s^(256^i)` and `t^(256^i) mod N`. Exponents are processed byte by byte; the
/// table is indexed by (secret) exponent digits, so the computation isn't constant-time.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MultiexpTable {
    #[cfg_attr(feature = "serde", serde(with = "serializable_vec_bigint"))]
    s: Vec<BigInt>,
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    ell_x: BigInt,
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    s_to_ell_x: BigInt,
    #[cfg_attr(feature = "serde", serde(with = "serializable_vec_bigint"))]
    t: Vec<BigInt>,
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    ell_y: BigInt,
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    t_to_ell_y: BigInt,
    #[cfg_attr(feature = "serde", serde(with = "serializable_bigint"))]
    N: BigInt,
}

impl MultiexpTable {
    /// Builds a multiexponentiation table to perform `s^x t^y mod N` faster
    /// where `x` and `y` are up to `x_bits` and `y_bits`
    ///
    /// Returns `None` is `s` or `t` are non-positive or if any of them are not co-prime to `N` or
    /// if `N` is less than 2.
    pub fn build(s: &BigInt, t: &BigInt, x_bits: u64, y_bits: u64, N: BigInt) -> Option<Self> {
        if !s.is_positive()
            || !t.is_positive()
            || N <= BigInt::one()
            || !s.gcd(&N).is_one()
            || !t.gcd(&N).is_one()
        {
            return None;
        }

        let k_x = usize::try_from(x_bits / 8 + 1).ok()?;
        let k_y = usize::try_from(y_bits / 8 + 1).ok()?;
        let s_table = powers_of_256(s, k_x, &N)?;
        let t_table = powers_of_256(t, k_y, &N)?;

        // smallest negative value possible for `x`
        let ell_x = -(BigInt::one() << (k_x * 8)) + 1;
        let s_to_ell_x = s.modpow_ext(&ell_x, &N)?;
        // smallest negative value possible for `y`
        let ell_y = -(BigInt::one() << (k_y * 8)) + 1;
        let t_to_ell_y = t.modpow_ext(&ell_y, &N)?;

        Some(Self {
            s: s_table,
            ell_x,
            s_to_ell_x,
            t: t_table,
            ell_y,
            t_to_ell_y,
            N,
        })
    }

    /// Calculates `s^x t^y mod N`
    ///
    /// Returns `None` if either `x` or `y` do not fit into `x_bits` or `y_bits` provided in [`MultiexpTable::build`].
    pub fn prod_exp(&self, x: &BigInt, y: &BigInt) -> Option<BigInt> {
        // Digits of `x` if it's non-negative, and of `x - ell_x` otherwise
        let x_digits = digits(x, &self.ell_x)?;
        let y_digits = digits(y, &self.ell_y)?;

        if x_digits.len() > self.s.len() || y_digits.len() > self.t.len() {
            // `x` or `y` are higher than upper bound
            return None;
        }

        // table[d - 1] = product of all base powers whose digit equals `d`
        let mut digits_table = [(); 255].map(|_| None);
        build_digits_table(&mut digits_table, &self.s, &x_digits, &self.N);
        build_digits_table(&mut digits_table, &self.t, &y_digits, &self.N);

        // res = prod_d table[d - 1]^d
        let mut res = BigInt::one();
        let mut acc = BigInt::one();
        for d in digits_table.iter().rev() {
            if let Some(d) = d {
                acc = (acc * d).mod_floor(&self.N);
            }
            res = (res * &acc).mod_floor(&self.N);
        }

        if x.is_negative() {
            res = (res * &self.s_to_ell_x).mod_floor(&self.N);
        }
        if y.is_negative() {
            res = (res * &self.t_to_ell_y).mod_floor(&self.N);
        }

        Some(res)
    }

    /// Returns max size of exponents (in bits) that can be computed
    ///
    /// Max exponent size is guaranteed to be equal or greater than `x_bits` and `y_bits`
    /// provided in [MultiexpTable::build]
    pub fn max_exponents_size(&self) -> (usize, usize) {
        (self.s.len() * 8, self.t.len() * 8)
    }

    /// Estimates size of the table in RAM in bytes
    pub fn size_in_bytes(&self) -> usize {
        let Self {
            s,
            ell_x,
            s_to_ell_x,
            t,
            ell_y,
            t_to_ell_y,
            N,
        } = self;

        // Heap size of an integer: whole number of 64-bit limbs
        let limbs_bytes = |x: &BigInt| x.bits().div_ceil(64) as usize * 8;
        // Each integer has a fixed size header (pointer, capacity, length, sign)
        let header = core::mem::size_of::<BigInt>();

        let ints = s
            .iter()
            .chain(t)
            .chain([ell_x, s_to_ell_x, ell_y, t_to_ell_y, N]);
        2 * core::mem::size_of::<Vec<BigInt>>()
            + ints.map(|x| header + limbs_bytes(x)).sum::<usize>()
    }
}

/// Returns `[b, b^256, b^(256^2), ..., b^(256^(k-1))] mod N`
fn powers_of_256(b: &BigInt, k: usize, N: &BigInt) -> Option<Vec<BigInt>> {
    let N_u = N.magnitude();
    let e = 256u32.into();
    let mut table = Vec::with_capacity(k);
    let mut cur = b.mod_floor(N).into_parts().1;
    for _ in 0..k {
        let next = fast_paillier::mont::pow_mod(&cur, &e, N_u)?;
        table.push(BigInt::from(core::mem::replace(&mut cur, next)));
    }
    Some(table)
}

/// Little-endian base-256 digits of `x` if it's non-negative, or of `x - ell` otherwise.
/// Returns `None` if `x < ell`.
fn digits(x: &BigInt, ell: &BigInt) -> Option<Vec<u8>> {
    if x.is_negative() {
        let shifted = x - ell;
        if shifted.is_negative() {
            return None;
        }
        Some(shifted.magnitude().to_bytes_le())
    } else {
        Some(x.magnitude().to_bytes_le())
    }
}

fn build_digits_table(
    table: &mut [Option<BigInt>; 255],
    base: &[BigInt],
    digits: &[u8],
    N: &BigInt,
) {
    for (digit, base_i) in digits.iter().copied().zip(base) {
        if digit != 0 {
            match &mut table[usize::from(digit - 1)] {
                Some(out) => {
                    *out *= base_i;
                    *out %= N;
                }
                out @ None => *out = Some(base_i.clone()),
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::BigIntExt;
    use num_bigint::{BigInt, RandBigInt};
    use num_integer::Integer;
    use num_traits::Signed;

    use super::MultiexpTable;

    #[test]
    fn multiexp_works() {
        let mut rng = rand_dev::DevRng::new();
        for (N, x_bits, y_bits) in [
            (BigInt::from(100000), 48u64, 32u64),
            (rng.gen_bigint(2048).abs() | BigInt::from(1), 700, 2800),
        ] {
            let s = BigInt::gen_invertible(&N, &mut rng);
            let t = BigInt::gen_invertible(&N, &mut rng);
            let table = MultiexpTable::build(&s, &t, x_bits, y_bits, N.clone()).unwrap();
            assert!(table.max_exponents_size().0 >= x_bits as usize);
            assert!(table.max_exponents_size().1 >= y_bits as usize);

            for _ in 0..50 {
                let x = rng.gen_bigint(x_bits);
                let y = rng.gen_bigint(y_bits);
                let actual = table.prod_exp(&x, &y).unwrap();
                let expected =
                    (s.modpow_ext(&x, &N).unwrap() * t.modpow_ext(&y, &N).unwrap()).mod_floor(&N);
                assert_eq!(actual, expected);
            }

            // Exponents out of range
            let too_big = BigInt::from(1) << (table.max_exponents_size().0 + 8);
            assert_eq!(table.prod_exp(&too_big, &BigInt::from(1)), None);
            assert_eq!(table.prod_exp(&-too_big, &BigInt::from(1)), None);
        }
    }

    #[test]
    fn build_rejects_bad_input() {
        let N = BigInt::from(35);
        assert!(
            MultiexpTable::build(&BigInt::from(5), &BigInt::from(2), 8, 8, N.clone()).is_none()
        );
        assert!(
            MultiexpTable::build(&BigInt::from(0), &BigInt::from(2), 8, 8, N.clone()).is_none()
        );
        assert!(MultiexpTable::build(&BigInt::from(-2), &BigInt::from(2), 8, 8, N).is_none());
        assert!(
            MultiexpTable::build(&BigInt::from(2), &BigInt::from(3), 8, 8, BigInt::from(1))
                .is_none()
        );
    }

    #[test]
    fn size_estimate() {
        let mut rng = rand_dev::DevRng::new();
        let N = rng.gen_bigint(2048).abs() | BigInt::from(1);
        let s = BigInt::gen_invertible(&N, &mut rng);
        let t = BigInt::gen_invertible(&N, &mut rng);
        let table = MultiexpTable::build(&s, &t, 1024, 1024, N).unwrap();
        // 2 * 129 entries of at most 2048 bits + 5 extra integers
        let upper = (2 * 129 + 5) * (2048 / 8 + core::mem::size_of::<BigInt>()) + 64;
        let lower = 2 * 129 * (2000 / 8);
        let size = table.size_in_bytes();
        assert!(lower < size && size < upper, "{size}");
    }
}
