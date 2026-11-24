use num_bigint::{BigInt, BigUint, RandBigInt};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand_core::RngCore;

/// Find `(y' = (-1)^a w^b y, a, b)` such that y' is a quadratic residue in Zn.
///
/// a and b are treated as false = 0, true = 1
///
/// Pre-requisites:
/// - `n = pq`, p and q are Blum primes
/// - `jacobi(w, n) = -1`, that is w is quadratic non-residue in Zn with jacobi
///   symbol of -1
///
/// If these don't hold, the y' might not exist. In this case, returns `None`
pub fn find_residue(
    y: &BigInt,
    w: &BigInt,
    p: &BigInt,
    q: &BigInt,
    n: &BigInt,
) -> Option<(bool, bool, BigInt)> {
    let y = y.mod_floor(n);
    match (jacobi(&y, p), jacobi(&y, q)) {
        (1, 1) => return Some((false, false, y)),
        (-1, -1) => return Some((true, false, n - y)),
        _ => (),
    }

    let y_times_w = (y * w).mod_floor(n);
    match (jacobi(&y_times_w, p), jacobi(&y_times_w, q)) {
        (1, 1) => Some((false, true, y_times_w)),
        (-1, -1) => Some((true, true, n - y_times_w)),
        _ => None,
    }
}

/// Finds a element in Zn that has jacobi symbol of -1
///
/// `n` must be odd and not a perfect square, otherwise the function never returns.
pub fn sample_neg_jacobi<R: RngCore>(n: &BigInt, rng: &mut R) -> BigInt {
    loop {
        let w = rng.gen_bigint_range(&BigInt::zero(), n);
        if jacobi(&w, n) == -1 {
            break w;
        }
    }
}

/// Computes the Jacobi symbol `(a/n)`
///
/// Returns 0 if `n` is not a positive odd integer (the symbol is undefined).
pub fn jacobi(a: &BigInt, n: &BigInt) -> i8 {
    if !n.is_odd() || n.sign() == num_bigint::Sign::Minus {
        return 0;
    }
    let low_bits = |x: &BigUint| x.iter_u32_digits().next().unwrap_or(0);

    let mut n = n.magnitude().clone();
    let mut a = a.mod_floor(&BigInt::from(n.clone())).into_parts().1;
    let mut result = 1;

    while !a.is_zero() {
        // Remove factors of 2: (2/n) = -1 iff n = 3, 5 (mod 8)
        let twos = a.trailing_zeros().unwrap_or(0);
        a >>= twos;
        if twos % 2 == 1 && matches!(low_bits(&n) % 8, 3 | 5) {
            result = -result;
        }

        // Quadratic reciprocity
        std::mem::swap(&mut a, &mut n);
        if low_bits(&a) % 4 == 3 && low_bits(&n) % 4 == 3 {
            result = -result;
        }
        a %= &n;
    }

    if n.is_one() {
        result
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::jacobi;
    use num_bigint::BigInt;

    /// Euler's criterion for a prime modulus
    fn legendre_reference(a: i64, p: i64) -> i8 {
        let r = BigInt::from(a).modpow(&BigInt::from((p - 1) / 2), &BigInt::from(p));
        if r == BigInt::from(0) {
            0
        } else if r == BigInt::from(1) {
            1
        } else {
            -1
        }
    }

    #[test]
    fn matches_euler_criterion_and_multiplicativity() {
        let primes = [3i64, 5, 7, 11, 13, 17, 19, 23, 101, 103];
        for &p in &primes {
            for a in -30i64..60 {
                let expected = legendre_reference(a.rem_euclid(p), p);
                assert_eq!(
                    jacobi(&BigInt::from(a), &BigInt::from(p)),
                    expected,
                    "({a}/{p})"
                );
            }
        }
        // composite moduli: (a/pq) = (a/p)(a/q)
        for &p in &primes {
            for &q in &primes {
                for a in 0i64..50 {
                    let expected = legendre_reference(a % p, p) * legendre_reference(a % q, q);
                    assert_eq!(jacobi(&BigInt::from(a), &BigInt::from(p * q)), expected);
                }
            }
        }
    }

    #[test]
    fn undefined_modulus() {
        assert_eq!(jacobi(&BigInt::from(5), &BigInt::from(8)), 0);
        assert_eq!(jacobi(&BigInt::from(5), &BigInt::from(0)), 0);
        assert_eq!(jacobi(&BigInt::from(5), &BigInt::from(-7)), 0);
    }
}
