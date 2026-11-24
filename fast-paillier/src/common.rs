use num_bigint::BigInt;
use num_traits::Signed;

/// Extension trait for BigInt
pub trait BigIntExt: Sized {
    /// Returns `self ^ exp mod modulo`
    fn modpow_ext(&self, exp: &Self, modulo: &Self) -> Option<Self>;
}

impl BigIntExt for BigInt {
    fn modpow_ext(&self, exp: &Self, modulo: &Self) -> Option<Self> {
        if exp.is_negative() {
            // For negative exponents: x^(-n) mod m = (x^(-1) mod m)^n mod m
            let base_inverse = self.clone().modinv(modulo)?;
            let positive_exp = -exp.clone();
            Some(base_inverse.modpow(&positive_exp, modulo))
        } else {
            // For positive exponents, use regular modpow
            Some(self.modpow(exp, modulo))
        }
    }
}
