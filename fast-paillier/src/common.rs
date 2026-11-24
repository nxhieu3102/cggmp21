use num_bigint::BigInt;

/// Extension trait for BigInt
pub trait BigIntExt: Sized {
    /// Returns `self ^ exp mod modulo`, see [`pow_mod_signed`](crate::utils::pow_mod_signed)
    fn modpow_ext(&self, exp: &Self, modulo: &Self) -> Option<Self>;
}

impl BigIntExt for BigInt {
    fn modpow_ext(&self, exp: &Self, modulo: &Self) -> Option<Self> {
        crate::utils::pow_mod_signed(self, exp, modulo)
    }
}
