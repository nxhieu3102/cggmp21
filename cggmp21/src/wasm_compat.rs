// This module provides compatibility replacements for paillier_zk when targeting WebAssembly
// It uses num-bigint instead of rug (GMP) which is not compatible with WASM

use num_bigint::{BigInt, BigUint, Sign};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::{Add, Div, Mul, Neg, Rem, Sub};

// A simplified Integer replacement for WASM that uses num_bigint::BigInt
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Integer(pub BigInt);

impl Integer {
    pub fn from_str_radix(s: &str, radix: u32) -> Result<Self, String> {
        BigInt::parse_bytes(s.as_bytes(), radix).map(Integer).ok_or_else(|| "Failed to parse".to_string())
    }
    
    pub fn to_string_radix(&self, radix: u32) -> String {
        self.0.to_str_radix(radix)
    }
    
    pub fn from_bytes_be(sign: Sign, bytes: &[u8]) -> Self {
        Integer(BigInt::from_bytes_be(sign, bytes))
    }
    
    pub fn to_bytes_be(&self) -> (Sign, Vec<u8>) {
        self.0.to_bytes_be()
    }
    
    pub fn modpow(&self, exp: &Self, modulus: &Self) -> Self {
        Integer(self.0.modpow(&exp.0, &modulus.0))
    }

    pub fn pow_mod(&self, exp: &Self, modulus: &Self) -> Self {
        self.modpow(exp, modulus)
    }
    
    pub fn is_zero(&self) -> bool {
        self.0 == BigInt::from(0)
    }
    
    pub fn is_one(&self) -> bool {
        self.0 == BigInt::from(1)
    }
    
    pub fn is_negative(&self) -> bool {
        self.0.sign() == Sign::Minus
    }
    
    pub fn abs(&self) -> Self {
        Integer(self.0.abs())
    }
    
    pub fn pow_u32(&self, exp: u32) -> Self {
        Integer(self.0.pow(exp))
    }
}

// Implement basic arithmetic operations
impl Add for Integer {
    type Output = Integer;
    
    fn add(self, other: Integer) -> Integer {
        Integer(self.0 + other.0)
    }
}

impl Sub for Integer {
    type Output = Integer;
    
    fn sub(self, other: Integer) -> Integer {
        Integer(self.0 - other.0)
    }
}

impl Mul for Integer {
    type Output = Integer;
    
    fn mul(self, other: Integer) -> Integer {
        Integer(self.0 * other.0)
    }
}

impl Div for Integer {
    type Output = Integer;
    
    fn div(self, other: Integer) -> Integer {
        Integer(self.0 / other.0)
    }
}

impl Rem for Integer {
    type Output = Integer;
    
    fn rem(self, other: Integer) -> Integer {
        Integer(self.0 % other.0)
    }
}

impl Neg for Integer {
    type Output = Integer;
    
    fn neg(self) -> Integer {
        Integer(-self.0)
    }
}

impl fmt::Debug for Integer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for Integer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// Simplified module to mimic the rug API
pub mod rug {
    pub use super::Integer;
    
    pub trait Complete {
        fn complete(self) -> Self;
    }
    
    impl Complete for Integer {
        fn complete(self) -> Self {
            self // For BigInt there's no need for completion like in rug
        }
    }
}

// A simple module to mimic paillier_zk::fast_paillier
pub mod fast_paillier {
    use super::*;
    
    pub mod utils {
        use rand::RngCore;
        
        // Simplified version that uses rand instead of GMP's random
        pub fn external_rand(bytes: &mut [u8]) {
            rand::thread_rng().fill_bytes(bytes);
        }
    }
}

// Stub implementation for π_enc to make code compile
pub fn paillier_encryption_in_range() {
    #[cfg(feature = "wasm")]
    wasm_bindgen::throw_str("Paillier encryption is not supported in WASM");
}

// When not targeting WASM, re-export from paillier_zk
#[cfg(not(feature = "wasm"))]
pub mod reexports {
    pub use paillier_zk::*;
} 
