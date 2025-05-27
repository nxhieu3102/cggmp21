//! Security level of CGGMP protocol with some modifies for Optimized Paillier
//!
//! Security level is defined as set of parameters in the CGGMP paper. Higher security level gives more
//! security but makes protocol execution slower.
//!
//! We provide a predefined default [SecurityLevel128].
//!
//! You can define your own security level using macro [define_security_level]. Be sure that you properly
//! analyzed the CGGMP paper and you understand implications. Inconsistent security level may cause unexpected
//! unverbose runtime error or reduced security of the protocol.
use num_bigint::BigInt;
/// Security level of CGGMP21 DKG protocol
pub use cggmp21_keygen::security_level::SecurityLevel as KeygenSecurityLevel;

/// Hardcoded value for parameter $m$ of security level
///
/// Currently, [security parameter $m$](SecurityLevel::M) is hardcoded to this constant. We're going to fix that
/// once `feature(generic_const_exprs)` is stable.
pub const M: usize = 128;

/// Hardcoded value for parameter $n_size$ of security level
/// Which is the size of Optimized Paillier public key
pub const N_SIZE: u32 = 3072;

/// Hardcoded value for parameter $a_size$ of security level
/// Which is the size of Optimized Paillier secret key (alpha)
pub const A_SIZE: u32 = 512;

/// Security level of the CGGMP21 protocol
///
/// You should not implement this trait manually. Use [define_security_level] macro instead.
pub trait SecurityLevel: KeygenSecurityLevel {
    /// Epsilon for the size of the public key N = P * Q. The size of N may be smaller than N_SIZE due to the generation algorithm.
    const EPSILON_N_SIZE: u32 = 3;
    /// Epsilon for the size of prime P. The size of P may be smaller than N_SIZE / 2.
    const EPSILON_P_SIZE: u32 = 1;
    /// Epsilon for the size of prime Q. The size of Q may be smaller than N_SIZE / 2.
    const EPSILON_Q_SIZE: u32 = 1;
    /// Epsilon for the size of the private key alpha. The size of alpha may be smaller than A_SIZE.
    const EPSILON_A_SIZE: u32 = 1;

    /// $\varepsilon$ bits
    const EPSILON: usize;

    /// $\ell$ parameter
    const ELL: usize;
    /// $\ell'$ parameter
    const ELL_PRIME: usize;

    /// $m$ parameter
    ///
    /// **Note:** currently, security parameter $m$ is hardcoded to [`M = 128`](M) due to compiler limitations.
    /// If you implement this trait directly, actual value of $m$ will be ignored. If you're using [define_security_level] macro
    /// it will produce a compilation error if different value of $m$ is set. We're going to fix that once `generic_const_exprs`
    /// feature is stable.
    const M: usize;

    /// $n_size$ parameter: size of Optimized Paillier public key
    /// Which is corresponding to $m$
    /// Because $m$ is hardcoded, so $n_size$ is hardcoded too
    const N_SIZE: u32;

    /// $a_size$ parameter: size of Optimized Paillier private key
    /// Which is corresponding to $m$
    /// Because $m$ is hardcoded, so $a_size$ is hardcoded too
    const A_SIZE: u32;

    /// $q$ parameter
    ///
    /// Note that it's not curve order, and it doesn't need to be a prime, it's another security parameter
    /// that determines security level.
    fn q() -> BigInt;
}

/// Determines max size of exponents
///
/// During the CGGMP21 protocol, we often calculate $s^x t^y \mod N$. Given the security level
/// we can determine max size of $x$ and $y$ in bits.
///
/// Size of exponents can be used to build a [multiexp table](paillier_zk::multiexp).
///
/// Returns `(x_bits, y_bits)`
pub fn max_exponents_size<L: SecurityLevel>() -> (u32, u32) {
    use std::cmp;

    let x_bits = cmp::max(
        L::ELL as u32 + L::EPSILON as u32 + 4 * L::SECURITY_BITS,
        (L::ELL_PRIME + L::EPSILON) as _,
    );
    let y_bits = (L::ELL + L::EPSILON) as u32 + 8 * L::SECURITY_BITS;

    (x_bits, y_bits)
}

/// Internal module that's powers `define_security_level` macro
#[doc(hidden)]
pub mod _internal {
    use hex::FromHex;

    pub use cggmp21_keygen::security_level::{
        define_security_level as define_keygen_security_level, SecurityLevel as KeygenSecurityLevel,
    };

    #[derive(Clone)]
    pub struct Rid<const N: usize>([u8; N]);

    impl<const N: usize> AsRef<[u8]> for Rid<N> {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    impl<const N: usize> AsMut<[u8]> for Rid<N> {
        fn as_mut(&mut self) -> &mut [u8] {
            &mut self.0
        }
    }

    impl<const N: usize> Default for Rid<N> {
        fn default() -> Self {
            Self([0u8; N])
        }
    }

    impl<const N: usize> FromHex for Rid<N>
    where
        [u8; N]: FromHex,
    {
        type Error = <[u8; N] as FromHex>::Error;
        fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
            FromHex::from_hex(hex).map(Self)
        }
    }
}

/// Defines security level
///
/// ## Example
///
/// This code defines security level corresponding to $\kappa=1024$, $\varepsilon=128$, $\ell = \ell' = 1024$,
/// $m = 128$, and $q = 2^{48}-1$ (note: choice of parameters is random, it does not correspond to meaningful
/// security level):
/// ```rust
/// use cggmp21::security_level::define_security_level;
/// use cggmp21::rug::Integer;
///
/// #[derive(Clone)]
/// pub struct MyLevel;
/// define_security_level!(MyLevel{
///     security_bits = 1024,
///     epsilon = 128,
///     ell = 1024,
///     ell_prime = 1024,
///     m = 128,
///     n_size = 3072,
///     a_size = 512,
///     q = (Integer::ONE.clone() << 48_u32) - 1,
/// });
/// ```
///
/// **Note:** currently, security parameter $m$ is hardcoded to the [`M = 128`](M) due to compiler limitations.
/// Setting any other value of $m$ results into compilation error. We're going to fix that once `generic_const_exprs`
/// feature is stable.
#[macro_export]
macro_rules! define_security_level {
    ($struct_name:ident {
        security_bits = $k:expr,
        epsilon = $e:expr,
        ell = $ell:expr,
        ell_prime = $ell_prime:expr,
        m = $m:tt,
        n_size = $n_size:tt,
        a_size = $a_size:tt,
        q = $q:expr,
    }) => {
        $crate::define_security_level! {
            $struct_name {
                epsilon = $e,
                ell = $ell,
                ell_prime = $ell_prime,
                m = $m,
                n_size = $n_size,
                a_size = $a_size,
                q = $q,
            }
        }
        $crate::security_level::_internal::define_keygen_security_level! {
            $struct_name {
                security_bits = $k,
            }
        }
    };
    ($struct_name:ident {
        epsilon = $e:expr,
        ell = $ell:expr,
        ell_prime = $ell_prime:expr,
        m = 128,
        n_size = 3072,
        a_size = 512,
        q = $q:expr,
    }) => {
        impl $crate::security_level::SecurityLevel for $struct_name {
            const EPSILON: usize = $e;
            const ELL: usize = $ell;
            const ELL_PRIME: usize = $ell_prime;
            const M: usize = 128;
            const N_SIZE: u32 = 3072;
            const A_SIZE: u32 = 512;

            fn q() -> BigInt{
                $q
            }
        }
    };
    ($struct_name:ident {
        epsilon = $e:expr,
        ell = $ell:expr,
        ell_prime = $ell_prime:expr,
        m = $m:tt,
        n_size = $n_size:tt,
        a_size = $a_size:tt,
        q = $q:expr,
    }) => {
        compile_error!(concat!("Currently, we can not set security parameter M to anything but 128 (you set m=", stringify!($m), ")"));
    };
}

#[doc(inline)]
pub use define_security_level;

#[doc(inline)]
pub use cggmp21_keygen::security_level::SecurityLevel128;
define_security_level!(SecurityLevel128{
    epsilon = 230,
    ell = 256,
    ell_prime = 848,
    m = 128,
    n_size = 3072,
    a_size = 512,
    q = BigInt::from(1) << 128_u32,
});

/// Checks that public paillier key meets security level constraints
pub(crate) fn validate_public_paillier_key_size<L: SecurityLevel>(N: &BigInt) -> bool {
    N.bits() >= (L::N_SIZE - L::EPSILON_N_SIZE) as u64
}

/// Checks that secret paillier key meets security level constraints
pub(crate) fn validate_secret_paillier_key_size<L: SecurityLevel>(
    p: &BigInt,
    q: &BigInt,
    alpha: &BigInt,
) -> bool {
    println!("N_SIZE: {}", L::N_SIZE);
    println!("A_SIZE: {}", L::A_SIZE);
    println!("p: {} bits", p.bits());
    println!("q: {} bits", q.bits());
    println!("alpha: {} bits", alpha.bits());

    p.bits() >= (L::N_SIZE / 2 - L::EPSILON_P_SIZE) as u64
        && q.bits() >= (L::N_SIZE / 2 - L::EPSILON_Q_SIZE) as u64
        && alpha.bits() >= (L::A_SIZE - L::EPSILON_A_SIZE) as u64
}
