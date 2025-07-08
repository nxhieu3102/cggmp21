use generic_ec::{Curve, Scalar};
use paillier_zk::{
    batch_paillier_affine_operation_in_range as pi_aff_batch,
    batch_paillier_encryption_in_range_with_el_gamal as pi_enc_el_gamal_batch,
};
use round_based::rounds_router::simple_store::RoundMsgs;
use round_based::{MsgId, PartyIndex};

use crate::security_level::SecurityLevel;
use malachite::Integer;
use malachite::base::num::basic::traits::One;
use malachite::base::num::logic::traits::SignificantBits;


pub struct SecurityParams {
    pub pi_aff_batch: pi_aff_batch::SecurityParams,
    pub pi_enc_el_gamal_batch: pi_enc_el_gamal_batch::SecurityParams,
}

impl SecurityParams {
    pub fn new<L: SecurityLevel>() -> Self {
        Self {
            pi_aff_batch: pi_aff_batch::SecurityParams {
                l_x: L::ELL,
                l_y: L::ELL_PRIME,
                epsilon: L::EPSILON,
                q: L::q(),
                t: 128,
            },
            pi_enc_el_gamal_batch: pi_enc_el_gamal_batch::SecurityParams {
                l: L::ELL,
                epsilon: L::EPSILON,
                q: L::q(),
                t: 128,
            },
        }
    }
}

pub fn xor_array<A, B>(mut a: A, b: B) -> A
where
    A: AsMut<[u8]>,
    B: AsRef<[u8]>,
{
    a.as_mut()
        .iter_mut()
        .zip(b.as_ref())
        .for_each(|(a_i, b_i)| *a_i ^= *b_i);
    a
}

/// For some messages it is possible to precisely identify where the fault
/// happened and which party is to blame. Use this struct to collect present the
/// blame.
///
/// In the future we might want to replace the data_message and proof_message
/// with a generic vec of messages.
#[derive(Debug)]
#[allow(dead_code)] // removes false-positive warnings
pub struct AbortBlame {
    /// Party which can be blamed for breaking the protocol
    pub faulty_party: PartyIndex,
    /// Message with initial data
    pub data_message: MsgId,
    /// Message with some kind of proof related to the data
    pub proof_message: MsgId,
}

impl AbortBlame {
    pub fn new(faulty_party: PartyIndex, data_message: MsgId, proof_message: MsgId) -> Self {
        Self {
            faulty_party,
            data_message,
            proof_message,
        }
    }
}

/// Filter returns `true` for every __faulty__ message pair
pub fn collect_blame<D, P, F>(
    data_messages: &RoundMsgs<D>,
    proof_messages: &RoundMsgs<P>,
    mut filter: F,
) -> Vec<AbortBlame>
where
    F: FnMut(PartyIndex, &D, &P) -> bool,
{
    data_messages
        .iter_indexed()
        .zip(proof_messages.iter_indexed())
        .filter_map(|((j, data_msg_id, data), (_, proof_msg_id, proof))| {
            if filter(j, data, proof) {
                Some(AbortBlame::new(j, data_msg_id, proof_msg_id))
            } else {
                None
            }
        })
        .collect()
}

// /// 
// pub fn scalar_to_integer<E: Curve>(scalar: impl AsRef<Scalar<E>>) -> Integer {
//     let bytes = scalar.as_ref().to_be_bytes();
//     if scalar.as_ref().lt(&Scalar::zero()) {
//         BigInt::from_bytes_be(Sign::Minus, &bytes)
//     } else {
//         BigInt::from_bytes_be(Sign::Plus, &bytes)
//     }
// }

/// Filter returns `true` for every __faulty__ message. Data and proof are set
/// to the same message.
pub fn collect_simple_blame<D, F>(messages: &RoundMsgs<D>, mut filter: F) -> Vec<AbortBlame>
where
    F: FnMut(&D) -> bool,
{
    messages
        .iter_indexed()
        .filter_map(|(j, msg_id, data)| {
            if filter(data) {
                Some(AbortBlame::new(j, msg_id, msg_id))
            } else {
                None
            }
        })
        .collect()
}

/// Same as [`collect_blame`], but filter can fail, in which case whole blame
/// collection will fail. So to not lose security the error type should be some
/// kind of unrecoverable internal assertion failure.
pub fn try_collect_blame<E, D, P, F>(
    data_messages: &RoundMsgs<D>,
    proof_messages: &RoundMsgs<P>,
    mut filter: F,
) -> Result<Vec<AbortBlame>, E>
where
    F: FnMut(PartyIndex, &D, &P) -> Result<bool, E>,
{
    let mut r = Vec::new();
    for ((j, data_msg_id, data), (_, proof_msg_id, proof)) in data_messages
        .iter_indexed()
        .zip(proof_messages.iter_indexed())
    {
        if filter(j, data, proof)? {
            r.push(AbortBlame::new(j, data_msg_id, proof_msg_id));
        }
    }
    Ok(r)
}

/// Iterate peers of i-th party
pub fn iter_peers(i: u16, n: u16) -> impl Iterator<Item = u16> {
    (0..n).filter(move |x| *x != i)
}

/// Drop n-th item from iteration
pub fn but_nth<T, I: IntoIterator<Item = T>>(n: u16, iter: I) -> impl Iterator<Item = T> {
    iter.into_iter()
        .enumerate()
        .filter(move |(i, _)| *i != usize::from(n))
        .map(|(_, x)| x)
}

/// Binary search for rounded down square root. For non-positive numbers returns
/// one
// pub fn sqrt(x: &BigInt) -> BigInt {
//     if x <= &BigInt::ZERO {
//         BigInt::one()
//     } else {
//         x.sqrt()
//     }
// }

/// Partition into vector of errors and vector of values
pub fn partition_results<I, A, B>(iter: I) -> (Vec<A>, Vec<B>)
where
    I: Iterator<Item = Result<A, B>>,
{
    let mut oks = Vec::new();
    let mut errs = Vec::new();
    for i in iter {
        match i {
            Ok(ok) => oks.push(ok),
            Err(err) => errs.push(err),
        }
    }
    (oks, errs)
}

/// Returns `[list[indexes[0]], list[indexes[1]], ..., list[indexes[n-1]]]`
///
/// Result is `None` if any of `indexes[i]` is out of range of `list`
pub fn subset<T: Clone, I: Into<usize> + Copy>(indexes: &[I], list: &[T]) -> Option<Vec<T>> {
    indexes
        .iter()
        .map(|&i| list.get(i.into()).cloned())
        .collect()
}


/// Generates **unsafe** blum primes
///
/// Blum primes are faster to generate than safe primes, and they don't break correctness of CGGMP protocol.
/// However, they do break security of the protocol.
///
/// Only supposed to be used in the tests.

// TODO: fix this
// #[cfg(test)]
// pub fn generate_blum_prime(rng: &mut impl rand_core::RngCore, bits_size: u32) -> BigInt {
//     loop {
//         let n = rng.gen
//         let mut n: BigInt = BigInt::random_bits(bits_size, &mut external_rand(rng)).into();
//         n.set_bit(bits_size - 1, true);
//         n.next_prime_mut();

//         if n.mod_u(4) == 3 {
//             break n;
//         }
//     }
// }

/// Unambiguous encoding for different types for which it was not defined
pub mod encoding {
    use paillier_zk::integer_ext::IntegerExt;
    use paillier_zk::fast_paillier::AnyEncryptionKey;
    pub struct Integer;
    impl udigest::DigestAs<malachite::Integer> for Integer {
        fn digest_as<B: udigest::Buffer>(
            value: &malachite::Integer,
            encoder: udigest::encoding::EncodeValue<B>,
        ) {
            let bytes = value.to_bytes();
            encoder.encode_leaf_value(bytes)
        }
    }

    pub struct EncryptionKey;
    impl udigest::DigestAs<paillier_zk::fast_paillier::EncryptionKey> for EncryptionKey {
        fn digest_as<B: udigest::Buffer>(
            x: &paillier_zk::fast_paillier::EncryptionKey,
            encoder: udigest::encoding::EncodeValue<B>,
        ) {
            // Encode as a structured sequence of fields
            let mut encoder = encoder.encode_struct();

            // Encode unsigned integer fields
            encoder
                .add_field("n_size")
                .encode_leaf_value(x.n_size().to_be_bytes());
            encoder
                .add_field("a_size")
                .encode_leaf_value(x.a_size().to_be_bytes());
            encoder
                .add_field("nounce_size")
                .encode_leaf_value(x.nounce_size().to_be_bytes());

            // Encode rug::Integer fields using most-significant-first byte order
            encoder
                .add_field("h")
                .encode_leaf_value(x.h().to_scalar_bytes());
            encoder
                .add_field("n")
                .encode_leaf_value(x.n().to_scalar_bytes());
            encoder
                .add_field("nn")
                .encode_leaf_value(x.nn().to_scalar_bytes());
            encoder
                .add_field("h_pow_n")
                .encode_leaf_value(x.h_pow_n().to_scalar_bytes());
            encoder
                .add_field("half_n")
                .encode_leaf_value(x.half_n().to_scalar_bytes());
            encoder
                .add_field("neg_half_n")
                .encode_leaf_value(x.neg_half_n().to_scalar_bytes());

            encoder.finish()
        }
    }
}

// #[cfg(test)]
// mod test {
//     use num_bigint::{RandBigInt};

//     #[test]
//     fn test_sqrt() {
//         use super::{sqrt, BigInt};
//         assert_eq!(sqrt(&BigInt::from(-5)), BigInt::from(1));
//         assert_eq!(sqrt(&BigInt::from(1)), BigInt::from(1));
//         assert_eq!(sqrt(&BigInt::from(2)), BigInt::from(1));
//         assert_eq!(sqrt(&BigInt::from(3)), BigInt::from(1));
//         assert_eq!(sqrt(&BigInt::from(4)), BigInt::from(2));
//         assert_eq!(sqrt(&BigInt::from(5)), BigInt::from(2));
//         assert_eq!(sqrt(&BigInt::from(6)), BigInt::from(2));
//         assert_eq!(sqrt(&BigInt::from(7)), BigInt::from(2));
//         assert_eq!(sqrt(&BigInt::from(8)), BigInt::from(2));
//         assert_eq!(sqrt(&BigInt::from(9)), BigInt::from(3));
//         assert_eq!(sqrt(&(BigInt::from(1) << 1024)), BigInt::from(1) << 512);

//         let modulo = (BigInt::from(1) << 1024_u32);
//         let mut rng = rand::thread_rng();
//         for _ in 0..100 {
//             let x = rng.gen_bigint_range(&BigInt::from(0), &modulo);
//             let root = sqrt(&x);
//             assert!(&root * &root <= x);
//             let root = root + 1u8;
//             assert!(&root * &root > x);
//         }
//     }
// }
