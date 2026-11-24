use generic_ec::{Curve, Scalar};
use num_bigint::{BigInt, Sign};
use num_traits::{One, Signed};
use paillier_zk::{
    batch_paillier_affine_operation_in_range as pi_aff_batch,
    batch_paillier_encryption_in_range_with_el_gamal as pi_enc_el_gamal_batch,
};
use round_based::rounds_router::simple_store::RoundMsgs;
use round_based::{MsgId, PartyIndex};

use crate::security_level::SecurityLevel;

/// Converts `&Scalar<E>` into BigInt
pub fn scalar_to_bignumber<E: Curve>(scalar: impl AsRef<Scalar<E>>) -> BigInt {
    BigInt::from_bytes_be(Sign::Plus, &scalar.as_ref().to_be_bytes())
}

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
                t: crate::security_level::BATCH_T,
            },
            pi_enc_el_gamal_batch: pi_enc_el_gamal_batch::SecurityParams {
                l: L::ELL,
                epsilon: L::EPSILON,
                q: L::q(),
                t: crate::security_level::BATCH_T,
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

/// Rounded down square root. For non-positive numbers returns one
pub fn sqrt(x: &BigInt) -> BigInt {
    if x.is_positive() {
        x.sqrt()
    } else {
        BigInt::one()
    }
}

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

/// [`serde_with`] adapter serializing [`BigInt`] in the canonical
/// [`serializable_bigint`](paillier_zk::fast_paillier::utils::serde_wrapper::serializable_bigint) format
pub struct SerdeBigInt;

impl serde_with::SerializeAs<BigInt> for SerdeBigInt {
    fn serialize_as<S: serde::Serializer>(x: &BigInt, serializer: S) -> Result<S::Ok, S::Error> {
        paillier_zk::fast_paillier::utils::serde_wrapper::serializable_bigint::serialize(
            x, serializer,
        )
    }
}

impl<'de> serde_with::DeserializeAs<'de, BigInt> for SerdeBigInt {
    fn deserialize_as<D: serde::Deserializer<'de>>(deserializer: D) -> Result<BigInt, D::Error> {
        paillier_zk::fast_paillier::utils::serde_wrapper::serializable_bigint::deserialize(
            deserializer,
        )
    }
}

/// Generates **unsafe** blum primes
///
/// Blum primes are faster to generate than safe primes, and they don't break correctness of CGGMP protocol.
/// However, they do break security of the protocol.
///
/// Only supposed to be used in the tests.
#[cfg(test)]
pub fn generate_blum_prime(rng: &mut impl rand_core::RngCore, bits_size: u32) -> BigInt {
    loop {
        let mut n = paillier_zk::fast_paillier::utils::sample_odd_with_size(rng, bits_size);
        n.set_bit(1, true);
        if paillier_zk::fast_paillier::utils::is_prime(&n) {
            break n;
        }
    }
}

/// Unambiguous encoding for different types for which it was not defined
pub mod encoding {
    use udigest::DigestAs;

    /// Sign-aware canonical integer encoding shared with `paillier-zk` transcripts
    pub use paillier_zk::encoding::BigInt as Integer;

    pub struct EncryptionKey;
    impl DigestAs<paillier_zk::fast_paillier::EncryptionKey> for EncryptionKey {
        fn digest_as<B: udigest::Buffer>(
            x: &paillier_zk::fast_paillier::EncryptionKey,
            encoder: udigest::encoding::EncodeValue<B>,
        ) {
            let mut encoder = encoder.encode_struct();
            encoder
                .add_field("n_size")
                .encode_leaf_value(x.n_size().to_be_bytes());
            encoder
                .add_field("a_size")
                .encode_leaf_value(x.a_size().to_be_bytes());
            encoder
                .add_field("nounce_size")
                .encode_leaf_value(x.nounce_size().to_be_bytes());
            // Remaining fields (`nn`, `half_n`, ...) are derived from `n` and `h`
            Integer::digest_as(x.h(), encoder.add_field("h"));
            Integer::digest_as(x.n(), encoder.add_field("n"));
            Integer::digest_as(x.h_pow_n(), encoder.add_field("h_pow_n"));
            encoder.finish()
        }
    }
}

#[cfg(test)]
mod test {
    use num_bigint::BigInt;
    use num_traits::One;

    #[test]
    fn test_sqrt() {
        use super::sqrt;
        for (x, expected) in [
            (-5, 1),
            (0, 1),
            (1, 1),
            (2, 1),
            (3, 1),
            (4, 2),
            (5, 2),
            (8, 2),
            (9, 3),
        ] {
            assert_eq!(sqrt(&BigInt::from(x)), BigInt::from(expected), "sqrt({x})");
        }
        assert_eq!(sqrt(&(BigInt::one() << 1024)), BigInt::one() << 512);

        let modulo = BigInt::one() << 1024;
        let mut rng = rand_dev::DevRng::new();
        for _ in 0..100 {
            let x = num_bigint::RandBigInt::gen_bigint_range(&mut rng, &BigInt::from(0), &modulo);
            let root = sqrt(&x);
            assert!(&root * &root <= x);
            let root = root + 1u8;
            assert!(&root * &root > x);
        }
    }
}
