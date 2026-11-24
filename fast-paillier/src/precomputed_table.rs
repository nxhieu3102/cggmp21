//! Fixed-base exponentiation table, used to speed up encryption under a known key
//!
//! `table[i][j] = base^(j · 2^(i·block_size)) mod modulo` for `i < ceil(pow_size / block_size)`
//! and `j < 2^block_size`. An exponent of at most `pow_size` bits is split into
//! `block_size`-bit digits and `base^exp` is the product of one entry per non-zero digit, i.e. at
//! most `ceil(pow_size / block_size)` modular multiplications and no squarings.
//!
//! Memory is `ceil(pow_size / block_size) · 2^block_size` residues. For a 3072-bit Paillier key
//! (`modulo = N²`, 768 bytes per entry) and 512-bit nonces:
//!
//! | `block_size` | entries | memory  | multiplications per encryption |
//! |--------------|---------|---------|--------------------------------|
//! | 4            | 2048    | ~1.6 MB | ≤ 128                          |
//! | 6 (default)  | 5504    | ~4.4 MB | ≤ 86                           |
//! | 8            | 16384   | ~13 MB  | ≤ 64                           |
//! | 10           | 53248   | ~43 MB  | ≤ 52                           |
//!
//! Building the table costs one modular multiplication per entry. Lookups and the skipping of
//! zero digits depend on the exponent, so this path is not constant-time.

use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
use num_traits::One;

use crate::{Error, Reason};

/// A table of precomputed powers of a fixed base, see the [module docs](self)
#[derive(Clone, Debug)]
pub struct PrecomputeTable {
    pow_size: usize,
    block_size: usize,
    modulo: BigInt,
    table: Vec<Vec<BigInt>>,
}

impl PrecomputeTable {
    /// Recommended block size: ~4.4 MB per 3072-bit key, ~6x fewer multiplications than a plain
    /// exponentiation with a 512-bit exponent
    pub const DEFAULT_BLOCK_SIZE: usize = 6;
    /// Largest supported block size (rows of `2^16` entries)
    pub const MAX_BLOCK_SIZE: usize = 16;

    /// Builds a table of powers of `g` modulo `modulo` for exponents of up to `pow_size` bits
    ///
    /// Returns an error if `block_size` is not in `1..=MAX_BLOCK_SIZE`, `pow_size == 0`, or
    /// `modulo <= 1`.
    pub fn new(
        g: BigInt,
        block_size: usize,
        pow_size: usize,
        modulo: BigInt,
    ) -> Result<Self, Error> {
        Self::check_params(block_size, pow_size, &modulo)?;
        let rows = pow_size.div_ceil(block_size);
        let width = 1usize << block_size;

        let mut table = Vec::with_capacity(rows);
        // base of the current row: g^(2^(i·block_size))
        let mut row_base = g.mod_floor(&modulo);
        for _ in 0..rows {
            let mut row = Vec::with_capacity(width);
            row.push(BigInt::one());
            row.push(row_base.clone());
            for j in 2..width {
                let next = (&row[j - 1] * &row_base) % &modulo;
                row.push(next);
            }
            row_base = (&row[width - 1] * &row_base) % &modulo;
            table.push(row);
        }

        Ok(Self {
            pow_size,
            block_size,
            modulo,
            table,
        })
    }

    fn check_params(block_size: usize, pow_size: usize, modulo: &BigInt) -> Result<(), Error> {
        if !(1..=Self::MAX_BLOCK_SIZE).contains(&block_size)
            || pow_size == 0
            || *modulo <= BigInt::one()
        {
            return Err(Reason::PrecomputeTable.into());
        }
        Ok(())
    }

    /// Computes `base^exp mod modulo`. Returns `None` if `exp` has more than `pow_size` bits.
    pub(crate) fn pow(&self, exp: &BigUint) -> Option<BigUint> {
        if exp.bits() > self.pow_size as u64 {
            return None;
        }
        let digits: Vec<u64> = exp.iter_u64_digits().collect();
        let mut acc: Option<BigInt> = None;
        for (i, row) in self.table.iter().enumerate() {
            let digit = extract_bits(&digits, i * self.block_size, self.block_size);
            if digit == 0 {
                continue;
            }
            let entry = &row[digit];
            acc = Some(match acc {
                None => entry.clone(),
                Some(acc) => (acc * entry) % &self.modulo,
            });
        }
        let acc = acc.unwrap_or_else(|| BigInt::one() % &self.modulo);
        Some(acc.into_parts().1)
    }

    /// Approximate heap + inline size of the table in bytes
    pub fn size_in_bytes(&self) -> usize {
        self.table
            .iter()
            .flatten()
            .map(|x| core::mem::size_of::<BigInt>() + x.bits().div_ceil(64) as usize * 8)
            .sum()
    }

    /// Returns the block size used in this precomputed table.
    pub fn block_size(&self) -> usize {
        self.block_size
    }

    /// Returns the maximum power size in bits used in this precomputed table.
    pub fn pow_size(&self) -> usize {
        self.pow_size
    }

    /// Returns a reference to the inner table of precomputed values.
    pub fn table(&self) -> &Vec<Vec<BigInt>> {
        &self.table
    }

    /// Returns a reference to the modulus used for calculations.
    pub fn modulo(&self) -> &BigInt {
        &self.modulo
    }
}

/// Bits `[start, start + len)` of the little-endian `digits` (`len <= 16`)
fn extract_bits(digits: &[u64], start: usize, len: usize) -> usize {
    let (limb, offset) = (start / 64, start % 64);
    let lo = digits.get(limb).copied().unwrap_or(0) >> offset;
    let hi = if offset + len > 64 {
        digits.get(limb + 1).copied().unwrap_or(0) << (64 - offset)
    } else {
        0
    };
    ((lo | hi) & ((1u64 << len) - 1)) as usize
}

#[cfg(feature = "serde")]
mod serde_impl {
    use super::PrecomputeTable;
    use crate::utils::serde_wrapper::{serializable_bigint, serializable_vec_vec_bigint};
    use num_bigint::{BigInt, Sign};

    #[derive(serde::Serialize)]
    struct ReprRef<'a> {
        pow_size: usize,
        block_size: usize,
        #[serde(with = "serializable_bigint")]
        modulo: &'a BigInt,
        #[serde(with = "serializable_vec_vec_bigint")]
        table: &'a [Vec<BigInt>],
    }

    #[derive(serde::Deserialize)]
    struct Repr {
        pow_size: usize,
        block_size: usize,
        #[serde(with = "serializable_bigint")]
        modulo: BigInt,
        #[serde(with = "serializable_vec_vec_bigint")]
        table: Vec<Vec<BigInt>>,
    }

    impl serde::Serialize for PrecomputeTable {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            ReprRef {
                pow_size: self.pow_size,
                block_size: self.block_size,
                modulo: &self.modulo,
                table: &self.table,
            }
            .serialize(serializer)
        }
    }

    /// Checks the shape of the table and that every entry is reduced. The entries themselves are
    /// trusted (tables are local data).
    impl<'de> serde::Deserialize<'de> for PrecomputeTable {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            use serde::de::Error;
            let repr = Repr::deserialize(deserializer)?;
            PrecomputeTable::check_params(repr.block_size, repr.pow_size, &repr.modulo)
                .map_err(D::Error::custom)?;
            let rows = repr.pow_size.div_ceil(repr.block_size);
            let width = 1usize << repr.block_size;
            let well_formed = repr.table.len() == rows
                && repr.table.iter().all(|row| {
                    row.len() == width
                        && row
                            .iter()
                            .all(|x| x.sign() != Sign::Minus && *x < repr.modulo)
                });
            if !well_formed {
                return Err(D::Error::custom("malformed precompute table"));
            }
            Ok(PrecomputeTable {
                pow_size: repr.pow_size,
                block_size: repr.block_size,
                modulo: repr.modulo,
                table: repr.table,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PrecomputeTable;
    use num_bigint::{BigInt, BigUint, RandBigInt};

    #[test]
    fn table_values() {
        let table = PrecomputeTable::new(BigInt::from(2), 2, 4, BigInt::from(7)).unwrap();
        // rows: 2^(j), 2^(4j) mod 7
        let expected: Vec<Vec<BigInt>> = [[1, 2, 4, 1], [1, 2, 4, 1]]
            .iter()
            .map(|row| row.iter().map(|&x| BigInt::from(x)).collect())
            .collect();
        assert_eq!(table.table(), &expected);

        let table = PrecomputeTable::new(BigInt::from(-3), 3, 7, BigInt::from(1000)).unwrap();
        assert_eq!(table.table().len(), 3);
        for (i, row) in table.table().iter().enumerate() {
            assert_eq!(row.len(), 8);
            for (j, x) in row.iter().enumerate() {
                let e = BigInt::from(j) << (3 * i);
                assert_eq!(*x, BigInt::from(997).modpow(&e, &BigInt::from(1000)));
            }
        }
    }

    #[test]
    fn pow_matches_modpow() {
        let mut rng = rand_dev::DevRng::new();
        let mut modulo = BigInt::from(rng.gen_biguint(1000));
        modulo.set_bit(0, true);
        let base = BigInt::from(rng.gen_biguint_below(modulo.magnitude()));
        for block_size in [1usize, 3, 5, 6, 8, 13, 16] {
            for pow_size in [1usize, 63, 64, 65, 200] {
                if block_size == 16 && pow_size > 64 {
                    continue;
                }
                let table =
                    PrecomputeTable::new(base.clone(), block_size, pow_size, modulo.clone())
                        .unwrap();
                assert_eq!(table.table().len(), pow_size.div_ceil(block_size));
                for exp_bits in [0u64, 1, pow_size as u64 / 2, pow_size as u64] {
                    let exp = rng.gen_biguint(exp_bits);
                    let expected = base.magnitude().modpow(&exp, modulo.magnitude());
                    assert_eq!(table.pow(&exp), Some(expected));
                }
                let too_big = BigUint::from(1u8) << pow_size;
                assert_eq!(table.pow(&too_big), None);
            }
        }
    }

    #[test]
    fn rejects_invalid_parameters() {
        let m = BigInt::from(101);
        let g = BigInt::from(3);
        assert!(PrecomputeTable::new(g.clone(), 0, 10, m.clone()).is_err());
        assert!(PrecomputeTable::new(g.clone(), 17, 10, m.clone()).is_err());
        assert!(PrecomputeTable::new(g.clone(), 4, 0, m.clone()).is_err());
        assert!(PrecomputeTable::new(g.clone(), 4, 10, BigInt::from(1)).is_err());
        assert!(PrecomputeTable::new(g, 4, 10, BigInt::from(-101)).is_err());
    }

    #[test]
    fn size_in_bytes() {
        let mut modulo = BigInt::from(1) << 1000u32;
        modulo += 1;
        let base = (BigInt::from(1) << 999u32) + 12345;
        let table = PrecomputeTable::new(base, 4, 64, modulo).unwrap();
        // 16 rows of 16 entries; all but the `1`s are ~1000 bits = 16 limbs
        let size = table.size_in_bytes();
        let header = core::mem::size_of::<BigInt>();
        assert!(size > 16 * 15 * (header + 15 * 8));
        assert!(size <= 16 * 16 * (header + 16 * 8));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_round_trip_and_validation() {
        let table = PrecomputeTable::new(BigInt::from(5), 3, 10, BigInt::from(1009)).unwrap();
        let json = serde_json::to_string(&table).unwrap();
        let back: PrecomputeTable = serde_json::from_str(&json).unwrap();
        assert_eq!(back.table(), table.table());
        assert_eq!(back.modulo(), table.modulo());
        assert_eq!((back.pow_size(), back.block_size()), (10, 3));

        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value["block_size"] = 64.into();
        assert!(serde_json::from_value::<PrecomputeTable>(value).is_err());

        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value["table"].as_array_mut().unwrap().pop();
        assert!(serde_json::from_value::<PrecomputeTable>(value).is_err());

        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value["table"][0][2] = serde_json::json!({"radix": 16, "value": "fffff"});
        assert!(serde_json::from_value::<PrecomputeTable>(value).is_err());
    }
}
