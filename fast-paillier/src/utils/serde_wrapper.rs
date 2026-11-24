//! Serde adapters for [`BigInt`](num_bigint::BigInt), to be used with `#[serde(with = "...")]`
//!
//! The wire format is compatible with `rug::Integer`'s serde format: every integer is an object
//! `{"radix": <u32>, "value": "<digits>"}`. Integers are written in radix 16; any radix in
//! `2..=36` is accepted on read (rug writes radix 10 for small values). Collections are
//! sequences of such objects.

use num_bigint::BigInt;
use num_traits::Num;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Serialize)]
struct BigIntRef<'a> {
    radix: u32,
    value: &'a str,
}

#[derive(Deserialize)]
struct BigIntOwned {
    radix: u32,
    value: String,
}

/// `BigInt` serialized in the `{radix, value}` format
struct Ser<'a>(&'a BigInt);

impl Serialize for Ser<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializable_bigint::serialize(self.0, serializer)
    }
}

/// `BigInt` deserialized from the `{radix, value}` format
struct De(BigInt);

impl<'de> Deserialize<'de> for De {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        serializable_bigint::deserialize(deserializer).map(De)
    }
}

/// Scalar `BigInt` as `{"radix": 16, "value": "<hex>"}`
pub mod serializable_bigint {
    use super::*;

    /// Serializes a `BigInt` as `{"radix": 16, "value": "<hex>"}`
    pub fn serialize<S: Serializer>(value: &BigInt, serializer: S) -> Result<S::Ok, S::Error> {
        BigIntRef {
            radix: 16,
            value: &value.to_str_radix(16),
        }
        .serialize(serializer)
    }

    /// Deserializes a `BigInt` from `{"radix": r, "value": "<digits>"}`, `r` in `2..=36`
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<BigInt, D::Error> {
        let BigIntOwned { radix, value } = BigIntOwned::deserialize(deserializer)?;
        if !(2..=36).contains(&radix) {
            return Err(D::Error::custom(format_args!("invalid radix {radix}")));
        }
        BigInt::from_str_radix(&value, radix).map_err(D::Error::custom)
    }
}

/// `Vec<BigInt>` as a sequence of [`serializable_bigint`] objects
pub mod serializable_vec_bigint {
    use super::*;

    /// Serializes a slice of `BigInt`s
    pub fn serialize<S: Serializer>(value: &[BigInt], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(value.iter().map(Ser))
    }

    /// Deserializes a `Vec<BigInt>`
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<BigInt>, D::Error> {
        let values = Vec::<De>::deserialize(deserializer)?;
        Ok(values.into_iter().map(|De(x)| x).collect())
    }
}

/// `Vec<Vec<BigInt>>` as a sequence of sequences of [`serializable_bigint`] objects
pub mod serializable_vec_vec_bigint {
    use super::*;

    /// Serializes a vector of vectors of `BigInt`s
    pub fn serialize<S: Serializer>(
        value: &[Vec<BigInt>],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(value.iter().map(|row| VecSer(row)))
    }

    /// Deserializes a `Vec<Vec<BigInt>>`
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<Vec<BigInt>>, D::Error> {
        let rows = Vec::<Vec<De>>::deserialize(deserializer)?;
        Ok(rows
            .into_iter()
            .map(|row| row.into_iter().map(|De(x)| x).collect())
            .collect())
    }

    struct VecSer<'a>(&'a [BigInt]);

    impl Serialize for VecSer<'_> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            super::serializable_vec_bigint::serialize(self.0, serializer)
        }
    }
}

/// `[BigInt; N]` as a sequence of exactly `N` [`serializable_bigint`] objects
pub mod serializable_array_bigint {
    use super::*;

    /// Serializes an array of `BigInt`s
    pub fn serialize<S: Serializer, const N: usize>(
        value: &[BigInt; N],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(value.iter().map(Ser))
    }

    /// Deserializes an array of `BigInt`s, rejecting sequences of the wrong length
    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        deserializer: D,
    ) -> Result<[BigInt; N], D::Error> {
        let values = super::serializable_vec_bigint::deserialize(deserializer)?;
        let len = values.len();
        values
            .try_into()
            .map_err(|_| D::Error::custom(format_args!("expected array of length {N}, got {len}")))
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::BigInt;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Scalar(#[serde(with = "super::serializable_bigint")] BigInt);

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Vector(#[serde(with = "super::serializable_vec_bigint")] Vec<BigInt>);

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Matrix(#[serde(with = "super::serializable_vec_vec_bigint")] Vec<Vec<BigInt>>);

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Array(#[serde(with = "super::serializable_array_bigint")] [BigInt; 3]);

    fn samples() -> Vec<BigInt> {
        vec![
            BigInt::from(0),
            BigInt::from(-1),
            BigInt::from(255),
            BigInt::from(-255),
            BigInt::from(1) << 3000u32,
            -(BigInt::from(3) << 777u32),
        ]
    }

    #[test]
    fn scalar_format_and_round_trip() {
        assert_eq!(
            serde_json::to_string(&Scalar(BigInt::from(-255))).unwrap(),
            r#"{"radix":16,"value":"-ff"}"#
        );
        for x in samples() {
            let json = serde_json::to_string(&Scalar(x.clone())).unwrap();
            assert_eq!(serde_json::from_str::<Scalar>(&json).unwrap(), Scalar(x));
        }
    }

    #[test]
    fn reads_rug_format() {
        let x: Scalar = serde_json::from_str(r#"{"radix":16,"value":"-ff"}"#).unwrap();
        assert_eq!(x.0, BigInt::from(-255));
        let x: Scalar = serde_json::from_str(r#"{"radix":10,"value":"-12345"}"#).unwrap();
        assert_eq!(x.0, BigInt::from(-12345));
        let x: Scalar = serde_json::from_str(r#"{"radix":36,"value":"z"}"#).unwrap();
        assert_eq!(x.0, BigInt::from(35));
        let v: Vector =
            serde_json::from_str(r#"[{"radix":10,"value":"7"},{"radix":16,"value":"-a"}]"#)
                .unwrap();
        assert_eq!(v.0, vec![BigInt::from(7), BigInt::from(-10)]);
    }

    #[test]
    fn malformed_scalars_are_errors() {
        for json in [
            r#"{"radix":99,"value":"ff"}"#,
            r#"{"radix":0,"value":"0"}"#,
            r#"{"radix":1,"value":"0"}"#,
            r#"{"radix":37,"value":"0"}"#,
            r#"{"radix":-16,"value":"ff"}"#,
            r#"{"radix":16,"value":""}"#,
            r#"{"radix":16,"value":"-"}"#,
            r#"{"radix":16,"value":"xyz"}"#,
            r#"{"radix":10,"value":"ff"}"#,
            r#"{"radix":16}"#,
            r#"{"value":"ff"}"#,
            r#""ff""#,
            r#"255"#,
        ] {
            assert!(serde_json::from_str::<Scalar>(json).is_err(), "{json}");
        }
    }

    #[test]
    fn vectors_round_trip() {
        for v in [vec![], vec![BigInt::from(1)], samples()] {
            let json = serde_json::to_string(&Vector(v.clone())).unwrap();
            assert_eq!(serde_json::from_str::<Vector>(&json).unwrap(), Vector(v));
        }
        assert_eq!(serde_json::to_string(&Vector(vec![])).unwrap(), "[]");
        assert!(serde_json::from_str::<Vector>(r#"[{"radix":99,"value":"1"}]"#).is_err());
        assert!(serde_json::from_str::<Vector>(r#"{"radix":16,"value":"1,2"}"#).is_err());

        for m in [vec![], vec![vec![]], vec![samples(), vec![], samples()]] {
            let json = serde_json::to_string(&Matrix(m.clone())).unwrap();
            assert_eq!(serde_json::from_str::<Matrix>(&json).unwrap(), Matrix(m));
        }
    }

    #[test]
    fn arrays_round_trip_and_check_length() {
        let a = Array([BigInt::from(1), BigInt::from(-2), BigInt::from(3) << 100u32]);
        let json = serde_json::to_string(&a).unwrap();
        assert_eq!(serde_json::from_str::<Array>(&json).unwrap(), a);
        let short = serde_json::to_string(&Vector(vec![BigInt::from(1)])).unwrap();
        assert!(serde_json::from_str::<Array>(&short).is_err());
        let long = serde_json::to_string(&Vector(samples())).unwrap();
        assert!(serde_json::from_str::<Array>(&long).is_err());
    }
}
