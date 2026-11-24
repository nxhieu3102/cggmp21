/// A wrapper around BigInt that implements Serialize and Deserialize
pub mod serializable_bigint {
    use std::str::FromStr;

    use num_bigint::BigInt;
    use num_traits::Num;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    struct BigIntFormat {
        radix: u32,
        value: String,
    }

    /// Serialize a BigInt to a JSON object with radix and value
    pub fn serialize<S>(_value: &BigInt, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let format = BigIntFormat {
            radix: 16, // Default to base 16
            value: _value.to_str_radix(16),
        };
        format.serialize(serializer)
    }

    /// Deserialize a BigInt from a JSON object with radix and value
    pub fn deserialize<'de, D>(deserializer: D) -> Result<BigInt, D::Error>
    where
        D: Deserializer<'de>,
    {
        let format = BigIntFormat::deserialize(deserializer)?;
        BigInt::from_str_radix(&format.value, format.radix).map_err(Error::custom)
    }
}

/// Serialize a vector of BigInts to a string
pub mod serializable_vec_bigint {
    use num_bigint::BigInt;
    use num_traits::Num;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    struct VecBigIntFormat {
        radix: u32,
        value: String,
    }

    /// Serialize a vector of BigInts to a JSON object with radix and comma-separated values
    pub fn serialize<S>(_value: &[BigInt], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let format = VecBigIntFormat {
            radix: 16, // Default to base 16
            value: _value
                .iter()
                .map(|x| x.to_str_radix(16))
                .collect::<Vec<String>>()
                .join(","),
        };
        format.serialize(serializer)
    }

    /// Deserialize a vector of BigInts from a JSON object with radix and comma-separated values
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<BigInt>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let format = VecBigIntFormat::deserialize(deserializer)?;
        format
            .value
            .split(",")
            .map(|x| BigInt::from_str_radix(x, format.radix).map_err(Error::custom))
            .collect::<Result<Vec<BigInt>, D::Error>>()
    }
}

/// Serialize a vector of vectors of BigInts to a string
pub mod serializable_vec_vec_bigint {
    use num_bigint::BigInt;
    use num_traits::Num;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    struct VecVecBigIntFormat {
        radix: u32,
        value: String,
    }

    /// Serialize a vector of vectors of BigInts to a JSON object with radix and semicolon-separated values
    pub fn serialize<S>(_value: &Vec<Vec<BigInt>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let format = VecVecBigIntFormat {
            radix: 16, // Default to base 16
            value: _value
                .iter()
                .map(|x| {
                    x.iter()
                        .map(|y| y.to_str_radix(16))
                        .collect::<Vec<String>>()
                        .join(",")
                })
                .collect::<Vec<String>>()
                .join(";"),
        };
        format.serialize(serializer)
    }

    /// Deserialize a vector of vectors of BigInts from a JSON object with radix and semicolon-separated values
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Vec<BigInt>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let format = VecVecBigIntFormat::deserialize(deserializer)?;
        format
            .value
            .split(";")
            .map(|x| {
                x.split(",")
                    .map(|y| BigInt::from_str_radix(y, format.radix).map_err(Error::custom))
                    .collect::<Result<Vec<BigInt>, D::Error>>()
            })
            .collect::<Result<Vec<Vec<BigInt>>, D::Error>>()
    }
}

/// Serialize a array of BigInts to a string
pub mod serializable_array_bigint {
    use num_bigint::BigInt;
    use num_traits::Num;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    struct ArrayBigIntFormat {
        radix: u32,
        value: String,
    }

    /// Serialize an array of BigInts to a JSON object with radix and comma-separated values
    pub fn serialize<S, const N: usize>(
        _value: &[BigInt; N],
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let format = ArrayBigIntFormat {
            radix: 16, // Default to base 16
            value: _value
                .iter()
                .map(|x| x.to_str_radix(16))
                .collect::<Vec<String>>()
                .join(","),
        };
        format.serialize(serializer)
    }

    /// Deserialize an array of BigInts from a JSON object with radix and comma-separated values
    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[BigInt; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let format = ArrayBigIntFormat::deserialize(deserializer)?;
        let values = format
            .value
            .split(",")
            .map(|x| BigInt::from_str_radix(x, format.radix).map_err(Error::custom))
            .collect::<Result<Vec<BigInt>, D::Error>>()?;
        if values.len() != N {
            return Err(D::Error::custom(format!(
                "Expected array of length {}, got {}",
                N,
                values.len()
            )));
        }
        let mut result = [BigInt::ZERO; N];
        for (i, value) in values.iter().enumerate() {
            result[i] = value.clone();
        }
        Ok(result)
    }
}
