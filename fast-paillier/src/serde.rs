use crate::{DecryptionKey, EncryptionKey, Error, Reason};
use num_bigint::BigInt;
use num_traits::Num;
use serde::de::{self};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

// Serializable representation of EncryptionKey
#[derive(Serialize, Deserialize)]
struct SerializableEncryptionKey {
    n_size: u32,
    a_size: u32,
    nounce_size: u32,
    h: String,
    n: String,
    nn: String,
    h_pow_n: String,
    half_n: String,
    neg_half_n: String,
}

// Serializable representation of DecryptionKey
#[derive(Serialize, Deserialize)]
struct SerializableDecryptionKey {
    ek: SerializableEncryptionKey,
    p: String,
    q: String,
    alpha: String,
}

// Convert BigInt to hex string
fn integer_to_hex(value: &BigInt) -> String {
    format!("{:x}", value)
}

// Convert hex string to BigInt
fn hex_to_integer(hex: &str) -> Result<BigInt, Error> {
    BigInt::from_str_radix(hex, 16).map_err(|_| Error::from(Reason::Ops))
}

impl Serialize for EncryptionKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let serializable = SerializableEncryptionKey {
            n_size: self.n_size(),
            a_size: self.a_size(),
            nounce_size: self.nounce_size(),
            h: integer_to_hex(self.h()),
            n: integer_to_hex(self.n()),
            nn: integer_to_hex(self.nn()),
            h_pow_n: integer_to_hex(self.h_pow_n()),
            half_n: integer_to_hex(self.half_n()),
            neg_half_n: integer_to_hex(self.neg_half_n()),
        };

        serializable.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for EncryptionKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let serializable = SerializableEncryptionKey::deserialize(deserializer)?;

        let h = hex_to_integer(&serializable.h).map_err(de::Error::custom)?;
        let n = hex_to_integer(&serializable.n).map_err(de::Error::custom)?;

        EncryptionKey::new(serializable.n_size, serializable.a_size, h, n)
            .map_err(de::Error::custom)
    }
}

impl Serialize for DecryptionKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let serializable = SerializableDecryptionKey {
            ek: SerializableEncryptionKey {
                n_size: self.encryption_key().n_size(),
                a_size: self.encryption_key().a_size(),
                nounce_size: self.encryption_key().nounce_size(),
                h: integer_to_hex(self.encryption_key().h()),
                n: integer_to_hex(self.encryption_key().n()),
                nn: integer_to_hex(self.encryption_key().nn()),
                h_pow_n: integer_to_hex(self.encryption_key().h_pow_n()),
                half_n: integer_to_hex(self.encryption_key().half_n()),
                neg_half_n: integer_to_hex(self.encryption_key().neg_half_n()),
            },
            p: integer_to_hex(self.p()),
            q: integer_to_hex(self.q()),
            alpha: integer_to_hex(self.alpha()),
        };

        serializable.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DecryptionKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let serializable = SerializableDecryptionKey::deserialize(deserializer)?;

        let h = hex_to_integer(&serializable.ek.h).map_err(de::Error::custom)?;
        let n = hex_to_integer(&serializable.ek.n).map_err(de::Error::custom)?;

        let ek = EncryptionKey::new(serializable.ek.n_size, serializable.ek.a_size, h, n)
            .map_err(de::Error::custom)?;

        let p = hex_to_integer(&serializable.p).map_err(de::Error::custom)?;
        let q = hex_to_integer(&serializable.q).map_err(de::Error::custom)?;
        let alpha = hex_to_integer(&serializable.alpha).map_err(de::Error::custom)?;

        DecryptionKey::new(ek, p, q, alpha).map_err(de::Error::custom)
    }
}

// Helper methods for easy conversion to/from JSON strings
#[cfg(feature = "serde")]
impl EncryptionKey {
    /// Serialize the EncryptionKey to a JSON string
    pub fn to_json(&self) -> Result<String, Error> {
        serde_json::to_string(self).map_err(|_| Error::from(Reason::Ops))
    }

    /// Deserialize an EncryptionKey from a JSON string
    pub fn from_json(json: &str) -> Result<Self, Error> {
        serde_json::from_str(json).map_err(|_| Error::from(Reason::Ops))
    }
}

#[cfg(feature = "serde")]
impl DecryptionKey {
    /// Serialize the DecryptionKey to a JSON string
    pub fn to_json(&self) -> Result<String, Error> {
        serde_json::to_string(self).map_err(|_| Error::from(Reason::Ops))
    }

    /// Deserialize a DecryptionKey from a JSON string
    pub fn from_json(json: &str) -> Result<Self, Error> {
        serde_json::from_str(json).map_err(|_| Error::from(Reason::Ops))
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{AnyEncryptionKey, DecryptionKey};

    #[test]
    fn test_encryption_key_serialization() {
        // Sample a known key
        let ek = EncryptionKey::sample_112();

        // Serialize to JSON string for testing
        let json = ek.to_json().unwrap();

        // Deserialize back
        let deserialized_ek = EncryptionKey::from_json(&json).unwrap();

        // Check key properties are preserved
        assert_eq!(ek.n_size(), deserialized_ek.n_size());
        assert_eq!(ek.a_size(), deserialized_ek.a_size());
        assert_eq!(ek.n().to_string(), deserialized_ek.n().to_string());
        assert_eq!(ek.h().to_string(), deserialized_ek.h().to_string());
    }

    #[test]
    fn test_decryption_key_serialization() {
        // Sample a known key
        let dk = DecryptionKey::sample_112();

        // Serialize to JSON string for testing
        let json = dk.to_json().unwrap();

        // Deserialize back
        let deserialized_dk = DecryptionKey::from_json(&json).unwrap();

        // Check key properties are preserved
        assert_eq!(dk.p().to_string(), deserialized_dk.p().to_string());
        assert_eq!(dk.q().to_string(), deserialized_dk.q().to_string());
        assert_eq!(dk.alpha().to_string(), deserialized_dk.alpha().to_string());
        assert_eq!(dk.n().to_string(), deserialized_dk.n().to_string());
    }

    #[test]
    fn test_encryption_key_deserialization() {
        let json = r#"{
            "n_size": 3072,
            "a_size": 512,
            "nounce_size": 512,
            "h": "-1182e8d35c338ce4cafa9eb594c5c6746fb0d738f8e4c2f48a40e53a21bb33725869adaf23282de264d9cadc92bb271f7b18b9862794ca25b28c333720e89774f5d2a6def4fa29852c9cd50cab69ae9bf9a088d98788cf0a6df0e68315567d08b1d3b71d91d2b34ed990daa668d598d324d5dde4f71fccf51812f7d923ea78951a1c53fe3f3c7327543c6cdb83b9eddcf295ceeb3ad097d87dc6b698e960f1e3d4637b1a7ffa5dd9b77c6046a6d03fe7e688553cdaba63d5bd22d5a58097a141b8ebb5ef6ca153309072d52338bdc72f977409dcc73c6038965cf9b190b95051f1ced9ea1b819a0cee8fdb1cea847f7b51d29cbf2bde90dabfd8943c8a5100c6fc3983d9e6de708c1dac58d92668f8aaa15fd686e361236350438aa9d383b4975fac0b5292435a0c82a36e54aba6a454df27092cae25be6a36a038caf125e4be95d464b8986d24131e142af9b6a5b9988a184cdc52f7b1394b700ea5e2bd365b2fb4e363dd40a56426fb6ec842b9da6bf68e4bd29938a4f9b8041606f910a0a5",
            "n": "45c9716df056836d704203e4126bb63d7b1828c2c64923f675dca762ed509810fe5cee0c1b69159fc1511fa8a049874a32c606217ab25dfb093553d295de4edc149c7103a4be418d4643fc3fab64c78486afe72080472f25d5e668416697a77f46fcef41bfc8d55960891fed5003aa1f0c94d65611d8d6b02cfee76ddc94802c8c68a077022916a705bc320db98d8826b0b3c70751f9d13291d797380e050b983a820e52dfdf4af471b2be39f8e2006180cda3943fa9e9b4964b1fc20bf8b88d73ee0f9e0c88445e9ad15669f6fbdae6f726becd2bf84d422e17885cfe86e40cdae1504264258e9cbad2ea6d48cd97bf384f9c952ef0ba35848694381c020e0b53397c23ce637749b20f1f01005a07f176e5db3bb02715f95e9735f266e5ebba1007b4004056f0dd7e694f4bda6b2d09346eae82d0699ea7551f6e1fd8dffccb6339b5d2fb14892ab209fe0f707acfc5a9adb03c5aefd00ae4579dc2acc92dbdc6e46c16db053a4b7a2888545a80f3702b2dc22546d57d11f2aa05b2671ab4b5",
            "nn": "130635a8947448164bb2b9b8b136092eb0b4ae805d6c74c3fe64a17d16f8ef5e2604ae159d728499bac40f906ada33187a1a880d26c2212a860983fd2ef9b61d2f795c531cb01c56a9be2afa165e520af8e2258022c9d0966ee74e6708ac668f0c55b58575aeefccc613395dad809f6f48e25887b43d4cdc5f3761c009f394672768aeef30a80f444007ceef01cd808595f2e5a6dbf71f4647e9c1faa102b12c3c229cf966a4b49ba4439535a9bd4e4152d92848d1c210ac110a9c49ee9d07b9f41a62efc49ee47a13780a2b380945869789ec63636ff76356ca910134eeb30dbf8ef620f6eeae7a7119b18166f8685f08d5b801bd2520f0d6858c6b9830416a307e43ba0955cf5a639b0194157930b83b6c1c1a726dac5be782da97f33e77da32f93d46b59596d9a87e196321e130ce8968f41d1e1450a04f5fdb28dd956027023450ad92e599ad4e7caf59f3c9067aa352d9194892123cb46cb54ee6badb8c8c6e82fa60eaaad13a225e5661aac69611ced2e509aac62f0a71cc27566480547a26fe8dace61b6464f023d1d61e095a947223cf3bbbbc9a7d1067518be54b9e86472d4356f3bf19850d4fd561989c39b1ec980accd97448eeedc2a516570cf6e3701931b1e324d9b412f774ff27dec276b373da078497a242ff1bed7a9288818089594c8f23af47916d822cc6fb09220d80f3992e7077cb44685cbd6c48779dccd7da99e572d53869a531727a393ab6264c5e4405727750d202804bf9998e29356115c5ab35d13a744c87988948914ab7dfb64ba9d4066cc5b2645a99e5cef04f75d94b70f4a5a74d6fa67f8afa9f375150ad82125de9467d5a9d0ed896b404d845444cdf7d76d439b00d76be4a477c413e1515a866271010cf9f74122d109b78a4466e3dbb65246b5e6f12f3bfa6abd76313948bc1eedef00da706c834602a285da35face39870e1a04187a9cb7233b1702036ef4a17ccbb1de03b129a5d381baa4561ecdf56456aaad4eabd4f4438e4d790edf5bd74eec55e597a17a0d7e959e8b2ac4933b9886345af7bd63e5095d2a99ba85336a382ca1cdde6da5307f9",
            "h_pow_n": "123dbc19404265c5fb27eb6dc50913d04406cd178e9a6e98f79aaa9a4f07464da190049c0549c74bfd7c45cc20179825bbf7a57c86bde9c21e61f55f555b91406063a013b62657c633dd61b16052cc9bb30f718e7532a6b69a7bbb68e55b6cce2303718fc1681a567e2bfab935ef3de0f6af236d37c80f06b585489bf9e6dcceb135335aa76d29a1ac6123b587d2b7eeb26c310e4b2640a2cb96c245e8666778ae1f978e6ae21138e0c5fbe63721c64cb4473fb5aee2d2ab11d770f8f4ab2c93c6ed3f3426953f8b7da068ffc3fea35def82fe106113339bf33594e6191e80310a42bd126f1029f0369611652854aa2a568b0b43fe066d426fd79cd84701b75ada08887bf52729309ad9883e04df02ec5b3cc1c9d8df9be84553eb8989cdde1a0a3c90c19f359f476449ac459d451a87b5069676125c2b3b25c9b063b97ea46854c99022134735b185c40179a06ee1f4597ddeed0b75dd6a86631948d10fd43ecb9191845a1178fcbb942ef428eb85df3fe3b51f5ef9877ccae87158d557783d4fbd30b630ea43e2c5c7a9bdd71d53ea288ea6fed2abc3dc3cc8981442cc0fccd5ecb78f4217f508b65ece07da331c5fab8d494ca3a94107babeb1cda370598301ea215468d994fe5c54e52331cca0476d387f592d471bb46091e18444a1b7cafdc42d24f1101c13d769a4eb10e5ebc202be9914e39a68668583e655d4593608bb410d1c31dea9b6055ab035ab0e2fc64604b52e93c5a6fc2e964a6300fdb5523f005c57fc561e71c9aaa8583cf071f44a7f9362989516503e588cb52393118c4aaf8ac36aa798fef8a8b91f6f0097bae738da76d6ee68468599cc15240b4b4f5030e5a1b3a247ec2e4f412cd36176a25db9fecda22e196c0f36ead128582be8f41b6ba1ad40c439d29c6582110b200dbfcc50eefc3b98e582b4f72be72af22f3664afe441c71087ecd451632c6ae5d9228d2d8cab6d9eb829a1c09ea774cebe25a5fefeb0437caecb210745e8e767c5a4086ff6f2c4bb77a325924b663167b57652c9ccbe361fd9d3c0488e615a5201b327e601beeca2c46dd32b383434ea4f",
            "half_n": "22e4b8b6f82b41b6b82101f20935db1ebd8c1461632491fb3aee53b176a84c087f2e77060db48acfe0a88fd45024c3a519630310bd592efd849aa9e94aef276e0a4e3881d25f20c6a321fe1fd5b263c24357f39040239792eaf33420b34bd3bfa37e77a0dfe46aacb0448ff6a801d50f864a6b2b08ec6b58167f73b6ee4a40164634503b81148b5382de1906dcc6c4135859e383a8fce89948ebcb9c070285cc1d4107296fefa57a38d95f1cfc710030c066d1ca1fd4f4da4b258fe105fc5c46b9f707cf0644222f4d68ab34fb7ded737b935f6695fc26a1170bc42e7f4372066d70a8213212c74e5d697536a466cbdf9c27ce4a97785d1ac2434a1c0e010705a99cbe11e731bba4d9078f80802d03f8bb72ed9dd8138afcaf4b9af93372f5dd0803da00202b786ebf34a7a5ed3596849a3757416834cf53aa8fb70fec6ffe65b19cdae97d8a44955904ff07b83d67e2d4d6d81e2d77e805722bcee1566496dee372360b6d829d25bd14442a2d4079b81596e112a36abe88f95502d9338d5a5a",
            "neg_half_n": "-22e4b8b6f82b41b6b82101f20935db1ebd8c1461632491fb3aee53b176a84c087f2e77060db48acfe0a88fd45024c3a519630310bd592efd849aa9e94aef276e0a4e3881d25f20c6a321fe1fd5b263c24357f39040239792eaf33420b34bd3bfa37e77a0dfe46aacb0448ff6a801d50f864a6b2b08ec6b58167f73b6ee4a40164634503b81148b5382de1906dcc6c4135859e383a8fce89948ebcb9c070285cc1d4107296fefa57a38d95f1cfc710030c066d1ca1fd4f4da4b258fe105fc5c46b9f707cf0644222f4d68ab34fb7ded737b935f6695fc26a1170bc42e7f4372066d70a8213212c74e5d697536a466cbdf9c27ce4a97785d1ac2434a1c0e010705a99cbe11e731bba4d9078f80802d03f8bb72ed9dd8138afcaf4b9af93372f5dd0803da00202b786ebf34a7a5ed3596849a3757416834cf53aa8fb70fec6ffe65b19cdae97d8a44955904ff07b83d67e2d4d6d81e2d77e805722bcee1566496dee372360b6d829d25bd14442a2d4079b81596e112a36abe88f95502d9338d5a5a"
        }"#;

        let ek = EncryptionKey::from_json(json).unwrap();

        assert_eq!(ek.n_size(), 3072);
        assert_eq!(ek.a_size(), 512);
        assert_eq!(ek.nounce_size(), 512);
        assert_eq!(ek.half_n() + ek.neg_half_n(), BigInt::from(0));
        assert_eq!(&(ek.n() * ek.n()), ek.nn());
    }

    #[test]
    fn test_decryption_key_deserialization() {
        let json = r#"{
            "ek": {
                "n_size": 3072,
                "a_size": 512,
                "nounce_size": 512,
                "h": "-1182e8d35c338ce4cafa9eb594c5c6746fb0d738f8e4c2f48a40e53a21bb33725869adaf23282de264d9cadc92bb271f7b18b9862794ca25b28c333720e89774f5d2a6def4fa29852c9cd50cab69ae9bf9a088d98788cf0a6df0e68315567d08b1d3b71d91d2b34ed990daa668d598d324d5dde4f71fccf51812f7d923ea78951a1c53fe3f3c7327543c6cdb83b9eddcf295ceeb3ad097d87dc6b698e960f1e3d4637b1a7ffa5dd9b77c6046a6d03fe7e688553cdaba63d5bd22d5a58097a141b8ebb5ef6ca153309072d52338bdc72f977409dcc73c6038965cf9b190b95051f1ced9ea1b819a0cee8fdb1cea847f7b51d29cbf2bde90dabfd8943c8a5100c6fc3983d9e6de708c1dac58d92668f8aaa15fd686e361236350438aa9d383b4975fac0b5292435a0c82a36e54aba6a454df27092cae25be6a36a038caf125e4be95d464b8986d24131e142af9b6a5b9988a184cdc52f7b1394b700ea5e2bd365b2fb4e363dd40a56426fb6ec842b9da6bf68e4bd29938a4f9b8041606f910a0a5",
                "n": "45c9716df056836d704203e4126bb63d7b1828c2c64923f675dca762ed509810fe5cee0c1b69159fc1511fa8a049874a32c606217ab25dfb093553d295de4edc149c7103a4be418d4643fc3fab64c78486afe72080472f25d5e668416697a77f46fcef41bfc8d55960891fed5003aa1f0c94d65611d8d6b02cfee76ddc94802c8c68a077022916a705bc320db98d8826b0b3c70751f9d13291d797380e050b983a820e52dfdf4af471b2be39f8e2006180cda3943fa9e9b4964b1fc20bf8b88d73ee0f9e0c88445e9ad15669f6fbdae6f726becd2bf84d422e17885cfe86e40cdae1504264258e9cbad2ea6d48cd97bf384f9c952ef0ba35848694381c020e0b53397c23ce637749b20f1f01005a07f176e5db3bb02715f95e9735f266e5ebba1007b4004056f0dd7e694f4bda6b2d09346eae82d0699ea7551f6e1fd8dffccb6339b5d2fb14892ab209fe0f707acfc5a9adb03c5aefd00ae4579dc2acc92dbdc6e46c16db053a4b7a2888545a80f3702b2dc22546d57d11f2aa05b2671ab4b5",
                "nn": "130635a8947448164bb2b9b8b136092eb0b4ae805d6c74c3fe64a17d16f8ef5e2604ae159d728499bac40f906ada33187a1a880d26c2212a860983fd2ef9b61d2f795c531cb01c56a9be2afa165e520af8e2258022c9d0966ee74e6708ac668f0c55b58575aeefccc613395dad809f6f48e25887b43d4cdc5f3761c009f394672768aeef30a80f444007ceef01cd808595f2e5a6dbf71f4647e9c1faa102b12c3c229cf966a4b49ba4439535a9bd4e4152d92848d1c210ac110a9c49ee9d07b9f41a62efc49ee47a13780a2b380945869789ec63636ff76356ca910134eeb30dbf8ef620f6eeae7a7119b18166f8685f08d5b801bd2520f0d6858c6b9830416a307e43ba0955cf5a639b0194157930b83b6c1c1a726dac5be782da97f33e77da32f93d46b59596d9a87e196321e130ce8968f41d1e1450a04f5fdb28dd956027023450ad92e599ad4e7caf59f3c9067aa352d9194892123cb46cb54ee6badb8c8c6e82fa60eaaad13a225e5661aac69611ced2e509aac62f0a71cc27566480547a26fe8dace61b6464f023d1d61e095a947223cf3bbbbc9a7d1067518be54b9e86472d4356f3bf19850d4fd561989c39b1ec980accd97448eeedc2a516570cf6e3701931b1e324d9b412f774ff27dec276b373da078497a242ff1bed7a9288818089594c8f23af47916d822cc6fb09220d80f3992e7077cb44685cbd6c48779dccd7da99e572d53869a531727a393ab6264c5e4405727750d202804bf9998e29356115c5ab35d13a744c87988948914ab7dfb64ba9d4066cc5b2645a99e5cef04f75d94b70f4a5a74d6fa67f8afa9f375150ad82125de9467d5a9d0ed896b404d845444cdf7d76d439b00d76be4a477c413e1515a866271010cf9f74122d109b78a4466e3dbb65246b5e6f12f3bfa6abd76313948bc1eedef00da706c834602a285da35face39870e1a04187a9cb7233b1702036ef4a17ccbb1de03b129a5d381baa4561ecdf56456aaad4eabd4f4438e4d790edf5bd74eec55e597a17a0d7e959e8b2ac4933b9886345af7bd63e5095d2a99ba85336a382ca1cdde6da5307f9",
                "h_pow_n": "123dbc19404265c5fb27eb6dc50913d04406cd178e9a6e98f79aaa9a4f07464da190049c0549c74bfd7c45cc20179825bbf7a57c86bde9c21e61f55f555b91406063a013b62657c633dd61b16052cc9bb30f718e7532a6b69a7bbb68e55b6cce2303718fc1681a567e2bfab935ef3de0f6af236d37c80f06b585489bf9e6dcceb135335aa76d29a1ac6123b587d2b7eeb26c310e4b2640a2cb96c245e8666778ae1f978e6ae21138e0c5fbe63721c64cb4473fb5aee2d2ab11d770f8f4ab2c93c6ed3f3426953f8b7da068ffc3fea35def82fe106113339bf33594e6191e80310a42bd126f1029f0369611652854aa2a568b0b43fe066d426fd79cd84701b75ada08887bf52729309ad9883e04df02ec5b3cc1c9d8df9be84553eb8989cdde1a0a3c90c19f359f476449ac459d451a87b5069676125c2b3b25c9b063b97ea46854c99022134735b185c40179a06ee1f4597ddeed0b75dd6a86631948d10fd43ecb9191845a1178fcbb942ef428eb85df3fe3b51f5ef9877ccae87158d557783d4fbd30b630ea43e2c5c7a9bdd71d53ea288ea6fed2abc3dc3cc8981442cc0fccd5ecb78f4217f508b65ece07da331c5fab8d494ca3a94107babeb1cda370598301ea215468d994fe5c54e52331cca0476d387f592d471bb46091e18444a1b7cafdc42d24f1101c13d769a4eb10e5ebc202be9914e39a68668583e655d4593608bb410d1c31dea9b6055ab035ab0e2fc64604b52e93c5a6fc2e964a6300fdb5523f005c57fc561e71c9aaa8583cf071f44a7f9362989516503e588cb52393118c4aaf8ac36aa798fef8a8b91f6f0097bae738da76d6ee68468599cc15240b4b4f5030e5a1b3a247ec2e4f412cd36176a25db9fecda22e196c0f36ead128582be8f41b6ba1ad40c439d29c6582110b200dbfcc50eefc3b98e582b4f72be72af22f3664afe441c71087ecd451632c6ae5d9228d2d8cab6d9eb829a1c09ea774cebe25a5fefeb0437caecb210745e8e767c5a4086ff6f2c4bb77a325924b663167b57652c9ccbe361fd9d3c0488e615a5201b327e601beeca2c46dd32b383434ea4f",
                "half_n": "22e4b8b6f82b41b6b82101f20935db1ebd8c1461632491fb3aee53b176a84c087f2e77060db48acfe0a88fd45024c3a519630310bd592efd849aa9e94aef276e0a4e3881d25f20c6a321fe1fd5b263c24357f39040239792eaf33420b34bd3bfa37e77a0dfe46aacb0448ff6a801d50f864a6b2b08ec6b58167f73b6ee4a40164634503b81148b5382de1906dcc6c4135859e383a8fce89948ebcb9c070285cc1d4107296fefa57a38d95f1cfc710030c066d1ca1fd4f4da4b258fe105fc5c46b9f707cf0644222f4d68ab34fb7ded737b935f6695fc26a1170bc42e7f4372066d70a8213212c74e5d697536a466cbdf9c27ce4a97785d1ac2434a1c0e010705a99cbe11e731bba4d9078f80802d03f8bb72ed9dd8138afcaf4b9af93372f5dd0803da00202b786ebf34a7a5ed3596849a3757416834cf53aa8fb70fec6ffe65b19cdae97d8a44955904ff07b83d67e2d4d6d81e2d77e805722bcee1566496dee372360b6d829d25bd14442a2d4079b81596e112a36abe88f95502d9338d5a5a",
                "neg_half_n": "-22e4b8b6f82b41b6b82101f20935db1ebd8c1461632491fb3aee53b176a84c087f2e77060db48acfe0a88fd45024c3a519630310bd592efd849aa9e94aef276e0a4e3881d25f20c6a321fe1fd5b263c24357f39040239792eaf33420b34bd3bfa37e77a0dfe46aacb0448ff6a801d50f864a6b2b08ec6b58167f73b6ee4a40164634503b81148b5382de1906dcc6c4135859e383a8fce89948ebcb9c070285cc1d4107296fefa57a38d95f1cfc710030c066d1ca1fd4f4da4b258fe105fc5c46b9f707cf0644222f4d68ab34fb7ded737b935f6695fc26a1170bc42e7f4372066d70a8213212c74e5d697536a466cbdf9c27ce4a97785d1ac2434a1c0e010705a99cbe11e731bba4d9078f80802d03f8bb72ed9dd8138afcaf4b9af93372f5dd0803da00202b786ebf34a7a5ed3596849a3757416834cf53aa8fb70fec6ffe65b19cdae97d8a44955904ff07b83d67e2d4d6d81e2d77e805722bcee1566496dee372360b6d829d25bd14442a2d4079b81596e112a36abe88f95502d9338d5a5a"
            },
            "p": "942cadfb27e08adaf86edd4e3cf11591aa7493c3212dab7592ed56352c9bd1aab3f62cbbd30d80ffe69745e393998e7fdee276b6da59160722761ce602d9a90eb153281984acac40a0320df22c35ab6e7e6e710a050771599e3902fd96ca875e5b20d248881451b63911f127426832a989bb34c731bc0123284b390b455fb6d6d00d902b13116d88a5e8dce3e925f4f9a120d132545cbcb2124e1c3fbd3c268e1ab393077492555e8cc4b0a99b6ab62378838bbede865a044eaf74d86efd62cb",
            "q": "7891fd39e4ead805161c6218a871cad4e2a8049d21005350d4b1122c479cc4e1d768ae8560838e9caafdd51bac6bf019bfbb5d4736cac150d49e6ad078639363b5602d861e53cdec9ba3af03c1a26269fbfea70d3a62e12d3e0741a5bf87eb719a48ba59bc86fe2198e2dbbdb6c1811a521b874525491387fcd73804566acd206091aaad324f48e755a9624d1a98142a2b0b041c3eddcb04666da691e9064e5cf613a57737480ce3500ccebe0790e4aa75c939de82c9793a44cdcfaa9d53d67f",
            "alpha": "7d7d3e5b64f20926591fc0cf8f8ea220e2fd5f066193eba9c9a5979263a42304f120754d7a87dd58b6d413219648c85942838110c5440326e01b666e3a554ac5"
        }"#;

        let dk = DecryptionKey::from_json(json).unwrap();

        assert_eq!(dk.n_size(), 3072);
        assert_eq!(dk.a_size(), 512);
        assert_eq!(dk.nounce_size(), 512);
        assert_eq!(&(dk.p() * dk.q()), dk.n());
        assert_eq!(dk.half_n() + dk.neg_half_n(), BigInt::from(0));
        assert_eq!(&(dk.n() * dk.n()), dk.nn());
    }
}
