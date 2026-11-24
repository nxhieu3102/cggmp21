use crate::common::BigIntExt;
use crate::precomputed_table::PrecomputeTable;
use crate::{utils, Ciphertext, Nonce, Plaintext};
use crate::{Error, Reason};
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::Num;
use num_traits::One;
use rand_core::{CryptoRng, RngCore};
/// Paillier encryption key
#[derive(Clone, Debug)]
pub struct EncryptionKey {
    /// n size (number bits of n)
    n_size: u32,

    /// alpha size in decryption key
    a_size: u32,

    /// nounce (random) in encryption have size a_size (follow the paper)
    nounce_size: u32,

    /// generator of nounce space (G)
    /// h = -y^(2*beta) mod n
    h: BigInt,

    /// n = q * p (q,p are primes)
    n: BigInt,

    /// nn = n * n
    /// modulo in Paillier scheme
    nn: BigInt,

    /// h_pow_n = (h^n) mod nn
    /// a constant in encryption
    h_pow_n: BigInt,

    /// half_n = n / 2
    /// use in validate plaintext (-n/2 <= p <= n/2)
    half_n: BigInt,

    /// neg_half_n = - (n / 2)
    /// use in validate plaintext (-n/2 <= p <= n/2)
    neg_half_n: BigInt,
}

impl EncryptionKey {
    /// Constructs an encryption key
    pub fn new(n_size: u32, a_size: u32, h: BigInt, n: BigInt) -> Result<Self, Error> {
        let nounce_size = a_size;
        let nn = n.clone() * &n;
        let half_n = n.clone() >> 1u32;
        let neg_half_n = -half_n.clone();
        let h_pow_n = h
            .clone()
            .modpow_ext(&n, &nn)
            .ok_or(Error(Reason::InvalidPowMod))?;

        Ok(Self {
            n_size,
            a_size,
            nounce_size,
            h,
            n,
            nn,
            h_pow_n,
            half_n,
            neg_half_n,
        })
    }

    /// Sample a default encryption key for testing
    /// Security level (kappa) = 112
    pub fn sample_112() -> Self {
        let n_size = 2048;
        let a_size = 448;
        let h = BigInt::from_str_radix("1c5e08d902e681c9bc7e915aa58ba4e5b67d7cd4a20d07253bb486d3cf0c9c4eb05f28fac0b30bce24b2502592ec06f206f07d298676e655b2a47575750f177ba05ca985900c053716cb41595ae7b6b90e2473d04f8ee0300e9441dba1e53fc26795e4e099a983fbfcc118390112c2fe2cb1e9a4ea3b32a6a458ae6a2a22d89d7f6a8ace29cc1c8bdb0babb7d8d85de58e3c0c5eae53fe638bf34b7b2aef251fd12e42d8c8498e29907205ec0e8520a508ab7f76ddb8b971d7ba7f92f4ecf074f5eced4a0fb0ee842707b0ba8fb8615dd5a67d7543b5c7c82a3df778c4a14082153e64842e97c3956d66af26dedf499343e992efae9283ae5a1aa9f939edfffe", 16).unwrap();
        let n = BigInt::from_str_radix("243518fee03fdf73a53413db4bd932ec13f07bd48bd815274f3571caa06c9b691dcb95779cbcd2fa844d04b6104c79d510782e9da665e9dd6b544169ed5ea23dba3a07c404a3469d1e4a7759987d75d03023ec87ee1c245402c1a9cae0c64dbc5d2cd8faec558aa981c09a29df4cd9725eb523181dc854ada7f9d137c7452f0115fee48c03308d58c6e87dd93cf1fde5850f6317a0eea6c822fa9485a3f610aae8353c237fd0fcb21e7e2b3de72bab897e37c4fd3b53a89960b546a31beff7466b2abe7a3a32795fe52f8146a28c1bdc659a44c6e2b73061a077945c6b26eb6d43a3a48c291cd39903e6ba29a169128743d0935cd60fd26f710dad064edfa7c5", 16).unwrap();

        Self::new(n_size, a_size, h, n).unwrap()
    }

    /// Sample a default encryption key for testing
    /// Security level (kappa) = 128
    pub fn sample_128() -> Self {
        let n_size = 3072;
        let a_size = 512;
        let h = BigInt::from_str_radix("-46118646770832830045641315635057147415619452896408495725084525515631763498419217092239007240481104785951515106141330780184017724711354754878105138981527814046713442701173158787961318701138213050689131500547667287835057808777090201233823259693317234765298199512393795028689399638011557338811405434847285549626923699588499355369100778944461335938055933338208588737362787471904613721909499495052563847250494605740519245116885721410290558409599017491571221814391229137726330359398608150289466563711537032436971344700037076458377527561048872725835181683669452128606967411636366306264582886347600341878183021479279996250977820902830628786961783055120959326713538614909410942862567628149824740864114037208934860868056544040342709335908500229136286989784554496443156132704420811055403006822848620991994750093609373760282848220484869564427940530240476784686626726481501299422807761209664211819557525909377117754524995670714798106228", 10).unwrap();
        let n = BigInt::from_str_radix("624498857762620325098235170965743800775986411638861818063975567416457548620626106589775762742147050332061040035988343327949848344781895647064874621111687462752351420252191016556563422405065857493565714223369457326132905751097688764312209576092608940344112195727294420580004446885734418485854984933721637793585572313379454462372823080364186214267829274487061982469987426935994509566980637443218966350207542793855595534878529696726480414810101468713027596090923530806002617542180788766147785236740591484455822141732077626477810969339706966842770784842141574665525282473888631304800798834440140046529558448816002513160409692564156284555087902686772224299491823502624123052301570848969169650127973801617496811923093923613174646328722924361659936987353289043665636098196190290386284750432940209381911182951746612131658041398132442860120556913619042902264243188841994871986844780749268847877605077940655376360242193578643742404317", 10).unwrap();

        Self::new(n_size, a_size, h, n).unwrap()
    }

    /// Sample another default encryption key for testing
    /// Security level (kappa) = 128
    pub fn sample_other_128() -> Self {
        let n_size = 3072;
        let a_size = 512;
        let h = BigInt::from_str_radix("-238268e4f0068befb247206cb393feec56046c7f3d347c080ffb1b2a8821c932e2aa150c36586fa060f2d35024487179427f17b8d92d979ae051ec45302c33beb4d7ce7bb9ff6dc807fc9993a4449c00af55789e0a500bcaf0d011d16cd2b784ed21e52fa8424565d91b2848f7be6ecd2d2d8c42a4299221ea1fccf486a19b844bba31e3224a341e625151e751b435a376eb64df69223003a5188cc9d8675e45c8a004258e296552ad50d017719e16ea225f073eab2b1abcccc22b592b40a204868ad020d7294bca1360cdea97da59765b03baf97e856f2bef986f88e56c75dd54dadcd1f71aae5cb25edfcc78ec175a3cd554f9ba6d125da80a3ae2b135bb061c31451463234ac217f3e642a2eb5b5869a4285f9ab442f8aef3efdb20ce9ae954968c9a1174a031e93b30c295e8f385f3e6654385b8f0d9706ad8879f6555f85d0b4b78942f65ccebdcd6405666e5e5488761e87c5babe9b60dd50923ed9073d45802d5be7116ab4ef74e46018d7142d2cb3be5e385a32f85c94b24d430ccee", 16).unwrap();
        let n = BigInt::from_str_radix("2f3fb34b2019f8046dea612a987751e756d9a16b9f1a524943a3cc756e3a85c039c44a8e92e105f7d65d4208fa9fd464ad870168e6a868d8e36263bfea05c3e0e6175ccb6686b5c1379da4259e695c46f0c0138474bf1ef67320b521154aaccc8489e4cccbd81fb8e3a7f274c8dffe03fc0d81935db916d7065b738a1e233d013caa4cd94b83a27cbfbba80997fba751ae9da403f53e9f4dbc894c3c813e4fb529805483ca45f5239e6d8119d95179e0ca8e16a166dc849d4f3691de2695eafe59d6ac0b9ac14a4bee2d60325f77485cb41e0f06883901190032cc0f08a83699715a6c71efe501ab366c270ff91cfae3169bee3b7c21169fd8293c9fc95e4565c2322e55cf8767fae0142aaf57fe1951b3ff95be14ce4b273a42c6b6e6e1a278010e59f1a28e07ef4ae0b9a0a8ac4c02c536565f5f007bb585a3f3a1ed2b641976f3dadb4465ea46150dab90dc38faaa362e8bc3dd6adfc1db60959b624092a48a6caeaf6aeb24fe76252a17b27694c99bc690bebd4bfd6c742f4e1c9eec239d", 16).unwrap();

        Self::new(n_size, a_size, h, n).unwrap()
    }

    /// Returns `n_size`
    pub fn n_size(&self) -> u32 {
        self.n_size
    }

    /// Returns `a_size`
    pub fn a_size(&self) -> u32 {
        self.a_size
    }

    /// Returns `nounce_size`
    pub fn nounce_size(&self) -> u32 {
        self.nounce_size
    }

    /// Returns `h`
    pub fn h(&self) -> &BigInt {
        &self.h
    }

    /// Returns `N`
    pub fn n(&self) -> &BigInt {
        &self.n
    }

    /// Returns `N^2`
    pub fn nn(&self) -> &BigInt {
        &self.nn
    }

    /// Returns `h^N mod N^2`
    pub fn h_pow_n(&self) -> &BigInt {
        &self.h_pow_n
    }

    /// Returns `N/2`
    pub fn half_n(&self) -> &BigInt {
        &self.half_n
    }

    /// Returns `-N/2`
    pub fn neg_half_n(&self) -> &BigInt {
        &self.neg_half_n
    }
}

impl EncryptionKey {
    /// Checks whether `x` is `{-N/2, .., N/2}`
    pub fn in_signed_group(&self, x: &BigInt) -> bool {
        self.neg_half_n <= *x && *x <= self.half_n
    }
}

impl EncryptionKey {
    /// Encrypts the plaintext `x` in `{-N/2, .., N_2}` with `nonce` in `{0,1}^nounce_size`
    /// regard nounce as an integer in Z naturally
    ///
    /// Encrypt: Enc(x) = (1 + N)^x.(h^r mod N)^N mod N^2
    ///                 = (1 + x.N).(h^N mod N^2)^r mod N^2
    ///                 = (1 + x.N).h_pow_n^r mod N^2 (h_pow_n = h^N mod N^2)
    ///
    /// Returns error if inputs are not in specified range
    pub fn encrypt_with(&self, x: &Plaintext, nonce: &Nonce) -> Result<Ciphertext, Error> {
        // Check plaintext is in signed group

        // assert_eq!(self.nounce_size(), nonce.bits() as u32, "nonce size is not correct");

        if !self.in_signed_group(x) {
            return Err(Reason::Encrypt.into());
        }

        // Make x positive
        let x = if *x > BigInt::ZERO {
            x.clone()
        } else {
            x + self.n()
        };

        // a = (1 + N)^x mod N^2 = (1 + xN) mod N^2
        let a = (BigInt::one() + (&x * self.n())).mod_floor(self.nn());
        // b = (h^nonce mod N)^N mod N^2 = (h^n mod N^2)^nonce mod N^2 = h_pow_n^nonce mod N^2
        let b: BigInt = self
            .h_pow_n()
            .clone()
            .modpow_ext(nonce, self.nn())
            .ok_or(Error(Reason::InvalidPowMod))?;

        let c = (a * b).mod_floor(self.nn());
        assert!(
            utils::in_mult_group(&c, self.nn()),
            "Ciphertext is not in the multiplicative group"
        );
        Ok(c)
    }

    /// Encrypts the plaintext `x` in `{-N/2, .., N_2}`
    ///
    /// Nonce is sampled randomly using `rng`.
    ///
    /// Returns error if plaintext is not in specified range
    pub fn encrypt_with_random(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        x: &Plaintext,
    ) -> Result<(Ciphertext, Nonce), Error> {
        let nonce = utils::sample_with_size(rng, self.nounce_size());
        let ciphertext = self.encrypt_with(x, &nonce)?;
        Ok((ciphertext, nonce))
    }
}

impl EncryptionKey {
    /// Homomorphic addition of two ciphertexts
    ///
    /// ```text
    /// oadd(Enc(a1), Enc(a2)) = Enc(a1 + a2)
    /// ```
    pub fn oadd(&self, c1: &Ciphertext, c2: &Ciphertext) -> Result<Ciphertext, Error> {
        if !utils::in_mult_group(c1, self.nn()) || !utils::in_mult_group(c2, self.nn()) {
            return Err(Reason::Ops.into());
        }
        Ok((c1 * c2).mod_floor(self.nn()))
    }

    /// Homomorphic subtraction of two ciphertexts
    ///
    /// ```text
    /// osub(Enc(a1), Enc(a2)) = Enc(a1 - a2)
    /// ```
    pub fn osub(&self, c1: &Ciphertext, c2: &Ciphertext) -> Result<Ciphertext, Error> {
        if !utils::in_mult_group(c1, self.nn()) {
            return Err(Reason::Ops.into());
        }
        let c2 = self.oneg(c2)?;
        Ok((c1 * c2).mod_floor(self.nn()))
    }

    /// Homomorphic multiplication of scalar at ciphertext
    ///
    /// ```text
    /// omul(a, Enc(c)) = Enc(a * c)
    /// ```
    pub fn omul(&self, scalar: &BigInt, ciphertext: &Ciphertext) -> Result<Ciphertext, Error> {
        if !utils::in_mult_group_abs(scalar, self.n())
            || !utils::in_mult_group(ciphertext, self.nn())
        {
            return Err(Reason::Ops.into());
        }

        ciphertext
            .modpow_ext(scalar, self.nn())
            .ok_or(Error(Reason::Ops))
    }

    /// Homomorphic negation of a ciphertext
    ///
    /// ```text
    /// oneg(Enc(a)) = Enc(-a)
    /// ```
    pub fn oneg(&self, ciphertext: &Ciphertext) -> Result<Ciphertext, Error> {
        Ok(ciphertext.modinv(self.nn()).ok_or(Reason::Ops)?)
    }
}

impl EncryptionKey {
    /// Encrypts the plaintext using a precomputed table for faster exponentiation
    pub fn encrypt_with_precompute_table(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        precompute_table: &PrecomputeTable,
        m: &Plaintext,
        nonce: Option<&Nonce>,
    ) -> Result<Ciphertext, Error> {
        let r = match nonce {
            Some(nonce) => nonce,
            None => &utils::sample_with_size(rng, self.nounce_size()),
        };
        println!("nonce: {:?}, r: {:?}", nonce, r);
        assert_eq!(
            precompute_table.pow_size(),
            r.bits() as usize,
            "nonce size is not correct"
        );

        // h_pow_rn = (h^n)^r = h^(n*r) mod n^2
        let h_pow_rn = Self::pow(precompute_table, &r);

        assert_eq!(
            self.h_pow_n().modpow_ext(&r, self.nn()).unwrap(),
            h_pow_rn,
            "h_pow_rn is not correct"
        );

        // g_pow_m = g^m = (1 + n) ^ m = (1 + n * m) mod n^2
        let g_pow_m = ((m * &self.n) + BigInt::from(1)).mod_floor(&self.nn);

        assert_eq!(
            g_pow_m,
            (BigInt::from(1) + (m * &self.n)).mod_floor(&self.nn),
            "g_pow_m is not correct"
        );

        let c = (g_pow_m * h_pow_rn).mod_floor(&self.nn);
        assert!(
            utils::in_mult_group(&c, self.nn()),
            "Ciphertext is not in the multiplicative group"
        );

        Ok(c)
    }

    fn pow(precompute_table: &PrecomputeTable, pow: &BigInt) -> BigInt {
        let pow_blocks = Self::convert_into_blocks(precompute_table, pow);
        let mut result = BigInt::from(1);

        for (id, pow_block) in pow_blocks.iter().enumerate() {
            result = (result * &precompute_table.table()[id][*pow_block])
                .mod_floor(precompute_table.modulo());
        }

        result.mod_floor(precompute_table.modulo())
    }

    fn convert_into_blocks(precompute_table: &PrecomputeTable, x: &BigInt) -> Vec<usize> {
        // convert bigint --> list of bits
        // block_size bits --> group (right to left)
        // each group --> usize/u64/...
        let block_size = precompute_table.block_size();
        let pow_size = precompute_table.pow_size();
        let num_block = pow_size / block_size + if (pow_size % block_size) > 0 { 1 } else { 0 };

        let mut result = vec![0; num_block];

        for bit_id in 0..pow_size {
            if x.bit(bit_id as u64) {
                // bit_id in is the (bit_id.mod_floor(block_size) bit of group (bit_id / block_size)
                // turn on the (bit_id.mod_floor(block_size) bit of group (bit_id / block_size)
                let block_id = bit_id / block_size;
                let bit_id = bit_id % block_size;
                result[block_id] |= 1 << bit_id;
            }
        }

        result
    }
}
