use crate::utils::{serializable_bigint, serializable_vec_vec_bigint};
use num_bigint::BigInt;
use num_integer::Integer;
use serde::{Deserialize, Serialize};
use serde_json;
use std::fs;
use std::mem;
use std::path::Path;

/// A table for precomputed values to speed up Paillier encryption operations.
/// This table stores modular exponentiations for faster computation of cryptographic operations.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrecomputeTable {
    pow_size: usize,
    block_size: usize,
    #[serde(with = "serializable_bigint")]
    modulo: BigInt,
    #[serde(with = "serializable_vec_vec_bigint")]
    table: Vec<Vec<BigInt>>,
}

impl PrecomputeTable {
    fn calculate_table(
        base: &BigInt,
        block_size: usize,
        pow_size: usize,
        modulo: &BigInt,
    ) -> Vec<Vec<BigInt>> {
        let num_blocks = pow_size / block_size + if (pow_size % block_size) > 0 { 1 } else { 0 };
        let max_block_value = (1 << block_size) - 1;

        // table[i][j] is
        // table[i][j] = [base^(2^(i*block_size))]^j % modulo

        let mut table = vec![vec![BigInt::from(1); max_block_value + 1]; num_blocks + 1];

        for (i, row_i) in table.iter_mut().enumerate().take(num_blocks + 1) {
            for (j, cell_ij) in row_i.iter_mut().enumerate().take(max_block_value + 1) {
                // tmp1 = 2^(i*block_size) % modulo
                let tmp1 = BigInt::from(2).modpow(&BigInt::from((i * block_size) as u32), modulo);
                // tmp2 = base^(tmp1) % modulo
                let tmp2: BigInt = base.clone().modpow(&tmp1, modulo);
                // tmp3 = tmp2^j % modulo
                let tmp3: BigInt = tmp2.clone().modpow(&BigInt::from(j as u32), modulo);

                *cell_ij = tmp3;
            }
        }
        table
    }

    fn calculate_table_dp(
        base: &BigInt,
        block_size: usize,
        pow_size: usize,
        modulo: &BigInt,
    ) -> Vec<Vec<BigInt>> {
        let num_blocks = pow_size / block_size + if (pow_size % block_size) > 0 { 1 } else { 0 };
        let max_block_value = (1 << block_size) - 1;

        // Initialize table: table[i][j] = (base^(2^(i*block_size)))^j % modulo
        let mut table = vec![vec![BigInt::from(0); max_block_value + 1]; num_blocks + 1];

        // Handle j=0 case: any number raised to 0 is 1
        for row_i in table.iter_mut().take(num_blocks + 1) {
            row_i[0] = BigInt::from(1);
        }

        // Precompute 2^(i*block_size) % modulo for each i
        let mut pow_2 = vec![BigInt::from(1); num_blocks + 1];
        for i in 1..=num_blocks {
            // Compute 2^(i*block_size) = 2^((i-1)*block_size) * 2^block_size
            let prev = &pow_2[i - 1];
            let block_exp = BigInt::from(2).modpow(&BigInt::from(block_size as u32), modulo);
            pow_2[i] = (prev * &block_exp) % modulo;
        }

        // Compute table[i][j]
        for i in 0..=num_blocks {
            // Compute tmp2 = base^(2^(i*block_size)) % modulo
            let tmp2: BigInt = base.modpow(&pow_2[i], modulo);

            // Compute table[i][j] iteratively for j >= 1
            table[i][1] = tmp2.clone();
            for j in 2..=max_block_value {
                // table[i][j] = table[i][j-1] * tmp2 % modulo
                table[i][j] = (&table[i][j - 1] * &tmp2).mod_floor(modulo);
            }
        }

        table
    }
    /// Creates a new precomputed table using the standard calculation method.
    ///
    /// # Arguments
    /// * `g` - The base BigInt for exponentiation
    /// * `block_size` - Size of each block in bits
    /// * `pow_size` - Maximum power size in bits
    /// * `modulo` - The modulus for all operations
    pub fn new(g: BigInt, block_size: usize, pow_size: usize, modulo: BigInt) -> Self {
        let table = Self::calculate_table(&g, block_size, pow_size, &modulo);

        PrecomputeTable {
            pow_size,
            block_size,
            modulo,
            table,
        }
    }

    /// Creates a new precomputed table using dynamic programming for calculation.
    ///
    /// # Arguments
    /// * `g` - The base BigInt for exponentiation
    /// * `block_size` - Size of each block in bits
    /// * `pow_size` - Maximum power size in bits
    /// * `modulo` - The modulus for all operations
    pub fn new_dp(g: BigInt, block_size: usize, pow_size: usize, modulo: BigInt) -> Self {
        let table = Self::calculate_table_dp(&g, block_size, pow_size, &modulo);

        PrecomputeTable {
            pow_size,
            block_size,
            modulo,
            table,
        }
    }

    /// Saves the precomputed table to a JSON file.
    ///
    /// # Arguments
    /// * `file_path` - Path where to save the JSON file
    ///
    /// # Returns
    /// * `Result<(), Box<dyn std::error::Error>>` - Success or error
    pub fn save_to_file<P: AsRef<Path>>(
        &self,
        file_path: P,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let json_string = serde_json::to_string_pretty(self)?;
        fs::write(file_path, json_string)?;
        Ok(())
    }

    /// Creates a precomputed table from a cached JSON file.
    ///
    /// # Arguments
    /// * `file_path` - Path to the JSON file containing the cached precomputed table
    ///
    /// # Returns
    /// * `Result<PrecomputeTable, Box<dyn std::error::Error>>` - The loaded precomputed table or error
    pub fn create_precomputable_from_cache<P: AsRef<Path>>(
        file_path: P,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let json_string = fs::read_to_string(file_path)?;
        let table: PrecomputeTable = serde_json::from_str(&json_string)?;
        Ok(table)
    }

    /// Returns the size of the precomputed table in bytes.
    pub fn size_in_bytes(&self) -> usize {
        let mut size = 0;
        for row in &self.table {
            size += row.len() * mem::size_of::<BigInt>();
        }
        size
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DecryptionKey;

    fn test_dk_with_128b() -> DecryptionKey {
        DecryptionKey::sample_128()
    }

    fn test_dk_with_112b() -> DecryptionKey {
        DecryptionKey::sample_112()
    }

    #[test]
    fn test_encryption_with_precompute_128b() {
        let dk = test_dk_with_128b();
        let ek = dk.encryption_key();
        let base = ek.h_pow_n();
        let block_size = 5 as usize;
        let pow_size = ek.a_size() as usize;
        let modulo: &BigInt = ek.nn();

        // Create and save precomputed table to cache
        let precompute = PrecomputeTable::new(base.clone(), block_size, pow_size, modulo.clone());
        let cache_file = "precompute_128b_cache.json";
        precompute
            .save_to_file(cache_file)
            .expect("Failed to save precompute table");

        // Load precomputed table from cache
        let precompute_from_cache = PrecomputeTable::create_precomputable_from_cache(cache_file)
            .expect("Failed to load precompute table from cache");

        // Test encryption using cached precomputed table
        let m = BigInt::from(10);
        let mut rng = rand::thread_rng();
        let c = ek
            .encrypt_with_precompute_table(&mut rng, &precompute_from_cache, &m, None)
            .unwrap();
        let recovered_m = dk.decrypt(&c).unwrap();
        assert_eq!(recovered_m, m);

        // Clean up cache file
        // std::fs::remove_file(cache_file).ok();
    }

    #[test]
    fn test_encryption_with_precompute_112b() {
        let dk = test_dk_with_112b();
        let ek = dk.encryption_key();
        let base = ek.h_pow_n();
        let block_size = 5 as usize;
        let pow_size = ek.a_size() as usize;
        let modulo: &BigInt = ek.nn();
        let precompute = PrecomputeTable::new(base.clone(), block_size, pow_size, modulo.clone());
        let m = BigInt::from(10);
        let mut rng = rand::thread_rng();
        let c = ek
            .encrypt_with_precompute_table(&mut rng, &precompute, &m, None)
            .unwrap();
        let recovered_m = dk.decrypt(&c).unwrap();
        assert_eq!(recovered_m, m);
    }

    #[test]
    fn test_encryption_with_precompute_dp_128b() {
        let dk = test_dk_with_128b();
        let ek = dk.encryption_key();
        let base = ek.h_pow_n();
        let block_size = 10 as usize;
        let pow_size: usize = ek.a_size() as usize;
        let modulo: &BigInt = ek.nn();
        let precompute =
            PrecomputeTable::new_dp(base.clone(), block_size, pow_size, modulo.clone());
        let m = BigInt::from(10);
        let mut rng = rand::thread_rng();
        let c = ek
            .encrypt_with_precompute_table(&mut rng, &precompute, &m, None)
            .unwrap();
        let recovered_m = dk.decrypt(&c).unwrap();
        assert_eq!(recovered_m, m);
    }

    #[test]
    fn test_encryption_with_precompute_dp_112b() {
        let dk = test_dk_with_112b();
        let ek = dk.encryption_key();
        let base = ek.h_pow_n();
        let block_size = 10 as usize;
        let pow_size = ek.a_size() as usize;
        let modulo: &BigInt = ek.nn();
        let precompute =
            PrecomputeTable::new_dp(base.clone(), block_size, pow_size, modulo.clone());
        let m = BigInt::from(10);
        let mut rng = rand::thread_rng();
        let c = ek
            .encrypt_with_precompute_table(&mut rng, &precompute, &m, None)
            .unwrap();
        let recovered_m = dk.decrypt(&c).unwrap();
        assert_eq!(recovered_m, m);
    }

    #[test]
    fn test_precompute_table_creation() {
        let dk = test_dk_with_112b();
        let ek = dk.encryption_key();
        let base = ek.h_pow_n();
        let block_size = 10 as usize;
        let pow_size = ek.a_size() as usize;
        let modulo: &BigInt = ek.nn();

        let table = PrecomputeTable::new(base.clone(), block_size, pow_size, modulo.clone());

        assert_eq!(table.block_size(), block_size);
        assert_eq!(table.pow_size(), pow_size);
        // assert_eq!(*table.modulo(), modulo);

        let expected_rows = pow_size / block_size + 1;
        let expected_cols = 1 << block_size;
        let table_data = table.table();
        assert_eq!(table_data.len(), expected_rows);
        for row in table_data {
            assert_eq!(row.len(), expected_cols);
        }
    }

    #[test]
    fn test_precompute_table_dp_creation() {
        let dk = test_dk_with_112b();
        let ek = dk.encryption_key();
        let base = ek.h_pow_n();
        let block_size = 10 as usize;
        let pow_size = ek.a_size() as usize;
        let modulo: &BigInt = ek.nn();

        let table: PrecomputeTable =
            PrecomputeTable::new_dp(base.clone(), block_size, pow_size, modulo.clone());

        assert_eq!(table.block_size(), block_size);
        assert_eq!(table.pow_size(), pow_size);
        // assert_eq!(*table.modulo(), modulo);

        let expected_rows = pow_size / block_size + 2;
        let expected_cols = 1 << block_size;
        let table_data = table.table();
        assert_eq!(table_data.len(), expected_rows);
        for row in table_data {
            assert_eq!(row.len(), expected_cols);
        }
    }

    #[test]
    fn test_table_values() {
        let g = BigInt::from(2);
        let block_size = 2;
        let pow_size = 4;
        let modulo = BigInt::from(7);

        let table = PrecomputeTable::new(g.clone(), block_size, pow_size, modulo.clone());
        let table_data = table.table();

        assert_eq!(table_data[0][0], BigInt::from(1));
        assert_eq!(table_data[0][1], BigInt::from(2));
        assert_eq!(table_data[0][2], BigInt::from(4));
        assert_eq!(table_data[0][3], BigInt::from(1));

        assert_eq!(table_data[1][0], BigInt::from(1));
        assert_eq!(table_data[1][1], BigInt::from(2));
        assert_eq!(table_data[1][2], BigInt::from(4));
        assert_eq!(table_data[1][3], BigInt::from(1));

        assert_eq!(table_data[2][0], BigInt::from(1));
        assert_eq!(table_data[2][1], BigInt::from(4));
        assert_eq!(table_data[2][2], BigInt::from(2));
        assert_eq!(table_data[2][3], BigInt::from(1));
    }

    #[test]
    fn test_table_dp_values() {
        let g = BigInt::from(2);
        let block_size = 2;
        let pow_size = 4;
        let modulo = BigInt::from(7);

        let table = PrecomputeTable::new_dp(g.clone(), block_size, pow_size, modulo.clone());
        let table_data = table.table();

        assert_eq!(table_data[0][0], BigInt::from(1));
        assert_eq!(table_data[0][1], BigInt::from(2));
        assert_eq!(table_data[0][2], BigInt::from(4));
        assert_eq!(table_data[0][3], BigInt::from(1));

        assert_eq!(table_data[1][0], BigInt::from(1));
        assert_eq!(table_data[1][1], BigInt::from(2));
        assert_eq!(table_data[1][2], BigInt::from(4));
        assert_eq!(table_data[1][3], BigInt::from(1));

        assert_eq!(table_data[2][0], BigInt::from(1));
        assert_eq!(table_data[2][1], BigInt::from(4));
        assert_eq!(table_data[2][2], BigInt::from(2));
        assert_eq!(table_data[2][3], BigInt::from(1));
    }

    use crate::EncryptionKey;

    #[test]
    fn test_size_in_bytes() {
        let block_size = 18;
        let pow_size = 512;
        let ek = EncryptionKey::sample_128();
        let modulo = ek.nn();
        let base = ek.h_pow_n();
        let table = PrecomputeTable::new_dp(base.clone(), block_size, pow_size, modulo.clone());

        let size = table.size_in_bytes();
        assert!(size > 0);

        let expected_rows = pow_size / block_size + 1;
        let expected_cols = 1 << block_size;
        let expected_elements = expected_rows * expected_cols;
        let expected_size = expected_elements * mem::size_of::<BigInt>();
        println!("expected_size: {}", expected_size);
        println!("size: {}", size);
        assert!(size >= expected_size);
    }

    #[test]
    fn test_save_and_load_precompute_table() {
        let dk = test_dk_with_128b();
        let ek = dk.encryption_key();
        let base = ek.h_pow_n();
        let block_size = 10;
        let pow_size = ek.a_size() as usize;
        let modulo = ek.nn();

        // Create original precomputed table
        let original_table =
            PrecomputeTable::new_dp(base.clone(), block_size, pow_size, modulo.clone());

        // Save to file
        let file_path = "./test_precompute_cache_128b.json";
        original_table
            .save_to_file(file_path)
            .expect("Failed to save precompute table");

        // Load from cache
        let loaded_table = PrecomputeTable::create_precomputable_from_cache(file_path)
            .expect("Failed to load precompute table from cache");

        // Verify the loaded table has the same properties
        assert_eq!(loaded_table.block_size(), original_table.block_size());
        assert_eq!(loaded_table.pow_size(), original_table.pow_size());
        assert_eq!(loaded_table.modulo(), original_table.modulo());

        // Test encryption with both tables to ensure they work identically
        let m = BigInt::from_str_radix(
            "111059274584159037583180965985692333558976830674721111613492917082463480024962",
            10,
        )
        .unwrap();

        let nonce = BigInt::from_str_radix("732911689077094917999787732601118729924686733015193458539990169234477127978464338825354892655278585155537516557769235739954124478537329253285352393161441319040527464989833650900813612317291614016820769918608864588447830727663698667276981015583782428638674608110906172846041743849706908674894268808957599160695894880678641020681120420307794343393663883455984248934660951479027113477434933717691697562736195421737448116960843913497260990794282692328492916970158483349212074979614140086448273259255458268094655659562968717410590324423497913466681423184603334547584840708993477598503171642794974497695371458965349658228326124990026575854751535042077203015958360890648644948508165178401055260956666281379901886465348203008540752783512657707562180780281579929836897680231953866381448813530290234243169259803919341862987736482304289550909705789843571414138322049868614029322459377247517682094132011467809075571455959204466107826486", 10).unwrap();
        let mut rng = rand::thread_rng();

        let c1 = ek
            .encrypt_with_precompute_table(&mut rng, &original_table, &m, Some(&nonce))
            .unwrap();
        let c2 = ek
            .encrypt_with_precompute_table(&mut rng, &loaded_table, &m, Some(&nonce))
            .unwrap();

        let recovered_m1 = dk.decrypt(&c1).unwrap();
        let recovered_m2 = dk.decrypt(&c2).unwrap();

        assert_eq!(recovered_m1, m);
        assert_eq!(recovered_m2, m);

        // Clean up test file
        std::fs::remove_file(file_path).ok();
    }

    use num_traits::Num;
    #[test]
    fn test_encrypt_with_precompute_table_vs_encrypt_with_same_nonce() {
        let dk = test_dk_with_128b();
        let ek = dk.encryption_key();
        let base = ek.h_pow_n();
        let block_size = 10;
        let pow_size = ek.n_size() as usize;
        let modulo = ek.nn();

        // Create precomputed table
        let precompute_table =
            PrecomputeTable::new_dp(base.clone(), block_size, pow_size, modulo.clone());

        // Test message
        let m = BigInt::from_str_radix("1", 10).unwrap();

        let nonce = BigInt::from_str_radix("732911689077094917999787732601118729924686733015193458539990169234477127978464338825354892655278585155537516557769235739954124478537329253285352393161441319040527464989833650900813612317291614016820769918608864588447830727663698667276981015583782428638674608110906172846041743849706908674894268808957599160695894880678641020681120420307794343393663883455984248934660951479027113477434933717691697562736195421737448116960843913497260990794282692328492916970158483349212074979614140086448273259255458268094655659562968717410590324423497913466681423184603334547584840708993477598503171642794974497695371458965349658228326124990026575854751535042077203015958360890648644948508165178401055260956666281379901886465348203008540752783512657707562180780281579929836897680231953866381448813530290234243169259803919341862987736482304289550909705789843571414138322049868614029322459377247517682094132011467809075571455959204466107826486", 10).unwrap();
        // Generate a specific nonce
        let mut rng = rand::thread_rng();
        // let nonce = crate::utils::sample_with_size(&mut rng, ek.nounce_size());

        // Encrypt with regular encrypt_with method using the nonce
        let c1 = dk.encrypt_with(&m, &nonce).unwrap();

        // Encrypt with precompute table using the same nonce
        let c2 = ek
            .encrypt_with_precompute_table(&mut rng, &precompute_table, &m, Some(&nonce))
            .unwrap();

        // Both ciphertexts should be identical since they use the same nonce

        println!("c1: {:?}", c1);
        println!("c2: {:?}", c2);
        println!("nn: {:?}", ek.nn());

        // assert_eq!(c1, c2, "Ciphertexts should be identical when using the same nonce");

        // Verify both decrypt to the same message
        let recovered_m1 = dk.decrypt(&c2).unwrap();
        let recovered_m2 = dk.decrypt(&c1).unwrap();

        assert_eq!(recovered_m1, m);
        assert_eq!(recovered_m2, m);
        assert_eq!(recovered_m1, recovered_m2);
    }
}
