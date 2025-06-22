// cargo run --bin precompute_tables

use anyhow::Context;
use cggmp21::security_level::SecurityLevel128;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Generating precompute tables cache...");

    // Generate precompute tables from cached paillier keys
    let tables = cggmp21_tests::PregeneratedPrecomputeTables::generate_from_paillier_keys::<SecurityLevel128>(
        &cggmp21_tests::CACHED_PAILLIER_KEYS,
        5, // block_size - matches what's used in signing.rs
    );

    // Serialize and save to file
    let serialized = tables.to_serialized().context("serialize precompute tables")?;
    fs::write("/Users/hieunguyen/WorkSpace/Personal/thesis/fork-cggmp21/test-data/precomputed_precompute_tables.json", serialized)
        .context("write precompute tables to file")?;

    println!("Generated {} precompute tables", tables.len());
    println!("Saved to /Users/hieunguyen/WorkSpace/Personal/thesis/fork-cggmp21/test-data/precomputed_precompute_tables.json");

    Ok(())
} 
