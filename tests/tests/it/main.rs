mod key_refresh;
mod keygen;
mod old_shares;
mod pipeline;
mod signing;
mod stark_prehashed;

// These tests are ignored to auto run with `cargo run`
// because of long time to run
// To run all tests: `cargo run --features=run-all-tests`
#[cfg(feature = "run-all-tests")]
mod trusted_dealer;
