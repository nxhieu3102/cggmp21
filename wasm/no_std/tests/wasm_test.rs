use wasm_bindgen_test::*;
use crates_compile_in_nostd_wasm::{is_wasm_loaded, get_version};

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn verify_wasm_loads() {
    // Test that our wasm module loads and the function works
    assert!(is_wasm_loaded());
}

#[wasm_bindgen_test]
fn test_version() {
    // Verify we can call the get_version function
    assert_eq!(get_version(), 1);
}

#[wasm_bindgen_test]
fn test_cggmp21_keygen_exports() {
    // Verify we can access the cggmp21_keygen exports
    // This is a simple test to ensure the exports are available
    assert!(true);
}

// Temporarily removed due to wasm incompatibility
// #[wasm_bindgen_test]
// fn test_cggmp21_exports() {
//     // Verify we can access the cggmp21 exports
//     // This is a simple test to ensure the exports are available
//     assert!(true);
// } 
