# Task 4: Expose `KeygenProtocol` (Constructor and Round 1) to WASM

**ID:** 4
**Status:** pending
**Priority:** high
**Dependencies:** [3]

## Description
Create WebAssembly (WASM) bindings for the `KeygenProtocol` Rust struct, its constructor (`new`), and the `round1_generate_commitment` method using `wasm-bindgen`.

## Implementation Details
In the `cggmp21-wasm` crate:
1. Define a new `#[wasm_bindgen]` wrapper struct for `cggmp21_keygen::threshold_stateful::KeygenProtocol`.
2. Implement a `#[wasm_bindgen(constructor)]` for this wrapper struct that calls the underlying Rust `KeygenProtocol::new` method. Ensure it correctly handles parameter passing from JavaScript, including the RNG choice (default to `DevRng` for initialization within WASM, and note PRD mitigation for RNG in WASM).
3. Implement a `#[wasm_bindgen]` method that calls `KeygenProtocol::round1_generate_commitment`. This method must handle `JsValue` deserialization for inputs (if any beyond `self`) and serialization for the `MsgRound1<D>` output, using `serde-wasm-bindgen`.

## Test Strategy
Successfully build the `cggmp21-wasm` module. Develop a minimal JavaScript test script (e.g., using Node.js or a simple HTML page) to instantiate the `KeygenProtocol` WASM object via its constructor and invoke the `round1_generate_commitment` method. Verify that messages can be passed (if applicable) and the round 1 output is received in JS without (de)serialization errors. 
