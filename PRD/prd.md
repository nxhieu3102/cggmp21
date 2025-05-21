# Product Requirements Document: Stateful WASM KeygenProtocol

# Overview
This document outlines the requirements for refactoring the existing CGGMP21 threshold key generation protocol implementation in `cggmp21-keygen/src/threshold.rs`. The current monolithic `run_threshold_keygen` function will be transformed into a stateful Rust struct, `KeygenProtocol`. This refactoring aims to make the key generation logic more modular, easier to manage for WebAssembly (WASM) multi-round interactions, and align with the JavaScript orchestration pattern already in place in `cggmp21-wasm/web/worker.js`. The primary goal is to enable robust and secure threshold key generation directly within a web browser environment.

# Core Features
1.  **Stateful `KeygenProtocol` Rust Struct**:
    *   **What it does**: Encapsulates the entire state and logic of the threshold key generation protocol.
    *   **Why it's important**: Manages complex cryptographic state across multiple asynchronous rounds required by WASM/JavaScript interaction, replacing the current monolithic function.
    *   **How it works at a high level**: It will hold all intermediate cryptographic values, party configurations, and an RNG instance. It will expose methods for each round of the protocol.
2.  **Round-Specific Methods**:
    *   **What it does**: The `KeygenProtocol` struct will have distinct public methods for each logical round/step of the key generation process (e.g., `round1_generate_commitment`, `round2_process_broadcast_and_p2p`, `finalize_keygen`).
    *   **Why it's important**: Allows JavaScript to drive the protocol round by round, passing messages and receiving new ones to send, which is essential for non-blocking web applications.
    *   **How it works at a high level**: Each method will consume messages from the previous round (if any), perform its cryptographic operations using and updating the internal state, and return the messages to be sent for the current round or the final result.
3.  **Integrated RNG Management**:
    *   **What it does**: The `KeygenProtocol` will initialize and manage its own cryptographic Random Number Generator (RNG) instance.
    *   **Why it's important**: Ensures that all cryptographic operations within the protocol use a consistent and secure source of randomness, which is critical for security.
    *   **How it works at a high level**: An RNG (e.g., `DevRng` or a WASM-compatible alternative) will be instantiated in the `KeygenProtocol`'s constructor and stored as a field, then used by all subsequent round methods.
4.  **WASM Bindings for `KeygenProtocol`**:
    *   **What it does**: The `KeygenProtocol` Rust struct and its methods will be exposed to JavaScript using `wasm-bindgen`.
    *   **Why it's important**: Makes the Rust protocol logic callable from the JavaScript environment in `cggmp21-wasm/web/worker.js`.
    *   **How it works at a high level**: A wrapper struct and methods in `cggmp21-wasm` will handle `JsValue` (de)serialization and expose the protocol's interface.
5.  **Revised JavaScript Orchestration**:
    *   **What it does**: The `cggmp21-wasm/web/worker.js` will be updated to instantiate and use the new stateful `KeygenProtocol` WASM object.
    *   **Why it's important**: Aligns the JavaScript control flow with the stateful Rust backend, simplifying message passing and state handling on the JS side.
    *   **How it works at a high level**: JS will call methods like `keygenWasmInstance.round1_generate_commitment()`, send the resulting messages, collect responses, and then call `keygenWasmInstance.round2_process_messages(collected_msgs)`, and so on.

# User Experience
This refactoring primarily targets the **developer experience** and the **overall system architecture** rather than end-user UI directly.
*   **Improved Modularity**: Rust code becomes more organized and easier to understand, with distinct responsibilities for state management and round logic.
*   **Enhanced Testability**: Individual rounds or state transitions within the `KeygenProtocol` can potentially be tested more easily.
*   **Simplified WASM Integration**: A stateful object model is often more natural to work with from JavaScript for multi-step operations.
*   **Maintainability**: Clearer separation of concerns will make future updates or debugging more straightforward.

# Technical Architecture

1.  **Rust `cggmp21-keygen` Crate (e.g., in `src/threshold_stateful.rs`):**
    *   **`KeygenState<E: Curve, L: SecurityLevel>` struct**:
        *   Fields: `i`, `t`, `n`, `sid: ExecutionId<'static>`, `reliable_broadcast_enforced`, `#[cfg(feature = "hd-wallet")] hd_enabled`, `schnorr_secret_r`, `my_decommitment_msg_round2broad`, `f_i_evaluations_sigmas_ij`, `commitments_from_r1_store`, `combined_rid`, `#[cfg(feature = "hd-wallet")] combined_chain_code`, `all_public_shares_ys`, `my_secret_share_sigma_i`. (This list is indicative and will be finalized during implementation based on `run_threshold_keygen`'s local variables.)
    *   **`KeygenProtocol<E: Curve, R: RngCore + CryptoRng, L: SecurityLevel, D: Digest>` struct**:
        *   Fields: `state: KeygenState<E, L>`, `rng: R`.
        *   **`new(...)`**: Constructor initializing state and RNG.
        *   **Round Methods (illustrative names)**:
            *   `round1_generate_commitment(&mut self) -> Result<MsgRound1<D>, KeygenError>`
            *   `round1_receive_commitments_and_prep_reliability_check(&mut self, commitments_from_r1: RoundMsgs<MsgRound1<D>>) -> Result<Option<MsgReliabilityCheck<D>>, KeygenError>`
            *   `round2_process_reliability_and_generate_broadcast_and_p2p(&mut self, reliability_hashes: Option<RoundMsgs<MsgReliabilityCheck<D>>>) -> Result<(MsgRound2Broad<E, L>, Vec<Outgoing<Msg<E, L, D>>>), KeygenError>`
            *   `round3_process_decommitments_and_shares_and_generate_schnorr_proof(&mut self, decommitments_from_r2: RoundMsgs<MsgRound2Broad<E, L>>, sigmas_from_r2: RoundMsgs<MsgRound2Uni<E>>) -> Result<MsgRound3<E>, KeygenError>`
            *   `finalize_keygen(&mut self, schnorr_proofs_from_r3: RoundMsgs<MsgRound3<E>>) -> Result<CoreKeyShare<E>, KeygenError>`
        *   All methods will mutate `self.state` and use `self.rng`.
2.  **Rust `cggmp21-wasm` Crate:**
    *   A `#[wasm_bindgen]` struct will wrap `cggmp21_keygen::threshold_stateful::KeygenProtocol`.
    *   Its `#[wasm_bindgen(constructor)]` will initialize the Rust `KeygenProtocol` (e.g., with `DevRng`).
    *   `#[wasm_bindgen]` methods will mirror the Rust `KeygenProtocol`'s round methods, handling `JsValue` (de)serialization using `serde-wasm-bindgen`.
    *   Existing stateless functions in `cggmp21-wasm/src/keygen/messages.rs` will be largely replaced or refactored as internal helpers if their JS input parsing structs remain useful.
3.  **JavaScript Orchestration (`cggmp21-wasm/web/worker.js`):**
    *   The worker will instantiate the WASM `KeygenProtocol` object.
    *   It will call the round methods sequentially, passing received messages (deserialized if necessary, though `serde-wasm-bindgen` can handle this) and sending out returned messages.
    *   The primary protocol state will reside within the WASM object.
4.  **Error Handling**: Rust `Result::Err` (e.g., `KeygenError`) will be propagated as JavaScript exceptions.

# Development Roadmap

*   **Phase 1 (MVP Foundation)**:
    *   Define `KeygenState` and `KeygenProtocol` structs in `cggmp21-keygen`.
    *   Implement `KeygenProtocol::new`.
    *   Implement `KeygenProtocol::round1_generate_commitment`.
    *   Expose `KeygenProtocol` and its `new` and `round1_generate_commitment` methods to WASM.
    *   Update `worker.js` to instantiate `KeygenProtocol` and execute round 1.
    *   **Goal**: Successfully generate and broadcast the first round's message from the browser using the new stateful approach.
*   **Phase 2 (Sequential Round Implementation)**:
    *   Implement `KeygenProtocol::round1_receive_commitments_and_prep_reliability_check`. Expose & Integrate.
    *   Implement `KeygenProtocol::round2_process_reliability_and_generate_broadcast_and_p2p`. Expose & Integrate.
    *   Implement `KeygenProtocol::round3_process_decommitments_and_shares_and_generate_schnorr_proof`. Expose & Integrate.
    *   **Goal**: Each round's logic is correctly implemented in Rust, callable from JS, and messages are correctly passed.
*   **Phase 3 (Finalization and Key Share Generation)**:
    *   Implement `KeygenProtocol::finalize_keygen`. Expose & Integrate.
    *   Ensure the final `CoreKeyShare` is correctly generated and returned to JavaScript.
    *   **Goal**: The full key generation protocol can be executed end-to-end, producing a valid key share.
*   **Phase 4 (Hardening & Testing)**:
    *   Thorough end-to-end testing of the WASM module within the browser environment.
    *   Refine error handling and propagation.
    *   Review security considerations, especially around state and RNG.
    *   Implement unit tests for `KeygenProtocol` methods in Rust where feasible.
    *   **Goal**: A robust, secure, and well-tested threshold key generation module for the web.

# Logical Dependency Chain
1.  **Rust Struct Definition**: The `KeygenState` and `KeygenProtocol` structs must be defined first in `cggmp21-keygen`.
2.  **Constructor Implementation**: The `new` method for `KeygenProtocol` is the entry point.
3.  **Round 1 Logic (Rust)**: Implement the first round's logic within `KeygenProtocol`.
4.  **WASM Binding for Round 1**: Expose the constructor and the first round's method via `wasm-bindgen`.
5.  **JS Integration for Round 1**: Update `worker.js` to use the new WASM interface for round 1.
6.  **Iterative Development**: For each subsequent round:
    *   Implement the round logic in the Rust `KeygenProtocol`.
    *   Update/add WASM bindings for the new method.
    *   Update `worker.js` to call the new method and handle its inputs/outputs.
7.  **Finalization Logic**: Implement the final key share generation and validation.
8.  **Comprehensive Testing**: After all rounds are integrated.

# Risks and Mitigations

*   **Complexity of State Management**:
    *   **Risk**: Incorrectly managing state between rounds can lead to difficult-to-debug cryptographic errors.
    *   **Mitigation**: Carefully map all necessary local variables from `run_threshold_keygen` to fields in `KeygenState`. Thoroughly review state transitions with each round method. Incremental implementation and testing per round.
*   **WASM Integration Challenges**:
    *   **Risk**: Issues with data serialization/deserialization between Rust and JavaScript, or unexpected behavior of WASM modules.
    *   **Mitigation**: Leverage `serde-wasm-bindgen` for robust (de)serialization. Start with simple data types and incrementally add complexity. Use browser debugging tools for WASM.
*   **Cryptographic Correctness**:
    *   **Risk**: Introducing errors during refactoring that compromise the security or correctness of the protocol.
    *   **Mitigation**: Adhere closely to the logic of the original, audited `run_threshold_keygen`. Perform extensive testing, potentially comparing outputs with a known-good implementation if possible. Code reviews focused on cryptographic steps.
*   **RNG in WASM Environment**:
    *   **Risk**: `DevRng` might have limitations or behave differently in a WASM/browser sandbox compared to a native environment.
    *   **Mitigation**: Research and confirm the best practices for cryptographic RNG in `wasm-bindgen` environments. If `DevRng` is problematic, explore alternatives like `getrandom` crate with `js` feature or passing entropy from JavaScript. For now, assume `DevRng` can be made to work or a suitable substitute found.
*   **Debugging Multi-Party Asynchronous Logic**:
    *   **Risk**: Diagnosing issues that span across multiple parties, the WebSocket server, and the internal state of the WASM module can be challenging.
    *   **Mitigation**: Implement comprehensive logging on both the JS and Rust (via `wasm-logger` or similar) sides. Develop a clear mental model of the message flow. Test with a minimal number of parties initially.

# Appendix
*   **Target Rust Crate**: `cggmp21-keygen` (specifically `src/threshold.rs` and a new `src/threshold_stateful.rs`).
*   **WASM Binding Crate**: `cggmp21-wasm`.
*   **JavaScript Orchestration**: `cggmp21-wasm/web/worker.js`.
*   **Key Security Primitive**: CGGMP21 Threshold Key Generation.
*   **External Crates**: `generic-ec`, `round-based`, `digest`, `rand_core`, `schnorr_pok`, `udigest`, `serde`, `wasm-bindgen`, `serde-wasm-bindgen`.
