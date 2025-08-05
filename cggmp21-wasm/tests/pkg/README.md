# CGGMP21 WASM Bindings

This project provides WebAssembly (WASM) bindings for the CGGMP21 threshold ECDSA protocol, allowing it to be used in web applications.

## Features

- Round-by-round key generation functions exposed to JavaScript
- State management between rounds
- Serialization/deserialization of protocol messages
- Simple test application

## Prerequisites

- Rust and Cargo (https://rustup.io/)
- wasm-pack (https://rustwasm.github.io/wasm-pack/installer/)
- Node.js and npm (https://nodejs.org/)

## Building

1. Clone the repository:
   ```
   git clone <repository-url>
   cd cggmp21-wasm
   ```

2. Build the WASM module:
   ```
   ./build.sh
   ```
   This will create the pkg/ directory containing the compiled WASM module and JavaScript bindings.

3. Set up the test environment:
   ```
   cd web
   npm install
   ```

## Running the Test Application

1. Start the test server:
   ```
   cd web
   npm start
   ```

2. Open a web browser and navigate to:
   ```
   http://localhost:3000
   ```

3. The test application will run automatically and show the results in the browser.

## Project Structure

- `src/keygen/` - WASM bindings for keygen protocol
- `web/` - Test application and server
- `pkg/` - Compiled WASM module and JavaScript bindings (generated)

## Implementation Details

The implementation follows a round-by-round approach for the key generation protocol:

1. `run_round_1`: Generates random values and commitments for the first round
2. `run_round_2`: Processes round 1 messages and sends decommitments
3. `run_round_3`: Processes round 2 messages and sends proofs
4. `finalize`: Processes round 3 messages and generates the final key share

Each function handles the state transition and message processing between rounds.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 
