# WASM Protocol Demo

A simple two-round protocol implementation demonstrating the interaction between Rust (compiled to WebAssembly) and JavaScript, using WebSockets for communication between parties.

## Overview

This project demonstrates a minimal 4-party protocol with the following components:

1. **Rust WASM Module**: Handles core protocol logic, random number generation, and computation
2. **JavaScript Client**: Orchestrates the protocol, loads the WASM module, and manages the UI
3. **Web Worker**: Handles WebSocket communication with other parties
4. **WebSocket Server**: Relays messages between the 4 parties

The protocol consists of two rounds:
- **Round 1**: Each party generates a random number and sends it to all other parties
- **Round 2**: Each party collects the numbers from all other parties, computes the sum, and displays the result

## Prerequisites

To build and run this project, you'll need:

- [Rust](https://www.rust-lang.org/tools/install) (with cargo)
- [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/)
- [Node.js](https://nodejs.org/) (v14 or later)
- A modern web browser

## Setup Instructions

1. **Clone the repository**

```bash
git clone <repository-url>
cd wasm-protocol
```

2. **Install Node.js dependencies**

```bash
npm install
```

3. **Build the Rust WASM module**

```bash
wasm-pack build --target web
```

This will compile the Rust code to WebAssembly and generate the necessary JavaScript bindings in the `pkg` directory.

4. **Start the WebSocket server**

```bash
npm start
```

This will start the WebSocket server on port 8080.

5. **Serve the web application**

You'll need a static file server to serve the web application. You can use any tool you prefer, such as:

```bash
# Using Node.js http-server
npx http-server . -p 3000
```

## Running the Protocol

1. Open the web application in a browser by navigating to http://localhost:3000
2. To test the full protocol, open 4 separate browser windows/tabs
3. In each browser window:
   - You'll be assigned a random party ID (or you can enter a custom one)
   - Click "Start Protocol" to begin
4. Each party will:
   - Generate a random number (between 1 and 100)
   - Send this number to the other parties
   - Collect numbers from the other parties
   - Compute the sum of all 4 numbers
   - Display the result

All 4 parties should compute the same final sum, confirming the protocol's correctness.

## Running Tests

The project includes unit tests for the Rust code and integration tests for the JavaScript components:

### Rust Unit Tests

```bash
cd wasm-protocol
cargo test
```

### JavaScript Integration Tests

```bash
npm test
```

This will run both the Rust tests and the JavaScript tests using Jest.

## Project Structure

- `src/lib.rs`: Rust implementation of the protocol logic
- `index.js`: Main JavaScript file that orchestrates the protocol
- `worker.js`: Web Worker for WebSocket communication
- `server.js`: WebSocket server for relaying messages
- `index.html`: Web interface
- `test.js`: JavaScript integration tests

## Implementation Details

### Rust WASM Module

The Rust module provides:
- A `Protocol` struct to maintain the protocol state
- Function to generate a random number for Round 1
- Function to compute the sum of all numbers for Round 2
- Utilities for message creation and serialization

### JavaScript Application

The JavaScript application:
- Loads and initializes the WASM module
- Creates a Web Worker for WebSocket communication
- Orchestrates the protocol flow (rounds 1 and 2)
- Updates the UI with the protocol state and results

### Web Worker

The Web Worker:
- Manages WebSocket connections
- Sends messages to other parties
- Collects messages from other parties
- Handles reconnection and error scenarios

### WebSocket Server

The Node.js server:
- Accepts WebSocket connections from all parties
- Broadcasts messages to the appropriate recipients
- Handles connection/disconnection events

## Error Handling

The implementation includes error handling for:
- WebSocket connection failures
- Invalid or malformed messages
- Timeouts if messages are not received

## License

MIT 
