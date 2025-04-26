# WASM Adaptation for CGGMP21 Protocol - Product Requirements Document (PRD)

## Overview
The WASM Adaptation for CGGMP21 Protocol aims to make the threshold ECDSA protocol (based on the CGGMP21 paper) compatible with web environments. This product solves the problem of running complex multi-party computation (MPC) protocols in browser-based applications, targeting developers and organizations building secure, decentralized applications (dApps) that require threshold signatures. Its value lies in enabling secure key generation and signing directly in web browsers, eliminating the need for native applications while maintaining cryptographic security.

## Core Features

### 1. Round-by-Round Protocol Execution
- **What it does**: Breaks down monolithic protocol functions (e.g., key generation, signing) into smaller, per-round functions that can be called independently from JavaScript.
- **Why it's important**: Allows handling of networking outside Rust via JavaScript (using WebSocket), addressing WASM's inability to directly manage network operations and preventing UI blocking during long computations.
- **How it works at a high level**: Each round function processes incoming messages, performs necessary computations, and returns outgoing messages along with a serialized state to maintain protocol continuity.

### 2. WASM-Compatible API
- **What it does**: Provides bindings for the CGGMP21 protocol functions using `wasm-bindgen`, enabling seamless interaction between Rust and JavaScript.
- **Why it's important**: Facilitates integration with web applications, allowing developers to use the protocol without deep Rust knowledge.
- **How it works at a high level**: Exposes round functions and state management to JavaScript, serializing data for transfer between WASM and the browser environment.

### 3. WebWorker Integration for Computation
- **What it does**: Offloads heavy cryptographic computations to WebWorkers to prevent blocking the main browser thread.
- **Why it's important**: Ensures a smooth user experience in web applications by keeping the UI responsive during protocol execution.
- **How it works at a high level**: WASM modules run within WebWorkers, receiving input and sending output via message passing with the main thread.

### 4. WebSocket-Based Networking
- **What it does**: Leverages JavaScript to handle networking via WebSocket for message exchange between protocol participants.
- **Why it's important**: Overcomes WASM's networking limitations by delegating communication to JavaScript, ensuring secure and authenticated message passing.
- **How it works at a high level**: JavaScript manages WebSocket connections, sending outgoing messages from the protocol and feeding incoming messages back to the WASM module.

## User Experience

### User Personas
- **dApp Developers**: Developers building decentralized applications requiring threshold ECDSA for secure key management and signing, who need an easy-to-integrate solution for web environments.
- **Cryptography Enthusiasts**: Individuals or teams experimenting with MPC protocols in browser contexts, seeking accessible tools for testing and deployment.

### Key User Flows
1. **Setup**: Developer integrates the WASM CGGMP21 library into their web application, initializing it with necessary parameters (e.g., party index, number of parties).
2. **Protocol Execution**: Developer triggers protocol rounds (e.g., keygen, signing) via JavaScript, with the application handling networking (sending/receiving messages) and passing data to/from WebWorkers running the WASM code.
3. **Result Handling**: Upon completion of all rounds, the application receives the final output (e.g., key share, signature) for use in the dApp.

### UI/UX Considerations
- **Ease of Integration**: Provide clear documentation and example code for integrating the library with popular web frameworks (e.g., React, Vue.js).
- **Feedback Mechanism**: Include progress indicators or callbacks in the API to inform users about the current round or protocol status, enhancing transparency during long-running operations.
- **Error Handling**: Ensure the API surfaces meaningful errors to JavaScript for debugging and user notification.

## Technical Architecture

### System Components
- **Core CGGMP21 Library**: Existing Rust crates (`cggmp21`, `cggmp21-keygen`) providing the protocol logic.
- **WASM Wrapper Module**: A new or extended module under a feature flag (e.g., `wasm-rounds`) that refactors protocol execution into round-by-round functions.
- **JavaScript Bridge**: Scripts to handle WebSocket networking and WebWorker management, interfacing with the WASM module.

### Data Models
- **Protocol State**: A serializable struct (e.g., `KeygenState`, `SigningState`) to store the protocol's internal state between rounds, ensuring continuity.
- **Message Format**: Structured data for incoming and outgoing messages, adhering to the CGGMP21 message types, serialized for JavaScript compatibility.

### APIs and Integrations
- **WASM API**: Exposed functions via `wasm-bindgen` for each protocol round (e.g., `keygen_round_1`, `signing_round_2`), accepting state and incoming messages, returning updated state and outgoing messages.
- **JavaScript API**: Helper functions to manage WebSocket connections, WebWorker communication, and protocol orchestration.

### Infrastructure Requirements
- **Build Tools**: `wasm-pack` for compiling Rust to WASM, ensuring compatibility with browser environments.
- **Web Environment**: Modern browsers supporting WebAssembly, WebWorkers, and WebSocket.
- **Testing Setup**: Simulated multi-party environments for testing protocol execution in a web context.

## Development Roadmap

### MVP Requirements
- **Round-by-Round Keygen**: Implement round-by-round execution for non-threshold key generation in `cggmp21-keygen`, including state serialization and WASM bindings.
- **Basic JavaScript Integration**: Develop a minimal JavaScript application to test keygen rounds using WebSocket for networking and WebWorker for computation.
- **Documentation**: Provide initial guides for setup and usage in web applications.

### Future Enhancements
- **Full Protocol Support**: Extend round-by-round execution to threshold keygen and signing protocols in `cggmp21`.
- **Performance Optimization**: Optimize state serialization and WebWorker communication, exploring SharedArrayBuffer if feasible.
- **Advanced Examples**: Create comprehensive examples for popular web frameworks, showcasing real-world dApp integration.
- **Security Enhancements**: Implement encryption for sensitive state data passed to JavaScript, ensuring robust security in browser environments.

## Logical Dependency Chain

### Foundation
- **WASM Build Setup**: Establish the build pipeline for compiling CGGMP21 to WASM using `wasm-pack`.
- **Round-by-Round Refactoring for Keygen**: Refactor non-threshold keygen to support per-round execution with state management.

### Quick Usable Front-End
- **Minimal JavaScript Demo**: Build a simple web app to demonstrate keygen protocol execution, focusing on visible progress (e.g., round completion indicators) and basic functionality.

### Pacing and Scoping Features
- **Threshold Keygen and Signing**: Incrementally add support for other protocols, ensuring each is fully functional before moving to the next.
- **UI/UX Improvements**: Enhance the JavaScript API with better feedback mechanisms and error handling after core functionality is stable.
- **Optimization and Security**: Address performance and security concerns as later iterations, building on a solid functional base.

## Risks and Mitigations

### Technical Challenges
- **State Serialization Complexity**: Serializing and deserializing protocol state between rounds may introduce errors. **Mitigation**: Thoroughly test state management with edge cases and use robust serialization formats (e.g., JSON via `serde`).
- **Performance Overhead**: Frequent context switching between JavaScript and WASM could impact performance. **Mitigation**: Optimize data transfer and explore advanced WebAssembly features like SharedArrayBuffer.

### Figuring Out the MVP
- **Scope Creep**: Risk of overcomplicating the MVP with non-essential features. **Mitigation**: Focus strictly on non-threshold keygen for MVP, deferring other protocols to future phases.

### Resource Constraints
- **Development Time**: Limited time to refactor and test WASM integration. **Mitigation**: Prioritize incremental development, starting with a small, testable component, and leverage community feedback for iterative improvement.

## Appendix

### Research Findings
- WASM's single-threaded nature and networking limitations necessitate external handling via JavaScript, aligning with the proposed WebSocket and WebWorker approach.
- Existing libraries like `wasm-bindgen` and `wasm-pack` provide robust tools for Rust-to-WASM integration, supporting the feasibility of this project.

### Technical Specifications
- **Rust Dependencies**: `wasm-bindgen`, `serde` for state management, existing `cggmp21` and `cggmp21-keygen` crates.
- **JavaScript Environment**: Requires modern browsers with WebAssembly, WebWorker, and WebSocket support (e.g., Chrome 85+, Firefox 79+). 
