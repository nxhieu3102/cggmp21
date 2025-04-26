# Task 4 Plan: Expose WASM Bindings for Keygen Round Functions

## Overview
This plan outlines the steps to implement WASM bindings for the CGGMP21 keygen round functions, making them callable from JavaScript. We'll focus on the non-threshold keygen protocol initially.

## Implementation Tasks

- [ ] **1. Create State Representation**
  - [ ] Define serializable state struct for keygen protocol
  - [ ] Implement serialization/deserialization to/from JsValue
  - [ ] Create error handling structure for JavaScript

- [ ] **2. Initialize Keygen Protocol**
  - [ ] Create initialization function with wasm-bindgen
  - [ ] Accept party ID, number of parties, and other configuration
  - [ ] Return initial state

- [ ] **3. Round 1 Implementation**
  - [ ] Implement run_round_1 function
  - [ ] Generate random values and commitments
  - [ ] Return serialized state and outgoing messages

- [ ] **4. Reliability Check Implementation (if needed)**
  - [ ] Implement reliability_check function
  - [ ] Process incoming messages and update state
  - [ ] Return updated state and outgoing messages

- [ ] **5. Round 2 Implementation**
  - [ ] Implement run_round_2 function
  - [ ] Process incoming messages from round 1
  - [ ] Generate round 2 messages
  - [ ] Return updated state and outgoing messages

- [ ] **6. Round 3 Implementation**
  - [ ] Implement run_round_3 function
  - [ ] Process incoming messages from round 2
  - [ ] Generate round 3 messages
  - [ ] Return updated state and outgoing messages 

- [ ] **7. Finalize Keygen**
  - [ ] Implement finalize function
  - [ ] Process incoming messages from round 3
  - [ ] Generate key share
  - [ ] Return final key share

- [ ] **8. Testing**
  - [ ] Create JavaScript test script
  - [ ] Test each round function with sample data
  - [ ] Test error conditions
  - [ ] Verify correct finalization

- [ ] **9. JavaScript Helper Functions**
  - [ ] Create JavaScript wrappers for easier integration
  - [ ] Add documentation and examples
  - [ ] Integrate with existing WebWorker and WebSocket framework

## Notes
- Will use serde and wasm-bindgen for serialization
- Will need to adapt the round-based protocol to a stateful approach
- Error handling must convert Rust errors to JavaScript exceptions
- State must be serialized/deserialized between round calls 
