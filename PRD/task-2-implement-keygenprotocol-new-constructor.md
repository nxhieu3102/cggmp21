# Task 2: Implement `KeygenProtocol::new` Constructor

**ID:** 2
**Status:** completed
**Priority:** high
**Dependencies:** [1]

## Description
Implement the constructor for the `KeygenProtocol` struct. This method will initialize the `KeygenState` and the cryptographic Random Number Generator (RNG).

## Implementation Details
In the `KeygenProtocol` struct located in `cggmp21-keygen/src/threshold_stateful.rs`:
Implement the `new(...)` method. This constructor should accept necessary parameters (e.g., `i, t, n, sid`, configuration flags like `reliable_broadcast_enforced`, `hd_enabled`) to fully initialize an instance of `KeygenState`. It should also initialize the `rng` field, for example, with `DevRng`. Address potential WASM compatibility issues for RNG as noted in PRD risk assessment if `DevRng` proves problematic.

## Test Strategy
Write a unit test for the `KeygenProtocol::new` constructor. Instantiate `KeygenProtocol` with a set of valid parameters and assert that the internal `state` fields are initialized to their expected values and the `rng` is successfully instantiated. 
