# Task 3: Implement `KeygenProtocol::round1_generate_commitment`

**ID:** 3
**Status:** completed
**Priority:** high
**Dependencies:** [2]

## Description
Implement the logic for the first round of the threshold key generation protocol within the `KeygenProtocol` struct. This method will generate and return the party's commitment message.

## Implementation Details
In the `KeygenProtocol` struct (in `cggmp21-keygen/src/threshold_stateful.rs`):
Implement the method `round1_generate_commitment(&mut self) -> Result<MsgRound1<D>, KeygenError>`. This method must use `self.rng` for any cryptographic randomness needed. It will update fields in `self.state` such as `schnorr_secret_r` and `my_decommitment_msg_round2broad` (or equivalents, based on analysis of `run_threshold_keygen`) with intermediate values critical for subsequent protocol rounds. The method returns the `MsgRound1` to be broadcast.

## Test Strategy
Unit test `round1_generate_commitment`. Call the method on an initialized `KeygenProtocol` instance. Verify the structure and content of the returned `MsgRound1<D>` object. Assert that relevant fields within `self.state` are correctly populated or updated as per the protocol's requirements for round 1. 
