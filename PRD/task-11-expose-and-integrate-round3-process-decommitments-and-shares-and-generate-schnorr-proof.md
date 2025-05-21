# Task 11: Expose and Integrate `round3_process_decommitments_and_shares_and_generate_schnorr_proof` (WASM & JS)

**ID:** 11
**Status:** pending
**Priority:** high
**Dependencies:** [10]

## Description
Expose the Round 3 processing Rust method to WASM. Update `worker.js` to call this WASM method after collecting all Round 2 messages, and then manage the sending of the Round 3 message.

## Implementation Details
1. In `cggmp21-wasm`: Add `#[wasm_bindgen]` method for `KeygenProtocol::round3_process_decommitments_and_shares_and_generate_schnorr_proof`. Handle (de)serialization for inputs (`RoundMsgs<MsgRound2Broad>`, `RoundMsgs<MsgRound2Uni>`) and output (`MsgRound3<E>`).
2. In `cggmp21-wasm/web/worker.js`: After collecting all Round 2 broadcast and P2P messages, call this WASM method. Broadcast the resulting `MsgRound3` message to all participants.

## Test Strategy
Integration test: Run the protocol through Round 3 in a browser. Verify `worker.js` calls the Round 3 WASM method. Ensure the `MsgRound3` (Schnorr proof) is correctly generated, returned to JS, and broadcast. Monitor for errors. 
