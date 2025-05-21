# Task 9: Expose and Integrate `round2_process_reliability_and_generate_broadcast_and_p2p` (WASM & JS)

**ID:** 9
**Status:** pending
**Priority:** high
**Dependencies:** [8]

## Description
Expose the Round 2 processing Rust method to WASM. Update `worker.js` to call this WASM method after collecting reliability check messages (if any), and then manage the sending of broadcast and P2P messages.

## Implementation Details
1. In `cggmp21-wasm`: Add a `#[wasm_bindgen]` method to call `KeygenProtocol::round2_process_reliability_and_generate_broadcast_and_p2p`. Handle (de)serialization for `Option<RoundMsgs<MsgReliabilityCheck<D>>>` input and the tuple `(MsgRound2Broad<E, L>, Vec<Outgoing<Msg<E, L, D>>>)` output.
2. In `cggmp21-wasm/web/worker.js`: After collecting `MsgReliabilityCheck` messages (or proceeding if none), call this WASM method. From the returned tuple, broadcast the `MsgRound2Broad` message and send each P2P message in the `Vec<Outgoing>` to its specific recipient.

## Test Strategy
Integration test: Run the protocol up to this point in a browser. Verify that `worker.js` correctly calls the Round 2 WASM method. Ensure that the Round 2 broadcast message is sent to all, and P2P messages are correctly routed to individual participants. Check for (de)serialization errors or protocol inconsistencies. 
