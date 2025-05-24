# Task 6: Implement `KeygenProtocol::round1_receive_commitments_and_prep_reliability_check`

**ID:** 6
**Status:** pending
**Priority:** high
**Dependencies:** [5]

## Description
Implement the Rust logic within `KeygenProtocol` to process incoming commitment messages from all parties from round 1 and, if configured, prepare messages for the reliability check phase.

## Implementation Details
In `KeygenProtocol` (in `cggmp21-keygen/src/threshold_stateful.rs`):
Implement the method `round1_receive_commitments_and_prep_reliability_check(&mut self, commitments_from_r1: RoundMsgs<MsgRound1<D>>) -> Result<Option<MsgReliabilityCheck<D>>, KeygenError>`. This method will consume `RoundMsgs<MsgRound1<D>>` containing messages from all parties. It must update `self.state` by storing these commitments (e.g., in `commitments_from_r1_store`). If `reliable_broadcast_enforced` is true in the state, it should generate and return `Some(MsgReliabilityCheck<D>)`; otherwise, it returns `Ok(None)`.

## Test Strategy
Unit test `round1_receive_commitments_and_prep_reliability_check`. Create mock `RoundMsgs<MsgRound1<D>>` input. Call the method. Verify that `self.state.commitments_from_r1_store` (or equivalent) is correctly populated. Verify that it returns `Some(MsgReliabilityCheck)` when `reliable_broadcast_enforced` is true and `None` when false. Check the content of `MsgReliabilityCheck`. 
