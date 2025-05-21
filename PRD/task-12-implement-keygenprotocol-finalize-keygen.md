# Task 12: Implement `KeygenProtocol::finalize_keygen`

**ID:** 12
**Status:** pending
**Priority:** high
**Dependencies:** [11]

## Description
Implement the final Rust logic for key generation within `KeygenProtocol`. This involves processing Schnorr proofs from all parties (from Round 3 messages) and generating the final `CoreKeyShare`.

## Implementation Details
In `KeygenProtocol` (in `cggmp21-keygen/src/threshold_stateful.rs`):
Implement `finalize_keygen(&mut self, schnorr_proofs_from_r3: RoundMsgs<MsgRound3<E>>) -> Result<CoreKeyShare<E>, KeygenError>`. This method consumes `RoundMsgs<MsgRound3<E>>`. It validates all received Schnorr proofs, computes the final secret key share (`my_secret_share_sigma_i`), and assembles the complete `CoreKeyShare<E>` object which includes the public key, individual party public key shares, and the local secret share data. If `hd_enabled`, ensure the `chain_code` is included in the result or handled appropriately.

## Test Strategy
Unit test `finalize_keygen`. Provide mock `RoundMsgs<MsgRound3<E>>` input. Verify the correct generation and structure of the `CoreKeyShare<E>` object. Specifically check the computation of the local secret share and the aggregated public key. Check `self.state.my_secret_share_sigma_i`. 
