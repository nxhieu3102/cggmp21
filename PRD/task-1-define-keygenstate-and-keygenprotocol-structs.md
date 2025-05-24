# Task 1: Define `KeygenState` and `KeygenProtocol` Structs in `cggmp21-keygen`

**ID:** 1
**Status:** completed
**Priority:** high
**Dependencies:** None

## Description
Define the core Rust structs `KeygenState` and `KeygenProtocol` in the `cggmp21-keygen` crate, as per the PRD. This includes all specified fields for managing cryptographic state and protocol logic.

## Implementation Details
In `cggmp21-keygen/src/threshold_stateful.rs` (create if not exists):
Define `KeygenState<E: Curve, L: SecurityLevel>` struct. Fields to include: `i`, `t`, `n`, `sid: ExecutionId<'static>`, `reliable_broadcast_enforced`, `#[cfg(feature = "hd-wallet")] hd_enabled`, `schnorr_secret_r`, `my_decommitment_msg_round2broad`, `f_i_evaluations_sigmas_ij`, `commitments_from_r1_store`, `combined_rid`, `#[cfg(feature = "hd-wallet")] combined_chain_code`, `all_public_shares_ys`, `my_secret_share_sigma_i`. This list is indicative and should be finalized during implementation by referencing local variables in the existing `run_threshold_keygen` function.
Define `KeygenProtocol<E: Curve, R: RngCore + CryptoRng, L: SecurityLevel, D: Digest>` struct. Fields to include: `state: KeygenState<E, L>`, `rng: R`.

## Test Strategy
Code review to ensure all PRD-specified fields (and those derived from `run_threshold_keygen`) are included and types are correct. Ensure the `cggmp21-keygen` crate compiles successfully after these definitions are added. 
