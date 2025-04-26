# Task 8: Refactor Signing Protocol for Round-by-Round Execution

## Details
- **ID**: 8
- **Title**: Refactor Signing Protocol for Round-by-Round Execution
- **Description**: Adapt the signing protocol in cggmp21 to support per-round execution with state serialization for WASM environments.
- **Status**: Pending
- **Dependencies**: [3, 7]
- **Priority**: Medium

## Implementation Details
Refactor signing_n_out_of_n and related functions into round-specific functions (e.g., signing_round_1) under wasm-rounds feature. Define a SigningState struct for state persistence, serializable with serde. Ensure compatibility with presignature and full signing modes, handling message exchanges per round.

## Test Strategy
Test each signing round function individually with mock data, then simulate a full signing protocol sequence. Verify partial signatures and final signature output against the original implementation for accuracy. 

## Notice
Before starting this task, create a summary of what needs to be done and break it down into smaller, manageable subtasks. Document this plan in a separate file with checkboxes for each subtask. As you complete each subtask, tick the corresponding checkbox to track progress. This planning approach will help ensure a methodical implementation and clear tracking of progress. 
