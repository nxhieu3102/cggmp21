# Task 7: Refactor Threshold Keygen for Round-by-Round Execution

## Details
- **ID**: 7
- **Title**: Refactor Threshold Keygen for Round-by-Round Execution
- **Description**: Extend round-by-round execution to the threshold keygen protocol in cggmp21-keygen for WASM compatibility.
- **Status**: Pending
- **Dependencies**: [3]
- **Priority**: Medium

## Implementation Details
Similar to non-threshold keygen, break down run_threshold_keygen into per-round functions under the wasm-rounds feature. Reuse or adapt the KeygenState struct for threshold parameters, ensuring state serialization with serde. Handle additional complexity of threshold parameters (e.g., t out of n) in round logic.

## Test Strategy
Unit test each round function for threshold keygen with varying t and n values. Simulate a full threshold keygen with mock messages, comparing output to the original monolithic function for correctness. 

## Notice
Before starting this task, create a summary of what needs to be done and break it down into smaller, manageable subtasks. Document this plan in a separate file with checkboxes for each subtask. As you complete each subtask, tick the corresponding checkbox to track progress. This planning approach will help ensure a methodical implementation and clear tracking of progress. 
