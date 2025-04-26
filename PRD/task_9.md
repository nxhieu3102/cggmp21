# Task 9: Expose WASM Bindings for Threshold Keygen and Signing

## Details
- **ID**: 9
- **Title**: Expose WASM Bindings for Threshold Keygen and Signing
- **Description**: Create WASM bindings for round-by-round threshold keygen and signing functions to make them accessible from JavaScript.
- **Status**: Pending
- **Dependencies**: [7, 8]
- **Priority**: Medium

## Implementation Details
Use wasm-bindgen to annotate threshold keygen and signing round functions for JavaScript interoperability. Ensure state and message serialization to JsValue, and handle errors by converting to JavaScript exceptions. Provide initialization functions for setting up threshold and signing parameters.

## Test Strategy
Extend the JavaScript test script to call threshold keygen and signing functions with dummy data. Validate returned state and messages, and test error handling for invalid inputs or protocol failures. 

## Notice
Before starting this task, create a summary of what needs to be done and break it down into smaller, manageable subtasks. Document this plan in a separate file with checkboxes for each subtask. As you complete each subtask, tick the corresponding checkbox to track progress. This planning approach will help ensure a methodical implementation and clear tracking of progress. 
