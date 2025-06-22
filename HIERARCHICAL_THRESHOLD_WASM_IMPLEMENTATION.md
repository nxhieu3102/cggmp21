# Hierarchical Threshold Key Generation for WASM

## Overview

This document describes the implementation of hierarchical threshold secret sharing (HTSS) key generation protocol for WebAssembly (WASM), extending the existing CGGMP21 implementation.

## What is Hierarchical Threshold Secret Sharing?

Unlike traditional threshold secret sharing where any `t` out of `n` parties can recover the secret, hierarchical threshold secret sharing assigns **ranks** to parties that determine their access privileges:

- Each party has a rank `r` where `0 ≤ r < t`
- For a threshold `t`, any `t` shares with ranks `(r₁, r₂, ..., rₜ)` can recover the secret **if and only if** `rᵢ ≤ i-1` for all `i ∈ {1, 2, ..., t}` when sorted by rank

### Example
With threshold `t=3` and parties with ranks `[0, 1, 1, 2]`:

**Valid combinations** (can recover secret):
- Parties with ranks `(0, 1, 1)` 
- Parties with ranks `(0, 1, 2)`
- All four parties: `(0, 1, 1, 2)`

**Invalid combinations** (cannot recover secret):
- Parties with ranks `(1, 1, 2)` - violates `r₁ ≤ 0`

## Implementation Structure

The implementation consists of two main components:

### 1. Stateful Protocol Implementation (`hierarchical_threshold_stateful.rs`)

Located in `cggmp21-keygen/src/hierarchical_threshold_stateful.rs`, this provides:

- **`HierarchicalThresholdKeygenProtocol`**: Main protocol struct
- **`HierarchicalThresholdKeygenState`**: Protocol state management
- **Round-by-round execution methods** for fine-grained control

Key differences from regular threshold:
- Uses `nth_derivative_at(x, rank)` instead of `polynomial.value(x)`
- Includes rank information in commitments and proofs
- Preserves ranks in the final key share

### 2. WASM Wrapper (`hierarchical_threshold.rs`)

Located in `cggmp21-wasm/src/keygen/hierarchical_threshold.rs`, this provides:

- **`StatefulHierarchicalThresholdKeygenProtocol`**: WASM-compatible wrapper
- **JavaScript-friendly parameter structures**
- **Convenience methods** for common operations

## API Reference

### Constructor

```rust
StatefulHierarchicalThresholdKeygenProtocol::new(params: JsValue)
```

**Parameters** (as JavaScript object):
```javascript
{
    i: number,                           // Party index (0-based)
    t: number,                          // Threshold
    ranks: number[],                    // Array of ranks for all parties
    n: number,                          // Total number of parties  
    sid: string,                        // Session identifier
    reliable_broadcast_enforced: boolean, // Enable reliability checks
    hd_enabled?: boolean                // HD wallet support (if feature enabled)
}
```

**Validation Rules**:
- `i < n` (party index must be valid)
- `t ≥ 1` and `t ≤ n` (threshold bounds)
- `ranks.length === n` (one rank per party)
- All `ranks[i] < t` (ranks must be less than threshold)

### Core Protocol Methods

#### Round 1: Generate Commitment
```rust
round1_generate_commitment() -> Result<JsValue, JsValue>
```
Generates and returns the commitment message for round 1.

#### Round 2: Decommitment and Share Distribution
```rust
// Get decommitment for broadcast
round2_get_decommitment() -> Result<JsValue, JsValue>

// Get unicast messages (shares) for each party
round2_get_unicast_messages() -> Result<JsValue, JsValue>
```

#### Round 3: Proof Generation
```rust
// Validate round 2 data and prepare for round 3
validate_round2_and_prepare_round3() -> Result<(), JsValue>

// Generate Schnorr proof
round3_generate_proof() -> Result<JsValue, JsValue>
```

#### Finalization
```rust
finalize_key_generation() -> Result<JsValue, JsValue>
```
Validates all proofs and generates the final hierarchical threshold key share.

### Input Management Methods

```rust
// Set received messages from other parties
set_round1_commitments(commitments: JsValue) -> Result<(), JsValue>
set_round2_decommitments(decommitments: JsValue) -> Result<(), JsValue>
set_round2_sigmas(sigmas: JsValue) -> Result<(), JsValue>
set_round3_schnorr_proofs(schnorr_proofs: JsValue) -> Result<(), JsValue>
```

### Convenience Methods

```rust
// Complete round 2 processing in one call
complete_round2(commitments: JsValue, decommitments: JsValue, sigmas: JsValue) -> Result<(), JsValue>

// Complete round 3 and generate final key share
complete_round3_and_generate_key_share(
    commitments: JsValue, 
    decommitments: JsValue, 
    sigmas: JsValue, 
    schnorr_proofs: JsValue
) -> Result<JsValue, JsValue>
```

### Debugging Support

```rust
// Get protocol state information
get_protocol_state_info() -> Result<JsValue, JsValue>
```

Returns a JSON object with current protocol state:
```javascript
{
    party_index: number,
    threshold: number,
    ranks: number[],
    num_parties: number,
    reliable_broadcast_enforced: boolean,
    has_commitment: boolean,
    has_decommitment: boolean,
    has_combined_rid: boolean,
    has_public_shares: boolean,
    has_secret_share: boolean,
    has_schnorr_proof: boolean,
    has_final_key_share: boolean
}
```

## Message Format Structures

### Round 1 Store
```javascript
{
    commitments: MsgRound1[],  // Array of commitments
    ids: number[]              // Corresponding message IDs
}
```

### Round 2 Store (Broadcast)
```javascript
{
    decommitments: MsgRound2Broad[], // Decommitment messages
    ids: number[]                    // Corresponding message IDs
}
```

### Round 2 Store (Unicast)
```javascript
{
    sigmas: MsgRound2Uni[],    // Share messages
    ids: number[]              // Corresponding message IDs
}
```

### Round 3 Store
```javascript
{
    sch_proof: MsgRound3[],    // Schnorr proof messages
    ids: number[]              // Corresponding message IDs
}
```

## Usage Example

```javascript
// Create protocol instance
const params = {
    i: 0,                          // This is party 0
    t: 2,                          // Threshold of 2
    ranks: [0, 1, 1, 0],          // Ranks for parties 0,1,2,3
    n: 4,                          // 4 total parties
    sid: "session_123",            // Session ID
    reliable_broadcast_enforced: true,
    hd_enabled: false
};

const protocol = new StatefulHierarchicalThresholdKeygenProtocol(params);

// Round 1: Generate commitment
const round1_msg = protocol.round1_generate_commitment();
// Broadcast round1_msg to all parties

// Round 2: After receiving round 1 messages from others
const round2_decommit = protocol.round2_get_decommitment();
const round2_unicast = protocol.round2_get_unicast_messages();
// Broadcast decommitment, send unicast messages to respective parties

// After receiving round 2 messages, validate and prepare round 3
protocol.set_round1_commitments(received_commitments);
protocol.set_round2_decommitments(received_decommitments);
protocol.set_round2_sigmas(received_sigmas);
protocol.validate_round2_and_prepare_round3();

// Round 3: Generate proof
const round3_proof = protocol.round3_generate_proof();
// Broadcast proof to all parties

// Finalize: After receiving all round 3 proofs
protocol.set_round3_schnorr_proofs(received_proofs);
const key_share = protocol.finalize_key_generation();

console.log("Generated hierarchical threshold key share:", key_share);
```

## Key Features

1. **Rank-based Access Control**: Parties with different ranks have different privileges
2. **Stateful Execution**: Step-by-step protocol execution suitable for WASM/web environments
3. **Comprehensive Validation**: Validates all protocol parameters and intermediate results
4. **JavaScript Integration**: Full WASM bindings with JavaScript-friendly APIs
5. **Error Handling**: Detailed error messages for debugging
6. **HD Wallet Support**: Optional hierarchical deterministic wallet features

## Integration with Existing CGGMP21 WASM

The hierarchical threshold implementation seamlessly integrates with your existing CGGMP21 WASM infrastructure:

- Uses the same underlying cryptographic primitives
- Compatible with existing signing and auxiliary generation protocols
- Follows the same API patterns as `threshold.rs`
- Can be used alongside regular threshold implementations

## Testing

The implementation includes comprehensive unit tests:

```bash
cd cggmp21-keygen
cargo test hierarchical_threshold
```

## Building for WASM

The implementation compiles successfully for WASM:

```bash
cd cggmp21-wasm
cargo check  # Successful compilation
wasm-pack build --target web
```

## Protocol Security

The hierarchical threshold implementation maintains the same security properties as the original CGGMP21 protocol while adding the hierarchical access control features. The key differences are:

1. **Rank-aware polynomial evaluation**: Uses derivatives instead of direct evaluation
2. **Enhanced commitment scheme**: Includes rank information in commitments
3. **Hierarchical verification**: Validates rank constraints during reconstruction

This provides a secure foundation for applications requiring fine-grained access control over threshold operations. 
