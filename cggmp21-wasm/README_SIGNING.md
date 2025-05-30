# CGGMP21 WASM Signing Implementation

This document describes the complete WASM implementation of the CGGMP21 threshold signature scheme, including key generation, auxiliary generation, and signing.

## Overview

The implementation provides three main protocols:

1. **Key Generation (`StatefulKeygenProtocol`)**: Generates threshold key shares using distributed key generation
2. **Auxiliary Generation (`StatefulAuxGenProtocol`)**: Generates auxiliary cryptographic information (Paillier keys, etc.)
3. **Threshold Signing (`StatefulSigningProtocol`)**: Creates signatures using a subset of the generated keys

## Architecture

### Files Structure

```
cggmp21-wasm/
├── src/
│   ├── lib.rs                          # Main library exports
│   ├── keygen/
│   │   ├── mod.rs                      # Keygen module exports
│   │   └── threshold.rs                # Stateful keygen protocol
│   ├── key_refresh/
│   │   ├── mod.rs                      # Key refresh module exports
│   │   └── aux_only.rs                 # Stateful aux generation protocol
│   └── signing/
│       ├── mod.rs                      # Signing module exports
│       └── stateful.rs                 # Stateful signing protocol
└── tests/
    ├── test_stateful_signing.js        # JavaScript full pipeline test
    └── test_stateful_signing.html      # HTML test interface
```

### Protocol Flow

The complete CGGMP21 pipeline follows this sequence:

```
1. Key Generation (all n parties)
   ├── Round 1: Generate commitments
   ├── Round 2: Broadcast decommitments, send sigma shares
   ├── Round 3: Generate Schnorr proofs
   └── Output: Incomplete key shares

2. Auxiliary Generation (all n parties)
   ├── Round 1: Generate Paillier commitments
   ├── Round 2: Decommit and validate parameters
   ├── Round 3: Exchange proofs
   └── Output: Complete key shares (core + auxiliary info)

3. Threshold Signing (t-of-n parties)
   ├── Round 1a: Broadcast initial commitments
   ├── Round 1b: P2P zero-knowledge proofs
   ├── Round 2: P2P MtA (Multiplicative-to-Additive) exchanges
   ├── Round 3: P2P final proofs and commitments
   ├── Generate presignatures
   ├── Round 4: Generate partial signatures (if message provided)
   └── Output: Complete ECDSA signature
```

## Building

### Prerequisites

- Rust (latest stable)
- wasm-pack
- Node.js (for testing)

### Build Commands

```bash
# Build the WASM package
cd cggmp21-wasm
wasm-pack build --target web --out-dir pkg

# Or build for specific targets
wasm-pack build --target bundler  # For webpack/bundlers
wasm-pack build --target nodejs   # For Node.js
```

## API Reference

### StatefulSigningProtocol

The main signing protocol class with the following key methods:

```typescript
// Constructor
new StatefulSigningProtocol(params: SigningProtocolParams, keyShare: KeyShare)

// Protocol rounds
round1a_generate_message(): MsgRound1a
set_round1a_messages(messages: Round1aStore): void
round1b_generate_messages(): P2PMessage<MsgRound1b>[]
set_round1b_messages(messages: Round1bStore): void
validate_round1b_proofs(): void
round2_generate_messages(): P2PMessage<MsgRound2>[]
set_round2_messages(messages: Round2Store): void
round3_generate_messages(): P2PMessage<MsgRound3>[]
set_round3_messages(messages: Round3Store): void

// Output generation
generate_presignature(): Presignature
round4_generate_message(): MsgRound4 | null
set_round4_messages(messages: Round4Store): void
generate_signature(myPartialSig: MsgRound4): Signature
```

### Parameters

```typescript
interface SigningProtocolParams {
    i: number;                          // Party index in signing group
    signing_parties: number[];          // Indices of parties participating in signing
    sid: string;                        // Session identifier
    reliable_broadcast_enforced: boolean; // Whether to enforce reliable broadcast
    message_hex?: string;               // Hex-encoded message to sign (optional, for presignature-only)
}
```

## Testing

### Running the Full Pipeline Test

1. **HTML Interface** (recommended for development):
   ```bash
   # Serve the HTML file from a local server
   python -m http.server 8000
   # Open http://localhost:8000/tests/test_stateful_signing.html
   ```

2. **JavaScript Test**:
   ```bash
   cd cggmp21-wasm/tests
   node test_stateful_signing.js
   ```

### Test Configuration

The test runs a **2-of-3 threshold** setup:
- 3 parties generate keys
- 2 parties participate in signing
- Message: "Hello, World!" (hex: `48656c6c6f2c20576f726c6421`)
- Security: 128-bit, secp256k1 curve, SHA-256

### Expected Output

A successful test should show:
```
✅ Key generation completed! Generated 3 incomplete key shares
✅ Auxiliary generation completed! Generated 3 complete key shares  
✅ Signing completed! Generated 2 signatures
🎉 Full Pipeline Test Completed Successfully!
```

## Usage Examples

### Basic Signing Workflow

```javascript
import init, { 
    StatefulKeygenProtocol, 
    StatefulAuxGenProtocol,
    StatefulSigningProtocol 
} from './pkg/cggmp21_wasm.js';

// Initialize WASM
await init();

// 1. Run key generation for all parties
const keygenProtocols = parties.map(party => new StatefulKeygenProtocol(party));
// ... execute keygen rounds ...
const incompleteKeyShares = /* result from keygen */;

// 2. Run auxiliary generation for all parties  
const auxGenProtocols = await Promise.all(
    parties.map(party => StatefulAuxGenProtocol.new(party))
);
// ... execute auxgen rounds ...
const completeKeyShares = /* result from auxgen */;

// 3. Run threshold signing with subset of parties
const signingParties = [0, 1]; // Use first 2 parties for 2-of-3 threshold
const signingProtocols = signingParties.map((globalIdx, localIdx) => 
    new StatefulSigningProtocol({
        i: localIdx,
        signing_parties: [0, 1],
        sid: "signing-session",
        reliable_broadcast_enforced: false,
        message_hex: "48656c6c6f2c20576f726c6421" // "Hello, World!"
    }, completeKeyShares[globalIdx])
);
// ... execute signing rounds ...
const signatures = /* final signatures */;
```

### Presignature Generation

To generate presignatures (without specifying a message):

```javascript
const signingProtocol = new StatefulSigningProtocol({
    i: 0,
    signing_parties: [0, 1],
    sid: "presig-session", 
    reliable_broadcast_enforced: false,
    message_hex: null  // No message = presignature mode
}, keyShare);

// ... execute rounds 1-3 ...
const presignature = signingProtocol.generate_presignature();
```

## Security Considerations

- **Session IDs**: Use unique session identifiers for each protocol run
- **Reliable Broadcast**: Enable in production environments (`reliable_broadcast_enforced: true`)
- **Key Share Storage**: Securely store and handle key shares
- **Message Handling**: Ensure proper hex encoding of messages to sign
- **Network Security**: Use secure channels for message transmission

## Troubleshooting

### Common Issues

1. **WASM Module Not Found**: Ensure `wasm-pack build` completed successfully
2. **Invalid Key Shares**: Verify key generation and auxiliary generation completed
3. **Message Routing**: Check that P2P messages are correctly routed between parties
4. **Threshold Errors**: Ensure at least `t` parties participate in signing

### Debug Mode

Enable detailed logging by checking browser console or adding debug statements:

```javascript
// Enable detailed console logging
console.log("Round 1a messages:", round1aMessages);
console.log("Presignatures:", presignatures);
```

## Performance Notes

- **Key Generation**: Most computationally intensive phase
- **Auxiliary Generation**: Requires Paillier key generation (can be slow)
- **Signing**: Relatively fast once keys are generated
- **Memory Usage**: Complete key shares contain large cryptographic objects

## Future Enhancements

- [ ] HD Wallet support (`hd-wallet` feature)
- [ ] Batch signing optimization
- [ ] WebWorker support for heavy computations
- [ ] Persistent state management
- [ ] Network abstraction layer 
