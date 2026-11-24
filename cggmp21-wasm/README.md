# cggmp21-wasm

Message-driven party sessions for CGGMP21 threshold ECDSA, compiled to WebAssembly.

Every protocol (threshold and hierarchical-threshold keygen, aux info, signing, presigning) runs the
original `cggmp21` implementation through `round_based::state_machine`; this crate only moves
serialized messages in and out. Fixed parameters: secp256k1, `SecurityLevel128`, SHA-256.

## JavaScript API

| Export | Purpose |
|---|---|
| `KeygenSession`, `AuxInfoSession`, `SigningSession`, `PresigningSession` | `new(config)`, `start()` → outgoing envelopes, `handleIncoming(envelope)` → outgoing envelopes + status/output, `finished` |
| `generatePaillierKey` | Paillier key for aux info, with progress callback |
| `completeKeyShare`, `keyShareInfo` | combine keygen output with aux info; inspect public data |
| `issuePartialSignature`, `combinePartialSignatures` | non-interactive signing from a presignature |
| `verifySignature` | ECDSA verification |

Envelopes carry `sender`, `recipient` (`null` = broadcast), `round` and a CBOR payload. Transport is
the caller's job, and the envelope's `sender` is trusted: real deployments need authenticated,
encrypted channels and a reliable broadcast.

Key shares, aux info, Paillier keys and presignatures are returned as opaque blobs that contain
secrets: store them encrypted, never log them, never send them to other parties.

## Build and test

```bash
cargo install wasm-pack
./build.sh                              # → ../demo/pkg (simd128, wasm-opt -O3)
cargo test -p cggmp21-wasm --release    # native end-to-end session tests
node tests/node-smoke.mjs               # end-to-end smoke test of the built package
python3 -m http.server -d ../demo 8080  # browser demo
```

The build targets browsers with WebAssembly SIMD: Chrome 91+, Firefox 89+, Safari 16.4+.
