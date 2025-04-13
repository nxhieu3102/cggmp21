# P2P Network Library

A modular peer-to-peer networking library for the CGGMP21 project that supports both native (desktop/server) and WASM (browser) environments.

## Features

- Abstract network layer with implementations for different environments
- Native implementation using TCP sockets
- Browser implementation using WebSockets
- Support for cryptographic key generation and message signing
- Environment-aware configuration system
- Fluent builder API for easy node setup

## Usage

### Basic Setup

```rust
use p2p_network::{create_node_builder, init_logger};
use p2p_network::native::tcp::TcpNetworkImpl;
use p2p_network::key::NativeKeyManager;
use p2p_network::config::FileConfigLoader;
use p2p_network::message::InternalMessage;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    init_logger();
    
    // Create components
    let network = TcpNetworkImpl::<InternalMessage>::new("127.0.0.1:8000");
    let mut key_manager = NativeKeyManager::new();
    key_manager.generate_keypair()?;
    let config = FileConfigLoader::new("config.yaml");
    
    // Build the node
    let mut node = create_node_builder()
        .with_id("node-1".to_string())
        .with_network(network)
        .with_key_manager(key_manager)
        .with_config(config)
        .build()?;
    
    // Start the node
    node.start()?;
    
    Ok(())
}
```

### WASM Usage

When using in a browser environment, compile with wasm-pack:

```bash
wasm-pack build --target web --features wasm --no-default-features
```

Then use in your JavaScript/TypeScript code:

```javascript
import init, { create_node_builder, init_logger } from './pkg/p2p_network.js';

async function setup() {
    await init();
    
    // Initialize logging
    init_logger();
    
    // Create a network node
    // (Implementation details will depend on your JS/WASM bridge)
}
```

## Building

### Native

```bash
cargo build --features native
```

### WebAssembly

```bash
wasm-pack build --target web --features wasm --no-default-features
```

## License

Licensed under either of

 * Apache License, Version 2.0
 * MIT License

at your option. 
