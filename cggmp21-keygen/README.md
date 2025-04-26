# CGGMP21 Keygen WASM Documentation

This document provides instructions for setting up and using the WASM-adapted CGGMP21 key generation protocol in web applications.

## Overview

The CGGMP21 keygen protocol is a UC-secure Distributed Key Generation (DKG) implementation that can be compiled to WebAssembly for use in browser environments. This documentation covers:

- Building the WASM module
- Integrating it into web applications
- Using the JavaScript API
- Setting up WebWorkers and WebSocket networking
- Browser compatibility requirements

## Prerequisites

- Rust toolchain (latest stable version)
- wasm-pack (install via `cargo install wasm-pack`)
- Modern web browser (Chrome 85+, Firefox 79+, or equivalent)
- Node.js and npm/yarn for JavaScript development

## Building the WASM Module

1. Install dependencies:
```bash
cargo install wasm-pack
```

2. Build the WASM module:
```bash
cd cggmp21-keygen
wasm-pack build --target web
```

This will generate a `pkg` directory containing the compiled WASM module and JavaScript bindings.

## Integration Guide

### Basic Setup

1. Add the WASM module to your project:
```bash
npm install ./cggmp21-keygen/pkg
```

2. Import and initialize the module:
```javascript
import { init, KeygenProtocol } from 'cggmp21-keygen';

// Initialize the WASM module
await init();

// Create a new keygen protocol instance
const protocol = new KeygenProtocol();
```

### WebWorker Setup

To prevent blocking the main thread during cryptographic operations, run the protocol in a WebWorker:

```javascript
// worker.js
import { init, KeygenProtocol } from 'cggmp21-keygen';

self.onmessage = async (e) => {
  await init();
  const protocol = new KeygenProtocol();
  
  // Handle protocol messages
  self.postMessage({ type: 'ready' });
};

// main.js
const worker = new Worker('worker.js');
worker.onmessage = (e) => {
  if (e.data.type === 'ready') {
    // Protocol is ready to use
  }
};
```

### WebSocket Networking

The protocol requires message exchange between parties. Implement WebSocket communication:

```javascript
// websocket.js
class WebSocketTransport {
  constructor(url) {
    this.ws = new WebSocket(url);
    this.messageHandlers = new Set();
    
    this.ws.onmessage = (e) => {
      const message = JSON.parse(e.data);
      this.messageHandlers.forEach(handler => handler(message));
    };
  }

  send(message) {
    this.ws.send(JSON.stringify(message));
  }

  onMessage(handler) {
    this.messageHandlers.add(handler);
    return () => this.messageHandlers.delete(handler);
  }
}
```

### Protocol Execution

Execute the keygen protocol rounds:

```javascript
// Example keygen execution
async function runKeygen(partyIndex, totalParties) {
  const protocol = new KeygenProtocol();
  const transport = new WebSocketTransport('ws://your-server');
  
  // Initialize protocol
  await protocol.init(partyIndex, totalParties);
  
  // Handle incoming messages
  transport.onMessage(async (message) => {
    const result = await protocol.handleMessage(message);
    if (result.outgoing) {
      transport.send(result.outgoing);
    }
    if (result.complete) {
      console.log('Keygen completed:', result.keyShare);
    }
  });
  
  // Start protocol
  const result = await protocol.start();
  if (result.outgoing) {
    transport.send(result.outgoing);
  }
}
```

## Browser Compatibility

The WASM module requires modern browser features:

- WebAssembly support
- WebWorker support
- WebSocket support
- BigInt support

Minimum browser versions:
- Chrome 85+
- Firefox 79+
- Safari 14+
- Edge 85+

## Error Handling

The protocol may throw various errors during execution:

```javascript
try {
  await protocol.start();
} catch (error) {
  if (error.name === 'KeygenError') {
    console.error('Protocol error:', error.message);
  } else if (error.name === 'IoError') {
    console.error('I/O error:', error.message);
  } else {
    console.error('Unexpected error:', error);
  }
}
```

## Security Considerations

1. Always run the protocol in a WebWorker to prevent UI blocking
2. Use secure WebSocket connections (wss://) in production
3. Validate all incoming messages before processing
4. Implement proper error handling and logging
5. Consider rate limiting and DoS protection

## Example Application

A complete example application demonstrating the keygen protocol can be found in the `examples` directory. It includes:

- WebWorker setup
- WebSocket server implementation
- Protocol execution
- Error handling
- Progress tracking

## Troubleshooting

Common issues and solutions:

1. **Module initialization fails**
   - Ensure wasm-pack build completed successfully
   - Check browser console for specific errors
   - Verify all dependencies are properly imported

2. **WebSocket connection issues**
   - Check server is running and accessible
   - Verify WebSocket URL is correct
   - Ensure proper CORS configuration

3. **Protocol execution errors**
   - Verify party indices and total parties are correct
   - Check message format and content
   - Ensure proper error handling is implemented

## Support

For additional support:
- Check the project's GitHub issues
- Review the CGGMP21 paper for protocol details
- Contact the development team through GitHub 
