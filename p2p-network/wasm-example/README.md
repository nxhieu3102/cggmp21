# P2P Network WASM Example

This is a simple example showing how to use the p2p-network library in a WASM environment.

## Building

Make sure you have `wasm-pack` installed:

```bash
cargo install wasm-pack
```

Then build the WASM package:

```bash
wasm-pack build --target web
```

## Running

You can serve the example using any HTTP server. For example, with Python:

```bash
python3 -m http.server
```

Or with Node.js and the `http-server` package:

```bash
npm install -g http-server
http-server
```

Then open your browser at http://localhost:8000 (or the appropriate port).

## What It Does

This example demonstrates:

1. Loading the WASM module in a browser
2. Creating messages using the library
3. Serializing and deserializing messages
4. Basic interop between JavaScript and Rust via WASM

## Project Structure

- `index.html` - The web page that loads and uses the WASM module
- `src/lib.rs` - The Rust code that exposes functionality to JavaScript
- `Cargo.toml` - The package configuration 
