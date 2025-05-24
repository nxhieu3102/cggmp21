#!/bin/bash
set -e

# Make the script executable
chmod +x "$0"

echo "=== CGGMP21 WASM Build Tool ==="

# Check if wasm-pack is installed
if ! command -v wasm-pack &> /dev/null; then
    echo "wasm-pack not found. Installing..."
    curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
else
    echo "wasm-pack is already installed"
fi

# Build the WASM package
echo "Building WASM package..."
wasm-pack build --target web
