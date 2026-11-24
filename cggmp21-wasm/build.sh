#!/usr/bin/env bash
# Builds the WebAssembly package used by the browser demo into ../demo/pkg.
#
# Requirements (install once, no curl | sh):
#   rustup target add wasm32-unknown-unknown
#   cargo install wasm-pack            # or: brew install wasm-pack
# wasm-pack runs wasm-opt (-O3, see Cargo.toml metadata); it downloads binaryen if needed.
#
# Then serve the demo: python3 -m http.server -d ../demo 8080
set -euo pipefail
cd "$(dirname "$0")"

# Optimization settings come from the workspace `[profile.release]` and `.cargo/config.toml`
# (simd128 for wasm32). Panics abort: wasm32-unknown-unknown cannot unwind anyway.
export CARGO_PROFILE_RELEASE_PANIC=abort

# demo/pkg is a build artifact: wasm-pack writes a catch-all .gitignore into it.
wasm-pack build --release --target web --out-dir ../demo/pkg --out-name cggmp21_wasm "$@"
ls -l ../demo/pkg/*.wasm
