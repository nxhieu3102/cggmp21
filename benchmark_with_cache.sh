#!/bin/bash

# Script to generate cached precompute tables and run signing benchmarks
set -e

echo "🔧 Building the project..."
cargo build --release --bin precompute_tables --bin measure_perf

echo "📊 Generating cached precompute tables..."
cargo run --release --bin precompute_tables

echo "✅ Cached precompute tables generated!"
echo "📁 Cache file: test-data/precomputed_precompute_tables.json"

echo "🚀 Running signing benchmarks with cached tables..."
cargo run --release --bin measure_perf -- --no-bench-non-threshold-keygen --no-bench-threshold-keygen --no-bench-hierarchical-threshold-keygen --no-bench-aux-data-gen --no-bench-threshold-signing --no-bench-htss-signing

echo "🎉 Benchmarking complete!" 
