![License](https://img.shields.io/crates/l/paillier-zk.svg)
[![Docs](https://docs.rs/paillier-zk/badge.svg)](https://docs.rs/paillier-zk)
[![Crates io](https://img.shields.io/crates/v/paillier-zk.svg)](https://crates.io/crates/paillier-zk)
[![Discord](https://img.shields.io/discord/905194001349627914?logo=discord&logoColor=ffffff&label=Discord)][in Discord]

[in Discord]: https://discordapp.com/channels/905194001349627914/1285268686147424388

# paillier-zk

This crate provides ZK-proofs for some properties about paillier encryption.
See the module docs for the properties and examples of usage.

This library is built on top of the [fast-paillier](https://lib.rs/fast-paillier) crate, which
is reexported for the consumer to be able to use it instead of trying to match a version.
Big integers are [`num-bigint`](https://docs.rs/num-bigint) `BigInt`s; all modular
exponentiations go through fast-paillier's pure-Rust Montgomery kernel, so the crate builds
for `wasm32-unknown-unknown`.

## Run tests

Big integer arithmetic is slow in debug builds, run tests in release mode:

```bash
cargo test -p paillier-zk --all-features --release
```

Prove/verify timings at cggmp21 `SecurityLevel128` sizes:

```bash
cargo bench -p paillier-zk --features serde --bench proofs
```
