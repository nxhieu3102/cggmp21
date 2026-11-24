![License](https://img.shields.io/crates/l/fast-paillier.svg)

# Optimized Paillier encryption scheme

Library implements the Paillier encryption scheme variant used by CGGMP21 (nonces from a
subgroup of order `2·alpha`), with optimizations such as:

* Pure-Rust big integers ([`num-bigint`](https://docs.rs/num-bigint)) and an in-house
  Montgomery exponentiation kernel ([`mont`]), so the crate builds for every target including
  `wasm32-unknown-unknown`
* Faster decryption, encryption and homomorphic multiplication via the Chinese Remainder
  Theorem when the private key is known
* Faster key generation: `p` and `q` are searched independently, with trial division before
  Miller–Rabin
* Optional fixed-base precomputation table for encryption under a known key

All randomness comes from the caller's RNG.

```rust
use fast_paillier::{AnyEncryptionKey, DecryptionKey};
use num_bigint::BigInt;

# let mut rng = rand_dev::DevRng::new();
// Real keys use n_size = 3072, a_size = 512; a small key keeps the example fast
let dk = DecryptionKey::generate(&mut rng, 512, 64)?;
let ek = dk.encryption_key();

let x = BigInt::from(-42);
let (c, _nonce) = ek.encrypt_with_random(&mut rng, &x)?;
let c2 = ek.oadd(&c, &c)?;
assert_eq!(dk.decrypt(&c2)?, BigInt::from(-84));
# Ok::<(), fast_paillier::Error>(())
```

## Features
* `serde`: serialization of keys, `CrtExp`, `PrecomputeTable` and the
  `utils::serde_wrapper` adapters for `BigInt` (rug-compatible `{"radix", "value"}` format)
