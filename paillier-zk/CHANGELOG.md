## Unreleased
* Replace rug/GMP with num-bigint; all modular exponentiation goes through
  `fast_paillier::mont` (multi-exponentiation for ring-Pedersen commitments, CRT when the
  factorization is known). Builds for `wasm32-unknown-unknown`.
* security fix: batch proofs (`batch_paillier_affine_operation_in_range`,
  `batch_paillier_encryption_in_range_with_el_gamal`) bind statement and commitment in the
  Fiat-Shamir challenge, use an independent challenge and fresh masks per element, range-check
  every `z1_i`, check all vector lengths and never panic on malformed proofs. Breaking: the
  `batch_size` argument is removed, batch size is `data.batch.len()`.
* security fix: nonce masks are sized from the actual nonce size (`nonce_bits + t + ε`).
* Fiat-Shamir transcripts encode integers sign-aware and canonically (`encoding::BigInt`, now
  public); encryption keys are digested as `(N, h)`.
* Πmod prover uses CRT and a single fourth-root exponent (~5x faster).
* `MultiexpTable::build` is linear in the table size; `size_in_bytes` fixed.
* Removed unused single-statement aff-g / group-element proofs.

## v0.4.2
* Update links in the crate settings, update readme [#53]

[#53]: https://github.com/LFDT-Lockness/paillier-zk/pull/53

## v0.4.1
* Prettify code by using `#[udigest(as = ...)]` attribute [#51]

[#51]: https://github.com/LFDT-Lockness/paillier-zk/pull/51

## v0.4.0
* security fix: derive challenges for zero-knowledge proof unambiguously

## v0.3.0
* Update `generic-ec` dep to v0.3 [#48]

[#48]: https://github.com/LFDT-Lockness/paillier-zk/pull/48

## v0.2.0

All changes prior to this version were not documented
