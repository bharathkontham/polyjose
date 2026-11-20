# polyjose-surface

Layer 2 of the bindings ([ARCHITECTURE.md](../../ARCHITECTURE.md)): every operation, record and result that a binding exposes, defined once in plain Rust over the core. It is not published.

- **Why it is separate:** the adapters (`bindings/node`, `bindings/wasm`, `bindings/uniffi`) then contain only type conversions, so all four platforms run the same code path, with the same JSON parsing and the same error codes.
- **What it holds:** one file per area in `src/` (`jws.rs`, `jwe.rs`, `jwk.rs`, `jwt.rs`, `keys.rs`, `util.rs`, `platform_key.rs`), the records in `records.rs`, zeroizing owners for secrets in `secret.rs`, and the one error type in `error.rs`, built only from a core error.
- **What it must not hold:** an FFI framework, serde, or a default of its own (an absent option means the core's default).
- **Dependencies:** `polyjose` and `zeroize` only (`bindings/deps-allowlist/surface.txt`).

Tests: `cargo test -p polyjose-surface` (also part of `scripts/test-all.sh rust`). `tests/conformance.rs` is the `rust-surface` conformance runner.
