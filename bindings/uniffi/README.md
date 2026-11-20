# polyjose-ffi (UniFFI adapter)

Layer 3 for Kotlin **and** Swift ([ARCHITECTURE.md](../../ARCHITECTURE.md)): the crate `polyjose-ffi`, which exports every surface operation through [UniFFI](https://mozilla.github.io/uniffi-rs/). It builds as a `cdylib` (Android, the JVM, the bindgen) and a `staticlib` (the Swift XCFramework). It is not published as a crate.

- One file per area in `src/`, mirroring `bindings/surface/src`. Each exported function is one type conversion and one surface call; `tests/adapter_rule.rs` checks this.
- `uniffi.toml` sets the generated Kotlin package (`dev.polyjose`) and the Swift module names.
- The Kotlin is generated at build time by `bindings/kotlin`; the Swift is generated and committed as `bindings/swift/Sources/Polyjose/Polyjose.swift`. Both use the pinned generator in `bindings/uniffi-bindgen`.

Tests: `cargo test -p polyjose-ffi`, and `tests/generated-names.sh`, which generates both languages and checks their names against `bindings/api-inventory.txt`. Both run in `scripts/test-all.sh rust`.
