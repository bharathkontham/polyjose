# polyjose

**One JOSE implementation, every platform.** polyjose is a pure-Rust implementation of JSON Object Signing and Encryption (JWA, JWK, JWS, JWE, JWT). It builds from a single core into:

| Platform | Package | Built with |
|---|---|---|
| Rust | [`polyjose`](https://crates.io/crates/polyjose) on crates.io | — |
| Node.js | `@polyjose/node` on npm | napi-rs |
| Web / edge (WASM) | `@polyjose/wasm` on npm | wasm-bindgen |
| Android, Kotlin, Java | `dev.polyjose:polyjose` on Maven Central | UniFFI + cargo-ndk |
| iOS, iPadOS, macOS, tvOS, watchOS, visionOS | Swift Package `Polyjose` | UniFFI + XCFramework |

> Status: **pre-alpha**. Nothing is published yet. Don't use it in production.

## Principles
- **Pure Rust crypto.** No OpenSSL, `ring` or `aws-lc`; `cargo deny` enforces it ([deny.toml](deny.toml)).
- **RFC-compliant.** Covers RFCs 7515–7520, 7638, 7797, 8037, 8725, 8812 and 9864, tested against the RFCs' own test vectors.
- **Misuse-resistant.** Verify and decrypt require an explicit algorithm allow-list, `none` is never accepted, and secrets are zeroized.
- **One behaviour everywhere.** Every binding runs the same conformance vectors ([conformance/](conformance/)).

## Layout
```
crates/polyjose/   core library (no unsafe)
bindings/node/     napi-rs addon
bindings/wasm/     wasm-bindgen package
bindings/ffi/      UniFFI cdylib/staticlib → Kotlin + Swift
platforms/android/ Gradle library (AAR) + tests
platforms/apple/   Swift Package + XCTest
conformance/       shared test vectors, consumed by every platform's test suite
scripts/           test-all.sh and build helpers
```

## Test everything
```sh
scripts/test-all.sh            # rust + wasm + node + android + apple (skips platforms whose toolchain is missing, and says so)
scripts/test-all.sh rust node  # only some platforms
```

## License
Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT), at your option.

Unless you explicitly state otherwise, any contribution you intentionally submit for inclusion in polyjose, as defined in the Apache-2.0 license, is dual-licensed as above, without any additional terms or conditions.
