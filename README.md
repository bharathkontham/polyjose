# polyjose

**One JOSE implementation, every platform.** polyjose is a pure-Rust implementation of JSON Object Signing and Encryption (JWA, JWK, JWS, JWE, JWT). It builds from a single core into:

| Platform | Package | Built with |
|---|---|---|
| Rust | [`polyjose`](https://crates.io/crates/polyjose) on crates.io | — |
| Node.js | `@polyjose/node` on npm | napi-rs |
| Web / edge (WASM) | `@polyjose/wasm` on npm | wasm-bindgen |
| Android, Kotlin, Java | `dev.polyjose:polyjose` on Maven Central | UniFFI + cargo-ndk |
| Swift (iOS; also iPadOS, macOS, tvOS, watchOS, visionOS) | Swift Package `Polyjose` | UniFFI + XCFramework |

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
platforms/swift/   Swift Package + XCTest (iOS first)
conformance/       shared test vectors, consumed by every platform's test suite
scripts/           test-all.sh and build helpers
```

## Test everything
```sh
scripts/test-all.sh            # rust + wasm + node + android + apple (skips platforms whose toolchain is missing, and says so)
scripts/test-all.sh rust node  # only some platforms
```

## License
Licensed under the [MIT license](LICENSE). Contributions are accepted under the same license.
