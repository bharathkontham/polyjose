<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://polyjose.dev/brand/lockup-dark.svg">
    <img alt="polyjose" src="https://polyjose.dev/brand/lockup-light.svg" width="360">
  </picture>
</p>

# polyjose

**One JOSE implementation, every platform.** polyjose is a pure-Rust implementation of JSON Object Signing and Encryption (JWA, JWK, JWS, JWE, JWT). It builds from a single core into:

| Platform | Package | Built with |
|---|---|---|
| [Rust](https://polyjose.dev/start/rust/) | [`polyjose`](https://crates.io/crates/polyjose) on crates.io | — |
| [Node.js](https://polyjose.dev/start/node/) | [`@polyjose/node`](https://www.npmjs.com/package/@polyjose/node) on npm | napi-rs |
| [Web (WASM)](https://polyjose.dev/start/web/) | [`@polyjose/wasm`](https://www.npmjs.com/package/@polyjose/wasm) on npm | wasm-bindgen |
| [Android, Kotlin, Java](https://polyjose.dev/start/android/) | [`dev.polyjose:polyjose`](https://central.sonatype.com/artifact/dev.polyjose/polyjose) and [`dev.polyjose:polyjose-jvm`](https://central.sonatype.com/artifact/dev.polyjose/polyjose-jvm) on Maven Central | UniFFI + cargo-ndk |
| [Swift](https://polyjose.dev/start/swift/) (iOS; also iPadOS, macOS, watchOS) | Swift Package `Polyjose`, XCFramework on [GitHub releases](https://github.com/bharathkontham/polyjose/releases/latest) | UniFFI + XCFramework |

Each platform name links to its get-started page on [polyjose.dev](https://polyjose.dev), with install and usage.

## Principles
- **Pure Rust crypto.** No OpenSSL, `ring` or `aws-lc`; `cargo deny` enforces it ([deny.toml](https://github.com/bharathkontham/polyjose/blob/main/deny.toml)).
- **RFC-compliant.** Covers RFCs 7515–7520, 7638, 7797, 8037, 8725, 8812 and 9864, tested against the RFCs' own test vectors.
- **Misuse-resistant.** Verify and decrypt require an explicit algorithm allow-list, `none` is never accepted, and secrets are zeroized.
- **One behaviour everywhere.** Every binding runs the same conformance vectors ([conformance/](https://github.com/bharathkontham/polyjose/tree/main/conformance)).

## Built on
polyjose writes no cryptographic primitives of its own. It composes pure-Rust primitives into JOSE, with no OpenSSL, `ring` or `aws-lc`:
- **[RustCrypto](https://github.com/RustCrypto):** `sha2`, `hmac`, `aes`, `aes-gcm`, `aes-kw`, `cbc`, `pbkdf2`, `p256`, `p384`, `p521`, `k256`, `rsa` and `zeroize`
- **[dalek-cryptography](https://github.com/dalek-cryptography):** `ed25519-dalek`, `x25519-dalek` and `subtle`
- **[rust-random](https://github.com/rust-random):** `getrandom`, the operating system's random number generator

[CREDITS.md](https://github.com/bharathkontham/polyjose/blob/main/CREDITS.md) credits every crate in the dependency tree, with its version and license. [AUDITS.md](https://github.com/bharathkontham/polyjose/blob/main/AUDITS.md) records which primitives have a published third-party audit. polyjose itself has not been independently audited.

## Layout
```
crates/polyjose/         core library (no unsafe)
bindings/surface/        the binding-facing API over the core, shared by every binding crate
bindings/node/           napi-rs addon (@polyjose/node)
bindings/wasm/           wasm-bindgen package (@polyjose/wasm)
bindings/js/             TypeScript facade shared by the Node and WASM packages (not published on its own)
bindings/ffi/            UniFFI cdylib/staticlib → Kotlin + Swift
bindings/uniffi-bindgen/ the pinned UniFFI generator for the Kotlin and Swift sources
platforms/android/       Gradle library (AAR, JVM jar) + tests
platforms/swift/         Swift Package + XCTest (iOS first)
conformance/             shared test vectors, consumed by every platform's test suite
interop/                 two-way interop tests against other JOSE libraries (panva/jose)
fuzz/                    cargo-fuzz targets (scripts/fuzz.sh); its own workspace
scripts/                 test-all.sh, the dependency and release guards, build helpers
dist/                    build output (packed release artifacts), git-ignored
```

The Rust code of the Kotlin and Swift bindings is `bindings/ffi`; their packages, generated sources and tests are in `platforms/android` and `platforms/swift`.

## Test everything
```sh
scripts/test-all.sh            # rust + wasm + node + android + apple (skips platforms whose toolchain is missing, and says so)
scripts/test-all.sh rust node  # only some platforms
scripts/test-all.sh tooling    # the self-tests of the guard scripts; slow, only needed when scripts/ or .github/ change
```

## License
Licensed under the [MIT license](https://github.com/bharathkontham/polyjose/blob/main/LICENSE). Contributions are accepted under the same license.
