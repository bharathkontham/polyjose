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
- **Pure Rust crypto.** No OpenSSL, `ring` or `aws-lc`; `cargo deny` enforces it ([deny.toml](https://github.com/bharathkontham/polyjose/blob/main/deny.toml)). With a platform-held key (`PlatformKey` on Kotlin and Swift, such as a Secure Enclave or Android Keystore key), the operating system's key service performs the one private-key operation, and polyjose checks its result and does every other step in pure Rust.
- **RFC-compliant.** Covers RFCs 7515–7520, 7638, 7797, 8037, 8725, 8812 and 9864, tested against the RFCs' own test vectors.
- **Misuse-resistant.** Verify and decrypt require an explicit algorithm allow-list, `none` is never accepted, and secrets are zeroized. Reading a token without verifying it is possible only through the `_unverified` decode utilities, which return their own result types, never a verified one.
- **One behaviour everywhere.** Every binding runs the same conformance vectors ([conformance/](https://github.com/bharathkontham/polyjose/tree/main/conformance)).

## Built on
polyjose writes no cryptographic primitives of its own. It composes pure-Rust primitives into JOSE, with no OpenSSL, `ring` or `aws-lc`:
- **[RustCrypto](https://github.com/RustCrypto):** `sha2`, `hmac`, `aes`, `aes-gcm`, `aes-kw`, `cbc`, `pbkdf2`, `p256`, `p384`, `p521`, `k256`, `rsa` and `zeroize`
- **[dalek-cryptography](https://github.com/dalek-cryptography):** `ed25519-dalek`, `x25519-dalek` and `subtle`
- **[rust-random](https://github.com/rust-random):** `getrandom`, the operating system's random number generator

[CREDITS.md](https://github.com/bharathkontham/polyjose/blob/main/CREDITS.md) credits every crate in the dependency tree, with its version and license. [AUDITS.md](https://github.com/bharathkontham/polyjose/blob/main/AUDITS.md) records which primitives have a published third-party audit. polyjose itself has not been independently audited.

## Layout
```
crates/polyjose/         the core library (no unsafe); the only crate on crates.io
bindings/                everything that exposes the core to another language:
  surface/               every operation once, in plain Rust, for the adapters
  node/  wasm/           napi-rs and wasm-bindgen adapters, each with its npm package
  ts-common/             TypeScript shared by @polyjose/node and @polyjose/wasm (not published)
  uniffi/  uniffi-bindgen/  UniFFI adapter for Kotlin and Swift, and its pinned generator
  kotlin/                Gradle build: Android AAR (android/), JVM jar (jvm/), shared sources
  swift/                 Swift package sources, tests and XCFramework scripts (Package.swift is at the root)
conformance/             shared test vectors and schemas, run by every platform
interop/                 two-way interop tests against panva/jose
fuzz/                    cargo-fuzz targets; its own workspace
scripts/                 test-all.sh, the guards, release scripts
dist/                    build output (packed release artifacts), git-ignored
```

[ARCHITECTURE.md](https://github.com/bharathkontham/polyjose/blob/main/ARCHITECTURE.md) explains the layers, where each binding lives, and how each kind of test is run.

## Test everything
```sh
scripts/test-all.sh            # rust + wasm + node + android + swift (skips platforms whose toolchain is missing, and says so)
scripts/test-all.sh rust node  # only some platforms
scripts/test-all.sh tooling    # the self-tests of the guard scripts; slow, only needed when scripts/ or .github/ change
```

## License
Licensed under the [MIT license](https://github.com/bharathkontham/polyjose/blob/main/LICENSE). Contributions are accepted under the same license.
