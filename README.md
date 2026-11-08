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
| Rust | [`polyjose`](https://crates.io/crates/polyjose) on crates.io | — |
| Node.js | `@polyjose/node` on npm | napi-rs |
| Web (WASM) | `@polyjose/wasm` on npm | wasm-bindgen |
| Android, Kotlin, Java | `dev.polyjose:polyjose` on Maven Central | UniFFI + cargo-ndk |
| Swift (iOS; also iPadOS, macOS, watchOS) | Swift Package `Polyjose` | UniFFI + XCFramework |

## Principles
- **Pure Rust crypto.** No OpenSSL, `ring` or `aws-lc`; `cargo deny` enforces it ([deny.toml](deny.toml)).
- **RFC-compliant.** Covers RFCs 7515–7520, 7638, 7797, 8037, 8725, 8812 and 9864, tested against the RFCs' own test vectors.
- **Misuse-resistant.** Verify and decrypt require an explicit algorithm allow-list, `none` is never accepted, and secrets are zeroized.
- **One behaviour everywhere.** Every binding runs the same conformance vectors ([conformance/](conformance/)).

## Built on
polyjose writes no cryptographic primitives of its own. It composes pure-Rust primitives into JOSE, with no OpenSSL, `ring` or `aws-lc`:
- **[RustCrypto](https://github.com/RustCrypto):** `sha2`, `hmac`, `aes`, `aes-gcm`, `aes-kw`, `cbc`, `pbkdf2`, `p256`, `p384`, `p521`, `k256`, `rsa` (public-key operations only) and `zeroize`
- **[dalek-cryptography](https://github.com/dalek-cryptography):** `ed25519-dalek`, `x25519-dalek` and `subtle`
- **[rust-random](https://github.com/rust-random):** `getrandom`, the operating system's random number generator

[CREDITS.md](CREDITS.md) credits every crate in the dependency tree, with its version and license. [AUDITS.md](AUDITS.md) records which primitives have a published third-party audit. polyjose itself has not been independently audited.

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
