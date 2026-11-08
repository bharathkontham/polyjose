# Changelog

All notable changes to polyjose are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and polyjose follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-09

The first release: a pure-Rust implementation of JOSE (JWS, JWE, JWK, JWT and JWA) for Rust, Node.js, the web (WebAssembly), Android and the JVM (Kotlin/Java), and Swift. All cryptography comes from RustCrypto and dalek crates, with no OpenSSL, `ring` or `aws-lc`. Every binding is built from the same Rust core and runs the same conformance vectors.

### Added

#### Algorithms (RFC 7518, RFC 8037, RFC 8812, RFC 9864)

- **JWS signing and verification:** `HS256`, `HS384`, `HS512`; `ES256` (P-256), `ES384` (P-384), `ES512` (P-521), `ES256K` (secp256k1); `Ed25519`, and `EdDSA` with Ed25519 keys.
- **JWS verification only:** `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512` with RSA public keys of 2048 to 8192 bits.
- **JWE key management:** `dir`; `A128KW`, `A192KW`, `A256KW`; `A128GCMKW`, `A192GCMKW`, `A256GCMKW`; `ECDH-ES`, `ECDH-ES+A128KW`, `ECDH-ES+A192KW`, `ECDH-ES+A256KW` on P-256, P-384, P-521 and X25519; `PBES2-HS256+A128KW`, `PBES2-HS384+A192KW`, `PBES2-HS512+A256KW`; `RSA-OAEP-256` for encryption only.
- **JWE content encryption:** `A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512`, `A128GCM`, `A192GCM`, `A256GCM`.

#### JOSE features

- **JWS (RFC 7515):** compact, flattened JSON and general JSON serializations, including several signatures; detached payloads; unencoded payloads (`b64: false`, RFC 7797).
- **JWE (RFC 7516):** compact, flattened JSON and general JSON serializations, including several recipients; additional authenticated data; protected, shared unprotected and per-recipient headers.
- **JWT (RFC 7519):** signed tokens and nested (signed, then encrypted) tokens. Validation covers `exp`, `nbf`, `iat` with leeway and maximum age, issuer, audience, subject, required claims and `typ`, plus the RFC 9068 access-token profile (`at+jwt`). Verification can select its key from a JWK Set.
- **JWK (RFC 7517):** `oct`, `EC` (P-256, P-384, P-521, secp256k1), `OKP` (Ed25519, X25519) and `RSA` public keys; JWK Sets with key selection by `kid`, `alg` and `use`; public-key extraction; RFC 7638 thumbprints (SHA-256, SHA-384, SHA-512) and RFC 9278 thumbprint URIs.
- **Key generation** of `oct`, EC and OKP keys from the operating system's random number generator, by key type or by algorithm.
- **PEM and DER import and export:** PKCS#8 and SEC1 private keys and SubjectPublicKeyInfo public keys for EC and OKP; SubjectPublicKeyInfo and PKCS#1 public keys for RSA.
- **base64url** encoding and decoding (RFC 4648 §5).
- **Rust only:** JWE compression (`zip: DEF`) behind the opt-in `deflate` cargo feature, off by default. The bindings are built without it.

#### Platforms and API

- **Rust:** the `polyjose` crate on crates.io. MSRV 1.89, edition 2024, no `unsafe` code.
- **Node.js:** `@polyjose/node` on npm, a native addon with prebuilt binaries for macOS (arm64, x64), Linux glibc 2.28+ and musl (arm64, x64), and Windows (arm64, x64), published as eight `@polyjose/node-*` platform packages. ESM only (CommonJS can load it through `require(esm)`), Node.js 22.12 or later, TypeScript types included. Every operation returns a Promise and runs off the event loop. The package loads only the addon whose SHA-256 it was built with.
- **Web (WebAssembly):** `@polyjose/wasm` on npm, with the same API and TypeScript types as `@polyjose/node`. Entries for browsers (including Web Workers), Node.js 22.12 or later and Cloudflare Workers. It is tested on Node.js, headless Chrome and Cloudflare Workers (workerd). The module is integrity-checked before it is instantiated.
- **Android and the JVM (Kotlin and Java):** on Maven Central under the group `dev.polyjose`. `polyjose` is the Android AAR (minSdk 23; arm64-v8a, armeabi-v7a, x86_64, x86). `polyjose-jvm` is the desktop JVM jar (Java 17 bytecode) with native libraries for macOS (arm64, x64), Linux (arm64, x64) and Windows (x64). Consuming the Kotlin API needs a Kotlin 2.4 compiler.
- **Swift:** the Swift package `Polyjose` (SwiftPM, from this repository's `Package.swift`) with a prebuilt XCFramework, for iOS 16, macOS 13 and watchOS 9. Tests run on macOS and the iOS Simulator; for watchOS the package is build- and link-checked only.
- **One API on every binding:** utilities (`version`, `errorCodes`, `base64urlEncode`, `base64urlDecode`); JWK (`jwkParse`, `jwkToPublic`, `jwkThumbprint`, `jwkThumbprintUri`, `jwksSelect`, `jwkGenerateOct`, `jwkGenerateEc`, `jwkGenerateOkp`, `jwkGenerateForAlg`, `jwkFromPem`, `jwkFromDer`, `jwkToPem`, `jwkToDer`); JWS (`jwsSignCompact`, `jwsSignFlattened`, `jwsSignGeneral`, `jwsVerifyCompact`, `jwsVerifyJson`); JWE (`jweEncryptCompact`, `jweEncryptJson`, `jweDecryptCompact`, `jweDecryptJson`); JWT (`jwtSign`, `jwtVerify`, `jwtVerifyWithJwks`, `jwtEncryptNested`, `jwtDecryptNested`, `jwtDecryptNestedWithJwks`). Names are camelCase in JavaScript, Kotlin and Swift, and snake_case in Rust. Errors carry one of 17 stable codes, such as `InvalidSignature`, `AlgorithmNotAllowed` and `TokenExpired`.

### Security

- **Explicit algorithm allow-lists.** Verify and decrypt always take the allowed algorithms (and, for JWE, the allowed `enc` values); the header's `alg` is never trusted on its own. `alg: none` is never accepted. Keys are bound to their algorithm family (RFC 8725).
- **Bounded inputs.** Limits on input length, signature and recipient count, JWK Set key candidates and, by default, the PBES2 iteration count (`p2c` at most 10,000 per token on decrypt). Unknown `crit` header parameters are rejected.
- **ECDH-ES:** the ephemeral public key must be on the recipient's curve and is validated before any key agreement.
- **Secrets:** key material is zeroized when dropped and is never put into `Debug` output or error messages. Kotlin and Swift records print their secret fields redacted.
- **Randomness** comes only from the operating system's random number generator.
- **Testing:** the RFCs' own test vectors (RFC 7515, 7516, 7517, 7518, 7519, the RFC 7520 cookbook, 7638, 7797, 8037, 9278), Wycheproof where it applies, one shared conformance suite run by every binding, two-way interop tests against panva/jose, and fuzzing of the parsers.
- **Audits:** polyjose itself has not been independently audited. [AUDITS.md](https://github.com/bharathkontham/polyjose/blob/main/AUDITS.md) lists which of the primitive crates have a published third-party audit, and which version line it covered.
- **Release integrity:** every release asset is listed in `SHA256SUMS`, signed with the release key in [`.github/keys/`](https://github.com/bharathkontham/polyjose/tree/main/.github/keys), and has a GitHub build attestation. The Maven artifacts are GPG-signed.

### Not supported in 0.1.0

- **RSA private-key operations.** There is no RS*/PS* signing, no RSA-OAEP-256 decryption and no RSA key generation, and RSA private keys are rejected on import (JWK, PEM and DER). The `rsa` crate's private-key operations are affected by [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html) (the Marvin timing attack), which has no patched release. RSA private-key support is planned for a later release, once a stable `rsa` 0.10 is marked patched.
- **`RSA1_5` and `RSA-OAEP` (SHA-1)** key management, and SHA-1 thumbprints.
- **Ed448 and X448** keys.
- **JWE compression (`zip: DEF`) in the bindings.** It is a Rust-only, opt-in feature.
- **Encrypt-only JWTs.** A nested JWT must be signed, then encrypted.
- **Encrypted PKCS#8** keys and BER encodings in PEM/DER import.
- **Deno and Bun** are not tested for `@polyjose/wasm`.
