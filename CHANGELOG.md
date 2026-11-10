# Changelog

All notable changes to polyjose are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and polyjose follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **RSA signing:** `RS256`, `RS384`, `RS512`, `PS256`, `PS384` and `PS512` sign with an RSA private key, in compact and JSON JWS and in JWT issuing (RFC 7518 §3.3, §3.5). `RS*` signatures are deterministic and match RFC 7515 Appendix A.2 exactly.
- **RSA-OAEP-256 decryption** (RFC 7518 §4.3), in compact and JSON JWE, with one or more recipients. A bad Encrypted Key is never reported as such: a random content key is used instead and the result is `DecryptionFailed`, like any other failure (RFC 7516 §11.5).
- **RSA private keys:** import from a JWK (all of `d`, `p`, `q`, `dp`, `dq` and `qi`; RFC 7518 §6.3.2), PKCS#8 (`PRIVATE KEY`) and PKCS#1 (`RSA PRIVATE KEY`, and `KeyFormat::Pkcs1` DER); export as a JWK and as PKCS#8. The private members must be the key of `n` and `e`, the modulus is 2048 to 8192 bits, and the key is wiped on drop and redacted in `Debug`. `RsaPublicKey::is_private` tells a private RSA key from a public one, and `Jwk::to_public` drops the private members.
- **JWK Sets** keep an RSA private member as imported, like EC and OKP private keys, so a set can hold RSA-OAEP-256 decryption keys. Call `to_public` on each key before publishing a set.

### Changed

- **Behaviour change:** an RSA private JWK, PEM or DER key used to fail with `UnsupportedAlgorithm`; it now imports. A JWK Set with an RSA private member used to fail as a whole; it now keeps the member. Signing RS*/PS* or decrypting RSA-OAEP-256 used to fail with `UnsupportedAlgorithm`; with a public key it now fails with `KeyAlgorithmMismatch`.
- **Behaviour change:** a PKCS#1 RSAPrivateKey given as PKCS#8 or SEC1 (by `KeyFormat` or by PEM label) is now `InvalidKey` (the wrong structure for the format), not `UnsupportedAlgorithm`.
- **Rust:** the `rsa` dependency is `0.10.0` with only its `pkcs1v15` feature; `crypto-bigint` is `0.7.11`.

### Security

- `rsa` 0.10.0 is the first release patched for RUSTSEC-2023-0071 (Marvin); the `cargo deny` ignore is gone. RSA private-key operations go only through `rsa`'s blinded entry points with the OS CSPRNG, and the build checks keep key generation, `RSA1_5`, unblinded paths and `rsa`'s `hazmat` API out. See SECURITY.md for the evidence and the two known `rsa` deviations.
- Multi-prime RSA keys (`oth`, PKCS#1 version `multi`) are `UnsupportedAlgorithm`, and an RSA private JWK without its CRT members is `InvalidKey`.

## [0.1.2] - 2026-11-10

A packaging and documentation release. The public API of every binding is unchanged from 0.1.1.

### Added

- **Rust:** the crate has its own crates.io README, with install, import and a quick start. Its examples are compiled and run as doctests, so they stay in step with the API.

### Changed

- **Node.js: `@polyjose/node` is now one package that contains the prebuilt addons for all 8 targets** (macOS arm64 and x64, Linux glibc and musl arm64 and x64, Windows arm64 and x64). It no longer has `optionalDependencies`, and the 8 `@polyjose/node-<platform>` packages are no longer published; they are deprecated on npm. The install now works with `--omit=optional` and in bundles built on one platform for another. The download is larger, about 23 MB unpacked instead of about 3 MB.
- **Node.js: the addon is loaded only from the package's own directory.** The loader resolves no module name and reads no environment variable. It loads `polyjose.<platform>.node` from its own package, checks the addon's SHA-256 against the pinned value, and refuses anything else with `ERR_POLYJOSE_ADDON_REFUSED`. `NODE_PATH`, ancestor `node_modules` directories and the `@polyjose/node-<platform>` packages no longer affect what loads.
- **Node.js, behaviour change: the `NAPI_RS_*` environment variables are ignored.** `NAPI_RS_NATIVE_LIBRARY_PATH` used to be accepted when it named the pinned addon, and `NAPI_RS_FORCE_WASI` and `NAPI_RS_WASI_FLAVOR` used to make the import throw. Now none of them has any effect, and the import never throws because of one.
  - **Migration:** remove `NAPI_RS_NATIVE_LIBRARY_PATH` from your environment; the bundled addon for your platform is always used. If you depended on `@polyjose/node-<platform>` directly, depend on `@polyjose/node` 0.1.2 instead. If you set `NAPI_RS_FORCE_WASI` to get a WebAssembly build, use `@polyjose/wasm`, which has the same API. Platforms outside the 8 targets are still refused, with a message that points at `@polyjose/wasm`.
- **Node.js on Windows embedders:** a host that napi-rs mapped to `win32-x64-gnu` (for example `node_target_type: shared_library`), which polyjose never shipped, now gets the `win32-x64-msvc` addon.
- **Docs:** every package README (crates.io, npm, Maven, Swift) is cut to install, import and a quick start, and links the full guide for its platform on polyjose.dev. The repository README links each platform's docs.
- **Swift:** `Package.swift` points at the 0.1.2 XCFramework, and its header no longer calls the binary target a placeholder.

### Security

- **Smaller Node.js loader surface.** The add-on loader no longer probes other packages, `NODE_PATH` or environment overrides, so nothing outside the installed `@polyjose/node` directory can influence which native code is loaded.
- **Publishing:** crates.io and npm packages are published by trusted publishing (GitHub OIDC) with provenance. No long-lived registry token is used.

### API by platform

- **Rust (`polyjose`):** no change.
- **Node.js (`@polyjose/node`):** no change to `index.d.ts` or the `exports` map. The internal `binding.cjs` backend, which was never a supported API, is no longer shipped.
- **Web (`@polyjose/wasm`):** no change.
- **Android and the JVM (`dev.polyjose:polyjose`, `polyjose-jvm`):** no change.
- **Swift (`Polyjose`):** no change.

## [0.1.1] - 2026-11-09

This is the first published release of polyjose; 0.1.0 was tagged but never published, because its release workflow did not create the draft release.

polyjose is a pure-Rust implementation of JOSE (JWS, JWE, JWK, JWT and JWA) for Rust, Node.js, the web (WebAssembly), Android and the JVM (Kotlin/Java), and Swift. All cryptography comes from RustCrypto and dalek crates, with no OpenSSL, `ring` or `aws-lc`. Every binding is built from the same Rust core and runs the same conformance vectors.

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

### Fixed

- **Release workflow:** the `attest` and `draft` jobs of `release.yml`, and the `spm` check of `publish.yml`, now run when a job further up their chain was skipped by design (the Apple build is skipped in tag mode). For 0.1.0 both jobs were skipped, so the tag run created no build attestations and no draft release.

### Security

- **Explicit algorithm allow-lists.** Verify and decrypt always take the allowed algorithms (and, for JWE, the allowed `enc` values); the header's `alg` is never trusted on its own. `alg: none` is never accepted. Keys are bound to their algorithm family (RFC 8725).
- **Bounded inputs.** Limits on input length, signature and recipient count, JWK Set key candidates and, by default, the PBES2 iteration count (`p2c` at most 10,000 per token on decrypt). Unknown `crit` header parameters are rejected.
- **ECDH-ES:** the ephemeral public key must be on the recipient's curve and is validated before any key agreement.
- **Secrets:** key material is zeroized when dropped and is never put into `Debug` output or error messages. Kotlin and Swift records print their secret fields redacted.
- **Randomness** comes only from the operating system's random number generator.
- **Testing:** the RFCs' own test vectors (RFC 7515, 7516, 7517, 7518, 7519, the RFC 7520 cookbook, 7638, 7797, 8037, 9278), Wycheproof where it applies, one shared conformance suite run by every binding, two-way interop tests against panva/jose, and fuzzing of the parsers.
- **Audits:** polyjose itself has not been independently audited. [AUDITS.md](https://github.com/bharathkontham/polyjose/blob/main/AUDITS.md) lists which of the primitive crates have a published third-party audit, and which version line it covered.
- **Release integrity:** every release asset is listed in `SHA256SUMS`, signed with the release key in [`.github/keys/`](https://github.com/bharathkontham/polyjose/tree/main/.github/keys), and has a GitHub build attestation. The Maven artifacts are GPG-signed.

### Not supported in 0.1.1

- **RSA private-key operations.** There is no RS*/PS* signing, no RSA-OAEP-256 decryption and no RSA key generation, and RSA private keys are rejected on import (JWK, PEM and DER). The `rsa` crate's private-key operations are affected by [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html) (the Marvin timing attack), which has no patched release. RSA private-key support is planned for a later release, once a stable `rsa` 0.10 is marked patched.
- **`RSA1_5` and `RSA-OAEP` (SHA-1)** key management, and SHA-1 thumbprints.
- **Ed448 and X448** keys.
- **JWE compression (`zip: DEF`) in the bindings.** It is a Rust-only, opt-in feature.
- **Encrypt-only JWTs.** A nested JWT must be signed, then encrypted.
- **Encrypted PKCS#8** keys and BER encodings in PEM/DER import.
- **Deno and Bun** are not tested for `@polyjose/wasm`.

## [0.1.0] - 2026-11-09

Tagged but not published (the release workflow created no draft release); superseded by 0.1.1.
