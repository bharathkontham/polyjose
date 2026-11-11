# polyjose for Swift

The Swift package of polyjose: JOSE (JWS, JWE, JWK and JWT; RFC 7515 to 7519) from the pure-Rust
polyjose core, linked as a static XCFramework. iOS is the main target; it also builds for iPadOS,
macOS and watchOS. tvOS and visionOS are not supported. Verify and decrypt always take an explicit
algorithm allow-list, and `none` is never accepted (RFC 8725).

## Install

Add the package with Swift Package Manager, in `Package.swift` or in Xcode under
**File › Add Package Dependencies**, and depend on the product `Polyjose`:

```swift
dependencies: [
    .package(url: "https://github.com/bharathkontham/polyjose", from: "0.2.0"),
],
targets: [
    .target(
        name: "MyApp",
        dependencies: [
            .product(name: "Polyjose", package: "polyjose"),
        ]
    ),
]
```

The XCFramework is attached to each
[GitHub release](https://github.com/bharathkontham/polyjose/releases), and the package's
`Package.swift` points at it with a checksum. iOS 16 and macOS 13 or later, with Swift tools 6.0;
see [Platforms](https://github.com/bharathkontham/polyjose/blob/main/platforms/swift/README.md#platforms).

## Import

```swift
import Polyjose
```

Calls are synchronous and throw `PolyjoseError`. Keep them off the main actor, for example in a
detached task.

## Quick start

Sign a JWT, then verify it with an explicit algorithm allow-list and the issuer and audience you
expect. `exp` is required and checked, with 60 seconds of leeway (RFC 8725 §3.8 to §3.10).

```swift
import Foundation
import Polyjose

// An ES256 key pair. The verifier needs only the public half.
let privateKey = try jwkGenerateForAlg(alg: "ES256")
let publicKey = try jwkToPublic(jwk: privateKey)

let now = Int64(Date().timeIntervalSince1970)
let token = try jwtSign(
    claims: #"{"iss":"https://issuer.example","sub":"user-123","aud":"https://api.example","exp":\#(now + 300)}"#,
    key: privateKey,
    options: JwtSignOptions(alg: "ES256")
)

do {
    let verified = try jwtVerify(
        token: token,
        key: publicKey,
        options: JwtVerifyOptions(
            allowedAlgs: ["ES256"],  // never trust the token's own `alg` (RFC 8725 §3.1)
            issuers: ["https://issuer.example"],
            audiences: ["https://api.example"]
        )
    )
    print(verified.claims)  // the claims as JSON text, with "sub":"user-123"
} catch let error as PolyjoseError {
    print(error.code())  // e.g. "TokenExpired"
}
```

Encrypt to a recipient's public key, then decrypt, naming the algorithms you accept:

```swift
let recipient = try jwkGenerateEc(crv: "P-256")
let jwe = try jweEncryptCompact(
    plaintext: Data("top secret".utf8),
    options: JweEncryptOptions(
        enc: "A256GCM",
        recipients: [JweRecipient(alg: "ECDH-ES+A256KW", key: try jwkToPublic(jwk: recipient))]
    )
)
var decrypted = try jweDecryptCompact(
    token: jwe,
    key: recipient,
    options: JweDecryptOptions(allowedAlgs: ["ECDH-ES+A256KW"], allowedEnc: ["A256GCM"])
)
print(String(decoding: decrypted.plaintext, as: UTF8.self))  // "top secret"
decrypted.plaintext.resetBytes(in: decrypted.plaintext.indices)  // wipe secret bytes when done
```

Printing a result redacts its secret fields, but reading a field gives the secret: never log
`verified.payload`, `decrypted.plaintext` or a key.

## Documentation

- Getting started in Swift: <https://polyjose.dev/start/swift/>
- Secrets in memory, and what printing a record shows: <https://polyjose.dev/reference/swift/>
- Guides (sign and verify, encrypt and decrypt, validate a JWT, keys): <https://polyjose.dev>
- Error codes: <https://polyjose.dev/concepts/errors/>
- Source and issues: <https://github.com/bharathkontham/polyjose>

## Platforms

### Static linking

The XCFramework holds static libraries (ADR 0032), so polyjose's Rust code, with its own copy of the Rust standard library, is linked into your app's binary. This has two consequences:
- **Another Rust static library in the same app can clash with it.** Both define `rust_eh_personality` and Rust standard library symbols, so the link can fail with duplicate-symbol errors. A dynamic-framework variant, which avoids this, is in the backlog.
- **Generic watchOS Simulator builds need `EXCLUDED_ARCHS`.** The watchOS Simulator library is arm64 only, but a generic simulator destination (`generic/platform=watchOS Simulator`) also builds x86_64, which then fails to link. Either set `EXCLUDED_ARCHS[sdk=watchsimulator*] = x86_64` in your target's build settings, or build for a concrete watch simulator (`-destination 'platform=watchOS Simulator,name=<device>'`). Limit the setting to `watchsimulator*`: the iOS Simulator library includes x86_64, which an Intel Mac needs.

### OS minimums

The deployment targets of the XCFramework and of `Package.swift`'s `platforms:` (ADR 0032 §1):

| Platform | Minimum | XCFramework library |
|---|---|---|
| iOS and iPadOS | 16.0 | `ios-arm64` |
| iOS Simulator | 16.0 | `ios-arm64_x86_64-simulator` |
| macOS | 13.0 | `macos-arm64_x86_64` |
| watchOS | 9.0 (see the note) | `watchos-arm64_arm64_32` |
| watchOS Simulator | 9.0 | `watchos-arm64-simulator` |

**watchOS:** the device library holds two architectures with different minimums.
- `arm64_32` starts at watchOS 9.0. Every watch on watchOS 9–25 runs this code, and on watchOS 26 the Series 4–8, SE 1–2 and Ultra 1 still do.
- `arm64` starts at watchOS 26.0, because rustc raises `aarch64-apple-watchos` to its own minimum, the first release with arm64 watch apps, whatever deployment target is asked for. Series 9 and later and Ultra 2 run this code on watchOS 26 and later.

So an app can keep a watchOS deployment target as low as 9: older releases use the `arm64_32` code. The watchOS Simulator library starts at 9.0.

## Building from source

How the Swift package is built, tested and packaged:
- `scripts/build-xcframework.sh` builds `build/PolyjoseFFI.xcframework` (gitignored), a static XCFramework with 5 libraries: iOS, iOS Simulator (arm64 + x86_64), macOS (arm64 + x86_64), watchOS (arm64 + arm64_32) and watchOS Simulator (ADR 0032).
  - Every Rust target is tier 2 on the stable toolchain of `rust-toolchain.toml` (the aarch64 watchOS targets since Rust 1.95), except `arm64_32-apple-watchos` (Apple Watch Series 4–8, SE 1–2, Ultra 1). That one is tier 3 and is built with the nightly pinned in `nightly-toolchain` and `-Zbuild-std`. Install it with `rustup toolchain install "$(cat platforms/swift/nightly-toolchain)" --profile minimal --component rust-src`.
  - Without that nightly the script makes a development build: the watchOS library is arm64 only, `PolyjoseFFI.xcframework/polyjose-build.txt` says `arm64_32: missing`, and the build must not be released. `--release` fails instead.
  - Deployment minimums: see [OS minimums](https://github.com/bharathkontham/polyjose/blob/main/platforms/swift/README.md#os-minimums).
  - The libraries ship without debug info. The script strips every archive with `xcrun strip -S` before it assembles the XCFramework, because the release profile's `strip` does not apply to static libraries and the debug info would triple the download. Symbols are kept, so linking is unaffected, and polyjose frames in your app's crash reports show function names but not file and line.
- `uniffi-bindgen generate --language swift` writes the Swift sources (the build leaves them in `build/generated/`)
- Tests: XCTest on the macOS host (`swift test`) and on the iOS Simulator, running the conformance vectors. The watchOS libraries are built and link-checked (`scripts/test-simulators.sh`) but not separately tested, because the Swift code is the same on every Apple platform.
- Packaging: `scripts/package.sh` writes `dist/apple/PolyjoseFFI.xcframework.zip` (the XCFramework with `THIRD-PARTY-NOTICES.txt` and `LICENSE` inside it), its `.sha256` and `binaryTarget.swift.txt`, the `binaryTarget(url:checksum:)` stanza for the release (ADR 0032 §6). It refuses a development build (`arm64_32: missing`) or a stale one unless `--allow-dev` is given, and a zip of 25,000,000 bytes or more. It publishes nothing; the release workflow attaches the zip to the GitHub Release. Its tests are `scripts/tests/test-*.sh`, which `test.sh` runs.
- Publishing: a `Package.swift` at the repo root with a `binaryTarget` (URL + checksum) pointing at the XCFramework zip on the GitHub Release

## License

MIT; see [LICENSE](https://github.com/bharathkontham/polyjose/blob/main/LICENSE).
