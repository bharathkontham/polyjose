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
    .package(url: "https://github.com/bharathkontham/polyjose", from: "0.4.0"),
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
see [Platforms](https://github.com/bharathkontham/polyjose/blob/main/bindings/swift/README.md#platforms).

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

## Platform keys: `AppleKey`

`AppleKey` is a private key held by the Apple platform. polyjose asks it for one private-key step
at a time (a signature, an ECDH shared secret or an RSA-OAEP-256 decryption) through the Security
framework (`SecKey`) and never sees the private key. Every JOSE check stays in polyjose.

```swift
// Once: create a Secure Enclave key under a tag of your choice.
let key = try AppleKey.generate(tag: "com.example.signing", algorithm: "ES256", protection: .secureEnclave)
let publicJwk = try key.publicJwk()  // give this to the verifier

// Later, also in a new process: find it again by its tag, and sign.
let signer = try AppleKey.open(tag: "com.example.signing", algorithm: "ES256")
let token = try jwtSignWithPlatformKey(claims: #"{"sub":"user-123"}"#, key: signer, options: JwtSignOptions(alg: "ES256"))
```

Decrypt with `jweDecryptCompactWithPlatformKey`, `jweDecryptJsonWithPlatformKey` or
`jwtDecryptNestedWithPlatformKey`, after encrypting to `publicJwk()`. `AppleKey(secKey:algorithm:)`
wraps a private `SecKey` your app created itself, and `AppleKey.delete(tag:)` deletes a key.

**Two protections.** `protection` is where the key lives, as the platform reports it:

| `protection` | Signing | Decryption |
|---|---|---|
| `.secureEnclave` | ES256 | ECDH-ES, ECDH-ES+A128KW/A192KW/A256KW on P-256 |
| `.keychain` | ES256, ES384, ES512; RS256/384/512 and PS256/384/512 (2048, 3072 or 4096 bits) | ECDH-ES family on P-256, P-384, P-521; RSA-OAEP-256 |

- `.secureEnclave` is the only hardware-bound protection.
- `.keychain` keys are stored and protected by the OS, not hardware-bound; on iOS, code that
  holds the key reference can export the private key.
- There is no fallback to a software key: `.secureEnclave` with any other algorithm is
  `UnsupportedAlgorithm`, and so is `.secureEnclave` when `SecureEnclave.isAvailable` is false,
  which `generate` checks first.

**One algorithm per key.** A key is bound to the one algorithm you name: a signing algorithm,
`RSA-OAEP-256`, or `ECDH-ES`, which also serves the three `ECDH-ES+A*KW` algorithms. Use
`keySizeInBits:` for an RSA size or an ECDH curve (256, 384 or 521). Generated keys are
`ThisDeviceOnly` and never synchronizable; `access:` sets the accessibility and optional
`.userPresence`, `.biometryAny`, `.biometryCurrentSet` or `.devicePasscode` flags, and can pass an
`LAContext`.

**Off the main thread.** The calls are synchronous. A key with an `access` flag makes the system
show a prompt during the call, so call it off the main thread.

**Face ID needs `NSFaceIDUsageDescription`.** An app whose `AppleKey` access control can use
biometry (`.biometryCurrentSet`, `.biometryAny`, or `.userPresence` where Face ID is used) must set
`NSFaceIDUsageDescription` in its Info.plist: Apple's documentation says the key "is required if
your app uses APIs that access Face ID"
([`NSFaceIDUsageDescription`](https://developer.apple.com/documentation/bundleresources/information-property-list/nsfaceidusagedescription)). With a generated Info.plist, set
the build setting `INFOPLIST_KEY_NSFaceIDUsageDescription`. Without the key, iOS terminated the
app when a `.biometryCurrentSet` key signed, on an iPhone 16 with iOS 27.0.1: "attempted to access
privacy-sensitive data without a usage description. The app's Info.plist must contain an
NSFaceIDUsageDescription key". On that device, the first Face ID use showed a one-time iOS prompt asking
whether the app may use Face ID, before the Face ID prompt itself, and the `.biometryCurrentSet`
prompt offered Face ID only, with no passcode fallback.

**macOS.** A permanent key needs a signed app with a keychain entitlement (Apple's rule): an
unsigned binary, such as `swift test`, gets `PlatformKeyFailed` from `generate`.

**Errors** (`PolyjoseError.code()`), with fixed text: no platform message, tag or key is included.

| Code | When |
|---|---|
| `KeyNotFound` | No key under that tag |
| `UserAuthenticationRequired` | The user has not authenticated, cancelled, or can't: biometry locked out, not available or not enrolled, or no passcode set. The same on Android; prompt, then retry |
| `PlatformKeyFailed` | Any other platform failure while creating, finding or signing |
| `DecryptionFailed` | Any other failure while decrypting (RFC 7516 §11.5) |
| `UnsupportedAlgorithm` | An algorithm or size the protection can't serve |
| `KeyAlgorithmMismatch` | A key that can't do the algorithm, or a call for another algorithm |
| `InvalidKey` | `AppleKey(secKey:algorithm:)` given a public key |

**Printing** an `AppleKey` shows its type and `protection` only, never the tag or the key.

**watchOS** has no biometry: `LAError.Code.biometryLockout`, `.biometryNotAvailable` and
`.biometryNotEnrolled` don't exist there, so they are left out of the error mapping on watchOS.

## Documentation

- Getting started in Swift: <https://polyjose.dev/start/swift/>
- Secrets in memory, and what printing a record shows: <https://polyjose.dev/reference/swift/>
- Guides (sign and verify, encrypt and decrypt, validate a JWT, keys): <https://polyjose.dev>
- Error codes: <https://polyjose.dev/concepts/errors/>
- Source and issues: <https://github.com/bharathkontham/polyjose>

## Platforms

### Static linking

The XCFramework holds static libraries (ADR 0032), so polyjose's Rust code, with its own copy of the Rust standard library, is linked into your app's binary. This has three consequences:
- **Another Rust static library in the same app can clash with it.** Both define `rust_eh_personality` and Rust standard library symbols, so the link can fail with duplicate-symbol errors. A dynamic-framework variant, which avoids this, is in the backlog.
- **Generic watchOS Simulator builds need `EXCLUDED_ARCHS`.** The watchOS Simulator library is arm64 only, but a generic simulator destination (`generic/platform=watchOS Simulator`) also builds x86_64, which then fails to link. Either set `EXCLUDED_ARCHS[sdk=watchsimulator*] = x86_64` in your target's build settings, or build for a concrete watch simulator (`-destination 'platform=watchOS Simulator,name=<device>'`).
- **The macOS and iOS Simulator libraries are arm64 (Apple silicon) only (ADR 0073), so a build that includes x86_64 needs `EXCLUDED_ARCHS`.** Measured with Xcode 27.2 and `POLYJOSE_LOCAL_XCFRAMEWORK=1`:
  - `swift build --arch x86_64` of a package that depends on `Polyjose` fails to link: `ld: warning: ignoring file '…/libpolyjose_ffi.a(…)': found architecture 'arm64', required architecture 'x86_64'`, then `Undefined symbols for architecture x86_64` and `ld: symbol(s) not found for architecture x86_64`.
  - A macOS app built with `ARCHS="arm64 x86_64"` (a universal build) fails to link with the same errors.
  - The same macOS build with `EXCLUDED_ARCHS = x86_64`, set in the app target's build settings or passed to `xcodebuild`, succeeds and produces an arm64 app.
  - An iOS app built for `generic/platform=iOS Simulator` also builds x86_64, and fails to link with the same errors.
  - The same iOS Simulator build with `EXCLUDED_ARCHS[sdk=iphonesimulator*] = x86_64` in the app target's build settings succeeds and produces an arm64 app. Passed on the `xcodebuild` command line instead, that conditional setting was not applied, and the link failed with the same errors.

### OS minimums

The deployment targets of the XCFramework and of `Package.swift`'s `platforms:` (ADR 0032 §1):

| Platform | Minimum | XCFramework library |
|---|---|---|
| iOS and iPadOS | 16.0 | `ios-arm64` |
| iOS Simulator | 16.0 | `ios-arm64-simulator` (arm64 only) |
| macOS | 13.0 | `macos-arm64` (arm64 only: Apple silicon Macs) |
| watchOS | 9.0 (see the note) | `watchos-arm64_arm64_32` |
| watchOS Simulator | 9.0 | `watchos-arm64-simulator` |

**watchOS:** the device library holds two architectures with different minimums.
- `arm64_32` starts at watchOS 9.0. Every watch on watchOS 9–25 runs this code, and on watchOS 26 the Series 4–8, SE 1–2 and Ultra 1 still do.
- `arm64` starts at watchOS 26.0, because rustc raises `aarch64-apple-watchos` to its own minimum, the first release with arm64 watch apps, whatever deployment target is asked for. Series 9 and later and Ultra 2 run this code on watchOS 26 and later.

So an app can keep a watchOS deployment target as low as 9: older releases use the `arm64_32` code. The watchOS Simulator library starts at 9.0.

## Building from source

| Path | What it is |
|---|---|
| `Package.swift` (repo root) | the SwiftPM manifest; Swift Package Manager needs it at the repository root |
| `Sources/Polyjose/` | `Polyjose.swift` (UniFFI-generated from `bindings/uniffi`, committed) and the hand-written `AppleKey.swift` and `Redaction.swift` |
| `Tests/PolyjoseTests/` | XCTest suites, including the Swift conformance runner; `Resources/` links to `conformance/` |
| `HostedTests/` | AppleKey tests inside a host app on the simulator (Keychain entitlement) |
| `scripts/` | XCFramework build, generated-code check, packaging, simulator runs; `scripts/tests/` tests those scripts |
| `test.sh` | the whole suite (`scripts/test-all.sh swift`) |

How the Swift package is built, tested and packaged:
- `scripts/build-xcframework.sh` builds `build/PolyjoseFFI.xcframework` (gitignored), a static XCFramework with 5 libraries: iOS (`ios-arm64`), iOS Simulator (`ios-arm64-simulator`, arm64), macOS (`macos-arm64`, arm64), watchOS (`watchos-arm64_arm64_32`, arm64 + arm64_32) and watchOS Simulator (`watchos-arm64-simulator`, arm64) (ADR 0032, ADR 0073). No x86_64 library is built.
  - Every Rust target is tier 2 on the stable toolchain of `rust-toolchain.toml` (the aarch64 watchOS targets since Rust 1.95), except `arm64_32-apple-watchos` (Apple Watch Series 4–8, SE 1–2, Ultra 1). That one is tier 3 and is built with the nightly pinned in `nightly-toolchain` and `-Zbuild-std`. Install it with `rustup toolchain install "$(cat bindings/swift/nightly-toolchain)" --profile minimal --component rust-src`.
  - Without that nightly the script makes a development build: the watchOS library is arm64 only, `PolyjoseFFI.xcframework/polyjose-build.txt` says `arm64_32: missing`, and the build must not be released. `--release` fails instead.
  - Deployment minimums: see [OS minimums](https://github.com/bharathkontham/polyjose/blob/main/bindings/swift/README.md#os-minimums).
  - The libraries ship without debug info. The script strips every archive with `xcrun strip -S` before it assembles the XCFramework, because the release profile's `strip` does not apply to static libraries and the debug info would triple the download. Symbols are kept, so linking is unaffected, and polyjose frames in your app's crash reports show function names but not file and line.
- `uniffi-bindgen generate --language swift` writes the Swift sources (the build leaves them in `build/generated/`)
- Tests: XCTest on the macOS host (`swift test`) and on the iOS Simulator, running the conformance vectors. The watchOS libraries are built and link-checked (`scripts/test-simulators.sh`) but not separately tested, because the Swift code is the same on every Apple platform.
- Packaging: `scripts/package.sh` writes `dist/apple/PolyjoseFFI.xcframework.zip` (the XCFramework with `THIRD-PARTY-NOTICES.txt` and `LICENSE` inside it), its `.sha256` and `binaryTarget.swift.txt`, the `binaryTarget(url:checksum:)` stanza for the release (ADR 0032 §6). It refuses a development build (`arm64_32: missing`) or a stale one unless `--allow-dev` is given, and a zip of 25,000,000 bytes or more. It publishes nothing; the release workflow attaches the zip to the GitHub Release. Its tests are `scripts/tests/test-*.sh`, which `test.sh` runs.
- Publishing: a `Package.swift` at the repo root with a `binaryTarget` (URL + checksum) pointing at the XCFramework zip on the GitHub Release

## License

MIT; see [LICENSE](https://github.com/bharathkontham/polyjose/blob/main/LICENSE).
