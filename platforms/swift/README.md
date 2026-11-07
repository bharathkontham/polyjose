# Swift (iOS)

The Swift binding of polyjose. iOS is the main target; it also builds for iPadOS, macOS, tvOS, watchOS and visionOS.

Swift Package:
- `scripts/build-xcframework.sh` builds `build/PolyjoseFFI.xcframework` (gitignored), a static XCFramework with 9 libraries: iOS, iOS Simulator (arm64 + x86_64), macOS (arm64 + x86_64), tvOS, tvOS Simulator, visionOS, visionOS Simulator, watchOS (arm64 + arm64_32) and watchOS Simulator (ADR 0032).
  - Every Rust target is tier 2 on the stable toolchain of `rust-toolchain.toml` (the aarch64 tvOS, visionOS and watchOS targets since Rust 1.95), except `arm64_32-apple-watchos` (Apple Watch Series 4–8, SE 1–2, Ultra 1). That one is tier 3 and is built with the nightly pinned in `nightly-toolchain` and `-Zbuild-std`. Install it with `rustup toolchain install "$(cat platforms/swift/nightly-toolchain)" --profile minimal --component rust-src`.
  - Without that nightly the script makes a development build: the watchOS library is arm64 only, `PolyjoseFFI.xcframework/polyjose-build.txt` says `arm64_32: missing`, and the build must not be released. `--release` fails instead.
  - Deployment minimums: see [OS minimums](#os-minimums).
  - The libraries ship without debug info. The script strips every archive with `xcrun strip -S` before it assembles the XCFramework, because the release profile's `strip` does not apply to static libraries and the debug info would triple the download. Symbols are kept, so linking is unaffected, and polyjose frames in your app's crash reports show function names but not file and line.
- `uniffi-bindgen generate --language swift` writes the Swift sources (the build leaves them in `build/generated/`)
- Tests: XCTest on the macOS host (`swift test`) and on the iOS Simulator, running the conformance vectors. The tvOS, watchOS and visionOS libraries are built but not separately tested, because the Swift code is the same on every Apple platform.
- Packaging: `scripts/package.sh` writes `dist/apple/PolyjoseFFI.xcframework.zip` (the XCFramework with `THIRD-PARTY-NOTICES.txt` and `LICENSE` inside it), its `.sha256` and `binaryTarget.swift.txt`, the `binaryTarget(url:checksum:)` stanza for the release (ADR 0032 §6). It refuses a development build (`arm64_32: missing`) or a stale one unless `--allow-dev` is given, and a zip of 25,000,000 bytes or more. It publishes nothing; the release workflow attaches the zip to the GitHub Release. Its tests are `scripts/tests/test-*.sh`, which `test.sh` runs.
- Publishing: a `Package.swift` at the repo root with a `binaryTarget` (URL + checksum) pointing at the XCFramework zip on the GitHub Release

## OS minimums

The deployment targets of the XCFramework and of `Package.swift`'s `platforms:` (ADR 0032 §1):

| Platform | Minimum | XCFramework library |
|---|---|---|
| iOS and iPadOS | 16.0 | `ios-arm64` |
| iOS Simulator | 16.0 | `ios-arm64_x86_64-simulator` |
| macOS | 13.0 | `macos-arm64_x86_64` |
| tvOS | 16.0 | `tvos-arm64` |
| tvOS Simulator | 16.0 | `tvos-arm64-simulator` |
| watchOS | 9.0 (see the note) | `watchos-arm64_arm64_32` |
| watchOS Simulator | 9.0 | `watchos-arm64-simulator` |
| visionOS | 1.0 | `xros-arm64` |
| visionOS Simulator | 1.0 | `xros-arm64-simulator` |

**watchOS:** the device library holds two architectures with different minimums.
- `arm64_32` starts at watchOS 9.0. Every watch on watchOS 9–25 runs this code, and on watchOS 26 the Series 4–8, SE 1–2 and Ultra 1 still do.
- `arm64` starts at watchOS 26.0, because rustc raises `aarch64-apple-watchos` to its own minimum, the first release with arm64 watch apps, whatever deployment target is asked for. Series 9 and later and Ultra 2 run this code on watchOS 26 and later.

So an app can keep a watchOS deployment target as low as 9: older releases use the `arm64_32` code. The watchOS Simulator library starts at 9.0.
