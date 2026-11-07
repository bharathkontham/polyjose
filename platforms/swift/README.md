# Swift (iOS)

The Swift binding of polyjose. iOS is the main target; it also builds for iPadOS, macOS, tvOS, watchOS and visionOS.

Swift Package:
- `scripts/build-xcframework.sh` builds `build/PolyjoseFFI.xcframework` (gitignored), a static XCFramework with 9 libraries: iOS, iOS Simulator (arm64 + x86_64), macOS (arm64 + x86_64), tvOS, tvOS Simulator, visionOS, visionOS Simulator, watchOS (arm64 + arm64_32) and watchOS Simulator (ADR 0032).
  - Every Rust target is tier 2 on the stable toolchain of `rust-toolchain.toml` (the aarch64 tvOS, visionOS and watchOS targets since Rust 1.95), except `arm64_32-apple-watchos` (Apple Watch Series 4–8, SE 1–2, Ultra 1). That one is tier 3 and is built with the nightly pinned in `nightly-toolchain` and `-Zbuild-std`. Install it with `rustup toolchain install "$(cat platforms/swift/nightly-toolchain)" --profile minimal --component rust-src`.
  - Without that nightly the script makes a development build: the watchOS library is arm64 only, `PolyjoseFFI.xcframework/polyjose-build.txt` says `arm64_32: missing`, and the build must not be released. `--release` fails instead.
  - Deployment minimums: iOS 16, macOS 13, tvOS 16, watchOS 9, visionOS 1 (the arm64 watchOS library starts at watchOS 26, the first release for arm64 watches).
  - The libraries ship without debug info. The script strips every archive with `xcrun strip -S` before it assembles the XCFramework, because the release profile's `strip` does not apply to static libraries and the debug info would triple the download. Symbols are kept, so linking is unaffected, and polyjose frames in your app's crash reports show function names but not file and line.
- `uniffi-bindgen generate --language swift` writes the Swift sources (the build leaves them in `build/generated/`)
- Tests: XCTest on the macOS host (`swift test`) and on the iOS Simulator, running the conformance vectors. The tvOS, watchOS and visionOS libraries are built but not separately tested, because the Swift code is the same on every Apple platform.
- Publishing: a `Package.swift` at the repo root with a `binaryTarget` (URL + checksum) pointing at the XCFramework zip on the GitHub Release
