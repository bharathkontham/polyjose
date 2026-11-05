# Apple platforms (Swift)

Swift Package:
- Static libraries for iOS, iOS Simulator and macOS (stable Rust), plus tvOS, watchOS and visionOS (tier 3 Rust targets, built with a pinned nightly and `-Zbuild-std`), combined into `PolyjoseFFI.xcframework`
- `uniffi-bindgen generate --language swift` writes the Swift sources
- Tests: XCTest on macOS, the iOS Simulator and the tvOS Simulator, running the conformance vectors
- Publishing: a `Package.swift` at the repo root with a `binaryTarget` (URL + checksum) pointing at the XCFramework zip on the GitHub Release
