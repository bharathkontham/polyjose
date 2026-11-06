# Swift (iOS)

Swift Package:
- Static libraries for iOS, iOS Simulator and macOS (stable Rust), plus tvOS, watchOS and visionOS (tier 3 Rust targets, built with a pinned nightly and `-Zbuild-std`), combined into `PolyjoseFFI.xcframework`
- `uniffi-bindgen generate --language swift` writes the Swift sources
- Tests: XCTest on the macOS host (`swift test`) and on the iOS Simulator, running the conformance vectors. The tvOS, watchOS and visionOS slices are built but not separately tested, because the Swift code is the same on every Apple platform.
- Publishing: a `Package.swift` at the repo root with a `binaryTarget` (URL + checksum) pointing at the XCFramework zip on the GitHub Release
