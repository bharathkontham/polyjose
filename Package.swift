// swift-tools-version: 6.0
// The Swift (iOS) binding of polyjose (ADR 0032 §4, ADR 0046). iOS is the main target; the
// package also builds for iPadOS, macOS and watchOS.
//
// - `PolyjoseFFI`: the static XCFramework of polyjose-ffi (ADR 0032 §1-§2), built by
//   platforms/swift/scripts/build-xcframework.sh.
// - `Polyjose`: the UniFFI-generated Swift API, committed as platforms/swift/Sources/Polyjose/
//   Polyjose.swift (ADR 0032 §4; platforms/swift/scripts/check-generated.sh keeps it fresh).
// - `PolyjoseTests`: XCTest, including the conformance runner over conformance/vectors (ADR 0034).
//
// Binary target source (ADR 0032 §4):
// - With POLYJOSE_LOCAL_XCFRAMEWORK=1 in the environment, the locally built
//   platforms/swift/build/PolyjoseFFI.xcframework is used:
//     platforms/swift/scripts/build-xcframework.sh
//     POLYJOSE_LOCAL_XCFRAMEWORK=1 swift test
// - Otherwise the XCFramework zip of the GitHub Release. Until the first release this is a
//   PLACEHOLDER: the asset does not exist yet and the checksum is all zeros, so resolving fails
//   and the package must be built locally as above. The release agent writes the real url and
//   checksum in the release PR (ADR 0032 §6; Gate 3 publishes).
import PackageDescription

let useLocalXCFramework = Context.environment["POLYJOSE_LOCAL_XCFRAMEWORK"] == "1"

let ffiTarget: Target =
    useLocalXCFramework
    ? .binaryTarget(
        name: "PolyjoseFFI",
        path: "platforms/swift/build/PolyjoseFFI.xcframework"
    )
    : .binaryTarget(
        name: "PolyjoseFFI",
        // PLACEHOLDER until the first release (see the header).
        url: "https://github.com/bharathkontham/polyjose/releases/download/v0.1.1/PolyjoseFFI.xcframework.zip",
        checksum: "0000000000000000000000000000000000000000000000000000000000000000"
    )

let package = Package(
    name: "polyjose",
    // ADR 0032 §1: the deployment targets the XCFramework is built for.
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
        .watchOS(.v9),
    ],
    products: [
        .library(name: "Polyjose", targets: ["Polyjose"])
    ],
    targets: [
        ffiTarget,
        .target(
            name: "Polyjose",
            dependencies: ["PolyjoseFFI"],
            path: "platforms/swift/Sources/Polyjose"
        ),
        .testTarget(
            name: "PolyjoseTests",
            dependencies: ["Polyjose"],
            path: "platforms/swift/Tests/PolyjoseTests",
            resources: [
                .copy("Resources/vectors"),
                .copy("Resources/schema.json"),
                .copy("Resources/api-inventory.txt"),
            ]
        ),
    ],
    swiftLanguageModes: [.v6]
)
