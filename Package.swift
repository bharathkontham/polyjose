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
// - Otherwise the XCFramework zip attached to the GitHub Release of this version, checked against
//   `checksum` (its SHA-256). Each release PR sets the url to its tag and the checksum to the
//   candidate build's zip, recorded in platforms/swift/release-candidate.json (RELEASING.md step 2,
//   ADR 0032 §6). On an unreleased commit the asset may not exist yet; build locally as above.
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
        // Set by each release PR (see the header).
        url: "https://github.com/bharathkontham/polyjose/releases/download/v0.1.2/PolyjoseFFI.xcframework.zip",
        checksum: "2ed063da7da70ecd106c670270bfe99ed7508df6dadd294c28d9e2b0a6eb13b8"
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
