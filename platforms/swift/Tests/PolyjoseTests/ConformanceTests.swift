import Foundation
import Polyjose
import XCTest

/// Runs every conformance vector through the Swift API (ADR 0008 layer 4, ADR 0034) and writes the
/// ADR 0034 §2 results document:
/// - to the file named by `POLYJOSE_CONFORMANCE_OUT`, when set (the macOS run:
///   platforms/swift/test.sh sets it to `target/conformance/swift-macos.json`);
/// - and to standard output as one line, prefixed `POLYJOSE-CONFORMANCE-RESULTS `, which the
///   simulator driver extracts (feature 0009 T03), since a simulator has no checkout to write to.
///
/// The vectors are the test bundle's copy (`Bundle.module`, Resources/vectors), and
/// `vectors_digest` is computed over those bundled bytes, the very bytes parsed (ADR 0060 §2), so
/// parity proves the bundle matches the checkout. An empty corpus fails and writes nothing (ADR
/// 0060 §3).
final class ConformanceTests: XCTestCase {
    /// The line prefix of the printed results document.
    static let marker = "POLYJOSE-CONFORMANCE-RESULTS "

    /// The ADR 0034 §2 runner name of this platform (ADR 0046 §4: macOS and the iOS Simulator;
    /// `swift-tvos-sim` only if that run is ever brought back). Nil elsewhere: no results document.
    static var runnerName: String? {
        #if os(macOS)
            return "swift-macos"
        #elseif os(iOS) && targetEnvironment(simulator)
            return "swift-ios-sim"
        #elseif os(tvOS) && targetEnvironment(simulator)
            return "swift-tvos-sim"
        #else
            return nil
        #endif
    }

    func testEveryConformanceVector() throws {
        let vectors = try XCTUnwrap(
            Bundle.module.url(forResource: "vectors", withExtension: nil), "the test bundle has no vectors resource")
        let schemaURL = try XCTUnwrap(
            Bundle.module.url(forResource: "schema", withExtension: "json"), "the test bundle has no schema.json")
        let corpus = try VectorCorpus.load(from: vectors)
        guard !corpus.files.isEmpty else {
            return XCTFail("no vector file (*.json) was read under \(vectors.path); nothing is written (ADR 0060 §3)")
        }
        let digest = try VectorsDigest.digest(of: corpus.files)
        let runner = ConformanceRunner(schema: try SchemaChecker(schema: JSONValue.parse(try Data(contentsOf: schemaURL))))

        let results = (corpus.files.map(runner.run)
            + corpus.unreadable.map { ConformanceRunner.Result.fail(id: $0.id, reason: $0.reason) })
            .sorted { Array($0.id.utf8).lexicographicallyPrecedes(Array($1.id.utf8)) }

        if let name = Self.runnerName {
            let document = Self.document(runner: name, digest: digest, results: results)
            // The document must be a JSON text JSONSerialization reads back, one entry per file.
            let reread = try JSONValue.parse(document)
            XCTAssertEqual(reread["results"]?.arrayValue?.count, corpus.files.count + corpus.unreadable.count)
            if let out = ProcessInfo.processInfo.environment["POLYJOSE_CONFORMANCE_OUT"], !out.isEmpty {
                let url = URL(fileURLWithPath: out)
                try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
                try Data((document + "\n").utf8).write(to: url)
            }
            print(Self.marker + document)
        } else {
            print("conformance: no ADR 0034 runner name for this platform; no results document")
        }

        let failed = results.filter { $0.status == .fail }
        let skipped = results.filter { $0.status == .skipped }.count
        print(
            "conformance (\(Self.runnerName ?? "swift")): \(results.count - failed.count - skipped) passed, "
                + "\(failed.count) failed, \(skipped) skipped of \(results.count); vectors_digest \(digest)")
        for failure in failed { XCTFail("FAIL \(failure.reason ?? failure.id)") }
    }

    /// Every expected error code of a vector is one of the binding's `errorCodes()` (ADR 0030 §5).
    func testEveryExpectedErrorCodeIsABindingCode() throws {
        let vectors = try XCTUnwrap(Bundle.module.url(forResource: "vectors", withExtension: nil))
        let codes = Set(errorCodes())
        var checked = 0
        for file in try VectorCorpus.load(from: vectors).files {
            guard let value = try? JSONValue.parse(file.bytes),
                case .bool(false) = value["expect"]?["ok"] ?? .null,
                let code = value["expect"]?["error"]?.stringValue
            else { continue }
            XCTAssertTrue(codes.contains(code), "\(file.path): expected code \(code) is not in errorCodes()")
            checked += 1
        }
        XCTAssertGreaterThan(checked, 0)
    }

    /// The ADR 0034 §2 / ADR 0060 §1 results document as one line of JSON
    /// (conformance/schema/results.schema.json).
    static func document(runner: String, digest: String, results: [ConformanceRunner.Result]) -> String {
        JSONValue.object([
            ("runner", .string(runner)),
            ("polyjose", .string(Polyjose.version())),
            ("vectors_digest", .string(digest)),
            ("features", .array(ConformanceRunner.bindingFeatures.map(JSONValue.string))),
            ("error_codes", .array(errorCodes().map(JSONValue.string))),
            ("results", .array(results.map(\.json))),
        ]).description
    }
}
