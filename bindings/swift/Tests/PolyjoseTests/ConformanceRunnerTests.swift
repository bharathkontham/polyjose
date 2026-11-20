import Foundation
import XCTest

/// The runner's own rules (conformance/README.md "Rules for every runner", ADR 0034 §3, ADR 0056):
/// a wrong outcome, a broken file and an unmapped operation fail, and only the feature rule skips.
final class ConformanceRunnerTests: XCTestCase {
    private func runner() throws -> ConformanceRunner {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "schema", withExtension: "json"))
        return ConformanceRunner(schema: try SchemaChecker(schema: JSONValue.parse(try Data(contentsOf: url))))
    }

    private func run(_ text: String) throws -> ConformanceRunner.Result {
        try runner().run(VectorFile(id: "t/x.json#0", path: "t/x.json", bytes: Data(text.utf8)))
    }

    private func vector(_ input: String, _ expect: String, op: String = "b64url.decode", extra: String = "") -> String {
        #"{"source":"test","description":"d","operation":"\#(op)","input":\#(input),"expect":\#(expect)\#(extra)}"#
    }

    func testPassRecordsTheOutcome() throws {
        let ok = try run(vector(#"{"b64u":"Zm8"}"#, #"{"ok":true,"bytes_hex":"666f"}"#))
        XCTAssertEqual(ok.status, .pass)
        XCTAssertTrue(ok.hasActual)
        XCTAssertNil(ok.actualError)
        // RFC 4648 §5 / R1: padding is refused; the expected code is the outcome.
        let refused = try run(vector(#"{"b64u":"Zm8="}"#, #"{"ok":false,"error":"InvalidBase64"}"#))
        XCTAssertEqual(refused.status, .pass)
        XCTAssertEqual(refused.actualError, "InvalidBase64")
    }

    /// A wrong error code or a wrong output fails, and still records what the library did.
    func testWrongOutcomeFailsWithActual() throws {
        let wrongCode = try run(vector(#"{"b64u":"Zm8="}"#, #"{"ok":false,"error":"InvalidJson"}"#))
        XCTAssertEqual(wrongCode.status, .fail)
        XCTAssertEqual(wrongCode.actualError, "InvalidBase64")
        let wrongOutput = try run(vector(#"{"b64u":"Zm8"}"#, #"{"ok":true,"bytes_hex":"6660"}"#))
        XCTAssertEqual(wrongOutput.status, .fail)
        XCTAssertTrue(wrongOutput.hasActual)
        XCTAssertNil(wrongOutput.actualError)
    }

    func testBrokenFilesFailWithoutActual() throws {
        for text in [
            #"{"source":"a","source":"b"}"#,  // duplicate member (RFC 7493 §2.3)
            vector(#"{"b64u":"Zm8","extra":1}"#, #"{"ok":true,"bytes_hex":"666f"}"#),  // schema: unknown member
            "not json",
        ] {
            let result = try run(text)
            XCTAssertEqual(result.status, .fail, text)
            XCTAssertFalse(result.hasActual, text)
        }
    }

    /// ADR 0034 §3, ADR 0056 §2: the only skips, with their reasons; the binding build has neither
    /// feature, so a `features_absent` vector runs.
    func testFeatureSkipReasons() throws {
        let needs = try run(vector(#"{"b64u":"Zm8"}"#, #"{"ok":true,"bytes_hex":"666f"}"#, extra: #","features":["fixed-rng"]"#))
        XCTAssertEqual(needs.status, .skipped)
        XCTAssertEqual(needs.reason, "feature:fixed-rng")
        XCTAssertFalse(needs.hasActual)
        let absent = try run(vector(#"{"b64u":"Zm8"}"#, #"{"ok":true,"bytes_hex":"666f"}"#, extra: #","features_absent":["deflate"]"#))
        XCTAssertEqual(absent.status, .pass)
        let both = try run(
            vector(#"{"b64u":"Zm8"}"#, #"{"ok":true,"bytes_hex":"666f"}"#, extra: #","features":["deflate"],"features_absent":["deflate"]"#))
        XCTAssertEqual(both.status, .fail)
    }

    func testResultEntryShape() throws {
        let result = try run(vector(#"{"b64u":"Zm8="}"#, #"{"ok":false,"error":"InvalidBase64"}"#))
        XCTAssertTrue(
            JSONValue.equal(
                result.json,
                try JSONValue.parse(#"{"id":"t/x.json#0","op":"b64url.decode","status":"pass","actual":{"ok":false,"error":"InvalidBase64"}}"#)))
    }
}
