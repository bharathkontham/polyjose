import Foundation
import XCTest

/// The runner's checker of `conformance/schema.json` (conformance/README.md "Rules for every
/// runner": a misspelled member anywhere fails the vector).
final class SchemaCheckTests: XCTestCase {
    private func schema() throws -> SchemaChecker {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "schema", withExtension: "json"))
        return try SchemaChecker(schema: JSONValue.parse(try Data(contentsOf: url)))
    }

    private let valid = #"""
        {"source":"RFC 4648 §10","description":"d","operation":"b64url.encode",
         "input":{"bytes_hex":"666f"},"expect":{"ok":true,"b64u":"Zm8"}}
        """#

    func testAcceptsAValidVector() throws {
        XCTAssertNil(try schema().violation(JSONValue.parse(valid)))
    }

    func testRefusesUnknownMembersAndWrongTypes() throws {
        let checker = try schema()
        let cases = [
            valid.replacingOccurrences(of: #""bytes_hex""#, with: #""byte_hex""#),  // misspelled
            valid.replacingOccurrences(of: #""666f""#, with: #""66f""#),  // pattern
            valid.replacingOccurrences(of: #""b64url.encode""#, with: #""b64url.nope""#),  // enum
            valid.replacingOccurrences(of: #","description":"d""#, with: ""),  // required
            valid.replacingOccurrences(of: #""ok":true"#, with: #""ok":1"#),  // type
        ]
        for text in cases {
            XCTAssertNotNil(try checker.violation(JSONValue.parse(text)), text)
        }
    }

    /// A keyword the checker does not implement throws instead of being ignored.
    func testUnsupportedKeywordThrows() throws {
        let checker = try SchemaChecker(schema: JSONValue.parse(#"{"type":"object","maxLength":3}"#))
        XCTAssertThrowsError(try checker.violation(JSONValue.parse("{}")))
    }
}
