import Foundation
import XCTest

/// The runner's strict JSON scanner and value model (conformance/README.md "Rules for every
/// runner"; RFC 8259, RFC 7493).
final class StrictJSONTests: XCTestCase {
    private func scan(_ text: String) throws -> JSONText {
        let bytes = Array(text.utf8)
        return JSONText(bytes: bytes, root: try JSONScanner.scan(bytes))
    }

    /// RFC 7493 §2.3: duplicate member names are refused, also when spelled with escapes.
    func testRefusesDuplicateMembers() {
        XCTAssertThrowsError(try scan(#"{"a":1,"a":2}"#))
        XCTAssertThrowsError(try scan(#"{"x":{"ab":1,"ab":2}}"#))
        XCTAssertNoThrow(try scan(#"{"a":{"a":1},"b":[{"a":1},{"a":2}]}"#))
    }

    /// RFC 8259 grammar: trailing data, bad numbers, control characters and lone surrogates fail.
    func testRefusesInvalidText() {
        for bad in [#"{"a":1} x"#, #"{"a":01}"#, #"{"a":1.}"#, "{\"a\":\"\u{01}\"}", #"{"a":"\ud800"}"#, #"{"a":tru}"#, ""] {
            XCTAssertThrowsError(try scan(bad), bad)
        }
        XCTAssertThrowsError(try JSONScanner.scan([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d]), "not UTF-8")
        XCTAssertNoThrow(try scan(#"{"a":"😀","b":-0.5e+3,"c":[true,false,null]}"#))
    }

    /// Inputs are handed over as their own compact text, in file order (ADR 0027 §1, note 4).
    func testTextAtKeepsOrderAndRemovesWhitespace() throws {
        let text = try scan("{ \"input\": { \"claims\": { \"z\" : 1,\n \"a\": \"x y\\\" \" } , \"k\": [ 1 , { \"q\" : 2 } ] } }")
        XCTAssertEqual(text.text(["input", "claims"]), #"{"z":1,"a":"x y\" "}"#)
        XCTAssertEqual(text.text(["input", "k", 1]), #"{"q":2}"#)
        XCTAssertNil(text.text(["input", "missing"]))
        XCTAssertNil(text.text(["input", "k", 5]))
    }

    /// Values compare as JSON values: member order ignored, numbers as doubles, booleans apart
    /// from numbers, strings code point for code point.
    func testValueEquality() throws {
        let a = try JSONValue.parse(#"{"n":1300819380,"b":true,"s":"é","l":[1,2]}"#)
        let b = try JSONValue.parse(#"{"l":[1,2],"s":"é","b":true,"n":1300819380.0}"#)
        XCTAssertTrue(JSONValue.equal(a, b))
        XCTAssertFalse(JSONValue.equal(try JSONValue.parse("true"), try JSONValue.parse("1")))
        XCTAssertFalse(JSONValue.equal(try JSONValue.parse(#""é""#), try JSONValue.parse(#""é""#)))
        XCTAssertFalse(JSONValue.equal(try JSONValue.parse("[1,2]"), try JSONValue.parse("[2,1]")))
        XCTAssertEqual(a["n"]?.numberValue, 1300819380)
    }

    func testDescriptionIsCompactJSON() throws {
        let value = try JSONValue.parse(#"{"a":[1,2.5,"q\"\n",null,false]}"#)
        XCTAssertTrue(JSONValue.equal(try JSONValue.parse(value.description), value))
        XCTAssertEqual(JSONValue.quote("a\u{01}b"), #""a\u0001b""#)
    }
}
