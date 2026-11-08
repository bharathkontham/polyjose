import Foundation
import Polyjose
import XCTest

/// The package links: the generated Swift calls into the XCFramework's static library.
final class SmokeTests: XCTestCase {
    /// ADR 0030 §4 `version`: the polyjose crate version, a SemVer string.
    func testVersionIsTheCrateVersion() {
        let version = Polyjose.version()
        XCTAssertNotNil(
            version.range(of: #"^[0-9]+\.[0-9]+\.[0-9]+"#, options: .regularExpression),
            "version() is not SemVer: \(version)")
    }

    /// RFC 4648 §10 test vector ("foobar" → "Zm9vYmFy"), without padding (RFC 4648 §5, §3.2).
    func testBase64urlRoundTrip() throws {
        let encoded = base64urlEncode(data: Data("foobar".utf8))
        XCTAssertEqual(encoded, "Zm9vYmFy")
        XCTAssertEqual(try base64urlDecode(text: encoded), Data("foobar".utf8))
    }
}
