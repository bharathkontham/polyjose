import Foundation
import Polyjose
import XCTest

/// ADR 0065 (superseding the printing residual of ADR 0030 §3, §7): a record's secret fields never
/// appear when the record is printed. Each secret field shows its type and length only,
/// `<redacted, N chars>` (String) or `<redacted, N bytes>` (Data), on every printing path:
/// `String(describing:)`, `String(reflecting:)`, `print`, `debugPrint` and `dump`. The secret
/// fields are the ones ADR 0030 §7 lists as secret-bearing: private JWKs and PBES2 passwords
/// (`JwsSigner.key`, `JweRecipient.key`), JWS payloads (`JwsVerified.payload`,
/// `JwsVerifyOptions.detachedPayload`, ADR 0049 §4), JWE plaintext (`JweDecrypted.plaintext`) and
/// `aad` (`JweDecrypted.aad`, `JweEncryptOptions.aad`, ADR 0050 §4). JWT claims are not redacted
/// (ADR 0058 decision 2, ADR 0065 §3).
final class RedactionTests: XCTestCase {
    /// The marker in every secret field: 12 characters, 12 bytes as UTF-8.
    private static let marker = "MARKERSECRET"
    private static let markerBytes = Data(marker.utf8)
    /// An `oct` JWK (RFC 7517 §4, RFC 7518 §6.4) whose `k` holds the marker, as a String secret.
    private static let markerKey = #"{"kty":"oct","k":"\#(marker)"}"#
    private static let keyChars = "<redacted, \(markerKey.count) chars>"
    private static let dataBytes = "<redacted, \(markerBytes.count) bytes>"

    /// The text of each of the five printing paths for one value, and of string interpolation,
    /// the form a log message built with `"\(value)"` shows.
    private func printed<T>(_ value: T) -> [(path: String, text: String)] {
        var print = "", debugPrint = "", dump = ""
        Swift.print(value, to: &print)
        Swift.debugPrint(value, to: &debugPrint)
        Swift.dump(value, to: &dump)
        return [
            ("String(describing:)", String(describing: value)),
            ("String(reflecting:)", String(reflecting: value)),
            ("print(to:)", print),
            ("debugPrint(to:)", debugPrint),
            ("dump(to:)", dump),
            ("interpolation", "\(value)"),
        ]
    }

    /// The unlabeled decimal lines of `dump`'s output (`- 77`), in order: how `dump` prints each
    /// byte of a `Data` through Foundation's Mirror.
    private func dumpedBytes(_ text: String) -> [UInt8] {
        text.split(separator: "\n").compactMap { line in
            let item = line.trimmingCharacters(in: .whitespaces)
            guard item.hasPrefix("- ") else { return nil }
            return UInt8(item.dropFirst(2))
        }
    }

    /// No printing path of `value` shows the marker, as text or as `dump`'s byte lines, and each
    /// path shows every expected redacted form.
    private func assertRedacted<T>(
        _ value: T, showing forms: [String], file: StaticString = #filePath, line: UInt = #line
    ) {
        for (path, text) in printed(value) {
            XCTAssertFalse(text.contains(Self.marker), "\(path) leaked the marker: \(text)", file: file, line: line)
            let bytes = dumpedBytes(text)
            XCTAssertTrue(bytes.isEmpty, "\(path) printed bytes of a Data: \(bytes) in \(text)", file: file, line: line)
            for form in forms {
                XCTAssertTrue(text.contains(form), "\(path) does not show \(form): \(text)", file: file, line: line)
            }
        }
    }

    private static let signer = JwsSigner(key: markerKey, protectedHeader: #"{"alg":"HS256"}"#)
    private static let recipient = JweRecipient(alg: "dir", key: markerKey)

    func testJwsSignerKeyIsRedacted() {
        assertRedacted(Self.signer, showing: ["key: \(Self.keyChars)"])
    }

    func testJweRecipientKeyIsRedacted() {
        assertRedacted(Self.recipient, showing: ["key: \(Self.keyChars)"])
    }

    func testJwsVerifiedPayloadIsRedacted() {
        let verified = JwsVerified(alg: "HS256", payload: Self.markerBytes, signatureIndex: 0)
        assertRedacted(verified, showing: ["payload: \(Self.dataBytes)"])
    }

    func testJweDecryptedPlaintextAndAadAreRedacted() {
        let decrypted = JweDecrypted(
            plaintext: Self.markerBytes, header: #"{"alg":"dir","enc":"A256GCM"}"#, aad: Self.markerBytes,
            recipientIndex: 0)
        assertRedacted(decrypted, showing: ["plaintext: \(Self.dataBytes)", "aad: \(Self.dataBytes)"])
    }

    /// The nested `JweRecipient` of a `JweEncryptOptions` is redacted too, on every path.
    func testJweEncryptOptionsAadAndNestedRecipientAreRedacted() {
        let options = JweEncryptOptions(enc: "A256GCM", recipients: [Self.recipient, Self.recipient], aad: Self.markerBytes)
        assertRedacted(options, showing: ["aad: \(Self.dataBytes)", "key: \(Self.keyChars)"])
    }

    func testJwsVerifyOptionsDetachedPayloadIsRedacted() {
        let options = JwsVerifyOptions(allowedAlgs: ["HS256"], detachedPayload: Self.markerBytes)
        assertRedacted(options, showing: ["detachedPayload: \(Self.dataBytes)"])
    }

    /// An absent secret stays `nil` on every path.
    func testAbsentSecretsPrintNil() {
        let decrypted = JweDecrypted(plaintext: Data(), header: "{}", recipientIndex: 0)
        assertRedacted(decrypted, showing: ["plaintext: <redacted, 0 bytes>", "aad: nil"])
        assertRedacted(JweEncryptOptions(enc: "A256GCM", recipients: []), showing: ["aad: nil"])
        assertRedacted(JwsVerifyOptions(allowedAlgs: ["HS256"]), showing: ["detachedPayload: nil"])
    }

    /// The real results of a verify and a decrypt, holding the marker as payload, plaintext and
    /// aad, are redacted like the records built by hand.
    func testOperationResultsAreRedacted() throws {
        let key = try jwkGenerateOct(lenBytes: 32)
        let token = try jwsSignCompact(
            payload: Self.markerBytes, key: key, options: JwsSignOptions(protectedHeader: #"{"alg":"HS256"}"#))
        let verified = try jwsVerifyCompact(token: token, key: key, options: JwsVerifyOptions(allowedAlgs: ["HS256"]))
        XCTAssertEqual(verified.payload, Self.markerBytes)
        assertRedacted(verified, showing: ["payload: \(Self.dataBytes)"])

        let jwe = try jweEncryptJson(
            plaintext: Self.markerBytes,
            options: JweEncryptOptions(enc: "A256GCM", recipients: [JweRecipient(alg: "dir", key: key)], aad: Self.markerBytes),
            form: "flattened")
        let decrypted = try jweDecryptJson(
            jwe: jwe, key: key, options: JweDecryptOptions(allowedAlgs: ["dir"], allowedEnc: ["A256GCM"]))
        XCTAssertEqual(decrypted.plaintext, Self.markerBytes)
        XCTAssertEqual(decrypted.aad, Self.markerBytes)
        assertRedacted(decrypted, showing: ["plaintext: \(Self.dataBytes)", "aad: \(Self.dataBytes)"])
    }

    /// Only the secret fields change: the others print as the generated structs print them by
    /// default (the debug form of each value), with the type name, qualified by the module in the
    /// debug forms.
    func testNonSecretFieldsPrintAsBefore() {
        XCTAssertEqual(
            String(describing: Self.signer),
            #"JwsSigner(key: \#(Self.keyChars), protectedHeader: Optional("{\"alg\":\"HS256\"}"), protectedB64u: nil, unprotectedHeader: nil)"#)
        XCTAssertEqual(
            String(reflecting: Self.signer),
            #"Polyjose.JwsSigner(key: \#(Self.keyChars), protectedHeader: Optional("{\"alg\":\"HS256\"}"), protectedB64u: nil, unprotectedHeader: nil)"#)
        let recipient = JweRecipient(alg: "ECDH-ES", key: Self.markerKey, apu: Data("Alice".utf8), p2c: 1000)
        XCTAssertEqual(
            String(describing: recipient),
            #"JweRecipient(alg: "ECDH-ES", key: \#(Self.keyChars), header: nil, apu: Optional(5 bytes), apv: nil, p2c: Optional(1000), p2sLen: nil)"#)
        let options = JweEncryptOptions(enc: "A256GCM", recipients: [Self.recipient], compress: false)
        XCTAssertEqual(
            String(describing: options),
            #"JweEncryptOptions(enc: "A256GCM", recipients: [Polyjose.JweRecipient(alg: "dir", key: \#(Self.keyChars), header: nil, apu: nil, apv: nil, p2c: nil, p2sLen: nil)], protectedHeader: nil, sharedUnprotectedHeader: nil, aad: nil, compress: false)"#)
        let verified = JwsVerified(alg: "HS256", payload: Self.markerBytes, signatureIndex: 3)
        XCTAssertEqual(
            String(reflecting: verified),
            #"Polyjose.JwsVerified(alg: "HS256", payload: \#(Self.dataBytes), protectedHeader: nil, unprotectedHeader: nil, signatureIndex: 3)"#)
    }

    /// The Mirror keeps every field, in declaration order, with the secret ones replaced by their
    /// redacted form and no byte children (ADR 0065 §2), so `dump` shows each field on one line.
    func testMirrorHasEveryFieldAndNoSecretBytes() {
        let decrypted = JweDecrypted(plaintext: Self.markerBytes, header: "{}", aad: Self.markerBytes, recipientIndex: 2)
        let mirror = Mirror(reflecting: decrypted)
        XCTAssertEqual(mirror.displayStyle, .struct)
        XCTAssertEqual(
            mirror.children.map { $0.label ?? "" },
            ["plaintext", "header", "protectedHeader", "sharedUnprotectedHeader", "recipientHeader", "aad", "recipientIndex"])
        for child in mirror.children where child.label == "plaintext" || child.label == "aad" {
            XCTAssertFalse(child.value is Data, "\(child.label ?? "") is a Data child")
            XCTAssertEqual(String(describing: child.value), Self.dataBytes)
            XCTAssertTrue(Mirror(reflecting: child.value).children.isEmpty)
        }
        var dumped = ""
        dump(decrypted, to: &dumped)
        XCTAssertTrue(dumped.contains("- plaintext: \(Self.dataBytes)\n"), dumped)
        XCTAssertTrue(dumped.contains("- aad: \(Self.dataBytes)\n"), dumped)
        XCTAssertTrue(dumped.contains("- recipientIndex: 2\n"), dumped)
    }

    /// The README's wipe of a returned `Data` (ADR 0030 §7.4) compiles and zeroes the field.
    func testReadmeWipeZeroesTheField() {
        var verified = JwsVerified(alg: "HS256", payload: Data(Self.markerBytes), signatureIndex: 0)
        verified.payload.resetBytes(in: verified.payload.indices)
        XCTAssertEqual(verified.payload, Data(count: Self.markerBytes.count))
    }

    /// JWT claims are not secret-bearing (ADR 0058 decision 2), so `JwtVerified` prints them.
    func testJwtClaimsAreNotRedacted() {
        let verified = JwtVerified(claims: #"{"sub":"\#(Self.marker)"}"#, header: "{}", alg: "HS256")
        XCTAssertTrue(String(describing: verified).contains(Self.marker))
    }
}
