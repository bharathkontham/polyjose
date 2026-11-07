import Foundation
import Polyjose
import XCTest

/// The binding's security contract on Swift (ADR 0030 §5, §7; ADR 0005; RFC 8725).
final class SecurityTests: XCTestCase {
    /// The marker in the secret members of the keys below: canonical base64url (30 octets), so it
    /// is a valid `k`, and a distinctive text to search for.
    private static let marker = "UE9MWUpPU0VNQVJLRVJzZWNyZXRrZXltYXRlcmlh"
    private static let octKey = #"{"kty":"oct","k":"\#(marker)"}"#
    /// A P-256 key whose `d` is the marker: a private scalar that does not match the public point.
    private static let ecKey =
        #"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","d":"\#(marker)"}"#

    /// Every failing call's error, for the marker test.
    private func failures() -> [Error] {
        var errors: [Error] = []
        func record(_ call: () throws -> Any) {
            do { _ = try call() } catch { errors.append(error) }
        }
        let verify = JwsVerifyOptions(allowedAlgs: ["HS256"])
        let decrypt = JweDecryptOptions(allowedAlgs: ["A256KW"], allowedEnc: ["A256GCM"])
        let jwt = JwtVerifyOptions(allowedAlgs: ["HS256"], now: 1_300_819_380)
        record { try jwsVerifyCompact(token: "eyJhbGciOiJIUzI1NiJ9.e30.AAAA", key: Self.octKey, options: verify) }
        record { try jwsVerifyCompact(token: "not-a-token", key: Self.octKey, options: verify) }
        record { try jwsVerifyCompact(token: "eyJhbGciOiJIUzI1NiJ9.e30.AAAA", key: Self.ecKey, options: verify) }
        record { try jwsSignCompact(payload: Data(), key: Self.octKey, options: JwsSignOptions(protectedHeader: #"{"alg":"ES256"}"#)) }
        record { try jwsSignCompact(payload: Data(), key: Self.ecKey, options: JwsSignOptions(protectedHeader: #"{"alg":"ES256"}"#)) }
        record { try jweDecryptCompact(token: "a.b.c.d.e", key: Self.octKey, options: decrypt) }
        record { try jwtVerify(token: "eyJhbGciOiJIUzI1NiJ9.e30.AAAA", key: Self.octKey, options: jwt) }
        record { try jwkToPem(jwk: Self.octKey, format: "pkcs8") }
        record { try jwkToDer(jwk: Self.ecKey, format: "sec1") }
        record { try jwkThumbprint(jwk: Self.octKey, hash: "SHA-1") }
        record { try jwksSelect(jwks: #"{"keys":[\#(Self.octKey),\#(Self.octKey)]}"#, selector: JwkSelector()) }
        return errors
    }

    /// ADR 0030 §5 marker test: key material never appears in an error's message or string form.
    func testErrorsNeverContainKeyMaterial() throws {
        let errors = failures()
        XCTAssertGreaterThanOrEqual(errors.count, 10, "too few calls failed; the marker test checks nothing")
        for error in errors {
            XCTAssertTrue(error is PolyjoseError, "not a PolyjoseError: \(type(of: error))")
            for form in [String(describing: error), String(reflecting: error), error.localizedDescription] {
                XCTAssertFalse(form.contains(Self.marker), "the marker leaked into an error: \(form)")
                XCTAssertFalse(form.contains("POLYJOSEMARKER"), "the decoded marker leaked into an error: \(form)")
            }
            if let error = error as? PolyjoseError {
                XCTAssertFalse(error.description.contains(Self.marker))
            }
        }
    }

    /// ADR 0030 §5, ADR 0034 §8: `errorCodes()` equals the inventory's codes, in order
    /// (bindings/api-inventory.txt, itself checked against `polyjose::Error::CODES`).
    func testErrorCodesEqualTheInventory() throws {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "api-inventory", withExtension: "txt"))
        let inventory = try String(contentsOf: url, encoding: .utf8)
            .split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { $0.hasPrefix("code ") }
            .map { String($0.dropFirst("code ".count)) }
        XCTAssertFalse(inventory.isEmpty)
        XCTAssertEqual(errorCodes(), inventory)
    }

    /// The Swift case name of each error, by an exhaustive switch: a new code fails to compile here
    /// until it is added (and to ``allErrors``).
    private func caseName(_ error: PolyjoseError) -> String {
        switch error {
        case .InvalidBase64: return "InvalidBase64"
        case .InvalidJson: return "InvalidJson"
        case .InvalidHeader: return "InvalidHeader"
        case .UnsupportedAlgorithm: return "UnsupportedAlgorithm"
        case .AlgorithmNotAllowed: return "AlgorithmNotAllowed"
        case .InvalidKey: return "InvalidKey"
        case .KeyAlgorithmMismatch: return "KeyAlgorithmMismatch"
        case .InvalidSignature: return "InvalidSignature"
        case .DecryptionFailed: return "DecryptionFailed"
        case .UnknownCritical: return "UnknownCritical"
        case .TokenExpired: return "TokenExpired"
        case .TokenNotYetValid: return "TokenNotYetValid"
        case .InvalidClaim: return "InvalidClaim"
        case .RandomnessUnavailable: return "RandomnessUnavailable"
        case .InvalidFormat: return "InvalidFormat"
        case .NoMatchingKey: return "NoMatchingKey"
        case .MultipleMatchingKeys: return "MultipleMatchingKeys"
        }
    }

    private let allErrors: [PolyjoseError] = [
        .InvalidBase64(detail: ""), .InvalidJson(detail: ""), .InvalidHeader(detail: ""),
        .UnsupportedAlgorithm(detail: ""), .AlgorithmNotAllowed(detail: ""), .InvalidKey(detail: ""),
        .KeyAlgorithmMismatch(detail: ""), .InvalidSignature(detail: ""), .DecryptionFailed(detail: ""),
        .UnknownCritical(detail: ""), .TokenExpired(detail: ""), .TokenNotYetValid(detail: ""),
        .InvalidClaim(detail: ""), .RandomnessUnavailable(detail: ""), .InvalidFormat(detail: ""),
        .NoMatchingKey(detail: ""), .MultipleMatchingKeys(detail: ""),
    ]

    /// ADR 0030 §5, ADR 0032 §3: every case's exported `code()` is its own name, and the cases are
    /// exactly `errorCodes()`.
    func testEveryCaseCodeIsItsName() {
        for error in allErrors {
            XCTAssertEqual(error.code(), caseName(error))
        }
        XCTAssertEqual(allErrors.map { $0.code() }, errorCodes())
    }

    /// ADR 0005: keys and encryptions draw fresh OS randomness on every call.
    func testRandomnessDiffersBetweenCalls() throws {
        func member(_ jwk: String, _ name: String) throws -> String? { try JSONValue.parse(jwk)[name]?.stringValue }
        let oct = (try jwkGenerateOct(lenBytes: 32), try jwkGenerateOct(lenBytes: 32))
        XCTAssertNotEqual(try member(oct.0, "k"), try member(oct.1, "k"))
        let ec = (try jwkGenerateEc(crv: "P-256"), try jwkGenerateEc(crv: "P-256"))
        XCTAssertNotEqual(try member(ec.0, "d"), try member(ec.1, "d"))
        let okp = (try jwkGenerateOkp(crv: "Ed25519"), try jwkGenerateOkp(crv: "Ed25519"))
        XCTAssertNotEqual(try member(okp.0, "d"), try member(okp.1, "d"))
        let options = JweEncryptOptions(enc: "A256GCM", recipients: [JweRecipient(alg: "dir", key: try jwkGenerateOct(lenBytes: 32))])
        let plaintext = Data("polyjose".utf8)
        XCTAssertNotEqual(
            try jweEncryptCompact(plaintext: plaintext, options: options),
            try jweEncryptCompact(plaintext: plaintext, options: options))
    }
}
