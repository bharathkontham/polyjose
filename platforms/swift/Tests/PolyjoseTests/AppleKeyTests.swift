import CryptoKit  // SecureEnclave.isAvailable only
import Foundation
import LocalAuthentication
@testable import Polyjose
import Security
import XCTest

/// `AppleKey` (ADR 0072 §1, feature 0025 T03) on macOS (`swift test`) and the iOS Simulator (the
/// package scheme), with non-permanent keys: an unsigned or un-hosted test binary cannot store a
/// Keychain item (-34018, ADR 0072 §6.1). Permanent keys, `open` and `delete` are tested by the
/// hosted test app, platforms/swift/HostedTests.
final class AppleKeyTests: XCTestCase {
    static let marker = "apple-key-marker-5c1e"
    static let payload = Data("hardware-backed keys".utf8)
    static let claims = #"{"iss":"joe","sub":"apple-key"}"#
    static let secureEnclaveSkip = "SecureEnclave.isAvailable is false here, so the Secure Enclave rows are SKIPPED, not run"
    /// Members a public JWK must not have (RFC 7518 §6.2.2, §6.3.2, §6.4).
    static let privateMembers = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]

    func requireSecureEnclave() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, Self.secureEnclaveSkip)
    }

    /// A non-permanent software `SecKey` the test makes itself.
    static func secKey(_ type: CFString, _ bits: Int) throws -> SecKey {
        let attributes: [CFString: Any] = [kSecAttrKeyType: type, kSecAttrKeySizeInBits: bits]
        return try XCTUnwrap(SecKeyCreateRandomKey(attributes as CFDictionary, nil))
    }

    static func key(_ algorithm: String, _ protection: AppleKey.Protection, bits: Int? = nil) throws -> AppleKey {
        try AppleKey.generateEphemeral(algorithm: algorithm, protection: protection, keySizeInBits: bits)
    }

    /// The `PolyjoseError` `call` throws.
    func polyjoseError(_ what: String, _ call: () throws -> Any, file: StaticString = #filePath, line: UInt = #line) -> PolyjoseError? {
        do {
            _ = try call()
            XCTFail("\(what): the call succeeded", file: file, line: line)
        } catch let error as PolyjoseError {
            return error
        } catch {
            XCTFail("\(what): not a PolyjoseError: \(error)", file: file, line: line)
        }
        return nil
    }

    func expectCode(_ what: String, _ code: String, _ call: () throws -> Any, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(polyjoseError(what, call, file: file, line: line)?.code(), code, what, file: file, line: line)
    }

    /// Every printed form of `value`.
    static func printed(_ value: Any) -> [String] {
        var dumped = ""
        dump(value, to: &dumped)
        var forms = ["\(value)", String(describing: value), String(reflecting: value), dumped]
        if let error = value as? Error { forms.append(error.localizedDescription) }
        return forms
    }

    /// No marker, platform error text or key reference in any printed form of `value`.
    func assertClean(_ value: Any, _ what: String, file: StaticString = #filePath, line: UInt = #line) {
        for text in Self.printed(value) {
            for needle in [Self.marker, "SecKeyRef", "NSOSStatusErrorDomain", "Domain=", "keychain:"] {
                XCTAssertFalse(text.contains(needle), "\(what): \(needle) in \(text)", file: file, line: line)
            }
        }
    }

    // MARK: - The matrix of ADR 0072 §1 (RFC 7515 §5.1, RFC 7516 §5.2, RFC 7518 §3, §4.3, §4.6)

    /// `jwsSignCompactWithPlatformKey` and `jwtSignWithPlatformKey`, verified with `publicJwk`.
    func signs(_ key: AppleKey, _ alg: String, file: StaticString = #filePath, line: UInt = #line) throws {
        let jwk = try key.publicJwk()
        let token = try jwsSignCompactWithPlatformKey(payload: Self.payload, key: key, options: JwsSignOptions(protectedHeader: #"{"alg":"\#(alg)"}"#))
        let verified = try jwsVerifyCompact(token: token, key: jwk, options: JwsVerifyOptions(allowedAlgs: [alg]))
        XCTAssertEqual(verified.payload, Self.payload, alg, file: file, line: line)
        let jwt = try jwtSignWithPlatformKey(claims: Self.claims, key: key, options: JwtSignOptions(alg: alg))
        let options = JwtVerifyOptions(allowedAlgs: [alg], now: 1_700_000_000, allowMissingExp: true)
        XCTAssertEqual(try jwtVerify(token: jwt, key: jwk, options: options).claims, Self.claims, alg, file: file, line: line)
    }

    /// `jweEncryptCompact` to `publicJwk`, then `jweDecryptCompactWithPlatformKey`.
    func decrypts(_ key: AppleKey, _ alg: String, file: StaticString = #filePath, line: UInt = #line) throws {
        let options = JweEncryptOptions(enc: "A256GCM", recipients: [JweRecipient(alg: alg, key: try key.publicJwk())])
        let token = try jweEncryptCompact(plaintext: Self.payload, options: options)
        let decrypted = try jweDecryptCompactWithPlatformKey(token: token, key: key, options: JweDecryptOptions(allowedAlgs: [alg], allowedEnc: ["A256GCM"]))
        XCTAssertEqual(decrypted.plaintext, Self.payload, alg, file: file, line: line)
    }

    /// `publicJwk` passes `jwkParse`, holds no private member, and has the expected type and curve.
    func checkPublicJwk(_ key: AppleKey, kty: String, crv: String? = nil, file: StaticString = #filePath, line: UInt = #line) throws {
        let jwk = try key.publicJwk()
        let parsed = try jwkParse(jwk: jwk)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(parsed.utf8)) as? [String: Any], file: file, line: line)
        XCTAssertEqual(object["kty"] as? String, kty, file: file, line: line)
        if let crv { XCTAssertEqual(object["crv"] as? String, crv, file: file, line: line) }
        for member in Self.privateMembers {
            XCTAssertNil(object[member], "private member \(member) in the public JWK", file: file, line: line)
        }
    }

    func testSecureEnclaveEs256Signs() throws {
        try requireSecureEnclave()
        let key = try Self.key("ES256", .secureEnclave)
        XCTAssertEqual(key.protection, .secureEnclave)
        XCTAssertEqual(try key.algorithms(), ["ES256"])
        try checkPublicJwk(key, kty: "EC", crv: "P-256")
        try signs(key, "ES256")
    }

    func testSecureEnclaveEcdhEsP256Decrypts() throws {
        try requireSecureEnclave()
        let key = try Self.key("ECDH-ES", .secureEnclave)
        XCTAssertEqual(key.protection, .secureEnclave)
        XCTAssertEqual(try key.algorithms(), ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"])
        try checkPublicJwk(key, kty: "EC", crv: "P-256")
        for alg in ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A256KW"] { try decrypts(key, alg) }
    }

    func testKeychainEcdsaSigns() throws {
        for (alg, crv) in [("ES256", "P-256"), ("ES384", "P-384"), ("ES512", "P-521")] {
            let key = try Self.key(alg, .keychain)
            XCTAssertEqual(key.protection, .keychain, alg)
            try checkPublicJwk(key, kty: "EC", crv: crv)
            try signs(key, alg)
        }
    }

    func testKeychainRsaSignsWithEveryAlgorithm() throws {
        for alg in ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"] {
            let key = try Self.key(alg, .keychain)
            try checkPublicJwk(key, kty: "RSA")
            try signs(key, alg)
        }
    }

    func testKeychainRsaKeysOf3072And4096Bits() throws {
        for bits in [3072, 4096] {
            for alg in ["RS256", "PS512"] { try signs(try Self.key(alg, .keychain, bits: bits), alg) }
            let key = try Self.key("RSA-OAEP-256", .keychain, bits: bits)
            try checkPublicJwk(key, kty: "RSA")
            try decrypts(key, "RSA-OAEP-256")
        }
    }

    func testKeychainEcdhEsDecryptsOnEveryCurve() throws {
        for (bits, crv) in [(256, "P-256"), (384, "P-384"), (521, "P-521")] {
            let key = try Self.key("ECDH-ES", .keychain, bits: bits)
            try checkPublicJwk(key, kty: "EC", crv: crv)
            for alg in ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A256KW"] { try decrypts(key, alg) }
        }
    }

    func testKeychainRsaOaep256Decrypts() throws {
        let key = try Self.key("RSA-OAEP-256", .keychain)
        XCTAssertEqual(try key.algorithms(), ["RSA-OAEP-256"])
        try checkPublicJwk(key, kty: "RSA")
        try decrypts(key, "RSA-OAEP-256")
        // The JSON serialization and a nested JWT take the same path (RFC 7516 §7.2).
        let json = try jweEncryptJson(
            plaintext: Self.payload, options: JweEncryptOptions(enc: "A256GCM", recipients: [JweRecipient(alg: "RSA-OAEP-256", key: try key.publicJwk())]),
            form: "general")
        let options = JweDecryptOptions(allowedAlgs: ["RSA-OAEP-256"], allowedEnc: ["A256GCM"])
        XCTAssertEqual(try jweDecryptJsonWithPlatformKey(jwe: json, key: key, options: options).plaintext, Self.payload)
    }

    // MARK: - Refusals (ADR 0072 §1, §3; ADR 0071 §2, §6)

    func testTheSecureEnclaveRefusesWhatItCannotServe() {
        for (alg, bits) in [("ES384", nil), ("ES512", nil), ("RS256", nil), ("PS256", nil), ("RSA-OAEP-256", nil), ("ECDH-ES", 384), ("ECDH-ES", 521)] as [(String, Int?)] {
            expectCode("Secure Enclave \(alg) \(bits.map(String.init) ?? "")", "UnsupportedAlgorithm") {
                try AppleKey.generate(tag: Self.marker, algorithm: alg, protection: .secureEnclave, keySizeInBits: bits)
            }
        }
    }

    func testAlgorithmsNoAppleKeyServesAreRefused() throws {
        for alg in ["EdDSA", "HS256", "ES256K", "A256KW", "dir", "RSA-OAEP", "ECDH-ES+A256KW", "none"] {
            for protection in [AppleKey.Protection.secureEnclave, .keychain] {
                expectCode("generate \(alg) \(protection)", "UnsupportedAlgorithm") {
                    try AppleKey.generate(tag: Self.marker, algorithm: alg, protection: protection)
                }
            }
            expectCode("open \(alg)", "UnsupportedAlgorithm") { try AppleKey.open(tag: Self.marker, algorithm: alg) }
        }
        let secKey = try Self.secKey(kSecAttrKeyTypeECSECPrimeRandom, 256)
        for alg in ["EdDSA", "HS256"] {
            expectCode("init \(alg)", "UnsupportedAlgorithm") { try AppleKey(secKey: secKey, algorithm: alg) }
        }
        for (alg, bits) in [("ES256", 384), ("RS256", 1024), ("RS256", 8192), ("ECDH-ES", 224)] {
            expectCode("generate \(alg) at \(bits) bits", "UnsupportedAlgorithm") {
                try AppleKey.generate(tag: Self.marker, algorithm: alg, protection: .keychain, keySizeInBits: bits)
            }
        }
    }

    func testInitRefusesAPublicKeyAndAKeyThatCannotDoTheAlgorithm() throws {
        let p256 = try Self.secKey(kSecAttrKeyTypeECSECPrimeRandom, 256)
        let rsa = try Self.secKey(kSecAttrKeyTypeRSA, 2048)
        expectCode("a public key", "InvalidKey") { try AppleKey(secKey: try XCTUnwrap(SecKeyCopyPublicKey(p256)), algorithm: "ES256") }
        expectCode("a public RSA key", "InvalidKey") { try AppleKey(secKey: try XCTUnwrap(SecKeyCopyPublicKey(rsa)), algorithm: "RSA-OAEP-256") }
        for (key, alg) in [(p256, "ES384"), (p256, "RS256"), (p256, "RSA-OAEP-256"), (rsa, "ES256"), (rsa, "ECDH-ES")] {
            guard let error = polyjoseError("\(alg) on another key", { try AppleKey(secKey: key, algorithm: alg) }) else { continue }
            XCTAssertEqual(error.code(), "KeyAlgorithmMismatch", alg)
            assertClean(error, "\(alg) on another key")
        }
        // An RSA key outside 2048, 3072 and 4096 bits (ADR 0072 §1).
        expectCode("RSA-1024", "KeyAlgorithmMismatch") { try AppleKey(secKey: try Self.secKey(kSecAttrKeyTypeRSA, 1024), algorithm: "RS256") }
        // A key the app made itself, bound correctly, works.
        let wrapped = try AppleKey(secKey: p256, algorithm: "ES256")
        XCTAssertEqual(wrapped.protection, .keychain)
        try signs(wrapped, "ES256")
        try decrypts(try AppleKey(secKey: rsa, algorithm: "RSA-OAEP-256"), "RSA-OAEP-256")
    }

    func testAKeyBoundToEs256CannotDecrypt() throws {
        let key = try Self.key("ES256", .keychain)
        let token = try jweEncryptCompact(
            plaintext: Self.payload, options: JweEncryptOptions(enc: "A256GCM", recipients: [JweRecipient(alg: "ECDH-ES", key: try key.publicJwk())]))
        expectCode("ES256 key, ECDH-ES token", "KeyAlgorithmMismatch") {
            try jweDecryptCompactWithPlatformKey(token: token, key: key, options: JweDecryptOptions(allowedAlgs: ["ECDH-ES"], allowedEnc: ["A256GCM"]))
        }
        let ecdh = try Self.key("ECDH-ES", .keychain)
        expectCode("ECDH-ES key, ES256 signature", "KeyAlgorithmMismatch") {
            try jwsSignCompactWithPlatformKey(payload: Self.payload, key: ecdh, options: JwsSignOptions(protectedHeader: #"{"alg":"ES256"}"#))
        }
        // Called directly, a method outside the key's binding is `failed` before any platform call.
        XCTAssertThrowsError(try key.agree(peerPublicKey: Data([4]))) { XCTAssertEqual($0 as? PlatformKeyError, .Failed) }
        XCTAssertThrowsError(try key.sign(alg: "ES384", signingInput: Data())) { XCTAssertEqual($0 as? PlatformKeyError, .Failed) }
        XCTAssertThrowsError(try ecdh.decryptKey(alg: "RSA-OAEP-256", encryptedKey: Data())) { XCTAssertEqual($0 as? PlatformKeyError, .Failed) }
    }

    // MARK: - Fixed properties (ADR 0072 §1)

    func testGenerationAttributesAreThisDeviceOnlyNotSynchronizableAndUseTheDataProtectionKeychain() throws {
        for protection in [AppleKey.Protection.secureEnclave, .keychain] {
            let spec = try XCTUnwrap(AppleKey.Spec("ES256")), size = 256
            let tag = Data("t".utf8)
            let attributes = try AppleKey.generationAttributes(spec: spec, size: size, protection: protection, access: AppleKey.Access(), tag: tag)
            XCTAssertEqual(attributes[kSecAttrSynchronizable] as? Bool, false)
            XCTAssertEqual(attributes[kSecUseDataProtectionKeychain] as? Bool, true)
            XCTAssertEqual(attributes[kSecAttrTokenID] as? String, protection == .secureEnclave ? kSecAttrTokenIDSecureEnclave as String : nil)
            let privateAttributes = try XCTUnwrap(attributes[kSecPrivateKeyAttrs] as? [CFString: Any])
            XCTAssertEqual(privateAttributes[kSecAttrIsPermanent] as? Bool, true)
            XCTAssertEqual(privateAttributes[kSecAttrApplicationTag] as? Data, tag)
            let control = try XCTUnwrap(privateAttributes[kSecAttrAccessControl])
            let expected = try XCTUnwrap(SecAccessControlCreateWithFlags(
                nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, protection == .secureEnclave ? .privateKeyUsage : [], nil))
            XCTAssertTrue(CFEqual(control as CFTypeRef, expected), "\(protection): \(control)")
        }
        // Every accessibility is a ThisDeviceOnly one, and the flags map one to one.
        XCTAssertEqual(AppleKey.accessibility(.whenUnlockedThisDeviceOnly), kSecAttrAccessibleWhenUnlockedThisDeviceOnly)
        XCTAssertEqual(AppleKey.accessibility(.afterFirstUnlockThisDeviceOnly), kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
        XCTAssertEqual(AppleKey.accessibility(.whenPasscodeSetThisDeviceOnly), kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly)
        let all: AppleKey.Access.Flags = [.userPresence, .biometryAny, .biometryCurrentSet, .devicePasscode]
        XCTAssertEqual(AppleKey.accessFlags(all, .keychain), [.userPresence, .biometryAny, .biometryCurrentSet, .devicePasscode])
        XCTAssertEqual(AppleKey.accessFlags([], .secureEnclave), .privateKeyUsage)
    }

    func testASecureEnclaveKeyCarriesPrivateKeyUsage() throws {
        try requireSecureEnclave()
        let key = try Self.key("ES256", .secureEnclave)
        let attributes = try XCTUnwrap(SecKeyCopyAttributes(key.key) as? [CFString: Any])
        XCTAssertEqual(attributes[kSecAttrTokenID] as? String, kSecAttrTokenIDSecureEnclave as String)
        let control = try XCTUnwrap(attributes[kSecAttrAccessControl])
        let expected = try XCTUnwrap(SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, nil))
        XCTAssertTrue(CFEqual(control as CFTypeRef, expected), "\(control)")
    }

    /// `protection` is read from the key (`kSecAttrTokenID`), not taken from the request.
    func testProtectionIsWhatThePlatformReports() throws {
        let software = try Self.secKey(kSecAttrKeyTypeECSECPrimeRandom, 256)
        XCTAssertEqual(try AppleKey(secKey: software, algorithm: "ES256").protection, .keychain)
        try requireSecureEnclave()
        let control = try XCTUnwrap(SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, nil))
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeySizeInBits: 256, kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs: [kSecAttrIsPermanent: false, kSecAttrAccessControl: control] as [CFString: Any],
        ]
        let enclave = try XCTUnwrap(SecKeyCreateRandomKey(attributes as CFDictionary, nil))
        XCTAssertEqual(try AppleKey(secKey: enclave, algorithm: "ES256").protection, .secureEnclave)
    }

    // MARK: - Error mapping, a pure function (ADR 0072 §1; ADR 0071 §4, §6)

    func testPlatformErrorsMapToTheThreeCases() {
        var table: [(String, Int, PlatformKeyError, String)] = [
            (NSOSStatusErrorDomain, Int(errSecItemNotFound), .NotFound, "KeyNotFound"),
            (NSOSStatusErrorDomain, Int(errSecUserCanceled), .UserAuthenticationRequired, "UserAuthenticationRequired"),
            (NSOSStatusErrorDomain, Int(errSecAuthFailed), .UserAuthenticationRequired, "UserAuthenticationRequired"),
            (NSOSStatusErrorDomain, Int(errSecInteractionNotAllowed), .UserAuthenticationRequired, "UserAuthenticationRequired"),
            (LAErrorDomain, LAError.Code.userCancel.rawValue, .UserAuthenticationRequired, "UserAuthenticationRequired"),
            (LAErrorDomain, LAError.Code.appCancel.rawValue, .UserAuthenticationRequired, "UserAuthenticationRequired"),
            (LAErrorDomain, LAError.Code.systemCancel.rawValue, .UserAuthenticationRequired, "UserAuthenticationRequired"),
            (LAErrorDomain, LAError.Code.authenticationFailed.rawValue, .UserAuthenticationRequired, "UserAuthenticationRequired"),
            (LAErrorDomain, LAError.Code.notInteractive.rawValue, .UserAuthenticationRequired, "UserAuthenticationRequired"),
            // Any other status or code, including the RSA-OAEP padding failure (errSecParam,
            // measured) and the missing-entitlement status: never one of the first two (ADR 0071 §4).
            (NSOSStatusErrorDomain, Int(errSecParam), .Failed, "PlatformKeyFailed"),
            (NSOSStatusErrorDomain, Int(errSecMissingEntitlement), .Failed, "PlatformKeyFailed"),
            (NSOSStatusErrorDomain, Int(errSecDecode), .Failed, "PlatformKeyFailed"),
            (NSOSStatusErrorDomain, -67712, .Failed, "PlatformKeyFailed"),
            (NSOSStatusErrorDomain, 0, .Failed, "PlatformKeyFailed"),
            (LAErrorDomain, LAError.Code.passcodeNotSet.rawValue, .Failed, "PlatformKeyFailed"),
            (LAErrorDomain, Int(errSecItemNotFound), .Failed, "PlatformKeyFailed"),
            (NSCocoaErrorDomain, Int(errSecItemNotFound), .Failed, "PlatformKeyFailed"),
            ("dev.polyjose.test", LAError.Code.userCancel.rawValue, .Failed, "PlatformKeyFailed"),
        ]
        #if !os(watchOS)  // no biometry on watchOS
        table.append((LAErrorDomain, LAError.Code.biometryLockout.rawValue, .UserAuthenticationRequired, "UserAuthenticationRequired"))
        table.append((LAErrorDomain, LAError.Code.biometryNotAvailable.rawValue, .Failed, "PlatformKeyFailed"))
        #endif
        for (domain, code, expected, polyjoseCode) in table {
            let mapped = AppleKey.platformKeyError(domain: domain, code: code)
            XCTAssertEqual(mapped, expected, "\(domain) \(code)")
            XCTAssertEqual(AppleKey.polyjoseError(mapped).code(), polyjoseCode, "\(domain) \(code)")
            let cfError = CFErrorCreate(nil, domain as CFString, code, [kCFErrorDescriptionKey: Self.marker] as CFDictionary)
            XCTAssertEqual(AppleKey.platformKeyError(cfError.map { Unmanaged.passRetained($0) }), expected, "CFError \(domain) \(code)")
        }
        XCTAssertEqual(AppleKey.platformKeyError(nil), .Failed)
        for status in [errSecItemNotFound, errSecUserCanceled, errSecAuthFailed, errSecInteractionNotAllowed, errSecParam] {
            XCTAssertEqual(AppleKey.platformKeyError(status: status), AppleKey.platformKeyError(domain: NSOSStatusErrorDomain, code: Int(status)))
        }
    }

    /// No `CFError` description, tag or key reference reaches a polyjose error: a key that is not
    /// there (the tag holds the marker), a key of the wrong algorithm, and platform failures.
    func testNoPlatformTextReachesAPolyjoseError() throws {
        let tag = "tag-\(Self.marker)"
        if let error = polyjoseError("open a missing key", { try AppleKey.open(tag: tag, algorithm: "ES256") }) {
            // errSecItemNotFound on macOS and in the hosted app; -34018 un-hosted on the simulator.
            XCTAssertTrue(["KeyNotFound", "PlatformKeyFailed"].contains(error.code()), error.code())
            assertClean(error, "open a missing key")
        }
        // Un-hosted, the platform refuses to store the key with a CFError whose description names
        // the key; on a signed host the key is created and deleted again.
        do {
            _ = try AppleKey.generate(tag: tag, algorithm: "ES256", protection: .keychain)
            try AppleKey.delete(tag: tag)
        } catch {
            XCTAssertEqual((error as? PolyjoseError)?.code(), "PlatformKeyFailed")
            assertClean(error, "generate un-hosted")
        }
        let p521 = try Self.key("ECDH-ES", .keychain, bits: 521)
        let p256Public = try XCTUnwrap(SecKeyCopyPublicKey(try Self.secKey(kSecAttrKeyTypeECSECPrimeRandom, 256)))
        let p256Point = try XCTUnwrap(SecKeyCopyExternalRepresentation(p256Public, nil) as Data?)
        XCTAssertThrowsError(try p521.agree(peerPublicKey: p256Point)) { error in
            XCTAssertEqual(error as? PlatformKeyError, .Failed)
            assertClean(error, "agree with a point of another curve")
        }
        let rsa = try Self.key("RSA-OAEP-256", .keychain)
        XCTAssertThrowsError(try rsa.decryptKey(alg: "RSA-OAEP-256", encryptedKey: Data(repeating: 7, count: 256))) { error in
            XCTAssertEqual(error as? PlatformKeyError, .Failed)
            assertClean(error, "RSA-OAEP padding failure")
        }
    }

    // MARK: - Printing (ADR 0071 §7)

    func testPrintingShowsTheTypeAndProtectionOnly() throws {
        var keys = [try Self.key("ES256", .keychain), try Self.key("RS256", .keychain)]
        if SecureEnclave.isAvailable { keys.append(try Self.key("ECDH-ES", .secureEnclave)) }
        for key in keys {
            let jwk = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(try key.publicJwk().utf8)) as? [String: String])
            let publicValues = ["x", "y", "n"].compactMap { jwk[$0] }
            XCTAssertFalse(publicValues.isEmpty)
            XCTAssertEqual(key.description, "AppleKey(protection: \(key.protection))")
            XCTAssertEqual(key.debugDescription, "Polyjose.AppleKey(protection: \(key.protection))")
            for text in Self.printed(key) {
                XCTAssertTrue(text.contains("AppleKey"), text)
                XCTAssertTrue(text.contains("\(key.protection)"), text)
                for value in publicValues { XCTAssertFalse(text.contains(value), "public key in \(text)") }
                XCTAssertFalse(text.contains("SecKey"), text)
            }
            assertClean(key, "AppleKey")
        }
    }
}
