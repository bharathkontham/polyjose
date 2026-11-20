import CryptoKit  // SecureEnclave.isAvailable only
import Foundation
import LocalAuthentication
import Polyjose
import Security
import XCTest

/// `AppleKey` with permanent keys (ADR 0072 §1, §6.1; feature 0025 T03), in a test bundle hosted in
/// an app, which is what lets a test store Keychain items on the iOS Simulator.
///
/// platforms/swift/scripts/test-simulators.sh runs this bundle twice on one disposable simulator,
/// passing POLYJOSE_HOSTED_PHASE and POLYJOSE_HOSTED_STATE (a directory on the host; without it,
/// as on a device, a directory in the app's container):
/// - run 1 (`testRun1…`, and every test but `testRun2…`) generates a Secure Enclave ES256 key, a
///   Keychain ES384 key and a Keychain RS256 key under fixed tags, records each public JWK in the
///   state directory and leaves the keys;
/// - run 2 (`testRun2…`), a new process, opens each by tag, gets the recorded public JWK, signs,
///   deletes, and then `open` is `KeyNotFound`.
/// Outside that script the two phases skip. Tests that need a person (keys that prompt) skip
/// off-device; platforms/swift/DEVICE-TESTS.md runs them on an iPhone.
final class AppleKeyHostedTests: XCTestCase {
    /// In every tag, so a test can check that no tag reaches an error or a printed form.
    static let marker = "hosted-marker-7f3a"
    static let payload = Data("hosted AppleKey".utf8)
    static let secureEnclaveSkip = "SecureEnclave.isAvailable is false here, so the Secure Enclave rows are SKIPPED, not run"
    static let personSkip = "needs a device and a person (platforms/swift/DEVICE-TESTS.md)"

    struct Fixture: Sendable {
        let tag: String
        let algorithm: String
        let protection: AppleKey.Protection
    }

    static let secureEnclave = Fixture(tag: "dev.polyjose.\(marker).se-es256", algorithm: "ES256", protection: .secureEnclave)
    static let keychain = [
        Fixture(tag: "dev.polyjose.\(marker).keychain-es384", algorithm: "ES384", protection: .keychain),
        Fixture(tag: "dev.polyjose.\(marker).keychain-rs256", algorithm: "RS256", protection: .keychain),
    ]

    static var environment: [String: String] { ProcessInfo.processInfo.environment }

    /// The state directory of `phase`, or a skip outside test-simulators.sh.
    func stateDirectory(phase: String) throws -> URL {
        try XCTSkipUnless(
            Self.environment["POLYJOSE_HOSTED_PHASE"] == phase,
            "run \(phase) of the persistence test, run by platforms/swift/scripts/test-simulators.sh")
        if let path = Self.environment["POLYJOSE_HOSTED_STATE"] { return URL(fileURLWithPath: path, isDirectory: true) }
        // On a device (DEVICE-TESTS.md), where no host path is reachable: the app's own container,
        // which a reinstall by the next `xcodebuild test` keeps.
        let support = try XCTUnwrap(FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first)
        return support.appendingPathComponent("polyjose-hosted-state", isDirectory: true)
    }

    static func recordFile(_ fixture: Fixture, in directory: URL) -> URL {
        directory.appendingPathComponent("\(fixture.algorithm)-\(fixture.protection).jwk")
    }

    func requireSecureEnclave() throws {
        print("POLYJOSE-SECURE-ENCLAVE \(SecureEnclave.isAvailable ? "available" : "unavailable")")
        try XCTSkipUnless(SecureEnclave.isAvailable, Self.secureEnclaveSkip)
    }

    func signs(_ key: AppleKey, _ alg: String, file: StaticString = #filePath, line: UInt = #line) throws {
        let token = try jwsSignCompactWithPlatformKey(payload: Self.payload, key: key, options: JwsSignOptions(protectedHeader: #"{"alg":"\#(alg)"}"#))
        let verified = try jwsVerifyCompact(token: token, key: try key.publicJwk(), options: JwsVerifyOptions(allowedAlgs: [alg]))
        XCTAssertEqual(verified.payload, Self.payload, alg, file: file, line: line)
    }

    func polyjoseCode(_ what: String, _ call: () throws -> Any, file: StaticString = #filePath, line: UInt = #line) -> String? {
        do {
            _ = try call()
            XCTFail("\(what): the call succeeded", file: file, line: line)
        } catch let error as PolyjoseError {
            assertClean(error, what, file: file, line: line)
            return error.code()
        } catch {
            XCTFail("\(what): not a PolyjoseError: \(error)", file: file, line: line)
        }
        return nil
    }

    /// No tag, platform error text or key reference in any printed form of `value`.
    func assertClean(_ value: Any, _ what: String, file: StaticString = #filePath, line: UInt = #line) {
        var dumped = ""
        dump(value, to: &dumped)
        var forms = ["\(value)", String(reflecting: value), dumped]
        if let error = value as? Error { forms.append(error.localizedDescription) }
        for text in forms {
            for needle in [Self.marker, "SecKeyRef", "NSOSStatusErrorDomain", "Domain="] {
                XCTAssertFalse(text.contains(needle), "\(what): \(needle) in \(text)", file: file, line: line)
            }
        }
    }

    /// The stored item's attributes (ADR 0072 §1, fixed key properties): never synchronizable and,
    /// for a Keychain key, `ThisDeviceOnly` with no other access control. They are printed for the
    /// device runbook.
    ///
    /// A Secure Enclave key's item is a token object whose own attributes, on the iOS 27.2
    /// simulator, are not the key's (measured 2026-11-15: `kSecAttrAccessible` `dk`, access control
    /// `cku;dacl(true)`, while the generated key reports `aku` with `.privateKeyUsage`), so for it
    /// only the token and the synchronizable flag are asserted here; AppleKeyTests checks the
    /// generated key's access control on macOS and the simulator.
    func checkStoredAttributes(_ fixture: Fixture, file: StaticString = #filePath, line: UInt = #line) throws {
        var query: [CFString: Any] = [
            kSecClass: kSecClassKey, kSecAttrApplicationTag: Data(fixture.tag.utf8), kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecUseDataProtectionKeychain: true, kSecReturnAttributes: true,
        ]
        var result: CFTypeRef?
        XCTAssertEqual(SecItemCopyMatching(query as CFDictionary, &result), errSecSuccess, file: file, line: line)
        let attributes = try XCTUnwrap(result as? [CFString: Any], file: file, line: line)
        let control = attributes[kSecAttrAccessControl]
        print("POLYJOSE-ATTRIBUTES \(fixture.algorithm) \(fixture.protection): kSecAttrAccessible=\(attributes[kSecAttrAccessible] ?? "none") kSecAttrAccessControl=\(control ?? "none") kSecAttrSynchronizable=\(attributes[kSecAttrSynchronizable] ?? "none")")
        XCTAssertNotEqual(attributes[kSecAttrSynchronizable] as? Bool, true, file: file, line: line)
        if fixture.protection == .secureEnclave {
            XCTAssertEqual(attributes[kSecAttrTokenID] as? String, kSecAttrTokenIDSecureEnclave as String, file: file, line: line)
        } else {
            XCTAssertNil(attributes[kSecAttrTokenID], file: file, line: line)
            XCTAssertEqual(attributes[kSecAttrAccessible] as? String, kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String, file: file, line: line)
            let expected = try XCTUnwrap(SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [], nil))
            XCTAssertTrue(CFEqual(try XCTUnwrap(control, file: file, line: line) as CFTypeRef, expected), "\(String(describing: control))", file: file, line: line)
        }
        // No synchronizable copy exists either.
        query[kSecAttrSynchronizable] = true
        query[kSecReturnAttributes] = nil
        XCTAssertEqual(SecItemCopyMatching(query as CFDictionary, nil), errSecItemNotFound, file: file, line: line)
    }

    // MARK: - Run 1: generate and leave the keys

    func generateAndRecord(_ fixture: Fixture, in directory: URL) throws {
        try AppleKey.delete(tag: fixture.tag)  // left by an interrupted earlier run
        let key = try AppleKey.generate(tag: fixture.tag, algorithm: fixture.algorithm, protection: fixture.protection)
        XCTAssertEqual(key.protection, fixture.protection, fixture.tag)
        try signs(key, fixture.algorithm)
        try checkStoredAttributes(fixture)
        assertClean(key, "generated \(fixture.algorithm)")
        XCTAssertEqual(polyjoseCode("generate under a used tag") {
            try AppleKey.generate(tag: fixture.tag, algorithm: fixture.algorithm, protection: fixture.protection)
        }, "PlatformKeyFailed")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try Data(try key.publicJwk().utf8).write(to: Self.recordFile(fixture, in: directory))
    }

    func testRun1SecureEnclave() throws {
        let directory = try stateDirectory(phase: "1")
        try requireSecureEnclave()
        try generateAndRecord(Self.secureEnclave, in: directory)
    }

    func testRun1Keychain() throws {
        let directory = try stateDirectory(phase: "1")
        for fixture in Self.keychain { try generateAndRecord(fixture, in: directory) }
    }

    // MARK: - Run 2, another process: open, compare, sign, delete

    func openSignAndDelete(_ fixture: Fixture, in directory: URL) throws {
        let recorded = try String(contentsOf: Self.recordFile(fixture, in: directory), encoding: .utf8)
        let key = try AppleKey.open(tag: fixture.tag, algorithm: fixture.algorithm)
        XCTAssertEqual(try key.publicJwk(), recorded, fixture.tag)
        XCTAssertEqual(key.protection, fixture.protection, fixture.tag)
        try signs(key, fixture.algorithm)
        assertClean(key, "opened \(fixture.algorithm)")
        let other = fixture.algorithm == "RS256" ? "ES256" : "RS256"
        XCTAssertEqual(polyjoseCode("open for another algorithm") { try AppleKey.open(tag: fixture.tag, algorithm: other) }, "KeyAlgorithmMismatch")
        try AppleKey.delete(tag: fixture.tag)
        XCTAssertEqual(polyjoseCode("open a deleted key") { try AppleKey.open(tag: fixture.tag, algorithm: fixture.algorithm) }, "KeyNotFound")
        try AppleKey.delete(tag: fixture.tag)  // deleting nothing is not an error
    }

    func testRun2SecureEnclave() throws {
        let directory = try stateDirectory(phase: "2")
        try requireSecureEnclave()
        try openSignAndDelete(Self.secureEnclave, in: directory)
    }

    func testRun2Keychain() throws {
        let directory = try stateDirectory(phase: "2")
        for fixture in Self.keychain { try openSignAndDelete(fixture, in: directory) }
    }

    // MARK: - A key the app stored itself (feature 0025 B04): found by tag, or wrapped as a SecKey

    static let claims = #"{"iss":"joe","sub":"existing-key"}"#

    /// A permanent private key the app makes itself with `SecKeyCreateRandomKey`, as an iOS app
    /// would: its own `kSecAttrApplicationTag` (the tag string's UTF-8 bytes), no polyjose call.
    /// `extra` adds private-key attributes; `top` adds top-level ones (for example the token).
    static func appKey(tag: String, type: CFString, bits: Int, extra: [CFString: Any] = [:], top: [CFString: Any] = [:]) throws -> SecKey {
        _ = SecItemDelete([kSecClass: kSecClassKey, kSecAttrApplicationTag: Data(tag.utf8)] as CFDictionary)
        var privateAttributes: [CFString: Any] = [kSecAttrIsPermanent: true, kSecAttrApplicationTag: Data(tag.utf8)]
        privateAttributes.merge(extra) { $1 }
        var attributes: [CFString: Any] = [kSecAttrKeyType: type, kSecAttrKeySizeInBits: bits, kSecPrivateKeyAttrs: privateAttributes]
        attributes.merge(top) { $1 }
        var error: Unmanaged<CFError>?
        let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error)
        let code = error.map { CFErrorGetCode($0.takeRetainedValue()) } ?? 0
        return try XCTUnwrap(key, "SecKeyCreateRandomKey failed with code \(code)")
    }

    /// `jwtSignWithPlatformKey`, verified with the key's public JWK alone (RFC 7519 §7.1, §7.2).
    func signsAJwt(_ key: AppleKey, _ alg: String, file: StaticString = #filePath, line: UInt = #line) throws {
        let jwt = try jwtSignWithPlatformKey(claims: Self.claims, key: key, options: JwtSignOptions(alg: alg))
        let options = JwtVerifyOptions(allowedAlgs: [alg], now: 1_700_000_000, allowMissingExp: true)
        XCTAssertEqual(try jwtVerify(token: jwt, key: try key.publicJwk(), options: options).claims, Self.claims, alg, file: file, line: line)
    }

    /// A JWE and a nested JWT (RFC 7519 §5.2) encrypted to the public JWK only, as a server would
    /// (RFC 7516 §5.1), then decrypted by `key`. The inner JWT is signed by `signer`.
    func decryptsAJweAndANestedJwt(_ key: AppleKey, _ alg: String, signer: AppleKey, file: StaticString = #filePath, line: UInt = #line) throws {
        let encrypt = JweEncryptOptions(enc: "A256GCM", recipients: [JweRecipient(alg: alg, key: try key.publicJwk())])
        let decrypt = JweDecryptOptions(allowedAlgs: [alg], allowedEnc: ["A256GCM"])
        let jwe = try jweEncryptCompact(plaintext: Self.payload, options: encrypt)
        XCTAssertEqual(try jweDecryptCompactWithPlatformKey(token: jwe, key: key, options: decrypt).plaintext, Self.payload, alg, file: file, line: line)
        let signerAlg = try XCTUnwrap(try signer.algorithms().first)
        let signed = try jwtSignWithPlatformKey(claims: Self.claims, key: signer, options: JwtSignOptions(alg: signerAlg))
        let nested = try jwtEncryptNested(signedJwt: signed, options: encrypt)
        let verified = try jwtDecryptNestedWithPlatformKey(
            token: nested, decryptKey: key, decryptOptions: decrypt, key: try signer.publicJwk(),
            options: JwtVerifyOptions(allowedAlgs: [signerAlg], now: 1_700_000_000, allowMissingExp: true))
        XCTAssertEqual(verified.inner.claims, Self.claims, alg, file: file, line: line)
    }

    /// A Keychain P-256 key the app stored: `open(tag:algorithm:)` finds it for ES256 and for
    /// ECDH-ES (a software key has no purpose of its own), `AppleKey(secKey:algorithm:)` wraps the
    /// same `SecKey`, another curve or type is `KeyAlgorithmMismatch`, and `delete(tag:)` removes it.
    func testAnExistingKeychainEcKeyOpensByTag() throws {
        let tag = "dev.polyjose.\(Self.marker).existing-ec"
        let secKey = try Self.appKey(tag: tag, type: kSecAttrKeyTypeECSECPrimeRandom, bits: 256)
        let opened = try AppleKey.open(tag: tag, algorithm: "ES256")
        XCTAssertEqual(opened.protection, .keychain)
        try signsAJwt(opened, "ES256")
        let wrapped = try AppleKey(secKey: secKey, algorithm: "ES256")
        XCTAssertEqual(try wrapped.publicJwk(), try opened.publicJwk())
        try signsAJwt(wrapped, "ES256")
        try decryptsAJweAndANestedJwt(try AppleKey.open(tag: tag, algorithm: "ECDH-ES"), "ECDH-ES", signer: opened)
        try decryptsAJweAndANestedJwt(try AppleKey(secKey: secKey, algorithm: "ECDH-ES"), "ECDH-ES+A256KW", signer: wrapped)
        for other in ["ES384", "RS256", "RSA-OAEP-256"] {
            XCTAssertEqual(polyjoseCode("P-256 key as \(other)") { try AppleKey.open(tag: tag, algorithm: other) }, "KeyAlgorithmMismatch", other)
        }
        XCTAssertEqual(polyjoseCode("ECDH-ES+A256KW name") { try AppleKey.open(tag: tag, algorithm: "ECDH-ES+A256KW") }, "UnsupportedAlgorithm")
        try AppleKey.delete(tag: tag)
        XCTAssertEqual(polyjoseCode("open after delete") { try AppleKey.open(tag: tag, algorithm: "ES256") }, "KeyNotFound")
    }

    /// A Keychain RSA-2048 key the app stored opens as RS256, PS256 and RSA-OAEP-256. `open` doesn't
    /// read `kSecAttrCanSign` or `kSecAttrCanDecrypt`, and a software key stored with either set to
    /// false still signed and decrypted (measured on the iOS 27.2 simulator, 2026-11-16).
    func testAnExistingKeychainRsaKeyOpensByTag() throws {
        let tag = "dev.polyjose.\(Self.marker).existing-rsa"
        let secKey = try Self.appKey(tag: tag, type: kSecAttrKeyTypeRSA, bits: 2048)
        for alg in ["RS256", "PS256"] { try signsAJwt(try AppleKey.open(tag: tag, algorithm: alg), alg) }
        let signer = try AppleKey(secKey: secKey, algorithm: "PS256")
        try decryptsAJweAndANestedJwt(try AppleKey.open(tag: tag, algorithm: "RSA-OAEP-256"), "RSA-OAEP-256", signer: signer)
        XCTAssertEqual(polyjoseCode("RSA key as ES256") { try AppleKey.open(tag: tag, algorithm: "ES256") }, "KeyAlgorithmMismatch")
        try AppleKey.delete(tag: tag)

        let noSign = "dev.polyjose.\(Self.marker).existing-rsa-nosign"
        _ = try Self.appKey(tag: noSign, type: kSecAttrKeyTypeRSA, bits: 2048, extra: [kSecAttrCanSign: false])
        let noSignOutcome = Self.openOutcome(tag: noSign, algorithm: "RS256")
        let noDecrypt = "dev.polyjose.\(Self.marker).existing-rsa-nodecrypt"
        _ = try Self.appKey(tag: noDecrypt, type: kSecAttrKeyTypeRSA, bits: 2048, extra: [kSecAttrCanDecrypt: false])
        let noDecryptOutcome = Self.openOutcome(tag: noDecrypt, algorithm: "RSA-OAEP-256")
        print("POLYJOSE-EXISTING kSecAttrCanSign=false as RS256: \(noSignOutcome); kSecAttrCanDecrypt=false as RSA-OAEP-256: \(noDecryptOutcome)")
        try AppleKey.delete(tag: noSign)
        try AppleKey.delete(tag: noDecrypt)
        XCTAssertEqual(noSignOutcome, "opened, signed")
        XCTAssertEqual(noDecryptOutcome, "opened, decrypted")
    }

    /// `open` for the printed outcome: `opened`, then `signed` or `decrypted` when the key works,
    /// or the polyjose code of the first failing step.
    static func openOutcome(tag: String, algorithm: String) -> String {
        do {
            let key = try AppleKey.open(tag: tag, algorithm: algorithm)
            if algorithm == "RSA-OAEP-256" {
                let encrypt = JweEncryptOptions(enc: "A256GCM", recipients: [JweRecipient(alg: algorithm, key: try key.publicJwk())])
                let jwe = try jweEncryptCompact(plaintext: payload, options: encrypt)
                _ = try jweDecryptCompactWithPlatformKey(token: jwe, key: key, options: JweDecryptOptions(allowedAlgs: [algorithm], allowedEnc: ["A256GCM"]))
                return "opened, decrypted"
            }
            _ = try jwtSignWithPlatformKey(claims: claims, key: key, options: JwtSignOptions(alg: algorithm))
            return "opened, signed"
        } catch let error as PolyjoseError {
            return error.code()
        } catch {
            return "unexpected error type"
        }
    }

    /// A Secure Enclave P-256 key the app stored (`kSecAttrTokenIDSecureEnclave`,
    /// `.privateKeyUsage`) opens by tag with `protection` `.secureEnclave`, for ES256 and ECDH-ES.
    func testAnExistingSecureEnclaveKeyOpensByTag() throws {
        try requireSecureEnclave()
        let tag = "dev.polyjose.\(Self.marker).existing-se"
        let control = try XCTUnwrap(SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, nil))
        let secKey = try Self.appKey(
            tag: tag, type: kSecAttrKeyTypeECSECPrimeRandom, bits: 256, extra: [kSecAttrAccessControl: control],
            top: [kSecAttrTokenID: kSecAttrTokenIDSecureEnclave])
        let opened = try AppleKey.open(tag: tag, algorithm: "ES256")
        XCTAssertEqual(opened.protection, .secureEnclave)
        try signsAJwt(opened, "ES256")
        let wrapped = try AppleKey(secKey: secKey, algorithm: "ES256")
        XCTAssertEqual(wrapped.protection, .secureEnclave)
        try signsAJwt(wrapped, "ES256")
        try decryptsAJweAndANestedJwt(try AppleKey.open(tag: tag, algorithm: "ECDH-ES"), "ECDH-ES", signer: opened)
        try AppleKey.delete(tag: tag)
        XCTAssertEqual(polyjoseCode("open after delete") { try AppleKey.open(tag: tag, algorithm: "ES256") }, "KeyNotFound")
    }

    // MARK: - Keys that prompt (ADR 0072 §4): on a device, with a person (DEVICE-TESTS.md)

    func requireDevice() throws {
        #if targetEnvironment(simulator)
        throw XCTSkip(Self.personSkip)
        #endif
    }

    /// Runs `body` off the main thread, as ADR 0072 §4 requires, and prints how long it took: a
    /// call that waits for the prompt takes as long as the person does. Nothing is asserted on time.
    func offMain(_ what: String, timeout: TimeInterval = 120, _ body: @escaping @Sendable () -> Void) {
        let done = expectation(description: what)
        DispatchQueue.global().async {
            let start = Date()
            body()
            print("POLYJOSE-DEVICE \(what): returned after \(String(format: "%.1f", Date().timeIntervalSince(start))) s, main thread: \(Thread.isMainThread)")
            done.fulfill()
        }
        wait(for: [done], timeout: timeout)
    }

    /// The outcome of a signing call, printed for the runbook: `signed` or the polyjose code.
    static func signOutcome(_ key: AppleKey) -> String {
        do {
            let token = try jwsSignCompactWithPlatformKey(payload: payload, key: key, options: JwsSignOptions(protectedHeader: #"{"alg":"ES256"}"#))
            _ = try jwsVerifyCompact(token: token, key: try key.publicJwk(), options: JwsVerifyOptions(allowedAlgs: ["ES256"]))
            return "signed"
        } catch let error as PolyjoseError {
            return error.code()
        } catch {
            return "unexpected error type"
        }
    }

    /// A non-permanent Secure Enclave P-256 key with `flags`, made here, so the raw platform error
    /// of a cancelled prompt can be printed too.
    static func promptingKey(_ flags: SecAccessControlCreateFlags) throws -> SecKey {
        let control = try XCTUnwrap(SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, flags], nil))
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeySizeInBits: 256, kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs: [kSecAttrIsPermanent: false, kSecAttrAccessControl: control] as [CFString: Any],
        ]
        return try XCTUnwrap(SecKeyCreateRandomKey(attributes as CFDictionary, nil))
    }

    /// DEVICE-TESTS.md steps 2 and 3: a `.userPresence` key, approved, then cancelled.
    func testDeviceUserPresence() throws {
        try requireDevice()
        // A SecKey is thread-safe (Security framework); Swift does not mark it Sendable.
        nonisolated(unsafe) let secKey = try Self.promptingKey(.userPresence)
        let key = try AppleKey(secKey: secKey, algorithm: "ES256")
        offMain("userPresence, approve the prompt") { print("POLYJOSE-DEVICE userPresence approve: \(Self.signOutcome(key))") }
        offMain("userPresence, cancel the prompt") { print("POLYJOSE-DEVICE userPresence cancel: \(Self.signOutcome(key))") }
        offMain("userPresence raw, cancel the prompt") {
            var error: Unmanaged<CFError>?
            let signature = SecKeyCreateSignature(secKey, .ecdsaSignatureMessageX962SHA256, Data("x".utf8) as CFData, &error)
            let raw = error?.takeRetainedValue()
            print("POLYJOSE-DEVICE userPresence raw cancel: signed=\(signature != nil) domain=\(raw.map { CFErrorGetDomain($0) as String } ?? "none") code=\(raw.map { CFErrorGetCode($0) } ?? 0)")
        }
    }

    /// DEVICE-TESTS.md step 4: a `.biometryCurrentSet` key, approved with biometry.
    func testDeviceBiometryCurrentSet() throws {
        try requireDevice()
        let key = try AppleKey(secKey: try Self.promptingKey(.biometryCurrentSet), algorithm: "ES256")
        offMain("biometryCurrentSet, authenticate") { print("POLYJOSE-DEVICE biometryCurrentSet: \(Self.signOutcome(key))") }
    }

    /// DEVICE-TESTS.md step 5: one `LAContext`, authenticated once, used for two signatures.
    func testDeviceReusedContext() throws {
        try requireDevice()
        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 30
        let tag = "dev.polyjose.\(Self.marker).device-context"
        try AppleKey.delete(tag: tag)
        _ = try AppleKey.generate(tag: tag, algorithm: "ES256", protection: .secureEnclave, access: AppleKey.Access(flags: .userPresence))
        let key = try AppleKey.open(tag: tag, algorithm: "ES256", context: context)
        offMain("context, authenticate once") {
            print("POLYJOSE-DEVICE context first: \(Self.signOutcome(key))")
            print("POLYJOSE-DEVICE context second: \(Self.signOutcome(key))")
        }
        try AppleKey.delete(tag: tag)
    }
}
