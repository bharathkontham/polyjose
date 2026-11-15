import CryptoKit
import Foundation
import Polyjose
import Security
import XCTest

/// The `PlatformKey` callback path through the generated Swift (feature 0025 T02; ADR 0071 §5), on
/// macOS and the iOS Simulator. The keys are software keys written here: CryptoKit P-256 keys and a
/// non-permanent RSA-2048 `SecKey`, stand-ins for a Secure Enclave or Keychain key (T03 adds those).
final class PlatformKeyTests: XCTestCase {
    static let marker = "host-error-marker-9b2d"
    static let payload = Data("platform keys sign and decrypt".utf8)
    static let claims = #"{"iss":"joe","sub":"platform"}"#

    /// Where a test key throws instead of returning.
    enum Method { case publicJwk, algorithms, sign, agree, decryptKey }

    /// The private-key work a test key does, by key kind. Immutable keys (CryptoKit values, a
    /// `SecKey`, which is thread-safe), shared by the tests.
    enum Kind: @unchecked Sendable {
        case p256(signing: P256.Signing.PrivateKey, agreement: P256.KeyAgreement.PrivateKey)
        case rsa(SecKey)
    }

    /// A software `PlatformKey`: `sign` returns the DER `Ecdsa-Sig-Value` (RFC 3279 §2.2.3) or the
    /// RSASSA-PKCS1-v1_5 signature, `agree` the ECDH shared secret Z (RFC 7518 §4.6.2), `decryptKey`
    /// the RSAES-OAEP-256 plaintext (RFC 7518 §4.3). It counts its private-key calls and throws
    /// `failure` from `failAt` when both are set.
    final class SoftKey: PlatformKey, @unchecked Sendable {
        let kind: Kind
        let algs: [String]
        let signer: Kind?
        let failAt: Method?
        let failure: Error?
        private let lock = NSLock()
        private var calls = 0

        init(_ kind: Kind, algs: [String], signer: Kind? = nil, failAt: Method? = nil, failure: Error? = nil) {
            self.kind = kind
            self.algs = algs
            self.signer = signer
            self.failAt = failAt
            self.failure = failure
        }

        var privateCalls: Int { lock.withLock { calls } }

        private func maybeFail(_ method: Method) throws {
            if method == failAt, let failure { throw failure }
        }

        private func countPrivate() { lock.withLock { calls += 1 } }

        func publicJwk() throws -> String {
            try maybeFail(.publicJwk)
            return PlatformKeyTests.publicJwk(kind)
        }

        func algorithms() throws -> [String] {
            try maybeFail(.algorithms)
            return algs
        }

        func sign(alg: String, signingInput: Data) throws -> Data {
            countPrivate()
            try maybeFail(.sign)
            switch signer ?? kind {
            case .p256(let signing, _):
                return try signing.signature(for: signingInput).derRepresentation
            case .rsa(let key):
                var error: Unmanaged<CFError>?
                guard let signature = SecKeyCreateSignature(key, .rsaSignatureMessagePKCS1v15SHA256, signingInput as CFData, &error) else {
                    throw PlatformKeyError.Failed
                }
                return signature as Data
            }
        }

        func agree(peerPublicKey: Data) throws -> Data {
            countPrivate()
            try maybeFail(.agree)
            guard case .p256(_, let agreement) = kind, peerPublicKey.count == 65, peerPublicKey.first == 4 else {
                throw PlatformKeyError.Failed
            }
            let peer = try P256.KeyAgreement.PublicKey(x963Representation: peerPublicKey)
            return try agreement.sharedSecretFromKeyAgreement(with: peer).withUnsafeBytes { Data($0) }
        }

        func decryptKey(alg: String, encryptedKey: Data) throws -> Data {
            countPrivate()
            try maybeFail(.decryptKey)
            guard case .rsa(let key) = kind, alg == "RSA-OAEP-256" else { throw PlatformKeyError.Failed }
            var error: Unmanaged<CFError>?
            guard let cek = SecKeyCreateDecryptedData(key, .rsaEncryptionOAEPSHA256, encryptedKey as CFData, &error) else {
                throw PlatformKeyError.Failed
            }
            return cek as Data
        }
    }

    /// One P-256 scalar, as a CryptoKit signing key and as an agreement key, so one public JWK.
    static func p256() -> Kind {
        let signing = P256.Signing.PrivateKey()
        // swiftlint:disable:next force_try
        let agreement = try! P256.KeyAgreement.PrivateKey(rawRepresentation: signing.rawRepresentation)
        return .p256(signing: signing, agreement: agreement)
    }

    /// A non-permanent RSA-2048 `SecKey`: it is never stored in a Keychain.
    static let rsa: Kind = {
        let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 2048]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            fatalError("SecKeyCreateRandomKey failed: \(String(describing: error))")
        }
        return .rsa(key)
    }()

    static let ec = p256()

    /// The public JWK (RFC 7517 §4; RFC 7518 §6.2.1, §6.3.1) of a test key.
    static func publicJwk(_ kind: Kind) -> String {
        switch kind {
        case .p256(let signing, _):
            let raw = signing.publicKey.rawRepresentation
            let x = base64urlEncode(data: raw.prefix(32))
            let y = base64urlEncode(data: raw.suffix(32))
            return #"{"kty":"EC","crv":"P-256","x":"\#(x)","y":"\#(y)"}"#
        case .rsa(let key):
            let (n, e) = rsaPublicNumbers(key)
            return #"{"kty":"RSA","n":"\#(base64urlEncode(data: n))","e":"\#(base64urlEncode(data: e))"}"#
        }
    }

    /// n and e of an RSA `SecKey`, from the PKCS #1 RSAPublicKey DER that
    /// `SecKeyCopyExternalRepresentation` returns (RFC 8017 App. A.1.1): two INTEGERs in a SEQUENCE.
    static func rsaPublicNumbers(_ key: SecKey) -> (Data, Data) {
        guard let publicKey = SecKeyCopyPublicKey(key),
              let der = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
            fatalError("no RSA public key")
        }
        var bytes = [UInt8](der)[...]
        func length() -> Int {
            let first = Int(bytes.removeFirst())
            guard first & 0x80 != 0 else { return first }
            return (0..<(first & 0x7f)).reduce(0) { value, _ in (value << 8) | Int(bytes.removeFirst()) }
        }
        func integer() -> Data {
            precondition(bytes.removeFirst() == 0x02)
            let count = length()
            let value = bytes.prefix(count)
            bytes = bytes.dropFirst(value.count)
            return Data(value.drop(while: { $0 == 0 }))
        }
        precondition(bytes.removeFirst() == 0x30)
        _ = length()
        return (integer(), integer())
    }

    // MARK: - Options

    static func signOptions(_ alg: String) -> JwsSignOptions { JwsSignOptions(protectedHeader: #"{"alg":"\#(alg)"}"#) }
    static func verifyOptions(_ alg: String) -> JwtVerifyOptions {
        JwtVerifyOptions(allowedAlgs: [alg], now: 1_700_000_000, allowMissingExp: true)
    }
    static func decryptOptions(_ algs: String...) -> JweDecryptOptions { JweDecryptOptions(allowedAlgs: algs, allowedEnc: ["A256GCM"]) }
    static func encryptOptions(_ alg: String, to jwk: String) -> JweEncryptOptions {
        JweEncryptOptions(enc: "A256GCM", recipients: [JweRecipient(alg: alg, key: jwk)])
    }

    /// The key a decrypting call uses, and the JWK to encrypt to.
    static func decrypter(_ kind: Kind, _ alg: String, failAt: Method? = nil, failure: Error? = nil) -> (PlatformKey, SoftKey, String) {
        let soft = SoftKey(kind, algs: [alg], failAt: failAt, failure: failure)
        return (soft, soft, publicJwk(kind))
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

    // MARK: - Signing (RFC 7515 §5.1; RFC 7518 §3.3, §3.4; ADR 0071 §3)

    func signs(_ kind: Kind, _ alg: String) throws {
        let key = SoftKey(kind, algs: [alg])
        let token = try jwsSignCompactWithPlatformKey(payload: Self.payload, key: key, options: Self.signOptions(alg))
        XCTAssertEqual(key.privateCalls, 1, alg)
        let verified = try jwsVerifyCompact(token: token, key: Self.publicJwk(kind), options: JwsVerifyOptions(allowedAlgs: [alg]))
        XCTAssertEqual(verified.payload, Self.payload, alg)
        let jwt = try jwtSignWithPlatformKey(claims: Self.claims, key: key, options: JwtSignOptions(alg: alg))
        XCTAssertEqual(try jwtVerify(token: jwt, key: Self.publicJwk(kind), options: Self.verifyOptions(alg)).claims, Self.claims, alg)
    }

    func testEs256SignsAJwsAndAJwtTheJwkVerifies() throws { try signs(Self.ec, "ES256") }

    func testRs256SignsAJwsAndAJwtTheJwkVerifies() throws { try signs(Self.rsa, "RS256") }

    // MARK: - Decryption (RFC 7516 §5.2; RFC 7518 §4.3, §4.6; ADR 0071 §4)

    func decrypts(_ kind: Kind, _ alg: String) throws {
        let (key, soft, jwk) = Self.decrypter(kind, alg)
        let compact = try jweEncryptCompact(plaintext: Self.payload, options: Self.encryptOptions(alg, to: jwk))
        XCTAssertEqual(try jweDecryptCompactWithPlatformKey(token: compact, key: key, options: Self.decryptOptions(alg)).plaintext, Self.payload, alg)
        let json = try jweEncryptJson(plaintext: Self.payload, options: Self.encryptOptions(alg, to: jwk), form: "general")
        XCTAssertEqual(try jweDecryptJsonWithPlatformKey(jwe: json, key: key, options: Self.decryptOptions(alg)).plaintext, Self.payload, alg)
        XCTAssertEqual(soft.privateCalls, 2, alg)
    }

    func testEcdhEsDecryptsCompactAndJson() throws {
        try decrypts(Self.ec, "ECDH-ES")
        try decrypts(Self.ec, "ECDH-ES+A256KW")
    }

    func testRsaOaep256DecryptsCompactAndJson() throws { try decrypts(Self.rsa, "RSA-OAEP-256") }

    func testNestedJwtDecryptsWithOneKeyAndWithAJwkSet() throws {
        let signed = try jwtSignWithPlatformKey(claims: Self.claims, key: SoftKey(Self.ec, algs: ["ES256"]), options: JwtSignOptions(alg: "ES256"))
        let verifyJwk = Self.publicJwk(Self.ec)
        for (kind, alg) in [(Self.ec, "ECDH-ES"), (Self.rsa, "RSA-OAEP-256")] {
            let (key, _, jwk) = Self.decrypter(kind, alg)
            let token = try jwtEncryptNested(signedJwt: signed, options: Self.encryptOptions(alg, to: jwk))
            let one = try jwtDecryptNestedWithPlatformKey(
                token: token, decryptKey: key, decryptOptions: Self.decryptOptions(alg), key: verifyJwk, options: Self.verifyOptions("ES256"))
            XCTAssertEqual(one.inner.claims, Self.claims, alg)
            let set = try jwtDecryptNestedWithPlatformKeyAndJwks(
                token: token, decryptKey: key, decryptOptions: Self.decryptOptions(alg), jwks: #"{"keys":[\#(verifyJwk)]}"#,
                options: Self.verifyOptions("ES256"))
            XCTAssertEqual(set.inner.claims, Self.claims, alg)
            XCTAssertEqual(set.inner.keyIndex, 0, alg)
        }
    }

    // MARK: - Misuse and errors (PRD 0005 criterion 4; ADR 0071 §2, §4, §6)

    func testMisuseIsRefusedBeforeThePrivateKeyIsUsed() throws {
        let wrongFamily = SoftKey(Self.ec, algs: ["RS256"])
        expectCode("wrong family", "KeyAlgorithmMismatch") {
            try jwsSignCompactWithPlatformKey(payload: Self.payload, key: wrongFamily, options: Self.signOptions("RS256"))
        }
        XCTAssertEqual(wrongFamily.privateCalls, 0)
        let es384Only = SoftKey(Self.ec, algs: ["ES384"])
        expectCode("wrong algorithms()", "KeyAlgorithmMismatch") {
            try jwtSignWithPlatformKey(claims: Self.claims, key: es384Only, options: JwtSignOptions(alg: "ES256"))
        }
        XCTAssertEqual(es384Only.privateCalls, 0)
        let (key, soft, jwk) = Self.decrypter(Self.ec, "ECDH-ES")
        let token = try jweEncryptCompact(plaintext: Self.payload, options: Self.encryptOptions("ECDH-ES", to: jwk))
        expectCode("outside allowedAlgs", "AlgorithmNotAllowed") {
            try jweDecryptCompactWithPlatformKey(token: token, key: key, options: Self.decryptOptions("ECDH-ES+A256KW"))
        }
        XCTAssertEqual(soft.privateCalls, 0)
    }

    func testASignatureByAnotherKeyIsPlatformKeyFailed() {
        let impostor = SoftKey(Self.ec, algs: ["ES256"], signer: Self.p256())
        expectCode("another key's JWS", "PlatformKeyFailed") {
            try jwsSignCompactWithPlatformKey(payload: Self.payload, key: impostor, options: Self.signOptions("ES256"))
        }
        expectCode("another key's JWT", "PlatformKeyFailed") {
            try jwtSignWithPlatformKey(claims: Self.claims, key: impostor, options: JwtSignOptions(alg: "ES256"))
        }
    }

    func testTheKeysErrorsSurfaceAsThePolyjoseCodes() throws {
        let (_, _, ecJwk) = Self.decrypter(Self.ec, "ECDH-ES")
        let ecdhToken = try jweEncryptCompact(plaintext: Self.payload, options: Self.encryptOptions("ECDH-ES", to: ecJwk))
        let rsaToken = try jweEncryptCompact(plaintext: Self.payload, options: Self.encryptOptions("RSA-OAEP-256", to: Self.publicJwk(Self.rsa)))
        for (thrown, code) in [(PlatformKeyError.NotFound, "KeyNotFound"), (.UserAuthenticationRequired, "UserAuthenticationRequired")] {
            let signer = SoftKey(Self.ec, algs: ["ES256"], failAt: .sign, failure: thrown)
            expectCode("sign throws \(thrown)", code) {
                try jwsSignCompactWithPlatformKey(payload: Self.payload, key: signer, options: Self.signOptions("ES256"))
            }
            let (agreer, _, _) = Self.decrypter(Self.ec, "ECDH-ES", failAt: .agree, failure: thrown)
            expectCode("agree throws \(thrown)", code) {
                try jweDecryptCompactWithPlatformKey(token: ecdhToken, key: agreer, options: Self.decryptOptions("ECDH-ES"))
            }
            let (decrypter, _, _) = Self.decrypter(Self.rsa, "RSA-OAEP-256", failAt: .decryptKey, failure: thrown)
            expectCode("decryptKey throws \(thrown)", code) {
                try jweDecryptCompactWithPlatformKey(token: rsaToken, key: decrypter, options: Self.decryptOptions("RSA-OAEP-256"))
            }
        }
        // `failed` on decrypt is one DecryptionFailed (RFC 7516 §11.5, ADR 0071 §4); on sign, PlatformKeyFailed.
        let (agreer, _, _) = Self.decrypter(Self.ec, "ECDH-ES", failAt: .agree, failure: PlatformKeyError.Failed)
        expectCode("agree throws failed", "DecryptionFailed") {
            try jweDecryptCompactWithPlatformKey(token: ecdhToken, key: agreer, options: Self.decryptOptions("ECDH-ES"))
        }
        let (decrypter, _, _) = Self.decrypter(Self.rsa, "RSA-OAEP-256", failAt: .decryptKey, failure: PlatformKeyError.Failed)
        expectCode("decryptKey throws failed", "DecryptionFailed") {
            try jweDecryptCompactWithPlatformKey(token: rsaToken, key: decrypter, options: Self.decryptOptions("RSA-OAEP-256"))
        }
        let signer = SoftKey(Self.ec, algs: ["ES256"], failAt: .sign, failure: PlatformKeyError.Failed)
        expectCode("sign throws failed", "PlatformKeyFailed") {
            try jwsSignCompactWithPlatformKey(payload: Self.payload, key: signer, options: Self.signOptions("ES256"))
        }
    }

    /// ADR 0071 §5: any other error from any method becomes `failed`, so a signing call fails with
    /// PlatformKeyFailed and a decrypting call with DecryptionFailed (ADR 0071 §4). The `NSError`'s
    /// text holds the marker, which appears in no polyjose message or printed form.
    func testAnUnexpectedHostErrorFailsTheCallAndItsTextIsDropped() throws {
        let thrown = NSError(domain: "dev.polyjose.test.\(Self.marker)", code: 7, userInfo: [NSLocalizedDescriptionKey: "the platform said \(Self.marker)"])
        let (_, _, ecJwk) = Self.decrypter(Self.ec, "ECDH-ES")
        let ecdhToken = try jweEncryptCompact(plaintext: Self.payload, options: Self.encryptOptions("ECDH-ES", to: ecJwk))
        let rsaToken = try jweEncryptCompact(plaintext: Self.payload, options: Self.encryptOptions("RSA-OAEP-256", to: Self.publicJwk(Self.rsa)))
        var cases: [(String, String, () throws -> Any)] = []
        for method in [Method.publicJwk, .algorithms, .sign] {
            let key = SoftKey(Self.ec, algs: ["ES256"], failAt: method, failure: thrown)
            cases.append(("JWS sign, \(method) throws", "PlatformKeyFailed", {
                try jwsSignCompactWithPlatformKey(payload: Self.payload, key: key, options: Self.signOptions("ES256"))
            }))
            cases.append(("JWT sign, \(method) throws", "PlatformKeyFailed", {
                try jwtSignWithPlatformKey(claims: Self.claims, key: key, options: JwtSignOptions(alg: "ES256"))
            }))
        }
        for method in [Method.publicJwk, .algorithms, .agree] {
            let (key, _, _) = Self.decrypter(Self.ec, "ECDH-ES", failAt: method, failure: thrown)
            cases.append(("ECDH-ES decrypt, \(method) throws", "DecryptionFailed", {
                try jweDecryptCompactWithPlatformKey(token: ecdhToken, key: key, options: Self.decryptOptions("ECDH-ES"))
            }))
        }
        let (rsaKey, _, _) = Self.decrypter(Self.rsa, "RSA-OAEP-256", failAt: .decryptKey, failure: thrown)
        cases.append(("RSA-OAEP-256 decrypt, decryptKey throws", "DecryptionFailed", {
            try jweDecryptCompactWithPlatformKey(token: rsaToken, key: rsaKey, options: Self.decryptOptions("RSA-OAEP-256"))
        }))
        for (what, code, call) in cases {
            guard let error = polyjoseError(what, call) else { continue }
            XCTAssertEqual(error.code(), code, what)
            for text in [error.code(), "\(error)", String(describing: error), String(reflecting: error), error.localizedDescription] {
                XCTAssertFalse(text.contains(Self.marker), "\(what): the host error's text reached polyjose: \(text)")
            }
        }
    }
}
