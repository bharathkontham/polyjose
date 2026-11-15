// Hand-written, not generated: `AppleKey`, the Apple implementation of `PlatformKey` (ADR 0072 §1,
// feature 0025 T03). It runs one Security framework call per private-key step and nothing else:
// no cryptography of its own, no CryptoKit key type, no JOSE logic. Every JOSE check (allow-lists,
// key binding, the `epk`, DER to R‖S, verify after sign, the KDF, key unwrap, content decryption)
// stays in the Rust core (ADR 0070 §4, ADR 0071 §2-§4). It is public API, listed with its members
// in scripts/check-binding-api.d/swift.host-types.

import CryptoKit  // `SecureEnclave.isAvailable` only, no key type (ADR 0072 §1)
import Foundation
import LocalAuthentication
import Security

/// A private key held by the Apple platform: a Secure Enclave key, or a Keychain software key
/// (ADR 0072 §1). polyjose asks it for one private-key step at a time (a signature, an ECDH
/// shared secret, an RSA-OAEP-256 decryption) and never sees the private key.
///
/// Pass it to the `…WithPlatformKey` operations, for example `jwsSignCompactWithPlatformKey` or
/// `jweDecryptCompactWithPlatformKey`. Encrypt or verify with ``publicJwk()``.
///
/// - **One algorithm per key** (RFC 8725 §3.1): a signing algorithm (`ES256`, `ES384`, `ES512`,
///   `RS256`…`RS512`, `PS256`…`PS512`), `RSA-OAEP-256`, or `ECDH-ES`, which also serves
///   `ECDH-ES+A128KW`, `+A192KW` and `+A256KW` (the decrypt allow-list picks, RFC 7518 §4.6).
/// - **``Protection/secureEnclave``** holds P-256 keys in the Secure Enclave: `ES256` and the
///   `ECDH-ES` family on P-256. This is the only hardware-bound protection.
/// - **``Protection/keychain``** keys are stored and protected by the OS, not hardware-bound; on
///   iOS, code that holds the key reference can export the private key.
/// - Every call is synchronous. A key created with an ``Access/Flags`` flag shows a system prompt
///   during the call and may block its thread while the prompt is up, so call it off the main
///   thread (ADR 0072 §4).
/// - Errors: `generate`, `open`, `delete` and `init` throw `PolyjoseError` (`UnsupportedAlgorithm`,
///   `KeyAlgorithmMismatch`, `InvalidKey`, `KeyNotFound`, `UserAuthenticationRequired`,
///   `PlatformKeyFailed`); the ``PlatformKey`` methods throw `PlatformKeyError`, which the core
///   reports as `KeyNotFound`, `UserAuthenticationRequired`, or `PlatformKeyFailed` when signing and
///   `DecryptionFailed` when decrypting (ADR 0071 §4, §6). No platform error text, tag or key is in
///   any of them.
/// - Printing shows the type and ``protection`` only, never a tag or key (ADR 0071 §7).
// One line, so scripts/check-binding-api.sh reads the members below as AppleKey's.
public final class AppleKey: PlatformKey, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable, @unchecked Sendable {
    /// Where a key lives (ADR 0072 §1).
    public enum Protection: Sendable {
        /// In the Secure Enclave: a hardware-bound P-256 key that cannot be exported.
        case secureEnclave
        /// A Keychain software key: stored and protected by the OS, not hardware-bound; on iOS,
        /// code that holds the key reference can export the private key.
        case keychain
    }

    /// How a generated key may be used (ADR 0072 §1): its accessibility, always "this device
    /// only", and optional user-authentication flags. Keys are never synchronizable.
    public struct Access {
        /// When the key can be used. Each option keeps the key on this device: it is never
        /// synchronized or restored to another device.
        public enum Accessibility: Sendable {
            /// `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (the default).
            case whenUnlockedThisDeviceOnly
            /// `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`.
            case afterFirstUnlockThisDeviceOnly
            /// `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`.
            case whenPasscodeSetThisDeviceOnly
        }

        /// User authentication the system asks for during each use of the key (the
        /// `SecAccessControlCreateFlags` of the same names). Any flag makes calls prompt, and block
        /// their thread while the prompt is up.
        public struct Flags: OptionSet, Sendable {
            public let rawValue: Int
            public init(rawValue: Int) { self.rawValue = rawValue }
            /// Biometry or the device passcode.
            public static let userPresence = Flags(rawValue: 1 << 0)
            /// Biometry, any enrolled finger or face.
            public static let biometryAny = Flags(rawValue: 1 << 1)
            /// Biometry, the set enrolled when the key was created.
            public static let biometryCurrentSet = Flags(rawValue: 1 << 2)
            /// The device passcode.
            public static let devicePasscode = Flags(rawValue: 1 << 3)
        }

        public var accessibility: Accessibility
        public var flags: Flags
        /// An authentication context the key's calls use (`kSecUseAuthenticationContext`), so one
        /// authentication can serve several calls.
        public var context: LAContext?

        public init(accessibility: Accessibility = .whenUnlockedThisDeviceOnly, flags: Flags = [], context: LAContext? = nil) {
            self.accessibility = accessibility
            self.flags = flags
            self.context = context
        }
    }

    /// Where the key lives, as the platform reports it (`kSecAttrTokenID`), not as requested.
    public let protection: Protection

    let key: SecKey  // internal: the tests read its attributes
    private let spec: Spec
    private let jwk: String

    // MARK: - Creating, finding and deleting keys

    /// Creates a permanent key under `tag` (`kSecAttrApplicationTag`) for `algorithm`, in the
    /// Secure Enclave or as a Keychain software key (ADR 0072 §1).
    ///
    /// - `keySizeInBits`: for RSA algorithms 2048 (the default), 3072 or 4096; for `ECDH-ES` the
    ///   curve, 256 (the default, P-256), 384 or 521; for `ES256`, `ES384`, `ES512` it is implied.
    /// - The key is `ThisDeviceOnly` and never synchronizable; a Secure Enclave key always gets
    ///   `.privateKeyUsage`. The data-protection keychain is always used, also on macOS, where a
    ///   permanent key needs a signed app with a keychain entitlement (Apple's rule).
    /// - `UnsupportedAlgorithm`: an algorithm or size this protection cannot serve, such as `ES384`
    ///   or RSA in the Secure Enclave, `EdDSA` or `HS256`, or `.secureEnclave` on a device without
    ///   one. There is no fallback to another protection (ADR 0072 §3).
    /// - `PlatformKeyFailed` when a key already exists under `tag`, or the platform fails.
    public static func generate(
        tag: String, algorithm: String, protection: Protection, access: Access = Access(), keySizeInBits: Int? = nil
    ) throws -> AppleKey {
        let (spec, size) = try checkedGeneration(algorithm: algorithm, protection: protection, keySizeInBits: keySizeInBits)
        let status = SecItemCopyMatching(query(tag: tag, context: nil) as CFDictionary, nil)
        if status == errSecSuccess {
            throw PolyjoseError.PlatformKeyFailed(detail: "a key already exists under this tag; delete it first")
        }
        if status != errSecItemNotFound { throw polyjoseError(platformKeyError(status: status)) }
        let key = try createKey(spec: spec, size: size, protection: protection, access: access, tag: Data(tag.utf8))
        do {
            return try AppleKey(key: key, spec: spec)
        } catch {
            _ = SecItemDelete(deleteQuery(tag: tag) as CFDictionary)  // not left behind unusable
            throw error
        }
    }

    /// Finds the private key stored under `tag` (`SecItemCopyMatching`) and binds it to
    /// `algorithm`. `context` is passed as `kSecUseAuthenticationContext`.
    ///
    /// - `KeyNotFound` when there is no key under `tag`.
    /// - `KeyAlgorithmMismatch` when the key cannot serve `algorithm` (RFC 8725 §3.1).
    public static func open(tag: String, algorithm: String, context: LAContext? = nil) throws -> AppleKey {
        guard let spec = Spec(algorithm) else { throw unsupported(algorithm) }
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query(tag: tag, context: context, returnRef: true) as CFDictionary, &result)
        guard status == errSecSuccess else { throw polyjoseError(platformKeyError(status: status)) }
        guard let result, CFGetTypeID(result) == SecKeyGetTypeID() else {
            throw PolyjoseError.PlatformKeyFailed(detail: "the platform returned no key")
        }
        return try AppleKey(key: result as! SecKey, spec: spec)  // swiftlint:disable:this force_cast
    }

    /// Deletes every key stored under `tag` (`SecItemDelete`). No key under `tag` is not an error.
    public static func delete(tag: String) throws {
        let status = SecItemDelete(deleteQuery(tag: tag) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw polyjoseError(platformKeyError(status: status))
        }
    }

    /// Wraps a private `SecKey` the app created itself, bound to `algorithm`.
    ///
    /// - `UnsupportedAlgorithm` for an algorithm no Apple platform key serves (`EdDSA`, `HS256`…).
    /// - `InvalidKey` for a public key.
    /// - `KeyAlgorithmMismatch` for a key of another type or size, or one the platform says cannot
    ///   do the algorithm (`SecKeyIsAlgorithmSupported`).
    public convenience init(secKey: SecKey, algorithm: String) throws {
        guard let spec = Spec(algorithm) else { throw Self.unsupported(algorithm) }
        try self.init(key: secKey, spec: spec)
    }

    private init(key: SecKey, spec: Spec) throws {
        let attributes = SecKeyCopyAttributes(key) as? [CFString: Any] ?? [:]
        guard attributes[kSecAttrKeyClass] as? String == kSecAttrKeyClassPrivate as String else {
            throw PolyjoseError.InvalidKey(detail: "not a private key")
        }
        guard attributes[kSecAttrKeyType] as? String == spec.keyType as String,
              let size = (attributes[kSecAttrKeySizeInBits] as? NSNumber)?.intValue, spec.sizes.contains(size),
              SecKeyIsAlgorithmSupported(key, spec.operation, spec.secKeyAlgorithm)
        else {
            throw PolyjoseError.KeyAlgorithmMismatch(detail: "the key cannot be used with this algorithm")
        }
        let token = attributes[kSecAttrTokenID] as? String
        let protection: Protection = token == kSecAttrTokenIDSecureEnclave as String ? .secureEnclave : .keychain
        guard protection == .keychain || size == 256 else {
            throw PolyjoseError.UnsupportedAlgorithm(detail: "the Secure Enclave serves P-256 keys only")
        }
        self.key = key
        self.spec = spec
        self.protection = protection
        self.jwk = try Self.publicJwk(of: key, spec: spec, size: size)
    }

    // MARK: - PlatformKey (ADR 0071 §1, §5)

    /// The public JWK, public members only (RFC 7517 §4; RFC 7518 §6.2.1, §6.3.1): EC from the
    /// X9.63 public key, RSA from the PKCS #1 `RSAPublicKey`, both read by the polyjose core.
    public func publicJwk() throws -> String { jwk }

    /// The JOSE algorithms the key is bound to: its one algorithm, or for `ECDH-ES` the four names
    /// of that family (RFC 7518 §4.6).
    public func algorithms() throws -> [String] { spec.algorithms }

    /// `SecKeyCreateSignature` over the JWS Signing Input (RFC 7515 §5.1 step 5): the X9.62 DER
    /// `Ecdsa-Sig-Value` for ES\* (RFC 7518 §3.4, the core converts it), the RSASSA-PKCS1-v1_5 or
    /// RSASSA-PSS signature for RS\* and PS\* (RFC 7518 §3.3, §3.5; Apple's PSS salt is the hash
    /// length, as RFC 7518 §3.5 requires).
    public func sign(alg: String, signingInput: Data) throws -> Data {
        guard case .sign = spec.kind, alg == spec.name else { throw PlatformKeyError.Failed }
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(key, spec.secKeyAlgorithm, signingInput as CFData, &error) else {
            throw Self.platformKeyError(error)
        }
        return signature as Data
    }

    /// `SecKeyCopyKeyExchangeResult` with `.ecdhKeyExchangeStandard`: Z, the x-coordinate of the
    /// shared point (RFC 7518 §4.6.2), with the validated `epk` given as `0x04 ‖ X ‖ Y`.
    public func agree(peerPublicKey: Data) throws -> Data {
        guard case .ecdh = spec.kind else { throw PlatformKeyError.Failed }
        let peerAttributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPublic]
        var error: Unmanaged<CFError>?
        guard let peer = SecKeyCreateWithData(peerPublicKey as CFData, peerAttributes as CFDictionary, &error) else {
            throw Self.platformKeyError(error)
        }
        guard let shared = SecKeyCopyKeyExchangeResult(key, .ecdhKeyExchangeStandard, peer, [:] as CFDictionary, &error) else {
            throw Self.platformKeyError(error)
        }
        return shared as Data
    }

    /// `SecKeyCreateDecryptedData` with `.rsaEncryptionOAEPSHA256`: RSAES-OAEP with SHA-256 and
    /// MGF1-SHA-256 (RFC 7518 §4.3). A failure is `failed`, which the core turns into the one
    /// `DecryptionFailed` of RFC 7516 §11.5.
    public func decryptKey(alg: String, encryptedKey: Data) throws -> Data {
        guard case .rsaOaep256 = spec.kind, alg == spec.name else { throw PlatformKeyError.Failed }
        var error: Unmanaged<CFError>?
        guard let cek = SecKeyCreateDecryptedData(key, .rsaEncryptionOAEPSHA256, encryptedKey as CFData, &error) else {
            throw Self.platformKeyError(error)
        }
        return cek as Data
    }

    // MARK: - Printing (ADR 0071 §7): the type and the protection only

    public var description: String { "AppleKey(protection: \(protection))" }
    public var debugDescription: String { "Polyjose.AppleKey(protection: \(protection))" }
    /// One child, the protection, so `dump` prints no tag and no key.
    public var customMirror: Mirror { Mirror(self, children: ["protection": protection], displayStyle: .class) }

    // MARK: - Internals

    /// What an algorithm needs of a key (ADR 0072 §1 table).
    struct Spec: @unchecked Sendable {
        enum Kind { case sign, ecdh, rsaOaep256 }
        let name: String
        let kind: Kind
        let keyType: CFString
        /// The allowed `kSecAttrKeySizeInBits`, the default first.
        let sizes: [Int]
        let secKeyAlgorithm: SecKeyAlgorithm
        let operation: SecKeyOperationType

        static let rsaSizes = [2048, 3072, 4096]

        init?(_ name: String) {
            switch name {
            case "ES256": self.init(name, .sign, kSecAttrKeyTypeECSECPrimeRandom, [256], .ecdsaSignatureMessageX962SHA256)
            case "ES384": self.init(name, .sign, kSecAttrKeyTypeECSECPrimeRandom, [384], .ecdsaSignatureMessageX962SHA384)
            case "ES512": self.init(name, .sign, kSecAttrKeyTypeECSECPrimeRandom, [521], .ecdsaSignatureMessageX962SHA512)
            case "RS256": self.init(name, .sign, kSecAttrKeyTypeRSA, Self.rsaSizes, .rsaSignatureMessagePKCS1v15SHA256)
            case "RS384": self.init(name, .sign, kSecAttrKeyTypeRSA, Self.rsaSizes, .rsaSignatureMessagePKCS1v15SHA384)
            case "RS512": self.init(name, .sign, kSecAttrKeyTypeRSA, Self.rsaSizes, .rsaSignatureMessagePKCS1v15SHA512)
            case "PS256": self.init(name, .sign, kSecAttrKeyTypeRSA, Self.rsaSizes, .rsaSignatureMessagePSSSHA256)
            case "PS384": self.init(name, .sign, kSecAttrKeyTypeRSA, Self.rsaSizes, .rsaSignatureMessagePSSSHA384)
            case "PS512": self.init(name, .sign, kSecAttrKeyTypeRSA, Self.rsaSizes, .rsaSignatureMessagePSSSHA512)
            case "ECDH-ES": self.init(name, .ecdh, kSecAttrKeyTypeECSECPrimeRandom, [256, 384, 521], .ecdhKeyExchangeStandard)
            case "RSA-OAEP-256": self.init(name, .rsaOaep256, kSecAttrKeyTypeRSA, Self.rsaSizes, .rsaEncryptionOAEPSHA256)
            default: return nil
            }
        }

        private init(_ name: String, _ kind: Kind, _ keyType: CFString, _ sizes: [Int], _ algorithm: SecKeyAlgorithm) {
            self.name = name
            self.kind = kind
            self.keyType = keyType
            self.sizes = sizes
            self.secKeyAlgorithm = algorithm
            switch kind {
            case .sign: operation = .sign
            case .ecdh: operation = .keyExchange
            case .rsaOaep256: operation = .decrypt
            }
        }

        var algorithms: [String] {
            kind == .ecdh ? ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"] : [name]
        }
    }

    /// The spec and key size `generate` uses, or `UnsupportedAlgorithm` (ADR 0072 §1, §3).
    static func checkedGeneration(algorithm: String, protection: Protection, keySizeInBits: Int?) throws -> (Spec, Int) {
        guard let spec = Spec(algorithm) else { throw unsupported(algorithm) }
        let size = keySizeInBits ?? spec.sizes[0]
        guard spec.sizes.contains(size) else {
            throw PolyjoseError.UnsupportedAlgorithm(detail: "this key size cannot be used with this algorithm")
        }
        if protection == .secureEnclave {
            guard spec.keyType == kSecAttrKeyTypeECSECPrimeRandom, size == 256 else {
                throw PolyjoseError.UnsupportedAlgorithm(detail: "the Secure Enclave serves ES256 and ECDH-ES on P-256 only")
            }
            guard SecureEnclave.isAvailable else {
                throw PolyjoseError.UnsupportedAlgorithm(detail: "this device has no Secure Enclave")
            }
        }
        return (spec, size)
    }

    /// The attributes of `SecKeyCreateRandomKey` (ADR 0072 §1, fixed key properties): a
    /// `ThisDeviceOnly` accessibility, never synchronizable, the data-protection keychain, and
    /// `.privateKeyUsage` for a Secure Enclave key. `tag` nil makes a non-permanent key (the macOS
    /// tests, where an unsigned binary cannot store one).
    static func generationAttributes(spec: Spec, size: Int, protection: Protection, access: Access, tag: Data?) throws -> [CFString: Any] {
        var error: Unmanaged<CFError>?
        guard let control = SecAccessControlCreateWithFlags(nil, accessibility(access.accessibility), accessFlags(access.flags, protection), &error) else {
            throw polyjoseError(platformKeyError(error))
        }
        var privateAttributes: [CFString: Any] = [kSecAttrIsPermanent: tag != nil, kSecAttrAccessControl: control]
        if let tag { privateAttributes[kSecAttrApplicationTag] = tag }
        var attributes: [CFString: Any] = [
            kSecAttrKeyType: spec.keyType,
            kSecAttrKeySizeInBits: size,
            kSecAttrSynchronizable: false,
            kSecUseDataProtectionKeychain: true,
            kSecPrivateKeyAttrs: privateAttributes,
        ]
        if protection == .secureEnclave { attributes[kSecAttrTokenID] = kSecAttrTokenIDSecureEnclave }
        if let context = access.context { attributes[kSecUseAuthenticationContext] = context }
        return attributes
    }

    static func accessibility(_ value: Access.Accessibility) -> CFString {
        switch value {
        case .whenUnlockedThisDeviceOnly: return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        case .afterFirstUnlockThisDeviceOnly: return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        case .whenPasscodeSetThisDeviceOnly: return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        }
    }

    /// The `SecAccessControlCreateFlags` of `flags`, plus `.privateKeyUsage` in the Secure Enclave.
    static func accessFlags(_ flags: Access.Flags, _ protection: Protection) -> SecAccessControlCreateFlags {
        var result: SecAccessControlCreateFlags = protection == .secureEnclave ? .privateKeyUsage : []
        if flags.contains(.userPresence) { result.insert(.userPresence) }
        if flags.contains(.biometryAny) { result.insert(.biometryAny) }
        if flags.contains(.biometryCurrentSet) { result.insert(.biometryCurrentSet) }
        if flags.contains(.devicePasscode) { result.insert(.devicePasscode) }
        return result
    }

    static func createKey(spec: Spec, size: Int, protection: Protection, access: Access, tag: Data?) throws -> SecKey {
        let attributes = try generationAttributes(spec: spec, size: size, protection: protection, access: access, tag: tag)
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw polyjoseError(platformKeyError(error))
        }
        return key
    }

    /// A non-permanent key, for the macOS tests (ADR 0072 §6.1).
    static func generateEphemeral(algorithm: String, protection: Protection, access: Access = Access(), keySizeInBits: Int? = nil) throws -> AppleKey {
        let (spec, size) = try checkedGeneration(algorithm: algorithm, protection: protection, keySizeInBits: keySizeInBits)
        return try AppleKey(key: createKey(spec: spec, size: size, protection: protection, access: access, tag: nil), spec: spec)
    }

    private static func query(tag: String, context: LAContext?, returnRef: Bool = false) -> [CFString: Any] {
        var query: [CFString: Any] = [
            kSecClass: kSecClassKey,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecAttrApplicationTag: Data(tag.utf8),
            kSecUseDataProtectionKeychain: true,
            kSecMatchLimit: kSecMatchLimitOne,
        ]
        if returnRef { query[kSecReturnRef] = true }
        if let context { query[kSecUseAuthenticationContext] = context }
        return query
    }

    private static func deleteQuery(tag: String) -> [CFString: Any] {
        [kSecClass: kSecClassKey, kSecAttrApplicationTag: Data(tag.utf8), kSecUseDataProtectionKeychain: true]
    }

    private static func unsupported(_ algorithm: String) -> PolyjoseError {
        algorithm.hasPrefix("ECDH-ES+")
            ? .UnsupportedAlgorithm(detail: "bind the key to ECDH-ES, which also serves the ECDH-ES+A*KW algorithms")
            : .UnsupportedAlgorithm(detail: "no Apple platform key serves this algorithm")
    }

    /// The public JWK of `key` (RFC 7517 §4), imported by the core so it is checked there too.
    private static func publicJwk(of key: SecKey, spec: Spec, size: Int) throws -> String {
        guard let publicKey = SecKeyCopyPublicKey(key),
              let external = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?
        else {
            throw PolyjoseError.PlatformKeyFailed(detail: "the platform returned no public key")
        }
        if spec.keyType == kSecAttrKeyTypeRSA {
            return try jwkFromDer(der: external, format: "pkcs1")  // RFC 8017 A.1.1 RSAPublicKey
        }
        // ANSI X9.63 uncompressed point, 0x04 ‖ X ‖ Y (SEC 1 §2.3.3); RFC 7518 §6.2.1.
        let width = (size + 7) / 8
        guard external.count == 1 + 2 * width, external.first == 0x04 else {
            throw PolyjoseError.PlatformKeyFailed(detail: "the platform returned an unexpected public key")
        }
        let crv = size == 521 ? "P-521" : "P-\(size)"
        let x = base64urlEncode(data: external.dropFirst().prefix(width))
        let y = base64urlEncode(data: external.suffix(width))
        return try jwkParse(jwk: #"{"kty":"EC","crv":"\#(crv)","x":"\#(x)","y":"\#(y)"}"#)
    }

    // MARK: - Error mapping (ADR 0072 §1): a pure function of the platform's status or code

    /// `errSecItemNotFound` is `NotFound`; a cancelled, failed, lockout or not-interactive user
    /// authentication is `UserAuthenticationRequired`; any other status is `Failed`. None depends
    /// on a ciphertext (ADR 0071 §4: an RSA-OAEP padding failure is `errSecParam`, measured).
    static func platformKeyError(status: OSStatus) -> PlatformKeyError {
        switch status {
        case errSecItemNotFound: return .NotFound
        case errSecUserCanceled, errSecAuthFailed, errSecInteractionNotAllowed: return .UserAuthenticationRequired
        default: return .Failed
        }
    }

    /// The same mapping for an error domain and code: `NSOSStatusErrorDomain` statuses as above,
    /// and the `LAError` cancel, failure, lockout and not-interactive codes.
    static func platformKeyError(domain: String, code: Int) -> PlatformKeyError {
        if domain == NSOSStatusErrorDomain { return platformKeyError(status: OSStatus(truncatingIfNeeded: code)) }
        if domain == LAErrorDomain {
            var authentication: [LAError.Code] = [.userCancel, .appCancel, .systemCancel, .authenticationFailed, .notInteractive]
            #if !os(watchOS)  // watchOS has no biometry, and no LAError.Code.biometryLockout
            authentication.append(.biometryLockout)
            #endif
            return authentication.contains { $0.rawValue == code } ? .UserAuthenticationRequired : .Failed
        }
        return .Failed
    }

    /// Reads a `CFError`'s domain and code only, never its text, and releases it.
    static func platformKeyError(_ error: Unmanaged<CFError>?) -> PlatformKeyError {
        guard let error = error?.takeRetainedValue() else { return .Failed }
        return platformKeyError(domain: CFErrorGetDomain(error) as String, code: CFErrorGetCode(error))
    }

    /// A `PolyjoseError` with fixed text for the creating, finding and deleting calls (ADR 0071 §6).
    static func polyjoseError(_ error: PlatformKeyError) -> PolyjoseError {
        switch error {
        case .NotFound: return .KeyNotFound(detail: "no key under this tag")
        case .UserAuthenticationRequired: return .UserAuthenticationRequired(detail: "the key needs user authentication")
        case .Failed: return .PlatformKeyFailed(detail: "the platform key operation failed")
        }
    }
}
