// Hand-written, not generated: the redacted printing of the records that hold a secret (ADR 0065,
// superseding the printing residual of ADR 0030 §3 and §7). The generated Polyjose.swift is left
// as UniFFI writes it (ADR 0032 §4); these are the "few hand-written extension members" ADR 0030
// §1 allows, and scripts/check-binding-api.sh (swift mode) allows exactly these three
// conformances, with exactly their three members, on exactly these six records.
//
// The secret fields are the ones ADR 0030 §7 lists as secret-bearing:
// - private JWKs and PBES2 passwords: `JwsSigner.key`, `JweRecipient.key` (RFC 7517 §4,
//   RFC 7518 §4.8);
// - JWS payloads, treated as secret: `JwsVerified.payload`, `JwsVerifyOptions.detachedPayload`
//   (RFC 7515 §2 and Appendix F; ADR 0049 §4);
// - JWE plaintext: `JweDecrypted.plaintext` (RFC 7516 §5.2 step 16);
// - `aad`: `JweDecrypted.aad`, `JweEncryptOptions.aad` (RFC 7516 §7.2.1; ADR 0050 §4).
// `JweEncryptOptions.recipients` prints each `JweRecipient` through its own redacted forms.
// Not secret, so printed as before: `JweRecipient.apu`/`apv` (public party information,
// RFC 7518 §4.6.1.2-§4.6.1.3), every header, and JWT claims (ADR 0058 decision 2, ADR 0065 §3).

import Foundation

/// A secret field's printed form: its type and length only, never its content (ADR 0065 §1).
/// `<redacted, N chars>` for a `String`, N being its `count` (Characters), and
/// `<redacted, N bytes>` for a `Data`; an absent optional secret prints `nil`.
private struct Redacted: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    let description: String
    var debugDescription: String { description }
    /// No children, so `dump` prints the form on one line and no byte of the secret (ADR 0065 §2).
    var customMirror: Mirror { Mirror(self, children: [:]) }

    init(_ secret: String) { description = "<redacted, \(secret.count) chars>" }
    init(_ secret: Data?) { description = secret.map { "<redacted, \($0.count) bytes>" } ?? "nil" }
}

/// A record printed as the generated struct prints by default, `Type(label: value, ...)` with each
/// value in its debug form, and the type name qualified by the module in the debug forms
/// (`debugDescription`, `String(reflecting:)`, `debugPrint`). The secret values are already
/// ``Redacted``.
private func printed(_ type: Any.Type, debug: Bool, _ fields: [(String, Any)]) -> String {
    let name = debug ? String(reflecting: type) : String(describing: type)
    let list = fields.map { "\($0.0): \(String(reflecting: $0.1))" }.joined(separator: ", ")
    return "\(name)(\(list))"
}

/// A record's Mirror for `dump` and other reflection: every field, in declaration order, as a
/// struct, with the secret values already ``Redacted`` so no child holds the secret's bytes.
private func mirror<Subject>(_ subject: Subject, _ fields: [(String, Any)]) -> Mirror {
    Mirror(subject, children: fields.map { field -> Mirror.Child in (field.0, field.1) }, displayStyle: .struct)
}

extension JwsSigner: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { printed(Self.self, debug: false, printedFields) }
    public var debugDescription: String { printed(Self.self, debug: true, printedFields) }
    public var customMirror: Mirror { mirror(self, printedFields) }

    /// `key`, a private JWK (RFC 7517 §4), is redacted.
    private var printedFields: [(String, Any)] {
        [
            ("key", Redacted(key)),
            ("protectedHeader", protectedHeader as Any),
            ("protectedB64u", protectedB64u as Any),
            ("unprotectedHeader", unprotectedHeader as Any),
        ]
    }
}

extension JweRecipient: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { printed(Self.self, debug: false, printedFields) }
    public var debugDescription: String { printed(Self.self, debug: true, printedFields) }
    public var customMirror: Mirror { mirror(self, printedFields) }

    /// `key`, a JWK or a PBES2 password as an `oct` JWK (RFC 7518 §4.8), is redacted. `apu` and
    /// `apv` are public party information (RFC 7518 §4.6.1.2-§4.6.1.3) and print as before.
    private var printedFields: [(String, Any)] {
        [
            ("alg", alg),
            ("key", Redacted(key)),
            ("header", header as Any),
            ("apu", apu as Any),
            ("apv", apv as Any),
            ("p2c", p2c as Any),
            ("p2sLen", p2sLen as Any),
        ]
    }
}

extension JwsVerified: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { printed(Self.self, debug: false, printedFields) }
    public var debugDescription: String { printed(Self.self, debug: true, printedFields) }
    public var customMirror: Mirror { mirror(self, printedFields) }

    /// `payload`, the JWS Payload (RFC 7515 §2), is treated as secret (ADR 0049 §4) and redacted.
    private var printedFields: [(String, Any)] {
        [
            ("alg", alg),
            ("payload", Redacted(payload)),
            ("protectedHeader", protectedHeader as Any),
            ("unprotectedHeader", unprotectedHeader as Any),
            ("signatureIndex", signatureIndex),
        ]
    }
}

extension JweDecrypted: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { printed(Self.self, debug: false, printedFields) }
    public var debugDescription: String { printed(Self.self, debug: true, printedFields) }
    public var customMirror: Mirror { mirror(self, printedFields) }

    /// `plaintext` (RFC 7516 §5.2 step 16) and `aad` (RFC 7516 §7.2.1, ADR 0050 §4) are redacted.
    private var printedFields: [(String, Any)] {
        [
            ("plaintext", Redacted(plaintext)),
            ("header", header),
            ("protectedHeader", protectedHeader as Any),
            ("sharedUnprotectedHeader", sharedUnprotectedHeader as Any),
            ("recipientHeader", recipientHeader as Any),
            ("aad", Redacted(aad)),
            ("recipientIndex", recipientIndex),
        ]
    }
}

extension JweEncryptOptions: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { printed(Self.self, debug: false, printedFields) }
    public var debugDescription: String { printed(Self.self, debug: true, printedFields) }
    public var customMirror: Mirror { mirror(self, printedFields) }

    /// `aad` (RFC 7516 §7.2.1, ADR 0030 §7) is redacted; each of `recipients` prints through the
    /// redacted forms of `JweRecipient`.
    private var printedFields: [(String, Any)] {
        [
            ("enc", enc),
            ("recipients", recipients),
            ("protectedHeader", protectedHeader as Any),
            ("sharedUnprotectedHeader", sharedUnprotectedHeader as Any),
            ("aad", Redacted(aad)),
            ("compress", compress),
        ]
    }
}

extension JwsVerifyOptions: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { printed(Self.self, debug: false, printedFields) }
    public var debugDescription: String { printed(Self.self, debug: true, printedFields) }
    public var customMirror: Mirror { mirror(self, printedFields) }

    /// `detachedPayload`, a JWS Payload sent separately (RFC 7515 Appendix F), is treated as
    /// secret (ADR 0049 §4) and redacted.
    private var printedFields: [(String, Any)] {
        [
            ("allowedAlgs", allowedAlgs),
            ("detachedPayload", Redacted(detachedPayload)),
            ("maxInputLen", maxInputLen as Any),
            ("maxSignatures", maxSignatures as Any),
        ]
    }
}
