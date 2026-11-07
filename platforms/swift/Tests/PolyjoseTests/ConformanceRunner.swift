import Foundation
import Polyjose

/// The Swift conformance runner (ADR 0008 layer 4, ADR 0034). It runs each vector file through the
/// **generated Swift API** (what users call), operation by operation as the Rust reference runner
/// `crates/polyjose/tests/conformance.rs` and the shared JS runner `bindings/js/conformance/
/// runner.ts` do, mapped by conformance/README.md "Binding runners" (Operation mapping), and
/// returns one ADR 0034 §2 result per file.
///
/// Rules (conformance/README.md "Rules for every runner"):
/// - a file that isn't strict JSON (duplicate members included, RFC 7493 §2.3) or isn't valid
///   against `schema.json` fails, whether or not it would be skipped;
/// - a vector whose `features` this build lacks is `skipped` with `reason: "feature:<names>"`
///   (ADR 0034 §3), and one whose `features_absent` this build has with `!<name>` after them
///   (ADR 0056 §2); nothing else is ever skipped;
/// - an unknown or unmapped operation, a broken vector, and any thrown error that isn't a
///   `PolyjoseError` are `fail`, never an outcome (implementer note 8);
/// - a `PolyjoseError` is the library's outcome and is compared by its `code()` (ADR 0030 §5);
/// - a success expectation lists exactly the outputs; values are compared as JSON values (member
///   order ignored, numbers as doubles, RFC 8259);
/// - JSON-object inputs (keys, JWK Sets, headers, claims, JSON JWS/JWE) are handed to the library
///   as their own compact text in file order, never re-serialized from a dictionary, so
///   `jwt.issue` claims keep their member order (ADR 0027 §1; implementer note 4);
/// - the clock is the vector's `now`, always (ADR 0028 §4): the runner never reads `Date()`;
/// - a boolean policy member set to `false` keeps the default (implementer note 6).
struct ConformanceRunner {
    /// One ADR 0034 §2 result. `reason` is the skip reason, or a failure message.
    struct Result: Sendable {
        enum Status: String, Sendable { case pass, fail, skipped }
        let id: String
        let op: String
        let status: Status
        /// The outcome: nil for ok, the error code otherwise. Absent (`hasActual` false) on a skip
        /// and on a failed runner check (conformance/README.md `results[].actual`).
        let actualError: String?
        let hasActual: Bool
        let reason: String?

        /// The results entry (conformance/schema/results.schema.json `result`).
        var json: JSONValue {
            var members: [(String, JSONValue)] = [("id", .string(id)), ("op", .string(op)), ("status", .string(status.rawValue))]
            if hasActual {
                members.append(
                    ("actual", actualError.map { .object([("ok", .bool(false)), ("error", .string($0))]) } ?? .object([("ok", .bool(true))])))
            }
            if let reason { members.append(("reason", .string(reason))) }
            return .object(members)
        }

        static func fail(id: String, op: String = "unknown", reason: String) -> Result {
            Result(id: id, op: op, status: .fail, actualError: nil, hasActual: false, reason: reason)
        }
    }

    /// The vector feature names this build enables. The binding configuration for 0.1.0 is the
    /// core's default features: no `fixed-rng` (ADR 0005), no `deflate` (ADR 0030 §4, ADR 0034 §3).
    static let bindingFeatures: [String] = []

    private let schema: SchemaChecker
    private let features: [String]

    init(schema: SchemaChecker, features: [String] = ConformanceRunner.bindingFeatures) {
        self.schema = schema
        self.features = features
    }

    /// Runs one vector file (ADR 0034 §1: its id is `<path>#0`).
    func run(_ file: VectorFile) -> Result {
        var op = "unknown"
        var source = "<missing>"
        func fail(_ problem: String, _ actual: Outcome? = nil) -> Result {
            let error: String?
            if case .failure(let code) = actual { error = code } else { error = nil }
            return Result(
                id: file.id, op: op, status: .fail, actualError: error, hasActual: actual != nil,
                reason: "\(file.path) (source: \(source)): \(problem)")
        }

        let bytes = [UInt8](file.bytes)
        let text: JSONText
        let value: JSONValue
        do {
            text = JSONText(bytes: bytes, root: try JSONScanner.scan(bytes))
            value = try JSONValue.parse(file.bytes)
        } catch {
            return fail("not a valid JSON text (\(error)); see conformance/schema.json")
        }
        if let name = value["operation"]?.stringValue { op = name }
        if let s = value["source"]?.stringValue, s.contains(where: { !$0.isWhitespace }) { source = s }
        do {
            if let violation = try schema.violation(value) { return fail(violation) }
            let vector = Vector(value)
            try crossMemberRules(vector)
            // ADR 0034 §3: the missing `features`, in order; then ADR 0056 §2: each enabled
            // `features_absent` one as `!<name>`.
            let skip =
                vector.features.filter { !features.contains($0) }
                + vector.featuresAbsent.filter { features.contains($0) }.map { "!\($0)" }
            if !skip.isEmpty {
                return Result(
                    id: file.id, op: op, status: .skipped, actualError: nil, hasActual: false,
                    reason: "feature:\(skip.joined(separator: ","))")
            }
            let outcome = try execute(vector, text)
            if let mismatch = compare(vector.expect, outcome) { return fail(mismatch, outcome) }
            let error: String?
            if case .failure(let code) = outcome { error = code } else { error = nil }
            return Result(id: file.id, op: op, status: .pass, actualError: error, hasActual: true, reason: nil)
        } catch let e as HarnessError {
            return fail(e.message)
        } catch {
            return fail("exception in the runner or the binding: \(String(reflecting: error))")
        }
    }
}

// MARK: - Vectors, outcomes and errors

/// A broken vector or a failed runner check: the vector fails with this message.
private struct HarnessError: Error {
    let message: String
    init(_ message: String) { self.message = message }
}

/// The library refused: the vector's outcome is this code.
private struct LibraryError: Error {
    let code: String
}

/// A schema-valid vector, as the runner reads it.
private struct Vector {
    let operation: String
    let input: JSONValue
    let expect: JSONValue
    let features: [String]
    /// The features the build must not enable (ADR 0056).
    let featuresAbsent: [String]

    init(_ value: JSONValue) {
        operation = value["operation"]?.stringValue ?? ""
        input = value["input"] ?? .object([])
        expect = value["expect"] ?? .object([])
        features = value["features"]?.arrayValue?.compactMap(\.stringValue) ?? []
        featuresAbsent = value["features_absent"]?.arrayValue?.compactMap(\.stringValue) ?? []
    }
}

/// The outputs of an executed operation, in the order they were produced.
private final class Outputs {
    private(set) var members: [(String, JSONValue)] = []
    subscript(name: String) -> JSONValue? {
        get { members.first { $0.0 == name }?.1 }
        set {
            members.removeAll { $0.0 == name }
            if let newValue { members.append((name, newValue)) }
        }
    }
}

private enum Outcome {
    case success(Outputs)
    case failure(String)
}

/// The rules tying members together that the schema can't state, as the Rust runner's
/// `check_jwe_encrypt_features` and `check_jwt_issue` check them (conformance/README.md).
private func crossMemberRules(_ vector: Vector) throws {
    let input = vector.input
    let expect = vector.expect
    // ADR 0056 §3: no name both needed and forbidden.
    if let both = vector.featuresAbsent.first(where: { vector.features.contains($0) }) {
        throw HarnessError("/features_absent: \"\(both)\" is listed in `features` too")
    }
    if vector.operation == "jwe.encrypt" {
        for member in ["rng_b64u", "protected_b64u"] where input.has(member) && !vector.features.contains("fixed-rng") {
            throw HarnessError("/features: `input/\(member)` needs \"fixed-rng\" listed in `features`")
        }
        // ADR 0056 §4: `deflate` in either list.
        if input.has("compress"), !vector.features.contains("deflate"), !vector.featuresAbsent.contains("deflate") {
            throw HarnessError("/features: `input/compress` needs \"deflate\" listed in `features` or `features_absent`")
        }
    }
    if vector.operation == "jwt.issue" {
        let ok = expect["ok"].map { JSONValue.equal($0, .bool(true)) } ?? false
        let encrypt = input.has("encrypt")
        let validate = input.has("validate")
        if ok, expect.has("token"), encrypt {
            throw HarnessError(
                "/expect/token: an encrypted token is randomized (RFC 7516 §5.1); expect {\"ok\": true} and give `validate`")
        }
        if ok, !expect.has("token"), !validate, !encrypt {
            throw HarnessError("/input/validate: required when the expectation has no `token`")
        }
        if !ok, validate {
            throw HarnessError("/input/validate: used only when the issue succeeds, so a failure vector has none")
        }
    }
}

/// Compares an outcome with the expectation, as the Rust runner's `compare` does.
private func compare(_ expect: JSONValue, _ outcome: Outcome) -> String? {
    if let ok = expect["ok"], JSONValue.equal(ok, .bool(true)) {
        guard case .success(let out) = outcome else {
            if case .failure(let code) = outcome { return "expected success, got error \(code)" }
            return "expected success"
        }
        for (name, want) in expect.objectMembers ?? [] where name != "ok" {
            guard let got = out[name] else { return "`\(name)`: expected \(want), got nothing" }
            if !JSONValue.equal(want, got) { return "`\(name)`: expected \(want), got \(got)" }
        }
        for (name, got) in out.members where !expect.has(name) {
            return "`\(name)`: expected nothing, got \(got)"
        }
        return nil
    }
    let want = expect["error"]?.stringValue ?? "<none>"
    switch outcome {
    case .success(let out):
        return "expected error \(want), but the operation succeeded with \(JSONValue.object(out.members))"
    case .failure(let code):
        return code == want ? nil : "expected error \(want), got error \(code)"
    }
}

// MARK: - Library calls and value helpers

/// Calls the library: a `PolyjoseError` becomes the outcome (its `code()`, ADR 0030 §5); any other
/// error propagates and fails the vector.
private func lib<T>(_ call: () throws -> T) throws -> T {
    do {
        return try call()
    } catch let e as PolyjoseError {
        throw LibraryError(code: e.code())
    }
}

/// A library call inside a runner check (round trip, decoding): any failure fails the vector.
private func check<T>(_ what: String, _ call: () throws -> T) throws -> T {
    do {
        return try lib(call)
    } catch let e as LibraryError {
        throw HarnessError("\(what) (\(e.code))")
    }
}

private func str(_ v: JSONValue?, _ name: String) throws -> String {
    guard let s = v?.stringValue else { throw HarnessError("`\(name)` is not a string") }
    return s
}

private func strs(_ v: JSONValue?, _ name: String) throws -> [String] {
    guard let items = v?.arrayValue else { throw HarnessError("`\(name)` is not an array") }
    return try items.map { try str($0, name) }
}

/// A count member (`u32` in ADR 0030 §2), or nil when absent or not a number.
private func count(_ v: JSONValue?, _ name: String) throws -> UInt32? {
    guard let n = v?.numberValue else { return nil }
    guard let value = UInt32(exactly: n) else { throw HarnessError("`\(name)` (\(n)) is not a u32 count") }
    return value
}

private func isTrue(_ v: JSONValue?) -> Bool {
    if case .bool(true) = v ?? .null { return true }
    return false
}

/// A `*_b64u` input's octets. A non-canonical value is a broken vector, never an outcome.
private func decode(_ v: JSONValue?, _ name: String) throws -> Data {
    let text = try str(v, name)
    return try check("`\(name)` is not canonical base64url; the runner must decode it") { try base64urlDecode(text: text) }
}

private func hexDecode(_ hex: String) throws -> Data {
    let digits = Array(hex.utf8)
    guard digits.count % 2 == 0 else { throw HarnessError("odd-length hex") }
    var out = Data(capacity: digits.count / 2)
    var i = 0
    while i < digits.count {
        guard let byte = UInt8(String(decoding: digits[i..<i + 2], as: UTF8.self), radix: 16) else {
            throw HarnessError("invalid hex")
        }
        out.append(byte)
        i += 2
    }
    return out
}

private func hexEncode(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

/// Parses a JSON text the library returned.
private func parseOutput(_ text: String, _ what: String) throws -> JSONValue {
    do {
        return try JSONValue.parse(text)
    } catch {
        throw HarnessError("\(what) does not parse as JSON")
    }
}

/// The vector's own compact text at `path`.
private func at(_ text: JSONText, _ path: [PathStep]) throws -> String {
    guard let value = text.text(path) else {
        throw HarnessError("no value at /\(path.map(\.description).joined(separator: "/"))")
    }
    return value
}

// MARK: - Operations

/// The members a generated private key has (RFC 7518 §6.2.1-§6.2.2, RFC 8037 §2, RFC 7518
/// §6.4.1), plus `alg`.
private let generatedMembers: [String: [String]] = [
    "EC": ["alg", "crv", "d", "kty", "x", "y"],
    "OKP": ["alg", "crv", "d", "kty", "x"],
    "oct": ["alg", "k", "kty"],
]

/// ``generatedMembers`` of a key bound to no algorithm (`jwkGenerateOct`, `Ec`, `Okp`): no `alg`.
private let unboundMembers: [String: [String]] = [
    "EC": ["crv", "d", "kty", "x", "y"],
    "OKP": ["crv", "d", "kty", "x"],
    "oct": ["k", "kty"],
]

/// The payload or plaintext of every `use_with` round trip: the ASCII octets of `polyjose`
/// (ADR 0034 §6).
private let useWithPayload = Data("polyjose".utf8)

extension ConformanceRunner {
    /// Runs the vector's operation; a library refusal is the outcome.
    fileprivate func execute(_ vector: Vector, _ text: JSONText) throws -> Outcome {
        let out = Outputs()
        do {
            try dispatch(vector, text, out)
        } catch let e as LibraryError {
            return .failure(e.code)
        }
        return .success(out)
    }

    /// One handler per schema operation, each mirroring the Rust runner's function of the same
    /// name (`run_jws_sign`, `run_jwe_decrypt`, ...) and the JS runner's handler. The Swift call it
    /// maps to (ADR 0030 §4) is named in each comment.
    private func dispatch(_ vector: Vector, _ text: JSONText, _ out: Outputs) throws {
        let input = vector.input
        let expect = vector.expect
        switch vector.operation {
        case "b64url.encode":
            // base64urlEncode(hex-decoded bytes_hex); RFC 4648 §5. The hex is the runner's own.
            let bytes = try hexDecode(try str(input["bytes_hex"], "bytes_hex"))
            out["b64u"] = .string(base64urlEncode(data: bytes))
        case "b64url.decode":
            // base64urlDecode(b64u), hex-encoded; RFC 4648 §5.
            let b64u = try str(input["b64u"], "b64u")
            out["bytes_hex"] = .string(hexEncode(try lib { try base64urlDecode(text: b64u) }))
        case "jwk.thumbprint":
            // jwkThumbprint + jwkThumbprintUri (RFC 7638 §3, RFC 9278 §3). The hash is passed as
            // given and an absent one as nil, the core default (ADR 0054 §9).
            let hash = try input["hash"].map { try str($0, "hash") }
            let jwk = try at(text, ["input", "jwk"])
            out["thumbprint"] = .string(try lib { try jwkThumbprint(jwk: jwk, hash: hash) })
            out["thumbprint_uri"] = .string(try lib { try jwkThumbprintUri(jwk: jwk, hash: hash) })
        case "jwks.select":
            // jwksSelect(jwks, JwkSelector { kid, alg, keyUse }) (RFC 7517 §5; ADR 0054 §1-§4, §9):
            // each selector member as given and only when present.
            let criteria = input["selector"] ?? .object([])
            let selector = JwkSelector(
                kid: try criteria["kid"].map { try str($0, "kid") },
                alg: try criteria["alg"].map { try str($0, "alg") },
                keyUse: try criteria["key_use"].map { try str($0, "key_use") })
            let jwks = try at(text, ["input", "jwks"])
            let selected = try lib { try jwksSelect(jwks: jwks, selector: selector) }
            out["jwk"] = try parseOutput(selected, "the selected JWK")
        case "jws.sign":
            try jwsSign(input, expect, text, out)
        case "jws.verify":
            // jwsVerifyCompact (string) / jwsVerifyJson (object, as its text); RFC 7515 §5.2.
            let key = try at(text, ["input", "key"])
            let options = JwsVerifyOptions(
                allowedAlgs: try strs(input["allowed_algs"], "allowed_algs"),
                detachedPayload: try input["detached_payload_b64u"].map { try decode($0, "detached_payload_b64u") },
                maxInputLen: try count(input["max_input_len"], "max_input_len"),
                maxSignatures: try count(input["max_signatures"], "max_signatures"))
            let verified: JwsVerified
            if let token = input["jws"]?.stringValue {
                verified = try lib { try jwsVerifyCompact(token: token, key: key, options: options) }
            } else {
                let jws = try at(text, ["input", "jws"])
                verified = try lib { try jwsVerifyJson(jws: jws, key: key, options: options) }
            }
            out["payload_b64u"] = .string(base64urlEncode(data: verified.payload))
            out["alg"] = .string(verified.alg)
            out["signature_index"] = .number(Double(verified.signatureIndex))
        case "keys.import_pem":
            // jwkFromPem (ADR 0018 §3).
            let pem = try str(input["pem"], "pem")
            out["jwk"] = try imported(try lib { try jwkFromPem(pem: pem) })
        case "keys.import_der":
            // jwkFromDer(decoded der_b64u, format).
            let der = try decode(input["der_b64u"], "der_b64u")
            let format = try str(input["format"], "format")
            out["jwk"] = try imported(try lib { try jwkFromDer(der: der, format: format) })
        case "keys.export_pem":
            // jwkToPem(jwk, format); the JWK import inside is the first step.
            let jwk = try at(text, ["input", "jwk"])
            let format = try str(input["format"], "format")
            out["pem"] = .string(try lib { try jwkToPem(jwk: jwk, format: format) })
        case "keys.export_der":
            // jwkToDer(jwk, format), base64url.
            let jwk = try at(text, ["input", "jwk"])
            let format = try str(input["format"], "format")
            out["der_b64u"] = .string(base64urlEncode(data: try lib { try jwkToDer(jwk: jwk, format: format) }))
        case "keys.generate_for":
            // jwkGenerateForAlg(alg) (ADR 0018 §5), then the `use_with` round trip (ADR 0034 §6).
            let alg = try str(input["alg"], "alg")
            let jwk = try lib { try jwkGenerateForAlg(alg: alg) }
            out["shape"] = try generatedShape(jwk, generatedMembers)
            try echoUseWith(jwk, expect, out)
        case "keys.generate_oct":
            // jwkGenerateOct(len_bytes) (RFC 7518 §6.4.1); a shape with no `alg`.
            guard let len = try count(input["len_bytes"], "len_bytes") else { throw HarnessError("`len_bytes` is not a count") }
            let jwk = try lib { try jwkGenerateOct(lenBytes: len) }
            out["shape"] = try generatedShape(jwk, unboundMembers)
            try echoUseWith(jwk, expect, out)
        case "keys.generate_ec":
            // jwkGenerateEc(crv) (RFC 7518 §6.2, RFC 8812 §3.1).
            let crv = try str(input["crv"], "crv")
            let jwk = try lib { try jwkGenerateEc(crv: crv) }
            out["shape"] = try generatedShape(jwk, unboundMembers)
            try echoUseWith(jwk, expect, out)
        case "keys.generate_okp":
            // jwkGenerateOkp(crv) (RFC 8037 §2).
            let crv = try str(input["crv"], "crv")
            let jwk = try lib { try jwkGenerateOkp(crv: crv) }
            out["shape"] = try generatedShape(jwk, unboundMembers)
            try echoUseWith(jwk, expect, out)
        case "jwe.encrypt":
            try jweEncrypt(input, expect, text, out)
        case "jwe.decrypt":
            // jweDecryptCompact (string) / jweDecryptJson (object, as its text); RFC 7516 §5.2.
            let key = try at(text, ["input", "key"])
            let options = try jweDecryptOptions(input)
            let decrypted: JweDecrypted
            if let token = input["jwe"]?.stringValue {
                decrypted = try lib { try jweDecryptCompact(token: token, key: key, options: options) }
            } else {
                let jwe = try at(text, ["input", "jwe"])
                decrypted = try lib { try jweDecryptJson(jwe: jwe, key: key, options: options) }
            }
            out["plaintext_b64u"] = .string(base64urlEncode(data: decrypted.plaintext))
            out["recipient"] = .number(Double(decrypted.recipientIndex))
        case "jwt.validate":
            // jwtVerify / jwtVerifyWithJwks, or jwtDecryptNested(WithJwks) with `decrypt` (RFC 7519 §7.2).
            let token = try str(input["token"], "token")
            let verified = try jwtValidate(input, ["input"], token, text)
            out["claims"] = try parseOutput(verified.claims, "the validated claims")
            out["alg"] = .string(verified.alg)
            // ADR 0029 §4: present exactly when a key set verified; 0 is an index (note 2).
            if let index = verified.keyIndex { out["key_index"] = .number(Double(index)) }
        case "jwt.issue":
            try jwtIssue(input, expect, text, out)
        default:
            throw HarnessError("operation `\(vector.operation)` is not implemented by the Swift runner; a vector is never skipped")
        }
    }

    /// jws.sign → jwsSignCompact / jwsSignFlattened / jwsSignGeneral (RFC 7515 §5.1, §7).
    private func jwsSign(_ input: JSONValue, _ expect: JSONValue, _ text: JSONText, _ out: Outputs) throws {
        let serialization = try str(input["serialization"], "serialization")
        let payload = try decode(input["payload_b64u"], "payload_b64u")
        let detached = isTrue(input["detached"])
        let signersIn = input["signers"]?.arrayValue ?? []
        let signers = try signersIn.enumerated().map { i, s in
            JwsSigner(
                key: try at(text, ["input", "signers", .index(i), "key"]),
                protectedB64u: s["protected_b64u"]?.stringValue,
                // RFC 7515 §7.2.1; ADR 0045 §1: a signer may have only an unprotected header.
                unprotectedHeader: text.text(["input", "signers", .index(i), "header"]))
        }
        guard let first = signers.first else { throw HarnessError("`signers` is empty") }
        let signed: String
        switch serialization {
        case "compact":
            let options = JwsSignOptions(protectedB64u: first.protectedB64u, detached: detached)
            signed = try lib { try jwsSignCompact(payload: payload, key: first.key, options: options) }
        case "flattened":
            signed = try lib { try jwsSignFlattened(payload: payload, signer: first, detached: detached) }
        default:
            signed = try lib { try jwsSignGeneral(payload: payload, signers: signers, detached: detached) }
        }
        let jws: JSONValue = serialization == "compact" ? .string(signed) : try parseOutput(signed, "the signed JSON JWS")
        guard let verifyWith = expect["verify_with"], verifyWith.isObject else {
            out["jws"] = jws
            return
        }
        // Round trip (Rust `check_round_trip`): shape, verify with verify_with, same payload.
        let shapeOK: Bool
        switch serialization {
        case "compact": shapeOK = signed.split(separator: ".", omittingEmptySubsequences: false).count == 3
        case "flattened": shapeOK = jws.has("signature") && !jws.has("signatures")
        default: shapeOK = jws["signatures"]?.arrayValue?.count == signers.count
        }
        guard shapeOK else {
            throw HarnessError("round trip: the output is not a \(serialization) JWS with \(signers.count) signature(s)")
        }
        let key = try at(text, ["expect", "verify_with", "key"])
        let options = JwsVerifyOptions(
            allowedAlgs: try strs(verifyWith["allowed_algs"], "allowed_algs"), detachedPayload: detached ? payload : nil)
        let verified = try check("round trip: the signed JWS does not verify with verify_with") {
            serialization == "compact"
                ? try jwsVerifyCompact(token: signed, key: key, options: options)
                : try jwsVerifyJson(jws: signed, key: key, options: options)
        }
        guard verified.payload == payload else { throw HarnessError("round trip: the verified payload is not the signed one") }
        out["verify_with"] = verifyWith
    }

    /// jwe.encrypt → jweEncryptCompact / jweEncryptJson(form) (RFC 7516 §5.1, §7).
    private func jweEncrypt(_ input: JSONValue, _ expect: JSONValue, _ text: JSONText, _ out: Outputs) throws {
        if input.has("rng_b64u") || input.has("protected_b64u") {
            throw HarnessError("a reproducible encryption (rng_b64u, protected_b64u) is not in the binding API (ADR 0005)")
        }
        let serialization = try str(input["serialization"], "serialization")
        let plaintext = try decode(input["plaintext_b64u"], "plaintext_b64u")
        var recipients: [JweRecipient] = []
        for (i, r) in (input["recipients"]?.arrayValue ?? []).enumerated() {
            recipients.append(
                JweRecipient(
                    alg: try str(r["alg"], "alg"),
                    key: try at(text, ["input", "recipients", .index(i), "key"]),
                    header: text.text(["input", "recipients", .index(i), "header"]),
                    apu: try r["apu_b64u"].map { try decode($0, "apu_b64u") },
                    apv: try r["apv_b64u"].map { try decode($0, "apv_b64u") },
                    p2c: try count(r["p2c"], "p2c"),
                    p2sLen: try count(r["p2s_len"], "p2s_len")))
        }
        let options = JweEncryptOptions(
            enc: try str(input["enc"], "enc"),
            recipients: recipients,
            protectedHeader: text.text(["input", "protected"]),
            sharedUnprotectedHeader: text.text(["input", "unprotected"]),
            aad: try input["aad_b64u"].map { try decode($0, "aad_b64u") },
            compress: isTrue(input["compress"]))
        let encrypted = try lib {
            serialization == "compact"
                ? try jweEncryptCompact(plaintext: plaintext, options: options)
                : try jweEncryptJson(plaintext: plaintext, options: options, form: serialization)
        }
        let jwe: JSONValue =
            serialization == "compact" ? .string(encrypted) : try parseOutput(encrypted, "the encrypted JSON JWE")
        guard let decryptWith = expect["decrypt_with"], decryptWith.isObject else {
            out["jwe"] = jwe
            return
        }
        // Round trip (Rust `check_jwe_round_trip`): shape, decrypt with decrypt_with, same plaintext.
        let shapeOK: Bool
        switch serialization {
        case "compact": shapeOK = encrypted.split(separator: ".", omittingEmptySubsequences: false).count == 5
        case "flattened": shapeOK = jwe.has("ciphertext") && !jwe.has("recipients")
        default: shapeOK = jwe["recipients"]?.arrayValue?.count == recipients.count
        }
        guard shapeOK else {
            throw HarnessError("round trip: the output is not a \(serialization) JWE with \(recipients.count) recipient(s)")
        }
        let key = try at(text, ["expect", "decrypt_with", "key"])
        let policy = JweDecryptOptions(
            allowedAlgs: try strs(decryptWith["allowed_algs"], "allowed_algs"),
            allowedEnc: try strs(decryptWith["allowed_enc"], "allowed_enc"))
        let decrypted = try check("round trip: the encrypted JWE does not decrypt with decrypt_with") {
            serialization == "compact"
                ? try jweDecryptCompact(token: encrypted, key: key, options: policy)
                : try jweDecryptJson(jwe: encrypted, key: key, options: policy)
        }
        guard decrypted.plaintext == plaintext else {
            throw HarnessError("round trip: the decrypted plaintext is not the encrypted one")
        }
        out["decrypt_with"] = decryptWith
    }

    /// jwt.issue → jwtSign, then jwtEncryptNested with `encrypt` (RFC 7519 §7.1; ADR 0027 §7-§8).
    /// Exactly the calls of the README "Binding runners" table, in order, and none of the
    /// runner's own (no jwkParse pre-check).
    private func jwtIssue(_ input: JSONValue, _ expect: JSONValue, _ text: JSONText, _ out: Outputs) throws {
        let key = try at(text, ["input", "key"])
        let claims = try at(text, ["input", "claims"])
        let encrypt = input["encrypt"].flatMap { $0.isObject ? $0 : nil }
        let encryptKey = try encrypt.map { _ in try at(text, ["input", "encrypt", "key"]) }
        let alg = try str(input["alg"], "alg")
        // `typ` (implementer note 3): absent → the core default JWT; null → omitted (RFC 7519
        // §5.1); a string → set.
        var typ: String?
        var omitTyp = false
        if let value = input["typ"] {
            if case .null = value { omitTyp = true } else { typ = try str(value, "typ") }
        }
        let options = JwtSignOptions(alg: alg, typ: typ, omitTyp: omitTyp)
        var token = try lib { try jwtSign(claims: claims, key: key, options: options) }
        var parts = 3
        if let encrypt, let encryptKey {
            let signed = token
            let nested = JweEncryptOptions(
                enc: try str(encrypt["enc"], "enc"),
                recipients: [JweRecipient(alg: try str(encrypt["alg"], "alg"), key: encryptKey)])
            token = try lib { try jwtEncryptNested(signedJwt: signed, options: nested) }
            parts = 5
        }
        guard token.split(separator: ".", omittingEmptySubsequences: false).count == parts else {
            throw HarnessError("the issued token is not \(parts) compact parts")
        }
        if let validate = input["validate"], validate.isObject {
            // Round trip (Rust `check_jwt_issue_round_trip`): validates, with the issued alg and claims.
            let verified: JwtVerified
            do {
                verified = try jwtValidate(validate, ["input", "validate"], token, text)
            } catch let e as LibraryError {
                throw HarnessError("round trip: the issued token does not validate with `validate` (\(e.code))")
            }
            guard verified.alg == alg else {
                throw HarnessError("round trip: validated with alg \(verified.alg), issued with \(alg)")
            }
            let got = try parseOutput(verified.claims, "the validated claims")
            guard let issued = input["claims"], JSONValue.equal(got, issued) else {
                throw HarnessError("round trip: validated claims \(got) are not the issued \(claims)")
            }
        }
        if isTrue(expect["ok"]), expect.has("token") { out["token"] = .string(token) }
    }

    /// A PEM/DER import result; an `oct` key fails the vector whatever it expects (RFC 8725 §2.1).
    private func imported(_ jwk: String) throws -> JSONValue {
        let value = try parseOutput(jwk, "the imported JWK")
        if value["kty"]?.stringValue == "oct" { throw HarnessError("a PEM or DER import returned an oct key (RFC 8725 §2.1)") }
        return value
    }

    /// Rust `generated_shape`: private, exactly the RFC members of `members`, imports back
    /// unchanged (`jwkParse`); then the shape (`kty`, `crv`, `alg`, `k_octets`).
    private func generatedShape(_ jwkText: String, _ members: [String: [String]]) throws -> JSONValue {
        let jwk = try parseOutput(jwkText, "the generated JWK")
        let kty = jwk["kty"]?.stringValue ?? ""
        guard kty == "oct" || jwk.has("d") else { throw HarnessError("generate_for returned a public key") }
        let names = (jwk.objectMembers ?? []).map(\.0).sorted { Array($0.utf8).lexicographicallyPrecedes(Array($1.utf8)) }
        guard let expected = members[kty], names == expected else {
            throw HarnessError("generate_for returned a JWK with members \(names)")
        }
        let again = try check("the generated JWK does not import") { try jwkParse(jwk: jwkText) }
        guard JSONValue.equal(try parseOutput(again, "the re-imported JWK"), jwk) else {
            throw HarnessError("the generated JWK imports as a different key")
        }
        var shape: [(String, JSONValue)] = []
        for name in ["kty", "crv", "alg"] {
            if let value = jwk[name] { shape.append((name, value)) }
        }
        if jwk["k"]?.stringValue != nil {
            shape.append(("k_octets", .number(Double(try decode(jwk["k"], "the generated k").count))))
        }
        return .object(shape)
    }

    /// Runs the expectation's `use_with` round trip on the generated key, if it has one, and
    /// echoes it back as an output, as `verify_with` is.
    private func echoUseWith(_ jwkText: String, _ expect: JSONValue, _ out: Outputs) throws {
        guard let useWith = expect["use_with"], useWith.isObject else { return }
        try checkUseWith(jwkText, useWith)
        out["use_with"] = useWith
    }

    /// Rust `check_use_with` (ADR 0034 §6; implementer note 14): every call is a check, so any
    /// failure fails the vector. The other side is the key's public form (`jwkToPublic`), or the
    /// key itself for `oct` (RFC 7518 §6.4).
    /// - Without `enc`: a compact JWS (RFC 7515 §7.1) of `polyjose` under `{"alg": alg}`, verified
    ///   with allow-list `[alg]` (RFC 7515 §5.1-§5.2).
    /// - With `enc`: a compact JWE (RFC 7516 §7.1) of it to one recipient with `alg`, decrypted
    ///   with the key and allow-lists `[alg]` and `[enc]` (RFC 7516 §5.1-§5.2).
    private func checkUseWith(_ key: String, _ useWith: JSONValue) throws {
        let alg = try str(useWith["alg"], "use_with/alg")
        let isOct = try parseOutput(key, "the generated JWK")["kty"]?.stringValue == "oct"
        let other = isOct ? key : try check("use_with: the key has no public form") { try jwkToPublic(jwk: key) }
        if let enc = useWith["enc"]?.stringValue {
            let options = JweEncryptOptions(enc: enc, recipients: [JweRecipient(alg: alg, key: other)])
            let token = try check("use_with: encryption to the key fails") {
                try jweEncryptCompact(plaintext: useWithPayload, options: options)
            }
            let decrypted = try check("use_with: the key does not decrypt") {
                try jweDecryptCompact(token: token, key: key, options: JweDecryptOptions(allowedAlgs: [alg], allowedEnc: [enc]))
            }
            guard decrypted.plaintext == useWithPayload else {
                throw HarnessError("use_with: the decrypted plaintext is not the encrypted one")
            }
        } else {
            let header = "{\"alg\":\(JSONValue.quote(alg))}"
            let token = try check("use_with: the key does not sign") {
                try jwsSignCompact(payload: useWithPayload, key: key, options: JwsSignOptions(protectedHeader: header))
            }
            let verified = try check("use_with: the signature does not verify") {
                try jwsVerifyCompact(token: token, key: other, options: JwsVerifyOptions(allowedAlgs: [alg]))
            }
            guard verified.payload == useWithPayload else {
                throw HarnessError("use_with: the verified payload is not the signed one")
            }
        }
    }

    /// The decrypt options of `jwe.decrypt` and of a nested JWT's `decrypt` (Rust `jwe_policy`).
    private func jweDecryptOptions(_ object: JSONValue) throws -> JweDecryptOptions {
        JweDecryptOptions(
            allowedAlgs: try strs(object["allowed_algs"], "allowed_algs"),
            allowedEnc: try strs(object["allowed_enc"], "allowed_enc"),
            maxPbes2Count: try count(object["max_pbes2_count"], "max_pbes2_count"),
            maxDecompressedLen: try count(object["max_decompressed_len"], "max_decompressed_len"),
            maxInputLen: try count(object["max_input_len"], "max_input_len"),
            maxRecipients: try count(object["max_recipients"], "max_recipients"),
            understoodCrit: try object["understood_crit"].map { try strs($0, "understood_crit") })
    }

    /// The JWT verify options from `allowed_algs`, `now` and `policy` (Rust `jwt_policy`), member
    /// by member (conformance/README.md, the `policy` → `JwtVerifyOptions` table). An absent
    /// member, or a boolean `false`, sets nothing, so the library default stays.
    private func jwtVerifyOptions(_ object: JSONValue) throws -> JwtVerifyOptions {
        let policy = object["policy"] ?? .object([])
        let typ = policy["typ"].flatMap { $0.isObject ? $0 : nil }
        let mode = typ?["mode"]?.stringValue
        if policy.has("profile"), mode == "default" {
            throw HarnessError(
                "`policy/typ/mode` \"default\" contradicts `policy/profile` \"access_token\", which requires typ at+jwt (RFC 9068 §4)")
        }
        // ADR 0028 §4: always the vector's `now`, an integer (implementer note 5).
        guard let nowValue = object["now"]?.numberValue, let now = Int64(exactly: nowValue) else {
            throw HarnessError("`now` is not an integer")
        }
        var issuers: [String]?
        if let issuer = policy["issuer"] {
            issuers = try issuer.stringValue.map { [$0] } ?? strs(issuer, "policy/issuer")
        }
        return JwtVerifyOptions(
            allowedAlgs: try strs(object["allowed_algs"], "allowed_algs"),
            now: now,
            issuers: issuers,
            audiences: try policy["audience"].map { try strs($0, "policy/audience") },
            subject: policy["subject"]?.stringValue,
            leeway: try count(policy["leeway"], "policy/leeway"),
            maxAge: try count(policy["max_age"], "policy/max_age"),
            requiredClaims: try policy["require"].map { try strs($0, "policy/require") },
            allowMissingExp: isTrue(policy["allow_missing_exp"]),
            ignoreAudience: isTrue(policy["ignore_audience"]),
            typ: mode == "exact" ? try str(typ?["value"], "policy/typ/value") : nil,
            anyTyp: mode == "any",
            // Passed as written, so the core's answer for any other name is what it checks.
            profile: policy["profile"]?.stringValue,
            maxKeyCandidates: try count(policy["max_key_candidates"], "policy/max_key_candidates"))
    }

    /// Validates `token` with a `jwt.validate` input or a `jwt.issue` `validate` object at `base`
    /// (Rust `jwt_validation` + `jwt_verify`): the four calls are chosen by `decrypt` and by `key`
    /// vs `jwks` (ADR 0030 §4). A nested JWT's result is its inner JWT.
    private func jwtValidate(_ object: JSONValue, _ base: [PathStep], _ token: String, _ text: JSONText) throws -> JwtVerified {
        let options = try jwtVerifyOptions(object)
        let decrypt = object["decrypt"].flatMap { $0.isObject ? $0 : nil }
        let jwks = text.text(base + ["jwks"])
        let keys = try jwks ?? at(text, base + ["key"])
        if let decrypt {
            let decryptKey = try at(text, base + ["decrypt", "key"])
            let decryptOptions = try jweDecryptOptions(decrypt)
            let nested = try lib {
                jwks == nil
                    ? try jwtDecryptNested(token: token, decryptKey: decryptKey, decryptOptions: decryptOptions, key: keys, options: options)
                    : try jwtDecryptNestedWithJwks(
                        token: token, decryptKey: decryptKey, decryptOptions: decryptOptions, jwks: keys, options: options)
            }
            return nested.inner
        }
        return try lib {
            jwks == nil
                ? try jwtVerify(token: token, key: keys, options: options)
                : try jwtVerifyWithJwks(token: token, jwks: keys, options: options)
        }
    }
}
