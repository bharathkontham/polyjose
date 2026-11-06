//! Shared conformance vector runner (ADR 0008 layer 4), Rust side.
//!
//! Loads every `*.json` file under `conformance/vectors/` (recursively,
//! `third_party/` included), checks each against the rules of
//! `conformance/schema.json`, runs it through the public API and collects
//! every failure before failing. A failure message names the file and the
//! vector's `source`.
//!
//! The rules the WASM, Node, Kotlin and Swift runners must follow too
//! (conformance/README.md):
//!
//! - a schema-invalid vector fails the run;
//! - a vector whose `operation` the runner does not implement fails the run,
//!   whether the schema reserves the operation or not; nothing is skipped;
//! - an empty or missing vectors directory fails the run;
//! - for `jws.sign` and `jws.verify` (RFC 7515), the step order of
//!   conformance/README.md: JWK import, then headers or options, then the
//!   call, the first error being the outcome; and the round trip of a
//!   randomized signature (`verify_with`);
//! - for `keys.import_pem` and `keys.export_pem` (ADR 0018 §3), the PEM
//!   import gives the expected JWK, and the export, after the JWK import,
//!   gives the exact PEM text;
//! - for `keys.import_der`, `der_b64u` is decoded (a non-canonical value is
//!   a broken vector, never an outcome) and imported in the named `format`.
//!
//! The schema is enforced by a strict hand-written check (no JSON Schema
//! crate, ADR 0016). `schema_and_runner_agree` parses `schema.json` and
//! fails if its operations, member names, member kinds, `required` lists,
//! `allOf` signer rules, patterns or error codes drift from the tables
//! below. `jws_and_keys_vectors_are_binding_ready` checks that every JWS and
//! keys vector is readable unchanged by every binding's JSON parser. Vector files are
//! parsed with
//! polyjose's own `json` module, and their inputs reach the library through
//! it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};

use polyjose::Error;
use polyjose::header::Header;
use polyjose::json::{self, Number, Object, Value};
use polyjose::jwa::SigningAlg;
use polyjose::jwk::Jwk;
use polyjose::jws::{self, ProtectedHeader, SignOptions, Signer, VerifyOptions};
use polyjose::keys::KeyFormat;
use polyjose::util::{b64url_decode, b64url_encode};

/// Top-level members of a vector; all required (schema `required`).
const TOP_LEVEL: &[&str] = &["source", "description", "operation", "input", "expect"];

/// Every operation `schema.json` names, in schema order. Only those with an
/// [`OpSpec`] have a defined input and expectation; the others are reserved
/// for the features that will define them.
const OPERATIONS: &[&str] = &[
    "b64url.encode",
    "b64url.decode",
    "jwk.thumbprint",
    "jws.sign",
    "jws.verify",
    "keys.import_pem",
    "keys.export_pem",
    "keys.import_der",
    "jwe.encrypt",
    "jwe.decrypt",
    "jwt.validate",
];

/// `$defs/hex/pattern`: lowercase hex, two digits per octet.
const HEX_PATTERN: &str = "^([0-9a-f]{2})*$";
/// `$defs/base64url/pattern`: the RFC 4648 §5 alphabet, no padding.
const BASE64URL_PATTERN: &str = "^[A-Za-z0-9_-]*$";
/// `$defs/text/pattern`: at least one non-whitespace character.
const TEXT_PATTERN: &str = "\\S";
/// `$defs/count/maximum`: an unsigned 32-bit integer (ADR 0030 `u32`), so
/// every binding holds a count natively and exactly.
const COUNT_MAX: u64 = u32::MAX as u64;

/// What a member's value must be. Each kind maps to one schema spelling
/// (see `schema_kind`).
#[derive(Debug, Clone, Copy)]
enum Kind {
    /// `{"$ref": "#/$defs/hex"}`
    Hex,
    /// `{"$ref": "#/$defs/base64url"}`
    Base64url,
    /// `{"type": "string"}`
    String,
    /// `{"type": "object"}`
    Object,
    /// `{"enum": [...]}` of strings
    Enum(&'static [&'static str]),
    /// `{"$ref": "#/$defs/count"}`: an integer in `0..=COUNT_MAX`
    Count,
    /// `{"$ref": "#/$defs/jws"}`: a string (compact) or an object (JSON)
    Jws,
    /// `{"$ref": "#/$defs/alg_list"}`: an array of strings
    AlgList,
    /// `{"type": "boolean"}`
    Bool,
    /// `{"$ref": "#/$defs/<def>"}` of a closed object definition
    Nested(&'static Shape),
    /// `{"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/<def>"}}`
    List(&'static Shape),
}

impl Kind {
    /// The shared `$defs` entry a `$ref` kind points at.
    fn def(self) -> Option<&'static str> {
        match self {
            Kind::Hex => Some("hex"),
            Kind::Base64url => Some("base64url"),
            Kind::Count => Some("count"),
            Kind::Jws => Some("jws"),
            Kind::AlgList => Some("alg_list"),
            Kind::Nested(shape) => Some(shape.def),
            Kind::String | Kind::Object | Kind::Enum(_) | Kind::Bool | Kind::List(_) => None,
        }
    }
}

/// One member of a [`Shape`].
#[derive(Debug)]
struct Member {
    name: &'static str,
    kind: Kind,
    /// Listed in the definition's `required`.
    required: bool,
}

/// A required member.
const fn req(name: &'static str, kind: Kind) -> Member {
    Member {
        name,
        kind,
        required: true,
    }
}

/// An optional member.
const fn opt(name: &'static str, kind: Kind) -> Member {
    Member {
        name,
        kind,
        required: false,
    }
}

/// A closed object definition in `$defs` (`additionalProperties: false`):
/// the listed members, no others, and its `allOf` rules.
#[derive(Debug)]
struct Shape {
    /// Its name under `$defs`.
    def: &'static str,
    members: &'static [Member],
    /// Per-serialization signer rules (`jws_sign_input` only).
    rules: &'static [SignerRule],
}

/// One `allOf` rule of `jws_sign_input`: when `serialization` is
/// `serialization`, `signers` has at most `max_signers` entries, each with
/// every `requires` member and none of the `forbids` members. In the
/// schema:
///
/// ```json
/// {"if": {"properties": {"serialization": {"const": "compact"}}},
///  "then": {"properties": {"signers": {"maxItems": 1,
///    "items": {"required": ["protected_b64u"], "properties": {"header": false}}}}}}
/// ```
#[derive(Debug)]
struct SignerRule {
    serialization: &'static str,
    max_signers: usize,
    requires: &'static [&'static str],
    forbids: &'static [&'static str],
}

/// The input and success shapes of an operation (schema `$defs`).
#[derive(Debug)]
struct OpSpec {
    name: &'static str,
    input: &'static Shape,
    /// The success expectations; `"ok": true` is implicit in each. With
    /// more than one, a vector matches exactly one (schema `oneOf`).
    ok: &'static [&'static Shape],
    /// Whether `{"ok": false, "error": <code>}` is allowed.
    can_fail: bool,
}

// RFC 7515 §2 base64url encoding (RFC 4648 §5, no padding).
const B64URL_ENCODE_INPUT: Shape = Shape {
    def: "b64url_encode_input",
    members: &[req("bytes_hex", Kind::Hex)],
    rules: &[],
};
const B64URL_ENCODE_OK: Shape = Shape {
    def: "b64url_encode_ok",
    members: &[req("b64u", Kind::Base64url)],
    rules: &[],
};
// RFC 7515 §2 decoding; non-canonical input is rejected (RFC 4648 §3.5).
const B64URL_DECODE_INPUT: Shape = Shape {
    def: "b64url_decode_input",
    members: &[req("b64u", Kind::String)],
    rules: &[],
};
const B64URL_DECODE_OK: Shape = Shape {
    def: "b64url_decode_ok",
    members: &[req("bytes_hex", Kind::Hex)],
    rules: &[],
};
// RFC 7638 §3 JWK Thumbprint and RFC 9278 §3 JWK Thumbprint URI.
const JWK_THUMBPRINT_INPUT: Shape = Shape {
    def: "jwk_thumbprint_input",
    members: &[
        req("jwk", Kind::Object),
        req("hash", Kind::Enum(&["sha-256"])),
    ],
    rules: &[],
};
const JWK_THUMBPRINT_OK: Shape = Shape {
    def: "jwk_thumbprint_ok",
    members: &[
        req("thumbprint", Kind::Base64url),
        req("thumbprint_uri", Kind::String),
    ],
    rules: &[],
};

// RFC 7515 §5.2 validation through `jws::verify_compact` (a string `jws`,
// RFC 7515 §7.1) or `jws::verify_json` (an object, §7.2), with the
// options of ADR 0026: allow-list, detached payload (Appendix F), limits.
const JWS_VERIFY_INPUT: Shape = Shape {
    def: "jws_verify_input",
    members: &[
        req("jws", Kind::Jws),
        req("key", Kind::Object),
        req("allowed_algs", Kind::AlgList),
        opt("detached_payload_b64u", Kind::Base64url),
        opt("max_input_len", Kind::Count),
        opt("max_signatures", Kind::Count),
    ],
    rules: &[],
};
const JWS_VERIFY_OK: Shape = Shape {
    def: "jws_verify_ok",
    members: &[
        req("payload_b64u", Kind::Base64url),
        req("alg", Kind::String),
        req("signature_index", Kind::Count),
    ],
    rules: &[],
};

/// The signer of a `jws.sign` vector: its JWS Protected Header as exact
/// octets (RFC 7515 §5.1 step 3; RFC 7515 A.1's CRLF header can only be
/// given this way), its JWS Unprotected Header (§7.2.1), and its key.
const JWS_SIGNER: Shape = Shape {
    def: "jws_signer",
    members: &[
        opt("protected_b64u", Kind::Base64url),
        opt("header", Kind::Object),
        req("key", Kind::Object),
    ],
    rules: &[],
};
// RFC 7515 §5.1 through `jws::sign_compact` (§7.1), `jws::sign_flattened`
// (§7.2.2) or `jws::sign_general` (§7.2.1), attached or detached
// (Appendix F).
const JWS_SIGN_INPUT: Shape = Shape {
    def: "jws_sign_input",
    members: &[
        req(
            "serialization",
            Kind::Enum(&["compact", "flattened", "general"]),
        ),
        req("payload_b64u", Kind::Base64url),
        req("detached", Kind::Bool),
        req("signers", Kind::List(&JWS_SIGNER)),
    ],
    rules: &[
        // RFC 7515 §7.1: one signature over a JWS Protected Header only.
        SignerRule {
            serialization: "compact",
            max_signers: 1,
            requires: &["protected_b64u"],
            forbids: &["header"],
        },
        // RFC 7515 §7.2.2: one signature.
        SignerRule {
            serialization: "flattened",
            max_signers: 1,
            requires: &[],
            forbids: &[],
        },
    ],
};
/// A deterministic signature's exact output: a string for compact, an
/// object for JSON, compared as JSON values (member order ignored,
/// RFC 8259 §4).
const JWS_SIGN_EXACT: Shape = Shape {
    def: "jws_sign_exact",
    members: &[req("jws", Kind::Jws)],
    rules: &[],
};
const JWS_VERIFY_WITH: Shape = Shape {
    def: "jws_verify_with",
    members: &[req("key", Kind::Object), req("allowed_algs", Kind::AlgList)],
    rules: &[],
};
/// A randomized signature (ECDSA): the runner verifies its own output with
/// `verify_with` and checks the payload, instead of comparing bytes.
const JWS_SIGN_ROUND_TRIP: Shape = Shape {
    def: "jws_sign_roundtrip",
    members: &[req("verify_with", Kind::Nested(&JWS_VERIFY_WITH))],
    rules: &[],
};

// ADR 0018 §3 PEM import through `Jwk::from_pem`: the label selects the
// structure (RFC 7468 §2), the key type comes from the DER.
const KEYS_IMPORT_PEM_INPUT: Shape = Shape {
    def: "keys_import_pem_input",
    members: &[req("pem", Kind::String)],
    rules: &[],
};
/// The imported JWK, compared as a JSON value (member order ignored).
const KEYS_IMPORT_PEM_OK: Shape = Shape {
    def: "keys_import_pem_ok",
    members: &[req("jwk", Kind::Object)],
    rules: &[],
};
/// The `format` names of the keys.* operations, in schema order, and the
/// library format each selects.
const KEY_FORMATS: &[(&str, KeyFormat)] = &[
    ("pkcs8", KeyFormat::Pkcs8),
    ("sec1", KeyFormat::Sec1),
    ("spki", KeyFormat::Spki),
    ("pkcs1", KeyFormat::Pkcs1),
];
/// The `format` enum of the keys.* operations: the names of [`KEY_FORMATS`].
const KEY_FORMAT_NAMES: &[&str] = &["pkcs8", "sec1", "spki", "pkcs1"];
// ADR 0018 §3 PEM export through `Jwk::from_object` then `Jwk::to_pem`.
const KEYS_EXPORT_PEM_INPUT: Shape = Shape {
    def: "keys_export_pem_input",
    members: &[
        req("jwk", Kind::Object),
        req("format", Kind::Enum(KEY_FORMAT_NAMES)),
    ],
    rules: &[],
};
/// The exact PEM text, compared as a string.
const KEYS_EXPORT_PEM_OK: Shape = Shape {
    def: "keys_export_pem_ok",
    members: &[req("pem", Kind::String)],
    rules: &[],
};
// ADR 0018 §3 DER import through `Jwk::from_der`: the caller names the
// structure, there is no format sniffing (ADR 0007), and the key type comes
// from the DER (ADR 0018 §2).
const KEYS_IMPORT_DER_INPUT: Shape = Shape {
    def: "keys_import_der_input",
    members: &[
        req("der_b64u", Kind::Base64url),
        req("format", Kind::Enum(KEY_FORMAT_NAMES)),
    ],
    rules: &[],
};
/// The imported JWK, compared as a JSON value (member order ignored).
const KEYS_IMPORT_DER_OK: Shape = Shape {
    def: "keys_import_der_ok",
    members: &[req("jwk", Kind::Object)],
    rules: &[],
};

/// The operations this runner implements.
const SPECS: &[OpSpec] = &[
    OpSpec {
        name: "b64url.encode",
        input: &B64URL_ENCODE_INPUT,
        ok: &[&B64URL_ENCODE_OK],
        can_fail: false,
    },
    OpSpec {
        name: "b64url.decode",
        input: &B64URL_DECODE_INPUT,
        ok: &[&B64URL_DECODE_OK],
        can_fail: true,
    },
    OpSpec {
        name: "jwk.thumbprint",
        input: &JWK_THUMBPRINT_INPUT,
        ok: &[&JWK_THUMBPRINT_OK],
        can_fail: true,
    },
    OpSpec {
        name: "jws.sign",
        input: &JWS_SIGN_INPUT,
        ok: &[&JWS_SIGN_EXACT, &JWS_SIGN_ROUND_TRIP],
        can_fail: true,
    },
    OpSpec {
        name: "jws.verify",
        input: &JWS_VERIFY_INPUT,
        ok: &[&JWS_VERIFY_OK],
        can_fail: true,
    },
    OpSpec {
        name: "keys.import_pem",
        input: &KEYS_IMPORT_PEM_INPUT,
        ok: &[&KEYS_IMPORT_PEM_OK],
        can_fail: true,
    },
    OpSpec {
        name: "keys.export_pem",
        input: &KEYS_EXPORT_PEM_INPUT,
        ok: &[&KEYS_EXPORT_PEM_OK],
        can_fail: true,
    },
    OpSpec {
        name: "keys.import_der",
        input: &KEYS_IMPORT_DER_INPUT,
        ok: &[&KEYS_IMPORT_DER_OK],
        can_fail: true,
    },
];

fn spec(operation: &str) -> Option<&'static OpSpec> {
    SPECS.iter().find(|s| s.name == operation)
}

/// What a vector expects.
#[derive(Debug)]
enum Expect {
    /// Success with these output members (`ok` removed).
    Ok(Object),
    /// Failure with this stable error code.
    Err(String),
}

/// A schema-valid vector.
#[derive(Debug)]
struct Vector {
    operation: String,
    input: Object,
    expect: Expect,
}

/// A schema violation: the JSON pointer and what is wrong there.
fn violation(pointer: &str, problem: impl std::fmt::Display) -> String {
    format!("schema: {pointer}: {problem}")
}

fn is_text(s: &str) -> bool {
    !s.is_empty() && s.chars().any(|c| !c.is_whitespace())
}

fn is_hex(s: &str) -> bool {
    s.len().is_multiple_of(2) && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_base64url_alphabet(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// `$defs/count`: `{"type": "integer", "minimum": 0, "maximum": COUNT_MAX}`.
fn is_count(value: &Value) -> bool {
    value.as_u64().is_some_and(|n| n <= COUNT_MAX)
}

/// Checks that `object` has exactly the `allowed` members, all of which are
/// required.
fn exact_members(object: &Object, allowed: &[&str], pointer: &str) -> Result<(), String> {
    for (name, _) in object {
        if !allowed.contains(&name) {
            return Err(violation(
                &format!("{pointer}/{name}"),
                "unknown member (additionalProperties is false)",
            ));
        }
    }
    for name in allowed {
        if !object.contains(name) {
            return Err(violation(
                &format!("{pointer}/{name}"),
                "required member is missing",
            ));
        }
    }
    Ok(())
}

fn check_kind(value: &Value, kind: Kind, pointer: &str) -> Result<(), String> {
    match (kind, value) {
        (Kind::Nested(shape), Value::Object(object)) => {
            return check_shape(object, shape, false, pointer);
        }
        (Kind::List(shape), Value::Array(items)) if !items.is_empty() => {
            for (i, item) in items.iter().enumerate() {
                let at = format!("{pointer}/{i}");
                let object = item
                    .as_object()
                    .ok_or_else(|| violation(&at, "must be an object"))?;
                check_shape(object, shape, false, &at)?;
            }
            return Ok(());
        }
        _ => {}
    }
    let ok = match kind {
        Kind::Object => value.as_object().is_some(),
        Kind::String => value.as_str().is_some(),
        Kind::Hex => value.as_str().is_some_and(is_hex),
        Kind::Base64url => value.as_str().is_some_and(is_base64url_alphabet),
        Kind::Enum(values) => value.as_str().is_some_and(|s| values.contains(&s)),
        Kind::Count => is_count(value),
        Kind::Jws => value.as_str().is_some() || value.as_object().is_some(),
        Kind::AlgList => value
            .as_array()
            .is_some_and(|items| items.iter().all(|item| item.as_str().is_some())),
        Kind::Bool => value.as_bool().is_some(),
        // Matched above when the value has the right type.
        Kind::Nested(_) | Kind::List(_) => false,
    };
    if ok {
        Ok(())
    } else {
        let wanted = match kind {
            Kind::Object => "an object".to_owned(),
            Kind::String => "a string".to_owned(),
            Kind::Hex => format!("a string matching {HEX_PATTERN}"),
            Kind::Base64url => format!("a string matching {BASE64URL_PATTERN}"),
            Kind::Enum(values) => format!("one of {values:?}"),
            Kind::Count => format!("an integer from 0 to {COUNT_MAX}"),
            Kind::Jws => "a string (compact) or an object (JSON serialization)".to_owned(),
            Kind::AlgList => "an array of strings".to_owned(),
            Kind::Bool => "a boolean".to_owned(),
            Kind::Nested(shape) => format!("an object ({})", shape.def),
            Kind::List(shape) => format!("a non-empty array of objects ({})", shape.def),
        };
        Err(violation(pointer, format!("must be {wanted}")))
    }
}

/// Checks `object` against `shape`, plus `"ok"` when `ok` is set (a
/// success expectation, whose `ok` is already known to be `true`).
fn check_shape(object: &Object, shape: &Shape, ok: bool, pointer: &str) -> Result<(), String> {
    for (name, _) in object {
        let known = (ok && name == "ok") || shape.members.iter().any(|m| m.name == name);
        if !known {
            return Err(violation(
                &format!("{pointer}/{name}"),
                "unknown member (additionalProperties is false)",
            ));
        }
    }
    for member in shape.members {
        let at = format!("{pointer}/{}", member.name);
        match object.get(member.name) {
            Some(value) => check_kind(value, member.kind, &at)?,
            None if member.required => return Err(violation(&at, "required member is missing")),
            None => {}
        }
    }
    for rule in shape.rules {
        check_rule(object, rule, pointer)?;
    }
    Ok(())
}

/// Applies a [`SignerRule`] to a `jws_sign_input` whose members are valid.
fn check_rule(object: &Object, rule: &SignerRule, pointer: &str) -> Result<(), String> {
    if object.get("serialization").and_then(Value::as_str) != Some(rule.serialization) {
        return Ok(());
    }
    let signers = object
        .get("signers")
        .and_then(Value::as_array)
        .expect("checked as a member");
    let what = format!("a {} JWS", rule.serialization);
    if signers.len() > rule.max_signers {
        return Err(violation(
            &format!("{pointer}/signers"),
            format!("{what} has at most {} signer", rule.max_signers),
        ));
    }
    for (i, signer) in signers.iter().enumerate() {
        let signer = signer.as_object().expect("checked as a member");
        for name in rule.requires {
            if !signer.contains(name) {
                return Err(violation(
                    &format!("{pointer}/signers/{i}/{name}"),
                    format!("required for {what}"),
                ));
            }
        }
        for name in rule.forbids {
            if signer.contains(name) {
                return Err(violation(
                    &format!("{pointer}/signers/{i}/{name}"),
                    format!("not allowed in {what}"),
                ));
            }
        }
    }
    Ok(())
}

/// Checks a success expectation against the operation's success shapes:
/// it must match exactly one (schema `oneOf`).
fn check_ok(expect: &Object, spec: &OpSpec) -> Result<(), String> {
    if let [shape] = spec.ok {
        return check_shape(expect, shape, true, "/expect");
    }
    let results: Vec<(&str, Result<(), String>)> = spec
        .ok
        .iter()
        .map(|shape| (shape.def, check_shape(expect, shape, true, "/expect")))
        .collect();
    match results.iter().filter(|(_, r)| r.is_ok()).count() {
        1 => Ok(()),
        0 => Err(violation(
            "/expect",
            format!(
                "matches none of the success forms: {}",
                results
                    .iter()
                    .map(|(def, r)| format!("{def} ({})", r.as_ref().unwrap_err()))
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
        )),
        _ => Err(violation(
            "/expect",
            "matches more than one success form (oneOf)",
        )),
    }
}

/// The vector's `source`, if it is usable, for failure messages.
fn usable_source(value: &Value) -> Option<String> {
    value
        .get("source")
        .and_then(Value::as_str)
        .filter(|s| is_text(s))
        .map(str::to_owned)
}

/// Checks one parsed vector file against the rules of `schema.json`.
fn validate(value: &Value) -> Result<Vector, String> {
    let root = value
        .as_object()
        .ok_or_else(|| violation("", "a vector file must hold one JSON object"))?;
    exact_members(root, TOP_LEVEL, "")?;
    for name in ["source", "description"] {
        let text = root.get(name).and_then(Value::as_str);
        if !text.is_some_and(is_text) {
            return Err(violation(
                &format!("/{name}"),
                "must be a string with a non-whitespace character",
            ));
        }
    }
    let operation = root
        .get("operation")
        .and_then(Value::as_str)
        .ok_or_else(|| violation("/operation", "must be a string"))?;
    if !OPERATIONS.contains(&operation) {
        return Err(violation(
            "/operation",
            format!("unknown operation `{operation}` (not in schema.json)"),
        ));
    }
    let input = root
        .get("input")
        .and_then(Value::as_object)
        .ok_or_else(|| violation("/input", "must be an object"))?;
    let expect = root
        .get("expect")
        .and_then(Value::as_object)
        .ok_or_else(|| violation("/expect", "must be an object"))?;
    let ok = expect
        .get("ok")
        .ok_or_else(|| violation("/expect/ok", "required member is missing"))?
        .as_bool()
        .ok_or_else(|| violation("/expect/ok", "must be a boolean"))?;

    let mut outputs = expect.clone();
    outputs.remove("ok");
    let expect = match spec(operation) {
        // Reserved operation: the schema constrains only `"ok"`, and
        // `execute` fails it, so the expectation is never compared.
        None if ok => Expect::Ok(outputs),
        None => Expect::Err(String::new()),
        Some(spec) => {
            check_shape(input, spec.input, false, "/input")?;
            if ok {
                check_ok(expect, spec)?;
                Expect::Ok(outputs)
            } else if !spec.can_fail {
                return Err(violation(
                    "/expect",
                    format!("`{operation}` cannot fail, so only {{\"ok\": true, ...}} is allowed"),
                ));
            } else {
                exact_members(expect, &["ok", "error"], "/expect")?;
                let code = expect
                    .get("error")
                    .and_then(Value::as_str)
                    .filter(|c| Error::CODES.contains(c))
                    .ok_or_else(|| violation("/expect/error", "must be one of Error::CODES"))?;
                Expect::Err(code.to_owned())
            }
        }
    };
    Ok(Vector {
        operation: operation.to_owned(),
        input: input.clone(),
        expect,
    })
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("validated hex"))
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn input_str<'a>(input: &'a Object, name: &str) -> &'a str {
    input.get(name).and_then(Value::as_str).expect("validated")
}

fn input_object<'a>(object: &'a Object, name: &str) -> &'a Object {
    object
        .get(name)
        .and_then(Value::as_object)
        .expect("validated")
}

/// A `*_b64u` member's octets. The runner decodes them to hand them to the
/// library, so a value that does not decode is a broken vector, never an
/// outcome (the codec has its own `b64url.*` vectors).
fn input_bytes(object: &Object, name: &str) -> Result<Vec<u8>, String> {
    let text = object.get(name).and_then(Value::as_str).expect("validated");
    b64url_decode(text).map_err(|e| {
        format!(
            "`{name}` is not canonical base64url ({}); the runner must decode it",
            e.code()
        )
    })
}

/// An optional `$defs/count` member, as a `usize`.
fn input_count(object: &Object, name: &str) -> Option<usize> {
    object
        .get(name)
        .and_then(Value::as_u64)
        .map(|n| usize::try_from(n).expect("validated: at most u32::MAX"))
}

/// `allowed_algs`, mapped name by name: an unknown name becomes
/// `SigningAlg::Unknown`, which `VerifyOptions::new` refuses.
fn input_algs(object: &Object) -> Vec<SigningAlg> {
    object
        .get("allowed_algs")
        .and_then(Value::as_array)
        .expect("validated")
        .iter()
        .map(|alg| SigningAlg::from(alg.as_str().expect("validated")))
        .collect()
}

/// One signer's inputs, built from the vector.
struct SignerParts {
    key: Jwk,
    protected: Option<ProtectedHeader>,
    unprotected: Option<Header>,
}

/// Builds each signer, in order: import `key`, then decode and parse
/// `protected_b64u` (RFC 7515 §5.1 step 3, kept verbatim), then parse
/// `header` (§7.2.1). The first error is the outcome.
fn signer_parts(input: &Object) -> Result<Vec<SignerParts>, Error> {
    let signers = input
        .get("signers")
        .and_then(Value::as_array)
        .expect("validated");
    let mut parts = Vec::with_capacity(signers.len());
    for signer in signers {
        let signer = signer.as_object().expect("validated");
        let key = Jwk::from_object(input_object(signer, "key"))?;
        let protected = match signer.get("protected_b64u").and_then(Value::as_str) {
            Some(encoded) => Some(ProtectedHeader::from_encoded(encoded)?),
            None => None,
        };
        let unprotected = match signer.get("header") {
            Some(header) => Some(Header::from_json(header.to_json().as_bytes())?),
            None => None,
        };
        parts.push(SignerParts {
            key,
            protected,
            unprotected,
        });
    }
    Ok(parts)
}

/// `jws.sign` (RFC 7515 §5.1): build the signers (see [`signer_parts`]),
/// then sign in the requested serialization. An exact expectation gets the
/// output as `jws` (a string for compact; JSON output parsed, so it is
/// compared as a JSON value). A round-trip expectation is checked here
/// (see [`check_round_trip`]) and echoed back on success.
fn run_jws_sign(
    input: &Object,
    expect: &Expect,
    out: &mut Object,
) -> Result<Result<(), Error>, String> {
    let serialization = input_str(input, "serialization");
    let payload = input_bytes(input, "payload_b64u")?;
    let detached = input
        .get("detached")
        .and_then(Value::as_bool)
        .expect("validated");
    let parts = match signer_parts(input) {
        Ok(parts) => parts,
        Err(e) => return Ok(Err(e)),
    };
    let opts = SignOptions::new().detached(detached);
    let signed = if serialization == "compact" {
        // Schema: exactly one signer, with a protected header.
        let only = &parts[0];
        let protected = only.protected.as_ref().expect("validated");
        jws::sign_compact(protected, &payload, &only.key, &opts)
    } else {
        let signers: Vec<Signer<'_>> = parts
            .iter()
            .map(|part| {
                let mut signer = Signer::new(&part.key);
                if let Some(protected) = &part.protected {
                    signer = signer.protected(protected.clone());
                }
                if let Some(unprotected) = &part.unprotected {
                    signer = signer.unprotected(unprotected.clone());
                }
                signer
            })
            .collect();
        if serialization == "flattened" {
            jws::sign_flattened(&signers[0], &payload, &opts)
        } else {
            jws::sign_general(&signers, &payload, &opts)
        }
    };
    let text = match signed {
        Ok(text) => text,
        Err(e) => return Ok(Err(e)),
    };
    let jws = if serialization == "compact" {
        Value::from(text.as_str())
    } else {
        json::parse(text.as_bytes())
            .map_err(|e| format!("the signed JSON JWS does not parse: {}", e.code()))?
    };
    let verify_with = match expect {
        Expect::Ok(want) => want.get("verify_with").and_then(Value::as_object),
        Expect::Err(_) => None,
    };
    match verify_with {
        Some(verify_with) => {
            check_round_trip(
                serialization,
                &jws,
                &text,
                &payload,
                detached,
                parts.len(),
                verify_with,
            )?;
            out.insert("verify_with", verify_with.clone());
        }
        None => {
            out.insert("jws", jws);
        }
    }
    Ok(Ok(()))
}

/// Checks a randomized signature by round trip: the output has the shape
/// of the requested serialization (RFC 7515 §7.1, §7.2.1, §7.2.2), verifies
/// with `verify_with` (with the payload supplied separately when detached,
/// Appendix F), and yields the signed payload. Any failure is the vector's.
fn check_round_trip(
    serialization: &str,
    jws: &Value,
    text: &str,
    payload: &[u8],
    detached: bool,
    signers: usize,
    verify_with: &Object,
) -> Result<(), String> {
    let shape_ok = match serialization {
        "compact" => text.split('.').count() == 3,
        "flattened" => jws.get("signature").is_some() && jws.get("signatures").is_none(),
        _ => jws
            .get("signatures")
            .and_then(Value::as_array)
            .is_some_and(|all| all.len() == signers),
    };
    if !shape_ok {
        return Err(format!(
            "round trip: the output is not a {serialization} JWS with {signers} signature(s)"
        ));
    }
    let key = Jwk::from_object(input_object(verify_with, "key"))
        .map_err(|e| format!("round trip: verify_with.key does not import ({})", e.code()))?;
    let algs = input_algs(verify_with);
    let mut opts = VerifyOptions::new(&algs).map_err(|e| {
        format!(
            "round trip: verify_with.allowed_algs is refused ({})",
            e.code()
        )
    })?;
    if detached {
        opts = opts.detached_payload(payload);
    }
    let verified = match jws.as_str() {
        Some(compact) => jws::verify_compact(compact, &key, &opts),
        None => jws::verify_json(text, &key, &opts),
    }
    .map_err(|e| {
        format!(
            "round trip: the signed JWS does not verify with verify_with ({})",
            e.code()
        )
    })?;
    if verified.payload != payload {
        return Err("round trip: the verified payload is not the signed one".to_owned());
    }
    Ok(())
}

/// `jws.verify` (RFC 7515 §5.2). The steps run in the order
/// conformance/README.md fixes for every runner, and the first error is
/// the outcome: import `key` (RFC 7517), build the options from
/// `allowed_algs` and the optional members, then verify. A string `jws`
/// goes to `verify_compact` (RFC 7515 §7.1); an object goes, as its JSON
/// text, to `verify_json` (§7.2).
fn run_jws_verify(input: &Object, out: &mut Object) -> Result<Result<(), Error>, String> {
    let key = match Jwk::from_object(input_object(input, "key")) {
        Ok(key) => key,
        Err(e) => return Ok(Err(e)),
    };
    let algs = input_algs(input);
    let detached = match input.get("detached_payload_b64u") {
        Some(_) => Some(input_bytes(input, "detached_payload_b64u")?),
        None => None,
    };
    let mut opts = match VerifyOptions::new(&algs) {
        Ok(opts) => opts,
        Err(e) => return Ok(Err(e)),
    };
    if let Some(payload) = &detached {
        opts = opts.detached_payload(payload);
    }
    if let Some(n) = input_count(input, "max_input_len") {
        opts = opts.max_input_len(n);
    }
    if let Some(n) = input_count(input, "max_signatures") {
        opts = opts.max_signatures(n);
    }
    let jws = input.get("jws").expect("validated");
    let result = match jws.as_str() {
        Some(compact) => jws::verify_compact(compact, &key, &opts),
        None => jws::verify_json(&jws.to_json(), &key, &opts),
    };
    let verified = match result {
        Ok(verified) => verified,
        Err(e) => return Ok(Err(e)),
    };
    let index = u64::try_from(verified.signature_index).expect("an index fits u64");
    out.insert("payload_b64u", b64url_encode(&verified.payload));
    out.insert("alg", verified.alg.as_str());
    out.insert(
        "signature_index",
        Number::from_u64(index).expect("an index is a safe integer"),
    );
    Ok(Ok(()))
}

/// The library format a validated `format` member names.
fn input_format(input: &Object) -> KeyFormat {
    let name = input_str(input, "format");
    KEY_FORMATS
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, f)| *f)
        .expect("validated")
}

/// The outcome of a PEM or DER import: the JWK as an object. An `oct`
/// result fails the vector whatever it expects: PEM and DER never carry one
/// (RFC 8725 §2.1, ADR 0018 §3).
fn imported(result: Result<Jwk, Error>, out: &mut Object) -> Result<Result<(), Error>, String> {
    let key = match result {
        Ok(key) => key,
        Err(e) => return Ok(Err(e)),
    };
    let jwk = key.to_object();
    if jwk.get("kty").and_then(Value::as_str) == Some("oct") {
        return Err("a PEM or DER import returned an oct key (RFC 8725 §2.1)".to_owned());
    }
    out.insert("jwk", Value::from(jwk));
    Ok(Ok(()))
}

/// `keys.import_pem`: `Jwk::from_pem`, and the JWK as an object.
fn run_keys_import_pem(input: &Object, out: &mut Object) -> Result<Result<(), Error>, String> {
    imported(Jwk::from_pem(input_str(input, "pem")), out)
}

/// `keys.import_der`: decode `der_b64u` (a broken vector if it is not
/// canonical), then `Jwk::from_der` in `format`, and the JWK as an object.
fn run_keys_import_der(input: &Object, out: &mut Object) -> Result<Result<(), Error>, String> {
    let der = input_bytes(input, "der_b64u")?;
    imported(Jwk::from_der(&der, input_format(input)), out)
}

/// `keys.export_pem`: the JWK import (`Jwk::from_object`), whose error is
/// the outcome, then `Jwk::to_pem` in `format`.
fn run_keys_export_pem(input: &Object, out: &mut Object) -> Result<Result<(), Error>, String> {
    let format = input_format(input);
    let key = match Jwk::from_object(input_object(input, "jwk")) {
        Ok(key) => key,
        Err(e) => return Ok(Err(e)),
    };
    match key.to_pem(format) {
        Ok(pem) => {
            out.insert("pem", pem.as_str());
            Ok(Ok(()))
        }
        Err(e) => Ok(Err(e)),
    }
}

/// Runs the operation through the public API: the success outputs, or the
/// library's error.
fn execute(vector: &Vector) -> Result<Result<Object, Error>, String> {
    let input = &vector.input;
    let mut out = Object::new();
    match vector.operation.as_str() {
        "b64url.encode" => {
            out.insert(
                "b64u",
                b64url_encode(&hex_decode(input_str(input, "bytes_hex"))),
            );
        }
        "b64url.decode" => match b64url_decode(input_str(input, "b64u")) {
            Ok(bytes) => {
                out.insert("bytes_hex", hex_encode(&bytes));
            }
            Err(e) => return Ok(Err(e)),
        },
        "jwk.thumbprint" => {
            // `hash` is validated to be "sha-256", the only one implemented.
            let jwk = input
                .get("jwk")
                .and_then(Value::as_object)
                .expect("validated");
            match Jwk::from_object(jwk) {
                Ok(key) => {
                    out.insert("thumbprint", key.thumbprint_sha256());
                    out.insert("thumbprint_uri", key.thumbprint_uri_sha256());
                }
                Err(e) => return Ok(Err(e)),
            }
        }
        "jws.sign" => {
            if let Err(e) = run_jws_sign(input, &vector.expect, &mut out)? {
                return Ok(Err(e));
            }
        }
        "jws.verify" => {
            if let Err(e) = run_jws_verify(input, &mut out)? {
                return Ok(Err(e));
            }
        }
        "keys.import_pem" => {
            if let Err(e) = run_keys_import_pem(input, &mut out)? {
                return Ok(Err(e));
            }
        }
        "keys.export_pem" => {
            if let Err(e) = run_keys_export_pem(input, &mut out)? {
                return Ok(Err(e));
            }
        }
        "keys.import_der" => {
            if let Err(e) = run_keys_import_der(input, &mut out)? {
                return Ok(Err(e));
            }
        }
        other => {
            return Err(format!(
                "operation `{other}` is not implemented by the Rust runner; a vector is never skipped"
            ));
        }
    }
    Ok(Ok(out))
}

/// Compares the outcome with the expectation.
fn compare(expect: &Expect, outcome: &Result<Object, Error>) -> Result<(), String> {
    match (expect, outcome) {
        (Expect::Ok(want), Ok(got)) => {
            for (name, value) in want {
                let got_value = got.get(name);
                if got_value != Some(value) {
                    return Err(format!(
                        "`{name}`: expected {}, got {}",
                        value.to_json(),
                        got_value.map_or("nothing".to_owned(), Value::to_json)
                    ));
                }
            }
            Ok(())
        }
        (Expect::Ok(_), Err(e)) => Err(format!("expected success, got error {}", e.code())),
        (Expect::Err(code), Ok(got)) => Err(format!(
            "expected error {code}, but the operation succeeded with {}",
            got.to_json()
        )),
        (Expect::Err(code), Err(e)) if e.code() == code => Ok(()),
        (Expect::Err(code), Err(e)) => {
            Err(format!("expected error {code}, got error {}", e.code()))
        }
    }
}

/// A vector that passed.
#[derive(Debug)]
struct Passed {
    operation: String,
    /// Whether it expects a failure (`"ok": false`).
    negative: bool,
}

/// Checks one vector file: parse, validate, run, compare. Returns what
/// passed, or a failure message naming the file and the `source`.
fn check_vector(name: &str, bytes: &[u8]) -> Result<Passed, String> {
    let value = json::parse(bytes)
        .map_err(|e| format!("{name}: not a valid JSON text ({e}); see conformance/schema.json"))?;
    let source = usable_source(&value).unwrap_or_else(|| "<missing>".to_owned());
    let fail = |problem: String| format!("{name} (source: {source}): {problem}");
    let vector = validate(&value).map_err(fail)?;
    let outcome = catch_unwind(AssertUnwindSafe(|| execute(&vector)))
        .map_err(|_| fail("panicked while running".to_owned()))?
        .map_err(fail)?;
    compare(&vector.expect, &outcome).map_err(fail)?;
    Ok(Passed {
        negative: matches!(vector.expect, Expect::Err(_)),
        operation: vector.operation,
    })
}

/// Every check over a vectors directory.
#[derive(Debug, Default)]
struct Report {
    files: usize,
    /// Passing vectors per operation.
    passed: BTreeMap<String, usize>,
    /// Passing failure (`"ok": false`) vectors per operation.
    passed_negative: BTreeMap<String, usize>,
    failures: Vec<String>,
}

/// Every `*.json` file under `dir`, recursively, sorted. A symbolic link is
/// a failure: vectors must be regular files every platform reads the same.
fn collect(dir: &Path, files: &mut Vec<PathBuf>, failures: &mut Vec<String>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            failures.push(format!("{}: cannot read directory: {e}", dir.display()));
            return;
        }
    };
    for entry in entries {
        let (path, file_type) = match entry.and_then(|e| Ok((e.path(), e.file_type()?))) {
            Ok(pair) => pair,
            Err(e) => {
                failures.push(format!("{}: cannot read entry: {e}", dir.display()));
                continue;
            }
        };
        if file_type.is_symlink() {
            failures.push(format!(
                "{}: symbolic links are not allowed",
                path.display()
            ));
        } else if file_type.is_dir() {
            collect(&path, files, failures);
        } else if path.extension().is_some_and(|e| e == "json") {
            files.push(path);
        }
    }
}

fn run_dir(dir: &Path) -> Report {
    let mut report = Report::default();
    let mut files = Vec::new();
    collect(dir, &mut files, &mut report.failures);
    files.sort();
    report.files = files.len();
    if files.is_empty() {
        report
            .failures
            .push(format!("{}: no vector files (*.json) found", dir.display()));
    }
    for path in files {
        let name = path
            .strip_prefix(dir)
            .unwrap_or(&path)
            .display()
            .to_string();
        let result = std::fs::read(&path)
            .map_err(|e| format!("{name}: cannot read: {e}"))
            .and_then(|bytes| check_vector(&name, &bytes));
        match result {
            Ok(passed) => {
                if passed.negative {
                    *report
                        .passed_negative
                        .entry(passed.operation.clone())
                        .or_default() += 1;
                }
                *report.passed.entry(passed.operation).or_default() += 1;
            }
            Err(msg) => report.failures.push(msg),
        }
    }
    report
}

fn conformance_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance")
}

/// The shared vectors: every file must be schema-valid and pass.
#[test]
fn conformance_vectors() {
    let report = run_dir(&conformance_dir().join("vectors"));
    assert!(
        report.failures.is_empty(),
        "{} of {} conformance vector file(s) failed:\n  {}",
        report.failures.len(),
        report.files,
        report.failures.join("\n  ")
    );
    eprintln!(
        "conformance: {} vectors passed {:?}",
        report.files, report.passed
    );
}

/// Every implemented operation has vectors, and every operation that can
/// fail has both success and failure vectors.
#[test]
fn every_implemented_operation_has_vectors() {
    let report = run_dir(&conformance_dir().join("vectors"));
    for spec in SPECS {
        let all = report.passed.get(spec.name).copied().unwrap_or(0);
        let negative = report.passed_negative.get(spec.name).copied().unwrap_or(0);
        assert!(all > negative, "{}: no passing success vectors", spec.name);
        assert!(
            !spec.can_fail || negative > 0,
            "{}: no passing failure vectors",
            spec.name
        );
    }
}

// ---------------------------------------------------------------------------
// schema.json and this runner must say the same thing.
// ---------------------------------------------------------------------------

fn schema() -> Value {
    let bytes = std::fs::read(conformance_dir().join("schema.json")).unwrap();
    json::parse(&bytes).expect("schema.json is I-JSON")
}

fn parse(json: &str) -> Value {
    json::parse(json.as_bytes()).unwrap()
}

fn at<'a>(value: &'a Value, path: &[&str]) -> &'a Value {
    path.iter().fold(value, |v, name| {
        v.get(name)
            .unwrap_or_else(|| panic!("schema.json: no member {path:?}"))
    })
}

fn strings(value: &Value) -> Vec<&str> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect()
}

fn member_names(value: &Value) -> Vec<&str> {
    value.as_object().unwrap().iter().map(|(n, _)| n).collect()
}

/// The value without its `description` annotation.
fn annotated(value: &Value) -> Value {
    let mut object = value.as_object().unwrap().clone();
    object.remove("description");
    Value::from(object)
}

/// How `kind` is spelled in the schema.
fn schema_kind(kind: Kind) -> Value {
    if let Some(def) = kind.def() {
        return parse(&format!(r##"{{"$ref":"#/$defs/{def}"}}"##));
    }
    match kind {
        Kind::Hex | Kind::Base64url | Kind::Count | Kind::Jws | Kind::AlgList | Kind::Nested(_) => {
            unreachable!("a $ref kind")
        }
        Kind::Bool => parse(r#"{"type":"boolean"}"#),
        Kind::List(shape) => parse(&format!(
            r##"{{"type":"array","minItems":1,"items":{{"$ref":"#/$defs/{}"}}}}"##,
            shape.def
        )),
        Kind::String => parse(r#"{"type":"string"}"#),
        Kind::Object => parse(r#"{"type":"object"}"#),
        Kind::Enum(values) => {
            let mut object = Object::new();
            object.insert(
                "enum",
                values.iter().map(|v| Value::from(*v)).collect::<Vec<_>>(),
            );
            Value::from(object)
        }
    }
}

/// How a [`SignerRule`] is spelled in the schema's `allOf`.
fn schema_rule(rule: &SignerRule) -> Value {
    let mut signers = format!(r#""maxItems":{}"#, rule.max_signers);
    if !rule.requires.is_empty() || !rule.forbids.is_empty() {
        let required: Vec<Value> = rule.requires.iter().map(|n| Value::from(*n)).collect();
        let forbidden: Vec<String> = rule
            .forbids
            .iter()
            .map(|n| format!(r#""{n}":false"#))
            .collect();
        signers.push_str(&format!(
            r#","items":{{"required":{},"properties":{{{}}}}}"#,
            Value::from(required).to_json(),
            forbidden.join(",")
        ));
    }
    parse(&format!(
        r#"{{"if":{{"properties":{{"serialization":{{"const":"{}"}}}}}},"then":{{"properties":{{"signers":{{{signers}}}}}}}}}"#,
        rule.serialization
    ))
}

/// `$ref` target name of `{"$ref": "#/$defs/<name>"}`.
fn def_ref<'a>(value: &'a Value, used: &mut Vec<String>) -> &'a str {
    let target = value.get("$ref").and_then(Value::as_str).unwrap();
    let name = target.strip_prefix("#/$defs/").unwrap();
    used.push(name.to_owned());
    name
}

/// A `$defs` object definition: exactly the keywords checked here, closed,
/// and its members (after `ok: {"const": true}` when `ok` is set) are
/// `shape`'s, in order, with the same kinds and the same `required` list.
fn check_def(defs: &Value, shape: &Shape, ok: bool, used: &mut Vec<String>) {
    let name = shape.def;
    used.push(name.to_owned());
    let def = at(defs, &[name]);
    let mut keywords = vec!["type", "required", "additionalProperties", "properties"];
    if !shape.rules.is_empty() {
        keywords.push("allOf");
        let rules: Vec<Value> = shape.rules.iter().map(schema_rule).collect();
        assert_eq!(*at(def, &["allOf"]), Value::from(rules), "{name}: allOf");
    }
    assert_eq!(member_names(&annotated(def)), keywords, "{name}: keywords");
    let mut names: Vec<&str> = shape.members.iter().map(|m| m.name).collect();
    let mut required: Vec<&str> = shape
        .members
        .iter()
        .filter(|m| m.required)
        .map(|m| m.name)
        .collect();
    if ok {
        names.insert(0, "ok");
        required.insert(0, "ok");
        assert_eq!(
            *at(def, &["properties", "ok"]),
            parse(r#"{"const":true}"#),
            "{name}"
        );
    }
    assert_eq!(at(def, &["type"]).as_str(), Some("object"), "{name}");
    assert_eq!(
        at(def, &["additionalProperties"]).as_bool(),
        Some(false),
        "{name}"
    );
    assert_eq!(strings(at(def, &["required"])), required, "{name}");
    assert_eq!(member_names(at(def, &["properties"])), names, "{name}");
    for member in shape.members {
        used.extend(member.kind.def().map(str::to_owned));
        if let Kind::Nested(inner) | Kind::List(inner) = member.kind {
            check_def(defs, inner, false, used);
        }
        let property = at(def, &["properties", member.name]);
        assert_eq!(
            annotated(property),
            schema_kind(member.kind),
            "{name}/{}",
            member.name
        );
    }
}

/// Drift guard: the hand-written validator implements exactly schema.json.
#[test]
fn schema_and_runner_agree() {
    let schema = schema();
    let defs = at(&schema, &["$defs"]);
    let mut used = Vec::new();

    assert_eq!(
        at(&schema, &["$schema"]).as_str(),
        Some("https://json-schema.org/draft/2020-12/schema")
    );
    // Root keywords: annotations plus exactly the constraints checked below.
    assert_eq!(
        member_names(&schema),
        [
            "$schema",
            "title",
            "description",
            "type",
            "required",
            "additionalProperties",
            "properties",
            "allOf",
            "$defs"
        ]
    );
    assert_eq!(at(&schema, &["type"]).as_str(), Some("object"));
    assert_eq!(
        at(&schema, &["additionalProperties"]).as_bool(),
        Some(false)
    );
    assert_eq!(strings(at(&schema, &["required"])), TOP_LEVEL);
    assert_eq!(member_names(at(&schema, &["properties"])), TOP_LEVEL);
    for name in ["source", "description"] {
        let property = annotated(at(&schema, &["properties", name]));
        assert_eq!(property, parse(r##"{"$ref":"#/$defs/text"}"##));
        def_ref(&property, &mut used);
    }
    assert_eq!(
        *at(defs, &["text"]),
        parse(&format!(
            r#"{{"type":"string","minLength":1,"pattern":{}}}"#,
            Value::from(TEXT_PATTERN).to_json()
        ))
    );
    assert_eq!(
        member_names(at(&schema, &["properties", "operation"])),
        ["enum"]
    );
    assert_eq!(
        strings(at(&schema, &["properties", "operation", "enum"])),
        OPERATIONS
    );
    assert_eq!(
        *at(&schema, &["properties", "input"]),
        parse(r#"{"type":"object"}"#)
    );
    assert_eq!(
        *at(&schema, &["properties", "expect"]),
        parse(r#"{"type":"object","required":["ok"],"properties":{"ok":{"type":"boolean"}}}"#)
    );

    for (name, pattern) in [("hex", HEX_PATTERN), ("base64url", BASE64URL_PATTERN)] {
        assert_eq!(
            annotated(at(defs, &[name])),
            parse(&format!(
                r#"{{"type":"string","pattern":{}}}"#,
                Value::from(pattern).to_json()
            )),
            "{name}"
        );
    }
    assert_eq!(
        member_names(&annotated(at(defs, &["error_code"]))),
        ["enum"]
    );
    assert_eq!(strings(at(defs, &["error_code", "enum"])), Error::CODES);
    assert_eq!(
        annotated(at(defs, &["failure"])),
        parse(
            r##"{"type":"object","required":["ok","error"],"additionalProperties":false,
                "properties":{"ok":{"const":false},"error":{"$ref":"#/$defs/error_code"}}}"##
        )
    );
    used.extend(["error_code"].map(str::to_owned));
    assert_eq!(
        annotated(at(defs, &["count"])),
        parse(&format!(
            r#"{{"type":"integer","minimum":0,"maximum":{COUNT_MAX}}}"#
        ))
    );
    assert_eq!(
        annotated(at(defs, &["jws"])),
        parse(r#"{"type":["string","object"]}"#)
    );
    assert_eq!(
        annotated(at(defs, &["alg_list"])),
        parse(r#"{"type":"array","items":{"type":"string"}}"#)
    );

    let rules = at(&schema, &["allOf"]).as_array().unwrap();
    assert_eq!(
        rules.len(),
        SPECS.len(),
        "one if/then rule per implemented operation"
    );
    for (rule, spec) in rules.iter().zip(SPECS) {
        assert_eq!(member_names(rule), ["if", "then"]);
        assert_eq!(
            *at(rule, &["if"]),
            parse(&format!(
                r#"{{"required":["operation"],"properties":{{"operation":{{"const":"{}"}}}}}}"#,
                spec.name
            ))
        );
        let then = at(rule, &["then"]);
        assert_eq!(member_names(then), ["properties"], "{}", spec.name);
        assert_eq!(member_names(at(then, &["properties"])), ["input", "expect"]);
        let input = def_ref(at(then, &["properties", "input"]), &mut used);
        assert_eq!(input, spec.input.def, "{}", spec.name);
        check_def(defs, spec.input, false, &mut used);

        // The success forms, then `failure` if the operation can fail: one
        // `$ref`, or a `oneOf` of them in that order.
        let mut alternatives: Vec<&str> = spec.ok.iter().map(|s| s.def).collect();
        if spec.can_fail {
            alternatives.push("failure");
        }
        let expect = at(then, &["properties", "expect"]);
        let refs: Vec<&str> = if alternatives.len() == 1 {
            assert_eq!(member_names(expect), ["$ref"], "{}", spec.name);
            vec![def_ref(expect, &mut used)]
        } else {
            assert_eq!(member_names(expect), ["oneOf"], "{}", spec.name);
            at(expect, &["oneOf"])
                .as_array()
                .unwrap()
                .iter()
                .map(|alternative| def_ref(alternative, &mut used))
                .collect()
        };
        assert_eq!(refs, alternatives, "{}", spec.name);
        for shape in spec.ok {
            check_def(defs, shape, true, &mut used);
        }
    }

    // No stale definitions.
    let mut defined: Vec<&str> = member_names(defs);
    defined.sort_unstable();
    used.sort();
    used.dedup();
    assert_eq!(defined, used, "every $defs entry is used");
}

/// The hand-written checks implement the schema's patterns.
#[test]
fn hand_written_checks_match_the_patterns() {
    // ^([0-9a-f]{2})*$
    for (s, ok) in [
        ("", true),
        ("00", true),
        ("0aff", true),
        ("0", false),
        ("0A", false),
        ("0g", false),
        ("00 ", false),
    ] {
        assert_eq!(is_hex(s), ok, "{s:?}");
    }
    // ^[A-Za-z0-9_-]*$
    for (s, ok) in [
        ("", true),
        ("AZaz09-_", true),
        ("Zg==", false),
        ("+/", false),
        ("a b", false),
        ("é", false),
    ] {
        assert_eq!(is_base64url_alphabet(s), ok, "{s:?}");
    }
    // minLength 1 and \S
    for (s, ok) in [
        ("", false),
        (" ", false),
        ("\t\r\n", false),
        ("x", true),
        (" RFC 4648 ", true),
    ] {
        assert_eq!(is_text(s), ok, "{s:?}");
    }
    // {"type": "integer", "minimum": 0, "maximum": 4294967295}
    for (json, ok) in [
        ("0", true),
        ("16", true),
        ("4294967295", true),
        ("1.0", true), // JSON Schema: an integer value is an integer
        ("4294967296", false),
        ("-1", false),
        ("1.5", false),
        ("\"1\"", false),
        ("null", false),
    ] {
        assert_eq!(is_count(&parse(json)), ok, "{json}");
    }
}

// ---------------------------------------------------------------------------
// Tests of the runner itself (criteria 1-3). Fixtures live in memory or in a
// temporary directory, never under conformance/vectors/.
// ---------------------------------------------------------------------------

const SOURCE: &str = "runner self-test 7f3a";

fn vector(operation: &str, input: &str, expect: &str) -> String {
    format!(
        r#"{{"source":"{SOURCE}","description":"self-test","operation":"{operation}","input":{input},"expect":{expect}}}"#
    )
}

fn fails_naming_source(name: &str, json: &str, needle: &str) {
    match check_vector(name, json.as_bytes()) {
        Ok(passed) => panic!("{name}: expected a failure, but it passed: {passed:?}: {json}"),
        Err(msg) => {
            assert!(msg.contains(name), "file name missing from {msg:?}");
            assert!(msg.contains(SOURCE), "source missing from {msg:?}");
            assert!(msg.contains(needle), "{needle:?} missing from {msg:?}");
        }
    }
}

#[test]
fn valid_vectors_pass() {
    let cases = [
        vector(
            "b64url.encode",
            r#"{"bytes_hex":"666f6f"}"#,
            r#"{"ok":true,"b64u":"Zm9v"}"#,
        ),
        vector(
            "b64url.decode",
            r#"{"b64u":"Zm9v"}"#,
            r#"{"ok":true,"bytes_hex":"666f6f"}"#,
        ),
        vector(
            "b64url.decode",
            r#"{"b64u":"Zg=="}"#,
            r#"{"ok":false,"error":"InvalidBase64"}"#,
        ),
        vector(
            "jwk.thumbprint",
            r#"{"hash":"sha-256","jwk":{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}}"#,
            r#"{"ok":true,"thumbprint":"kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k","thumbprint_uri":"urn:ietf:params:oauth:jwk-thumbprint:sha-256:kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"}"#,
        ),
        vector(
            "jwk.thumbprint",
            r#"{"hash":"sha-256","jwk":{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg=="}}"#,
            r#"{"ok":false,"error":"InvalidBase64"}"#,
        ),
        // RFC 8410 §10.1; member order of the expected JWK does not matter.
        vector(
            "keys.import_pem",
            &format!(r#"{{"pem":{}}}"#, Value::from(RFC8410_10_1_PEM).to_json()),
            r#"{"ok":true,"jwk":{"x":"Gb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE","crv":"Ed25519","kty":"OKP"}}"#,
        ),
        vector(
            "keys.import_pem",
            r#"{"pem":"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"}"#,
            r#"{"ok":false,"error":"UnsupportedAlgorithm"}"#,
        ),
        vector(
            "keys.export_pem",
            r#"{"format":"spki","jwk":{"kty":"OKP","crv":"Ed25519","x":"Gb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE"}}"#,
            &format!(
                r#"{{"ok":true,"pem":{}}}"#,
                Value::from(RFC8410_10_1_PEM).to_json()
            ),
        ),
        vector(
            "keys.export_pem",
            r#"{"format":"pkcs8","jwk":{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}}"#,
            r#"{"ok":false,"error":"UnsupportedAlgorithm"}"#,
        ),
        vector(
            "keys.import_der",
            &format!(r#"{{"format":"spki","der_b64u":"{RFC8410_10_1_DER}"}}"#),
            r#"{"ok":true,"jwk":{"x":"Gb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE","crv":"Ed25519","kty":"OKP"}}"#,
        ),
        // RFC 5958 §2: an SPKI is not a OneAsymmetricKey.
        vector(
            "keys.import_der",
            &format!(r#"{{"format":"pkcs8","der_b64u":"{RFC8410_10_1_DER}"}}"#),
            r#"{"ok":false,"error":"InvalidKey"}"#,
        ),
    ];
    for json in cases {
        assert!(
            check_vector("ok.json", json.as_bytes()).is_ok(),
            "{:?}",
            check_vector("ok.json", json.as_bytes())
        );
    }
}

/// RFC 8410 §10.1, the Ed25519 public key as SPKI.
const RFC8410_10_1_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n-----END PUBLIC KEY-----\n";
/// The DER of [`RFC8410_10_1_PEM`], as canonical base64url.
const RFC8410_10_1_DER: &str = "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE";

/// The keys.* vectors are checked like every other: a wrong expectation,
/// a format outside the enum and a missing member all fail the run.
#[test]
fn keys_vectors_fail_when_wrong_or_malformed() {
    let pem = Value::from(RFC8410_10_1_PEM).to_json();
    let jwk = r#"{"kty":"OKP","crv":"Ed25519","x":"Gb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE"}"#;
    for (name, json, needle) in [
        (
            "import-wrong-jwk.json",
            vector(
                "keys.import_pem",
                &format!(r#"{{"pem":{pem}}}"#),
                r#"{"ok":true,"jwk":{"kty":"OKP","crv":"X25519","x":"Gb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE"}}"#,
            ),
            "`jwk`",
        ),
        (
            "import-wrong-code.json",
            vector(
                "keys.import_pem",
                &format!(r#"{{"pem":{pem}}}"#),
                r#"{"ok":false,"error":"InvalidKey"}"#,
            ),
            "expected error InvalidKey",
        ),
        (
            "export-bad-format.json",
            vector(
                "keys.export_pem",
                &format!(r#"{{"jwk":{jwk},"format":"der"}}"#),
                r#"{"ok":false,"error":"UnsupportedAlgorithm"}"#,
            ),
            "/input/format",
        ),
        (
            "export-no-format.json",
            vector(
                "keys.export_pem",
                &format!(r#"{{"jwk":{jwk}}}"#),
                r#"{"ok":false,"error":"UnsupportedAlgorithm"}"#,
            ),
            "/input/format",
        ),
        (
            "export-wrong-pem.json",
            vector(
                "keys.export_pem",
                &format!(r#"{{"jwk":{jwk},"format":"spki"}}"#),
                r#"{"ok":true,"pem":"-----BEGIN PUBLIC KEY-----\n"}"#,
            ),
            "`pem`",
        ),
        (
            "import-der-wrong-jwk.json",
            vector(
                "keys.import_der",
                &format!(r#"{{"der_b64u":"{RFC8410_10_1_DER}","format":"spki"}}"#),
                r#"{"ok":true,"jwk":{"kty":"OKP","crv":"X25519","x":"Gb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE"}}"#,
            ),
            "`jwk`",
        ),
        (
            "import-der-padded.json",
            vector(
                "keys.import_der",
                &format!(r#"{{"der_b64u":"{RFC8410_10_1_DER}=","format":"spki"}}"#),
                r#"{"ok":false,"error":"InvalidKey"}"#,
            ),
            "/input/der_b64u",
        ),
        (
            // The last character carries non-zero pad bits (RFC 4648 §3.5):
            // the runner cannot decode it, so the vector is broken.
            "import-der-non-canonical.json",
            vector(
                "keys.import_der",
                &format!(
                    r#"{{"der_b64u":"{}F","format":"spki"}}"#,
                    &RFC8410_10_1_DER[..RFC8410_10_1_DER.len() - 1]
                ),
                r#"{"ok":false,"error":"InvalidKey"}"#,
            ),
            "not canonical base64url",
        ),
        (
            "import-der-no-format.json",
            vector(
                "keys.import_der",
                &format!(r#"{{"der_b64u":"{RFC8410_10_1_DER}"}}"#),
                r#"{"ok":false,"error":"InvalidKey"}"#,
            ),
            "/input/format",
        ),
        (
            "import-der-pem-member.json",
            vector(
                "keys.import_der",
                &format!(r#"{{"pem":{pem},"format":"spki"}}"#),
                r#"{"ok":false,"error":"InvalidKey"}"#,
            ),
            "/input/pem",
        ),
        (
            "import-extra-member.json",
            vector(
                "keys.import_pem",
                &format!(r#"{{"pem":{pem},"format":"spki"}}"#),
                r#"{"ok":false,"error":"InvalidKey"}"#,
            ),
            "/input/format",
        ),
    ] {
        fails_naming_source(name, &json, needle);
    }
}

/// Criterion 1: an operation the schema does not know fails the run.
#[test]
fn unknown_operation_fails() {
    let json = vector("b64url.frobnicate", r#"{"b64u":""}"#, r#"{"ok":true}"#);
    fails_naming_source("unknown-op.json", &json, "unknown operation");
}

/// Criterion 1: an operation the schema reserves but this runner does not
/// implement fails the run too; it is never skipped.
#[test]
fn reserved_but_unimplemented_operations_fail() {
    for op in ["jwe.encrypt", "jwe.decrypt", "jwt.validate"] {
        let json = vector(op, r#"{"token":"a.b.c"}"#, r#"{"ok":true}"#);
        fails_naming_source("reserved-op.json", &json, "not implemented");
    }
}

/// Criterion 2: every way of breaking the schema fails the run, and the
/// message names the source whenever the vector has a usable one.
#[test]
fn schema_invalid_vectors_fail() {
    let encode_ok = r#"{"ok":true,"b64u":"Zm9v"}"#;
    let cases: &[(&str, String, &str)] = &[
        (
            "extra top-level member",
            vector("b64url.encode", r#"{"bytes_hex":"666f6f"}"#, encode_ok)
                .replace(r#""operation""#, r#""comment":"x","operation""#),
            "/comment: unknown member",
        ),
        (
            "blank description",
            vector("b64url.encode", r#"{"bytes_hex":"666f6f"}"#, encode_ok)
                .replace(r#""self-test""#, r#"" \t""#),
            "/description",
        ),
        (
            "description not a string",
            vector("b64url.encode", r#"{"bytes_hex":"666f6f"}"#, encode_ok)
                .replace(r#""self-test""#, "7"),
            "/description",
        ),
        (
            "missing input",
            vector("b64url.encode", r#"{"bytes_hex":"666f6f"}"#, encode_ok)
                .replace(r#""input":{"bytes_hex":"666f6f"},"#, ""),
            "/input: required member is missing",
        ),
        (
            "input not an object",
            vector("b64url.encode", r#""666f6f""#, encode_ok),
            "/input",
        ),
        (
            "unknown input member",
            vector(
                "b64url.encode",
                r#"{"bytes_hex":"666f6f","bytes":"foo"}"#,
                encode_ok,
            ),
            "/input/bytes: unknown member",
        ),
        (
            "missing input member",
            vector("b64url.encode", "{}", encode_ok),
            "/input/bytes_hex: required member is missing",
        ),
        (
            "uppercase hex",
            vector("b64url.encode", r#"{"bytes_hex":"666F6F"}"#, encode_ok),
            "/input/bytes_hex",
        ),
        (
            "odd-length hex",
            vector("b64url.encode", r#"{"bytes_hex":"666f6"}"#, encode_ok),
            "/input/bytes_hex",
        ),
        (
            "non-hex digit",
            vector("b64url.encode", r#"{"bytes_hex":"66zz"}"#, encode_ok),
            "/input/bytes_hex",
        ),
        (
            "base64url output with padding",
            vector(
                "b64url.encode",
                r#"{"bytes_hex":"66"}"#,
                r#"{"ok":true,"b64u":"Zg=="}"#,
            ),
            "/expect/b64u",
        ),
        (
            "missing ok",
            vector("b64url.encode", r#"{"bytes_hex":"66"}"#, r#"{"b64u":"Zg"}"#),
            "/expect/ok: required member is missing",
        ),
        (
            "ok not a boolean",
            vector(
                "b64url.encode",
                r#"{"bytes_hex":"66"}"#,
                r#"{"ok":"true","b64u":"Zg"}"#,
            ),
            "/expect/ok",
        ),
        (
            "encode cannot expect a failure",
            vector(
                "b64url.encode",
                r#"{"bytes_hex":"66"}"#,
                r#"{"ok":false,"error":"InvalidBase64"}"#,
            ),
            "cannot fail",
        ),
        (
            "success with an error member",
            vector(
                "b64url.decode",
                r#"{"b64u":"Zg"}"#,
                r#"{"ok":true,"bytes_hex":"66","error":"InvalidBase64"}"#,
            ),
            "/expect/error: unknown member",
        ),
        (
            "failure with an output member",
            vector(
                "b64url.decode",
                r#"{"b64u":"Zg"}"#,
                r#"{"ok":false,"error":"InvalidBase64","bytes_hex":"66"}"#,
            ),
            "/expect/bytes_hex: unknown member",
        ),
        (
            "failure without an error code",
            vector("b64url.decode", r#"{"b64u":"Zg=="}"#, r#"{"ok":false}"#),
            "/expect/error: required member is missing",
        ),
        (
            "unknown error code",
            vector(
                "b64url.decode",
                r#"{"b64u":"Zg=="}"#,
                r#"{"ok":false,"error":"BadBase64"}"#,
            ),
            "/expect/error",
        ),
        (
            "decode input not a string",
            vector(
                "b64url.decode",
                r#"{"b64u":["Zg"]}"#,
                r#"{"ok":true,"bytes_hex":"66"}"#,
            ),
            "/input/b64u",
        ),
        (
            "unsupported thumbprint hash",
            vector(
                "jwk.thumbprint",
                r#"{"hash":"sha-1","jwk":{"kty":"oct","k":"AA"}}"#,
                r#"{"ok":false,"error":"InvalidKey"}"#,
            ),
            "/input/hash",
        ),
        (
            "jwk not an object",
            vector(
                "jwk.thumbprint",
                r#"{"hash":"sha-256","jwk":"{\"kty\":\"oct\"}"}"#,
                r#"{"ok":false,"error":"InvalidKey"}"#,
            ),
            "/input/jwk",
        ),
        (
            "thumbprint success missing the URI",
            vector(
                "jwk.thumbprint",
                r#"{"hash":"sha-256","jwk":{"kty":"oct","k":"AA"}}"#,
                r#"{"ok":true,"thumbprint":"AA"}"#,
            ),
            "/expect/thumbprint_uri: required member is missing",
        ),
        (
            "operation not a string",
            vector("b64url.encode", r#"{"bytes_hex":"66"}"#, encode_ok)
                .replace(r#""b64url.encode""#, r#"["b64url.encode"]"#),
            "/operation",
        ),
    ];
    for (what, json, needle) in cases {
        let name = format!("invalid ({what}).json");
        fails_naming_source(&name, json, needle);
    }
}

/// A vector without a usable `source` is schema-invalid; the message still
/// names the file and says the source is missing.
#[test]
fn vectors_without_a_source_fail() {
    let valid = vector(
        "b64url.encode",
        r#"{"bytes_hex":"66"}"#,
        r#"{"ok":true,"b64u":"Zg"}"#,
    );
    let source_member = format!(r#""source":"{SOURCE}","#);
    let cases = [
        valid.replace(&source_member, ""),
        valid.replace(&source_member, r#""source":"","#),
        valid.replace(&source_member, r#""source":"   ","#),
        valid.replace(&source_member, r#""source":null,"#),
    ];
    for json in cases {
        let msg = check_vector("no-source.json", json.as_bytes()).unwrap_err();
        assert!(msg.contains("no-source.json"), "{msg}");
        assert!(msg.contains("/source"), "{msg}");
    }
}

/// Files that are not one JSON object fail, naming the file.
#[test]
fn unparseable_files_fail() {
    let duplicate = vector(
        "b64url.encode",
        r#"{"bytes_hex":"66"}"#,
        r#"{"ok":true,"b64u":"Zg"}"#,
    )
    .replace(r#""input""#, r#""source":"again","input""#);
    for json in ["", "[]", "{", "\"vector\"", duplicate.as_str()] {
        let msg = check_vector("broken.json", json.as_bytes()).unwrap_err();
        assert!(msg.contains("broken.json"), "{msg}");
    }
}

/// Criterion 3: a vector whose expectation the library does not meet fails,
/// and the message names the file and the source.
#[test]
fn failing_vectors_fail_naming_their_source() {
    let cases = [
        (
            "wrong encoding",
            vector(
                "b64url.encode",
                r#"{"bytes_hex":"666f6f"}"#,
                r#"{"ok":true,"b64u":"Zm9w"}"#,
            ),
            "Zm9w",
        ),
        (
            "wrong decoded bytes",
            vector(
                "b64url.decode",
                r#"{"b64u":"Zm9v"}"#,
                r#"{"ok":true,"bytes_hex":"666f70"}"#,
            ),
            "666f70",
        ),
        (
            "expected success, got an error",
            vector(
                "b64url.decode",
                r#"{"b64u":"Zg=="}"#,
                r#"{"ok":true,"bytes_hex":"66"}"#,
            ),
            "InvalidBase64",
        ),
        (
            "expected an error, got success",
            vector(
                "b64url.decode",
                r#"{"b64u":"Zg"}"#,
                r#"{"ok":false,"error":"InvalidBase64"}"#,
            ),
            "succeeded",
        ),
        (
            "wrong error code",
            vector(
                "b64url.decode",
                r#"{"b64u":"Zg=="}"#,
                r#"{"ok":false,"error":"InvalidKey"}"#,
            ),
            "InvalidKey",
        ),
        (
            "wrong thumbprint URI",
            vector(
                "jwk.thumbprint",
                r#"{"hash":"sha-256","jwk":{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}}"#,
                r#"{"ok":true,"thumbprint":"kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k","thumbprint_uri":"urn:ietf:params:oauth:jwk-thumbprint:sha-512:kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"}"#,
            ),
            "thumbprint_uri",
        ),
    ];
    for (what, json, needle) in cases {
        let name = format!("failing ({what}).json");
        fails_naming_source(&name, &json, needle);
    }
}

// ---------------------------------------------------------------------------
// jws.* self-tests, on RFC 7515 Appendix A values (the vector files under
// conformance/vectors/jws-rfc7515/ cite them).
// ---------------------------------------------------------------------------

/// RFC 7515 A.1 HMAC key.
const A1_KEY: &str = r#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#;
/// RFC 7515 A.1 protected header `{"typ":"JWT",\r\n "alg":"HS256"}`.
const A1_PROTECTED: &str = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9";
/// RFC 7515 A.1 payload (also A.2, A.3, A.5, A.6, A.7).
const PAYLOAD: &str = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
/// RFC 7515 A.1 HS256 signature.
const A1_SIGNATURE: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
/// RFC 7515 A.3 P-256 key, public and private.
const A3_PUBLIC: &str = r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#;
/// RFC 7515 A.3 protected header `{"alg":"ES256"}` and signature.
const A3_PROTECTED: &str = "eyJhbGciOiJFUzI1NiJ9";
const A3_SIGNATURE: &str =
    "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";
/// RFC 7515 A.5 unsecured JWS.
const A5_JWS: &str = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.";
/// An RSA private JWK, which JWK import refuses (ADR 0021).
const RSA_PRIVATE: &str = r#"{"kty":"RSA","n":"AQAB","e":"AQAB","d":"AQAB"}"#;

fn a1_compact() -> String {
    format!("{A1_PROTECTED}.{PAYLOAD}.{A1_SIGNATURE}")
}

/// RFC 7515 A.7, the flattened JSON Serialization.
fn a7_flattened() -> String {
    format!(
        r#"{{"payload":"{PAYLOAD}","protected":"{A3_PROTECTED}","header":{{"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"}},"signature":"{A3_SIGNATURE}"}}"#
    )
}

/// A general JSON JWS whose signatures are A.1's (HS256) and A.3's (ES256).
fn general_hs256_es256() -> String {
    format!(
        r#"{{"payload":"{PAYLOAD}","signatures":[{{"protected":"{A1_PROTECTED}","signature":"{A1_SIGNATURE}"}},{{"protected":"{A3_PROTECTED}","signature":"{A3_SIGNATURE}"}}]}}"#
    )
}

fn verify_input(jws: &str, key: &str, algs: &str, extra: &str) -> String {
    format!(r#"{{"jws":{jws},"key":{key},"allowed_algs":{algs}{extra}}}"#)
}

fn verified(alg: &str, index: u32) -> String {
    format!(r#"{{"ok":true,"payload_b64u":"{PAYLOAD}","alg":"{alg}","signature_index":{index}}}"#)
}

fn quoted(s: &str) -> String {
    format!("\"{s}\"")
}

fn assert_passes(cases: &[String]) {
    for json in cases {
        let result = check_vector("ok.json", json.as_bytes());
        assert!(result.is_ok(), "{result:?}\n  for {json}");
    }
}

/// Every `jws.verify` input form runs: compact, flattened and general,
/// detached, limits, and errors from JWK import and the allow-list.
#[test]
fn jws_verify_vectors_pass() {
    let a1 = quoted(&a1_compact());
    let detached = quoted(&format!("{A1_PROTECTED}..{A1_SIGNATURE}"));
    let fails = |code: &str| format!(r#"{{"ok":false,"error":"{code}"}}"#);
    assert_passes(&[
        vector(
            "jws.verify",
            &verify_input(&a1, A1_KEY, r#"["HS256"]"#, ""),
            &verified("HS256", 0),
        ),
        vector(
            "jws.verify",
            &verify_input(&a7_flattened(), A3_PUBLIC, r#"["ES256"]"#, ""),
            &verified("ES256", 0),
        ),
        // The first signature that verifies with the key wins (ADR 0026 §3).
        vector(
            "jws.verify",
            &verify_input(
                &general_hs256_es256(),
                A3_PUBLIC,
                r#"["HS256","ES256"]"#,
                "",
            ),
            &verified("ES256", 1),
        ),
        vector(
            "jws.verify",
            &verify_input(
                &detached,
                A1_KEY,
                r#"["HS256"]"#,
                &format!(r#","detached_payload_b64u":"{PAYLOAD}""#),
            ),
            &verified("HS256", 0),
        ),
        vector(
            "jws.verify",
            &verify_input(&quoted(A5_JWS), A1_KEY, r#"["HS256"]"#, ""),
            &fails("AlgorithmNotAllowed"),
        ),
        // The allow-list is refused before anything is verified.
        vector(
            "jws.verify",
            &verify_input(&a1, A1_KEY, "[]", ""),
            &fails("AlgorithmNotAllowed"),
        ),
        vector(
            "jws.verify",
            &verify_input(&a1, A1_KEY, r#"["none"]"#, ""),
            &fails("AlgorithmNotAllowed"),
        ),
        // A JWK import error is the vector's outcome.
        vector(
            "jws.verify",
            &verify_input(&a1, RSA_PRIVATE, r#"["RS256"]"#, ""),
            &fails("UnsupportedAlgorithm"),
        ),
        vector(
            "jws.verify",
            &verify_input(&a1, A1_KEY, r#"["HS256"]"#, r#","max_input_len":10"#),
            &fails("InvalidFormat"),
        ),
        vector(
            "jws.verify",
            &verify_input(
                &general_hs256_es256(),
                A3_PUBLIC,
                r#"["HS256","ES256"]"#,
                r#","max_signatures":1"#,
            ),
            &fails("InvalidFormat"),
        ),
        vector(
            "jws.verify",
            &verify_input(
                &general_hs256_es256(),
                A3_PUBLIC,
                r#"["HS256","ES256"]"#,
                r#","max_signatures":2,"max_input_len":4294967295"#,
            ),
            &verified("ES256", 1),
        ),
    ]);
}

/// A `jws.verify` vector that breaks the schema fails the run.
#[test]
fn jws_verify_schema_violations_fail() {
    let a1 = quoted(&a1_compact());
    let input = |extra: &str| verify_input(&a1, A1_KEY, r#"["HS256"]"#, extra);
    let ok = verified("HS256", 0);
    let cases: Vec<(&str, String, &str)> = vec![
        (
            "misspelled member",
            vector(
                "jws.verify",
                &format!(r#"{{"jws":{a1},"key":{A1_KEY},"allowed_alg":["HS256"]}}"#),
                &ok,
            ),
            "/input/allowed_alg: unknown member",
        ),
        (
            "missing allowed_algs",
            vector(
                "jws.verify",
                &format!(r#"{{"jws":{a1},"key":{A1_KEY}}}"#),
                &ok,
            ),
            "/input/allowed_algs: required member is missing",
        ),
        (
            "jws a number",
            vector(
                "jws.verify",
                &verify_input("7", A1_KEY, r#"["HS256"]"#, ""),
                &ok,
            ),
            "/input/jws",
        ),
        (
            "jws an array",
            vector(
                "jws.verify",
                &verify_input(&format!("[{a1}]"), A1_KEY, r#"["HS256"]"#, ""),
                &ok,
            ),
            "/input/jws",
        ),
        (
            "key a string",
            vector(
                "jws.verify",
                &verify_input(&a1, &quoted("k"), r#"["HS256"]"#, ""),
                &ok,
            ),
            "/input/key",
        ),
        (
            "allowed_algs a string",
            vector(
                "jws.verify",
                &verify_input(&a1, A1_KEY, r#""HS256""#, ""),
                &ok,
            ),
            "/input/allowed_algs",
        ),
        (
            "allowed_algs with a number",
            vector(
                "jws.verify",
                &verify_input(&a1, A1_KEY, r#"["HS256",256]"#, ""),
                &ok,
            ),
            "/input/allowed_algs",
        ),
        (
            "negative max_signatures",
            vector("jws.verify", &input(r#","max_signatures":-1"#), &ok),
            "/input/max_signatures",
        ),
        (
            "fractional max_signatures",
            vector("jws.verify", &input(r#","max_signatures":1.5"#), &ok),
            "/input/max_signatures",
        ),
        (
            "max_input_len above u32",
            vector("jws.verify", &input(r#","max_input_len":4294967296"#), &ok),
            "/input/max_input_len",
        ),
        (
            "max_input_len a string",
            vector("jws.verify", &input(r#","max_input_len":"10""#), &ok),
            "/input/max_input_len",
        ),
        (
            "padded detached payload",
            vector(
                "jws.verify",
                &input(r#","detached_payload_b64u":"Zg==""#),
                &ok,
            ),
            "/input/detached_payload_b64u",
        ),
        (
            "success without signature_index",
            vector(
                "jws.verify",
                &input(""),
                &format!(r#"{{"ok":true,"payload_b64u":"{PAYLOAD}","alg":"HS256"}}"#),
            ),
            "/expect/signature_index: required member is missing",
        ),
        (
            "signature_index a string",
            vector(
                "jws.verify",
                &input(""),
                &ok.replace(r#""signature_index":0"#, r#""signature_index":"0""#),
            ),
            "/expect/signature_index",
        ),
        (
            "success with a sign output",
            vector(
                "jws.verify",
                &input(""),
                &ok.replace(r#""ok":true"#, &format!(r#""ok":true,"jws":{a1}"#)),
            ),
            "/expect/jws: unknown member",
        ),
        (
            "failure with an output member",
            vector(
                "jws.verify",
                &input(""),
                r#"{"ok":false,"error":"InvalidSignature","alg":"HS256"}"#,
            ),
            "/expect/alg: unknown member",
        ),
    ];
    for (what, json, needle) in cases {
        fails_naming_source(&format!("invalid ({what}).json"), &json, needle);
    }
}

/// A `jws.verify` vector the library does not meet fails, naming the file
/// and the source.
#[test]
fn jws_verify_mismatches_fail() {
    let a1 = quoted(&a1_compact());
    let input = verify_input(&a1, A1_KEY, r#"["HS256"]"#, "");
    let cases = [
        (
            "wrong signature_index",
            vector("jws.verify", &input, &verified("HS256", 1)),
            "signature_index",
        ),
        (
            "wrong alg",
            vector("jws.verify", &input, &verified("HS384", 0)),
            "HS384",
        ),
        (
            "wrong payload",
            vector(
                "jws.verify",
                &input,
                &verified("HS256", 0).replace(PAYLOAD, "UGF5bG9hZA"),
            ),
            "payload_b64u",
        ),
        (
            "tampered signature",
            vector(
                "jws.verify",
                &input.replace(A1_SIGNATURE, &A1_SIGNATURE.replace('d', "e")),
                &verified("HS256", 0),
            ),
            "InvalidSignature",
        ),
        (
            "expected an error, got success",
            vector(
                "jws.verify",
                &input,
                r#"{"ok":false,"error":"InvalidSignature"}"#,
            ),
            "succeeded",
        ),
        // The runner decodes bytes it passes to the library; a value that
        // does not decode is the vector's fault, never an outcome.
        (
            "detached payload that does not decode",
            vector(
                "jws.verify",
                &verify_input(
                    &quoted(&format!("{A1_PROTECTED}..{A1_SIGNATURE}")),
                    A1_KEY,
                    r#"["HS256"]"#,
                    r#","detached_payload_b64u":"Zh""#,
                ),
                r#"{"ok":false,"error":"InvalidBase64"}"#,
            ),
            "detached_payload_b64u",
        ),
    ];
    for (what, json, needle) in cases {
        fails_naming_source(&format!("failing ({what}).json"), &json, needle);
    }
}

/// RFC 7515 A.3 P-256 private key.
const A3_PRIVATE: &str = r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"}"#;
/// Another P-256 public key (RFC 7517 A.1), which verifies nothing A.3 signs.
const OTHER_P256: &str = r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}"#;

fn sign_input(serialization: &str, detached: bool, signers: &[String]) -> String {
    format!(
        r#"{{"serialization":"{serialization}","payload_b64u":"{PAYLOAD}","detached":{detached},"signers":[{}]}}"#,
        signers.join(",")
    )
}

fn signer(protected: Option<&str>, header: Option<&str>, key: &str) -> String {
    let mut members = Vec::new();
    if let Some(protected) = protected {
        members.push(format!(r#""protected_b64u":"{protected}""#));
    }
    if let Some(header) = header {
        members.push(format!(r#""header":{header}"#));
    }
    members.push(format!(r#""key":{key}"#));
    format!("{{{}}}", members.join(","))
}

fn signed(jws: &str) -> String {
    format!(r#"{{"ok":true,"jws":{jws}}}"#)
}

fn round_trip(key: &str, algs: &str) -> String {
    format!(r#"{{"ok":true,"verify_with":{{"key":{key},"allowed_algs":{algs}}}}}"#)
}

/// Every `jws.sign` form runs: exact and round-trip expectations, all three
/// serializations, several signers, unprotected headers, detached output,
/// and errors from JWK import and header parsing.
#[test]
fn jws_sign_vectors_pass() {
    let hs256 = signer(Some(A1_PROTECTED), None, A1_KEY);
    let es256 = signer(Some(A3_PROTECTED), None, A3_PRIVATE);
    let fails = |code: &str| format!(r#"{{"ok":false,"error":"{code}"}}"#);
    assert_passes(&[
        vector(
            "jws.sign",
            &sign_input("compact", false, std::slice::from_ref(&hs256)),
            &signed(&quoted(&a1_compact())),
        ),
        // Appendix F: the payload part is empty.
        vector(
            "jws.sign",
            &sign_input("compact", true, std::slice::from_ref(&hs256)),
            &signed(&quoted(&format!("{A1_PROTECTED}..{A1_SIGNATURE}"))),
        ),
        // JSON output is compared as JSON: member order does not matter.
        vector(
            "jws.sign",
            &sign_input("flattened", false, std::slice::from_ref(&hs256)),
            &signed(&format!(
                r#"{{"signature":"{A1_SIGNATURE}","protected":"{A1_PROTECTED}","payload":"{PAYLOAD}"}}"#
            )),
        ),
        // Two signers; the unprotected header is not signed, so both MACs
        // are A.1's.
        vector(
            "jws.sign",
            &sign_input(
                "general",
                false,
                &[
                    hs256.clone(),
                    signer(Some(A1_PROTECTED), Some(r#"{"kid":"k2"}"#), A1_KEY),
                ],
            ),
            &signed(&format!(
                r#"{{"payload":"{PAYLOAD}","signatures":[{{"protected":"{A1_PROTECTED}","signature":"{A1_SIGNATURE}"}},{{"protected":"{A1_PROTECTED}","header":{{"kid":"k2"}},"signature":"{A1_SIGNATURE}"}}]}}"#
            )),
        ),
        vector(
            "jws.sign",
            &sign_input("compact", false, std::slice::from_ref(&es256)),
            &round_trip(A3_PUBLIC, r#"["ES256"]"#),
        ),
        vector(
            "jws.sign",
            &sign_input("flattened", true, std::slice::from_ref(&es256)),
            &round_trip(A3_PUBLIC, r#"["ES256"]"#),
        ),
        // A multi-signer round trip verifies the signature the key fits.
        vector(
            "jws.sign",
            &sign_input("general", false, &[hs256.clone(), es256.clone()]),
            &round_trip(A3_PUBLIC, r#"["ES256"]"#),
        ),
        // No protected header (RFC 7515 §7.2.1; RFC 7520 §4.7).
        vector(
            "jws.sign",
            &sign_input(
                "flattened",
                false,
                &[signer(None, Some(r#"{"alg":"HS256"}"#), A1_KEY)],
            ),
            &round_trip(A1_KEY, r#"["HS256"]"#),
        ),
        // A JWK import error is the vector's outcome (ADR 0021).
        vector(
            "jws.sign",
            &sign_input(
                "compact",
                false,
                &[signer(Some(A1_PROTECTED), None, RSA_PRIVATE)],
            ),
            &fails("UnsupportedAlgorithm"),
        ),
        // So are header errors: "foo" is not a JSON object, and kid must be
        // a string (RFC 7515 §4.1.4).
        vector(
            "jws.sign",
            &sign_input("compact", false, &[signer(Some("Zm9v"), None, A1_KEY)]),
            &fails("InvalidJson"),
        ),
        vector(
            "jws.sign",
            &sign_input(
                "flattened",
                false,
                &[signer(Some(A1_PROTECTED), Some(r#"{"kid":5}"#), A1_KEY)],
            ),
            &fails("InvalidHeader"),
        ),
        // Without a protected header, alg is missing.
        vector(
            "jws.sign",
            &sign_input("general", false, &[signer(None, None, A1_KEY)]),
            &fails("InvalidHeader"),
        ),
    ]);
}

/// A `jws.sign` vector that breaks the schema, including its
/// per-serialization rules, fails the run.
#[test]
fn jws_sign_schema_violations_fail() {
    let hs256 = signer(Some(A1_PROTECTED), None, A1_KEY);
    let one = |serialization: &str| sign_input(serialization, false, std::slice::from_ref(&hs256));
    let ok = signed(&quoted(&a1_compact()));
    let cases: Vec<(&str, String, &str)> = vec![
        (
            "compact with two signers",
            vector(
                "jws.sign",
                &sign_input("compact", false, &[hs256.clone(), hs256.clone()]),
                &ok,
            ),
            "/input/signers: a compact JWS has at most 1 signer",
        ),
        (
            "flattened with two signers",
            vector(
                "jws.sign",
                &sign_input("flattened", false, &[hs256.clone(), hs256.clone()]),
                &ok,
            ),
            "/input/signers: a flattened JWS has at most 1 signer",
        ),
        (
            "compact with only a key",
            vector(
                "jws.sign",
                &sign_input("compact", false, &[signer(None, None, A1_KEY)]),
                &ok,
            ),
            "/input/signers/0/protected_b64u: required for a compact JWS",
        ),
        (
            "compact with an unprotected header",
            vector(
                "jws.sign",
                &sign_input(
                    "compact",
                    false,
                    &[signer(Some(A1_PROTECTED), Some("{}"), A1_KEY)],
                ),
                &ok,
            ),
            "/input/signers/0/header: not allowed in a compact JWS",
        ),
        (
            "no signers",
            vector("jws.sign", &sign_input("general", false, &[]), &ok),
            "/input/signers",
        ),
        (
            "signers not an array",
            vector(
                "jws.sign",
                &one("general").replace(&format!("[{hs256}]"), &hs256),
                &ok,
            ),
            "/input/signers",
        ),
        (
            "signer not an object",
            vector(
                "jws.sign",
                &sign_input("general", false, &[quoted(A1_PROTECTED)]),
                &ok,
            ),
            "/input/signers/0",
        ),
        (
            "misspelled signer member",
            vector(
                "jws.sign",
                &one("compact").replace("protected_b64u", "protected"),
                &ok,
            ),
            "/input/signers/0/protected: unknown member",
        ),
        (
            "signer without a key",
            vector(
                "jws.sign",
                &one("compact").replace(&format!(r#","key":{A1_KEY}"#), ""),
                &ok,
            ),
            "/input/signers/0/key: required member is missing",
        ),
        (
            "padded protected header",
            vector(
                "jws.sign",
                &one("compact").replace(A1_PROTECTED, "eyJhbGciOiJIUzI1NiJ9=="),
                &ok,
            ),
            "/input/signers/0/protected_b64u",
        ),
        (
            "unknown serialization",
            vector("jws.sign", &one("json"), &ok),
            "/input/serialization",
        ),
        (
            "detached a string",
            vector(
                "jws.sign",
                &one("compact").replace(r#""detached":false"#, r#""detached":"false""#),
                &ok,
            ),
            "/input/detached",
        ),
        (
            "detached missing",
            vector(
                "jws.sign",
                &one("compact").replace(r#""detached":false,"#, ""),
                &ok,
            ),
            "/input/detached: required member is missing",
        ),
        (
            "misspelled input member",
            vector(
                "jws.sign",
                &one("compact").replace("payload_b64u", "payload"),
                &ok,
            ),
            "/input/payload: unknown member",
        ),
        (
            "both success forms",
            vector(
                "jws.sign",
                &one("compact"),
                &round_trip(A1_KEY, r#"["HS256"]"#).replace(
                    r#""ok":true"#,
                    &format!(r#""ok":true,"jws":"{}""#, a1_compact()),
                ),
            ),
            "matches none of the success forms",
        ),
        (
            "neither success form",
            vector("jws.sign", &one("compact"), r#"{"ok":true}"#),
            "matches none of the success forms",
        ),
        (
            "misspelled verify_with member",
            vector(
                "jws.sign",
                &one("compact"),
                &round_trip(A1_KEY, r#"["HS256"]"#).replace("allowed_algs", "allowed_alg"),
            ),
            "/expect/verify_with/allowed_alg: unknown member",
        ),
        (
            "verify_with without allowed_algs",
            vector(
                "jws.sign",
                &one("compact"),
                &format!(r#"{{"ok":true,"verify_with":{{"key":{A1_KEY}}}}}"#),
            ),
            "/expect/verify_with/allowed_algs: required member is missing",
        ),
        (
            "jws a number",
            vector("jws.sign", &one("compact"), &signed("7")),
            "/expect/jws",
        ),
        (
            "failure with an output",
            vector(
                "jws.sign",
                &one("compact"),
                &format!(
                    r#"{{"ok":false,"error":"InvalidKey","jws":"{}"}}"#,
                    a1_compact()
                ),
            ),
            "/expect/jws: unknown member",
        ),
    ];
    for (what, json, needle) in cases {
        fails_naming_source(&format!("invalid ({what}).json"), &json, needle);
    }
}

/// A `jws.sign` vector the library does not meet fails, naming the file and
/// the source; so does a round trip whose verification fails.
#[test]
fn jws_sign_mismatches_fail() {
    let hs256 = sign_input(
        "compact",
        false,
        &[signer(Some(A1_PROTECTED), None, A1_KEY)],
    );
    let es256 = sign_input(
        "compact",
        false,
        &[signer(Some(A3_PROTECTED), None, A3_PRIVATE)],
    );
    let cases = [
        (
            "wrong signature",
            vector(
                "jws.sign",
                &hs256,
                &signed(&quoted(&a1_compact().replace('d', "e"))),
            ),
            "`jws`",
        ),
        (
            "flattened output expected for compact",
            vector(
                "jws.sign",
                &hs256,
                &signed(&format!(
                    r#"{{"payload":"{PAYLOAD}","protected":"{A1_PROTECTED}","signature":"{A1_SIGNATURE}"}}"#
                )),
            ),
            "`jws`",
        ),
        (
            "round trip with another key",
            vector("jws.sign", &es256, &round_trip(OTHER_P256, r#"["ES256"]"#)),
            "round trip",
        ),
        (
            "round trip with another algorithm",
            vector("jws.sign", &es256, &round_trip(A3_PUBLIC, r#"["ES384"]"#)),
            "AlgorithmNotAllowed",
        ),
        (
            "round trip with a key that does not import",
            vector("jws.sign", &es256, &round_trip(RSA_PRIVATE, r#"["ES256"]"#)),
            "verify_with",
        ),
        (
            "expected an error, got success",
            vector("jws.sign", &hs256, r#"{"ok":false,"error":"InvalidKey"}"#),
            "succeeded",
        ),
        (
            "payload that does not decode",
            vector(
                "jws.sign",
                &hs256.replace(PAYLOAD, "Zh"),
                &signed(&quoted(&a1_compact())),
            ),
            "payload_b64u",
        ),
    ];
    for (what, json, needle) in cases {
        fails_naming_source(&format!("failing ({what}).json"), &json, needle);
    }
}

// ---------------------------------------------------------------------------
// Binding readiness: the WASM, Node, Kotlin and Swift runners (features
// 0006-0009) must read the jws.* vectors with their platform JSON parsers,
// unchanged (ADR 0034).
// ---------------------------------------------------------------------------

/// The number tokens of a JSON text, as written (outside strings).
fn number_tokens(text: &str) -> Vec<&str> {
    let mut tokens = Vec::new();
    let (mut in_string, mut escaped, mut start) = (false, false, None);
    for (i, c) in text.char_indices() {
        if in_string {
            match (escaped, c) {
                (true, _) => escaped = false,
                (false, '\\') => escaped = true,
                (false, '"') => in_string = false,
                _ => {}
            }
            continue;
        }
        // A number starts with '-' or a digit (RFC 8259 §6); `true` and
        // `false` hold an `e` but never start one.
        let begins = c.is_ascii_digit() || c == '-';
        let continues = begins || matches!(c, '+' | '.' | 'e' | 'E');
        match (start, begins, continues) {
            (None, true, _) => start = Some(i),
            (Some(s), _, false) => {
                tokens.push(&text[s..i]);
                start = None;
            }
            _ => {}
        }
        in_string = c == '"';
    }
    if let Some(s) = start {
        tokens.push(&text[s..]);
    }
    tokens
}

/// Every member of `value`, at any depth, with its JSON pointer.
fn members_deep<'a>(
    value: &'a Value,
    pointer: String,
    out: &mut Vec<(String, &'a str, &'a Value)>,
) {
    if let Some(object) = value.as_object() {
        for (name, member) in object {
            let at = format!("{pointer}/{name}");
            out.push((at.clone(), name, member));
            members_deep(member, at, out);
        }
    } else if let Some(items) = value.as_array() {
        for (i, item) in items.iter().enumerate() {
            members_deep(item, format!("{pointer}/{i}"), out);
        }
    }
}

/// Whether a vector file uses only what every binding's JSON parser reads
/// exactly:
///
/// - every number is written as a plain integer (no fraction or exponent,
///   which JavaScript, Kotlin and Swift parsers may read as a double) of
///   magnitude at most 2^32 - 1, so no binding needs a 64-bit-only type
///   (ADR 0030 `u32`);
/// - octets are base64url text (`*_b64u`), never raw bytes or `*_hex`, and
///   every one the runner decodes is canonical (`protected_b64u` is passed
///   to the library as text, so it may be anything the schema allows);
/// - in a `keys.*` vector, every base64url JWK member (`x`, `y`, `d`, `n`,
///   `e`, `k`; RFC 7518 §6, RFC 8037 §2) of a `jwk` object is canonical, so
///   a binding's base64url decoder reads the key the vector means.
fn binding_ready(text: &str) -> Result<(), String> {
    for token in number_tokens(text) {
        let plain = token
            .strip_prefix('-')
            .unwrap_or(token)
            .bytes()
            .all(|b| b.is_ascii_digit())
            && !token.is_empty()
            && token != "-";
        let small = token
            .parse::<i64>()
            .is_ok_and(|n| n.unsigned_abs() <= COUNT_MAX);
        if !plain || !small {
            return Err(format!(
                "number {token} is not a plain integer of magnitude at most {COUNT_MAX}"
            ));
        }
    }
    let value = json::parse(text.as_bytes()).map_err(|e| format!("not JSON ({})", e.code()))?;
    let keys_vector = value
        .get("operation")
        .and_then(Value::as_str)
        .is_some_and(|op| op.starts_with("keys."));
    let mut members = Vec::new();
    members_deep(&value, String::new(), &mut members);
    for (pointer, name, member) in members {
        let jwk_member = pointer
            .rsplit_once('/')
            .is_some_and(|(parent, _)| parent.ends_with("/jwk"));
        if keys_vector && jwk_member && JWK_B64U_MEMBERS.contains(&name) {
            let canonical = member
                .as_str()
                .is_some_and(|s| b64url_decode(s).is_ok_and(|b| b64url_encode(&b) == s));
            if !canonical {
                return Err(format!("{pointer}: not canonical base64url"));
            }
        }
        if name.ends_with("_hex") {
            return Err(format!(
                "{pointer}: raw bytes; jws.* vectors write octets as *_b64u"
            ));
        }
        if name.ends_with("_b64u") && name != "protected_b64u" {
            let canonical = member
                .as_str()
                .is_some_and(|s| b64url_decode(s).is_ok_and(|b| b64url_encode(&b) == s));
            if !canonical {
                return Err(format!("{pointer}: not canonical base64url"));
            }
        }
    }
    Ok(())
}

/// The base64url members of a JWK (RFC 7518 §6.2–§6.4, RFC 8037 §2).
const JWK_B64U_MEMBERS: &[&str] = &["x", "y", "d", "n", "e", "k"];

/// The vectors the binding-readiness rule covers: everything under a
/// `jws-*` directory, a `third_party/**/jws/` directory or `keys/`, and any
/// jws.* or keys.* vector elsewhere.
fn needs_binding_readiness(relative: &Path, text: &str) -> bool {
    let parts: Vec<String> = relative
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    let jws_dir = parts
        .first()
        .is_some_and(|first| first.starts_with("jws-") || first == "keys");
    let third_party_jws = parts.first().is_some_and(|first| first == "third_party")
        && parts[..parts.len() - 1].iter().any(|part| part == "jws");
    let jws_operation = json::parse(text.as_bytes()).is_ok_and(|v| {
        v.get("operation")
            .and_then(Value::as_str)
            .is_some_and(|op| op.starts_with("jws.") || op.starts_with("keys."))
    });
    jws_dir || third_party_jws || jws_operation
}

/// Every JWS and keys vector is binding-ready (see [`binding_ready`]).
#[test]
fn jws_and_keys_vectors_are_binding_ready() {
    let dir = conformance_dir().join("vectors");
    let (mut files, mut failures) = (Vec::new(), Vec::new());
    collect(&dir, &mut files, &mut failures);
    let mut checked = 0;
    for path in files {
        let relative = path.strip_prefix(&dir).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        if !needs_binding_readiness(relative, &text) {
            continue;
        }
        checked += 1;
        if let Err(problem) = binding_ready(&text) {
            failures.push(format!("{}: {problem}", relative.display()));
        }
    }
    assert!(
        failures.is_empty(),
        "not binding-ready:\n  {}",
        failures.join("\n  ")
    );
    assert!(
        checked >= 19,
        "only {checked} JWS and keys vector files found"
    );
}

/// The readiness check rejects what a binding could misread, and nothing
/// else; the vector selection matches the documented directories.
#[test]
fn binding_readiness_check_works() {
    for ok in [
        r#"{"a":0,"b":16,"c":-1,"d":4294967295,"e":[1,2]}"#,
        r#"{"s":"1.5e3 inside a string","t":"a\"1.0\\","n":7}"#,
        r#"{"payload_b64u":"Zm9v","protected_b64u":"Zh","x":{"detached_payload_b64u":""}}"#,
        r#"{"detached":false,"ok":true,"v":null,"n":12}"#,
        r#"{"operation":"keys.export_pem","input":{"jwk":{"kty":"oct","k":"Zm9v"}}}"#,
        // Outside keys.*, a `jwk` object's members are not checked here.
        r#"{"operation":"jws.verify","x":{"jwk":{"k":"Zh"}}}"#,
    ] {
        assert_eq!(binding_ready(ok), Ok(()), "{ok}");
    }
    for (bad, needle) in [
        (r#"{"n":1.0}"#, "1.0"),
        (r#"{"n":1e3}"#, "1e3"),
        (r#"{"n":0.5}"#, "0.5"),
        (r#"{"n":-0.0}"#, "-0.0"),
        (r#"{"n":4294967296}"#, "4294967296"),
        (r#"{"n":-4294967296}"#, "-4294967296"),
        (r#"{"a":[{"n":9007199254740993}]}"#, "9007199254740993"),
        (r#"{"input":{"bytes_hex":"00"}}"#, "/input/bytes_hex"),
        (r#"{"payload_b64u":"Zh"}"#, "/payload_b64u"),
        (
            r#"{"x":[{"detached_payload_b64u":"Zg=="}]}"#,
            "/x/0/detached_payload_b64u",
        ),
        (
            r#"{"operation":"keys.export_pem","input":{"jwk":{"kty":"oct","k":"Zh"}}}"#,
            "/input/jwk/k",
        ),
        (
            r#"{"operation":"keys.import_pem","expect":{"jwk":{"x":"Zg=="}}}"#,
            "/expect/jwk/x",
        ),
    ] {
        let problem = binding_ready(bad).unwrap_err();
        assert!(problem.contains(needle), "{bad}: {problem}");
    }
    let verify = r#"{"operation":"jws.verify"}"#;
    let import = r#"{"operation":"keys.import_pem"}"#;
    let other = r#"{"operation":"b64url.encode"}"#;
    for (path, text, covered) in [
        ("jws-rfc7515/a.json", other, true),
        ("jws-negative/deep/a.json", other, true),
        ("third_party/rfc7520/jws/a.json", other, true),
        ("third_party/rfc7520/jwe/a.json", other, false),
        ("third_party/jws.json", other, false),
        ("b64url/a.json", other, false),
        ("binding-surface/a.json", verify, true),
        ("keys/a.json", other, true),
        ("keys-extra/a.json", other, false),
        ("elsewhere/a.json", import, true),
    ] {
        assert_eq!(
            needs_binding_readiness(Path::new(path), text),
            covered,
            "{path}"
        );
    }
}

/// A temporary directory, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        let path =
            std::env::temp_dir().join(format!("polyjose-conformance-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        TempDir(path)
    }

    fn write(&self, relative: &str, contents: &str) {
        let path = self.0.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The directory walk finds nested files, ignores non-JSON files, and
/// collects every failure before reporting instead of stopping at the first.
#[test]
fn run_dir_collects_every_failure() {
    let dir = TempDir::new("collect");
    let ok = vector(
        "b64url.encode",
        r#"{"bytes_hex":"66"}"#,
        r#"{"ok":true,"b64u":"Zg"}"#,
    );
    dir.write("a/ok.json", &ok);
    dir.write("third_party/deep/ok.json", &ok);
    dir.write("third_party/LICENSE", "not a vector");
    dir.write(
        "a/unknown-op.json",
        &vector("jws.frobnicate", "{}", r#"{"ok":true}"#),
    );
    dir.write("b/invalid.json", &ok.replace(r#""66""#, r#""6""#));
    dir.write(
        "b/failing.json",
        &ok.replace(r#""b64u":"Zg""#, r#""b64u":"Zh""#),
    );
    let report = run_dir(&dir.0);
    assert_eq!(report.files, 5, "{report:?}");
    assert_eq!(report.failures.len(), 3, "{report:?}");
    for file in ["unknown-op.json", "invalid.json", "failing.json"] {
        assert!(
            report
                .failures
                .iter()
                .any(|f| f.contains(file) && f.contains(SOURCE)),
            "{file} not reported with its source: {report:?}"
        );
    }
}

/// An empty or missing directory fails, so a broken path cannot pass
/// vacuously.
#[test]
fn run_dir_fails_when_there_is_nothing_to_run() {
    let empty = TempDir::new("empty");
    empty.write("README.md", "no vectors here");
    let report = run_dir(&empty.0);
    assert_eq!(report.files, 0);
    assert!(
        report
            .failures
            .iter()
            .any(|f| f.contains("no vector files")),
        "{report:?}"
    );

    let missing = empty.0.join("does-not-exist");
    let report = run_dir(&missing);
    assert!(!report.failures.is_empty(), "{report:?}");
}
