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
//! - an empty or missing vectors directory fails the run.
//!
//! The schema is enforced by a strict hand-written check (no JSON Schema
//! crate, ADR 0016). `schema_and_runner_agree` parses `schema.json` and
//! fails if its operations, member names, member kinds, patterns or error
//! codes drift from the tables below. Vector files are parsed with
//! polyjose's own `json` module, and their inputs reach the library through
//! it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};

use polyjose::Error;
use polyjose::json::{self, Object, Value};
use polyjose::jwk::Jwk;
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

/// What a member's value must be. Each kind maps to one schema spelling
/// (see `schema_kind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
}

/// The input and success shape of an operation (schema `$defs`). Every
/// listed member is required and no other member is allowed.
#[derive(Debug)]
struct OpSpec {
    name: &'static str,
    input: &'static [(&'static str, Kind)],
    /// Members of a success expectation besides `"ok": true`.
    ok: &'static [(&'static str, Kind)],
    /// Whether `{"ok": false, "error": <code>}` is allowed.
    can_fail: bool,
}

/// The operations this runner implements.
const SPECS: &[OpSpec] = &[
    // RFC 7515 §2 base64url encoding (RFC 4648 §5, no padding).
    OpSpec {
        name: "b64url.encode",
        input: &[("bytes_hex", Kind::Hex)],
        ok: &[("b64u", Kind::Base64url)],
        can_fail: false,
    },
    // RFC 7515 §2 decoding; non-canonical input is rejected (RFC 4648 §3.5).
    OpSpec {
        name: "b64url.decode",
        input: &[("b64u", Kind::String)],
        ok: &[("bytes_hex", Kind::Hex)],
        can_fail: true,
    },
    // RFC 7638 §3 JWK Thumbprint and RFC 9278 §3 JWK Thumbprint URI.
    OpSpec {
        name: "jwk.thumbprint",
        input: &[("jwk", Kind::Object), ("hash", Kind::Enum(&["sha-256"]))],
        ok: &[
            ("thumbprint", Kind::Base64url),
            ("thumbprint_uri", Kind::String),
        ],
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
    s.len() % 2 == 0 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_base64url_alphabet(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
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
    let ok = match kind {
        Kind::Object => value.as_object().is_some(),
        Kind::String => value.as_str().is_some(),
        Kind::Hex => value.as_str().is_some_and(is_hex),
        Kind::Base64url => value.as_str().is_some_and(is_base64url_alphabet),
        Kind::Enum(values) => value.as_str().is_some_and(|s| values.contains(&s)),
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
        };
        Err(violation(pointer, format!("must be {wanted}")))
    }
}

fn check_members(
    object: &Object,
    members: &[(&str, Kind)],
    implicit: &[&str],
    pointer: &str,
) -> Result<(), String> {
    let names: Vec<&str> = implicit
        .iter()
        .copied()
        .chain(members.iter().map(|(n, _)| *n))
        .collect();
    exact_members(object, &names, pointer)?;
    for (name, kind) in members {
        let value = object.get(name).expect("checked by exact_members");
        check_kind(value, *kind, &format!("{pointer}/{name}"))?;
    }
    Ok(())
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
            check_members(input, spec.input, &[], "/input")?;
            if ok {
                check_members(expect, spec.ok, &["ok"], "/expect")?;
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
    match kind {
        Kind::Hex => parse(r##"{"$ref":"#/$defs/hex"}"##),
        Kind::Base64url => parse(r##"{"$ref":"#/$defs/base64url"}"##),
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

/// `$ref` target name of `{"$ref": "#/$defs/<name>"}`.
fn def_ref<'a>(value: &'a Value, used: &mut Vec<String>) -> &'a str {
    let target = value.get("$ref").and_then(Value::as_str).unwrap();
    let name = target.strip_prefix("#/$defs/").unwrap();
    used.push(name.to_owned());
    name
}

/// A `$defs` object definition: closed, every member required, and the
/// members (after `ok: {"const": true}` when `ok` is set) match `members`.
fn check_def(defs: &Value, name: &str, ok: bool, members: &[(&str, Kind)]) {
    let def = at(defs, &[name]);
    let mut expected_names: Vec<&str> = members.iter().map(|(n, _)| *n).collect();
    if ok {
        expected_names.insert(0, "ok");
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
    assert_eq!(strings(at(def, &["required"])), expected_names, "{name}");
    assert_eq!(
        member_names(at(def, &["properties"])),
        expected_names,
        "{name}"
    );
    for (member, kind) in members {
        let property = at(def, &["properties", member]);
        assert_eq!(annotated(property), schema_kind(*kind), "{name}/{member}");
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
    assert_eq!(at(&schema, &["type"]).as_str(), Some("object"));
    assert_eq!(
        at(&schema, &["additionalProperties"]).as_bool(),
        Some(false)
    );
    assert_eq!(strings(at(&schema, &["required"])), TOP_LEVEL);
    assert_eq!(member_names(at(&schema, &["properties"])), TOP_LEVEL);
    for name in ["source", "description"] {
        let property = at(&schema, &["properties", name]);
        assert_eq!(def_ref(property, &mut used), "text");
    }
    assert_eq!(
        *at(defs, &["text"]),
        parse(&format!(
            r#"{{"type":"string","minLength":1,"pattern":{}}}"#,
            Value::from(TEXT_PATTERN).to_json()
        ))
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

    assert_eq!(at(defs, &["hex", "pattern"]).as_str(), Some(HEX_PATTERN));
    assert_eq!(annotated(at(defs, &["hex"])).as_object().unwrap().len(), 2);
    assert_eq!(
        at(defs, &["base64url", "pattern"]).as_str(),
        Some(BASE64URL_PATTERN)
    );
    assert_eq!(
        annotated(at(defs, &["base64url"]))
            .as_object()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(strings(at(defs, &["error_code", "enum"])), Error::CODES);
    assert_eq!(
        annotated(at(defs, &["failure"])),
        parse(
            r##"{"type":"object","required":["ok","error"],"additionalProperties":false,
                "properties":{"ok":{"const":false},"error":{"$ref":"#/$defs/error_code"}}}"##
        )
    );
    used.extend(["hex", "base64url", "error_code"].map(str::to_owned));

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
        check_def(defs, input, false, spec.input);
        let expect = at(then, &["properties", "expect"]);
        let ok = if spec.can_fail {
            let one_of = at(expect, &["oneOf"]).as_array().unwrap();
            assert_eq!(member_names(expect), ["oneOf"], "{}", spec.name);
            assert_eq!(one_of.len(), 2, "{}", spec.name);
            assert_eq!(def_ref(&one_of[1], &mut used), "failure", "{}", spec.name);
            def_ref(&one_of[0], &mut used)
        } else {
            assert_eq!(member_names(expect), ["$ref"], "{}", spec.name);
            def_ref(expect, &mut used)
        };
        check_def(defs, ok, true, spec.ok);
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
    ];
    for json in cases {
        assert!(
            check_vector("ok.json", json.as_bytes()).is_ok(),
            "{:?}",
            check_vector("ok.json", json.as_bytes())
        );
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
    for op in [
        "jws.sign",
        "jws.verify",
        "jwe.encrypt",
        "jwe.decrypt",
        "jwt.validate",
    ] {
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
