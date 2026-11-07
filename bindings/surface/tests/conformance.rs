//! The `rust-surface` conformance runner (ADR 0034 §2, §4; ADR 0008 layer 4).
//!
//! It runs every `*.json` file under `conformance/vectors/` through the **`polyjose-surface` API
//! only** (ADR 0030), following the "Binding runners" mapping of `conformance/README.md` call by
//! call, and writes `target/conformance/rust-surface.json`. `scripts/conformance-parity.sh` then
//! compares that file with the `rust-core` reference run (`crates/polyjose/tests/conformance.rs`),
//! so a surface mapping bug shows up before any host toolchain is involved (ADR 0034 §4).
//!
//! The rules are those of every binding runner (conformance/README.md "Rules for every runner"):
//!
//! - every vector file is checked against `conformance/schema.json` itself, with a small checker
//!   of exactly the JSON Schema 2020-12 keywords the schema uses (any other keyword, or a pattern
//!   it doesn't know, fails the run), plus the cross-member rules the schema can't state;
//! - a vector is skipped only when its `features` lists one this build lacks (ADR 0034 §3), or
//!   its `features_absent` one this build has (ADR 0056); the surface never offers the
//!   deterministic test RNG (ADR 0005), so `fixed-rng` is never enabled, and `deflate` is enabled
//!   exactly when the core under it has it (probed through the surface);
//! - an unknown or unmapped operation, a broken vector, a panic, and any failure of a runner
//!   check (a round trip, a shape) is a `fail`, never an outcome;
//! - a `SurfaceError` is the library's outcome and is compared by its code (ADR 0030 §5);
//! - JSON-valued arguments go to the surface as JSON text, re-serialized in file order by the
//!   harness's own JSON (`polyjose::json`, the only `polyjose::` item used here), so `claims`
//!   keep their member order (ADR 0027 §1; README implementer note 4);
//! - the clock is the vector's `now`, always (ADR 0028 §4); the runner never reads a clock.
//!
//! Only the binding configuration (default features) writes `rust-surface.json`: a build in which
//! the core has `deflate` (`cargo test --workspace --all-features`) still runs and checks every
//! vector, but writes no results file, because it is not what the bindings ship (ADR 0034 §3) and
//! its skip set differs from the reference's.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};

// The harness's JSON parser and writer (README "Binding runners": "the harness's JSON parsing").
use polyjose::json::{self, Number, Object, Value};
use polyjose_surface::records::{
    JweDecryptOptions, JweEncryptOptions, JweRecipient, JwsSignOptions, JwsSigner,
    JwsVerifyOptions, JwtSignOptions, JwtVerified, JwtVerifyOptions,
};
use polyjose_surface::{SecretString, SurfaceError, jwe, jwk, jws, jwt, keys, util};

/// This runner's name (ADR 0034 §2; `conformance/schema/results.schema.json`).
const RUNNER: &str = "rust-surface";

/// The vector-file name of `polyjose/deflate` (conformance/README.md "Features").
const DEFLATE: &str = "deflate";

/// The `jwk.thumbprint` hash names of the schema, mapped to the surface's (ADR 0030 §4).
const HASHES: &[(&str, &str)] = &[("sha-256", "SHA-256")];

// ---------------------------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------------------------

fn conformance_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance")
}

/// `target/conformance/` at the repository root, whatever `CARGO_TARGET_DIR` says (README
/// "Runner names and results files").
fn results_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/conformance")
}

/// Parses a vector file or the schema with a 4 MiB input limit (README "Rules for every
/// runner": a vector of a JWS just over the library's 1 MiB default is itself over 1 MiB).
fn parse_file(bytes: &[u8]) -> Result<Value, String> {
    let mut limits = json::Limits::DEFAULT;
    limits.max_input_len = 4 * 1024 * 1024;
    json::parse_with_limits(bytes, &limits).map_err(|e| e.to_string())
}

fn schema() -> Value {
    let path = conformance_dir().join("schema.json");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    parse_file(&bytes).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

// ---------------------------------------------------------------------------------------------
// The schema checker: the JSON Schema 2020-12 keywords schema.json uses, and no others
// ---------------------------------------------------------------------------------------------

const ANNOTATIONS: &[&str] = &["$schema", "title", "description"];
const KEYWORDS: &[&str] = &[
    "$ref",
    "$defs",
    "type",
    "enum",
    "const",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "minItems",
    "maxItems",
    "uniqueItems",
    "minimum",
    "maximum",
    "minLength",
    "pattern",
    "allOf",
    "oneOf",
    "if",
    "then",
    "else",
];

/// Whether `s` matches `pattern`, for the three patterns `schema.json` uses (the
/// `$defs/text`, `$defs/hex` and `$defs/base64url` patterns). Any other pattern is an error, so
/// a schema change can't be ignored by this checker.
fn pattern_matches(pattern: &str, s: &str) -> Result<bool, String> {
    match pattern {
        // At least one non-whitespace character.
        "\\S" => Ok(s.chars().any(|c| !c.is_whitespace())),
        // Lowercase hex, two digits per octet.
        "^([0-9a-f]{2})*$" => {
            Ok(s.len().is_multiple_of(2)
                && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
        }
        // The RFC 4648 §5 alphabet, no padding.
        "^[A-Za-z0-9_-]*$" => Ok(s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')),
        other => Err(format!("schema: unsupported pattern {other:?}")),
    }
}

fn has_type(value: &Value, name: &str) -> Result<bool, String> {
    Ok(match name {
        "object" => value.as_object().is_some(),
        "array" => value.as_array().is_some(),
        "string" => value.as_str().is_some(),
        "boolean" => value.as_bool().is_some(),
        "null" => value.is_null(),
        "number" => value.as_number().is_some(),
        // An exact integer within ±(2^53 − 1), decided from the text (polyjose::json::Number).
        "integer" => value.as_i64().is_some(),
        other => return Err(format!("schema: unknown type {other:?}")),
    })
}

fn number(schema: &Object, keyword: &str) -> Option<f64> {
    schema.get(keyword).and_then(Value::as_f64)
}

/// The first violation of `schema` by `value`, as `<JSON pointer>: <problem>`; `Ok(())` when it
/// is valid. A construct the checker does not implement is a violation too.
fn check(root: &Value, schema: &Value, value: &Value, ptr: &str) -> Result<(), String> {
    let at = if ptr.is_empty() { "(root)" } else { ptr };
    let s = match schema {
        Value::Bool(true) => return Ok(()),
        Value::Bool(false) => return Err(format!("{at}: not allowed")),
        Value::Object(s) => s,
        _ => return Err(format!("schema: not a schema at {at}")),
    };
    for (keyword, _) in s {
        if !KEYWORDS.contains(&keyword) && !ANNOTATIONS.contains(&keyword) {
            return Err(format!("schema: unsupported keyword {keyword}"));
        }
    }
    if let Some(reference) = s.get("$ref") {
        let target = reference
            .as_str()
            .and_then(|r| r.strip_prefix("#/$defs/"))
            .and_then(|name| root.get("$defs").and_then(|defs| defs.get(name)))
            .ok_or_else(|| format!("schema: unresolvable $ref {}", reference.to_json()))?;
        check(root, target, value, ptr)?;
    }
    if let Some(types) = s.get("type") {
        let names: Vec<&str> = match types {
            Value::Array(items) => items.iter().filter_map(Value::as_str).collect(),
            other => other.as_str().into_iter().collect(),
        };
        let mut matched = false;
        for name in &names {
            matched |= has_type(value, name)?;
        }
        if !matched {
            return Err(format!("{at}: must be of type {}", names.join(" or ")));
        }
    }
    if let Some(options) = s.get("enum") {
        let options = options
            .as_array()
            .ok_or("schema: enum is not an array".to_owned())?;
        if !options.contains(value) {
            return Err(format!(
                "{at}: must be one of {}",
                Value::from(options.to_vec()).to_json()
            ));
        }
    }
    if let Some(constant) = s.get("const")
        && constant != value
    {
        return Err(format!("{at}: must be {}", constant.to_json()));
    }
    if let Some(object) = value.as_object() {
        let empty = Object::new();
        let properties = s
            .get("properties")
            .and_then(Value::as_object)
            .unwrap_or(&empty);
        if let Some(required) = s.get("required").and_then(Value::as_array) {
            for name in required.iter().filter_map(Value::as_str) {
                if !object.contains(name) {
                    return Err(format!("{ptr}/{name}: required member is missing"));
                }
            }
        }
        for (name, sub) in properties {
            if let Some(member) = object.get(name) {
                check(root, sub, member, &format!("{ptr}/{name}"))?;
            }
        }
        if let Some(additional) = s.get("additionalProperties") {
            for (name, member) in object {
                if properties.contains(name) {
                    continue;
                }
                if matches!(additional, Value::Bool(false)) {
                    return Err(format!(
                        "{ptr}/{name}: unknown member (additionalProperties is false)"
                    ));
                }
                check(root, additional, member, &format!("{ptr}/{name}"))?;
            }
        }
    }
    if let Some(items) = value.as_array() {
        let len = items.len() as f64;
        if number(s, "minItems").is_some_and(|min| len < min) {
            return Err(format!("{at}: too few items"));
        }
        if number(s, "maxItems").is_some_and(|max| len > max) {
            return Err(format!("{at}: too many items"));
        }
        if s.get("uniqueItems").and_then(Value::as_bool) == Some(true) {
            for (i, item) in items.iter().enumerate() {
                if items[..i].contains(item) {
                    return Err(format!("{at}: item {i} repeats an earlier one"));
                }
            }
        }
        if let Some(item_schema) = s.get("items") {
            for (i, item) in items.iter().enumerate() {
                check(root, item_schema, item, &format!("{ptr}/{i}"))?;
            }
        }
    }
    if let Some(n) = value.as_f64() {
        if number(s, "minimum").is_some_and(|min| n < min) {
            return Err(format!("{at}: below the minimum"));
        }
        if number(s, "maximum").is_some_and(|max| n > max) {
            return Err(format!("{at}: above the maximum"));
        }
    }
    if let Some(text) = value.as_str() {
        // JSON Schema counts characters as code points.
        if number(s, "minLength").is_some_and(|min| (text.chars().count() as f64) < min) {
            return Err(format!("{at}: too short"));
        }
        if let Some(pattern) = s.get("pattern").and_then(Value::as_str)
            && !pattern_matches(pattern, text)?
        {
            return Err(format!("{at}: must match {pattern}"));
        }
    }
    if let Some(all) = s.get("allOf").and_then(Value::as_array) {
        for sub in all {
            check(root, sub, value, ptr)?;
        }
    }
    if let Some(one) = s.get("oneOf").and_then(Value::as_array) {
        let results: Vec<Result<(), String>> =
            one.iter().map(|sub| check(root, sub, value, ptr)).collect();
        if let Some(Err(e)) = results
            .iter()
            .find(|r| matches!(r, Err(e) if e.starts_with("schema:")))
        {
            return Err(e.clone());
        }
        match results.iter().filter(|r| r.is_ok()).count() {
            1 => {}
            0 => {
                let problems: Vec<&str> = results
                    .iter()
                    .filter_map(|r| r.as_ref().err())
                    .map(String::as_str)
                    .collect();
                return Err(format!(
                    "{at}: matches none of oneOf ({})",
                    problems.join("; ")
                ));
            }
            _ => return Err(format!("{at}: matches more than one of oneOf")),
        }
    }
    if let Some(condition) = s.get("if") {
        let branch = match check(root, condition, value, ptr) {
            Ok(()) => s.get("then"),
            Err(e) if e.starts_with("schema:") => return Err(e),
            Err(_) => s.get("else"),
        };
        if let Some(branch) = branch {
            check(root, branch, value, ptr)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// One vector: validation, cross-member rules, skip, execution, comparison
// ---------------------------------------------------------------------------------------------

/// Why an operation stopped: the library's outcome, or a broken vector / failed runner check.
enum Stop {
    /// The surface refused: the vector's outcome is this code (ADR 0030 §5).
    Library(&'static str),
    /// The vector fails with this message, whatever it expects.
    Harness(String),
}

impl From<SurfaceError> for Stop {
    fn from(e: SurfaceError) -> Self {
        Stop::Library(e.code())
    }
}

type Step<T> = Result<T, Stop>;

fn harness<T>(message: impl Into<String>) -> Step<T> {
    Err(Stop::Harness(message.into()))
}

/// A surface call inside a runner check (a round trip, an import back, decoding an input): any
/// failure there fails the vector instead of being its outcome.
fn checked<T>(what: &str, result: Result<T, SurfaceError>) -> Step<T> {
    result.map_err(|e| Stop::Harness(format!("{what} ({})", e.code())))
}

/// The outcome of a vector that ran: success with its outputs, or the library's code.
type Outcome = Result<Object, &'static str>;

/// A vector's status for the results file (ADR 0034 §2).
enum Status {
    Pass,
    /// Skipped for these features, as the results-file `reason` lists them: the missing
    /// `features` in the vector's order (ADR 0034 §3), then each enabled `features_absent` one as
    /// `!<name>` in its order (ADR 0056 §2).
    Skipped(Vec<String>),
    Fail(String),
}

/// What the results file records of one vector besides its status.
#[derive(Default)]
struct Trace {
    source: Option<String>,
    op: Option<String>,
    /// Set once the operation's calls returned (README "The results file", `actual`).
    actual: Option<Result<(), &'static str>>,
}

fn is_text(s: &str) -> bool {
    s.chars().any(|c| !c.is_whitespace())
}

fn text_member(value: &Value, name: &str) -> Option<String> {
    value
        .get(name)
        .and_then(Value::as_str)
        .filter(|s| is_text(s))
        .map(str::to_owned)
}

/// Checks and runs one vector file, recording into `trace` as it goes.
fn run_vector(
    name: &str,
    bytes: &[u8],
    schema: &Value,
    enabled: &[&str],
    trace: &mut Trace,
) -> Status {
    let value = match parse_file(bytes) {
        Ok(value) => value,
        Err(e) => {
            return Status::Fail(format!(
                "{name}: not a valid JSON text ({e}); see conformance/schema.json"
            ));
        }
    };
    trace.source = text_member(&value, "source");
    trace.op = text_member(&value, "operation");
    let source = trace
        .source
        .clone()
        .unwrap_or_else(|| "<missing>".to_owned());
    let fail = |problem: String| Status::Fail(format!("{name} (source: {source}): {problem}"));
    if let Err(e) = check(schema, schema, &value, "") {
        return fail(format!("schema: {e}"));
    }
    if let Err(e) = cross_member_rules(&value) {
        return fail(e);
    }
    let names = |member: &str| -> Vec<String> {
        value
            .get(member)
            .and_then(Value::as_array)
            .unwrap_or_default()
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect()
    };
    let mut skip: Vec<String> = names("features")
        .into_iter()
        .filter(|f| !enabled.contains(&f.as_str()))
        .collect();
    skip.extend(
        names("features_absent")
            .into_iter()
            .filter(|f| enabled.contains(&f.as_str()))
            .map(|f| format!("!{f}")),
    );
    if !skip.is_empty() {
        return Status::Skipped(skip);
    }
    let outcome = match catch_unwind(AssertUnwindSafe(|| execute(&value))) {
        Err(_) => return fail("panicked while running".to_owned()),
        Ok(Err(message)) => return fail(message),
        Ok(Ok(outcome)) => outcome,
    };
    trace.actual = Some(outcome.as_ref().map(|_| ()).map_err(|code| *code));
    match compare(value.get("expect").expect("validated"), &outcome) {
        Ok(()) => Status::Pass,
        Err(message) => fail(message),
    }
}

/// The rules tying members together that the schema can't state, as the reference runner's
/// `check_jwe_encrypt_features` and `check_jwt_issue` check them (conformance/README.md).
fn cross_member_rules(vector: &Value) -> Result<(), String> {
    let operation = vector
        .get("operation")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let input = vector
        .get("input")
        .and_then(Value::as_object)
        .expect("validated");
    let expect = vector
        .get("expect")
        .and_then(Value::as_object)
        .expect("validated");
    let listed_in = |member: &str, feature: &str| {
        vector
            .get(member)
            .and_then(Value::as_array)
            .is_some_and(|items| items.iter().any(|f| f.as_str() == Some(feature)))
    };
    let listed = |feature: &str| listed_in("features", feature);
    // ADR 0056 §3: no name both needed and forbidden.
    let absent = vector
        .get("features_absent")
        .and_then(Value::as_array)
        .unwrap_or_default();
    if let Some(both) = absent.iter().filter_map(Value::as_str).find(|f| listed(f)) {
        return Err(format!(
            "schema: /features_absent: \"{both}\" is listed in `features` too"
        ));
    }
    if operation == "jwe.encrypt" {
        for (member, feature) in [("rng_b64u", "fixed-rng"), ("protected_b64u", "fixed-rng")] {
            if input.contains(member) && !listed(feature) {
                return Err(format!(
                    "schema: /features: `input/{member}` needs \"{feature}\" listed in `features`"
                ));
            }
        }
        // ADR 0056 §4: `deflate` in either list.
        if input.contains("compress") && !listed(DEFLATE) && !listed_in("features_absent", DEFLATE)
        {
            return Err(
                "schema: /features: `input/compress` needs \"deflate\" listed in `features` or \
                 `features_absent`"
                    .to_owned(),
            );
        }
    }
    if operation == "jwt.issue" {
        let ok = expect.get("ok").and_then(Value::as_bool) == Some(true);
        let encrypt = input.contains("encrypt");
        let validate = input.contains("validate");
        if ok && expect.contains("token") && encrypt {
            return Err(
                "schema: /expect/token: an encrypted token is randomized (RFC 7516 \
                        §5.1), so with `encrypt` expect {\"ok\": true} and give `validate`"
                    .to_owned(),
            );
        }
        if ok && !expect.contains("token") && !validate && !encrypt {
            return Err(
                "schema: /input/validate: required when the expectation has no `token`".to_owned(),
            );
        }
        if !ok && validate {
            return Err(
                "schema: /input/validate: used only when the issue succeeds, so a \
                        failure vector has none"
                    .to_owned(),
            );
        }
    }
    Ok(())
}

/// Compares the outcome with `expect`: on success exactly the expected outputs, each equal as a
/// JSON value (member order ignored, numbers as doubles; RFC 8259 §4, RFC 7493 §2.2).
fn compare(expect: &Value, outcome: &Outcome) -> Result<(), String> {
    let want_ok = expect.get("ok").and_then(Value::as_bool) == Some(true);
    match outcome {
        Ok(got) if want_ok => {
            for (name, want) in expect.as_object().expect("validated") {
                if name == "ok" {
                    continue;
                }
                if got.get(name) != Some(want) {
                    return Err(format!(
                        "`{name}`: expected {}, got {}",
                        want.to_json(),
                        got.get(name).map_or("nothing".to_owned(), Value::to_json)
                    ));
                }
            }
            for (name, value) in got {
                if !expect.as_object().expect("validated").contains(name) {
                    return Err(format!(
                        "`{name}`: expected nothing, got {}",
                        value.to_json()
                    ));
                }
            }
            Ok(())
        }
        Err(code) if want_ok => Err(format!("expected success, got error {code}")),
        Ok(got) => Err(format!(
            "expected error {}, but the operation succeeded with {}",
            expect.get("error").map_or_else(String::new, Value::to_json),
            got.to_json()
        )),
        Err(code) => match expect.get("error").and_then(Value::as_str) {
            Some(want) if want == *code => Ok(()),
            want => Err(format!(
                "expected error {}, got error {code}",
                want.unwrap_or_default()
            )),
        },
    }
}

// ---------------------------------------------------------------------------------------------
// Input helpers
// ---------------------------------------------------------------------------------------------

fn str_of<'a>(object: &'a Object, name: &str) -> &'a str {
    object.get(name).and_then(Value::as_str).expect("validated")
}

/// A JSON-valued argument, as JSON text in file order (README "Operation mapping", Arguments).
fn json_text(object: &Object, name: &str) -> String {
    object.get(name).expect("validated").to_json()
}

fn secret_json(object: &Object, name: &str) -> SecretString {
    SecretString::from(json_text(object, name))
}

fn strings(object: &Object, name: &str) -> Vec<String> {
    object
        .get(name)
        .and_then(Value::as_array)
        .expect("validated")
        .iter()
        .map(|item| item.as_str().expect("validated").to_owned())
        .collect()
}

/// An optional `$defs/count` member as the surface's `u32` (ADR 0030: counts are `u32`).
fn count(object: &Object, name: &str) -> Option<u32> {
    object
        .get(name)
        .and_then(Value::as_u64)
        .map(|n| u32::try_from(n).expect("validated: at most u32::MAX"))
}

/// A `*_b64u` member's octets, decoded with the surface's codec. A value that doesn't decode is
/// a broken vector, never an outcome (README "How bytes are written").
fn bytes(object: &Object, name: &str) -> Step<Vec<u8>> {
    checked(
        &format!("`{name}` is not canonical base64url; the runner must decode it"),
        util::base64url_decode(str_of(object, name)),
    )
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

fn index(n: u32) -> Value {
    Value::from(Number::from_u64(u64::from(n)).expect("a u32 is a safe integer"))
}

/// Parses JSON text the surface returned. Text that doesn't parse fails the vector.
fn parse_output(text: &str, what: &str) -> Step<Value> {
    match json::parse(text.as_bytes()) {
        Ok(value) => Ok(value),
        Err(e) => harness(format!("{what} does not parse as JSON ({e})")),
    }
}

// ---------------------------------------------------------------------------------------------
// The operations (README "Operation mapping")
// ---------------------------------------------------------------------------------------------

/// Runs the vector's operation through the surface: its outputs, or the library's code; a
/// broken vector or a failed runner check is the `Err` message.
fn execute(vector: &Value) -> Result<Outcome, String> {
    let operation = vector
        .get("operation")
        .and_then(Value::as_str)
        .expect("validated");
    let input = vector
        .get("input")
        .and_then(Value::as_object)
        .expect("validated");
    let expect = vector
        .get("expect")
        .and_then(Value::as_object)
        .expect("validated");
    let mut out = Object::new();
    let step = match operation {
        "b64url.encode" => b64url_encode(input, &mut out),
        "b64url.decode" => b64url_decode(input, &mut out),
        "jwk.thumbprint" => jwk_thumbprint(input, &mut out),
        "jws.sign" => jws_sign(input, expect, &mut out),
        "jws.verify" => jws_verify(input, &mut out),
        "keys.import_pem" => keys_import_pem(input, &mut out),
        "keys.import_der" => keys_import_der(input, &mut out),
        "keys.export_pem" => keys_export_pem(input, &mut out),
        "keys.export_der" => keys_export_der(input, &mut out),
        "keys.generate_for" => keys_generate_for(input, &mut out),
        "jwe.encrypt" => jwe_encrypt(input, expect, &mut out),
        "jwe.decrypt" => jwe_decrypt(input, &mut out),
        "jwt.validate" => jwt_validate(input, &mut out),
        "jwt.issue" => jwt_issue(input, expect, &mut out),
        other => {
            return Err(format!(
                "operation `{other}` is not implemented by the rust-surface runner; a vector is \
                 never skipped"
            ));
        }
    };
    match step {
        Ok(()) => Ok(Ok(out)),
        Err(Stop::Library(code)) => Ok(Err(code)),
        Err(Stop::Harness(message)) => Err(message),
    }
}

/// `b64url.encode` → `base64url_encode(bytes)` (RFC 4648 §5).
fn b64url_encode(input: &Object, out: &mut Object) -> Step<()> {
    out.insert(
        "b64u",
        util::base64url_encode(&hex_decode(str_of(input, "bytes_hex"))),
    );
    Ok(())
}

/// `b64url.decode` → `base64url_decode(b64u)` (RFC 4648 §5, §3.5).
fn b64url_decode(input: &Object, out: &mut Object) -> Step<()> {
    out.insert(
        "bytes_hex",
        hex_encode(&util::base64url_decode(str_of(input, "b64u"))?),
    );
    Ok(())
}

/// `jwk.thumbprint` → `jwk_thumbprint`, then `jwk_thumbprint_uri` (RFC 7638 §3, RFC 9278 §3).
fn jwk_thumbprint(input: &Object, out: &mut Object) -> Step<()> {
    let name = str_of(input, "hash");
    let Some((_, hash)) = HASHES.iter().find(|(vector, _)| *vector == name) else {
        return harness(format!("hash `{name}` has no surface name"));
    };
    let key = json_text(input, "jwk");
    out.insert("thumbprint", jwk::jwk_thumbprint(&key, hash)?);
    out.insert("thumbprint_uri", jwk::jwk_thumbprint_uri(&key, hash)?);
    Ok(())
}

/// `jws.sign` → `jws_sign_compact` / `jws_sign_flattened` / `jws_sign_general` (RFC 7515 §5.1,
/// §7); the header always goes as `protected_b64u`, a signer may have only `header` (ADR 0045
/// §1, README implementer note 11).
fn jws_sign(input: &Object, expect: &Object, out: &mut Object) -> Step<()> {
    let serialization = str_of(input, "serialization");
    let payload = bytes(input, "payload_b64u")?;
    let detached = input.get("detached").and_then(Value::as_bool) == Some(true);
    let signers_in = input
        .get("signers")
        .and_then(Value::as_array)
        .expect("validated");
    let signers: Vec<JwsSigner> = signers_in
        .iter()
        .map(|s| {
            let s = s.as_object().expect("validated");
            let mut signer = JwsSigner::new(secret_json(s, "key"));
            signer.protected_b64u = s
                .get("protected_b64u")
                .and_then(Value::as_str)
                .map(str::to_owned);
            signer.unprotected_header = s.get("header").map(Value::to_json);
            signer
        })
        .collect();
    let signed = match serialization {
        "compact" => {
            let first = signers_in[0].as_object().expect("validated");
            let options = JwsSignOptions {
                protected_b64u: first
                    .get("protected_b64u")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                detached,
                ..JwsSignOptions::default()
            };
            jws::jws_sign_compact(&payload, &json_text(first, "key"), &options)?
        }
        "flattened" => jws::jws_sign_flattened(&payload, &signers[0], detached)?,
        _ => jws::jws_sign_general(&payload, &signers, detached)?,
    };
    let jws_out = if serialization == "compact" {
        Value::from(signed.as_str())
    } else {
        parse_output(&signed, "the signed JSON JWS")?
    };
    let Some(verify_with) = expect.get("verify_with").and_then(Value::as_object) else {
        out.insert("jws", jws_out);
        return Ok(());
    };
    // The round trip (README `jws.sign` round trip): shape, verify with `verify_with`, same
    // payload; a detached payload goes to verify as its decoded octets.
    let shape_ok = match serialization {
        "compact" => signed.split('.').count() == 3,
        "flattened" => jws_out.get("signature").is_some() && jws_out.get("signatures").is_none(),
        _ => jws_out
            .get("signatures")
            .and_then(Value::as_array)
            .is_some_and(|s| s.len() == signers.len()),
    };
    if !shape_ok {
        return harness(format!(
            "round trip: the output is not a {serialization} JWS with {} signature(s)",
            signers.len()
        ));
    }
    let mut options = JwsVerifyOptions::new(strings(verify_with, "allowed_algs"));
    if detached {
        options.detached_payload = Some(payload.clone().into());
    }
    let key = json_text(verify_with, "key");
    let verified = checked(
        "round trip: the signed JWS does not verify with verify_with",
        if serialization == "compact" {
            jws::jws_verify_compact(&signed, &key, &options)
        } else {
            jws::jws_verify_json(&signed, &key, &options)
        },
    )?;
    if verified.payload.as_bytes() != payload.as_slice() {
        return harness("round trip: the verified payload is not the signed one");
    }
    out.insert("verify_with", Value::from(verify_with.clone()));
    Ok(())
}

/// `jws.verify` → `jws_verify_compact` (a string) / `jws_verify_json` (an object, as its JSON
/// text) (RFC 7515 §5.2; ADR 0026).
fn jws_verify(input: &Object, out: &mut Object) -> Step<()> {
    let key = json_text(input, "key");
    let mut options = JwsVerifyOptions::new(strings(input, "allowed_algs"));
    if input.contains("detached_payload_b64u") {
        options.detached_payload = Some(bytes(input, "detached_payload_b64u")?.into());
    }
    options.max_input_len = count(input, "max_input_len");
    options.max_signatures = count(input, "max_signatures");
    let jws_in = input.get("jws").expect("validated");
    let verified = match jws_in.as_str() {
        Some(compact) => jws::jws_verify_compact(compact, &key, &options)?,
        None => jws::jws_verify_json(&jws_in.to_json(), &key, &options)?,
    };
    out.insert(
        "payload_b64u",
        util::base64url_encode(verified.payload.as_bytes()),
    );
    out.insert("alg", verified.alg.as_str());
    out.insert("signature_index", index(verified.signature_index));
    Ok(())
}

/// A PEM or DER import result as an object; an `oct` key fails the vector whatever it expects
/// (RFC 8725 §2.1, README `keys.import_pem`).
fn imported(jwk: &SecretString) -> Step<Value> {
    let value = parse_output(jwk.as_str(), "the imported JWK")?;
    if value.get("kty").and_then(Value::as_str) == Some("oct") {
        return harness("a PEM or DER import returned an oct key (RFC 8725 §2.1)");
    }
    Ok(value)
}

/// `keys.import_pem` → `jwk_from_pem(pem)` (ADR 0018 §3).
fn keys_import_pem(input: &Object, out: &mut Object) -> Step<()> {
    out.insert("jwk", imported(&keys::jwk_from_pem(str_of(input, "pem"))?)?);
    Ok(())
}

/// `keys.import_der` → `jwk_from_der(der, format)`, `der` being `der_b64u` decoded.
fn keys_import_der(input: &Object, out: &mut Object) -> Step<()> {
    let der = bytes(input, "der_b64u")?;
    out.insert(
        "jwk",
        imported(&keys::jwk_from_der(&der, str_of(input, "format"))?)?,
    );
    Ok(())
}

/// `keys.export_pem` → `jwk_to_pem(jwk, format)`.
fn keys_export_pem(input: &Object, out: &mut Object) -> Step<()> {
    let pem = keys::jwk_to_pem(&json_text(input, "jwk"), str_of(input, "format"))?;
    out.insert("pem", pem.as_str());
    Ok(())
}

/// `keys.export_der` → `jwk_to_der(jwk, format)`, as base64url.
fn keys_export_der(input: &Object, out: &mut Object) -> Step<()> {
    let der = keys::jwk_to_der(&json_text(input, "jwk"), str_of(input, "format"))?;
    out.insert("der_b64u", util::base64url_encode(der.as_bytes()));
    Ok(())
}

/// The members a generated private key has (RFC 7518 §6.2.1–§6.2.2, RFC 8037 §2, RFC 7518
/// §6.4.1), plus `alg` (RFC 7517 §4.4). Sorted.
fn generated_members(kty: &str) -> Option<&'static [&'static str]> {
    match kty {
        "EC" => Some(&["alg", "crv", "d", "kty", "x", "y"]),
        "OKP" => Some(&["alg", "crv", "d", "kty", "x"]),
        "oct" => Some(&["alg", "k", "kty"]),
        _ => None,
    }
}

/// The shape of a generated key, after the checks a shape can't say (README
/// `keys.generate_for`): private, exactly the RFC members, and `jwk_parse` gives it back.
fn generated_shape(generated: &SecretString) -> Step<Object> {
    let jwk = parse_output(generated.as_str(), "the generated JWK")?;
    let object = jwk.as_object().ok_or(Stop::Harness(
        "the generated JWK is not an object".to_owned(),
    ))?;
    let kty = object
        .get("kty")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if kty != "oct" && !object.contains("d") {
        return harness("generate_for returned a public key");
    }
    let mut names: Vec<&str> = object.iter().map(|(name, _)| name).collect();
    names.sort_unstable();
    if generated_members(kty) != Some(names.as_slice()) {
        return harness(format!(
            "generate_for returned a JWK with members {names:?}"
        ));
    }
    let again = checked(
        "the generated JWK does not import",
        jwk::jwk_parse(generated.as_str()),
    )?;
    if parse_output(again.as_str(), "the re-imported JWK")? != jwk {
        return harness("the generated JWK imports as a different key");
    }
    let mut shape = Object::new();
    for name in ["kty", "crv", "alg"] {
        if let Some(value) = object.get(name) {
            shape.insert(name, value.clone());
        }
    }
    if let Some(k) = object.get("k").and_then(Value::as_str) {
        let octets = checked(
            "the generated k is not canonical base64url",
            util::base64url_decode(k),
        )?;
        let len = u64::try_from(octets.len()).expect("a length fits u64");
        shape.insert(
            "k_octets",
            Number::from_u64(len).expect("a key length is a safe integer"),
        );
    }
    Ok(shape)
}

/// `keys.generate_for` → `jwk_generate_for_alg(alg)` (ADR 0018 §5), `alg` passed as given.
fn keys_generate_for(input: &Object, out: &mut Object) -> Step<()> {
    let generated = keys::jwk_generate_for_alg(str_of(input, "alg"))?;
    out.insert("shape", generated_shape(&generated)?);
    Ok(())
}

/// `jwe.encrypt` → `jwe_encrypt_compact` / `jwe_encrypt_json(serialization)` (RFC 7516 §5.1,
/// §7), with the `JweEncryptOptions` mapping of the README.
fn jwe_encrypt(input: &Object, expect: &Object, out: &mut Object) -> Step<()> {
    if input.contains("rng_b64u") || input.contains("protected_b64u") {
        // Only in `fixed-rng` vectors, which this runner always skips (ADR 0005).
        return harness(
            "a reproducible encryption (rng_b64u, protected_b64u) is not in the binding API",
        );
    }
    let serialization = str_of(input, "serialization");
    let plaintext = bytes(input, "plaintext_b64u")?;
    let recipients_in = input
        .get("recipients")
        .and_then(Value::as_array)
        .expect("validated");
    let mut recipients = Vec::with_capacity(recipients_in.len());
    for r in recipients_in {
        let r = r.as_object().expect("validated");
        let mut recipient = JweRecipient::new(str_of(r, "alg").to_owned(), secret_json(r, "key"));
        recipient.header = r.get("header").map(Value::to_json);
        if r.contains("apu_b64u") {
            recipient.apu = Some(bytes(r, "apu_b64u")?);
        }
        if r.contains("apv_b64u") {
            recipient.apv = Some(bytes(r, "apv_b64u")?);
        }
        recipient.p2c = count(r, "p2c");
        recipient.p2s_len = count(r, "p2s_len");
        recipients.push(recipient);
    }
    let recipient_count = recipients.len();
    let mut options = JweEncryptOptions::new(str_of(input, "enc").to_owned(), recipients);
    options.protected_header = input.get("protected").map(Value::to_json);
    options.shared_unprotected_header = input.get("unprotected").map(Value::to_json);
    if input.contains("aad_b64u") {
        options.aad = Some(bytes(input, "aad_b64u")?.into());
    }
    options.compress = input.get("compress").and_then(Value::as_bool) == Some(true);
    let encrypted = if serialization == "compact" {
        jwe::jwe_encrypt_compact(&plaintext, &options)?
    } else {
        jwe::jwe_encrypt_json(&plaintext, &options, serialization)?
    };
    let jwe_out = if serialization == "compact" {
        Value::from(encrypted.as_str())
    } else {
        parse_output(&encrypted, "the encrypted JSON JWE")?
    };
    let Some(decrypt_with) = expect.get("decrypt_with").and_then(Value::as_object) else {
        out.insert("jwe", jwe_out);
        return Ok(());
    };
    // The round trip (README `jwe.encrypt` round trip): shape, decrypt, same plaintext.
    let shape_ok = match serialization {
        "compact" => encrypted.split('.').count() == 5,
        "flattened" => jwe_out.get("ciphertext").is_some() && jwe_out.get("recipients").is_none(),
        _ => jwe_out
            .get("recipients")
            .and_then(Value::as_array)
            .is_some_and(|r| r.len() == recipient_count),
    };
    if !shape_ok {
        return harness(format!(
            "round trip: the output is not a {serialization} JWE with {recipient_count} recipient(s)"
        ));
    }
    let key = json_text(decrypt_with, "key");
    let policy = JweDecryptOptions::new(
        strings(decrypt_with, "allowed_algs"),
        strings(decrypt_with, "allowed_enc"),
    );
    let decrypted = checked(
        "round trip: the encrypted JWE does not decrypt with decrypt_with",
        if serialization == "compact" {
            jwe::jwe_decrypt_compact(&encrypted, &key, &policy)
        } else {
            jwe::jwe_decrypt_json(&encrypted, &key, &policy)
        },
    )?;
    if decrypted.plaintext.as_bytes() != plaintext.as_slice() {
        return harness("round trip: the decrypted plaintext is not the encrypted one");
    }
    out.insert("decrypt_with", Value::from(decrypt_with.clone()));
    Ok(())
}

/// The `JweDecryptOptions` of `jwe.decrypt` and of a nested JWT's `decrypt`, member by member;
/// an absent member keeps the core default (ADR 0030 §3).
fn jwe_decrypt_options(object: &Object) -> JweDecryptOptions {
    let mut options = JweDecryptOptions::new(
        strings(object, "allowed_algs"),
        strings(object, "allowed_enc"),
    );
    if object.contains("understood_crit") {
        options.understood_crit = Some(strings(object, "understood_crit"));
    }
    options.max_input_len = count(object, "max_input_len");
    options.max_recipients = count(object, "max_recipients");
    options.max_pbes2_count = count(object, "max_pbes2_count");
    options.max_decompressed_len = count(object, "max_decompressed_len");
    options
}

/// `jwe.decrypt` → `jwe_decrypt_compact` (a string) / `jwe_decrypt_json` (an object, as its
/// JSON text) (RFC 7516 §5.2).
fn jwe_decrypt(input: &Object, out: &mut Object) -> Step<()> {
    let key = json_text(input, "key");
    let options = jwe_decrypt_options(input);
    let jwe_in = input.get("jwe").expect("validated");
    let decrypted = match jwe_in.as_str() {
        Some(compact) => jwe::jwe_decrypt_compact(compact, &key, &options)?,
        None => jwe::jwe_decrypt_json(&jwe_in.to_json(), &key, &options)?,
    };
    out.insert(
        "plaintext_b64u",
        util::base64url_encode(decrypted.plaintext.as_bytes()),
    );
    out.insert("recipient", index(decrypted.recipient_index));
    Ok(())
}

/// `JwtVerifyOptions` from `now`, `allowed_algs` and `policy`, member by member (README "policy
/// → JwtVerifyOptions"). A boolean `false` or an absent member sets nothing (note 6); `profile`
/// with `typ` mode `default` is a broken vector.
fn jwt_verify_options(object: &Object) -> Step<JwtVerifyOptions> {
    let mut options = JwtVerifyOptions::new(strings(object, "allowed_algs"));
    options.now = Some(
        object
            .get("now")
            .and_then(Value::as_i64)
            .expect("validated"),
    );
    let empty = Object::new();
    let policy = object
        .get("policy")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let typ = policy.get("typ").and_then(Value::as_object);
    let mode = typ.map(|t| str_of(t, "mode"));
    if policy.contains("profile") && mode == Some("default") {
        return harness(
            "`policy/typ/mode` \"default\" contradicts `policy/profile` \"access_token\", which \
             requires typ at+jwt (RFC 9068 §4)",
        );
    }
    if let Some(issuer) = policy.get("issuer") {
        options.issuers = Some(match issuer.as_str() {
            Some(one) => vec![one.to_owned()],
            None => strings(policy, "issuer"),
        });
    }
    if policy.contains("audience") {
        options.audiences = Some(strings(policy, "audience"));
    }
    options.subject = policy
        .get("subject")
        .and_then(Value::as_str)
        .map(str::to_owned);
    options.leeway = count(policy, "leeway");
    options.max_age = count(policy, "max_age");
    if policy.contains("require") {
        options.required_claims = Some(strings(policy, "require"));
    }
    if policy.get("allow_missing_exp").and_then(Value::as_bool) == Some(true) {
        options.allow_missing_exp = true;
    }
    if policy.get("ignore_audience").and_then(Value::as_bool) == Some(true) {
        options.ignore_audience = true;
    }
    match mode {
        Some("exact") => options.typ = Some(str_of(typ.expect("present"), "value").to_owned()),
        Some("any") => options.any_typ = true,
        _ => {}
    }
    options.profile = policy
        .get("profile")
        .and_then(Value::as_str)
        .map(str::to_owned);
    options.max_key_candidates = count(policy, "max_key_candidates");
    Ok(options)
}

/// Validates `token` with a `jwt.validate` input or a `jwt.issue` `validate` object: one of the
/// four surface forms, chosen by `decrypt` and by `key` or `jwks` (README "Operation mapping").
fn jwt_validated(object: &Object, token: &str) -> Step<JwtVerified> {
    let options = jwt_verify_options(object)?;
    let keys = object
        .get("jwks")
        .or_else(|| object.get("key"))
        .expect("validated")
        .to_json();
    let with_jwks = object.contains("jwks");
    Ok(match object.get("decrypt").and_then(Value::as_object) {
        Some(decrypt) => {
            let decrypt_key = json_text(decrypt, "key");
            let decrypt_options = jwe_decrypt_options(decrypt);
            let nested = if with_jwks {
                jwt::jwt_decrypt_nested_with_jwks(
                    token,
                    &decrypt_key,
                    &decrypt_options,
                    &keys,
                    &options,
                )?
            } else {
                jwt::jwt_decrypt_nested(token, &decrypt_key, &decrypt_options, &keys, &options)?
            };
            nested.inner
        }
        None if with_jwks => jwt::jwt_verify_with_jwks(token, &keys, &options)?,
        None => jwt::jwt_verify(token, &keys, &options)?,
    })
}

/// `jwt.validate` (RFC 7519 §7.2): `claims` as a JSON value, `alg`, and `key_index` exactly
/// when the surface reports one (ADR 0029 §4; README implementer note 2).
fn jwt_validate(input: &Object, out: &mut Object) -> Step<()> {
    let verified = jwt_validated(input, str_of(input, "token"))?;
    out.insert(
        "claims",
        parse_output(&verified.claims, "the validated claims")?,
    );
    out.insert("alg", verified.alg.as_str());
    if let Some(key_index) = verified.key_index {
        out.insert("key_index", index(key_index));
    }
    Ok(())
}

/// `jwt.issue` → `jwt_sign`, then `jwt_encrypt_nested` with `encrypt` (RFC 7519 §7.1, §11.2;
/// ADR 0027 §7–§8). `typ`: absent sets nothing, a string sets it, `null` sets `omit_typ`
/// (README implementer note 3).
fn jwt_issue(input: &Object, expect: &Object, out: &mut Object) -> Step<()> {
    let alg = str_of(input, "alg");
    let mut options = JwtSignOptions::new(alg.to_owned());
    match input.get("typ") {
        Some(Value::Null) => options.omit_typ = true,
        Some(typ) => options.typ = Some(typ.as_str().expect("validated").to_owned()),
        None => {}
    }
    let claims = input.get("claims").expect("validated");
    let mut token = jwt::jwt_sign(&claims.to_json(), &json_text(input, "key"), &options)?;
    let mut parts = 3;
    if let Some(encrypt) = input.get("encrypt").and_then(Value::as_object) {
        let recipient = JweRecipient::new(
            str_of(encrypt, "alg").to_owned(),
            secret_json(encrypt, "key"),
        );
        let encrypt_options =
            JweEncryptOptions::new(str_of(encrypt, "enc").to_owned(), vec![recipient]);
        token = jwt::jwt_encrypt_nested(&token, &encrypt_options)?;
        parts = 5;
    }
    if token.split('.').count() != parts {
        return harness(format!("the issued token is not {parts} compact parts"));
    }
    if let Some(validate) = input.get("validate").and_then(Value::as_object) {
        // The round trip (README implementer note 10): validates, with the issued alg and claims.
        let verified = match jwt_validated(validate, &token) {
            Ok(verified) => verified,
            Err(Stop::Library(code)) => {
                return harness(format!(
                    "round trip: the issued token does not validate with `validate` ({code})"
                ));
            }
            Err(stop) => return Err(stop),
        };
        if verified.alg != alg {
            return harness(format!(
                "round trip: validated with alg {}, issued with {alg}",
                verified.alg
            ));
        }
        let validated = parse_output(&verified.claims, "the validated claims")?;
        if validated != *claims {
            return harness(format!(
                "round trip: validated claims {} are not the issued {}",
                validated.to_json(),
                claims.to_json()
            ));
        }
    }
    if expect.get("ok").and_then(Value::as_bool) == Some(true) && expect.contains("token") {
        out.insert("token", token);
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// The run: walk, results file
// ---------------------------------------------------------------------------------------------

/// Whether the core under the surface has `deflate`: `compress` succeeds with it and is
/// `UnsupportedAlgorithm` without it (ADR 0017 §5, ADR 0030 §4). Anything else fails the run.
fn deflate_enabled() -> bool {
    let key = SecretString::from(r#"{"kty":"oct","k":"AAECAwQFBgcICQoLDA0ODw"}"#.to_owned());
    let mut options = JweEncryptOptions::new(
        "A128GCM".to_owned(),
        vec![JweRecipient::new("dir".to_owned(), key)],
    );
    options.compress = true;
    match jwe::jwe_encrypt_compact(b"deflate probe", &options) {
        Ok(_) => true,
        Err(e) if e.code() == "UnsupportedAlgorithm" => false,
        Err(e) => panic!("the deflate probe failed with {}", e.code()),
    }
}

/// The vector feature names this build enables: never `fixed-rng` (the surface has no
/// reproducible encryption, ADR 0005), and `deflate` when the core has it.
fn enabled_features() -> Vec<&'static str> {
    if deflate_enabled() {
        vec![DEFLATE]
    } else {
        Vec::new()
    }
}

/// Every `*.json` file under `dir`, recursively. A symbolic link or an unreadable entry is a
/// failure (README "Rules for every runner").
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

/// A vector's id (ADR 0034 §1 as amended by ADR 0045 §4): its `/`-separated path under the
/// vectors directory, then `#0`.
fn vector_id(relative: &Path) -> String {
    let parts: Vec<String> = relative
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    format!("{}#0", parts.join("/"))
}

/// One results-file entry (`conformance/schema/results.schema.json`).
fn result_entry(id: String, trace: Trace, status: &Status) -> Object {
    let mut entry = Object::new();
    entry.insert("id", id);
    if let Some(source) = trace.source {
        entry.insert("source", source);
    }
    if let Some(op) = trace.op {
        entry.insert("op", op);
    }
    entry.insert(
        "status",
        match status {
            Status::Pass => "pass",
            Status::Skipped(_) => "skipped",
            Status::Fail(_) => "fail",
        },
    );
    if let Some(actual) = trace.actual {
        let mut outcome = Object::new();
        outcome.insert("ok", actual.is_ok());
        if let Err(code) = actual {
            outcome.insert("error", code);
        }
        entry.insert("actual", outcome);
    }
    match status {
        Status::Pass => {}
        Status::Skipped(features) => {
            entry.insert("reason", format!("feature:{}", features.join(",")));
        }
        Status::Fail(message) => {
            entry.insert("reason", message.as_str());
        }
    }
    entry
}

/// Every check over a vectors directory.
#[derive(Default)]
struct Report {
    files: usize,
    passed: usize,
    skipped: Vec<String>,
    failures: Vec<String>,
    results: Vec<Object>,
    /// Whether the walk saw every vector file (no unreadable directory, no symbolic link, not
    /// empty); only a complete run writes a results file.
    complete: bool,
}

fn run_dir(dir: &Path, schema: &Value, enabled: &[&str]) -> Report {
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
    report.complete = report.failures.is_empty();
    for path in files {
        let relative = path.strip_prefix(dir).unwrap_or(&path);
        let name = relative.display().to_string();
        let mut trace = Trace::default();
        let status = match std::fs::read(&path) {
            Ok(bytes) => run_vector(&name, &bytes, schema, enabled, &mut trace),
            Err(e) => Status::Fail(format!("{name}: cannot read: {e}")),
        };
        match &status {
            Status::Pass => report.passed += 1,
            Status::Skipped(features) => report.skipped.push(format!(
                "{name}: SKIPPED (needs feature {})",
                features.join(", ")
            )),
            Status::Fail(message) => report.failures.push(message.clone()),
        }
        report
            .results
            .push(result_entry(vector_id(relative), trace, &status));
    }
    report
}

/// The results file text: the runner, the surface's `version()`, the enabled features, its
/// `error_codes()` (ADR 0034 §8) and one result per line.
fn results_document(enabled: &[&str], results: &[Object]) -> String {
    let list =
        |items: &[&str]| Value::from(items.iter().map(|s| Value::from(*s)).collect::<Vec<_>>());
    let header: [(&str, Value); 4] = [
        ("runner", Value::from(RUNNER)),
        ("polyjose", Value::from(util::version())),
        ("features", list(enabled)),
        ("error_codes", list(util::error_codes())),
    ];
    let mut text = String::from("{\n");
    for (name, value) in &header {
        text.push_str(&format!(
            "  {}: {},\n",
            Value::from(*name).to_json(),
            value.to_json()
        ));
    }
    text.push_str("  \"results\": [");
    for (i, result) in results.iter().enumerate() {
        text.push_str(if i == 0 { "\n    " } else { ",\n    " });
        text.push_str(&result.to_json());
    }
    text.push_str(if results.is_empty() {
        "]\n}\n"
    } else {
        "\n  ]\n}\n"
    });
    text
}

/// Writes `rust-surface.json` atomically, or removes a stale one when the walk was incomplete.
fn write_results(enabled: &[&str], report: &Report) -> Option<PathBuf> {
    let dir = results_dir();
    let path = dir.join(format!("{RUNNER}.json"));
    if !report.complete {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => panic!("{}: cannot remove: {e}", path.display()),
        }
        return None;
    }
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
    let temporary = dir.join(format!(".{RUNNER}.json.{}.tmp", std::process::id()));
    std::fs::write(&temporary, results_document(enabled, &report.results))
        .unwrap_or_else(|e| panic!("{}: {e}", temporary.display()));
    std::fs::rename(&temporary, &path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    Some(path)
}

/// The shared vectors through the surface: every file schema-valid and passing, or skipped for
/// a named feature. The default-features build writes `rust-surface.json` before any assertion,
/// so a failing run is recorded too.
#[test]
fn conformance_vectors() {
    let schema = schema();
    let enabled = enabled_features();
    let report = run_dir(&conformance_dir().join("vectors"), &schema, &enabled);
    if enabled.is_empty() {
        if let Some(path) = write_results(&enabled, &report) {
            eprintln!("conformance (rust-surface): wrote {}", path.display());
        }
    } else {
        eprintln!(
            "conformance (rust-surface): the core has {enabled:?}, which the bindings don't ship \
             (ADR 0034 §3): no results file written"
        );
    }
    assert!(
        report.failures.is_empty(),
        "{} of {} conformance vector file(s) failed through the surface:\n  {}",
        report.failures.len(),
        report.files,
        report.failures.join("\n  ")
    );
    eprintln!(
        "conformance (rust-surface): {} of {} vectors passed; {} skipped",
        report.passed,
        report.files,
        report.skipped.len()
    );
    for line in &report.skipped {
        eprintln!("  {line}");
    }
    assert_eq!(report.passed + report.skipped.len(), report.files);
}

// ---------------------------------------------------------------------------------------------
// The runner's own checks
// ---------------------------------------------------------------------------------------------

/// Every keyword and pattern of `schema.json` is one the checker implements, so no rule of the
/// schema is silently ignored.
#[test]
fn the_schema_uses_only_what_the_checker_implements() {
    fn walk(value: &Value, ptr: &str) {
        if let Value::Object(s) = value {
            for (keyword, sub) in s {
                assert!(
                    KEYWORDS.contains(&keyword) || ANNOTATIONS.contains(&keyword),
                    "{ptr}: unsupported keyword {keyword}"
                );
                match keyword {
                    "properties" | "$defs" => {
                        for (name, member) in sub.as_object().expect("an object") {
                            walk(member, &format!("{ptr}/{keyword}/{name}"));
                        }
                    }
                    "allOf" | "oneOf" => {
                        for (i, branch) in sub.as_array().expect("an array").iter().enumerate() {
                            walk(branch, &format!("{ptr}/{keyword}/{i}"));
                        }
                    }
                    "items" | "if" | "then" | "else" | "additionalProperties" => {
                        walk(sub, &format!("{ptr}/{keyword}"));
                    }
                    "pattern" => {
                        pattern_matches(sub.as_str().expect("a string"), "")
                            .unwrap_or_else(|e| panic!("{ptr}: {e}"));
                    }
                    _ => {}
                }
            }
        }
    }
    walk(&schema(), "");
    assert!(pattern_matches("^[a-z]+$", "a").is_err());
}

const SOURCE: &str = "rust-surface self-test";

fn vector(operation: &str, input: &str, expect: &str, extra: &str) -> String {
    format!(
        r#"{{"source":"{SOURCE}","description":"self-test","operation":"{operation}","input":{input},"expect":{expect}{extra}}}"#
    )
}

fn status_of(json: &str, enabled: &[&str]) -> (Status, Trace) {
    let mut trace = Trace::default();
    let status = run_vector(
        "self-test.json",
        json.as_bytes(),
        &schema(),
        enabled,
        &mut trace,
    );
    (status, trace)
}

fn assert_fails(json: &str, needle: &str) {
    match status_of(json, &[]).0 {
        Status::Fail(message) => {
            assert!(message.contains(SOURCE), "{message}");
            assert!(message.contains(needle), "expected {needle:?} in {message}");
        }
        _ => panic!("expected a fail for {json}"),
    }
}

const A1_KEY: &str = r#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#;
const A1_JWS: &str = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

/// Valid vectors pass and record their outcome; a library error is an outcome compared by code.
#[test]
fn valid_vectors_pass_and_record_the_outcome() {
    let ok = vector(
        "b64url.decode",
        r#"{"b64u":"AQI"}"#,
        r#"{"ok":true,"bytes_hex":"0102"}"#,
        "",
    );
    let (status, trace) = status_of(&ok, &[]);
    assert!(matches!(status, Status::Pass));
    assert_eq!(trace.actual, Some(Ok(())));
    assert_eq!(trace.op.as_deref(), Some("b64url.decode"));
    let refused = vector(
        "jws.verify",
        &format!(r#"{{"jws":"{A1_JWS}","key":{A1_KEY},"allowed_algs":[]}}"#),
        r#"{"ok":false,"error":"AlgorithmNotAllowed"}"#,
        "",
    );
    let (status, trace) = status_of(&refused, &[]);
    assert!(matches!(status, Status::Pass));
    assert_eq!(trace.actual, Some(Err("AlgorithmNotAllowed")));
    // The wrong code is a fail, and still records what happened.
    let wrong = refused.replace("AlgorithmNotAllowed\"}", "InvalidKey\"}");
    let (status, trace) = status_of(&wrong, &[]);
    assert!(matches!(status, Status::Fail(m) if m.contains("got error AlgorithmNotAllowed")));
    assert_eq!(trace.actual, Some(Err("AlgorithmNotAllowed")));
}

/// Schema-invalid and broken vectors fail, never pass or skip (README "Rules for every runner").
#[test]
fn broken_vectors_fail() {
    let input = r#"{"b64u":"AQI"}"#;
    let ok = r#"{"ok":true,"bytes_hex":"0102"}"#;
    assert_fails(
        &vector("b64url.decode", input, ok, r#","extra":1"#),
        "unknown member",
    );
    assert_fails(
        &vector("b64url.decode", r#"{"b64u":"AQI","x":1}"#, ok, ""),
        "/input/x",
    );
    assert_fails(&vector("b64url.nope", input, ok, ""), "/operation");
    assert_fails(
        &vector("b64url.decode", input, r#"{"ok":true}"#, ""),
        "bytes_hex",
    );
    assert_fails(
        &vector("b64url.decode", input, r#"{"ok":false,"error":"Nope"}"#, ""),
        "error",
    );
    assert_fails(
        &vector("b64url.decode", input, ok, r#","features":["zip"]"#),
        "/features/0",
    );
    assert_fails(
        &vector(
            "b64url.decode",
            input,
            ok,
            r#","features":["deflate","deflate"]"#,
        ),
        "repeats",
    );
    // A schema-invalid vector fails even when it would be skipped.
    assert_fails(
        &vector(
            "b64url.decode",
            r#"{"b64u":1}"#,
            ok,
            r#","features":["fixed-rng"]"#,
        ),
        "/input/b64u",
    );
    // A non-canonical *_b64u input is a broken vector, not an outcome.
    let verify = vector(
        "jws.verify",
        &format!(
            r#"{{"jws":"{A1_JWS}","key":{A1_KEY},"allowed_algs":["HS256"],"detached_payload_b64u":"AR"}}"#
        ),
        r#"{"ok":false,"error":"InvalidFormat"}"#,
        "",
    );
    assert_fails(&verify, "not canonical base64url");
    assert!(status_of(&verify, &[]).1.actual.is_none());
    // `compress` needs `deflate` listed (the cross-member rules).
    let encrypt = vector(
        "jwe.encrypt",
        r#"{"serialization":"compact","enc":"A128GCM","plaintext_b64u":"AQI","compress":true,"recipients":[{"alg":"dir","key":{"kty":"oct","k":"AAECAwQFBgcICQoLDA0ODw"}}]}"#,
        r#"{"ok":false,"error":"UnsupportedAlgorithm"}"#,
        "",
    );
    assert_fails(&encrypt, "needs \"deflate\"");
    // `profile` with `typ` mode `default` is a broken vector.
    let validate = vector(
        "jwt.validate",
        &format!(
            r#"{{"token":"{A1_JWS}","now":1300819320,"allowed_algs":["HS256"],"key":{A1_KEY},"policy":{{"profile":"access_token","issuer":"joe","audience":["a"],"typ":{{"mode":"default"}}}}}}"#
        ),
        r#"{"ok":false,"error":"InvalidClaim"}"#,
        "",
    );
    assert_fails(&validate, "contradicts");
    assert!(
        matches!(status_of("{", &[]).0, Status::Fail(m) if m.contains("not a valid JSON text"))
    );
}

/// A vector needing a feature this build lacks is skipped with exactly those names, in the
/// vector's order; one whose features are all enabled runs (ADR 0034 §3).
#[test]
fn vectors_needing_a_disabled_feature_are_skipped_by_name() {
    let needs = vector(
        "b64url.decode",
        r#"{"b64u":"AQI"}"#,
        r#"{"ok":true,"bytes_hex":"0102"}"#,
        r#","features":["fixed-rng","deflate"]"#,
    );
    let (status, trace) = status_of(&needs, &[]);
    assert!(matches!(&status, Status::Skipped(f) if f == &["fixed-rng", "deflate"]));
    assert!(trace.actual.is_none());
    let entry = result_entry("a.json#0".to_owned(), trace, &status);
    assert_eq!(
        entry.get("reason").and_then(Value::as_str),
        Some("feature:fixed-rng,deflate")
    );
    let (status, _) = status_of(&needs, &["deflate"]);
    assert!(matches!(&status, Status::Skipped(f) if f == &["fixed-rng"]));
    let (status, _) = status_of(&needs, &["deflate", "fixed-rng"]);
    assert!(matches!(status, Status::Pass));
}

/// A vector that must run without a feature this build has is skipped with `!<name>`, after
/// the missing `features` names; with every forbidden feature off it runs (ADR 0056 §2).
#[test]
fn vectors_forbidding_an_enabled_feature_are_skipped_by_name() {
    let forbids = vector(
        "b64url.decode",
        r#"{"b64u":"AQI"}"#,
        r#"{"ok":true,"bytes_hex":"0102"}"#,
        r#","features_absent":["deflate","fixed-rng"]"#,
    );
    let (status, trace) = status_of(&forbids, &["deflate", "fixed-rng"]);
    assert!(matches!(&status, Status::Skipped(f) if f == &["!deflate", "!fixed-rng"]));
    assert!(trace.actual.is_none());
    let entry = result_entry("a.json#0".to_owned(), trace, &status);
    assert_eq!(
        entry.get("reason").and_then(Value::as_str),
        Some("feature:!deflate,!fixed-rng")
    );
    let (status, _) = status_of(&forbids, &["deflate"]);
    assert!(matches!(&status, Status::Skipped(f) if f == &["!deflate"]));
    let (status, _) = status_of(&forbids, &[]);
    assert!(matches!(status, Status::Pass));
    // Needed and forbidden at once: the missing names first.
    let mixed = vector(
        "b64url.decode",
        r#"{"b64u":"AQI"}"#,
        r#"{"ok":true,"bytes_hex":"0102"}"#,
        r#","features":["fixed-rng"],"features_absent":["deflate"]"#,
    );
    let (status, trace) = status_of(&mixed, &["deflate"]);
    let entry = result_entry("a.json#0".to_owned(), trace, &status);
    assert_eq!(
        entry.get("reason").and_then(Value::as_str),
        Some("feature:fixed-rng,!deflate")
    );
}

/// `features_absent` is strict (ADR 0056 §1, §3, §4): known names, each once, at least one,
/// none also in `features`; `compress` may list `deflate` in either list.
#[test]
fn features_absent_is_strict() {
    let input = r#"{"b64u":"AQI"}"#;
    let ok = r#"{"ok":true,"bytes_hex":"0102"}"#;
    for (extra, needle) in [
        (r#","features_absent":["zip"]"#, "/features_absent/0"),
        (r#","features_absent":["deflate","deflate"]"#, "repeats"),
        (r#","features_absent":[]"#, "/features_absent"),
        (r#","features_absent":"deflate""#, "/features_absent"),
        (
            r#","features":["deflate"],"features_absent":["deflate"]"#,
            "is listed in `features` too",
        ),
        (r#","feature_absent":["deflate"]"#, "unknown member"),
    ] {
        assert_fails(&vector("b64url.decode", input, ok, extra), needle);
    }
    let encrypt = |extra: &str| {
        vector(
            "jwe.encrypt",
            r#"{"serialization":"compact","enc":"A128GCM","plaintext_b64u":"AQI","compress":true,"recipients":[{"alg":"dir","key":{"kty":"oct","k":"AAECAwQFBgcICQoLDA0ODw"}}]}"#,
            r#"{"ok":false,"error":"UnsupportedAlgorithm"}"#,
            extra,
        )
    };
    assert_fails(
        &encrypt(r#","features_absent":["fixed-rng"]"#),
        "listed in `features` or `features_absent`",
    );
    // Without `deflate` in the core under the surface, `compress` is UnsupportedAlgorithm.
    let pin = encrypt(r#","features_absent":["deflate"]"#);
    let (status, trace) = status_of(&pin, &enabled_features());
    if deflate_enabled() {
        assert!(matches!(&status, Status::Skipped(f) if f == &["!deflate"]));
    } else {
        assert!(matches!(status, Status::Pass));
        assert_eq!(trace.actual, Some(Err("UnsupportedAlgorithm")));
    }
}

/// The runner calls the surface only: `polyjose::` appears only for the harness's JSON, and no
/// clock is ever read (ADR 0028 §4; README "Rules for jwt.* runners").
#[test]
fn the_runner_uses_only_the_surface_and_no_clock() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/conformance.rs");
    let source = std::fs::read_to_string(&path).unwrap();
    // Every `polyjose::` path is `polyjose::json`; a bare `polyjose::` followed by a backquote
    // or a quote is prose or this test's own needle.
    for (at, _) in source.match_indices("polyjose::") {
        let rest = &source[at + "polyjose::".len()..];
        assert!(
            rest.starts_with("json") || rest.starts_with('`') || rest.starts_with('"'),
            "a core path other than the harness JSON: {}",
            &source[at..(at + 40).min(source.len())]
        );
    }
    for clock in ["SystemTime", "Instant::now", "UNIX_EPOCH"] {
        assert_eq!(source.matches(clock).count(), 1, "{clock} is used");
    }
}

/// The surface's `error_codes()` are what the results file records (ADR 0034 §8), and the
/// results document has one entry per vector.
#[test]
fn results_document_lists_the_surface_codes() {
    let mut entry = Object::new();
    entry.insert("id", "a.json#0");
    let text = results_document(&[], &[entry]);
    let doc = json::parse(text.as_bytes()).unwrap();
    assert_eq!(doc.get("runner").and_then(Value::as_str), Some(RUNNER));
    assert_eq!(
        doc.get("polyjose").and_then(Value::as_str),
        Some(util::version())
    );
    let codes: Vec<&str> = doc
        .get("error_codes")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(codes, util::error_codes());
    assert_eq!(
        doc.get("results")
            .and_then(Value::as_array)
            .map(<[Value]>::len),
        Some(1)
    );
}
