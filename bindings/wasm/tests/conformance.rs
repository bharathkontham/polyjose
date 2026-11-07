//! The `wasm-node` and `wasm-chrome` conformance runners (ADR 0034 §2; ADR 0008 layer 4;
//! ADR 0031 §3): every `conformance/vectors/**/*.json` file through the WASM adapter's exports,
//! inside wasm-bindgen-test, under `wasm-pack test --node` and
//! `wasm-pack test --headless --chrome --features browser` (`bindings/wasm/test.sh`).
//!
//! The exports are called directly from Rust with the arguments the JS glue would hand them:
//! `Vec<u8>` and `String` data, and **plain JS objects** for every record, so the adapter's
//! `Reflect` readers (`src/read.rs`), its result objects (`src/write.rs`), its thrown
//! `PolyjoseError` objects (`src/error.rs`) and the `crypto.getRandomValues` backend run in each
//! engine. The JS glue and the shared facade are not on this path; 0006 T04's `wasm-pkg-*` runs
//! cover them.
//!
//! The mapping is conformance/README.md "Binding runners", call by call, and mirrors the JS
//! runner (`bindings/js/conformance/runner.ts`) and the `rust-surface` runner
//! (`bindings/surface/tests/conformance.rs`). The rules are those of every runner
//! (README "Rules for every runner"):
//!
//! - **Files.** Every vector file is embedded through the generated index `tests/vectors/mod.rs`,
//!   whose freshness `tests/vector_index.rs` checks against the directory (an engine has no file
//!   system to walk). Each is parsed with `JSON.parse` (`js_sys::JSON::parse`). `JSON.parse` keeps
//!   the last of duplicate members, but vector files must be I-JSON (RFC 7493 §2.3), so a file
//!   with more `:` member separators than parsed members fails.
//! - **Schema.** Every file is checked against `conformance/schema.json` by a checker of exactly
//!   the JSON Schema 2020-12 keywords the schema uses (any other keyword fails), plus the
//!   cross-member rules the schema can't state. JavaScript reads `1300819439.0` as an integer, so
//!   `"type": "integer"` can't tell the spellings apart here; the Rust runner's binding-readiness
//!   tests keep such spellings out of the vector files (README "Binding readiness").
//! - **Skips.** A vector is skipped only when its `features` lists one this build lacks
//!   (ADR 0034 §3): never `fixed-rng` (no binding has the test RNG, ADR 0005), and `deflate` only
//!   if the core under the adapter has it, found out through the adapter (a `compress`
//!   encryption).
//! - **Fails.** An unknown or unmapped operation, a broken vector, a failed runner check (a round
//!   trip, a shape) and any thrown value that is not a `PolyjoseError` (a `TypeError` from a
//!   reader included, README implementer note 8) fail the vector; they are never an outcome or a
//!   skip. A `PolyjoseError` is the library's outcome, compared by its own `code` property
//!   (ADR 0030 §5).
//! - **JSON arguments** (keys, JWK Sets, headers, claims, JSON JWS/JWE) go to the adapter as
//!   `JSON.stringify` of the parsed value: compact, members in file order. A JS object moves
//!   integer-like member names to the front, which would reorder `jwt.issue` claims (ADR 0027 §1),
//!   so a JSON argument with such a name fails the vector instead (README implementer note 4).
//! - **The clock** is the vector's `now`, always (ADR 0028 §4); this runner never reads one.
//! - **The corpus digest** (ADR 0060): the SHA-256 over the byte-sorted `<id>\t<sha256>` lines
//!   of the embedded bytes it parsed (`tests/digest/mod.rs`, with `sha2` as the oracle, never
//!   polyjose). An empty corpus fails before any results line. It goes into the results document
//!   once [`EMIT_VECTORS_DIGEST`] is on; until then it is printed in the summary line.
//!
//! The browser can't write files, so the ADR 0034 §2 results document is printed as one line
//! prefixed `POLYJOSE-CONFORMANCE-RESULTS ` (before any assertion, so a failing run is recorded),
//! and `bindings/wasm/test.sh` writes it to `target/conformance/wasm-node.json` or
//! `wasm-chrome.json`.
#![cfg(target_arch = "wasm32")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

mod common;
mod digest;
mod vectors;

use js_sys::{Array, JSON, JsString, Object, Reflect, RegExp, Uint8Array};
use polyjose_wasm::{jwe, jwk, jws, jwt, keys, util};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_test::{console_log, wasm_bindgen_test};

#[cfg(feature = "browser")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

/// `conformance/schema.json`, the vector format (README "Members").
const SCHEMA: &str = include_str!("../../../conformance/schema.json");

/// The prefix of the one results line that `bindings/wasm/test.sh` extracts.
const MARKER: &str = "POLYJOSE-CONFORMANCE-RESULTS ";

/// Whether the results document carries the ADR 0060 `vectors_digest` member.
///
/// ADR 0060 §1 makes it a required member of every results file. On this base
/// `conformance/schema/results.schema.json` does not define it yet and closes the top level
/// (`additionalProperties: false`), so `scripts/conformance-parity.sh`, which validates every
/// results file against that schema, would reject `wasm-node.json` and `wasm-chrome.json` with it.
/// The digest is still computed and checked on every run (`conformance_vectors`, and
/// `tests/vector_index.rs` against the ADR's shell reference); only writing it waits.
/// **Flip this to `true` when feature 0013 F08 makes `results.schema.json` require the member**
/// (0006 T06; decided with the 0006 lead, 2026-11-07).
const EMIT_VECTORS_DIGEST: bool = false;

/// The vector-file name of `polyjose/deflate` (README "Features").
const DEFLATE: &str = "deflate";

/// The `jwk.thumbprint` hash names of the schema, mapped to the adapter's (ADR 0030 §4).
const HASHES: &[(&str, &str)] = &[("sha-256", "SHA-256")];

/// The members a generated private key has (RFC 7518 §6.2.1–§6.2.2, RFC 8037 §2,
/// RFC 7518 §6.4.1), plus `alg` (RFC 7517 §4.4), sorted.
fn generated_members(kty: &str) -> Option<&'static [&'static str]> {
    match kty {
        "EC" => Some(&["alg", "crv", "d", "kty", "x", "y"]),
        "OKP" => Some(&["alg", "crv", "d", "kty", "x"]),
        "oct" => Some(&["alg", "k", "kty"]),
        _ => None,
    }
}

/// [`generated_members`] of a key bound to no algorithm (`jwkGenerateOct`, `jwkGenerateEc`,
/// `jwkGenerateOkp`, ADR 0030 §4): no `alg`.
fn unbound_members(kty: &str) -> Option<&'static [&'static str]> {
    match kty {
        "EC" => Some(&["crv", "d", "kty", "x", "y"]),
        "OKP" => Some(&["crv", "d", "kty", "x"]),
        "oct" => Some(&["k", "kty"]),
        _ => None,
    }
}

/// The payload or plaintext of every `use_with` round trip: `polyjose` (ADR 0034 §6).
const USE_WITH_PAYLOAD: &[u8] = b"polyjose";

// ---------------------------------------------------------------------------------------------
// JS values
// ---------------------------------------------------------------------------------------------

/// An object that is not an array (and not `null`, which `is_object` excludes).
fn is_plain_object(v: &JsValue) -> bool {
    v.is_object() && !Array::is_array(v)
}

/// The own member `name` of a plain object, `None` when `v` is not one or lacks it.
fn get(v: &JsValue, name: &str) -> Option<JsValue> {
    if !is_plain_object(v) {
        return None;
    }
    let key = JsValue::from_str(name);
    if !Object::has_own(v.unchecked_ref::<Object>(), &key) {
        return None;
    }
    Reflect::get(v, &key).ok()
}

fn has(v: &JsValue, name: &str) -> bool {
    get(v, name).is_some()
}

/// The own enumerable member names of a plain object, in JS order.
fn member_names(v: &JsValue) -> Vec<String> {
    if !is_plain_object(v) {
        return Vec::new();
    }
    Object::keys(v.unchecked_ref::<Object>())
        .iter()
        .filter_map(|k| k.as_string())
        .collect()
}

fn items(v: &JsValue) -> Vec<JsValue> {
    if Array::is_array(v) {
        v.unchecked_ref::<Array>().iter().collect()
    } else {
        Vec::new()
    }
}

/// `JSON.stringify(v)`, for messages and JSON arguments.
fn stringify(v: &JsValue) -> String {
    JSON::stringify(v)
        .ok()
        .and_then(|s| s.as_string())
        .unwrap_or_else(|| "<not JSON>".to_owned())
}

/// Equality of JSON values (RFC 8259): member order ignored, numbers compared as doubles
/// (README implementer note 1), strings code unit for code unit.
fn json_equal(a: &JsValue, b: &JsValue) -> bool {
    let (aa, ba) = (Array::is_array(a), Array::is_array(b));
    if aa || ba {
        let (x, y) = (items(a), items(b));
        return aa && ba && x.len() == y.len() && x.iter().zip(&y).all(|(p, q)| json_equal(p, q));
    }
    let (ao, bo) = (is_plain_object(a), is_plain_object(b));
    if ao || bo {
        let names = member_names(a);
        return ao
            && bo
            && names.len() == member_names(b).len()
            && names.iter().all(|n| match (get(a, n), get(b, n)) {
                (Some(p), Some(q)) => json_equal(&p, &q),
                _ => false,
            });
    }
    if let (Some(x), Some(y)) = (a.as_f64(), b.as_f64()) {
        return x == y;
    }
    if let (Some(x), Some(y)) = (a.as_string(), b.as_string()) {
        return x == y;
    }
    if let (Some(x), Some(y)) = (a.as_bool(), b.as_bool()) {
        return x == y;
    }
    a.is_null() && b.is_null()
}

/// A fresh plain object, filled member by member.
struct Rec(Object);

impl Rec {
    fn new() -> Self {
        Self(Object::new())
    }

    /// `Reflect.set` on a fresh ordinary object defines an own data property and can't fail
    /// (ECMA-262 OrdinarySet), so its result carries nothing.
    fn set(&self, name: &str, value: impl Into<JsValue>) {
        let _ = Reflect::set(&self.0, &JsValue::from_str(name), &value.into());
    }

    fn value(self) -> JsValue {
        self.0.into()
    }
}

fn array_of(values: Vec<JsValue>) -> JsValue {
    values.into_iter().collect::<Array>().into()
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

fn has_type(v: &JsValue, name: &str) -> Result<bool, String> {
    Ok(match name {
        "object" => is_plain_object(v),
        "array" => Array::is_array(v),
        "string" => v.is_string(),
        "boolean" => v.as_bool().is_some(),
        "null" => v.is_null(),
        "number" => v.as_f64().is_some(),
        // Number.isInteger (see the module doc on `1300819439.0`).
        "integer" => v
            .as_f64()
            .is_some_and(|n| n.is_finite() && n.fract() == 0.0),
        other => return Err(format!("schema: unknown type {other:?}")),
    })
}

fn number_of(schema: &JsValue, keyword: &str) -> Option<f64> {
    get(schema, keyword).and_then(|v| v.as_f64())
}

/// The first violation of `schema` by `v`, as `<JSON pointer>: <problem>`. A schema construct
/// this checker does not implement is an error too, so a schema change can't be ignored here.
fn check(defs: &JsValue, schema: &JsValue, v: &JsValue, ptr: &str) -> Result<(), String> {
    let at = if ptr.is_empty() { "(root)" } else { ptr };
    match schema.as_bool() {
        Some(true) => return Ok(()),
        Some(false) => return Err(format!("{at}: not allowed")),
        None if !is_plain_object(schema) => return Err(format!("schema: not a schema at {at}")),
        None => {}
    }
    for keyword in member_names(schema) {
        if !KEYWORDS.contains(&keyword.as_str()) && !ANNOTATIONS.contains(&keyword.as_str()) {
            return Err(format!("schema: unsupported keyword {keyword}"));
        }
    }
    if let Some(reference) = get(schema, "$ref") {
        let target = reference
            .as_string()
            .and_then(|r| r.strip_prefix("#/$defs/").map(str::to_owned))
            .and_then(|name| get(defs, &name))
            .ok_or_else(|| format!("schema: unresolvable $ref {}", stringify(&reference)))?;
        check(defs, &target, v, ptr)?;
    }
    if let Some(types) = get(schema, "type") {
        let names: Vec<String> = if Array::is_array(&types) {
            items(&types)
                .iter()
                .filter_map(JsValue::as_string)
                .collect()
        } else {
            types.as_string().into_iter().collect()
        };
        let mut matched = false;
        for name in &names {
            matched |= has_type(v, name)?;
        }
        if !matched {
            return Err(format!("{at}: must be of type {}", names.join(" or ")));
        }
    }
    if let Some(options) = get(schema, "enum") {
        if !Array::is_array(&options) {
            return Err("schema: enum is not an array".to_owned());
        }
        if !items(&options).iter().any(|o| json_equal(o, v)) {
            return Err(format!("{at}: must be one of {}", stringify(&options)));
        }
    }
    if let Some(constant) = get(schema, "const")
        && !json_equal(&constant, v)
    {
        return Err(format!("{at}: must be {}", stringify(&constant)));
    }
    if is_plain_object(v) {
        let properties = get(schema, "properties").unwrap_or_else(|| Object::new().into());
        if let Some(required) = get(schema, "required") {
            for name in items(&required).iter().filter_map(JsValue::as_string) {
                if !has(v, &name) {
                    return Err(format!("{ptr}/{name}: required member is missing"));
                }
            }
        }
        for name in member_names(&properties) {
            if let (Some(sub), Some(member)) = (get(&properties, &name), get(v, &name)) {
                check(defs, &sub, &member, &format!("{ptr}/{name}"))?;
            }
        }
        if let Some(additional) = get(schema, "additionalProperties") {
            for name in member_names(v) {
                if has(&properties, &name) {
                    continue;
                }
                if additional.as_bool() == Some(false) {
                    return Err(format!(
                        "{ptr}/{name}: unknown member (additionalProperties is false)"
                    ));
                }
                let member = get(v, &name).unwrap_or(JsValue::UNDEFINED);
                check(defs, &additional, &member, &format!("{ptr}/{name}"))?;
            }
        }
    }
    if Array::is_array(v) {
        let list = items(v);
        let len = list.len() as f64;
        if let Some(min) = number_of(schema, "minItems")
            && len < min
        {
            return Err(format!("{at}: at least {min} item(s)"));
        }
        if let Some(max) = number_of(schema, "maxItems")
            && len > max
        {
            return Err(format!("{at}: at most {max} item(s)"));
        }
        if get(schema, "uniqueItems").and_then(|u| u.as_bool()) == Some(true) {
            for (i, x) in list.iter().enumerate() {
                if list[..i].iter().any(|y| json_equal(x, y)) {
                    return Err(format!("{at}: items must be unique"));
                }
            }
        }
        if let Some(item_schema) = get(schema, "items") {
            for (i, item) in list.iter().enumerate() {
                check(defs, &item_schema, item, &format!("{ptr}/{i}"))?;
            }
        }
    }
    if let Some(n) = v.as_f64() {
        if let Some(min) = number_of(schema, "minimum")
            && n < min
        {
            return Err(format!("{at}: at least {min}"));
        }
        if let Some(max) = number_of(schema, "maximum")
            && n > max
        {
            return Err(format!("{at}: at most {max}"));
        }
    }
    if let Some(s) = v.as_string() {
        // JSON Schema counts characters as code points.
        if let Some(min) = number_of(schema, "minLength")
            && (s.chars().count() as f64) < min
        {
            return Err(format!("{at}: at least {min} character(s)"));
        }
        if let Some(pattern) = get(schema, "pattern").and_then(|p| p.as_string())
            && !RegExp::new(&pattern, "u").test(&s)
        {
            return Err(format!("{at}: must match {pattern}"));
        }
    }
    if let Some(all) = get(schema, "allOf") {
        for sub in items(&all) {
            check(defs, &sub, v, ptr)?;
        }
    }
    if let Some(one) = get(schema, "oneOf") {
        let results: Vec<Result<(), String>> = items(&one)
            .iter()
            .map(|sub| check(defs, sub, v, ptr))
            .collect();
        let passing = results.iter().filter(|r| r.is_ok()).count();
        if passing == 0 {
            let reasons: Vec<String> = results.into_iter().filter_map(Result::err).collect();
            return Err(format!(
                "{at}: matches none of oneOf ({})",
                reasons.join("; ")
            ));
        }
        if passing > 1 {
            return Err(format!("{at}: matches more than one of oneOf"));
        }
    }
    if let Some(condition) = get(schema, "if") {
        let branch = if check(defs, &condition, v, ptr).is_ok() {
            get(schema, "then")
        } else {
            get(schema, "else")
        };
        if let Some(branch) = branch {
            check(defs, &branch, v, ptr)?;
        }
    }
    Ok(())
}

/// The number of `:` member separators outside strings in a JSON text (RFC 8259 §4: a `:` occurs
/// outside a string only between a member name and its value).
fn separators(text: &str) -> usize {
    let (mut n, mut in_string, mut escaped) = (0, false, false);
    for b in text.bytes() {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
        } else if b == b'"' {
            in_string = true;
        } else if b == b':' {
            n += 1;
        }
    }
    n
}

/// The number of object members in a parsed value, at every depth.
fn members(v: &JsValue) -> usize {
    if Array::is_array(v) {
        items(v).iter().map(members).sum()
    } else if is_plain_object(v) {
        member_names(v)
            .iter()
            .map(|n| 1 + get(v, n).map_or(0, |m| members(&m)))
            .sum()
    } else {
        0
    }
}

// ---------------------------------------------------------------------------------------------
// One vector: parse, validate, cross-member rules, skip, execute, compare
// ---------------------------------------------------------------------------------------------

/// Why an operation stopped: the library's outcome, or a broken vector / failed runner check.
enum Stop {
    /// The adapter threw a `PolyjoseError`: the vector's outcome is this code (ADR 0030 §5).
    Library(String),
    /// The vector fails with this message, whatever it expects.
    Harness(String),
}

type Step<T> = Result<T, Stop>;

fn harness<T>(message: impl Into<String>) -> Step<T> {
    Err(Stop::Harness(message.into()))
}

/// An adapter call: a thrown `PolyjoseError` (name `PolyjoseError`, an own string `code`) is the
/// outcome; anything else thrown fails the vector (README implementer note 8).
fn lib<T>(result: Result<T, JsValue>) -> Step<T> {
    result.map_err(|thrown| {
        let name = get_any(&thrown, "name").and_then(|n| n.as_string());
        let code = own_string(&thrown, "code");
        match (thrown.dyn_ref::<js_sys::Error>(), name.as_deref(), code) {
            (Some(_), Some("PolyjoseError"), Some(code)) => Stop::Library(code),
            _ => Stop::Harness(format!(
                "the adapter threw something that is not a PolyjoseError: {}: {}",
                name.unwrap_or_else(|| "?".to_owned()),
                get_any(&thrown, "message")
                    .and_then(|m| m.as_string())
                    .unwrap_or_else(|| stringify(&thrown))
            )),
        }
    })
}

/// `v[name]`, inherited members included (an `Error`'s `name` and `message`).
fn get_any(v: &JsValue, name: &str) -> Option<JsValue> {
    if !v.is_object() {
        return None;
    }
    Reflect::get(v, &JsValue::from_str(name))
        .ok()
        .filter(|m| !m.is_undefined())
}

/// An own string member of any object (the `code` of a thrown error, ADR 0030 §5).
fn own_string(v: &JsValue, name: &str) -> Option<String> {
    let key = JsValue::from_str(name);
    if v.is_object() && Object::has_own(v.unchecked_ref::<Object>(), &key) {
        Reflect::get(v, &key).ok().and_then(|m| m.as_string())
    } else {
        None
    }
}

/// An adapter call inside a runner check (a round trip, an import back, decoding an input): any
/// failure there fails the vector instead of being its outcome.
fn checked<T>(what: &str, result: Result<T, JsValue>) -> Step<T> {
    lib(result).map_err(|stop| match stop {
        Stop::Library(code) => Stop::Harness(format!("{what} ({code})")),
        other => other,
    })
}

/// The outputs of an operation, in insertion order.
#[derive(Default)]
struct Out(Vec<(String, JsValue)>);

impl Out {
    fn set(&mut self, name: &str, value: impl Into<JsValue>) {
        self.0.push((name.to_owned(), value.into()));
    }

    fn get(&self, name: &str) -> Option<&JsValue> {
        self.0.iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }

    fn to_json(&self) -> String {
        let rec = Rec::new();
        for (name, value) in &self.0 {
            rec.set(name, value.clone());
        }
        stringify(&rec.value())
    }
}

/// The outcome of a vector that ran: its outputs, or the library's code.
type Outcome = Result<Out, String>;

/// A vector's status for the results file (ADR 0034 §2).
enum Status {
    Pass,
    /// Skipped for these names: the missing `features`, in the vector's order (ADR 0034 §3),
    /// then each enabled `features_absent` one as `!<name>`, in its order (ADR 0056 §2).
    Skipped(Vec<String>),
    Fail(String),
}

/// What the results file records of one vector besides its status.
#[derive(Default)]
struct Trace {
    source: Option<String>,
    op: Option<String>,
    /// Set once the operation's calls returned (README "The results file", `actual`).
    actual: Option<Result<(), String>>,
}

/// A string member with at least one non-whitespace character (`$defs/text`).
fn text_member(v: &JsValue, name: &str) -> Option<String> {
    get(v, name)
        .and_then(|m| m.as_string())
        .filter(|s| s.chars().any(|c| !c.is_whitespace()))
}

/// Checks and runs one vector file, recording into `trace` as it goes.
fn run_vector(
    name: &str,
    text: &str,
    defs: &JsValue,
    schema: &JsValue,
    enabled: &[&str],
    trace: &mut Trace,
) -> Status {
    let value = match JSON::parse(text) {
        Ok(value) => value,
        Err(e) => {
            return Status::Fail(format!(
                "{name}: not a valid JSON text ({}); see conformance/schema.json",
                get_any(&e, "message")
                    .and_then(|m| m.as_string())
                    .unwrap_or_default()
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
    if separators(text) != members(&value) {
        return fail("duplicate member names: a vector file must be I-JSON (RFC 7493 §2.3)".into());
    }
    if let Err(e) = check(defs, schema, &value, "") {
        return fail(format!("schema: {e}"));
    }
    if let Err(e) = cross_member_rules(&value) {
        return fail(e);
    }
    let names = |member: &str| -> Vec<String> {
        get(&value, member)
            .map(|f| items(&f))
            .unwrap_or_default()
            .iter()
            .filter_map(JsValue::as_string)
            .collect()
    };
    let skip: Vec<String> = names("features")
        .into_iter()
        .filter(|f| !enabled.contains(&f.as_str()))
        .chain(
            names("features_absent")
                .into_iter()
                .filter(|f| enabled.contains(&f.as_str()))
                .map(|f| format!("!{f}")),
        )
        .collect();
    if !skip.is_empty() {
        return Status::Skipped(skip);
    }
    let outcome = match execute(&value) {
        Err(message) => return fail(message),
        Ok(outcome) => outcome,
    };
    trace.actual = Some(outcome.as_ref().map(|_| ()).map_err(Clone::clone));
    let expect = get(&value, "expect").unwrap_or(JsValue::UNDEFINED);
    match compare(&expect, &outcome) {
        Ok(()) => Status::Pass,
        Err(message) => fail(message),
    }
}

/// The rules tying members together that the schema can't state, as the reference runner's
/// `check_jwe_encrypt_features` and `check_jwt_issue` check them (conformance/README.md).
fn cross_member_rules(vector: &JsValue) -> Result<(), String> {
    let operation = text_member(vector, "operation").unwrap_or_default();
    let input = get(vector, "input").unwrap_or(JsValue::UNDEFINED);
    let expect = get(vector, "expect").unwrap_or(JsValue::UNDEFINED);
    let listed_in = |member: &str, feature: &str| {
        get(vector, member).is_some_and(|f| {
            items(&f)
                .iter()
                .any(|x| x.as_string().as_deref() == Some(feature))
        })
    };
    let listed = |feature: &str| listed_in("features", feature);
    // ADR 0056 §3: no name both needed and forbidden.
    if let Some(both) = get(vector, "features_absent")
        .map(|f| items(&f))
        .unwrap_or_default()
        .iter()
        .filter_map(JsValue::as_string)
        .find(|f| listed(f))
    {
        return Err(format!(
            "schema: /features_absent: \"{both}\" is listed in `features` too"
        ));
    }
    if operation == "jwe.encrypt" {
        for (member, feature) in [("rng_b64u", "fixed-rng"), ("protected_b64u", "fixed-rng")] {
            if has(&input, member) && !listed(feature) {
                return Err(format!(
                    "schema: /features: `input/{member}` needs \"{feature}\" listed in `features`"
                ));
            }
        }
        // ADR 0056 §4: `deflate` in either list (`features_absent` pins UnsupportedAlgorithm).
        if has(&input, "compress") && !listed(DEFLATE) && !listed_in("features_absent", DEFLATE) {
            return Err(
                "schema: /features: `input/compress` needs \"deflate\" listed in \
                        `features` or `features_absent`"
                    .to_owned(),
            );
        }
    }
    if operation == "jwt.issue" {
        let ok = get(&expect, "ok").and_then(|o| o.as_bool()) == Some(true);
        let encrypt = has(&input, "encrypt");
        let validate = has(&input, "validate");
        if ok && has(&expect, "token") && encrypt {
            return Err(
                "schema: /expect/token: an encrypted token is randomized (RFC 7516 \
                        §5.1), so with `encrypt` expect {\"ok\": true} and give `validate`"
                    .to_owned(),
            );
        }
        if ok && !has(&expect, "token") && !validate && !encrypt {
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
fn compare(expect: &JsValue, outcome: &Outcome) -> Result<(), String> {
    let want_ok = get(expect, "ok").and_then(|o| o.as_bool()) == Some(true);
    let want_error = get(expect, "error").and_then(|e| e.as_string());
    match outcome {
        Ok(got) if want_ok => {
            for name in member_names(expect) {
                if name == "ok" {
                    continue;
                }
                let want = get(expect, &name).unwrap_or(JsValue::UNDEFINED);
                match got.get(&name) {
                    Some(value) if json_equal(&want, value) => {}
                    value => {
                        return Err(format!(
                            "`{name}`: expected {}, got {}",
                            stringify(&want),
                            value.map_or("nothing".to_owned(), stringify)
                        ));
                    }
                }
            }
            for (name, value) in &got.0 {
                if !has(expect, name) {
                    return Err(format!(
                        "`{name}`: expected nothing, got {}",
                        stringify(value)
                    ));
                }
            }
            Ok(())
        }
        Err(code) if want_ok => Err(format!("expected success, got error {code}")),
        Ok(got) => Err(format!(
            "expected error {}, but the operation succeeded with {}",
            want_error.unwrap_or_default(),
            got.to_json()
        )),
        Err(code) => match want_error {
            Some(want) if want == *code => Ok(()),
            want => Err(format!(
                "expected error {}, got error {code}",
                want.unwrap_or_default()
            )),
        },
    }
}

// ---------------------------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------------------------

/// A string member (the schema has checked the type).
fn str_of(object: &JsValue, name: &str) -> Step<String> {
    match get(object, name).and_then(|v| v.as_string()) {
        Some(s) => Ok(s),
        None => harness(format!("`{name}` is not a string")),
    }
}

/// An array of strings as a fresh JS array, passed as given (an allow-list, a claim list).
fn strings_of(object: &JsValue, name: &str) -> Step<JsValue> {
    let list = get(object, name).map(|v| items(&v)).unwrap_or_default();
    if list.iter().any(|v| !v.is_string()) {
        return harness(format!("`{name}` is not an array of strings"));
    }
    Ok(array_of(list))
}

/// An integer member (a count, a limit, `now`), as the JS number it already is.
fn number_member(object: &JsValue, name: &str) -> Option<JsValue> {
    get(object, name).filter(|v| v.as_f64().is_some())
}

/// Whether a member name is an array index (ECMA-262 §6.1.7: a canonical numeric string below
/// 2^32 − 1), which a JS object enumerates first, before every other name.
fn is_array_index(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| b.is_ascii_digit())
        && (name == "0" || !name.starts_with('0'))
        && name.parse::<u64>().is_ok_and(|n| n < 4_294_967_295)
}

fn has_array_index_name(v: &JsValue) -> bool {
    if Array::is_array(v) {
        items(v).iter().any(has_array_index_name)
    } else if is_plain_object(v) {
        member_names(v)
            .iter()
            .any(|n| is_array_index(n) || get(v, n).is_some_and(|m| has_array_index_name(&m)))
    } else {
        false
    }
}

/// A JSON-valued member (a JWK, a JWK Set, a header, claims, a JSON JWS or JWE) as JSON text in
/// file order: `JSON.stringify` of the parsed value, unless a JS object would have moved one of
/// its names (README implementer note 4; module doc).
fn json_arg(object: &JsValue, name: &str) -> Step<String> {
    let Some(value) = get(object, name) else {
        return harness(format!("no member `{name}`"));
    };
    if has_array_index_name(&value) {
        return harness(format!(
            "`{name}` has an integer-like member name, which a JS object reorders, so its file \
             order can't be passed on (README implementer note 4)"
        ));
    }
    Ok(stringify(&value))
}

/// `json_arg` for an optional member.
fn opt_json_arg(object: &JsValue, name: &str) -> Step<Option<String>> {
    if has(object, name) {
        json_arg(object, name).map(Some)
    } else {
        Ok(None)
    }
}

/// A `*_b64u` input's octets, decoded with the adapter. A non-canonical value is a broken
/// vector, never an outcome (README "How bytes are written").
fn decode(text: String, name: &str) -> Step<Vec<u8>> {
    checked(
        &format!("`{name}` is not canonical base64url; the runner must decode it"),
        util::base64url_decode(text),
    )
    .map(|bytes| bytes.to_vec())
}

fn decode_member(object: &JsValue, name: &str) -> Step<Vec<u8>> {
    decode(str_of(object, name)?, name)
}

/// Output octets as canonical base64url (RFC 4648 §5).
fn encode(bytes: Vec<u8>) -> JsValue {
    util::base64url_encode(bytes).into()
}

fn hex_decode(s: &str) -> Step<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return harness("`bytes_hex` has an odd length");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| Stop::Harness("`bytes_hex` is not hex".to_owned()))
        })
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A returned JSON text, parsed.
fn parse_output(text: &str, what: &str) -> Step<JsValue> {
    JSON::parse(text).or_else(|_| harness(format!("{what} does not parse as JSON")))
}

/// A member of an adapter result object.
fn result_member(result: &JsValue, name: &str) -> Step<JsValue> {
    match get(result, name) {
        Some(v) => Ok(v),
        None => harness(format!("the adapter's result has no `{name}`")),
    }
}

fn result_bytes(result: &JsValue, name: &str) -> Step<Vec<u8>> {
    let value = result_member(result, name)?;
    match value.dyn_ref::<Uint8Array>() {
        Some(bytes) => Ok(bytes.to_vec()),
        None => harness(format!("the adapter's `{name}` is not a Uint8Array")),
    }
}

fn result_string(result: &JsValue, name: &str) -> Step<String> {
    match result_member(result, name)?.as_string() {
        Some(s) => Ok(s),
        None => harness(format!("the adapter's `{name}` is not a string")),
    }
}

// ---------------------------------------------------------------------------------------------
// Operations (README "Operation mapping"), each mirroring the JS runner's handler
// ---------------------------------------------------------------------------------------------

/// Runs the operation: `Ok(outcome)` when the adapter returned or threw a `PolyjoseError`,
/// `Err(message)` when the vector fails whatever it expects.
fn execute(vector: &JsValue) -> Result<Outcome, String> {
    let operation = text_member(vector, "operation").unwrap_or_default();
    let input = get(vector, "input").unwrap_or(JsValue::UNDEFINED);
    let expect = get(vector, "expect").unwrap_or(JsValue::UNDEFINED);
    let mut out = Out::default();
    let step = match operation.as_str() {
        "b64url.encode" => b64url_encode(&input, &mut out),
        "b64url.decode" => b64url_decode(&input, &mut out),
        "jwk.thumbprint" => jwk_thumbprint(&input, &mut out),
        "jws.sign" => jws_sign(&input, &expect, &mut out),
        "jws.verify" => jws_verify(&input, &mut out),
        "keys.import_pem" => keys_import_pem(&input, &mut out),
        "keys.import_der" => keys_import_der(&input, &mut out),
        "keys.export_pem" => keys_export_pem(&input, &mut out),
        "keys.export_der" => keys_export_der(&input, &mut out),
        "keys.generate_for" => keys_generate_for(&input, &expect, &mut out),
        "keys.generate_oct" | "keys.generate_ec" | "keys.generate_okp" => {
            keys_generate(&operation, &input, &expect, &mut out)
        }
        "jwe.encrypt" => jwe_encrypt(&input, &expect, &mut out),
        "jwe.decrypt" => jwe_decrypt(&input, &mut out),
        "jwt.validate" => jwt_validate(&input, &mut out),
        "jwt.issue" => jwt_issue(&input, &expect, &mut out),
        other => {
            return Err(format!(
                "operation `{other}` is not implemented by the WASM runner; a vector is never \
                 skipped"
            ));
        }
    };
    match step {
        Ok(()) => Ok(Ok(out)),
        Err(Stop::Library(code)) => Ok(Err(code)),
        Err(Stop::Harness(message)) => Err(message),
    }
}

/// `b64url.encode` → `base64urlEncode(bytes_hex decoded)` (RFC 4648 §5).
fn b64url_encode(input: &JsValue, out: &mut Out) -> Step<()> {
    let bytes = hex_decode(&str_of(input, "bytes_hex")?)?;
    out.set("b64u", encode(bytes));
    Ok(())
}

/// `b64url.decode` → `base64urlDecode(b64u)`, written back as lowercase hex (RFC 4648 §5).
fn b64url_decode(input: &JsValue, out: &mut Out) -> Step<()> {
    let bytes = lib(util::base64url_decode(str_of(input, "b64u")?))?;
    out.set("bytes_hex", hex_encode(&bytes.to_vec()));
    Ok(())
}

/// `jwk.thumbprint` → `jwkThumbprint` then `jwkThumbprintUri` (RFC 7638 §3, RFC 9278 §3);
/// `hash` `sha-256` is the adapter's `SHA-256`.
fn jwk_thumbprint(input: &JsValue, out: &mut Out) -> Step<()> {
    let hash = str_of(input, "hash")?;
    let Some((_, name)) = HASHES.iter().find(|(h, _)| *h == hash) else {
        return harness(format!("hash `{hash}` has no adapter name"));
    };
    let jwk = json_arg(input, "jwk")?;
    let name = Some((*name).to_owned());
    out.set(
        "thumbprint",
        lib(jwk::jwk_thumbprint(jwk.clone(), name.clone()))?,
    );
    out.set("thumbprint_uri", lib(jwk::jwk_thumbprint_uri(jwk, name))?);
    Ok(())
}

/// The shape of a JWS (RFC 7515 §7.1, §7.2.1, §7.2.2), for a round trip.
fn jws_shape_ok(serialization: &str, signed: &str, parsed: &JsValue, signers: usize) -> bool {
    match serialization {
        "compact" => signed.split('.').count() == 3,
        "flattened" => has(parsed, "signature") && !has(parsed, "signatures"),
        _ => get(parsed, "signatures").is_some_and(|s| items(&s).len() == signers),
    }
}

/// `jws.sign` → `jwsSignCompact` / `jwsSignFlattened` / `jwsSignGeneral` (RFC 7515 §5.1, §7).
fn jws_sign(input: &JsValue, expect: &JsValue, out: &mut Out) -> Step<()> {
    let serialization = str_of(input, "serialization")?;
    let payload = decode_member(input, "payload_b64u")?;
    let detached = get(input, "detached").and_then(|d| d.as_bool()) == Some(true);
    let mut signers = Vec::new();
    let mut first_key = String::new();
    let mut first_protected = None;
    for (i, s) in get(input, "signers")
        .map(|v| items(&v))
        .unwrap_or_default()
        .iter()
        .enumerate()
    {
        let signer = Rec::new();
        let key = json_arg(s, "key")?;
        let protected = get(s, "protected_b64u").and_then(|p| p.as_string());
        if i == 0 {
            first_key.clone_from(&key);
            first_protected.clone_from(&protected);
        }
        signer.set("key", key);
        if let Some(p) = protected {
            signer.set("protectedB64u", p);
        }
        // RFC 7515 §7.2.1: a signer may have only an unprotected header (ADR 0045 §1).
        if let Some(header) = opt_json_arg(s, "header")? {
            signer.set("unprotectedHeader", header);
        }
        signers.push(signer.value());
    }
    let Some(first) = signers.first().cloned() else {
        return harness("no signers");
    };
    let signed: String = match serialization.as_str() {
        "compact" => {
            let options = Rec::new();
            if let Some(p) = first_protected {
                options.set("protectedB64u", p);
            }
            if detached {
                options.set("detached", true);
            }
            lib(jws::jws_sign_compact(
                payload.clone(),
                first_key,
                &options.value(),
            ))?
            .into()
        }
        "flattened" => lib(jws::jws_sign_flattened(payload.clone(), &first, detached))?.into(),
        _ => lib(jws::jws_sign_general(
            payload.clone(),
            &array_of(signers.clone()),
            detached,
        ))?
        .into(),
    };
    let jws: JsValue = if serialization == "compact" {
        signed.as_str().into()
    } else {
        parse_output(&signed, "the signed JSON JWS")?
    };
    let Some(verify_with) = get(expect, "verify_with").filter(is_plain_object) else {
        out.set("jws", jws);
        return Ok(());
    };
    // Round trip (Rust `check_round_trip`): shape, verify with verify_with, same payload.
    if !jws_shape_ok(&serialization, &signed, &jws, signers.len()) {
        return harness(format!(
            "round trip: the output is not a {serialization} JWS with {} signature(s)",
            signers.len()
        ));
    }
    let key = json_arg(&verify_with, "key")?;
    let options = Rec::new();
    options.set("allowedAlgs", strings_of(&verify_with, "allowed_algs")?);
    if detached {
        options.set("detachedPayload", Uint8Array::from(&payload[..]));
    }
    let options = options.value();
    let what = "round trip: the signed JWS does not verify with verify_with";
    let verified = if serialization == "compact" {
        checked(what, jws::jws_verify_compact(signed, key, &options))?
    } else {
        checked(what, jws::jws_verify_json(signed, key, &options))?
    };
    if result_bytes(&verified, "payload")? != payload {
        return harness("round trip: the verified payload is not the signed one");
    }
    out.set("verify_with", verify_with);
    Ok(())
}

/// `jws.verify` → `jwsVerifyCompact` (a string) / `jwsVerifyJson` (an object, as its text)
/// (RFC 7515 §5.2, RFC 8725 §3.1).
fn jws_verify(input: &JsValue, out: &mut Out) -> Step<()> {
    let key = json_arg(input, "key")?;
    let options = Rec::new();
    options.set("allowedAlgs", strings_of(input, "allowed_algs")?);
    if has(input, "detached_payload_b64u") {
        let detached = decode_member(input, "detached_payload_b64u")?;
        options.set("detachedPayload", Uint8Array::from(&detached[..]));
    }
    if let Some(n) = number_member(input, "max_input_len") {
        options.set("maxInputLen", n);
    }
    if let Some(n) = number_member(input, "max_signatures") {
        options.set("maxSignatures", n);
    }
    let options = options.value();
    let jws = get(input, "jws").unwrap_or(JsValue::UNDEFINED);
    let verified = match jws.as_string() {
        Some(compact) => lib(jws::jws_verify_compact(compact, key, &options))?,
        None => lib(jws::jws_verify_json(json_arg(input, "jws")?, key, &options))?,
    };
    out.set("payload_b64u", encode(result_bytes(&verified, "payload")?));
    out.set("alg", result_string(&verified, "alg")?);
    out.set(
        "signature_index",
        result_member(&verified, "signatureIndex")?,
    );
    Ok(())
}

/// A PEM or DER import result; an `oct` key fails the vector whatever it expects
/// (RFC 8725 §2.1).
fn imported(jwk: JsString) -> Step<JsValue> {
    let value = parse_output(&String::from(jwk), "the imported JWK")?;
    if get(&value, "kty").and_then(|k| k.as_string()).as_deref() == Some("oct") {
        return harness("a PEM or DER import returned an oct key (RFC 8725 §2.1)");
    }
    Ok(value)
}

/// `keys.import_pem` → `jwkFromPem(pem)` (RFC 7468; ADR 0018 §3).
fn keys_import_pem(input: &JsValue, out: &mut Out) -> Step<()> {
    out.set(
        "jwk",
        imported(lib(keys::jwk_from_pem(str_of(input, "pem")?))?)?,
    );
    Ok(())
}

/// `keys.import_der` → `jwkFromDer(der_b64u decoded, format)` (ADR 0018 §3).
fn keys_import_der(input: &JsValue, out: &mut Out) -> Step<()> {
    let der = decode_member(input, "der_b64u")?;
    let format = str_of(input, "format")?;
    out.set("jwk", imported(lib(keys::jwk_from_der(der, &format))?)?);
    Ok(())
}

/// `keys.export_pem` → `jwkToPem(jwk, format)`; the JWK import inside is the first step.
fn keys_export_pem(input: &JsValue, out: &mut Out) -> Step<()> {
    let jwk = json_arg(input, "jwk")?;
    let format = str_of(input, "format")?;
    out.set("pem", lib(keys::jwk_to_pem(jwk, &format))?);
    Ok(())
}

/// `keys.export_der` → `jwkToDer(jwk, format)`, base64url.
fn keys_export_der(input: &JsValue, out: &mut Out) -> Step<()> {
    let jwk = json_arg(input, "jwk")?;
    let format = str_of(input, "format")?;
    let der = lib(keys::jwk_to_der(jwk, &format))?;
    out.set("der_b64u", encode(der.to_vec()));
    Ok(())
}

/// The shape of a generated key after the checks a shape can't say (README
/// `keys.generate_for`): private, exactly the RFC members of `members`, and `jwkParse` gives it
/// back.
fn generated_shape(
    text: &str,
    members: fn(&str) -> Option<&'static [&'static str]>,
) -> Step<JsValue> {
    let jwk = parse_output(text, "the generated JWK")?;
    if !is_plain_object(&jwk) {
        return harness("the generated JWK is not an object");
    }
    let kty = get(&jwk, "kty")
        .and_then(|k| k.as_string())
        .unwrap_or_default();
    if kty != "oct" && !has(&jwk, "d") {
        return harness("generate_for returned a public key");
    }
    let mut names = member_names(&jwk);
    names.sort();
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    if members(&kty) != Some(names.as_slice()) {
        return harness(format!(
            "generate_for returned a JWK with members {names:?}"
        ));
    }
    let again = checked(
        "the generated JWK does not import",
        jwk::jwk_parse(text.to_owned()),
    )?;
    if !json_equal(
        &parse_output(&String::from(again), "the re-imported JWK")?,
        &jwk,
    ) {
        return harness("the generated JWK imports as a different key");
    }
    let shape = Rec::new();
    for name in ["kty", "crv", "alg"] {
        if let Some(value) = get(&jwk, name) {
            shape.set(name, value);
        }
    }
    if let Some(k) = get(&jwk, "k").and_then(|k| k.as_string()) {
        let octets = decode(k, "the generated k")?;
        shape.set("k_octets", octets.len() as f64);
    }
    Ok(shape.value())
}

/// `keys.generate_for` → `jwkGenerateForAlg(alg)` (ADR 0018 §5), `alg` passed as given; then
/// the `use_with` round trip when the vector has one (ADR 0034 §6).
fn keys_generate_for(input: &JsValue, expect: &JsValue, out: &mut Out) -> Step<()> {
    let generated = String::from(lib(keys::jwk_generate_for_alg(&str_of(input, "alg")?))?);
    out.set("shape", generated_shape(&generated, generated_members)?);
    echo_use_with(&generated, expect, out)
}

/// `keys.generate_oct` → `jwkGenerateOct(len_bytes)` (RFC 7518 §6.4.1), `keys.generate_ec` →
/// `jwkGenerateEc(crv)` (RFC 7518 §6.2, RFC 8812 §3.1), `keys.generate_okp` →
/// `jwkGenerateOkp(crv)` (RFC 8037 §2) (ADR 0030 §4, ADR 0018 §5); then the shape (no `alg`) and
/// the `use_with` round trip.
fn keys_generate(operation: &str, input: &JsValue, expect: &JsValue, out: &mut Out) -> Step<()> {
    let generated = match operation {
        "keys.generate_oct" => {
            let Some(len) = get(input, "len_bytes")
                .and_then(|n| n.as_f64())
                .filter(|n| n.fract() == 0.0 && (0.0..=f64::from(u32::MAX)).contains(n))
            else {
                return harness("`len_bytes` is not a u32");
            };
            // An integral number in u32 range (checked above, and by the schema's `count`).
            lib(keys::jwk_generate_oct(len as u32))?
        }
        "keys.generate_ec" => lib(keys::jwk_generate_ec(&str_of(input, "crv")?))?,
        _ => lib(keys::jwk_generate_okp(&str_of(input, "crv")?))?,
    };
    let generated = String::from(generated);
    out.set("shape", generated_shape(&generated, unbound_members)?);
    echo_use_with(&generated, expect, out)
}

/// Runs the expectation's `use_with` round trip on `generated`, if it has one, and echoes it back
/// as an output, as `verify_with` is.
fn echo_use_with(generated: &str, expect: &JsValue, out: &mut Out) -> Step<()> {
    if let Some(use_with) = get(expect, "use_with").filter(is_plain_object) {
        check_use_with(generated, &use_with)?;
        out.set("use_with", use_with);
    }
    Ok(())
}

/// The `use_with` round trip of a generated key (ADR 0034 §6; README `use_with`); every call is
/// a check, so any failure fails the vector. The other side is the key's public form
/// (`jwkToPublic`), or the key itself for `oct` (RFC 7518 §6.4).
///
/// - Without `enc`: a compact JWS (RFC 7515 §7.1) of [`USE_WITH_PAYLOAD`] under `{"alg": alg}`,
///   verified with the allow-list `[alg]` (RFC 7515 §5.1–§5.2).
/// - With `enc`: a compact JWE (RFC 7516 §7.1) of it to one recipient with `alg`, decrypted with
///   the key and the allow-lists `[alg]` and `[enc]` (RFC 7516 §5.1–§5.2).
fn check_use_with(generated: &str, use_with: &JsValue) -> Step<()> {
    let alg = str_of(use_with, "alg")?;
    let jwk = parse_output(generated, "the generated JWK")?;
    let other = if get(&jwk, "kty").and_then(|k| k.as_string()).as_deref() == Some("oct") {
        generated.to_owned()
    } else {
        checked(
            "use_with: the key has no public form",
            jwk::jwk_to_public(generated.to_owned()),
        )?
    };
    let algs = array_of(vec![JsValue::from_str(&alg)]);
    match get(use_with, "enc").and_then(|e| e.as_string()) {
        None => {
            let header = Rec::new();
            header.set("alg", alg.as_str());
            let options = Rec::new();
            options.set("protectedHeader", stringify(&header.value()));
            let token = checked(
                "use_with: the key does not sign",
                jws::jws_sign_compact(
                    USE_WITH_PAYLOAD.to_vec(),
                    generated.to_owned(),
                    &options.value(),
                ),
            )?;
            let policy = Rec::new();
            policy.set("allowedAlgs", algs);
            let verified = checked(
                "use_with: the signature does not verify",
                jws::jws_verify_compact(token.into(), other, &policy.value()),
            )?;
            if result_bytes(&verified, "payload")? != USE_WITH_PAYLOAD {
                return harness("use_with: the verified payload is not the signed one");
            }
        }
        Some(enc) => {
            let recipient = Rec::new();
            recipient.set("alg", alg.as_str());
            recipient.set("key", other);
            let options = Rec::new();
            options.set("enc", enc.as_str());
            options.set("recipients", array_of(vec![recipient.value()]));
            let token = checked(
                "use_with: encryption to the key fails",
                jwe::jwe_encrypt_compact(USE_WITH_PAYLOAD.to_vec(), &options.value()),
            )?;
            let policy = Rec::new();
            policy.set("allowedAlgs", algs);
            policy.set("allowedEnc", array_of(vec![JsValue::from_str(&enc)]));
            let decrypted = checked(
                "use_with: the key does not decrypt",
                jwe::jwe_decrypt_compact(token, generated.to_owned(), &policy.value()),
            )?;
            if result_bytes(&decrypted, "plaintext")? != USE_WITH_PAYLOAD {
                return harness("use_with: the decrypted plaintext is not the encrypted one");
            }
        }
    }
    Ok(())
}

/// The shape of a JWE (RFC 7516 §7.1, §7.2.1, §7.2.2), for a round trip.
fn jwe_shape_ok(serialization: &str, encrypted: &str, parsed: &JsValue, recipients: usize) -> bool {
    match serialization {
        "compact" => encrypted.split('.').count() == 5,
        "flattened" => has(parsed, "ciphertext") && !has(parsed, "recipients"),
        _ => get(parsed, "recipients").is_some_and(|r| items(&r).len() == recipients),
    }
}

/// `jwe.encrypt` → `jweEncryptCompact` / `jweEncryptJson(serialization)` (RFC 7516 §5.1, §7),
/// with the `JweEncryptOptions` mapping of the README.
fn jwe_encrypt(input: &JsValue, expect: &JsValue, out: &mut Out) -> Step<()> {
    if has(input, "rng_b64u") || has(input, "protected_b64u") {
        return harness(
            "a reproducible encryption (rng_b64u, protected_b64u) is not in the binding API \
             (ADR 0005)",
        );
    }
    let serialization = str_of(input, "serialization")?;
    let plaintext = decode_member(input, "plaintext_b64u")?;
    let mut recipients = Vec::new();
    for r in get(input, "recipients")
        .map(|v| items(&v))
        .unwrap_or_default()
    {
        let recipient = Rec::new();
        recipient.set("alg", str_of(&r, "alg")?);
        recipient.set("key", json_arg(&r, "key")?);
        if let Some(header) = opt_json_arg(&r, "header")? {
            recipient.set("header", header);
        }
        for (member, field) in [("apu_b64u", "apu"), ("apv_b64u", "apv")] {
            if has(&r, member) {
                recipient.set(field, Uint8Array::from(&decode_member(&r, member)?[..]));
            }
        }
        if let Some(n) = number_member(&r, "p2c") {
            recipient.set("p2c", n);
        }
        if let Some(n) = number_member(&r, "p2s_len") {
            recipient.set("p2sLen", n);
        }
        recipients.push(recipient.value());
    }
    let count = recipients.len();
    let options = Rec::new();
    options.set("enc", str_of(input, "enc")?);
    options.set("recipients", array_of(recipients));
    if let Some(protected) = opt_json_arg(input, "protected")? {
        options.set("protectedHeader", protected);
    }
    if let Some(shared) = opt_json_arg(input, "unprotected")? {
        options.set("sharedUnprotectedHeader", shared);
    }
    if has(input, "aad_b64u") {
        options.set(
            "aad",
            Uint8Array::from(&decode_member(input, "aad_b64u")?[..]),
        );
    }
    if get(input, "compress").and_then(|c| c.as_bool()) == Some(true) {
        options.set("compress", true);
    }
    let options = options.value();
    let encrypted = if serialization == "compact" {
        lib(jwe::jwe_encrypt_compact(plaintext.clone(), &options))?
    } else {
        lib(jwe::jwe_encrypt_json(
            plaintext.clone(),
            &options,
            &serialization,
        ))?
    };
    let jwe: JsValue = if serialization == "compact" {
        encrypted.as_str().into()
    } else {
        parse_output(&encrypted, "the encrypted JSON JWE")?
    };
    let Some(decrypt_with) = get(expect, "decrypt_with").filter(is_plain_object) else {
        out.set("jwe", jwe);
        return Ok(());
    };
    // Round trip (Rust `check_jwe_round_trip`): shape, decrypt with decrypt_with, same plaintext.
    if !jwe_shape_ok(&serialization, &encrypted, &jwe, count) {
        return harness(format!(
            "round trip: the output is not a {serialization} JWE with {count} recipient(s)"
        ));
    }
    let key = json_arg(&decrypt_with, "key")?;
    let policy = Rec::new();
    policy.set("allowedAlgs", strings_of(&decrypt_with, "allowed_algs")?);
    policy.set("allowedEnc", strings_of(&decrypt_with, "allowed_enc")?);
    let policy = policy.value();
    let what = "round trip: the encrypted JWE does not decrypt with decrypt_with";
    let decrypted = if serialization == "compact" {
        checked(what, jwe::jwe_decrypt_compact(encrypted, key, &policy))?
    } else {
        checked(what, jwe::jwe_decrypt_json(encrypted, key, &policy))?
    };
    if result_bytes(&decrypted, "plaintext")? != plaintext {
        return harness("round trip: the decrypted plaintext is not the encrypted one");
    }
    out.set("decrypt_with", decrypt_with);
    Ok(())
}

/// The decrypt options of `jwe.decrypt` and of a nested JWT's `decrypt` (Rust `jwe_policy`):
/// the allow-lists, and each optional member only when present (RFC 7516 §5.2, RFC 8725 §3.1,
/// ADR 0023).
fn jwe_decrypt_options(object: &JsValue) -> Step<JsValue> {
    let options = Rec::new();
    options.set("allowedAlgs", strings_of(object, "allowed_algs")?);
    options.set("allowedEnc", strings_of(object, "allowed_enc")?);
    if has(object, "understood_crit") {
        options.set("understoodCrit", strings_of(object, "understood_crit")?);
    }
    for (member, field) in [
        ("max_input_len", "maxInputLen"),
        ("max_recipients", "maxRecipients"),
        ("max_pbes2_count", "maxPbes2Count"),
        ("max_decompressed_len", "maxDecompressedLen"),
    ] {
        if let Some(n) = number_member(object, member) {
            options.set(field, n);
        }
    }
    Ok(options.value())
}

/// `jwe.decrypt` → `jweDecryptCompact` (a string) / `jweDecryptJson` (an object, as its text)
/// (RFC 7516 §5.2).
fn jwe_decrypt(input: &JsValue, out: &mut Out) -> Step<()> {
    let key = json_arg(input, "key")?;
    let policy = jwe_decrypt_options(input)?;
    let jwe = get(input, "jwe").unwrap_or(JsValue::UNDEFINED);
    let decrypted = match jwe.as_string() {
        Some(compact) => lib(jwe::jwe_decrypt_compact(compact, key, &policy))?,
        None => lib(jwe::jwe_decrypt_json(json_arg(input, "jwe")?, key, &policy))?,
    };
    out.set(
        "plaintext_b64u",
        encode(result_bytes(&decrypted, "plaintext")?),
    );
    out.set("recipient", result_member(&decrypted, "recipientIndex")?);
    Ok(())
}

/// The JWT verify options from `allowed_algs`, `now` and `policy` (Rust `jwt_policy`), member by
/// member (README "The JWT policy"). An absent member, or a boolean `false`, sets nothing, so the
/// library default stays (README implementer note 6).
fn jwt_verify_options(object: &JsValue) -> Step<JsValue> {
    let policy = get(object, "policy").unwrap_or_else(|| Object::new().into());
    let typ = get(&policy, "typ").filter(is_plain_object);
    let mode = typ
        .as_ref()
        .and_then(|t| get(t, "mode"))
        .and_then(|m| m.as_string());
    if has(&policy, "profile") && mode.as_deref() == Some("default") {
        return harness(
            "`policy/typ/mode` \"default\" contradicts `policy/profile` \"access_token\", which \
             requires typ at+jwt (RFC 9068 §4)",
        );
    }
    let options = Rec::new();
    options.set("allowedAlgs", strings_of(object, "allowed_algs")?);
    // ADR 0028 §4: the vector's `now`, never a clock.
    match number_member(object, "now") {
        Some(now) => options.set("now", now),
        None => return harness("`now` is required (ADR 0028 §4)"),
    }
    if let Some(issuer) = get(&policy, "issuer") {
        let issuers = if issuer.is_string() {
            array_of(vec![issuer])
        } else {
            strings_of(&policy, "issuer")?
        };
        options.set("issuers", issuers);
    }
    if has(&policy, "audience") {
        options.set("audiences", strings_of(&policy, "audience")?);
    }
    if let Some(subject) = get(&policy, "subject").filter(JsValue::is_string) {
        options.set("subject", subject);
    }
    for (member, field) in [
        ("leeway", "leeway"),
        ("max_age", "maxAge"),
        ("max_key_candidates", "maxKeyCandidates"),
    ] {
        if let Some(n) = number_member(&policy, member) {
            options.set(field, n);
        }
    }
    if has(&policy, "require") {
        options.set("requiredClaims", strings_of(&policy, "require")?);
    }
    for (member, field) in [
        ("allow_missing_exp", "allowMissingExp"),
        ("ignore_audience", "ignoreAudience"),
    ] {
        if get(&policy, member).and_then(|b| b.as_bool()) == Some(true) {
            options.set(field, true);
        }
    }
    match mode.as_deref() {
        Some("exact") => {
            let typ = typ.unwrap_or(JsValue::UNDEFINED);
            options.set("typ", str_of(&typ, "value")?);
        }
        Some("any") => options.set("anyTyp", true),
        _ => {}
    }
    if let Some(profile) = get(&policy, "profile").filter(JsValue::is_string) {
        options.set("profile", profile);
    }
    Ok(options.value())
}

/// Validates `token` with a `jwt.validate` input or a `jwt.issue` `validate` object (Rust
/// `jwt_validation` + `jwt_verify`): the four adapter forms are chosen by `decrypt` and by `key`
/// vs `jwks` (ADR 0030 §4). A nested JWT's result is its inner JWT (RFC 7519 §11.2).
fn jwt_validated(object: &JsValue, token: String) -> Step<JsValue> {
    let options = jwt_verify_options(object)?;
    let jwks = opt_json_arg(object, "jwks")?;
    let decrypt = get(object, "decrypt").filter(is_plain_object);
    match decrypt {
        Some(decrypt) => {
            let decrypt_key = json_arg(&decrypt, "key")?;
            let decrypt_options = jwe_decrypt_options(&decrypt)?;
            let nested = match jwks {
                Some(set) => lib(jwt::jwt_decrypt_nested_with_jwks(
                    token,
                    decrypt_key,
                    &decrypt_options,
                    set,
                    &options,
                ))?,
                None => lib(jwt::jwt_decrypt_nested(
                    token,
                    decrypt_key,
                    &decrypt_options,
                    json_arg(object, "key")?,
                    &options,
                ))?,
            };
            result_member(&nested, "inner")
        }
        None => match jwks {
            Some(set) => Ok(lib(jwt::jwt_verify_with_jwks(token, set, &options))?.into()),
            None => Ok(lib(jwt::jwt_verify(token, json_arg(object, "key")?, &options))?.into()),
        },
    }
}

/// `jwt.validate` → `jwtVerify` / `jwtVerifyWithJwks`, or `jwtDecryptNested(WithJwks)` with
/// `decrypt` (RFC 7519 §7.2; ADR 0027, ADR 0029).
fn jwt_validate(input: &JsValue, out: &mut Out) -> Step<()> {
    let verified = jwt_validated(input, str_of(input, "token")?)?;
    out.set(
        "claims",
        parse_output(&result_string(&verified, "claims")?, "the validated claims")?,
    );
    out.set("alg", result_string(&verified, "alg")?);
    // ADR 0029 §4: present exactly when a key set verified; 0 is an index, not "absent"
    // (README implementer note 2).
    if let Some(index) = get(&verified, "keyIndex") {
        out.set("key_index", index);
    }
    Ok(())
}

/// `jwt.issue` → `jwtSign`, then `jwtEncryptNested` with `encrypt` (RFC 7519 §7.1, §11.2;
/// ADR 0027 §7–§8): exactly the calls of the README table, in order, and none of the runner's own.
fn jwt_issue(input: &JsValue, expect: &JsValue, out: &mut Out) -> Step<()> {
    let key = json_arg(input, "key")?;
    // The claims' member order decides the exact token (ADR 0027 §1, implementer note 4).
    let claims = json_arg(input, "claims")?;
    let alg = str_of(input, "alg")?;
    let options = Rec::new();
    options.set("alg", alg.as_str());
    // `typ`: absent → the core default JWT; null → omitted (RFC 7519 §5.1); a string → set
    // (README implementer note 3).
    if let Some(typ) = get(input, "typ") {
        if typ.is_null() {
            options.set("omitTyp", true);
        } else {
            options.set("typ", str_of(input, "typ")?);
        }
    }
    let mut token = String::from(lib(jwt::jwt_sign(claims, key, &options.value()))?);
    let mut parts = 3;
    if let Some(encrypt) = get(input, "encrypt").filter(is_plain_object) {
        let recipient = Rec::new();
        recipient.set("alg", str_of(&encrypt, "alg")?);
        recipient.set("key", json_arg(&encrypt, "key")?);
        let options = Rec::new();
        options.set("enc", str_of(&encrypt, "enc")?);
        options.set("recipients", array_of(vec![recipient.value()]));
        token = lib(jwt::jwt_encrypt_nested(token, &options.value()))?;
        parts = 5;
    }
    if token.split('.').count() != parts {
        return harness(format!("the issued token is not {parts} compact parts"));
    }
    if let Some(validate) = get(input, "validate").filter(is_plain_object) {
        // Round trip (Rust `check_jwt_issue_round_trip`): validates, with the issued alg and
        // claims (README implementer note 10).
        let verified = match jwt_validated(&validate, token.clone()) {
            Ok(verified) => verified,
            Err(Stop::Library(code)) => {
                return harness(format!(
                    "round trip: the issued token does not validate with `validate` ({code})"
                ));
            }
            Err(other) => return Err(other),
        };
        let got_alg = result_string(&verified, "alg")?;
        if got_alg != alg {
            return harness(format!(
                "round trip: validated with alg {got_alg}, issued with {alg}"
            ));
        }
        let got = parse_output(&result_string(&verified, "claims")?, "the validated claims")?;
        let issued = get(input, "claims").unwrap_or(JsValue::UNDEFINED);
        if !json_equal(&got, &issued) {
            return harness(format!(
                "round trip: validated claims {} are not the issued {}",
                stringify(&got),
                stringify(&issued)
            ));
        }
    }
    if get(expect, "ok").and_then(|o| o.as_bool()) == Some(true) && has(expect, "token") {
        out.set("token", token);
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// The run and the results document
// ---------------------------------------------------------------------------------------------

/// Whether the core under the adapter has `deflate`: `compress` succeeds with it and is
/// `UnsupportedAlgorithm` without it (ADR 0017 §5, ADR 0030 §4). Anything else fails the run.
fn deflate_enabled() -> bool {
    let recipient = Rec::new();
    recipient.set("alg", "dir");
    recipient.set("key", r#"{"kty":"oct","k":"AAECAwQFBgcICQoLDA0ODw"}"#);
    let options = Rec::new();
    options.set("enc", "A128GCM");
    options.set("recipients", array_of(vec![recipient.value()]));
    options.set("compress", true);
    match lib(jwe::jwe_encrypt_compact(
        b"deflate probe".to_vec(),
        &options.value(),
    )) {
        Ok(_) => true,
        Err(Stop::Library(code)) if code == "UnsupportedAlgorithm" => false,
        Err(Stop::Library(message) | Stop::Harness(message)) => {
            panic!("the deflate probe failed: {message}")
        }
    }
}

/// The vector feature names this build enables (README "Features"): never `fixed-rng`, and
/// `deflate` when the core has it.
fn enabled_features() -> Vec<&'static str> {
    if deflate_enabled() {
        vec![DEFLATE]
    } else {
        Vec::new()
    }
}

/// One results-file entry (`conformance/schema/results.schema.json`).
fn result_entry(id: &str, trace: Trace, status: &Status) -> JsValue {
    let entry = Rec::new();
    entry.set("id", id);
    if let Some(source) = trace.source {
        entry.set("source", source);
    }
    if let Some(op) = trace.op {
        entry.set("op", op);
    }
    entry.set(
        "status",
        match status {
            Status::Pass => "pass",
            Status::Skipped(_) => "skipped",
            Status::Fail(_) => "fail",
        },
    );
    if let Some(actual) = trace.actual {
        let outcome = Rec::new();
        outcome.set("ok", actual.is_ok());
        if let Err(code) = actual {
            outcome.set("error", code);
        }
        entry.set("actual", outcome.value());
    }
    match status {
        Status::Pass => {}
        Status::Skipped(features) => entry.set("reason", format!("feature:{}", features.join(","))),
        Status::Fail(message) => entry.set("reason", message.as_str()),
    }
    entry.value()
}

/// Every vector of the index, checked and run.
#[derive(Default)]
struct Report {
    passed: usize,
    skipped: Vec<String>,
    failures: Vec<String>,
    results: Vec<JsValue>,
    /// The ADR 0060 digest of every file run, `None` for an empty corpus.
    digest: Option<String>,
}

fn run_all(enabled: &[&str]) -> Report {
    let schema =
        JSON::parse(SCHEMA).unwrap_or_else(|_| panic!("conformance/schema.json is not JSON"));
    let defs = get(&schema, "$defs").unwrap_or_else(|| Object::new().into());
    let mut report = Report::default();
    if vectors::VECTORS.is_empty() {
        report
            .failures
            .push("tests/vectors/mod.rs lists no vector files".to_owned());
    }
    for (path, text) in vectors::VECTORS {
        let mut trace = Trace::default();
        let status = run_vector(path, text, &defs, &schema, enabled, &mut trace);
        match &status {
            Status::Pass => report.passed += 1,
            Status::Skipped(features) => report.skipped.push(format!(
                "{path}: SKIPPED (needs feature {})",
                features.join(", ")
            )),
            Status::Fail(message) => report.failures.push(message.clone()),
        }
        // ADR 0034 §1, ADR 0045 §4: every file holds one vector.
        report
            .results
            .push(result_entry(&format!("{path}#0"), trace, &status));
    }
    // ADR 0060 §2: one line per file read, over the embedded bytes the run parsed (`text` is the
    // `include_str!` of the file, taken as bytes with no conversion), with its results-file id.
    let ids: Vec<String> = vectors::VECTORS
        .iter()
        .map(|(path, _)| format!("{path}#0"))
        .collect();
    report.digest = digest::vectors_digest(
        ids.iter()
            .zip(vectors::VECTORS)
            .map(|(id, (_, text))| (id.as_str(), text.as_bytes())),
    );
    report
}

/// The ADR 0034 §2 results document on one line: the runner, the adapter's `version()`, the
/// enabled features, its `errorCodes()` (ADR 0034 §8), one result per vector file and, once
/// [`EMIT_VECTORS_DIGEST`] is on, the ADR 0060 `vectors_digest`.
fn results_document(enabled: &[&str], results: Vec<JsValue>, digest: &str) -> String {
    let doc = Rec::new();
    doc.set("runner", common::RUNNER);
    doc.set("polyjose", util::version());
    doc.set(
        "features",
        array_of(enabled.iter().map(|f| JsValue::from_str(f)).collect()),
    );
    doc.set(
        "error_codes",
        array_of(
            util::error_codes()
                .into_iter()
                .map(|c| JsValue::from_str(&c))
                .collect(),
        ),
    );
    doc.set("results", array_of(results));
    if EMIT_VECTORS_DIGEST {
        doc.set("vectors_digest", digest);
    }
    stringify(&doc.value())
}

/// Every vector through the adapter: each schema-valid and passing, or skipped for a named
/// feature. The results line is printed before any assertion, so a failing run is recorded too.
#[wasm_bindgen_test]
fn conformance_vectors() {
    let agent = common::check_engine().unwrap_or_else(|e| panic!("{e}"));
    let enabled = enabled_features();
    let report = run_all(&enabled);
    let files = report.results.len();
    // ADR 0060 §3: a run that read no vector file fails and writes no results.
    let Some(digest) = report.digest else {
        panic!("no vector files were run (tests/vectors/mod.rs is empty): no results written");
    };
    assert_ne!(
        digest,
        digest::EMPTY_DIGEST,
        "the empty-input digest (ADR 0060 §3)"
    );
    console_log!(
        "{MARKER}{}",
        results_document(&enabled, report.results, &digest)
    );
    assert!(
        report.failures.is_empty(),
        "{} of {files} conformance vector file(s) failed through the WASM adapter ({}):\n  {}",
        report.failures.len(),
        common::RUNNER,
        report.failures.join("\n  ")
    );
    console_log!(
        "conformance ({}, {agent}): {} of {files} vectors passed; {} skipped; \
         vectors_digest {digest}",
        common::RUNNER,
        report.passed,
        report.skipped.len()
    );
    for line in &report.skipped {
        console_log!("  {line}");
    }
    assert_eq!(report.passed + report.skipped.len(), files);
}

// ---------------------------------------------------------------------------------------------
// The runner's own checks
// ---------------------------------------------------------------------------------------------

fn vector(operation: &str, input: &str, expect: &str, extra: &str) -> String {
    format!(
        r#"{{"source": "polyjose", "description": "a runner test", "operation": "{operation}", "input": {input}, "expect": {expect}{extra}}}"#
    )
}

fn status_of(json: &str, enabled: &[&str]) -> (Status, Trace) {
    let schema = JSON::parse(SCHEMA).unwrap();
    let defs = get(&schema, "$defs").unwrap();
    let mut trace = Trace::default();
    let status = run_vector("test.json", json, &defs, &schema, enabled, &mut trace);
    (status, trace)
}

fn assert_fails(json: &str, needle: &str) {
    match status_of(json, &[]).0 {
        Status::Fail(message) => assert!(
            message.contains(needle),
            "expected a failure mentioning {needle:?}, got: {message}"
        ),
        Status::Pass => panic!("expected a failure mentioning {needle:?}, but it passed: {json}"),
        Status::Skipped(f) => panic!("expected a failure, but it was skipped for {f:?}: {json}"),
    }
}

#[wasm_bindgen_test]
fn valid_vectors_pass_and_record_the_outcome() {
    // RFC 4648 §10: BASE64URL("foo") = "Zm9v".
    let (status, trace) = status_of(
        &vector(
            "b64url.encode",
            r#"{"bytes_hex": "666f6f"}"#,
            r#"{"ok": true, "b64u": "Zm9v"}"#,
            "",
        ),
        &[],
    );
    assert!(matches!(status, Status::Pass));
    assert_eq!(trace.actual, Some(Ok(())));
    // A library refusal is the outcome, compared by code (ADR 0030 §5).
    let (status, trace) = status_of(
        &vector(
            "b64url.decode",
            r#"{"b64u": "Zm9v="}"#,
            r#"{"ok": false, "error": "InvalidBase64"}"#,
            "",
        ),
        &[],
    );
    assert!(matches!(status, Status::Pass));
    assert_eq!(trace.actual, Some(Err("InvalidBase64".to_owned())));
}

#[wasm_bindgen_test]
fn broken_vectors_fail() {
    let ok = r#"{"ok": true, "b64u": "Zm9v"}"#;
    // Not JSON; a duplicate member (RFC 7493 §2.3); a schema violation; a misspelled member.
    assert_fails("{", "not a valid JSON text");
    assert_fails(
        &vector(
            "b64url.encode",
            r#"{"bytes_hex": "00", "bytes_hex": "666f6f"}"#,
            ok,
            "",
        ),
        "duplicate member names",
    );
    assert_fails(
        &vector("b64url.encode", r#"{"bytes_hex": "XYZ"}"#, ok, ""),
        "schema:",
    );
    assert_fails(
        &vector(
            "b64url.encode",
            r#"{"bytes_hex": "666f6f", "bytes_hexx": "00"}"#,
            ok,
            "",
        ),
        "unknown member",
    );
    // The wrong output, the wrong code, success where failure was expected.
    assert_fails(
        &vector(
            "b64url.encode",
            r#"{"bytes_hex": "666f6f"}"#,
            r#"{"ok": true, "b64u": "Zm9w"}"#,
            "",
        ),
        "`b64u`: expected",
    );
    assert_fails(
        &vector(
            "b64url.decode",
            r#"{"b64u": "Zm9v="}"#,
            r#"{"ok": false, "error": "InvalidFormat"}"#,
            "",
        ),
        "got error InvalidBase64",
    );
    // A vector whose base64url input is not canonical is broken, never an outcome.
    let (status, trace) = status_of(
        &vector(
            "jws.verify",
            r#"{"jws": "a.b.c", "key": {"kty": "oct", "k": "AAAA"}, "allowed_algs": ["HS256"], "detached_payload_b64u": "Zm9"}"#,
            r#"{"ok": false, "error": "InvalidFormat"}"#,
            "",
        ),
        &[],
    );
    assert!(matches!(status, Status::Fail(ref m) if m.contains("not canonical base64url")));
    assert_eq!(
        trace.actual, None,
        "a failed runner check records no actual"
    );
}

#[wasm_bindgen_test]
fn an_unmapped_operation_fails_and_is_never_skipped() {
    // An operation the schema doesn't know fails at the schema; this one is checked below it.
    let value = JSON::parse(&vector("b64url.reverse", "{}", r#"{"ok": true}"#, "")).unwrap();
    match execute(&value) {
        Err(message) => assert!(message.contains("not implemented by the WASM runner")),
        Ok(_) => panic!("an unmapped operation ran"),
    }
}

#[wasm_bindgen_test]
fn a_thrown_value_that_is_not_a_polyjose_error_fails_the_vector() {
    // A reader's TypeError (src/read.rs) is a harness failure, never an outcome (note 8).
    let thrown = jws::jws_verify_compact("a.b.c".to_owned(), "{}".to_owned(), &JsValue::NULL);
    match lib(thrown) {
        Err(Stop::Harness(message)) => assert!(message.contains("TypeError"), "{message}"),
        Err(Stop::Library(code)) => panic!("a TypeError became the outcome {code}"),
        Ok(_) => panic!("a null options record was accepted"),
    }
}

#[wasm_bindgen_test]
fn vectors_needing_a_disabled_feature_are_skipped_by_name() {
    let json = vector(
        "b64url.encode",
        r#"{"bytes_hex": "666f6f"}"#,
        r#"{"ok": true, "b64u": "Zm9v"}"#,
        r#", "features": ["deflate", "fixed-rng"]"#,
    );
    match status_of(&json, &["deflate"]).0 {
        Status::Skipped(missing) => assert_eq!(missing, vec!["fixed-rng".to_owned()]),
        _ => panic!("expected a skip for fixed-rng"),
    }
    assert!(matches!(
        status_of(&json, &["deflate", "fixed-rng"]).0,
        Status::Pass
    ));
}

#[wasm_bindgen_test]
fn vectors_forbidding_an_enabled_feature_are_skipped_by_name() {
    // ADR 0056 §2: each enabled `features_absent` name as `!<name>`, after the missing
    // `features`, in each list's order.
    let encode = |extra: &str| {
        vector(
            "b64url.encode",
            r#"{"bytes_hex": "666f6f"}"#,
            r#"{"ok": true, "b64u": "Zm9v"}"#,
            extra,
        )
    };
    let forbids = encode(r#", "features_absent": ["deflate", "fixed-rng"]"#);
    let (status, trace) = status_of(&forbids, &["deflate", "fixed-rng"]);
    assert!(matches!(&status, Status::Skipped(f) if f == &["!deflate", "!fixed-rng"]));
    let entry = result_entry("t.json#0", trace, &status);
    assert_eq!(
        get(&entry, "reason").and_then(|r| r.as_string()).as_deref(),
        Some("feature:!deflate,!fixed-rng")
    );
    assert!(get(&entry, "actual").is_none(), "a skip records no actual");
    let both = encode(r#", "features": ["fixed-rng"], "features_absent": ["deflate"]"#);
    match status_of(&both, &["deflate"]).0 {
        Status::Skipped(f) => assert_eq!(f, vec!["fixed-rng".to_owned(), "!deflate".to_owned()]),
        _ => panic!("expected a skip for fixed-rng and !deflate"),
    }
    // Absent features absent: the vector runs.
    assert!(matches!(status_of(&forbids, &[]).0, Status::Pass));
    // ADR 0056 §3: one name in both lists is broken, never a skip.
    assert_fails(
        &encode(r#", "features": ["deflate"], "features_absent": ["deflate"]"#),
        "is listed in `features` too",
    );
}

#[wasm_bindgen_test]
fn compress_needs_deflate_in_either_list() {
    // ADR 0056 §4, through the cross-member rule (the schema alone can't say it).
    let encrypt = |extra: &str| {
        vector(
            "jwe.encrypt",
            r#"{"serialization": "compact", "enc": "A128GCM", "plaintext_b64u": "", "recipients": [{"alg": "dir", "key": {"kty": "oct", "k": "AAECAwQFBgcICQoLDA0ODw"}}], "compress": true}"#,
            r#"{"ok": false, "error": "UnsupportedAlgorithm"}"#,
            extra,
        )
    };
    let value = JSON::parse(&encrypt("")).unwrap();
    assert!(cross_member_rules(&value).is_err_and(|e| e.contains("`features_absent`")));
    let absent = JSON::parse(&encrypt(r#", "features_absent": ["deflate"]"#)).unwrap();
    assert!(cross_member_rules(&absent).is_ok());
    let needed = JSON::parse(&encrypt(r#", "features": ["deflate"]"#)).unwrap();
    assert!(cross_member_rules(&needed).is_ok());
}

#[wasm_bindgen_test]
fn an_integer_like_member_name_fails_instead_of_being_reordered() {
    let input =
        r#"{"claims": {"sub": "a", "1": "b"}, "alg": "HS256", "key": {"kty": "oct", "k": "AAAA"}}"#;
    let value = JSON::parse(input).unwrap();
    assert!(
        matches!(json_arg(&value, "claims"), Err(Stop::Harness(m)) if m.contains("integer-like"))
    );
    assert!(json_arg(&value, "key").is_ok());
    assert!(is_array_index("0") && is_array_index("4294967294"));
    assert!(!is_array_index("01") && !is_array_index("4294967295") && !is_array_index("-1"));
}

#[wasm_bindgen_test]
fn the_results_document_names_this_runner_and_the_adapter_codes() {
    let some = "0".repeat(64);
    let doc = JSON::parse(&results_document(&[], Vec::new(), &some)).unwrap();
    assert_eq!(
        get(&doc, "vectors_digest").and_then(|d| d.as_string()),
        EMIT_VECTORS_DIGEST.then_some(some)
    );
    assert_eq!(
        get(&doc, "runner").and_then(|r| r.as_string()).as_deref(),
        Some(common::RUNNER)
    );
    let codes: Vec<String> = items(&get(&doc, "error_codes").unwrap())
        .iter()
        .filter_map(JsValue::as_string)
        .collect();
    assert_eq!(codes, util::error_codes());
    assert!(!codes.is_empty());
}

#[wasm_bindgen_test]
fn the_digest_of_the_adr_0060_worked_example_in_this_engine() {
    let (files, want) = digest::WORKED_EXAMPLE;
    let got = digest::vectors_digest(files.iter().map(|(id, bytes)| (*id, *bytes)));
    assert_eq!(got.as_deref(), Some(want));
    assert_eq!(digest::vectors_digest(std::iter::empty()), None);
}
