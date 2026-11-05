//! Differential tests of `polyjose::json` against serde_json (a dev-only
//! test oracle, ADR 0016 §5).
//!
//! For every generated input:
//!
//! - if both parsers accept it, the values are equal, and our serialized
//!   output parses back (in both parsers) to the same value;
//! - if only polyjose rejects it, the rejection must be an I-JSON rule or a
//!   limit that serde_json does not enforce: a duplicate member name
//!   (RFC 7493 §2.3), nesting deeper than 32, more than 10 000 entries in a
//!   container, or more than 1 MiB of input. A probe deserializer checks the
//!   claimed reason against the input independently. (serde_json already
//!   rejects non-finite numbers.)
//! - polyjose never accepts input that serde_json rejects.
//!
//! Inputs are structured JSON (escapes, surrogates, Unicode, numbers around
//! 2^53 and the double range, random whitespace, duplicate-prone names),
//! deeply nested JSON, mutated JSON, JSON-alphabet soup and arbitrary bytes.

use polyjose::Error;
use polyjose::json::{Limits, MAX_SAFE_INTEGER, Value, parse};
use proptest::prelude::*;
use proptest::sample::{Index, select};
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// Oracle helpers
// ---------------------------------------------------------------------------

/// Whether our value equals serde_json's.
fn same(ours: &Value, theirs: &serde_json::Value) -> bool {
    use serde_json::Value as J;
    match (ours, theirs) {
        (Value::Null, J::Null) => true,
        (Value::Bool(a), J::Bool(b)) => a == b,
        (Value::String(a), J::String(b)) => a == b,
        (Value::Number(a), J::Number(b)) => {
            let doubles_equal = b.as_f64() == Some(a.as_f64());
            // An integer serde_json read exactly, within the I-JSON range,
            // must be an exact integer for us too (RFC 7493 §2.2).
            let safe = |i: i64| i.unsigned_abs() <= MAX_SAFE_INTEGER.unsigned_abs();
            let int_ok = match (b.as_i64(), b.as_u64()) {
                (Some(i), _) if safe(i) => a.as_i64() == Some(i),
                _ => true,
            };
            doubles_equal && int_ok
        }
        (Value::Array(a), J::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(x, y)| same(x, y))
        }
        (Value::Object(a), J::Object(b)) => {
            a.len() == b.len() && a.iter().all(|(k, v)| b.get(k).is_some_and(|w| same(v, w)))
        }
        _ => false,
    }
}

/// What a probe deserializer sees in a text that serde_json accepts.
#[derive(Debug, Default)]
struct Shape {
    /// Nesting depth: 0 for a scalar.
    depth: usize,
    /// Largest number of entries in one container.
    max_entries: usize,
    /// Whether some object repeats a member name (after unescaping).
    duplicate: bool,
}

impl Shape {
    fn absorb(&mut self, child: &Shape) {
        self.depth = self.depth.max(child.depth + 1);
        self.max_entries = self.max_entries.max(child.max_entries);
        self.duplicate |= child.duplicate;
    }
}

impl<'de> Deserialize<'de> for Shape {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Shape, D::Error> {
        d.deserialize_any(ShapeVisitor)
    }
}

struct ShapeVisitor;

impl<'de> Visitor<'de> for ShapeVisitor {
    type Value = Shape;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("any JSON value")
    }
    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Shape, E> {
        Ok(Shape::default())
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<Shape, E> {
        Ok(Shape::default())
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<Shape, E> {
        Ok(Shape::default())
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Shape, E> {
        Ok(Shape::default())
    }
    fn visit_str<E: de::Error>(self, _: &str) -> Result<Shape, E> {
        Ok(Shape::default())
    }
    fn visit_unit<E: de::Error>(self) -> Result<Shape, E> {
        Ok(Shape::default())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Shape, A::Error> {
        let mut shape = Shape {
            depth: 1,
            ..Shape::default()
        };
        let mut n = 0;
        while let Some(child) = seq.next_element::<Shape>()? {
            n += 1;
            shape.absorb(&child);
        }
        shape.max_entries = shape.max_entries.max(n);
        Ok(shape)
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Shape, A::Error> {
        let mut shape = Shape {
            depth: 1,
            ..Shape::default()
        };
        let mut names = BTreeSet::new();
        while let Some(name) = map.next_key::<String>()? {
            shape.duplicate |= !names.insert(name);
            let child = map.next_value::<Shape>()?;
            shape.absorb(&child);
        }
        shape.max_entries = shape.max_entries.max(names.len());
        Ok(shape)
    }
}

fn lossy(input: &[u8]) -> String {
    String::from_utf8_lossy(input).into_owned()
}

/// The differential property for one input.
fn check(input: &[u8]) -> Result<(), TestCaseError> {
    let ours = parse(input);
    let theirs = serde_json::from_slice::<serde_json::Value>(input);
    match (&ours, &theirs) {
        (Ok(a), Ok(b)) => {
            prop_assert!(
                same(a, b),
                "values differ for {:?}: {a:?} vs {b:?}",
                lossy(input)
            );
            let written = a.to_json();
            let reparsed = parse(written.as_bytes());
            prop_assert_eq!(reparsed.as_ref(), Ok(a), "round trip of {}", written);
            // Compare serde_json's reading of our output with our own reading
            // of it: a text with more precision than a double, such as
            // 9007199254740990.6, is not an exact integer, but it is written
            // as the integer double it rounds to (see json::Number).
            let back = serde_json::from_str::<serde_json::Value>(&written);
            prop_assert!(
                back.as_ref()
                    .is_ok_and(|b| reparsed.as_ref().is_ok_and(|r| same(r, b))),
                "serde_json reads our output {written:?} as {back:?}"
            );
        }
        (Ok(a), Err(e)) => {
            prop_assert!(
                false,
                "accepted {:?} as {a:?}; serde_json: {e}",
                lossy(input)
            );
        }
        (Err(e), Ok(_)) => {
            let shape: Shape = serde_json::from_slice(input)
                .map_err(|e| TestCaseError::fail(format!("probe failed: {e}")))?;
            let limits = Limits::DEFAULT;
            let justified = match e {
                Error::InvalidJson("duplicate member name") => shape.duplicate,
                Error::InvalidJson("nesting too deep") => shape.depth > limits.max_depth,
                Error::InvalidJson("too many members or elements") => {
                    shape.max_entries > limits.max_entries
                }
                Error::InvalidJson("input too large") => input.len() > limits.max_input_len,
                _ => false,
            };
            prop_assert!(
                justified,
                "rejected {:?} with {e:?}; probe: {shape:?}",
                lossy(input)
            );
        }
        (Err(e), Err(_)) => prop_assert_eq!(e.code(), "InvalidJson"),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

fn ws() -> impl Strategy<Value = &'static str> {
    select(vec!["", "", "", "", " ", "\n", "\t", "\r\n", "  "])
}

fn digits(range: std::ops::Range<usize>) -> impl Strategy<Value = String> {
    prop::collection::vec(0u8..=9, range)
        .prop_map(|d| d.iter().map(|d| char::from(b'0' + d)).collect())
}

/// Grammar-valid number lexemes, weighted towards the interesting edges.
fn number() -> BoxedStrategy<String> {
    let boundary = select(vec![
        "9007199254740991",
        "-9007199254740991",
        "9007199254740992",
        "-9007199254740992",
        "9007199254740993",
        "9007199254740991.0",
        "9007199254740990.6",
        "9.007199254740991e15",
        "90071992547409910e-1",
        "1e16",
        "18446744073709551615",
        "18446744073709551616",
        "-9223372036854775808",
        "-9223372036854775809",
        "0",
        "-0",
        "-0.0",
        "0e0",
        "0.0e-999",
        "1e308",
        "1.7976931348623157e308",
        "1.7976931348623158e308",
        "1.7976931348623159e308",
        "2e308",
        "-1e400",
        "1e-400",
        "5e-324",
        "2.4703282292062327e-324",
        "2.4703282292062328e-324",
        "1.00000000000000001",
        "0.1",
        "1E2",
        "1e+2",
        "1e-2",
        "123456789012345678901234567890",
    ])
    .prop_map(String::from);
    let int_part = prop_oneof![
        Just("0".to_owned()),
        (1u8..=9, digits(0..20)).prop_map(|(first, rest)| format!("{first}{rest}")),
    ];
    let exp = (
        select(vec!["e", "E"]),
        select(vec!["", "+", "-"]),
        digits(1..5),
    )
        .prop_map(|(e, sign, d)| format!("{e}{sign}{d}"));
    let general = (
        any::<bool>(),
        int_part,
        prop::option::of(digits(1..20)),
        prop::option::of(exp),
    )
        .prop_map(|(neg, int, frac, exp)| {
            let sign = if neg { "-" } else { "" };
            let frac = frac.map(|f| format!(".{f}")).unwrap_or_default();
            format!("{sign}{int}{frac}{}", exp.unwrap_or_default())
        });
    prop_oneof![1 => boundary, 2 => general].boxed()
}

/// `\u` followed by four hex digits of `unit`, built at run time.
fn u_escape(unit: u16, upper: bool) -> String {
    if upper {
        format!("\\u{unit:04X}")
    } else {
        format!("\\u{unit:04x}")
    }
}

/// String literals mixing raw Unicode, every escape form, valid and lone
/// surrogates, and the occasional raw control character.
fn string_literal() -> BoxedStrategy<String> {
    let piece = prop_oneof![
        6 => any::<char>()
            .prop_filter("unescaped", |c| *c != '"' && *c != '\\' && *c >= ' ')
            .prop_map(String::from),
        2 => select(vec!["\\\"", "\\\\", "\\/", "\\b", "\\f", "\\n", "\\r", "\\t"]).prop_map(String::from),
        2 => (any::<u16>(), any::<bool>()).prop_map(|(u, up)| u_escape(u, up)),
        1 => (0xD800u16..0xDC00, 0xDC00u16..0xE000, any::<bool>())
            .prop_map(|(h, l, up)| format!("{}{}", u_escape(h, up), u_escape(l, !up))),
        1 => select(vec!["\u{0}", "\u{1f}", "\u{7f}", "\u{feff}", "\u{fffe}", "\u{10fffe}", "\\x", "\\u12"])
            .prop_map(String::from),
    ];
    prop::collection::vec(piece, 0..8)
        .prop_map(|p| format!("\"{}\"", p.concat()))
        .boxed()
}

/// Member names drawn mostly from a tiny set, so duplicates (including
/// escaped spellings of the same name) are common.
fn member_name() -> BoxedStrategy<String> {
    let small = select(vec![
        "\"a\"".to_owned(),
        "\"b\"".to_owned(),
        "\"A\"".to_owned(),
        "\"\"".to_owned(),
        format!("\"{}\"", u_escape(0x61, false)),
        format!("\"{}\"", u_escape(0xe9, true)),
        "\"\u{e9}\"".to_owned(),
        "\"e\u{301}\"".to_owned(),
        "\"\\/\"".to_owned(),
        "\"/\"".to_owned(),
    ]);
    prop_oneof![3 => small, 1 => string_literal()].boxed()
}

fn json_text() -> BoxedStrategy<String> {
    let leaf = prop_oneof![
        Just("null".to_owned()),
        Just("true".to_owned()),
        Just("false".to_owned()),
        number(),
        string_literal(),
    ];
    let value = leaf.prop_recursive(5, 64, 6, |inner| {
        prop_oneof![
            prop::collection::vec((ws(), inner.clone(), ws()), 0..6).prop_map(|items| {
                let items: Vec<String> =
                    items.iter().map(|(a, v, b)| format!("{a}{v}{b}")).collect();
                format!("[{}]", items.join(","))
            }),
            prop::collection::vec((ws(), member_name(), ws(), ws(), inner, ws()), 0..6).prop_map(
                |members| {
                    let members: Vec<String> = members
                        .iter()
                        .map(|(a, k, b, c, v, d)| format!("{a}{k}{b}:{c}{v}{d}"))
                        .collect();
                    format!("{{{}}}", members.join(","))
                }
            ),
        ]
    });
    (ws(), value, ws())
        .prop_map(|(a, v, b)| format!("{a}{v}{b}"))
        .boxed()
}

/// Nesting around the depth limit (25 to 40 levels of arrays and objects).
fn deep_text() -> impl Strategy<Value = String> {
    prop::collection::vec(any::<bool>(), 25..=40).prop_map(|kinds| {
        let open: String = kinds
            .iter()
            .map(|&arr| if arr { "[" } else { "{\"k\":" })
            .collect();
        let close: String = kinds
            .iter()
            .rev()
            .map(|&arr| if arr { "]" } else { "}" })
            .collect();
        format!("{open}1{close}")
    })
}

const ALPHABET: &[u8] = b"{}[],:\"\\ \n0123456789.eE+-truefalsnu/bfrtx";

/// Valid JSON with a few bytes inserted, deleted or replaced.
fn mutated_text() -> impl Strategy<Value = Vec<u8>> {
    let edit = (
        any::<Index>(),
        0u8..3,
        any::<bool>(),
        any::<u8>(),
        any::<Index>(),
    );
    (json_text(), prop::collection::vec(edit, 1..4)).prop_map(|(text, edits)| {
        let mut bytes = text.into_bytes();
        for (at, op, from_alphabet, raw, pick) in edits {
            let byte = if from_alphabet {
                *pick.get(ALPHABET)
            } else {
                raw
            };
            let len = bytes.len();
            match op {
                0 => bytes.insert(at.index(len + 1), byte),
                1 if len > 0 => {
                    bytes.remove(at.index(len));
                }
                _ if len > 0 => bytes[at.index(len)] = byte,
                _ => bytes.push(byte),
            }
        }
        bytes
    })
}

fn alphabet_soup() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(select(ALPHABET.to_vec()), 0..40)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    #[test]
    fn structured_json_agrees_with_serde_json(text in json_text()) {
        check(text.as_bytes())?;
    }

    #[test]
    fn deep_nesting_agrees_with_serde_json(text in deep_text()) {
        check(text.as_bytes())?;
    }

    #[test]
    fn mutated_json_agrees_with_serde_json(bytes in mutated_text()) {
        check(&bytes)?;
    }

    #[test]
    fn json_alphabet_soup_agrees_with_serde_json(bytes in alphabet_soup()) {
        check(&bytes)?;
    }

    #[test]
    fn arbitrary_bytes_agree_with_serde_json(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
        check(&bytes)?;
    }
}

#[test]
fn boundary_numbers_agree_with_serde_json() {
    // Every number edge case, deterministically (the generator only samples).
    for n in [
        "9007199254740991",
        "9007199254740992",
        "-9007199254740993",
        "9007199254740990.6",
        "1.7976931348623158e308",
        "1.7976931348623159e308",
        "2.4703282292062327e-324",
        "2.4703282292062328e-324",
        "1e-400",
        "-0",
        "1.00000000000000001",
    ] {
        let text = format!("[{n}]");
        check(text.as_bytes()).unwrap_or_else(|e| unreachable!("{n}: {e}"));
    }
}

#[test]
fn rejections_beyond_serde_json_are_justified() {
    // Self-test of the oracle: each of these is valid for serde_json and
    // rejected by polyjose for an I-JSON rule or a limit.
    let wide = format!("[{}]", vec!["0"; 10_001].join(","));
    let deep = format!("{}{}", "[".repeat(33), "]".repeat(33));
    let large = format!("\"{}\"", "a".repeat(1024 * 1024));
    let escaped_dup = format!("{{\"a\":1,\"{}\":2}}", u_escape(0x61, false));
    for text in [
        r#"{"a":1,"a":2}"#,
        escaped_dup.as_str(),
        &wide,
        &deep,
        &large,
    ] {
        assert!(serde_json::from_str::<serde_json::Value>(text).is_ok());
        assert!(parse(text.as_bytes()).is_err());
        check(text.as_bytes()).unwrap_or_else(|e| unreachable!("{e}"));
    }
}
