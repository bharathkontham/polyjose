//! Compact, deterministic serializer (RFC 8259).

use super::{Number, Object, Value};

impl Value {
    /// Serializes to compact JSON text (RFC 8259 §2), with no insignificant
    /// whitespace.
    ///
    /// The output depends only on the value, so it is deterministic:
    ///
    /// - members are written in the object's order (parse or insertion
    ///   order; see [`Object::sort_members`] for the RFC 7638 §3.3 order);
    /// - strings use minimal escaping (see below);
    /// - numbers use one canonical form (see below).
    ///
    /// **Strings** (RFC 8259 §7): only `"`, `\` and U+0000–U+001F are
    /// escaped, which is all RFC 8259 requires. They use the two-character
    /// forms `\"`, `\\`, `\b`, `\f`, `\n`, `\r` and `\t` where one exists,
    /// otherwise `\u00XX` with lowercase hex, as ECMAScript's
    /// `JSON.stringify` does. Everything else, including `/`, DEL and all
    /// non-ASCII characters, is written as UTF-8 (RFC 8259 §8.1).
    ///
    /// **Numbers** (RFC 8259 §6): an exact integer (see [`Number`]) is
    /// written in decimal, with no fraction or exponent; `-0`, and a value
    /// that underflowed to zero, is written as `0`. Other values use the
    /// shortest digits that parse back to the same double, in fixed notation
    /// when 10^-6 ≤ |v| < 10^21 and as `d.ddde±n` otherwise, the same text
    /// as ECMAScript's `Number.prototype.toString`. Parsing the output
    /// yields an equal value.
    ///
    /// ```
    /// use polyjose::json::parse;
    ///
    /// let v = parse(br#"{ "b": [1.0, 2.50, 1E21], "a": "\u00e9\n" }"#).unwrap();
    /// assert_eq!(v.to_json(), "{\"b\":[1,2.5,1e+21],\"a\":\"\u{e9}\\n\"}");
    /// ```
    ///
    /// **Secrets:** the output contains every string in the value, so for a
    /// private JWK it contains key material. It is a plain `String` and the
    /// caller owns wiping it: wrap it in `zeroize::Zeroizing` when the value
    /// holds secrets. The buffer is allocated once, at its exact final size
    /// (a counting pass runs first), so serializing leaves no stale partial
    /// copies in freed memory.
    pub fn to_json(&self) -> String {
        let mut size = Counter(0);
        write_value(&mut size, self);
        let mut out = String::with_capacity(size.0);
        write_value(&mut out, self);
        out
    }
}

impl Object {
    /// Serializes to compact JSON text, as [`Value::to_json`] does, with the
    /// same exact-size buffer and the same caller obligation for secrets.
    pub fn to_json(&self) -> String {
        let mut size = Counter(0);
        write_object(&mut size, self);
        let mut out = String::with_capacity(size.0);
        write_object(&mut out, self);
        out
    }
}

/// Where serialized text goes: the output, or a byte counter that sizes it.
trait Sink {
    fn push_str(&mut self, s: &str);

    fn push(&mut self, c: char) {
        self.push_str(c.encode_utf8(&mut [0; 4]));
    }
}

impl Sink for String {
    fn push_str(&mut self, s: &str) {
        String::push_str(self, s);
    }
}

/// Counts the bytes [`write_value`] would emit.
struct Counter(usize);

impl Sink for Counter {
    fn push_str(&mut self, s: &str) {
        self.0 = self.0.saturating_add(s.len());
    }
}

fn write_value(out: &mut impl Sink, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => write_number(out, *n),
        Value::String(s) => write_string(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item);
            }
            out.push(']');
        }
        Value::Object(o) => write_object(out, o),
    }
}

fn write_object(out: &mut impl Sink, object: &Object) {
    out.push('{');
    for (i, (name, value)) in object.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        write_string(out, name);
        out.push(':');
        write_value(out, value);
    }
    out.push('}');
}

fn write_string(out: &mut impl Sink, s: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0}'..='\u{1f}' => {
                let b = c as usize; // < 0x20
                out.push_str("\\u00");
                for nibble in [b >> 4, b & 0xf] {
                    out.push(char::from(HEX.get(nibble).copied().unwrap_or(b'0')));
                }
            }
            _ => out.push(c),
        }
    }
    out.push('"');
}

fn write_number(out: &mut impl Sink, n: Number) {
    if let Some(i) = n.as_i64() {
        out.push_str(&i.to_string());
        return;
    }
    // Rust's float formatting (with no precision given) emits the shortest
    // digits that round-trip. `Display` never uses an exponent; `LowerExp`
    // always does, without a `+`. A Number is finite and never -0.
    let v = n.as_f64();
    if v == 0.0 {
        out.push('0'); // a non-integer text that underflowed, like `1e-400`
    } else if (1e-6..1e21).contains(&v.abs()) {
        out.push_str(&v.to_string());
    } else {
        let s = format!("{v:e}");
        match s.split_once('e') {
            Some((mantissa, exp)) if !exp.starts_with('-') => {
                out.push_str(mantissa);
                out.push_str("e+");
                out.push_str(exp);
            }
            _ => out.push_str(&s),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::parse;

    fn num(v: f64) -> Value {
        Number::from_f64(v).map_or(Value::Null, Value::Number)
    }

    fn obj(members: &[(&str, Value)]) -> Object {
        let mut o = Object::new();
        for (n, v) in members {
            o.insert(*n, v.clone());
        }
        o
    }

    #[test]
    fn output_is_compact_and_keeps_member_order() {
        let v = Value::Array(vec![
            Value::Null,
            Value::Bool(true),
            Value::Bool(false),
            num(1.0),
            Value::from("s"),
            Value::Array(vec![]),
            Value::from(Object::new()),
            Value::from(obj(&[
                ("z", num(1.0)),
                ("a", Value::Array(vec![num(2.0), num(3.0)])),
            ])),
        ]);
        assert_eq!(
            v.to_json(),
            r#"[null,true,false,1,"s",[],{},{"z":1,"a":[2,3]}]"#
        );
    }

    #[test]
    fn strings_use_minimal_escaping() {
        let cases = [
            ("plain", r#""plain""#),
            ("\"", r#""\"""#),
            ("\\", r#""\\""#),
            ("/", r#""/""#),
            ("\u{8}\u{c}\n\r\t", r#""\b\f\n\r\t""#),
            ("\u{0}\u{1}\u{1f}", r#""\u0000\u0001\u001f""#),
            ("\u{b}\u{1b}", r#""\u000b\u001b""#),
            ("\u{7f}", "\"\u{7f}\""),
            (
                "\u{e9}\u{2028}\u{1f600}\u{fffe}",
                "\"\u{e9}\u{2028}\u{1f600}\u{fffe}\"",
            ),
            ("</script>", r#""</script>""#),
        ];
        for (s, json) in cases {
            assert_eq!(Value::from(s).to_json(), json, "{s:?}");
        }
        // Names are escaped the same way.
        assert_eq!(
            obj(&[("a\"b\n", Value::Null)]).to_json(),
            r#"{"a\"b\n":null}"#
        );
    }

    #[test]
    fn integers_are_written_as_integers() {
        for (v, json) in [
            (0.0, "0"),
            (-0.0, "0"),
            (7.0, "7"),
            (-7.0, "-7"),
            (9007199254740991.0, "9007199254740991"),
            (-9007199254740991.0, "-9007199254740991"),
        ] {
            assert_eq!(num(v).to_json(), json, "{v}");
        }
    }

    #[test]
    fn other_numbers_use_the_shortest_round_trip_form() {
        // The same text ECMAScript's Number.prototype.toString produces.
        for (v, json) in [
            (0.1, "0.1"),
            (-1.25, "-1.25"),
            (0.000001, "0.000001"),
            (1e-7, "1e-7"),
            (1.5e-7, "1.5e-7"),
            (9007199254740992.0, "9007199254740992"),
            (1.2345678901234568e20, "123456789012345680000"),
            (1e21, "1e+21"),
            (-1.5e300, "-1.5e+300"),
            (f64::MAX, "1.7976931348623157e+308"),
            (5e-324, "5e-324"),
            (f64::MIN_POSITIVE, "2.2250738585072014e-308"),
        ] {
            assert_eq!(num(v).to_json(), json, "{v:e}");
        }
    }

    #[test]
    fn non_integer_text_that_rounds_to_an_integer_writes_the_double() {
        // RFC 7493 §2.2: more precision than a double; the double is 1.
        let v = parse(b"1.00000000000000001").unwrap_or(Value::Null);
        assert_eq!(v.as_i64(), None);
        assert_eq!(v.to_json(), "1");
        assert_eq!(parse(b"1e-400").map(|v| v.to_json()), Ok("0".to_owned()));
    }

    #[test]
    fn output_round_trips_through_the_parser() {
        let inputs = [
            r#"{"a":[1,-2.5,1e300,5e-324,"x\u0000y",{"":null}],"b":true,"\u00e9":"\ud83d\ude00"}"#,
            r#"[0.30000000000000004,123456789.123,-1e-7,9007199254740993]"#,
            r#""\u001f\"\\\/\b\f\n\r\t""#,
        ];
        for input in inputs {
            let v = parse(input.as_bytes()).unwrap_or(Value::Null);
            assert!(!v.is_null(), "{input}");
            let written = v.to_json();
            assert_eq!(parse(written.as_bytes()), Ok(v), "{input}");
            // Writing is deterministic and a fixed point after one pass.
            let again = parse(written.as_bytes()).map(|v| v.to_json());
            assert_eq!(again, Ok(written));
        }
    }

    #[test]
    fn rfc7638_thumbprint_input_is_reproduced() {
        // RFC 7638 §3.1: the required RSA members, ordered lexicographically
        // (§3.3), with no whitespace.
        let n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
        let mut jwk = obj(&[
            ("n", Value::from(n)),
            ("e", Value::from("AQAB")),
            ("kty", Value::from("RSA")),
        ]);
        jwk.sort_members();
        assert_eq!(
            jwk.to_json(),
            format!(r#"{{"e":"AQAB","kty":"RSA","n":"{n}"}}"#)
        );
    }

    #[test]
    fn output_buffer_is_allocated_once_at_its_exact_size() {
        // The output may hold secrets (a private JWK), so it must not grow
        // through reallocations that leave freed copies behind.
        let inputs = [
            r#"{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}"#,
            r#"[1,-2.5,1e300,5e-324,true,null,"\u0000\n\"",{"":[]}]"#,
            r#""""#,
            "0",
        ];
        for input in inputs {
            let v = parse(input.as_bytes()).unwrap_or(Value::Null);
            let out = v.to_json();
            assert_eq!(out.capacity(), out.len(), "{input}");
        }
        let long = Value::from("x".repeat(10_000));
        let out = long.to_json();
        assert_eq!(out.capacity(), out.len());
    }
}
