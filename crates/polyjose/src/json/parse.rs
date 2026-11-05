//! Strict RFC 8259 parser with the I-JSON constraints of RFC 7493.

use super::{Number, Object, Value};
use crate::{Error, Result};
use zeroize::Zeroizing;

const EOF: Error = Error::InvalidJson("unexpected end of input");
const UNEXPECTED: Error = Error::InvalidJson("unexpected character");
const NOT_UTF8: Error = Error::InvalidJson("invalid UTF-8");
const TRAILING: Error = Error::InvalidJson("trailing content after the value");
const BAD_NUMBER: Error = Error::InvalidJson("invalid number");
const BAD_ESCAPE: Error = Error::InvalidJson("invalid escape");
const LONE_SURROGATE: Error = Error::InvalidJson("lone surrogate escape");
const CONTROL_CHAR: Error = Error::InvalidJson("unescaped control character in string");
const BOM: Error = Error::InvalidJson("byte order mark");
const DUPLICATE: Error = Error::InvalidJson("duplicate member name");
const TOO_DEEP: Error = Error::InvalidJson("nesting too deep");
const TOO_LARGE: Error = Error::InvalidJson("input too large");
const TOO_MANY: Error = Error::InvalidJson("too many members or elements");

/// Resource limits for [`parse_with_limits`].
///
/// JOSE parses untrusted headers, claims and keys, so every limit fails
/// closed with [`Error::InvalidJson`]. RFC 8259 §9 lets a parser limit the
/// size of texts, the nesting depth and other values; these defaults are
/// far above what any JOSE object needs:
///
/// | limit | default | bounds |
/// |---|---|---|
/// | [`max_depth`](Limits::max_depth) | 32 | recursion depth |
/// | [`max_input_len`](Limits::max_input_len) | 1 MiB | work and memory per call |
/// | [`max_entries`](Limits::max_entries) | 10 000 | members of one object, elements of one array |
///
/// Start from [`Limits::default`] and change a field:
///
/// ```
/// use polyjose::json::{parse_with_limits, Limits};
///
/// let mut limits = Limits::default();
/// limits.max_depth = 2;
/// assert!(parse_with_limits(b"[[1]]", &limits).is_ok());
/// assert!(parse_with_limits(b"[[[1]]]", &limits).is_err());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Limits {
    /// Maximum nesting of arrays and objects. A scalar has depth 0, `[]`
    /// depth 1 and `[{}]` depth 2. Values above
    /// [`MAX_DEPTH_CEILING`](Limits::MAX_DEPTH_CEILING) act as the ceiling.
    pub max_depth: usize,
    /// Maximum input length in bytes, checked before anything else.
    pub max_input_len: usize,
    /// Maximum number of members in any one object, or elements in any one
    /// array. With `max_input_len` it bounds the per-object duplicate-name
    /// check and keeps container sizes predictable for callers.
    pub max_entries: usize,
}

impl Limits {
    /// The default limits: depth 32, 1 MiB of input, 10 000 entries per
    /// container.
    pub const DEFAULT: Limits = Limits {
        max_depth: 32,
        max_input_len: 1024 * 1024,
        max_entries: 10_000,
    };

    /// Hard cap on [`max_depth`](Limits::max_depth).
    ///
    /// The parser recurses once per level, and so do `Drop`, `Clone`,
    /// equality and serialization of the resulting [`Value`], so the depth
    /// must stay small enough for any thread's stack, including WASM's.
    pub const MAX_DEPTH_CEILING: usize = 128;
}

impl Default for Limits {
    fn default() -> Limits {
        Limits::DEFAULT
    }
}

/// Parses one JSON text (RFC 8259 §2) into a [`Value`], with the default
/// [`Limits`].
///
/// The rules are listed in the [module docs](crate::json). Any failure is
/// [`Error::InvalidJson`] with a fixed detail and no input bytes.
///
/// ```
/// use polyjose::{json::parse, Error};
///
/// let v = parse(br#" [1, {"a": null}] "#).unwrap();
/// assert_eq!(v.to_json(), r#"[1,{"a":null}]"#);
///
/// assert_eq!(parse(b"[1,]"), Err(Error::InvalidJson("unexpected character")));
/// assert_eq!(parse(b"{} {}"), Err(Error::InvalidJson("trailing content after the value")));
/// ```
pub fn parse(input: &[u8]) -> Result<Value> {
    parse_with_limits(input, &Limits::DEFAULT)
}

/// Parses one JSON text (RFC 8259 §2) into a [`Value`], within `limits`.
pub fn parse_with_limits(input: &[u8], limits: &Limits) -> Result<Value> {
    if input.len() > limits.max_input_len {
        return Err(TOO_LARGE);
    }
    // RFC 8259 §8.1: JSON exchanged between systems MUST be UTF-8, and
    // I-JSON messages MUST be UTF-8 (RFC 7493 §2.1). `from_utf8` rejects
    // overlong forms, encoded surrogates and code points above U+10FFFF.
    let text = core::str::from_utf8(input).map_err(|_| NOT_UTF8)?;
    // RFC 8259 §8.1: senders MUST NOT add a byte order mark; parsers MAY
    // ignore one. polyjose rejects it: a JOSE Header is exactly the octets
    // that were signed (RFC 7515 §5.2), and accepting U+FEFF would give the
    // same object two encodings. It is the clearest error to report, since
    // U+FEFF is not JSON whitespace either.
    if text.starts_with('\u{feff}') {
        return Err(BOM);
    }
    let mut parser = Parser {
        text,
        bytes: text.as_bytes(),
        pos: 0,
        max_depth: limits.max_depth.min(Limits::MAX_DEPTH_CEILING),
        max_entries: limits.max_entries,
    };
    parser.skip_ws();
    let value = parser.value(0)?;
    parser.skip_ws();
    // RFC 8259 §2: JSON-text = ws value ws, and nothing else.
    if parser.pos != parser.bytes.len() {
        return Err(TRAILING);
    }
    Ok(value)
}

struct Parser<'a> {
    text: &'a str,
    bytes: &'a [u8],
    /// Always at a char boundary of `text`, and `<= bytes.len()`.
    pos: usize,
    /// At most [`Limits::MAX_DEPTH_CEILING`].
    max_depth: usize,
    max_entries: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    /// Consumes `b` if it is next.
    fn eat(&mut self, b: u8) -> bool {
        let found = self.peek() == Some(b);
        if found {
            self.pos += 1;
        }
        found
    }

    /// Consumes `b`, or fails.
    fn expect(&mut self, b: u8) -> Result<()> {
        match self.peek() {
            Some(c) if c == b => {
                self.pos += 1;
                Ok(())
            }
            Some(_) => Err(UNEXPECTED),
            None => Err(EOF),
        }
    }

    /// RFC 8259 §2: `ws = *( %x20 / %x09 / %x0A / %x0D )`.
    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    /// RFC 8259 §3: `value = false / null / true / object / array / number
    /// / string`. `depth` is the number of enclosing arrays and objects.
    fn value(&mut self, depth: usize) -> Result<Value> {
        match self.peek() {
            None => Err(EOF),
            Some(b'{') => self.object(depth + 1).map(Value::Object),
            Some(b'[') => self.array(depth + 1).map(Value::Array),
            Some(b'"') => self.string().map(Value::String),
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            Some(b'n') => self.literal("null", Value::Null),
            Some(b'-' | b'0'..=b'9') => self.number().map(Value::Number),
            Some(_) => Err(UNEXPECTED),
        }
    }

    /// RFC 8259 §3: the literal names are lowercase and exact.
    fn literal(&mut self, name: &str, value: Value) -> Result<Value> {
        let rest = self.bytes.get(self.pos..).unwrap_or_default();
        if rest.starts_with(name.as_bytes()) {
            self.pos += name.len();
            Ok(value)
        } else if name.as_bytes().starts_with(rest) {
            Err(EOF)
        } else {
            Err(UNEXPECTED)
        }
    }

    /// Opens a container at `depth`. The recursion is bounded by
    /// `max_depth` (itself capped), so hostile nesting cannot exhaust the
    /// stack.
    fn enter(&self, depth: usize) -> Result<()> {
        if depth > self.max_depth {
            Err(TOO_DEEP)
        } else {
            Ok(())
        }
    }

    /// RFC 8259 §5: `array = [ value *( , value ) ]` with insignificant
    /// whitespace; no trailing comma.
    fn array(&mut self, depth: usize) -> Result<Vec<Value>> {
        self.enter(depth)?;
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.eat(b']') {
            return Ok(items);
        }
        loop {
            self.skip_ws();
            if items.len() >= self.max_entries {
                return Err(TOO_MANY);
            }
            items.push(self.value(depth)?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(items);
                }
                Some(_) => return Err(UNEXPECTED),
                None => return Err(EOF),
            }
        }
    }

    /// RFC 8259 §4: `object = { member *( , member ) }`,
    /// `member = string : value`; no trailing comma.
    ///
    /// Duplicate member names are rejected (see [`unique`]).
    fn object(&mut self, depth: usize) -> Result<Object> {
        self.enter(depth)?;
        self.expect(b'{')?;
        let mut members = Vec::new();
        self.skip_ws();
        if self.eat(b'}') {
            return Ok(Object::from_unique_members(members));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(if self.peek().is_none() {
                    EOF
                } else {
                    UNEXPECTED
                });
            }
            if members.len() >= self.max_entries {
                return Err(TOO_MANY);
            }
            let name = self.string()?;
            self.skip_ws();
            self.expect(b':')?;
            self.skip_ws();
            let value = self.value(depth)?;
            members.push((name, value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return unique(members).map(Object::from_unique_members);
                }
                Some(_) => return Err(UNEXPECTED),
                None => return Err(EOF),
            }
        }
    }

    /// RFC 8259 §7: a quoted string. Unescaped characters are any code
    /// point except `"`, `\` and the controls U+0000–U+001F.
    ///
    /// The string may be key material (a JWK `d` or `k`), so it is built in
    /// a [`Zeroizing`] buffer: on any error the partial string is wiped as
    /// it is dropped.
    fn string(&mut self) -> Result<Zeroizing<String>> {
        self.expect(b'"')?;
        let mut out = Zeroizing::new(String::new());
        loop {
            let start = self.pos;
            // Bytes >= 0x80 belong to multi-byte UTF-8 sequences, whose bytes
            // are all >= 0x80, so this stops only at ASCII and every slice
            // boundary is a char boundary.
            while matches!(self.peek(), Some(b) if b >= 0x20 && b != b'"' && b != b'\\') {
                self.pos += 1;
            }
            out.push_str(self.text.get(start..self.pos).ok_or(NOT_UTF8)?);
            match self.peek() {
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.pos += 1;
                    out.push(self.escape()?);
                }
                Some(_) => return Err(CONTROL_CHAR),
                None => return Err(EOF),
            }
        }
    }

    /// RFC 8259 §7: the character after a `\`.
    fn escape(&mut self) -> Result<char> {
        let c = match self.peek() {
            None => return Err(EOF),
            Some(b'"') => '"',
            Some(b'\\') => '\\',
            Some(b'/') => '/',
            Some(b'b') => '\u{8}',
            Some(b'f') => '\u{c}',
            Some(b'n') => '\n',
            Some(b'r') => '\r',
            Some(b't') => '\t',
            Some(b'u') => {
                self.pos += 1;
                return self.unicode_escape();
            }
            Some(_) => return Err(BAD_ESCAPE),
        };
        self.pos += 1;
        Ok(c)
    }

    /// RFC 8259 §7: `\uXXXX`, where a code point above the BMP is a UTF-16
    /// surrogate pair `\uD8xx\uDCxx`. A lone or reversed surrogate is not a
    /// Unicode scalar value, and I-JSON forbids it (RFC 7493 §2.1).
    fn unicode_escape(&mut self) -> Result<char> {
        let first = self.hex4()?;
        let code = match first {
            0xD800..=0xDBFF => {
                if !(self.eat(b'\\') && self.eat(b'u')) {
                    return Err(LONE_SURROGATE);
                }
                let second = self.hex4()?;
                if !(0xDC00..=0xDFFF).contains(&second) {
                    return Err(LONE_SURROGATE);
                }
                0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
            }
            0xDC00..=0xDFFF => return Err(LONE_SURROGATE),
            _ => first,
        };
        char::from_u32(code).ok_or(LONE_SURROGATE)
    }

    /// Four hex digits, either case (RFC 8259 §7, RFC 5234 `HEXDIG`).
    fn hex4(&mut self) -> Result<u32> {
        let mut code = 0;
        for _ in 0..4 {
            let digit = match self.peek() {
                None => return Err(EOF),
                Some(b) => char::from(b).to_digit(16).ok_or(BAD_ESCAPE)?,
            };
            code = code * 16 + digit;
            self.pos += 1;
        }
        Ok(code)
    }

    /// RFC 8259 §6: `number = [ minus ] int [ frac ] [ exp ]` where
    /// `int = zero / ( digit1-9 *DIGIT )`, `frac = . 1*DIGIT` and
    /// `exp = e [ minus / plus ] 1*DIGIT`. Leading zeros, a leading `+`,
    /// a bare `.` and `Infinity`/`NaN` are not numbers.
    fn number(&mut self) -> Result<Number> {
        let start = self.pos;
        self.eat(b'-');
        match self.peek() {
            Some(b'0') => {
                self.pos += 1;
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err(BAD_NUMBER); // leading zero
                }
            }
            Some(b'1'..=b'9') => self.digits(),
            _ => return Err(BAD_NUMBER),
        }
        if self.eat(b'.') {
            self.digits1()?;
        }
        if self.eat(b'e') || self.eat(b'E') {
            if !self.eat(b'+') {
                self.eat(b'-');
            }
            self.digits1()?;
        }
        Number::from_lexeme(self.text.get(start..self.pos).ok_or(BAD_NUMBER)?)
    }

    fn digits(&mut self) {
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
    }

    /// `1*DIGIT`.
    fn digits1(&mut self) -> Result<()> {
        let start = self.pos;
        self.digits();
        if self.pos == start {
            Err(BAD_NUMBER)
        } else {
            Ok(())
        }
    }
}

/// An object's members while parsing. Names are [`Zeroizing`] and values
/// wipe their strings, so dropping a partial object on an error path, or
/// the old buffer when the `Vec` grows (which holds only pointers, lengths
/// and non-secret scalars), leaves no string contents behind.
type Members = Vec<(Zeroizing<String>, Value)>;

/// Rejects an object with two members of the same name.
///
/// RFC 8259 §4 only says names SHOULD be unique, but JOSE requires either
/// rejecting duplicates or using a parser that returns the last one
/// (RFC 7515 §5.2 step 4, RFC 7516 §5.2 step 4), and I-JSON objects MUST
/// NOT have duplicate names (RFC 7493 §2.3). Picking one silently lets two
/// parsers read different headers from the same bytes, so polyjose rejects,
/// at every nesting level.
///
/// Names are compared after unescaping, so `"a"` and `"\u0061"` are the
/// same name, and code point by code point (RFC 8259 §8.3), so `"a"` and
/// `"A"`, or precomposed and decomposed `"é"`, are different. Sorting keeps
/// the check O(n log n) for large objects.
fn unique(members: Members) -> Result<Members> {
    let mut names: Vec<&str> = members.iter().map(|(n, _)| n.as_str()).collect();
    names.sort_unstable();
    if names.windows(2).any(|w| matches!(w, [a, b] if a == b)) {
        return Err(DUPLICATE);
    }
    Ok(members)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(input: &str) -> Value {
        parse(input.as_bytes()).unwrap_or_else(|e| unreachable!("{input:?}: {e}"))
    }

    fn err(input: &[u8]) -> Error {
        match parse(input) {
            Ok(v) => unreachable!("{:?} parsed as {v:?}", String::from_utf8_lossy(input)),
            Err(e) => e,
        }
    }

    fn num(v: f64) -> Value {
        Number::from_f64(v).map_or(Value::Null, Value::Number)
    }

    #[test]
    fn parses_every_value_kind() {
        assert_eq!(ok("null"), Value::Null);
        assert_eq!(ok("true"), Value::Bool(true));
        assert_eq!(ok("false"), Value::Bool(false));
        assert_eq!(ok("0"), num(0.0));
        assert_eq!(ok("-12.5e-1"), num(-1.25));
        assert_eq!(ok(r#""hi""#), Value::from("hi"));
        assert_eq!(ok("[]"), Value::Array(vec![]));
        assert_eq!(ok("{}"), Value::Object(Object::new()));
        assert_eq!(
            ok(r#"[1,"a",[true],{"k":null}]"#),
            Value::Array(vec![
                num(1.0),
                Value::from("a"),
                Value::Array(vec![Value::Bool(true)]),
                Value::Object({
                    let mut o = Object::new();
                    o.insert("k", Value::Null);
                    o
                }),
            ])
        );
    }

    #[test]
    fn objects_keep_member_order() {
        let v = ok(r#"{"z":1,"a":2,"m":3}"#);
        let names: Vec<&str> = v
            .as_object()
            .map_or(vec![], |o| o.iter().map(|(n, _)| n).collect());
        assert_eq!(names, ["z", "a", "m"]);
    }

    #[test]
    fn insignificant_whitespace_is_the_four_rfc_characters() {
        assert_eq!(ok(" \t\r\n[ 1 ,\n2 ] \r\n"), ok("[1,2]"));
        assert_eq!(ok("{ \"a\" : 1 }"), ok(r#"{"a":1}"#));
        // Form feed, vertical tab, NBSP and U+2028 are not JSON whitespace.
        for ws in ["\u{c}", "\u{b}", "\u{a0}", "\u{2028}"] {
            assert_eq!(err(format!("[{ws}1]").as_bytes()), UNEXPECTED, "{ws:?}");
        }
        assert_eq!(err(b""), EOF);
        assert_eq!(err(b"  "), EOF);
    }

    #[test]
    fn string_escapes_are_decoded() {
        assert_eq!(
            ok(r#""\"\\\/\b\f\n\r\t""#),
            Value::from("\"\\/\u{8}\u{c}\n\r\t")
        );
        assert_eq!(
            ok(r#""\u0041\u00e9\u00E9\u20AC""#),
            Value::from("A\u{e9}\u{e9}\u{20ac}")
        );
        assert_eq!(ok(r#""\u0000""#), Value::from("\u{0}"));
        assert_eq!(ok(r#""\ud834\udd1e""#), Value::from("\u{1d11e}"));
        assert_eq!(ok(r#""\uDBFF\uDFFF""#), Value::from("\u{10ffff}"));
        assert_eq!(
            ok("\"\u{e9}\u{1d11e}\u{7f}\""),
            Value::from("\u{e9}\u{1d11e}\u{7f}")
        );
    }

    #[test]
    fn invalid_escapes_are_rejected() {
        for s in [
            r#""\x41""#,
            r#""\'""#,
            r#""\a""#,
            r#""\U0041""#,
            r#""\u00G1""#,
            r#""\u-123""#,
        ] {
            assert_eq!(err(s.as_bytes()), BAD_ESCAPE, "{s}");
        }
        assert_eq!(err(br#""\u12"#), EOF);
        assert_eq!(err(br#""\"#), EOF);
    }

    #[test]
    fn lone_and_misordered_surrogates_are_rejected() {
        for s in [
            r#""\ud800""#,
            r#""\uDBFF""#,
            r#""\udc00""#,
            r#""\uDFFF""#,
            r#""\ud800abc""#,
            r#""\ud800\n""#,
            r#""\ud800\u0041""#,
            r#""\ud800\ud800""#,
            r#""\udd1e\ud834""#,
            r#""\uD800\""#,
        ] {
            assert_eq!(err(s.as_bytes()), LONE_SURROGATE, "{s}");
        }
    }

    #[test]
    fn unescaped_control_characters_are_rejected() {
        for c in 0u8..0x20 {
            let input = [b'"', c, b'"'];
            assert_eq!(err(&input), CONTROL_CHAR, "byte {c:#04x}");
        }
        assert_eq!(err(b"\"abc"), EOF);
    }

    #[test]
    fn invalid_utf8_is_rejected_anywhere() {
        for input in [
            &b"\"\xff\""[..],
            b"\"\xc0\xaf\"",         // overlong '/'
            b"\"\xed\xa0\x80\"",     // encoded surrogate U+D800
            b"\"\xf4\x90\x80\x80\"", // above U+10FFFF
            b"\"\xe0\xff\"",
            b"\"\x81\"",
            b"[1]\xff",
            b"\xff",
        ] {
            assert_eq!(err(input), NOT_UTF8, "{input:?}");
        }
    }

    #[test]
    fn number_grammar_is_strict() {
        for s in [
            "01", "-01", "00", "+1", ".5", "1.", "1.e1", "1e", "1e+", "-", "-a", "0x10", "1.5.2",
        ] {
            assert!(matches!(err(s.as_bytes()), Error::InvalidJson(_)), "{s}");
        }
        for s in ["NaN", "Infinity", "-Infinity", "nan", "inf"] {
            assert!(matches!(err(s.as_bytes()), Error::InvalidJson(_)), "{s}");
        }
        assert_eq!(err(b"01"), BAD_NUMBER);
        assert_eq!(ok("-0"), num(0.0));
        assert_eq!(ok("0e0"), num(0.0));
        assert_eq!(ok("1E+2"), num(100.0));
        assert_eq!(ok("1e-2"), num(0.01));
        assert_eq!(ok("[-0.0]"), Value::Array(vec![num(0.0)]));
    }

    #[test]
    fn non_finite_numbers_are_rejected() {
        assert_eq!(err(b"1e400"), Error::InvalidJson("number out of range"));
        assert_eq!(
            err(b"[-1e+9999]"),
            Error::InvalidJson("number out of range")
        );
    }

    #[test]
    fn literals_are_exact_and_lowercase() {
        for s in ["True", "NULL", "nul", "tru", "falsey", "nulll", "t"] {
            assert!(matches!(err(s.as_bytes()), Error::InvalidJson(_)), "{s}");
        }
        assert_eq!(err(b"nul"), EOF);
        assert_eq!(err(b"nulx"), UNEXPECTED);
    }

    #[test]
    fn structural_errors_are_rejected() {
        for s in [
            "[1,]",
            "[,1]",
            "[1 2]",
            "[",
            "]",
            "[1",
            "{",
            "}",
            r#"{"a"}"#,
            r#"{"a":}"#,
            r#"{"a" 1}"#,
            r#"{"a":1,}"#,
            r#"{,"a":1}"#,
            "{a:1}",
            "{'a':1}",
            r#"{"a":1"b":2}"#,
            "[1]]",
            r#"{1:1}"#,
            r#"{"a":1}}"#,
            "[\"a\":1]",
        ] {
            assert!(matches!(err(s.as_bytes()), Error::InvalidJson(_)), "{s}");
        }
    }

    #[test]
    fn duplicate_member_names_are_rejected_after_unescaping() {
        // RFC 7515 §5.2 step 4, RFC 7516 §5.2 step 4, RFC 7493 §2.3.
        for s in [
            r#"{"a":1,"a":1}"#,
            r#"{"a":1,"a":2}"#,
            r#"{"alg":"HS256","b":0,"alg":"none"}"#,
            r#"{"a":1,"\u0061":2}"#,
            r#"{"\u00e9":1,"é":2}"#,
            r#"{"\ud83d\ude00":1,"😀":2}"#,
            r#"{"\/":1,"/":2}"#,
            r#"{"":1,"":2}"#,
            r#"[{"x":{"y":[{"k":1,"k":2}]}}]"#,
        ] {
            assert_eq!(err(s.as_bytes()), DUPLICATE, "{s}");
        }
    }

    #[test]
    fn similar_but_distinct_names_are_not_duplicates() {
        // Names compare code point by code point: no case folding and no
        // Unicode normalization (RFC 8259 §8.3).
        let v = ok(r#"{"a":1,"A":2,"\u00e9":3,"e\u0301":4,"a ":5}"#);
        assert_eq!(v.as_object().map(Object::len), Some(5));
        // The same name in different objects is fine.
        assert!(parse(br#"{"a":{"a":{"a":1}},"b":{"a":2}}"#).is_ok());
    }

    #[test]
    fn a_byte_order_mark_is_rejected() {
        assert_eq!(err(b"\xef\xbb\xbf{}"), BOM);
        assert_eq!(err(b"\xef\xbb\xbf"), BOM);
        // U+FEFF is an ordinary character inside a string.
        assert_eq!(ok("\"\u{feff}\""), Value::from("\u{feff}"));
        assert_eq!(err(b"{} \xef\xbb\xbf"), TRAILING);
    }

    #[test]
    fn exactly_one_value_is_accepted() {
        assert_eq!(err(b"1 2"), TRAILING);
        assert_eq!(err(b"{}{}"), TRAILING);
        assert_eq!(err(b"[] x"), TRAILING);
        assert_eq!(err(b"null\0"), TRAILING);
        assert_eq!(err(b"\"a\"/**/"), TRAILING);
    }

    fn nested_arrays(depth: usize) -> String {
        format!("{}{}", "[".repeat(depth), "]".repeat(depth))
    }

    fn with(limits: Limits, input: &[u8]) -> Result<Value> {
        parse_with_limits(input, &limits)
    }

    #[test]
    fn default_limits_are_the_documented_values() {
        let l = Limits::default();
        assert_eq!(l, Limits::DEFAULT);
        assert_eq!(l.max_depth, 32);
        assert_eq!(l.max_input_len, 1024 * 1024);
        assert_eq!(l.max_entries, 10_000);
    }

    #[test]
    fn nesting_is_bounded_by_max_depth() {
        assert!(parse(nested_arrays(32).as_bytes()).is_ok());
        assert_eq!(err(nested_arrays(33).as_bytes()), TOO_DEEP);
        let objects = format!("{}1{}", r#"{"a":"#.repeat(33), "}".repeat(33));
        assert_eq!(err(objects.as_bytes()), TOO_DEEP);
        let mixed = format!("{}1{}", r#"[{"a":"#.repeat(16), "}]".repeat(16));
        assert!(parse(mixed.as_bytes()).is_ok());
        let mixed = format!("[{}1{}]", r#"[{"a":"#.repeat(16), "}]".repeat(16));
        assert_eq!(err(mixed.as_bytes()), TOO_DEEP);
        // Far deeper than any stack could recurse: rejected, not a crash.
        assert_eq!(err("[".repeat(100_000).as_bytes()), TOO_DEEP);
    }

    #[test]
    fn max_depth_is_configurable_up_to_the_ceiling() {
        let mut l = Limits {
            max_depth: 2,
            ..Limits::DEFAULT
        };
        assert!(with(l, b"[[1]]").is_ok());
        assert_eq!(with(l, b"[[[1]]]"), Err(TOO_DEEP));
        l.max_depth = 0;
        assert!(with(l, b"\"scalars need no depth\"").is_ok());
        assert_eq!(with(l, b"[]"), Err(TOO_DEEP));
        // Larger settings are capped, so recursion stays bounded.
        l.max_depth = usize::MAX;
        let ceiling = Limits::MAX_DEPTH_CEILING;
        assert!(with(l, nested_arrays(ceiling).as_bytes()).is_ok());
        assert_eq!(
            with(l, nested_arrays(ceiling + 1).as_bytes()),
            Err(TOO_DEEP)
        );
    }

    #[test]
    fn input_size_is_bounded_by_max_input_len() {
        let max = Limits::DEFAULT.max_input_len;
        let fits = format!("\"{}\"", "a".repeat(max - 2));
        assert!(parse(fits.as_bytes()).is_ok());
        let over = format!("{fits} ");
        assert_eq!(err(over.as_bytes()), TOO_LARGE);
        // The size check comes first, before any other validation.
        assert_eq!(err(&vec![0xff; max + 1]), TOO_LARGE);

        let l = Limits {
            max_input_len: 4,
            ..Limits::DEFAULT
        };
        assert!(with(l, b"[ 1]").is_ok());
        assert_eq!(with(l, b"[ 1 ]"), Err(TOO_LARGE));
    }

    #[test]
    fn container_sizes_are_bounded_by_max_entries() {
        let max = Limits::DEFAULT.max_entries;
        let array = |n: usize| format!("[{}]", vec!["0"; n].join(","));
        assert!(parse(array(max).as_bytes()).is_ok());
        assert_eq!(err(array(max + 1).as_bytes()), TOO_MANY);
        let object = |n: usize| {
            let members: Vec<String> = (0..n).map(|i| format!("\"{i}\":0")).collect();
            format!("{{{}}}", members.join(","))
        };
        assert!(parse(object(max).as_bytes()).is_ok());
        assert_eq!(err(object(max + 1).as_bytes()), TOO_MANY);

        // The limit is per container, not a total.
        let mut l = Limits {
            max_entries: 2,
            ..Limits::DEFAULT
        };
        assert!(with(l, b"[[1,2],[3,4]]").is_ok());
        assert_eq!(with(l, b"[1,2,3]"), Err(TOO_MANY));
        assert_eq!(with(l, br#"{"a":1,"b":2,"c":3}"#), Err(TOO_MANY));
        l.max_entries = 0;
        assert!(with(l, b"[]").is_ok());
        assert!(with(l, b"{}").is_ok());
        assert_eq!(with(l, b"[1]"), Err(TOO_MANY));
    }
}
