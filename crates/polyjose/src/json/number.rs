//! JSON numbers (RFC 8259 §6) under the I-JSON rules (RFC 7493 §2.2).

use crate::{Error, Result};

/// The largest integer magnitude that an IEEE 754 double holds exactly,
/// 2^53 − 1 (RFC 7493 §2.2).
///
/// Integers outside `[-MAX_SAFE_INTEGER, MAX_SAFE_INTEGER]` cannot be
/// expected to be treated as exact values (RFC 7493 §2.2), so the integer
/// accessors return `None` for them.
pub const MAX_SAFE_INTEGER: i64 = (1 << 53) - 1;

/// `MAX_SAFE_INTEGER` as a double (exact: it is below 2^53).
const MAX_SAFE_F64: f64 = MAX_SAFE_INTEGER as f64;

/// A finite JSON number.
///
/// # Representation (RFC 7493 §2.2)
///
/// I-JSON numbers are IEEE 754 double precision values, so a `Number` holds
/// a finite `f64`: the nearest double to the JSON text (correctly rounded by
/// `core`'s `str::parse::<f64>`). Values that round to an infinity, such as
/// `1e400`, are rejected by the parser. Values below the smallest double
/// round to zero, as RFC 8259 §6 allows. A negative zero is stored as zero.
///
/// It also records whether the number is an **exact integer** in
/// `[-(2^53 − 1), 2^53 − 1]`. For a parsed number that is decided from the
/// decimal text itself, not from the rounded double: `100`, `1.0`, `1e2`
/// and `-0` are integers; `1.5`, `1.00000000000000001` (which rounds to the
/// double 1.0) and `9007199254740992` (2^53, outside the range) are not.
/// [`as_i64`](Number::as_i64) and [`as_u64`](Number::as_u64) return `Some`
/// only for exact integers, so an integer read from JSON is never the
/// result of rounding.
///
/// # Equality
///
/// Two numbers are equal when their doubles are equal (RFC 7493 §2.2: the
/// double is the interoperable value). So `1`, `1.0` and `1e0` are equal.
/// A text with more precision than a double, like `1.00000000000000001`,
/// equals the double it rounds to even though only the latter is an exact
/// integer; RFC 7493 §2.2 says such numbers should not be sent.
#[derive(Debug, Clone, Copy)]
pub struct Number {
    /// Finite, never negative zero.
    value: f64,
    /// `Some` iff the number is exactly this integer, within
    /// ±[`MAX_SAFE_INTEGER`].
    int: Option<i64>,
}

impl Number {
    /// An exact integer, or `None` if `i` is outside ±(2^53 − 1)
    /// (RFC 7493 §2.2), since a receiver could not read it back exactly.
    ///
    /// ```
    /// use polyjose::json::{Number, MAX_SAFE_INTEGER};
    ///
    /// assert_eq!(Number::from_i64(-42).and_then(|n| n.as_i64()), Some(-42));
    /// assert!(Number::from_i64(MAX_SAFE_INTEGER + 1).is_none());
    /// ```
    pub fn from_i64(i: i64) -> Option<Number> {
        (i.unsigned_abs() <= MAX_SAFE_INTEGER.unsigned_abs()).then_some(Number {
            value: i as f64,
            int: Some(i),
        })
    }

    /// An exact non-negative integer, or `None` above 2^53 − 1
    /// (RFC 7493 §2.2).
    pub fn from_u64(u: u64) -> Option<Number> {
        i64::try_from(u).ok().and_then(Number::from_i64)
    }

    /// A number from a double, or `None` if it is NaN or infinite, which
    /// JSON cannot represent (RFC 8259 §6).
    ///
    /// The double is exact, so an integral `v` within ±(2^53 − 1) is an exact
    /// integer.
    ///
    /// ```
    /// use polyjose::json::Number;
    ///
    /// assert_eq!(Number::from_f64(3.0).and_then(|n| n.as_i64()), Some(3));
    /// assert_eq!(Number::from_f64(0.5).and_then(|n| n.as_i64()), None);
    /// assert!(Number::from_f64(f64::NAN).is_none());
    /// ```
    pub fn from_f64(v: f64) -> Option<Number> {
        if !v.is_finite() {
            return None;
        }
        // `-0.0 + 0.0` is `+0.0` (IEEE 754 round-to-nearest).
        let value = v + 0.0;
        let int = (value.fract() == 0.0 && value.abs() <= MAX_SAFE_F64).then_some(value as i64);
        Some(Number { value, int })
    }

    /// Builds a number from a lexeme that already matches the RFC 8259 §6
    /// `number` grammar (the parser guarantees this).
    ///
    /// Fails with [`Error::InvalidJson`] if the value rounds to an infinity:
    /// RFC 8259 §6 forbids Infinity, and RFC 7493 §2.2 rules out numbers of
    /// greater magnitude than a double.
    pub(crate) fn from_lexeme(lexeme: &str) -> Result<Number> {
        let parsed: f64 = lexeme
            .parse()
            .map_err(|_| Error::InvalidJson("invalid number"))?;
        if !parsed.is_finite() {
            return Err(Error::InvalidJson("number out of range"));
        }
        let value = parsed + 0.0;
        // An integer lexeme within ±(2^53 − 1) is exactly representable, so
        // its double is that integer; outside the range the double is too.
        let int =
            (lexeme_is_integer(lexeme) && value.abs() <= MAX_SAFE_F64).then_some(value as i64);
        Ok(Number { value, int })
    }

    /// The value if it is exactly an integer within ±(2^53 − 1), else `None`
    /// (RFC 7493 §2.2). See the type docs for what "exactly" means.
    ///
    /// ```
    /// use polyjose::json::Number;
    ///
    /// let ints: Vec<Option<i64>> = [1e3, 1.5, 9007199254740992.0]
    ///     .into_iter()
    ///     .map(|v| Number::from_f64(v).and_then(|n| n.as_i64()))
    ///     .collect();
    /// assert_eq!(ints, [Some(1000), None, None]);
    /// ```
    pub fn as_i64(&self) -> Option<i64> {
        self.int
    }

    /// Like [`as_i64`](Number::as_i64), for non-negative integers only.
    pub fn as_u64(&self) -> Option<u64> {
        self.int.and_then(|i| u64::try_from(i).ok())
    }

    /// The value as a double: always finite, never negative zero.
    pub fn as_f64(&self) -> f64 {
        self.value
    }
}

impl PartialEq for Number {
    /// Compares the doubles (RFC 7493 §2.2); see the type docs.
    fn eq(&self, other: &Number) -> bool {
        self.value == other.value
    }
}

/// Whether a grammar-valid RFC 8259 §6 number lexeme denotes an integer
/// exactly, judged from its decimal digits (no rounding involved).
///
/// The lexeme is `-? int (. frac)? ([eE] [+-]? exp)?`. Its value is
/// `digits × 10^(exp − len(frac))`; with trailing zeros stripped from the
/// digits, it is an integer iff it is zero or the remaining power of ten is
/// non-negative. The exponent saturates, which keeps its sign (all that
/// matters here) for exponents of any length.
fn lexeme_is_integer(lexeme: &str) -> bool {
    let body = lexeme.strip_prefix('-').unwrap_or(lexeme);
    let (mantissa, exp) = match body.split_once(['e', 'E']) {
        Some((m, e)) => (m, parse_exponent(e)),
        None => (body, 0),
    };
    let (int_part, frac) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let frac_significant = frac.trim_end_matches('0');
    if !frac_significant.is_empty() {
        // The last non-zero digit is `len` places after the point.
        let places = i64::try_from(frac_significant.len()).unwrap_or(i64::MAX);
        return exp >= places;
    }
    let int_significant = int_part.trim_end_matches('0');
    if int_significant.is_empty() {
        return true; // the value is zero
    }
    let trailing_zeros = i64::try_from(int_part.len() - int_significant.len()).unwrap_or(i64::MAX);
    exp.saturating_add(trailing_zeros) >= 0
}

/// Parses an exponent `[+-]? DIGIT+`, saturating at the `i64` bounds.
fn parse_exponent(e: &str) -> i64 {
    let (negative, digits) = match e.as_bytes().first() {
        Some(b'-') => (true, e.get(1..).unwrap_or("")),
        Some(b'+') => (false, e.get(1..).unwrap_or("")),
        _ => (false, e),
    };
    let magnitude = digits.bytes().fold(0i64, |acc, d| {
        acc.saturating_mul(10)
            .saturating_add(i64::from(d.wrapping_sub(b'0')))
    });
    if negative { -magnitude } else { magnitude }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lex(s: &str) -> Number {
        Number::from_lexeme(s).unwrap_or_else(|e| unreachable!("{s}: {e}"))
    }

    #[test]
    fn integer_lexemes_are_exact() {
        for (s, i) in [
            ("0", 0),
            ("-0", 0),
            ("7", 7),
            ("-7", -7),
            ("1e2", 100),
            ("1E+2", 100),
            ("1.0", 1),
            ("1.500e1", 15),
            ("100e-2", 1),
            ("0.0e-99999999999999999999999", 0),
            ("9007199254740991", MAX_SAFE_INTEGER),
            ("-9007199254740991", -MAX_SAFE_INTEGER),
        ] {
            assert_eq!(lex(s).as_i64(), Some(i), "{s}");
        }
    }

    #[test]
    fn non_integers_and_out_of_range_integers_have_no_integer_value() {
        for s in [
            "1.5",
            "1e-1",
            "10e-2",
            "1.00000000000000001", // rounds to 1.0, but is not an integer
            "1e-400",              // underflows to 0, but is not an integer
            "9007199254740992",    // 2^53
            "-9007199254740992",
            "9007199254740993",
            "1e16",
            "123123123123123123123123123123",
        ] {
            assert_eq!(lex(s).as_i64(), None, "{s}");
        }
    }

    #[test]
    fn non_finite_values_are_rejected() {
        for s in [
            "1e400",
            "-1e400",
            "1.5e+9999",
            "0.4e0066999999999999999999999",
        ] {
            assert_eq!(
                Number::from_lexeme(s),
                Err(Error::InvalidJson("number out of range")),
                "{s}"
            );
        }
    }

    #[test]
    fn values_are_correctly_rounded_doubles() {
        assert_eq!(lex("0.1").as_f64(), 0.1);
        assert_eq!(lex("-2.5e-3").as_f64(), -0.0025);
        assert_eq!(lex("1.7976931348623157e308").as_f64(), f64::MAX);
        assert_eq!(lex("5e-324").as_f64(), 5e-324);
        assert_eq!(lex("9007199254740993").as_f64(), 9007199254740992.0);
    }

    #[test]
    fn negative_zero_is_stored_as_zero() {
        for s in ["-0", "-0.0", "-0e5", "-1e-400"] {
            assert!(lex(s).as_f64().is_sign_positive(), "{s}");
        }
        let from_f64 = Number::from_f64(-0.0).map(|n| n.as_f64());
        assert!(from_f64.is_some_and(f64::is_sign_positive));
    }

    #[test]
    fn u64_accessor_is_non_negative_exact_integers_only() {
        assert_eq!(lex("42").as_u64(), Some(42));
        assert_eq!(lex("-1").as_u64(), None);
        assert_eq!(lex("4.2").as_u64(), None);
    }

    #[test]
    fn constructors_enforce_the_safe_range_and_finiteness() {
        assert!(Number::from_i64(MAX_SAFE_INTEGER).is_some());
        assert!(Number::from_i64(-MAX_SAFE_INTEGER).is_some());
        assert!(Number::from_i64(MAX_SAFE_INTEGER + 1).is_none());
        assert!(Number::from_i64(i64::MIN).is_none());
        assert!(Number::from_u64(u64::MAX).is_none());
        assert_eq!(Number::from_u64(5).and_then(|n| n.as_u64()), Some(5));
        assert!(Number::from_f64(f64::INFINITY).is_none());
        assert!(Number::from_f64(f64::NEG_INFINITY).is_none());
        assert_eq!(Number::from_f64(2.0e20).and_then(|n| n.as_i64()), None);
        assert_eq!(Number::from_f64(-0.0).and_then(|n| n.as_i64()), Some(0));
    }

    #[test]
    fn equality_compares_doubles() {
        assert_eq!(lex("1"), lex("1.0"));
        assert_eq!(lex("1"), lex("1e0"));
        assert_eq!(lex("0"), lex("-0"));
        assert_ne!(lex("1"), lex("1.5"));
        assert_eq!(Number::from_i64(3), Number::from_f64(3.0));
    }
}
