//! JSON numbers (RFC 8259 §6) under the I-JSON rules (RFC 7493 §2.2).

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

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(Number::from_i64(3), Number::from_f64(3.0));
        assert_eq!(Number::from_f64(0.0), Number::from_f64(-0.0));
        assert_ne!(Number::from_i64(1), Number::from_f64(1.5));
    }
}
