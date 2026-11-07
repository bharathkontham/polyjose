//! The NumericDate type of `exp`, `nbf` and `iat` (RFC 7519 §2,
//! §4.1.4–§4.1.6; ADR 0027 §2–§3).

use core::cmp::Ordering;

use crate::error::{Error, Result};
use crate::json::{MAX_SAFE_INTEGER, Number, Value};

/// The largest accepted magnitude, 2^53 − 1, as a double (exact).
const MAX_SAFE_F64: f64 = MAX_SAFE_INTEGER as f64;

/// A NumericDate (RFC 7519 §2): "the number of seconds from
/// 1970-01-01T00:00:00Z UTC until the specified UTC date/time, ignoring
/// leap seconds", the type of the `exp`, `nbf` and `iat` claims
/// (RFC 7519 §4.1.4–§4.1.6).
///
/// The range is ADR 0027 §2:
///
/// - It is a **JSON number**. A string such as `"1300819380"`, a boolean,
///   `null`, an array or an object is not a NumericDate (RFC 7519 §4.1.4:
///   "MUST be a number").
/// - **Fractions are kept exactly**, never truncated or rounded
///   (RFC 7519 §2: "non-integer values can be represented").
/// - **Negative values are accepted**: RFC 7519 sets no lower bound.
/// - The magnitude is at most **2^53 − 1** (9007199254740991), the range
///   in which an I-JSON number is exact (RFC 7493 §2.2) and every binding
///   represents it unchanged.
///
/// Comparisons with the current time ([`is_expired`](Self::is_expired),
/// [`is_not_yet_valid`](Self::is_not_yet_valid)) are exact: the leeway is
/// applied to the whole-second time on the integer side, and the result is
/// compared with the date without rounding (ADR 0027 §3).
///
/// ```
/// use polyjose::json::parse;
/// use polyjose::jwt::NumericDate;
///
/// let exp = NumericDate::from_json(&parse(b"1300819380")?, "exp")?;
/// assert_eq!(exp.as_secs(), Some(1300819380));
/// assert!(!exp.is_expired(1300819439, 60)); // within the 60 s leeway
/// assert!(exp.is_expired(1300819440, 60));
///
/// // A string is not a NumericDate (RFC 7519 §4.1.4).
/// let err = NumericDate::from_json(&parse(br#""1300819380""#)?, "exp");
/// assert_eq!(err, Err(polyjose::Error::InvalidClaim("exp")));
/// # Ok::<(), polyjose::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NumericDate(Number);

impl NumericDate {
    /// Reads the NumericDate held by the claim `claim` (RFC 7519 §2,
    /// §4.1.4–§4.1.6).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidClaim`]`(claim)` if `value` is not a JSON number, or
    /// its magnitude is above 2^53 − 1 (ADR 0027 §2, RFC 7493 §2.2). The
    /// value is not echoed.
    pub fn from_json(value: &Value, claim: &'static str) -> Result<Self> {
        match value {
            Value::Number(n) => Self::from_number(*n).ok_or(Error::InvalidClaim(claim)),
            _ => Err(Error::InvalidClaim(claim)),
        }
    }

    /// The date `secs` whole seconds after the epoch (RFC 7519 §2), or
    /// `None` if `|secs|` is above 2^53 − 1 (ADR 0027 §2).
    pub fn from_secs(secs: i64) -> Option<Self> {
        Number::from_i64(secs).map(Self)
    }

    /// The date `value` seconds after the epoch, fraction included
    /// (RFC 7519 §2), or `None` if `value` is not finite or its magnitude
    /// is above 2^53 − 1 (ADR 0027 §2).
    pub fn from_f64(value: f64) -> Option<Self> {
        Number::from_f64(value).and_then(Self::from_number)
    }

    /// The date as seconds since the epoch, fraction included.
    pub fn as_f64(&self) -> f64 {
        self.0.as_f64()
    }

    /// The date as whole seconds since the epoch, or `None` if it has a
    /// fraction (RFC 7519 §2).
    pub fn as_secs(&self) -> Option<i64> {
        self.0.as_i64()
    }

    /// The date as a JSON number, for serializing a Claims Set
    /// (ADR 0027 §1): an integral date is written without a fraction
    /// (`1e3` becomes `1000`), any other exactly as received.
    pub fn to_json_value(&self) -> Value {
        Value::Number(self.0)
    }

    /// Whether an `exp` of this date has passed at `now` (whole seconds
    /// since the epoch), allowing `leeway` seconds of clock skew:
    /// `exp ≤ now − leeway`.
    ///
    /// RFC 7519 §4.1.4: "the current date/time MUST be before the
    /// expiration date/time", with "some small leeway" allowed
    /// (ADR 0027 §3). So with `exp` 1000 and leeway 60, `now` 1059 is
    /// accepted and 1060 is expired.
    pub fn is_expired(&self, now: i64, leeway: u32) -> bool {
        self.cmp_secs(now.saturating_sub(i64::from(leeway))) != Ordering::Greater
    }

    /// Whether an `nbf` of this date is still in the future at `now`
    /// (whole seconds since the epoch), allowing `leeway` seconds of clock
    /// skew: `nbf > now + leeway`.
    ///
    /// RFC 7519 §4.1.5: "the current date/time MUST be after or equal to
    /// the not-before date/time", with "some small leeway" allowed
    /// (ADR 0027 §3). So with `nbf` 1000 and leeway 60, `now` 940 is
    /// accepted and 939 is not yet valid.
    pub fn is_not_yet_valid(&self, now: i64, leeway: u32) -> bool {
        self.cmp_secs(now.saturating_add(i64::from(leeway))) == Ordering::Greater
    }

    /// Compares this date with the whole-second time `t`, exactly
    /// (ADR 0027 §3).
    ///
    /// `t` may be outside the double's exact range (`now ± leeway` near
    /// 2^53), so it is never converted: the date's floor is an exact
    /// integer (the date is at most 2^53 − 1 in magnitude), and a date
    /// with a fraction lies strictly between its floor and the next
    /// integer.
    pub(crate) fn cmp_secs(&self, t: i64) -> Ordering {
        let value = self.0.as_f64();
        let floor = value.floor();
        // Exact: |floor| ≤ 2^53, an integer.
        match (floor as i64).cmp(&t) {
            Ordering::Equal if value != floor => Ordering::Greater,
            ordering => ordering,
        }
    }

    /// `n` as a date if its magnitude is at most 2^53 − 1 (ADR 0027 §2).
    fn from_number(n: Number) -> Option<Self> {
        (n.as_f64().abs() <= MAX_SAFE_F64).then_some(Self(n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::parse;

    fn date(json: &str) -> Result<NumericDate> {
        NumericDate::from_json(&parse(json.as_bytes())?, "exp")
    }

    fn at(json: &str) -> NumericDate {
        date(json).unwrap()
    }

    #[test]
    fn accepts_json_numbers_within_the_safe_range() {
        // RFC 7519 §2: non-integer values allowed; no lower bound (ADR 0027 §2).
        for (text, value) in [
            ("1300819380", 1_300_819_380.0),
            ("1300819380.5", 1_300_819_380.5),
            ("-1", -1.0),
            ("0", 0.0),
            ("9007199254740991", 9_007_199_254_740_991.0),
            ("-9007199254740991", -9_007_199_254_740_991.0),
        ] {
            assert_eq!(at(text).as_f64(), value, "{text}");
        }
    }

    #[test]
    fn rejects_out_of_range_and_non_numbers_with_the_claim_name() {
        // RFC 7493 §2.2 bound, and RFC 7519 §4.1.4: "MUST be a number".
        for text in [
            "9007199254740992",
            "1e300",
            "-9007199254740992",
            r#""1300819380""#,
            "true",
            "null",
            "[]",
            "{}",
        ] {
            assert_eq!(date(text), Err(Error::InvalidClaim("exp")), "{text}");
        }
        let nbf = NumericDate::from_json(&Value::from("1"), "nbf");
        assert_eq!(nbf, Err(Error::InvalidClaim("nbf")));
    }

    #[test]
    fn fractions_are_kept_exactly_and_integers_serialize_without_one() {
        assert_eq!(at("1300819380.5").to_json_value().to_json(), "1300819380.5");
        assert_eq!(at("1e3").to_json_value().to_json(), "1000");
        assert_eq!(at("1e3").as_secs(), Some(1000));
        assert_eq!(at("1300819380.5").as_secs(), None);
        assert_eq!(at("-1").to_json_value().to_json(), "-1");
        // Round trip through the value.
        let v = at("1300819380.25");
        assert_eq!(NumericDate::from_json(&v.to_json_value(), "iat"), Ok(v));
    }

    #[test]
    fn constructors_enforce_the_same_range() {
        assert_eq!(
            NumericDate::from_secs(1000).map(|d| d.as_f64()),
            Some(1000.0)
        );
        assert_eq!(
            NumericDate::from_secs(MAX_SAFE_INTEGER).and_then(|d| d.as_secs()),
            Some(MAX_SAFE_INTEGER)
        );
        assert_eq!(NumericDate::from_secs(MAX_SAFE_INTEGER + 1), None);
        assert_eq!(NumericDate::from_secs(-MAX_SAFE_INTEGER - 1), None);
        assert_eq!(NumericDate::from_secs(i64::MIN), None);
        assert_eq!(NumericDate::from_f64(0.5).map(|d| d.as_f64()), Some(0.5));
        assert_eq!(NumericDate::from_f64(9_007_199_254_740_992.0), None);
        assert_eq!(NumericDate::from_f64(f64::NAN), None);
        assert_eq!(NumericDate::from_f64(f64::INFINITY), None);
        assert_eq!(
            NumericDate::from_f64(-0.0).and_then(|d| d.as_secs()),
            Some(0)
        );
    }

    #[test]
    fn exp_boundaries_of_adr_0027_section_3() {
        // exp ≤ now − leeway is expired (RFC 7519 §4.1.4).
        let exp = at("1000");
        assert!(!exp.is_expired(1059, 60));
        assert!(exp.is_expired(1060, 60));
        assert!(!exp.is_expired(999, 0));
        assert!(exp.is_expired(1000, 0));
        let half = at("1000.5");
        assert!(!half.is_expired(1000, 0));
        assert!(half.is_expired(1001, 0));
        assert!(at("-1").is_expired(0, 0));
    }

    #[test]
    fn nbf_boundaries_of_adr_0027_section_3() {
        // nbf > now + leeway is not yet valid (RFC 7519 §4.1.5).
        let nbf = at("1000");
        assert!(!nbf.is_not_yet_valid(940, 60));
        assert!(nbf.is_not_yet_valid(939, 60));
        assert!(!nbf.is_not_yet_valid(1000, 0));
        assert!(nbf.is_not_yet_valid(999, 0));
        let half = at("1000.5");
        assert!(half.is_not_yet_valid(1000, 0));
        assert!(!half.is_not_yet_valid(1001, 0));
    }

    #[test]
    fn comparison_is_exact_at_the_edges_of_the_range() {
        let max = at("9007199254740991");
        // now + leeway beyond 2^53 is not representable as a double; the
        // integer-side comparison stays exact (ADR 0027 §3).
        assert!(!max.is_not_yet_valid(MAX_SAFE_INTEGER, 600));
        assert!(max.is_not_yet_valid(MAX_SAFE_INTEGER - 1, 0));
        assert!(max.is_expired(MAX_SAFE_INTEGER, 0));
        assert!(!max.is_expired(MAX_SAFE_INTEGER - 1, 0));
        let min = at("-9007199254740991");
        assert!(min.is_expired(-MAX_SAFE_INTEGER + 600, 600));
        assert!(!min.is_expired(-MAX_SAFE_INTEGER - 1, 0));
        // Saturating arithmetic: an i64 extreme never wraps around.
        assert!(min.is_expired(i64::MAX, u32::MAX));
        assert!(!max.is_not_yet_valid(i64::MAX, u32::MAX));
        assert!(max.is_not_yet_valid(i64::MIN, u32::MAX));
        assert!(!min.is_expired(i64::MIN, u32::MAX));
    }

    #[test]
    fn cmp_secs_orders_fractions_between_their_integers() {
        let half = at("1000.5");
        assert_eq!(half.cmp_secs(1000), Ordering::Greater);
        assert_eq!(half.cmp_secs(1001), Ordering::Less);
        assert_eq!(at("1000").cmp_secs(1000), Ordering::Equal);
        let neg = at("-0.5");
        assert_eq!(neg.cmp_secs(0), Ordering::Less);
        assert_eq!(neg.cmp_secs(-1), Ordering::Greater);
    }
}
