//! Explicit typing of JWTs: the `typ` values polyjose knows, and the RFC
//! 9068 access-token profile's required claims (RFC 7519 §5.1, RFC 8725
//! §3.11, RFC 9068 §2.1–§2.2; ADR 0027 §5).
//!
//! Use these with [`Policy::expect_typ`](super::Policy::expect_typ) and
//! [`IssueOptions::typ`](super::IssueOptions::typ). Other explicit types
//! (`secevent+jwt`, `logout+jwt`, `dpop+jwt`, …) are passed as strings.

use crate::error::{Error, Result};
use crate::header::Header;

use super::Policy;

/// `JWT`, the `typ` RFC 7519 §5.1 recommends for a generic JWT.
///
/// It is not an explicit type in the RFC 8725 §3.11 sense: under the
/// default [`TypMode`](super::TypMode) it is accepted like an absent `typ`
/// (ADR 0027 §5).
pub const JWT: &str = "JWT";

/// `at+jwt`, the `typ` of a JWT access token (RFC 9068 §2.1: "SHOULD be
/// `at+jwt`"). It compares equal to `application/at+jwt` and `at+JWT`
/// (RFC 7515 §4.1.9).
pub const AT_JWT: &str = "at+jwt";

/// The claims a JWT access token must carry (RFC 9068 §2.2), in the
/// ADR 0027 §9 J4 order: `iss`, `exp`, `aud`, `sub`, `client_id`, `iat`,
/// `jti`. [`Policy::access_token`](super::Policy::access_token) requires
/// every one of them.
pub const ACCESS_TOKEN_REQUIRED_CLAIMS: [&str; 7] =
    ["iss", "exp", "aud", "sub", "client_id", "iat", "jti"];

/// Which JOSE layer of a JWT a header belongs to (ADR 0027 §5–§7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Layer {
    /// The JWS of a signed JWT, or the inner JWS of a nested one.
    Signed,
    /// The outer JWE of a nested JWT (RFC 7519 §5.2, §7.2 step 8).
    Outer,
}

/// The prefix RFC 7515 §4.1.9 lets a producer omit from `typ` and `cty`.
const APPLICATION: &[u8] = b"application/";

/// Whether `a` and `b` are the same media type as `typ` or `cty` values
/// (RFC 7515 §4.1.9–§4.1.10; RFC 7519 §7.3 exempts both from exact
/// comparison; ADR 0027 §5):
///
/// - A value with no `/` **anywhere** is read as `application/` + value
///   (RFC 7515 §4.1.9: "MUST treat it as if "application/" were prepended
///   to any "typ" value not containing a '/'"). So `example;part="1/2"`
///   gets no prefix and differs from `application/example;part="1/2"`,
///   the RFC's own example of a value that can't be shortened.
/// - The part before the first `;` (type and subtype) compares
///   ASCII-case-insensitively (RFC 7515 §4.1.9, citing RFC 2045).
/// - Everything after the first `;` compares **exactly**, byte for byte,
///   parameter names included (ADR 0027 §5; RFC 7515 §4.1.9: parameter
///   values are case-sensitive). A trailing `;` is therefore not the same
///   as no parameters.
/// - Nothing is trimmed: `at+jwt ` is not `at+jwt`.
///
/// Compares in place, without allocating.
pub(crate) fn media_type_eq(a: &str, b: &str) -> bool {
    let (a_short, a_type, a_params) = split_media_type(a);
    let (b_short, b_type, b_params) = split_media_type(b);
    if a_params != b_params {
        return false;
    }
    match (a_short, b_short) {
        (true, false) => {
            without_application(b_type).is_some_and(|b| b.eq_ignore_ascii_case(a_type))
        }
        (false, true) => {
            without_application(a_type).is_some_and(|a| a.eq_ignore_ascii_case(b_type))
        }
        _ => a_type.eq_ignore_ascii_case(b_type),
    }
}

/// Splits a `typ`/`cty` value into (no `/` anywhere, so `application/` is
/// implied; the type/subtype before the first `;`; the rest after it).
fn split_media_type(value: &str) -> (bool, &[u8], Option<&[u8]>) {
    let short = !value.contains('/');
    match value.split_once(';') {
        Some((media_type, params)) => (short, media_type.as_bytes(), Some(params.as_bytes())),
        None => (short, value.as_bytes(), None),
    }
}

/// `media_type` without a leading `application/` (any case), or `None`
/// when it does not start with one.
fn without_application(media_type: &[u8]) -> Option<&[u8]> {
    let (prefix, rest) = media_type.split_at_checked(APPLICATION.len())?;
    prefix.eq_ignore_ascii_case(APPLICATION).then_some(rest)
}

/// The JWT header rules of ADR 0027 §9 step J1 (and N1 for a nested
/// JWT's outer layer), for one JOSE layer.
///
/// `protected` is the integrity-protected header (the JWS or JWE
/// Protected Header). `unprotected` is any header of the same layer that
/// is not integrity-protected; compact serializations have none. `typ`
/// and `cty` are read from `protected` only (ADR 0049 §2, ADR 0050 §3).
///
/// - [`Layer::Signed`]: `b64: false` → [`Error::InvalidHeader`]
///   (RFC 7797 §7); `cty` equal to `JWT` (JWS-in-JWS nesting, not
///   supported) → `InvalidHeader`; then the policy's [`TypMode`]
///   (RFC 8725 §3.11–§3.12).
/// - [`Layer::Outer`]: `cty` must equal `JWT` (RFC 7519 §5.2), else
///   `InvalidHeader`; the outer `typ`, if present, must satisfy the same
///   `typ` policy (ADR 0027 §7).
/// - Both layers: an `unprotected` header that sets `typ` or `cty` →
///   `InvalidHeader`, even when `protected` is valid (ADR 0049 §2,
///   ADR 0050 §3).
///
/// [`TypMode`]: super::TypMode
///
/// **Not implemented yet** (feature 0004 T04): returns
/// [`Error::UnsupportedAlgorithm`].
pub(crate) fn check_jwt_header(
    protected: &Header,
    unprotected: Option<&Header>,
    p: &Policy<'_>,
    layer: Layer,
) -> Result<()> {
    let _ = (protected, unprotected, p, layer);
    Err(Error::UnsupportedAlgorithm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[track_caller]
    fn assert_eq_both_ways(a: &str, b: &str) {
        assert!(media_type_eq(a, b), "{a:?} should equal {b:?}");
        assert!(media_type_eq(b, a), "{b:?} should equal {a:?}");
    }

    #[track_caller]
    fn assert_ne_both_ways(a: &str, b: &str) {
        assert!(!media_type_eq(a, b), "{a:?} should not equal {b:?}");
        assert!(!media_type_eq(b, a), "{b:?} should not equal {a:?}");
    }

    #[test]
    fn short_and_full_forms_are_equal_ignoring_case() {
        // RFC 7515 §4.1.9 (implicit `application/`, case-insensitive media
        // types); RFC 9068 §3's `at+JWT` example.
        let at_jwt = [
            "at+jwt",
            "application/at+jwt",
            "at+JWT",
            "Application/AT+JWT",
        ];
        for a in at_jwt {
            for b in at_jwt {
                assert_eq_both_ways(a, b);
            }
        }
        let jwt = ["JWT", "jwt", "application/jwt", "APPLICATION/JWT"];
        for a in jwt {
            for b in jwt {
                assert_eq_both_ways(a, b);
            }
        }
    }

    #[test]
    fn a_slash_anywhere_suppresses_the_implicit_prefix() {
        // RFC 7515 §4.1.9: "application/example;part="1/2"" cannot be
        // shortened, because the short form already contains a '/'.
        assert_ne_both_ways(r#"example;part="1/2""#, r#"application/example;part="1/2""#);
        assert_eq_both_ways(r#"example;part="1/2""#, r#"EXAMPLE;part="1/2""#);
        assert_eq_both_ways(
            r#"application/example;part="1/2""#,
            r#"Application/Example;part="1/2""#,
        );
    }

    #[test]
    fn parameters_compare_exactly() {
        // ADR 0027 §5: only the part before the first `;` ignores case.
        assert_ne_both_ways("a+jwt;v=1", "a+jwt;v=1X");
        assert_ne_both_ways("a+jwt;v=x", "a+jwt;v=X");
        assert_ne_both_ways("a+jwt;v=1", "a+jwt");
        assert_ne_both_ways("a+jwt;", "a+jwt");
        assert_eq_both_ways("A+JWT;v=1", "a+jwt;v=1");
        assert_eq_both_ways("application/A+JWT;v=1", "a+jwt;v=1");
        assert_eq_both_ways("a+jwt;v=1;w=2", "a+JWT;v=1;w=2");
        assert_ne_both_ways("a+jwt;v=1;w=2", "a+jwt;w=2;v=1");
    }

    #[test]
    fn different_types_and_untrimmed_values_differ() {
        assert_ne_both_ways("at+jwt", "jwt");
        assert_ne_both_ways("at+jwt", "at+jwt ");
        assert_ne_both_ways("at+jwt", " at+jwt");
        assert_ne_both_ways("JWT", "application/jwt ");
        assert_ne_both_ways("jwt", "text/jwt");
        assert_ne_both_ways("jwt", "applicationjwt");
        assert_ne_both_ways("jwt", "application//jwt");
        assert_ne_both_ways("JWT", "JOSE");
        assert_ne_both_ways("JWT", "");
        // Only ASCII folds (RFC 2045 tokens are ASCII): a non-ASCII value is
        // equal only to itself.
        assert_eq_both_ways("jwt\u{e9}", "JWT\u{e9}");
        assert_ne_both_ways("jwt\u{e9}", "JWT\u{c9}");
        assert_ne_both_ways("\u{e9}pplication/jwt", "jwt");
    }

    #[test]
    fn constants_are_the_rfc_values() {
        // RFC 7519 §5.1, RFC 9068 §2.1, RFC 9068 §2.2 (in that section's order).
        assert_eq!(JWT, "JWT");
        assert_eq!(AT_JWT, "at+jwt");
        assert_eq!(
            ACCESS_TOKEN_REQUIRED_CLAIMS,
            ["iss", "exp", "aud", "sub", "client_id", "iat", "jti"]
        );
    }
}
