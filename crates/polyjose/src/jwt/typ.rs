//! Explicit typing of JWTs: the `typ` values polyjose knows, and the RFC
//! 9068 access-token profile's required claims (RFC 7519 §5.1, RFC 8725
//! §3.11, RFC 9068 §2.1–§2.2; ADR 0027 §5).
//!
//! Use these with [`Policy::expect_typ`](super::Policy::expect_typ) and
//! [`IssueOptions::typ`](super::IssueOptions::typ). Other explicit types
//! (`secevent+jwt`, `logout+jwt`, `dpop+jwt`, …) are passed as strings.

use crate::error::{Error, Result};
use crate::header::Header;

use super::{Policy, TypMode};

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
    let _ = unprotected;
    match layer {
        Layer::Signed => {
            // RFC 7797 §7: "JSON Web Tokens MUST NOT use "b64" with a
            // "false" value", even when `crit` lists it (ADR 0027 §6).
            if protected.b64 == Some(false) {
                return Err(Error::InvalidHeader("b64"));
            }
            // ADR 0027 §5, §7: `cty: JWT` on a JWS would nest a JWS in a
            // JWS (RFC 7519 §5.2), which is not supported. Any other `cty`
            // is ignored.
            if protected
                .cty
                .as_deref()
                .is_some_and(|cty| media_type_eq(cty, JWT))
            {
                return Err(Error::InvalidHeader("cty"));
            }
            check_typ(protected.typ.as_deref(), p.typ_mode())
        }
        Layer::Outer => Err(Error::UnsupportedAlgorithm),
    }
}

/// The `typ` policy of ADR 0027 §5 on the `typ` of one layer.
///
/// - [`TypMode::Default`]: absent or `JWT` (RFC 7519 §5.1) is accepted;
///   any other value is an explicit type that must not pass generic
///   validation (RFC 8725 §3.12) → [`Error::InvalidHeader`].
/// - [`TypMode::Exact`]: `typ` must be present and equal (RFC 8725 §3.11,
///   RFC 9068 §4) → else `InvalidHeader`.
/// - [`TypMode::Any`]: no check.
///
/// Equality is [`media_type_eq`] (RFC 7515 §4.1.9).
fn check_typ(typ: Option<&str>, mode: &TypMode) -> Result<()> {
    let accepted = match mode {
        TypMode::Default => typ.is_none_or(|t| media_type_eq(t, JWT)),
        TypMode::Exact(expected) => typ.is_some_and(|t| media_type_eq(t, expected)),
        TypMode::Any => true,
    };
    if accepted {
        Ok(())
    } else {
        Err(Error::InvalidHeader("typ"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwa::SigningAlg;
    use crate::jwt::FixedClock;

    const CLOCK: FixedClock = FixedClock(1_300_819_380);
    const ES256: &[SigningAlg] = &[SigningAlg::ES256];

    fn default_policy() -> Policy<'static> {
        Policy::new(&CLOCK, ES256).unwrap()
    }

    /// A header from JSON; `alg` is added so every value parses as a JWS
    /// or JWE header would.
    fn header(members: &str) -> Header {
        let json = if members.is_empty() {
            r#"{"alg":"ES256"}"#.to_owned()
        } else {
            format!(r#"{{"alg":"ES256",{members}}}"#)
        };
        Header::from_json(json.as_bytes()).unwrap()
    }

    fn with_typ(typ: Option<&str>) -> Header {
        match typ {
            Some(t) => header(&format!(r#""typ":"{t}""#)),
            None => header(""),
        }
    }

    fn signed(h: &Header, p: &Policy<'_>) -> Result<()> {
        check_jwt_header(h, None, p, Layer::Signed)
    }

    fn is_invalid_header(r: Result<()>) -> bool {
        matches!(r, Err(Error::InvalidHeader(_)))
    }

    #[test]
    fn default_mode_accepts_only_absent_or_jwt() {
        // ADR 0027 §5 (d2); RFC 8725 §3.12: an explicitly typed token is
        // kept out of generic validation.
        let p = default_policy();
        for ok in [
            None,
            Some("JWT"),
            Some("jwt"),
            Some("application/jwt"),
            Some("Application/JWT"),
        ] {
            assert_eq!(signed(&with_typ(ok), &p), Ok(()), "{ok:?}");
        }
        for bad in [
            "at+jwt",
            "secevent+jwt",
            "JOSE",
            "JOSE+JSON",
            "jwt ",
            "",
            "text/jwt",
        ] {
            assert!(
                is_invalid_header(signed(&with_typ(Some(bad)), &p)),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn explicit_mode_requires_an_equal_typ() {
        // ADR 0027 §5; RFC 8725 §3.11; RFC 9068 §2.1, §4.
        let p = default_policy().expect_typ(AT_JWT);
        for ok in [
            "at+jwt",
            "application/at+jwt",
            "at+JWT",
            "Application/AT+JWT",
        ] {
            assert_eq!(signed(&with_typ(Some(ok)), &p), Ok(()), "{ok:?}");
        }
        assert!(is_invalid_header(signed(&with_typ(None), &p)));
        for bad in ["JWT", "jwt", "secevent+jwt", "at+jwt;v=1", "at+jwt "] {
            assert!(
                is_invalid_header(signed(&with_typ(Some(bad)), &p)),
                "{bad:?}"
            );
        }
        let p = default_policy().expect_typ("application/secevent+jwt");
        assert_eq!(signed(&with_typ(Some("secevent+jwt")), &p), Ok(()));
    }

    #[test]
    fn any_mode_accepts_every_typ() {
        let p = default_policy().any_typ();
        for typ in [
            None,
            Some("JWT"),
            Some("at+jwt"),
            Some("JOSE"),
            Some(""),
            Some("x/y;z"),
        ] {
            assert_eq!(signed(&with_typ(typ), &p), Ok(()), "{typ:?}");
        }
    }

    #[test]
    fn access_token_policy_expects_at_jwt() {
        // RFC 9068 §4: the resource server MUST check `typ` is `at+jwt`.
        let p = Policy::access_token(&CLOCK, ES256, &["https://as"], &["https://rs"]).unwrap();
        assert_eq!(signed(&with_typ(Some("application/at+jwt")), &p), Ok(()));
        assert!(is_invalid_header(signed(&with_typ(Some(JWT)), &p)));
        assert!(is_invalid_header(signed(&with_typ(None), &p)));
    }

    #[test]
    fn signed_layer_rejects_unencoded_payloads() {
        // RFC 7797 §7: JWTs MUST NOT use "b64" with a "false" value.
        for p in [default_policy(), default_policy().any_typ()] {
            let h = header(r#""b64":false,"crit":["b64"]"#);
            assert_eq!(signed(&h, &p), Err(Error::InvalidHeader("b64")));
            let h = header(r#""b64":true,"crit":["b64"]"#);
            assert_eq!(signed(&h, &p), Ok(()));
        }
    }

    #[test]
    fn signed_layer_rejects_jws_in_jws_nesting() {
        // ADR 0027 §5–§7: `cty: JWT` on a JWS means JWS-in-JWS nesting,
        // which is not supported; other `cty` values are ignored (RFC 7519
        // §5.2 makes them NOT RECOMMENDED, not forbidden).
        for p in [default_policy(), default_policy().any_typ()] {
            for cty in ["JWT", "jwt", "application/jwt", "APPLICATION/Jwt"] {
                let h = header(&format!(r#""cty":"{cty}""#));
                assert_eq!(signed(&h, &p), Err(Error::InvalidHeader("cty")), "{cty:?}");
            }
            for cty in ["text/plain", "JOSE", "jwt;v=1", "at+jwt"] {
                let h = header(&format!(r#""cty":"{cty}""#));
                assert_eq!(signed(&h, &p), Ok(()), "{cty:?}");
            }
        }
    }

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
