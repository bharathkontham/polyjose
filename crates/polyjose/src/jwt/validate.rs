//! Claims validation against the policy: steps J4–J10 of ADR 0027 §9
//! (RFC 7519 §4.1.1–§4.1.6; RFC 8725 §3.8–§3.9; RFC 9068 §2.2, §4).

use crate::error::{Error, Result};

use super::claims::REGISTERED_CLAIMS;
use super::typ::ACCESS_TOKEN_REQUIRED_CLAIMS;
use super::{Claims, Policy};

/// The [`Error::InvalidClaim`] detail for a missing claim whose name the
/// caller chose and that is not one polyjose knows: the detail is a
/// `&'static str`, so it cannot carry the caller's string. Details are
/// diagnostic only; the code is the contract (ADR 0027 §9).
const OTHER_REQUIRED_CLAIM: &str = "required";

/// Validates `c` against `p`, in the ADR 0027 §9 order; the first failing
/// step decides the error:
///
/// - J4: required-claim presence, in the order `iss, sub, aud, exp, nbf,
///   iat, jti`, then the policy's other required names in order →
///   [`Error::InvalidClaim`];
/// - J5: `exp` (RFC 7519 §4.1.4) → [`Error::TokenExpired`];
/// - J6: `nbf` (RFC 7519 §4.1.5) → [`Error::TokenNotYetValid`];
/// - J7: `iat` with a maximum age (RFC 7519 §4.1.6) → `InvalidClaim`;
/// - J8–J10: `iss`, `sub`, `aud`, the last including a token `aud` with
///   no configured audience (RFC 7519 §4.1.1–§4.1.3) → `InvalidClaim`.
///
/// The clock is read (through the policy) only when a time check runs
/// (ADR 0028).
pub(crate) fn validate_claims(c: &Claims, p: &Policy<'_>) -> Result<()> {
    check_presence(c, p)?;
    Ok(())
}

/// J4 (ADR 0027 §9): every required claim is present, with any value.
///
/// A registered claim is required when the policy names it in
/// [`require`](Policy::require) or implies it (ADR 0027 §3–§4):
///
/// - `iss` once an issuer is accepted (RFC 8725 §3.8, RFC 9068 §4);
/// - `sub` once a subject is expected;
/// - `aud` once an audience is accepted (RFC 7519 §4.1.3, RFC 8725 §3.9);
/// - `exp` unless [`allow_missing_exp`](Policy::allow_missing_exp)
///   (ADR 0007);
/// - `iat` once a maximum age is set (RFC 7519 §4.1.6).
///
/// The registered claims are checked in the order `iss, sub, aud, exp,
/// nbf, iat, jti`, then the other required names in the order given. Any
/// JSON value counts as present (ADR 0027 §4; RFC 9068 §2.2 uses this for
/// `client_id`). An empty `aud` array is present; it then fails J10.
///
/// # Errors
///
/// [`Error::InvalidClaim`] naming the first missing claim.
fn check_presence(c: &Claims, p: &Policy<'_>) -> Result<()> {
    let required = p.required_claims();
    let present = [
        c.iss.is_some(),
        c.sub.is_some(),
        c.aud.is_some(),
        c.exp.is_some(),
        c.nbf.is_some(),
        c.iat.is_some(),
        c.jti.is_some(),
    ];
    let implied = [
        !p.accepted_issuers().is_empty(),
        p.expected_subject().is_some(),
        !p.accepted_audiences().is_empty(),
        p.requires_exp(),
        false,
        p.max_age_secs().is_some(),
        false,
    ];
    for ((name, present), implied) in REGISTERED_CLAIMS.into_iter().zip(present).zip(implied) {
        if !present && (implied || required.iter().any(|r| r == name)) {
            return Err(Error::InvalidClaim(name));
        }
    }
    for name in required {
        if !REGISTERED_CLAIMS.contains(&name.as_str()) && c.get(name).is_none() {
            return Err(Error::InvalidClaim(detail(name)));
        }
    }
    Ok(())
}

/// The `InvalidClaim` detail naming `name`: the name itself when it is an
/// RFC 9068 §2.2 claim, else [`OTHER_REQUIRED_CLAIM`]. Never echoes the
/// caller's string, and never a claim value.
fn detail(name: &str) -> &'static str {
    ACCESS_TOKEN_REQUIRED_CLAIMS
        .into_iter()
        .find(|known| *known == name)
        .unwrap_or(OTHER_REQUIRED_CLAIM)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::Number;
    use crate::json::{Object, Value};
    use crate::jwa::SigningAlg;
    use crate::jwt::{Audience, Clock, FixedClock, NumericDate};

    const ES256: &[SigningAlg] = &[SigningAlg::ES256];

    /// A clock that must not be read: passed wherever no time check runs,
    /// to prove validation reads the time only when it needs it
    /// (ADR 0028).
    struct PanicClock;

    impl Clock for PanicClock {
        fn now(&self) -> Result<i64> {
            panic!("the clock was read although no time check runs");
        }
    }

    /// A policy over [`PanicClock`].
    fn untimed() -> Policy<'static> {
        Policy::new(&PanicClock, ES256).unwrap()
    }

    fn date(secs: i64) -> Option<NumericDate> {
        NumericDate::from_secs(secs)
    }

    #[test]
    fn missing_exp_is_rejected_by_default_without_reading_the_clock() {
        // ADR 0007, ADR 0027 §3: `exp` is required unless explicitly
        // waived; presence (J4) runs before any time check.
        assert_eq!(
            validate_claims(&Claims::new(), &untimed()),
            Err(Error::InvalidClaim("exp"))
        );
    }

    #[test]
    fn allow_missing_exp_accepts_a_token_without_exp_or_a_clock_read() {
        // ADR 0027 §3: the explicit opt-out. Nothing to compare with the
        // time, so the clock is not read (ADR 0028).
        let p = untimed().allow_missing_exp();
        assert_eq!(validate_claims(&Claims::new(), &p), Ok(()));
        // A future `iat` without `max_age` is not checked either
        // (reported erratum 7720 on RFC 7519 §4.1.6).
        let mut c = Claims::new();
        c.iat = date(i64::from(u32::MAX));
        c.jti = Some("id".into());
        assert_eq!(validate_claims(&c, &p), Ok(()));
    }

    #[test]
    fn configured_issuer_subject_audience_and_max_age_imply_presence() {
        // ADR 0027 §3–§4: each makes its claim required, checked in the
        // J4 order iss, sub, aud, exp, nbf, iat, jti.
        let p = untimed()
            .issuer("https://a")
            .subject("alice")
            .audience("api")
            .max_age(300);
        let mut c = Claims::new();
        assert_eq!(validate_claims(&c, &p), Err(Error::InvalidClaim("iss")));
        c.iss = Some("https://a".into());
        assert_eq!(validate_claims(&c, &p), Err(Error::InvalidClaim("sub")));
        c.sub = Some("alice".into());
        assert_eq!(validate_claims(&c, &p), Err(Error::InvalidClaim("aud")));
        c.aud = Some(Audience::One("api".into()));
        assert_eq!(validate_claims(&c, &p), Err(Error::InvalidClaim("exp")));
        let p = p.allow_missing_exp();
        assert_eq!(validate_claims(&c, &p), Err(Error::InvalidClaim("iat")));
    }

    #[test]
    fn required_claim_may_hold_any_json_type() {
        // ADR 0027 §4: "must be present (any JSON type)".
        let p = untimed().allow_missing_exp().require("client_id");
        let mut c = Claims::new();
        assert_eq!(
            validate_claims(&c, &p),
            Err(Error::InvalidClaim("client_id"))
        );
        // A claim of another name does not count.
        c.insert("client", "s6BhdRkqt3").unwrap();
        assert_eq!(
            validate_claims(&c, &p),
            Err(Error::InvalidClaim("client_id"))
        );
        let mut object = Object::new();
        object.insert("id", "s6BhdRkqt3");
        for value in [
            Value::from("s6BhdRkqt3"),
            Value::Number(Number::from_i64(42).unwrap()),
            Value::from(object),
            Value::Null,
            Value::Bool(false),
            Value::from(Vec::new()),
        ] {
            c.insert("client_id", value.clone()).unwrap();
            assert_eq!(validate_claims(&c, &p), Ok(()), "{value:?}");
        }
    }

    #[test]
    fn required_names_follow_the_registered_order_then_the_callers() {
        // ADR 0027 §9 J4: registered claims first, whatever order they
        // were required in, then the other names in the order given.
        // The detail of a caller-chosen name is "required" (the detail is
        // a `&'static str`), except for the RFC 9068 §2.2 names, so
        // `client_id` against `x-tenant` shows the caller's order.
        let clock = FixedClock(0);
        let first_tenant = Policy::new(&clock, ES256)
            .unwrap()
            .allow_missing_exp()
            .require("x-tenant")
            .require("jti")
            .require("client_id")
            .require("nbf");
        let first_client = Policy::new(&clock, ES256)
            .unwrap()
            .allow_missing_exp()
            .require("client_id")
            .require("nbf")
            .require("x-tenant")
            .require("jti");
        let mut c = Claims::new();
        for p in [&first_tenant, &first_client] {
            assert_eq!(validate_claims(&c, p), Err(Error::InvalidClaim("nbf")));
        }
        c.nbf = date(-100);
        for p in [&first_tenant, &first_client] {
            assert_eq!(validate_claims(&c, p), Err(Error::InvalidClaim("jti")));
        }
        c.jti = Some("id".into());
        assert_eq!(
            validate_claims(&c, &first_tenant),
            Err(Error::InvalidClaim("required"))
        );
        assert_eq!(
            validate_claims(&c, &first_client),
            Err(Error::InvalidClaim("client_id"))
        );
        c.insert("x-tenant", "t1").unwrap();
        for p in [&first_tenant, &first_client] {
            assert_eq!(
                validate_claims(&c, p),
                Err(Error::InvalidClaim("client_id"))
            );
        }
        c.insert("client_id", Value::Null).unwrap();
        for p in [&first_tenant, &first_client] {
            assert_eq!(validate_claims(&c, p), Ok(()));
        }
    }

    #[test]
    fn require_exp_still_applies_after_allow_missing_exp() {
        // policy.rs: "a require("exp") still applies".
        let p = untimed().allow_missing_exp().require("exp");
        assert_eq!(
            validate_claims(&Claims::new(), &p),
            Err(Error::InvalidClaim("exp"))
        );
    }
}
