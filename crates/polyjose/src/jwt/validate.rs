//! Claims validation against the policy: steps J4–J10 of ADR 0027 §9
//! (RFC 7519 §4.1.1–§4.1.6; RFC 8725 §3.8–§3.9; RFC 9068 §2.2, §4).

use core::cmp::Ordering;

use crate::error::{Error, Result};

use super::claims::REGISTERED_CLAIMS;
use super::typ::ACCESS_TOKEN_REQUIRED_CLAIMS;
use super::{Claims, NumericDate, Policy};

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
    let mut now = Now::new(p);
    check_exp(c, p, &mut now)?;
    check_nbf(c, p, &mut now)?;
    check_iat(c, p, &mut now)?;
    Ok(())
}

/// The current time, read from the policy's clock on first use and then
/// reused: at most one read per validation, and none when no time check
/// runs (ADR 0028).
struct Now<'p, 'a> {
    policy: &'p Policy<'a>,
    secs: Option<i64>,
}

impl<'p, 'a> Now<'p, 'a> {
    fn new(policy: &'p Policy<'a>) -> Self {
        Self { policy, secs: None }
    }

    /// Whole seconds since the epoch, within ±(2^53 − 1).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidClaim`]`("clock")`, or the clock's own error
    /// (ADR 0028 §1).
    fn get(&mut self) -> Result<i64> {
        match self.secs {
            Some(secs) => Ok(secs),
            None => {
                let secs = self.policy.now()?;
                self.secs = Some(secs);
                Ok(secs)
            }
        }
    }
}

/// J5: a present `exp` has not passed. RFC 7519 §4.1.4: "the current
/// date/time MUST be before the expiration date/time", with "some small
/// leeway"; rejected iff `exp ≤ now − leeway` (ADR 0027 §3). Presence is
/// J4's job.
///
/// # Errors
///
/// [`Error::TokenExpired`], or a clock error.
fn check_exp(c: &Claims, p: &Policy<'_>, now: &mut Now<'_, '_>) -> Result<()> {
    match &c.exp {
        Some(exp) if exp.is_expired(now.get()?, p.leeway_secs()) => Err(Error::TokenExpired),
        _ => Ok(()),
    }
}

/// J6: a present `nbf` has been reached. RFC 7519 §4.1.5: "the current
/// date/time MUST be after or equal to the not-before date/time", with
/// "some small leeway"; rejected iff `nbf > now + leeway` (ADR 0027 §3).
///
/// # Errors
///
/// [`Error::TokenNotYetValid`], or a clock error.
fn check_nbf(c: &Claims, p: &Policy<'_>, now: &mut Now<'_, '_>) -> Result<()> {
    match &c.nbf {
        Some(nbf) if nbf.is_not_yet_valid(now.get()?, p.leeway_secs()) => {
            Err(Error::TokenNotYetValid)
        }
        _ => Ok(()),
    }
}

/// J7: with a maximum age set, `iat` lies within
/// `[now − max_age − leeway, now + leeway]` (ADR 0027 §3). RFC 7519
/// §4.1.6 "can be used to determine the age of the JWT" but sets no rule
/// of its own, so without a maximum age `iat` is not time-checked and a
/// future `iat` is accepted (reported erratum 7720).
///
/// # Errors
///
/// [`Error::InvalidClaim`]`("iat")`, or a clock error.
fn check_iat(c: &Claims, p: &Policy<'_>, now: &mut Now<'_, '_>) -> Result<()> {
    let Some(max_age) = p.max_age_secs() else {
        return Ok(());
    };
    // J4 made `iat` required with a maximum age; checked again so this
    // step never depends on that.
    let iat = c.iat.as_ref().ok_or(Error::InvalidClaim("iat"))?;
    if iat_outside_window(iat, now.get()?, max_age, p.leeway_secs()) {
        return Err(Error::InvalidClaim("iat"));
    }
    Ok(())
}

/// Whether `iat` was issued in the future (`iat > now + leeway`) or too
/// long ago (`iat < now − max_age − leeway`), ADR 0027 §3.
///
/// Exact for every `i64` `now` and `u32` setting, with no overflow: the
/// bounds are computed with saturating `i64` arithmetic and compared
/// without rounding by [`NumericDate::cmp_secs`]. A bound that saturates
/// lies beyond `i64`'s range, so beyond every NumericDate (at most
/// 2^53 − 1 in magnitude), and the saturated value orders the same way
/// against every NumericDate. Both bounds move in one direction only, so
/// saturating twice clamps the same way as once.
fn iat_outside_window(iat: &NumericDate, now: i64, max_age: u32, leeway: u32) -> bool {
    let leeway = i64::from(leeway);
    let latest = now.saturating_add(leeway);
    let earliest = now
        .saturating_sub(i64::from(max_age))
        .saturating_sub(leeway);
    iat.cmp_secs(latest) == Ordering::Greater || iat.cmp_secs(earliest) == Ordering::Less
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
    use core::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    use crate::json::{MAX_SAFE_INTEGER, Number};
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

    /// A policy over `clock` with `leeway` seconds of skew.
    fn timed(clock: &FixedClock, leeway: u32) -> Policy<'_> {
        Policy::new(clock, ES256).unwrap().leeway(leeway).unwrap()
    }

    /// A clock that counts its reads.
    struct CountingClock(i64, AtomicUsize);

    impl Clock for CountingClock {
        fn now(&self) -> Result<i64> {
            self.1.fetch_add(1, AtomicOrdering::Relaxed);
            Ok(self.0)
        }
    }

    #[test]
    fn exp_boundaries_of_adr_0027_section_3() {
        // RFC 7519 §4.1.4: rejected iff exp ≤ now − leeway (ADR 0027 §3).
        for (exp, leeway, now, expected) in [
            (1000.0, 60, 1059, Ok(())),
            (1000.0, 60, 1060, Err(Error::TokenExpired)),
            (1000.0, 0, 999, Ok(())),
            (1000.0, 0, 1000, Err(Error::TokenExpired)),
            (1000.5, 0, 1000, Ok(())),
            (1000.5, 0, 1001, Err(Error::TokenExpired)),
            // A negative date is simply in the past (ADR 0027 §2).
            (-1.0, 0, 0, Err(Error::TokenExpired)),
            (-1.0, 60, 0, Ok(())),
            (-61.0, 60, 0, Err(Error::TokenExpired)),
        ] {
            let clock = FixedClock(now);
            let mut c = Claims::new();
            c.exp = NumericDate::from_f64(exp);
            assert_eq!(
                validate_claims(&c, &timed(&clock, leeway)),
                expected,
                "exp {exp}, leeway {leeway}, now {now}"
            );
        }
    }

    #[test]
    fn nbf_boundaries_of_adr_0027_section_3() {
        // RFC 7519 §4.1.5: rejected iff nbf > now + leeway (ADR 0027 §3).
        for (nbf, leeway, now, expected) in [
            (Some(1000.0), 60, 940, Ok(())),
            (Some(1000.0), 60, 939, Err(Error::TokenNotYetValid)),
            (Some(1000.0), 0, 1000, Ok(())),
            (Some(1000.0), 0, 999, Err(Error::TokenNotYetValid)),
            (Some(1000.5), 0, 1000, Err(Error::TokenNotYetValid)),
            (Some(1000.5), 0, 1001, Ok(())),
            (Some(-100.0), 60, 0, Ok(())),
            (Some(-100.0), 0, -100, Ok(())),
            (None, 0, 0, Ok(())),
        ] {
            let clock = FixedClock(now);
            let mut c = Claims::new();
            c.nbf = nbf.and_then(NumericDate::from_f64);
            let p = timed(&clock, leeway).allow_missing_exp();
            assert_eq!(
                validate_claims(&c, &p),
                expected,
                "nbf {nbf:?}, leeway {leeway}, now {now}"
            );
        }
    }

    #[test]
    fn future_iat_is_accepted_without_max_age() {
        // Reported erratum 7720 on RFC 7519 §4.1.6 (ADR 0027 §3).
        let now = 1_300_819_380;
        let clock = FixedClock(now);
        let mut c = Claims::new();
        c.exp = date(now + 7200);
        c.iat = date(now + 3600);
        assert_eq!(validate_claims(&c, &timed(&clock, 60)), Ok(()));
        assert_eq!(validate_claims(&c, &timed(&clock, 0)), Ok(()));
    }

    #[test]
    fn iat_window_with_max_age() {
        // ADR 0027 §3: rejected iff iat > now + leeway or
        // iat < now − max_age − leeway (RFC 7519 §4.1.6).
        let now = 1_300_819_380;
        let clock = FixedClock(now);
        let p = timed(&clock, 60).max_age(300);
        let mut c = Claims::new();
        c.exp = date(now + 7200);
        assert_eq!(validate_claims(&c, &p), Err(Error::InvalidClaim("iat")));
        for (offset, expected) in [
            (61.0, Err(Error::InvalidClaim("iat"))),
            (60.5, Err(Error::InvalidClaim("iat"))),
            (60.0, Ok(())),
            (0.0, Ok(())),
            (-360.0, Ok(())),
            (-360.5, Err(Error::InvalidClaim("iat"))),
            (-361.0, Err(Error::InvalidClaim("iat"))),
        ] {
            c.iat = NumericDate::from_f64(now as f64 + offset);
            assert_eq!(validate_claims(&c, &p), expected, "iat now{offset:+}");
        }
    }

    #[test]
    fn iat_window_is_exact_for_any_now_and_bound() {
        // No overflow, no panic and no rounding for every i64 time and u32
        // setting (ADR 0027 §3). The policy's clock is bounded to
        // ±(2^53 − 1), but the arithmetic does not rely on it.
        let max = NumericDate::from_secs(MAX_SAFE_INTEGER).unwrap();
        let min = NumericDate::from_secs(-MAX_SAFE_INTEGER).unwrap();
        let half = NumericDate::from_f64(0.5).unwrap();
        for (iat, now, max_age, leeway, outside) in [
            // i64 extremes: now ± max_age ± leeway leaves the i64 range.
            (max, i64::MAX, u32::MAX, u32::MAX, true),
            (min, i64::MAX, u32::MAX, u32::MAX, true),
            (max, i64::MAX, 0, u32::MAX, true),
            (max, i64::MIN, u32::MAX, u32::MAX, true),
            (min, i64::MIN, u32::MAX, u32::MAX, true),
            (min, i64::MIN + 1, 0, 0, true),
            // Exact at the edges of the NumericDate range, where
            // now ± leeway is beyond 2^53 and not exact as a double.
            (max, MAX_SAFE_INTEGER, 0, 0, false),
            (max, MAX_SAFE_INTEGER - 1, 0, 0, true),
            (max, MAX_SAFE_INTEGER + 1, 0, 0, true),
            (max, MAX_SAFE_INTEGER + 1, 1, 0, false),
            (max, MAX_SAFE_INTEGER + 600, 0, 600, false),
            (max, MAX_SAFE_INTEGER + 601, 0, 600, true),
            (min, -MAX_SAFE_INTEGER, 0, 0, false),
            (min, -MAX_SAFE_INTEGER + 1, 0, 0, true),
            (min, -MAX_SAFE_INTEGER - 1, 0, 0, true),
            (min, -MAX_SAFE_INTEGER - 1, 0, 1, false),
            // Fractions lie strictly between their integers.
            (half, 0, 0, 0, true),
            (half, 1, 0, 0, true),
            (half, 1, 1, 0, false),
            (half, 0, 0, 1, false),
        ] {
            assert_eq!(
                iat_outside_window(&iat, now, max_age, leeway),
                outside,
                "iat {}, now {now}, max_age {max_age}, leeway {leeway}",
                iat.as_f64()
            );
        }
    }

    #[test]
    fn the_clock_is_read_once_and_only_for_a_time_check() {
        // ADR 0028: no read without a time check (PanicClock above), and
        // one read however many checks run.
        let clock = CountingClock(1000, AtomicUsize::new(0));
        let p = Policy::new(&clock, ES256).unwrap().max_age(300);
        let mut c = Claims::new();
        c.exp = date(2000);
        c.nbf = date(900);
        c.iat = date(950);
        assert_eq!(validate_claims(&c, &p), Ok(()));
        assert_eq!(clock.1.load(AtomicOrdering::Relaxed), 1);

        // Each time claim alone needs one read.
        for claim in ["exp", "nbf", "iat"] {
            let clock = CountingClock(1000, AtomicUsize::new(0));
            let p = Policy::new(&clock, ES256).unwrap().allow_missing_exp();
            let mut c = Claims::new();
            let p = match claim {
                "exp" => {
                    c.exp = date(2000);
                    p
                }
                "nbf" => {
                    c.nbf = date(900);
                    p
                }
                _ => {
                    c.iat = date(950);
                    p.max_age(300)
                }
            };
            assert_eq!(validate_claims(&c, &p), Ok(()), "{claim}");
            assert_eq!(clock.1.load(AtomicOrdering::Relaxed), 1, "{claim}");
        }
    }

    #[test]
    fn a_clock_out_of_range_fails_the_first_time_check() {
        // ADR 0028 §1: InvalidClaim("clock"), never a panic.
        let clock = FixedClock(MAX_SAFE_INTEGER + 1);
        let p = Policy::new(&clock, ES256).unwrap();
        let mut c = Claims::new();
        c.exp = date(1000);
        assert_eq!(validate_claims(&c, &p), Err(Error::InvalidClaim("clock")));

        let p = Policy::new(&clock, ES256).unwrap().allow_missing_exp();
        let mut c = Claims::new();
        c.nbf = date(1000);
        assert_eq!(validate_claims(&c, &p), Err(Error::InvalidClaim("clock")));

        let p = p.max_age(300);
        let mut c = Claims::new();
        c.iat = date(1000);
        assert_eq!(validate_claims(&c, &p), Err(Error::InvalidClaim("clock")));

        // Presence (J4) runs first; without a time check the clock is not
        // read at all.
        let p = Policy::new(&clock, ES256).unwrap();
        assert_eq!(
            validate_claims(&Claims::new(), &p),
            Err(Error::InvalidClaim("exp"))
        );
        let p = p.allow_missing_exp();
        assert_eq!(validate_claims(&Claims::new(), &p), Ok(()));
    }
}
