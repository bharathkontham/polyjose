//! 0004 F04 tester: the `aud` verdict for every combination of audience
//! configuration and `aud` claim, through the public API (ADR 0027 §4, §9
//! J10; RFC 7519 §4.1.3). The expected table is written from the ADR, so
//! it holds before and after the F04 `check_aud` refactor.

#![allow(clippy::unwrap_used)] // test code: a panic is a failed assertion

use polyjose::Error;
use polyjose::jwa::SigningAlg;
use polyjose::jwk::Jwk;
use polyjose::jwt::{self, Audience, Claims, FixedClock, IssueOptions, Keys, NumericDate, Policy};

const ALLOWED: [SigningAlg; 1] = [SigningAlg::HS256];
const KEY: &str = r#"{"kty":"oct","k":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"}"#;

#[derive(Clone, Copy, Debug)]
enum A {
    Absent,
    One(&'static str),
    OneOther,
    Many,
    ManyNoMatch,
    Empty,
}

fn claims(a: A) -> Claims {
    let mut c = Claims::new();
    c.exp = NumericDate::from_secs(2_000);
    c.aud = match a {
        A::Absent => None,
        A::One(s) => Some(Audience::One(s.into())),
        A::OneOther => Some(Audience::One("other".into())),
        A::Many => Some(Audience::Many(vec!["x".into(), "me".into()])),
        A::ManyNoMatch => Some(Audience::Many(vec!["x".into(), "y".into()])),
        A::Empty => Some(Audience::Many(vec![])),
    };
    c
}

fn run(a: A, configured: &[&str], ignore: bool) -> Result<(), Error> {
    let key = Jwk::from_json(KEY.as_bytes()).unwrap();
    let token = jwt::sign(&claims(a), &IssueOptions::new(SigningAlg::HS256), &key).unwrap();
    let clock = FixedClock(1_000);
    let mut p = Policy::new(&clock, &ALLOWED).unwrap().audiences(configured);
    if ignore {
        p = p.ignore_audience();
    }
    jwt::verify(&token, Keys::One(&key), &p).map(|_| ())
}

#[test]
fn no_audience_configured() {
    let bad = Err(Error::InvalidClaim("aud"));
    for ignore in [false, true] {
        assert_eq!(
            run(A::Absent, &[], ignore),
            Ok(()),
            "absent ignore={ignore}"
        );
        for a in [A::One("me"), A::OneOther, A::Many, A::Empty] {
            let want = if ignore { Ok(()) } else { bad.clone() };
            assert_eq!(run(a, &[], ignore), want, "{a:?} ignore={ignore}");
        }
    }
}

#[test]
fn audiences_configured() {
    let bad = Err(Error::InvalidClaim("aud"));
    // ignore_audience has no effect when audiences are configured.
    for ignore in [false, true] {
        assert_eq!(run(A::One("me"), &["me", "you"], ignore), Ok(()));
        assert_eq!(run(A::Many, &["me"], ignore), Ok(()));
        assert_eq!(run(A::OneOther, &["me"], ignore), bad);
        assert_eq!(run(A::ManyNoMatch, &["me"], ignore), bad);
        assert_eq!(run(A::Empty, &["me"], ignore), bad);
        assert_eq!(run(A::Absent, &["me"], ignore), bad);
        assert_eq!(run(A::One("ME"), &["me"], ignore), bad); // exact match
    }
}
