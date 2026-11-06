//! 0004 F01 tester probes: adversarial claim values never reach `Debug`
//! or `Display` through the public API (workspace secrets rule, ADR 0049 §4).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use polyjose::json::Value;
use polyjose::jwa::SigningAlg;
use polyjose::jwk::Jwk;
use polyjose::jwt::{self, Audience, Claims, FixedClock, IssueOptions, Keys, NumericDate, Policy};

const OCT_64: &str = r#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#;
const EXP: i64 = 1_300_819_380;
const AUD: &str = "https://api.example";

fn key() -> Jwk {
    Jwk::from_json(OCT_64.as_bytes()).unwrap()
}

/// Claim string values to try: non-ASCII, a claim name, empty, very long.
fn values() -> Vec<String> {
    vec![
        "ZZ-pr\u{00e9}nom-\u{65e5}\u{672c}\u{8a9e}-\u{1f512}".into(),
        "sub".into(),
        "iss".into(),
        "jti".into(),
        "aud".into(),
        String::new(),
        format!("LONG-{}", "x".repeat(100_000)),
        "quote\"back\\slash\nnl".into(),
    ]
}

fn texts(v: &jwt::VerifiedJwt) -> [String; 3] {
    [format!("{v:?}"), format!("{v:#?}"), format!("{:?}", v.claims)]
}

#[test]
fn adversarial_values_never_print_through_verified_jwt() {
    for val in values() {
        for aud in [
            Audience::One(val.clone()),
            Audience::Many(vec![val.clone()]),
            Audience::Many(vec![AUD.into(), val.clone()]),
        ] {
            let mut c = Claims::new();
            c.iss = Some(val.clone());
            c.sub = Some(val.clone());
            c.aud = Some(aud);
            c.exp = NumericDate::from_secs(EXP);
            c.jti = Some(val.clone());
            c.insert("p_str", val.clone()).unwrap();
            c.insert(
                "p_arr",
                Value::Array(vec![Value::from(val.clone()), Value::from(val.clone())]),
            )
            .ok();
            let token = jwt::sign(&c, &IssueOptions::new(SigningAlg::HS256), &key()).unwrap();
            let clock = FixedClock(EXP - 60);
            let algs = [SigningAlg::HS256];
            // The policy accepts AUD only; skip the verify when `aud` lacks it,
            // and probe the claims directly instead.
            let outs: Vec<String> = match jwt::verify(
                &token,
                Keys::One(&key()),
                &Policy::new(&clock, &algs).unwrap().audience(AUD),
            ) {
                Ok(v) => texts(&v).into(),
                Err(e) => {
                    let s = format!("{e} {e:?}");
                    assert_no_leak(&val, &s);
                    vec![format!("{c:?}"), format!("{c:#?}")]
                }
            };
            for o in outs {
                assert_no_leak(&val, &o);
            }
            // from_json path
            let parsed = Claims::from_json(c.to_json().as_bytes()).unwrap();
            assert_no_leak(&val, &format!("{parsed:?}"));
            assert_no_leak(&val, &format!("{parsed:#?}"));
        }
    }
}

/// Short values like `sub` legitimately appear as field names, so test
/// them by an unambiguous wrapper: only the long/unique values are checked
/// by containment; short ones by exact output equality.
fn assert_no_leak(val: &str, out: &str) {
    if val.len() > 8 {
        assert!(!out.contains(val), "leak of {:?}", &val[..8.min(val.len())]);
    }
}

#[test]
fn short_and_empty_values_print_exactly_redacted() {
    for val in ["sub", "iss", "aud", "jti", "other", ""] {
        let mut c = Claims::new();
        c.iss = Some(val.into());
        c.sub = Some(val.into());
        c.aud = Some(Audience::Many(vec![val.into()]));
        c.jti = Some(val.into());
        assert_eq!(
            format!("{c:?}"),
            r#"Claims { iss: Some("<redacted>"), sub: Some("<redacted>"), aud: Some(Many(["<redacted>"])), exp: None, nbf: None, iat: None, jti: Some("<redacted>"), other: {} }"#
        );
    }
    let mut c = Claims::new();
    c.aud = Some(Audience::Many(vec![]));
    assert!(format!("{c:?}").contains("aud: Some(Many([]))"));
}

#[test]
fn nested_object_private_claim_is_redacted() {
    let c = Claims::from_json(
        br#"{"iss":"NESTED-ISS-VALUE","org":{"name":"NESTED-OBJ-VALUE","tags":["NESTED-TAG-VALUE"],"n":1}}"#,
    )
    .unwrap();
    let d = format!("{c:?} {c:#?}");
    for s in ["NESTED-ISS-VALUE", "NESTED-OBJ-VALUE", "NESTED-TAG-VALUE"] {
        assert!(!d.contains(s), "{d}");
    }
    println!("{c:#?}");
}

#[test]
fn error_display_never_carries_claim_values() {
    let m = "ERRMARK-claim-value";
    let mut c = Claims::new();
    c.iss = Some(m.into());
    c.sub = Some(m.into());
    c.aud = Some(Audience::One(m.into()));
    c.exp = NumericDate::from_secs(EXP);
    c.jti = Some(m.into());
    c.insert("p", m).unwrap();
    let token = jwt::sign(&c, &IssueOptions::new(SigningAlg::HS256), &key()).unwrap();
    let algs = [SigningAlg::HS256];
    for now in [EXP - 60, EXP + 10_000] {
        let clock = FixedClock(now);
        for pol in [
            Policy::new(&clock, &algs).unwrap(),
            Policy::new(&clock, &algs).unwrap().audience("other"),
            Policy::new(&clock, &algs).unwrap().issuer("other"),
        ] {
            if let Err(e) = jwt::verify(&token, Keys::One(&key()), &pol) {
                let s = format!("{e} | {e:?} | {e:#?}");
                assert!(!s.contains(m), "{s}");
                println!("err: {s}");
            }
        }
    }
    // Tampered signature and garbage.
    let bad = format!("{}x", token);
    if let Err(e) = jwt::verify(&bad, Keys::One(&key()), &Policy::new(&FixedClock(EXP - 60), &algs).unwrap()) {
        assert!(!format!("{e} {e:?}").contains(m));
    }
}

#[test]
fn header_debug_note() {
    let c = Claims::new();
    let opts = IssueOptions::new(SigningAlg::HS256)
        .header_param("x-str", Value::from("HDR-STR-MARK")).unwrap();
    let mut c = c;
    c.exp = NumericDate::from_secs(EXP);
    let token = jwt::sign(&c, &opts, &key()).unwrap();
    let algs = [SigningAlg::HS256];
    let clock = FixedClock(EXP - 60);
    let v = jwt::verify(&token, Keys::One(&key()), &Policy::new(&clock, &algs).unwrap());
    if let Ok(v) = v {
        println!("HEADER DEBUG: {:?}", v.header);
        assert!(!format!("{v:?}").contains(polyjose::util::b64url_encode(OCT_64.as_bytes()).as_str()));
    } else {
        println!("verify err {:?}", v.err());
    }
}
