//! `Debug` never prints secret text (workspace secrets rule; F02).
//!
//! JWK private members (`d`, `k`, `p`, `q`, `dp`, `dq`, `qi`; RFC 7517 §4,
//! RFC 7518 §6) are JSON strings, and a JOSE Header may carry a JWK in `jwk`
//! or `epk` (RFC 7515 §4.1.3, RFC 7518 §4.6.1.1) or anything at all in a
//! Private Header Parameter (RFC 7515 §4.3). These tests check, through the
//! public API, that `{:?}` and `{:#?}` of every type that can hold such a
//! string never contain it.
//!
//! They do not depend on how `zeroize` formats `Zeroizing`: each test also
//! checks for polyjose's own `"<redacted>"` placeholder, so a `Debug` that
//! merely delegates to `Zeroizing` (opaque in zeroize 1.9.1, the contents in
//! 1.9.0) fails them.
#![allow(clippy::unwrap_used, clippy::panic)] // test code: a panic is a failed assertion

use polyjose::header::Header;
use polyjose::json::{self, Object, Value};
use polyjose::jwk::{Jwk, JwkSet};

/// The secret text. It is valid unpadded base64url of 32 octets (the last
/// character's low two bits are zero), so it can stand in for an EC P-256
/// or Ed25519 `d` or an oct `k` that the JWK parser decodes.
const SECRET: &str = "MARKERsecretMARKERsecretMARKERsecretMARKERs";
/// What a leak would contain; shorter than `SECRET` so that a truncated or
/// re-wrapped copy is caught as well.
const MARKER: &str = "MARKERsecret";

/// RFC 7517 Appendix A.2, the P-256 private key, with `d` replaced.
fn ec_private_jwk() -> String {
    format!(
        r#"{{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","d":"{SECRET}","use":"enc","kid":"1"}}"#
    )
}

/// RFC 8037 Appendix A.1, the Ed25519 private key, with `d` replaced.
fn okp_private_jwk() -> String {
    format!(
        r#"{{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"{SECRET}"}}"#
    )
}

/// A symmetric key whose `k` is the secret.
fn oct_jwk() -> String {
    format!(r#"{{"kty":"oct","k":"{SECRET}","alg":"HS256"}}"#)
}

/// Asserts that neither `{:?}` nor `{:#?}` of `value` contains the secret,
/// and that both show polyjose's own placeholder instead.
fn assert_redacted<T: core::fmt::Debug>(value: &T) {
    for (style, debug) in [
        ("{:?}", format!("{value:?}")),
        ("{:#?}", format!("{value:#?}")),
    ] {
        assert!(!debug.contains(MARKER), "{style} leaks the secret: {debug}");
        assert!(
            debug.contains("\"<redacted>\""),
            "{style} lacks the placeholder: {debug}"
        );
    }
}

#[test]
fn a_string_value_is_redacted() {
    assert_redacted(&Value::from(SECRET));
    assert_redacted(&json::parse(format!("\"{SECRET}\"").as_bytes()).unwrap());
}

#[test]
fn a_private_member_of_an_object_is_redacted_and_its_name_is_shown() {
    let mut o = Object::new();
    o.insert("d", SECRET);
    assert_redacted(&o);
    assert!(format!("{o:?}").contains("\"d\""), "{o:?}");
    let v = Value::from(o);
    assert_redacted(&v);
    assert!(format!("{v:?}").contains("\"d\""), "{v:?}");
}

#[test]
fn strings_nested_in_arrays_and_objects_are_redacted() {
    let input = format!(
        r#"{{"keys":[{ec},{okp},{oct}],"deep":[[[{{"a":[{{"k":"{SECRET}"}}]}}]]],"list":["{SECRET}"]}}"#,
        ec = ec_private_jwk(),
        okp = okp_private_jwk(),
        oct = oct_jwk(),
    );
    let v = json::parse(input.as_bytes()).unwrap();
    assert_redacted(&v);
    assert_redacted(v.as_object().unwrap());
}

#[test]
fn the_object_iterators_are_redacted() {
    let o = json::parse(oct_jwk().as_bytes())
        .unwrap()
        .into_object()
        .unwrap();
    assert_redacted(&o.iter());
    assert_redacted(&o.into_iter());
}

#[test]
fn a_header_with_private_keys_and_private_parameters_is_redacted() {
    let input = format!(
        r#"{{"alg":"ECDH-ES+A128KW","enc":"A128GCM","kid":"k1","jwk":{ec},"epk":{okp},"x-wrapped":{oct},"x-secret":"{SECRET}","x-list":[1,"{SECRET}"]}}"#,
        ec = ec_private_jwk(),
        okp = okp_private_jwk(),
        oct = oct_jwk(),
    );
    let h = Header::from_json(input.as_bytes()).unwrap();
    assert_redacted(&h);
    // Registered parameters are public (they travel in the clear), so they
    // still print, as they do for a `Jwk`.
    let debug = format!("{h:?}");
    assert!(debug.contains(r#"kid: Some("k1")"#), "{debug}");
    assert!(debug.contains("ECDH-ES+A128KW"), "{debug}");
}

#[test]
fn a_header_with_only_an_oct_key_in_jwk_is_redacted() {
    let input = format!(r#"{{"alg":"HS256","jwk":{oct}}}"#, oct = oct_jwk());
    assert_redacted(&Header::from_json(input.as_bytes()).unwrap());
}

/// `Jwk` and `JwkSet` have their own redacting `Debug` (T05, T07); keep it.
#[test]
fn private_jwks_and_jwk_sets_stay_redacted() {
    for key in [ec_private_jwk(), okp_private_jwk(), oct_jwk()] {
        assert_redacted(&Jwk::from_json(key.as_bytes()).unwrap());
    }
    let with_secret_member = format!(r#"{{"kty":"oct","k":"{SECRET}","x-note":"{SECRET}"}}"#);
    assert_redacted(&Jwk::from_json(with_secret_member.as_bytes()).unwrap());

    let set = format!(
        r#"{{"keys":[{ec},{okp},{oct}],"x-secret":"{SECRET}"}}"#,
        ec = ec_private_jwk(),
        okp = okp_private_jwk(),
        oct = oct_jwk(),
    );
    let set = JwkSet::from_json(set.as_bytes()).unwrap();
    assert_eq!(set.len(), 3);
    assert_redacted(&set);
}
