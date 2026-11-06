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

// ---- tester probes (F02 test job r1) ----

use std::collections::BTreeMap;

/// Takes a nested array apart one level at a time, so that dropping a value
/// deeper than the stack allows does not recurse.
fn dismantle(mut v: Value) {
    while let Value::Array(mut items) = v {
        v = items.pop().unwrap_or(Value::Null);
    }
}

#[test]
fn a_value_wrapped_in_option_result_vec_and_map_is_redacted() {
    let v = Value::from(SECRET);
    assert_redacted(&Some(v.clone()));
    assert_redacted(&Ok::<Value, ()>(v.clone()));
    assert_redacted(&Err::<(), Value>(v.clone()));
    assert_redacted(&vec![v.clone(), Value::Null]);
    assert_redacted(&(1, v.clone()));
    assert_redacted(&BTreeMap::from([("k", v)]));

    let o = json::parse(oct_jwk().as_bytes())
        .unwrap()
        .into_object()
        .unwrap();
    assert_redacted(&Some(&o));
    assert_redacted(&json::parse(oct_jwk().as_bytes()));
    let h = Header::from_json(format!(r#"{{"jwk":{}}}"#, oct_jwk()).as_bytes());
    assert_redacted(&h);
}

#[test]
fn a_jws_style_header_with_escaped_and_spaced_input_is_redacted() {
    // RFC 7515 §7.1 / App. A.1: whitespace and CRLF are allowed between
    // tokens, and a string may spell its characters as \u escapes. The
    // decoded secret must not print either way.
    let escaped = SECRET.replacen('M', "\\u004d", 1);
    let input = format!(
        "{{\"typ\":\"JWT\",\r\n \"alg\":\"ES256\",\r\n \"jwk\":{{ \"kty\" : \"oct\", \"k\" : \"{escaped}\" }},\r\n \"x-d\":\"{escaped}\"}}"
    );
    let h = Header::from_json(input.as_bytes()).unwrap();
    assert_redacted(&h);
    assert!(!format!("{h:?}").contains("u004d"));
}

#[test]
fn an_oct_only_jwk_set_and_its_other_params_are_redacted() {
    let set = format!(
        r#"{{"keys":[{{"kty":"oct","k":"{SECRET}","kid":"a"}},{{"kty":"oct","k":"{SECRET}","kid":"b"}}],"x-s":["{SECRET}",{{"k":"{SECRET}"}}]}}"#
    );
    let set = JwkSet::from_json(set.as_bytes()).unwrap();
    assert_eq!(set.len(), 2);
    assert_redacted(&set);
    assert_redacted(set.other_params());
    for key in set.keys() {
        assert_redacted(key);
    }
}

#[test]
fn errors_from_malformed_secret_bearing_input_do_not_echo_it() {
    // A private member that fails validation, a bad header and bad JSON
    // that contain the secret: neither Debug nor Display of the error may
    // repeat it (workspace rule: no key material in errors).
    let bad_keys = [
        format!(r#"{{"kty":"oct","k":"{SECRET}!!"}}"#),
        format!(r#"{{"kty":"EC","crv":"P-256","x":"AA","y":"AA","d":"{SECRET}"}}"#),
        format!(r#"{{"kty":"oct","k":"{SECRET}"#),
        format!(r#"{{"kty":"RSA","n":"AQAB","e":"AQAB","d":"{SECRET}"}}"#),
        format!(r#"{{"kty":"{SECRET}","k":"{SECRET}"}}"#),
    ];
    let mut errors = 0;
    for bad in &bad_keys {
        if let Err(e) = Jwk::from_json(bad.as_bytes()) {
            errors += 1;
            for text in [format!("{e:?}"), format!("{e:#?}"), e.to_string()] {
                assert!(!text.contains(MARKER), "{text}");
            }
        }
    }
    assert!(
        errors >= 3,
        "the inputs must be rejected, got {errors} errors"
    );
    let bad_header = format!(r#"{{"alg":"{SECRET}","p2c":"{SECRET}","jwk":"{SECRET}"}}"#);
    if let Err(e) = Header::from_json(bad_header.as_bytes()) {
        for text in [format!("{e:?}"), e.to_string()] {
            assert!(!text.contains(MARKER), "{text}");
        }
    }
    let bad_json = format!(r#"{{"d":"{SECRET}","d":"{SECRET}"}}"#);
    if let Err(e) = json::parse(bad_json.as_bytes()) {
        for text in [format!("{e:?}"), e.to_string()] {
            assert!(!text.contains(MARKER), "{text}");
        }
    }
}

#[test]
fn formatter_flags_do_not_reveal_a_string() {
    let v = Value::from(SECRET);
    for text in [
        format!("{v:>80?}"),
        format!("{v:<80?}"),
        format!("{v:.3?}"),
        format!("{v:#10?}"),
        format!("{v:#x?}"),
    ] {
        assert!(!text.contains(MARKER), "{text}");
    }
}

#[test]
fn debug_prints_128_levels_in_full_and_marks_the_129th() {
    // The parser accepts 128 nested containers (Limits::MAX_DEPTH_CEILING).
    let nest = |levels: usize| {
        let mut v = Value::from(SECRET);
        for _ in 0..levels {
            v = Value::Array(vec![v]);
        }
        v
    };
    let v = nest(128);
    let debug = format!("{v:?}");
    assert_eq!(debug.matches("Array(").count(), 128);
    assert!(debug.contains("String(\"<redacted>\")"));
    assert!(!debug.contains("<too deep>") && !debug.contains(MARKER));
    dismantle(v);

    let v = nest(129);
    let debug = format!("{v:?}");
    assert_eq!(debug.matches("Array(").count(), 128);
    assert_eq!(debug.matches("<too deep>").count(), 1);
    assert!(
        !debug.contains("String(") && !debug.contains(MARKER),
        "{debug}"
    );
    dismantle(v);
}

#[test]
fn debug_of_a_million_deep_hand_built_value_neither_overflows_nor_leaks() {
    let mut v = Value::from(SECRET);
    for _ in 0..1_000_000 {
        v = Value::Array(vec![v]);
    }
    for debug in [format!("{v:?}"), format!("{v:#?}")] {
        assert_eq!(debug.matches("<too deep>").count(), 1);
        assert!(!debug.contains(MARKER));
    }
    // Dropping a hand-built value this deep recurses in the compiler's drop
    // glue (see the F02 test report); take it apart iteratively here.
    dismantle(v);
}

#[test]
fn numbers_and_bools_print_but_hold_no_secret() {
    let v = json::parse(br#"{"exp":1700000000,"p2c":1000,"ext":true,"n":null,"f":1.5e3}"#).unwrap();
    let debug = format!("{v:?}");
    assert!(
        debug.contains("Bool(true)") && debug.contains("Null"),
        "{debug}"
    );
    assert!(debug.contains("Number("), "{debug}");
}
