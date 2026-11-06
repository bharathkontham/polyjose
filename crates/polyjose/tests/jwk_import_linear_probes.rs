//! F01 tester probes: crafted untrusted JWK / JWK Set inputs must never
//! trip `from_unique_members`'s debug assertion (these run in debug builds),
//! and Object equality edge cases stay correct after the linear-time change.

use polyjose::json::{self, Object, Value};
use polyjose::jwk::{Jwk, JwkSet};

const K: &str =
    "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";

fn names(o: &Object) -> Vec<String> {
    o.iter().map(|(n, _)| n.to_owned()).collect()
}

/// A backslash, so the JSON below spells names with `\u` escapes.
const BS: char = '\\';

#[test]
fn escaped_spellings_of_registered_names_never_become_unknown_duplicates() {
    // `{BS}u006b` is "k", `{BS}u006bty` is "kty", `{BS}u0075` is "u".
    for json in [
        format!(r#"{{"kty":"oct","k":"{K}","{BS}u006b":"{K}"}}"#),
        format!(r#"{{"kty":"oct","k":"{K}","{BS}u006bty":"oct"}}"#),
        format!(r#"{{"kty":"oct","k":"{K}","a{BS}u006cg":"HS256","alg":"HS256"}}"#),
        format!(r#"{{"kty":"oct","k":"{K}","u":1,"{BS}u0075":2}}"#),
    ] {
        // Rejected by the duplicate-name check, never a panic.
        assert!(Jwk::from_json(json.as_bytes()).is_err(), "{json}");
    }
    // An escaped spelling of a registered name alone is that name (not unknown).
    let json = format!(r#"{{"kty":"oct","{BS}u006b":"{K}"}}"#);
    let jwk = Jwk::from_json(json.as_bytes()).unwrap();
    assert!(jwk.other_params().is_empty());
}

#[test]
fn kty_specific_names_of_other_types_are_kept_and_round_trip_without_collision() {
    // For each kty, members that belong to another kty are unknown here.
    let cases = [
        format!(r#"{{"kty":"oct","k":"{K}","n":"AQAB","e":"AQAB","crv":"P-256","x":"AA","y":"AA","d":"AA"}}"#),
        r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","y":"AA","k":"AA","n":"AA"}"#.to_owned(),
    ];
    for json in cases {
        let jwk = Jwk::from_json(json.as_bytes()).expect("imports");
        let o = jwk.to_object();
        let n = names(&o);
        let mut dedup = n.clone();
        dedup.sort();
        dedup.dedup();
        assert_eq!(n.len(), dedup.len(), "to_object names unique: {n:?}");
        assert_eq!(
            Jwk::from_json(jwk.to_json().as_bytes())
                .unwrap()
                .to_object(),
            o
        );
    }
}

#[test]
fn jwk_set_other_members_exclude_keys_and_survive_escaped_keys() {
    let set = format!(r#"{{"keys":[{{"kty":"oct","k":"{K}"}}],"x":1,"y":[1,2],"z":{{"a":1}}}}"#);
    let s = JwkSet::from_json(set.as_bytes()).unwrap();
    assert_eq!(names(s.other_params()), ["x", "y", "z"]);
    // Escaped spelling of "keys" is the same member; a second is a duplicate.
    let dup = format!(r#"{{"keys":[],"{BS}u006beys":[],"a":1}}"#);
    assert!(JwkSet::from_json(dup.as_bytes()).is_err());
    let esc = format!(r#"{{"{BS}u006beys":[],"a":1}}"#);
    let s = JwkSet::from_json(esc.as_bytes()).unwrap();
    assert_eq!(names(s.other_params()), ["a"]);
    assert!(s.is_empty());
}

#[test]
fn object_equality_edge_cases() {
    let p = |s: &str| json::parse(s.as_bytes()).unwrap();
    let (a, b) = (p(r#"{"a":1,"b":2}"#), p(r#"{"b":2,"a":1}"#));
    assert_eq!(a, b);
    assert_ne!(
        p(r#"{"a":1,"b":2}"#),
        p(r#"{"a":2,"b":1}"#),
        "swapped values"
    );
    assert_ne!(p(r#"{"a":1}"#), p(r#"{"a":1,"b":2}"#), "different lengths");
    assert_ne!(
        p(r#"{"a":1,"b":2}"#),
        p(r#"{"a":1,"c":2}"#),
        "different names"
    );
    assert_eq!(p("{}"), p("{}"));
    assert_ne!(p("{}"), p(r#"{"a":null}"#));
    assert_eq!(
        p(r#"{"o":{"x":1,"y":[{"p":1,"q":2}]},"z":0}"#),
        p(r#"{"z":0,"o":{"y":[{"q":2,"p":1}],"x":1}}"#),
        "nested, different order"
    );
    assert_ne!(p(r#"{"o":{"x":1,"y":2}}"#), p(r#"{"o":{"x":1,"y":3}}"#));
    // Array order still matters.
    assert_ne!(p(r#"{"a":[1,2]}"#), p(r#"{"a":[2,1]}"#));
    let _: Value = Value::Null;
}
