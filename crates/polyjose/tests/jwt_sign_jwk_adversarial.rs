//! 0004 F03 tester probes: `IssueOptions::header_param("jwk", ..)` against
//! escaped member names, case variants, nesting, other key types and
//! redaction (review S2, CLAUDE.md secrets rule).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

use polyjose::Error;
use polyjose::json::{self, Value};
use polyjose::jwa::SigningAlg;
use polyjose::jwt::IssueOptions;

const MARK: &str = "c2VjcmV0LWtleS1tYXRlcmlhbC1tYXJrZXI";
const EC_PUB: &str = r#""kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0""#;

fn try_jwk(text: &str) -> Result<IssueOptions, Error> {
    let v: Value = json::parse(text.as_bytes()).unwrap();
    IssueOptions::new(SigningAlg::ES256).header_param("jwk", v)
}

fn refused(text: &str) {
    let err = try_jwk(text).unwrap_err();
    assert_eq!(err, Error::InvalidHeader("jwk"), "{text}");
    let shown = format!("{err} {err:?}");
    assert!(!shown.contains(MARK), "{shown}");
}

/// Turns the `@` escape marker into a JSON backslash.
fn esc(s: &str) -> String {
    s.replace('@', "\\")
}

#[test]
fn escaped_member_names_are_refused_once_unescaped() {
    // @u0064 is "d", @u006b "k", @u0071@u0069 "qi", @u006f@u0074@u0068 "oth".
    refused(&esc(&format!(r#"{{{EC_PUB},"@u0064":"{MARK}"}}"#)));
    refused(&esc(&format!(r#"{{"kty":"oct","@u006b":"{MARK}"}}"#)));
    refused(&esc(&format!(r#"{{{EC_PUB},"@u0071@u0069":"{MARK}"}}"#)));
    refused(&esc(&format!(
        r#"{{{EC_PUB},"@u006F@u0074@u0068":[{{"r":"{MARK}"}}]}}"#
    )));
    refused(&esc(&format!(r#"{{"@u006bty":"oct","k":"{MARK}"}}"#)));
    refused(&esc(&format!(r#"{{"@u006bty":"oct","@u006b":"{MARK}"}}"#)));
    // Surrogate-pair-free multi byte neighbours must not confuse the match.
    refused(&esc(&format!(
        r#"{{{EC_PUB},"@u00e9":1,"@u0064":"{MARK}"}}"#
    )));
}

#[test]
fn duplicate_member_via_escape_does_not_smuggle() {
    // "d" and "@u0064" are the same name: never Ok.
    let text = esc(&format!(r#"{{{EC_PUB},"d":"x","@u0064":"{MARK}"}}"#));
    assert!(json::parse(text.as_bytes()).is_err());
}

#[test]
fn uppercase_d_and_k_are_distinct_members_and_are_accepted() {
    // RFC 7517 §4: member names are case sensitive; "D" and "K" are not
    // secret members of any registered kty. Documenting the behaviour.
    let r = try_jwk(&format!(r#"{{{EC_PUB},"D":"{MARK}","K":"{MARK}"}}"#));
    assert!(r.is_ok(), "RFC 7517 §4: names are case sensitive");
}

#[test]
fn private_members_with_any_value_type_or_nesting() {
    for v in ["null", "1", "true", "[]", "{}", r#"{"x":"y"}"#, r#"["a"]"#] {
        refused(&format!(r#"{{{EC_PUB},"d":{v}}}"#));
        refused(&format!(r#"{{{EC_PUB},"oth":{v}}}"#));
        refused(&format!(r#"{{{EC_PUB},"k":{v}}}"#));
    }
    refused(&format!(
        r#"{{"kty":"RSA","n":"AQAB","e":"AQAB","oth":[{{"r":"{MARK}","d":"{MARK}","t":"{MARK}"}}]}}"#
    ));
}

#[test]
fn nested_private_member_in_an_unknown_member_is_accepted() {
    // Documented gap: only top-level members are checked.
    let r = try_jwk(&format!(r#"{{{EC_PUB},"x-extra":{{"d":"{MARK}"}}}}"#));
    println!("nested d in unknown member accepted: {}", r.is_ok());
    let r = try_jwk(&format!(r#"{{{EC_PUB},"x-secret":"{MARK}"}}"#));
    println!("unknown x-secret member accepted: {}", r.is_ok());
}

#[test]
fn other_key_types() {
    refused(&format!(r#"{{"kty":"RSA","d":"{MARK}"}}"#));
    refused(&format!(
        r#"{{"kty":"RSA","n":"AQAB","e":"AQAB","d":"{MARK}"}}"#
    ));
    refused(&format!(r#"{{"kty":"XYZ","d":"{MARK}"}}"#));
    refused(&format!(r#"{{"kty":"XYZ","k":"{MARK}"}}"#));
    refused(&format!(r#"{{"kty":"","d":"{MARK}"}}"#));
    refused(&format!(r#"{{"d":"{MARK}","kty":5}}"#));
    refused(&format!(
        r#"{{"kty":"OKP","crv":"X25519","x":"AA","d":"{MARK}"}}"#
    ));
    // not objects
    for v in ["null", "\"str\"", "[]", "1", "true"] {
        refused(v);
    }
    // unknown kty without private members: not a valid JWK
    refused(r#"{"kty":"XYZ","foo":"bar"}"#);
}

#[test]
fn debug_of_options_hides_nothing_secret_because_nothing_secret_is_stored() {
    let err = try_jwk(&format!(r#"{{"kty":"oct","k":"{MARK}"}}"#)).unwrap_err();
    assert!(!format!("{err:?}{err}").contains(MARK));
    let ok = try_jwk(&format!(r#"{{{EC_PUB}}}"#)).unwrap();
    assert!(!format!("{ok:?}").contains(MARK));
}
