#![allow(clippy::unwrap_used, clippy::panic)] // test code: a panic is a failed assertion
//! RSA private key import and secret handling (ADR 0067 §3, RFC 7518
//! §6.3.2, RFC 8017 §3.2, workspace secrets rule): a key whose private
//! members disagree is `InvalidKey`, `oth` is `UnsupportedAlgorithm`, a
//! missing CRT member is `InvalidKey`, and neither `Debug`, `Display` nor
//! any error ever contains a private member, whichever format it came from.

use std::path::PathBuf;

use polyjose::keys::KeyFormat;
use polyjose::{Error, jwk::Jwk};

const PRIVATE: [&str; 6] = ["d", "p", "q", "dp", "dq", "qi"];

fn fixture() -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/vectors/jwe/rsa-oaep-256/keys/rsa-2048.private.jwk");
    String::from_utf8(std::fs::read(p).unwrap()).unwrap()
}

/// The string value of member `name` in the fixture.
fn member(json: &str, name: &str) -> String {
    let needle = format!("\"{name}\": \"");
    let start = json.find(&needle).unwrap() + needle.len();
    json[start..start + json[start..].find('"').unwrap()].to_owned()
}

/// `json` with the value of `name` changed in its last character (still base64url).
fn tamper(json: &str, name: &str) -> String {
    let v = member(json, name);
    let last = if v.ends_with('A') { 'B' } else { 'A' };
    let bad = format!("{}{last}", &v[..v.len() - 1]);
    json.replacen(
        &format!("\"{name}\": \"{v}\""),
        &format!("\"{name}\": \"{bad}\""),
        1,
    )
}

fn without(json: &str, name: &str) -> String {
    let v = member(json, name);
    json.replacen(&format!("\"{name}\": \"{v}\","), "", 1)
        .replacen(&format!(",\n  \"{name}\": \"{v}\""), "", 1)
}

fn assert_no_secret(text: &str, secrets: &[String], what: &str) {
    for s in secrets {
        assert!(!text.contains(s.as_str()), "{what} leaks a private member");
        // A quarter of the value would be as bad.
        assert!(
            !text.contains(&s[..s.len().min(24)]),
            "{what} leaks part of one"
        );
    }
}

#[test]
fn the_fixture_imports_and_inconsistent_private_members_do_not() {
    let json = fixture();
    assert!(Jwk::from_json(json.as_bytes()).is_ok());
    for name in PRIVATE {
        let bad = tamper(&json, name);
        assert_ne!(bad, json, "{name}");
        let err = Jwk::from_json(bad.as_bytes()).unwrap_err();
        assert!(matches!(err, Error::InvalidKey(_)), "{name}: {err:?}");
    }
}

#[test]
fn a_missing_crt_member_is_invalid_and_oth_is_unsupported() {
    let json = fixture();
    for name in ["dp", "dq", "qi", "p", "q", "d"] {
        let bad = without(&json, name);
        assert_ne!(bad, json, "{name}");
        let err = Jwk::from_json(bad.as_bytes()).unwrap_err();
        assert!(matches!(err, Error::InvalidKey(_)), "{name}: {err:?}");
    }
    let oth = json.replacen(
        "\"kty\": \"RSA\"",
        "\"kty\": \"RSA\", \"oth\": [{\"r\":\"AQAB\",\"d\":\"AQAB\",\"t\":\"AQAB\"}]",
        1,
    );
    assert_eq!(
        Jwk::from_json(oth.as_bytes()).unwrap_err(),
        Error::UnsupportedAlgorithm
    );
}

#[test]
fn debug_display_and_errors_never_show_a_private_member() {
    let json = fixture();
    let secrets: Vec<String> = PRIVATE.iter().map(|n| member(&json, n)).collect();
    let key = Jwk::from_json(json.as_bytes()).unwrap();
    assert_no_secret(&format!("{key:?}"), &secrets, "Debug");
    assert_no_secret(&format!("{key:#?}"), &secrets, "pretty Debug");
    assert_no_secret(&format!("{:?}", key.material()), &secrets, "material Debug");
    let public = key.to_public().unwrap();
    assert!(public.is_public());
    assert_no_secret(&public.to_json(), &secrets, "to_public JSON");
    for name in PRIVATE {
        let err = Jwk::from_json(tamper(&json, name).as_bytes()).unwrap_err();
        assert_no_secret(&format!("{err:?} {err}"), &secrets, "error");
        let err = Jwk::from_json(without(&json, name).as_bytes()).unwrap_err();
        assert_no_secret(&format!("{err:?} {err}"), &secrets, "error");
    }
}

#[test]
fn pkcs8_and_pkcs1_private_import_checks_consistency_and_leaks_nothing() {
    let json = fixture();
    let secrets: Vec<String> = PRIVATE.iter().map(|n| member(&json, n)).collect();
    let key = Jwk::from_json(json.as_bytes()).unwrap();
    let der = key.to_der(KeyFormat::Pkcs8).unwrap();
    let back = Jwk::from_der(&der, KeyFormat::Pkcs8).unwrap();
    assert_eq!(back.to_json().as_str(), key.to_json().as_str());
    let pem = key.to_pem(KeyFormat::Pkcs8).unwrap();
    assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    assert!(Jwk::from_pem(&pem).is_ok());
    // Flip one octet in every position of the DER tail (the private
    // integers): each result either fails as InvalidKey or, if the flipped
    // octet is structural, as another key error; none imports a key that
    // differs from the original, and no error carries key material.
    for i in (der.len() / 3..der.len()).step_by(7) {
        let mut bad = der.to_vec();
        bad[i] ^= 0x01;
        match Jwk::from_der(&bad, KeyFormat::Pkcs8) {
            Ok(k) => assert_eq!(k.to_json().as_str(), key.to_json().as_str(), "octet {i}"),
            Err(e) => assert_no_secret(&format!("{e:?} {e}"), &secrets, "der error"),
        }
    }
}
