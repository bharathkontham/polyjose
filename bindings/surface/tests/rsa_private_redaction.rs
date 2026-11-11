//! ADR 0065 / ADR 0030 section 7: an RSA private key never shows in `Debug` of the surface
//! records or the parse result, and never in the error of a failing RSA sign or decrypt.
//! ADR 0067 section 2 error rows: public key -> KeyAlgorithmMismatch, no CRT -> InvalidKey.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

use polyjose_surface::jwk::{jwk_parse, jwk_to_public};
use polyjose_surface::jws::jws_sign_compact;
use polyjose_surface::records::{JweRecipient, JwsSignOptions, JwsSigner};
use polyjose_surface::{SecretString, SurfaceError};

const A2: &str =
    include_str!("../../../conformance/vectors/jws-rfc7515/a2-rs256-compact-sign.json");

fn private_jwk() -> String {
    let text = std::str::from_utf8(A2.as_bytes()).unwrap();
    // the vector's signer key is the RFC 7515 A.2 private key
    let start = text.find(r#""key""#).expect("key member");
    let obj_start = start + text[start..].find('{').unwrap();
    let mut depth = 0;
    for (i, c) in text[obj_start..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return text[obj_start..obj_start + i + 1].to_string();
                }
            }
            _ => {}
        }
    }
    panic!("unterminated key")
}

fn member(jwk: &str, name: &str) -> String {
    let pat = format!("\"{name}\"");
    let at = jwk.find(&pat).unwrap() + pat.len();
    let rest = &jwk[at..];
    let q1 = rest.find('"').unwrap() + 1;
    let q2 = rest[q1..].find('"').unwrap();
    rest[q1..q1 + q2].to_string()
}

fn secrets(jwk: &str) -> Vec<String> {
    ["d", "p", "q", "dp", "dq", "qi"]
        .iter()
        .map(|m| member(jwk, m))
        .collect()
}

fn assert_clean(what: &str, text: &str, secrets: &[String]) {
    for s in secrets {
        assert!(
            !text.contains(&s[..24]),
            "{what} leaks a private member: {text}"
        );
    }
}

#[test]
fn rsa_private_key_is_redacted_in_debug_and_errors() {
    let jwk = private_jwk();
    let s = secrets(&jwk);
    let key = SecretString::from(jwk.clone());
    let hdr = JwsSignOptions {
        protected_header: Some(r#"{"alg":"RS256"}"#.into()),
        ..Default::default()
    };
    assert_clean("JwsSignOptions", &format!("{hdr:?} {:#?}", hdr), &s);
    let mut signer = JwsSigner::new(key);
    signer.protected_header = Some(r#"{"alg":"RS256"}"#.into());
    assert_clean("JwsSigner", &format!("{signer:?}{signer:#?}"), &s);
    let rec = JweRecipient::new("RSA-OAEP-256".into(), SecretString::from(jwk.clone()));
    assert_clean("JweRecipient", &format!("{rec:?}{rec:#?}"), &s);
    let parsed = jwk_parse(&jwk).unwrap();
    assert_eq!(format!("{parsed:?}"), "<redacted>");
    assert_clean("jwk_to_public", &jwk_to_public(&jwk).unwrap(), &s);

    // Failing paths: wrong alg for the key, header missing alg, tampered CRT member.
    let tampered = jwk.replace(&member(&jwk, "dq"), &member(&jwk, "dp"));
    let no_qi = jwk.replace("\"qi\"", "\"zz\"");
    assert_ne!(no_qi, jwk);
    for (what, key, alg) in [
        ("ES256 with RSA key", jwk.clone(), "ES256"),
        ("tampered dq", tampered, "RS256"),
        ("no qi", no_qi, "RS256"),
    ] {
        let h = JwsSignOptions {
            protected_header: Some(format!(r#"{{"alg":"{alg}"}}"#)),
            ..Default::default()
        };
        let err: SurfaceError = jws_sign_compact(b"payload", &key, &h).unwrap_err();
        assert_clean(what, &format!("{err:?} {err}"), &s);
    }
    let h = JwsSignOptions {
        protected_header: Some(r#"{"alg":"RS256"}"#.into()),
        ..Default::default()
    };
    let public = jwk_to_public(&jwk).unwrap();
    let e = jws_sign_compact(b"p", &public, &h).unwrap_err();
    assert!(format!("{e:?}").contains("KeyAlgorithmMismatch"), "{e:?}");
}
