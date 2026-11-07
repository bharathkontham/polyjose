//! The JWS operations of the surface (ADR 0030 §4, "JWS"), through the public API only.
//!
//! Inputs and expected outputs are the RFC's own values, taken from the conformance vectors in
//! `conformance/vectors` (RFC 7515 Appendices A.1, A.3, A.6 and F; RFC 7520 §4.7; ADR 0026 §7
//! limits; an ADR 0048 precedence vector), so a test here and the matching vector cannot drift
//! apart. Every behaviour is the core's: these tests show that the surface passes each argument
//! through and converts each result, adding nothing (ADR 0030 §3, §6).

use polyjose::json::{self, Value};
use polyjose_surface::jws::{
    jws_sign_compact, jws_sign_flattened, jws_sign_general, jws_verify_compact, jws_verify_json,
};
use polyjose_surface::records::{JwsSignOptions, JwsSigner, JwsVerifyOptions};
use polyjose_surface::{SecretString, SurfaceError, util};

// --- Vectors ----------------------------------------------------------------------------------

/// A conformance vector file, parsed by the core's own JSON parser.
fn vector(text: &str) -> Value {
    json::parse(text.as_bytes()).expect("a conformance vector is valid JSON")
}

/// The string at `path` (member names) inside `value`.
fn text<'v>(value: &'v Value, path: &[&str]) -> &'v str {
    member(value, path)
        .as_str()
        .unwrap_or_else(|| panic!("{path:?} is not a string"))
}

/// The value at `path` (member names) inside `value`.
fn member<'v>(value: &'v Value, path: &[&str]) -> &'v Value {
    path.iter().fold(value, |v, name| {
        v.get(name)
            .unwrap_or_else(|| panic!("vector has no member {name:?}"))
    })
}

/// The value at `path`, written back as JSON text by the core.
fn json_at(value: &Value, path: &[&str]) -> String {
    member(value, path).to_json()
}

/// The `i`-th signer of a `jws.sign` vector.
fn signer_at(value: &Value, i: usize) -> &Value {
    &member(value, &["input", "signers"])
        .as_array()
        .expect("signers is an array")[i]
}

fn b64u(encoded: &str) -> Vec<u8> {
    util::base64url_decode(encoded).expect("vector base64url is valid")
}

fn list(names: &[&str]) -> Vec<String> {
    names.iter().map(|s| (*s).to_owned()).collect()
}

fn secret(json: &str) -> SecretString {
    SecretString::from(json.to_owned())
}

fn code(result: Result<impl Sized, SurfaceError>) -> &'static str {
    match result {
        Ok(_) => "Ok",
        Err(e) => e.code(),
    }
}

/// Two JSON texts are equal as JSON values (objects are unordered, RFC 8259 §4).
fn assert_same_json(actual: &str, expected: &str) {
    assert!(
        vector(actual) == vector(expected),
        "JSON differs:\n  actual   {actual}\n  expected {expected}"
    );
}

const A1_COMPACT_SIGN: &str =
    include_str!("../../../conformance/vectors/jws-rfc7515/a1-hs256-compact-sign.json");
const A3_VERIFY: &str =
    include_str!("../../../conformance/vectors/jws-rfc7515/a3-es256-compact-verify.json");
const A3_SIGN: &str =
    include_str!("../../../conformance/vectors/jws-rfc7515/a3-es256-compact-sign-roundtrip.json");
const F_DETACHED_COMPACT_SIGN: &str =
    include_str!("../../../conformance/vectors/jws-rfc7515/f-detached-compact-sign.json");
const A2_RS256_SIGN: &str = include_str!(
    "../../../conformance/vectors/jws-rfc7515/a2-rs256-sign-private-key-unsupported.json"
);
const A2_RS256_VERIFY: &str =
    include_str!("../../../conformance/vectors/jws-rfc7515/a2-rs256-compact-verify.json");

/// RFC 7515 Appendix A.1's HMAC key.
const OCT: &str = r#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#;

fn header_b64u(b64u: &str) -> JwsSignOptions {
    JwsSignOptions {
        protected_b64u: Some(b64u.to_owned()),
        ..JwsSignOptions::default()
    }
}

fn header_json(json: &str) -> JwsSignOptions {
    JwsSignOptions {
        protected_header: Some(json.to_owned()),
        ..JwsSignOptions::default()
    }
}

// --- jws_sign_compact (RFC 7515 §5.1, §7.1) ---------------------------------------------------

#[test]
fn sign_compact_reproduces_rfc7515_a1_from_the_exact_header_octets() {
    // RFC 7515 Appendix A.1: the protected header has CRLF line breaks, so only signing over the
    // caller's octets (`protected_b64u`) gives the printed JWS byte for byte.
    let v = vector(A1_COMPACT_SIGN);
    let signer = signer_at(&v, 0);
    let token = jws_sign_compact(
        &b64u(text(&v, &["input", "payload_b64u"])),
        &json_at(signer, &["key"]),
        &header_b64u(text(signer, &["protected_b64u"])),
    )
    .unwrap();
    assert_eq!(token, text(&v, &["expect", "jws"]));
}

#[test]
fn sign_compact_from_header_json_gives_a_token_the_core_verifies() {
    let token = jws_sign_compact(b"hello", OCT, &header_json(r#"{"alg":"HS256","kid":"k1"}"#))
        .unwrap();
    let key = polyjose::jwk::Jwk::from_json(OCT.as_bytes()).unwrap();
    let allowed = [polyjose::jwa::SigningAlg::HS256];
    let opts = polyjose::jws::VerifyOptions::new(&allowed).unwrap();
    let verified = polyjose::jws::verify_compact(&token, &key, &opts).unwrap();
    assert_eq!(&verified.payload[..], b"hello");
    assert_eq!(verified.protected.unwrap().kid.as_deref(), Some("k1"));
}

#[test]
fn sign_compact_es256_round_trips_through_the_surface() {
    // RFC 7515 Appendix A.3's P-256 key. ECDSA signatures are randomized, so the vector is a
    // round trip: sign with the private key, verify with the public one.
    let v = vector(A3_SIGN);
    let signer = signer_at(&v, 0);
    let payload = b64u(text(&v, &["input", "payload_b64u"]));
    let token = jws_sign_compact(
        &payload,
        &json_at(signer, &["key"]),
        &header_b64u(text(signer, &["protected_b64u"])),
    )
    .unwrap();
    let public = json_at(&vector(A3_VERIFY), &["input", "key"]);
    let verified =
        jws_verify_compact(&token, &public, &JwsVerifyOptions::new(list(&["ES256"]))).unwrap();
    assert_eq!(verified.payload.as_bytes(), payload);
    assert_eq!(verified.alg, "ES256");
}

#[test]
fn sign_compact_detached_leaves_the_payload_part_empty() {
    // RFC 7515 Appendix F.
    let v = vector(F_DETACHED_COMPACT_SIGN);
    let signer = signer_at(&v, 0);
    let mut options = header_b64u(text(signer, &["protected_b64u"]));
    options.detached = true;
    let token = jws_sign_compact(
        &b64u(text(&v, &["input", "payload_b64u"])),
        &json_at(signer, &["key"]),
        &options,
    )
    .unwrap();
    assert_eq!(token, text(&v, &["expect", "jws"]));
    assert!(token.contains(".."));
}

#[test]
fn sign_compact_needs_exactly_one_protected_header_form() {
    // ADR 0030 §4: both or neither → InvalidHeader. The compact serialization has no
    // unprotected header, so the protected one is the whole JOSE Header (RFC 7515 §7.1).
    let both = JwsSignOptions {
        protected_header: Some(r#"{"alg":"HS256"}"#.to_owned()),
        protected_b64u: Some("eyJhbGciOiJIUzI1NiJ9".to_owned()),
        detached: false,
    };
    assert_eq!(code(jws_sign_compact(b"p", OCT, &both)), "InvalidHeader");
    let neither = JwsSignOptions::default();
    assert_eq!(code(jws_sign_compact(b"p", OCT, &neither)), "InvalidHeader");
}

#[test]
fn sign_compact_reports_the_core_codes_for_bad_arguments() {
    let hs256 = header_json(r#"{"alg":"HS256"}"#);
    // The key: not JSON, not a JWK (RFC 7517 §4).
    assert_eq!(code(jws_sign_compact(b"p", "{", &hs256)), "InvalidJson");
    assert_eq!(
        code(jws_sign_compact(b"p", r#"{"kty":"oct"}"#, &hs256)),
        "InvalidKey"
    );
    // The protected header: JSON syntax, a registered parameter of the wrong type
    // (RFC 7515 §4.1.1), bad base64url (RFC 7515 §2), no `alg` (RFC 7515 §4.1.1).
    assert_eq!(
        code(jws_sign_compact(b"p", OCT, &header_json("{"))),
        "InvalidJson"
    );
    assert_eq!(
        code(jws_sign_compact(b"p", OCT, &header_json(r#"{"alg":256}"#))),
        "InvalidHeader"
    );
    assert_eq!(
        code(jws_sign_compact(b"p", OCT, &header_b64u("eyJ=="))),
        "InvalidBase64"
    );
    assert_eq!(
        code(jws_sign_compact(b"p", OCT, &header_json("{}"))),
        "InvalidHeader"
    );
    // `none` is never signed (RFC 8725 §3.2); an unknown alg is unsupported (RFC 7515 §4.1.1).
    assert_eq!(
        code(jws_sign_compact(b"p", OCT, &header_json(r#"{"alg":"none"}"#))),
        "AlgorithmNotAllowed"
    );
    assert_eq!(
        code(jws_sign_compact(b"p", OCT, &header_json(r#"{"alg":"HS999"}"#))),
        "UnsupportedAlgorithm"
    );
}

#[test]
fn sign_compact_rs256_is_unsupported() {
    // ADR 0021: no RSA signing. The RFC 7515 A.2 private key is refused on import, and the A.2
    // public key is refused for RS256 before key binding.
    let v = vector(A2_RS256_SIGN);
    let signer = signer_at(&v, 0);
    let rs256 = header_b64u(text(signer, &["protected_b64u"]));
    let private = json_at(signer, &["key"]);
    assert_eq!(
        code(jws_sign_compact(b"p", &private, &rs256)),
        "UnsupportedAlgorithm"
    );
    let public = json_at(&vector(A2_RS256_VERIFY), &["input", "key"]);
    assert_eq!(
        code(jws_sign_compact(b"p", &public, &rs256)),
        "UnsupportedAlgorithm"
    );
    assert_eq!(text(&v, &["expect", "error"]), "UnsupportedAlgorithm");
}
