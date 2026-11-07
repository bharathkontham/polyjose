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

// --- jws_sign_flattened, jws_sign_general (RFC 7515 §7.2) -------------------------------------

/// Every exact-output JSON `jws.sign` vector: RFC 7515 A.1 in both JSON forms, and RFC 7520
/// §4.4 (protected header), §4.5 (detached, RFC 7515 Appendix F), §4.6 (protected `alg`,
/// unprotected `kid`), §4.7 (unprotected header only, ADR 0045 §1) and §4.8 (several signers).
const JSON_SIGN_VECTORS: [&str; 11] = [
    include_str!("../../../conformance/vectors/jws-rfc7515/a1-hs256-flattened-sign.json"),
    include_str!("../../../conformance/vectors/jws-rfc7515/a1-hs256-general-sign.json"),
    include_str!("../../../conformance/vectors/third_party/rfc7520/jws/4-4-hs256-flattened-sign.json"),
    include_str!("../../../conformance/vectors/third_party/rfc7520/jws/4-4-hs256-general-sign.json"),
    include_str!(
        "../../../conformance/vectors/third_party/rfc7520/jws/4-5-detached-hs256-flattened-sign.json"
    ),
    include_str!(
        "../../../conformance/vectors/third_party/rfc7520/jws/4-5-detached-hs256-general-sign.json"
    ),
    include_str!(
        "../../../conformance/vectors/third_party/rfc7520/jws/4-6-protected-alg-hs256-flattened-sign.json"
    ),
    include_str!(
        "../../../conformance/vectors/third_party/rfc7520/jws/4-6-protected-alg-hs256-general-sign.json"
    ),
    RFC7520_4_7_FLATTENED_SIGN,
    RFC7520_4_7_GENERAL_SIGN,
    include_str!(
        "../../../conformance/vectors/third_party/rfc7520/jws/4-8-multiple-hs256-only-general-sign.json"
    ),
];

const RFC7520_4_7_FLATTENED_SIGN: &str = include_str!(
    "../../../conformance/vectors/third_party/rfc7520/jws/4-7-unprotected-only-hs256-flattened-sign.json"
);
const RFC7520_4_7_GENERAL_SIGN: &str = include_str!(
    "../../../conformance/vectors/third_party/rfc7520/jws/4-7-unprotected-only-hs256-general-sign.json"
);

/// A vector signer as a surface [`JwsSigner`]: its key, `protected_b64u` and unprotected
/// `header`, each as given.
fn surface_signer(signer: &Value) -> JwsSigner {
    let mut out = JwsSigner::new(secret(&json_at(signer, &["key"])));
    out.protected_b64u = signer
        .get("protected_b64u")
        .and_then(Value::as_str)
        .map(str::to_owned);
    out.unprotected_header = signer.get("header").map(Value::to_json);
    out
}

/// Runs a JSON `jws.sign` vector through the surface, returning the output JSON text.
fn sign_json_vector(v: &Value) -> Result<String, SurfaceError> {
    let payload = b64u(text(v, &["input", "payload_b64u"]));
    let detached = member(v, &["input", "detached"]).as_bool().unwrap();
    let signers: Vec<JwsSigner> = member(v, &["input", "signers"])
        .as_array()
        .unwrap()
        .iter()
        .map(surface_signer)
        .collect();
    match text(v, &["input", "serialization"]) {
        "flattened" => jws_sign_flattened(&payload, &signers[0], detached),
        "general" => jws_sign_general(&payload, &signers, detached),
        other => panic!("not a JSON serialization: {other}"),
    }
}

#[test]
fn json_sign_reproduces_the_rfc_vectors() {
    for text_ in JSON_SIGN_VECTORS {
        let v = vector(text_);
        let signed = sign_json_vector(&v)
            .unwrap_or_else(|e| panic!("{}: {}", text(&v, &["source"]), e.code()));
        assert_same_json(&signed, &json_at(&v, &["expect", "jws"]));
    }
}

#[test]
fn json_sign_with_only_an_unprotected_header_signs_dot_payload() {
    // ADR 0045 §1, RFC 7515 §5.1: with no protected header the signing input is "." || payload,
    // and RFC 7520 §4.7 prints the result (Figures 54, 55).
    for text_ in [RFC7520_4_7_FLATTENED_SIGN, RFC7520_4_7_GENERAL_SIGN] {
        let v = vector(text_);
        let signer = surface_signer(signer_at(&v, 0));
        assert!(signer.protected_b64u.is_none() && signer.protected_header.is_none());
        let signed = sign_json_vector(&v).unwrap();
        assert_same_json(&signed, &json_at(&v, &["expect", "jws"]));
        assert!(!signed.contains("\"protected\""));
    }
}

/// The core's own `verify_json` (the oracle of ADR 0030 §1: the surface adds nothing).
fn core_verify_json(jws: &str, key: &str) -> polyjose::Result<Vec<u8>> {
    let key = polyjose::jwk::Jwk::from_json(key.as_bytes())?;
    let allowed = [polyjose::jwa::SigningAlg::HS256];
    let opts = polyjose::jws::VerifyOptions::new(&allowed)?;
    Ok(polyjose::jws::verify_json(jws, &key, &opts)?.payload.to_vec())
}

#[test]
fn json_sign_from_header_json_gives_json_the_core_verifies() {
    let mut signer = JwsSigner::new(secret(OCT));
    signer.protected_header = Some(r#"{"alg":"HS256"}"#.to_owned());
    signer.unprotected_header = Some(r#"{"kid":"k1"}"#.to_owned());
    let flattened = jws_sign_flattened(b"hello", &signer, false).unwrap();
    assert_eq!(core_verify_json(&flattened, OCT).unwrap(), b"hello");

    let mut second = JwsSigner::new(secret(OCT));
    second.unprotected_header = Some(r#"{"alg":"HS256","kid":"k2"}"#.to_owned());
    let general = jws_sign_general(b"hello", &[signer, second], false).unwrap();
    assert_eq!(core_verify_json(&general, OCT).unwrap(), b"hello");
    let parsed = vector(&general);
    assert_eq!(
        member(&parsed, &["signatures"]).as_array().unwrap().len(),
        2
    );
}

#[test]
fn json_sign_detached_omits_the_payload_member() {
    // RFC 7515 Appendix F.
    let mut signer = JwsSigner::new(secret(OCT));
    signer.protected_header = Some(r#"{"alg":"HS256"}"#.to_owned());
    let flattened = jws_sign_flattened(b"hello", &signer, true).unwrap();
    assert!(vector(&flattened).get("payload").is_none());
    let general = jws_sign_general(b"hello", &[signer], true).unwrap();
    assert!(vector(&general).get("payload").is_none());
}

#[test]
fn json_sign_signer_header_rules() {
    let with = |protected_header: Option<&str>,
                protected_b64u: Option<&str>,
                unprotected_header: Option<&str>| {
        let mut signer = JwsSigner::new(secret(OCT));
        signer.protected_header = protected_header.map(str::to_owned);
        signer.protected_b64u = protected_b64u.map(str::to_owned);
        signer.unprotected_header = unprotected_header.map(str::to_owned);
        signer
    };
    let codes = |signer: &JwsSigner| {
        [
            code(jws_sign_flattened(b"p", signer, false)),
            code(jws_sign_general(b"p", std::slice::from_ref(signer), false)),
        ]
    };
    // Both protected forms: header-form misuse (ADR 0030 §4, ADR 0045 §1).
    let both = with(
        Some(r#"{"alg":"HS256"}"#),
        Some("eyJhbGciOiJIUzI1NiJ9"),
        None,
    );
    assert_eq!(codes(&both), ["InvalidHeader"; 2]);
    // No header at all: the core's code for a JOSE Header without `alg` (RFC 7515 §4.1.1,
    // ADR 0048 step 5), recorded here.
    assert_eq!(codes(&with(None, None, None)), ["InvalidHeader"; 2]);
    // A member in both headers: they must be disjoint (RFC 7515 §4, §5.2 step 4; core).
    let overlap = with(Some(r#"{"alg":"HS256","kid":"a"}"#), None, Some(r#"{"kid":"a"}"#));
    assert_eq!(codes(&overlap), ["InvalidHeader"; 2]);
    // `crit` must be protected (RFC 7515 §4.1.11; core).
    let crit = with(None, None, Some(r#"{"alg":"HS256","crit":["b64"],"b64":true}"#));
    assert_eq!(codes(&crit), ["InvalidHeader"; 2]);
    // The unprotected header's JSON, parsed by the core (RFC 7515 §7.2.1 `header`).
    assert_eq!(codes(&with(None, None, Some("{"))), ["InvalidJson"; 2]);
    assert_eq!(
        codes(&with(None, None, Some(r#"{"alg":256}"#))),
        ["InvalidHeader"; 2]
    );
    // RSA signing is not offered (ADR 0021).
    let rs256 = with(None, None, Some(r#"{"alg":"RS256"}"#));
    assert_eq!(codes(&rs256), ["UnsupportedAlgorithm"; 2]);
}

#[test]
fn json_sign_reports_key_and_signer_list_errors() {
    let mut bad_key = JwsSigner::new(secret(r#"{"kty":"oct"}"#));
    bad_key.unprotected_header = Some(r#"{"alg":"HS256"}"#.to_owned());
    assert_eq!(code(jws_sign_flattened(b"p", &bad_key, false)), "InvalidKey");

    // RFC 7515 §7.2.1: `signatures` has at least one member, so no signers is a format error.
    assert_eq!(code(jws_sign_general(b"p", &[], false)), "InvalidFormat");

    // A later signer's error is reported even when the first is fine.
    let mut good = JwsSigner::new(secret(OCT));
    good.unprotected_header = Some(r#"{"alg":"HS256"}"#.to_owned());
    assert_eq!(
        code(jws_sign_general(b"p", &[good, bad_key], false)),
        "InvalidKey"
    );
}
