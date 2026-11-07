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
use polyjose_surface::records::{JwsSignOptions, JwsSigner, JwsVerified, JwsVerifyOptions};
use polyjose_surface::{SecretBytes, SecretString, SurfaceError, util};

// --- Vectors ----------------------------------------------------------------------------------

/// A conformance vector file, parsed by the core's own JSON parser. The input limit is the
/// file's own length: the ADR 0026 §7 limit vectors hold a JWS just over the 1 MiB default.
fn vector(text: &str) -> Value {
    let mut limits = json::Limits::default();
    limits.max_input_len = limits.max_input_len.max(text.len());
    json::parse_with_limits(text.as_bytes(), &limits).expect("a conformance vector is valid JSON")
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
    let token =
        jws_sign_compact(b"hello", OCT, &header_json(r#"{"alg":"HS256","kid":"k1"}"#)).unwrap();
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
        code(jws_sign_compact(
            b"p",
            OCT,
            &header_json(r#"{"alg":"none"}"#)
        )),
        "AlgorithmNotAllowed"
    );
    assert_eq!(
        code(jws_sign_compact(
            b"p",
            OCT,
            &header_json(r#"{"alg":"HS999"}"#)
        )),
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
    include_str!(
        "../../../conformance/vectors/third_party/rfc7520/jws/4-4-hs256-flattened-sign.json"
    ),
    include_str!(
        "../../../conformance/vectors/third_party/rfc7520/jws/4-4-hs256-general-sign.json"
    ),
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
    Ok(polyjose::jws::verify_json(jws, &key, &opts)?
        .payload
        .to_vec())
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
    let overlap = with(
        Some(r#"{"alg":"HS256","kid":"a"}"#),
        None,
        Some(r#"{"kid":"a"}"#),
    );
    assert_eq!(codes(&overlap), ["InvalidHeader"; 2]);
    // `crit` must be protected (RFC 7515 §4.1.11; core).
    let crit = with(
        None,
        None,
        Some(r#"{"alg":"HS256","crit":["b64"],"b64":true}"#),
    );
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
    assert_eq!(
        code(jws_sign_flattened(b"p", &bad_key, false)),
        "InvalidKey"
    );

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

// --- jws_verify_compact, jws_verify_json (RFC 7515 §5.2) --------------------------------------

/// `jws.verify` vectors, run through the surface exactly as the conformance runner reads them.
const VERIFY_VECTORS: [&str; 16] = [
    A1_COMPACT_VERIFY,
    A3_VERIFY,
    include_str!("../../../conformance/vectors/jws-rfc7515/a6-general-verify-rsa-key.json"),
    include_str!("../../../conformance/vectors/jws-rfc7515/a6-general-verify-ec-key.json"),
    include_str!("../../../conformance/vectors/jws-rfc7515/a7-flattened-verify.json"),
    include_str!("../../../conformance/vectors/jws-rfc7515/f-detached-compact-verify.json"),
    include_str!("../../../conformance/vectors/jws-rfc7515/f-detached-flattened-verify.json"),
    include_str!("../../../conformance/vectors/jws-rfc7515/f-detached-general-verify.json"),
    RFC7520_4_7_FLATTENED_VERIFY,
    RFC7520_4_7_GENERAL_VERIFY,
    // ADR 0026 §7: the defaults (`None` limits) and explicit values both reach the core.
    include_str!(
        "../../../conformance/vectors/jws-limits/general-16-signatures-at-default-limit.json"
    ),
    include_str!(
        "../../../conformance/vectors/jws-limits/compact-just-over-default-max-input-len.json"
    ),
    GENERAL_17_SIGNATURES,
    include_str!("../../../conformance/vectors/jws-negative/max-input-len-at-limit.json"),
    include_str!("../../../conformance/vectors/jws-negative/max-input-len-exceeded.json"),
    include_str!("../../../conformance/vectors/jws-negative/max-signatures-exceeded.json"),
];

const A1_COMPACT_VERIFY: &str =
    include_str!("../../../conformance/vectors/jws-rfc7515/a1-hs256-compact-verify.json");
const A6_RSA_KEY: &str =
    include_str!("../../../conformance/vectors/jws-rfc7515/a6-general-verify-rsa-key.json");
const A6_EC_KEY: &str =
    include_str!("../../../conformance/vectors/jws-rfc7515/a6-general-verify-ec-key.json");
const RFC7520_4_7_FLATTENED_VERIFY: &str = include_str!(
    "../../../conformance/vectors/third_party/rfc7520/jws/4-7-unprotected-only-hs256-flattened-verify.json"
);
const RFC7520_4_7_GENERAL_VERIFY: &str = include_str!(
    "../../../conformance/vectors/third_party/rfc7520/jws/4-7-unprotected-only-hs256-general-verify.json"
);
const GENERAL_17_SIGNATURES: &str =
    include_str!("../../../conformance/vectors/jws-negative/general-17-signatures.json");
const PRECEDENCE_ALG_TYPE_BEFORE_PAYLOAD: &str = include_str!(
    "../../../conformance/vectors/jws-negative/precedence-header-alg-wrong-type-before-payload-base64.json"
);

/// The surface options of a `jws.verify` vector: its allow-list, detached payload and limits.
fn verify_options(input: &Value) -> JwsVerifyOptions {
    let allowed = member(input, &["allowed_algs"])
        .as_array()
        .unwrap()
        .iter()
        .map(|alg| alg.as_str().unwrap().to_owned())
        .collect();
    let mut options = JwsVerifyOptions::new(allowed);
    options.detached_payload = input
        .get("detached_payload_b64u")
        .and_then(Value::as_str)
        .map(|p| SecretBytes::from(b64u(p)));
    let count = |name: &str| {
        input
            .get(name)
            .and_then(Value::as_u64)
            .map(|n| u32::try_from(n).unwrap())
    };
    options.max_input_len = count("max_input_len");
    options.max_signatures = count("max_signatures");
    options
}

/// Runs a `jws.verify` vector through the surface: a string `jws` is compact, an object is JSON.
fn verify_vector(v: &Value) -> Result<JwsVerified, SurfaceError> {
    let input = member(v, &["input"]);
    let key = json_at(input, &["key"]);
    let options = verify_options(input);
    let jws = member(input, &["jws"]);
    match jws.as_str() {
        Some(compact) => jws_verify_compact(compact, &key, &options),
        None => jws_verify_json(&jws.to_json(), &key, &options),
    }
}

#[test]
fn verify_reproduces_the_vectors() {
    for text_ in VERIFY_VECTORS {
        let v = vector(text_);
        let source = text(&v, &["source"]);
        let expect = member(&v, &["expect"]);
        match verify_vector(&v) {
            Ok(verified) if expect.get("ok").and_then(Value::as_bool) == Some(true) => {
                assert_eq!(
                    util::base64url_encode(verified.payload.as_bytes()),
                    text(expect, &["payload_b64u"]),
                    "{source}"
                );
                assert_eq!(verified.alg, text(expect, &["alg"]), "{source}");
                let index = member(expect, &["signature_index"]).as_u64().unwrap();
                assert_eq!(u64::from(verified.signature_index), index, "{source}");
            }
            Ok(_) => panic!("{source}: verified, but the vector expects a failure"),
            Err(e) => assert_eq!(e.code(), text(expect, &["error"]), "{source}"),
        }
    }
}

#[test]
fn verify_json_reports_which_signature_verified() {
    // RFC 7515 Appendix A.6: RS256 then ES256. The RSA key verifies signature 0; with the EC
    // key, signature 0 fails key binding and signature 1 verifies (ADR 0026 §3).
    let rsa = verify_vector(&vector(A6_RSA_KEY)).unwrap();
    assert_eq!((rsa.alg.as_str(), rsa.signature_index), ("RS256", 0));
    let ec = verify_vector(&vector(A6_EC_KEY)).unwrap();
    assert_eq!((ec.alg.as_str(), ec.signature_index), ("ES256", 1));
    // The headers are those of the signature that verified, as the core serializes them.
    assert_eq!(ec.protected_header.as_deref(), Some(r#"{"alg":"ES256"}"#));
    assert_eq!(
        ec.unprotected_header.as_deref(),
        Some(r#"{"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"}"#)
    );
    assert_eq!(
        rsa.unprotected_header.as_deref(),
        Some(r#"{"kid":"2010-12-29"}"#)
    );
}

#[test]
fn verify_compact_returns_the_core_serialized_protected_header() {
    // RFC 7515 Appendix A.1: the header's octets are {"typ":"JWT",\r\n "alg":"HS256"}; the
    // result is the core's serialization of it (registered parameters in core order).
    let verified = verify_vector(&vector(A1_COMPACT_VERIFY)).unwrap();
    assert_eq!(
        verified.protected_header.as_deref(),
        Some(r#"{"alg":"HS256","typ":"JWT"}"#)
    );
    assert_eq!(verified.unprotected_header, None);
    assert_eq!(verified.signature_index, 0);
}

#[test]
fn verify_json_with_only_an_unprotected_header_has_no_protected_header() {
    // RFC 7520 §4.7, ADR 0045 §1: the signature's whole JOSE Header is unprotected.
    for text_ in [RFC7520_4_7_FLATTENED_VERIFY, RFC7520_4_7_GENERAL_VERIFY] {
        let verified = verify_vector(&vector(text_)).unwrap();
        assert_eq!(verified.protected_header, None);
        assert_same_json(
            verified.unprotected_header.as_deref().unwrap(),
            r#"{"alg":"HS256","kid":"018c0ae5-4d9b-471b-bfd6-eef314bc7037"}"#,
        );
    }
}

#[test]
fn verify_needs_a_usable_allow_list() {
    // RFC 8725 §3.1, ADR 0007: an empty list, or one holding only `none`, is refused by the core.
    let token = text(&vector(A1_COMPACT_VERIFY), &["input", "jws"]).to_owned();
    let flattened = jws_sign_flattened(
        b"p",
        &{
            let mut s = JwsSigner::new(secret(OCT));
            s.protected_header = Some(r#"{"alg":"HS256"}"#.to_owned());
            s
        },
        false,
    )
    .unwrap();
    for allowed in [list(&[]), list(&["none"]), list(&["HS256", "none"])] {
        let options = JwsVerifyOptions::new(allowed);
        assert_eq!(
            code(jws_verify_compact(&token, OCT, &options)),
            "AlgorithmNotAllowed"
        );
        assert_eq!(
            code(jws_verify_json(&flattened, OCT, &options)),
            "AlgorithmNotAllowed"
        );
    }
    // A known algorithm that is not the token's: refused before any cryptography (core).
    let es256_only = JwsVerifyOptions::new(list(&["ES256"]));
    assert_eq!(
        code(jws_verify_compact(&token, OCT, &es256_only)),
        "AlgorithmNotAllowed"
    );
}

#[test]
fn verify_limits_default_to_the_core_and_explicit_values_reach_it() {
    // `None`: the core default refuses 17 signatures (ADR 0026 §7).
    let v17 = vector(GENERAL_17_SIGNATURES);
    let jws17 = json_at(&v17, &["input", "jws"]);
    let defaults = JwsVerifyOptions::new(list(&["HS256"]));
    assert_eq!(
        code(jws_verify_json(&jws17, OCT, &defaults)),
        "InvalidFormat"
    );
    // An explicit, larger `max_signatures` reaches the core and lets all 17 through.
    let mut seventeen = JwsVerifyOptions::new(list(&["HS256"]));
    seventeen.max_signatures = Some(17);
    assert_eq!(code(jws_verify_json(&jws17, OCT, &seventeen)), "Ok");

    // Small explicit values: A.6 has two signatures; A.1 is 179 bytes long.
    let a6 = vector(A6_EC_KEY);
    let a6_jws = json_at(&a6, &["input", "jws"]);
    let a6_key = json_at(&a6, &["input", "key"]);
    let mut one = JwsVerifyOptions::new(list(&["RS256", "ES256"]));
    one.max_signatures = Some(1);
    assert_eq!(
        code(jws_verify_json(&a6_jws, &a6_key, &one)),
        "InvalidFormat"
    );
    one.max_signatures = Some(2);
    assert_eq!(code(jws_verify_json(&a6_jws, &a6_key, &one)), "Ok");

    let token = text(&vector(A1_COMPACT_VERIFY), &["input", "jws"]).to_owned();
    let len = u32::try_from(token.len()).unwrap();
    let mut short = JwsVerifyOptions::new(list(&["HS256"]));
    short.max_input_len = Some(len - 1);
    assert_eq!(
        code(jws_verify_compact(&token, OCT, &short)),
        "InvalidFormat"
    );
    assert_eq!(
        code(jws_verify_json(&a6_jws, &a6_key, &{
            let mut o = JwsVerifyOptions::new(list(&["ES256"]));
            o.max_input_len = Some(16);
            o
        })),
        "InvalidFormat"
    );
    short.max_input_len = Some(len);
    assert_eq!(code(jws_verify_compact(&token, OCT, &short)), "Ok");
}

#[test]
fn verify_detached_payload_reaches_the_core() {
    // RFC 7515 Appendix F: sign detached, verify against the payload given separately.
    let token = jws_sign_compact(b"hello", OCT, &{
        let mut o = header_json(r#"{"alg":"HS256"}"#);
        o.detached = true;
        o
    })
    .unwrap();
    let mut options = JwsVerifyOptions::new(list(&["HS256"]));
    options.detached_payload = Some(SecretBytes::from(b"hello".to_vec()));
    let verified = jws_verify_compact(&token, OCT, &options).unwrap();
    assert_eq!(verified.payload.as_bytes(), b"hello");
    // Another payload does not verify; no detached payload leaves an empty attached one.
    options.detached_payload = Some(SecretBytes::from(b"hellO".to_vec()));
    assert_eq!(
        code(jws_verify_compact(&token, OCT, &options)),
        "InvalidSignature"
    );
    let attached = JwsVerifyOptions::new(list(&["HS256"]));
    assert_eq!(
        code(jws_verify_compact(&token, OCT, &attached)),
        "InvalidSignature"
    );
    // A detached payload against an attached JWS: refused by the core (ADR 0026 §1).
    let a1 = text(&vector(A1_COMPACT_VERIFY), &["input", "jws"]).to_owned();
    options.detached_payload = Some(SecretBytes::from(b"x".to_vec()));
    assert_eq!(
        code(jws_verify_compact(&a1, OCT, &options)),
        "InvalidFormat"
    );
}

#[test]
fn verify_passes_the_core_precedence_through() {
    // ADR 0048: a numeric `alg` (header-parse check, step 3) beats a padded payload (step 4).
    let v = vector(PRECEDENCE_ALG_TYPE_BEFORE_PAYLOAD);
    assert_eq!(code(verify_vector(&v)), text(&v, &["expect", "error"]));
    assert_eq!(code(verify_vector(&v)), "InvalidHeader");
}

#[test]
fn verify_reports_the_core_codes_for_bad_arguments() {
    let token = text(&vector(A1_COMPACT_VERIFY), &["input", "jws"]).to_owned();
    let hs256 = JwsVerifyOptions::new(list(&["HS256"]));
    assert_eq!(code(jws_verify_compact(&token, "{", &hs256)), "InvalidJson");
    assert_eq!(code(jws_verify_json("{", OCT, &hs256)), "InvalidJson");
    assert_eq!(code(jws_verify_json(&token, OCT, &hs256)), "InvalidJson");
    assert_eq!(
        code(jws_verify_compact("a.b", OCT, &hs256)),
        "InvalidFormat"
    );
    // A wrong key: the MAC fails (RFC 7515 §5.2 step 8).
    let other = r#"{"kty":"oct","k":"hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"}"#;
    assert_eq!(
        code(jws_verify_compact(&token, other, &hs256)),
        "InvalidSignature"
    );
}
#[test]
fn es256_compact_round_trips_through_the_surface() {
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
