//! Every `polyjose-ffi` export, called directly from Rust once with a valid and once with an
//! invalid input (feature 0013 T12). Each failure is checked as both the [`PolyjoseError`]
//! variant and its exported `code()`, which is what Kotlin and Swift callers match on (ADR 0030
//! §5, ADR 0032 §3, ADR 0033 §3).
//!
//! The behaviour behind each export is the surface's and the core's, tested there with the full
//! RFC vector sets; these tests prove only that each adapter converts its arguments, makes its
//! one surface call and converts the result (ADR 0030 §1, "the adapter test"). Inputs are RFC
//! values where one is deterministic (RFC 7515 Appendix A.1, RFC 7516 Appendices A.3 and A.5,
//! RFC 7517 Appendix A, RFC 7519 §3.1, RFC 7638 §3.1, RFC 8037 Appendix A, RFC 9278 §3) and
//! round trips where the operation draws randomness (ADR 0005: no fixed RNG in a binding).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

use polyjose::json::{self, Value};
use polyjose_ffi::PolyjoseError;
use polyjose_ffi::jwe::{
    jwe_decrypt_compact, jwe_decrypt_json, jwe_encrypt_compact, jwe_encrypt_json,
};
use polyjose_ffi::jwk::{
    jwk_parse, jwk_thumbprint, jwk_thumbprint_uri, jwk_to_public, jwks_select,
};
use polyjose_ffi::jws::{
    jws_sign_compact, jws_sign_flattened, jws_sign_general, jws_verify_compact, jws_verify_json,
};
use polyjose_ffi::jwt::{
    jwt_decrypt_nested, jwt_decrypt_nested_with_jwks, jwt_encrypt_nested, jwt_sign, jwt_verify,
    jwt_verify_with_jwks,
};
use polyjose_ffi::keys;
use polyjose_ffi::records::{
    JweDecryptOptions, JweEncryptOptions, JweRecipient, JwkSelector, JwsSignOptions, JwsSigner,
    JwsVerifyOptions, JwtSignOptions, JwtVerifyOptions,
};

/// Asserts that `$result` failed as `PolyjoseError::$variant` and that the exported `code()` is
/// the variant's name, the stable code (ADR 0030 §5).
macro_rules! assert_fails {
    ($result:expr, $variant:ident) => {{
        let err: PolyjoseError = match $result {
            Ok(_) => panic!(
                "{} succeeded, expected {}",
                stringify!($result),
                stringify!($variant)
            ),
            Err(e) => e,
        };
        assert!(
            matches!(err, PolyjoseError::$variant { .. }),
            "{}: expected {}, got {err:?}",
            stringify!($result),
            stringify!($variant)
        );
        assert_eq!(err.code(), stringify!($variant), "{}", stringify!($result));
    }};
}

fn s(v: &str) -> String {
    v.to_owned()
}

/// Parses JSON text with the core's parser, so two texts compare as JSON values.
fn value(text: &str) -> Value {
    json::parse(text.as_bytes()).expect("valid JSON")
}

// --- RFC values -------------------------------------------------------------------------------

/// RFC 7517 Appendix A.2: the P-256 private key (with `use` and `kid`).
const RFC7517_A2_P256_PRIVATE: &str = r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE","use":"enc","kid":"1"}"#;

/// RFC 7517 Appendix A.1: the public half of [`RFC7517_A2_P256_PRIVATE`], in core member order.
const RFC7517_A1_P256_PUBLIC: &str = r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","use":"enc","kid":"1"}"#;

/// RFC 7638 §3.1: the RSA public key of the thumbprint example.
const RFC7638_RSA: &str = r#"{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","alg":"RS256","kid":"2011-04-29"}"#;

/// RFC 7638 §3.1: the SHA-256 thumbprint of [`RFC7638_RSA`].
const RFC7638_THUMBPRINT: &str = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

/// RFC 9278 §3 (example in §6): the thumbprint URI of [`RFC7638_RSA`].
const RFC9278_URI: &str =
    "urn:ietf:params:oauth:jwk-thumbprint:sha-256:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

// --- JWK (RFC 7517, RFC 7638, RFC 9278) -------------------------------------------------------

#[test]
fn jwk_parse_reserializes_a_valid_key_and_rejects_malformed_json() {
    // RFC 7517 §4: the key is validated and written back by the core, private members included.
    let parsed = jwk_parse(s(RFC7517_A2_P256_PRIVATE)).unwrap();
    assert!(value(&parsed) == value(RFC7517_A2_P256_PRIVATE), "{parsed}");
    assert_fails!(jwk_parse(s("{")), InvalidJson);
}

#[test]
fn jwk_to_public_drops_the_private_member_and_rejects_an_incomplete_key() {
    // RFC 7517 Appendix A.1 is Appendix A.2 without `d` (RFC 7518 §6.2.2.1).
    assert_eq!(
        jwk_to_public(s(RFC7517_A2_P256_PRIVATE)).unwrap(),
        RFC7517_A1_P256_PUBLIC
    );
    assert_fails!(
        jwk_to_public(s(r#"{"kty":"EC","crv":"P-256"}"#)),
        InvalidKey
    );
}

#[test]
fn jwk_thumbprint_is_rfc7638_and_rejects_an_unsupported_hash() {
    assert_eq!(
        jwk_thumbprint(s(RFC7638_RSA), Some(s("SHA-256"))).unwrap(),
        RFC7638_THUMBPRINT
    );
    // ADR 0054 §9: an absent hash is the core default, SHA-256 (RFC 9278 §5).
    assert_eq!(
        jwk_thumbprint(s(RFC7638_RSA), None).unwrap(),
        RFC7638_THUMBPRINT
    );
    // ADR 0054 §8.2: the core parses the name; SHA-384 is 64 base64url characters.
    assert_eq!(
        jwk_thumbprint(s(RFC7638_RSA), Some(s("sha384"))).unwrap(),
        jwk_thumbprint(s(RFC7638_RSA), Some(s("sha-384"))).unwrap()
    );
    assert_eq!(
        jwk_thumbprint(s(RFC7638_RSA), Some(s("SHA-384")))
            .unwrap()
            .len(),
        64
    );
    // ADR 0022: no SHA-1 thumbprints.
    assert_fails!(
        jwk_thumbprint(s(RFC7638_RSA), Some(s("SHA-1"))),
        UnsupportedAlgorithm
    );
}

#[test]
fn jwk_thumbprint_uri_is_rfc9278_and_rejects_malformed_json() {
    assert_eq!(
        jwk_thumbprint_uri(s(RFC7638_RSA), Some(s("SHA-256"))).unwrap(),
        RFC9278_URI
    );
    assert_eq!(
        jwk_thumbprint_uri(s(RFC7638_RSA), None).unwrap(),
        RFC9278_URI
    );
    // RFC 9278 §3, §4: the URI carries the IANA name whatever spelling was passed.
    let sha512 = jwk_thumbprint_uri(s(RFC7638_RSA), Some(s("sha512"))).unwrap();
    assert!(
        sha512.starts_with("urn:ietf:params:oauth:jwk-thumbprint:sha-512:"),
        "{sha512}"
    );
    assert_fails!(jwk_thumbprint_uri(s("{"), Some(s("SHA-256"))), InvalidJson);
    assert_fails!(jwk_thumbprint_uri(s("{"), None), InvalidJson);
    // ADR 0057 §2: the key is imported before the hash name is parsed.
    assert_fails!(jwk_thumbprint(s("{"), Some(s("SHA-1"))), InvalidJson);
    assert_fails!(jwk_thumbprint_uri(s("{"), Some(s("SHA-1"))), InvalidJson);
}

#[test]
fn jwks_select_returns_the_one_match_and_reports_the_core_codes() {
    // ADR 0054 §4, §9: one match is the member in core form; none is NoMatchingKey; two or more
    // is MultipleMatchingKeys (RFC 7517 §5.1).
    let ed25519 = r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","use":"sig","kid":"ed"}"#;
    let jwks = format!(r#"{{"keys":[{RFC7517_A1_P256_PUBLIC},{ed25519}]}}"#);
    let by = |kid: Option<&str>, alg: Option<&str>, key_use: Option<&str>| JwkSelector {
        kid: kid.map(s),
        alg: alg.map(s),
        key_use: key_use.map(s),
    };
    let selected = jwks_select(jwks.clone(), by(Some("1"), None, None)).unwrap();
    assert_eq!(selected, RFC7517_A1_P256_PUBLIC);
    let selected = jwks_select(jwks.clone(), by(None, Some("EdDSA"), Some("sig"))).unwrap();
    assert!(value(&selected) == value(ed25519), "{selected}");
    assert_fails!(
        jwks_select(jwks.clone(), by(Some("2"), None, None)),
        NoMatchingKey
    );
    assert_fails!(
        jwks_select(jwks.clone(), by(None, None, None)),
        MultipleMatchingKeys
    );
    // ADR 0054 §1.1: the core refuses the name.
    assert_fails!(
        jwks_select(jwks, by(None, Some("none"), None)),
        UnsupportedAlgorithm
    );
    // ADR 0054 §4: set import errors come first.
    assert_fails!(
        jwks_select(s("not a JWK Set"), by(None, Some("none"), None)),
        InvalidJson
    );
    // A private member comes back as imported (ADR 0054 §3).
    let private = format!(r#"{{"keys":[{RFC7517_A2_P256_PRIVATE}]}}"#);
    let selected = jwks_select(private, by(None, None, None)).unwrap();
    assert!(
        value(&selected) == value(RFC7517_A2_P256_PRIVATE),
        "{selected}"
    );
}

// --- Keys (RFC 7518 §6, RFC 8037, RFC 7468, RFC 5958, RFC 5280; ADR 0018) --------------------

/// The Ed25519 PKCS#8 fixture of feature 0005 (RFC 5958 §2, RFC 8410 §7) as PEM (RFC 7468
/// §10), DER, and the JWK the core reads from it (RFC 8037 §2).
const ED25519_PKCS8_PEM: &str =
    include_str!("../../../crates/polyjose/tests/data/keys/openssl/ed25519-pkcs8.pem");
const ED25519_PKCS8_DER: &[u8] =
    include_bytes!("../../../crates/polyjose/tests/data/keys/openssl/ed25519-pkcs8.der");
const ED25519_JWK: &str = include_str!(
    "../../../crates/polyjose/tests/data/keys/openssl/expected/ed25519-pkcs8.jwk.json"
);

/// The string member `name` of the JSON object `text`.
fn member(text: &str, name: &str) -> String {
    value(text)
        .get(name)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("no string member {name:?} in {text}"))
        .to_owned()
}

#[test]
fn jwk_generate_oct_makes_a_key_of_the_length_and_rejects_a_short_one() {
    // RFC 7518 §6.4.1: `k` holds the key octets, base64url encoded.
    let key = keys::jwk_generate_oct(32).unwrap();
    assert_eq!(member(&key, "kty"), "oct");
    assert_eq!(
        polyjose_ffi::util::base64url_decode(member(&key, "k"))
            .unwrap()
            .len(),
        32
    );
    // ADR 0030 §5: `len_bytes` outside 16..=512 is `InvalidKey`.
    assert_fails!(keys::jwk_generate_oct(15), InvalidKey);
}

#[test]
fn jwk_generate_ec_makes_a_private_key_and_rejects_an_unknown_curve() {
    // RFC 7518 §6.2.1–§6.2.2: kty, crv, x, y and the private d.
    let key = keys::jwk_generate_ec(s("P-256")).unwrap();
    assert_eq!(
        (member(&key, "kty"), member(&key, "crv")),
        (s("EC"), s("P-256"))
    );
    assert!(!member(&key, "d").is_empty());
    assert_fails!(keys::jwk_generate_ec(s("P-192")), UnsupportedAlgorithm);
}

#[test]
fn jwk_generate_okp_makes_a_private_key_and_rejects_an_unknown_curve() {
    // RFC 8037 §2: kty OKP, crv, x and the private d. Ed448 is out of scope (ADR 0006).
    let key = keys::jwk_generate_okp(s("Ed25519")).unwrap();
    assert_eq!(
        (member(&key, "kty"), member(&key, "crv")),
        (s("OKP"), s("Ed25519"))
    );
    assert!(!member(&key, "d").is_empty());
    assert_fails!(keys::jwk_generate_okp(s("Ed448")), UnsupportedAlgorithm);
}

#[test]
fn jwk_generate_for_alg_sets_alg_and_rejects_none() {
    // RFC 7518 §3.4: ES256 is P-256; RFC 7517 §4.4: the key's `alg` is set.
    let key = keys::jwk_generate_for_alg(s("ES256")).unwrap();
    assert_eq!(
        (member(&key, "alg"), member(&key, "crv")),
        (s("ES256"), s("P-256"))
    );
    // RFC 8725 §3.1, ADR 0007: `none` has no key.
    assert_fails!(keys::jwk_generate_for_alg(s("none")), UnsupportedAlgorithm);
}

#[test]
fn jwk_from_pem_reads_pkcs8_and_rejects_an_empty_body() {
    assert_eq!(
        keys::jwk_from_pem(s(ED25519_PKCS8_PEM)).unwrap(),
        jwk_parse(s(ED25519_JWK)).unwrap()
    );
    assert_fails!(
        keys::jwk_from_pem(s("-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n")),
        InvalidKey
    );
}

#[test]
fn jwk_from_der_reads_pkcs8_and_rejects_the_wrong_structure() {
    assert_eq!(
        keys::jwk_from_der(ED25519_PKCS8_DER.to_vec(), s("pkcs8")).unwrap(),
        jwk_parse(s(ED25519_JWK)).unwrap()
    );
    // ADR 0018 §3: no format sniffing; PKCS#8 bytes are not an SPKI.
    assert_fails!(
        keys::jwk_from_der(ED25519_PKCS8_DER.to_vec(), s("spki")),
        InvalidKey
    );
}

#[test]
fn jwk_to_pem_writes_the_fixture_and_rejects_an_unknown_format() {
    // ADR 0018 §3: export writes the layout OpenSSL writes, byte for byte.
    assert_eq!(
        keys::jwk_to_pem(s(ED25519_JWK), s("pkcs8")).unwrap(),
        ED25519_PKCS8_PEM
    );
    assert_fails!(
        keys::jwk_to_pem(s(ED25519_JWK), s("PKCS8")),
        UnsupportedAlgorithm
    );
}

#[test]
fn jwk_to_der_writes_the_fixture_and_rejects_an_unknown_format() {
    assert_eq!(
        keys::jwk_to_der(s(ED25519_JWK), s("pkcs8")).unwrap(),
        ED25519_PKCS8_DER
    );
    assert_fails!(
        keys::jwk_to_der(s(ED25519_JWK), s("der")),
        UnsupportedAlgorithm
    );
}

// --- JWS (RFC 7515) ---------------------------------------------------------------------------

/// RFC 7515 Appendix A.1 (RFC 7517 Appendix A.3): the HMAC key.
const RFC7515_A1_KEY: &str = r#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#;

/// The RFC 7515 Appendix A.1 key with its first octet changed: a valid key that is not the one.
const OTHER_HMAC_KEY: &str = r#"{"kty":"oct","k":"ByM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#;

/// RFC 7515 Appendix A.1.1: `BASE64URL(UTF8(JWS Protected Header))`, kept verbatim (its CRLF
/// line breaks are part of the signed octets).
const RFC7515_A1_PROTECTED_B64U: &str = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9";

/// RFC 7515 Appendix A.1.1: `BASE64URL(JWS Payload)`.
const RFC7515_A1_PAYLOAD_B64U: &str = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";

/// RFC 7515 Appendix A.1.1: the HMAC SHA-256 signature, base64url encoded.
const RFC7515_A1_SIGNATURE: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

/// RFC 7515 Appendix A.1.1: the JWS Compact Serialization.
const RFC7515_A1_JWS: &str = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

fn a1_payload() -> Vec<u8> {
    polyjose_ffi::util::base64url_decode(s(RFC7515_A1_PAYLOAD_B64U)).unwrap()
}

fn a1_signer() -> JwsSigner {
    JwsSigner {
        key: s(RFC7515_A1_KEY),
        protected_header: None,
        protected_b64u: Some(s(RFC7515_A1_PROTECTED_B64U)),
        unprotected_header: None,
    }
}

fn verify_options(allowed_algs: &[&str]) -> JwsVerifyOptions {
    JwsVerifyOptions {
        allowed_algs: allowed_algs.iter().map(|a| s(a)).collect(),
        detached_payload: None,
        max_input_len: None,
        max_signatures: None,
    }
}

#[test]
fn jws_sign_compact_reproduces_rfc7515_a1_and_rejects_both_header_forms() {
    let options = || JwsSignOptions {
        protected_header: None,
        protected_b64u: Some(s(RFC7515_A1_PROTECTED_B64U)),
        detached: false,
    };
    assert_eq!(
        jws_sign_compact(a1_payload(), s(RFC7515_A1_KEY), options()).unwrap(),
        RFC7515_A1_JWS
    );
    // ADR 0030 §4: exactly one of the two header forms.
    let both = JwsSignOptions {
        protected_header: Some(s(r#"{"alg":"HS256"}"#)),
        ..options()
    };
    assert_fails!(
        jws_sign_compact(a1_payload(), s(RFC7515_A1_KEY), both),
        InvalidHeader
    );
}

#[test]
fn jws_sign_flattened_signs_the_rfc7515_a1_input_and_rejects_a_signer_without_alg() {
    // RFC 7515 §7.2.2: the same signing input as A.1, so the same HMAC signature.
    let jws = jws_sign_flattened(a1_payload(), a1_signer(), false).unwrap();
    assert_eq!(member(&jws, "signature"), RFC7515_A1_SIGNATURE);
    assert_eq!(member(&jws, "payload"), RFC7515_A1_PAYLOAD_B64U);
    // RFC 7515 §4.1.1: `alg` is required, in some header.
    let no_alg = JwsSigner {
        protected_b64u: None,
        ..a1_signer()
    };
    assert_fails!(
        jws_sign_flattened(a1_payload(), no_alg, false),
        InvalidHeader
    );
}

#[test]
fn jws_sign_general_signs_the_rfc7515_a1_input_and_rejects_no_signers() {
    // RFC 7515 §7.2.1: one entry in `signatures`.
    let jws = jws_sign_general(a1_payload(), vec![a1_signer()], false).unwrap();
    let signatures = value(&jws);
    let first = &signatures
        .get("signatures")
        .and_then(Value::as_array)
        .expect("signatures array")[0];
    assert_eq!(
        first.get("signature").and_then(Value::as_str),
        Some(RFC7515_A1_SIGNATURE)
    );
    // RFC 7515 §7.2.1: `signatures` has at least one member.
    assert_fails!(jws_sign_general(a1_payload(), vec![], false), InvalidFormat);
}

#[test]
fn jws_verify_compact_verifies_rfc7515_a1_and_rejects_an_alg_outside_the_allow_list() {
    let verified = jws_verify_compact(
        s(RFC7515_A1_JWS),
        s(RFC7515_A1_KEY),
        verify_options(&["HS256"]),
    )
    .unwrap();
    assert_eq!(verified.alg, "HS256");
    assert_eq!(verified.payload, a1_payload());
    assert_eq!(verified.signature_index, 0);
    assert!(verified.protected_header.is_some());
    // RFC 8725 §3.1, ADR 0007: only the caller's allow-list admits an algorithm.
    assert_fails!(
        jws_verify_compact(
            s(RFC7515_A1_JWS),
            s(RFC7515_A1_KEY),
            verify_options(&["ES256"])
        ),
        AlgorithmNotAllowed
    );
}

#[test]
fn jws_verify_json_verifies_a_flattened_jws_and_rejects_the_wrong_key() {
    let jws = jws_sign_flattened(a1_payload(), a1_signer(), false).unwrap();
    let verified =
        jws_verify_json(jws.clone(), s(RFC7515_A1_KEY), verify_options(&["HS256"])).unwrap();
    assert_eq!(verified.payload, a1_payload());
    assert_eq!(verified.signature_index, 0);
    // RFC 7515 §5.2 step 8.
    assert_fails!(
        jws_verify_json(jws, s(OTHER_HMAC_KEY), verify_options(&["HS256"])),
        InvalidSignature
    );
}

// --- JWE (RFC 7516, RFC 7518 §4–§5) -----------------------------------------------------------

/// RFC 7516 Appendix A.3.3: the A128KW key.
const RFC7516_A3_KEY: &str = r#"{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}"#;

/// RFC 7516 Appendix A.3.7: the compact JWE (A128KW, A128CBC-HS256).
const RFC7516_A3_JWE: &str = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.U0m_YmjN04DJvceFICbCVQ";

/// RFC 7516 Appendix A.5: the flattened JWE JSON Serialization of the A.3 content, with `alg`
/// and `kid` in the per-recipient header and `jku` in the shared unprotected header.
const RFC7516_A5_JWE: &str = r#"{"protected":"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","unprotected":{"jku":"https://server.example.com/keys.jwks"},"header":{"alg":"A128KW","kid":"7"},"encrypted_key":"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ","iv":"AxY8DCtDaGlsbGljb3RoZQ","ciphertext":"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY","tag":"Mz-VPPyU4RlcuYv1IwIvzw"}"#;

/// RFC 7516 Appendix A.3: the plaintext.
const RFC7516_A3_PLAINTEXT: &[u8] = b"Live long and prosper.";

fn decrypt_options(allowed_algs: &[&str], allowed_enc: &[&str]) -> JweDecryptOptions {
    JweDecryptOptions {
        allowed_algs: allowed_algs.iter().map(|a| s(a)).collect(),
        allowed_enc: allowed_enc.iter().map(|e| s(e)).collect(),
        max_pbes2_count: None,
        max_decompressed_len: None,
        max_input_len: None,
        max_recipients: None,
        understood_crit: None,
    }
}

fn a3_decrypt_options() -> JweDecryptOptions {
    decrypt_options(&["A128KW"], &["A128CBC-HS256"])
}

/// Encryption to the RFC 7516 A.3 key with A128KW and A128CBC-HS256, as RFC 7516 Appendix A.3.
fn a3_encrypt_options(aad: Option<Vec<u8>>, recipients: usize) -> JweEncryptOptions {
    JweEncryptOptions {
        enc: s("A128CBC-HS256"),
        recipients: (0..recipients)
            .map(|_| JweRecipient {
                alg: s("A128KW"),
                key: s(RFC7516_A3_KEY),
                header: None,
                apu: None,
                apv: None,
                p2c: None,
                p2s_len: None,
            })
            .collect(),
        protected_header: None,
        shared_unprotected_header: None,
        aad,
        compress: false,
    }
}

#[test]
fn jwe_decrypt_compact_decrypts_rfc7516_a3_and_rejects_an_enc_outside_the_allow_list() {
    let decrypted =
        jwe_decrypt_compact(s(RFC7516_A3_JWE), s(RFC7516_A3_KEY), a3_decrypt_options()).unwrap();
    assert_eq!(decrypted.plaintext, RFC7516_A3_PLAINTEXT);
    assert_eq!(decrypted.recipient_index, 0);
    assert_eq!(member(&decrypted.header, "alg"), "A128KW");
    assert!(decrypted.protected_header.is_some());
    assert!(decrypted.aad.is_none());
    // RFC 8725 §3.1, ADR 0007: `enc` must be in the caller's list too.
    assert_fails!(
        jwe_decrypt_compact(
            s(RFC7516_A3_JWE),
            s(RFC7516_A3_KEY),
            decrypt_options(&["A128KW"], &["A256GCM"])
        ),
        AlgorithmNotAllowed
    );
}

#[test]
fn jwe_decrypt_json_decrypts_rfc7516_a5_and_rejects_the_wrong_key() {
    let decrypted =
        jwe_decrypt_json(s(RFC7516_A5_JWE), s(RFC7516_A3_KEY), a3_decrypt_options()).unwrap();
    assert_eq!(decrypted.plaintext, RFC7516_A3_PLAINTEXT);
    assert_eq!(decrypted.recipient_index, 0);
    let recipient_header = decrypted
        .recipient_header
        .expect("A.5 has a per-recipient header");
    assert_eq!(member(&recipient_header, "kid"), "7");
    let shared = decrypted
        .shared_unprotected_header
        .expect("A.5 has a shared header");
    assert_eq!(
        member(&shared, "jku"),
        "https://server.example.com/keys.jwks"
    );
    // RFC 7516 §11.5: one code for every failure once key management starts.
    assert_fails!(
        jwe_decrypt_json(
            s(RFC7516_A5_JWE),
            s(r#"{"kty":"oct","k":"AAECAwQFBgcICQoLDA0ODw"}"#),
            a3_decrypt_options()
        ),
        DecryptionFailed
    );
}

#[test]
fn jwe_encrypt_compact_round_trips_and_rejects_two_recipients() {
    let jwe =
        jwe_encrypt_compact(RFC7516_A3_PLAINTEXT.to_vec(), a3_encrypt_options(None, 1)).unwrap();
    let decrypted = jwe_decrypt_compact(jwe, s(RFC7516_A3_KEY), a3_decrypt_options()).unwrap();
    assert_eq!(decrypted.plaintext, RFC7516_A3_PLAINTEXT);
    // RFC 7516 §7.1: the compact form has exactly one recipient.
    assert_fails!(
        jwe_encrypt_compact(RFC7516_A3_PLAINTEXT.to_vec(), a3_encrypt_options(None, 2)),
        InvalidFormat
    );
}

#[test]
fn jwe_encrypt_json_round_trips_the_aad_and_rejects_an_unknown_form() {
    // RFC 7516 §5.1 step 14: the JWE AAD is authenticated and returned on decryption.
    let aad = b"additional authenticated data".to_vec();
    let jwe = jwe_encrypt_json(
        RFC7516_A3_PLAINTEXT.to_vec(),
        a3_encrypt_options(Some(aad.clone()), 1),
        s("flattened"),
    )
    .unwrap();
    let decrypted = jwe_decrypt_json(jwe, s(RFC7516_A3_KEY), a3_decrypt_options()).unwrap();
    assert_eq!(decrypted.plaintext, RFC7516_A3_PLAINTEXT);
    assert_eq!(decrypted.aad, Some(aad));
    // ADR 0030 §5: an unknown form name is `UnsupportedAlgorithm`.
    assert_fails!(
        jwe_encrypt_json(
            RFC7516_A3_PLAINTEXT.to_vec(),
            a3_encrypt_options(None, 1),
            s("compact")
        ),
        UnsupportedAlgorithm
    );
}

// --- JWT (RFC 7519, RFC 8725; ADR 0027, ADR 0028, ADR 0029) -----------------------------------

/// RFC 7519 §3.1: the example JWT, an HS256 JWS with the RFC 7515 Appendix A.1 key; its `exp`
/// is 1300819380.
const RFC7519_3_1_JWT: &str = RFC7515_A1_JWS;

/// 60 s before the RFC 7519 §3.1 `exp` (the `jwt/rfc7519/3-1-hs256-before-exp` vector).
const BEFORE_EXP: i64 = 1_300_819_320;

/// One hour after the RFC 7519 §3.1 `exp`, past any leeway the core allows (ADR 0027).
const AFTER_EXP: i64 = 1_300_822_980;

fn jwt_options(now: i64) -> JwtVerifyOptions {
    JwtVerifyOptions {
        allowed_algs: vec![s("HS256")],
        now: Some(now),
        issuers: None,
        audiences: None,
        subject: None,
        leeway: None,
        max_age: None,
        required_claims: None,
        allow_missing_exp: false,
        ignore_audience: false,
        typ: None,
        any_typ: false,
        profile: None,
        max_key_candidates: None,
        max_input_len: None,
    }
}

fn hs256_sign_options() -> JwtSignOptions {
    JwtSignOptions {
        alg: s("HS256"),
        typ: None,
        omit_typ: false,
        access_token: false,
        header: None,
    }
}

/// The JWK Set holding only the RFC 7515 Appendix A.1 key (RFC 7517 §5).
fn a1_jwks() -> String {
    format!(r#"{{"keys":[{RFC7515_A1_KEY}]}}"#)
}

/// A nested JWT (RFC 7519 §5.2, Appendix A.2): the RFC 7519 §3.1 JWT encrypted to the RFC 7516
/// A.3 key.
fn nested_jwt() -> String {
    jwt_encrypt_nested(s(RFC7519_3_1_JWT), a3_encrypt_options(None, 1)).unwrap()
}

#[test]
fn jwt_verify_validates_rfc7519_3_1_and_rejects_it_after_exp() {
    let verified = jwt_verify(
        s(RFC7519_3_1_JWT),
        s(RFC7515_A1_KEY),
        jwt_options(BEFORE_EXP),
    )
    .unwrap();
    assert_eq!(verified.alg, "HS256");
    assert_eq!(member(&verified.claims, "iss"), "joe");
    assert_eq!(member(&verified.header, "typ"), "JWT");
    // ADR 0029 §4: a single key is not a set.
    assert_eq!(verified.key_index, None);
    // RFC 7519 §4.1.4.
    assert_fails!(
        jwt_verify(
            s(RFC7519_3_1_JWT),
            s(RFC7515_A1_KEY),
            jwt_options(AFTER_EXP)
        ),
        TokenExpired
    );
}

#[test]
fn jwt_verify_with_jwks_reports_the_member_and_rejects_a_set_without_a_candidate() {
    let verified =
        jwt_verify_with_jwks(s(RFC7519_3_1_JWT), a1_jwks(), jwt_options(BEFORE_EXP)).unwrap();
    assert_eq!(member(&verified.claims, "iss"), "joe");
    assert_eq!(verified.key_index, Some(0));
    // ADR 0029 §4: no member can verify HS256 (the binding-surface/jwt-jwks-no-candidate
    // vector).
    let ec_only = format!(r#"{{"keys":[{RFC7517_A1_P256_PUBLIC}]}}"#);
    assert_fails!(
        jwt_verify_with_jwks(s(RFC7519_3_1_JWT), ec_only, jwt_options(BEFORE_EXP)),
        NoMatchingKey
    );
}

#[test]
fn jwt_sign_round_trips_and_rejects_typ_with_omit_typ() {
    let token = jwt_sign(
        s(r#"{"iss":"joe","exp":1300819380}"#),
        s(RFC7515_A1_KEY),
        hs256_sign_options(),
    )
    .unwrap();
    let verified = jwt_verify(token, s(RFC7515_A1_KEY), jwt_options(BEFORE_EXP)).unwrap();
    assert_eq!(member(&verified.claims, "iss"), "joe");
    // RFC 7519 §5.1: the core's default `typ`.
    assert_eq!(member(&verified.header, "typ"), "JWT");
    // ADR 0030 §4: `typ` together with `omit_typ` is `InvalidHeader`.
    let both = JwtSignOptions {
        typ: Some(s("JWT")),
        omit_typ: true,
        ..hs256_sign_options()
    };
    assert_fails!(
        jwt_sign(s(r#"{"iss":"joe"}"#), s(RFC7515_A1_KEY), both),
        InvalidHeader
    );
}

#[test]
fn jwt_encrypt_nested_sets_cty_and_rejects_a_token_that_is_not_a_jws() {
    let decrypted =
        jwe_decrypt_compact(nested_jwt(), s(RFC7516_A3_KEY), a3_decrypt_options()).unwrap();
    // RFC 7519 §5.2: the outer header says the content is a JWT.
    assert_eq!(member(&decrypted.header, "cty"), "JWT");
    assert_eq!(decrypted.plaintext, RFC7519_3_1_JWT.as_bytes());
    assert_fails!(
        jwt_encrypt_nested(s("not.a-jws"), a3_encrypt_options(None, 1)),
        InvalidFormat
    );
}

#[test]
fn jwt_decrypt_nested_validates_the_inner_jwt_and_rejects_an_enc_outside_the_allow_list() {
    let verified = jwt_decrypt_nested(
        nested_jwt(),
        s(RFC7516_A3_KEY),
        a3_decrypt_options(),
        s(RFC7515_A1_KEY),
        jwt_options(BEFORE_EXP),
    )
    .unwrap();
    assert_eq!(member(&verified.inner.claims, "iss"), "joe");
    assert_eq!(member(&verified.outer_header, "cty"), "JWT");
    assert_eq!(verified.recipient_index, 0);
    // RFC 8725 §3.1, ADR 0007.
    assert_fails!(
        jwt_decrypt_nested(
            nested_jwt(),
            s(RFC7516_A3_KEY),
            decrypt_options(&["A128KW"], &["A256GCM"]),
            s(RFC7515_A1_KEY),
            jwt_options(BEFORE_EXP),
        ),
        AlgorithmNotAllowed
    );
}

#[test]
fn jwt_decrypt_nested_with_jwks_reports_the_member_and_rejects_an_expired_inner_jwt() {
    let verified = jwt_decrypt_nested_with_jwks(
        nested_jwt(),
        s(RFC7516_A3_KEY),
        a3_decrypt_options(),
        a1_jwks(),
        jwt_options(BEFORE_EXP),
    )
    .unwrap();
    assert_eq!(member(&verified.inner.claims, "iss"), "joe");
    assert_eq!(verified.inner.key_index, Some(0));
    // RFC 7519 §4.1.4, checked on the inner JWT (RFC 7519 §7.2 step 8).
    assert_fails!(
        jwt_decrypt_nested_with_jwks(
            nested_jwt(),
            s(RFC7516_A3_KEY),
            a3_decrypt_options(),
            a1_jwks(),
            jwt_options(AFTER_EXP),
        ),
        TokenExpired
    );
}

// --- No input in errors (ADR 0030 §5) ---------------------------------------------------------

/// A distinctive value standing in for key material (the surface's marker style).
const MARKER: &str = "pj-SECRET-marker-7f3a";

/// Asserts that the failed `result` mentions the marker, raw or base64url-encoded, in none of
/// what a Kotlin or Swift caller can print: `code()`, `detail`, `toString()`/`description`
/// (`Display`) and `Debug`.
fn assert_no_marker<T>(what: &str, result: Result<T, PolyjoseError>) {
    let Err(err) = result else {
        panic!("{what} succeeded");
    };
    let encoded = polyjose_ffi::util::base64url_encode(MARKER.as_bytes().to_vec());
    for rendered in [
        err.code(),
        err.detail().to_owned(),
        err.to_string(),
        format!("{err:?}"),
    ] {
        for needle in [MARKER, encoded.as_str()] {
            assert!(
                !rendered.contains(needle),
                "{what}: error leaks input: {rendered}"
            );
        }
    }
}

#[test]
fn no_failing_export_puts_a_marked_private_member_into_its_error() {
    let marked_b64 = polyjose_ffi::util::base64url_encode(MARKER.as_bytes().to_vec());
    // The marker as a malformed EC `d`, as a well-formed `oct` key that fails later, and next to
    // a JSON syntax error, where a quoting parser would echo it.
    let marked_ec =
        RFC7517_A2_P256_PRIVATE.replace("870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE", MARKER);
    let marked_oct = format!(r#"{{"kty":"oct","k":"{marked_b64}"}}"#);
    let marked_json = format!(r#"{{"kty":"oct","k":"{MARKER}" {MARKER}}}"#);
    // The `oct` key is well formed, so only the two malformed keys fail to parse.
    for key in [&marked_ec, &marked_json] {
        assert_no_marker("jwk_parse", jwk_parse(key.clone()));
    }
    for key in [&marked_ec, &marked_oct, &marked_json] {
        assert_no_marker("jwk_to_der", keys::jwk_to_der(key.clone(), s("sec1")));
        assert_no_marker(
            "jws_sign_compact",
            jws_sign_compact(
                a1_payload(),
                key.clone(),
                JwsSignOptions {
                    protected_header: Some(s(r#"{"alg":"ES256"}"#)),
                    protected_b64u: None,
                    detached: false,
                },
            ),
        );
        assert_no_marker(
            "jws_verify_compact",
            jws_verify_compact(s(RFC7515_A1_JWS), key.clone(), verify_options(&["HS256"])),
        );
        assert_no_marker(
            "jwe_decrypt_compact",
            jwe_decrypt_compact(s(RFC7516_A3_JWE), key.clone(), a3_decrypt_options()),
        );
        assert_no_marker(
            "jwt_verify",
            jwt_verify(s(RFC7519_3_1_JWT), key.clone(), jwt_options(BEFORE_EXP)),
        );
        assert_no_marker(
            "jwt_verify_with_jwks",
            jwt_verify_with_jwks(
                s(RFC7519_3_1_JWT),
                format!(r#"{{"keys":[{key}]}}"#),
                jwt_options(BEFORE_EXP),
            ),
        );
    }
    // A marked PEM body, and a marked plaintext that fails to encrypt (RFC 7516 §7.1).
    assert_no_marker(
        "jwk_from_pem",
        keys::jwk_from_pem(format!(
            "-----BEGIN PRIVATE KEY-----\n{marked_b64}\n-----END PRIVATE KEY-----\n"
        )),
    );
    assert_no_marker(
        "jwe_encrypt_compact",
        jwe_encrypt_compact(MARKER.as_bytes().to_vec(), a3_encrypt_options(None, 2)),
    );
}
