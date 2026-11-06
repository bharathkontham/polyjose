//! 0004 T08: issuing signed JWTs with `jwt::sign` (RFC 7519 §7.1) through
//! the public API only (ADR 0008 layer 2).
//!
//! - The JWS Protected Header: `alg`, `typ` (default `JWT`, RFC 7519
//!   §5.1), `kid` copied from the key, then extra members (ADR 0027 §8).
//! - Exact output against tokens computed by the independent T02 oracle
//!   (`conformance/tools/jwt-oracle`, `node:crypto`).
//! - Every signing algorithm polyjose ships issues tokens that 0002's
//!   `verify_compact` accepts and whose payload parses back to the claims
//!   (ADR 0027 §8); RS*/PS* are `UnsupportedAlgorithm` (ADR 0021).
//! - No implicit claims (ADR 0027 §8).
//!
//! No test reads the wall clock (pipeline rule 8).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

mod common;

use polyjose::Error;
use polyjose::json::{self, Number, Value};
use polyjose::jwa::SigningAlg;
use polyjose::jwk::Jwk;
use polyjose::jws::{VerifyOptions, verify_compact};
use polyjose::jwt::{self, Audience, Claims, IssueOptions, NumericDate};
use polyjose::util::b64url_decode;

// ---------------------------------------------------------------------------
// Keys. Every private key here is published test data.
// ---------------------------------------------------------------------------

/// RFC 7515 Appendix A.1.1: the HMAC key of RFC 7515 A.1 and RFC 7519 §3.1
/// (the oracle's `oct-64`).
const OCT_64: &str = r#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#;
/// The oracle's `oct-32-kid-hs-32`: a 32-octet HMAC key with `kid` `hs-32`.
const OCT_32_KID: &str =
    r#"{"kty":"oct","k":"LEogBFIZxkmhKksJAqKSeN60dLO4zaahULwqC5j-8pY","kid":"hs-32"}"#;
/// The oracle's `oct-48`.
const OCT_48: &str =
    r#"{"kty":"oct","k":"HaXRYPWLBA7toQDZnVni2HLq2-9y_Z2UV7sJDibkvvOrbVCruY-ldC5ETUPV5e0n"}"#;
/// RFC 7515 Appendix A.3.1: the P-256 key.
const P256: &str = r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"}"#;
/// RFC 7520 §5.4.1's P-384 key, without its `kid` and `use` (the oracle's
/// `p384`).
const P384: &str = r#"{"kty":"EC","crv":"P-384","x":"YU4rRUzdmVqmRtWOs2OpDE_T5fsNIodcG8G5FWPrTPMyxpzsSOGaQLpe2FpxBmu2","y":"A8-yxCHxkfBz3hKZfI1jUYMjUhsEveZ9THuwFjH2sCNdtksRJU7D5-SkgaFL1ETP","d":"iTx2pk7wW-GqJkHcEkFQb2EFyYcO7RugmaW3mRrQVAOUiPommT0IdnYK2xDlZh-j"}"#;
/// RFC 7515 Appendix A.4.1: the P-521 key.
const P521: &str = r#"{"kty":"EC","crv":"P-521","x":"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk","y":"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2","d":"AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C"}"#;
/// RFC 7515 Appendix A.2.1's RS256 key, public members only (ADR 0021:
/// RSA keys appear as JSON test data only).
const RS_PUBLIC: &str = r#"{"kty":"RSA","n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ","e":"AQAB"}"#;

fn jwk(json: &str) -> Jwk {
    Jwk::from_json(json.as_bytes()).unwrap()
}

/// RFC 8037 Appendix A.1: the Ed25519 key (the oracle's `ed25519`).
fn ed25519() -> Jwk {
    jwk(&format!(
        r#"{{"kty":"OKP","crv":"Ed25519","x":"{}","d":"{}"}}"#,
        common::ED25519_X,
        common::ED25519_D
    ))
}

/// A secp256k1 key pair from `common` (d = 0x99, computed independently
/// of polyjose).
fn secp256k1() -> Jwk {
    let k = common::LEADING_ZEROS
        .iter()
        .find(|k| k.crv == "secp256k1")
        .unwrap();
    jwk(&format!(
        r#"{{"kty":"EC","crv":"secp256k1","x":"{}","y":"{}","d":"{}"}}"#,
        k.x, k.y, k.d
    ))
}

/// The key that signs `alg`.
fn key_for(alg: &SigningAlg) -> Jwk {
    match alg {
        SigningAlg::HS256 | SigningAlg::HS512 => jwk(OCT_64),
        SigningAlg::HS384 => jwk(OCT_48),
        SigningAlg::ES256 => jwk(P256),
        SigningAlg::ES384 => jwk(P384),
        SigningAlg::ES512 => jwk(P521),
        SigningAlg::ES256K => secp256k1(),
        SigningAlg::EdDSA | SigningAlg::Ed25519 => ed25519(),
        other => panic!("no signing key for {other:?}"),
    }
}

/// Every signing algorithm polyjose ships (ADR 0021, ADR 0027 §8).
const SIGNING_ALGS: [SigningAlg; 9] = [
    SigningAlg::HS256,
    SigningAlg::HS384,
    SigningAlg::HS512,
    SigningAlg::ES256,
    SigningAlg::ES384,
    SigningAlg::ES512,
    SigningAlg::ES256K,
    SigningAlg::EdDSA,
    SigningAlg::Ed25519,
];

/// RS*/PS*: verify-only, never issued (ADR 0021).
const RS_PS_ALGS: [SigningAlg; 6] = [
    SigningAlg::RS256,
    SigningAlg::RS384,
    SigningAlg::RS512,
    SigningAlg::PS256,
    SigningAlg::PS384,
    SigningAlg::PS512,
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// RFC 7519 §3.1's claims: `{"iss":"joe","exp":1300819380,
/// "http://example.com/is_root":true}` (without its CRLFs).
fn rfc7519_claims() -> Claims {
    let mut c = Claims::new();
    c.iss = Some("joe".into());
    c.exp = NumericDate::from_secs(1_300_819_380);
    c.insert("http://example.com/is_root", true).unwrap();
    c
}

/// A JSON integer.
fn int(i: i64) -> Value {
    Value::from(Number::from_i64(i).unwrap())
}

/// The three parts of a compact JWS.
fn parts(token: &str) -> [&str; 3] {
    let p: Vec<&str> = token.split('.').collect();
    assert_eq!(p.len(), 3, "a compact JWS has three parts: {token}");
    [p[0], p[1], p[2]]
}

/// The decoded JWS Protected Header text of `token`.
fn header_text(token: &str) -> String {
    String::from_utf8(b64url_decode(parts(token)[0]).unwrap()).unwrap()
}

/// The decoded payload octets of `token`.
fn payload(token: &str) -> Vec<u8> {
    b64url_decode(parts(token)[1]).unwrap()
}

/// Verifies `token` with 0002's verifier, allowing only `alg`.
fn verify(token: &str, alg: SigningAlg, key: &Jwk) -> polyjose::jws::Verified {
    let algs = [alg];
    let opts = VerifyOptions::new(&algs).unwrap();
    verify_compact(
        token,
        &key.to_public().unwrap_or_else(|| key.clone()),
        &opts,
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// Exact output (T02 oracle)
// ---------------------------------------------------------------------------
//
// The fixture tokens below were produced on 2026-11-06 with the T02 oracle
// (Node v24.21.0, OpenSSL 3.5.8), independently of polyjose:
//
//     node conformance/tools/jwt-oracle/gen.mjs spec.json out.json
//
// from this spec (keys named from conformance/tools/jwt-oracle/keys.json;
// `header_text` and `payload` are the exact octets polyjose is expected to
// write, the payload being RFC 7519 §3.1's claims without CRLFs):
//
//     [
//       {"description": "T08 HS256 exact", "operation": "jwt.issue", "input": {},
//        "expect": {"ok": true, "token": "$token"},
//        "jws": {"header_text": "{\"alg\":\"HS256\",\"typ\":\"JWT\"}",
//                "payload": "{\"iss\":\"joe\",\"exp\":1300819380,\"http://example.com/is_root\":true}",
//                "key": "oct-64"}},
//       {"description": "T08 EdDSA exact", ...same payload...,
//        "jws": {"header_text": "{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}", ..., "key": "ed25519"}},
//       {"description": "T08 HS256 kid + extra exact", ...same payload...,
//        "jws": {"header_text": "{\"alg\":\"HS256\",\"typ\":\"secevent+jwt\",\"kid\":\"hs-32\",\"x-tenant\":\"a\"}",
//                ..., "key": "oct-32-kid-hs-32"}}
//     ]
//
// HMAC and EdDSA are deterministic, so two runs of the oracle wrote
// identical files (checked with `cmp`).

/// HS256, RFC 7515 A.1 key, `typ: JWT` (oracle entry "T08 HS256 exact").
const ORACLE_HS256: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.d6nMDXnJZfNNj-1o1e75s6d0six0lkLp5hSrGaz4o9A";
/// EdDSA, RFC 8037 A.1 key, `typ: JWT` (oracle entry "T08 EdDSA exact").
const ORACLE_EDDSA: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.zXyykSyoFyMcEOqiABgsURO6qSw44FqPppA1649d5Hs73cKjPAcMO0X218x-wDYKz5cyJ5x0zqqtP6ajVB05Dg";
/// HS256 with a `kid` key, `typ: secevent+jwt` and one extra member
/// (oracle entry "T08 HS256 kid + extra exact").
const ORACLE_HS256_KID_EXTRA: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6InNlY2V2ZW50K2p3dCIsImtpZCI6ImhzLTMyIiwieC10ZW5hbnQiOiJhIn0.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.IDOAtWMXIFaj52DjOpIEq0H3drTmafr8WM6IcOk3II8";

#[test]
fn hs256_matches_the_oracle_exactly() {
    let token = jwt::sign(
        &rfc7519_claims(),
        &IssueOptions::new(SigningAlg::HS256),
        &jwk(OCT_64),
    )
    .unwrap();
    assert_eq!(token, ORACLE_HS256);
}

#[test]
fn eddsa_matches_the_oracle_exactly_and_repeatably() {
    let opts = IssueOptions::new(SigningAlg::EdDSA);
    let first = jwt::sign(&rfc7519_claims(), &opts, &ed25519()).unwrap();
    let second = jwt::sign(&rfc7519_claims(), &opts, &ed25519()).unwrap();
    // RFC 8032 §5.1.6: Ed25519 signing is deterministic.
    assert_eq!(first, second);
    assert_eq!(first, ORACLE_EDDSA);
}

#[test]
fn header_order_with_kid_and_extra_matches_the_oracle_exactly() {
    let opts = IssueOptions::new(SigningAlg::HS256)
        .typ("secevent+jwt")
        .header_param("x-tenant", "a")
        .unwrap();
    let token = jwt::sign(&rfc7519_claims(), &opts, &jwk(OCT_32_KID)).unwrap();
    assert_eq!(token, ORACLE_HS256_KID_EXTRA);
}

// ---------------------------------------------------------------------------
// The protected header (RFC 7519 §5, ADR 0027 §8)
// ---------------------------------------------------------------------------

#[test]
fn default_header_is_alg_and_typ_jwt() {
    let token = jwt::sign(
        &rfc7519_claims(),
        &IssueOptions::new(SigningAlg::ES256),
        &jwk(P256),
    )
    .unwrap();
    assert_eq!(header_text(&token), r#"{"alg":"ES256","typ":"JWT"}"#);
}

#[test]
fn kid_is_copied_from_the_key() {
    let token = jwt::sign(
        &rfc7519_claims(),
        &IssueOptions::new(SigningAlg::HS256),
        &jwk(OCT_32_KID),
    )
    .unwrap();
    assert_eq!(
        header_text(&token),
        r#"{"alg":"HS256","typ":"JWT","kid":"hs-32"}"#
    );
}

#[test]
fn explicit_typ_replaces_jwt() {
    let opts = IssueOptions::new(SigningAlg::EdDSA).typ("secevent+jwt");
    let token = jwt::sign(&rfc7519_claims(), &opts, &ed25519()).unwrap();
    assert_eq!(
        header_text(&token),
        r#"{"alg":"EdDSA","typ":"secevent+jwt"}"#
    );
}

#[test]
fn no_typ_omits_it() {
    let opts = IssueOptions::new(SigningAlg::HS256).no_typ();
    let token = jwt::sign(&rfc7519_claims(), &opts, &jwk(OCT_32_KID)).unwrap();
    assert_eq!(header_text(&token), r#"{"alg":"HS256","kid":"hs-32"}"#);
}

#[test]
fn access_token_sets_typ_at_jwt() {
    let opts = IssueOptions::new(SigningAlg::ES256).access_token();
    let token = jwt::sign(&rfc7519_claims(), &opts, &jwk(P256)).unwrap();
    assert_eq!(header_text(&token), r#"{"alg":"ES256","typ":"at+jwt"}"#);
}

#[test]
fn extra_members_follow_in_insertion_order() {
    let opts = IssueOptions::new(SigningAlg::HS256)
        .header_param("x-b", int(2))
        .unwrap()
        .header_param("jku", "https://issuer.example/jwks")
        .unwrap()
        .header_param("x-a", Value::Array(vec![Value::from("v")]))
        .unwrap();
    let token = jwt::sign(&rfc7519_claims(), &opts, &jwk(OCT_32_KID)).unwrap();
    assert_eq!(
        header_text(&token),
        r#"{"alg":"HS256","typ":"JWT","kid":"hs-32","x-b":2,"jku":"https://issuer.example/jwks","x-a":["v"]}"#
    );
}

#[test]
fn setting_an_extra_member_again_replaces_its_value() {
    let opts = IssueOptions::new(SigningAlg::HS256)
        .header_param("x-a", int(1))
        .unwrap()
        .header_param("x-a", int(2))
        .unwrap();
    let token = jwt::sign(&rfc7519_claims(), &opts, &jwk(OCT_64)).unwrap();
    assert_eq!(
        header_text(&token),
        r#"{"alg":"HS256","typ":"JWT","x-a":2}"#
    );
}

#[test]
fn forbidden_header_members_are_invalid_header() {
    // RFC 7797 §7 (`b64`), RFC 7515 §4.1.11 (`crit`: no extension is
    // understood for JWTs), RFC 7519 §5.2 (`cty` belongs to nesting),
    // RFC 7516 §4.1.2–§4.1.3 (`enc`, `zip`: JWE only); ADR 0027 §6, §8.
    for name in ["b64", "crit", "cty", "zip", "enc"] {
        let err = IssueOptions::new(SigningAlg::HS256)
            .header_param(name, "x")
            .unwrap_err();
        assert!(matches!(err, Error::InvalidHeader(_)), "{name}: {err:?}");
    }
    let err = IssueOptions::new(SigningAlg::HS256)
        .header_param("b64", true)
        .unwrap_err();
    assert!(matches!(err, Error::InvalidHeader(_)), "{err:?}");
    let err = IssueOptions::new(SigningAlg::HS256)
        .header_param("crit", Value::Array(vec![Value::from("b64")]))
        .unwrap_err();
    assert!(matches!(err, Error::InvalidHeader(_)), "{err:?}");
}

#[test]
fn members_set_by_the_options_or_the_key_are_invalid_header() {
    // `alg` comes from `IssueOptions::new`, `typ` from its typ setters and
    // `kid` from the key (ADR 0027 §8); a second source would make the
    // header ambiguous (RFC 7515 §4: names are unique).
    for name in ["alg", "typ", "kid"] {
        let err = IssueOptions::new(SigningAlg::HS256)
            .header_param(name, "x")
            .unwrap_err();
        assert!(matches!(err, Error::InvalidHeader(_)), "{name}: {err:?}");
    }
}

#[test]
fn a_registered_member_of_the_wrong_type_is_invalid_header() {
    // RFC 7515 §4.1.2 (`jku`: a URI string), §4.1.6 (`x5c`: an array of
    // strings).
    for (name, v) in [
        ("jku", int(1)),
        ("x5c", Value::from("not-an-array")),
        ("jwk", Value::from("not-an-object")),
    ] {
        let err = IssueOptions::new(SigningAlg::HS256)
            .header_param(name, v)
            .unwrap_err();
        assert!(matches!(err, Error::InvalidHeader(_)), "{name}: {err:?}");
    }
}

// ---------------------------------------------------------------------------
// Algorithms (ADR 0021, ADR 0026 §2 step 8, ADR 0027 §8)
// ---------------------------------------------------------------------------

#[test]
fn every_signing_alg_round_trips_through_jws_verify_and_claims_parse() {
    let mut claims = rfc7519_claims();
    claims.sub = Some("alice".into());
    claims.aud = Some(Audience::Many(vec!["a".into(), "b".into()]));
    claims.nbf = NumericDate::from_secs(1_300_819_000);
    claims.jti = Some("id-1".into());
    claims.insert("scope", "read write").unwrap();
    for alg in SIGNING_ALGS {
        let key = key_for(&alg);
        let token = jwt::sign(&claims, &IssueOptions::new(alg.clone()), &key).unwrap();
        let verified = verify(&token, alg.clone(), &key);
        assert_eq!(verified.alg, alg);
        assert_eq!(
            verified.protected.as_ref().unwrap().typ.as_deref(),
            Some("JWT"),
            "{alg:?}"
        );
        assert_eq!(
            Claims::from_json(&verified.payload).unwrap(),
            claims,
            "{alg:?}"
        );
    }
}

#[test]
fn rs_and_ps_issuing_is_unsupported_with_an_rsa_public_key() {
    // ADR 0021: polyjose holds no RSA private key, so RS*/PS* never sign.
    let key = jwk(RS_PUBLIC);
    for alg in RS_PS_ALGS {
        let err = jwt::sign(&rfc7519_claims(), &IssueOptions::new(alg.clone()), &key).unwrap_err();
        assert_eq!(err, Error::UnsupportedAlgorithm, "{alg:?}");
    }
}

#[test]
fn rs_and_ps_issuing_is_unsupported_before_the_key_is_looked_at() {
    // The algorithm decides before any key binding: an HMAC key (wrong
    // family, which would be KeyAlgorithmMismatch) still reports
    // UnsupportedAlgorithm (ADR 0021, ADR 0026 §2 step 8).
    for alg in RS_PS_ALGS {
        let err = jwt::sign(
            &rfc7519_claims(),
            &IssueOptions::new(alg.clone()),
            &jwk(OCT_32_KID),
        )
        .unwrap_err();
        assert_eq!(err, Error::UnsupportedAlgorithm, "{alg:?}");
    }
}

#[test]
fn none_is_never_issued() {
    // RFC 8725 §3.2, ADR 0007, ADR 0027 §8.
    let err = jwt::sign(
        &rfc7519_claims(),
        &IssueOptions::new(SigningAlg::None),
        &jwk(OCT_64),
    )
    .unwrap_err();
    assert_eq!(err, Error::AlgorithmNotAllowed);
}

#[test]
fn an_unknown_alg_is_unsupported() {
    // RFC 7515 §4.1.1.
    let err = jwt::sign(
        &rfc7519_claims(),
        &IssueOptions::new(SigningAlg::from("HS1024")),
        &jwk(OCT_64),
    )
    .unwrap_err();
    assert_eq!(err, Error::UnsupportedAlgorithm);
}

#[test]
fn a_public_ec_key_cannot_sign() {
    // ADR 0026 §2 step 8: a public-only key handed to a sign call.
    let public = jwk(P256).to_public().unwrap();
    let err = jwt::sign(
        &rfc7519_claims(),
        &IssueOptions::new(SigningAlg::ES256),
        &public,
    )
    .unwrap_err();
    assert_eq!(err, Error::KeyAlgorithmMismatch);
}

#[test]
fn a_key_of_the_wrong_family_or_strength_is_rejected() {
    // ADR 0026 §2 step 8: family mismatch, then RFC 7518 §3.2 strength.
    let err = jwt::sign(
        &rfc7519_claims(),
        &IssueOptions::new(SigningAlg::ES256),
        &jwk(OCT_64),
    )
    .unwrap_err();
    assert_eq!(err, Error::KeyAlgorithmMismatch);
    let err = jwt::sign(
        &rfc7519_claims(),
        &IssueOptions::new(SigningAlg::HS512),
        &jwk(OCT_32_KID),
    )
    .unwrap_err();
    assert!(matches!(err, Error::InvalidKey(_)), "{err:?}");
}

// ---------------------------------------------------------------------------
// No implicit claims (ADR 0027 §8)
// ---------------------------------------------------------------------------

#[test]
fn the_payload_is_exactly_the_claims_json() {
    for claims in [Claims::new(), rfc7519_claims()] {
        for alg in [SigningAlg::HS256, SigningAlg::ES256, SigningAlg::EdDSA] {
            let token =
                jwt::sign(&claims, &IssueOptions::new(alg.clone()), &key_for(&alg)).unwrap();
            assert_eq!(payload(&token), claims.to_json().as_bytes(), "{alg:?}");
        }
    }
}

#[test]
fn sign_adds_no_iat_exp_or_jti() {
    let mut claims = Claims::new();
    claims.insert("x", "y").unwrap();
    let token = jwt::sign(&claims, &IssueOptions::new(SigningAlg::HS256), &jwk(OCT_64)).unwrap();
    let parsed = json::parse(&payload(&token)).unwrap();
    let object = parsed.as_object().unwrap();
    for name in ["iat", "exp", "jti", "nbf", "iss", "sub", "aud"] {
        assert!(!object.contains(name), "{name} was added");
    }
    assert_eq!(payload(&token), br#"{"x":"y"}"#);
}

// ---------------------------------------------------------------------------
// Tester additions (T08 r1)
// ---------------------------------------------------------------------------

#[test]
fn an_ec_key_of_the_wrong_curve_is_rejected_for_the_alg() {
    // ADR 0026 §2 step 8: ES256 is bound to P-256 (RFC 7518 §3.4).
    let err = jwt::sign(
        &rfc7519_claims(),
        &IssueOptions::new(SigningAlg::ES256),
        &jwk(P384),
    )
    .unwrap_err();
    assert_eq!(err, Error::KeyAlgorithmMismatch);
    let err = jwt::sign(
        &rfc7519_claims(),
        &IssueOptions::new(SigningAlg::ES384),
        &jwk(P256),
    )
    .unwrap_err();
    assert_eq!(err, Error::KeyAlgorithmMismatch);
}

#[test]
fn rs_and_ps_with_an_ec_okp_or_rsa_key_are_unsupported() {
    // The algorithm check is first for every key kind.
    for key in [jwk(P256), ed25519(), jwk(RS_PUBLIC)] {
        for alg in [SigningAlg::RS256, SigningAlg::PS256] {
            let err = jwt::sign(&rfc7519_claims(), &IssueOptions::new(alg), &key).unwrap_err();
            assert_eq!(err, Error::UnsupportedAlgorithm);
        }
    }
}

#[test]
fn none_is_not_allowed_for_every_key_kind() {
    for key in [jwk(P256), ed25519(), jwk(RS_PUBLIC), jwk(OCT_32_KID)] {
        let err = jwt::sign(
            &rfc7519_claims(),
            &IssueOptions::new(SigningAlg::None),
            &key,
        )
        .unwrap_err();
        assert_eq!(err, Error::AlgorithmNotAllowed);
    }
}

#[test]
fn every_issued_header_round_trips_with_alg_typ_kid_order() {
    use polyjose::jws::ProtectedHeader;
    for alg in SIGNING_ALGS {
        let mut key_json = key_for(&alg).to_json();
        // add a kid through the JWK JSON
        assert!(key_json.ends_with('}'));
        key_json.pop();
        key_json.push_str(r#","kid":"k-1"}"#);
        let key = jwk(&key_json);
        let token = jwt::sign(&rfc7519_claims(), &IssueOptions::new(alg.clone()), &key).unwrap();
        let text = header_text(&token);
        assert_eq!(
            text,
            format!(r#"{{"alg":"{}","typ":"JWT","kid":"k-1"}}"#, alg.as_str())
        );
        let ph = ProtectedHeader::from_encoded(parts(&token)[0]).unwrap();
        assert_eq!(ph.encoded(), parts(&token)[0]);
        assert_eq!(ph.header().kid.as_deref(), Some("k-1"));
        verify(&token, alg, &key);
    }
}
