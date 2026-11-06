//! 0004 T07: verifying signed JWTs with `jwt::verify` (RFC 7519 §7.2)
//! through the public API only (ADR 0008 layer 2).
//!
//! - RFC 7519 §3.1 (HS256, RFC 7515 A.1 key), its `exp` boundaries
//!   (ADR 0027 §3) and RFC 7519 §6.1's Unsecured JWT (never accepted).
//! - RFC 7515 A.2 (RS256) as a JWT: public-key verification only
//!   (ADR 0021), with one key and through a JWK Set.
//! - The JWT header rules (ADR 0027 §6, step J1), the compact-only shape
//!   (ADR 0027 §6–§7) and the protected-header-only rule (ADR 0049 §2).
//! - The ADR 0027 §9 precedence between the JWS, key-selection and claim
//!   steps.
//! - The `VerifiedJwt` result, and ES256 / EdDSA end to end.
//!
//! The raw-payload tokens (duplicate claims, a string `exp`, a missing
//! `exp`, and the flattened rewrap) come from the independent T02 oracle,
//! `node:crypto` (the spec that made them is next to the tokens). The other tokens are the RFCs' own
//! or are signed here with 0002's `jws::sign_compact` and T08's
//! `jwt::sign`.
//!
//! Time comes only from `FixedClock`; no test reads the wall clock
//! (pipeline rule 8).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

mod common;

use polyjose::Error;
use polyjose::header::Header;
use polyjose::json::Value;
use polyjose::jwa::SigningAlg;
use polyjose::jwk::{Jwk, JwkSet};
use polyjose::jws::{ProtectedHeader, SignOptions, sign_compact};
use polyjose::jwt::{
    self, Audience, Claims, FixedClock, IssueOptions, Keys, NumericDate, Policy, VerifiedJwt,
};
use polyjose::util::{b64url_decode, b64url_encode};

// ---------------------------------------------------------------------------
// Test data. Every private key here is published test data.
// ---------------------------------------------------------------------------

/// RFC 7515 Appendix A.1.1: the HMAC key of RFC 7515 A.1 and RFC 7519 §3.1
/// (the oracle's `oct-64`).
const OCT_64: &str = r#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#;
/// The `k` of [`OCT_64`], which must never appear in any output.
const OCT_64_K: &str =
    "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";

/// RFC 7519 §3.1 (= RFC 7515 A.1): the HS256 JWT, CRLFs inside its header
/// and claims included.
const RFC7519_3_1: &str = concat!(
    "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9",
    ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
    ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
);
/// RFC 7519 §3.1's `exp`.
const EXP: i64 = 1_300_819_380;
/// RFC 7519 §3.1's private claim.
const IS_ROOT: &str = "http://example.com/is_root";

/// RFC 7519 §6.1: the Unsecured JWT (`alg: none`, empty signature), over
/// the §3.1 claims.
const RFC7519_6_1: &str = concat!(
    "eyJhbGciOiJub25lIn0",
    ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
    ".",
);

/// RFC 7515 Appendix A.2: the RS256 JWS over the §3.1 claims, a JWT.
const RFC7515_A2: &str = concat!(
    "eyJhbGciOiJSUzI1NiJ9",
    ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
    ".cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5",
    "jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb",
    "1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QO",
    "YEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw",
);
/// RFC 7515 Appendix A.2.1's RS256 key, public members only (ADR 0021: RSA
/// keys appear as public JSON test data only).
const A2_PUBLIC: &str = r#"{"kty":"RSA","n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ","e":"AQAB"}"#;

/// RFC 7515 Appendix A.3.1: the P-256 key.
const P256: &str = r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"}"#;

/// RFC 7520 §5.8 (Figure 159): a five-part compact JWE (A128KW, A128GCM).
const RFC7520_5_8_JWE: &str = concat!(
    "eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04MzMyLTQzZDktYTQ2OC04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIn0",
    ".CBI6oDw8MydIx1IBntf_lQcw2MmJKIQx",
    ".Qx0pmsDa8KnJc9Jo",
    ".AwliP-KmWgsZ37BvzCefNen6VTbRK3QMA4TkvRkH0tP1bTdhtFJgJxeVmJkLD61A1hnWGetdg11c9ADsnWgL56NyxwSYjU1Z",
    "EHcGkd3EkU0vjHi9gTlb90qSYFfeF0LwkcTtjbYKCsiNJQkcIp1yeM03OmuiYSoYJVSpf7ej6zaYcMv3WwdxDFl8REwOhNim",
    "k2Xld2JXq6BR53TSFkyT7PwVLuq-1GwtGHlQeg7gDT6xW0JqHDPn_H-puQsmthc9Zg0ojmJfqqFvETUxLAF-KjcBTS5dNy6e",
    "gwkYtOt8EIHK-oEsKYtZRaa8Z7MOZ7UGxGIMvEmxrGCPeJa14slv2-gaqK0kEThkaSqdYw0FkQZF",
    ".ER7MWJZ1FBI_NKvn7Zb1Lw",
);

// The four `ORACLE_*` tokens below were made by the T02 oracle from this
// spec, run once on 2026-11-06 with
// `node conformance/tools/jwt-oracle/gen.mjs spec.json out.json`
// (Node v24.21.0, OpenSSL 3.5.8). HS256 with `oct-64` is deterministic,
// so a re-run reproduces them byte for byte.
//
// ```json
// [
//   {"description":"duplicate exp behind a valid HS256 signature", …,
//    "jws":{"header":{"alg":"HS256","typ":"JWT"},
//           "payload":"{\"iss\":\"joe\",\"exp\":1300819380,\"exp\":1300819380}","key":"oct-64"}},
//   {"description":"exp as a string behind a valid HS256 signature", …,
//    "jws":{"header":{"alg":"HS256","typ":"JWT"},
//           "payload":"{\"iss\":\"joe\",\"exp\":\"1300819380\"}","key":"oct-64"}},
//   {"description":"no exp behind a valid HS256 signature", …,
//    "jws":{"header":{"alg":"HS256","typ":"JWT"},"payload":"{\"iss\":\"joe\"}","key":"oct-64"}},
//   {"description":"RFC 7519 §3.1 rewrapped as flattened JSON with an unprotected typ at+jwt", …,
//    "jws":{"header_text":"{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}",
//           "payload":"{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}",
//           "key":"oct-64","serialization":"flattened","unprotected":{"typ":"at+jwt"}}}
// ]
// ```

/// Oracle: `{"iss":"joe","exp":1300819380,"exp":1300819380}`, HS256.
const ORACLE_DUPLICATE_EXP: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImV4cCI6MTMwMDgxOTM4MH0.g1kCPMBvlKt98txOi09CJA5xG-x27v6JyxpJsI7MOS8";
/// Oracle: `{"iss":"joe","exp":"1300819380"}`, HS256.
const ORACLE_STRING_EXP: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqb2UiLCJleHAiOiIxMzAwODE5MzgwIn0.mmM2epfVchjCU1lJxUfr3x-KOIG1GA1QaDk4pmyl0DU";
/// Oracle: `{"iss":"joe"}`, HS256.
const ORACLE_NO_EXP: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqb2UifQ.CvbQM_74ZIYgIJHW5Z-qNuAPVhwLrPy1ozVyZcILw0s";
/// Oracle: RFC 7519 §3.1 rewrapped as a flattened JSON JWS (RFC 7515
/// §7.2.2) with the attacker's unprotected `{"typ":"at+jwt"}`. Its
/// `protected`, `payload` and `signature` are §3.1's three parts, so the
/// signature is valid.
const ORACLE_FLATTENED_REWRAP: &str = r#"{"payload":"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ","protected":"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9","header":{"typ":"at+jwt"},"signature":"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}"#;

/// An issuer and audience for the RFC 9068 tokens.
const ISSUER: &str = "https://issuer.example";
const AUDIENCE: &str = "https://api.example";

const HS256: [SigningAlg; 1] = [SigningAlg::HS256];
const ES256: [SigningAlg; 1] = [SigningAlg::ES256];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn jwk(json: &str) -> Jwk {
    Jwk::from_json(json.as_bytes()).unwrap()
}

fn set(members: &[&str]) -> JwkSet {
    JwkSet::from_json(format!(r#"{{"keys":[{}]}}"#, members.join(",")).as_bytes()).unwrap()
}

/// RFC 8037 Appendix A.1: the Ed25519 key.
fn ed25519() -> Jwk {
    jwk(&format!(
        r#"{{"kty":"OKP","crv":"Ed25519","x":"{}","d":"{}"}}"#,
        common::ED25519_X,
        common::ED25519_D
    ))
}

/// The public half of `key`.
fn public(key: &Jwk) -> Jwk {
    key.to_public()
        .expect("an asymmetric key has a public half")
}

/// `jws::sign_compact` over `payload` with the protected header given as
/// JSON text (signed as written, RFC 7515 §5.1 step 5).
fn sign_raw(header_json: &str, payload: &[u8], key: &Jwk) -> String {
    let protected = ProtectedHeader::from_encoded(&b64url_encode(header_json.as_bytes())).unwrap();
    sign_compact(&protected, payload, key, &SignOptions::new()).unwrap()
}

/// `token` with its JWS Payload part replaced by BASE64URL(`payload`) and
/// the original signature kept.
fn with_payload(token: &str, payload: &[u8]) -> String {
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3);
    format!("{}.{}.{}", parts[0], b64url_encode(payload), parts[2])
}

/// `token` with the low bit of its last signature octet flipped.
fn flip_signature(token: &str) -> String {
    let (head, signature) = token.rsplit_once('.').unwrap();
    let mut octets = b64url_decode(signature).unwrap();
    *octets.last_mut().unwrap() ^= 0x01;
    format!("{head}.{}", b64url_encode(&octets))
}

/// The seven claims RFC 9068 §2.2 requires of a JWT access token.
fn access_token_claims(exp: i64) -> Claims {
    let mut c = Claims::new();
    c.iss = Some(ISSUER.into());
    c.exp = NumericDate::from_secs(exp);
    c.aud = Some(Audience::One(AUDIENCE.into()));
    c.sub = Some("5ba552d67".into());
    c.insert("client_id", "s6BhdRkqt3").unwrap();
    c.iat = NumericDate::from_secs(EXP - 1_000);
    c.jti = Some("dbe39bf3a3ba4238a513f51d6e1691c4".into());
    c
}

/// RFC 7519 §3.1's claims as T03 holds them.
fn rfc7519_claims() -> Claims {
    let mut c = Claims::new();
    c.iss = Some("joe".into());
    c.exp = NumericDate::from_secs(EXP);
    c.insert(IS_ROOT, Value::Bool(true)).unwrap();
    c
}

/// `jwt::verify` of `token` with the RFC 7515 A.1 key, HS256 allowed, at
/// `now`.
fn verify_hs256_at(token: &str, now: i64) -> Result<VerifiedJwt, Error> {
    let clock = FixedClock(now);
    let policy = Policy::new(&clock, &HS256).unwrap();
    jwt::verify(token, Keys::One(&jwk(OCT_64)), &policy)
}

// ---------------------------------------------------------------------------
// RFC 7519 §3.1 and §6.1
// ---------------------------------------------------------------------------

/// RFC 7519 §3.1 at its `exp − 60`: accepted, with the claims, the
/// protected header and the `alg` returned (RFC 7519 §7.2).
#[test]
fn rfc7519_3_1_verifies_with_its_claims() {
    let v = verify_hs256_at(RFC7519_3_1, 1_300_819_320).unwrap();
    assert_eq!(v.claims.iss.as_deref(), Some("joe"));
    assert_eq!(v.claims.exp.and_then(|d| d.as_secs()), Some(EXP));
    assert_eq!(v.claims.get(IS_ROOT), Some(&Value::Bool(true)));
    assert_eq!(v.claims, rfc7519_claims());
    assert_eq!(v.alg, SigningAlg::HS256);
    assert_eq!(v.header.typ.as_deref(), Some("JWT"));
    assert_eq!(v.header.alg.as_deref(), Some("HS256"));
    assert_eq!(v.key_index, None);
    assert_eq!(v.kid, None);
}

/// ADR 0027 §3: `exp ≤ now − leeway` is expired. With the default leeway
/// of 60 s, exp + 60 is rejected and exp + 59 accepted; with leeway 0,
/// exp itself is rejected (RFC 7519 §4.1.4: "MUST be before").
#[test]
fn rfc7519_3_1_exp_boundaries() {
    assert_eq!(
        verify_hs256_at(RFC7519_3_1, 1_300_819_440),
        Err(Error::TokenExpired)
    );
    assert!(verify_hs256_at(RFC7519_3_1, 1_300_819_439).is_ok());

    let clock = FixedClock(EXP);
    let strict = Policy::new(&clock, &HS256).unwrap().leeway(0).unwrap();
    let key = jwk(OCT_64);
    assert_eq!(
        jwt::verify(RFC7519_3_1, Keys::One(&key), &strict).map(|_| ()),
        Err(Error::TokenExpired)
    );
    let clock = FixedClock(EXP - 1);
    let strict = Policy::new(&clock, &HS256).unwrap().leeway(0).unwrap();
    assert!(jwt::verify(RFC7519_3_1, Keys::One(&key), &strict).is_ok());
}

/// Every allowed list polyjose can build, for the `none` checks: one per
/// known algorithm, and all of them together.
fn every_allow_list() -> Vec<Vec<SigningAlg>> {
    let known: Vec<SigningAlg> = SigningAlg::KNOWN
        .iter()
        .filter(|alg| **alg != SigningAlg::None)
        .cloned()
        .collect();
    let mut lists: Vec<Vec<SigningAlg>> = known.iter().map(|alg| vec![alg.clone()]).collect();
    lists.push(known);
    lists
}

/// RFC 7519 §6.1's Unsecured JWT is `AlgorithmNotAllowed` with every
/// policy and key source (RFC 8725 §3.2, ADR 0007, ADR 0027 §6), before
/// any key or claim is looked at: here even an expired token, a
/// non-matching key and policies that relax the claims.
#[test]
fn rfc7519_6_1_unsecured_jwt_is_never_accepted() {
    let key = jwk(OCT_64);
    let keys = set(&[OCT_64]);
    for now in [1_300_819_320, EXP + 10_000] {
        let clock = FixedClock(now);
        for list in every_allow_list() {
            let policies = [
                Policy::new(&clock, &list).unwrap(),
                Policy::new(&clock, &list).unwrap().any_typ(),
                Policy::new(&clock, &list)
                    .unwrap()
                    .allow_missing_exp()
                    .ignore_audience(),
                Policy::access_token(&clock, &list, &[ISSUER], &[AUDIENCE]).unwrap(),
            ];
            for policy in &policies {
                for source in [Keys::One(&key), Keys::Set(&keys)] {
                    assert_eq!(
                        jwt::verify(RFC7519_6_1, source, policy).map(|_| ()),
                        Err(Error::AlgorithmNotAllowed),
                        "{list:?}"
                    );
                }
            }
        }
    }
    // A policy cannot allow `none` at all (RFC 8725 §3.2).
    let clock = FixedClock(0);
    assert!(matches!(
        Policy::new(&clock, &[SigningAlg::None]),
        Err(Error::AlgorithmNotAllowed)
    ));
    assert!(matches!(
        Policy::new(&clock, &[SigningAlg::HS256, SigningAlg::None]),
        Err(Error::AlgorithmNotAllowed)
    ));
}

// ---------------------------------------------------------------------------
// RFC 7515 A.2 (RS256, ADR 0021)
// ---------------------------------------------------------------------------

/// RFC 7515 A.2 is a JWT over the §3.1 claims; RS256 verification is a
/// public-key operation (ADR 0021), through one key or a JWK Set.
#[test]
fn rfc7515_a2_rs256_verifies_as_a_jwt() {
    let clock = FixedClock(1_300_819_320);
    let policy = Policy::new(&clock, &[SigningAlg::RS256]).unwrap();

    let key = jwk(A2_PUBLIC);
    let v = jwt::verify(RFC7515_A2, Keys::One(&key), &policy).unwrap();
    assert_eq!(v.alg, SigningAlg::RS256);
    assert_eq!(v.claims, rfc7519_claims());
    assert_eq!((v.key_index, v.kid), (None, None));

    let keys = set(&[A2_PUBLIC]);
    let v = jwt::verify(RFC7515_A2, Keys::Set(&keys), &policy).unwrap();
    assert_eq!(v.alg, SigningAlg::RS256);
    assert_eq!(v.claims, rfc7519_claims());
    assert_eq!((v.key_index, v.kid), (Some(0), None));

    // The claims checks still run: the same token later is expired.
    let late = FixedClock(EXP + 60);
    let policy = Policy::new(&late, &[SigningAlg::RS256]).unwrap();
    assert_eq!(
        jwt::verify(RFC7515_A2, Keys::Set(&keys), &policy).map(|_| ()),
        Err(Error::TokenExpired)
    );
}

// ---------------------------------------------------------------------------
// JWT header rules (ADR 0027 §5–§6, step J1)
// ---------------------------------------------------------------------------

/// RFC 7797 §7: "JSON Web Tokens MUST NOT use "b64" with a "false"
/// value", even when `crit` lists it (ADR 0027 §6). The JWS itself is a
/// valid RFC 7797 JWS.
#[test]
fn b64_false_is_invalid_header() {
    let key = jwk(OCT_64);
    let token = sign_raw(
        r#"{"alg":"HS256","b64":false,"crit":["b64"]}"#,
        br#"{"iss":"joe","exp":1300819380}"#,
        &key,
    );
    assert!(matches!(
        verify_hs256_at(&token, 1_300_819_320),
        Err(Error::InvalidHeader(_))
    ));
}

/// ADR 0027 §5: `cty: JWT` on a JWS would nest a JWS in a JWS (RFC 7519
/// §5.2), which is not supported; any other `cty` is ignored.
#[test]
fn cty_jwt_on_a_jws_is_invalid_header() {
    let key = jwk(OCT_64);
    let claims = rfc7519_claims().to_json();
    for cty in ["JWT", "jwt", "application/JWT"] {
        let token = sign_raw(
            &format!(r#"{{"alg":"HS256","cty":"{cty}"}}"#),
            claims.as_bytes(),
            &key,
        );
        assert!(
            matches!(
                verify_hs256_at(&token, 1_300_819_320),
                Err(Error::InvalidHeader(_))
            ),
            "{cty}"
        );
    }
    let token = sign_raw(
        r#"{"alg":"HS256","cty":"example"}"#,
        claims.as_bytes(),
        &key,
    );
    assert!(verify_hs256_at(&token, 1_300_819_320).is_ok());
}

/// ADR 0027 §5 (RFC 8725 §3.11–§3.12, RFC 9068 §4): an `at+jwt` token is
/// `InvalidHeader` under the default policy, and the same token verifies
/// with `Policy::access_token` and the RFC 9068 §2.2 claims.
#[test]
fn at_jwt_needs_the_access_token_policy() {
    let key = jwk(P256);
    let token = jwt::sign(
        &access_token_claims(EXP),
        &IssueOptions::new(SigningAlg::ES256).access_token(),
        &key,
    )
    .unwrap();
    let verifier = public(&key);
    let clock = FixedClock(1_300_819_320);

    let default = Policy::new(&clock, &ES256)
        .unwrap()
        .issuer(ISSUER)
        .audience(AUDIENCE);
    assert!(matches!(
        jwt::verify(&token, Keys::One(&verifier), &default),
        Err(Error::InvalidHeader(_))
    ));

    let access = Policy::access_token(&clock, &ES256, &[ISSUER], &[AUDIENCE]).unwrap();
    let v = jwt::verify(&token, Keys::One(&verifier), &access).unwrap();
    assert_eq!(v.header.typ.as_deref(), Some("at+jwt"));
    assert_eq!(v.claims, access_token_claims(EXP));
    assert_eq!(v.claims.get("client_id"), Some(&Value::from("s6BhdRkqt3")));

    // A generic JWT is not an access token.
    let generic = jwt::sign(
        &access_token_claims(EXP),
        &IssueOptions::new(SigningAlg::ES256),
        &key,
    )
    .unwrap();
    assert!(matches!(
        jwt::verify(&generic, Keys::One(&verifier), &access),
        Err(Error::InvalidHeader(_))
    ));
}

// ---------------------------------------------------------------------------
// Shape (ADR 0027 §6–§7) and the protected header (ADR 0049 §2)
// ---------------------------------------------------------------------------

/// A JWT is compact (RFC 7519 §1, §7.2 step 1). A five-part JWE goes to
/// the nested verifier, not this one (ADR 0027 §7); a JSON serialization
/// or a two-part string is `InvalidFormat` (ADR 0027 §6, ADR 0026 §1).
#[test]
fn non_compact_shapes_are_invalid_format() {
    let key = jwk(OCT_64);
    let keys = set(&[OCT_64]);
    let clock = FixedClock(1_300_819_320);
    let policy = Policy::new(&clock, &HS256).unwrap();
    let general = format!(
        r#"{{"payload":"{}","signatures":[{{"protected":"{}","signature":"{}"}}]}}"#,
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
        "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9",
        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    );
    let two_parts = RFC7519_3_1.rsplit_once('.').unwrap().0;
    let four_parts = format!("{RFC7519_3_1}.");
    for token in [
        RFC7520_5_8_JWE,
        ORACLE_FLATTENED_REWRAP,
        general.as_str(),
        two_parts,
        four_parts.as_str(),
        "",
    ] {
        for source in [Keys::One(&key), Keys::Set(&keys)] {
            assert!(
                matches!(
                    jwt::verify(token, source, &policy),
                    Err(Error::InvalidFormat(_))
                ),
                "{token}"
            );
        }
    }
}

/// ADR 0049 §2, ADR 0027 §6: RFC 7519 §3.1 rewrapped as flattened JSON
/// with an attacker's unprotected `{"typ":"at+jwt"}` and a valid
/// signature. The compact-only shape (step 1) decides first, under every
/// `typ` mode, so the unprotected header is never read.
#[test]
fn the_flattened_rewrap_is_invalid_format() {
    let key = jwk(OCT_64);
    let clock = FixedClock(1_300_819_320);
    for policy in [
        Policy::new(&clock, &HS256).unwrap(),
        Policy::new(&clock, &HS256).unwrap().expect_typ("at+jwt"),
        Policy::new(&clock, &HS256).unwrap().any_typ(),
    ] {
        assert!(matches!(
            jwt::verify(ORACLE_FLATTENED_REWRAP, Keys::One(&key), &policy),
            Err(Error::InvalidFormat(_))
        ));
    }
    // The rewrap's protected, payload and signature are §3.1's, so the
    // signature is valid: 0002's JSON verifier accepts it.
    let v = polyjose::jws::verify_json(
        ORACLE_FLATTENED_REWRAP,
        &key,
        &polyjose::jws::VerifyOptions::new(&HS256).unwrap(),
    )
    .unwrap();
    assert_eq!(v.unprotected.and_then(|h| h.typ).as_deref(), Some("at+jwt"));
}

/// ADR 0049 §2: `typ` comes from the protected header only. A compact
/// token's header is its protected header, so the `typ` that is checked
/// and returned is the signed one.
#[test]
fn typ_cty_and_kid_are_read_from_the_protected_header() {
    let key = jwk(OCT_64);
    let claims = rfc7519_claims().to_json();
    let token = sign_raw(
        r#"{"alg":"HS256","typ":"at+jwt","kid":"k1"}"#,
        claims.as_bytes(),
        &key,
    );
    let clock = FixedClock(1_300_819_320);
    let policy = Policy::new(&clock, &HS256).unwrap().expect_typ("at+jwt");
    let keyed = set(&[&format!(r#"{{"kty":"oct","kid":"k1","k":"{OCT_64_K}"}}"#)]);
    let v = jwt::verify(&token, Keys::Set(&keyed), &policy).unwrap();
    let mut expected = Header::new();
    expected.alg = Some("HS256".into());
    expected.typ = Some("at+jwt".into());
    expected.kid = Some("k1".into());
    assert_eq!(v.header, expected);
    assert_eq!((v.key_index, v.kid.as_deref()), (Some(0), Some("k1")));
}

// ---------------------------------------------------------------------------
// Precedence (ADR 0027 §9)
// ---------------------------------------------------------------------------

/// Step 9 before J3: a tampered payload of an expired token is
/// `InvalidSignature`; the claims are never parsed before the signature
/// verifies.
#[test]
fn a_tampered_expired_token_is_invalid_signature() {
    let late = 1_300_819_440;
    assert_eq!(verify_hs256_at(RFC7519_3_1, late), Err(Error::TokenExpired));
    for payload in [
        &br#"{"iss":"joe","exp":1300819381}"#[..],
        br#"{"iss":"joe","exp":"not a date"}"#,
        br#"{"exp":1,"exp":2}"#,
        b"not json",
    ] {
        let tampered = with_payload(RFC7519_3_1, payload);
        assert_eq!(
            verify_hs256_at(&tampered, late),
            Err(Error::InvalidSignature)
        );
    }
}

/// J3: duplicate claim names behind a valid signature are `InvalidJson`
/// (RFC 7519 §4; ADR 0027 §1).
#[test]
fn duplicate_claims_behind_a_valid_signature_are_invalid_json() {
    assert!(matches!(
        verify_hs256_at(ORACLE_DUPLICATE_EXP, 1_300_819_320),
        Err(Error::InvalidJson(_))
    ));
}

/// J3: `exp` as a string behind a valid signature is `InvalidClaim`
/// (RFC 7519 §4.1.4 "MUST be a number"; ADR 0027 §2), even when `exp`
/// could be ignored.
#[test]
fn a_string_exp_behind_a_valid_signature_is_invalid_claim() {
    assert_eq!(
        verify_hs256_at(ORACLE_STRING_EXP, 1_300_819_320),
        Err(Error::InvalidClaim("exp"))
    );
    let clock = FixedClock(1_300_819_320);
    let relaxed = Policy::new(&clock, &HS256).unwrap().allow_missing_exp();
    assert_eq!(
        jwt::verify(ORACLE_STRING_EXP, Keys::One(&jwk(OCT_64)), &relaxed).map(|_| ()),
        Err(Error::InvalidClaim("exp"))
    );
}

/// J4: `exp` is required by default (ADR 0007, ADR 0027 §3); the opt-out
/// is explicit.
#[test]
fn a_missing_exp_behind_a_valid_signature_is_invalid_claim() {
    assert_eq!(
        verify_hs256_at(ORACLE_NO_EXP, 1_300_819_320),
        Err(Error::InvalidClaim("exp"))
    );
    let clock = FixedClock(1_300_819_320);
    let relaxed = Policy::new(&clock, &HS256).unwrap().allow_missing_exp();
    let v = jwt::verify(ORACLE_NO_EXP, Keys::One(&jwk(OCT_64)), &relaxed).unwrap();
    assert_eq!(v.claims.iss.as_deref(), Some("joe"));
    assert_eq!(v.claims.exp, None);
}

/// Step 7 before J1: a disallowed `alg` with `typ: at+jwt` is
/// `AlgorithmNotAllowed`, with one key or a set.
#[test]
fn a_disallowed_alg_beats_a_wrong_typ() {
    let key = jwk(OCT_64);
    let token = sign_raw(
        r#"{"alg":"HS256","typ":"at+jwt"}"#,
        rfc7519_claims().to_json().as_bytes(),
        &key,
    );
    let clock = FixedClock(1_300_819_320);
    let policy = Policy::new(&clock, &ES256).unwrap();
    let keys = set(&[OCT_64]);
    for source in [Keys::One(&key), Keys::Set(&keys)] {
        assert_eq!(
            jwt::verify(&token, source, &policy).map(|_| ()),
            Err(Error::AlgorithmNotAllowed)
        );
    }
}

/// J1 before J2: `typ: at+jwt` with a `kid` no set member has is
/// `InvalidHeader`, not `NoMatchingKey`.
#[test]
fn a_wrong_typ_beats_an_unknown_kid() {
    let key = jwk(OCT_64);
    let token = sign_raw(
        r#"{"alg":"HS256","typ":"at+jwt","kid":"unknown"}"#,
        rfc7519_claims().to_json().as_bytes(),
        &key,
    );
    let keys = set(&[&format!(r#"{{"kty":"oct","kid":"k1","k":"{OCT_64_K}"}}"#)]);
    let clock = FixedClock(1_300_819_320);
    let policy = Policy::new(&clock, &HS256).unwrap();
    assert!(matches!(
        jwt::verify(&token, Keys::Set(&keys), &policy),
        Err(Error::InvalidHeader(_))
    ));
    // With the `typ` accepted, the unknown kid decides.
    let any = Policy::new(&clock, &HS256).unwrap().any_typ();
    assert_eq!(
        jwt::verify(&token, Keys::Set(&keys), &any).map(|_| ()),
        Err(Error::NoMatchingKey)
    );
}

/// J2 before J5: an unknown `kid` on an expired token is `NoMatchingKey`.
#[test]
fn an_unknown_kid_beats_expiry() {
    let key = jwk(OCT_64);
    let token = sign_raw(
        r#"{"alg":"HS256","kid":"unknown"}"#,
        rfc7519_claims().to_json().as_bytes(),
        &key,
    );
    let keys = set(&[&format!(r#"{{"kty":"oct","kid":"k1","k":"{OCT_64_K}"}}"#)]);
    let clock = FixedClock(EXP + 10_000);
    let policy = Policy::new(&clock, &HS256).unwrap();
    assert_eq!(
        jwt::verify(&token, Keys::Set(&keys), &policy).map(|_| ()),
        Err(Error::NoMatchingKey)
    );
    // With a key it can select, expiry decides.
    let matching = set(&[&format!(
        r#"{{"kty":"oct","kid":"unknown","k":"{OCT_64_K}"}}"#
    )]);
    assert_eq!(
        jwt::verify(&token, Keys::Set(&matching), &policy).map(|_| ()),
        Err(Error::TokenExpired)
    );
}

/// J2 with one key (ADR 0026 step 8): a key of the wrong family is
/// `KeyAlgorithmMismatch`, before the claims (the token is also expired).
#[test]
fn a_single_key_of_the_wrong_family_is_key_algorithm_mismatch() {
    let clock = FixedClock(EXP + 10_000);
    let policy = Policy::new(&clock, &HS256).unwrap();
    let ec = public(&jwk(P256));
    assert_eq!(
        jwt::verify(RFC7519_3_1, Keys::One(&ec), &policy).map(|_| ()),
        Err(Error::KeyAlgorithmMismatch)
    );
}

// ---------------------------------------------------------------------------
// The result
// ---------------------------------------------------------------------------

/// `VerifiedJwt::kid` is the selected key's `kid` (RFC 7517 §4.5): the set
/// member's with `Keys::Set`, the single key's with `Keys::One`, whose
/// `kid` is not compared with the header's (ADR 0029 §1).
#[test]
fn kid_and_key_index_come_from_the_key_that_verified() {
    let key = jwk(P256);
    let claims = rfc7519_claims().to_json();
    let token = sign_raw(
        r#"{"alg":"ES256","kid":"header-kid"}"#,
        claims.as_bytes(),
        &key,
    );
    let clock = FixedClock(1_300_819_320);
    let policy = Policy::new(&clock, &ES256).unwrap();

    // One key without a kid: none reported, though the header has one.
    let v = jwt::verify(&token, Keys::One(&public(&key)), &policy).unwrap();
    assert_eq!((v.key_index, v.kid), (None, None));
    assert_eq!(v.header.kid.as_deref(), Some("header-kid"));

    // One key with its own kid: that kid, though it differs from the
    // header's.
    let p256 = public(&key);
    let mine = format!(
        r#"{{"kty":"EC","crv":"P-256","kid":"mine","x":"{}","y":"{}"}}"#,
        "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
    );
    let v = jwt::verify(&token, Keys::One(&jwk(&mine)), &policy).unwrap();
    assert_eq!((v.key_index, v.kid.as_deref()), (None, Some("mine")));
    drop(p256);

    // A set: the selected member's index and kid.
    let other = public(&ed25519());
    let other_json = other.to_json();
    let member = format!(
        r#"{{"kty":"EC","crv":"P-256","kid":"header-kid","x":"{}","y":"{}"}}"#,
        "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
    );
    let keys = set(&[other_json.as_str(), OCT_64, &member]);
    let v = jwt::verify(&token, Keys::Set(&keys), &policy).unwrap();
    assert_eq!(
        (v.key_index, v.kid.as_deref()),
        (Some(2), Some("header-kid"))
    );
}

/// `VerifiedJwt`'s `Debug` prints no key material: it holds none, and the
/// HMAC key's octets appear nowhere in it.
#[test]
fn verified_jwt_debug_has_no_key_material() {
    let v = verify_hs256_at(RFC7519_3_1, 1_300_819_320).unwrap();
    let debug = format!("{v:?}");
    assert!(!debug.contains(OCT_64_K));
    let k = b64url_decode(OCT_64_K).unwrap();
    assert!(!debug.contains(&b64url_encode(&k[..16])));
    assert!(debug.contains("VerifiedJwt"));
}

// ---------------------------------------------------------------------------
// ES256 and EdDSA end to end
// ---------------------------------------------------------------------------

/// Tokens signed by 0002's `sign_compact` over T03's serialized claims
/// verify, with ES256 (RFC 7518 §3.4) and EdDSA / Ed25519 (RFC 8037 §3.1,
/// RFC 9864 §2.2); one flipped signature bit is `InvalidSignature`.
#[test]
fn es256_and_eddsa_end_to_end() {
    let clock = FixedClock(1_300_819_320);
    let claims = rfc7519_claims();
    for (alg, key) in [
        (SigningAlg::ES256, jwk(P256)),
        (SigningAlg::EdDSA, ed25519()),
        (SigningAlg::Ed25519, ed25519()),
    ] {
        let mut header = Header::new();
        header.alg = Some(alg.to_string());
        header.typ = Some("JWT".into());
        let token = sign_compact(
            &ProtectedHeader::new(header).unwrap(),
            claims.to_json().as_bytes(),
            &key,
            &SignOptions::new(),
        )
        .unwrap();
        let allowed = [alg.clone()];
        let policy = Policy::new(&clock, &allowed).unwrap();
        let verifier = public(&key);

        let v = jwt::verify(&token, Keys::One(&verifier), &policy).unwrap();
        assert_eq!((&v.alg, &v.claims), (&alg, &claims));
        let keys = JwkSet::from_json(
            format!(r#"{{"keys":[{}]}}"#, verifier.to_json().as_str()).as_bytes(),
        )
        .unwrap();
        let v = jwt::verify(&token, Keys::Set(&keys), &policy).unwrap();
        assert_eq!(v.key_index, Some(0));

        let flipped = flip_signature(&token);
        assert_eq!(
            jwt::verify(&flipped, Keys::One(&verifier), &policy).map(|_| ()),
            Err(Error::InvalidSignature),
            "{alg:?}"
        );
        assert_eq!(
            jwt::verify(&flipped, Keys::Set(&keys), &policy).map(|_| ()),
            Err(Error::InvalidSignature),
            "{alg:?}"
        );
    }
}

/// T08's `jwt::sign` and `jwt::verify` round-trip.
#[test]
fn jwt_sign_round_trips() {
    let key = ed25519();
    let claims = access_token_claims(EXP);
    let token = jwt::sign(&claims, &IssueOptions::new(SigningAlg::Ed25519), &key).unwrap();
    let clock = FixedClock(1_300_819_320);
    let policy = Policy::new(&clock, &[SigningAlg::Ed25519])
        .unwrap()
        .issuer(ISSUER)
        .audience(AUDIENCE)
        .subject("5ba552d67");
    let v = jwt::verify(&token, Keys::One(&public(&key)), &policy).unwrap();
    assert_eq!(v.claims, claims);
    assert_eq!(v.header.typ.as_deref(), Some("JWT"));
}
