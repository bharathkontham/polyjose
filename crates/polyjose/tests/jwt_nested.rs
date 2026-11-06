//! 0004 T09: nested JWTs, a signed JWT encrypted as a compact JWE
//! (RFC 7519 §5.2, §7.1 step 5, §7.2 step 8, §11.2; RFC 8725 §3.3, §3.11;
//! ADR 0027 §7, §9), through the public API only (ADR 0008 layer 2).
//!
//! - Decrypt-then-verify across the JWE key management modes, with an
//!   ES256 or EdDSA inner JWS; RSA-OAEP-256 never decrypts (ADR 0021).
//! - Both layers validated with the caller's keys and algorithms
//!   (RFC 8725 §3.3).
//! - The shape and typing rules (ADR 0027 §6–§7): outer `cty`, depth 1,
//!   separate entry points, explicit typing on the inner JWS.
//! - Replicated claims (RFC 7519 §5.3) and the ADR 0027 §9 precedence.
//! - The outer typing read from the JWE Protected Header only, and the
//!   compact-only shape (ADR 0050 §3, ADR 0049 §2).
//! - No part of the decrypted inner token in `Debug` or errors
//!   (ADR 0049 §4).
//!
//! Time comes only from `FixedClock`; no test reads the wall clock
//! (pipeline rule 8). PBES2 tokens use a small `p2c`, inside the default
//! decrypt budget (ADR 0023, ADR 0050 §2). RSA keys appear as public JWK
//! JSON only (ADR 0021).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

mod common;

use polyjose::Error;
use polyjose::header::Header;
use polyjose::jwa::{ContentEncAlg, KeyMgmtAlg, SigningAlg};
use polyjose::jwe::{DecryptPolicy, Encryptor, JsonForm, Recipient};
use polyjose::jwk::{EcCurve, Jwk, OkpCurve};
use polyjose::jws::{ProtectedHeader, SignOptions, sign_compact};
use polyjose::jwt::{
    self, Audience, Claims, FixedClock, IssueOptions, Keys, NumericDate, Policy, VerifiedNestedJwt,
};
use polyjose::keys::{KeySpec, generate};
use polyjose::util::{b64url_decode, b64url_encode};

use ContentEncAlg as E;
use KeyMgmtAlg as A;

// ---------------------------------------------------------------------------
// Test data. Every private key here is published test data or generated
// per run.
// ---------------------------------------------------------------------------

/// RFC 7515 Appendix A.3.1: the P-256 key (the inner ES256 signer).
const P256: &str = r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"}"#;
/// RFC 7520 §5.8.1: the A128KW key-encryption key.
const KEK: &str = r#"{"kty":"oct","k":"GZy6sIZ6wl9NJOKB-jnmVQ"}"#;
/// RFC 7520 §5.3.1: the PBES2 password.
const PASSWORD: &[u8] = b"entrap_o\xe2\x80\x93peter_long\xe2\x80\x93credit_tun";
/// RFC 7515 Appendix A.2.1's 2048-bit RSA key, public members only
/// (ADR 0021: RSA keys appear as public JSON test data only).
const RSA_PUBLIC: &str = r#"{"kty":"RSA","n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ","e":"AQAB"}"#;

/// The inner tokens' `exp` and the fixed time, one minute before it.
const EXP: i64 = 1_300_819_380;
const NOW: i64 = EXP - 60;
/// Past `exp` plus the 60 s default leeway (ADR 0027 §3).
const LATE: i64 = EXP + 60;

const ISSUER: &str = "https://issuer.example";
const AUDIENCE: &str = "https://api.example";

const SIGNING: [SigningAlg; 2] = [SigningAlg::ES256, SigningAlg::EdDSA];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn jwk(json: &str) -> Jwk {
    Jwk::from_json(json.as_bytes()).unwrap()
}

fn header(json: &str) -> Header {
    Header::from_json(json.as_bytes()).unwrap()
}

fn code<T>(r: polyjose::Result<T>) -> &'static str {
    match r {
        Ok(_) => "ok",
        Err(e) => e.code(),
    }
}

/// The inner signer: RFC 7515 A.3.1's P-256 key.
fn es256_key() -> Jwk {
    jwk(P256)
}

/// RFC 8037 Appendix A.1: the Ed25519 key.
fn ed25519_key() -> Jwk {
    jwk(&format!(
        r#"{{"kty":"OKP","crv":"Ed25519","x":"{}","d":"{}"}}"#,
        common::ED25519_X,
        common::ED25519_D
    ))
}

fn public(key: &Jwk) -> Jwk {
    key.to_public().unwrap()
}

/// `iss`, `sub` and `exp`, the inner claims of most tests.
fn claims() -> Claims {
    let mut c = Claims::new();
    c.iss = Some(ISSUER.into());
    c.sub = Some("alice".into());
    c.exp = NumericDate::from_secs(EXP);
    c
}

/// A signed JWT (T08's `jwt::sign`) over `claims`.
fn signed(claims: &Claims, alg: SigningAlg, key: &Jwk) -> String {
    jwt::sign(claims, &IssueOptions::new(alg), key).unwrap()
}

/// An ES256 inner JWT over [`claims`].
fn inner_es256() -> String {
    signed(&claims(), SigningAlg::ES256, &es256_key())
}

/// `jws::sign_compact` over `payload` with the protected header given as
/// JSON text (signed as written, RFC 7515 §5.1 step 5).
fn sign_raw(header_json: &str, payload: &[u8], key: &Jwk) -> String {
    let protected = ProtectedHeader::from_encoded(&b64url_encode(header_json.as_bytes())).unwrap();
    sign_compact(&protected, payload, key, &SignOptions::new()).unwrap()
}

/// An encryptor for one recipient, with `protected` as its extra
/// protected header parameters.
fn encryptor(enc: ContentEncAlg, recipient: Recipient, protected: Header) -> Encryptor {
    Encryptor::new(enc)
        .recipient(recipient)
        .protected_header(protected)
}

/// The A128KW + A128GCM encryptor of most tests, with `protected` as its
/// extra protected header parameters.
fn kw(protected: &str) -> Encryptor {
    encryptor(
        E::A128GCM,
        Recipient::new(A::A128KW, &jwk(KEK)),
        header(protected),
    )
}

/// `plaintext` as a compact JWE with A128KW + A128GCM and the protected
/// header parameters `protected`, built with 0003's encryptor directly, so
/// the outer header can be anything (no `cty`, a wrong `cty`, replicated
/// claims).
fn nest_raw(plaintext: &str, protected: &str) -> String {
    kw(protected).encrypt_compact(plaintext.as_bytes()).unwrap()
}

/// `inner` as a nested JWT made by `jwt::encrypt_nested` with A128KW +
/// A128GCM and no caller protected header.
fn nest(inner: &str) -> String {
    jwt::encrypt_nested(inner, &kw("{}")).unwrap()
}

/// The protected header of compact JWE `token`, as sent.
fn outer_header_of(token: &str) -> Header {
    let first = token.split('.').next().unwrap();
    Header::from_json(&b64url_decode(first).unwrap()).unwrap()
}

/// Every JWE algorithm these tests decrypt with, and every `enc`.
fn decrypt_policy() -> DecryptPolicy {
    DecryptPolicy::new(
        &[
            A::Dir,
            A::A128KW,
            A::EcdhEs,
            A::EcdhEsA128KW,
            A::Pbes2Hs256A128KW,
            A::RsaOaep256,
        ],
        E::KNOWN,
    )
    .unwrap()
}

/// `decrypt_nested` with the A128KW key, the ES256 public key and a
/// default policy at `now`.
fn open_at(token: &str, now: i64) -> polyjose::Result<VerifiedNestedJwt> {
    let clock = FixedClock(now);
    let policy = Policy::new(&clock, &SIGNING).unwrap();
    let key = public(&es256_key());
    jwt::decrypt_nested(
        token,
        &jwk(KEK),
        &decrypt_policy(),
        Keys::One(&key),
        &policy,
    )
}

fn open(token: &str) -> polyjose::Result<VerifiedNestedJwt> {
    open_at(token, NOW)
}

/// `token` (five parts) with the low bit of its authentication tag's last
/// octet flipped.
fn flip_tag(token: &str) -> String {
    let (head, tag) = token.rsplit_once('.').unwrap();
    let mut octets = b64url_decode(tag).unwrap();
    *octets.last_mut().unwrap() ^= 0x01;
    format!("{head}.{}", b64url_encode(&octets))
}

// ---------------------------------------------------------------------------
// Decrypt-then-verify across the key management modes (RFC 7519 §7.2)
// ---------------------------------------------------------------------------

/// RFC 7519 §7.1 step 5, §7.2 step 8, §11.2: an ES256 inner JWT nested by
/// `encrypt_nested` with `dir`, A128KW, ECDH-ES+A128KW (P-256), ECDH-ES
/// (X25519) and PBES2-HS256+A128KW is a compact JWE with `cty: JWT`, and
/// it decrypts, verifies and validates; the result carries the inner
/// verification, the outer protected header and the recipient index.
#[test]
fn every_outer_mode_decrypts_then_verifies() {
    let dir = generate(KeySpec::Oct { bytes: 32 }).unwrap();
    let p256 = generate(KeySpec::Ec(EcCurve::P256)).unwrap();
    let x25519 = generate(KeySpec::Okp(OkpCurve::X25519)).unwrap();
    let password = jwk(&format!(
        r#"{{"kty":"oct","k":"{}"}}"#,
        b64url_encode(PASSWORD)
    ));
    let cases: [(Recipient, ContentEncAlg, &Jwk, &str); 5] = [
        (Recipient::new(A::Dir, &dir), E::A256GCM, &dir, "dir"),
        (
            Recipient::new(A::A128KW, &jwk(KEK)),
            E::A128GCM,
            &jwk(KEK),
            "A128KW",
        ),
        (
            Recipient::new(A::EcdhEsA128KW, &public(&p256)),
            E::A128GCM,
            &p256,
            "ECDH-ES+A128KW",
        ),
        (
            Recipient::new(A::EcdhEs, &public(&x25519)),
            E::A256GCM,
            &x25519,
            "ECDH-ES",
        ),
        (
            Recipient::new(A::Pbes2Hs256A128KW, &password).p2c(1_000),
            E::A128GCM,
            &password,
            "PBES2-HS256+A128KW",
        ),
    ];
    let clock = FixedClock(NOW);
    let policy = Policy::new(&clock, &SIGNING).unwrap();
    let verifier = public(&es256_key());
    let inner = inner_es256();
    for (recipient, enc, decrypt_key, alg) in cases {
        let e = Encryptor::new(enc.clone()).recipient(recipient);
        let token = jwt::encrypt_nested(&inner, &e).unwrap_or_else(|e| panic!("{alg}: {e}"));
        assert_eq!(token.split('.').count(), 5, "{alg}");
        assert_eq!(outer_header_of(&token).cty.as_deref(), Some("JWT"), "{alg}");
        let v = jwt::decrypt_nested(
            &token,
            decrypt_key,
            &decrypt_policy(),
            Keys::One(&verifier),
            &policy,
        )
        .unwrap_or_else(|e| panic!("{alg}: {e}"));
        assert_eq!(v.inner.claims, claims(), "{alg}");
        assert_eq!(v.inner.alg, SigningAlg::ES256, "{alg}");
        assert_eq!(v.inner.header.typ.as_deref(), Some("JWT"), "{alg}");
        assert_eq!(v.outer_header.alg.as_deref(), Some(alg));
        assert_eq!(v.outer_header.enc, Some(enc), "{alg}");
        assert_eq!(v.outer_header.cty.as_deref(), Some("JWT"), "{alg}");
        assert_eq!(v.recipient, 0, "{alg}");
    }
}

/// ADR 0021: an EdDSA inner JWT nested by `encrypt_nested` for an
/// RSA-OAEP-256 recipient (a public-key operation) is produced, but never
/// decrypted: there is no RSA private-key operation, so the JWE layer
/// answers `UnsupportedAlgorithm` even when the policy allows the `alg`.
#[test]
fn rsa_oaep_256_encrypts_but_never_decrypts() {
    let rsa = jwk(RSA_PUBLIC);
    let inner = signed(&claims(), SigningAlg::EdDSA, &ed25519_key());
    let e = Encryptor::new(E::A256GCM).recipient(Recipient::new(A::RsaOaep256, &rsa));
    let token = jwt::encrypt_nested(&inner, &e).unwrap();
    assert_eq!(token.split('.').count(), 5);
    let h = outer_header_of(&token);
    assert_eq!(h.alg.as_deref(), Some("RSA-OAEP-256"));
    assert_eq!(h.cty.as_deref(), Some("JWT"));
    let clock = FixedClock(NOW);
    let policy = Policy::new(&clock, &SIGNING).unwrap();
    let verifier = public(&ed25519_key());
    let r = jwt::decrypt_nested(
        &token,
        &rsa,
        &decrypt_policy(),
        Keys::One(&verifier),
        &policy,
    );
    assert_eq!(r, Err(Error::UnsupportedAlgorithm));
}

/// The EdDSA inner JWT itself verifies under a non-RSA outer layer.
#[test]
fn an_eddsa_inner_jwt_verifies() {
    let inner = signed(&claims(), SigningAlg::EdDSA, &ed25519_key());
    let clock = FixedClock(NOW);
    let policy = Policy::new(&clock, &SIGNING).unwrap();
    let verifier = public(&ed25519_key());
    let v = jwt::decrypt_nested(
        &nest(&inner),
        &jwk(KEK),
        &decrypt_policy(),
        Keys::One(&verifier),
        &policy,
    )
    .unwrap();
    assert_eq!(v.inner.alg, SigningAlg::EdDSA);
    assert_eq!(v.inner.claims, claims());
}

// ---------------------------------------------------------------------------
// Sign-then-encrypt (RFC 7519 §5.2, §7.1 step 5, §11.2)
// ---------------------------------------------------------------------------

/// RFC 7519 §5.2: `encrypt_nested` sets `cty: "JWT"` in the JWE Protected
/// Header, keeps the caller's other protected parameters, rewrites a
/// caller `cty` that already means `JWT` to the exact spelling, and does
/// not change the caller's encryptor, which stays reusable.
#[test]
fn encrypt_nested_sets_cty_jwt_and_keeps_the_callers_header() {
    let inner = inner_es256();
    let e = kw(r#"{"typ":"JWT","kid":"outer-1","x-tenant":"acme"}"#);
    let first = jwt::encrypt_nested(&inner, &e).unwrap();
    let second = jwt::encrypt_nested(&inner, &e).unwrap();
    assert_ne!(first, second, "fresh CEK and IV each time (ADR 0005)");
    for token in [&first, &second] {
        let h = outer_header_of(token);
        assert_eq!(h.cty.as_deref(), Some("JWT"));
        assert_eq!(h.typ.as_deref(), Some("JWT"));
        assert_eq!(h.kid.as_deref(), Some("outer-1"));
        assert!(h.other_params().contains("x-tenant"));
        let v = open(token).unwrap();
        assert_eq!(v.outer_header, h);
    }
    for cty in ["JWT", "jwt", "application/JWT", "Application/jwt"] {
        let token = jwt::encrypt_nested(&inner, &kw(&format!(r#"{{"cty":"{cty}"}}"#))).unwrap();
        assert_eq!(outer_header_of(&token).cty.as_deref(), Some("JWT"), "{cty}");
        assert_eq!(code(open(&token)), "ok", "{cty}");
    }
}

/// ADR 0027 §7: a caller `cty` other than `JWT` (RFC 7515 §4.1.10
/// comparison) is `InvalidHeader`, never silently replaced.
#[test]
fn encrypt_nested_refuses_a_different_caller_cty() {
    let inner = inner_es256();
    for cty in ["JOSE", "at+jwt", "JWT ", "text/JWT", "application/jwt;v=1"] {
        let r = jwt::encrypt_nested(&inner, &kw(&format!(r#"{{"cty":"{cty}"}}"#)));
        assert!(matches!(r, Err(Error::InvalidHeader(_))), "{cty:?}: {r:?}");
    }
}

/// RFC 7515 §7.1, ADR 0027 §6–§7: the input must be a three-part compact
/// JWS. A nested JWT (five parts), a JWS JSON serialization, or anything
/// else is `InvalidFormat`, before the caller's `cty` is looked at.
#[test]
fn encrypt_nested_needs_a_compact_jws() {
    let inner = inner_es256();
    let jwe = nest(&inner);
    let json = format!(
        r#"{{"payload":"{}","protected":"{}","signature":"{}"}}"#,
        inner.split('.').nth(1).unwrap(),
        inner.split('.').next().unwrap(),
        inner.split('.').nth(2).unwrap(),
    );
    let with_newline = format!("{inner}\n");
    for input in [
        "",
        "not a jws",
        "a.b",
        jwe.as_str(),
        json.as_str(),
        with_newline.as_str(),
        ".eyJ9.sig",
    ] {
        for e in [kw("{}"), kw(r#"{"cty":"JOSE"}"#)] {
            assert!(
                matches!(jwt::encrypt_nested(input, &e), Err(Error::InvalidFormat(_))),
                "{input:?}"
            );
        }
    }
}

/// RFC 7516 §7.1: the output is compact, so the encryptor's compact
/// restrictions apply (`Encryptor::encrypt_compact` errors pass through).
#[test]
fn encrypt_nested_is_compact_only() {
    let inner = inner_es256();
    let no_recipient = Encryptor::new(E::A128GCM);
    let shared = kw("{}").shared_unprotected_header(header(r#"{"x":1}"#));
    let aad = kw("{}").aad(b"aad".to_vec());
    for e in [no_recipient, shared, aad] {
        assert!(
            matches!(
                jwt::encrypt_nested(&inner, &e),
                Err(Error::InvalidFormat(_))
            ),
            "{e:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Both layers validated (RFC 8725 §3.3)
// ---------------------------------------------------------------------------

/// RFC 8725 §3.3: decrypting is not enough. An inner JWS signed with a
/// different key, then encrypted correctly, is `InvalidSignature`.
#[test]
fn an_inner_signature_from_another_key_is_invalid_signature() {
    let other = generate(KeySpec::Ec(EcCurve::P256)).unwrap();
    let inner = signed(&claims(), SigningAlg::ES256, &other);
    assert_eq!(code(open(&nest(&inner))), "InvalidSignature");
}

/// RFC 7519 §4.1.4: the inner claims are validated; expired is
/// `TokenExpired`.
#[test]
fn an_expired_inner_jwt_is_token_expired() {
    let token = nest(&inner_es256());
    assert_eq!(code(open_at(&token, NOW)), "ok");
    assert_eq!(open_at(&token, LATE), Err(Error::TokenExpired));
}

/// RFC 7516 §5.2 step 16: a tampered authentication tag is
/// `DecryptionFailed`, detail-free (the 0003 error contract).
#[test]
fn a_tampered_outer_tag_is_decryption_failed() {
    let token = flip_tag(&nest(&inner_es256()));
    assert_eq!(open(&token), Err(Error::DecryptionFailed));
}

/// RFC 8725 §3.1, ADR 0007: the outer `enc` must be in the
/// `DecryptPolicy`, else `AlgorithmNotAllowed` before any cryptography.
#[test]
fn an_outer_enc_outside_the_decrypt_policy_is_algorithm_not_allowed() {
    let token = nest(&inner_es256());
    let only_a256gcm = DecryptPolicy::new(&[A::A128KW], &[E::A256GCM]).unwrap();
    let clock = FixedClock(NOW);
    let policy = Policy::new(&clock, &SIGNING).unwrap();
    let key = public(&es256_key());
    let r = jwt::decrypt_nested(&token, &jwk(KEK), &only_a256gcm, Keys::One(&key), &policy);
    assert!(matches!(r, Err(Error::AlgorithmNotAllowed)), "{r:?}");
    // And the outer alg likewise.
    let only_a256kw = DecryptPolicy::new(&[A::A256KW], &[E::A128GCM]).unwrap();
    let r = jwt::decrypt_nested(&token, &jwk(KEK), &only_a256kw, Keys::One(&key), &policy);
    assert!(matches!(r, Err(Error::AlgorithmNotAllowed)), "{r:?}");
}

/// RFC 8725 §3.1: the inner `alg` must be in the JWT `Policy`; an HS256
/// inner token under an ES256/EdDSA policy is `AlgorithmNotAllowed`, the
/// JWE key never standing in for the JWS key.
#[test]
fn an_inner_alg_outside_the_jwt_policy_is_algorithm_not_allowed() {
    let hmac = jwk(
        r#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#,
    );
    let inner = signed(&claims(), SigningAlg::HS256, &hmac);
    assert!(matches!(
        open(&nest(&inner)),
        Err(Error::AlgorithmNotAllowed)
    ));
}

/// RFC 8725 §3.2, ADR 0007: an inner Unsecured JWS (`alg: none`) is never
/// accepted, even inside a valid JWE.
#[test]
fn an_inner_alg_none_is_algorithm_not_allowed() {
    let payload = b64url_encode(claims().to_json().as_bytes());
    let inner = format!("{}.{payload}.", b64url_encode(br#"{"alg":"none"}"#));
    assert!(matches!(
        open(&nest(&inner)),
        Err(Error::AlgorithmNotAllowed)
    ));
}

// ---------------------------------------------------------------------------
// Shape and typing (ADR 0027 §6–§7)
// ---------------------------------------------------------------------------

/// RFC 7519 §5.2: the outer `cty` "MUST be present" and be `JWT`.
/// Without it the JWE is an encrypt-only JWT (not supported in 0.1.0),
/// with another value it is not a nested JWT: `InvalidHeader` either way.
#[test]
fn an_outer_cty_other_than_jwt_is_invalid_header() {
    let inner = inner_es256();
    for protected in [
        r#"{}"#,
        r#"{"cty":"JOSE"}"#,
        r#"{"cty":"at+jwt"}"#,
        r#"{"cty":"JWT "}"#,
        r#"{"cty":"text/JWT"}"#,
    ] {
        let token = nest_raw(&inner, protected);
        assert!(
            matches!(open(&token), Err(Error::InvalidHeader(_))),
            "{protected}"
        );
    }
    // The claims as the plaintext: an encrypt-only JWT.
    let encrypt_only = nest_raw(&claims().to_json(), r#"{}"#);
    assert!(matches!(open(&encrypt_only), Err(Error::InvalidHeader(_))));
}

/// RFC 7515 §4.1.10 (ADR 0027 §5, §7): `cty` compares as a media type, so
/// `jwt` and `application/JWT` are `JWT`.
#[test]
fn an_outer_cty_compares_as_a_media_type() {
    let inner = inner_es256();
    for cty in ["JWT", "jwt", "application/JWT", "Application/jwt"] {
        let token = nest_raw(&inner, &format!(r#"{{"cty":"{cty}"}}"#));
        let v = open(&token).unwrap_or_else(|e| panic!("{cty}: {e}"));
        assert_eq!(v.outer_header.cty.as_deref(), Some(cty));
    }
}

/// ADR 0027 §7, depth 1: an inner plaintext that is a JWE (five parts) is
/// `InvalidFormat`, as is one that is no JWS at all.
#[test]
fn an_inner_jwe_is_invalid_format() {
    let doubly_nested = nest_raw(&nest(&inner_es256()), r#"{"cty":"JWT"}"#);
    assert!(matches!(open(&doubly_nested), Err(Error::InvalidFormat(_))));
    for plaintext in ["", "a.b", "a.b.c.d", "{\"iss\":\"x\"}"] {
        assert!(
            matches!(
                open(&nest_raw(plaintext, r#"{"cty":"JWT"}"#)),
                Err(Error::InvalidFormat(_))
            ),
            "{plaintext:?}"
        );
    }
}

/// ADR 0027 §5, §7: an inner JWS whose own `cty` is `JWT` would nest a
/// JWS in a JWS (depth 2), which is not supported: `InvalidHeader`.
#[test]
fn an_inner_jws_with_cty_jwt_is_invalid_header() {
    let payload = claims().to_json();
    for cty in ["JWT", "jwt", "application/jwt"] {
        let inner = sign_raw(
            &format!(r#"{{"alg":"ES256","cty":"{cty}"}}"#),
            payload.as_bytes(),
            &es256_key(),
        );
        assert!(
            matches!(open(&nest(&inner)), Err(Error::InvalidHeader(_))),
            "{cty}"
        );
    }
}

/// ADR 0027 §7: signed and nested JWTs have separate entry points. A
/// three-part signed JWT given to `decrypt_nested` is `InvalidFormat`, and
/// a nested JWT given to `jwt::verify` is `InvalidFormat`.
#[test]
fn signed_and_nested_jwts_have_separate_entry_points() {
    let inner = inner_es256();
    assert!(matches!(open(&inner), Err(Error::InvalidFormat(_))));
    let clock = FixedClock(NOW);
    let policy = Policy::new(&clock, &SIGNING).unwrap();
    let key = public(&es256_key());
    assert!(matches!(
        jwt::verify(&nest(&inner), Keys::One(&key), &policy),
        Err(Error::InvalidFormat(_))
    ));
}

/// The seven claims RFC 9068 §2.2 requires of a JWT access token.
fn access_token_claims() -> Claims {
    let mut c = claims();
    c.aud = Some(Audience::One(AUDIENCE.into()));
    c.insert("client_id", "s6BhdRkqt3").unwrap();
    c.iat = NumericDate::from_secs(EXP - 1_000);
    c.jti = Some("dbe39bf3a3ba4238a513f51d6e1691c4".into());
    c
}

/// RFC 8725 §3.11: explicit typing applies to the inner JWT; the outer
/// `typ`, if present, must satisfy the same `typ` policy (ADR 0027 §7).
/// Under `Policy::access_token` (RFC 9068 §4), an inner `typ: at+jwt`
/// with no outer `typ` passes, an outer `secevent+jwt` (or `JWT`) does
/// not, and an untyped inner token does not either.
#[test]
fn explicit_typing_is_checked_on_the_inner_jws() {
    let key = es256_key();
    let at = jwt::sign(
        &access_token_claims(),
        &IssueOptions::new(SigningAlg::ES256).access_token(),
        &key,
    )
    .unwrap();
    let generic = signed(&access_token_claims(), SigningAlg::ES256, &key);
    let clock = FixedClock(NOW);
    let policy = Policy::access_token(&clock, &SIGNING, &[ISSUER], &[AUDIENCE]).unwrap();
    let verifier = public(&key);
    let run = |token: &str| {
        jwt::decrypt_nested(
            token,
            &jwk(KEK),
            &decrypt_policy(),
            Keys::One(&verifier),
            &policy,
        )
    };
    let v = run(&nest(&at)).unwrap();
    assert_eq!(v.inner.header.typ.as_deref(), Some("at+jwt"));
    assert_eq!(v.outer_header.typ, None);
    assert_eq!(
        code(run(&nest_raw(&at, r#"{"cty":"JWT","typ":"at+jwt"}"#))),
        "ok"
    );
    for outer in [
        r#"{"cty":"JWT","typ":"secevent+jwt"}"#,
        r#"{"cty":"JWT","typ":"JWT"}"#,
    ] {
        assert!(
            matches!(run(&nest_raw(&at, outer)), Err(Error::InvalidHeader(_))),
            "{outer}"
        );
    }
    // The outer typ does not stand in for the inner one.
    assert!(matches!(
        run(&nest_raw(&generic, r#"{"cty":"JWT","typ":"at+jwt"}"#)),
        Err(Error::InvalidHeader(_))
    ));
}

/// ADR 0027 §7 under the default `typ` mode: an outer `typ` must be absent
/// or `JWT`, like the inner one.
#[test]
fn the_default_typ_mode_applies_to_the_outer_typ() {
    let inner = inner_es256();
    for ok in [
        r#"{"cty":"JWT","typ":"JWT"}"#,
        r#"{"cty":"JWT","typ":"jwt"}"#,
    ] {
        assert_eq!(code(open(&nest_raw(&inner, ok))), "ok", "{ok}");
    }
    let token = nest_raw(&inner, r#"{"cty":"JWT","typ":"secevent+jwt"}"#);
    assert!(matches!(open(&token), Err(Error::InvalidHeader(_))));
}

// ---------------------------------------------------------------------------
// Replicated claims (RFC 7519 §5.3)
// ---------------------------------------------------------------------------

/// `inner` encrypted with `cty: JWT` and `members` added to the outer
/// protected header, as replicated claims.
fn nest_with(inner: &str, members: &str) -> String {
    nest_raw(inner, &format!(r#"{{"cty":"JWT",{members}}}"#))
}

/// RFC 7519 §5.3: replicated `iss`, `sub` and `aud` must be identical to
/// the inner claims (ADR 0027 §7: JSON-equal).
#[test]
fn replicated_claims_equal_to_the_inner_ones_pass() {
    let mut c = claims();
    c.aud = Some(Audience::One("a".into()));
    let inner = signed(&c, SigningAlg::ES256, &es256_key());
    let clock = FixedClock(NOW);
    let policy = Policy::new(&clock, &SIGNING).unwrap().audience("a");
    let key = public(&es256_key());
    let run = |token: &str| {
        jwt::decrypt_nested(
            token,
            &jwk(KEK),
            &decrypt_policy(),
            Keys::One(&key),
            &policy,
        )
    };
    for members in [
        format!(r#""iss":"{ISSUER}""#),
        r#""sub":"alice""#.to_owned(),
        r#""aud":"a""#.to_owned(),
        format!(r#""iss":"{ISSUER}","sub":"alice","aud":"a""#),
    ] {
        let v = run(&nest_with(&inner, &members)).unwrap_or_else(|e| panic!("{members}: {e}"));
        assert!(v.outer_header.contains(members.split('"').nth(1).unwrap()));
    }
    // A Many audience matches the same array.
    let mut many = claims();
    many.aud = Some(Audience::Many(vec!["a".into(), "b".into()]));
    let inner = signed(&many, SigningAlg::ES256, &es256_key());
    assert_eq!(code(run(&nest_with(&inner, r#""aud":["a","b"]"#))), "ok");
}

/// RFC 7519 §5.3: a replicated claim that differs is `InvalidClaim`. The
/// form matters (ADR 0027 §7: JSON equality): an outer `aud: ["a"]` does
/// not equal an inner `aud: "a"`, and an outer claim the inner Claims Set
/// lacks is a mismatch too.
#[test]
fn replicated_claims_that_differ_are_invalid_claim() {
    let mut c = claims();
    c.aud = Some(Audience::One("a".into()));
    let inner = signed(&c, SigningAlg::ES256, &es256_key());
    let clock = FixedClock(NOW);
    let policy = Policy::new(&clock, &SIGNING).unwrap().audience("a");
    let key = public(&es256_key());
    let run = |token: &str| {
        jwt::decrypt_nested(
            token,
            &jwk(KEK),
            &decrypt_policy(),
            Keys::One(&key),
            &policy,
        )
    };
    let cases = [
        (r#""iss":"https://evil.example""#, "iss"),
        (r#""iss":"HTTPS://ISSUER.EXAMPLE""#, "iss"),
        (r#""sub":"mallory""#, "sub"),
        (r#""aud":["a"]"#, "aud"),
        (r#""aud":"b""#, "aud"),
        (r#""aud":1"#, "aud"),
    ];
    for (members, name) in cases {
        assert_eq!(
            run(&nest_with(&inner, members)),
            Err(Error::InvalidClaim(name)),
            "{members}"
        );
    }
    // The inner token has no `jti`; a replicated `jti` is not checked.
    assert_eq!(code(run(&nest_with(&inner, r#""jti":"x""#))), "ok");
    // An outer `sub` with no inner `sub`.
    let mut no_sub = c.clone();
    no_sub.sub = None;
    let inner = signed(&no_sub, SigningAlg::ES256, &es256_key());
    assert_eq!(
        run(&nest_with(&inner, r#""sub":"alice""#)),
        Err(Error::InvalidClaim("sub"))
    );
}

// ---------------------------------------------------------------------------
// Precedence (ADR 0027 §9)
// ---------------------------------------------------------------------------

/// ADR 0027 §9: the JWE errors come first, then N1, then the inner steps,
/// then N2.
#[test]
fn the_layers_fail_in_the_adr_0027_order() {
    let other = generate(KeySpec::Ec(EcCurve::P256)).unwrap();
    let bad_signature = signed(&claims(), SigningAlg::ES256, &other);
    // Outer tampered and inner signature invalid: the JWE decides.
    assert_eq!(
        open(&flip_tag(&nest(&bad_signature))),
        Err(Error::DecryptionFailed)
    );
    // Outer cty missing and inner expired: N1 decides.
    let no_cty = nest_raw(&inner_es256(), r#"{}"#);
    assert!(matches!(
        open_at(&no_cty, LATE),
        Err(Error::InvalidHeader(_))
    ));
    // Outer cty missing and inner signature invalid: N1 decides.
    assert!(matches!(
        open(&nest_raw(&bad_signature, r#"{}"#)),
        Err(Error::InvalidHeader(_))
    ));
    // A replicated claim that differs and the inner expired: the inner
    // claims (J5) come before N2.
    let mismatch = nest_with(&inner_es256(), r#""iss":"https://evil.example""#);
    assert_eq!(open_at(&mismatch, LATE), Err(Error::TokenExpired));
    assert_eq!(open_at(&mismatch, NOW), Err(Error::InvalidClaim("iss")));
    // A replicated claim that differs and the inner signature invalid:
    // the signature (step 9) comes first.
    let mismatch = nest_with(&bad_signature, r#""iss":"https://evil.example""#);
    assert_eq!(code(open(&mismatch)), "InvalidSignature");
    // The outer enc not allowed and the outer cty missing: the JWE
    // contract runs before N1.
    let only_a256gcm = DecryptPolicy::new(&[A::A128KW], &[E::A256GCM]).unwrap();
    let clock = FixedClock(NOW);
    let policy = Policy::new(&clock, &SIGNING).unwrap();
    let key = public(&es256_key());
    assert!(matches!(
        jwt::decrypt_nested(&no_cty, &jwk(KEK), &only_a256gcm, Keys::One(&key), &policy),
        Err(Error::AlgorithmNotAllowed)
    ));
}

// ---------------------------------------------------------------------------
// Compact only; the outer typing from the protected header (ADR 0050 §3)
// ---------------------------------------------------------------------------

/// ADR 0027 §6, ADR 0050 §3: a JWE JSON Serialization, flattened or
/// general, is `InvalidFormat`, even a valid one whose `cty: JWT` is
/// protected, and one whose `cty: JWT` is only in the shared unprotected
/// header (where anyone could have put it).
#[test]
fn a_json_jwe_is_invalid_format() {
    let inner = inner_es256();
    let recipient = || Recipient::new(A::A128KW, &jwk(KEK));
    let protected_cty = || encryptor(E::A128GCM, recipient(), header(r#"{"cty":"JWT"}"#));
    let unprotected_cty = || {
        Encryptor::new(E::A128GCM)
            .recipient(recipient())
            .shared_unprotected_header(header(r#"{"cty":"JWT"}"#))
    };
    for form in [JsonForm::Flattened, JsonForm::General] {
        for e in [protected_cty(), unprotected_cty()] {
            let jwe = e.encrypt_json(inner.as_bytes(), form).unwrap();
            assert!(
                matches!(open(&jwe), Err(Error::InvalidFormat(_))),
                "{form:?} {jwe}"
            );
            // With surrounding JSON whitespace too.
            let spaced = format!("\r\n {jwe}");
            assert!(matches!(open(&spaced), Err(Error::InvalidFormat(_))));
        }
    }
}

// ---------------------------------------------------------------------------
// Secrets (ADR 0049 §4)
// ---------------------------------------------------------------------------

/// ADR 0049 §4, ADR 0027 §7: no claim value of the decrypted inner token
/// is in the result's `Debug` or in any error. The marker is in every
/// string claim: `iss`, `sub`, an `aud` element, `jti` (RFC 7519 §4.1)
/// and a private claim. It reaches the output only if the inner token, its
/// payload or a claim string leaks: `Claims`' `Debug` prints `iss`, `sub`,
/// `jti` and each `aud` element as `"<redacted>"`, and the other claims
/// through `Value`'s redacting `Debug`.
#[test]
fn the_inner_token_never_appears_in_debug_or_errors() {
    const MARKER: &str = "MARKER-7c1f2b9e-secret-claim-value";
    let mut c = claims();
    c.iss = Some(format!("{MARKER}-iss"));
    c.sub = Some(format!("{MARKER}-sub"));
    c.aud = Some(Audience::Many(vec![
        AUDIENCE.into(),
        format!("{MARKER}-aud"),
    ]));
    c.jti = Some(format!("{MARKER}-jti"));
    c.insert("secret", MARKER).unwrap();
    let inner = signed(&c, SigningAlg::ES256, &es256_key());
    // `open_at` with the policy accepting the token's audience, so every
    // step runs (ADR 0027 §9 J6).
    let key = public(&es256_key());
    let open_at = |token: &str, now: i64| {
        let clock = FixedClock(now);
        let policy = Policy::new(&clock, &SIGNING).unwrap().audience(AUDIENCE);
        jwt::decrypt_nested(
            token,
            &jwk(KEK),
            &decrypt_policy(),
            Keys::One(&key),
            &policy,
        )
    };
    let open = |token: &str| open_at(token, NOW);
    let payload_b64 = inner.split('.').nth(1).unwrap().to_owned();
    let signature_b64 = inner.split('.').nth(2).unwrap().to_owned();
    let leaks = |text: &str| {
        text.contains(MARKER)
            || text.contains(&inner)
            || text.contains(&payload_b64)
            || text.contains(&signature_b64)
    };

    let v = open(&nest(&inner)).unwrap();
    // Every marker made it into the result, so its absence from `Debug`
    // is redaction, not a missing claim.
    assert_eq!(v.inner.claims, c);
    let debug = format!("{v:?} {v:#?} {:?}", v.inner);
    assert!(!leaks(&debug), "{debug}");

    let other = generate(KeySpec::Ec(EcCurve::P256)).unwrap();
    let errors = [
        // N2
        open(&nest_with(&inner, r#""iss":"https://evil.example""#)),
        // J5
        open_at(&nest(&inner), LATE),
        // step 9
        open(&nest(&signed(&c, SigningAlg::ES256, &other))),
        // J1
        open(&nest(&sign_raw(
            r#"{"alg":"ES256","cty":"JWT"}"#,
            c.to_json().as_bytes(),
            &es256_key(),
        ))),
        // N1
        open(&nest_raw(&inner, r#"{}"#)),
        // The JWE
        open(&flip_tag(&nest(&inner))),
    ];
    for r in errors {
        let e = r.unwrap_err();
        let text = format!("{e} {e:?} {}", e.code());
        assert!(!leaks(&text), "{text}");
    }
}

// ---------------------------------------------------------------------------
// PBES2 budget through the nested entry point (ADR 0050 §2)
// ---------------------------------------------------------------------------

/// ADR 0050 §2: a `DecryptPolicy` PBES2 budget bounds `p2c` for a nested
/// JWT too: over budget is the uniform `DecryptionFailed`, at or under it
/// decrypts and verifies.
#[test]
fn the_pbes2_budget_applies_to_nested_decryption() {
    let password =
        Jwk::from_json(format!(r#"{{"kty":"oct","k":"{}"}}"#, b64url_encode(PASSWORD)).as_bytes())
            .unwrap();
    let token = jwt::encrypt_nested(
        &inner_es256(),
        &Encryptor::new(E::A128GCM)
            .recipient(Recipient::new(A::Pbes2Hs256A128KW, &password).p2c(1_000)),
    )
    .unwrap();
    let clock = FixedClock(NOW);
    let policy = Policy::new(&clock, &SIGNING).unwrap();
    let key = public(&es256_key());
    let run = |budget: u32| {
        let dp = DecryptPolicy::new(&[A::Pbes2Hs256A128KW], &[E::A128GCM])
            .unwrap()
            .max_pbes2_count(budget);
        jwt::decrypt_nested(&token, &password, &dp, Keys::One(&key), &policy)
    };
    assert_eq!(run(999).unwrap_err(), Error::DecryptionFailed);
    assert_eq!(run(1).unwrap_err(), Error::DecryptionFailed);
    assert!(run(1_000).is_ok());
    assert!(run(10_000).is_ok());
}
