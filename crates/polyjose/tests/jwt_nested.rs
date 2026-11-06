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
use polyjose::jwe::{DecryptPolicy, Encryptor, Recipient};
use polyjose::jwk::{EcCurve, Jwk, OkpCurve};
use polyjose::jwt::{
    self, Claims, FixedClock, IssueOptions, Keys, NumericDate, Policy, VerifiedNestedJwt,
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

/// `inner` as a nested JWT: A128KW + A128GCM with `cty: JWT`.
fn nest(inner: &str) -> String {
    nest_raw(inner, r#"{"cty":"JWT"}"#)
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

/// RFC 7519 §7.2 step 8, §11.2: an ES256 inner JWT encrypted with `dir`,
/// A128KW, ECDH-ES+A128KW (P-256), ECDH-ES (X25519) and PBES2-HS256+A128KW
/// decrypts, verifies and validates, and the result carries the inner
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
        let token = encryptor(enc.clone(), recipient, header(r#"{"cty":"JWT"}"#))
            .encrypt_compact(inner.as_bytes())
            .unwrap();
        assert_eq!(token.split('.').count(), 5, "{alg}");
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

/// ADR 0021: an EdDSA inner JWT encrypted to an RSA-OAEP-256 recipient
/// (a public-key operation) is produced, but never decrypted: there is no
/// RSA private-key operation, so the JWE layer answers
/// `UnsupportedAlgorithm` even when the policy allows the `alg`.
#[test]
fn rsa_oaep_256_encrypts_but_never_decrypts() {
    let rsa = jwk(RSA_PUBLIC);
    let inner = signed(&claims(), SigningAlg::EdDSA, &ed25519_key());
    let token = encryptor(
        E::A256GCM,
        Recipient::new(A::RsaOaep256, &rsa),
        header(r#"{"cty":"JWT"}"#),
    )
    .encrypt_compact(inner.as_bytes())
    .unwrap();
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
