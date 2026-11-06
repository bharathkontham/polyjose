//! T09 (tester): `EdDSA` and `Ed25519` through the public API only
//! (RFC 8037 §3.1/§A.4/§A.5; RFC 9864 §2.2/§7; RFC 8032 §5.1.7;
//! ADR 0026 §2 steps 8-9 and §6; ADR 0041 §4).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

use polyjose::Error;
use polyjose::header::Header;
use polyjose::jwa::SigningAlg;
use polyjose::jwk::Jwk;
use polyjose::jws::{ProtectedHeader, SignOptions, VerifyOptions, sign_compact, verify_compact};
use polyjose::util::{b64url_decode, b64url_encode};

const X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
const D: &str = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";
/// RFC 8037 §A.4 compact JWS, copied from the RFC text.
const A4: &str = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.\
hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";
const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

fn public(extra: &str) -> Jwk {
    Jwk::from_json(format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{X}"{extra}}}"#).as_bytes())
        .unwrap()
}

fn private(extra: &str) -> Jwk {
    public(&format!(r#","d":"{D}"{extra}"#))
}

fn opts(algs: &[SigningAlg]) -> VerifyOptions<'_> {
    VerifyOptions::new(algs).unwrap()
}

fn code(jws: &str, key: &Jwk, algs: &[SigningAlg]) -> &'static str {
    verify_compact(jws, key, &opts(algs)).map_or_else(|e| e.code(), |_| "ok")
}

fn with_signature(sig: &[u8]) -> String {
    let (head, _) = A4.rsplit_once('.').unwrap();
    format!("{head}.{}", b64url_encode(sig))
}

#[test]
fn rfc8037_a4_a5_via_public_api() {
    let protected = ProtectedHeader::from_encoded("eyJhbGciOiJFZERTQSJ9").unwrap();
    let jws = sign_compact(
        &protected,
        b"Example of Ed25519 signing",
        &private(""),
        &SignOptions::new(),
    )
    .unwrap();
    assert_eq!(jws, A4);
    assert_eq!(code(A4, &public(""), &[SigningAlg::EdDSA]), "ok");
}

#[test]
fn small_order_signature_and_malleated_s_are_invalid_signature() {
    let sig = b64url_decode(A4.rsplit_once('.').unwrap().1).unwrap();
    let all = [SigningAlg::EdDSA];
    // all-zero (R = s = 0) and identity R.
    let mut ident_r = [0u8; 64];
    ident_r[0] = 1;
    for bad in [[0u8; 64], ident_r] {
        assert_eq!(
            code(&with_signature(&bad), &public(""), &all),
            "InvalidSignature"
        );
    }
    // s + L.
    let mut m = sig.clone();
    let mut carry = 0u16;
    for (b, l) in m[32..].iter_mut().zip(L) {
        let t = u16::from(*b) + u16::from(l) + carry;
        *b = t as u8;
        carry = t >> 8;
    }
    assert_eq!(
        code(&with_signature(&m), &public(""), &all),
        "InvalidSignature"
    );
    // wrong lengths
    for n in [0, 1, 32, 63, 65, 128] {
        let s = vec![sig[0]; n];
        assert_eq!(
            code(&with_signature(&s), &public(""), &all),
            "InvalidSignature",
            "{n}"
        );
    }
}

#[test]
fn small_order_public_keys_never_import() {
    // identity, order-2 point (0,-1), and the order-4 points.
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let mut neg_one = [0xffu8; 32];
    neg_one[0] = 0xec;
    neg_one[31] = 0x7f;
    let mut order4 = [0u8; 32]; // y = 0
    for p in [identity, neg_one, order4] {
        let j = format!(
            r#"{{"kty":"OKP","crv":"Ed25519","x":"{}"}}"#,
            b64url_encode(&p)
        );
        assert!(matches!(
            Jwk::from_json(j.as_bytes()),
            Err(Error::InvalidKey(_))
        ));
    }
    order4[31] = 0x80; // sign bit variant
    let j = format!(
        r#"{{"kty":"OKP","crv":"Ed25519","x":"{}"}}"#,
        b64url_encode(&order4)
    );
    assert!(matches!(
        Jwk::from_json(j.as_bytes()),
        Err(Error::InvalidKey(_))
    ));
}

#[test]
fn eddsa_and_ed25519_are_not_interchangeable() {
    // RFC 9864 §7: a key bound to one name does not verify the other.
    let mut h = Header::new();
    h.alg = Some("Ed25519".into());
    let protected = ProtectedHeader::new(h).unwrap();
    let k_ed = private(r#","alg":"Ed25519""#);
    let k_eddsa_pub = public(r#","alg":"EdDSA""#);
    let jws = sign_compact(&protected, b"p", &k_ed, &SignOptions::new()).unwrap();
    assert_eq!(
        code(&jws, &public(r#","alg":"Ed25519""#), &[SigningAlg::Ed25519]),
        "ok"
    );
    assert_eq!(
        code(&jws, &k_eddsa_pub, &[SigningAlg::Ed25519]),
        "KeyAlgorithmMismatch"
    );
    // Allow-list entries are separate.
    assert_eq!(
        code(&jws, &public(""), &[SigningAlg::EdDSA]),
        "AlgorithmNotAllowed"
    );
    // Signing with a key whose alg says EdDSA under header Ed25519.
    let eddsa_priv = private(r#","alg":"EdDSA""#);
    assert_eq!(
        sign_compact(&protected, b"p", &eddsa_priv, &SignOptions::new()).err(),
        Some(Error::KeyAlgorithmMismatch)
    );
}

#[test]
fn alg_confusion_hmac_with_the_public_key_is_refused() {
    // HS256 token whose HMAC key is the Ed25519 public key's octets.
    let k = public("");
    let h = b64url_encode(br#"{"alg":"HS256"}"#);
    let jws = format!("{h}.{}.{}", b64url_encode(b"p"), b64url_encode(&[0u8; 32]));
    assert_eq!(code(&jws, &k, &[SigningAlg::HS256]), "KeyAlgorithmMismatch");
    // And an EdDSA allow-list refuses an HS256 token outright.
    assert_eq!(code(&jws, &k, &[SigningAlg::EdDSA]), "AlgorithmNotAllowed");
}

#[test]
fn ed448_is_unsupported_at_import() {
    let x = b64url_encode(&[0x42; 57]);
    let j = format!(r#"{{"kty":"OKP","crv":"Ed448","x":"{x}"}}"#);
    assert_eq!(
        Jwk::from_json(j.as_bytes()).err(),
        Some(Error::UnsupportedAlgorithm)
    );
}

#[test]
fn mismatched_d_and_wrong_length_fail_with_fixed_strings_not_key_bytes() {
    let d2 = b64url_encode(&[7u8; 32]);
    let k = Jwk::from_json(
        format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{X}","d":"{d2}"}}"#).as_bytes(),
    )
    .unwrap();
    let protected = ProtectedHeader::from_encoded("eyJhbGciOiJFZERTQSJ9").unwrap();
    let e = sign_compact(&protected, b"p", &k, &SignOptions::new()).unwrap_err();
    assert_eq!(e.code(), "InvalidKey");
    let shown = format!("{e} {e:?}");
    assert!(!shown.contains(&d2) && !shown.contains(D) && !shown.contains(X));
    // d of wrong length never imports.
    let short = b64url_encode(&[7u8; 31]);
    assert!(
        Jwk::from_json(
            format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{X}","d":"{short}"}}"#).as_bytes()
        )
        .is_err()
    );
}

/// A forgery that only strict verification stops: R is the identity (small
/// order) and S = k*a mod L, so [S]B = R + [k]A holds for the A.1 key. It was
/// computed offline from the A.1 seed (RFC 8032 §5.1.5-§5.1.6 arithmetic with
/// R replaced by the identity). RFC 8032 §5.1.7 cofactorless verification
/// accepts it; ADR 0026 §6 (`verify_strict`) must not.
const SMALL_ORDER_R_FORGERY: &str = "eyJhbGciOiJFZERTQSJ9.Zm9yZ2Vk.AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADl_T4pLKwoGTnFRGQYoV79pc-ReYRX6BWHBGBejO3oDQ";

#[test]
fn small_order_r_forgery_valid_under_the_lenient_equation_is_refused() {
    use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};

    // Oracle: the lenient check does accept this forgery, so the test below
    // distinguishes `verify_strict` from `verify`.
    let (input, sig) = SMALL_ORDER_R_FORGERY.rsplit_once('.').unwrap();
    let sig = Signature::from_slice(&b64url_decode(sig).unwrap()).unwrap();
    let vk = VerifyingKey::from_bytes(&b64url_decode(X).unwrap().try_into().unwrap()).unwrap();
    assert!(vk.verify(input.as_bytes(), &sig).is_ok());
    assert!(vk.verify_strict(input.as_bytes(), &sig).is_err());

    assert_eq!(
        code(SMALL_ORDER_R_FORGERY, &public(""), &[SigningAlg::EdDSA]),
        "InvalidSignature"
    );
}
