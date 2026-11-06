//! X25519 private/public consistency at JWK import (ADR 0043 §3, amending
//! ADR 0041 §4; feature 0003 T17): a private `OKP` `X25519` key whose `x`
//! is not X25519(`d`, 9) (RFC 7748 §6.1: the public key is the X25519
//! function of the private key and the base point u = 9; RFC 8037 §2: `d`
//! is the private key of `x`) is `InvalidKey` with a fixed detail, on
//! every import path: `Jwk::from_json`, `Jwk::from_object`, JWK Sets
//! (where it is skipped, ADR 0041 §2) and the JWE recipient keys that the
//! JWE API takes as an imported `Jwk`.
//!
//! What stays accepted (ADR 0043 §2): a public-only `X25519` `x` is any 32
//! octets (RFC 7748 §5), including u-coordinates with a torsion component
//! and low-order ones, since clamping neutralises torsion and ECDH-ES
//! rejects the all-zero shared secret where it computes one (RFC 7748
//! §6.1).
//!
//! Every value below was derived independently of polyjose and of
//! x25519-dalek, with pure Python big-integer arithmetic: the RFC 7748 §5
//! Montgomery ladder (`decodeScalar25519`, `decodeUCoordinate`), checked
//! against the RFC 7748 §6.1 public keys and shared secret, and RFC 8032
//! §5.1 Edwards arithmetic for the torsion inputs (the Montgomery image
//! u = (1 + y) / (1 − y) of the Wycheproof `ed25519_test.json` tcId 160
//! mixed-order key, whose [8]P and [L]P are both not the identity; and of
//! its order-8 component [L]P). The RFC keys were copied from the RFC
//! texts, as hex in RFC 7748 §6.1 and as JWKs in RFC 8037 Appendix A.6.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

use polyjose::Error;
use polyjose::json;
use polyjose::jwk::{Jwk, JwkSet, KeyMaterial, OkpCurve};
use polyjose::util::{b64url_decode, b64url_encode};

/// The detail of an `X25519` private key whose `d` does not derive `x`.
const MISMATCH: Error = Error::InvalidKey("X25519 private key d does not match x");

/// RFC 7748 §6.1 Alice's private key
/// (`77076d0a…1db92c2a`), which RFC 8037 A.6 reuses as the ephemeral key.
const ALICE_D: &str = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo";
/// RFC 7748 §6.1 Alice's public key X25519(a, 9) (`8520f009…aa9b4e6a`).
const ALICE_X: &str = "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo";
/// RFC 7748 §6.1 Bob's private key (`5dab087e…ff88e0eb`).
const BOB_D: &str = "XasIfmJKikt54X-Lg4AO5m87sSkmGLb9HC-LJ_-I4Os";
/// RFC 7748 §6.1 Bob's public key X25519(b, 9) (`de9edb7d…6f882b4f`),
/// the recipient key of RFC 8037 A.6.
const BOB_X: &str = "3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08";

/// RFC 8037 Appendix A.6, the ephemeral private key exactly as printed.
const RFC8037_A6_EPHEMERAL: &str = r#"{"kty":"OKP","crv":"X25519",
 "d":"dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo",
 "x":"hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo"}"#;

/// Alice's `d` with the five bits `decodeScalar25519` overwrites flipped
/// (bits 0–2 of octet 0, bits 6–7 of octet 31; RFC 7748 §5): the clamped
/// scalar is unchanged, so it still derives `ALICE_X`.
const ALICE_D_CLAMP_BITS_FLIPPED: &str = "cAdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LOo";

/// A u-coordinate with a torsion component that is not of small order:
/// the Montgomery image of Wycheproof `ed25519_test.json` tcId 160's
/// mixed-order Ed25519 key (`3bf2adea…52a78760`).
const MIXED_ORDER_U: &str = "O_Kt6gI5z1U-xvItlVHhvvv3Fj9BrBK47HT55lKnh2A";
/// Low-order u-coordinates, for which X25519 with any clamped scalar is
/// all zero (RFC 7748 §6.1): u = 0, u = 1, and a point of order 8
/// (`5f9c95bc…d09f1157`, the Montgomery image of tcId 160's torsion
/// component).
const LOW_ORDER_U: [&str; 3] = [
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "X5yVvKNQjCSx0LFVnIPvWwREXMRYHI6G2CJO3dCfEVc",
];

fn import(json: &str) -> polyjose::Result<Jwk> {
    Jwk::from_json(json.as_bytes())
}

fn public(x: &str) -> String {
    format!(r#"{{"kty":"OKP","crv":"X25519","x":"{x}"}}"#)
}

fn private(x: &str, d: &str) -> String {
    format!(r#"{{"kty":"OKP","crv":"X25519","x":"{x}","d":"{d}"}}"#)
}

/// The 32 octets of an unpadded base64url string.
fn octets(b64u: &str) -> [u8; 32] {
    b64url_decode(b64u).unwrap().try_into().unwrap()
}

#[test]
fn rfc7748_6_1_private_keys_import() {
    for (x, d) in [(ALICE_X, ALICE_D), (BOB_X, BOB_D)] {
        let jwk = import(&private(x, d)).unwrap_or_else(|e| panic!("{e}: {x}"));
        let KeyMaterial::Okp(okp) = jwk.material() else {
            panic!("not an OKP key");
        };
        assert_eq!(okp.crv(), OkpCurve::X25519);
        assert!(okp.is_private());
    }
}

#[test]
fn rfc8037_a6_ephemeral_key_imports() {
    let jwk = import(RFC8037_A6_EPHEMERAL).unwrap();
    assert!(!jwk.is_public());
    assert_eq!(jwk.to_public().unwrap().to_json().as_str(), public(ALICE_X));
}

#[test]
fn the_bits_clamping_ignores_do_not_matter() {
    // RFC 7748 §5: decodeScalar25519 clears bits 0–2 and 255 and sets bit
    // 254, so a `d` that differs only there is the same private key.
    assert!(import(&private(ALICE_X, ALICE_D_CLAMP_BITS_FLIPPED)).is_ok());
}

#[test]
fn another_keys_x_is_invalid_key() {
    assert_eq!(import(&private(BOB_X, ALICE_D)).err(), Some(MISMATCH));
    assert_eq!(import(&private(ALICE_X, BOB_D)).err(), Some(MISMATCH));
}

#[test]
fn every_one_bit_flip_of_x_is_invalid_key() {
    // The derived public key is compared octet for octet. That includes
    // bit 255: RFC 7748 §5 masks it when *using* a u-coordinate, but
    // X25519(d, 9) never sets it, so an `x` with it set is not the
    // encoding `d` derives (and would not have the key's RFC 7638
    // thumbprint).
    let x = octets(ALICE_X);
    for bit in 0..256 {
        let mut flipped = x;
        flipped[bit / 8] ^= 1 << (bit % 8);
        let json = private(&b64url_encode(&flipped), ALICE_D);
        assert_eq!(import(&json).err(), Some(MISMATCH), "bit {bit}");
    }
}

#[test]
fn a_one_bit_flip_of_d_outside_the_clamped_bits_is_invalid_key() {
    let d = octets(ALICE_D);
    for bit in [3, 8, 128, 253] {
        let mut flipped = d;
        flipped[bit / 8] ^= 1 << (bit % 8);
        let json = private(ALICE_X, &b64url_encode(&flipped));
        assert_eq!(import(&json).err(), Some(MISMATCH), "bit {bit}");
    }
}

#[test]
fn a_private_key_never_derives_a_torsion_or_low_order_x() {
    // Clamping makes every X25519(d, 9) a point of the prime-order
    // subgroup, so `d` with such an `x` is always a mismatch.
    for x in LOW_ORDER_U.iter().chain([&MIXED_ORDER_U]) {
        assert_eq!(import(&private(x, ALICE_D)).err(), Some(MISMATCH), "{x}");
    }
}

#[test]
fn public_keys_with_torsion_or_low_order_still_import() {
    // ADR 0043 §2: no mixed-order or low-order rejection of an X25519 `x`
    // at import; every 32 octets are a u-coordinate (RFC 7748 §5).
    for x in LOW_ORDER_U.iter().chain([&MIXED_ORDER_U, &ALICE_X, &BOB_X]) {
        let jwk = import(&public(x)).unwrap_or_else(|e| panic!("{e}: {x}"));
        assert!(jwk.is_public(), "{x}");
    }
}

#[test]
fn from_object_rejects_the_same_mismatch() {
    let parsed = json::parse(private(BOB_X, ALICE_D).as_bytes()).unwrap();
    assert_eq!(
        Jwk::from_object(parsed.as_object().unwrap()).err(),
        Some(MISMATCH)
    );
}

#[test]
fn length_errors_come_before_the_consistency_check() {
    // RFC 8037 §2 lengths are checked first; there is nothing to derive
    // from a `d` of the wrong length.
    let short_d = b64url_encode(&octets(ALICE_D)[..31]);
    assert_eq!(
        import(&private(BOB_X, &short_d)).err(),
        Some(Error::InvalidKey("d has the wrong length for crv"))
    );
}

#[test]
fn a_mismatch_is_invalid_key_whatever_the_alg() {
    // As for EC and Ed25519 (ADR 0018 Q3): a malformed key is InvalidKey
    // even when its `alg` belongs to another family.
    for alg in ["ECDH-ES", "ECDH-ES+A256KW", "EdDSA"] {
        let json = format!(
            r#"{{"kty":"OKP","crv":"X25519","x":"{BOB_X}","d":"{ALICE_D}","alg":"{alg}"}}"#
        );
        assert_eq!(import(&json).err(), Some(MISMATCH), "{alg}");
    }
}

#[test]
fn mismatch_errors_never_contain_key_material() {
    let e = import(&private(BOB_X, ALICE_D)).unwrap_err();
    assert_eq!(e.code(), "InvalidKey");
    let shown = format!("{e} {e:?}");
    for value in [BOB_X, ALICE_D, &BOB_X[..8], &ALICE_D[..8], ALICE_X] {
        assert!(!shown.contains(value), "{shown}");
    }
}

#[test]
fn jwk_set_skips_a_mismatched_member() {
    // ADR 0041 §2: a member that fails validation is skipped (RFC 7517 §5,
    // "values ... out of the supported ranges"), never fatal, and the
    // valid keys stay in order.
    let doc = format!(
        r#"{{"keys":[{},{},{},{}]}}"#,
        private(BOB_X, ALICE_D),
        private(BOB_X, BOB_D),
        private(ALICE_X, BOB_D),
        public(MIXED_ORDER_U),
    );
    let set = JwkSet::from_json(doc.as_bytes()).expect("the set itself is valid");
    assert_eq!((set.len(), set.skipped()), (2, 2));
    assert!(!set.keys()[0].is_public());
    assert!(set.keys()[1].is_public());
}

#[test]
fn jwe_recipient_keys_reject_the_mismatch() {
    // The JWE API (`decrypt_compact`, `decrypt_json`, `Recipient::new`)
    // takes an imported `Jwk`, so a recipient key goes through the same
    // import: a mismatched ECDH-ES key, shaped as a JWE recipient key
    // (RFC 7517 §4.2 `use` "enc", RFC 8037 §3.2 ECDH-ES `alg`), never
    // reaches decryption, alone or from a JWK Set.
    for alg in [
        "ECDH-ES",
        "ECDH-ES+A128KW",
        "ECDH-ES+A192KW",
        "ECDH-ES+A256KW",
    ] {
        let key = |d: &str| {
            format!(
                r#"{{"kty":"OKP","crv":"X25519","kid":"bob","use":"enc","alg":"{alg}","x":"{BOB_X}","d":"{d}"}}"#
            )
        };
        assert!(import(&key(BOB_D)).is_ok(), "{alg}");
        assert_eq!(import(&key(ALICE_D)).err(), Some(MISMATCH), "{alg}");
        let set = JwkSet::from_json(format!(r#"{{"keys":[{}]}}"#, key(ALICE_D)).as_bytes())
            .expect("the set itself is valid");
        assert_eq!((set.len(), set.skipped()), (0, 1), "{alg}");
    }
}
