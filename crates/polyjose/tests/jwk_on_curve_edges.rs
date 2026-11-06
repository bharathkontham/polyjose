//! Additional edge cases for on-curve validation at JWK import (ADR 0041 §4),
//! written by the tester for feature 0002 T01: Ed25519 sign-bit variants and
//! non-canonical y values, an over-range P-521 scalar, and a robustness
//! property (no panic; every rejection is `InvalidKey`).

use base64ct::{Base64UrlUnpadded, Encoding};
use polyjose::Error;
use polyjose::jwk::Jwk;
use proptest::prelude::*;

fn b64(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

fn import(json: &str) -> Result<Jwk, Error> {
    Jwk::from_json(json.as_bytes())
}

fn okp(x: &[u8; 32]) -> String {
    format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{}"}}"#, b64(x))
}

/// RFC 8037 Appendix A.2 public key.
const RFC8037_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";

#[test]
fn ed25519_valid_key_with_the_other_sign_bit_is_accepted() {
    // Flipping the sign bit of x gives the negated point, also a valid
    // large-order point, and canonical.
    let mut x = [0u8; 32];
    Base64UrlUnpadded::decode(RFC8037_X.as_bytes(), &mut x).unwrap();
    assert!(import(&okp(&x)).is_ok());
    x[31] ^= 0x80;
    assert!(import(&okp(&x)).is_ok(), "negated point");
}

#[test]
fn ed25519_small_order_points_with_either_sign_bit_are_rejected() {
    let mut cases: Vec<[u8; 32]> = Vec::new();
    // identity y = 1, order-2 y = p - 1, both with the sign bit set (x = 0, so
    // the "negative zero" encodings that ZIP-215 decoders accept).
    let mut id = [0u8; 32];
    id[0] = 1;
    cases.push(id);
    id[31] = 0x80;
    cases.push(id);
    let mut o2 = [0xffu8; 32];
    o2[0] = 0xec;
    o2[31] = 0x7f;
    cases.push(o2);
    o2[31] = 0xff;
    cases.push(o2);
    // y = 0 : order 4 points (x = +-sqrt(-1)), both signs.
    let mut o4 = [0u8; 32];
    cases.push(o4);
    o4[31] = 0x80;
    cases.push(o4);
    for x in cases {
        assert_eq!(
            import(&okp(&x)).err(),
            Some(Error::InvalidKey("Ed25519 public key is invalid")),
            "{x:02x?}"
        );
    }
}

#[test]
fn ed25519_y_at_or_above_p_is_rejected() {
    // y = p, p + 1 (decode to y = 0 and y = 1 under ZIP-215), 2^255 - 1.
    for lo in [0xedu8, 0xee] {
        let mut x = [0xffu8; 32];
        x[0] = lo;
        x[31] = 0x7f;
        assert!(import(&okp(&x)).is_err(), "{x:02x?}");
    }
    let x = {
        let mut x = [0xffu8; 32];
        x[31] = 0x7f;
        x
    };
    assert!(import(&okp(&x)).is_err());
}

#[test]
fn p521_scalar_with_high_bits_set_is_rejected() {
    // 66 octets of 0xff is 2^528 - 1, far above n; x, y are P-521 G.
    let gx =
        "AMaFjga3BATpzZ4-y2YjlbRCnGSBOQU_tSH4KK9ga009uqFLXnfv51ko_h3BJ6L_qN4zSLPBhWpCm_l-fjHC5b1m";
    let gy =
        "ARg5KWp4mjvABFyKX7QsfRvZmPVESVebRGgXr70XJz5mLJfucple9CZAxVC5AT-tB2E1PHCGonLCQIi-lHaf0WZQ";
    let d = b64(&[0xffu8; 66]);
    let json = format!(r#"{{"kty":"EC","crv":"P-521","x":"{gx}","y":"{gy}","d":"{d}"}}"#);
    assert_eq!(
        import(&json).err(),
        Some(Error::InvalidKey("EC private key d is out of range"))
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    #[test]
    fn random_okp_ec_inputs_never_panic_and_reject_as_invalid_key(
        x in proptest::collection::vec(any::<u8>(), 32),
        y in proptest::collection::vec(any::<u8>(), 32),
        d in proptest::option::of(proptest::collection::vec(any::<u8>(), 32)),
        crv in prop_oneof![Just("P-256"), Just("secp256k1")],
    ) {
        let d = d.map(|d| format!(r#","d":"{}""#, b64(&d))).unwrap_or_default();
        let ec = format!(r#"{{"kty":"EC","crv":"{crv}","x":"{}","y":"{}"{d}}}"#, b64(&x), b64(&y));
        match import(&ec) {
            Ok(_) => {}
            Err(Error::InvalidKey(_)) => {}
            Err(e) => prop_assert!(false, "unexpected {e:?}"),
        }
        let mut xa = [0u8; 32];
        xa.copy_from_slice(&x);
        match import(&okp(&xa)) {
            Ok(_) | Err(Error::InvalidKey(_)) => {}
            Err(e) => prop_assert!(false, "unexpected {e:?}"),
        }
    }
}
