//! The one way the keys module builds a [`Jwk`] from raw key components.
//!
//! Each function writes the components as base64url members (RFC 7515 §2)
//! of a [`json::Object`](crate::json::Object) and hands it to
//! [`Jwk::from_object`], so a key decoded from PEM/DER or generated from
//! the CSPRNG goes through exactly the validation a JWK read from JSON does
//! (RFC 7517 §4, RFC 7518 §6, RFC 8037 §2; ADR 0007, ADR 0041 §4):
//! coordinate and key lengths, EC points on their curve, EC scalars in
//! [1, n − 1], Ed25519 point decoding, RSA moduli of at least 2048 bits, and
//! the `alg` binding of RFC 8725 §3.1. There is no second constructor to
//! keep in step with it.
//!
//! # Secrets
//!
//! The private members (`d`, `k`) are encoded with
//! [`b64url_encode`](crate::util::b64url_encode), which is constant-time in
//! its input and allocates its output once at the exact length, and that
//! `String` moves straight into the `Zeroizing<String>` of a
//! [`Value::String`]. No other copy is made. The object, and every string in
//! it, is wiped when it is dropped at the end of each function; the decoded
//! key inside the returned `Jwk` is zeroizing too.

use zeroize::Zeroizing;

use crate::error::Result;
use crate::json::{Object, Value};
use crate::jwk::{EcCurve, Jwk, OkpCurve};
use crate::util::b64url_encode;

/// A binary member: the unpadded base64url of `bytes` (RFC 7515 §2), held in
/// a zeroizing string from the moment it is encoded.
fn b64url_member(bytes: &[u8]) -> Value {
    Value::String(Zeroizing::new(b64url_encode(bytes)))
}

/// Adds the optional `alg` member (RFC 7517 §4.4), then validates the whole
/// key, `alg` binding included.
fn finish(mut object: Object, alg: Option<&str>) -> Result<Jwk> {
    if let Some(alg) = alg {
        object.insert("alg", alg);
    }
    Jwk::from_object(&object)
}

/// An `EC` key (RFC 7518 §6.2): `x`, `y` and, for a private key, `d`, each
/// big-endian and exactly the curve's coordinate length (RFC 7518
/// §6.2.1.2–§6.2.1.3, §6.2.2.1; RFC 8812 §3.1).
///
/// # Errors
///
/// [`Error::InvalidKey`](crate::Error::InvalidKey) for a wrong length, a
/// point off the curve or a scalar out of range, and
/// [`Error::KeyAlgorithmMismatch`](crate::Error::KeyAlgorithmMismatch) for
/// an `alg` this curve cannot serve; whatever [`Jwk::from_object`] returns.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "used by key generation (generate.rs) and the EC mapper (ec.rs)"
    )
)]
pub(crate) fn ec_jwk(
    crv: EcCurve,
    x: &[u8],
    y: &[u8],
    d: Option<&[u8]>,
    alg: Option<&str>,
) -> Result<Jwk> {
    let mut object = Object::new();
    object.insert("kty", "EC");
    object.insert("crv", crv.as_str());
    object.insert("x", b64url_member(x));
    object.insert("y", b64url_member(y));
    if let Some(d) = d {
        object.insert("d", b64url_member(d));
    }
    finish(object, alg)
}

/// An `OKP` key (RFC 8037 §2): the public key `x` and, for a private key,
/// `d`, each 32 octets for Ed25519 (RFC 8032 §5.1.5) and X25519 (RFC 7748
/// §5).
///
/// # Errors
///
/// [`Error::InvalidKey`](crate::Error::InvalidKey) for a wrong length or an
/// invalid Ed25519 public key, and
/// [`Error::KeyAlgorithmMismatch`](crate::Error::KeyAlgorithmMismatch) for
/// an `alg` this curve cannot serve; whatever [`Jwk::from_object`] returns.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "used by key generation (generate.rs) and the OKP mapper (okp.rs)"
    )
)]
pub(crate) fn okp_jwk(crv: OkpCurve, x: &[u8], d: Option<&[u8]>, alg: Option<&str>) -> Result<Jwk> {
    let mut object = Object::new();
    object.insert("kty", "OKP");
    object.insert("crv", crv.as_str());
    object.insert("x", b64url_member(x));
    if let Some(d) = d {
        object.insert("d", b64url_member(d));
    }
    finish(object, alg)
}

/// An `RSA` public key (RFC 7518 §6.3.1): modulus `n` and exponent `e` as
/// unsigned big-endian integers in their minimal form, with no leading zero
/// octet (Base64urlUInt, RFC 7518 §2, §6.3.1.1). A DER INTEGER's sign octet
/// must be removed first. RSA private keys are not supported (ADR 0021).
///
/// # Errors
///
/// [`Error::InvalidKey`](crate::Error::InvalidKey) for a non-minimal value,
/// a modulus under 2048 bits or an invalid exponent, and
/// [`Error::KeyAlgorithmMismatch`](crate::Error::KeyAlgorithmMismatch) for a
/// non-RSA `alg`; whatever [`Jwk::from_object`] returns.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "used by the RSA public-key mapper (rsa.rs)")
)]
pub(crate) fn rsa_public_jwk(n: &[u8], e: &[u8], alg: Option<&str>) -> Result<Jwk> {
    let mut object = Object::new();
    object.insert("kty", "RSA");
    object.insert("n", b64url_member(n));
    object.insert("e", b64url_member(e));
    finish(object, alg)
}

/// An `oct` key (RFC 7518 §6.4.1) with key value `k`. Only key generation
/// builds one: PEM/DER never carries an `oct` key (ADR 0018 §3).
///
/// # Errors
///
/// [`Error::InvalidKey`](crate::Error::InvalidKey) for an empty `k`, and
/// [`Error::KeyAlgorithmMismatch`](crate::Error::KeyAlgorithmMismatch) for an
/// `alg` that does not take an `oct` key; whatever [`Jwk::from_object`]
/// returns.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "used by key generation (generate.rs)")
)]
pub(crate) fn oct_jwk(k: &[u8], alg: Option<&str>) -> Result<Jwk> {
    let mut object = Object::new();
    object.insert("kty", "oct");
    object.insert("k", b64url_member(k));
    finish(object, alg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;
    use crate::jwk::KeyMaterial;
    use crate::util::b64url_decode;

    fn b64(s: &str) -> Vec<u8> {
        b64url_decode(s).expect("RFC vector is canonical base64url")
    }

    /// The JWK parsed from `json` and the built one serialize identically.
    fn assert_same_key(built: &Jwk, json: &str) {
        let expected = Jwk::from_json(json.as_bytes()).expect("RFC JWK parses");
        assert_eq!(*built.to_json(), *expected.to_json());
    }

    // RFC 7517 Appendix A.1 / A.2, the P-256 key (kid "1", use "enc" left out).
    const A_EC_X: &str = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4";
    const A_EC_Y: &str = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM";
    const A2_EC_D: &str = "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE";
    // RFC 7517 Appendix A.1, the RSA key (kid "2011-04-29" left out).
    const A1_RSA_N: &str = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";

    #[test]
    fn rfc7517_a1_ec_public_key() {
        let jwk = ec_jwk(EcCurve::P256, &b64(A_EC_X), &b64(A_EC_Y), None, None).unwrap();
        assert!(jwk.is_public());
        assert_same_key(
            &jwk,
            &format!(r#"{{"kty":"EC","crv":"P-256","x":"{A_EC_X}","y":"{A_EC_Y}"}}"#),
        );
    }

    #[test]
    fn rfc7517_a2_ec_private_key() {
        let d = b64(A2_EC_D);
        let jwk = ec_jwk(EcCurve::P256, &b64(A_EC_X), &b64(A_EC_Y), Some(&d), None).unwrap();
        assert!(!jwk.is_public());
        let KeyMaterial::Ec(key) = jwk.material() else {
            panic!("an EC key")
        };
        assert_eq!(key.d(), Some(d.as_slice()));
        assert_same_key(
            &jwk,
            &format!(
                r#"{{"kty":"EC","crv":"P-256","x":"{A_EC_X}","y":"{A_EC_Y}","d":"{A2_EC_D}"}}"#
            ),
        );
    }

    #[test]
    fn rfc7517_a1_rsa_public_key_with_its_alg() {
        let jwk = rsa_public_jwk(&b64(A1_RSA_N), &b64("AQAB"), Some("RS256")).unwrap();
        assert_eq!(jwk.alg().map(|a| a.as_str()), Some("RS256"));
        assert_same_key(
            &jwk,
            &format!(r#"{{"kty":"RSA","n":"{A1_RSA_N}","e":"AQAB","alg":"RS256"}}"#),
        );
    }

    #[test]
    fn rfc7517_a3_oct_keys() {
        // A.3: the AES key (alg A128KW) and the HMAC key (alg HS256).
        let aes = "GawgguFyGrWKav7AX4VKUg";
        let jwk = oct_jwk(&b64(aes), Some("A128KW")).unwrap();
        assert_same_key(
            &jwk,
            &format!(r#"{{"kty":"oct","alg":"A128KW","k":"{aes}"}}"#),
        );
        let hmac = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";
        let jwk = oct_jwk(&b64(hmac), None).unwrap();
        assert_same_key(&jwk, &format!(r#"{{"kty":"oct","k":"{hmac}"}}"#));
    }

    #[test]
    fn rfc8037_a1_a2_ed25519_keys() {
        let d = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";
        let x = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
        let private = okp_jwk(OkpCurve::Ed25519, &b64(x), Some(&b64(d)), None).unwrap();
        assert_same_key(
            &private,
            &format!(r#"{{"kty":"OKP","crv":"Ed25519","d":"{d}","x":"{x}"}}"#),
        );
        let public = okp_jwk(OkpCurve::Ed25519, &b64(x), None, Some("EdDSA")).unwrap();
        assert!(public.is_public());
        assert_same_key(
            &public,
            &format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{x}","alg":"EdDSA"}}"#),
        );
    }

    #[test]
    fn rfc8037_a6_x25519_keys() {
        // The ephemeral key (= RFC 7748 §6.1 Alice) and Bob's public key.
        let d = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo";
        let x = "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo";
        let jwk = okp_jwk(OkpCurve::X25519, &b64(x), Some(&b64(d)), Some("ECDH-ES")).unwrap();
        assert_same_key(
            &jwk,
            &format!(r#"{{"kty":"OKP","crv":"X25519","x":"{x}","d":"{d}","alg":"ECDH-ES"}}"#),
        );
        let bob = "3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08";
        let jwk = okp_jwk(OkpCurve::X25519, &b64(bob), None, None).unwrap();
        assert_same_key(
            &jwk,
            &format!(r#"{{"kty":"OKP","crv":"X25519","x":"{bob}"}}"#),
        );
    }

    #[test]
    fn an_off_curve_point_is_rejected() {
        let mut y = b64(A_EC_Y);
        *y.last_mut().unwrap() ^= 0x01;
        assert!(matches!(
            ec_jwk(EcCurve::P256, &b64(A_EC_X), &y, None, None),
            Err(Error::InvalidKey(_))
        ));
    }

    #[test]
    fn a_1024_bit_rsa_modulus_is_rejected() {
        let n = b64(A1_RSA_N);
        assert_eq!(
            rsa_public_jwk(&n[..128], &b64("AQAB"), None).unwrap_err(),
            Error::InvalidKey("RSA modulus is shorter than 2048 bits")
        );
    }

    #[test]
    fn an_alg_the_key_cannot_serve_is_rejected() {
        // RFC 8725 §3.1: a P-256 key never serves RS256, and an Ed25519 key
        // never serves ECDH-ES (ADR 0006).
        assert_eq!(
            ec_jwk(
                EcCurve::P256,
                &b64(A_EC_X),
                &b64(A_EC_Y),
                None,
                Some("RS256")
            )
            .unwrap_err(),
            Error::KeyAlgorithmMismatch
        );
        let x = b64("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");
        assert_eq!(
            okp_jwk(OkpCurve::Ed25519, &x, None, Some("ECDH-ES")).unwrap_err(),
            Error::KeyAlgorithmMismatch
        );
        assert_eq!(
            oct_jwk(&[7; 32], Some("ES256")).unwrap_err(),
            Error::KeyAlgorithmMismatch
        );
    }

    #[test]
    fn wrong_lengths_are_rejected() {
        // RFC 7518 §6.2.1.2: x is exactly the coordinate length (a P-256
        // point under the P-384 name), and RFC 8037 §2: 32-octet OKP keys.
        assert!(matches!(
            ec_jwk(EcCurve::P384, &b64(A_EC_X), &b64(A_EC_Y), None, None),
            Err(Error::InvalidKey(_))
        ));
        assert!(matches!(
            okp_jwk(OkpCurve::X25519, &[9; 31], None, None),
            Err(Error::InvalidKey(_))
        ));
        assert!(matches!(oct_jwk(&[], None), Err(Error::InvalidKey(_))));
    }

    #[test]
    fn secret_members_are_zeroizing_strings() {
        // The private members are held only as Zeroizing<String> (no plain
        // String outlives b64url_encode's return).
        let Value::String(member) = b64url_member(&[0xA5; 32]) else {
            panic!("a string member")
        };
        let _: &Zeroizing<String> = &member;
        assert_eq!(member.as_str(), b64url_encode(&[0xA5; 32]));
    }
}
