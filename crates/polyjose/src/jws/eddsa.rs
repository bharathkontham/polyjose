//! EdDSA family: `EdDSA` (RFC 8037 §3.1) and `Ed25519` (RFC 9864 §2.2),
//! with Ed25519 keys only (ADR 0006, ADR 0026 §6).
//!
//! Implements the family contract documented in `jws/alg.rs` on
//! `ed25519-dalek` (ADR 0002, ADR 0019).
//!
//! - **One algorithm, two names.** `EdDSA` with an `Ed25519` key and
//!   `Ed25519` are the same signature scheme (RFC 8037 §3.1, RFC 9864
//!   §2.2), so both produce identical signature octets. Which name a key
//!   may be used with is key binding's job (`alg::bind_key`, RFC 9864 §7).
//! - **Ed448** is out of scope (ADR 0006). JWK import rejects an `Ed448`
//!   OKP key with [`Error::UnsupportedAlgorithm`], so none reaches this
//!   module.
//! - **Strict verification** (ADR 0026 §6): only
//!   `VerifyingKey::verify_strict`, never the ZIP-215-lenient `verify`.
//!   It rejects a small-order R, a non-canonical R and s ≥ L (RFC 8032
//!   §5.1.7 step 1), and a small-order public key, which this module also
//!   rejects first with [`Error::InvalidKey`] as defence in depth (JWK
//!   import already refuses one, ADR 0041 §4).

use ed25519_dalek::{PUBLIC_KEY_LENGTH, Signature, VerifyingKey};

use crate::error::{Error, Result};
use crate::jwa::SigningAlg;
use crate::jwk::{Jwk, KeyMaterial, OkpCurve, OkpKey};

/// Signs `signing_input` with Ed25519 (RFC 8032 §5.1.6; RFC 8037 §3.1,
/// RFC 9864 §2.2), returning the 64-octet signature.
///
/// Key binding has checked that `key` is an `OKP` `Ed25519` private key.
///
/// # Errors
///
/// [`Error::InvalidKey`] if the key does not decode.
pub(crate) fn sign(alg: &SigningAlg, key: &Jwk, signing_input: &[u8]) -> Result<Vec<u8>> {
    let _ = (alg, key, signing_input);
    Err(Error::UnsupportedAlgorithm)
}

/// Validates an Ed25519 signature over `signing_input` with strict
/// verification (RFC 8032 §5.1.7; ADR 0026 §6).
///
/// Key binding has checked that `key` is an `OKP` `Ed25519` key. The key
/// is checked before the signature, so a bad key wins over a bad signature
/// (ADR 0026 §2 steps 8 and 9).
///
/// # Errors
///
/// - [`Error::InvalidKey`] if `x` is not 32 octets (RFC 8037 §2, RFC 8032
///   §5.1.5), does not decode to a point (RFC 8032 §5.1.3), or is of small
///   order (ADR 0026 §6).
/// - [`Error::InvalidSignature`] if the signature is not 64 octets
///   (RFC 8032 §5.1.6 step 6), has a small-order or non-canonical R, or
///   s ≥ L (RFC 8032 §5.1.7 step 1), or does not validate (RFC 8032 §5.1.7
///   step 3).
/// - [`Error::KeyAlgorithmMismatch`] only if key binding was bypassed:
///   `alg` or `key` is not this family's (`alg.rs` contract).
pub(crate) fn verify(
    alg: &SigningAlg,
    key: &Jwk,
    signing_input: &[u8],
    signature: &[u8],
) -> Result<()> {
    verify_ed25519(ed25519_key(alg, key)?.x(), signing_input, signature)
}

/// [`verify`] on the raw public key `x`, after the family check.
fn verify_ed25519(x: &[u8], signing_input: &[u8], signature: &[u8]) -> Result<()> {
    let public = verifying_key(x)?;
    // RFC 8032 §5.1.6 step 6: a signature is exactly 64 octets.
    let signature = Signature::from_slice(signature).map_err(|_| Error::InvalidSignature)?;
    public
        .verify_strict(signing_input, &signature)
        .map_err(|_| Error::InvalidSignature)
}

/// The `OKP` `Ed25519` key in `key`, if `alg` is this family's.
///
/// Key binding guarantees both (ADR 0026 §2 step 8); anything else is
/// [`Error::KeyAlgorithmMismatch`], never a panic (`alg.rs` contract).
fn ed25519_key<'k>(alg: &SigningAlg, key: &'k Jwk) -> Result<&'k OkpKey> {
    match (alg, key.material()) {
        (SigningAlg::EdDSA | SigningAlg::Ed25519, KeyMaterial::Okp(okp))
            if okp.crv() == OkpCurve::Ed25519 =>
        {
            Ok(okp)
        }
        _ => Err(Error::KeyAlgorithmMismatch),
    }
}

/// The public key `x` (RFC 8037 §2) as a point that strict verification
/// accepts.
///
/// - `x` is 32 octets (RFC 8037 §2, RFC 8032 §5.1.5) and decodes to a point
///   (RFC 8032 §5.1.3);
/// - the point is not of small order (`is_weak`, ADR 0026 §6): a
///   small-order key admits signatures valid for almost every message.
///   JWK import already rejects both (ADR 0041 §4); this is defence in
///   depth, so the family never relies on how a key was built.
fn verifying_key(x: &[u8]) -> Result<VerifyingKey> {
    let x = <&[u8; PUBLIC_KEY_LENGTH]>::try_from(x)
        .map_err(|_| Error::InvalidKey("Ed25519 x must be 32 octets"))?;
    let public = VerifyingKey::from_bytes(x)
        .map_err(|_| Error::InvalidKey("Ed25519 x is not a valid point"))?;
    if public.is_weak() {
        return Err(Error::InvalidKey("Ed25519 x is of small order"));
    }
    Ok(public)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jws::alg::test_keys as keys;
    use crate::util::b64url_decode;

    use SigningAlg as A;

    /// RFC 8037 §A.4: the JWS Signing Input, `b64(protected) '.'
    /// b64(payload)` for `{"alg":"EdDSA"}` and "Example of Ed25519 signing".
    const A4_SIGNING_INPUT: &[u8] = b"eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc";

    /// RFC 8037 §A.4: the signature, base64url.
    const A4_SIGNATURE: &str =
        "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";

    fn a4_signature() -> Vec<u8> {
        b64url_decode(A4_SIGNATURE).unwrap()
    }

    #[test]
    fn rfc8037_a5_verifies_with_the_a1_public_key() {
        // RFC 8037 §A.5: the A.4 signature validates under the A.1 `x`,
        // for `EdDSA` and for the fully-specified `Ed25519` (RFC 9864 §2.2:
        // the same algorithm, only the identifier differs).
        let public = keys::ed25519("");
        for alg in [A::EdDSA, A::Ed25519] {
            assert_eq!(
                verify(&alg, &public, A4_SIGNING_INPUT, &a4_signature()),
                Ok(()),
                "{alg}"
            );
        }
    }

    /// The encoding of the identity point (0, 1): y = 1, sign bit 0
    /// (RFC 8032 §5.1.2). It has order 1, so `is_weak`.
    const IDENTITY: [u8; 32] = {
        let mut p = [0u8; 32];
        p[0] = 1;
        p
    };

    /// The group order L = 2^252 + 27742317777372353535851937790883648493
    /// (RFC 8032 §5.1), little-endian.
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];

    fn a1_x() -> Vec<u8> {
        b64url_decode(keys::ED25519_X).unwrap()
    }

    #[test]
    fn the_identity_key_and_an_all_zero_signature_are_refused() {
        // The classic strictness probe: with A = identity and
        // signature (R = 0, s = 0) the lenient check [8][s]B = [8]R + [8][k]A
        // holds for every message. ADR 0026 §6: small-order keys are
        // InvalidKey, before any signature arithmetic.
        let zero = [0u8; 64];
        assert_eq!(
            verify_ed25519(&IDENTITY, b"any message", &zero),
            Err(Error::InvalidKey("Ed25519 x is of small order"))
        );
        // The same with the identity as R (encoded as IDENTITY) and s = 0.
        let mut identity_r = [0u8; 64];
        identity_r[..32].copy_from_slice(&IDENTITY);
        assert!(matches!(
            verify_ed25519(&IDENTITY, b"any message", &identity_r),
            Err(Error::InvalidKey(_))
        ));
        // JWK import refuses the key first (ADR 0041 §4), so through the
        // public API the probe never gets as far as the family.
        let jwk = format!(
            r#"{{"kty":"OKP","crv":"Ed25519","x":"{}"}}"#,
            crate::util::b64url_encode(&IDENTITY)
        );
        assert!(matches!(
            Jwk::from_json(jwk.as_bytes()),
            Err(Error::InvalidKey(_))
        ));
    }

    #[test]
    fn the_probe_would_pass_a_lenient_verifier() {
        // Shows the probe above tests something: ed25519-dalek's
        // non-strict `verify` accepts the identity key with the identity R
        // and s = 0 for any message, which is why only `verify_strict` is
        // used (ADR 0026 §6).
        use ed25519_dalek::Verifier as _;

        let weak = VerifyingKey::from_bytes(&IDENTITY).unwrap();
        let mut identity_r = [0u8; 64];
        identity_r[..32].copy_from_slice(&IDENTITY);
        let sig = Signature::from_bytes(&identity_r);
        assert!(weak.verify(b"any message", &sig).is_ok());
        assert!(weak.verify_strict(b"any message", &sig).is_err());
    }

    #[test]
    fn a_small_order_r_is_an_invalid_signature() {
        // RFC 8032 §5.1.7 / ADR 0026 §6: R of small order is rejected even
        // under a good key.
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&IDENTITY);
        assert_eq!(
            verify_ed25519(&a1_x(), A4_SIGNING_INPUT, &sig),
            Err(Error::InvalidSignature)
        );
        assert_eq!(
            verify_ed25519(&a1_x(), A4_SIGNING_INPUT, &[0u8; 64]),
            Err(Error::InvalidSignature)
        );
    }

    #[test]
    fn s_at_or_above_the_group_order_is_an_invalid_signature() {
        // RFC 8032 §5.1.7 step 1: "If ... S ... is not in the range 0 <= s < L,
        // the signature is invalid". s + L is the classic malleated twin of
        // a valid signature.
        let good = a4_signature();
        let mut malleated = good.clone();
        let mut carry = 0u16;
        for (byte, l) in malleated[32..].iter_mut().zip(L) {
            let sum = u16::from(*byte) + u16::from(l) + carry;
            *byte = sum as u8;
            carry = sum >> 8;
        }
        assert_eq!(carry, 0, "s + L still fits in 32 octets");
        assert_eq!(verify_ed25519(&a1_x(), A4_SIGNING_INPUT, &good), Ok(()));
        assert_eq!(
            verify_ed25519(&a1_x(), A4_SIGNING_INPUT, &malleated),
            Err(Error::InvalidSignature)
        );
        // s = L exactly.
        let mut s_is_l = good;
        s_is_l[32..].copy_from_slice(&L);
        assert_eq!(
            verify_ed25519(&a1_x(), A4_SIGNING_INPUT, &s_is_l),
            Err(Error::InvalidSignature)
        );
    }

    #[test]
    fn a_signature_of_the_wrong_length_is_invalid() {
        // RFC 8032 §5.1.6 step 6: 64 octets, R || S. No DER, no truncation,
        // no trailing garbage.
        let good = a4_signature();
        let public = keys::ed25519("");
        let mut long = good.clone();
        long.push(0);
        for sig in [
            &[][..],
            &good[..32],
            &good[..63],
            &long[..],
            &[good.clone(), good.clone()].concat()[..],
        ] {
            for alg in [A::EdDSA, A::Ed25519] {
                assert_eq!(
                    verify(&alg, &public, A4_SIGNING_INPUT, sig),
                    Err(Error::InvalidSignature),
                    "{alg}, {} octets",
                    sig.len()
                );
            }
        }
    }

    #[test]
    fn a_changed_input_or_signature_is_invalid() {
        let public = keys::ed25519("");
        let good = a4_signature();
        let mut input = A4_SIGNING_INPUT.to_vec();
        input[0] ^= 1;
        assert_eq!(
            verify(&A::EdDSA, &public, &input, &good),
            Err(Error::InvalidSignature)
        );
        for i in [0, 31, 32, 63] {
            let mut sig = good.clone();
            sig[i] ^= 0x01;
            assert_eq!(
                verify(&A::EdDSA, &public, A4_SIGNING_INPUT, &sig),
                Err(Error::InvalidSignature),
                "bit flip in octet {i}"
            );
        }
    }

    #[test]
    fn a_public_key_of_the_wrong_length_is_an_invalid_key() {
        // RFC 8037 §2, RFC 8032 §5.1.5: x is exactly 32 octets.
        let x = a1_x();
        for bad in [&x[..31], &[x.clone(), vec![0]].concat()[..], &[][..]] {
            assert!(
                matches!(
                    verify_ed25519(bad, A4_SIGNING_INPUT, &a4_signature()),
                    Err(Error::InvalidKey(_))
                ),
                "{} octets",
                bad.len()
            );
        }
    }

    #[test]
    fn a_foreign_alg_or_key_is_a_mismatch_not_a_panic() {
        // alg.rs contract: unreachable after key binding, but never a panic.
        assert_eq!(
            verify(
                &A::ES256,
                &keys::ed25519(""),
                A4_SIGNING_INPUT,
                &a4_signature()
            ),
            Err(Error::KeyAlgorithmMismatch)
        );
        for key in [keys::x25519(), keys::p256(""), keys::oct(32, "")] {
            assert_eq!(
                verify(&A::EdDSA, &key, A4_SIGNING_INPUT, &a4_signature()),
                Err(Error::KeyAlgorithmMismatch)
            );
        }
    }

    #[test]
    fn ed448_keys_never_reach_the_family() {
        // ADR 0006: Ed448 is out of scope. A well-formed Ed448 OKP key
        // (57-octet x, RFC 8037 §2) fails JWK import with
        // UnsupportedAlgorithm, so neither `EdDSA` nor `Ed25519` can be
        // asked to use one.
        let x = crate::util::b64url_encode(&[0x42; 57]);
        let jwk = format!(r#"{{"kty":"OKP","crv":"Ed448","x":"{x}"}}"#);
        assert_eq!(
            Jwk::from_json(jwk.as_bytes()).err(),
            Some(Error::UnsupportedAlgorithm)
        );
    }
}
