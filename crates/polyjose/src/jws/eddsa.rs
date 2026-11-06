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
//! - **Mixed-order public keys** (a torsion component, but not of small
//!   order) are [`Error::InvalidKey`] too (ADR 0043 §1), although
//!   `verify_strict` and RFC 8032 §5.1.7 accept them: implementations
//!   disagree on such keys. JWK import refuses them first; `verify`
//!   re-checks.

use ed25519_dalek::{
    PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, Signature, Signer as _, SigningKey, VerifyingKey,
};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::jwa::SigningAlg;
use crate::jwk::{Jwk, KeyMaterial, OkpCurve, OkpKey};

/// Signs `signing_input` with Ed25519 (RFC 8032 §5.1.6; RFC 8037 §3.1,
/// RFC 9864 §2.2), returning the 64-octet signature `R || S`.
///
/// Key binding has checked that `key` is an `OKP` `Ed25519` private key.
/// Ed25519 is deterministic (RFC 8032 §5.1.6), so this uses no randomness.
///
/// The 32-octet seed `d` is copied only into a [`Zeroizing`] buffer, and
/// the `SigningKey` built from it is wiped on drop (ed25519-dalek's
/// `zeroize` feature; ADR 0007). Neither appears in an error.
///
/// # Errors
///
/// - [`Error::InvalidKey`] if `d` is not 32 octets (RFC 8037 §2, RFC 8032
///   §5.1.5), or is not the private key of `x` (RFC 8037 §2: a mismatched
///   pair would sign for a key other than the published one).
/// - [`Error::KeyAlgorithmMismatch`] only if key binding was bypassed:
///   `alg` or `key` is not this family's, or `key` has no `d` (`alg.rs`
///   contract).
pub(crate) fn sign(alg: &SigningAlg, key: &Jwk, signing_input: &[u8]) -> Result<Vec<u8>> {
    let okp = ed25519_key(alg, key)?;
    let d = okp.d().ok_or(Error::KeyAlgorithmMismatch)?;
    if d.len() != SECRET_KEY_LENGTH {
        return Err(Error::InvalidKey("Ed25519 d must be 32 octets"));
    }
    let mut seed = Zeroizing::new([0u8; SECRET_KEY_LENGTH]);
    seed.copy_from_slice(d);
    let signing_key = SigningKey::from_bytes(&seed);
    // RFC 8037 §2: `x` is the public key of `d` (RFC 8032 §5.1.5). The
    // derived key is public, but subtle keeps the comparison free of
    // data-dependent branches anyway.
    let derived = signing_key.verifying_key();
    if !bool::from(derived.as_bytes()[..].ct_eq(okp.x())) {
        return Err(Error::InvalidKey("Ed25519 d does not match x"));
    }
    let signature = signing_key
        .try_sign(signing_input)
        .map_err(|_| Error::InvalidKey("Ed25519 signing failed"))?;
    Ok(signature.to_bytes().to_vec())
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
///   §5.1.5), does not decode to a point (RFC 8032 §5.1.3), is of small
///   order (ADR 0026 §6), or has a torsion component (ADR 0043 §1).
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
///   small-order key admits signatures valid for almost every message;
/// - the point has no torsion component (`is_torsion_free`, ADR 0043 §1):
///   implementations disagree on mixed-order keys, which `verify_strict`
///   and RFC 8032 §5.1.7 accept.
///
/// JWK import already rejects all of these (ADR 0041 §4, ADR 0043 §1);
/// this is defence in depth, so the family never relies on how a key was
/// built.
fn verifying_key(x: &[u8]) -> Result<VerifyingKey> {
    let x = <&[u8; PUBLIC_KEY_LENGTH]>::try_from(x)
        .map_err(|_| Error::InvalidKey("Ed25519 x must be 32 octets"))?;
    let public = VerifyingKey::from_bytes(x)
        .map_err(|_| Error::InvalidKey("Ed25519 x is not a valid point"))?;
    if public.is_weak() {
        return Err(Error::InvalidKey("Ed25519 x is of small order"));
    }
    if !public.to_edwards().is_torsion_free() {
        return Err(Error::InvalidKey("Ed25519 x has a torsion component"));
    }
    Ok(public)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jws::alg::test_keys as keys;
    use crate::test_support::wycheproof::{self, Deviation, Outcome};
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

    /// Wycheproof `ed25519_test.json` tcId 160's public key
    /// 15deb307…b2c23b (`MixedOrderPublicKey`): canonical, not of small
    /// order, with a torsion component of order 8 (checked independently
    /// with RFC 8032 §5.1 arithmetic in Python).
    const MIXED_ORDER: &str = "Fd6zBynrPkZciPEbV9DI026w9nDDsi0vgOpgSe6ywjs";

    #[test]
    fn a_key_with_a_torsion_component_is_refused_before_the_signature() {
        // ADR 0043 §1: defence in depth behind JWK import, which refuses
        // the key first. `is_weak` alone lets it through.
        let x = b64url_decode(MIXED_ORDER).unwrap();
        let key = VerifyingKey::from_bytes(&<[u8; 32]>::try_from(&x[..]).unwrap()).unwrap();
        assert!(!key.is_weak());
        assert_eq!(
            verify_ed25519(&x, A4_SIGNING_INPUT, &a4_signature()),
            Err(Error::InvalidKey("Ed25519 x has a torsion component"))
        );
        let jwk = format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{MIXED_ORDER}"}}"#);
        assert!(matches!(
            Jwk::from_json(jwk.as_bytes()),
            Err(Error::InvalidKey(_))
        ));
    }

    /// An Ed25519 `x` encoding y = p + 3 with sign bit 0, where
    /// p = 2^255 − 19 (RFC 8032 §5.1): the same octets as the conformance
    /// vector `jwk-thumbprint/reject-ed25519-x-non-canonical.json`.
    const NON_CANONICAL: &str = "8P_______________________________________38";

    #[test]
    fn a_non_canonical_key_is_refused_at_verify_as_at_import() {
        // RFC 8032 §5.1.3 step 1: "If the resulting y >= p, decoding
        // fails". ed25519-dalek's `from_bytes` follows ZIP-215 and accepts
        // y ≥ p, so only the re-encode round trip catches this. JWK import
        // refuses the key (ADR 0041 §4); the key is built unchecked to show
        // verify makes the same call instead of relying on import. Every
        // y ≥ p that decodes gives a point of small order or with a torsion
        // component (checked with RFC 8032 §5.1 arithmetic in Python), so
        // the torsion check also stops this key; the point here is that
        // verify and import share one check and answer identically.
        let x = b64url_decode(NON_CANONICAL).unwrap();
        assert!(
            VerifyingKey::from_bytes(&<[u8; 32]>::try_from(&x[..]).unwrap()).is_ok(),
            "the probe needs a key that ZIP-215 decoding accepts"
        );
        let jwk = format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{NON_CANONICAL}"}}"#);
        let import = Jwk::from_json(jwk.as_bytes()).err();
        assert!(matches!(import, Some(Error::InvalidKey(_))), "{import:?}");

        let key = Jwk::okp_unchecked(OkpCurve::Ed25519, &x, None);
        for alg in [A::EdDSA, A::Ed25519] {
            assert_eq!(
                verify(&alg, &key, A4_SIGNING_INPUT, &a4_signature()).err(),
                import,
                "{alg}"
            );
        }
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

    #[test]
    fn rfc8037_a4_signs_exactly() {
        // RFC 8037 §A.4: Ed25519 is deterministic (RFC 8032 §5.1.6), so
        // the A.1 private key gives exactly the published signature. The
        // fully-specified `Ed25519` (RFC 9864 §2.2) is the same algorithm
        // and gives the same octets.
        let private = keys::ed25519_private("");
        for alg in [A::EdDSA, A::Ed25519] {
            let sig = sign(&alg, &private, A4_SIGNING_INPUT).unwrap();
            assert_eq!(sig, a4_signature(), "{alg}");
            assert_eq!(sig.len(), 64);
        }
    }

    #[test]
    fn signatures_round_trip_and_bind_the_input() {
        let private = keys::ed25519_private("");
        let public = keys::ed25519("");
        for input in [&b""[..], b"x", &[0xff; 1000][..]] {
            let sig = sign(&A::Ed25519, &private, input).unwrap();
            assert_eq!(verify(&A::Ed25519, &public, input, &sig), Ok(()));
            assert_eq!(verify(&A::EdDSA, &private, input, &sig), Ok(()));
            assert_eq!(
                verify(&A::Ed25519, &public, b"other", &sig),
                Err(Error::InvalidSignature)
            );
        }
    }

    #[test]
    fn a_private_key_that_does_not_match_x_is_an_invalid_key() {
        // RFC 8037 §2: `d` is the private key of the public key `x`. A
        // mismatched pair would emit signatures that never verify under the
        // published `x`, so signing fails closed instead. JWK import refuses
        // such a pair first (ADR 0043 §3), so the key is built unchecked to
        // reach the family's own check.
        let mismatched = Jwk::okp_unchecked(OkpCurve::Ed25519, &a1_x(), Some(&[7u8; 32]));
        let other_d = crate::util::b64url_encode(&[7u8; 32]);
        let json = format!(
            r#"{{"kty":"OKP","crv":"Ed25519","x":"{}","d":"{other_d}"}}"#,
            keys::ED25519_X
        );
        assert!(matches!(
            Jwk::from_json(json.as_bytes()),
            Err(Error::InvalidKey(_))
        ));
        assert_eq!(
            sign(&A::EdDSA, &mismatched, A4_SIGNING_INPUT),
            Err(Error::InvalidKey("Ed25519 d does not match x"))
        );
    }

    #[test]
    fn signing_needs_this_familys_private_key() {
        // alg.rs contract: key binding refuses these first; the family still
        // answers with KeyAlgorithmMismatch rather than panicking.
        assert_eq!(
            sign(&A::EdDSA, &keys::ed25519(""), A4_SIGNING_INPUT),
            Err(Error::KeyAlgorithmMismatch)
        );
        assert_eq!(
            sign(&A::ES256, &keys::ed25519_private(""), A4_SIGNING_INPUT),
            Err(Error::KeyAlgorithmMismatch)
        );
        for key in [keys::p256_private(""), keys::oct(32, "")] {
            assert_eq!(
                sign(&A::Ed25519, &key, A4_SIGNING_INPUT),
                Err(Error::KeyAlgorithmMismatch)
            );
        }
    }

    #[test]
    fn a_private_key_of_the_wrong_length_never_imports() {
        // RFC 8037 §2, RFC 8032 §5.1.5: `d` is the 32-octet seed. Import
        // rejects any other length (InvalidKey), so `sign` only sees 32.
        for len in [0, 31, 33, 64] {
            let d = crate::util::b64url_encode(&vec![1u8; len]);
            let jwk = format!(
                r#"{{"kty":"OKP","crv":"Ed25519","x":"{}","d":"{d}"}}"#,
                keys::ED25519_X
            );
            assert!(
                matches!(Jwk::from_json(jwk.as_bytes()), Err(Error::InvalidKey(_))),
                "{len}"
            );
        }
    }

    /// Where polyjose's outcome on `ed25519_test.json` differs from
    /// Wycheproof's `result`, or picks a side on an `acceptable` test.
    /// Every other test, `valid` and `invalid`, gets exactly the required
    /// outcome.
    const WYCHEPROOF_ED25519: &[Deviation] = &[
        Deviation::range(
            152,
            159,
            Outcome::Reject,
            "ADR 0026 §6, ADR 0041 §4: a public key of small order (the identity \
             and the seven torsion points, RFC 8032 §5.1.3) is rejected with \
             InvalidKey at JWK import; verify re-checks is_weak()",
        ),
        Deviation::range(
            160,
            180,
            Outcome::Reject,
            "ADR 0043 §1: a public key with a torsion component (mixed order, not \
             small order) is rejected with InvalidKey at JWK import, although \
             RFC 8032 §5.1.7 and verify_strict accept it, because implementations \
             disagree on such keys; verify re-checks is_torsion_free()",
        ),
    ];

    #[test]
    fn wycheproof_ed25519() {
        // ADR 0008 layer 1, ADR 0026 §6. The group key is `publicKeyJwk`
        // where the file has one, else a JWK rebuilt from `pk`.
        let suite = wycheproof::load("ed25519");
        let summary = wycheproof::assert_conforms(&suite, WYCHEPROOF_ED25519, |group, test| {
            let (msg, sig) = test.signature();
            let id = test.tc_id;
            let key = match Jwk::from_json(group.verification_jwk().as_bytes()) {
                Ok(key) => key,
                Err(e) => {
                    // Only the small-order (ADR 0041 §4) and mixed-order
                    // (ADR 0043 §1) keys fail import, and only with
                    // InvalidKey.
                    assert!(
                        test.has_flag("SmallOrderPublicKey")
                            || test.has_flag("MixedOrderPublicKey"),
                        "tcId {id}: {e:?}"
                    );
                    assert_eq!(e.code(), "InvalidKey", "tcId {id}");
                    return Outcome::Reject;
                }
            };
            let eddsa = verify(&A::EdDSA, &key, msg, sig);
            // RFC 9864 §2.2: `Ed25519` is the same algorithm as `EdDSA`
            // with an Ed25519 key.
            assert_eq!(eddsa, verify(&A::Ed25519, &key, msg, sig), "tcId {id}");
            // alg.rs contract: a key that imported is never refused here,
            // so every rejection is the signature's.
            if let Err(e) = &eddsa {
                assert_eq!(*e, Error::InvalidSignature, "tcId {id}");
            }
            Outcome::of(&eddsa)
        });
        assert_eq!(summary.tests, 210);
        assert_eq!(summary.deviations, 29);
        // 117 valid accepted; 64 invalid + 8 small-order acceptable +
        // 21 mixed-order acceptable rejected.
        assert_eq!(summary.accepted, 117);
        assert_eq!(summary.rejected, 64 + 8 + 21);
    }

    /// RFC 8037 §A.4: the complete compact JWS.
    const A4_JWS: &str = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.\
                          hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";

    #[test]
    fn rfc8037_a4_and_a5_end_to_end_through_compact() {
        use crate::jws::{
            ProtectedHeader, SignOptions, VerifyOptions, sign_compact, verify_compact,
        };

        // RFC 8037 §A.4: sign over the published protected header octets.
        let protected = ProtectedHeader::from_encoded("eyJhbGciOiJFZERTQSJ9").unwrap();
        let jws = sign_compact(
            &protected,
            b"Example of Ed25519 signing",
            &keys::ed25519_private(""),
            &SignOptions::new(),
        )
        .unwrap();
        assert_eq!(jws, A4_JWS);
        // RFC 8037 §A.5: verify with the public key.
        let opts = VerifyOptions::new(&[A::EdDSA]).unwrap();
        let verified = verify_compact(A4_JWS, &keys::ed25519(""), &opts).unwrap();
        assert_eq!(verified.alg, A::EdDSA);
        assert_eq!(verified.payload, b"Example of Ed25519 signing");
        // A changed signature fails (ADR 0026 §2 step 9).
        let tampered = A4_JWS.replace("hgyY", "hgyZ");
        assert_eq!(
            verify_compact(&tampered, &keys::ed25519(""), &opts).err(),
            Some(Error::InvalidSignature)
        );
        // RFC 9864 §2.2 and ADR 0026 §6: `EdDSA` and `Ed25519` are separate
        // allow-list entries.
        let only_ed25519 = VerifyOptions::new(&[A::Ed25519]).unwrap();
        assert_eq!(
            verify_compact(A4_JWS, &keys::ed25519(""), &only_ed25519).err(),
            Some(Error::AlgorithmNotAllowed)
        );
    }

    #[test]
    fn ed25519_end_to_end_through_compact() {
        use crate::header::Header;
        use crate::jws::{
            ProtectedHeader, SignOptions, VerifyOptions, sign_compact, verify_compact,
        };

        let mut header = Header::new();
        header.alg = Some("Ed25519".into());
        let protected = ProtectedHeader::new(header).unwrap();
        let payload = b"Example of Ed25519 signing";
        let private = keys::ed25519_private(r#","alg":"Ed25519""#);
        let jws = sign_compact(&protected, payload, &private, &SignOptions::new()).unwrap();

        // RFC 9864 §2.2: the same signature octets as `EdDSA` over the same
        // signing input.
        let parts: Vec<&str> = jws.split('.').collect();
        assert_eq!(parts.len(), 3);
        let input = format!("{}.{}", parts[0], parts[1]);
        let expected = sign(&A::EdDSA, &keys::ed25519_private(""), input.as_bytes()).unwrap();
        assert_eq!(b64url_decode(parts[2]).unwrap(), expected);

        let opts = VerifyOptions::new(&[A::Ed25519]).unwrap();
        let public = keys::ed25519(r#","alg":"Ed25519""#);
        let verified = verify_compact(&jws, &public, &opts).unwrap();
        assert_eq!(verified.alg, A::Ed25519);
        assert_eq!(verified.payload, payload);
        // RFC 9864 §7, ADR 0026 §2 step 8: a key bound to `EdDSA` does not
        // verify an `Ed25519` JWS.
        let eddsa_key = keys::ed25519(r#","alg":"EdDSA""#);
        assert_eq!(
            verify_compact(&jws, &eddsa_key, &opts).err(),
            Some(Error::KeyAlgorithmMismatch)
        );
        // Detached (RFC 7515 Appendix F).
        let detached = sign_compact(
            &protected,
            payload,
            &private,
            &SignOptions::new().detached(true),
        )
        .unwrap();
        let opts = VerifyOptions::new(&[A::Ed25519])
            .unwrap()
            .detached_payload(payload);
        assert_eq!(
            verify_compact(&detached, &public, &opts).unwrap().payload,
            payload
        );
    }
}
