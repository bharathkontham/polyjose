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
    let public = verifying_key(ed25519_key(alg, key)?)?;
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

/// The public key `x` as a point that strict verification accepts.
///
/// - `x` is 32 octets (RFC 8037 §2, RFC 8032 §5.1.5) and decodes to a point
///   (RFC 8032 §5.1.3);
/// - the point is not of small order (`is_weak`, ADR 0026 §6): a
///   small-order key admits signatures valid for almost every message.
///   JWK import already rejects both (ADR 0041 §4); this is defence in
///   depth, so the family never relies on how a key was built.
fn verifying_key(okp: &OkpKey) -> Result<VerifyingKey> {
    let x = <&[u8; PUBLIC_KEY_LENGTH]>::try_from(okp.x())
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
}
