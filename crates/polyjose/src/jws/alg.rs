//! JWS algorithm families: `alg` → family dispatch, the per-family
//! contract, and the test seam.
//!
//! # The family contract
//!
//! Each family module (`hmac`, `rsa`, `ecdsa`, `eddsa`) provides exactly:
//!
//! ```text
//! pub(crate) fn sign(alg: &SigningAlg, key: &Jwk, signing_input: &[u8]) -> Result<Vec<u8>>;
//! pub(crate) fn verify(alg: &SigningAlg, key: &Jwk, signing_input: &[u8], signature: &[u8]) -> Result<()>;
//! ```
//!
//! - `signing_input` is the complete JWS Signing Input (RFC 7515 §5.1
//!   step 5, RFC 7797 §3), built by `process::signing_input`.
//! - `signature` is the decoded JWS Signature octets (RFC 7515 §5.2
//!   step 7), unchecked: a wrong length is the family's to reject.
//! - **Preconditions.** The caller has already run key binding
//!   ([`bind_key`], ADR 0026 §2 step 8), so `alg` belongs to the family,
//!   the key is of the family's `kty`/`crv`, its JWK `alg`/`use`/`key_ops`
//!   allow the operation, a sign key holds private material, an HMAC key
//!   is at least the hash size and an RSA modulus is 2048..=8192 bits.
//!   A family still matches on the key material and returns
//!   [`Error::KeyAlgorithmMismatch`] if it is not its own, rather than
//!   panicking.
//! - **What a family checks itself**, because it needs the primitive:
//!   EC points and scalars, Ed25519 small-order keys
//!   ([`Error::InvalidKey`]), and signature length and value
//!   ([`Error::InvalidSignature`]).
//! - **Errors.** `verify` returns only [`Error::InvalidSignature`] or
//!   [`Error::InvalidKey`]. `sign` returns only [`Error::InvalidKey`] or,
//!   for ECDSA, [`Error::RandomnessUnavailable`]; RSA `sign` always
//!   returns [`Error::UnsupportedAlgorithm`] (ADR 0021). No error carries
//!   key material or input (ADR 0007).
//!
//! # The test seam
//!
//! The serialization layers never call a family directly. They take a
//! [`Families`] table and call it after key binding; the public functions
//! pass [`FAMILIES`], the real dispatch. A `#[cfg(test)]` module can pass
//! its own table instead (for example [`fake::FAKE`]) to test the
//! serialization and the processing order without any real algorithm.
//! Key binding is not part of the table, so it is never substituted.

use crate::error::{Error, Result};
use crate::jwa::SigningAlg;
use crate::jwk::Jwk;

use super::{ecdsa, eddsa, hmac, rsa};

/// A family `sign` function (see the module docs for the contract).
pub(crate) type SignFn = fn(&SigningAlg, &Jwk, &[u8]) -> Result<Vec<u8>>;

/// A family `verify` function (see the module docs for the contract).
pub(crate) type VerifyFn = fn(&SigningAlg, &Jwk, &[u8], &[u8]) -> Result<()>;

/// The signature primitives the serialization layers call, after key
/// binding: the crate-internal test seam (see the module docs).
#[derive(Clone, Copy)]
pub(crate) struct Families {
    /// Computes a JWS Signature over a JWS Signing Input
    /// (RFC 7515 §5.1 step 5).
    pub(crate) sign: SignFn,
    /// Validates a JWS Signature against a JWS Signing Input
    /// (RFC 7515 §5.2 step 8).
    pub(crate) verify: VerifyFn,
}

/// The real dispatch: each `alg` goes to its family module.
pub(crate) const FAMILIES: Families = Families {
    sign: dispatch_sign,
    verify: dispatch_verify,
};

/// The JWS algorithm families (RFC 7518 §3.1, RFC 8037 §3.1,
/// RFC 8812 §3.2, RFC 9864 §2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Family {
    /// HS256, HS384, HS512 (RFC 7518 §3.2).
    Hmac,
    /// RS256/384/512 (RFC 7518 §3.3) and PS256/384/512 (RFC 7518 §3.5).
    Rsa,
    /// ES256, ES384, ES512 (RFC 7518 §3.4) and ES256K (RFC 8812 §3.2).
    Ecdsa,
    /// EdDSA (RFC 8037 §3.1) and Ed25519 (RFC 9864 §2.2), Ed25519 keys only.
    EdDsa,
}

/// The family of `alg`, or `None` for `none` (RFC 7518 §3.6) and unknown
/// values, which no family serves.
pub(crate) fn family(alg: &SigningAlg) -> Option<Family> {
    use SigningAlg as A;
    match alg {
        A::HS256 | A::HS384 | A::HS512 => Some(Family::Hmac),
        A::RS256 | A::RS384 | A::RS512 | A::PS256 | A::PS384 | A::PS512 => Some(Family::Rsa),
        A::ES256 | A::ES384 | A::ES512 | A::ES256K => Some(Family::Ecdsa),
        A::EdDSA | A::Ed25519 => Some(Family::EdDsa),
        A::None | A::Unknown(_) => None,
    }
}

/// The error for an `alg` no family serves: `none` is never allowed
/// (RFC 8725 §3.1, ADR 0007), an unknown value is unsupported
/// (RFC 7515 §4.1.1).
pub(crate) fn unserved(alg: &SigningAlg) -> Error {
    if *alg == SigningAlg::None {
        Error::AlgorithmNotAllowed
    } else {
        Error::UnsupportedAlgorithm
    }
}

fn dispatch_sign(alg: &SigningAlg, key: &Jwk, signing_input: &[u8]) -> Result<Vec<u8>> {
    match family(alg) {
        Some(Family::Hmac) => hmac::sign(alg, key, signing_input),
        Some(Family::Rsa) => rsa::sign(alg, key, signing_input),
        Some(Family::Ecdsa) => ecdsa::sign(alg, key, signing_input),
        Some(Family::EdDsa) => eddsa::sign(alg, key, signing_input),
        None => Err(unserved(alg)),
    }
}

fn dispatch_verify(
    alg: &SigningAlg,
    key: &Jwk,
    signing_input: &[u8],
    signature: &[u8],
) -> Result<()> {
    match family(alg) {
        Some(Family::Hmac) => hmac::verify(alg, key, signing_input, signature),
        Some(Family::Rsa) => rsa::verify(alg, key, signing_input, signature),
        Some(Family::Ecdsa) => ecdsa::verify(alg, key, signing_input, signature),
        Some(Family::EdDsa) => eddsa::verify(alg, key, signing_input, signature),
        None => Err(unserved(alg)),
    }
}

/// Test-only [`Families`] tables for the serialization and processing
/// tests.
#[cfg(test)]
pub(crate) mod fake {
    use sha2::{Digest, Sha256};

    use super::Families;
    use crate::error::{Error, Result};
    use crate::jwa::SigningAlg;
    use crate::jwk::Jwk;

    /// A deterministic stand-in for every family: the "signature" is
    /// SHA-256(`alg` ‖ 0x00 ‖ signing input). It ignores the key, so it is
    /// no MAC; it only lets a test round-trip and tamper with a JWS.
    pub(crate) const FAKE: Families = Families {
        sign: fake_sign,
        verify: fake_verify,
    };

    /// A table whose `verify` always fails with
    /// [`Error::InvalidSignature`], and whose `sign` is [`FAKE`]'s.
    pub(crate) const REJECTING: Families = Families {
        sign: fake_sign,
        verify: |_, _, _, _| Err(Error::InvalidSignature),
    };

    /// The fake signature of `signing_input` under `alg`.
    pub(crate) fn fake_signature(alg: &SigningAlg, signing_input: &[u8]) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(alg.as_str().as_bytes());
        h.update([0]);
        h.update(signing_input);
        h.finalize().to_vec()
    }

    fn fake_sign(alg: &SigningAlg, _key: &Jwk, signing_input: &[u8]) -> Result<Vec<u8>> {
        Ok(fake_signature(alg, signing_input))
    }

    fn fake_verify(
        alg: &SigningAlg,
        _key: &Jwk,
        signing_input: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        if fake_signature(alg, signing_input) == signature {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oct() -> Jwk {
        Jwk::from_json(br#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#).unwrap()
    }

    #[test]
    fn every_known_alg_but_none_has_a_family() {
        use Family as F;
        use SigningAlg as A;
        let expected = [
            (A::HS256, F::Hmac),
            (A::HS384, F::Hmac),
            (A::HS512, F::Hmac),
            (A::RS256, F::Rsa),
            (A::RS384, F::Rsa),
            (A::RS512, F::Rsa),
            (A::PS256, F::Rsa),
            (A::PS384, F::Rsa),
            (A::PS512, F::Rsa),
            (A::ES256, F::Ecdsa),
            (A::ES384, F::Ecdsa),
            (A::ES512, F::Ecdsa),
            (A::ES256K, F::Ecdsa),
            (A::EdDSA, F::EdDsa),
            (A::Ed25519, F::EdDsa),
        ];
        for (alg, fam) in &expected {
            assert_eq!(family(alg), Some(*fam), "{alg}");
        }
        assert_eq!(expected.len() + 1, SigningAlg::KNOWN.len());
        assert_eq!(family(&A::None), None);
        assert_eq!(family(&A::Unknown("HS1".into())), None);
    }

    #[test]
    fn dispatch_refuses_none_and_unknown() {
        let key = oct();
        let unknown = SigningAlg::Unknown("HS1".into());
        assert_eq!(
            (FAMILIES.sign)(&SigningAlg::None, &key, b"x"),
            Err(Error::AlgorithmNotAllowed)
        );
        assert_eq!(
            (FAMILIES.verify)(&SigningAlg::None, &key, b"x", b""),
            Err(Error::AlgorithmNotAllowed)
        );
        assert_eq!(
            (FAMILIES.sign)(&unknown, &key, b"x"),
            Err(Error::UnsupportedAlgorithm)
        );
        assert_eq!(
            (FAMILIES.verify)(&unknown, &key, b"x", b""),
            Err(Error::UnsupportedAlgorithm)
        );
    }

    #[test]
    fn rsa_sign_is_never_offered() {
        // ADR 0021: no RSA private-key operations in 0.1.0.
        let key = oct();
        for alg in [SigningAlg::RS256, SigningAlg::PS512] {
            assert_eq!(
                (FAMILIES.sign)(&alg, &key, b"x"),
                Err(Error::UnsupportedAlgorithm)
            );
        }
    }

    #[test]
    fn fake_families_round_trip_and_reject_tampering() {
        let key = oct();
        let alg = SigningAlg::HS256;
        let sig = (fake::FAKE.sign)(&alg, &key, b"input").unwrap();
        assert_eq!((fake::FAKE.verify)(&alg, &key, b"input", &sig), Ok(()));
        assert_eq!(
            (fake::FAKE.verify)(&alg, &key, b"inpuT", &sig),
            Err(Error::InvalidSignature)
        );
        assert_eq!(
            (fake::FAKE.verify)(&SigningAlg::HS384, &key, b"input", &sig),
            Err(Error::InvalidSignature)
        );
        assert_eq!(
            (fake::REJECTING.verify)(&alg, &key, b"input", &sig),
            Err(Error::InvalidSignature)
        );
    }
}
