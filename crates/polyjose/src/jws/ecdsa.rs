//! ECDSA family: ES256, ES384, ES512 (RFC 7518 §3.4) and ES256K
//! (RFC 8812 §3.2), with fixed-length R‖S signatures.
//!
//! Implements the family contract documented in `jws/alg.rs`. This file is
//! a stub until T08 replaces it; the signatures are final.

use crate::error::{Error, Result};
use crate::jwa::SigningAlg;
use crate::jwk::Jwk;

/// Signs `signing_input` with hedged RFC 6979 ECDSA (ADR 0005), returning
/// R‖S of exactly 64/96/132/64 octets for ES256/384/512/256K
/// (RFC 7518 §3.4, RFC 8812 §3.2), with S in low form (ADR 0026 §5).
///
/// Key binding has checked that `key` is an `EC` private key on the
/// curve `alg` requires (RFC 7518 §3.4, RFC 8812 §3.3).
///
/// # Errors
///
/// - [`Error::InvalidKey`] if the private scalar is not exactly the field
///   size or not a valid scalar.
/// - [`Error::RandomnessUnavailable`] if the OS CSPRNG fails (ADR 0005).
pub(crate) fn sign(alg: &SigningAlg, key: &Jwk, signing_input: &[u8]) -> Result<Vec<u8>> {
    let _ = (alg, key, signing_input);
    Err(Error::UnsupportedAlgorithm)
}

/// Validates an R‖S signature over `signing_input` (RFC 7518 §3.4,
/// RFC 8812 §3.2; RFC 7515 §5.2 step 8). A high-S signature is valid
/// exactly when its low-S twin is (ADR 0026 §5).
///
/// Key binding has checked the key's family and curve as for [`sign`].
///
/// # Errors
///
/// - [`Error::InvalidSignature`] if the signature is not exactly
///   64/96/132/64 octets (DER is never accepted), has r = 0 or s = 0, or
///   does not validate.
/// - [`Error::InvalidKey`] if the public point is not on the curve or is
///   the identity.
pub(crate) fn verify(
    alg: &SigningAlg,
    key: &Jwk,
    signing_input: &[u8],
    signature: &[u8],
) -> Result<()> {
    let _ = (alg, key, signing_input, signature);
    Err(Error::UnsupportedAlgorithm)
}
