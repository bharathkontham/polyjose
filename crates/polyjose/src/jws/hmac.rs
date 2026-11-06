//! HMAC family: HS256, HS384 and HS512 (RFC 7518 §3.2).
//!
//! Implements the family contract documented in `jws/alg.rs`. This file is
//! a stub until T06 replaces it; the signatures are final.

use crate::error::{Error, Result};
use crate::jwa::SigningAlg;
use crate::jwk::Jwk;

/// Computes the HMAC of `signing_input` with SHA-256/384/512 for
/// HS256/384/512 (RFC 7518 §3.2), returning the full 32/48/64-octet tag.
///
/// Key binding (ADR 0026 §2 step 8) has checked that `key` is `oct` and at
/// least as long as the hash output (RFC 7518 §3.2).
///
/// # Errors
///
/// [`Error::KeyAlgorithmMismatch`] only if called against the contract
/// with a non-`oct` key.
pub(crate) fn sign(alg: &SigningAlg, key: &Jwk, signing_input: &[u8]) -> Result<Vec<u8>> {
    let _ = (alg, key, signing_input);
    Err(Error::UnsupportedAlgorithm)
}

/// Validates an HS256/384/512 tag over `signing_input` (RFC 7518 §3.2,
/// RFC 7515 §5.2 step 8), in constant time.
///
/// Key binding has checked the key as for [`sign`].
///
/// # Errors
///
/// [`Error::InvalidSignature`] if the tag does not match, including a tag
/// of the wrong length (no truncated MACs).
pub(crate) fn verify(
    alg: &SigningAlg,
    key: &Jwk,
    signing_input: &[u8],
    signature: &[u8],
) -> Result<()> {
    let _ = (alg, key, signing_input, signature);
    Err(Error::UnsupportedAlgorithm)
}
