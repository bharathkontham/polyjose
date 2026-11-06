//! EdDSA family: `EdDSA` (RFC 8037 §3.1) and `Ed25519` (RFC 9864 §2.2),
//! with Ed25519 keys only (ADR 0006, ADR 0026 §6).
//!
//! Implements the family contract documented in `jws/alg.rs`. This file is
//! a stub until T09 replaces it; the signatures are final.

use crate::error::{Error, Result};
use crate::jwa::SigningAlg;
use crate::jwk::Jwk;

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
/// Key binding has checked that `key` is an `OKP` `Ed25519` key.
///
/// # Errors
///
/// - [`Error::InvalidKey`] if the public key is of small order (ADR 0026 §6)
///   or does not decode.
/// - [`Error::InvalidSignature`] if the signature is not 64 octets, has a
///   small-order R or s ≥ L, or does not validate.
pub(crate) fn verify(
    alg: &SigningAlg,
    key: &Jwk,
    signing_input: &[u8],
    signature: &[u8],
) -> Result<()> {
    let _ = (alg, key, signing_input, signature);
    Err(Error::UnsupportedAlgorithm)
}
