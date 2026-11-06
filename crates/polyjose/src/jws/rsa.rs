//! RSA family: RS256/384/512 (RSASSA-PKCS1-v1_5, RFC 7518 §3.3) and
//! PS256/384/512 (RSASSA-PSS, RFC 7518 §3.5), verify only (ADR 0021).
//!
//! Implements the family contract documented in `jws/alg.rs`. `verify` is a
//! stub until T07 replaces it; `sign` is final; the signatures are final.

use crate::error::{Error, Result};
use crate::jwa::SigningAlg;
use crate::jwk::Jwk;

/// RSA signing is not offered in 0.1.0 (ADR 0021: RUSTSEC-2023-0071
/// affects private-key operations). This body is final.
///
/// # Errors
///
/// Always [`Error::UnsupportedAlgorithm`]. Key binding already refuses
/// RS*/PS* signing with the same error before any other key check
/// (ADR 0026 §2 step 8).
pub(crate) fn sign(alg: &SigningAlg, key: &Jwk, signing_input: &[u8]) -> Result<Vec<u8>> {
    let _ = (alg, key, signing_input);
    Err(Error::UnsupportedAlgorithm)
}

/// Validates an RS256/384/512 (RFC 7518 §3.3) or PS256/384/512
/// (RFC 7518 §3.5: MGF1 with the same hash, salt length equal to the hash
/// output) signature over `signing_input` (RFC 7515 §5.2 step 8).
///
/// Key binding has checked that `key` is an `RSA` public key with a
/// modulus of 2048..=8192 bits (RFC 7518 §3.3, §3.5; ADR 0026 §2 step 8).
///
/// # Errors
///
/// [`Error::InvalidSignature`] if the signature does not validate, or is
/// not exactly the modulus length.
pub(crate) fn verify(
    alg: &SigningAlg,
    key: &Jwk,
    signing_input: &[u8],
    signature: &[u8],
) -> Result<()> {
    let _ = (alg, key, signing_input, signature);
    Err(Error::UnsupportedAlgorithm)
}
