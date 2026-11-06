//! The JWE Compact Serialization (RFC 7516 §7.1): five base64url parts,
//! `protected.encrypted_key.iv.ciphertext.tag`, for exactly one recipient,
//! with no unprotected header and no JWE AAD. Filled in by T09.

use super::api::DecryptPolicy;
use super::core::JweParts;
use crate::{Error, Result};

/// Splits and decodes a compact JWE (RFC 7516 §5.2 steps 1–3, §7.1).
///
/// # Errors
///
/// [`Error::InvalidFormat`] for an input over `policy`'s `max_input_len`
/// (checked first) or other than exactly five parts;
/// [`Error::InvalidBase64`] for a part that is not strict base64url;
/// [`Error::InvalidJson`] or [`Error::InvalidHeader`] for the protected
/// header.
pub(crate) fn parse(_token: &str, _policy: &DecryptPolicy) -> Result<JweParts> {
    Err(Error::UnsupportedAlgorithm)
}

/// Writes `parts` as a compact JWE (RFC 7516 §7.1).
///
/// # Errors
///
/// [`Error::InvalidFormat`] if `parts` has other than one recipient, an
/// unprotected header or a JWE AAD.
pub(crate) fn serialize(_parts: &JweParts) -> Result<String> {
    Err(Error::UnsupportedAlgorithm)
}
