//! The JWE JSON Serialization (RFC 7516 §7.2): general (§7.2.1) with a
//! `recipients` array, and flattened (§7.2.2) with one recipient at the
//! top level; shared and per-recipient unprotected headers and the JWE AAD.
//! Filled in by T14.

use super::api::{DecryptPolicy, JsonForm};
use super::core::JweParts;
use crate::{Error, Result};

/// Parses a general or flattened JSON JWE (RFC 7516 §5.2 steps 1–3,
/// §7.2.1, §7.2.2).
///
/// # Errors
///
/// [`Error::InvalidFormat`] for an input over `policy`'s `max_input_len`
/// (checked first), more than `max_recipients` recipients, or a shape
/// RFC 7516 §7.2 forbids; [`Error::InvalidJson`] for JSON syntax,
/// duplicate members (ADR 0041 §1) or limits; [`Error::InvalidBase64`] for
/// a member that is not strict base64url.
pub(crate) fn parse(_jwe: &str, _policy: &DecryptPolicy) -> Result<JweParts> {
    Err(Error::UnsupportedAlgorithm)
}

/// Writes `parts` in `form` (RFC 7516 §7.2.1, §7.2.2).
///
/// # Errors
///
/// [`Error::InvalidFormat`] for a flattened JWE with other than one
/// recipient.
pub(crate) fn serialize(_parts: &JweParts, _form: JsonForm) -> Result<String> {
    Err(Error::UnsupportedAlgorithm)
}
