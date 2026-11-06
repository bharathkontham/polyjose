//! The JWE processing rules of RFC 7516 §5.1 (encrypt) and §5.2 (decrypt)
//! over [`JweParts`], independent of the serialization. Filled in by T09.
//!
//! `compact` (RFC 7516 §7.1) and `json` (§7.2) only convert between their
//! text and [`JweParts`].
//!
//! Decrypt runs the plan.md error contract in order: the input limits and
//! steps 1–5 (structure, base64url, headers, `crit`), then the support
//! check over all recipients, the allow-list and the key family, and only
//! then key management and content decryption, after which every failure
//! is [`Error::DecryptionFailed`] (RFC 7516 §11.4, §11.5).

use super::api::{DecryptPolicy, Decrypted, Encryptor, Serialization};
use super::random::RandomSource;
use crate::header::Header;
use crate::jwk::Jwk;
use crate::{Error, Result};

/// One recipient's part of a JWE (RFC 7516 §7.2.1 `recipients`).
#[derive(Debug, Clone, Default)]
pub(crate) struct RecipientParts {
    /// The per-recipient unprotected header (`header`), if any.
    pub(crate) header: Option<Header>,
    /// The JWE Encrypted Key (`encrypted_key`), decoded; empty for `dir`
    /// and ECDH-ES.
    pub(crate) encrypted_key: Vec<u8>,
}

/// A JWE with its parts decoded, whatever its serialization (RFC 7516 §3).
#[derive(Debug, Clone, Default)]
pub(crate) struct JweParts {
    /// The JWE Protected Header exactly as received or produced, base64url
    /// encoded: the AAD is computed over these bytes, never over a
    /// re-serialization (RFC 7516 §5.2 step 14, erratum 8676). Empty when
    /// a JSON JWE has no protected header.
    pub(crate) protected_b64: String,
    /// The JWE Protected Header, parsed.
    pub(crate) protected: Option<Header>,
    /// The JWE Shared Unprotected Header (`unprotected`), JSON only.
    pub(crate) shared: Option<Header>,
    /// The recipients, in order: exactly one for compact (RFC 7516 §7.1).
    pub(crate) recipients: Vec<RecipientParts>,
    /// The JWE Initialization Vector, decoded.
    pub(crate) iv: Vec<u8>,
    /// The JWE Ciphertext, decoded.
    pub(crate) ciphertext: Vec<u8>,
    /// The JWE Authentication Tag, decoded.
    pub(crate) tag: Vec<u8>,
    /// The JWE AAD (`aad`), decoded, JSON only.
    pub(crate) aad: Option<Vec<u8>>,
}

/// Encrypts `plaintext` for the recipients of `encryptor` (RFC 7516 §5.1),
/// placing the header parameters as `form` requires, with the random values
/// drawn from `rng` in the documented order (`jwe::random`).
///
/// `protected_b64` is the `insecure-test-vectors` hook: an RFC's exact
/// encoded protected header, used verbatim for the AAD and the output only
/// if it decodes to a header JSON-equal to the one built here.
///
/// # Errors
///
/// [`Error::InvalidFormat`] for a request `form` cannot carry (RFC 7516
/// §7.1) or no recipients; otherwise the header, key and algorithm errors
/// of the plan.md error contract.
pub(crate) fn encrypt(
    _encryptor: &Encryptor,
    _plaintext: &[u8],
    _form: Serialization,
    _rng: &mut dyn RandomSource,
    _protected_b64: Option<&str>,
) -> Result<JweParts> {
    Err(Error::UnsupportedAlgorithm)
}

/// Decrypts `parts` with `key` under `policy` (RFC 7516 §5.2), trying each
/// candidate recipient in order; the first that decrypts wins.
///
/// # Errors
///
/// The plan.md error contract: structural and header errors first, then
/// [`Error::UnsupportedAlgorithm`], [`Error::AlgorithmNotAllowed`] and
/// [`Error::KeyAlgorithmMismatch`] when no recipient is a candidate, and
/// [`Error::DecryptionFailed`] once key management has started.
pub(crate) fn decrypt(_parts: JweParts, _key: &Jwk, _policy: &DecryptPolicy) -> Result<Decrypted> {
    Err(Error::UnsupportedAlgorithm)
}
