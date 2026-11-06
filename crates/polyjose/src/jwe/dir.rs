//! `dir`: direct use of a shared symmetric key as the CEK (RFC 7518
//! §4.5). The JWE Encrypted Key is empty on encrypt and must be empty on
//! decrypt (RFC 7516 §5.1 step 6, §5.2 step 10). Filled in by T09.

use super::api::DecryptPolicy;
use super::content::Cek;
use super::key::RecipientKey;
use super::keymgmt::{KeyOutput, RecipientOptions};
use super::random::RandomSource;
use crate::header::Header;
use crate::jwa::{ContentEncAlg, KeyMgmtAlg};
use crate::{Error, Result};

/// Key management on encrypt (RFC 7516 §5.1 steps 3–7) for `dir`.
///
/// # Errors
///
/// An error if the key is not exactly `cek_len(enc)` bytes.
pub(super) fn encrypt_key(
    _alg: &KeyMgmtAlg,
    _key: &RecipientKey,
    _enc: &ContentEncAlg,
    _cek: Option<&Cek>,
    _options: &RecipientOptions,
    _rng: &mut dyn RandomSource,
) -> Result<KeyOutput> {
    Err(Error::UnsupportedAlgorithm)
}

/// Key management on decrypt (RFC 7516 §5.2 steps 6–12) for `dir`: the
/// CEK, which must have the length `enc` requires (§5.2 step 9).
///
/// # Errors
///
/// An error if the encrypted key is not empty or the key length is not `cek_len(enc)`. `core` reports every error from here as `DecryptionFailed`.
pub(super) fn decrypt_key(
    _alg: &KeyMgmtAlg,
    _key: &RecipientKey,
    _enc: &ContentEncAlg,
    _header: &Header,
    _encrypted_key: &[u8],
    _policy: &DecryptPolicy,
) -> Result<Cek> {
    Err(Error::UnsupportedAlgorithm)
}
