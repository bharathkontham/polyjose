//! PBES2-HS256+A128KW, PBES2-HS384+A192KW and PBES2-HS512+A256KW
//! (RFC 7518 §4.8): PBKDF2 (RFC 8018 §5.2) over the password with salt
//! `UTF8(alg) || 0x00 || p2s`, then AES Key Wrap of the CEK. The decrypt
//! bound on `p2c` is `DecryptPolicy::max_pbes2_count` (ADR 0023), checked
//! before any derivation. Filled in by T12.

use super::api::DecryptPolicy;
use super::content::Cek;
use super::key::RecipientKey;
use super::keymgmt::{KeyOutput, RecipientOptions};
use super::random::RandomSource;
use crate::header::Header;
use crate::jwa::{ContentEncAlg, KeyMgmtAlg};
use crate::{Error, Result};

/// Key management on encrypt (RFC 7516 §5.1 steps 3–7) for the three PBES2 algorithms.
///
/// # Errors
///
/// An error for a `p2s` shorter than 8 bytes or a `p2c` of 0; `RandomnessUnavailable` if `rng` fails.
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

/// Key management on decrypt (RFC 7516 §5.2 steps 6–12) for the three PBES2 algorithms: the
/// CEK, which must have the length `enc` requires (§5.2 step 9).
///
/// # Errors
///
/// An error for a missing or malformed `p2s` or `p2c`, a `p2c` below 1 or above the policy bound, or a failed unwrap. `core` reports every error from here as `DecryptionFailed`.
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
