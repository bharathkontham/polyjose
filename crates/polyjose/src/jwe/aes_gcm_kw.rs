//! A128GCMKW, A192GCMKW and A256GCMKW: key wrapping with AES-GCM
//! (RFC 7518 §4.7), with a random 96-bit IV and a 128-bit tag carried in
//! the `iv` and `tag` header parameters (§4.7.1). Filled in by T10.

use super::api::DecryptPolicy;
use super::content::Cek;
use super::key::RecipientKey;
use super::keymgmt::{KeyOutput, RecipientOptions};
use super::random::RandomSource;
use crate::header::Header;
use crate::jwa::{ContentEncAlg, KeyMgmtAlg};
use crate::{Error, Result};

/// Key management on encrypt (RFC 7516 §5.1 steps 3–7) for A128GCMKW, A192GCMKW and A256GCMKW.
///
/// # Errors
///
/// An error if the KEK length does not match `alg`; `RandomnessUnavailable` if `rng` fails.
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

/// Key management on decrypt (RFC 7516 §5.2 steps 6–12) for A128GCMKW, A192GCMKW and A256GCMKW: the
/// CEK, which must have the length `enc` requires (§5.2 step 9).
///
/// # Errors
///
/// An error for a missing or malformed `iv` or `tag`, a wrong KEK length or a failed tag. `core` reports every error from here as `DecryptionFailed`.
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
