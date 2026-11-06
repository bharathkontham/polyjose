//! A128KW, A192KW and A256KW: AES Key Wrap (RFC 3394) of a random CEK
//! (RFC 7518 §4.4), on `aes-kw`. Also the [`wrap`]/[`unwrap`] helper that
//! PBES2 (RFC 7518 §4.8) and ECDH-ES+A*KW (RFC 7518 §4.6) call. Filled in
//! by T06.

use super::api::DecryptPolicy;
use super::content::Cek;
use super::key::RecipientKey;
use super::keymgmt::{KeyOutput, RecipientOptions};
use super::random::RandomSource;
use crate::header::Header;
use crate::jwa::{ContentEncAlg, KeyMgmtAlg};
use crate::{Error, Result};
use zeroize::Zeroizing;

/// Key management on encrypt (RFC 7516 §5.1 steps 3–7) for A128KW, A192KW and A256KW.
///
/// # Errors
///
/// An error if the KEK length does not match `alg` (16, 24 or 32 bytes).
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

/// Key management on decrypt (RFC 7516 §5.2 steps 6–12) for A128KW, A192KW and A256KW: the
/// CEK, which must have the length `enc` requires (§5.2 step 9).
///
/// # Errors
///
/// An error for a wrong KEK length, a wrapped key of the wrong size, an integrity failure (RFC 3394 §2.2.3) or an unwrapped CEK of the wrong length. `core` reports every error from here as `DecryptionFailed`.
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

/// Wraps `cek` under `kek` (RFC 3394 §2.2.1). The KEK is 16, 24 or 32
/// bytes; the CEK at least 16 bytes, a multiple of 8.
///
/// # Errors
///
/// An error for a KEK or CEK of a size outside those.
pub(super) fn wrap(_kek: &[u8], _cek: &[u8]) -> Result<Vec<u8>> {
    Err(Error::UnsupportedAlgorithm)
}

/// Unwraps `wrapped` under `kek` and checks its integrity (RFC 3394
/// §2.2.2–§2.2.3). The wrapped input is at least 24 bytes, a multiple of 8.
///
/// # Errors
///
/// An error for a size outside those or an integrity failure; no partial
/// key is returned.
pub(super) fn unwrap(_kek: &[u8], _wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    Err(Error::UnsupportedAlgorithm)
}
