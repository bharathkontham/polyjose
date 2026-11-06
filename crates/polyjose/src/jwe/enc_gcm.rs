//! AES-GCM content encryption: A128GCM, A192GCM and A256GCM (RFC 7518
//! §5.3), with a 96-bit IV and a detached 128-bit tag. Filled in by T02.

use zeroize::Zeroizing;

use crate::jwa::ContentEncAlg;
use crate::{Error, Result};

/// Encrypts `plaintext` under `cek` (16, 24 or 32 bytes for A128GCM,
/// A192GCM, A256GCM) and the 12-byte `iv`, authenticating `aad`, and
/// returns `(ciphertext, tag)` with a 16-byte tag (RFC 7518 §5.3).
///
/// # Errors
///
/// An error if `enc` is not A*GCM or the CEK or IV length is wrong.
pub(super) fn encrypt(
    _enc: &ContentEncAlg,
    _cek: &[u8],
    _iv: &[u8],
    _aad: &[u8],
    _plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    Err(Error::UnsupportedAlgorithm)
}

/// Checks the 16-byte `tag` over `aad` and `ciphertext`, then decrypts
/// (RFC 7518 §5.3, RFC 7516 §5.2 step 16).
///
/// # Errors
///
/// [`Error::DecryptionFailed`] for every failure: tag, IV or tag length,
/// CEK length (RFC 7516 §11.4).
pub(super) fn decrypt(
    _enc: &ContentEncAlg,
    _cek: &[u8],
    _iv: &[u8],
    _aad: &[u8],
    _ciphertext: &[u8],
    _tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    Err(Error::UnsupportedAlgorithm)
}
