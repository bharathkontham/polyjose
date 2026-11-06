//! AES_CBC_HMAC_SHA2 content encryption: A128CBC-HS256, A192CBC-HS384 and
//! A256CBC-HS512 (RFC 7518 §5.2), composed from `cbc`, `aes`, `hmac` and
//! `sha2`. The tag is verified in constant time before any decryption
//! (RFC 7518 §5.2.2.2). Filled in by T03.

use zeroize::Zeroizing;

use crate::jwa::ContentEncAlg;
use crate::{Error, Result};

/// Encrypts `plaintext` under `cek` (MAC_KEY || ENC_KEY: 32, 48 or 64
/// bytes) and the 16-byte `iv`, and returns `(ciphertext, tag)`, the tag
/// being the first T_LEN octets of `HMAC(MAC_KEY, A || IV || E || AL)`
/// (RFC 7518 §5.2.2.1).
///
/// # Errors
///
/// An error if `enc` is not A*CBC-HS* or the CEK or IV length is wrong.
pub(super) fn encrypt(
    _enc: &ContentEncAlg,
    _cek: &[u8],
    _iv: &[u8],
    _aad: &[u8],
    _plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    Err(Error::UnsupportedAlgorithm)
}

/// Verifies `tag` first and only then decrypts and unpads (RFC 7518
/// §5.2.2.2).
///
/// # Errors
///
/// [`Error::DecryptionFailed`] for every failure: tag, tag or IV length,
/// padding, CEK length (RFC 7516 §11.4).
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
