//! JWE operations (ADR 0030 §4, "JWE"; RFC 7516, RFC 7518 §4–§5; ADR 0017, 0021, 0022, 0023,
//! 0050).
//!
//! Keys are JWK JSON text, borrowed or held as [`SecretString`](crate::secret::SecretString)
//! (ADR 0030 §7.1). Plaintext is borrowed on the way in, and decrypted plaintext and `aad` are
//! [`SecretBytes`](crate::secret::SecretBytes) (ADR 0030 §7.2, ADR 0050 §4). Decryption takes the
//! caller's `alg` and `enc` allow-lists (ADR 0007, RFC 8725 §3.1).

use crate::error::{SurfaceError, SurfaceResult};
use crate::records::{JweDecryptOptions, JweDecrypted, JweEncryptOptions};

/// Encrypts `plaintext` into a JWE Compact Serialization, for exactly one recipient (ADR 0030
/// §4; RFC 7516 §5.1, §7.1).
pub fn jwe_encrypt_compact(plaintext: &[u8], options: &JweEncryptOptions) -> SurfaceResult<String> {
    // stub: T08
    let _ = (plaintext, options);
    Err(SurfaceError::from(polyjose::Error::UnsupportedAlgorithm))
}

/// Encrypts `plaintext` into a JWE JSON Serialization of `form`, `general` or `flattened`
/// (ADR 0030 §4; RFC 7516 §5.1, §7.2.1, §7.2.2). Any other `form` fails with
/// `UnsupportedAlgorithm` (ADR 0030 §5).
pub fn jwe_encrypt_json(
    plaintext: &[u8],
    options: &JweEncryptOptions,
    form: &str,
) -> SurfaceResult<String> {
    // stub: T08
    let _ = (plaintext, options, form);
    Err(SurfaceError::from(polyjose::Error::UnsupportedAlgorithm))
}

/// Decrypts the JWE Compact Serialization `token` with `key` (ADR 0030 §4; RFC 7516 §5.2,
/// §7.1).
///
/// Only [`JweDecrypted::protected_header`] is integrity-protected (ADR 0050 §3).
pub fn jwe_decrypt_compact(
    token: &str,
    key: &str,
    options: &JweDecryptOptions,
) -> SurfaceResult<JweDecrypted> {
    // stub: T08
    let _ = (token, key, options);
    Err(SurfaceError::from(polyjose::Error::UnsupportedAlgorithm))
}

/// Decrypts the flattened or general JWE JSON Serialization `jwe` with `key` (ADR 0030 §4;
/// RFC 7516 §5.2, §7.2).
///
/// Only [`JweDecrypted::protected_header`] is integrity-protected: the shared and per-recipient
/// unprotected headers, and the merged [`JweDecrypted::header`], are not (ADR 0050 §3).
pub fn jwe_decrypt_json(
    jwe: &str,
    key: &str,
    options: &JweDecryptOptions,
) -> SurfaceResult<JweDecrypted> {
    // stub: T08
    let _ = (jwe, key, options);
    Err(SurfaceError::from(polyjose::Error::UnsupportedAlgorithm))
}
