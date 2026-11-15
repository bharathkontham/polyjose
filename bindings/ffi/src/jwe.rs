//! The JWE exports (ADR 0030 §4, "JWE"): `jwe_encrypt_compact`, `jwe_encrypt_json`,
//! `jwe_decrypt_compact` and `jwe_decrypt_json` (RFC 7516, RFC 7518 §4–§5).
//!
//! Each export is a type conversion and one call into `polyjose_surface::jwe` (ADR 0030 §1,
//! "the adapter test"). Decryption takes the caller's `alg` and `enc` allow-lists only (RFC 8725
//! §3.1, ADR 0007); the PBES2 bound and the input limits are the core's defaults unless set
//! (ADR 0023, ADR 0026 §7). The bindings build without the core's `deflate` feature, so
//! `compress: true` and `zip` tokens fail with `UnsupportedAlgorithm` (ADR 0030 §4, ADR 0034 §3).
//!
//! **Secrets (ADR 0030 §7).** Plaintext, keys (PBES2 passwords among them) and `aad` are secret.
//! - **Inputs.** The plaintext `Vec<u8>` and the key `String` are moved into [`Zeroizing`]
//!   owners, and [`JweEncryptOptions`] (recipient keys, `aad`) is converted into the surface's
//!   record, whose secret fields are `SecretString`/`SecretBytes`, in the first statements.
//!   UniFFI 0.32.2 lifted each `Vec<u8>` argument, and each `String` or `Vec<u8>` inside a record
//!   argument, by copying it out of a `RustBuffer` that it then freed unwiped: 1 copy each
//!   (ADR 0030 §7.1, §7.3; restated in ADR 0058).
//! - **Outputs.** [`JweDecrypted::plaintext`] and [`JweDecrypted::aad`] are copied once from the
//!   surface's `SecretBytes`, which are wiped when the surface record drops (ADR 0030 §7.2,
//!   ADR 0050 §4). UniFFI 0.32.2 then writes the record into a buffer that grows as it is written
//!   and drops the record, and the host frees the final `RustBuffer`, all unwiped. So each of
//!   the two fields leaves **at least 2** full Rust-heap copies (the adapter's vector and the
//!   host-freed buffer), plus a full or partial copy for each move of the growing buffer,
//!   depending on the size, the fields written after it and the platform allocator (2 to 5 full
//!   copies of the plaintext and 2 to 3 of the aad measured on macOS). These are the measured
//!   residual of ADR 0058, which supersedes ADR 0030 §7.3 for outputs; the adapter cannot reach
//!   them without `unsafe`. Callers should wipe the `ByteArray`/`Data` they receive (ADR 0030
//!   §7.4).

use std::sync::Arc;

use polyjose_surface::records as surface;
use zeroize::Zeroizing;

use crate::PolyjoseError;
use crate::platform_key::{HostKey, PlatformKey};
use crate::records::{JweDecryptOptions, JweDecrypted, JweEncryptOptions};

/// Encrypts `plaintext` into a JWE Compact Serialization, for exactly one recipient (ADR 0030
/// §4; RFC 7516 §5.1, §7.1). The core puts `alg`, `enc` and the key management parameters in
/// the JWE Protected Header (RFC 7516 §7.1, ADR 0050 §1).
///
/// # Errors
///
/// `InvalidFormat` unless there is exactly one recipient and no `aad`, shared unprotected header
/// or per-recipient header (RFC 7516 §7.1); `UnsupportedAlgorithm` for `RSA-OAEP`, `RSA1_5`
/// (ADR 0022, ADR 0067 §3), unknown names and `compress: true`; `InvalidKey` for a key of the wrong
/// size or a PBES2 `p2c`/`p2s_len` outside the core's range (RFC 7518 §4.8.1.1, §4.8.1.2;
/// ADR 0050 §2).
#[uniffi::export]
pub fn jwe_encrypt_compact(
    plaintext: Vec<u8>,
    options: JweEncryptOptions,
) -> Result<String, PolyjoseError> {
    let plaintext = Zeroizing::new(plaintext);
    let options = surface::JweEncryptOptions::from(options);
    Ok(polyjose_surface::jwe::jwe_encrypt_compact(
        &plaintext, &options,
    )?)
}

/// Encrypts `plaintext` into a JWE JSON Serialization of `form`, `general` or `flattened`
/// (ADR 0030 §4; RFC 7516 §5.1, §7.2.1, §7.2.2).
///
/// # Errors
///
/// `UnsupportedAlgorithm` for any other `form` (ADR 0030 §5), checked first; then those of
/// [`jwe_encrypt_compact`], except that `aad` and the unprotected headers are allowed, and
/// `InvalidFormat` is for no recipients, or more than one when flattened (RFC 7516 §7.2.2).
#[uniffi::export]
pub fn jwe_encrypt_json(
    plaintext: Vec<u8>,
    options: JweEncryptOptions,
    form: String,
) -> Result<String, PolyjoseError> {
    let plaintext = Zeroizing::new(plaintext);
    let options = surface::JweEncryptOptions::from(options);
    Ok(polyjose_surface::jwe::jwe_encrypt_json(
        &plaintext, &options, &form,
    )?)
}

/// Decrypts the JWE Compact Serialization `token` with `key` (ADR 0030 §4; RFC 7516 §5.2,
/// §7.1). Only `protected_header` of the result is integrity-protected (ADR 0050 §3).
///
/// # Errors
///
/// `AlgorithmNotAllowed` for an empty allow-list or an `alg`/`enc` outside it (RFC 8725 §3.1);
/// `InvalidHeader` for `dir` or `ECDH-ES` without `alg` and `enc` protected (ADR 0050 §1);
/// `KeyAlgorithmMismatch` for `RSA-OAEP-256` with an RSA public key (decryption needs the private
/// key, ADR 0067 §2); `UnsupportedAlgorithm` for `RSA-OAEP`, `RSA1_5` (ADR 0022) and `zip`; and
/// `DecryptionFailed`, one code and message for every failure once key management starts, a PBES2
/// count over `max_pbes2_count` and an `RSA-OAEP-256` Encrypted Key that does not decrypt included
/// (RFC 7516 §11.4–§11.5, ADR 0023, ADR 0050 §2, ADR 0067 §5).
#[uniffi::export]
pub fn jwe_decrypt_compact(
    token: String,
    key: String,
    options: JweDecryptOptions,
) -> Result<JweDecrypted, PolyjoseError> {
    let key = Zeroizing::new(key);
    let options = surface::JweDecryptOptions::from(options);
    Ok(polyjose_surface::jwe::jwe_decrypt_compact(&token, &key, &options)?.into())
}

/// Decrypts the JWE Compact Serialization `token` with the host's platform key (ADR 0071 §5;
/// RFC 7516 §5.2, §7.1): `jwe_decrypt_compact` with the private-key step done by `key`.
///
/// The `alg` and `enc` must be in the allow-lists before `key` is touched (RFC 8725 §3.1). A
/// platform key serves `ECDH-ES` and `ECDH-ES+A128KW`, `+A192KW`, `+A256KW` on P-256, P-384 and
/// P-521 (`key.agree` with the validated `epk`, RFC 7518 §4.6) and `RSA-OAEP-256`
/// (`key.decryptKey`, RFC 7518 §4.3).
///
/// # Errors
///
/// `AlgorithmNotAllowed` for an empty allow-list or an `alg`/`enc` outside it, with no call to
/// `key`; `UnsupportedAlgorithm` for an `alg` a platform key may not serve; `KeyAlgorithmMismatch`
/// for an `alg` the key is not bound to; `KeyNotFound` and `UserAuthenticationRequired` from the
/// key; `DecryptionFailed` for every other failure, of the key (any other exception included) or
/// of the JWE (RFC 7516 §11.5, ADR 0071 §4).
#[uniffi::export]
pub fn jwe_decrypt_compact_with_platform_key(
    token: String,
    key: Arc<dyn PlatformKey>,
    options: JweDecryptOptions,
) -> Result<JweDecrypted, PolyjoseError> {
    let key = HostKey(key);
    let options = surface::JweDecryptOptions::from(options);
    Ok(
        polyjose_surface::jwe::jwe_decrypt_compact_with_platform_key(&token, &key, &options)?
            .into(),
    )
}

/// Decrypts the flattened or general JWE JSON Serialization `jwe` with `key`; the result names
/// the first recipient that decrypts (ADR 0030 §4; RFC 7516 §5.2, §7.2.1).
///
/// Only `protected_header` of the result is integrity-protected: the shared and per-recipient
/// unprotected headers, and the merged `header`, are not (ADR 0050 §3). The PBES2 budget is
/// spent across all recipients of one token (ADR 0050 §2).
///
/// # Errors
///
/// Those of [`jwe_decrypt_compact`], plus `InvalidFormat` for a JSON shape RFC 7516 §7.2
/// forbids or more recipients than `max_recipients` (ADR 0026 §7).
#[uniffi::export]
pub fn jwe_decrypt_json(
    jwe: String,
    key: String,
    options: JweDecryptOptions,
) -> Result<JweDecrypted, PolyjoseError> {
    let key = Zeroizing::new(key);
    let options = surface::JweDecryptOptions::from(options);
    Ok(polyjose_surface::jwe::jwe_decrypt_json(&jwe, &key, &options)?.into())
}

/// Decrypts the flattened or general JWE JSON Serialization `jwe` with the host's platform key
/// (ADR 0071 §5; RFC 7516 §5.2, §7.2): `jwe_decrypt_json` with the private-key step done by `key`.
///
/// `key` is called at most once per recipient whose `alg` passes the checks, in order, bounded by
/// `max_recipients`; `KeyNotFound` or `UserAuthenticationRequired` stops at once, so a cancelled
/// prompt is not followed by another (ADR 0071 §4).
///
/// # Errors
///
/// Those of [`jwe_decrypt_compact_with_platform_key`], plus `InvalidFormat` as for
/// [`jwe_decrypt_json`].
#[uniffi::export]
pub fn jwe_decrypt_json_with_platform_key(
    jwe: String,
    key: Arc<dyn PlatformKey>,
    options: JweDecryptOptions,
) -> Result<JweDecrypted, PolyjoseError> {
    let key = HostKey(key);
    let options = surface::JweDecryptOptions::from(options);
    Ok(polyjose_surface::jwe::jwe_decrypt_json_with_platform_key(&jwe, &key, &options)?.into())
}
