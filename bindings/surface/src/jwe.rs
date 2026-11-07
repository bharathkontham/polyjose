//! JWE operations (ADR 0030 §4, "JWE"; RFC 7516, RFC 7518 §4–§5; ADR 0017, 0021, 0022, 0023,
//! 0050).
//!
//! Keys are JWK JSON text, borrowed or held as [`SecretString`](crate::secret::SecretString)
//! (ADR 0030 §7.1). Plaintext is borrowed on the way in, and decrypted plaintext and `aad` are
//! [`SecretBytes`](crate::secret::SecretBytes) (ADR 0030 §7.2, ADR 0050 §4). Decryption takes the
//! caller's `alg` and `enc` allow-lists (ADR 0007, RFC 8725 §3.1).

use polyjose::jwa::{ContentEncAlg, KeyMgmtAlg};
use polyjose::jwe::{self, DecryptPolicy, Decrypted};
use polyjose::jwk::Jwk;
use zeroize::Zeroizing;

use crate::error::{SurfaceError, SurfaceResult};
use crate::records::{
    JweDecryptOptions, JweDecrypted, JweEncryptOptions, algs, apply, strs, to_usize,
};
use crate::secret::SecretBytes;

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
    let key = Jwk::from_json(key.as_bytes())?;
    let policy = decrypt_policy(options)?;
    Ok(decrypted(jwe::decrypt_compact(token, &key, &policy)?)?)
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
    let key = Jwk::from_json(key.as_bytes())?;
    let policy = decrypt_policy(options)?;
    Ok(decrypted(jwe::decrypt_json(jwe, &key, &policy)?)?)
}

/// The core [`DecryptPolicy`] for `options` (ADR 0030 §3).
///
/// The allow-lists go to the core as given, so an empty list is the core's
/// `AlgorithmNotAllowed` (ADR 0007, RFC 8725 §3.1) and an unknown name is kept for the core to
/// refuse. Each tunable calls its core setter only when it is `Some`, so the limits
/// (`max_pbes2_count`, a per-token budget, ADR 0023 and ADR 0050 §2; `max_decompressed_len`,
/// ADR 0017; `max_input_len` and `max_recipients`, ADR 0026 §7) default in the core alone.
///
/// Crate-visible so the nested JWT decrypt (`jwt.rs`) can build the same policy.
pub(crate) fn decrypt_policy(options: &JweDecryptOptions) -> polyjose::Result<DecryptPolicy> {
    let allowed_algs: Vec<KeyMgmtAlg> = algs(&options.allowed_algs);
    let allowed_enc: Vec<ContentEncAlg> = algs(&options.allowed_enc);
    let mut policy = DecryptPolicy::new(&allowed_algs, &allowed_enc)?;
    policy = apply(
        policy,
        options.max_pbes2_count,
        DecryptPolicy::max_pbes2_count,
    );
    policy = apply(
        policy,
        options.max_decompressed_len.map(to_usize),
        DecryptPolicy::max_decompressed_len,
    );
    policy = apply(
        policy,
        options.max_input_len.map(to_usize),
        DecryptPolicy::max_input_len,
    );
    policy = apply(
        policy,
        options.max_recipients.map(to_usize),
        DecryptPolicy::max_recipients,
    );
    policy = apply(policy, options.understood_crit.as_deref(), |p, names| {
        p.understood_crit(&strs(names))
    });
    Ok(policy)
}

/// The surface record for a core [`Decrypted`] (RFC 7516 §5.2).
///
/// Each header part is written by the core's own JSON (ADR 0016, ADR 0030 §2), in the core's
/// member order. The plaintext moves, uncopied, into a [`SecretBytes`]; the AAD is copied once,
/// straight into a [`SecretBytes`], because the core lends it only, and the core's own buffer is
/// wiped when `decrypted` drops (ADR 0030 §7.2, ADR 0050 §4).
fn decrypted(decrypted: Decrypted) -> polyjose::Result<JweDecrypted> {
    let header = decrypted.header().to_json()?;
    let protected_header = decrypted
        .protected_header()
        .map(|h| h.to_json())
        .transpose()?;
    let shared_unprotected_header = decrypted.shared_header().map(|h| h.to_json()).transpose()?;
    let recipient_header = decrypted
        .recipient_header()
        .map(|h| h.to_json())
        .transpose()?;
    let aad = decrypted
        .aad()
        .map(|aad| SecretBytes::from(Zeroizing::new(aad.to_vec())));
    // The index is below the policy's `max_recipients`, which the surface sets from a u32
    // (ADR 0030 §2), so it always fits; the error branch is unreachable.
    let recipient_index = u32::try_from(decrypted.recipient())
        .map_err(|_| polyjose::Error::InvalidFormat("too many recipients"))?;
    Ok(JweDecrypted {
        plaintext: SecretBytes::from(decrypted.into_plaintext()),
        header,
        protected_header,
        shared_unprotected_header,
        recipient_header,
        aad,
        recipient_index,
    })
}
