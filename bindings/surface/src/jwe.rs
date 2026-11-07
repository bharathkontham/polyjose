//! JWE operations (ADR 0030 §4, "JWE"; RFC 7516, RFC 7518 §4–§5; ADR 0017, 0021, 0022, 0023,
//! 0050).
//!
//! Keys are JWK JSON text, borrowed or held as [`SecretString`](crate::secret::SecretString)
//! (ADR 0030 §7.1). Plaintext is borrowed on the way in, and decrypted plaintext and `aad` are
//! [`SecretBytes`](crate::secret::SecretBytes) (ADR 0030 §7.2, ADR 0050 §4). Decryption takes the
//! caller's `alg` and `enc` allow-lists (ADR 0007, RFC 8725 §3.1).

use polyjose::header::Header;
use polyjose::jwa::{ContentEncAlg, KeyMgmtAlg};
use polyjose::jwe::{self, DecryptPolicy, Decrypted, Encryptor, JsonForm, Recipient};
use polyjose::jwk::Jwk;
use zeroize::Zeroizing;

use crate::error::SurfaceResult;
use crate::records::{
    JweDecryptOptions, JweDecrypted, JweEncryptOptions, JweRecipient, algs, apply, apply_flag,
    strs, to_usize, try_apply,
};
use crate::secret::SecretBytes;

/// Encrypts `plaintext` into a JWE Compact Serialization, for exactly one recipient (ADR 0030
/// §4; RFC 7516 §5.1, §7.1).
///
/// The core puts `alg`, `enc` and the key management parameters in the JWE Protected Header,
/// the only header the compact form has (RFC 7516 §7.1, ADR 0050 §1).
///
/// # Errors
///
/// The core's codes (ADR 0030 §5). The first error wins, in this order: each recipient's key
/// and header, the protected header, the shared header, then encryption. Notably:
///
/// - `InvalidFormat` unless there is exactly one recipient and no `aad`, shared unprotected
///   header or per-recipient header (RFC 7516 §7.1);
/// - `UnsupportedAlgorithm` for `RSA-OAEP` and `RSA1_5` (ADR 0021, ADR 0022), an unknown `alg`
///   or `enc`, and `compress: true`, as the bindings build without `deflate` (ADR 0030 §4,
///   ADR 0034 §3);
/// - `InvalidKey` for a key of the wrong size, or a PBES2 `p2c` or `p2s_len` outside what the
///   core encrypts with (RFC 7518 §4.8.1.1, §4.8.1.2; ADR 0050 §2).
pub fn jwe_encrypt_compact(plaintext: &[u8], options: &JweEncryptOptions) -> SurfaceResult<String> {
    Ok(encryptor(options)?.encrypt_compact(plaintext)?)
}

/// Encrypts `plaintext` into a JWE JSON Serialization of `form`, `general` or `flattened`
/// (ADR 0030 §4; RFC 7516 §5.1, §7.2.1, §7.2.2). Any other `form` fails with
/// `UnsupportedAlgorithm` (ADR 0030 §5).
///
/// In the flattened form the core protects `alg` and the key management parameters; in the
/// general form it puts them in each recipient's `header`, except for the direct modes `dir`
/// and `ECDH-ES`, which it protects in every form, leaving an empty recipient entry (ADR 0050
/// §1).
///
/// # Errors
///
/// `UnsupportedAlgorithm` for an unknown `form`, checked before anything else; then the codes of
/// [`jwe_encrypt_compact`], except that `aad` and the unprotected headers are allowed, and
/// `InvalidFormat` is for no recipients, or more than one when flattened (RFC 7516 §7.2.2).
pub fn jwe_encrypt_json(
    plaintext: &[u8],
    options: &JweEncryptOptions,
    form: &str,
) -> SurfaceResult<String> {
    let form = json_form(form)?;
    Ok(encryptor(options)?.encrypt_json(plaintext, form)?)
}

/// The core [`JsonForm`] named by `form`, exactly as ADR 0030 §4 spells it (RFC 7516 §7.2.1
/// general, §7.2.2 flattened). Any other string is `UnsupportedAlgorithm` (ADR 0030 §5).
fn json_form(form: &str) -> polyjose::Result<JsonForm> {
    match form {
        "general" => Ok(JsonForm::General),
        "flattened" => Ok(JsonForm::Flattened),
        _ => Err(polyjose::Error::UnsupportedAlgorithm),
    }
}

/// The core [`Encryptor`] for `options` (ADR 0030 §3; RFC 7516 §5.1).
///
/// The steps run in the order the conformance runners use (conformance/README.md): each
/// recipient (its key, then its header), then the protected header, then the shared unprotected
/// header; the first error is the result. Every header is parsed by the core's I-JSON parser
/// (ADR 0016, ADR 0030 §2). `None` and `false` call no core setter, so the core keeps its
/// defaults, among them the PBES2 `p2c` and `p2s` length (ADR 0023) and no compression.
///
/// The AAD is copied once into the core encryptor, which owns it from then on.
///
/// Crate-visible so the nested JWT encrypt (`jwt.rs`) can build the same encryptor.
pub(crate) fn encryptor(options: &JweEncryptOptions) -> polyjose::Result<Encryptor> {
    let recipients = options
        .recipients
        .iter()
        .map(recipient)
        .collect::<polyjose::Result<Vec<_>>>()?;
    let mut encryptor = Encryptor::new(ContentEncAlg::from(options.enc.as_str()));
    encryptor = try_apply(encryptor, options.protected_header.as_deref(), |e, json| {
        Ok(e.protected_header(Header::from_json(json.as_bytes())?))
    })?;
    encryptor = try_apply(
        encryptor,
        options.shared_unprotected_header.as_deref(),
        |e, json| Ok(e.shared_unprotected_header(Header::from_json(json.as_bytes())?)),
    )?;
    encryptor = apply(
        encryptor,
        options.aad.as_ref().map(SecretBytes::as_bytes),
        Encryptor::aad,
    );
    encryptor = apply_flag(encryptor, options.compress, Encryptor::compress);
    Ok(recipients.into_iter().fold(encryptor, Encryptor::recipient))
}

/// The core [`Recipient`] for `recipient` (RFC 7516 §5.1 steps 1–8; RFC 7518 §4).
///
/// The key is parsed from its [`SecretString`](crate::secret::SecretString) into a core JWK,
/// which wipes itself on drop (ADR 0030 §7.1); `apu`, `apv`, `p2c` and `p2s_len` reach the core
/// only when set (RFC 7518 §4.6.1.2, §4.6.1.3, §4.8.1.1, §4.8.1.2).
fn recipient(recipient: &JweRecipient) -> polyjose::Result<Recipient> {
    let key = Jwk::from_json(recipient.key.as_str().as_bytes())?;
    let mut out = Recipient::new(KeyMgmtAlg::from(recipient.alg.as_str()), &key);
    out = try_apply(out, recipient.header.as_deref(), |r, json| {
        Ok(r.header(Header::from_json(json.as_bytes())?))
    })?;
    out = apply(out, recipient.apu.as_deref(), Recipient::apu);
    out = apply(out, recipient.apv.as_deref(), Recipient::apv);
    out = apply(out, recipient.p2c, Recipient::p2c);
    out = apply(out, recipient.p2s_len.map(to_usize), Recipient::p2s_len);
    Ok(out)
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
