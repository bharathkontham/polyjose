//! The JWE exports (ADR 0030 §4, "JWE"): `jweEncryptCompact`, `jweEncryptJson`,
//! `jweDecryptCompact` and `jweDecryptJson` (RFC 7516, RFC 7518 §4–§5; ADR 0017, ADR 0022, ADR 0023, ADR 0067).
//!
//! Plaintext, keys and the `aad` are secret (ADR 0030 §7, ADR 0050 §4): inputs are taken by value
//! and wiped on return (ADR 0030 §7.1), and decrypted values are copied out of the surface's
//! [`SecretBytes`](polyjose_surface::SecretBytes) (ADR 0030 §7.2). Tokens are taken by value too,
//! at no cost, so no data string of any JOSE operation lingers in wasm memory. A serialized JWE
//! is ciphertext and returns as a plain `String`. Decryption takes the caller's `alg` and `enc`
//! allow-lists only (RFC 8725 §3.1, ADR 0007).

use js_sys::Object;
use polyjose_surface::jwe;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::error::polyjose_error;
use crate::{read, write};

/// Encrypts `plaintext` into a JWE Compact Serialization (RFC 7516 §3.1, §5.1, §7.1). `options`
/// is `{ enc, recipients, protectedHeader?, sharedUnprotectedHeader?, aad?, compress? }` with
/// exactly one recipient; compact has no `aad` (RFC 7516 §7.1).
#[wasm_bindgen(js_name = jweEncryptCompact)]
pub fn jwe_encrypt_compact(plaintext: Vec<u8>, options: &JsValue) -> Result<String, JsValue> {
    let plaintext = Zeroizing::new(plaintext);
    let options = read::jwe_encrypt_options(options)?;
    jwe::jwe_encrypt_compact(&plaintext, &options).map_err(polyjose_error)
}

/// Encrypts `plaintext` into a JWE JSON Serialization, `form` `general` or `flattened`
/// (RFC 7516 §7.2.1, §7.2.2); any other form fails with `UnsupportedAlgorithm` (ADR 0030 §5).
#[wasm_bindgen(js_name = jweEncryptJson)]
pub fn jwe_encrypt_json(
    plaintext: Vec<u8>,
    options: &JsValue,
    form: &str,
) -> Result<String, JsValue> {
    let plaintext = Zeroizing::new(plaintext);
    let options = read::jwe_encrypt_options(options)?;
    jwe::jwe_encrypt_json(&plaintext, &options, form).map_err(polyjose_error)
}

/// Decrypts a JWE Compact Serialization with `key`, accepting only `options.allowedAlgs` and
/// `options.allowedEnc` (RFC 7516 §5.2, RFC 8725 §3.1). Returns `{ plaintext, header,
/// protectedHeader?, sharedUnprotectedHeader?, recipientHeader?, aad?, recipientIndex }`.
#[wasm_bindgen(js_name = jweDecryptCompact)]
pub fn jwe_decrypt_compact(
    token: String,
    key: String,
    options: &JsValue,
) -> Result<Object, JsValue> {
    let token = Zeroizing::new(token);
    let key = Zeroizing::new(key);
    let options = read::jwe_decrypt_options(options)?;
    let decrypted = jwe::jwe_decrypt_compact(&token, &key, &options).map_err(polyjose_error)?;
    write::jwe_decrypted(decrypted)
}

/// Decrypts a flattened or general JWE JSON Serialization with `key` (RFC 7516 §5.2, §7.2): the
/// first recipient that decrypts wins, and `recipientIndex` says which.
#[wasm_bindgen(js_name = jweDecryptJson)]
pub fn jwe_decrypt_json(jwe: String, key: String, options: &JsValue) -> Result<Object, JsValue> {
    let jwe = Zeroizing::new(jwe);
    let key = Zeroizing::new(key);
    let options = read::jwe_decrypt_options(options)?;
    let decrypted = jwe::jwe_decrypt_json(&jwe, &key, &options).map_err(polyjose_error)?;
    write::jwe_decrypted(decrypted)
}
