//! The JWS exports (ADR 0030 §4, "JWS"): `jwsSignCompact`, `jwsSignFlattened`,
//! `jwsSignGeneral`, `jwsVerifyCompact` and `jwsVerifyJson` (RFC 7515, RFC 7797, RFC 8037;
//! ADR 0026).
//!
//! The payload is secret (ADR 0030 §7, ADR 0049 §4): it is taken by value and wiped on return,
//! and so are keys and tokens, whose payload segment encodes it (RFC 7515 §7.1). A serialized JWS
//! is copied into the JS string from a zeroizing buffer for the same reason, and the verified
//! payload is copied out of the surface's [`SecretBytes`](polyjose_surface::SecretBytes)
//! (ADR 0030 §7.2). Verification takes the caller's allow-list only (RFC 8725 §3.1, ADR 0007).

use js_sys::{JsString, Object};
use polyjose_surface::jws;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::error::polyjose_error;
use crate::{read, write};

/// Signs `payload` with `key` into a JWS Compact Serialization (RFC 7515 §3.1, §5.1, §7.1).
/// `options` is `{ protectedHeader?, protectedB64u?, detached? }`: exactly one header form, or
/// `InvalidHeader` (ADR 0030 §4); `detached` leaves the payload out (RFC 7515 Appendix F).
#[wasm_bindgen(js_name = jwsSignCompact)]
pub fn jws_sign_compact(
    payload: Vec<u8>,
    key: String,
    options: &JsValue,
) -> Result<JsString, JsValue> {
    let payload = Zeroizing::new(payload);
    let key = Zeroizing::new(key);
    let options = read::jws_sign_options(options)?;
    let jws =
        Zeroizing::new(jws::jws_sign_compact(&payload, &key, &options).map_err(polyjose_error)?);
    Ok(JsString::from(jws.as_str()))
}

/// Signs `payload` into a flattened JWS JSON Serialization with one `signer`
/// (`{ key, protectedHeader?, protectedB64u?, unprotectedHeader? }`) (RFC 7515 §7.2.2).
#[wasm_bindgen(js_name = jwsSignFlattened)]
pub fn jws_sign_flattened(
    payload: Vec<u8>,
    signer: &JsValue,
    detached: bool,
) -> Result<JsString, JsValue> {
    let payload = Zeroizing::new(payload);
    let signer = read::jws_signer(signer)?;
    let jws = Zeroizing::new(
        jws::jws_sign_flattened(&payload, &signer, detached).map_err(polyjose_error)?,
    );
    Ok(JsString::from(jws.as_str()))
}

/// Signs `payload` into a general JWS JSON Serialization, one signature per signer
/// (RFC 7515 §7.2.1). The core bounds the number of signers (ADR 0026 §7).
#[wasm_bindgen(js_name = jwsSignGeneral)]
pub fn jws_sign_general(
    payload: Vec<u8>,
    signers: &JsValue,
    detached: bool,
) -> Result<JsString, JsValue> {
    let payload = Zeroizing::new(payload);
    let signers = read::jws_signers(signers)?;
    let jws = Zeroizing::new(
        jws::jws_sign_general(&payload, &signers, detached).map_err(polyjose_error)?,
    );
    Ok(JsString::from(jws.as_str()))
}

/// Verifies a JWS Compact Serialization with `key`, accepting only `options.allowedAlgs`
/// (RFC 7515 §5.2, RFC 8725 §3.1). Returns `{ alg, payload, protectedHeader?,
/// unprotectedHeader?, signatureIndex }`.
#[wasm_bindgen(js_name = jwsVerifyCompact)]
pub fn jws_verify_compact(
    token: String,
    key: String,
    options: &JsValue,
) -> Result<Object, JsValue> {
    let token = Zeroizing::new(token);
    let key = Zeroizing::new(key);
    let options = read::jws_verify_options(options)?;
    let verified = jws::jws_verify_compact(&token, &key, &options).map_err(polyjose_error)?;
    write::jws_verified(verified)
}

/// Verifies a flattened or general JWS JSON Serialization with `key` (RFC 7515 §5.2, §7.2): the
/// first signature that verifies under an allowed algorithm wins, and `signatureIndex` says which.
#[wasm_bindgen(js_name = jwsVerifyJson)]
pub fn jws_verify_json(jws: String, key: String, options: &JsValue) -> Result<Object, JsValue> {
    let jws = Zeroizing::new(jws);
    let key = Zeroizing::new(key);
    let options = read::jws_verify_options(options)?;
    let verified = jws::jws_verify_json(&jws, &key, &options).map_err(polyjose_error)?;
    write::jws_verified(verified)
}
