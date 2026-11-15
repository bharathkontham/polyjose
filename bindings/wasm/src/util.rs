//! The utility exports (ADR 0030 §4, "Utilities"), with the unverified decode utilities
//! (ADR 0069). Each is a type conversion and one surface call (ADR 0030 §1, "the adapter test").

use js_sys::{JsString, Object, Uint8Array};
use polyjose_surface::util;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::error::polyjose_error;
use crate::write;

/// The polyjose crate version, e.g. `0.1.0` (ADR 0030 §4). Synchronous (BACKEND.md).
#[wasm_bindgen(js_name = version)]
pub fn version() -> String {
    util::version().to_owned()
}

/// Every stable error code, in the core's order: `polyjose::Error::CODES` (ADR 0030 §5).
/// Synchronous (BACKEND.md).
#[wasm_bindgen(js_name = errorCodes)]
pub fn error_codes() -> Vec<String> {
    util::error_codes()
        .iter()
        .map(|code| (*code).to_owned())
        .collect()
}

/// Encodes `data` as unpadded base64url (RFC 4648 §5, RFC 7515 §2).
///
/// The input may be key material, so it is taken by value and wiped on return, and the text,
/// which encodes it equally, is copied into the JS string from a zeroizing buffer
/// (ADR 0030 §7, ADR 0031 §3).
#[wasm_bindgen(js_name = base64urlEncode)]
pub fn base64url_encode(data: Vec<u8>) -> JsString {
    let data = Zeroizing::new(data);
    let text = Zeroizing::new(util::base64url_encode(&data));
    JsString::from(text.as_str())
}

/// Decodes strict unpadded base64url (RFC 4648 §5, RFC 7515 §2): padding, characters outside the
/// URL-safe alphabet, whitespace and non-canonical trailing bits fail with `InvalidBase64`.
///
/// The text may encode key material: it is taken by value and wiped on return, and the octets
/// are copied into the `Uint8Array` from a zeroizing buffer (ADR 0030 §7, ADR 0031 §3).
#[wasm_bindgen(js_name = base64urlDecode)]
pub fn base64url_decode(text: String) -> Result<Uint8Array, JsValue> {
    let text = Zeroizing::new(text);
    let bytes = Zeroizing::new(util::base64url_decode(&text).map_err(polyjose_error)?);
    Ok(Uint8Array::from(&bytes[..]))
}

/// Reads the protected header of a compact JWS (3 parts) or JWE (5 parts) without verifying or
/// decrypting it (ADR 0069 §1-§2; RFC 7515 §7.1, RFC 7516 §7.1). This doesn't check the
/// signature; don't trust these values until you verify the token. Returns the header's JSON
/// text.
///
/// The token embeds base64url(payload) (ADR 0049 §4): it is taken by value and wiped on return.
/// The header text is copied into the JS string from a zeroizing buffer, as the Node adapter does
/// with every string result.
#[wasm_bindgen(js_name = decodeProtectedHeaderUnverified)]
pub fn decode_protected_header_unverified(token: String) -> Result<JsString, JsValue> {
    let token = Zeroizing::new(token);
    let header =
        Zeroizing::new(util::decode_protected_header_unverified(&token).map_err(polyjose_error)?);
    Ok(JsString::from(header.as_str()))
}

/// Reads the protected header and the payload of a compact JWS without verifying it
/// (ADR 0069 §1-§2; RFC 7515 §7.1). This doesn't check the signature; don't trust these values
/// until you verify the JWS with `jwsVerifyCompact`. Returns `{ protectedHeader, payload }`.
///
/// The JWS is taken by value and wiped on return; the payload is copied into the `Uint8Array`
/// from the surface's zeroizing buffer (ADR 0069 §5, ADR 0030 §7.2).
#[wasm_bindgen(js_name = decodeJwsUnverified)]
pub fn decode_jws_unverified(jws: String) -> Result<Object, JsValue> {
    let jws = Zeroizing::new(jws);
    let decoded = util::decode_jws_unverified(&jws).map_err(polyjose_error)?;
    write::jws_unverified(decoded)
}

/// Reads the header and the claims of a compact signed JWT without verifying or validating it
/// (ADR 0069 §1-§2; RFC 7519 §7.2). This doesn't check the signature; don't trust these values
/// until you verify the token with `jwtVerify`. Returns `{ header, claims }`.
#[wasm_bindgen(js_name = decodeJwtUnverified)]
pub fn decode_jwt_unverified(token: String) -> Result<Object, JsValue> {
    let token = Zeroizing::new(token);
    let decoded = util::decode_jwt_unverified(&token).map_err(polyjose_error)?;
    write::jwt_unverified(decoded)
}
