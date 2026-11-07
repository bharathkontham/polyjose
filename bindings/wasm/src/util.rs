//! The utility exports (ADR 0030 §4, "Utilities"). Each is a type conversion and one surface
//! call (ADR 0030 §1, "the adapter test").

use js_sys::{JsString, Uint8Array};
use polyjose_surface::util;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::error::polyjose_error;

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
