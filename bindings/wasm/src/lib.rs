//! polyjose-wasm: the wasm-bindgen adapter of `@polyjose/wasm` (ADR 0030 §1, ADR 0031 §3).

use wasm_bindgen::prelude::*;

/// Encodes `data` as unpadded base64url (RFC 4648 §5, RFC 7515 §2).
#[wasm_bindgen(js_name = base64urlEncode)]
pub fn base64url_encode(data: &[u8]) -> String {
    polyjose_surface::util::base64url_encode(data)
}
