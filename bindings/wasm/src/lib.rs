use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = base64urlEncode)]
pub fn base64url_encode(data: &[u8]) -> String {
    polyjose::util::b64url_encode(data)
}
