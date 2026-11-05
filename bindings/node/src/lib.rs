use napi_derive::napi;

#[napi]
pub fn base64url_encode(data: napi::bindgen_prelude::Buffer) -> String {
    polyjose::util::b64url_encode(&data)
}
