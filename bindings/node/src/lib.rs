//! polyjose-node: the napi-rs adapter of `@polyjose/node` (ADR 0030 §1, ADR 0031 §2).

use napi_derive::napi;

/// Encodes `data` as unpadded base64url (RFC 4648 §5).
#[napi]
pub fn base64url_encode(data: napi::bindgen_prelude::Buffer) -> String {
    polyjose_surface::util::base64url_encode(&data)
}
