//! Surface results to plain JS objects with camelCase members (BACKEND.md, "Operations";
//! ADR 0030 §2, §4).
//!
//! - **Secrets out** (ADR 0030 §7.2, ADR 0031 §3): secret members (`JwsVerified.payload`,
//!   `JweDecrypted.plaintext` and `aad`) become a `Uint8Array` copied straight from the surface's
//!   borrowed, zeroizing buffer, and the result is consumed here so that buffer is wiped as soon
//!   as the object exists (measured: no copy left in wasm memory, 0006 research §3).
//! - **Absent optional members are left out** (BACKEND.md: "may be absent"), never written as
//!   `null`. JSON-valued members (headers, claims) are the core's JSON text; the facade parses
//!   them (ADR 0030 §2).
//!
//! `Reflect.set` on a fresh ordinary object defines an own data property (ECMA-262,
//! OrdinarySet), so the `?` below is never taken in practice; it only forwards whatever a JS
//! engine would throw.

use js_sys::{Object, Reflect, Uint8Array};
use polyjose_surface::records::{JweDecrypted, JwsVerified};
use wasm_bindgen::JsValue;

/// A JS object being filled.
struct Out(Object);

impl Out {
    fn new() -> Self {
        Self(Object::new())
    }

    fn set(&self, key: &str, value: &JsValue) -> Result<(), JsValue> {
        Reflect::set(&self.0, &JsValue::from_str(key), value).map(drop)
    }

    fn str(&self, key: &str, value: &str) -> Result<(), JsValue> {
        self.set(key, &JsValue::from_str(value))
    }

    fn opt_str(&self, key: &str, value: Option<&str>) -> Result<(), JsValue> {
        value.map_or(Ok(()), |v| self.str(key, v))
    }

    /// Bytes copied from a borrowed slice into a new `Uint8Array` (ADR 0030 §7.2).
    fn bytes(&self, key: &str, value: &[u8]) -> Result<(), JsValue> {
        self.set(key, &Uint8Array::from(value))
    }

    fn u32(&self, key: &str, value: u32) -> Result<(), JsValue> {
        self.set(key, &JsValue::from(value))
    }
}

/// `{ alg, payload, protectedHeader?, unprotectedHeader?, signatureIndex }` (RFC 7515 §5.2).
/// The payload is secret (ADR 0049 §4).
pub(crate) fn jws_verified(v: JwsVerified) -> Result<Object, JsValue> {
    let o = Out::new();
    o.str("alg", &v.alg)?;
    o.bytes("payload", v.payload.as_bytes())?;
    o.opt_str("protectedHeader", v.protected_header.as_deref())?;
    o.opt_str("unprotectedHeader", v.unprotected_header.as_deref())?;
    o.u32("signatureIndex", v.signature_index)?;
    Ok(o.0)
}

/// `{ plaintext, header, protectedHeader?, sharedUnprotectedHeader?, recipientHeader?, aad?,
/// recipientIndex }` (RFC 7516 §5.2, §7.2.1). The plaintext and the `aad` are secret
/// (ADR 0030 §7, ADR 0050 §4).
pub(crate) fn jwe_decrypted(v: JweDecrypted) -> Result<Object, JsValue> {
    let o = Out::new();
    o.bytes("plaintext", v.plaintext.as_bytes())?;
    o.str("header", &v.header)?;
    o.opt_str("protectedHeader", v.protected_header.as_deref())?;
    o.opt_str(
        "sharedUnprotectedHeader",
        v.shared_unprotected_header.as_deref(),
    )?;
    o.opt_str("recipientHeader", v.recipient_header.as_deref())?;
    if let Some(aad) = &v.aad {
        o.bytes("aad", aad.as_bytes())?;
    }
    o.u32("recipientIndex", v.recipient_index)?;
    Ok(o.0)
}
