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
//! - **Own data, whatever `Object.prototype` holds** (BACKEND.md "Results", 0006 review S1,
//!   security audit I2). Each result is created with a null prototype (`Object.create(null)`,
//!   ECMA-262 §20.1.2.2), so `Reflect.set` has no parent to consult: OrdinarySetWithOwnDescriptor
//!   (ECMA-262 §10.1.9.2, step 2.c) finds no inherited setter and no inherited read-only member,
//!   and creates an own, enumerable, writable, configurable data property (CreateDataProperty,
//!   §7.3.5). On an object inheriting from `Object.prototype`, an accessor planted there would
//!   receive the secret `payload`, `plaintext` or `aad` and no own member would be made, and a
//!   read-only member there would make `Reflect.set` return `false` with the member missing. The
//!   facade reads results by own members only (`Object.hasOwn`, 0013 F09), which a prototype-less
//!   object meets.
//! - **A `false` is never dropped.** `Reflect.set` cannot return `false` for a new key on a fresh,
//!   extensible, prototype-less object, but if an engine ever did, the call fails with the
//!   adapter's `TypeError` (ADR 0031 §3) instead of returning a result without that member.

use js_sys::{Object, Reflect, Uint8Array};
use polyjose_surface::records::{JweDecrypted, JwsVerified, JwtNestedVerified, JwtVerified};
use wasm_bindgen::{JsCast, JsValue};

use crate::error::type_error;

/// A JS object being filled.
struct Out(Object);

impl Out {
    /// A new result object with a null prototype (ECMA-262 §20.1.2.2 `Object.create(null)`).
    fn new() -> Self {
        Self(Object::create(JsValue::NULL.unchecked_ref()))
    }

    /// Writes `key` as an own data property; a `false` from `Reflect.set` is the adapter's
    /// `TypeError`, and a JS exception is forwarded unchanged.
    fn set(&self, key: &str, value: &JsValue) -> Result<(), JsValue> {
        if Reflect::set(&self.0, &JsValue::from_str(key), value)? {
            Ok(())
        } else {
            Err(type_error(&format!(
                "could not write the result member `{key}`"
            )))
        }
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

/// `{ claims, header, alg, keyIndex?, kid? }` (RFC 7519 §7.2; ADR 0027 §1, ADR 0029).
pub(crate) fn jwt_verified(v: JwtVerified) -> Result<Object, JsValue> {
    let o = Out::new();
    o.str("claims", &v.claims)?;
    o.str("header", &v.header)?;
    o.str("alg", &v.alg)?;
    if let Some(index) = v.key_index {
        o.u32("keyIndex", index)?;
    }
    o.opt_str("kid", v.kid.as_deref())?;
    Ok(o.0)
}

/// `{ inner, outerHeader, recipientIndex }` (RFC 7519 §5.2, §11.2; ADR 0027 §7).
pub(crate) fn jwt_nested_verified(v: JwtNestedVerified) -> Result<Object, JsValue> {
    let o = Out::new();
    let inner = jwt_verified(v.inner)?;
    o.set("inner", &inner)?;
    o.str("outerHeader", &v.outer_header)?;
    o.u32("recipientIndex", v.recipient_index)?;
    Ok(o.0)
}
