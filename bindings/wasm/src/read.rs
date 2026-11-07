//! Plain JS objects to surface records, read with `js_sys::Reflect` (ADR 0031 §3, "Records";
//! 0006 research §4).
//!
//! wasm-bindgen has no record derive without serde (banned: ADR 0016, ADR 0030 §1), and its typed
//! parameters coerce silently (`-1` becomes `4294967295` for a `u32`, a string passed as a list is
//! split into characters; research §4). So every record argument arrives as a `JsValue` and is
//! read here, member by member, with type checks only:
//!
//! - **No logic beyond type checks** (ADR 0030 §1, "the adapter test"). Each reader fills the
//!   surface record with a struct literal, so a field added to the surface fails to compile here
//!   until it is mapped. Unknown members are ignored: the facade passes only fields it validated.
//! - **Absent means `undefined`** (BACKEND.md: the facade leaves absent optional fields out). An
//!   absent optional member is `None`, the core default, and an absent flag is `false`: no default
//!   value is written here (ADR 0030 §3). A missing required member (an allow-list, a key) and any
//!   member of the wrong type, `null` included, is a JS `TypeError`, not a `PolyjoseError`
//!   (ADR 0031 §3). The message names the member, never its value (ADR 0030 §5).
//! - **Integers** are JS numbers that are integral and in range: `0..=2^32-1` for the `u32` sizes
//!   and counts, and a safe integer (`|n| <= 2^53-1`) for JWT `now` (ADR 0030 §2, ADR 0028).
//!   The facade already checked them (BACKEND.md); this is the type check of the conversion.
//! - **Secrets** (ADR 0030 §7.1): a key is read with `JsValue::as_string`, which hands Rust the
//!   only wasm-memory copy (like a by-value `String` parameter, research §3), and moved straight
//!   into a [`SecretString`]; secret bytes (`detachedPayload`, `aad`) are copied once out of the
//!   `Uint8Array` into a new `Vec<u8>` that moves straight into a [`SecretBytes`]. A reader that
//!   fails half-way drops what it has read, wiping it.

use js_sys::{Array, Reflect, Uint8Array};
use polyjose_surface::records::{JwkSelector, JwsSignOptions, JwsSigner, JwsVerifyOptions};
use polyjose_surface::{SecretBytes, SecretString};
use wasm_bindgen::{JsCast, JsValue};

use crate::error::type_error;

/// A reader's result: the value, or the JS error to throw.
type Read<T> = Result<T, JsValue>;

/// A record argument: one plain object, as the facade builds it (BACKEND.md, "Records").
struct Record<'a> {
    obj: &'a JsValue,
    name: &'static str,
}

impl<'a> Record<'a> {
    /// `value` must be a non-null, non-array object.
    fn new(value: &'a JsValue, name: &'static str) -> Read<Self> {
        if value.is_object() && !Array::is_array(value) {
            Ok(Self { obj: value, name })
        } else {
            Err(type_error(&format!("`{name}` must be an object")))
        }
    }

    /// The JS `TypeError` for member `key`, expected to be `expected`.
    fn wrong(&self, key: &str, expected: &str) -> JsValue {
        type_error(&format!("`{}.{key}` must be {expected}", self.name))
    }

    /// The member `key`, `None` when it is absent (`undefined`). A throwing getter's exception
    /// propagates unchanged.
    fn get(&self, key: &str) -> Read<Option<JsValue>> {
        let value = Reflect::get(self.obj, &JsValue::from_str(key))?;
        Ok((!value.is_undefined()).then_some(value))
    }

    /// A required member.
    fn need(&self, key: &str, expected: &str) -> Read<JsValue> {
        self.get(key)?.ok_or_else(|| self.wrong(key, expected))
    }

    fn opt_string(&self, key: &str) -> Read<Option<String>> {
        self.get(key)?
            .map(|v| v.as_string().ok_or_else(|| self.wrong(key, "a string")))
            .transpose()
    }

    fn string(&self, key: &str) -> Read<String> {
        self.need(key, "a string")?
            .as_string()
            .ok_or_else(|| self.wrong(key, "a string"))
    }

    /// A secret string (a JWK), owned by a [`SecretString`] from the moment it exists in Rust.
    fn secret_string(&self, key: &str) -> Read<SecretString> {
        self.string(key).map(SecretString::from)
    }

    fn opt_bytes(&self, key: &str) -> Read<Option<Vec<u8>>> {
        self.get(key)?
            .map(|v| {
                v.dyn_ref::<Uint8Array>()
                    .map(Uint8Array::to_vec)
                    .ok_or_else(|| self.wrong(key, "a Uint8Array"))
            })
            .transpose()
    }

    /// Secret octets, owned by a [`SecretBytes`] from the moment they exist in Rust.
    fn opt_secret_bytes(&self, key: &str) -> Read<Option<SecretBytes>> {
        Ok(self.opt_bytes(key)?.map(SecretBytes::from))
    }

    /// A `u32` size or count (ADR 0030 §2).
    fn opt_u32(&self, key: &str) -> Read<Option<u32>> {
        self.get(key)?
            .map(|v| match v.as_f64() {
                Some(n) if n.fract() == 0.0 && (0.0..=f64::from(u32::MAX)).contains(&n) => {
                    Ok(n as u32)
                }
                _ => Err(self.wrong(key, "an integer in 0..=4294967295")),
            })
            .transpose()
    }

    /// A flag: absent is `false`, the record's own meaning of an absent flag (ADR 0030 §4).
    fn flag(&self, key: &str) -> Read<bool> {
        self.get(key)?
            .map(|v| v.as_bool().ok_or_else(|| self.wrong(key, "a boolean")))
            .transpose()
            .map(Option::unwrap_or_default)
    }

    fn opt_strings(&self, key: &str) -> Read<Option<Vec<String>>> {
        self.get(key)?
            .map(|v| {
                let wrong = || self.wrong(key, "an array of strings");
                v.dyn_ref::<Array>()
                    .ok_or_else(wrong)?
                    .iter()
                    .map(|item| item.as_string().ok_or_else(wrong))
                    .collect()
            })
            .transpose()
    }

    fn strings(&self, key: &str) -> Read<Vec<String>> {
        self.opt_strings(key)?
            .ok_or_else(|| self.wrong(key, "an array of strings"))
    }
}

/// `{ kid?, alg?, keyUse? }` (RFC 7517 §4.2, §4.4, §4.5; ADR 0030 §4).
pub(crate) fn jwk_selector(value: &JsValue) -> Read<JwkSelector> {
    let r = Record::new(value, "JwkSelector")?;
    Ok(JwkSelector {
        kid: r.opt_string("kid")?,
        alg: r.opt_string("alg")?,
        key_use: r.opt_string("keyUse")?,
    })
}

/// `{ protectedHeader?, protectedB64u?, detached? }` (RFC 7515 §5.1, §7.1, Appendix F).
pub(crate) fn jws_sign_options(value: &JsValue) -> Read<JwsSignOptions> {
    let r = Record::new(value, "JwsSignOptions")?;
    Ok(JwsSignOptions {
        protected_header: r.opt_string("protectedHeader")?,
        protected_b64u: r.opt_string("protectedB64u")?,
        detached: r.flag("detached")?,
    })
}

/// `{ key, protectedHeader?, protectedB64u?, unprotectedHeader? }` (RFC 7515 §7.2.1). The key
/// is secret (ADR 0030 §7).
pub(crate) fn jws_signer(value: &JsValue) -> Read<JwsSigner> {
    let r = Record::new(value, "JwsSigner")?;
    Ok(JwsSigner {
        key: r.secret_string("key")?,
        protected_header: r.opt_string("protectedHeader")?,
        protected_b64u: r.opt_string("protectedB64u")?,
        unprotected_header: r.opt_string("unprotectedHeader")?,
    })
}

/// An array of [`jws_signer`] records (RFC 7515 §7.2.1 `signatures`).
pub(crate) fn jws_signers(value: &JsValue) -> Read<Vec<JwsSigner>> {
    value
        .dyn_ref::<Array>()
        .ok_or_else(|| type_error("`signers` must be an array"))?
        .iter()
        .map(|item| jws_signer(&item))
        .collect()
}

/// `{ allowedAlgs, detachedPayload?, maxInputLen?, maxSignatures? }` (RFC 7515 §5.2,
/// RFC 8725 §3.1, ADR 0026 §7). The detached payload is secret (ADR 0049 §4).
pub(crate) fn jws_verify_options(value: &JsValue) -> Read<JwsVerifyOptions> {
    let r = Record::new(value, "JwsVerifyOptions")?;
    Ok(JwsVerifyOptions {
        allowed_algs: r.strings("allowedAlgs")?,
        detached_payload: r.opt_secret_bytes("detachedPayload")?,
        max_input_len: r.opt_u32("maxInputLen")?,
        max_signatures: r.opt_u32("maxSignatures")?,
    })
}
