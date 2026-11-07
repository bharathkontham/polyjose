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

use js_sys::{Array, Reflect};
use polyjose_surface::records::JwkSelector;
use wasm_bindgen::JsValue;

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

    fn opt_string(&self, key: &str) -> Read<Option<String>> {
        self.get(key)?
            .map(|v| v.as_string().ok_or_else(|| self.wrong(key, "a string")))
            .transpose()
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
