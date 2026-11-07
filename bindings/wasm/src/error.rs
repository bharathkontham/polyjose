//! The two kinds of JS error the adapter throws (ADR 0030 §5, ADR 0031 §3, 0006 research §2).
//!
//! - **A core failure** becomes a [`js_sys::Error`] with `name = "PolyjoseError"`, `message` =
//!   the surface message and an own `code` property = the stable surface code. `name` and `code`
//!   are defined, not assigned (see [`polyjose_error`]). wasm-bindgen's
//!   glue throws that exact object for an `Err(JsValue)` (measured: `instanceof Error`, `name`,
//!   `code` and a stack in Node, Chrome and workerd). `wasm_bindgen::JsError` cannot carry `code`.
//!   The shared facade re-wraps it in its own `PolyjoseError` class (BACKEND.md, "Errors").
//! - **A record of the wrong shape** (only possible when the facade is bypassed) becomes a JS
//!   `TypeError`, never a `PolyjoseError`, so it can never be mistaken for a core code
//!   (BACKEND.md, ADR 0031 §3, "Records").
//!
//! Neither carries input: the code and message come from the core only (ADR 0030 §5, ADR 0007),
//! and reader messages name the field, never its value.

use js_sys::{Error, Object, Reflect, TypeError};
use polyjose_surface::SurfaceError;
use wasm_bindgen::{JsCast, JsValue};

/// The `name` of every thrown core error (ADR 0030 §5, "JS").
pub(crate) const ERROR_NAME: &str = "PolyjoseError";

/// The JS value thrown for a surface error (ADR 0030 §5).
///
/// `name` and `code` are defined on the new `Error` with `Reflect.defineProperty` (ECMA-262
/// §28.1.3, ValidateAndApplyPropertyDescriptor §10.1.6.3) as own data properties `{ value,
/// writable: true, enumerable: false, configurable: true }`, the attributes of the `Error`'s own
/// `message` (§20.5.1.1). Assigning them (`err.code = …`, OrdinarySet §10.1.9.2) would walk the
/// prototype chain: an accessor planted on `Object.prototype.code` (or `Error.prototype.name`)
/// would receive the value and leave no own member, so `e.code` would read whatever the realm put
/// there (0006 review S1). Defining an own property never consults the prototype.
///
/// The descriptor object itself has a null prototype, since ToPropertyDescriptor (§6.2.6.5) reads
/// `get`, `set`, `value` and the flags through the prototype chain. Defining a new key on a
/// fresh, extensible object cannot return `false`; if an engine ever did, or threw, the adapter's
/// `TypeError` is returned instead, never an error without its `code`.
pub(crate) fn polyjose_error(e: SurfaceError) -> JsValue {
    let err = Error::new(e.message());
    for (key, value) in [("name", ERROR_NAME), ("code", e.code())] {
        if !define_data(&err, key, &JsValue::from_str(value)) {
            return type_error(&format!("could not define the error's `{key}`"));
        }
    }
    err.into()
}

/// Defines `key` on `target` as an own, writable, non-enumerable, configurable data property;
/// `true` when the engine reports success.
fn define_data(target: &Object, key: &str, value: &JsValue) -> bool {
    let descriptor = Object::create(JsValue::NULL.unchecked_ref());
    let fields = [
        ("value", value.clone()),
        ("writable", JsValue::TRUE),
        ("enumerable", JsValue::FALSE),
        ("configurable", JsValue::TRUE),
    ];
    // OrdinarySet on a prototype-less object creates an own data property (§10.1.9.2 step 2.c).
    let built = fields
        .iter()
        .all(|(f, v)| Reflect::set(&descriptor, &JsValue::from_str(f), v) == Ok(true));
    built && Reflect::define_property(target, &JsValue::from_str(key), &descriptor) == Ok(true)
}

/// The JS `TypeError` thrown when a record field has the wrong type (ADR 0031 §3, "Records").
/// `what` names the field and the expected type; it never quotes the value.
pub(crate) fn type_error(what: &str) -> JsValue {
    TypeError::new(&format!("polyjose: {what}")).into()
}
