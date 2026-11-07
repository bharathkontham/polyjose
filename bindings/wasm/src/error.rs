//! The two kinds of JS error the adapter throws (ADR 0030 §5, ADR 0031 §3, 0006 research §2).
//!
//! - **A core failure** becomes a [`js_sys::Error`] with `name = "PolyjoseError"`, `message` =
//!   the surface message and an own `code` property = the stable surface code. wasm-bindgen's
//!   glue throws that exact object for an `Err(JsValue)` (measured: `instanceof Error`, `name`,
//!   `code` and a stack in Node, Chrome and workerd). `wasm_bindgen::JsError` cannot carry `code`.
//!   The shared facade re-wraps it in its own `PolyjoseError` class (BACKEND.md, "Errors").
//! - **A record of the wrong shape** (only possible when the facade is bypassed) becomes a JS
//!   `TypeError`, never a `PolyjoseError`, so it can never be mistaken for a core code
//!   (BACKEND.md, ADR 0031 §3, "Records").
//!
//! Neither carries input: the code and message come from the core only (ADR 0030 §5, ADR 0007),
//! and reader messages name the field, never its value.

use js_sys::{Error, Reflect, TypeError};
use polyjose_surface::SurfaceError;
use wasm_bindgen::JsValue;

/// The `name` of every thrown core error (ADR 0030 §5, "JS").
pub(crate) const ERROR_NAME: &str = "PolyjoseError";

/// The JS value thrown for a surface error (ADR 0030 §5).
///
/// `Reflect.set` on a freshly created, ordinary `Error` defines an own writable data property and
/// cannot fail or return `false` (ECMA-262, OrdinarySet on an extensible object), so its
/// result carries no information and is not inspected.
pub(crate) fn polyjose_error(e: SurfaceError) -> JsValue {
    let err = Error::new(e.message());
    err.set_name(ERROR_NAME);
    let _ = Reflect::set(
        &err,
        &JsValue::from_str("code"),
        &JsValue::from_str(e.code()),
    );
    err.into()
}

/// The JS `TypeError` thrown when a record field has the wrong type (ADR 0031 §3, "Records").
/// `what` names the field and the expected type; it never quotes the value.
pub(crate) fn type_error(what: &str) -> JsValue {
    TypeError::new(&format!("polyjose: {what}")).into()
}
