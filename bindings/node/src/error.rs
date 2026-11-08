//! The Node error mapping: a [`SurfaceError`] becomes a JS `Error` whose `code` is the stable core
//! code and whose `message` is the core text (ADR 0030 §5, ADR 0031 §2).
//!
//! napi-rs puts the status string of a `napi::Error<S: AsRef<str>>` on the JS error's `code`
//! (0007 research §2). [`Code`] is that status: it can only be built from a [`SurfaceError`], so
//! every code a Promise rejects with is one of `errorCodes()`. The facade turns the object into
//! its `PolyjoseError` (ADR 0031 §1, `bindings/js/BACKEND.md`).
//!
//! `Task::compute` can only fail with a `napi::Status` (a custom code there becomes
//! `GenericFailure`, research §3), so each task's `compute` returns `Ok(SurfaceResult<_>)` and
//! its `resolve` calls [`reject`], which builds the coded JS error on the JS thread.

use napi::{Env, JsError};
use polyjose_surface::SurfaceError;

/// The stable error code of a failed call, as the JS error's `code` (ADR 0030 §5).
///
/// Built only from a [`SurfaceError`], whose code is always one of `polyjose::Error::CODES`; the
/// adapter never invents one (ADR 0030 §5, option E1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Code(&'static str);

impl Code {
    /// The code string, e.g. `InvalidSignature`.
    pub fn as_str(&self) -> &'static str {
        self.0
    }
}

/// napi-rs reads the JS `code` through this (`napi::Error<S: AsRef<str>>`, research §2).
impl AsRef<str> for Code {
    fn as_ref(&self) -> &str {
        self.0
    }
}

/// The code of a surface error, unchanged (ADR 0030 §5).
impl From<&SurfaceError> for Code {
    fn from(e: &SurfaceError) -> Self {
        Self(e.code())
    }
}

/// The napi error for a surface error: status [`Code`], reason the core message (ADR 0030 §5).
/// The core message never holds key material or input (ADR 0007), so neither does the JS error.
pub fn coded(e: &SurfaceError) -> napi::Error<Code> {
    napi::Error::new(Code::from(e), e.message())
}

/// Turns a surface error into the rejection of a task's Promise, on the JS thread (`resolve`).
///
/// The JS error object is created here with its `code` (research §3, measured) and handed back
/// as a referenced `napi::Error`, which napi-rs rejects the Promise with unchanged.
pub fn reject(env: &Env, e: &SurfaceError) -> napi::Error {
    let error = JsError::from(coded(e)).into_unknown(Env::from_raw(env.raw()));
    napi::Error::from(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn surface_error() -> SurfaceError {
        polyjose_surface::util::base64url_decode("Zg==").unwrap_err()
    }

    #[test]
    fn code_is_the_surface_code() {
        let e = surface_error();
        let code = Code::from(&e);
        assert_eq!(code.as_str(), "InvalidBase64");
        assert_eq!(code.as_ref(), e.code());
    }

    #[test]
    fn coded_error_carries_the_code_and_the_core_message() {
        let e = surface_error();
        let napi_error = coded(&e);
        assert_eq!(napi_error.status, Code::from(&e));
        assert_eq!(napi_error.reason, e.message());
    }
}
