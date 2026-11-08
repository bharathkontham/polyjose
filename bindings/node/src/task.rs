//! The async machinery shared by every operation (ADR 0030 §2, §7; ADR 0031 §2).
//!
//! Each operation is a `#[napi]` function that copies its arguments into a task struct on the JS
//! thread and returns `AsyncTask<…>`, which napi-rs turns into a Promise (0007 research §3):
//!
//! 1. **On the JS thread** the function moves every secret-bearing argument into a
//!    [`Zeroizing`](zeroize::Zeroizing) field (or a surface record whose secret fields are
//!    `SecretString`/`SecretBytes`). Borrowed JS memory (`&[u8]`, a `Uint8ArraySlice`) is copied
//!    there and never read again, because JS may mutate or collect it once the call returns
//!    (research §4, ADR 0030 §7.1).
//! 2. **On the libuv pool**, `compute` makes the one surface call over those owned fields
//!    (ADR 0030 §1). A surface failure is part of the output (`Ok(Err(_))`), because `compute`
//!    can only fail with a `napi::Status` (research §3).
//! 3. **On the JS thread**, `resolve` converts the result with [`ToJs`], or rejects the Promise
//!    with the coded error ([`crate::error::reject`]).
//! 4. The task then drops, and its `Zeroizing` fields wipe the copied inputs (ADR 0030 §7.6).
//!
//! [`ToJs`] builds every result by copying from a borrow of a zeroizing buffer
//! (`env.create_string`, `Uint8ArraySlice::copy_from`), never by handing an owned `String` or
//! `Vec<u8>` to napi, so no un-wiped Rust copy is left (research §4, ADR 0030 §7.2). That holds
//! for the results ADR 0030 §7 classifies as secret and, since review-code.md SF-6, for every
//! other string too: a compact token embeds base64url(payload), which ADR 0049 §4 treats as
//! secret, and the JWT claims ADR 0058 leaves plain in the API are still wiped here. The JS types
//! are unchanged (`string`, `Uint8Array`).

use napi::bindgen_prelude::{ToNapiValue, TypeName, Uint8ArraySlice};
use napi::{Env, JsString};
use polyjose_surface::{SecretBytes, SecretString, SurfaceResult};
use zeroize::Zeroizing;

/// Converts a surface result into the JS value a task resolves with, on the JS thread.
pub trait ToJs<'env> {
    /// The JS value: `string`, a `Uint8Array` or a plain object.
    type Js: ToNapiValue + TypeName;

    /// Builds the JS value. Secret results copy from a borrow of their zeroizing buffer, which
    /// is wiped when `self` drops at the end of this call (ADR 0030 §7.2).
    fn to_js(self, env: &'env Env) -> napi::Result<Self::Js>;
}

/// A string the API does not classify as secret (a compact token, a JSON serialization, a
/// thumbprint, a public JWK). A token still embeds base64url(payload) (ADR 0049 §4), so the value
/// moves into a zeroizing owner, V8 copies it from the borrow, and the Rust buffer is wiped on
/// drop, as for [`SecretString`] (ADR 0030 §7.2, review-code.md SF-6). JS sees a `string`.
impl<'env> ToJs<'env> for String {
    type Js = JsString<'env>;

    fn to_js(self, env: &'env Env) -> napi::Result<JsString<'env>> {
        let value = Zeroizing::new(self);
        env.create_string(value.as_str())
    }
}

/// A secret string (a private or generated JWK, the PEM of a private key): V8 copies it from the
/// borrow, and the Rust buffer is wiped on drop (research §4, ADR 0030 §7.2).
impl<'env> ToJs<'env> for SecretString {
    type Js = JsString<'env>;

    fn to_js(self, env: &'env Env) -> napi::Result<JsString<'env>> {
        env.create_string(self.as_str())
    }
}

/// Secret octets (decoded base64url, the DER of a private key): copied into a new JS
/// `ArrayBuffer` from the borrow, and the Rust buffer is wiped on drop (research §4,
/// ADR 0030 §7.2).
impl<'env> ToJs<'env> for SecretBytes {
    type Js = Uint8ArraySlice<'env>;

    fn to_js(self, env: &'env Env) -> napi::Result<Uint8ArraySlice<'env>> {
        Uint8ArraySlice::copy_from(env, self.as_bytes())
    }
}

/// `resolve` of every task: the converted value, or the coded rejection (ADR 0030 §5).
pub fn settle<'env, T: ToJs<'env>>(
    env: &'env Env,
    output: SurfaceResult<T>,
) -> napi::Result<T::Js> {
    match output {
        Ok(value) => value.to_js(env),
        Err(e) => Err(crate::error::reject(env, &e)),
    }
}

/// Declares one operation's task: a struct of owned inputs and its `ScopedTask` impl, whose
/// `compute` is the given single surface call and whose `resolve` is [`settle`].
///
/// ```ignore
/// surface_task! {
///     /// Doc of the task.
///     JwkParseTask { jwk: Zeroizing<String> } -> SecretString
///         = |t| polyjose_surface::jwk::jwk_parse(&t.jwk)
/// }
/// ```
macro_rules! surface_task {
    (
        $(#[$meta:meta])*
        $name:ident { $($(#[$field_meta:meta])* $field:ident: $ty:ty),* $(,)? } -> $out:ty
            = |$task:ident| $compute:expr
    ) => {
        $(#[$meta])*
        pub struct $name {
            $($(#[$field_meta])* pub(crate) $field: $ty,)*
        }

        impl<'env> napi::ScopedTask<'env> for $name {
            type Output = polyjose_surface::SurfaceResult<$out>;
            type JsValue = <$out as $crate::task::ToJs<'env>>::Js;

            /// Runs on the libuv pool: one surface call over the owned inputs (ADR 0030 §1).
            fn compute(&mut self) -> napi::Result<Self::Output> {
                let $task = &*self;
                Ok($compute)
            }

            /// Runs on the JS thread: the JS value, or the coded rejection (ADR 0030 §5).
            fn resolve(
                &mut self,
                env: &'env napi::Env,
                output: Self::Output,
            ) -> napi::Result<Self::JsValue> {
                $crate::task::settle(env, output)
            }
        }
    };
}

pub(crate) use surface_task;

#[cfg(test)]
mod tests {
    use napi::ScopedTask;
    use zeroize::Zeroizing;

    use super::*;

    surface_task! {
        /// A test task over a surface call that can fail.
        DecodeTask { text: Zeroizing<String> } -> SecretBytes
            = |t| polyjose_surface::util::base64url_decode(&t.text).map(SecretBytes::from)
    }

    #[test]
    fn compute_returns_the_surface_success() {
        let mut task = DecodeTask {
            text: Zeroizing::new("Zm9v".to_owned()),
        };
        let out = task.compute().unwrap().unwrap();
        assert_eq!(out.as_bytes(), b"foo");
    }

    #[test]
    fn compute_carries_a_surface_failure_as_output_not_as_a_napi_error() {
        let mut task = DecodeTask {
            text: Zeroizing::new("Zg==".to_owned()),
        };
        let err = task.compute().unwrap().unwrap_err();
        assert_eq!(err.code(), "InvalidBase64");
    }
}
