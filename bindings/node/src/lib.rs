//! polyjose-node: the napi-rs adapter of `@polyjose/node` (ADR 0030 §1, ADR 0031 §2).
//!
//! A mechanical adapter over `polyjose-surface`: every export is a type conversion and one
//! surface call, with no JSON parsing, policy, defaults or crypto of its own (ADR 0030 §1, "the
//! adapter test"). The exported names, argument order and record fields are the backend contract
//! of the shared JS facade (`bindings/js/BACKEND.md`, `bindings/js/src/backend.ts`); napi-rs
//! turns the `snake_case` Rust names into those `camelCase` names.
//!
//! - [`util`]: `version` and `errorCodes` (synchronous), `base64urlEncode`, `base64urlDecode`;
//! - [`error`]: [`error::Code`], the stable code on every rejected Promise (ADR 0030 §5);
//! - the operations, each returning a Promise from an `AsyncTask` that runs on the libuv pool
//!   (ADR 0031 §2, 0007 research §3).
//!
//! # Secrets (ADR 0030 §7, ADR 0031 §2)
//!
//! - **Inputs** are copied on the JS thread into `Zeroizing` task fields (or surface records
//!   whose secret fields are `SecretString`/`SecretBytes`), which wipe when the task drops after
//!   `resolve`. `compute` never reads borrowed JS memory.
//! - **Outputs** that are secret are created by copying from a borrow of the surface's zeroizing
//!   buffer (`env.create_string`, `Uint8ArraySlice::copy_from`), never by handing an owned
//!   `String`/`Vec<u8>` to napi, so no un-wiped Rust copy remains. JS strings are immutable and
//!   cannot be wiped (ADR 0030 §7.4).
//! - Nothing is logged, and no hand-written `unsafe` exists; the only `unsafe` is what
//!   napi-derive generates.

pub mod error;
pub mod jwe;
pub mod jwk;
pub mod jws;
pub mod keys;
pub mod records;
mod task;
pub mod util;

#[cfg(test)]
pub(crate) mod tests {
    use zeroize::ZeroizeOnDrop;

    /// RFC 7517 Appendix A.2: a P-256 private key (with `use` and `kid`).
    pub(crate) const RFC7517_A2_P256_PRIVATE: &str = r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE","use":"enc","kid":"1"}"#;

    /// Compiles only if `value`'s type wipes itself on drop (ADR 0030 §7.7: the secret-input
    /// path compiles to a zeroizing owner).
    pub(crate) fn wipes_on_drop<T: ZeroizeOnDrop>(_value: &T) {}
}
