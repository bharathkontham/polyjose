#![forbid(unsafe_code)]
//! polyjose: JSON Object Signing and Encryption in pure Rust.
//!
//! - [`json`] RFC 8259 JSON with RFC 7493 (I-JSON) constraints
//! - [`jwa`]  RFC 7518 – algorithm identifiers
//! - [`jwk`]  RFC 7517 – keys and key sets
//! - [`jws`]  RFC 7515 – signatures
//! - [`jwe`]  RFC 7516 – encryption
//! - [`jwt`]  RFC 7519 – tokens and claims
//! - [`util`] base64url and other helpers

/// Error type.
pub mod error;
/// JSON parser, value type and serializer (RFC 8259, RFC 7493).
pub mod json;
/// Algorithm identifiers (RFC 7518).
pub mod jwa;
/// JSON Web Encryption (RFC 7516).
pub mod jwe;
/// JSON Web Key (RFC 7517).
pub mod jwk;
/// JSON Web Signature (RFC 7515).
pub mod jws;
/// JSON Web Token (RFC 7519).
pub mod jwt;
/// base64url and helpers.
pub mod util;

pub use error::{Error, Result};
