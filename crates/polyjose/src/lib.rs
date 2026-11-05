#![forbid(unsafe_code)]
//! polyjose: JSON Object Signing and Encryption in pure Rust.
//!
//! - [`jwa`]  RFC 7518 – algorithm identifiers
//! - [`header`] RFC 7515/7516 – the JOSE Header
//! - [`jwk`]  RFC 7517 – keys and key sets
//! - [`jws`]  RFC 7515 – signatures
//! - [`jwe`]  RFC 7516 – encryption
//! - [`jwt`]  RFC 7519 – tokens and claims
//! - [`util`] base64url and other helpers

/// Error type.
pub mod error;
/// The JOSE Header (RFC 7515 §4, RFC 7516 §4).
pub mod header;
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
