#![forbid(unsafe_code)]
//! polyjose: JSON Object Signing and Encryption in pure Rust.
//!
//! - [`jwa`]  RFC 7518 – algorithm identifiers
//! - [`jwk`]  RFC 7517 – keys and key sets
//! - [`jws`]  RFC 7515 – signatures
//! - [`jwe`]  RFC 7516 – encryption
//! - [`jwt`]  RFC 7519 – tokens and claims
//! - [`util`] base64url and other helpers

pub mod error;
pub mod jwa;
pub mod jwe;
pub mod jwk;
pub mod jws;
pub mod jwt;
pub mod util;

pub use error::{Error, Result};
