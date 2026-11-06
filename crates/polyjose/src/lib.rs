#![forbid(unsafe_code)]
//! polyjose: JSON Object Signing and Encryption in pure Rust.
//!
//! - [`json`] RFC 8259 JSON with RFC 7493 (I-JSON) constraints
//! - [`jwa`]  RFC 7518 – algorithm identifiers
//! - [`header`] RFC 7515/7516 – the JOSE Header
//! - [`jwk`]  RFC 7517 – keys and key sets
//! - [`keys`] key generation and PEM/DER import and export (RFC 7468, RFC 5958, RFC 5280)
//! - [`jws`]  RFC 7515 – signatures
//! - [`jwe`]  RFC 7516 – encryption
//! - [`jwt`]  RFC 7519 – tokens and claims
//! - [`util`] base64url and other helpers

/// Error type.
pub mod error;
/// The JOSE Header (RFC 7515 §4, RFC 7516 §4).
pub mod header;
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
/// Key generation and PEM/DER key import and export (RFC 7468, RFC 5958,
/// RFC 5280 §4.1, RFC 5915, RFC 8410, RFC 8017 App. A.1.1).
pub mod keys;
mod rng;
#[cfg(feature = "insecure-test-vectors")]
pub use rng::insecure_test_vectors;
// Test-only operation counters. Keep this exact two-line declaration: the
// RNG state scan (rng.rs) exempts the file only when it is declared so.
#[cfg(test)]
mod test_counters;
// Test-only fixtures (the vendored Wycheproof loader): never in a non-test
// build, and not reachable from the integration tests in `tests/`.
#[cfg(test)]
mod test_support;
/// base64url and helpers.
pub mod util;

pub use error::{Error, Result};
