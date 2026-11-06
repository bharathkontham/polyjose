#![forbid(unsafe_code)]
//! polyjose: JSON Object Signing and Encryption in pure Rust.
//!
//! - [`json`] RFC 8259 JSON with RFC 7493 (I-JSON) constraints
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
// Internal: nothing calls the CSPRNG until the JWE/key-generation features
// land; the expectation fails (and must be removed) once something does.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "fill_random is the RNG boundary for later JWE and key-generation features"
    )
)]
mod rng;
#[cfg(feature = "insecure-test-vectors")]
pub use rng::insecure_test_vectors;
// Test-only operation counters. Keep this exact two-line declaration: the
// RNG state scan (rng.rs) exempts the file only when it is declared so.
#[cfg(test)]
mod test_counters;
/// base64url and helpers.
pub mod util;

pub use error::{Error, Result};
