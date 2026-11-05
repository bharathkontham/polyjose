#![forbid(unsafe_code)]
//! polyjose: JSON Object Signing and Encryption in pure Rust.
//!
//! - [`jwa`]  RFC 7518 – algorithm identifiers
//! - [`jwk`]  RFC 7517 – keys and key sets
//! - [`jws`]  RFC 7515 – signatures
//! - [`jwe`]  RFC 7516 – encryption
//! - [`jwt`]  RFC 7519 – tokens and claims
//! - [`util`] base64url and other helpers

/// Error type.
pub mod error;
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
#[cfg(feature = "test-vectors")]
pub use rng::test_vectors;
/// base64url and helpers.
pub mod util;

pub use error::{Error, Result};
