//! The JWK exports (ADR 0030 §4, "JWK"): `jwk_parse`, `jwk_to_public`, `jwk_thumbprint`,
//! `jwk_thumbprint_uri` and `jwks_select` (RFC 7517, RFC 7638, RFC 9278).
//!
//! Each export is a type conversion and one call into `polyjose_surface::jwk` (ADR 0030 §1,
//! "the adapter test"); validation, error codes and member order are the core's.
//!
//! **Secrets (ADR 0030 §7).** A JWK or JWK Set argument may be private, so it is moved into a
//! [`Zeroizing`] owner in the first statement; a `String` argument is UniFFI's only Rust-heap
//! copy of it (lifted from its `RustBuffer` without a copy, 0009 research §8), so nothing
//! unwiped remains on the Rust side (ADR 0030 §7.1). A result that may be private comes from the
//! surface as a `SecretString`: the adapter copies it once into the `String` that UniFFI lowers,
//! as is, into the `RustBuffer` the host reads and then frees unwiped; the surface's buffer is
//! wiped when it drops at the end of the statement. That one copy is the documented residual of
//! ADR 0030 §7.3.

use zeroize::Zeroizing;

use crate::PolyjoseError;
use crate::records::JwkSelector;

/// Parses and validates `jwk` and returns the core's re-serialization of it, members in core
/// order (ADR 0030 §4; RFC 7517 §4, RFC 7518 §6, RFC 8037 §2).
///
/// The result may hold private members (module docs, ADR 0030 §7.2–§7.3).
///
/// # Errors
///
/// The core's JWK parse errors: `InvalidJson`, `InvalidBase64`, `InvalidKey`,
/// `KeyAlgorithmMismatch`, and `UnsupportedAlgorithm` for an RSA private JWK (ADR 0021).
#[uniffi::export]
pub fn jwk_parse(jwk: String) -> Result<String, PolyjoseError> {
    let jwk = Zeroizing::new(jwk);
    Ok(polyjose_surface::jwk::jwk_parse(&jwk)?.as_str().to_owned())
}

/// The public form of `jwk`: the private members removed (ADR 0030 §4; RFC 7518 §6.2.2,
/// §6.3.2, RFC 8037 §2).
///
/// # Errors
///
/// The core's JWK parse errors; `UnsupportedAlgorithm` for an `oct` key, which has no public
/// part (RFC 7518 §6.4).
#[uniffi::export]
pub fn jwk_to_public(jwk: String) -> Result<String, PolyjoseError> {
    let jwk = Zeroizing::new(jwk);
    Ok(polyjose_surface::jwk::jwk_to_public(&jwk)?)
}

/// The JWK Thumbprint of `jwk` under `hash` (`SHA-256`), base64url encoded without padding
/// (ADR 0030 §4; RFC 7638 §3, RFC 7515 §2).
///
/// # Errors
///
/// `UnsupportedAlgorithm` for any other `hash`, `SHA-1` included (ADR 0022); the core's JWK
/// parse errors.
#[uniffi::export]
pub fn jwk_thumbprint(jwk: String, hash: String) -> Result<String, PolyjoseError> {
    let jwk = Zeroizing::new(jwk);
    Ok(polyjose_surface::jwk::jwk_thumbprint(&jwk, &hash)?)
}

/// The JWK Thumbprint URI of `jwk` under `hash`,
/// `urn:ietf:params:oauth:jwk-thumbprint:<hash>:<thumbprint>` (ADR 0030 §4; RFC 9278 §3).
///
/// # Errors
///
/// Those of [`jwk_thumbprint`].
#[uniffi::export]
pub fn jwk_thumbprint_uri(jwk: String, hash: String) -> Result<String, PolyjoseError> {
    let jwk = Zeroizing::new(jwk);
    Ok(polyjose_surface::jwk::jwk_thumbprint_uri(&jwk, &hash)?)
}

/// The member of the JWK Set `jwks` that `selector` picks (ADR 0030 §4; RFC 7517 §5, §4.2,
/// §4.4, §4.5). `kid` selects a key only here, by the caller's choice, never during
/// verification (ADR 0026 §2, ADR 0030 §6).
///
/// The member may be private (module docs, ADR 0030 §7.2–§7.3).
///
/// # Errors
///
/// Whatever the surface returns: for now always `UnsupportedAlgorithm`, until the core's JWK
/// Set selection arrives with feature 0015 (feature 0013 T14), behind this same signature.
#[uniffi::export]
pub fn jwks_select(jwks: String, selector: JwkSelector) -> Result<String, PolyjoseError> {
    let jwks = Zeroizing::new(jwks);
    let selector = polyjose_surface::records::JwkSelector::from(selector);
    Ok(polyjose_surface::jwk::jwks_select(&jwks, &selector)?
        .as_str()
        .to_owned())
}
