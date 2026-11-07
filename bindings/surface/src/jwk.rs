//! JWK operations (ADR 0030 §4, "JWK"): parsing, the public form, thumbprints and JWK Set
//! selection (RFC 7517, RFC 7518 §6, RFC 7638, RFC 9278, RFC 8037; ADR 0018, 0021, 0022).
//!
//! JWKs and JWK Sets are JSON text in and out, parsed and written by the core's strict I-JSON
//! code (ADR 0016, ADR 0030 §2). A JWK argument may be private, so it is borrowed and never
//! copied by the surface (ADR 0030 §7.1), and a result that may be private is a
//! [`SecretString`] (ADR 0030 §7.2).

use crate::error::{SurfaceError, SurfaceResult};
use crate::records::JwkSelector;
use crate::secret::SecretString;

/// Parses and validates `jwk` and returns the core's re-serialization of it, members in core
/// order (ADR 0030 §4; RFC 7517 §4, RFC 7518 §6, RFC 8037 §2).
///
/// The result may hold private members, so it is a [`SecretString`]. An RSA private JWK fails
/// with `UnsupportedAlgorithm` (ADR 0021).
pub fn jwk_parse(jwk: &str) -> SurfaceResult<SecretString> {
    // stub: T06
    let _ = jwk;
    Err(SurfaceError::from(polyjose::Error::UnsupportedAlgorithm))
}

/// The public form of `jwk`: its private members removed (ADR 0030 §4; RFC 7517 §4, RFC 7518
/// §6.2.2, §6.3.2, RFC 8037 §2).
pub fn jwk_to_public(jwk: &str) -> SurfaceResult<String> {
    // stub: T06
    let _ = jwk;
    Err(SurfaceError::from(polyjose::Error::UnsupportedAlgorithm))
}

/// The JWK Thumbprint of `jwk` under `hash` (`SHA-256`, `SHA-384` or `SHA-512`), base64url
/// encoded (ADR 0030 §4; RFC 7638 §3).
///
/// `SHA-1` and any other hash name fail with `UnsupportedAlgorithm` (ADR 0022, ADR 0030 §5).
pub fn jwk_thumbprint(jwk: &str, hash: &str) -> SurfaceResult<String> {
    // stub: T06
    let _ = (jwk, hash);
    Err(SurfaceError::from(polyjose::Error::UnsupportedAlgorithm))
}

/// The JWK Thumbprint URI of `jwk` under `hash`,
/// `urn:ietf:params:oauth:jwk-thumbprint:<hash>:<thumbprint>` (ADR 0030 §4; RFC 9278 §3).
pub fn jwk_thumbprint_uri(jwk: &str, hash: &str) -> SurfaceResult<String> {
    // stub: T06
    let _ = (jwk, hash);
    Err(SurfaceError::from(polyjose::Error::UnsupportedAlgorithm))
}

/// The member of the JWK Set `jwks` that `selector` picks (ADR 0030 §4; RFC 7517 §5, §4.2,
/// §4.4, §4.5; the 0001 T07 selection rules).
///
/// `kid` is used only here, by an explicit caller choice; verification never selects a key by
/// a header's `kid` (ADR 0026 §2, ADR 0030 §6). The member may be private, so the result is a
/// [`SecretString`].
pub fn jwks_select(jwks: &str, selector: &JwkSelector) -> SurfaceResult<SecretString> {
    // stub: T06
    let _ = (jwks, selector);
    Err(SurfaceError::from(polyjose::Error::UnsupportedAlgorithm))
}
