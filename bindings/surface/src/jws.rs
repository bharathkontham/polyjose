//! JWS operations (ADR 0030 §4, "JWS"; RFC 7515, RFC 7797, RFC 8037, RFC 8812, RFC 9864;
//! ADR 0026, ADR 0045, ADR 0049).
//!
//! Keys are JWK JSON text, borrowed (ADR 0030 §7.1). Payloads are treated as secret: they are
//! borrowed on the way in, and a verified payload is [`SecretBytes`](crate::secret::SecretBytes)
//! (ADR 0049 §4). Verification takes the caller's allow-list and nothing else selects the
//! algorithm (ADR 0007, RFC 8725 §3.1); RSA signing fails with `UnsupportedAlgorithm`
//! (ADR 0021).

use crate::error::{SurfaceError, SurfaceResult};
use crate::records::{JwsSignOptions, JwsSigner, JwsVerified, JwsVerifyOptions};

/// Signs `payload` with `key` into a JWS Compact Serialization (ADR 0030 §4; RFC 7515 §5.1,
/// §7.1).
///
/// `options` must set exactly one of `protected_header` and `protected_b64u`
/// (`InvalidHeader` otherwise, ADR 0030 §4).
pub fn jws_sign_compact(
    payload: &[u8],
    key: &str,
    options: &JwsSignOptions,
) -> SurfaceResult<String> {
    // stub: T07
    let _ = (payload, key, options);
    Err(SurfaceError::from(polyjose::Error::UnsupportedAlgorithm))
}

/// Signs `payload` into a flattened JWS JSON Serialization with one `signer` (ADR 0030 §4;
/// RFC 7515 §7.2.2). `detached` leaves the payload out (RFC 7515 Appendix F).
///
/// The signer may carry only an unprotected header (RFC 7515 §7.2.1, ADR 0045 §1).
pub fn jws_sign_flattened(
    payload: &[u8],
    signer: &JwsSigner,
    detached: bool,
) -> SurfaceResult<String> {
    // stub: T07
    let _ = (payload, signer, detached);
    Err(SurfaceError::from(polyjose::Error::UnsupportedAlgorithm))
}

/// Signs `payload` into a general JWS JSON Serialization, one signature per signer, in order
/// (ADR 0030 §4; RFC 7515 §7.2.1). `detached` leaves the payload out (RFC 7515 Appendix F).
pub fn jws_sign_general(
    payload: &[u8],
    signers: &[JwsSigner],
    detached: bool,
) -> SurfaceResult<String> {
    // stub: T07
    let _ = (payload, signers, detached);
    Err(SurfaceError::from(polyjose::Error::UnsupportedAlgorithm))
}

/// Verifies the JWS Compact Serialization `token` with `key` (ADR 0030 §4; RFC 7515 §5.2,
/// §7.1; ADR 0026 §2).
pub fn jws_verify_compact(
    token: &str,
    key: &str,
    options: &JwsVerifyOptions,
) -> SurfaceResult<JwsVerified> {
    // stub: T07
    let _ = (token, key, options);
    Err(SurfaceError::from(polyjose::Error::UnsupportedAlgorithm))
}

/// Verifies the flattened or general JWS JSON Serialization `jws` with `key` (ADR 0030 §4;
/// RFC 7515 §5.2, §7.2; ADR 0026 §3).
///
/// The returned [`JwsVerified::unprotected_header`] is **not integrity-protected** (ADR 0049
/// §2): never trust `typ`, `cty`, `kid` or `crit` from it.
pub fn jws_verify_json(
    jws: &str,
    key: &str,
    options: &JwsVerifyOptions,
) -> SurfaceResult<JwsVerified> {
    // stub: T07
    let _ = (jws, key, options);
    Err(SurfaceError::from(polyjose::Error::UnsupportedAlgorithm))
}
