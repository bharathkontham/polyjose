//! JWS operations (ADR 0030 §4, "JWS"; RFC 7515, RFC 7797, RFC 8037, RFC 8812, RFC 9864;
//! ADR 0026, ADR 0045, ADR 0049).
//!
//! Keys are JWK JSON text, borrowed (ADR 0030 §7.1). Payloads are treated as secret: they are
//! borrowed on the way in, and a verified payload is [`SecretBytes`](crate::secret::SecretBytes)
//! (ADR 0049 §4). Verification takes the caller's allow-list and nothing else selects the
//! algorithm (ADR 0007, RFC 8725 §3.1); RSA signing fails with `UnsupportedAlgorithm`
//! (ADR 0021).

use polyjose::Error;
use polyjose::header::Header;
use polyjose::jwk::Jwk;
use polyjose::jws::{ProtectedHeader, SignOptions};

use crate::error::{SurfaceError, SurfaceResult};
use crate::records::{JwsSignOptions, JwsSigner, JwsVerified, JwsVerifyOptions, apply_flag};

/// Header-form misuse (ADR 0030 §4, §5): a signer sets both `protected_header` and
/// `protected_b64u`.
const BOTH_PROTECTED_FORMS: &str = "set only one of protected_header and protected_b64u";

/// Header-form misuse (ADR 0030 §4, §5): a compact JWS needs a JWS Protected Header, which is its
/// whole JOSE Header (RFC 7515 §7.1, ADR 0045 §1).
const NO_PROTECTED_HEADER: &str = "compact JWS needs protected_header or protected_b64u";

/// Signs `payload` with `key` into a JWS Compact Serialization (ADR 0030 §4; RFC 7515 §5.1,
/// §7.1).
///
/// `options` must set exactly one of `protected_header` and `protected_b64u`
/// (`InvalidHeader` otherwise, ADR 0030 §4): the compact serialization's JOSE Header is its JWS
/// Protected Header (RFC 7515 §7.1). `protected_header` is serialized by the core;
/// `protected_b64u` is signed over exactly as given (RFC 7515 §5.1 step 5, Appendix A.1).
/// `detached` leaves the payload part empty (RFC 7515 Appendix F).
///
/// # Errors
///
/// The key is parsed first, then the header, then the core signs (the order of the core's
/// `jws.sign` conformance runner): the core's code for a bad key or header JSON, `InvalidHeader`
/// for the header-form misuse above, then every error of `polyjose::jws::sign_compact`, among
/// them `UnsupportedAlgorithm` for RS*/PS* (ADR 0021) and `AlgorithmNotAllowed` for `none`
/// (RFC 8725 §3.2).
pub fn jws_sign_compact(
    payload: &[u8],
    key: &str,
    options: &JwsSignOptions,
) -> SurfaceResult<String> {
    let key = parse_key(key)?;
    let protected = protected_header(
        options.protected_header.as_deref(),
        options.protected_b64u.as_deref(),
    )?
    .ok_or(Error::InvalidHeader(NO_PROTECTED_HEADER))?;
    Ok(polyjose::jws::sign_compact(
        &protected,
        payload,
        &key,
        &sign_options(options.detached),
    )?)
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

// ------------------------------------------------------------------------------------------------
// Conversions to the core (ADR 0030 §3): each parses with the core's own code and passes values
// through unchanged.
// ------------------------------------------------------------------------------------------------

/// Parses a JWK with the core's strict I-JSON parser (RFC 7517 §4, ADR 0016). The text is
/// borrowed, and the parsed key wipes itself on drop (ADR 0030 §7.1).
fn parse_key(key: &str) -> polyjose::Result<Jwk> {
    Jwk::from_json(key.as_bytes())
}

/// The JWS Protected Header from at most one of its two forms (ADR 0030 §4): JSON text the core
/// serializes (RFC 7515 §5.1 steps 3-4), or `BASE64URL(UTF8(JWS Protected Header))` kept
/// verbatim for the signing input (RFC 7515 §5.1 step 5). Both → `InvalidHeader`; neither →
/// `None`, which only the JSON serializations accept (RFC 7515 §7.2.1, ADR 0045 §1).
fn protected_header(
    json: Option<&str>,
    b64u: Option<&str>,
) -> polyjose::Result<Option<ProtectedHeader>> {
    match (json, b64u) {
        (Some(_), Some(_)) => Err(Error::InvalidHeader(BOTH_PROTECTED_FORMS)),
        (Some(json), None) => ProtectedHeader::new(Header::from_json(json.as_bytes())?).map(Some),
        (None, Some(encoded)) => ProtectedHeader::from_encoded(encoded).map(Some),
        (None, None) => Ok(None),
    }
}

/// The core sign options: `detached: false` calls nothing, so the core default (attached)
/// stands (ADR 0030 §3); `true` is RFC 7515 Appendix F.
fn sign_options(detached: bool) -> SignOptions {
    apply_flag(SignOptions::new(), detached, |o| o.detached(true))
}
