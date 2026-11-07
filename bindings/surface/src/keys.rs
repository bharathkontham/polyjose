//! Key generation and PEM/DER import and export (ADR 0030 §4, "JWK", the `jwk_generate_*`,
//! `jwk_from_*` and `jwk_to_*` operations; RFC 7518 §6, RFC 8037 §2, RFC 7468, RFC 5958,
//! RFC 5280 §4.1, RFC 5915, RFC 8410; ADR 0005, 0018, 0021).
//!
//! Keys are JWK JSON text (ADR 0030 option C1). Generated keys and imported or exported private
//! keys are secrets, so they are returned as [`SecretString`]/[`SecretBytes`] (ADR 0030 §7.2).
//! Randomness comes only from the OS CSPRNG, through the core (ADR 0005). Format names are
//! `pkcs8`, `sec1`, `spki` and `pkcs1`; any other string fails with `UnsupportedAlgorithm`
//! (ADR 0030 §5).

use crate::error::{SurfaceError, SurfaceResult};
use crate::secret::{SecretBytes, SecretString};

/// A new random `oct` key of `len_bytes` octets, 16 to 512 (ADR 0030 §4; RFC 7518 §6.4,
/// ADR 0018 §5).
///
/// A length outside that range fails with `InvalidKey` (ADR 0030 §5).
pub fn jwk_generate_oct(len_bytes: u32) -> SurfaceResult<SecretString> {
    // stub: T06
    let _ = len_bytes;
    Err(SurfaceError::from(polyjose::Error::UnsupportedAlgorithm))
}

/// A new `EC` key pair on `crv`: `P-256`, `P-384`, `P-521` or `secp256k1` (ADR 0030 §4;
/// RFC 7518 §6.2, RFC 8812 §3.1).
pub fn jwk_generate_ec(crv: &str) -> SurfaceResult<SecretString> {
    // stub: T06
    let _ = crv;
    Err(SurfaceError::from(polyjose::Error::UnsupportedAlgorithm))
}

/// A new `OKP` key pair on `crv`: `Ed25519` or `X25519` (ADR 0030 §4; RFC 8037 §2).
pub fn jwk_generate_okp(crv: &str) -> SurfaceResult<SecretString> {
    // stub: T06
    let _ = crv;
    Err(SurfaceError::from(polyjose::Error::UnsupportedAlgorithm))
}

/// A new key for the JWS `alg`, JWE `alg` or JWE `enc` named `alg`, with the JWK `alg` member
/// set (ADR 0030 §4; RFC 7517 §4.4, RFC 7518 §3.1, §4.1, §5.1; the 0005 `generate_for` table).
///
/// RSA algorithms fail with `UnsupportedAlgorithm` (ADR 0021).
pub fn jwk_generate_for_alg(alg: &str) -> SurfaceResult<SecretString> {
    // stub: T06
    let _ = alg;
    Err(SurfaceError::from(polyjose::Error::UnsupportedAlgorithm))
}

/// The JWK of the PEM-encoded key `pem` (ADR 0030 §4; RFC 7468 §2, §10, §13; RFC 5915 §4).
///
/// The PEM may hold a private key, so it is borrowed, and the JWK returned as a
/// [`SecretString`]. RSA private and encrypted PKCS#8 keys fail with `UnsupportedAlgorithm`
/// (ADR 0018, ADR 0021).
pub fn jwk_from_pem(pem: &str) -> SurfaceResult<SecretString> {
    // stub: T06
    let _ = pem;
    Err(SurfaceError::from(polyjose::Error::UnsupportedAlgorithm))
}

/// The JWK of the DER-encoded key `der` in `format` (ADR 0030 §4; RFC 5958 §2, RFC 5915 §3,
/// RFC 5280 §4.1.2.7, RFC 8017 App. A.1.1).
pub fn jwk_from_der(der: &[u8], format: &str) -> SurfaceResult<SecretString> {
    // stub: T06
    let _ = (der, format);
    Err(SurfaceError::from(polyjose::Error::UnsupportedAlgorithm))
}

/// `jwk` as PEM in `format` (ADR 0030 §4; RFC 7468 §2). The PEM of a private key is a secret,
/// so the result is a [`SecretString`].
pub fn jwk_to_pem(jwk: &str, format: &str) -> SurfaceResult<SecretString> {
    // stub: T06
    let _ = (jwk, format);
    Err(SurfaceError::from(polyjose::Error::UnsupportedAlgorithm))
}

/// `jwk` as DER in `format` (ADR 0030 §4; RFC 5958 §2, RFC 5915 §3, RFC 5280 §4.1.2.7). The DER
/// of a private key is a secret, so the result is [`SecretBytes`].
pub fn jwk_to_der(jwk: &str, format: &str) -> SurfaceResult<SecretBytes> {
    // stub: T06
    let _ = (jwk, format);
    Err(SurfaceError::from(polyjose::Error::UnsupportedAlgorithm))
}
