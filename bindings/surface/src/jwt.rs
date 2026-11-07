//! JWT operations (ADR 0030 §4, "JWT"; RFC 7519, RFC 8725, RFC 9068; ADR 0027 policy and error
//! order, ADR 0028 clock, ADR 0029 JWK Set selection, ADR 0052).
//!
//! One key or a JWK Set is chosen by which function is called (`jwt_verify` or
//! `jwt_verify_with_jwks`), and signed and nested JWTs have separate entry points (ADR 0027 §7,
//! ADR 0030 §4). Claims are JSON text, written back by the core with registered claims first
//! (ADR 0027 §1).
//!
//! **The clock (ADR 0030 §4, ADR 0028 §4):** an explicit `now` always wins. Without one, the
//! surface reads the platform clock where the core has one (`SystemClock`); on
//! `wasm32-unknown-unknown`, where it does not, a missing `now` fails with `InvalidClaim`,
//! never a panic (the JS facade always passes `now`).

use crate::error::{SurfaceError, SurfaceResult};
use crate::records::{
    JweDecryptOptions, JweEncryptOptions, JwtNestedVerified, JwtSignOptions, JwtVerified,
    JwtVerifyOptions,
};

/// Signs the JWT Claims Set `claims` (JSON text) with `key` into a compact JWS (ADR 0030 §4;
/// RFC 7519 §7.1). RS*/PS* signing fails with `UnsupportedAlgorithm` (ADR 0021).
pub fn jwt_sign(claims: &str, key: &str, options: &JwtSignOptions) -> SurfaceResult<String> {
    // stub: T09
    let _ = (claims, key, options);
    Err(SurfaceError::from(polyjose::Error::UnsupportedAlgorithm))
}

/// Verifies and validates the signed JWT `token` with one `key` (ADR 0030 §4; RFC 7519 §7.2,
/// RFC 8725 §3; ADR 0027 §9 error order).
pub fn jwt_verify(
    token: &str,
    key: &str,
    options: &JwtVerifyOptions,
) -> SurfaceResult<JwtVerified> {
    // stub: T09
    let _ = (token, key, options);
    Err(SurfaceError::from(polyjose::Error::UnsupportedAlgorithm))
}

/// Verifies and validates the signed JWT `token` against the JWK Set `jwks` (ADR 0030 §4;
/// RFC 7519 §7.2, RFC 7517 §5; ADR 0029). No candidate fails with `NoMatchingKey`
/// (ADR 0029 §4).
pub fn jwt_verify_with_jwks(
    token: &str,
    jwks: &str,
    options: &JwtVerifyOptions,
) -> SurfaceResult<JwtVerified> {
    // stub: T09
    let _ = (token, jwks, options);
    Err(SurfaceError::from(polyjose::Error::UnsupportedAlgorithm))
}

/// Encrypts the signed JWT `signed_jwt` into a compact JWE for exactly one recipient, with
/// `cty: "JWT"` set by the core (ADR 0030 §4; RFC 7519 §5.2, §11.2).
pub fn jwt_encrypt_nested(signed_jwt: &str, options: &JweEncryptOptions) -> SurfaceResult<String> {
    // stub: T09
    let _ = (signed_jwt, options);
    Err(SurfaceError::from(polyjose::Error::UnsupportedAlgorithm))
}

/// Decrypts the nested JWT `token` with `decrypt_key`, then verifies and validates the inner
/// JWT with one `key` (ADR 0030 §4; RFC 7519 §5.2, §7.2 step 8; RFC 8725 §3.3).
pub fn jwt_decrypt_nested(
    token: &str,
    decrypt_key: &str,
    decrypt_options: &JweDecryptOptions,
    key: &str,
    options: &JwtVerifyOptions,
) -> SurfaceResult<JwtNestedVerified> {
    // stub: T09
    let _ = (token, decrypt_key, decrypt_options, key, options);
    Err(SurfaceError::from(polyjose::Error::UnsupportedAlgorithm))
}

/// Decrypts the nested JWT `token` with `decrypt_key`, then verifies and validates the inner
/// JWT against the JWK Set `jwks` (ADR 0030 §4; RFC 7519 §5.2, §7.2 step 8; ADR 0029).
pub fn jwt_decrypt_nested_with_jwks(
    token: &str,
    decrypt_key: &str,
    decrypt_options: &JweDecryptOptions,
    jwks: &str,
    options: &JwtVerifyOptions,
) -> SurfaceResult<JwtNestedVerified> {
    // stub: T09
    let _ = (token, decrypt_key, decrypt_options, jwks, options);
    Err(SurfaceError::from(polyjose::Error::UnsupportedAlgorithm))
}
