//! The JWT exports (ADR 0030 §4, "JWT"): `jwt_sign`, `jwt_verify`, `jwt_verify_with_jwks`,
//! `jwt_encrypt_nested`, `jwt_decrypt_nested` and `jwt_decrypt_nested_with_jwks` (RFC 7519,
//! RFC 8725, RFC 9068; ADR 0027, ADR 0028, ADR 0029).
//!
//! Each export is a type conversion and one call into `polyjose_surface::jwt` (ADR 0030 §1,
//! "the adapter test"). One key or a JWK Set is chosen by which function is called, and signed
//! and nested JWTs have separate entry points (ADR 0027 §7, ADR 0030 §4).
//!
//! **The clock (ADR 0030 §4, ADR 0028 §4).** An explicit `now` (whole seconds since the epoch)
//! always wins. Without one, the surface reads the core's `SystemClock`, which on Android, the
//! JVM, iOS and macOS is the same OS real-time clock as `System.currentTimeMillis()` and
//! `Date()`; the adapter adds no clock of its own.
//!
//! **Secrets (ADR 0030 §7).** Keys and JWK Sets may be private, the claims of a JWT to be signed
//! are a JWS payload, and the signed JWT that `jwt_encrypt_nested` takes is JWE plaintext: each
//! such `String` argument is moved into a [`Zeroizing`] owner in the first statements, and is
//! UniFFI's only Rust-heap copy of it (0009 research §8; ADR 0030 §7.1). [`JweEncryptOptions`]
//! is converted into the surface's record (`SecretString` recipient keys, `SecretBytes` `aad`)
//! in the first statement; UniFFI 0.32.2 made 1 copy of each secret field while lifting it out of
//! a `RustBuffer` it then freed unwiped (ADR 0030 §7.1, §7.3; restated in ADR 0058).
//!
//! **Claims are not secret outputs (ADR 0058, owner decision 2026-11-07).** `JwtVerified.claims`
//! and the inner claims of `JwtNestedVerified` are plain `String`s, outside ADR 0030 §7's secret
//! handling, decrypted nested claims included: the surface does not zeroize them, and UniFFI
//! leaves the copies of any record `String` field. Claims are usually not secret; carry secrets
//! in a JWE payload instead.

use polyjose_surface::records as surface;
use zeroize::Zeroizing;

use crate::PolyjoseError;
use crate::records::{
    JweDecryptOptions, JweEncryptOptions, JwtNestedVerified, JwtSignOptions, JwtVerified,
    JwtVerifyOptions,
};

/// Signs the JWT Claims Set `claims` (JSON text) with `key` into a compact JWS (ADR 0030 §4;
/// RFC 7519 §7.1). The header holds `alg`, `typ` (`JWT` unless set otherwise, RFC 7519 §5.1),
/// the key's `kid`, then the `header` members (ADR 0027 §8).
///
/// # Errors
///
/// `InvalidHeader` for `typ` with `omit_typ` or `access_token`, or `omit_typ` with
/// `access_token` (ADR 0030 §4), and for reserved `header` members (ADR 0027 §6, §8);
/// `KeyAlgorithmMismatch` for `RS*` and `PS*` without an RSA private key (ADR 0067 §2); the
/// core's key and claims errors.
#[uniffi::export]
pub fn jwt_sign(
    claims: String,
    key: String,
    options: JwtSignOptions,
) -> Result<String, PolyjoseError> {
    let claims = Zeroizing::new(claims);
    let key = Zeroizing::new(key);
    let options = surface::JwtSignOptions::from(options);
    Ok(polyjose_surface::jwt::jwt_sign(&claims, &key, &options)?)
}

/// Verifies and validates the signed JWT `token` with `key` (ADR 0030 §4; RFC 7519 §7.2,
/// RFC 8725 §3). Only an `alg` in `options.allowed_algs` is accepted (RFC 8725 §3.1); unset
/// options are the core's defaults (ADR 0027). `key_index` of the result is `None`
/// (ADR 0029 §4).
///
/// # Errors
///
/// The codes of ADR 0027 §9, in the fixed order the core enforces (among them
/// `AlgorithmNotAllowed`, `InvalidSignature`, `TokenExpired`, `TokenNotYetValid` and
/// `InvalidClaim`);
/// `InvalidFormat` for a JWE or a JSON serialization (ADR 0027 §7); `InvalidHeader` for `typ`
/// with `any_typ` and `UnsupportedAlgorithm` for an unknown `profile` (ADR 0030 §4).
#[uniffi::export]
pub fn jwt_verify(
    token: String,
    key: String,
    options: JwtVerifyOptions,
) -> Result<JwtVerified, PolyjoseError> {
    let key = Zeroizing::new(key);
    let options = surface::JwtVerifyOptions::from(options);
    Ok(polyjose_surface::jwt::jwt_verify(&token, &key, &options)?.into())
}

/// Verifies and validates the signed JWT `token` against the JWK Set `jwks` (ADR 0030 §4;
/// RFC 7519 §7.2, RFC 7517 §5; ADR 0029). `key_index` of the result is the verifying member's
/// position in the set (ADR 0029 §4).
///
/// # Errors
///
/// Those of [`jwt_verify`], plus `NoMatchingKey` for no candidate or more than
/// `max_key_candidates` (ADR 0029 §4). An RSA private member is imported as is (ADR 0067 §4,
/// amending ADR 0029 §3).
#[uniffi::export]
pub fn jwt_verify_with_jwks(
    token: String,
    jwks: String,
    options: JwtVerifyOptions,
) -> Result<JwtVerified, PolyjoseError> {
    let jwks = Zeroizing::new(jwks);
    let options = surface::JwtVerifyOptions::from(options);
    Ok(polyjose_surface::jwt::jwt_verify_with_jwks(&token, &jwks, &options)?.into())
}

/// Encrypts the signed JWT `signed_jwt` into a compact JWE for exactly one recipient, with
/// `cty: "JWT"` set by the core (ADR 0030 §4; RFC 7519 §5.2, §11.2).
///
/// # Errors
///
/// The recipient's key and header errors; `InvalidFormat` unless `signed_jwt` is a signed
/// compact JWS, or unless there is exactly one recipient and no unprotected header or `aad`
/// (RFC 7516 §7.1); `InvalidHeader` for a `cty` other than `JWT` or for compression (RFC 8725
/// §3.6); `AlgorithmNotAllowed` for an inner `alg: none`; then the errors of
/// [`jwe_encrypt_compact`](crate::jwe::jwe_encrypt_compact).
#[uniffi::export]
pub fn jwt_encrypt_nested(
    signed_jwt: String,
    options: JweEncryptOptions,
) -> Result<String, PolyjoseError> {
    let signed_jwt = Zeroizing::new(signed_jwt);
    let options = surface::JweEncryptOptions::from(options);
    Ok(polyjose_surface::jwt::jwt_encrypt_nested(
        &signed_jwt,
        &options,
    )?)
}

/// Decrypts the nested JWT `token` with `decrypt_key` under `decrypt_options`, then verifies
/// and validates the inner JWT with `key` under `options` (ADR 0030 §4; RFC 7519 §5.2, §7.2
/// step 8; RFC 8725 §3.3).
///
/// # Errors
///
/// `InvalidFormat` for a three-part token or a JSON serialization; the errors of
/// [`jwe_decrypt_compact`](crate::jwe::jwe_decrypt_compact) (`DecryptionFailed` for every
/// failure after key management, RFC 7516 §11.5); `InvalidHeader` for the outer `cty`/`typ`
/// rules; those of [`jwt_verify`] for the inner JWT; and `InvalidClaim` for a replicated
/// `iss`/`sub`/`aud` that differs (RFC 7519 §5.3).
#[uniffi::export]
pub fn jwt_decrypt_nested(
    token: String,
    decrypt_key: String,
    decrypt_options: JweDecryptOptions,
    key: String,
    options: JwtVerifyOptions,
) -> Result<JwtNestedVerified, PolyjoseError> {
    let decrypt_key = Zeroizing::new(decrypt_key);
    let key = Zeroizing::new(key);
    let decrypt_options = surface::JweDecryptOptions::from(decrypt_options);
    let options = surface::JwtVerifyOptions::from(options);
    Ok(polyjose_surface::jwt::jwt_decrypt_nested(
        &token,
        &decrypt_key,
        &decrypt_options,
        &key,
        &options,
    )?
    .into())
}

/// Decrypts the nested JWT `token` with `decrypt_key`, then verifies and validates the inner
/// JWT against the JWK Set `jwks` (ADR 0030 §4; RFC 7519 §5.2, §7.2 step 8; ADR 0029).
///
/// # Errors
///
/// Those of [`jwt_decrypt_nested`], plus `NoMatchingKey` (ADR 0029 §4).
#[uniffi::export]
pub fn jwt_decrypt_nested_with_jwks(
    token: String,
    decrypt_key: String,
    decrypt_options: JweDecryptOptions,
    jwks: String,
    options: JwtVerifyOptions,
) -> Result<JwtNestedVerified, PolyjoseError> {
    let decrypt_key = Zeroizing::new(decrypt_key);
    let jwks = Zeroizing::new(jwks);
    let decrypt_options = surface::JweDecryptOptions::from(decrypt_options);
    let options = surface::JwtVerifyOptions::from(options);
    Ok(polyjose_surface::jwt::jwt_decrypt_nested_with_jwks(
        &token,
        &decrypt_key,
        &decrypt_options,
        &jwks,
        &options,
    )?
    .into())
}
