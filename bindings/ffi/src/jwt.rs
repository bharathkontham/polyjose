//! The JWT exports (ADR 0030 §4): `jwt_sign`, `jwt_verify`, `jwt_verify_with_jwks`,
//! `jwt_encrypt_nested`, `jwt_decrypt_nested` and `jwt_decrypt_nested_with_jwks` (RFC 7519,
//! RFC 8725, RFC 9068).
//!
//! Empty until feature 0013 T12, which adds one `#[uniffi::export]` per surface operation: a
//! type conversion and one surface call (ADR 0030 §1).
