//! The JWT exports (ADR 0030 §4, "JWT"): `jwtSign`, `jwtVerify`, `jwtVerifyWithJwks`,
//! `jwtEncryptNested`, `jwtDecryptNested` and `jwtDecryptNestedWithJwks` (RFC 7519, RFC 8725,
//! RFC 9068; ADR 0027, ADR 0028, ADR 0029).
//!
//! - **Secrets** (ADR 0030 §7): the claims are the JWS payload (ADR 0049 §4) and a signed JWT is
//!   the plaintext of a nested JWT (RFC 7519 §5.2, §11.2), so both are taken by value and wiped
//!   on return, like keys, JWK Sets and tokens; a signed JWT is copied into the JS string from a
//!   zeroizing buffer (ADR 0030 §7.2).
//! - **Clock** (ADR 0028, ADR 0030 §4): this adapter never reads one. `JwtVerifyOptions.now` is
//!   the facade's `Math.floor(Date.now() / 1000)` or the caller's own value, passed through as
//!   given (`src/read.rs`).
//! - One key or a JWK Set is chosen by which function is called, and signed and nested JWTs have
//!   separate entry points (ADR 0027 §7, ADR 0030 §4).

use js_sys::{JsString, Object};
use polyjose_surface::jwt;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::error::polyjose_error;
use crate::{read, write};

/// Signs `claims` (JSON text, RFC 7519 §4) with `key` into a JWT, a compact JWS (RFC 7519 §7.1).
/// `options` is `{ alg, typ?, omitTyp?, accessToken?, header? }` (RFC 7519 §5.1, RFC 9068 §2.1).
#[wasm_bindgen(js_name = jwtSign)]
pub fn jwt_sign(claims: String, key: String, options: &JsValue) -> Result<JsString, JsValue> {
    let claims = Zeroizing::new(claims);
    let key = Zeroizing::new(key);
    let options = read::jwt_sign_options(options)?;
    let jwt = Zeroizing::new(jwt::jwt_sign(&claims, &key, &options).map_err(polyjose_error)?);
    Ok(JsString::from(jwt.as_str()))
}

/// Verifies a signed JWT with `key` and validates its claims (RFC 7519 §7.2, RFC 8725 §3.1,
/// ADR 0027). Returns `{ claims, header, alg, keyIndex?, kid? }`.
#[wasm_bindgen(js_name = jwtVerify)]
pub fn jwt_verify(token: String, key: String, options: &JsValue) -> Result<Object, JsValue> {
    let token = Zeroizing::new(token);
    let key = Zeroizing::new(key);
    let options = read::jwt_verify_options(options)?;
    let verified = jwt::jwt_verify(&token, &key, &options).map_err(polyjose_error)?;
    write::jwt_verified(verified)
}

/// Verifies a signed JWT with a key selected from the JWK Set `jwks` (RFC 7517 §5, ADR 0029);
/// no member that matches fails with `NoMatchingKey`.
#[wasm_bindgen(js_name = jwtVerifyWithJwks)]
pub fn jwt_verify_with_jwks(
    token: String,
    jwks: String,
    options: &JsValue,
) -> Result<Object, JsValue> {
    let token = Zeroizing::new(token);
    let jwks = Zeroizing::new(jwks);
    let options = read::jwt_verify_options(options)?;
    let verified = jwt::jwt_verify_with_jwks(&token, &jwks, &options).map_err(polyjose_error)?;
    write::jwt_verified(verified)
}

/// Encrypts the signed JWT `signed_jwt` into a nested JWT, a compact JWE with `cty: "JWT"` set by
/// the core (RFC 7519 §5.2, §7.1 step 5, §11.2). Exactly one recipient.
#[wasm_bindgen(js_name = jwtEncryptNested)]
pub fn jwt_encrypt_nested(signed_jwt: String, options: &JsValue) -> Result<String, JsValue> {
    let signed_jwt = Zeroizing::new(signed_jwt);
    let options = read::jwe_encrypt_options(options)?;
    jwt::jwt_encrypt_nested(&signed_jwt, &options).map_err(polyjose_error)
}

/// Decrypts a nested JWT with `decrypt_key`, then verifies the inner JWT with `key`
/// (RFC 7519 §5.2, §7.2 step 8, §11.2; RFC 8725 §3.3; ADR 0027 §7). Returns `{ inner,
/// outerHeader, recipientIndex }`.
#[wasm_bindgen(js_name = jwtDecryptNested)]
pub fn jwt_decrypt_nested(
    token: String,
    decrypt_key: String,
    decrypt_options: &JsValue,
    key: String,
    verify_options: &JsValue,
) -> Result<Object, JsValue> {
    let token = Zeroizing::new(token);
    let decrypt_key = Zeroizing::new(decrypt_key);
    let key = Zeroizing::new(key);
    let decrypt_options = read::jwe_decrypt_options(decrypt_options)?;
    let verify_options = read::jwt_verify_options(verify_options)?;
    let verified = jwt::jwt_decrypt_nested(
        &token,
        &decrypt_key,
        &decrypt_options,
        &key,
        &verify_options,
    )
    .map_err(polyjose_error)?;
    write::jwt_nested_verified(verified)
}

/// As [`jwt_decrypt_nested`], verifying the inner JWT with a key selected from the JWK Set `jwks`
/// (RFC 7517 §5, ADR 0029).
#[wasm_bindgen(js_name = jwtDecryptNestedWithJwks)]
pub fn jwt_decrypt_nested_with_jwks(
    token: String,
    decrypt_key: String,
    decrypt_options: &JsValue,
    jwks: String,
    verify_options: &JsValue,
) -> Result<Object, JsValue> {
    let token = Zeroizing::new(token);
    let decrypt_key = Zeroizing::new(decrypt_key);
    let jwks = Zeroizing::new(jwks);
    let decrypt_options = read::jwe_decrypt_options(decrypt_options)?;
    let verify_options = read::jwt_verify_options(verify_options)?;
    let verified = jwt::jwt_decrypt_nested_with_jwks(
        &token,
        &decrypt_key,
        &decrypt_options,
        &jwks,
        &verify_options,
    )
    .map_err(polyjose_error)?;
    write::jwt_nested_verified(verified)
}
