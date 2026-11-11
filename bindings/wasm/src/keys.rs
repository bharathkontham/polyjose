//! Key generation and PEM/DER import and export (ADR 0030 §4, "JWK"; RFC 7518 §6, RFC 8037 §2,
//! RFC 7468, RFC 5958, RFC 5280 §4.1, RFC 5915, RFC 8410; ADR 0005, ADR 0018, ADR 0067).
//!
//! Generated keys and imported or exported private keys are secrets: inputs are taken by value
//! and wiped on return (ADR 0030 §7.1), and results are copied into the JS value from the
//! surface's [`SecretString`](polyjose_surface::SecretString) or
//! [`SecretBytes`](polyjose_surface::SecretBytes) (ADR 0030 §7.2). Randomness comes only from the
//! OS CSPRNG, `crypto.getRandomValues` through getrandom's `wasm_js` backend (ADR 0005).

use js_sys::{JsString, Uint8Array};
use polyjose_surface::keys;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::error::polyjose_error;

/// A new random `oct` JWK of `lenBytes` octets, 16 to 512 (RFC 7518 §6.4, ADR 0018 §5); out of
/// range fails with `InvalidKey`. The facade has checked that `lenBytes` is a `u32` (BACKEND.md).
#[wasm_bindgen(js_name = jwkGenerateOct)]
pub fn jwk_generate_oct(len_bytes: u32) -> Result<JsString, JsValue> {
    let jwk = keys::jwk_generate_oct(len_bytes).map_err(polyjose_error)?;
    Ok(JsString::from(jwk.as_str()))
}

/// A new `EC` key pair on `crv`: `P-256`, `P-384`, `P-521` or `secp256k1` (RFC 7518 §6.2,
/// RFC 8812 §3.1); any other name fails with `UnsupportedAlgorithm`.
#[wasm_bindgen(js_name = jwkGenerateEc)]
pub fn jwk_generate_ec(crv: &str) -> Result<JsString, JsValue> {
    let jwk = keys::jwk_generate_ec(crv).map_err(polyjose_error)?;
    Ok(JsString::from(jwk.as_str()))
}

/// A new `OKP` key pair on `crv`: `Ed25519` or `X25519` (RFC 8037 §2); any other name fails with
/// `UnsupportedAlgorithm`.
#[wasm_bindgen(js_name = jwkGenerateOkp)]
pub fn jwk_generate_okp(crv: &str) -> Result<JsString, JsValue> {
    let jwk = keys::jwk_generate_okp(crv).map_err(polyjose_error)?;
    Ok(JsString::from(jwk.as_str()))
}

/// A new key for the JWS `alg` or JWE `alg`/`enc` name, with `alg` set (RFC 7517 §4.4;
/// RFC 7518 §3.1, §4.1, §5.1). RSA fails with `UnsupportedAlgorithm` (no RSA key generation,
/// ADR 0067 §3).
#[wasm_bindgen(js_name = jwkGenerateForAlg)]
pub fn jwk_generate_for_alg(alg: &str) -> Result<JsString, JsValue> {
    let jwk = keys::jwk_generate_for_alg(alg).map_err(polyjose_error)?;
    Ok(JsString::from(jwk.as_str()))
}

/// The JWK of a PEM key (RFC 7468): PKCS #8, SEC 1, SPKI, or PKCS #1 public or private
/// (RFC 5958, RFC 5915, RFC 5280 §4.1.2.7, RFC 8017 Appendix A.1.1, A.1.2). An RSA private key
/// imports with all its members (ADR 0067 §2).
#[wasm_bindgen(js_name = jwkFromPem)]
pub fn jwk_from_pem(pem: String) -> Result<JsString, JsValue> {
    let pem = Zeroizing::new(pem);
    let jwk = keys::jwk_from_pem(&pem).map_err(polyjose_error)?;
    Ok(JsString::from(jwk.as_str()))
}

/// The JWK of a DER key in `format`: `pkcs8`, `sec1`, `spki` or `pkcs1` (RFC 5958, RFC 5915,
/// RFC 5280 §4.1, RFC 8017 Appendix A.1.1); any other name fails with `UnsupportedAlgorithm`.
#[wasm_bindgen(js_name = jwkFromDer)]
pub fn jwk_from_der(der: Vec<u8>, format: &str) -> Result<JsString, JsValue> {
    let der = Zeroizing::new(der);
    let jwk = keys::jwk_from_der(&der, format).map_err(polyjose_error)?;
    Ok(JsString::from(jwk.as_str()))
}

/// The PEM text of `jwk` in `format` (RFC 7468 §10, §11, §13; RFC 5915 §4). May be private.
#[wasm_bindgen(js_name = jwkToPem)]
pub fn jwk_to_pem(jwk: String, format: &str) -> Result<JsString, JsValue> {
    let jwk = Zeroizing::new(jwk);
    let pem = keys::jwk_to_pem(&jwk, format).map_err(polyjose_error)?;
    Ok(JsString::from(pem.as_str()))
}

/// The DER octets of `jwk` in `format` (RFC 5958, RFC 5915, RFC 5280 §4.1). May be private.
#[wasm_bindgen(js_name = jwkToDer)]
pub fn jwk_to_der(jwk: String, format: &str) -> Result<Uint8Array, JsValue> {
    let jwk = Zeroizing::new(jwk);
    let der = keys::jwk_to_der(&jwk, format).map_err(polyjose_error)?;
    Ok(Uint8Array::from(der.as_bytes()))
}
