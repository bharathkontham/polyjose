//! The JWK exports (ADR 0030 §4, "JWK"; ADR 0054 §9): `jwkParse`, `jwkToPublic`, `jwkThumbprint`,
//! `jwkThumbprintUri` and `jwksSelect` (RFC 7517, RFC 7638, RFC 9278).
//!
//! JWKs and JWK Sets are JSON text, taken by value and wiped on return because they may hold a
//! private key (ADR 0030 §7.1). A result that may be private is copied into the JS string from the
//! surface's [`SecretString`](polyjose_surface::SecretString) (ADR 0030 §7.2).

use js_sys::JsString;
use polyjose_surface::jwk;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::error::polyjose_error;
use crate::read;

/// Validates `jwk` and returns it re-serialized by the core, members in core order (RFC 7517 §4,
/// §5; RFC 7518 §6; ADR 0018). A private key stays private.
#[wasm_bindgen(js_name = jwkParse)]
pub fn jwk_parse(jwk: String) -> Result<JsString, JsValue> {
    let jwk = Zeroizing::new(jwk);
    let parsed = jwk::jwk_parse(&jwk).map_err(polyjose_error)?;
    Ok(JsString::from(parsed.as_str()))
}

/// The public JWK of `jwk`: private members removed (RFC 7517 §4, RFC 7518 §6.2.2, §6.3.2,
/// RFC 8037 §2). An `oct` key has none and fails with `UnsupportedAlgorithm`.
#[wasm_bindgen(js_name = jwkToPublic)]
pub fn jwk_to_public(jwk: String) -> Result<String, JsValue> {
    let jwk = Zeroizing::new(jwk);
    jwk::jwk_to_public(&jwk).map_err(polyjose_error)
}

/// The RFC 7638 thumbprint of `jwk`, base64url (RFC 7638 §3, §3.4; RFC 7515 §2).
///
/// `hash` is optional (ADR 0054 §9): JS `undefined` or `null` is `None`, which the surface turns
/// into the core default, SHA-256 (RFC 9278 §5; ADR 0030 §3: the adapter writes no default). A
/// name is passed on as given and parsed by the core (`ThumbprintHash::from_name`, ADR 0054 §8.2:
/// `sha-256`, `SHA-256`, `sha256` and the 384 and 512 forms); any other name fails with
/// `UnsupportedAlgorithm` (ADR 0022, ADR 0030 §5), after the JWK's own import errors
/// (ADR 0057 §2).
#[wasm_bindgen(js_name = jwkThumbprint)]
pub fn jwk_thumbprint(jwk: String, hash: Option<String>) -> Result<String, JsValue> {
    let jwk = Zeroizing::new(jwk);
    jwk::jwk_thumbprint(&jwk, hash.as_deref()).map_err(polyjose_error)
}

/// The RFC 9278 thumbprint URI of `jwk`, `urn:ietf:params:oauth:jwk-thumbprint:<hash>:<value>`
/// (RFC 9278 §3), with the IANA hash name whichever accepted spelling was passed (RFC 9278 §4,
/// ADR 0054 §8.3). `hash` and the errors are as for [`jwk_thumbprint`].
#[wasm_bindgen(js_name = jwkThumbprintUri)]
pub fn jwk_thumbprint_uri(jwk: String, hash: Option<String>) -> Result<String, JsValue> {
    let jwk = Zeroizing::new(jwk);
    jwk::jwk_thumbprint_uri(&jwk, hash.as_deref()).map_err(polyjose_error)
}

/// The one member of the JWK Set `jwks` that `selector` (`{ kid?, alg?, keyUse? }`) picks, by the
/// core's `JwkSet::select` (RFC 7517 §5, §4.2, §4.4, §4.5; ADR 0054 §1-§4, §9). The first error
/// is the outcome: the set's import errors, then `UnsupportedAlgorithm` for an `alg` or `keyUse`
/// the core refuses, then `NoMatchingKey` or `MultipleMatchingKeys` (ADR 0054 §4, §5). The set
/// and the result may hold private keys.
#[wasm_bindgen(js_name = jwksSelect)]
pub fn jwks_select(jwks: String, selector: &JsValue) -> Result<JsString, JsValue> {
    let jwks = Zeroizing::new(jwks);
    let selector = read::jwk_selector(selector)?;
    let selected = jwk::jwks_select(&jwks, &selector).map_err(polyjose_error)?;
    Ok(JsString::from(selected.as_str()))
}
