//! The JWK exports (ADR 0030 §4, "JWK"): `jwk_parse`, `jwk_to_public`, `jwk_thumbprint`,
//! `jwk_thumbprint_uri` and `jwks_select` (RFC 7517, RFC 7638, RFC 9278).
//!
//! Each export is a type conversion and one call into `polyjose_surface::jwk` (ADR 0030 §1,
//! "the adapter test"); validation, error codes and member order are the core's.
//!
//! **Secrets (ADR 0030 §7).** A JWK or JWK Set argument may be private, so it is moved into a
//! [`Zeroizing`] owner in the first statement; a `String` argument is UniFFI's only Rust-heap
//! copy of it (lifted from its `RustBuffer` without a copy, 0009 research §8), so nothing
//! unwiped remains on the Rust side (ADR 0030 §7.1). A result that may be private comes from the
//! surface as a `SecretString`: the adapter copies it once into the `String` that UniFFI lowers,
//! as is, into the `RustBuffer` the host reads and then frees unwiped; the surface's buffer is
//! wiped when it drops at the end of the statement (ADR 0030 §7.2). So each `String` result
//! leaves exactly **1** unwiped Rust-heap copy, the host-freed buffer: the measured UniFFI 0.32.2
//! residual of ADR 0058, which supersedes ADR 0030 §7.3 for outputs.

use polyjose_surface::records as surface;
use zeroize::Zeroizing;

use crate::PolyjoseError;
use crate::records::JwkSelector;

/// Parses and validates `jwk` and returns the core's re-serialization of it, members in core
/// order (ADR 0030 §4; RFC 7517 §4, RFC 7518 §6, RFC 8037 §2).
///
/// The result may hold private members (module docs; ADR 0030 §7.2, ADR 0058).
///
/// # Errors
///
/// The core's JWK parse errors: `InvalidJson`, `InvalidBase64`, `InvalidKey`,
/// `KeyAlgorithmMismatch`, and `UnsupportedAlgorithm` for a multi-prime RSA JWK (ADR 0067 §3);
/// an RSA private JWK without its CRT members is `InvalidKey`.
#[uniffi::export]
pub fn jwk_parse(jwk: String) -> Result<String, PolyjoseError> {
    let jwk = Zeroizing::new(jwk);
    Ok(polyjose_surface::jwk::jwk_parse(&jwk)?.as_str().to_owned())
}

/// The public form of `jwk`: the private members removed (ADR 0030 §4; RFC 7518 §6.2.2,
/// §6.3.2, RFC 8037 §2).
///
/// # Errors
///
/// The core's JWK parse errors; `UnsupportedAlgorithm` for an `oct` key, which has no public
/// part (RFC 7518 §6.4).
#[uniffi::export]
pub fn jwk_to_public(jwk: String) -> Result<String, PolyjoseError> {
    let jwk = Zeroizing::new(jwk);
    Ok(polyjose_surface::jwk::jwk_to_public(&jwk)?)
}

/// The JWK Thumbprint of `jwk` under `hash`, base64url encoded without padding: 43, 64 or 86
/// characters for SHA-256, SHA-384 or SHA-512 (ADR 0030 §4, ADR 0054 §9; RFC 7638 §3, §3.4,
/// RFC 7515 §2).
///
/// `hash` is optional: Kotlin `hash: String? = null`, Swift `hash: String? = nil`. Absent is the
/// core default, SHA-256 (RFC 9278 §5). A name is parsed by the core, which accepts exactly
/// `sha-256` | `SHA-256` | `sha256` and the same three forms for 384 and 512, case-sensitive
/// (ADR 0054 §8.2); the adapter passes it through unchanged.
///
/// # Security
///
/// For an `oct` key the hash input is the secret `k` (RFC 7638 §7). Never publish the thumbprint
/// of a password (a PBES2 key) or any other low-entropy `oct` key, and never use it as a `kid`:
/// it is an unsalted fast hash of the secret (ADR 0057 §4).
///
/// # Errors
///
/// In this order (ADR 0057 §2): the core's JWK parse errors (`InvalidJson`, `InvalidBase64`,
/// `InvalidKey`, `UnsupportedAlgorithm` for a multi-prime RSA JWK), then `UnsupportedAlgorithm` for
/// any other `hash` name, `SHA-1` included (ADR 0022).
#[uniffi::export(default(hash = None))]
pub fn jwk_thumbprint(jwk: String, hash: Option<String>) -> Result<String, PolyjoseError> {
    let jwk = Zeroizing::new(jwk);
    Ok(polyjose_surface::jwk::jwk_thumbprint(
        &jwk,
        hash.as_deref(),
    )?)
}

/// The JWK Thumbprint URI of `jwk` under `hash`,
/// `urn:ietf:params:oauth:jwk-thumbprint:<hash>:<thumbprint>` (ADR 0030 §4, ADR 0054 §9;
/// RFC 9278 §3).
///
/// `hash` is as for [`jwk_thumbprint`], and optional in the same way. `<hash>` is always the
/// IANA name (`sha-256`, `sha-384` or `sha-512`, RFC 9278 §4), whatever spelling was passed.
///
/// # Errors
///
/// Those of [`jwk_thumbprint`], in the same order.
#[uniffi::export(default(hash = None))]
pub fn jwk_thumbprint_uri(jwk: String, hash: Option<String>) -> Result<String, PolyjoseError> {
    let jwk = Zeroizing::new(jwk);
    Ok(polyjose_surface::jwk::jwk_thumbprint_uri(
        &jwk,
        hash.as_deref(),
    )?)
}

/// The one member of the JWK Set `jwks` that `selector` picks (ADR 0030 §4, ADR 0054 §9;
/// RFC 7517 §5, §4.2, §4.4, §4.5), by the core rule (`JwkSet::select`, ADR 0054 §2 as ADR 0057
/// §1 amends it). `kid` selects a key only here, by the caller's choice, never during
/// verification (ADR 0026 §2, ADR 0030 §6).
///
/// The member may be private (module docs; ADR 0030 §7.2, ADR 0058): call `jwkToPublic` before
/// publishing it. Selection never authorizes an algorithm; pass the key only to an operation
/// with an allow-list, and pair a `kid` from an untrusted header with `alg` (ADR 0054 §7). A
/// server maps `NoMatchingKey` and `MultipleMatchingKeys` to one opaque client error, such as
/// `invalid_token` (RFC 6750 §3.1).
///
/// # Errors
///
/// In this order (ADR 0054 §4): the set's import errors (`InvalidJson`, `InvalidKey`; an RSA
/// private member is imported as is, ADR 0067 §4); `UnsupportedAlgorithm` for an `alg` or
/// `key_use` the core refuses; `NoMatchingKey` for no match, `MultipleMatchingKeys` for two or
/// more.
#[uniffi::export]
pub fn jwks_select(jwks: String, selector: JwkSelector) -> Result<String, PolyjoseError> {
    let jwks = Zeroizing::new(jwks);
    let selector = surface::JwkSelector::from(selector);
    Ok(polyjose_surface::jwk::jwks_select(&jwks, &selector)?
        .as_str()
        .to_owned())
}
