//! The JWS exports (ADR 0030 §4, "JWS"): `jws_sign_compact`, `jws_sign_flattened`,
//! `jws_sign_general`, `jws_verify_compact` and `jws_verify_json` (RFC 7515, RFC 7797, RFC 8037).
//!
//! Each export is a type conversion and one call into `polyjose_surface::jws` (ADR 0030 §1,
//! "the adapter test"). Verification takes the caller's allow-list and key only: no header
//! member selects an algorithm or a key (RFC 8725 §3.1, ADR 0007, ADR 0026 §2).
//!
//! **Secrets (ADR 0030 §7).** Payloads are treated as secret, and keys may be private.
//! - **Inputs.** The key `String` is moved into a [`Zeroizing`] owner, and records holding a key
//!   or a detached payload ([`JwsSigner`], [`JwsVerifyOptions`]) are converted into the
//!   surface's records, whose secret fields are `SecretString`/`SecretBytes`, in the first
//!   statements. A payload `Vec<u8>` is moved into a [`Zeroizing`] owner the same way. UniFFI
//!   0.32.2 lifted each `Vec<u8>` argument, and each `String` inside a record argument, by
//!   copying it out of a `RustBuffer` that it then freed unwiped: the documented residual of
//!   ADR 0030 §7.3 (ADR 0030 §7.1).
//! - **Outputs.** [`JwsVerified::payload`] is copied once from the surface's `SecretBytes`, which
//!   is wiped when the surface record drops (ADR 0030 §7.2, ADR 0049 §4). UniFFI 0.32.2
//!   serializes the record into a buffer that grows as it is written (earlier allocations of it
//!   are freed unwiped), drops the record unwiped, and the host frees the `RustBuffer` unwiped:
//!   the documented residual of ADR 0030 §7.3, which the adapter cannot reach without `unsafe`. The signed serializations are the surface's plain
//!   `String`s (they are the transmitted token).

use polyjose_surface::records as surface;
use zeroize::Zeroizing;

use crate::PolyjoseError;
use crate::records::{JwsSignOptions, JwsSigner, JwsVerified, JwsVerifyOptions};

/// Signs `payload` with `key` into a JWS Compact Serialization (ADR 0030 §4; RFC 7515 §5.1,
/// §7.1).
///
/// The JWS Protected Header is `options.protected_header` (serialized by the core) or
/// `options.protected_b64u` (signed over exactly as given, RFC 7515 Appendix A.1);
/// `options.detached` leaves the payload part empty (RFC 7515 Appendix F).
///
/// # Errors
///
/// `InvalidHeader` for both or neither header form (ADR 0030 §4) or a missing `alg` (RFC 7515
/// §4.1.1); `UnsupportedAlgorithm` for RSA signing (ADR 0021) and unknown algorithms;
/// `AlgorithmNotAllowed` for `none` (RFC 8725 §3.2); `KeyAlgorithmMismatch` and the core's key
/// errors.
#[uniffi::export]
pub fn jws_sign_compact(
    payload: Vec<u8>,
    key: String,
    options: JwsSignOptions,
) -> Result<String, PolyjoseError> {
    let payload = Zeroizing::new(payload);
    let key = Zeroizing::new(key);
    let options = surface::JwsSignOptions::from(options);
    Ok(polyjose_surface::jws::jws_sign_compact(
        &payload, &key, &options,
    )?)
}

/// Signs `payload` with `signer` into a flattened JWS JSON Serialization (ADR 0030 §4; RFC 7515
/// §7.2.2). `detached` leaves the `payload` member out (RFC 7515 Appendix F).
///
/// # Errors
///
/// `InvalidHeader` for both header forms, a missing `alg` or a member in both headers (RFC 7515
/// §4, §5.2 step 4); the errors of [`jws_sign_compact`] otherwise.
#[uniffi::export]
pub fn jws_sign_flattened(
    payload: Vec<u8>,
    signer: JwsSigner,
    detached: bool,
) -> Result<String, PolyjoseError> {
    let payload = Zeroizing::new(payload);
    let signer = surface::JwsSigner::from(signer);
    Ok(polyjose_surface::jws::jws_sign_flattened(
        &payload, &signer, detached,
    )?)
}

/// Signs `payload` with every signer into a general JWS JSON Serialization, signatures in list
/// order (ADR 0030 §4; RFC 7515 §7.2.1). `detached` leaves the `payload` member out (RFC 7515
/// Appendix F).
///
/// # Errors
///
/// `InvalidFormat` for an empty `signers` (RFC 7515 §7.2.1); the errors of
/// [`jws_sign_flattened`] for each signer.
#[uniffi::export]
pub fn jws_sign_general(
    payload: Vec<u8>,
    signers: Vec<JwsSigner>,
    detached: bool,
) -> Result<String, PolyjoseError> {
    let payload = Zeroizing::new(payload);
    let signers: Vec<surface::JwsSigner> = signers.into_iter().map(Into::into).collect();
    Ok(polyjose_surface::jws::jws_sign_general(
        &payload, &signers, detached,
    )?)
}

/// Verifies the JWS Compact Serialization `token` with `key` (ADR 0030 §4; RFC 7515 §5.2,
/// §7.1).
///
/// Only an `alg` in `options.allowed_algs` is accepted, and `none` never is (RFC 8725 §3.1,
/// ADR 0007). `options.detached_payload` is RFC 7515 Appendix F; unset limits are the core's
/// defaults (ADR 0026 §7).
///
/// # Errors
///
/// `AlgorithmNotAllowed`, `InvalidFormat`, `InvalidHeader`, `UnknownCritical`,
/// `KeyAlgorithmMismatch`, `InvalidSignature` and the other verification errors of the core, in
/// the core's order.
#[uniffi::export]
pub fn jws_verify_compact(
    token: String,
    key: String,
    options: JwsVerifyOptions,
) -> Result<JwsVerified, PolyjoseError> {
    let key = Zeroizing::new(key);
    let options = surface::JwsVerifyOptions::from(options);
    Ok(polyjose_surface::jws::jws_verify_compact(&token, &key, &options)?.into())
}

/// Verifies the flattened or general JWS JSON Serialization `jws` with `key`; the result names
/// the first signature that `key` verifies (ADR 0030 §4; RFC 7515 §5.2, §7.2; ADR 0026 §3).
///
/// **`unprotected_header` is not integrity-protected** (ADR 0049 §2; RFC 7515 §7.2.1): never
/// trust `typ`, `cty`, `kid` or `crit` from it; read them from `protected_header`.
///
/// # Errors
///
/// Those of [`jws_verify_compact`]; `InvalidFormat` also for more signatures than
/// `options.max_signatures` allows (ADR 0026 §7). When no signature verifies, the code of the
/// one that got furthest (ADR 0026 §3).
#[uniffi::export]
pub fn jws_verify_json(
    jws: String,
    key: String,
    options: JwsVerifyOptions,
) -> Result<JwsVerified, PolyjoseError> {
    let key = Zeroizing::new(key);
    let options = surface::JwsVerifyOptions::from(options);
    Ok(polyjose_surface::jws::jws_verify_json(&jws, &key, &options)?.into())
}
