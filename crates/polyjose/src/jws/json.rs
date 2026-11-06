//! JWS JSON Serialization, flattened and general (RFC 7515 §7.2), with
//! detached content (RFC 7515 Appendix F), the unencoded payload option
//! (RFC 7797 §5.3) and the multiple-signature policy of ADR 0026 §3.
//!
//! This file is a stub until T05 replaces it; the signatures are final.
//! The public functions call their `*_with` twins with the real
//! [`FAMILIES`]; tests call the twins with a fake table (see `jws/alg.rs`,
//! "The test seam").

use crate::error::{Error, Result};
use crate::jwk::Jwk;

use super::alg::{FAMILIES, Families};
use super::{SignOptions, Signer, Verified, VerifyOptions};

/// Signs `payload` in the flattened JWS JSON Serialization
/// (RFC 7515 §7.2.2): one signature, with its `protected`, `header` and
/// `signature` members at the top level.
///
/// The JOSE Header is the union of the signer's protected and unprotected
/// headers, which must be disjoint (RFC 7515 §5.2 step 4). With no
/// protected header the signing input starts with an empty string
/// (RFC 7515 §5.1). With [`SignOptions::detached`] the `payload` member is
/// omitted (RFC 7515 Appendix F); with `"b64": false` it is the payload
/// itself as a JSON string (RFC 7797 §5.3).
///
/// The output is compact, deterministic JSON.
///
/// # Errors
///
/// As [`sign_general`] with one signer.
pub fn sign_flattened(signer: &Signer<'_>, payload: &[u8], opts: &SignOptions) -> Result<String> {
    sign_flattened_with(&FAMILIES, signer, payload, opts)
}

/// [`sign_flattened`] with the signature primitives taken from `families`.
pub(crate) fn sign_flattened_with(
    families: &Families,
    signer: &Signer<'_>,
    payload: &[u8],
    opts: &SignOptions,
) -> Result<String> {
    let _ = (families.sign, families.verify, signer, payload, opts);
    Err(Error::UnsupportedAlgorithm)
}

/// Signs `payload` in the general JWS JSON Serialization
/// (RFC 7515 §7.2.1): one entry in `signatures` per signer, in order.
///
/// Each signer's JOSE Header is the union of its protected and unprotected
/// headers (RFC 7515 §5.2 step 4). Every signer must give the same `b64`
/// value (RFC 7797 §3). Detached content and `b64: false` behave as in
/// [`sign_flattened`].
///
/// # Errors
///
/// For each signer, in order, the first failing check decides:
///
/// - [`Error::InvalidFormat`]: `signers` is empty (RFC 7515 §7.2.1).
/// - [`Error::InvalidHeader`]: the two headers share a name, `alg` is
///   missing, `crit` is malformed or not in the protected header, `b64` is
///   not in the protected header or not listed in `crit`, or the signers
///   disagree on `b64` (RFC 7515 §4.1.11, §5.2 step 4; RFC 7797 §3, §6).
/// - [`Error::UnknownCritical`], [`Error::UnsupportedAlgorithm`] (also for
///   RS*/PS*, ADR 0021), [`Error::AlgorithmNotAllowed`] (`none`),
///   [`Error::KeyAlgorithmMismatch`] or [`Error::InvalidKey`], as for
///   [`sign_compact`](super::sign_compact).
/// - [`Error::InvalidFormat`]: `b64: false` with a payload that is not
///   UTF-8, so it cannot be a JSON string (RFC 7797 §5.3).
/// - [`Error::InvalidKey`] / [`Error::RandomnessUnavailable`] from the
///   algorithm itself.
pub fn sign_general(signers: &[Signer<'_>], payload: &[u8], opts: &SignOptions) -> Result<String> {
    sign_general_with(&FAMILIES, signers, payload, opts)
}

/// [`sign_general`] with the signature primitives taken from `families`.
pub(crate) fn sign_general_with(
    families: &Families,
    signers: &[Signer<'_>],
    payload: &[u8],
    opts: &SignOptions,
) -> Result<String> {
    let _ = (families.sign, families.verify, signers, payload, opts);
    Err(Error::UnsupportedAlgorithm)
}

/// Verifies a JWS in the JSON Serialization, flattened (RFC 7515 §7.2.2)
/// or general (RFC 7515 §7.2.1), with `key`, accepting only the
/// algorithms `opts` allows.
///
/// RFC 7515 §5.2 leaves the multiple-signature policy to the application;
/// polyjose's is ADR 0026 §3:
///
/// - Steps 1–4 (shape, base64url, header structure) run over **every**
///   signature first, and all signatures must agree on `b64`. Any failure
///   rejects the whole JWS.
/// - Steps 5–9 then run per signature, in array order, and stop at the
///   first that verifies. [`Verified::signature_index`] says which.
/// - If none verifies, the error is that of the signature that got
///   furthest: [`Error::InvalidSignature`] > [`Error::InvalidKey`] >
///   [`Error::KeyAlgorithmMismatch`] > [`Error::AlgorithmNotAllowed`] >
///   [`Error::UnsupportedAlgorithm`] > [`Error::UnknownCritical`], ties
///   to the lowest index.
///
/// With [`VerifyOptions::detached_payload`] the JWS must have no `payload`
/// member (RFC 7515 Appendix F); without it, `payload` is required
/// (RFC 7515 §7.2.1). Unknown top-level members are ignored
/// (RFC 7515 §7.2.1).
///
/// # Errors
///
/// - [`Error::InvalidFormat`]: over [`VerifyOptions::max_input_len`] or
///   [`VerifyOptions::max_signatures`]; not the §7.2 shape (`signature`
///   missing or not a string, `signatures` empty or mixed with top-level
///   signature members, `protected` the empty string, `header` not an
///   object); `payload` present or absent against the detached mode.
/// - [`Error::InvalidJson`]: JSON syntax, or a duplicate member anywhere,
///   including inside a header (ADR 0041 §1).
/// - [`Error::InvalidBase64`], [`Error::InvalidHeader`], then the per-signature
///   errors ranked as above (ADR 0026 §2, §3).
pub fn verify_json(jws: &str, key: &Jwk, opts: &VerifyOptions<'_>) -> Result<Verified> {
    verify_json_with(&FAMILIES, jws, key, opts)
}

/// [`verify_json`] with the signature primitives taken from `families`.
pub(crate) fn verify_json_with(
    families: &Families,
    jws: &str,
    key: &Jwk,
    opts: &VerifyOptions<'_>,
) -> Result<Verified> {
    let _ = (families.sign, families.verify, jws, key, opts);
    Err(Error::UnsupportedAlgorithm)
}
