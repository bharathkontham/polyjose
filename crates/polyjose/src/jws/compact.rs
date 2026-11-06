//! JWS Compact Serialization (RFC 7515 §3.1, §7.1), with detached content
//! (RFC 7515 Appendix F) and the unencoded payload option (RFC 7797 §5.2).
//!
//! This file is a stub until T04 replaces it; the signatures are final.
//! The public functions call their `*_with` twins with the real
//! [`FAMILIES`]; tests call the twins with a fake table (see `jws/alg.rs`,
//! "The test seam").

use crate::error::{Error, Result};
use crate::jwk::Jwk;

use super::alg::{FAMILIES, Families};
use super::{ProtectedHeader, SignOptions, Verified, VerifyOptions};

/// Signs `payload` in the JWS Compact Serialization (RFC 7515 §5.1, §7.1):
/// `BASE64URL(UTF8(JWS Protected Header)) '.' BASE64URL(JWS Payload) '.'
/// BASE64URL(JWS Signature)`.
///
/// - `alg` comes from `protected`, the whole JOSE Header in this
///   serialization (RFC 7515 §7.1).
/// - With [`SignOptions::detached`] the payload part is empty:
///   `header..signature` (RFC 7515 Appendix F).
/// - With `"b64": false` (listed in `crit`), the payload is signed and
///   carried unencoded (RFC 7797 §3, §5.2).
///
/// # Errors
///
/// In this order (see the [module docs](crate::jws) for the full table):
///
/// - [`Error::InvalidHeader`]: `alg` missing, `crit` malformed, or `b64`
///   not listed in `crit` (RFC 7515 §4.1.11; RFC 7797 §3, §6).
/// - [`Error::UnknownCritical`]: `crit` lists a name other than `b64`.
/// - [`Error::UnsupportedAlgorithm`]: `alg` unknown, or RS*/PS* (no RSA
///   signing, ADR 0021).
/// - [`Error::AlgorithmNotAllowed`]: `alg` is `none` (RFC 8725 §3.2).
/// - [`Error::KeyAlgorithmMismatch`] / [`Error::InvalidKey`]: key binding
///   (ADR 0026 §2 step 8), including a public-only key.
/// - [`Error::InvalidFormat`]: `b64: false` with an attached payload that
///   contains `.` or octets outside %x20-7E (RFC 7797 §5.2).
/// - [`Error::InvalidKey`] / [`Error::RandomnessUnavailable`] from the
///   algorithm itself.
pub fn sign_compact(
    protected: &ProtectedHeader,
    payload: &[u8],
    key: &Jwk,
    opts: &SignOptions,
) -> Result<String> {
    sign_compact_with(&FAMILIES, protected, payload, key, opts)
}

/// [`sign_compact`] with the signature primitives taken from `families`.
pub(crate) fn sign_compact_with(
    families: &Families,
    protected: &ProtectedHeader,
    payload: &[u8],
    key: &Jwk,
    opts: &SignOptions,
) -> Result<String> {
    let _ = (
        families.sign,
        families.verify,
        protected,
        payload,
        key,
        opts,
    );
    Err(Error::UnsupportedAlgorithm)
}

/// Verifies a JWS in the Compact Serialization (RFC 7515 §5.2, §7.1)
/// with `key`, accepting only the algorithms `opts` allows.
///
/// - Exactly three parts, separated by two `.` (RFC 7515 §5.2 step 1).
/// - With [`VerifyOptions::detached_payload`], the payload part must be
///   empty and the supplied octets are verified (RFC 7515 Appendix F).
///   Without it, an empty payload part is an empty payload.
/// - With `"b64": false`, the payload part's octets are the payload
///   (RFC 7797 §3).
///
/// On success, [`Verified::signature_index`] is `0` and
/// [`Verified::unprotected`] is `None`.
///
/// # Errors
///
/// The first failing step of ADR 0026 §2 decides (see the
/// [module docs](crate::jws)):
///
/// - Steps 1–2, [`Error::InvalidFormat`]: longer than
///   [`VerifyOptions::max_input_len`], not three parts, or a payload part
///   present against the detached mode.
/// - Step 3, [`Error::InvalidBase64`]: a part is not strict base64url.
/// - Step 4, [`Error::InvalidJson`] (including a duplicate header member,
///   ADR 0041 §1) or [`Error::InvalidHeader`].
/// - Step 5, [`Error::UnknownCritical`].
/// - Step 6, [`Error::UnsupportedAlgorithm`].
/// - Step 7, [`Error::AlgorithmNotAllowed`], always for `none`.
/// - Step 8, [`Error::KeyAlgorithmMismatch`] or [`Error::InvalidKey`].
/// - Step 9, [`Error::InvalidSignature`].
pub fn verify_compact(jws: &str, key: &Jwk, opts: &VerifyOptions<'_>) -> Result<Verified> {
    verify_compact_with(&FAMILIES, jws, key, opts)
}

/// [`verify_compact`] with the signature primitives taken from `families`.
pub(crate) fn verify_compact_with(
    families: &Families,
    jws: &str,
    key: &Jwk,
    opts: &VerifyOptions<'_>,
) -> Result<Verified> {
    let _ = (families.sign, families.verify, jws, key, opts);
    Err(Error::UnsupportedAlgorithm)
}
