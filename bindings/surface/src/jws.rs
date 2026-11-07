//! JWS operations (ADR 0030 §4, "JWS"; RFC 7515, RFC 7797, RFC 8037, RFC 8812, RFC 9864;
//! ADR 0026, ADR 0045, ADR 0049).
//!
//! Keys are JWK JSON text, borrowed (ADR 0030 §7.1). Payloads are treated as secret: they are
//! borrowed on the way in, and a verified payload is [`SecretBytes`](crate::secret::SecretBytes)
//! (ADR 0049 §4). Verification takes the caller's allow-list and nothing else selects the
//! algorithm (ADR 0007, RFC 8725 §3.1); RSA signing fails with `UnsupportedAlgorithm`
//! (ADR 0021).

use polyjose::Error;
use polyjose::header::Header;
use polyjose::jwa::SigningAlg;
use polyjose::jwk::Jwk;
use polyjose::jws::{ProtectedHeader, SignOptions, Signer, Verified, VerifyOptions};

use crate::error::SurfaceResult;
use crate::records::{
    JwsSignOptions, JwsSigner, JwsVerified, JwsVerifyOptions, algs, apply, apply_flag, to_usize,
};
use crate::secret::SecretBytes;

/// Header-form misuse (ADR 0030 §4, §5): a signer sets both `protected_header` and
/// `protected_b64u`.
const BOTH_PROTECTED_FORMS: &str = "set only one of protected_header and protected_b64u";

/// Header-form misuse (ADR 0030 §4, §5): a compact JWS needs a JWS Protected Header, which is its
/// whole JOSE Header (RFC 7515 §7.1, ADR 0045 §1).
const NO_PROTECTED_HEADER: &str = "compact JWS needs protected_header or protected_b64u";

/// Signs `payload` with `key` into a JWS Compact Serialization (ADR 0030 §4; RFC 7515 §5.1,
/// §7.1).
///
/// `options` must set exactly one of `protected_header` and `protected_b64u`
/// (`InvalidHeader` otherwise, ADR 0030 §4): the compact serialization's JOSE Header is its JWS
/// Protected Header (RFC 7515 §7.1). `protected_header` is serialized by the core;
/// `protected_b64u` is signed over exactly as given (RFC 7515 §5.1 step 5, Appendix A.1).
/// `detached` leaves the payload part empty (RFC 7515 Appendix F).
///
/// # Errors
///
/// The key is parsed first, then the header, then the core signs (the order of the core's
/// `jws.sign` conformance runner): the core's code for a bad key or header JSON, `InvalidHeader`
/// for the header-form misuse above, then every error of `polyjose::jws::sign_compact`, among
/// them `UnsupportedAlgorithm` for RS*/PS* (ADR 0021) and `AlgorithmNotAllowed` for `none`
/// (RFC 8725 §3.2).
pub fn jws_sign_compact(
    payload: &[u8],
    key: &str,
    options: &JwsSignOptions,
) -> SurfaceResult<String> {
    let key = parse_key(key)?;
    let protected = protected_header(
        options.protected_header.as_deref(),
        options.protected_b64u.as_deref(),
    )?
    .ok_or(Error::InvalidHeader(NO_PROTECTED_HEADER))?;
    Ok(polyjose::jws::sign_compact(
        &protected,
        payload,
        &key,
        &sign_options(options.detached),
    )?)
}

/// Signs `payload` into a flattened JWS JSON Serialization with one `signer` (ADR 0030 §4;
/// RFC 7515 §7.2.2). `detached` leaves the `payload` member out (RFC 7515 Appendix F).
///
/// The signer sets at most one of `protected_header` and `protected_b64u` (both →
/// `InvalidHeader`, ADR 0030 §4). It may carry only an `unprotected_header`: the signing input
/// is then `"." || payload` (RFC 7515 §5.1, §7.2.1; ADR 0045 §1; RFC 7520 §4.7). Its `alg` may
/// be in either header, and a member may not be in both (RFC 7515 §4, §5.2 step 4): the core
/// checks both rules.
///
/// # Errors
///
/// As [`jws_sign_general`] with one signer.
pub fn jws_sign_flattened(
    payload: &[u8],
    signer: &JwsSigner,
    detached: bool,
) -> SurfaceResult<String> {
    let (key, protected, unprotected) = signer_parts(signer)?;
    let signer = core_signer(&key, protected, unprotected);
    Ok(polyjose::jws::sign_flattened(
        &signer,
        payload,
        &sign_options(detached),
    )?)
}

/// Signs `payload` into a general JWS JSON Serialization, one signature per signer, in order
/// (ADR 0030 §4; RFC 7515 §7.2.1). `detached` leaves the `payload` member out (RFC 7515
/// Appendix F).
///
/// Each signer follows the rules of [`jws_sign_flattened`]; an unprotected-only signer is
/// allowed (ADR 0045 §1).
///
/// # Errors
///
/// Signer by signer, in order: the core's code for a bad key, header JSON or header type, and
/// `InvalidHeader` for both protected forms (ADR 0030 §4). Then every error of
/// `polyjose::jws::sign_general`: `InvalidFormat` for no signers (RFC 7515 §7.2.1),
/// `InvalidHeader` for a missing `alg` or a member in both headers (RFC 7515 §4.1.1, §5.2
/// step 4), `UnsupportedAlgorithm` for RS*/PS* (ADR 0021), and the rest of its list.
pub fn jws_sign_general(
    payload: &[u8],
    signers: &[JwsSigner],
    detached: bool,
) -> SurfaceResult<String> {
    let mut keys = Vec::with_capacity(signers.len());
    let mut headers = Vec::with_capacity(signers.len());
    for signer in signers {
        let (key, protected, unprotected) = signer_parts(signer)?;
        keys.push(key);
        headers.push((protected, unprotected));
    }
    let signers: Vec<Signer<'_>> = keys
        .iter()
        .zip(headers)
        .map(|(key, (protected, unprotected))| core_signer(key, protected, unprotected))
        .collect();
    Ok(polyjose::jws::sign_general(
        &signers,
        payload,
        &sign_options(detached),
    )?)
}

/// Verifies the JWS Compact Serialization `token` with `key` (ADR 0030 §4; RFC 7515 §5.2,
/// §7.1; ADR 0026 §2).
///
/// Only `options.allowed_algs` decides which algorithms are accepted: the header `alg` must be
/// in it, and `none` never is (RFC 8725 §3.1, ADR 0007). The key is the caller's; a header's
/// `jwk`, `jku`, `x5c` or `kid` never selects one (ADR 0026 §2). `None` limits are the core
/// defaults (ADR 0026 §7), and `detached_payload` is RFC 7515 Appendix F.
///
/// The result's [`JwsVerified::protected_header`] is the core's serialization of the verified
/// header (always present for compact), and its payload is wiped on drop (ADR 0049 §4).
///
/// # Errors
///
/// The core's code for a bad key, then `AlgorithmNotAllowed` for an empty or `none`-only
/// allow-list (RFC 8725 §3.1), then every error of `polyjose::jws::verify_compact` in the core's
/// fixed order (ADR 0048; ADR 0026 §2): the surface adds no check and no ordering of its own.
pub fn jws_verify_compact(
    token: &str,
    key: &str,
    options: &JwsVerifyOptions,
) -> SurfaceResult<JwsVerified> {
    let key = parse_key(key)?;
    let allowed: Vec<SigningAlg> = algs(&options.allowed_algs);
    let verified = polyjose::jws::verify_compact(token, &key, &verify_options(&allowed, options)?)?;
    Ok(verified_from_core(verified)?)
}

/// Verifies the flattened or general JWS JSON Serialization `jws` with `key` (ADR 0030 §4;
/// RFC 7515 §5.2, §7.2; ADR 0026 §3).
///
/// The allow-list, key, limits and detached payload work as in [`jws_verify_compact`]. For a
/// general JWS the result describes the first signature, in array order, that verifies with
/// `key`, and [`JwsVerified::signature_index`] says which (ADR 0026 §3; RFC 7515 Appendix A.6).
///
/// **[`JwsVerified::unprotected_header`] is not integrity-protected** (ADR 0049 §2): the
/// signature does not cover it (RFC 7515 §5.1 step 5, §7.2.1), so anyone can change or add it
/// and the JWS still verifies. Never trust `typ`, `cty`, `kid` or `crit` from it; read them from
/// [`JwsVerified::protected_header`]. A signature may have only an unprotected header (RFC 7520
/// §4.7, ADR 0045 §1); its `alg` then still has to be in the caller's allow-list (ADR 0045 §2).
///
/// # Errors
///
/// As [`jws_verify_compact`], with the errors of `polyjose::jws::verify_json`: when no
/// signature verifies, the code of the one that got furthest (ADR 0026 §3).
pub fn jws_verify_json(
    jws: &str,
    key: &str,
    options: &JwsVerifyOptions,
) -> SurfaceResult<JwsVerified> {
    let key = parse_key(key)?;
    let allowed: Vec<SigningAlg> = algs(&options.allowed_algs);
    let verified = polyjose::jws::verify_json(jws, &key, &verify_options(&allowed, options)?)?;
    Ok(verified_from_core(verified)?)
}

// ------------------------------------------------------------------------------------------------
// Conversions to the core (ADR 0030 §3): each parses with the core's own code and passes values
// through unchanged.
// ------------------------------------------------------------------------------------------------

/// Parses a JWK with the core's strict I-JSON parser (RFC 7517 §4, ADR 0016). The text is
/// borrowed, and the parsed key wipes itself on drop (ADR 0030 §7.1).
fn parse_key(key: &str) -> polyjose::Result<Jwk> {
    Jwk::from_json(key.as_bytes())
}

/// The JWS Protected Header from at most one of its two forms (ADR 0030 §4): JSON text the core
/// serializes (RFC 7515 §5.1 steps 3-4), or `BASE64URL(UTF8(JWS Protected Header))` kept
/// verbatim for the signing input (RFC 7515 §5.1 step 5). Both → `InvalidHeader`; neither →
/// `None`, which only the JSON serializations accept (RFC 7515 §7.2.1, ADR 0045 §1).
fn protected_header(
    json: Option<&str>,
    b64u: Option<&str>,
) -> polyjose::Result<Option<ProtectedHeader>> {
    match (json, b64u) {
        (Some(_), Some(_)) => Err(Error::InvalidHeader(BOTH_PROTECTED_FORMS)),
        (Some(json), None) => ProtectedHeader::new(Header::from_json(json.as_bytes())?).map(Some),
        (None, Some(encoded)) => ProtectedHeader::from_encoded(encoded).map(Some),
        (None, None) => Ok(None),
    }
}

/// One surface signer as its core parts: the key, then the JWS Protected Header (at most one
/// form), then the JWS Unprotected Header (RFC 7515 §7.2.1 `header`), parsed in the order of the
/// core's `jws.sign` conformance runner, so a signer that is wrong in two ways fails with the
/// same code on every platform.
fn signer_parts(
    signer: &JwsSigner,
) -> polyjose::Result<(Jwk, Option<ProtectedHeader>, Option<Header>)> {
    let key = parse_key(signer.key.as_str())?;
    let protected = protected_header(
        signer.protected_header.as_deref(),
        signer.protected_b64u.as_deref(),
    )?;
    let unprotected = signer
        .unprotected_header
        .as_deref()
        .map(|json| Header::from_json(json.as_bytes()))
        .transpose()?;
    Ok((key, protected, unprotected))
}

/// The core signer over `key`, with each header set only when present (ADR 0030 §3). The
/// headers are moved in, not copied.
fn core_signer(
    key: &Jwk,
    protected: Option<ProtectedHeader>,
    unprotected: Option<Header>,
) -> Signer<'_> {
    let signer = apply(Signer::new(key), protected, Signer::protected);
    apply(signer, unprotected, Signer::unprotected)
}

/// The core sign options: `detached: false` calls nothing, so the core default (attached)
/// stands (ADR 0030 §3); `true` is RFC 7515 Appendix F.
fn sign_options(detached: bool) -> SignOptions {
    apply_flag(SignOptions::new(), detached, |o| o.detached(true))
}

/// The core verify options: the allow-list (required, checked by the core: RFC 8725 §3.1,
/// ADR 0007), then each limit and the detached payload only when set (ADR 0030 §3), so a `None`
/// is the core default (ADR 0026 §7). The detached payload is borrowed, not copied (ADR 0030
/// §7.1).
fn verify_options<'a>(
    allowed: &'a [SigningAlg],
    options: &'a JwsVerifyOptions,
) -> polyjose::Result<VerifyOptions<'a>> {
    let opts = VerifyOptions::new(allowed)?;
    let opts = apply(
        opts,
        options.max_input_len.map(to_usize),
        VerifyOptions::max_input_len,
    );
    let opts = apply(
        opts,
        options.max_signatures.map(to_usize),
        VerifyOptions::max_signatures,
    );
    Ok(apply(
        opts,
        options.detached_payload.as_ref().map(SecretBytes::as_bytes),
        VerifyOptions::detached_payload,
    ))
}

/// A signature index that does not fit a `u32` (ADR 0030 §2). Unreachable: the index is below
/// the number of signatures, which `max_signatures` (a `u32`, or the core default) bounds
/// (ADR 0026 §7). Reported as the over-limit `InvalidFormat` rather than a panic.
const INDEX_OVERFLOW: &str = "signature index exceeds u32";

/// The surface result of a core verification (ADR 0030 §4): the registered `alg` name, the
/// headers as the core serializes them (RFC 7515 §4), and the index.
///
/// The payload is the core's [`zeroize::Zeroizing`] buffer, moved into [`SecretBytes`] without
/// a copy, so no unwiped intermediate exists (ADR 0049 §4, ADR 0030 §7.2).
fn verified_from_core(verified: Verified) -> polyjose::Result<JwsVerified> {
    let signature_index = u32::try_from(verified.signature_index)
        .map_err(|_| Error::InvalidFormat(INDEX_OVERFLOW))?;
    Ok(JwsVerified {
        alg: verified.alg.as_str().to_owned(),
        protected_header: verified
            .protected
            .as_ref()
            .map(Header::to_json)
            .transpose()?,
        unprotected_header: verified
            .unprotected
            .as_ref()
            .map(Header::to_json)
            .transpose()?,
        payload: SecretBytes::from(verified.payload),
        signature_index,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7515 Appendix A.1's HMAC key.
    const OCT: &str = r#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#;

    fn core_verified(payload: &[u8]) -> Verified {
        let key = parse_key(OCT).unwrap();
        let protected = protected_header(Some(r#"{"alg":"HS256"}"#), None)
            .unwrap()
            .unwrap();
        let token =
            polyjose::jws::sign_compact(&protected, payload, &key, &SignOptions::new()).unwrap();
        let allowed = [SigningAlg::HS256];
        let opts = VerifyOptions::new(&allowed).unwrap();
        polyjose::jws::verify_compact(&token, &key, &opts).unwrap()
    }

    #[test]
    fn the_verified_payload_is_moved_into_secret_bytes_not_copied() {
        // ADR 0049 §4: the core's Zeroizing buffer becomes the surface's SecretBytes, so the
        // payload exists in one wiped-on-drop allocation only.
        let verified = core_verified(b"a secret payload");
        let core_buffer = verified.payload.as_ptr();
        let surface = verified_from_core(verified).unwrap();
        assert_eq!(surface.payload.as_bytes().as_ptr(), core_buffer);
        assert_eq!(surface.payload.as_bytes(), b"a secret payload");
    }

    #[test]
    fn the_conversion_keeps_the_core_values() {
        let surface = verified_from_core(core_verified(b"p")).unwrap();
        assert_eq!(surface.alg, "HS256");
        assert_eq!(
            surface.protected_header.as_deref(),
            Some(r#"{"alg":"HS256"}"#)
        );
        assert_eq!(surface.unprotected_header, None);
        assert_eq!(surface.signature_index, 0);
    }

    #[test]
    fn detached_false_leaves_the_core_default() {
        // ADR 0030 §3: `false` calls no setter.
        assert_eq!(sign_options(false), SignOptions::new());
        assert!(sign_options(true).detached);
    }
}
