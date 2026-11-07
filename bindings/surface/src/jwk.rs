//! JWK operations (ADR 0030 §4, "JWK"): parsing, the public form, thumbprints and JWK Set
//! selection (RFC 7517, RFC 7518 §6, RFC 7638, RFC 9278, RFC 8037; ADR 0018, 0021, 0022).
//!
//! JWKs and JWK Sets are JSON text in and out, parsed and written by the core's strict I-JSON
//! code (ADR 0016, ADR 0030 §2). A JWK argument may be private, so it is borrowed and never
//! copied by the surface (ADR 0030 §7.1), and a result that may be private is a
//! [`SecretString`] (ADR 0030 §7.2).
//!
//! Every operation parses its JWK with [`Jwk::from_json`], so the core's validation and its error
//! codes apply unchanged: `InvalidJson` for text that is not one I-JSON object, `InvalidBase64`,
//! `InvalidKey`, `KeyAlgorithmMismatch`, and `UnsupportedAlgorithm` for well-formed keys polyjose
//! does not support, an RSA private key among them (ADR 0021).

use polyjose::jwk::{Jwk, ThumbprintHash};

use crate::error::{SurfaceError, SurfaceResult};
use crate::records::JwkSelector;
use crate::secret::SecretString;

/// Parses `jwk` with the core's validation (RFC 7517 §4, RFC 7518 §6, RFC 8037 §2).
fn parse(jwk: &str) -> SurfaceResult<Jwk> {
    Ok(Jwk::from_json(jwk.as_bytes())?)
}

/// Parses and validates `jwk` and returns the core's re-serialization of it, members in core
/// order (ADR 0030 §4; RFC 7517 §4, RFC 7518 §6, RFC 8037 §2).
///
/// The core order is `kty`, the key-type members, then `use`, `key_ops`, `alg`, `kid`, `x5u`,
/// `x5c`, `x5t`, `x5t#S256` and any other members in input order, without whitespace
/// ([`Jwk::to_json`]). The result may hold private members, so it is a [`SecretString`].
///
/// # Errors
///
/// The core's JWK parse errors (module docs); an RSA private JWK fails with
/// `UnsupportedAlgorithm` (ADR 0021).
pub fn jwk_parse(jwk: &str) -> SurfaceResult<SecretString> {
    Ok(SecretString::from(parse(jwk)?.to_json()))
}

/// The public form of `jwk`: its private members removed (ADR 0030 §4; RFC 7517 §4, RFC 7518
/// §6.2.2, §6.3.2, RFC 8037 §2).
///
/// This is the core's [`Jwk::to_public`] in core member order: `d` is dropped, `kid`, `use`,
/// `key_ops`, `alg` and the `x5*` members are kept, and members the core does not know are
/// dropped, because the core cannot tell whether they are secret. A public key comes back in
/// its core form.
///
/// # Errors
///
/// - The core's JWK parse errors (module docs).
/// - `UnsupportedAlgorithm` for an `oct` key, which has no public part (RFC 7518 §6.4). The core
///   returns no value for it rather than an error; the surface reports the code the core gives
///   for exporting an `oct` key's public half as SPKI (ADR 0018 §3 format matrix), so the same
///   request fails the same way through both operations.
pub fn jwk_to_public(jwk: &str) -> SurfaceResult<String> {
    let public = parse(jwk)?
        .to_public()
        .ok_or(SurfaceError::from(polyjose::Error::UnsupportedAlgorithm))?;
    // A public JWK holds no secret, so it leaves the core's zeroizing buffer as a plain String
    // (ADR 0030 §4 returns `jwk`, not a secret, here).
    Ok(public.to_json().as_str().to_owned())
}

/// The core hash that `hash` names, or the core default for `None` (ADR 0054 §8.2, §9;
/// ADR 0030 §3: defaults live in the core).
///
/// The surface keeps no name table and no default of its own: `Some(name)` goes to
/// [`ThumbprintHash::from_name`], which accepts exactly nine case-sensitive names (the IANA
/// Named Information names of RFC 9278 §4, the ADR 0030 §4 upper-case forms and the panva/jose
/// forms, for SHA-256, SHA-384 and SHA-512), and `None` is [`ThumbprintHash::default()`],
/// SHA-256, the hash RFC 9278 §5 makes mandatory to implement.
///
/// # Errors
///
/// `UnsupportedAlgorithm` from the core for any other name, SHA-1 among them (ADR 0022). The
/// name is not echoed.
fn thumbprint_hash(hash: Option<&str>) -> SurfaceResult<ThumbprintHash> {
    Ok(match hash {
        Some(name) => ThumbprintHash::from_name(name)?,
        None => ThumbprintHash::default(),
    })
}

/// The JWK Thumbprint of `jwk` under `hash`, base64url encoded without padding (ADR 0030 §4,
/// ADR 0054 §9; RFC 7638 §3, §3.4, RFC 7515 §2): 43, 64 or 86 characters for SHA-256, SHA-384
/// or SHA-512.
///
/// `hash` is optional: `None` is the core default, SHA-256 (RFC 9278 §5). A name is parsed by
/// the core ([`ThumbprintHash::from_name`]): `sha-256` | `SHA-256` | `sha256`, and the same
/// three forms for 384 and 512, matched exactly.
///
/// The hash input holds only the key type's required members (RFC 7638 §3.2), so `kid`, `use`,
/// `alg` and other members do not change the value, and a private key has the thumbprint of
/// its public key (RFC 7638 §3.2.1). For an `oct` key the input is the secret `k`; see the
/// RFC 7638 §7 caution on [`Jwk::thumbprint`].
///
/// # Security
///
/// Never publish the thumbprint of a password (a PBES2 `oct` key) or any other low-entropy `oct`
/// key, and never use it as a `kid`: it is an unsalted fast hash of the secret (ADR 0057 §4,
/// RFC 7638 §7).
///
/// # Errors
///
/// In this order, the first being the outcome (ADR 0057 §2):
///
/// 1. the core's JWK parse errors (module docs), an RSA private JWK's `UnsupportedAlgorithm`
///    among them;
/// 2. `UnsupportedAlgorithm` for any other `hash` name, from the core (ADR 0054 §8.2, ADR 0022,
///    ADR 0030 §5).
pub fn jwk_thumbprint(jwk: &str, hash: Option<&str>) -> SurfaceResult<String> {
    let key = parse(jwk)?;
    Ok(key.thumbprint(thumbprint_hash(hash)?))
}

/// The JWK Thumbprint URI of `jwk` under `hash`,
/// `urn:ietf:params:oauth:jwk-thumbprint:<hash>:<thumbprint>` (ADR 0030 §4, ADR 0054 §9;
/// RFC 9278 §3).
///
/// `hash` is as for [`jwk_thumbprint`]. `<hash>` is always the IANA Named Information hash name
/// (RFC 9278 §4), whichever accepted spelling was passed, written by the core
/// ([`Jwk::thumbprint_uri`], ADR 0054 §8.3).
///
/// # Errors
///
/// Those of [`jwk_thumbprint`], in the same order.
pub fn jwk_thumbprint_uri(jwk: &str, hash: Option<&str>) -> SurfaceResult<String> {
    let key = parse(jwk)?;
    Ok(key.thumbprint_uri(thumbprint_hash(hash)?))
}

/// The member of the JWK Set `jwks` that `selector` picks (ADR 0030 §4; RFC 7517 §5, §4.2,
/// §4.4, §4.5; the 0001 T07 selection rules).
///
/// `kid` is used only here, by an explicit caller choice; verification never selects a key by
/// a header's `kid` (ADR 0026 §2, ADR 0030 §6). The member may be private, so the result is a
/// [`SecretString`].
///
/// # Errors
///
/// For now, always `UnsupportedAlgorithm`: the core has no general JWK Set selection yet. It
/// arrives with feature 0015 (`JwkSet::select`), and task T14 wires it in here behind this same
/// signature (feature 0013 T06 Log, owner decision 2026-11-07).
pub fn jwks_select(jwks: &str, selector: &JwkSelector) -> SurfaceResult<SecretString> {
    // Interim stub until feature 0015 / task T14.
    let _ = (jwks, selector);
    Err(SurfaceError::from(polyjose::Error::UnsupportedAlgorithm))
}
