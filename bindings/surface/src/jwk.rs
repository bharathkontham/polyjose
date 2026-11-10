//! JWK operations (ADR 0030 §4, "JWK"; ADR 0054 §9): parsing, the public form, thumbprints and JWK Set
//! selection (RFC 7517, RFC 7518 §6, RFC 7638, RFC 9278, RFC 8037; ADR 0018, 0022, 0067).
//!
//! JWKs and JWK Sets are JSON text in and out, parsed and written by the core's strict I-JSON
//! code (ADR 0016, ADR 0030 §2). A JWK argument may be private, so it is borrowed and never
//! copied by the surface (ADR 0030 §7.1), and a result that may be private is a
//! [`SecretString`] (ADR 0030 §7.2).
//!
//! Every operation parses its JWK with [`Jwk::from_json`], so the core's validation and its error
//! codes apply unchanged: `InvalidJson` for text that is not one I-JSON object, `InvalidBase64`,
//! `InvalidKey`, `KeyAlgorithmMismatch`, and `UnsupportedAlgorithm` for well-formed keys polyjose
//! does not support. An RSA private key (RFC 7518 §6.3.2) is supported with all its CRT members
//! (`InvalidKey` without them) and two primes only (`UnsupportedAlgorithm` for `oth`); ADR 0067
//! §2, §3.

use polyjose::jwk::{Jwk, JwkSelector as CoreSelector, JwkSet, KeyAlg, KeyUse, ThumbprintHash};

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
/// The core's JWK parse errors (module docs); a multi-prime RSA JWK fails with
/// `UnsupportedAlgorithm` and one without its CRT members with `InvalidKey` (ADR 0067 §3).
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
/// 1. the core's JWK parse errors (module docs), a multi-prime RSA JWK's `UnsupportedAlgorithm`
///    among them (ADR 0067 §3);
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

/// The one member of the JWK Set `jwks` that `selector` picks (ADR 0030 §4, ADR 0054 §9;
/// RFC 7517 §5, §4.2, §4.4, §4.5).
///
/// The rule is the core's [`JwkSet::select`] (ADR 0054 §2, as ADR 0057 §1 amends it), which
/// "0001 T07 selection rules" in ADR 0030 §4 now means. The surface only builds the core
/// selector, in this order, the first error being the outcome (ADR 0054 §4):
///
/// 1. [`JwkSet::from_json`] imports `jwks`; members the core cannot use are skipped
///    (ADR 0041 §2), and an RSA private member is imported as is, like EC and OKP members
///    (ADR 0067 §4, amending ADR 0029 §3);
/// 2. a core [`JwkSelector`](polyjose::jwk::JwkSelector) from `new()`, then `kid`, then `alg`
///    parsed by [`KeyAlg::from`], then `key_use` parsed by [`KeyUse::from`], each set only when
///    `Some`; the core setters validate the names (ADR 0054 §1.1), the surface maps none;
/// 3. `select`: exactly one match, or `NoMatchingKey` (none, an empty set included), or
///    `MultipleMatchingKeys` (two or more: RFC 7517 §5.1 gives a set's order no meaning).
///
/// The result is the member's core serialization ([`Jwk::to_json`]); its index in the set is
/// not returned (ADR 0030 §4 returns a JWK). EC, OKP and `oct` members come back as imported,
/// private parts included (ADR 0054 §3), so the result is a [`SecretString`] (ADR 0030 §7.2).
///
/// # Security (ADR 0054 §7, RFC 8725)
///
/// - Selection identifies a key; it never authorizes an algorithm. Pass the key only to an
///   operation that takes an allow-list, as every verify and decrypt does (ADR 0007).
/// - A selector with `alg` never crosses key families. One without `alg` (a `kid` alone) may
///   return a key of any family. A `kid` from an untrusted header is safe to compare: pair it
///   with `alg`. For JWS and JWT, verify against the set with `jwt_verify_with_jwks` instead,
///   which selects by the header's `alg` and `kid` after the allow-list (ADR 0029).
/// - Call [`jwk_to_public`] before publishing a selected key.
/// - `NoMatchingKey` and `MultipleMatchingKeys` tell a prober which `kid`s exist and which
///   repeat. A server should map both, with the verify and decrypt codes, to one opaque client
///   error such as `invalid_token` (RFC 6750 §3.1).
/// - Pin a JWK `alg` on every `oct` key, or select with a `kid`: an `oct` key without `alg`
///   matches every symmetric `alg`, and selection checks no key size (ADR 0057 §3).
///
/// # Errors
///
/// In the order above: the set's import errors (`InvalidJson`; `InvalidKey` for a missing or
/// non-array `keys`), then
/// `UnsupportedAlgorithm` for an `alg` that is not a JWS or JWE key management algorithm
/// polyjose implements (`none`, `RSA1_5`, `RSA-OAEP`, an `enc` name, an unknown name) or a
/// `key_use` other than `sig` or `enc`, then `NoMatchingKey` or `MultipleMatchingKeys`.
/// Neither the input nor the selector is echoed.
pub fn jwks_select(jwks: &str, selector: &JwkSelector) -> SurfaceResult<SecretString> {
    let set = JwkSet::from_json(jwks.as_bytes())?;
    let mut core = CoreSelector::new();
    if let Some(kid) = &selector.kid {
        core = core.kid(kid);
    }
    if let Some(alg) = &selector.alg {
        core = core.alg(KeyAlg::from(alg.as_str()))?;
    }
    if let Some(key_use) = &selector.key_use {
        core = core.key_use(KeyUse::from(key_use.as_str()))?;
    }
    let (_, key) = set.select(&core)?;
    Ok(SecretString::from(key.to_json()))
}
