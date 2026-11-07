//! Key generation and PEM/DER import and export (ADR 0030 §4, "JWK", the `jwk_generate_*`,
//! `jwk_from_*` and `jwk_to_*` operations; RFC 7518 §6, RFC 8037 §2, RFC 7468, RFC 5958,
//! RFC 5280 §4.1, RFC 5915, RFC 8410; ADR 0005, 0018, 0021).
//!
//! Keys are JWK JSON text (ADR 0030 option C1). Generated keys and imported or exported private
//! keys are secrets, so they are returned as [`SecretString`]/[`SecretBytes`] (ADR 0030 §7.2).
//! Randomness comes only from the OS CSPRNG, through the core (ADR 0005). Format names are
//! `pkcs8`, `sec1`, `spki` and `pkcs1`; any other string fails with `UnsupportedAlgorithm`
//! (ADR 0030 §5).

use polyjose::jwa::{ContentEncAlg, KeyMgmtAlg, SigningAlg};
use polyjose::jwk::{EcCurve, Jwk, OkpCurve};
use polyjose::keys::{self as core_keys, JoseAlg, KeySpec};

use crate::error::{SurfaceError, SurfaceResult};
use crate::records::to_usize;
use crate::secret::{SecretBytes, SecretString};

/// The `EC` curves of ADR 0030 §4, as the core's values. Their names come from the core
/// ([`EcCurve::as_str`]: RFC 7518 §7.6.2, RFC 8812 §4.4), so the surface spells none itself.
const EC_CURVES: [EcCurve; 4] = [
    EcCurve::P256,
    EcCurve::P384,
    EcCurve::P521,
    EcCurve::Secp256k1,
];

/// The `OKP` curves of ADR 0030 §4, as the core's values ([`OkpCurve::as_str`]: RFC 8037 §5).
const OKP_CURVES: [OkpCurve; 2] = [OkpCurve::Ed25519, OkpCurve::X25519];

/// `UnsupportedAlgorithm`, the code ADR 0030 §5 fixes for an unknown curve or format name. The
/// name is not echoed.
fn unsupported() -> SurfaceError {
    SurfaceError::from(polyjose::Error::UnsupportedAlgorithm)
}

/// A generated core key as the secret JWK text the surface returns (ADR 0030 §7.2): the core's
/// [`Jwk::to_json`] buffer is moved in, not copied.
fn secret_jwk(key: polyjose::Result<Jwk>) -> SurfaceResult<SecretString> {
    Ok(SecretString::from(key?.to_json()))
}

/// A new random `oct` key of `len_bytes` octets, 16 to 512 (ADR 0030 §4; RFC 7518 §6.4,
/// ADR 0018 §5).
///
/// `k` is `len_bytes` octets from the OS CSPRNG (RFC 7518 §6.4.1, ADR 0005), and the JWK has no
/// `alg` member. The range is the core's: the surface passes `len_bytes` through unchanged.
///
/// # Errors
///
/// - `InvalidKey` for a length outside the range, as the core decides before drawing any random
///   byte (ADR 0030 §5).
/// - `RandomnessUnavailable` if the OS CSPRNG fails (ADR 0005).
pub fn jwk_generate_oct(len_bytes: u32) -> SurfaceResult<SecretString> {
    secret_jwk(core_keys::generate(KeySpec::Oct {
        bytes: to_usize(len_bytes),
    }))
}

/// A new `EC` key pair on `crv`: `P-256`, `P-384`, `P-521` or `secp256k1` (ADR 0030 §4;
/// RFC 7518 §6.2, RFC 8812 §3.1).
///
/// The private scalar comes from the OS CSPRNG (SEC 1 v2 §3.2.1, ADR 0005); the JWK has `crv`,
/// `x`, `y` and `d` and no `alg` member.
///
/// # Errors
///
/// - `UnsupportedAlgorithm` for any other `crv`, matched exactly (RFC 7518 §6.2.1.1: `crv` is
///   case-sensitive; ADR 0030 §5).
/// - `RandomnessUnavailable` if the OS CSPRNG fails (ADR 0005).
pub fn jwk_generate_ec(crv: &str) -> SurfaceResult<SecretString> {
    let crv = EC_CURVES
        .into_iter()
        .find(|c| c.as_str() == crv)
        .ok_or_else(unsupported)?;
    secret_jwk(core_keys::generate(KeySpec::Ec(crv)))
}

/// A new `OKP` key pair on `crv`: `Ed25519` or `X25519` (ADR 0030 §4; RFC 8037 §2).
///
/// `d` is 32 octets from the OS CSPRNG (RFC 8032 §5.1.5, RFC 7748 §5; ADR 0005) and `x` its
/// public key; the JWK has no `alg` member.
///
/// # Errors
///
/// - `UnsupportedAlgorithm` for any other `crv`, matched exactly; `Ed448` and `X448` are out of
///   scope (ADR 0006, ADR 0030 §5).
/// - `RandomnessUnavailable` if the OS CSPRNG fails (ADR 0005).
pub fn jwk_generate_okp(crv: &str) -> SurfaceResult<SecretString> {
    let crv = OKP_CURVES
        .into_iter()
        .find(|c| c.as_str() == crv)
        .ok_or_else(unsupported)?;
    secret_jwk(core_keys::generate(KeySpec::Okp(crv)))
}

/// A new key for the JWS `alg`, JWE `alg` or JWE `enc` named `alg`, with the JWK `alg` member
/// set (ADR 0030 §4; RFC 7517 §4.4, RFC 7518 §3.1, §4.1, §5.1; the 0005 `generate_for` table).
///
/// The key type and size for each name are the core's (`polyjose::keys::generate_for`): `oct`
/// keys of the RFC 7518 size for `HS*`, `A*KW`, `A*GCMKW`, `A*GCM` and `A*CBC-HS*`, EC keys for
/// `ES256`/`ES384`/`ES512`/`ES256K`, Ed25519 for `EdDSA` and `Ed25519`. Binding the key to its
/// algorithm is the RFC 8725 §3.1 "one key, one algorithm" rule (ADR 0007).
///
/// # Errors
///
/// As the core decides, never substituted by the surface:
///
/// - `UnsupportedAlgorithm` for the RSA algorithms (no RSA key generation, ADR 0021),
///   `RSA-OAEP` and `RSA1_5` (ADR 0021, ADR 0022), `PBES2-*` (passwords are not generated),
///   `dir` (its key is the key of its `enc`), `none`, and any unknown name.
/// - `InvalidKey` for `ECDH-ES` and `ECDH-ES+A*KW`: they work on several curves, so the caller
///   names one with [`jwk_generate_ec`] or [`jwk_generate_okp`]; polyjose never picks one.
/// - `RandomnessUnavailable` if the OS CSPRNG fails (ADR 0005).
pub fn jwk_generate_for_alg(alg: &str) -> SurfaceResult<SecretString> {
    secret_jwk(core_keys::generate_for(jose_alg(alg)))
}

/// The core algorithm identifier named `alg`: a JWS `alg`, a JWE `alg` or a JWE `enc`.
///
/// JWS `alg`, JWE `alg` and JWE `enc` names share one IANA registry (RFC 7518 §7.1), so a name
/// the core knows belongs to exactly one of its three enums. A name it does not know becomes
/// the core's `Unknown` value, which `generate_for` rejects with `UnsupportedAlgorithm`: the
/// surface never filters a name itself (ADR 0030 §3).
fn jose_alg(alg: &str) -> JoseAlg {
    let signing = SigningAlg::from(alg);
    if signing.is_known() {
        return signing.into();
    }
    let key_mgmt = KeyMgmtAlg::from(alg);
    if key_mgmt.is_known() {
        return key_mgmt.into();
    }
    ContentEncAlg::from(alg).into()
}

/// The JWK of the PEM-encoded key `pem` (ADR 0030 §4; RFC 7468 §2, §10, §13; RFC 5915 §4).
///
/// The PEM may hold a private key, so it is borrowed, and the JWK returned as a
/// [`SecretString`]. RSA private and encrypted PKCS#8 keys fail with `UnsupportedAlgorithm`
/// (ADR 0018, ADR 0021).
pub fn jwk_from_pem(pem: &str) -> SurfaceResult<SecretString> {
    // stub: T06
    let _ = pem;
    Err(SurfaceError::from(polyjose::Error::UnsupportedAlgorithm))
}

/// The JWK of the DER-encoded key `der` in `format` (ADR 0030 §4; RFC 5958 §2, RFC 5915 §3,
/// RFC 5280 §4.1.2.7, RFC 8017 App. A.1.1).
pub fn jwk_from_der(der: &[u8], format: &str) -> SurfaceResult<SecretString> {
    // stub: T06
    let _ = (der, format);
    Err(SurfaceError::from(polyjose::Error::UnsupportedAlgorithm))
}

/// `jwk` as PEM in `format` (ADR 0030 §4; RFC 7468 §2). The PEM of a private key is a secret,
/// so the result is a [`SecretString`].
pub fn jwk_to_pem(jwk: &str, format: &str) -> SurfaceResult<SecretString> {
    // stub: T06
    let _ = (jwk, format);
    Err(SurfaceError::from(polyjose::Error::UnsupportedAlgorithm))
}

/// `jwk` as DER in `format` (ADR 0030 §4; RFC 5958 §2, RFC 5915 §3, RFC 5280 §4.1.2.7). The DER
/// of a private key is a secret, so the result is [`SecretBytes`].
pub fn jwk_to_der(jwk: &str, format: &str) -> SurfaceResult<SecretBytes> {
    // stub: T06
    let _ = (jwk, format);
    Err(SurfaceError::from(polyjose::Error::UnsupportedAlgorithm))
}
