//! Key generation and PEM/DER import and export (ADR 0030 §4, "JWK", the `jwk_generate_*`,
//! `jwk_from_*` and `jwk_to_*` operations; RFC 7518 §6, RFC 8037 §2, RFC 7468, RFC 5958,
//! RFC 5280 §4.1, RFC 5915, RFC 8410, RFC 8017 App. A.1; ADR 0005, 0018, 0067).
//!
//! Keys are JWK JSON text (ADR 0030 option C1). Generated keys and imported or exported private
//! keys are secrets, so they are returned as [`SecretString`]/[`SecretBytes`] (ADR 0030 §7.2).
//! Randomness comes only from the OS CSPRNG, through the core (ADR 0005). Format names are
//! `pkcs8`, `sec1`, `spki` and `pkcs1`; any other string fails with `UnsupportedAlgorithm`
//! (ADR 0030 §5).

use polyjose::jwa::{ContentEncAlg, KeyMgmtAlg, SigningAlg};
use polyjose::jwk::{EcCurve, Jwk, OkpCurve};
use polyjose::keys::{self as core_keys, JoseAlg, KeyFormat, KeySpec};

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
/// - `UnsupportedAlgorithm` for the RSA algorithms (no RSA key generation, ADR 0067 §3),
///   `RSA-OAEP` and `RSA1_5` (ADR 0022, ADR 0067 §3), `PBES2-*` (passwords are not generated),
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

/// The core [`KeyFormat`] the ADR 0030 §4 format name `format` stands for, matched exactly
/// (case-sensitive, no trimming). This is the one place that maps format names.
///
/// | Name | Structure |
/// |---|---|
/// | `pkcs8` | PKCS#8 OneAsymmetricKey (RFC 5958 §2): an EC or OKP private key |
/// | `sec1` | SEC1 ECPrivateKey (RFC 5915 §3): an EC private key |
/// | `spki` | SubjectPublicKeyInfo (RFC 5280 §4.1.2.7): an EC, OKP or RSA public key |
/// | `pkcs1` | PKCS#1 RSAPublicKey (RFC 8017 App. A.1.1): an RSA public key |
///
/// # Errors
///
/// `UnsupportedAlgorithm` for any other name (ADR 0030 §5). The name is not echoed.
fn key_format(format: &str) -> SurfaceResult<KeyFormat> {
    match format {
        "pkcs8" => Ok(KeyFormat::Pkcs8),
        "sec1" => Ok(KeyFormat::Sec1),
        "spki" => Ok(KeyFormat::Spki),
        "pkcs1" => Ok(KeyFormat::Pkcs1),
        _ => Err(unsupported()),
    }
}

/// The JWK of the PEM-encoded key `pem` (ADR 0030 §4; RFC 7468 §2, §10, §13; RFC 5915 §4).
///
/// The PEM label selects the structure (`PRIVATE KEY`, `PUBLIC KEY`, `EC PRIVATE KEY`,
/// `RSA PRIVATE KEY`, `RSA PUBLIC KEY`) and the key type comes from its DER, never from the label
/// (`polyjose::jwk::Jwk::from_pem`, ADR 0018 §2, §3). The result never has `kty` `oct`
/// (RFC 8725 §2.1) and no `alg` member.
///
/// The PEM may hold a private key, so it is borrowed, and the JWK returned as a
/// [`SecretString`] (ADR 0030 §7).
///
/// # Errors
///
/// As the core decides: `UnsupportedAlgorithm` for multi-prime RSA private keys (ADR 0067 §3),
/// encrypted keys (RFC 5958 §3, RFC 1421 §4.6.1.1; ADR 0018 §4), other labels such as
/// `CERTIFICATE` (RFC 7468 §5) and unsupported algorithms or curves; `InvalidKey` for malformed
/// or non-canonical PEM or DER and keys that fail JWK validation.
pub fn jwk_from_pem(pem: &str) -> SurfaceResult<SecretString> {
    secret_jwk(Jwk::from_pem(pem))
}

/// The JWK of the DER-encoded key `der` in `format` (ADR 0030 §4; RFC 5958 §2, RFC 5915 §3,
/// RFC 5280 §4.1.2.7, RFC 8017 App. A.1.1; `pkcs1` also reads an RSAPrivateKey, RFC 8017
/// App. A.1.2, ADR 0067 §2).
///
/// The caller names the structure; the core does no format sniffing (ADR 0007, ADR 0018 §3).
/// The DER may hold a private key, so it is borrowed, and the JWK returned as a
/// [`SecretString`] (ADR 0030 §7).
///
/// # Errors
///
/// - `UnsupportedAlgorithm` for a format name other than `pkcs8`, `sec1`, `spki` and `pkcs1`
///   (ADR 0030 §5), checked before `der` is read.
/// - The errors of [`jwk_from_pem`], from the core; DER of another structure than `format` is
///   `InvalidKey`.
pub fn jwk_from_der(der: &[u8], format: &str) -> SurfaceResult<SecretString> {
    let format = key_format(format)?;
    secret_jwk(Jwk::from_der(der, format))
}

/// `jwk` as PEM in `format` (ADR 0030 §4; RFC 7468 §2): the DER of [`jwk_to_der`] with the
/// format's label (`PRIVATE KEY`, RFC 7468 §10; `PUBLIC KEY`, §13; `EC PRIVATE KEY`, RFC 5915
/// §4; `RSA PUBLIC KEY`), 64-character lines and LF line endings, as the core writes it.
///
/// The PEM of a private key is a secret, so the result is a [`SecretString`] (ADR 0030 §7.2).
///
/// # Errors
///
/// Those of [`jwk_to_der`], in the same order.
pub fn jwk_to_pem(jwk: &str, format: &str) -> SurfaceResult<SecretString> {
    let format = key_format(format)?;
    let key = Jwk::from_json(jwk.as_bytes())?;
    Ok(SecretString::from(key.to_pem(format)?))
}

/// `jwk` as DER in `format` (ADR 0030 §4; RFC 5958 §2, RFC 5915 §3, RFC 5280 §4.1.2.7, RFC 8017
/// App. A.1.1), in the byte layout the core writes (ADR 0018 §3). Only the key material is
/// exported; `kid`, `use`, `alg` and the other JWK members have no place in these structures.
///
/// `spki` of a private key exports its public half, and so does `pkcs1` of an RSA private key
/// (RFC 8017 App. A.1.1; private RSA export is `pkcs8` only, ADR 0067 §2). The DER of a private
/// key is a secret, so the result is [`SecretBytes`] (ADR 0030 §7.2).
///
/// # Errors
///
/// 1. `UnsupportedAlgorithm` for a format name other than `pkcs8`, `sec1`, `spki` and `pkcs1`
///    (ADR 0030 §5), checked before `jwk` is parsed.
/// 2. The core's JWK parse errors (a multi-prime RSA JWK is `UnsupportedAlgorithm`, ADR 0067 §3).
/// 3. The core's export errors (ADR 0018 §3 format matrix): `UnsupportedAlgorithm` for an `oct`
///    key in any format (RFC 8725 §2.1), a non-EC key in `sec1` and a non-RSA key in `pkcs1`;
///    `InvalidKey` for a public key in `pkcs8` or `sec1`.
pub fn jwk_to_der(jwk: &str, format: &str) -> SurfaceResult<SecretBytes> {
    let format = key_format(format)?;
    let key = Jwk::from_json(jwk.as_bytes())?;
    Ok(SecretBytes::from(key.to_der(format)?))
}
