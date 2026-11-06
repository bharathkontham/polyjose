//! Key generation from the OS CSPRNG (ADR 0005, ADR 0018 §5):
//!
//! - `oct`: the RFC 7518 key sizes per `alg`/`enc` (§3.2, §4.4, §4.7,
//!   §5.2.3–§5.2.5, §5.3);
//! - EC P-256/P-384/P-521/secp256k1: a private scalar d in [1, n − 1]
//!   (SEC 1 v2 §3.2.1) by rejection sampling;
//! - Ed25519: 32 random octets (RFC 8032 §5.1.5);
//! - X25519: 32 random octets (RFC 7748 §5, §6.1).
//!
//! No RSA key generation (ADR 0021).
//!
//! # Randomness
//!
//! Every generator takes the RNG as a parameter and never reaches the OS
//! itself. The public entry points ([`generate`], [`generate_for`]) pass
//! [`CryptoRngAdapter::os`], the crate's one `TryCryptoRng` (ADR 0005,
//! ADR 0018 §5), so every random byte of a public key generation comes from
//! the OS CSPRNG through `rng::fill_random`. Any RNG failure becomes
//! [`Error::RandomnessUnavailable`] and no key is returned.
//!
//! # Validation
//!
//! Every key is built by `keys::jwk_build`, so it passes exactly the
//! [`Jwk::from_object`] validation of a JWK read from JSON (lengths, EC
//! points on their curve, scalars in range, Ed25519 decoding, `alg`
//! binding; ADR 0041 §4) before it is returned. Secret bytes are held only
//! in [`Zeroizing`] buffers on the way.

use p256::elliptic_curve::rand_core::TryCryptoRng;
use p256::elliptic_curve::sec1::{FromSec1Point, ModulusSize, ToSec1Point};
use p256::elliptic_curve::{
    AffinePoint, CurveArithmetic, FieldBytesSize, Generate, NonZeroScalar, SecretKey,
};
use zeroize::{Zeroize, Zeroizing};

use super::jwk_build;
use super::types::{JoseAlg, KeySpec};
use crate::error::{Error, Result};
use crate::jwa::{ContentEncAlg, KeyMgmtAlg, SigningAlg};
use crate::jwk::{EcCurve, Jwk, OkpCurve};
use crate::rng::CryptoRngAdapter;

/// The shortest `oct` key [`generate`] accepts: 16 octets, the smallest
/// RFC 7518 key size (A128KW §4.4, A128GCMKW §4.7, A128GCM §5.3).
const OCT_MIN_BYTES: usize = 16;

/// The longest `oct` key [`generate`] accepts: 512 octets (plan.md), well
/// above the largest RFC 7518 size (64 octets, HS512 §3.2 and
/// A256CBC-HS512 §5.2.5).
const OCT_MAX_BYTES: usize = 512;

/// Generates a new private key for `spec` from the OS CSPRNG (ADR 0005).
///
/// - [`KeySpec::Oct`]: `bytes` random octets as `k` (RFC 7518 §6.4.1), for
///   16 ≤ `bytes` ≤ 512.
/// - [`KeySpec::Ec`]: a private scalar d ∈ [1, n − 1] (SEC 1 v2 §3.2.1)
///   and its public point; `x`, `y` and `d` are each the curve's full
///   coordinate length (RFC 7518 §6.2.1.2–§6.2.1.3, §6.2.2.1; RFC 8812
///   §3.1 for secp256k1).
/// - [`KeySpec::Okp`]: 32 random octets as `d` and the derived public key
///   `x` (RFC 8037 §2): Ed25519 per RFC 8032 §5.1.5, X25519 per RFC 7748
///   §5 and §6.1.
///
/// The returned JWK has no `alg` member; use [`generate_for`] to bind the
/// key to one algorithm (RFC 8725 §3.1).
///
/// ```
/// use polyjose::keys::{generate, KeySpec};
///
/// let jwk = generate(KeySpec::Oct { bytes: 32 })?;
/// assert!(!jwk.is_public());
/// assert!(jwk.alg().is_none());
/// # Ok::<(), polyjose::Error>(())
/// ```
///
/// # Errors
///
/// - [`Error::InvalidKey`] for an `oct` length outside 16..=512; no random
///   byte is drawn.
/// - [`Error::RandomnessUnavailable`] if the OS CSPRNG fails; no key is
///   returned (ADR 0005).
pub fn generate(spec: KeySpec) -> Result<Jwk> {
    generate_with(spec, &mut CryptoRngAdapter::os())
}

/// [`generate`] with the RNG passed in.
fn generate_with<R: TryCryptoRng + ?Sized>(spec: KeySpec, rng: &mut R) -> Result<Jwk> {
    match spec {
        KeySpec::Oct { bytes } => generate_oct(bytes, rng),
        KeySpec::Ec(crv) => generate_ec(crv, rng),
        KeySpec::Okp(crv) => generate_okp(crv, rng),
    }
}

/// Generates a private EC key on `crv` from `rng`, as a validated JWK with
/// `crv`, `x`, `y` and `d` and no `alg` member (RFC 7518 §6.2).
///
/// **This is the crate's single EC key generator**, and its signature is
/// stable: [`generate`] uses it, and JWE uses it, through
/// `crate::keys::generate::generate_ec`, for the fresh ephemeral key of
/// every ECDH-ES operation (RFC 7518 §4.6.1: "a new ephemeral public key
/// value MUST be generated for each key agreement operation"). It samples
/// through [`generate_ec_secret`], the one EC sampling path.
///
/// # Errors
///
/// [`Error::RandomnessUnavailable`] if `rng` fails; no key is returned.
pub(crate) fn generate_ec<R: TryCryptoRng + ?Sized>(crv: EcCurve, rng: &mut R) -> Result<Jwk> {
    ec_key(crv, None, rng)
}

/// Samples a private EC scalar d ∈ [1, n − 1] for the curve `C` from `rng`
/// (SEC 1 v2 §3.2.1), as the curve crate's `SecretKey`, which is wiped on
/// drop.
///
/// **This is the crate's one EC sampling path,** with a stable signature:
/// [`generate_ec`] builds its JWK from it, and JWE takes the `SecretKey`
/// straight to `diffie_hellman` for its ECDH-ES ephemeral keys (RFC 7518
/// §4.6), with no base64url round trip. `C` is `p256::NistP256`,
/// `p384::NistP384`, `p521::NistP521` or `k256::Secp256k1`.
///
/// # Errors
///
/// [`Error::RandomnessUnavailable`] if `rng` fails, whatever its error
/// type; no scalar is returned (ADR 0005).
pub(crate) fn generate_ec_secret<C, R>(rng: &mut R) -> Result<SecretKey<C>>
where
    C: CurveArithmetic,
    R: TryCryptoRng + ?Sized,
{
    // research.md §6: `NonZeroScalar::try_generate_from_rng`, not
    // `SecretKey::try_generate_from_rng`. The latter samples through
    // `ScalarValue::try_random_mod_vartime`, which can in principle return
    // 0; this one draws a scalar below n by rejection sampling and redraws
    // on 0, so d ∈ [1, n − 1] (SEC 1 v2 §3.2.1, Key Pair Generation
    // Primitive step 1).
    let mut scalar =
        NonZeroScalar::<C>::try_generate_from_rng(rng).map_err(|_| Error::RandomnessUnavailable)?;
    let secret = SecretKey::from(&scalar);
    // NonZeroScalar does not wipe itself on drop; SecretKey does.
    scalar.zeroize();
    Ok(secret)
}

/// Generates a private OKP key on `crv` from `rng`, as a validated JWK with
/// `crv`, `x` and `d` and no `alg` member (RFC 8037 §2).
///
/// The private key is 32 octets drawn from `rng` (Ed25519: RFC 8032 §5.1.5,
/// "The private key is 32 octets (256 bits) of cryptographically secure
/// random data"; X25519: RFC 7748 §5 and §6.1, 32 random bytes, clamped
/// only when used). The public key `x` is derived by ed25519-dalek or
/// x25519-dalek. Like [`generate_ec`], this is the crate-wide entry point,
/// for X25519 ECDH-ES ephemeral keys too (RFC 8037 §3.1, RFC 7518 §4.6).
///
/// # Errors
///
/// [`Error::RandomnessUnavailable`] if `rng` fails; no key is returned.
pub(crate) fn generate_okp<R: TryCryptoRng + ?Sized>(crv: OkpCurve, rng: &mut R) -> Result<Jwk> {
    okp_key(crv, None, rng)
}

/// [`generate_okp`] with the optional `alg` member (RFC 7517 §4.4). The
/// 32-octet seed lives only in a [`Zeroizing`] buffer, and the dalek key
/// types built from it are wiped on drop (their `zeroize` feature).
fn okp_key<R: TryCryptoRng + ?Sized>(crv: OkpCurve, alg: Option<&str>, rng: &mut R) -> Result<Jwk> {
    let mut d = Zeroizing::new([0u8; 32]);
    fill(rng, d.as_mut_slice())?;
    let x = match crv {
        // RFC 8032 §5.1.5 steps 1–4: A = [s]B from SHA-512(d).
        OkpCurve::Ed25519 => ed25519_dalek::SigningKey::from_bytes(&d)
            .verifying_key()
            .to_bytes(),
        // RFC 7748 §6.1: the public key is X25519(d, 9).
        OkpCurve::X25519 => {
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*d)).to_bytes()
        }
    };
    jwk_build::okp_jwk(crv, &x, Some(d.as_slice()), alg)
}

/// [`generate_ec`] with the optional `alg` member (RFC 7517 §4.4).
fn ec_key<R: TryCryptoRng + ?Sized>(crv: EcCurve, alg: Option<&str>, rng: &mut R) -> Result<Jwk> {
    match crv {
        EcCurve::P256 => {
            ec_jwk_from_secret(crv, &generate_ec_secret::<p256::NistP256, R>(rng)?, alg)
        }
        EcCurve::P384 => {
            ec_jwk_from_secret(crv, &generate_ec_secret::<p384::NistP384, R>(rng)?, alg)
        }
        EcCurve::P521 => {
            ec_jwk_from_secret(crv, &generate_ec_secret::<p521::NistP521, R>(rng)?, alg)
        }
        EcCurve::Secp256k1 => {
            ec_jwk_from_secret(crv, &generate_ec_secret::<k256::Secp256k1, R>(rng)?, alg)
        }
    }
}

/// The JWK of `secret` on `crv`: the affine coordinates of Q = d·G
/// (SEC 1 v2 §3.2.1 step 2) from the uncompressed SEC 1 encoding
/// (§2.3.3), and d as big-endian bytes of the full field length
/// (RFC 7518 §6.2.2.1), held in a [`Zeroizing`] buffer.
fn ec_jwk_from_secret<C>(crv: EcCurve, secret: &SecretKey<C>, alg: Option<&str>) -> Result<Jwk>
where
    C: CurveArithmetic,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: ModulusSize,
{
    let point = secret.public_key().to_sec1_point(false);
    // d ≠ 0 and G has order n, so Q is never the identity, which is the
    // only point without coordinates.
    let (Some(x), Some(y)) = (point.x(), point.y()) else {
        return Err(Error::InvalidKey("EC public key is the identity"));
    };
    let d = Zeroizing::new(secret.to_bytes());
    jwk_build::ec_jwk(crv, x, y, Some(&d), alg)
}

/// Generates a new private key for the algorithm `alg` from the OS CSPRNG
/// (ADR 0005), and binds it to `alg` by setting the JWK `alg` member
/// (RFC 7517 §4.4; RFC 8725 §3.1, ADR 0007: one key, one algorithm).
///
/// | `alg` / `enc` | Key |
/// |---|---|
/// | `HS256`, `HS384`, `HS512` | `oct`, 32/48/64 octets: the hash output size (RFC 7518 §3.2) |
/// | `A128KW`, `A192KW`, `A256KW` | `oct`, 16/24/32 octets (RFC 7518 §4.4) |
/// | `A128GCMKW`, `A192GCMKW`, `A256GCMKW` | `oct`, 16/24/32 octets (RFC 7518 §4.7) |
/// | `A128GCM`, `A192GCM`, `A256GCM` | `oct`, 16/24/32 octets (RFC 7518 §5.3) |
/// | `A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512` | `oct`, 32/48/64 octets (RFC 7518 §5.2.3–§5.2.5) |
/// | `ES256`, `ES384`, `ES512` | EC P-256/P-384/P-521 (RFC 7518 §3.4) |
/// | `ES256K` | EC secp256k1 (RFC 8812 §3.2) |
/// | `EdDSA`, `Ed25519` | OKP Ed25519 (RFC 8037 §3.1, RFC 9864) |
///
/// A key for `dir` (RFC 7518 §4.5) is the key of its `enc`: call
/// `generate_for(enc)`.
///
/// ```
/// use polyjose::jwa::{ContentEncAlg, SigningAlg};
/// use polyjose::keys::generate_for;
///
/// let signing = generate_for(SigningAlg::ES256)?;
/// assert_eq!(signing.alg().map(|a| a.as_str()), Some("ES256"));
/// let cek = generate_for(ContentEncAlg::A256GCM)?;
/// assert_eq!(cek.alg().map(|a| a.as_str()), Some("A256GCM"));
/// # Ok::<(), polyjose::Error>(())
/// ```
///
/// # Errors
///
/// - [`Error::InvalidKey`] (`"curve required"`) for `ECDH-ES` and
///   `ECDH-ES+A128KW`/`+A192KW`/`+A256KW`: they work on several curves, so
///   there is no default. Call [`generate`] with `KeySpec::Ec(crv)` or
///   `KeySpec::Okp(OkpCurve::X25519)` instead.
/// - [`Error::UnsupportedAlgorithm`] for the RSA algorithms (`RS*`, `PS*`,
///   `RSA-OAEP-256`, `RSA-OAEP`, `RSA1_5`: no RSA key generation,
///   ADR 0021), `PBES2-*` (passwords are not generated), `dir` (its key
///   size depends on `enc`), `none` (no key), and any unknown value.
/// - [`Error::RandomnessUnavailable`] if the OS CSPRNG fails; no key is
///   returned (ADR 0005).
pub fn generate_for(alg: impl Into<JoseAlg>) -> Result<Jwk> {
    generate_for_with(&alg.into(), &mut CryptoRngAdapter::os())
}

/// [`generate_for`] with the RNG passed in.
fn generate_for_with<R: TryCryptoRng + ?Sized>(alg: &JoseAlg, rng: &mut R) -> Result<Jwk> {
    let name = Some(jose_alg_name(alg));
    match spec_for(alg)? {
        KeySpec::Oct { bytes } => oct_key(bytes, name, rng),
        KeySpec::Ec(crv) => ec_key(crv, name, rng),
        KeySpec::Okp(crv) => okp_key(crv, name, rng),
    }
}

/// The key `generate_for(alg)` generates (the table on [`generate_for`],
/// plan.md). Every variant is listed, with no wildcard, so a new algorithm
/// does not compile until it is mapped here.
fn spec_for(alg: &JoseAlg) -> Result<KeySpec> {
    const CURVE_REQUIRED: Error = Error::InvalidKey("curve required");
    let oct = |bytes| Ok(KeySpec::Oct { bytes });
    match alg {
        JoseAlg::Signing(alg) => match alg {
            SigningAlg::HS256 => oct(32),
            SigningAlg::HS384 => oct(48),
            SigningAlg::HS512 => oct(64),
            SigningAlg::ES256 => Ok(KeySpec::Ec(EcCurve::P256)),
            SigningAlg::ES384 => Ok(KeySpec::Ec(EcCurve::P384)),
            SigningAlg::ES512 => Ok(KeySpec::Ec(EcCurve::P521)),
            SigningAlg::ES256K => Ok(KeySpec::Ec(EcCurve::Secp256k1)),
            SigningAlg::EdDSA | SigningAlg::Ed25519 => Ok(KeySpec::Okp(OkpCurve::Ed25519)),
            SigningAlg::RS256
            | SigningAlg::RS384
            | SigningAlg::RS512
            | SigningAlg::PS256
            | SigningAlg::PS384
            | SigningAlg::PS512
            | SigningAlg::None
            | SigningAlg::Unknown(_) => Err(Error::UnsupportedAlgorithm),
        },
        JoseAlg::KeyMgmt(alg) => match alg {
            KeyMgmtAlg::A128KW | KeyMgmtAlg::A128GCMKW => oct(16),
            KeyMgmtAlg::A192KW | KeyMgmtAlg::A192GCMKW => oct(24),
            KeyMgmtAlg::A256KW | KeyMgmtAlg::A256GCMKW => oct(32),
            KeyMgmtAlg::EcdhEs
            | KeyMgmtAlg::EcdhEsA128KW
            | KeyMgmtAlg::EcdhEsA192KW
            | KeyMgmtAlg::EcdhEsA256KW => Err(CURVE_REQUIRED),
            KeyMgmtAlg::RsaOaep256
            | KeyMgmtAlg::Dir
            | KeyMgmtAlg::Pbes2Hs256A128KW
            | KeyMgmtAlg::Pbes2Hs384A192KW
            | KeyMgmtAlg::Pbes2Hs512A256KW
            | KeyMgmtAlg::Unknown(_) => Err(Error::UnsupportedAlgorithm),
        },
        JoseAlg::ContentEnc(enc) => match enc {
            ContentEncAlg::A128GCM => oct(16),
            ContentEncAlg::A192GCM => oct(24),
            ContentEncAlg::A256GCM => oct(32),
            ContentEncAlg::A128CbcHs256 => oct(32),
            ContentEncAlg::A192CbcHs384 => oct(48),
            ContentEncAlg::A256CbcHs512 => oct(64),
            ContentEncAlg::Unknown(_) => Err(Error::UnsupportedAlgorithm),
        },
    }
}

/// The registered name of `alg`, as written into the JWK `alg` member.
fn jose_alg_name(alg: &JoseAlg) -> &str {
    match alg {
        JoseAlg::Signing(alg) => alg.as_str(),
        JoseAlg::KeyMgmt(alg) => alg.as_str(),
        JoseAlg::ContentEnc(enc) => enc.as_str(),
    }
}

/// An `oct` key of `bytes` random octets from `rng` (RFC 7518 §6.4.1), with
/// no `alg` member.
fn generate_oct<R: TryCryptoRng + ?Sized>(bytes: usize, rng: &mut R) -> Result<Jwk> {
    oct_key(bytes, None, rng)
}

/// An `oct` key of `bytes` random octets from `rng`, with the optional
/// `alg` member (RFC 7517 §4.4). The length is checked before any byte is
/// drawn, and the key bytes live only in a [`Zeroizing`] buffer.
fn oct_key<R: TryCryptoRng + ?Sized>(bytes: usize, alg: Option<&str>, rng: &mut R) -> Result<Jwk> {
    if !(OCT_MIN_BYTES..=OCT_MAX_BYTES).contains(&bytes) {
        return Err(Error::InvalidKey("oct key length must be 16 to 512 octets"));
    }
    let mut k = Zeroizing::new(vec![0u8; bytes]);
    fill(rng, &mut k)?;
    jwk_build::oct_jwk(&k, alg)
}

/// Fills `dest` from `rng`, mapping any RNG error to the detail-free
/// [`Error::RandomnessUnavailable`] (ADR 0005, ADR 0007).
fn fill<R: TryCryptoRng + ?Sized>(rng: &mut R, dest: &mut [u8]) -> Result<()> {
    rng.try_fill_bytes(dest)
        .map_err(|_| Error::RandomnessUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;
    use crate::jwa::{ContentEncAlg, KeyMgmtAlg, SigningAlg};
    use crate::jwk::{EcCurve, EcKey, Jwk, KeyMaterial, OkpCurve, OkpKey};
    use crate::rng::CryptoRngAdapter;
    use crate::rng::insecure_test_vectors::FixedRng;
    use crate::util::b64url_encode;

    const EC_CURVES: [EcCurve; 4] = [
        EcCurve::P256,
        EcCurve::P384,
        EcCurve::P521,
        EcCurve::Secp256k1,
    ];

    /// The coordinate and scalar length of `crv` (RFC 7518 §6.2.1.2,
    /// §6.2.2.1; RFC 8812 §3.1 for secp256k1).
    fn ec_len(crv: EcCurve) -> usize {
        match crv {
            EcCurve::P256 | EcCurve::Secp256k1 => 32,
            EcCurve::P384 => 48,
            EcCurve::P521 => 66,
        }
    }

    /// A published private EC key per curve, as a JWK with its public
    /// point: RFC 7517 Appendix A.2 (P-256), RFC 9500 §2.3 testECCP384 and
    /// testECCP521, and RFC 7468 Figure 12 (secp256k1). The fixtures and
    /// their provenance are under `tests/data/keys/rfc` (T01).
    fn published_ec_key(crv: EcCurve) -> Jwk {
        let json: &[u8] = match crv {
            EcCurve::P256 => {
                include_bytes!("../../tests/data/keys/rfc/rfc7517-a2-ec-p256-pkcs8.jwk.json")
            }
            EcCurve::P384 => {
                include_bytes!("../../tests/data/keys/rfc/rfc9500-testECCP384-sec1.jwk.json")
            }
            EcCurve::P521 => {
                include_bytes!("../../tests/data/keys/rfc/rfc9500-testECCP521-sec1.jwk.json")
            }
            EcCurve::Secp256k1 => {
                include_bytes!("../../tests/data/keys/rfc/rfc7468-fig12-secp256k1-pkcs8.jwk.json")
            }
        };
        Jwk::from_json(json).expect("the fixture is a valid private EC JWK")
    }

    fn ec_key(jwk: &Jwk) -> &EcKey {
        let KeyMaterial::Ec(key) = jwk.material() else {
            panic!("an EC key")
        };
        key
    }

    fn ec_d(jwk: &Jwk) -> Vec<u8> {
        ec_key(jwk).d().expect("a private EC key").to_vec()
    }

    const OKP_CURVES: [OkpCurve; 2] = [OkpCurve::Ed25519, OkpCurve::X25519];

    /// RFC 8037 A.1 (Ed25519) and A.6 (X25519, the ephemeral key, which
    /// is RFC 7748 §6.1's Alice), from `tests/data/keys/rfc` (T01).
    fn published_okp_key(crv: OkpCurve) -> Jwk {
        let json: &[u8] = match crv {
            OkpCurve::Ed25519 => {
                include_bytes!("../../tests/data/keys/rfc/rfc8037-a1-ed25519-pkcs8.jwk.json")
            }
            OkpCurve::X25519 => {
                include_bytes!("../../tests/data/keys/rfc/rfc8037-a6-x25519-pkcs8.jwk.json")
            }
        };
        Jwk::from_json(json).expect("the fixture is a valid private OKP JWK")
    }

    fn okp_key(jwk: &Jwk) -> &OkpKey {
        let KeyMaterial::Okp(key) = jwk.material() else {
            panic!("an OKP key")
        };
        key
    }

    fn okp_d(jwk: &Jwk) -> Vec<u8> {
        okp_key(jwk).d().expect("a private OKP key").to_vec()
    }

    /// `generate_ec` over a `FixedRng` that holds exactly `bytes`.
    fn ec_from_bytes(crv: EcCurve, bytes: &[u8]) -> (Result<Jwk>, usize) {
        let mut fixed = FixedRng::new(bytes);
        let jwk = generate_ec(crv, &mut CryptoRngAdapter::fixed(&mut fixed));
        (jwk, fixed.remaining())
    }

    /// The `k` of an `oct` JWK.
    fn oct_k(jwk: &Jwk) -> Vec<u8> {
        let KeyMaterial::Oct(key) = jwk.material() else {
            panic!("an oct key")
        };
        key.k().to_vec()
    }

    #[test]
    fn oct_has_exactly_the_requested_length_from_16_to_512() {
        // ADR 0018 §5 / plan.md: KeySpec::Oct accepts 16 ≤ bytes ≤ 512.
        for bytes in [16, 17, 32, 64, 511, 512] {
            let jwk = generate(KeySpec::Oct { bytes }).unwrap();
            assert_eq!(oct_k(&jwk).len(), bytes);
            assert!(jwk.alg().is_none());
        }
    }

    #[test]
    fn oct_outside_16_to_512_is_invalid_and_draws_nothing() {
        for bytes in [0, 1, 15, 513, usize::MAX] {
            let mut fixed = FixedRng::new([0x42u8; 1024]);
            let mut rng = CryptoRngAdapter::fixed(&mut fixed);
            assert!(matches!(
                generate_with(KeySpec::Oct { bytes }, &mut rng),
                Err(Error::InvalidKey(_))
            ));
            assert_eq!(fixed.remaining(), 1024, "no random byte is drawn");
        }
    }

    #[test]
    fn oct_takes_its_bytes_from_the_rng_passed_in() {
        let seed: Vec<u8> = (0u8..32).collect();
        let mut fixed = FixedRng::new(seed.clone());
        let jwk = generate_with(
            KeySpec::Oct { bytes: 32 },
            &mut CryptoRngAdapter::fixed(&mut fixed),
        )
        .unwrap();
        assert_eq!(oct_k(&jwk), seed);
        assert_eq!(fixed.remaining(), 0);
    }

    #[test]
    fn oct_fails_closed_on_rng_failure() {
        // ADR 0005: a CSPRNG failure is RandomnessUnavailable and no key.
        let spec = KeySpec::Oct { bytes: 32 };
        assert_eq!(
            generate_with(
                spec,
                &mut CryptoRngAdapter::failing(getrandom::Error::UNEXPECTED)
            )
            .unwrap_err(),
            Error::RandomnessUnavailable
        );
        // A short FixedRng runs out the same way.
        let mut fixed = FixedRng::new([7u8; 31]);
        assert_eq!(
            generate_with(spec, &mut CryptoRngAdapter::fixed(&mut fixed)).unwrap_err(),
            Error::RandomnessUnavailable
        );
    }

    #[test]
    fn ec_keys_have_full_size_members_and_validate_after_a_json_round_trip() {
        // RFC 7518 §6.2.1.2–§6.2.1.3, §6.2.2.1: x, y and d are exactly the
        // coordinate length, leading zeros kept (32/48/66/32 octets).
        for crv in EC_CURVES {
            let jwk = generate(KeySpec::Ec(crv)).unwrap();
            let key = ec_key(&jwk);
            assert_eq!(key.crv(), crv);
            assert_eq!(key.x().len(), ec_len(crv));
            assert_eq!(key.y().len(), ec_len(crv));
            assert_eq!(ec_d(&jwk).len(), ec_len(crv));
            assert!(jwk.alg().is_none());

            // Typed-JWK validation (lengths, on-curve, scalar range;
            // ADR 0041 §4) accepts the serialized key, member by member.
            let reparsed = Jwk::from_json(jwk.to_json().as_bytes()).unwrap();
            let again = ec_key(&reparsed);
            assert_eq!(again.crv(), crv);
            assert_eq!(again.x(), key.x());
            assert_eq!(again.y(), key.y());
            assert_eq!(ec_d(&reparsed), ec_d(&jwk));
            assert_eq!(*reparsed.to_json(), *jwk.to_json());

            let public = jwk.to_public().expect("an EC key has a public part");
            assert!(public.is_public());
            assert_eq!(ec_key(&public).d(), None);
            assert_eq!(ec_key(&public).x(), key.x());
        }
    }

    #[test]
    fn ec_reproduces_published_keys_from_their_scalar() {
        // Each curve crate samples d as big-endian field bytes (SEC 1 v2
        // §2.3.7), so a FixedRng holding a published d yields exactly that
        // key, and generation derives the published public point.
        for crv in EC_CURVES {
            let published = published_ec_key(crv);
            let (jwk, left) = ec_from_bytes(crv, &ec_d(&published));
            let jwk = jwk.unwrap();
            assert_eq!(left, 0);
            assert_eq!(*jwk.to_json(), *published.to_json(), "{crv:?}");
        }
    }

    #[test]
    fn ec_rejection_samples_zero_and_out_of_range_scalars() {
        // SEC 1 v2 §3.2.1: d ∈ [1, n − 1]. NonZeroScalar redraws on 0
        // (research.md §6), and the curve's scalar sampler redraws on
        // values ≥ n (all-0xFF is above every order here).
        for crv in EC_CURVES {
            let published = published_ec_key(crv);
            let d = ec_d(&published);
            let mut bytes = vec![0u8; ec_len(crv)];
            bytes.extend(vec![0xFFu8; ec_len(crv)]);
            bytes.extend(&d);
            let (jwk, left) = ec_from_bytes(crv, &bytes);
            assert_eq!(left, 0, "{crv:?}: both rejected draws were consumed");
            assert_eq!(ec_d(&jwk.unwrap()), d, "{crv:?}");
        }
    }

    #[test]
    fn ec_secret_is_the_d_of_generate_ec() {
        // One EC sampling path: generate_ec is generate_ec_secret plus the
        // JWK, so the same FixedRng bytes give the same scalar.
        fn secret_bytes<C: CurveArithmetic>(bytes: &[u8]) -> Vec<u8> {
            let mut fixed = FixedRng::new(bytes);
            let secret =
                generate_ec_secret::<C, _>(&mut CryptoRngAdapter::fixed(&mut fixed)).unwrap();
            assert_eq!(fixed.remaining(), 0);
            secret.to_bytes().to_vec()
        }
        for crv in EC_CURVES {
            // The published d, and 00 01 02 …: below every order, nonzero.
            let counting: Vec<u8> = (0..ec_len(crv)).map(|i| i as u8).collect();
            for bytes in [ec_d(&published_ec_key(crv)), counting] {
                let (jwk, left) = ec_from_bytes(crv, &bytes);
                assert_eq!(left, 0);
                let secret = match crv {
                    EcCurve::P256 => secret_bytes::<p256::NistP256>(&bytes),
                    EcCurve::P384 => secret_bytes::<p384::NistP384>(&bytes),
                    EcCurve::P521 => secret_bytes::<p521::NistP521>(&bytes),
                    EcCurve::Secp256k1 => secret_bytes::<k256::Secp256k1>(&bytes),
                };
                assert_eq!(secret, ec_d(&jwk.unwrap()), "{crv:?}");
                assert_eq!(secret, bytes, "{crv:?}");
            }
        }
    }

    #[test]
    fn ec_fails_closed_on_rng_failure() {
        // ADR 0005: RandomnessUnavailable and no key, for an OS failure and
        // for a FixedRng one byte short of a scalar.
        for crv in EC_CURVES {
            assert_eq!(
                generate_ec(
                    crv,
                    &mut CryptoRngAdapter::failing(getrandom::Error::UNSUPPORTED)
                )
                .unwrap_err(),
                Error::RandomnessUnavailable
            );
            let (jwk, _) = ec_from_bytes(crv, &vec![0x11u8; ec_len(crv) - 1]);
            assert_eq!(jwk.unwrap_err(), Error::RandomnessUnavailable);
            // Exhausted after rejecting a zero draw.
            let (jwk, _) = ec_from_bytes(crv, &vec![0u8; ec_len(crv)]);
            assert_eq!(jwk.unwrap_err(), Error::RandomnessUnavailable);
        }
        let failing = || CryptoRngAdapter::failing(getrandom::Error::UNEXPECTED);
        assert!(matches!(
            generate_ec_secret::<p256::NistP256, _>(&mut failing()),
            Err(Error::RandomnessUnavailable)
        ));
        assert!(matches!(
            generate_ec_secret::<p384::NistP384, _>(&mut failing()),
            Err(Error::RandomnessUnavailable)
        ));
        assert!(matches!(
            generate_ec_secret::<p521::NistP521, _>(&mut failing()),
            Err(Error::RandomnessUnavailable)
        ));
        assert!(matches!(
            generate_ec_secret::<k256::Secp256k1, _>(&mut failing()),
            Err(Error::RandomnessUnavailable)
        ));
    }

    #[test]
    fn debug_of_a_generated_ec_key_redacts_d() {
        // T05 behaviour, asserted on a generated key: d never reaches Debug.
        let jwk = generate(KeySpec::Ec(EcCurve::P256)).unwrap();
        let debug = format!("{jwk:?}");
        assert!(debug.contains(r#"d: "<redacted>""#), "{debug}");
        assert!(!debug.contains(&b64url_encode(&ec_d(&jwk))));
    }

    #[test]
    fn okp_keys_have_32_octet_members_and_validate_after_a_json_round_trip() {
        // RFC 8032 §5.1.5 / RFC 7748 §5: 32-octet private keys; RFC 8037
        // §2: x is the 32-octet public key.
        for crv in OKP_CURVES {
            let jwk = generate(KeySpec::Okp(crv)).unwrap();
            let key = okp_key(&jwk);
            assert_eq!(key.crv(), crv);
            assert_eq!(key.x().len(), 32);
            assert_eq!(okp_d(&jwk).len(), 32);
            assert!(jwk.alg().is_none());

            let reparsed = Jwk::from_json(jwk.to_json().as_bytes()).unwrap();
            assert_eq!(okp_key(&reparsed).crv(), crv);
            assert_eq!(okp_key(&reparsed).x(), key.x());
            assert_eq!(okp_d(&reparsed), okp_d(&jwk));
            assert_eq!(*reparsed.to_json(), *jwk.to_json());

            let public = jwk.to_public().expect("an OKP key has a public part");
            assert!(public.is_public());
            assert_eq!(okp_key(&public).d(), None);
        }
    }

    #[test]
    fn okp_derives_the_published_public_keys() {
        // RFC 8037 A.1: Ed25519 d → x (RFC 8032 §5.1.5); RFC 8037 A.6 /
        // RFC 7748 §6.1: X25519 d → x = X25519(d, 9) (RFC 7748 §6.1).
        for crv in OKP_CURVES {
            let published = published_okp_key(crv);
            let mut fixed = FixedRng::new(okp_d(&published));
            let jwk = generate_okp(crv, &mut CryptoRngAdapter::fixed(&mut fixed)).unwrap();
            assert_eq!(fixed.remaining(), 0);
            assert_eq!(*jwk.to_json(), *published.to_json(), "{crv:?}");
        }
    }

    #[test]
    fn a_generated_ed25519_key_signs_and_verifies() {
        // Sanity check through ed25519-dalek (RFC 8032 §5.1.6, §5.1.7).
        use ed25519_dalek::{Signer, Verifier};
        let jwk = generate(KeySpec::Okp(OkpCurve::Ed25519)).unwrap();
        let d: [u8; 32] = okp_d(&jwk).try_into().unwrap();
        let x: [u8; 32] = okp_key(&jwk).x().try_into().unwrap();
        let signature = ed25519_dalek::SigningKey::from_bytes(&d).sign(b"polyjose");
        let verifying = ed25519_dalek::VerifyingKey::from_bytes(&x).unwrap();
        assert!(verifying.verify(b"polyjose", &signature).is_ok());
        assert!(verifying.verify(b"polyjosE", &signature).is_err());
    }

    #[test]
    fn okp_fails_closed_on_rng_failure() {
        for crv in OKP_CURVES {
            assert_eq!(
                generate_okp(
                    crv,
                    &mut CryptoRngAdapter::failing(getrandom::Error::UNSUPPORTED)
                )
                .unwrap_err(),
                Error::RandomnessUnavailable
            );
            let mut fixed = FixedRng::new([0x5Au8; 31]);
            assert_eq!(
                generate_okp(crv, &mut CryptoRngAdapter::fixed(&mut fixed)).unwrap_err(),
                Error::RandomnessUnavailable
            );
        }
    }

    #[test]
    fn debug_of_a_generated_okp_key_redacts_d() {
        for crv in OKP_CURVES {
            let jwk = generate(KeySpec::Okp(crv)).unwrap();
            let debug = format!("{jwk:?}");
            assert!(debug.contains(r#"d: "<redacted>""#), "{debug}");
            assert!(!debug.contains(&b64url_encode(&okp_d(&jwk))));
        }
    }

    /// What `generate_for(alg)` must produce: plan.md's table.
    #[derive(Debug, PartialEq)]
    enum Expect {
        Key(KeySpec),
        CurveRequired,
        Unsupported,
    }

    fn expected(alg: &JoseAlg) -> Expect {
        use Expect::{CurveRequired, Key, Unsupported};
        let oct = |bytes| Key(KeySpec::Oct { bytes });
        match alg.clone() {
            // RFC 7518 §3.2: a key of the hash output size.
            JoseAlg::Signing(SigningAlg::HS256) => oct(32),
            JoseAlg::Signing(SigningAlg::HS384) => oct(48),
            JoseAlg::Signing(SigningAlg::HS512) => oct(64),
            JoseAlg::Signing(SigningAlg::ES256) => Key(KeySpec::Ec(EcCurve::P256)),
            JoseAlg::Signing(SigningAlg::ES384) => Key(KeySpec::Ec(EcCurve::P384)),
            JoseAlg::Signing(SigningAlg::ES512) => Key(KeySpec::Ec(EcCurve::P521)),
            JoseAlg::Signing(SigningAlg::ES256K) => Key(KeySpec::Ec(EcCurve::Secp256k1)),
            JoseAlg::Signing(SigningAlg::EdDSA | SigningAlg::Ed25519) => {
                Key(KeySpec::Okp(OkpCurve::Ed25519))
            }
            // RFC 7518 §4.4, §4.7.
            JoseAlg::KeyMgmt(KeyMgmtAlg::A128KW | KeyMgmtAlg::A128GCMKW) => oct(16),
            JoseAlg::KeyMgmt(KeyMgmtAlg::A192KW | KeyMgmtAlg::A192GCMKW) => oct(24),
            JoseAlg::KeyMgmt(KeyMgmtAlg::A256KW | KeyMgmtAlg::A256GCMKW) => oct(32),
            JoseAlg::KeyMgmt(
                KeyMgmtAlg::EcdhEs
                | KeyMgmtAlg::EcdhEsA128KW
                | KeyMgmtAlg::EcdhEsA192KW
                | KeyMgmtAlg::EcdhEsA256KW,
            ) => CurveRequired,
            // RFC 7518 §5.3, §5.2.3–§5.2.5.
            JoseAlg::ContentEnc(ContentEncAlg::A128GCM) => oct(16),
            JoseAlg::ContentEnc(ContentEncAlg::A192GCM) => oct(24),
            JoseAlg::ContentEnc(ContentEncAlg::A256GCM) => oct(32),
            JoseAlg::ContentEnc(ContentEncAlg::A128CbcHs256) => oct(32),
            JoseAlg::ContentEnc(ContentEncAlg::A192CbcHs384) => oct(48),
            JoseAlg::ContentEnc(ContentEncAlg::A256CbcHs512) => oct(64),
            // RS*/PS*/RSA-OAEP-256 (ADR 0021), PBES2-* (no passwords),
            // dir (size depends on enc), none, and every unknown value.
            _ => Unsupported,
        }
    }

    /// Every known `alg` and `enc`, plus the registered names polyjose
    /// keeps as `Unknown` (RSA-OAEP, RSA1_5) and an unregistered one.
    fn every_alg() -> Vec<JoseAlg> {
        let mut all: Vec<JoseAlg> = SigningAlg::KNOWN.iter().cloned().map(Into::into).collect();
        all.extend(KeyMgmtAlg::KNOWN.iter().cloned().map(JoseAlg::from));
        all.extend(ContentEncAlg::KNOWN.iter().cloned().map(JoseAlg::from));
        all.push(KeyMgmtAlg::from("RSA-OAEP").into());
        all.push(KeyMgmtAlg::from("RSA1_5").into());
        all.push(SigningAlg::from("HS1").into());
        all.push(ContentEncAlg::from("A512GCM").into());
        all
    }

    fn alg_str(alg: &JoseAlg) -> &str {
        match alg {
            JoseAlg::Signing(a) => a.as_str(),
            JoseAlg::KeyMgmt(a) => a.as_str(),
            JoseAlg::ContentEnc(a) => a.as_str(),
        }
    }

    /// The `KeySpec` that `jwk` is an instance of.
    fn spec_of(jwk: &Jwk) -> KeySpec {
        match jwk.material() {
            KeyMaterial::Oct(key) => KeySpec::Oct {
                bytes: key.k().len(),
            },
            KeyMaterial::Ec(key) => KeySpec::Ec(key.crv()),
            KeyMaterial::Okp(key) => KeySpec::Okp(key.crv()),
            other => panic!("generated an unexpected key type: {other:?}"),
        }
    }

    #[test]
    fn generate_for_follows_the_plan_table_and_sets_alg() {
        // plan.md `generate_for` mapping; RFC 8725 §3.1 / ADR 0007: the key
        // is bound to the requested algorithm by its `alg` member.
        let mut keys = 0;
        for alg in every_alg() {
            let got = generate_for(alg.clone());
            match expected(&alg) {
                Expect::Key(spec) => {
                    let jwk = got.unwrap_or_else(|e| panic!("{}: {e:?}", alg_str(&alg)));
                    assert_eq!(spec_of(&jwk), spec, "{}", alg_str(&alg));
                    assert!(!jwk.is_public());
                    let member = jwk.alg().map(|a| a.as_str().to_owned());
                    assert_eq!(member.as_deref(), Some(alg_str(&alg)));
                    // The alg member survives the JSON round trip.
                    let reparsed = Jwk::from_json(jwk.to_json().as_bytes()).unwrap();
                    assert_eq!(*reparsed.to_json(), *jwk.to_json());
                    keys += 1;
                }
                Expect::CurveRequired => assert_eq!(
                    got.unwrap_err(),
                    Error::InvalidKey("curve required"),
                    "{}",
                    alg_str(&alg)
                ),
                Expect::Unsupported => assert_eq!(
                    got.unwrap_err(),
                    Error::UnsupportedAlgorithm,
                    "{}",
                    alg_str(&alg)
                ),
            }
        }
        // 3 HS + 4 ES + 2 EdDSA/Ed25519 + 6 AES-KW/GCMKW + 6 enc.
        assert_eq!(keys, 21);
    }

    #[test]
    fn generate_for_rejects_what_it_cannot_generate() {
        // Spelled out for the record (plan.md, ADR 0021).
        for alg in [
            JoseAlg::from(SigningAlg::RS256),
            SigningAlg::PS512.into(),
            SigningAlg::None.into(),
            KeyMgmtAlg::RsaOaep256.into(),
            KeyMgmtAlg::from("RSA1_5").into(),
            KeyMgmtAlg::Pbes2Hs256A128KW.into(),
            KeyMgmtAlg::Dir.into(),
            SigningAlg::from("XS256").into(),
        ] {
            assert_eq!(generate_for(alg).unwrap_err(), Error::UnsupportedAlgorithm);
        }
        // ECDH-ES has no default curve (0005 Gate 1): the caller passes
        // KeySpec::Ec(crv) or KeySpec::Okp(X25519) to generate.
        assert_eq!(
            generate_for(KeyMgmtAlg::EcdhEs).unwrap_err(),
            Error::InvalidKey("curve required")
        );
    }

    #[test]
    fn generate_for_fails_closed_on_rng_failure() {
        for alg in [
            JoseAlg::from(SigningAlg::HS256),
            ContentEncAlg::A256GCM.into(),
            SigningAlg::ES256.into(),
            SigningAlg::EdDSA.into(),
        ] {
            assert_eq!(
                generate_for_with(
                    &alg,
                    &mut CryptoRngAdapter::failing(getrandom::Error::UNEXPECTED)
                )
                .unwrap_err(),
                Error::RandomnessUnavailable
            );
            let mut fixed = FixedRng::new([]);
            assert_eq!(
                generate_for_with(&alg, &mut CryptoRngAdapter::fixed(&mut fixed)).unwrap_err(),
                Error::RandomnessUnavailable
            );
        }
    }

    #[test]
    fn generate_for_es256_reproduces_a_published_key_with_its_alg() {
        // RFC 7517 A.2's P-256 d, bound to ES256 (RFC 7518 §3.4).
        let published = published_ec_key(EcCurve::P256);
        let mut fixed = FixedRng::new(ec_d(&published));
        let jwk = generate_for_with(
            &SigningAlg::ES256.into(),
            &mut CryptoRngAdapter::fixed(&mut fixed),
        )
        .unwrap();
        assert_eq!(ec_key(&jwk).x(), ec_key(&published).x());
        assert_eq!(ec_key(&jwk).y(), ec_key(&published).y());
        assert_eq!(ec_d(&jwk), ec_d(&published));
        assert_eq!(jwk.alg().map(|a| a.as_str()), Some("ES256"));
    }

    /// The private member (`k` or `d`) of a generated key.
    fn secret_of(jwk: &Jwk) -> Vec<u8> {
        match jwk.material() {
            KeyMaterial::Oct(key) => key.k().to_vec(),
            KeyMaterial::Ec(_) => ec_d(jwk),
            KeyMaterial::Okp(_) => okp_d(jwk),
            other => panic!("generated an unexpected key type: {other:?}"),
        }
    }

    #[test]
    fn consecutive_generations_differ() {
        // A sanity check only (no statistics, no timing): two draws from
        // the OS CSPRNG never repeat a 128-bit or longer secret.
        let mut specs = vec![KeySpec::Oct { bytes: 16 }];
        specs.extend(EC_CURVES.map(KeySpec::Ec));
        specs.extend(OKP_CURVES.map(KeySpec::Okp));
        for spec in specs {
            let first = generate(spec).unwrap();
            let second = generate(spec).unwrap();
            assert_ne!(secret_of(&first), secret_of(&second), "{spec:?}");
            assert_ne!(*first.to_json(), *second.to_json(), "{spec:?}");
        }
    }

    #[test]
    fn debug_of_a_generated_oct_key_redacts_k() {
        let jwk = generate_for(SigningAlg::HS256).unwrap();
        let debug = format!("{jwk:?}");
        assert!(debug.contains(r#"k: "<redacted>""#), "{debug}");
        assert!(!debug.contains(&b64url_encode(&oct_k(&jwk))));
    }

    #[test]
    fn ec_sampling_uses_nonzero_scalar_rejection_sampling() {
        // ADR 0018 §5, research.md §6: the one EC sampling call is
        // NonZeroScalar's, never SecretKey's (which can in principle yield
        // 0). The zero-block test above checks the behaviour; this pins the
        // call in the production half of this file.
        let source = include_str!("generate.rs");
        let production = &source[..source.find("#[cfg(test)]").unwrap()];
        assert_eq!(
            production
                .matches("NonZeroScalar::<C>::try_generate_from_rng(rng)")
                .count(),
            1
        );
        assert!(!production.contains("SecretKey::try_generate_from_rng("));
        assert!(!production.contains("SecretKey::<C>::try_generate_from_rng("));
        // No RNG impl here: rng.rs holds the crate's only one. The needle
        // is joined at run time so this file stays out of the audit grep.
        assert!(!production.contains(&["impl", "TryCryptoRng"].join(" ")));
    }
}
