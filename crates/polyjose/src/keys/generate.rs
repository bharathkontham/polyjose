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
use super::types::KeySpec;
use crate::error::{Error, Result};
use crate::jwk::{EcCurve, Jwk};
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
        KeySpec::Okp(_) => Err(Error::UnsupportedAlgorithm),
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
    use crate::jwk::{EcCurve, EcKey, Jwk, KeyMaterial};
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
}
