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
use zeroize::Zeroizing;

use super::jwk_build;
use super::types::KeySpec;
use crate::error::{Error, Result};
use crate::jwk::Jwk;
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
        KeySpec::Ec(_) | KeySpec::Okp(_) => Err(Error::UnsupportedAlgorithm),
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
    use crate::jwk::{Jwk, KeyMaterial};
    use crate::rng::CryptoRngAdapter;
    use crate::rng::insecure_test_vectors::FixedRng;

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
}
