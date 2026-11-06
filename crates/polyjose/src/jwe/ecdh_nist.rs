//! ECDH on P-256, P-384 and P-521 for ECDH-ES (RFC 7518 §4.6), on the
//! `ecdh` feature of the pinned curve crates. Filled in by T13.
//!
//! The functions are generic over the curve, so `C` is `p256::NistP256`,
//! `p384::NistP384` or `p521::NistP521`.

use p256::elliptic_curve::{CurveArithmetic, PublicKey, SecretKey};
use zeroize::Zeroizing;

use super::random::RandomSource;
use crate::{Error, Result};

/// A fresh ephemeral key pair (RFC 7518 §4.6: one per key agreement),
/// from the crate-wide `NonZeroScalar` generator over
/// [`RandomSource::crypto_rng`].
///
/// # Errors
///
/// [`Error::RandomnessUnavailable`] if `rng` fails.
pub(crate) fn generate<C: CurveArithmetic>(
    _rng: &mut dyn RandomSource,
) -> Result<(SecretKey<C>, PublicKey<C>)> {
    Err(Error::UnsupportedAlgorithm)
}

/// The ECDH shared secret Z of `secret` and `public`: the x-coordinate of
/// the shared point, at the full field length (RFC 7518 §4.6.2,
/// SP 800-56A §5.7.1.2). Ticks `test_counters::ecdh_agreements`.
///
/// # Errors
///
/// An error if the agreement fails; JWE decrypt maps it to
/// `DecryptionFailed`.
pub(crate) fn agree<C: CurveArithmetic>(
    _secret: &SecretKey<C>,
    _public: &PublicKey<C>,
) -> Result<Zeroizing<Vec<u8>>> {
    Err(Error::UnsupportedAlgorithm)
}
