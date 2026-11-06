//! X25519 (RFC 7748) for ECDH-ES with OKP keys (RFC 8037 §3.2), on
//! `x25519-dalek`. Filled in by T07.

use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use super::random::RandomSource;
use crate::{Error, Result};

/// A fresh ephemeral key pair (RFC 7518 §4.6): 32 bytes drawn from `rng`
/// into `StaticSecret::from` (RFC 7748 §6.1; clamping is the primitive's),
/// and its public key.
///
/// # Errors
///
/// [`Error::RandomnessUnavailable`] if `rng` fails.
pub(crate) fn generate(_rng: &mut dyn RandomSource) -> Result<(StaticSecret, PublicKey)> {
    Err(Error::UnsupportedAlgorithm)
}

/// The X25519 shared secret of `secret` and `public` (RFC 7748 §6.1),
/// rejecting an all-zero result (a low-order `public`) in constant time
/// with `SharedSecret::was_contributory`. Ticks
/// `test_counters::ecdh_agreements`.
///
/// # Errors
///
/// An error for an all-zero shared secret; JWE decrypt maps it to
/// `DecryptionFailed`.
pub(crate) fn agree(_secret: &StaticSecret, _public: &PublicKey) -> Result<Zeroizing<[u8; 32]>> {
    Err(Error::UnsupportedAlgorithm)
}
