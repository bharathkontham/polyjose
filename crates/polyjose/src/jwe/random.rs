//! Where JWE draws its random values from (RFC 7516 §5.1, ADR 0005).
//!
//! Every random value of a JWE (the CEK, the content IV, ephemeral keys,
//! salts, key-wrapping IVs) is drawn through a [`RandomSource`]. Production
//! code passes [`OsRandom`], the OS CSPRNG through
//! [`crate::rng::fill_random`]. polyjose's own tests and the off-by-default
//! `insecure-test-vectors` feature can pass an explicit
//! `insecure_test_vectors::FixedRng` instead, to reproduce the RFC 7516
//! Appendix A and RFC 7520 §5 outputs byte for byte. There is no global or
//! thread-local switch (ADR 0041 §3): the source is always a parameter.
//!
//! Primitives that take a `rand_core` RNG (the RSA-OAEP seed, the ECDH
//! ephemeral scalar) get one for the same source from
//! [`RandomSource::crypto_rng`], the crate's single
//! [`CryptoRngAdapter`]. Both paths consume one stream, so the draw order
//! below holds whichever path a family uses.
//!
//! # Draw order
//!
//! Encryption follows RFC 7516 §5.1, and a `FixedRng` vector supplies its
//! bytes in exactly this order:
//!
//! 1. The CEK (§5.1 step 2), `cek_len(enc)` bytes, once per message, when
//!    the mode needs a random CEK: key encryption, key wrapping and key
//!    agreement with key wrapping (RFC 7516 §2). `dir` and ECDH-ES draw
//!    none (§5.1 steps 5–6).
//! 2. For each recipient in order (§5.1 step 8), what its algorithm needs:
//!    - ECDH-ES on P-256/384/521: the ephemeral private key (§5.1 step 3,
//!      RFC 7518 §4.6), from the crate-wide `NonZeroScalar` generator
//!      through [`RandomSource::crypto_rng`] (rejection sampling: the
//!      bytes it consumes per attempt are the field size);
//!    - ECDH-ES on X25519: 32 bytes for the ephemeral secret (RFC 7748 §6.1,
//!      RFC 8037 §3.2);
//!    - PBES2: the salt input `p2s`, 16 bytes unless the recipient asks for
//!      another length of at least 8 (RFC 7518 §4.8.1.1);
//!    - A*GCMKW: the 96-bit key-wrapping IV (RFC 7518 §4.7.1.1);
//!    - RSA-OAEP-256: the OAEP seed (RFC 8017 §7.1.1), through
//!      [`RandomSource::crypto_rng`].
//! 3. The content IV (§5.1 step 9): 12 bytes for A*GCM (RFC 7518 §5.3),
//!    16 for A*CBC-HS* (RFC 7518 §5.2.2.1).

use crate::Result;
#[cfg(any(test, feature = "insecure-test-vectors"))]
use crate::rng::insecure_test_vectors::FixedRng;
use crate::rng::{self, CryptoRngAdapter};

/// A source of the random values JWE encryption needs (see the module
/// documentation for the draw order).
///
/// Implemented by [`OsRandom`] and, in polyjose's own tests and with the
/// `insecure-test-vectors` feature, by `FixedRng`. No other implementation
/// may exist (ADR 0005).
pub(crate) trait RandomSource {
    /// Fills `dst` with the next `dst.len()` bytes of the source.
    ///
    /// # Errors
    ///
    /// [`crate::Error::RandomnessUnavailable`] if the source cannot supply
    /// them; `dst` is then zeroed (ADR 0005: fail closed).
    fn fill(&mut self, dst: &mut [u8]) -> Result<()>;

    /// A `rand_core` `TryRng + TryCryptoRng` drawing from this same source,
    /// for primitives that take one (the RSA-OAEP seed, the ECDH ephemeral
    /// scalar). Its draws continue the stream [`RandomSource::fill`] reads.
    fn crypto_rng(&mut self) -> CryptoRngAdapter<'_>;
}

/// The OS CSPRNG (ADR 0005), the only source in production code.
pub(crate) struct OsRandom;

impl RandomSource for OsRandom {
    fn fill(&mut self, dst: &mut [u8]) -> Result<()> {
        rng::fill_random(dst)
    }

    fn crypto_rng(&mut self) -> CryptoRngAdapter<'_> {
        CryptoRngAdapter::os()
    }
}

/// A fixed byte sequence a test passes explicitly to reproduce published
/// vectors (ADR 0005, ADR 0041 §3). It replays its bytes in order, once,
/// and fails closed when they run out.
#[cfg(any(test, feature = "insecure-test-vectors"))]
impl RandomSource for FixedRng {
    fn fill(&mut self, dst: &mut [u8]) -> Result<()> {
        FixedRng::fill(self, dst)
    }

    fn crypto_rng(&mut self) -> CryptoRngAdapter<'_> {
        CryptoRngAdapter::fixed(self)
    }
}

#[cfg(test)]
mod tests {
    use p256::elliptic_curve::rand_core::TryRng;

    use super::*;
    use crate::Error;

    #[test]
    fn os_bytes_differ_between_two_draws() {
        // 256 bits: equal draws are a 2^-256 event, not flakiness.
        let source: &mut dyn RandomSource = &mut OsRandom;
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        assert_eq!(source.fill(&mut a), Ok(()));
        assert_eq!(source.fill(&mut b), Ok(()));
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
        let mut c = [0u8; 32];
        assert_eq!(source.crypto_rng().try_fill_bytes(&mut c), Ok(()));
        assert_ne!(c, a);
        assert_ne!(c, b);
    }

    #[test]
    fn fixed_bytes_replay_in_order() {
        let mut fixed = FixedRng::new([1u8, 2, 3, 4, 5, 6]);
        let source: &mut dyn RandomSource = &mut fixed;
        let (mut cek, mut iv) = ([0u8; 2], [0u8; 4]);
        assert_eq!(source.fill(&mut cek), Ok(()));
        assert_eq!(source.fill(&mut iv), Ok(()));
        assert_eq!((cek, iv), ([1, 2], [3, 4, 5, 6]));
        assert_eq!(fixed.remaining(), 0);
    }

    #[test]
    fn fixed_source_fails_closed_when_exhausted() {
        // Never repeat or pad: a reused AES-GCM IV breaks JWE
        // (RFC 7518 §8.4). The output is zeroed and nothing is consumed.
        let mut fixed = FixedRng::new([7u8, 8, 9]);
        let source: &mut dyn RandomSource = &mut fixed;
        let mut too_long = [0xA5u8; 4];
        assert_eq!(
            source.fill(&mut too_long),
            Err(Error::RandomnessUnavailable)
        );
        assert_eq!(too_long, [0u8; 4]);
        let mut rest = [0u8; 3];
        assert_eq!(source.fill(&mut rest), Ok(()));
        assert_eq!(rest, [7, 8, 9]);
        assert_eq!(
            source.crypto_rng().try_fill_bytes(&mut [0u8; 1]),
            Err(Error::RandomnessUnavailable)
        );
    }

    #[test]
    fn crypto_rng_continues_the_same_fixed_stream() {
        // A family that draws through `crypto_rng` (RSA-OAEP, the ECDH
        // scalar) consumes the injected bytes at the position `fill` left,
        // so one vector feeds both paths in the documented order.
        let mut fixed = FixedRng::new([1u8, 2, 3, 4, 5, 6, 7, 8]);
        let source: &mut dyn RandomSource = &mut fixed;
        let mut cek = [0u8; 2];
        assert_eq!(source.fill(&mut cek), Ok(()));
        let mut seed = [0u8; 3];
        assert_eq!(source.crypto_rng().try_fill_bytes(&mut seed), Ok(()));
        let mut iv = [0u8; 3];
        assert_eq!(source.fill(&mut iv), Ok(()));
        assert_eq!((cek, seed, iv), ([1, 2], [3, 4, 5], [6, 7, 8]));
        assert_eq!(fixed.remaining(), 0);
    }
}
