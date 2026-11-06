//! The single source of randomness in polyjose: the OS CSPRNG (ADR 0005).
//!
//! JOSE is only as strong as its random values. Keys need enough entropy
//! (RFC 7515 §10.1); JWE also draws Content Encryption Keys and IVs from it
//! (RFC 7516 §11.1, RFC 7518 §8.9), AES-CBC needs a random 128-bit IV
//! (RFC 7518 §5.2.2.1), an AES-GCM IV must never repeat under one key
//! (RFC 7518 §8.4), ECDH-ES needs a fresh ephemeral key per operation
//! (RFC 7518 §4.6) and PBES2 a fresh random salt per encryption
//! (RFC 7518 §4.8.1.1).
//!
//! Every random byte comes from [`fill_random`], which calls the OS CSPRNG
//! through `getrandom` 0.4 and fails closed: there is no fallback source, no
//! retry loop of our own and no switchable source in production code. On
//! `wasm32-unknown-unknown` the backend is `crypto.getRandomValues`, which
//! the WASM binding selects with getrandom's `wasm_js` crate feature (see
//! `bindings/wasm/Cargo.toml`).
//!
//! The only other byte source is `insecure_test_vectors::FixedRng`, compiled
//! for polyjose's own tests and behind the off-by-default
//! `insecure-test-vectors` feature, which no binding may enable
//! (`scripts/check-test-vectors-off.sh`).

use zeroize::Zeroize;

use crate::{Error, Result};

/// Fills `dest` with bytes from the operating-system CSPRNG (ADR 0005).
///
/// Use it for every key, CEK, IV, salt and ephemeral key (RFC 7515 §10.1,
/// RFC 7516 §11.1, RFC 7518 §8.9).
///
/// # Errors
///
/// [`Error::RandomnessUnavailable`] if the OS source fails. The call is
/// made once; getrandom itself only retries interrupted system calls. On
/// failure `dest` is zeroed, so no partial output survives, and the error
/// carries no backend or OS detail.
pub(crate) fn fill_random(dest: &mut [u8]) -> Result<()> {
    let outcome = getrandom::fill(dest);
    fail_closed(dest, outcome)
}

/// Maps the outcome of a `getrandom` call to polyjose's result, failing
/// closed.
///
/// Any `getrandom::Error` becomes a detail-free
/// [`Error::RandomnessUnavailable`] (ADR 0005, ADR 0007) and `dest` is
/// zeroed. It is a separate pure function so tests can inject every
/// `getrandom::Error` without a switchable source in production code.
fn fail_closed(dest: &mut [u8], outcome: core::result::Result<(), getrandom::Error>) -> Result<()> {
    match outcome {
        Ok(()) => Ok(()),
        Err(_) => {
            dest.zeroize();
            Err(Error::RandomnessUnavailable)
        }
    }
}

/// Deterministic byte source for reproducing published test vectors.
///
/// **Never use this in production.** Its output is fixed by the caller and
/// is not random. It exists only so tests can reproduce outputs that depend
/// on "random" values, such as the CEKs and IVs of the RFC 7520 JWE
/// examples. Outside polyjose's own unit tests it exists only with the
/// off-by-default `insecure-test-vectors` cargo feature (ADR 0005), and
/// `scripts/check-test-vectors-off.sh` fails if any binding enables it.
///
/// ```
/// use polyjose::insecure_test_vectors::FixedRng;
///
/// let mut rng = FixedRng::new([0x01, 0x02, 0x03]);
/// let mut iv = [0u8; 2];
/// rng.fill(&mut iv)?;
/// assert_eq!(iv, [0x01, 0x02]);
/// assert!(rng.fill(&mut [0u8; 2]).is_err()); // only one byte is left
/// # Ok::<(), polyjose::Error>(())
/// ```
#[cfg(any(test, feature = "insecure-test-vectors"))]
pub mod insecure_test_vectors {
    use zeroize::{Zeroize, Zeroizing};

    use crate::{Error, Result};

    /// Replays a fixed byte sequence, in order and exactly once.
    ///
    /// It never wraps around or pads: a repeated IV would break AES-GCM
    /// (RFC 7518 §8.4), so running out is an error, just like a failing OS
    /// source. The bytes are zeroized on drop, since they become test keys.
    pub struct FixedRng {
        bytes: Zeroizing<Vec<u8>>,
        pos: usize,
    }

    impl FixedRng {
        /// Creates a source that hands out `bytes` in order, exactly once.
        pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
            Self {
                bytes: Zeroizing::new(bytes.into()),
                pos: 0,
            }
        }

        /// Fills `dest` with the next `dest.len()` bytes.
        ///
        /// # Errors
        ///
        /// [`Error::RandomnessUnavailable`] if fewer than `dest.len()` bytes
        /// are left. Nothing is consumed and `dest` is zeroed, matching the
        /// fail-closed behaviour of the OS source.
        pub fn fill(&mut self, dest: &mut [u8]) -> Result<()> {
            let next = self
                .pos
                .checked_add(dest.len())
                .and_then(|end| self.bytes.get(self.pos..end).map(|src| (src, end)));
            match next {
                Some((src, end)) => {
                    dest.copy_from_slice(src);
                    self.pos = end;
                    Ok(())
                }
                None => {
                    dest.zeroize();
                    Err(Error::RandomnessUnavailable)
                }
            }
        }

        /// The number of bytes not yet handed out.
        pub fn remaining(&self) -> usize {
            self.bytes.len().saturating_sub(self.pos)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn replays_bytes_in_order_across_calls() {
            let mut rng = FixedRng::new([1u8, 2, 3, 4, 5]);
            let (mut a, mut b) = ([0u8; 2], [0u8; 3]);
            assert_eq!(rng.fill(&mut a), Ok(()));
            assert_eq!(rng.fill(&mut b), Ok(()));
            assert_eq!((a, b), ([1, 2], [3, 4, 5]));
            assert_eq!(rng.remaining(), 0);
        }

        #[test]
        fn empty_request_consumes_nothing() {
            let mut rng = FixedRng::new([7u8]);
            assert_eq!(rng.fill(&mut []), Ok(()));
            assert_eq!(rng.remaining(), 1);
        }

        #[test]
        fn exhaustion_fails_closed_without_wrapping() {
            // Never repeat or pad: a reused AES-GCM IV breaks JWE
            // (RFC 7518 §8.4). Asking for more than is left is an error, the
            // output is zeroed and nothing is consumed.
            let mut rng = FixedRng::new([1u8, 2, 3]);
            let mut buf = [0xA5u8; 4];
            assert_eq!(rng.fill(&mut buf), Err(Error::RandomnessUnavailable));
            assert_eq!(buf, [0u8; 4]);
            assert_eq!(rng.remaining(), 3);
            let mut rest = [0u8; 3];
            assert_eq!(rng.fill(&mut rest), Ok(()));
            assert_eq!(rest, [1, 2, 3]);
            assert_eq!(rng.fill(&mut [0u8; 1]), Err(Error::RandomnessUnavailable));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_with_os_randomness() {
        // 256 bits: an all-zero or repeated output is a 2^-256 event, not flakiness.
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        assert_eq!(fill_random(&mut a), Ok(()));
        assert_eq!(fill_random(&mut b), Ok(()));
        assert_ne!(a, [0u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn empty_buffer_is_ok() {
        assert_eq!(fill_random(&mut []), Ok(()));
    }

    #[test]
    fn fills_every_chunk_of_a_large_buffer() {
        // Larger than the 65,536-byte `crypto.getRandomValues` limit that
        // getrandom chunks around on WASM; every 32-byte window must be filled.
        let mut buf = vec![0u8; 65_536 + 4_096];
        assert_eq!(fill_random(&mut buf), Ok(()));
        assert!(buf.chunks(32).all(|c| c.iter().any(|&b| b != 0)));
    }

    /// Every `getrandom::Error` a test can construct. OS errors (`errno`)
    /// can't be built outside getrandom; they take the same `Err(_)` arm.
    fn injected_errors() -> [getrandom::Error; 5] {
        [
            getrandom::Error::UNSUPPORTED,
            getrandom::Error::ERRNO_NOT_POSITIVE,
            getrandom::Error::UNEXPECTED,
            getrandom::Error::new_custom(0),
            getrandom::Error::new_custom(u16::MAX),
        ]
    }

    #[test]
    fn success_passes_through_untouched() {
        let mut buf = [0xA5u8; 16];
        assert_eq!(fail_closed(&mut buf, Ok(())), Ok(()));
        assert_eq!(buf, [0xA5u8; 16]);
    }

    #[test]
    fn failure_leaves_no_partial_output() {
        // A backend may fail after writing part of `dest` (getrandom chunks
        // large requests); none of it may survive as if it were usable.
        for injected in injected_errors() {
            let mut buf = [0xA5u8; 16];
            assert!(fail_closed(&mut buf, Err(injected)).is_err());
            assert_eq!(buf, [0u8; 16], "{injected:?}");
        }
    }

    #[test]
    fn every_getrandom_error_maps_to_randomness_unavailable() {
        for injected in injected_errors() {
            let e = fail_closed(&mut [0u8; 4], Err(injected)).err();
            assert_eq!(e, Some(Error::RandomnessUnavailable), "{injected:?}");
        }
    }

    #[test]
    fn mapped_error_carries_no_backend_detail() {
        // getrandom's own message names the backend or OS error; ours must
        // not, and must not expose it as a cause either (ADR 0007).
        for injected in injected_errors() {
            let Err(e) = fail_closed(&mut [0u8; 4], Err(injected)) else {
                unreachable!("an injected error must fail");
            };
            assert_eq!(e.code(), "RandomnessUnavailable");
            assert_eq!(format!("{e:?}"), "RandomnessUnavailable");
            assert_eq!(e.to_string(), "randomness unavailable");
            assert!(!e.to_string().contains(&injected.to_string()));
            assert!(std::error::Error::source(&e).is_none());
        }
    }
}
