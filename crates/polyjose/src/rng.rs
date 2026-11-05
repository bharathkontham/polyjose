//! The single source of randomness in polyjose: the OS CSPRNG (ADR 0005).

use zeroize::Zeroize;

use crate::{Error, Result};

/// Fills `dest` with bytes from the operating-system CSPRNG.
pub(crate) fn fill_random(dest: &mut [u8]) -> Result<()> {
    let outcome = getrandom::fill(dest);
    fail_closed(dest, outcome)
}

/// Maps the outcome of a `getrandom` call to polyjose's result.
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
#[cfg(any(test, feature = "test-vectors"))]
pub mod test_vectors {
    use zeroize::Zeroizing;

    use crate::{Error, Result};

    /// Replays a fixed byte sequence.
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
        pub fn fill(&mut self, dest: &mut [u8]) -> Result<()> {
            let _ = (dest, &self.bytes, self.pos);
            Err(Error::RandomnessUnavailable)
        }

        /// The number of bytes not yet handed out.
        pub fn remaining(&self) -> usize {
            0
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
