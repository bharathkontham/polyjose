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
