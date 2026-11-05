//! The single source of randomness in polyjose: the OS CSPRNG (ADR 0005).

use crate::{Error, Result};

/// Fills `dest` with bytes from the operating-system CSPRNG.
pub(crate) fn fill_random(dest: &mut [u8]) -> Result<()> {
    let _ = dest;
    Err(Error::RandomnessUnavailable)
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
}
