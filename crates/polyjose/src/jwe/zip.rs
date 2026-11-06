//! JWE `zip: DEF` (RFC 7516 §4.1.3): raw DEFLATE (RFC 1951) of the
//! plaintext before encryption (§5.1 step 11) and inflation after the tag
//! is verified (§5.2 step 17), on polyjose's own bounded codec
//! (`crate::deflate`, ADR 0017). Only with the off-by-default `deflate`
//! feature; without it both functions fail with
//! [`Error::UnsupportedAlgorithm`]. Filled in by T15.

use zeroize::Zeroizing;

use crate::{Error, Result};

/// Compresses `plaintext` with raw DEFLATE (RFC 7516 §5.1 step 11).
///
/// # Errors
///
/// [`Error::UnsupportedAlgorithm`] without the `deflate` feature.
pub(crate) fn compress(_plaintext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    Err(Error::UnsupportedAlgorithm)
}

/// Inflates `compressed` (RFC 7516 §5.2 step 17), stopping as soon as the
/// output would exceed `max_len` (`DecryptPolicy::max_decompressed_len`,
/// ADR 0017). Ticks `test_counters::inflate_calls`.
///
/// # Errors
///
/// [`Error::UnsupportedAlgorithm`] without the `deflate` feature; an error
/// for malformed input or output over `max_len`, which `core` reports as
/// `DecryptionFailed`.
pub(crate) fn decompress(_compressed: &[u8], _max_len: usize) -> Result<Zeroizing<Vec<u8>>> {
    Err(Error::UnsupportedAlgorithm)
}
