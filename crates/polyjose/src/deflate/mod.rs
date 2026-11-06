//! Raw DEFLATE (RFC 1951), polyjose's own bounded codec for JWE `zip: DEF`
//! (RFC 7516 §4.1.3, ADR 0017), behind the off-by-default `deflate`
//! feature. Owned utility code (ADR 0016, ADR 0020), filled in by T08:
//!
//! - [`inflate`] fails as soon as the output would exceed its cap, and
//!   rejects every RFC 1951 §3.2 structural error;
//! - [`deflate`] emits a valid RFC 1951 stream (stored and fixed-Huffman
//!   blocks, bounded LZ77).
//!
//! Both are total functions of their input (no panics), so feature 0012
//! can fuzz `inflate(&[u8], usize)` directly.

use zeroize::Zeroizing;

use crate::{Error, Result};

/// Inflates the raw DEFLATE stream `input` (RFC 1951 §3.2), producing at
/// most `max_output` bytes.
///
/// # Errors
///
/// An error for a malformed or truncated stream, or one whose output would
/// exceed `max_output`.
pub(crate) fn inflate(_input: &[u8], _max_output: usize) -> Result<Zeroizing<Vec<u8>>> {
    Err(Error::UnsupportedAlgorithm)
}

/// Compresses `input` into a raw DEFLATE stream (RFC 1951 §3.2).
///
/// # Errors
///
/// None once implemented; the stub fails with
/// [`Error::UnsupportedAlgorithm`].
pub(crate) fn deflate(_input: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    Err(Error::UnsupportedAlgorithm)
}
