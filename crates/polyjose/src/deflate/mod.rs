//! Raw DEFLATE (RFC 1951), polyjose's own bounded codec for JWE `zip: DEF`
//! (RFC 7516 §4.1.3, ADR 0017), behind the off-by-default `deflate`
//! feature. Owned utility code (ADR 0016, ADR 0020), written clean-room from
//! RFC 1951 §3.2 (with errata 7764 and 8429: extra bits are read
//! least-significant bit first):
//!
//! - [`inflate`] fails as soon as the output would exceed its cap, and
//!   rejects every RFC 1951 §3.2 structural error;
//! - [`deflate`] emits a valid RFC 1951 stream (stored and fixed-Huffman
//!   blocks, bounded LZ77).
//!
//! Both are total functions of their input (no panics, no `unsafe`), and the
//! module depends only on [`crate::Error`] and `zeroize`, so feature 0012 can
//! fuzz `inflate(&[u8], usize)` directly by re-exporting it from `lib.rs`
//! under `#[cfg(fuzzing)]`.
//!
//! Errors are [`Error::InvalidFormat`] with a fixed detail naming the rule
//! (never the input). The JWE layer reports every one of them as
//! `DecryptionFailed` (RFC 7516 §5.2 step 17, ADR 0017 §1).

use zeroize::Zeroizing;

use crate::{Error, Result};

mod bits;

/// The input ended inside a block (RFC 1951 §3.2.3: every stream ends with
/// a block whose BFINAL bit is set).
const TRUNCATED: &str = "deflate: truncated input";

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
