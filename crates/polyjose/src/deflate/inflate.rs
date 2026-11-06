//! The bounded inflater (RFC 1951 §3.2).

use zeroize::Zeroizing;

use crate::{Error, Result};

/// Inflates `input`, recording the output buffer's peak capacity in `peak`.
pub(super) fn inflate_tracked(
    _input: &[u8],
    _max_output: usize,
    _peak: &mut usize,
) -> Result<Zeroizing<Vec<u8>>> {
    Err(Error::UnsupportedAlgorithm)
}
