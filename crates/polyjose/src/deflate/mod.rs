//! Raw DEFLATE (RFC 1951), polyjose's own bounded codec for JWE `zip: DEF`
//! (RFC 7516 §4.1.3, ADR 0017), behind the off-by-default `deflate`
//! feature. Owned utility code (ADR 0016, ADR 0020), written clean-room from
//! RFC 1951 §3.2 (with errata 7764 and 8429: extra bits are read
//! least-significant bit first):
//!
//! - [`inflate()`] fails as soon as the output would exceed its cap, and
//!   rejects every RFC 1951 §3.2 structural error;
//! - [`deflate()`] emits a valid RFC 1951 stream (stored and fixed-Huffman
//!   blocks, bounded LZ77).
//!
//! Both are total functions of their input (no panics, no `unsafe`), and the
//! module depends only on [`crate::Error`] and `zeroize`, so feature 0012 can
//! fuzz `inflate(&[u8], usize)` directly by re-exporting it from `lib.rs`
//! under `#[cfg(fuzzing)]`.
//!
//! Errors are [`crate::Error::InvalidFormat`] with a fixed detail naming the rule
//! (never the input). The JWE layer reports every one of them as
//! `DecryptionFailed` (RFC 7516 §5.2 step 17, ADR 0017 §1).

use zeroize::Zeroizing;

use crate::Result;

mod bits;
#[cfg(test)]
mod differential;
mod encode;
mod huffman;
mod inflate;
#[cfg(test)]
mod tests;

/// The input ended inside a block (RFC 1951 §3.2.3: every stream ends with
/// a block whose BFINAL bit is set).
const TRUNCATED: &str = "deflate: truncated input";
/// Code lengths that assign more codes than the code space holds, so they
/// are not a prefix code (RFC 1951 §3.2.2).
const OVERSUBSCRIBED_CODE: &str = "deflate: over-subscribed Huffman code";
/// Code lengths that leave code space unused, other than the distance-code
/// cases RFC 1951 §3.2.7 allows.
const INCOMPLETE_CODE: &str = "deflate: incomplete Huffman code";
/// A bit sequence that is no code of the table (the unused code of a single
/// distance code, RFC 1951 §3.2.7), or a code length outside 0–15.
const INVALID_CODE: &str = "deflate: invalid Huffman code";
/// BTYPE 11 (RFC 1951 §3.2.3: "reserved (error)").
const RESERVED_BLOCK_TYPE: &str = "deflate: reserved block type 11";
/// A stored block whose NLEN is not the one's complement of LEN (RFC 1951
/// §3.2.4).
const STORED_LENGTH_MISMATCH: &str = "deflate: stored block NLEN is not the complement of LEN";
/// A distance reaching before the start of the output (RFC 1951 §3.2.5).
const DISTANCE_TOO_FAR: &str = "deflate: distance beyond the output so far";
/// Literal/length symbol 286 or 287 (RFC 1951 §3.2.6: they "will never
/// actually occur in the compressed data").
const INVALID_LENGTH_SYMBOL: &str = "deflate: literal/length symbol 286 or 287";
/// Distance symbol 30 or 31 (RFC 1951 §3.2.6).
const INVALID_DISTANCE_SYMBOL: &str = "deflate: distance symbol 30 or 31";
/// HLIT above 286: more literal/length codes than RFC 1951 §3.2.5 defines.
const TOO_MANY_LENGTH_CODES: &str = "deflate: HLIT above 286";
/// HDIST above 30: more distance codes than RFC 1951 §3.2.5 defines.
const TOO_MANY_DISTANCE_CODES: &str = "deflate: HDIST above 30";
/// Code-length symbol 16 with no previous length to repeat (RFC 1951
/// §3.2.7).
const REPEAT_WITHOUT_PREVIOUS: &str = "deflate: repeat code 16 with no previous length";
/// Code lengths running past HLIT + HDIST (RFC 1951 §3.2.7).
const REPEAT_OVERRUN: &str = "deflate: code lengths overrun HLIT + HDIST";
/// A literal/length code without end-of-block symbol 256 (RFC 1951 §3.2.5,
/// §3.2.7).
const MISSING_END_OF_BLOCK: &str = "deflate: missing end-of-block code";
/// A literal/length code with a single one-bit code, which can only be
/// end-of-block: incomplete, and RFC 1951 §3.2.7 makes the one-code
/// exception for the distance code only (research.md §2.7). zlib-derived
/// decoders accept it; it has its own detail so the differential tests can
/// name this one deliberate divergence exactly.
const SINGLE_LENGTH_CODE: &str = "deflate: literal/length code with a single code";
/// The output would exceed the caller's cap (ADR 0017 §1).
const OUTPUT_LIMIT: &str = "deflate: output exceeds the limit";
/// The output buffer could not be allocated.
const OUTPUT_ALLOCATION: &str = "deflate: output allocation failed";
/// A length/distance pair in a block that declared no distance codes
/// (RFC 1951 §3.2.7: "the data is all literals").
const NO_DISTANCE_CODES: &str = "deflate: distance in a block with no distance codes";

/// Inflates the raw DEFLATE stream `input` (RFC 1951 §3.2), producing at
/// most `max_output` bytes.
///
/// Decoding stops at the end of the block whose BFINAL bit is set (RFC 1951
/// §3.2.3); any bytes after it are ignored. The output buffer grows with the
/// output and its capacity never exceeds `max_output`; nothing else is
/// allocated on the heap. Total for every input: no panic, no `unsafe`.
///
/// # Errors
///
/// [`crate::Error::InvalidFormat`] for a truncated stream or any RFC 1951 §3.2
/// structural error (reserved BTYPE, LEN/NLEN mismatch, a distance before
/// the start of the output, symbols 286/287 or distances 30/31, HLIT above
/// 286 or HDIST above 30, a bad code-length repeat, an over-subscribed or
/// incomplete Huffman code, a missing end-of-block code), and as soon as the
/// output would exceed `max_output`.
pub(crate) fn inflate(input: &[u8], max_output: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut peak = 0;
    inflate::inflate_tracked(input, max_output, &mut peak)
}

/// Compresses `input` into a raw DEFLATE stream (RFC 1951 §3.2): stored
/// (§3.2.4) and fixed-Huffman (§3.2.6) blocks, with greedy LZ77 over a
/// bounded hash chain (ADR 0017 §2). The output is never larger than
/// `input` stored, plus 6 bytes per 65,535-byte block and 1.
///
/// # Errors
///
/// None: every input has a valid encoding. The `Result` keeps the shape
/// `jwe::zip` was written against.
pub(crate) fn deflate(input: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    Ok(encode::compress(input))
}
