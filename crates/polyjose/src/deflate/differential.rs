//! Differential tests against `miniz_oxide`, a black-box dev-dependency
//! oracle (ADR 0016 §5, ADR 0017 §4): never read to write the codec, only
//! called. ADR 0008 layer 2: at most 1,000 cases per property.
//!
//! - `miniz_oxide` inflates our [`deflate()`] output back to the input;
//! - our [`inflate()`] inverts `miniz_oxide`'s compressor at levels 0–9;
//! - on random and on corrupted streams, both accept or both reject, with
//!   equal output when both accept.
//!
//! The one deliberate divergence: a dynamic block whose literal/length code
//! is a single one-bit end-of-block code. `miniz_oxide`, like zlib, accepts
//! it; RFC 1951 §3.2.7 allows a single code only for distances, so we reject
//! it with [`SINGLE_LENGTH_CODE`] (research.md §2.7). The agreement
//! properties allow exactly that detail and nothing else.

use miniz_oxide::deflate::compress_to_vec;
use miniz_oxide::inflate::{decompress_to_vec, decompress_to_vec_with_limit};
use proptest::prelude::*;

use super::*;
use crate::Error;

/// A cap neither side reaches on these inputs (at DEFLATE's ~1032:1
/// ceiling, 16 KiB of input describes under 17 MiB).
const LIMIT: usize = 32 << 20;

/// Inputs worth compressing: random bytes, a small alphabet, and repeated
/// chunks (long matches, distances up to the window).
fn plaintext() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        prop::collection::vec(any::<u8>(), 0..2048),
        prop::collection::vec(0u8..4, 0..8192),
        (prop::collection::vec(any::<u8>(), 1..300), 1usize..120)
            .prop_map(|(chunk, n)| chunk.repeat(n)),
    ]
}

/// Asserts that we and the oracle agree on `input`.
fn assert_agree(input: &[u8]) -> std::result::Result<(), TestCaseError> {
    let ours = inflate(input, LIMIT);
    let theirs = decompress_to_vec_with_limit(input, LIMIT);
    match (&ours, &theirs) {
        (Ok(a), Ok(b)) => prop_assert_eq!(&a[..], &b[..]),
        (Err(_), Err(_)) => {}
        (Err(Error::InvalidFormat(SINGLE_LENGTH_CODE)), Ok(_)) => {}
        _ => prop_assert!(
            false,
            "disagree: ours {:?}, miniz {:?}",
            ours.as_ref().map(|v| v.len()),
            theirs.as_ref().map(|v| v.len()).map_err(|e| e.status)
        ),
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// RFC 1951 conformance of the encoder: an independent inflater
    /// recovers the input.
    #[test]
    fn miniz_inflates_our_deflate(input in plaintext()) {
        let compressed = deflate(&input).unwrap();
        prop_assert_eq!(decompress_to_vec(&compressed).unwrap(), input);
    }

    /// RFC 1951 coverage of the decoder: streams from an independent
    /// encoder at every level (0 stored, 1 fast, up to 9 with dynamic
    /// Huffman blocks) inflate to the input.
    #[test]
    fn we_inflate_miniz_at_every_level(input in plaintext()) {
        for level in 0..=9u8 {
            let compressed = compress_to_vec(&input, level);
            let out = inflate(&compressed, input.len()).unwrap();
            prop_assert_eq!(&out[..], &input[..], "level {}", level);
        }
    }

    /// Accept/reject agreement on random bytes.
    #[test]
    fn agree_on_random_bytes(input in prop::collection::vec(any::<u8>(), 0..2048)) {
        assert_agree(&input)?;
    }

    /// Accept/reject agreement on corrupted valid streams, which reach the
    /// dynamic-header and code-length paths random bytes rarely do: one bit
    /// flipped, one byte overwritten, or the stream truncated.
    #[test]
    fn agree_on_corrupted_streams(
        input in plaintext(),
        level in 0..=9u8,
        at in any::<prop::sample::Index>(),
        bit in 0..8u32,
        byte in any::<u8>(),
        kind in 0..3u8,
    ) {
        let mut stream = compress_to_vec(&input, level);
        let i = at.index(stream.len());
        match kind {
            0 => stream[i] ^= 1 << bit,
            1 => stream[i] = byte,
            _ => stream.truncate(i),
        }
        assert_agree(&stream)?;
    }
}

/// The empty input through the oracle's compressor at every level.
#[test]
fn we_inflate_miniz_empty_input() {
    for level in 0..=9u8 {
        let compressed = compress_to_vec(b"", level);
        assert!(inflate(&compressed, 0).unwrap().is_empty(), "level {level}");
    }
}
