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

// ---- tester additions (T08 adversarial pass) ----

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// Random bytes forced to open with a final dynamic block (BFINAL = 1,
    /// BTYPE = 10): reaches the HLIT/HDIST/HCLEN, code-length-code and
    /// code-length-repeat paths on every case, which plain random bytes hit
    /// only one time in eight. Accept/reject must agree with the oracle.
    #[test]
    fn agree_on_random_dynamic_headers(mut input in prop::collection::vec(any::<u8>(), 1..512)) {
        input[0] = (input[0] & 0xF8) | 0b101;
        assert_agree(&input)?;
    }

    /// The same, for a non-final dynamic block followed by a fixed block.
    #[test]
    fn agree_on_random_nonfinal_dynamic_headers(mut input in prop::collection::vec(any::<u8>(), 1..512)) {
        input[0] = (input[0] & 0xF8) | 0b100;
        assert_agree(&input)?;
    }

    /// Multi-byte corruption confined to the first 64 bytes (the dynamic
    /// header and the first symbols) of a level-9 stream of text.
    #[test]
    fn agree_on_header_corruption(
        edits in prop::collection::vec((0usize..64, any::<u8>()), 1..6),
        repeat in 1usize..40,
    ) {
        let text = b"It was the best of times, it was the worst of times, ".repeat(repeat);
        let mut stream = compress_to_vec(&text, 9);
        for (at, byte) in edits {
            let i = at.min(stream.len() - 1);
            stream[i] = byte;
        }
        assert_agree(&stream)?;
    }

    /// Under an unlimited cap, the single allocation is never outgrown and
    /// the unreachable EXPANSION_BOUND guard never fires, on streams that
    /// reach the decode loop (dynamic prefix) and on corrupted real ones.
    #[test]
    fn expansion_bound_guard_never_fires(
        mut input in prop::collection::vec(any::<u8>(), 1..2048),
        mutate_real in any::<bool>(),
        repeat in 1usize..200,
        at in any::<prop::sample::Index>(),
        byte in any::<u8>(),
    ) {
        if mutate_real {
            let text = b"abcabcabcabd".repeat(repeat);
            input = compress_to_vec(&text, 6);
            let i = at.index(input.len());
            input[i] = byte;
        } else {
            input[0] = (input[0] & 0xF8) | 0b101;
        }
        let mut capacity = inflate::Capacity::default();
        let result = inflate::inflate_tracked(&input, usize::MAX, &mut capacity);
        prop_assert!(!matches!(result, Err(Error::InvalidFormat(EXPANSION_BOUND))));
        if let Ok(out) = &result {
            prop_assert!(out.len() <= inflate::max_expansion(input.len()));
        }
        prop_assert_eq!(capacity.last, capacity.initial);
    }
}

/// Stored blocks are the 8-bits-per-byte floor: 65,535 bytes in a block
/// plus a 5-byte header can never exceed the 1032:1 allocation, and many
/// empty or non-final stored blocks produce nothing.
#[test]
fn stored_blocks_and_tiny_blocks_stay_within_the_allocation() {
    let mut full = vec![1, 0xFF, 0xFF, 0x00, 0x00];
    full.extend(std::iter::repeat_n(7u8, 65_535));
    let mut capacity = inflate::Capacity::default();
    let out = inflate::inflate_tracked(&full, usize::MAX, &mut capacity).unwrap();
    assert_eq!(out.len(), 65_535);
    assert_eq!(capacity.last, capacity.initial);

    // 10,000 empty non-final stored blocks, then a final empty one.
    let mut tiny = Vec::new();
    for _ in 0..10_000 {
        tiny.extend_from_slice(&[0, 0, 0, 0xFF, 0xFF]);
    }
    tiny.extend_from_slice(&[1, 0, 0, 0xFF, 0xFF]);
    let mut capacity = inflate::Capacity::default();
    let out = inflate::inflate_tracked(&tiny, usize::MAX, &mut capacity).unwrap();
    assert!(out.is_empty());
    assert_eq!(capacity.last, capacity.initial);
    assert_eq!(inflate(&tiny, 0).unwrap().len(), 0);
}
