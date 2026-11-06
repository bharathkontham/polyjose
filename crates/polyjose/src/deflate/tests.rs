//! Unit tests for [`super::inflate`]: valid streams of each block type, one
//! test per RFC 1951 structural error (research.md §2.7), and the output
//! cap. Streams are built bit by bit with the module's own writer, so each
//! test names exactly the field it breaks.

use super::bits::BitWriter;
use super::*;

/// A generous cap for tests that are not about the cap.
const CAP: usize = 1 << 20;

/// Builds a stream with `f`, zero-padding the last byte.
fn stream(f: impl FnOnce(&mut BitWriter<'_>)) -> Vec<u8> {
    let mut out = Vec::new();
    let mut w = BitWriter::new(&mut out);
    f(&mut w);
    w.finish();
    out
}

/// The error detail of a failed inflate.
fn err(input: &[u8]) -> &'static str {
    match inflate(input, CAP) {
        Err(Error::InvalidFormat(detail)) => detail,
        other => panic!("expected InvalidFormat, got {other:?}"),
    }
}

/// Block header: BFINAL then the 2-bit BTYPE (RFC 1951 §3.2.3).
fn header(w: &mut BitWriter<'_>, last: bool, btype: u32) {
    w.bits(u32::from(last), 1);
    w.bits(btype, 2);
}

/// A literal/length symbol in the fixed code (RFC 1951 §3.2.6).
fn fixed(w: &mut BitWriter<'_>, symbol: u32) {
    match symbol {
        0..=143 => w.code(0b0011_0000 + symbol, 8),
        144..=255 => w.code(0b1_1001_0000 + symbol - 144, 9),
        256..=279 => w.code(symbol - 256, 7),
        _ => w.code(0b1100_0000 + symbol - 280, 8),
    }
}

/// A fixed-code distance symbol: 5 bits (RFC 1951 §3.2.6).
fn fixed_distance(w: &mut BitWriter<'_>, symbol: u32) {
    w.code(symbol, 5);
}

/// Canonical codes for `lengths` (RFC 1951 §3.2.2), as (code, length).
fn canonical(lengths: &[u8]) -> Vec<(u32, u32)> {
    let mut count = [0u32; 16];
    for &l in lengths {
        count[usize::from(l)] += 1;
    }
    count[0] = 0;
    let mut next = [0u32; 16];
    let mut code = 0;
    for bits in 1..16 {
        code = (code + count[bits - 1]) << 1;
        next[bits] = code;
    }
    lengths
        .iter()
        .map(|&l| {
            let l = usize::from(l);
            let c = next[l];
            if l != 0 {
                next[l] += 1;
            }
            (c, l as u32)
        })
        .collect()
}

/// The order code-length code lengths are sent in (RFC 1951 §3.2.7).
const CL_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/// A complete code-length code: symbols 0–12 and 16–18, all of length 4.
fn cl_lengths() -> [u8; 19] {
    let mut l = [4u8; 19];
    l[13] = 0;
    l[14] = 0;
    l[15] = 0;
    l
}

/// One code-length instruction (RFC 1951 §3.2.7).
#[derive(Clone, Copy)]
enum Cl {
    /// A literal length 0–15.
    Len(u32),
    /// Symbol 16: repeat the previous length 3–6 times.
    Repeat(u32),
    /// Symbol 17: 3–10 zeros.
    Zeros3(u32),
    /// Symbol 18: 11–138 zeros.
    Zeros11(u32),
}

/// Writes a dynamic block header (RFC 1951 §3.2.7) after BFINAL/BTYPE:
/// HLIT, HDIST, all 19 code-length code lengths, then `instructions` coded
/// with that code-length code.
fn dynamic_header(
    w: &mut BitWriter<'_>,
    hlit: u32,
    hdist: u32,
    cl: &[u8; 19],
    instructions: &[Cl],
) {
    w.bits(hlit - 257, 5);
    w.bits(hdist - 1, 5);
    w.bits(19 - 4, 4);
    for &symbol in &CL_ORDER {
        w.bits(u32::from(cl[symbol]), 3);
    }
    let codes = canonical(cl);
    for &instruction in instructions {
        let (symbol, extra, extra_bits) = match instruction {
            Cl::Len(l) => (l as usize, 0, 0),
            Cl::Repeat(n) => (16, n - 3, 2),
            Cl::Zeros3(n) => (17, n - 3, 3),
            Cl::Zeros11(n) => (18, n - 11, 7),
        };
        let (code, len) = codes[symbol];
        w.code(code, len);
        w.bits(extra, extra_bits);
    }
}

/// Code-length instructions for a literal/length code where symbol 97
/// (`a`) and 256 (end of block) have length 1, and one distance code
/// (symbol 0, distance 1) of length 1: HLIT 257, HDIST 1.
fn minimal_instructions() -> Vec<Cl> {
    vec![
        Cl::Zeros11(97),
        Cl::Len(1), // 97
        Cl::Zeros11(138),
        Cl::Zeros11(20), // 98..=255
        Cl::Len(1),      // 256
        Cl::Len(1),      // distance 0
    ]
}

// ---- valid streams ----

/// RFC 1951 §3.2.4: a stored block copies LEN bytes verbatim.
#[test]
fn stored_block() {
    let input = stream(|w| {
        header(w, true, 0b00);
        w.align_to_byte();
        w.bytes(&[3, 0, 0xFC, 0xFF, b'a', b'b', b'c']);
    });
    assert_eq!(&inflate(&input, CAP).unwrap()[..], b"abc");
}

/// RFC 1951 §3.2.6: literals, a length/distance pair that overlaps its own
/// output, then end of block.
#[test]
fn fixed_block_with_overlapping_copy() {
    let input = stream(|w| {
        header(w, true, 0b01);
        fixed(w, u32::from(b'x'));
        fixed(w, u32::from(b'y'));
        // Length 10 is symbol 264 (no extra bits); distance 2 is symbol 1.
        fixed(w, 264);
        fixed_distance(w, 1);
        fixed(w, 256);
    });
    assert_eq!(&inflate(&input, CAP).unwrap()[..], b"xyxyxyxyxyxy");
}

/// RFC 1951 §3.2.7: a dynamic block with a single distance code of one bit.
#[test]
fn dynamic_block() {
    let input = stream(|w| {
        header(w, true, 0b10);
        dynamic_header(w, 257, 1, &cl_lengths(), &minimal_instructions());
        // Canonical codes: 97 -> 0, 256 -> 1.
        w.code(0, 1);
        w.code(0, 1);
        w.code(1, 1);
    });
    assert_eq!(&inflate(&input, CAP).unwrap()[..], b"aa");
}

/// RFC 1951 §3.2: blocks follow each other until BFINAL, and a distance may
/// reach back into an earlier block (§3.2.5: "a back-reference may refer to
/// a string in a previous block").
#[test]
fn multiple_blocks_share_the_window() {
    let input = stream(|w| {
        header(w, false, 0b00);
        w.align_to_byte();
        w.bytes(&[4, 0, 0xFB, 0xFF, b'a', b'b', b'c', b'd']);
        header(w, true, 0b01);
        // Length 4 is symbol 258; distance 4 is symbol 3.
        fixed(w, 258);
        fixed_distance(w, 3);
        fixed(w, 256);
    });
    assert_eq!(&inflate(&input, CAP).unwrap()[..], b"abcdabcd");
}

/// RFC 1951 §3.2.5: distance code 29 with all 13 extra bits set is 32768,
/// the largest distance, and length code 285 is 258.
#[test]
fn largest_distance_and_length() {
    let mut data = vec![0u8; 32768];
    data[0] = 7;
    let input = stream(|w| {
        header(w, false, 0b00);
        w.align_to_byte();
        w.bytes(&[0x00, 0x80, 0xFF, 0x7F]);
        w.bytes(&data);
        header(w, true, 0b01);
        fixed(w, 285);
        fixed_distance(w, 29);
        w.bits(0x1FFF, 13);
        fixed(w, 256);
    });
    let out = inflate(&input, CAP).unwrap();
    assert_eq!(out.len(), 32768 + 258);
    assert_eq!(&out[..32768], &data[..]);
    assert_eq!(&out[32768..], &data[..258]);
}

/// Bytes after the final block are not part of the stream (RFC 1951 §3.2.3:
/// BFINAL "is set if and only if this is the last block of the data set").
#[test]
fn ignores_bytes_after_the_final_block() {
    let mut input = stream(|w| {
        header(w, true, 0b01);
        fixed(w, u32::from(b'z'));
        fixed(w, 256);
    });
    input.extend_from_slice(b"trailing");
    assert_eq!(&inflate(&input, CAP).unwrap()[..], b"z");
}

// ---- RFC 1951 structural errors (research.md §2.7) ----

/// RFC 1951 §3.2.3: BTYPE 11 is "reserved (error)".
#[test]
fn rejects_btype_11() {
    let input = stream(|w| header(w, true, 0b11));
    assert_eq!(err(&input), RESERVED_BLOCK_TYPE);
}

/// RFC 1951 §3.2.4: NLEN "is the one's complement of LEN".
#[test]
fn rejects_stored_len_nlen_mismatch() {
    let input = stream(|w| {
        header(w, true, 0b00);
        w.align_to_byte();
        w.bytes(&[3, 0, 0xFD, 0xFF, b'a', b'b', b'c']);
    });
    assert_eq!(err(&input), STORED_LENGTH_MISMATCH);
}

/// RFC 1951 §3.2.5: a distance can only refer back into the output already
/// produced.
#[test]
fn rejects_distance_beyond_output() {
    let input = stream(|w| {
        header(w, true, 0b01);
        fixed(w, u32::from(b'a'));
        fixed(w, 257); // length 3
        fixed_distance(w, 1); // distance 2, but only 1 byte so far
        fixed(w, 256);
    });
    assert_eq!(err(&input), DISTANCE_TOO_FAR);
    let at_start = stream(|w| {
        header(w, true, 0b01);
        fixed(w, 257);
        fixed_distance(w, 0); // distance 1 with no output
    });
    assert_eq!(err(&at_start), DISTANCE_TOO_FAR);
}

/// RFC 1951 §3.2.6: literal/length values 286–287 "will never actually
/// occur in the compressed data".
#[test]
fn rejects_fixed_symbols_286_and_287() {
    for symbol in [286, 287] {
        let input = stream(|w| {
            header(w, true, 0b01);
            fixed(w, u32::from(b'a'));
            fixed(w, symbol);
            fixed_distance(w, 0);
            fixed(w, 256);
        });
        assert_eq!(err(&input), INVALID_LENGTH_SYMBOL, "symbol {symbol}");
    }
}

/// RFC 1951 §3.2.6: distance codes 30–31 "will never actually occur in the
/// compressed data".
#[test]
fn rejects_distance_codes_30_and_31() {
    for symbol in [30, 31] {
        let input = stream(|w| {
            header(w, true, 0b01);
            fixed(w, u32::from(b'a'));
            fixed(w, 257);
            fixed_distance(w, symbol);
            fixed(w, 256);
        });
        assert_eq!(err(&input), INVALID_DISTANCE_SYMBOL, "symbol {symbol}");
    }
}

/// RFC 1951 §3.2.5 defines 286 literal/length codes (0–285); HLIT counts
/// above 286 can only describe the unusable 286/287 (zlib practice).
#[test]
fn rejects_hlit_above_286() {
    for hlit in [287, 288] {
        let input = stream(|w| {
            header(w, true, 0b10);
            dynamic_header(w, hlit, 1, &cl_lengths(), &[]);
        });
        assert_eq!(err(&input), TOO_MANY_LENGTH_CODES, "HLIT {hlit}");
    }
}

/// RFC 1951 §3.2.5 defines 30 distance codes (0–29); HDIST counts above 30
/// can only describe the unusable 30/31 (zlib practice).
#[test]
fn rejects_hdist_above_30() {
    for hdist in [31, 32] {
        let input = stream(|w| {
            header(w, true, 0b10);
            dynamic_header(w, 257, hdist, &cl_lengths(), &[]);
        });
        assert_eq!(err(&input), TOO_MANY_DISTANCE_CODES, "HDIST {hdist}");
    }
}

/// RFC 1951 §3.2.7: code 16 copies "the previous code length", so it cannot
/// come first.
#[test]
fn rejects_repeat_code_16_first() {
    let input = stream(|w| {
        header(w, true, 0b10);
        dynamic_header(w, 257, 1, &cl_lengths(), &[Cl::Repeat(3)]);
    });
    assert_eq!(err(&input), REPEAT_WITHOUT_PREVIOUS);
}

/// RFC 1951 §3.2.7: the repeats fill exactly HLIT + HDIST code lengths; one
/// running past the end is an error.
#[test]
fn rejects_repeat_overrun() {
    // 257 + 1 = 258 lengths; 97 + 1 + 158 + 1 = 257 then 3 zeros overrun.
    let mut zeros = minimal_instructions();
    zeros.pop();
    zeros.push(Cl::Zeros3(3));
    let input = stream(|w| {
        header(w, true, 0b10);
        dynamic_header(w, 257, 1, &cl_lengths(), &zeros);
    });
    assert_eq!(err(&input), REPEAT_OVERRUN);
    // Code 16 overrunning, across the literal/length and distance lengths.
    let mut repeat = minimal_instructions();
    repeat.pop();
    repeat.push(Cl::Repeat(3));
    let input = stream(|w| {
        header(w, true, 0b10);
        dynamic_header(w, 257, 1, &cl_lengths(), &repeat);
    });
    assert_eq!(err(&input), REPEAT_OVERRUN);
    // Code 18 overrunning: 138 + 110 = 248, then 11 more of 258.
    let input = stream(|w| {
        header(w, true, 0b10);
        dynamic_header(
            w,
            257,
            1,
            &cl_lengths(),
            &[Cl::Zeros11(138), Cl::Zeros11(110), Cl::Zeros11(11)],
        );
    });
    assert_eq!(err(&input), REPEAT_OVERRUN);
}

/// RFC 1951 §3.2.2: over-subscribed lengths are not a prefix code: in the
/// code-length code, the literal/length code and the distance code.
#[test]
fn rejects_over_subscribed_codes() {
    let mut cl = cl_lengths();
    cl[13] = 4; // 17 codes of length 4
    let input = stream(|w| {
        header(w, true, 0b10);
        dynamic_header(w, 257, 1, &cl, &[]);
    });
    assert_eq!(err(&input), OVERSUBSCRIBED_CODE, "code-length code");

    let mut lit = minimal_instructions();
    lit[0] = Cl::Zeros11(96);
    lit.insert(1, Cl::Len(1)); // 96, 97 and 256 all of length 1
    let input = stream(|w| {
        header(w, true, 0b10);
        dynamic_header(w, 257, 1, &cl_lengths(), &lit);
    });
    assert_eq!(err(&input), OVERSUBSCRIBED_CODE, "literal/length code");

    let mut dist = minimal_instructions();
    dist.push(Cl::Len(1));
    dist.push(Cl::Len(1));
    let input = stream(|w| {
        header(w, true, 0b10);
        dynamic_header(w, 257, 3, &cl_lengths(), &dist);
    });
    assert_eq!(err(&input), OVERSUBSCRIBED_CODE, "distance code");
}

/// RFC 1951 §3.2.2 and §3.2.7: incomplete codes are rejected, except a
/// single one-bit distance code (accepted in [`dynamic_block`]) and no
/// distance codes at all.
#[test]
fn rejects_incomplete_codes() {
    let mut cl = cl_lengths();
    cl[12] = 0; // 15 codes of length 4
    let input = stream(|w| {
        header(w, true, 0b10);
        dynamic_header(w, 257, 1, &cl, &[]);
    });
    assert_eq!(err(&input), INCOMPLETE_CODE, "code-length code");

    let mut lit = minimal_instructions();
    lit[4] = Cl::Len(2); // 97 of length 1, 256 of length 2
    let input = stream(|w| {
        header(w, true, 0b10);
        dynamic_header(w, 257, 1, &cl_lengths(), &lit);
    });
    assert_eq!(err(&input), INCOMPLETE_CODE, "literal/length code");

    let mut dist = minimal_instructions();
    dist.pop();
    dist.push(Cl::Len(1));
    dist.push(Cl::Len(2)); // distance codes of lengths 1 and 2
    let input = stream(|w| {
        header(w, true, 0b10);
        dynamic_header(w, 257, 2, &cl_lengths(), &dist);
    });
    assert_eq!(err(&input), INCOMPLETE_CODE, "distance code");
}

/// RFC 1951 §3.2.7: "One distance code of zero bits means that there are no
/// distance codes used at all (the data is all literals)": accepted, and a
/// length symbol in such a block is an error.
#[test]
fn no_distance_codes_means_literals_only() {
    let mut instructions = minimal_instructions();
    instructions.pop();
    instructions.push(Cl::Len(0));
    let input = stream(|w| {
        header(w, true, 0b10);
        dynamic_header(w, 257, 1, &cl_lengths(), &instructions);
        w.code(0, 1);
        w.code(1, 1);
    });
    assert_eq!(&inflate(&input, CAP).unwrap()[..], b"a");

    // 97 -> 1 bit, 256 and 257 -> 2 bits, no distance codes.
    let instructions = [
        Cl::Zeros11(97),
        Cl::Len(1),
        Cl::Zeros11(138),
        Cl::Zeros11(20),
        Cl::Len(2),
        Cl::Len(2),
        Cl::Len(0),
    ];
    let input = stream(|w| {
        header(w, true, 0b10);
        dynamic_header(w, 258, 1, &cl_lengths(), &instructions);
        w.code(0, 1); // a
        w.code(0b11, 2); // 257: length 3
        w.code(0, 1);
    });
    assert_eq!(err(&input), NO_DISTANCE_CODES);
}

/// RFC 1951 §3.2.5 and §3.2.7: every block ends with symbol 256, so the
/// literal/length code must give it a code.
#[test]
fn rejects_missing_end_of_block_code() {
    let instructions = [
        Cl::Zeros11(97),
        Cl::Len(1),
        Cl::Len(1), // 97 and 98
        Cl::Zeros11(138),
        Cl::Zeros11(20), // 99..=256
        Cl::Len(1),
    ];
    let input = stream(|w| {
        header(w, true, 0b10);
        dynamic_header(w, 257, 1, &cl_lengths(), &instructions);
    });
    assert_eq!(err(&input), MISSING_END_OF_BLOCK);
}

/// RFC 1951 §3.2.3: the stream ends with the final block; input that stops
/// earlier, anywhere, is truncated.
#[test]
fn rejects_truncated_input() {
    assert_eq!(err(&[]), TRUNCATED, "empty input");
    let full = stream(|w| {
        header(w, true, 0b01);
        fixed(w, u32::from(b'a'));
        fixed(w, 257);
        fixed_distance(w, 0);
        fixed(w, 256);
    });
    assert_eq!(inflate(&full, CAP).unwrap().len(), 4);
    for cut in 0..full.len() {
        assert_eq!(err(&full[..cut]), TRUNCATED, "fixed block cut at {cut}");
    }
    let stored = stream(|w| {
        header(w, true, 0b00);
        w.align_to_byte();
        w.bytes(&[3, 0, 0xFC, 0xFF, b'a', b'b', b'c']);
    });
    for cut in 0..stored.len() {
        assert_eq!(err(&stored[..cut]), TRUNCATED, "stored block cut at {cut}");
    }
    let dynamic = stream(|w| {
        header(w, true, 0b10);
        dynamic_header(w, 257, 1, &cl_lengths(), &minimal_instructions());
        w.code(0, 1);
        w.code(1, 1);
    });
    for cut in 0..dynamic.len() {
        assert_eq!(
            err(&dynamic[..cut]),
            TRUNCATED,
            "dynamic block cut at {cut}"
        );
    }
    // A non-final block with nothing after it.
    let not_final = stream(|w| {
        header(w, false, 0b01);
        fixed(w, 256);
    });
    assert_eq!(err(&not_final), TRUNCATED, "no final block");
}

// ---- the output cap (ADR 0017 §1) ----

#[test]
fn output_cap_is_inclusive() {
    let input = stream(|w| {
        header(w, true, 0b00);
        w.align_to_byte();
        w.bytes(&[3, 0, 0xFC, 0xFF, b'a', b'b', b'c']);
    });
    assert_eq!(&inflate(&input, 3).unwrap()[..], b"abc");
    assert_eq!(inflate(&input, 2), Err(Error::InvalidFormat(OUTPUT_LIMIT)));
    assert_eq!(inflate(&input, 0), Err(Error::InvalidFormat(OUTPUT_LIMIT)));
    let empty = stream(|w| {
        header(w, true, 0b01);
        fixed(w, 256);
    });
    assert!(inflate(&empty, 0).unwrap().is_empty());
}

#[test]
fn output_cap_applies_to_literals_and_copies() {
    let input = stream(|w| {
        header(w, true, 0b01);
        fixed(w, u32::from(b'a'));
        fixed(w, u32::from(b'b'));
        fixed(w, 257);
        fixed_distance(w, 1);
        fixed(w, 256);
    });
    assert_eq!(&inflate(&input, 5).unwrap()[..], b"ababa");
    for cap in 0..5 {
        assert_eq!(
            inflate(&input, cap),
            Err(Error::InvalidFormat(OUTPUT_LIMIT)),
            "cap {cap}"
        );
    }
}

/// A decompression bomb (the CVE-2024-28180 class, ADR 0017): a dynamic
/// block where length 258 (symbol 285) and distance 1 each take one bit, so
/// every 2 bits of input expand to 258 bytes. That ratio (about 1032:1) is
/// DEFLATE's ceiling, so 1 KiB of input can describe at most about 1 MiB;
/// the 1 GiB bomb is therefore about 1 MiB of input, and its first 1 KiB is
/// the 1 KiB input. Both must stop at the cap without the output buffer
/// ever growing past `max_output` + 32 KiB.
#[test]
fn decompression_bomb_stops_at_the_cap() {
    const GIB: usize = 1 << 30;
    const MAX: usize = 250_000;
    // Literal/length lengths: 97 -> 2, 256 -> 2, 285 -> 1 (HLIT 286);
    // distance 0 -> 1 (HDIST 1).
    let instructions = [
        Cl::Zeros11(97),
        Cl::Len(2),
        Cl::Zeros11(138),
        Cl::Zeros11(20),
        Cl::Len(2),
        Cl::Zeros11(28),
        Cl::Len(1),
        Cl::Len(1),
    ];
    let matches = GIB / 258 + 1;
    let bomb = stream(|w| {
        header(w, true, 0b10);
        dynamic_header(w, 286, 1, &cl_lengths(), &instructions);
        // Canonical codes: 285 -> 0, 97 -> 10, 256 -> 11.
        w.code(0b10, 2); // 'a'
        for _ in 0..matches {
            w.code(0, 1); // length 258
            w.code(0, 1); // distance 1
        }
        w.code(0b11, 2);
    });
    assert!(bomb.len() < 1100 * 1024, "bomb is {} bytes", bomb.len());

    for input in [&bomb[..], &bomb[..1024]] {
        let mut peak = 0;
        let result = inflate::inflate_tracked(input, MAX, &mut peak);
        assert_eq!(result, Err(Error::InvalidFormat(OUTPUT_LIMIT)));
        assert!(peak <= MAX + 32 * 1024, "peak capacity {peak}");
        assert!(peak > 0);
    }

    // The same bomb with a cap above its output inflates in full, which
    // proves the input really describes 1 GiB (checked on a 1 MiB slice of
    // the matches to keep the test small).
    let small = stream(|w| {
        header(w, true, 0b10);
        dynamic_header(w, 286, 1, &cl_lengths(), &instructions);
        w.code(0b10, 2);
        for _ in 0..4096 {
            w.code(0, 1);
            w.code(0, 1);
        }
        w.code(0b11, 2);
    });
    let out = inflate(&small, CAP + 64 * 1024).unwrap();
    assert_eq!(out.len(), 1 + 4096 * 258);
    assert!(out.iter().all(|&b| b == b'a'));
}

/// The output buffer grows with the output, not to the cap up front.
#[test]
fn output_buffer_grows_with_the_output() {
    let input = stream(|w| {
        header(w, true, 0b01);
        fixed(w, u32::from(b'a'));
        fixed(w, 256);
    });
    let mut peak = 0;
    let out = inflate::inflate_tracked(&input, usize::MAX, &mut peak).unwrap();
    assert_eq!(&out[..], b"a");
    assert!(peak <= 64 * 1024, "peak capacity {peak}");
}

/// RFC 7520 §5.9.2: the compressed plaintext the cookbook prints (Fig. 162,
/// vendored as `generated.plaintext_c`) inflates to exactly the Fig. 72
/// plaintext.
#[test]
fn rfc7520_section_5_9_compressed_plaintext() {
    let cookbook = crate::json::parse(include_bytes!(
        "../../tests/third_party/ietf-jose-cookbook/jwe/5_9.compressed_content.json"
    ))
    .unwrap();
    let plaintext = cookbook
        .get("input")
        .and_then(|v| v.get("plaintext"))
        .and_then(|v| v.as_str())
        .unwrap();
    let compressed = cookbook
        .get("generated")
        .and_then(|v| v.get("plaintext_c"))
        .and_then(|v| v.as_str())
        .unwrap();
    assert_eq!(
        compressed,
        "bY_BDcIwDEVX-QNU3QEOrIA4pqlDokYxchxVvbEDGzIJbioOSJwc-f___HPjBu8KVFpVtAplVE1-wZo0YjNZo3C7R5v72pV5f5X382VWjYQpqZKAyjziZOr2B7kQPSy6oZIXUnDYbVKN4jNXi2u0yB7t1qSHTjmMODf9QgvrDzfTIQXnyQRuUya4zIWG3vTOdir0v7BRHFYWq3k1k1A_gSDJqtcBF-GZxw8"
    );
    let compressed = crate::util::b64url_decode(compressed).unwrap();
    let out = inflate(&compressed, CAP).unwrap();
    assert_eq!(&out[..], plaintext.as_bytes());
    assert!(plaintext.starts_with("You can trust us to stick with you"));
    assert!(plaintext.ends_with("We are your friends, Frodo."));
}
