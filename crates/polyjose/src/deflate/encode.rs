//! The encoder: stored and fixed-Huffman blocks with greedy LZ77 over a
//! bounded hash chain (ADR 0017 §2).
//!
//! The input is cut into spans of at most 65,535 bytes (the stored-block
//! limit, RFC 1951 §3.2.4). Each span is tokenized into literals and
//! length/distance pairs (§3.2.5; distances may reach into earlier spans,
//! "a back-reference may refer to a string in a previous block"), then
//! emitted as whichever of a fixed-Huffman block (§3.2.6) or a stored block
//! (§3.2.4) is shorter. Choosing the cheaper form per span bounds the output
//! by the all-stored size, so the output buffer is allocated once, at that
//! bound, and never reallocated. Any valid DEFLATE stream interoperates;
//! the compression ratio is not a JOSE requirement (ADR 0017).

use zeroize::Zeroizing;

use super::bits::BitWriter;
use super::inflate::{DISTANCE_BASE, DISTANCE_EXTRA, LENGTH_BASE, LENGTH_EXTRA};

/// The largest stored block (RFC 1951 §3.2.4: LEN is 16 bits).
const SPAN: usize = 65_535;
/// RFC 1951 §3.2.5: the window is 32,768 bytes.
const WINDOW: usize = 32_768;
/// RFC 1951 §3.2.5: matches are 3–258 bytes long.
const MIN_MATCH: usize = 3;
const MAX_MATCH: usize = 258;
/// Hash-chain bounds: positions per bucket chain walked, and the number of
/// hash buckets.
const MAX_CHAIN: usize = 128;
const HASH_BITS: u32 = 15;
/// Bytes a block adds besides its data, at most: a stored block costs 3
/// header bits, up to 7 padding bits and 32 bits of LEN/NLEN (42 bits, under
/// 6 bytes), and a fixed block is only chosen when it costs fewer bits.
const STORED_OVERHEAD: usize = 6;

/// A literal byte, or a match: bit 31 set, length in bits 16–24, distance
/// in bits 0–15 (distance 32,768 fits 16 bits).
type Token = u32;
const MATCH: Token = 1 << 31;

/// Compresses `input` into a raw DEFLATE stream (RFC 1951 §3.2). Never
/// fails.
pub(super) fn compress(input: &[u8]) -> Zeroizing<Vec<u8>> {
    let spans = input.len().div_ceil(SPAN).max(1);
    // The all-stored size, plus one byte for the final partial byte.
    let bound = input.len() + spans * STORED_OVERHEAD + 1;
    let mut out = Zeroizing::new(Vec::with_capacity(bound));
    let mut matcher = Matcher::new();
    // A span has at most one token per byte, so this never grows.
    let mut tokens: Zeroizing<Vec<Token>> =
        Zeroizing::new(Vec::with_capacity(SPAN.min(input.len())));
    {
        let mut w = BitWriter::new(&mut out);
        let mut start = 0;
        loop {
            let end = (start + SPAN).min(input.len());
            let last = end == input.len();
            tokens.clear();
            matcher.tokenize(input, start, end, &mut tokens);
            let fixed_bits = 3 + tokens.iter().map(|&t| fixed_token_bits(t)).sum::<u64>() + 7;
            let padding = u64::from((8 - (w.bit_offset() + 3) % 8) % 8);
            let stored_bits = 3 + padding + 32 + 8 * (end - start) as u64;
            if fixed_bits < stored_bits {
                fixed_block(&mut w, last, &tokens);
            } else {
                stored_block(&mut w, last, &input[start..end]);
            }
            if last {
                break;
            }
            start = end;
        }
        w.finish();
    }
    debug_assert!(out.len() <= bound);
    out
}

/// RFC 1951 §3.2.4: BFINAL, BTYPE 00, padding, LEN, NLEN, then the bytes.
fn stored_block(w: &mut BitWriter<'_>, last: bool, data: &[u8]) {
    // `data` is one span, at most 65,535 bytes.
    let len = data.len() as u16;
    w.bits(u32::from(last), 1);
    w.bits(0b00, 2);
    w.align_to_byte();
    w.bits(u32::from(len), 16);
    w.bits(u32::from(!len), 16);
    w.bytes(data);
}

/// RFC 1951 §3.2.6: BFINAL, BTYPE 01, the tokens in the fixed code, then
/// end-of-block.
fn fixed_block(w: &mut BitWriter<'_>, last: bool, tokens: &[Token]) {
    w.bits(u32::from(last), 1);
    w.bits(0b01, 2);
    for &token in tokens {
        if token & MATCH == 0 {
            let (code, len) = fixed_literal_code(token);
            w.code(code, len);
            continue;
        }
        let length = ((token >> 16) & 0x1FF) as usize;
        let distance = (token & 0xFFFF) as usize;
        let (index, extra) = length_symbol(length);
        let (code, len) = fixed_literal_code(257 + index as u32);
        w.code(code, len);
        w.bits(extra, u32::from(LENGTH_EXTRA[index]));
        let (index, extra) = distance_symbol(distance);
        w.code(index as u32, 5);
        w.bits(extra, u32::from(DISTANCE_EXTRA[index]));
    }
    let (code, len) = fixed_literal_code(256);
    w.code(code, len);
}

/// RFC 1951 §3.2.6: the fixed literal/length code of `symbol` (0–287).
fn fixed_literal_code(symbol: u32) -> (u32, u32) {
    match symbol {
        0..=143 => (0b0011_0000 + symbol, 8),
        144..=255 => (0b1_1001_0000 + symbol - 144, 9),
        256..=279 => (symbol - 256, 7),
        _ => (0b1100_0000 + symbol - 280, 8),
    }
}

/// Bits a token takes in a fixed-Huffman block.
fn fixed_token_bits(token: Token) -> u64 {
    if token & MATCH == 0 {
        return u64::from(fixed_literal_code(token).1);
    }
    let (index, _) = length_symbol(((token >> 16) & 0x1FF) as usize);
    let (dindex, _) = distance_symbol((token & 0xFFFF) as usize);
    u64::from(fixed_literal_code(257 + index as u32).1)
        + u64::from(LENGTH_EXTRA[index])
        + 5
        + u64::from(DISTANCE_EXTRA[dindex])
}

/// RFC 1951 §3.2.5: the length symbol index (symbol − 257) and extra-bit
/// value for a match length 3–258. 258 is symbol 285.
fn length_symbol(length: usize) -> (usize, u32) {
    let index = LENGTH_BASE
        .iter()
        .rposition(|&base| usize::from(base) <= length)
        .unwrap_or(0);
    (index, (length - usize::from(LENGTH_BASE[index])) as u32)
}

/// RFC 1951 §3.2.5: the distance symbol and extra-bit value for a distance
/// 1–32,768.
fn distance_symbol(distance: usize) -> (usize, u32) {
    let index = DISTANCE_BASE
        .iter()
        .rposition(|&base| usize::from(base) <= distance)
        .unwrap_or(0);
    (index, (distance - usize::from(DISTANCE_BASE[index])) as u32)
}

/// Greedy LZ77 over hash chains of 3-byte prefixes. `head[h]` and
/// `prev[pos % WINDOW]` hold positions plus one (0 is "none"). Both are
/// wiped on drop: their contents depend on the plaintext.
struct Matcher {
    head: Zeroizing<Vec<usize>>,
    prev: Zeroizing<Vec<usize>>,
}

impl Matcher {
    fn new() -> Self {
        Self {
            head: Zeroizing::new(vec![0; 1 << HASH_BITS]),
            prev: Zeroizing::new(vec![0; WINDOW]),
        }
    }

    fn hash(bytes: [u8; 3]) -> usize {
        let v = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0]);
        (v.wrapping_mul(0x9E37_79B1) >> (32 - HASH_BITS)) as usize
    }

    fn prefix(input: &[u8], pos: usize) -> Option<[u8; 3]> {
        match input.get(pos..pos + MIN_MATCH)? {
            &[a, b, c] => Some([a, b, c]),
            _ => None,
        }
    }

    /// Records `pos` as the newest position with its 3-byte prefix.
    fn insert(&mut self, input: &[u8], pos: usize) {
        let Some(prefix) = Self::prefix(input, pos) else {
            return;
        };
        let h = Self::hash(prefix);
        self.prev[pos % WINDOW] = self.head[h];
        self.head[h] = pos + 1;
    }

    /// The longest match for `pos`, at most `limit` bytes, as (length,
    /// distance), from at most `MAX_CHAIN` earlier positions within the
    /// window.
    fn longest_match(&self, input: &[u8], pos: usize, limit: usize) -> Option<(usize, usize)> {
        if limit < MIN_MATCH {
            return None;
        }
        let prefix = Self::prefix(input, pos)?;
        let mut candidate = self.head[Self::hash(prefix)];
        let mut best: Option<(usize, usize)> = None;
        for _ in 0..MAX_CHAIN {
            let Some(at) = candidate.checked_sub(1) else {
                break;
            };
            let distance = match pos.checked_sub(at) {
                Some(d) if d > 0 && d <= WINDOW => d,
                _ => break,
            };
            let length = input[at..]
                .iter()
                .zip(&input[pos..pos + limit])
                .take_while(|(a, b)| a == b)
                .count();
            if length >= MIN_MATCH && best.is_none_or(|(l, _)| length > l) {
                best = Some((length, distance));
                if length == limit {
                    break;
                }
            }
            candidate = self.prev[at % WINDOW];
        }
        best
    }

    /// Appends the tokens for `input[start..end]`; matches stay inside the
    /// span but may reach back into earlier ones.
    fn tokenize(&mut self, input: &[u8], start: usize, end: usize, tokens: &mut Vec<Token>) {
        let mut pos = start;
        while pos < end {
            let limit = (end - pos).min(MAX_MATCH);
            match self.longest_match(input, pos, limit) {
                Some((length, distance)) => {
                    tokens.push(MATCH | ((length as u32) << 16) | distance as u32);
                    for p in pos..pos + length {
                        self.insert(input, p);
                    }
                    pos += length;
                }
                None => {
                    tokens.push(Token::from(input[pos]));
                    self.insert(input, pos);
                    pos += 1;
                }
            }
        }
    }
}
