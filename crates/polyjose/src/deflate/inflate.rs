//! The bounded inflater (RFC 1951 §3.2).
//!
//! The output cap is part of the decoding loop, not a wrapper (ADR 0017 §1):
//! every literal, copy and stored block reserves its bytes first, and the
//! reservation fails the moment the output would exceed `max_output`. The
//! output itself is the LZ77 window (§3.2.5 distances reach at most 32,768
//! bytes back, always into output already produced), so the only heap
//! allocation is the output buffer; the Huffman tables are fixed-size values
//! on the stack.
//!
//! # Reservation and growth (ADR 0050 §4)
//!
//! The output can never pass `limit` = min(`max_output`,
//! [`max_expansion`]`(input.len())`). Up front the buffer reserves
//! min(`limit`, [`INITIAL_RESERVATION`]), so a caller-chosen huge
//! `max_output` (say, a 1 GiB `DecryptPolicy::max_decompressed_len`) costs
//! nothing until the stream actually produces that much. Beyond that the
//! buffer grows by doubling, capped at `limit`, and never past `max_output`.
//!
//! Each growth step allocates a new buffer, copies the output into it, and
//! drops the old one inside its `Zeroizing`, which wipes its whole capacity:
//! there is never a plain `Vec` reallocation, so no unwiped copy of the
//! plaintext is left in freed memory.
//!
//! The trade-off: memory now follows the output instead of the cap, at the
//! price of copies and a transient peak.
//! - At rest the buffer is at most twice the output length.
//! - During a growth step the old buffer (full, about the output length)
//!   and the new one (twice that) are both live: a peak of under 3× the
//!   output length once the step's write lands, i.e. 1.5× the new
//!   capacity, and always under 2 × `max_output`.
//! - Each byte is copied O(1) times on average (doubling).
//!
//! Without growth the up-front reservation would have to be `limit`
//! itself, which is what the reservation cap exists to avoid.

use zeroize::Zeroizing;

use super::bits::BitReader;
use super::huffman::{Huffman, Kind, MAX_BITS};
use super::{
    DISTANCE_TOO_FAR, EXPANSION_BOUND, INVALID_CODE, INVALID_DISTANCE_SYMBOL,
    INVALID_LENGTH_SYMBOL, MISSING_END_OF_BLOCK, OUTPUT_ALLOCATION, OUTPUT_LIMIT, REPEAT_OVERRUN,
    REPEAT_WITHOUT_PREVIOUS, RESERVED_BLOCK_TYPE, SINGLE_LENGTH_CODE, STORED_LENGTH_MISMATCH,
    TOO_MANY_DISTANCE_CODES, TOO_MANY_LENGTH_CODES,
};
use crate::{Error, Result};

/// RFC 1951 §3.2.5: base lengths for literal/length symbols 257–285.
pub(super) const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
/// RFC 1951 §3.2.5: extra bits for literal/length symbols 257–285.
pub(super) const LENGTH_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
/// RFC 1951 §3.2.5: base distances for distance symbols 0–29.
pub(super) const DISTANCE_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
/// RFC 1951 §3.2.5: extra bits for distance symbols 0–29.
pub(super) const DISTANCE_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
/// RFC 1951 §3.2.7: the order the code-length code lengths are sent in.
const CODE_LENGTH_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];
/// End-of-block (RFC 1951 §3.2.5).
const END_OF_BLOCK: u16 = 256;
/// RFC 1951's largest output per input bit: a length/distance pair takes at
/// least two bits (a literal/length code and a distance code, each at least
/// one bit, §3.2.2, §3.2.7) and yields at most 258 bytes (§3.2.5).
const MAX_BYTES_PER_BIT: usize = 258 / 2;

/// The most output any `input_len` bytes of raw DEFLATE can produce:
/// 1,032 bytes per input byte.
///
/// Every output byte comes from bits the decoder consumes, and each kind of
/// element yields at most [`MAX_BYTES_PER_BIT`] bytes per bit it consumes:
/// a literal (§3.2.5) is at least one bit for one byte; a length/distance
/// pair is at least two bits for at most 258 bytes; a stored block (§3.2.4)
/// is eight bits per byte; block headers, LEN/NLEN, code-length tables and
/// end-of-block produce nothing. The decoder never consumes more than
/// `8 * input_len` bits, so the output is at most `129 * 8 * input_len`. No
/// constant term is needed: a final partial byte still counts as consumed
/// input. Saturates at `usize::MAX`.
pub(super) fn max_expansion(input_len: usize) -> usize {
    input_len.saturating_mul(8 * MAX_BYTES_PER_BIT)
}

/// The most the output buffer reserves before decoding: 250,000 bytes, the
/// default `DecryptPolicy::max_decompressed_len` (ADR 0017 §3, ADR 0050 §4).
/// This module may depend only on `crate::Error` and `zeroize` (the fuzz
/// target's shape), so the value is repeated here and the `jwe::zip` tests
/// pin the two together.
pub(super) const INITIAL_RESERVATION: usize = 250_000;

/// The output buffer's capacities, recorded for tests: `initial` right after
/// the up-front reservation, `last` when decoding ends (also on error),
/// `peak` the most bytes of buffer live at once (the old plus the new
/// buffer during a growth step; `initial` if it never grew), and `len` the
/// output length when decoding ended.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct Capacity {
    pub(super) initial: usize,
    pub(super) last: usize,
    pub(super) peak: usize,
    pub(super) len: usize,
}

/// The output buffer: the inflated data and the LZ77 window.
struct Output {
    buf: Zeroizing<Vec<u8>>,
    /// The caller's cap (ADR 0017 §1).
    max: usize,
    /// min(`max`, [`max_expansion`] of the input): the most the buffer is
    /// ever grown to.
    limit: usize,
    /// See [`Capacity::peak`].
    peak: usize,
}

impl Output {
    /// Reserves min(`max_output`, [`max_expansion`]`(input_len)`,
    /// [`INITIAL_RESERVATION`]) bytes (ADR 0050 §4).
    fn new(input_len: usize, max_output: usize) -> Result<Self> {
        let limit = max_output.min(max_expansion(input_len));
        let capacity = limit.min(INITIAL_RESERVATION);
        let mut buf = Vec::new();
        buf.try_reserve_exact(capacity)
            .map_err(|_| Error::InvalidFormat(OUTPUT_ALLOCATION))?;
        Ok(Self {
            buf: Zeroizing::new(buf),
            max: max_output,
            limit,
            peak: capacity,
        })
    }

    /// Checks that `n` more bytes fit, failing as soon as the output would
    /// exceed the cap (ADR 0017 §1), and grows the buffer if they do not fit
    /// its capacity. By [`max_expansion`] the output never passes `limit`;
    /// if that ever failed to hold, decoding stops with an error instead of
    /// growing past it.
    fn reserve(&mut self, n: usize) -> Result<()> {
        let needed = self
            .buf
            .len()
            .checked_add(n)
            .ok_or(Error::InvalidFormat(OUTPUT_LIMIT))?;
        if needed > self.max {
            return Err(Error::InvalidFormat(OUTPUT_LIMIT));
        }
        debug_assert!(
            needed <= self.limit,
            "output beyond the RFC 1951 expansion bound"
        );
        if needed > self.limit {
            return Err(Error::InvalidFormat(EXPANSION_BOUND));
        }
        if needed > self.buf.capacity() {
            self.grow(needed)?;
        }
        Ok(())
    }

    /// Moves the output into a new buffer of twice the capacity (at least
    /// `needed`, at most `limit`; ADR 0050 §4). The old buffer is dropped
    /// inside its `Zeroizing`, which wipes all of its capacity, so no
    /// unwiped plaintext stays in freed memory; a plain `Vec` reallocation
    /// would not wipe the block it frees.
    fn grow(&mut self, needed: usize) -> Result<()> {
        let capacity = self
            .buf
            .capacity()
            .saturating_mul(2)
            .max(needed)
            .min(self.limit);
        let mut grown = Vec::new();
        grown
            .try_reserve_exact(capacity)
            .map_err(|_| Error::InvalidFormat(OUTPUT_ALLOCATION))?;
        grown.extend_from_slice(&self.buf);
        self.peak = self
            .peak
            .max(self.buf.capacity().saturating_add(grown.capacity()));
        // The old buffer drops here and is wiped.
        self.buf = Zeroizing::new(grown);
        Ok(())
    }

    fn push(&mut self, byte: u8) -> Result<()> {
        self.reserve(1)?;
        self.buf.push(byte);
        Ok(())
    }

    fn extend(&mut self, bytes: &[u8]) -> Result<()> {
        self.reserve(bytes.len())?;
        self.buf.extend_from_slice(bytes);
        Ok(())
    }

    /// Copies `length` bytes starting `distance` bytes back (RFC 1951
    /// §3.2.3). The copy may overlap its own output ("the referenced string
    /// may overlap the current position"), so it goes in chunks of at most
    /// `distance` bytes, each a copy of bytes already present.
    fn copy(&mut self, distance: usize, length: usize) -> Result<()> {
        if distance == 0 || distance > self.buf.len() {
            return Err(Error::InvalidFormat(DISTANCE_TOO_FAR));
        }
        self.reserve(length)?;
        let mut remaining = length;
        while remaining > 0 {
            let chunk = remaining.min(distance);
            let start = self.buf.len() - distance;
            self.buf.extend_from_within(start..start + chunk);
            remaining -= chunk;
        }
        Ok(())
    }
}

/// Inflates `input`, producing at most `max_output` bytes, and records the
/// output buffer's capacity in `capacity` (also on error).
pub(super) fn inflate_tracked(
    input: &[u8],
    max_output: usize,
    capacity: &mut Capacity,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut reader = BitReader::new(input);
    let mut out = Output::new(input.len(), max_output)?;
    capacity.initial = out.buf.capacity();
    let result = inflate_blocks(&mut reader, &mut out);
    capacity.last = out.buf.capacity();
    capacity.peak = out.peak;
    capacity.len = out.buf.len();
    result?;
    Ok(out.buf)
}

/// RFC 1951 §3.2.3: blocks, each starting with BFINAL and BTYPE, until the
/// block with BFINAL set. Any bytes after that block are not read.
fn inflate_blocks(reader: &mut BitReader<'_>, out: &mut Output) -> Result<()> {
    loop {
        let last = reader.bits(1)? == 1;
        match reader.bits(2)? {
            0b00 => stored_block(reader, out)?,
            0b01 => {
                let (literals, distances) = fixed_tables()?;
                compressed_block(reader, out, &literals, &distances)?;
            }
            0b10 => {
                let (literals, distances) = dynamic_tables(reader)?;
                compressed_block(reader, out, &literals, &distances)?;
            }
            _ => return Err(Error::InvalidFormat(RESERVED_BLOCK_TYPE)),
        }
        if last {
            return Ok(());
        }
    }
}

/// RFC 1951 §3.2.4: skip to a byte boundary, read LEN and NLEN (NLEN must
/// be the one's complement of LEN), then copy LEN bytes.
fn stored_block(reader: &mut BitReader<'_>, out: &mut Output) -> Result<()> {
    reader.align_to_byte();
    let header = reader.bytes(4)?;
    let len = u16::from_le_bytes([header[0], header[1]]);
    let nlen = u16::from_le_bytes([header[2], header[3]]);
    if nlen != !len {
        return Err(Error::InvalidFormat(STORED_LENGTH_MISMATCH));
    }
    let data = reader.bytes(usize::from(len))?;
    out.extend(data)
}

/// RFC 1951 §3.2.6: the fixed literal/length code (lengths 8, 9, 7, 8 for
/// 0–143, 144–255, 256–279, 280–287) and the fixed distance code (32
/// five-bit codes). Symbols 286–287 and distances 30–31 have codes but are
/// rejected when decoded.
fn fixed_tables() -> Result<(Huffman, Huffman)> {
    let mut lengths = [0u8; 288];
    lengths[..144].fill(8);
    lengths[144..256].fill(9);
    lengths[256..280].fill(7);
    lengths[280..].fill(8);
    let literals = Huffman::new(&lengths, Kind::Complete)?;
    let distances = Huffman::new(&[5; 32], Kind::Complete)?;
    Ok((literals, distances))
}

/// RFC 1951 §3.2.7: HLIT, HDIST and HCLEN, the code-length code, then the
/// HLIT + HDIST code lengths of the literal/length and distance codes.
fn dynamic_tables(reader: &mut BitReader<'_>) -> Result<(Huffman, Huffman)> {
    let hlit = reader.bits(5)? as usize + 257;
    let hdist = reader.bits(5)? as usize + 1;
    let hclen = reader.bits(4)? as usize + 4;
    if hlit > 286 {
        return Err(Error::InvalidFormat(TOO_MANY_LENGTH_CODES));
    }
    if hdist > 30 {
        return Err(Error::InvalidFormat(TOO_MANY_DISTANCE_CODES));
    }

    let mut code_lengths = [0u8; 19];
    for &symbol in &CODE_LENGTH_ORDER[..hclen] {
        code_lengths[symbol] = reader.bits(3)? as u8;
    }
    let code_length_code = Huffman::new(&code_lengths, Kind::Complete)?;

    // One sequence: repeats may run from the literal/length lengths into the
    // distance lengths (§3.2.7: "code lengths form a single sequence").
    let total = hlit + hdist;
    let mut lengths = [0u8; 286 + 30];
    let mut filled = 0;
    while filled < total {
        let symbol = code_length_code.decode(reader)?;
        let (value, count) = match symbol {
            0..=15 => (symbol as u8, 1),
            16 => {
                let previous = filled
                    .checked_sub(1)
                    .map(|i| lengths[i])
                    .ok_or(Error::InvalidFormat(REPEAT_WITHOUT_PREVIOUS))?;
                (previous, 3 + reader.bits(2)? as usize)
            }
            17 => (0, 3 + reader.bits(3)? as usize),
            18 => (0, 11 + reader.bits(7)? as usize),
            _ => return Err(Error::InvalidFormat(INVALID_CODE)),
        };
        let end = filled + count;
        if end > total {
            return Err(Error::InvalidFormat(REPEAT_OVERRUN));
        }
        lengths[filled..end].fill(value);
        filled = end;
    }
    debug_assert!(lengths.iter().all(|&l| u32::from(l) <= MAX_BITS));

    if lengths[usize::from(END_OF_BLOCK)] == 0 {
        return Err(Error::InvalidFormat(MISSING_END_OF_BLOCK));
    }
    // Incomplete, so `Huffman::new` would reject it too; named separately
    // (see `SINGLE_LENGTH_CODE`).
    if lengths[usize::from(END_OF_BLOCK)] == 1
        && lengths[..hlit].iter().filter(|&&l| l != 0).count() == 1
    {
        return Err(Error::InvalidFormat(SINGLE_LENGTH_CODE));
    }
    let literals = Huffman::new(&lengths[..hlit], Kind::Complete)?;
    let distances = Huffman::new(&lengths[hlit..total], Kind::Distance)?;
    Ok((literals, distances))
}

/// RFC 1951 §3.2.5: literals 0–255, end-of-block 256, and length symbols
/// 257–285 (base plus extra bits), each followed by a distance symbol 0–29
/// (base plus extra bits; extra bits are an integer read least-significant
/// bit first, errata 7764 and 8429).
fn compressed_block(
    reader: &mut BitReader<'_>,
    out: &mut Output,
    literals: &Huffman,
    distances: &Huffman,
) -> Result<()> {
    loop {
        let symbol = literals.decode(reader)?;
        if symbol < END_OF_BLOCK {
            out.push(symbol as u8)?;
            continue;
        }
        if symbol == END_OF_BLOCK {
            return Ok(());
        }
        let index = usize::from(symbol - 257);
        let (Some(&base), Some(&extra)) = (LENGTH_BASE.get(index), LENGTH_EXTRA.get(index)) else {
            return Err(Error::InvalidFormat(INVALID_LENGTH_SYMBOL));
        };
        let length = usize::from(base) + reader.bits(u32::from(extra))? as usize;

        let index = usize::from(distances.decode(reader)?);
        let (Some(&base), Some(&extra)) = (DISTANCE_BASE.get(index), DISTANCE_EXTRA.get(index))
        else {
            return Err(Error::InvalidFormat(INVALID_DISTANCE_SYMBOL));
        };
        let distance = usize::from(base) + reader.bits(u32::from(extra))? as usize;
        out.copy(distance, length)?;
    }
}
