//! Bit-level input and output for raw DEFLATE (RFC 1951 §3.1.1).
//!
//! RFC 1951 §3.1.1: "Data elements are packed into bytes in order of
//! increasing bit number within the byte, i.e., starting with the
//! least-significant bit of the byte." Data elements other than Huffman
//! codes (header fields, LEN/NLEN, extra bits) are packed starting with
//! their least-significant bit; Huffman codes are packed starting with
//! their most-significant bit (errata 7764 and 8429 restate the extra-bit
//! order). Every reader method is total: running out of input is
//! [`TRUNCATED`], never a panic.

use super::TRUNCATED;
use crate::{Error, Result};

/// Reads RFC 1951 §3.1.1 bit fields from a byte slice.
///
/// Invariant: `buf` holds `count` unread bits in its low bits, and every bit
/// above `count` is zero.
pub(super) struct BitReader<'a> {
    input: &'a [u8],
    pos: usize,
    buf: u64,
    count: u32,
}

impl<'a> BitReader<'a> {
    pub(super) fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            pos: 0,
            buf: 0,
            count: 0,
        }
    }

    /// Buffers whole input bytes until at least `n` bits are held or the
    /// input is exhausted. `n` is at most 32, so `count` stays below 40.
    fn refill(&mut self, n: u32) {
        while self.count < n {
            let Some(&byte) = self.input.get(self.pos) else {
                return;
            };
            self.buf |= u64::from(byte) << self.count;
            self.pos += 1;
            self.count += 8;
        }
    }

    /// Reads an `n`-bit (`n` ≤ 16) number packed least-significant bit first
    /// (RFC 1951 §3.1.1): header fields, LEN/NLEN and extra bits.
    pub(super) fn bits(&mut self, n: u32) -> Result<u32> {
        debug_assert!(n <= 16);
        self.refill(n);
        if self.count < n {
            return Err(Error::InvalidFormat(TRUNCATED));
        }
        let value = self.buf & ((1u64 << n) - 1);
        self.buf >>= n;
        self.count -= n;
        // `value` < 2^16.
        Ok(value as u32)
    }

    /// Returns the next up-to-`n` bits (`n` ≤ 16) without consuming them, and
    /// how many of them are real input (fewer than `n` only at the end of the
    /// input; the missing high bits read as zero).
    pub(super) fn peek(&mut self, n: u32) -> (u32, u32) {
        debug_assert!(n <= 16);
        self.refill(n);
        let value = self.buf & ((1u64 << n) - 1);
        // `value` < 2^16.
        (value as u32, self.count.min(n))
    }

    /// Consumes `n` bits that [`Self::peek`] reported as available.
    pub(super) fn consume(&mut self, n: u32) {
        debug_assert!(n <= self.count);
        let n = n.min(self.count);
        self.buf >>= n;
        self.count -= n;
    }

    /// Skips to the next byte boundary (RFC 1951 §3.2.4: "skip any remaining
    /// bits in current partially processed byte") and hands every buffered
    /// whole byte back to the input, so the reader is byte-aligned with an
    /// empty buffer.
    pub(super) fn align_to_byte(&mut self) {
        // Buffered bits are always the low end of the most recently read
        // bytes, so `count % 8` partial bits belong to the current byte and
        // the remaining `count / 8` bytes are unread whole bytes.
        let whole_bytes = (self.count / 8) as usize;
        self.pos -= whole_bytes;
        self.buf = 0;
        self.count = 0;
    }

    /// Reads `n` raw bytes after [`Self::align_to_byte`] (RFC 1951 §3.2.4).
    pub(super) fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        debug_assert_eq!(self.count, 0);
        let end = self
            .pos
            .checked_add(n)
            .ok_or(Error::InvalidFormat(TRUNCATED))?;
        let slice = self
            .input
            .get(self.pos..end)
            .ok_or(Error::InvalidFormat(TRUNCATED))?;
        self.pos = end;
        Ok(slice)
    }
}

/// Writes RFC 1951 §3.1.1 bit fields into a byte vector whose capacity the
/// caller reserves up front (so the buffer is never reallocated and no
/// unzeroized copy of the compressed plaintext is left behind).
pub(super) struct BitWriter<'a> {
    out: &'a mut Vec<u8>,
    buf: u64,
    count: u32,
}

impl<'a> BitWriter<'a> {
    pub(super) fn new(out: &'a mut Vec<u8>) -> Self {
        Self {
            out,
            buf: 0,
            count: 0,
        }
    }

    /// Writes the low `n` bits (`n` ≤ 16) of `value`, least-significant bit
    /// first (RFC 1951 §3.1.1).
    pub(super) fn bits(&mut self, value: u32, n: u32) {
        debug_assert!(n <= 16);
        let mask = (1u64 << n) - 1;
        self.buf |= (u64::from(value) & mask) << self.count;
        self.count += n;
        while self.count >= 8 {
            self.out.push(self.buf as u8);
            self.buf >>= 8;
            self.count -= 8;
        }
    }

    /// Writes an `n`-bit Huffman code, most-significant bit first (RFC 1951
    /// §3.1.1: "Huffman codes are packed starting with the most-significant
    /// bit of the code").
    pub(super) fn code(&mut self, code: u32, n: u32) {
        self.bits(reverse(code, n), n);
    }

    /// Pads with zero bits to the next byte boundary (RFC 1951 §3.2.4).
    pub(super) fn align_to_byte(&mut self) {
        if self.count > 0 {
            self.bits(0, 8 - self.count);
        }
    }

    /// Writes raw bytes; the writer must be byte-aligned.
    pub(super) fn bytes(&mut self, bytes: &[u8]) {
        debug_assert_eq!(self.count, 0);
        self.out.extend_from_slice(bytes);
    }

    /// Bits written past the last whole byte (0–7).
    pub(super) fn bit_offset(&self) -> u32 {
        self.count
    }

    /// Flushes the final partial byte, zero-padded.
    pub(super) fn finish(mut self) {
        self.align_to_byte();
    }
}

/// Reverses the low `n` bits of `code`: Huffman codes are defined
/// most-significant bit first but the stream is read least-significant bit
/// first (RFC 1951 §3.1.1).
pub(super) fn reverse(code: u32, n: u32) -> u32 {
    if n == 0 {
        return 0;
    }
    code.reverse_bits() >> (32 - n)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 1951 §3.1.1: bits are taken from the least-significant end of
    /// each byte, and a multi-bit number's first bit is its LSB.
    #[test]
    fn reads_fields_lsb_first_across_bytes() {
        let mut r = BitReader::new(&[0b1010_1101, 0b0000_0011]);
        assert_eq!(r.bits(1).unwrap(), 1);
        assert_eq!(r.bits(2).unwrap(), 0b10);
        assert_eq!(r.bits(7).unwrap(), 0b11_10101);
        assert_eq!(r.bits(6).unwrap(), 0);
        assert_eq!(r.bits(1), Err(Error::InvalidFormat(TRUNCATED)));
    }

    #[test]
    fn zero_bit_read_is_zero_even_at_end() {
        let mut r = BitReader::new(&[]);
        assert_eq!(r.bits(0).unwrap(), 0);
        assert_eq!(r.bits(1), Err(Error::InvalidFormat(TRUNCATED)));
    }

    #[test]
    fn peek_reports_available_bits_at_end() {
        let mut r = BitReader::new(&[0xFF]);
        assert_eq!(r.peek(15), (0xFF, 8));
        r.consume(3);
        assert_eq!(r.peek(15), (0x1F, 5));
    }

    /// RFC 1951 §3.2.4: the stored block starts at the next byte boundary,
    /// including bytes the reader had already buffered.
    #[test]
    fn align_returns_buffered_bytes_to_the_input() {
        let mut r = BitReader::new(&[0b0000_0101, 0xAA, 0xBB, 0xCC]);
        assert_eq!(r.bits(3).unwrap(), 0b101);
        let _ = r.peek(16); // buffers 0xAA and 0xBB as well
        r.align_to_byte();
        assert_eq!(r.bytes(2).unwrap(), &[0xAA, 0xBB]);
        assert_eq!(r.bytes(1).unwrap(), &[0xCC]);
        assert_eq!(r.bytes(1), Err(Error::InvalidFormat(TRUNCATED)));
        assert_eq!(r.bytes(usize::MAX), Err(Error::InvalidFormat(TRUNCATED)));
    }

    #[test]
    fn writer_round_trips_with_reader() {
        let mut out = Vec::new();
        let mut w = BitWriter::new(&mut out);
        w.bits(1, 1);
        w.bits(0b10, 2);
        w.code(0b0011_0000, 8);
        assert_eq!(w.bit_offset(), 3);
        w.align_to_byte();
        w.bytes(&[0x12, 0x34]);
        w.bits(0x1FF, 9);
        w.finish();
        let mut r = BitReader::new(&out);
        assert_eq!(r.bits(1).unwrap(), 1);
        assert_eq!(r.bits(2).unwrap(), 0b10);
        assert_eq!(reverse(r.bits(8).unwrap(), 8), 0b0011_0000);
        r.align_to_byte();
        assert_eq!(r.bytes(2).unwrap(), &[0x12, 0x34]);
        assert_eq!(r.bits(9).unwrap(), 0x1FF);
        assert_eq!(r.bits(7).unwrap(), 0);
        assert!(r.bits(1).is_err());
    }

    #[test]
    fn reverse_reverses_low_bits() {
        assert_eq!(reverse(0b001, 3), 0b100);
        assert_eq!(reverse(0b1101, 4), 0b1011);
        assert_eq!(reverse(0, 0), 0);
        assert_eq!(reverse(0x7FFF, 15), 0x7FFF);
    }
}
