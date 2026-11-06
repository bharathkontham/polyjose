//! Canonical Huffman decoding (RFC 1951 §3.2.2).
//!
//! RFC 1951 §3.2.2 defines a code entirely by its code lengths: shorter
//! codes lexicographically precede longer ones, and codes of one length are
//! consecutive in symbol order. A decoder table is built from the lengths
//! only after checking that they describe a usable prefix code:
//!
//! - **over-subscribed** lengths (more codes than the code space holds) are
//!   not a prefix code and are always rejected;
//! - **incomplete** lengths (unused code space) are rejected, except for the
//!   two distance-code cases §3.2.7 allows: "If only one distance code is
//!   used, it is encoded using one bit, not zero bits", and "One distance
//!   code of zero bits means that there are no distance codes used at all".
//!
//! The tables are fixed-size arrays (no heap), sized for the largest
//! alphabet, the 288 literal/length symbols of §3.2.5.

use super::bits::{BitReader, reverse};
use super::{INCOMPLETE_CODE, INVALID_CODE, NO_DISTANCE_CODES, OVERSUBSCRIBED_CODE, TRUNCATED};
use crate::{Error, Result};

/// RFC 1951 §3.2.7: code lengths are 0–15.
pub(super) const MAX_BITS: u32 = 15;
/// The largest alphabet: literal/length symbols 0–287 (RFC 1951 §3.2.5).
const MAX_SYMBOLS: usize = 288;
/// Codes up to this length decode with one table lookup.
const FAST_BITS: u32 = 9;

/// Which incomplete codes a table accepts (RFC 1951 §3.2.7).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    /// The code-length and literal/length codes: complete codes only.
    Complete,
    /// The distance code: complete, or exactly one code of length 1, or no
    /// codes at all.
    Distance,
}

/// A canonical Huffman decoding table.
pub(super) struct Huffman {
    /// `counts[len]`: how many symbols have code length `len` (`counts[0]`
    /// is unused).
    counts: [u16; MAX_BITS as usize + 1],
    /// The symbols with non-zero length, sorted by (length, symbol): the
    /// canonical code order of RFC 1951 §3.2.2.
    symbols: [u16; MAX_SYMBOLS],
    /// Number of symbols with a non-zero code length.
    used: u16,
    /// The longest code length in use: a bit sequence that matches no code
    /// within this many bits matches none at all.
    max_len: u32,
    /// Indexed by the next `FAST_BITS` input bits: `symbol | length << 9`
    /// for codes of length ≤ `FAST_BITS`, 0 when the code is longer or
    /// unused.
    fast: [u16; 1 << FAST_BITS],
}

impl Huffman {
    /// Builds the table for the code lengths `lengths[symbol]` (each 0–15,
    /// at most 288 symbols), rejecting over-subscribed codes and the
    /// incomplete codes `kind` does not allow (RFC 1951 §3.2.2, §3.2.7).
    pub(super) fn new(lengths: &[u8], kind: Kind) -> Result<Self> {
        if lengths.len() > MAX_SYMBOLS {
            return Err(Error::InvalidFormat(INVALID_CODE));
        }
        let mut counts = [0u16; MAX_BITS as usize + 1];
        for &len in lengths {
            let slot = counts
                .get_mut(usize::from(len))
                .ok_or(Error::InvalidFormat(INVALID_CODE))?;
            *slot += 1;
        }
        counts[0] = 0;

        // Code space left after assigning every length: the Kraft sum. Each
        // step doubles the space and spends one slot per code of that length.
        let mut left: i32 = 1;
        for &count in &counts[1..] {
            left = (left << 1) - i32::from(count);
            if left < 0 {
                return Err(Error::InvalidFormat(OVERSUBSCRIBED_CODE));
            }
        }
        let used: u16 = counts[1..].iter().sum();
        if left > 0 {
            let allowed = kind == Kind::Distance && (used == 0 || (used == 1 && counts[1] == 1));
            if !allowed {
                return Err(Error::InvalidFormat(INCOMPLETE_CODE));
            }
        }

        // Symbols in canonical order: by length, then by symbol value.
        let mut offsets = [0usize; MAX_BITS as usize + 2];
        for len in 1..=MAX_BITS as usize {
            offsets[len + 1] = offsets[len] + usize::from(counts[len]);
        }
        let mut symbols = [0u16; MAX_SYMBOLS];
        // RFC 1951 §3.2.2 step 2: the first code of each length.
        let mut next_code = [0u32; MAX_BITS as usize + 1];
        let mut code = 0u32;
        for len in 1..=MAX_BITS as usize {
            code = (code + u32::from(counts[len - 1])) << 1;
            next_code[len] = code;
        }
        let mut fast = [0u16; 1 << FAST_BITS];
        for (symbol, &len) in (0u16..).zip(lengths) {
            if len == 0 {
                continue;
            }
            let len_index = usize::from(len);
            symbols[offsets[len_index]] = symbol;
            offsets[len_index] += 1;
            // RFC 1951 §3.2.2 step 3: consecutive codes per length.
            let code = next_code[len_index];
            next_code[len_index] += 1;
            let len = u32::from(len);
            if len <= FAST_BITS {
                let entry = symbol | ((len as u16) << FAST_BITS);
                let step = 1usize << len;
                let mut index = reverse(code, len) as usize;
                while index < fast.len() {
                    fast[index] = entry;
                    index += step;
                }
            }
        }
        let max_len = (1..=MAX_BITS)
            .rev()
            .find(|&len| counts[len as usize] != 0)
            .unwrap_or(0);
        Ok(Self {
            counts,
            symbols,
            used,
            max_len,
            fast,
        })
    }

    /// Decodes one symbol, reading the code most-significant bit first
    /// (RFC 1951 §3.1.1).
    pub(super) fn decode(&self, reader: &mut BitReader<'_>) -> Result<u16> {
        if self.used == 0 {
            // §3.2.7: a block with no distance codes holds only literals.
            return Err(Error::InvalidFormat(NO_DISTANCE_CODES));
        }
        let (bits, available) = reader.peek(MAX_BITS);
        let entry = self.fast[(bits & ((1 << FAST_BITS) - 1)) as usize];
        if entry != 0 {
            let len = u32::from(entry >> FAST_BITS);
            if len > available {
                return Err(Error::InvalidFormat(TRUNCATED));
            }
            reader.consume(len);
            return Ok(entry & ((1 << FAST_BITS) - 1));
        }
        // Codes longer than FAST_BITS (or the unused code of a single
        // distance code): walk the lengths, one input bit at a time. `first`
        // is the first code of length `len` and `index` its position in
        // `symbols` (RFC 1951 §3.2.2).
        let mut code: i32 = 0;
        let mut first: i32 = 0;
        let mut index: i32 = 0;
        for len in 1..=self.max_len {
            if len > available {
                return Err(Error::InvalidFormat(TRUNCATED));
            }
            code |= ((bits >> (len - 1)) & 1) as i32;
            let count = i32::from(self.counts[len as usize]);
            if code >= first && code - first < count {
                let symbol = self
                    .symbols
                    .get((index + code - first) as usize)
                    .copied()
                    .ok_or(Error::InvalidFormat(INVALID_CODE))?;
                reader.consume(len);
                return Ok(symbol);
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        Err(Error::InvalidFormat(INVALID_CODE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deflate::bits::BitWriter;

    /// RFC 1951 §3.2.2's worked example: lengths (3, 3, 3, 3, 3, 2, 4, 4)
    /// for A–H give codes 010, 011, 100, 101, 110, 00, 1110, 1111.
    #[test]
    fn rfc1951_section_3_2_2_example() {
        let lengths = [3, 3, 3, 3, 3, 2, 4, 4];
        let table = Huffman::new(&lengths, Kind::Complete).unwrap();
        let codes: [(u32, u32); 8] = [
            (0b010, 3),
            (0b011, 3),
            (0b100, 3),
            (0b101, 3),
            (0b110, 3),
            (0b00, 2),
            (0b1110, 4),
            (0b1111, 4),
        ];
        let mut out = Vec::new();
        let mut w = BitWriter::new(&mut out);
        for &(code, len) in codes.iter().rev() {
            w.code(code, len);
        }
        w.finish();
        let mut r = BitReader::new(&out);
        for symbol in (0..8u16).rev() {
            assert_eq!(table.decode(&mut r).unwrap(), symbol);
        }
    }

    /// Codes longer than the fast table decode through the slow path.
    #[test]
    fn decodes_fifteen_bit_codes() {
        // One code each of lengths 1..=14, and two of length 15: complete.
        let mut lengths: Vec<u8> = (1..=15).collect();
        lengths.push(15);
        let table = Huffman::new(&lengths, Kind::Complete).unwrap();
        // Symbol 15 (the second 15-bit code) is all ones.
        let mut out = Vec::new();
        let mut w = BitWriter::new(&mut out);
        w.code(0x7FFF, 15);
        w.code(0x7FFE, 15);
        w.code(0b10, 2);
        w.finish();
        let mut r = BitReader::new(&out);
        assert_eq!(table.decode(&mut r).unwrap(), 15);
        assert_eq!(table.decode(&mut r).unwrap(), 14);
        assert_eq!(table.decode(&mut r).unwrap(), 1);
    }

    /// RFC 1951 §3.2.2: three 1-bit codes do not fit a prefix code.
    #[test]
    fn rejects_over_subscribed_code() {
        let r = Huffman::new(&[1, 1, 1], Kind::Complete);
        assert!(matches!(r, Err(Error::InvalidFormat(OVERSUBSCRIBED_CODE))));
        let r = Huffman::new(&[1, 1, 1], Kind::Distance);
        assert!(matches!(r, Err(Error::InvalidFormat(OVERSUBSCRIBED_CODE))));
    }

    #[test]
    fn rejects_incomplete_code() {
        let r = Huffman::new(&[1, 2], Kind::Complete);
        assert!(matches!(r, Err(Error::InvalidFormat(INCOMPLETE_CODE))));
        // No codes at all is incomplete too, outside the distance code.
        let r = Huffman::new(&[0; 19], Kind::Complete);
        assert!(matches!(r, Err(Error::InvalidFormat(INCOMPLETE_CODE))));
        // §3.2.7 allows only one distance code of length one, not longer.
        let r = Huffman::new(&[0, 2], Kind::Distance);
        assert!(matches!(r, Err(Error::InvalidFormat(INCOMPLETE_CODE))));
        let r = Huffman::new(&[1, 2], Kind::Distance);
        assert!(matches!(r, Err(Error::InvalidFormat(INCOMPLETE_CODE))));
        // A single literal/length code is not allowed either.
        let r = Huffman::new(&[1], Kind::Complete);
        assert!(matches!(r, Err(Error::InvalidFormat(INCOMPLETE_CODE))));
    }

    /// RFC 1951 §3.2.7: a single distance code uses one bit; the other
    /// one-bit code is unused and is an error when it appears.
    #[test]
    fn single_distance_code() {
        let table = Huffman::new(&[0, 0, 1], Kind::Distance).unwrap();
        let mut r = BitReader::new(&[0b0000_0010]);
        assert_eq!(table.decode(&mut r).unwrap(), 2);
        assert_eq!(
            table.decode(&mut r),
            Err(Error::InvalidFormat(INVALID_CODE))
        );
    }

    /// RFC 1951 §3.2.7: "One distance code of zero bits means that there are
    /// no distance codes used at all".
    #[test]
    fn no_distance_codes() {
        let table = Huffman::new(&[0], Kind::Distance).unwrap();
        let mut r = BitReader::new(&[0]);
        assert_eq!(
            table.decode(&mut r),
            Err(Error::InvalidFormat(NO_DISTANCE_CODES))
        );
    }

    #[test]
    fn truncated_code_is_an_error() {
        // 256 codes of length 8: complete, and nothing to read.
        let table = Huffman::new(&[8u8; 256], Kind::Complete).unwrap();
        let mut r = BitReader::new(&[]);
        assert_eq!(table.decode(&mut r), Err(Error::InvalidFormat(TRUNCATED)));
        // A long code cut short.
        let mut lengths: Vec<u8> = (1..=15).collect();
        lengths.push(15);
        let table = Huffman::new(&lengths, Kind::Complete).unwrap();
        let mut r = BitReader::new(&[0xFF]);
        assert_eq!(table.decode(&mut r), Err(Error::InvalidFormat(TRUNCATED)));
    }

    #[test]
    fn rejects_lengths_above_fifteen_and_oversized_alphabets() {
        assert!(Huffman::new(&[16, 1], Kind::Complete).is_err());
        assert!(Huffman::new(&[9u8; 289], Kind::Complete).is_err());
    }
}
