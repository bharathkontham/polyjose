//! Strict DER (ITU-T X.690 §8, §10, §11) for exactly the tags the key
//! structures use: INTEGER, BIT STRING, OCTET STRING, NULL, OBJECT IDENTIFIER,
//! SEQUENCE, and the context tags `[0]`/`[1]` in their explicit (0xA0/0xA1) and
//! implicit primitive (0x81) forms (ADR 0018 §1).
//!
//! Definite lengths in the fewest octets (X.690 §10.1, §8.1.3), minimal
//! INTEGERs (§8.3.2), primitive strings only (§10.2), minimal OID
//! subidentifiers (§8.19.2), low-tag-number form only (§8.1.2.4) and no data
//! after the outermost element (§8.1.1). BER is rejected (ADR 0018 §2).
//!
//! - [`Reader`] reads one element at a time from a borrowed buffer of at most
//!   [`MAX_INPUT_LEN`] octets and returns sub-slices, so secret contents are
//!   never copied. Constructed elements are entered by asking for a new
//!   reader over their contents: the call stack never follows the input's
//!   nesting.
//! - [`check_well_formed`] validates values polyjose ignores (PKCS#8
//!   attributes, unsupported algorithm parameters) with an explicit,
//!   bounded stack.
//! - [`Writer`] writes into a [`Zeroizing`] buffer sized exactly up front,
//!   so it never reallocates and leaves no unzeroized copy behind.
//!
//! Every error is `InvalidKey` with a static detail; no input octet ever
//! reaches an error.

use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// The largest DER input the reader accepts: 64 KiB. A 4096-bit RSA SPKI is
/// about 550 octets, so this bounds work and memory without rejecting any
/// supported key (ADR 0018 §2; research.md §4).
pub(crate) const MAX_INPUT_LEN: usize = 64 * 1024;

/// UNIVERSAL 2: INTEGER (X.690 §8.3).
pub(crate) const INTEGER: u8 = 0x02;
/// UNIVERSAL 3, primitive: BIT STRING (X.690 §8.6, §10.2).
pub(crate) const BIT_STRING: u8 = 0x03;
/// UNIVERSAL 4, primitive: OCTET STRING (X.690 §8.7, §10.2).
pub(crate) const OCTET_STRING: u8 = 0x04;
/// UNIVERSAL 6: OBJECT IDENTIFIER (X.690 §8.19).
pub(crate) const OID: u8 = 0x06;
/// UNIVERSAL 16, constructed: SEQUENCE and SEQUENCE OF (X.690 §8.9, §8.10).
pub(crate) const SEQUENCE: u8 = 0x30;
/// UNIVERSAL 17, constructed: SET and SET OF (X.690 §8.11, §8.12).
pub(crate) const SET: u8 = 0x31;
/// Context-specific `[0]`, constructed: an EXPLICIT `[0]` (X.690 §8.14.2)
/// or an IMPLICIT `[0]` of a constructed type (RFC 5958 §2 attributes).
pub(crate) const CONTEXT_0: u8 = 0xA0;
/// Context-specific `[1]`, constructed: an EXPLICIT `[1]` (RFC 5915 §3
/// publicKey).
pub(crate) const CONTEXT_1: u8 = 0xA1;
/// Context-specific `[1]`, primitive: an IMPLICIT `[1]` BIT STRING
/// (RFC 5958 §2 publicKey, an IMPLICIT TAGS module).
pub(crate) const CONTEXT_1_PRIMITIVE: u8 = 0x81;

/// The constructed bit of an identifier octet (X.690 §8.1.2.5).
const CONSTRUCTED: u8 = 0x20;

/// One DER element: its identifier octet, its whole encoding (identifier,
/// length and contents octets) and its contents octets (X.690 §8.1.1).
///
/// Both slices borrow from the reader's input; nothing is copied. There is
/// deliberately no `Debug`: the contents may be secret.
#[derive(Clone, Copy)]
pub(crate) struct Element<'a> {
    /// The identifier octet (X.690 §8.1.2), always in low-tag-number form.
    pub(crate) tag: u8,
    /// The complete encoding of the element.
    pub(crate) encoding: &'a [u8],
    /// The contents octets (X.690 §8.1.4).
    pub(crate) contents: &'a [u8],
}

/// A strict, non-recursive DER reader over a borrowed buffer.
///
/// Each accessor reads one element from the front and returns sub-slices of
/// the input, so secret contents are never copied. A constructed element is
/// read by asking for a new `Reader` over its contents, so the call stack
/// never grows with the input's nesting.
#[derive(Clone, Copy)]
pub(crate) struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    /// A reader over `input`, which must be at most [`MAX_INPUT_LEN`] octets.
    pub(crate) fn new(input: &'a [u8]) -> Result<Self> {
        if input.len() > MAX_INPUT_LEN {
            return Err(Error::InvalidKey("DER input too large"));
        }
        Ok(Reader { rest: input })
    }

    /// Whether every octet has been read.
    pub(crate) fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    /// The identifier octet of the next element, without reading it.
    pub(crate) fn peek_tag(&self) -> Option<u8> {
        self.rest.first().copied()
    }

    /// Reads one element of any tag, checking only its framing:
    ///
    /// - The identifier is in low-tag-number form (X.690 §8.1.2.2): tag
    ///   number 31 starts the high-tag-number form of §8.1.2.4, which no key
    ///   structure uses.
    /// - The length is definite (§8.1.3.6 indefinite form is BER only,
    ///   §10.1) and in the fewest octets (§10.1): the short form for 0–127
    ///   (§8.1.3.4), otherwise a long form (§8.1.3.5) without leading zero
    ///   octets, of at most four octets.
    /// - The contents are present in full (§8.1.3, §8.1.4).
    pub(crate) fn element(&mut self) -> Result<Element<'a>> {
        let input = self.rest;
        let (&tag, after_tag) = input
            .split_first()
            .ok_or(Error::InvalidKey("DER truncated"))?;
        if tag & 0x1F == 0x1F {
            return Err(Error::InvalidKey("DER high-tag-number form"));
        }
        let (&first, mut after_len) = after_tag
            .split_first()
            .ok_or(Error::InvalidKey("DER truncated"))?;
        let len = match first {
            0x00..=0x7F => usize::from(first),
            0x80 => return Err(Error::InvalidKey("DER indefinite length")),
            0x81..=0x84 => {
                let count = usize::from(first & 0x7F);
                let (octets, rest) = after_len
                    .split_at_checked(count)
                    .ok_or(Error::InvalidKey("DER truncated"))?;
                // The fewest octets (§10.1): no leading zero, and the long
                // form only for lengths the short form cannot hold.
                if octets.first() == Some(&0) {
                    return Err(Error::InvalidKey("DER length not minimal"));
                }
                let len = octets
                    .iter()
                    .fold(0usize, |acc, &octet| (acc << 8) | usize::from(octet));
                if len < 0x80 {
                    return Err(Error::InvalidKey("DER length not minimal"));
                }
                after_len = rest;
                len
            }
            _ => return Err(Error::InvalidKey("DER length too long")),
        };
        let header = input.len() - after_len.len();
        let (contents, rest) = after_len
            .split_at_checked(len)
            .ok_or(Error::InvalidKey("DER length exceeds input"))?;
        self.rest = rest;
        Ok(Element {
            tag,
            encoding: &input[..header + len],
            contents,
        })
    }

    /// Reads one element whose identifier octet is exactly `tag`.
    pub(crate) fn expect(&mut self, tag: u8) -> Result<Element<'a>> {
        let element = self.element()?;
        if element.tag == tag {
            Ok(element)
        } else {
            Err(Error::InvalidKey("DER unexpected tag"))
        }
    }

    /// Reads the next element only if its identifier octet is `tag`
    /// (an OPTIONAL component, X.680 §25.8), otherwise reads nothing.
    pub(crate) fn optional(&mut self, tag: u8) -> Result<Option<Element<'a>>> {
        if self.peek_tag() == Some(tag) {
            self.element().map(Some)
        } else {
            Ok(None)
        }
    }

    /// Reads a SEQUENCE (X.690 §8.9) and returns a reader over its contents.
    pub(crate) fn sequence(&mut self) -> Result<Reader<'a>> {
        self.explicit(SEQUENCE)
    }

    /// Reads a constructed element tagged `tag`, such as an EXPLICIT `[0]`
    /// (X.690 §8.14.2 c: the contents are the complete encoding of the
    /// inner value), and returns a reader over its contents.
    pub(crate) fn explicit(&mut self, tag: u8) -> Result<Reader<'a>> {
        let element = self.expect(tag)?;
        Ok(Reader {
            rest: element.contents,
        })
    }

    /// Reads an INTEGER (X.690 §8.3) and returns its two's-complement
    /// contents octets, which must be minimal (§8.3.2).
    pub(crate) fn integer(&mut self) -> Result<&'a [u8]> {
        let contents = self.expect(INTEGER)?.contents;
        check_integer(contents)?;
        Ok(contents)
    }

    /// Reads a non-negative INTEGER and returns its magnitude, big-endian in
    /// the fewest octets: the leading 0x00 that keeps the sign bit clear
    /// (X.690 §8.3.3) is dropped, and zero is the single octet 0x00.
    pub(crate) fn unsigned_integer(&mut self) -> Result<&'a [u8]> {
        let contents = self.integer()?;
        match contents {
            [first, ..] if first & 0x80 != 0 => Err(Error::InvalidKey("DER INTEGER negative")),
            [0x00, magnitude @ ..] if !magnitude.is_empty() => Ok(magnitude),
            _ => Ok(contents),
        }
    }

    /// Reads a non-negative INTEGER of at most 255, such as a `version`
    /// (RFC 5958 §2, RFC 5915 §3).
    pub(crate) fn small_unsigned(&mut self) -> Result<u8> {
        match self.unsigned_integer()? {
            [value] => Ok(*value),
            _ => Err(Error::InvalidKey("DER INTEGER out of range")),
        }
    }

    /// Reads a primitive OCTET STRING (X.690 §8.7) and returns its contents.
    /// The constructed form is BER only (§10.2).
    pub(crate) fn octet_string(&mut self) -> Result<&'a [u8]> {
        Ok(self.string(OCTET_STRING)?.contents)
    }

    /// Reads a primitive BIT STRING (X.690 §8.6) with no unused bits and
    /// returns the octets after its initial octet; see
    /// [`Reader::implicit_bit_string`].
    pub(crate) fn bit_string(&mut self) -> Result<&'a [u8]> {
        self.implicit_bit_string(BIT_STRING)
    }

    /// Reads a primitive BIT STRING under the identifier `tag` (BIT_STRING,
    /// or an IMPLICIT tag such as the RFC 5958 §2 `[1]` publicKey, 0x81) and
    /// returns the octets after the initial octet.
    ///
    /// The initial octet, always present (X.690 §8.6.2.3), counts the unused
    /// bits of the last octet (§8.6.2.2). Every key polyjose reads from a
    /// BIT STRING is a whole number of octets (RFC 5480 §2.2, RFC 8410 §4,
    /// RFC 3279 §2.3.1, RFC 5958 §2), so the count must be 0, which also
    /// satisfies DER's zero padding rule (§11.2.1) trivially.
    pub(crate) fn implicit_bit_string(&mut self, tag: u8) -> Result<&'a [u8]> {
        match self.string(tag)?.contents {
            [0x00, octets @ ..] => Ok(octets),
            [] => Err(Error::InvalidKey("DER BIT STRING empty")),
            [_, ..] => Err(Error::InvalidKey("DER BIT STRING has unused bits")),
        }
    }

    /// Reads a NULL (X.690 §8.8), whose contents must be empty (§8.8.2).
    ///
    /// Test-only: the one NULL in a supported key structure, the
    /// rsaEncryption parameters (RFC 3279 §2.3.1), is matched as part of a
    /// whole AlgorithmIdentifier template (`oid.rs`), and `check_well_formed`
    /// checks a NULL inside values polyjose ignores.
    #[cfg(test)]
    pub(crate) fn null(&mut self) -> Result<()> {
        /// UNIVERSAL 5: NULL (X.690 §8.8).
        const NULL: u8 = 0x05;
        if self.expect(NULL)?.contents.is_empty() {
            Ok(())
        } else {
            Err(Error::InvalidKey("DER NULL not empty"))
        }
    }

    /// Reads an OBJECT IDENTIFIER (X.690 §8.19) with minimal subidentifiers
    /// (§8.19.2) and returns its whole encoding, to compare with the `OID_*`
    /// constants of `oid.rs`.
    pub(crate) fn oid(&mut self) -> Result<&'a [u8]> {
        let element = self.expect(OID)?;
        check_oid(element.contents)?;
        Ok(element.encoding)
    }

    /// Reads a primitive string element tagged `tag`, naming the BER-only
    /// constructed form (X.690 §10.2) in the error.
    fn string(&mut self, tag: u8) -> Result<Element<'a>> {
        let element = self.element()?;
        if element.tag == tag {
            Ok(element)
        } else if element.tag == tag | CONSTRUCTED {
            Err(Error::InvalidKey("DER constructed string"))
        } else {
            Err(Error::InvalidKey("DER unexpected tag"))
        }
    }

    /// Fails unless every octet has been read: no data may follow the last
    /// element (X.690 §8.1.1; RFC 5958 §2, RFC 5280 §4.1).
    pub(crate) fn finish(self) -> Result<()> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(Error::InvalidKey("DER trailing data"))
        }
    }
}

/// Checks INTEGER contents octets (X.690 §8.3): at least one octet
/// (§8.3.1), and minimal, so the first nine bits are neither all zero nor
/// all one (§8.3.2).
fn check_integer(contents: &[u8]) -> Result<()> {
    match contents {
        [] => Err(Error::InvalidKey("DER INTEGER empty")),
        [0x00, next, ..] if next & 0x80 == 0 => Err(Error::InvalidKey("DER INTEGER not minimal")),
        [0xFF, next, ..] if next & 0x80 != 0 => Err(Error::InvalidKey("DER INTEGER not minimal")),
        _ => Ok(()),
    }
}

/// Checks OBJECT IDENTIFIER contents octets (X.690 §8.19): one or more
/// subidentifiers (§8.19.1), each in the fewest octets, so its leading octet
/// is never 0x80, and each ending in an octet with bit 8 clear (§8.19.2).
fn check_oid(contents: &[u8]) -> Result<()> {
    let malformed = Err(Error::InvalidKey("DER OBJECT IDENTIFIER malformed"));
    if contents.last().is_none_or(|last| last & 0x80 != 0) {
        return malformed;
    }
    let mut at_start = true;
    for &octet in contents {
        if at_start && octet == 0x80 {
            return malformed;
        }
        at_start = octet & 0x80 == 0;
    }
    Ok(())
}

/// How many constructed elements [`check_well_formed`] follows inside each
/// other. The key structures nest at most four deep; attribute values and
/// unsupported algorithm parameters (an RFC 4055 §3.1 RSASSA-PSS-params, an
/// RFC 3279 §2.3.5 specifiedCurve) need a few more.
pub(crate) const MAX_DEPTH: usize = 16;

/// Checks that `contents` is a sequence of zero or more well-formed DER
/// elements, for values polyjose validates and then ignores: PKCS#8
/// attributes (RFC 5958 §2) and the parameters of an AlgorithmIdentifier
/// it does not support (RFC 5280 §4.1.1.2). With `set_of`, `contents` are
/// the components of a SET OF and must be sorted (X.690 §11.6).
///
/// The walk is iterative, with an explicit stack of [`MAX_DEPTH`] levels, so
/// hostile nesting can't exhaust the call stack. It applies the framing
/// rules of [`Reader::element`] to every element, and to every UNIVERSAL
/// one the DER content rules that need no schema:
///
/// - end-of-contents only exists in the indefinite form (X.690 §8.1.5);
/// - strings are primitive (§10.2), SEQUENCE and SET constructed (§8.9.1,
///   §8.11.1), the other simple types primitive (§8.2.1, §8.3.1, §8.8.1,
///   §8.19.1);
/// - BOOLEAN is 0x00 or 0xFF (§11.1), INTEGER and ENUMERATED minimal
///   (§8.3.2, §8.4), NULL empty (§8.8.2), OBJECT IDENTIFIER and
///   RELATIVE-OID subidentifiers minimal (§8.19.2, §8.20.2);
/// - a BIT STRING has an initial octet of at most 7 (§8.6.2.2), 0 when no
///   octet follows (§8.6.2.3), and zero unused bits (§11.2.1);
/// - the components of every SET are in SET OF order: their whole
///   encodings ascending as octet strings (§11.6).
///
/// A SET and a SET OF have the same tag, UNIVERSAL 17 (X.690 §8.11.1,
/// §8.12.1), and this walk has no schema to tell them apart, so every
/// nested SET is checked as a SET OF. The SET rule of §10.3 orders by tag
/// instead (X.680 §8.6: class, then number), and the two orders are not
/// the same: the identifier octet puts the P/C bit (bit 6, §8.1.2.5)
/// between the class (bits 8-7) and the number (bits 5-1) (§8.1.2.2), so
/// a primitive `[1]` (0x81) sorts before a constructed `[0]` (0xA0) as
/// octets but after it by tag. A DER SET whose components are in tag
/// order but not in octet order is therefore rejected. This fails closed
/// on values polyjose ignores; the SETs a PKCS#8 attribute is built from,
/// Attributes (RFC 5958 §2) and attrValues (RFC 5652 §5.3), are SET OFs.
pub(crate) fn check_well_formed(contents: &[u8], set_of: bool) -> Result<()> {
    #[derive(Clone, Copy)]
    struct Level<'a> {
        reader: Reader<'a>,
        sorted: bool,
        previous: Option<&'a [u8]>,
    }
    let empty = Level {
        reader: Reader { rest: &[] },
        sorted: false,
        previous: None,
    };
    let mut stack = [empty; MAX_DEPTH + 1];
    stack[0] = Level {
        reader: Reader::new(contents)?,
        sorted: set_of,
        previous: None,
    };
    let mut depth: usize = 1;
    while let Some(level) = depth.checked_sub(1).and_then(|top| stack.get_mut(top)) {
        if level.reader.is_empty() {
            depth -= 1;
            continue;
        }
        let element = level.reader.element()?;
        if level.sorted {
            if level
                .previous
                .is_some_and(|previous| !set_of_ordered(previous, element.encoding))
            {
                return Err(Error::InvalidKey("DER SET OF not sorted"));
            }
            level.previous = Some(element.encoding);
        }
        check_universal(element)?;
        if element.tag & CONSTRUCTED != 0 {
            let next = stack
                .get_mut(depth)
                .ok_or(Error::InvalidKey("DER nesting too deep"))?;
            *next = Level {
                reader: Reader {
                    rest: element.contents,
                },
                sorted: element.tag == SET,
                previous: None,
            };
            depth += 1;
        }
    }
    Ok(())
}

/// Whether `first` may precede `second` in a SET OF: X.690 §11.6 compares
/// the encodings as octet strings, padding the shorter at its trailing end
/// with 0x00 octets, and requires ascending order (equal is allowed).
fn set_of_ordered(first: &[u8], second: &[u8]) -> bool {
    let len = first.len().max(second.len());
    for i in 0..len {
        let a = first.get(i).copied().unwrap_or(0);
        let b = second.get(i).copied().unwrap_or(0);
        if a != b {
            return a < b;
        }
    }
    true
}

/// The schema-free DER content rules for one element; see
/// [`check_well_formed`]. Non-UNIVERSAL elements are framing-checked only.
fn check_universal(element: Element<'_>) -> Result<()> {
    if element.tag & 0xC0 != 0 {
        return Ok(());
    }
    let number = element.tag & 0x1F;
    let constructed = element.tag & CONSTRUCTED != 0;
    // SEQUENCE, SET, EXTERNAL, EMBEDDED PDV and CHARACTER STRING are
    // always constructed (X.690 §8.9.1, §8.11.1, §8.18.1, §8.17, §8.24);
    // everything else in the UNIVERSAL class is primitive in DER.
    let always_constructed = matches!(number, 8 | 11 | 16 | 17 | 29);
    if constructed != always_constructed {
        // Strings (BIT, OCTET, ObjectDescriptor, the character strings and
        // the time types) have a BER-only constructed form (§10.2).
        let string = matches!(number, 3 | 4 | 7 | 12 | 18..=30) && number != 29;
        return if constructed && string {
            Err(Error::InvalidKey("DER constructed string"))
        } else {
            Err(Error::InvalidKey("DER unexpected tag"))
        };
    }
    let contents = element.contents;
    match number {
        0 => Err(Error::InvalidKey("DER end-of-contents")),
        1 => match contents {
            [0x00] | [0xFF] => Ok(()),
            _ => Err(Error::InvalidKey("DER BOOLEAN not canonical")),
        },
        2 | 10 => check_integer(contents),
        3 => match contents {
            [] => Err(Error::InvalidKey("DER BIT STRING empty")),
            [0x00, ..] => Ok(()),
            [unused, .., last] if *unused <= 7 && last & ((1u8 << unused) - 1) == 0 => Ok(()),
            _ => Err(Error::InvalidKey("DER BIT STRING malformed")),
        },
        5 if contents.is_empty() => Ok(()),
        5 => Err(Error::InvalidKey("DER NULL not empty")),
        6 | 13 => check_oid(contents),
        _ => Ok(()),
    }
}

/// The length of an element's identifier and length octets for
/// `content_len` contents octets: one identifier octet (low-tag-number
/// form) and the fewest length octets (X.690 §10.1, §8.1.3.4, §8.1.3.5).
fn header_len(content_len: usize) -> usize {
    if content_len < 0x80 {
        2
    } else {
        2 + length_octets(content_len)
    }
}

/// How many octets the long form needs for `len` (X.690 §8.1.3.5).
fn length_octets(len: usize) -> usize {
    let bits = usize::BITS - len.leading_zeros();
    bits.div_ceil(8) as usize
}

/// The length of a whole element with `content_len` contents octets.
pub(crate) fn encoded_len(content_len: usize) -> usize {
    header_len(content_len) + content_len
}

/// The length of a BIT STRING element (or an IMPLICIT one) carrying
/// `octets_len` octets after its initial octet (X.690 §8.6.2).
pub(crate) fn bit_string_len(octets_len: usize) -> usize {
    encoded_len(1 + octets_len)
}

/// The non-negative INTEGER `magnitude` (big-endian, leading zero octets
/// allowed) in its minimal two's-complement contents (X.690 §8.3.2, §8.3.3):
/// leading zeros dropped, zero as one 0x00 octet, and whether a 0x00 must be
/// prefixed to keep the sign bit clear.
fn minimal_unsigned(magnitude: &[u8]) -> (&[u8], bool) {
    let start = magnitude
        .iter()
        .position(|&octet| octet != 0)
        .unwrap_or(magnitude.len());
    match magnitude.get(start..) {
        Some(digits @ [first, ..]) => (digits, first & 0x80 != 0),
        _ => (&[0x00], false),
    }
}

/// The length of the INTEGER element [`Writer::unsigned_integer`] writes for
/// `magnitude`.
pub(crate) fn unsigned_integer_len(magnitude: &[u8]) -> usize {
    let (digits, pad) = minimal_unsigned(magnitude);
    encoded_len(digits.len() + usize::from(pad))
}

/// A DER writer into a [`Zeroizing`] buffer of a length planned up front.
///
/// Callers compute the exact output length with [`encoded_len`] and friends
/// and write each header before its contents, so the buffer is allocated
/// once and never grows: a reallocation would free an unzeroized copy of
/// whatever secret octets were already written. A write past the plan, or a
/// [`Writer::finish`] short of it, fails instead of reallocating.
pub(crate) struct Writer {
    buf: Zeroizing<Vec<u8>>,
    planned: usize,
}

impl Writer {
    /// A writer for exactly `planned` octets, at most [`MAX_INPUT_LEN`] so
    /// that everything written can be read back.
    pub(crate) fn new(planned: usize) -> Result<Self> {
        if planned > MAX_INPUT_LEN {
            return Err(Error::InvalidKey("DER output too large"));
        }
        Ok(Writer {
            buf: Zeroizing::new(Vec::with_capacity(planned)),
            planned,
        })
    }

    /// Appends `bytes` as they are, such as a template from `oid.rs`.
    pub(crate) fn raw(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > self.planned - self.buf.len() {
            return Err(Error::InvalidKey("DER output length mismatch"));
        }
        self.buf.extend_from_slice(bytes);
        Ok(())
    }

    /// Writes the identifier octet `tag` and the length octets for
    /// `content_len`, in the fewest octets (X.690 §10.1); the caller then
    /// writes exactly `content_len` contents octets.
    pub(crate) fn header(&mut self, tag: u8, content_len: usize) -> Result<()> {
        let mut header = [0u8; 2 + core::mem::size_of::<usize>()];
        header[0] = tag;
        let used = if content_len < 0x80 {
            header[1] = content_len as u8;
            2
        } else {
            let count = length_octets(content_len);
            header[1] = 0x80 | count as u8;
            let be = content_len.to_be_bytes();
            header[2..2 + count].copy_from_slice(&be[be.len() - count..]);
            2 + count
        };
        self.raw(&header[..used])
    }

    /// Writes a whole element: `tag`, the length and `contents`.
    pub(crate) fn element(&mut self, tag: u8, contents: &[u8]) -> Result<()> {
        self.header(tag, contents.len())?;
        self.raw(contents)
    }

    /// Writes a primitive BIT STRING under `tag` (BIT_STRING or an IMPLICIT
    /// tag) with an initial octet of 0: `octets` are a whole number of
    /// octets (X.690 §8.6.2.2, §11.2.1).
    pub(crate) fn bit_string(&mut self, tag: u8, octets: &[u8]) -> Result<()> {
        self.header(tag, 1 + octets.len())?;
        self.raw(&[0x00])?;
        self.raw(octets)
    }

    /// Writes the non-negative INTEGER `magnitude` (big-endian) in minimal
    /// two's complement (X.690 §8.3.2, §8.3.3).
    pub(crate) fn unsigned_integer(&mut self, magnitude: &[u8]) -> Result<()> {
        let (digits, pad) = minimal_unsigned(magnitude);
        self.header(INTEGER, digits.len() + usize::from(pad))?;
        if pad {
            self.raw(&[0x00])?;
        }
        self.raw(digits)
    }

    /// The finished encoding, which must be exactly the planned length.
    pub(crate) fn finish(self) -> Result<Zeroizing<Vec<u8>>> {
        if self.buf.len() == self.planned {
            Ok(self.buf)
        } else {
            Err(Error::InvalidKey("DER output length mismatch"))
        }
    }
}

/// Test-only access to the committed key fixtures in `tests/data/keys/`,
/// shared by the DER, PKCS#8 and SPKI tests.
#[cfg(test)]
pub(super) mod fixtures {
    use std::path::{Path, PathBuf};

    use crate::json::{self, Value};

    fn dir(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/keys")
            .join(name)
    }

    /// A fixture as DER: `.der` files as they are, `.pem` files decoded by
    /// the `pem-rfc7468` oracle (a dev-dependency only).
    pub(crate) fn load(dir_name: &str, file: &str) -> Vec<u8> {
        let path = dir(dir_name).join(file);
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        if file.ends_with(".pem") {
            pem_rfc7468::decode_vec(&bytes)
                .unwrap_or_else(|e| panic!("{file}: {e}"))
                .1
        } else {
            bytes
        }
    }

    /// The `.der` and `.pem` files in a fixture directory whose names match
    /// `keep`, sorted.
    pub(crate) fn files(dir_name: &str, keep: impl Fn(&str) -> bool) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir(dir_name))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| name.ends_with(".der") || name.ends_with(".pem"))
            .filter(|name| keep(name))
            .collect();
        names.sort();
        names
    }

    /// One entry of `negative/manifest.json`.
    pub(crate) struct Negative {
        pub(crate) id: String,
        pub(crate) file: String,
        pub(crate) expect: String,
    }

    /// Every entry of `negative/manifest.json`.
    pub(crate) fn negatives() -> Vec<Negative> {
        let bytes = std::fs::read(dir("negative").join("manifest.json")).unwrap();
        let manifest = json::parse(&bytes).unwrap();
        let field =
            |entry: &Value, name: &str| entry.get(name).and_then(Value::as_str).unwrap().to_owned();
        manifest
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| Negative {
                id: field(entry, "id"),
                file: field(entry, "file"),
                expect: field(entry, "expect"),
            })
            .collect()
    }

    /// The manifest entry `id` loaded as DER.
    pub(crate) fn negative(id: &str) -> Vec<u8> {
        let entry = negatives().into_iter().find(|n| n.id == id).unwrap();
        load("negative", &entry.file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invalid(result: Result<impl Sized>) -> &'static str {
        match result {
            Err(Error::InvalidKey(detail)) => detail,
            Err(other) => panic!("expected InvalidKey, got {other:?}"),
            Ok(_) => panic!("expected InvalidKey, got Ok"),
        }
    }

    /// Reads exactly one element from `input` and requires nothing after it.
    fn one(input: &[u8]) -> Result<Element<'_>> {
        let mut reader = Reader::new(input)?;
        let element = reader.element()?;
        reader.finish()?;
        Ok(element)
    }

    #[test]
    fn reads_a_short_form_element() {
        let input = [0x04, 0x02, 0xAB, 0xCD];
        let element = one(&input).unwrap();
        assert_eq!(element.tag, 0x04);
        assert_eq!(element.contents, &[0xAB, 0xCD]);
        assert_eq!(element.encoding, &input);
    }

    #[test]
    fn reads_long_form_lengths_of_one_to_four_octets() {
        // X.690 §8.1.3.5: long form, the first octet gives the count.
        for (header, len) in [
            (vec![0x04, 0x81, 0x80], 0x80usize),
            (vec![0x04, 0x81, 0xFF], 0xFF),
            (vec![0x04, 0x82, 0x01, 0x00], 0x100),
            (vec![0x04, 0x82, 0xFF, 0xF0], 0xFFF0),
        ] {
            let mut input = header.clone();
            input.resize(header.len() + len, 0x5A);
            let element = one(&input).unwrap();
            assert_eq!(element.contents.len(), len, "{header:02x?}");
        }
    }

    #[test]
    fn long_form_for_a_short_length_is_rejected() {
        // X.690 §10.1: "the definite form ... shall be used, encoded in the
        // minimum number of octets"; lengths up to 127 use the short form.
        assert_eq!(
            invalid(one(&[0x04, 0x81, 0x01, 0x00])),
            "DER length not minimal"
        );
        assert_eq!(invalid(one(&[0x04, 0x81, 0x7F])), "DER length not minimal");
    }

    #[test]
    fn leading_zero_length_octets_are_rejected() {
        // X.690 §10.1: fewest octets, so no leading 0x00 length octet.
        let mut input = vec![0x04, 0x82, 0x00, 0x80];
        input.resize(4 + 0x80, 0);
        assert_eq!(invalid(one(&input)), "DER length not minimal");
    }

    #[test]
    fn indefinite_length_is_rejected() {
        // X.690 §10.1 and §8.1.3.6: the indefinite form is BER only.
        assert_eq!(
            invalid(one(&[0x30, 0x80, 0x05, 0x00, 0x00, 0x00])),
            "DER indefinite length"
        );
    }

    #[test]
    fn lengths_of_five_or_more_octets_are_rejected() {
        // At most four length octets (the 64 KiB cap needs three), and 0xFF
        // is reserved (X.690 §8.1.3.5 c).
        assert_eq!(
            invalid(one(&[0x04, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00])),
            "DER length too long"
        );
        assert_eq!(invalid(one(&[0x04, 0xFF])), "DER length too long");
    }

    #[test]
    fn a_length_beyond_the_input_is_rejected() {
        // X.690 §8.1.3: the contents must be present in full.
        assert_eq!(
            invalid(one(&[0x04, 0x03, 0x01, 0x02])),
            "DER length exceeds input"
        );
        assert_eq!(
            invalid(one(&[0x04, 0x82, 0x01, 0x00, 0x00])),
            "DER length exceeds input"
        );
    }

    #[test]
    fn truncated_headers_are_rejected() {
        assert_eq!(invalid(one(&[])), "DER truncated");
        assert_eq!(invalid(one(&[0x04])), "DER truncated");
        assert_eq!(invalid(one(&[0x04, 0x82, 0x01])), "DER truncated");
    }

    #[test]
    fn high_tag_number_form_is_rejected() {
        // X.690 §8.1.2.4: tag number 31 in the first octet means the
        // high-tag-number form, which none of the key structures uses.
        assert_eq!(
            invalid(one(&[0x3F, 0x10, 0x00])),
            "DER high-tag-number form"
        );
        assert_eq!(
            invalid(one(&[0x9F, 0x01, 0x00])),
            "DER high-tag-number form"
        );
    }

    #[test]
    fn finish_rejects_leftover_bytes() {
        // X.690 §8.1.1 and RFC 5958 §2 / RFC 5280 §4.1: exactly one
        // element, no data after it.
        assert_eq!(invalid(one(&[0x05, 0x00, 0x00])), "DER trailing data");
        let mut reader = Reader::new(&[0x05, 0x00, 0x05, 0x00]).unwrap();
        reader.element().unwrap();
        assert_eq!(invalid(reader.finish()), "DER trailing data");
    }

    #[test]
    fn the_input_is_capped_at_64_kib() {
        // One OCTET STRING filling the cap exactly: 4 header octets plus
        // 0xFFFC contents octets is 65,536.
        let mut input = vec![0x04, 0x82, 0xFF, 0xFC];
        input.resize(4 + 0xFFFC, 0);
        assert_eq!(input.len(), MAX_INPUT_LEN);
        assert!(one(&input).is_ok());
        input.push(0);
        assert_eq!(invalid(Reader::new(&input)), "DER input too large");
    }

    #[test]
    fn elements_are_sub_slices_of_the_input() {
        let input = [0x30, 0x04, 0x04, 0x02, 0xA5, 0xA5];
        let element = one(&input).unwrap();
        let range = input.as_ptr_range();
        assert!(range.contains(&element.contents.as_ptr()));
        assert!(range.contains(&element.encoding.as_ptr()));
    }

    /// A reader over `input` that must yield `read`'s value and then end.
    fn read_all<'a, T>(
        input: &'a [u8],
        read: impl FnOnce(&mut Reader<'a>) -> Result<T>,
    ) -> Result<T> {
        let mut reader = Reader::new(input)?;
        let value = read(&mut reader)?;
        reader.finish()?;
        Ok(value)
    }

    #[test]
    fn expect_checks_the_tag() {
        let element = read_all(&[0x05, 0x00], |r| r.expect(0x05)).unwrap();
        assert_eq!(element.contents, &[] as &[u8]);
        assert_eq!(
            invalid(read_all(&[0x05, 0x00], |r| r.expect(0x04))),
            "DER unexpected tag"
        );
        assert_eq!(invalid(read_all(&[], |r| r.expect(0x04))), "DER truncated");
    }

    #[test]
    fn sequence_and_explicit_tags_read_their_contents() {
        // SEQUENCE (X.690 §8.9) and an EXPLICIT [0] (§8.14.2 b) are both
        // constructed; their contents are read by a nested reader.
        let input = [0x30, 0x06, 0xA0, 0x02, 0x05, 0x00, 0x05, 0x00];
        let (first, second) = read_all(&input, |r| {
            let mut seq = r.sequence()?;
            let mut tagged = seq.explicit(0xA0)?;
            tagged.null()?;
            tagged.finish()?;
            seq.null()?;
            seq.finish()?;
            Ok((input[2], input[6]))
        })
        .unwrap();
        assert_eq!((first, second), (0xA0, 0x05));
        assert_eq!(
            invalid(read_all(&[0x31, 0x00], |r| r.sequence().map(|_| ()))),
            "DER unexpected tag"
        );
    }

    #[test]
    fn optional_reads_only_a_matching_tag() {
        let input = [0x81, 0x01, 0x00, 0x05, 0x00];
        read_all(&input, |r| {
            assert!(r.optional(0xA0)?.is_none());
            assert_eq!(r.optional(0x81)?.map(|e| e.contents), Some(&[0u8][..]));
            assert!(r.optional(0x81)?.is_none());
            r.null()
        })
        .unwrap();
    }

    #[test]
    fn integers_must_be_minimal() {
        // X.690 §8.3.2: the first nine bits are neither all zero nor all
        // one; §8.3.1: at least one contents octet.
        for ok in [
            &[0x02, 0x01, 0x00][..],
            &[0x02, 0x01, 0x7F],
            &[0x02, 0x02, 0x00, 0x80],
            &[0x02, 0x01, 0x80],
            &[0x02, 0x02, 0xFF, 0x7F],
        ] {
            let contents = read_all(ok, Reader::integer).unwrap();
            assert_eq!(contents, &ok[2..]);
        }
        for (bad, why) in [
            (&[0x02, 0x00][..], "DER INTEGER empty"),
            (&[0x02, 0x02, 0x00, 0x00], "DER INTEGER not minimal"),
            (&[0x02, 0x02, 0x00, 0x7F], "DER INTEGER not minimal"),
            (&[0x02, 0x02, 0xFF, 0x80], "DER INTEGER not minimal"),
            (&[0x02, 0x02, 0xFF, 0xFF], "DER INTEGER not minimal"),
        ] {
            assert_eq!(invalid(read_all(bad, Reader::integer)), why, "{bad:02x?}");
        }
    }

    #[test]
    fn unsigned_integers_reject_negatives_and_drop_the_sign_octet() {
        // X.690 §8.3.3: two's complement, so a set high bit is negative.
        assert_eq!(
            read_all(&[0x02, 0x02, 0x00, 0x80], Reader::unsigned_integer).unwrap(),
            &[0x80]
        );
        assert_eq!(
            read_all(&[0x02, 0x01, 0x00], Reader::unsigned_integer).unwrap(),
            &[0x00]
        );
        assert_eq!(
            read_all(&[0x02, 0x02, 0x01, 0x00], Reader::unsigned_integer).unwrap(),
            &[0x01, 0x00]
        );
        assert_eq!(
            invalid(read_all(&[0x02, 0x01, 0x80], Reader::unsigned_integer)),
            "DER INTEGER negative"
        );
        assert_eq!(
            invalid(read_all(
                &[0x02, 0x02, 0xFF, 0x00],
                Reader::unsigned_integer
            )),
            "DER INTEGER negative"
        );
    }

    #[test]
    fn small_unsigned_reads_versions() {
        assert_eq!(
            read_all(&[0x02, 0x01, 0x00], Reader::small_unsigned).unwrap(),
            0
        );
        assert_eq!(
            read_all(&[0x02, 0x01, 0x02], Reader::small_unsigned).unwrap(),
            2
        );
        assert_eq!(
            read_all(&[0x02, 0x02, 0x00, 0xFF], Reader::small_unsigned).unwrap(),
            255
        );
        assert_eq!(
            invalid(read_all(&[0x02, 0x02, 0x01, 0x00], Reader::small_unsigned)),
            "DER INTEGER out of range"
        );
        assert_eq!(
            invalid(read_all(&[0x02, 0x01, 0xFF], Reader::small_unsigned)),
            "DER INTEGER negative"
        );
    }

    #[test]
    fn strings_must_be_primitive() {
        // X.690 §10.2: DER uses the primitive form for string types, so the
        // constructed OCTET STRING (0x24) and BIT STRING (0x23) are BER only.
        assert_eq!(
            read_all(&[0x04, 0x02, 0x01, 0x02], Reader::octet_string).unwrap(),
            &[0x01, 0x02]
        );
        assert_eq!(
            invalid(read_all(
                &[0x24, 0x03, 0x04, 0x01, 0x00],
                Reader::octet_string
            )),
            "DER constructed string"
        );
        assert_eq!(
            invalid(read_all(
                &[0x23, 0x03, 0x03, 0x01, 0x00],
                Reader::bit_string
            )),
            "DER constructed string"
        );
        assert_eq!(
            invalid(read_all(&[0x05, 0x00], Reader::octet_string)),
            "DER unexpected tag"
        );
    }

    #[test]
    fn bit_strings_must_have_no_unused_bits() {
        // X.690 §8.6.2.2: the initial octet counts the unused bits. Every
        // key carried in a BIT STRING is an octet string (RFC 5480 §2.2,
        // RFC 8410 §4, RFC 3279 §2.3.1), so it must be 0, and §8.6.2.3: the
        // initial octet is always present.
        assert_eq!(
            read_all(&[0x03, 0x03, 0x00, 0xAB, 0xCD], Reader::bit_string).unwrap(),
            &[0xAB, 0xCD]
        );
        assert_eq!(
            read_all(&[0x03, 0x01, 0x00], Reader::bit_string).unwrap(),
            &[] as &[u8]
        );
        assert_eq!(
            invalid(read_all(&[0x03, 0x02, 0x01, 0xAA], Reader::bit_string)),
            "DER BIT STRING has unused bits"
        );
        assert_eq!(
            invalid(read_all(&[0x03, 0x00], Reader::bit_string)),
            "DER BIT STRING empty"
        );
        // The same rules under an IMPLICIT [1] tag (RFC 5958 §2 publicKey).
        assert_eq!(
            read_all(&[0x81, 0x02, 0x00, 0x11], |r| r.implicit_bit_string(0x81)).unwrap(),
            &[0x11]
        );
        assert_eq!(
            invalid(read_all(&[0x81, 0x02, 0x07, 0x80], |r| r.implicit_bit_string(0x81))),
            "DER BIT STRING has unused bits"
        );
    }

    #[test]
    fn null_must_be_empty() {
        // X.690 §8.8.2: "The contents octets shall not contain any octets."
        read_all(&[0x05, 0x00], Reader::null).unwrap();
        assert_eq!(
            invalid(read_all(&[0x05, 0x01, 0x00], Reader::null)),
            "DER NULL not empty"
        );
    }

    #[test]
    fn object_identifiers_must_have_minimal_subidentifiers() {
        // X.690 §8.19.2: each subidentifier in the fewest octets, so its
        // leading octet is never 0x80; its last octet has bit 8 clear.
        let ed25519 = [0x06, 0x03, 0x2B, 0x65, 0x70];
        assert_eq!(read_all(&ed25519, Reader::oid).unwrap(), &ed25519);
        let p256 = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
        assert_eq!(read_all(&p256, Reader::oid).unwrap(), &p256);
        for bad in [
            &[0x06, 0x00][..],
            &[0x06, 0x04, 0x2B, 0x80, 0x65, 0x70],
            &[0x06, 0x02, 0x80, 0x01],
            &[0x06, 0x02, 0x2B, 0x86],
        ] {
            assert_eq!(
                invalid(read_all(bad, Reader::oid)),
                "DER OBJECT IDENTIFIER malformed",
                "{bad:02x?}"
            );
        }
    }

    #[test]
    fn peek_and_is_empty_do_not_consume() {
        let mut reader = Reader::new(&[0x05, 0x00]).unwrap();
        assert_eq!(reader.peek_tag(), Some(0x05));
        assert!(!reader.is_empty());
        reader.null().unwrap();
        assert_eq!(reader.peek_tag(), None);
        assert!(reader.is_empty());
    }

    /// `contents` wrapped in one element tagged `tag`, short or long form.
    fn wrap(tag: u8, contents: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        match contents.len() {
            len @ 0..=0x7F => out.push(len as u8),
            len @ 0x80..=0xFF => out.extend_from_slice(&[0x81, len as u8]),
            len => out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]),
        }
        out.extend_from_slice(contents);
        out
    }

    /// The RFC 8410 §10.3 v2 attributes contents: one Attribute
    /// `SEQUENCE { 1.2.840.113549.1.9.9.20, SET { UTF8String "Curdle Chairs" } }`.
    const RFC8410_ATTRIBUTES: [u8; 31] = [
        0x30, 0x1D, 0x06, 0x0A, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x09, 0x14, 0x31,
        0x0F, 0x0C, 0x0D, 0x43, 0x75, 0x72, 0x64, 0x6C, 0x65, 0x20, 0x43, 0x68, 0x61, 0x69, 0x72,
        0x73,
    ];

    #[test]
    fn well_formed_der_is_accepted() {
        check_well_formed(&[], true).unwrap();
        check_well_formed(&RFC8410_ATTRIBUTES, true).unwrap();
        // Nested constructed values, a BOOLEAN TRUE, a BIT STRING with
        // zero padding, an application tag and a context primitive.
        let nested = wrap(
            0x30,
            &[
                &wrap(0x30, &wrap(0x30, &[0x02, 0x01, 0x05]))[..],
                &[0x01, 0x01, 0xFF],
                &[0x03, 0x02, 0x04, 0xF0],
                &[0x61, 0x00],
                &[0x80, 0x01, 0xAA],
                &wrap(0x31, &[0x02, 0x01, 0x01, 0x02, 0x01, 0x02]),
            ]
            .concat(),
        );
        check_well_formed(&nested, false).unwrap();
    }

    #[test]
    fn nested_framing_errors_are_rejected() {
        for (bad, why) in [
            (
                wrap(0x30, &[0x04, 0x81, 0x01, 0x00]),
                "DER length not minimal",
            ),
            (wrap(0x30, &[0x04, 0x05, 0x00]), "DER length exceeds input"),
            (wrap(0x30, &[0x3F, 0x10, 0x00]), "DER high-tag-number form"),
            (
                wrap(0x30, &[0x30, 0x80, 0x00, 0x00]),
                "DER indefinite length",
            ),
        ] {
            assert_eq!(invalid(check_well_formed(&bad, false)), why, "{bad:02x?}");
        }
    }

    #[test]
    fn primitive_type_rules_apply_at_any_depth() {
        for (bad, why) in [
            // X.690 §8.1.5: end-of-contents exists only in the indefinite form.
            (wrap(0x30, &[0x00, 0x00]), "DER end-of-contents"),
            // §10.2: strings are primitive in DER.
            (
                wrap(0x30, &wrap(0x24, &[0x04, 0x00])),
                "DER constructed string",
            ),
            (
                wrap(0x30, &wrap(0x2C, &[0x0C, 0x00])),
                "DER constructed string",
            ),
            // §8.3.2: minimal INTEGER, and ENUMERATED likewise (§8.4).
            (
                wrap(0x30, &[0x02, 0x02, 0x00, 0x01]),
                "DER INTEGER not minimal",
            ),
            (
                wrap(0x30, &[0x0A, 0x02, 0xFF, 0x80]),
                "DER INTEGER not minimal",
            ),
            // §11.1: BOOLEAN TRUE is 0xFF.
            (wrap(0x30, &[0x01, 0x01, 0x01]), "DER BOOLEAN not canonical"),
            (wrap(0x30, &[0x01, 0x00]), "DER BOOLEAN not canonical"),
            // §8.8.2, §8.19.2.
            (wrap(0x30, &[0x05, 0x01, 0x00]), "DER NULL not empty"),
            (
                wrap(0x30, &[0x06, 0x02, 0x80, 0x01]),
                "DER OBJECT IDENTIFIER malformed",
            ),
            // §8.6.2.2 (at most 7 unused bits), §8.6.2.3 (none if empty),
            // §11.2.1 (unused bits are zero).
            (
                wrap(0x30, &[0x03, 0x02, 0x08, 0x00]),
                "DER BIT STRING malformed",
            ),
            (wrap(0x30, &[0x03, 0x01, 0x01]), "DER BIT STRING malformed"),
            (wrap(0x30, &[0x03, 0x00]), "DER BIT STRING empty"),
            (
                wrap(0x30, &[0x03, 0x02, 0x04, 0xF8]),
                "DER BIT STRING malformed",
            ),
            // §8.9.1, §8.11.1: SEQUENCE and SET are always constructed;
            // INTEGER is always primitive (§8.3.1).
            (wrap(0x30, &[0x10, 0x00]), "DER unexpected tag"),
            (
                wrap(0x30, &wrap(0x22, &[0x02, 0x01, 0x00])),
                "DER unexpected tag",
            ),
        ] {
            assert_eq!(invalid(check_well_formed(&bad, false)), why, "{bad:02x?}");
        }
    }

    #[test]
    fn set_of_components_must_be_in_ascending_order() {
        // X.690 §11.6: the encodings compared as octet strings, the shorter
        // padded at its end with 0x00 octets.
        let ascending = [0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        let descending = [0x02, 0x01, 0x02, 0x02, 0x01, 0x01];
        check_well_formed(&ascending, true).unwrap();
        assert_eq!(
            invalid(check_well_formed(&descending, true)),
            "DER SET OF not sorted"
        );
        // Not a SET OF at the top: any order.
        check_well_formed(&descending, false).unwrap();
        // A nested SET follows the same rule.
        assert_eq!(
            invalid(check_well_formed(&wrap(0x31, &descending), false)),
            "DER SET OF not sorted"
        );
        // Equal components, and a shorter one that pads to equality, pass.
        check_well_formed(&[0x05, 0x00, 0x05, 0x00], true).unwrap();
        check_well_formed(&[0x04, 0x00, 0x04, 0x01, 0x00], true).unwrap();
        assert_eq!(
            invalid(check_well_formed(&[0x04, 0x01, 0x00, 0x04, 0x00], true)),
            "DER SET OF not sorted"
        );
    }

    #[test]
    fn pkcs8_attributes_are_ordered_by_whole_encoding_not_by_tag() {
        // `Attributes ::= SET OF Attribute` (RFC 5958 §2) is ordered by
        // X.690 §11.6. Every Attribute is a SEQUENCE (0x30), so a tag
        // order (X.690 §10.3, X.680 §8.6) would accept both orders; the
        // octet comparison does not. The shorter attribute sorts first by
        // its length octet (0x0A < 0x0B) although its OID is the larger.
        let short = wrap(
            0x30,
            &[
                &[0x06, 0x03, 0x55, 0x04, 0x0A][..],
                &wrap(0x31, &[0x0C, 0x01, 0x61]),
            ]
            .concat(),
        );
        let long = wrap(
            0x30,
            &[
                &[0x06, 0x03, 0x55, 0x04, 0x03][..],
                &wrap(0x31, &[0x0C, 0x02, 0x61, 0x62]),
            ]
            .concat(),
        );
        check_well_formed(&[&short[..], &long].concat(), true).unwrap();
        assert_eq!(
            invalid(check_well_formed(&[&long[..], &short].concat(), true)),
            "DER SET OF not sorted"
        );
    }

    #[test]
    fn nested_sets_are_checked_as_set_of_even_where_tag_order_disagrees() {
        // The identifier octet is class (bits 8-7), P/C (bit 6), number
        // (bits 5-1) (X.690 §8.1.2.2, §8.1.2.5), so as octets [1]
        // primitive (0x81) sorts before [0] constructed (0xA0), while the
        // tag order of a SET (§10.3, X.680 §8.6: class, then number) puts
        // [0] first. A SET and a SET OF share UNIVERSAL 17, and without a
        // schema every nested SET is checked as a SET OF (§11.6), here the
        // attrValues of an Attribute (RFC 5652 §5.3).
        let attribute = |values: &[u8]| {
            wrap(
                0x30,
                &[&[0x06, 0x03, 0x55, 0x04, 0x03][..], &wrap(0x31, values)].concat(),
            )
        };
        let octet_order = [0x81, 0x01, 0x00, 0xA0, 0x00];
        let tag_order = [0xA0, 0x00, 0x81, 0x01, 0x00];
        check_well_formed(&attribute(&octet_order), true).unwrap();
        assert_eq!(
            invalid(check_well_formed(&attribute(&tag_order), true)),
            "DER SET OF not sorted"
        );
    }

    #[test]
    fn deep_nesting_is_rejected_without_recursion() {
        // 2,000 nested SEQUENCEs fit in the 64 KiB cap; the walk keeps an
        // explicit stack of MAX_DEPTH levels and stops there.
        let mut value = vec![0x05, 0x00];
        for _ in 0..2_000 {
            value = wrap(0x30, &value);
        }
        assert!(value.len() <= MAX_INPUT_LEN);
        assert_eq!(
            invalid(check_well_formed(&value, false)),
            "DER nesting too deep"
        );
        let mut shallow = vec![0x05, 0x00];
        for _ in 0..MAX_DEPTH {
            shallow = wrap(0x30, &shallow);
        }
        check_well_formed(&shallow, false).unwrap();
        assert_eq!(
            invalid(check_well_formed(&wrap(0x30, &shallow), false)),
            "DER nesting too deep"
        );
    }

    #[test]
    fn writer_lengths_are_minimal() {
        // X.690 §10.1: short form to 127, then the fewest long-form octets.
        for (len, header) in [
            (0usize, &[0x04, 0x00][..]),
            (0x7F, &[0x04, 0x7F]),
            (0x80, &[0x04, 0x81, 0x80]),
            (0xFF, &[0x04, 0x81, 0xFF]),
            (0x100, &[0x04, 0x82, 0x01, 0x00]),
            (0xFFFB, &[0x04, 0x82, 0xFF, 0xFB]),
        ] {
            let contents = vec![0xA5; len];
            assert_eq!(encoded_len(len), header.len() + len);
            let mut writer = Writer::new(encoded_len(len)).unwrap();
            writer.element(OCTET_STRING, &contents).unwrap();
            let out = writer.finish().unwrap();
            assert_eq!(&out[..header.len()], header, "{len}");
            // What the writer emits, the reader accepts.
            assert_eq!(read_all(&out, Reader::octet_string).unwrap(), &contents[..]);
        }
    }

    #[test]
    fn writer_unsigned_integers_are_minimal_and_positive() {
        // X.690 §8.3.2 minimal; §8.3.3 a 0x00 octet keeps the sign bit clear.
        for (magnitude, encoding) in [
            (&[][..], &[0x02, 0x01, 0x00][..]),
            (&[0x00], &[0x02, 0x01, 0x00]),
            (&[0x00, 0x00, 0x05], &[0x02, 0x01, 0x05]),
            (&[0x7F], &[0x02, 0x01, 0x7F]),
            (&[0x80], &[0x02, 0x02, 0x00, 0x80]),
            (&[0x00, 0xFF, 0x01], &[0x02, 0x03, 0x00, 0xFF, 0x01]),
            (&[0x01, 0x00, 0x01], &[0x02, 0x03, 0x01, 0x00, 0x01]),
        ] {
            assert_eq!(unsigned_integer_len(magnitude), encoding.len());
            let mut writer = Writer::new(encoding.len()).unwrap();
            writer.unsigned_integer(magnitude).unwrap();
            let out = writer.finish().unwrap();
            assert_eq!(&out[..], encoding, "{magnitude:02x?}");
            let read = read_all(&out, Reader::unsigned_integer).unwrap();
            let expected: &[u8] = match magnitude.iter().position(|&b| b != 0) {
                Some(i) => &magnitude[i..],
                None => &[0x00],
            };
            assert_eq!(read, expected);
        }
    }

    #[test]
    fn writer_bit_strings_have_no_unused_bits() {
        let mut writer = Writer::new(bit_string_len(2)).unwrap();
        writer
            .bit_string(CONTEXT_1_PRIMITIVE, &[0xAB, 0xCD])
            .unwrap();
        let out = writer.finish().unwrap();
        assert_eq!(&out[..], &[0x81, 0x03, 0x00, 0xAB, 0xCD]);
    }

    #[test]
    fn writer_builds_nested_structures_from_planned_lengths() {
        // SEQUENCE { INTEGER 0, NULL, [0] { OCTET STRING 01 } }
        let inner = encoded_len(1);
        let body = unsigned_integer_len(&[0]) + 2 + encoded_len(inner);
        let mut writer = Writer::new(encoded_len(body)).unwrap();
        writer.header(SEQUENCE, body).unwrap();
        writer.unsigned_integer(&[0]).unwrap();
        writer.raw(&[0x05, 0x00]).unwrap();
        writer.header(CONTEXT_0, inner).unwrap();
        writer.element(OCTET_STRING, &[0x01]).unwrap();
        let out = writer.finish().unwrap();
        assert_eq!(
            &out[..],
            &[
                0x30, 0x0A, 0x02, 0x01, 0x00, 0x05, 0x00, 0xA0, 0x03, 0x04, 0x01, 0x01
            ]
        );
    }

    #[test]
    fn writer_rejects_writes_past_or_short_of_the_plan() {
        let mut writer = Writer::new(2).unwrap();
        assert_eq!(
            invalid(writer.element(OCTET_STRING, &[0x00])),
            "DER output length mismatch"
        );
        let mut writer = Writer::new(3).unwrap();
        writer.raw(&[0x05, 0x00]).unwrap();
        assert_eq!(invalid(writer.finish()), "DER output length mismatch");
        assert_eq!(
            invalid(Writer::new(MAX_INPUT_LEN + 1)),
            "DER output too large"
        );
    }

    #[test]
    fn writer_output_is_zeroizing() {
        fn zeroizing(_: &zeroize::Zeroizing<Vec<u8>>) {}
        let mut writer = Writer::new(2).unwrap();
        writer.raw(&[0x05, 0x00]).unwrap();
        let out = writer.finish().unwrap();
        zeroizing(&out);
        // Planned exactly, so the buffer never reallocated (which would leave
        // an unzeroized copy behind).
        assert!(out.capacity() >= 2);
    }

    #[test]
    fn an_explicit_tag_wraps_a_complete_inner_encoding() {
        // RFC 5915 §3 (EXPLICIT TAGS): publicKey [1] BIT STRING is A1 len
        // followed by the whole BIT STRING element (X.690 §8.14.2 c).
        let input = [CONTEXT_1, 0x04, BIT_STRING, 0x02, 0x00, 0x04];
        let point = read_all(&input, |r| {
            let mut tagged = r.explicit(CONTEXT_1)?;
            let point = tagged.bit_string()?;
            tagged.finish()?;
            Ok(point)
        })
        .unwrap();
        assert_eq!(point, &[0x04]);
        // An IMPLICIT [1] (0x81) is not the EXPLICIT form.
        assert_eq!(
            invalid(read_all(&[0x81, 0x02, 0x00, 0x04], |r| r
                .explicit(CONTEXT_1)
                .map(|_| ()))),
            "DER unexpected tag"
        );
    }

    mod properties {
        use proptest::prelude::*;

        use super::super::{Reader, check_well_formed};

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(1_000))]

            /// The reader and the well-formedness walk return a result for
            /// any input; neither panics nor recurses.
            #[test]
            fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512), set_of in any::<bool>()) {
                let _ = check_well_formed(&bytes, set_of);
                let mut reader = Reader::new(&bytes).unwrap();
                while let Ok(element) = reader.element() {
                    prop_assert!(element.encoding.len() >= 2 + element.contents.len());
                    let mut inner = Reader::new(element.contents).unwrap();
                    let _ = (inner.integer(), inner.bit_string(), inner.oid(), inner.null());
                }
            }
        }
    }
}
