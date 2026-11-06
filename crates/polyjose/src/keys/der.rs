//! Strict DER (ITU-T X.690 §8, §10, §11) for exactly the tags the key
//! structures use: INTEGER, BIT STRING, OCTET STRING, NULL, OBJECT IDENTIFIER,
//! SEQUENCE, and the context tags `[0]`/`[1]` in their explicit (0xA0/0xA1) and
//! implicit primitive (0x81) forms (ADR 0018 §1).
//!
//! Definite lengths in the fewest octets (X.690 §10.1, §8.1.3), minimal
//! INTEGERs (§8.3.2), primitive strings only (§10.2), minimal OID
//! subidentifiers (§8.19.2), low-tag-number form only (§8.1.2.4) and no data
//! after the outermost element (§8.1.1). BER is rejected (ADR 0018 §2).
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the DER engine is used by pkcs8.rs and spki.rs, and later by the key mappers"
    )
)]

use crate::error::{Error, Result};

/// The largest DER input the reader accepts: 64 KiB. A 4096-bit RSA SPKI is
/// about 550 octets, so this bounds work and memory without rejecting any
/// supported key (ADR 0018 §2; research.md §4).
pub(crate) const MAX_INPUT_LEN: usize = 64 * 1024;

/// UNIVERSAL 16, constructed: SEQUENCE (X.690 §8.9).
pub(crate) const SEQUENCE: u8 = 0x30;

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
}
