//! base64url (RFC 4648 §5, no padding) helpers used throughout JOSE.
//!
//! JOSE serializes every binary value as "Base64url Encoding": the URL- and
//! filename-safe alphabet of RFC 4648 §5 "with all trailing '=' characters
//! omitted ... and without the inclusion of any line breaks, whitespace, or
//! other additional characters" (RFC 7515 §2; RFC 7516 §2, RFC 7517 §2 and
//! RFC 7518 §2 use the same definition).
//!
//! [`b64url_decode`](crate::util::b64url_decode) is strict, so each octet string has exactly one accepted
//! encoding. That keeps signature and JWK comparisons from being fooled by
//! alternative spellings of the same bytes. All base64url encoding and
//! decoding in polyjose must go through this module.
//!
//! The codec is polyjose's own (ADR 0016: no base64 crate in the core). It
//! is constant-time with respect to the encoded or decoded content, because
//! secret key material (`oct` `k`, private RSA/EC/OKP members, RFC 7518 §6)
//! passes through it. Only the input length, which is public, affects
//! control flow. The alphabet mapping in both directions is branch-free,
//! table-free arithmetic over the five contiguous runs of RFC 4648 §5
//! Table 2, the decoder folds every fault into one `subtle::Choice` that it
//! checks once at the end, and a rejected decode wipes its partial output.
//! This is "best effort" constant time at the source level: Rust gives no
//! guarantee about the machine code, as for any pure-Rust implementation.
//! `base64ct` serves only as a dev-dependency oracle in the differential
//! tests (`tests/base64url_differential.rs`).
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroizing;

/// Encodes bytes as unpadded base64url (RFC 7515 §2, RFC 4648 §5).
///
/// The output uses only `A`–`Z`, `a`–`z`, `0`–`9`, `-` and `_`, never `=`,
/// and its pad bits are zero (RFC 4648 §3.5), so it is the canonical
/// encoding that [`b64url_decode`] accepts.
///
/// # Constant time
///
/// `data` may be secret (exporting an `oct` `k` or a private JWK member), so
/// the running time depends only on `data.len()`, which is public. Each
/// 3-octet group (RFC 4648 §4) is split into 6-bit values and every value
/// goes through `encode_symbol_in`, which is pure arithmetic: no branch and
/// no table lookup depends on the octets. The only branches are on lengths.
/// Each character pushed is ASCII, so `String::push` takes the same one-byte
/// path for every input. The output is allocated once at its exact length
/// (RFC 7515 §2: ⌈4n/3⌉ characters), so no reallocation leaves copies behind.
///
/// ```
/// use polyjose::util::b64url_encode;
///
/// // RFC 7515 Appendix C.
/// assert_eq!(b64url_encode(&[3, 236, 255, 224, 193]), "A-z_4ME");
/// ```
pub fn b64url_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(encoded_len(data.len()));
    encode_groups(data, URL_SAFE, &mut out);
    out
}

/// Appends the symbols of `data` in `alphabet` to `out`, without padding:
/// 1, 2 or 3 octets give 2, 3 or 4 symbols (RFC 4648 §4; RFC 7515 §2 for
/// base64url). Shared by the base64url and the standard base64 encoders.
///
/// # Constant time
///
/// As for [`b64url_encode`]: every 6-bit value goes through
/// [`encode_symbol_in`], and the only branches are on `data.len()`.
fn encode_groups(data: &[u8], alphabet: Alphabet, out: &mut String) {
    for group in data.chunks(3) {
        // RFC 4648 §4: a short final group is padded with zero bits on the
        // right, which makes the pad bits zero (§3.5).
        let mut octets = [0u8; 3];
        octets[..group.len()].copy_from_slice(group);
        let bits = u32::from(octets[0]) << 16 | u32::from(octets[1]) << 8 | u32::from(octets[2]);
        for i in 0..=group.len() {
            // Truncation is intended: encode_symbol_in uses only the low 6 bits.
            let value = (bits >> (18 - 6 * i)) as u8;
            out.push(char::from(encode_symbol_in(value, alphabet)));
        }
    }
}

/// Length of the unpadded base64url encoding of `len` octets: ⌈4·len/3⌉
/// (RFC 4648 §4, with the `=` padding of RFC 4648 §3.2 dropped per RFC 7515
/// §2). Divides before multiplying so it cannot overflow for any slice length.
fn encoded_len(len: usize) -> usize {
    len / 3 * 4 + (len % 3 * 4).div_ceil(3)
}

/// The two characters in which the base 64 alphabets of RFC 4648 differ:
/// the symbols for values 62 and 63. Values 0–61 are `A`–`Z`, `a`–`z`,
/// `0`–`9` in both (RFC 4648 §4 Table 1, §5 Table 2).
///
/// The alphabet is a public parameter of the codec, never data, so code may
/// depend on it freely.
#[derive(Clone, Copy)]
struct Alphabet {
    /// The symbol for value 62.
    c62: u8,
    /// The symbol for value 63.
    c63: u8,
}

/// RFC 4648 §5 Table 2, "URL and Filename safe": `-` and `_`.
const URL_SAFE: Alphabet = Alphabet {
    c62: b'-',
    c63: b'_',
};

/// `-1` (all bits set) if `x >= k`, else `0`, without a branch.
///
/// For `0 <= x, k < 2^15`, `k - 1 - x` is negative exactly when `x >= k`,
/// and an arithmetic right shift by 15 spreads the sign bit over the word.
#[inline]
fn ge_mask(x: i16, k: i16) -> i16 {
    (k - 1 - x) >> 15
}

/// Maps the low 6 bits of `value` to its RFC 4648 §5 (Table 2) character:
/// [`encode_symbol_in`] with the base64url alphabet, kept for the Table 2
/// tests.
#[cfg(test)]
fn encode_symbol(value: u8) -> u8 {
    encode_symbol_in(value, URL_SAFE)
}

/// Maps the low 6 bits of `value` to its character in `alphabet`
/// (RFC 4648 §4 Table 1 or §5 Table 2).
///
/// # Constant time
///
/// Both tables are five contiguous runs, each a fixed offset from the value:
/// 0–25 → `'A' + v`, 26–51 → `'a' + (v - 26)`, 52–61 → `'0' + (v - 52)`,
/// 62 → the alphabet's 62nd symbol (`-` or `+`), 63 → its 63rd (`_` or `/`).
/// Instead of choosing a run with a branch or a table lookup indexed by the
/// (secret) value, we start from the first run's offset and add the
/// difference to the next run's offset under a mask from [`ge_mask`]. The
/// alphabet only changes those public offsets. Every value runs the same
/// instructions and touches no memory, so neither timing nor cache state
/// depends on it.
#[inline]
fn encode_symbol_in(value: u8, alphabet: Alphabet) -> u8 {
    let v = i16::from(value & 0x3f);
    let (c62, c63) = (i16::from(alphabet.c62), i16::from(alphabet.c63));
    let mut offset = i16::from(b'A');
    offset += ge_mask(v, 26) & ((i16::from(b'a') - 26) - i16::from(b'A'));
    offset += ge_mask(v, 52) & ((i16::from(b'0') - 52) - (i16::from(b'a') - 26));
    offset += ge_mask(v, 62) & ((c62 - 62) - (i16::from(b'0') - 52));
    offset += ge_mask(v, 63) & ((c63 - 63) - (c62 - 62));
    // In range: the sum is one of the 64 ASCII alphabet bytes.
    (v + offset) as u8
}

/// Strictly decodes unpadded base64url (RFC 7515 §2, RFC 4648 §5).
///
/// The empty string decodes to no octets (RFC 4648 §10). Everything else
/// that is not the canonical encoding of some octet string fails with
/// [`Error::InvalidBase64`](crate::Error::InvalidBase64). That covers:
///
/// - `=` padding, which RFC 7515 §2 omits;
/// - `+` and `/` from the standard alphabet (RFC 4648 §4), since base64url
///   uses `-` and `_` (§5);
/// - whitespace and line breaks, which RFC 7515 §2 forbids and RFC 4648 §3.3
///   allows a specification to reject;
/// - any other byte outside the alphabet (RFC 4648 §3.3);
/// - a length ≡ 1 (mod 4), which no input can produce (RFC 4648 §4);
/// - non-zero pad bits in the final quantum. RFC 4648 §3.5 lets decoders
///   reject them, and we do so that each value has one encoding: `"QQ"` is
///   0x41, and `"QR"` is rejected rather than read as 0x41 too.
///
/// # Constant time
///
/// `s` may hold secret key material (an `oct` `k`, RFC 7518 §6.4.1, or a
/// private JWK member, RFC 7518 §6.3.2), so the running time and memory
/// access pattern depend only on `s.len()`, which is public:
///
/// - each byte goes through `decode_symbol_in`, which maps it to its 6-bit
///   value with arithmetic range masks: no branch and no table index
///   depends on the byte;
/// - a bad byte or non-zero pad bits do not stop decoding. They are folded
///   into one `subtle::Choice`, and every quantum is decoded, so the work
///   done does not reveal where the first fault is;
/// - the pad-bit check is a `subtle` comparison folded into that same
///   `Choice`, and the only branch on secret-derived data is the final
///   accept/reject verdict.
///
/// The only other branch is the length ≡ 1 (mod 4) check, on the public
/// length.
///
/// The error carries no input bytes (ADR 0007). The returned bytes may be key
/// material: callers decoding secrets should wrap them in
/// `zeroize::Zeroizing`.
///
/// ```
/// use polyjose::{Error, util::b64url_decode};
///
/// assert_eq!(b64url_decode("QQ"), Ok(vec![0x41]));
/// assert_eq!(b64url_decode("QR"), Err(Error::InvalidBase64)); // non-canonical
/// assert_eq!(b64url_decode("QQ=="), Err(Error::InvalidBase64)); // padded
/// ```
pub fn b64url_decode(s: &str) -> crate::Result<Vec<u8>> {
    // RFC 4648 §4: a final quantum has 2, 3 or 4 characters, never 1.
    if s.len() % 4 == 1 {
        return Err(crate::Error::InvalidBase64);
    }
    // Decode into a buffer that is wiped on drop. On failure every quantum
    // has already been written, and for an `oct` `k` or a private JWK member
    // (RFC 7518 §6.4.1, §6.3.2) those bytes are key material, so they must
    // not be left in freed memory (workspace CLAUDE.md: key material is
    // zeroized). The buffer has its exact final length, so it never grows.
    let mut buf = Zeroizing::new(vec![0u8; decoded_len(s.len())]);
    let valid = decode_into(s.as_bytes(), &mut buf);
    if bool::from(valid) {
        // Move the allocation out without copying; the emptied wrapper is dropped.
        Ok(core::mem::take(&mut *buf))
    } else {
        // `buf` is zeroized as it drops here.
        Err(crate::Error::InvalidBase64)
    }
}

/// Decodes base64url `input` into `out` and returns whether `input` was the
/// canonical encoding of `out` (RFC 4648 §5, §3.5).
///
/// The caller guarantees `input.len() % 4 != 1` and
/// `out.len() == decoded_len(input.len())`. Every quantum is decoded, even
/// after a fault, and faults are folded into the returned `Choice`, so the
/// loop runs the same steps for every input of a given length.
fn decode_into(input: &[u8], out: &mut [u8]) -> Choice {
    decode_into_in(input, out, URL_SAFE)
}

/// [`decode_into`] for any `alphabet`: decodes unpadded symbols of
/// `alphabet` into `out` and returns whether they were the canonical
/// encoding of `out` (RFC 4648 §3.5). Same preconditions and the same
/// constant-time structure.
fn decode_into_in(input: &[u8], out: &mut [u8], alphabet: Alphabet) -> Choice {
    let mut valid = Choice::from(1);
    for (quantum, octets) in input.chunks(4).zip(out.chunks_mut(3)) {
        let mut bits = 0u32;
        for (i, &byte) in quantum.iter().enumerate() {
            let (value, symbol_valid) = decode_symbol_in(byte, alphabet);
            valid &= symbol_valid;
            bits |= u32::from(value) << (18 - 6 * i);
        }
        for (j, octet) in octets.iter_mut().enumerate() {
            // Truncation is intended: take octet j of the 24-bit group.
            *octet = (bits >> (16 - 8 * j)) as u8;
        }
        // RFC 4648 §3.5: the bits below the last output octet (4 for a
        // 2-character quantum, 2 for a 3-character one, none for a full
        // quantum) must be zero, so each octet string has one encoding.
        let pad_bits = bits & (0x00ff_ffff >> (8 * octets.len()));
        valid &= pad_bits.ct_eq(&0);
    }
    valid
}

/// `-1` (all bits set) if `lo <= x <= hi`, else `0`, without a branch.
///
/// For `0 <= lo, hi, x < 2^15`, `lo - 1 - x` and `x - hi - 1` are both
/// negative exactly when `x` is in range, so their AND has the sign bit set
/// exactly then, and an arithmetic right shift by 15 spreads it.
#[inline]
fn in_range_mask(x: i16, lo: i16, hi: i16) -> i16 {
    ((lo - 1 - x) & (x - hi - 1)) >> 15
}

/// Maps a byte to its RFC 4648 §5 (Table 2) value and whether it is in the
/// alphabet: [`decode_symbol_in`] with the base64url alphabet, kept for the
/// Table 2 tests.
#[cfg(test)]
fn decode_symbol(byte: u8) -> (u8, Choice) {
    decode_symbol_in(byte, URL_SAFE)
}

/// Maps a byte to its value in `alphabet` (RFC 4648 §4 Table 1 or §5
/// Table 2) and whether it is in the alphabet at all (RFC 4648 §3.3: any
/// other byte makes the input invalid). A byte outside the alphabet yields
/// value 0, so it adds no bits.
///
/// # Constant time
///
/// The alphabet is five disjoint byte ranges, `A`–`Z`, `a`–`z`, `0`–`9`,
/// and the single symbols for 62 and 63 (`-` and `_`, or `+` and `/`), each
/// a fixed offset from its value. Every range is tested with
/// [`in_range_mask`]; the mask selects that range's value and marks the byte
/// valid. All five tests always run and no memory is indexed by the byte,
/// so neither timing nor cache state depends on it. The alphabet is public.
#[inline]
fn decode_symbol_in(byte: u8, alphabet: Alphabet) -> (u8, Choice) {
    let c = i16::from(byte);
    let mut value = 0i16;
    let mut found = 0i16;
    for (lo, hi, first_value) in [
        (b'A', b'Z', 0),
        (b'a', b'z', 26),
        (b'0', b'9', 52),
        (alphabet.c62, alphabet.c62, 62),
        (alphabet.c63, alphabet.c63, 63),
    ] {
        let (lo, hi) = (i16::from(lo), i16::from(hi));
        let mask = in_range_mask(c, lo, hi);
        value |= mask & (c - lo + first_value);
        found |= mask;
    }
    // `found` is 0 or -1 and `value` is in 0..64, so both casts are exact.
    (value as u8, Choice::from((found & 1) as u8))
}

/// Exact decoded length of an unpadded base64url string of `encoded_len`
/// characters (RFC 4648 §4: each 4-character quantum is 3 octets; a final
/// 2- or 3-character quantum is 1 or 2 octets). A remainder of 1 is not a
/// valid length and gets 0; the decoder rejects that input anyway. Written
/// so that it cannot overflow.
fn decoded_len(encoded_len: usize) -> usize {
    encoded_len / 4 * 3 + (encoded_len % 4) * 3 / 4
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let s = b64url_encode(b"{\"alg\":\"HS256\"}");
        assert_eq!(s, "eyJhbGciOiJIUzI1NiJ9");
        assert_eq!(b64url_decode(&s).unwrap(), b"{\"alg\":\"HS256\"}");
    }

    /// RFC 4648 §10 test vectors, converted to the URL alphabet (§5) with the
    /// `=` padding removed as RFC 7515 §2 requires. None of these vectors
    /// contains `+` or `/`, so the conversion only strips padding.
    const RFC4648_SECTION_10: [(&[u8], &str); 7] = [
        (b"", ""),             // BASE64("") = ""
        (b"f", "Zg"),          // BASE64("f") = "Zg=="
        (b"fo", "Zm8"),        // BASE64("fo") = "Zm8="
        (b"foo", "Zm9v"),      // BASE64("foo") = "Zm9v"
        (b"foob", "Zm9vYg"),   // BASE64("foob") = "Zm9vYg=="
        (b"fooba", "Zm9vYmE"), // BASE64("fooba") = "Zm9vYmE="
        (b"foobar", "Zm9vYmFy"),
    ];

    #[test]
    fn rfc4648_section_10_vectors_encode() {
        for (bytes, encoded) in RFC4648_SECTION_10 {
            assert_eq!(b64url_encode(bytes), encoded, "encode {bytes:?}");
        }
    }

    #[test]
    fn rfc4648_section_10_vectors_decode() {
        for (bytes, encoded) in RFC4648_SECTION_10 {
            assert_eq!(b64url_decode(encoded).unwrap(), bytes, "decode {encoded:?}");
        }
    }

    /// RFC 7515 Appendix C: the octets [3, 236, 255, 224, 193] encode to
    /// "A-z_4ME". This is the RFC's own example of the URL-safe characters
    /// `-` (62) and `_` (63) replacing `+` and `/` (RFC 4648 §5, Table 2).
    #[test]
    fn rfc7515_appendix_c_vector_uses_url_alphabet() {
        let bytes = [3u8, 236, 255, 224, 193];
        assert_eq!(b64url_encode(&bytes), "A-z_4ME");
        assert_eq!(b64url_decode("A-z_4ME").unwrap(), bytes);
    }

    #[test]
    fn url_alphabet_covers_values_62_and_63() {
        // 0xFB 0xFF = 111110 111111 1111(00): values 62, 63, 60 -> "-_8".
        // RFC 4648 §4 would encode this as "+/8=".
        assert_eq!(b64url_encode(&[0xfb, 0xff]), "-_8");
        assert_eq!(b64url_decode("-_8").unwrap(), [0xfb, 0xff]);
    }

    /// Asserts that every input is rejected with `Error::InvalidBase64`.
    fn assert_all_rejected(inputs: &[&str]) {
        for input in inputs {
            assert_eq!(
                b64url_decode(input),
                Err(crate::Error::InvalidBase64),
                "{input:?} must be rejected"
            );
        }
    }

    /// RFC 7515 §2: base64url "with all trailing '=' characters omitted".
    #[test]
    fn rejects_padding() {
        assert_all_rejected(&[
            "Zg==", "Zg=", "Zm8=", "Zm9vYg==", "Zm9vYmE=", "=", "==", "Zm9v====",
        ]);
    }

    /// RFC 4648 §5: `+` and `/` belong to the base64 alphabet (§4), not to
    /// base64url, where values 62 and 63 are `-` and `_`.
    #[test]
    fn rejects_standard_alphabet_characters() {
        assert_all_rejected(&["+/8", "+_8", "-/8", "Zm9v+mFy", "Zm9v/mFy"]);
    }

    /// RFC 7515 §2: "no line breaks, whitespace, or other additional
    /// characters"; RFC 4648 §3.3 lets a specification reject them.
    #[test]
    fn rejects_whitespace_and_line_breaks() {
        assert_all_rejected(&[
            " Zm9v",
            "Zm9v ",
            "Zm 9v",
            "Zm9v\nYmFy",
            "Zm9v\r\nYmFy",
            "Zm9v\tYmFy",
            "Zm9v\n",
            "\u{a0}Zm9v",
            " ",
        ]);
    }

    /// RFC 4648 §3.3: characters outside the alphabet make the input invalid.
    #[test]
    fn rejects_non_alphabet_bytes() {
        assert_all_rejected(&[
            "Zm9v*",
            "Zm9v.",
            "Zm9v%3D",
            "Zm9v\0",
            "Zm9vé",
            "Zm9v~",
            "Zm9v,YmFy",
        ]);
    }

    /// RFC 4648 §4/§5: an encoding ends in a 2-, 3- or 4-character quantum,
    /// so a length ≡ 1 (mod 4) cannot be produced by any input.
    #[test]
    fn rejects_impossible_lengths() {
        assert_all_rejected(&["Z", "A", "Zm9vY", "AAAAA", "Zm9vYmFyZ"]);
    }

    /// RFC 4648 §3.5: the pad bits of the final quantum must be zero, so each
    /// octet string has exactly one encoding. "QQ" is 0x41; "QR" differs only
    /// in those unused bits and must not also decode to 0x41.
    #[test]
    fn rejects_non_canonical_trailing_bits() {
        assert_eq!(b64url_decode("QQ").unwrap(), [0x41]);
        assert_eq!(b64url_decode("QUE").unwrap(), [0x41, 0x41]);
        // 2-char tail: 4 unused bits. 3-char tail: 2 unused bits.
        assert_all_rejected(&[
            "QR", "QS", "QT", "Q_", "QUF", "QUG", "QUH", "Zh", "Zm9vYh", "Zm9vYmF",
        ]);
    }

    /// The decode buffer is sized exactly: n octets encode to
    /// ceil(4n / 3) characters without padding (RFC 4648 §4, RFC 7515 §2).
    #[test]
    fn decoded_len_matches_every_canonical_length() {
        for n in 0..=64usize {
            let encoded = b64url_encode(&vec![0xa5; n]);
            assert_eq!(decoded_len(encoded.len()), n, "{n} octets");
        }
        assert_eq!(decoded_len(usize::MAX), usize::MAX / 4 * 3 + 2);
    }

    /// RFC 4648 §10: BASE64("") = "".
    #[test]
    fn empty_input_decodes_to_empty_bytes() {
        assert_eq!(b64url_decode("").unwrap(), Vec::<u8>::new());
        assert_eq!(b64url_encode(&[]), "");
    }

    /// RFC 4648 §5, Table 2 ("The 'URL and Filename safe' Base 64
    /// Alphabet"), written out independently of the codec under test.
    const TABLE_2: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    /// RFC 4648 §5 Table 2: every 6-bit value v encodes as `TABLE_2[v]`,
    /// both as the first symbol of a quantum (v << 2 in a 1-octet input)
    /// and as the last symbol of a full quantum (low 6 bits of octet 3).
    #[test]
    fn encode_maps_every_value_per_table_2() {
        for (v, &symbol) in (0u8..).zip(TABLE_2.iter()) {
            assert_eq!(
                b64url_encode(&[v << 2]).as_bytes(),
                [symbol, b'A'],
                "value {v} first"
            );
            assert_eq!(
                b64url_encode(&[0, 0, v]).as_bytes(),
                [b'A', b'A', b'A', symbol],
                "value {v} last"
            );
        }
    }

    /// RFC 4648 §5 Table 2 and §3.3: every character U+0000..=U+00FF
    /// decodes to its Table 2 value if it is in the alphabet and is rejected
    /// otherwise, in the first and in the last position of a quantum.
    #[test]
    fn decode_maps_every_byte_per_table_2() {
        for c in (0u8..=0xff).map(char::from) {
            let value = u8::try_from(c)
                .ok()
                .and_then(|b| TABLE_2.iter().position(|&s| s == b))
                .and_then(|v| u8::try_from(v).ok());
            let first = b64url_decode(&format!("{c}A"));
            let last = b64url_decode(&format!("AAA{c}"));
            match value {
                Some(v) => {
                    assert_eq!(first, Ok(vec![v << 2]), "{c:?} first");
                    assert_eq!(last, Ok(vec![0, 0, v]), "{c:?} last");
                }
                None => {
                    assert_eq!(first, Err(crate::Error::InvalidBase64), "{c:?} first");
                    assert_eq!(last, Err(crate::Error::InvalidBase64), "{c:?} last");
                }
            }
        }
    }

    /// The arithmetic symbol mapping agrees with Table 2 for all 64 values,
    /// and only the low 6 bits of its argument matter.
    #[test]
    fn encode_symbol_matches_table_2() {
        for (v, &symbol) in (0u8..).zip(TABLE_2.iter()) {
            assert_eq!(encode_symbol(v), symbol, "value {v}");
            assert_eq!(
                encode_symbol(v | 0xc0),
                symbol,
                "value {v} with high bits set"
            );
        }
    }

    /// The arithmetic inverse mapping agrees with Table 2 for all 256 byte
    /// values: alphabet bytes give their value and are valid; every other
    /// byte is invalid and contributes no bits.
    #[test]
    fn decode_symbol_matches_table_2() {
        for b in 0u8..=0xff {
            let (value, valid) = decode_symbol(b);
            match TABLE_2.iter().position(|&s| s == b) {
                Some(v) => {
                    assert_eq!(usize::from(value), v, "byte {b:#04x}");
                    assert!(bool::from(valid), "byte {b:#04x} must be valid");
                }
                None => {
                    assert_eq!(value, 0, "byte {b:#04x} must contribute no bits");
                    assert!(!bool::from(valid), "byte {b:#04x} must be invalid");
                }
            }
        }
    }

    /// No early exit: a bad symbol is only folded into the verdict, so every
    /// quantum is still decoded and the work done does not reveal where the
    /// first bad byte (or a bad pad bit) is.
    #[test]
    fn decode_into_processes_the_whole_input_before_the_verdict() {
        let mut out = [0u8; 6];
        assert!(!bool::from(decode_into(b"*AAAZm9v", &mut out)));
        assert_eq!(&out[3..], b"foo", "quantum after the bad byte decoded");

        let mut out = [0u8; 4];
        assert!(!bool::from(decode_into(b"Zm9vQR", &mut out)));
        assert_eq!(out, *b"fooA", "non-canonical tail decoded, then rejected");

        let mut out = [0u8; 5];
        assert!(bool::from(decode_into(b"Zm9vYmE", &mut out)));
        assert_eq!(out, *b"fooba");
    }

    mod properties {
        use super::super::*;
        use proptest::prelude::*;

        proptest! {
            // ADR 0008 layer 2: bounded case counts in the fast suite.
            #![proptest_config(ProptestConfig::with_cases(256))]

            /// RFC 4648 §5 / RFC 7515 §2: decoding inverts encoding, and the
            /// encoding is unpadded and uses only the URL-safe alphabet.
            #[test]
            fn encode_then_decode_round_trips(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
                let encoded = b64url_encode(&bytes);
                prop_assert!(encoded.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'));
                prop_assert_eq!(encoded.len(), (bytes.len() * 4).div_ceil(3));
                prop_assert_eq!(b64url_decode(&encoded)?, bytes);
            }

            /// RFC 4648 §3.5: each octet string has exactly one encoding, so
            /// whenever a string over the alphabet decodes, re-encoding gives
            /// it back unchanged (non-canonical pad bits are rejected).
            #[test]
            fn decode_accepts_only_canonical_alphabet_strings(s in "[A-Za-z0-9_-]{0,96}") {
                if let Ok(bytes) = b64url_decode(&s) {
                    prop_assert_eq!(b64url_encode(&bytes), s);
                }
            }

            /// Same property over strings that mix in the characters RFC 7515
            /// §2 forbids (`=`, `+`, `/`, whitespace) and arbitrary Unicode.
            /// Decoding never panics, and any success is canonical.
            #[test]
            fn decode_of_arbitrary_text_is_canonical_or_rejected(
                s in prop_oneof![
                    "[A-Za-z0-9_=+/ \\t\\r\\n-]{0,64}",
                    any::<String>(),
                ]
            ) {
                if let Ok(bytes) = b64url_decode(&s) {
                    prop_assert_eq!(b64url_encode(&bytes), s);
                }
            }
        }
    }
}
