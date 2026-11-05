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
//! alternative spellings of the same bytes. All base64url decoding in
//! polyjose must go through it. Don't call `base64ct` directly:
//! `Base64UrlUnpadded::decode_in_place` (base64ct 1.8.3) skips the
//! canonical-trailing-bits check that `decode` performs.
//!
//! The codec is `base64ct`, which works "without data-dependent branches or
//! lookup tables" ("best effort" constant time, per its README). That
//! matters because secret key material (`oct` `k`, private RSA/EC/OKP
//! members) is decoded here.
use base64ct::{Base64UrlUnpadded, Encoding};
use zeroize::Zeroizing;

/// Encodes bytes as unpadded base64url (RFC 7515 §2, RFC 4648 §5).
///
/// The output uses only `A`–`Z`, `a`–`z`, `0`–`9`, `-` and `_`, never `=`,
/// and its pad bits are zero (RFC 4648 §3.5), so it is the canonical
/// encoding that [`b64url_decode`] accepts.
///
/// ```
/// use polyjose::util::b64url_encode;
///
/// // RFC 7515 Appendix C.
/// assert_eq!(b64url_encode(&[3, 236, 255, 224, 193]), "A-z_4ME");
/// ```
pub fn b64url_encode(data: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(data)
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
/// `base64ct`'s `decode` already enforces all of these (its branch-free
/// symbol decoding rejects every non-alphabet byte and impossible length,
/// and it re-encodes the last block to compare it with the input). This
/// module's tests pin each rule, so a behaviour change in a `base64ct`
/// update fails the build instead of loosening JOSE parsing.
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
    // Decode into a buffer that is wiped on drop. On failure base64ct has
    // already written every quantum before the bad one, and for an `oct` `k`
    // or a private JWK member (RFC 7518 §6.4.1, §6.3.2) those bytes are key
    // material, so they must not be left in freed memory (workspace
    // CLAUDE.md: key material is zeroized).
    let mut buf = Zeroizing::new(vec![0u8; decoded_len(s.len())]);
    let len = Base64UrlUnpadded::decode(s, &mut buf)
        .map_err(|_| crate::Error::InvalidBase64)?
        .len();
    buf.truncate(len);
    // Move the allocation out without copying; the emptied wrapper is dropped.
    Ok(core::mem::take(&mut *buf))
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
