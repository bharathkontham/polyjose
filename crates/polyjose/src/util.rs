//! base64url (RFC 4648 §5, no padding) helpers used throughout JOSE.
use base64ct::{Base64UrlUnpadded, Encoding};

/// Encodes bytes as unpadded base64url.
pub fn b64url_encode(data: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(data)
}

/// Decodes unpadded base64url.
pub fn b64url_decode(s: &str) -> crate::Result<Vec<u8>> {
    Base64UrlUnpadded::decode_vec(s).map_err(|_| crate::Error::InvalidBase64)
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
}
