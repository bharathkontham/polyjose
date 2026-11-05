//! base64url (RFC 4648 §5, no padding) helpers used throughout JOSE.
use base64ct::{Base64UrlUnpadded, Encoding};

/// Encodes bytes as unpadded base64url.
pub fn b64url_encode(data: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(data)
}

/// Decodes unpadded base64url.
pub fn b64url_decode(s: &str) -> crate::Result<Vec<u8>> {
    Base64UrlUnpadded::decode_vec(s).map_err(|_| crate::Error::Base64)
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
}
