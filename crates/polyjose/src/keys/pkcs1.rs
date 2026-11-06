//! The PKCS#1 RSAPublicKey structure (RFC 8017 App. A.1.1), standalone as
//! OpenSSL's `RSA PUBLIC KEY` and inside the SPKI subjectPublicKey: a
//! positive, minimal modulus and public exponent (X.690 §8.3).
//!
//! ```text
//! RSAPublicKey ::= SEQUENCE {
//!     modulus           INTEGER,  -- n
//!     publicExponent    INTEGER   -- e
//! }
//! ```
//!
//! Only the encoding is checked here. What makes `n` and `e` a usable key
//! (at least 2048 bits, odd `n`, odd `e` with 3 ≤ e < n; RFC 7518 §3.3,
//! §4.2, RFC 8017 §3.1, ADR 0007) is checked once, by `Jwk::from_object`,
//! when `rsa.rs` builds the JWK.

use zeroize::Zeroizing;

use super::der::{self, Reader, Writer};
use crate::error::{Error, Result};

/// The two RSAPublicKey INTEGERs as unsigned big-endian magnitudes in the
/// fewest octets (the DER sign octet removed, X.690 §8.3.3), the form JWK's
/// Base64urlUInt needs (RFC 7518 §2, §6.3.1). Both borrow from the decoded
/// DER. The values are public, so they need no zeroization.
#[derive(Clone, Copy)]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "read by the RSA mapper (rsa.rs)")
)]
pub(crate) struct RsaPublicParts<'a> {
    /// `modulus`, n (RFC 8017 App. A.1.1).
    pub(crate) n: &'a [u8],
    /// `publicExponent`, e (RFC 8017 App. A.1.1).
    pub(crate) e: &'a [u8],
}

/// Decodes a DER RSAPublicKey (RFC 8017 App. A.1.1), as found in the
/// subjectPublicKey of an rsaEncryption SPKI (RFC 3279 §2.3.1: the key
/// "MUST" be an RSAPublicKey): one SEQUENCE of exactly two non-negative,
/// minimal INTEGERs (X.690 §8.3.2), with no data after it (§8.1.1).
///
/// # Errors
///
/// [`Error::InvalidKey`] for anything else: a negative or non-minimal
/// INTEGER, a missing or extra field, trailing data.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "called by the RSA mapper (rsa.rs)")
)]
pub(crate) fn decode_public(der: &[u8]) -> Result<RsaPublicParts<'_>> {
    let mut outer = Reader::new(der)?;
    let fields = outer.sequence()?;
    outer.finish()?;
    read_public(fields)
}

/// Reads the fields of an RSAPublicKey SEQUENCE: `modulus` and
/// `publicExponent`, each a non-negative minimal INTEGER
/// ([`Reader::unsigned_integer`], X.690 §8.3), and nothing else
/// (RFC 8017 App. A.1.1).
fn read_public(mut fields: Reader<'_>) -> Result<RsaPublicParts<'_>> {
    let n = fields.unsigned_integer()?;
    let e = fields.unsigned_integer()?;
    if !fields.is_empty() {
        return Err(Error::InvalidKey(
            "RSAPublicKey holds more than modulus and publicExponent",
        ));
    }
    Ok(RsaPublicParts { n, e })
}

/// Encodes an RSAPublicKey (RFC 8017 App. A.1.1) in DER from the unsigned
/// magnitudes `n` and `e`: each a minimal INTEGER with a 0x00 sign octet
/// where the top bit is set (X.690 §8.3.2, §8.3.3), the layout OpenSSL 4
/// emits (ADR 0018 §3).
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "called by the RSA mapper (rsa.rs)")
)]
pub(crate) fn encode_public(n: &[u8], e: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let body = der::unsigned_integer_len(n) + der::unsigned_integer_len(e);
    let mut writer = Writer::new(der::encoded_len(body))?;
    writer.header(der::SEQUENCE, body)?;
    writer.unsigned_integer(n)?;
    writer.unsigned_integer(e)?;
    writer.finish()
}

#[cfg(test)]
mod tests {
    use super::super::der::fixtures;
    use super::*;
    use crate::util::b64url_decode;

    fn is_invalid<T>(result: &Result<T>) -> bool {
        matches!(result, Err(Error::InvalidKey(_)))
    }

    /// RFC 7517 App. A.1, the RSA public key: `n` and `e` as Base64urlUInt
    /// (RFC 7518 §6.3.1.1, §6.3.1.2).
    const A1_N: &str = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";

    /// Every positive standalone RSAPublicKey fixture, as DER.
    fn public_fixtures() -> Vec<(&'static str, String)> {
        let mut out = Vec::new();
        for dir in ["openssl", "rfc"] {
            for file in fixtures::files(dir, |name| {
                name.contains("-pkcs1-pub") && !name.starts_with("reject-")
            }) {
                out.push((dir, file));
            }
        }
        assert_eq!(
            out.len(),
            5,
            "rsa2048 (der, pem), rsa4096 (pem), RFC 7517 A.1 (der, pem)"
        );
        out
    }

    #[test]
    fn rfc7517_a1_rsa_public_key_decodes_to_its_n_and_e() {
        // RFC 7517 App. A.1 as PKCS#1: `n` with its DER sign octet removed
        // is exactly the JWK's minimal `n`, and e is 65537 (AQAB).
        let der = fixtures::load("rfc", "rfc7517-a1-rsa-pkcs1-pub.der");
        let key = decode_public(&der).unwrap();
        assert_eq!(key.n, b64url_decode(A1_N).unwrap().as_slice());
        assert_eq!(key.e, &[0x01, 0x00, 0x01]);
        // The modulus's top bit is set, so DER carries a 0x00 sign octet
        // (X.690 §8.3.3) that the magnitude does not.
        assert_eq!(key.n.len(), 256);
        assert!(key.n[0] & 0x80 != 0);
    }

    #[test]
    fn every_public_fixture_decodes_and_re_encodes_to_its_bytes() {
        // ADR 0018 §3: export in the layout OpenSSL 4 emits.
        for (dir, file) in public_fixtures() {
            let der = fixtures::load(dir, &file);
            let key = decode_public(&der).unwrap_or_else(|e| panic!("{file}: {e:?}"));
            assert_ne!(key.n[0], 0, "{file}: n is minimal");
            let again = encode_public(key.n, key.e).unwrap();
            assert_eq!(&again[..], &der[..], "{file}");
        }
    }

    #[test]
    fn decode_borrows_the_input() {
        let der = fixtures::load("rfc", "rfc7517-a1-rsa-pkcs1-pub.der");
        let key = decode_public(&der).unwrap();
        let range = der.as_ptr_range();
        assert!(range.contains(&key.n.as_ptr()));
        assert!(range.contains(&key.e.as_ptr()));
    }

    #[test]
    fn encode_adds_the_sign_octet_only_where_needed() {
        // X.690 §8.3.2, §8.3.3: 0x80 needs a leading 0x00, 0x7F does not;
        // leading zero octets in the input are not significant.
        let der = encode_public(&[0x80, 0x01], &[0x00, 0x03]).unwrap();
        assert_eq!(
            &der[..],
            &[0x30, 0x08, 0x02, 0x03, 0x00, 0x80, 0x01, 0x02, 0x01, 0x03]
        );
        let der = encode_public(&[0x7F], &[0x03]).unwrap();
        assert_eq!(&der[..], &[0x30, 0x06, 0x02, 0x01, 0x7F, 0x02, 0x01, 0x03]);
    }

    #[test]
    fn malformed_rsa_public_keys_are_invalid() {
        // RFC 8017 App. A.1.1: exactly modulus and publicExponent, both
        // positive (X.690 §8.3.3) and minimal (§8.3.2).
        for (what, der) in [
            ("empty", vec![]),
            ("empty SEQUENCE", vec![0x30, 0x00]),
            ("one INTEGER", vec![0x30, 0x03, 0x02, 0x01, 0x05]),
            (
                "three INTEGERs",
                vec![
                    0x30, 0x09, 0x02, 0x01, 0x05, 0x02, 0x01, 0x03, 0x02, 0x01, 0x03,
                ],
            ),
            (
                "negative n",
                vec![0x30, 0x06, 0x02, 0x01, 0x85, 0x02, 0x01, 0x03],
            ),
            (
                "negative e",
                vec![0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x83],
            ),
            (
                "non-minimal n",
                vec![0x30, 0x07, 0x02, 0x02, 0x00, 0x05, 0x02, 0x01, 0x03],
            ),
            (
                "n not an INTEGER",
                vec![0x30, 0x06, 0x04, 0x01, 0x05, 0x02, 0x01, 0x03],
            ),
            (
                "trailing data",
                vec![0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x03, 0x00],
            ),
            (
                "an uncompressed EC point",
                vec![0x04, 0x01, 0x02, 0x03, 0x04],
            ),
        ] {
            assert!(is_invalid(&decode_public(&der)), "{what}");
        }
    }

    #[test]
    fn the_rsa_public_key_negative_vectors_are_invalid() {
        // N65: RSAPublicKey with a third INTEGER (RFC 8017 App. A.1.1).
        assert!(is_invalid(&decode_public(&fixtures::negative("N65"))));
    }
}
