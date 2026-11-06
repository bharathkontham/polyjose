//! JWE `zip: DEF` (RFC 7516 §4.1.3): raw DEFLATE (RFC 1951) of the
//! plaintext before encryption (§5.1 step 11) and inflation after the tag
//! is verified (§5.2 step 17), on polyjose's own bounded codec
//! (`crate::deflate`, ADR 0017). Only with the off-by-default `deflate`
//! feature; without it both functions fail with
//! [`Error::UnsupportedAlgorithm`].

use zeroize::Zeroizing;

use crate::{Error, Result};

/// Compresses `plaintext` with raw DEFLATE (RFC 7516 §5.1 step 11, RFC
/// 1951; RFC 7518 §7.3 registers `DEF`). `core` calls it after the content
/// IV is drawn and before content encryption, and puts `zip: "DEF"` in the
/// protected header (RFC 7516 §4.1.3).
///
/// Compressing before encrypting can reveal plaintext through the
/// ciphertext length (RFC 8725 §3.6), which is why `Encryptor::compress`
/// exists only with the `deflate` feature and is opt-in.
///
/// # Errors
///
/// None with the `deflate` feature (every input has a DEFLATE encoding).
#[cfg(feature = "deflate")]
pub(crate) fn compress(plaintext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    crate::deflate::deflate(plaintext)
}

/// Without the `deflate` feature there is no codec (ADR 0017 §5).
///
/// # Errors
///
/// Always [`Error::UnsupportedAlgorithm`].
#[cfg(not(feature = "deflate"))]
pub(crate) fn compress(_plaintext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    Err(Error::UnsupportedAlgorithm)
}

/// Inflates `compressed`, the plaintext of a `zip: "DEF"` JWE (RFC 7516
/// §5.2 step 17), producing at most `max_len` bytes. `core` calls it only
/// after the authentication tag verified (§5.2 step 16), with
/// `max_len` = `DecryptPolicy::max_decompressed_len` (ADR 0017 §3).
///
/// The bound is inclusive: exactly `max_len` bytes inflate, one more fails.
/// `max_len == 0` rejects every compressed JWE (ADR 0017 §3), even one
/// whose plaintext is empty, without starting inflation.
///
/// # Errors
///
/// [`Error::DecryptionFailed`] for every failure: a malformed RFC 1951
/// stream, output over `max_len`, or `max_len == 0` (ADR 0017 §1; RFC 7516
/// §11.4 asks for one undifferentiated error once key management has
/// started).
#[cfg(feature = "deflate")]
pub(crate) fn decompress(compressed: &[u8], max_len: usize) -> Result<Zeroizing<Vec<u8>>> {
    if max_len == 0 {
        return Err(Error::DecryptionFailed);
    }
    crate::deflate::inflate(compressed, max_len).map_err(|_| Error::DecryptionFailed)
}

/// Without the `deflate` feature there is no codec (ADR 0017 §5); `core`
/// already rejects `zip: "DEF"` before decryption, so this is unreachable
/// from the public API.
///
/// # Errors
///
/// Always [`Error::UnsupportedAlgorithm`].
#[cfg(not(feature = "deflate"))]
pub(crate) fn decompress(_compressed: &[u8], _max_len: usize) -> Result<Zeroizing<Vec<u8>>> {
    Err(Error::UnsupportedAlgorithm)
}

#[cfg(all(test, not(feature = "deflate")))]
mod tests_without_deflate {
    use super::*;

    #[test]
    fn both_directions_are_unsupported_without_deflate() {
        // ADR 0017 §5; core rejects `zip: DEF` before either is reached.
        assert_eq!(compress(b"x"), Err(Error::UnsupportedAlgorithm));
        assert_eq!(
            decompress(&[0x03, 0x00], 1),
            Err(Error::UnsupportedAlgorithm)
        );
    }
}

#[cfg(all(test, feature = "deflate"))]
mod tests {
    #![allow(clippy::panic)] // test code: a panic is a failed assertion

    use super::*;

    /// Inflates with no bound worth mentioning, for round-trip checks.
    fn inflate_all(compressed: &[u8]) -> Zeroizing<Vec<u8>> {
        decompress(compressed, usize::MAX).unwrap_or_else(|e| panic!("{e}"))
    }

    #[test]
    fn compressed_plaintext_round_trips() {
        // RFC 7516 §5.1 step 11 and §5.2 step 17 are inverses.
        let text = b"You can trust us to stick with you through thick and thin".repeat(40);
        for plaintext in [&b""[..], b"a", &text[..], &[0u8; 70_000][..]] {
            let compressed = compress(plaintext).unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(&inflate_all(&compressed)[..], plaintext);
        }
        let compressed = compress(&text).unwrap_or_else(|e| panic!("{e}"));
        assert!(compressed.len() < text.len() / 4, "not compressed");
    }

    /// A fixed-Huffman block (RFC 1951 §3.2.6) holding only end-of-block:
    /// a valid stream that inflates to nothing.
    const EMPTY_STREAM: [u8; 2] = [0x03, 0x00];

    #[test]
    fn the_bound_is_inclusive() {
        // ADR 0017 §1: inflation fails "the moment the output would exceed"
        // the bound, so exactly `max_len` bytes still succeed.
        let plaintext = b"0123456789".repeat(25_000);
        let compressed = compress(&plaintext).unwrap_or_else(|e| panic!("{e}"));
        let out = decompress(&compressed, 250_000).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(&out[..], &plaintext[..]);
        assert_eq!(
            decompress(&compressed, 249_999),
            Err(Error::DecryptionFailed)
        );

        let longer = b"0123456789".repeat(25_001);
        let compressed = compress(&longer[..250_001]).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            decompress(&compressed, 250_000),
            Err(Error::DecryptionFailed)
        );
        assert_eq!(
            decompress(&compressed, 250_001).map(|v| v.len()),
            Ok(250_001)
        );
    }

    #[test]
    fn a_zero_bound_rejects_every_stream() {
        // ADR 0017 §3: "Setting it to 0 rejects every zip token", even one
        // whose plaintext is empty and so would fit.
        assert_eq!(decompress(&EMPTY_STREAM, 0), Err(Error::DecryptionFailed));
        let empty = compress(b"").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(decompress(&empty, 0), Err(Error::DecryptionFailed));
        assert_eq!(decompress(b"", 0), Err(Error::DecryptionFailed));
        assert_eq!(decompress(&EMPTY_STREAM, 1).map(|v| v.len()), Ok(0));
    }

    #[test]
    fn every_inflate_error_is_decryption_failed() {
        // ADR 0017 §1, RFC 7516 §11.4: the unit error, whatever the cause.
        let valid = compress(b"hello hello hello").unwrap_or_else(|e| panic!("{e}"));
        let malformed: [&[u8]; 6] = [
            b"",                                // no block at all (RFC 1951 §3.2.3)
            &[0x07],                            // BTYPE 11, reserved (§3.2.3)
            &[0x01, 0x05, 0x00, 0x00, 0x00],    // stored, NLEN not ~LEN (§3.2.4)
            &[0x01, 0x05, 0x00, 0xFA, 0xFF, 1], // stored, LEN past the input
            &[0x00],                            // BFINAL 0 and then nothing
            &valid[..valid.len() - 1],          // truncated
        ];
        for input in malformed {
            assert_eq!(
                decompress(input, 1 << 20),
                Err(Error::DecryptionFailed),
                "{input:?}"
            );
        }
    }
}
