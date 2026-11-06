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
/// # Errors
///
/// [`Error::DecryptionFailed`] for every failure: a malformed RFC 1951
/// stream or output over `max_len` (ADR 0017 §1; RFC 7516 §11.4 asks for
/// one undifferentiated error once key management has started).
#[cfg(feature = "deflate")]
pub(crate) fn decompress(compressed: &[u8], max_len: usize) -> Result<Zeroizing<Vec<u8>>> {
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
}
