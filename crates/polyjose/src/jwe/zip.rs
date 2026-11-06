//! JWE `zip: DEF` (RFC 7516 §4.1.3): raw DEFLATE (RFC 1951) of the
//! plaintext before encryption (§5.1 step 11) and inflation after the tag
//! is verified (§5.2 step 17), on polyjose's own bounded codec
//! (`crate::deflate`, ADR 0017). Only with the off-by-default `deflate`
//! feature; without it both functions fail with
//! [`Error::UnsupportedAlgorithm`].
//!
//! RFC 8725 §3.6: compressing data before encrypting it can reveal
//! information about the plaintext through the ciphertext length, so
//! `Encryptor::compress` is off by default and should be used only for data
//! an attacker cannot influence. Decryption accepts `zip` only from the
//! protected header (RFC 7516 §4.1.3), which `core` checks before this
//! module is reached.

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
/// **`max_len` is also the up-front allocation.** `deflate::inflate`
/// allocates its single output buffer before decoding, with capacity
/// min(`max_len`, 1,032 × `compressed.len()`), and never grows it, so one
/// JWE costs at most `max_len` bytes of plaintext buffer however far its
/// stream claims to expand (the LZ77 window lives inside that buffer;
/// ADR 0017 §1 allows the bound plus 32 KiB). `max_len` is therefore passed
/// on unchanged, never widened (say, to `usize::MAX`), and a caller who
/// raises `DecryptPolicy::max_decompressed_len` raises the memory one
/// authenticated JWE can claim by the same amount. The returned buffer is
/// that allocation, not shrunk (a shrink would reallocate and leave an
/// unwiped copy of the plaintext behind), and is wiped on drop.
///
/// Inflation runs only on authenticated data, but the sender can be anyone
/// holding the recipient's public key (ECDH-ES, RSA-OAEP-256), so the
/// stream is still untrusted (ADR 0017 context; CVE-2024-28180,
/// CVE-2024-28176, CVE-2024-29371).
///
/// # Errors
///
/// [`Error::DecryptionFailed`] for every failure: a malformed RFC 1951
/// stream, output over `max_len`, or `max_len == 0` (ADR 0017 §1; RFC 7516
/// §11.4 asks for one undifferentiated error once key management has
/// started).
#[cfg(feature = "deflate")]
pub(crate) fn decompress(compressed: &[u8], max_len: usize) -> Result<Zeroizing<Vec<u8>>> {
    decompress_with(compressed, max_len, crate::deflate::inflate)
}

/// [`decompress`] over the inflater `inflate`, which tests replace to see
/// the bound it is given. `max_len` is passed unchanged: it is also the
/// size `deflate::inflate` allocates up front (at most; less when the input
/// cannot expand that far), so a larger value would only allocate more.
#[cfg(feature = "deflate")]
fn decompress_with(
    compressed: &[u8],
    max_len: usize,
    inflate: impl FnOnce(&[u8], usize) -> Result<Zeroizing<Vec<u8>>>,
) -> Result<Zeroizing<Vec<u8>>> {
    if max_len == 0 {
        return Err(Error::DecryptionFailed);
    }
    #[cfg(test)]
    crate::test_counters::inflate_calls::tick();
    inflate(compressed, max_len).map_err(|_| Error::DecryptionFailed)
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
    use crate::header::Header;
    use crate::jwa::{ContentEncAlg, KeyMgmtAlg};
    use crate::jwe::api::DecryptPolicy;
    use crate::jwe::content::{self, Cek};
    use crate::jwe::core::{self as pipeline, JweParts, RecipientParts};
    use crate::jwk::Jwk;
    use crate::test_counters::inflate_calls;
    use crate::util::b64url_encode;

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

    /// An RFC 1951 stream written LSB first (§3.1.1); Huffman codes go
    /// most-significant bit first (§3.2.2).
    #[derive(Default)]
    struct Bits {
        out: Vec<u8>,
        len: usize,
    }

    impl Bits {
        fn bit(&mut self, bit: u32) {
            self.zeros(1);
            if let Some(last) = self.out.last_mut() {
                *last |= u8::from(bit & 1 == 1) << ((self.len - 1) % 8);
            }
        }

        /// A header field or extra bits: least-significant bit first.
        fn value(&mut self, value: u32, count: u32) {
            (0..count).for_each(|i| self.bit(value >> i));
        }

        /// A Huffman code: most-significant bit first.
        fn code(&mut self, code: u32, count: u32) {
            (0..count).rev().for_each(|i| self.bit(code >> i));
        }

        fn zeros(&mut self, count: usize) {
            self.len += count;
            self.out.resize(self.len.div_ceil(8), 0);
        }
    }

    /// A decompression bomb (the CVE-2024-28180 class, ADR 0017): one
    /// dynamic block (RFC 1951 §3.2.7) in which length 258 (symbol 285) and
    /// distance 1 (distance code 0) are one-bit codes, so after one `a`
    /// every two input bits, both zero, expand to 258 more `a`s: DEFLATE's
    /// ceiling of 1,032 output bytes per input byte. The output is
    /// `1 + 258 * matches` bytes.
    fn bomb(matches: usize) -> Vec<u8> {
        let mut w = Bits::default();
        w.value(1, 1); // BFINAL
        w.value(0b10, 2); // BTYPE: dynamic Huffman codes
        w.value(286 - 257, 5); // HLIT
        w.value(0, 5); // HDIST: one distance code
        w.value(18 - 4, 4); // HCLEN: code-length codes up to symbol 1
        // Code-length code lengths, in the §3.2.7 order 16, 17, 18, 0, 8,
        // 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1: symbol 18 gets length
        // 1 (code 0), symbols 1 and 2 length 2 (codes 10 and 11).
        let order = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1];
        for symbol in order {
            w.value(
                match symbol {
                    18 => 1,
                    1 | 2 => 2,
                    _ => 0,
                },
                3,
            );
        }
        let zeros = |w: &mut Bits, n: u32| {
            w.code(0, 1); // 18: repeat a zero length 11-138 times
            w.value(n - 11, 7);
        };
        // Literal/length lengths: 97 ('a') -> 2, 256 -> 2, 285 -> 1, so the
        // codes are 285 -> 0, 'a' -> 10, 256 -> 11; distance 0 -> 1.
        zeros(&mut w, 97);
        w.code(0b11, 2); // length 2 for 'a'
        zeros(&mut w, 138);
        zeros(&mut w, 20);
        w.code(0b11, 2); // length 2 for 256
        zeros(&mut w, 28);
        w.code(0b10, 2); // length 1 for 285
        w.code(0b10, 2); // length 1 for distance code 0
        w.code(0b10, 2); // 'a'
        w.zeros(2 * matches); // length 258 (code 0), distance 1 (code 0)
        w.code(0b11, 2); // end of block
        w.out
    }

    /// The 1 GiB bomb: about 1 MiB of input (DEFLATE expands at most
    /// 1,032:1).
    fn gib_bomb() -> Vec<u8> {
        let bomb = bomb((1 << 30) / 258 + 1);
        assert!(bomb.len() < 1100 * 1024, "bomb is {} bytes", bomb.len());
        bomb
    }

    #[test]
    fn the_bomb_is_valid_deflate() {
        let out = inflate_all(&bomb(1000));
        assert_eq!(out.len(), 1 + 258 * 1000);
        assert!(out.iter().all(|&b| b == b'a'));
    }

    const KEY: [u8; 16] = [0x5A; 16];

    fn dir_key() -> Jwk {
        let json = format!(r#"{{"kty":"oct","k":"{}"}}"#, b64url_encode(&KEY));
        Jwk::from_json(json.as_bytes()).unwrap_or_else(|e| panic!("{e}"))
    }

    fn policy() -> DecryptPolicy {
        DecryptPolicy::new(&[KeyMgmtAlg::Dir], &[ContentEncAlg::A128GCM])
            .unwrap_or_else(|e| panic!("{e}"))
    }

    /// A `dir` + A128GCM + `zip: DEF` JWE whose authenticated plaintext is
    /// `payload` as given, so it can be a stream polyjose would never write.
    fn zip_jwe(payload: &[u8]) -> JweParts {
        let json = r#"{"alg":"dir","enc":"A128GCM","zip":"DEF"}"#;
        let protected_b64 = b64url_encode(json.as_bytes());
        let iv = vec![7; 12];
        let aad = content::aad(&protected_b64, None);
        let cek = Cek::from_slice(&KEY);
        let (ciphertext, tag) = content::encrypt(&ContentEncAlg::A128GCM, &cek, &iv, &aad, payload)
            .unwrap_or_else(|e| panic!("{e}"));
        JweParts {
            protected_b64,
            protected: Some(Header::from_json(json.as_bytes()).unwrap_or_else(|e| panic!("{e}"))),
            shared: None,
            recipients: vec![RecipientParts {
                header: None,
                encrypted_key: Vec::new(),
            }],
            iv,
            ciphertext,
            tag,
            aad: None,
        }
    }

    #[test]
    fn a_bad_tag_never_inflates() {
        // RFC 7516 §5.2 steps 16-17: decompression only after the tag
        // verified, so a forged bomb costs no inflation at all.
        let bomb = gib_bomb();
        let mut parts = zip_jwe(&bomb);
        parts.tag[0] ^= 1;
        let (result, inflations) =
            inflate_calls::count(|| pipeline::decrypt(parts, &dir_key(), &policy()));
        assert_eq!(result.err(), Some(Error::DecryptionFailed));
        assert_eq!(inflations, 0);

        // The same bomb, authenticated: inflated once, stopped at the bound.
        let parts = zip_jwe(&bomb);
        let (result, inflations) =
            inflate_calls::count(|| pipeline::decrypt(parts, &dir_key(), &policy()));
        assert_eq!(result.err(), Some(Error::DecryptionFailed));
        assert_eq!(inflations, 1);
    }

    #[test]
    fn a_zero_bound_never_inflates() {
        let parts = zip_jwe(&EMPTY_STREAM);
        let zero = policy().max_decompressed_len(0);
        let (result, inflations) =
            inflate_calls::count(|| pipeline::decrypt(parts, &dir_key(), &zero));
        assert_eq!(result.err(), Some(Error::DecryptionFailed));
        assert_eq!(inflations, 0);
    }

    #[test]
    fn inflate_gets_exactly_the_policy_bound() {
        // The T08 note: `deflate::inflate` allocates min(max_output, 1,032 x
        // input length) up front, so the bound zip passes is the allocation
        // size and must be the policy's, never a larger one.
        let bomb = gib_bomb();
        for bound in [
            DecryptPolicy::DEFAULT_MAX_DECOMPRESSED_LEN,
            1,
            4096,
            1 << 20,
        ] {
            let mut seen = Vec::new();
            let result = decompress_with(&bomb, bound, |input, max| {
                seen.push(max);
                crate::deflate::inflate(input, max)
            });
            assert_eq!(result, Err(Error::DecryptionFailed), "bound {bound}");
            assert_eq!(seen, [bound]);
        }
        assert_eq!(policy().max_decompressed_len, 250_000);
    }

    #[test]
    fn the_output_buffer_is_at_most_the_policy_bound() {
        // Through the whole pipeline (policy -> core -> zip -> inflate): a
        // stream inflating to exactly the policy bound succeeds, so the cap
        // inflate got is at least the bound; its single buffer, sized
        // min(cap, 1,032 x input length) with the second term above the
        // bound, is no larger than the bound, so the cap is at most the
        // bound. With bound - 1 it fails.
        let matches = 2000;
        let stream = bomb(matches);
        let bound = 1 + 258 * matches;
        assert!(1032 * stream.len() > bound);
        let exact = policy().max_decompressed_len(bound);
        let decrypted = pipeline::decrypt(zip_jwe(&stream), &dir_key(), &exact)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(decrypted.plaintext.len(), bound);
        assert!(decrypted.plaintext.capacity() <= bound);

        let under = policy().max_decompressed_len(bound - 1);
        let result = pipeline::decrypt(zip_jwe(&stream), &dir_key(), &under);
        assert_eq!(result.err(), Some(Error::DecryptionFailed));
    }
}
