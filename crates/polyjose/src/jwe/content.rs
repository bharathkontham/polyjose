//! Content encryption: the CEK, the content IV, the Additional
//! Authenticated Data and the `enc` dispatcher (RFC 7516 §5.1 steps 2, 9
//! and 13–15, §5.2 steps 14–16; RFC 7518 §5).
//!
//! [`encrypt`] and [`decrypt`] dispatch on `enc` to `enc_gcm` (A*GCM,
//! RFC 7518 §5.3) and `enc_cbc_hmac` (A*CBC-HS*, RFC 7518 §5.2). Every
//! decryption failure is [`Error::DecryptionFailed`], with no detail
//! (RFC 7516 §11.4).

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::random::RandomSource;
use crate::jwa::ContentEncAlg;
use crate::util::b64url_encode;
use crate::{Error, Result};

/// A Content Encryption Key (RFC 7516 §2).
///
/// The bytes are wiped on drop, and `Debug` prints `<redacted>` instead of
/// them (ADR 0007).
pub(crate) struct Cek(Zeroizing<Vec<u8>>);

impl Cek {
    /// A CEK holding `bytes`.
    pub(crate) fn new(bytes: Zeroizing<Vec<u8>>) -> Self {
        Cek(bytes)
    }

    /// A CEK holding a copy of `bytes`.
    pub(crate) fn from_slice(bytes: &[u8]) -> Self {
        Cek(Zeroizing::new(bytes.to_vec()))
    }

    /// The key bytes.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The key length in bytes.
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
}

impl Zeroize for Cek {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// The only field is a [`Zeroizing`] buffer.
impl ZeroizeOnDrop for Cek {}

impl fmt::Debug for Cek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Cek(<redacted>)")
    }
}

/// The CEK length `enc` requires, in bytes: 32, 48 and 64 for
/// A128CBC-HS256, A192CBC-HS384 and A256CBC-HS512 (RFC 7518 §5.2.3–§5.2.5:
/// MAC_KEY || ENC_KEY), and 16, 24 and 32 for A128GCM, A192GCM and A256GCM
/// (RFC 7518 §5.3).
///
/// # Errors
///
/// [`Error::UnsupportedAlgorithm`] for an unknown `enc` (RFC 7516 §4.1.2).
pub(crate) fn cek_len(enc: &ContentEncAlg) -> Result<usize> {
    match enc {
        ContentEncAlg::A128CbcHs256 => Ok(32),
        ContentEncAlg::A192CbcHs384 => Ok(48),
        ContentEncAlg::A256CbcHs512 => Ok(64),
        ContentEncAlg::A128GCM => Ok(16),
        ContentEncAlg::A192GCM => Ok(24),
        ContentEncAlg::A256GCM => Ok(32),
        ContentEncAlg::Unknown(_) => Err(Error::UnsupportedAlgorithm),
    }
}

/// The content IV length `enc` requires, in bytes: 16 for A*CBC-HS*, the
/// AES block size (RFC 7518 §5.2.2.1), and 12 for A*GCM, 96 bits
/// (RFC 7518 §5.3).
///
/// # Errors
///
/// [`Error::UnsupportedAlgorithm`] for an unknown `enc` (RFC 7516 §4.1.2).
pub(crate) fn iv_len(enc: &ContentEncAlg) -> Result<usize> {
    match enc {
        ContentEncAlg::A128CbcHs256 | ContentEncAlg::A192CbcHs384 | ContentEncAlg::A256CbcHs512 => {
            Ok(16)
        }
        ContentEncAlg::A128GCM | ContentEncAlg::A192GCM | ContentEncAlg::A256GCM => Ok(12),
        ContentEncAlg::Unknown(_) => Err(Error::UnsupportedAlgorithm),
    }
}

/// Draws a random CEK of exactly [`cek_len`] bytes from `rng` (RFC 7516
/// §5.1 step 2: "generate a random Content Encryption Key"; RFC 7518 §8.9:
/// a key must not be reused across algorithms), as the first draw of a
/// message (see `jwe::random` for the draw order).
///
/// The bytes go straight into the zeroizing [`Cek`] buffer; no other copy
/// is made.
///
/// # Errors
///
/// [`Error::UnsupportedAlgorithm`] for an unknown `enc`, before anything
/// is drawn; [`Error::RandomnessUnavailable`] if `rng` fails (ADR 0005:
/// fail closed, never a short key).
pub(crate) fn generate_cek(enc: &ContentEncAlg, rng: &mut dyn RandomSource) -> Result<Cek> {
    let mut cek = Zeroizing::new(vec![0u8; cek_len(enc)?]);
    rng.fill(&mut cek)?;
    Ok(Cek::new(cek))
}

/// Draws a random content IV of exactly [`iv_len`] bytes from `rng`
/// (RFC 7516 §5.1 step 9: "generate a random JWE Initialization Vector of
/// the correct size for the content encryption algorithm"): 16 bytes for
/// A*CBC-HS* (RFC 7518 §5.2.2.1) and 12 for A*GCM (RFC 7518 §5.3).
///
/// A random 96-bit GCM IV under one key is safe for at most 2^32
/// messages (RFC 7518 §8.4); that bound is documented, not enforced.
///
/// # Errors
///
/// [`Error::UnsupportedAlgorithm`] for an unknown `enc`, before anything
/// is drawn; [`Error::RandomnessUnavailable`] if `rng` fails (ADR 0005).
pub(crate) fn generate_iv(enc: &ContentEncAlg, rng: &mut dyn RandomSource) -> Result<Vec<u8>> {
    let mut iv = vec![0u8; iv_len(enc)?];
    rng.fill(&mut iv)?;
    Ok(iv)
}

/// The Additional Authenticated Data of RFC 7516 §5.1 step 14 (and §5.2
/// step 15): `ASCII(Encoded Protected Header)`, or, with a JWE AAD value,
/// `ASCII(Encoded Protected Header || '.' || BASE64URL(JWE AAD))`.
///
/// `encoded_protected` must be the protected header **as received** (or as
/// produced on encrypt), never a re-serialization (RFC 7516 §5.2 step 14;
/// erratum 8676). It is empty when a JSON JWE has no protected header
/// (RFC 7516 §7.2.1).
pub(crate) fn aad(encoded_protected: &str, jwe_aad: Option<&[u8]>) -> Vec<u8> {
    let mut out = encoded_protected.as_bytes().to_vec();
    if let Some(jwe_aad) = jwe_aad {
        out.push(b'.');
        out.extend_from_slice(b64url_encode(jwe_aad).as_bytes());
    }
    out
}

/// Encrypts `plaintext` under `cek` and `iv` with `aad` (RFC 7516 §5.1
/// step 15) and returns `(ciphertext, tag)`, dispatching on `enc` to
/// AES-GCM (RFC 7518 §5.3) or AES_CBC_HMAC_SHA2 (RFC 7518 §5.2). Filled in
/// by T02 (dispatch and GCM) and T03 (CBC-HMAC).
///
/// # Errors
///
/// [`Error::UnsupportedAlgorithm`] for an unknown `enc`; an error if the
/// CEK or IV length is wrong for `enc`.
pub(crate) fn encrypt(
    _enc: &ContentEncAlg,
    _cek: &Cek,
    _iv: &[u8],
    _aad: &[u8],
    _plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    Err(Error::UnsupportedAlgorithm)
}

/// Verifies `tag` and decrypts `ciphertext` (RFC 7516 §5.2 step 16): no
/// plaintext is returned, or left in a returned buffer, unless the tag is
/// correct. Dispatches like [`encrypt`]. Filled in by T02 and T03.
///
/// # Errors
///
/// [`Error::DecryptionFailed`] for every failure once `enc` is known:
/// tag, ciphertext, IV, AAD, padding, or CEK length (RFC 7516 §11.4).
pub(crate) fn decrypt(
    _enc: &ContentEncAlg,
    _cek: &Cek,
    _iv: &[u8],
    _aad: &[u8],
    _ciphertext: &[u8],
    _tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    Err(Error::UnsupportedAlgorithm)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwe::random::OsRandom;
    use crate::rng::insecure_test_vectors::FixedRng;

    fn assert_zeroize_on_drop<T: Zeroize + ZeroizeOnDrop>() {}

    #[test]
    fn cek_is_wiped_and_never_printed() {
        assert_zeroize_on_drop::<Cek>();
        let mut cek = Cek::from_slice(&[0xC5; 16]);
        assert_eq!(cek.len(), 16);
        assert_eq!(cek.as_bytes(), &[0xC5; 16]);
        let debug = format!("{cek:?}");
        assert_eq!(debug, "Cek(<redacted>)");
        assert!(!debug.contains("197") && !debug.to_lowercase().contains("c5"));
        cek.zeroize();
        assert!(cek.as_bytes().iter().all(|&b| b == 0));
        let cek = Cek::new(Zeroizing::new(vec![1, 2, 3]));
        assert_eq!(cek.as_bytes(), [1, 2, 3]);
    }

    #[test]
    fn cek_and_iv_lengths_follow_rfc_7518() {
        let table = [
            (ContentEncAlg::A128CbcHs256, 32, 16),
            (ContentEncAlg::A192CbcHs384, 48, 16),
            (ContentEncAlg::A256CbcHs512, 64, 16),
            (ContentEncAlg::A128GCM, 16, 12),
            (ContentEncAlg::A192GCM, 24, 12),
            (ContentEncAlg::A256GCM, 32, 12),
        ];
        assert_eq!(table.len(), ContentEncAlg::KNOWN.len());
        for (enc, cek, iv) in table {
            assert_eq!((cek_len(&enc), iv_len(&enc)), (Ok(cek), Ok(iv)), "{enc}");
        }
        let unknown = ContentEncAlg::from("A128CTR");
        assert_eq!(cek_len(&unknown), Err(Error::UnsupportedAlgorithm));
        assert_eq!(iv_len(&unknown), Err(Error::UnsupportedAlgorithm));
    }

    /// `0, 1, 2, ...`, so a draw's bytes show where in the stream it read.
    fn counting_rng(len: usize) -> FixedRng {
        FixedRng::new((0..len).map(|i| (i % 251) as u8).collect::<Vec<u8>>())
    }

    #[test]
    fn cek_and_iv_are_the_injected_bytes_in_draw_order() {
        // RFC 7516 §5.1 steps 2 and 9: the CEK is drawn first, then the IV
        // (the documented draw order of `jwe::random`), and each takes
        // exactly cek_len / iv_len bytes of the stream, nothing more.
        for enc in ContentEncAlg::KNOWN {
            let (cek_n, iv_n) = (cek_len(enc).unwrap(), iv_len(enc).unwrap());
            let mut rng = counting_rng(cek_n + iv_n + 5);
            let cek = generate_cek(enc, &mut rng).unwrap();
            assert_eq!(rng.remaining(), iv_n + 5, "{enc}: CEK draw size");
            let iv = generate_iv(enc, &mut rng).unwrap();
            assert_eq!(rng.remaining(), 5, "{enc}: IV draw size");
            let expected: Vec<u8> = (0..cek_n + iv_n).map(|i| i as u8).collect();
            assert_eq!(cek.as_bytes(), &expected[..cek_n], "{enc}");
            assert_eq!(iv, &expected[cek_n..], "{enc}");
        }
    }

    #[test]
    fn cek_and_iv_from_the_os_are_fresh() {
        // 128 bits or more per draw: equal draws are a 2^-96 event at
        // worst (the 96-bit GCM IV), not flakiness.
        for enc in ContentEncAlg::KNOWN {
            let mut os = OsRandom;
            let (a, b) = (generate_cek(enc, &mut os), generate_cek(enc, &mut os));
            let (a, b) = (a.unwrap(), b.unwrap());
            assert_eq!(a.len(), cek_len(enc).unwrap());
            assert_ne!(a.as_bytes(), b.as_bytes(), "{enc}");
            let (a, b) = (generate_iv(enc, &mut os), generate_iv(enc, &mut os));
            let (a, b) = (a.unwrap(), b.unwrap());
            assert_eq!(a.len(), iv_len(enc).unwrap());
            assert_ne!(a, b, "{enc}");
        }
    }

    #[test]
    fn cek_and_iv_fail_closed() {
        // An unknown `enc` draws nothing (RFC 7516 §4.1.2); a source that
        // runs short fails with RandomnessUnavailable (ADR 0005), never a
        // short or padded key or IV.
        let unknown = ContentEncAlg::from("A128CTR");
        let mut rng = counting_rng(64);
        assert_eq!(
            generate_cek(&unknown, &mut rng).map(|_| ()),
            Err(Error::UnsupportedAlgorithm)
        );
        assert_eq!(
            generate_iv(&unknown, &mut rng),
            Err(Error::UnsupportedAlgorithm)
        );
        assert_eq!(rng.remaining(), 64);
        for enc in ContentEncAlg::KNOWN {
            let mut short = counting_rng(cek_len(enc).unwrap() - 1);
            assert_eq!(
                generate_cek(enc, &mut short).map(|_| ()),
                Err(Error::RandomnessUnavailable),
                "{enc}"
            );
            let mut short = counting_rng(iv_len(enc).unwrap() - 1);
            assert_eq!(
                generate_iv(enc, &mut short),
                Err(Error::RandomnessUnavailable),
                "{enc}"
            );
        }
    }

    #[test]
    fn aad_is_the_encoded_protected_header_and_the_encoded_jwe_aad() {
        assert_eq!(aad("eyJ9", None), b"eyJ9");
        assert_eq!(aad("eyJ9", Some(b"\xff")), b"eyJ9._w");
        // No protected header (RFC 7516 §7.2.1): the '.' still separates.
        assert_eq!(aad("", Some(b"\xff")), b"._w");
        assert_eq!(aad("", None), b"");
    }
}
