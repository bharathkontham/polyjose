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

/// Draws a random CEK of [`cek_len`] bytes (RFC 7516 §5.1 step 2,
/// RFC 7518 §8.9). Filled in by T02.
///
/// # Errors
///
/// [`Error::UnsupportedAlgorithm`] for an unknown `enc`;
/// [`Error::RandomnessUnavailable`] if `rng` fails.
pub(crate) fn generate_cek(_enc: &ContentEncAlg, _rng: &mut dyn RandomSource) -> Result<Cek> {
    Err(Error::UnsupportedAlgorithm)
}

/// Draws a random content IV of [`iv_len`] bytes (RFC 7516 §5.1 step 9,
/// RFC 7518 §5.2.2.1, §5.3). Filled in by T02.
///
/// # Errors
///
/// [`Error::UnsupportedAlgorithm`] for an unknown `enc`;
/// [`Error::RandomnessUnavailable`] if `rng` fails.
pub(crate) fn generate_iv(_enc: &ContentEncAlg, _rng: &mut dyn RandomSource) -> Result<Vec<u8>> {
    Err(Error::UnsupportedAlgorithm)
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

    #[test]
    fn aad_is_the_encoded_protected_header_and_the_encoded_jwe_aad() {
        assert_eq!(aad("eyJ9", None), b"eyJ9");
        assert_eq!(aad("eyJ9", Some(b"\xff")), b"eyJ9._w");
        // No protected header (RFC 7516 §7.2.1): the '.' still separates.
        assert_eq!(aad("", Some(b"\xff")), b"._w");
        assert_eq!(aad("", None), b"");
    }
}
