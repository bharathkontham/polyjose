//! AES-GCM content encryption: A128GCM, A192GCM and A256GCM (RFC 7518
//! §5.3), with a 96-bit IV and a detached 128-bit tag.
//!
//! The primitive is RustCrypto `aes-gcm` through `aead`'s `AeadInOut`
//! (detached tag; `AeadInPlace` is deprecated in aead 0.6). `aes-gcm`
//! checks the tag in constant time **before** it decrypts, so on failure
//! the working buffer still holds ciphertext, never plaintext.
//!
//! Every length is checked before a key schedule is built or any AES block
//! is computed: the IV must be 96 bits and the tag 128 bits (RFC 7518
//! §5.3: "Use of an IV of size 96 bits is REQUIRED", "the Authentication
//! Tag MUST be 128 bits"). A shorter tag is never accepted, so a truncated
//! tag cannot be forged more cheaply.

use aes_gcm::aead::consts::{U12, U16};
use aes_gcm::aes::{Aes128, Aes192, Aes256};
use aes_gcm::{AeadCore, AeadInOut, AesGcm, KeyInit, Nonce, Tag};
use zeroize::{Zeroize, Zeroizing};

use super::content::cek_len;
use crate::jwa::ContentEncAlg;
use crate::{Error, Result};

/// The content IV length: 96 bits (RFC 7518 §5.3).
const IV_LEN: usize = 12;
/// The Authentication Tag length: 128 bits (RFC 7518 §5.3).
const TAG_LEN: usize = 16;

/// AES-GCM with a 192-bit key and a 96-bit nonce, for A192GCM
/// (RFC 7518 §5.3). `aes-gcm` names only the 128- and 256-bit types.
type Aes192Gcm = AesGcm<Aes192, U12>;
type Aes128Gcm = AesGcm<Aes128, U12>;
type Aes256Gcm = AesGcm<Aes256, U12>;

/// Encrypts `plaintext` under `cek` (16, 24 or 32 bytes for A128GCM,
/// A192GCM, A256GCM) and the 12-byte `iv`, authenticating `aad`, and
/// returns `(ciphertext, tag)` with a 16-byte tag (RFC 7518 §5.3,
/// RFC 7516 §5.1 step 15). The ciphertext has the plaintext's length.
///
/// # Errors
///
/// - [`Error::UnsupportedAlgorithm`] if `enc` is not A*GCM;
/// - [`Error::InvalidKey`] if `cek` is not the key size of `enc`
///   (RFC 7518 §5.3; reachable with a `dir` key of the wrong size);
/// - [`Error::InvalidFormat`] if `iv` is not 12 bytes, or the plaintext or
///   AAD exceed the GCM input limits (NIST SP 800-38D §5.2.1.1, cited by
///   RFC 7518 §5.3).
pub(super) fn encrypt(
    enc: &ContentEncAlg,
    cek: &[u8],
    iv: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let seal = match enc {
        ContentEncAlg::A128GCM => seal::<Aes128Gcm>,
        ContentEncAlg::A192GCM => seal::<Aes192Gcm>,
        ContentEncAlg::A256GCM => seal::<Aes256Gcm>,
        _ => return Err(Error::UnsupportedAlgorithm),
    };
    if cek.len() != cek_len(enc)? {
        return Err(Error::InvalidKey("CEK length does not match enc"));
    }
    if iv.len() != IV_LEN {
        return Err(Error::InvalidFormat("content IV length does not match enc"));
    }
    seal(cek, iv, aad, plaintext)
}

/// Checks the 16-byte `tag` over `aad` and `ciphertext` in constant time,
/// then decrypts (RFC 7518 §5.3, RFC 7516 §5.2 step 16). Plaintext is
/// returned only after the tag is verified, in a zeroizing buffer.
///
/// # Errors
///
/// [`Error::DecryptionFailed`] for every failure, with no detail
/// (RFC 7516 §11.4, §11.5): `enc` not A*GCM, an IV that is not 12 bytes,
/// a tag that is not 16 bytes, a CEK of the wrong size, or a tag mismatch
/// (any change to the CEK, IV, AAD, ciphertext or tag).
pub(super) fn decrypt(
    enc: &ContentEncAlg,
    cek: &[u8],
    iv: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let open = match enc {
        ContentEncAlg::A128GCM => open::<Aes128Gcm>,
        ContentEncAlg::A192GCM => open::<Aes192Gcm>,
        ContentEncAlg::A256GCM => open::<Aes256Gcm>,
        _ => return Err(Error::DecryptionFailed),
    };
    // All three lengths are public and checked before any AES work.
    if iv.len() != IV_LEN || tag.len() != TAG_LEN || Ok(cek.len()) != cek_len(enc) {
        return Err(Error::DecryptionFailed);
    }
    open(cek, iv, aad, ciphertext, tag)
}

/// AES-GCM encryption with `C`; the caller has checked every length.
fn seal<C>(cek: &[u8], iv: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)>
where
    C: KeyInit + AeadInOut + AeadCore<NonceSize = U12, TagSize = U16>,
{
    let cipher =
        C::new_from_slice(cek).map_err(|_| Error::InvalidKey("CEK length does not match enc"))?;
    let nonce = Nonce::<U12>::try_from(iv)
        .map_err(|_| Error::InvalidFormat("content IV length does not match enc"))?;
    let mut buffer = plaintext.to_vec();
    match cipher.encrypt_inout_detached(&nonce, aad, buffer.as_mut_slice().into()) {
        Ok(tag) => Ok((buffer, tag.to_vec())),
        Err(_) => {
            // Only the input-length limit fails, before any keystream is
            // applied: the buffer is a plaintext copy, so wipe it.
            buffer.zeroize();
            Err(Error::InvalidFormat(
                "plaintext or AAD too long for AES-GCM",
            ))
        }
    }
}

/// AES-GCM decryption with `C`; the caller has checked every length.
fn open<C>(
    cek: &[u8],
    iv: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>>
where
    C: KeyInit + AeadInOut + AeadCore<NonceSize = U12, TagSize = U16>,
{
    let cipher = C::new_from_slice(cek).map_err(|_| Error::DecryptionFailed)?;
    let nonce = Nonce::<U12>::try_from(iv).map_err(|_| Error::DecryptionFailed)?;
    let tag = Tag::<U16>::try_from(tag).map_err(|_| Error::DecryptionFailed)?;
    let mut buffer = Zeroizing::new(ciphertext.to_vec());
    // On a tag mismatch `aes-gcm` leaves the buffer as ciphertext; it is
    // dropped (and wiped) here, and only the unit error escapes.
    cipher
        .decrypt_inout_detached(&nonce, aad, buffer.as_mut_slice().into(), &tag)
        .map_err(|_| Error::DecryptionFailed)?;
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GCM: [ContentEncAlg; 3] = [
        ContentEncAlg::A128GCM,
        ContentEncAlg::A192GCM,
        ContentEncAlg::A256GCM,
    ];
    const NOT_GCM: [ContentEncAlg; 3] = [
        ContentEncAlg::A128CbcHs256,
        ContentEncAlg::A192CbcHs384,
        ContentEncAlg::A256CbcHs512,
    ];

    fn key(enc: &ContentEncAlg) -> Vec<u8> {
        (0..cek_len(enc).unwrap()).map(|i| i as u8 ^ 0x5A).collect()
    }

    const IV: [u8; 12] = [7; 12];
    const AAD: &[u8] = b"eyJlbmMiOiJBMTI4R0NNIn0";
    const MSG: &[u8] = b"Live long and prosper.";

    #[test]
    fn round_trips_with_a_detached_16_byte_tag() {
        // RFC 7518 §5.3: the ciphertext has the plaintext's length and the
        // tag is 128 bits, returned separately.
        for enc in &GCM {
            let (ct, tag) = encrypt(enc, &key(enc), &IV, AAD, MSG).unwrap();
            assert_eq!((ct.len(), tag.len()), (MSG.len(), TAG_LEN), "{enc}");
            assert_ne!(ct, MSG);
            let pt = decrypt(enc, &key(enc), &IV, AAD, &ct, &tag).unwrap();
            assert_eq!(pt.as_slice(), MSG, "{enc}");
        }
        // The empty plaintext still gets a full tag (RFC 7518 §5.3).
        let (ct, tag) = encrypt(&GCM[0], &key(&GCM[0]), &IV, b"", b"").unwrap();
        assert_eq!((ct.len(), tag.len()), (0, TAG_LEN));
        let pt = decrypt(&GCM[0], &key(&GCM[0]), &IV, b"", &ct, &tag).unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn the_three_key_sizes_are_three_different_ciphers() {
        // A192GCM is AES-192 (RFC 7518 §5.3), not AES-128 or AES-256 on a
        // prefix or extension of the key: the same leading key bytes give
        // three unrelated outputs.
        let long = key(&ContentEncAlg::A256GCM);
        let outs: Vec<_> = GCM
            .iter()
            .map(|enc| {
                let k = &long[..cek_len(enc).unwrap()];
                encrypt(enc, k, &IV, AAD, MSG).unwrap()
            })
            .collect();
        assert_ne!(outs[0], outs[1]);
        assert_ne!(outs[1], outs[2]);
        assert_ne!(outs[0], outs[2]);
    }

    #[test]
    fn decrypt_rejects_every_wrong_iv_or_tag_length() {
        // RFC 7518 §5.3: a 96-bit IV and a 128-bit tag are required. A
        // truncated tag, even a correct prefix, is a cheaper forgery and
        // must fail like any other mismatch.
        for enc in &GCM {
            let k = key(enc);
            let (ct, tag) = encrypt(enc, &k, &IV, AAD, MSG).unwrap();
            for n in [0, 1, 8, 11, 13, 16, 32] {
                let iv = vec![7u8; n];
                assert_eq!(
                    decrypt(enc, &k, &iv, AAD, &ct, &tag),
                    Err(Error::DecryptionFailed),
                    "{enc}: IV of {n} bytes"
                );
            }
            for n in [0, 1, 4, 8, 12, 15] {
                assert_eq!(
                    decrypt(enc, &k, &IV, AAD, &ct, &tag[..n]),
                    Err(Error::DecryptionFailed),
                    "{enc}: tag prefix of {n} bytes"
                );
            }
            let mut long_tag = tag.clone();
            long_tag.push(0);
            assert_eq!(
                decrypt(enc, &k, &IV, AAD, &ct, &long_tag),
                Err(Error::DecryptionFailed),
                "{enc}: 17-byte tag"
            );
        }
    }

    #[test]
    fn decrypt_rejects_a_cek_of_another_size() {
        // RFC 7518 §5.3: the key size is fixed by `enc`; a CEK unwrapped
        // for another `enc` fails with the same detail-free error.
        for enc in &GCM {
            let (ct, tag) = encrypt(enc, &key(enc), &IV, AAD, MSG).unwrap();
            for n in [0, 15, 16, 17, 24, 31, 32, 33, 64] {
                if n == cek_len(enc).unwrap() {
                    continue;
                }
                assert_eq!(
                    decrypt(enc, &vec![0x5A; n], &IV, AAD, &ct, &tag),
                    Err(Error::DecryptionFailed),
                    "{enc}: CEK of {n} bytes"
                );
            }
        }
    }

    #[test]
    fn decrypt_rejects_a_tag_mismatch_without_plaintext() {
        // RFC 7516 §5.2 step 16: "If the JWE Authentication Tag is
        // incorrect, reject the input without emitting any decrypted
        // output." The error is the unit variant, so no buffer comes back.
        for enc in &GCM {
            let k = key(enc);
            let (ct, tag) = encrypt(enc, &k, &IV, AAD, MSG).unwrap();
            let mut bad_tag = tag.clone();
            bad_tag[15] ^= 1;
            let mut bad_ct = ct.clone();
            bad_ct[0] ^= 0x80;
            let mut bad_key = k.clone();
            bad_key[0] ^= 1;
            // (key, iv, aad, ciphertext, tag), one input changed in each.
            let cases: [[&[u8]; 5]; 5] = [
                [&k, &IV, AAD, &ct, &bad_tag],
                [&k, &IV, AAD, &bad_ct, &tag],
                [&k, &[8; 12], AAD, &ct, &tag],
                [&k, &IV, b"eyJlbmMiOiJBMTI4R0NNIn1", &ct, &tag],
                [&bad_key, &IV, AAD, &ct, &tag],
            ];
            for [key, iv, aad, ct, tag] in cases {
                assert_eq!(
                    decrypt(enc, key, iv, aad, ct, tag),
                    Err(Error::DecryptionFailed),
                    "{enc}"
                );
            }
        }
    }

    #[test]
    fn non_gcm_enc_is_refused_before_any_work() {
        // The dispatcher in `content` sends only A*GCM here; anything else
        // is a bug and fails closed.
        for enc in NOT_GCM.iter().chain([&ContentEncAlg::from("A128CTR")]) {
            assert_eq!(
                encrypt(enc, &[0; 32], &[0; 16], b"", MSG),
                Err(Error::UnsupportedAlgorithm),
                "{enc}"
            );
            assert_eq!(
                decrypt(enc, &[0; 32], &IV, b"", MSG, &[0; 16]),
                Err(Error::DecryptionFailed),
                "{enc}"
            );
        }
    }

    #[test]
    fn encrypt_rejects_a_wrong_cek_or_iv_length() {
        // The CEK size is fixed by `enc` (RFC 7518 §5.3); a `dir` key of
        // the wrong size is the caller's key error. A non-96-bit IV is
        // refused (RFC 7518 §5.3: a 96-bit IV is REQUIRED).
        for enc in &GCM {
            let n = cek_len(enc).unwrap();
            for bad in [n - 1, n + 1, n + 8] {
                assert_eq!(
                    encrypt(enc, &vec![0; bad], &IV, AAD, MSG),
                    Err(Error::InvalidKey("CEK length does not match enc")),
                    "{enc}: CEK of {bad} bytes"
                );
            }
            for bad in [0, 11, 13, 16] {
                assert_eq!(
                    encrypt(enc, &key(enc), &vec![0; bad], AAD, MSG),
                    Err(Error::InvalidFormat("content IV length does not match enc")),
                    "{enc}: IV of {bad} bytes"
                );
            }
        }
    }
}
