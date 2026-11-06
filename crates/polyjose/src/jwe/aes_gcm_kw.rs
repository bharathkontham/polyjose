//! A128GCMKW, A192GCMKW and A256GCMKW: key wrapping with AES-GCM
//! (RFC 7518 §4.7), on T02's `enc_gcm` wrapper.
//!
//! RFC 7518 §4.7 fixes every choice: the CEK is encrypted with AES-GCM
//! under the shared symmetric key (128, 192 or 256 bits, by `alg`), with
//! "an Initialization Vector (IV) of size 96 bits", "the empty octet
//! string" as the Additional Authenticated Data, and a tag that "MUST be
//! 128 bits, regardless of the key size". "The JWE Encrypted Key value is
//! the ciphertext output", and the IV and tag travel base64url-encoded as
//! the `iv` and `tag` header parameters (§4.7.1.1, §4.7.1.2), which "MUST
//! be present" when these algorithms are used.
//!
//! The AES-GCM in this file is the content-encryption AES-GCM of RFC 7518
//! §5.3 with the same key size, IV size and tag size, so `enc_gcm` is
//! reused through the A*GCM `enc` whose key size matches the `alg`
//! ([`gcm_for`]). Its tag check is constant time and comes before any
//! decryption, so a failed unwrap never yields CEK bytes.
//!
//! The IV is drawn fresh for every wrap from the caller's [`RandomSource`]
//! (the documented draw order: after the CEK, in recipient order, before
//! the content IV). A GCM IV must never repeat under one key
//! (RFC 7518 §8.4; NIST SP 800-38D §8): with random 96-bit IVs that holds,
//! with the usual bound, for up to 2^32 wraps under one KEK, which is
//! documented and not enforced.

use super::api::DecryptPolicy;
use super::content::{Cek, cek_len};
use super::enc_gcm;
use super::key::RecipientKey;
use super::keymgmt::{KeyOutput, RecipientOptions};
use super::random::RandomSource;
use crate::header::Header;
use crate::json::Object;
use crate::jwa::{ContentEncAlg, KeyMgmtAlg};
use crate::util::b64url_encode;
use crate::{Error, Result};

/// The key-wrapping IV length: 96 bits (RFC 7518 §4.7: "Use of an
/// Initialization Vector (IV) of size 96 bits is REQUIRED").
const IV_LEN: usize = 12;
/// The Additional Authenticated Data of the key wrap: "the empty octet
/// string" (RFC 7518 §4.7).
const NO_AAD: &[u8] = b"";

/// The [`Error::InvalidKey`] detail for a KEK whose size does not match
/// `alg`.
const KEK_SIZE: &str = "AES-GCM key wrap key length does not match alg";
/// The [`Error::InvalidKey`] detail for a missing CEK or one of the wrong
/// length for `enc`.
const CEK_SIZE: &str = "AES-GCM key wrap needs the CEK length of enc";

/// Key management on encrypt (RFC 7516 §5.1 steps 3–7) for A128GCMKW,
/// A192GCMKW and A256GCMKW: the random CEK encrypted with AES-GCM under
/// the shared symmetric key is the JWE Encrypted Key (RFC 7518 §4.7,
/// RFC 7516 §5.1 step 4), and the fresh 96-bit IV and the 128-bit tag are
/// returned as the `iv` and `tag` header parameters, base64url-encoded
/// (RFC 7518 §4.7.1.1, §4.7.1.2). The AAD is empty (§4.7).
///
/// Every check runs before the IV is drawn, so a refused key consumes no
/// randomness. The IV is the only value drawn: 12 bytes from `rng`.
///
/// # Errors
///
/// - [`Error::UnsupportedAlgorithm`] for an `alg` outside the family or an
///   unknown `enc`;
/// - [`Error::KeyAlgorithmMismatch`] for a key that is not a symmetric key
///   (RFC 7518 §6.4, RFC 8725 §3.1);
/// - [`Error::InvalidKey`] if the KEK is not 16, 24 or 32 bytes as `alg`
///   requires (RFC 7518 §4.7), or the CEK is missing or not the length
///   `enc` requires (RFC 7516 §5.1 step 2);
/// - [`Error::RandomnessUnavailable`] if `rng` cannot supply the IV
///   (ADR 0005: fail closed).
pub(super) fn encrypt_key(
    alg: &KeyMgmtAlg,
    key: &RecipientKey,
    enc: &ContentEncAlg,
    cek: Option<&Cek>,
    _options: &RecipientOptions,
    rng: &mut dyn RandomSource,
) -> Result<KeyOutput> {
    let gcm = gcm_for(alg).ok_or(Error::UnsupportedAlgorithm)?;
    let RecipientKey::Symmetric(kek) = key else {
        return Err(Error::KeyAlgorithmMismatch);
    };
    if kek.len() != cek_len(&gcm)? {
        return Err(Error::InvalidKey(KEK_SIZE));
    }
    let cek_len = cek_len(enc)?;
    let cek = cek
        .filter(|cek| cek.len() == cek_len)
        .ok_or(Error::InvalidKey(CEK_SIZE))?;
    // RFC 7518 §4.7.1.1: a fresh random 96-bit IV for every wrap.
    let mut iv = [0u8; IV_LEN];
    rng.fill(&mut iv)?;
    let (encrypted_key, tag) = enc_gcm::encrypt(&gcm, kek, &iv, NO_AAD, cek.as_bytes())?;
    let mut header_params = Object::new();
    header_params.insert("iv", b64url_encode(&iv));
    header_params.insert("tag", b64url_encode(&tag));
    Ok(KeyOutput {
        encrypted_key,
        header_params,
        cek: None,
    })
}

/// Key management on decrypt (RFC 7516 §5.2 steps 6–12) for A128GCMKW,
/// A192GCMKW and A256GCMKW. Not yet implemented.
///
/// # Errors
///
/// [`Error::UnsupportedAlgorithm`] for now.
pub(super) fn decrypt_key(
    _alg: &KeyMgmtAlg,
    _key: &RecipientKey,
    _enc: &ContentEncAlg,
    _header: &Header,
    _encrypted_key: &[u8],
    _policy: &DecryptPolicy,
) -> Result<Cek> {
    Err(Error::UnsupportedAlgorithm)
}

/// The A*GCM content encryption algorithm whose AES-GCM is the key wrap of
/// `alg`: the same key size, a 96-bit IV and a 128-bit tag (RFC 7518 §4.7,
/// §5.3), or `None` for an `alg` outside the A*GCMKW family.
fn gcm_for(alg: &KeyMgmtAlg) -> Option<ContentEncAlg> {
    match alg {
        KeyMgmtAlg::A128GCMKW => Some(ContentEncAlg::A128GCM),
        KeyMgmtAlg::A192GCMKW => Some(ContentEncAlg::A192GCM),
        KeyMgmtAlg::A256GCMKW => Some(ContentEncAlg::A256GCM),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use zeroize::Zeroizing;

    use super::*;
    use crate::json::Value;
    use crate::jwe::random::OsRandom;
    use crate::rng::insecure_test_vectors::FixedRng;
    use crate::util::{b64url_decode, b64url_encode};

    use KeyMgmtAlg as A;

    const FAMILY: [(KeyMgmtAlg, usize); 3] =
        [(A::A128GCMKW, 16), (A::A192GCMKW, 24), (A::A256GCMKW, 32)];

    fn sym(len: usize) -> RecipientKey {
        RecipientKey::Symmetric(Zeroizing::new((0..len).map(|i| i as u8 ^ 0xA5).collect()))
    }

    fn cek(enc: &ContentEncAlg) -> Cek {
        let len = cek_len(enc).unwrap_or_else(|e| panic!("{e}"));
        Cek::from_slice(&(0..len).map(|i| i as u8).collect::<Vec<_>>())
    }

    fn param<'a>(out: &'a KeyOutput, name: &str) -> &'a str {
        out.header_params
            .get(name)
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("no {name}"))
    }

    fn wrap(
        alg: &KeyMgmtAlg,
        kek: &RecipientKey,
        enc: &ContentEncAlg,
        rng: &mut dyn RandomSource,
    ) -> KeyOutput {
        let options = RecipientOptions::default();
        encrypt_key(alg, kek, enc, Some(&cek(enc)), &options, rng)
            .unwrap_or_else(|e| panic!("{alg}: {e}"))
    }

    // -------------------------------------------------------------------
    // Encrypt
    // -------------------------------------------------------------------

    #[test]
    fn encrypt_emits_the_encrypted_key_and_only_iv_and_tag() {
        // RFC 7518 §4.7: the JWE Encrypted Key is the GCM ciphertext (the
        // CEK's length), and the 96-bit IV and 128-bit tag are the `iv`
        // and `tag` header parameters, base64url-encoded (§4.7.1.1,
        // §4.7.1.2). No CEK is returned: the random one is used.
        for (alg, kek_len) in &FAMILY {
            for enc in ContentEncAlg::KNOWN {
                let out = wrap(alg, &sym(*kek_len), enc, &mut OsRandom);
                assert_eq!(out.encrypted_key.len(), cek(enc).len(), "{alg} {enc}");
                assert_ne!(out.encrypted_key, cek(enc).as_bytes(), "{alg} {enc}");
                assert!(out.cek.is_none(), "{alg} {enc}");
                let names: Vec<&str> = out.header_params.iter().map(|(n, _)| n).collect();
                assert_eq!(names, ["iv", "tag"], "{alg} {enc}");
                let iv = b64url_decode(param(&out, "iv")).unwrap_or_else(|e| panic!("{e}"));
                let tag = b64url_decode(param(&out, "tag")).unwrap_or_else(|e| panic!("{e}"));
                assert_eq!((iv.len(), tag.len()), (12, 16), "{alg} {enc}");
            }
        }
    }

    #[test]
    fn encrypt_draws_exactly_the_12_byte_iv() {
        // The documented draw order (`random` module, RFC 7518 §4.7.1.1):
        // A*GCMKW draws its 96-bit IV and nothing else; the bytes drawn
        // are the `iv` emitted.
        let iv: Vec<u8> = (1..=12).collect();
        for (alg, kek_len) in &FAMILY {
            let mut rng = FixedRng::new(iv.clone());
            let out = wrap(alg, &sym(*kek_len), &ContentEncAlg::A128GCM, &mut rng);
            assert_eq!(rng.remaining(), 0, "{alg}");
            assert_eq!(param(&out, "iv"), b64url_encode(&iv), "{alg}");
        }
    }

    #[test]
    fn encrypt_matches_an_independent_aes_gcm_with_empty_aad() {
        // RFC 7518 §4.7: AES-GCM of the CEK under the KEK with the `iv`
        // and an empty AAD, checked against `aes-gcm` called directly.
        use aes_gcm::aead::consts::U12;
        use aes_gcm::aes::{Aes128, Aes192, Aes256};
        use aes_gcm::{AeadCore, AeadInOut, AesGcm, KeyInit, Nonce};
        fn reference<C: KeyInit + AeadInOut + AeadCore<NonceSize = U12>>(
            kek: &[u8],
            iv: &[u8],
            cek: &[u8],
        ) -> (Vec<u8>, Vec<u8>) {
            let cipher = C::new_from_slice(kek).unwrap_or_else(|e| panic!("{e}"));
            let nonce = Nonce::<U12>::try_from(iv).unwrap_or_else(|e| panic!("{e}"));
            let mut buf = cek.to_vec();
            let tag = cipher
                .encrypt_inout_detached(&nonce, b"", buf.as_mut_slice().into())
                .unwrap_or_else(|e| panic!("{e}"));
            (buf, tag.to_vec())
        }
        let iv = [0x42u8; 12];
        let enc = ContentEncAlg::A256CbcHs512;
        for (alg, kek_len) in &FAMILY {
            let RecipientKey::Symmetric(kek) = sym(*kek_len) else {
                unreachable!()
            };
            let expected = match kek_len {
                16 => reference::<AesGcm<Aes128, U12>>(&kek, &iv, cek(&enc).as_bytes()),
                24 => reference::<AesGcm<Aes192, U12>>(&kek, &iv, cek(&enc).as_bytes()),
                _ => reference::<AesGcm<Aes256, U12>>(&kek, &iv, cek(&enc).as_bytes()),
            };
            let out = wrap(alg, &sym(*kek_len), &enc, &mut FixedRng::new(iv));
            let tag = b64url_decode(param(&out, "tag")).unwrap_or_else(|e| panic!("{e}"));
            assert_eq!((out.encrypted_key, tag), expected, "{alg}");
        }
    }

    #[test]
    fn os_ivs_never_repeat_over_1000_wraps() {
        // RFC 7518 §8.4: a GCM IV must never repeat under one key. 1,000
        // OS draws of 96 bits collide with probability below 2^-76.
        let kek = sym(32);
        let enc = ContentEncAlg::A128GCM;
        let mut ivs = HashSet::new();
        let mut wrapped = HashSet::new();
        for _ in 0..1000 {
            let out = wrap(&A::A256GCMKW, &kek, &enc, &mut OsRandom);
            assert!(ivs.insert(param(&out, "iv").to_owned()));
            assert!(wrapped.insert(out.encrypted_key.clone()));
        }
        assert_eq!(ivs.len(), 1000);
    }

    #[test]
    fn encrypt_rejects_a_kek_of_the_wrong_size_or_kind() {
        // RFC 7518 §4.7: A128GCMKW, A192GCMKW and A256GCMKW use a 128-,
        // 192- and 256-bit key. Nothing is drawn before the refusal.
        let enc = ContentEncAlg::A128GCM;
        let options = RecipientOptions::default();
        for (alg, kek_len) in &FAMILY {
            for len in [0, 15, 16, 17, 24, 31, 32, 33, 64] {
                if len == *kek_len {
                    continue;
                }
                let mut rng = FixedRng::new([0u8; 12]);
                let result =
                    encrypt_key(alg, &sym(len), &enc, Some(&cek(&enc)), &options, &mut rng);
                assert!(
                    matches!(result, Err(Error::InvalidKey(_))),
                    "{alg}: {len}-byte KEK"
                );
                assert_eq!(rng.remaining(), 12, "{alg}: drew before refusing");
            }
            let password = RecipientKey::Password(Zeroizing::new(vec![0; *kek_len]));
            let result = encrypt_key(
                alg,
                &password,
                &enc,
                Some(&cek(&enc)),
                &options,
                &mut OsRandom,
            );
            assert_eq!(
                result.map(|_| ()),
                Err(Error::KeyAlgorithmMismatch),
                "{alg}"
            );
        }
    }

    #[test]
    fn encrypt_rejects_a_missing_or_wrong_size_cek() {
        // RFC 7516 §5.1 step 2: key wrapping wraps the random CEK of the
        // length `enc` requires; `core` always passes one.
        let options = RecipientOptions::default();
        let enc = ContentEncAlg::A128CbcHs256;
        let result = encrypt_key(&A::A128GCMKW, &sym(16), &enc, None, &options, &mut OsRandom);
        assert!(matches!(result, Err(Error::InvalidKey(_))));
        let short = Cek::from_slice(&[0; 16]);
        let result = encrypt_key(
            &A::A128GCMKW,
            &sym(16),
            &enc,
            Some(&short),
            &options,
            &mut OsRandom,
        );
        assert!(matches!(result, Err(Error::InvalidKey(_))));
    }

    #[test]
    fn encrypt_outside_the_family_or_with_an_unknown_enc_is_unsupported() {
        let options = RecipientOptions::default();
        let enc = ContentEncAlg::A128GCM;
        for alg in [A::A128KW, A::Dir, A::from("A512GCMKW")] {
            let result = encrypt_key(
                &alg,
                &sym(16),
                &enc,
                Some(&cek(&enc)),
                &options,
                &mut OsRandom,
            );
            assert_eq!(
                result.map(|_| ()),
                Err(Error::UnsupportedAlgorithm),
                "{alg}"
            );
        }
        let unknown = ContentEncAlg::from("A128CTR");
        let some = Cek::from_slice(&[0; 16]);
        let result = encrypt_key(
            &A::A128GCMKW,
            &sym(16),
            &unknown,
            Some(&some),
            &options,
            &mut OsRandom,
        );
        assert_eq!(result.map(|_| ()), Err(Error::UnsupportedAlgorithm));
    }

    #[test]
    fn encrypt_fails_closed_when_randomness_runs_out() {
        // ADR 0005: no IV, no wrap.
        let enc = ContentEncAlg::A128GCM;
        let options = RecipientOptions::default();
        let mut rng = FixedRng::new([0u8; 11]);
        let result = encrypt_key(
            &A::A128GCMKW,
            &sym(16),
            &enc,
            Some(&cek(&enc)),
            &options,
            &mut rng,
        );
        assert_eq!(result.map(|_| ()), Err(Error::RandomnessUnavailable));
    }
}
