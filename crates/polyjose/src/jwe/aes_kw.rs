//! A128KW, A192KW and A256KW: AES Key Wrap (RFC 3394) of a random CEK
//! (RFC 7518 §4.4), on `aes-kw`. Also the [`wrap`]/[`unwrap`] helper that
//! PBES2 (RFC 7518 §4.8) and ECDH-ES+A*KW (RFC 7518 §4.6) call.
//!
//! `aes-kw` wraps and unwraps any multiple of 8 bytes, 0 included
//! (research.md §3), so the RFC 3394 §2 sizes are enforced here: key data
//! of at least two 64-bit blocks, a KEK of an AES key size.

use super::api::DecryptPolicy;
use super::content::{Cek, cek_len};
use super::key::RecipientKey;
use super::keymgmt::{KeyOutput, RecipientOptions};
use super::random::RandomSource;
use crate::header::Header;
use crate::json::Object;
use crate::jwa::{ContentEncAlg, KeyMgmtAlg};
use crate::{Error, Result};
use aes_kw::{KeyInit, KwAes128, KwAes192, KwAes256};
use zeroize::Zeroizing;

/// Key management on encrypt (RFC 7516 §5.1 steps 3–7) for A128KW, A192KW
/// and A256KW: the random CEK wrapped under the shared symmetric key with
/// RFC 3394 is the JWE Encrypted Key (RFC 7518 §4.4, RFC 7516 §5.1 step 4).
/// The algorithm defines no header parameters, and draws no randomness:
/// RFC 3394 wrapping is deterministic (§2.2.1).
///
/// # Errors
///
/// - [`Error::UnsupportedAlgorithm`] for an `alg` outside the family or an
///   unknown `enc`;
/// - [`Error::KeyAlgorithmMismatch`] for a key that is not a symmetric key
///   (RFC 7518 §6.4, RFC 8725 §3.1);
/// - [`Error::InvalidKey`] if the KEK length does not match `alg` (16, 24
///   or 32 bytes, RFC 7518 §4.4), or the CEK is missing or not the length
///   `enc` requires (RFC 7516 §5.1 step 2).
pub(super) fn encrypt_key(
    alg: &KeyMgmtAlg,
    key: &RecipientKey,
    enc: &ContentEncAlg,
    cek: Option<&Cek>,
    _options: &RecipientOptions,
    _rng: &mut dyn RandomSource,
) -> Result<KeyOutput> {
    let kek_len = kek_len(alg).ok_or(Error::UnsupportedAlgorithm)?;
    let RecipientKey::Symmetric(kek) = key else {
        return Err(Error::KeyAlgorithmMismatch);
    };
    if kek.len() != kek_len {
        return Err(Error::InvalidKey(KEK_SIZE));
    }
    let cek_len = cek_len(enc)?;
    let cek = cek
        .filter(|cek| cek.len() == cek_len)
        .ok_or(Error::InvalidKey(CEK_SIZE))?;
    Ok(KeyOutput {
        encrypted_key: wrap(kek, cek.as_bytes())?,
        header_params: Object::new(),
        cek: None,
    })
}

/// Key management on decrypt (RFC 7516 §5.2 steps 6–12) for A128KW, A192KW
/// and A256KW: the JWE Encrypted Key unwrapped under the shared symmetric
/// key with RFC 3394 (RFC 7518 §4.4, RFC 7516 §5.2 step 10). The CEK must
/// have the length `enc` requires (§5.2 step 9).
///
/// # Errors
///
/// [`Error::DecryptionFailed`], whatever the cause, so no cause can be told
/// from another (RFC 7516 §11.4–§11.5, the plan.md error contract): an
/// `alg` outside the family, a key that is not symmetric or whose length
/// does not match `alg`, an unknown `enc`, a wrapped key of the wrong size,
/// an integrity failure (RFC 3394 §2.2.3) or an unwrapped CEK of the wrong
/// length. No CEK, partial or whole, is returned with an error, and every
/// unwrapped byte is wiped before returning.
pub(super) fn decrypt_key(
    alg: &KeyMgmtAlg,
    key: &RecipientKey,
    enc: &ContentEncAlg,
    _header: &Header,
    encrypted_key: &[u8],
    _policy: &DecryptPolicy,
) -> Result<Cek> {
    let kek = match (kek_len(alg), key) {
        (Some(len), RecipientKey::Symmetric(kek)) if kek.len() == len => kek,
        _ => return Err(Error::DecryptionFailed),
    };
    let cek_len = cek_len(enc).map_err(|_| Error::DecryptionFailed)?;
    let cek = unwrap(kek, encrypted_key)?;
    if cek.len() != cek_len {
        // `cek` is `Zeroizing`: dropping it here wipes the unwrapped bytes.
        return Err(Error::DecryptionFailed);
    }
    Ok(Cek::new(cek))
}

/// The KEK length of `alg` in bytes (RFC 7518 §4.4), or `None` for an `alg`
/// outside the A*KW family.
fn kek_len(alg: &KeyMgmtAlg) -> Option<usize> {
    match alg {
        KeyMgmtAlg::A128KW => Some(16),
        KeyMgmtAlg::A192KW => Some(24),
        KeyMgmtAlg::A256KW => Some(32),
        _ => None,
    }
}

/// Wraps `cek` under `kek` (RFC 3394 §2.2.1). The KEK is 16, 24 or 32
/// bytes; the CEK at least 16 bytes, a multiple of 8.
///
/// # Errors
///
/// An error for a KEK or CEK of a size outside those.
pub(super) fn wrap(kek: &[u8], cek: &[u8]) -> Result<Vec<u8>> {
    let kw = Kw::new(kek).ok_or(Error::InvalidKey(KEK_SIZE))?;
    if !is_key_data_len(cek.len()) {
        return Err(Error::InvalidKey(CEK_SIZE));
    }
    let mut out = vec![0; cek.len() + SEMIBLOCK];
    kw.wrap(cek, &mut out)
        .map_err(|_| Error::InvalidKey(CEK_SIZE))?;
    Ok(out)
}

/// Unwraps `wrapped` under `kek` and checks its integrity (RFC 3394
/// §2.2.2–§2.2.3). The wrapped input is at least 24 bytes, a multiple of 8.
///
/// # Errors
///
/// [`Error::DecryptionFailed`] for a size outside those or an integrity
/// failure; no partial key is returned (RFC 3394 §2.2.3: "the unwrap must
/// return an error and not return any key data").
pub(super) fn unwrap(kek: &[u8], wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let kw = Kw::new(kek).ok_or(Error::DecryptionFailed)?;
    let len = wrapped
        .len()
        .checked_sub(SEMIBLOCK)
        .filter(|&len| is_key_data_len(len))
        .ok_or(Error::DecryptionFailed)?;
    let mut out = Zeroizing::new(vec![0; len]);
    // On an integrity failure aes-kw zeroes `out` before returning, and
    // `Zeroizing` wipes it again on drop.
    kw.unwrap(wrapped, &mut out)
        .map_err(|_| Error::DecryptionFailed)?;
    Ok(out)
}

/// The 64-bit semiblock of RFC 3394 §2: the unit of key data and the
/// length of the integrity check register `A`.
const SEMIBLOCK: usize = 8;

/// Whether `len` bytes is key data RFC 3394 can wrap: n 64-bit blocks with
/// n >= 2 (RFC 3394 §2, §2.2.1). aes-kw also accepts n = 0 and n = 1
/// (research.md §3), so the bound is enforced here, before it runs.
fn is_key_data_len(len: usize) -> bool {
    len >= 2 * SEMIBLOCK && len.is_multiple_of(SEMIBLOCK)
}

/// The [`Error::InvalidKey`] detail for a KEK of the wrong size.
const KEK_SIZE: &str = "AES Key Wrap needs a 16, 24 or 32 byte key";

/// The [`Error::InvalidKey`] detail for key data of the wrong size.
const CEK_SIZE: &str = "AES Key Wrap wraps 16 or more bytes, a multiple of 8";

/// AES Key Wrap (RFC 3394 §2.2) under a KEK of one of the three AES key
/// sizes (FIPS 197, RFC 7518 §4.4). Each variant wipes its key schedule on
/// drop (the `zeroize` feature of `aes` and `aes-kw`). No `Debug`: it holds
/// the KEK schedule.
enum Kw {
    A128(KwAes128),
    A192(KwAes192),
    A256(KwAes256),
}

impl Kw {
    /// The wrapper for `kek`, or `None` unless it is 16, 24 or 32 bytes.
    fn new(kek: &[u8]) -> Option<Kw> {
        match kek.len() {
            16 => KwAes128::new_from_slice(kek).ok().map(Kw::A128),
            24 => KwAes192::new_from_slice(kek).ok().map(Kw::A192),
            32 => KwAes256::new_from_slice(kek).ok().map(Kw::A256),
            _ => None,
        }
    }

    /// RFC 3394 §2.2.1 into `out`, which is `data.len() + 8` bytes.
    fn wrap(&self, data: &[u8], out: &mut [u8]) -> core::result::Result<(), aes_kw::Error> {
        match self {
            Kw::A128(kw) => kw.wrap_key(data, out),
            Kw::A192(kw) => kw.wrap_key(data, out),
            Kw::A256(kw) => kw.wrap_key(data, out),
        }
        .map(|_| ())
    }

    /// RFC 3394 §2.2.2 with the §2.2.3.1 check into `out`, which is
    /// `wrapped.len() - 8` bytes.
    fn unwrap(&self, wrapped: &[u8], out: &mut [u8]) -> core::result::Result<(), aes_kw::Error> {
        match self {
            Kw::A128(kw) => kw.unwrap_key(wrapped, out),
            Kw::A192(kw) => kw.unwrap_key(wrapped, out),
            Kw::A256(kw) => kw.unwrap_key(wrapped, out),
        }
        .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::wycheproof::{self, Deviation, Expected, Outcome};

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or_else(|e| panic!("{e}")))
            .collect()
    }

    const KEK_128: &str = "000102030405060708090A0B0C0D0E0F";
    const KEK_192: &str = "000102030405060708090A0B0C0D0E0F1011121314151617";
    const KEK_256: &str = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
    const DATA_128: &str = "00112233445566778899AABBCCDDEEFF";
    const DATA_192: &str = "00112233445566778899AABBCCDDEEFF0001020304050607";
    const DATA_256: &str = "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F";

    /// RFC 3394 §4.1–§4.6: `(section, KEK, key data, ciphertext)`.
    const RFC_3394: &[(&str, &str, &str, &str)] = &[
        (
            "4.1",
            KEK_128,
            DATA_128,
            "1FA68B0A8112B447 AEF34BD8FB5A7B82 9D3E862371D2CFE5",
        ),
        (
            "4.2",
            KEK_192,
            DATA_128,
            "96778B25AE6CA435 F92B5B97C050AED2 468AB8A17AD84E5D",
        ),
        (
            "4.3",
            KEK_256,
            DATA_128,
            "64E8C3F9CE0F5BA2 63E9777905818A2A 93C8191E7D6E8AE7",
        ),
        (
            "4.4",
            KEK_192,
            DATA_192,
            "031D33264E15D332 68F24EC260743EDC E1C6C7DDEE725A93 6BA814915C6762D2",
        ),
        (
            "4.5",
            KEK_256,
            DATA_192,
            "A8F9BC1612C68B3F F6E6F4FBE30E71E4 769C8B80A32CB895 8CD5D17D6B254DA1",
        ),
        (
            "4.6",
            KEK_256,
            DATA_256,
            "28C9F404C4B810F4 CBCCB35CFB87F826 3F5786E2D80ED326 \
             CBC7F0E71A99F43B FB988B9B7A02DD21",
        ),
    ];

    #[test]
    fn rfc_3394_section_4_vectors_wrap_exactly() {
        for (section, kek, data, ct) in RFC_3394 {
            let wrapped = wrap(&hex(kek), &hex(data)).unwrap_or_else(|e| panic!("§{section}: {e}"));
            assert_eq!(wrapped, hex(ct), "RFC 3394 §{section}");
        }
    }

    #[test]
    fn rfc_3394_section_4_vectors_unwrap_exactly() {
        for (section, kek, data, ct) in RFC_3394 {
            let unwrapped =
                unwrap(&hex(kek), &hex(ct)).unwrap_or_else(|e| panic!("§{section}: {e}"));
            assert_eq!(*unwrapped, hex(data), "RFC 3394 §{section}");
        }
    }

    #[test]
    fn a_modified_wrapped_key_fails_the_integrity_check() {
        // RFC 3394 §2.2.3: any A[0] other than the default IV is an error,
        // and no key data is returned.
        let (_, kek, _, ct) = RFC_3394[0];
        for at in 0..24 {
            let mut tampered = hex(ct);
            tampered[at] ^= 0x01;
            assert_eq!(
                unwrap(&hex(kek), &tampered).map(|_| ()),
                Err(Error::DecryptionFailed),
                "byte {at}"
            );
        }
        let mut wrong_kek = hex(kek);
        wrong_kek[0] ^= 0x80;
        assert_eq!(
            unwrap(&wrong_kek, &hex(ct)).map(|_| ()),
            Err(Error::DecryptionFailed)
        );
    }

    #[test]
    fn wrap_rejects_a_kek_that_is_not_an_aes_key_size() {
        // RFC 7518 §4.4: A128KW, A192KW and A256KW use 128, 192 and 256 bit
        // keys; AES has no other key size (FIPS 197 §5).
        let cek = hex(DATA_128);
        for len in [0, 1, 8, 15, 17, 20, 23, 25, 31, 33, 48, 64] {
            assert_eq!(
                wrap(&vec![0x4B; len], &cek),
                Err(Error::InvalidKey(KEK_SIZE)),
                "KEK of {len} bytes"
            );
        }
    }

    #[test]
    fn wrap_rejects_key_data_shorter_than_two_semiblocks_or_not_a_multiple_of_8() {
        // RFC 3394 §2: the key data is n 64-bit blocks with n >= 2. aes-kw
        // itself also wraps 0 and 8 bytes (research.md §3).
        let kek = hex(KEK_128);
        for len in [0, 1, 7, 8, 9, 15, 17, 20, 23, 33] {
            assert_eq!(
                wrap(&kek, &vec![0xC5; len]),
                Err(Error::InvalidKey(CEK_SIZE)),
                "key data of {len} bytes"
            );
        }
        for len in [16, 24, 32, 40, 48, 64, 384] {
            let wrapped = wrap(&kek, &vec![0xC5; len]).unwrap_or_else(|e| panic!("{len}: {e}"));
            assert_eq!(wrapped.len(), len + 8, "key data of {len} bytes");
        }
    }

    #[test]
    fn unwrap_rejects_input_shorter_than_three_semiblocks_or_not_a_multiple_of_8() {
        // RFC 3394 §2.2.2: the input is n + 1 64-bit blocks with n >= 2.
        let kek = hex(KEK_128);
        for len in [0, 1, 4, 7, 8, 15, 17, 20, 23, 25, 31] {
            assert_eq!(
                unwrap(&kek, &vec![0xA6; len]).map(|_| ()),
                Err(Error::DecryptionFailed),
                "wrapped input of {len} bytes"
            );
        }
        // A genuine 16-byte wrapping of 8 bytes of key data, which aes-kw
        // itself unwraps: still rejected.
        let mut one_block = [0u8; 16];
        let kw = KwAes128::new_from_slice(&kek).unwrap_or_else(|e| panic!("{e}"));
        kw.wrap_key(&[0xC5; 8], &mut one_block)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            unwrap(&kek, &one_block).map(|_| ()),
            Err(Error::DecryptionFailed)
        );
    }

    #[test]
    fn unwrap_rejects_a_kek_that_is_not_an_aes_key_size() {
        let (_, _, _, ct) = RFC_3394[0];
        for len in [0, 8, 15, 17, 33] {
            assert_eq!(
                unwrap(&vec![0x4B; len], &hex(ct)).map(|_| ()),
                Err(Error::DecryptionFailed),
                "KEK of {len} bytes"
            );
        }
    }

    /// Where polyjose's outcome differs from Wycheproof's `result`.
    const AES_WRAP: &[Deviation] = &[Deviation::tests(
        &[12, 54, 109],
        Outcome::Reject,
        "RFC 3394 §2: key data is at least two 64-bit blocks; a JWE CEK is at least 16 bytes \
         (RFC 7518 §5.2.3, §5.3), so wrapping an 8 byte key is refused",
    )];

    #[test]
    fn wycheproof_aes_wrap() {
        let suite = wycheproof::load("aes_wrap");
        let summary = wycheproof::assert_conforms(&suite, AES_WRAP, |_, test| {
            let (kek, msg, ct) = test.key_wrap();
            let unwrapped = unwrap(kek, ct);
            if test.result == Expected::Invalid {
                // ModifiedIv, InvalidWrappingSize, EmptyKey, ShortKey and
                // WrongDataSize: the wrapped input itself must be refused.
                assert_eq!(
                    unwrapped.as_ref().map(|_| ()),
                    Err(&Error::DecryptionFailed),
                    "tcId {}: unwrap",
                    test.tc_id
                );
            }
            let wrapped = wrap(kek, msg);
            if test.has_flag("WrongDataSize") || test.has_flag("EmptyKey") {
                assert!(wrapped.is_err(), "tcId {}: wrap", test.tc_id);
            }
            let round_trips = matches!(&unwrapped, Ok(key) if key.as_slice() == msg)
                && matches!(&wrapped, Ok(w) if w.as_slice() == ct);
            Outcome::of(&if round_trips { Ok(()) } else { Err(()) })
        });
        assert_eq!(summary.tests, 165);
        assert_eq!(summary.deviations, 3);
    }

    use crate::rng::insecure_test_vectors::FixedRng;

    /// `(alg, KEK length)` of RFC 7518 §4.4.
    const FAMILY: [(KeyMgmtAlg, usize); 3] = [
        (KeyMgmtAlg::A128KW, 16),
        (KeyMgmtAlg::A192KW, 24),
        (KeyMgmtAlg::A256KW, 32),
    ];

    fn kek(len: usize) -> RecipientKey {
        RecipientKey::Symmetric(Zeroizing::new((0..len).map(|i| 0x40 ^ i as u8).collect()))
    }

    fn cek_for(enc: &ContentEncAlg) -> Cek {
        let len = cek_len(enc).unwrap_or_else(|e| panic!("{e}"));
        Cek::new(Zeroizing::new((0..len).map(|i| 0xC0 ^ i as u8).collect()))
    }

    fn policy() -> DecryptPolicy {
        DecryptPolicy::new(&FAMILY.map(|(alg, _)| alg), ContentEncAlg::KNOWN)
            .unwrap_or_else(|e| panic!("{e}"))
    }

    fn encrypt(
        alg: &KeyMgmtAlg,
        key: &RecipientKey,
        enc: &ContentEncAlg,
        cek: Option<&Cek>,
    ) -> Result<KeyOutput> {
        let mut rng = FixedRng::new(vec![0x5A; 64]);
        let out = encrypt_key(alg, key, enc, cek, &RecipientOptions::default(), &mut rng);
        // A*KW is deterministic (RFC 3394 §2.2.1): it draws nothing.
        assert_eq!(rng.remaining(), 64, "{alg} drew randomness");
        out
    }

    fn decrypt(
        alg: &KeyMgmtAlg,
        key: &RecipientKey,
        enc: &ContentEncAlg,
        encrypted_key: &[u8],
    ) -> Result<Cek> {
        decrypt_key(alg, key, enc, &Header::new(), encrypted_key, &policy())
    }

    #[test]
    fn encrypt_key_wraps_the_random_cek_and_adds_no_header_parameter() {
        // RFC 7518 §4.4: the CEK is wrapped with RFC 3394 and the result is
        // the JWE Encrypted Key; no header parameters are used.
        for (alg, kek_len) in &FAMILY {
            for enc in ContentEncAlg::KNOWN {
                let key = kek(*kek_len);
                let cek = cek_for(enc);
                let out = encrypt(alg, &key, enc, Some(&cek))
                    .unwrap_or_else(|e| panic!("{alg} {enc}: {e}"));
                let RecipientKey::Symmetric(k) = &key else {
                    unreachable!()
                };
                assert_eq!(
                    out.encrypted_key,
                    wrap(k, cek.as_bytes()).unwrap_or_else(|e| panic!("{e}")),
                    "{alg} {enc}"
                );
                assert_eq!(out.encrypted_key.len(), cek.len() + 8, "{alg} {enc}");
                assert!(out.header_params.is_empty(), "{alg} {enc}");
                assert!(out.cek.is_none(), "{alg} {enc}");
            }
        }
    }

    #[test]
    fn decrypt_key_unwraps_what_encrypt_key_wrapped() {
        for (alg, kek_len) in &FAMILY {
            for enc in ContentEncAlg::KNOWN {
                let key = kek(*kek_len);
                let cek = cek_for(enc);
                let out = encrypt(alg, &key, enc, Some(&cek)).unwrap_or_else(|e| panic!("{e}"));
                let got = decrypt(alg, &key, enc, &out.encrypted_key)
                    .unwrap_or_else(|e| panic!("{alg} {enc}: {e}"));
                assert_eq!(got.as_bytes(), cek.as_bytes(), "{alg} {enc}");
            }
        }
    }

    #[test]
    fn encrypt_key_rejects_a_kek_whose_length_does_not_match_the_alg() {
        // RFC 7518 §4.4: A128KW, A192KW, A256KW use 128, 192, 256 bit keys.
        let enc = ContentEncAlg::A128GCM;
        let cek = cek_for(&enc);
        for (alg, kek_len) in &FAMILY {
            for len in [0, 8, 16, 24, 32, 48, 64] {
                if len == *kek_len {
                    continue;
                }
                assert_eq!(
                    encrypt(alg, &kek(len), &enc, Some(&cek)).map(|_| ()),
                    Err(Error::InvalidKey(KEK_SIZE)),
                    "{alg} with a {len} byte KEK"
                );
            }
        }
    }

    #[test]
    fn encrypt_key_rejects_a_missing_or_wrong_length_cek_and_a_non_symmetric_key() {
        let enc = ContentEncAlg::A256GCM;
        let alg = KeyMgmtAlg::A128KW;
        let key = kek(16);
        assert_eq!(
            encrypt(&alg, &key, &enc, None).map(|_| ()),
            Err(Error::InvalidKey(CEK_SIZE))
        );
        // RFC 7516 §5.1 step 2: the CEK has the length `enc` requires.
        let short = cek_for(&ContentEncAlg::A128GCM);
        assert_eq!(
            encrypt(&alg, &key, &enc, Some(&short)).map(|_| ()),
            Err(Error::InvalidKey(CEK_SIZE))
        );
        let password = RecipientKey::Password(Zeroizing::new(vec![0x50; 16]));
        let x25519 = RecipientKey::X25519Public(x25519_dalek::PublicKey::from([9; 32]));
        for wrong in [password, x25519] {
            assert_eq!(
                encrypt(&alg, &wrong, &enc, Some(&cek_for(&enc))).map(|_| ()),
                Err(Error::KeyAlgorithmMismatch),
                "{wrong:?}"
            );
        }
    }

    #[test]
    fn every_decrypt_key_failure_is_decryption_failed_with_no_cek() {
        // RFC 7516 §11.4–§11.5 and the plan.md error contract: integrity,
        // input length, KEK and CEK length failures are indistinguishable.
        let alg = KeyMgmtAlg::A128KW;
        let key = kek(16);
        let enc = ContentEncAlg::A128GCM;
        let wrapped = encrypt(&alg, &key, &enc, Some(&cek_for(&enc)))
            .unwrap_or_else(|e| panic!("{e}"))
            .encrypted_key;
        let mut tampered = wrapped.clone();
        tampered[5] ^= 0x20;
        // A valid wrapping of a 32-byte key: it unwraps, but A128GCM needs
        // 16 bytes (RFC 7516 §5.2 step 9).
        let RecipientKey::Symmetric(k) = &key else {
            unreachable!()
        };
        let long = wrap(k, &[0xC5; 32]).unwrap_or_else(|e| panic!("{e}"));
        let short = wrap(k, &[0xC5; 16]).unwrap_or_else(|e| panic!("{e}"));
        let cases: Vec<(&str, KeyMgmtAlg, RecipientKey, ContentEncAlg, Vec<u8>)> = vec![
            ("tampered", alg.clone(), kek(16), enc.clone(), tampered),
            (
                "wrong KEK",
                alg.clone(),
                kek(24),
                enc.clone(),
                wrapped.clone(),
            ),
            (
                "A192KW with a 16 byte KEK",
                KeyMgmtAlg::A192KW,
                kek(16),
                enc.clone(),
                wrapped.clone(),
            ),
            (
                "A256KW with a 24 byte KEK",
                KeyMgmtAlg::A256KW,
                kek(24),
                enc.clone(),
                wrapped.clone(),
            ),
            ("empty", alg.clone(), kek(16), enc.clone(), Vec::new()),
            (
                "one semiblock short",
                alg.clone(),
                kek(16),
                enc.clone(),
                wrapped[..16].to_vec(),
            ),
            (
                "not a multiple of 8",
                alg.clone(),
                kek(16),
                enc.clone(),
                wrapped[..23].to_vec(),
            ),
            (
                "unwrapped CEK too long",
                alg.clone(),
                kek(16),
                enc.clone(),
                long,
            ),
            (
                "unwrapped CEK too short",
                alg.clone(),
                kek(16),
                ContentEncAlg::A128CbcHs256,
                short,
            ),
            (
                "unknown enc",
                alg.clone(),
                kek(16),
                ContentEncAlg::from("A512GCM"),
                wrapped.clone(),
            ),
            (
                "password key",
                alg.clone(),
                RecipientKey::Password(Zeroizing::new(vec![0x40; 16])),
                enc.clone(),
                wrapped.clone(),
            ),
        ];
        for (what, alg, key, enc, encrypted_key) in cases {
            let result = decrypt(&alg, &key, &enc, &encrypted_key);
            assert!(
                matches!(result, Err(Error::DecryptionFailed)),
                "{what}: {result:?}"
            );
        }
    }

    mod properties {
        use super::*;
        use proptest::prelude::*;

        /// An `alg` of the family with a random KEK of its length, an `enc`
        /// and a random CEK of the length that `enc` requires.
        fn case() -> impl Strategy<Value = (KeyMgmtAlg, Vec<u8>, ContentEncAlg, Vec<u8>)> {
            (0..FAMILY.len(), 0..ContentEncAlg::KNOWN.len()).prop_flat_map(|(a, e)| {
                let (alg, kek_len) = FAMILY[a].clone();
                let enc = ContentEncAlg::KNOWN[e].clone();
                let cek_len = cek_len(&enc).unwrap_or_else(|err| panic!("{err}"));
                (
                    Just(alg),
                    proptest::collection::vec(any::<u8>(), kek_len),
                    Just(enc),
                    proptest::collection::vec(any::<u8>(), cek_len),
                )
            })
        }

        proptest! {
            // ADR 0008 layer 2: bounded case counts in the fast suite.
            #![proptest_config(ProptestConfig::with_cases(512))]

            /// RFC 3394 §2.2.2 inverts §2.2.1 for every KEK size and every
            /// `enc` CEK length (RFC 7518 §4.4, §5.2.3–§5.2.5, §5.3).
            #[test]
            fn encrypt_key_then_decrypt_key_round_trips((alg, kek, enc, cek) in case()) {
                let key = RecipientKey::Symmetric(Zeroizing::new(kek));
                let random_cek = Cek::from_slice(&cek);
                let out = encrypt(&alg, &key, &enc, Some(&random_cek))?;
                prop_assert_eq!(out.encrypted_key.len(), cek.len() + 8);
                let got = decrypt(&alg, &key, &enc, &out.encrypted_key)?;
                prop_assert_eq!(got.as_bytes(), cek.as_slice());
            }

            /// RFC 3394 §2.2.3: flipping any bit of the wrapped key fails the
            /// integrity check, and decrypt says only DecryptionFailed.
            #[test]
            fn any_flipped_bit_fails_as_decryption_failed(
                (alg, kek, enc, cek) in case(),
                at in any::<prop::sample::Index>(),
                bit in 0..8u8,
            ) {
                let key = RecipientKey::Symmetric(Zeroizing::new(kek));
                let mut wrapped = encrypt(&alg, &key, &enc, Some(&Cek::from_slice(&cek)))?.encrypted_key;
                let at = at.index(wrapped.len());
                wrapped[at] ^= 1 << bit;
                let result = decrypt(&alg, &key, &enc, &wrapped);
                prop_assert!(matches!(result, Err(Error::DecryptionFailed)), "{:?}", result);
            }
        }
    }
}
