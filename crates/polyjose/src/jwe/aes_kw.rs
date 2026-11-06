//! A128KW, A192KW and A256KW: AES Key Wrap (RFC 3394) of a random CEK
//! (RFC 7518 §4.4), on `aes-kw`. Also the [`wrap`]/[`unwrap`] helper that
//! PBES2 (RFC 7518 §4.8) and ECDH-ES+A*KW (RFC 7518 §4.6) call. Filled in
//! by T06.

use super::api::DecryptPolicy;
use super::content::Cek;
use super::key::RecipientKey;
use super::keymgmt::{KeyOutput, RecipientOptions};
use super::random::RandomSource;
use crate::header::Header;
use crate::jwa::{ContentEncAlg, KeyMgmtAlg};
use crate::{Error, Result};
use aes_kw::{KeyInit, KwAes128, KwAes192, KwAes256};
use zeroize::Zeroizing;

/// Key management on encrypt (RFC 7516 §5.1 steps 3–7) for A128KW, A192KW and A256KW.
///
/// # Errors
///
/// An error if the KEK length does not match `alg` (16, 24 or 32 bytes).
pub(super) fn encrypt_key(
    _alg: &KeyMgmtAlg,
    _key: &RecipientKey,
    _enc: &ContentEncAlg,
    _cek: Option<&Cek>,
    _options: &RecipientOptions,
    _rng: &mut dyn RandomSource,
) -> Result<KeyOutput> {
    Err(Error::UnsupportedAlgorithm)
}

/// Key management on decrypt (RFC 7516 §5.2 steps 6–12) for A128KW, A192KW and A256KW: the
/// CEK, which must have the length `enc` requires (§5.2 step 9).
///
/// # Errors
///
/// An error for a wrong KEK length, a wrapped key of the wrong size, an integrity failure (RFC 3394 §2.2.3) or an unwrapped CEK of the wrong length. `core` reports every error from here as `DecryptionFailed`.
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
}
