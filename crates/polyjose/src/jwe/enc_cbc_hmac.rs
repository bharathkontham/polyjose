//! AES_CBC_HMAC_SHA2 content encryption: A128CBC-HS256, A192CBC-HS384 and
//! A256CBC-HS512 (RFC 7518 §5.2), composed from `cbc`, `aes`, `hmac` and
//! `sha2`. The tag is verified in constant time before any decryption
//! (RFC 7518 §5.2.2.2). Filled in by T03.

use zeroize::Zeroizing;

use crate::jwa::ContentEncAlg;
use crate::{Error, Result};

/// AL: the number of bits in the Additional Authenticated Data A, as a
/// 64-bit unsigned big-endian integer (RFC 7518 §5.2.2.1 step 4).
///
/// The count is computed in `u64`, never in `usize`, so it cannot wrap on
/// a 32-bit target for an A of 512 MiB or more (CVE-2016-9123, go-jose).
/// `None` only for an A of 2^61 octets or more, whose bit count does not
/// fit 64 bits; no such slice can exist on a 32-bit target.
fn al(aad_len: usize) -> Option<[u8; 8]> {
    u64::try_from(aad_len)
        .ok()?
        .checked_mul(8)
        .map(u64::to_be_bytes)
}

/// Encrypts `plaintext` under `cek` (MAC_KEY || ENC_KEY: 32, 48 or 64
/// bytes) and the 16-byte `iv`, and returns `(ciphertext, tag)`, the tag
/// being the first T_LEN octets of `HMAC(MAC_KEY, A || IV || E || AL)`
/// (RFC 7518 §5.2.2.1).
///
/// # Errors
///
/// An error if `enc` is not A*CBC-HS* or the CEK or IV length is wrong.
pub(super) fn encrypt(
    _enc: &ContentEncAlg,
    _cek: &[u8],
    _iv: &[u8],
    _aad: &[u8],
    _plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    Err(Error::UnsupportedAlgorithm)
}

/// Verifies `tag` first and only then decrypts and unpads (RFC 7518
/// §5.2.2.2).
///
/// # Errors
///
/// [`Error::DecryptionFailed`] for every failure: tag, tag or IV length,
/// padding, CEK length (RFC 7516 §11.4).
pub(super) fn decrypt(
    _enc: &ContentEncAlg,
    _cek: &[u8],
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

    /// Hex with any whitespace, as RFC 7518 Appendix B prints it.
    fn hex(s: &str) -> Vec<u8> {
        let digits: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        assert_eq!(digits.len() % 2, 0, "odd hex length");
        digits
            .chunks(2)
            .map(|pair| {
                let pair = core::str::from_utf8(pair).unwrap();
                u8::from_str_radix(pair, 16).unwrap()
            })
            .collect()
    }

    /// RFC 7518 Appendix B.1–B.3: AL for the 42-octet A.
    const B_AL: &str = "00 00 00 00 00 00 01 50";

    #[test]
    fn al_is_the_aad_bit_count_as_a_big_endian_u64() {
        // RFC 7518 §5.2.2.1 step 4, and Appendix B's AL for a 42-octet A.
        assert_eq!(al(0), Some([0; 8]));
        assert_eq!(al(42).map(|al| al.to_vec()), Some(hex(B_AL)));
        // CVE-2016-9123: on a 32-bit target, `len * 8` in usize wraps from
        // here on. These are lengths only; nothing of this size is
        // allocated.
        let limit = (u32::MAX / 8) as usize;
        assert_eq!(al(limit), Some((u64::from(u32::MAX / 8) * 8).to_be_bytes()));
        assert_eq!(al(limit + 1), Some(0x1_0000_0000_u64.to_be_bytes()));
        assert_eq!(al(limit + 2), Some(0x1_0000_0008_u64.to_be_bytes()));
        #[cfg(target_pointer_width = "64")]
        {
            // The largest A whose bit count fits a u64, and the first that
            // does not.
            assert_eq!(al((1 << 61) - 1), Some((u64::MAX - 7).to_be_bytes()));
            assert_eq!(al(1 << 61), None);
            assert_eq!(al(usize::MAX), None);
        }
    }
}
