//! AES_CBC_HMAC_SHA2 content encryption: A128CBC-HS256, A192CBC-HS384 and
//! A256CBC-HS512 (RFC 7518 §5.2), composed from the RustCrypto `cbc`,
//! `aes`, `hmac` and `sha2` crates (ADR 0002); no primitive is written
//! here.
//!
//! - **Key split.** The CEK is K = MAC_KEY || ENC_KEY, MAC key first
//!   (RFC 7518 §5.2.2.1 step 1), of exactly 32, 48 or 64 octets
//!   (§5.2.3–§5.2.5). Any other length fails before a primitive is keyed.
//! - **Tag.** T is the first T_LEN = 16, 24 or 32 octets of
//!   `HMAC-SHA-256/384/512(MAC_KEY, A || IV || E || AL)` (RFC 7518
//!   §5.2.2.1 step 5), with AL counted in `u64` (step 4; CVE-2016-9123).
//! - **MAC before decryption.** Decrypt checks the tag length and the IV
//!   length (both public), then the tag, in constant time with
//!   `Mac::verify_truncated_left` (`subtle`), and only then runs AES-CBC
//!   (RFC 7518 §5.2.2.2 steps 2–3). `cbc`'s PKCS #7 unpadding is not
//!   constant-time; that is safe only because nothing reaches it without a
//!   valid tag, so no padding oracle exists (RFC 7516 §11.5).
//! - **One failure.** Every decryption failure is the same
//!   [`Error::DecryptionFailed`] (RFC 7516 §11.4, §11.5): CEK, IV or tag
//!   length, tag mismatch, ciphertext length and padding alike.
//! - **Secrets.** The CEK halves are borrowed, never copied. The plaintext
//!   is decrypted and unpadded in place in a [`Zeroizing`] buffer, so it is
//!   wiped when unpadding fails as well as when the caller drops it. The
//!   AES key schedules (`aes`'s `zeroize` feature, through `cbc`) and the
//!   keyed HMAC cores (`sha2`'s `zeroize` feature) are wiped on drop.
//!   (`hmac` 0.13.0 does not wipe the key-xor-pad block it builds on the
//!   stack while keying; that is upstream code, as for JWS HMAC.)

use aes::{Aes128, Aes192, Aes256};
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Sha256, Sha384, Sha512};
use zeroize::Zeroizing;

use crate::jwa::ContentEncAlg;
use crate::{Error, Result};

/// The IV length: 128 bits, the AES block size (RFC 7518 §5.2.2.1 step 2).
const IV_LEN: usize = 16;

/// The detail of [`Error::InvalidKey`] for a CEK of the wrong length on
/// encrypt.
const CEK_LEN: &str = "content encryption key length does not match enc";
/// The detail of [`Error::InvalidFormat`] for an IV of the wrong length on
/// encrypt.
const IV_LEN_MISMATCH: &str = "A*CBC-HS* content IV must be 16 octets";
/// The detail of [`Error::InvalidFormat`] for an AAD whose bit count does
/// not fit AL's 64 bits on encrypt.
const AAD_TOO_LONG: &str = "AAD is too long for A*CBC-HS*";

/// The parameters of one AES_CBC_HMAC_SHA2 instance (RFC 7518
/// §5.2.3–§5.2.5). In all three, MAC_KEY_LEN = ENC_KEY_LEN = T_LEN.
struct Params {
    /// MAC_KEY_LEN: MAC_KEY is the initial octets of K.
    mac_key_len: usize,
    /// ENC_KEY_LEN: ENC_KEY is the final octets of K.
    enc_key_len: usize,
    /// T_LEN: the octets of the HMAC output kept as T.
    t_len: usize,
}

/// AES_128_CBC_HMAC_SHA_256 (RFC 7518 §5.2.3): K is 32 octets, T 16.
const A128CBC_HS256: Params = Params {
    mac_key_len: 16,
    enc_key_len: 16,
    t_len: 16,
};
/// AES_192_CBC_HMAC_SHA_384 (RFC 7518 §5.2.4): K is 48 octets, T 24.
const A192CBC_HS384: Params = Params {
    mac_key_len: 24,
    enc_key_len: 24,
    t_len: 24,
};
/// AES_256_CBC_HMAC_SHA_512 (RFC 7518 §5.2.5): K is 64 octets, T 32.
const A256CBC_HS512: Params = Params {
    mac_key_len: 32,
    enc_key_len: 32,
    t_len: 32,
};

impl Params {
    /// `(MAC_KEY, ENC_KEY)`: the initial MAC_KEY_LEN and the final
    /// ENC_KEY_LEN octets of K, which must be exactly their sum
    /// (RFC 7518 §5.2.2.1 step 1). `None` for any other length.
    fn split<'k>(&self, k: &'k [u8]) -> Option<(&'k [u8], &'k [u8])> {
        (k.len() == self.mac_key_len + self.enc_key_len).then(|| k.split_at(self.mac_key_len))
    }
}

/// `HMAC(MAC_KEY, A || IV || E || AL)`, keyed and fed but not finalized
/// (RFC 7518 §5.2.2.1 step 5). `None` if `M` refuses the key, which HMAC
/// never does (RFC 2104 §2).
fn mac<M: Mac + KeyInit>(mac_key: &[u8], a: &[u8], iv: &[u8], e: &[u8], al: &[u8; 8]) -> Option<M> {
    let mut mac = <M as KeyInit>::new_from_slice(mac_key).ok()?;
    mac.update(a);
    mac.update(iv);
    mac.update(e);
    mac.update(al);
    Some(mac)
}

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
/// - [`Error::UnsupportedAlgorithm`] if `enc` is not A*CBC-HS*.
/// - [`Error::InvalidKey`] if the CEK is not 32, 48 or 64 octets for
///   A128CBC-HS256, A192CBC-HS384 or A256CBC-HS512 (RFC 7518
///   §5.2.3–§5.2.5), checked before any primitive is keyed.
/// - [`Error::InvalidFormat`] if the IV is not 16 octets (RFC 7518
///   §5.2.2.1 step 2), or if the AAD is 2^61 octets or more, so that AL
///   cannot hold its bit count (step 4).
pub(super) fn encrypt(
    enc: &ContentEncAlg,
    cek: &[u8],
    iv: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    match enc {
        ContentEncAlg::A128CbcHs256 => {
            seal::<cbc::Encryptor<Aes128>, Hmac<Sha256>>(&A128CBC_HS256, cek, iv, aad, plaintext)
        }
        ContentEncAlg::A192CbcHs384 => {
            seal::<cbc::Encryptor<Aes192>, Hmac<Sha384>>(&A192CBC_HS384, cek, iv, aad, plaintext)
        }
        ContentEncAlg::A256CbcHs512 => {
            seal::<cbc::Encryptor<Aes256>, Hmac<Sha512>>(&A256CBC_HS512, cek, iv, aad, plaintext)
        }
        _ => Err(Error::UnsupportedAlgorithm),
    }
}

/// Verifies `tag` first and only then decrypts and unpads (RFC 7518
/// §5.2.2.2).
///
/// # Errors
///
/// - [`Error::UnsupportedAlgorithm`] if `enc` is not A*CBC-HS* (a call
///   against the dispatcher's contract).
/// - [`Error::DecryptionFailed`] for every other failure, all identical:
///   CEK, tag or IV length, tag mismatch, ciphertext length and padding
///   (RFC 7516 §11.4, §11.5).
pub(super) fn decrypt(
    enc: &ContentEncAlg,
    cek: &[u8],
    iv: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    match enc {
        ContentEncAlg::A128CbcHs256 => open::<cbc::Decryptor<Aes128>, Hmac<Sha256>>(
            &A128CBC_HS256,
            cek,
            iv,
            aad,
            ciphertext,
            tag,
        ),
        ContentEncAlg::A192CbcHs384 => open::<cbc::Decryptor<Aes192>, Hmac<Sha384>>(
            &A192CBC_HS384,
            cek,
            iv,
            aad,
            ciphertext,
            tag,
        ),
        ContentEncAlg::A256CbcHs512 => open::<cbc::Decryptor<Aes256>, Hmac<Sha512>>(
            &A256CBC_HS512,
            cek,
            iv,
            aad,
            ciphertext,
            tag,
        ),
        _ => Err(Error::UnsupportedAlgorithm),
    }
}

/// RFC 7518 §5.2.2.1 for one instance: `Enc` is AES-CBC with the
/// instance's key size and `M` is HMAC with its hash.
fn seal<Enc, M>(
    params: &Params,
    k: &[u8],
    iv: &[u8],
    a: &[u8],
    p: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)>
where
    Enc: KeyIvInit + BlockModeEncrypt,
    M: Mac + KeyInit,
{
    // Step 1: split K; its length is checked before anything is keyed.
    let (mac_key, enc_key) = params.split(k).ok_or(Error::InvalidKey(CEK_LEN))?;
    // Step 2: a 128-bit IV.
    if iv.len() != IV_LEN {
        return Err(Error::InvalidFormat(IV_LEN_MISMATCH));
    }
    // Step 4 (computed first, so nothing is encrypted for an AAD AL cannot
    // describe).
    let al = al(a.len()).ok_or(Error::InvalidFormat(AAD_TOO_LONG))?;
    // Step 3: E = CBC-PKCS7-ENC(ENC_KEY, P).
    let cipher = Enc::new_from_slices(enc_key, iv).map_err(|_| Error::InvalidKey(CEK_LEN))?;
    let e = cipher.encrypt_padded_vec::<Pkcs7>(p);
    // Step 5: M = MAC(MAC_KEY, A || IV || E || AL); T = the first T_LEN
    // octets of M.
    let m = mac::<M>(mac_key, a, iv, &e, &al)
        .ok_or(Error::InvalidKey(CEK_LEN))?
        .finalize()
        .into_bytes();
    // (`get` never fails: T_LEN is half the hash output.)
    let t = m
        .get(..params.t_len)
        .ok_or(Error::InvalidKey(CEK_LEN))?
        .to_vec();
    // Step 6.
    Ok((e, t))
}

/// RFC 7518 §5.2.2.2 for one instance, as [`seal`].
fn open<Dec, M>(
    params: &Params,
    k: &[u8],
    iv: &[u8],
    a: &[u8],
    e: &[u8],
    t: &[u8],
) -> Result<Zeroizing<Vec<u8>>>
where
    Dec: KeyIvInit + BlockModeDecrypt,
    M: Mac + KeyInit,
{
    // Step 1: split K.
    let (mac_key, enc_key) = params.split(k).ok_or(Error::DecryptionFailed)?;
    // T must be exactly T_LEN octets: `verify_truncated_left` alone would
    // accept any non-empty prefix of M, down to a single octet. The length
    // is public, so this check need not be constant-time.
    if t.len() != params.t_len {
        return Err(Error::DecryptionFailed);
    }
    if iv.len() != IV_LEN {
        return Err(Error::DecryptionFailed);
    }
    let al = al(a.len()).ok_or(Error::DecryptionFailed)?;
    // Step 2: compare T with the first T_LEN octets of
    // MAC(MAC_KEY, A || IV || E || AL) in constant time, and halt on a
    // mismatch before E is decrypted (RFC 7516 §11.5).
    mac::<M>(mac_key, a, iv, e, &al)
        .ok_or(Error::DecryptionFailed)?
        .verify_truncated_left(t)
        .map_err(|_| Error::DecryptionFailed)?;
    // Step 3: decrypt E and check and remove the PKCS #7 padding, in place
    // in a buffer that is wiped on every path out of here.
    let cipher = Dec::new_from_slices(enc_key, iv).map_err(|_| Error::DecryptionFailed)?;
    let mut buf = Zeroizing::new(e.to_vec());
    #[cfg(test)]
    crate::test_counters::cbc_hmac_decryptions::tick();
    let len = cipher
        .decrypt_padded::<Pkcs7>(&mut buf)
        .map_err(|_| Error::DecryptionFailed)?
        .len();
    // Step 4. The padding octets left beyond `len` are wiped with the rest.
    buf.truncate(len);
    Ok(buf)
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

    /// One RFC 7518 Appendix B test case: the inputs K, P, IV and A and the
    /// outputs E and T.
    struct AppendixB {
        enc: ContentEncAlg,
        k: &'static str,
        e: &'static str,
        t: &'static str,
    }

    /// RFC 7518 Appendix B.1–B.3: P, IV and A are the same in all three.
    const B_P: &str = "41 20 63 69 70 68 65 72 20 73 79 73 74 65 6d 20
        6d 75 73 74 20 6e 6f 74 20 62 65 20 72 65 71 75
        69 72 65 64 20 74 6f 20 62 65 20 73 65 63 72 65
        74 2c 20 61 6e 64 20 69 74 20 6d 75 73 74 20 62
        65 20 61 62 6c 65 20 74 6f 20 66 61 6c 6c 20 69
        6e 74 6f 20 74 68 65 20 68 61 6e 64 73 20 6f 66
        20 74 68 65 20 65 6e 65 6d 79 20 77 69 74 68 6f
        75 74 20 69 6e 63 6f 6e 76 65 6e 69 65 6e 63 65";
    const B_IV: &str = "1a f3 8c 2d c2 b9 6f fd d8 66 94 09 23 41 bc 04";
    const B_A: &str = "54 68 65 20 73 65 63 6f 6e 64 20 70 72 69 6e 63
        69 70 6c 65 20 6f 66 20 41 75 67 75 73 74 65 20
        4b 65 72 63 6b 68 6f 66 66 73";
    /// RFC 7518 Appendix B.1–B.3: AL for the 42-octet A.
    const B_AL: &str = "00 00 00 00 00 00 01 50";

    fn appendix_b() -> [AppendixB; 3] {
        [
            // RFC 7518 Appendix B.1: AES_128_CBC_HMAC_SHA_256.
            AppendixB {
                enc: ContentEncAlg::A128CbcHs256,
                k: "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
                    10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f",
                e: "c8 0e df a3 2d df 39 d5 ef 00 c0 b4 68 83 42 79
                    a2 e4 6a 1b 80 49 f7 92 f7 6b fe 54 b9 03 a9 c9
                    a9 4a c9 b4 7a d2 65 5c 5f 10 f9 ae f7 14 27 e2
                    fc 6f 9b 3f 39 9a 22 14 89 f1 63 62 c7 03 23 36
                    09 d4 5a c6 98 64 e3 32 1c f8 29 35 ac 40 96 c8
                    6e 13 33 14 c5 40 19 e8 ca 79 80 df a4 b9 cf 1b
                    38 4c 48 6f 3a 54 c5 10 78 15 8e e5 d7 9d e5 9f
                    bd 34 d8 48 b3 d6 95 50 a6 76 46 34 44 27 ad e5
                    4b 88 51 ff b5 98 f7 f8 00 74 b9 47 3c 82 e2 db",
                t: "65 2c 3f a3 6b 0a 7c 5b 32 19 fa b3 a3 0b c1 c4",
            },
            // RFC 7518 Appendix B.2: AES_192_CBC_HMAC_SHA_384.
            AppendixB {
                enc: ContentEncAlg::A192CbcHs384,
                k: "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
                    10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
                    20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f",
                e: "ea 65 da 6b 59 e6 1e db 41 9b e6 2d 19 71 2a e5
                    d3 03 ee b5 00 52 d0 df d6 69 7f 77 22 4c 8e db
                    00 0d 27 9b dc 14 c1 07 26 54 bd 30 94 42 30 c6
                    57 be d4 ca 0c 9f 4a 84 66 f2 2b 22 6d 17 46 21
                    4b f8 cf c2 40 0a dd 9f 51 26 e4 79 66 3f c9 0b
                    3b ed 78 7a 2f 0f fc bf 39 04 be 2a 64 1d 5c 21
                    05 bf e5 91 ba e2 3b 1d 74 49 e5 32 ee f6 0a 9a
                    c8 bb 6c 6b 01 d3 5d 49 78 7b cd 57 ef 48 49 27
                    f2 80 ad c9 1a c0 c4 e7 9c 7b 11 ef c6 00 54 e3",
                t: "84 90 ac 0e 58 94 9b fe 51 87 5d 73 3f 93 ac 20
                    75 16 80 39 cc c7 33 d7",
            },
            // RFC 7518 Appendix B.3: AES_256_CBC_HMAC_SHA_512.
            AppendixB {
                enc: ContentEncAlg::A256CbcHs512,
                k: "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
                    10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
                    20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f
                    30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f",
                e: "4a ff aa ad b7 8c 31 c5 da 4b 1b 59 0d 10 ff bd
                    3d d8 d5 d3 02 42 35 26 91 2d a0 37 ec bc c7 bd
                    82 2c 30 1d d6 7c 37 3b cc b5 84 ad 3e 92 79 c2
                    e6 d1 2a 13 74 b7 7f 07 75 53 df 82 94 10 44 6b
                    36 eb d9 70 66 29 6a e6 42 7e a7 5c 2e 08 46 a1
                    1a 09 cc f5 37 0d c8 0b fe cb ad 28 c7 3f 09 b3
                    a3 b7 5e 66 2a 25 94 41 0a e4 96 b2 e2 e6 60 9e
                    31 e6 e0 2c c8 37 f0 53 d2 1f 37 ff 4f 51 95 0b
                    be 26 38 d0 9d d7 a4 93 09 30 80 6d 07 03 b1 f6",
                t: "4d d3 b4 c0 88 a7 f4 5c 21 68 39 64 5b 20 12 bf
                    2e 62 69 a8 c5 6a 81 6d bc 1b 26 77 61 95 5b c5",
            },
        ]
    }

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

    #[test]
    fn rfc7518_appendix_b_vectors_encrypt_exactly_and_decrypt_back() {
        let (p, iv, a) = (hex(B_P), hex(B_IV), hex(B_A));
        for case in appendix_b() {
            let (k, e, t) = (hex(case.k), hex(case.e), hex(case.t));
            let (ciphertext, tag) = encrypt(&case.enc, &k, &iv, &a, &p).unwrap();
            assert_eq!(ciphertext, e, "{} E", case.enc);
            assert_eq!(tag, t, "{} T", case.enc);
            let plaintext = decrypt(&case.enc, &k, &iv, &a, &e, &t).unwrap();
            assert_eq!(&plaintext[..], &p[..], "{} P", case.enc);
        }
    }

    use crate::test_counters::cbc_hmac_decryptions;

    /// The three `enc` values with their K and T lengths (RFC 7518
    /// §5.2.3–§5.2.5).
    const ENCS: [(ContentEncAlg, usize, usize); 3] = [
        (ContentEncAlg::A128CbcHs256, 32, 16),
        (ContentEncAlg::A192CbcHs384, 48, 24),
        (ContentEncAlg::A256CbcHs512, 64, 32),
    ];

    /// A distinct, non-trivial K of `len` octets.
    fn key(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(29).wrapping_add(7))
            .collect()
    }

    const IV: [u8; 16] = [0x5A; 16];
    const AAD: &[u8] = b"eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0";
    const PLAINTEXT: &[u8] = b"Live long and prosper.";

    /// `decrypt`, with the number of CBC decryptions it started.
    fn decrypt_counted(
        enc: &ContentEncAlg,
        k: &[u8],
        iv: &[u8],
        aad: &[u8],
        e: &[u8],
        t: &[u8],
    ) -> (Result<Zeroizing<Vec<u8>>>, u64) {
        cbc_hmac_decryptions::count(|| decrypt(enc, k, iv, aad, e, t))
    }

    #[test]
    fn a_valid_message_reaches_the_cipher_exactly_once() {
        for (enc, k_len, t_len) in ENCS {
            let k = key(k_len);
            let (e, t) = encrypt(&enc, &k, &IV, AAD, PLAINTEXT).unwrap();
            assert_eq!(t.len(), t_len, "{enc}");
            // PKCS #7 always pads, by 1 to 16 octets (RFC 7518 §5.2.2.1
            // step 3).
            assert_eq!(e.len(), PLAINTEXT.len().next_multiple_of(16), "{enc}");
            let (plaintext, n) = decrypt_counted(&enc, &k, &IV, AAD, &e, &t);
            assert_eq!(&plaintext.unwrap()[..], PLAINTEXT, "{enc}");
            assert_eq!(n, 1, "{enc}");
        }
    }

    #[test]
    fn a_tampered_tag_never_reaches_the_cipher() {
        // RFC 7518 §5.2.2.2 step 2: on a MAC mismatch the operation halts
        // before E is decrypted, so no padding check ever runs on
        // unauthenticated data (RFC 7516 §11.5).
        for (enc, k_len, _) in ENCS {
            let k = key(k_len);
            let (e, t) = encrypt(&enc, &k, &IV, AAD, PLAINTEXT).unwrap();
            for byte in 0..t.len() {
                for bit in [0x01, 0x80] {
                    let mut bad = t.clone();
                    bad[byte] ^= bit;
                    let (result, n) = decrypt_counted(&enc, &k, &IV, AAD, &e, &bad);
                    assert_eq!(result, Err(Error::DecryptionFailed), "{enc} T[{byte}]");
                    assert_eq!(n, 0, "{enc} T[{byte}] reached the cipher");
                }
            }
            // The tag covers A, IV and E (RFC 7518 §5.2.2.1 step 5), and the
            // key: a change to any of them fails before decryption too.
            let mut bad_e = e.clone();
            bad_e[0] ^= 1;
            let mut bad_iv = IV;
            bad_iv[15] ^= 1;
            let mut bad_k = k.clone();
            bad_k[0] ^= 1;
            let mut short_aad = AAD.to_vec();
            short_aad.pop();
            for (what, k, iv, aad, e) in [
                ("E", &k, &IV[..], AAD, &bad_e[..]),
                ("IV", &k, &bad_iv[..], AAD, &e[..]),
                ("A", &k, &IV[..], &short_aad[..], &e[..]),
                ("A empty", &k, &IV[..], &[][..], &e[..]),
                ("MAC_KEY", &bad_k, &IV[..], AAD, &e[..]),
            ] {
                let (result, n) = decrypt_counted(&enc, k, iv, aad, e, &t);
                assert_eq!(result, Err(Error::DecryptionFailed), "{enc} {what}");
                assert_eq!(n, 0, "{enc} {what} reached the cipher");
            }
        }
    }

    #[test]
    fn a_tag_of_any_other_length_fails_even_as_a_true_prefix() {
        // `Mac::verify_truncated_left` accepts any non-empty prefix of M; T
        // must be exactly T_LEN octets (RFC 7518 §5.2.2.1 step 5,
        // §5.2.3–§5.2.5), so a prefix of the right tag, or the right tag
        // with an extra octet, fails before the MAC is even computed.
        for (enc, k_len, t_len) in ENCS {
            let k = key(k_len);
            let (e, t) = encrypt(&enc, &k, &IV, AAD, PLAINTEXT).unwrap();
            let m = full_mac(&enc, &k, &IV, AAD, &e);
            assert_eq!(&m[..t_len], &t[..], "{enc}");
            let mut longer = t.clone();
            longer.push(m[t_len]);
            for (what, bad) in [
                ("empty", &[][..]),
                ("1 octet", &t[..1]),
                ("T_LEN - 1", &t[..t_len - 1]),
                ("T_LEN + 1 (a prefix of M)", &longer[..]),
                ("all of M", &m[..]),
            ] {
                let (result, n) = decrypt_counted(&enc, &k, &IV, AAD, &e, bad);
                assert_eq!(result, Err(Error::DecryptionFailed), "{enc} {what}");
                assert_eq!(n, 0, "{enc} {what} reached the cipher");
            }
        }
    }

    #[test]
    fn a_cek_or_iv_of_the_wrong_length_fails_before_any_primitive() {
        // RFC 7518 §5.2.2.1 step 1: K is exactly MAC_KEY_LEN + ENC_KEY_LEN
        // octets; step 2: the IV is 128 bits.
        for (enc, k_len, _) in ENCS {
            let k = key(k_len);
            let (e, t) = encrypt(&enc, &k, &IV, AAD, PLAINTEXT).unwrap();
            let other_k = [0, 16, 24, 31, 32, 33, 47, 48, 49, 63, 64, 65, 128];
            for len in other_k.into_iter().filter(|&len| len != k_len) {
                // A K one octet longer or shorter still holds a valid-length
                // MAC_KEY prefix; it must be refused, not split.
                let wrong = key(len);
                assert_eq!(
                    encrypt(&enc, &wrong, &IV, AAD, PLAINTEXT),
                    Err(Error::InvalidKey(CEK_LEN)),
                    "{enc} K of {len}"
                );
                let (result, n) = decrypt_counted(&enc, &wrong, &IV, AAD, &e, &t);
                assert_eq!(result, Err(Error::DecryptionFailed), "{enc} K of {len}");
                assert_eq!(n, 0, "{enc} K of {len}");
            }
            for len in [0, 8, 12, 15, 17, 32] {
                let iv = vec![0x5A; len];
                assert_eq!(
                    encrypt(&enc, &k, &iv, AAD, PLAINTEXT),
                    Err(Error::InvalidFormat(IV_LEN_MISMATCH)),
                    "{enc} IV of {len}"
                );
                let (result, n) = decrypt_counted(&enc, &k, &iv, AAD, &e, &t);
                assert_eq!(result, Err(Error::DecryptionFailed), "{enc} IV of {len}");
                assert_eq!(n, 0, "{enc} IV of {len}");
            }
        }
    }

    #[test]
    fn another_enc_is_unsupported_not_a_decryption_failure() {
        // The dispatcher (`content`) sends only A*CBC-HS* here; anything
        // else is a call against its contract (RFC 7516 §4.1.2).
        for enc in [
            ContentEncAlg::A128GCM,
            ContentEncAlg::A256GCM,
            ContentEncAlg::from("A128CBC-HS512"),
        ] {
            let k = key(32);
            assert_eq!(
                encrypt(&enc, &k, &IV, AAD, PLAINTEXT),
                Err(Error::UnsupportedAlgorithm),
                "{enc}"
            );
            let (result, n) = decrypt_counted(&enc, &k, &IV, AAD, &[0; 16], &[0; 16]);
            assert_eq!(result, Err(Error::UnsupportedAlgorithm), "{enc}");
            assert_eq!(n, 0, "{enc}");
        }
    }

    /// E = AES-CBC(ENC_KEY, IV, `blocks`) with no padding added, so the
    /// "plaintext" ends however the test chooses.
    fn cbc_raw(enc: &ContentEncAlg, k: &[u8], iv: &[u8], blocks: &[u8]) -> Vec<u8> {
        use cbc::cipher::block_padding::NoPadding;
        fn run<Enc: KeyIvInit + BlockModeEncrypt>(key: &[u8], iv: &[u8], blocks: &[u8]) -> Vec<u8> {
            Enc::new_from_slices(key, iv)
                .unwrap()
                .encrypt_padded_vec::<NoPadding>(blocks)
        }
        let enc_key = &k[k.len() / 2..];
        match enc {
            ContentEncAlg::A128CbcHs256 => run::<cbc::Encryptor<Aes128>>(enc_key, iv, blocks),
            ContentEncAlg::A192CbcHs384 => run::<cbc::Encryptor<Aes192>>(enc_key, iv, blocks),
            ContentEncAlg::A256CbcHs512 => run::<cbc::Encryptor<Aes256>>(enc_key, iv, blocks),
            _ => panic!("not A*CBC-HS*: {enc}"),
        }
    }

    /// `(E, T)` with a valid tag over an E whose decryption ends in
    /// `last_block`: forged under the known K, as only a key holder could.
    fn forge(enc: &ContentEncAlg, k: &[u8], last_block: [u8; 16]) -> (Vec<u8>, Vec<u8>) {
        let mut blocks = vec![0x42; 16];
        blocks.extend_from_slice(&last_block);
        let e = cbc_raw(enc, k, &IV, &blocks);
        let t_len = k.len() / 2;
        let t = full_mac(enc, k, &IV, AAD, &e)[..t_len].to_vec();
        (e, t)
    }

    #[test]
    fn a_padding_error_under_a_valid_tag_is_the_same_error_as_a_bad_tag() {
        // RFC 7516 §11.5 (and RFC 7518 §5.2.2.2 step 3): a padding failure
        // and a MAC failure must be indistinguishable to the sender. Here
        // the tag is valid, so decryption runs and unpadding fails.
        let bad_paddings = [
            ("last octet 0", {
                let mut b = [0x11; 16];
                b[15] = 0;
                b
            }),
            ("last octet 17", {
                let mut b = [0x11; 16];
                b[15] = 17;
                b
            }),
            ("last octet 0xff", [0xff; 16]),
            ("2 claimed, 1 present", {
                let mut b = [0x11; 16];
                b[15] = 2;
                b
            }),
            ("16 claimed, one 15", {
                let mut b = [16; 16];
                b[0] = 15;
                b
            }),
        ];
        for (enc, k_len, _) in ENCS {
            let k = key(k_len);
            let (e, t) = encrypt(&enc, &k, &IV, AAD, PLAINTEXT).unwrap();
            let mut bad_t = t.clone();
            bad_t[0] ^= 1;
            let (tag_error, n) = decrypt_counted(&enc, &k, &IV, AAD, &e, &bad_t);
            assert_eq!(n, 0, "{enc}");
            let tag_error = tag_error.unwrap_err();
            // The forgery itself is sound: a well-padded block decrypts.
            let (good_e, good_t) = forge(&enc, &k, [16; 16]);
            let (good, n) = decrypt_counted(&enc, &k, &IV, AAD, &good_e, &good_t);
            assert_eq!(&good.unwrap()[..], &[0x42; 16][..], "{enc}");
            assert_eq!(n, 1, "{enc}");
            for (what, last_block) in &bad_paddings {
                let (e, t) = forge(&enc, &k, *last_block);
                let (padding_error, n) = decrypt_counted(&enc, &k, &IV, AAD, &e, &t);
                assert_eq!(n, 1, "{enc} {what}: the tag was valid, so AES-CBC ran");
                let padding_error = padding_error.unwrap_err();
                assert_eq!(padding_error, tag_error, "{enc} {what}");
                assert_eq!(padding_error, Error::DecryptionFailed, "{enc} {what}");
                assert_eq!(padding_error.code(), tag_error.code(), "{enc} {what}");
                assert_eq!(
                    format!("{padding_error:?}"),
                    format!("{tag_error:?}"),
                    "{enc} {what}"
                );
                assert_eq!(
                    padding_error.to_string(),
                    tag_error.to_string(),
                    "{enc} {what}"
                );
            }
        }
    }

    #[test]
    fn an_authentic_e_that_is_not_whole_blocks_fails_like_the_rest() {
        // A PKCS #7 E is a non-empty multiple of the block size (RFC 7518
        // §5.2.2.1 step 3). With a valid tag over any other E, decryption
        // fails the same way as a padding or tag error.
        for (enc, k_len, t_len) in ENCS {
            let k = key(k_len);
            let (e, _) = encrypt(&enc, &k, &IV, AAD, PLAINTEXT).unwrap();
            for e in [&[][..], &e[..1], &e[..15], &e[..e.len() - 1]] {
                let t = full_mac(&enc, &k, &IV, AAD, e)[..t_len].to_vec();
                let (result, n) = decrypt_counted(&enc, &k, &IV, AAD, e, &t);
                assert_eq!(
                    result,
                    Err(Error::DecryptionFailed),
                    "{enc} E of {}",
                    e.len()
                );
                assert!(n <= 1, "{enc} E of {}", e.len());
            }
        }
    }

    #[test]
    fn wycheproof_aes_cbc_hmac_sha2_suites_conform_with_no_deviations() {
        // Wycheproof's `a*cbc_hs*_test.json` are written for exactly
        // RFC 7518 §5.2: K is MAC_KEY || ENC_KEY, the IV is 128 bits and the
        // tag is T_LEN octets. Every `valid` case must encrypt to its ct and
        // tag and decrypt back to its msg; every `invalid` case (all are
        // `ModifiedTag`) must be DecryptionFailed without reaching AES-CBC.
        use crate::test_support::wycheproof::{self, Expected, Outcome, Summary};
        for (name, enc) in [
            ("a128cbc_hs256", ContentEncAlg::A128CbcHs256),
            ("a192cbc_hs384", ContentEncAlg::A192CbcHs384),
            ("a256cbc_hs512", ContentEncAlg::A256CbcHs512),
        ] {
            let suite = wycheproof::load(name);
            let summary = wycheproof::assert_conforms(&suite, &[], |_, test| {
                let id = test.tc_id;
                let input = test.aead();
                let (result, n) = decrypt_counted(
                    &enc, &input.key, &input.iv, &input.aad, &input.ct, &input.tag,
                );
                match test.result {
                    Expected::Valid => {
                        let sealed = encrypt(&enc, &input.key, &input.iv, &input.aad, &input.msg);
                        assert_eq!(
                            sealed.as_ref().map(|(e, _)| e),
                            Ok(&input.ct),
                            "{name} tcId {id}: E"
                        );
                        assert_eq!(
                            sealed.as_ref().map(|(_, t)| t),
                            Ok(&input.tag),
                            "{name} tcId {id}: T"
                        );
                        if let Ok(plaintext) = &result {
                            assert_eq!(&plaintext[..], &input.msg[..], "{name} tcId {id}: P");
                        }
                    }
                    Expected::Invalid | Expected::Acceptable => {
                        if let Err(e) = &result {
                            assert_eq!(e, &Error::DecryptionFailed, "{name} tcId {id}");
                        }
                        if test.has_flag("ModifiedTag") {
                            assert_eq!(n, 0, "{name} tcId {id}: reached the cipher");
                        }
                    }
                }
                Outcome::of(&result)
            });
            assert_eq!(
                summary,
                Summary {
                    tests: 94,
                    accepted: 67,
                    rejected: 27,
                    deviations: 0,
                },
                "{name}"
            );
        }
    }

    mod properties {
        use proptest::prelude::*;

        use super::*;

        /// One of the three `enc` values with a K of its length.
        fn enc_and_key() -> impl Strategy<Value = (ContentEncAlg, Vec<u8>)> {
            (0..ENCS.len()).prop_flat_map(|i| {
                let (enc, k_len, _) = ENCS[i].clone();
                prop::collection::vec(any::<u8>(), k_len).prop_map(move |k| (enc.clone(), k))
            })
        }

        proptest! {
            // ADR 0008 layer 2: bounded case counts in the fast suite.
            #![proptest_config(ProptestConfig::with_cases(256))]

            /// RFC 7518 §5.2.2.1–§5.2.2.2: decryption inverts encryption
            /// for any K, IV, A and P; E is P padded to whole blocks and T
            /// is T_LEN octets. A tag one octet shorter or longer fails
            /// (§5.2.3–§5.2.5), as does any flipped bit of E, T, IV or A.
            #[test]
            fn round_trip_and_any_change_fails(
                (enc, k) in enc_and_key(),
                iv in any::<[u8; 16]>(),
                aad in prop::collection::vec(any::<u8>(), 0..80),
                plaintext in prop::collection::vec(any::<u8>(), 0..80),
                extra in any::<u8>(),
                flip in any::<(u8, prop::sample::Index)>(),
            ) {
                let (e, t) = encrypt(&enc, &k, &iv, &aad, &plaintext).unwrap();
                prop_assert_eq!(e.len(), (plaintext.len() / 16 + 1) * 16);
                prop_assert_eq!(t.len(), k.len() / 2);
                let opened = decrypt(&enc, &k, &iv, &aad, &e, &t).unwrap();
                prop_assert_eq!(&opened[..], &plaintext[..]);

                let failed = Err(Error::DecryptionFailed);
                prop_assert_eq!(decrypt(&enc, &k, &iv, &aad, &e, &t[..t.len() - 1]), failed.clone());
                let mut longer = t.clone();
                longer.push(extra);
                prop_assert_eq!(decrypt(&enc, &k, &iv, &aad, &e, &longer), failed.clone());

                let (bit, at) = flip;
                let mask = 1 << (bit % 8);
                let mut bad_e = e.clone();
                bad_e[at.index(e.len())] ^= mask;
                prop_assert_eq!(decrypt(&enc, &k, &iv, &aad, &bad_e, &t), failed.clone());
                let mut bad_t = t.clone();
                bad_t[at.index(t.len())] ^= mask;
                prop_assert_eq!(decrypt(&enc, &k, &iv, &aad, &e, &bad_t), failed.clone());
                let mut bad_iv = iv;
                bad_iv[at.index(16)] ^= mask;
                prop_assert_eq!(decrypt(&enc, &k, &bad_iv, &aad, &e, &t), failed.clone());
                if !aad.is_empty() {
                    let mut bad_aad = aad.clone();
                    bad_aad[at.index(aad.len())] ^= mask;
                    prop_assert_eq!(decrypt(&enc, &k, &iv, &bad_aad, &e, &t), failed);
                }
            }
        }
    }

    /// M, the full HMAC output over A || IV || E || AL (RFC 7518 §5.2.2.1
    /// step 5), for forging test inputs under a known K.
    fn full_mac(enc: &ContentEncAlg, k: &[u8], iv: &[u8], a: &[u8], e: &[u8]) -> Vec<u8> {
        fn run<M: Mac + KeyInit>(mac_key: &[u8], iv: &[u8], a: &[u8], e: &[u8]) -> Vec<u8> {
            let al = al(a.len()).unwrap();
            mac::<M>(mac_key, a, iv, e, &al)
                .unwrap()
                .finalize()
                .into_bytes()
                .to_vec()
        }
        let half = &k[..k.len() / 2];
        match enc {
            ContentEncAlg::A128CbcHs256 => run::<Hmac<Sha256>>(half, iv, a, e),
            ContentEncAlg::A192CbcHs384 => run::<Hmac<Sha384>>(half, iv, a, e),
            ContentEncAlg::A256CbcHs512 => run::<Hmac<Sha512>>(half, iv, a, e),
            _ => panic!("not A*CBC-HS*: {enc}"),
        }
    }
}
