//! The single-step Concat KDF of NIST SP 800-56A §5.8.1 with SHA-256, as
//! RFC 7518 §4.6.2 profiles it for ECDH-ES. polyjose's own composition on
//! `sha2` (ADR 0002), in the scope of the ADR 0019 §5 audit. Filled in by
//! T04.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{Error, Result};

/// The SHA-256 output length in octets, the Concat KDF block size
/// (NIST SP 800-56A §5.8.1.1, `hashlen`).
const HASH_LEN: usize = 32;

/// The largest keydatalen `derive` accepts, in bits: the 64-octet key of
/// direct ECDH-ES with A256CBC-HS512 (RFC 7518 §4.6.2, §5.2.5), the
/// longest key JWE derives. It bounds the block loop at two iterations.
pub(crate) const MAX_KEYDATALEN_BITS: u32 = 512;

/// Derives `keydatalen_bits` bits from the shared secret `z` (RFC 7518
/// §4.6.2):
///
/// `K(i) = SHA-256(be32(i) || Z || OtherInfo)` for i = 1, 2, …, truncated
/// to keydatalen, where `OtherInfo` is `be32(len) || AlgorithmID ||
/// be32(len) || apu || be32(len) || apv || be32(keydatalen_bits)` with an
/// empty SuppPrivInfo.
///
/// - `alg_id` is the `enc` value for direct ECDH-ES and the `alg` value
///   for ECDH-ES+A*KW (RFC 7518 §4.6.2).
/// - `apu` and `apv` are the base64url-decoded header values; an absent
///   value is passed as empty and encoded as a zero length.
///
/// # Errors
///
/// An error unless `keydatalen_bits` is a positive multiple of 8 and at
/// most 512.
pub(crate) fn derive(
    z: &[u8],
    alg_id: &str,
    apu: &[u8],
    apv: &[u8],
    keydatalen_bits: u32,
) -> Result<Zeroizing<Vec<u8>>> {
    // RFC 7518 §4.6.2: keydatalen is the number of bits of the key to
    // derive. JWE keys are whole octets, so it is a positive multiple of 8,
    // and no JWE algorithm needs more than MAX_KEYDATALEN_BITS. Rejecting
    // anything else keeps the loop below bounded.
    if keydatalen_bits == 0
        || !keydatalen_bits.is_multiple_of(8)
        || keydatalen_bits > MAX_KEYDATALEN_BITS
    {
        return Err(Error::UnsupportedAlgorithm);
    }
    let keydatalen =
        usize::try_from(keydatalen_bits / 8).map_err(|_| Error::UnsupportedAlgorithm)?;
    let other_info = other_info(alg_id, apu, apv, keydatalen_bits)?;

    let mut out = Zeroizing::new(Vec::with_capacity(keydatalen));
    // Each K(i) lands here, never in an unwiped temporary.
    let mut block = Zeroizing::new([0u8; HASH_LEN]);
    // NIST SP 800-56A §5.8.1.1 step 4: `counter` starts at 1 and is a
    // 32-bit big-endian integer.
    let mut counter: u32 = 1;
    while out.len() < keydatalen {
        // `sha2`'s `zeroize` feature (workspace Cargo.toml) wipes the
        // hasher, whose buffered block holds Z, when it is dropped.
        let mut hash = Sha256::new();
        hash.update(counter.to_be_bytes());
        hash.update(z);
        hash.update(&other_info);
        hash.finalize_into((&mut *block).into());
        // §5.8.1.1 steps 5–6: the leftmost keydatalen bits of
        // K(1) || … || K(reps); only the last block is truncated.
        let take = (keydatalen - out.len()).min(HASH_LEN);
        out.extend_from_slice(&block[..take]);
        // At most two blocks (MAX_KEYDATALEN_BITS), so this never overflows.
        counter += 1;
    }
    Ok(out)
}

/// Appends one NIST SP 800-56A §5.8.1.2 "Datalen || Data" field: a 32-bit
/// big-endian octet count, then the octets (RFC 7518 §4.6.2, AlgorithmID,
/// PartyUInfo and PartyVInfo).
///
/// # Errors
///
/// [`Error::InvalidFormat`] if `data` is longer than a 32-bit length can
/// state.
fn push_len_prefixed(out: &mut Vec<u8>, data: &[u8]) -> Result<()> {
    let len = u32::try_from(data.len())
        .map_err(|_| Error::InvalidFormat("Concat KDF input longer than 2^32 - 1 octets"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(data);
    Ok(())
}

/// The Concat KDF `OtherInfo` of RFC 7518 §4.6.2 (NIST SP 800-56A
/// §5.8.1.2, concatenation format):
///
/// `AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo || SuppPrivInfo`
///
/// - AlgorithmID, PartyUInfo and PartyVInfo are each a 32-bit big-endian
///   octet count followed by the octets: `alg_id` as UTF-8, then the
///   base64url-decoded `apu` and `apv`. An absent `apu`/`apv` is an empty
///   slice, which encodes as Datalen 0 and empty Data (RFC 7518 §4.6.2).
/// - SuppPubInfo is `keydatalen_bits` as a 32-bit big-endian integer.
/// - SuppPrivInfo is the empty octet sequence (RFC 7518 §4.6.2).
///
/// None of these inputs is secret, so the result is a plain `Vec`.
fn other_info(alg_id: &str, apu: &[u8], apv: &[u8], keydatalen_bits: u32) -> Result<Vec<u8>> {
    // Four 4-octet fields plus the three Data values.
    let capacity = 16_usize
        .saturating_add(alg_id.len())
        .saturating_add(apu.len())
        .saturating_add(apv.len());
    let mut out = Vec::with_capacity(capacity);
    push_len_prefixed(&mut out, alg_id.as_bytes())?;
    push_len_prefixed(&mut out, apu)?;
    push_len_prefixed(&mut out, apv)?;
    out.extend_from_slice(&keydatalen_bits.to_be_bytes());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7518 Appendix C: AlgorithmID, PartyUInfo, PartyVInfo and
    /// SuppPubInfo as printed there, concatenated (SuppPrivInfo is empty).
    #[test]
    fn other_info_matches_rfc7518_appendix_c() {
        let mut expected = Vec::new();
        expected.extend_from_slice(&[0, 0, 0, 7]);
        expected.extend_from_slice(b"A128GCM");
        expected.extend_from_slice(&[0, 0, 0, 5]);
        expected.extend_from_slice(b"Alice");
        expected.extend_from_slice(&[0, 0, 0, 3]);
        expected.extend_from_slice(b"Bob");
        expected.extend_from_slice(&[0, 0, 0, 128]);
        // The same bytes as the RFC prints them in decimal.
        assert_eq!(
            expected,
            [
                0, 0, 0, 7, 65, 49, 50, 56, 71, 67, 77, // AlgorithmID
                0, 0, 0, 5, 65, 108, 105, 99, 101, // PartyUInfo
                0, 0, 0, 3, 66, 111, 98, // PartyVInfo
                0, 0, 0, 128, // SuppPubInfo
            ]
        );
        assert_eq!(
            other_info("A128GCM", b"Alice", b"Bob", 128).unwrap(),
            expected
        );
    }

    /// An independent reference: the RFC 7518 §4.6.2 layout spelled out
    /// field by field, hashed with one explicit SHA-256 call per block and a
    /// literal big-endian counter (NIST SP 800-56A §5.8.1.1).
    fn reference(z: &[u8], alg_id: &str, apu: &[u8], apv: &[u8], bits: u32) -> Vec<u8> {
        let be32 = |n: usize| u32::try_from(n).unwrap().to_be_bytes();
        let info = [
            &be32(alg_id.len())[..],
            alg_id.as_bytes(),
            &be32(apu.len()),
            apu,
            &be32(apv.len()),
            apv,
            &bits.to_be_bytes(),
        ]
        .concat();
        let k1 = Sha256::digest([&[0, 0, 0, 1][..], z, &info].concat());
        let k2 = Sha256::digest([&[0, 0, 0, 2][..], z, &info].concat());
        let mut both = [k1.as_slice(), k2.as_slice()].concat();
        both.truncate(usize::try_from(bits / 8).unwrap());
        both
    }

    /// RFC 7518 Appendix C: the ECDH-ES shared secret Z of the printed
    /// P-256 keys (Alice's ephemeral `d` with Bob's public key).
    const APPENDIX_C_Z: [u8; 32] = [
        158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49, 110,
        163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196,
    ];

    /// RFC 7518 Appendix C: direct ECDH-ES with A128GCM, `apu` "Alice" and
    /// `apv` "Bob" derives `VqqN6vgjbSBcIijNcacQGg`.
    #[test]
    fn derive_matches_rfc7518_appendix_c() {
        let k = derive(&APPENDIX_C_Z, "A128GCM", b"Alice", b"Bob", 128).unwrap();
        assert_eq!(
            k.as_slice(),
            [
                86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26
            ]
        );
        assert_eq!(crate::util::b64url_encode(&k), "VqqN6vgjbSBcIijNcacQGg");
    }

    /// RFC 7518 §4.6.2: an absent `apu`/`apv` is a zero Datalen with an
    /// empty Data.
    #[test]
    fn other_info_encodes_absent_apu_apv_as_zero_length() {
        assert_eq!(
            other_info("ECDH-ES+A128KW", b"", b"", 128).unwrap(),
            [
                &[0, 0, 0, 14][..],
                b"ECDH-ES+A128KW",
                &[0, 0, 0, 0],
                &[0, 0, 0, 0],
                &[0, 0, 0, 128],
            ]
            .concat()
        );
        assert_eq!(
            other_info("A256GCM", b"", b"v", 256).unwrap(),
            [
                &[0, 0, 0, 7][..],
                b"A256GCM",
                &[0, 0, 0, 0],
                &[0, 0, 0, 1],
                b"v",
                &[0, 0, 1, 0]
            ]
            .concat()
        );
    }

    /// 512 bits (direct ECDH-ES with A256CBC-HS512) take two SHA-256 blocks,
    /// K(1) || K(2), with the counter incremented as a big-endian integer.
    #[test]
    fn derive_512_bits_concatenates_two_blocks_with_big_endian_counter() {
        let z = [0x5a; 32];
        let k = derive(&z, "A256CBC-HS512", b"Alice", b"Bob", 512).unwrap();
        assert_eq!(k.len(), 64);
        assert_eq!(
            k.as_slice(),
            reference(&z, "A256CBC-HS512", b"Alice", b"Bob", 512)
        );
        assert_ne!(k[..32], k[32..]);

        // The second block is keyed by 00 00 00 02, not a little-endian 2.
        let info = other_info("A256CBC-HS512", b"Alice", b"Bob", 512).unwrap();
        let be = Sha256::digest([&[0, 0, 0, 2][..], &z, &info].concat());
        let le = Sha256::digest([&[2, 0, 0, 0][..], &z, &info].concat());
        assert_eq!(&k[32..], be.as_slice());
        assert_ne!(&k[32..], le.as_slice());
    }

    /// 384 bits (A192CBC-HS384) truncate the second block to its leftmost
    /// 16 octets (NIST SP 800-56A §5.8.1.1 step 6).
    #[test]
    fn derive_384_bits_truncates_the_second_block() {
        let z = [0xa5; 48];
        let k = derive(&z, "A192CBC-HS384", b"", b"", 384).unwrap();
        assert_eq!(k.len(), 48);
        assert_eq!(k.as_slice(), reference(&z, "A192CBC-HS384", b"", b"", 384));
    }

    /// 256 bits are exactly K(1).
    #[test]
    fn derive_256_bits_is_one_block() {
        let z = [7; 66];
        let k = derive(&z, "ECDH-ES+A256KW", b"u", b"v", 256).unwrap();
        let info = other_info("ECDH-ES+A256KW", b"u", b"v", 256).unwrap();
        let k1 = Sha256::digest([&[0, 0, 0, 1][..], &z, &info].concat());
        assert_eq!(k.as_slice(), k1.as_slice());
    }

    /// Every allowed length, 8 to 512 bits in steps of 8, matches the
    /// reference and has keydatalen / 8 octets.
    #[test]
    fn derive_matches_reference_for_every_allowed_length() {
        let z: Vec<u8> = (0u8..32).collect();
        for bits in (8..=512).step_by(8) {
            let k = derive(&z, "A128GCM", b"Alice", b"Bob", bits).unwrap();
            assert_eq!(k.len(), usize::try_from(bits / 8).unwrap(), "{bits}");
            assert_eq!(
                k.as_slice(),
                reference(&z, "A128GCM", b"Alice", b"Bob", bits),
                "{bits}"
            );
        }
    }

    /// keydatalen is part of OtherInfo (SuppPubInfo), so a shorter key is
    /// not a prefix of a longer one (RFC 7518 §4.6.2).
    #[test]
    fn derive_binds_keydatalen() {
        let z = [1; 32];
        let short = derive(&z, "A128GCM", b"", b"", 128).unwrap();
        let long = derive(&z, "A128GCM", b"", b"", 256).unwrap();
        assert_ne!(short[..], long[..16]);
    }

    /// Absent `apu`/`apv` (empty slices) derive the same key as the
    /// zero-length layout, and a different key from a present value.
    #[test]
    fn derive_with_absent_apu_apv() {
        let z = APPENDIX_C_Z;
        let k = derive(&z, "A128GCM", b"", b"", 128).unwrap();
        assert_eq!(k.as_slice(), reference(&z, "A128GCM", b"", b"", 128));
        assert_ne!(k, derive(&z, "A128GCM", b"Alice", b"", 128).unwrap());
        assert_ne!(k, derive(&z, "A128GCM", b"", b"Bob", 128).unwrap());
    }

    /// keydatalen must be a positive multiple of 8 bits and at most 512
    /// (the largest key JWE derives: A256CBC-HS512, RFC 7518 §5.2.5), so
    /// the block loop runs at most twice.
    #[test]
    fn derive_rejects_keydatalen_outside_the_allowed_range() {
        let z = [1; 32];
        for bits in [
            0,
            1,
            7,
            9,
            127,
            129,
            511,
            513,
            520,
            1024,
            u32::MAX - 7,
            u32::MAX,
        ] {
            assert_eq!(
                derive(&z, "A128GCM", b"", b"", bits),
                Err(Error::UnsupportedAlgorithm),
                "{bits}"
            );
        }
        assert_eq!(MAX_KEYDATALEN_BITS, 512);
        assert!(derive(&z, "A128GCM", b"", b"", 8).is_ok());
        assert!(derive(&z, "A128GCM", b"", b"", 512).is_ok());
    }

    /// The hasher's buffered block holds Z, so it must wipe itself on drop:
    /// this fails to compile if `sha2`'s `zeroize` feature is ever dropped
    /// from the workspace manifest.
    #[test]
    fn sha256_state_is_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<Sha256>();
    }

    /// The output is `Zeroizing` and is allocated once at its final size: a
    /// reallocation would leave an unwiped copy of key bytes behind.
    #[test]
    fn derive_output_is_zeroizing_and_never_reallocated() {
        for bits in [8, 128, 256, 264, 384, 512] {
            let k: Zeroizing<Vec<u8>> = derive(&[3; 32], "A128GCM", b"", b"", bits).unwrap();
            assert_eq!(k.capacity(), k.len(), "{bits}");
        }
    }
}
