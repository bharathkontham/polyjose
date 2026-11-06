//! The single-step Concat KDF of NIST SP 800-56A §5.8.1 with SHA-256, as
//! RFC 7518 §4.6.2 profiles it for ECDH-ES. polyjose's own composition on
//! `sha2` (ADR 0002), in the scope of the ADR 0019 §5 audit. Filled in by
//! T04.

use zeroize::Zeroizing;

use crate::{Error, Result};

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
    _z: &[u8],
    _alg_id: &str,
    _apu: &[u8],
    _apv: &[u8],
    _keydatalen_bits: u32,
) -> Result<Zeroizing<Vec<u8>>> {
    Err(Error::UnsupportedAlgorithm)
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
}
