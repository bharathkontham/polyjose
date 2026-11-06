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
