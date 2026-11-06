//! ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A192KW and ECDH-ES+A256KW (RFC 7518
//! §4.6) on P-256/384/521 (`ecdh_nist`) and X25519 (`ecdh_x25519`, RFC 8037
//! §3.2), with the Concat KDF (`concat_kdf`, §4.6.2). The `epk` is
//! validated before any agreement (RFC 8725 §3.4). Filled in by T13.

use super::api::DecryptPolicy;
use super::content::Cek;
use super::key::RecipientKey;
use super::keymgmt::{KeyOutput, RecipientOptions};
use super::random::RandomSource;
use crate::header::Header;
use crate::jwa::{ContentEncAlg, KeyMgmtAlg};
use crate::{Error, Result};

/// Key management on encrypt (RFC 7516 §5.1 steps 3–7) for ECDH-ES and ECDH-ES+A*KW.
///
/// # Errors
///
/// An error for `apu` equal to `apv` (RFC 7518 §4.6.2); `RandomnessUnavailable` if `rng` fails.
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

/// Key management on decrypt (RFC 7516 §5.2 steps 6–12) for ECDH-ES and ECDH-ES+A*KW: the
/// CEK, which must have the length `enc` requires (§5.2 step 9).
///
/// # Errors
///
/// An error for a missing or invalid `epk` (wrong curve, private members, off-curve, identity, low order), a non-empty encrypted key for direct ECDH-ES (RFC 7516 §5.2 step 10), or a failed unwrap. `core` reports every error from here as `DecryptionFailed`.
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
