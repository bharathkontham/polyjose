//! RSA-OAEP-256 (RFC 7518 §4.3): RSAES-OAEP with SHA-256 and MGF1 with
//! SHA-256, to an RSA public key of at least 2048 bits. **Encryption
//! only** (ADR 0021): polyjose performs no RSA private-key operation, so
//! the dispatcher in `keymgmt` answers RSA-OAEP-256 on the receiving side
//! with `UnsupportedAlgorithm` itself and never reaches this file. The OAEP
//! seed comes from `RandomSource::crypto_rng`. Filled in by T11.

use super::content::Cek;
use super::key::RecipientKey;
use super::keymgmt::{KeyOutput, RecipientOptions};
use super::random::RandomSource;
use crate::jwa::{ContentEncAlg, KeyMgmtAlg};
use crate::{Error, Result};

/// Key management on encrypt (RFC 7516 §5.1 steps 3–7) for RSA-OAEP-256.
///
/// # Errors
///
/// An error for a key that is not an RSA public key of at least 2048 bits; `RandomnessUnavailable` if `rng` fails.
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
