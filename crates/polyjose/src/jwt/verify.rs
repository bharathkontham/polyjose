//! Verifying a signed JWT: ADR 0026 §2 steps 1–9 on the compact JWS, the
//! JWT header rules, key selection and the claims checks, in the
//! ADR 0027 §9 order (RFC 7519 §7.2).

use crate::error::{Error, Result};
use crate::header::Header;
use crate::jwa::SigningAlg;
use crate::jwk::{Jwk, JwkSet};

use super::{Claims, Policy};

/// The caller's verification keys: one key, or the issuer's JWK Set
/// (ADR 0029 §1).
///
/// Keys always come from the caller. A JWS header's `jwk`, `jku`, `x5u`
/// or `x5c` never supplies one, and `kid` only selects among the set's
/// members (RFC 8725 §3.10; ADR 0026 §2, ADR 0029 §2).
///
/// ```
/// use polyjose::jwk::Jwk;
/// use polyjose::jwt::Keys;
///
/// let key = Jwk::from_json(br#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#)?;
/// let keys: Keys<'_> = (&key).into();
/// assert!(matches!(keys, Keys::One(_)));
/// # Ok::<(), polyjose::Error>(())
/// ```
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum Keys<'a> {
    /// A single key. ADR 0026 §2 step 8 binds it to the header `alg`; its
    /// `kid` is not compared (ADR 0029 §1).
    One(&'a Jwk),
    /// A JWK Set (RFC 7517 §5): candidates are selected by `alg`, `use`,
    /// `key_ops` and `kid`, and tried in set order (ADR 0029 §2–§4).
    Set(&'a JwkSet),
}

impl<'a> From<&'a Jwk> for Keys<'a> {
    fn from(key: &'a Jwk) -> Self {
        Keys::One(key)
    }
}

impl<'a> From<&'a JwkSet> for Keys<'a> {
    fn from(set: &'a JwkSet) -> Self {
        Keys::Set(set)
    }
}

/// A verified, validated signed JWT (RFC 7519 §7.2).
///
/// `Debug` prints no key material: the claims and the header only.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct VerifiedJwt {
    /// The validated JWT Claims Set (RFC 7519 §4).
    pub claims: Claims,
    /// The JWS Protected Header (RFC 7515 §4), which the signature covers.
    /// A JWT is compact, so this is its whole JOSE Header (RFC 7515 §7.1).
    pub header: Header,
    /// The `alg` that verified (RFC 7515 §4.1.1), one of the policy's.
    pub alg: SigningAlg,
    /// The index in [`JwkSet::keys`] of the key that verified, with
    /// [`Keys::Set`]; `None` with [`Keys::One`] (ADR 0029 §4).
    pub key_index: Option<usize>,
    /// The `kid` of the key that verified, if it has one (RFC 7517 §4.5).
    pub kid: Option<String>,
}

/// Verifies the signed JWT `token` with `keys` and validates it against
/// `policy` (RFC 7519 §7.2; RFC 8725 §3; ADR 0027).
///
/// `token` must be a compact JWS (RFC 7519 §1, §7.2 step 1). A JWS JSON
/// serialization, or a five-part compact JWE (a nested JWT, see
/// [`decrypt_nested`](super::decrypt_nested)), fails with
/// [`Error::InvalidFormat`] (ADR 0027 §6–§7). Checks run in the
/// ADR 0027 §9 order and the first failure decides the error: the JWS
/// (ADR 0026 §2 steps 1–7), the JWT header rules, key selection, the
/// signature, then the claims, so a tampered payload is
/// [`Error::InvalidSignature`], never a claim error.
///
/// **Not implemented yet** (feature 0004 T07): returns
/// [`Error::UnsupportedAlgorithm`].
///
/// # Errors
///
/// Every stable code of ADR 0027 §9: [`Error::InvalidFormat`],
/// [`Error::InvalidJson`], [`Error::InvalidBase64`],
/// [`Error::InvalidHeader`], [`Error::UnknownCritical`],
/// [`Error::UnsupportedAlgorithm`], [`Error::AlgorithmNotAllowed`],
/// [`Error::NoMatchingKey`], [`Error::KeyAlgorithmMismatch`],
/// [`Error::InvalidKey`], [`Error::InvalidSignature`],
/// [`Error::InvalidClaim`], [`Error::TokenExpired`] and
/// [`Error::TokenNotYetValid`].
pub fn verify(token: &str, keys: Keys<'_>, policy: &Policy<'_>) -> Result<VerifiedJwt> {
    verify_inner(token, keys, policy)
}

/// The signed-JWT pipeline behind [`verify`], also run by the nested
/// verifier on the decrypted inner token (ADR 0027 §7, §9).
///
/// **Not implemented yet** (feature 0004 T07): returns
/// [`Error::UnsupportedAlgorithm`].
pub(crate) fn verify_inner(token: &str, keys: Keys<'_>, p: &Policy<'_>) -> Result<VerifiedJwt> {
    let _ = (token, keys, p);
    Err(Error::UnsupportedAlgorithm)
}
