//! Nested JWTs: a signed JWT encrypted as a compact JWE, at depth 1
//! (RFC 7519 §5.2, §7.1 step 5, §7.2 step 8, §11.2; RFC 8725 §3.3,
//! §3.11; ADR 0027 §7).

use crate::error::{Error, Result};
use crate::header::Header;
use crate::jwe::{DecryptPolicy, Encryptor};
use crate::jwk::Jwk;

use super::{Keys, Policy, VerifiedJwt};

/// A decrypted, verified and validated nested JWT (RFC 7519 §7.2).
///
/// `Debug` prints no key material and none of the decrypted inner token.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct VerifiedNestedJwt {
    /// The inner signed JWT, verified with the caller's keys and validated
    /// against the caller's policy (RFC 8725 §3.3).
    pub inner: VerifiedJwt,
    /// The outer JWE Protected Header (RFC 7516 §4), which the JWE's
    /// authentication tag covers. A JWT is compact, so this is the whole
    /// outer JOSE Header (RFC 7516 §7.1).
    pub outer_header: Header,
    /// The index of the JWE recipient that decrypted: always `0`, since a
    /// compact JWE has one recipient (RFC 7516 §7.1).
    pub recipient: usize,
}

/// Encrypts the signed JWT `signed_jwt` with `encryptor` as a compact JWE
/// whose protected header carries `cty: "JWT"` (RFC 7519 §5.2, §7.1
/// step 5): the sign-then-encrypt order of RFC 7519 §11.2.
///
/// **Not implemented yet** (feature 0004 T09): returns
/// [`Error::UnsupportedAlgorithm`].
///
/// # Errors
///
/// [`Error::InvalidFormat`] if `signed_jwt` is not a three-part compact
/// JWS; [`Error::InvalidHeader`] if the encryptor's protected header sets
/// a `cty` other than `JWT`; and the errors of
/// [`Encryptor::encrypt_compact`].
pub fn encrypt_nested(signed_jwt: &str, encryptor: &Encryptor) -> Result<String> {
    let _ = (signed_jwt, encryptor);
    Err(Error::UnsupportedAlgorithm)
}

/// Decrypts the nested JWT `token` with `decrypt_key` under
/// `decrypt_policy`, then verifies and validates the inner signed JWT
/// with `keys` and `policy` (RFC 7519 §7.2 step 8; RFC 8725 §3.3;
/// ADR 0027 §7, §9).
///
/// Both layers use the caller's keys and algorithms, and neither layer's
/// header selects the other's keys (RFC 8725 §3.3). The outer `cty` must
/// be `JWT` and is read, with `typ`, from the JWE Protected Header only
/// (ADR 0050 §3). The decrypted inner token is wiped after use.
///
/// **Not implemented yet** (feature 0004 T09): returns
/// [`Error::UnsupportedAlgorithm`].
///
/// # Errors
///
/// First the JWE errors of [`decrypt_compact`](crate::jwe::decrypt_compact)
/// (every failure after key management is [`Error::DecryptionFailed`]);
/// then [`Error::InvalidHeader`] for the outer `cty`/`typ`; then every
/// error of [`verify`](super::verify) for the inner token; then
/// [`Error::InvalidClaim`] if an `iss`, `sub` or `aud` replicated in the
/// outer header differs from the inner claim (RFC 7519 §5.3). A
/// three-part token is [`Error::InvalidFormat`].
pub fn decrypt_nested(
    token: &str,
    decrypt_key: &Jwk,
    decrypt_policy: &DecryptPolicy,
    keys: Keys<'_>,
    policy: &Policy<'_>,
) -> Result<VerifiedNestedJwt> {
    let _ = (token, decrypt_key, decrypt_policy, keys, policy);
    Err(Error::UnsupportedAlgorithm)
}
