//! Verifying a signed JWT: ADR 0026 §2 steps 1–9 on the compact JWS, the
//! JWT header rules, key selection and the claims checks, in the
//! ADR 0027 §9 order (RFC 7519 §7.2).

#[cfg(doc)]
use crate::error::Error;
use crate::error::Result;
use crate::header::Header;
use crate::jwa::SigningAlg;
use crate::jwk::{Jwk, JwkSet};
use crate::jws::{FAMILIES, finish_compact, precheck_compact};

use super::keyset::select_and_verify;
use super::typ::{Layer, check_jwt_header};
use super::validate::validate_claims;
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
    /// The `kid` of the key that verified, if it has one (RFC 7517 §4.5):
    /// the selected set member's with [`Keys::Set`], or the single key's
    /// own with [`Keys::One`]. It is the key's, never the header's: a
    /// single key's `kid` is not compared with the header's (ADR 0029 §1),
    /// so the two may differ, and a key without one gives `None` whatever
    /// the header says. The header's `kid` is in [`header`](Self::header).
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
/// `typ`, `cty`, `kid` and `crit` are read from the JWS Protected Header
/// only, which the signature covers (ADR 0049 §2); a compact JWS has no
/// other header (RFC 7515 §7.1).
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
/// The token is parsed once, and the steps run in the ADR 0027 §9 order;
/// the first failure decides the error:
///
/// 1. **Steps 1–7** (ADR 0026 §2), with the policy's allow-list and input
///    limit: [`precheck_compact`]. Only the compact serialization is
///    accepted (RFC 7519 §1, §7.2 step 1); a JSON serialization or a
///    five-part JWE is [`Error::InvalidFormat`] (ADR 0027 §6–§7). `none`
///    is [`Error::AlgorithmNotAllowed`] (RFC 8725 §3.2).
/// 2. **J1**, the JWT header rules on the protected header
///    ([`check_jwt_header`], [`Layer::Signed`]): `b64: false`
///    (RFC 7797 §7), `cty: JWT` (RFC 7519 §5.2) and the `typ` policy
///    (RFC 8725 §3.11–§3.12). There is no unprotected header to pass: a
///    compact JWS has none (RFC 7515 §7.1, ADR 0049 §2).
/// 3. **J2 and steps 8–9**: with [`Keys::Set`], candidate selection by
///    `alg` and the protected `kid` and the bounded try-in-order
///    ([`select_and_verify`], ADR 0029); with [`Keys::One`], key binding
///    and the signature with that key alone ([`finish_compact`],
///    ADR 0026 §2 steps 8–9; its `kid` is not compared, ADR 0029 §1).
/// 4. **J3**, the Claims Set, parsed from the verified payload octets
///    (RFC 7519 §7.2 step 10; no second base64url decoding, erratum 8225):
///    [`Claims::from_json`]. Only now, after the signature, are the claims
///    looked at (ADR 0027 §9).
/// 5. **J4–J10**, the claim rules ([`validate_claims`]): presence, `exp`,
///    `nbf`, `iat`, `iss`, `sub`, `aud` (RFC 7519 §4.1, ADR 0027 §3–§4).
///
/// **Payload secrecy** (ADR 0049 §4): the payload stays in the verified
/// JWS's wiping buffer ([`Verified::payload`](crate::jws::Verified::payload)),
/// the claims are parsed from it by reference, and it is wiped when this
/// function returns, on success and on every error; no other copy of the
/// payload octets is made here.
///
/// # Errors
///
/// As [`verify`].
pub(crate) fn verify_inner(token: &str, keys: Keys<'_>, p: &Policy<'_>) -> Result<VerifiedJwt> {
    // Steps 1-7 (ADR 0026 §2): limits, compact shape, base64url, header
    // JSON and structure, crit, alg known, alg allowed. No key yet.
    let pre = precheck_compact(token, &p.verify_options())?;

    // J1 (ADR 0027 §5-§6): the JWT header rules, before any key is chosen.
    check_jwt_header(pre.header(), None, p, Layer::Signed)?;

    // J2 and steps 8-9: the key, then the signature.
    let (verified, key_index, kid) = match keys {
        Keys::One(key) => (finish_compact(&FAMILIES, &pre, key)?, None, key.kid()),
        Keys::Set(set) => {
            let (verified, index) = select_and_verify(&pre, set, p)?;
            let kid = set.keys().get(index).and_then(Jwk::kid);
            (verified, Some(index), kid)
        }
    };

    // J3 (RFC 7519 §7.2 step 10): parsed straight from the wiping buffer
    // (ADR 0049 §4); `verified` drops, and wipes it, on every path out.
    let claims = Claims::from_json(&verified.payload)?;

    // J4-J10 (ADR 0027 §3-§4).
    validate_claims(&claims, p)?;

    Ok(VerifiedJwt {
        claims,
        // RFC 7515 §7.1: the protected header is the whole JOSE Header.
        header: pre.header().clone(),
        alg: verified.alg.clone(),
        key_index,
        kid: kid.map(str::to_owned),
    })
}
