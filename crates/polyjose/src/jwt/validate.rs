//! Claims validation against the policy: steps J4–J10 of ADR 0027 §9
//! (RFC 7519 §4.1.1–§4.1.6; RFC 8725 §3.8–§3.9; RFC 9068 §2.2, §4).

use crate::error::{Error, Result};

use super::{Claims, Policy};

/// Validates `c` against `p`, in the ADR 0027 §9 order; the first failing
/// step decides the error:
///
/// - J4: required-claim presence, in the order `iss, sub, aud, exp, nbf,
///   iat, jti`, then the policy's other required names in order →
///   [`Error::InvalidClaim`];
/// - J5: `exp` (RFC 7519 §4.1.4) → [`Error::TokenExpired`];
/// - J6: `nbf` (RFC 7519 §4.1.5) → [`Error::TokenNotYetValid`];
/// - J7: `iat` with a maximum age (RFC 7519 §4.1.6) → `InvalidClaim`;
/// - J8–J10: `iss`, `sub`, `aud`, the last including a token `aud` with
///   no configured audience (RFC 7519 §4.1.1–§4.1.3) → `InvalidClaim`.
///
/// The clock is read (through the policy) only when a time check runs
/// (ADR 0028).
///
/// **Not implemented yet** (feature 0004 T06): returns
/// [`Error::UnsupportedAlgorithm`].
pub(crate) fn validate_claims(c: &Claims, p: &Policy<'_>) -> Result<()> {
    let _ = (c, p);
    Err(Error::UnsupportedAlgorithm)
}
