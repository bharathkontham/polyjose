//! Explicit typing of JWTs: the `typ` values polyjose knows, and the RFC
//! 9068 access-token profile's required claims (RFC 7519 §5.1, RFC 8725
//! §3.11, RFC 9068 §2.1–§2.2; ADR 0027 §5).
//!
//! Use these with [`Policy::expect_typ`](super::Policy::expect_typ) and
//! [`IssueOptions::typ`](super::IssueOptions::typ). Other explicit types
//! (`secevent+jwt`, `logout+jwt`, `dpop+jwt`, …) are passed as strings.

use crate::error::{Error, Result};
use crate::header::Header;

use super::Policy;

/// `JWT`, the `typ` RFC 7519 §5.1 recommends for a generic JWT.
///
/// It is not an explicit type in the RFC 8725 §3.11 sense: under the
/// default [`TypMode`](super::TypMode) it is accepted like an absent `typ`
/// (ADR 0027 §5).
pub const JWT: &str = "JWT";

/// `at+jwt`, the `typ` of a JWT access token (RFC 9068 §2.1: "SHOULD be
/// `at+jwt`"). It compares equal to `application/at+jwt` and `at+JWT`
/// (RFC 7515 §4.1.9).
pub const AT_JWT: &str = "at+jwt";

/// The claims a JWT access token must carry (RFC 9068 §2.2), in the
/// ADR 0027 §9 J4 order: `iss`, `exp`, `aud`, `sub`, `client_id`, `iat`,
/// `jti`. [`Policy::access_token`](super::Policy::access_token) requires
/// every one of them.
pub const ACCESS_TOKEN_REQUIRED_CLAIMS: [&str; 7] =
    ["iss", "exp", "aud", "sub", "client_id", "iat", "jti"];

/// Which JOSE layer of a JWT a header belongs to (ADR 0027 §5–§7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Layer {
    /// The JWS of a signed JWT, or the inner JWS of a nested one.
    Signed,
    /// The outer JWE of a nested JWT (RFC 7519 §5.2, §7.2 step 8).
    Outer,
}

/// Whether `a` and `b` are the same media type as `typ` or `cty` values
/// (RFC 7515 §4.1.9–§4.1.10; RFC 7519 §7.3; ADR 0027 §5): a value without
/// `/` has `application/` prepended; the part before the first `;`
/// compares ASCII-case-insensitively, the parameters after it exactly.
///
/// **Not implemented yet** (feature 0004 T04): returns `false`.
pub(crate) fn media_type_eq(a: &str, b: &str) -> bool {
    let _ = (a, b);
    false
}

/// The JWT header rules of ADR 0027 §9 step J1 (and N1 for a nested
/// JWT's outer layer), for one JOSE layer.
///
/// `protected` is the integrity-protected header (the JWS or JWE
/// Protected Header). `unprotected` is any header of the same layer that
/// is not integrity-protected; compact serializations have none. `typ`
/// and `cty` are read from `protected` only (ADR 0049 §2, ADR 0050 §3).
///
/// - [`Layer::Signed`]: `b64: false` → [`Error::InvalidHeader`]
///   (RFC 7797 §7); `cty` equal to `JWT` (JWS-in-JWS nesting, not
///   supported) → `InvalidHeader`; then the policy's [`TypMode`]
///   (RFC 8725 §3.11–§3.12).
/// - [`Layer::Outer`]: `cty` must equal `JWT` (RFC 7519 §5.2), else
///   `InvalidHeader`; the outer `typ`, if present, must satisfy the same
///   `typ` policy (ADR 0027 §7).
/// - Both layers: an `unprotected` header that sets `typ` or `cty` →
///   `InvalidHeader`, even when `protected` is valid (ADR 0049 §2,
///   ADR 0050 §3).
///
/// [`TypMode`]: super::TypMode
///
/// **Not implemented yet** (feature 0004 T04): returns
/// [`Error::UnsupportedAlgorithm`].
pub(crate) fn check_jwt_header(
    protected: &Header,
    unprotected: Option<&Header>,
    p: &Policy<'_>,
    layer: Layer,
) -> Result<()> {
    let _ = (protected, unprotected, p, layer);
    Err(Error::UnsupportedAlgorithm)
}
