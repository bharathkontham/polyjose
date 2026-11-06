//! Explicit typing of JWTs: the `typ` values polyjose knows, and the RFC
//! 9068 access-token profile's required claims (RFC 7519 §5.1, RFC 8725
//! §3.11, RFC 9068 §2.1–§2.2; ADR 0027 §5).
//!
//! Use these with [`Policy::expect_typ`](super::Policy::expect_typ) and
//! [`IssueOptions::typ`](super::IssueOptions::typ). Other explicit types
//! (`secevent+jwt`, `logout+jwt`, `dpop+jwt`, …) are passed as strings.

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
