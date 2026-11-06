//! Issuing a signed JWT (RFC 7519 §7.1; ADR 0027 §8).

use crate::error::{Error, Result};
use crate::json::{Object, Value};
use crate::jwa::SigningAlg;
use crate::jwk::Jwk;

use super::Claims;
use super::typ::{AT_JWT, JWT};

/// How [`sign`] builds the JWS Protected Header of a JWT (RFC 7519 §5,
/// §7.1).
///
/// The header is `alg`, then `typ` (default [`JWT`], RFC 7519 §5.1),
/// then `kid` copied from the key when it has one (ADR 0027 §8), then any
/// extra members.
///
/// ```
/// use polyjose::jwa::SigningAlg;
/// use polyjose::jwt::IssueOptions;
///
/// let generic = IssueOptions::new(SigningAlg::ES256);
/// let access_token = IssueOptions::new(SigningAlg::ES256).access_token();
/// let untyped = IssueOptions::new(SigningAlg::EdDSA).no_typ();
/// # let _ = (generic, access_token, untyped);
/// ```
#[derive(Debug, Clone)]
pub struct IssueOptions {
    alg: SigningAlg,
    typ: Option<String>,
    params: Object,
}

impl IssueOptions {
    /// Options signing with `alg` (RFC 7515 §4.1.1) and `typ` set to
    /// [`JWT`] (RFC 7519 §5.1).
    pub fn new(alg: SigningAlg) -> Self {
        Self {
            alg,
            typ: Some(JWT.to_owned()),
            params: Object::new(),
        }
    }

    /// Sets `typ` to `t`, an explicit type such as `secevent+jwt`
    /// (RFC 7515 §4.1.9, RFC 8725 §3.11).
    pub fn typ(mut self, t: &str) -> Self {
        self.typ = Some(t.to_owned());
        self
    }

    /// Omits `typ` (it is OPTIONAL, RFC 7519 §5.1).
    pub fn no_typ(mut self) -> Self {
        self.typ = None;
        self
    }

    /// Sets `typ` to [`at+jwt`](super::typ::AT_JWT), for a JWT access
    /// token (RFC 9068 §2.1).
    pub fn access_token(self) -> Self {
        self.typ(AT_JWT)
    }

    /// Adds the header parameter `name` (RFC 7515 §4.2–§4.3).
    ///
    /// **Not implemented yet** (feature 0004 T08): returns
    /// [`Error::UnsupportedAlgorithm`].
    ///
    /// # Errors
    ///
    /// [`Error::InvalidHeader`] for a parameter the JWT issuer controls or
    /// a JWT must not carry: `b64` (RFC 7797 §7), `crit`, `cty`
    /// (RFC 7519 §5.2), `zip` and `enc` (ADR 0027 §6, §8).
    pub fn header_param(self, name: &str, v: impl Into<Value>) -> Result<Self> {
        let _ = (self.alg, self.typ, self.params, name, v.into());
        Err(Error::UnsupportedAlgorithm)
    }
}

/// Signs `claims` as a compact JWS with `key` (RFC 7519 §7.1), the
/// payload being the Claims Set's JSON (ADR 0027 §1).
///
/// No claim is added: `sign` never sets `iat`, `exp` or `jti` itself
/// (ADR 0027 §8).
///
/// **Not implemented yet** (feature 0004 T08): returns
/// [`Error::UnsupportedAlgorithm`].
///
/// # Errors
///
/// [`Error::UnsupportedAlgorithm`] for RS256/384/512 and PS256/384/512:
/// polyjose holds no RSA private keys (ADR 0021). [`Error::AlgorithmNotAllowed`]
/// for `none` (RFC 8725 §3.2). [`Error::KeyAlgorithmMismatch`] or
/// [`Error::InvalidKey`] when `key` cannot sign with the algorithm
/// (ADR 0026 §2 step 8).
pub fn sign(claims: &Claims, opts: &IssueOptions, key: &Jwk) -> Result<String> {
    let _ = (claims, opts, key);
    Err(Error::UnsupportedAlgorithm)
}
