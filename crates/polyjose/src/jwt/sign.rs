//! Issuing a signed JWT (RFC 7519 §7.1; ADR 0027 §8).

use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::header::Header;
use crate::json::{Object, Value};
use crate::jwa::SigningAlg;
use crate::jwk::Jwk;
use crate::jws::{ProtectedHeader, SignOptions, sign_compact};
use crate::util::b64url_encode;

use super::Claims;
use super::typ::{AT_JWT, JWT};

/// Header parameters a JWT issuer must not add through
/// [`IssueOptions::header_param`]:
///
/// - `b64`: "JSON Web Tokens MUST NOT use "b64" with a "false" value"
///   (RFC 7797 §7), and `true` is the default (RFC 7797 §3); ADR 0027 §6.
/// - `crit`: the only extension polyjose understands is `b64`, which a JWT
///   never uses, so no JWT needs `crit` (RFC 7515 §4.1.11; ADR 0027 §6).
/// - `cty`: belongs to nesting, where the JWE layer sets `"JWT"`
///   (RFC 7519 §5.2, §7.1 step 5); on a JWS, `cty: JWT` would be JWS-in-JWS
///   nesting, which is not supported (ADR 0027 §5).
/// - `zip`, `enc`: JWE parameters (RFC 7516 §4.1.2, §4.1.3), meaningless
///   in a JWS (ADR 0027 §8).
const FORBIDDEN_PARAMS: [&str; 5] = ["b64", "crit", "cty", "zip", "enc"];

/// Header parameters [`sign`] sets itself: `alg` from
/// [`IssueOptions::new`] (RFC 7515 §4.1.1), `typ` from the typ setters
/// (RFC 7519 §5.1) and `kid` from the key (RFC 7515 §4.1.4, ADR 0027 §8).
/// A second source would make the header ambiguous, and its names must be
/// unique (RFC 7515 §4).
const OWNED_PARAMS: [&str; 3] = ["alg", "typ", "kid"];

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

    /// Adds the header parameter `name` with the value `v` (RFC 7515
    /// §4.1–§4.3), after `alg`, `typ` and `kid`, in the order added.
    /// Setting a name again replaces its value and keeps its place.
    ///
    /// A registered parameter must have its registered JSON type, for
    /// example `jku` a string (RFC 7515 §4.1.2) and `x5c` an array of
    /// strings (§4.1.6).
    ///
    /// ```
    /// use polyjose::jwa::SigningAlg;
    /// use polyjose::jwt::IssueOptions;
    ///
    /// let opts = IssueOptions::new(SigningAlg::ES256).header_param("x-tenant", "a")?;
    /// assert!(IssueOptions::new(SigningAlg::ES256).header_param("crit", "b64").is_err());
    /// # let _ = opts;
    /// # Ok::<(), polyjose::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::InvalidHeader`]:
    ///
    /// - for a parameter a JWT must not carry or its issuer controls: `b64`
    ///   (RFC 7797 §7), `crit` (RFC 7515 §4.1.11), `cty` (RFC 7519 §5.2),
    ///   `zip` and `enc` (RFC 7516 §4.1.2–§4.1.3; ADR 0027 §6, §8);
    /// - for `alg`, `typ` and `kid`, which come from [`IssueOptions::new`],
    ///   the typ setters and the key (ADR 0027 §8);
    /// - for a registered parameter of the wrong JSON type (RFC 7515
    ///   §4.1).
    pub fn header_param(mut self, name: &str, v: impl Into<Value>) -> Result<Self> {
        if let Some(n) = FORBIDDEN_PARAMS.iter().find(|n| **n == name) {
            return Err(Error::InvalidHeader(n));
        }
        if let Some(n) = OWNED_PARAMS.iter().find(|n| **n == name) {
            return Err(Error::InvalidHeader(n));
        }
        let v = v.into();
        // RFC 7515 §4.1: type-check a registered parameter now, with the
        // header parser's own rules, so the error points at this call.
        let mut probe = Object::new();
        probe.insert(name, v.clone());
        Header::from_object(probe)?;
        self.params.insert(name, v);
        Ok(self)
    }

    /// The JWS Protected Header for `key` (RFC 7519 §7.1 step 3–4): `alg`,
    /// `typ`, `kid` copied from the key, then the extra members, written
    /// in exactly that order.
    ///
    /// [`ProtectedHeader::new`] would serialize in [`Header`]'s fixed
    /// order (`kid` before `typ`), so the JSON is written here and kept
    /// verbatim through [`ProtectedHeader::from_encoded`], which also
    /// re-checks every registered parameter (RFC 7515 §5.1 steps 3–4).
    fn protected_header(&self, kid: Option<&str>) -> Result<ProtectedHeader> {
        let mut header = Object::new();
        header.insert("alg", self.alg.as_str());
        if let Some(typ) = &self.typ {
            header.insert("typ", typ.as_str());
        }
        if let Some(kid) = kid {
            header.insert("kid", kid);
        }
        // `params` never holds `alg`, `typ` or `kid` (`header_param`
        // refuses them), so no member above is replaced.
        for (name, value) in &self.params {
            header.insert(name, value.clone());
        }
        let json = Zeroizing::new(header.to_json());
        ProtectedHeader::from_encoded(&b64url_encode(json.as_bytes()))
    }
}

/// Whether polyjose issues JWTs with `alg`, decided from the algorithm
/// alone, before the key is read (ADR 0027 §8).
///
/// Fail-closed: only the algorithms listed here are issued.
///
/// - HS256/384/512 (RFC 7518 §3.2), ES256/384/512 (RFC 7518 §3.4),
///   ES256K (RFC 8812 §3.2), EdDSA (RFC 8037 §3.1) and Ed25519
///   (RFC 9864 §2.2) → `Ok`.
/// - `none` → [`Error::AlgorithmNotAllowed`] (RFC 8725 §3.2, ADR 0007).
/// - RS256/384/512 and PS256/384/512 → [`Error::UnsupportedAlgorithm`]:
///   RSA private-key operations are not shipped (ADR 0021).
/// - Anything else → [`Error::UnsupportedAlgorithm`] (RFC 7515 §4.1.1).
fn check_issuable(alg: &SigningAlg) -> Result<()> {
    use SigningAlg as A;
    match alg {
        A::HS256
        | A::HS384
        | A::HS512
        | A::ES256
        | A::ES384
        | A::ES512
        | A::ES256K
        | A::EdDSA
        | A::Ed25519 => Ok(()),
        A::None => Err(Error::AlgorithmNotAllowed),
        _ => Err(Error::UnsupportedAlgorithm),
    }
}

/// Signs `claims` as a compact JWS with `key` (RFC 7519 §7.1), the
/// payload being the Claims Set's JSON (ADR 0027 §1).
///
/// - The JWS Protected Header is built by `opts` (see [`IssueOptions`]):
///   `alg`, `typ` (default `JWT`, RFC 7519 §5.1), `kid` copied from `key`
///   when it has one (ADR 0027 §8), then the extra members.
/// - The payload octets are exactly [`Claims::to_json`] of `claims`
///   (RFC 7519 §7.1 steps 1–2). No claim is added: `sign` never sets
///   `iat`, `exp` or `jti` itself (ADR 0027 §8).
/// - The signature comes from [`sign_compact`] (RFC 7515 §5.1, §7.1),
///   including its key binding (ADR 0026 §2 step 8).
///
/// ```
/// use polyjose::jwa::SigningAlg;
/// use polyjose::jwk::Jwk;
/// use polyjose::jwt::{self, Claims, IssueOptions, NumericDate};
///
/// // RFC 7515 Appendix A.1.1's HMAC key.
/// let key = Jwk::from_json(br#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#)?;
/// let mut claims = Claims::new();
/// claims.iss = Some("joe".into());
/// claims.exp = NumericDate::from_secs(1300819380);
/// let token = jwt::sign(&claims, &IssueOptions::new(SigningAlg::HS256), &key)?;
/// assert!(token.starts_with("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."));
/// # Ok::<(), polyjose::Error>(())
/// ```
///
/// **Secrets:** the Claims Set may be secret (ADR 0049 §4). Its JSON is
/// held in a wiping buffer while signing, but the returned token carries
/// it base64url-encoded, and wiping that `String` is the caller's job.
///
/// # Errors
///
/// In this order:
///
/// - [`Error::UnsupportedAlgorithm`] for RS256/384/512 and PS256/384/512,
///   before `key` is read: polyjose holds no RSA private keys (ADR 0021).
///   Also for an unknown algorithm (RFC 7515 §4.1.1).
/// - [`Error::AlgorithmNotAllowed`] for `none` (RFC 8725 §3.2).
/// - [`Error::KeyAlgorithmMismatch`] or [`Error::InvalidKey`] when `key`
///   cannot sign with the algorithm, including a public-only key
///   (ADR 0026 §2 step 8).
/// - [`Error::RandomnessUnavailable`] from hedged ECDSA signing
///   (ADR 0005, ADR 0026 §5).
pub fn sign(claims: &Claims, opts: &IssueOptions, key: &Jwk) -> Result<String> {
    // ADR 0021, ADR 0027 §8: decided by the algorithm alone, before any
    // key use (sign_compact would reject these too, after reading the key).
    check_issuable(&opts.alg)?;
    let protected = opts.protected_header(key.kid())?;
    // RFC 7519 §7.1 steps 1-2: the Claims Set's octets are the JWS Payload.
    // ADR 0049 §4: they may be secret, so they are wiped on drop.
    let payload = Zeroizing::new(claims.to_json());
    sign_compact(&protected, payload.as_bytes(), key, &SignOptions::new())
}
