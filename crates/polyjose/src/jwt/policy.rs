//! The JWT validation policy: algorithms, clock, leeway, issuer, subject,
//! audience, required claims, `typ` and key-set bounds (RFC 7519 §4.1,
//! §7.2; RFC 8725 §3; ADR 0027 §3–§5, ADR 0028, ADR 0029 §4).

use core::fmt;

use crate::error::{Error, Result};
use crate::jwa::SigningAlg;
use crate::jws::VerifyOptions;

use super::clock::{Clock, now_checked};
use super::typ::{ACCESS_TOKEN_REQUIRED_CLAIMS, AT_JWT};

/// How the JWS Protected Header's `typ` is checked (RFC 7515 §4.1.9,
/// RFC 7519 §5.1, RFC 8725 §3.11–§3.12; ADR 0027 §5).
///
/// Values compare as media types: a value without `/` has `application/`
/// prepended, the type and subtype compare ASCII-case-insensitively, and
/// parameters after `;` exactly (RFC 7515 §4.1.9). So `at+jwt`,
/// `application/at+jwt` and `at+JWT` are equal.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum TypMode {
    /// `typ` absent or equal to [`JWT`](super::typ::JWT); any other value
    /// is rejected with [`Error::InvalidHeader`]. This keeps explicitly
    /// typed tokens (an `at+jwt` access token, a `secevent+jwt` event) out
    /// of generic validation (RFC 8725 §3.11–§3.12).
    #[default]
    Default,
    /// `typ` must be present and equal to this value (RFC 8725 §3.11),
    /// else [`Error::InvalidHeader`]. Set with
    /// [`Policy::expect_typ`].
    Exact(String),
    /// No `typ` check. Set with [`Policy::any_typ`]; this gives up the
    /// RFC 8725 §3.12 protection against cross-JWT confusion.
    Any,
}

/// How a JWT is validated: the caller's algorithm allow-list, clock and
/// claim rules (RFC 7519 §4.1, §7.2; RFC 8725 §3).
///
/// Built with [`Policy::new`] (or [`Policy::access_token`] for RFC 9068
/// access tokens) and the builder methods. The defaults are ADR 0027's:
///
/// | Setting | Default | Change with |
/// |---|---|---|
/// | `exp` | required (ADR 0007) | [`allow_missing_exp`](Self::allow_missing_exp) |
/// | leeway | 60 s, at most 600 s (RFC 7519 §4.1.4) | [`leeway`](Self::leeway) |
/// | issuer, subject | not checked | [`issuer`](Self::issuer), [`subject`](Self::subject) |
/// | audience | none accepted: a token **with** `aud` is rejected (RFC 7519 §4.1.3) | [`audience`](Self::audience), [`ignore_audience`](Self::ignore_audience) |
/// | `iat` | type only; future values accepted (erratum 7720) | [`max_age`](Self::max_age) |
/// | `typ` | absent or `JWT` ([`TypMode::Default`]) | [`expect_typ`](Self::expect_typ), [`any_typ`](Self::any_typ) |
/// | JWK Set candidates | at most 8 (ADR 0029 §4) | [`max_key_candidates`](Self::max_key_candidates) |
///
/// The policy borrows its clock and allow-list, like
/// [`VerifyOptions`] borrows its allow-list
/// (ADR 0028 §3). There is no `Default`: a policy without a clock or
/// algorithms cannot exist (ADR 0028 §3, RFC 8725 §3.1).
///
/// ```
/// use polyjose::jwa::SigningAlg;
/// use polyjose::jwt::{FixedClock, Policy};
///
/// let clock = FixedClock(1300819380);
/// let policy = Policy::new(&clock, &[SigningAlg::ES256])?
///     .issuer("https://issuer.example")
///     .audience("https://api.example")
///     .leeway(30)?;
/// # let _ = policy;
///
/// // `none` can never be allowed (RFC 8725 §3.1).
/// let err = Policy::new(&clock, &[SigningAlg::None]).unwrap_err();
/// assert_eq!(err, polyjose::Error::AlgorithmNotAllowed);
/// # Ok::<(), polyjose::Error>(())
/// ```
///
/// `Debug` prints the settings, and only the placeholder `dyn Clock` for
/// the clock: never the clock's time or other internals.
#[derive(Clone)]
pub struct Policy<'a> {
    clock: &'a dyn Clock,
    /// The allow-list and the input limit, checked by `VerifyOptions::new`.
    jws: VerifyOptions<'a>,
    leeway: u32,
    issuers: Vec<String>,
    audiences: Vec<String>,
    subject: Option<String>,
    max_age: Option<u32>,
    required: Vec<String>,
    require_exp: bool,
    ignore_audience: bool,
    typ: TypMode,
    max_key_candidates: usize,
}

impl<'a> Policy<'a> {
    /// The default [`leeway`](Self::leeway): 60 seconds (ADR 0007,
    /// ADR 0027 §3).
    pub const DEFAULT_LEEWAY: u32 = 60;

    /// The largest accepted [`leeway`](Self::leeway): 600 seconds, since
    /// the leeway is "usually no more than a few minutes" (RFC 7519
    /// §4.1.4, RFC 9068 §4; ADR 0027 §3).
    pub const MAX_LEEWAY: u32 = 600;

    /// The default [`max_key_candidates`](Self::max_key_candidates): 8
    /// (ADR 0029 §4).
    pub const DEFAULT_MAX_KEY_CANDIDATES: usize = 8;

    /// A policy reading the time from `clock` and accepting exactly the
    /// JWS algorithms in `allowed_algs` (RFC 8725 §3.1), with the defaults
    /// in the table above.
    ///
    /// # Errors
    ///
    /// [`Error::AlgorithmNotAllowed`] if `allowed_algs` is empty, or holds
    /// `none` (RFC 8725 §3.2, ADR 0007) or an
    /// [`Unknown`](SigningAlg::Unknown) value: the same rule as
    /// [`VerifyOptions::new`](crate::jws::VerifyOptions::new).
    pub fn new(clock: &'a dyn Clock, allowed_algs: &'a [SigningAlg]) -> Result<Self> {
        Ok(Self {
            clock,
            jws: VerifyOptions::new(allowed_algs)?,
            leeway: Self::DEFAULT_LEEWAY,
            issuers: Vec::new(),
            audiences: Vec::new(),
            subject: None,
            max_age: None,
            required: Vec::new(),
            require_exp: true,
            ignore_audience: false,
            typ: TypMode::Default,
            max_key_candidates: Self::DEFAULT_MAX_KEY_CANDIDATES,
        })
    }

    /// A policy for JWT access tokens, as a resource server validates them
    /// (RFC 9068 §4; ADR 0027 §5):
    ///
    /// - `typ` must be [`at+jwt`](super::typ::AT_JWT) (RFC 9068 §2.1, §4);
    /// - `iss` must equal one of `issuers` and `aud` contain one of
    ///   `audiences` (RFC 9068 §4);
    /// - every claim of
    ///   [`ACCESS_TOKEN_REQUIRED_CLAIMS`]
    ///   must be present (RFC 9068 §2.2);
    /// - the signature is always verified, and `none` is never accepted
    ///   (RFC 9068 §2.1, §4).
    ///
    /// The other settings keep their defaults.
    ///
    /// # Errors
    ///
    /// As [`Policy::new`]; then [`Error::InvalidClaim`]`("iss")` if
    /// `issuers` is empty and [`Error::InvalidClaim`]`("aud")` if
    /// `audiences` is empty (RFC 9068 §4 requires both checks).
    pub fn access_token(
        clock: &'a dyn Clock,
        allowed_algs: &'a [SigningAlg],
        issuers: &[&str],
        audiences: &[&str],
    ) -> Result<Self> {
        let policy = Self::new(clock, allowed_algs)?;
        if issuers.is_empty() {
            return Err(Error::InvalidClaim("iss"));
        }
        if audiences.is_empty() {
            return Err(Error::InvalidClaim("aud"));
        }
        let policy = ACCESS_TOKEN_REQUIRED_CLAIMS
            .iter()
            .fold(policy, |policy, claim| policy.require(claim));
        Ok(policy
            .issuers(issuers)
            .audiences(audiences)
            .expect_typ(AT_JWT))
    }

    /// Adds `iss` to the accepted issuers. Once any is set, `iss` is
    /// required and must equal one of them exactly, case-sensitively
    /// (RFC 7519 §4.1.1, §7.3; RFC 8725 §3.8; ADR 0027 §4).
    ///
    /// Binding keys to their issuer is the caller's job (RFC 8725 §3.8):
    /// pass that issuer's keys with its policy.
    pub fn issuer(mut self, iss: &str) -> Self {
        self.issuers.push(iss.to_owned());
        self
    }

    /// Adds every value of `iss` to the accepted issuers; see
    /// [`issuer`](Self::issuer).
    pub fn issuers(self, iss: &[&str]) -> Self {
        iss.iter().fold(self, |policy, iss| policy.issuer(iss))
    }

    /// Adds `aud` to the accepted audiences. Once any is set, `aud` is
    /// required and at least one of its values must equal one of them
    /// exactly (RFC 7519 §4.1.3; RFC 8725 §3.9; ADR 0027 §4).
    pub fn audience(mut self, aud: &str) -> Self {
        self.audiences.push(aud.to_owned());
        self
    }

    /// Adds every value of `aud` to the accepted audiences; see
    /// [`audience`](Self::audience).
    pub fn audiences(self, aud: &[&str]) -> Self {
        aud.iter().fold(self, |policy, aud| policy.audience(aud))
    }

    /// Requires `sub` to be present and equal to `sub` exactly
    /// (RFC 7519 §4.1.2; RFC 8725 §3.8; ADR 0027 §4). Setting it again
    /// replaces the expected subject.
    pub fn subject(mut self, sub: &str) -> Self {
        self.subject = Some(sub.to_owned());
        self
    }

    /// The clock skew allowed on `exp`, `nbf` and `iat`, in whole seconds
    /// (RFC 7519 §4.1.4–§4.1.5: "some small leeway"; ADR 0027 §3).
    /// Default [`DEFAULT_LEEWAY`](Self::DEFAULT_LEEWAY).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidClaim`]`("leeway")` above
    /// [`MAX_LEEWAY`](Self::MAX_LEEWAY).
    pub fn leeway(mut self, secs: u32) -> Result<Self> {
        if secs > Self::MAX_LEEWAY {
            return Err(Error::InvalidClaim("leeway"));
        }
        self.leeway = secs;
        Ok(self)
    }

    /// Requires `iat` and rejects a token issued more than `secs` seconds
    /// ago or in the future, each beyond the leeway (RFC 7519 §4.1.6;
    /// ADR 0027 §3). Without it, `iat` is only type-checked, and a future
    /// `iat` is accepted (reported erratum 7720 on RFC 7519).
    pub fn max_age(mut self, secs: u32) -> Self {
        self.max_age = Some(secs);
        self
    }

    /// Requires the claim `claim` to be present, with any JSON value
    /// (RFC 7519 §4: which claims are required "is context dependent";
    /// ADR 0027 §4). Requiring a name twice has no further effect.
    ///
    /// Presence is checked in the ADR 0027 §9 J4 order: the registered
    /// claims `iss, sub, aud, exp, nbf, iat, jti` first, then the other
    /// names in the order they were first required.
    pub fn require(mut self, claim: &str) -> Self {
        if !self.required.iter().any(|name| name == claim) {
            self.required.push(claim.to_owned());
        }
        self
    }

    /// Accepts a token without `exp`. **Weakens validation**: such a token
    /// never expires. An explicit opt-out of the ADR 0007 default, never a
    /// side effect (ADR 0027 §3). A present `exp` is still checked, and a
    /// [`require`](Self::require)`("exp")` still applies.
    pub fn allow_missing_exp(mut self) -> Self {
        self.require_exp = false;
        self
    }

    /// Accepts a token whose `aud` names someone else when no audience is
    /// configured. **Weakens validation** and departs from RFC 7519
    /// §4.1.3 ("the JWT MUST be rejected"): when one issuer serves several
    /// relying parties, a token meant for one is then accepted by all
    /// (RFC 8725 §3.9). Prefer [`audience`](Self::audience). Has no effect
    /// once an audience is configured (ADR 0027 §4).
    pub fn ignore_audience(mut self) -> Self {
        self.ignore_audience = true;
        self
    }

    /// Requires `typ` to be present and equal to `typ` as a media type
    /// ([`TypMode::Exact`]; RFC 8725 §3.11, RFC 7515 §4.1.9).
    pub fn expect_typ(mut self, typ: &str) -> Self {
        self.typ = TypMode::Exact(typ.to_owned());
        self
    }

    /// Skips the `typ` check ([`TypMode::Any`]). **Weakens validation**:
    /// explicitly typed tokens of another kind are then accepted as well
    /// (RFC 8725 §3.12).
    pub fn any_typ(mut self) -> Self {
        self.typ = TypMode::Any;
        self
    }

    /// The most JWK Set members that may be tried for one token. With more
    /// candidates, verification fails with [`Error::NoMatchingKey`] before
    /// any signature is computed, which bounds the work an unauthenticated
    /// token can cause (ADR 0029 §4). Default
    /// [`DEFAULT_MAX_KEY_CANDIDATES`](Self::DEFAULT_MAX_KEY_CANDIDATES).
    pub fn max_key_candidates(mut self, n: usize) -> Self {
        self.max_key_candidates = n;
        self
    }

    /// The largest compact token accepted, in bytes; longer input fails
    /// with [`Error::InvalidFormat`] before it is parsed (ADR 0026 §7).
    /// Default
    /// [`VerifyOptions::DEFAULT_MAX_INPUT_LEN`](crate::jws::VerifyOptions::DEFAULT_MAX_INPUT_LEN).
    pub fn max_input_len(mut self, n: usize) -> Self {
        self.jws = self.jws.max_input_len(n);
        self
    }
}

/// Read access for the verification pipeline (`typ.rs`, `keyset.rs`,
/// `validate.rs`, `verify.rs`, `nested.rs`).
impl<'a> Policy<'a> {
    /// The current time from the clock, in whole seconds, bounded to
    /// ±(2^53 − 1) (ADR 0028 §1). Read only when a time check runs.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidClaim`]`("clock")`, or the clock's own error.
    pub(crate) fn now(&self) -> Result<i64> {
        now_checked(self.clock)
    }

    /// The JWS options for the token's signature: the allow-list and
    /// [`max_input_len`](Self::max_input_len) (ADR 0026 §2, §7).
    pub(crate) fn verify_options(&self) -> VerifyOptions<'a> {
        self.jws
    }

    /// The allowed JWS algorithms, as given (RFC 8725 §3.1). Test-only:
    /// the pipeline reads them through [`verify_options`](Self::verify_options).
    #[cfg(test)]
    pub(crate) fn allowed_algs(&self) -> &'a [SigningAlg] {
        self.jws.allowed_algs()
    }

    /// The leeway in seconds, at most [`Policy::MAX_LEEWAY`].
    pub(crate) fn leeway_secs(&self) -> u32 {
        self.leeway
    }

    /// The accepted issuers; empty means `iss` is not checked.
    pub(crate) fn accepted_issuers(&self) -> &[String] {
        &self.issuers
    }

    /// The accepted audiences; empty means none is configured.
    pub(crate) fn accepted_audiences(&self) -> &[String] {
        &self.audiences
    }

    /// The expected subject, if any.
    pub(crate) fn expected_subject(&self) -> Option<&str> {
        self.subject.as_deref()
    }

    /// The maximum token age in seconds, if set (it makes `iat` required).
    pub(crate) fn max_age_secs(&self) -> Option<u32> {
        self.max_age
    }

    /// The names passed to [`require`](Self::require), in first-required
    /// order, without duplicates. Requirements implied by other settings
    /// (`exp` by default, `iss`/`sub`/`aud` once configured, `iat` with a
    /// maximum age) are not in this list.
    pub(crate) fn required_claims(&self) -> &[String] {
        &self.required
    }

    /// Whether `exp` is required (true unless
    /// [`allow_missing_exp`](Self::allow_missing_exp)).
    pub(crate) fn requires_exp(&self) -> bool {
        self.require_exp
    }

    /// Whether [`ignore_audience`](Self::ignore_audience) was called.
    pub(crate) fn ignores_audience(&self) -> bool {
        self.ignore_audience
    }

    /// The `typ` mode.
    pub(crate) fn typ_mode(&self) -> &TypMode {
        &self.typ
    }

    /// The JWK Set candidate bound (ADR 0029 §4).
    pub(crate) fn key_candidate_limit(&self) -> usize {
        self.max_key_candidates
    }
}

impl fmt::Debug for Policy<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Policy")
            .field("clock", &format_args!("dyn Clock"))
            .field("jws", &self.jws)
            .field("leeway", &self.leeway)
            .field("issuers", &self.issuers)
            .field("audiences", &self.audiences)
            .field("subject", &self.subject)
            .field("max_age", &self.max_age)
            .field("required", &self.required)
            .field("require_exp", &self.require_exp)
            .field("ignore_audience", &self.ignore_audience)
            .field("typ", &self.typ)
            .field("max_key_candidates", &self.max_key_candidates)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::MAX_SAFE_INTEGER;
    use crate::jwt::FixedClock;

    const CLOCK: FixedClock = FixedClock(1_300_819_380);
    const ES256: &[SigningAlg] = &[SigningAlg::ES256];

    fn policy() -> Policy<'static> {
        Policy::new(&CLOCK, ES256).unwrap()
    }

    #[test]
    fn new_refuses_lists_that_verify_nothing_or_none() {
        // RFC 8725 §3.1–§3.2, the VerifyOptions::new rule (ADR 0026 §2 step 7).
        let unknown = [SigningAlg::Unknown("XS999".into())];
        let with_none = [SigningAlg::HS256, SigningAlg::None];
        for algs in [&[][..], &[SigningAlg::None], &unknown, &with_none] {
            assert_eq!(
                Policy::new(&CLOCK, algs).err(),
                Some(Error::AlgorithmNotAllowed),
                "{algs:?}"
            );
        }
        assert!(Policy::new(&CLOCK, &[SigningAlg::HS256, SigningAlg::EdDSA]).is_ok());
    }

    #[test]
    fn defaults_are_adr_0027() {
        let p = policy();
        assert!(p.requires_exp());
        assert_eq!(p.leeway_secs(), 60);
        assert_eq!(p.typ_mode(), &TypMode::Default);
        assert!(p.accepted_issuers().is_empty());
        assert!(p.accepted_audiences().is_empty());
        assert_eq!(p.expected_subject(), None);
        assert_eq!(p.max_age_secs(), None);
        assert!(p.required_claims().is_empty());
        assert!(!p.ignores_audience());
        assert_eq!(p.key_candidate_limit(), 8);
        assert_eq!(p.allowed_algs(), ES256);
        assert_eq!(p.verify_options().allowed_algs(), ES256);
        let jws = format!("{:?}", p.verify_options());
        assert!(jws.contains("max_input_len: 1048576"), "{jws}");
        assert_eq!(p.now(), Ok(1_300_819_380));
    }

    #[test]
    fn leeway_is_capped_at_600_seconds() {
        assert_eq!(policy().leeway(600).map(|p| p.leeway_secs()), Ok(600));
        assert_eq!(policy().leeway(0).map(|p| p.leeway_secs()), Ok(0));
        assert_eq!(
            policy().leeway(601).err(),
            Some(Error::InvalidClaim("leeway"))
        );
        assert_eq!(
            policy().leeway(u32::MAX).err(),
            Some(Error::InvalidClaim("leeway"))
        );
    }

    #[test]
    fn builders_set_what_they_name() {
        let p = policy()
            .issuer("https://a")
            .issuers(&["https://b", "https://c"])
            .audience("api")
            .audiences(&["web"])
            .subject("bob")
            .subject("alice")
            .max_age(300)
            .require("client_id")
            .require("jti")
            .require("client_id")
            .allow_missing_exp()
            .ignore_audience()
            .max_key_candidates(2)
            .max_input_len(4096);
        assert_eq!(
            p.accepted_issuers(),
            ["https://a", "https://b", "https://c"]
        );
        assert_eq!(p.accepted_audiences(), ["api", "web"]);
        assert_eq!(p.expected_subject(), Some("alice"));
        assert_eq!(p.max_age_secs(), Some(300));
        assert_eq!(p.required_claims(), ["client_id", "jti"]);
        assert!(!p.requires_exp());
        assert!(p.ignores_audience());
        assert_eq!(p.key_candidate_limit(), 2);
        let jws = format!("{:?}", p.verify_options());
        assert!(jws.contains("max_input_len: 4096"), "{jws}");
    }

    #[test]
    fn typ_modes() {
        assert_eq!(
            policy().expect_typ("secevent+jwt").typ_mode(),
            &TypMode::Exact("secevent+jwt".into())
        );
        assert_eq!(policy().any_typ().typ_mode(), &TypMode::Any);
        assert_eq!(
            policy().any_typ().expect_typ("x").typ_mode(),
            &TypMode::Exact("x".into())
        );
    }

    #[test]
    fn access_token_sets_the_rfc_9068_requirements() {
        let p = Policy::access_token(&CLOCK, ES256, &["https://as"], &["https://rs"]).unwrap();
        assert_eq!(p.typ_mode(), &TypMode::Exact("at+jwt".into()));
        assert_eq!(
            p.required_claims(),
            ["iss", "exp", "aud", "sub", "client_id", "iat", "jti"]
        );
        assert_eq!(p.accepted_issuers(), ["https://as"]);
        assert_eq!(p.accepted_audiences(), ["https://rs"]);
        assert!(p.requires_exp());
        assert!(!p.ignores_audience());
        assert_eq!(p.leeway_secs(), 60);
        assert_eq!(p.allowed_algs(), ES256);
    }

    #[test]
    fn access_token_needs_algorithms_issuers_and_audiences() {
        let none = [SigningAlg::None];
        assert_eq!(
            Policy::access_token(&CLOCK, &none, &[], &[]).err(),
            Some(Error::AlgorithmNotAllowed)
        );
        assert_eq!(
            Policy::access_token(&CLOCK, ES256, &[], &["https://rs"]).err(),
            Some(Error::InvalidClaim("iss"))
        );
        assert_eq!(
            Policy::access_token(&CLOCK, ES256, &["https://as"], &[]).err(),
            Some(Error::InvalidClaim("aud"))
        );
    }

    #[test]
    fn now_rejects_a_clock_out_of_range() {
        let late = FixedClock(MAX_SAFE_INTEGER + 1);
        let p = Policy::new(&late, ES256).unwrap();
        assert_eq!(p.now(), Err(Error::InvalidClaim("clock")));
    }

    #[test]
    fn debug_shows_no_clock_internals() {
        let clock = FixedClock(987_654_321);
        let p = Policy::new(&clock, ES256).unwrap().issuer("https://a");
        let debug = format!("{p:?}");
        assert!(!debug.contains("987654321"), "{debug}");
        assert!(!debug.contains("FixedClock"), "{debug}");
        assert!(debug.starts_with("Policy { clock: dyn Clock, "), "{debug}");
        assert!(debug.contains("https://a"), "{debug}");
        let alternate = format!("{p:#?}");
        assert!(!alternate.contains("987654321"), "{alternate}");
    }

    #[test]
    fn policy_is_send_and_sync() {
        fn shared<T: Send + Sync>(_: &T) {}
        shared(&policy());
    }
}
