//! JWT operations (ADR 0030 §4, "JWT"; RFC 7519, RFC 8725, RFC 9068; ADR 0027 policy and error
//! order, ADR 0028 clock, ADR 0029 JWK Set selection, ADR 0052).
//!
//! One key or a JWK Set is chosen by which function is called (`jwt_verify` or
//! `jwt_verify_with_jwks`), and signed and nested JWTs have separate entry points (ADR 0027 §7,
//! ADR 0030 §4). Claims are JSON text, written back by the core with registered claims first
//! (ADR 0027 §1).
//!
//! **The clock (ADR 0030 §4, ADR 0028 §4):** an explicit `now` always wins. Without one, the
//! surface reads the platform clock where the core has one (`SystemClock`); on
//! `wasm32-unknown-unknown`, where it does not, a missing `now` fails with `InvalidClaim`,
//! never a panic (the JS facade always passes `now`).

use polyjose::Error;
use polyjose::header::Header;
use polyjose::json::{self, Object};
use polyjose::jwa::{ContentEncAlg, KeyMgmtAlg, SigningAlg};
use polyjose::jwe::{DecryptPolicy, Encryptor, Recipient};
use polyjose::jwk::{Jwk, JwkSet};
use polyjose::jwt::{
    self, Claims, Clock, FixedClock, IssueOptions, Keys, Policy, VerifiedJwt, VerifiedNestedJwt,
};

use crate::error::SurfaceResult;
use crate::records::{
    JweDecryptOptions, JweEncryptOptions, JweRecipient, JwtNestedVerified, JwtSignOptions,
    JwtVerified, JwtVerifyOptions, algs, apply, apply_flag, strs, to_usize, try_apply,
};

/// Signs the JWT Claims Set `claims` (JSON text) with `key` into a compact JWS (ADR 0030 §4;
/// RFC 7519 §7.1). RS*/PS* signing fails with `UnsupportedAlgorithm` (ADR 0021).
///
/// The steps run in the conformance order (conformance/README.md, "Step order"): import `key`
/// (RFC 7517 §4), parse `claims` (RFC 7519 §4; ADR 0027 §1–§2), build the core
/// `IssueOptions` from `options`, then the core's [`jwt::sign`]. The header holds `alg`, `typ`
/// (the core default `JWT` when `typ` is `None`, RFC 7519 §5.1), the key's `kid`, then the
/// `header` members in the caller's order (ADR 0027 §8).
///
/// `typ`, `omit_typ` and `access_token` each choose the `typ`, so at most one may be set:
/// `typ` with either of the others fails with `InvalidHeader` (ADR 0030 §4), and so do
/// `omit_typ` with `access_token`, which contradict each other the same way.
///
/// # Errors
///
/// The core's, from the key, the claims, `header_param` (`b64`, `crit`, `cty`, `alg`, `typ`,
/// `kid` and mistyped registered members are `InvalidHeader`, ADR 0027 §6, §8) and signing; a
/// `header` that is not a JSON object is `InvalidJson`.
pub fn jwt_sign(claims: &str, key: &str, options: &JwtSignOptions) -> SurfaceResult<String> {
    let key = Jwk::from_json(key.as_bytes())?;
    let claims = Claims::from_json(claims.as_bytes())?;
    let issue = issue_options(options)?;
    Ok(jwt::sign(&claims, &issue, &key)?)
}

/// Verifies and validates the signed JWT `token` with one `key` (ADR 0030 §4; RFC 7519 §7.2,
/// RFC 8725 §3; ADR 0027 §9 error order).
///
/// The steps run in the conformance order (conformance/README.md, "Step order"), and the first
/// failure is the error: import `key` (RFC 7517 §4), then build the policy from `options`
/// (the allow-list first, then the other members, ADR 0030 §4), then the core's
/// [`jwt::verify`]. So a bad option is reported before anything in `token` is read (0004
/// implementer note 7). A JWE or a JSON serialization fails with `InvalidFormat`
/// (ADR 0027 §7). [`JwtVerified::key_index`] is `None`: a single key is not a set
/// (ADR 0029 §4).
///
/// # Errors
///
/// The core's: every code of ADR 0027 §9, plus `InvalidHeader` for `typ` together with
/// `any_typ` and `UnsupportedAlgorithm` for an unknown `profile` (ADR 0030 §4).
pub fn jwt_verify(
    token: &str,
    key: &str,
    options: &JwtVerifyOptions,
) -> SurfaceResult<JwtVerified> {
    let key = Jwk::from_json(key.as_bytes())?;
    let v = with_policy(options, |policy| {
        jwt::verify(token, Keys::One(&key), policy)
    })?;
    Ok(verified(v)?)
}

/// Verifies and validates the signed JWT `token` against the JWK Set `jwks` (ADR 0030 §4;
/// RFC 7519 §7.2, RFC 7517 §5; ADR 0029). No candidate fails with `NoMatchingKey`
/// (ADR 0029 §4).
///
/// As [`jwt_verify`], with the set imported by the core (RFC 7517 §5: an invalid member is
/// skipped; an RSA private member fails the whole set with `UnsupportedAlgorithm`, ADR 0021,
/// ADR 0029 §3). [`JwtVerified::key_index`] is the verifying member's position in the set,
/// `Some(0)` for the first (ADR 0029 §4).
///
/// # Errors
///
/// As [`jwt_verify`], plus `NoMatchingKey` for no candidate or more than
/// `max_key_candidates` (ADR 0029 §4).
pub fn jwt_verify_with_jwks(
    token: &str,
    jwks: &str,
    options: &JwtVerifyOptions,
) -> SurfaceResult<JwtVerified> {
    let set = JwkSet::from_json(jwks.as_bytes())?;
    let v = with_policy(options, |policy| {
        jwt::verify(token, Keys::Set(&set), policy)
    })?;
    Ok(verified(v)?)
}

/// Encrypts the signed JWT `signed_jwt` into a compact JWE for exactly one recipient, with
/// `cty: "JWT"` set by the core (ADR 0030 §4; RFC 7519 §5.2, §11.2).
///
/// `options` becomes a core `Encryptor` member by member (ADR 0030 §3: `None`/`false` calls
/// nothing), then the core's [`jwt::encrypt_nested`] checks and encrypts.
///
/// # Errors
///
/// The core's: `InvalidKey` and the other JWK errors for a recipient key; `InvalidJson` or
/// `InvalidHeader` for a header; `InvalidFormat` unless `signed_jwt` is a signed compact JWS,
/// or unless there is exactly one recipient and no unprotected header or `aad` (RFC 7516
/// §7.1); `InvalidHeader` for a `cty` other than `JWT` or for compression (RFC 8725 §3.6);
/// `AlgorithmNotAllowed` for an inner `alg: none`; then the JWE errors.
pub fn jwt_encrypt_nested(signed_jwt: &str, options: &JweEncryptOptions) -> SurfaceResult<String> {
    let encryptor = encryptor(options)?;
    Ok(jwt::encrypt_nested(signed_jwt, &encryptor)?)
}

/// Decrypts the nested JWT `token` with `decrypt_key`, then verifies and validates the inner
/// JWT with one `key` (ADR 0030 §4; RFC 7519 §5.2, §7.2 step 8; RFC 8725 §3.3).
///
/// The steps run in the conformance order (conformance/README.md, "Step order"): import
/// `decrypt_key`, build the JWE policy from `decrypt_options`, import `key`, build the JWT
/// policy from `options` as for [`jwt_verify`], then the core's [`jwt::decrypt_nested`]. So
/// every option is checked before `token` is read (0004 implementer note 7). The decrypt key is
/// parsed into the core's `Jwk`, which wipes itself on drop, like every key (ADR 0030 §7).
///
/// # Errors
///
/// The core's: a three-part token or a JSON serialization is `InvalidFormat`; then the JWE
/// errors (every failure after key management is `DecryptionFailed`), the outer `cty`/`typ`
/// rules (`InvalidHeader`), every error of [`jwt_verify`] for the inner JWT, and
/// `InvalidClaim` for a replicated `iss`/`sub`/`aud` that differs (RFC 7519 §5.3).
pub fn jwt_decrypt_nested(
    token: &str,
    decrypt_key: &str,
    decrypt_options: &JweDecryptOptions,
    key: &str,
    options: &JwtVerifyOptions,
) -> SurfaceResult<JwtNestedVerified> {
    let decrypt_key = Jwk::from_json(decrypt_key.as_bytes())?;
    let decrypt_policy = decrypt_policy(decrypt_options)?;
    let key = Jwk::from_json(key.as_bytes())?;
    let v = with_policy(options, |policy| {
        jwt::decrypt_nested(
            token,
            &decrypt_key,
            &decrypt_policy,
            Keys::One(&key),
            policy,
        )
    })?;
    Ok(nested_verified(v)?)
}

/// Decrypts the nested JWT `token` with `decrypt_key`, then verifies and validates the inner
/// JWT against the JWK Set `jwks` (ADR 0030 §4; RFC 7519 §5.2, §7.2 step 8; ADR 0029).
///
/// As [`jwt_decrypt_nested`], with the set imported as for [`jwt_verify_with_jwks`].
///
/// # Errors
///
/// As [`jwt_decrypt_nested`], plus `NoMatchingKey` (ADR 0029 §4).
pub fn jwt_decrypt_nested_with_jwks(
    token: &str,
    decrypt_key: &str,
    decrypt_options: &JweDecryptOptions,
    jwks: &str,
    options: &JwtVerifyOptions,
) -> SurfaceResult<JwtNestedVerified> {
    let decrypt_key = Jwk::from_json(decrypt_key.as_bytes())?;
    let decrypt_policy = decrypt_policy(decrypt_options)?;
    let set = JwkSet::from_json(jwks.as_bytes())?;
    let v = with_policy(options, |policy| {
        jwt::decrypt_nested(
            token,
            &decrypt_key,
            &decrypt_policy,
            Keys::Set(&set),
            policy,
        )
    })?;
    Ok(nested_verified(v)?)
}

// ------------------------------------------------------------------------------------------------
// The clock and the policy (ADR 0030 §4, ADR 0028, ADR 0027)
// ------------------------------------------------------------------------------------------------

/// The `profile` name of the RFC 9068 §4 access-token policy (ADR 0030 §4).
const ACCESS_TOKEN_PROFILE: &str = "access_token";

/// The clock of one verify call (ADR 0030 §4, "The clock"; ADR 0028 §4).
///
/// An explicit `now` is a [`FixedClock`]. Without one, the core's [`jwt::SystemClock`] where it
/// exists; on `wasm32-unknown-unknown`, where it does not (ADR 0028 §2), a clock that is
/// unavailable, so validation fails with the core's `InvalidClaim("clock")` when it reads the
/// time (ADR 0028 §1: an unavailable time is that error, never a panic). The JS facade always
/// passes `now`, so only a caller bypassing it gets there.
enum SurfaceClock {
    Fixed(FixedClock),
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    System(jwt::SystemClock),
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    Unavailable,
}

impl SurfaceClock {
    fn new(now: Option<i64>) -> Self {
        match now {
            Some(secs) => Self::Fixed(FixedClock(secs)),
            #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
            None => Self::System(jwt::SystemClock),
            #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
            None => Self::Unavailable,
        }
    }
}

impl Clock for SurfaceClock {
    fn now(&self) -> polyjose::Result<i64> {
        match self {
            Self::Fixed(clock) => clock.now(),
            #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
            Self::System(clock) => clock.now(),
            // ADR 0028 §1: the detail the core gives an unavailable time.
            #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
            Self::Unavailable => Err(Error::InvalidClaim("clock")),
        }
    }
}

/// Builds the clock and the policy of `options`, then runs `run` under them (ADR 0030 §4). The
/// policy borrows the clock and the allow-list, so all three live in this frame.
fn with_policy<T>(
    options: &JwtVerifyOptions,
    run: impl FnOnce(&Policy<'_>) -> polyjose::Result<T>,
) -> polyjose::Result<T> {
    let clock = SurfaceClock::new(options.now);
    let allowed: Vec<SigningAlg> = algs(&options.allowed_algs);
    let policy = policy(&clock, &allowed, options)?;
    run(&policy)
}

/// The core [`Policy`] of `options` (ADR 0030 §4): each member is one core call, and `None` or
/// `false` calls nothing, so every default stays the core's (ADR 0027 §3–§5, ADR 0029 §4).
///
/// The calls run in the member order, starting with the constructor, so the allow-list is
/// checked first and `leeway` next (the conformance step order, 0004 implementer note 7):
///
/// - no `profile`: [`Policy::new`], then [`Policy::issuers`] and [`Policy::audiences`];
/// - `profile: "access_token"`: [`Policy::access_token`] with `issuers` and `audiences`, which
///   the core requires (RFC 9068 §4); it also requires `typ: at+jwt`, the RFC 9068 §2.2 claims
///   and a string `client_id`, which no later member removes (ADR 0052 §4);
/// - any other `profile`: `UnsupportedAlgorithm` (ADR 0030 §4), after the allow-list check;
/// - then `subject`, `leeway` (the core caps it, `InvalidClaim("leeway")`), `max_age`,
///   `required_claims` (one [`Policy::require`] per name, in order), `allow_missing_exp`,
///   `ignore_audience`, `typ` ([`Policy::expect_typ`]), `any_typ`, `max_key_candidates` and
///   `max_input_len`.
///
/// `typ` together with `any_typ` asks for two `typ` modes at once (ADR 0027 §5) and fails with
/// `InvalidHeader("typ")` (ADR 0030 §4).
fn policy<'a>(
    clock: &'a dyn Clock,
    allowed: &'a [SigningAlg],
    o: &JwtVerifyOptions,
) -> polyjose::Result<Policy<'a>> {
    let mut p = match o.profile.as_deref() {
        None => {
            let p = Policy::new(clock, allowed)?;
            let p = apply(p, o.issuers.as_deref(), |p, iss| p.issuers(&strs(iss)));
            apply(p, o.audiences.as_deref(), |p, aud| p.audiences(&strs(aud)))
        }
        Some(ACCESS_TOKEN_PROFILE) => Policy::access_token(
            clock,
            allowed,
            &strs(o.issuers.as_deref().unwrap_or_default()),
            &strs(o.audiences.as_deref().unwrap_or_default()),
        )?,
        Some(_) => {
            Policy::new(clock, allowed)?;
            return Err(Error::UnsupportedAlgorithm);
        }
    };
    p = apply(p, o.subject.as_deref(), Policy::subject);
    p = try_apply(p, o.leeway, Policy::leeway)?;
    p = apply(p, o.max_age, Policy::max_age);
    p = apply(p, o.required_claims.as_deref(), |p, names| {
        names.iter().fold(p, |p, name| p.require(name))
    });
    p = apply_flag(p, o.allow_missing_exp, Policy::allow_missing_exp);
    p = apply_flag(p, o.ignore_audience, Policy::ignore_audience);
    if o.typ.is_some() && o.any_typ {
        return Err(Error::InvalidHeader("typ"));
    }
    p = apply(p, o.typ.as_deref(), Policy::expect_typ);
    p = apply_flag(p, o.any_typ, Policy::any_typ);
    p = apply(
        p,
        o.max_key_candidates.map(to_usize),
        Policy::max_key_candidates,
    );
    p = apply(p, o.max_input_len.map(to_usize), Policy::max_input_len);
    Ok(p)
}

// ------------------------------------------------------------------------------------------------
// Issuing (ADR 0030 §4, ADR 0027 §8)
// ------------------------------------------------------------------------------------------------

/// The core [`IssueOptions`] of `options` (ADR 0030 §4): `typ` → [`IssueOptions::typ`],
/// `omit_typ` → [`IssueOptions::no_typ`], `access_token` → [`IssueOptions::access_token`], and
/// one [`IssueOptions::header_param`] per `header` member, in order. `None`/`false` calls
/// nothing, so the core's `typ: JWT` default stands.
fn issue_options(o: &JwtSignOptions) -> polyjose::Result<IssueOptions> {
    let typ_choices = [o.typ.is_some(), o.omit_typ, o.access_token];
    if typ_choices.into_iter().filter(|chosen| *chosen).count() > 1 {
        return Err(Error::InvalidHeader("typ"));
    }
    let mut issue = IssueOptions::new(SigningAlg::from(o.alg.as_str()));
    issue = apply(issue, o.typ.as_deref(), IssueOptions::typ);
    issue = apply_flag(issue, o.omit_typ, IssueOptions::no_typ);
    issue = apply_flag(issue, o.access_token, IssueOptions::access_token);
    match o.header.as_deref() {
        Some(header) => json_object(header)?
            .into_iter()
            .try_fold(issue, |issue, (name, value)| {
                issue.header_param(&name, value)
            }),
        None => Ok(issue),
    }
}

/// Parses `text` as a JSON object with the core's I-JSON parser (RFC 7493, ADR 0016), keeping
/// its member order. Anything else is `InvalidJson`, the code and detail the core's own header
/// parser gives a non-object (RFC 7515 §4).
fn json_object(text: &str) -> polyjose::Result<Object> {
    json::parse(text.as_bytes())?
        .into_object()
        .ok_or(Error::InvalidJson("expected a JSON object"))
}

// ------------------------------------------------------------------------------------------------
// The JWE layer of a nested JWT (ADR 0030 §4, "JWE"; RFC 7516)
// ------------------------------------------------------------------------------------------------

/// The core [`Encryptor`] of `o` (ADR 0030 §3): `enc`, then each member present, then the
/// recipients in order (RFC 7516 §5.1). Headers are parsed by the core's [`Header::from_json`].
/// The core decides what the compact form allows (RFC 7516 §7.1).
fn encryptor(o: &JweEncryptOptions) -> polyjose::Result<Encryptor> {
    let mut e = Encryptor::new(ContentEncAlg::from(o.enc.as_str()));
    e = try_apply(e, o.protected_header.as_deref(), |e, h| {
        Ok(e.protected_header(Header::from_json(h.as_bytes())?))
    })?;
    e = try_apply(e, o.shared_unprotected_header.as_deref(), |e, h| {
        Ok(e.shared_unprotected_header(Header::from_json(h.as_bytes())?))
    })?;
    e = apply(e, o.aad.as_ref(), |e, aad| e.aad(aad.as_bytes()));
    e = apply_flag(e, o.compress, Encryptor::compress);
    o.recipients
        .iter()
        .try_fold(e, |e, r| Ok(e.recipient(recipient(r)?)))
}

/// The core [`Recipient`] of `r` (RFC 7516 §7.2.1, RFC 7518 §4): the key is parsed into the
/// core's wiping `Jwk` (ADR 0030 §7); `apu`, `apv` (RFC 7518 §4.6.1.2–§4.6.1.3), `p2c` and
/// `p2s_len` (RFC 7518 §4.8.1) are set only when present, so the PBES2 defaults are the core's
/// (ADR 0023).
fn recipient(r: &JweRecipient) -> polyjose::Result<Recipient> {
    let key = Jwk::from_json(r.key.as_str().as_bytes())?;
    let mut rec = Recipient::new(KeyMgmtAlg::from(r.alg.as_str()), &key);
    rec = try_apply(rec, r.header.as_deref(), |rec, h| {
        Ok(rec.header(Header::from_json(h.as_bytes())?))
    })?;
    rec = apply(rec, r.apu.as_deref(), Recipient::apu);
    rec = apply(rec, r.apv.as_deref(), Recipient::apv);
    rec = apply(rec, r.p2c, Recipient::p2c);
    rec = apply(rec, r.p2s_len.map(to_usize), Recipient::p2s_len);
    Ok(rec)
}

/// The core [`DecryptPolicy`] of `o` (RFC 7516 §5.2, RFC 8725 §3.1; ADR 0023, ADR 0050): the
/// allow-lists, which the core checks first, then each bound present.
fn decrypt_policy(o: &JweDecryptOptions) -> polyjose::Result<DecryptPolicy> {
    let alg: Vec<KeyMgmtAlg> = algs(&o.allowed_algs);
    let enc: Vec<ContentEncAlg> = algs(&o.allowed_enc);
    let mut p = DecryptPolicy::new(&alg, &enc)?;
    p = apply(p, o.max_pbes2_count, DecryptPolicy::max_pbes2_count);
    p = apply(
        p,
        o.max_decompressed_len.map(to_usize),
        DecryptPolicy::max_decompressed_len,
    );
    p = apply(
        p,
        o.max_input_len.map(to_usize),
        DecryptPolicy::max_input_len,
    );
    p = apply(
        p,
        o.max_recipients.map(to_usize),
        DecryptPolicy::max_recipients,
    );
    p = apply(p, o.understood_crit.as_deref(), |p, crit| {
        p.understood_crit(&strs(crit))
    });
    Ok(p)
}

// ------------------------------------------------------------------------------------------------
// Results
// ------------------------------------------------------------------------------------------------

/// The surface form of a core [`VerifiedNestedJwt`] (ADR 0030 §4): the inner JWT as
/// [`verified`] gives it, the outer JWE Protected Header (the whole JOSE Header of a compact
/// JWE, RFC 7516 §7.1) as the core serializes it, and the recipient index (`0`).
fn nested_verified(v: VerifiedNestedJwt) -> polyjose::Result<JwtNestedVerified> {
    Ok(JwtNestedVerified {
        outer_header: v.outer_header.to_json()?,
        recipient_index: index(v.recipient),
        inner: verified(v.inner)?,
    })
}

/// The surface form of a core [`VerifiedJwt`] (ADR 0030 §4): the claims as the core serializes
/// them, registered claims first (ADR 0027 §1), and the JWS Protected Header likewise.
fn verified(v: VerifiedJwt) -> polyjose::Result<JwtVerified> {
    Ok(JwtVerified {
        claims: v.claims.to_json(),
        header: v.header.to_json()?,
        alg: v.alg.as_str().to_owned(),
        key_index: v.key_index.map(index),
        kid: v.kid,
    })
}

/// A core index (a JWK Set member, a JWE recipient) as the surface's `u32` (ADR 0030 §2). The
/// core's input limits keep every index far below `u32::MAX`; it saturates rather than panics.
fn index(i: usize) -> u32 {
    u32::try_from(i).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_explicit_now_is_returned_as_given() {
        assert_eq!(
            SurfaceClock::new(Some(1_300_819_320)).now(),
            Ok(1_300_819_320)
        );
        assert_eq!(SurfaceClock::new(Some(-1)).now(), Ok(-1));
    }

    /// ADR 0030 §4: without `now`, the time is the system clock's, within the test's own two
    /// reads of `SystemTime` (no other wall-clock assertion, pipeline rule 8).
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    #[test]
    fn a_missing_now_reads_the_system_clock_between_two_reads() {
        let read = || {
            let since = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap();
            i64::try_from(since.as_secs()).unwrap()
        };
        let before = read();
        let now = SurfaceClock::new(None).now().unwrap();
        let after = read();
        assert!(
            before <= now && now <= after,
            "{before} <= {now} <= {after}"
        );
    }

    /// ADR 0030 §4, ADR 0028 §1: on `wasm32-unknown-unknown` a missing `now` is the core's
    /// `InvalidClaim("clock")`, through every verify operation, and never a panic. Run by
    /// feature 0006 (wasm-bindgen-test); it compiles in every wasm32 build of the tests.
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    #[test]
    fn a_missing_now_is_invalid_claim_clock_on_wasm32_unknown() {
        assert_eq!(
            SurfaceClock::new(None).now(),
            Err(Error::InvalidClaim("clock"))
        );
        // RFC 7519 §3.1 with RFC 7515 Appendix A.1's key: everything but the time checks
        // passes, so the error is the clock's.
        let key = r#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#;
        let token = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let options = JwtVerifyOptions::new(vec!["HS256".to_owned()]);
        let err = jwt_verify(token, key, &options).unwrap_err();
        assert_eq!(err.code(), "InvalidClaim");
        assert_eq!(err, crate::SurfaceError::from(Error::InvalidClaim("clock")));
        let jwks = format!(r#"{{"keys":[{key}]}}"#);
        let err = jwt_verify_with_jwks(token, &jwks, &options).unwrap_err();
        assert_eq!(err, crate::SurfaceError::from(Error::InvalidClaim("clock")));
    }

    #[test]
    fn index_converts_losslessly_and_saturates() {
        assert_eq!(index(0), 0);
        assert_eq!(index(1), 1);
        assert_eq!(index(usize::try_from(u32::MAX).unwrap()), u32::MAX);
        #[cfg(target_pointer_width = "64")]
        assert_eq!(index(usize::MAX), u32::MAX);
    }
}
