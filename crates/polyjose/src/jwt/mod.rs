//! JSON Web Token (RFC 7519): claims, the RFC 8725 validation policy, and
//! nested JWTs.
//!
//! - **Verify** a signed JWT with [`verify`]: the caller's [`Keys`] (one
//!   key or a JWK Set, ADR 0029) and a [`Policy`] holding the algorithm
//!   allow-list, an injected [`Clock`] and the claim rules (ADR 0027,
//!   ADR 0028). The result is a [`VerifiedJwt`].
//! - **Issue** one with [`sign`] and [`IssueOptions`] (RFC 7519 §7.1).
//! - **Nest** it, sign-then-encrypt, with [`encrypt_nested`], and verify a
//!   nested JWT with [`decrypt_nested`] (RFC 7519 §5.2, §11.2; RFC 8725
//!   §3.3). Signed and nested JWTs have separate entry points, so a caller
//!   always knows which protection it got (ADR 0027 §7).
//!
//! A JWT is always a compact serialization (RFC 7519 §1). `none` is never
//! accepted (RFC 8725 §3.2, ADR 0007), and the time comes only from the
//! policy's clock: `SystemClock` where std has one, [`FixedClock`] in
//! tests (ADR 0028).
//!
//! [`verify`]: crate::jwt::verify
//! [`Keys`]: crate::jwt::Keys
//! [`Policy`]: crate::jwt::Policy
//! [`Clock`]: crate::jwt::Clock
//! [`VerifiedJwt`]: crate::jwt::VerifiedJwt
//! [`sign`]: crate::jwt::sign
//! [`IssueOptions`]: crate::jwt::IssueOptions
//! [`encrypt_nested`]: crate::jwt::encrypt_nested
//! [`decrypt_nested`]: crate::jwt::decrypt_nested
//! [`FixedClock`]: crate::jwt::FixedClock
//!
//! ```no_run
//! use polyjose::jwa::SigningAlg;
//! use polyjose::jwk::JwkSet;
//! use polyjose::jwt::{self, Keys, Policy, SystemClock};
//!
//! # fn run(token: &str, jwks_json: &[u8]) -> polyjose::Result<()> {
//! let keys = JwkSet::from_json(jwks_json)?;
//! let policy = Policy::new(&SystemClock, &[SigningAlg::ES256])?
//!     .issuer("https://issuer.example")
//!     .audience("https://api.example");
//! let verified = jwt::verify(token, Keys::Set(&keys), &policy)?;
//! println!("subject: {:?}", verified.claims.sub);
//! # Ok(())
//! # }
//! ```

mod claims;
mod clock;
mod nested;
mod numeric_date;
mod sign;
mod verify;
// The pipeline modules below are wired together by the later tasks of
// feature 0004; until verify (T07) and nested (T09) call them, their
// crate-internal items have no caller. `allow`, not `expect`: each task
// fills in its own file and must not edit this one, and an `expect` would
// become an error as soon as the item is used. Remove these attributes
// once the feature's last code task has landed (as 0003 did in a5b789b).
#[allow(
    dead_code,
    reason = "the JWT skeleton (0004 T01): called once verify (T07) lands"
)]
mod keyset;
#[allow(
    dead_code,
    reason = "the JWT skeleton (0004 T01): read once validate (T06) and verify (T07) land"
)]
mod policy;
#[allow(
    dead_code,
    reason = "the JWT skeleton (0004 T01): called once verify (T07) and nested (T09) land"
)]
pub mod typ;
#[allow(
    dead_code,
    reason = "the JWT skeleton (0004 T01): called once verify (T07) lands"
)]
mod validate;

pub use claims::{Audience, Claims};
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub use clock::SystemClock;
pub use clock::{Clock, FixedClock};
pub use nested::{VerifiedNestedJwt, decrypt_nested, encrypt_nested};
pub use numeric_date::NumericDate;
pub use policy::{Policy, TypMode};
pub use sign::{IssueOptions, sign};
pub use verify::{Keys, VerifiedJwt, verify};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Result;
    use crate::header::Header;
    use crate::jwe::{DecryptPolicy, Encryptor};
    use crate::jwk::{Jwk, JwkSet};
    use crate::jws::{CompactPrechecked, Verified};

    /// The signatures frozen by 0004 T01. Later tasks fill in the bodies
    /// only; changing a signature here is a contract change for every
    /// task coding against it.
    #[test]
    fn signatures_are_frozen() {
        let _: fn(&str, Keys<'_>, &Policy<'_>) -> Result<VerifiedJwt> = verify;
        let _: fn(&str, Keys<'_>, &Policy<'_>) -> Result<VerifiedJwt> = verify::verify_inner;
        let _: fn(&Claims, &IssueOptions, &Jwk) -> Result<String> = sign;
        let _: fn(&str, &Encryptor) -> Result<String> = encrypt_nested;
        let _: fn(&str, &Jwk, &DecryptPolicy, Keys<'_>, &Policy<'_>) -> Result<VerifiedNestedJwt> =
            decrypt_nested;
        let _: fn(&Header, Option<&Header>, &Policy<'_>, typ::Layer) -> Result<()> =
            typ::check_jwt_header;
        let _: fn(&str, &str) -> bool = typ::media_type_eq;
        let _: fn(&CompactPrechecked<'_>, &JwkSet, &Policy<'_>) -> Result<(Verified, usize)> =
            keyset::select_and_verify;
        let _: fn(&Claims, &Policy<'_>) -> Result<()> = validate::validate_claims;
        let _: fn(&[u8]) -> Result<Claims> = Claims::from_json;
        let _: fn(&Claims) -> String = Claims::to_json;
        let _: fn(&crate::json::Value, &'static str) -> Result<NumericDate> =
            NumericDate::from_json;
        let _: fn(&dyn Clock) -> Result<i64> = clock::now_checked;
        let _ = [typ::Layer::Signed, typ::Layer::Outer];
    }
}
