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
//! **What nesting proves.** The outer JWE gives confidentiality, and the
//! inner JWS's signature authenticates the issuer (RFC 7519 §11.2). A
//! nested JWT does not prove that the issuer encrypted it. Anyone able to
//! decrypt it can take out the inner JWS, which is an ordinary signed JWT,
//! and present it to [`verify`]. With a key management mode that anyone
//! can use (ECDH-ES, RSA-OAEP-256 to a published key, or a known PBES2
//! password), anyone can also encrypt a signed JWT of the issuer to the
//! recipient. Both layers are still validated with the caller's keys
//! (RFC 8725 §3.3), so nothing is forged. A deployment that must accept a
//! token only in nested form makes that visible inside the signed claims,
//! with a distinct explicit `typ` on the inner JWT or a distinct `aud`, and
//! checks it in the policy (RFC 8725 §3.11–§3.12). See [`decrypt_nested`].
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
mod keyset;
mod nested;
mod numeric_date;
mod policy;
mod sign;
pub mod typ;
mod validate;
mod verify;

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
