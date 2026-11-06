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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use crate::jws::{ProtectedHeader, SignOptions, Signer, sign_compact, sign_flattened};
    use crate::jws::{VerifyOptions, verify_json};
    use crate::jwt::FixedClock;

    /// RFC 7515 Appendix A.1.1: the HMAC key of RFC 7519 §3.1.
    const OCT_64: &str = r#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#;
    /// RFC 7519 §3.1: the HS256 JWT.
    const RFC7519_3_1: &str = concat!(
        "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9",
        ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
        ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    );
    /// RFC 7519 §3.1's claims, CRLFs included.
    const CLAIMS: &[u8] =
        b"{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";
    const HS256: [SigningAlg; 1] = [SigningAlg::HS256];
    /// RFC 7519 §3.1's `exp − 60`.
    const NOW: i64 = 1_300_819_320;

    fn key() -> Jwk {
        Jwk::from_json(OCT_64.as_bytes()).expect("RFC 7515 A.1.1 key")
    }

    fn protected(alg: &str) -> ProtectedHeader {
        let mut header = Header::new();
        header.alg = Some(alg.into());
        ProtectedHeader::new(header).expect("protected header")
    }

    /// A flattened JWS (RFC 7515 §7.2.2) over the §3.1 claims, signed with
    /// a protected `{"alg":"HS256"}` and the given unprotected header.
    fn flattened(unprotected: Header) -> String {
        let key = key();
        let signer = Signer::new(&key)
            .protected(protected("HS256"))
            .unprotected(unprotected);
        sign_flattened(&signer, CLAIMS, &SignOptions::new()).expect("flattened JWS")
    }

    /// ADR 0049 §2 (contract criterion of 0004 T07): a JWS whose
    /// unprotected header sets `typ` or `cty` is `InvalidHeader`, whatever
    /// the protected header says.
    ///
    /// `verify_inner` takes compact tokens only (RFC 7519 §1), and a
    /// compact JWS has no unprotected header (RFC 7515 §7.1), so the
    /// pipeline's J1 call always passes `None`. The only crate-internal
    /// seam that sees an unprotected header is therefore
    /// [`check_jwt_header`] itself: this drives it with the unprotected
    /// header of a flattened JWS that 0002's `verify_json` accepted, with
    /// a valid signature, under every `typ` mode. `verify_inner` on the
    /// same JWS is `InvalidFormat` (step 1 decides first).
    #[test]
    fn an_unprotected_typ_or_cty_is_invalid_header_on_the_internal_path() {
        let key = key();
        let clock = FixedClock(NOW);
        let policies = [
            Policy::new(&clock, &HS256).expect("policy"),
            Policy::new(&clock, &HS256)
                .expect("policy")
                .expect_typ("at+jwt"),
            Policy::new(&clock, &HS256).expect("policy").any_typ(),
        ];
        let mut typ = Header::new();
        typ.typ = Some("at+jwt".into());
        let mut cty = Header::new();
        cty.cty = Some("example".into());
        let mut both = Header::new();
        both.typ = Some("JWT".into());
        both.cty = Some("JWT".into());
        for unprotected in [typ, cty, both] {
            let jws = flattened(unprotected);
            let opts = VerifyOptions::new(&HS256).expect("options");
            let verified = verify_json(&jws, &key, &opts).expect("a valid flattened JWS");
            let protected = verified.protected.as_ref().expect("protected header");
            assert!(verified.unprotected.is_some());
            for policy in &policies {
                assert!(matches!(
                    check_jwt_header(
                        protected,
                        verified.unprotected.as_ref(),
                        policy,
                        Layer::Signed
                    ),
                    Err(Error::InvalidHeader(_))
                ));
                // The protected header alone passes the rules that apply
                // to it, except an explicit `typ` it does not carry.
                if !matches!(policy.typ_mode(), crate::jwt::TypMode::Exact(_)) {
                    assert_eq!(
                        check_jwt_header(protected, None, policy, Layer::Signed),
                        Ok(())
                    );
                }
                assert!(matches!(
                    verify_inner(&jws, Keys::One(&key), policy),
                    Err(Error::InvalidFormat(_))
                ));
            }
        }
        // An unprotected header without typ or cty is not this rule's
        // concern (but is still not a JWT: InvalidFormat in the pipeline).
        let mut other = Header::new();
        other.kid = Some("k1".into());
        let jws = flattened(other);
        let opts = VerifyOptions::new(&HS256).expect("options");
        let verified = verify_json(&jws, &key, &opts).expect("a valid flattened JWS");
        let protected = verified.protected.as_ref().expect("protected header");
        assert_eq!(
            check_jwt_header(
                protected,
                verified.unprotected.as_ref(),
                &policies[0],
                Layer::Signed
            ),
            Ok(())
        );
    }

    /// T09 runs `verify_inner` on the decrypted inner token: it is
    /// `verify`, result for result.
    #[test]
    fn verify_inner_is_verify() {
        let key = key();
        for now in [NOW, 1_300_819_440] {
            let clock = FixedClock(now);
            let policy = Policy::new(&clock, &HS256).expect("policy");
            for token in [RFC7519_3_1, "a.b", ""] {
                assert_eq!(
                    verify_inner(token, Keys::One(&key), &policy),
                    verify(token, Keys::One(&key), &policy)
                );
            }
        }
    }

    /// RFC 7519 §7.2 step 10: a verified payload that is not UTF-8, not
    /// JSON, or not a JSON object is `InvalidJson` (ADR 0027 §1), after the
    /// signature (J3 after step 9).
    #[test]
    fn a_verified_payload_that_is_not_a_json_object_is_invalid_json() {
        let key = key();
        let clock = FixedClock(NOW);
        let policy = Policy::new(&clock, &HS256).expect("policy");
        for payload in [&b"\xff\xfe"[..], b"", b"[]", b"\"joe\"", b"{\"iss\":"] {
            let token =
                sign_compact(&protected("HS256"), payload, &key, &SignOptions::new()).expect("JWS");
            assert!(
                matches!(
                    verify_inner(&token, Keys::One(&key), &policy),
                    Err(Error::InvalidJson(_))
                ),
                "{payload:?}"
            );
        }
    }

    /// The result's header is the JWS Protected Header the signature
    /// covers (RFC 7515 §7.1), as parsed, and `alg` is the verified one.
    #[test]
    fn the_result_carries_the_protected_header_and_alg() {
        let key = key();
        let clock = FixedClock(NOW);
        let policy = Policy::new(&clock, &HS256).expect("policy");
        let v = verify_inner(RFC7519_3_1, Keys::One(&key), &policy).expect("§3.1 verifies");
        let mut header = Header::new();
        header.typ = Some("JWT".into());
        header.alg = Some("HS256".into());
        assert_eq!(v.header, header);
        assert_eq!(v.alg, SigningAlg::HS256);
        assert_eq!(v.claims, Claims::from_json(CLAIMS).expect("claims"));
    }
}
