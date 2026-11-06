//! The RFC 7515 / RFC 7797 processing rules shared by both serializations
//! (ADR 0026 §2–§4).
//!
//! `compact.rs` and `json.rs` own steps 1–3 of ADR 0026 §2 (limits, shape,
//! base64url) and parse each protected header with
//! [`ProtectedHeader::from_encoded`](super::ProtectedHeader::from_encoded)
//! (step 4's I-JSON part, where a duplicate member is
//! [`Error::InvalidJson`], ADR 0041 §1). Everything after that lives here,
//! so the two serializations cannot drift apart:
//!
//! - step 4's header structure: [`JoseHeader::new`] for one signature,
//!   [`common_b64`] across signatures;
//! - the JWS Signing Input: [`signing_input`];
//! - steps 5–9 for verification: [`check_verify`] (5–8) and
//!   [`verify_signature`] (5–9, calling the [`Families`] table);
//! - steps 5–8 for signing: [`prepare_sign`], whose [`SignReady`] is the
//!   only way to reach a family's `sign`;
//! - the multiple-signature ranking of ADR 0026 §3: [`progress_rank`] and
//!   [`furthest`].
//!
//! # How the serializations use this
//!
//! Verify (one signature, or each of several):
//!
//! ```text
//! ProtectedHeader::from_encoded / Header::from_object  // step 4, I-JSON + types
//! JoseHeader::new(protected, unprotected)              // step 4, structure
//! common_b64(&all_headers)                             // step 4, across signatures
//! signing_input(encoded_protected, payload, b64)
//! verify_signature(families, &header, key, opts, &input, &signature)  // steps 5-9
//! furthest(errors)                                     // none verified (ADR 0026 §3)
//! ```
//!
//! Sign (per signer): `JoseHeader::new`, `common_b64` (general JSON), then
//! `prepare_sign` (steps 5–8), then the serialization's payload rules
//! (`InvalidFormat`, RFC 7797 §5.2–§5.3), then `signing_input` and
//! `SignReady::sign`.

use std::collections::BTreeSet;

use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::header::Header;
use crate::json::{Object, Value};
use crate::jwa::SigningAlg;
use crate::jwk::Jwk;
use crate::util::b64url_encode;

use super::VerifyOptions;
use super::alg::{Families, Operation, bind_key};

/// The `crit` extensions polyjose understands: only `b64` (RFC 7797 §6;
/// RFC 7515 §4.1.11; ADR 0007).
pub(crate) const UNDERSTOOD_CRIT: &[&str] = &["b64"];

/// One signature's JOSE Header after ADR 0026 §2 step 4: the JWS Protected
/// and Unprotected Headers as given, and their union, which has passed
/// every structural rule.
///
/// The only way to build one is [`JoseHeader::new`], so holding a
/// `JoseHeader` means step 4 passed.
#[derive(Debug, Clone)]
pub(crate) struct JoseHeader {
    protected: Option<Header>,
    unprotected: Option<Header>,
    union: Header,
}

impl JoseHeader {
    /// Checks the header-structure rules of ADR 0026 §2 step 4 for one
    /// signature and forms the JOSE Header, the union of `protected` and
    /// `unprotected` (RFC 7515 §5.2 step 4). For compact, `unprotected`
    /// is `None` (RFC 7515 §7.1).
    ///
    /// Each header has already been parsed, so its registered parameters
    /// have their types and its `crit` its shape ([`Header::from_json`]).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidHeader`] if:
    /// - the two headers share a name (RFC 7515 §5.2 step 4, §7.2.1);
    /// - `crit` is in the unprotected header (RFC 7515 §4.1.11);
    /// - `crit` lists a name absent from the union, or is otherwise
    ///   malformed ([`Header::validate_crit`], RFC 7515 §4.1.11);
    /// - `b64` is in the unprotected header (RFC 7797 §3), or is present
    ///   without being listed in `crit` (RFC 7797 §6; ADR 0026 §2 step 4,
    ///   §4);
    /// - `alg` is absent from the union (RFC 7515 §4.1.1).
    ///
    /// Whether `crit`'s names are understood and `alg` is known are later
    /// steps (5 and 6).
    pub(crate) fn new(protected: Option<Header>, unprotected: Option<Header>) -> Result<Self> {
        let union = union(protected.as_ref(), unprotected.as_ref())?;
        if let Some(u) = &unprotected {
            if u.crit.is_some() {
                return Err(Error::InvalidHeader("crit must be in the protected header"));
            }
            if u.b64.is_some() {
                return Err(Error::InvalidHeader("b64 must be in the protected header"));
            }
        }
        union.validate_crit()?;
        if let Some(p) = &protected {
            let b64_critical = p.crit.iter().flatten().any(|name| name == "b64");
            if p.b64.is_some() && !b64_critical {
                return Err(Error::InvalidHeader("b64 must be listed in crit"));
            }
        }
        if union.alg.is_none() {
            return Err(Error::InvalidHeader("missing alg"));
        }
        Ok(Self {
            protected,
            unprotected,
            union,
        })
    }

    /// The JWS Protected Header, if any.
    pub(crate) fn protected(&self) -> Option<&Header> {
        self.protected.as_ref()
    }

    /// The JWS Unprotected Header, if any (JSON serialization only).
    pub(crate) fn unprotected(&self) -> Option<&Header> {
        self.unprotected.as_ref()
    }

    /// The JOSE Header: the union of both (RFC 7515 §5.2 step 4).
    pub(crate) fn union(&self) -> &Header {
        &self.union
    }

    /// Whether the payload is base64url-encoded: the `b64` value, `true`
    /// when absent (RFC 7797 §3).
    pub(crate) fn b64(&self) -> bool {
        self.union.b64.unwrap_or(true)
    }

    /// The protected and unprotected headers, for [`super::Verified`].
    pub(crate) fn into_parts(self) -> (Option<Header>, Option<Header>) {
        (self.protected, self.unprotected)
    }
}

/// The union of two headers, which must not share a name
/// (RFC 7515 §5.2 step 4). O(n log n) in the member count.
fn union(protected: Option<&Header>, unprotected: Option<&Header>) -> Result<Header> {
    let (p, u) = match (protected, unprotected) {
        (Some(p), Some(u)) => (p, u),
        (Some(only), None) | (None, Some(only)) => return Ok(only.clone()),
        (None, None) => return Ok(Header::new()),
    };
    let p = p.to_object()?;
    let u = u.to_object()?;
    let names: BTreeSet<&str> = p.iter().map(|(name, _)| name).collect();
    if u.iter().any(|(name, _)| names.contains(name)) {
        return Err(Error::InvalidHeader(
            "protected and unprotected headers share a parameter",
        ));
    }
    drop(names);
    let members: Vec<(Zeroizing<String>, Value)> = p.into_iter().chain(u).collect();
    // Each side's names are unique, and the sides are disjoint.
    Header::from_object(Object::from_unique_members(members))
}

/// The `b64` value every signature of one JWS shares: RFC 7797 §3 requires
/// "the same" value for all of them, absent meaning `true`. An empty slice
/// gives the default, `true`.
///
/// # Errors
///
/// [`Error::InvalidHeader`] if two signatures differ (RFC 7797 §3;
/// ADR 0026 §2 step 4, §3). The whole JWS is then rejected.
pub(crate) fn common_b64(headers: &[JoseHeader]) -> Result<bool> {
    let first = headers.first().is_none_or(JoseHeader::b64);
    if headers.iter().all(|h| h.b64() == first) {
        Ok(first)
    } else {
        Err(Error::InvalidHeader("b64 differs between signatures"))
    }
}

/// The JWS Signing Input (RFC 7515 §5.1 step 5, RFC 7797 §3):
///
/// - `b64` true: `ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' ||
///   BASE64URL(JWS Payload))`;
/// - `b64` false: `ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.') ||
///   JWS Payload`, the payload octets unencoded.
///
/// `protected_b64` is the encoded protected header exactly as signed or
/// received ([`super::ProtectedHeader::encoded`]), or `""` when a JSON
/// signature has none (RFC 7515 §5.1, RFC 7520 §4.7). `payload` is the
/// JWS Payload, also for detached content (RFC 7515 Appendix F).
pub(crate) fn signing_input(protected_b64: &str, payload: &[u8], b64: bool) -> Vec<u8> {
    let mut input = Vec::with_capacity(protected_b64.len() + 1 + payload.len().div_ceil(3) * 4);
    input.extend_from_slice(protected_b64.as_bytes());
    input.push(b'.');
    if b64 {
        input.extend_from_slice(b64url_encode(payload).as_bytes());
    } else {
        input.extend_from_slice(payload);
    }
    input
}

/// Steps 5 and 6 of ADR 0026 §2: every `crit` name understood, then a
/// known `alg`.
fn understood_alg(header: &JoseHeader) -> Result<SigningAlg> {
    // Step 5 (RFC 7515 §4.1.11): UnknownCritical. Its `validate_crit` part
    // already passed in step 4.
    header.union.validate_crit_understood(UNDERSTOOD_CRIT)?;
    // Step 6 (RFC 7515 §4.1.1): UnsupportedAlgorithm. Step 4 checked that
    // `alg` is present.
    header.union.signing_alg()
}

/// Steps 5–8 of ADR 0026 §2 for one signature being verified, returning
/// its `alg`.
///
/// # Errors
///
/// In this order:
/// 5. [`Error::UnknownCritical`]: `crit` lists a name other than `b64`
///    (RFC 7515 §4.1.11).
/// 6. [`Error::UnsupportedAlgorithm`]: `alg` is not a known JWS algorithm
///    (RFC 7515 §4.1.1).
/// 7. [`Error::AlgorithmNotAllowed`]: `alg` is `none` or not in
///    `opts`'s allow-list (RFC 8725 §3.1; RFC 7515 §5.2, last paragraph).
/// 8. [`Error::KeyAlgorithmMismatch`] / [`Error::InvalidKey`]: key binding
///    ([`bind_key`]).
pub(crate) fn check_verify(
    header: &JoseHeader,
    key: &Jwk,
    opts: &VerifyOptions<'_>,
) -> Result<SigningAlg> {
    let alg = understood_alg(header)?;
    // `VerifyOptions` cannot hold `none`; checked again regardless.
    if alg == SigningAlg::None || !opts.allowed_algs.contains(&alg) {
        return Err(Error::AlgorithmNotAllowed);
    }
    bind_key(&alg, key, Operation::Verify)?;
    Ok(alg)
}

/// Steps 5–9 of ADR 0026 §2 for one signature: [`check_verify`], then the
/// signature check through `families` (RFC 7515 §5.2 step 8).
///
/// `signing_input` is [`signing_input`] of this signature's encoded
/// protected header and the payload; `signature` is the decoded JWS
/// Signature.
///
/// # Errors
///
/// As [`check_verify`], then [`Error::InvalidSignature`] (or
/// [`Error::InvalidKey`] for a key only the primitive can reject) from the
/// family.
pub(crate) fn verify_signature(
    families: &Families,
    header: &JoseHeader,
    key: &Jwk,
    opts: &VerifyOptions<'_>,
    signing_input: &[u8],
    signature: &[u8],
) -> Result<SigningAlg> {
    let alg = check_verify(header, key, opts)?;
    (families.verify)(&alg, key, signing_input, signature)?;
    Ok(alg)
}

/// A signature that passed steps 5–8 for signing and may be computed.
///
/// Only [`prepare_sign`] builds one, so a family's `sign` is never reached
/// without key binding.
pub(crate) struct SignReady<'k> {
    alg: SigningAlg,
    key: &'k Jwk,
}

impl SignReady<'_> {
    /// The `alg` the signature will use.
    pub(crate) fn alg(&self) -> &SigningAlg {
        &self.alg
    }

    /// Computes the JWS Signature over `signing_input` (RFC 7515 §5.1
    /// step 5) through `families`.
    ///
    /// # Errors
    ///
    /// The family's: [`Error::InvalidKey`], or
    /// [`Error::RandomnessUnavailable`] for ECDSA.
    pub(crate) fn sign(&self, families: &Families, signing_input: &[u8]) -> Result<Vec<u8>> {
        (families.sign)(&self.alg, self.key, signing_input)
    }
}

/// Steps 5–8 of ADR 0026 §2 for a signature being produced, so that
/// polyjose only signs what it would itself accept.
///
/// # Errors
///
/// In this order:
/// 5. [`Error::UnknownCritical`]: `crit` lists a name other than `b64`;
///    polyjose cannot honour an extension it does not understand
///    (RFC 7515 §4.1.11).
/// 6. [`Error::UnsupportedAlgorithm`]: `alg` is not a known JWS algorithm.
/// 7. [`Error::AlgorithmNotAllowed`]: `alg` is `none` (RFC 8725 §3.2,
///    ADR 0007).
/// 8. [`Error::UnsupportedAlgorithm`] for RS*/PS* (ADR 0021), then
///    [`Error::KeyAlgorithmMismatch`] / [`Error::InvalidKey`] from key
///    binding, including a public-only key ([`bind_key`]).
pub(crate) fn prepare_sign<'k>(header: &JoseHeader, key: &'k Jwk) -> Result<SignReady<'k>> {
    let alg = understood_alg(header)?;
    if alg == SigningAlg::None {
        return Err(Error::AlgorithmNotAllowed);
    }
    bind_key(&alg, key, Operation::Sign)?;
    Ok(SignReady { alg, key })
}

/// How far a signature got through steps 5–9 before failing, for
/// ADR 0026 §3: `InvalidSignature` (6) > `InvalidKey` (5) >
/// `KeyAlgorithmMismatch` (4) > `AlgorithmNotAllowed` (3) >
/// `UnsupportedAlgorithm` (2) > `UnknownCritical` (1).
///
/// Steps 5–9 produce no other code under the family contract; anything
/// else ranks 0, so the ranking stays total and deterministic.
pub(crate) fn progress_rank(error: &Error) -> u8 {
    match error {
        Error::InvalidSignature => 6,
        Error::InvalidKey(_) => 5,
        Error::KeyAlgorithmMismatch => 4,
        Error::AlgorithmNotAllowed => 3,
        Error::UnsupportedAlgorithm => 2,
        Error::UnknownCritical => 1,
        _ => 0,
    }
}

/// The error to report when no signature of a JWS verified (ADR 0026 §3):
/// the one with the highest [`progress_rank`], ties going to the earliest,
/// so pass the errors in signature order. `None` if there are none.
pub(crate) fn furthest(errors: impl IntoIterator<Item = Error>) -> Option<Error> {
    errors.into_iter().fold(None, |best, e| match best {
        Some(b) if progress_rank(&b) >= progress_rank(&e) => Some(b),
        _ => Some(e),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwa::SigningAlg;
    use crate::jwk::Jwk;
    use crate::jws::alg::fake::{FAKE, REJECTING, fake_signature};
    use crate::jws::alg::test_keys as keys;
    use crate::jws::{ProtectedHeader, VerifyOptions};
    use crate::util::b64url_encode;

    fn h(json: &str) -> Header {
        Header::from_json(json.as_bytes()).unwrap()
    }

    fn jose(protected: Option<&str>, unprotected: Option<&str>) -> Result<JoseHeader> {
        JoseHeader::new(protected.map(h), unprotected.map(h))
    }

    fn code(r: Result<JoseHeader>) -> &'static str {
        r.err().map_or("ok", |e| e.code())
    }

    #[test]
    fn signing_input_rfc7515_a1() {
        // RFC 7515 Appendix A.1.1: the CRLF header octets and the payload
        // {"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}
        let payload =
            b"{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";
        let expected = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
        let input = signing_input("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9", payload, true);
        assert_eq!(input, expected.as_bytes());
        // The RFC lists the first and last octets of the ASCII array.
        assert_eq!(&input[..8], &[101, 121, 74, 48, 101, 88, 65, 105]);
        assert_eq!(&input[input.len() - 4..], &[86, 108, 102, 81]);
    }

    #[test]
    fn signing_input_rfc7797_section_4() {
        // RFC 7797 §4.1: b64 true, payload "$.02".
        assert_eq!(
            signing_input("eyJhbGciOiJIUzI1NiJ9", b"$.02", true),
            b"eyJhbGciOiJIUzI1NiJ9.JC4wMg"
        );
        // RFC 7797 §4.2: b64 false, the payload octets themselves (§3).
        let protected = "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19";
        let input = signing_input(protected, b"$.02", false);
        assert_eq!(
            input,
            b"eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19.$.02"
        );
        assert_eq!(&input[input.len() - 5..], &[46, 36, 46, 48, 50]);
    }

    #[test]
    fn signing_input_edge_cases() {
        // RFC 7515 §5.1, RFC 7520 §4.7: no protected header, empty first part.
        assert_eq!(signing_input("", b"$.02", true), b".JC4wMg");
        // An empty payload (RFC 7515 Appendix F detached content still signs it).
        assert_eq!(signing_input("e30", b"", true), b"e30.");
        assert_eq!(signing_input("e30", b"", false), b"e30.");
        // b64 false keeps any octets, untouched.
        assert_eq!(
            signing_input("e30", &[0, 0xff, b'.'], false),
            b"e30.\x00\xff."
        );
    }

    #[test]
    fn union_of_disjoint_headers() {
        // RFC 7515 §5.2 step 4: the JOSE Header is the union.
        let j = jose(
            Some(r#"{"alg":"HS256","x-a":1}"#),
            Some(r#"{"kid":"k1","x-b":2}"#),
        )
        .unwrap();
        let u = j.union();
        assert_eq!(u.alg.as_deref(), Some("HS256"));
        assert_eq!(u.kid.as_deref(), Some("k1"));
        assert!(u.contains("x-a") && u.contains("x-b"));
        assert_eq!(j.protected(), Some(&h(r#"{"alg":"HS256","x-a":1}"#)));
        assert_eq!(j.unprotected(), Some(&h(r#"{"kid":"k1","x-b":2}"#)));
        assert!(j.b64());
        let (p, up) = j.into_parts();
        assert!(p.is_some() && up.is_some());

        // Either header alone (RFC 7515 §7.2.1; RFC 7520 §4.7 has no
        // protected header).
        let only_p = jose(Some(r#"{"alg":"ES256"}"#), None).unwrap();
        assert_eq!(only_p.union(), &h(r#"{"alg":"ES256"}"#));
        let only_u = jose(None, Some(r#"{"alg":"HS256","kid":"k"}"#)).unwrap();
        assert_eq!(only_u.union(), &h(r#"{"alg":"HS256","kid":"k"}"#));
        assert!(only_u.protected().is_none());
    }

    #[test]
    fn overlapping_headers_are_invalid() {
        // RFC 7515 §5.2 step 4, §7.2.1: the two sets MUST be disjoint.
        for (p, u) in [
            (r#"{"alg":"HS256"}"#, r#"{"alg":"HS256"}"#),
            (r#"{"alg":"HS256","kid":"a"}"#, r#"{"kid":"b"}"#),
            (r#"{"alg":"HS256","x-a":1}"#, r#"{"x-a":1}"#),
        ] {
            assert_eq!(code(jose(Some(p), Some(u))), "InvalidHeader", "{p} {u}");
        }
    }

    #[test]
    fn crit_must_be_protected_and_well_formed() {
        // RFC 7515 §4.1.11: crit MUST occur only in the protected header.
        assert_eq!(
            code(jose(
                Some(r#"{"alg":"HS256","x-a":1}"#),
                Some(r#"{"crit":["x-a"]}"#)
            )),
            "InvalidHeader"
        );
        assert_eq!(
            code(jose(
                None,
                Some(r#"{"alg":"HS256","crit":["x-a"],"x-a":1}"#)
            )),
            "InvalidHeader"
        );
        // A listed name absent from the whole JOSE Header (§4.1.11).
        assert_eq!(
            code(jose(Some(r#"{"alg":"HS256","crit":["x-a"]}"#), None)),
            "InvalidHeader"
        );
        // A listed name may live in the unprotected header: step 4 passes,
        // and whether it is understood is step 5's question.
        assert_eq!(
            code(jose(
                Some(r#"{"alg":"HS256","crit":["x-a"]}"#),
                Some(r#"{"x-a":1}"#)
            )),
            "ok"
        );
        // Malformed lists are rejected while parsing the header itself.
        for crit in [r#"[]"#, r#"["alg"]"#, r#"["b64","b64"]"#, r#""b64""#] {
            let json = format!(r#"{{"alg":"HS256","b64":false,"crit":{crit}}}"#);
            assert_eq!(
                Header::from_json(json.as_bytes())
                    .map(drop)
                    .unwrap_err()
                    .code(),
                "InvalidHeader",
                "{crit}"
            );
        }
    }

    #[test]
    fn b64_must_be_protected_and_critical() {
        // RFC 7797 §3: b64 MUST be integrity protected.
        assert_eq!(
            code(jose(Some(r#"{"alg":"HS256"}"#), Some(r#"{"b64":false}"#))),
            "InvalidHeader"
        );
        // RFC 7797 §6, ADR 0026 §2 step 4 (d3): b64 must be listed in crit,
        // whatever its value.
        for p in [
            r#"{"alg":"HS256","b64":false}"#,
            r#"{"alg":"HS256","b64":true}"#,
            r#"{"alg":"HS256","b64":false,"crit":["x-a"],"x-a":1}"#,
        ] {
            assert_eq!(code(jose(Some(p), None)), "InvalidHeader", "{p}");
        }
        let f = jose(Some(r#"{"alg":"HS256","b64":false,"crit":["b64"]}"#), None).unwrap();
        assert!(!f.b64());
        let t = jose(Some(r#"{"alg":"HS256","b64":true,"crit":["b64"]}"#), None).unwrap();
        assert!(t.b64());
        // crit lists b64 but b64 is absent (RFC 7515 §4.1.11).
        assert_eq!(
            code(jose(Some(r#"{"alg":"HS256","crit":["b64"]}"#), None)),
            "InvalidHeader"
        );
    }

    #[test]
    fn alg_must_be_present() {
        // RFC 7515 §4.1.1: alg MUST be present (ADR 0026 §2 step 4).
        assert_eq!(code(jose(Some(r#"{"typ":"JWT"}"#), None)), "InvalidHeader");
        assert_eq!(
            code(jose(Some(r#"{"typ":"JWT"}"#), Some(r#"{"kid":"k"}"#))),
            "InvalidHeader"
        );
        assert_eq!(code(jose(None, None)), "InvalidHeader");
        // An unknown alg is not step 4's concern (step 6).
        assert_eq!(code(jose(Some(r#"{"alg":"HS1"}"#), None)), "ok");
    }

    #[test]
    fn duplicate_header_member_is_invalid_json() {
        // ADR 0041 §1, amending ADR 0026 §2 step 4: the JSON layer rejects
        // it before any header rule runs, so the code is InvalidJson.
        for json in [
            r#"{"alg":"HS256","alg":"none"}"#,
            r#"{"alg":"HS256","alg":"none"}"#,
            r#"{"alg":"HS256","b64":false,"crit":["b64"],"b64":true}"#,
        ] {
            let parsed = Header::from_json(json.as_bytes()).map(drop);
            assert_eq!(parsed.unwrap_err().code(), "InvalidJson", "{json}");
            let encoded = b64url_encode(json.as_bytes());
            let protected = ProtectedHeader::from_encoded(&encoded).map(drop);
            assert_eq!(protected.unwrap_err().code(), "InvalidJson", "{json}");
        }
    }

    #[test]
    fn b64_must_agree_across_signatures() {
        // RFC 7797 §3: the same b64 value for every signature, the absent
        // value being the default, true.
        let f = || jose(Some(r#"{"alg":"HS256","b64":false,"crit":["b64"]}"#), None).unwrap();
        let t = || jose(Some(r#"{"alg":"HS256","b64":true,"crit":["b64"]}"#), None).unwrap();
        let absent = || jose(Some(r#"{"alg":"HS256"}"#), None).unwrap();
        let unprotected_only = || jose(None, Some(r#"{"alg":"HS256"}"#)).unwrap();
        assert_eq!(common_b64(&[f(), f()]), Ok(false));
        assert_eq!(common_b64(&[t(), absent(), unprotected_only()]), Ok(true));
        assert_eq!(common_b64(&[absent()]), Ok(true));
        assert_eq!(common_b64(&[]), Ok(true));
        for headers in [[f(), absent()], [absent(), f()], [t(), f()]] {
            assert_eq!(
                common_b64(&headers).map_err(|e| e.code()),
                Err("InvalidHeader")
            );
        }
    }

    // ---- Steps 5-9 and the ADR 0026 §2 precedence ----

    use SigningAlg as A;

    fn hj(protected: &str) -> JoseHeader {
        jose(Some(protected), None).unwrap()
    }

    fn opts(allowed: &[SigningAlg]) -> VerifyOptions<'_> {
        VerifyOptions::new(allowed).unwrap()
    }

    /// Steps 5-8 for verification, as an error code.
    fn verify_code(protected: &str, key: &Jwk, allowed: &[SigningAlg]) -> &'static str {
        check_verify(&hj(protected), key, &opts(allowed)).map_or_else(|e| e.code(), |_| "ok")
    }

    #[test]
    fn verify_policy_each_step() {
        let hs = keys::oct(32, "");
        // Step 5: crit names must be understood (RFC 7515 §4.1.11).
        assert_eq!(
            verify_code(
                r#"{"alg":"HS256","crit":["x-a"],"x-a":1}"#,
                &hs,
                &[A::HS256]
            ),
            "UnknownCritical"
        );
        assert_eq!(
            verify_code(
                r#"{"alg":"HS256","b64":false,"crit":["b64"]}"#,
                &hs,
                &[A::HS256]
            ),
            "ok"
        );
        // Step 6: a known alg (RFC 7515 §4.1.1).
        assert_eq!(
            verify_code(r#"{"alg":"HS1"}"#, &hs, &[A::HS256]),
            "UnsupportedAlgorithm"
        );
        assert_eq!(
            verify_code(r#"{"alg":"RSA1_5"}"#, &hs, &[A::HS256]),
            "UnsupportedAlgorithm"
        );
        // Step 7: the allow-list; `none` never passes (RFC 8725 §3.1).
        assert_eq!(
            verify_code(r#"{"alg":"HS384"}"#, &hs, &[A::HS256]),
            "AlgorithmNotAllowed"
        );
        assert_eq!(
            verify_code(r#"{"alg":"none"}"#, &hs, &[A::HS256]),
            "AlgorithmNotAllowed"
        );
        // Step 8: key binding.
        assert_eq!(
            verify_code(r#"{"alg":"ES256"}"#, &hs, &[A::ES256]),
            "KeyAlgorithmMismatch"
        );
        assert_eq!(
            verify_code(r#"{"alg":"HS512"}"#, &hs, &[A::HS512]),
            "InvalidKey"
        );
        assert_eq!(
            check_verify(&hj(r#"{"alg":"HS256"}"#), &hs, &opts(&[A::HS256])),
            Ok(A::HS256)
        );
    }

    #[test]
    fn precedence_follows_the_adr_0026_order() {
        let rsa = keys::rsa(2048);
        let hs = keys::oct(32, "");
        // Unknown crit (5) and a disallowed alg (7): UnknownCritical.
        assert_eq!(
            verify_code(
                r#"{"alg":"HS512","crit":["x-a"],"x-a":1}"#,
                &hs,
                &[A::HS256]
            ),
            "UnknownCritical"
        );
        // Unknown crit (5) and an unknown alg (6): UnknownCritical.
        assert_eq!(
            verify_code(r#"{"alg":"HS1","crit":["x-a"],"x-a":1}"#, &hs, &[A::HS256]),
            "UnknownCritical"
        );
        // Unknown alg (6) can't be allowed (7) either: UnsupportedAlgorithm.
        assert_eq!(
            verify_code(r#"{"alg":"XS256"}"#, &rsa, &[A::RS256]),
            "UnsupportedAlgorithm"
        );
        // A disallowed alg (7) with a mismatched key (8): AlgorithmNotAllowed.
        assert_eq!(
            verify_code(r#"{"alg":"HS256"}"#, &rsa, &[A::RS256]),
            "AlgorithmNotAllowed"
        );
        // `none` with any key and list: AlgorithmNotAllowed, never a key error.
        assert_eq!(
            verify_code(r#"{"alg":"none"}"#, &rsa, &[A::RS256]),
            "AlgorithmNotAllowed"
        );
        // Step 4 beats them all: crit listing an absent name, with `none`.
        assert_eq!(
            code(jose(Some(r#"{"alg":"none","crit":["x-a"]}"#), None)),
            "InvalidHeader"
        );
        // A mismatched key (8) is reported before any signature check (9).
        let hdr = hj(r#"{"alg":"HS256"}"#);
        assert_eq!(
            verify_signature(&FAKE, &hdr, &rsa, &opts(&[A::HS256]), b"x", b""),
            Err(Error::KeyAlgorithmMismatch)
        );
    }

    #[test]
    fn verify_signature_runs_step_9_through_the_families_table() {
        let key = keys::oct(32, "");
        let hdr = hj(r#"{"alg":"HS256"}"#);
        let o = opts(&[A::HS256]);
        let input = signing_input("eyJhbGciOiJIUzI1NiJ9", b"$.02", hdr.b64());
        let sig = fake_signature(&A::HS256, &input);
        assert_eq!(
            verify_signature(&FAKE, &hdr, &key, &o, &input, &sig),
            Ok(A::HS256)
        );
        assert_eq!(
            verify_signature(&FAKE, &hdr, &key, &o, &input, &sig[1..]),
            Err(Error::InvalidSignature)
        );
        assert_eq!(
            verify_signature(&REJECTING, &hdr, &key, &o, &input, &sig),
            Err(Error::InvalidSignature)
        );
    }

    #[test]
    fn sign_policy_each_step() {
        let hs = keys::oct(32, "");
        let sign_code = |protected: &str, key: &Jwk| {
            prepare_sign(&hj(protected), key).map_or_else(|e| e.code(), |_| "ok")
        };
        assert_eq!(
            sign_code(r#"{"alg":"HS256","crit":["x-a"],"x-a":1}"#, &hs),
            "UnknownCritical"
        );
        assert_eq!(sign_code(r#"{"alg":"HS1"}"#, &hs), "UnsupportedAlgorithm");
        // RFC 8725 §3.2: never produce `none`.
        assert_eq!(sign_code(r#"{"alg":"none"}"#, &hs), "AlgorithmNotAllowed");
        // ADR 0021: no RSA signing, whatever the key.
        assert_eq!(
            sign_code(r#"{"alg":"RS256"}"#, &keys::rsa(2048)),
            "UnsupportedAlgorithm"
        );
        assert_eq!(sign_code(r#"{"alg":"PS256"}"#, &hs), "UnsupportedAlgorithm");
        // Key binding: a public key cannot sign; a short HMAC key is weak.
        assert_eq!(
            sign_code(r#"{"alg":"ES256"}"#, &keys::p256("")),
            "KeyAlgorithmMismatch"
        );
        assert_eq!(sign_code(r#"{"alg":"HS512"}"#, &hs), "InvalidKey");
        // b64 false is fine to sign once it is critical (RFC 7797 §6).
        assert_eq!(
            sign_code(r#"{"alg":"HS256","b64":false,"crit":["b64"]}"#, &hs),
            "ok"
        );
    }

    #[test]
    fn prepared_signature_round_trips() {
        let key = keys::oct(32, "");
        let hdr = jose(Some(r#"{"alg":"HS256"}"#), Some(r#"{"kid":"k"}"#)).unwrap();
        let ready = prepare_sign(&hdr, &key).unwrap();
        assert_eq!(ready.alg(), &A::HS256);
        let input = signing_input("eyJhbGciOiJIUzI1NiJ9", b"payload", hdr.b64());
        let sig = ready.sign(&FAKE, &input).unwrap();
        assert_eq!(
            verify_signature(&FAKE, &hdr, &key, &opts(&[A::HS256]), &input, &sig),
            Ok(A::HS256)
        );
    }

    #[test]
    fn progress_ranking_matches_adr_0026_section_3() {
        let ranked = [
            Error::InvalidSignature,
            Error::InvalidKey("k"),
            Error::KeyAlgorithmMismatch,
            Error::AlgorithmNotAllowed,
            Error::UnsupportedAlgorithm,
            Error::UnknownCritical,
        ];
        for pair in ranked.windows(2) {
            assert!(
                progress_rank(&pair[0]) > progress_rank(&pair[1]),
                "{pair:?}"
            );
        }
        // Errors of steps 1-4 never come out of steps 5-9; they rank last.
        assert!(progress_rank(&Error::UnknownCritical) > progress_rank(&Error::InvalidHeader("h")));
    }

    #[test]
    fn furthest_error_wins_with_ties_to_the_lowest_index() {
        use Error as E;
        // T05's named cases (ADR 0026 §3).
        assert_eq!(
            furthest([E::InvalidSignature, E::AlgorithmNotAllowed]),
            Some(E::InvalidSignature)
        );
        assert_eq!(
            furthest([E::AlgorithmNotAllowed, E::InvalidSignature]),
            Some(E::InvalidSignature)
        );
        assert_eq!(
            furthest([E::UnknownCritical, E::UnknownCritical]),
            Some(E::UnknownCritical)
        );
        // Ties go to the lowest index (the detail tells them apart).
        assert_eq!(
            furthest([
                E::UnknownCritical,
                E::InvalidKey("first"),
                E::InvalidKey("second")
            ]),
            Some(E::InvalidKey("first"))
        );
        assert_eq!(furthest([]), None);
    }

    #[test]
    fn multi_signature_flow_with_the_shared_helpers() {
        // How json.rs composes the helpers (ADR 0026 §3): step 4 over all
        // signatures, common b64, then steps 5-9 per signature, first
        // success wins, else the furthest error.
        let key = keys::oct(32, "");
        let headers = [
            hj(r#"{"alg":"HS256","crit":["x-a"],"x-a":1}"#), // UnknownCritical
            hj(r#"{"alg":"HS384"}"#),                        // AlgorithmNotAllowed
            hj(r#"{"alg":"HS256"}"#),                        // InvalidSignature (bad sig)
            hj(r#"{"alg":"HS256","kid":"good"}"#),           // verifies
        ];
        let b64 = common_b64(&headers).unwrap();
        let o = opts(&[A::HS256]);
        let run = |count: usize| {
            let mut errors = Vec::new();
            for (index, hdr) in headers.iter().take(count).enumerate() {
                let input = signing_input("", b"p", b64);
                let sig = if index == 3 {
                    fake_signature(&A::HS256, &input)
                } else {
                    vec![0]
                };
                match verify_signature(&FAKE, hdr, &key, &o, &input, &sig) {
                    Ok(_) => return Ok(index),
                    Err(e) => errors.push(e),
                }
            }
            Err(furthest(errors))
        };
        assert_eq!(run(4), Ok(3));
        assert_eq!(run(3), Err(Some(Error::InvalidSignature)));
        assert_eq!(run(2), Err(Some(Error::AlgorithmNotAllowed)));
        assert_eq!(run(1), Err(Some(Error::UnknownCritical)));
    }
}
