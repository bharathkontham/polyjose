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
//! - the JWS Signing Input: [`signing_input`].

use std::collections::BTreeSet;

use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::header::Header;
use crate::json::{Object, Value};
use crate::util::b64url_encode;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jws::ProtectedHeader;
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
}
