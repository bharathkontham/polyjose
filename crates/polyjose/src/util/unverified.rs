//! The unverified decode utilities of ADR 0069, re-exported from
//! [`crate::util`], whose module docs describe them.

use core::fmt;

use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::header::Header;
use crate::jws::{VerifyOptions, parse_compact};
use crate::jwt::Claims;
use crate::jwt::typ::check_signed_layer_structure;

use super::b64url_decode;

/// The fixed input limit of the three utilities: 1 MiB, the default of
/// ADR 0026 §7 that verification uses too (ADR 0069 §2, "Limits").
const MAX_INPUT_LEN: usize = VerifyOptions::DEFAULT_MAX_INPUT_LEN;

/// A compact JWS read without verifying it: its JWS Protected Header and
/// its JWS Payload, as [`decode_jws_unverified`] returns them (ADR 0069
/// §1, §4). This doesn't check the signature: anyone can write these
/// values, so don't use them for authorization or trust decisions until
/// you verify the token. Verify it with
/// [`jws::verify_compact`](crate::jws::verify_compact).
///
/// See the [`util` module docs](crate::util#unverified-decode) for using a
/// `kid` (RFC 8725 §3.10).
///
/// It is not a [`jws::Verified`](crate::jws::Verified) and has no `alg`
/// member: the `alg` is in [`protected`](Self::protected), unchecked, and
/// may be `none` or unknown. No conversion between the two exists.
///
/// `Debug` prints the header through [`Header`]'s redacting `Debug` and
/// the payload's length, never its octets (ADR 0069 §5).
#[derive(Clone, PartialEq)]
#[non_exhaustive]
#[must_use]
pub struct UnverifiedJws {
    /// The JWS Protected Header (RFC 7515 §4), which in the Compact
    /// Serialization is the whole JOSE Header (RFC 7515 §7.1). Unverified.
    pub protected: Header,
    /// The JWS Payload (RFC 7515 §2): base64url-decoded, or the payload
    /// part's octets as they are when `b64` is `false` (RFC 7797 §3), or
    /// empty for a detached payload (RFC 7515 Appendix F). Unverified.
    ///
    /// Treated as secret like every JWS payload, so it is wiped when
    /// dropped (ADR 0049 §4, ADR 0069 §5). Copying it out (`to_vec`,
    /// `mem::take`) leaves the copy unprotected.
    pub payload: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for UnverifiedJws {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnverifiedJws")
            .field("protected", &self.protected)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

/// A compact signed JWT read without verifying or validating it: its JWS
/// Protected Header and its JWT Claims Set, as [`decode_jwt_unverified`]
/// returns them (ADR 0069 §1, §4). This doesn't check the signature:
/// anyone can write these values, so don't use them for authorization or
/// trust decisions until you verify the token. Verify it with
/// [`jwt::verify`](crate::jwt::verify).
///
/// No claim was validated: the token may be expired, not yet valid, or
/// for another audience. If you read `iss` to choose a key set, verify
/// with [`Policy::issuer`](crate::jwt::Policy::issuer) set to it
/// (RFC 8725 §3.8); see the [`util` module docs](crate::util#unverified-decode).
///
/// It is not a [`VerifiedJwt`](crate::jwt::VerifiedJwt) and has no `alg`
/// member: the `alg` is in [`header`](Self::header), unchecked, and may be
/// `none` or unknown. No conversion between the two exists.
///
/// `Debug` prints the header and the claims through their redacting
/// `Debug` (see [`Header`#debug] and [`Claims`#debug]).
#[derive(Clone, PartialEq)]
#[non_exhaustive]
#[must_use]
pub struct UnverifiedJwt {
    /// The JWS Protected Header (RFC 7515 §4; RFC 7519 §5), the whole JOSE
    /// Header of a compact JWS (RFC 7515 §7.1). Unverified.
    pub header: Header,
    /// The JWT Claims Set (RFC 7519 §4), parsed and type-checked
    /// (ADR 0027 §1–§2) but not validated. Unverified.
    pub claims: Claims,
}

impl fmt::Debug for UnverifiedJwt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnverifiedJwt")
            .field("header", &self.header)
            .field("claims", &self.claims)
            .finish()
    }
}

/// This doesn't check the signature: anyone can write these values, so
/// don't use them for authorization or trust decisions until you verify
/// the token.
///
/// Reads the JOSE Protected Header of a compact JWS or JWE without
/// verifying or decrypting anything (ADR 0069 §1–§2, §4; RFC 7515 §5.2
/// steps 1–3, §7.1; RFC 7516 §5.2 steps 1–3, §7.1). Verify the token with
/// [`jwt::verify`](crate::jwt::verify) or
/// [`jws::verify_compact`](crate::jws::verify_compact).
///
/// Sanitise a `kid` before using it in a lookup, and take keys from your
/// own configuration, not from `jku` or `x5u` (RFC 8725 §3.10). A
/// [`JwkSet`] passed as [`Keys::Set`] already selects by `kid` during
/// verification (ADR 0029).
///
/// Only the first part is read. A five-part input is a compact JWE
/// (RFC 7516 §7.1); for a nested JWT that is the outer header. The
/// payload, ciphertext and signature are not looked at.
///
/// ```
/// use polyjose::util::decode_protected_header_unverified;
///
/// // RFC 7516 Appendix A.3: a compact JWE; nothing is decrypted.
/// let jwe = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.U0m_YmjN04DJvceFICbCVQ";
/// let header = decode_protected_header_unverified(jwe)?;
/// assert_eq!(header.alg.as_deref(), Some("A128KW"));
/// # Ok::<(), polyjose::Error>(())
/// ```
///
/// # Errors
///
/// In this order (ADR 0069 §2):
///
/// - [`Error::InvalidFormat`]: longer than 1 MiB (ADR 0026 §7), or not
///   exactly three or five `.`-separated parts (RFC 7515 §7.1,
///   RFC 7516 §7.1).
/// - [`Error::InvalidBase64`]: the first part is not strict unpadded
///   base64url (RFC 7515 §2).
/// - [`Error::InvalidJson`]: its octets are not one I-JSON object, or
///   repeat a member name (RFC 7515 §5.2 step 3; ADR 0041 §1).
/// - [`Error::InvalidHeader`]: a registered parameter has the wrong type
///   or `crit` is malformed ([`Header::from_json`]; RFC 7515 §4.1.11,
///   RFC 7516 §4.1.13).
///
/// A JSON Serialization (RFC 7515 §7.2, RFC 7516 §7.2) is not read. JSON
/// text is [`Error::InvalidFormat`] by the part count, except when it
/// happens to contain exactly two or four `.`: its first part then starts
/// with `{`, which is not base64url, so it is [`Error::InvalidBase64`].
///
/// [`JwkSet`]: crate::jwk::JwkSet
/// [`Keys::Set`]: crate::jwt::Keys::Set
pub fn decode_protected_header_unverified(token: &str) -> Result<Header> {
    // ADR 0026 §7: the input limit, before any parsing.
    if token.len() > MAX_INPUT_LEN {
        return Err(Error::InvalidFormat(
            "compact token exceeds the 1 MiB input limit",
        ));
    }
    // RFC 7515 §7.1 (three parts, two '.') or RFC 7516 §7.1 (five parts,
    // four '.'); the shape only, the other parts are not decoded.
    let parts = token.split('.').count();
    if parts != 3 && parts != 5 {
        return Err(Error::InvalidFormat(
            "compact token must have three (JWS) or five (JWE) parts",
        ));
    }
    let first = token.split_once('.').map_or(token, |(first, _)| first);
    // RFC 7515 §5.2 steps 2–3 / RFC 7516 §5.2 steps 2–3: strict base64url,
    // then I-JSON and the parameter types. The decoded octets are wiped
    // (as in `jws::ProtectedHeader::from_encoded`).
    let json = Zeroizing::new(b64url_decode(first)?);
    Header::from_json(&json)
}

/// This doesn't check the signature: anyone can write these values, so
/// don't use them for authorization or trust decisions until you verify
/// the token.
///
/// Reads the protected header and the payload of a compact JWS without
/// verifying it (ADR 0069 §1–§4; RFC 7515 §5.2 steps 1–4 and 6–7, §7.1).
/// Verify the JWS with [`jws::verify_compact`](crate::jws::verify_compact).
///
/// Sanitise a `kid` before using it in a lookup, and take keys from your
/// own configuration, not from `jku` or `x5u` (RFC 8725 §3.10).
///
/// It runs exactly steps 1–5 of ADR 0048, the same code
/// [`jws::verify_compact`](crate::jws::verify_compact) runs, and stops
/// there: it succeeds exactly when verification would get past step 5,
/// and fails with the same code otherwise, except a JSON serialization,
/// which is always `InvalidFormat`. Steps 6a–6e (`crit`
/// understood, `alg` known, `alg` allowed, key binding, the signature) are
/// skipped, so `alg: none` (ADR 0007), an unknown `alg` and an unknown
/// `crit` entry (RFC 7515 §4.1.11) are returned as data. The signature
/// part must still be strict base64url, and is not returned.
///
/// - With `b64: false` (RFC 7797 §3) the payload is the payload part's
///   octets as they are.
/// - A detached payload (RFC 7515 Appendix F, `header..signature`) gives
///   an empty payload, as an attached empty payload does.
///
/// ```
/// use polyjose::util::decode_jws_unverified;
///
/// // RFC 7515 Appendix A.5: an Unsecured JWS, returned as data.
/// let jws = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.";
/// let decoded = decode_jws_unverified(jws)?;
/// assert_eq!(decoded.protected.alg.as_deref(), Some("none"));
/// assert!(decoded.payload.starts_with(b"{\"iss\":\"joe\""));
/// # Ok::<(), polyjose::Error>(())
/// ```
///
/// # Errors
///
/// Steps 1–5 of ADR 0048, as [`jws::verify_compact`](crate::jws::verify_compact)
/// reports them:
///
/// - Step 1, [`Error::InvalidFormat`]: longer than 1 MiB (ADR 0026 §7),
///   or not three parts (RFC 7515 §7.1). A JWS JSON Serialization (input
///   starting with `{`, RFC 7515 §7.2) is always `InvalidFormat`: only the
///   compact form is decoded (ADR 0069 §2).
/// - Step 2, [`Error::InvalidBase64`]: the signature part.
/// - Step 3, the protected header: [`Error::InvalidBase64`],
///   [`Error::InvalidJson`] (a duplicate member included, ADR 0041 §1), or
///   [`Error::InvalidHeader`] for a registered parameter of the wrong type
///   or a malformed `crit`.
/// - Step 4, [`Error::InvalidBase64`]: the payload part, unless `b64` is
///   `false` (RFC 7797 §3).
/// - Step 5, [`Error::InvalidHeader`]: `alg` missing, `crit` naming an
///   absent parameter, `b64` not listed in `crit` (RFC 7515 §4.1.1,
///   §4.1.11; RFC 7797 §6).
pub fn decode_jws_unverified(jws: &str) -> Result<UnverifiedJws> {
    // Steps 1-5 (ADR 0048), the shared parser, with the default limit and
    // no detached payload.
    let parsed = match parse_compact(jws, MAX_INPUT_LEN, None) {
        Ok(parsed) => parsed,
        // A JSON Serialization can never parse as compact ('{' is not
        // base64url, RFC 7515 §2); it is reported as the wrong
        // serialization, InvalidFormat, whichever step 1-3 caught it.
        Err(_) if is_json_serialization(jws) => {
            return Err(Error::InvalidFormat(
                "JWS JSON Serialization is not decoded; compact only",
            ));
        }
        Err(e) => return Err(e),
    };
    let (protected, payload) = parsed.into_header_and_payload();
    Ok(UnverifiedJws { protected, payload })
}

/// This doesn't check the signature: anyone can write these values, so
/// don't use them for authorization or trust decisions until you verify
/// the token.
///
/// Reads the header and the claims of a compact signed JWT without
/// verifying or validating it (ADR 0069 §1–§2, §4; RFC 7519 §7.2 steps 1–6
/// and 10, without the signature). Verify the token with
/// [`jwt::verify`](crate::jwt::verify).
///
/// No claim is validated: an expired token, a token for another audience
/// or with an unknown `crit` entry decodes all the same. If you read `iss`
/// to choose an issuer's key set, verify with
/// [`Policy::issuer`](crate::jwt::Policy::issuer) set to that issuer, so
/// the keys are bound to it (RFC 8725 §3.8). Sanitise a `kid` before using
/// it in a lookup, and take keys from your own configuration, not from
/// `jku` or `x5u` (RFC 8725 §3.10); a [`JwkSet`] passed as [`Keys::Set`]
/// already selects by `kid` (ADR 0029).
///
/// In order:
///
/// 1. [`decode_jws_unverified`]: steps 1–5 of ADR 0048, with the same
///    code as verification, except a JSON serialization, which is always
///    `InvalidFormat`. A five-part token
///    (a nested JWT, RFC 7519 §5.2) is [`Error::InvalidFormat`]; its outer
///    header can be read with [`decode_protected_header_unverified`].
/// 2. The rules of ADR 0027 §9 J1 that need no policy: `b64: false`
///    (RFC 7797 §7: "JSON Web Tokens MUST NOT use "b64" with a "false"
///    value") and `cty: JWT` on the signed layer (a JWS nested in a JWS,
///    RFC 7519 §5.2, not supported) are both [`Error::InvalidHeader`].
///    There is no `typ` policy.
/// 3. ADR 0027 §9 J3, the Claims Set ([`Claims::from_json`]; RFC 7519
///    §7.2 step 10, following erratum 8225).
///
/// Nothing of J2 and J4–J10 runs: no key, no signature, no `exp`, `nbf`,
/// `iat`, `iss`, `sub` or `aud` check, and no clock.
///
/// ```
/// use polyjose::util::decode_jwt_unverified;
///
/// // RFC 7519 §3.1 (RFC 7515 Appendix A.1): expired since 2011, decoded.
/// let token = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
/// let decoded = decode_jwt_unverified(token)?;
/// assert_eq!(decoded.header.alg.as_deref(), Some("HS256"));
/// assert_eq!(decoded.claims.iss.as_deref(), Some("joe"));
/// # Ok::<(), polyjose::Error>(())
/// ```
///
/// # Errors
///
/// - As [`decode_jws_unverified`]: [`Error::InvalidFormat`],
///   [`Error::InvalidBase64`], [`Error::InvalidJson`],
///   [`Error::InvalidHeader`].
/// - [`Error::InvalidHeader`]: `b64: false`, or `cty` equal to `JWT`.
/// - [`Error::InvalidJson`]: the payload is not UTF-8, not one JSON
///   object, or repeats a member name (RFC 7519 §7.2 step 10).
/// - [`Error::InvalidClaim`]: a registered claim has the wrong type
///   (ADR 0027 §1–§2), for example `"exp": "x"`.
///
/// [`JwkSet`]: crate::jwk::JwkSet
/// [`Keys::Set`]: crate::jwt::Keys::Set
pub fn decode_jwt_unverified(token: &str) -> Result<UnverifiedJwt> {
    // RFC 7519 §7.2 steps 1-6 without the signature: the JWS steps 1-5.
    let UnverifiedJws { protected, payload } = decode_jws_unverified(token)?;
    // J1 without the `typ` policy (ADR 0027 §9; RFC 7797 §7, RFC 7519
    // §5.2).
    check_signed_layer_structure(&protected)?;
    // J3 (RFC 7519 §7.2 step 10): parsed from the wiping buffer, which is
    // wiped when this function returns (ADR 0049 §4).
    let claims = Claims::from_json(&payload)?;
    Ok(UnverifiedJwt {
        header: protected,
        claims,
    })
}

/// Whether `input` is a JSON Serialization rather than a compact one: its
/// first character after JSON whitespace (RFC 8259 §2) is `{`, which opens
/// a JWS or JWE JSON object (RFC 7515 §7.2, RFC 7516 §7.2) and is never
/// base64url (RFC 7515 §2).
fn is_json_serialization(input: &str) -> bool {
    input
        .trim_start_matches([' ', '\t', '\n', '\r'])
        .starts_with('{')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwa::SigningAlg;
    use crate::jwk::Jwk;
    use crate::jws::{self, ProtectedHeader, SignOptions};

    /// RFC 7515 Appendix A.1 / RFC 7519 §3.1.
    const A1: &str = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    /// The A.1 payload octets as printed (RFC 7515 A.1.1, with CRLF).
    const A1_PAYLOAD: &[u8] =
        b"{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";
    /// The RFC 7515 A.1 HMAC key.
    const A1_KEY: &str = r#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#;

    fn b64(json: &str) -> String {
        super::super::b64url_encode(json.as_bytes())
    }

    /// A compact token from a header JSON, a payload part and a signature
    /// part, unsigned (the signature is never checked here).
    fn token(header: &str, payload_part: &str) -> String {
        format!("{}.{payload_part}.c2ln", b64(header))
    }

    /// The signatures frozen by 0026 T01 (ADR 0069 §1). T02 and T03 code
    /// against them; changing one is a contract change.
    #[test]
    fn signatures_are_frozen() {
        let _: fn(&str) -> Result<Header> = decode_protected_header_unverified;
        let _: fn(&str) -> Result<UnverifiedJws> = decode_jws_unverified;
        let _: fn(&str) -> Result<UnverifiedJwt> = decode_jwt_unverified;
        let jws = decode_jws_unverified(A1).unwrap();
        let _: (&Header, &Zeroizing<Vec<u8>>) = (&jws.protected, &jws.payload);
        let jwt = decode_jwt_unverified(A1).unwrap();
        let _: (&Header, &Claims) = (&jwt.header, &jwt.claims);
        let _: fn(&Header) -> Result<()> = check_signed_layer_structure;
        assert_eq!(MAX_INPUT_LEN, 1024 * 1024);
    }

    #[test]
    fn jws_decode_returns_the_rfc_7515_a1_header_and_payload() {
        let jws = decode_jws_unverified(A1).unwrap();
        assert_eq!(jws.protected.typ.as_deref(), Some("JWT"));
        assert_eq!(jws.protected.alg.as_deref(), Some("HS256"));
        assert_eq!(&jws.payload[..], A1_PAYLOAD);
    }

    #[test]
    fn jwt_decode_returns_the_rfc_7519_3_1_claims_without_validating() {
        // exp 1300819380 is in 2011: no clock, no validation.
        let jwt = decode_jwt_unverified(A1).unwrap();
        assert_eq!(jwt.claims.iss.as_deref(), Some("joe"));
        assert_eq!(
            jwt.claims.exp.and_then(|d| d.as_secs()),
            Some(1_300_819_380)
        );
        assert_eq!(
            jwt.claims.other_claims().get("http://example.com/is_root"),
            Some(&crate::json::Value::Bool(true))
        );
    }

    #[test]
    fn header_peek_reads_only_the_first_part_of_three_or_five() {
        // RFC 7515 §7.1 / RFC 7516 §7.1. Garbage in the other parts is not
        // looked at.
        let header = b64(r#"{"alg":"ES256","kid":"k1"}"#);
        for t in [
            format!("{header}.!!.!!"),
            format!("{header}.!.!.!.!"),
            format!("{header}.."),
            format!("{header}...."),
        ] {
            let h = decode_protected_header_unverified(&t).unwrap();
            assert_eq!(h.kid.as_deref(), Some("k1"), "{t}");
        }
        for t in [
            header.clone(),
            format!("{header}."),
            format!("{header}..."),
            format!("{header}....."),
        ] {
            assert!(
                matches!(
                    decode_protected_header_unverified(&t),
                    Err(Error::InvalidFormat(_))
                ),
                "{t}"
            );
        }
    }

    #[test]
    fn header_peek_errors_are_the_header_parse_codes() {
        // RFC 7515 §2 strict base64url; ADR 0041 §1 duplicates; types.
        let cases = [
            (format!("{}=..", b64(r#"{"alg":"x"}"#)), "InvalidBase64"),
            (
                format!("{}..", b64(r#"{"alg":"a","alg":"b"}"#)),
                "InvalidJson",
            ),
            (format!("{}..", b64(r#"["alg"]"#)), "InvalidJson"),
            (
                format!("{}..", b64(r#"{"alg":"x","kid":1}"#)),
                "InvalidHeader",
            ),
        ];
        for (t, code) in cases {
            let e = decode_protected_header_unverified(&t).unwrap_err();
            assert_eq!(e.code(), code, "{t}");
        }
    }

    #[test]
    fn header_peek_does_not_require_alg_or_check_crit_presence() {
        // Only `Header::from_json`'s checks: the JWS structure rules
        // (alg present, crit names present) are step 5, not a peek's.
        let h = decode_protected_header_unverified(&format!("{}..", b64("{}"))).unwrap();
        assert_eq!(h.alg, None);
        let h = decode_protected_header_unverified(&format!(
            "{}..",
            b64(r#"{"alg":"x","crit":["urn:x"]}"#)
        ))
        .unwrap();
        assert_eq!(h.crit, Some(vec!["urn:x".to_owned()]));
    }

    #[test]
    fn the_input_limit_is_one_mebibyte_for_every_utility() {
        // ADR 0026 §7: 1 MiB is accepted, one octet more is not.
        let header = b64(r#"{"alg":"none"}"#);
        let fill = MAX_INPUT_LEN - header.len() - 2;
        let at_limit = format!("{header}.{}.", "A".repeat(fill));
        assert_eq!(at_limit.len(), MAX_INPUT_LEN);
        assert!(decode_protected_header_unverified(&at_limit).is_ok());
        assert!(decode_jws_unverified(&at_limit).is_ok());
        let over = format!("{header}.{}.", "A".repeat(fill + 1));
        assert!(matches!(
            decode_protected_header_unverified(&over),
            Err(Error::InvalidFormat(_))
        ));
        assert!(matches!(
            decode_jws_unverified(&over),
            Err(Error::InvalidFormat(_))
        ));
        assert!(matches!(
            decode_jwt_unverified(&over),
            Err(Error::InvalidFormat(_))
        ));
    }

    #[test]
    fn jws_decode_returns_none_unknown_alg_and_unknown_crit_as_data() {
        // ADR 0007, RFC 7515 §4.1.11, RFC 8725 §3.1: verification refuses
        // these at step 6; decode stops at step 5.
        let none = decode_jws_unverified(&token(r#"{"alg":"none"}"#, "cA")).unwrap();
        assert_eq!(none.protected.alg.as_deref(), Some("none"));
        let unknown = decode_jws_unverified(&token(r#"{"alg":"XX999"}"#, "cA")).unwrap();
        assert_eq!(unknown.protected.alg.as_deref(), Some("XX999"));
        let crit = decode_jws_unverified(&token(
            r#"{"alg":"HS256","crit":["urn:x"],"urn:x":1}"#,
            "cA",
        ))
        .unwrap();
        assert_eq!(crit.protected.crit, Some(vec!["urn:x".to_owned()]));
        assert_eq!(&crit.payload[..], b"p");
    }

    #[test]
    fn jws_decode_steps_1_to_5_keep_their_codes() {
        let cases = [
            // Step 1: shape.
            ("a.b".to_owned(), "InvalidFormat"),
            ("a.b.c.d.e".to_owned(), "InvalidFormat"),
            // Step 2: the signature part.
            (
                format!("{}.cA.c2ln=", b64(r#"{"alg":"x"}"#)),
                "InvalidBase64",
            ),
            // Step 3: header base64url, JSON, types.
            ("eyJ=.cA.c2ln".to_owned(), "InvalidBase64"),
            (token(r#"{"alg":"a","alg":"b"}"#, "cA"), "InvalidJson"),
            (token(r#"{"alg":1}"#, "cA"), "InvalidHeader"),
            // Step 4: the payload part.
            (token(r#"{"alg":"x"}"#, "cA="), "InvalidBase64"),
            // Step 5: structure.
            (token(r#"{"typ":"JWT"}"#, "cA"), "InvalidHeader"),
            (
                token(r#"{"alg":"x","crit":["urn:x"]}"#, "cA"),
                "InvalidHeader",
            ),
            (token(r#"{"alg":"x","b64":false}"#, "cA"), "InvalidHeader"),
        ];
        for (t, code) in cases {
            assert_eq!(decode_jws_unverified(&t).unwrap_err().code(), code, "{t}");
        }
    }

    #[test]
    fn json_serializations_are_invalid_format() {
        // RFC 7515 §7.2: only the compact form is decoded (ADR 0069 §2),
        // even when the JSON happens to hold exactly two '.'.
        for json in [
            r#"{"payload":"cA","protected":"eyJhbGciOiJIUzI1NiJ9","signature":"c2ln"}"#,
            r#" {"payload":"a.b","header":{"kid":"c.d"},"signature":"x"}"#,
            "\n\t{\"payload\":\"x.y\",\"signatures\":[{\"signature\":\"z.w\"}]}",
        ] {
            assert!(
                matches!(decode_jws_unverified(json), Err(Error::InvalidFormat(_))),
                "{json}"
            );
            assert!(
                matches!(decode_jwt_unverified(json), Err(Error::InvalidFormat(_))),
                "{json}"
            );
        }
    }

    #[test]
    fn unencoded_and_detached_payloads() {
        // RFC 7797 §3: the payload part's octets as they are.
        let attached = token(r#"{"alg":"HS256","b64":false,"crit":["b64"]}"#, "$-02 x");
        assert_eq!(
            &decode_jws_unverified(&attached).unwrap().payload[..],
            b"$-02 x"
        );
        // RFC 7515 Appendix F: detached is an empty payload.
        let detached = token(r#"{"alg":"HS256"}"#, "");
        assert!(decode_jws_unverified(&detached).unwrap().payload.is_empty());
        // RFC 7797 §7: never in a JWT, detached or attached.
        for t in [
            attached,
            token(r#"{"alg":"HS256","b64":false,"crit":["b64"]}"#, ""),
        ] {
            assert!(matches!(
                decode_jwt_unverified(&t),
                Err(Error::InvalidHeader("b64"))
            ));
        }
    }

    #[test]
    fn jwt_decode_refuses_cty_jwt_and_runs_no_typ_policy() {
        // RFC 7519 §5.2: a JWS in a JWS is not supported (ADR 0027 §7).
        let claims = b64(r#"{"sub":"a"}"#);
        for cty in ["JWT", "jwt", "application/JWT"] {
            let t = token(&format!(r#"{{"alg":"HS256","cty":"{cty}"}}"#), &claims);
            assert!(matches!(
                decode_jwt_unverified(&t),
                Err(Error::InvalidHeader("cty"))
            ));
        }
        // No `typ` policy: an explicit type that default validation refuses
        // (RFC 8725 §3.12) decodes.
        let t = token(r#"{"alg":"HS256","typ":"at+jwt","cty":"x"}"#, &claims);
        assert_eq!(
            decode_jwt_unverified(&t).unwrap().header.typ.as_deref(),
            Some("at+jwt")
        );
    }

    #[test]
    fn jwt_decode_claim_errors() {
        // RFC 7519 §7.2 step 10; ADR 0027 §1–§2.
        let header = r#"{"alg":"HS256"}"#;
        let cases = [
            (token(header, &b64("[1]")), "InvalidJson"),
            (token(header, ""), "InvalidJson"),
            (token(header, &b64(r#"{"a":1,"a":2}"#)), "InvalidJson"),
            (token(header, &b64(r#"{"exp":"x"}"#)), "InvalidClaim"),
            (token(header, &b64(r#"{"aud":5}"#)), "InvalidClaim"),
        ];
        for (t, code) in cases {
            assert_eq!(decode_jwt_unverified(&t).unwrap_err().code(), code, "{t}");
        }
    }

    #[test]
    fn decode_agrees_with_verify_on_a_signed_token() {
        let key = Jwk::from_json(A1_KEY.as_bytes()).unwrap();
        let mut header = Header::new();
        header.alg = Some("HS256".into());
        header.kid = Some("k1".into());
        let protected = ProtectedHeader::new(header).unwrap();
        let signed = jws::sign_compact(&protected, b"hello", &key, &SignOptions::new()).unwrap();
        let algs = [SigningAlg::HS256];
        let verified =
            jws::verify_compact(&signed, &key, &jws::VerifyOptions::new(&algs).unwrap()).unwrap();
        let decoded = decode_jws_unverified(&signed).unwrap();
        assert_eq!(decoded.payload, verified.payload);
        assert_eq!(Some(&decoded.protected), verified.protected.as_ref());
    }

    #[test]
    fn debug_prints_the_payload_length_only() {
        // ADR 0069 §5, ADR 0049 §4.
        let t = token(r#"{"alg":"none","kid":"k"}"#, &b64("MARKER-SECRET"));
        let jws = decode_jws_unverified(&t).unwrap();
        let printed = format!("{jws:?}");
        assert!(!printed.contains("MARKER-SECRET"), "{printed}");
        assert!(printed.contains("payload_len: 13"), "{printed}");
        let t = token(r#"{"alg":"none"}"#, &b64(r#"{"sub":"MARKER-SUB"}"#));
        let jwt = decode_jwt_unverified(&t).unwrap();
        let printed = format!("{jwt:?}");
        assert!(!printed.contains("MARKER-SUB"), "{printed}");
        assert!(printed.starts_with("UnverifiedJwt"), "{printed}");
    }
}
