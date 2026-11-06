//! JWS Compact Serialization (RFC 7515 §3.1, §7.1), with detached content
//! (RFC 7515 Appendix F) and the unencoded payload option (RFC 7797 §5.2).
//!
//! This file is a stub until T04 replaces it; the signatures are final.
//! The public functions call their `*_with` twins with the real
//! [`FAMILIES`]; tests call the twins with a fake table (see `jws/alg.rs`,
//! "The test seam").

use std::borrow::Cow;

use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::header::Header;
use crate::jwk::Jwk;
use crate::util::b64url_decode;

use super::alg::{FAMILIES, Families};
use super::process::{JoseHeader, signing_input, verify_signature};
use super::{ProtectedHeader, SignOptions, Verified, VerifyOptions};

/// Signs `payload` in the JWS Compact Serialization (RFC 7515 §5.1, §7.1):
/// `BASE64URL(UTF8(JWS Protected Header)) '.' BASE64URL(JWS Payload) '.'
/// BASE64URL(JWS Signature)`.
///
/// - `alg` comes from `protected`, the whole JOSE Header in this
///   serialization (RFC 7515 §7.1).
/// - With [`SignOptions::detached`] the payload part is empty:
///   `header..signature` (RFC 7515 Appendix F).
/// - With `"b64": false` (listed in `crit`), the payload is signed and
///   carried unencoded (RFC 7797 §3, §5.2).
///
/// # Errors
///
/// In this order (see the [module docs](crate::jws) for the full table):
///
/// - [`Error::InvalidHeader`]: `alg` missing, `crit` malformed, or `b64`
///   not listed in `crit` (RFC 7515 §4.1.11; RFC 7797 §3, §6).
/// - [`Error::UnknownCritical`]: `crit` lists a name other than `b64`.
/// - [`Error::UnsupportedAlgorithm`]: `alg` unknown, or RS*/PS* (no RSA
///   signing, ADR 0021).
/// - [`Error::AlgorithmNotAllowed`]: `alg` is `none` (RFC 8725 §3.2).
/// - [`Error::KeyAlgorithmMismatch`] / [`Error::InvalidKey`]: key binding
///   (ADR 0026 §2 step 8), including a public-only key.
/// - [`Error::InvalidFormat`]: `b64: false` with an attached payload that
///   contains `.` or octets outside %x20-7E (RFC 7797 §5.2).
/// - [`Error::InvalidKey`] / [`Error::RandomnessUnavailable`] from the
///   algorithm itself.
pub fn sign_compact(
    protected: &ProtectedHeader,
    payload: &[u8],
    key: &Jwk,
    opts: &SignOptions,
) -> Result<String> {
    sign_compact_with(&FAMILIES, protected, payload, key, opts)
}

/// [`sign_compact`] with the signature primitives taken from `families`.
pub(crate) fn sign_compact_with(
    families: &Families,
    protected: &ProtectedHeader,
    payload: &[u8],
    key: &Jwk,
    opts: &SignOptions,
) -> Result<String> {
    let _ = (
        families.sign,
        families.verify,
        protected,
        payload,
        key,
        opts,
    );
    Err(Error::UnsupportedAlgorithm)
}

/// Verifies a JWS in the Compact Serialization (RFC 7515 §5.2, §7.1)
/// with `key`, accepting only the algorithms `opts` allows.
///
/// - Exactly three parts, separated by two `.` (RFC 7515 §5.2 step 1).
/// - With [`VerifyOptions::detached_payload`], the payload part must be
///   empty and the supplied octets are verified (RFC 7515 Appendix F).
///   Without it, an empty payload part is an empty payload.
/// - With `"b64": false`, the payload part's octets are the payload
///   (RFC 7797 §3).
///
/// On success, [`Verified::signature_index`] is `0` and
/// [`Verified::unprotected`] is `None`.
///
/// # Errors
///
/// The first failing step of ADR 0026 §2 decides (see the
/// [module docs](crate::jws)):
///
/// - Steps 1–2, [`Error::InvalidFormat`]: longer than
///   [`VerifyOptions::max_input_len`], not three parts, or a payload part
///   present against the detached mode.
/// - Step 3, [`Error::InvalidBase64`]: a part is not strict base64url.
/// - Step 4, [`Error::InvalidJson`] (including a duplicate header member,
///   ADR 0041 §1) or [`Error::InvalidHeader`].
/// - Step 5, [`Error::UnknownCritical`].
/// - Step 6, [`Error::UnsupportedAlgorithm`].
/// - Step 7, [`Error::AlgorithmNotAllowed`], always for `none`.
/// - Step 8, [`Error::KeyAlgorithmMismatch`] or [`Error::InvalidKey`].
/// - Step 9, [`Error::InvalidSignature`].
pub fn verify_compact(jws: &str, key: &Jwk, opts: &VerifyOptions<'_>) -> Result<Verified> {
    verify_compact_with(&FAMILIES, jws, key, opts)
}

/// [`verify_compact`] with the signature primitives taken from `families`.
pub(crate) fn verify_compact_with(
    families: &Families,
    jws: &str,
    key: &Jwk,
    opts: &VerifyOptions<'_>,
) -> Result<Verified> {
    // Step 1 (ADR 0026 §7): the serialized JWS only, not a detached
    // payload, before any parsing.
    if jws.len() > opts.max_input_len {
        return Err(Error::InvalidFormat("compact JWS exceeds max_input_len"));
    }
    // Step 2 (RFC 7515 §5.2 step 1, §7.1; Appendix F).
    let (protected_b64, payload_part, signature_b64) = split(jws)?;
    if opts.detached_payload.is_some() && !payload_part.is_empty() {
        return Err(Error::InvalidFormat(
            "compact payload part must be empty with a detached payload",
        ));
    }
    // Step 3 (RFC 7515 §5.2 steps 2 and 7): the protected header and the
    // signature.
    let protected_json = Zeroizing::new(b64url_decode(protected_b64)?);
    let signature = b64url_decode(signature_b64)?;
    // Step 4, I-JSON (RFC 7515 §5.2 step 3; a duplicate member is
    // InvalidJson, ADR 0041 §1).
    let protected = Header::from_json(&protected_json)?;
    // Step 3 for the payload part (RFC 7515 §5.2 step 6). Whether it is
    // base64url at all is the protected header's `b64` (RFC 7797 §3), so
    // it runs once that header has parsed, and before its structure rules.
    let b64 = protected.b64 != Some(false);
    let payload: Cow<'_, [u8]> = match opts.detached_payload {
        Some(detached) => Cow::Borrowed(detached),
        None if b64 => Cow::Owned(b64url_decode(payload_part)?),
        None => Cow::Borrowed(payload_part.as_bytes()),
    };
    // Step 4, header structure (RFC 7515 §5.2 step 4, §7.1: the protected
    // header is the whole JOSE Header).
    let header = JoseHeader::new(Some(protected), None)?;
    // Steps 5-9 (RFC 7515 §5.2 steps 5 and 8), over the received encoding.
    let input = signing_input(protected_b64, &payload, header.b64());
    let alg = verify_signature(families, &header, key, opts, &input, &signature)?;
    let (protected, _) = header.into_parts();
    Ok(Verified {
        alg,
        protected,
        unprotected: None,
        payload: payload.into_owned(),
        signature_index: 0,
    })
}

/// Splits a compact JWS into its three parts (RFC 7515 §5.2 step 1: "exactly
/// two delimiting period characters"; §7.1).
///
/// # Errors
///
/// [`Error::InvalidFormat`] for any other number of parts (ADR 0026 §1).
fn split(jws: &str) -> Result<(&str, &str, &str)> {
    let mut parts = jws.split('.');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(protected), Some(payload), Some(signature), None) => {
            Ok((protected, payload, signature))
        }
        _ => Err(Error::InvalidFormat("compact JWS must have three parts")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwa::SigningAlg;
    use crate::jws::alg::fake::{FAKE, REJECTING, fake_signature};
    use crate::jws::alg::test_keys as keys;
    use crate::jws::process::signing_input;
    use crate::util::b64url_encode;

    use SigningAlg as A;

    const HS256: &str = r#"{"alg":"HS256"}"#;
    const HS256_B64_FALSE: &str = r#"{"alg":"HS256","b64":false,"crit":["b64"]}"#;
    const ALLOW_HS256: &[SigningAlg] = &[A::HS256];

    /// A compact JWS over `payload` with `header_json` as its protected
    /// header and the fake signature for `alg`, built by hand (RFC 7515
    /// §7.1, App. F; RFC 7797 §3, §5.2) so verify is tested apart from sign.
    fn forge(alg: &SigningAlg, header_json: &str, payload: &[u8], detached: bool) -> String {
        let b64 = !header_json.contains(r#""b64":false"#);
        let protected = b64url_encode(header_json.as_bytes());
        let sig = fake_signature(alg, &signing_input(&protected, payload, b64));
        let payload_part = match (detached, b64) {
            (true, _) => String::new(),
            (false, true) => b64url_encode(payload),
            (false, false) => String::from_utf8(payload.to_vec()).unwrap(),
        };
        format!("{protected}.{payload_part}.{}", b64url_encode(&sig))
    }

    fn hs_key() -> Jwk {
        keys::oct(32, "")
    }

    fn verify_with(jws: &str, opts: &VerifyOptions<'_>) -> Result<Verified> {
        verify_compact_with(&FAKE, jws, &hs_key(), opts)
    }

    fn verify(jws: &str) -> Result<Verified> {
        verify_with(jws, &VerifyOptions::new(ALLOW_HS256).unwrap())
    }

    fn verify_code(jws: &str) -> &'static str {
        verify(jws).map_or_else(|e| e.code(), |_| "ok")
    }

    fn parts(jws: &str) -> [String; 3] {
        let p: Vec<&str> = jws.split('.').collect();
        [p[0].to_owned(), p[1].to_owned(), p[2].to_owned()]
    }

    #[test]
    fn verifies_a_forged_token() {
        let jws = forge(&A::HS256, HS256, b"hello", false);
        let v = verify(&jws).unwrap();
        assert_eq!(v.alg, A::HS256);
        assert_eq!(
            v.protected,
            Some(Header::from_json(HS256.as_bytes()).unwrap())
        );
        assert_eq!(v.unprotected, None);
        assert_eq!(v.payload, b"hello");
        assert_eq!(v.signature_index, 0);
    }

    #[test]
    fn exactly_three_parts() {
        // RFC 7515 §5.2 step 1, §7.1; ADR 0026 §1, §2 step 2.
        let [p, l, s] = parts(&forge(&A::HS256, HS256, b"hello", false));
        for jws in [
            String::new(),
            p.clone(),
            format!("{p}.{l}"),
            format!("{p}.{l}.{s}.{s}"),
            format!("{p}.{l}.{s}."),
            format!(".{p}.{l}.{s}"),
            "...".to_owned(),
        ] {
            assert_eq!(verify_code(&jws), "InvalidFormat", "{jws}");
        }
    }

    #[test]
    fn input_over_max_input_len() {
        // ADR 0026 §7, §2 step 1: measured on the serialized JWS.
        let jws = forge(&A::HS256, HS256, b"hello", false);
        let opts = VerifyOptions::new(ALLOW_HS256).unwrap();
        assert!(verify_with(&jws, &opts.max_input_len(jws.len())).is_ok());
        assert_eq!(
            verify_with(&jws, &opts.max_input_len(jws.len() - 1)).map_err(|e| e.code()),
            Err("InvalidFormat")
        );
        // The limit is checked before the shape.
        assert_eq!(
            verify_with("a.b", &opts.max_input_len(1)),
            Err(Error::InvalidFormat("compact JWS exceeds max_input_len"))
        );
    }

    #[test]
    fn strict_base64url_in_every_part() {
        // RFC 7515 §2, §5.2 steps 2, 6 and 7: no padding, no '+' or '/',
        // no whitespace or line breaks (ADR 0026 §2 step 3).
        let jws = forge(&A::HS256, HS256, b"hello world", false);
        let [p, l, s] = parts(&jws);
        let mutations: [fn(&str) -> String; 7] = [
            |x| format!("{x}="),
            |x| format!("{x}=="),
            |x| format!("+{}", &x[1..]),
            |x| format!("/{}", &x[1..]),
            |x| format!("{} {}", &x[..2], &x[2..]),
            |x| format!("{}\n{}", &x[..2], &x[2..]),
            |x| format!("{}\r\n{}", &x[..2], &x[2..]),
        ];
        for m in mutations {
            for jws in [
                format!("{}.{l}.{s}", m(&p)),
                format!("{p}.{}.{s}", m(&l)),
                format!("{p}.{l}.{}", m(&s)),
            ] {
                assert_eq!(verify(&jws), Err(Error::InvalidBase64), "{jws:?}");
            }
        }
    }

    #[test]
    fn protected_header_must_be_one_json_object() {
        // RFC 7515 §5.2 step 3: UTF-8, a completely valid JSON object, so
        // trailing garbage after it is InvalidJson (ADR 0026 §2 step 4).
        for header in [
            &br#"{"alg":"HS256"}x"#[..],
            br#"{"alg":"HS256"}{}"#,
            br#"{"alg":"HS256"},"#,
            br#"["HS256"]"#,
            br#""HS256""#,
            b"",
            b"{\"alg\":\"HS256\",\"x\":\"\xff\"}",
        ] {
            let jws = format!("{}.aGk.", b64url_encode(header));
            assert_eq!(verify_code(&jws), "InvalidJson", "{header:?}");
        }
    }

    #[test]
    fn duplicate_header_member_is_invalid_json() {
        // ADR 0041 §1, amending ADR 0026 §2 step 4.
        for header in [
            r#"{"alg":"HS256","alg":"HS256"}"#,
            r#"{"alg":"HS256","alg":"none"}"#,
            r#"{"alg":"HS256","b64":false,"crit":["b64"],"b64":false}"#,
            r#"{"alg":"HS256","x":1,"x":2}"#,
        ] {
            let jws = forge(&A::HS256, header, b"hi", false);
            assert_eq!(verify_code(&jws), "InvalidJson", "{header}");
        }
    }

    #[test]
    fn header_structure_rules_apply() {
        // ADR 0026 §2 step 4, through process::JoseHeader::new.
        for header in [
            r#"{"typ":"JWT"}"#,
            r#"{"alg":"HS256","b64":false}"#,
            r#"{"alg":"HS256","b64":true}"#,
            r#"{"alg":"HS256","crit":["x-a"]}"#,
            r#"{"alg":1}"#,
        ] {
            let jws = forge(&A::HS256, header, b"hi", false);
            assert_eq!(verify_code(&jws), "InvalidHeader", "{header}");
        }
    }

    #[test]
    fn detached_payload_requires_an_empty_payload_part() {
        // RFC 7515 Appendix F; ADR 0026 §1.
        let attached = forge(&A::HS256, HS256, b"hello", false);
        let opts = VerifyOptions::new(ALLOW_HS256)
            .unwrap()
            .detached_payload(b"hello");
        assert_eq!(
            verify_with(&attached, &opts).map_err(|e| e.code()),
            Err("InvalidFormat")
        );
        // The empty part: the supplied octets are verified.
        let detached = forge(&A::HS256, HS256, b"hello", true);
        assert!(detached.contains(".."));
        let v = verify_with(&detached, &opts).unwrap();
        assert_eq!(v.payload, b"hello");
        let wrong = VerifyOptions::new(ALLOW_HS256)
            .unwrap()
            .detached_payload(b"hellO");
        assert_eq!(verify_with(&detached, &wrong), Err(Error::InvalidSignature));
    }

    #[test]
    fn empty_payload_part_without_detached_is_an_empty_payload() {
        // RFC 7515 §7.1: BASE64URL of the empty octet sequence is "".
        let empty = forge(&A::HS256, HS256, b"", false);
        let v = verify(&empty).unwrap();
        assert_eq!(v.payload, b"");
        // A detached token's signature is over its real payload, not "".
        let detached = forge(&A::HS256, HS256, b"hello", true);
        assert_eq!(verify(&detached), Err(Error::InvalidSignature));
        // Detached mode with an empty supplied payload is the same token.
        let opts = VerifyOptions::new(ALLOW_HS256)
            .unwrap()
            .detached_payload(b"");
        assert_eq!(verify_with(&empty, &opts).unwrap().payload, b"");
    }

    #[test]
    fn b64_false_payload_part_is_the_raw_octets() {
        // RFC 7797 §3, §5.2: no base64url decoding of the payload part.
        for payload in [
            &b"$02"[..],
            b"QQ",
            b"hello world",
            b" ~!",
            "\u{e9}".as_bytes(),
            b"",
        ] {
            let jws = forge(&A::HS256, HS256_B64_FALSE, payload, false);
            let v = verify(&jws).unwrap();
            assert_eq!(v.payload, payload, "{jws}");
            assert_eq!(v.protected.unwrap().b64, Some(false));
        }
        // The same octets read as base64url would give another signing
        // input: "QQ" is not 0x41 here.
        let jws = forge(&A::HS256, HS256_B64_FALSE, b"QQ", false);
        assert_eq!(verify(&jws).unwrap().payload, b"QQ");
    }

    #[test]
    fn b64_false_detached_rfc7797_section_4_2() {
        // RFC 7797 §4.2's header and payload "$.02", detached, with the
        // fake signature in place of the RFC's HMAC.
        let protected = "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19";
        let input = format!("{protected}.$.02");
        let sig = b64url_encode(&fake_signature(&A::HS256, input.as_bytes()));
        let jws = format!("{protected}..{sig}");
        let opts = VerifyOptions::new(ALLOW_HS256)
            .unwrap()
            .detached_payload(b"$.02");
        let v = verify_with(&jws, &opts).unwrap();
        assert_eq!(v.payload, b"$.02");
        assert_eq!(v.alg, A::HS256);
        // The RFC's own token, with its real HMAC: well-formed through step
        // 8, rejected by the fake family at step 9.
        let rfc = format!("{protected}..A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY");
        assert_eq!(verify_with(&rfc, &opts), Err(Error::InvalidSignature));
    }

    #[test]
    fn rfc7515_a1_token_parses_and_keeps_the_crlf_header() {
        // RFC 7515 Appendix A.1: the header octets contain CRLF, so the
        // signing input must use the received encoding verbatim.
        let protected = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9";
        let payload_part = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
        let rfc = format!("{protected}.{payload_part}.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
        assert_eq!(verify(&rfc), Err(Error::InvalidSignature));
        assert_eq!(
            verify_compact_with(
                &REJECTING,
                &rfc,
                &hs_key(),
                &VerifyOptions::new(ALLOW_HS256).unwrap()
            ),
            Err(Error::InvalidSignature)
        );
        let input = format!("{protected}.{payload_part}");
        let sig = b64url_encode(&fake_signature(&A::HS256, input.as_bytes()));
        let v = verify(&format!("{input}.{sig}")).unwrap();
        assert_eq!(v.protected.unwrap().typ.as_deref(), Some("JWT"));
        assert_eq!(
            v.payload,
            b"{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}"
        );
    }

    /// RFC 7515 Appendix A.5: the Unsecured JWS, `{"alg":"none"}`.
    const A5_NONE: &str = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.";

    #[test]
    fn rfc7515_a5_none_is_never_allowed() {
        // RFC 8725 §3.1, ADR 0026 §2 step 7: whatever the list and key, and
        // whether or not the real families are used.
        let all: Vec<SigningAlg> = SigningAlg::KNOWN
            .iter()
            .filter(|a| **a != A::None)
            .cloned()
            .collect();
        let lists: [&[SigningAlg]; 3] = [ALLOW_HS256, &[A::RS256, A::ES256], &all];
        let keys = [hs_key(), keys::rsa(2048), keys::p256(""), keys::ed25519("")];
        let forged_sig = format!(
            "{}{}",
            A5_NONE,
            b64url_encode(&fake_signature(
                &A::None,
                A5_NONE.trim_end_matches('.').as_bytes()
            ))
        );
        for allowed in lists {
            let opts = VerifyOptions::new(allowed).unwrap();
            for key in &keys {
                for jws in [A5_NONE, forged_sig.as_str()] {
                    assert_eq!(
                        verify_compact(jws, key, &opts),
                        Err(Error::AlgorithmNotAllowed)
                    );
                    assert_eq!(
                        verify_compact_with(&FAKE, jws, key, &opts),
                        Err(Error::AlgorithmNotAllowed)
                    );
                }
            }
        }
    }

    #[test]
    fn steps_5_to_9_come_from_the_shared_rules() {
        let opts = VerifyOptions::new(ALLOW_HS256).unwrap();
        let code = |header: &str, key: &Jwk| {
            let jws = forge(&A::HS256, header, b"hi", false);
            verify_compact_with(&FAKE, &jws, key, &opts).map_or_else(|e| e.code(), |_| "ok")
        };
        let hs = hs_key();
        assert_eq!(
            code(r#"{"alg":"HS256","crit":["x-a"],"x-a":1}"#, &hs),
            "UnknownCritical"
        );
        assert_eq!(code(r#"{"alg":"HS1"}"#, &hs), "UnsupportedAlgorithm");
        assert_eq!(code(r#"{"alg":"HS384"}"#, &hs), "AlgorithmNotAllowed");
        assert_eq!(code(HS256, &keys::rsa(2048)), "KeyAlgorithmMismatch");
        assert_eq!(code(HS256, &keys::oct(31, "")), "InvalidKey");
        assert_eq!(code(HS256, &hs), "ok");
    }

    #[test]
    fn tampering_is_an_invalid_signature() {
        let jws = forge(&A::HS256, HS256, b"hello", false);
        let [p, _, s] = parts(&jws);
        let other_payload = format!("{p}.{}.{s}", b64url_encode(b"hellO"));
        let other_header = format!(
            "{}.{}.{s}",
            b64url_encode(br#"{"alg":"HS256","kid":"x"}"#),
            b64url_encode(b"hello")
        );
        let mut sig = crate::util::b64url_decode(&s).unwrap();
        sig[0] ^= 1;
        let other_sig = format!("{p}.{}.{}", b64url_encode(b"hello"), b64url_encode(&sig));
        let short_sig = format!("{p}.{}.", b64url_encode(b"hello"));
        for t in [other_payload, other_header, other_sig, short_sig] {
            assert_eq!(verify(&t), Err(Error::InvalidSignature), "{t}");
        }
        // REJECTING's verify fails a genuine signature too.
        assert_eq!(
            verify_compact_with(
                &REJECTING,
                &jws,
                &hs_key(),
                &VerifyOptions::new(ALLOW_HS256).unwrap()
            ),
            Err(Error::InvalidSignature)
        );
    }

    #[test]
    fn precedence_of_steps_1_to_4() {
        // ADR 0026 §2: the first failing step decides.
        let jws = forge(&A::HS256, HS256, b"hello", false);
        let [p, l, s] = parts(&jws);
        let bad_json = b64url_encode(br#"{"alg":"HS256""#);
        // Shape (2) before base64 (3).
        assert_eq!(verify_code(&format!("{p}=.{l}.{s}.x")), "InvalidFormat");
        // Detached mismatch (2) before base64 (3) and JSON (4).
        let opts = VerifyOptions::new(ALLOW_HS256)
            .unwrap()
            .detached_payload(b"hello");
        assert_eq!(
            verify_with(&format!("{bad_json}.{l}.{s}="), &opts).map_err(|e| e.code()),
            Err("InvalidFormat")
        );
        // The signature's base64 (3) before the header JSON (4).
        assert_eq!(
            verify_code(&format!("{bad_json}.{l}.{s}=")),
            "InvalidBase64"
        );
        // The payload part's base64 needs the header's b64 (RFC 7797 §3),
        // so an unparsable header (4) is reported before it.
        assert_eq!(verify_code(&format!("{bad_json}.{l}=.{s}")), "InvalidJson");
        // A parsable header: the payload's base64 (3) before the header
        // structure (4) and every later step.
        let no_alg = b64url_encode(br#"{"typ":"JWT"}"#);
        assert_eq!(verify_code(&format!("{no_alg}.{l}=.{s}")), "InvalidBase64");
        // Header structure (4) before crit (5) and the allow-list (7).
        let none_bad_crit = b64url_encode(br#"{"alg":"none","crit":["x-a"]}"#);
        assert_eq!(
            verify_code(&format!("{none_bad_crit}.{l}.{s}")),
            "InvalidHeader"
        );
    }
}
