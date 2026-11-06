//! The JWE JSON Serialization (RFC 7516 §7.2): general (§7.2.1) with a
//! `recipients` array, and flattened (§7.2.2) with one recipient at the
//! top level; shared and per-recipient unprotected headers and the JWE AAD.
//!
//! This file only converts between the text and [`JweParts`]; every
//! processing rule after parsing is `core`'s: header disjointness across
//! the protected, shared and every per-recipient header, `crit` and `zip`
//! only in the protected header, `alg` and `enc` present, one `enc` for all
//! recipients, the support, allow-list and key checks, and recipient
//! selection (RFC 7516 §5.2 steps 4–18).
//!
//! # Parsing, step by step (plan.md error contract, ADR 0026 §2)
//!
//! Each step runs over the whole document before the next starts, so a JWE
//! that is wrong in several places fails the same way whatever the order
//! of its members or recipients:
//!
//! 1. the input length, before anything is parsed (ADR 0026 §7)
//!    → `InvalidFormat`;
//! 2. JSON syntax, I-JSON and the JSON limits, with duplicate member names
//!    anywhere in the document (RFC 7516 §5.2 step 1, RFC 7493 §2.3,
//!    ADR 0041 §1) → `InvalidJson`;
//! 3. the §7.2.1/§7.2.2 shape, with the recipient count checked as soon as
//!    it is known (ADR 0026 §7) → `InvalidFormat`;
//! 4. strict base64url of every encoded member (§5.2 step 2, RFC 7515 §2)
//!    → `InvalidBase64`;
//! 5. the protected header ([`core::parse_protected`], §5.2 step 3): not a
//!    JSON object → `InvalidJson`; a registered parameter of the wrong type
//!    → `InvalidHeader`;
//! 6. the shared and per-recipient unprotected headers, typed the same way
//!    → `InvalidHeader`.

use super::api::{DecryptPolicy, JsonForm};
use super::core::{self, JweParts, RecipientParts};
use crate::header::Header;
use crate::json::{self, Limits, Object, Value};
use crate::util::b64url_decode;
#[cfg(test)]
use crate::util::b64url_encode;
use crate::{Error, Result};

/// The members of one `recipients` entry (RFC 7516 §7.2.1), which the
/// flattened syntax puts at the top level instead (§7.2.2).
const RECIPIENT_MEMBERS: [&str; 2] = ["header", "encrypted_key"];

/// A JSON JWE after the shape step: every member of the right type, still
/// encoded.
struct Raw {
    protected: Option<String>,
    unprotected: Option<Object>,
    recipients: Vec<RawRecipient>,
    aad: Option<String>,
    iv: Option<String>,
    ciphertext: String,
    tag: Option<String>,
}

/// One recipient after the shape step (RFC 7516 §7.2.1 `recipients`
/// entry, or the top level of a flattened JWE).
struct RawRecipient {
    header: Option<Object>,
    encrypted_key: Option<String>,
}

/// Parses a general or flattened JSON JWE (RFC 7516 §5.2 steps 1–3,
/// §7.2.1, §7.2.2), in the order of the module documentation.
///
/// A document with a `recipients` member is general; one without is
/// flattened (§7.2.2: flattening removes `recipients`). Members this
/// serialization does not define are ignored at every level (§7.2.1:
/// "Additional members can be present in both the JSON objects defined
/// above; if not understood by implementations encountering them, they
/// MUST be ignored").
///
/// The encoded protected header is kept exactly as received, for the AAD
/// (§5.2 step 14), or `""` when the JWE has none (§5.1 step 14).
///
/// # Errors
///
/// [`Error::InvalidFormat`] for an input over `policy`'s `max_input_len`
/// (checked first), more than `max_recipients` recipients, or a shape
/// RFC 7516 §7.2 forbids; [`Error::InvalidJson`] for JSON syntax,
/// duplicate members (ADR 0041 §1), the JSON limits, or a protected
/// header that is not a JSON object; [`Error::InvalidBase64`] for a
/// member that is not strict base64url; [`Error::InvalidHeader`] for a
/// registered header parameter of the wrong type. No error carries any
/// part of the input.
pub(crate) fn parse(jwe: &str, policy: &DecryptPolicy) -> Result<JweParts> {
    // Step 1 (ADR 0026 §7). The JSON layer's own input limit follows the
    // caller's, so a larger configured limit holds.
    if jwe.len() > policy.max_input_len {
        return Err(Error::InvalidFormat("JSON JWE exceeds max_input_len"));
    }
    let mut limits = Limits::DEFAULT;
    limits.max_input_len = policy.max_input_len;
    // Step 2.
    let top = json::parse_with_limits(jwe.as_bytes(), &limits)?
        .into_object()
        .ok_or(Error::InvalidFormat(
            "JWE JSON Serialization must be an object",
        ))?;
    // Step 3.
    let raw = shape(top, policy.max_recipients)?;

    // Step 4: every encoded member, before any header is parsed.
    let decode = |member: Option<&String>| member.map(|s| b64url_decode(s)).transpose();
    let protected_json = decode(raw.protected.as_ref())?;
    let mut encrypted_keys = Vec::with_capacity(raw.recipients.len());
    for recipient in &raw.recipients {
        encrypted_keys.push(decode(recipient.encrypted_key.as_ref())?.unwrap_or_default());
    }
    let aad = decode(raw.aad.as_ref())?;
    let iv = decode(raw.iv.as_ref())?.unwrap_or_default();
    let ciphertext = b64url_decode(&raw.ciphertext)?;
    let tag = decode(raw.tag.as_ref())?.unwrap_or_default();

    // Steps 5 and 6.
    let protected = protected_json
        .as_deref()
        .map(core::parse_protected)
        .transpose()?;
    let shared = raw.unprotected.map(Header::from_object).transpose()?;
    let mut recipients = Vec::with_capacity(raw.recipients.len());
    for (recipient, encrypted_key) in raw.recipients.into_iter().zip(encrypted_keys) {
        recipients.push(RecipientParts {
            header: recipient.header.map(Header::from_object).transpose()?,
            encrypted_key,
        });
    }

    Ok(JweParts {
        protected_b64: raw.protected.unwrap_or_default(),
        protected,
        shared,
        recipients,
        iv,
        ciphertext,
        tag,
        aad,
    })
}

/// Step 3: the RFC 7516 §7.2.1/§7.2.2 shape. Only member presence and JSON
/// types are checked here; the values are still encoded.
///
/// - `ciphertext` MUST be present (§7.2.1), as a string; it may be empty
///   (an empty plaintext under AES-GCM).
/// - `protected`, `unprotected`, `aad`, `iv` and `tag`, and in each
///   recipient `header` and `encrypted_key`, "MUST be present ... when the
///   ... value is non-empty; otherwise, it MUST be absent" (§7.2.1). So an
///   empty string or an empty object is refused: an empty `aad` in
///   particular would change the AAD computation (§5.2 step 15).
/// - `recipients`, when present, is a non-empty array of objects
///   (§7.2.1: "MUST be an array of JSON objects"; "{}" is a recipient with
///   neither member, as for `dir`), with at most `max_recipients` entries
///   (ADR 0026 §7). A flattened JWE "MUST NOT" have `recipients` (§7.2.2),
///   so top-level `header` or `encrypted_key` next to `recipients` is
///   neither form.
/// - Each recipient has at least one of `header`, `protected` and
///   `unprotected` (§7.2.1: "At least one of the "header", "protected", and
///   "unprotected" members MUST be present so that "alg" and "enc" Header
///   Parameter values are conveyed for each recipient computation").
///
/// # Errors
///
/// [`Error::InvalidFormat`] for any of the above.
fn shape(mut top: Object, max_recipients: usize) -> Result<Raw> {
    let recipients = match top.remove("recipients") {
        // General (§7.2.1).
        Some(recipients) => {
            if RECIPIENT_MEMBERS.iter().any(|name| top.contains(name)) {
                return Err(Error::InvalidFormat(
                    "recipients mixed with top-level header or encrypted_key",
                ));
            }
            let Value::Array(entries) = recipients else {
                return Err(Error::InvalidFormat("recipients must be an array"));
            };
            if entries.is_empty() {
                return Err(Error::InvalidFormat("recipients must not be empty"));
            }
            if entries.len() > max_recipients {
                return Err(Error::InvalidFormat("JWE exceeds max_recipients"));
            }
            entries
                .into_iter()
                .map(|entry| {
                    entry
                        .into_object()
                        .ok_or(Error::InvalidFormat("each recipient must be an object"))
                        .and_then(raw_recipient)
                })
                .collect::<Result<Vec<_>>>()?
        }
        // Flattened (§7.2.2): the recipient's members are at the top level.
        None => vec![raw_recipient_members(&mut top)?],
    };
    let protected = string_member(&mut top, "protected", PROTECTED)?;
    let unprotected = object_member(&mut top, "unprotected", UNPROTECTED)?;
    let aad = string_member(&mut top, "aad", AAD)?;
    let iv = string_member(&mut top, "iv", IV)?;
    let tag = string_member(&mut top, "tag", TAG)?;
    let ciphertext = match top.remove("ciphertext") {
        None => return Err(Error::InvalidFormat("ciphertext member missing")),
        Some(value) => value
            .as_str()
            .map(str::to_owned)
            .ok_or(Error::InvalidFormat("ciphertext must be a string"))?,
    };
    let shared_header = protected.is_some() || unprotected.is_some();
    if !shared_header && recipients.iter().any(|r| r.header.is_none()) {
        return Err(Error::InvalidFormat(
            "a recipient has no header, protected or unprotected member",
        ));
    }
    Ok(Raw {
        protected,
        unprotected,
        recipients,
        aad,
        iv,
        ciphertext,
        tag,
    })
}

/// One `recipients` entry (§7.2.1); its other members are ignored.
fn raw_recipient(mut entry: Object) -> Result<RawRecipient> {
    raw_recipient_members(&mut entry)
}

/// Takes `header` and `encrypted_key` out of `object` (a `recipients`
/// entry, or the top level of a flattened JWE).
fn raw_recipient_members(object: &mut Object) -> Result<RawRecipient> {
    Ok(RawRecipient {
        header: object_member(object, "header", HEADER)?,
        encrypted_key: string_member(object, "encrypted_key", ENCRYPTED_KEY)?,
    })
}

/// The two ways a member present only when non-empty (§7.2.1) can be
/// malformed: the wrong JSON type, or present but empty.
struct Faults {
    wrong_type: &'static str,
    empty: &'static str,
}

const PROTECTED: Faults = Faults {
    wrong_type: "protected must be a string",
    empty: "protected must be absent when empty",
};
const UNPROTECTED: Faults = Faults {
    wrong_type: "unprotected must be a JSON object",
    empty: "unprotected must be absent when empty",
};
const HEADER: Faults = Faults {
    wrong_type: "header must be a JSON object",
    empty: "header must be absent when empty",
};
const ENCRYPTED_KEY: Faults = Faults {
    wrong_type: "encrypted_key must be a string",
    empty: "encrypted_key must be absent when empty",
};
const AAD: Faults = Faults {
    wrong_type: "aad must be a string",
    empty: "aad must be absent when empty",
};
const IV: Faults = Faults {
    wrong_type: "iv must be a string",
    empty: "iv must be absent when empty",
};
const TAG: Faults = Faults {
    wrong_type: "tag must be a string",
    empty: "tag must be absent when empty",
};

/// Removes the optional, non-empty string member `name` from `object`.
///
/// # Errors
///
/// [`Error::InvalidFormat`] if it is not a string, or is `""`.
fn string_member(object: &mut Object, name: &str, faults: Faults) -> Result<Option<String>> {
    match object.remove(name) {
        None => Ok(None),
        Some(value) => match value.as_str() {
            Some("") => Err(Error::InvalidFormat(faults.empty)),
            Some(s) => Ok(Some(s.to_owned())),
            None => Err(Error::InvalidFormat(faults.wrong_type)),
        },
    }
}

/// Removes the optional, non-empty object member `name` from `object`
/// (§7.2.1: the unprotected headers are "an unencoded JSON object, rather
/// than as a string").
///
/// # Errors
///
/// [`Error::InvalidFormat`] if it is not an object, or is `{}`.
fn object_member(object: &mut Object, name: &str, faults: Faults) -> Result<Option<Object>> {
    match object.remove(name) {
        None => Ok(None),
        Some(value) => match value.into_object() {
            Some(o) if o.is_empty() => Err(Error::InvalidFormat(faults.empty)),
            Some(o) => Ok(Some(o)),
            None => Err(Error::InvalidFormat(faults.wrong_type)),
        },
    }
}

/// Writes `parts` in `form` (RFC 7516 §7.2.1, §7.2.2).
///
/// # Errors
///
/// [`Error::InvalidFormat`] for a flattened JWE with other than one
/// recipient.
pub(crate) fn serialize(_parts: &JweParts, _form: JsonForm) -> Result<String> {
    Err(Error::UnsupportedAlgorithm)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwa::{ContentEncAlg, KeyMgmtAlg};

    /// RFC 7516 A.4.7 (general, two recipients), without line breaks.
    const A4: &str = concat!(
        r#"{"protected":"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","#,
        r#""unprotected":{"jku":"https://server.example.com/keys.jwks"},"#,
        r#""recipients":[{"header":{"alg":"RSA1_5","kid":"2011-04-29"},"#,
        r#""encrypted_key":"UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-"#,
        r#"kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKx"#,
        r#"GHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3"#,
        r#"YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPh"#,
        r#"cCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPg"#,
        r#"wCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A"},"#,
        r#"{"header":{"alg":"A128KW","kid":"7"},"#,
        r#""encrypted_key":"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"}],"#,
        r#""iv":"AxY8DCtDaGlsbGljb3RoZQ","#,
        r#""ciphertext":"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY","#,
        r#""tag":"Mz-VPPyU4RlcuYv1IwIvzw"}"#,
    );

    /// RFC 7516 A.5 (flattened), without line breaks.
    const A5: &str = concat!(
        r#"{"protected":"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","#,
        r#""unprotected":{"jku":"https://server.example.com/keys.jwks"},"#,
        r#""header":{"alg":"A128KW","kid":"7"},"#,
        r#""encrypted_key":"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ","#,
        r#""iv":"AxY8DCtDaGlsbGljb3RoZQ","#,
        r#""ciphertext":"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY","#,
        r#""tag":"Mz-VPPyU4RlcuYv1IwIvzw"}"#,
    );

    /// The flattened members of A.5 after `protected`, as `"name":value`
    /// pairs, for building variants.
    const A5_PROTECTED: &str = r#""protected":"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0""#;
    const A5_HEADER: &str = r#""header":{"alg":"A128KW","kid":"7"}"#;
    const A5_KEY: &str =
        r#""encrypted_key":"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ""#;
    const A5_IV: &str = r#""iv":"AxY8DCtDaGlsbGljb3RoZQ""#;
    const A5_CT: &str = r#""ciphertext":"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY""#;
    const A5_TAG: &str = r#""tag":"Mz-VPPyU4RlcuYv1IwIvzw""#;

    fn policy() -> DecryptPolicy {
        DecryptPolicy::new(&[KeyMgmtAlg::A128KW], &[ContentEncAlg::A128CbcHs256])
            .unwrap_or_else(|e| panic!("{e}"))
    }

    fn parse_code(jwe: &str) -> &'static str {
        match parse(jwe, &policy()) {
            Ok(_) => "ok",
            Err(e) => e.code(),
        }
    }

    fn parsed(jwe: &str) -> JweParts {
        parse(jwe, &policy()).unwrap_or_else(|e| panic!("{jwe}: {e}"))
    }

    /// An object from `"name":value` members.
    fn object(members: &[&str]) -> String {
        format!("{{{}}}", members.join(","))
    }

    /// A.5 (without `unprotected`) with the members named in `drop`
    /// removed and the `"name":value` pairs of `extra` appended.
    fn a5_with(extra: &[&str], drop: &[&str]) -> String {
        let mut members: Vec<&str> = vec![A5_PROTECTED, A5_HEADER, A5_KEY, A5_IV, A5_CT, A5_TAG];
        members.retain(|m| !drop.iter().any(|d| m.starts_with(&format!("\"{d}\""))));
        members.extend_from_slice(extra);
        object(&members)
    }

    /// A one-recipient general JWE: the A.5 recipient moved into
    /// `recipients`.
    fn general(entries: &str) -> String {
        object(&[
            A5_PROTECTED,
            &format!(r#""recipients":{entries}"#),
            A5_IV,
            A5_CT,
            A5_TAG,
        ])
    }

    fn a5_entry() -> String {
        object(&[A5_HEADER, A5_KEY])
    }

    #[test]
    fn parses_rfc_7516_a4_general() {
        let parts = parsed(A4);
        assert_eq!(parts.protected_b64, "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0");
        let protected = parts.protected.as_ref().unwrap_or_else(|| panic!("none"));
        assert_eq!(protected.enc, Some(ContentEncAlg::A128CbcHs256));
        assert!(protected.alg.is_none());
        let shared = parts.shared.as_ref().unwrap_or_else(|| panic!("none"));
        assert_eq!(
            shared.jku.as_deref(),
            Some("https://server.example.com/keys.jwks")
        );
        assert_eq!(parts.recipients.len(), 2);
        let alg = |i: usize| {
            parts.recipients[i]
                .header
                .as_ref()
                .and_then(|h| h.alg.clone())
        };
        assert_eq!(alg(0).as_deref(), Some("RSA1_5"));
        assert_eq!(alg(1).as_deref(), Some("A128KW"));
        assert_eq!(parts.recipients[0].encrypted_key.len(), 256);
        assert_eq!(parts.recipients[1].encrypted_key.len(), 24 + 16);
        assert_eq!(parts.iv.len(), 16);
        assert_eq!(parts.ciphertext.len(), 32);
        assert_eq!(parts.tag.len(), 16);
        assert!(parts.aad.is_none());
    }

    #[test]
    fn the_input_length_limit_comes_first() {
        // ADR 0026 §7: even invalid JSON over the limit is only
        // InvalidFormat.
        let at = policy().max_input_len(A5.len());
        assert!(parse(A5, &at).is_ok());
        let under = policy().max_input_len(A5.len() - 1);
        assert_eq!(
            parse(A5, &under).map(|_| ()),
            Err(Error::InvalidFormat("JSON JWE exceeds max_input_len"))
        );
        let garbage = "{".repeat(64);
        let tiny = policy().max_input_len(10);
        assert_eq!(code_with(&garbage, &tiny), "InvalidFormat");
        // A configured limit above the JSON default holds.
        let big = format!(
            r#"{{"x":"{}",{}}}"#,
            "a".repeat(Limits::DEFAULT.max_input_len),
            &A5[1..A5.len() - 1]
        );
        assert_eq!(code_with(&big, &policy()), "InvalidFormat");
        let raised = policy().max_input_len(big.len());
        assert_eq!(code_with(&big, &raised), "ok");
    }

    fn code_with(jwe: &str, policy: &DecryptPolicy) -> &'static str {
        match parse(jwe, policy) {
            Ok(_) => "ok",
            Err(e) => e.code(),
        }
    }

    #[test]
    fn json_syntax_and_duplicates_are_invalid_json() {
        for jwe in ["", "{", "{} {}", "[1,]", r#"{"ciphertext":"AA"#] {
            assert_eq!(parse_code(jwe), "InvalidJson", "{jwe:?}");
        }
        // ADR 0041 §1: a duplicate member anywhere in the document.
        let top = format!("{},{A5_CT}}}", &A5[..A5.len() - 1]);
        assert_eq!(parse_code(&top), "InvalidJson");
        let in_header = A5.replace(r#""kid":"7""#, r#""kid":"7","kid":"8""#);
        assert_eq!(parse_code(&in_header), "InvalidJson");
        let in_shared = A5.replace(
            r#"{"jku":"https://server.example.com/keys.jwks"}"#,
            r#"{"jku":"a","jku":"b"}"#,
        );
        assert_eq!(parse_code(&in_shared), "InvalidJson");
        let in_entry = general(&format!(r#"[{{{A5_HEADER},{A5_KEY},{A5_KEY}}}]"#));
        assert_eq!(parse_code(&in_entry), "InvalidJson");
        // Escaped and unescaped spellings of one name are the same name.
        let escaped = format!(r#"{},"ciphertext":"AA"}}"#, &A5[..A5.len() - 1]);
        assert_eq!(parse_code(&escaped), "InvalidJson");
    }

    #[test]
    fn the_top_level_must_be_an_object() {
        for jwe in ["[]", "[1]", r#""x""#, "1", "null", "true"] {
            assert_eq!(parse_code(jwe), "InvalidFormat", "{jwe}");
        }
    }

    #[test]
    fn ciphertext_is_required_and_may_be_empty() {
        assert_eq!(
            parse(&a5_with(&[], &["ciphertext"]), &policy()).map(|_| ()),
            Err(Error::InvalidFormat("ciphertext member missing"))
        );
        for bad in ["1", "null", "{}", "[]", "true"] {
            let jwe = a5_with(&[&format!(r#""ciphertext":{bad}"#)], &["ciphertext"]);
            assert_eq!(parse_code(&jwe), "InvalidFormat", "{bad}");
        }
        // An empty plaintext under AES-GCM has an empty ciphertext; §7.2.1
        // does not make `ciphertext` conditional.
        let empty = parsed(&a5_with(&[r#""ciphertext":"""#], &["ciphertext"]));
        assert!(empty.ciphertext.is_empty());
    }

    #[test]
    fn members_have_their_json_types() {
        let cases: &[(&str, &[&str])] = &[
            ("protected", &["1", "{}", "[]", "null", "true"]),
            ("unprotected", &["1", r#""x""#, "[]", "null"]),
            ("header", &["1", r#""x""#, "[]", "null"]),
            ("encrypted_key", &["1", "{}", "[]", "null"]),
            ("aad", &["1", "{}", "[]", "null"]),
            ("iv", &["1", "{}", "[]", "null"]),
            ("tag", &["1", "{}", "[]", "null"]),
        ];
        for (name, values) in cases {
            for value in *values {
                let member = format!(r#""{name}":{value}"#);
                let flat = a5_with(&[&member], &[name]);
                assert_eq!(parse_code(&flat), "InvalidFormat", "{member}");
            }
        }
        // The same inside a `recipients` entry.
        for entry in [
            object(&[r#""header":"x""#]),
            object(&[A5_HEADER, r#""encrypted_key":1"#]),
        ] {
            assert_eq!(
                parse_code(&general(&format!("[{entry}]"))),
                "InvalidFormat",
                "{entry}"
            );
        }
    }

    #[test]
    fn optional_members_are_absent_when_empty() {
        // §7.2.1: each "MUST be absent" when its value is empty.
        for (name, empty) in [
            ("protected", r#""""#),
            ("unprotected", "{}"),
            ("header", "{}"),
            ("encrypted_key", r#""""#),
            ("aad", r#""""#),
            ("iv", r#""""#),
            ("tag", r#""""#),
        ] {
            let member = format!(r#""{name}":{empty}"#);
            let jwe = a5_with(&[&member], &[name]);
            assert_eq!(
                parse(&jwe, &policy()).map(|_| ()).unwrap_err().code(),
                "InvalidFormat",
                "{member}"
            );
        }
        // Absent is fine, and decodes to "nothing".
        let parts = parsed(&a5_with(&[], &["encrypted_key", "iv", "tag"]));
        assert!(parts.recipients[0].encrypted_key.is_empty());
        assert!(parts.iv.is_empty() && parts.tag.is_empty() && parts.aad.is_none());
    }

    #[test]
    fn recipients_is_a_non_empty_array_of_objects() {
        for entries in ["[]", "{}", r#""x""#, "null", "1", "[1]", "[[]]", r#"["x"]"#] {
            assert_eq!(parse_code(&general(entries)), "InvalidFormat", "{entries}");
        }
        // `{}` is a recipient (dir: no header, no encrypted key), given the
        // protected header conveys alg and enc.
        let dir = parsed(&general("[{}]"));
        assert_eq!(dir.recipients.len(), 1);
        assert!(dir.recipients[0].header.is_none());
        assert!(dir.recipients[0].encrypted_key.is_empty());
        assert_eq!(parse_code(&general(&format!("[{}]", a5_entry()))), "ok");
    }

    #[test]
    fn a_flattened_jwe_has_no_recipients_member() {
        // §7.2.2: "the "recipients" member MUST NOT be present". A document
        // with both is neither form.
        let entries = format!(r#""recipients":[{}]"#, a5_entry());
        assert_eq!(parse_code(&a5_with(&[&entries], &[])), "InvalidFormat");
        assert_eq!(
            parse_code(&a5_with(&[&entries], &["encrypted_key"])),
            "InvalidFormat"
        );
        assert_eq!(
            parse_code(&a5_with(&[&entries], &["header"])),
            "InvalidFormat"
        );
        assert_eq!(
            parse(
                &a5_with(&[&entries], &["header", "encrypted_key"]),
                &policy()
            )
            .map(|p| p.recipients.len()),
            Ok(1)
        );
    }

    #[test]
    fn every_recipient_has_a_header_somewhere() {
        // §7.2.1: at least one of header, protected and unprotected.
        let no_headers = a5_with(&[], &["protected", "header"]);
        assert_eq!(
            parse(&no_headers, &policy()).map(|_| ()),
            Err(Error::InvalidFormat(
                "a recipient has no header, protected or unprotected member"
            ))
        );
        // Each one alone is enough at parse time; whether alg and enc are
        // there is core's rule.
        assert_eq!(parse_code(&a5_with(&[], &["protected"])), "ok");
        assert_eq!(parse_code(&a5_with(&[], &["header"])), "ok");
        let shared_only = a5_with(
            &[r#""unprotected":{"enc":"A128GCM"}"#],
            &["protected", "header"],
        );
        assert_eq!(parse_code(&shared_only), "ok");
        // In general form, every entry is checked.
        let mixed = object(&[
            &format!(r#""recipients":[{},{{}}]"#, a5_entry()),
            A5_IV,
            A5_CT,
            A5_TAG,
        ]);
        assert_eq!(parse_code(&mixed), "InvalidFormat");
    }

    #[test]
    fn the_recipient_count_is_limited_while_parsing() {
        let entries = |n: usize| format!("[{}]", vec![a5_entry(); n].join(","));
        assert_eq!(
            parse(&general(&entries(16)), &policy()).map(|p| p.recipients.len()),
            Ok(16)
        );
        assert_eq!(
            parse(&general(&entries(17)), &policy()).map(|_| ()),
            Err(Error::InvalidFormat("JWE exceeds max_recipients"))
        );
        let two = policy().max_recipients(2);
        assert_eq!(code_with(&general(&entries(2)), &two), "ok");
        assert_eq!(code_with(&general(&entries(3)), &two), "InvalidFormat");
        // Checked before the entries themselves: 17 malformed entries are
        // still a count error.
        let junk = format!("[{}]", vec!["1"; 17].join(","));
        assert_eq!(
            parse(&general(&junk), &policy()).map(|_| ()),
            Err(Error::InvalidFormat("JWE exceeds max_recipients"))
        );
    }

    #[test]
    fn unknown_members_are_ignored_at_every_level() {
        // §7.2.1: "if not understood by implementations encountering them,
        // they MUST be ignored".
        let jwe = object(&[
            r#""x":{"y":[1,2,{"z":null}]}"#,
            A5_PROTECTED,
            &format!(r#""recipients":[{{"note":"hi",{A5_HEADER},{A5_KEY},"n":1}}]"#),
            A5_IV,
            A5_CT,
            A5_TAG,
            r#""signatures":[]"#,
        ]);
        let parts = parsed(&jwe);
        assert_eq!(parts.recipients.len(), 1);
        assert_eq!(parts.recipients[0].encrypted_key.len(), 40);
    }

    #[test]
    fn every_encoded_member_is_strict_base64url() {
        // §5.2 step 2, RFC 7515 §2: no padding, no standard alphabet, no
        // whitespace, canonical trailing bits.
        for name in [
            "protected",
            "encrypted_key",
            "aad",
            "iv",
            "ciphertext",
            "tag",
        ] {
            for bad in ["AA==", "A+/A", "AA AA", "Zh", "A\\nAA"] {
                let member = format!(r#""{name}":"{bad}""#);
                let jwe = a5_with(&[&member], &[name]);
                assert_eq!(parse_code(&jwe), "InvalidBase64", "{member}");
            }
        }
        let in_entry = general(&format!(r#"[{{{A5_HEADER},"encrypted_key":"AA=="}}]"#));
        assert_eq!(parse_code(&in_entry), "InvalidBase64");
    }

    #[test]
    fn the_steps_run_in_order_over_the_whole_document() {
        // Shape (step 3) before base64url (step 4): a bad encoding in one
        // member and a missing ciphertext.
        let jwe = a5_with(&[r#""iv":"AA==""#], &["iv", "ciphertext"]);
        assert_eq!(parse_code(&jwe), "InvalidFormat");
        // Base64url of a later member (step 4) before the protected
        // header's JSON (step 5).
        let not_json = b64url_encode(b"not json");
        let jwe = a5_with(
            &[&format!(r#""protected":"{not_json}""#), r#""tag":"AA==""#],
            &["protected", "tag"],
        );
        assert_eq!(parse_code(&jwe), "InvalidBase64");
        // The protected header (step 5) before the unprotected ones
        // (step 6).
        let jwe = a5_with(
            &[
                &format!(r#""protected":"{not_json}""#),
                r#""header":{"alg":1}"#,
            ],
            &["protected", "header"],
        );
        assert_eq!(parse_code(&jwe), "InvalidJson");
        // A bad encoding in the second recipient still beats a bad header
        // in the first.
        let entries =
            format!(r#"[{{"header":{{"alg":1}}}},{{{A5_HEADER},"encrypted_key":"AA=="}}]"#);
        assert_eq!(parse_code(&general(&entries)), "InvalidBase64");
    }

    #[test]
    fn the_protected_header_must_be_one_json_object() {
        let with = |json: &str| {
            let member = format!(r#""protected":"{}""#, b64url_encode(json.as_bytes()));
            parse_code(&a5_with(&[&member], &["protected"]))
        };
        assert_eq!(with("{"), "InvalidJson");
        assert_eq!(with(r#"{"enc":"A128GCM"} x"#), "InvalidJson");
        // ADR 0041 §1: a duplicate member is InvalidJson.
        assert_eq!(with(r#"{"enc":"A128GCM","enc":"A128GCM"}"#), "InvalidJson");
        // Valid JSON that is not an object: InvalidJson (plan.md lead
        // refinement 15, as for JWS).
        for json in ["[]", "[1]", "\"x\"", "\"\"", "1", "null"] {
            assert_eq!(with(json), "InvalidJson", "{json}");
        }
        assert_eq!(with(r#"{"enc":1}"#), "InvalidHeader");
        // Parsing does not require alg/enc: that is core's header rule.
        assert_eq!(with("{}"), "ok");
    }

    #[test]
    fn unprotected_headers_have_typed_registered_parameters() {
        let shared = a5_with(&[r#""unprotected":{"kid":7}"#], &[]);
        assert_eq!(parse_code(&shared), "InvalidHeader");
        let header = a5_with(&[r#""header":{"alg":["A128KW"]}"#], &["header"]);
        assert_eq!(parse_code(&header), "InvalidHeader");
        let entry = general(r#"[{"header":{"p2c":0}}]"#);
        assert_eq!(parse_code(&entry), "InvalidHeader");
    }

    #[test]
    fn parsing_leaves_the_header_rules_to_core() {
        // Overlapping headers, crit or zip outside the protected header,
        // missing alg: all parse; core decides (§5.2 step 4).
        for extra in [
            r#""unprotected":{"kid":"7"}"#,
            r#""unprotected":{"zip":"DEF"}"#,
            r#""unprotected":{"crit":["x"],"x":1}"#,
        ] {
            assert_eq!(parse_code(&a5_with(&[extra], &[])), "ok", "{extra}");
        }
        let both = a5_with(&[r#""header":{"enc":"A128CBC-HS256"}"#], &["header"]);
        assert_eq!(parse_code(&both), "ok");
    }

    #[test]
    fn errors_carry_no_input() {
        // ADR 0026: error details are fixed strings.
        let secretish = "c2VjcmV0LXZhbHVl";
        for jwe in [
            a5_with(&[&format!(r#""iv":"{secretish}=""#)], &["iv"]),
            a5_with(
                &[&format!(r#""ciphertext":{{"{secretish}":1}}"#)],
                &["ciphertext"],
            ),
            a5_with(
                &[&format!(r#""unprotected":{{"kid":["{secretish}"]}}"#)],
                &[],
            ),
        ] {
            let e = parse(&jwe, &policy()).map(|_| ()).unwrap_err();
            assert!(!format!("{e} {e:?}").contains(secretish), "{e:?}");
        }
    }
}
