//! The JWE Compact Serialization (RFC 7516 §7.1): five base64url parts,
//! `protected.encrypted_key.iv.ciphertext.tag`, for exactly one recipient,
//! with no unprotected header and no JWE AAD.
//!
//! This file only converts between the text and [`JweParts`]; every
//! processing rule after parsing is `core`'s.

use super::api::DecryptPolicy;
use super::core::{self, JweParts, RecipientParts};
use crate::util::{b64url_decode, b64url_encode};
use crate::{Error, Result};

/// Splits and decodes a compact JWE (RFC 7516 §5.2 steps 1–3, §7.1), in
/// the order of the plan.md error contract (ADR 0026 §2 applied to JWE):
///
/// 1. the input length, before anything else is looked at (ADR 0026 §7);
/// 2. exactly five parts (§5.2 step 1, §7.1);
/// 3. every part strict base64url (§5.2 step 2; RFC 7515 §2: no padding,
///    no line breaks, no other characters);
/// 4. the protected header a JSON object (§5.2 step 3,
///    [`core::parse_protected`]).
///
/// The encoded protected header is kept exactly as received, for the AAD
/// (§5.2 step 14). That `alg` and `enc` are in it (§7.1: the protected
/// header is the whole JOSE Header) is one of `core`'s header rules.
///
/// # Errors
///
/// [`Error::InvalidFormat`] for an input over `policy`'s `max_input_len`
/// or other than exactly five parts; [`Error::InvalidBase64`] for a part
/// that is not strict base64url; [`Error::InvalidJson`] (syntax, I-JSON,
/// duplicate members, ADR 0041 §1) or [`Error::InvalidHeader`] for the
/// protected header. No error carries any part of the input.
pub(crate) fn parse(token: &str, policy: &DecryptPolicy) -> Result<JweParts> {
    if token.len() > policy.max_input_len {
        return Err(Error::InvalidFormat("compact JWE exceeds max_input_len"));
    }
    let [protected_b64, encrypted_key, iv, ciphertext, tag] = split(token)?;
    let protected_json = b64url_decode(protected_b64)?;
    let encrypted_key = b64url_decode(encrypted_key)?;
    let iv = b64url_decode(iv)?;
    let ciphertext = b64url_decode(ciphertext)?;
    let tag = b64url_decode(tag)?;
    let protected = core::parse_protected(&protected_json)?;
    Ok(JweParts {
        protected_b64: protected_b64.to_owned(),
        protected: Some(protected),
        shared: None,
        recipients: vec![RecipientParts {
            header: None,
            encrypted_key,
        }],
        iv,
        ciphertext,
        tag,
        aad: None,
    })
}

/// Writes `parts` as a compact JWE (RFC 7516 §7.1):
/// `BASE64URL(UTF8(JWE Protected Header)) '.' BASE64URL(JWE Encrypted Key)
/// '.' BASE64URL(JWE Initialization Vector) '.' BASE64URL(JWE Ciphertext)
/// '.' BASE64URL(JWE Authentication Tag)`, with the protected header in
/// the encoding the AAD was computed over.
///
/// # Errors
///
/// [`Error::InvalidFormat`] if `parts` has other than one recipient, no
/// protected header, an unprotected header or a JWE AAD, none of which
/// the compact serialization can carry (§7.1).
pub(crate) fn serialize(parts: &JweParts) -> Result<String> {
    let [recipient] = parts.recipients.as_slice() else {
        return Err(Error::InvalidFormat(
            "compact JWE must have exactly one recipient",
        ));
    };
    if parts.protected_b64.is_empty() {
        return Err(Error::InvalidFormat("compact JWE needs a protected header"));
    }
    if parts.shared.is_some() || recipient.header.is_some() {
        return Err(Error::InvalidFormat(
            "compact JWE cannot carry an unprotected header",
        ));
    }
    if parts.aad.is_some() {
        return Err(Error::InvalidFormat("compact JWE cannot carry a JWE AAD"));
    }
    Ok([
        parts.protected_b64.clone(),
        b64url_encode(&recipient.encrypted_key),
        b64url_encode(&parts.iv),
        b64url_encode(&parts.ciphertext),
        b64url_encode(&parts.tag),
    ]
    .join("."))
}

/// The five parts of a compact JWE (RFC 7516 §7.1; §5.2 step 1: "parse the
/// JWE representation to extract the serialized values").
///
/// # Errors
///
/// [`Error::InvalidFormat`] for any other number of parts (ADR 0026 §1).
fn split(token: &str) -> Result<[&str; 5]> {
    let mut parts = token.split('.');
    let mut out = [""; 5];
    for slot in &mut out {
        *slot = parts
            .next()
            .ok_or(Error::InvalidFormat("compact JWE must have five parts"))?;
    }
    if parts.next().is_some() {
        return Err(Error::InvalidFormat("compact JWE must have five parts"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::Header;
    use crate::jwa::{ContentEncAlg, KeyMgmtAlg};
    use zeroize::Zeroizing;

    /// RFC 7516 A.3.7.
    const A3: &str = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.\
        6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.\
        AxY8DCtDaGlsbGljb3RoZQ.\
        KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.\
        U0m_YmjN04DJvceFICbCVQ";

    fn policy() -> DecryptPolicy {
        DecryptPolicy::new(&[KeyMgmtAlg::A128KW], &[ContentEncAlg::A128CbcHs256])
            .unwrap_or_else(|e| panic!("{e}"))
    }

    fn parse_code(token: &str) -> &'static str {
        match parse(token, &policy()) {
            Ok(_) => "ok",
            Err(e) => e.code(),
        }
    }

    #[test]
    fn parses_rfc_7516_a3_and_serializes_it_back() {
        let parts = parse(A3, &policy()).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            parts.protected_b64,
            "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0"
        );
        let protected = parts.protected.as_ref().unwrap_or_else(|| panic!("none"));
        assert_eq!(protected.alg.as_deref(), Some("A128KW"));
        assert_eq!(protected.enc, Some(ContentEncAlg::A128CbcHs256));
        assert_eq!(parts.recipients.len(), 1);
        assert_eq!(parts.recipients[0].encrypted_key.len(), 40);
        assert!(parts.recipients[0].header.is_none());
        assert_eq!(parts.iv.len(), 16);
        assert_eq!(parts.ciphertext.len(), 32);
        assert_eq!(parts.tag.len(), 16);
        assert!(parts.shared.is_none() && parts.aad.is_none());
        assert_eq!(serialize(&parts).as_deref(), Ok(A3));
    }

    #[test]
    fn exactly_five_parts() {
        let parts: Vec<&str> = A3.split('.').collect();
        for n in [1, 2, 3, 4] {
            assert_eq!(parse_code(&parts[..n].join(".")), "InvalidFormat", "{n}");
        }
        assert_eq!(parse_code(&format!("{A3}.")), "InvalidFormat");
        assert_eq!(parse_code(&format!("{A3}.AA")), "InvalidFormat");
        assert_eq!(parse_code(""), "InvalidFormat");
        assert_eq!(parse_code("...."), "InvalidJson"); // five empty parts
    }

    #[test]
    fn the_length_limit_comes_before_anything_else() {
        // ADR 0026 §7: even a malformed input over the limit is only
        // InvalidFormat, so no parsing work is done on it.
        let at_limit = policy().max_input_len(A3.len());
        assert!(parse(A3, &at_limit).is_ok());
        let under = policy().max_input_len(A3.len() - 1);
        assert_eq!(
            parse(A3, &under).map(|_| ()),
            Err(Error::InvalidFormat("compact JWE exceeds max_input_len"))
        );
        let garbage = "=".repeat(64);
        let tiny = policy().max_input_len(10);
        assert_eq!(
            parse(&garbage, &tiny).map(|_| ()).unwrap_err().code(),
            "InvalidFormat"
        );
    }

    #[test]
    fn every_part_must_be_strict_base64url() {
        // RFC 7516 §5.2 step 2, RFC 7515 §2: no padding, no standard
        // alphabet, no whitespace, canonical trailing bits.
        let parts: Vec<&str> = A3.split('.').collect();
        for i in 0..5 {
            for bad in ["AA==", "A+/A", "AA AA", "Zh", "A\nAA"] {
                let mut p = parts.clone();
                p[i] = bad;
                assert_eq!(
                    parse_code(&p.join(".")),
                    "InvalidBase64",
                    "part {i}: {bad:?}"
                );
            }
        }
    }

    #[test]
    fn base64url_is_checked_in_every_part_before_the_header() {
        // A bad header and a bad later part: step 2 (base64url) wins over
        // step 3 (header JSON).
        let not_json = b64url_encode(b"not json");
        let token = format!("{not_json}..AA==..");
        assert_eq!(parse_code(&token), "InvalidBase64");
    }

    #[test]
    fn the_protected_header_must_be_one_json_object() {
        let enc = |json: &str| format!("{}..AAAA.AAAA.AAAA", b64url_encode(json.as_bytes()));
        assert_eq!(parse_code(&enc("")), "InvalidJson");
        assert_eq!(parse_code(&enc("{")), "InvalidJson");
        assert_eq!(parse_code(&enc(r#"{"alg":"dir"} x"#)), "InvalidJson");
        // ADR 0041 §1: a duplicate member is InvalidJson.
        assert_eq!(
            parse_code(&enc(r#"{"alg":"dir","alg":"dir","enc":"A128GCM"}"#)),
            "InvalidJson"
        );
        // Valid JSON that is not an object: InvalidJson, as for JWS
        // (ADR 0026 §2 step 4).
        for json in ["[]", "[1]", "\"x\"", "\"\"", "1", "null"] {
            assert_eq!(parse_code(&enc(json)), "InvalidJson", "{json}");
        }
        // A registered parameter of the wrong type.
        assert_eq!(
            parse_code(&enc(r#"{"alg":1,"enc":"A128GCM"}"#)),
            "InvalidHeader"
        );
        // Parsing does not require alg/enc: that is core's header rule.
        assert_eq!(parse_code(&enc("{}")), "ok");
    }

    #[test]
    fn the_received_header_encoding_is_kept() {
        // RFC 7516 §5.2 step 14, erratum 8676: the AAD is the received
        // text, so it is kept byte for byte, spacing and order included.
        let json = "{ \"enc\" : \"A128GCM\",\r\n \"alg\":\"dir\" }";
        let encoded = b64url_encode(json.as_bytes());
        let parts = parse(&format!("{encoded}..AAAA.AAAA.AAAA"), &policy())
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(parts.protected_b64, encoded);
        assert_eq!(serialize(&parts), Ok(format!("{encoded}..AAAA.AAAA.AAAA")));
    }

    #[test]
    fn serialize_refuses_what_compact_cannot_carry() {
        let base = || parse(A3, &policy()).unwrap_or_else(|e| panic!("{e}"));
        let mut two = base();
        two.recipients.push(two.recipients[0].clone());
        let mut none = base();
        none.recipients.clear();
        let mut shared = base();
        shared.shared = Some(Header::new());
        let mut per_recipient = base();
        per_recipient.recipients[0].header = Some(Header::new());
        let mut aad = base();
        aad.aad = Some(Zeroizing::new(Vec::new()));
        let mut no_protected = base();
        no_protected.protected_b64.clear();
        for parts in [two, none, shared, per_recipient, aad, no_protected] {
            assert_eq!(serialize(&parts).unwrap_err().code(), "InvalidFormat");
        }
    }
}
