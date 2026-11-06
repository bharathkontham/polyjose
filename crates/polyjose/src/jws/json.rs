//! JWS JSON Serialization, flattened and general (RFC 7515 §7.2), with
//! detached content (RFC 7515 Appendix F), the unencoded payload option
//! (RFC 7797 §5.3) and the multiple-signature policy of ADR 0026 §3.
//!
//! The public functions call their `*_with` twins with the real
//! [`FAMILIES`]; tests call the twins with a fake table (see `jws/alg.rs`,
//! "The test seam").
//!
//! # Verification, step by step (ADR 0026 §2, §3)
//!
//! [`verify_json`] owns steps 1–3 and the parsing part of step 4; the rest
//! is the shared chain of `process.rs`. Each step runs over **every**
//! signature before the next step starts, so a JWS that is wrong in
//! several places fails identically whatever the order of its signatures:
//!
//! 1. the input length, then (once parsed) the signature count
//!    → `InvalidFormat`;
//! 2. the RFC 7515 §7.2.1/§7.2.2 shape → `InvalidFormat`; JSON syntax and
//!    duplicate members anywhere in the document → `InvalidJson`;
//! 3. base64url of each `protected` and `signature` (RFC 7515 §5.2 steps
//!    2, 7) → `InvalidBase64`;
//! 4. in this order, each over every signature:
//!    - each protected header is a JSON object (RFC 7515 §5.2 step 3;
//!      duplicates included, ADR 0041 §1) → `InvalidJson`;
//!    - every registered parameter of both headers has its type
//!      (`Header::from_object`) → `InvalidHeader`;
//!    - the payload, base64url-decoded unless the protected headers' `b64`
//!      is `false` (RFC 7515 §5.2 step 6, RFC 7797 §3) → `InvalidBase64`.
//!      It waits until here because only the headers say whether it is
//!      encoded, and runs before the structure rules, as in `compact.rs`
//!      (lead ruling on ADR 0026 §2 steps 3–4). If the protected headers
//!      disagree on `b64` there is no single encoding, so this is skipped
//!      and the disagreement below decides;
//!    - each signature's header structure (`JoseHeader::new`, RFC 7515
//!      §5.2 step 4, §4.1.11), then `b64` agreement across signatures
//!      (`common_b64`, RFC 7797 §3) → `InvalidHeader`;
//! 5. to 9. per signature, in array order, until one verifies
//!    (`verify_signature`, RFC 7515 §5.2 step 8); if none does, the
//!    furthest-progressed error (`furthest`, ADR 0026 §3).

use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::header::Header;
use crate::json::{self, Limits, Object, Value};
use crate::jwk::Jwk;
use crate::util::{b64url_decode, b64url_encode};

use super::alg::{FAMILIES, Families};
use super::process::{
    JoseHeader, common_b64, furthest, prepare_sign, signing_input, verify_signature,
};
use super::{ProtectedHeader, SignOptions, Signer, Verified, VerifyOptions};

/// The members of one signature object (RFC 7515 §7.2.1), which the
/// flattened syntax puts at the top level instead of `signatures`
/// (RFC 7515 §7.2.2).
const SIGNATURE_MEMBERS: [&str; 3] = ["protected", "header", "signature"];

/// Signs `payload` in the flattened JWS JSON Serialization
/// (RFC 7515 §7.2.2): one signature, with its `protected`, `header` and
/// `signature` members at the top level.
///
/// The JOSE Header is the union of the signer's protected and unprotected
/// headers, which must be disjoint (RFC 7515 §5.2 step 4). With no
/// protected header the signing input starts with an empty string
/// (RFC 7515 §5.1). With [`SignOptions::detached`] the `payload` member is
/// omitted (RFC 7515 Appendix F); with `"b64": false` it is the payload
/// itself as a JSON string (RFC 7797 §5.3).
///
/// The output is compact, deterministic JSON.
///
/// # Errors
///
/// As [`sign_general`] with one signer.
pub fn sign_flattened(signer: &Signer<'_>, payload: &[u8], opts: &SignOptions) -> Result<String> {
    sign_flattened_with(&FAMILIES, signer, payload, opts)
}

/// [`sign_flattened`] with the signature primitives taken from `families`.
pub(crate) fn sign_flattened_with(
    families: &Families,
    signer: &Signer<'_>,
    payload: &[u8],
    opts: &SignOptions,
) -> Result<String> {
    let (payload, mut signed) = sign_all(families, core::slice::from_ref(signer), payload, opts)?;
    let mut jws = Object::new();
    if let Some(payload) = payload {
        jws.insert("payload", payload);
    }
    // One signer, one entry.
    if let Some(entry) = signed.pop() {
        entry.write_to(&mut jws);
    }
    Ok(jws.to_json())
}

/// Signs `payload` in the general JWS JSON Serialization
/// (RFC 7515 §7.2.1): one entry in `signatures` per signer, in order.
///
/// Each signer's JOSE Header is the union of its protected and unprotected
/// headers (RFC 7515 §5.2 step 4). Every signer must give the same `b64`
/// value (RFC 7797 §3). Detached content and `b64: false` behave as in
/// [`sign_flattened`].
///
/// # Errors
///
/// For each signer, in order, the first failing check decides:
///
/// - [`Error::InvalidFormat`]: `signers` is empty (RFC 7515 §7.2.1).
/// - [`Error::InvalidHeader`]: the two headers share a name, `alg` is
///   missing, `crit` is malformed or not in the protected header, `b64` is
///   not in the protected header or not listed in `crit`, or the signers
///   disagree on `b64` (RFC 7515 §4.1.11, §5.2 step 4; RFC 7797 §3, §6).
/// - [`Error::UnknownCritical`], [`Error::UnsupportedAlgorithm`] (also for
///   RS*/PS*, ADR 0021), [`Error::AlgorithmNotAllowed`] (`none`),
///   [`Error::KeyAlgorithmMismatch`] or [`Error::InvalidKey`], as for
///   [`sign_compact`](super::sign_compact).
/// - [`Error::InvalidFormat`]: `b64: false` with a payload that is not
///   UTF-8, so it cannot be a JSON string (RFC 7797 §5.3).
/// - [`Error::InvalidKey`] / [`Error::RandomnessUnavailable`] from the
///   algorithm itself.
pub fn sign_general(signers: &[Signer<'_>], payload: &[u8], opts: &SignOptions) -> Result<String> {
    sign_general_with(&FAMILIES, signers, payload, opts)
}

/// [`sign_general`] with the signature primitives taken from `families`.
pub(crate) fn sign_general_with(
    families: &Families,
    signers: &[Signer<'_>],
    payload: &[u8],
    opts: &SignOptions,
) -> Result<String> {
    let (payload, signed) = sign_all(families, signers, payload, opts)?;
    let mut jws = Object::new();
    if let Some(payload) = payload {
        jws.insert("payload", payload);
    }
    let signatures: Vec<Value> = signed
        .into_iter()
        .map(|entry| {
            let mut object = Object::new();
            entry.write_to(&mut object);
            Value::from(object)
        })
        .collect();
    jws.insert("signatures", signatures);
    Ok(jws.to_json())
}

/// One computed signature's members (RFC 7515 §7.2.1).
struct SignedEntry<'s> {
    /// `protected`: the encoding as made or given (RFC 7515 §5.1 step 3).
    protected: Option<&'s str>,
    /// `header`, absent when the JWS Unprotected Header is empty
    /// (RFC 7515 §7.2.1: "MUST be absent").
    header: Option<Object>,
    /// `signature`: BASE64URL(JWS Signature) (RFC 7515 §5.1 step 7).
    signature: String,
}

impl SignedEntry<'_> {
    /// Appends the members in RFC 7515 §7.2.1 order: `protected`,
    /// `header`, `signature`.
    fn write_to(self, object: &mut Object) {
        if let Some(protected) = self.protected {
            object.insert("protected", protected);
        }
        if let Some(header) = self.header {
            object.insert("header", header);
        }
        object.insert("signature", self.signature);
    }
}

/// Computes every signature of a JSON JWS (RFC 7515 §5.1), returning the
/// `payload` member (absent when detached) and one entry per signer.
///
/// Like verification, each step runs over every signer before the next:
/// the header structure of every signer (ADR 0026 §2 step 4, RFC 7515
/// §5.2 step 4) and `b64` agreement (RFC 7797 §3); then steps 5–8 per
/// signer, in order (`prepare_sign`); then the payload rule of RFC 7797
/// §5.3; then the signatures themselves.
fn sign_all<'s>(
    families: &Families,
    signers: &'s [Signer<'_>],
    payload: &[u8],
    opts: &SignOptions,
) -> Result<(Option<Value>, Vec<SignedEntry<'s>>)> {
    if signers.is_empty() {
        return Err(Error::InvalidFormat(
            "a general JWS needs at least one signer",
        ));
    }
    // Step 4 for every signer, then one `b64` for the whole JWS.
    let mut headers = Vec::with_capacity(signers.len());
    let mut unprotected_members = Vec::with_capacity(signers.len());
    for signer in signers {
        let members = signer
            .unprotected
            .as_ref()
            .map(Header::to_object)
            .transpose()?
            .filter(|members| !members.is_empty());
        let protected = signer.protected.as_ref().map(|p| p.header().clone());
        headers.push(JoseHeader::new(protected, signer.unprotected.clone())?);
        unprotected_members.push(members);
    }
    let b64 = common_b64(&headers)?;
    // Steps 5-8, per signer.
    let ready = headers
        .iter()
        .zip(signers)
        .map(|(header, signer)| prepare_sign(header, signer.key))
        .collect::<Result<Vec<_>>>()?;
    // RFC 7797 §5.3: with `b64: false` the payload member is the payload
    // itself, a JSON string, so it must be UTF-8. Detached content is not
    // carried (RFC 7515 Appendix F), so any octets will do.
    let payload_member = match (opts.detached, b64) {
        (true, _) => None,
        (false, true) => Some(Value::from(b64url_encode(payload))),
        (false, false) => Some(Value::from(core::str::from_utf8(payload).map_err(
            |_| Error::InvalidFormat("a b64:false payload must be UTF-8 in the JSON Serialization"),
        )?)),
    };
    // RFC 7515 §5.1 steps 5-7, signer by signer.
    let mut entries = Vec::with_capacity(signers.len());
    for ((signer, ready), header) in signers.iter().zip(&ready).zip(unprotected_members) {
        let protected = signer.protected.as_ref().map(ProtectedHeader::encoded);
        let input = signing_input(protected.unwrap_or(""), payload, b64);
        let signature = b64url_encode(&ready.sign(families, &input)?);
        entries.push(SignedEntry {
            protected,
            header,
            signature,
        });
    }
    Ok((payload_member, entries))
}

/// Verifies a JWS in the JSON Serialization, flattened (RFC 7515 §7.2.2)
/// or general (RFC 7515 §7.2.1), with `key`, accepting only the
/// algorithms `opts` allows.
///
/// RFC 7515 §5.2 leaves the multiple-signature policy to the application;
/// polyjose's is ADR 0026 §3:
///
/// - Steps 1–4 (shape, base64url, header structure) run over **every**
///   signature first, and all signatures must agree on `b64`. Any failure
///   rejects the whole JWS.
/// - Steps 5–9 then run per signature, in array order, and stop at the
///   first that verifies. [`Verified::signature_index`] says which.
/// - If none verifies, the error is that of the signature that got
///   furthest: [`Error::InvalidSignature`] > [`Error::InvalidKey`] >
///   [`Error::KeyAlgorithmMismatch`] > [`Error::AlgorithmNotAllowed`] >
///   [`Error::UnsupportedAlgorithm`] > [`Error::UnknownCritical`], ties
///   to the lowest index.
///
/// With [`VerifyOptions::detached_payload`] the JWS must have no `payload`
/// member (RFC 7515 Appendix F); without it, `payload` is required
/// (RFC 7515 §7.2.1). Unknown top-level members are ignored
/// (RFC 7515 §7.2.1).
///
/// # Errors
///
/// - [`Error::InvalidFormat`]: over [`VerifyOptions::max_input_len`] or
///   [`VerifyOptions::max_signatures`]; not the §7.2 shape (`signature`
///   missing or not a string, `signatures` empty or mixed with top-level
///   signature members, `protected` the empty string, `header` not an
///   object); `payload` present or absent against the detached mode.
/// - [`Error::InvalidJson`]: JSON syntax, or a duplicate member anywhere,
///   including inside a header (ADR 0041 §1).
/// - [`Error::InvalidBase64`], [`Error::InvalidHeader`], then the per-signature
///   errors ranked as above (ADR 0026 §2, §3).
pub fn verify_json(jws: &str, key: &Jwk, opts: &VerifyOptions<'_>) -> Result<Verified> {
    verify_json_with(&FAMILIES, jws, key, opts)
}

/// [`verify_json`] with the signature primitives taken from `families`.
pub(crate) fn verify_json_with(
    families: &Families,
    jws: &str,
    key: &Jwk,
    opts: &VerifyOptions<'_>,
) -> Result<Verified> {
    // Steps 1-2.
    let Parsed {
        payload,
        signatures,
    } = parse(jws, opts)?;

    // Step 3 (RFC 7515 §5.2 steps 2 and 7), every signature.
    let decoded = signatures
        .iter()
        .map(|raw| {
            let protected = raw
                .protected
                .as_deref()
                .map(|p| b64url_decode(p).map(Zeroizing::new))
                .transpose()?;
            Ok((protected, b64url_decode(&raw.signature)?))
        })
        .collect::<Result<Vec<_>>>()?;

    // Step 4, I-JSON (RFC 7515 §5.2 step 3; duplicates are InvalidJson,
    // ADR 0041 §1), every protected header.
    let protected_objects = decoded
        .iter()
        .map(|(protected, _)| protected.as_ref().map(|p| protected_object(p)).transpose())
        .collect::<Result<Vec<_>>>()?;

    // Step 4, parameter types (Header::from_object → InvalidHeader), every
    // header of every signature.
    let mut typed = Vec::with_capacity(signatures.len());
    let mut signed = Vec::with_capacity(signatures.len());
    for ((raw, protected), (_, signature)) in
        signatures.into_iter().zip(protected_objects).zip(decoded)
    {
        let protected = protected.map(Header::from_object).transpose()?;
        let unprotected = raw.header.map(Header::from_object).transpose()?;
        typed.push((protected, unprotected));
        signed.push((raw.protected, signature));
    }

    // Step 3 for the payload (RFC 7515 §5.2 step 6): whether it is
    // base64url at all is the protected headers' `b64` (RFC 7797 §3), so it
    // runs now, before the structure rules, as in compact.rs. If the
    // protected headers disagree there is no one encoding to check; the
    // disagreement is reported below instead (InvalidHeader).
    let encodings: Vec<bool> = typed
        .iter()
        .map(|(protected, _)| protected.as_ref().and_then(|h| h.b64) != Some(false))
        .collect();
    let payload = match encodings.split_first() {
        Some((&b64, rest)) if rest.iter().all(|&other| other == b64) => Some(match payload {
            Payload::Attached(text) if b64 => b64url_decode(&text)?,
            Payload::Attached(text) => text.as_bytes().to_vec(),
            Payload::Detached(octets) => octets.to_vec(),
        }),
        _ => None,
    };

    // Step 4, header structure (RFC 7515 §5.2 step 4), every signature,
    // then `b64` agreement across them (RFC 7797 §3, ADR 0026 §3).
    let headers = typed
        .into_iter()
        .map(|(protected, unprotected)| JoseHeader::new(protected, unprotected))
        .collect::<Result<Vec<_>>>()?;
    let b64 = common_b64(&headers)?;
    // `JoseHeader::new` keeps `b64` out of unprotected headers, so each
    // union's `b64` is its protected header's, and `common_b64` passing
    // means `encodings` agreed and the payload was decoded. Fail closed
    // regardless.
    let Some(payload) = payload else {
        return Err(Error::InvalidHeader("b64 differs between signatures"));
    };

    // Steps 5-9, per signature in array order, first success wins
    // (ADR 0026 §3).
    let mut errors = Vec::with_capacity(headers.len());
    for (signature_index, (header, (protected_b64, signature))) in
        headers.into_iter().zip(signed).enumerate()
    {
        let input = signing_input(protected_b64.as_deref().unwrap_or(""), &payload, b64);
        match verify_signature(families, &header, key, opts, &input, &signature) {
            Ok(alg) => {
                let (protected, unprotected) = header.into_parts();
                return Ok(Verified {
                    alg,
                    protected,
                    unprotected,
                    payload,
                    signature_index,
                });
            }
            Err(e) => errors.push(e),
        }
    }
    // Step 2 guarantees at least one signature, so `furthest` is `Some`;
    // fail closed regardless.
    Err(furthest(errors).unwrap_or(Error::InvalidSignature))
}

/// A JSON JWS after steps 1–2: its payload and its signature objects.
struct Parsed<'a> {
    payload: Payload<'a>,
    signatures: Vec<RawSignature>,
}

/// Where the JWS Payload comes from.
enum Payload<'a> {
    /// The `payload` member as received: BASE64URL(JWS Payload), or with
    /// `b64: false` the payload itself (RFC 7515 §7.2.1, RFC 7797 §5.3).
    Attached(Zeroizing<String>),
    /// [`VerifyOptions::detached_payload`] (RFC 7515 Appendix F).
    Detached(&'a [u8]),
}

/// One signature object's members after step 2 (RFC 7515 §7.2.1).
struct RawSignature {
    /// `protected`, still encoded: the signing input uses it verbatim
    /// (RFC 7515 §5.2 step 8). Never the empty string.
    protected: Option<String>,
    /// `header`, the JWS Unprotected Header, still untyped.
    header: Option<Object>,
    /// `signature`, still encoded.
    signature: String,
}

/// Steps 1 and 2 of ADR 0026 §2: the size limits and the RFC 7515 §7.2
/// shape. Unknown members are ignored at every level (RFC 7515 §7.2.1).
fn parse<'a>(jws: &str, opts: &VerifyOptions<'a>) -> Result<Parsed<'a>> {
    // Step 1, before parsing (ADR 0026 §7). The JSON layer's own input
    // limit follows the caller's, so a larger configured limit holds.
    if jws.len() > opts.max_input_len {
        return Err(Error::InvalidFormat("JWS is longer than max_input_len"));
    }
    let mut limits = Limits::DEFAULT;
    limits.max_input_len = opts.max_input_len;
    // Step 2: JSON syntax and duplicate members, anywhere in the document
    // (RFC 7515 §5.2 step 4, RFC 7493 §2.3) → InvalidJson.
    let mut top = json::parse_with_limits(jws.as_bytes(), &limits)?
        .into_object()
        .ok_or(Error::InvalidFormat(
            "JWS JSON Serialization must be an object",
        ))?;

    let payload = match (top.remove("payload"), opts.detached_payload) {
        (Some(_), Some(_)) => {
            return Err(Error::InvalidFormat(
                "payload member present with a detached payload",
            ));
        }
        (None, None) => return Err(Error::InvalidFormat("payload member missing")),
        (Some(value), None) => Payload::Attached(
            string(value).ok_or(Error::InvalidFormat("payload must be a string"))?,
        ),
        (None, Some(octets)) => Payload::Detached(octets),
    };

    let signatures = match top.remove("signatures") {
        // General (RFC 7515 §7.2.1).
        Some(signatures) => {
            if SIGNATURE_MEMBERS.iter().any(|name| top.contains(name)) {
                return Err(Error::InvalidFormat(
                    "signatures mixed with top-level signature members",
                ));
            }
            let Value::Array(entries) = signatures else {
                return Err(Error::InvalidFormat("signatures must be an array"));
            };
            if entries.is_empty() {
                return Err(Error::InvalidFormat("signatures must not be empty"));
            }
            // Step 1's signature-count limit (ADR 0026 §7), once known.
            if entries.len() > opts.max_signatures {
                return Err(Error::InvalidFormat("more signatures than max_signatures"));
            }
            entries
                .into_iter()
                .map(|entry| {
                    entry
                        .into_object()
                        .ok_or(Error::InvalidFormat("each signature must be an object"))
                        .and_then(raw_signature)
                })
                .collect::<Result<Vec<_>>>()?
        }
        // Flattened (RFC 7515 §7.2.2): the rest of the top level is the
        // one signature object.
        None => vec![raw_signature(top)?],
    };
    Ok(Parsed {
        payload,
        signatures,
    })
}

/// The members of one signature object (RFC 7515 §7.2.1), checked for
/// shape only.
fn raw_signature(mut object: Object) -> Result<RawSignature> {
    // "protected" MUST be absent when the protected header is empty, so
    // the empty string is malformed (ADR 0026 §1).
    let protected = match object.remove("protected") {
        None => None,
        Some(value) => match value.as_str() {
            Some("") => return Err(Error::InvalidFormat("protected must not be empty")),
            Some(encoded) => Some(encoded.to_owned()),
            None => return Err(Error::InvalidFormat("protected must be a string")),
        },
    };
    // "header" is "an unencoded JSON object, rather than as a string".
    let header = object
        .remove("header")
        .map(|value| {
            value
                .into_object()
                .ok_or(Error::InvalidFormat("header must be a JSON object"))
        })
        .transpose()?;
    // "The "signature" member MUST be present".
    let signature = object
        .remove("signature")
        .as_ref()
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(Error::InvalidFormat(
            "signature must be present and a string",
        ))?;
    Ok(RawSignature {
        protected,
        header,
        signature,
    })
}

/// A JSON string member's value, wiped on drop like the `Value` it came
/// from.
fn string(value: Value) -> Option<Zeroizing<String>> {
    match value {
        Value::String(s) => Some(s),
        _ => None,
    }
}

/// A decoded protected header parsed as an I-JSON object (RFC 7515 §5.2
/// step 3), before its parameters are typed.
fn protected_object(octets: &[u8]) -> Result<Object> {
    json::parse(octets)?
        .into_object()
        .ok_or(Error::InvalidJson("protected header must be a JSON object"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::Header;
    use crate::jwa::SigningAlg;
    use crate::jws::ProtectedHeader;
    use crate::jws::alg::fake::{FAKE, REJECTING, fake_signature};
    use crate::jws::alg::test_keys as keys;
    use crate::util::b64url_encode;

    /// RFC 7797 §4's payload `$.02` and its base64url encoding.
    const PAYLOAD: &[u8] = b"$.02";
    const PAYLOAD_B64: &str = "JC4wMg";
    const HS256: &[SigningAlg] = &[SigningAlg::HS256];
    const P_HS256: &str = r#"{"alg":"HS256"}"#;
    /// RFC 7797 §4.2's protected header, `b64: false`.
    const P_B64_FALSE: &str = r#"{"alg":"HS256","b64":false,"crit":["b64"]}"#;

    /// A 64-octet `oct` key: HS256, HS384 and HS512 all accept it. The
    /// fake families ignore it after key binding.
    fn key() -> Jwk {
        keys::oct(64, "")
    }

    fn enc(json: &str) -> String {
        b64url_encode(json.as_bytes())
    }

    /// The base64url fake signature of `protected_b64 '.' payload_part`.
    fn sig(alg: SigningAlg, protected_b64: &str, payload_part: &str) -> String {
        let input = format!("{protected_b64}.{payload_part}");
        b64url_encode(&fake_signature(&alg, input.as_bytes()))
    }

    /// The members of one signature object (no braces), with `signature`
    /// given verbatim.
    fn members_signed(protected: Option<&str>, header: Option<&str>, signature: &str) -> String {
        let mut parts = Vec::new();
        if let Some(p) = protected {
            parts.push(format!(r#""protected":"{}""#, enc(p)));
        }
        if let Some(h) = header {
            parts.push(format!(r#""header":{h}"#));
        }
        parts.push(format!(r#""signature":"{signature}""#));
        parts.join(",")
    }

    /// The members of one signature object (no braces), validly signed
    /// under `alg` over [`PAYLOAD_B64`].
    fn members(protected: Option<&str>, header: Option<&str>, alg: SigningAlg) -> String {
        let p = protected.map(enc).unwrap_or_default();
        members_signed(protected, header, &sig(alg, &p, PAYLOAD_B64))
    }

    fn flattened(members: &str) -> String {
        format!(r#"{{"payload":"{PAYLOAD_B64}",{members}}}"#)
    }

    fn general(entries: &[String]) -> String {
        let entries: Vec<String> = entries.iter().map(|m| format!("{{{m}}}")).collect();
        format!(
            r#"{{"payload":"{PAYLOAD_B64}","signatures":[{}]}}"#,
            entries.join(",")
        )
    }

    fn verify_opts(jws: &str, opts: &VerifyOptions<'_>) -> Result<Verified> {
        verify_json_with(&FAKE, jws, &key(), opts)
    }

    fn verify_allowing(jws: &str, allowed: &[SigningAlg]) -> Result<Verified> {
        verify_opts(jws, &VerifyOptions::new(allowed).unwrap())
    }

    fn verify(jws: &str) -> Result<Verified> {
        verify_allowing(jws, HS256)
    }

    fn code(r: Result<Verified>) -> &'static str {
        r.err().map_or("ok", |e| e.code())
    }

    fn hs256() -> Header {
        Header::from_json(P_HS256.as_bytes()).unwrap()
    }

    fn kid(kid: &str) -> Header {
        let mut h = Header::new();
        h.kid = Some(kid.into());
        h
    }

    // ---- Shape (RFC 7515 §7.2.1, §7.2.2; ADR 0026 §1, §2 steps 1-3) ----

    #[test]
    fn flattened_and_general_verify() {
        let m = members(Some(P_HS256), Some(r#"{"kid":"k1"}"#), SigningAlg::HS256);
        for jws in [flattened(&m), general(std::slice::from_ref(&m))] {
            let v = verify(&jws).unwrap();
            assert_eq!(v.alg, SigningAlg::HS256);
            assert_eq!(v.payload, PAYLOAD);
            assert_eq!(v.signature_index, 0);
            assert_eq!(v.protected, Some(hs256()));
            assert_eq!(v.unprotected, Some(kid("k1")));
        }
    }

    #[test]
    fn signatures_with_top_level_signature_members_is_invalid_format() {
        // RFC 7515 §7.2.2: the flattened members replace `signatures`;
        // ADR 0026 §1: mixing them is a shape error.
        let entry = members(Some(P_HS256), None, SigningAlg::HS256);
        for extra in [
            r#""signature":"AAAA""#,
            r#""protected":"e30""#,
            r#""header":{"kid":"k"}"#,
        ] {
            let jws =
                format!(r#"{{"payload":"{PAYLOAD_B64}",{extra},"signatures":[{{{entry}}}]}}"#);
            assert_eq!(code(verify(&jws)), "InvalidFormat", "{extra}");
        }
    }

    #[test]
    fn signatures_must_be_a_non_empty_array_of_objects() {
        // RFC 7515 §7.2.1: "an array of JSON objects"; ADR 0026 §1.
        for signatures in ["[]", "{}", r#""x""#, "null", "[1]", r#"[[]]"#] {
            let jws = format!(r#"{{"payload":"{PAYLOAD_B64}","signatures":{signatures}}}"#);
            assert_eq!(code(verify(&jws)), "InvalidFormat", "{signatures}");
        }
    }

    #[test]
    fn signature_missing_or_not_a_string_is_invalid_format() {
        // RFC 7515 §7.2.1: "The "signature" member MUST be present".
        let p = format!(r#""protected":"{}""#, enc(P_HS256));
        let cases = [
            p.clone(),
            format!(r#"{p},"signature":1"#),
            format!(r#"{p},"signature":null"#),
            format!(r#"{p},"signature":["AAAA"]"#),
        ];
        for m in &cases {
            assert_eq!(code(verify(&flattened(m))), "InvalidFormat", "{m}");
            assert_eq!(
                code(verify(&general(std::slice::from_ref(m)))),
                "InvalidFormat",
                "{m}"
            );
        }
        // Neither `signature` nor `signatures`.
        assert_eq!(
            code(verify(&format!(r#"{{"payload":"{PAYLOAD_B64}"}}"#))),
            "InvalidFormat"
        );
    }

    #[test]
    fn empty_or_non_string_protected_is_invalid_format() {
        // RFC 7515 §7.2.1: `protected` MUST be absent when the protected
        // header is empty, so "" is malformed (ADR 0026 §1).
        let header = r#""header":{"alg":"HS256"}"#;
        let signature = sig(SigningAlg::HS256, "", PAYLOAD_B64);
        for protected in [r#""""#, "1", "{}", "null"] {
            let m = format!(r#""protected":{protected},{header},"signature":"{signature}""#);
            assert_eq!(code(verify(&flattened(&m))), "InvalidFormat", "{protected}");
            assert_eq!(
                code(verify(&general(std::slice::from_ref(&m)))),
                "InvalidFormat",
                "{protected}"
            );
        }
    }

    #[test]
    fn header_not_an_object_is_invalid_format() {
        // RFC 7515 §7.2.1: `header` is "an unencoded JSON object".
        for header in [r#""e30""#, "[]", "null", "1", "true"] {
            let m = members_signed(
                Some(P_HS256),
                Some(header),
                &sig(SigningAlg::HS256, &enc(P_HS256), PAYLOAD_B64),
            );
            assert_eq!(code(verify(&flattened(&m))), "InvalidFormat", "{header}");
            assert_eq!(code(verify(&general(&[m]))), "InvalidFormat", "{header}");
        }
    }

    #[test]
    fn duplicate_member_anywhere_is_invalid_json() {
        // RFC 7515 §5.2 step 4 and RFC 7493 §2.3 via the JSON layer;
        // ADR 0041 §1 for headers.
        let good = members(Some(P_HS256), None, SigningAlg::HS256);
        let cases = [
            // Top level.
            format!(r#"{{"payload":"{PAYLOAD_B64}","payload":"{PAYLOAD_B64}",{good}}}"#),
            format!(r#"{{"payload":"{PAYLOAD_B64}","x":1,"x":2,{good}}}"#),
            // A flattened signature member.
            flattened(&format!(r#"{good},"signature":"AAAA""#)),
            // A general signature object.
            general(&[format!(r#"{good},"protected":"e30""#)]),
            // Inside the unprotected header, also nested.
            flattened(&members(
                Some(P_HS256),
                Some(r#"{"kid":"a","kid":"b"}"#),
                SigningAlg::HS256,
            )),
            general(&[members(
                Some(P_HS256),
                Some(r#"{"jwk":{"kty":"oct","kty":"RSA"}}"#),
                SigningAlg::HS256,
            )]),
            // Inside the protected header, even spelled differently.
            flattened(&members(
                Some(r#"{"alg":"HS256","alg":"HS256"}"#),
                None,
                SigningAlg::HS256,
            )),
        ];
        for jws in &cases {
            assert_eq!(code(verify(jws)), "InvalidJson", "{jws}");
        }
    }

    #[test]
    fn unknown_members_are_ignored() {
        // RFC 7515 §7.2.1: members not understood MUST be ignored.
        let m = members(Some(P_HS256), None, SigningAlg::HS256);
        let flat = format!(r#"{{"x":{{"y":[1]}},"payload":"{PAYLOAD_B64}",{m},"z":null}}"#);
        let gen_ =
            format!(r#"{{"x":1,"payload":"{PAYLOAD_B64}","signatures":[{{"x":"y",{m}}}],"z":[]}}"#);
        for jws in [flat, gen_] {
            assert_eq!(verify(&jws).unwrap().payload, PAYLOAD, "{jws}");
        }
    }

    #[test]
    fn more_than_max_signatures_is_invalid_format() {
        // ADR 0026 §7: default 16, configurable.
        let m = members(Some(P_HS256), None, SigningAlg::HS256);
        let allowed = HS256;
        let three = general(&vec![m.clone(); 3]);
        let opts = VerifyOptions::new(allowed).unwrap();
        assert_eq!(
            code(verify_opts(&three, &opts.max_signatures(2))),
            "InvalidFormat"
        );
        assert_eq!(code(verify_opts(&three, &opts.max_signatures(3))), "ok");
        assert_eq!(code(verify(&general(&vec![m.clone(); 16]))), "ok");
        assert_eq!(code(verify(&general(&vec![m; 17]))), "InvalidFormat");
    }

    #[test]
    fn input_over_max_input_len_is_invalid_format() {
        // ADR 0026 §7, step 1: checked before parsing.
        let jws = flattened(&members(Some(P_HS256), None, SigningAlg::HS256));
        let opts = VerifyOptions::new(HS256).unwrap();
        assert_eq!(
            code(verify_opts(&jws, &opts.max_input_len(jws.len() - 1))),
            "InvalidFormat"
        );
        assert_eq!(
            code(verify_opts(&jws, &opts.max_input_len(jws.len()))),
            "ok"
        );
        // Not JSON at all, but too long: the limit comes first.
        assert_eq!(
            code(verify_opts("{{{{", &opts.max_input_len(3))),
            "InvalidFormat"
        );
        // A limit above the JSON layer's default 1 MiB is honoured.
        let filler = "a".repeat(VerifyOptions::DEFAULT_MAX_INPUT_LEN);
        let big = format!(
            r#"{{"x":"{filler}","payload":"{PAYLOAD_B64}",{}}}"#,
            members(Some(P_HS256), None, SigningAlg::HS256)
        );
        assert_eq!(code(verify(&big)), "InvalidFormat");
        assert_eq!(
            code(verify_opts(&big, &opts.max_input_len(big.len()))),
            "ok"
        );
    }

    #[test]
    fn not_a_json_object_is_invalid_json_or_invalid_format() {
        for (jws, expected) in [
            ("", "InvalidJson"),
            ("{", "InvalidJson"),
            ("eyJhbGciOiJIUzI1NiJ9.JC4wMg.AAAA", "InvalidJson"),
            ("[]", "InvalidFormat"),
            (r#""x""#, "InvalidFormat"),
            ("null", "InvalidFormat"),
        ] {
            assert_eq!(code(verify(jws)), expected, "{jws}");
        }
    }

    #[test]
    fn payload_not_a_string_is_invalid_format() {
        // RFC 7515 §7.2.1: `payload` is BASE64URL(JWS Payload), a string.
        let m = members(Some(P_HS256), None, SigningAlg::HS256);
        for payload in ["1", "null", "{}", r#"["JC4wMg"]"#] {
            let jws = format!(r#"{{"payload":{payload},{m}}}"#);
            assert_eq!(code(verify(&jws)), "InvalidFormat", "{payload}");
        }
    }

    #[test]
    fn no_protected_header_signs_dot_payload() {
        // RFC 7515 §5.1 step 5 with an empty protected header; RFC 7520
        // §4.7's form: `header` only, signing input "." || b64(payload).
        let signature = b64url_encode(&fake_signature(&SigningAlg::HS256, b".JC4wMg"));
        let m = members_signed(None, Some(r#"{"alg":"HS256","kid":"k"}"#), &signature);
        for jws in [flattened(&m), general(std::slice::from_ref(&m))] {
            let v = verify(&jws).unwrap();
            assert_eq!(v.protected, None);
            assert_eq!(
                v.unprotected.as_ref().and_then(|h| h.kid.as_deref()),
                Some("k")
            );
            assert_eq!(v.payload, PAYLOAD);
        }
        // Signed as if the protected header were "e30" ({}): not the same.
        let wrong = members_signed(
            None,
            Some(r#"{"alg":"HS256"}"#),
            &sig(SigningAlg::HS256, "e30", PAYLOAD_B64),
        );
        assert_eq!(code(verify(&flattened(&wrong))), "InvalidSignature");
    }

    #[test]
    fn bad_base64url_is_invalid_base64() {
        // RFC 7515 §5.2 steps 2, 6, 7; ADR 0026 §2 step 3.
        let p = enc(P_HS256);
        let s = sig(SigningAlg::HS256, &p, PAYLOAD_B64);
        for m in [
            format!(r#""protected":"{p}=","signature":"{s}""#),
            format!(r#""protected":"{p}","signature":"{s}=""#),
            format!(r#""protected":"{p}","signature":"A""#),
            format!(r#""protected":"e+0","signature":"{s}""#),
        ] {
            assert_eq!(code(verify(&flattened(&m))), "InvalidBase64", "{m}");
        }
        let jws = format!(r#"{{"payload":"JC4wMg=","protected":"{p}","signature":"{s}"}}"#);
        assert_eq!(code(verify(&jws)), "InvalidBase64");
    }

    // ---- Header rules across objects (RFC 7515 §5.2 step 4, §4.1.11;
    // RFC 7797 §3) ----

    #[test]
    fn header_rules_are_invalid_header() {
        let cases = [
            // A name in both the protected and the unprotected header.
            members(
                Some(r#"{"alg":"HS256","kid":"a"}"#),
                Some(r#"{"kid":"b"}"#),
                SigningAlg::HS256,
            ),
            members(Some(P_HS256), Some(r#"{"alg":"HS256"}"#), SigningAlg::HS256),
            // `crit` in the unprotected header.
            members(
                Some(P_HS256),
                Some(r#"{"crit":["exp"],"exp":1}"#),
                SigningAlg::HS256,
            ),
            // `b64` in the unprotected header.
            members(Some(P_HS256), Some(r#"{"b64":true}"#), SigningAlg::HS256),
            // A registered parameter of the wrong type, in either header.
            members(Some(P_HS256), Some(r#"{"kid":1}"#), SigningAlg::HS256),
            members(Some(r#"{"alg":"HS256","kid":1}"#), None, SigningAlg::HS256),
            // No `alg` in the union, or no header at all.
            members(None, Some(r#"{"kid":"k"}"#), SigningAlg::HS256),
            members(None, None, SigningAlg::HS256),
        ];
        for m in &cases {
            assert_eq!(code(verify(&flattened(m))), "InvalidHeader", "{m}");
            assert_eq!(
                code(verify(&general(std::slice::from_ref(m)))),
                "InvalidHeader",
                "{m}"
            );
        }
        // The protected header must be a JSON object (ADR 0026 §2 step 4).
        let m = members(Some("[1]"), None, SigningAlg::HS256);
        assert_eq!(code(verify(&flattened(&m))), "InvalidJson");
    }

    #[test]
    fn b64_must_agree_across_signatures() {
        // RFC 7797 §3: every signature must use the same `b64` value; a
        // disagreement rejects the whole JWS (ADR 0026 §3), even though
        // signature 1 verifies on its own.
        let p_false = enc(P_B64_FALSE);
        let unencoded = members_signed(
            Some(P_B64_FALSE),
            None,
            &sig(SigningAlg::HS256, &p_false, PAYLOAD_B64),
        );
        let encoded = members(Some(P_HS256), None, SigningAlg::HS256);
        for entries in [
            [unencoded.clone(), encoded.clone()],
            [encoded.clone(), unencoded.clone()],
        ] {
            assert_eq!(code(verify(&general(&entries))), "InvalidHeader");
        }
        // Absent and `true` are the same value (RFC 7797 §3).
        let explicit_true = r#"{"alg":"HS256","b64":true,"crit":["b64"]}"#;
        let jws = general(&[
            members(Some(explicit_true), None, SigningAlg::HS256),
            encoded,
        ]);
        assert_eq!(code(verify(&jws)), "ok");
    }

    #[test]
    fn b64_false_payload_is_the_json_string() {
        // RFC 7797 §3, §5.3: the signing input ends in the payload octets,
        // and the JSON Serialization carries them as a string.
        let p = enc(P_B64_FALSE);
        let payload = "a \"quoted\" $.02\n";
        let signature = sig(SigningAlg::HS256, &p, payload);
        let jws = format!(
            r#"{{"payload":"a \"quoted\" $.02\n","protected":"{p}","signature":"{signature}"}}"#
        );
        let v = verify(&jws).unwrap();
        assert_eq!(v.payload, payload.as_bytes());
        // Not base64url-decoded: "JC4wMg" stays six octets.
        let s = sig(SigningAlg::HS256, &p, PAYLOAD_B64);
        let jws = format!(r#"{{"payload":"{PAYLOAD_B64}","protected":"{p}","signature":"{s}"}}"#);
        assert_eq!(verify(&jws).unwrap().payload, PAYLOAD_B64.as_bytes());
    }

    #[test]
    fn earlier_steps_win_across_signatures() {
        // ADR 0026 §2-§3: steps 1-4 run over every signature first, step
        // by step, so a later signature's earlier-step error wins.
        let good = members(Some(P_HS256), None, SigningAlg::HS256);
        let overlap = members(Some(P_HS256), Some(r#"{"alg":"HS256"}"#), SigningAlg::HS256);
        let not_json = members(Some("{"), None, SigningAlg::HS256);
        let bad_b64 = members_signed(Some(P_HS256), None, "A");
        let no_sig = format!(r#""protected":"{}""#, enc(P_HS256));
        for (entries, expected) in [
            (vec![overlap.clone(), not_json.clone()], "InvalidJson"),
            (vec![not_json.clone(), bad_b64.clone()], "InvalidBase64"),
            (vec![bad_b64, no_sig], "InvalidFormat"),
            (vec![good.clone(), overlap], "InvalidHeader"),
            (vec![good, not_json], "InvalidJson"),
        ] {
            assert_eq!(code(verify(&general(&entries))), expected, "{entries:?}");
        }
    }

    #[test]
    fn payload_base64_runs_after_header_parsing_before_header_structure() {
        // Lead ruling on ADR 0026 §2 steps 3-4, as in compact.rs: the
        // payload's encoding depends on `b64`, so it is decoded once every
        // protected header has parsed (and its parameters have their
        // types), and before the structure rules.
        let bad_payload = |entries: &[String]| {
            general(entries).replacen(
                &format!(r#""payload":"{PAYLOAD_B64}""#),
                r#""payload":"JC4wMg=""#,
                1,
            )
        };
        let good = members(Some(P_HS256), None, SigningAlg::HS256);
        let no_alg = members(Some(r#"{"kid":"k"}"#), None, SigningAlg::HS256);
        let overlap = members(Some(P_HS256), Some(r#"{"alg":"HS256"}"#), SigningAlg::HS256);
        let unknown_crit = members(
            Some(r#"{"alg":"HS256","crit":["exp"],"exp":1}"#),
            None,
            SigningAlg::HS256,
        );
        let not_json = members(Some("{"), None, SigningAlg::HS256);
        let mistyped = members(
            Some(r#"{"alg":"HS256","b64":"no"}"#),
            None,
            SigningAlg::HS256,
        );
        let mistyped_unprotected = members(Some(P_HS256), Some(r#"{"kid":1}"#), SigningAlg::HS256);
        for (entries, expected) in [
            (vec![good.clone()], "InvalidBase64"),
            (vec![good.clone(), no_alg], "InvalidBase64"),
            (vec![overlap, good.clone()], "InvalidBase64"),
            (vec![unknown_crit], "InvalidBase64"),
            (vec![good.clone(), not_json], "InvalidJson"),
            (vec![good.clone(), mistyped], "InvalidHeader"),
            (vec![mistyped_unprotected, good], "InvalidHeader"),
        ] {
            assert_eq!(
                code(verify(&bad_payload(&entries))),
                expected,
                "{entries:?}"
            );
        }
    }

    #[test]
    fn b64_disagreement_wins_over_the_payload_encoding() {
        // When the protected headers disagree on `b64` (RFC 7797 §3) there
        // is no single payload encoding to check, so the disagreement
        // (InvalidHeader) is reported, never InvalidBase64.
        let p_false = enc(P_B64_FALSE);
        let unencoded = members_signed(
            Some(P_B64_FALSE),
            None,
            &sig(SigningAlg::HS256, &p_false, "$.02"),
        );
        let encoded = members(Some(P_HS256), None, SigningAlg::HS256);
        for entries in [[unencoded.clone(), encoded.clone()], [encoded, unencoded]] {
            let jws = general(&entries).replacen(PAYLOAD_B64, "$.02", 1);
            assert_eq!(code(verify(&jws)), "InvalidHeader");
        }
        // `b64` in the unprotected header does not decide the encoding:
        // the payload is checked as base64url, then the placement fails.
        let misplaced = members(Some(P_HS256), Some(r#"{"b64":false}"#), SigningAlg::HS256);
        let jws = flattened(&misplaced).replacen(PAYLOAD_B64, "$.02", 1);
        assert_eq!(code(verify(&jws)), "InvalidBase64");
        assert_eq!(code(verify(&flattened(&misplaced))), "InvalidHeader");
    }

    // ---- Detached content (RFC 7515 Appendix F) ----

    #[test]
    fn detached_payload_must_match_the_payload_member() {
        let m = members(Some(P_HS256), None, SigningAlg::HS256);
        let opts = VerifyOptions::new(HS256).unwrap();
        // Detached, but `payload` is present.
        assert_eq!(
            code(verify_opts(&flattened(&m), &opts.detached_payload(PAYLOAD))),
            "InvalidFormat"
        );
        // Attached, but `payload` is missing (RFC 7515 §7.2.1: MUST be present).
        let detached = format!("{{{m}}}");
        let general_detached = format!(r#"{{"signatures":[{{{m}}}]}}"#);
        for jws in [&detached, &general_detached] {
            assert_eq!(code(verify_opts(jws, &opts)), "InvalidFormat");
            let v = verify_opts(jws, &opts.detached_payload(PAYLOAD)).unwrap();
            assert_eq!(v.payload, PAYLOAD);
        }
        // The signature covers the detached payload.
        assert_eq!(
            code(verify_opts(&detached, &opts.detached_payload(b"$.03"))),
            "InvalidSignature"
        );
        // b64 false and detached: the raw octets, which need not be UTF-8.
        let p = enc(P_B64_FALSE);
        let raw = [0xff, b'.', 0x00];
        let mut input = format!("{p}.").into_bytes();
        input.extend_from_slice(&raw);
        let s = b64url_encode(&fake_signature(&SigningAlg::HS256, &input));
        let jws = format!(r#"{{"protected":"{p}","signature":"{s}"}}"#);
        let v = verify_opts(&jws, &opts.detached_payload(&raw)).unwrap();
        assert_eq!(v.payload, raw);
    }

    // ---- Multiple signatures (ADR 0026 §3) ----

    #[test]
    fn first_success_wins() {
        let bad = members_signed(
            Some(P_HS256),
            Some(r#"{"kid":"k0"}"#),
            &sig(SigningAlg::HS256, &enc(P_HS256), "other"),
        );
        let k1 = members(Some(P_HS256), Some(r#"{"kid":"k1"}"#), SigningAlg::HS256);
        let k2 = members(
            None,
            Some(r#"{"alg":"HS256","kid":"k2"}"#),
            SigningAlg::HS256,
        );
        let v = verify(&general(&[bad, k1, k2])).unwrap();
        assert_eq!(v.signature_index, 1);
        assert_eq!(v.protected, Some(hs256()));
        assert_eq!(v.unprotected, Some(kid("k1")));

        // Selection by the allow-list: only signature 2 uses HS384.
        let k2_384 = members(
            None,
            Some(r#"{"alg":"HS384","kid":"k2"}"#),
            SigningAlg::HS384,
        );
        let ok = members(Some(P_HS256), None, SigningAlg::HS256);
        let v = verify_allowing(&general(&[ok.clone(), ok, k2_384]), &[SigningAlg::HS384]).unwrap();
        assert_eq!(v.signature_index, 2);
        assert_eq!(v.alg, SigningAlg::HS384);
        assert_eq!(v.protected, None);
        assert_eq!(v.unprotected.and_then(|h| h.kid), Some("k2".into()));
    }

    #[test]
    fn a_malformed_signature_object_rejects_the_whole_jws() {
        // ADR 0026 §3: steps 1-4 over every signature first, even when an
        // earlier one verifies.
        let good = members(Some(P_HS256), None, SigningAlg::HS256);
        let p = enc(P_HS256);
        let s = sig(SigningAlg::HS256, &p, PAYLOAD_B64);
        for (bad, expected) in [
            (format!(r#""protected":"{p}""#), "InvalidFormat"),
            (
                format!(r#""protected":"","signature":"{s}""#),
                "InvalidFormat",
            ),
            (
                format!(r#""protected":"{p}","header":"x","signature":"{s}""#),
                "InvalidFormat",
            ),
            (
                format!(r#""protected":"{p}","signature":"{s}=""#),
                "InvalidBase64",
            ),
            (
                members(Some(r#"{"alg":"HS256""#), None, SigningAlg::HS256),
                "InvalidJson",
            ),
            (
                members(Some(P_HS256), Some(r#"{"alg":"HS256"}"#), SigningAlg::HS256),
                "InvalidHeader",
            ),
            (
                members(
                    Some(P_HS256),
                    Some(r#"{"crit":["b64"]}"#),
                    SigningAlg::HS256,
                ),
                "InvalidHeader",
            ),
        ] {
            let jws = general(&[good.clone(), bad.clone()]);
            assert_eq!(code(verify(&jws)), expected, "{bad}");
        }
    }

    #[test]
    fn none_verifies_reports_the_furthest_error() {
        // ADR 0026 §3: InvalidSignature > InvalidKey > KeyAlgorithmMismatch
        // > AlgorithmNotAllowed > UnsupportedAlgorithm > UnknownCritical.
        let p = enc(P_HS256);
        let invalid_signature =
            members_signed(Some(P_HS256), None, &sig(SigningAlg::HS256, &p, "other"));
        let not_allowed = members(Some(r#"{"alg":"HS384"}"#), None, SigningAlg::HS384);
        let unknown_crit = members(
            Some(r#"{"alg":"HS256","crit":["exp"],"exp":1}"#),
            None,
            SigningAlg::HS256,
        );
        let unsupported = members(Some(r#"{"alg":"HS1"}"#), None, SigningAlg::HS256);
        let mismatch = members(Some(r#"{"alg":"ES256"}"#), None, SigningAlg::ES256);
        let allowed = [SigningAlg::HS256, SigningAlg::ES256];
        for (entries, expected) in [
            (
                vec![invalid_signature.clone(), not_allowed.clone()],
                "InvalidSignature",
            ),
            (
                vec![not_allowed.clone(), invalid_signature.clone()],
                "InvalidSignature",
            ),
            (
                vec![unknown_crit.clone(), unknown_crit.clone()],
                "UnknownCritical",
            ),
            (
                vec![unknown_crit.clone(), unsupported.clone()],
                "UnsupportedAlgorithm",
            ),
            (
                vec![unsupported, not_allowed.clone()],
                "AlgorithmNotAllowed",
            ),
            (
                vec![not_allowed, mismatch.clone(), unknown_crit],
                "KeyAlgorithmMismatch",
            ),
            (vec![mismatch, invalid_signature], "InvalidSignature"),
        ] {
            assert_eq!(
                code(verify_allowing(&general(&entries), &allowed)),
                expected,
                "{entries:?}"
            );
        }
    }

    #[test]
    fn rejecting_family_fails_every_signature() {
        let m = members(Some(P_HS256), None, SigningAlg::HS256);
        let jws = general(&[m.clone(), m]);
        let opts = VerifyOptions::new(HS256).unwrap();
        assert_eq!(
            verify_json_with(&REJECTING, &jws, &key(), &opts),
            Err(Error::InvalidSignature)
        );
    }

    #[test]
    fn public_verify_json_checks_the_shape_first() {
        // The real families are not reached for a malformed JWS.
        let opts = VerifyOptions::new(HS256).unwrap();
        assert_eq!(
            verify_json("[]", &key(), &opts)
                .map(drop)
                .unwrap_err()
                .code(),
            "InvalidFormat"
        );
    }

    // ---- Signing (RFC 7515 §5.1, §7.2) ----

    fn protected(json: &str) -> ProtectedHeader {
        ProtectedHeader::new(Header::from_json(json.as_bytes()).unwrap()).unwrap()
    }

    fn header(json: &str) -> Header {
        Header::from_json(json.as_bytes()).unwrap()
    }

    fn sign_code(r: Result<String>) -> &'static str {
        r.err().map_or("ok", |e| e.code())
    }

    fn attached() -> SignOptions {
        SignOptions::new()
    }

    #[test]
    fn sign_flattened_output_is_exact_and_verifies() {
        // RFC 7515 §7.2.2: payload, protected, header, signature at the
        // top level; compact, deterministic JSON.
        let k = key();
        let signer = Signer::new(&k)
            .protected(protected(P_HS256))
            .unprotected(kid("k1"));
        let jws = sign_flattened_with(&FAKE, &signer, PAYLOAD, &attached()).unwrap();
        let p = enc(P_HS256);
        let s = sig(SigningAlg::HS256, &p, PAYLOAD_B64);
        assert_eq!(
            jws,
            format!(
                r#"{{"payload":"{PAYLOAD_B64}","protected":"{p}","header":{{"kid":"k1"}},"signature":"{s}"}}"#
            )
        );
        assert_eq!(
            sign_flattened_with(&FAKE, &signer, PAYLOAD, &attached()).unwrap(),
            jws
        );
        let v = verify(&jws).unwrap();
        assert_eq!((v.payload.as_slice(), v.signature_index), (PAYLOAD, 0));
        assert_eq!(v.protected, Some(hs256()));
        assert_eq!(v.unprotected, Some(kid("k1")));
    }

    #[test]
    fn sign_flattened_keeps_the_protected_encoding() {
        // RFC 7515 §5.1 step 3: the signature covers the encoded octets,
        // here RFC 7515 A.1's header with its CRLF.
        let a1 = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9";
        let k = key();
        let signer = Signer::new(&k).protected(ProtectedHeader::from_encoded(a1).unwrap());
        let jws = sign_flattened_with(&FAKE, &signer, PAYLOAD, &attached()).unwrap();
        let s = sig(SigningAlg::HS256, a1, PAYLOAD_B64);
        assert_eq!(
            jws,
            format!(r#"{{"payload":"{PAYLOAD_B64}","protected":"{a1}","signature":"{s}"}}"#)
        );
        assert_eq!(verify(&jws).unwrap().payload, PAYLOAD);
    }

    #[test]
    fn sign_general_mixes_header_kinds_and_round_trips() {
        // RFC 7515 §7.2.1: `protected` only, `header` only, and both.
        let k = key();
        let signers = [
            Signer::new(&k).protected(protected(P_HS256)),
            Signer::new(&k).unprotected(header(r#"{"alg":"HS384","kid":"u"}"#)),
            Signer::new(&k)
                .protected(protected(r#"{"alg":"HS512"}"#))
                .unprotected(kid("b")),
        ];
        let jws = sign_general_with(&FAKE, &signers, PAYLOAD, &attached()).unwrap();
        let p0 = enc(P_HS256);
        let p2 = enc(r#"{"alg":"HS512"}"#);
        let s0 = sig(SigningAlg::HS256, &p0, PAYLOAD_B64);
        let s1 = sig(SigningAlg::HS384, "", PAYLOAD_B64);
        let s2 = sig(SigningAlg::HS512, &p2, PAYLOAD_B64);
        assert_eq!(
            jws,
            format!(
                r#"{{"payload":"{PAYLOAD_B64}","signatures":[{{"protected":"{p0}","signature":"{s0}"}},{{"header":{{"alg":"HS384","kid":"u"}},"signature":"{s1}"}},{{"protected":"{p2}","header":{{"kid":"b"}},"signature":"{s2}"}}]}}"#
            )
        );
        for (index, alg) in [SigningAlg::HS256, SigningAlg::HS384, SigningAlg::HS512]
            .into_iter()
            .enumerate()
        {
            let v = verify_allowing(&jws, std::slice::from_ref(&alg)).unwrap();
            assert_eq!(v.signature_index, index);
            assert_eq!(v.alg, alg);
            assert_eq!(v.payload, PAYLOAD);
            assert_eq!(v.protected.is_some(), index != 1);
            assert_eq!(v.unprotected.is_some(), index != 0);
        }
    }

    #[test]
    fn empty_unprotected_header_is_omitted() {
        // RFC 7515 §7.2.1: `header` MUST be absent when the JWS
        // Unprotected Header is empty.
        let k = key();
        let signer = Signer::new(&k)
            .protected(protected(P_HS256))
            .unprotected(Header::new());
        let flat = sign_flattened_with(&FAKE, &signer, PAYLOAD, &attached()).unwrap();
        let gen_ = sign_general_with(&FAKE, &[signer], PAYLOAD, &attached()).unwrap();
        for jws in [flat, gen_] {
            assert!(!jws.contains("header"), "{jws}");
            assert_eq!(verify(&jws).unwrap().unprotected, None);
        }
    }

    #[test]
    fn sign_detached_omits_the_payload_member() {
        // RFC 7515 Appendix F: the signature still covers the payload.
        let k = key();
        let signer = Signer::new(&k).protected(protected(P_HS256));
        let detached = SignOptions::new().detached(true);
        let flat = sign_flattened_with(&FAKE, &signer, PAYLOAD, &detached).unwrap();
        let p = enc(P_HS256);
        let s = sig(SigningAlg::HS256, &p, PAYLOAD_B64);
        assert_eq!(flat, format!(r#"{{"protected":"{p}","signature":"{s}"}}"#));
        let gen_ = sign_general_with(&FAKE, &[signer], PAYLOAD, &detached).unwrap();
        assert_eq!(
            gen_,
            format!(r#"{{"signatures":[{{"protected":"{p}","signature":"{s}"}}]}}"#)
        );
        let opts = VerifyOptions::new(HS256).unwrap().detached_payload(PAYLOAD);
        for jws in [flat, gen_] {
            assert_eq!(verify_opts(&jws, &opts).unwrap().payload, PAYLOAD);
        }
    }

    #[test]
    fn sign_b64_false_carries_the_payload_as_a_json_string() {
        // RFC 7797 §5.3: the unencoded payload is a JSON string, escaped
        // by the serializer; the signing input has its octets (§3).
        let k = key();
        let ph = protected(P_B64_FALSE);
        let p = ph.encoded().to_owned();
        let signer = Signer::new(&k).protected(ph);
        let payload = "a \"quoted\" $.02\n";
        let flat = sign_flattened_with(&FAKE, &signer, payload.as_bytes(), &attached()).unwrap();
        let s = sig(SigningAlg::HS256, &p, payload);
        assert_eq!(
            flat,
            format!(r#"{{"payload":"a \"quoted\" $.02\n","protected":"{p}","signature":"{s}"}}"#)
        );
        let gen_ = sign_general_with(
            &FAKE,
            &[signer.clone(), signer.clone()],
            payload.as_bytes(),
            &attached(),
        )
        .unwrap();
        for jws in [flat, gen_] {
            assert_eq!(verify(&jws).unwrap().payload, payload.as_bytes());
        }

        // Octets that are not UTF-8 cannot be a JSON string.
        let raw = [b'a', 0xff];
        assert_eq!(
            sign_code(sign_flattened_with(&FAKE, &signer, &raw, &attached())),
            "InvalidFormat"
        );
        assert_eq!(
            sign_code(sign_general_with(
                &FAKE,
                std::slice::from_ref(&signer),
                &raw,
                &attached()
            )),
            "InvalidFormat"
        );
        // Detached, they are never carried, so any octets sign.
        let detached = SignOptions::new().detached(true);
        let jws = sign_flattened_with(&FAKE, &signer, &raw, &detached).unwrap();
        let opts = VerifyOptions::new(HS256).unwrap().detached_payload(&raw);
        assert_eq!(verify_opts(&jws, &opts).unwrap().payload, raw);
        // b64 true: any octets, base64url-encoded.
        let plain = Signer::new(&k).protected(protected(P_HS256));
        let jws = sign_flattened_with(&FAKE, &plain, &raw, &attached()).unwrap();
        assert_eq!(verify(&jws).unwrap().payload, raw);
    }

    #[test]
    fn sign_general_with_no_signers_is_invalid_format() {
        // RFC 7515 §7.2.1: `signatures` holds one or more objects.
        assert_eq!(
            sign_code(sign_general_with(&FAKE, &[], PAYLOAD, &attached())),
            "InvalidFormat"
        );
    }

    #[test]
    fn sign_applies_the_header_and_key_rules() {
        // ADR 0026 §2 steps 4-8 on sign, through process.rs.
        let k = key();
        let public = keys::p256("");
        let short = keys::oct(16, "");
        let p = |json| Some(protected(json));
        let u = |json| Some(header(json));
        let cases: [(Option<ProtectedHeader>, Option<Header>, &Jwk, &str); 11] = [
            (
                p(r#"{"alg":"HS256","kid":"a"}"#),
                u(r#"{"kid":"b"}"#),
                &k,
                "InvalidHeader",
            ),
            (None, None, &k, "InvalidHeader"),
            (None, u(r#"{"kid":"k"}"#), &k, "InvalidHeader"),
            (
                p(P_HS256),
                u(r#"{"crit":["exp"],"exp":1}"#),
                &k,
                "InvalidHeader",
            ),
            (
                p(r#"{"alg":"HS256","b64":false}"#),
                None,
                &k,
                "InvalidHeader",
            ),
            (
                p(r#"{"alg":"HS256","crit":["exp"],"exp":1}"#),
                None,
                &k,
                "UnknownCritical",
            ),
            (p(r#"{"alg":"HS1"}"#), None, &k, "UnsupportedAlgorithm"),
            (p(r#"{"alg":"none"}"#), None, &k, "AlgorithmNotAllowed"),
            (None, u(r#"{"alg":"RS256"}"#), &k, "UnsupportedAlgorithm"),
            (
                p(r#"{"alg":"ES256"}"#),
                None,
                &public,
                "KeyAlgorithmMismatch",
            ),
            (p(P_HS256), None, &short, "InvalidKey"),
        ];
        for (protected, unprotected, key, expected) in cases {
            let mut signer = Signer::new(key);
            signer.protected = protected;
            signer.unprotected = unprotected;
            assert_eq!(
                sign_code(sign_flattened_with(&FAKE, &signer, PAYLOAD, &attached())),
                expected,
                "{signer:?}"
            );
            assert_eq!(
                sign_code(sign_general_with(&FAKE, &[signer], PAYLOAD, &attached())),
                expected
            );
        }
    }

    #[test]
    fn sign_general_checks_every_signer_step_by_step() {
        let k = key();
        let ok = Signer::new(&k).protected(protected(P_HS256));
        let none = Signer::new(&k).protected(protected(r#"{"alg":"none"}"#));
        let overlap = Signer::new(&k)
            .protected(protected(P_HS256))
            .unprotected(header(r#"{"alg":"HS256"}"#));
        let unencoded = Signer::new(&k).protected(protected(P_B64_FALSE));
        let unencoded_unknown = Signer::new(&k).protected(protected(
            r#"{"alg":"HS256","b64":false,"crit":["b64","exp"],"exp":1}"#,
        ));
        let unknown =
            Signer::new(&k).protected(protected(r#"{"alg":"HS256","crit":["exp"],"exp":1}"#));
        let raw: &[u8] = &[0xff];
        for (signers, payload, expected) in [
            // Step 4 runs over every signer before steps 5-8.
            (vec![none.clone(), overlap], PAYLOAD, "InvalidHeader"),
            // RFC 7797 §3: one `b64` value for the whole JWS.
            (
                vec![ok.clone(), unencoded.clone()],
                PAYLOAD,
                "InvalidHeader",
            ),
            (
                vec![unencoded.clone(), ok.clone()],
                PAYLOAD,
                "InvalidHeader",
            ),
            // Steps 5-8 per signer, in order.
            (
                vec![none.clone(), unknown.clone()],
                PAYLOAD,
                "AlgorithmNotAllowed",
            ),
            (vec![unknown, none], PAYLOAD, "UnknownCritical"),
            // Then the payload rule (RFC 7797 §5.3).
            (
                vec![unencoded.clone(), unencoded_unknown],
                raw,
                "UnknownCritical",
            ),
            (vec![unencoded.clone(), unencoded], raw, "InvalidFormat"),
            (vec![ok.clone(), ok], raw, "ok"),
        ] {
            assert_eq!(
                sign_code(sign_general_with(&FAKE, &signers, payload, &attached())),
                expected,
                "{signers:?}"
            );
        }
    }

    #[test]
    fn public_sign_functions_check_headers_before_the_family() {
        let k = key();
        assert_eq!(
            sign_code(sign_general(&[], PAYLOAD, &attached())),
            "InvalidFormat"
        );
        let no_alg = Signer::new(&k).unprotected(kid("k"));
        assert_eq!(
            sign_code(sign_flattened(&no_alg, PAYLOAD, &attached())),
            "InvalidHeader"
        );
    }
}
