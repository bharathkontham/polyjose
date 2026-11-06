//! T05 (tester): the JWS JSON Serialization through the public API only
//! (RFC 7515 §7.2, App. F; RFC 7797 §3, §5.3; ADR 0026 §1-§3, §7;
//! ADR 0041 §1). Every case fails before the signature check (step 9) or
//! only asserts "not this error", so it stays valid while the algorithm
//! families (T06-T09) are stubs and after they land.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

use polyjose::header::Header;
use polyjose::jwa::SigningAlg;
use polyjose::jwk::Jwk;
use polyjose::jws::{
    ProtectedHeader, SignOptions, Signer, Verified, VerifyOptions, sign_flattened, sign_general,
    verify_json,
};

const MARKER_K: &str = "TUFSS0VSc2VjcmV0TUFSS0VSc2VjcmV0TUFSS0VSc2VjcmV0MTI";
const ALLOW: &[SigningAlg] = &[SigningAlg::HS256];
const S: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn b64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let n = c.iter().fold(0u32, |a, b| a << 8 | u32::from(*b)) << (8 * (3 - c.len()));
        for i in 0..=c.len() {
            out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

fn key() -> Jwk {
    Jwk::from_json(format!(r#"{{"kty":"oct","k":"{MARKER_K}"}}"#).as_bytes()).unwrap()
}

fn opts() -> VerifyOptions<'static> {
    VerifyOptions::new(ALLOW).unwrap()
}

fn code(jws: &str, o: &VerifyOptions<'_>) -> &'static str {
    verify_json(jws, &key(), o).map_or_else(|e| e.code(), |_| "ok")
}

fn p(json: &str) -> String {
    b64(json.as_bytes())
}

const HS: &str = r#"{"alg":"HS256"}"#;
const F: &str = r#"{"alg":"HS256","b64":false,"crit":["b64"]}"#;

fn sigobj(protected: &str) -> String {
    format!(r#"{{"protected":"{}","signature":"{S}"}}"#, p(protected))
}

/// The JWS Payload whose base64url is the `"AA"` used throughout.
const AA: &[u8] = &[0];

/// A real HS256 signature with `key()` over `payload` (RFC 7515 §5.1,
/// RFC 7518 §3.2), base64url. With `Some(json)` the protected header is
/// exactly `p(json)`; with `None` the header is an unprotected
/// `{"alg":"HS256"}` only and the signing input starts with an empty
/// string (RFC 7515 §5.1 step 6). Taken from a detached `sign_flattened`,
/// whose signing input is the same as attached (RFC 7515 Appendix F), so
/// the caller can place it in any hand-built JSON shape.
fn real_sig(protected: Option<&str>, payload: &[u8]) -> String {
    let k = key();
    let signer = match protected {
        Some(json) => Signer::new(&k).protected(ProtectedHeader::from_encoded(&p(json)).unwrap()),
        None => {
            let mut h = Header::new();
            h.alg = Some("HS256".into());
            Signer::new(&k).unprotected(h)
        }
    };
    let jws = sign_flattened(&signer, payload, &SignOptions::new().detached(true)).unwrap();
    let (_, rest) = jws.split_once(r#""signature":""#).unwrap();
    rest.split('"').next().unwrap().to_owned()
}

/// [`sigobj`] with a real signature over `payload` instead of the zero tag.
fn real(protected: &str, payload: &[u8]) -> String {
    format!(
        r#"{{"protected":"{}","signature":"{}"}}"#,
        p(protected),
        real_sig(Some(protected), payload)
    )
}

/// `jws` verifies under `o` (RFC 7515 §5.2, §7.2) as HS256 with `payload`,
/// by the signature at `index` (ADR 0026 §3: the first that verifies).
fn assert_verifies(jws: &str, o: &VerifyOptions<'_>, payload: &[u8], index: usize) -> Verified {
    let v = verify_json(jws, &key(), o).unwrap_or_else(|e| panic!("{}: {jws}", e.code()));
    assert_eq!(v.alg, SigningAlg::HS256, "{jws}");
    assert_eq!(v.signature_index, index, "{jws}");
    assert_eq!(*v.payload, payload, "{jws}");
    v
}

fn general(payload: &str, entries: &[String]) -> String {
    format!(
        r#"{{"payload":"{payload}","signatures":[{}]}}"#,
        entries.join(",")
    )
}

#[test]
fn shape_rows_are_invalid_format() {
    let prot = p(HS);
    for jws in [
        // signatures + top-level signature members
        format!(
            r#"{{"payload":"AA","signature":"{S}","signatures":[{}]}}"#,
            sigobj(HS)
        ),
        format!(
            r#"{{"payload":"AA","protected":"{prot}","signatures":[{}]}}"#,
            sigobj(HS)
        ),
        format!(
            r#"{{"payload":"AA","header":{{}},"signatures":[{}]}}"#,
            sigobj(HS)
        ),
        // empty / wrong-typed signatures
        r#"{"payload":"AA","signatures":[]}"#.into(),
        r#"{"payload":"AA","signatures":{}}"#.into(),
        r#"{"payload":"AA","signatures":[1]}"#.into(),
        // signature missing / wrong type
        format!(r#"{{"payload":"AA","protected":"{prot}"}}"#),
        format!(r#"{{"payload":"AA","protected":"{prot}","signature":5}}"#),
        format!(r#"{{"payload":"AA","protected":"{prot}","signature":null}}"#),
        // protected "" / non-string; header non-object
        format!(r#"{{"payload":"AA","protected":"","signature":"{S}"}}"#),
        format!(r#"{{"payload":"AA","protected":7,"signature":"{S}"}}"#),
        format!(r#"{{"payload":"AA","protected":"{prot}","header":[],"signature":"{S}"}}"#),
        format!(r#"{{"payload":"AA","protected":"{prot}","header":"x","signature":"{S}"}}"#),
        // payload missing / not a string
        format!(r#"{{"protected":"{prot}","signature":"{S}"}}"#),
        format!(r#"{{"payload":1,"protected":"{prot}","signature":"{S}"}}"#),
        // not an object
        "[]".into(),
        "\"x\"".into(),
    ] {
        assert_eq!(code(&jws, &opts()), "InvalidFormat", "{jws}");
    }
}

#[test]
fn json_syntax_and_duplicates_are_invalid_json() {
    let prot = p(HS);
    for jws in [
        String::new(),
        "{".into(),
        format!(r#"{{"payload":"AA","protected":"{prot}","signature":"{S}"}}x"#),
        // duplicate top-level, in signature object, in header object
        format!(r#"{{"payload":"AA","payload":"AA","protected":"{prot}","signature":"{S}"}}"#),
        format!(
            r#"{{"payload":"AA","protected":"{prot}","protected":"{prot}","signature":"{S}"}}"#
        ),
        format!(
            r#"{{"payload":"AA","protected":"{prot}","header":{{"kid":"a","kid":"b"}},"signature":"{S}"}}"#
        ),
        format!(
            r#"{{"payload":"AA","signatures":[{{"protected":"{prot}","signature":"{S}","signature":"{S}"}}]}}"#
        ),
        // duplicate inside the decoded protected header
        format!(
            r#"{{"payload":"AA","protected":"{}","signature":"{S}"}}"#,
            p(r#"{"alg":"HS256","alg":"none"}"#)
        ),
        // protected header not an object
        format!(
            r#"{{"payload":"AA","protected":"{}","signature":"{S}"}}"#,
            p("[]")
        ),
    ] {
        assert_eq!(code(&jws, &opts()), "InvalidJson", "{jws}");
    }
}

#[test]
fn limits() {
    let e = sigobj(HS);
    let r = real(HS, AA);
    // the zero tag first, a real one second: index 1 verifies (ADR 0026 §3)
    let two = general("AA", &[e.clone(), r.clone()]);
    assert_verifies(&two, &opts().max_signatures(2), AA, 1);
    assert_eq!(code(&two, &opts().max_signatures(1)), "InvalidFormat");
    let zeros = general("AA", &[e.clone(), e.clone()]);
    assert_eq!(code(&zeros, &opts().max_signatures(2)), "InvalidSignature");
    // flattened is one signature whatever max_signatures says (documented)
    let flat = format!(
        r#"{{"payload":"AA","protected":"{}","signature":"{}"}}"#,
        p(HS),
        real_sig(Some(HS), AA)
    );
    assert_verifies(&flat, &opts().max_signatures(1), AA, 0);
    let n = flat.len();
    assert_verifies(&flat, &opts().max_input_len(n), AA, 0);
    assert_eq!(code(&flat, &opts().max_input_len(n - 1)), "InvalidFormat");
    // a configured limit above the 1 MiB JSON default holds
    let big = "a".repeat((1 << 20) + 10);
    let flat = format!(
        r#"{{"payload":"AA","x":"{big}","protected":"{}","signature":"{}"}}"#,
        p(HS),
        real_sig(Some(HS), AA)
    );
    assert_eq!(code(&flat, &opts()), "InvalidFormat");
    assert_verifies(&flat, &opts().max_input_len(2 << 20), AA, 0);
    // the default max_signatures is 16
    let many = general("AA", &vec![e.clone(); 17]);
    assert_eq!(code(&many, &opts()), "InvalidFormat");
    let mut sixteen = vec![e.clone(); 15];
    sixteen.push(r);
    assert_verifies(&general("AA", &sixteen), &opts(), AA, 15);
    let zeros16 = general("AA", &vec![e; 16]);
    assert_eq!(code(&zeros16, &opts()), "InvalidSignature");
}

#[test]
fn unknown_members_are_ignored() {
    let shape = |sig: &str| {
        format!(
            r#"{{"payload":"AA","x":{{"y":[1,2]}},"protected":"{}","z":1,"signature":"{sig}"}}"#,
            p(HS)
        )
    };
    assert_verifies(&shape(&real_sig(Some(HS), AA)), &opts(), AA, 0);
    // with the zero tag only step 9 fails: x and z were ignored
    assert_eq!(code(&shape(S), &opts()), "InvalidSignature");
}

#[test]
fn header_rules_across_objects() {
    let sig = |prot: Option<&str>, hdr: Option<&str>, signature: &str| {
        let mut m = Vec::new();
        if let Some(x) = prot {
            m.push(format!(r#""protected":"{}""#, p(x)));
        }
        if let Some(x) = hdr {
            m.push(format!(r#""header":{x}"#));
        }
        m.push(format!(r#""signature":"{signature}""#));
        format!(r#"{{"payload":"AA",{}}}"#, m.join(","))
    };
    for (prot, hdr) in [
        (Some(r#"{"alg":"HS256","kid":"a"}"#), Some(r#"{"kid":"b"}"#)), // overlap
        (Some(HS), Some(r#"{"alg":"HS256"}"#)),                         // alg in both
        (
            Some(r#"{"alg":"HS256","crit":["b64"],"b64":false}"#),
            Some(r#"{"crit":["b64"]}"#),
        ),
        (Some(HS), Some(r#"{"crit":["exp"],"exp":1}"#)), // crit in header
        (Some(HS), Some(r#"{"b64":false}"#)),            // b64 unprotected
        (None, Some(r#"{"alg":"HS256"}"#)),              // alg unprotected only is fine?
        (None, None),                                    // missing alg
        (Some(r#"{"kid":"a"}"#), None),                  // missing alg
        (Some(r#"{"alg":5}"#), None),                    // type
        (Some(HS), Some(r#"{"kid":5}"#)),                // type in header
    ] {
        let c = code(&sig(prot, hdr, S), &opts());
        if let (None, Some(_)) = (prot, hdr) {
            // alg may live in the unprotected header (RFC 7515 §7.2.1): the
            // zero tag fails only at step 9 and a real signature, over an
            // empty protected part (RFC 7515 §5.1), verifies.
            assert_eq!(c, "InvalidSignature", "{prot:?} {hdr:?}");
            let v = assert_verifies(&sig(prot, hdr, &real_sig(None, AA)), &opts(), AA, 0);
            assert_eq!(v.protected, None);
            assert_eq!(v.unprotected.and_then(|h| h.alg).as_deref(), Some("HS256"));
        } else {
            assert_eq!(c, "InvalidHeader", "{prot:?} {hdr:?}");
        }
    }
    // an unprotected-only alg of "none" is never accepted
    let none = r#"{"payload":"AA","header":{"alg":"none"},"signature":""}"#.to_string();
    assert_eq!(code(&none, &opts()), "AlgorithmNotAllowed");
}

#[test]
fn b64_mixed_across_signatures_rejects_the_whole_jws() {
    let t = sigobj(HS);
    let f = sigobj(F);
    let jws = general("AA", &[t.clone(), f.clone()]);
    assert_eq!(code(&jws, &opts()), "InvalidHeader");
    let jws = general("AA", &[f, t]);
    assert_eq!(code(&jws, &opts()), "InvalidHeader");
    // explicit b64:true with b64 absent is still the same encoding
    // (zero tag first, so index 1 proves the b64:true entry verified)
    let tt = r#"{"alg":"HS256","b64":true,"crit":["b64"]}"#;
    let jws = general("AA", &[sigobj(HS), real(tt, AA)]);
    assert_verifies(&jws, &opts(), AA, 1);
    let zeros = general("AA", &[sigobj(HS), sigobj(tt)]);
    assert_eq!(code(&zeros, &opts()), "InvalidSignature");
}

#[test]
fn processing_order() {
    let h = |x: &str| p(x);
    // limits beat shape
    assert_eq!(code("[", &opts().max_input_len(0)), "InvalidFormat");
    // shape of a LATER signature beats base64 of an earlier one
    let bad_b64 = format!(r#"{{"protected":"a=","signature":"{S}"}}"#);
    let bad_shape = r#"{"protected":"AA"}"#.to_string();
    assert_eq!(
        code(&general("AA", &[bad_b64.clone(), bad_shape]), &opts()),
        "InvalidFormat"
    );
    // base64 (protected/signature) beats protected JSON of an earlier one
    let bad_json = format!(r#"{{"protected":"{}","signature":"{S}"}}"#, h("{"));
    assert_eq!(
        code(&general("AA", &[bad_json.clone(), bad_b64]), &opts()),
        "InvalidBase64"
    );
    // protected JSON beats parameter types of an earlier one
    let bad_type = format!(
        r#"{{"protected":"{}","signature":"{S}"}}"#,
        h(r#"{"alg":5}"#)
    );
    assert_eq!(
        code(&general("AA", &[bad_type.clone(), bad_json]), &opts()),
        "InvalidJson"
    );
    // parameter types beat the payload base64
    assert_eq!(code(&general("a=", &[bad_type]), &opts()), "InvalidHeader");
    // payload base64 beats header structure (missing alg)
    let noalg = format!(
        r#"{{"protected":"{}","signature":"{S}"}}"#,
        h(r#"{"typ":"JWT"}"#)
    );
    assert_eq!(
        code(&general("a=", std::slice::from_ref(&noalg)), &opts()),
        "InvalidBase64"
    );
    assert_eq!(code(&general("AA", &[noalg]), &opts()), "InvalidHeader");
    // header structure of ANY signature beats unknown-crit/alg of an earlier one
    let uc = format!(
        r#"{{"protected":"{}","signature":"{S}"}}"#,
        h(r#"{"alg":"HS256","crit":["exp"],"exp":1}"#)
    );
    let noalg2 = format!(
        r#"{{"protected":"{}","signature":"{S}"}}"#,
        h(r#"{"typ":"JWT"}"#)
    );
    assert_eq!(
        code(&general("AA", &[uc, noalg2]), &opts()),
        "InvalidHeader"
    );
}

#[test]
fn b64_false_payload_is_not_base64_checked_and_unprotected_b64_does_not_choose() {
    let f = sigobj(F);
    // payload is a free string under b64:false (RFC 7797 §5.3): the
    // octets are the payload; the zero tag fails only at step 9
    let raw = b"a=+/ x.y";
    let jws = general("a=+/ x.y", &[real(F, raw)]);
    assert_verifies(&jws, &opts(), raw, 0);
    assert_eq!(
        code(&general("a=+/ x.y", std::slice::from_ref(&f)), &opts()),
        "InvalidSignature"
    );
    // b64:false disagreement beats a bad payload encoding
    let t = sigobj(HS);
    assert_eq!(code(&general("a=+/ x", &[t, f]), &opts()), "InvalidHeader");
    // b64 only in the unprotected header: InvalidHeader (payload is base64url)
    let un = format!(
        r#"{{"protected":"{}","header":{{"b64":false}},"signature":"{S}"}}"#,
        p(HS)
    );
    assert_eq!(
        code(&general("AA", std::slice::from_ref(&un)), &opts()),
        "InvalidHeader"
    );
    assert_eq!(code(&general("a=", &[un]), &opts()), "InvalidBase64");
}

#[test]
fn detached_rules() {
    let flat = format!(
        r#"{{"payload":"AA","protected":"{}","signature":"{S}"}}"#,
        p(HS)
    );
    let no_payload = format!(r#"{{"protected":"{}","signature":"{S}"}}"#, p(HS));
    let detached = |prot: &str, payload: &[u8]| {
        format!(
            r#"{{"protected":"{}","signature":"{}"}}"#,
            p(prot),
            real_sig(Some(prot), payload)
        )
    };
    let d = opts().detached_payload(b"abc");
    assert_eq!(code(&flat, &d), "InvalidFormat");
    assert_eq!(code(&no_payload, &opts()), "InvalidFormat");
    assert_eq!(code(&no_payload, &d), "InvalidSignature");
    let abc = detached(HS, b"abc");
    assert_verifies(&abc, &d, b"abc", 0);
    let empty = opts().detached_payload(b"");
    assert_eq!(code(&flat, &empty), "InvalidFormat");
    assert_eq!(code(&no_payload, &empty), "InvalidSignature");
    assert_verifies(&detached(HS, b""), &empty, b"", 0);
    // a signature over "abc" is not one over the empty detached payload
    assert_eq!(code(&abc, &empty), "InvalidSignature");
    // detached general
    let g = format!(r#"{{"signatures":[{}]}}"#, sigobj(HS));
    assert_eq!(code(&g, &d), "InvalidSignature");
    assert_eq!(code(&g, &opts()), "InvalidFormat");
    let g = format!(r#"{{"signatures":[{},{}]}}"#, sigobj(HS), real(HS, b"abc"));
    assert_verifies(&g, &d, b"abc", 1);
    assert_eq!(code(&g, &opts()), "InvalidFormat");
    // detached bytes need not be UTF-8 (b64:false verify)
    let raw = [0xff, 0xfe];
    let f = format!(r#"{{"protected":"{}","signature":"{S}"}}"#, p(F));
    assert_eq!(code(&f, &opts().detached_payload(&raw)), "InvalidSignature");
    assert_verifies(&detached(F, &raw), &opts().detached_payload(&raw), &raw, 0);
}

#[test]
fn error_text_never_echoes_input() {
    let secret = "SEKRET-PAYLOAD-MARKER";
    for jws in [
        format!(
            r#"{{"payload":"{secret}!","protected":"{}","signature":"{S}"}}"#,
            p(HS)
        ),
        format!(r#"{{"payload":"AA","protected":"{secret}!","signature":"{S}"}}"#),
        format!(r#"{{"payload":"AA","{secret}":1,"{secret}":2,"signature":"{S}"}}"#),
        format!(
            r#"{{"payload":"AA","protected":"{}","header":{{"kid":"{secret}","kid":1}},"signature":"{S}"}}"#,
            p(HS)
        ),
        format!(
            r#"{{"payload":"AA","protected":"{}","signature":"{S}!{secret}"}}"#,
            p(HS)
        ),
    ] {
        let e = verify_json(&jws, &key(), &opts()).unwrap_err();
        let text = format!("{e} {e:?}");
        assert!(!text.contains(secret) && !text.contains(MARKER_K), "{text}");
    }
}

#[test]
fn sign_public_api_error_rows() {
    let k = key();
    let hs = ProtectedHeader::from_encoded(&p(HS)).unwrap();
    // no signers
    assert_eq!(
        sign_general(&[], b"x", &SignOptions::new())
            .unwrap_err()
            .code(),
        "InvalidFormat"
    );
    // no alg anywhere -> InvalidHeader
    let s = Signer::new(&k);
    assert_eq!(
        sign_flattened(&s, b"x", &SignOptions::new())
            .unwrap_err()
            .code(),
        "InvalidHeader"
    );
    // protected/unprotected overlap
    let mut h = Header::new();
    h.alg = Some("HS256".into());
    let s = Signer::new(&k).protected(hs.clone()).unprotected(h);
    assert_eq!(
        sign_flattened(&s, b"x", &SignOptions::new())
            .unwrap_err()
            .code(),
        "InvalidHeader"
    );
    // b64 mixed across signers
    let f = ProtectedHeader::from_encoded(&p(F)).unwrap();
    let a = Signer::new(&k).protected(hs.clone());
    let b = Signer::new(&k).protected(f.clone());
    assert_eq!(
        sign_general(&[a, b], b"x", &SignOptions::new())
            .unwrap_err()
            .code(),
        "InvalidHeader"
    );
    // crit in the unprotected header
    let mut h = Header::new();
    h.crit = Some(vec!["b64".into()]);
    let s = Signer::new(&k).protected(hs).unprotected(h);
    assert_eq!(
        sign_flattened(&s, b"x", &SignOptions::new())
            .unwrap_err()
            .code(),
        "InvalidHeader"
    );
    // b64:false, non-UTF-8 payload -> InvalidFormat (attached only: it
    // cannot be a JSON string, RFC 7797 §5.3)
    let s = Signer::new(&k).protected(f);
    assert_eq!(
        sign_flattened(&s, &[0xff, 0xfe], &SignOptions::new()).map_err(|e| e.code()),
        Err("InvalidFormat")
    );
}
