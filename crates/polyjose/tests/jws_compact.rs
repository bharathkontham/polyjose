//! T04 (tester): the JWS Compact Serialization through the public API only
//! (RFC 7515 §5.2, §7.1, App. A.5, App. F; RFC 7797 §5.2; ADR 0026 §2, §7;
//! ADR 0041 §1). Every case here fails before the signature check (step 9)
//! or only asserts "not this error", so it stays valid while the algorithm
//! families (T06-T09) are stubs and after they land.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

use polyjose::header::Header;
use polyjose::jwa::SigningAlg;
use polyjose::jwk::Jwk;
use polyjose::jws::{ProtectedHeader, SignOptions, VerifyOptions, sign_compact, verify_compact};

const MARKER_K: &str = "TUFSS0VSc2VjcmV0TUFSS0VSc2VjcmV0TUFSS0VSc2VjcmV0MTI";
const A5_NONE: &str = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.";
const ALLOW: &[SigningAlg] = &[SigningAlg::HS256];

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

fn code(jws: &str, opts: &VerifyOptions<'_>) -> &'static str {
    verify_compact(jws, &key(), opts).map_or_else(|e| e.code(), |_| "ok")
}

fn hdr(json: &str) -> String {
    b64(json.as_bytes())
}

fn opts() -> VerifyOptions<'static> {
    VerifyOptions::new(ALLOW).unwrap()
}

/// A real HS256 JWS over `payload` with `key()` (RFC 7515 §5.1, RFC 7518
/// §3.2), under the protected header whose base64url encoding is exactly
/// `encoded`, so the token shares its first part with the hand-built ones.
/// `detached` leaves the payload part empty (RFC 7515 Appendix F).
fn sign_real(encoded: &str, payload: &[u8], detached: bool) -> String {
    let protected = ProtectedHeader::from_encoded(encoded).unwrap();
    let opts = SignOptions::new().detached(detached);
    sign_compact(&protected, payload, &key(), &opts).unwrap()
}

/// `jws` verifies under `opts` (RFC 7515 §5.2) as HS256, signature 0, no
/// unprotected header (compact has none, RFC 7515 §7.1), with `payload`.
fn assert_verifies(jws: &str, opts: &VerifyOptions<'_>, payload: &[u8]) {
    let v = verify_compact(jws, &key(), opts).unwrap_or_else(|e| panic!("{}: {jws}", e.code()));
    assert_eq!(v.alg, SigningAlg::HS256, "{jws}");
    assert_eq!(v.signature_index, 0, "{jws}");
    assert_eq!(v.unprotected, None, "{jws}");
    assert!(v.protected.is_some(), "{jws}");
    assert_eq!(*v.payload, payload, "{jws}");
}

#[test]
fn a5_none_token_is_algorithm_not_allowed_for_every_list() {
    let lists: [&[SigningAlg]; 4] = [
        ALLOW,
        &[SigningAlg::ES256, SigningAlg::EdDSA],
        &[SigningAlg::HS512, SigningAlg::Ed25519, SigningAlg::ES256K],
        SigningAlg::KNOWN,
    ];
    for l in lists {
        // `none` itself cannot be in a list, so KNOWN minus none.
        let l: Vec<SigningAlg> = l
            .iter()
            .filter(|a| **a != SigningAlg::None)
            .cloned()
            .collect();
        let o = VerifyOptions::new(&l).unwrap();
        assert_eq!(code(A5_NONE, &o), "AlgorithmNotAllowed");
        // With a junk non-empty signature too (a forged "none" token).
        assert_eq!(code(&format!("{A5_NONE}AAAA"), &o), "AlgorithmNotAllowed");
    }
}

#[test]
fn shape_limits_and_base64_rows() {
    let h = hdr(r#"{"alg":"HS256"}"#);
    let p = b64(b"hi");
    let s = b64(&[0u8; 32]);
    for jws in [
        String::new(),
        h.clone(),
        format!("{h}.{p}"),
        format!("{h}.{p}.{s}.{s}"),
        format!("{h}.{p}.{s}."),
    ] {
        assert_eq!(code(&jws, &opts()), "InvalidFormat", "{jws}");
    }
    // A real signature over the same header and payload: exactly
    // max_input_len verifies, one octet less is refused (step 1).
    let ok = sign_real(&h, b"hi", false);
    assert!(ok.starts_with(&format!("{h}.{p}.")), "{ok}");
    let n = ok.len();
    assert_verifies(&ok, &opts().max_input_len(n), b"hi");
    assert_eq!(code(&ok, &opts().max_input_len(n - 1)), "InvalidFormat");
    // The same shape with an all-zero tag passes steps 1-8 and fails step 9.
    let zero = format!("{h}.{p}.{s}");
    assert_eq!(zero.len(), n);
    assert_eq!(code(&zero, &opts().max_input_len(n)), "InvalidSignature");
    // Padding, '+', '/', whitespace, a stray '.'-free garbage char, in each part.
    for bad in [
        "aGk=", "a+b", "a/b", "aG k", "aGk\n", " aGk", "aG\u{e9}", "a$b",
    ] {
        assert_eq!(
            code(&format!("{bad}.{p}.{s}"), &opts()),
            "InvalidBase64",
            "hdr {bad:?}"
        );
        assert_eq!(
            code(&format!("{h}.{bad}.{s}"), &opts()),
            "InvalidBase64",
            "pay {bad:?}"
        );
        assert_eq!(
            code(&format!("{h}.{p}.{bad}"), &opts()),
            "InvalidBase64",
            "sig {bad:?}"
        );
    }
    // A single leftover sextet (length % 4 == 1) is not base64url.
    assert_eq!(code(&format!("{h}.{p}.A"), &opts()), "InvalidBase64");
}

#[test]
fn header_json_rows() {
    let p = b64(b"hi");
    let s = b64(&[0u8; 32]);
    for (json, want) in [
        (r#"{"alg":"HS256"}x"#, "InvalidJson"),
        (r#"{"alg":"HS256"} {"alg":"HS256"}"#, "InvalidJson"),
        (r#"{"alg":"HS256","alg":"HS256"}"#, "InvalidJson"),
        (r#"{"alg":"HS256","alg":"none"}"#, "InvalidJson"),
        ("", "InvalidJson"),
        ("[]", "InvalidJson"),
        ("null", "InvalidJson"),
        ("{", "InvalidJson"),
        (r#"{"typ":"JWT"}"#, "InvalidHeader"),
        (r#"{"alg":5}"#, "InvalidHeader"),
    ] {
        assert_eq!(
            code(&format!("{}.{p}.{s}", hdr(json)), &opts()),
            want,
            "{json}"
        );
    }
}

#[test]
fn detached_rules() {
    let h = hdr(r#"{"alg":"HS256"}"#);
    let s = b64(&[0u8; 32]);
    let payload = b"detached payload";
    let d = opts().detached_payload(payload);
    // Non-empty payload part against a detached payload.
    assert_eq!(
        code(&format!("{h}.{}.{s}", b64(payload)), &d),
        "InvalidFormat"
    );
    assert_eq!(code(&format!("{h}.AAAA.{s}"), &d), "InvalidFormat");
    // Even an undecodable payload part is a format error first (step 2 before 3).
    assert_eq!(code(&format!("{h}.a=.{s}"), &d), "InvalidFormat");
    // Empty part: the detached octets are what is verified (Appendix F).
    let det = sign_real(&h, payload, true);
    assert!(det.starts_with(&format!("{h}..")), "{det}");
    assert_verifies(&det, &d, payload);
    assert_eq!(code(&format!("{h}..{s}"), &d), "InvalidSignature");
    // Without the detached octets the same token is a signature over an
    // empty payload, so it fails at step 9, not at a format check.
    assert_eq!(code(&det, &opts()), "InvalidSignature");
    // Empty detached payload is still "detached": a non-empty part is refused.
    let empty = opts().detached_payload(b"");
    assert_eq!(code(&format!("{h}.AAAA.{s}"), &empty), "InvalidFormat");
    // No detached payload: an empty part is a legal empty payload.
    let none = sign_real(&h, b"", false);
    assert!(none.starts_with(&format!("{h}..")), "{none}");
    assert_verifies(&none, &opts(), b"");
    assert_verifies(&none, &empty, b"");
    assert_eq!(code(&format!("{h}..{s}"), &opts()), "InvalidSignature");
}

#[test]
fn max_input_len_excludes_a_detached_payload() {
    let h = hdr(r#"{"alg":"HS256"}"#);
    let s = b64(&[0u8; 32]);
    let big = vec![b'x'; 1 << 16];
    let jws = sign_real(&h, &big, true);
    assert!(jws.starts_with(&format!("{h}..")), "{jws}");
    let o = opts().detached_payload(&big).max_input_len(jws.len());
    assert_verifies(&jws, &o, &big);
    let o = opts().detached_payload(&big).max_input_len(jws.len() - 1);
    assert_eq!(code(&jws, &o), "InvalidFormat");
    // The all-zero tag of the same length is past step 1 and fails step 9.
    let zero = format!("{h}..{s}");
    let o = opts().detached_payload(&big).max_input_len(zero.len());
    assert_eq!(code(&zero, &o), "InvalidSignature");
}

#[test]
fn processing_order_of_steps_1_to_4() {
    let s = b64(&[0u8; 32]);
    let noalg = hdr(r#"{"typ":"JWT"}"#);
    let bad_json = hdr("{");
    // limits beat everything; parts beat base64.
    assert_eq!(code("a=.b=", &opts()), "InvalidFormat");
    assert_eq!(code("a=.b=.c=.d", &opts()), "InvalidFormat");
    // header base64 beats signature base64 beats header JSON.
    assert_eq!(code("a=.AAAA.b=", &opts()), "InvalidBase64");
    assert_eq!(
        code(&format!("{bad_json}.AAAA.b="), &opts()),
        "InvalidBase64"
    );
    // header JSON beats payload base64 (the documented ordering).
    assert_eq!(code(&format!("{bad_json}.a=.{s}"), &opts()), "InvalidJson");
    // payload base64 beats header structure.
    assert_eq!(code(&format!("{noalg}.a=.{s}"), &opts()), "InvalidBase64");
    // header structure beats algorithm checks.
    assert_eq!(code(&format!("{noalg}.AAAA.{s}"), &opts()), "InvalidHeader");
    // b64:false: payload part is not base64 (any octets but '.'), but a
    // missing crit is still InvalidHeader.
    let f = hdr(r#"{"alg":"HS256","b64":false}"#);
    assert_eq!(code(&format!("{f}.a=+/ x.{s}"), &opts()), "InvalidHeader");
    let fc = hdr(r#"{"alg":"HS256","b64":false,"crit":["b64"]}"#);
    assert_ne!(code(&format!("{fc}.a=+/ x.{s}"), &opts()), "InvalidBase64");
    // b64:true explicit: payload part is base64url again.
    let t = hdr(r#"{"alg":"HS256","b64":true,"crit":["b64"]}"#);
    assert_eq!(code(&format!("{t}.a=.{s}"), &opts()), "InvalidBase64");
    // crit unknown, then alg checks, in ADR order.
    let uc = hdr(r#"{"alg":"none","crit":["exp"],"exp":1}"#);
    assert_eq!(code(&format!("{uc}.AAAA.{s}"), &opts()), "UnknownCritical");
    let ua = hdr(r#"{"alg":"XX999"}"#);
    assert_eq!(
        code(&format!("{ua}.AAAA.{s}"), &opts()),
        "UnsupportedAlgorithm"
    );
    let na = hdr(r#"{"alg":"ES256"}"#);
    assert_eq!(
        code(&format!("{na}.AAAA.{s}"), &opts()),
        "AlgorithmNotAllowed"
    );
    let mm = hdr(r#"{"alg":"HS256"}"#);
    let ec = Jwk::from_json(
        br#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#,
    )
    .unwrap();
    assert_eq!(
        verify_compact(&format!("{mm}.AAAA.{s}"), &ec, &opts()).map_err(|e| e.code()),
        Err("KeyAlgorithmMismatch")
    );
}

#[test]
fn errors_carry_no_input_or_key_bytes() {
    let marker = "MARKERxyz";
    let h = hdr(&format!(r#"{{"alg":"HS256","x":"{marker}"}}"#));
    let m = b64(marker.as_bytes());
    for jws in [
        marker.to_owned(),
        format!("{h}.{m}.{marker}="),
        format!("{marker}=.{m}.{m}"),
        format!("{h}.{m}.{m}.{m}"),
        format!(
            "{}.{m}.",
            hdr(&format!(r#"{{"alg":"HS256","alg":"{marker}"}}"#))
        ),
        format!("{}.{m}.", hdr(&format!(r#"{{"alg":"{marker}"}}"#))),
    ] {
        let e = verify_compact(&jws, &key(), &opts()).unwrap_err();
        for t in [e.to_string(), format!("{e:?}")] {
            assert!(
                !t.contains(marker) && !t.contains(&m) && !t.contains(MARKER_K),
                "{t}"
            );
        }
    }
}

fn protected(json: &str) -> ProtectedHeader {
    let h = Header::from_json(json.as_bytes()).unwrap();
    ProtectedHeader::new(h).unwrap()
}

fn sign_code(json: &str, payload: &[u8], detached: bool) -> &'static str {
    sign_compact(
        &protected(json),
        payload,
        &key(),
        &SignOptions::new().detached(detached),
    )
    .map_or_else(|e| e.code(), |_| "ok")
}

#[test]
fn sign_rules_before_the_family() {
    let f = r#"{"alg":"HS256","b64":false,"crit":["b64"]}"#;
    // No crit.
    assert_eq!(
        sign_code(r#"{"alg":"HS256","b64":false}"#, b"abc", false),
        "InvalidHeader"
    );
    assert_eq!(
        sign_code(r#"{"alg":"HS256","b64":false}"#, b"abc", true),
        "InvalidHeader"
    );
    // none can never be signed with.
    assert_eq!(
        sign_code(r#"{"alg":"none"}"#, b"abc", false),
        "AlgorithmNotAllowed"
    );
    // Attached b64:false payload: '.', control, DEL, non-ASCII, \n.
    for bad in [
        &b"a.b"[..],
        b"a\nb",
        b"\x7f",
        b"\x1f",
        "\u{e9}".as_bytes(),
        b"\t",
    ] {
        assert_eq!(sign_code(f, bad, false), "InvalidFormat", "{bad:?}");
    }
    // Boundaries 0x20 and 0x7e are allowed; empty is allowed.
    for ok in [&b" "[..], b"~", b"", b"a b~"] {
        assert_ne!(sign_code(f, ok, false), "InvalidFormat", "{ok:?}");
    }
    // Detached b64:false accepts any octets.
    assert_ne!(sign_code(f, b"a.b\n\xff\x00", true), "InvalidFormat");
    // b64 true / absent: any payload is fine.
    assert_ne!(
        sign_code(r#"{"alg":"HS256"}"#, b"a.b\n\xff", false),
        "InvalidFormat"
    );
}
