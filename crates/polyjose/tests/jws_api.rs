//! T02 (tester): the frozen public JWS API surface, through the crate's
//! public items only. Nothing here depends on a serialization or algorithm
//! family being implemented, so it stays valid after wave 2.

use polyjose::Error;
use polyjose::header::Header;
use polyjose::jwa::SigningAlg;
use polyjose::jwk::Jwk;
use polyjose::jws::{ProtectedHeader, SignOptions, Signer, VerifyOptions};

const MARKER_K: &str = "TUFSS0VSc2VjcmV0TUFSS0VSc2VjcmV0TUFSS0VSc2VjcmV0MTI"; // "MARKERsecret..." base64url
const A1_PROTECTED: &str = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9";

fn b64(s: &str) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for c in s.as_bytes().chunks(3) {
        let n = c.iter().fold(0u32, |a, b| a << 8 | u32::from(*b)) << (8 * (3 - c.len()));
        for i in 0..=c.len() {
            out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

#[test]
fn verify_options_reject_empty_none_and_unknown_publicly() {
    let cases: [&[SigningAlg]; 4] = [
        &[],
        &[SigningAlg::None],
        &[SigningAlg::ES256, SigningAlg::None],
        &[SigningAlg::Unknown("HS1".into())],
    ];
    for c in cases {
        assert_eq!(
            VerifyOptions::new(c).map(drop),
            Err(Error::AlgorithmNotAllowed)
        );
    }
    let ok = [SigningAlg::HS256, SigningAlg::Ed25519];
    let o = VerifyOptions::new(&ok).unwrap();
    assert_eq!(o.allowed_algs(), &ok);
    assert_eq!(VerifyOptions::DEFAULT_MAX_INPUT_LEN, 1 << 20);
    assert_eq!(VerifyOptions::DEFAULT_MAX_SIGNATURES, 16);
}

#[test]
fn protected_header_keeps_rfc7515_a1_crlf_octets() {
    let p = ProtectedHeader::from_encoded(A1_PROTECTED).unwrap();
    assert_eq!(p.encoded(), A1_PROTECTED);
    assert_eq!(p.header().typ.as_deref(), Some("JWT"));
    assert_eq!(p.header().signing_alg(), Ok(SigningAlg::HS256));
}

#[test]
fn duplicate_protected_member_is_invalid_json_not_invalid_header() {
    // ADR 0041 §1, also when the duplicate would change `alg`.
    for json in [
        r#"{"alg":"HS256","alg":"none"}"#,
        r#"{"alg":"HS256","kid":"a","kid":"b"}"#,
        r#"{"alg":"HS256","alg":"none"}"#, // duplicate after unescaping
    ] {
        let err = ProtectedHeader::from_encoded(&b64(json))
            .map(drop)
            .unwrap_err();
        assert_eq!(err.code(), "InvalidJson", "{json}");
    }
}

#[test]
fn debug_output_never_carries_key_or_input_bytes() {
    let key = Jwk::from_json(format!(r#"{{"kty":"oct","k":"{MARKER_K}"}}"#).as_bytes()).unwrap();
    let mut h = Header::new();
    h.alg = Some("HS256".into());
    let signer = Signer::new(&key).protected(ProtectedHeader::new(h).unwrap());
    let allowed = [SigningAlg::HS256];
    let payload = b"MARKERpayload";
    let opts = VerifyOptions::new(&allowed)
        .unwrap()
        .detached_payload(payload);
    for dbg in [
        format!("{signer:?}"),
        format!("{signer:#?}"),
        format!("{opts:?}"),
        format!("{:?}", SignOptions::new()),
    ] {
        assert!(!dbg.contains(MARKER_K), "{dbg}");
        assert!(!dbg.contains("MARKERpayload"), "{dbg}");
        assert!(!dbg.contains("TUFSS0VS"), "{dbg}");
    }
}
