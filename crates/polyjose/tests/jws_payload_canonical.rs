//! F03 (tester): received payload text is reused as the signing input
//! (ADR 0049 §4). That is sound only because `b64url_decode` accepts the
//! canonical encoding alone (RFC 4648 §3.5). These probes sign non-canonical
//! encodings with a real HMAC over exactly the received text, the strongest
//! forgery for a verifier that reused the text without strict decoding, and
//! expect `InvalidBase64` from both serializations, never a verification.
//! Also pins ADR 0026 §2 order (payload base64url before signature check)
//! and the public type of `Verified::payload`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

use hmac::{Hmac, KeyInit, Mac};
use polyjose::Error;
use polyjose::header::Header;
use polyjose::jwa::SigningAlg;
use polyjose::jwk::Jwk;
use polyjose::jws::{self, ProtectedHeader, SignOptions, Signer, Verified, VerifyOptions};
use sha2::Sha256;
use zeroize::Zeroizing;

const K: [u8; 32] = [7u8; 32];
const PROTECTED: &str = "eyJhbGciOiJIUzI1NiJ9"; // {"alg":"HS256"}

const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
fn enc(bytes: &[u8]) -> String {
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
    Jwk::from_json(format!(r#"{{"kty":"oct","k":"{}"}}"#, enc(&K)).as_bytes()).unwrap()
}

fn mac(input: &str) -> String {
    let mut m = Hmac::<Sha256>::new_from_slice(&K).unwrap();
    m.update(input.as_bytes());
    enc(&m.finalize().into_bytes())
}

fn opts() -> VerifyOptions<'static> {
    VerifyOptions::new(&[SigningAlg::HS256]).unwrap()
}

fn compact(payload_text: &str) -> String {
    let input = format!("{PROTECTED}.{payload_text}");
    format!("{input}.{}", mac(&input))
}

fn flattened(payload_text: &str) -> String {
    let input = format!("{PROTECTED}.{payload_text}");
    format!(
        r#"{{"payload":"{payload_text}","protected":"{PROTECTED}","signature":"{}"}}"#,
        mac(&input)
    )
}

fn general(payload_text: &str) -> String {
    let input = format!("{PROTECTED}.{payload_text}");
    format!(
        r#"{{"payload":"{payload_text}","signatures":[{{"protected":"{PROTECTED}","signature":"{}"}}]}}"#,
        mac(&input)
    )
}

fn code<T>(r: Result<T, Error>) -> &'static str {
    r.map(drop).unwrap_err().code()
}

#[test]
fn canonical_baseline_verifies_in_every_serialization() {
    for (jws, json) in [
        (compact("QQ"), false),
        (flattened("QQ"), true),
        (general("QQ"), true),
    ] {
        let v = if json {
            jws::verify_json(&jws, &key(), &opts())
        } else {
            jws::verify_compact(&jws, &key(), &opts())
        }
        .unwrap();
        assert_eq!(*v.payload, [0x41]);
    }
}

#[test]
fn non_canonical_payload_text_signed_as_received_is_invalid_base64() {
    // "QQ" is canonical for 0x41. Each variant below decodes loosely to the
    // same octets (or garbage) yet is a different signing input.
    let variants = [
        "QR",    // non-zero trailing bits
        "QS",    // non-zero trailing bits
        "Qf",    // non-zero trailing bits
        "QQ==",  // padding
        "QQ=",   // partial padding
        "QQ=\n", // padding + newline
        "Q Q",   // inner space
        "QQ ",   // trailing space
        " QQ",   // leading space
        "QQ\n",  // trailing newline (raw LF is invalid in a JSON string, escaped below)
        "Q",     // one char, length % 4 == 1
        "QUJDR", // length % 4 == 1
        "QUI", // 0x41 0x42 with non-canonical? "QUI" -> bits 'I'=8 -> low 2 bits 00 canonical for AB
        "QUJ", // trailing bits non-zero (J=9)
        "+Q",  // standard alphabet
        "/Q",
        "QQ.",
        "\u{ff11}Q", // non-ASCII
    ];
    for text in variants {
        // QUI is canonical for "AB" (I = 8 = 0b001000, low 2 bits are 00).
        if text == "QUI" {
            continue;
        }
        // Compact: the text may not contain '.' structure issues; skip those.
        let json_text = text.replace('\n', "\\n");
        if !text.contains('.') && !text.contains(' ') && !text.contains('\n') {
            assert_eq!(
                code(jws::verify_compact(&compact(text), &key(), &opts())),
                "InvalidBase64",
                "compact {text:?}"
            );
        } else if !text.contains('.') && !text.contains(' ') {
            // newline inside compact: still InvalidBase64 or InvalidFormat
            // is acceptable only as a rejection, never success.
            assert!(jws::verify_compact(&compact(text), &key(), &opts()).is_err());
        } else if text.contains(' ') {
            assert_eq!(
                code(jws::verify_compact(&compact(text), &key(), &opts())),
                "InvalidBase64",
                "compact {text:?}"
            );
        }
        // JSON: the signing input is the *unescaped* member text.
        let input = format!("{PROTECTED}.{text}");
        let sig = mac(&input);
        for json in [
            format!(r#"{{"payload":"{json_text}","protected":"{PROTECTED}","signature":"{sig}"}}"#),
            format!(
                r#"{{"payload":"{json_text}","signatures":[{{"protected":"{PROTECTED}","signature":"{sig}"}}]}}"#
            ),
        ] {
            assert_eq!(
                code(jws::verify_json(&json, &key(), &opts())),
                "InvalidBase64",
                "json {text:?}"
            );
        }
    }
}

#[test]
fn json_escaped_spelling_of_canonical_text_signs_the_unescaped_text() {
    // The JSON spelling "<bs>u0051<bs>u0051" parses to "QQ": the signing
    // input is the parsed text, equal to the canonical encoding, and it
    // verifies. The raw escaped spelling signed instead must not.
    let escaped = format!("{0}u0051{0}u0051", '\\');
    let sig_ok = mac(&format!("{PROTECTED}.QQ"));
    let ok =
        format!(r#"{{"payload":"{escaped}","protected":"{PROTECTED}","signature":"{sig_ok}"}}"#);
    assert_eq!(
        *jws::verify_json(&ok, &key(), &opts()).unwrap().payload,
        [0x41]
    );
    let sig_raw = mac(&format!("{PROTECTED}.{escaped}"));
    let bad =
        format!(r#"{{"payload":"{escaped}","protected":"{PROTECTED}","signature":"{sig_raw}"}}"#);
    assert_eq!(
        code(jws::verify_json(&bad, &key(), &opts())),
        "InvalidSignature"
    );
}

#[test]
fn payload_base64_error_precedes_signature_check() {
    // ADR 0026 §2: InvalidBase64 (step 3) before InvalidSignature (step 9).
    assert_eq!(
        code(jws::verify_compact(
            &format!("{PROTECTED}.QR.AAAA"),
            &key(),
            &opts()
        )),
        "InvalidBase64"
    );
    let json = format!(r#"{{"payload":"QR","protected":"{PROTECTED}","signature":"AAAA"}}"#);
    assert_eq!(
        code(jws::verify_json(&json, &key(), &opts())),
        "InvalidBase64"
    );
}

#[test]
fn detached_payload_is_signed_in_canonical_form_and_leaves_caller_buffer() {
    let payload = [0x41u8];
    let detached = |sig_over: &str| format!("{PROTECTED}..{}", mac(sig_over));
    let o = opts().detached_payload(&payload);
    assert_eq!(
        *jws::verify_compact(&detached(&format!("{PROTECTED}.QQ")), &key(), &o)
            .unwrap()
            .payload,
        payload
    );
    // A signature over a non-canonical spelling never matches the detached
    // octets: they are encoded canonically.
    assert_eq!(
        code(jws::verify_compact(
            &detached(&format!("{PROTECTED}.QR")),
            &key(),
            &o
        )),
        "InvalidSignature"
    );
    // Failed detached verify: caller buffer unchanged, error only.
    assert_eq!(payload, [0x41]);
}

#[test]
fn verified_payload_type_and_sign_round_trip_all_modes() {
    fn takes(_: &Zeroizing<Vec<u8>>) {}
    let k = key();
    let mut h = Header::new();
    h.alg = Some("HS256".into());
    let p = ProtectedHeader::new(h).unwrap();
    let payload: Vec<u8> = (0..=255u8).collect();
    let jws_c = jws::sign_compact(&p, &payload, &k, &SignOptions::new()).unwrap();
    let v: Verified = jws::verify_compact(&jws_c, &k, &opts()).unwrap();
    takes(&v.payload);
    assert_eq!(*v.payload, payload);
    let s = Signer::new(&k).protected(p.clone());
    let signers = [s.clone(), Signer::new(&k).protected(p.clone())];
    let g = jws::sign_general(&signers, &payload, &SignOptions::new()).unwrap();
    assert_eq!(*jws::verify_json(&g, &k, &opts()).unwrap().payload, payload);
    let f = jws::sign_flattened(&s, &payload, &SignOptions::new()).unwrap();
    assert_eq!(*jws::verify_json(&f, &k, &opts()).unwrap().payload, payload);
    // The sign-side payload member is the single canonical encoding for all signers.
    assert!(g.matches(&enc(&payload)).count() == 1);
}
