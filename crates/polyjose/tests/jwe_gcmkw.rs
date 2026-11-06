//! A128GCMKW, A192GCMKW and A256GCMKW (RFC 7518 §4.7) through the public
//! compact API (0003 T10).
//!
//! - RFC 7520 §5.7 (A256GCMKW + A128CBC-HS256) decrypts with the RFC key,
//!   and (with `insecure-test-vectors`) `encrypt_reproducible` reproduces
//!   the RFC's compact string byte for byte from its CEK, key-wrap IV and
//!   content IV, drawn in the documented order. Every RFC value is read
//!   from the vendored ietf-jose cookbook, never transcribed.
//! - The `iv` and `tag` header parameters (§4.7.1.1–§4.7.1.2): each
//!   missing or malformed value, and any swap of them between two valid
//!   tokens, is the one detail-free `DecryptionFailed` (RFC 7516 §11.4).
//! - Round trips over every `alg` of the family and every `enc`.
#![allow(clippy::panic)] // test code: a panic is a failed assertion

use polyjose::header::Header;
use polyjose::jwa::{ContentEncAlg, KeyMgmtAlg};
use polyjose::jwe::{DecryptPolicy, Encryptor, Recipient, decrypt_compact};
use polyjose::jwk::Jwk;
use polyjose::util::{b64url_decode, b64url_encode};
use serde_json::Value;

use ContentEncAlg as E;
use KeyMgmtAlg as A;

/// The ietf-jose cookbook's RFC 7520 §5.7 (vendored, see its README).
const RFC7520_5_7: &str = include_str!(
    "third_party/ietf-jose-cookbook/jwe/5_7.key_wrap_using_aes-gcm_keywrap_with_aes-cbc-hmac-sha2.json"
);

/// The family and its KEK sizes (RFC 7518 §4.7).
const FAMILY: [(KeyMgmtAlg, usize); 3] =
    [(A::A128GCMKW, 16), (A::A192GCMKW, 24), (A::A256GCMKW, 32)];

/// The RFC 7520 §5.7 values, read from the cookbook.
struct Example {
    key: Jwk,
    kid: String,
    plaintext: Vec<u8>,
    cek: Vec<u8>,
    wrap_iv: Vec<u8>,
    wrap_iv_b64: String,
    wrap_tag_b64: String,
    content_iv: Vec<u8>,
    encrypted_key_b64: String,
    protected_b64: String,
    compact: String,
}

fn text<'a>(doc: &'a Value, path: &[&str]) -> &'a str {
    path.iter()
        .fold(doc, |v, name| &v[*name])
        .as_str()
        .unwrap_or_else(|| panic!("cookbook: no string at {path:?}"))
}

fn bytes(b64u: &str) -> Vec<u8> {
    b64url_decode(b64u).unwrap_or_else(|e| panic!("{b64u}: {e}"))
}

fn rfc7520_5_7() -> Example {
    let doc: Value = serde_json::from_str(RFC7520_5_7).unwrap_or_else(|e| panic!("{e}"));
    let key_json = serde_json::to_string(&doc["input"]["key"]).unwrap_or_else(|e| panic!("{e}"));
    Example {
        key: jwk(&key_json),
        kid: text(&doc, &["input", "key", "kid"]).to_owned(),
        plaintext: text(&doc, &["input", "plaintext"]).as_bytes().to_vec(),
        cek: bytes(text(&doc, &["generated", "cek"])),
        wrap_iv: bytes(text(&doc, &["encrypting_key", "iv"])),
        wrap_iv_b64: text(&doc, &["encrypting_key", "iv"]).to_owned(),
        wrap_tag_b64: text(&doc, &["encrypting_key", "tag"]).to_owned(),
        content_iv: bytes(text(&doc, &["generated", "iv"])),
        encrypted_key_b64: text(&doc, &["encrypting_key", "encrypted_key"]).to_owned(),
        protected_b64: text(&doc, &["encrypting_content", "protected_b64u"]).to_owned(),
        compact: text(&doc, &["output", "compact"]).to_owned(),
    }
}

fn jwk(json: &str) -> Jwk {
    Jwk::from_json(json.as_bytes()).unwrap_or_else(|e| panic!("{json}: {e}"))
}

fn oct(bytes: &[u8]) -> Jwk {
    jwk(&format!(
        r#"{{"kty":"oct","k":"{}"}}"#,
        b64url_encode(bytes)
    ))
}

fn policy(alg: &KeyMgmtAlg, enc: &ContentEncAlg) -> DecryptPolicy {
    DecryptPolicy::new(std::slice::from_ref(alg), std::slice::from_ref(enc))
        .unwrap_or_else(|e| panic!("{e}"))
}

fn code<T>(result: polyjose::Result<T>) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(e) => e.code(),
    }
}

fn segments(token: &str) -> Vec<String> {
    token.split('.').map(str::to_owned).collect()
}

/// The protected header of a compact JWE as a JSON object.
fn protected(token: &str) -> serde_json::Map<String, Value> {
    let json = bytes(&segments(token)[0]);
    match serde_json::from_slice(&json).unwrap_or_else(|e| panic!("{e}")) {
        Value::Object(map) => map,
        other => panic!("not an object: {other}"),
    }
}

/// `token` with its protected header replaced by `header` (re-encoded),
/// every other segment unchanged.
fn with_protected(token: &str, header: &serde_json::Map<String, Value>) -> String {
    let mut parts = segments(token);
    let json = serde_json::to_vec(header).unwrap_or_else(|e| panic!("{e}"));
    parts[0] = b64url_encode(&json);
    parts.join(".")
}

/// `token` with its protected `iv` and `tag` set (or removed, for `None`).
fn with_iv_tag(token: &str, iv: Option<Value>, tag: Option<Value>) -> String {
    let mut header = protected(token);
    for (name, value) in [("iv", iv), ("tag", tag)] {
        match value {
            Some(v) => header.insert(name.to_owned(), v),
            None => header.remove(name),
        };
    }
    with_protected(token, &header)
}

fn s(text: &str) -> Option<Value> {
    Some(Value::String(text.to_owned()))
}

// ---------------------------------------------------------------------------
// RFC 7520 §5.7
// ---------------------------------------------------------------------------

#[test]
fn rfc_7520_5_7_cookbook_is_self_consistent() {
    // §5.7.4-§5.7.5: the compact output's first three segments are the
    // printed protected header, encrypted key and content IV, and the
    // protected header carries the printed key-wrap `iv` and `tag`.
    let ex = rfc7520_5_7();
    let parts = segments(&ex.compact);
    assert_eq!(parts.len(), 5);
    assert_eq!(parts[0], ex.protected_b64);
    assert_eq!(parts[1], ex.encrypted_key_b64);
    assert_eq!(bytes(&parts[2]), ex.content_iv);
    let header = protected(&ex.compact);
    assert_eq!(header["alg"], "A256GCMKW");
    assert_eq!(header["enc"], "A128CBC-HS256");
    assert_eq!(header["iv"].as_str(), Some(ex.wrap_iv_b64.as_str()));
    assert_eq!(header["tag"].as_str(), Some(ex.wrap_tag_b64.as_str()));
    assert_eq!((ex.wrap_iv.len(), bytes(&ex.wrap_tag_b64).len()), (12, 16));
    assert_eq!((ex.cek.len(), bytes(&ex.encrypted_key_b64).len()), (32, 32));
}

#[test]
fn rfc_7520_5_7_decrypts() {
    let ex = rfc7520_5_7();
    let d = decrypt_compact(
        &ex.compact,
        &ex.key,
        &policy(&A::A256GCMKW, &E::A128CbcHs256),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(d.plaintext(), ex.plaintext);
    assert_eq!(d.recipient(), 0);
    let h = d.header();
    assert_eq!(h.alg.as_deref(), Some("A256GCMKW"));
    assert_eq!(h.enc, Some(E::A128CbcHs256));
    assert_eq!(h.kid.as_deref(), Some(ex.kid.as_str()));
    assert_eq!(h.iv.as_deref(), Some(ex.wrap_iv_b64.as_str()));
    assert_eq!(h.tag.as_deref(), Some(ex.wrap_tag_b64.as_str()));
}

#[test]
fn rfc_7520_5_7_needs_both_allow_lists_and_the_right_key() {
    // RFC 8725 §3.1: the allow-lists come first; the family's errors only
    // follow once the key is a candidate.
    let ex = rfc7520_5_7();
    let not_allowed = decrypt_compact(
        &ex.compact,
        &ex.key,
        &policy(&A::A128GCMKW, &E::A128CbcHs256),
    );
    assert_eq!(code(not_allowed), "AlgorithmNotAllowed");
    let not_allowed = decrypt_compact(&ex.compact, &ex.key, &policy(&A::A256GCMKW, &E::A256GCM));
    assert_eq!(code(not_allowed), "AlgorithmNotAllowed");
    // A 128-bit key cannot serve A256GCMKW (RFC 7518 §4.7).
    let p = policy(&A::A256GCMKW, &E::A128CbcHs256);
    assert_eq!(
        code(decrypt_compact(&ex.compact, &oct(&[7; 16]), &p)),
        "KeyAlgorithmMismatch"
    );
    // Another 256-bit key: the wrap tag fails.
    assert_eq!(
        code(decrypt_compact(&ex.compact, &oct(&[7; 32]), &p)),
        "DecryptionFailed"
    );
}

// ---------------------------------------------------------------------------
// The iv and tag header parameters
// ---------------------------------------------------------------------------

#[test]
fn every_iv_or_tag_fault_is_decryption_failed() {
    // RFC 7518 §4.7.1.1-§4.7.1.2: both MUST be present; §4.7: a 96-bit IV
    // and a 128-bit tag. A fault anywhere is the same unit error.
    let ex = rfc7520_5_7();
    let iv = ex.wrap_iv_b64.as_str();
    let tag = ex.wrap_tag_b64.as_str();
    let tag_bytes = bytes(tag);
    let mut flipped = tag_bytes.clone();
    flipped[15] ^= 0x01;
    let mut iv_flipped = ex.wrap_iv.clone();
    iv_flipped[0] ^= 0x80;
    let cases: Vec<(Option<Value>, Option<Value>, &str)> = vec![
        (None, s(tag), "iv missing"),
        (s(iv), None, "tag missing"),
        (None, None, "both missing"),
        (s(""), s(tag), "iv empty"),
        (s(iv), s(""), "tag empty"),
        (s(&format!("{iv}==")), s(tag), "iv padded"),
        (
            s(&iv.replace('_', "/")),
            s(tag),
            "iv in the base64 alphabet",
        ),
        (
            s(&b64url_encode(&[ex.wrap_iv.as_slice(), &[0; 4]].concat())),
            s(tag),
            "16-byte iv",
        ),
        (s(&b64url_encode(&ex.wrap_iv[..8])), s(tag), "8-byte iv"),
        (s(&b64url_encode(&iv_flipped)), s(tag), "another iv"),
        (
            s(iv),
            s(&b64url_encode(&tag_bytes[..12])),
            "12-byte tag prefix",
        ),
        (
            s(iv),
            s(&b64url_encode(&[tag_bytes.as_slice(), &[0]].concat())),
            "17-byte tag",
        ),
        (s(iv), s(&b64url_encode(&flipped)), "tag bit flip"),
        (s(tag), s(iv), "iv and tag exchanged"),
    ];
    let p = policy(&A::A256GCMKW, &E::A128CbcHs256);
    for (iv, tag, what) in cases {
        let token = with_iv_tag(&ex.compact, iv, tag);
        assert_eq!(
            code(decrypt_compact(&token, &ex.key, &p)),
            "DecryptionFailed",
            "{what}"
        );
    }
}

#[test]
fn an_iv_or_tag_that_is_not_a_string_is_an_invalid_header() {
    // RFC 7518 §4.7.1: both are base64url strings. A value of another JSON
    // type is a header-structure fault (RFC 7516 §5.2 steps 3-4), found
    // before any key management.
    let ex = rfc7520_5_7();
    let p = policy(&A::A256GCMKW, &E::A128CbcHs256);
    for (iv, tag) in [
        (Some(Value::from(12)), s(&ex.wrap_tag_b64)),
        (s(&ex.wrap_iv_b64), Some(Value::Array(Vec::new()))),
        (Some(Value::Null), s(&ex.wrap_tag_b64)),
    ] {
        let token = with_iv_tag(&ex.compact, iv, tag);
        assert_eq!(code(decrypt_compact(&token, &ex.key, &p)), "InvalidHeader");
    }
}

#[test]
fn a_tampered_encrypted_key_is_decryption_failed() {
    let ex = rfc7520_5_7();
    let p = policy(&A::A256GCMKW, &E::A128CbcHs256);
    let mut parts = segments(&ex.compact);
    let mut ek = bytes(&parts[1]);
    ek[0] ^= 0x01;
    for replacement in [
        ek.clone(),
        ek[..16].to_vec(),
        Vec::new(),
        [ek.as_slice(), &[0; 8]].concat(),
    ] {
        parts[1] = b64url_encode(&replacement);
        let token = parts.join(".");
        assert_eq!(
            code(decrypt_compact(&token, &ex.key, &p)),
            "DecryptionFailed",
            "{} bytes",
            replacement.len()
        );
    }
}

#[test]
fn swapping_iv_and_tag_between_two_valid_tokens_fails() {
    // Two valid tokens under one KEK. The wrap tag binds its IV and
    // encrypted key (NIST SP 800-38D §7.2), and the protected header is
    // the content AAD (RFC 7516 §5.1 step 14), so no exchange of `iv`,
    // `tag` or both between them decrypts.
    let key = oct(&[0x24; 32]);
    let encryptor = Encryptor::new(E::A256GCM).recipient(Recipient::new(A::A256GCMKW, &key));
    let a = encryptor
        .encrypt_compact(b"token a")
        .unwrap_or_else(|e| panic!("{e}"));
    let b = encryptor
        .encrypt_compact(b"token b")
        .unwrap_or_else(|e| panic!("{e}"));
    let p = policy(&A::A256GCMKW, &E::A256GCM);
    assert_eq!(code(decrypt_compact(&a, &key, &p)), "ok");
    assert_eq!(code(decrypt_compact(&b, &key, &p)), "ok");
    let (ha, hb) = (protected(&a), protected(&b));
    assert_ne!(ha["iv"], hb["iv"]);
    for (target, from, to) in [(&a, &hb, &ha), (&b, &ha, &hb)] {
        let get = |h: &serde_json::Map<String, Value>, n: &str| h.get(n).cloned();
        let swaps = [
            (get(from, "iv"), get(to, "tag"), "iv"),
            (get(to, "iv"), get(from, "tag"), "tag"),
            (get(from, "iv"), get(from, "tag"), "iv and tag"),
        ];
        for (iv, tag, what) in swaps {
            let token = with_iv_tag(target, iv, tag);
            assert_eq!(
                code(decrypt_compact(&token, &key, &p)),
                "DecryptionFailed",
                "{what}"
            );
        }
        // The other token's whole protected header: still refused.
        let token = with_protected(target, from);
        assert_eq!(code(decrypt_compact(&token, &key, &p)), "DecryptionFailed");
    }
}

// ---------------------------------------------------------------------------
// Encrypt
// ---------------------------------------------------------------------------

#[test]
fn every_alg_and_enc_round_trips_with_iv_and_tag_protected() {
    // RFC 7516 §5.1, RFC 7518 §4.7: compact puts `alg`, `iv` and `tag` in
    // the protected header (plan.md), in polyjose's member order.
    let kid = Header::from_json(br#"{"kid":"t10"}"#).unwrap_or_else(|e| panic!("{e}"));
    for (alg, kek_len) in &FAMILY {
        let key = oct(&vec![0x5C; *kek_len]);
        for enc in ContentEncAlg::KNOWN {
            let token = Encryptor::new(enc.clone())
                .protected_header(kid.clone())
                .recipient(Recipient::new(alg.clone(), &key))
                .encrypt_compact(b"Live long and prosper.")
                .unwrap_or_else(|e| panic!("{alg} {enc}: {e}"));
            let header = protected(&token);
            let names: Vec<&str> = header.keys().map(String::as_str).collect();
            let mut expected = ["alg", "enc", "iv", "kid", "tag"]; // serde_json sorts
            expected.sort_unstable();
            assert_eq!(names, expected, "{alg} {enc}");
            let raw =
                String::from_utf8(bytes(&segments(&token)[0])).unwrap_or_else(|e| panic!("{e}"));
            assert!(
                raw.starts_with(&format!(
                    r#"{{"alg":"{alg}","enc":"{enc}","kid":"t10","iv":""#
                )),
                "{raw}"
            );
            let iv = bytes(header["iv"].as_str().unwrap_or_default());
            let tag = bytes(header["tag"].as_str().unwrap_or_default());
            assert_eq!((iv.len(), tag.len()), (12, 16), "{alg} {enc}");
            let d = decrypt_compact(&token, &key, &policy(alg, enc))
                .unwrap_or_else(|e| panic!("{alg} {enc}: {e}"));
            assert_eq!(d.plaintext(), b"Live long and prosper.");
        }
    }
}

#[test]
fn two_encryptions_use_different_wrap_ivs() {
    // RFC 7518 §8.4: a fresh IV per wrap (the 1,000-draw check is the
    // `aes_gcm_kw` unit test).
    let key = oct(&[1; 16]);
    let e = Encryptor::new(E::A128GCM).recipient(Recipient::new(A::A128GCMKW, &key));
    let one = e
        .encrypt_compact(b"x")
        .unwrap_or_else(|err| panic!("{err}"));
    let two = e
        .encrypt_compact(b"x")
        .unwrap_or_else(|err| panic!("{err}"));
    assert_ne!(protected(&one)["iv"], protected(&two)["iv"]);
    assert_ne!(segments(&one)[1], segments(&two)[1]);
}

#[test]
fn a_kek_of_the_wrong_size_is_an_invalid_key() {
    // RFC 7518 §4.7: 128, 192 or 256 bits, as `alg` says.
    for (alg, kek_len) in &FAMILY {
        for len in [8, 16, 24, 32, 64] {
            if len == *kek_len {
                continue;
            }
            let result = Encryptor::new(E::A128GCM)
                .recipient(Recipient::new(alg.clone(), &oct(&vec![3; len])))
                .encrypt_compact(b"x");
            assert_eq!(code(result), "InvalidKey", "{alg}: {len}-byte key");
        }
    }
}

#[test]
fn the_caller_cannot_set_iv_or_tag() {
    // plan.md: polyjose sets the key management parameters itself.
    let key = oct(&[1; 16]);
    for json in [
        r#"{"iv":"AAAAAAAAAAAAAAAA"}"#,
        r#"{"tag":"AAAAAAAAAAAAAAAAAAAAAA"}"#,
    ] {
        let header = Header::from_json(json.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
        let result = Encryptor::new(E::A128GCM)
            .protected_header(header)
            .recipient(Recipient::new(A::A128GCMKW, &key))
            .encrypt_compact(b"x");
        assert_eq!(code(result), "InvalidHeader", "{json}");
    }
}

/// Byte-exact reproduction of RFC 7520 §5.7: the RFC's CEK, key-wrap IV
/// and content IV through `FixedRng`, in the documented draw order (CEK,
/// then the recipient's 96-bit wrap IV, then the content IV).
#[cfg(feature = "insecure-test-vectors")]
mod reproducible {
    use polyjose::Error;
    use polyjose::insecure_test_vectors::FixedRng;
    use polyjose::jwe::Serialization;

    use super::*;

    fn draws(ex: &Example) -> Vec<u8> {
        [ex.cek.as_slice(), &ex.wrap_iv, &ex.content_iv].concat()
    }

    fn encryptor(ex: &Example) -> Encryptor {
        let kid = Header::from_json(format!(r#"{{"kid":"{}"}}"#, ex.kid).as_bytes())
            .unwrap_or_else(|e| panic!("{e}"));
        Encryptor::new(E::A128CbcHs256)
            .protected_header(kid)
            .recipient(Recipient::new(A::A256GCMKW, &ex.key))
    }

    #[test]
    fn rfc_7520_5_7_is_reproduced() {
        let ex = rfc7520_5_7();
        let mut rng = FixedRng::new(draws(&ex));
        let token = encryptor(&ex)
            .encrypt_reproducible(
                &ex.plaintext,
                Serialization::Compact,
                &mut rng,
                Some(&ex.protected_b64),
            )
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(token, ex.compact);
        assert_eq!(rng.remaining(), 0);
    }

    #[test]
    fn without_the_hook_the_same_draws_give_the_rfc_wrap() {
        // polyjose orders the members alg, enc, kid, iv, tag (the RFC has
        // alg, kid, tag, iv, enc), so only the protected header and the
        // content tag over it differ; the wrap is the RFC's.
        let ex = rfc7520_5_7();
        let mut rng = FixedRng::new(draws(&ex));
        let token = encryptor(&ex)
            .encrypt_reproducible(&ex.plaintext, Serialization::Compact, &mut rng, None)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(rng.remaining(), 0);
        let (ours, rfc) = (segments(&token), segments(&ex.compact));
        assert_eq!(protected(&token), protected(&ex.compact));
        assert_ne!(ours[0], rfc[0]);
        assert_eq!(ours[1..3], rfc[1..3]);
        assert_eq!(ours[3], rfc[3]);
        assert_ne!(ours[4], rfc[4]);
        let p = policy(&A::A256GCMKW, &E::A128CbcHs256);
        let d = decrypt_compact(&token, &ex.key, &p).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(d.plaintext(), ex.plaintext);
    }

    #[test]
    fn a_draw_short_of_the_wrap_iv_fails_closed() {
        // ADR 0005: the wrap IV cannot be drawn, so nothing is emitted.
        let ex = rfc7520_5_7();
        let mut rng = FixedRng::new([ex.cek.as_slice(), &ex.wrap_iv[..11]].concat());
        let result = encryptor(&ex).encrypt_reproducible(
            &ex.plaintext,
            Serialization::Compact,
            &mut rng,
            None,
        );
        assert_eq!(result, Err(Error::RandomnessUnavailable));
    }
}
