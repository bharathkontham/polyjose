//! The uniform-error audit (0003 T16; ADR 0007; RFC 7516 §11.4–§11.5;
//! RFC 7518 §5.2.2.2).
//!
//! Every failure after key management starts (RFC 7516 §5.2 steps 6–17;
//! plan.md "Error contract") must be the one unit [`Error::DecryptionFailed`]:
//! the same value, the same `Debug`, `Display` and `code()`, and no
//! `source()`. Otherwise the error itself would tell an attacker which
//! check failed: a padding oracle (RFC 7516 §11.5), a key-wrap integrity
//! oracle, or an invalid-curve probe (RFC 7516 §11.4).
//!
//! One table holds one failing JWE per cause, across every family: content
//! encryption (both AEADs), dir, AES-KW, AES-GCMKW, PBES2, ECDH-ES on a NIST
//! curve and on X25519, and (with `deflate`) inflation. Each starts from a
//! token that is first checked to decrypt, and changes exactly one thing.
//! Values come from polyjose's own encryptor with OS randomness; the only
//! hand-built parts are the tampering itself and, for an invalid DEFLATE
//! stream, a payload sealed by the RustCrypto `aes-gcm` crate directly.
//!
//! No timing is measured here: timing belongs in `benches/` (pipeline
//! rule 8).
#![allow(clippy::panic)] // test code: a panic is a failed assertion

use std::collections::BTreeSet;
use std::error::Error as _;

use polyjose::Error;
use polyjose::jwa::{ContentEncAlg, KeyMgmtAlg};
use polyjose::jwe::{DecryptPolicy, Encryptor, JsonForm, Recipient, decrypt_compact, decrypt_json};
use polyjose::jwk::{EcCurve, Jwk, OkpCurve};
use polyjose::keys::{KeySpec, generate};
use polyjose::util::{b64url_decode, b64url_encode};
use serde_json::{Map, Value, json};

use ContentEncAlg as E;
use KeyMgmtAlg as A;

const PT: &[u8] = b"The true sign of intelligence is not knowledge but imagination.";

// ---------------------------------------------------------------------------
// Keys, policies and tokens
// ---------------------------------------------------------------------------

fn oct(bytes: &[u8]) -> Jwk {
    let json = format!(r#"{{"kty":"oct","k":"{}"}}"#, b64url_encode(bytes));
    Jwk::from_json(json.as_bytes()).unwrap_or_else(|e| panic!("{e}"))
}

fn random_oct(len: usize) -> Jwk {
    generate(KeySpec::Oct { bytes: len }).unwrap_or_else(|e| panic!("{e}"))
}

fn ec(curve: EcCurve) -> Jwk {
    generate(KeySpec::Ec(curve)).unwrap_or_else(|e| panic!("{e}"))
}

fn x25519() -> Jwk {
    generate(KeySpec::Okp(OkpCurve::X25519)).unwrap_or_else(|e| panic!("{e}"))
}

fn public(key: &Jwk) -> Jwk {
    key.to_public().unwrap_or_else(|| panic!("no public part"))
}

/// Every `alg` and `enc`: the allow-list is not under test here.
fn policy() -> DecryptPolicy {
    DecryptPolicy::new(KeyMgmtAlg::KNOWN, ContentEncAlg::KNOWN).unwrap_or_else(|e| panic!("{e}"))
}

fn bytes(b64u: &str) -> Vec<u8> {
    b64url_decode(b64u).unwrap_or_else(|e| panic!("{b64u}: {e}"))
}

/// A compact JWE to `recipient`, checked to decrypt with `key`.
fn compact(enc: ContentEncAlg, recipient: Recipient, key: &Jwk) -> String {
    let token = Encryptor::new(enc)
        .recipient(recipient)
        .encrypt_compact(PT)
        .unwrap_or_else(|e| panic!("{e}"));
    let opened = decrypt_compact(&token, key, &policy()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(opened.plaintext(), PT);
    token
}

/// A one-recipient general JSON JWE (RFC 7516 §7.2.1), checked to decrypt
/// with `key`. `alg` and its parameters are in `recipients[0].header`.
fn general(encryptor: Encryptor, recipient: Recipient, key: &Jwk) -> Value {
    let text = encryptor
        .recipient(recipient)
        .encrypt_json(PT, JsonForm::General)
        .unwrap_or_else(|e| panic!("{e}"));
    let opened = decrypt_json(&text, key, &policy()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(opened.plaintext(), PT);
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{e}"))
}

fn open_compact(token: &str, key: &Jwk) -> polyjose::Result<()> {
    decrypt_compact(token, key, &policy()).map(drop)
}

fn open_json(doc: &Value, key: &Jwk) -> polyjose::Result<()> {
    decrypt_json(&doc.to_string(), key, &policy()).map(drop)
}

// ---------------------------------------------------------------------------
// Tampering
// ---------------------------------------------------------------------------

/// The compact parts (RFC 7516 §7.1): 0 protected, 1 encrypted key, 2 IV,
/// 3 ciphertext, 4 tag.
const PROTECTED: usize = 0;
const ENCRYPTED_KEY: usize = 1;
const IV: usize = 2;
const CIPHERTEXT: usize = 3;
const TAG: usize = 4;

/// `token` with compact part `index` replaced by `f` of its decoded octets.
fn edit_part(token: &str, index: usize, f: impl FnOnce(&mut Vec<u8>)) -> String {
    let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
    let mut octets = bytes(&parts[index]);
    f(&mut octets);
    parts[index] = b64url_encode(&octets);
    parts.join(".")
}

/// Flips the low bit of the first octet.
const FLIP: fn(&mut Vec<u8>) = |octets| octets[0] ^= 0x01;

/// `token` with its protected header (RFC 7516 §4) replaced by `f` of it.
fn edit_protected(token: &str, f: impl FnOnce(&mut Map<String, Value>)) -> String {
    let mut header = protected(token);
    f(&mut header);
    let text = Value::Object(header).to_string();
    edit_part(token, PROTECTED, |octets| *octets = text.into_bytes())
}

fn protected(token: &str) -> Map<String, Value> {
    let first = token.split('.').next().unwrap_or_default();
    serde_json::from_slice(&bytes(first)).unwrap_or_else(|e| panic!("{e}"))
}

/// A string member holding base64url, replaced by `f` of its octets.
fn edit_b64(value: &mut Value, f: impl FnOnce(&mut Vec<u8>)) {
    let mut octets = bytes(value.as_str().unwrap_or_else(|| panic!("{value}")));
    f(&mut octets);
    *value = Value::String(b64url_encode(&octets));
}

/// `recipients[0].header` of a general JWE.
fn recipient_header(doc: &mut Value) -> &mut Map<String, Value> {
    doc["recipients"][0]["header"]
        .as_object_mut()
        .unwrap_or_else(|| panic!("no per-recipient header"))
}

/// `doc` with `recipients[0].header[name]` replaced by `f` of its octets.
fn edit_recipient_b64(mut doc: Value, name: &str, f: impl FnOnce(&mut Vec<u8>)) -> Value {
    let member = recipient_header(&mut doc)
        .get_mut(name)
        .unwrap_or_else(|| panic!("no {name}"));
    edit_b64(member, f);
    doc
}

/// `doc` with `recipients[0].header.epk` replaced by `f` of it.
fn edit_epk(mut doc: Value, f: impl FnOnce(&mut Map<String, Value>)) -> Value {
    let epk = recipient_header(&mut doc)
        .get_mut("epk")
        .and_then(Value::as_object_mut)
        .unwrap_or_else(|| panic!("no epk"));
    f(epk);
    doc
}

/// `doc` with its first recipient taken from `donor` (same `alg` and key,
/// another `enc`), so the key unwraps cleanly to a CEK of the donor's
/// length (RFC 7516 §5.2 step 10 then rejects it).
fn graft_recipient(mut doc: Value, donor: &Value) -> Value {
    doc["recipients"][0] = donor["recipients"][0].clone();
    doc
}

/// An X25519 `epk` with this `x` (RFC 8037 §2).
fn x25519_epk(x: &[u8]) -> Value {
    json!({ "kty": "OKP", "crv": "X25519", "x": b64url_encode(x) })
}

/// The public JWK of `key` as a JSON object, for use as an `epk`.
fn epk_of(key: &Jwk) -> Value {
    serde_json::from_str(&public(key).to_json()).unwrap_or_else(|e| panic!("{e}"))
}

// ---------------------------------------------------------------------------
// The table
// ---------------------------------------------------------------------------

/// One failing JWE per cause: a name and what decrypting it gave.
type Cases = Vec<(&'static str, polyjose::Result<()>)>;

/// Content encryption (RFC 7516 §5.2 steps 14–16; RFC 7518 §5.2.2.2,
/// §5.3), dir (RFC 7518 §4.5) and the JWE AAD (RFC 7516 §5.2 step 14).
fn content_causes(cases: &mut Cases) {
    let kek = random_oct(16);
    let gcm = compact(E::A128GCM, Recipient::new(A::A128KW, &kek), &kek);
    let cbc = compact(E::A128CbcHs256, Recipient::new(A::A128KW, &kek), &kek);
    let truncate = |o: &mut Vec<u8>| {
        o.pop();
    };
    let mut add = |name, token: String| cases.push((name, open_compact(&token, &kek)));
    add("A128GCM tag, one bit flipped", edit_part(&gcm, TAG, FLIP));
    add(
        "A128CBC-HS256 tag, one bit flipped",
        edit_part(&cbc, TAG, FLIP),
    );
    add("A128GCM tag of 15 octets", edit_part(&gcm, TAG, truncate));
    add(
        "A128CBC-HS256 tag of 15 octets",
        edit_part(&cbc, TAG, truncate),
    );
    add(
        "A128GCM ciphertext, one bit flipped",
        edit_part(&gcm, CIPHERTEXT, FLIP),
    );
    add(
        "A128CBC-HS256 ciphertext, one bit flipped",
        edit_part(&cbc, CIPHERTEXT, FLIP),
    );
    add(
        "A128CBC-HS256 ciphertext not a whole AES block",
        edit_part(&cbc, CIPHERTEXT, truncate),
    );
    add("A128GCM IV, one bit flipped", edit_part(&gcm, IV, FLIP));
    add(
        "A128CBC-HS256 IV, one bit flipped",
        edit_part(&cbc, IV, FLIP),
    );
    add("A128GCM IV of 11 octets", edit_part(&gcm, IV, truncate));
    add(
        "A128CBC-HS256 IV of 15 octets",
        edit_part(&cbc, IV, truncate),
    );
    add(
        "protected header with an added member",
        edit_protected(&gcm, |h| {
            h.insert("typ".into(), json!("JWE"));
        }),
    );
    // The same members in other bytes: the AAD is the received encoding
    // (RFC 7516 §5.2 step 14), not a re-serialization.
    add(
        "protected header re-encoded with whitespace",
        edit_part(&gcm, PROTECTED, |o| {
            let header: Value = serde_json::from_slice(o).unwrap_or_else(|e| panic!("{e}"));
            *o = serde_json::to_vec_pretty(&header).unwrap_or_else(|e| panic!("{e}"));
        }),
    );

    let with_aad = general(
        Encryptor::new(E::A256GCM).aad(&b"bound to the tag"[..]),
        Recipient::new(A::A128KW, &kek),
        &kek,
    );
    let mut flipped = with_aad.clone();
    edit_b64(&mut flipped["aad"], FLIP);
    cases.push(("JWE AAD, one bit flipped", open_json(&flipped, &kek)));
    let mut dropped = with_aad;
    dropped
        .as_object_mut()
        .unwrap_or_else(|| panic!("not an object"))
        .remove("aad");
    cases.push(("JWE AAD removed", open_json(&dropped, &kek)));

    // dir (RFC 7518 §4.5): the key is the CEK.
    let cek = random_oct(16);
    let dir = compact(E::A128GCM, Recipient::new(A::Dir, &cek), &cek);
    cases.push((
        "dir with another 16-octet key",
        open_compact(&dir, &random_oct(16)),
    ));
    cases.push((
        "dir with a 32-octet key for A128GCM",
        open_compact(&dir, &random_oct(32)),
    ));
    cases.push((
        "dir with a non-empty encrypted key",
        open_compact(&edit_part(&dir, ENCRYPTED_KEY, |o| *o = vec![0; 16]), &cek),
    ));
}

/// AES Key Wrap (RFC 7518 §4.4, RFC 3394 §2.2.3) and AES-GCM key wrap
/// (RFC 7518 §4.7).
fn wrap_causes(cases: &mut Cases) {
    let kek = random_oct(16);
    let kw = compact(E::A128GCM, Recipient::new(A::A128KW, &kek), &kek);
    cases.push((
        "A128KW encrypted key, one bit flipped (integrity check)",
        open_compact(&edit_part(&kw, ENCRYPTED_KEY, FLIP), &kek),
    ));
    cases.push((
        "A128KW unwrapped with another 16-octet KEK (integrity check)",
        open_compact(&kw, &random_oct(16)),
    ));
    cases.push((
        "A128KW encrypted key of 23 octets",
        open_compact(&edit_part(&kw, ENCRYPTED_KEY, |o| o.truncate(23)), &kek),
    ));
    let a128 = general(
        Encryptor::new(E::A128GCM),
        Recipient::new(A::A128KW, &kek),
        &kek,
    );
    let a256 = general(
        Encryptor::new(E::A256GCM),
        Recipient::new(A::A128KW, &kek),
        &kek,
    );
    cases.push((
        "A128KW wrapping a 32-octet CEK for A128GCM",
        open_json(&graft_recipient(a128, &a256), &kek),
    ));

    let gkek = random_oct(16);
    let gcmkw = compact(E::A128GCM, Recipient::new(A::A128GCMKW, &gkek), &gkek);
    cases.push((
        "A128GCMKW tag, one bit flipped, in the protected header",
        open_compact(
            &edit_protected(&gcmkw, |h| {
                let tag = h.get_mut("tag").unwrap_or_else(|| panic!("no tag"));
                edit_b64(tag, FLIP);
            }),
            &gkek,
        ),
    ));
    cases.push((
        "A128GCMKW encrypted key, one bit flipped",
        open_compact(&edit_part(&gcmkw, ENCRYPTED_KEY, FLIP), &gkek),
    ));
    let g128 = general(
        Encryptor::new(E::A128GCM),
        Recipient::new(A::A128GCMKW, &gkek),
        &gkek,
    );
    // RFC 7516 §7.2.1 lets `iv` and `tag` sit in the per-recipient
    // unprotected header; the GCMKW tag still binds them (RFC 7518 §4.7).
    cases.push((
        "A128GCMKW iv, one bit flipped, in the per-recipient header",
        open_json(&edit_recipient_b64(g128.clone(), "iv", FLIP), &gkek),
    ));
    cases.push((
        "A128GCMKW tag, one bit flipped, in the per-recipient header",
        open_json(&edit_recipient_b64(g128.clone(), "tag", FLIP), &gkek),
    ));
    cases.push((
        "A128GCMKW iv of 8 octets in the per-recipient header",
        open_json(
            &edit_recipient_b64(g128.clone(), "iv", |o| o.truncate(8)),
            &gkek,
        ),
    ));
    let g256 = general(
        Encryptor::new(E::A256GCM),
        Recipient::new(A::A128GCMKW, &gkek),
        &gkek,
    );
    cases.push((
        "A128GCMKW wrapping a 32-octet CEK for A128GCM",
        open_json(&graft_recipient(g128, &g256), &gkek),
    ));
}

/// PBES2 (RFC 7518 §4.8, ADR 0023).
fn pbes2_causes(cases: &mut Cases) {
    let password = oct(b"correct horse battery staple");
    let alg = A::Pbes2Hs256A128KW;
    let pbes2 = compact(
        E::A128GCM,
        Recipient::new(alg.clone(), &password),
        &password,
    );
    cases.push((
        "PBES2 with the wrong password",
        open_compact(&pbes2, &oct(b"correct horse battery stapler")),
    ));
    cases.push((
        "PBES2 encrypted key, one bit flipped",
        open_compact(&edit_part(&pbes2, ENCRYPTED_KEY, FLIP), &password),
    ));
    // ADR 0023: the default decrypt bound is 10,000 iterations.
    let over = Encryptor::new(E::A128GCM)
        .recipient(Recipient::new(alg.clone(), &password).p2c(10_001))
        .encrypt_compact(PT)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        decrypt_compact(&over, &password, &policy().max_pbes2_count(10_001))
            .map(|d| d.plaintext().to_vec())
            .ok()
            .as_deref(),
        Some(PT)
    );
    cases.push((
        "PBES2 p2c of 10,001, over the bound",
        open_compact(&over, &password),
    ));

    let doc = general(
        Encryptor::new(E::A128GCM),
        Recipient::new(alg, &password),
        &password,
    );
    cases.push((
        "PBES2 p2s of 7 octets (RFC 7518 §4.8.1.1 requires 8)",
        open_json(
            &edit_recipient_b64(doc.clone(), "p2s", |o| o.truncate(7)),
            &password,
        ),
    ));
    cases.push((
        "PBES2 p2s, one bit flipped",
        open_json(&edit_recipient_b64(doc.clone(), "p2s", FLIP), &password),
    ));
    let mut lower = doc;
    recipient_header(&mut lower).insert("p2c".into(), json!(9_999));
    cases.push((
        "PBES2 p2c changed within the bound",
        open_json(&lower, &password),
    ));
}

/// ECDH-ES (RFC 7518 §4.6) on P-256 and X25519 (RFC 8037 §3.2), direct
/// and with key wrapping.
fn ecdh_causes(cases: &mut Cases) {
    let p256 = ec(EcCurve::P256);
    let kw = Recipient::new(A::EcdhEsA128KW, &public(&p256))
        .apu(&b"Alice"[..])
        .apv(&b"Bob"[..]);
    let doc = general(Encryptor::new(E::A128GCM), kw, &p256);
    cases.push((
        "ECDH-ES+A128KW P-256 epk off the curve (y flipped)",
        open_json(
            &edit_epk(doc.clone(), |epk| edit_b64(&mut epk["y"], FLIP)),
            &p256,
        ),
    ));
    let p384 = ec(EcCurve::P384);
    cases.push((
        "ECDH-ES+A128KW P-384 epk for a P-256 key",
        open_json(
            &edit_epk(doc.clone(), |epk| {
                *epk = epk_of(&p384).as_object().cloned().unwrap_or_default()
            }),
            &p256,
        ),
    ));
    cases.push((
        "ECDH-ES+A128KW epk with a private member d",
        open_json(
            &edit_epk(doc.clone(), |epk| {
                let d = serde_json::from_str::<Value>(&p256.to_json())
                    .unwrap_or_else(|e| panic!("{e}"))["d"]
                    .clone();
                epk.insert("d".into(), d);
            }),
            &p256,
        ),
    ));
    cases.push((
        "ECDH-ES+A128KW apu changed (Concat KDF input)",
        open_json(&edit_recipient_b64(doc.clone(), "apu", FLIP), &p256),
    ));
    let mut added = doc.clone();
    edit_b64(
        recipient_header(&mut added)
            .get_mut("apv")
            .unwrap_or_else(|| panic!("no apv")),
        |o| o.extend_from_slice(b"!"),
    );
    cases.push(("ECDH-ES+A128KW apv lengthened", open_json(&added, &p256)));
    let mut ek = doc;
    edit_b64(&mut ek["recipients"][0]["encrypted_key"], FLIP);
    cases.push((
        "ECDH-ES+A128KW encrypted key, one bit flipped",
        open_json(&ek, &p256),
    ));

    let direct = general(
        Encryptor::new(E::A128GCM),
        Recipient::new(A::EcdhEs, &public(&p256)),
        &p256,
    );
    cases.push((
        "ECDH-ES P-256 epk replaced by another valid point",
        open_json(
            &edit_epk(direct.clone(), |epk| {
                *epk = epk_of(&ec(EcCurve::P256))
                    .as_object()
                    .cloned()
                    .unwrap_or_default();
            }),
            &p256,
        ),
    ));
    let mut nonempty = direct;
    nonempty["recipients"][0]["encrypted_key"] = json!(b64url_encode(&[0; 16]));
    cases.push((
        "ECDH-ES (direct) with a non-empty encrypted key",
        open_json(&nonempty, &p256),
    ));

    let okp = x25519();
    let x = general(
        Encryptor::new(E::A128GCM),
        Recipient::new(A::EcdhEs, &public(&okp)),
        &okp,
    );
    let replace = |epk: Value| {
        edit_epk(x.clone(), move |m| {
            *m = epk.as_object().cloned().unwrap_or_default()
        })
    };
    // u = 1 has order 4, u = 0 order 2: X25519 gives the all-zero shared
    // secret, which RFC 7748 §6.1 says to reject.
    let mut one = [0u8; 32];
    one[0] = 1;
    cases.push((
        "ECDH-ES X25519 epk of low order (u = 1)",
        open_json(&replace(x25519_epk(&one)), &okp),
    ));
    cases.push((
        "ECDH-ES X25519 epk u = 0 (all-zero shared secret)",
        open_json(&replace(x25519_epk(&[0; 32])), &okp),
    ));
    cases.push((
        "ECDH-ES X25519 epk x of 31 octets",
        open_json(&replace(x25519_epk(&[9; 31])), &okp),
    ));
}

/// `zip: DEF` (RFC 7516 §4.1.3, §5.2 step 17; ADR 0017).
#[cfg(feature = "deflate")]
fn inflate_causes(cases: &mut Cases) {
    use aes_gcm::aead::consts::U12;
    use aes_gcm::{AeadInOut, Aes128Gcm, KeyInit, Nonce};

    let cek = [0x42u8; 16];
    let key = oct(&cek);
    let big = vec![b'a'; 4_096];
    let token = Encryptor::new(E::A128GCM)
        .compress()
        .recipient(Recipient::new(A::Dir, &key))
        .encrypt_compact(&big)
        .unwrap_or_else(|e| panic!("{e}"));
    let roomy = policy().max_decompressed_len(4_096);
    assert!(decrypt_compact(&token, &key, &roomy).is_ok());
    cases.push((
        "zip: DEF inflating past max_decompressed_len",
        decrypt_compact(&token, &key, &policy().max_decompressed_len(4_095)).map(drop),
    ));

    // An authenticated payload that is not DEFLATE (BTYPE 11 is reserved,
    // RFC 1951 §3.2.3), sealed with RustCrypto AES-GCM directly.
    let header = r#"{"alg":"dir","enc":"A128GCM","zip":"DEF"}"#;
    let protected = b64url_encode(header.as_bytes());
    let iv = [7u8; 12];
    let cipher = Aes128Gcm::new_from_slice(&cek).unwrap_or_else(|e| panic!("{e}"));
    let nonce = Nonce::<U12>::try_from(&iv[..]).unwrap_or_else(|e| panic!("{e}"));
    let mut payload = vec![0b0000_0111u8, 0, 0];
    let tag = cipher
        .encrypt_inout_detached(&nonce, protected.as_bytes(), payload.as_mut_slice().into())
        .unwrap_or_else(|e| panic!("{e}"));
    let forged = [
        protected,
        String::new(),
        b64url_encode(&iv),
        b64url_encode(&payload),
        b64url_encode(&tag),
    ]
    .join(".");
    cases.push((
        "zip: DEF payload that is not a DEFLATE stream",
        open_compact(&forged, &key),
    ));
}

fn all_causes() -> Cases {
    let mut cases = Cases::new();
    content_causes(&mut cases);
    wrap_causes(&mut cases);
    pbes2_causes(&mut cases);
    ecdh_causes(&mut cases);
    #[cfg(feature = "deflate")]
    inflate_causes(&mut cases);
    cases
}

#[test]
fn every_post_key_management_failure_is_the_same_decryption_failed() {
    let cases = all_causes();
    assert!(cases.len() >= 25, "only {} causes", cases.len());
    let names: BTreeSet<_> = cases.iter().map(|(name, _)| *name).collect();
    assert_eq!(names.len(), cases.len(), "cause names must be unique");

    let mut wrong = Vec::new();
    let mut renderings = BTreeSet::new();
    for (name, result) in &cases {
        match result {
            Err(e) if *e == Error::DecryptionFailed => {
                renderings.insert((
                    format!("{e:?}"),
                    e.to_string(),
                    e.code(),
                    e.source().is_none(),
                ));
            }
            other => wrong.push(format!("{name}: {:?}", other.as_ref().err())),
        }
    }
    assert!(
        wrong.is_empty(),
        "not DecryptionFailed:\n{}",
        wrong.join("\n")
    );
    // One value, one rendering: nothing distinguishes the causes.
    let expected = (
        "DecryptionFailed".to_owned(),
        "decryption failed".to_owned(),
        "DecryptionFailed",
        true,
    );
    assert_eq!(renderings.into_iter().collect::<Vec<_>>(), vec![expected]);
}

#[test]
fn the_table_counts_its_causes() {
    // 45 causes in every build, 47 with `deflate`.
    let expected = if cfg!(feature = "deflate") { 47 } else { 45 };
    assert_eq!(all_causes().len(), expected);
}
