//! The whole JWE algorithm matrix through the public API (0003 T16; ADR 0008
//! layers 1 and 4).
//!
//! Every `alg` polyjose encrypts with (RFC 7518 §4.1: dir, A*KW, A*GCMKW,
//! ECDH-ES and ECDH-ES+A*KW on P-256, P-384, P-521 and X25519, PBES2, and
//! RSA-OAEP-256) × every `enc` (RFC 7518 §5.1) × every serialization
//! (compact, RFC 7516 §7.1; flattened and general JSON, §7.2.2, §7.2.1):
//!
//! - **Round trip.** Encrypt, then decrypt with the recipient's key, gives
//!   the plaintext back, and `alg` sits where polyjose documents it: in the
//!   protected header for compact and flattened, in the recipient's header
//!   for general (plan.md "Interface contract").
//! - **One-bit flips.** A flip in the encrypted key, IV, ciphertext, tag or
//!   AAD is exactly [`Error::DecryptionFailed`] (RFC 7516 §11.4–§11.5). A
//!   flip in the protected or per-recipient header is `DecryptionFailed`,
//!   or a structural code if it broke the header's JSON, its parameters or
//!   its `alg`/`enc`. A flip in the encoded text may also break the
//!   base64url (RFC 7515 §2) or the serialization itself. Nothing ever
//!   decrypts.
//! - **RSA-OAEP-256** is encrypt-only (ADR 0021): its cells are checked by
//!   structure (a k-octet encrypted key, RFC 8017 §7.1.1; the IV and tag
//!   lengths of `enc`), and decrypting is `UnsupportedAlgorithm`. Its
//!   decryption is checked by the Node oracle (`scripts/test-all.sh node`).
//!
//! A deterministic sweep covers all 486 cells once with a flip in every
//! segment; a property test (≤ 1,000 cases, pipeline rule 8) adds random
//! plaintexts, AADs and flip positions. Last, the mixed-family general JWE
//! deferred from T14: A128KW, ECDH-ES+A128KW on P-256 and on X25519, PBES2
//! and A256GCMKW recipients, where each key opens the message and reports
//! its own index (RFC 7516 §7.2.1; plan.md "Recipient selection").
#![allow(clippy::panic)] // test code: a panic is a failed assertion

use std::ops::Range;

use polyjose::Error;
use polyjose::jwa::{ContentEncAlg, KeyMgmtAlg};
use polyjose::jwe::{
    DecryptPolicy, Encryptor, JsonForm, Recipient, Serialization, decrypt_compact, decrypt_json,
};
use polyjose::jwk::{EcCurve, Jwk, OkpCurve};
use polyjose::keys::{KeySpec, generate};
use polyjose::util::{b64url_decode, b64url_encode};
use proptest::prelude::*;
use serde_json::Value;

use ContentEncAlg as E;
use KeyMgmtAlg as A;

// ---------------------------------------------------------------------------
// The matrix
// ---------------------------------------------------------------------------

/// The key a cell's `alg` needs.
#[derive(Clone, Copy, Debug)]
enum Kind {
    /// A KEK of this many octets (RFC 7518 §4.4, §4.7).
    Kek(usize),
    /// The CEK itself, `cek_len(enc)` octets (RFC 7518 §4.5).
    Cek,
    /// A PBES2 password (RFC 7518 §4.8).
    Password,
    /// An EC key pair (RFC 7518 §6.2).
    Ec(EcCurve),
    /// An X25519 key pair (RFC 8037 §2).
    X25519,
    /// An RSA public key (RFC 7518 §6.3): encrypt only.
    Rsa,
}

/// One `alg` with its key kind.
#[derive(Clone, Debug)]
struct Cell {
    alg: KeyMgmtAlg,
    kind: Kind,
}

/// Every `alg` polyjose encrypts with, once per key kind: 27 cells.
fn cells() -> Vec<Cell> {
    let cell = |alg, kind| Cell { alg, kind };
    let mut all = vec![
        cell(A::Dir, Kind::Cek),
        cell(A::A128KW, Kind::Kek(16)),
        cell(A::A192KW, Kind::Kek(24)),
        cell(A::A256KW, Kind::Kek(32)),
        cell(A::A128GCMKW, Kind::Kek(16)),
        cell(A::A192GCMKW, Kind::Kek(24)),
        cell(A::A256GCMKW, Kind::Kek(32)),
        cell(A::Pbes2Hs256A128KW, Kind::Password),
        cell(A::Pbes2Hs384A192KW, Kind::Password),
        cell(A::Pbes2Hs512A256KW, Kind::Password),
        cell(A::RsaOaep256, Kind::Rsa),
    ];
    let curves = [
        Kind::Ec(EcCurve::P256),
        Kind::Ec(EcCurve::P384),
        Kind::Ec(EcCurve::P521),
        Kind::X25519,
    ];
    for alg in [A::EcdhEs, A::EcdhEsA128KW, A::EcdhEsA192KW, A::EcdhEsA256KW] {
        all.extend(curves.iter().map(|&kind| cell(alg.clone(), kind)));
    }
    all
}

const FORMS: [Serialization; 3] = [
    Serialization::Compact,
    Serialization::Json(JsonForm::Flattened),
    Serialization::Json(JsonForm::General),
];

/// The CEK length of `enc` (RFC 7518 §5.2.3–§5.2.5, §5.3).
fn cek_len(enc: &ContentEncAlg) -> usize {
    match enc {
        E::A128GCM => 16,
        E::A192GCM => 24,
        E::A256GCM | E::A128CbcHs256 => 32,
        E::A192CbcHs384 => 48,
        E::A256CbcHs512 => 64,
        other => panic!("no CEK length for {other}"),
    }
}

/// The IV length of `enc` (RFC 7518 §5.2.2.1: 16; §5.3: 12).
fn iv_len(enc: &ContentEncAlg) -> usize {
    if is_gcm(enc) { 12 } else { 16 }
}

/// The tag length of `enc` (RFC 7518 §5.2.3–§5.2.5: half the CEK; §5.3: 16).
fn tag_len(enc: &ContentEncAlg) -> usize {
    if is_gcm(enc) { 16 } else { cek_len(enc) / 2 }
}

fn is_gcm(enc: &ContentEncAlg) -> bool {
    matches!(enc, E::A128GCM | E::A192GCM | E::A256GCM)
}

fn generated(spec: KeySpec) -> Jwk {
    generate(spec).unwrap_or_else(|e| panic!("{e}"))
}

/// The cookbook's RFC 7520 §5.1 RSA key (2048 bits), public members only:
/// polyjose imports no RSA private key (ADR 0021).
fn rsa_public() -> Jwk {
    let cookbook: Value = serde_json::from_str(include_str!(
        "third_party/ietf-jose-cookbook/jwe/5_1.key_encryption_using_rsa_v15_and_aes-hmac-sha2.json"
    ))
    .unwrap_or_else(|e| panic!("{e}"));
    let key = &cookbook["input"]["key"];
    let public = serde_json::json!({ "kty": "RSA", "n": key["n"], "e": key["e"] });
    Jwk::from_json(public.to_string().as_bytes()).unwrap_or_else(|e| panic!("{e}"))
}

/// The keys of one cell: the one the sender encrypts to, the one the
/// recipient decrypts with (the same for symmetric keys).
struct Keys {
    encrypt: Jwk,
    decrypt: Jwk,
}

fn keys(kind: Kind, enc: &ContentEncAlg) -> Keys {
    let symmetric = |len| {
        let key = generated(KeySpec::Oct { bytes: len });
        Keys {
            encrypt: key.clone(),
            decrypt: key,
        }
    };
    let pair = |key: Jwk| Keys {
        encrypt: key.to_public().unwrap_or_else(|| panic!("no public part")),
        decrypt: key,
    };
    match kind {
        Kind::Kek(len) => symmetric(len),
        Kind::Cek => symmetric(cek_len(enc)),
        // Any octets are a password (RFC 7518 §4.8.1, RFC 8018 §4.1).
        Kind::Password => symmetric(24),
        Kind::Ec(curve) => pair(generated(KeySpec::Ec(curve))),
        Kind::X25519 => pair(generated(KeySpec::Okp(OkpCurve::X25519))),
        Kind::Rsa => {
            let key = rsa_public();
            Keys {
                encrypt: key.clone(),
                decrypt: key,
            }
        }
    }
}

/// Every `alg` and `enc`: the allow-list is not under test here.
fn policy() -> DecryptPolicy {
    DecryptPolicy::new(KeyMgmtAlg::KNOWN, ContentEncAlg::KNOWN).unwrap_or_else(|e| panic!("{e}"))
}

/// PBES2 with 1,000 iterations, the RFC 7518 §4.8.1.2 minimum
/// recommendation, keeps the suite fast; the count is not under test.
fn recipient(cell: &Cell, key: &Jwk) -> Recipient {
    let r = Recipient::new(cell.alg.clone(), key);
    if matches!(cell.kind, Kind::Password) {
        r.p2c(1_000)
    } else {
        r
    }
}

fn encrypt(
    cell: &Cell,
    enc: &ContentEncAlg,
    form: Serialization,
    key: &Jwk,
    plaintext: &[u8],
    aad: Option<&[u8]>,
) -> String {
    let mut encryptor = Encryptor::new(enc.clone()).recipient(recipient(cell, key));
    if let (Serialization::Json(_), Some(aad)) = (form, aad) {
        encryptor = encryptor.aad(aad);
    }
    match form {
        Serialization::Compact => encryptor.encrypt_compact(plaintext),
        Serialization::Json(json_form) => encryptor.encrypt_json(plaintext, json_form),
    }
    .unwrap_or_else(|e| panic!("{} {enc} {form:?}: {e}", cell.alg))
}

fn decrypt(form: Serialization, text: &str, key: &Jwk) -> polyjose::Result<Vec<u8>> {
    match form {
        Serialization::Compact => decrypt_compact(text, key, &policy()),
        Serialization::Json(_) => decrypt_json(text, key, &policy()),
    }
    .map(|d| d.plaintext().to_vec())
}

// ---------------------------------------------------------------------------
// Segments of a serialized JWE
// ---------------------------------------------------------------------------

/// A part of a JWE (RFC 7516 §7.1, §7.2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Segment {
    Protected,
    EncryptedKey,
    Iv,
    Ciphertext,
    Tag,
    Aad,
    /// The per-recipient unprotected header (JSON object, not base64url).
    Header,
}

impl Segment {
    fn is_header(self) -> bool {
        matches!(self, Segment::Protected | Segment::Header)
    }
}

/// The byte range of every non-empty segment in the serialized `text`.
fn segments(form: Serialization, text: &str) -> Vec<(Segment, Range<usize>)> {
    let found = match form {
        Serialization::Compact => compact_segments(text),
        Serialization::Json(_) => json_segments(text),
    };
    found.into_iter().filter(|(_, r)| !r.is_empty()).collect()
}

fn compact_segments(text: &str) -> Vec<(Segment, Range<usize>)> {
    let order = [
        Segment::Protected,
        Segment::EncryptedKey,
        Segment::Iv,
        Segment::Ciphertext,
        Segment::Tag,
    ];
    let mut start = 0;
    let parts: Vec<&str> = text.split('.').collect();
    assert_eq!(parts.len(), 5, "RFC 7516 §7.1: five parts");
    order
        .into_iter()
        .zip(parts)
        .map(|(segment, part)| {
            let range = start..start + part.len();
            start = range.end + 1;
            (segment, range)
        })
        .collect()
}

/// The range of the unique occurrence of `"value"` in `text`, quotes
/// excluded.
fn string_range(text: &str, value: &str) -> Range<usize> {
    let quoted = format!("\"{value}\"");
    let at = text
        .find(&quoted)
        .unwrap_or_else(|| panic!("{value} not in {text}"));
    assert_eq!(text.matches(&quoted).count(), 1, "{value} is not unique");
    at + 1..at + 1 + value.len()
}

/// The range of the object value of member `"header"` in `text`.
fn header_range(text: &str) -> Option<Range<usize>> {
    let at = text.find("\"header\"")?;
    let open = at + text[at..].find('{')?;
    let mut depth = 0usize;
    for (i, b) in text.bytes().enumerate().skip(open) {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(open..i + 1);
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced header in {text}")
}

fn json_segments(text: &str) -> Vec<(Segment, Range<usize>)> {
    let doc: Value = serde_json::from_str(text).unwrap_or_else(|e| panic!("{e}"));
    let recipient = doc["recipients"].get(0).unwrap_or(&doc);
    let mut found = Vec::new();
    let mut add = |segment, value: &Value| {
        if let Some(s) = value.as_str().filter(|s| !s.is_empty()) {
            found.push((segment, string_range(text, s)));
        }
    };
    add(Segment::Protected, &doc["protected"]);
    add(Segment::EncryptedKey, &recipient["encrypted_key"]);
    add(Segment::Iv, &doc["iv"]);
    add(Segment::Ciphertext, &doc["ciphertext"]);
    add(Segment::Tag, &doc["tag"]);
    add(Segment::Aad, &doc["aad"]);
    found.extend(header_range(text).map(|r| (Segment::Header, r)));
    found
}

/// `text` with one bit of the decoded octets of base64url `range` flipped,
/// re-encoded: always valid base64url, so only the octets changed.
fn flip_decoded(text: &str, range: Range<usize>, bit: usize) -> String {
    let mut octets = b64url_decode(&text[range.clone()]).unwrap_or_else(|e| panic!("{e}"));
    let bit = bit % (octets.len() * 8);
    octets[bit / 8] ^= 1 << (bit % 8);
    let encoded = b64url_encode(&octets);
    assert_eq!(encoded.len(), range.len());
    format!("{}{encoded}{}", &text[..range.start], &text[range.end..])
}

/// `text` with one of the low seven bits of one byte in `range` flipped.
/// The text stays ASCII, so it is still a `str`.
fn flip_text(text: &str, range: Range<usize>, at: usize, bit: u8) -> String {
    let mut octets = text.as_bytes().to_vec();
    let i = range.start + at % range.len();
    octets[i] ^= 1 << (bit % 7);
    String::from_utf8(octets).unwrap_or_else(|e| panic!("{e}"))
}

// ---------------------------------------------------------------------------
// Expectations
// ---------------------------------------------------------------------------

/// What a flip in a header may give besides `DecryptionFailed`: a broken
/// JSON (RFC 7516 §5.2 step 3), a broken or missing parameter (step 4), or
/// an `alg`/`enc` changed to one polyjose lacks or the key cannot serve
/// (plan.md "Error contract").
const HEADER_CODES: &[&str] = &[
    "DecryptionFailed",
    "InvalidJson",
    "InvalidHeader",
    "UnsupportedAlgorithm",
    "KeyAlgorithmMismatch",
];

/// What a flip in encoded text may add: an octet outside the base64url
/// alphabet or non-canonical trailing bits (RFC 7515 §2), a `.` that
/// changes the compact part count (RFC 7516 §7.1), or a `"` or `\` that
/// breaks the JSON string (RFC 8259 §7).
const TEXT_CODES: &[&str] = &["InvalidBase64", "InvalidFormat", "InvalidJson"];

/// Checks the outcome of decrypting a JWE with one flip in `segment`.
fn check_flip(result: polyjose::Result<Vec<u8>>, segment: Segment, text_flip: bool, what: &str) {
    let code = match result {
        Ok(_) => panic!("{what}: a flipped {segment:?} decrypted"),
        Err(e) => e.code(),
    };
    let ok = code == "DecryptionFailed"
        || (segment.is_header() && HEADER_CODES.contains(&code))
        || (text_flip && TEXT_CODES.contains(&code));
    assert!(ok, "{what}: a flipped {segment:?} gave {code}");
}

/// Checks where `alg` and `enc` went (plan.md "Interface contract") and,
/// for RSA-OAEP-256, the lengths of every part.
fn check_structure(cell: &Cell, enc: &ContentEncAlg, form: Serialization, text: &str) {
    let protected_of = |b64u: &str| -> Value {
        let octets = b64url_decode(b64u).unwrap_or_else(|e| panic!("{e}"));
        serde_json::from_slice(&octets).unwrap_or_else(|e| panic!("{e}"))
    };
    let (protected, header, parts) = match form {
        Serialization::Compact => {
            let parts: Vec<String> = text.split('.').map(str::to_owned).collect();
            (protected_of(&parts[0]), Value::Null, parts)
        }
        Serialization::Json(json_form) => {
            let doc: Value = serde_json::from_str(text).unwrap_or_else(|e| panic!("{e}"));
            let recipient = match json_form {
                JsonForm::General => doc["recipients"][0].clone(),
                JsonForm::Flattened => doc.clone(),
            };
            let s = |v: &Value| v.as_str().unwrap_or_default().to_owned();
            let parts = vec![
                s(&doc["protected"]),
                s(&recipient["encrypted_key"]),
                s(&doc["iv"]),
                s(&doc["ciphertext"]),
                s(&doc["tag"]),
            ];
            (protected_of(&parts[0]), recipient["header"].clone(), parts)
        }
    };
    assert_eq!(protected["enc"], enc.as_str(), "enc is always protected");
    let alg_at = match form {
        Serialization::Json(JsonForm::General) => &header["alg"],
        _ => &protected["alg"],
    };
    assert_eq!(alg_at, cell.alg.as_str(), "{form:?}: alg placement");
    let len = |i: usize| {
        b64url_decode(&parts[i])
            .map(|o| o.len())
            .unwrap_or(usize::MAX)
    };
    assert_eq!(len(2), iv_len(enc), "IV length");
    assert_eq!(len(4), tag_len(enc), "tag length");
    if matches!(cell.kind, Kind::Rsa) {
        // RFC 8017 §7.1.1: the ciphertext is k octets, k = 256 for 2048 bits.
        assert_eq!(len(1), 256, "RSA-OAEP-256 encrypted key length");
    }
}

/// Which bit to flip.
struct Flip {
    /// The index (mod the count) of the segment to flip; every segment,
    /// one after another, when `None`.
    pick: Option<usize>,
    /// The bit (decoded) or byte (text) position, mod the segment length.
    position: usize,
    /// Flip this low bit of an encoded byte instead of a decoded bit.
    /// Per-recipient headers are JSON, so they are always flipped as text.
    text_bit: Option<u8>,
}

/// One cell: round trip and structure, then `flip`.
fn run_cell(
    cell: &Cell,
    enc: &ContentEncAlg,
    form: Serialization,
    plaintext: &[u8],
    aad: Option<&[u8]>,
    flip: &Flip,
) {
    let what = format!("{} {enc} {form:?}", cell.alg);
    let keys = keys(cell.kind, enc);
    let text = encrypt(cell, enc, form, &keys.encrypt, plaintext, aad);
    check_structure(cell, enc, form, &text);
    let opened = decrypt(form, &text, &keys.decrypt);
    if matches!(cell.kind, Kind::Rsa) {
        // ADR 0021: RSA-OAEP-256 never decrypts, not even our own output.
        assert_eq!(opened.err(), Some(Error::UnsupportedAlgorithm), "{what}");
        return;
    }
    assert_eq!(
        opened.as_deref().ok(),
        Some(plaintext),
        "{what}: round trip"
    );

    let all = segments(form, &text);
    let chosen: Vec<_> = match flip.pick {
        Some(i) => vec![all[i % all.len()].clone()],
        None => all,
    };
    for (segment, range) in chosen {
        let at = flip.position;
        let flipped = match (segment, flip.text_bit) {
            (Segment::Header, bit) => flip_text(&text, range, at, bit.unwrap_or(0)),
            (_, Some(bit)) => flip_text(&text, range, at, bit),
            (_, None) => flip_decoded(&text, range, at),
        };
        let text_level = flip.text_bit.is_some() || segment == Segment::Header;
        let result = decrypt(form, &flipped, &keys.decrypt);
        check_flip(result, segment, text_level, &what);
    }
}

// ---------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------

const PT: &[u8] = b"Every alg, every enc, every serialization.";

#[test]
fn the_matrix_has_every_alg_and_enc() {
    let cells = cells();
    assert_eq!(cells.len(), 27);
    // Every alg polyjose knows is in the matrix: RFC 7518 §4.1 minus what
    // ADRs 0021 and 0022 leave out (those are KeyMgmtAlg::Unknown).
    for alg in KeyMgmtAlg::KNOWN {
        assert!(cells.iter().any(|c| c.alg == *alg), "{alg} missing");
    }
    assert_eq!(ContentEncAlg::KNOWN.len(), 6);
    assert_eq!(cells.len() * ContentEncAlg::KNOWN.len() * FORMS.len(), 486);
}

#[test]
fn every_cell_round_trips_and_every_segment_flip_fails() {
    for cell in cells() {
        for enc in ContentEncAlg::KNOWN {
            for form in FORMS {
                // A middle bit of each segment's decoded octets.
                let flip = Flip {
                    pick: None,
                    position: 13,
                    text_bit: None,
                };
                run_cell(&cell, enc, form, PT, Some(b"aad"), &flip);
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    #[test]
    fn any_cell_round_trips_and_any_one_bit_flip_fails(
        cell in 0usize..27,
        enc in 0usize..6,
        form in 0usize..3,
        plaintext in proptest::collection::vec(any::<u8>(), 0..96),
        aad in proptest::option::of(proptest::collection::vec(any::<u8>(), 1..24)),
        pick in any::<usize>(),
        position in any::<usize>(),
        text_flip in proptest::option::of(0u8..7),
    ) {
        let cells = cells();
        run_cell(
            &cells[cell],
            &ContentEncAlg::KNOWN[enc],
            FORMS[form],
            &plaintext,
            aad.as_deref(),
            &Flip {
                pick: Some(pick),
                position,
                text_bit: text_flip,
            },
        );
    }
}

// ---------------------------------------------------------------------------
// Mixed-family recipients (deferred from T14)
// ---------------------------------------------------------------------------

/// `key` with JWK `alg` set (RFC 7517 §4.4), so it serves that `alg` only.
fn bound(key: &Jwk, alg: &KeyMgmtAlg) -> Jwk {
    let mut object: Value = serde_json::from_str(&key.to_json()).unwrap_or_else(|e| panic!("{e}"));
    object["alg"] = Value::String(alg.as_str().to_owned());
    Jwk::from_json(object.to_string().as_bytes()).unwrap_or_else(|e| panic!("{e}"))
}

/// The five mixed-family recipients: (alg, encrypt-to key, decrypt key).
fn mixed_recipients() -> Vec<(KeyMgmtAlg, Jwk, Jwk)> {
    let oct = |len| generated(KeySpec::Oct { bytes: len });
    let pair = |spec| {
        let key = generated(spec);
        (key.to_public().unwrap_or_else(|| panic!("no public")), key)
    };
    let a128kw = oct(16);
    // A 16-octet password: also the right size for A128KW, so trial
    // decryption must move past recipient 0 to reach it.
    let password = oct(16);
    let a256gcmkw = oct(32);
    let (p256_pub, p256) = pair(KeySpec::Ec(EcCurve::P256));
    let (x_pub, x) = pair(KeySpec::Okp(OkpCurve::X25519));
    vec![
        (A::A128KW, a128kw.clone(), a128kw),
        (A::EcdhEsA128KW, p256_pub, p256),
        (A::EcdhEsA128KW, x_pub, x),
        (A::Pbes2Hs256A128KW, password.clone(), password),
        (A::A256GCMKW, a256gcmkw.clone(), a256gcmkw),
    ]
}

fn mixed_jwe(enc: &ContentEncAlg, recipients: &[(KeyMgmtAlg, Jwk, Jwk)]) -> String {
    recipients
        .iter()
        .fold(
            Encryptor::new(enc.clone()).aad(&b"to five recipients"[..]),
            |e, (alg, to, _)| {
                let r = Recipient::new(alg.clone(), to);
                e.recipient(if alg == &A::Pbes2Hs256A128KW {
                    r.p2c(1_000)
                } else {
                    r
                })
            },
        )
        .encrypt_json(PT, JsonForm::General)
        .unwrap_or_else(|e| panic!("{e}"))
}

#[test]
fn each_key_of_a_mixed_family_jwe_opens_it_and_reports_its_index() {
    for enc in ContentEncAlg::KNOWN {
        let recipients = mixed_recipients();
        let jwe = mixed_jwe(enc, &recipients);
        let doc: Value = serde_json::from_str(&jwe).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(doc["recipients"].as_array().map(Vec::len), Some(5));
        for (index, (alg, _, key)) in recipients.iter().enumerate() {
            // Unbound keys: trial decryption over every candidate.
            // Bound keys: only the recipient of their `alg` is a candidate.
            for key in [key.clone(), bound(key, alg)] {
                let d = decrypt_json(&jwe, &key, &policy())
                    .unwrap_or_else(|e| panic!("{enc} recipient {index}: {e}"));
                assert_eq!(d.plaintext(), PT);
                assert_eq!(d.recipient(), index, "{enc} {alg}");
                assert_eq!(d.aad(), Some(&b"to five recipients"[..]));
                let header = d.recipient_header().unwrap_or_else(|| panic!("no header"));
                assert_eq!(header.key_mgmt_alg().ok().as_ref(), Some(alg));
            }
        }
    }
}

#[test]
fn a_mixed_family_jwe_with_a_flipped_shared_part_opens_for_no_key() {
    let recipients = mixed_recipients();
    let jwe = mixed_jwe(&E::A256GCM, &recipients);
    let form = Serialization::Json(JsonForm::General);
    for (segment, range) in segments(form, &jwe) {
        if matches!(
            segment,
            Segment::Iv | Segment::Ciphertext | Segment::Tag | Segment::Aad
        ) {
            let flipped = flip_decoded(&jwe, range, 7);
            for (_, _, key) in &recipients {
                assert_eq!(
                    decrypt(form, &flipped, key).err(),
                    Some(Error::DecryptionFailed),
                    "{segment:?}"
                );
            }
        }
    }
}

#[test]
fn a_mixed_family_jwe_with_one_recipient_broken_still_opens_for_the_others() {
    // Flip recipient 1's (P-256) encrypted key: its key now fails with the
    // one DecryptionFailed, and every other key still opens the JWE.
    let recipients = mixed_recipients();
    let jwe = mixed_jwe(&E::A128CbcHs256, &recipients);
    let mut doc: Value = serde_json::from_str(&jwe).unwrap_or_else(|e| panic!("{e}"));
    let ek = doc["recipients"][1]["encrypted_key"]
        .as_str()
        .unwrap_or_else(|| panic!("no encrypted key"))
        .to_owned();
    let mut octets = b64url_decode(&ek).unwrap_or_else(|e| panic!("{e}"));
    octets[0] ^= 0x80;
    doc["recipients"][1]["encrypted_key"] = Value::String(b64url_encode(&octets));
    let broken = doc.to_string();
    for (index, (_, _, key)) in recipients.iter().enumerate() {
        let result = decrypt_json(&broken, key, &policy());
        if index == 1 {
            assert_eq!(result.err(), Some(Error::DecryptionFailed));
        } else {
            let d = result.unwrap_or_else(|e| panic!("recipient {index}: {e}"));
            assert_eq!((d.recipient(), d.plaintext()), (index, PT));
        }
    }
}
