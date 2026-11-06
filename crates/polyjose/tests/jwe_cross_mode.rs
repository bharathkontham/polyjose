//! Cross-mode key confusion (ADR 0050 §1, security audit B1, 0003 F06).
//!
//! A*GCMKW wraps the CEK with AES-GCM under the key-encryption key and an
//! **empty** AAD (RFC 7518 §4.7). A JWE JSON Serialization with no JWE
//! Protected Header and no `aad` also has the content AAD `""` (RFC 7516
//! §5.1 step 14). So a GCMKW recipient's (`iv`, `encrypted_key`, `tag`)
//! is a valid `dir` + A*GCM ciphertext under the same key, and an alg-less
//! oct key (RFC 7517 §4.4 makes `alg` optional) allowed for both `dir` and
//! A*GCMKW would decrypt a relabelled token to the victim's CEK.
//!
//! The rule that closes it: for the direct modes, `dir` (RFC 7518 §4.5) and
//! `ECDH-ES` (§4.6, Direct Key Agreement), `alg` **and** `enc` must both be
//! in the JWE Protected Header, else `InvalidHeader` before any
//! cryptographic operation (RFC 7516 §5.2 step 4). The content AAD of a
//! direct message is then never empty, so no key-wrap tag over the empty
//! AAD verifies as content.
//!
//! Every forged token below is checked to be a **live** forgery with an
//! independent AES-GCM (the RustCrypto crate directly), so the rejection is
//! the header rule, never a failed tag.
#![allow(clippy::panic)] // test code: a panic is a failed assertion

use aes_gcm::aead::consts::U12;
use aes_gcm::{AeadInOut, Aes128Gcm, KeyInit, Nonce};
use polyjose::Error;
use polyjose::header::Header;
use polyjose::jwa::{ContentEncAlg, KeyMgmtAlg};
use polyjose::jwe::{
    DecryptPolicy, Decrypted, Encryptor, JsonForm, Recipient, decrypt_compact, decrypt_json,
};
use polyjose::jwk::{EcCurve, Jwk, OkpCurve};
use polyjose::keys::{KeySpec, generate};
use polyjose::util::{b64url_decode, b64url_encode};
use serde_json::{Value, json};

use ContentEncAlg as E;
use KeyMgmtAlg as A;

/// The audit's key: 16 octets 00..0f, no `alg` (RFC 7517 §4.4).
const AUDIT_KEY: &str = r#"{"kty":"oct","k":"AAECAwQFBgcICQoLDA0ODw"}"#;

/// The audit's forged token: a victim's A128GCMKW (`iv`, `encrypted_key`,
/// `tag`) relabelled as a flattened `dir` + A128GCM JWE with no protected
/// header and no `aad` (ADR 0050 §1, Context 1).
const AUDIT_FORGED: &str = r#"{"unprotected":{"alg":"dir","enc":"A128GCM"},"iv":"O7z64SOn4nzSXqYX","ciphertext":"MnP1M2KMxJATaL2fiHopzA","tag":"1iuYCU-NaRWTNmU0AQpqYg"}"#;

fn jwk(json: &str) -> Jwk {
    Jwk::from_json(json.as_bytes()).unwrap_or_else(|e| panic!("{json}: {e}"))
}

fn audit_key() -> Jwk {
    jwk(AUDIT_KEY)
}

fn audit_key_bytes() -> Vec<u8> {
    bytes("AAECAwQFBgcICQoLDA0ODw")
}

/// The audit's policy: `[A128GCMKW, dir]` × `[A128GCM]`.
fn audit_policy() -> DecryptPolicy {
    policy(&[A::A128GCMKW, A::Dir], &[E::A128GCM])
}

fn policy(algs: &[KeyMgmtAlg], encs: &[ContentEncAlg]) -> DecryptPolicy {
    DecryptPolicy::new(algs, encs).unwrap_or_else(|e| panic!("{e}"))
}

fn bytes(b64u: &str) -> Vec<u8> {
    b64url_decode(b64u).unwrap_or_else(|e| panic!("{b64u}: {e}"))
}

fn text(v: &Value, name: &str) -> String {
    v[name]
        .as_str()
        .unwrap_or_else(|| panic!("no string {name} in {v}"))
        .to_owned()
}

fn parse(json: &str) -> Value {
    serde_json::from_str(json).unwrap_or_else(|e| panic!("{json}: {e}"))
}

fn code(result: &polyjose::Result<Decrypted>) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(e) => e.code(),
    }
}

/// Independent AES-128-GCM open (RustCrypto directly, not polyjose): the
/// plaintext, or `None` if the tag does not verify.
fn gcm_open(key: &[u8], iv: &[u8], aad: &[u8], ciphertext: &[u8], tag: &[u8]) -> Option<Vec<u8>> {
    let cipher = Aes128Gcm::new_from_slice(key).ok()?;
    let nonce = Nonce::<U12>::try_from(iv).ok()?;
    let tag = tag.try_into().ok()?;
    let mut buffer = ciphertext.to_vec();
    cipher
        .decrypt_inout_detached(&nonce, aad, buffer.as_mut_slice().into(), tag)
        .ok()?;
    Some(buffer)
}

/// Independent AES-128-GCM seal: `(ciphertext, tag)`.
fn gcm_seal(key: &[u8], iv: &[u8], aad: &[u8], plaintext: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let cipher = Aes128Gcm::new_from_slice(key).unwrap_or_else(|e| panic!("{e}"));
    let nonce = Nonce::<U12>::try_from(iv).unwrap_or_else(|e| panic!("{e}"));
    let mut buffer = plaintext.to_vec();
    let tag = cipher
        .encrypt_inout_detached(&nonce, aad, buffer.as_mut_slice().into())
        .unwrap_or_else(|e| panic!("{e}"));
    (buffer, tag.to_vec())
}

/// A victim's A128GCMKW + A128GCM compact token, its protected header, and
/// the forgery the audit derives from it: the key-wrap `iv`, the encrypted
/// key and the key-wrap `tag`, relabelled as a flattened `dir` JWE with no
/// protected header (the audit PoC, rebuilt through the public API).
struct Victim {
    compact: String,
    segments: Vec<String>,
    wrap_iv: String,
    wrap_tag: String,
}

fn victim(key: &Jwk, plaintext: &[u8]) -> Victim {
    let compact = Encryptor::new(E::A128GCM)
        .recipient(Recipient::new(A::A128GCMKW, key))
        .encrypt_compact(plaintext)
        .unwrap_or_else(|e| panic!("{e}"));
    let segments: Vec<String> = compact.split('.').map(str::to_owned).collect();
    let header = Header::from_json(&bytes(&segments[0])).unwrap_or_else(|e| panic!("{e}"));
    let wrap_iv = header.iv.clone().unwrap_or_else(|| panic!("no iv"));
    let wrap_tag = header.tag.clone().unwrap_or_else(|| panic!("no tag"));
    Victim {
        compact,
        segments,
        wrap_iv,
        wrap_tag,
    }
}

impl Victim {
    /// The audit's forgery, in the flattened form with `alg` and `enc` in
    /// the shared unprotected header.
    fn forged(&self) -> Value {
        json!({
            "unprotected": {"alg": "dir", "enc": "A128GCM"},
            "iv": self.wrap_iv,
            "ciphertext": self.segments[1],
            "tag": self.wrap_tag,
        })
    }

    /// Opens the victim's content with `cek` (independent AES-GCM over the
    /// victim's encoded protected header, RFC 7516 §5.2 step 14).
    fn open_with(&self, cek: &[u8]) -> Option<Vec<u8>> {
        gcm_open(
            cek,
            &bytes(&self.segments[2]),
            self.segments[0].as_bytes(),
            &bytes(&self.segments[3]),
            &bytes(&self.segments[4]),
        )
    }
}

// ---------------------------------------------------------------------------
// The audit PoC (ADR 0050 §1)
// ---------------------------------------------------------------------------

#[test]
fn the_audit_forgery_is_a_live_aes_gcm_ciphertext_under_the_empty_aad() {
    // Not a polyjose behaviour: the premise of the attack. The forged
    // (iv, ciphertext, tag) open under the audit key with AAD "", to the
    // 16-octet CEK of the victim message it came from (RFC 7518 §4.7).
    let v = parse(AUDIT_FORGED);
    let cek = gcm_open(
        &audit_key_bytes(),
        &bytes(&text(&v, "iv")),
        b"",
        &bytes(&text(&v, "ciphertext")),
        &bytes(&text(&v, "tag")),
    );
    assert_eq!(cek.map(|c| c.len()), Some(16));
}

#[test]
fn the_audit_forgery_is_invalid_header() {
    // RFC 7516 §5.2 step 4, RFC 7518 §4.5, ADR 0050 §1: `dir` with `alg`
    // and `enc` outside the protected header, before any cryptography.
    let result = decrypt_json(AUDIT_FORGED, &audit_key(), &audit_policy());
    assert_eq!(code(&result), "InvalidHeader");
}

#[test]
fn a_forgery_of_a_fresh_victim_token_does_not_leak_its_cek() {
    let key = audit_key();
    let p = audit_policy();
    let victim = victim(&key, b"top secret victim plaintext");
    let forged = victim.forged().to_string();

    // The forgery is live: its triple opens to the CEK, which opens the
    // victim's content without the key-encryption key.
    let cek = gcm_open(
        &audit_key_bytes(),
        &bytes(&victim.wrap_iv),
        b"",
        &bytes(&victim.segments[1]),
        &bytes(&victim.wrap_tag),
    )
    .unwrap_or_else(|| panic!("the relabelled key wrap must open under the empty AAD"));
    assert_eq!(
        victim.open_with(&cek).as_deref(),
        Some(&b"top secret victim plaintext"[..])
    );

    // polyjose refuses it, so the CEK is never returned.
    let result = decrypt_json(&forged, &key, &p);
    assert_eq!(code(&result), "InvalidHeader");
    assert!(matches!(result, Err(Error::InvalidHeader(_))));

    // The victim's own token still decrypts under the same key and policy.
    let d = decrypt_compact(&victim.compact, &key, &p).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(d.plaintext(), b"top secret victim plaintext");
}

#[test]
fn the_forgery_is_invalid_header_wherever_its_alg_and_enc_sit() {
    // RFC 7516 §7.2.1: the shared, per-recipient (flattened `header`) and
    // general `recipients[].header` locations; and `alg` protected with
    // `enc` not, or the reverse. Each is InvalidHeader (ADR 0050 §1).
    let key = audit_key();
    let p = audit_policy();
    let victim = victim(&key, b"m");
    let base = victim.forged();
    let (iv, ct, tag) = (&base["iv"], &base["ciphertext"], &base["tag"]);
    let protected = |json: &str| b64url_encode(json.as_bytes());
    let cases = [
        (
            "flattened, per-recipient header",
            json!({"header": {"alg": "dir", "enc": "A128GCM"}, "iv": iv, "ciphertext": ct, "tag": tag}),
        ),
        (
            "flattened, alg shared, enc per-recipient",
            json!({"unprotected": {"alg": "dir"}, "header": {"enc": "A128GCM"}, "iv": iv, "ciphertext": ct, "tag": tag}),
        ),
        (
            "general, per-recipient header",
            json!({"recipients": [{"header": {"alg": "dir", "enc": "A128GCM"}}], "iv": iv, "ciphertext": ct, "tag": tag}),
        ),
        (
            "general, enc shared, alg per-recipient",
            json!({"unprotected": {"enc": "A128GCM"}, "recipients": [{"header": {"alg": "dir"}}], "iv": iv, "ciphertext": ct, "tag": tag}),
        ),
        (
            "enc protected, alg shared",
            json!({"protected": protected(r#"{"enc":"A128GCM"}"#), "unprotected": {"alg": "dir"}, "iv": iv, "ciphertext": ct, "tag": tag}),
        ),
        (
            "alg protected, enc shared",
            json!({"protected": protected(r#"{"alg":"dir"}"#), "unprotected": {"enc": "A128GCM"}, "iv": iv, "ciphertext": ct, "tag": tag}),
        ),
    ];
    for (name, token) in cases {
        let result = decrypt_json(&token.to_string(), &key, &p);
        assert_eq!(code(&result), "InvalidHeader", "{name}");
    }
}

#[test]
fn every_gcmkw_size_relabelled_as_dir_is_invalid_header() {
    // RFC 7518 §4.7 for A192GCMKW and A256GCMKW too: the same relabel,
    // with the content enc of the same AES size.
    for (alg, enc, len) in [
        (A::A128GCMKW, E::A128GCM, 16),
        (A::A192GCMKW, E::A192GCM, 24),
        (A::A256GCMKW, E::A256GCM, 32),
    ] {
        let k = (0..len).map(|i| i as u8).collect::<Vec<u8>>();
        let key = jwk(&format!(r#"{{"kty":"oct","k":"{}"}}"#, b64url_encode(&k)));
        let token = Encryptor::new(enc.clone())
            .recipient(Recipient::new(alg.clone(), &key))
            .encrypt_compact(b"m")
            .unwrap_or_else(|e| panic!("{e}"));
        let seg: Vec<&str> = token.split('.').collect();
        let header = Header::from_json(&bytes(seg[0])).unwrap_or_else(|e| panic!("{e}"));
        let forged = json!({
            "unprotected": {"alg": "dir", "enc": enc.as_str()},
            "iv": header.iv,
            "ciphertext": seg[1],
            "tag": header.tag,
        });
        let p = policy(&[alg.clone(), A::Dir], std::slice::from_ref(&enc));
        let result = decrypt_json(&forged.to_string(), &key, &p);
        assert_eq!(code(&result), "InvalidHeader", "{alg}");
    }
}

#[test]
fn a_key_pinned_to_gcmkw_rejects_the_forgery_too() {
    // ADR 0050 §3 guidance: binding the key's alg is the second defence.
    // The header rule (step 4) still comes first.
    let pinned = jwk(r#"{"kty":"oct","alg":"A128GCMKW","k":"AAECAwQFBgcICQoLDA0ODw"}"#);
    let result = decrypt_json(AUDIT_FORGED, &pinned, &audit_policy());
    assert_eq!(code(&result), "InvalidHeader");
}

// ---------------------------------------------------------------------------
// The reverse relabel: a dir token presented as A*GCMKW
// ---------------------------------------------------------------------------

#[test]
fn the_reverse_relabel_never_decrypts() {
    // A `dir` + A128GCM token with no protected header (another library
    // could write one) whose plaintext is 16 octets, i.e. a plausible CEK.
    let key = audit_key();
    let p = audit_policy();
    let iv = [7u8; 12];
    let secret = [0x42u8; 16];
    let (ct, tag) = gcm_seal(&audit_key_bytes(), &iv, b"", &secret);
    let dir = json!({
        "unprotected": {"alg": "dir", "enc": "A128GCM"},
        "iv": b64url_encode(&iv), "ciphertext": b64url_encode(&ct), "tag": b64url_encode(&tag),
    });
    // As `dir` it is now refused (ADR 0050 §1).
    assert_eq!(
        code(&decrypt_json(&dir.to_string(), &key, &p)),
        "InvalidHeader"
    );

    // Relabelled as A128GCMKW (RFC 7518 §4.7), the triple becomes the key
    // wrap and unwraps to `secret`; the content, which the attacker could
    // only copy from the same triple, does not open under it. GCMKW with
    // an unprotected `alg` is not a direct mode, so the header rule does
    // not apply: the outcome is the uniform DecryptionFailed of key
    // management onwards (RFC 7516 §11.4), never a plaintext.
    let relabelled = json!({
        "unprotected": {"alg": "A128GCMKW", "enc": "A128GCM", "iv": b64url_encode(&iv), "tag": b64url_encode(&tag)},
        "encrypted_key": b64url_encode(&ct),
        "iv": b64url_encode(&iv), "ciphertext": b64url_encode(&ct), "tag": b64url_encode(&tag),
    });
    let result = decrypt_json(&relabelled.to_string(), &key, &p);
    assert_eq!(code(&result), "DecryptionFailed");
}

// ---------------------------------------------------------------------------
// ECDH-ES (direct key agreement)
// ---------------------------------------------------------------------------

fn ecdh_keys() -> [(&'static str, Jwk); 2] {
    [
        ("P-256", KeySpec::Ec(EcCurve::P256)),
        ("X25519", KeySpec::Okp(OkpCurve::X25519)),
    ]
    .map(|(name, spec)| (name, generate(spec).unwrap_or_else(|e| panic!("{e}"))))
}

fn public(key: &Jwk) -> Jwk {
    key.to_public().unwrap_or_else(|| panic!("no public part"))
}

#[test]
fn direct_ecdh_es_with_an_unprotected_alg_is_invalid_header() {
    // RFC 7518 §4.6 (Direct Key Agreement), ADR 0050 §1: a compact ECDH-ES
    // token rewritten as flattened JSON with its header unprotected, in the
    // shared and then the per-recipient header, is InvalidHeader before the
    // agreement runs; the compact original still decrypts.
    let p = policy(&[A::EcdhEs], &[E::A128GCM]);
    for (curve, key) in ecdh_keys() {
        let compact = Encryptor::new(E::A128GCM)
            .recipient(Recipient::new(A::EcdhEs, &public(&key)))
            .encrypt_compact(b"m")
            .unwrap_or_else(|e| panic!("{curve}: {e}"));
        let d = decrypt_compact(&compact, &key, &p).unwrap_or_else(|e| panic!("{curve}: {e}"));
        assert_eq!(d.plaintext(), b"m", "{curve}");

        let seg: Vec<&str> = compact.split('.').collect();
        let header: Value =
            serde_json::from_slice(&bytes(seg[0])).unwrap_or_else(|e| panic!("{e}"));
        let mut enc_only = header.clone();
        let alg_and_epk = json!({"alg": header["alg"], "epk": header["epk"]});
        if let Some(o) = enc_only.as_object_mut() {
            o.remove("alg");
            o.remove("epk");
        }
        let protected_enc = b64url_encode(enc_only.to_string().as_bytes());
        let (iv, ct, tag) = (seg[2], seg[3], seg[4]);
        for (place, token) in [
            (
                "all shared",
                json!({"unprotected": header, "iv": iv, "ciphertext": ct, "tag": tag}),
            ),
            (
                "all per-recipient",
                json!({"header": header, "iv": iv, "ciphertext": ct, "tag": tag}),
            ),
            (
                "enc protected, alg shared",
                json!({"protected": protected_enc, "unprotected": alg_and_epk, "iv": iv, "ciphertext": ct, "tag": tag}),
            ),
            (
                "enc protected, alg in recipients[]",
                json!({"protected": protected_enc, "recipients": [{"header": alg_and_epk}], "iv": iv, "ciphertext": ct, "tag": tag}),
            ),
        ] {
            let result = decrypt_json(&token.to_string(), &key, &p);
            assert_eq!(code(&result), "InvalidHeader", "{curve}: {place}");
        }
    }
}

// ---------------------------------------------------------------------------
// Positive controls
// ---------------------------------------------------------------------------

#[test]
fn direct_modes_with_a_protected_alg_and_enc_still_decrypt() {
    // polyjose's compact and flattened output protects alg and enc.
    let key = audit_key();
    let p = audit_policy();
    let e = Encryptor::new(E::A128GCM).recipient(Recipient::new(A::Dir, &key));
    let compact = e.encrypt_compact(b"m").unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(code(&decrypt_compact(&compact, &key, &p)), "ok");
    let flat = e
        .encrypt_json(b"m", JsonForm::Flattened)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(code(&decrypt_json(&flat, &key, &p)), "ok");

    // A protected alg and enc with other members unprotected is fine.
    let iv = [9u8; 12];
    let protected = b64url_encode(br#"{"alg":"dir","enc":"A128GCM"}"#);
    let (ct, tag) = gcm_seal(&audit_key_bytes(), &iv, protected.as_bytes(), b"m");
    let token = json!({
        "protected": protected, "unprotected": {"kid": "k"},
        "iv": b64url_encode(&iv), "ciphertext": b64url_encode(&ct), "tag": b64url_encode(&tag),
    });
    let d = decrypt_json(&token.to_string(), &key, &p).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(d.plaintext(), b"m");

    let p = policy(&[A::EcdhEs], &[E::A128GCM]);
    for (curve, key) in ecdh_keys() {
        let e = Encryptor::new(E::A128GCM).recipient(Recipient::new(A::EcdhEs, &public(&key)));
        let compact = e.encrypt_compact(b"m").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(code(&decrypt_compact(&compact, &key, &p)), "ok", "{curve}");
        let flat = e
            .encrypt_json(b"m", JsonForm::Flattened)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(code(&decrypt_json(&flat, &key, &p)), "ok", "{curve}");
    }
}

#[test]
fn an_honest_gcmkw_token_with_an_unprotected_alg_still_decrypts() {
    // RFC 7516 §7.2.1 lets a non-direct alg sit in any header: the victim
    // token re-expressed with no protected header at all decrypts under
    // the audit policy (A128GCMKW unwraps; the content AAD is its own).
    let key = audit_key();
    let p = audit_policy();
    let iv = [3u8; 12];
    let cek = [0x5au8; 16];
    let (wrapped, wrap_tag) = gcm_seal(&audit_key_bytes(), &iv, b"", &cek);
    let content_iv = [4u8; 12];
    let (ct, tag) = gcm_seal(&cek, &content_iv, b"", b"hello");
    let token = json!({
        "unprotected": {"alg": "A128GCMKW", "enc": "A128GCM", "iv": b64url_encode(&iv), "tag": b64url_encode(&wrap_tag)},
        "encrypted_key": b64url_encode(&wrapped),
        "iv": b64url_encode(&content_iv), "ciphertext": b64url_encode(&ct), "tag": b64url_encode(&tag),
    });
    let d = decrypt_json(&token.to_string(), &key, &p).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(d.plaintext(), b"hello");
}

/// A general-form JWE to one recipient, and the same token with the
/// recipient's header moved to the shared unprotected header: moving
/// members between unprotected headers leaves the AAD unchanged, so both
/// are valid (RFC 7516 §5.1 step 14, §7.2.1).
fn general_and_shared(alg: &KeyMgmtAlg, recipient_key: &Jwk) -> [String; 2] {
    let general = Encryptor::new(E::A128GCM)
        .recipient(Recipient::new(alg.clone(), recipient_key).p2c(1000))
        .encrypt_json(b"m", JsonForm::General)
        .unwrap_or_else(|e| panic!("{alg}: {e}"));
    let mut v = parse(&general);
    let r = v["recipients"][0].clone();
    let mut shared = json!({
        "protected": v["protected"].take(),
        "unprotected": r["header"],
        "iv": v["iv"].take(), "ciphertext": v["ciphertext"].take(), "tag": v["tag"].take(),
    });
    if let Some(ek) = r.get("encrypted_key") {
        shared["encrypted_key"] = ek.clone();
    }
    [general, shared.to_string()]
}

#[test]
fn non_direct_modes_with_an_unprotected_alg_still_decrypt() {
    // RFC 7516 §7.2.1, RFC 7520 §5.11/§5.12, RFC 7516 A.4/A.5: the rule is
    // for the direct modes only (ADR 0050 §1).
    let oct16 = audit_key();
    let password = jwk(r#"{"kty":"oct","k":"cGFzc3dvcmQtZm9yLWYwNg"}"#);
    let ec = generate(KeySpec::Ec(EcCurve::P256)).unwrap_or_else(|e| panic!("{e}"));
    for (alg, decrypt_key, encrypt_key) in [
        (A::A128KW, &oct16, oct16.clone()),
        (A::A128GCMKW, &oct16, oct16.clone()),
        (A::Pbes2Hs256A128KW, &password, password.clone()),
        (A::EcdhEsA128KW, &ec, public(&ec)),
    ] {
        let p = policy(&[alg.clone(), A::Dir, A::EcdhEs], &[E::A128GCM]);
        for token in general_and_shared(&alg, &encrypt_key) {
            let d = decrypt_json(&token, decrypt_key, &p).unwrap_or_else(|e| panic!("{alg}: {e}"));
            assert_eq!(d.plaintext(), b"m", "{alg}");
        }
    }
}

#[test]
fn polyjose_protects_a_direct_alg_in_every_serialization() {
    // ADR 0050 §1: "polyjose's encryptor already places alg and enc in the
    // protected header". For the direct modes that holds in the general
    // form too: they have exactly one recipient (RFC 7516 §5.1 steps 5–6),
    // so `alg` and its parameters (`epk`, `apu`, `apv`, RFC 7518 §4.6.1)
    // go in the protected header and `recipients[0]` is empty (§7.2.1:
    // `header` and `encrypted_key` are both optional). The output decrypts.
    let oct = audit_key();
    let ec = generate(KeySpec::Ec(EcCurve::P256)).unwrap_or_else(|e| panic!("{e}"));
    let okp = generate(KeySpec::Okp(OkpCurve::X25519)).unwrap_or_else(|e| panic!("{e}"));
    for (alg, decrypt_key, encrypt_key) in [
        (A::Dir, &oct, oct.clone()),
        (A::EcdhEs, &ec, public(&ec)),
        (A::EcdhEs, &okp, public(&okp)),
    ] {
        let general = Encryptor::new(E::A128GCM)
            .recipient(Recipient::new(alg.clone(), &encrypt_key).apu(b"a".to_vec()))
            .encrypt_json(b"m", JsonForm::General)
            .unwrap_or_else(|e| panic!("{alg}: {e}"));
        let v = parse(&general);
        let protected: Value = serde_json::from_slice(&bytes(&text(&v, "protected")))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(protected["alg"], alg.as_str(), "{alg}");
        assert_eq!(protected["enc"], "A128GCM", "{alg}");
        if alg == A::EcdhEs {
            assert_eq!(protected["apu"], "YQ", "{alg}");
            assert!(protected["epk"].is_object(), "{alg}");
        }
        assert_eq!(v["recipients"], json!([{}]), "{alg}");
        let p = policy(std::slice::from_ref(&alg), &[E::A128GCM]);
        let d = decrypt_json(&general, decrypt_key, &p).unwrap_or_else(|e| panic!("{alg}: {e}"));
        assert_eq!(d.plaintext(), b"m", "{alg}");
    }
}
