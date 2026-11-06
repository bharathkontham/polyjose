//! Adversarial bypass attempts against the ADR 0050 §1 direct-mode rule
//! (0003 F06, tester). Every forgery that could decrypt if the rule were
//! missing is a **live** AES-128-GCM ciphertext made with an independent
//! implementation over the AAD its layout implies (RFC 7516 §5.1 step 14),
//! so an `InvalidHeader` is the header rule, never a failed tag.
#![allow(clippy::panic)] // test code: a panic is a failed assertion

use aes_gcm::aead::consts::U12;
use aes_gcm::{AeadInOut, Aes128Gcm, KeyInit, Nonce};
use polyjose::jwa::{ContentEncAlg, KeyMgmtAlg};
use polyjose::jwe::{DecryptPolicy, Encryptor, Recipient, decrypt_compact, decrypt_json};
use polyjose::jwk::{EcCurve, Jwk, OkpCurve};
use polyjose::keys::{KeySpec, generate};
use polyjose::util::{b64url_decode, b64url_encode};
use serde_json::{Value, json};

use ContentEncAlg as E;
use KeyMgmtAlg as A;

const KEY: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
const IV: [u8; 12] = [7; 12];

fn oct() -> Jwk {
    Jwk::from_json(br#"{"kty":"oct","k":"AAECAwQFBgcICQoLDA0ODw"}"#)
        .unwrap_or_else(|e| panic!("{e}"))
}

fn policy(algs: &[KeyMgmtAlg]) -> DecryptPolicy {
    DecryptPolicy::new(algs, &[E::A128GCM]).unwrap_or_else(|e| panic!("{e}"))
}

fn b64(v: &Value) -> String {
    b64url_encode(v.to_string().as_bytes())
}

/// A live `dir` + A128GCM ciphertext under [`KEY`] with the given AAD.
fn live(aad: &[u8], plaintext: &[u8]) -> (String, String) {
    let cipher = Aes128Gcm::new_from_slice(&KEY).unwrap_or_else(|e| panic!("{e}"));
    let nonce = Nonce::<U12>::try_from(&IV[..]).unwrap_or_else(|e| panic!("{e}"));
    let mut buf = plaintext.to_vec();
    let tag = cipher
        .encrypt_inout_detached(&nonce, aad, buf.as_mut_slice().into())
        .unwrap_or_else(|e| panic!("{e}"));
    (b64url_encode(&buf), b64url_encode(&tag))
}

fn code(token: &Value, key: &Jwk, p: &DecryptPolicy) -> &'static str {
    match decrypt_json(&token.to_string(), key, p) {
        Ok(_) => "ok",
        Err(e) => e.code(),
    }
}

/// Token with `protected` (may be absent), `unprotected`, `header`,
/// live-sealed over the AAD the layout implies.
fn dir_token(protected: Option<&Value>, shared: Option<Value>, per: Option<Value>) -> Value {
    let p64 = protected.map(b64);
    let aad = p64.clone().unwrap_or_default();
    let (ct, tag) = live(aad.as_bytes(), b"secret");
    let mut t = json!({"iv": b64url_encode(&IV), "ciphertext": ct, "tag": tag});
    if let Some(p) = p64 {
        t["protected"] = p.into();
    }
    if let Some(s) = shared {
        t["unprotected"] = s;
    }
    if let Some(h) = per {
        t["header"] = h;
    }
    t
}

#[test]
fn control_a_fully_protected_dir_token_decrypts() {
    let t = dir_token(Some(&json!({"alg":"dir","enc":"A128GCM"})), None, None);
    assert_eq!(code(&t, &oct(), &policy(&[A::Dir])), "ok");
}

#[test]
fn split_protected_and_unprotected_alg_enc_are_invalid_header_both_ways() {
    let k = oct();
    let p = policy(&[A::Dir]);
    let cases = [
        (
            "alg protected, enc shared",
            dir_token(
                Some(&json!({"alg":"dir"})),
                Some(json!({"enc":"A128GCM"})),
                None,
            ),
        ),
        (
            "enc protected, alg shared",
            dir_token(
                Some(&json!({"enc":"A128GCM"})),
                Some(json!({"alg":"dir"})),
                None,
            ),
        ),
        (
            "alg protected, enc per-recipient",
            dir_token(
                Some(&json!({"alg":"dir"})),
                None,
                Some(json!({"enc":"A128GCM"})),
            ),
        ),
        (
            "enc protected, alg per-recipient",
            dir_token(
                Some(&json!({"enc":"A128GCM"})),
                None,
                Some(json!({"alg":"dir"})),
            ),
        ),
        (
            "empty-AAD forgery shape",
            dir_token(None, Some(json!({"alg":"dir","enc":"A128GCM"})), None),
        ),
    ];
    for (name, t) in cases {
        assert_eq!(code(&t, &k, &p), "InvalidHeader", "{name}");
    }
}

#[test]
fn duplicate_alg_or_enc_across_headers_is_invalid_header_from_disjointness() {
    // These would decrypt (the protected header carries alg+enc and the AAD
    // is right) if the duplicate were tolerated; RFC 7516 §7.2.1 says the
    // header parameter names must be disjoint.
    let k = oct();
    let p = policy(&[A::Dir]);
    let prot = json!({"alg":"dir","enc":"A128GCM"});
    for (name, shared, per) in [
        ("alg in shared", Some(json!({"alg":"dir"})), None),
        ("alg in per-recipient", None, Some(json!({"alg":"dir"}))),
        ("enc in shared", Some(json!({"enc":"A128GCM"})), None),
        ("enc in per-recipient", None, Some(json!({"enc":"A128GCM"}))),
        (
            "alg shared with a different value",
            Some(json!({"alg":"A128GCMKW"})),
            None,
        ),
    ] {
        let t = dir_token(Some(&prot), shared, per);
        assert_eq!(code(&t, &k, &p), "InvalidHeader", "{name}");
        let wide = policy(&[A::Dir, A::A128GCMKW]);
        assert_eq!(code(&t, &k, &wide), "InvalidHeader", "{name} (wide policy)");
    }
}

#[test]
fn case_and_whitespace_variants_of_dir_never_decrypt() {
    let k = oct();
    let wide = policy(&[A::Dir, A::A128GCMKW, A::A128KW, A::EcdhEs]);
    for variant in [
        "Dir",
        "DIR",
        " dir",
        "dir ",
        "dir\n",
        "d\u{130}r",
        "dir\u{0}",
        "",
    ] {
        // unprotected variant with a protected enc, and fully protected.
        let unprot = dir_token(
            Some(&json!({"enc":"A128GCM"})),
            Some(json!({"alg": variant})),
            None,
        );
        let full = dir_token(Some(&json!({"alg": variant, "enc":"A128GCM"})), None, None);
        let none = dir_token(None, Some(json!({"alg": variant, "enc":"A128GCM"})), None);
        for (n, t) in [("unprot", unprot), ("full", full), ("none", none)] {
            let c = code(&t, &k, &wide);
            assert_ne!(c, "ok", "{variant:?} {n}");
        }
    }
}

#[test]
fn a_two_recipient_general_json_with_one_dir_never_decrypts_via_the_unprotected_dir() {
    let k = oct();
    let wide = policy(&[A::Dir, A::A128GCMKW, A::A128KW]);
    let (ct, tag) = live(b"", b"secret");
    // dir unprotected beside an A128KW recipient, empty AAD (live).
    let t = json!({
        "unprotected": {"enc": "A128GCM"},
        "recipients": [
            {"header": {"alg": "dir"}},
            {"header": {"alg": "A128KW"}, "encrypted_key": b64url_encode(&[0u8; 24])},
        ],
        "iv": b64url_encode(&IV), "ciphertext": ct, "tag": tag,
    });
    assert_eq!(code(&t, &k, &wide), "InvalidHeader");
    // dir protected for both recipients, second carries an encrypted key.
    let prot = json!({"alg":"dir","enc":"A128GCM"});
    let p64 = b64(&prot);
    let (ct2, tag2) = live(p64.as_bytes(), b"secret");
    let t2 = json!({
        "protected": p64,
        "recipients": [{}, {"encrypted_key": b64url_encode(&[0u8; 24])}],
        "iv": b64url_encode(&IV), "ciphertext": ct2, "tag": tag2,
    });
    // Protected alg dir applies to every recipient; the content is the
    // sender's own message under the shared key, so this is not a leak. The
    // outcome is recorded: it must not be an error other than the uniform
    // one, and never a panic.
    let c = code(&t2, &k, &wide);
    assert!(
        c == "ok" || c == "DecryptionFailed" || c == "InvalidFormat",
        "{c}"
    );
}

#[test]
fn ecdh_es_alg_per_recipient_or_shared_is_invalid_header_on_every_curve() {
    let specs = [
        ("P-256", KeySpec::Ec(EcCurve::P256)),
        ("P-384", KeySpec::Ec(EcCurve::P384)),
        ("P-521", KeySpec::Ec(EcCurve::P521)),
        ("X25519", KeySpec::Okp(OkpCurve::X25519)),
    ];
    let p = policy(&[A::EcdhEs]);
    for (name, spec) in specs {
        let key = generate(spec).unwrap_or_else(|e| panic!("{name}: {e}"));
        let public = key.to_public().unwrap_or_else(|| panic!("{name}: public"));
        let compact = Encryptor::new(E::A128GCM)
            .recipient(Recipient::new(A::EcdhEs, &public))
            .encrypt_compact(b"m")
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(
            decrypt_compact(&compact, &key, &p).is_ok(),
            "{name} control"
        );
        let seg: Vec<&str> = compact.split('.').collect();
        let h: Value =
            serde_json::from_slice(&b64url_decode(seg[0]).unwrap_or_else(|e| panic!("{e}")))
                .unwrap_or_else(|e| panic!("{e}"));
        let enc_only = json!({"enc": h["enc"]});
        let alg_epk = json!({"alg": h["alg"], "epk": h["epk"]});
        for (place, tok) in [
            (
                "recipients[].header",
                json!({"protected": b64(&enc_only), "recipients":[{"header": alg_epk}],
                       "iv": seg[2], "ciphertext": seg[3], "tag": seg[4]}),
            ),
            (
                "shared",
                json!({"protected": b64(&enc_only), "unprotected": alg_epk,
                       "iv": seg[2], "ciphertext": seg[3], "tag": seg[4]}),
            ),
            (
                "alg only per-recipient, epk protected",
                json!({"protected": b64(&json!({"enc": h["enc"], "epk": h["epk"]})),
                       "recipients":[{"header": {"alg": "ECDH-ES"}}],
                       "iv": seg[2], "ciphertext": seg[3], "tag": seg[4]}),
            ),
        ] {
            assert_eq!(code(&tok, &key, &p), "InvalidHeader", "{name}: {place}");
        }
    }
}

#[test]
fn ecdh_es_a128kw_relabelled_as_ecdh_es_and_back_never_decrypts() {
    let key = generate(KeySpec::Ec(EcCurve::P256)).unwrap_or_else(|e| panic!("{e}"));
    let public = key.to_public().unwrap_or_else(|| panic!("public"));
    let wide = policy(&[A::EcdhEs, A::EcdhEsA128KW]);
    let kw = Encryptor::new(E::A128GCM)
        .recipient(Recipient::new(A::EcdhEsA128KW, &public))
        .encrypt_compact(b"m")
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(decrypt_compact(&kw, &key, &wide).is_ok());
    let seg: Vec<&str> = kw.split('.').collect();
    let mut h: Value =
        serde_json::from_slice(&b64url_decode(seg[0]).unwrap_or_else(|e| panic!("{e}")))
            .unwrap_or_else(|e| panic!("{e}"));
    h["alg"] = "ECDH-ES".into();
    let relabelled_compact = format!("{}.{}.{}.{}.{}", b64(&h), seg[1], seg[2], seg[3], seg[4]);
    assert!(decrypt_compact(&relabelled_compact, &key, &wide).is_err());
    // Same, dropping the encrypted key (a "direct" shape), compact and JSON.
    let direct_shape = format!("{}..{}.{}.{}", b64(&h), seg[2], seg[3], seg[4]);
    assert!(decrypt_compact(&direct_shape, &key, &wide).is_err());
    let flat = json!({"protected": b64(&h), "iv": seg[2], "ciphertext": seg[3], "tag": seg[4]});
    assert_ne!(code(&flat, &key, &wide), "ok");
    // The reverse: a direct ECDH-ES token relabelled as ECDH-ES+A128KW.
    let direct = Encryptor::new(E::A128GCM)
        .recipient(Recipient::new(A::EcdhEs, &public))
        .encrypt_compact(b"m")
        .unwrap_or_else(|e| panic!("{e}"));
    let s: Vec<&str> = direct.split('.').collect();
    let mut dh: Value =
        serde_json::from_slice(&b64url_decode(s[0]).unwrap_or_else(|e| panic!("{e}")))
            .unwrap_or_else(|e| panic!("{e}"));
    dh["alg"] = "ECDH-ES+A128KW".into();
    let rev = format!("{}.{}.{}.{}.{}", b64(&dh), s[1], s[2], s[3], s[4]);
    assert!(decrypt_compact(&rev, &key, &wide).is_err());
}

#[test]
fn aes_kw_and_pbes2_wrapped_keys_relabelled_as_dir_never_decrypt() {
    let k = oct();
    let wide = policy(&[A::Dir, A::A128KW, A::Pbes2Hs256A128KW]);
    for alg in [A::A128KW, A::Pbes2Hs256A128KW] {
        let compact = Encryptor::new(E::A128GCM)
            .recipient(Recipient::new(alg.clone(), &k).p2c(1000))
            .encrypt_compact(b"m")
            .unwrap_or_else(|e| panic!("{alg}: {e}"));
        let seg: Vec<&str> = compact.split('.').collect();
        // as dir with everything unprotected, empty AAD
        let unprot = json!({"unprotected": {"alg":"dir","enc":"A128GCM"},
            "iv": seg[2], "ciphertext": seg[1], "tag": seg[4]});
        assert_eq!(code(&unprot, &k, &wide), "InvalidHeader", "{alg}");
        // as dir with the wrapped key as ciphertext under a protected header
        let prot = b64(&json!({"alg":"dir","enc":"A128GCM"}));
        let protected = json!({"protected": prot,
            "iv": seg[2], "ciphertext": seg[1], "tag": seg[4]});
        assert_ne!(code(&protected, &k, &wide), "ok", "{alg}");
        // compact dir shape
        let c = format!("{prot}..{}.{}.{}", seg[2], seg[1], seg[4]);
        assert!(decrypt_compact(&c, &k, &wide).is_err(), "{alg}");
    }
}

#[test]
fn empty_protected_string_with_aad_and_the_reverse_never_decrypt() {
    let k = oct();
    let wide = policy(&[A::Dir, A::A128GCMKW]);
    let shared = json!({"alg":"dir","enc":"A128GCM"});
    for (name, aad_bytes, protected, aad_field) in [
        (
            "empty protected, non-empty aad",
            b".c2VjcmV0".to_vec(),
            Some(""),
            Some("c2VjcmV0"),
        ),
        (
            "empty protected, empty aad",
            b".".to_vec(),
            Some(""),
            Some(""),
        ),
        ("empty protected, no aad", Vec::new(), Some(""), None),
        (
            "no protected, non-empty aad",
            b".c2VjcmV0".to_vec(),
            None,
            Some("c2VjcmV0"),
        ),
        ("no protected, empty aad", b".".to_vec(), None, Some("")),
    ] {
        for aad_try in [aad_bytes.clone(), Vec::new()] {
            let (ct, tag) = live(&aad_try, b"secret");
            let mut t = json!({"unprotected": shared, "iv": b64url_encode(&IV),
                "ciphertext": ct, "tag": tag});
            if let Some(p) = protected {
                t["protected"] = p.into();
            }
            if let Some(a) = aad_field {
                t["aad"] = a.into();
            }
            // Whatever the parser does with these shapes, the unprotected
            // dir is refused or the message fails; it never decrypts.
            assert_ne!(code(&t, &k, &wide), "ok", "{name}");
        }
    }
    // Non-empty protected (alg and enc) with a non-empty aad: the AAD is
    // "<protected>.<aad>" (RFC 7516 §5.1 step 14), a legit token only if
    // sealed so; sealed over the bare protected header it fails.
    let prot = b64(&shared);
    let (ct, tag) = live(format!("{prot}.c2VjcmV0").as_bytes(), b"secret");
    let t = json!({"protected": prot, "aad": "c2VjcmV0", "iv": b64url_encode(&IV), "ciphertext": ct, "tag": tag});
    assert_eq!(code(&t, &k, &wide), "ok");
    let (ct, tag) = live(prot.as_bytes(), b"secret");
    let t = json!({"protected": prot, "aad": "c2VjcmV0", "iv": b64url_encode(&IV), "ciphertext": ct, "tag": tag});
    assert_eq!(code(&t, &k, &wide), "DecryptionFailed");
    // An empty "aad" member is refused as malformed (InvalidFormat), so the
    // "<protected>." AAD shape cannot be reached.
    let t = json!({"protected": prot, "aad": "", "iv": b64url_encode(&IV), "ciphertext": ct, "tag": tag});
    assert_eq!(code(&t, &k, &wide), "InvalidFormat");
}

#[test]
fn the_audit_forgery_in_compact_clothing_is_not_the_victim_cek() {
    // decrypt_compact cannot express an unprotected alg: a compact header is
    // always protected, so its (non-empty) encoded form is the AAD and the
    // empty-AAD key-wrap tag cannot verify (DecryptionFailed, not a leak).
    let k = oct();
    let h = b64(&json!({"alg":"dir","enc":"A128GCM"}));
    let c = format!("{h}..O7z64SOn4nzSXqYX.MnP1M2KMxJATaL2fiHopzA.1iuYCU-NaRWTNmU0AQpqYg");
    let err = decrypt_compact(&c, &k, &policy(&[A::A128GCMKW, A::Dir])).map(|_| ());
    assert_eq!(err.map_err(|e| e.code()), Err("DecryptionFailed"));
}
