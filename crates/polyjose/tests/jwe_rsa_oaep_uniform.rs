//! RFC 7516 §11.5 for RSA-OAEP-256 in the JSON and multi-recipient
//! serializations (ADR 0067 §5): a failed CEK unwrap and a failed tag
//! give the same error, with the same code and `Debug`, as every other
//! decryption failure. The compact case is in `jwe_rsa_oaep.rs`.

#![allow(clippy::unwrap_used)] // test code: a panic is a failed assertion

use std::path::PathBuf;

use polyjose::jwa::{ContentEncAlg, KeyMgmtAlg};
use polyjose::jwe::{DecryptPolicy, Encryptor, JsonForm, Recipient, decrypt_json};
use polyjose::jwk::Jwk;
use polyjose::util::{b64url_decode, b64url_encode};

fn private() -> Jwk {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/vectors/jwe/rsa-oaep-256/keys/rsa-2048.private.jwk");
    Jwk::from_json(&std::fs::read(p).unwrap()).unwrap()
}

fn policy() -> DecryptPolicy {
    DecryptPolicy::new(
        &[KeyMgmtAlg::RsaOaep256, KeyMgmtAlg::A128KW],
        &[ContentEncAlg::A128GCM, ContentEncAlg::A256CbcHs512],
    )
    .unwrap()
}

/// `json` with the base64url value of every `"<name>":"..."` flipped in its first octet.
fn flip_all(json: &str, name: &str) -> String {
    let needle = format!("\"{name}\":\"");
    let mut out = String::new();
    let mut rest = json;
    while let Some(i) = rest.find(&needle) {
        let start = i + needle.len();
        out.push_str(&rest[..start]);
        let end = start + rest[start..].find('"').unwrap();
        let mut v = b64url_decode(&rest[start..end]).unwrap();
        v[0] ^= 0x80;
        out.push_str(&b64url_encode(&v));
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

fn outcome(json: &str, key: &Jwk) -> (&'static str, String) {
    let e = decrypt_json(json, key, &policy()).unwrap_err();
    (e.code(), format!("{e:?} / {e}"))
}

#[test]
fn bad_encrypted_key_and_bad_tag_are_one_error_in_json_and_multi_recipient() {
    let key = private();
    let public = key.to_public().unwrap();
    let oct = Jwk::from_json(br#"{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}"#).unwrap();
    for enc in [ContentEncAlg::A128GCM, ContentEncAlg::A256CbcHs512] {
        let flattened = Encryptor::new(enc.clone())
            .recipient(Recipient::new(KeyMgmtAlg::RsaOaep256, &public))
            .encrypt_json(b"section 11.5", JsonForm::Flattened)
            .unwrap();
        let general = Encryptor::new(enc.clone())
            .recipient(Recipient::new(KeyMgmtAlg::RsaOaep256, &public))
            .encrypt_json(b"section 11.5", JsonForm::General)
            .unwrap();
        let general_multi = if enc == ContentEncAlg::A128GCM {
            Some(
                Encryptor::new(enc.clone())
                    .recipient(Recipient::new(KeyMgmtAlg::A128KW, &oct))
                    .recipient(Recipient::new(KeyMgmtAlg::RsaOaep256, &public))
                    .encrypt_json(b"section 11.5", JsonForm::General)
                    .unwrap(),
            )
        } else {
            None
        };
        let mut forms = vec![flattened, general];
        forms.extend(general_multi.clone());
        for jwe in forms {
            assert!(decrypt_json(&jwe, &key, &policy()).is_ok(), "{enc}");
            let bad_ek = outcome(&flip_all(&jwe, "encrypted_key"), &key);
            let bad_tag = outcome(&flip_all(&jwe, "tag"), &key);
            assert_eq!(bad_ek.0, "DecryptionFailed", "{enc}");
            assert_eq!(bad_ek, bad_tag, "{enc}: same code, Debug and Display");
        }
    }
}
