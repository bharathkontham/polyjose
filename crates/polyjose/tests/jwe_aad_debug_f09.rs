//! F09 tester: the JWE AAD (RFC 7516 §7.2.1 `aad`) never appears in `Debug`
//! of `Encryptor` or `Decrypted` (ADR 0050 §4, ADR 0030 §7), for printable,
//! long and binary AADs, in text, base64url, hex and decimal-list forms.
#![allow(clippy::panic)] // test code: a panic is a failed assertion

use polyjose::jwa::{ContentEncAlg as E, KeyMgmtAlg as A};
use polyjose::jwe::{DecryptPolicy, Encryptor, JsonForm, Recipient, decrypt_json};
use polyjose::jwk::Jwk;
use polyjose::util::b64url_encode;

fn oct(bytes: &[u8]) -> Jwk {
    Jwk::from_json(format!(r#"{{"kty":"oct","k":"{}"}}"#, b64url_encode(bytes)).as_bytes())
        .unwrap_or_else(|e| panic!("{e}"))
}

fn squash(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn needles(aad: &[u8]) -> Vec<String> {
    let mut n = vec![
        b64url_encode(aad),
        hex(aad),
        hex(aad).to_uppercase(),
        squash(&format!("{aad:?}")),
        squash(&format!("{:?}", aad.to_vec())),
    ];
    if let Ok(s) = std::str::from_utf8(aad) {
        n.push(s.to_owned());
    }
    n
}

fn aads() -> Vec<Vec<u8>> {
    vec![
        b"secret-token-4f9a1c".to_vec(),
        (0..=255u8).collect(),
        (0..4096u32).map(|i| (i * 31 % 251) as u8 ^ 0x5a).collect(),
        vec![0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce],
        b"Zq7Xk!p@9".repeat(200),
    ]
}

#[derive(Debug)]
#[allow(dead_code)]
struct Nest<'a> {
    e: &'a Encryptor,
    o: Option<&'a Encryptor>,
}

#[test]
fn encryptor_debug_never_leaks_aad() {
    let key = oct(&[9; 16]);
    for aad in aads() {
        let e = Encryptor::new(E::A128GCM)
            .aad(aad.clone())
            .recipient(Recipient::new(A::A128KW, &key));
        let nest = Nest { e: &e, o: Some(&e) };
        for dump in [
            format!("{e:?}"),
            format!("{e:#?}"),
            format!("{nest:?}"),
            format!("{nest:#?}"),
        ] {
            let sq = squash(&dump);
            for n in needles(&aad) {
                assert!(
                    n.len() < 4 || !sq.contains(&n),
                    "leak {n:.40} in {dump:.200}"
                );
            }
            assert!(
                dump.contains(&format!("<redacted, len={}>", aad.len())),
                "{dump:.200}"
            );
        }
    }
}

#[test]
fn decrypted_aad_round_trips_and_debug_clean() {
    let key = oct(&[9; 16]);
    let pol = DecryptPolicy::new(&[A::A128KW], &[E::A128GCM]).unwrap_or_else(|e| panic!("{e}"));
    for aad in aads() {
        let tok = Encryptor::new(E::A128GCM)
            .aad(aad.clone())
            .recipient(Recipient::new(A::A128KW, &key))
            .encrypt_json(b"pt", JsonForm::General)
            .unwrap_or_else(|e| panic!("{e}"));
        let d = decrypt_json(&tok, &key, &pol).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(d.aad(), Some(aad.as_slice()));
        for dump in [format!("{d:?}"), format!("{d:#?}")] {
            let sq = squash(&dump);
            for n in needles(&aad) {
                assert!(n.len() < 4 || !sq.contains(&n), "leak {n:.40}");
            }
        }
    }
}
