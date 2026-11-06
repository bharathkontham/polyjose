//! Extra `epk` kty/crv shapes against every recipient family (F11 tester,
//! RFC 7518 §4.6, RFC 8725 §3.4, ADR 0007): each is `DecryptionFailed`,
//! never another code, never a panic. JSON-escaped names are parsed strings,
//! as in `Jwk::from_json`.
#![allow(clippy::panic)] // test code: a panic is a failed assertion

use polyjose::Error;
use polyjose::jwa::{ContentEncAlg, KeyMgmtAlg};
use polyjose::jwe::{DecryptPolicy, decrypt_compact};
use polyjose::jwk::{EcCurve, Jwk, OkpCurve};
use polyjose::keys::{KeySpec, generate};
use polyjose::util::b64url_encode;

const ALGS: [KeyMgmtAlg; 4] = [
    KeyMgmtAlg::EcdhEs,
    KeyMgmtAlg::EcdhEsA128KW,
    KeyMgmtAlg::EcdhEsA192KW,
    KeyMgmtAlg::EcdhEsA256KW,
];

fn forge(header_json: &str, encrypted_key: &[u8]) -> String {
    [
        b64url_encode(header_json.as_bytes()),
        b64url_encode(encrypted_key),
        b64url_encode(&[0x11; 12]),
        b64url_encode(b"ciphertext"),
        b64url_encode(&[0x22; 16]),
    ]
    .join(".")
}

const X: &str = "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0";
const Y: &str = "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFppo";

#[test]
fn odd_kty_crv_shapes_are_decryption_failed_for_every_recipient() {
    let keys: Vec<Jwk> = vec![
        generate(KeySpec::Ec(EcCurve::P256)).unwrap_or_else(|e| panic!("{e}")),
        generate(KeySpec::Ec(EcCurve::P384)).unwrap_or_else(|e| panic!("{e}")),
        generate(KeySpec::Ec(EcCurve::P521)).unwrap_or_else(|e| panic!("{e}")),
        generate(KeySpec::Okp(OkpCurve::X25519)).unwrap_or_else(|e| panic!("{e}")),
    ];
    let epks = [
        // escapes (parsed strings), each family
        format!(r#"{{"kty":"EC","crv":"P-256","x":"{X}","y":"{Y}"}}"#),
        format!(r#"{{"kty":"EC","crv":"P-384","x":"{X}","y":"{Y}"}}"#),
        format!(r#"{{"kty":"EC","crv":"P-521","x":"{X}","y":"{Y}"}}"#),
        format!(r#"{{"kty":"OKP","crv":"X25519","x":"{X}"}}"#),
        format!(r#"{{"kty":"OKP","crv":"X225519","x":"{X}"}}"#),
        // case variants
        format!(r#"{{"kty":"EC","crv":"p-256","x":"{X}","y":"{Y}"}}"#),
        format!(r#"{{"kty":"ec","crv":"P-256","x":"{X}","y":"{Y}"}}"#),
        format!(r#"{{"kty":"okp","crv":"x25519","x":"{X}"}}"#),
        format!(r#"{{"kty":"OKP","crv":"X25519 ","x":"{X}"}}"#),
        // non-string / missing / null / duplicate
        format!(r#"{{"kty":"EC","crv":null,"x":"{X}","y":"{Y}"}}"#),
        format!(r#"{{"kty":"EC","crv":["P-256"],"x":"{X}","y":"{Y}"}}"#),
        format!(r#"{{"kty":"EC","crv":{{"a":1}},"x":"{X}","y":"{Y}"}}"#),
        format!(r#"{{"kty":"EC","crv":true,"x":"{X}","y":"{Y}"}}"#),
        format!(r#"{{"kty":"EC","crv":1.5e300,"x":"{X}","y":"{Y}"}}"#),
        format!(r#"{{"kty":1,"crv":"P-256","x":"{X}","y":"{Y}"}}"#),
        format!(r#"{{"crv":"P-256","x":"{X}","y":"{Y}"}}"#),
        format!(r#"{{"kty":"EC","x":"{X}","y":"{Y}"}}"#),
        format!(r#"{{"kty":"oct","k":"{X}"}}"#),
        format!(r#"{{"kty":"oct","crv":"P-256","k":"{X}"}}"#),
        format!(r#"{{"kty":"RSA","n":"{X}","e":"AQAB"}}"#),
        // X25519 epk to EC recipients and EC epk to X25519
        format!(r#"{{"kty":"OKP","crv":"X25519","x":"{X}"}}"#),
        format!(r#"{{"kty":"OKP","crv":"X448","x":"{X}"}}"#),
        format!(r#"{{"kty":"EC","crv":"X25519","x":"{X}","y":"{Y}"}}"#),
        "{}".to_owned(),
    ];
    let policy = DecryptPolicy::new(KeyMgmtAlg::KNOWN, ContentEncAlg::KNOWN)
        .unwrap_or_else(|e| panic!("{e}"));
    for epk in &epks {
        for alg in &ALGS {
            let header = format!(r#"{{"alg":"{alg}","enc":"A128GCM","epk":{epk}}}"#);
            let ek: &[u8] = if *alg == KeyMgmtAlg::EcdhEs {
                &[]
            } else {
                &[0xA6; 24]
            };
            let token = forge(&header, ek);
            for key in &keys {
                let result = decrypt_compact(&token, key, &policy);
                assert_eq!(
                    result.map(|_| ()),
                    Err(Error::DecryptionFailed),
                    "{epk} {alg}"
                );
            }
        }
    }
}

#[test]
fn escaped_crv_parses_like_import_does() {
    // Parity: Jwk::from_json reads "P-256" as P-256, the same parsed
    // string the raw epk match compares.
    let plain = format!(r#"{{"kty":"EC","crv":"P-256","x":"{X}","y":"{Y}"}}"#);
    let escaped = format!(r#"{{"kty":"EC","crv":"P-256","x":"{X}","y":"{Y}"}}"#);
    let a = Jwk::from_json(plain.as_bytes()).map(|j| j.to_json());
    let b = Jwk::from_json(escaped.as_bytes()).map(|j| j.to_json());
    assert_eq!(a.is_ok(), b.is_ok());
    assert_eq!(a.ok(), b.ok());
}
