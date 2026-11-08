#![no_main]
//! DER and PEM key import (RFC 5958, RFC 5280 §4.1, RFC 5915, RFC 8017
//! App. A.1.1, RFC 8410, RFC 7468; ADR 0018): `Jwk::from_der` for every
//! `KeyFormat` and `Jwk::from_pem`.
//!
//! Input: one selector byte (0–3: DER in Pkcs8, Sec1, Spki, Pkcs1; 4: PEM),
//! then the DER bytes or the PEM text.
//!
//! - Ok ⇒ never an `oct` key, never a JWK `alg` (DER carries none).
//! - Ok ⇒ every export that succeeds re-imports to the same key, for DER
//!   and for PEM: the whole key from PKCS #8 and SEC1, its public part from
//!   SPKI and PKCS #1, which carry no private key (RFC 5280 §4.1.2.7,
//!   RFC 8017 App. A.1.1).
use libfuzzer_sys::fuzz_target;
use polyjose::jwk::{Jwk, KeyMaterial};
use polyjose::keys::KeyFormat;
use polyjose_fuzz::check_err;

const FORMATS: [KeyFormat; 4] = [
    KeyFormat::Pkcs8,
    KeyFormat::Sec1,
    KeyFormat::Spki,
    KeyFormat::Pkcs1,
];

fn check_imported(jwk: &Jwk) {
    assert!(
        !matches!(jwk.material(), KeyMaterial::Oct(_)),
        "oct key from DER/PEM"
    );
    assert!(jwk.alg().is_none(), "DER/PEM import set a JWK alg");
    let whole = jwk.to_json();
    let public = jwk.to_public().map(|p| p.to_json());
    for f in FORMATS {
        let json = match (f, &public) {
            (KeyFormat::Spki | KeyFormat::Pkcs1, Some(p)) => p,
            _ => &whole,
        };
        match jwk.to_der(f) {
            Ok(der) => match Jwk::from_der(&der, f) {
                Ok(back) => assert!(
                    *back.to_json() == **json,
                    "DER {f:?} round trip changed the key"
                ),
                Err(e) => panic!("exported DER {f:?} does not re-import: {}", e.code()),
            },
            Err(e) => check_err(&e),
        }
        match jwk.to_pem(f) {
            Ok(pem) => match Jwk::from_pem(&pem) {
                Ok(back) => assert!(
                    *back.to_json() == **json,
                    "PEM {f:?} round trip changed the key"
                ),
                Err(e) => panic!("exported PEM {f:?} does not re-import: {}", e.code()),
            },
            Err(e) => check_err(&e),
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let imported = match sel % 5 {
        4 => match core::str::from_utf8(rest) {
            Ok(text) => Jwk::from_pem(text),
            Err(_) => return,
        },
        i => Jwk::from_der(rest, FORMATS[usize::from(i)]),
    };
    match imported {
        Ok(jwk) => check_imported(&jwk),
        Err(e) => check_err(&e),
    }
});
