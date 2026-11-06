//! The RSA modulus range 2048..=8192 bits (RFC 7518 §3.3, §3.5, §4.3;
//! ADR 0007; ADR 0026 §2 step 8) is enforced at JWK import, so it holds for
//! every import path: JSON (`Jwk::from_json`), SPKI and PKCS#1 DER
//! (`Jwk::from_der`) and their PEM forms (`Jwk::from_pem`).
//!
//! The moduli are built here: odd, with the top bit set, and e = 65537. They
//! are structurally valid only (no signature verifies under them), which is
//! all import checks. The DER and PEM are written by the small encoders
//! below, and the base64 by `base64ct`, so the test does not lean on
//! polyjose's own encoders.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use polyjose::Error;
use polyjose::jwk::{Jwk, KeyMaterial};
use polyjose::keys::KeyFormat;

/// e = 65537 (F4), as DER INTEGER contents and as Base64urlUInt.
const F4: [u8; 3] = [0x01, 0x00, 0x01];

/// The detail `Jwk::from_object` gives for a modulus above 8192 bits.
const TOO_LONG: Error = Error::InvalidKey("RSA modulus is longer than 8192 bits");
/// The detail `Jwk::from_object` gives for a modulus under 2048 bits.
const TOO_SHORT: Error = Error::InvalidKey("RSA modulus is shorter than 2048 bits");

/// The largest DER input `Jwk::from_der` reads (ADR 0018 §2).
const DER_CAP: usize = 64 * 1024;

/// An odd modulus of exactly `bits` bits (top bit set), big-endian with no
/// leading zero octet.
fn modulus(bits: usize) -> Vec<u8> {
    let mut n = vec![0xA5; bits.div_ceil(8)];
    let top = (bits - 1) % 8;
    n[0] = (1 << top) | (0xA5 & ((1 << top) - 1));
    *n.last_mut().unwrap() |= 1;
    n
}

/// A DER element (X.690 §8.1): tag, definite length in the fewest octets
/// (§10.1), contents.
fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = contents.len();
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap());
    } else {
        let octets: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|&b| b == 0)
            .collect();
        out.push(0x80 | u8::try_from(octets.len()).unwrap());
        out.extend_from_slice(&octets);
    }
    out.extend_from_slice(contents);
    out
}

/// A non-negative DER INTEGER (X.690 §8.3): a 0x00 sign octet when the top
/// bit is set.
fn integer(magnitude: &[u8]) -> Vec<u8> {
    let mut contents = Vec::with_capacity(magnitude.len() + 1);
    if magnitude[0] & 0x80 != 0 {
        contents.push(0);
    }
    contents.extend_from_slice(magnitude);
    tlv(0x02, &contents)
}

/// RSAPublicKey ::= SEQUENCE { modulus, publicExponent } (RFC 8017
/// App. A.1.1).
fn pkcs1(n: &[u8]) -> Vec<u8> {
    let mut body = integer(n);
    body.extend_from_slice(&integer(&F4));
    tlv(0x30, &body)
}

/// SubjectPublicKeyInfo (RFC 5280 §4.1.2.7) with rsaEncryption and NULL
/// parameters (RFC 3279 §2.3.1).
fn spki(n: &[u8]) -> Vec<u8> {
    // 1.2.840.113549.1.1.1, then NULL.
    let mut alg = tlv(
        0x06,
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01],
    );
    alg.extend_from_slice(&[0x05, 0x00]);
    let mut bits = vec![0x00];
    bits.extend_from_slice(&pkcs1(n));
    let mut body = tlv(0x30, &alg);
    body.extend_from_slice(&tlv(0x03, &bits));
    tlv(0x30, &body)
}

/// RFC 7468 §2 strict textual encoding: 64-character lines.
fn pem(label: &str, der: &[u8]) -> String {
    let b64 = Base64::encode_string(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// An RSA public JWK (RFC 7518 §6.3.1) with modulus `n` and e = 65537.
fn json(n: &[u8]) -> String {
    format!(
        r#"{{"kty":"RSA","n":"{}","e":"{}"}}"#,
        Base64UrlUnpadded::encode_string(n),
        Base64UrlUnpadded::encode_string(&F4)
    )
}

/// Each import path, named, applied to the key with modulus `n`.
fn every_import(n: &[u8]) -> Vec<(&'static str, Result<Jwk, Error>)> {
    vec![
        ("from_json", Jwk::from_json(json(n).as_bytes())),
        ("from_der Spki", Jwk::from_der(&spki(n), KeyFormat::Spki)),
        ("from_der Pkcs1", Jwk::from_der(&pkcs1(n), KeyFormat::Pkcs1)),
        (
            "from_pem PUBLIC KEY",
            Jwk::from_pem(&pem("PUBLIC KEY", &spki(n))),
        ),
        (
            "from_pem RSA PUBLIC KEY",
            Jwk::from_pem(&pem("RSA PUBLIC KEY", &pkcs1(n))),
        ),
    ]
}

fn modulus_bits(jwk: &Jwk) -> usize {
    let KeyMaterial::Rsa(key) = jwk.material() else {
        panic!("an RSA key")
    };
    key.modulus_bits()
}

#[test]
fn the_moduli_built_here_have_the_stated_size() {
    for bits in [2047, 2048, 8192, 8193, 65536, 400_000] {
        let n = modulus(bits);
        assert_eq!(n.len(), bits.div_ceil(8), "{bits}");
        let top = 8 * n.len() - usize::try_from(n[0].leading_zeros()).unwrap();
        assert_eq!(top, bits, "{bits}");
        assert_eq!(n.last().unwrap() & 1, 1, "{bits}: odd");
    }
}

#[test]
fn every_import_accepts_2048_and_8192_bits() {
    // RFC 7518 §3.3: 2048 is the floor; 8192 the ceiling (ADR 0026 §2
    // step 8). Both ends are in range.
    for bits in [2048, 8192] {
        for (path, result) in every_import(&modulus(bits)) {
            let jwk = result.unwrap_or_else(|e| panic!("{bits} bits, {path}: {e:?}"));
            assert_eq!(modulus_bits(&jwk), bits, "{bits} bits, {path}");
        }
    }
}

#[test]
fn every_import_rejects_8193_and_65536_bits() {
    for bits in [8193, 65536] {
        for (path, result) in every_import(&modulus(bits)) {
            assert_eq!(result.err(), Some(TOO_LONG), "{bits} bits, {path}");
        }
    }
}

#[test]
fn every_import_still_rejects_2047_bits() {
    for (path, result) in every_import(&modulus(2047)) {
        assert_eq!(result.err(), Some(TOO_SHORT), "{path}");
    }
}

#[test]
fn the_upper_bound_is_checked_on_n_before_e_is_read() {
    // The JSON import decides on `n` alone: with `e` missing, an 8193-bit
    // `n` is refused for its size, not for the missing `e`. An in-range `n`
    // with `e` missing reaches the `e` check.
    let n = Base64UrlUnpadded::encode_string(&modulus(8193));
    let doc = format!(r#"{{"kty":"RSA","n":"{n}"}}"#);
    assert_eq!(Jwk::from_json(doc.as_bytes()).err(), Some(TOO_LONG));
    let n = Base64UrlUnpadded::encode_string(&modulus(8192));
    let doc = format!(r#"{{"kty":"RSA","n":"{n}"}}"#);
    assert_eq!(
        Jwk::from_json(doc.as_bytes()).err(),
        Some(Error::InvalidKey("e is missing"))
    );
}

#[test]
fn a_400000_bit_pkcs1_key_is_refused_by_the_modulus_bound_without_arithmetic() {
    // A 400,000-bit modulus is 50,000 octets, so its RSAPublicKey is under
    // the 64 KiB DER cap: the cap does not fire, the modulus bound does.
    // Work is counted, not timed: import does one pass over the PEM text,
    // one over the DER, and a length comparison on `n`; no big-integer
    // arithmetic runs on an RSA key at import (the `rsa` crate is used only
    // by the JWS and JWE code, which never sees this key).
    let n = modulus(400_000);
    let der = pkcs1(&n);
    assert!(der.len() < DER_CAP, "{} octets", der.len());
    assert_eq!(
        Jwk::from_pem(&pem("RSA PUBLIC KEY", &der)).err(),
        Some(TOO_LONG)
    );
    assert_eq!(Jwk::from_der(&der, KeyFormat::Pkcs1).err(), Some(TOO_LONG));
    assert_eq!(Jwk::from_json(json(&n).as_bytes()).err(), Some(TOO_LONG));
}

#[test]
fn a_pkcs1_key_over_the_der_cap_is_refused_by_the_cap() {
    // 600,000 bits is 75,000 octets: over 64 KiB, so the DER reader refuses
    // the input before it reads any element. The result is InvalidKey
    // either way.
    let der = pkcs1(&modulus(600_000));
    assert!(der.len() > DER_CAP, "{} octets", der.len());
    let refused = Some(Error::InvalidKey("DER input too large"));
    assert_eq!(Jwk::from_pem(&pem("RSA PUBLIC KEY", &der)).err(), refused);
    assert_eq!(Jwk::from_der(&der, KeyFormat::Pkcs1).err(), refused);
}
