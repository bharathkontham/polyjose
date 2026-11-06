//! The RSA modulus range of RSA-OAEP-256 (RFC 7518 §4.3: "A key of size
//! 2048 bits or larger MUST be used with these algorithms"; at most 8192
//! bits, the `rsa` crate's maximum, ADR 0026 §2 step 8) is enforced by JWK
//! import, on every path a JWE recipient key can come from (0003 F04).
//!
//! JWE has no bound of its own: `jwe::Recipient` takes a [`Jwk`], so a key
//! import refuses never reaches it. These tests are the proof that import
//! refuses both ends on every path:
//!
//! - JSON: `Jwk::from_json` and `Jwk::from_object` (RFC 7518 §6.3.1);
//! - PEM, through the keys facade's `Jwk::from_pem`: SPKI `PUBLIC KEY`
//!   (RFC 7468 §13) and PKCS#1 `RSA PUBLIC KEY` (RFC 8017 App. A.1.1);
//! - DER: `Jwk::from_der` with `KeyFormat::Spki` and `KeyFormat::Pkcs1`.
//!
//! The keys are real RSA public keys from OpenSSL and Node's built-in
//! crypto (`tests/data/jwe/rsa-bound/regen.sh`), never polyjose output; no
//! private key is committed (ADR 0021). Their sizes are checked here
//! independently of polyjose, from the JWK's `n` decoded with `base64ct`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

use std::path::PathBuf;

use base64ct::{Base64UrlUnpadded, Encoding};
use polyjose::Error;
use polyjose::json::{self, Value};
use polyjose::jwk::{Jwk, KeyMaterial};
use polyjose::keys::KeyFormat;

/// The detail import gives for a modulus under 2048 bits (RFC 7518 §4.3).
const TOO_SHORT: Error = Error::InvalidKey("RSA modulus is shorter than 2048 bits");
/// The detail import gives for a modulus over 8192 bits (ADR 0026 §2 step 8).
const TOO_LONG: Error = Error::InvalidKey("RSA modulus is longer than 8192 bits");

/// Sizes import accepts: both ends of 2048..=8192.
const IN_RANGE: [usize; 2] = [2048, 8192];
/// Sizes under the range.
const TOO_SHORT_BITS: [usize; 2] = [1024, 2047];
/// Sizes over the range.
const TOO_LONG_BITS: [usize; 2] = [8193, 8200];

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/jwe/rsa-bound")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn text(name: &str) -> String {
    String::from_utf8(fixture(name)).unwrap()
}

/// The fixture JWK's `n`, decoded independently of polyjose.
fn fixture_n(bits: usize) -> Vec<u8> {
    let jwk = text(&format!("rsa{bits}.jwk.json"));
    let value: serde_json::Value = serde_json::from_str(&jwk).unwrap();
    Base64UrlUnpadded::decode_vec(value["n"].as_str().unwrap()).unwrap()
}

/// Each import path, named, applied to the `bits`-bit fixture key.
fn every_import(bits: usize) -> Vec<(&'static str, Result<Jwk, Error>)> {
    let jwk = fixture(&format!("rsa{bits}.jwk.json"));
    let object = match json::parse(&jwk).unwrap() {
        Value::Object(object) => object,
        other => panic!("rsa{bits}.jwk.json is not an object: {other:?}"),
    };
    vec![
        ("Jwk::from_json", Jwk::from_json(&jwk)),
        ("Jwk::from_object", Jwk::from_object(&object)),
        (
            "Jwk::from_pem PUBLIC KEY",
            Jwk::from_pem(&text(&format!("rsa{bits}-spki.pem"))),
        ),
        (
            "Jwk::from_pem RSA PUBLIC KEY",
            Jwk::from_pem(&text(&format!("rsa{bits}-pkcs1.pem"))),
        ),
        (
            "Jwk::from_der Spki",
            Jwk::from_der(&fixture(&format!("rsa{bits}-spki.der")), KeyFormat::Spki),
        ),
        (
            "Jwk::from_der Pkcs1",
            Jwk::from_der(&fixture(&format!("rsa{bits}-pkcs1.der")), KeyFormat::Pkcs1),
        ),
    ]
}

#[test]
fn the_fixture_keys_have_the_stated_sizes() {
    // Checked without polyjose: the bit length of the big-endian `n`.
    for bits in TOO_SHORT_BITS
        .into_iter()
        .chain(IN_RANGE)
        .chain(TOO_LONG_BITS)
    {
        let n = fixture_n(bits);
        assert_ne!(n[0], 0, "{bits}: n is minimal");
        let len = 8 * n.len() - usize::try_from(n[0].leading_zeros()).unwrap();
        assert_eq!(len, bits, "rsa{bits}");
    }
}

#[test]
fn every_import_path_accepts_2048_and_8192_bits_as_the_same_key() {
    for bits in IN_RANGE {
        let expected = fixture_n(bits);
        for (path, result) in every_import(bits) {
            let jwk = result.unwrap_or_else(|e| panic!("{bits} bits, {path}: {e:?}"));
            let KeyMaterial::Rsa(key) = jwk.material() else {
                panic!("{bits} bits, {path}: not an RSA key")
            };
            assert_eq!(key.modulus_bits(), bits, "{bits} bits, {path}");
            assert_eq!(key.n(), expected.as_slice(), "{bits} bits, {path}");
            assert_eq!(key.e(), [0x01, 0x00, 0x01], "{bits} bits, {path}");
        }
    }
}

#[test]
fn every_import_path_refuses_1024_and_2047_bits() {
    for bits in TOO_SHORT_BITS {
        for (path, result) in every_import(bits) {
            assert_eq!(result.err(), Some(TOO_SHORT), "{bits} bits, {path}");
        }
    }
}

#[test]
fn every_import_path_refuses_8193_and_8200_bits() {
    for bits in TOO_LONG_BITS {
        for (path, result) in every_import(bits) {
            assert_eq!(result.err(), Some(TOO_LONG), "{bits} bits, {path}");
        }
    }
}

#[test]
fn every_refusal_is_the_invalid_key_code_of_the_rsa_oaep_256_vectors() {
    // conformance/vectors/jwe/rsa-oaep-256/encrypt-1024-bit-key-invalid.json
    // expects "InvalidKey"; import is now where that code comes from.
    for bits in TOO_SHORT_BITS.into_iter().chain(TOO_LONG_BITS) {
        for (path, result) in every_import(bits) {
            assert_eq!(
                result.err().map(|e| e.code()),
                Some("InvalidKey"),
                "{bits} bits, {path}"
            );
        }
    }
}
