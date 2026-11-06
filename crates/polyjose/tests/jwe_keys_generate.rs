//! Keys from `polyjose::keys` (0005) used as JWE keys (0003 F03), through
//! the public API only.
//!
//! - `generate_for(enc)` gives the `dir` key of that `enc` (RFC 7518 §4.5):
//!   an `oct` key whose `alg` is the `enc` (RFC 7517 §4.4), which
//!   round-trips with `dir` + that `enc` and is refused for any other.
//! - `generate_for(A256KW)` round-trips with A256KW (RFC 7518 §4.4).
//! - `generate` with an explicit curve gives an ECDH-ES recipient key
//!   (RFC 7518 §4.6, RFC 8037 §3.2) that round-trips with ECDH-ES+A128KW.
#![allow(clippy::panic)] // test code: a panic is a failed assertion

use polyjose::Error;
use polyjose::jwa::{ContentEncAlg, KeyMgmtAlg};
use polyjose::jwe::{DecryptPolicy, Encryptor, Recipient, decrypt_compact};
use polyjose::jwk::{EcCurve, Jwk, KeyAlg, KeyMaterial, KeyType, OkpCurve};
use polyjose::keys::{KeySpec, generate, generate_for};

use ContentEncAlg as E;
use KeyMgmtAlg as A;

/// The six registered `enc` values (RFC 7518 §5.1), with the CEK length
/// each one fixes for `dir` (RFC 7518 §4.5, §5.2.3–§5.2.5, §5.3).
const ENCS: [(ContentEncAlg, usize); 6] = [
    (E::A128GCM, 16),
    (E::A192GCM, 24),
    (E::A256GCM, 32),
    (E::A128CbcHs256, 32),
    (E::A192CbcHs384, 48),
    (E::A256CbcHs512, 64),
];

fn policy(algs: &[KeyMgmtAlg], encs: &[ContentEncAlg]) -> DecryptPolicy {
    DecryptPolicy::new(algs, encs).unwrap_or_else(|e| panic!("{e}"))
}

fn key_for(alg: impl Into<polyjose::keys::JoseAlg>) -> Jwk {
    generate_for(alg).unwrap_or_else(|e| panic!("{e}"))
}

fn encrypt(
    alg: &KeyMgmtAlg,
    key: &Jwk,
    enc: &ContentEncAlg,
    plaintext: &[u8],
) -> Result<String, Error> {
    Encryptor::new(enc.clone())
        .recipient(Recipient::new(alg.clone(), key))
        .encrypt_compact(plaintext)
}

/// Encrypts `plaintext` to `encrypt_key` and decrypts it with
/// `decrypt_key`, allowing only `alg` and `enc`.
fn round_trip(alg: &KeyMgmtAlg, encrypt_key: &Jwk, decrypt_key: &Jwk, enc: &ContentEncAlg) {
    let plaintext = format!("{alg} {enc}");
    let token = encrypt(alg, encrypt_key, enc, plaintext.as_bytes())
        .unwrap_or_else(|e| panic!("{alg} {enc}: {e}"));
    let p = policy(std::slice::from_ref(alg), std::slice::from_ref(enc));
    let d = decrypt_compact(&token, decrypt_key, &p).unwrap_or_else(|e| panic!("{alg} {enc}: {e}"));
    assert_eq!(d.plaintext(), plaintext.as_bytes(), "{alg} {enc}");
    assert_eq!(d.header().alg.as_deref(), Some(alg.as_str()), "{alg} {enc}");
    assert_eq!(d.header().enc.as_ref(), Some(enc), "{alg} {enc}");
}

// ---------------------------------------------------------------------------
// dir (RFC 7518 §4.5)
// ---------------------------------------------------------------------------

/// `generate_for(enc)` is an `oct` key (RFC 7518 §6.4) of the CEK length
/// of `enc`, with `alg` set to the `enc` value (RFC 7517 §4.4): the form
/// of a `dir` key, whose key is the CEK (RFC 7518 §4.5).
#[test]
fn generate_for_enc_is_an_oct_key_bound_to_the_enc() {
    for (enc, len) in &ENCS {
        let key = key_for(enc.clone());
        assert_eq!(key.key_type(), KeyType::Oct, "{enc}");
        assert_eq!(key.alg(), Some(&KeyAlg::ContentEnc(enc.clone())), "{enc}");
        assert_eq!(key.alg().map(KeyAlg::as_str), Some(enc.as_str()), "{enc}");
        let KeyMaterial::Oct(k) = key.material() else {
            panic!("{enc}: not oct")
        };
        assert_eq!(k.len(), *len, "{enc}");
    }
}

/// RFC 7518 §4.5: with `dir` the shared key is the CEK, so a
/// `generate_for(enc)` key encrypts and decrypts `dir` + `enc`.
#[test]
fn generate_for_enc_round_trips_with_dir() {
    for (enc, _) in &ENCS {
        let key = key_for(enc.clone());
        round_trip(&A::Dir, &key, &key, enc);
    }
}

/// RFC 8725 §3.1, RFC 7517 §4.4: a key whose `alg` is one `enc` is not
/// used with `dir` and any other `enc`, even one of the same length
/// (A256GCM and A128CBC-HS256 both take 32 octets). Refused on encrypt,
/// before any cryptography, as `KeyAlgorithmMismatch`.
#[test]
fn generate_for_enc_is_key_algorithm_mismatch_for_another_enc() {
    for (enc, _) in &ENCS {
        let key = key_for(enc.clone());
        for (other, _) in ENCS.iter().filter(|(e, _)| e != enc) {
            assert_eq!(
                encrypt(&A::Dir, &key, other, b"x").map(|_| ()),
                Err(Error::KeyAlgorithmMismatch),
                "{enc} key, {other}"
            );
        }
    }
}

/// The decrypt side of the same rule (RFC 8725 §3.1): a `dir` + `other`
/// JWE is not decrypted with a key bound to another `enc`, even when the
/// policy allows `other`; the key is not a candidate, `KeyAlgorithmMismatch`.
#[test]
fn generate_for_enc_does_not_decrypt_another_enc() {
    for (enc, _) in &ENCS {
        let key = key_for(enc.clone());
        for (other, _) in ENCS.iter().filter(|(e, _)| e != enc) {
            let other_key = key_for(other.clone());
            let token = encrypt(&A::Dir, &other_key, other, b"x")
                .unwrap_or_else(|e| panic!("{other}: {e}"));
            let p = policy(&[A::Dir], std::slice::from_ref(other));
            assert_eq!(
                decrypt_compact(&token, &key, &p).map(|_| ()),
                Err(Error::KeyAlgorithmMismatch),
                "{enc} key, {other} token"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// A256KW (RFC 7518 §4.4)
// ---------------------------------------------------------------------------

/// `generate_for(A256KW)` is a 32-octet `oct` key bound to A256KW
/// (RFC 7518 §4.4, RFC 7517 §4.4) that wraps and unwraps the CEK of every
/// `enc`.
#[test]
fn generate_for_a256kw_round_trips_with_a256kw() {
    let key = key_for(A::A256KW);
    assert_eq!(key.key_type(), KeyType::Oct);
    assert_eq!(key.alg(), Some(&KeyAlg::KeyMgmt(A::A256KW)));
    let KeyMaterial::Oct(k) = key.material() else {
        panic!("not oct")
    };
    assert_eq!(k.len(), 32);
    for (enc, _) in &ENCS {
        round_trip(&A::A256KW, &key, &key, enc);
    }
}

// ---------------------------------------------------------------------------
// ECDH-ES+A128KW (RFC 7518 §4.6, RFC 8037 §3.2)
// ---------------------------------------------------------------------------

/// ECDH-ES works on several curves, so `generate_for(ECDH-ES+A128KW)` has
/// no default and asks for one (`InvalidKey("curve required")`); the key
/// comes from `generate` with an explicit curve instead. The sender
/// encrypts to its public part (RFC 7518 §4.6.1, the recipient's static
/// public key); the recipient decrypts with the private key
/// (RFC 7518 §4.6.2).
#[test]
fn explicit_curve_keys_round_trip_with_ecdh_es_a128kw() {
    assert_eq!(
        generate_for(A::EcdhEsA128KW).map(|_| ()),
        Err(Error::InvalidKey("curve required"))
    );
    for spec in [KeySpec::Ec(EcCurve::P256), KeySpec::Okp(OkpCurve::X25519)] {
        let private = generate(spec).unwrap_or_else(|e| panic!("{e}"));
        let public = private
            .to_public()
            .unwrap_or_else(|| panic!("no public part"));
        assert!(public.is_public());
        for (enc, _) in &ENCS {
            round_trip(&A::EcdhEsA128KW, &public, &private, enc);
        }
    }
}
