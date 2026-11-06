//! RSA-OAEP-256 (RFC 7518 §4.3) through the public API (0003 T11).
//!
//! polyjose encrypts a CEK to an RSA public key and nothing more: it has no
//! RSA private-key code (ADR 0021), so these tests cannot open what they
//! produce. Correctness is checked independently by
//! `conformance/tools/rsa-oaep-oracle.mjs` (Node's built-in crypto, run by
//! `scripts/test-all.sh node`), against the test-only private keys that only
//! it reads. Here:
//!
//! - every key size and `enc` gives the RFC 7516 §7.1 shape with an
//!   encrypted key of exactly k octets (RFC 8017 §7.1.1) and fresh OS
//!   randomness each time (ADR 0005);
//! - RSA-OAEP-256 never decrypts, not even polyjose's own output, and
//!   RSA-OAEP (SHA-1, ADR 0022) and RSA1_5 (ADR 0021) never encrypt;
//! - a modulus under 2048 bits is `InvalidKey` (RFC 7518 §4.3);
//! - with `insecure-test-vectors`, the committed vectors in
//!   `conformance/vectors/jwe/rsa-oaep-256/` are reproduced byte for byte,
//!   and the drawn bytes are consumed as the CEK, the OAEP seed, then the
//!   IV (`jwe::random`'s documented order).
#![allow(clippy::panic)] // test code: a panic is a failed assertion

use std::path::PathBuf;

use polyjose::Error;
use polyjose::json::{self, Value};
use polyjose::jwa::{ContentEncAlg, KeyMgmtAlg};
use polyjose::jwe::{DecryptPolicy, Encryptor, Recipient, decrypt_compact};
use polyjose::jwk::Jwk;
use polyjose::util::b64url_decode;

use ContentEncAlg as E;
use KeyMgmtAlg as A;

const PLAINTEXT: &[u8] = b"Encrypted to an RSA public key, opened only by its holder.";

fn vector_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/vectors/jwe/rsa-oaep-256")
}

fn code<T>(result: polyjose::Result<T>) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(e) => e.code(),
    }
}

fn bytes(b64u: &str) -> Vec<u8> {
    b64url_decode(b64u).unwrap_or_else(|e| panic!("{b64u}: {e}"))
}

fn parse(text: &[u8]) -> Value {
    json::parse(text).unwrap_or_else(|e| panic!("{e}"))
}

fn str_at<'a>(value: &'a Value, path: &[&str]) -> &'a str {
    let mut at = value;
    for name in path {
        at = at
            .get(name)
            .unwrap_or_else(|| panic!("no {name} in {path:?}"));
    }
    at.as_str()
        .unwrap_or_else(|| panic!("{path:?} is not a string"))
}

/// One committed exact vector: `<bits>-<enc>-reproduced.json`.
#[cfg_attr(
    not(feature = "insecure-test-vectors"),
    allow(
        dead_code,
        reason = "enc, plaintext and rng feed the reproducible tests only"
    )
)]
struct Vector {
    name: String,
    enc: ContentEncAlg,
    /// The recipient's public JWK (`kty`, `n`, `e` only).
    key: String,
    plaintext: Vec<u8>,
    rng: Vec<u8>,
    jwe: String,
}

fn vectors() -> Vec<Vector> {
    let mut names: Vec<String> = std::fs::read_dir(vector_dir())
        .unwrap_or_else(|e| panic!("{e}"))
        .map(|entry| entry.unwrap_or_else(|e| panic!("{e}")).file_name())
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| name.ends_with("-reproduced.json"))
        .collect();
    names.sort();
    // 2048, 3072 and 4096 bits × A128GCM and A256CBC-HS512.
    assert!(names.len() >= 6, "{names:?}");
    names
        .into_iter()
        .map(|name| {
            let text = std::fs::read(vector_dir().join(&name)).unwrap_or_else(|e| panic!("{e}"));
            let v = json::parse(&text).unwrap_or_else(|e| panic!("{name}: {e}"));
            let input = v.get("input").unwrap_or_else(|| panic!("{name}: no input"));
            let recipient = &input
                .get("recipients")
                .and_then(Value::as_array)
                .unwrap_or_else(|| panic!("{name}: no recipients"))[0];
            assert_eq!(str_at(recipient, &["alg"]), "RSA-OAEP-256", "{name}");
            assert!(
                recipient.get("key").and_then(|k| k.get("d")).is_none(),
                "{name}"
            );
            let key = format!(
                r#"{{"kty":"RSA","n":"{}","e":"{}"}}"#,
                str_at(recipient, &["key", "n"]),
                str_at(recipient, &["key", "e"]),
            );
            Vector {
                enc: ContentEncAlg::from(str_at(input, &["enc"])),
                key,
                plaintext: bytes(str_at(input, &["plaintext_b64u"])),
                rng: bytes(str_at(input, &["rng_b64u"])),
                jwe: str_at(&v, &["expect", "jwe"]).to_owned(),
                name,
            }
        })
        .collect()
}

fn jwk(json: &str) -> Jwk {
    Jwk::from_json(json.as_bytes()).unwrap_or_else(|e| panic!("{e}"))
}

/// The distinct recipient keys of the vectors, with their modulus length k.
fn keys() -> Vec<(Jwk, usize)> {
    let mut seen: Vec<String> = Vec::new();
    let mut keys = Vec::new();
    for v in vectors() {
        if seen.contains(&v.key) {
            continue;
        }
        let n = str_at(&parse(v.key.as_bytes()), &["n"]).to_owned();
        keys.push((jwk(&v.key), bytes(&n).len()));
        seen.push(v.key);
    }
    assert_eq!(
        keys.iter().map(|(_, k)| *k * 8).collect::<Vec<_>>(),
        [2048, 3072, 4096]
    );
    keys
}

fn encryptor(enc: ContentEncAlg, key: &Jwk) -> Encryptor {
    Encryptor::new(enc).recipient(Recipient::new(A::RsaOaep256, key))
}

fn segments(token: &str) -> Vec<Vec<u8>> {
    let parts: Vec<Vec<u8>> = token.split('.').map(bytes).collect();
    assert_eq!(parts.len(), 5, "RFC 7516 §7.1: five segments");
    parts
}

fn iv_len(enc: &ContentEncAlg) -> usize {
    if enc.to_string().contains("GCM") {
        12
    } else {
        16
    }
}

#[test]
fn every_size_and_enc_gives_a_k_octet_encrypted_key_and_fresh_randomness() {
    // RFC 7518 §4.3 and RFC 8017 §7.1.1: the JWE Encrypted Key is the
    // OAEP ciphertext, exactly k octets. RFC 7516 §5.1: the protected
    // header carries alg and enc and RSA-OAEP-256 adds no parameter. The
    // seed, CEK and IV come from the OS CSPRNG (ADR 0005), so two
    // encryptions of one plaintext share no random part.
    for (key, k) in keys() {
        for enc in ContentEncAlg::KNOWN {
            let first = encryptor(enc.clone(), &key)
                .encrypt_compact(PLAINTEXT)
                .unwrap_or_else(|e| panic!("{k} {enc}: {e}"));
            let again = encryptor(enc.clone(), &key)
                .encrypt_compact(PLAINTEXT)
                .unwrap_or_else(|e| panic!("{k} {enc}: {e}"));
            let (a, b) = (segments(&first), segments(&again));
            let header = parse(&a[0]);
            let members = header.as_object().map(|object| object.len());
            assert_eq!(members, Some(2), "{k} {enc}: only alg and enc");
            assert_eq!(str_at(&header, &["alg"]), "RSA-OAEP-256");
            assert_eq!(str_at(&header, &["enc"]), enc.to_string());
            assert_eq!(a[1].len(), k, "{k} {enc}: the encrypted key is k octets");
            assert_eq!(a[2].len(), iv_len(enc), "{k} {enc}");
            assert_ne!(a[1], b[1], "{k} {enc}: a fresh seed and CEK");
            assert_ne!(a[2], b[2], "{k} {enc}: a fresh IV");
        }
    }
}

#[test]
fn rsa_oaep_256_never_decrypts_not_even_polyjose_output() {
    // ADR 0021: no RSA private-key operation. The support check comes
    // before the key and the allow-list (plan.md error contract), so the
    // result is UnsupportedAlgorithm even when the policy allows the alg.
    let policy = DecryptPolicy::new(&[A::RsaOaep256], ContentEncAlg::KNOWN)
        .unwrap_or_else(|e| panic!("{e}"));
    for v in vectors() {
        assert_eq!(
            code(decrypt_compact(&v.jwe, &jwk(&v.key), &policy)),
            "UnsupportedAlgorithm",
            "{}",
            v.name
        );
    }
}

#[test]
fn rsa_oaep_sha1_never_decrypts() {
    // ADR 0022: RSA-OAEP (SHA-1) is unsupported on decrypt too, even with
    // the alg on the allow-list. The protected header is swapped for
    // {"alg":"RSA-OAEP","enc":"A128GCM"}; the rest is a real token.
    let v = vectors().remove(0);
    let rest = v.jwe.split_once('.').map(|(_, rest)| rest).unwrap_or("");
    let header = polyjose::util::b64url_encode(br#"{"alg":"RSA-OAEP","enc":"A128GCM"}"#);
    let policy = DecryptPolicy::new(&[A::from("RSA-OAEP")], ContentEncAlg::KNOWN)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        code(decrypt_compact(
            &format!("{header}.{rest}"),
            &jwk(&v.key),
            &policy
        )),
        "UnsupportedAlgorithm"
    );
}

#[test]
fn rsa_oaep_and_rsa1_5_never_encrypt() {
    // ADR 0022 (RSA-OAEP uses SHA-1) and ADR 0021 (RSA1_5), to a key that
    // RSA-OAEP-256 accepts.
    let (key, _) = keys().remove(0);
    for alg in ["RSA-OAEP", "RSA1_5"] {
        let result = Encryptor::new(E::A128GCM)
            .recipient(Recipient::new(A::from(alg), &key))
            .encrypt_compact(PLAINTEXT);
        assert_eq!(result, Err(Error::UnsupportedAlgorithm), "{alg}");
    }
}

#[test]
fn a_modulus_under_2048_bits_is_an_invalid_key() {
    // RFC 7518 §4.3: "A key of size 2048 bits or larger MUST be used".
    // The modulus is all ones (odd), so size is the only fault.
    for bits in [1024usize, 2040, 2047] {
        let mut n = vec![0xffu8; bits.div_ceil(8)];
        n[0] >>= (8 - bits % 8) % 8;
        let json = format!(
            r#"{{"kty":"RSA","n":"{}","e":"AQAB"}}"#,
            polyjose::util::b64url_encode(&n)
        );
        let result = Jwk::from_json(json.as_bytes())
            .and_then(|key| encryptor(E::A128GCM, &key).encrypt_compact(PLAINTEXT));
        assert_eq!(code(result), "InvalidKey", "{bits}");
    }
}

#[test]
fn rsa_oaep_256_needs_an_rsa_public_key() {
    // RFC 8725 §3.1: the alg is bound to one key family (RFC 7518 §4.3).
    let oct = jwk(r#"{"kty":"oct","k":"XctOhJAkA-pD9Lh7ZgW_2A"}"#);
    assert_eq!(
        encryptor(E::A128GCM, &oct).encrypt_compact(PLAINTEXT),
        Err(Error::KeyAlgorithmMismatch)
    );
}

#[cfg(feature = "insecure-test-vectors")]
mod reproducible {
    use polyjose::insecure_test_vectors::FixedRng;
    use polyjose::jwe::Serialization;

    use super::*;

    fn encrypt(v: &Vector, rng: Vec<u8>) -> polyjose::Result<(String, usize)> {
        let mut rng = FixedRng::new(rng);
        let token = encryptor(v.enc.clone(), &jwk(&v.key)).encrypt_reproducible(
            &v.plaintext,
            Serialization::Compact,
            &mut rng,
            None,
        )?;
        Ok((token, rng.remaining()))
    }

    #[test]
    fn every_committed_vector_is_reproduced_byte_for_byte_on_every_run() {
        // RSAES-OAEP is deterministic given its seed (RFC 8017 §7.1.1), so
        // with every random value injected the whole JWE is too. The
        // expected tokens were computed by the Node oracle, not polyjose.
        for v in vectors() {
            for _ in 0..2 {
                assert_eq!(
                    encrypt(&v, v.rng.clone()),
                    Ok((v.jwe.clone(), 0)),
                    "{}",
                    v.name
                );
            }
        }
    }

    #[test]
    fn the_bytes_are_drawn_as_cek_then_oaep_seed_then_iv() {
        // The `jwe::random` draw order: the CEK (RFC 7516 §5.1 step 2),
        // the recipient's 32-octet OAEP seed (RFC 8017 §7.1.1 step 2.d),
        // the content IV (§5.1 step 9). Flipping one byte in each region
        // changes exactly the segments that region feeds.
        for v in vectors() {
            let cek_len = v.rng.len() - 32 - iv_len(&v.enc);
            let expected = segments(&v.jwe);
            let changed = |at: usize| {
                let mut rng = v.rng.clone();
                rng[at] ^= 0x01;
                let (token, left) = encrypt(&v, rng).unwrap_or_else(|e| panic!("{e}"));
                assert_eq!(left, 0);
                let got = segments(&token);
                (0..5).map(|i| got[i] != expected[i]).collect::<Vec<bool>>()
            };
            // header, encrypted key, IV, ciphertext, tag. For A*CBC-HS*
            // the first half of the CEK is the MAC key and feeds only the
            // tag (RFC 7518 §5.2.2.1); for A*GCM every CEK byte feeds both.
            let cek = [false, true, false, true, true];
            let mac_key = [false, true, false, false, true];
            let seed = [false, true, false, false, false];
            let iv = [false, false, true, true, true];
            let first = if iv_len(&v.enc) == 16 { mac_key } else { cek };
            assert_eq!(changed(0), first, "{}: first CEK byte", v.name);
            assert_eq!(changed(cek_len - 1), cek, "{}: last CEK byte", v.name);
            assert_eq!(changed(cek_len), seed, "{}: first seed byte", v.name);
            assert_eq!(changed(cek_len + 31), seed, "{}: last seed byte", v.name);
            assert_eq!(changed(cek_len + 32), iv, "{}: first IV byte", v.name);
            assert_eq!(changed(v.rng.len() - 1), iv, "{}: last IV byte", v.name);
        }
    }

    #[test]
    fn a_short_source_fails_closed_and_extra_bytes_stay_unread() {
        // ADR 0005: a source that runs out is RandomnessUnavailable, never
        // a short seed or IV; the encryption draws exactly CEK + 32 + IV.
        for v in vectors() {
            let cek_len = v.rng.len() - 32 - iv_len(&v.enc);
            for len in [v.rng.len() - 1, cek_len + 31, cek_len] {
                assert_eq!(
                    encrypt(&v, v.rng[..len].to_vec()).map(|_| ()),
                    Err(Error::RandomnessUnavailable),
                    "{}: {len} bytes",
                    v.name
                );
            }
            let mut longer = v.rng.clone();
            longer.extend_from_slice(&[0xee; 7]);
            assert_eq!(encrypt(&v, longer), Ok((v.jwe.clone(), 7)), "{}", v.name);
        }
    }
}
