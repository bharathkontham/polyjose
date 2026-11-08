#![no_main]
//! JWE decryption (RFC 7516 §5.2): `jwe::decrypt_compact` and
//! `jwe::decrypt_json`, with fixed published keys.
//!
//! Input: a mode byte, then
//! - mode 0 / 1: a key byte (an index into `JWE_KEYS`), then a compact /
//!   JSON JWE.
//! - mode 2: a recipient byte, a flags byte, a tamper byte, then the
//!   protected header JSON, a zero byte, the shared unprotected header
//!   JSON, a zero byte, the AAD, a zero byte and the plaintext. The harness
//!   encrypts it to its own key (ADR 0036 §2, 3a: the decrypter is never
//!   weakened) and decrypts it.
//!
//! - Ok ⇒ `alg` and `enc` are in the allow-lists: the same JWE fails under
//!   a policy without its `alg` (compact) or without its `enc` (RFC 8725
//!   §3.1).
//! - A JWE the harness encrypted decrypts to the plaintext and AAD;
//!   changing any one character of a compact JWE makes it fail (RFC 7516
//!   §5.2 steps 14–16: the AEAD covers the protected header, the IV, the
//!   ciphertext and the tag, and the key wraps are authenticated).
//! - PBES2 runs under a low iteration budget for throughput.
//! - Every failure has a stable code.
use libfuzzer_sys::fuzz_target;
use polyjose::header::Header;
use polyjose::jwa::{ContentEncAlg as E, KeyMgmtAlg as A};
use polyjose::jwe::{self, DecryptPolicy, Decrypted, Encryptor, JsonForm, Recipient};
use polyjose::jwk::Jwk;
use polyjose_fuzz::{self as fx, check_err, split0};

const ENCS: [E; 6] = [
    E::A128CbcHs256,
    E::A192CbcHs384,
    E::A256CbcHs512,
    E::A128GCM,
    E::A192GCM,
    E::A256GCM,
];

/// RFC 7518 App. C's P-256 key without `kid`, so a fuzzed header `kid`
/// cannot narrow it away (RFC 7516 §4.1.6).
const P256: &str = r#"{"kty":"EC","crv":"P-256","x":"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ","y":"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck","d":"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"}"#;
/// RFC 7520 §3.3's P-384 key, without `kid` and `use`.
const P384: &str = r#"{"kty":"EC","crv":"P-384","x":"YU4rRUzdmVqmRtWOs2OpDE_T5fsNIodcG8G5FWPrTPMyxpzsSOGaQLpe2FpxBmu2","y":"A8-yxCHxkfBz3hKZfI1jUYMjUhsEveZ9THuwFjH2sCNdtksRJU7D5-SkgaFL1ETP","d":"iTx2pk7wW-GqJkHcEkFQb2EFyYcO7RugmaW3mRrQVAOUiPommT0IdnYK2xDlZh-j"}"#;
/// RFC 8037 App. A.6 / conformance X25519 key.
const X25519: &str = r#"{"kty":"OKP","crv":"X25519","x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08","d":"XasIfmJKikt54X-Lg4AO5m87sSkmGLb9HC-LJ_-I4Os"}"#;
/// A PBES2 password (conformance `binding-surface`).
const PASSWORD: &str = r#"{"kty":"oct","k":"YmluZGluZyBzdXJmYWNlIHBhc3N3b3Jk"}"#;

/// The content encryption key length of `enc`, in octets (RFC 7518 §5.2.3–
/// §5.2.5, §5.3).
fn cek_len(enc: &E) -> usize {
    match enc {
        E::A128GCM => 16,
        E::A192GCM => 24,
        E::A256GCM | E::A128CbcHs256 => 32,
        E::A192CbcHs384 => 48,
        _ => 64,
    }
}

/// The recipient `i` of mode 2: its `alg` and its decryption key.
fn recipient(i: u8, enc: &E) -> (A, Jwk) {
    match i % 10 {
        0 => (A::Dir, fx::oct_of_len(cek_len(enc))),
        1 => (A::A128KW, fx::oct_of_len(16)),
        2 => (A::A256KW, fx::oct_of_len(32)),
        3 => (A::A128GCMKW, fx::oct_of_len(16)),
        4 => (A::A256GCMKW, fx::oct_of_len(32)),
        5 => (A::EcdhEs, fx::jwk(P256)),
        6 => (A::EcdhEsA128KW, fx::jwk(X25519)),
        7 => (A::EcdhEsA256KW, fx::jwk(P384)),
        8 => (A::Pbes2Hs256A128KW, fx::jwk(PASSWORD)),
        _ => (A::Pbes2Hs512A256KW, fx::jwk(PASSWORD)),
    }
}

fn policy(algs: &[A], encs: &[E]) -> Option<DecryptPolicy> {
    DecryptPolicy::new(algs, encs)
        .ok()
        .map(|p| p.max_pbes2_count(fx::PBES2_BUDGET))
}

fn without<T: Clone + PartialEq>(all: &[T], drop: &T) -> Vec<T> {
    all.iter().filter(|&x| x != drop).cloned().collect()
}

fn raw(json: bool, rest: &[u8]) {
    let Some((&k, token)) = rest.split_first() else {
        return;
    };
    let Ok(token) = core::str::from_utf8(token) else {
        return;
    };
    let key = fx::jwk(fx::JWE_KEYS[usize::from(k) % fx::JWE_KEYS.len()]);
    let decrypt = |p: &DecryptPolicy| {
        if json {
            jwe::decrypt_json(token, &key, p)
        } else {
            jwe::decrypt_compact(token, &key, p)
        }
    };
    let Some(all) = policy(A::KNOWN, E::KNOWN) else {
        return;
    };
    let d: Decrypted = match decrypt(&all) {
        Ok(d) => d,
        Err(e) => return check_err(&e),
    };
    let h = d.header();
    let (Ok(alg), Ok(enc)) = (h.key_mgmt_alg(), h.content_enc_alg()) else {
        panic!("decrypted a JWE without a valid alg and enc");
    };
    if !json {
        assert!(d.protected_header().is_some() && d.recipient() == 0);
        if let Some(p) = policy(&without(A::KNOWN, &alg), E::KNOWN) {
            assert!(
                decrypt(&p).is_err(),
                "decrypted with its alg outside the allow-list"
            );
        }
    }
    if let Some(p) = policy(A::KNOWN, &without(E::KNOWN, &enc)) {
        assert!(
            decrypt(&p).is_err(),
            "decrypted with its enc outside the allow-list"
        );
    }
}

fn header(bytes: &[u8]) -> Option<Header> {
    if bytes.is_empty() {
        None
    } else {
        Header::from_json(bytes).ok()
    }
}

fn crit_names(h: &[Option<Header>]) -> Vec<String> {
    h.iter()
        .flatten()
        .filter_map(|h| h.crit.clone())
        .flatten()
        .collect()
}

fn structured(data: &[u8]) {
    let [rec, flags, tamper, fields @ ..] = data else {
        return;
    };
    let enc = ENCS[usize::from(flags & 7) % ENCS.len()].clone();
    let compress = flags & 8 != 0;
    let json = flags & 16 != 0;
    let general = flags & 32 != 0;
    let (alg, key) = recipient(*rec, &enc);
    let (protected, rest) = split0(fields);
    let (shared, rest) = split0(rest);
    let (aad, plaintext) = split0(rest);
    let protected = header(protected);
    let shared = if json { header(shared) } else { None };
    let aad = if json && !aad.is_empty() {
        Some(aad)
    } else {
        None
    };

    let to = key.to_public().unwrap_or_else(|| key.clone());
    let mut r = Recipient::new(alg.clone(), &to);
    if matches!(alg, A::Pbes2Hs256A128KW | A::Pbes2Hs512A256KW) {
        r = r.p2c(fx::PBES2_BUDGET);
    }
    let mut e = Encryptor::new(enc.clone()).recipient(r);
    if let Some(p) = protected.clone() {
        e = e.protected_header(p);
    }
    if let Some(s) = shared.clone() {
        e = e.shared_unprotected_header(s);
    }
    if let Some(a) = aad {
        e = e.aad(a.to_vec());
    }
    if compress {
        e = e.compress();
    }
    let form = if general {
        JsonForm::General
    } else {
        JsonForm::Flattened
    };
    let token = match if json {
        e.encrypt_json(plaintext, form)
    } else {
        e.encrypt_compact(plaintext)
    } {
        Ok(t) => t,
        Err(e) => return check_err(&e),
    };

    let crit = crit_names(&[protected, shared]);
    let crit: Vec<&str> = crit.iter().map(String::as_str).collect();
    let Some(p) = policy(&[alg], &[enc]) else {
        return;
    };
    let p = p.understood_crit(&crit);
    let decrypt = |t: &str| {
        if json {
            jwe::decrypt_json(t, &key, &p)
        } else {
            jwe::decrypt_compact(t, &key, &p)
        }
    };
    match decrypt(&token) {
        Ok(d) => {
            assert!(d.plaintext() == plaintext, "decrypted plaintext differs");
            assert!(d.aad() == aad, "decrypted AAD differs");
        }
        Err(e) => panic!("a JWE the harness encrypted does not decrypt: {}", e.code()),
    }

    if !json && !token.is_empty() {
        let mut bytes = token.into_bytes();
        let i = usize::from(*tamper) * 131 % bytes.len();
        bytes[i] = if bytes[i] == b'A' { b'B' } else { b'A' };
        if let Ok(t) = core::str::from_utf8(&bytes) {
            assert!(
                decrypt(t).is_err(),
                "a JWE with one character changed decrypts"
            );
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    match mode % 3 {
        0 => raw(false, rest),
        1 => raw(true, rest),
        _ => structured(rest),
    }
});
