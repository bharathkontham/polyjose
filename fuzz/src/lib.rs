//! Shared fixtures for the polyjose fuzz targets (feature 0012, ADR 0036).
//!
//! Every key here is a published test key (RFC 7515 App. A, RFC 7518
//! App. C, RFC 7520 §3, RFC 8037 App. A) or a fixed byte pattern, taken from
//! `conformance/vectors/`, so the committed seeds verify or decrypt. No
//! harness draws a key from an RNG, and none uses the fixed test RNG
//! (ADR 0036 §2: the real verifiers and decrypters run, never weakened).

use polyjose::Error;
use polyjose::jwk::{Jwk, JwkSet};
use polyjose::util::b64url_encode;

/// Parses a fixture key. Fixtures are constants, so failure is a harness
/// bug, never a finding.
pub fn jwk(json: &str) -> Jwk {
    match Jwk::from_json(json.as_bytes()) {
        Ok(k) => k,
        Err(e) => panic!("harness fixture key rejected: {}", e.code()),
    }
}

/// Parses a fixture JWK Set.
pub fn jwk_set(json: &str) -> JwkSet {
    match JwkSet::from_json(json.as_bytes()) {
        Ok(s) => s,
        Err(e) => panic!("harness fixture set rejected: {}", e.code()),
    }
}

/// An `oct` key of `len` fixed bytes (0, 1, 2, ...), for `dir` and the AES
/// key wraps, whose key length depends on the algorithm (RFC 7518 §4.4,
/// §4.7, §5.2, §5.3).
pub fn oct_of_len(len: usize) -> Jwk {
    let bytes: Vec<u8> = (0..len)
        .map(|i| (i as u8).wrapping_mul(7).wrapping_add(1))
        .collect();
    jwk(&format!(
        r#"{{"kty":"oct","k":"{}"}}"#,
        b64url_encode(&bytes)
    ))
}

/// Every error is one of the stable codes (ADR 0007), and printing it
/// never panics. Called on every `Err` a harness sees.
pub fn check_err(e: &Error) {
    assert!(
        Error::CODES.contains(&e.code()),
        "unknown error code {}",
        e.code()
    );
    let _ = e.to_string();
    let _ = format!("{e:?}");
}

/// Splits `data` at the first zero byte: the harnesses' field separator.
pub fn split0(data: &[u8]) -> (&[u8], &[u8]) {
    match data.iter().position(|&b| b == 0) {
        Some(i) => (&data[..i], &data[i + 1..]),
        None => (data, &[]),
    }
}

// --- JWS keys -------------------------------------------------------------

/// RFC 7515 App. A.1: the 64-octet HMAC key.
pub const OCT_A1: &str = r#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#;
/// RFC 7797 §4: an HS256 key bound by `alg`, `use` and `kid`.
pub const OCT_7797: &str = r#"{"kty":"oct","kid":"018c0ae5-4d9b-471b-bfd6-eef314bc7037","use":"sig","alg":"HS256","k":"hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"}"#;
/// A 32-octet prefix of the App. A.1 key (conformance key-length vectors).
pub const OCT_32: &str = r#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLg"}"#;
/// RFC 7515 App. A.3: the P-256 key, private.
pub const P256_A3: &str = r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"}"#;
/// RFC 7515 App. A.3: the P-256 key, public.
pub const P256_A3_PUB: &str = r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#;
/// RFC 7515 App. A.4: the P-521 key, private.
pub const P521_A4: &str = r#"{"kty":"EC","crv":"P-521","x":"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk","y":"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2","d":"AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C"}"#;
/// RFC 7520 §3.2: Bilbo's P-521 key, public.
pub const P521_BILBO_PUB: &str = r#"{"kty":"EC","kid":"bilbo.baggins@hobbiton.example","use":"sig","crv":"P-521","x":"AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt","y":"AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1"}"#;
/// RFC 8812 §3.2 / conformance: a secp256k1 key, private.
pub const K256: &str = r#"{"kty":"EC","crv":"secp256k1","x":"iaRF75M3-cfFwiUEHlB9FebMTJKDr8YEDBIwnOuNsWU","y":"OxAm4OdyD33a-vsL6NKW26bLSore_lOgDN2AGbLhn1g","d":"EE9oTP04ShCl38a3KQRRUczSgnx0bTgrXNm5oGf9xhk"}"#;
/// RFC 7515 App. A.4: the P-521 key, public.
pub const P521_A4_PUB: &str = r#"{"kty":"EC","crv":"P-521","x":"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk","y":"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2"}"#;
/// The secp256k1 key, public.
pub const K256_PUB: &str = r#"{"kty":"EC","crv":"secp256k1","x":"iaRF75M3-cfFwiUEHlB9FebMTJKDr8YEDBIwnOuNsWU","y":"OxAm4OdyD33a-vsL6NKW26bLSore_lOgDN2AGbLhn1g"}"#;
/// RFC 8037 App. A.2: the Ed25519 key, public.
pub const ED25519_PUB: &str =
    r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
/// RFC 8037 App. A.1: the Ed25519 key, private.
pub const ED25519: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
/// RFC 7515 App. A.2: the RSA key, public (RSA is verify-only, ADR 0021).
pub const RSA_A2_PUB: &str = r#"{"kty":"RSA","n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ","e":"AQAB"}"#;
/// RFC 7520 §3.4: Bilbo's RSA key, public.
pub const RSA_BILBO_PUB: &str = r#"{"kty":"RSA","kid":"bilbo.baggins@hobbiton.example","use":"sig","n":"n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw","e":"AQAB"}"#;

/// The keys of the raw JWS modes, chosen by the input's key byte (one
/// verification per input keeps the RSA and P-521 cost down). The seeds
/// carry the index of the key their vector names.
pub const JWS_VERIFY_KEYS: &[&str] = &[
    OCT_A1,
    OCT_7797,
    OCT_32,
    P256_A3_PUB,
    P521_A4_PUB,
    P521_BILBO_PUB,
    K256_PUB,
    ED25519_PUB,
    RSA_A2_PUB,
    RSA_BILBO_PUB,
];

// --- JWE keys -------------------------------------------------------------

/// The keys of the raw JWE targets, chosen by the input's key byte. The
/// seeds carry the index of the key their vector names.
pub const JWE_KEYS: &[&str] = &[
    r#"{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}"#,
    r#"{"kty":"oct","kid":"18ec08e1-bfa9-4d95-b205-2b4dd1d4321d","use":"enc","alg":"A256GCMKW","k":"qC57l_uxcm7Nm3K-ct4GFjx8tM1U8CZ0NLBvdQstiS8"}"#,
    r#"{"kty":"oct","kid":"81b20965-8332-43d9-a468-82160ad91ac8","use":"enc","alg":"A128KW","k":"GZy6sIZ6wl9NJOKB-jnmVQ"}"#,
    r#"{"kty":"oct","k":"ZW50cmFwX2_igJNwZXRlcl9sb25n4oCTY3JlZGl0X3R1bg"}"#,
    r#"{"kty":"oct","k":"AAECAwQFBgcICQoLDA0ODw"}"#,
    r#"{"kty":"EC","crv":"P-256","x":"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ","y":"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck","d":"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"}"#,
    r#"{"kty":"EC","kid":"peregrin.took@tuckborough.example","use":"enc","crv":"P-384","x":"YU4rRUzdmVqmRtWOs2OpDE_T5fsNIodcG8G5FWPrTPMyxpzsSOGaQLpe2FpxBmu2","y":"A8-yxCHxkfBz3hKZfI1jUYMjUhsEveZ9THuwFjH2sCNdtksRJU7D5-SkgaFL1ETP","d":"iTx2pk7wW-GqJkHcEkFQb2EFyYcO7RugmaW3mRrQVAOUiPommT0IdnYK2xDlZh-j"}"#,
    r#"{"kty":"oct","k":"WlpaWlpaWlpaWlpaWlpaWg"}"#,
    r#"{"kty":"oct","kid":"77c7e2b8-6e13-45cf-8672-617b5b45243a","use":"enc","alg":"A128GCM","k":"XctOhJAkA-pD9Lh7ZgW_2A"}"#,
    r#"{"kty":"OKP","crv":"X25519","x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08","d":"XasIfmJKikt54X-Lg4AO5m87sSkmGLb9HC-LJ_-I4Os"}"#,
    r#"{"kty":"EC","crv":"P-521","x":"AQgPCmwvTq-Kc6aJTUqEzAqdCSpbj6m1ZXWVTcjKC9yNaLL7Rj0d2EZQHSwDueBw_bNg7gJIkyvZPBeUagxxCsWq","y":"AYL3pbw7G2TiJtgJQEt7lozdY0iXK7EPyxyGOv-aeS6ykLtI7-kuS4ShWjI-6POOzLMWb-uxleEvlPEKb1D7IISw","d":"AJEhLbh3NK7njT9yn0hgDie98hTZGPZhVjjrtzU18RiqXFDbcRavq1bAgS92NDHSdlJY2tXh14UUGVhN-76ImmzZ"}"#,
    r#"{"kty":"oct","k":"YmluZGluZyBzdXJmYWNlIHBhc3N3b3Jk"}"#,
    r#"{"kty":"oct","k":"7sfQWXWZY3kStl0mBQRl_pYX8HKX0ork"}"#,
    r#"{"kty":"oct","k":"_EtaR6SY1PaVyPgaxLYtIuMyj-961EJyPJcj8Kmv-ts"}"#,
    r#"{"kty":"oct","k":"X8EwrK_w_mNZySX8TCh4Bw"}"#,
    r#"{"kty":"oct","k":"2NdU7GIWhcWSb-BBh18Luh6UTRiFSZMrcFs5t9TboHA"}"#,
];

/// The PBES2 iteration budget of every JWE harness: RFC 7518 §4.8.1.2's
/// minimum, low for throughput (ADR 0036 §2).
pub const PBES2_BUDGET: u32 = 1000;

// --- JWT keys -------------------------------------------------------------

/// The conformance JWT HS256 key (32 octets).
pub const JWT_OCT: &str = r#"{"kty":"oct","k":"2NdU7GIWhcWSb-BBh18Luh6UTRiFSZMrcFs5t9TboHA"}"#;
/// A JWK Set of four keys of four families (conformance `jwt/`).
pub const JWT_SET: &str = r#"{"keys":[{"kty":"oct","k":"2NdU7GIWhcWSb-BBh18Luh6UTRiFSZMrcFs5t9TboHA"},{"kty":"EC","crv":"P-384","x":"YU4rRUzdmVqmRtWOs2OpDE_T5fsNIodcG8G5FWPrTPMyxpzsSOGaQLpe2FpxBmu2","y":"A8-yxCHxkfBz3hKZfI1jUYMjUhsEveZ9THuwFjH2sCNdtksRJU7D5-SkgaFL1ETP"},{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"},{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}"#;
/// The A128KW key of the conformance nested JWTs.
pub const JWT_KEK: &str = r#"{"kty":"oct","k":"X8EwrK_w_mNZySX8TCh4Bw"}"#;
/// The clocks of the raw JWT target, chosen by the input's clock byte: the
/// two `now` values most conformance JWT vectors use.
pub const JWT_CLOCKS: [i64; 2] = [1_300_819_320, 1_700_000_000];
