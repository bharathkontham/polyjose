//! Engine checks of the WASM adapter under wasm-bindgen-test (0006 T02; ADR 0008 layer 4,
//! ADR 0031 §3): the run is in the engine it was built for, and the OS CSPRNG is wired.
//!
//! Run with `wasm-pack test --node` and `wasm-pack test --headless --chrome --features browser`
//! (`bindings/wasm/test.sh`).
//!
//! **Randomness (ADR 0005).** polyjose draws every key, CEK, IV, salt and ephemeral key from
//! `getrandom::fill`, which on `wasm32-unknown-unknown` is `crypto.getRandomValues` through the
//! adapter's `wasm_js` backend (bindings/wasm/Cargo.toml). Two generated keys and two encryptions
//! of the same plaintext under the same key must differ in both engines; without a working
//! backend the calls fail instead. Equal outputs would mean a constant or repeating source, which
//! for AES-GCM IVs breaks confidentiality and authenticity (RFC 7518 §5.3, NIST SP 800-38D §8).
#![cfg(target_arch = "wasm32")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

mod common;

use js_sys::{Array, Object, Reflect, Uint8Array};
use polyjose_wasm::{jwe, keys};
use wasm_bindgen::JsValue;
use wasm_bindgen_test::wasm_bindgen_test;

#[cfg(feature = "browser")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

/// A plain object with these members.
fn object(members: &[(&str, JsValue)]) -> JsValue {
    let o = Object::new();
    for (key, value) in members {
        Reflect::set(&o, &JsValue::from_str(key), value).unwrap();
    }
    o.into()
}

fn strings(items: &[&str]) -> JsValue {
    items
        .iter()
        .map(|s| JsValue::from_str(s))
        .collect::<Array>()
        .into()
}

#[wasm_bindgen_test]
fn the_run_is_in_the_engine_it_was_built_for() {
    let agent = common::check_engine().unwrap_or_else(|e| panic!("{e}"));
    assert!(!agent.is_empty());
}

#[wasm_bindgen_test]
fn generated_keys_differ() {
    for _ in 0..2 {
        let a = String::from(keys::jwk_generate_ec("P-256").unwrap());
        let b = String::from(keys::jwk_generate_ec("P-256").unwrap());
        assert_ne!(a, b, "two P-256 keys are equal (RFC 7518 §6.2.2)");
    }
    let a = String::from(keys::jwk_generate_okp("Ed25519").unwrap());
    let b = String::from(keys::jwk_generate_okp("Ed25519").unwrap());
    assert_ne!(a, b, "two Ed25519 keys are equal (RFC 8037 §2)");
    let a = String::from(keys::jwk_generate_oct(32).unwrap());
    let b = String::from(keys::jwk_generate_oct(32).unwrap());
    assert_ne!(a, b, "two oct keys are equal (RFC 7518 §6.4)");
}

#[wasm_bindgen_test]
fn encryptions_of_one_plaintext_differ_and_decrypt() {
    let plaintext = b"the same plaintext, twice".to_vec();
    // A random CEK (A128KW) and a random IV (A128GCM) per encryption (RFC 7516 §5.1 steps 2, 9).
    let key = String::from(keys::jwk_generate_for_alg("A128KW").unwrap());
    let options = object(&[
        ("enc", "A128GCM".into()),
        (
            "recipients",
            [object(&[
                ("alg", "A128KW".into()),
                ("key", key.as_str().into()),
            ])]
            .iter()
            .collect::<Array>()
            .into(),
        ),
    ]);
    let a = jwe::jwe_encrypt_compact(plaintext.clone(), &options).unwrap();
    let b = jwe::jwe_encrypt_compact(plaintext.clone(), &options).unwrap();
    let parts = |jwe: &str| jwe.split('.').map(str::to_owned).collect::<Vec<_>>();
    let (pa, pb) = (parts(&a), parts(&b));
    assert_eq!((pa.len(), pb.len()), (5, 5), "compact JWEs (RFC 7516 §7.1)");
    assert_ne!(pa[1], pb[1], "the same wrapped CEK twice");
    assert_ne!(pa[2], pb[2], "the same IV twice");
    let policy = object(&[
        ("allowedAlgs", strings(&["A128KW"])),
        ("allowedEnc", strings(&["A128GCM"])),
    ]);
    for token in [a, b] {
        let decrypted = jwe::jwe_decrypt_compact(token, key.clone(), &policy).unwrap();
        let got = Reflect::get(&decrypted, &JsValue::from_str("plaintext")).unwrap();
        assert_eq!(Uint8Array::from(got).to_vec(), plaintext);
    }
}
