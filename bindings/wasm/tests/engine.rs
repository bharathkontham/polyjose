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
//! Without a source the calls fail closed with `RandomnessUnavailable` (no fallback, ADR 0005), and
//! work again once `crypto` is back (0006 review S5).
//!
//! **Results are own data (0006 review S1, audit I2).** Every record result and the thrown error's
//! `code` are own data properties whatever `Object.prototype` holds (BACKEND.md "Results",
//! ECMA-262 §10.1.9 OrdinarySet, §7.3.8 DefinePropertyOrThrow): with an accessor or a read-only
//! member planted there for `payload`, `plaintext`, `aad`, `signatureIndex`, `claims` or `code`,
//! no inherited setter ever sees a value and every member is still own, with the right value.
//!
//! **Fresh outputs (BACKEND.md "never return an input array").** Byte results are new
//! `Uint8Array`s: never a caller's buffer, never a view of the module's linear memory.
//!
//! **Tampering with globals.** These tests change `Object.prototype` and `globalThis.crypto` and
//! put back exactly what was there before they assert anything ([`with_member`]): wasm32 panics
//! abort without unwinding, so a `Drop` guard would never run, and the planted window runs only
//! code that returns `Result`s.
#![cfg(target_arch = "wasm32")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

mod common;

use std::cell::RefCell;
use std::rc::Rc;

use js_sys::{Array, Object, Reflect, Uint8Array};
use polyjose_wasm::{jwe, jws, jwt, keys, util};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
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

// --- Tampered globals: helpers ----------------------------------------------------------------

/// A prototype-less object with these own members: a record as the facade passes it
/// (BACKEND.md "Records", 0013 F04), or a property descriptor that no `Object.prototype` member
/// can change (ECMA-262 §6.2.6.5 ToPropertyDescriptor reads through the prototype chain).
fn bare(members: &[(&str, JsValue)]) -> Object {
    let o = Object::create(JsValue::NULL.unchecked_ref());
    for (key, value) in members {
        assert!(Reflect::set(&o, &JsValue::from_str(key), value).unwrap());
    }
    o
}

/// The realm's `Object.prototype`.
fn object_prototype() -> Object {
    Object::get_prototype_of(&Object::new())
}

/// The own descriptor of `target[key]` as a prototype-less copy, or `None` if it has no own member.
fn own_descriptor(target: &Object, key: &str) -> Option<Object> {
    let d = Object::get_own_property_descriptor(target, &JsValue::from_str(key));
    if d.is_undefined() {
        return None;
    }
    let d: Object = d.unchecked_into();
    let fields = [
        "value",
        "writable",
        "get",
        "set",
        "enumerable",
        "configurable",
    ]
    .into_iter()
    .filter(|f| Object::has_own(&d, &JsValue::from_str(f)))
    .map(|f| (f, Reflect::get(&d, &JsValue::from_str(f)).unwrap()))
    .collect::<Vec<_>>();
    Some(bare(&fields))
}

/// Defines `target[key]` with `descriptor`, runs `run`, then puts back exactly what was there (the
/// old own descriptor, or no own member) and checks that it did, and only then returns.
///
/// wasm32 panics abort without unwinding, so `run` must not panic: it returns what it saw and the
/// caller asserts after this returns. Nothing here panics between planting and restoring.
fn with_member<T>(target: &Object, key: &str, descriptor: &Object, run: impl FnOnce() -> T) -> T {
    let name = JsValue::from_str(key);
    let previous = own_descriptor(target, key);
    let planted = Reflect::define_property(target, &name, descriptor);
    let out = matches!(planted, Ok(true)).then(run);
    let restored = match &previous {
        Some(d) => Reflect::define_property(target, &name, d),
        None => Reflect::delete_property(target, &name),
    };
    assert!(matches!(restored, Ok(true)), "could not restore `{key}`");
    let now = own_descriptor(target, key);
    assert_eq!(
        now.is_some(),
        previous.is_some(),
        "`{key}` is not as it was before the test"
    );
    out.unwrap_or_else(|| panic!("could not define `{key}` for the test"))
}

/// `a` and `b` are the same JS value; `Uint8Array`s by content.
fn same(a: &JsValue, b: &JsValue) -> bool {
    match (a.dyn_ref::<Uint8Array>(), b.dyn_ref::<Uint8Array>()) {
        (Some(a), Some(b)) => a.to_vec() == b.to_vec(),
        _ => a == b,
    }
}

/// `o[key]` if `o` owns it as a writable, configurable data property with this `enumerable`;
/// otherwise a failed assertion naming what is wrong.
fn own_data(o: &Object, key: &str, enumerable: bool, at: &str) -> JsValue {
    let d = own_descriptor(o, key).unwrap_or_else(|| panic!("{at}: `{key}` is not an own member"));
    let field = |f: &str| Reflect::get(&d, &JsValue::from_str(f)).unwrap();
    assert!(
        Object::has_own(&d, &JsValue::from_str("value")),
        "{at}: `{key}` is an accessor, not a data member"
    );
    assert_eq!(
        field("writable"),
        JsValue::TRUE,
        "{at}: `{key}` is not writable"
    );
    assert_eq!(
        field("configurable"),
        JsValue::TRUE,
        "{at}: `{key}` is not configurable"
    );
    assert_eq!(
        field("enumerable"),
        JsValue::from_bool(enumerable),
        "{at}: `{key}` enumerable"
    );
    field("value")
}

// --- Results and the error code are own data (S1) ------------------------------------------------

/// The RFC 7515 Appendix A.1 HMAC key (§A.1.1).
const HS256_KEY: &str = r#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#;
/// The RFC 7516 Appendix A.3 key (§A.3.3): 128 bits, used here as an A128GCM `dir` key.
const A128_KEY: &str = r#"{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}"#;
/// What a planted `Object.prototype` member returns or holds.
const DECOY: &str = "planted on Object.prototype";
/// The members the guard plants: every secret or required member a result could lose to an
/// inherited setter or read-only member, and the error `code` (0006 review S1).
const PLANTED: [&str; 6] = [
    "payload",
    "plaintext",
    "aad",
    "signatureIndex",
    "claims",
    "code",
];

/// Tokens and records made before anything is planted.
struct Fixture {
    other_key: String,
    jws_compact: String,
    jws_flattened: String,
    jwe_compact: String,
    jwe_flattened: String,
    jwt: String,
    nested: String,
    jws_options: JsValue,
    jwe_options: JsValue,
    jwt_options: JsValue,
}

fn fixture() -> Fixture {
    let payload = b"own data, whatever the prototype holds".to_vec();
    let protected = || JsValue::from_str(r#"{"alg":"HS256"}"#);
    let dir = || {
        [bare(&[("alg", "dir".into()), ("key", A128_KEY.into())])]
            .iter()
            .collect::<Array>()
    };
    let jwe_compact = jwe::jwe_encrypt_compact(
        payload.clone(),
        &bare(&[("enc", "A128GCM".into()), ("recipients", dir().into())]),
    )
    .unwrap();
    // RFC 7516 §5.1 step 14: the JSON serialization's `aad`, returned by decryption (§5.2).
    let jwe_flattened = jwe::jwe_encrypt_json(
        payload.clone(),
        &bare(&[
            ("enc", "A128GCM".into()),
            ("recipients", dir().into()),
            ("aad", Uint8Array::from(&b"additional data"[..]).into()),
        ]),
        "flattened",
    )
    .unwrap();
    let jwt = String::from(
        jwt::jwt_sign(
            r#"{"sub":"alice"}"#.into(),
            HS256_KEY.into(),
            &bare(&[("alg", "HS256".into())]),
        )
        .unwrap(),
    );
    let nested = jwt::jwt_encrypt_nested(
        jwt.clone(),
        &bare(&[("enc", "A128GCM".into()), ("recipients", dir().into())]),
    )
    .unwrap();
    Fixture {
        other_key: String::from(keys::jwk_generate_oct(64).unwrap()),
        jws_compact: String::from(
            jws::jws_sign_compact(
                payload.clone(),
                HS256_KEY.into(),
                &bare(&[("protectedHeader", protected())]),
            )
            .unwrap(),
        ),
        jws_flattened: String::from(
            jws::jws_sign_flattened(
                payload,
                &bare(&[("key", HS256_KEY.into()), ("protectedHeader", protected())]),
                false,
            )
            .unwrap(),
        ),
        jwe_compact,
        jwe_flattened,
        jwt,
        nested,
        jws_options: bare(&[("allowedAlgs", strings(&["HS256"]))]).into(),
        jwe_options: bare(&[
            ("allowedAlgs", strings(&["dir"])),
            ("allowedEnc", strings(&["A128GCM"])),
        ])
        .into(),
        // RFC 7519 §4.1.4: no `exp` in the claims, allowed explicitly; `now` from the caller
        // (ADR 0028: the adapter reads no clock).
        jwt_options: bare(&[
            ("allowedAlgs", strings(&["HS256"])),
            ("now", JsValue::from_f64(1_700_000_000.0)),
            ("allowMissingExp", JsValue::TRUE),
        ])
        .into(),
    }
}

/// The outcome of each record-returning export, by name.
type Results = Vec<(&'static str, Result<Object, JsValue>)>;
/// The error each failing call threw, by name.
type Errors = Vec<(&'static str, JsValue)>;

/// One run of every export whose result or error the guard checks. Never panics (see
/// [`with_member`]): every outcome is returned as it came.
fn run_exports(f: &Fixture) -> (Results, Errors) {
    let results = vec![
        (
            "jwsVerifyCompact",
            jws::jws_verify_compact(f.jws_compact.clone(), HS256_KEY.into(), &f.jws_options),
        ),
        (
            "jwsVerifyJson",
            jws::jws_verify_json(f.jws_flattened.clone(), HS256_KEY.into(), &f.jws_options),
        ),
        (
            "jweDecryptCompact",
            jwe::jwe_decrypt_compact(f.jwe_compact.clone(), A128_KEY.into(), &f.jwe_options),
        ),
        (
            "jweDecryptJson",
            jwe::jwe_decrypt_json(f.jwe_flattened.clone(), A128_KEY.into(), &f.jwe_options),
        ),
        (
            "jwtVerify",
            jwt::jwt_verify(f.jwt.clone(), HS256_KEY.into(), &f.jwt_options),
        ),
        (
            "jwtDecryptNested",
            jwt::jwt_decrypt_nested(
                f.nested.clone(),
                A128_KEY.into(),
                &f.jwe_options,
                HS256_KEY.into(),
                &f.jwt_options,
            ),
        ),
    ];
    let errors = vec![
        (
            "base64urlDecode",
            util::base64url_decode("not base64url!".into()).map_or_else(|e| e, JsValue::from),
        ),
        (
            "jwsVerifyCompact (wrong key)",
            jws::jws_verify_compact(f.jws_compact.clone(), f.other_key.clone(), &f.jws_options)
                .map_or_else(|e| e, JsValue::from),
        ),
    ];
    (results, errors)
}

/// `got` has exactly the own members of `want`, each an own enumerable data member with the same
/// value; a nested result (`inner`) is compared the same way.
fn same_result(got: &Object, want: &Object, at: &str) {
    let keys = |o: &Object| {
        let mut k: Vec<String> = Object::keys(o)
            .iter()
            .filter_map(|k| k.as_string())
            .collect();
        k.sort();
        k
    };
    for key in keys(want) {
        let w = Reflect::get(want, &JsValue::from_str(&key)).unwrap();
        let g = own_data(got, &key, true, at);
        if w.is_object() && !w.is_instance_of::<Uint8Array>() {
            same_result(
                &g.unchecked_into(),
                &w.unchecked_into(),
                &format!("{at}.{key}"),
            );
        } else {
            assert!(same(&g, &w), "{at}: `{key}` has the wrong value");
        }
    }
    assert_eq!(keys(got), keys(want), "{at}: other own members");
}

/// The error is a JS `Error` named `PolyjoseError` that owns `code` (and `name`) as
/// non-enumerable data, the core's code (ADR 0030 §5).
fn same_error(got: &JsValue, want: &JsValue, at: &str) {
    assert!(got.is_instance_of::<js_sys::Error>(), "{at}: not an Error");
    let got: &Object = got.unchecked_ref();
    let want_code = Reflect::get(want, &JsValue::from_str("code")).unwrap();
    assert!(
        want_code.is_string(),
        "{at}: the baseline error has no code"
    );
    assert_eq!(
        own_data(got, "code", false, at),
        want_code,
        "{at}: own code"
    );
    assert_eq!(
        Reflect::get(got, &JsValue::from_str("code")).unwrap(),
        want_code,
        "{at}: e.code"
    );
    assert_eq!(
        own_data(got, "name", false, at),
        JsValue::from_str("PolyjoseError"),
        "{at}: own name"
    );
}

/// How a member is planted on `Object.prototype`.
#[derive(Clone, Copy)]
enum Plant {
    /// A getter returning [`DECOY`] and a setter that records what it receives.
    Accessor,
    /// `{ value: DECOY, writable: false }`: an OrdinarySet of that name returns `false`
    /// (ECMA-262 §10.1.9.2 step 2.a).
    ReadOnly,
}

impl Plant {
    fn name(self) -> &'static str {
        match self {
            Self::Accessor => "an accessor",
            Self::ReadOnly => "a read-only data member",
        }
    }
}

#[wasm_bindgen_test]
fn results_and_the_error_code_are_own_data_whatever_object_prototype_holds() {
    let f = fixture();
    let (want_results, want_errors) = run_exports(&f);
    let want_results: Vec<(&str, Object)> = want_results
        .into_iter()
        .map(|(at, r)| {
            (
                at,
                r.unwrap_or_else(|_| panic!("{at} failed without tampering")),
            )
        })
        .collect();
    // Every planted member is a member of at least one result, or the error code.
    for key in PLANTED.iter().filter(|k| **k != "code") {
        let in_some = want_results.iter().any(|(_, r)| {
            Object::has_own(r, &JsValue::from_str(key))
                || Reflect::get(r, &JsValue::from_str("inner")).is_ok_and(|i| {
                    i.is_object() && Reflect::has(&i, &JsValue::from_str(key)).unwrap()
                })
        });
        assert!(
            in_some,
            "no result has `{key}`, so planting it would test nothing"
        );
    }

    let proto = object_prototype();
    for key in PLANTED {
        for plant in [Plant::Accessor, Plant::ReadOnly] {
            let at = format!("{} on Object.prototype.{key}", plant.name());
            let received = Rc::new(RefCell::new(Vec::<JsValue>::new()));
            let log = Rc::clone(&received);
            let getter = Closure::<dyn FnMut() -> JsValue>::new(|| JsValue::from_str(DECOY));
            let setter = Closure::<dyn FnMut(JsValue)>::new(move |v| log.borrow_mut().push(v));
            let descriptor = match plant {
                Plant::Accessor => bare(&[
                    ("get", getter.as_ref().clone()),
                    ("set", setter.as_ref().clone()),
                    ("configurable", JsValue::TRUE),
                ]),
                Plant::ReadOnly => bare(&[
                    ("value", DECOY.into()),
                    ("writable", JsValue::FALSE),
                    ("configurable", JsValue::TRUE),
                ]),
            };
            let (results, errors) = with_member(&proto, key, &descriptor, || run_exports(&f));

            assert!(
                received.borrow().is_empty(),
                "{at}: its setter received {} value(s) from the adapter",
                received.borrow().len()
            );
            for ((op, got), (_, want)) in results.iter().zip(&want_results) {
                let got = got.as_ref().unwrap_or_else(|_| panic!("{at}: {op} failed"));
                same_result(got, want, &format!("{at}: {op}"));
            }
            for ((op, got), (_, want)) in errors.iter().zip(&want_errors) {
                same_error(got, want, &format!("{at}: {op}"));
            }
        }
    }
}

// --- No RNG fallback (S5, ADR 0005) -----------------------------------------------------------

/// Every key generator, over each name it takes, and one encryption of each kind of random
/// value: a CEK (A128KW, RFC 7516 §5.1 step 2) and an IV (A128GCM, RFC 7518 §5.3). Never panics.
fn draw_randomness() -> Vec<(String, Result<(), JsValue>)> {
    let mut out: Vec<(String, Result<(), JsValue>)> = Vec::new();
    let mut push = |what: String, r: Result<(), JsValue>| out.push((what, r));
    push(
        "jwkGenerateOct(32)".into(),
        keys::jwk_generate_oct(32).map(drop),
    );
    for crv in ["P-256", "P-384", "P-521", "secp256k1"] {
        push(
            format!("jwkGenerateEc({crv})"),
            keys::jwk_generate_ec(crv).map(drop),
        );
    }
    for crv in ["Ed25519", "X25519"] {
        push(
            format!("jwkGenerateOkp({crv})"),
            keys::jwk_generate_okp(crv).map(drop),
        );
    }
    for alg in ["HS256", "A128KW", "A128GCM", "ES256", "EdDSA"] {
        push(
            format!("jwkGenerateForAlg({alg})"),
            keys::jwk_generate_for_alg(alg).map(drop),
        );
    }
    for (alg, key) in [("dir", A128_KEY), ("A128KW", A128_KEY)] {
        let recipients = [bare(&[("alg", alg.into()), ("key", key.into())])]
            .iter()
            .collect::<Array>();
        let options = bare(&[("enc", "A128GCM".into()), ("recipients", recipients.into())]);
        push(
            format!("jweEncryptCompact({alg}, A128GCM)"),
            jwe::jwe_encrypt_compact(b"plaintext".to_vec(), &options).map(drop),
        );
    }
    out
}

#[wasm_bindgen_test]
fn without_crypto_get_random_values_every_draw_fails_closed_and_works_again_after() {
    let global: Object = js_sys::global();
    let crypto: Object = Reflect::get(&global, &JsValue::from_str("crypto"))
        .unwrap()
        .dyn_into()
        .unwrap_or_else(|_| panic!("globalThis.crypto is not an object"));
    let thrower = Closure::<dyn FnMut(JsValue) -> Result<JsValue, JsValue>>::new(|_| {
        Err(js_sys::Error::new("no randomness here").into())
    });
    let cases = [
        (
            "crypto.getRandomValues throws",
            &crypto,
            "getRandomValues",
            thrower.as_ref().clone(),
        ),
        (
            "globalThis.crypto is undefined",
            &global,
            "crypto",
            JsValue::UNDEFINED,
        ),
    ];
    for (case, target, key, value) in cases {
        let descriptor = bare(&[
            ("value", value),
            ("writable", JsValue::TRUE),
            ("configurable", JsValue::TRUE),
        ]);
        let outcomes = with_member(target, key, &descriptor, draw_randomness);
        for (what, outcome) in outcomes {
            let e = outcome
                .err()
                .unwrap_or_else(|| panic!("{case}: {what} succeeded"));
            assert!(
                e.is_instance_of::<js_sys::Error>(),
                "{case}: {what}: not an Error"
            );
            assert_eq!(
                Reflect::get(&e, &JsValue::from_str("name")).unwrap(),
                JsValue::from_str("PolyjoseError"),
                "{case}: {what}: name"
            );
            assert_eq!(
                Reflect::get(&e, &JsValue::from_str("code")).unwrap(),
                JsValue::from_str("RandomnessUnavailable"),
                "{case}: {what}: code (ADR 0005: fail closed, no fallback)"
            );
        }
        for (what, outcome) in draw_randomness() {
            assert!(
                outcome.is_ok(),
                "{what} fails after `{key}` was restored ({case})"
            );
        }
    }
}

// --- Fresh outputs (S5) -----------------------------------------------------------------------

/// The `ArrayBuffer` behind the module's linear memory, now (it is replaced when memory grows).
fn linear_memory() -> JsValue {
    Reflect::get(&wasm_bindgen::memory(), &JsValue::from_str("buffer")).unwrap()
}

/// `bytes` owns a whole `ArrayBuffer` of its own: not one of `others`, not linear memory.
fn fresh(bytes: &Uint8Array, others: &[&Uint8Array], at: &str) {
    let buffer = bytes.buffer();
    assert!(
        !Object::is(&buffer, &linear_memory()),
        "{at}: a view of linear memory"
    );
    for other in others {
        assert!(
            !Object::is(&buffer, &other.buffer()),
            "{at}: shares a buffer with an input or another output"
        );
    }
    assert_eq!(bytes.byte_offset(), 0, "{at}: a view into a larger buffer");
    assert_eq!(
        buffer.byte_length(),
        bytes.length(),
        "{at}: a view into a larger buffer"
    );
}

#[wasm_bindgen_test]
fn byte_results_are_fresh_arrays_never_an_input_or_linear_memory() {
    let payload = b"a detached payload (RFC 7515 Appendix F)".to_vec();
    let token = String::from(
        jws::jws_sign_compact(
            payload.clone(),
            HS256_KEY.into(),
            &bare(&[
                ("protectedHeader", r#"{"alg":"HS256"}"#.into()),
                ("detached", JsValue::TRUE),
            ]),
        )
        .unwrap(),
    );
    let input = Uint8Array::from(&payload[..]);
    let options = bare(&[
        ("allowedAlgs", strings(&["HS256"])),
        ("detachedPayload", input.clone().into()),
    ]);
    let verified = jws::jws_verify_compact(token, HS256_KEY.into(), &options).unwrap();
    let out: Uint8Array = Reflect::get(&verified, &JsValue::from_str("payload"))
        .unwrap()
        .unchecked_into();
    assert_eq!(out.to_vec(), payload);
    fresh(&out, &[&input], "jwsVerifyCompact detached payload");
    out.fill(0, 0, out.length());
    assert_eq!(
        input.to_vec(),
        payload,
        "writing the result changed the input"
    );

    let a = util::base64url_decode("AAECAwQFBgcICQ".into()).unwrap();
    let b = util::base64url_decode("AAECAwQFBgcICQ".into()).unwrap();
    assert_eq!(a.to_vec(), (0u8..10).collect::<Vec<_>>());
    fresh(&a, &[&b], "base64urlDecode");

    let jwk = String::from(keys::jwk_generate_okp("Ed25519").unwrap());
    let a = keys::jwk_to_der(jwk.clone(), "pkcs8").unwrap();
    let b = keys::jwk_to_der(jwk, "pkcs8").unwrap();
    assert_eq!(a.to_vec(), b.to_vec());
    fresh(&a, &[&b], "jwkToDer");
}
