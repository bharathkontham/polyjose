//! Decrypting with a platform-held key (feature 0025 T01; ADR 0071 §2, §4;
//! RFC 7516 §5.2, §11.5; RFC 7518 §4.3, §4.6), through the public API, with
//! the software fake of `platform_support`.
//!
//! - RFC 7520 §5.4 and §5.5 decrypt with the cookbook key behind the fake.
//! - Every ECDH-ES form on P-256, P-384 and P-521, and RSA-OAEP-256 for
//!   2048, 3072 and 4096 bits, round-trips from the existing encrypt, in
//!   compact and JSON and as the outer layer of a nested JWT.
//! - The order of checks: the allow-list and the algorithm set before any
//!   call; the `epk` before `agree`; key binding before the private key.
//! - A wrong Z or CEK, or `Failed`, is one `DecryptionFailed`, the same as
//!   a tampered ciphertext on the JWK path (RFC 7516 §11.5).
//! - `NotFound` and `UserAuthenticationRequired` pass through and stop a
//!   multi-recipient JWE at once (ADR 0071 §4).
//!
//! The "substitute CEK is drawn before `decrypt_key`" proof is a unit test
//! in `src/jwe/rsa_oaep.rs` (its counter exists only under `cfg(test)`).
#![allow(clippy::panic)] // test code: a panic is a failed assertion

mod platform_support;

use platform_support::{Fake, SecretFault, rsa_keys, with};
use polyjose::json::{self, Object, Value};
use polyjose::jwa::{ContentEncAlg, KeyMgmtAlg, SigningAlg};
use polyjose::jwe::{
    DecryptPolicy, Encryptor, JsonForm, Recipient, decrypt_compact,
    decrypt_compact_with_platform_key, decrypt_json_with_platform_key,
};
use polyjose::jwk::{EcCurve, Jwk, JwkSet, OkpCurve};
use polyjose::jwt::{self, Claims, FixedClock, IssueOptions, Keys, NumericDate, Policy};
use polyjose::keys::{KeySpec, generate};
use polyjose::util::{b64url_decode, b64url_encode};
use polyjose::{Error, PlatformKeyError};

use ContentEncAlg as E;
use KeyMgmtAlg as A;

const PLAINTEXT: &[u8] = b"You can't go on with a Ring of Power for ever.";

const ECDH: [KeyMgmtAlg; 4] = [A::EcdhEs, A::EcdhEsA128KW, A::EcdhEsA192KW, A::EcdhEsA256KW];

fn policy(algs: &[KeyMgmtAlg], encs: &[ContentEncAlg]) -> DecryptPolicy {
    DecryptPolicy::new(algs, encs).unwrap_or_else(|e| panic!("{e}"))
}

fn ec_private(crv: EcCurve) -> String {
    generate(KeySpec::Ec(crv))
        .unwrap_or_else(|e| panic!("{e}"))
        .to_json()
        .to_string()
}

fn jwk(json: &str) -> Jwk {
    Jwk::from_json(json.as_bytes()).unwrap_or_else(|e| panic!("{e}: {json}"))
}

fn encryptor(alg: &KeyMgmtAlg, enc: &ContentEncAlg, to: &Jwk) -> Encryptor {
    Encryptor::new(enc.clone()).recipient(Recipient::new(alg.clone(), to))
}

fn compact(alg: &KeyMgmtAlg, enc: &ContentEncAlg, to: &Jwk) -> String {
    encryptor(alg, enc, to)
        .encrypt_compact(PLAINTEXT)
        .unwrap_or_else(|e| panic!("{alg} {enc}: {e}"))
}

fn code<T>(result: polyjose::Result<T>) -> &'static str {
    result.map_or_else(|e| e.code(), |_| "ok")
}

/// The compact JWE `token` with its protected header changed by `edit`.
fn edit_header(token: &str, edit: impl FnOnce(&mut Object)) -> String {
    let (header, rest) = token.split_once('.').unwrap_or_default();
    let decoded = b64url_decode(header).unwrap_or_else(|e| panic!("{e}"));
    let mut object = json::parse(&decoded)
        .ok()
        .and_then(Value::into_object)
        .unwrap_or_default();
    edit(&mut object);
    format!("{}.{rest}", b64url_encode(object.to_json().as_bytes()))
}

/// The `epk` member of a compact JWE's protected header.
fn epk(token: &str) -> Object {
    let header = token.split('.').next().unwrap_or_default();
    let decoded = b64url_decode(header).unwrap_or_else(|e| panic!("{e}"));
    json::parse(&decoded)
        .ok()
        .and_then(|v| v.get("epk").and_then(Value::as_object).cloned())
        .unwrap_or_default()
}

fn member(object: &Object, name: &str) -> Vec<u8> {
    let text = object.get(name).and_then(Value::as_str).unwrap_or_default();
    b64url_decode(text).unwrap_or_else(|e| panic!("{e}"))
}

// ---------------------------------------------------------------------------
// RFC 7520 §5.4 and §5.5
// ---------------------------------------------------------------------------

fn cookbook(file: &str) -> serde_json::Value {
    let path = format!(
        "{}/tests/third_party/ietf-jose-cookbook/jwe/{file}",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{e}"))
}

#[test]
fn rfc7520_5_4_and_5_5_decrypt_through_the_platform_key() {
    for (file, alg, enc) in [
        (
            "5_4.key_agreement_with_key_wrapping_using_ecdh-es_and_aes-keywrap_with_aes-gcm.json",
            A::EcdhEsA128KW,
            E::A128GCM,
        ),
        (
            "5_5.key_agreement_using_ecdh-es_with_aes-cbc-hmac-sha2.json",
            A::EcdhEs,
            E::A128CbcHs256,
        ),
    ] {
        let c = cookbook(file);
        assert_eq!(c["input"]["alg"].as_str(), Some(alg.as_str()));
        assert_eq!(c["input"]["enc"].as_str(), Some(enc.as_str()));
        let key = Fake::new(&c["input"]["key"].to_string(), &[alg.as_str()]);
        let token = c["output"]["compact"].as_str().unwrap_or_default();
        let decrypted = decrypt_compact_with_platform_key(token, &key, &policy(&[alg], &[enc]))
            .unwrap_or_else(|e| panic!("{file}: {e}"));
        assert_eq!(
            decrypted.plaintext(),
            c["input"]["plaintext"]
                .as_str()
                .unwrap_or_default()
                .as_bytes()
        );
        let calls = key.calls();
        assert_eq!((calls.agree, calls.public_jwk, calls.algorithms), (1, 1, 1));
        // `agree` received exactly 0x04 || X || Y of the epk (SEC 1 v2 §2.3.3).
        let epk = epk(token);
        let point = [vec![0x04], member(&epk, "x"), member(&epk, "y")].concat();
        assert_eq!(calls.peers, [point]);
    }
}

// ---------------------------------------------------------------------------
// Round trips
// ---------------------------------------------------------------------------

#[test]
fn every_ecdh_es_form_round_trips_compact_and_json() {
    for crv in [EcCurve::P256, EcCurve::P384, EcCurve::P521] {
        let private = ec_private(crv);
        let key = Fake::new(
            &private,
            &[
                "ECDH-ES",
                "ECDH-ES+A128KW",
                "ECDH-ES+A192KW",
                "ECDH-ES+A256KW",
            ],
        );
        let public = key.public();
        for alg in ECDH {
            for enc in [E::A128GCM, E::A256GCM, E::A128CbcHs256, E::A256CbcHs512] {
                let p = policy(&ECDH, std::slice::from_ref(&enc));
                let token = compact(&alg, &enc, &public);
                let d = decrypt_compact_with_platform_key(&token, &key, &p)
                    .unwrap_or_else(|e| panic!("{crv} {alg} {enc}: {e}"));
                assert_eq!(d.plaintext(), PLAINTEXT);
                for form in [JsonForm::Flattened, JsonForm::General] {
                    let jwe = encryptor(&alg, &enc, &public)
                        .encrypt_json(PLAINTEXT, form)
                        .unwrap_or_else(|e| panic!("{e}"));
                    let d = decrypt_json_with_platform_key(&jwe, &key, &p)
                        .unwrap_or_else(|e| panic!("{crv} {alg} {enc} json: {e}"));
                    assert_eq!(d.plaintext(), PLAINTEXT);
                }
            }
        }
    }
}

#[test]
fn rsa_oaep_256_round_trips_for_2048_3072_and_4096_bits() {
    for private in rsa_keys() {
        let key = Fake::new(&private, &["RSA-OAEP-256"]);
        let public = key.public();
        let p = policy(&[A::RsaOaep256], &[E::A128GCM, E::A256CbcHs512]);
        for enc in [E::A128GCM, E::A256CbcHs512] {
            let token = compact(&A::RsaOaep256, &enc, &public);
            let d = decrypt_compact_with_platform_key(&token, &key, &p)
                .unwrap_or_else(|e| panic!("{enc}: {e}"));
            assert_eq!(d.plaintext(), PLAINTEXT);
            let jwe = encryptor(&A::RsaOaep256, &enc, &public)
                .encrypt_json(PLAINTEXT, JsonForm::General)
                .unwrap_or_else(|e| panic!("{e}"));
            let d = decrypt_json_with_platform_key(&jwe, &key, &p)
                .unwrap_or_else(|e| panic!("{enc} json: {e}"));
            assert_eq!(d.plaintext(), PLAINTEXT);
        }
    }
}

#[test]
fn nested_jwt_outer_layer_decrypts_with_one_key_and_with_a_jwk_set() {
    let signing = jwk(platform_support::RFC7515_A3);
    let verify = signing.to_public().unwrap_or_else(|| panic!("public"));
    let set =
        JwkSet::from_json(format!(r#"{{"keys":[{}]}}"#, verify.to_json().as_str()).as_bytes())
            .unwrap_or_else(|e| panic!("{e}"));
    let mut claims = Claims::new();
    claims.exp = NumericDate::from_secs(2_000_000_000);
    let inner = jwt::sign(&claims, &IssueOptions::new(SigningAlg::ES256), &signing)
        .unwrap_or_else(|e| panic!("{e}"));
    let clock = FixedClock(1_900_000_000);
    let algs = [SigningAlg::ES256];
    let jwt_policy = Policy::new(&clock, &algs).unwrap_or_else(|e| panic!("{e}"));

    let mut outer: Vec<(Fake, KeyMgmtAlg)> = ECDH
        .into_iter()
        .map(|alg| (Fake::new(&ec_private(EcCurve::P256), &[alg.as_str()]), alg))
        .collect();
    outer.push((Fake::new(&rsa_keys()[0], &["RSA-OAEP-256"]), A::RsaOaep256));
    for (key, alg) in &outer {
        let nested = jwt::encrypt_nested(&inner, &encryptor(alg, &E::A256GCM, &key.public()))
            .unwrap_or_else(|e| panic!("{e}"));
        let p = policy(std::slice::from_ref(alg), &[E::A256GCM]);
        for keys in [Keys::One(&verify), Keys::Set(&set)] {
            let verified =
                jwt::decrypt_nested_with_platform_key(&nested, key, &p, keys, &jwt_policy)
                    .unwrap_or_else(|e| panic!("{alg}: {e}"));
            assert_eq!(verified.inner.claims.exp, claims.exp, "{alg}");
        }
    }
}

// ---------------------------------------------------------------------------
// Order of checks
// ---------------------------------------------------------------------------

#[test]
fn an_alg_or_enc_outside_the_policy_never_reaches_the_key() {
    // RFC 8725 §3.1, ADR 0071 §2 item 1: not even public_jwk is called.
    let key = Fake::new(&ec_private(EcCurve::P256), &["ECDH-ES"]);
    let token = compact(&A::EcdhEs, &E::A128GCM, &key.public());
    for p in [
        policy(&[A::RsaOaep256], &[E::A128GCM]),
        policy(&[A::EcdhEs], &[E::A256GCM]),
    ] {
        assert_eq!(
            code(decrypt_compact_with_platform_key(&token, &key, &p)),
            "AlgorithmNotAllowed"
        );
    }
    assert_eq!(key.calls().all(), 0);
}

#[test]
fn symmetric_and_x25519_algorithms_are_unsupported_for_a_platform_key() {
    // ADR 0071 §2: A*KW, A*GCMKW, dir and PBES2 never reach the key.
    let oct = |bytes| generate(KeySpec::Oct { bytes }).unwrap_or_else(|e| panic!("{e}"));
    let password = jwk(r#"{"kty":"oct","k":"ZW50cmFwIG8n6I-dLmFybmF1ZA"}"#);
    let tokens = [
        (A::A128KW, compact(&A::A128KW, &E::A128GCM, &oct(16))),
        (A::A256GCMKW, compact(&A::A256GCMKW, &E::A128GCM, &oct(32))),
        (A::Dir, compact(&A::Dir, &E::A128GCM, &oct(16))),
        (
            A::Pbes2Hs256A128KW,
            compact(&A::Pbes2Hs256A128KW, &E::A128GCM, &password),
        ),
    ];
    let key = Fake::new(&ec_private(EcCurve::P256), &["ECDH-ES"]);
    for (alg, token) in &tokens {
        let p = policy(std::slice::from_ref(alg), &[E::A128GCM]);
        assert_eq!(
            code(decrypt_compact_with_platform_key(token, &key, &p)),
            "UnsupportedAlgorithm",
            "{alg}"
        );
    }
    assert_eq!(key.calls().all(), 0);

    // ECDH-ES on X25519: the curve shows only in the public JWK, so it is
    // read, but the private key is never called.
    let x25519 = generate(KeySpec::Okp(OkpCurve::X25519)).unwrap_or_else(|e| panic!("{e}"));
    let key = Fake::new(&x25519.to_json(), &["ECDH-ES"]);
    let token = compact(&A::EcdhEs, &E::A128GCM, &key.public());
    let p = policy(&[A::EcdhEs], &[E::A128GCM]);
    assert_eq!(
        code(decrypt_compact_with_platform_key(&token, &key, &p)),
        "UnsupportedAlgorithm"
    );
    assert_eq!(key.calls().private(), 0);
}

#[test]
fn unbound_keys_are_key_algorithm_mismatch_without_agree_or_decrypt() {
    let ec = ec_private(EcCurve::P256);
    let ec_token = compact(&A::EcdhEs, &E::A128GCM, &Fake::new(&ec, &[]).public());
    let rsa = rsa_keys()[0].clone();
    let rsa_token = compact(&A::RsaOaep256, &E::A128GCM, &Fake::new(&rsa, &[]).public());
    let p = policy(&[A::EcdhEs, A::RsaOaep256], &[E::A128GCM]);
    let mut cases: Vec<(&str, Fake, String)> = vec![
        (
            "not listed",
            Fake::new(&ec, &["ECDH-ES+A128KW"]),
            ec_token.clone(),
        ),
        (
            "rsa not listed",
            Fake::new(&rsa, &["RS256"]),
            rsa_token.clone(),
        ),
    ];
    // use: sig on a decrypt call (RFC 7517 §4.2).
    let mut key = Fake::new(&ec, &["ECDH-ES"]);
    key.public_json = with(&key.public_json, "use", "sig");
    cases.push(("use sig", key, ec_token.clone()));
    // The JWK alg names another algorithm (RFC 7517 §4.4).
    let mut key = Fake::new(&rsa, &["RSA-OAEP-256"]);
    key.public_json = with(&key.public_json, "alg", "RS256");
    cases.push(("jwk alg", key, rsa_token));
    // The header kid names another key (RFC 7516 §4.1.6).
    let mut key = Fake::new(&ec, &["ECDH-ES"]);
    key.public_json = with(&key.public_json, "kid", "a");
    let kid_token = edit_header(&ec_token, |h| {
        h.insert("kid", "b");
    });
    cases.push(("kid", key, kid_token));
    for (what, key, token) in cases {
        assert_eq!(
            code(decrypt_compact_with_platform_key(&token, &key, &p)),
            "KeyAlgorithmMismatch",
            "{what}"
        );
        assert_eq!(key.calls().private(), 0, "{what}");
    }
}

#[test]
fn a_public_jwk_with_private_members_is_invalid_key() {
    for (private, alg, token_alg) in [
        (ec_private(EcCurve::P384), "ECDH-ES", A::EcdhEs),
        (rsa_keys()[0].clone(), "RSA-OAEP-256", A::RsaOaep256),
    ] {
        let mut key = Fake::new(&private, &[alg]);
        let token = compact(&token_alg, &E::A128GCM, &key.public());
        key.public_json = private.clone();
        let p = policy(std::slice::from_ref(&token_alg), &[E::A128GCM]);
        let err = decrypt_compact_with_platform_key(&token, &key, &p).err();
        let err = err.unwrap_or_else(|| panic!("{alg}: decrypted"));
        assert_eq!(err.code(), "InvalidKey", "{alg}");
        let d = json::parse(private.as_bytes())
            .ok()
            .and_then(|v| v.get("d").and_then(Value::as_str).map(str::to_owned))
            .unwrap_or_default();
        assert!(!err.to_string().contains(&d) && !format!("{err:?}").contains(&d));
        assert_eq!(key.calls().private(), 0);
    }
}

#[test]
fn the_epk_is_validated_before_agree() {
    // RFC 7518 §4.6.1.1, RFC 8725 §3.4, ADR 0071 §4.
    let key = Fake::new(&ec_private(EcCurve::P256), &["ECDH-ES"]);
    let token = compact(&A::EcdhEs, &E::A128GCM, &key.public());
    let p = policy(&[A::EcdhEs], &[E::A128GCM]);
    let epk = epk(&token);
    let mut flipped = member(&epk, "y");
    flipped[31] ^= 1;
    let other = Fake::new(&ec_private(EcCurve::P384), &[])
        .public()
        .to_object();
    type Edit = Box<dyn Fn(&mut Object)>;
    let edits: Vec<(&str, Edit)> = vec![
        (
            "with d",
            Box::new(|e: &mut Object| {
                e.insert("d", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE");
            }),
        ),
        (
            "wrong curve",
            Box::new(move |e: &mut Object| {
                for name in ["crv", "x", "y"] {
                    e.insert(name, other.get(name).cloned().unwrap_or(Value::Null));
                }
            }),
        ),
        (
            "off curve",
            Box::new(move |e: &mut Object| {
                e.insert("y", b64url_encode(&flipped));
            }),
        ),
    ];
    for (what, edit) in edits {
        let tampered = edit_header(&token, |h| {
            let mut epk = h
                .get("epk")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            edit(&mut epk);
            h.insert("epk", epk);
        });
        assert_eq!(
            code(decrypt_compact_with_platform_key(&tampered, &key, &p)),
            "DecryptionFailed",
            "{what}"
        );
        assert_eq!(key.calls().agree, 0, "{what}");
    }
}

#[test]
fn a_wrong_z_or_cek_is_decryption_failed_like_a_tampered_ciphertext() {
    // The JWK path's error for a tampered tag is the reference
    // (RFC 7516 §11.5): same code, same message.
    let rsa = rsa_keys()[0].clone();
    let reference_key = jwk(&rsa);
    let token = compact(&A::RsaOaep256, &E::A128GCM, &reference_key);
    let mut tampered = token.clone();
    let last = tampered.pop().unwrap_or('A');
    tampered.push(if last == 'A' { 'Q' } else { 'A' });
    let p = policy(&[A::RsaOaep256, A::EcdhEs, A::EcdhEsA128KW], &[E::A128GCM]);
    let reference = decrypt_compact(&tampered, &reference_key, &p)
        .err()
        .unwrap_or_else(|| panic!("tampered decrypted"));
    assert_eq!(reference, Error::DecryptionFailed);

    let check = |what: &str, result: polyjose::Result<polyjose::jwe::Decrypted>| {
        let e = result.err().unwrap_or_else(|| panic!("{what}: decrypted"));
        assert_eq!(e, reference, "{what}");
        assert_eq!(e.to_string(), reference.to_string(), "{what}");
    };

    for fault in [SecretFault::Short, SecretFault::Flipped] {
        let mut key = Fake::new(&rsa, &["RSA-OAEP-256"]);
        key.secret_fault = fault;
        check(
            &format!("CEK {fault:?}"),
            decrypt_compact_with_platform_key(&token, &key, &p),
        );
        assert_eq!(key.calls().decrypt_key, 1);
    }
    let mut key = Fake::new(&rsa, &["RSA-OAEP-256"]);
    key.fail_decrypt_key = Some(PlatformKeyError::Failed);
    check(
        "CEK Failed",
        decrypt_compact_with_platform_key(&token, &key, &p),
    );

    for alg in [A::EcdhEs, A::EcdhEsA128KW] {
        let ec = ec_private(EcCurve::P521);
        let ec_token = compact(&alg, &E::A128GCM, &Fake::new(&ec, &[]).public());
        for fault in [SecretFault::Short, SecretFault::Flipped] {
            let mut key = Fake::new(&ec, &[alg.as_str()]);
            key.secret_fault = fault;
            check(
                &format!("{alg} Z {fault:?}"),
                decrypt_compact_with_platform_key(&ec_token, &key, &p),
            );
            assert_eq!(key.calls().agree, 1);
        }
        let mut key = Fake::new(&ec, &[alg.as_str()]);
        key.fail_agree = Some(PlatformKeyError::Failed);
        check(
            &format!("{alg} Z Failed"),
            decrypt_compact_with_platform_key(&ec_token, &key, &p),
        );
    }
}

// ---------------------------------------------------------------------------
// Errors from the key
// ---------------------------------------------------------------------------

#[test]
fn not_found_and_user_authentication_pass_through_from_every_method() {
    use PlatformKeyError as P;
    let ec = ec_private(EcCurve::P256);
    let rsa = rsa_keys()[0].clone();
    let ec_token = compact(&A::EcdhEs, &E::A128GCM, &Fake::new(&ec, &[]).public());
    let rsa_token = compact(&A::RsaOaep256, &E::A128GCM, &Fake::new(&rsa, &[]).public());
    let p = policy(&[A::EcdhEs, A::RsaOaep256], &[E::A128GCM]);
    for (error, expected) in [
        (P::NotFound, "KeyNotFound"),
        (P::UserAuthenticationRequired, "UserAuthenticationRequired"),
        // ADR 0071 §4: every other outcome of a decryption.
        (P::Failed, "DecryptionFailed"),
    ] {
        for method in ["public_jwk", "algorithms", "agree", "decrypt_key"] {
            let (private, alg, token) = if method == "decrypt_key" {
                (&rsa, "RSA-OAEP-256", &rsa_token)
            } else {
                (&ec, "ECDH-ES", &ec_token)
            };
            let mut key = Fake::new(private, &[alg]);
            match method {
                "public_jwk" => key.fail_public_jwk = Some(error),
                "algorithms" => key.fail_algorithms = Some(error),
                "agree" => key.fail_agree = Some(error),
                _ => key.fail_decrypt_key = Some(error),
            }
            assert_eq!(
                code(decrypt_compact_with_platform_key(token, &key, &p)),
                expected,
                "{method} {error:?}"
            );
        }
    }
}

#[test]
fn several_recipients_stop_at_not_found_or_cancel_and_try_all_on_failed() {
    use PlatformKeyError as P;
    let rsa = rsa_keys()[0].clone();
    let public = Fake::new(&rsa, &[]).public();
    let jwe = Encryptor::new(E::A128GCM)
        .recipient(Recipient::new(A::RsaOaep256, &public))
        .recipient(Recipient::new(A::RsaOaep256, &public))
        .recipient(Recipient::new(A::RsaOaep256, &public))
        .encrypt_json(PLAINTEXT, JsonForm::General)
        .unwrap_or_else(|e| panic!("{e}"));
    let p = policy(&[A::RsaOaep256], &[E::A128GCM]);
    for (error, expected, calls) in [
        (P::NotFound, "KeyNotFound", 1),
        (
            P::UserAuthenticationRequired,
            "UserAuthenticationRequired",
            1,
        ),
        (P::Failed, "DecryptionFailed", 3),
    ] {
        let mut key = Fake::new(&rsa, &["RSA-OAEP-256"]);
        key.fail_decrypt_key = Some(error);
        assert_eq!(
            code(decrypt_json_with_platform_key(&jwe, &key, &p)),
            expected,
            "{error:?}"
        );
        let c = key.calls();
        assert_eq!(c.decrypt_key, calls, "{error:?}");
        assert_eq!((c.public_jwk, c.algorithms), (1, 1), "{error:?}");
    }
    // A good key decrypts with the first recipient and calls once.
    let key = Fake::new(&rsa, &["RSA-OAEP-256"]);
    let d = decrypt_json_with_platform_key(&jwe, &key, &p).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!((d.recipient(), key.calls().decrypt_key), (0, 1));

    // Calls never exceed max_recipients: over the bound, none at all.
    let key = Fake::new(&rsa, &["RSA-OAEP-256"]);
    let bounded = policy(&[A::RsaOaep256], &[E::A128GCM]).max_recipients(2);
    assert_eq!(
        code(decrypt_json_with_platform_key(&jwe, &key, &bounded)),
        "InvalidFormat"
    );
    assert_eq!(key.calls().all(), 0);
}
