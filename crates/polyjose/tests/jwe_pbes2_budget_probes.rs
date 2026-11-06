//! Adversarial probes of the per-token PBES2 budget (F07, ADR 0050 §2):
//! mixed algorithms, huge `p2c`, `kid` narrowing and the exact-remainder
//! edge, through the public API. Derivation counts are asserted by the
//! crate-internal unit tests; here the observable is which recipient wins.
#![allow(clippy::panic)] // test code: a panic is a failed assertion

use polyjose::Error;
use polyjose::header::Header;
use polyjose::jwa::{ContentEncAlg as E, KeyMgmtAlg as A};
use polyjose::jwe::{DecryptPolicy, Encryptor, JsonForm, Recipient, decrypt_json};
use polyjose::jwk::Jwk;
use polyjose::util::b64url_encode;

fn oct(k: &[u8], kid: Option<&str>) -> Jwk {
    let kid = kid.map_or(String::new(), |k| format!(r#","kid":"{k}""#));
    let json = format!(r#"{{"kty":"oct","k":"{}"{kid}}}"#, b64url_encode(k));
    Jwk::from_json(json.as_bytes()).unwrap_or_else(|e| panic!("{e}"))
}

fn policy(algs: &[A]) -> DecryptPolicy {
    DecryptPolicy::new(algs, &[E::A128GCM]).unwrap_or_else(|e| panic!("{e}"))
}

fn enc(e: Encryptor) -> String {
    e.encrypt_json(b"probe", JsonForm::General)
        .unwrap_or_else(|e| panic!("{e}"))
}

#[test]
fn non_pbes2_recipients_spend_no_budget() {
    // 6 A128KW + 6 A128GCMKW recipients (wrong key for the password-shaped
    // key), then the correct PBES2 recipient of p2c 1000 under a budget of
    // exactly 1000: it fits only if nothing before it spent budget.
    let other = oct(&[7u8; 16], None);
    let pw = oct(b"correct", None);
    let mut e = Encryptor::new(E::A128GCM);
    for _ in 0..6 {
        e = e.recipient(Recipient::new(A::A128KW, &other));
    }
    for _ in 0..6 {
        e = e.recipient(Recipient::new(A::A128GCMKW, &other));
    }
    e = e.recipient(Recipient::new(A::Pbes2Hs256A128KW, &pw).p2c(1000));
    let token = enc(e);
    let p = policy(&[A::A128KW, A::A128GCMKW, A::Pbes2Hs256A128KW]).max_pbes2_count(1000);
    let out = decrypt_json(&token, &pw, &p).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(out.recipient(), 12);
    // One short: uniform DecryptionFailed.
    let short = p.clone().max_pbes2_count(999);
    assert_eq!(
        decrypt_json(&token, &pw, &short).map(|_| ()),
        Err(Error::DecryptionFailed)
    );
}

#[test]
fn a_huge_p2c_decoy_spends_nothing_and_never_overflows() {
    let pw = oct(b"correct", None);
    let decoy = oct(b"decoy", None);
    for huge in ["4294967295", "4294967296", "9007199254740991"] {
        let token = enc(Encryptor::new(E::A128GCM)
            .recipient(Recipient::new(A::Pbes2Hs256A128KW, &decoy).p2c(1000))
            .recipient(Recipient::new(A::Pbes2Hs256A128KW, &decoy).p2c(1000))
            .recipient(Recipient::new(A::Pbes2Hs256A128KW, &pw).p2c(1000)));
        // Rewrite the first two recipients' p2c to a huge value.
        let bad = token.replacen(r#""p2c":1000"#, &format!(r#""p2c":{huge}"#), 2);
        assert_ne!(bad, token, "p2c not found in per-recipient header");
        // Even with the maximum policy budget the huge ones must not fit or
        // wrap the total; the real recipient still decrypts at exactly 1000.
        for budget in [1000, DecryptPolicy::MAX_PBES2_COUNT_CEILING, u32::MAX] {
            let p = policy(&[A::Pbes2Hs256A128KW]).max_pbes2_count(budget);
            let out = decrypt_json(&bad, &pw, &p);
            match out {
                Ok(d) => assert_eq!(d.recipient(), 2, "{huge} budget {budget}"),
                Err(e) => panic!("{huge} budget {budget}: {e}"),
            }
        }
    }
}

#[test]
fn kid_narrows_the_pbes2_candidates() {
    // 16 recipients with distinct kids: a key with kid k12 tries only #12,
    // so the default budget is ample even with p2c 5000 each (16x would be
    // 80,000).
    let mut e = Encryptor::new(E::A128GCM);
    for i in 0..16 {
        let k = oct(format!("pw{i}").as_bytes(), Some(&format!("k{i}")));
        let h = Header::from_json(format!(r#"{{"kid":"k{i}"}}"#).as_bytes())
            .unwrap_or_else(|e| panic!("{e}"));
        e = e.recipient(Recipient::new(A::Pbes2Hs256A128KW, &k).p2c(5000).header(h));
    }
    let token = enc(e);
    let key = oct(b"pw12", Some("k12"));
    let out = decrypt_json(&token, &key, &policy(&[A::Pbes2Hs256A128KW]))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(out.recipient(), 12);
}

#[test]
fn the_budget_is_not_carried_between_calls() {
    let pw = oct(b"correct", None);
    let token = enc(Encryptor::new(E::A128GCM)
        .recipient(Recipient::new(A::Pbes2Hs256A128KW, &oct(b"d", None)).p2c(1000))
        .recipient(Recipient::new(A::Pbes2Hs256A128KW, &pw).p2c(1000)));
    let p = policy(&[A::Pbes2Hs256A128KW]).max_pbes2_count(2000);
    for _ in 0..3 {
        assert!(decrypt_json(&token, &pw, &p).is_ok());
    }
    let tight = policy(&[A::Pbes2Hs256A128KW]).max_pbes2_count(1999);
    assert_eq!(
        decrypt_json(&token, &pw, &tight).map(|_| ()),
        Err(Error::DecryptionFailed)
    );
}

#[test]
fn p2c_at_or_above_2_pow_53_is_refused_at_the_header_not_the_budget() {
    // I-JSON integers stop at 2^53 - 1: the token is InvalidHeader, never a
    // wrapped budget total.
    let pw = oct(b"correct", None);
    let token =
        enc(Encryptor::new(E::A128GCM)
            .recipient(Recipient::new(A::Pbes2Hs256A128KW, &pw).p2c(1000)));
    for huge in ["9007199254740992", "18446744073709551615"] {
        let bad = token.replacen(r#""p2c":1000"#, &format!(r#""p2c":{huge}"#), 1);
        assert_ne!(bad, token);
        let p = policy(&[A::Pbes2Hs256A128KW]).max_pbes2_count(u32::MAX);
        assert!(decrypt_json(&bad, &pw, &p).is_err(), "{huge}");
    }
}
