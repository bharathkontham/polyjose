//! Wycheproof `json_web_encryption_test.json` (C2SP/wycheproof `d17cc89f`,
//! 139 cases) through polyjose's public JWE API (0003 T16; ADR 0008
//! layer 2).
//!
//! The file models a JWE library's compact API (its `JsonSerialization`
//! flag marks a JSON input as a bug for that API), so every case goes to
//! [`decrypt_compact`] with the group's `private` key and a policy that
//! allows every `alg` and `enc` polyjose knows. Each case ends in one of
//! three outcomes:
//!
//! - **accepted:** it decrypts to the expected plaintext (`result: valid`);
//! - **rejected:** it fails with an error other than `UnsupportedAlgorithm`
//!   (`result: invalid`);
//! - **unsupported:** polyjose does not implement its algorithm. Every case
//!   of an RSA group (`jwe_rsa1_5`, `jwe_rsa_oaep`, `jwe_rsa_oaep_256`,
//!   `jwe_rsa_oaep_modified`, and the RSA keys of `rfc_7520`) is
//!   unsupported twice over: the RSA private JWK does not import (no RSA
//!   private-key code, ADR 0021), and decrypting with the group's public
//!   JWK is `UnsupportedAlgorithm` too, because no RSA `alg` decrypts
//!   (RSA-OAEP-256 is encrypt-only, ADR 0021; RSA-OAEP is not implemented,
//!   ADR 0022; RSA1_5 is not implemented, ADR 0021).
//!
//! A `valid` case that is not accepted is a deviation from upstream's
//! `result`. Each one is listed in [`DEVIATIONS`] with its RFC or ADR
//! reason; any other mismatch fails the test. An `invalid` case that is
//! unsupported is still rejected, so it is not a deviation.
//!
//! The counts are asserted exactly, so a change in polyjose's behaviour on
//! any case shows up here.
#![allow(clippy::panic)] // test code: a panic is a failed assertion

mod common;

use std::collections::BTreeMap;

use common::jwe_wycheproof::{self, Expected, Group, Test};
use polyjose::Error;
use polyjose::jwa::{ContentEncAlg, KeyMgmtAlg};
use polyjose::jwe::{DecryptPolicy, decrypt_compact, decrypt_json};
use polyjose::jwk::Jwk;

/// What polyjose did with one case.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// Decrypted, to these bytes.
    Plaintext(Vec<u8>),
    /// Failed with this error code (never `UnsupportedAlgorithm`).
    Rejected(&'static str),
    /// `UnsupportedAlgorithm` (ADR 0006, 0017, 0021, 0022).
    Unsupported,
}

/// The `result: valid` cases polyjose does not accept, and why. Nothing
/// else may differ from upstream's `result`.
const DEVIATIONS: &[(&[u32], &str)] = &[
    (
        &[82, 83, 84, 85, 86, 87, 129],
        "RSA-OAEP (SHA-1) is not implemented (ADR 0022); RSA decryption is not \
         shipped (ADR 0021, RUSTSEC-2023-0071)",
    ),
    (
        &[88, 89, 90, 91, 92, 93, 121],
        "RSA-OAEP-256 is encrypt-only: RSA private-key operations are not \
         shipped (ADR 0021, RUSTSEC-2023-0071)",
    ),
    (
        &[100, 101, 102, 103, 104, 105, 112, 128],
        "RSA1_5 is not implemented (ADR 0021; RFC 8725 §3.2)",
    ),
    #[cfg(not(feature = "deflate"))]
    (
        &[135],
        "zip: DEF needs the off-by-default `deflate` feature (ADR 0017, \
         RFC 8725 §3.6); RFC 7516 §4.1.3 makes zip optional to support",
    ),
];

/// Every `alg` and `enc` polyjose knows: the allow-list is not what these
/// cases test (that is `jwe_compact.rs` and the negative vectors).
fn policy() -> DecryptPolicy {
    DecryptPolicy::new(KeyMgmtAlg::KNOWN, ContentEncAlg::KNOWN).unwrap_or_else(|e| panic!("{e}"))
}

/// The JWK `kty` of a group's key.
fn kty(jwk_text: &str) -> String {
    let value: serde_json::Value = serde_json::from_str(jwk_text).unwrap_or_else(|e| panic!("{e}"));
    value["kty"].as_str().unwrap_or_default().to_owned()
}

/// Whether a group's key is an RSA key (`kty: RSA`, RFC 7518 §6.3).
fn is_rsa(group: &Group) -> bool {
    kty(&group.private) == "RSA"
}

fn outcome(result: polyjose::Result<Vec<u8>>) -> Outcome {
    match result {
        Ok(plaintext) => Outcome::Plaintext(plaintext),
        Err(Error::UnsupportedAlgorithm) => Outcome::Unsupported,
        Err(e) => Outcome::Rejected(e.code()),
    }
}

/// Runs one case through the public API.
fn run(group: &Group, test: &Test, policy: &DecryptPolicy) -> Outcome {
    if is_rsa(group) {
        return run_rsa(group, test, policy);
    }
    let key = Jwk::from_json(group.private.as_bytes())
        .unwrap_or_else(|e| panic!("tcId {}: key does not import: {e}", test.tc_id));
    outcome(decrypt_compact(&test.jwe, &key, policy).map(|d| d.plaintext().to_vec()))
}

/// An RSA group: both of polyjose's possible paths must say
/// `UnsupportedAlgorithm`, and then the case is unsupported.
fn run_rsa(group: &Group, test: &Test, policy: &DecryptPolicy) -> Outcome {
    let tc = test.tc_id;
    // No RSA private keys (ADR 0021): the import refuses them.
    assert_eq!(
        Jwk::from_json(group.private.as_bytes()).err(),
        Some(Error::UnsupportedAlgorithm),
        "tcId {tc}: an RSA private JWK must not import"
    );
    let public = group
        .public
        .as_deref()
        .unwrap_or_else(|| panic!("tcId {tc}: RSA group without a public key"));
    // A public JWK whose `alg` is RSA-OAEP or RSA1_5 does not import either
    // (ADRs 0021, 0022); an RSA-OAEP-256 one does, and cannot decrypt.
    let via_public = Jwk::from_json(public.as_bytes())
        .and_then(|key| decrypt_compact(&test.jwe, &key, policy).map(|d| d.plaintext().to_vec()));
    let got = outcome(via_public);
    assert_eq!(
        got,
        Outcome::Unsupported,
        "tcId {tc}: RSA must be unsupported"
    );
    got
}

/// The deviation reason of `tc_id`, if it has one.
fn deviation(tc_id: u32) -> Option<&'static str> {
    DEVIATIONS
        .iter()
        .find(|(ids, _)| ids.contains(&tc_id))
        .map(|&(_, reason)| reason)
}

/// Every case, its outcome checked against `result` and [`DEVIATIONS`].
fn outcomes() -> Vec<(u32, Outcome)> {
    let suite = jwe_wycheproof::load();
    let policy = policy();
    let mut all = Vec::new();
    for (group, test) in suite.tests() {
        let tc = test.tc_id;
        let got = run(group, test, &policy);
        match (test.result, &got) {
            (Expected::Valid, Outcome::Plaintext(pt)) => {
                assert_eq!(Some(pt), test.pt.as_ref(), "tcId {tc}: wrong plaintext");
                assert_eq!(deviation(tc), None, "tcId {tc}: listed but accepted");
            }
            (Expected::Valid, _) => assert!(
                deviation(tc).is_some(),
                "tcId {tc} ({}, {}): valid but {got:?}, with no listed deviation",
                group.comment,
                test.comment
            ),
            (Expected::Invalid, Outcome::Plaintext(_)) => panic!(
                "tcId {tc} ({}, {}): invalid but decrypted",
                group.comment, test.comment
            ),
            (Expected::Invalid, _) => {
                assert_eq!(deviation(tc), None, "tcId {tc}: invalid and rejected");
            }
            (Expected::Acceptable, _) => panic!("tcId {tc}: the file has no acceptable cases"),
        }
        all.push((tc, got));
    }
    all
}

#[test]
fn every_case_matches_its_result_or_a_listed_deviation() {
    let all = outcomes();
    assert_eq!(all.len(), 139);
    let accepted = all
        .iter()
        .filter(|(_, o)| matches!(o, Outcome::Plaintext(_)))
        .count();
    let rejected = all
        .iter()
        .filter(|(_, o)| matches!(o, Outcome::Rejected(_)))
        .count();
    let unsupported = all
        .iter()
        .filter(|(_, o)| *o == Outcome::Unsupported)
        .count();
    // 65 valid = 43 non-RSA (42 without `deflate`: tcId 135 is zip) + 22
    // RSA; 74 invalid = 52 non-RSA + 22 RSA.
    let expected = if cfg!(feature = "deflate") {
        (43, 52, 44)
    } else {
        (42, 52, 45)
    };
    assert_eq!((accepted, rejected, unsupported), expected);
    // Every deviation is a valid case that was not accepted: none is stale.
    let listed: usize = DEVIATIONS.iter().map(|(ids, _)| ids.len()).sum();
    assert_eq!(listed, 65 - accepted);
}

#[test]
fn every_rsa_group_case_is_unsupported() {
    let suite = jwe_wycheproof::load();
    let policy = policy();
    let rsa: Vec<_> = suite.tests().filter(|(g, _)| is_rsa(g)).collect();
    // 42 in the `jwe_rsa*` groups, 2 in `rfc_7520` (RFC 7520 §5.1, §5.2).
    assert_eq!(rsa.len(), 44);
    assert_eq!(
        rsa.iter()
            .filter(|(g, _)| g.comment.starts_with("jwe_rsa"))
            .count(),
        42
    );
    for (group, test) in rsa {
        assert_eq!(run(group, test, &policy), Outcome::Unsupported);
    }
}

#[test]
fn rejections_have_the_codes_of_the_error_contract() {
    let mut codes: BTreeMap<&str, usize> = BTreeMap::new();
    for (_, o) in outcomes() {
        if let Outcome::Rejected(code) = o {
            *codes.entry(code).or_default() += 1;
        }
    }
    let expected: BTreeMap<&str, usize> = [
        // Steps 6–17: tampered or truncated tag, ciphertext, IV or
        // encrypted key, an off-curve epk, a bad padding (RFC 7516 §11.5).
        ("DecryptionFailed", 31),
        // A part that is not canonical base64url (RFC 7515 §2, ADR 0041).
        ("InvalidBase64", 2),
        // Not five compact parts (RFC 7516 §7.1), or JSON given to the
        // compact API.
        ("InvalidFormat", 11),
        // `Alg` instead of `alg`: `alg` missing (RFC 7516 §4.1.1).
        ("InvalidHeader", 1),
        // An empty protected header is not a JSON object (RFC 7516 §5.2
        // step 3).
        ("InvalidJson", 2),
        // The JWK's `alg` (or `kid`) does not fit the JWE: WrongCipher and
        // a modified `kid` (RFC 7517 §4.4, §4.5; RFC 8725 §3.1).
        ("KeyAlgorithmMismatch", 5),
    ]
    .into_iter()
    .collect();
    assert_eq!(codes, expected);
}

#[test]
fn padding_and_truncation_failures_are_indistinguishable() {
    // `Pkcs5Padding` (tcIds 136–139: a bad CBC padding, IV, ciphertext or
    // HMAC under A128CBC-HS256) and every truncated or lengthened tag must
    // be the one `DecryptionFailed`, so no padding oracle exists
    // (RFC 7516 §11.5, RFC 7518 §5.2.2.2).
    let suite = jwe_wycheproof::load();
    let policy = policy();
    let mut seen = 0;
    for (group, test) in suite.tests() {
        let truncated = test.comment.contains("Truncated") || test.comment.starts_with("tagTrunc");
        if test.flags.iter().any(|f| f == "Pkcs5Padding") || truncated {
            assert_eq!(
                run(group, test, &policy),
                Outcome::Rejected("DecryptionFailed"),
                "tcId {}",
                test.tc_id
            );
            seen += 1;
        }
    }
    assert_eq!(seen, 4 + 9);
}

#[test]
fn the_only_undefined_flag_is_pkcs5_padding() {
    // T01 found that upstream uses `Pkcs5Padding` (tcIds 136–139) without
    // defining it in `notes`. That changes no `result`: all four are
    // `invalid`, and all four are rejected above.
    let suite = jwe_wycheproof::load();
    let mut undefined: Vec<(String, u32)> = suite
        .tests()
        .flat_map(|(_, t)| t.flags.iter().map(move |f| (f.clone(), t.tc_id)))
        .filter(|(f, _)| !suite.notes.contains(f))
        .collect();
    undefined.sort();
    let expected: Vec<(String, u32)> = (136..=139)
        .map(|tc| ("Pkcs5Padding".to_owned(), tc))
        .collect();
    assert_eq!(undefined, expected);
}

#[test]
fn the_json_serialization_case_decrypts_through_the_json_api() {
    // tcId 22 is upstream's compact-API bug check (flag `JsonSerialization`):
    // tcId 1's JWE in the flattened JSON form, with unknown unprotected
    // members. The compact API rejects it (above); the JSON API opens it,
    // as RFC 7516 §7.2.2 defines the form and §4 says unknown Header
    // Parameters are ignored when not in `crit`.
    let suite = jwe_wycheproof::load();
    let find = |id| {
        suite
            .tests()
            .find(|(_, t)| t.tc_id == id)
            .unwrap_or_else(|| panic!("no tcId {id}"))
    };
    let (group, json_case) = find(22);
    let (_, compact_case) = find(1);
    assert!(json_case.flags.iter().any(|f| f == "JsonSerialization"));
    let key = Jwk::from_json(group.private.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
    let policy = policy();
    assert_eq!(
        decrypt_compact(&json_case.jwe, &key, &policy)
            .err()
            .map(|e| e.code()),
        Some("InvalidFormat")
    );
    let opened = decrypt_json(&json_case.jwe, &key, &policy).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(Some(opened.plaintext()), compact_case.pt.as_deref());
}
