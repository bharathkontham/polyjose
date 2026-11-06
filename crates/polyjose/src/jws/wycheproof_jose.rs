//! Wycheproof's JOSE-level suite, `json_web_signature_test.json`, end to
//! end through the JWS API (ADR 0008 layer 1; feature 0002 T11).
//!
//! The per-primitive suites run in the family modules (`hmac.rs`, `rsa.rs`,
//! `ecdsa.rs`, `eddsa.rs`). This one feeds whole JWS strings to
//! [`verify_compact`], the way an application would:
//!
//! - **Key:** the group's verification JWK, `public`, or `private` for an
//!   `oct` key ([`Group::verification_jwk`]). An RSA `private` JWK is never
//!   imported: polyjose refuses it with `UnsupportedAlgorithm` (ADR 0021 §2).
//! - **Allow-list:** exactly the group's algorithm ([`group_alg`],
//!   RFC 8725 §3.1).
//! - **Expectation:** Wycheproof's `result`, adjusted by [`DEVIATIONS`];
//!   an unexplained deviation fails.
//!
//! It is a unit-test module, not an integration test, because the loader
//! (`crate::test_support::wycheproof`) is `cfg(test)` only.

use crate::json::Object;
use crate::jwa::SigningAlg;
use crate::jwk::{EcCurve, Jwk, KeyAlg, KeyMaterial};
use crate::test_support::wycheproof::{self, Deviation, Expected, Group, Outcome, Suite, Test};
use crate::{Error, Result};

use super::{ProtectedHeader, Verified, VerifyOptions, verify_compact, verify_json};

/// The vendored suite.
const SUITE: &str = "json_web_signature";

/// Where polyjose's outcome differs from Wycheproof's `result`, and why.
const DEVIATIONS: &[Deviation] = &[
    Deviation::tests(
        &[346, 350],
        Outcome::Reject,
        "RFC 8725 §3.1, RFC 7517 §4.4, ADR 0026 §2 steps 7-8: Wycheproof pairs the \
         RFC 7520 §4.2 PS384 token (Figure 20) with a key whose \"alg\" is \"PS256\", so \
         PS384 is not the group's algorithm (AlgorithmNotAllowed); with PS384 allowed, the \
         key's alg still differs from the header's (KeyAlgorithmMismatch)",
    ),
    Deviation::tests(
        &[347, 351],
        Outcome::Reject,
        "RFC 7518 §3.1, RFC 7517 §4.4, ADR 0026 §2 step 8: Wycheproof pairs the \
         RFC 7520 §4.3 ES512 token (Figure 27) with a key whose \"alg\" is \"ES521\", which \
         is no registered JWS algorithm; a key's alg must equal the header's \
         (KeyAlgorithmMismatch)",
    ),
    Deviation::tests(
        &[372, 373],
        Outcome::Reject,
        "RFC 7515 §2, §5.2 steps 2 and 6, ADR 0026 §2 step 3: base64url admits no \
         additional characters, so a '?' inside the header or payload part is \
         InvalidBase64 (upstream marks these valid, as a decoder that skips unknown \
         characters would)",
    ),
];

/// Tests whose `jws` is byte-identical to a `valid` test of the same group
/// (same key), so no verifier can meet both labels: `(tcId, valid twin,
/// why)`. The upstream comments suggest padding (`=`) was meant to be
/// added and was lost.
///
/// polyjose accepts them, as RFC 7515 §5.2 requires for that input. They
/// cannot go in [`DEVIATIONS`], which rightly never lets an `invalid` test
/// be accepted, so [`split_off_duplicates`] proves each pairing and takes
/// them out of the comparison, and [`upstream_duplicates_verify_like_their_valid_twin`]
/// checks polyjose's outcome on them.
const UPSTREAM_DUPLICATES: &[(u32, u32, &str)] = &[
    (
        367,
        357,
        "RFC 7515 §5.2: \"invalidBase64Padding\" carries no padding; it is tcId 357 byte for byte",
    ),
    (
        370,
        357,
        "RFC 7515 §5.2: \"invalidBase64PaddingInPayload\" carries no padding; it is tcId 357 \
         byte for byte",
    ),
];

/// The group's algorithm, the single entry of `allowed_algs`.
///
/// It is the verification JWK's `alg` when that is a registered JWS
/// algorithm. Some groups' keys have no `alg` (`rsa_encryption`,
/// `ec_key_for_encryption`) or an unregistered one (`"ES521"` in the
/// `rfc7520` groups); for those it is the algorithm RFC 7518 binds to the
/// key, so that key binding (ADR 0026 §2 step 8), not the allow-list,
/// decides: ES256 for P-256 and ES512 for P-521 (RFC 7518 §3.4), and RS256
/// for RSA, the algorithm of those groups' only tokens (RFC 7518 §3.3).
fn group_alg(key: &Jwk) -> SigningAlg {
    if let Some(KeyAlg::Signing(alg)) = key.alg() {
        return alg.clone();
    }
    match key.material() {
        KeyMaterial::Rsa(_) => SigningAlg::RS256,
        KeyMaterial::Ec(ec) if ec.crv() == EcCurve::P256 => SigningAlg::ES256,
        KeyMaterial::Ec(ec) if ec.crv() == EcCurve::P521 => SigningAlg::ES512,
        _ => panic!("no algorithm rule for this group's key"),
    }
}

/// The group's verification key. Every key in the file imports.
fn verification_key(group: &Group) -> Jwk {
    Jwk::from_json(group.verification_jwk().as_bytes())
        .unwrap_or_else(|e| panic!("group {:?}: key import failed: {e}", group.comment))
}

/// What polyjose does with `test`: [`verify_compact`] with the group's key
/// and algorithm.
fn verify(group: &Group, test: &Test) -> Result<Verified> {
    let key = verification_key(group);
    let allowed = [group_alg(&key)];
    verify_compact(test.jws(), &key, &VerifyOptions::new(&allowed)?)
}

/// Loads the suite and removes the [`UPSTREAM_DUPLICATES`], after checking
/// that each is in the same group as its twin, byte-identical to it, and
/// that the twin is `valid`. Returns the suite and the removed tests'
/// `(group index, test)`.
fn split_off_duplicates() -> (Suite, Vec<(usize, Test)>) {
    let mut suite = wycheproof::load(SUITE);
    let mut removed = Vec::new();
    for &(tc_id, twin_id, reason) in UPSTREAM_DUPLICATES {
        assert!(
            reason.starts_with("RFC "),
            "tcId {tc_id}: reason cites no RFC"
        );
        let (index, group) = suite
            .groups
            .iter_mut()
            .enumerate()
            .find(|(_, g)| g.tests.iter().any(|t| t.tc_id == tc_id))
            .unwrap_or_else(|| panic!("tcId {tc_id} is not in the suite"));
        let twin = group
            .tests
            .iter()
            .find(|t| t.tc_id == twin_id)
            .unwrap_or_else(|| panic!("tcId {twin_id} is not in tcId {tc_id}'s group"));
        assert_eq!(twin.result, Expected::Valid, "tcId {twin_id} must be valid");
        let twin_jws = twin.jws().to_owned();
        let at = group.tests.iter().position(|t| t.tc_id == tc_id).unwrap();
        let test = group.tests.remove(at);
        assert_eq!(
            test.result,
            Expected::Invalid,
            "tcId {tc_id} must be invalid"
        );
        assert_eq!(
            test.jws(),
            twin_jws,
            "tcId {tc_id} is no longer identical to tcId {twin_id}: drop it from \
             UPSTREAM_DUPLICATES"
        );
        removed.push((index, test));
    }
    (suite, removed)
}

#[test]
fn wycheproof_json_web_signature() {
    let (suite, removed) = split_off_duplicates();
    let summary = wycheproof::assert_conforms(&suite, DEVIATIONS, |group, test| {
        Outcome::of(&verify(group, test))
    });
    // 401 in the file; the two duplicates are checked on their own.
    assert_eq!(summary.tests + removed.len(), 401);
    assert_eq!(summary.deviations, 6);
}

#[test]
fn upstream_duplicates_verify_like_their_valid_twin() {
    let (suite, removed) = split_off_duplicates();
    assert_eq!(removed.len(), UPSTREAM_DUPLICATES.len());
    for (index, test) in &removed {
        let verified = verify(&suite.groups[*index], test)
            .unwrap_or_else(|e| panic!("tcId {}: {e}", test.tc_id));
        assert_eq!(*verified.payload, b"Test", "tcId {}", test.tc_id);
        assert_eq!(verified.alg, SigningAlg::HS256);
    }
}

/// The error of every test polyjose rejects, by the ADR 0026 §2 step that
/// fails first: `(tcIds, code, why)`. A rejected test not listed here fails
/// at step 9, the signature check (`InvalidSignature`): a modified or
/// truncated signature, RSA padding or PSS encoding, an ES256 signature of
/// the wrong length (RFC 7518 §3.4) or with r or s out of range, an
/// embedded `jwk` that is ignored (ADR 0026 §2, CVE-2018-0114).
const ERRORS: &[(&[u32], &str, &str)] = &[
    (
        &[
            4, 7, 10, 12, 13, 14, 15, 17, 21, 24, 27, 29, 30, 36, 39, 42, 44, 45,
        ],
        "InvalidFormat",
        "step 2, RFC 7515 §7.1: not three parts (tcId 17 is a JSON JWS given to the compact API)",
    ),
    (
        &[
            360, 361, 362, 363, 364, 365, 366, 368, 369, 371, 372, 373, 374, 375,
        ],
        "InvalidBase64",
        "step 3, RFC 7515 §2: spaces, '?', '#', or non-zero unused bits (RFC 4648 §3.5)",
    ),
    (
        &[9, 11, 26, 28, 41, 43],
        "InvalidJson",
        "step 4, RFC 7515 §5.2 step 3: an empty header part is no JSON object",
    ),
    (
        &[342],
        "UnsupportedAlgorithm",
        "step 6, RFC 7515 §4.1.1: \"NONE\" is no algorithm; names are case-sensitive",
    ),
    (
        &[16, 31, 332, 334, 336, 338, 340, 341, 343, 344, 346, 350],
        "AlgorithmNotAllowed",
        "step 7, RFC 8725 §3.1: the header alg is not the group's (or is none)",
    ),
    (
        &[347, 351, 353, 354, 355, 356],
        "KeyAlgorithmMismatch",
        "step 8, RFC 7517 §4.2-§4.4: the key's alg differs, its use is enc, or its \
         key_ops lack verify",
    ),
];

#[test]
fn every_rejection_fails_at_its_adr_0026_step() {
    let suite = wycheproof::load(SUITE);
    let mut listed = std::collections::BTreeMap::new();
    for (ids, code, why) in ERRORS {
        assert!(why.contains("RFC "), "{code}: the reason cites no RFC");
        for id in *ids {
            assert!(
                listed.insert(*id, *code).is_none(),
                "tcId {id} listed twice"
            );
        }
    }
    let mut seen = 0;
    for (group, test) in suite.tests() {
        let id = test.tc_id;
        match (verify(group, test), listed.get(&id)) {
            (Ok(_), None) => {}
            (Ok(_), Some(code)) => panic!("tcId {id} verified; ERRORS expects {code}"),
            (Err(e), code) => {
                assert_eq!(e.code(), *code.unwrap_or(&"InvalidSignature"), "tcId {id}");
            }
        }
        seen += usize::from(listed.contains_key(&id));
    }
    assert_eq!(
        seen,
        listed.len(),
        "ERRORS lists a tcId that is not in the suite"
    );
}

/// The test with `tc_id`, with its group.
fn find(suite: &Suite, tc_id: u32) -> (&Group, &Test) {
    suite
        .tests()
        .find(|(_, t)| t.tc_id == tc_id)
        .unwrap_or_else(|| panic!("tcId {tc_id} is not in the suite"))
}

/// The flattened JWS JSON Serialization (RFC 7515 §7.2.2) of a compact
/// JWS's three parts, or `None` if it does not have exactly three.
fn flattened(compact: &str) -> Option<String> {
    let parts: Vec<&str> = compact.split('.').collect();
    let [protected, payload, signature] = parts[..] else {
        return None;
    };
    let mut jws = Object::new();
    jws.insert("payload", payload);
    jws.insert("protected", protected);
    jws.insert("signature", signature);
    Some(jws.to_json())
}

#[test]
fn verify_json_agrees_with_verify_compact() {
    // Every three-part test, re-serialized as flattened JSON
    // (RFC 7515 §7.2.2), has the same outcome and payload through
    // verify_json. An empty `protected` is InvalidFormat in JSON
    // (RFC 7515 §7.2.1, ADR 0026 §1) where compact says InvalidJson, so
    // only the outcome is compared.
    let suite = wycheproof::load(SUITE);
    let mut compared = 0;
    for (group, test) in suite.tests() {
        let Some(json) = flattened(test.jws()) else {
            continue;
        };
        let key = verification_key(group);
        let allowed = [group_alg(&key)];
        let opts = VerifyOptions::new(&allowed).unwrap();
        let compact = verify_compact(test.jws(), &key, &opts);
        let json = verify_json(&json, &key, &opts);
        let id = test.tc_id;
        assert_eq!(Outcome::of(&json), Outcome::of(&compact), "tcId {id}");
        if let (Ok(json), Ok(compact)) = (json, compact) {
            assert_eq!(json.payload, compact.payload, "tcId {id}");
            assert_eq!(json.protected, compact.protected, "tcId {id}");
        }
        compared += 1;
    }
    // 401 tests, of which 18 do not have three parts.
    assert_eq!(compared, 383);
}

#[test]
fn json_serialization_case_through_verify_json() {
    // tcId 17 is meant as a general JSON JWS (RFC 7515 §7.2.1) that a
    // compact verifier must reject, and verify_compact does (see ERRORS).
    // Upstream's text is truncated, though: it lacks the closing `]}`, so
    // the JSON API rejects it as InvalidJson (RFC 8259 §2). Completed, it
    // verifies, and its unprotected `header` is returned as data and
    // selects nothing (ADR 0026 §2).
    let suite = wycheproof::load(SUITE);
    let (group, test) = find(&suite, 17);
    assert!(test.has_flag("JsonSerialization"));
    let key = verification_key(group);
    let allowed = [SigningAlg::HS256];
    let opts = VerifyOptions::new(&allowed).unwrap();
    assert!(!test.jws().ends_with("]}"));
    let error = verify_json(test.jws(), &key, &opts).map(drop).unwrap_err();
    assert_eq!(error.code(), "InvalidJson");
    let verified = verify_json(&format!("{}]}}", test.jws()), &key, &opts).unwrap();
    assert_eq!(*verified.payload, b"foo");
    assert_eq!(verified.alg, SigningAlg::HS256);
    assert_eq!(verified.signature_index, 0);
    assert!(verified.unprotected.unwrap().contains("unknown"));
}

#[test]
fn private_jwks_are_refused_for_rsa_and_verify_like_the_public_ones() {
    // ADR 0021 §2: an RSA private JWK fails to import with
    // UnsupportedAlgorithm. An EC or oct private JWK verifies every test
    // exactly as the group's verification JWK does (RFC 7517 §4.3: a
    // private key may verify; `key_ops`, when present, decides).
    let suite = wycheproof::load(SUITE);
    let (mut rsa, mut others) = (0, 0);
    for group in &suite.groups {
        let keys = group.jws_keys.as_ref().unwrap();
        let private = Jwk::from_json(keys.private.as_bytes());
        let public = verification_key(group);
        if let KeyMaterial::Rsa(_) = public.material() {
            assert_eq!(private.map(drop), Err(Error::UnsupportedAlgorithm));
            rsa += 1;
            continue;
        }
        let private = private.unwrap();
        let allowed = [group_alg(&public)];
        let opts = VerifyOptions::new(&allowed).unwrap();
        for test in &group.tests {
            let with_private = verify_compact(test.jws(), &private, &opts).map(|v| v.payload);
            let with_public = verify_compact(test.jws(), &public, &opts).map(|v| v.payload);
            assert_eq!(with_private, with_public, "tcId {}", test.tc_id);
        }
        others += 1;
    }
    assert_eq!((rsa, others), (13, 10));
}

#[test]
fn allowing_the_header_alg_still_fails_key_binding() {
    // RFC 8725 §2.1, §3.1, ADR 0026 §2 step 8: the allow-list is not the
    // only guard. Where the header alg is not the group's, allowing exactly
    // the header's alg moves the failure to key binding: an EC key never
    // verifies HS256 (tcId 31), a PS512 key never RS*, PS256 or PS384
    // (332-340), and the RFC 7520 key labelled PS256 never PS384 (346,
    // 350). `none`, in any case, can never be allowed (341-344).
    let suite = wycheproof::load(SUITE);
    let header_alg = |test: &Test| {
        let protected = test.jws().split('.').next().unwrap();
        let header = ProtectedHeader::from_encoded(protected).unwrap();
        SigningAlg::from(header.header().alg.as_deref().unwrap())
    };
    for id in [31, 332, 334, 336, 338, 340, 346, 350] {
        let (group, test) = find(&suite, id);
        let key = verification_key(group);
        let alg = header_alg(test);
        assert_ne!(alg, group_alg(&key), "tcId {id}");
        let allowed = [alg];
        let result = verify_compact(test.jws(), &key, &VerifyOptions::new(&allowed).unwrap());
        assert_eq!(
            result.map(drop),
            Err(Error::KeyAlgorithmMismatch),
            "tcId {id}"
        );
    }
    for id in 341..=344 {
        let alg = header_alg(find(&suite, id).1);
        assert_eq!(
            VerifyOptions::new(&[alg]).map(drop),
            Err(Error::AlgorithmNotAllowed),
            "tcId {id}"
        );
    }
}
