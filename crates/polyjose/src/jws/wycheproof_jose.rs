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

use crate::jwa::SigningAlg;
use crate::jwk::{EcCurve, Jwk, KeyAlg, KeyMaterial};
use crate::test_support::wycheproof::{self, Deviation, Expected, Group, Outcome, Suite, Test};
use crate::{Error, Result};

use super::{Verified, VerifyOptions, verify_compact};

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
        assert_eq!(verified.payload, b"Test", "tcId {}", test.tc_id);
        assert_eq!(verified.alg, SigningAlg::HS256);
    }
}

#[test]
fn rejections_that_wycheproof_allows_fail_with_the_policy_error() {
    // The tests in DEVIATIONS fail at the step ADR 0026 §2 names.
    let suite = wycheproof::load(SUITE);
    for (group, test) in suite.tests() {
        let expected = match test.tc_id {
            346 | 350 => Error::AlgorithmNotAllowed,
            347 | 351 => Error::KeyAlgorithmMismatch,
            372 | 373 => Error::InvalidBase64,
            _ => continue,
        };
        let error = verify(group, test).map(drop).unwrap_err();
        assert_eq!(error.code(), expected.code(), "tcId {}", test.tc_id);
    }
}
