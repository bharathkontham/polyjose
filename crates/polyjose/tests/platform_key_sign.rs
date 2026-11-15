//! Signing with a platform-held key (feature 0025 T01; ADR 0071 §2–§3,
//! RFC 7515 §5.1, RFC 7518 §3.3–§3.5, RFC 7519 §7.1), through the public
//! API, with the software fake of `platform_support`.
//!
//! - Every algorithm a platform key serves produces a compact JWS, a
//!   flattened and a general JWS JSON and a JWT that the existing verify
//!   accepts, with the RFC 7520 §4.1 (RS256), §4.2 (PS384) and §4.3
//!   (ES512) keys among them.
//! - The order of checks: what fails before the key is called, and what
//!   fails before the private key is.
//! - Verify after sign: a signature that does not verify is never
//!   returned.
//! - Errors from the key pass through as the three ADR 0071 §6 codes.
#![allow(clippy::panic)] // test code: a panic is a failed assertion

mod platform_support;

use platform_support::{Fake, RFC7515_A3, RFC7520_3_2, SignFault, rfc7520_3_4, with};
use polyjose::header::Header;
use polyjose::jwa::SigningAlg;
use polyjose::jws::{
    PlatformSigner, ProtectedHeader, SignOptions, VerifyOptions, sign_compact_with_platform_key,
    sign_flattened_with_platform_key, sign_general_with_platform_key, verify_compact, verify_json,
};
use polyjose::jwt::{self, Claims, FixedClock, IssueOptions, Keys, NumericDate, Policy};
use polyjose::keys::{KeySpec, generate};
use polyjose::{Error, PlatformKeyError};

use SigningAlg as S;

const PAYLOAD: &[u8] = b"It's a dangerous business, Frodo, going out your door.";

fn protected(alg: &SigningAlg) -> ProtectedHeader {
    let mut header = Header::new();
    header.alg = Some(alg.as_str().into());
    ProtectedHeader::new(header).unwrap_or_else(|e| panic!("{e}"))
}

fn p384() -> String {
    generate(KeySpec::Ec(polyjose::jwk::EcCurve::P384))
        .unwrap_or_else(|e| panic!("{e}"))
        .to_json()
        .to_string()
}

/// `(alg, private JWK)` for every algorithm a platform key serves
/// (ADR 0071 §2): RFC 7515 A.3 (ES256), a fresh P-384 key (ES384),
/// RFC 7520 §3.2 (ES512, §4.3) and RFC 7520 §3.4 (RS*, PS*; §4.1 RS256,
/// §4.2 PS384).
fn every_alg() -> Vec<(SigningAlg, String)> {
    let rsa = rfc7520_3_4();
    vec![
        (S::ES256, RFC7515_A3.to_owned()),
        (S::ES384, p384()),
        (S::ES512, RFC7520_3_2.to_owned()),
        (S::RS256, rsa.clone()),
        (S::RS384, rsa.clone()),
        (S::RS512, rsa.clone()),
        (S::PS256, rsa.clone()),
        (S::PS384, rsa.clone()),
        (S::PS512, rsa),
    ]
}

fn fake(alg: &SigningAlg, private: &str) -> Fake {
    Fake::new(private, &[alg.as_str()])
}

fn verify_opts(algs: &[SigningAlg]) -> VerifyOptions<'_> {
    VerifyOptions::new(algs).unwrap_or_else(|e| panic!("{e}"))
}

#[test]
fn every_platform_alg_signs_compact_json_and_jwt_that_verify() {
    for (alg, private) in every_alg() {
        let key = fake(&alg, &private);
        let public = key.public();
        let algs = [alg.clone()];
        let opts = verify_opts(&algs);

        let compact =
            sign_compact_with_platform_key(&protected(&alg), PAYLOAD, &key, &SignOptions::new())
                .unwrap_or_else(|e| panic!("{alg} compact: {e}"));
        let verified = verify_compact(&compact, &public, &opts)
            .unwrap_or_else(|e| panic!("{alg} compact verify: {e}"));
        assert_eq!(verified.payload.as_slice(), PAYLOAD, "{alg}");

        let signer = PlatformSigner::new(&key).protected(protected(&alg));
        let flattened = sign_flattened_with_platform_key(&signer, PAYLOAD, &SignOptions::new())
            .unwrap_or_else(|e| panic!("{alg} flattened: {e}"));
        assert!(!flattened.contains("\"signatures\""), "{alg}");
        verify_json(&flattened, &public, &opts).unwrap_or_else(|e| panic!("{alg} flattened: {e}"));

        let general =
            sign_general_with_platform_key(&[signer.clone(), signer], PAYLOAD, &SignOptions::new())
                .unwrap_or_else(|e| panic!("{alg} general: {e}"));
        assert!(general.contains("\"signatures\""), "{alg}");
        verify_json(&general, &public, &opts).unwrap_or_else(|e| panic!("{alg} general: {e}"));

        let mut claims = Claims::new();
        claims.iss = Some("https://issuer.example".into());
        claims.exp = NumericDate::from_secs(2_000_000_000);
        let token = jwt::sign_with_platform_key(&claims, &IssueOptions::new(alg.clone()), &key)
            .unwrap_or_else(|e| panic!("{alg} jwt: {e}"));
        let clock = FixedClock(1_900_000_000);
        let policy = Policy::new(&clock, &algs).unwrap_or_else(|e| panic!("{e}"));
        let verified = jwt::verify(&token, Keys::One(&public), &policy)
            .unwrap_or_else(|e| panic!("{alg} jwt verify: {e}"));
        assert_eq!(
            verified.claims.iss.as_deref(),
            Some("https://issuer.example")
        );

        // Each signature is one call; the public side is read once per call
        // (twice for the general JWS: one per signer).
        let calls = key.calls();
        assert_eq!(calls.sign, 1 + 1 + 2 + 1, "{alg}");
        assert_eq!(calls.public_jwk, 1 + 1 + 2 + 1, "{alg}");
        assert_eq!(calls.algorithms, calls.public_jwk, "{alg}");
    }
}

#[test]
fn es_signatures_are_fixed_width_r_s() {
    // RFC 7518 §3.4: 64, 96 and 132 octets, never DER.
    for (alg, private, len) in [
        (S::ES256, RFC7515_A3.to_owned(), 64),
        (S::ES384, p384(), 96),
        (S::ES512, RFC7520_3_2.to_owned(), 132),
    ] {
        let key = fake(&alg, &private);
        for _ in 0..8 {
            let jws = sign_compact_with_platform_key(
                &protected(&alg),
                PAYLOAD,
                &key,
                &SignOptions::new(),
            )
            .unwrap_or_else(|e| panic!("{e}"));
            let signature = jws.rsplit('.').next().unwrap_or_default();
            let octets = polyjose::util::b64url_decode(signature).unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(octets.len(), len, "{alg}");
        }
    }
}

#[test]
fn jwt_copies_the_public_jwk_kid() {
    // ADR 0027 §8, as for a JWK: RFC 7520 §3.2 has kid bilbo.baggins.
    let key = fake(&S::ES512, RFC7520_3_2);
    let token = jwt::sign_with_platform_key(&Claims::new(), &IssueOptions::new(S::ES512), &key)
        .unwrap_or_else(|e| panic!("{e}"));
    let header = token.split('.').next().unwrap_or_default();
    let header = polyjose::util::b64url_decode(header).unwrap_or_else(|e| panic!("{e}"));
    let header = String::from_utf8(header).unwrap_or_default();
    assert!(
        header.contains("\"kid\":\"bilbo.baggins@hobbiton.example\""),
        "{header}"
    );
}

/// Runs every signing entry point with `key` and `alg`, returning each
/// result's code.
fn sign_codes(key: &Fake, alg: &SigningAlg) -> Vec<&'static str> {
    let code = |r: polyjose::Result<String>| r.map_or_else(|e| e.code(), |_| "ok");
    let signer = PlatformSigner::new(key).protected(protected(alg));
    vec![
        code(sign_compact_with_platform_key(
            &protected(alg),
            PAYLOAD,
            key,
            &SignOptions::new(),
        )),
        code(sign_flattened_with_platform_key(
            &signer,
            PAYLOAD,
            &SignOptions::new(),
        )),
        code(sign_general_with_platform_key(
            std::slice::from_ref(&signer),
            PAYLOAD,
            &SignOptions::new(),
        )),
        code(jwt::sign_with_platform_key(
            &Claims::new(),
            &IssueOptions::new(alg.clone()),
            key,
        )),
    ]
}

fn all(code: &'static str) -> Vec<&'static str> {
    vec![code; 4]
}

#[test]
fn algorithms_no_platform_key_serves_never_reach_the_key() {
    // ADR 0071 §2: EdDSA, ES256K and HS* are UnsupportedAlgorithm before
    // the key is called at all.
    for alg in [
        S::EdDSA,
        S::Ed25519,
        S::ES256K,
        S::HS256,
        S::HS384,
        S::HS512,
    ] {
        let key = Fake::new(RFC7515_A3, &[alg.as_str()]);
        assert_eq!(sign_codes(&key, &alg), all("UnsupportedAlgorithm"), "{alg}");
        assert_eq!(key.calls().all(), 0, "{alg}");
    }
    // `none` is AlgorithmNotAllowed (RFC 8725 §3.2), also with no call.
    let key = Fake::new(RFC7515_A3, &["ES256"]);
    let codes = sign_codes(&key, &S::None);
    assert!(
        codes.iter().all(|c| *c == "AlgorithmNotAllowed"),
        "{codes:?}"
    );
    assert_eq!(key.calls().all(), 0);
}

#[test]
fn unbound_keys_are_key_algorithm_mismatch_without_signing() {
    let rsa = rfc7520_3_4();
    let cases: Vec<(&str, Fake, SigningAlg)> = vec![
        // A P-256 key asked for ES384 (it lists ES384, so only the curve
        // binding fails).
        (
            "P-256 for ES384",
            Fake::new(RFC7515_A3, &["ES256", "ES384"]),
            S::ES384,
        ),
        // An EC key asked for RS256.
        (
            "EC for RS256",
            Fake::new(RFC7515_A3, &["ES256", "RS256"]),
            S::RS256,
        ),
        // algorithms() omits the algorithm.
        ("not listed", Fake::new(&rsa, &["RS256"]), S::PS256),
        ("empty list", Fake::new(&rsa, &[]), S::RS256),
        // The public JWK's alg differs (RFC 7517 §4.4).
        (
            "jwk alg",
            {
                let mut key = Fake::new(&rsa, &["RS256", "RS384"]);
                key.public_json = with(&key.public_json, "alg", "RS384");
                key
            },
            S::RS256,
        ),
        // use: enc on a signing call (RFC 7517 §4.2).
        (
            "use enc",
            {
                let mut key = Fake::new(RFC7515_A3, &["ES256"]);
                key.public_json = with(&key.public_json, "use", "enc");
                key
            },
            S::ES256,
        ),
    ];
    for (what, key, alg) in cases {
        assert_eq!(
            sign_codes(&key, &alg),
            all("KeyAlgorithmMismatch"),
            "{what}"
        );
        assert_eq!(key.calls().sign, 0, "{what}");
    }
}

#[test]
fn key_ops_on_the_public_jwk_is_not_consulted() {
    // ADR 0071 §2: on a public JWK, key_ops names public-key operations
    // (RFC 7517 §4.3), so ["verify"] does not stop signing.
    let mut key = Fake::new(RFC7515_A3, &["ES256"]);
    let parsed =
        polyjose::json::parse(key.public_json.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
    let mut object = parsed.into_object().unwrap_or_default();
    object.insert("key_ops", vec![polyjose::json::Value::from("verify")]);
    key.public_json = object.to_json();
    assert_eq!(sign_codes(&key, &S::ES256), all("ok"));
}

#[test]
fn a_public_jwk_with_private_members_is_invalid_key() {
    // ADR 0071 §2: public members only. The message holds no key material.
    let rsa = rfc7520_3_4();
    for (what, private, alg) in [
        ("EC", RFC7515_A3.to_owned(), S::ES256),
        ("RSA", rsa, S::RS256),
    ] {
        let mut key = Fake::new(&private, &[alg.as_str()]);
        key.public_json = private.clone();
        let d = polyjose::json::parse(private.as_bytes())
            .ok()
            .and_then(|v| {
                v.get("d")
                    .and_then(polyjose::json::Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_default();
        let result =
            sign_compact_with_platform_key(&protected(&alg), PAYLOAD, &key, &SignOptions::new());
        let err = result.err().unwrap_or_else(|| panic!("{what}: signed"));
        assert_eq!(err.code(), "InvalidKey", "{what}");
        assert!(
            !err.to_string().contains(&d) && !format!("{err:?}").contains(&d),
            "{what}"
        );
        assert_eq!(sign_codes(&key, &alg), all("InvalidKey"), "{what}");
        assert_eq!(key.calls().sign, 0, "{what}");
    }
}

#[test]
fn weak_or_off_curve_public_jwks_are_invalid_key() {
    // RSA modulus under 2048 bits (RFC 7518 §3.3): the RFC 7520 §3.3 key cut
    // to 1024 bits, top bit set, odd.
    let rsa = rfc7520_3_4();
    let mut key = Fake::new(&rsa, &["RS256"]);
    let n = key
        .public()
        .to_object()
        .get("n")
        .and_then(polyjose::json::Value::as_str)
        .map(str::to_owned)
        .unwrap_or_default();
    let mut short = polyjose::util::b64url_decode(&n).unwrap_or_default();
    short.truncate(128);
    short[0] |= 0x80;
    short[127] |= 1;
    key.public_json = with(
        &key.public_json,
        "n",
        &polyjose::util::b64url_encode(&short),
    );
    assert_eq!(sign_codes(&key, &S::RS256), all("InvalidKey"));

    // An EC point off its curve (RFC 8725 §3.4): y changed by one bit.
    let mut key = Fake::new(RFC7515_A3, &["ES256"]);
    let y = key
        .public()
        .to_object()
        .get("y")
        .and_then(polyjose::json::Value::as_str)
        .map(str::to_owned)
        .unwrap_or_default();
    let mut y = polyjose::util::b64url_decode(&y).unwrap_or_default();
    y[31] ^= 1;
    key.public_json = with(&key.public_json, "y", &polyjose::util::b64url_encode(&y));
    assert_eq!(sign_codes(&key, &S::ES256), all("InvalidKey"));
    assert_eq!(key.calls().sign, 0);
}

#[test]
fn a_signature_that_does_not_verify_is_never_returned() {
    // ADR 0071 §3, verify after sign, always on.
    let rsa = rfc7520_3_4();

    // Signs with another key than the one it reports.
    let mut other = Fake::new(&p384(), &["ES384"]);
    other.public_json = Fake::new(&p384(), &["ES384"]).public_json;
    assert_eq!(sign_codes(&other, &S::ES384), all("PlatformKeyFailed"));
    assert_eq!(other.calls().sign, 4);

    for (what, private, alg, fault) in [
        ("truncated RSA", rsa.clone(), S::RS256, SignFault::Truncated),
        ("truncated PSS", rsa.clone(), S::PS384, SignFault::Truncated),
        ("empty RSA", rsa, S::RS256, SignFault::Empty),
        (
            "raw R||S ES256",
            RFC7515_A3.to_owned(),
            S::ES256,
            SignFault::RawRs,
        ),
        (
            "raw R||S ES512",
            RFC7520_3_2.to_owned(),
            S::ES512,
            SignFault::RawRs,
        ),
        (
            "truncated DER",
            RFC7515_A3.to_owned(),
            S::ES256,
            SignFault::Truncated,
        ),
        (
            "empty EC",
            RFC7515_A3.to_owned(),
            S::ES256,
            SignFault::Empty,
        ),
    ] {
        let mut key = Fake::new(&private, &[alg.as_str()]);
        key.sign_fault = fault;
        assert_eq!(sign_codes(&key, &alg), all("PlatformKeyFailed"), "{what}");
    }
}

#[test]
fn errors_from_the_key_pass_through() {
    use PlatformKeyError as P;
    for (error, code) in [
        (P::NotFound, "KeyNotFound"),
        (P::UserAuthenticationRequired, "UserAuthenticationRequired"),
        (P::Failed, "PlatformKeyFailed"),
    ] {
        for method in ["public_jwk", "algorithms", "sign"] {
            let mut key = Fake::new(RFC7515_A3, &["ES256"]);
            match method {
                "public_jwk" => key.fail_public_jwk = Some(error),
                "algorithms" => key.fail_algorithms = Some(error),
                _ => key.fail_sign = Some(error),
            }
            assert_eq!(sign_codes(&key, &S::ES256), all(code), "{method} {error:?}");
            let calls = key.calls();
            if method != "sign" {
                assert_eq!(calls.sign, 0, "{method}");
            }
        }
    }
    // The fixed messages (ADR 0071 §6).
    assert_eq!(Error::KeyNotFound.to_string(), "platform key not found");
    assert_eq!(
        Error::UserAuthenticationRequired.to_string(),
        "user authentication required"
    );
    assert_eq!(
        Error::PlatformKeyFailed.to_string(),
        "platform key operation failed"
    );
    assert_eq!(Error::from(P::Failed), Error::PlatformKeyFailed);
}

#[test]
fn a_general_jws_checks_every_signer_before_signing() {
    // RFC 7515 §5.1 per signer, after steps 5-8 for all (as sign_general):
    // a second signer that is not bound stops the call before either key
    // signs.
    let good = Fake::new(RFC7515_A3, &["ES256"]);
    let bad = Fake::new(RFC7515_A3, &["ES384"]);
    let signers = [
        PlatformSigner::new(&good).protected(protected(&S::ES256)),
        PlatformSigner::new(&bad).protected(protected(&S::ES256)),
    ];
    let result = sign_general_with_platform_key(&signers, PAYLOAD, &SignOptions::new());
    assert_eq!(result.err(), Some(Error::KeyAlgorithmMismatch));
    assert_eq!(good.calls().sign + bad.calls().sign, 0);
}

#[test]
fn debug_prints_no_key_material() {
    // ADR 0071 §7: the type name only for anything holding a platform key.
    const MARKER: &str = "pj-SECRET-marker-0025";
    let mut key = Fake::new(RFC7515_A3, &["ES256"]);
    key.public_json = with(&key.public_json, "kid", MARKER);
    let signer = PlatformSigner::new(&key).protected(protected(&S::ES256));
    let debug = format!("{signer:?}");
    assert!(
        debug.contains("PlatformSigner") && debug.contains("<platform key>"),
        "{debug}"
    );
    assert!(!debug.contains(MARKER), "{debug}");
    for e in [
        PlatformKeyError::NotFound,
        PlatformKeyError::UserAuthenticationRequired,
        PlatformKeyError::Failed,
    ] {
        assert!(!format!("{e:?}{e}").contains(MARKER));
    }
    // No call was made by printing.
    assert_eq!(key.calls().all(), 0);
}
