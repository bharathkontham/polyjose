//! T11: JWS sign → verify properties through the public API only
//! (ADR 0008 layer 2).
//!
//! The matrix is every signing algorithm polyjose ships, HS256/384/512
//! (RFC 7518 §3.2), ES256/384/512 (RFC 7518 §3.4), ES256K (RFC 8812 §3.2),
//! EdDSA (RFC 8037 §3.1) and Ed25519 (RFC 9864), times every
//! serialization: compact, attached and detached (RFC 7515 §7.1,
//! Appendix F), flattened JSON (§7.2.2) and general JSON with one to three
//! signers (§7.2.1), each with `b64` true and false (RFC 7797 §3).
//!
//! Keys are published or independently computed key pairs (RFC 7515 A.3,
//! A.4; RFC 7520 §3.2; RFC 8032 §7.1; `common`), plus random HMAC keys;
//! payloads, headers and the serialization are random. ECDSA signing is
//! hedged (ADR 0026 §5), so every case signs differently.
//!
//! ADR 0009: at most 1,000 cases per property, and no wall-clock
//! assertions. P-521 is slow in a debug build, so the counts stay below
//! the cap.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

mod common;

use polyjose::header::Header;
use polyjose::jwa::SigningAlg;
use polyjose::jwk::Jwk;
use polyjose::jws::{
    ProtectedHeader, SignOptions, Signer, Verified, VerifyOptions, sign_compact, sign_flattened,
    sign_general, verify_compact, verify_json,
};
use polyjose::util::b64url_encode;
use proptest::prelude::*;
use proptest::sample::select;

/// Every signing algorithm polyjose ships (RS*/PS* are verify-only,
/// ADR 0021).
const ALGS: [SigningAlg; 9] = [
    SigningAlg::HS256,
    SigningAlg::HS384,
    SigningAlg::HS512,
    SigningAlg::ES256,
    SigningAlg::ES384,
    SigningAlg::ES512,
    SigningAlg::ES256K,
    SigningAlg::EdDSA,
    SigningAlg::Ed25519,
];

// RFC 7515 Appendix A.3: the P-256 key.
const A3: (&str, &str, &str) = (
    "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
    "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI",
);
// RFC 7515 Appendix A.4: the P-521 key.
const A4: (&str, &str, &str) = (
    "AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk",
    "ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2",
    "AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C",
);
// RFC 7520 §3.2 (Figure 2): the P-521 key.
const RFC7520_P521: (&str, &str, &str) = (
    "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
    "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1",
    "AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt",
);
/// Ed25519 key pairs `(x, d)`: RFC 8037 A.1 (RFC 8032 §7.1 TEST 1), and
/// RFC 8032 §7.1 TEST 2 and TEST 3.
const ED25519: [(&str, &str); 3] = [
    (common::ED25519_X, common::ED25519_D),
    (
        "PUAXw-hDiVqStwqnTRt-vJyYLM8uxJaMwM1V8Sr0Zgw",
        "TM0Imyj_ltqdtsNG7BFOD1uKMZ81q6Yk2oz27U-4pvs",
    ),
    (
        "_FHNjmIYoaONpH7QAjDwWAgW7RO6MwOsXeuRFUiQgCU",
        "xaqN9D-fg3vtt0QvMdy3sWbThTUHbwlLhc46LgtEWPc",
    ),
];

/// The HMAC key length the algorithm needs at least: its hash output
/// (RFC 7518 §3.2).
fn hash_len(alg: &SigningAlg) -> usize {
    match alg {
        SigningAlg::HS256 => 32,
        SigningAlg::HS384 => 48,
        _ => 64,
    }
}

fn is_hmac(alg: &SigningAlg) -> bool {
    matches!(
        alg,
        SigningAlg::HS256 | SigningAlg::HS384 | SigningAlg::HS512
    )
}

fn ec_jwk(crv: &str, (x, y, d): (&str, &str, &str), private: bool) -> Jwk {
    let d = if private {
        format!(r#","d":"{d}""#)
    } else {
        String::new()
    };
    Jwk::from_json(format!(r#"{{"kty":"EC","crv":"{crv}","x":"{x}","y":"{y}"{d}}}"#).as_bytes())
        .unwrap()
}

/// The `(x, y, d)` key pairs used for `crv`.
fn ec_pool(crv: &str) -> Vec<(&'static str, &'static str, &'static str)> {
    let fixture = |k: &'static common::EcKeyPair| (k.x, k.y, k.d);
    let zeros = common::LEADING_ZEROS.iter().find(|k| k.crv == crv).unwrap();
    let mut pool = vec![fixture(zeros), fixture(common::generator(crv))];
    match crv {
        "P-256" => pool.insert(0, A3),
        "P-521" => pool.splice(0..1, [A4, RFC7520_P521]).for_each(drop),
        _ => {}
    }
    pool
}

/// A signer's key and the key its verifier holds.
struct KeyPair {
    sign: Jwk,
    verify: Jwk,
}

/// One signature of a case.
#[derive(Debug, Clone)]
struct SignerSpec {
    alg: SigningAlg,
    /// Which key of the algorithm's pool (modulo its size).
    key: usize,
    /// HS*: the key octets, at least the hash output long (RFC 7518 §3.2).
    hmac_key: Vec<u8>,
    /// JSON only: `alg` in the protected header, otherwise in the
    /// unprotected one (RFC 7515 §7.2.1 allows either).
    alg_protected: bool,
    /// A `kid`, data only (ADR 0026 §2): in the protected header for
    /// compact, in the unprotected one for JSON.
    kid: Option<String>,
}

impl SignerSpec {
    fn key_pair(&self) -> KeyPair {
        if is_hmac(&self.alg) {
            let k = b64url_encode(&self.hmac_key);
            let key = Jwk::from_json(format!(r#"{{"kty":"oct","k":"{k}"}}"#).as_bytes()).unwrap();
            return KeyPair {
                sign: key.clone(),
                verify: key,
            };
        }
        if matches!(self.alg, SigningAlg::EdDSA | SigningAlg::Ed25519) {
            let (x, d) = ED25519[self.key % ED25519.len()];
            let okp = |d: &str| {
                Jwk::from_json(
                    format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{x}"{d}}}"#).as_bytes(),
                )
                .unwrap()
            };
            return KeyPair {
                sign: okp(&format!(r#","d":"{d}""#)),
                verify: okp(""),
            };
        }
        let crv = match self.alg {
            SigningAlg::ES256 => "P-256",
            SigningAlg::ES384 => "P-384",
            SigningAlg::ES512 => "P-521",
            _ => "secp256k1",
        };
        let pool = ec_pool(crv);
        let pair = pool[self.key % pool.len()];
        KeyPair {
            sign: ec_jwk(crv, pair, true),
            verify: ec_jwk(crv, pair, false),
        }
    }

    /// Two signers with the same identity, the alg and the verification
    /// key, verify each other's signatures.
    fn identity(&self) -> (SigningAlg, String) {
        let key = self.key_pair().verify.to_json();
        (self.alg.clone(), key.as_str().to_owned())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Form {
    Compact,
    Flattened,
    General,
}

#[derive(Debug, Clone)]
struct Case {
    form: Form,
    /// One for compact and flattened, one to three for general.
    signers: Vec<SignerSpec>,
    payload: Vec<u8>,
    /// The protected `b64` (RFC 7797 §3), shared by every signer (§6).
    b64: bool,
    detached: bool,
}

impl Case {
    fn keys(&self) -> Vec<KeyPair> {
        self.signers.iter().map(SignerSpec::key_pair).collect()
    }

    fn protected(&self, spec: &SignerSpec) -> Option<Header> {
        let mut h = Header::new();
        if self.form == Form::Compact || spec.alg_protected {
            h.alg = Some(spec.alg.as_str().into());
        }
        if self.form == Form::Compact {
            h.kid = spec.kid.clone();
        }
        if !self.b64 {
            // RFC 7797 §3, §6: `b64` is protected and listed in `crit`.
            h.b64 = Some(false);
            h.crit = Some(vec!["b64".into()]);
        }
        (h != Header::new()).then_some(h)
    }

    fn unprotected(&self, spec: &SignerSpec) -> Option<Header> {
        if self.form == Form::Compact {
            return None;
        }
        let mut h = Header::new();
        if !spec.alg_protected {
            h.alg = Some(spec.alg.as_str().into());
        }
        h.kid = spec.kid.clone();
        (h != Header::new()).then_some(h)
    }

    /// Whether the payload may be serialized as it is: always with `b64`
    /// or when detached; otherwise compact needs %x20-7E without '.'
    /// (RFC 7797 §5.2) and JSON needs UTF-8 (RFC 7797 §5.3).
    fn payload_fits(&self) -> bool {
        if self.b64 || self.detached {
            return true;
        }
        match self.form {
            Form::Compact => self
                .payload
                .iter()
                .all(|&b| (0x20..=0x7e).contains(&b) && b != b'.'),
            _ => core::str::from_utf8(&self.payload).is_ok(),
        }
    }

    fn sign(&self, keys: &[KeyPair]) -> polyjose::Result<String> {
        let opts = SignOptions::new().detached(self.detached);
        let signers: Vec<Signer<'_>> = self
            .signers
            .iter()
            .zip(keys)
            .map(|(spec, key)| {
                let mut signer = Signer::new(&key.sign);
                if let Some(h) = self.protected(spec) {
                    signer = signer.protected(ProtectedHeader::new(h).unwrap());
                }
                if let Some(h) = self.unprotected(spec) {
                    signer = signer.unprotected(h);
                }
                signer
            })
            .collect();
        match self.form {
            Form::Compact => {
                let protected = signers[0].protected.as_ref().unwrap();
                sign_compact(protected, &self.payload, &keys[0].sign, &opts)
            }
            Form::Flattened => sign_flattened(&signers[0], &self.payload, &opts),
            Form::General => sign_general(&signers, &self.payload, &opts),
        }
    }

    /// Verifies `jws` with `key`, allowing `allowed`, and supplying
    /// `detached` as the payload when the case is detached.
    fn verify(
        &self,
        jws: &str,
        key: &Jwk,
        allowed: &[SigningAlg],
        detached: &[u8],
    ) -> polyjose::Result<Verified> {
        let mut opts = VerifyOptions::new(allowed)?;
        if self.detached {
            opts = opts.detached_payload(detached);
        }
        match self.form {
            Form::Compact => verify_compact(jws, key, &opts),
            _ => verify_json(jws, key, &opts),
        }
    }

    /// The signature that verifies first with signer `i`'s key and alg:
    /// the first with the same identity (ADR 0026 §3, array order).
    fn first_like(&self, i: usize) -> usize {
        let id = self.signers[i].identity();
        self.signers
            .iter()
            .position(|s| s.identity() == id)
            .unwrap()
    }
}

/// %x20-7E without '.': an unencoded compact payload (RFC 7797 §5.2).
fn unencoded_octet() -> impl Strategy<Value = u8> {
    (0x20u8..=0x7e).prop_map(|b| if b == b'.' { b'-' } else { b })
}

/// Arbitrary octets, RFC 7797 §5.2-safe ASCII, or UTF-8 text.
fn payload() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        prop::collection::vec(any::<u8>(), 0..160),
        prop::collection::vec(unencoded_octet(), 0..160),
        prop::collection::vec(any::<char>(), 0..40)
            .prop_map(|cs| cs.into_iter().collect::<String>().into_bytes()),
    ]
}

fn signer() -> impl Strategy<Value = SignerSpec> {
    (
        select(&ALGS[..]),
        0..3usize,
        prop::collection::vec(any::<u8>(), 96),
        0..=32usize,
        any::<bool>(),
        prop::option::of(0u16..1000),
    )
        .prop_map(|(alg, key, mut hmac_key, extra, alg_protected, kid)| {
            hmac_key.truncate(if is_hmac(&alg) {
                hash_len(&alg) + extra
            } else {
                0
            });
            SignerSpec {
                alg,
                key,
                hmac_key,
                alg_protected,
                kid: kid.map(|n| format!("k{n}")),
            }
        })
}

fn case() -> impl Strategy<Value = Case> {
    (
        select(&[Form::Compact, Form::Flattened, Form::General][..]),
        prop::collection::vec(signer(), 1..=3),
        payload(),
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(|(form, mut signers, payload, b64, detached)| {
            if form != Form::General {
                signers.truncate(1);
            }
            Case {
                form,
                signers,
                payload,
                b64,
                detached,
            }
        })
}

/// The members of each signature of a JSON JWS: the top level for
/// flattened, each `signatures` entry for general.
fn signature_objects(jws: &serde_json::Value) -> Vec<&serde_json::Value> {
    match jws.get("signatures") {
        Some(serde_json::Value::Array(entries)) => entries.iter().collect(),
        _ => vec![jws],
    }
}

/// The serialization has the shape `case` asks for (RFC 7515 §7.1,
/// §7.2.1, §7.2.2, Appendix F).
fn check_shape(case: &Case, jws: &str) -> Result<(), TestCaseError> {
    if case.form == Form::Compact {
        let parts: Vec<&str> = jws.split('.').collect();
        prop_assert_eq!(parts.len(), 3);
        prop_assert_eq!(
            parts[1].is_empty(),
            case.detached || case.payload.is_empty()
        );
        return Ok(());
    }
    let value: serde_json::Value = serde_json::from_str(jws).unwrap();
    prop_assert_eq!(value.get("payload").is_none(), case.detached);
    prop_assert_eq!(
        value.get("signatures").is_some(),
        case.form == Form::General
    );
    prop_assert_eq!(signature_objects(&value).len(), case.signers.len());
    Ok(())
}

proptest! {
    // ADR 0009: at most 1,000 cases; P-521 keeps this one lower.
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// RFC 7515 §5.1-§5.2: every signer's key verifies the JWS and gets
    /// the payload back, with the signer's alg and headers and the index
    /// of the first signature it can verify (ADR 0026 §3). A payload the
    /// serialization cannot carry unencoded is refused with InvalidFormat
    /// (RFC 7797 §5.2-§5.3, ADR 0026 §4).
    #[test]
    fn sign_then_verify_returns_the_payload(case in case()) {
        let keys = case.keys();
        let signed = case.sign(&keys);
        if !case.payload_fits() {
            prop_assert_eq!(signed.map_err(|e| e.code()), Err("InvalidFormat"));
            return Ok(());
        }
        let jws = signed.unwrap();
        check_shape(&case, &jws)?;
        for (i, spec) in case.signers.iter().enumerate() {
            let allowed = [spec.alg.clone()];
            let verified = case.verify(&jws, &keys[i].verify, &allowed, &case.payload).unwrap();
            let index = case.first_like(i);
            let first = &case.signers[index];
            prop_assert_eq!(&verified.payload, &case.payload);
            prop_assert_eq!(&verified.alg, &spec.alg);
            prop_assert_eq!(verified.signature_index, index);
            prop_assert_eq!(verified.protected, case.protected(first));
            prop_assert_eq!(verified.unprotected, case.unprotected(first));
        }
    }
}

#[test]
fn every_fixture_key_signs_what_its_public_key_verifies() {
    // The fixtures are consistent key pairs: signing refuses a `d` that
    // does not derive the public key (T09, ADR 0043 §3), so a typo fails
    // here rather than as a vacuous property.
    for alg in ALGS {
        for key in 0..3 {
            let spec = SignerSpec {
                alg: alg.clone(),
                key,
                hmac_key: vec![7; hash_len(&alg)],
                alg_protected: true,
                kid: None,
            };
            let case = Case {
                form: Form::Compact,
                signers: vec![spec],
                payload: b"fixture".to_vec(),
                b64: true,
                detached: false,
            };
            let keys = case.keys();
            let jws = case
                .sign(&keys)
                .unwrap_or_else(|e| panic!("{alg:?} key {key}: {e}"));
            let allowed = [alg.clone()];
            case.verify(&jws, &keys[0].verify, &allowed, b"")
                .unwrap_or_else(|e| panic!("{alg:?} key {key}: {e}"));
        }
    }
}

#[test]
fn every_alg_serialization_and_b64_round_trips() {
    // The deterministic floor under the property above: each algorithm in
    // every serialization, attached and detached, with `b64` true and
    // false, signs and verifies once. General JSON gets three signers of
    // different algorithms, the case's alg in the middle (ADR 0026 §3:
    // index 1 is the one that verifies).
    let mut cells = 0;
    for (n, alg) in ALGS.iter().enumerate() {
        for form in [Form::Compact, Form::Flattened, Form::General] {
            for b64 in [true, false] {
                for detached in [false, true] {
                    let spec = |alg: &SigningAlg, protected: bool| SignerSpec {
                        alg: alg.clone(),
                        key: n,
                        hmac_key: vec![0x5a; hash_len(alg)],
                        alg_protected: protected,
                        kid: Some(format!("k{n}")),
                    };
                    let signers = match form {
                        Form::General => vec![
                            spec(&ALGS[(n + 1) % ALGS.len()], true),
                            spec(alg, false),
                            spec(&ALGS[(n + 2) % ALGS.len()], true),
                        ],
                        _ => vec![spec(alg, true)],
                    };
                    let case = Case {
                        form,
                        signers,
                        payload: b"RFC 7797 safe payload, ASCII only".to_vec(),
                        b64,
                        detached,
                    };
                    let target = usize::from(form == Form::General);
                    let keys = case.keys();
                    let what = format!("{alg:?} {form:?} b64={b64} detached={detached}");
                    let jws = case.sign(&keys).unwrap_or_else(|e| panic!("{what}: {e}"));
                    check_shape(&case, &jws).unwrap_or_else(|e| panic!("{what}: {e}"));
                    let allowed = [alg.clone()];
                    let verified = case
                        .verify(&jws, &keys[target].verify, &allowed, &case.payload)
                        .unwrap_or_else(|e| panic!("{what}: {e}"));
                    assert_eq!(verified.payload, case.payload, "{what}");
                    assert_eq!(verified.signature_index, target, "{what}");
                    cells += 1;
                }
            }
        }
    }
    assert_eq!(cells, ALGS.len() * 3 * 2 * 2);
}
