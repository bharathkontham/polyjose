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
use polyjose::util::{b64url_decode, b64url_encode};
use proptest::prelude::*;
use proptest::sample::{Index, select};

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
            prop_assert_eq!(&*verified.payload, &case.payload);
            prop_assert_eq!(&verified.alg, &spec.alg);
            prop_assert_eq!(verified.signature_index, index);
            prop_assert_eq!(verified.protected, case.protected(first));
            prop_assert_eq!(verified.unprotected, case.unprotected(first));
        }
    }
}

/// A case whose payload its serialization can carry (`b64` is turned on
/// where the unencoded payload would not fit).
fn signable_case() -> impl Strategy<Value = Case> {
    case().prop_map(|mut case| {
        if !case.payload_fits() {
            case.b64 = true;
        }
        case
    })
}

/// The part of a JWS a tamper property changes.
#[derive(Debug, Clone, Copy)]
enum Part {
    Protected,
    Payload,
    Signature,
}

/// Flips bit `bit` of the octet at `at` (modulo the length).
fn flip(bytes: &mut [u8], at: Index, bit: u8) {
    let i = at.index(bytes.len());
    bytes[i] ^= 1 << bit;
}

/// `part` with one bit of its base64url-decoded octets flipped.
fn flip_encoded(part: &str, at: Index, bit: u8) -> String {
    let mut octets = b64url_decode(part).unwrap();
    flip(&mut octets, at, bit);
    b64url_encode(&octets)
}

/// `text` with one character changed: an ASCII one by one of its low
/// seven bits, so the text stays UTF-8 (a `&str` cannot hold anything
/// else), any other by `A`.
fn flip_text(text: &str, at: Index, bit: u8) -> String {
    let i = at.index(text.chars().count());
    text.chars()
        .enumerate()
        .map(|(j, c)| match (j == i, u8::try_from(c)) {
            (false, _) => c,
            (true, Ok(b)) if b.is_ascii() => char::from(b ^ (1 << (bit % 7))),
            (true, _) => 'A',
        })
        .collect()
}

/// `jws` with one octet of `part` changed: of the payload (or of
/// `detached`, the payload a detached verifier supplies), of the protected
/// header, or of the signature of every entry that signer 0's key could
/// verify. An empty payload, or a JSON entry without a protected header,
/// has its signature changed instead.
fn tamper(case: &Case, jws: &str, detached: &mut [u8], part: Part, at: Index, bit: u8) -> String {
    let part = match part {
        Part::Payload if case.payload.is_empty() => Part::Signature,
        part => part,
    };
    if let (Part::Payload, true) = (part, case.detached) {
        flip(detached, at, bit);
        return jws.to_owned();
    }
    if case.form == Form::Compact {
        let mut parts: Vec<String> = jws.split('.').map(String::from).collect();
        match part {
            Part::Protected => parts[0] = flip_encoded(&parts[0], at, bit),
            Part::Payload if case.b64 => parts[1] = flip_encoded(&parts[1], at, bit),
            Part::Payload => parts[1] = flip_text(&parts[1], at, bit),
            Part::Signature => parts[2] = flip_encoded(&parts[2], at, bit),
        }
        return parts.join(".");
    }
    let mut value: serde_json::Value = serde_json::from_str(jws).unwrap();
    let edit = |object: &mut serde_json::Value, name: &str, b64: bool| {
        let text = object[name].as_str().unwrap();
        let changed = if b64 {
            flip_encoded(text, at, bit)
        } else {
            flip_text(text, at, bit)
        };
        object[name] = serde_json::Value::from(changed);
    };
    if let Part::Payload = part {
        edit(&mut value, "payload", case.b64);
        return serde_json::to_string(&value).unwrap();
    }
    let id = case.signers[0].identity();
    for (i, spec) in case.signers.iter().enumerate() {
        if spec.identity() != id {
            continue;
        }
        let entry = match case.form {
            Form::General => &mut value["signatures"][i],
            _ => &mut value,
        };
        match part {
            Part::Protected if entry.get("protected").is_some() => edit(entry, "protected", true),
            _ => edit(entry, "signature", true),
        }
    }
    serde_json::to_string(&value).unwrap()
}

proptest! {
    // ADR 0009: at most 1,000 cases.
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// RFC 7515 §5.2 step 8: the signature covers the protected header and
    /// the payload, so changing one octet of either, or of the signature,
    /// makes verification fail, whatever the alg or serialization. For a
    /// detached JWS the payload is the one the verifier supplies
    /// (Appendix F).
    #[test]
    fn changing_one_octet_fails_verification(
        case in signable_case(),
        part in select(&[Part::Protected, Part::Payload, Part::Signature][..]),
        at in any::<Index>(),
        bit in 0u8..8,
    ) {
        let keys = case.keys();
        let jws = case.sign(&keys).unwrap();
        let allowed = [case.signers[0].alg.clone()];
        let key = &keys[0].verify;
        prop_assert!(case.verify(&jws, key, &allowed, &case.payload).is_ok());
        let mut detached = case.payload.clone();
        let tampered = tamper(&case, &jws, &mut detached, part, at, bit);
        let result = case.verify(&tampered, key, &allowed, &detached);
        prop_assert!(result.is_err(), "{part:?} changed, still verified: {tampered}");
    }

    /// RFC 8725 §3.1, ADR 0026 §2 step 7: with an allow-list holding none of
    /// the JWS's algorithms, every signer's key fails with
    /// AlgorithmNotAllowed, before any key or signature is looked at.
    #[test]
    fn an_alg_outside_the_allow_list_is_not_allowed(
        case in signable_case(),
        mask in prop::collection::vec(any::<bool>(), SigningAlg::KNOWN.len()),
    ) {
        let others: Vec<SigningAlg> = SigningAlg::KNOWN
            .iter()
            .filter(|alg| **alg != SigningAlg::None)
            .filter(|alg| case.signers.iter().all(|s| s.alg != **alg))
            .cloned()
            .collect();
        let mut allowed: Vec<SigningAlg> = others
            .iter()
            .zip(&mask)
            .filter(|(_, keep)| **keep)
            .map(|(alg, _)| alg.clone())
            .collect();
        if allowed.is_empty() {
            allowed.push(others[0].clone());
        }
        let keys = case.keys();
        let jws = case.sign(&keys).unwrap();
        for key in &keys {
            let result = case.verify(&jws, &key.verify, &allowed, &case.payload);
            prop_assert_eq!(result.map(drop).map_err(|e| e.code()), Err("AlgorithmNotAllowed"));
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
                    assert_eq!(*verified.payload, case.payload, "{what}");
                    assert_eq!(verified.signature_index, target, "{what}");
                    cells += 1;
                }
            }
        }
    }
    assert_eq!(cells, ALGS.len() * 3 * 2 * 2);
}

/// RFC 7520 §3.3 (Figure 3): the RSA public key's `n` (`e` is `AQAB`).
const RFC7520_N: &str = concat!(
    "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT",
    "-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqV",
    "wGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-",
    "oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde",
    "3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuC",
    "LqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5g",
    "HdrNP5zw",
);

/// RFC 7520 §4 (Figure 8): BASE64URL(JWS Payload) of §4.1 and §4.2.
const RFC7520_PAYLOAD: &str = concat!(
    "SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IH",
    "lvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBk",
    "b24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcm",
    "UgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4",
);

/// RFC 7520 §4.1.3 (Figure 13): the RS256 compact JWS, as `(protected,
/// signature)` around [`RFC7520_PAYLOAD`] (Figures 10 and 12).
const RFC7520_4_1: (&str, &str) = (
    "eyJhbGciOiJSUzI1NiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9",
    concat!(
        "MRjdkly7_-oTPTS3AXP41iQIGKa80A0ZmTuV5MEaHoxnW2e5CZ5NlKtainoFmK",
        "ZopdHM1O2U4mwzJdQx996ivp83xuglII7PNDi84wnB-BDkoBwA78185hX-Es4J",
        "IwmDLJK3lfWRa-XtL0RnltuYv746iYTh_qHRD68BNt1uSNCrUCTJDt5aAE6x8w",
        "W1Kt9eRo4QPocSadnHXFxnt8Is9UzpERV0ePPQdLuW3IS_de3xyIrDaLGdjluP",
        "xUAhb6L2aXic1U12podGU0KLUQSE_oI-ZnmKJ3F4uOZDnd6QZWJushZ41Axf_f",
        "cIe8u9ipH84ogoree7vjbU5y18kDquDg",
    ),
);

/// RFC 7520 §4.2.3 (Figure 20): the PS384 compact JWS (Figures 17, 19).
const RFC7520_4_2: (&str, &str) = (
    "eyJhbGciOiJQUzM4NCIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9",
    concat!(
        "cu22eBqkYDKgIlTpzDXGvaFfz6WGoz7fUDcfT0kkOy42miAh2qyBzk1xEsnk2I",
        "pN6-tPid6VrklHkqsGqDqHCdP6O8TTB5dDDItllVo6_1OLPpcbUrhiUSMxbbXU",
        "vdvWXzg-UD8biiReQFlfz28zGWVsdiNAUf8ZnyPEgVFn442ZdNqiVJRmBqrYRX",
        "e8P_ijQ7p8Vdz0TTrxUeT3lm8d9shnr2lfJT8ImUjvAA2Xez2Mlp8cBE5awDzT",
        "0qI0n6uiP1aCN_2_jLAeQTlqRHtfa64QQSUmFAAjVKPbByi7xho0uTOcbH510a",
        "6GYmJUAfmWjwZ6oD4ifKo8DYM-X72Eaw",
    ),
);

/// The RFC 7520 RSA tokens with their alg, and the §3.3 public key.
fn rfc7520_rsa() -> ([(String, SigningAlg); 2], Jwk) {
    let token =
        |(protected, signature): (&str, &str)| format!("{protected}.{RFC7520_PAYLOAD}.{signature}");
    let key = Jwk::from_json(format!(r#"{{"kty":"RSA","n":"{RFC7520_N}","e":"AQAB"}}"#).as_bytes())
        .unwrap();
    (
        [
            (token(RFC7520_4_1), SigningAlg::RS256),
            (token(RFC7520_4_2), SigningAlg::PS384),
        ],
        key,
    )
}

#[test]
fn rfc7520_rsa_tokens_verify() {
    // RFC 7520 §4.1 and §4.2: RSA is verify-only (ADR 0021), so these
    // published tokens stand in for a round trip.
    let (tokens, key) = rfc7520_rsa();
    for (jws, alg) in &tokens {
        let allowed = [alg.clone()];
        let verified = verify_compact(jws, &key, &VerifyOptions::new(&allowed).unwrap()).unwrap();
        assert!(
            verified
                .payload
                .starts_with("It\u{2019}s a dangerous business".as_bytes())
        );
    }
}

proptest! {
    // ADR 0009: at most 1,000 cases.
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// RFC 7515 §5.2, ADR 0021: one bit flipped anywhere in the RFC 7520
    /// §4.1 (RS256) or §4.2 (PS384) token, separators included, and it
    /// never verifies. The flip is in the low seven bits, so the token
    /// stays ASCII: a `&str` holds nothing else.
    #[test]
    fn flipping_a_bit_of_an_rfc7520_rsa_token_never_verifies(
        which in 0..2usize,
        at in any::<Index>(),
        bit in 0u8..7,
    ) {
        let (tokens, key) = rfc7520_rsa();
        let (jws, alg) = &tokens[which];
        let tampered = flip_text(jws, at, bit);
        prop_assert_ne!(&tampered, jws);
        let allowed = [alg.clone()];
        let result = verify_compact(&tampered, &key, &VerifyOptions::new(&allowed).unwrap());
        prop_assert!(result.is_err(), "still verified: {tampered}");
    }
}
