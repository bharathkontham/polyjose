//! ECDH-ES and ECDH-ES+A128KW/A192KW/A256KW (RFC 7518 §4.6) through the
//! public API (0003 T13), on P-256, P-384, P-521 and X25519.
//!
//! - RFC 7520 §5.4 (P-384, ECDH-ES+A128KW, A128GCM) and §5.5 (P-256,
//!   ECDH-ES, A128CBC-HS256) decrypt with the RFC key, and (with
//!   `insecure-test-vectors`) `encrypt_reproducible` reproduces the compact
//!   output byte for byte from the RFC's random values. The values are read
//!   from the vendored ietf-jose cookbook, never transcribed.
//! - RFC 7518 Appendix C: Alice's ephemeral key, Bob's key and apu/apv
//!   "Alice"/"Bob" give a JWE that Bob decrypts.
//! - Every invalid `epk` is `DecryptionFailed`; the "no agreement ran"
//!   proofs are unit tests in `src/jwe/ecdh_es.rs` (the counter exists only
//!   under `cfg(test)`).
//! - Encrypt errors: `apu == apv` and direct ECDH-ES with more than one
//!   recipient are `InvalidFormat`.
//! - A property test round-trips 4 curves × 4 algs × 6 `enc`.
#![allow(clippy::panic)] // test code: a panic is a failed assertion

use polyjose::Error;
use polyjose::header::Header;
use polyjose::jwa::{ContentEncAlg, KeyMgmtAlg};
use polyjose::jwe::{DecryptPolicy, Encryptor, JsonForm, Recipient, decrypt_compact};
use polyjose::jwk::{EcCurve, Jwk, OkpCurve};
use polyjose::keys::{KeySpec, generate};
use polyjose::util::{b64url_decode, b64url_encode};
use proptest::prelude::*;
use serde_json::Value;

use ContentEncAlg as E;
use KeyMgmtAlg as A;

const ALGS: [KeyMgmtAlg; 4] = [A::EcdhEs, A::EcdhEsA128KW, A::EcdhEsA192KW, A::EcdhEsA256KW];

fn jwk(json: &str) -> Jwk {
    Jwk::from_json(json.as_bytes()).unwrap_or_else(|e| panic!("{json}: {e}"))
}

fn public(key: &Jwk) -> Jwk {
    key.to_public().unwrap_or_else(|| panic!("no public part"))
}

fn policy(algs: &[KeyMgmtAlg], encs: &[ContentEncAlg]) -> DecryptPolicy {
    DecryptPolicy::new(algs, encs).unwrap_or_else(|e| panic!("{e}"))
}

fn all_ecdh() -> DecryptPolicy {
    policy(&ALGS, ContentEncAlg::KNOWN)
}

fn bytes(b64u: &str) -> Vec<u8> {
    b64url_decode(b64u).unwrap_or_else(|e| panic!("{b64u}: {e}"))
}

// ---------------------------------------------------------------------------
// RFC 7520 §5.4 and §5.5, from the vendored cookbook
// ---------------------------------------------------------------------------

/// One RFC 7520 §5 example of `tests/third_party/ietf-jose-cookbook/jwe/`.
struct Cookbook(Value);

impl Cookbook {
    fn c54() -> Cookbook {
        Cookbook::parse(include_str!(
            "third_party/ietf-jose-cookbook/jwe/5_4.key_agreement_with_key_wrapping_using_ecdh-es_and_aes-keywrap_with_aes-gcm.json"
        ))
    }

    fn c55() -> Cookbook {
        Cookbook::parse(include_str!(
            "third_party/ietf-jose-cookbook/jwe/5_5.key_agreement_using_ecdh-es_with_aes-cbc-hmac-sha2.json"
        ))
    }

    fn parse(text: &str) -> Cookbook {
        Cookbook(serde_json::from_str(text).unwrap_or_else(|e| panic!("{e}")))
    }

    fn str(&self, path: &[&str]) -> &str {
        path.iter()
            .fold(&self.0, |v, k| &v[k])
            .as_str()
            .unwrap_or_else(|| panic!("{path:?}"))
    }

    /// `input.key`, the recipient's private key (RFC 7520 Figures 107, 118).
    fn key(&self) -> Jwk {
        jwk(&self.0["input"]["key"].to_string())
    }

    fn plaintext(&self) -> &[u8] {
        self.str(&["input", "plaintext"]).as_bytes()
    }

    fn compact(&self) -> &str {
        self.str(&["output", "compact"])
    }

    fn alg(&self) -> KeyMgmtAlg {
        KeyMgmtAlg::from(self.str(&["input", "alg"]))
    }

    fn enc(&self) -> ContentEncAlg {
        ContentEncAlg::from(self.str(&["input", "enc"]))
    }

    fn kid(&self) -> &str {
        self.str(&["input", "key", "kid"])
    }
}

#[test]
fn rfc7520_5_4_decrypts() {
    let c = Cookbook::c54();
    assert_eq!((c.alg(), c.enc()), (A::EcdhEsA128KW, E::A128GCM));
    let d = decrypt_compact(c.compact(), &c.key(), &policy(&[c.alg()], &[c.enc()]))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(d.plaintext(), c.plaintext());
    assert_eq!(d.header().kid.as_deref(), Some(c.kid()));
    assert!(d.header().epk.is_some());
}

#[test]
fn rfc7520_5_5_decrypts() {
    let c = Cookbook::c55();
    assert_eq!((c.alg(), c.enc()), (A::EcdhEs, E::A128CbcHs256));
    // RFC 7516 §5.2 step 10: the encrypted key segment is empty.
    assert!(c.compact().contains(".."));
    let d = decrypt_compact(c.compact(), &c.key(), &policy(&[c.alg()], &[c.enc()]))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(d.plaintext(), c.plaintext());
}

#[test]
fn rfc7520_vectors_need_the_private_key_and_an_allowed_alg() {
    for c in [Cookbook::c54(), Cookbook::c55()] {
        // A public key cannot decrypt (RFC 7518 §4.6, plan.md error
        // contract): it is not a candidate.
        let result = decrypt_compact(c.compact(), &public(&c.key()), &all_ecdh());
        assert_eq!(result.map(|_| ()), Err(Error::KeyAlgorithmMismatch));
        // RFC 8725 §3.1: the allow-list decides, not the header.
        let other = if c.alg() == A::EcdhEs {
            A::EcdhEsA128KW
        } else {
            A::EcdhEs
        };
        let result = decrypt_compact(c.compact(), &c.key(), &policy(&[other], &[c.enc()]));
        assert_eq!(result.map(|_| ()), Err(Error::AlgorithmNotAllowed));
        // Another key of the same curve fails as DecryptionFailed.
        let crv = if c.alg() == A::EcdhEs {
            EcCurve::P256
        } else {
            EcCurve::P384
        };
        let other_key = generate(KeySpec::Ec(crv)).unwrap_or_else(|e| panic!("{e}"));
        let result = decrypt_compact(c.compact(), &other_key, &all_ecdh());
        assert_eq!(result.map(|_| ()), Err(Error::DecryptionFailed));
    }
}

#[cfg(feature = "insecure-test-vectors")]
mod reproducible {
    use polyjose::insecure_test_vectors::FixedRng;
    use polyjose::jwe::Serialization;

    use super::*;

    fn kid_header(kid: &str) -> Header {
        Header::from_json(format!(r#"{{"kid":"{kid}"}}"#).as_bytes())
            .unwrap_or_else(|e| panic!("{e}"))
    }

    /// The RFC's compact JWE from its random values in the documented draw
    /// order (`jwe::random`): the CEK (random modes only), the ephemeral d
    /// (one draw: the RFC d is below n), then the content IV.
    fn reproduce(c: &Cookbook, rng_bytes: Vec<u8>) {
        let mut rng = FixedRng::new(rng_bytes);
        let token = Encryptor::new(c.enc())
            .protected_header(kid_header(c.kid()))
            .recipient(Recipient::new(c.alg(), &public(&c.key())))
            .encrypt_reproducible(
                c.plaintext(),
                Serialization::Compact,
                &mut rng,
                Some(c.str(&["encrypting_content", "protected_b64u"])),
            )
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(token, c.compact());
        assert_eq!(rng.remaining(), 0);
    }

    #[test]
    fn rfc7520_5_4_is_reproduced() {
        let c = Cookbook::c54();
        let rng = [
            bytes(c.str(&["generated", "cek"])),
            bytes(c.str(&["encrypting_key", "epk", "d"])),
            bytes(c.str(&["generated", "iv"])),
        ]
        .concat();
        assert_eq!(rng.len(), 16 + 48 + 12);
        reproduce(&c, rng);
    }

    #[test]
    fn rfc7520_5_5_is_reproduced() {
        let c = Cookbook::c55();
        let rng = [
            bytes(c.str(&["encrypting_key", "epk", "d"])),
            bytes(c.str(&["generated", "iv"])),
        ]
        .concat();
        assert_eq!(rng.len(), 32 + 16);
        reproduce(&c, rng);
    }

    #[test]
    fn a_wrong_ephemeral_d_does_not_reproduce() {
        // The hook refuses a protected header that differs from the one
        // built (another epk), so the RFC output is never faked.
        let c = Cookbook::c55();
        let mut d = bytes(c.str(&["encrypting_key", "epk", "d"]));
        d[31] ^= 1;
        let mut rng = FixedRng::new([d, bytes(c.str(&["generated", "iv"]))].concat());
        let result = Encryptor::new(c.enc())
            .protected_header(kid_header(c.kid()))
            .recipient(Recipient::new(c.alg(), &public(&c.key())))
            .encrypt_reproducible(
                c.plaintext(),
                Serialization::Compact,
                &mut rng,
                Some(c.str(&["encrypting_content", "protected_b64u"])),
            );
        assert!(matches!(result, Err(Error::InvalidFormat(_))));
    }

    #[test]
    fn rfc7518_appendix_c_end_to_end() {
        // RFC 7518 Appendix C: Alice encrypts to Bob with her printed
        // ephemeral key, apu "Alice" and apv "Bob"; Bob decrypts. The
        // header carries Alice's public key and the printed apu/apv.
        let mut rng = FixedRng::new([bytes(app_c::ALICE_D), vec![0x42; 12]].concat());
        let token = Encryptor::new(E::A128GCM)
            .recipient(
                Recipient::new(A::EcdhEs, &public(&jwk(app_c::BOB)))
                    .apu(b"Alice".to_vec())
                    .apv(b"Bob".to_vec()),
            )
            .encrypt_reproducible(b"Appendix C", Serialization::Compact, &mut rng, None)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(rng.remaining(), 0);
        let d = decrypt_compact(&token, &jwk(app_c::BOB), &all_ecdh())
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(d.plaintext(), b"Appendix C");
        assert_eq!(d.header().apu.as_deref(), Some("QWxpY2U"));
        assert_eq!(d.header().apv.as_deref(), Some("Qm9i"));
        let epk = d.header().epk.as_ref().unwrap_or_else(|| panic!("epk"));
        assert_eq!(
            Jwk::from_object(epk).map(|k| k.to_json().to_string()),
            Ok(jwk(app_c::ALICE_EPK).to_json().to_string())
        );
        // The CEK itself (the printed derived key) is not visible here; the
        // unit test `ecdh_es::tests::rfc7518_appendix_c_end_to_end` pins it.
    }
}

/// RFC 7518 Appendix C keys (P-256).
mod app_c {
    pub const ALICE_D: &str = "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo";
    #[cfg_attr(
        not(feature = "insecure-test-vectors"),
        allow(dead_code, reason = "used by the reproducible tests only")
    )]
    pub const ALICE_EPK: &str = r#"{"kty":"EC","crv":"P-256","x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0","y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"}"#;
    pub const BOB: &str = r#"{"kty":"EC","crv":"P-256","x":"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ","y":"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck","d":"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"}"#;
}

// ---------------------------------------------------------------------------
// Round trips
// ---------------------------------------------------------------------------

/// A private key on each ECDH-ES curve (RFC 7518 §6.2.1.1, RFC 8037 §3.2).
fn keys() -> [Jwk; 4] {
    [
        KeySpec::Ec(EcCurve::P256),
        KeySpec::Ec(EcCurve::P384),
        KeySpec::Ec(EcCurve::P521),
        KeySpec::Okp(OkpCurve::X25519),
    ]
    .map(|spec| generate(spec).unwrap_or_else(|e| panic!("{e}")))
}

fn round_trip(key: &Jwk, alg: &KeyMgmtAlg, enc: &ContentEncAlg, plaintext: &[u8]) -> String {
    let token = Encryptor::new(enc.clone())
        .recipient(Recipient::new(alg.clone(), &public(key)))
        .encrypt_compact(plaintext)
        .unwrap_or_else(|e| panic!("{alg} {enc}: {e}"));
    let p = policy(std::slice::from_ref(alg), std::slice::from_ref(enc));
    let d = decrypt_compact(&token, key, &p).unwrap_or_else(|e| panic!("{alg} {enc}: {e}"));
    assert_eq!(d.plaintext(), plaintext, "{alg} {enc}");
    assert_eq!(d.header().alg.as_deref(), Some(alg.as_str()));
    token
}

#[test]
fn x25519_round_trips_for_every_alg() {
    // RFC 8037 §3.2: ECDH-ES and ECDH-ES+A*KW with X25519 keys; the epk is
    // an OKP key with only kty, crv and x.
    let key = generate(KeySpec::Okp(OkpCurve::X25519)).unwrap_or_else(|e| panic!("{e}"));
    for alg in &ALGS {
        let token = round_trip(&key, alg, &E::A256GCM, b"X25519");
        let header = token.split('.').next().unwrap_or_default();
        let header = Header::from_json(&bytes(header)).unwrap_or_else(|e| panic!("{e}"));
        let epk = header.epk.unwrap_or_else(|| panic!("epk"));
        let names: Vec<&str> = epk.iter().map(|(n, _)| n).collect();
        assert_eq!(names, ["kty", "crv", "x"]);
        let empty_key = token.split('.').nth(1) == Some("");
        assert_eq!(empty_key, *alg == A::EcdhEs, "{alg}");
    }
}

#[test]
fn nist_round_trips_for_every_alg_carry_a_full_length_epk() {
    // RFC 7518 §6.2.1.2–§6.2.1.3: x and y at the full coordinate length.
    for (key, len) in keys().iter().take(3).zip([32, 48, 66]) {
        for alg in &ALGS {
            let token = round_trip(key, alg, &E::A128CbcHs256, b"NIST");
            let header = token.split('.').next().unwrap_or_default();
            let header = Header::from_json(&bytes(header)).unwrap_or_else(|e| panic!("{e}"));
            let epk = header.epk.unwrap_or_else(|| panic!("epk"));
            for member in ["x", "y"] {
                let value = epk.get(member).and_then(|v| v.as_str()).unwrap_or_default();
                assert_eq!(bytes(value).len(), len, "{alg} {member}");
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(384))]

    /// RFC 7518 §4.6 over 4 curves × 4 algs × 6 enc: every combination
    /// round-trips, with or without apu/apv, and flipping one tag bit is
    /// DecryptionFailed.
    #[test]
    fn every_curve_alg_and_enc_round_trips(
        curve in 0usize..4,
        alg in 0usize..4,
        enc in 0usize..6,
        apu in proptest::option::of(proptest::collection::vec(any::<u8>(), 0..16)),
        plaintext in proptest::collection::vec(any::<u8>(), 0..200),
    ) {
        thread_local! {
            static KEYS: [Jwk; 4] = keys();
        }
        let key = KEYS.with(|keys| keys[curve].clone());
        let alg = ALGS[alg].clone();
        let enc = ContentEncAlg::KNOWN[enc].clone();
        let mut recipient = Recipient::new(alg.clone(), &public(&key));
        if let Some(apu) = &apu {
            recipient = recipient.apu(apu.clone()).apv(b"recipient".to_vec());
        }
        let token = Encryptor::new(enc.clone())
            .recipient(recipient)
            .encrypt_compact(&plaintext)
            .unwrap_or_else(|e| panic!("{alg} {enc}: {e}"));
        let p = policy(std::slice::from_ref(&alg), std::slice::from_ref(&enc));
        let d = decrypt_compact(&token, &key, &p).unwrap_or_else(|e| panic!("{alg} {enc}: {e}"));
        prop_assert_eq!(d.plaintext(), plaintext.as_slice());
        let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
        let mut tag = bytes(&parts[4]);
        tag[0] ^= 0x80;
        parts[4] = b64url_encode(&tag);
        prop_assert_eq!(
            decrypt_compact(&parts.join("."), &key, &p).map(|_| ()),
            Err(Error::DecryptionFailed)
        );
    }
}

// ---------------------------------------------------------------------------
// Invalid epk and encrypted key (all DecryptionFailed)
// ---------------------------------------------------------------------------

/// A compact JWE whose protected header is `header_json`, with an empty or
/// given encrypted key and dummy content parts (RFC 7516 §7.1). Key
/// management fails before the content parts are used.
fn forge(header_json: &str, encrypted_key: &[u8]) -> String {
    [
        b64url_encode(header_json.as_bytes()),
        b64url_encode(encrypted_key),
        b64url_encode(&[0x11; 12]),
        b64url_encode(b"ciphertext"),
        b64url_encode(&[0x22; 16]),
    ]
    .join(".")
}

#[test]
fn every_invalid_epk_is_decryption_failed() {
    // RFC 8725 §3.4, RFC 7518 §4.6.1.1, ADR 0041 §4. Bob's P-256 key.
    let bob = jwk(app_c::BOB);
    let epk = |x: &str, y: &str| format!(r#"{{"kty":"EC","crv":"P-256","x":"{x}","y":"{y}"}}"#);
    let (ax, ay) = (
        "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
        "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
    );
    let zero = "A".repeat(43);
    let cases = [
        ("missing epk", String::new()),
        (
            "private d",
            format!(
                r#","epk":{{"kty":"EC","crv":"P-256","x":"{ax}","y":"{ay}","d":"{}"}}"#,
                app_c::ALICE_D
            ),
        ),
        (
            "kty OKP",
            r#","epk":{"kty":"OKP","crv":"X25519","x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"}"#.to_owned(),
        ),
        (
            "crv P-384",
            // RFC 7520 §5.4's epk: a valid P-384 point, on the wrong curve.
            r#","epk":{"kty":"EC","crv":"P-384","x":"uBo4kHPw6kbjx5l0xowrd_oYzBmaz-GKFZu4xAFFkbYiWgutEK6iuEDsQ6wNdNg3","y":"sp3p5SGhZVC2faXumI-e9JU2Mo8KpoYrFDr5yPNVtW4PgEwZOyQTA-JdaY8tb7E0"}"#.to_owned(),
        ),
        ("x 31 octets", format!(r#","epk":{}"#, epk(&ax[..42], ay))),
        ("off-curve", format!(r#","epk":{}"#, epk(ax, "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFppo"))),
        ("identity (0, 0)", format!(r#","epk":{}"#, epk(&zero, &zero))),
        (
            "invalid-curve point",
            format!(
                r#","epk":{}"#,
                epk(
                    "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
                    "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfY"
                )
            ),
        ),
        (
            "twist point",
            format!(
                r#","epk":{}"#,
                epk(
                    "793jsyhyqe_887lMv3Oqezn5aD7OkSG5hSFn9OPaYJs",
                    "6rahtGMUwhn3AU4EFtzM7Ice2VkxZ8AgMIZQw-EQ6Uo"
                )
            ),
        ),
        ("epk not an object", r#","epk":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0""#.to_owned()),
    ];
    for (what, epk_member) in &cases {
        for alg in &ALGS {
            let header = format!(r#"{{"alg":"{alg}","enc":"A128GCM"{epk_member}}}"#);
            let ek: &[u8] = if *alg == A::EcdhEs { &[] } else { &[0xA6; 24] };
            let result = decrypt_compact(&forge(&header, ek), &bob, &all_ecdh());
            let expected = if *what == "epk not an object" {
                // RFC 7516 §4.1, ADR 0026: a registered header parameter of
                // the wrong type is a header error, before key management.
                Err(Error::InvalidHeader("epk must be a JSON object"))
            } else {
                Err(Error::DecryptionFailed)
            };
            assert_eq!(result.map(|_| ()), expected, "{what} {alg}");
        }
    }
}

#[test]
fn direct_ecdh_es_with_a_non_empty_encrypted_key_is_decryption_failed() {
    // RFC 7516 §5.2 step 10. Re-encode RFC 7520 §5.5 with one key byte.
    let c = Cookbook::c55();
    let parts: Vec<&str> = c.compact().split('.').collect();
    let token = [parts[0], "AA", parts[2], parts[3], parts[4]].join(".");
    let result = decrypt_compact(&token, &c.key(), &all_ecdh());
    assert_eq!(result.map(|_| ()), Err(Error::DecryptionFailed));
}

#[test]
fn a_low_order_x25519_epk_is_decryption_failed() {
    // RFC 7748 §6.1: Wycheproof `LowOrderPublic` points give the all-zero
    // shared secret, which is rejected.
    let key = generate(KeySpec::Okp(OkpCurve::X25519)).unwrap_or_else(|e| panic!("{e}"));
    for u in [
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "4Ot6fDtBuK4WVuP68Z_EatoJjeucMrH9hmIFFl9JuAA",
    ] {
        for alg in &ALGS {
            let header = format!(
                r#"{{"alg":"{alg}","enc":"A128GCM","epk":{{"kty":"OKP","crv":"X25519","x":"{u}"}}}}"#
            );
            let ek: &[u8] = if *alg == A::EcdhEs { &[] } else { &[0xA6; 24] };
            let result = decrypt_compact(&forge(&header, ek), &key, &all_ecdh());
            assert_eq!(
                result.map(|_| ()),
                Err(Error::DecryptionFailed),
                "{alg} {u}"
            );
        }
    }
}

#[test]
fn a_tampered_epk_or_apu_is_decryption_failed() {
    // Changing the epk or apu of a valid JWE changes the derived key (and
    // the AAD): DecryptionFailed, never another error.
    let key = jwk(app_c::BOB);
    let token = Encryptor::new(E::A128GCM)
        .recipient(Recipient::new(A::EcdhEsA128KW, &public(&key)).apu(b"Alice".to_vec()))
        .encrypt_compact(b"tamper")
        .unwrap_or_else(|e| panic!("{e}"));
    let parts: Vec<&str> = token.split('.').collect();
    let header = String::from_utf8(bytes(parts[0])).unwrap_or_else(|e| panic!("{e}"));
    for tampered in [
        header.replace(r#""apu":"QWxpY2U""#, r#""apu":"Qm9i""#),
        header.replace(r#""apu":"QWxpY2U""#, r#""apu":"QWxpY2U","apv":"Qm9i""#),
    ] {
        assert_ne!(tampered, header);
        let forged = [
            &b64url_encode(tampered.as_bytes()),
            parts[1],
            parts[2],
            parts[3],
            parts[4],
        ]
        .join(".");
        let result = decrypt_compact(&forged, &key, &all_ecdh());
        assert_eq!(result.map(|_| ()), Err(Error::DecryptionFailed));
    }
}

// ---------------------------------------------------------------------------
// Encrypt errors
// ---------------------------------------------------------------------------

#[test]
fn apu_equal_to_apv_is_invalid_format() {
    // RFC 7518 §4.6.2: "The "apu" and "apv" values MUST be distinct, when
    // used."
    let key = public(&jwk(app_c::BOB));
    for alg in &ALGS {
        let result = Encryptor::new(E::A128GCM)
            .recipient(
                Recipient::new(alg.clone(), &key)
                    .apu(b"same".to_vec())
                    .apv(b"same".to_vec()),
            )
            .encrypt_compact(b"x");
        assert!(matches!(result, Err(Error::InvalidFormat(_))), "{alg}");
    }
}

#[test]
fn direct_ecdh_es_with_more_than_one_recipient_is_invalid_format() {
    // Direct Key Agreement determines the CEK from one recipient's key
    // (RFC 7516 §5.1 step 5, RFC 7518 §4.6), so it cannot have two
    // recipients (plan.md error contract; panva/jose 6.2.8).
    let a = public(&jwk(app_c::BOB));
    let b = public(&generate(KeySpec::Okp(OkpCurve::X25519)).unwrap_or_else(|e| panic!("{e}")));
    let pairs = [
        (A::EcdhEs, A::EcdhEs),
        (A::EcdhEs, A::EcdhEsA128KW),
        (A::EcdhEsA128KW, A::EcdhEs),
    ];
    for (first, second) in pairs {
        for form in [JsonForm::General, JsonForm::Flattened] {
            let result = Encryptor::new(E::A128GCM)
                .recipient(Recipient::new(first.clone(), &a))
                .recipient(Recipient::new(second.clone(), &b))
                .encrypt_json(b"x", form);
            assert!(
                matches!(result, Err(Error::InvalidFormat(_))),
                "{first} + {second}"
            );
        }
    }
}

#[test]
fn encrypt_needs_a_public_key_of_an_ecdh_family() {
    // RFC 8725 §3.1, plan.md error contract: a key that cannot serve
    // ECDH-ES is KeyAlgorithmMismatch before any cryptography; an Ed25519
    // key "MUST NOT be used for ECDH-ES" (RFC 8037 §3.2).
    let oct = jwk(r#"{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}"#);
    let ed25519 = generate(KeySpec::Okp(OkpCurve::Ed25519)).unwrap_or_else(|e| panic!("{e}"));
    for key in [oct, ed25519] {
        for alg in &ALGS {
            let result = Encryptor::new(E::A128GCM)
                .recipient(Recipient::new(alg.clone(), &key))
                .encrypt_compact(b"x");
            assert_eq!(
                result.map(|_| ()),
                Err(Error::KeyAlgorithmMismatch),
                "{alg}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Tester T13 (adversarial): points computed independently in Python
// ---------------------------------------------------------------------------

/// Per curve, `(label, x, y)` of epk coordinates that must all be refused (RFC 8725
/// §3.4, SP 800-56A r3 §5.6.2.3.4). Computed with Python integers, never by the
/// library under test:
/// - `alias_x` and `x_eq_p`: a point of the curve whose x is written as x + p
///   or p (a coordinate >= p, the same field element as x or 0);
/// - `y_eq_p`: y = p;
/// - `order2`, `order2b`: order-2 points (y = 0) of the curve y^2 = x^3 - 3x
///   over the same field (b' = 0), a small-subgroup attack;
/// - `other_b`: a point of y^2 = x^3 - 3x + b + 1 over the same field.
const ADVERSARIAL_EPKS: &[(EcCurve, &str, &str, &str, &str)] = &[
    (
        EcCurve::P256,
        "alias_x",
        "P-256",
        "_____wAAAAEAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAQ",
        "RZJDuapYGAb-kTvOmYF63hHKUDxk2aPFM0FcCDJI-8w",
    ),
    (
        EcCurve::P256,
        "x_eq_p",
        "P-256",
        "_____wAAAAEAAAAAAAAAAAAAAAD_______________8",
        "ZkhceA4vg9ckM71dhKBrtlQcKvMdrocXKL-FahdPk_Q",
    ),
    (
        EcCurve::P256,
        "order2",
        "P-256",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ),
    (
        EcCurve::P256,
        "other_b",
        "P-256",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAc",
        "iHUg-1_zc53z6OJxrLX362J7kNEyKryhc105u7PPWgs",
    ),
    (
        EcCurve::P256,
        "y_eq_p",
        "P-256",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAU",
        "_____wAAAAEAAAAAAAAAAAAAAAD_______________8",
    ),
    (
        EcCurve::P384,
        "alias_x",
        "P-384",
        "__________________________________________7_____AAAAAAAAAAEAAAAJ",
        "DOQKzMvAqs-L2vvY-i2idOzMtl0Ry3DhvpMEU8GZbTz7jGt8tqNWQjwO6ACQtDl9",
    ),
    (
        EcCurve::P384,
        "x_eq_p",
        "P-384",
        "__________________________________________7_____AAAAAAAAAAD_____",
        "wwZhD7CuWhWc9FwGBp8ipsXrNkHGAtQt6ixLT3VVB5NAbYDSuRrVT5BIvUh68a3h",
    ),
    (
        EcCurve::P384,
        "order2",
        "P-384",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ),
    (
        EcCurve::P384,
        "other_b",
        "P-384",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAH",
        "EQvFUNjPlHFk00zkQQt1n2yNFVonCl9efFOC2SwEdm6t-U6upyYEHHv6hPZTFn6X",
    ),
    (
        EcCurve::P384,
        "order2b",
        "P-384",
        "lWZaUytYEk44-CgHQe0X7r_MccHrRanDj8OX5c5lwGIeBvD71Ae_DIpxdjV60xNZ",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ),
    (
        EcCurve::P384,
        "y_eq_p",
        "P-384",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAK",
        "__________________________________________7_____AAAAAAAAAAD_____",
    ),
    (
        EcCurve::P521,
        "alias_x",
        "P-521",
        "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAF",
        "AbzZSv4v7tRe6TBtcIbTyHZm11yiQYwpubGlfCxj8jLnv3kOjlbDY-WDuuKspKK5-Ak5AVofJnv4DxQKo-4mlzqg",
    ),
    (
        EcCurve::P521,
        "x_eq_p",
        "P-521",
        "Af______________________________________________________________________________________",
        "AS3xNgFZSog-8tk15Eu5C_TWYZt05Sr3VS-XdpARwHGetDnPqyqI1A_lmivtH0NVcWmi0KLM0oDGB7krv1H_4LB4",
    ),
    (
        EcCurve::P521,
        "order2",
        "P-521",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ),
    (
        EcCurve::P521,
        "other_b",
        "P-521",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAH",
        "AWdXJS7YfrPuKuy_MT_c0IW_8JXj5iL-2SfBrRGiotE5cVs9Vd999fRWAF1Tek_4P74xpezN1mYfaS-GheE9X4v4",
    ),
    (
        EcCurve::P521,
        "y_eq_p",
        "P-521",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAG",
        "Af______________________________________________________________________________________",
    ),
];

#[test]
fn adversarial_epks_are_decryption_failed_for_every_recipient_curve() {
    // Each point above, sent to a recipient on its own curve and to recipients
    // on every other curve and to X25519: always DecryptionFailed.
    let keys: Vec<(EcCurve, Jwk)> = [EcCurve::P256, EcCurve::P384, EcCurve::P521]
        .into_iter()
        .map(|crv| {
            (
                crv,
                generate(KeySpec::Ec(crv)).unwrap_or_else(|e| panic!("{e}")),
            )
        })
        .collect();
    let x25519 = generate(KeySpec::Okp(OkpCurve::X25519)).unwrap_or_else(|e| panic!("{e}"));
    for (_, label, crv, x, y) in ADVERSARIAL_EPKS {
        let epk = format!(r#"{{"kty":"EC","crv":"{crv}","x":"{x}","y":"{y}"}}"#);
        for alg in &ALGS {
            let header = format!(r#"{{"alg":"{alg}","enc":"A128GCM","epk":{epk}}}"#);
            let ek: &[u8] = if *alg == A::EcdhEs { &[] } else { &[0xA6; 24] };
            let token = forge(&header, ek);
            for (_, key) in &keys {
                assert_eq!(
                    decrypt_compact(&token, key, &all_ecdh()).map(|_| ()),
                    Err(Error::DecryptionFailed),
                    "{label} {crv} {alg}"
                );
            }
            assert_eq!(
                decrypt_compact(&token, &x25519, &all_ecdh()).map(|_| ()),
                Err(Error::DecryptionFailed),
                "{label} {crv} {alg} x25519"
            );
        }
    }
}
