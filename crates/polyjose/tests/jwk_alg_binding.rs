//! JWK `alg` strictness at import (RFC 7517 §4.4, RFC 7518 §3–§5,
//! RFC 8037 §3, RFC 8812 §3; ADRs 0006, 0021, 0022, 0026 §2 step 8, 0067), black
//! box (ADR 0008 layer 2): `RSA-OAEP` and `RSA1_5` are unsupported, a known
//! `alg` the key family cannot serve is a mismatch, unknown values are kept,
//! the error precedence is fixed, and a JWK Set skips such members.
//!
//! The expected family tables below are written out by hand from the ADRs,
//! not derived from the library, so they check it independently.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

mod common;

use polyjose::Error;
use polyjose::json::{self, Value};
use polyjose::jwa::{ContentEncAlg, KeyMgmtAlg, SigningAlg};
use polyjose::jwk::{Jwk, JwkSet, KeyAlg};
use polyjose::util::b64url_encode;

/// The 2048-bit modulus of RFC 7517 Appendix A.1.
const RSA_N: &str = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";

/// RFC 7517 Appendix A.2: the private members of the `RSA_N` key
/// (RFC 7518 §6.3.2), as JSON members to append after `n` and `e`.
const RSA_A2_PRIVATE: &str = r#","d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q","p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs","q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk","dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0","dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk","qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU""#;

/// The key kinds polyjose imports, by a short label.
const KINDS: &[&str] = &[
    "oct",
    "RSA",
    "P-256",
    "P-384",
    "P-521",
    "secp256k1",
    "Ed25519",
    "X25519",
];

/// An open JWK object (no closing brace) of `kind`. EC points and the
/// Ed25519 key are real (import checks them, ADR 0041 §4); the X25519 and
/// `oct` members are filler octets of the right length.
fn prefix(kind: &str) -> String {
    let coordinate = |len: usize| b64url_encode(&vec![7u8; len]);
    match kind {
        "oct" => format!(r#"{{"kty":"oct","k":"{}""#, coordinate(32)),
        "RSA" => format!(r#"{{"kty":"RSA","n":"{RSA_N}","e":"AQAB""#),
        "P-256" | "secp256k1" => ec(kind, 32),
        "P-384" => ec(kind, 48),
        "P-521" => ec(kind, 66),
        "Ed25519" => format!(
            r#"{{"kty":"OKP","crv":"Ed25519","x":"{}""#,
            common::ED25519_X
        ),
        "X25519" => format!(r#"{{"kty":"OKP","crv":"X25519","x":"{}""#, coordinate(32)),
        other => panic!("unknown kind {other}"),
    }
}

/// An open EC JWK: the curve's generator when `len` is its coordinate
/// length, otherwise filler coordinates of `len` octets (a wrong length).
fn ec(crv: &str, len: usize) -> String {
    let g = common::generator(crv);
    if g.len == len {
        format!(r#"{{"kty":"EC","crv":"{crv}","x":"{}","y":"{}""#, g.x, g.y)
    } else {
        let c = b64url_encode(&vec![7u8; len]);
        format!(r#"{{"kty":"EC","crv":"{crv}","x":"{c}","y":"{c}""#)
    }
}

/// A JWK of `kind` with `"alg": alg`.
fn with_alg(kind: &str, alg: &str) -> String {
    format!(r#"{},"alg":"{alg}"}}"#, prefix(kind))
}

fn import(json: &str) -> Result<Jwk, Error> {
    Jwk::from_json(json.as_bytes())
}

/// ADR 0026 §2 step 8: the key kinds each JWS `alg` binds to.
fn signing_kinds(alg: &SigningAlg) -> &'static [&'static str] {
    match alg.as_str() {
        "HS256" | "HS384" | "HS512" => &["oct"],
        "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" => &["RSA"],
        "ES256" => &["P-256"],
        "ES384" => &["P-384"],
        "ES512" => &["P-521"],
        "ES256K" => &["secp256k1"],
        "EdDSA" | "Ed25519" => &["Ed25519"],
        "none" => &[],
        other => panic!("{other} missing from the expected signing table"),
    }
}

/// RFC 7518 §4.3–§4.8, RFC 8037 §3.2 and ADR 0006: the key kinds each JWE
/// `alg` binds to. ECDH-ES is P-256/P-384/P-521 and X25519 only.
fn key_mgmt_kinds(alg: &KeyMgmtAlg) -> &'static [&'static str] {
    match alg.as_str() {
        "RSA-OAEP-256" => &["RSA"],
        "A128KW" | "A192KW" | "A256KW" | "A128GCMKW" | "A192GCMKW" | "A256GCMKW" | "dir"
        | "PBES2-HS256+A128KW" | "PBES2-HS384+A192KW" | "PBES2-HS512+A256KW" => &["oct"],
        "ECDH-ES" | "ECDH-ES+A128KW" | "ECDH-ES+A192KW" | "ECDH-ES+A256KW" => {
            &["P-256", "P-384", "P-521", "X25519"]
        }
        other => panic!("{other} missing from the expected key management table"),
    }
}

/// RFC 7517 §4.4 and RFC 7518 §4.5, §5: every known signing algorithm
/// imports on exactly the kinds of ADR 0026 §2 step 8, and is a
/// `KeyAlgorithmMismatch` on every other kind (`none` on all of them).
#[test]
fn signing_alg_family_matrix() {
    for alg in SigningAlg::KNOWN {
        let allowed = signing_kinds(alg);
        for kind in KINDS {
            let json = with_alg(kind, alg.as_str());
            let got = import(&json);
            if allowed.contains(kind) {
                let jwk = got.unwrap_or_else(|e| panic!("{alg} on {kind}: {e:?}"));
                assert_eq!(jwk.alg(), Some(&KeyAlg::Signing(alg.clone())));
            } else {
                assert_eq!(
                    got.err(),
                    Some(Error::KeyAlgorithmMismatch),
                    "{alg} on {kind}"
                );
            }
        }
    }
}

/// The JWE key management table (RFC 7518 §4, RFC 8037 §3.2, ADR 0006):
/// secp256k1 and Ed25519 keys never serve ECDH-ES.
#[test]
fn key_mgmt_alg_family_matrix() {
    for alg in KeyMgmtAlg::KNOWN {
        let allowed = key_mgmt_kinds(alg);
        for kind in KINDS {
            let got = import(&with_alg(kind, alg.as_str()));
            if allowed.contains(kind) {
                let jwk = got.unwrap_or_else(|e| panic!("{alg} on {kind}: {e:?}"));
                assert_eq!(jwk.alg(), Some(&KeyAlg::KeyMgmt(alg.clone())));
            } else {
                assert_eq!(
                    got.err(),
                    Some(Error::KeyAlgorithmMismatch),
                    "{alg} on {kind}"
                );
            }
        }
    }
}

/// A content encryption `enc` as a JWK `alg` names a symmetric CEK
/// (RFC 7518 §5.1, used directly with `dir`, §4.5): `oct` only.
#[test]
fn content_enc_alg_family_matrix() {
    for enc in ContentEncAlg::KNOWN {
        for kind in KINDS {
            let got = import(&with_alg(kind, enc.as_str()));
            if *kind == "oct" {
                let jwk = got.unwrap_or_else(|e| panic!("{enc} on {kind}: {e:?}"));
                assert_eq!(jwk.alg(), Some(&KeyAlg::ContentEnc(enc.clone())));
            } else {
                assert_eq!(
                    got.err(),
                    Some(Error::KeyAlgorithmMismatch),
                    "{enc} on {kind}"
                );
            }
        }
    }
}

/// ADR 0022 (`RSA-OAEP`, SHA-1) and ADR 0021 (`RSA1_5`): a JWK naming
/// either is `UnsupportedAlgorithm` on every key kind, RSA included.
#[test]
fn rsa_oaep_and_rsa1_5_are_unsupported_on_every_kind() {
    for alg in ["RSA-OAEP", "RSA1_5"] {
        for kind in KINDS {
            assert_eq!(
                import(&with_alg(kind, alg)).err(),
                Some(Error::UnsupportedAlgorithm),
                "{alg} on {kind}"
            );
        }
    }
}

/// Only the exact registered strings are rejected (RFC 7518 §7.1 names are
/// case-sensitive); near misses are unknown values and are kept.
#[test]
fn only_the_exact_unsupported_names_are_rejected() {
    for alg in [
        "rsa-oaep",
        "RSA-OAEP ",
        " RSA1_5",
        "RSA1_5\u{0}",
        "rsa1_5",
        "RSA_1_5",
        "RSA-OAEP-1",
    ] {
        let jwk = import(&with_alg("RSA", &alg.replace('\0', "\\u0000")))
            .unwrap_or_else(|e| panic!("{alg:?}: {e:?}"));
        assert_eq!(jwk.alg(), Some(&KeyAlg::Unknown(alg.to_owned())), "{alg:?}");
    }
}

/// Unknown `alg` values (unregistered, or registered but not shipped:
/// `Ed448`, `RSA-OAEP-384`, `HPKE-0`, `ML-DSA-44`) are kept verbatim on
/// every kind, re-serialize unchanged and do not change the thumbprint
/// (RFC 7517 §4.4 "MAY" values; RFC 7638 §3.2 hashes required members only).
#[test]
fn unknown_alg_is_preserved_and_round_trips() {
    for alg in [
        "x-custom",
        "Ed448",
        "RSA-OAEP-384",
        "HPKE-0",
        "ML-DSA-44",
        "",
        "HS256 ",
        "es256",
    ] {
        for kind in KINDS {
            let json = with_alg(kind, alg);
            let jwk = import(&json).unwrap_or_else(|e| panic!("{alg:?} on {kind}: {e:?}"));
            assert_eq!(jwk.alg(), Some(&KeyAlg::Unknown(alg.to_owned())));
            assert_eq!(jwk.alg().map(KeyAlg::as_str), Some(alg));
            assert_eq!(jwk.to_json().as_str(), json, "{alg:?} on {kind}");
            let plain = import(&format!("{}}}", prefix(kind))).unwrap();
            assert_eq!(jwk.thumbprint_sha256(), plain.thumbprint_sha256());
            if let Some(public) = jwk.to_public() {
                assert_eq!(public.alg(), jwk.alg());
            }
        }
    }
}

/// `Jwk::from_object` (the header `jwk`/`epk` path) applies the same rules.
#[test]
fn from_object_applies_the_same_rules() {
    let object = |json: &str| {
        json::parse(json.as_bytes())
            .ok()
            .and_then(Value::into_object)
            .unwrap()
    };
    let cases = [
        (with_alg("oct", "RS256"), Some(Error::KeyAlgorithmMismatch)),
        (
            with_alg("X25519", "EdDSA"),
            Some(Error::KeyAlgorithmMismatch),
        ),
        (
            with_alg("RSA", "RSA-OAEP"),
            Some(Error::UnsupportedAlgorithm),
        ),
        (with_alg("P-256", "ECDH-ES"), None),
        (with_alg("Ed25519", "x-future"), None),
    ];
    for (json, want) in cases {
        assert_eq!(Jwk::from_object(&object(&json)).err(), want, "{json}");
        assert_eq!(import(&json).err(), want, "{json}");
    }
}

/// The precedence, fixed and documented in `crate::jwk`:
/// 1. `kty`/`crv` support, and a multi-prime RSA key (`oth`, ADR 0067 §3);
/// 2. every structural check of the key and the common members, an
///    incomplete RSA private key included (ADR 0067);
/// 3. then the `alg` checks: `RSA-OAEP`/`RSA1_5`, then the family.
#[test]
fn error_precedence() {
    let rsa_d_only =
        |alg: &str| format!(r#"{{"kty":"RSA","n":"{RSA_N}","e":"AQAB","d":"AQAB","alg":"{alg}"}}"#);
    let rsa_private = |alg: &str| {
        format!(r#"{{"kty":"RSA","n":"{RSA_N}","e":"AQAB"{RSA_A2_PRIVATE},"alg":"{alg}"}}"#)
    };
    let incomplete = Error::InvalidKey("RSA private key must have d, p, q, dp, dq and qi");
    let cases: Vec<(String, Error)> = vec![
        // 1. `oth` (multi-prime) comes first, whatever else is wrong.
        (
            r#"{"kty":"RSA","n":"AQAB","oth":[],"alg":"HS256"}"#.to_owned(),
            Error::UnsupportedAlgorithm,
        ),
        (
            format!(r#"{{"kty":"RSA","n":"{RSA_N}","e":"AQAB","d":"AQAB","oth":7,"alg":"RS256"}}"#),
            Error::UnsupportedAlgorithm,
        ),
        // 2. An incomplete RSA private key is structural: it wins over
        // every alg check (ADR 0067).
        (rsa_d_only("RSA1_5"), incomplete.clone()),
        (rsa_d_only("HS256"), incomplete.clone()),
        (rsa_d_only("x-future"), incomplete.clone()),
        // 3. A complete RSA private key gets to the alg checks like a
        // public one.
        (rsa_private("RSA1_5"), Error::UnsupportedAlgorithm),
        (rsa_private("RSA-OAEP"), Error::UnsupportedAlgorithm),
        (rsa_private("HS256"), Error::KeyAlgorithmMismatch),
        (rsa_private("EdDSA"), Error::KeyAlgorithmMismatch),
        // An unsupported kty or crv is reported before the alg.
        (
            r#"{"kty":"OKP","crv":"Ed448","x":"AA","alg":"HS256"}"#.to_owned(),
            Error::UnsupportedAlgorithm,
        ),
        // 2. Structural errors of the key material win over the alg checks.
        (
            r#"{"kty":"oct","k":"","alg":"RS256"}"#.to_owned(),
            Error::InvalidKey("k must not be empty"),
        ),
        (
            r#"{"kty":"oct","k":"AA==","alg":"RSA-OAEP"}"#.to_owned(),
            Error::InvalidBase64,
        ),
        (
            format!(r#"{},"alg":"ES384"}}"#, ec("P-256", 31)),
            Error::InvalidKey("x has the wrong length for crv"),
        ),
        (
            r#"{"kty":"RSA","n":"AQAB","e":"AQAB","alg":"RSA1_5"}"#.to_owned(),
            Error::InvalidKey("RSA modulus is shorter than 2048 bits"),
        ),
        // ... and so do structural errors of the common members, wherever
        // they sit in the object.
        (
            format!(r#"{},"alg":"RS256","kid":7}}"#, prefix("oct")),
            Error::InvalidKey("kid must be a string"),
        ),
        (
            format!(r#"{},"x5c":"no","alg":"RSA-OAEP"}}"#, prefix("oct")),
            Error::InvalidKey("x5c must be an array of strings"),
        ),
        (
            format!(
                r#"{},"alg":"ES256","use":"sig","key_ops":["encrypt"]}}"#,
                prefix("oct")
            ),
            Error::InvalidKey("use and key_ops are inconsistent"),
        ),
        (
            format!(r#"{},"alg":["HS256"]}}"#, prefix("RSA")),
            Error::InvalidKey("alg must be a string"),
        ),
        // 3. A well-formed key: the unsupported names, then the family.
        (with_alg("oct", "RSA1_5"), Error::UnsupportedAlgorithm),
        (with_alg("oct", "RS256"), Error::KeyAlgorithmMismatch),
    ];
    for (json, want) in cases {
        assert_eq!(import(&json).err(), Some(want), "{json}");
    }
    // A complete RSA private key with an alg it serves imports (ADR 0067).
    for alg in ["RS256", "PS512", "RSA-OAEP-256", "x-future"] {
        let key = import(&rsa_private(alg)).unwrap_or_else(|e| panic!("{alg}: {e}"));
        assert!(!key.is_public(), "{alg}");
    }
}

/// `use` and `key_ops` do not affect the family check: a key whose `use`
/// matches the alg is still rejected if the family does not.
#[test]
fn use_and_key_ops_do_not_rescue_a_family_mismatch() {
    for extra in [
        r#""use":"sig""#,
        r#""key_ops":["verify"]"#,
        r#""use":"enc""#,
    ] {
        let json = format!(r#"{},{extra},"alg":"ES256"}}"#, prefix("P-384"));
        assert_eq!(
            import(&json).err(),
            Some(Error::KeyAlgorithmMismatch),
            "{json}"
        );
    }
}

/// RFC 7517 §5 / 0001-T07: a set skips members whose `alg` is unsupported
/// or does not fit the key, and keeps the rest in order.
#[test]
fn jwk_set_skips_alg_failures() {
    let members = [
        with_alg("oct", "HS256"),         // kept 0
        with_alg("RSA", "RSA-OAEP"),      // skipped
        with_alg("RSA", "RSA1_5"),        // skipped
        with_alg("oct", "RS256"),         // skipped
        with_alg("Ed25519", "ES256"),     // skipped
        with_alg("P-256", "ES384"),       // skipped
        with_alg("X25519", "EdDSA"),      // skipped
        with_alg("secp256k1", "ECDH-ES"), // skipped
        with_alg("RSA", "RSA-OAEP-256"),  // kept 1
        with_alg("P-256", "x-future"),    // kept 2
    ];
    let set = JwkSet::from_json(format!(r#"{{"keys":[{}]}}"#, members.join(",")).as_bytes())
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!((set.len(), set.skipped()), (3, 7));
    let algs: Vec<&str> = set
        .keys()
        .iter()
        .map(|k| k.alg().map_or("", KeyAlg::as_str))
        .collect();
    assert_eq!(algs, ["HS256", "RSA-OAEP-256", "x-future"]);
    let candidates: Vec<usize> = set
        .verification_candidates(&SigningAlg::HS256, None)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(candidates, [0]);
}

/// ADR 0067 §4 (amending ADR 0029 §3): an RSA private member no longer
/// fails the set. A complete one is kept when its alg fits; one with an
/// unsupported or mismatched alg, an incomplete one, or a multi-prime one
/// is skipped (RFC 7517 §5). JSON errors still fail the whole set.
#[test]
fn jwk_set_keeps_usable_rsa_private_keys_and_still_fails_on_json_errors() {
    let p_only =
        |alg: &str| format!(r#"{{"kty":"RSA","n":"{RSA_N}","e":"AQAB","p":"AQAB","alg":"{alg}"}}"#);
    let complete = |alg: &str| {
        format!(r#"{{"kty":"RSA","n":"{RSA_N}","e":"AQAB"{RSA_A2_PRIVATE},"alg":"{alg}"}}"#)
    };
    let multi = |alg: &str| {
        format!(
            r#"{{"kty":"RSA","n":"{RSA_N}","e":"AQAB"{RSA_A2_PRIVATE},"oth":[],"alg":"{alg}"}}"#
        )
    };
    for alg in ["RSA1_5", "RSA-OAEP", "HS256", "RS256"] {
        for member in [p_only(alg), complete(alg), multi(alg)] {
            let doc = format!(r#"{{"keys":[{},{member}]}}"#, with_alg("RSA", "RSA-OAEP"));
            let set = JwkSet::from_json(doc.as_bytes()).unwrap_or_else(|e| panic!("{alg}: {e}"));
            let kept = usize::from(alg == "RS256" && member == complete(alg));
            assert_eq!((set.len(), set.skipped()), (kept, 2 - kept), "{member}");
            assert!(set.keys().iter().all(|k| !k.is_public()), "{alg}");
        }
    }
    let duplicate = r#"{"keys":[{"kty":"oct","k":"AA","alg":"RS256","alg":"RS256"}]}"#;
    assert!(matches!(
        JwkSet::from_json(duplicate.as_bytes()),
        Err(Error::InvalidJson(_))
    ));
}

/// The errors never echo the rejected `alg`.
#[test]
fn errors_do_not_echo_the_alg() {
    for (kind, alg) in [("RSA", "RSA-OAEP"), ("oct", "RS256"), ("X25519", "EdDSA")] {
        let err = import(&with_alg(kind, alg)).unwrap_err();
        assert!(!format!("{err:?}").contains(alg), "{err:?}");
        assert!(!err.to_string().contains(alg), "{err}");
        assert!(Error::CODES.contains(&err.code()));
    }
}
