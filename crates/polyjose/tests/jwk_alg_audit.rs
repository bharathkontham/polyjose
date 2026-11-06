//! Independent audit of JWK `alg` strictness (feature 0001 F07): the
//! expected tables are spelled out here as literal registered names from
//! RFC 7518 §3.1, §4.1, §5.1, RFC 8037 §3.1, RFC 8812 §3.1 and RFC 9864,
//! not taken from the library's `KNOWN` lists, so an omission in those lists
//! is caught. JWK Set cases cover escaped member names and member placement.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

use polyjose::Error;
use polyjose::jwk::{Jwk, JwkSet, KeyAlg};
use polyjose::util::b64url_encode;

const RSA_N: &str = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";

const KINDS: [&str; 8] = [
    "oct",
    "RSA",
    "P-256",
    "P-384",
    "P-521",
    "secp256k1",
    "Ed25519",
    "X25519",
];

fn key(kind: &str, tail: &str) -> String {
    let c = |n: usize| b64url_encode(&vec![9u8; n]);
    let head = match kind {
        "oct" => format!(r#"{{"kty":"oct","k":"{}""#, c(32)),
        "RSA" => format!(r#"{{"kty":"RSA","n":"{RSA_N}","e":"AQAB""#),
        "P-256" | "secp256k1" => {
            format!(r#"{{"kty":"EC","crv":"{kind}","x":"{0}","y":"{0}""#, c(32))
        }
        "P-384" => format!(r#"{{"kty":"EC","crv":"P-384","x":"{0}","y":"{0}""#, c(48)),
        "P-521" => format!(r#"{{"kty":"EC","crv":"P-521","x":"{0}","y":"{0}""#, c(66)),
        _ => format!(r#"{{"kty":"OKP","crv":"{kind}","x":"{}""#, c(32)),
    };
    format!("{head}{tail}}}")
}

fn outcome(kind: &str, alg: &str) -> Result<Jwk, Error> {
    Jwk::from_json(key(kind, &format!(r#","alg":"{alg}""#)).as_bytes())
}

/// (alg, kinds that serve it). Literal RFC names.
fn expected() -> Vec<(&'static str, Vec<&'static str>)> {
    let mut t: Vec<(&str, Vec<&str>)> = Vec::new();
    for a in ["HS256", "HS384", "HS512"] {
        t.push((a, vec!["oct"])); // RFC 7518 §3.2
    }
    for a in ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"] {
        t.push((a, vec!["RSA"])); // RFC 7518 §3.3, §3.5
    }
    t.push(("ES256", vec!["P-256"])); // RFC 7518 §3.4
    t.push(("ES384", vec!["P-384"]));
    t.push(("ES512", vec!["P-521"]));
    t.push(("ES256K", vec!["secp256k1"])); // RFC 8812 §3.1
    t.push(("EdDSA", vec!["Ed25519"])); // RFC 8037 §3.1
    t.push(("Ed25519", vec!["Ed25519"])); // RFC 9864
    t.push(("none", vec![])); // RFC 7518 §3.6, never a key's alg
    t.push(("RSA-OAEP-256", vec!["RSA"])); // §4.3
    for a in [
        "A128KW",
        "A192KW",
        "A256KW",
        "dir",
        "A128GCMKW",
        "A192GCMKW",
        "A256GCMKW",
        "PBES2-HS256+A128KW",
        "PBES2-HS384+A192KW",
        "PBES2-HS512+A256KW",
    ] {
        t.push((a, vec!["oct"]));
    }
    for a in [
        "ECDH-ES",
        "ECDH-ES+A128KW",
        "ECDH-ES+A192KW",
        "ECDH-ES+A256KW",
    ] {
        t.push((a, vec!["P-256", "P-384", "P-521", "X25519"])); // §4.6, RFC 8037 §3.2
    }
    for e in [
        "A128CBC-HS256",
        "A192CBC-HS384",
        "A256CBC-HS512",
        "A128GCM",
        "A192GCM",
        "A256GCM",
    ] {
        t.push((e, vec!["oct"])); // §5.1
    }
    t
}

#[test]
fn literal_rfc_matrix_every_alg_on_every_kind() {
    for (alg, ok) in expected() {
        for kind in KINDS {
            let got = outcome(kind, alg);
            if ok.contains(&kind) {
                let jwk = got.unwrap_or_else(|e| panic!("{alg} on {kind}: {e:?}"));
                assert_eq!(jwk.alg().map(KeyAlg::as_str), Some(alg));
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

#[test]
fn escaped_alg_names_decode_before_the_check() {
    // JSON escapes decode before the check: u0052 is R, u002d is '-', u005f is '_'.
    assert_eq!(
        outcome("oct", r"\u0052S256").err(),
        Some(Error::KeyAlgorithmMismatch)
    );
    assert_eq!(
        outcome("oct", r"RSA\u002dOAEP").err(),
        Some(Error::UnsupportedAlgorithm)
    );
    assert_eq!(
        outcome("RSA", r"RSA1\u005f5").err(),
        Some(Error::UnsupportedAlgorithm)
    );
    // Non-string alg is structural.
    for v in ["7", "null", "true", "[]", "{}"] {
        let j = key("oct", &format!(r#","alg":{v}"#));
        assert!(
            matches!(Jwk::from_json(j.as_bytes()), Err(Error::InvalidKey(_))),
            "{v}"
        );
    }
}

fn set(members: &[String]) -> Result<JwkSet, Error> {
    JwkSet::from_json(format!(r#"{{"keys":[{}]}}"#, members.join(",")).as_bytes())
}

#[test]
fn set_rsa_private_wherever_placed_and_however_escaped() {
    let good = key("oct", r#","alg":"HS256""#);
    let bad_alg = key("oct", r#","alg":"RS256""#);
    let privates = [
        // member name escaped
        format!(r#"{{"kty":"RSA","n":"{RSA_N}","e":"AQAB","\u0064":"AQAB","alg":"RSA1_5"}}"#),
        // private member first, before kty
        format!(r#"{{"\u0070":"AQAB","alg":"RS256","kty":"RSA","n":"{RSA_N}","e":"AQAB"}}"#),
        // kty value escaped
        format!(r#"{{"kty":"\u0052SA","n":"{RSA_N}","e":"AQAB","oth":[],"alg":"x"}}"#),
        // kty name escaped
        r#"{"\u006bty":"RSA","qi":7}"#.to_owned(),
        // otherwise malformed RSA with a private member
        r#"{"kty":"RSA","dq":null,"n":1}"#.to_owned(),
    ];
    for p in &privates {
        for layout in 0..3 {
            let members = match layout {
                0 => vec![p.clone()],
                1 => vec![bad_alg.clone(), good.clone(), p.clone()],
                _ => vec![p.clone(), bad_alg.clone()],
            };
            assert_eq!(
                set(&members).err(),
                Some(Error::UnsupportedAlgorithm),
                "{p}"
            );
        }
    }
    // Non-RSA kinds with d / p are not RSA private keys: kept.
    let ok = set(&[key(
        "P-256",
        r#","d":"AA","alg":"ES256""#.replace("AA", &b64url_encode(&[9u8; 32])).as_str(),
    )])
    .unwrap();
    assert_eq!(ok.len(), 1);
    let oct_d = set(&[key("oct", r#","d":"AQAB","alg":"HS256""#)]).unwrap();
    assert_eq!(oct_d.len(), 1);
    // lower-case "rsa" is an unsupported kty: skipped, not fatal.
    let s = set(&[r#"{"kty":"rsa","d":"AQAB"}"#.to_owned(), good.clone()]).unwrap();
    assert_eq!((s.len(), s.skipped()), (1, 1));
}

#[test]
fn set_json_errors_still_fail_after_skippable_members() {
    let skip = key("oct", r#","alg":"RS256""#);
    for tail in [
        r#"{"kty":"oct","k":"AA","k":"AA"}"#,
        r#"{"kty":"oct","k":"AA","alg":"\ud800"}"#,
    ] {
        let doc = format!(r#"{{"keys":[{skip},{tail}]}}"#);
        assert!(
            matches!(
                JwkSet::from_json(doc.as_bytes()),
                Err(Error::InvalidJson(_))
            ),
            "{tail}"
        );
    }
    // A set of only skippable members is empty, not an error.
    let s = set(&[skip.clone(), key("RSA", r#","alg":"RSA-OAEP""#)]).unwrap();
    assert_eq!((s.len(), s.skipped()), (0, 2));
}

#[test]
fn thumbprint_unaffected_by_any_accepted_alg() {
    for (alg, ok) in expected() {
        for kind in ok {
            let with = outcome(kind, alg).unwrap();
            let without = Jwk::from_json(key(kind, "").as_bytes()).unwrap();
            assert_eq!(
                with.thumbprint_sha256(),
                without.thumbprint_sha256(),
                "{alg} {kind}"
            );
        }
    }
}
