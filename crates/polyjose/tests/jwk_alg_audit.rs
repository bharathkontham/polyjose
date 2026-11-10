//! Independent audit of JWK `alg` strictness (feature 0001 F07): the
//! expected tables are spelled out here as literal registered names from
//! RFC 7518 §3.1, §4.1, §5.1, RFC 8037 §3.1, RFC 8812 §3.1 and RFC 9864,
//! not taken from the library's `KNOWN` lists, so an omission in those lists
//! is caught. JWK Set cases cover escaped member names and member placement.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

mod common;

use polyjose::Error;
use polyjose::jwk::{Jwk, JwkSet, KeyAlg};
use polyjose::util::b64url_encode;

const RSA_N: &str = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";

/// RFC 7517 Appendix A.2: the private members of the RSA key whose modulus
/// is `RSA_N` (RFC 7518 §6.3.2).
const RSA_D: &str = "X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q";
const RSA_P: &str = "83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs";
const RSA_Q: &str = "3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk";
const RSA_DP: &str = "G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0";
const RSA_DQ: &str = "s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk";
const RSA_QI: &str = "GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU";

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
        // Real points (the generators): import checks that a point is on
        // its curve (ADR 0041 §4).
        "P-256" | "secp256k1" | "P-384" | "P-521" => {
            let g = common::generator(kind);
            format!(r#"{{"kty":"EC","crv":"{kind}","x":"{}","y":"{}""#, g.x, g.y)
        }
        // A real Ed25519 key (RFC 8037 A.2): import rejects points with a
        // torsion component (ADR 0043 §1). Any 32 octets are an X25519 key.
        "Ed25519" => {
            r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo""#
                .to_owned()
        }
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
    // ADR 0067 §4: an RSA private member no longer fails the set. An
    // escaped member name is the member it decodes to (RFC 8259 §7), so a
    // complete private key spelled with escapes imports as private, and an
    // incomplete, multi-prime or malformed one is skipped like any other
    // unusable member (RFC 7517 §5), wherever it sits.
    let good = key("oct", r#","alg":"HS256""#);
    let bad_alg = key("oct", r#","alg":"RS256""#);
    let unusable = [
        // member name escaped: `d` alone is incomplete
        format!(r#"{{"kty":"RSA","n":"{RSA_N}","e":"AQAB","\u0064":"AQAB","alg":"RSA1_5"}}"#),
        // private member first, before kty: `p` alone is incomplete
        format!(r#"{{"\u0070":"AQAB","alg":"RS256","kty":"RSA","n":"{RSA_N}","e":"AQAB"}}"#),
        // kty value escaped, multi-prime (`oth`, ADR 0067 §3)
        format!(r#"{{"kty":"\u0052SA","n":"{RSA_N}","e":"AQAB","oth":[],"alg":"x"}}"#),
        // kty name escaped
        r#"{"\u006bty":"RSA","qi":7}"#.to_owned(),
        // otherwise malformed RSA with a private member
        r#"{"kty":"RSA","dq":null,"n":1}"#.to_owned(),
    ];
    // Alone, the escaped names are recognised as private members.
    let incomplete = Error::InvalidKey("RSA private key must have d, p, q, dp, dq and qi");
    for p in &unusable[..2] {
        assert_eq!(
            Jwk::from_json(p.as_bytes()).err(),
            Some(incomplete.clone()),
            "{p}"
        );
    }
    assert_eq!(
        Jwk::from_json(unusable[2].as_bytes()).err(),
        Some(Error::UnsupportedAlgorithm)
    );
    for p in &unusable {
        for layout in 0..3 {
            let (members, kept) = match layout {
                0 => (vec![p.clone()], 0),
                1 => (vec![bad_alg.clone(), good.clone(), p.clone()], 1),
                _ => (vec![p.clone(), bad_alg.clone()], 0),
            };
            let s = set(&members).unwrap_or_else(|e| panic!("{p}: {e}"));
            assert_eq!((s.len(), s.skipped()), (kept, members.len() - kept), "{p}");
        }
    }
    // RFC 7517 A.2's RSA private key with escaped member names (`d`, `qi`)
    // and an escaped kty value, first, middle or last: kept, private.
    let private = format!(
        r#"{{"kty":"\u0052SA","n":"{RSA_N}","e":"AQAB","\u0064":"{RSA_D}","p":"{RSA_P}","q":"{RSA_Q}","dp":"{RSA_DP}","dq":"{RSA_DQ}","\u0071\u0069":"{RSA_QI}","alg":"RS256"}}"#
    );
    for layout in 0..3 {
        let members = match layout {
            0 => vec![private.clone(), good.clone()],
            1 => vec![bad_alg.clone(), private.clone(), good.clone()],
            _ => vec![good.clone(), bad_alg.clone(), private.clone()],
        };
        let s = set(&members).unwrap_or_else(|e| panic!("{layout}: {e}"));
        assert_eq!(s.len(), 2, "{layout}");
        let rsa = s
            .keys()
            .iter()
            .find(|k| k.key_type() == polyjose::jwk::KeyType::Rsa)
            .unwrap();
        assert!(!rsa.is_public(), "{layout}");
        assert_eq!(rsa.alg(), Some(&KeyAlg::from("RS256")));
    }
    // Non-RSA kinds with d / p are not RSA private keys: kept. `d` = 1 is
    // the generator's private key (import checks the pair, ADR 0043 §3).
    let mut one = [0u8; 32];
    one[31] = 1;
    let ok = set(&[key(
        "P-256",
        r#","d":"AA","alg":"ES256""#.replace("AA", &b64url_encode(&one)).as_str(),
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
