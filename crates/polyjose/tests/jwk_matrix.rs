//! Independent tester matrix for the T05 structural JWK validation: every
//! (crv, member, length) cell, the RSA 2047/2048-bit boundary, the RSA
//! private-member precedence, and escaped member names. Written from the
//! RFC text (RFC 7518 §6.2, §6.3, RFC 8037 §2, RFC 8812 §3.1), not from the
//! implementation.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

mod common;

use polyjose::Error;
use polyjose::jwk::Jwk;
use polyjose::util::b64url_encode;

fn import(json: &str) -> Result<Jwk, Error> {
    Jwk::from_json(json.as_bytes())
}

fn code(json: &str) -> &'static str {
    match import(json) {
        Ok(_) => "OK",
        Err(Error::InvalidKey(_)) => "InvalidKey",
        Err(Error::UnsupportedAlgorithm) => "UnsupportedAlgorithm",
        Err(Error::InvalidBase64) => "InvalidBase64",
        Err(Error::InvalidJson(_)) => "InvalidJson",
        Err(_) => "other",
    }
}

fn b(len: usize) -> String {
    b64url_encode(&vec![0x11; len])
}

#[test]
fn ec_every_curve_member_and_length_cell() {
    for (crv, len) in [
        ("P-256", 32),
        ("P-384", 48),
        ("P-521", 66),
        ("secp256k1", 32),
    ] {
        // A member of the curve's own length is the real generator key (G,
        // d = 1), since import checks the point and the scalar (ADR 0041
        // §4); any other length is filler, rejected before those checks.
        let g = common::generator(crv);
        let member = |n: usize, real: &str| if n == len { real.to_owned() } else { b(n) };
        let key = |x: usize, y: usize, d: Option<usize>| {
            let d = d
                .map(|d| format!(r#","d":"{}""#, member(d, g.d)))
                .unwrap_or_default();
            format!(
                r#"{{"kty":"EC","crv":"{crv}","x":"{}","y":"{}"{d}}}"#,
                member(x, g.x),
                member(y, g.y)
            )
        };
        assert_eq!(code(&key(len, len, None)), "OK", "{crv} public");
        assert_eq!(code(&key(len, len, Some(len))), "OK", "{crv} private");
        for bad in [0, 1, len - 1, len + 1, 2 * len] {
            assert_eq!(code(&key(bad, len, None)), "InvalidKey", "{crv} x={bad}");
            assert_eq!(code(&key(len, bad, None)), "InvalidKey", "{crv} y={bad}");
            assert_eq!(
                code(&key(len, len, Some(bad))),
                "InvalidKey",
                "{crv} d={bad}"
            );
        }
        // The other curves' lengths are wrong for this one unless equal.
        for other in [32, 48, 66] {
            let expect = if other == len { "OK" } else { "InvalidKey" };
            assert_eq!(
                code(&key(other, other, Some(other))),
                expect,
                "{crv}/{other}"
            );
        }
        // y and x are required.
        let no_y = format!(r#"{{"kty":"EC","crv":"{crv}","x":"{}"}}"#, b(len));
        assert_eq!(code(&no_y), "InvalidKey");
        let no_x = format!(r#"{{"kty":"EC","crv":"{crv}","y":"{}"}}"#, b(len));
        assert_eq!(code(&no_x), "InvalidKey");
    }
}

#[test]
fn ec_and_okp_unknown_or_out_of_scope_curves_are_unsupported() {
    let x = b(32);
    for crv in [
        "P-192",
        "P-224",
        "p-256",
        "P256",
        "secp256r1",
        "K-256",
        "Ed25519",
        "X25519",
        "Ed448",
        "X448",
        "",
        "BrainpoolP256r1",
    ] {
        let j = format!(r#"{{"kty":"EC","crv":"{crv}","x":"{x}","y":"{x}"}}"#);
        assert_eq!(code(&j), "UnsupportedAlgorithm", "EC {crv}");
    }
    for crv in [
        "Ed448",
        "X448",
        "ed25519",
        "x25519",
        "EdDSA",
        "P-256",
        "secp256k1",
        "",
    ] {
        let j = format!(r#"{{"kty":"OKP","crv":"{crv}","x":"{x}"}}"#);
        assert_eq!(code(&j), "UnsupportedAlgorithm", "OKP {crv}");
    }
    // Ed448 / X448 with their real 57 / 56 octet keys: still unsupported,
    // not a length error.
    let ed448 = format!(r#"{{"kty":"OKP","crv":"Ed448","x":"{}"}}"#, b(57));
    assert_eq!(code(&ed448), "UnsupportedAlgorithm");
    let x448 = format!(
        r#"{{"kty":"OKP","crv":"X448","x":"{}","d":"{}"}}"#,
        b(56),
        b(56)
    );
    assert_eq!(code(&x448), "UnsupportedAlgorithm");
}

#[test]
fn okp_x_and_d_must_be_32_octets() {
    for crv in ["Ed25519", "X25519"] {
        // At 32 octets, the RFC 8037 A.1 key pair: import rejects Ed25519
        // points with a torsion component and a `d` that does not derive
        // `x` (ADR 0043 §1, §3). The other lengths fail on length alone.
        let sized = |len: usize, real: &str| if len == 32 { real.to_owned() } else { b(len) };
        let key = |x: usize, d: Option<usize>| {
            let d = d
                .map(|d| {
                    format!(
                        r#","d":"{}""#,
                        sized(d, "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A")
                    )
                })
                .unwrap_or_default();
            format!(
                r#"{{"kty":"OKP","crv":"{crv}","x":"{}"{d}}}"#,
                sized(x, "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")
            )
        };
        assert_eq!(code(&key(32, None)), "OK");
        assert_eq!(code(&key(32, Some(32))), "OK");
        for bad in [0, 1, 31, 33, 57, 64] {
            assert_eq!(code(&key(bad, None)), "InvalidKey", "{crv} x={bad}");
            assert_eq!(code(&key(32, Some(bad))), "InvalidKey", "{crv} d={bad}");
        }
        assert_eq!(
            code(&format!(r#"{{"kty":"OKP","crv":"{crv}"}}"#)),
            "InvalidKey"
        );
    }
}

fn rsa_n(len: usize, first: u8, last: u8) -> String {
    let mut n = vec![0x55; len];
    n[0] = first;
    n[len - 1] = last;
    b64url_encode(&n)
}

#[test]
fn rsa_modulus_2047_2048_boundary() {
    let e = "AQAB";
    let rsa = |n: &str| format!(r#"{{"kty":"RSA","n":"{n}","e":"{e}"}}"#);
    // 2048 bits exactly: 256 octets, top bit set.
    assert_eq!(code(&rsa(&rsa_n(256, 0x80, 1))), "OK");
    assert_eq!(code(&rsa(&rsa_n(256, 0xff, 1))), "OK");
    // 2047 bits: 256 octets, top bit clear (0x7f is the largest).
    assert_eq!(code(&rsa(&rsa_n(256, 0x7f, 1))), "InvalidKey");
    assert_eq!(code(&rsa(&rsa_n(256, 0x01, 1))), "InvalidKey");
    // 2040 bits and below.
    assert_eq!(code(&rsa(&rsa_n(255, 0xff, 1))), "InvalidKey");
    assert_eq!(code(&rsa(&rsa_n(1, 0xff, 0xff))), "InvalidKey");
    // 2049 bits: 257 octets, first octet 0x01.
    assert_eq!(code(&rsa(&rsa_n(257, 0x01, 1))), "OK");
    // Leading zero octet: non-minimal even if the value is >= 2048 bits.
    assert_eq!(code(&rsa(&rsa_n(257, 0x00, 1))), "InvalidKey");
    assert_eq!(code(&rsa(&rsa_n(258, 0x00, 1))), "InvalidKey");
    // Empty.
    assert_eq!(code(&rsa("")), "InvalidKey");
}

#[test]
fn rsa_exponent_rules() {
    let n = rsa_n(256, 0x80, 1);
    let rsa = |e: &str| format!(r#"{{"kty":"RSA","n":"{n}","e":"{e}"}}"#);
    // Valid odd exponents >= 3.
    for e in ["Aw", "BQ", "AQAB", "Ag" /* 2 */] {
        let expect = if e == "Ag" { "InvalidKey" } else { "OK" };
        assert_eq!(code(&rsa(e)), expect, "{e}");
    }
    // 0, 1, even, empty, leading zero.
    for e in ["AA", "AQ", "BA", "CA", "AQAA", "", "AAEAAQ", "AAM"] {
        assert_eq!(code(&rsa(e)), "InvalidKey", "{e}");
    }
    // Not canonical / padded / url-unsafe.
    for e in ["AQAB=", "AQA B", "AQA+", "AQA/", "AR"] {
        assert_eq!(code(&rsa(e)), "InvalidBase64", "{e}");
    }
}

#[test]
fn rsa_any_private_member_alone_wins_over_every_other_error() {
    let valid_n = rsa_n(256, 0x80, 1);
    for member in ["d", "p", "q", "dp", "dq", "qi", "oth"] {
        // Alone, with garbage n/e, with a short n, with a bad `use`, with
        // wrong-typed members: always UnsupportedAlgorithm.
        let cases = [
            format!(r#"{{"kty":"RSA","{member}":"AQAB"}}"#),
            format!(r#"{{"kty":"RSA","n":"@@","e":"@@","{member}":"AQAB"}}"#),
            format!(r#"{{"kty":"RSA","n":"AQAB","e":"AA","{member}":"AQAB"}}"#),
            format!(
                r#"{{"kty":"RSA","n":"{valid_n}","e":"AQAB","use":5,"key_ops":3,"{member}":"x"}}"#
            ),
            format!(r#"{{"{member}":"AQAB","kid":[],"kty":"RSA"}}"#),
            // A member name spelled with a JSON escape is the same member.
            format!(
                r#"{{"kty":"RSA","n":"{valid_n}","e":"AQAB","\u00{:02x}{}":"AQAB"}}"#,
                member.as_bytes()[0],
                &member[1..]
            ),
        ];
        for c in cases {
            assert_eq!(code(&c), "UnsupportedAlgorithm", "{c}");
        }
    }
    // Without a private member the same garbage is a plain InvalidKey.
    assert_eq!(code(r#"{"kty":"RSA","n":"AQAB","e":"AQAB"}"#), "InvalidKey");
    // RFC 7517 Appendix A.2's real RSA private key.
    let a2 = r#"{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q"}"#;
    assert_eq!(code(a2), "UnsupportedAlgorithm");
}

#[test]
fn private_members_are_not_special_on_other_key_types() {
    // `p`/`q`/`oth` on EC, OKP and oct are unknown members, kept and ignored
    // (RFC 7517 §4), never an RSA private key.
    let g = common::generator("P-256");
    let ec = format!(
        r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}","p":"AQAB","oth":[]}}"#,
        g.x, g.y
    );
    assert_eq!(code(&ec), "OK");
    assert_eq!(code(r#"{"kty":"oct","k":"AA","d":"AQAB","p":1}"#), "OK");
}

#[test]
fn secrets_with_bad_encoding_report_invalid_base64_without_panic() {
    for k in [
        "A",
        "AAA=",
        "AA==",
        "A A",
        "\u{e9}\u{e9}",
        "AB",
        "-_-_/",
        "AAEC\n",
    ] {
        let j = format!(r#"{{"kty":"oct","k":"{}"}}"#, k.replace('\n', "\\n"));
        assert_eq!(code(&j), "InvalidBase64", "{k:?}");
    }
}

#[test]
fn duplicate_names_including_escaped_spellings_are_rejected() {
    assert_eq!(code(r#"{"kty":"oct","k":"AA","k":"AQ"}"#), "InvalidJson");
    assert_eq!(code(r#"{"kty":"oct","k":"AA","k":"AQ"}"#), "InvalidJson");
    assert_eq!(code(r#"{"kty":"oct","kty":"oct","k":"AA"}"#), "InvalidJson");
}
