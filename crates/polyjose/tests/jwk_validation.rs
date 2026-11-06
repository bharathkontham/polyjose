//! Structural JWK validation (RFC 7517 §4, RFC 7518 §2 and §6,
//! RFC 8037 §2, RFC 8812 §3.1, ADR 0021): every rejection and its stable
//! error code, through the public API with raw JSON input.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

mod common;

use polyjose::Error;
use polyjose::json::{self, Value};
use polyjose::jwk::{Jwk, KeyMaterial, KeyOp, KeyUse, OkpCurve};
use polyjose::util::b64url_encode;

/// The 2048-bit modulus of RFC 7517 Appendix A.1.
const RSA_N: &str = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";

fn err(json: &str) -> Option<Error> {
    Jwk::from_json(json.as_bytes()).err()
}

fn ok(json: &str) -> Jwk {
    match Jwk::from_json(json.as_bytes()) {
        Ok(jwk) => jwk,
        Err(e) => panic!("rejected {json}: {e:?}"),
    }
}

fn b64(len: usize, byte: u8) -> String {
    b64url_encode(&vec![byte; len])
}

fn ec(crv: &str, x: &str, y: &str, d: Option<&str>) -> String {
    let d = d.map(|d| format!(r#","d":"{d}""#)).unwrap_or_default();
    format!(r#"{{"kty":"EC","crv":"{crv}","x":"{x}","y":"{y}"{d}}}"#)
}

fn okp(crv: &str, x: &str, d: Option<&str>) -> String {
    let d = d.map(|d| format!(r#","d":"{d}""#)).unwrap_or_default();
    format!(r#"{{"kty":"OKP","crv":"{crv}","x":"{x}"{d}}}"#)
}

fn rsa(n: &str, e: &str) -> String {
    format!(r#"{{"kty":"RSA","n":"{n}","e":"{e}"}}"#)
}

/// A modulus of `len` octets with first octet `first` and an odd last one.
fn modulus(len: usize, first: u8) -> String {
    let mut n = vec![0x5a; len];
    n[0] = first;
    n[len - 1] = 0x01;
    b64url_encode(&n)
}

fn oct_with(extra: &str) -> String {
    format!(r#"{{"kty":"oct","k":"AAEC"{extra}}}"#)
}

#[test]
fn kty_is_required_case_sensitive_and_supported() {
    assert_eq!(
        err(r#"{"k":"AAEC"}"#),
        Some(Error::InvalidKey("kty is missing"))
    );
    for kty in ["1", "null", "[\"oct\"]", "{}", "true"] {
        let json = format!(r#"{{"kty":{kty},"k":"AAEC"}}"#);
        assert_eq!(
            err(&json),
            Some(Error::InvalidKey("kty must be a string")),
            "{json}"
        );
    }
    // RFC 7517 §4.1: case-sensitive, so these are unknown key types.
    for kty in ["OCT", "ec", "rsa", "okp", "AKP", "", " oct"] {
        let json = format!(r#"{{"kty":"{kty}","k":"AAEC"}}"#);
        assert_eq!(err(&json), Some(Error::UnsupportedAlgorithm), "{json}");
    }
}

#[test]
fn from_json_needs_one_i_json_object() {
    for json in ["[]", "\"jwk\"", "1", "null", ""] {
        assert!(matches!(err(json), Some(Error::InvalidJson(_))), "{json}");
    }
    // RFC 7517 §4: duplicate member names are rejected, even when escaped.
    let dup = r#"{"kty":"oct","k":"AAEC","k":"AAED"}"#;
    assert!(matches!(err(dup), Some(Error::InvalidJson(_))));
    assert!(matches!(
        Jwk::from_json(b"{\"kty\":\"oct\",\"k\":\"\xff\"}").err(),
        Some(Error::InvalidJson(_))
    ));
}

#[test]
fn ec_accepts_exact_lengths_for_every_curve() {
    for (crv, len) in [
        ("P-256", 32),
        ("P-384", 48),
        ("P-521", 66),
        ("secp256k1", 32),
    ] {
        // Real points: import checks that they are on the curve (ADR 0041 §4).
        let g = common::generator(crv);
        let public = ok(&ec(crv, g.x, g.y, None));
        assert!(public.is_public(), "{crv}");
        let private = ok(&ec(crv, g.x, g.y, Some(g.d)));
        assert!(!private.is_public(), "{crv}");
        let KeyMaterial::Ec(key) = private.material() else {
            panic!("not EC")
        };
        assert_eq!(key.crv().as_str(), crv);
        assert_eq!((key.x().len(), key.y().len()), (len, len));
        // Leading zero octets are part of the fixed-size encoding (RFC 8812
        // §3.1: "with any leading zeros preserved").
        let z = common::LEADING_ZEROS.iter().find(|k| k.crv == crv).unwrap();
        assert_eq!(z.len, len);
        ok(&ec(crv, z.x, z.y, Some(z.d)));
    }
}

#[test]
fn ec_rejects_wrong_lengths() {
    for (crv, len) in [
        ("P-256", 32),
        ("P-384", 48),
        ("P-521", 66),
        ("secp256k1", 32),
    ] {
        let good = b64(len, 7);
        for bad_len in [0, 1, len - 1, len + 1, 2 * len] {
            let bad = b64(bad_len, 7);
            assert_eq!(
                err(&ec(crv, &bad, &good, None)),
                Some(Error::InvalidKey("x has the wrong length for crv")),
                "{crv} x {bad_len}"
            );
            assert_eq!(
                err(&ec(crv, &good, &bad, None)),
                Some(Error::InvalidKey("y has the wrong length for crv")),
                "{crv} y {bad_len}"
            );
            assert_eq!(
                err(&ec(crv, &good, &good, Some(&bad))),
                Some(Error::InvalidKey("d has the wrong length for crv")),
                "{crv} d {bad_len}"
            );
        }
    }
    // P-521 is 66 octets, not 65 or 64 (RFC 7518 §6.2.1.2 example).
    assert!(err(&ec("P-521", &b64(65, 1), &b64(65, 1), None)).is_some());
}

#[test]
fn ec_rejects_unknown_curves_and_missing_or_mistyped_members() {
    let c = b64(32, 1);
    // Unknown, case-mismatched, or another key type's curve.
    for crv in [
        "P-192",
        "p-256",
        "P256",
        "secp256r1",
        "brainpoolP256r1",
        "Ed25519",
        "X25519",
        "",
    ] {
        assert_eq!(
            err(&ec(crv, &c, &c, None)),
            Some(Error::UnsupportedAlgorithm),
            "{crv}"
        );
    }
    let base = format!(r#""kty":"EC","crv":"P-256","x":"{c}","y":"{c}""#);
    assert_eq!(
        err(&format!(r#"{{"kty":"EC","x":"{c}","y":"{c}"}}"#)),
        Some(Error::InvalidKey("crv is missing"))
    );
    assert_eq!(
        err(&format!(r#"{{"kty":"EC","crv":256,"x":"{c}","y":"{c}"}}"#)),
        Some(Error::InvalidKey("crv must be a string"))
    );
    // RFC 7518 §6.2.1: y is required for all four curves (no compressed
    // points, RFC 8812 §3.1).
    assert_eq!(
        err(&format!(r#"{{"kty":"EC","crv":"P-256","x":"{c}"}}"#)),
        Some(Error::InvalidKey("y is missing"))
    );
    assert_eq!(
        err(&format!(r#"{{"kty":"EC","crv":"P-256","y":"{c}"}}"#)),
        Some(Error::InvalidKey("x is missing"))
    );
    assert_eq!(
        err(&format!(
            r#"{{"kty":"EC","crv":"P-256","x":"{c}","y":true}}"#
        )),
        Some(Error::InvalidKey("y must be a string"))
    );
    assert_eq!(
        err(&format!(
            r#"{{"kty":"EC","crv":"P-256","x":["{c}"],"y":"{c}"}}"#
        )),
        Some(Error::InvalidKey("x must be a string"))
    );
    assert_eq!(
        err(&format!(r#"{{{base},"d":null}}"#)),
        Some(Error::InvalidKey("d must be a string"))
    );
}

#[test]
fn binary_members_must_be_canonical_unpadded_base64url() {
    let c = b64(32, 1);
    let padded = format!("{c}=");
    let std_alphabet = c.replace('A', "+");
    let non_canonical = "AQ_".to_owned() + &c[3..42] + "B"; // 43 chars, non-zero pad bits
    for bad in [
        padded.as_str(),
        &std_alphabet,
        &non_canonical,
        "A",
        "!!!!",
        "QQ QQ",
    ] {
        assert_eq!(
            err(&ec("P-256", bad, &c, None)),
            Some(Error::InvalidBase64),
            "{bad}"
        );
        assert_eq!(
            err(&ec("P-256", &c, &c, Some(bad))),
            Some(Error::InvalidBase64),
            "{bad}"
        );
        assert_eq!(
            err(&okp("Ed25519", bad, None)),
            Some(Error::InvalidBase64),
            "{bad}"
        );
        assert_eq!(err(&rsa(bad, "AQAB")), Some(Error::InvalidBase64), "{bad}");
        assert_eq!(err(&rsa(RSA_N, bad)), Some(Error::InvalidBase64), "{bad}");
        let oct = format!(r#"{{"kty":"oct","k":"{bad}"}}"#);
        assert_eq!(err(&oct), Some(Error::InvalidBase64), "{bad}");
    }
}

#[test]
fn okp_accepts_only_ed25519_and_x25519_with_32_octet_members() {
    for (crv, curve) in [("Ed25519", OkpCurve::Ed25519), ("X25519", OkpCurve::X25519)] {
        // Ed25519 needs a real key pair (RFC 8037 A.1): import rejects
        // points with a torsion component and a `d` that does not derive
        // `x` (ADR 0043 §1, §3). Any 32 octets are an X25519 key.
        let (x, d) = if crv == "Ed25519" {
            (
                "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo".to_owned(),
                "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A".to_owned(),
            )
        } else {
            (b64(32, 9), b64(32, 8))
        };
        let key = ok(&okp(crv, &x, Some(&d)));
        let KeyMaterial::Okp(okp_key) = key.material() else {
            panic!("not OKP")
        };
        assert_eq!(okp_key.crv(), curve);
        assert!(okp_key.is_private());
        assert!(ok(&okp(crv, &x, None)).is_public());
        for bad_len in [0, 31, 33, 57, 64] {
            assert_eq!(
                err(&okp(crv, &b64(bad_len, 9), None)),
                Some(Error::InvalidKey("x has the wrong length for crv")),
                "{crv} x {bad_len}"
            );
            assert_eq!(
                err(&okp(crv, &x, Some(&b64(bad_len, 8)))),
                Some(Error::InvalidKey("d has the wrong length for crv")),
                "{crv} d {bad_len}"
            );
        }
    }
    // Ed448 and X448 are out of scope for 0.1.0 (ADR 0006), even with
    // well-formed 57/56-octet keys; other curves are unknown.
    assert_eq!(
        err(&okp("Ed448", &b64(57, 1), None)),
        Some(Error::UnsupportedAlgorithm)
    );
    assert_eq!(
        err(&okp("X448", &b64(56, 1), None)),
        Some(Error::UnsupportedAlgorithm)
    );
    for crv in ["ed25519", "P-256", "secp256k1", "Curve25519", ""] {
        assert_eq!(
            err(&okp(crv, &b64(32, 1), None)),
            Some(Error::UnsupportedAlgorithm),
            "{crv}"
        );
    }
    assert_eq!(
        err(&format!(r#"{{"kty":"OKP","x":"{}"}}"#, b64(32, 1))),
        Some(Error::InvalidKey("crv is missing"))
    );
    assert_eq!(
        err(r#"{"kty":"OKP","crv":"Ed25519"}"#),
        Some(Error::InvalidKey("x is missing"))
    );
}

#[test]
fn rsa_public_accepts_minimal_values_of_2048_bits_and_more() {
    ok(&rsa(RSA_N, "AQAB"));
    // Exactly 2048 bits: 256 octets with the top bit set.
    ok(&rsa(&modulus(256, 0x80), "Aw"));
    ok(&rsa(&modulus(257, 0x01), "AQAB"));
    ok(&rsa(&modulus(512, 0xff), "AQAB"));
    let k = ok(&rsa(&modulus(257, 0x01), "AQAB"));
    let KeyMaterial::Rsa(key) = k.material() else {
        panic!("not RSA")
    };
    assert_eq!(key.modulus_bits(), 2049);
}

#[test]
fn rsa_rejects_non_minimal_short_or_even_modulus() {
    let not_minimal = Some(Error::InvalidKey("n is not a minimal Base64urlUInt"));
    let short = Some(Error::InvalidKey("RSA modulus is shorter than 2048 bits"));
    // RFC 7518 §6.3.1.1: no extra leading zero octet (257 octets for 2048 bits).
    let mut padded = vec![0u8];
    padded.extend(polyjose::util::b64url_decode(RSA_N).unwrap());
    assert_eq!(err(&rsa(&b64url_encode(&padded), "AQAB")), not_minimal);
    assert_eq!(err(&rsa(&modulus(300, 0x00), "AQAB")), not_minimal);
    // RFC 7518 §2: an empty octet string is no Base64urlUInt.
    assert_eq!(err(&rsa("", "AQAB")), not_minimal);
    // Zero ("AA") is minimal but far too short.
    assert_eq!(err(&rsa("AA", "AQAB")), short);
    // Under 2048 bits: 255 octets, or 256 octets without the top bit.
    assert_eq!(err(&rsa(&modulus(255, 0xff), "AQAB")), short);
    assert_eq!(err(&rsa(&modulus(256, 0x7f), "AQAB")), short);
    assert_eq!(err(&rsa(&modulus(128, 0xff), "AQAB")), short);
    // RFC 8017 §3.1: n is a product of odd primes.
    let mut even = polyjose::util::b64url_decode(RSA_N).unwrap();
    *even.last_mut().unwrap() &= 0xfe;
    assert_eq!(
        err(&rsa(&b64url_encode(&even), "AQAB")),
        Some(Error::InvalidKey("RSA modulus must be odd"))
    );
}

#[test]
fn rsa_rejects_bad_exponents() {
    let bad_e = Some(Error::InvalidKey(
        "RSA exponent must be odd and greater than 1",
    ));
    // Even, one, or zero.
    for e in ["AQAA", "Ag", "BA", "AQ", "AA"] {
        assert_eq!(err(&rsa(RSA_N, e)), bad_e, "{e}");
    }
    // Leading zero octet or empty (RFC 7518 §2, §6.3.1.2).
    for e in ["AAEAAQ", "AAM", ""] {
        assert_eq!(
            err(&rsa(RSA_N, e)),
            Some(Error::InvalidKey("e is not a minimal Base64urlUInt")),
            "{e}"
        );
    }
    // RFC 8017 §3.1: e < n.
    let big = Some(Error::InvalidKey(
        "RSA exponent must be less than the modulus",
    ));
    assert_eq!(err(&rsa(RSA_N, RSA_N)), big);
    assert_eq!(err(&rsa(&modulus(256, 0x80), &modulus(257, 0x01))), big);
    let n = modulus(256, 0x80);
    assert_eq!(err(&rsa(&n, &modulus(256, 0x81))), big);
    ok(&rsa(&modulus(256, 0x81), &modulus(256, 0x80)));
}

#[test]
fn rsa_requires_string_n_and_e() {
    assert_eq!(
        err(r#"{"kty":"RSA","e":"AQAB"}"#),
        Some(Error::InvalidKey("n is missing"))
    );
    let no_e = format!(r#"{{"kty":"RSA","n":"{RSA_N}"}}"#);
    assert_eq!(err(&no_e), Some(Error::InvalidKey("e is missing")));
    let num_e = format!(r#"{{"kty":"RSA","n":"{RSA_N}","e":65537}}"#);
    assert_eq!(err(&num_e), Some(Error::InvalidKey("e must be a string")));
    assert_eq!(
        err(r#"{"kty":"RSA","n":{},"e":"AQAB"}"#),
        Some(Error::InvalidKey("n must be a string"))
    );
}

#[test]
fn rsa_with_any_private_member_is_unsupported() {
    // ADR 0021: whatever the value, and before n and e are looked at.
    for member in ["d", "p", "q", "dp", "dq", "qi", "oth"] {
        for value in [
            r#""AQAB""#,
            "null",
            "[]",
            r#"[{"r":"AQ","d":"AQ","t":"AQ"}]"#,
            "0",
        ] {
            let with_valid =
                format!(r#"{{"kty":"RSA","n":"{RSA_N}","e":"AQAB","{member}":{value}}}"#);
            assert_eq!(
                err(&with_valid),
                Some(Error::UnsupportedAlgorithm),
                "{with_valid}"
            );
            let without_n = format!(r#"{{"kty":"RSA","{member}":{value}}}"#);
            assert_eq!(
                err(&without_n),
                Some(Error::UnsupportedAlgorithm),
                "{without_n}"
            );
        }
    }
}

#[test]
fn oct_rejects_empty_missing_or_mistyped_k() {
    assert_eq!(
        err(r#"{"kty":"oct","k":""}"#),
        Some(Error::InvalidKey("k must not be empty"))
    );
    assert_eq!(
        err(r#"{"kty":"oct"}"#),
        Some(Error::InvalidKey("k is missing"))
    );
    assert_eq!(
        err(r#"{"kty":"oct","k":42}"#),
        Some(Error::InvalidKey("k must be a string"))
    );
    let one = ok(r#"{"kty":"oct","k":"AA"}"#);
    let KeyMaterial::Oct(k) = one.material() else {
        panic!("not oct")
    };
    assert_eq!(k.len(), 1);
}

#[test]
fn common_members_must_have_their_json_types() {
    let cases = [
        (r#","kid":7"#, "kid must be a string"),
        (r#","use":["sig"]"#, "use must be a string"),
        (r#","alg":null"#, "alg must be a string"),
        (r#","x5u":{}"#, "x5u must be a string"),
        (r#","x5t":1"#, "x5t must be a string"),
        (r#","x5t#S256":false"#, "x5t#S256 must be a string"),
        (r#","x5c":"MIIB""#, "x5c must be an array of strings"),
        (r#","x5c":["MIIB",1]"#, "x5c must be an array of strings"),
        (
            r#","key_ops":"sign""#,
            "key_ops must be an array of strings",
        ),
        (
            r#","key_ops":["sign",null]"#,
            "key_ops must be an array of strings",
        ),
    ];
    for (extra, detail) in cases {
        let json = oct_with(extra);
        assert_eq!(err(&json), Some(Error::InvalidKey(detail)), "{json}");
    }
    // Strings of any content are carried; certificates are not decoded.
    let jwk = ok(&oct_with(r#","x5c":[],"kid":"","alg":"x-🙂""#));
    assert_eq!(jwk.x5c(), Some(&[][..]));
    assert_eq!(jwk.kid(), Some(""));
    assert_eq!(jwk.alg().map(|a| a.as_str()), Some("x-🙂"));
}

#[test]
fn key_ops_must_not_repeat_a_value() {
    for ops in [
        r#"["sign","sign"]"#,
        r#"["verify","sign","verify"]"#,
        r#"["x-op","x-op"]"#,
    ] {
        let json = oct_with(&format!(r#","key_ops":{ops}"#));
        assert_eq!(
            err(&json),
            Some(Error::InvalidKey("key_ops must not contain duplicates")),
            "{json}"
        );
    }
    // Case-sensitive values, so these are distinct.
    let jwk = ok(&oct_with(r#","key_ops":["sign","Sign"]"#));
    assert_eq!(
        jwk.key_ops(),
        Some(&[KeyOp::Sign, KeyOp::Unknown("Sign".into())][..])
    );
    assert_eq!(ok(&oct_with(r#","key_ops":[]"#)).key_ops(), Some(&[][..]));
}

#[test]
fn use_and_key_ops_must_be_consistent() {
    let conflict = Some(Error::InvalidKey("use and key_ops are inconsistent"));
    let enc_ops = [
        "encrypt",
        "decrypt",
        "wrapKey",
        "unwrapKey",
        "deriveKey",
        "deriveBits",
    ];
    for op in enc_ops {
        let json = oct_with(&format!(r#","use":"sig","key_ops":["verify","{op}"]"#));
        assert_eq!(err(&json), conflict, "{json}");
        let json = oct_with(&format!(r#","use":"enc","key_ops":["{op}"]"#));
        ok(&json);
    }
    for op in ["sign", "verify"] {
        let json = oct_with(&format!(r#","use":"enc","key_ops":["{op}"]"#));
        assert_eq!(err(&json), conflict, "{json}");
        ok(&oct_with(&format!(r#","use":"sig","key_ops":["{op}"]"#)));
    }
    ok(&oct_with(r#","use":"sig","key_ops":["sign","verify"]"#));
    ok(&oct_with(
        r#","use":"enc","key_ops":["encrypt","decrypt","wrapKey","unwrapKey"]"#,
    ));
    // Unregistered values have no meaning to compare, so never conflict.
    ok(&oct_with(r#","use":"sig","key_ops":["x-attest"]"#));
    ok(&oct_with(r#","use":"tls","key_ops":["sign","encrypt"]"#));
    // key_ops alone may combine unrelated operations (only a SHOULD NOT,
    // RFC 7517 §4.3), as WebCrypto exports do.
    ok(&oct_with(r#","key_ops":["sign","encrypt"]"#));
    // The member is case-sensitive: "Sig" is an unregistered use.
    let jwk = ok(&oct_with(r#","use":"Sig","key_ops":["encrypt"]"#));
    assert_eq!(jwk.key_use(), Some(&KeyUse::Unknown("Sig".into())));
}

#[test]
fn permits_follows_use_and_key_ops() {
    let any = ok(&oct_with(""));
    for op in [
        KeyOp::Sign,
        KeyOp::Verify,
        KeyOp::Encrypt,
        KeyOp::DeriveBits,
    ] {
        assert!(any.permits(&op), "{op}");
    }
    let sig = ok(&oct_with(r#","use":"sig""#));
    assert!(sig.permits(&KeyOp::Sign) && sig.permits(&KeyOp::Verify));
    assert!(!sig.permits(&KeyOp::Encrypt) && !sig.permits(&KeyOp::UnwrapKey));
    let enc = ok(&oct_with(r#","use":"enc""#));
    assert!(enc.permits(&KeyOp::WrapKey) && enc.permits(&KeyOp::DeriveKey));
    assert!(!enc.permits(&KeyOp::Verify));
    let only_verify = ok(&oct_with(r#","key_ops":["verify"]"#));
    assert!(only_verify.permits(&KeyOp::Verify));
    assert!(!only_verify.permits(&KeyOp::Sign));
    let both = ok(&oct_with(r#","use":"sig","key_ops":["sign"]"#));
    assert!(both.permits(&KeyOp::Sign) && !both.permits(&KeyOp::Verify));
    // An unregistered use allows nothing polyjose does.
    let unknown_use = ok(&oct_with(r#","use":"x-attest""#));
    for op in [KeyOp::Sign, KeyOp::Verify, KeyOp::Encrypt, KeyOp::Decrypt] {
        assert!(!unknown_use.permits(&op), "{op}");
    }
    assert!(!ok(&oct_with(r#","key_ops":[]"#)).permits(&KeyOp::Verify));
}

#[test]
fn errors_never_echo_the_input() {
    let marker = "SECRETMARKER";
    let inputs = [
        format!(r#"{{"kty":"{marker}"}}"#),
        format!(r#"{{"kty":"oct","k":"{marker}!"}}"#),
        format!(r#"{{"kty":"EC","crv":"{marker}","x":"AA","y":"AA"}}"#),
        format!(r#"{{"kty":"EC","crv":"P-256","x":"{marker}","y":"AA"}}"#),
        format!(r#"{{"kty":"RSA","n":"{marker}","e":"AQAB"}}"#),
        format!(r#"{{"kty":"RSA","n":"AQAB","e":"AQAB","d":"{marker}"}}"#),
        format!(r#"{{"kty":"oct","k":"AA","kid":7,"{marker}":1}}"#),
        format!(r#"{{"kty":"oct","k":"AA","key_ops":["{marker}","{marker}"]}}"#),
        format!(r#"{{"kty":"oct","k":"AA","{marker}":1,"{marker}":2}}"#),
    ];
    for input in &inputs {
        let e = Jwk::from_json(input.as_bytes()).expect_err("rejected");
        assert!(!format!("{e}").contains(marker), "{input}");
        assert!(!format!("{e:?}").contains(marker), "{input}");
    }
}

#[test]
fn from_object_takes_header_jwk_and_epk_objects() {
    use polyjose::header::Header;
    let x = b64(32, 5);
    let header = format!(
        r#"{{"alg":"ECDH-ES","enc":"A256GCM","epk":{{"kty":"OKP","crv":"X25519","x":"{x}"}}}}"#
    );
    let h = Header::from_json(header.as_bytes()).unwrap();
    let epk = Jwk::from_object(h.epk.as_ref().unwrap()).unwrap();
    assert!(epk.is_public());
    assert_eq!(
        Value::from(epk.to_object()),
        Value::from(h.epk.clone().unwrap())
    );
    // An object that came from elsewhere is validated the same way.
    let parsed = json::parse(br#"{"kty":"OKP","crv":"X25519","x":"AA"}"#).unwrap();
    assert_eq!(
        Jwk::from_object(parsed.as_object().unwrap()).err(),
        Some(Error::InvalidKey("x has the wrong length for crv"))
    );
}
