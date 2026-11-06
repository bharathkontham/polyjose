//! Tester probes for the header and algorithm model (T04): acceptance
//! criteria checked through the public API only, with raw JSON inputs.
#![allow(clippy::unwrap_used, clippy::panic)] // test code: a panic is a failed assertion

use polyjose::Error;
use polyjose::header::Header;
use polyjose::json::{self, Value};
use polyjose::jwa::{ContentEncAlg, KeyMgmtAlg, SigningAlg};

/// Independent copy of the IANA "JSON Web Signature and Encryption
/// Algorithms" registry names that are in scope (ADR 0006 minus RSA-OAEP and
/// RSA1_5 per ADRs 0021/0022).
const JWS: &[&str] = &[
    "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "ES256K",
    "PS256", "PS384", "PS512", "EdDSA", "Ed25519", "none",
];
const JWE_ALG: &[&str] = &[
    "RSA-OAEP-256",
    "A128KW",
    "A192KW",
    "A256KW",
    "dir",
    "ECDH-ES",
    "ECDH-ES+A128KW",
    "ECDH-ES+A192KW",
    "ECDH-ES+A256KW",
    "A128GCMKW",
    "A192GCMKW",
    "A256GCMKW",
    "PBES2-HS256+A128KW",
    "PBES2-HS384+A192KW",
    "PBES2-HS512+A256KW",
];
const JWE_ENC: &[&str] = &[
    "A128CBC-HS256",
    "A192CBC-HS384",
    "A256CBC-HS512",
    "A128GCM",
    "A192GCM",
    "A256GCM",
];
/// Registered (or plausible) names polyjose must treat as Unknown.
const UNKNOWN: &[&str] = &[
    "RSA-OAEP",
    "RSA1_5",
    "RSA-OAEP-384",
    "RSA-OAEP-512",
    "Ed448",
    "HS224",
    "ES256k",
    "hs256",
    "HS256 ",
    " HS256",
    "eddsa",
    "EDDSA",
    "NONE",
    "None",
    "DIR",
    "a128kw",
    "A128GCM ",
    "",
    "\u{0}",
    "HS256\u{0}",
    "ＨＳ２５６",
];

#[test]
fn every_in_scope_name_parses_and_serializes_exactly() {
    assert_eq!(SigningAlg::KNOWN.len(), JWS.len());
    for n in JWS {
        let a = SigningAlg::from(*n);
        assert!(
            a.is_known() && a.as_str() == *n && a.to_string() == *n,
            "{n}"
        );
        assert!(a.ensure_known().is_ok());
    }
    assert_eq!(KeyMgmtAlg::KNOWN.len(), JWE_ALG.len());
    for n in JWE_ALG {
        let a = KeyMgmtAlg::from(*n);
        assert!(a.is_known() && a.as_str() == *n, "{n}");
    }
    assert_eq!(ContentEncAlg::KNOWN.len(), JWE_ENC.len());
    for n in JWE_ENC {
        let a = ContentEncAlg::from(*n);
        assert!(a.is_known() && a.as_str() == *n, "{n}");
    }
}

#[test]
fn names_are_case_sensitive_and_cross_family_names_are_unknown() {
    for n in UNKNOWN {
        for a in [
            SigningAlg::from(*n).is_known(),
            KeyMgmtAlg::from(*n).is_known(),
            ContentEncAlg::from(*n).is_known(),
        ] {
            assert!(!a, "{n:?} must be Unknown");
        }
        let s = SigningAlg::from(*n);
        assert_eq!(s, SigningAlg::Unknown((*n).to_owned()));
        assert_eq!(s.as_str(), *n);
        assert_eq!(s.ensure_known(), Err(Error::UnsupportedAlgorithm));
        let k = KeyMgmtAlg::from((*n).to_owned());
        assert_eq!(k.as_str(), *n);
        assert_eq!(k.ensure_known(), Err(Error::UnsupportedAlgorithm));
    }
    // A JWS name is not a JWE alg and vice versa.
    assert!(!KeyMgmtAlg::from("HS256").is_known());
    assert!(!SigningAlg::from("A128KW").is_known());
    assert!(!ContentEncAlg::from("A128KW").is_known());
    assert!(!KeyMgmtAlg::from("A128GCM").is_known());
}

#[test]
fn unsupported_algorithm_error_never_echoes_the_value() {
    let secret = "SECRET-ALG-VALUE-xyz";
    let h =
        Header::from_json(format!(r#"{{"alg":"{secret}","enc":"{secret}"}}"#).as_bytes()).unwrap();
    for e in [
        h.signing_alg().unwrap_err(),
        h.key_mgmt_alg().unwrap_err(),
        h.content_enc_alg().unwrap_err(),
    ] {
        assert_eq!(e, Error::UnsupportedAlgorithm);
        for text in [format!("{e}"), format!("{e:?}")] {
            assert!(!text.contains("SECRET"), "{text}");
        }
    }
    // RSA-OAEP / RSA1_5 / Ed448 round trip exactly through a header.
    for n in ["RSA-OAEP", "RSA1_5", "Ed448"] {
        let src = format!(r#"{{"alg":"{n}","enc":"{n}"}}"#);
        let h = Header::from_json(src.as_bytes()).unwrap();
        assert_eq!(h.to_json().unwrap(), src);
        assert_eq!(h.key_mgmt_alg(), Err(Error::UnsupportedAlgorithm));
        assert_eq!(h.signing_alg(), Err(Error::UnsupportedAlgorithm));
        assert_eq!(h.content_enc_alg(), Err(Error::UnsupportedAlgorithm));
        assert_eq!(h.enc, Some(ContentEncAlg::Unknown(n.to_owned())));
    }
}

#[test]
fn none_parses_but_is_only_recognised() {
    let h = Header::from_json(br#"{"alg":"none"}"#).unwrap();
    assert_eq!(h.signing_alg(), Ok(SigningAlg::None));
    assert_eq!(h.to_json().unwrap(), r#"{"alg":"none"}"#);
}

// ---------- criterion 2: duplicate member names (raw JSON) ----------

fn assert_dup(input: &str) {
    match Header::from_json(input.as_bytes()) {
        Err(Error::InvalidJson(_)) => {}
        other => panic!("{input}: expected InvalidJson, got {other:?}"),
    }
}

#[test]
fn duplicate_header_names_are_rejected() {
    for input in [
        r#"{"alg":"HS256","alg":"none"}"#,
        r#"{"alg":"HS256","alg":"HS256"}"#,
        r#"{"alg":"HS256","\u0061lg":"none"}"#,
        r#"{"\u0061lg":"HS256","al\u0067":"none"}"#,
        r#"{"alg":"HS256","\u0061\u006c\u0067":"none"}"#,
        r#"{"alg":"HS256","typ":"JWT","typ":"x"}"#,
        r#"{"enc":"A128GCM","alg":"dir","enc":"A256GCM"}"#,
        r#"{"alg":"HS256","kid":"a","kid":"b"}"#,
        r#"{"alg":"HS256","crit":["x"],"x":1,"crit":["y"]}"#,
        r#"{"alg":"HS256","x5t#S256":"a","x5t\u0023S256":"b"}"#,
        r#"{"alg":"HS256","b64":false,"b64":true}"#,
        r#"{"alg":"HS256","p2c":1,"p2c":2}"#,
        r#"{"alg":"HS256","private":1,"private":2}"#,
        r#"{"alg":"HS256","pr\u00efv":1,"priv":2,"prï\u0076":3,"priï":4,"pr\u00efv":5}"#,
        r#"{"alg":"HS256","😀":1,"😀":2}"#,
        r#"{"alg":"HS256","":1,"":2}"#,
        r#"{"alg":"ECDH-ES","epk":{"kty":"EC","x":"a","x":"b"}}"#,
        r#"{"alg":"ES256","jwk":{"kty":"EC","kty":"EC"}}"#,
        r#"{"alg":"ES256","jwk":{"kty":"EC","k\u0074y":"EC"}}"#,
        r#"{"alg":"HS256","extra":{"a":{"b":[{"c":1,"c":2}]}}}"#,
        r#"{"alg":"HS256","jwk":{"a":1},"jwk":{"a":1}}"#,
    ] {
        assert_dup(input);
    }
    // Names that differ only in case, or after normalisation, are distinct.
    for ok in [
        r#"{"alg":"HS256","ALG":"none"}"#,
        r#"{"alg":"HS256","Alg":"none"}"#,
        r#"{"alg":"HS256","é":1,"e\u0301":2}"#,
    ] {
        assert!(Header::from_json(ok.as_bytes()).is_ok(), "{ok}");
    }
}

#[test]
fn duplicate_rejection_does_not_leak_input() {
    let e = Header::from_json(br#"{"SECRETNAME":1,"SECRETNAME":2}"#).unwrap_err();
    for t in [format!("{e}"), format!("{e:?}")] {
        assert!(!t.contains("SECRET"), "{t}");
    }
}

// ---------- criterion 3: crit ----------

fn code(input: &str, understood: &[&str]) -> Result<(), Error> {
    let h = Header::from_json(input.as_bytes())?;
    h.validate_crit_understood(understood)
}

fn invalid_header(input: &str) {
    match code(input, &["b64"]) {
        Err(Error::InvalidHeader(_)) => {}
        other => panic!("{input}: expected InvalidHeader, got {other:?}"),
    }
}

#[test]
fn crit_shape_rules() {
    invalid_header(r#"{"alg":"HS256","crit":[]}"#);
    for name in [
        "alg", "enc", "zip", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty",
        "crit", "epk", "apu", "apv", "iv", "tag", "p2s", "p2c",
    ] {
        let prefix = if name == "alg" {
            ""
        } else {
            r#""alg":"HS256","#
        };
        if name != "crit" && name != "alg" {
            invalid_header(&format!(r#"{{{prefix}"{name}":"v","crit":["{name}"]}}"#));
        }
        invalid_header(&format!(r#"{{"alg":"HS256","crit":["{name}"]}}"#));
    }
    invalid_header(r#"{"alg":"HS256","exp":1,"crit":["exp","exp"]}"#);
    invalid_header(r#"{"alg":"HS256","crit":["exp"]}"#);
    invalid_header(r#"{"alg":"HS256","exp":1,"crit":["exp","other"]}"#);
    // wrong types for crit
    for bad in [
        r#""exp""#,
        "1",
        "null",
        "{}",
        r#"[1]"#,
        r#"["a",null]"#,
        r#"[["a"]]"#,
        "true",
    ] {
        invalid_header(&format!(r#"{{"alg":"HS256","exp":1,"crit":{bad}}}"#));
    }
}

#[test]
fn crit_unknown_extension_is_unknown_critical() {
    assert_eq!(
        code(r#"{"alg":"HS256","exp":1,"crit":["exp"]}"#, &["b64"]),
        Err(Error::UnknownCritical)
    );
    // understood set respected
    assert_eq!(
        code(r#"{"alg":"HS256","exp":1,"crit":["exp"]}"#, &["exp"]),
        Ok(())
    );
    // b64 understood; b64 present and listed
    assert_eq!(
        code(r#"{"alg":"HS256","b64":false,"crit":["b64"]}"#, &["b64"]),
        Ok(())
    );
    // b64 listed, not understood (e.g. JWE layer)
    assert_eq!(
        code(r#"{"alg":"HS256","b64":false,"crit":["b64"]}"#, &[]),
        Err(Error::UnknownCritical)
    );
    // b64 listed but absent: shape error wins over understood
    invalid_header(r#"{"alg":"HS256","crit":["b64"]}"#);
    // Structural error is reported before UnknownCritical
    assert!(matches!(
        code(r#"{"alg":"HS256","exp":1,"crit":["exp","exp"]}"#, &[]),
        Err(Error::InvalidHeader(_))
    ));
    // names containing a hash or odd chars
    assert_eq!(
        code(r##"{"alg":"HS256","x#y":1,"crit":["x#y"]}"##, &[]),
        Err(Error::UnknownCritical)
    );
    let e = code(r#"{"alg":"HS256","SECRETEXT":1,"crit":["SECRETEXT"]}"#, &[]).unwrap_err();
    for t in [format!("{e}"), format!("{e:?}")] {
        assert!(!t.contains("SECRET"), "{t}");
    }
}

#[test]
fn crit_set_from_code() {
    let mut h = Header::new();
    h.alg = Some("HS256".into());
    h.crit = Some(vec![]);
    assert!(matches!(h.validate_crit(), Err(Error::InvalidHeader(_))));
    h.crit = Some(vec!["kid".into()]);
    h.kid = Some("k".into());
    assert!(matches!(h.validate_crit(), Err(Error::InvalidHeader(_))));
    h.crit = Some(vec!["ext".into(), "ext".into()]);
    h.insert_other("ext", true).unwrap();
    assert!(matches!(h.validate_crit(), Err(Error::InvalidHeader(_))));
    h.crit = Some(vec!["ghost".into()]);
    assert!(matches!(h.validate_crit(), Err(Error::InvalidHeader(_))));
    h.crit = Some(vec!["ext".into()]);
    assert_eq!(h.validate_crit(), Ok(()));
    assert_eq!(
        h.validate_crit_understood(&["b64"]),
        Err(Error::UnknownCritical)
    );
    assert_eq!(h.validate_crit_understood(&["ext"]), Ok(()));
    // b64 via the typed field
    h.crit = Some(vec!["b64".into()]);
    assert!(matches!(h.validate_crit(), Err(Error::InvalidHeader(_))));
    h.b64 = Some(false);
    assert_eq!(h.validate_crit_understood(&["b64"]), Ok(()));
    // insert_other refuses typed names (cannot create duplicate members)
    for n in ["alg", "b64", "crit", "x5t#S256", "p2c"] {
        assert!(h.insert_other(n, true).is_err(), "{n}");
    }
    // serialization of a programmatic header never repeats a name
    let text = h.to_json().unwrap();
    assert!(Header::from_json(text.as_bytes()).is_ok(), "{text}");
}

// ---------- wrong-typed registered parameters ----------

#[test]
fn wrong_typed_registered_parameters_are_invalid_header() {
    let cases: &[(&str, &[&str])] = &[
        ("alg", &["1", "null", "[]", "{}", "true"]),
        ("enc", &["1", "null", "[]", "{}", "false"]),
        ("zip", &["1", "null", "[]"]),
        ("jku", &["1", "null", "[]"]),
        ("jwk", &[r#""x""#, "1", "null", "[]", "true"]),
        ("kid", &["1", "null", "[]", "{}"]),
        ("x5u", &["1", "null", "[]"]),
        ("x5c", &[r#""x""#, "1", "null", "[1]", "{}", r#"["a",1]"#]),
        ("x5t", &["1", "null", "[]"]),
        ("x5t#S256", &["1", "null", "[]"]),
        ("typ", &["1", "null", "[]"]),
        ("cty", &["1", "null", "{}"]),
        ("crit", &[r#""x""#, "1", "null"]),
        ("epk", &[r#""x""#, "1", "null", "[]"]),
        ("apu", &["1", "null", "[]"]),
        ("apv", &["1", "null", "[]"]),
        ("iv", &["1", "null", "[]"]),
        ("tag", &["1", "null", "[]"]),
        ("p2s", &["1", "null", "[]"]),
        ("p2c", &[r#""1000""#, "null", "[]", "true", "{}"]),
        ("b64", &[r#""false""#, "0", "1", "null", "[]"]),
    ];
    for (name, values) in cases {
        for v in *values {
            let prefix = if *name == "alg" {
                ""
            } else {
                r#""alg":"HS256","#
            };
            let input = format!(r#"{{{prefix}"{name}":{v}}}"#);
            match Header::from_json(input.as_bytes()) {
                Err(Error::InvalidHeader(_)) => {}
                other => panic!("{input}: {other:?}"),
            }
        }
    }
}

#[test]
fn p2c_edges() {
    let p2c =
        |lit: &str| Header::from_json(format!(r#"{{"p2c":{lit}}}"#).as_bytes()).map(|h| h.p2c);
    assert_eq!(p2c("1"), Ok(Some(1)));
    assert_eq!(p2c("1000"), Ok(Some(1000)));
    assert_eq!(p2c("1000.0"), Ok(Some(1000)));
    assert_eq!(p2c("1e3"), Ok(Some(1000)));
    assert_eq!(p2c("1E3"), Ok(Some(1000)));
    assert_eq!(p2c("10000000000000000e-16"), Ok(Some(1)));
    assert_eq!(p2c("9007199254740991"), Ok(Some(9_007_199_254_740_991)));
    for bad in [
        "0",
        "0.0",
        "-0",
        "-0.0",
        "-1",
        "-1000",
        "1.5",
        "0.5",
        "1000.5",
        "9007199254740992",
        "9007199254740993",
        "18446744073709551615",
        "18446744073709551616",
        "1e400",
        "1e19",
        "-9007199254740991",
        "1e-1",
    ] {
        assert!(
            matches!(
                p2c(bad),
                Err(Error::InvalidHeader(_)) | Err(Error::InvalidJson(_))
            ),
            "{bad}: {:?}",
            p2c(bad)
        );
    }
    // serializer side: values JSON cannot carry exactly are refused.
    let mut h = Header::new();
    for bad in [0u64, 9_007_199_254_740_992, u64::MAX] {
        h.p2c = Some(bad);
        assert!(matches!(h.to_json(), Err(Error::InvalidHeader(_))), "{bad}");
    }
    h.p2c = Some(9_007_199_254_740_991);
    assert_eq!(h.to_json().unwrap(), r#"{"p2c":9007199254740991}"#);
}

// ---------- round trips on RFC examples ----------

fn b64d(s: &str) -> Vec<u8> {
    // Minimal base64url decoder for test fixtures.
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => panic!("bad char"),
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

fn round_trips(bytes: &[u8]) -> Header {
    let h = Header::from_json(bytes).unwrap();
    let again = h.to_json().unwrap();
    assert_eq!(
        json::parse(again.as_bytes()).unwrap(),
        json::parse(bytes).unwrap()
    );
    assert_eq!(Header::from_json(again.as_bytes()).unwrap(), h);
    h
}

#[test]
fn rfc_example_headers_round_trip() {
    // RFC 7515 A.1 protected header.
    let h = round_trips(&b64d("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"));
    assert_eq!(h.signing_alg(), Ok(SigningAlg::HS256));
    assert_eq!(h.typ.as_deref(), Some("JWT"));
    // RFC 7516 A.1 protected header.
    let h = round_trips(&b64d("eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ"));
    assert_eq!(h.key_mgmt_alg(), Err(Error::UnsupportedAlgorithm)); // RSA-OAEP: ADR 0022
    assert_eq!(h.content_enc_alg(), Ok(ContentEncAlg::A256GCM));
    // RFC 7520 5.3 (PBES2).
    let h = round_trips(
        br#"{"alg":"PBES2-HS512+A256KW","p2s":"8Q1SzinasR3xchYz6ZZcHA","p2c":8192,"cty":"jwk-set+json","enc":"A128CBC-HS256"}"#,
    );
    assert_eq!(h.key_mgmt_alg(), Ok(KeyMgmtAlg::Pbes2Hs512A256KW));
    assert_eq!(h.p2c, Some(8192));
    // RFC 7520 5.4 (ECDH-ES + A128KW), epk nested object.
    let h = round_trips(
        br#"{"alg":"ECDH-ES+A128KW","kid":"peregrin.took@tuckborough.example","epk":{"kty":"EC","crv":"P-384","x":"uBo4kHPw6kbjx5l0xowrd_oYzBmaz-GKFZu4xAFFkbYiWgutEK6iuEDsQ6wNdNg3","y":"sp3p5SGhZVC2faXumI-e9JU2Mo8KpoYrFDr5yPNVtW4PgEwZOyQTA-JdaY8tb7E0"},"enc":"A256GCM"}"#,
    );
    assert_eq!(h.key_mgmt_alg(), Ok(KeyMgmtAlg::EcdhEsA128KW));
    assert!(h.epk.is_some());
    // RFC 7797 4.2 (b64 false, crit).
    let h = round_trips(br#"{"alg":"HS256","b64":false,"crit":["b64"]}"#);
    assert_eq!(h.b64, Some(false));
    assert_eq!(h.validate_crit_understood(&["b64"]), Ok(()));
    // RFC 7515 4.1.11-style private crit extension, tolerated but not understood.
    let h = round_trips(br#"{"alg":"ES256","crit":["exp"],"exp":1363284000}"#);
    assert_eq!(
        h.validate_crit_understood(&["b64"]),
        Err(Error::UnknownCritical)
    );
    // Private params of every JSON type survive.
    round_trips(br#"{"alg":"HS256","a":null,"b":[1,2.5,{"c":[]}],"d":"\u00e9\ud83d\ude00","e":-0.0,"f":1e2}"#);
}

#[test]
fn rfc7520_5_4_header_with_every_param_round_trips() {
    let src = r#"{"alg":"A128GCMKW","enc":"A128GCM","zip":"DEF","jku":"https://e/x","jwk":{"kty":"oct"},"kid":"k","x5u":"https://e/c","x5c":["QUJD"],"x5t":"a","x5t#S256":"b","typ":"JWE","cty":"JWT","crit":["z"],"epk":{"kty":"OKP"},"apu":"a","apv":"b","iv":"c","tag":"d","p2s":"e","p2c":1000,"b64":true,"z":1}"#;
    let h = round_trips(src.as_bytes());
    assert_eq!(h.to_json().unwrap(), src);
}

// ---------- no input in errors, no panics ----------

#[test]
fn errors_from_header_parsing_contain_no_input() {
    let marker = "ZZINPUTMARKERZZ";
    let inputs = [
        format!(r#"{{"alg":"{marker}","kid":1}}"#),
        format!(r#"{{"{marker}":1,"{marker}":2}}"#),
        format!(r#"{{"crit":["{marker}","{marker}"]}}"#),
        format!(r#"{{"crit":["{marker}"]}}"#),
        format!(r#"{{"p2c":"{marker}"}}"#),
        format!(r#"{{"jwk":"{marker}"}}"#),
        format!(r#"["{marker}"]"#),
        format!(r#""{marker}""#),
        format!(r#"{{"{marker}":"#),
        format!(r#"{{"x":"{marker}" garbage"#),
    ];
    for i in inputs {
        let r = Header::from_json(i.as_bytes()).and_then(|h| h.validate_crit_understood(&[]));
        if let Err(e) = r {
            for t in [format!("{e}"), format!("{e:?}")] {
                assert!(!t.contains(marker), "{i} -> {t}");
            }
        }
    }
}

#[test]
fn hostile_inputs_do_not_panic() {
    let deep = format!("{}1{}", "[".repeat(100_000), "]".repeat(100_000));
    let deep_obj = format!(r#"{{"alg":"HS256","x":{deep}}}"#);
    assert!(Header::from_json(deep_obj.as_bytes()).is_err());
    let mut many = String::from(r#"{"alg":"HS256","crit":["#);
    for i in 0..20_000 {
        if i > 0 {
            many.push(',');
        }
        many.push_str(&format!("\"n{i}\""));
    }
    many.push_str("]}");
    let _ = Header::from_json(many.as_bytes()).map(|h| h.validate_crit());
    for bytes in [
        &b""[..],
        b"{",
        b"}",
        b"{}",
        b"null",
        b"\xff\xfe",
        b"\xef\xbb\xbf{}",
        b"{\"alg\":\"\xff\"}",
        b"{\"a\":\"\\ud800\"}",
        b"{\"p2c\":1e999999999999}",
        b"{\"p2c\":-}",
    ] {
        let _ = Header::from_json(bytes);
    }
}

mod props {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(500))]

        /// Any programmatically built header with private params round-trips
        /// and serializes each name once.
        #[test]
        fn built_headers_round_trip(
            alg in proptest::sample::select(JWS),
            kid in proptest::option::of("\\PC{0,12}"),
            p2c in proptest::option::of(1u64..=9_007_199_254_740_991),
            privs in prop::collection::vec(("[a-z]{1,4}", "\\PC{0,6}"), 0..5),
        ) {
            let mut h = Header::new();
            h.alg = Some(alg.to_owned());
            h.kid = kid;
            h.p2c = p2c;
            for (n, v) in privs {
                // names a-z only; skip those that collide with typed fields
                if h.contains(&n) { continue; }
                let _ = h.insert_other(n, Value::from(v.as_str()));
            }
            let text = h.to_json().unwrap();
            let parsed = Header::from_json(text.as_bytes()).unwrap();
            prop_assert_eq!(&parsed, &h);
            prop_assert_eq!(parsed.to_json().unwrap(), text);
        }

        /// Arbitrary bytes: never panic; failures are InvalidJson/InvalidHeader.
        #[test]
        fn arbitrary_text_never_panics(s in "\\PC{0,64}", bytes in prop::collection::vec(any::<u8>(), 0..64)) {
            for b in [s.as_bytes(), &bytes[..]] {
                if let Err(e) = Header::from_json(b) {
                    prop_assert!(matches!(e, Error::InvalidJson(_) | Error::InvalidHeader(_)));
                }
            }
        }

        /// Any string yields a total alg conversion that round-trips.
        #[test]
        fn alg_from_any_string_round_trips(s in "\\PC{0,24}") {
            for out in [
                SigningAlg::from(s.clone()).as_str().to_owned(),
                KeyMgmtAlg::from(s.as_str()).as_str().to_owned(),
                ContentEncAlg::from(s.clone()).to_string(),
            ] {
                prop_assert_eq!(&out, &s);
            }
        }
    }
}
