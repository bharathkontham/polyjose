//! JWK Set import and verification-key selection, black-box (ADR 0008
//! layer 2): RFC 7517 §5 skipping, the RSA-private fail-closed rule
//! (ADR 0021, ADR 0029 §3), the ADR 0029 §2 candidate filter over every
//! `SigningAlg`, secret hygiene and robustness.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

mod common;

use polyjose::Error;
use polyjose::jwa::SigningAlg;
use polyjose::jwk::JwkSet;
use proptest::prelude::*;

const EC_P256: &str = r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM""#;
const ED: &str =
    r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo""#;
const X25519: &str =
    r#"{"kty":"OKP","crv":"X25519","x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08""#;
const OCT: &str = r#"{"kty":"oct","k":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8""#;
const RSA_N: &str = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";

/// A key prefix (open object) plus extra members and the closing brace.
fn m(prefix: &str, extra: &str) -> String {
    if extra.is_empty() {
        format!("{prefix}}}")
    } else {
        format!("{prefix},{extra}}}")
    }
}

fn rsa(extra: &str) -> String {
    m(&format!(r#"{{"kty":"RSA","n":"{RSA_N}","e":"AQAB""#), extra)
}

fn set(members: &[String]) -> String {
    format!(r#"{{"keys":[{}]}}"#, members.join(","))
}

fn parse(members: &[String]) -> Result<JwkSet, Error> {
    JwkSet::from_json(set(members).as_bytes())
}

fn idx(s: &JwkSet, alg: &SigningAlg, kid: Option<&str>) -> Vec<usize> {
    s.verification_candidates(alg, kid)
        .map(|(i, _)| i)
        .collect()
}

/// The full family table through the public selection API: for every known
/// algorithm (including `none`) and every key kind, a kid-less selection
/// picks exactly the keys ADR 0026 step 8 allows; X25519 is never chosen.
#[test]
fn every_alg_selects_exactly_its_family() {
    let k = |p: &str| m(p, "");
    // Real points (the generators): import checks that a point is on its
    // curve (ADR 0041 §4).
    let ec = |crv: &str| {
        let g = common::generator(crv);
        format!(
            r#"{{"kty":"EC","crv":"{crv}","x":"{}","y":"{}"}}"#,
            g.x, g.y
        )
    };
    let p384 = ec("P-384");
    let p521 = ec("P-521");
    let k256 = ec("secp256k1");
    let members = [
        k(OCT),     // 0
        rsa(""),    // 1
        k(EC_P256), // 2
        p384,       // 3
        p521,       // 4
        k256,       // 5
        k(ED),      // 6
        k(X25519),  // 7
    ];
    let s = parse(&members).unwrap();
    assert_eq!(s.len(), 8, "all eight keys import");
    let expect: &[(&str, &[usize])] = &[
        ("HS256", &[0]),
        ("HS384", &[0]),
        ("HS512", &[0]),
        ("RS256", &[1]),
        ("RS384", &[1]),
        ("RS512", &[1]),
        ("PS256", &[1]),
        ("PS384", &[1]),
        ("PS512", &[1]),
        ("ES256", &[2]),
        ("ES384", &[3]),
        ("ES512", &[4]),
        ("ES256K", &[5]),
        ("EdDSA", &[6]),
        ("Ed25519", &[6]),
        ("none", &[]),
        ("HS257", &[]),
        ("hs256", &[]),
        ("", &[]),
    ];
    for (name, want) in expect {
        let alg = SigningAlg::from(*name);
        assert_eq!(idx(&s, &alg, None), *want, "alg {name:?}");
    }
    // Every known algorithm is covered by the table above.
    for alg in SigningAlg::KNOWN {
        assert!(
            expect.iter().any(|(n, _)| SigningAlg::from(*n) == *alg),
            "{alg} missing from the test table"
        );
        assert!(!idx(&s, alg, None).contains(&7), "X25519 chosen for {alg}");
        // A kid never widens the selection.
        assert!(idx(&s, alg, Some("absent")).is_empty());
    }
}

/// ADR 0029 §2 item 5: exact, case-sensitive, byte-for-byte kid equality.
#[test]
fn kid_comparison_is_exact() {
    let kids = [
        "key",
        "Key",
        "key ",
        " key",
        "k\u{0435}y",         // Cyrillic ie
        "ke\u{0079}\u{200b}", // zero width space
        "e\u{0301}",          // e + combining acute
        "\u{00e9}",           // precomposed e acute
        "key\u{0000}",
    ];
    let members: Vec<String> = kids
        .iter()
        .map(|kid| m(OCT, &format!(r#""kid":{}"#, serde_json_string(kid))))
        .collect();
    let s = parse(&members).unwrap();
    assert_eq!(s.len(), kids.len());
    for (i, kid) in kids.iter().enumerate() {
        assert_eq!(idx(&s, &SigningAlg::HS256, Some(kid)), [i], "{kid:?}");
    }
    for probe in ["KEY", "key\t", "ke", "", "e\u{0301}\u{0301}"] {
        assert!(
            idx(&s, &SigningAlg::HS256, Some(probe)).is_empty(),
            "{probe:?}"
        );
    }
    // An empty header kid matches only an empty key kid, never "no kid".
    let s = parse(&[m(OCT, ""), m(OCT, r#""kid":"""#)]).unwrap();
    assert_eq!(idx(&s, &SigningAlg::HS256, Some("")), [1]);
    assert_eq!(idx(&s, &SigningAlg::HS256, None), [0, 1]);
}

fn serde_json_string(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A header kid matches nothing when the key has no kid, and kid-less
/// keys are not matched by a kid.
#[test]
fn header_kid_excludes_kidless_keys() {
    let s = parse(&[m(OCT, ""), m(OCT, r#""kid":"a""#), m(OCT, "")]).unwrap();
    assert_eq!(idx(&s, &SigningAlg::HS256, Some("a")), [1]);
    assert_eq!(idx(&s, &SigningAlg::HS256, None), [0, 1, 2]);
}

/// ADR 0029 §2 items 2-4: JWK alg exact (case-sensitive, EdDSA != Ed25519),
/// use absent or sig (case-sensitive), key_ops absent or containing verify.
#[test]
fn alg_use_key_ops_filters() {
    let h = |extra: &str| m(OCT, extra);
    let members = [
        h(r#""alg":"HS256""#),                                         // 0 ok
        h(r#""alg":"HS384""#),                                         // 1
        h(r#""alg":"hs256""#),                                         // 2
        h(r#""alg":"HS256 ""#),                                        // 3
        h(r#""use":"sig""#),                                           // 4 ok
        h(r#""use":"SIG""#),                                           // 5
        h(r#""use":"enc""#),                                           // 6
        h(r#""use":"""#),                                              // 7
        h(r#""key_ops":["verify"]"#),                                  // 8 ok
        h(r#""key_ops":["sign"]"#),                                    // 9
        h(r#""key_ops":["sign","verify"]"#),                           // 10 ok
        h(r#""key_ops":["Verify"]"#),                                  // 11
        h(r#""key_ops":[]"#),                                          // 12
        h(r#""use":"sig","key_ops":["verify"]"#),                      // 13 ok
        h(r#""alg":"HS256","use":"sig","key_ops":["verify","sign"]"#), // 14 ok
        h(r#""x-extra":1"#),                                           // 15 ok
    ];
    let s = parse(&members).unwrap_or_else(|e| panic!("{e:?}"));
    // Some of the above may legitimately be skipped by Jwk::from_object
    // (use/key_ops inconsistency); selection must still never return a
    // key that violates a rule. Compare against the kept keys.
    let got: Vec<String> = s
        .verification_candidates(&SigningAlg::HS256, None)
        .map(|(_, k)| {
            format!(
                "{:?}|{:?}|{}",
                k.alg().map(|a| a.to_string()),
                k.permits(&polyjose::jwk::KeyOp::Verify),
                k.kid().is_none()
            )
        })
        .collect();
    for (i, key) in s.keys().iter().enumerate() {
        let alg_ok = key.alg().is_none_or(|a| a.to_string() == "HS256");
        let want = alg_ok && key.permits(&polyjose::jwk::KeyOp::Verify);
        assert_eq!(
            idx(&s, &SigningAlg::HS256, None).contains(&i),
            want,
            "key {i}"
        );
    }
    assert!(!got.is_empty());
    // HS384 sees only HS384-or-no-alg keys.
    for (_, key) in s.verification_candidates(&SigningAlg::HS384, None) {
        assert!(key.alg().is_none_or(|a| a.to_string() == "HS384"));
    }
    // `use`:"SIG"/"enc"/"" are never candidates.
    let s = parse(&[
        h(r#""use":"SIG""#),
        h(r#""use":"enc""#),
        h(r#""use":"""#),
        h(r#""use":"sig""#),
    ])
    .unwrap();
    assert_eq!(idx(&s, &SigningAlg::HS256, None), [s.len() - 1]);
    // key_ops without verify, or empty, is never a candidate.
    let s = parse(&[
        h(r#""key_ops":["sign"]"#),
        h(r#""key_ops":["Verify"]"#),
        h(r#""key_ops":[]"#),
        h(r#""key_ops":["sign","verify"]"#),
    ])
    .unwrap();
    assert_eq!(s.keys().len(), 4);
    assert_eq!(idx(&s, &SigningAlg::HS256, None), [3]);
}

/// `EdDSA` and `Ed25519` JWK algs are distinct (ADR 0029 §2 item 2).
#[test]
fn eddsa_is_not_ed25519() {
    let s = parse(&[
        m(ED, r#""alg":"EdDSA""#),
        m(ED, r#""alg":"Ed25519""#),
        m(ED, ""),
    ])
    .unwrap();
    assert_eq!(idx(&s, &SigningAlg::EdDSA, None), [0, 2]);
    assert_eq!(idx(&s, &SigningAlg::Ed25519, None), [1, 2]);
}

/// An X25519 key with a signing `alg` or `use`:"sig" is still never chosen.
#[test]
fn x25519_never_selected_even_when_it_claims_sig() {
    let s = parse(&[
        m(X25519, r#""use":"sig","alg":"EdDSA""#),
        m(X25519, r#""key_ops":["verify"]"#),
        m(X25519, ""),
    ]);
    // Whether such members import or are skipped, none is a candidate.
    let s = s.unwrap();
    for alg in SigningAlg::KNOWN {
        assert!(idx(&s, alg, None).is_empty(), "{alg}");
    }
}

/// Order is preserved; key_index counts kept keys only.
#[test]
fn order_and_key_index_semantics() {
    let s = parse(&[
        r#"{"kty":"XYZ"}"#.to_owned(),
        m(OCT, r#""kid":"a""#),
        "7".to_owned(),
        m(OCT, r#""kid":"b""#),
        r#"{"kty":"oct"}"#.to_owned(),
        m(OCT, r#""kid":"a""#),
    ])
    .unwrap();
    assert_eq!((s.len(), s.skipped()), (3, 3));
    let all: Vec<(usize, Option<&str>)> = s
        .verification_candidates(&SigningAlg::HS512, None)
        .map(|(i, k)| (i, k.kid()))
        .collect();
    assert_eq!(all, [(0, Some("a")), (1, Some("b")), (2, Some("a"))]);
    assert_eq!(idx(&s, &SigningAlg::HS512, Some("a")), [0, 2]);
    for (i, k) in s.verification_candidates(&SigningAlg::HS512, None) {
        assert!(std::ptr::eq(k, &s.keys()[i]));
    }
}

/// ADR 0021: an RSA private member fails the set wherever it sits, with
/// escaped member names, and is never masked by a defect in the same
/// member or in other members.
#[test]
fn rsa_private_fails_closed_everywhere() {
    let privates: Vec<String> = vec![
        rsa(r#""d":"AQAB""#),
        // escaped member names decode to d / p / oth
        rsa(r#""d":"AQAB""#),
        rsa(r#""p":"AQAB""#),
        rsa(r#""oth":[]"#),
        // defects in the same member must not hide the private part
        r#"{"kty":"RSA","n":"AQAB","e":"AQAB","d":"AQAB"}"#.to_owned(), // small modulus
        r#"{"kty":"RSA","d":"AQAB"}"#.to_owned(),                       // n, e missing
        r#"{"kty":"RSA","n":7,"e":null,"d":"!!"}"#.to_owned(),
        r#"{"kty":"RSA","d":null}"#.to_owned(),
        r#"{"kty":"RSA","d":{"nested":[1]}}"#.to_owned(),
        rsa(r#""d":"AQAB","use":["sig"],"kid":5,"key_ops":"x","alg":1"#),
        rsa(r#""dq":"AQAB""#),
        rsa(r#""dp":"AQAB""#),
        rsa(r#""q":"AQAB""#),
        rsa(r#""qi":"AQAB""#),
        // escaped kty
        r#"{"kty":"RSA","d":"AQAB"}"#.to_owned(),
    ];
    let decoys: Vec<String> = vec![
        r#"{"kty":"XYZ"}"#.to_owned(),
        r#"{"kty":"oct"}"#.to_owned(),
        "null".to_owned(),
        r#"{"kty":"EC","crv":"Ed448"}"#.to_owned(),
        m(OCT, ""),
    ];
    for p in &privates {
        for pos in 0..=decoys.len() {
            let mut members = decoys.clone();
            members.insert(pos, p.clone());
            let r = parse(&members);
            assert_eq!(r.unwrap_err(), Error::UnsupportedAlgorithm, "{p} at {pos}");
        }
        assert_eq!(
            parse(std::slice::from_ref(p)).unwrap_err(),
            Error::UnsupportedAlgorithm,
            "{p}"
        );
        // Two private members, and a private member after another RSA key.
        assert_eq!(
            parse(&[rsa(""), p.clone(), p.clone()]).unwrap_err(),
            Error::UnsupportedAlgorithm
        );
    }
    // Boundary: RSA *public* defects are skipped; private members are fatal.
    let s = parse(&[r#"{"kty":"RSA","n":"AQAB","e":"AQAB"}"#.to_owned(), rsa("")]).unwrap();
    assert_eq!((s.len(), s.skipped()), (1, 1));
    // A private-looking member on a non-RSA key is not an RSA private key.
    let s = parse(&[m(OCT, r#""d":"AQAB","p":1"#)]).unwrap();
    assert_eq!(s.len(), 1);
    // `d` in a skipped unsupported key is just skipped.
    let s = parse(&[r#"{"kty":"XYZ","d":"AQAB"}"#.to_owned()]).unwrap();
    assert_eq!((s.len(), s.skipped()), (0, 1));
}

/// JSON-level errors and a bad `keys` member classify as documented, even
/// when the document also holds an RSA private member.
#[test]
fn document_level_error_classes() {
    let bad = |doc: &str| JwkSet::from_json(doc.as_bytes()).unwrap_err();
    assert!(matches!(bad(""), Error::InvalidJson(_)));
    assert!(matches!(bad("[]"), Error::InvalidJson(_)));
    assert!(matches!(
        bad(r#"{"keys":[],"keys":[]}"#),
        Error::InvalidJson(_)
    ));
    assert!(matches!(
        bad(r#"{"keys":[{"kty":"RSA","d":"A"},"#),
        Error::InvalidJson(_)
    ));
    assert!(matches!(bad("{}"), Error::InvalidKey(_)));
    for v in ["null", "{}", "\"keys\"", "1", "true"] {
        assert!(
            matches!(bad(&format!(r#"{{"keys":{v}}}"#)), Error::InvalidKey(_)),
            "{v}"
        );
    }
    // A name escaped to "keys" is the keys member.
    assert!(JwkSet::from_json(br#"{"keys":[]}"#).unwrap().is_empty());
    // Case matters: "Keys" is not "keys".
    assert!(matches!(bad(r#"{"Keys":[]}"#), Error::InvalidKey(_)));
    // Empty set parses.
    let s = JwkSet::from_json(br#"{"keys":[]}"#).unwrap();
    assert!(s.is_empty() && s.skipped() == 0);
    assert!(idx(&s, &SigningAlg::HS256, None).is_empty());
}

/// Errors never echo the input, and Debug of a set hides secrets, unknown
/// member values and top-level member values.
#[test]
fn no_secret_in_debug_or_errors() {
    const SECRET: &str = "SeCrEtMaRkEr";
    let k = "c2VjcmV0LWtleS1ieXRlcy1zZWNyZXQta2V5LWJ5dGVz"; // base64url
    let doc = format!(
        r#"{{"keys":[{{"kty":"oct","k":"{k}","kid":"visible","x-unknown":"{SECRET}"}},
        {}, {{"kty":"XYZ","z":"{SECRET}"}}],"x-top":"{SECRET}","iss":"{SECRET}"}}"#,
        m(
            r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM""#,
            r#""d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE""#
        )
    );
    let s = JwkSet::from_json(doc.as_bytes()).unwrap();
    let dbg = format!("{s:?} {s:#?}");
    for forbidden in [SECRET, k, "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"] {
        assert!(!dbg.contains(forbidden), "Debug leaks {forbidden}: {dbg}");
    }
    for name in ["x-top", "iss"] {
        let _ = name; // names may appear; values may not
    }
    // Errors.
    let errs = [
        JwkSet::from_json(format!(r#"{{"keys":[{{"kty":"RSA","d":"{SECRET}"}}]}}"#).as_bytes())
            .unwrap_err(),
        JwkSet::from_json(format!(r#"{{"keys":"{SECRET}"}}"#).as_bytes()).unwrap_err(),
        JwkSet::from_json(format!(r#"{{"keys":[],"{SECRET}":1,"{SECRET}":2}}"#).as_bytes())
            .unwrap_err(),
        JwkSet::from_json(SECRET.as_bytes()).unwrap_err(),
        JwkSet::from_json(format!(r#""{SECRET}""#).as_bytes()).unwrap_err(),
    ];
    for e in errs {
        let text = format!("{e:?} {e} {}", e.code());
        assert!(!text.contains(SECRET), "{text}");
    }
}

fn pool() -> Vec<String> {
    vec![
        m(OCT, ""),
        m(OCT, r#""kid":"a""#),
        m(OCT, r#""kid":"b","alg":"HS256""#),
        m(OCT, r#""use":"enc""#),
        m(OCT, r#""key_ops":["sign"]"#),
        m(ED, r#""kid":"a""#),
        m(ED, r#""alg":"EdDSA""#),
        m(EC_P256, r#""alg":"ES256","kid":"b""#),
        m(X25519, ""),
        rsa(r#""kid":"a""#),
        r#"{"kty":"XYZ"}"#.to_owned(),
        r#"{"kty":"OKP","crv":"Ed448","x":"AA"}"#.to_owned(),
        "null".to_owned(),
        r#"{"kty":"oct"}"#.to_owned(),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Arbitrary bytes never panic; selection over whatever parses never
    /// panics either.
    #[test]
    fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..300)) {
        if let Ok(s) = JwkSet::from_json(&bytes) {
            for alg in SigningAlg::KNOWN {
                let _ = s.verification_candidates(alg, Some("a")).count();
            }
        }
    }

    /// Structured fuzz: random subsets of the pool, in random order, plus
    /// random byte flips. Selection returns ascending, in-range, unique
    /// indices that satisfy the documented filter, and never an X25519 key.
    #[test]
    fn pool_sets_select_consistently(
        picks in prop::collection::vec(0usize..14, 0..10),
        alg_i in 0usize..15,
        kid in prop::option::of(prop::sample::select(vec!["a", "b", "A", "a ", ""])),
        flip in prop::option::of((0usize..400, any::<u8>())),
    ) {
        let pool = pool();
        let members: Vec<String> = picks.iter().map(|&i| pool[i].clone()).collect();
        let mut doc = set(&members).into_bytes();
        if let Some((pos, byte)) = flip {
            if !doc.is_empty() { let p = pos % doc.len(); doc[p] = byte; }
        }
        if let Ok(s) = JwkSet::from_json(&doc) {
            let alg = &SigningAlg::KNOWN[alg_i % SigningAlg::KNOWN.len()];
            let got = idx(&s, alg, kid);
            prop_assert!(got.windows(2).all(|w| w[0] < w[1]));
            for &i in &got {
                let key = &s.keys()[i];
                prop_assert!(i < s.len());
                let name = alg.to_string();
                let rsa_alg = name.starts_with("RS") || name.starts_with("PS");
                prop_assert_eq!(key.material().key_type() == polyjose::jwk::KeyType::Rsa, rsa_alg);
                if let Some(kid) = kid { prop_assert_eq!(key.kid(), Some(kid)); }
                prop_assert!(key.permits(&polyjose::jwk::KeyOp::Verify));
                if let Some(a) = key.alg() { prop_assert_eq!(a.to_string(), alg.to_string()); }
            }
        }
    }

    /// An RSA private member anywhere in an otherwise well-formed pool set
    /// always fails the set with UnsupportedAlgorithm.
    #[test]
    fn rsa_private_always_fatal(
        picks in prop::collection::vec(0usize..13, 0..8),
        pos in 0usize..9,
        which in 0usize..4,
    ) {
        let pool = pool();
        let mut members: Vec<String> = picks.iter().map(|&i| pool[i].clone()).collect();
        let private = [
            rsa(r#""d":"AQAB""#),
            r#"{"kty":"RSA","d":null}"#.to_owned(),
            r#"{"kty":"RSA","oth":[{"r":1}]}"#.to_owned(),
            rsa(r#""p":"!","kid":7"#),
        ][which].clone();
        let pos = pos.min(members.len());
        members.insert(pos, private);
        prop_assert_eq!(parse(&members).unwrap_err(), Error::UnsupportedAlgorithm);
    }
}
