//! Tester probes for the `json` module (T10): acceptance criteria that the
//! worker's suites do not pin down directly. Each test names the criterion.

use polyjose::Error;
use polyjose::json::{Limits, MAX_SAFE_INTEGER, Number, Object, Value, parse, parse_with_limits};

fn invalid(input: &[u8]) -> bool {
    matches!(parse(input), Err(Error::InvalidJson(_)))
}

fn ok(input: &str) -> Value {
    parse(input.as_bytes()).unwrap_or_else(|e| unreachable!("{input:?}: {e}"))
}

#[test]
fn duplicate_names_are_rejected_after_unescaping_at_every_level() {
    for bad in [
        r#"{"a":1,"a":2}"#,
        r#"{"a":1,"a":2}"#,
        r#"{"a":1,"a":2}"#,
        r#"{"a/b":1,"a\/b":2}"#,
        r#"{"😀":1,"😀":2}"#,
        r#"{"😀":1,"😀":2}"#,
        r#"{"x":{"a":1,"a":1}}"#,
        r#"[{"a":1,"a":1}]"#,
        r#"{"o":[{"p":{"k":0,"k":0}}]}"#,
        r#"{"":1,"":2}"#,
        r#"{"\u0000":1,"\u0000":2}"#,
    ] {
        assert!(invalid(bad.as_bytes()), "{bad}");
    }
    // Different names stay distinct: case and normalization form matter.
    ok(r#"{"a":1,"A":2}"#);
    ok("{\"\u{e9}\":1,\"e\u{301}\":2}");
    ok(r#"{"a":1}"#);
    // The same name in sibling objects is fine.
    ok(r#"[{"a":1},{"a":2}]"#);
}

#[test]
fn surrogates_escapes_utf8_numbers_and_trailing_content() {
    for bad in [
        r#""\ud800""#,
        r#""\udc00""#,
        r#""\udc00\ud800""#,
        r#""\ud800A""#,
        r#""\ud800x""#,
        r#""\ud800\ud800""#,
        r#""\x41""#,
        r#""\u12""#,
        r#""\u12G4""#,
        r#""\U0041""#,
        r#""\'""#,
        "\"\\\"",
        "\"a\nb\"",
        "\"a\u{1f}b\"",
        "01",
        "-01",
        "00",
        "+1",
        ".5",
        "1.",
        "1e",
        "1e+",
        "-",
        "--1",
        "0x10",
        "NaN",
        "Infinity",
        "-Infinity",
        "1 2",
        "{}x",
        "[]]",
        "null,",
        "nul",
        "tru",
        "True",
        "[1,]",
        "{\"a\":1,}",
        "{'a':1}",
        "[",
        "{",
        "",
    ] {
        assert!(invalid(bad.as_bytes()), "{bad:?}");
    }
    for bad in [
        &b"\"\xff\""[..],
        b"\"\xc0\xaf\"",
        b"\"\xed\xa0\x80\"",
        b"\"\xf4\x90\x80\x80\"",
        b"\"\xe2\x82\"",
        b"\xef\xbb\xbf{}",
        b"\xef\xbb\xbf",
        b"\xfe\xff\x00{",
        b"\"a\"\x00",
        b"\x00",
    ] {
        assert!(invalid(bad), "{bad:?}");
    }
    assert_eq!(ok(r#""😀""#).as_str(), Some("\u{1f600}"));
    assert_eq!(ok(r#""😀""#).as_str(), Some("\u{1f600}"));
}

#[test]
fn depth_boundaries() {
    let nest = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
    assert!(parse(nest(32).as_bytes()).is_ok());
    assert!(invalid(nest(33).as_bytes()));
    let objs = |n: usize| format!("{}1{}", "{\"a\":".repeat(n), "}".repeat(n));
    assert!(parse(objs(32).as_bytes()).is_ok());
    assert!(invalid(objs(33).as_bytes()));

    // max_depth above the hard ceiling of 128 is capped.
    let mut limits = Limits::default();
    limits.max_depth = usize::MAX;
    limits.max_input_len = usize::MAX;
    assert!(parse_with_limits(nest(128).as_bytes(), &limits).is_ok());
    assert!(matches!(
        parse_with_limits(nest(129).as_bytes(), &limits),
        Err(Error::InvalidJson(_))
    ));
    // A parsed value at the ceiling serializes, clones, compares and drops.
    let v = parse_with_limits(nest(128).as_bytes(), &limits).unwrap_or(Value::Null);
    assert_eq!(v.to_json(), nest(128));
    assert_eq!(v.clone(), v);
    drop(v);

    let mut zero = Limits::default();
    zero.max_depth = 0;
    assert!(parse_with_limits(b"1", &zero).is_ok());
    assert!(parse_with_limits(b"[]", &zero).is_err());
}

#[test]
fn hostile_nesting_does_not_overflow_the_stack() {
    let mut limits = Limits::default();
    limits.max_input_len = usize::MAX;
    limits.max_depth = usize::MAX;
    for open in ["[", "{\"a\":", "[{\"a\":"] {
        let input = open.repeat(1_000_000);
        for l in [Limits::default(), limits] {
            assert!(matches!(
                parse_with_limits(input.as_bytes(), &l),
                Err(Error::InvalidJson(_))
            ));
        }
    }
    // Closed, balanced and huge.
    let balanced = format!("{}{}", "[".repeat(500_000), "]".repeat(500_000));
    assert!(matches!(
        parse_with_limits(balanced.as_bytes(), &limits),
        Err(Error::InvalidJson(_))
    ));
}

#[test]
fn input_size_and_entry_limits() {
    let mut l = Limits::default();
    l.max_input_len = 5;
    assert!(parse_with_limits(b"[1,2]", &l).is_ok());
    assert!(parse_with_limits(b"[1,2] ", &l).is_err());
    // Size is checked before UTF-8 validity: still InvalidJson.
    assert!(parse_with_limits(&[0xff; 6], &l).is_err());

    let default_over = vec![b' '; 1024 * 1024 + 1];
    assert!(invalid(&default_over));
    let mut at = vec![b' '; 1024 * 1024 - 1];
    at.push(b'1');
    assert!(parse(&at).is_ok());

    let arr = |n: usize| format!("[{}]", vec!["0"; n].join(","));
    assert!(parse(arr(10_000).as_bytes()).is_ok());
    assert!(invalid(arr(10_001).as_bytes()));
    let obj = |n: usize| {
        let m: Vec<String> = (0..n).map(|i| format!("\"k{i}\":0")).collect();
        format!("{{{}}}", m.join(","))
    };
    assert!(parse(obj(10_000).as_bytes()).is_ok());
    assert!(invalid(obj(10_001).as_bytes()));
}

#[test]
fn errors_never_contain_the_input() {
    let secret = "SECRETKEYMATERIAL-d-AbCdEf";
    let inputs = [
        format!("{{\"d\":\"{secret}\",\"d\":1}}"),
        format!("{{\"d\":\"{secret}\" x}}"),
        format!("[\"{secret}\\ud800\"]"),
        format!("\"{secret}\"\"{secret}\""),
        secret.to_string(),
        format!("[\"{secret}\", 01]"),
    ];
    for i in &inputs {
        let e = parse(i.as_bytes()).err();
        let e = e.unwrap_or_else(|| unreachable!("accepted {i}"));
        for s in [format!("{e}"), format!("{e:?}")] {
            assert!(!s.contains("SECRET") && !s.contains("AbCdEf"), "{s}");
        }
        assert_eq!(e.code(), "InvalidJson");
    }
    let mut tiny = Limits::default();
    tiny.max_input_len = 3;
    let e = parse_with_limits(secret.as_bytes(), &tiny).err();
    assert!(!format!("{e:?}").contains("SECRET"));
}

#[test]
fn numbers() {
    let int = |s: &str| ok(s).as_i64();
    assert_eq!(int("9007199254740991"), Some(MAX_SAFE_INTEGER));
    assert_eq!(int("-9007199254740991"), Some(-MAX_SAFE_INTEGER));
    assert_eq!(int("9007199254740992"), None);
    assert_eq!(int("-9007199254740992"), None);
    assert_eq!(int("9007199254740993"), None);
    assert_eq!(int("90071992547409910000000000"), None);
    assert_eq!(int("-0"), Some(0));
    assert_eq!(int("0"), Some(0));
    assert_eq!(int("1e2"), Some(100));
    assert_eq!(int("1.0"), Some(1));
    assert_eq!(int("1.5"), None);
    assert_eq!(int("1.00000000000000001"), None);
    assert_eq!(int("9007199254740991.0"), Some(MAX_SAFE_INTEGER));
    assert_eq!(int("9007199254740991.5"), None);
    assert_eq!(int("1e-400"), None);
    assert_eq!(ok("1e-400").as_f64(), Some(0.0));
    assert_eq!(ok("-0").to_json(), "0");
    assert_eq!(ok("-0.0").to_json(), "0");
    assert!(invalid(b"1e400"));
    assert!(invalid(b"-1e400"));
    assert!(invalid(b"[1e999]"));
    assert_eq!(ok("0.1").to_json(), "0.1");
    assert_eq!(ok("1e21").to_json(), "1e+21");
    assert_eq!(ok("1e-7").to_json(), "1e-7");
    assert_eq!(
        ok("123456789012345680000").to_json(),
        "123456789012345680000"
    );
    assert_eq!(ok("5e-324").to_json(), "5e-324");
    assert_eq!(
        ok("1.7976931348623157e308").to_json(),
        "1.7976931348623157e+308"
    );
    // Equality compares doubles; the integer accessor is stricter.
    assert_eq!(ok("1"), ok("1.0"));
    assert_eq!(ok("1"), ok("1.00000000000000001"));
    assert_eq!(Number::from_i64(MAX_SAFE_INTEGER + 1), None);
    assert_eq!(Number::from_u64(u64::MAX), None);
    assert_eq!(Number::from_f64(f64::NAN), None);
    assert_eq!(Number::from_f64(f64::INFINITY), None);
    assert_eq!(
        Number::from_f64(-0.0).map(|n| n.as_f64().is_sign_negative()),
        Some(false)
    );
}

#[test]
fn serializer_is_deterministic_and_round_trips() {
    let src = r#" { "z" : [ 1 , 2.50 , "é\/\u001f\u007f" , null ] , "a" : { "k" : true } } "#;
    let v = ok(src);
    let out = v.to_json();
    assert_eq!(
        out,
        "{\"z\":[1,2.5,\"\u{e9}/\\u001f\u{7f}\",null],\"a\":{\"k\":true}}"
    );
    assert_eq!(v.to_json(), out);
    assert_eq!(ok(&out), v);
    assert_eq!(ok(&out).to_json(), out);
    // Escapes.
    let s = Value::from("\"\\\u{8}\u{c}\n\r\t\u{0}\u{1f}/\u{2028}");
    assert_eq!(
        s.to_json(),
        "\"\\\"\\\\\\b\\f\\n\\r\\t\\u0000\\u001f/\u{2028}\""
    );
    assert_eq!(ok(&s.to_json()), s);
    // RFC 7638 §3.1 thumbprint input.
    let mut o = Object::new();
    o.insert("e", "AQAB");
    o.insert("kty", "RSA");
    o.insert(
        "n",
        "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
    );
    let expected = "{\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\"}";
    assert_eq!(o.to_json(), expected);
    assert_eq!(Value::from(o.clone()).to_json(), expected);
    // Member order is preserved, and sort_members gives the lexicographic order.
    let mut u = Object::new();
    u.insert("n", "1");
    u.insert("e", "2");
    u.insert("kty", "RSA");
    assert_eq!(u.to_json(), r#"{"n":"1","e":"2","kty":"RSA"}"#);
    u.sort_members();
    assert_eq!(u.to_json(), r#"{"e":"2","kty":"RSA","n":"1"}"#);
    // insert replaces rather than duplicating.
    u.insert("e", "3");
    assert_eq!(u.len(), 3);
}

#[test]
fn no_panic_on_arbitrary_and_truncated_bytes() {
    // Every prefix and every single-byte mutation of a rich document.
    let doc = "{\"a\":[1,-2.5e+3,\"\\u00e9\\ud83d\\ude00\",null,true,false],\"b\":{\"c\":\"\u{20ac}\u{1f600}\"}}"
        .as_bytes()
        .to_vec();
    for end in 0..=doc.len() {
        let _ = parse(&doc[..end]);
    }
    for i in 0..doc.len() {
        for b in [0u8, 0x22, 0x5c, 0x7b, 0x7d, 0x80, 0xc0, 0xed, 0xf4, 0xff] {
            let mut m = doc.clone();
            m[i] = b;
            let _ = parse(&m);
        }
    }
    // Deterministic pseudo-random bytes.
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    for len in 0..300 {
        let bytes: Vec<u8> = (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect();
        let _ = parse(&bytes);
    }
}
