//! Tester probes for B01: secrets in `json::Value` are wiped, parser string
//! buffers never reallocate, and the serializer sizes its output exactly.

use polyjose::json::{Number, Object, Value, parse};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

fn assert_zeroize<T: Zeroize + ZeroizeOnDrop>() {}

fn cap(input: &str) -> Option<(usize, usize)> {
    match parse(input.as_bytes()) {
        Ok(Value::String(s)) => Some((s.len(), s.capacity())),
        _ => None,
    }
}

#[test]
fn value_and_object_are_zeroize_and_zeroize_on_drop() {
    assert_zeroize::<Value>();
    assert_zeroize::<Object>();
    let _: fn(&Value) -> Option<&str> = Value::as_str;
}

#[test]
fn zeroize_wipes_nested_strings_and_leaves_null() {
    let mut v = parse(br#"{"d":"secret","k":["a",{"p":"q"}]}"#).unwrap_or(Value::Null);
    v.zeroize();
    assert!(v.is_null());
    let mut o = Object::new();
    o.insert("d", "secret");
    o.zeroize();
    assert!(o.is_empty());
}

#[test]
fn buffers_never_grow_for_escape_edge_cases() {
    // (input, expected content length)
    let cases: &[(&str, usize)] = &[
        (r#""a\"""#, 2),
        (r#""\"""#, 1),
        (r#""\\""#, 1),
        (r#""\\\\\\""#, 3),
        (r#""\\\"""#, 2),
        (r#""\u0041\u0042""#, 2),
        (r#""\u00e9""#, 2),
        (r#""\u20ac""#, 3),
        (r#""\ud83d\ude00""#, 4),
        ("\"\u{e9}\u{20ac}\u{1f600}\"", 9),
        (r#""\/\b\f\n\r\t""#, 6),
        (r#""""#, 0),
    ];
    for (input, len) in cases {
        let (l, c) = cap(input).unwrap_or((usize::MAX, 0));
        assert_eq!(l, *len, "{input}");
        assert!(c >= l, "{input}");
        // Capacity is sized from the quoted span, so it is the span length
        // and never a doubled-up grown buffer.
        assert!(c <= input.len() - 2, "{input}: cap {c}");
    }
    let long = format!("\"{}\"", "\\u0041".repeat(10_000));
    assert_eq!(cap(&long), Some((10_000, 60_000)));
}

#[test]
fn error_paths_are_unchanged_for_odd_strings() {
    for bad in [
        &b"\"abc"[..],
        b"\"abc\\",
        b"\"abc\\\"",
        b"\"\\\\\\\"",
        b"\"\\u00",
        b"\"\\ud83d\"",
        b"\"\\ud83d\\u0041\"",
        b"\"\\ude00\"",
        b"\"a\x01\"",
        b"\"\xff\"",
        b"{\"d\":\"secret\",\"d\":\"x\"}",
        b"{\"d\":\"secret\"} x",
        b"[\"secret\",",
        b"{\"d\":\"secret\",",
    ] {
        assert!(parse(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn serializer_output_is_exactly_sized() {
    let nums = [
        "-0",
        "0",
        "1e-7",
        "1e21",
        "1e-400",
        "9007199254740992",
        "-9007199254740993",
        "1.7976931348623157e308",
        "5e-324",
        "0.000001",
        "123456789012345678901",
        "1.5",
    ];
    for n in nums {
        let v = parse(n.as_bytes()).unwrap_or(Value::Null);
        let s = v.to_json();
        assert_eq!(s.capacity(), s.len(), "{n} -> {s}");
    }
    let texts = [
        "\"\\\"\\\\\\b\\f\\n\\r\\t\\u0000\\u001f/\u{7f}\u{e9}\u{20ac}\u{1f600}\"",
        r#"{"a":[1,2.5,"x\n",{"b":null,"c":true}],"é😀":[]}"#,
        "[]",
        "{}",
        "[[],{},\"\"]",
    ];
    for t in texts {
        let v = parse(t.as_bytes()).unwrap_or(Value::Null);
        let s = v.to_json();
        assert_eq!(s.capacity(), s.len(), "{t}");
        assert_eq!(parse(s.as_bytes()), Ok(v.clone()), "{t}");
        if let Value::Object(o) = &v {
            let so = o.to_json();
            assert_eq!(so.capacity(), so.len());
        }
    }
    let built = Value::from(vec![
        Number::from_i64(-1).map_or(Value::Null, Value::from),
        Value::from("\u{0}\u{1f}\""),
    ]);
    let s = built.to_json();
    assert_eq!(s.capacity(), s.len());
}

fn nested(depth: usize, secret: bool) -> String {
    let leaf = if secret { "\"secret\"" } else { "0" };
    format!("{}{leaf}{}", "[".repeat(depth), "]".repeat(depth))
}

#[test]
fn drop_and_zeroize_of_deepest_allowed_trees_do_not_overflow() {
    // Run on a small stack to show the 128 cap bounds the recursion.
    let handle = std::thread::Builder::new()
        .stack_size(512 * 1024)
        .spawn(|| {
            for depth in [1, 64, 127, 128] {
                let v = parse(nested(depth, true).as_bytes());
                if let Ok(mut v) = v {
                    v.clone().zeroize();
                    v.zeroize();
                }
            }
            let objs = format!("{}\"s\"{}", "{\"a\":".repeat(128), "}".repeat(128));
            if let Ok(v) = parse(objs.as_bytes()) {
                drop(v.clone());
                drop(v);
            }
            assert!(parse(nested(129, false).as_bytes()).is_err());
            assert!(parse("[".repeat(1_000_000).as_bytes()).is_err());
        });
    assert!(handle.map(|h| h.join().is_ok()).unwrap_or(false));
}

#[test]
fn removed_replaced_and_iterated_values_are_zeroizing_types() {
    let mut o = Object::new();
    o.insert("d", "one");
    let old = o.insert("d", "two");
    assert_eq!(old, Some(Value::from("one")));
    let gone = o.remove("d");
    assert_eq!(gone, Some(Value::from("two")));
    o.insert("k", "v");
    let names: Vec<Zeroizing<String>> = o.into_iter().map(|(n, _)| n).collect();
    assert_eq!(names.len(), 1);
}
