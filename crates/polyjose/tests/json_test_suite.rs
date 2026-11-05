//! Runs every JSONTestSuite `test_parsing` case through `polyjose::json::parse`.
//!
//! The suite is vendored under `tests/third_party/JSONTestSuite` (see the
//! README there for the pinned commit and its MIT license). Every `y_` file
//! must be accepted and every `n_` file rejected, except for the exact list
//! in [`Y_REJECTED`]. Every `i_` file (behaviour left to the implementation
//! by RFC 8259) has its expected result and the reason in [`I_CASES`].

use polyjose::Error;
use polyjose::json::parse;
use std::fs;
use std::path::PathBuf;

/// `y_` cases that polyjose rejects on purpose.
///
/// RFC 8259 §4 only says object names SHOULD be unique, so these are valid
/// JSON. JOSE requires rejecting duplicate Header Parameter names (or
/// taking the last one) (RFC 7515 §5.2 step 4, RFC 7516 §5.2 step 4), and
/// I-JSON objects MUST NOT contain them (RFC 7493 §2.3), so polyjose
/// rejects duplicates everywhere. Any other `y_` rejection fails the test.
const Y_REJECTED: &[(&str, Error)] = &[
    (
        "y_object_duplicated_key.json",
        Error::InvalidJson("duplicate member name"),
    ),
    (
        "y_object_duplicated_key_and_value.json",
        Error::InvalidJson("duplicate member name"),
    ),
];

/// Every `i_` case: `(file, accepted, reason)`.
///
/// Note that the `y_` noncharacter cases (`U+FDD0`, `U+FFFE`, `U+10FFFE`,
/// ...) are accepted: they are Unicode scalar values, and RFC 7493 §2.1's
/// advice against them concerns what senders put in messages.
const I_CASES: &[(&str, bool, &str)] = &[
    (
        "i_number_double_huge_neg_exp.json",
        true,
        "123.456e-789 rounds to 0 (RFC 8259 §6 allows approximation); not an exact integer",
    ),
    (
        "i_number_huge_exp.json",
        false,
        "rounds to infinity: not representable (RFC 8259 §6, RFC 7493 §2.2)",
    ),
    (
        "i_number_neg_int_huge_exp.json",
        false,
        "rounds to -infinity (RFC 8259 §6, RFC 7493 §2.2)",
    ),
    (
        "i_number_pos_double_huge_exp.json",
        false,
        "rounds to infinity (RFC 8259 §6, RFC 7493 §2.2)",
    ),
    (
        "i_number_real_neg_overflow.json",
        false,
        "rounds to -infinity (RFC 8259 §6, RFC 7493 §2.2)",
    ),
    (
        "i_number_real_pos_overflow.json",
        false,
        "rounds to infinity (RFC 8259 §6, RFC 7493 §2.2)",
    ),
    (
        "i_number_real_underflow.json",
        true,
        "123e-10000000 rounds to 0 (RFC 8259 §6); not an exact integer",
    ),
    (
        "i_number_too_big_neg_int.json",
        true,
        "a finite double, but outside ±(2^53-1) so as_i64 is None (RFC 7493 §2.2)",
    ),
    (
        "i_number_too_big_pos_int.json",
        true,
        "a finite double, but outside ±(2^53-1) so as_i64 is None (RFC 7493 §2.2)",
    ),
    (
        "i_number_very_big_negative_int.json",
        true,
        "a finite double, but outside ±(2^53-1) so as_i64 is None (RFC 7493 §2.2)",
    ),
    (
        "i_object_key_lone_2nd_surrogate.json",
        false,
        "lone surrogate escape (RFC 7493 §2.1)",
    ),
    (
        "i_string_1st_surrogate_but_2nd_missing.json",
        false,
        "lone surrogate escape (RFC 7493 §2.1)",
    ),
    (
        "i_string_1st_valid_surrogate_2nd_invalid.json",
        false,
        "high surrogate not followed by a low one (RFC 7493 §2.1)",
    ),
    (
        "i_string_incomplete_surrogate_and_escape_valid.json",
        false,
        "lone surrogate escape (RFC 7493 §2.1)",
    ),
    (
        "i_string_incomplete_surrogate_pair.json",
        false,
        "lone surrogate escape (RFC 7493 §2.1)",
    ),
    (
        "i_string_incomplete_surrogates_escape_valid.json",
        false,
        "lone surrogate escapes (RFC 7493 §2.1)",
    ),
    (
        "i_string_invalid_lonely_surrogate.json",
        false,
        "lone surrogate escape (RFC 7493 §2.1)",
    ),
    (
        "i_string_invalid_surrogate.json",
        false,
        "lone surrogate escape (RFC 7493 §2.1)",
    ),
    (
        "i_string_inverted_surrogates_U+1D11E.json",
        false,
        "low surrogate before high surrogate (RFC 7493 §2.1)",
    ),
    (
        "i_string_lone_second_surrogate.json",
        false,
        "lone surrogate escape (RFC 7493 §2.1)",
    ),
    (
        "i_string_invalid_utf-8.json",
        false,
        "invalid UTF-8 (RFC 8259 §8.1, RFC 7493 §2.1)",
    ),
    (
        "i_string_iso_latin_1.json",
        false,
        "ISO-8859-1 byte, not UTF-8 (RFC 8259 §8.1, RFC 7493 §2.1)",
    ),
    (
        "i_string_lone_utf8_continuation_byte.json",
        false,
        "invalid UTF-8 (RFC 8259 §8.1, RFC 7493 §2.1)",
    ),
    (
        "i_string_not_in_unicode_range.json",
        false,
        "UTF-8 for a code point above U+10FFFF is invalid (RFC 3629 §3)",
    ),
    (
        "i_string_overlong_sequence_2_bytes.json",
        false,
        "overlong UTF-8 is invalid (RFC 3629 §3)",
    ),
    (
        "i_string_overlong_sequence_6_bytes.json",
        false,
        "overlong UTF-8 is invalid (RFC 3629 §3)",
    ),
    (
        "i_string_overlong_sequence_6_bytes_null.json",
        false,
        "overlong UTF-8 is invalid (RFC 3629 §3)",
    ),
    (
        "i_string_truncated-utf-8.json",
        false,
        "invalid UTF-8 (RFC 8259 §8.1, RFC 7493 §2.1)",
    ),
    (
        "i_string_UTF-8_invalid_sequence.json",
        false,
        "invalid UTF-8 (RFC 8259 §8.1, RFC 7493 §2.1)",
    ),
    (
        "i_string_UTF8_surrogate_U+D800.json",
        false,
        "UTF-8-encoded surrogate is invalid UTF-8 (RFC 3629 §3)",
    ),
    (
        "i_string_UTF-16LE_with_BOM.json",
        false,
        "UTF-16, not UTF-8 (RFC 8259 §8.1, RFC 7493 §2.1)",
    ),
    (
        "i_string_utf16BE_no_BOM.json",
        false,
        "UTF-16, not UTF-8 (RFC 8259 §8.1, RFC 7493 §2.1)",
    ),
    (
        "i_string_utf16LE_no_BOM.json",
        false,
        "UTF-16, not UTF-8 (RFC 8259 §8.1, RFC 7493 §2.1)",
    ),
    (
        "i_structure_500_nested_arrays.json",
        false,
        "deeper than the default max_depth of 32 (RFC 8259 §9)",
    ),
    (
        "i_structure_UTF-8_BOM_empty_object.json",
        false,
        "byte order mark: RFC 8259 §8.1 lets parsers ignore it; polyjose rejects it",
    ),
];

fn suite_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/third_party/JSONTestSuite/test_parsing")
}

/// Every case file name, sorted.
fn case_names() -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(suite_dir())
        .unwrap_or_else(|e| unreachable!("cannot read the vendored suite: {e}"))
        .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
        .filter(|name| name.ends_with(".json"))
        .collect();
    names.sort();
    names
}

fn parse_case(name: &str) -> Result<polyjose::json::Value, Error> {
    let bytes = fs::read(suite_dir().join(name)).unwrap_or_else(|e| unreachable!("{name}: {e}"));
    parse(&bytes)
}

#[test]
fn vendored_suite_is_complete() {
    let names = case_names();
    let count = |prefix: &str| names.iter().filter(|n| n.starts_with(prefix)).count();
    assert_eq!(names.len(), 318);
    assert_eq!(count("y_"), 95);
    assert_eq!(count("n_"), 188);
    assert_eq!(count("i_"), 35);
}

#[test]
fn every_y_case_is_accepted_except_duplicate_names() {
    let mut failures = Vec::new();
    for name in case_names().iter().filter(|n| n.starts_with("y_")) {
        let result = parse_case(name);
        match Y_REJECTED.iter().find(|(n, _)| n == name) {
            Some((_, expected)) if result.as_ref().err() != Some(expected) => {
                failures.push(format!("{name}: expected {expected:?}, got {result:?}"));
            }
            None if result.is_err() => failures.push(format!("{name}: rejected with {result:?}")),
            _ => {}
        }
    }
    assert!(failures.is_empty(), "y_ failures:\n{}", failures.join("\n"));
}

#[test]
fn every_n_case_is_rejected() {
    let mut failures = Vec::new();
    for name in case_names().iter().filter(|n| n.starts_with("n_")) {
        match parse_case(name) {
            Ok(v) => failures.push(format!("{name}: accepted as {v:?}")),
            Err(e) if e.code() != "InvalidJson" => failures.push(format!("{name}: {e:?}")),
            Err(_) => {}
        }
    }
    assert!(failures.is_empty(), "n_ failures:\n{}", failures.join("\n"));
}

#[test]
fn every_i_case_matches_its_documented_result() {
    let i_names: Vec<String> = case_names()
        .into_iter()
        .filter(|n| n.starts_with("i_"))
        .collect();
    let mut failures = Vec::new();
    for name in &i_names {
        match I_CASES.iter().find(|(n, _, _)| n == name) {
            None => failures.push(format!("{name}: not documented in I_CASES")),
            Some((_, accepted, reason)) => {
                let result = parse_case(name);
                if result.is_ok() != *accepted {
                    failures.push(format!(
                        "{name}: expected accepted={accepted} ({reason}), got {result:?}"
                    ));
                }
            }
        }
    }
    for (name, _, _) in I_CASES {
        if !i_names.iter().any(|n| n == name) {
            failures.push(format!("{name}: in I_CASES but not in the suite"));
        }
    }
    assert!(failures.is_empty(), "i_ failures:\n{}", failures.join("\n"));
}

#[test]
fn exceptions_name_real_files() {
    let names = case_names();
    for (name, _) in Y_REJECTED {
        assert!(
            names.iter().any(|n| n == name),
            "{name} is not in the suite"
        );
    }
}

#[test]
fn accepted_numbers_beyond_the_safe_range_are_not_integers() {
    for name in [
        "i_number_too_big_neg_int.json",
        "i_number_too_big_pos_int.json",
        "i_number_very_big_negative_int.json",
        "i_number_real_underflow.json",
        "i_number_double_huge_neg_exp.json",
    ] {
        let value = parse_case(name).unwrap_or_else(|e| unreachable!("{name}: {e}"));
        let first = value.as_array().and_then(|a| a.first());
        assert!(first.is_some_and(|n| n.as_f64().is_some()), "{name}");
        assert_eq!(first.and_then(|n| n.as_i64()), None, "{name}");
    }
}
