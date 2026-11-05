//! Black-box checks of the public error contract (T02, ADR 0007):
//! exact code names, and no input bytes in `Debug`/`Display`/`source()` of
//! any error, including `serde_json` errors built from marked input.

use polyjose::Error;
use serde::Deserialize;

const MARKER: &str = "pj-SECRET-marker-9c1d";

const AC_CODES: [&str; 14] = [
    "InvalidBase64",
    "InvalidJson",
    "InvalidHeader",
    "UnsupportedAlgorithm",
    "AlgorithmNotAllowed",
    "InvalidKey",
    "KeyAlgorithmMismatch",
    "InvalidSignature",
    "DecryptionFailed",
    "UnknownCritical",
    "TokenExpired",
    "TokenNotYetValid",
    "InvalidClaim",
    "RandomnessUnavailable",
];

#[test]
fn codes_contain_exactly_the_acceptance_criteria_names() {
    let mut have: Vec<&str> = Error::CODES.to_vec();
    let mut want: Vec<&str> = AC_CODES.to_vec();
    have.sort_unstable();
    want.sort_unstable();
    assert_eq!(have, want);
}

#[test]
fn code_is_reachable_for_every_code_via_public_api() {
    let all = [
        Error::InvalidBase64,
        Error::InvalidJson("x"),
        Error::InvalidHeader("x"),
        Error::UnsupportedAlgorithm,
        Error::AlgorithmNotAllowed,
        Error::InvalidKey("x"),
        Error::KeyAlgorithmMismatch,
        Error::InvalidSignature,
        Error::DecryptionFailed,
        Error::UnknownCritical,
        Error::TokenExpired,
        Error::TokenNotYetValid,
        Error::InvalidClaim("x"),
        Error::RandomnessUnavailable,
    ];
    let mut codes: Vec<&str> = all.iter().map(Error::code).collect();
    codes.sort_unstable();
    let mut want = AC_CODES.to_vec();
    want.sort_unstable();
    assert_eq!(codes, want);
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Strict {
    #[serde(rename = "a")]
    _a: u8,
}

#[derive(Debug, Deserialize)]
enum Kind {
    #[serde(rename = "known")]
    _Known,
}

#[derive(Debug)]
struct Custom;
impl<'de> Deserialize<'de> for Custom {
    fn deserialize<D: serde::Deserializer<'de>>(_: D) -> Result<Self, D::Error> {
        Err(serde::de::Error::custom(MARKER))
    }
}

struct FailingReader;
impl std::io::Read for FailingReader {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other(MARKER))
    }
}

fn marked_json_errors() -> Vec<serde_json::Error> {
    let q = format!("\"{MARKER}\"");
    let mut v: Vec<Option<serde_json::Error>> = vec![
        serde_json::from_str::<u32>(&q).err(), // invalid type, string value
        serde_json::from_str::<Strict>(&format!("{{\"{MARKER}\":1}}")).err(), // unknown field
        serde_json::from_str::<Kind>(&q).err(), // unknown variant
        serde_json::from_str::<serde_json::Value>(&format!("{q} {MARKER}")).err(), // trailing chars
        serde_json::from_str::<serde_json::Value>(&format!("{{\"{MARKER}\":")).err(), // EOF
        serde_json::from_str::<serde_json::Value>(&format!("{{\"{MARKER}\" {MARKER}}}")).err(), // syntax
        serde_json::from_str::<Custom>("1").err(), // custom message
        serde_json::from_str::<Strict>(&format!("{{\"a\":\"{MARKER}\"}}")).err(), // nested type error
        serde_json::from_str::<u8>("99999999999").err(), // number out of range
        serde_json::from_str::<String>(&format!("\"{MARKER}\\q\"")).err(), // invalid escape
        serde_json::from_str::<String>(&format!("\"{MARKER}\\ud800\"")).err(), // lone surrogate
        serde_json::from_str::<String>(&format!("\"{MARKER}\n\"")).err(), // control char
        serde_json::from_slice::<String>(&[b'"', 0xff, 0xfe, b'"']).err(), // invalid UTF-8
        serde_json::from_reader::<_, serde_json::Value>(FailingReader).err(), // io
    ];
    let n = v.len();
    let errs: Vec<serde_json::Error> = v.drain(..).flatten().collect();
    assert_eq!(errs.len(), n, "every probe input must fail to parse");
    errs
}

fn assert_clean(e: &Error) {
    let dbg = format!("{e:?}");
    let disp = e.to_string();
    let alt = format!("{e:#?}");
    for s in [&dbg, &disp, &alt] {
        assert!(!s.contains(MARKER), "leak: {s}");
        assert!(!s.contains("pj-SECRET"), "leak: {s}");
    }
    // The whole source chain must be clean too (and is expected empty).
    let mut src = std::error::Error::source(e);
    assert!(src.is_none(), "unexpected source for {}", e.code());
    while let Some(s) = src {
        assert!(!format!("{s:?}{s}").contains(MARKER));
        src = s.source();
    }
}

#[test]
fn adversarial_serde_json_errors_do_not_leak_input() {
    let errs = marked_json_errors();
    assert!(errs.len() >= 14);
    let mut echoed = 0;
    for je in errs {
        if format!("{je}{je:?}").contains(MARKER) {
            echoed += 1;
        }
        let e: Error = je.into();
        assert_eq!(e.code(), "InvalidJson");
        assert_clean(&e);
    }
    // The probe is meaningful only if serde_json itself echoes input.
    assert!(echoed >= 5, "serde_json echoed only {echoed}");
}

#[test]
fn question_mark_conversion_does_not_leak() {
    fn parse(s: &str) -> polyjose::Result<serde_json::Value> {
        Ok(serde_json::from_str(s)?)
    }
    let e = parse(&format!("{{\"k\": {MARKER}}}")).unwrap_err();
    assert_eq!(e.code(), "InvalidJson");
    assert_clean(&e);
}

#[test]
fn decryption_failed_is_a_bare_unit() {
    let e = Error::DecryptionFailed;
    assert_eq!(format!("{e:?}"), "DecryptionFailed");
    assert_eq!(format!("{e:#?}"), "DecryptionFailed");
    assert_eq!(e.to_string(), "decryption failed");
    assert!(std::error::Error::source(&e).is_none());
    assert_eq!(e.clone(), Error::DecryptionFailed);
}

#[test]
fn error_is_send_sync_static() {
    fn ok<T: Send + Sync + 'static + std::error::Error>() {}
    ok::<Error>();
}
