//! Black-box checks of the public error contract (T02, ADR 0007):
//! exact code names, and no input bytes in `Debug`/`Display`/`source()` of
//! any error, including errors from parsing marked input with polyjose's own
//! JSON parser (T10) and the header and JWK parsers built on it.
//!
//! `serde_json` (a dev-dependency only, ADR 0016 §5) is the oracle that
//! shows the probes are adversarial: on the same bytes, its messages quote
//! the marker.

use polyjose::header::Header;
use polyjose::jwk::Jwk;
use polyjose::{Error, json};
use serde::Deserialize;

const MARKER: &str = "pj-SECRET-marker-9c1d";

const AC_CODES: [&str; 17] = [
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
    "InvalidFormat",
    "NoMatchingKey",
    "MultipleMatchingKeys",
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
        Error::InvalidFormat("x"),
        Error::NoMatchingKey,
        Error::MultipleMatchingKeys,
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

#[derive(Debug, Deserialize)]
struct KtyOnly {
    #[serde(rename = "kty")]
    _kty: Kind,
}

#[derive(Debug, Deserialize)]
struct AlgOnly {
    #[serde(rename = "alg")]
    _alg: Kind,
}

#[derive(Debug, Deserialize)]
struct P2cOnly {
    #[serde(rename = "p2c")]
    _p2c: u64,
}

/// The outcome of one adversarial input: what polyjose does with it, and what
/// `serde_json` does with the same bytes.
struct Probe {
    what: &'static str,
    ours: polyjose::Result<()>,
    /// `true` if the failure must come from the JSON layer itself.
    json_level: bool,
    oracle: Option<serde_json::Error>,
}

fn json_only(input: &[u8]) -> polyjose::Result<()> {
    json::parse(input).map(drop)
}

fn jwk(input: &[u8]) -> polyjose::Result<()> {
    Jwk::from_json(input).map(drop)
}

fn header(input: &[u8]) -> polyjose::Result<()> {
    Header::from_json(input).map(drop)
}

/// A header that parses but whose `alg` names no supported algorithm.
fn header_alg(input: &[u8]) -> polyjose::Result<()> {
    Header::from_json(input)?.signing_alg().map(drop)
}

fn probe(
    what: &'static str,
    input: &[u8],
    ours: fn(&[u8]) -> polyjose::Result<()>,
    json_level: bool,
    oracle: Option<serde_json::Error>,
) -> Probe {
    assert!(
        input.windows(MARKER.len()).any(|w| w == MARKER.as_bytes()),
        "probe {what} lacks the marker"
    );
    Probe {
        what,
        ours: ours(input),
        json_level,
        oracle,
    }
}

/// Inputs that quote `MARKER` next to a fault. JSON syntax faults go to
/// `json::parse`; valid JSON of the wrong shape goes to the typed parsers,
/// which replaced serde's typed deserialization (ADR 0016).
///
/// The two former serde-only probes have no counterpart: a custom
/// `Deserialize` message (polyjose has no user deserializers) and an I/O
/// error from a reader (polyjose parses byte slices, so it never reads).
fn marked_probes() -> Vec<Probe> {
    let q = format!("\"{MARKER}\"");
    let unknown_field = format!("{{\"{MARKER}\":1}}");
    let kty = format!("{{\"kty\":{q}}}");
    let alg = format!("{{\"alg\":{q}}}");
    let p2c = format!("{{\"p2c\":{q}}}");
    let out_of_range = format!("{{\"{MARKER}\":1e400}}");
    let trailing = format!("{q} {MARKER}");
    let eof = format!("{{\"{MARKER}\":");
    let syntax = format!("{{\"{MARKER}\" {MARKER}}}");
    let bad_escape = format!("\"{MARKER}\\q\"");
    let surrogate = format!("\"{MARKER}\\ud800\"");
    let control = format!("\"{MARKER}\n\"");
    let duplicate = format!("{{\"{MARKER}\":1,\"{MARKER}\":2}}");
    let bom = format!("\u{feff}{q}");
    let mut utf8 = format!("\"{MARKER}").into_bytes();
    utf8.extend_from_slice(&[0xff, 0xfe, b'"']);
    type V = serde_json::Value;
    vec![
        probe(
            "invalid type, string value",
            q.as_bytes(),
            jwk,
            false,
            serde_json::from_str::<u32>(&q).err(),
        ),
        probe(
            "unknown field",
            unknown_field.as_bytes(),
            jwk,
            false,
            serde_json::from_str::<Strict>(&unknown_field).err(),
        ),
        probe(
            "unknown kty",
            kty.as_bytes(),
            jwk,
            false,
            serde_json::from_str::<KtyOnly>(&kty).err(),
        ),
        probe(
            "unknown alg",
            alg.as_bytes(),
            header_alg,
            false,
            serde_json::from_str::<AlgOnly>(&alg).err(),
        ),
        probe(
            "nested type error",
            p2c.as_bytes(),
            header,
            false,
            serde_json::from_str::<P2cOnly>(&p2c).err(),
        ),
        probe(
            "number out of range",
            out_of_range.as_bytes(),
            json_only,
            true,
            serde_json::from_str::<V>(&out_of_range).err(),
        ),
        probe(
            "trailing chars",
            trailing.as_bytes(),
            json_only,
            true,
            serde_json::from_str::<V>(&trailing).err(),
        ),
        probe(
            "EOF",
            eof.as_bytes(),
            json_only,
            true,
            serde_json::from_str::<V>(&eof).err(),
        ),
        probe(
            "syntax",
            syntax.as_bytes(),
            json_only,
            true,
            serde_json::from_str::<V>(&syntax).err(),
        ),
        probe(
            "invalid escape",
            bad_escape.as_bytes(),
            json_only,
            true,
            serde_json::from_str::<V>(&bad_escape).err(),
        ),
        probe(
            "lone surrogate",
            surrogate.as_bytes(),
            json_only,
            true,
            serde_json::from_str::<V>(&surrogate).err(),
        ),
        probe(
            "control char",
            control.as_bytes(),
            json_only,
            true,
            serde_json::from_str::<V>(&control).err(),
        ),
        probe(
            "invalid UTF-8",
            &utf8,
            json_only,
            true,
            serde_json::from_slice::<V>(&utf8).err(),
        ),
        probe(
            "duplicate member",
            duplicate.as_bytes(),
            json_only,
            true,
            serde_json::from_str::<V>(&duplicate).err(),
        ),
        probe(
            "byte order mark",
            bom.as_bytes(),
            json_only,
            true,
            serde_json::from_str::<V>(&bom).err(),
        ),
    ]
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
fn adversarial_json_errors_do_not_leak_input() {
    let probes = marked_probes();
    assert!(probes.len() >= 14);
    let mut echoed = 0;
    for p in probes {
        if let Some(je) = &p.oracle
            && format!("{je}{je:?}").contains(MARKER)
        {
            echoed += 1;
        }
        let e = p.ours.err();
        assert!(e.is_some(), "probe {} must fail", p.what);
        if let Some(e) = e {
            assert!(Error::CODES.contains(&e.code()), "{}", p.what);
            if p.json_level {
                assert_eq!(e.code(), "InvalidJson", "{}", p.what);
            }
            assert_clean(&e);
        }
    }
    // The probe is meaningful only if a parser that quotes input (serde_json)
    // echoes the marker on these same bytes.
    assert!(echoed >= 5, "serde_json echoed only {echoed}");
}

#[test]
fn question_mark_propagation_does_not_leak() {
    /// Caller code that propagates a parse error with `?`.
    fn member_count(s: &str) -> polyjose::Result<usize> {
        let value = json::parse(s.as_bytes())?;
        Ok(value.as_object().map_or(0, json::Object::len))
    }
    assert_eq!(member_count("{\"k\":1}"), Ok(1));
    let e = member_count(&format!("{{\"k\": {MARKER}}}")).unwrap_err();
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
