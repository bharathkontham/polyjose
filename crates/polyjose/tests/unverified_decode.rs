//! The unverified decode utilities against verification (feature 0026,
//! ADR 0069; PRD 0004 R7, R9, R12).
//!
//! - **R12, the differential test:** `decode_jws_unverified` runs exactly
//!   steps 1–5 of ADR 0048, the code `jws::verify_compact` runs (ADR 0069
//!   §3). Over every compact `jws.verify` vector under
//!   `conformance/vectors/jws-*/`, verification failing at steps 1–5 means
//!   decode fails with the same code; anything else means decode succeeds,
//!   and when verification succeeds the two agree on the payload and the
//!   protected header.
//! - **R7:** no error message or `Debug` output of the three utilities
//!   contains a marker placed in the token.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

use std::path::{Path, PathBuf};

use polyjose::Error;
use polyjose::json::{self, Object, Value};
use polyjose::jwa::SigningAlg;
use polyjose::jwk::Jwk;
use polyjose::jws::{self, VerifyOptions};
use polyjose::util::{
    b64url_encode, decode_jws_unverified, decode_jwt_unverified, decode_protected_header_unverified,
};

/// The error codes of ADR 0048 steps 1–5 (`jws` module table): the only
/// codes decode can give, and the only ones verification gives before
/// step 6 (`crit` understood, `alg`, key binding, signature).
const STEPS_1_TO_5: [&str; 4] = [
    "InvalidFormat",
    "InvalidBase64",
    "InvalidJson",
    "InvalidHeader",
];

/// The RFC 7515 A.1 key: a stand-in for a vector key that doesn't import.
/// Steps 1–5 use no key, so it changes no step 1–5 outcome.
const STAND_IN_KEY: &str = r#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#;

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/vectors")
}

fn collect(dir: &Path, files: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect(&path, files);
        } else if path.extension().is_some_and(|e| e == "json") {
            files.push(path);
        }
    }
}

/// Every compact `jws.verify` vector under `jws-*/`: its file name and its
/// input. Vector files may exceed the 1 MiB JSON default (the
/// `jws-limits/` ones do), as conformance/README.md allows.
fn compact_verify_vectors() -> Vec<(String, Object)> {
    let root = vectors_dir();
    let mut files = Vec::new();
    for entry in std::fs::read_dir(&root).unwrap() {
        let path = entry.unwrap().path();
        let top = path.file_name().unwrap().to_string_lossy().into_owned();
        if path.is_dir() && top.starts_with("jws-") {
            collect(&path, &mut files);
        }
    }
    files.sort();
    let mut limits = json::Limits::DEFAULT;
    limits.max_input_len = 4 * 1024 * 1024;
    files
        .into_iter()
        .filter_map(|path| {
            let bytes = std::fs::read(&path).unwrap();
            let vector = json::parse_with_limits(&bytes, &limits).unwrap();
            let operation = vector.get("operation").and_then(Value::as_str);
            let input = vector.get("input").and_then(Value::as_object)?.clone();
            let compact = input.get("jws").is_some_and(|j| j.as_str().is_some());
            let name = path.strip_prefix(&root).unwrap().display().to_string();
            (operation == Some("jws.verify") && compact).then_some((name, input))
        })
        .collect()
}

/// Verification of the vector's token with its key and allow-list, but
/// with the default limits and no detached payload: the configuration
/// decode always uses (ADR 0069 §2). A key or allow-list the library
/// refuses is replaced by a stand-in; neither is read before step 6.
fn verify_as_decode_would(input: &Object) -> Result<jws::Verified, Error> {
    let token = input.get("jws").and_then(Value::as_str).unwrap();
    let key = input
        .get("key")
        .and_then(Value::as_object)
        .and_then(|k| Jwk::from_object(k).ok())
        .unwrap_or_else(|| Jwk::from_json(STAND_IN_KEY.as_bytes()).unwrap());
    let algs: Vec<SigningAlg> = input
        .get("allowed_algs")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .map(|a| SigningAlg::from(a.as_str().unwrap()))
        .collect();
    let stand_in = [SigningAlg::HS256];
    let opts = VerifyOptions::new(&algs).unwrap_or_else(|_| VerifyOptions::new(&stand_in).unwrap());
    jws::verify_compact(token, &key, &opts)
}

/// PRD 0004 R12 (ADR 0069 §2–§3): decode succeeds exactly when
/// verification gets past step 5, with verification's code otherwise.
#[test]
fn decode_agrees_with_verify_over_every_compact_jws_verify_vector() {
    let vectors = compact_verify_vectors();
    let (mut early, mut late, mut verified_count) = (0, 0, 0);
    let mut failures = Vec::new();
    for (name, input) in &vectors {
        let token = input.get("jws").and_then(Value::as_str).unwrap();
        let decoded = decode_jws_unverified(token);
        match (verify_as_decode_would(input), decoded) {
            (Err(v), Err(d)) if STEPS_1_TO_5.contains(&v.code()) => {
                early += 1;
                if v.code() != d.code() {
                    failures.push(format!("{name}: verify {}, decode {}", v.code(), d.code()));
                }
            }
            (Err(v), Ok(_)) if STEPS_1_TO_5.contains(&v.code()) => {
                failures.push(format!(
                    "{name}: verify {} at steps 1-5, decode succeeded",
                    v.code()
                ));
            }
            (Err(_), Ok(_)) => late += 1,
            (Err(v), Err(d)) => {
                failures.push(format!(
                    "{name}: verify {} after step 5, decode {}",
                    v.code(),
                    d.code()
                ));
            }
            (Ok(v), Ok(d)) => {
                verified_count += 1;
                if d.payload != v.payload {
                    failures.push(format!("{name}: payloads differ"));
                }
                if Some(&d.protected) != v.protected.as_ref() {
                    failures.push(format!("{name}: protected headers differ"));
                }
            }
            (Ok(_), Err(d)) => {
                failures.push(format!("{name}: verify succeeded, decode {}", d.code()));
            }
        }
    }
    eprintln!(
        "{} compact jws.verify vectors: {early} fail at steps 1-5, {late} after, {verified_count} verify",
        vectors.len()
    );
    assert!(
        failures.is_empty(),
        "decode and verify disagree:\n  {}",
        failures.join("\n  ")
    );
    // Not vacuous: the corpus exercises all three outcomes.
    assert!(
        vectors.len() >= 50,
        "only {} compact jws.verify vectors",
        vectors.len()
    );
    assert!(early >= 10, "only {early} vectors fail at steps 1-5");
    assert!(late >= 10, "only {late} vectors fail after step 5");
    assert!(verified_count >= 5, "only {verified_count} vectors verify");
}

/// The JWS decode never returns verification's step 6 codes, whatever the
/// header says: `none`, unknown `alg` and unknown `crit` are data
/// (ADR 0069 §2, PRD 0004 R8), and verification still refuses each.
#[test]
fn what_verify_refuses_at_step_6_decode_returns_as_data() {
    let h = |json: &str| b64url_encode(json.as_bytes());
    let payload = b64url_encode(b"{}");
    let key = Jwk::from_json(STAND_IN_KEY.as_bytes()).unwrap();
    let algs = [SigningAlg::HS256];
    let opts = VerifyOptions::new(&algs).unwrap();
    for (header, refused) in [
        (r#"{"alg":"none"}"#, "AlgorithmNotAllowed"),
        (r#"{"alg":"HS999"}"#, "UnsupportedAlgorithm"),
        (
            r#"{"alg":"HS256","crit":["urn:x"],"urn:x":1}"#,
            "UnknownCritical",
        ),
        (r#"{"alg":"ES256"}"#, "AlgorithmNotAllowed"),
        (r#"{"alg":"HS256"}"#, "InvalidSignature"),
    ] {
        let token = format!("{}.{payload}.c2ln", h(header));
        assert_eq!(
            jws::verify_compact(&token, &key, &opts).unwrap_err().code(),
            refused,
            "{header}"
        );
        assert!(decode_jws_unverified(&token).is_ok(), "{header}");
        assert!(decode_jwt_unverified(&token).is_ok(), "{header}");
        assert!(
            decode_protected_header_unverified(&token).is_ok(),
            "{header}"
        );
    }
}

/// PRD 0004 R7 and AC 6: a marker placed in every part of a failing token
/// never appears in an error's `Display` or `Debug`, and a marker in a
/// payload never appears in an `UnverifiedJws`'s `Debug`.
#[test]
fn no_error_or_debug_contains_input() {
    const MARKER: &str = "MARKER7f3a";
    let h = |json: &str| b64url_encode(json.as_bytes());
    let marked = h(&format!(r#"{{"{MARKER}":"{MARKER}"}}"#));
    let tokens = [
        // Each fails at a different step, with the marker in every part.
        format!("{MARKER}.{MARKER}"),
        format!("{MARKER}.{MARKER}.{MARKER}.{MARKER}"),
        format!("{marked}.{marked}.{MARKER}="),
        format!("{MARKER}=.{marked}.c2ln"),
        format!(
            "{}.{marked}.c2ln",
            h(&format!(r#"{{"alg":"{MARKER}","alg":"x"}}"#))
        ),
        format!(
            "{}.{marked}.c2ln",
            h(&format!(r#"{{"alg":1,"kid":"{MARKER}"}}"#))
        ),
        format!("{}.{MARKER}=.c2ln", h(&format!(r#"{{"alg":"{MARKER}"}}"#))),
        format!("{}.{marked}.c2ln", h(&format!(r#"{{"kid":"{MARKER}"}}"#))),
        format!(
            "{}.{marked}.c2ln",
            h(&format!(r#"{{"alg":"x","cty":"JWT","kid":"{MARKER}"}}"#))
        ),
        format!(
            "{}.{}.c2ln",
            h(r#"{"alg":"x"}"#),
            h(&format!(r#"{{"exp":"{MARKER}"}}"#))
        ),
        format!(
            "{}.{}.c2ln",
            h(r#"{"alg":"x"}"#),
            h(&format!(r#"["{MARKER}"]"#))
        ),
        format!(r#"{{"payload":"{MARKER}","signature":"{MARKER}"}}"#),
        format!("{marked}.{MARKER}.{MARKER}.{MARKER}.{MARKER}.{MARKER}"),
    ];
    let mut errors = 0;
    for token in &tokens {
        let results = [
            decode_protected_header_unverified(token).err(),
            decode_jws_unverified(token).err(),
            decode_jwt_unverified(token).err(),
        ];
        for error in results.into_iter().flatten() {
            errors += 1;
            for rendered in [
                error.to_string(),
                format!("{error:?}"),
                format!("{error:#?}"),
            ] {
                assert!(!rendered.contains(MARKER), "{token}: {rendered}");
            }
        }
    }
    assert!(errors >= 30, "only {errors} errors were checked");

    let token = format!(
        "{}.{}.c2ln",
        h(r#"{"alg":"none"}"#),
        b64url_encode(MARKER.as_bytes())
    );
    let decoded = decode_jws_unverified(&token).unwrap();
    for rendered in [format!("{decoded:?}"), format!("{decoded:#?}")] {
        assert!(!rendered.contains(MARKER), "{rendered}");
    }
}
