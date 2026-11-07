//! A source scan of every `#[uniffi::export]` function of `polyjose-ffi` (feature 0013 T12),
//! pinning two review rules so that a later change cannot quietly break them:
//!
//! 1. **The adapter test (ADR 0030 §1).** A body is a run of leading conversions (`let`
//!    statements that wrap or convert one argument) followed by one expression that makes
//!    exactly one `polyjose_surface` call: no JSON, policy, defaults or crypto of its own.
//! 2. **Secret inputs first (ADR 0030 §7.1).** Every secret-bearing argument, listed in
//!    [`SECRET_INPUTS`], is moved into a `Zeroizing` owner, or converted into the surface record
//!    whose secret fields are `SecretString`/`SecretBytes`, by one of those leading conversions,
//!    before anything else runs.
//!
//! The table must name every export, so a new export has to be classified here. What counts as
//! secret is ADR 0030 §7's list: private JWKs and JWK Sets, PBES2 passwords (an `oct` JWK), JWE
//! plaintext, JWS payloads (JWT claims to be signed among them), PEM and DER that may hold a
//! private key, `aad`, and records holding any of these. Tokens to verify or decrypt and the
//! names of algorithms, curves, hashes and formats are not.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

use std::collections::BTreeMap;

/// The adapter sources that hold exports.
const SOURCES: [&str; 6] = ["util", "jwk", "keys", "jws", "jwe", "jwt"];

/// Every export and its secret-bearing arguments (ADR 0030 §7).
const SECRET_INPUTS: &[(&str, &[&str])] = &[
    // util
    ("version", &[]),
    ("error_codes", &[]),
    ("base64url_encode", &["data"]),
    ("base64url_decode", &["text"]),
    // jwk
    ("jwk_parse", &["jwk"]),
    ("jwk_to_public", &["jwk"]),
    ("jwk_thumbprint", &["jwk"]),
    ("jwk_thumbprint_uri", &["jwk"]),
    ("jwks_select", &["jwks"]),
    // keys
    ("jwk_generate_oct", &[]),
    ("jwk_generate_ec", &[]),
    ("jwk_generate_okp", &[]),
    ("jwk_generate_for_alg", &[]),
    ("jwk_from_pem", &["pem"]),
    ("jwk_from_der", &["der"]),
    ("jwk_to_pem", &["jwk"]),
    ("jwk_to_der", &["jwk"]),
    // jws: `options` of verify holds the detached payload
    ("jws_sign_compact", &["payload", "key"]),
    ("jws_sign_flattened", &["payload", "signer"]),
    ("jws_sign_general", &["payload", "signers"]),
    ("jws_verify_compact", &["key", "options"]),
    ("jws_verify_json", &["key", "options"]),
    // jwe: `options` of encrypt holds the recipient keys and the aad
    ("jwe_encrypt_compact", &["plaintext", "options"]),
    ("jwe_encrypt_json", &["plaintext", "options"]),
    ("jwe_decrypt_compact", &["key"]),
    ("jwe_decrypt_json", &["key"]),
    // jwt: the signed JWT to encrypt is JWE plaintext
    ("jwt_sign", &["claims", "key"]),
    ("jwt_verify", &["key"]),
    ("jwt_verify_with_jwks", &["jwks"]),
    ("jwt_encrypt_nested", &["signed_jwt", "options"]),
    ("jwt_decrypt_nested", &["decrypt_key", "key"]),
    ("jwt_decrypt_nested_with_jwks", &["decrypt_key", "jwks"]),
];

/// One exported function: its source file, parameter names and body.
struct Export {
    file: &'static str,
    params: Vec<String>,
    body: String,
}

/// Every `#[uniffi::export]` free function of [`SOURCES`], by name.
fn exports() -> BTreeMap<String, Export> {
    let mut out = BTreeMap::new();
    for file in SOURCES {
        let path = format!("{}/src/{file}.rs", env!("CARGO_MANIFEST_DIR"));
        let source = std::fs::read_to_string(&path).unwrap();
        for chunk in source.split("#[uniffi::export]\npub fn ").skip(1) {
            let name = chunk[..chunk.find('(').unwrap()].to_owned();
            let open = chunk.find('(').unwrap();
            let close = open + chunk[open..].find(')').unwrap();
            let params = chunk[open + 1..close]
                .split(',')
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(|p| p[..p.find(':').unwrap()].trim().to_owned())
                .collect();
            // Exports are top-level items: the body ends at the first unindented `}`.
            let start = close + chunk[close..].find("{\n").unwrap() + 2;
            let end = start + chunk[start..].find("\n}\n").unwrap();
            let body = chunk[start..end].to_owned();
            let previous = out.insert(name.clone(), Export { file, params, body });
            assert!(previous.is_none(), "{name} is exported twice");
        }
    }
    out
}

/// `text` without any whitespace, so the checks do not depend on rustfmt's line breaks.
fn squash(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

/// The argument a leading statement converts, if it is one of the allowed conversions: a move
/// into `Zeroizing`, a `From` conversion into a surface record, or the element-wise conversion of
/// a list of records.
fn converted_argument(statement: &str) -> Option<String> {
    let s = squash(statement);
    let rest = s.strip_prefix("let")?;
    let (lhs, rhs) = rest.split_once('=')?;
    let name = lhs.split(':').next()?.to_owned();
    let allowed = [
        format!("Zeroizing::new({name})"),
        format!("{name}.into_iter().map(Into::into).collect()"),
    ];
    let is_from = rhs.starts_with("surface::") && rhs.ends_with(&format!("::from({name})"));
    (allowed.contains(&rhs.to_owned()) || is_from).then_some(name)
}

#[test]
fn the_table_names_every_export_and_only_exports() {
    let exports = exports();
    let found: Vec<&str> = exports.keys().map(String::as_str).collect();
    let mut listed: Vec<&str> = SECRET_INPUTS.iter().map(|(name, _)| *name).collect();
    listed.sort_unstable();
    assert_eq!(found, listed);
    for (name, secrets) in SECRET_INPUTS {
        for secret in *secrets {
            assert!(
                exports[*name].params.iter().any(|p| p == secret),
                "{name} has no argument {secret}"
            );
        }
    }
}

#[test]
fn every_export_is_leading_conversions_and_one_surface_call() {
    for (name, export) in exports() {
        let statements: Vec<&str> = export.body.split(';').map(str::trim).collect();
        let lets = statements
            .iter()
            .take_while(|s| s.starts_with("let "))
            .count();
        for statement in &statements[..lets] {
            let argument = converted_argument(statement).unwrap_or_else(|| {
                panic!(
                    "{}.rs {name}: `{statement}` is not a conversion of one argument",
                    export.file
                )
            });
            assert!(
                export.params.contains(&argument),
                "{}.rs {name}: `{statement}` converts no argument",
                export.file
            );
        }
        let rest = &statements[lets..];
        assert_eq!(
            rest.len(),
            1,
            "{}.rs {name}: one expression must follow the conversions, found {rest:?}",
            export.file
        );
        let calls = squash(rest[0]).matches("polyjose_surface::").count();
        assert_eq!(
            calls, 1,
            "{}.rs {name}: expected one surface call in `{}`",
            export.file, rest[0]
        );
    }
}

#[test]
fn every_secret_input_is_wrapped_by_a_leading_conversion() {
    let exports = exports();
    for (name, secrets) in SECRET_INPUTS {
        let export = &exports[*name];
        let converted: Vec<String> = export
            .body
            .split(';')
            .map(str::trim)
            .take_while(|s| s.starts_with("let "))
            .filter_map(converted_argument)
            .collect();
        for secret in *secrets {
            assert!(
                converted.iter().any(|c| c == secret),
                "{}.rs {name}: secret argument {secret} is not moved into a Zeroizing owner or a \
                 surface record before the surface call (ADR 0030 §7.1)",
                export.file
            );
        }
    }
}

#[test]
fn the_scan_rejects_a_body_that_does_more_than_convert() {
    // The scan's own negative cases: anything but a conversion of an argument is refused.
    for statement in [
        "let jwk = jwk.clone()",
        "let jwk = Zeroizing::new(other)",
        "let options = surface::JwsVerifyOptions::default()",
        "let n = 3",
        "let alg = String::from(\"HS256\")",
    ] {
        assert_eq!(converted_argument(statement), None, "{statement} accepted");
    }
    assert_eq!(
        converted_argument("let jwk = Zeroizing::new(jwk)").as_deref(),
        Some("jwk")
    );
    assert_eq!(
        converted_argument(
            "let signers: Vec<surface::JwsSigner> = signers.into_iter().map(Into::into).collect()"
        )
        .as_deref(),
        Some("signers")
    );
}

#[test]
fn no_doc_comment_can_end_or_nest_a_generated_block_comment() {
    // UniFFI copies each doc comment verbatim into a `/** ... */` block of the generated Kotlin
    // and Swift. A `*/` inside ends that block early and a `/*` opens a nested one (both
    // languages nest block comments), so either breaks compilation of the generated sources:
    // write `RS*` and `PS*`, never `RS*/PS*`.
    let dir = format!("{}/src", env!("CARGO_MANIFEST_DIR"));
    let mut scanned = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let source = std::fs::read_to_string(&path).unwrap();
        for (number, line) in source.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("///") || trimmed.starts_with("//!") {
                let text = &trimmed[3..];
                assert!(
                    !text.contains("*/") && !text.contains("/*"),
                    "{}:{}: a doc comment holds `*/` or `/*`: {line}",
                    path.display(),
                    number + 1
                );
            }
        }
        scanned += 1;
    }
    assert!(
        scanned >= SOURCES.len(),
        "scanned only {scanned} files in {dir}"
    );
}
