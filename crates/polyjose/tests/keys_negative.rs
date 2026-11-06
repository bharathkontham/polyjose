//! Rejections of the PEM/DER facade (ADR 0018 §2–§4) through the public API
//! only:
//!
//! - every row of `tests/data/keys/negative/manifest.json` gives its
//!   `expect`: PEM rows through `Jwk::from_pem`, DER rows through
//!   `Jwk::from_der` in the format the vector holds;
//! - every `reject-*` fixture in `openssl/` and `rfc/` gives the code of the
//!   fixtures README table (`tests/data/keys/regen/README.md`);
//! - encrypted keys (RFC 5958 §3, RFC 1421 §4.6.1.1) are
//!   `UnsupportedAlgorithm`;
//! - the export format matrix (plan.md, ADR 0018 §3).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

use std::path::{Path, PathBuf};

use polyjose::Error;
use polyjose::json::{self, Value};
use polyjose::jwk::Jwk;
use polyjose::keys::{KeyFormat, KeySpec, generate};

const FORMATS: [KeyFormat; 4] = [
    KeyFormat::Pkcs8,
    KeyFormat::Sec1,
    KeyFormat::Spki,
    KeyFormat::Pkcs1,
];

fn data_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/keys")
}

fn read(dir: &str, file: &str) -> Vec<u8> {
    let path = data_dir().join(dir).join(file);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn files(dir: &str) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(data_dir().join(dir))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.ends_with(".pem") || n.ends_with(".der"))
        .collect();
    names.sort();
    names
}

/// The format a fixture name says it holds, if any.
fn named_format(name: &str) -> Option<KeyFormat> {
    [
        ("-pkcs8", KeyFormat::Pkcs8),
        ("-sec1", KeyFormat::Sec1),
        ("-spki", KeyFormat::Spki),
        ("-pkcs1", KeyFormat::Pkcs1),
    ]
    .into_iter()
    .find(|(token, _)| name.contains(token))
    .map(|(_, format)| format)
}

/// Imports a fixture through the public API: `.pem` with `from_pem`,
/// `.der` with `from_der` in `format`.
fn import(bytes: &[u8], name: &str, format: Option<KeyFormat>) -> Result<Jwk, Error> {
    if name.ends_with(".pem") {
        Jwk::from_pem(std::str::from_utf8(bytes).unwrap())
    } else {
        Jwk::from_der(bytes, format.unwrap_or_else(|| panic!("{name}: no format")))
    }
}

fn code(result: &Result<Jwk, Error>) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(e) => e.code(),
    }
}

// ---------------------------------------------------------------------------
// negative/manifest.json
// ---------------------------------------------------------------------------

struct Row {
    id: String,
    file: String,
    base: String,
    expect: String,
    jwk: Option<String>,
}

fn manifest() -> Vec<Row> {
    let manifest = json::parse(&read("negative", "manifest.json")).unwrap();
    let field = |row: &Value, name: &str| row.get(name).and_then(Value::as_str).map(str::to_owned);
    manifest
        .as_array()
        .unwrap()
        .iter()
        .map(|row| Row {
            id: field(row, "id").unwrap(),
            file: field(row, "file").unwrap(),
            base: field(row, "base").unwrap(),
            expect: field(row, "expect").unwrap(),
            jwk: field(row, "jwk"),
        })
        .collect()
}

/// The format a DER vector holds: the one its own name states (N40–N47
/// `-sec1-`, N50–N52 and N67 `-pkcs8-`, N65 `-pkcs1-`, N38 `-spki-`),
/// otherwise its base file's. N67 is the one vector whose structure is not
/// its base's: a minimal PKCS#8 with rsaEncryption, built from the RSA SPKI
/// (its mutation says so, and its name says `pkcs8`).
fn row_format(row: &Row) -> KeyFormat {
    named_format(&row.file)
        .or_else(|| named_format(&row.base))
        .unwrap_or_else(|| panic!("{}: no format", row.id))
}

#[test]
fn every_manifest_row_gives_its_expected_result() {
    let rows = manifest();
    assert_eq!(rows.len(), 67, "64 must-reject and 3 must-accept vectors");
    let mut failures = Vec::new();
    for row in &rows {
        let bytes = read("negative", &row.file);
        let result = import(&bytes, &row.file, Some(row_format(row)));
        if code(&result) != row.expect {
            failures.push(format!(
                "{} {}: expected {}, got {:?}",
                row.id,
                row.file,
                row.expect,
                result.as_ref().err()
            ));
            continue;
        }
        if let (Ok(jwk), Some(want)) = (&result, &row.jwk) {
            let want = Jwk::from_json(&read("rfc", want)).unwrap();
            assert_eq!(jwk.to_object(), want.to_object(), "{}", row.id);
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn pem_armor_around_the_wrong_or_trailing_der_is_rejected() {
    // P14: a PUBLIC KEY label around a PKCS#8 body. The label selects SPKI
    // (RFC 7468 §13) and the body is not one, so the key is never read as
    // the private key it is (ADR 0018 §2: structure from the DER).
    let p14 = String::from_utf8(read("negative", "P14-label-public-key-body-pkcs8.pem")).unwrap();
    assert!(matches!(Jwk::from_pem(&p14), Err(Error::InvalidKey(_))));
    // P16: valid armor around DER with a trailing 0x00 (X.690 §8.1.1).
    let p16 = String::from_utf8(read("negative", "P16-trailing-der-garbage.pem")).unwrap();
    assert!(matches!(Jwk::from_pem(&p16), Err(Error::InvalidKey(_))));
}

// ---------------------------------------------------------------------------
// reject-* fixtures (tests/data/keys/regen/README.md table)
// ---------------------------------------------------------------------------

/// A fixtures README table row's file pattern.
type Rule = dyn Fn(&str) -> bool;

/// The code the fixtures README table gives a `reject-*` file, rules in
/// table order (the first that matches wins).
fn readme_expect(file: &str) -> &'static str {
    let rules: [(&Rule, &str); 9] = [
        // ADR 0021: no RSA private keys (RSA-PSS private included).
        (
            &|f| f.starts_with("reject-rsa") && f.contains("-private-") || f.contains("testRSA"),
            "UnsupportedAlgorithm",
        ),
        // RFC 5958 §3 and RFC 1421 encryption: out of scope.
        (&|f| f.contains("-encrypted"), "UnsupportedAlgorithm"),
        // ADR 0006: no Ed448/X448.
        (
            &|f| f.starts_with("reject-ed448-") || f.starts_with("reject-x448-"),
            "UnsupportedAlgorithm",
        ),
        // Not a JOSE curve.
        (
            &|f| f.starts_with("reject-ec-brainpoolp256r1-"),
            "UnsupportedAlgorithm",
        ),
        // specifiedCurve (RFC 5480 §2.1.1 requires namedCurve).
        (
            &|f| f.starts_with("reject-ec-p256-explicit-"),
            "UnsupportedAlgorithm",
        ),
        // id-RSASSA-PSS key OID (RFC 4055).
        (
            &|f| f == "reject-rsapss2048-spki.pem",
            "UnsupportedAlgorithm",
        ),
        // Under 2048 bits (RFC 7518 §3.3, §4.2; ADR 0007).
        (&|f| f.starts_with("reject-rsa1024-"), "InvalidKey"),
        // RFC 7468 §2: exactly five dashes (RFC 8410 §7, erratum 5459).
        (&|f| f == "reject-rfc8410-7-six-dash-end.pem", "InvalidKey"),
        // CERTIFICATE is not a key label (ADR 0006).
        (&|f| f.contains("-cert"), "UnsupportedAlgorithm"),
    ];
    rules
        .iter()
        .find(|(matches, _)| matches(file))
        .map(|(_, code)| *code)
        .unwrap_or_else(|| panic!("{file}: no row in the fixtures README table"))
}

#[test]
fn every_reject_fixture_gives_its_readme_code() {
    let mut checked = 0;
    let mut failures = Vec::new();
    for dir in ["openssl", "rfc"] {
        for file in files(dir).into_iter().filter(|f| f.starts_with("reject-")) {
            let result = import(&read(dir, &file), &file, named_format(&file));
            let want = readme_expect(&file);
            if code(&result) != want {
                failures.push(format!(
                    "{dir}/{file}: expected {want}, got {}",
                    code(&result)
                ));
            }
            checked += 1;
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    // 28 OpenSSL reject files and 5 RFC ones.
    assert_eq!(checked, 33);
}

#[test]
fn encrypted_keys_are_unsupported_with_a_static_error() {
    // Encrypted keys are out of scope (ADR 0018 §4): EncryptedPrivateKeyInfo
    // (RFC 5958 §3) as PEM (RFC 7468 §11) and DER, and legacy RFC 1421
    // `Proc-Type: 4,ENCRYPTED` PEM. `Error::UnsupportedAlgorithm` carries no
    // detail, so nothing derived from the input can reach its message.
    let pem = [
        "reject-ec-p256-pkcs8-encrypted.pem",
        "reject-ed25519-pkcs8-encrypted.pem",
        "reject-rsa2048-pkcs8-encrypted.pem",
        "reject-ec-p256-sec1-legacy-encrypted.pem",
        "reject-rsa2048-pkcs1-legacy-encrypted.pem",
    ];
    for file in pem {
        let text = String::from_utf8(read("openssl", file)).unwrap();
        let err = Jwk::from_pem(&text).unwrap_err();
        assert_eq!(err, Error::UnsupportedAlgorithm, "{file}");
        assert_eq!(err.to_string(), "unsupported algorithm", "{file}");
    }
    let der = read("openssl", "reject-ec-p256-pkcs8-encrypted.der");
    assert_eq!(
        Jwk::from_der(&der, KeyFormat::Pkcs8).unwrap_err(),
        Error::UnsupportedAlgorithm
    );
}

#[test]
fn der_in_another_format_than_named_is_never_imported() {
    // No sniffing (ADR 0007): the caller's format is the only one tried, so
    // every positive DER fixture fails in each of the other formats.
    for dir in ["openssl", "rfc"] {
        for file in files(dir)
            .into_iter()
            .filter(|f| f.ends_with(".der") && !f.starts_with("reject-"))
        {
            let der = read(dir, &file);
            let own = named_format(&file).unwrap();
            for format in FORMATS.into_iter().filter(|f| *f != own) {
                let result = Jwk::from_der(&der, format);
                // An SPKI starts SEQUENCE { SEQUENCE { … } }, the shape of an
                // EncryptedPrivateKeyInfo (RFC 5958 §3), which pkcs8::decode
                // refuses as unsupported before reading further. Every other
                // mismatch is malformed for the named structure.
                let want_unsupported = own == KeyFormat::Spki && format == KeyFormat::Pkcs8;
                let ok = if want_unsupported {
                    result.as_ref().err() == Some(&Error::UnsupportedAlgorithm)
                } else {
                    matches!(result, Err(Error::InvalidKey(_)))
                };
                assert!(ok, "{dir}/{file} as {format:?}: {:?}", result.err());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The export format matrix (plan.md, ADR 0018 §3)
// ---------------------------------------------------------------------------

fn pem_key(dir: &str, file: &str) -> Jwk {
    Jwk::from_pem(std::str::from_utf8(&read(dir, file)).unwrap()).unwrap()
}

fn assert_export(jwk: &Jwk, format: KeyFormat, want: &Error, what: &str) {
    assert_eq!(
        jwk.to_der(format).unwrap_err(),
        *want,
        "{what} to_der {format:?}"
    );
    assert_eq!(
        jwk.to_pem(format).unwrap_err(),
        *want,
        "{what} to_pem {format:?}"
    );
}

#[test]
fn oct_keys_never_export() {
    for bytes in [16, 32, 64, 512] {
        let oct = generate(KeySpec::Oct { bytes }).unwrap();
        for format in FORMATS {
            assert_export(&oct, format, &Error::UnsupportedAlgorithm, "oct");
        }
    }
}

#[test]
fn public_keys_do_not_export_to_private_formats() {
    let required = Error::InvalidKey("private key required");
    let ec = pem_key("openssl", "ec-p256-spki.pem");
    let okp = pem_key("openssl", "ed25519-spki.pem");
    let rsa = pem_key("openssl", "rsa2048-spki.pem");
    assert_export(&ec, KeyFormat::Pkcs8, &required, "EC public");
    assert_export(&ec, KeyFormat::Sec1, &required, "EC public");
    assert_export(&okp, KeyFormat::Pkcs8, &required, "OKP public");
    assert_export(&rsa, KeyFormat::Pkcs8, &required, "RSA");
    // The private key's own public half is refused the same way.
    let public = pem_key("openssl", "ec-p384-pkcs8.pem").to_public().unwrap();
    assert_export(&public, KeyFormat::Sec1, &required, "to_public");
}

#[test]
fn key_types_a_format_cannot_hold_are_unsupported() {
    let unsupported = Error::UnsupportedAlgorithm;
    let keys = [
        ("Ed25519 private", pem_key("openssl", "ed25519-pkcs8.pem")),
        ("X25519 public", pem_key("openssl", "x25519-spki.pem")),
        ("RSA", pem_key("openssl", "rsa2048-pkcs1-pub.pem")),
    ];
    // SEC1 holds only EC keys (RFC 5915 §3), checked before privateness.
    for (what, key) in &keys {
        assert_export(key, KeyFormat::Sec1, &unsupported, what);
    }
    // PKCS#1 holds only RSA keys (RFC 8017 App. A.1).
    for (what, key) in [
        ("EC private", pem_key("openssl", "ec-p521-sec1.pem")),
        ("EC public", pem_key("openssl", "ec-secp256k1-spki.pem")),
        ("Ed25519 private", pem_key("openssl", "ed25519-pkcs8.pem")),
        ("X25519 public", pem_key("openssl", "x25519-spki.pem")),
    ] {
        assert_export(&key, KeyFormat::Pkcs1, &unsupported, what);
    }
}
