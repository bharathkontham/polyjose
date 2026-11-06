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
//! - the export format matrix (plan.md, ADR 0018 §3);
//! - **no input ever yields an `oct` JWK** (RFC 8725 §2.1: the key-confusion
//!   class of CVE-2015-9235, CVE-2017-11424, CVE-2023-48223);
//! - no error's `Debug` or `Display` contains input bytes (ADR 0007,
//!   ADR 0018 §4).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

use std::path::{Path, PathBuf};

use polyjose::Error;
use polyjose::json::{self, Value};
use polyjose::jwk::{EcCurve, Jwk, KeyType, OkpCurve};
use polyjose::keys::{KeyFormat, KeySpec, generate};
use proptest::prelude::*;

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
/// and N69 `-sec1`, N50–N52, N67 and N68 `-pkcs8`, N65 `-pkcs1-`, N38
/// `-spki-`; `-pkcs8` and `-sec1` are looked for before `-pkcs1`),
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
    assert_eq!(rows.len(), 71, "68 must-reject and 3 must-accept vectors");
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
                // SPKI as PKCS#8 has its own test, below.
                if own == KeyFormat::Spki && format == KeyFormat::Pkcs8 {
                    continue;
                }
                let result = Jwk::from_der(&der, format);
                assert!(
                    matches!(result, Err(Error::InvalidKey(_))),
                    "{dir}/{file} as {format:?}: {:?}",
                    result.err()
                );
            }
        }
    }
}

/// SPKI DER passed as `KeyFormat::Pkcs8` is `InvalidKey`: an SPKI is
/// `SEQUENCE { AlgorithmIdentifier, BIT STRING }` (RFC 5280 §4.1.2.7), which
/// is malformed PKCS#8. Only the exact EncryptedPrivateKeyInfo shape,
/// `SEQUENCE { AlgorithmIdentifier, OCTET STRING }` (RFC 5958 §3), is
/// `UnsupportedAlgorithm` (ADR 0018 §4).
#[test]
fn spki_as_pkcs8_is_invalid_key() {
    let mut checked = 0;
    for dir in ["openssl", "rfc"] {
        for file in files(dir)
            .into_iter()
            .filter(|f| f.ends_with(".der") && !f.starts_with("reject-"))
            .filter(|f| named_format(f) == Some(KeyFormat::Spki))
        {
            let result = Jwk::from_der(&read(dir, &file), KeyFormat::Pkcs8);
            assert!(
                matches!(result, Err(Error::InvalidKey(_))),
                "{dir}/{file}: {:?}",
                result.err()
            );
            checked += 1;
        }
    }
    assert!(checked >= 10, "{checked} SPKI fixtures");
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

// ---------------------------------------------------------------------------
// No input ever yields an `oct` JWK (RFC 8725 §2.1, ADR 0018 §3)
// ---------------------------------------------------------------------------

/// Imports `input` every way the public API allows: as PEM text when it is
/// UTF-8, and as DER in each of the four formats. Returns every success.
fn every_import(input: &[u8]) -> Vec<Jwk> {
    let mut keys = Vec::new();
    if let Ok(text) = std::str::from_utf8(input) {
        keys.extend(Jwk::from_pem(text));
    }
    for format in FORMATS {
        keys.extend(Jwk::from_der(input, format));
    }
    keys
}

/// Every committed key fixture and negative vector, and the DER inside each
/// PEM file (decoded by the `pem-rfc7468` oracle where it can).
fn every_fixture_input() -> Vec<(String, Vec<u8>)> {
    let mut inputs = Vec::new();
    for dir in ["openssl", "rfc", "negative"] {
        for file in files(dir) {
            let bytes = read(dir, &file);
            if file.ends_with(".pem")
                && let Ok((_, der)) = pem_rfc7468::decode_vec(&bytes)
            {
                inputs.push((format!("{dir}/{file} (body)"), der));
            }
            inputs.push((format!("{dir}/{file}"), bytes));
        }
    }
    inputs
}

#[test]
fn no_fixture_or_negative_vector_ever_yields_an_oct_jwk() {
    let inputs = every_fixture_input();
    assert!(inputs.len() > 200, "{} inputs", inputs.len());
    let mut successes = 0;
    for (name, input) in &inputs {
        for jwk in every_import(input) {
            assert_ne!(jwk.key_type(), KeyType::Oct, "{name}");
            assert_ne!(
                jwk.to_object().get("kty").and_then(Value::as_str),
                Some("oct"),
                "{name}"
            );
            successes += 1;
        }
    }
    // The positive fixtures do import, so the check is not vacuous.
    assert!(successes > 100, "{successes} successful imports");
}

/// A positive DER fixture to mutate.
fn some_der() -> Vec<Vec<u8>> {
    ["openssl", "rfc"]
        .iter()
        .flat_map(|dir| {
            files(dir)
                .into_iter()
                .filter(|f| f.ends_with(".der") && !f.starts_with("reject-"))
                .map(|f| read(dir, &f))
        })
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    /// Arbitrary bytes never import as `oct`, and never panic.
    #[test]
    fn random_input_never_yields_an_oct_jwk(input in proptest::collection::vec(any::<u8>(), 0..512)) {
        for jwk in every_import(&input) {
            prop_assert_ne!(jwk.key_type(), KeyType::Oct);
        }
    }

    /// A valid key with one octet changed, or cut short, never imports as
    /// `oct`, and a changed key that still imports is EC, OKP or RSA.
    #[test]
    fn mutated_fixtures_never_yield_an_oct_jwk(
        which in any::<prop::sample::Index>(),
        at in any::<prop::sample::Index>(),
        xor in 1u8..=255,
        cut in any::<bool>(),
    ) {
        let all = some_der();
        let mut der = which.get(&all).clone();
        let i = at.index(der.len());
        if cut { der.truncate(i); } else { der[i] ^= xor; }
        for jwk in every_import(&der) {
            prop_assert_ne!(jwk.key_type(), KeyType::Oct);
        }
    }
}

// ---------------------------------------------------------------------------
// Error hygiene: no input bytes in Debug or Display (ADR 0007, ADR 0018 §4)
// ---------------------------------------------------------------------------

/// Renderings of `input` that would reveal it in a message: for every
/// 6-octet window, its lowercase and uppercase hex, its `Debug` list of
/// decimals, and its standard and URL-safe base64.
fn leaks(message: &str, input: &[u8]) -> Option<String> {
    for window in input.windows(6) {
        if window.iter().all(|b| *b == window[0]) {
            continue; // runs such as 00 00 00 … say nothing about the key
        }
        let hex: String = window.iter().map(|b| format!("{b:02x}")).collect();
        let decimal = format!("{window:?}");
        let decimal = &decimal[1..decimal.len() - 1];
        let b64 = std_b64(window);
        let b64url = b64.replace('+', "-").replace('/', "_");
        for needle in [
            hex.clone(),
            hex.to_uppercase(),
            decimal.to_owned(),
            b64,
            b64url,
        ] {
            if message.contains(&needle) {
                return Some(needle);
            }
        }
    }
    // Lines of a PEM body, which is base64 text already.
    if let Ok(text) = std::str::from_utf8(input) {
        for line in text
            .lines()
            .filter(|l| l.len() >= 8 && !l.starts_with("-----"))
        {
            for window in line.as_bytes().windows(8) {
                let needle = std::str::from_utf8(window).unwrap();
                if message.contains(needle) {
                    return Some(needle.to_owned());
                }
            }
        }
    }
    None
}

/// RFC 4648 §4 base64 of 6 octets (two whole quanta, so no padding).
fn std_b64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    bytes
        .chunks(3)
        .flat_map(|c| {
            let n = u32::from(c[0]) << 16 | u32::from(c[1]) << 8 | u32::from(c[2]);
            (0..4)
                .rev()
                .map(move |i| ALPHABET[(n >> (6 * i) & 63) as usize] as char)
        })
        .collect()
}

#[test]
fn the_leak_detector_finds_every_rendering() {
    let input = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05];
    for message in [
        "invalid key: 302e02010030",
        "invalid key: 302E02010030",
        "InvalidKey([48, 46, 2, 1, 0, 48])",
        "x MC4CAQAw y",
        "the last window 2e0201003005",
    ] {
        assert!(leaks(message, &input).is_some(), "{message}");
    }
    let url = [0xfb, 0xff, 0xbf, 0x01, 0x02, 0x03];
    assert!(leaks("+/+/AQID", &url).is_some());
    assert!(leaks("-_-_AQID", &url).is_some());
    let pem = b"-----BEGIN X-----\nMCowBQYDK2VwAyEAGb9ECWmEzf6FQbrB\n-----END X-----\n";
    assert!(leaks("in MCowBQYD body", pem).is_some());
    assert_eq!(leaks("invalid key: DER input too large", &input), None);
}

fn assert_no_leak(err: &Error, input: &[u8], what: &str) {
    for message in [format!("{err:?}"), format!("{err:#?}"), err.to_string()] {
        assert!(
            message.len() < 160,
            "{what}: suspiciously long message {message:?}"
        );
        if let Some(needle) = leaks(&message, input) {
            panic!("{what}: {message:?} contains input bytes ({needle})");
        }
    }
}

#[test]
fn no_error_over_the_negative_suite_contains_input_bytes() {
    let mut errors = 0;
    for (name, input) in every_fixture_input() {
        if let Ok(text) = std::str::from_utf8(&input)
            && let Err(e) = Jwk::from_pem(text)
        {
            assert_no_leak(&e, &input, &name);
            errors += 1;
        }
        for format in FORMATS {
            if let Err(e) = Jwk::from_der(&input, format) {
                assert_no_leak(&e, &input, &format!("{name} as {format:?}"));
                errors += 1;
            }
        }
    }
    assert!(errors > 500, "{errors} errors checked");
}

/// The marker 0xA5 (165, `pQ`/`pa`/`paWl` in base64) in the key octets.
const MARKER: u8 = 0xA5;

fn overwrite(mut der: Vec<u8>, from: usize, len: usize) -> Vec<u8> {
    der[from..from + len].fill(MARKER);
    der
}

fn find(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
        .unwrap()
}

#[test]
fn marker_key_octets_never_reach_an_error() {
    let spki = read("rfc", "rfc7517-a1-ec-p256-spki.der");
    let sec1 = read("rfc", "rfc7517-a2-ec-p256-sec1.der");
    let pkcs8 = read("rfc", "rfc8037-a1-ed25519-pkcs8.der");
    let rsa = read("rfc", "rfc7517-a1-rsa-spki.der");
    let n = find(&rsa, &[0x02, 0x82, 0x01, 0x01]) + 4;
    let cases = [
        // x and y off the curve.
        (
            KeyFormat::Spki,
            overwrite(spki.clone(), spki.len() - 64, 64),
        ),
        // d replaced: the [1] publicKey no longer matches (RFC 5915 §3).
        (KeyFormat::Sec1, overwrite(sec1, 7, 32)),
        // A 32-octet marker in a 31-octet-shortened CurvePrivateKey slot.
        (KeyFormat::Pkcs8, {
            let mut der = overwrite(pkcs8.clone(), pkcs8.len() - 32, 32);
            der.pop();
            der
        }),
        // A negative modulus (X.690 §8.3.3).
        (KeyFormat::Spki, overwrite(rsa, n, 257)),
    ];
    for (format, der) in cases {
        let err = Jwk::from_der(&der, format).unwrap_err();
        let pem = pem_rfc7468::encode_string(
            match format {
                KeyFormat::Sec1 => "EC PRIVATE KEY",
                KeyFormat::Pkcs8 => "PRIVATE KEY",
                _ => "PUBLIC KEY",
            },
            pem_rfc7468::LineEnding::LF,
            &der,
        )
        .unwrap();
        let pem_err = Jwk::from_pem(&pem).unwrap_err();
        for (err, input) in [(&err, der.as_slice()), (&pem_err, pem.as_bytes())] {
            for message in [format!("{err:?}"), err.to_string()] {
                for needle in ["165", "a5a5", "A5A5", "paWl", "pQ"] {
                    assert!(!message.contains(needle), "{message:?} has {needle}");
                }
            }
            assert_no_leak(err, input, &format!("{format:?} marker"));
        }
    }
}

#[test]
fn generated_private_keys_never_reach_an_error_on_export() {
    // A public-only format refusal reports a static detail, not the key.
    for spec in [KeySpec::Ec(EcCurve::P256), KeySpec::Okp(OkpCurve::X25519)] {
        let key = generate(spec).unwrap();
        let err = key.to_der(KeyFormat::Pkcs1).unwrap_err();
        let der = key.to_der(KeyFormat::Pkcs8).unwrap();
        assert_no_leak(&err, &der, "export");
    }
}
