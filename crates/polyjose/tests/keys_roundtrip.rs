//! End-to-end round trips of the PEM/DER facade (`Jwk::from_pem`,
//! `from_der`, `to_pem`, `to_der`; ADR 0018 §3) over every positive key
//! fixture in `tests/data/keys/openssl` and `tests/data/keys/rfc`.
//!
//! - **Import:** PEM → JWK and DER → JWK equal the committed `.jwk.json`
//!   member by member. The expected JWKs come from OpenSSL's own text dump
//!   (`openssl/expected/`) or from the RFCs (`rfc/`), never from polyjose.
//! - **Export:** JWK → PEM (DER) in the same format is byte-identical to the
//!   input (ADR 0018 §3: polyjose writes OpenSSL 4's layout), except for the
//!   three documented forms polyjose reads but never writes:
//!   - `*-sec1-nopub` (SEC1 without `[1]`, RFC 5915 §3) → the `*-sec1` file;
//!   - `*-spki-compressed` (RFC 5480 §2.2) → the `*-spki` file;
//!   - RFC 8410 §10.3 v2 (attribute and publicKey) → the §10.3 v1 file.
//! - **JWK → PEM → JWK** is the identity for every expected JWK in every
//!   format the matrix allows for it; SPKI of a private key gives its public
//!   half (`Jwk::to_public`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

use std::path::{Path, PathBuf};

use polyjose::json::{self, Value};
use polyjose::jwk::{Jwk, KeyMaterial};
use polyjose::keys::KeyFormat;
use zeroize::Zeroizing;

fn data_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/keys")
}

fn read(dir: &str, file: &str) -> Vec<u8> {
    let path = data_dir().join(dir).join(file);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn read_text(dir: &str, file: &str) -> String {
    String::from_utf8(read(dir, file)).unwrap()
}

/// The DER of a fixture: a `.der` file as it is; a `.pem` file decoded by
/// the `pem-rfc7468` oracle (a dev-dependency), not by polyjose.
fn der_of(dir: &str, file: &str) -> Vec<u8> {
    let bytes = read(dir, file);
    if file.ends_with(".pem") {
        pem_rfc7468::decode_vec(&bytes)
            .unwrap_or_else(|e| panic!("{file}: {e}"))
            .1
    } else {
        bytes
    }
}

/// Every positive (`reject-*` excluded) PEM and DER fixture of `dir`.
fn positives(dir: &str) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(data_dir().join(dir))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| (n.ends_with(".pem") || n.ends_with(".der")) && !n.starts_with("reject-"))
        .collect();
    names.sort();
    names
}

/// The file name without `.pem`/`.der`.
fn stem(file: &str) -> &str {
    file.strip_suffix(".pem")
        .or_else(|| file.strip_suffix(".der"))
        .unwrap()
}

/// The format a fixture's name says it holds.
fn format_of(file: &str) -> KeyFormat {
    if file.contains("-pkcs8") {
        KeyFormat::Pkcs8
    } else if file.contains("-sec1") {
        KeyFormat::Sec1
    } else if file.contains("-spki") {
        KeyFormat::Spki
    } else if file.contains("-pkcs1") {
        KeyFormat::Pkcs1
    } else {
        panic!("{file}: no format in the name")
    }
}

/// The expected JWK file of a positive fixture. A compressed SPKI point
/// is the same key as the uncompressed one, whose JWK it shares.
fn expected_jwk_file(dir: &str, file: &str) -> (String, String) {
    let stem = stem(file).replace("-spki-compressed", "-spki");
    match dir {
        "openssl" => ("openssl/expected".to_owned(), format!("{stem}.jwk.json")),
        _ => (dir.to_owned(), format!("{stem}.jwk.json")),
    }
}

fn expected_object(dir: &str, file: &str) -> Value {
    let (dir, name) = expected_jwk_file(dir, file);
    json::parse(&read(&dir, &name)).unwrap_or_else(|e| panic!("{name}: {e:?}"))
}

/// The fixture a re-export of `file` must equal: itself, or one of the
/// three documented canonical forms.
fn canonical_file(dir: &str, file: &str) -> String {
    let ext = &file[file.len() - 4..];
    let stem = stem(file);
    let canonical = if let Some(prefix) = stem.strip_suffix("-sec1-nopub") {
        format!("{prefix}-sec1")
    } else if let Some(prefix) = stem.strip_suffix("-spki-compressed") {
        format!("{prefix}-spki")
    } else if stem == "rfc8410-10.3-ed25519-pkcs8-v2-attr-pub" {
        "rfc8410-10.3-ed25519-pkcs8-v1".to_owned()
    } else {
        stem.to_owned()
    };
    let with_ext = format!("{canonical}{ext}");
    // The canonical file exists in the same encoding, or as PEM only.
    if data_dir().join(dir).join(&with_ext).exists() {
        with_ext
    } else {
        format!("{canonical}.pem")
    }
}

fn assert_jwk_eq(got: &Jwk, want: &Value, what: &str) {
    assert_eq!(
        Value::from(got.to_object()),
        *want,
        "{what}: JWK members differ"
    );
}

/// Every positive fixture, as `(dir, file)`.
fn all_positives() -> Vec<(&'static str, String)> {
    let mut all = Vec::new();
    for dir in ["openssl", "rfc"] {
        all.extend(positives(dir).into_iter().map(|f| (dir, f)));
    }
    all
}

#[test]
fn the_fixture_set_covers_every_key_type_and_format() {
    let all = all_positives();
    let has = |needle: &str| all.iter().any(|(_, f)| f.contains(needle));
    for curve in ["ec-p256", "ec-p384", "ec-p521", "ec-secp256k1"] {
        for format in ["-pkcs8", "-sec1", "-spki"] {
            assert!(has(&format!("{curve}{format}")), "{curve}{format}");
        }
    }
    for okp in ["ed25519", "x25519"] {
        for format in ["-pkcs8", "-spki"] {
            assert!(has(&format!("{okp}{format}")), "{okp}{format}");
        }
    }
    assert!(has("rsa2048-spki") && has("rsa2048-pkcs1-pub"));
    // 25 OpenSSL PEM files plus their DER twins, and the RFC golden files.
    assert!(all.len() > 60, "{} positive fixtures", all.len());
}

#[test]
fn pem_imports_to_the_expected_jwk_and_exports_byte_identically() {
    let mut checked = 0;
    for (dir, file) in all_positives() {
        if !file.ends_with(".pem") {
            continue;
        }
        let pem = read_text(dir, &file);
        let jwk = Jwk::from_pem(&pem).unwrap_or_else(|e| panic!("{dir}/{file}: {e:?}"));
        assert_jwk_eq(&jwk, &expected_object(dir, &file), &file);
        assert!(jwk.alg().is_none(), "{file}: PEM carries no alg");

        let want = read_text(dir, &canonical_file(dir, &file));
        let out: Zeroizing<String> = jwk.to_pem(format_of(&file)).unwrap();
        assert_eq!(*out, want, "{dir}/{file}: PEM re-export");
        checked += 1;
    }
    assert!(checked >= 40, "{checked} PEM fixtures");
}

#[test]
fn der_imports_to_the_expected_jwk_and_exports_byte_identically() {
    let mut checked = 0;
    for (dir, file) in all_positives() {
        let der = der_of(dir, &file);
        let format = format_of(&file);
        let jwk = Jwk::from_der(&der, format).unwrap_or_else(|e| panic!("{dir}/{file}: {e:?}"));
        assert_jwk_eq(&jwk, &expected_object(dir, &file), &file);

        let want = der_of(dir, &canonical_file(dir, &file));
        let out: Zeroizing<Vec<u8>> = jwk.to_der(format).unwrap();
        assert_eq!(*out, want, "{dir}/{file}: DER re-export");
        checked += 1;
    }
    assert!(checked > 60, "{checked} DER fixtures");
}

#[test]
fn committed_der_and_pem_twins_agree() {
    // Where a fixture exists in both encodings, the PEM body is the DER
    // file (checked with the oracle), so both entry points see one key.
    for (dir, file) in all_positives() {
        let Some(stem) = file.strip_suffix(".der") else {
            continue;
        };
        let pem = format!("{stem}.pem");
        assert_eq!(der_of(dir, &file), der_of(dir, &pem), "{dir}/{file}");
        let a = Jwk::from_der(&read(dir, &file), format_of(&file)).unwrap();
        let b = Jwk::from_pem(&read_text(dir, &pem)).unwrap();
        assert_eq!(a.to_object(), b.to_object(), "{dir}/{file}");
    }
}

#[test]
fn only_the_documented_forms_re_export_differently() {
    let mut differing: Vec<String> = all_positives()
        .into_iter()
        .filter(|(dir, file)| canonical_file(dir, file) != *file)
        .map(|(dir, file)| format!("{dir}/{file}"))
        .collect();
    differing.sort();
    let mut want = vec!["rfc/rfc8410-10.3-ed25519-pkcs8-v2-attr-pub.pem".to_owned()];
    for curve in ["p256", "p384", "p521", "secp256k1"] {
        want.push(format!("openssl/ec-{curve}-sec1-nopub.pem"));
        want.push(format!("openssl/ec-{curve}-spki-compressed.pem"));
    }
    want.sort();
    assert_eq!(differing, want);
}

/// The formats the matrix (ADR 0018 §3) allows for a key, and whether each
/// keeps the private part.
fn allowed_formats(jwk: &Jwk) -> Vec<(KeyFormat, bool)> {
    let private = !jwk.is_public();
    match jwk.material() {
        KeyMaterial::Ec(_) if private => vec![
            (KeyFormat::Pkcs8, true),
            (KeyFormat::Sec1, true),
            (KeyFormat::Spki, false),
        ],
        KeyMaterial::Okp(_) if private => vec![(KeyFormat::Pkcs8, true), (KeyFormat::Spki, false)],
        KeyMaterial::Ec(_) | KeyMaterial::Okp(_) => vec![(KeyFormat::Spki, false)],
        // PKCS#1 export is the RSAPublicKey of a public key only (RFC 8017
        // App. A.1.1); a private key is InvalidKey (feature 0020 review).
        KeyMaterial::Rsa(_) if private => vec![(KeyFormat::Pkcs8, true), (KeyFormat::Spki, false)],
        KeyMaterial::Rsa(_) => vec![(KeyFormat::Spki, false), (KeyFormat::Pkcs1, false)],
        other => panic!("no PEM/DER form for {:?}", other.key_type()),
    }
}

/// Every expected `.jwk.json`, as `(name, jwk)`.
fn expected_jwks() -> Vec<(String, Jwk)> {
    let mut out = Vec::new();
    for dir in ["openssl/expected", "rfc"] {
        let mut names: Vec<String> = std::fs::read_dir(data_dir().join(dir))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.ends_with(".jwk.json"))
            .collect();
        names.sort();
        for name in names {
            let jwk = Jwk::from_json(&read(dir, &name)).unwrap_or_else(|e| panic!("{name}: {e:?}"));
            out.push((format!("{dir}/{name}"), jwk));
        }
    }
    out
}

#[test]
fn jwk_to_pem_to_jwk_is_the_identity_in_every_allowed_format() {
    let jwks = expected_jwks();
    assert!(jwks.len() >= 40, "{} expected JWKs", jwks.len());
    for (name, jwk) in jwks {
        for (format, keeps_private) in allowed_formats(&jwk) {
            let want = if keeps_private {
                jwk.to_object()
            } else {
                jwk.to_public().unwrap().to_object()
            };
            let pem = jwk.to_pem(format).unwrap();
            let back = Jwk::from_pem(&pem).unwrap_or_else(|e| panic!("{name} {format:?}: {e:?}"));
            assert_eq!(back.to_object(), want, "{name} {format:?} via PEM");

            let der = jwk.to_der(format).unwrap();
            let back = Jwk::from_der(&der, format).unwrap();
            assert_eq!(back.to_object(), want, "{name} {format:?} via DER");
            // The PEM body is exactly the DER (RFC 7468 §2).
            let (_, body) = pem_rfc7468::decode_vec(pem.as_bytes()).unwrap();
            assert_eq!(body, *der, "{name} {format:?}");
        }
    }
}

#[test]
fn to_pem_writes_the_format_label_and_strict_layout() {
    let jwks = expected_jwks();
    for (name, jwk) in &jwks {
        for (format, _) in allowed_formats(jwk) {
            let pem = jwk.to_pem(format).unwrap();
            let label = match format {
                KeyFormat::Pkcs8 => "PRIVATE KEY",
                KeyFormat::Sec1 => "EC PRIVATE KEY",
                KeyFormat::Spki => "PUBLIC KEY",
                KeyFormat::Pkcs1 => "RSA PUBLIC KEY",
                _ => unreachable!(),
            };
            assert!(
                pem.starts_with(&format!("-----BEGIN {label}-----\n")),
                "{name}"
            );
            assert!(pem.ends_with(&format!("-----END {label}-----\n")), "{name}");
            let lines: Vec<&str> = pem.lines().collect();
            let body = &lines[1..lines.len() - 1];
            for line in &body[..body.len() - 1] {
                assert_eq!(line.len(), 64, "{name}");
            }
            assert!(!body.last().unwrap().is_empty() && body.last().unwrap().len() <= 64);
            assert!(!pem.contains('\r'), "{name}: LF line endings");
        }
    }
}

#[test]
fn export_drops_jwk_metadata_and_import_sets_none() {
    // RFC 7517 App. A.1's EC key with its kid and use: neither has a place
    // in SPKI (RFC 5280 §4.1.2.7), so the round trip keeps the key only.
    let with_meta = Jwk::from_json(
        br#"{"kty":"EC","crv":"P-256",
        "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
        "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
        "use":"enc","kid":"1","alg":"ES256"}"#,
    )
    .unwrap();
    let back = Jwk::from_pem(&with_meta.to_pem(KeyFormat::Spki).unwrap()).unwrap();
    assert_eq!(back.kid(), None);
    assert_eq!(back.key_use(), None);
    assert_eq!(back.alg(), None);
    assert_eq!(
        back.to_object(),
        Jwk::from_json(&read("rfc", "rfc7517-a1-ec-p256-spki.jwk.json"))
            .unwrap()
            .to_object()
    );
}
