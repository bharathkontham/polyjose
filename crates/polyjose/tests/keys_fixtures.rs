//! Integrity of the committed key fixtures in `tests/data/keys/`.
//!
//! The PEM/DER fixtures are interop data: OpenSSL 4.1.0 keys, RFC golden
//! pairs (RFC 7468, 7517, 8037, 8410, 9500) and byte-level negative vectors
//! (see `tests/data/keys/regen/README.md`). Regenerating them produces new
//! random keys, so they are committed and pinned instead: each data
//! directory's `SHA256SUMS` (FIPS 180-4 SHA-256, in `shasum -a 256` format)
//! lists every key file, and this test fails if any byte changes, if a key
//! file is added without being pinned, or if a pinned file disappears.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use polyjose::json::{self, Value};
use sha2::{Digest, Sha256};

/// The fixture directories, each with its own `SHA256SUMS`.
const DIRS: [&str; 3] = ["openssl", "rfc", "negative"];

fn data_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/keys")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parses a `SHA256SUMS` file strictly: one `<64 lowercase hex>  <name>`
/// line per file (text mode, two spaces), no blank lines, no duplicates, a
/// plain file name (no directory part), and a final newline.
fn read_sums(dir: &Path) -> Vec<(String, String)> {
    let path = dir.join("SHA256SUMS");
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    assert!(text.ends_with('\n'), "{}: no final newline", path.display());
    let mut seen = BTreeSet::new();
    let mut sums = Vec::new();
    for (number, line) in text.lines().enumerate() {
        let (digest, name) = line
            .split_once("  ")
            .unwrap_or_else(|| panic!("{}:{}: not `<digest>  <name>`", path.display(), number + 1));
        assert!(
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "{}:{}: digest is not 64 lowercase hex digits",
            path.display(),
            number + 1
        );
        assert!(
            !name.is_empty() && !name.contains('/') && !name.starts_with(['*', ' ']),
            "{}:{}: bad file name {name:?}",
            path.display(),
            number + 1
        );
        assert!(
            seen.insert(name.to_owned()),
            "{}: {name} is listed twice",
            path.display()
        );
        sums.push((digest.to_owned(), name.to_owned()));
    }
    assert!(!sums.is_empty(), "{}: empty", path.display());
    sums
}

/// Files (not directories) directly in `dir`.
fn files_in(dir: &Path) -> BTreeSet<String> {
    fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|entry| entry.expect("readable directory entry"))
        .filter(|entry| entry.file_type().expect("file type").is_file())
        .map(|entry| entry.file_name().into_string().expect("UTF-8 file name"))
        .collect()
}

/// Whether `name` must be pinned: every key encoding, plus the negative
/// vectors' manifest, which says what each vector must fail with.
fn must_be_pinned(dir: &str, name: &str) -> bool {
    is_key_file(name) || (dir == "negative" && name == "manifest.json")
}

/// A PEM or DER key encoding.
fn is_key_file(name: &str) -> bool {
    name.ends_with(".pem") || name.ends_with(".der")
}

/// The files a directory may hold without pinning them: expectations and
/// provenance derived from the pinned keys (README "Regenerate"). A wrong
/// expected JWK fails the test that compares against it.
fn may_be_unpinned(dir: &str, name: &str) -> bool {
    name == "SHA256SUMS"
        || (dir == "rfc" && name.ends_with(".jwk.json"))
        || (dir == "openssl" && name == "OPENSSL_VERSION")
}

#[test]
fn every_pinned_fixture_matches_its_sha256() {
    for dir in DIRS {
        let path = data_dir().join(dir);
        for (digest, name) in read_sums(&path) {
            let file = path.join(&name);
            let bytes = fs::read(&file).unwrap_or_else(|e| panic!("{}: {e}", file.display()));
            assert_eq!(
                hex(&Sha256::digest(&bytes)),
                digest,
                "{dir}/{name} differs from its SHA256SUMS entry; fixtures are never edited in place"
            );
        }
    }
}

#[test]
fn every_key_file_is_pinned_and_nothing_else_is_unaccounted_for() {
    for dir in DIRS {
        let path = data_dir().join(dir);
        let pinned: BTreeSet<String> = read_sums(&path).into_iter().map(|(_, name)| name).collect();
        for name in files_in(&path) {
            if pinned.contains(&name) {
                assert!(
                    must_be_pinned(dir, &name),
                    "{dir}/{name} is pinned but is not a key file"
                );
            } else {
                assert!(
                    !must_be_pinned(dir, &name),
                    "{dir}/{name} is a key file missing from {dir}/SHA256SUMS"
                );
                assert!(
                    may_be_unpinned(dir, &name),
                    "{dir}/{name} is neither pinned nor a known derived file"
                );
            }
        }
    }
}

#[test]
fn openssl_subdirectories_hold_only_derived_files() {
    // `openssl/expected/*.jwk.json` (expected-jwks.py) and `openssl/text/*.txt`
    // (`openssl pkey -text` dumps) are derived from pinned files of the same
    // stem.
    let openssl = data_dir().join("openssl");
    let pinned: BTreeSet<String> = read_sums(&openssl)
        .into_iter()
        .map(|(_, name)| name)
        .collect();
    for (sub, suffix) in [("expected", ".jwk.json"), ("text", ".txt")] {
        let names = files_in(&openssl.join(sub));
        assert!(!names.is_empty(), "openssl/{sub} is empty");
        for name in names {
            let stem = name
                .strip_suffix(suffix)
                .unwrap_or_else(|| panic!("openssl/{sub}/{name}: expected a {suffix} file"));
            assert!(
                pinned.contains(&format!("{stem}.pem")),
                "openssl/{sub}/{name} has no pinned {stem}.pem"
            );
        }
    }
}

#[test]
fn negative_manifest_lists_exactly_the_vectors() {
    let negative = data_dir().join("negative");
    let manifest = json::parse(&fs::read(negative.join("manifest.json")).expect("manifest.json"))
        .expect("manifest.json is I-JSON");
    let rows = manifest.as_array().expect("manifest.json is an array");
    let mut listed = BTreeSet::new();
    for row in rows {
        let field = |name: &str| {
            row.get(name)
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("manifest row without string {name:?}"))
                .to_owned()
        };
        let (id, file, expect) = (field("id"), field("file"), field("expect"));
        assert!(
            file.starts_with(&format!("{id}-")),
            "{file} does not start with {id}-"
        );
        assert!(
            ["InvalidKey", "UnsupportedAlgorithm", "ok"].contains(&expect.as_str()),
            "{id}: unknown expectation {expect}"
        );
        assert!(
            !field("cite").is_empty() && !field("mutation").is_empty(),
            "{id}: no rule"
        );
        assert!(listed.insert(file), "{id} is listed twice");
    }
    let vectors: BTreeSet<String> = files_in(&negative)
        .into_iter()
        .filter(|n| is_key_file(n))
        .collect();
    assert_eq!(
        listed, vectors,
        "manifest.json and the vector files disagree"
    );
}
