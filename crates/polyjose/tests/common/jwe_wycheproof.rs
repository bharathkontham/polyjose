//! A minimal reader for the vendored Wycheproof `json_web_encryption_test.json`
//! (C2SP/wycheproof `d17cc89f`, Apache-2.0; see
//! `tests/third_party/wycheproof/README.md`), for integration tests.
//!
//! The in-crate loader (`src/test_support/wycheproof.rs`) is test-only and
//! invisible to `tests/`, so a JWE integration test (0003 T16,
//! `tests/jwe_wycheproof.rs`) reads the file through this module instead.
//! Like the loader, [`load`] checks the file's size and SHA-256 against the
//! README row before parsing, and rejects members outside the schema, so a
//! test never runs on altered data.
//!
//! The file is untrusted input: it is parsed, never executed.

use std::collections::BTreeSet;

use serde::Deserialize;
use serde::de::IgnoredAny;
use sha2::{Digest, Sha256};

/// The vendored file.
const FILE: &str = "json_web_encryption_test.json";
/// The vendored directory.
const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/third_party/wycheproof");

/// The parsed file.
pub struct Suite {
    /// The test groups, in file order.
    pub groups: Vec<Group>,
}

impl Suite {
    /// Every test with its group, in file order.
    pub fn tests(&self) -> impl Iterator<Item = (&Group, &Test)> {
        self.groups
            .iter()
            .flat_map(|group| group.tests.iter().map(move |test| (group, test)))
    }
}

/// One group: one key and its tests.
pub struct Group {
    /// Upstream's topic, e.g. `"jwe_aes"`, `"rfc_7520"`, `"jwe_rsa1_5"`.
    pub comment: String,
    /// The decryption key (`private`), as JWK JSON text.
    pub private: String,
    /// The encryption key (`public`), as JWK JSON text, for asymmetric keys.
    pub public: Option<String>,
    /// The tests, in file order.
    pub tests: Vec<Test>,
}

/// One test case.
pub struct Test {
    /// `tcId`, unique within the file.
    pub tc_id: u32,
    /// Upstream's comment.
    pub comment: String,
    /// Upstream's flags.
    pub flags: Vec<String>,
    /// The JWE: compact, JSON or malformed text.
    pub jwe: String,
    /// The expected plaintext, hex-decoded (every `valid` test has one).
    pub pt: Option<Vec<u8>>,
    /// The `enc` the test names.
    pub enc: String,
    /// The expected result.
    pub result: Expected,
}

/// A test's expected result (`result`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Expected {
    /// Must decrypt to `pt`.
    Valid,
    /// Must be rejected.
    Invalid,
    /// Either outcome is allowed (upstream `doc/files.md`).
    Acceptable,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawSuite {
    schema: String,
    number_of_tests: usize,
    #[serde(rename = "header")]
    _header: IgnoredAny,
    #[serde(rename = "notes")]
    _notes: IgnoredAny,
    test_groups: Vec<RawGroup>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGroup {
    #[serde(rename = "type")]
    group_type: String,
    #[serde(rename = "source")]
    _source: IgnoredAny,
    comment: String,
    private: serde_json::Value,
    public: Option<serde_json::Value>,
    tests: Vec<RawTest>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawTest {
    tc_id: u32,
    comment: String,
    flags: Vec<String>,
    jwe: String,
    pt: Option<String>,
    enc: String,
    result: Expected,
}

/// Lowercase hex of `bytes`.
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decodes hex (either case, even length).
fn hex(text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("not hex: {text:?}"));
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

/// A JWK member as JSON text.
fn jwk_text(value: &serde_json::Value) -> Result<String, String> {
    if !value.is_object() {
        return Err("a JWK must be a JSON object".to_owned());
    }
    serde_json::to_string(value).map_err(|e| e.to_string())
}

/// The `(bytes, sha256)` README row for [`FILE`].
fn readme_row() -> Result<(usize, String), String> {
    let path = format!("{DIR}/README.md");
    let readme = std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
    let prefix = format!("| `{FILE}` |");
    let line = readme
        .lines()
        .find(|l| l.starts_with(&prefix))
        .ok_or_else(|| format!("{FILE} is not in the README checksum table"))?;
    let cells: Vec<&str> = line
        .trim_matches('|')
        .split('|')
        .map(|c| c.trim().trim_matches('`'))
        .collect();
    let [_, size, sha256] = cells[..] else {
        return Err(format!("bad README row: {line}"));
    };
    let size = size.parse().map_err(|_| format!("bad size: {line}"))?;
    Ok((size, sha256.to_owned()))
}

fn parse(bytes: &[u8]) -> Result<Suite, String> {
    let (size, sha256) = readme_row()?;
    if bytes.len() != size {
        return Err(format!("{FILE}: {} bytes, README says {size}", bytes.len()));
    }
    let actual = to_hex(&Sha256::digest(bytes));
    if actual != sha256 {
        return Err(format!("{FILE}: SHA-256 {actual}, README says {sha256}"));
    }
    let raw: RawSuite = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    if raw.schema != "json_web_encryption_schema_v1.json" {
        return Err(format!("unexpected schema {:?}", raw.schema));
    }
    let mut ids = BTreeSet::new();
    let mut groups = Vec::with_capacity(raw.test_groups.len());
    for g in raw.test_groups {
        if g.group_type != "JsonWebEncryption" {
            return Err(format!("unexpected group type {:?}", g.group_type));
        }
        let mut tests = Vec::with_capacity(g.tests.len());
        for t in g.tests {
            if !ids.insert(t.tc_id) {
                return Err(format!("duplicate tcId {}", t.tc_id));
            }
            tests.push(Test {
                tc_id: t.tc_id,
                comment: t.comment,
                flags: t.flags,
                jwe: t.jwe,
                pt: t.pt.as_deref().map(hex).transpose()?,
                enc: t.enc,
                result: t.result,
            });
        }
        groups.push(Group {
            comment: g.comment,
            private: jwk_text(&g.private)?,
            public: g.public.as_ref().map(jwk_text).transpose()?,
            tests,
        });
    }
    if ids.len() != raw.number_of_tests {
        return Err(format!(
            "{} tests, numberOfTests says {}",
            ids.len(),
            raw.number_of_tests
        ));
    }
    Ok(Suite { groups })
}

/// Loads and checks the vendored file. Panics, naming the problem, if it
/// does not match its README row or its schema.
pub fn load() -> Suite {
    let path = format!("{DIR}/{FILE}");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
    parse(&bytes).unwrap_or_else(|e| panic!("{e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_web_encryption_loads_with_its_counts() {
        let suite = load();
        assert_eq!(suite.groups.len(), 31);
        assert_eq!(suite.tests().count(), 139);
        let count = |e: Expected| suite.tests().filter(|(_, t)| t.result == e).count();
        assert_eq!((count(Expected::Valid), count(Expected::Invalid)), (65, 74));
        assert!(
            suite
                .tests()
                .all(|(_, t)| t.result != Expected::Valid || t.pt.is_some())
        );
        assert_eq!(
            suite.groups.iter().filter(|g| g.public.is_some()).count(),
            11
        );
        assert!(suite.tests().all(|(_, t)| !t.enc.is_empty() && t.tc_id > 0));
        assert!(suite.tests().any(|(_, t)| !t.flags.is_empty()));
        assert!(suite.tests().any(|(_, t)| !t.comment.is_empty()));
        assert!(suite.groups.iter().any(|g| g.comment == "rfc_7520"));
        let (_, first) = suite.tests().next().unwrap_or_else(|| panic!("no tests"));
        assert_eq!(first.pt.as_deref(), Some(&b"foo"[..]));
        assert!(first.jwe.starts_with("eyJ"));
    }

    #[test]
    fn a_changed_byte_is_rejected() {
        let path = format!("{DIR}/{FILE}");
        let mut bytes = std::fs::read(&path).unwrap_or_default();
        let middle = bytes.len() / 2;
        bytes[middle] ^= 0x01;
        assert!(parse(&bytes).is_err_and(|e| e.contains("SHA-256")));
        assert_eq!(hex("0g"), Err("not hex: \"0g\"".to_owned()));
        assert_eq!(hex("00Ff"), Ok(vec![0x00, 0xff]));
    }
}
