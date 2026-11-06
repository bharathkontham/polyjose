//! Loader for the vendored Wycheproof vectors (ADR 0008 layer 1).
#![cfg(test)]

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::Deserialize;
use serde::de::IgnoredAny;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// The vendored directory, `tests/third_party/wycheproof`.
const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/third_party/wycheproof");

/// One row of the README's checksum table.
struct ManifestEntry {
    file: String,
    size: usize,
    sha256: String,
}

/// Parses the `| `file` | bytes | `sha256` |` rows of the vendored README.
fn manifest() -> Vec<ManifestEntry> {
    let path = format!("{DIR}/README.md");
    let readme =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
    parse_manifest(&readme).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn parse_manifest(readme: &str) -> Result<Vec<ManifestEntry>, String> {
    let mut entries: Vec<ManifestEntry> = Vec::new();
    for line in readme.lines().filter(|l| l.starts_with("| `")) {
        let cells: Vec<&str> = line
            .trim_matches('|')
            .split('|')
            .map(|c| c.trim().trim_matches('`'))
            .collect();
        let [file, size, sha256] = cells[..] else {
            return Err(format!("row needs 3 cells: {line}"));
        };
        let size = size.parse().map_err(|_| format!("bad size: {line}"))?;
        let is_hex = |b: u8| b.is_ascii_digit() || (b'a'..=b'f').contains(&b);
        if sha256.len() != 64 || !sha256.bytes().all(is_hex) {
            return Err(format!("bad SHA-256 (64 lowercase hex digits): {line}"));
        }
        if entries.iter().any(|e| e.file == file) {
            return Err(format!("{file} is listed twice"));
        }
        entries.push(ManifestEntry {
            file: file.to_owned(),
            size,
            sha256: sha256.to_owned(),
        });
    }
    if entries.is_empty() {
        return Err("no checksum rows".to_owned());
    }
    Ok(entries)
}

/// Lowercase hex of `bytes`.
fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

/// Checks `bytes` against the README row for its file.
fn verify_entry(entry: &ManifestEntry, bytes: &[u8]) -> Result<(), String> {
    if bytes.len() != entry.size {
        return Err(format!(
            "{}: {} bytes, README says {}",
            entry.file,
            bytes.len(),
            entry.size
        ));
    }
    let actual = to_hex(&Sha256::digest(bytes));
    if actual != entry.sha256 {
        return Err(format!(
            "{}: SHA-256 {actual}, README says {}",
            entry.file, entry.sha256
        ));
    }
    Ok(())
}

/// The test-vector schema of a suite, from its `schema` member. It fixes
/// which group and test fields are present.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Schema {
    /// `mac_test_schema_v1.json`: groups of type `MacTest`, tests with
    /// [`Input::Mac`].
    Mac,
    /// `rsassa_pkcs1_verify_schema_v1.json` (`RsassaPkcs1Verify`): RSASSA-PKCS1-v1_5,
    /// RFC 8017 §8.2. Groups carry `keyJwk` and an RSA [`PublicKey`].
    RsassaPkcs1Verify,
    /// `rsassa_pss_verify_schema_v1.json` (`RsassaPssVerify`): RSASSA-PSS,
    /// RFC 8017 §8.1, MGF1. Groups carry `publicKeyJwk`, an RSA [`PublicKey`]
    /// and the salt length.
    RsassaPssVerify,
    /// `ecdsa_p1363_verify_schema_v1.json` (`EcdsaP1363Verify`): ECDSA with
    /// the `R || S` signature encoding that JWS uses (RFC 7518 §3.4).
    EcdsaP1363Verify,
    /// `eddsa_verify_schema_v1.json` (`EddsaVerify`): Ed25519, RFC 8032 §5.1.
    EddsaVerify,
    /// `json_web_signature_schema_v1.json` (`JsonWebSignature`): whole JWS
    /// objects (RFC 7515), tests with [`Input::Jws`] and groups with
    /// [`JwsKeys`].
    JsonWebSignature,
}

impl Schema {
    /// The value of each group's `type` member under this schema.
    fn group_type(self) -> &'static str {
        match self {
            Schema::Mac => "MacTest",
            Schema::RsassaPkcs1Verify => "RsassaPkcs1Verify",
            Schema::RsassaPssVerify => "RsassaPssVerify",
            Schema::EcdsaP1363Verify => "EcdsaP1363Verify",
            Schema::EddsaVerify => "EddsaVerify",
            Schema::JsonWebSignature => "JsonWebSignature",
        }
    }

    /// The upstream schema file name.
    fn file(self) -> &'static str {
        match self {
            Schema::Mac => "mac_test_schema_v1.json",
            Schema::RsassaPkcs1Verify => "rsassa_pkcs1_verify_schema_v1.json",
            Schema::RsassaPssVerify => "rsassa_pss_verify_schema_v1.json",
            Schema::EcdsaP1363Verify => "ecdsa_p1363_verify_schema_v1.json",
            Schema::EddsaVerify => "eddsa_verify_schema_v1.json",
            Schema::JsonWebSignature => "json_web_signature_schema_v1.json",
        }
    }
}

/// Every vendored suite: `(name, schema, algorithm)`. The name is the file
/// name without `_test.json`; `algorithm` is the file's `algorithm` member
/// (the JOSE-level file has none).
const SUITES: &[(&str, Schema, Option<&str>)] = &[
    ("hmac_sha256", Schema::Mac, Some("HMACSHA256")),
    ("hmac_sha384", Schema::Mac, Some("HMACSHA384")),
    ("hmac_sha512", Schema::Mac, Some("HMACSHA512")),
    (
        "rsa_signature_2048_sha256",
        Schema::RsassaPkcs1Verify,
        Some(PKCS1),
    ),
    (
        "rsa_signature_2048_sha384",
        Schema::RsassaPkcs1Verify,
        Some(PKCS1),
    ),
    (
        "rsa_signature_2048_sha512",
        Schema::RsassaPkcs1Verify,
        Some(PKCS1),
    ),
    (
        "rsa_signature_3072_sha256",
        Schema::RsassaPkcs1Verify,
        Some(PKCS1),
    ),
    (
        "rsa_signature_3072_sha384",
        Schema::RsassaPkcs1Verify,
        Some(PKCS1),
    ),
    (
        "rsa_signature_3072_sha512",
        Schema::RsassaPkcs1Verify,
        Some(PKCS1),
    ),
    (
        "rsa_signature_4096_sha256",
        Schema::RsassaPkcs1Verify,
        Some(PKCS1),
    ),
    (
        "rsa_signature_4096_sha384",
        Schema::RsassaPkcs1Verify,
        Some(PKCS1),
    ),
    (
        "rsa_signature_4096_sha512",
        Schema::RsassaPkcs1Verify,
        Some(PKCS1),
    ),
    (
        "rsa_signature_8192_sha256",
        Schema::RsassaPkcs1Verify,
        Some(PKCS1),
    ),
    (
        "rsa_pss_2048_sha256_mgf1_32",
        Schema::RsassaPssVerify,
        Some(PSS),
    ),
    (
        "rsa_pss_2048_sha384_mgf1_48",
        Schema::RsassaPssVerify,
        Some(PSS),
    ),
    (
        "rsa_pss_3072_sha256_mgf1_32",
        Schema::RsassaPssVerify,
        Some(PSS),
    ),
    (
        "rsa_pss_4096_sha256_mgf1_32",
        Schema::RsassaPssVerify,
        Some(PSS),
    ),
    (
        "rsa_pss_4096_sha384_mgf1_48",
        Schema::RsassaPssVerify,
        Some(PSS),
    ),
    (
        "rsa_pss_4096_sha512_mgf1_64",
        Schema::RsassaPssVerify,
        Some(PSS),
    ),
    (
        "ecdsa_secp256r1_sha256_p1363",
        Schema::EcdsaP1363Verify,
        Some("ECDSA"),
    ),
    (
        "ecdsa_secp384r1_sha384_p1363",
        Schema::EcdsaP1363Verify,
        Some("ECDSA"),
    ),
    (
        "ecdsa_secp521r1_sha512_p1363",
        Schema::EcdsaP1363Verify,
        Some("ECDSA"),
    ),
    (
        "ecdsa_secp256k1_sha256_p1363",
        Schema::EcdsaP1363Verify,
        Some("ECDSA"),
    ),
    ("ed25519", Schema::EddsaVerify, Some("EDDSA")),
    ("json_web_signature", Schema::JsonWebSignature, None),
];
const PKCS1: &str = "RSASSA-PKCS1-v1_5";
const PSS: &str = "RSASSA-PSS";

/// The names of the vendored suites that start with `prefix`, for example
/// `names("rsa_pss_")`. Panics if none does, so a typo cannot select an
/// empty set.
pub(crate) fn names(prefix: &str) -> Vec<&'static str> {
    let found: Vec<&'static str> = SUITES
        .iter()
        .map(|(name, _, _)| *name)
        .filter(|name| name.starts_with(prefix))
        .collect();
    assert!(
        !found.is_empty(),
        "no vendored Wycheproof suite starts with {prefix:?}"
    );
    found
}

/// A parsed Wycheproof file.
pub(crate) struct Suite {
    /// The suite name: the file name without `_test.json`.
    pub(crate) name: String,
    /// The file's schema; every group and test follows it.
    pub(crate) schema: Schema,
    /// The file's `algorithm` member (`None` for `json_web_signature`).
    pub(crate) algorithm: Option<String>,
    /// The flag definitions (`notes`): flag name → note. Every test flag is
    /// one of these.
    pub(crate) notes: BTreeMap<String, Note>,
    /// The test groups, in file order.
    pub(crate) groups: Vec<Group>,
}

impl Suite {
    /// Every test with its group, in file order.
    pub(crate) fn tests(&self) -> impl Iterator<Item = (&Group, &Test)> {
        self.groups
            .iter()
            .flat_map(|group| group.tests.iter().map(move |test| (group, test)))
    }
}

/// What a flag means (`notes` in the file).
pub(crate) struct Note {
    /// Upstream's classification, e.g. `AUTH_BYPASS`, `EDGE_CASE`.
    pub(crate) bug_type: String,
    /// Upstream's description of the flag.
    pub(crate) description: String,
}

/// A test group: one key (or key size) and its tests.
///
/// Which fields are `Some` depends on the [`Schema`]; [`load`] checks them,
/// so a family test may rely on its schema's fields being present.
pub(crate) struct Group {
    /// The group's `comment` (`JsonWebSignature` only: the algorithm or
    /// topic, e.g. `"es256"`, `"rfc7520"`).
    pub(crate) comment: Option<String>,
    /// `keySize` in bits (`Mac`, `RsassaPkcs1Verify`, `RsassaPssVerify`).
    pub(crate) key_size: Option<u32>,
    /// `tagSize` in bits (`Mac`). A JWS MAC is never truncated
    /// (RFC 7518 §3.2), so groups with `tag_size` below the hash size hold
    /// truncated MACs.
    pub(crate) tag_size: Option<u32>,
    /// `sha`, the message digest, e.g. `"SHA-256"` (the RSA and ECDSA
    /// schemas).
    pub(crate) sha: Option<String>,
    /// `mgfSha`, the MGF1 digest (`RsassaPssVerify`; the MGF is always MGF1).
    pub(crate) mgf_sha: Option<String>,
    /// `sLen`, the PSS salt length in bytes (`RsassaPssVerify`).
    pub(crate) salt_len: Option<u32>,
    /// The group's public key as a JWK, as JSON text: `keyJwk`
    /// (`RsassaPkcs1Verify`) or `publicKeyJwk` (the other signature
    /// schemas), for `polyjose::jwk::Jwk::from_json(jwk.as_bytes())`.
    /// Always present for RSA; absent on some ECDSA and EdDSA edge-case
    /// groups, which have only [`Group::public_key`].
    ///
    /// The text is re-serialized from the parsed value, so member order and
    /// whitespace may differ from the file; the members and values do not.
    pub(crate) key_jwk: Option<String>,
    /// The raw public key (`publicKey`), for the signature schemas.
    pub(crate) public_key: Option<PublicKey>,
    /// The `private` and `public` JWKs (`JsonWebSignature`).
    pub(crate) jws_keys: Option<JwsKeys>,
    /// The tests, in file order.
    pub(crate) tests: Vec<Test>,
}

/// The raw public key of a signature group, as Wycheproof prints it. The
/// integers are big-endian bytes decoded from the file's hex; they may carry
/// a leading `00` (ASN.1 style) or be shorter than the field size.
pub(crate) enum PublicKey {
    /// `modulus` and `publicExponent`.
    Rsa {
        modulus: Vec<u8>,
        public_exponent: Vec<u8>,
    },
    /// An EC point: `curve` (e.g. `"secp256r1"`), `wx` and `wy`.
    Ec {
        curve: String,
        wx: Vec<u8>,
        wy: Vec<u8>,
    },
    /// An EdDSA key: `curve` (`"edwards25519"`) and the encoded point `pk`.
    Eddsa { curve: String, pk: Vec<u8> },
}

impl PublicKey {
    /// The key as a public JWK, as JSON text, with only the members that
    /// define the key (no `alg`, `kid` or `use`):
    ///
    /// - RSA: `kty`, `n`, `e`, unsigned big-endian with leading zero octets
    ///   removed (RFC 7518 §6.3.1.1, §6.3.1.2).
    /// - EC: `kty`, `crv`, `x`, `y`, each coordinate left-padded to the full
    ///   field size (RFC 7518 §6.2.1.2, §6.2.1.3). `secp256r1`, `secp384r1`
    ///   and `secp521r1` are `P-256`, `P-384` and `P-521` (RFC 7518
    ///   §6.2.1.1); `secp256k1` keeps its name (RFC 8812 §3.1).
    /// - EdDSA: `kty: OKP`, `crv: Ed25519`, `x` = the 32-byte `pk`
    ///   (RFC 8037 §2).
    ///
    /// Fails on an unknown curve, a coordinate wider than the field, or a
    /// `pk` that is not 32 bytes.
    pub(crate) fn to_jwk(&self) -> Result<String, String> {
        let b64 = |bytes: &[u8]| Base64UrlUnpadded::encode_string(bytes);
        let jwk = match self {
            PublicKey::Rsa {
                modulus,
                public_exponent,
            } => serde_json::json!({
                "kty": "RSA",
                "n": b64(strip_leading_zeros(modulus)),
                "e": b64(strip_leading_zeros(public_exponent)),
            }),
            PublicKey::Ec { curve, wx, wy } => {
                let (crv, size) = match curve.as_str() {
                    "secp256r1" => ("P-256", 32),
                    "secp384r1" => ("P-384", 48),
                    "secp521r1" => ("P-521", 66),
                    "secp256k1" => ("secp256k1", 32),
                    other => return Err(format!("no JWK curve for {other:?}")),
                };
                serde_json::json!({
                    "kty": "EC",
                    "crv": crv,
                    "x": b64(&to_field_size(wx, size)?),
                    "y": b64(&to_field_size(wy, size)?),
                })
            }
            PublicKey::Eddsa { curve, pk } => {
                if curve != "edwards25519" || pk.len() != 32 {
                    return Err(format!("no JWK for a {}-byte {curve:?} key", pk.len()));
                }
                serde_json::json!({ "kty": "OKP", "crv": "Ed25519", "x": b64(pk) })
            }
        };
        json_text(&jwk)
    }
}

/// `bytes` without leading zero octets.
fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[start..]
}

/// The big-endian integer `bytes` as exactly `size` octets.
fn to_field_size(bytes: &[u8], size: usize) -> Result<Vec<u8>, String> {
    let digits = strip_leading_zeros(bytes);
    if digits.len() > size {
        return Err(format!(
            "{}-byte coordinate for a {size}-byte field",
            digits.len()
        ));
    }
    let mut out = vec![0; size - digits.len()];
    out.extend_from_slice(digits);
    Ok(out)
}

impl Group {
    /// The JWK to verify this group's tests with, as JSON text:
    ///
    /// - signature schemas: [`Group::key_jwk`] when the file has one, else
    ///   [`PublicKey::to_jwk`] of [`Group::public_key`];
    /// - `JsonWebSignature`: the `public` JWK, else the `private` one (an
    ///   `oct` key is both).
    ///
    /// Panics for `Mac` groups, whose keys are per test ([`Test::mac`]), and
    /// if the raw key has no JWK form.
    pub(crate) fn verification_jwk(&self) -> String {
        if let Some(jwk) = &self.key_jwk {
            return jwk.clone();
        }
        if let Some(keys) = &self.jws_keys {
            return keys.public.clone().unwrap_or_else(|| keys.private.clone());
        }
        match &self.public_key {
            Some(key) => key.to_jwk().unwrap_or_else(|e| panic!("{e}")),
            None => panic!("a MAC group has no group key; use Test::mac"),
        }
    }
}

/// The keys of a `JsonWebSignature` group, as JWK JSON text.
pub(crate) struct JwsKeys {
    /// `private`: the signing key (for `oct` keys, the only key).
    pub(crate) private: String,
    /// `public`: the verification key, when it differs from `private`.
    pub(crate) public: Option<String>,
}

/// One test case.
pub(crate) struct Test {
    /// `tcId`, unique within the file. Deviation lists key on it.
    pub(crate) tc_id: u32,
    /// Upstream's comment.
    pub(crate) comment: String,
    /// Upstream's flags; each is a key of [`Suite::notes`].
    pub(crate) flags: Vec<String>,
    /// Upstream's expected result.
    pub(crate) result: Expected,
    /// The inputs; the variant follows the [`Schema`].
    pub(crate) input: Input,
}

/// A test's inputs.
pub(crate) enum Input {
    /// The signature schemas: `msg` and `sig`.
    Signature { msg: Vec<u8>, sig: Vec<u8> },
    /// `Mac`: the per-test `key`, `msg` and `tag`.
    Mac {
        key: Vec<u8>,
        msg: Vec<u8>,
        tag: Vec<u8>,
    },
    /// `JsonWebSignature`: the JWS, in compact or JSON serialization.
    Jws(String),
}

impl Test {
    /// `(msg, sig)` of a signature test. Panics on another schema.
    pub(crate) fn signature(&self) -> (&[u8], &[u8]) {
        match &self.input {
            Input::Signature { msg, sig } => (msg, sig),
            _ => panic!("tcId {} is not a signature test", self.tc_id),
        }
    }

    /// `(key, msg, tag)` of a `Mac` test. Panics on another schema.
    pub(crate) fn mac(&self) -> (&[u8], &[u8], &[u8]) {
        match &self.input {
            Input::Mac { key, msg, tag } => (key, msg, tag),
            _ => panic!("tcId {} is not a MAC test", self.tc_id),
        }
    }

    /// The JWS text of a `JsonWebSignature` test. Panics on another schema.
    pub(crate) fn jws(&self) -> &str {
        match &self.input {
            Input::Jws(jws) => jws,
            _ => panic!("tcId {} is not a JWS test", self.tc_id),
        }
    }

    /// Whether the test carries `flag`.
    pub(crate) fn has_flag(&self, flag: &str) -> bool {
        self.flags.iter().any(|f| f == flag)
    }
}

/// A test's expected result (`result`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Expected {
    /// The input is valid and must be accepted.
    Valid,
    /// The input is invalid and must be rejected.
    Invalid,
    /// Either outcome is allowed (upstream `doc/files.md`); polyjose's
    /// choice goes in the family's deviation list.
    Acceptable,
}

/// Loads and checks the vendored suite `name` (see [`names`]), e.g.
/// `load("hmac_sha256")` for `hmac_sha256_test.json`.
///
/// Panics, naming the problem, if the name is not vendored, the file does
/// not match its README checksum, or the file does not follow its schema:
/// an unknown member, a missing field, bad hex, a duplicate `tcId`, an
/// undefined flag or a wrong `numberOfTests`.
pub(crate) fn load(name: &str) -> Suite {
    let Some(&(_, schema, algorithm)) = SUITES.iter().find(|(n, _, _)| *n == name) else {
        panic!("{name:?} is not a vendored Wycheproof suite");
    };
    let file = format!("{name}_test.json");
    let entries = manifest();
    let Some(entry) = entries.iter().find(|e| e.file == file) else {
        panic!("{file} is not in the README checksum table");
    };
    let path = format!("{DIR}/{file}");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
    if let Err(e) = verify_entry(entry, &bytes) {
        panic!("{e}");
    }
    let text = core::str::from_utf8(&bytes).unwrap_or_else(|e| panic!("{file}: {e}"));
    parse(name, schema, algorithm, text).unwrap_or_else(|e| panic!("{file}: {e}"))
}

/// What polyjose did with a test's input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// The signature, MAC or JWS verified.
    Accept,
    /// It was rejected (with any error).
    Reject,
}

impl Outcome {
    /// [`Outcome::Accept`] for `Ok`, [`Outcome::Reject`] for `Err`.
    pub(crate) fn of<T, E>(result: &Result<T, E>) -> Outcome {
        if result.is_ok() {
            Outcome::Accept
        } else {
            Outcome::Reject
        }
    }

    /// The outcome Wycheproof requires for `expected`, if it requires one.
    fn required_by(expected: Expected) -> Option<Outcome> {
        match expected {
            Expected::Valid => Some(Outcome::Accept),
            Expected::Invalid => Some(Outcome::Reject),
            Expected::Acceptable => None,
        }
    }
}

/// One entry of a family's deviation list: tests of one suite where
/// polyjose's outcome is not the one Wycheproof's `result` requires, or
/// where the `result` is `acceptable` and polyjose picks a side.
///
/// Write the list as a `const` (the RNG state scan in `rng.rs` bans
/// `static` items):
///
/// ```ignore
/// const HMAC_SHA256: &[Deviation] = &[Deviation::range(
///     30,
///     58,
///     Outcome::Reject,
///     "RFC 7518 §3.2: a JWS HMAC tag is never truncated",
/// )];
/// ```
///
/// [`check`] enforces the rules:
///
/// - the reason cites an RFC or ADR (`"RFC 7518 §3.2: ..."`,
///   `"ADR 0026 §6: ..."`);
/// - every listed `tcId` exists in the suite, and is listed once;
/// - an entry changes something: listing a `valid` test as `Accept` or an
///   `invalid` one as `Reject` is redundant and fails;
/// - an `invalid` test is never listed as `Accept`: accepting it would be a
///   security bug, not a policy;
/// - every `acceptable` test is listed, so polyjose's choice is recorded.
pub(crate) struct Deviation {
    tests: DeviationTests,
    outcome: Outcome,
    reason: &'static str,
}

enum DeviationTests {
    Ids(&'static [u32]),
    /// `first..=last`.
    Range(u32, u32),
}

impl Deviation {
    /// The tests `tc_ids` have `outcome`, for `reason`.
    pub(crate) const fn tests(
        tc_ids: &'static [u32],
        outcome: Outcome,
        reason: &'static str,
    ) -> Deviation {
        Deviation {
            tests: DeviationTests::Ids(tc_ids),
            outcome,
            reason,
        }
    }

    /// The tests `first..=last` have `outcome`, for `reason`. Every `tcId`
    /// in the range must exist (Wycheproof numbers a file's tests 1..=n, and
    /// a group's tests are consecutive).
    pub(crate) const fn range(
        first: u32,
        last: u32,
        outcome: Outcome,
        reason: &'static str,
    ) -> Deviation {
        Deviation {
            tests: DeviationTests::Range(first, last),
            outcome,
            reason,
        }
    }

    fn tc_ids(&self) -> Vec<u32> {
        match self.tests {
            DeviationTests::Ids(ids) => ids.to_vec(),
            DeviationTests::Range(first, last) => (first..=last).collect(),
        }
    }
}

/// Whether `reason` cites an RFC or ADR by number (`RFC 7518`, `ADR 0026`).
fn cites_rfc_or_adr(reason: &str) -> bool {
    ["RFC ", "ADR "].iter().any(|tag| {
        reason
            .match_indices(tag)
            .any(|(at, _)| reason[at + tag.len()..].starts_with(|c: char| c.is_ascii_digit()))
    })
}

/// Counts from a [`check`] that passed.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Summary {
    /// Tests run.
    pub(crate) tests: usize,
    /// Tests polyjose accepted.
    pub(crate) accepted: usize,
    /// Tests polyjose rejected.
    pub(crate) rejected: usize,
    /// Tests whose outcome came from the deviation list.
    pub(crate) deviations: usize,
}

/// Runs every test of `suite` through `run` and compares what polyjose did
/// with what Wycheproof requires, adjusted by `deviations` (see
/// [`Deviation`] for the rules).
///
/// `run` gets each test with its group and returns polyjose's
/// [`Outcome`] (usually `Outcome::of(&result)`); it may also assert the
/// error kind. Every test runs; the result lists every failure, each naming
/// the file, `tcId`, comment, flags and both outcomes.
pub(crate) fn check(
    suite: &Suite,
    deviations: &[Deviation],
    mut run: impl FnMut(&Group, &Test) -> Outcome,
) -> Result<Summary, Vec<String>> {
    let name = &suite.name;
    let mut failures = Vec::new();
    let mut listed: BTreeMap<u32, &Deviation> = BTreeMap::new();
    for deviation in deviations {
        if !cites_rfc_or_adr(deviation.reason) {
            failures.push(format!(
                "{name}: deviation reason cites no RFC or ADR: {:?}",
                deviation.reason
            ));
        }
        let ids = deviation.tc_ids();
        if ids.is_empty() {
            failures.push(format!(
                "{name}: deviation lists no tests: {:?}",
                deviation.reason
            ));
        }
        for id in ids {
            if listed.insert(id, deviation).is_some() {
                failures.push(format!("{name}: tcId {id} is in the deviation list twice"));
            }
        }
    }
    let mut summary = Summary {
        tests: 0,
        accepted: 0,
        rejected: 0,
        deviations: 0,
    };
    let mut seen = BTreeSet::new();
    for (group, test) in suite.tests() {
        seen.insert(test.tc_id);
        let observed = run(group, test);
        summary.tests += 1;
        match observed {
            Outcome::Accept => summary.accepted += 1,
            Outcome::Reject => summary.rejected += 1,
        }
        let what = format!(
            "{name}: tcId {} ({:?}, flags {:?}, result {:?})",
            test.tc_id, test.comment, test.flags, test.result
        );
        let required = Outcome::required_by(test.result);
        let Some(deviation) = listed.get(&test.tc_id) else {
            match required {
                Some(required) if required == observed => {}
                Some(required) => failures.push(format!(
                    "{what}: unexplained deviation: expected {required:?}, polyjose did {observed:?}"
                )),
                None => failures.push(format!(
                    "{what}: acceptable test not in the deviation list (polyjose did {observed:?})"
                )),
            }
            continue;
        };
        summary.deviations += 1;
        if required == Some(deviation.outcome) {
            failures.push(format!(
                "{what}: redundant deviation: {:?} is what Wycheproof requires",
                deviation.outcome
            ));
        }
        if test.result == Expected::Invalid && deviation.outcome == Outcome::Accept {
            failures.push(format!(
                "{what}: an invalid test can never be listed as Accept"
            ));
        }
        if deviation.outcome != observed {
            failures.push(format!(
                "{what}: deviation list says {:?} ({}), polyjose did {observed:?}",
                deviation.outcome, deviation.reason
            ));
        }
    }
    for id in listed.keys().filter(|id| !seen.contains(id)) {
        failures.push(format!(
            "{name}: deviation lists tcId {id}, which is not in the suite"
        ));
    }
    if failures.is_empty() {
        Ok(summary)
    } else {
        Err(failures)
    }
}

/// [`check`], panicking with every failure if any test deviates without
/// an explanation or the deviation list is wrong. Returns the counts.
pub(crate) fn assert_conforms(
    suite: &Suite,
    deviations: &[Deviation],
    run: impl FnMut(&Group, &Test) -> Outcome,
) -> Summary {
    match check(suite, deviations, run) {
        Ok(summary) => summary,
        Err(failures) => panic!(
            "{} Wycheproof failure(s) in {}:\n{}",
            failures.len(),
            suite.name,
            failures.join("\n")
        ),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawSuite {
    algorithm: Option<String>,
    schema: String,
    number_of_tests: usize,
    #[serde(rename = "header")]
    _header: IgnoredAny,
    notes: BTreeMap<String, RawNote>,
    test_groups: Vec<RawGroup>,
}

/// Notes may also carry `effect`, `cves` and `links`, which are ignored.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawNote {
    bug_type: String,
    description: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawGroup {
    #[serde(rename = "type")]
    group_type: String,
    #[serde(rename = "source")]
    _source: IgnoredAny,
    comment: Option<String>,
    key_size: Option<u32>,
    tag_size: Option<u32>,
    sha: Option<String>,
    mgf: Option<String>,
    mgf_sha: Option<String>,
    s_len: Option<u32>,
    public_key: Option<RawPublicKey>,
    // The ASN.1, DER and PEM encodings repeat `publicKey`.
    #[serde(rename = "publicKeyAsn")]
    _public_key_asn: Option<IgnoredAny>,
    #[serde(rename = "publicKeyDer")]
    _public_key_der: Option<IgnoredAny>,
    #[serde(rename = "publicKeyPem")]
    _public_key_pem: Option<IgnoredAny>,
    key_jwk: Option<serde_json::Value>,
    public_key_jwk: Option<serde_json::Value>,
    private: Option<serde_json::Value>,
    public: Option<serde_json::Value>,
    tests: Vec<RawTest>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawPublicKey {
    #[serde(rename = "type")]
    key_type: Option<String>,
    curve: Option<String>,
    key_size: Option<u32>,
    uncompressed: Option<String>,
    wx: Option<String>,
    wy: Option<String>,
    pk: Option<String>,
    modulus: Option<String>,
    public_exponent: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawTest {
    tc_id: u32,
    comment: String,
    flags: Vec<String>,
    result: Expected,
    key: Option<String>,
    msg: Option<String>,
    sig: Option<String>,
    tag: Option<String>,
    jws: Option<String>,
}

/// Decodes hex (either case, even length).
fn hex(text: &str) -> Result<Vec<u8>, String> {
    let digit = |c: u8| match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(format!("not hex: {text:?}")),
    };
    if text.len() % 2 != 0 {
        return Err(format!("odd-length hex: {text:?}"));
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok((digit(pair[0])? << 4) | digit(pair[1])?))
        .collect()
}

fn json_text(value: &serde_json::Value) -> Result<String, String> {
    if !value.is_object() {
        return Err("a JWK must be a JSON object".to_owned());
    }
    serde_json::to_string(value).map_err(|e| e.to_string())
}

fn parse(name: &str, schema: Schema, algorithm: Option<&str>, text: &str) -> Result<Suite, String> {
    let raw: RawSuite = serde_json::from_str(text).map_err(|e| e.to_string())?;
    if raw.schema != schema.file() {
        return Err(format!(
            "schema {:?}, expected {:?}",
            raw.schema,
            schema.file()
        ));
    }
    if raw.algorithm.as_deref() != algorithm {
        return Err(format!(
            "algorithm {:?}, expected {algorithm:?}",
            raw.algorithm
        ));
    }
    let notes: BTreeMap<String, Note> = raw
        .notes
        .into_iter()
        .map(|(flag, note)| {
            let note = Note {
                bug_type: note.bug_type,
                description: note.description,
            };
            (flag, note)
        })
        .collect();
    let mut tc_ids = BTreeSet::new();
    let mut groups = Vec::with_capacity(raw.test_groups.len());
    for raw_group in raw.test_groups {
        let group = parse_group(schema, raw_group)?;
        for test in &group.tests {
            if !tc_ids.insert(test.tc_id) {
                return Err(format!("duplicate tcId {}", test.tc_id));
            }
            if let Some(flag) = test.flags.iter().find(|f| !notes.contains_key(*f)) {
                return Err(format!("tcId {}: flag {flag:?} has no note", test.tc_id));
            }
        }
        groups.push(group);
    }
    if tc_ids.len() != raw.number_of_tests {
        return Err(format!(
            "{} tests, numberOfTests says {}",
            tc_ids.len(),
            raw.number_of_tests
        ));
    }
    Ok(Suite {
        name: name.to_owned(),
        schema,
        algorithm: raw.algorithm,
        notes,
        groups,
    })
}

fn parse_group(schema: Schema, raw: RawGroup) -> Result<Group, String> {
    if raw.group_type != schema.group_type() {
        return Err(format!(
            "group type {:?} in a {:?} file",
            raw.group_type,
            schema.group_type()
        ));
    }
    let key_jwk = match (&raw.key_jwk, &raw.public_key_jwk) {
        (Some(_), Some(_)) => return Err("group has both keyJwk and publicKeyJwk".to_owned()),
        (Some(jwk), None) | (None, Some(jwk)) => Some(json_text(jwk)?),
        (None, None) => None,
    };
    let public_key = raw.public_key.map(parse_public_key).transpose()?;
    let jws_keys = match (&raw.private, &raw.public) {
        (Some(private), public) => Some(JwsKeys {
            private: json_text(private)?,
            public: public.as_ref().map(json_text).transpose()?,
        }),
        (None, Some(_)) => return Err("group has `public` without `private`".to_owned()),
        (None, None) => None,
    };
    let is_rsa = |k: &Option<PublicKey>| matches!(k, Some(PublicKey::Rsa { .. }));
    let is_ec = |k: &Option<PublicKey>| matches!(k, Some(PublicKey::Ec { .. }));
    let is_eddsa = |k: &Option<PublicKey>| matches!(k, Some(PublicKey::Eddsa { .. }));
    // The fields each schema must have (and the key fields it must not).
    let shape_ok = match schema {
        Schema::Mac => {
            raw.key_size.is_some()
                && raw.tag_size.is_some()
                && public_key.is_none()
                && key_jwk.is_none()
        }
        Schema::RsassaPkcs1Verify => {
            raw.key_size.is_some()
                && raw.sha.is_some()
                && raw.key_jwk.is_some()
                && is_rsa(&public_key)
        }
        Schema::RsassaPssVerify => {
            raw.key_size.is_some()
                && raw.sha.is_some()
                && raw.mgf.as_deref() == Some("MGF1")
                && raw.mgf_sha.is_some()
                && raw.s_len.is_some()
                && raw.public_key_jwk.is_some()
                && is_rsa(&public_key)
        }
        Schema::EcdsaP1363Verify => raw.sha.is_some() && is_ec(&public_key),
        Schema::EddsaVerify => is_eddsa(&public_key),
        Schema::JsonWebSignature => jws_keys.is_some() && public_key.is_none() && key_jwk.is_none(),
    };
    if !shape_ok {
        return Err(format!(
            "a {} group is missing a field or has an unexpected key",
            schema.group_type()
        ));
    }
    let tests = raw
        .tests
        .into_iter()
        .map(|t| parse_test(schema, t))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Group {
        comment: raw.comment,
        key_size: raw.key_size,
        tag_size: raw.tag_size,
        sha: raw.sha,
        mgf_sha: raw.mgf_sha,
        salt_len: raw.s_len,
        key_jwk,
        public_key,
        jws_keys,
        tests,
    })
}

fn parse_public_key(raw: RawPublicKey) -> Result<PublicKey, String> {
    let RawPublicKey {
        key_type,
        curve,
        key_size,
        uncompressed,
        wx,
        wy,
        pk,
        modulus,
        public_exponent,
    } = raw;
    let ec_type = key_type.as_deref() == Some("EcPublicKey");
    let eddsa_type = key_type.as_deref() == Some("EDDSAPublicKey");
    match (modulus, public_exponent, wx, wy, pk) {
        (Some(n), Some(e), None, None, None) if key_type.is_none() && curve.is_none() => {
            Ok(PublicKey::Rsa {
                modulus: hex(&n)?,
                public_exponent: hex(&e)?,
            })
        }
        (None, None, Some(x), Some(y), None) if ec_type && key_size.is_some() => {
            let (Some(curve), Some(_)) = (curve, uncompressed) else {
                return Err("EC public key without curve or uncompressed point".to_owned());
            };
            Ok(PublicKey::Ec {
                curve,
                wx: hex(&x)?,
                wy: hex(&y)?,
            })
        }
        (None, None, None, None, Some(pk)) if eddsa_type && key_size.is_some() => {
            let Some(curve) = curve else {
                return Err("EdDSA public key without curve".to_owned());
            };
            Ok(PublicKey::Eddsa {
                curve,
                pk: hex(&pk)?,
            })
        }
        _ => Err("publicKey is not an RSA, EC or EdDSA key".to_owned()),
    }
}

fn parse_test(schema: Schema, raw: RawTest) -> Result<Test, String> {
    let tc_id = raw.tc_id;
    let input = match (schema, raw.key, raw.msg, raw.sig, raw.tag, raw.jws) {
        (Schema::Mac, Some(key), Some(msg), None, Some(tag), None) => Input::Mac {
            key: hex(&key)?,
            msg: hex(&msg)?,
            tag: hex(&tag)?,
        },
        (Schema::JsonWebSignature, None, None, None, None, Some(jws)) => Input::Jws(jws),
        (Schema::Mac | Schema::JsonWebSignature, ..) => {
            return Err(format!("tcId {tc_id}: fields do not match the schema"));
        }
        (_, None, Some(msg), Some(sig), None, None) => Input::Signature {
            msg: hex(&msg)?,
            sig: hex(&sig)?,
        },
        _ => return Err(format!("tcId {tc_id}: fields do not match the schema")),
    };
    Ok(Test {
        tc_id,
        comment: raw.comment,
        flags: raw.flags,
        result: raw.result,
        input,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendored_files_match_the_readme() {
        let entries = manifest();
        let mut on_disk: Vec<String> = std::fs::read_dir(DIR)
            .unwrap_or_else(|e| panic!("cannot list {DIR}: {e}"))
            .map(|entry| entry.map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect::<Result<_, _>>()
            .unwrap_or_else(|e| panic!("cannot list {DIR}: {e}"));
        on_disk.retain(|f| f != "README.md");
        on_disk.sort();
        let mut listed: Vec<String> = entries.iter().map(|e| e.file.clone()).collect();
        listed.sort();
        assert_eq!(
            on_disk, listed,
            "files on disk vs. files in the README table"
        );

        let failures: Vec<String> = entries
            .iter()
            .filter_map(|entry| {
                let path = format!("{DIR}/{}", entry.file);
                let bytes =
                    std::fs::read(&path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
                verify_entry(entry, &bytes).err()
            })
            .collect();
        assert!(
            failures.is_empty(),
            "checksum mismatches:\n{}",
            failures.join("\n")
        );
    }

    #[test]
    fn a_one_byte_change_fails_the_checksum() {
        let entries = manifest();
        let entry = entries
            .iter()
            .find(|e| e.file == "hmac_sha256_test.json")
            .unwrap_or_else(|| panic!("hmac_sha256_test.json is not in the README"));
        let mut bytes = std::fs::read(format!("{DIR}/{}", entry.file)).unwrap_or_default();
        assert_eq!(verify_entry(entry, &bytes), Ok(()));
        let middle = bytes.len() / 2;
        bytes[middle] ^= 0x01;
        let err = verify_entry(entry, &bytes).err().unwrap_or_default();
        assert!(err.contains("SHA-256"), "{err}");
        bytes.push(b'\n');
        let err = verify_entry(entry, &bytes).err().unwrap_or_default();
        assert!(err.contains("bytes"), "{err}");
    }

    #[test]
    fn manifest_rows_are_strict() {
        let good = "| `a.json` | 3 | `".to_owned() + &"0".repeat(64) + "` |";
        assert_eq!(parse_manifest(&good).map(|e| e[0].size), Ok(3));
        for bad in [
            "| `a.json` | x | `".to_owned() + &"0".repeat(64) + "` |",
            "| `a.json` | 3 | `".to_owned() + &"A".repeat(64) + "` |",
            "| `a.json` | 3 | `".to_owned() + &"0".repeat(63) + "` |",
            "| `a.json` | 3 |".to_owned(),
            format!("{good}\n{good}"),
            String::new(),
        ] {
            assert!(parse_manifest(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn hex_is_lowercase() {
        assert_eq!(to_hex(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
    }

    fn jwk_value(text: Option<&str>) -> serde_json::Value {
        let text = text.unwrap_or_else(|| panic!("no JWK"));
        serde_json::from_str(text).unwrap_or_else(|e| panic!("bad JWK text: {e}"))
    }

    /// `(name, digest bits)` from a name such as `rsa_pss_2048_sha256_mgf1_32`.
    fn digest_bits(name: &str) -> u32 {
        let sha = name
            .split('_')
            .find_map(|part| part.strip_prefix("sha"))
            .unwrap_or_else(|| panic!("{name} names no digest"));
        sha.parse().unwrap_or_else(|_| panic!("{name}: bad digest"))
    }

    fn count(suite: &Suite, expected: Expected) -> usize {
        suite.tests().filter(|(_, t)| t.result == expected).count()
    }

    #[test]
    fn every_vendored_suite_loads_and_is_in_the_readme() {
        let mut listed: Vec<String> = manifest().into_iter().map(|e| e.file).collect();
        listed.retain(|f| f != "LICENSE");
        listed.sort();
        let mut known: Vec<String> = SUITES
            .iter()
            .map(|(n, _, _)| format!("{n}_test.json"))
            .collect();
        known.sort();
        assert_eq!(listed, known);
        for &(name, schema, algorithm) in SUITES {
            let suite = load(name);
            assert_eq!(suite.name, name);
            assert_eq!(suite.schema, schema);
            assert_eq!(suite.algorithm.as_deref(), algorithm);
            assert!(suite.tests().count() > 0, "{name} has no tests");
            for (flag, note) in &suite.notes {
                assert!(
                    !note.bug_type.is_empty() && !note.description.is_empty(),
                    "{name}: {flag}"
                );
            }
            for (_, test) in suite.tests() {
                assert!(test.flags.iter().all(|f| test.has_flag(f)));
                assert!(!test.has_flag("NoSuchFlag"));
                let _ = &test.comment;
            }
        }
        assert_eq!(names("").len(), SUITES.len());
    }

    #[test]
    fn hmac_suites_have_per_test_keys_and_truncated_groups() {
        let names = names("hmac_");
        assert_eq!(names.len(), 3);
        for name in names {
            let suite = load(name);
            let hash_bits = digest_bits(name);
            assert_eq!(suite.schema, Schema::Mac);
            assert_eq!(suite.tests().count(), 174, "{name}");
            for (group, test) in suite.tests() {
                let (key, msg, tag) = test.mac();
                let key_size = group.key_size.unwrap_or_default();
                let tag_size = group.tag_size.unwrap_or_default();
                assert_eq!(
                    key.len() * 8,
                    key_size as usize,
                    "{name} tcId {}",
                    test.tc_id
                );
                if test.result == Expected::Valid {
                    assert_eq!(
                        tag.len() * 8,
                        tag_size as usize,
                        "{name} tcId {}",
                        test.tc_id
                    );
                }
                assert!(msg.len() < 1 << 20);
                assert!(group.public_key.is_none() && group.key_jwk.is_none());
            }
            // Full-length MACs, truncated MACs (RFC 7518 §3.2 forbids them in
            // JWS) and keys shorter than the hash output are all present.
            assert!(suite.groups.iter().any(|g| g.tag_size == Some(hash_bits)));
            assert!(suite.groups.iter().any(|g| g.tag_size < Some(hash_bits)));
            assert!(suite.groups.iter().any(|g| g.key_size < Some(hash_bits)));
            assert_eq!(count(&suite, Expected::Acceptable), 0);
        }
    }

    /// The JWK `n`/`e` are the raw modulus and exponent (RFC 7518 §6.3.1).
    fn assert_rsa_jwk_matches(name: &str, group: &Group) {
        let jwk = jwk_value(group.key_jwk.as_deref());
        let Some(PublicKey::Rsa {
            modulus,
            public_exponent,
        }) = &group.public_key
        else {
            panic!("{name}: no RSA public key");
        };
        assert_eq!(jwk["kty"], "RSA", "{name}");
        let n = Base64UrlUnpadded::encode_string(strip_leading_zeros(modulus));
        let e = Base64UrlUnpadded::encode_string(strip_leading_zeros(public_exponent));
        assert_eq!(jwk["n"], n.as_str(), "{name}");
        assert_eq!(jwk["e"], e.as_str(), "{name}");
        let bits = strip_leading_zeros(modulus).len() * 8;
        assert_eq!(Some(bits as u32), group.key_size, "{name}");
    }

    #[test]
    fn rsa_pkcs1_suites_carry_a_key_jwk_matching_the_raw_key() {
        let names = names("rsa_signature_");
        assert_eq!(names.len(), 10);
        for name in names {
            let suite = load(name);
            let sha = format!("SHA-{}", digest_bits(name));
            assert_eq!(suite.schema, Schema::RsassaPkcs1Verify);
            for group in &suite.groups {
                assert_eq!(group.sha.as_deref(), Some(sha.as_str()), "{name}");
                assert_rsa_jwk_matches(name, group);
            }
            for (group, test) in suite.tests() {
                let (_, sig) = test.signature();
                if test.result == Expected::Valid {
                    let bits = group.key_size.unwrap_or_default() as usize;
                    assert_eq!(sig.len() * 8, bits, "{name} tcId {}", test.tc_id);
                }
            }
            assert!(count(&suite, Expected::Valid) > 0);
            assert!(count(&suite, Expected::Invalid) > 0);
            assert_eq!(count(&suite, Expected::Acceptable), 1, "{name}");
        }
    }

    #[test]
    fn rsa_pss_suites_use_mgf1_with_the_message_digest_and_a_hash_length_salt() {
        let names = names("rsa_pss_");
        assert_eq!(names.len(), 6);
        for name in names {
            let suite = load(name);
            let bits = digest_bits(name);
            let sha = format!("SHA-{bits}");
            assert_eq!(suite.schema, Schema::RsassaPssVerify);
            for group in &suite.groups {
                // The JWS PS* profile (RFC 7518 §3.5).
                assert_eq!(group.sha.as_deref(), Some(sha.as_str()), "{name}");
                assert_eq!(group.mgf_sha.as_deref(), Some(sha.as_str()), "{name}");
                assert_eq!(group.salt_len, Some(bits / 8), "{name}");
                assert_rsa_jwk_matches(name, group);
            }
            for (_, test) in suite.tests() {
                let (msg, sig) = test.signature();
                assert!(!sig.is_empty() || test.result == Expected::Invalid);
                assert!(msg.len() < 1 << 20);
            }
        }
    }

    #[test]
    fn ecdsa_p1363_suites_have_points_and_nine_groups_without_a_jwk() {
        let names = names("ecdsa_");
        assert_eq!(names.len(), 4);
        for (name, curve, field_bytes) in [
            ("ecdsa_secp256r1_sha256_p1363", "secp256r1", 32),
            ("ecdsa_secp384r1_sha384_p1363", "secp384r1", 48),
            ("ecdsa_secp521r1_sha512_p1363", "secp521r1", 66),
            ("ecdsa_secp256k1_sha256_p1363", "secp256k1", 32),
        ] {
            assert!(names.contains(&name));
            let suite = load(name);
            assert_eq!(suite.schema, Schema::EcdsaP1363Verify);
            let sha = format!("SHA-{}", digest_bits(name));
            let without_jwk = suite.groups.iter().filter(|g| g.key_jwk.is_none()).count();
            assert_eq!(without_jwk, 9, "{name}");
            for group in &suite.groups {
                assert_eq!(group.sha.as_deref(), Some(sha.as_str()), "{name}");
                let Some(PublicKey::Ec { curve: c, wx, wy }) = &group.public_key else {
                    panic!("{name}: no EC public key");
                };
                assert_eq!(c, curve, "{name}");
                assert!(strip_leading_zeros(wx).len() <= field_bytes, "{name}");
                assert!(strip_leading_zeros(wy).len() <= field_bytes, "{name}");
            }
            for (_, test) in suite.tests() {
                let (_, sig) = test.signature();
                if test.result == Expected::Valid {
                    assert_eq!(sig.len(), 2 * field_bytes, "{name} tcId {}", test.tc_id);
                }
            }
            // High-S signatures are valid ECDSA (research.md §3).
            assert!(count(&suite, Expected::Valid) > count(&suite, Expected::Invalid));
            assert_eq!(count(&suite, Expected::Acceptable), 0);
        }
    }

    #[test]
    fn ed25519_suite_has_32_byte_keys_and_acceptable_small_order_cases() {
        let suite = load("ed25519");
        assert_eq!(suite.schema, Schema::EddsaVerify);
        assert_eq!(suite.tests().count(), 210);
        assert_eq!(
            suite.groups.iter().filter(|g| g.key_jwk.is_none()).count(),
            33
        );
        for group in &suite.groups {
            let Some(PublicKey::Eddsa { curve, pk }) = &group.public_key else {
                panic!("no EdDSA public key");
            };
            assert_eq!(curve, "edwards25519");
            assert_eq!(pk.len(), 32);
        }
        let acceptable: Vec<&Test> = suite
            .tests()
            .filter(|(_, t)| t.result == Expected::Acceptable)
            .map(|(_, t)| t)
            .collect();
        assert_eq!(acceptable.len(), 29);
        for test in acceptable {
            assert!(
                test.has_flag("SmallOrderPublicKey") || test.has_flag("MixedOrderPublicKey"),
                "tcId {}: {:?}",
                test.tc_id,
                test.flags
            );
        }
    }

    #[test]
    fn json_web_signature_suite_has_jws_text_and_group_keys() {
        let suite = load("json_web_signature");
        assert_eq!(suite.schema, Schema::JsonWebSignature);
        assert_eq!(suite.groups.len(), 23);
        assert_eq!(suite.tests().count(), 401);
        assert_eq!(count(&suite, Expected::Valid), 46);
        assert_eq!(count(&suite, Expected::Invalid), 355);
        for group in &suite.groups {
            assert!(group.comment.is_some());
            let keys = group
                .jws_keys
                .as_ref()
                .unwrap_or_else(|| panic!("no JWS keys"));
            assert!(jwk_value(Some(&keys.private)).is_object());
            if let Some(public) = &keys.public {
                assert!(
                    jwk_value(Some(public)).get("d").is_none(),
                    "public JWK has d"
                );
            }
        }
        assert!(
            suite
                .groups
                .iter()
                .any(|g| g.jws_keys.as_ref().is_some_and(|k| k.public.is_none()))
        );
        // The empty string is one of the invalid inputs.
        let empty: Vec<&Test> = suite
            .tests()
            .map(|(_, t)| t)
            .filter(|t| t.jws().is_empty())
            .collect();
        assert!(!empty.is_empty() && empty.iter().all(|t| t.result == Expected::Invalid));
        // Both serializations are present (RFC 7515 §7.1, §7.2).
        assert!(suite.tests().any(|(_, t)| t.jws().starts_with('{')));
        assert!(suite.tests().any(|(_, t)| t.jws().starts_with("ey")));
    }

    #[test]
    fn input_accessors_reject_the_wrong_schema() {
        let suite = load("ed25519");
        let (_, test) = suite.tests().next().unwrap_or_else(|| panic!("no tests"));
        assert!(std::panic::catch_unwind(|| test.mac()).is_err());
        assert!(std::panic::catch_unwind(|| test.jws()).is_err());
        let _ = test.signature();
    }

    #[test]
    fn hex_decoding_is_strict() {
        assert_eq!(hex(""), Ok(vec![]));
        assert_eq!(hex("00ffA5"), Ok(vec![0x00, 0xff, 0xa5]));
        assert!(hex("0").is_err());
        assert!(hex("0g").is_err());
        assert!(hex(" 00").is_err());
        assert!(hex("+0").is_err());
    }

    /// A minimal `MacTest` file, with `{test}` replaced by one test object.
    fn mac_file(number_of_tests: usize, extra_group_member: &str, test: &str) -> String {
        format!(
            r#"{{"algorithm":"HMACSHA256","schema":"mac_test_schema_v1.json",
               "numberOfTests":{number_of_tests},"header":[],
               "notes":{{"Pseudorandom":{{"bugType":"FUNCTIONALITY","description":"d"}}}},
               "testGroups":[{{"type":"MacTest","source":{{}},"keySize":8,"tagSize":8,
               {extra_group_member}"tests":[{test}]}}]}}"#
        )
    }

    const GOOD_TEST: &str = r#"{"tcId":1,"comment":"","flags":["Pseudorandom"],"key":"00","msg":"","tag":"ff","result":"valid"}"#;

    fn parse_mac(text: &str) -> Result<Suite, String> {
        parse("hmac_sha256", Schema::Mac, Some("HMACSHA256"), text)
    }

    #[test]
    fn parse_accepts_a_minimal_file() {
        let suite = parse_mac(&mac_file(1, "", GOOD_TEST));
        let suite = suite.unwrap_or_else(|e| panic!("{e}"));
        let (_, test) = suite.tests().next().unwrap_or_else(|| panic!("no test"));
        assert_eq!(test.tc_id, 1);
        assert_eq!(test.mac(), (&[0x00][..], &[][..], &[0xff][..]));
    }

    #[test]
    fn parse_rejects_files_that_break_the_schema() {
        let cases = [
            (
                "unknown group member",
                mac_file(1, r#""surprise":1,"#, GOOD_TEST),
            ),
            ("wrong numberOfTests", mac_file(2, "", GOOD_TEST)),
            (
                "duplicate tcId",
                mac_file(2, "", &format!("{GOOD_TEST},{GOOD_TEST}")),
            ),
            (
                "undefined flag",
                mac_file(1, "", &GOOD_TEST.replace("Pseudorandom", "Nope")),
            ),
            (
                "bad hex",
                mac_file(1, "", &GOOD_TEST.replace(r#""ff""#, r#""f""#)),
            ),
            (
                "unknown result",
                mac_file(1, "", &GOOD_TEST.replace("valid", "maybe")),
            ),
            (
                "signature in a MAC file",
                mac_file(1, "", &GOOD_TEST.replace("tag", "sig")),
            ),
            (
                "missing key",
                mac_file(1, "", &GOOD_TEST.replace(r#""key":"00","#, "")),
            ),
            (
                "unknown test member",
                mac_file(1, "", &GOOD_TEST.replace("{", r#"{"x":1,"#)),
            ),
            (
                "public key in a MAC group",
                mac_file(
                    1,
                    r#""publicKey":{"modulus":"01","publicExponent":"03"},"#,
                    GOOD_TEST,
                ),
            ),
            (
                "wrong schema",
                mac_file(1, "", GOOD_TEST).replace("mac_test", "mac_tset"),
            ),
            (
                "wrong algorithm",
                mac_file(1, "", GOOD_TEST).replace("HMACSHA256", "HMACSHA1"),
            ),
            (
                "wrong group type",
                mac_file(1, "", GOOD_TEST).replace("MacTest", "Mac"),
            ),
        ];
        for (what, text) in cases {
            assert!(parse_mac(&text).is_err(), "{what} was accepted");
        }
    }

    #[test]
    fn load_rejects_unknown_names() {
        assert!(std::panic::catch_unwind(|| load("hmac_sha1")).is_err());
        assert!(std::panic::catch_unwind(|| names("nope")).is_err());
    }

    /// The members of `rebuilt` that are also in the file's JWK.
    fn assert_same_key(what: &str, file_jwk: &str, rebuilt: &str) {
        let file_jwk = jwk_value(Some(file_jwk));
        let rebuilt = jwk_value(Some(rebuilt));
        let members = rebuilt.as_object().map(|m| m.len()).unwrap_or_default();
        assert!(members >= 3, "{what}: {rebuilt}");
        for (name, value) in rebuilt.as_object().into_iter().flatten() {
            assert_eq!(&file_jwk[name], value, "{what}: member {name}");
        }
    }

    #[test]
    fn rebuilt_jwks_match_every_upstream_jwk() {
        let mut compared = 0;
        let mut rebuilt_only = 0;
        for name in names("rsa_")
            .into_iter()
            .chain(names("ecdsa_"))
            .chain(names("ed25519"))
        {
            let suite = load(name);
            for group in &suite.groups {
                let key = group
                    .public_key
                    .as_ref()
                    .unwrap_or_else(|| panic!("{name}: no key"));
                let rebuilt = key.to_jwk().unwrap_or_else(|e| panic!("{name}: {e}"));
                match &group.key_jwk {
                    Some(file_jwk) => {
                        assert_same_key(name, file_jwk, &rebuilt);
                        assert_eq!(&group.verification_jwk(), file_jwk);
                        compared += 1;
                    }
                    None => {
                        assert_eq!(group.verification_jwk(), rebuilt);
                        rebuilt_only += 1;
                    }
                }
            }
        }
        // 9 ECDSA groups per curve and 33 Ed25519 groups have no JWK.
        assert_eq!(rebuilt_only, 4 * 9 + 33);
        assert!(compared > 400, "{compared}");
    }

    #[test]
    fn jws_groups_verify_with_the_public_jwk_or_the_oct_key() {
        let suite = load("json_web_signature");
        for group in &suite.groups {
            let keys = group.jws_keys.as_ref().unwrap_or_else(|| panic!("no keys"));
            let jwk = group.verification_jwk();
            match &keys.public {
                Some(public) => assert_eq!(&jwk, public),
                None => {
                    assert_eq!(jwk, keys.private);
                    assert_eq!(jwk_value(Some(&jwk))["kty"], "oct");
                }
            }
        }
        let hmac = load("hmac_sha256");
        let group = &hmac.groups[0];
        assert!(std::panic::catch_unwind(|| group.verification_jwk()).is_err());
    }

    #[test]
    fn to_jwk_pads_coordinates_and_rejects_what_has_no_jwk_form() {
        let ec = |curve: &str, wx: Vec<u8>| PublicKey::Ec {
            curve: curve.to_owned(),
            wx,
            wy: vec![0x00, 0x01],
        };
        let jwk = ec("secp256r1", vec![0x00, 0xff])
            .to_jwk()
            .unwrap_or_default();
        let jwk = jwk_value(Some(&jwk));
        assert_eq!(jwk["crv"], "P-256");
        let x = Base64UrlUnpadded::decode_vec(jwk["x"].as_str().unwrap_or_default());
        let mut expected = vec![0; 31];
        expected.push(0xff);
        assert_eq!(x.ok(), Some(expected));
        assert!(ec("secp256r1", vec![1; 33]).to_jwk().is_err());
        assert!(
            ec("secp256r1", [vec![0], vec![1; 32]].concat())
                .to_jwk()
                .is_ok()
        );
        assert!(ec("brainpoolP256r1", vec![1]).to_jwk().is_err());
        let ed = |curve: &str, len: usize| PublicKey::Eddsa {
            curve: curve.to_owned(),
            pk: vec![9; len],
        };
        assert!(ed("edwards25519", 32).to_jwk().is_ok());
        assert!(ed("edwards25519", 31).to_jwk().is_err());
        assert!(ed("edwards448", 57).to_jwk().is_err());
        let rsa = PublicKey::Rsa {
            modulus: vec![0x00, 0xc1],
            public_exponent: vec![0x01, 0x00, 0x01],
        };
        let rsa = jwk_value(rsa.to_jwk().ok().as_deref());
        assert_eq!(rsa["n"], "wQ");
        assert_eq!(rsa["e"], "AQAB");
    }

    /// tcId 1 valid, 2 invalid, 3 acceptable, 4 valid.
    fn four_tests() -> Suite {
        let tests = [
            (1, "valid"),
            (2, "invalid"),
            (3, "acceptable"),
            (4, "valid"),
        ]
        .map(|(id, result)| {
            GOOD_TEST
                .replace(r#""tcId":1"#, &format!(r#""tcId":{id}"#))
                .replace(r#""valid""#, &format!("{result:?}"))
        })
        .join(",");
        parse_mac(&mac_file(4, "", &tests)).unwrap_or_else(|e| panic!("{e}"))
    }

    /// A verifier that accepts exactly the tcIds in `accepts`.
    fn accepting(accepts: &[u32]) -> impl FnMut(&Group, &Test) -> Outcome + '_ {
        move |_, test| {
            if accepts.contains(&test.tc_id) {
                Outcome::Accept
            } else {
                Outcome::Reject
            }
        }
    }

    const REASON: &str = "ADR 0026 §6: test policy";

    fn failures(deviations: &[Deviation], accepts: &[u32]) -> String {
        check(&four_tests(), deviations, accepting(accepts))
            .err()
            .unwrap_or_default()
            .join("\n")
    }

    #[test]
    fn check_passes_when_every_deviation_is_listed() {
        let deviations = [Deviation::tests(&[3], Outcome::Reject, REASON)];
        let summary = check(&four_tests(), &deviations, accepting(&[1, 4]));
        let expected = Summary {
            tests: 4,
            accepted: 2,
            rejected: 2,
            deviations: 1,
        };
        assert_eq!(summary, Ok(expected));
        // A policy that rejects a valid test, listed by range (3..=4).
        let deviations = [Deviation::range(3, 4, Outcome::Reject, "RFC 7518 §3.2: x")];
        let summary = check(&four_tests(), &deviations, accepting(&[1]));
        assert_eq!(summary.map(|s| s.deviations), Ok(2));
        // An acceptable test may be listed as accepted.
        let deviations = [Deviation::tests(&[3], Outcome::Accept, REASON)];
        assert!(check(&four_tests(), &deviations, accepting(&[1, 3, 4])).is_ok());
    }

    #[test]
    fn check_fails_on_unexplained_deviations() {
        let listed = [Deviation::tests(&[3], Outcome::Reject, REASON)];
        let cases: [(&[Deviation], &[u32], &str); 5] = [
            (
                &[],
                &[1, 4],
                "tcId 3 (\"\", flags [\"Pseudorandom\"], result Acceptable): acceptable test not in the deviation list (polyjose did Reject)",
            ),
            (&listed, &[1], "tcId 4"),
            (&listed, &[1, 2, 4], "tcId 2"),
            (
                &listed,
                &[1, 3, 4],
                "deviation list says Reject (ADR 0026 §6: test policy), polyjose did Accept",
            ),
            (&[], &[1, 2, 3, 4], "expected Reject, polyjose did Accept"),
        ];
        for (deviations, accepts, needle) in cases {
            let failures = failures(deviations, accepts);
            assert!(failures.contains(needle), "{needle:?} not in:\n{failures}");
            assert!(failures.starts_with("hmac_sha256: tcId"), "{failures}");
        }
        assert!(failures(&listed, &[1, 4]).is_empty());
        assert!(failures(&listed, &[1]).contains("unexplained deviation: expected Accept"));
    }

    #[test]
    fn check_fails_on_a_bad_deviation_list() {
        let ok = &[1, 4];
        let cases: [(Vec<Deviation>, &[u32], &str); 7] = [
            (
                vec![Deviation::tests(&[3], Outcome::Reject, "policy")],
                ok,
                "cites no RFC or ADR",
            ),
            (
                vec![Deviation::tests(&[3], Outcome::Reject, "see RFC x")],
                ok,
                "cites no RFC or ADR",
            ),
            (
                vec![Deviation::tests(&[], Outcome::Reject, REASON)],
                ok,
                "lists no tests",
            ),
            (
                vec![Deviation::range(3, 2, Outcome::Reject, REASON)],
                ok,
                "lists no tests",
            ),
            (
                vec![
                    Deviation::tests(&[3], Outcome::Reject, REASON),
                    Deviation::range(3, 3, Outcome::Reject, REASON),
                ],
                ok,
                "tcId 3 is in the deviation list twice",
            ),
            (
                vec![Deviation::range(3, 5, Outcome::Reject, REASON)],
                &[1],
                "deviation lists tcId 5, which is not in the suite",
            ),
            (
                vec![
                    Deviation::tests(&[3], Outcome::Reject, REASON),
                    Deviation::tests(&[1], Outcome::Accept, REASON),
                ],
                ok,
                "redundant deviation",
            ),
        ];
        for (deviations, accepts, needle) in cases {
            let failures = failures(&deviations, accepts);
            assert!(failures.contains(needle), "{needle:?} not in:\n{failures}");
        }
        let deviations = [
            Deviation::tests(&[3], Outcome::Reject, REASON),
            Deviation::tests(&[2], Outcome::Accept, REASON),
        ];
        let failures = failures(&deviations, &[1, 2, 4]);
        assert!(
            failures.contains("an invalid test can never be listed as Accept"),
            "{failures}"
        );
    }

    #[test]
    fn citations_need_a_number() {
        assert!(cites_rfc_or_adr("RFC 7518 §3.2: truncated"));
        assert!(cites_rfc_or_adr("rejected (ADR 0026 §6)"));
        assert!(!cites_rfc_or_adr("RFC: missing number"));
        assert!(!cites_rfc_or_adr("ADR"));
        assert!(!cites_rfc_or_adr("rfc 7518"));
    }

    #[test]
    fn assert_conforms_panics_with_every_failure() {
        let suite = four_tests();
        let summary = assert_conforms(
            &suite,
            &[Deviation::tests(&[3], Outcome::Accept, REASON)],
            accepting(&[1, 3, 4]),
        );
        assert_eq!((summary.accepted, summary.rejected), (3, 1));
        let panicked = std::panic::catch_unwind(|| assert_conforms(&suite, &[], accepting(&[2])));
        let message = panicked
            .err()
            .and_then(|e| e.downcast::<String>().ok())
            .map(|m| *m)
            .unwrap_or_default();
        assert!(
            message.starts_with("4 Wycheproof failure(s) in hmac_sha256:"),
            "{message}"
        );
    }

    #[test]
    fn outcome_of_a_result() {
        assert_eq!(Outcome::of(&Ok::<(), ()>(())), Outcome::Accept);
        assert_eq!(Outcome::of(&Err::<(), ()>(())), Outcome::Reject);
    }

    /// A verifier that follows `result` exactly passes every real suite once
    /// the `acceptable` tests are listed; this runs the whole path on the
    /// vendored files.
    #[test]
    fn check_runs_every_vendored_suite() {
        for name in names("") {
            let suite = load(name);
            let acceptable: Vec<u32> = suite
                .tests()
                .filter(|(_, t)| t.result == Expected::Acceptable)
                .map(|(_, t)| t.tc_id)
                .collect();
            let follow = |_: &Group, t: &Test| match t.result {
                Expected::Valid => Outcome::Accept,
                _ => Outcome::Reject,
            };
            // Until its acceptable tests are listed, a suite fails once per test.
            let failures = check(&suite, &[], follow).err().unwrap_or_default();
            assert_eq!(failures.len(), acceptable.len(), "{name}");
            // A family lists them as a const; a test may leak a runtime list.
            let listed: &'static [u32] = Vec::leak(acceptable.clone());
            let deviations = [Deviation::tests(listed, Outcome::Reject, REASON)];
            let deviations = if acceptable.is_empty() {
                &[][..]
            } else {
                &deviations[..]
            };
            let summary = assert_conforms(&suite, deviations, follow);
            assert_eq!(summary.tests, suite.tests().count(), "{name}");
            assert_eq!(summary.deviations, acceptable.len(), "{name}");
            let valid = suite
                .tests()
                .filter(|(_, t)| t.result == Expected::Valid)
                .count();
            assert_eq!(summary.accepted, valid, "{name}");
            assert_eq!(summary.rejected, summary.tests - valid, "{name}");
        }
    }
}
