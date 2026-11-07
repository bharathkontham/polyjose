//! Shared conformance vector runner (ADR 0008 layer 4), Rust side.
//!
//! Loads every `*.json` file under `conformance/vectors/` (recursively,
//! `third_party/` included), checks each against the rules of
//! `conformance/schema.json`, runs it through the public API and collects
//! every failure before failing. A failure message names the file and the
//! vector's `source`.
//!
//! The rules the WASM, Node, Kotlin and Swift runners must follow too
//! (conformance/README.md):
//!
//! - a schema-invalid vector fails the run;
//! - a vector whose `operation` the runner does not implement fails the run,
//!   whether the schema reserves the operation or not; nothing is skipped;
//! - an empty or missing vectors directory fails the run;
//! - for `jws.sign` and `jws.verify` (RFC 7515), the step order of
//!   conformance/README.md: JWK import, then headers or options, then the
//!   call, the first error being the outcome; and the round trip of a
//!   randomized signature (`verify_with`);
//! - for `jwe.encrypt` and `jwe.decrypt` (RFC 7516), the same step order,
//!   and the round trip of a randomized encryption (`decrypt_with`);
//! - for `keys.import_pem` and `keys.export_pem` (ADR 0018 §3), the PEM
//!   import gives the expected JWK, and the export, after the JWK import,
//!   gives the exact PEM text;
//! - for `keys.import_der`, `der_b64u` is decoded (a non-canonical value is
//!   a broken vector, never an outcome) and imported in the named `format`;
//!   `keys.export_der` gives the exact DER, as canonical base64url;
//! - for `keys.generate_for` (ADR 0018 §5), `alg` is resolved in the one
//!   RFC 7518 §7.1 registry, and a generated key, being random, is compared
//!   by its shape, after the runner checks it is private, has exactly the
//!   RFC members plus `alg`, and imports back unchanged;
//! - for `jwt.validate` and `jwt.issue` (RFC 7519), a fixed clock built
//!   from `now` and no other (ADR 0028 §4); the step order of
//!   conformance/README.md (`decrypt.key`, `decrypt`'s lists, `key` or
//!   `jwks`, the policy; or `key`, `claims`, `encrypt.key`, sign, encrypt),
//!   the first error, a JWK or JWK Set import error included, being the
//!   outcome; claims compared as JSON values; and an issued token checked
//!   exactly, or by validating it with `validate`;
//! - a success expectation lists exactly the outputs, so an optional one
//!   (`key_index`) can't be left out unnoticed;
//! - a vector whose optional top-level `features` names a cargo feature
//!   this build does not enable, or whose `features_absent` names one it
//!   enables (ADR 0056), is reported **SKIPPED**, with the feature names;
//!   it is never counted as passing.
//!
//! The schema is enforced by a strict hand-written check (no JSON Schema
//! crate, ADR 0016). `schema_and_runner_agree` parses `schema.json` and
//! fails if its operations, member names, member kinds, `required` lists,
//! `allOf` signer rules, patterns or error codes drift from the tables
//! below. `jws_and_keys_vectors_are_binding_ready`, `jwe_vectors_are_binding_ready`
//! and `jwt_vectors_are_binding_ready` check that every JWS, JWE, keys and
//! JWT vector is readable unchanged by every binding's JSON parser. Vector files are
//! parsed with
//! polyjose's own `json` module, and their inputs reach the library through
//! it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};

use polyjose::Error;
use polyjose::header::Header;
use polyjose::json::{self, Number, Object, Value};
use polyjose::jwa::{ContentEncAlg, KeyMgmtAlg, SigningAlg};
use polyjose::jwe::{self, DecryptPolicy, Encryptor, JsonForm, Recipient};
use polyjose::jwk::{EcCurve, Jwk, JwkSet, OkpCurve};
use polyjose::jws::{self, ProtectedHeader, SignOptions, Signer, VerifyOptions};
use polyjose::jwt::{self, Claims, FixedClock, IssueOptions, Keys, Policy, VerifiedJwt};
use polyjose::keys::{JoseAlg, KeyFormat, KeySpec, generate, generate_for};
use polyjose::util::{b64url_decode, b64url_encode};

/// Top-level members of a vector; all required (schema `required`).
const TOP_LEVEL: &[&str] = &["source", "description", "operation", "input", "expect"];

/// The optional top-level members, after [`TOP_LEVEL`] in the schema's
/// `properties`.
const TOP_LEVEL_OPTIONAL: &[&str] = &["features", "features_absent"];

/// The names a vector's top-level `features` may list, each with the cargo
/// feature of `polyjose` it stands for. A vector needing one this build
/// does not enable is SKIPPED, naming the cargo feature, never passed.
///
/// The test RNG feature is written `fixed-rng` in vector files:
/// `scripts/check-test-vectors-off.sh` allows its cargo name only in
/// `crates/polyjose`, the script and Markdown, so that no file outside the
/// core can switch it on (ADR 0005), and vector JSON is not exempt.
const FEATURES: &[(&str, &str)] = &[
    ("deflate", "deflate"),
    ("fixed-rng", "insecure-test-vectors"),
];

/// The cargo feature a [`FEATURES`] name stands for.
fn cargo_feature(name: &str) -> &'static str {
    FEATURES
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, cargo)| *cargo)
        .expect("a validated features name")
}

/// The [`FEATURES`] names whose cargo feature this build enables.
fn enabled_features() -> Vec<&'static str> {
    let mut enabled = Vec::new();
    if cfg!(feature = "deflate") {
        enabled.push("deflate");
    }
    if cfg!(feature = "insecure-test-vectors") {
        enabled.push("fixed-rng");
    }
    enabled
}

/// The vector-file names of [`FEATURES`], in schema order.
fn feature_names() -> Vec<&'static str> {
    FEATURES.iter().map(|(name, _)| *name).collect()
}

/// Every operation `schema.json` names, in schema order. Only those with an
/// [`OpSpec`] have a defined input and expectation; the others are reserved
/// for the features that will define them.
const OPERATIONS: &[&str] = &[
    "b64url.encode",
    "b64url.decode",
    "jwk.thumbprint",
    "jws.sign",
    "jws.verify",
    "keys.import_pem",
    "keys.export_pem",
    "keys.import_der",
    "keys.export_der",
    "keys.generate_for",
    "keys.generate_oct",
    "keys.generate_ec",
    "keys.generate_okp",
    "jwe.encrypt",
    "jwe.decrypt",
    "jwt.validate",
    "jwt.issue",
];

/// `$defs/hex/pattern`: lowercase hex, two digits per octet.
const HEX_PATTERN: &str = "^([0-9a-f]{2})*$";
/// `$defs/base64url/pattern`: the RFC 4648 §5 alphabet, no padding.
const BASE64URL_PATTERN: &str = "^[A-Za-z0-9_-]*$";
/// `$defs/text/pattern`: at least one non-whitespace character.
const TEXT_PATTERN: &str = "\\S";
/// `$defs/count/maximum`: an unsigned 32-bit integer (ADR 0030 `u32`), so
/// every binding holds a count natively and exactly.
const COUNT_MAX: u64 = u32::MAX as u64;
/// `$defs/seconds/maximum` (and, negated, `minimum`): 2^53 − 1, the
/// NumericDate and clock range (RFC 7493 §2.2; ADR 0027 §2, ADR 0028 §1),
/// which every binding holds exactly, JavaScript's numbers included.
const SECONDS_MAX: i64 = 9_007_199_254_740_991;

/// What a member's value must be. Each kind maps to one schema spelling
/// (see `schema_kind`).
#[derive(Debug, Clone, Copy)]
enum Kind {
    /// `{"$ref": "#/$defs/hex"}`
    Hex,
    /// `{"$ref": "#/$defs/base64url"}`
    Base64url,
    /// `{"type": "string"}`
    String,
    /// `{"type": "object"}`
    Object,
    /// `{"enum": [...]}` of strings
    Enum(&'static [&'static str]),
    /// `{"$ref": "#/$defs/count"}`: an integer in `0..=COUNT_MAX`
    Count,
    /// `{"$ref": "#/$defs/jws"}`: a string (compact) or an object (JSON)
    Jws,
    /// `{"$ref": "#/$defs/alg_list"}`: an array of strings
    AlgList,
    /// `{"$ref": "#/$defs/jwe"}`: a string (compact) or an object (JSON)
    Jwe,
    /// `{"type": "array", "items": {"type": "string"}}`
    StringList,
    /// `{"type": "boolean"}`
    Bool,
    /// `{"$ref": "#/$defs/<def>"}` of a closed object definition
    Nested(&'static Shape),
    /// `{"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/<def>"}}`
    List(&'static Shape),
    /// `{"$ref": "#/$defs/seconds"}`: an integer in `-SECONDS_MAX..=SECONDS_MAX`
    Seconds,
    /// `{"type": ["string", "array"], "items": {"type": "string"}}`
    StringOrList,
    /// `{"type": ["string", "null"]}`
    StringOrNull,
}

impl Kind {
    /// The shared `$defs` entry a `$ref` kind points at.
    fn def(self) -> Option<&'static str> {
        match self {
            Kind::Hex => Some("hex"),
            Kind::Base64url => Some("base64url"),
            Kind::Count => Some("count"),
            Kind::Jws => Some("jws"),
            Kind::AlgList => Some("alg_list"),
            Kind::Jwe => Some("jwe"),
            Kind::Nested(shape) => Some(shape.def),
            Kind::Seconds => Some("seconds"),
            Kind::String
            | Kind::Object
            | Kind::Enum(_)
            | Kind::Bool
            | Kind::List(_)
            | Kind::StringList
            | Kind::StringOrList
            | Kind::StringOrNull => None,
        }
    }
}

/// One member of a [`Shape`].
#[derive(Debug)]
struct Member {
    name: &'static str,
    kind: Kind,
    /// Listed in the definition's `required`.
    required: bool,
}

/// A required member.
const fn req(name: &'static str, kind: Kind) -> Member {
    Member {
        name,
        kind,
        required: true,
    }
}

/// An optional member.
const fn opt(name: &'static str, kind: Kind) -> Member {
    Member {
        name,
        kind,
        required: false,
    }
}

/// A closed object definition in `$defs` (`additionalProperties: false`):
/// the listed members, no others, and its `allOf` rules.
#[derive(Debug)]
struct Shape {
    /// Its name under `$defs`.
    def: &'static str,
    members: &'static [Member],
    /// Its `allOf` rules, in schema order.
    rules: &'static [Rule],
}

/// One entry of a closed definition's `allOf`: a constraint across its
/// members, which the per-member kinds cannot say.
#[derive(Debug)]
enum Rule {
    /// The per-serialization signer limits of `jws_sign_input`.
    Signers(SignerRule),
    /// Exactly one of these members is present. In the schema:
    ///
    /// ```json
    /// {"oneOf": [{"required": ["key"]}, {"required": ["jwks"]}]}
    /// ```
    ExactlyOne(&'static [&'static str]),
    /// `dependent` is required when `member` is `value`, and not allowed
    /// otherwise. In the schema:
    ///
    /// ```json
    /// {"if": {"properties": {"mode": {"const": "exact"}}},
    ///  "then": {"required": ["value"]},
    ///  "else": {"properties": {"value": false}}}
    /// ```
    OnlyWhen {
        member: &'static str,
        value: &'static str,
        dependent: &'static str,
    },
}

/// One `allOf` rule of `jws_sign_input`: when `serialization` is
/// `serialization`, `signers` has at most `max_signers` entries, each with
/// every `requires` member and none of the `forbids` members. In the
/// schema:
///
/// ```json
/// {"if": {"properties": {"serialization": {"const": "compact"}}},
///  "then": {"properties": {"signers": {"maxItems": 1,
///    "items": {"required": ["protected_b64u"], "properties": {"header": false}}}}}}
/// ```
#[derive(Debug)]
struct SignerRule {
    serialization: &'static str,
    max_signers: usize,
    requires: &'static [&'static str],
    forbids: &'static [&'static str],
}

/// The input and success shapes of an operation (schema `$defs`).
#[derive(Debug)]
struct OpSpec {
    name: &'static str,
    input: &'static Shape,
    /// The success expectations; `"ok": true` is implicit in each. With
    /// more than one, a vector matches exactly one (schema `oneOf`).
    ok: &'static [&'static Shape],
    /// Whether `{"ok": false, "error": <code>}` is allowed.
    can_fail: bool,
}

// RFC 7515 §2 base64url encoding (RFC 4648 §5, no padding).
const B64URL_ENCODE_INPUT: Shape = Shape {
    def: "b64url_encode_input",
    members: &[req("bytes_hex", Kind::Hex)],
    rules: &[],
};
const B64URL_ENCODE_OK: Shape = Shape {
    def: "b64url_encode_ok",
    members: &[req("b64u", Kind::Base64url)],
    rules: &[],
};
// RFC 7515 §2 decoding; non-canonical input is rejected (RFC 4648 §3.5).
const B64URL_DECODE_INPUT: Shape = Shape {
    def: "b64url_decode_input",
    members: &[req("b64u", Kind::String)],
    rules: &[],
};
const B64URL_DECODE_OK: Shape = Shape {
    def: "b64url_decode_ok",
    members: &[req("bytes_hex", Kind::Hex)],
    rules: &[],
};
// RFC 7638 §3 JWK Thumbprint and RFC 9278 §3 JWK Thumbprint URI.
const JWK_THUMBPRINT_INPUT: Shape = Shape {
    def: "jwk_thumbprint_input",
    members: &[
        req("jwk", Kind::Object),
        req("hash", Kind::Enum(&["sha-256"])),
    ],
    rules: &[],
};
const JWK_THUMBPRINT_OK: Shape = Shape {
    def: "jwk_thumbprint_ok",
    members: &[
        req("thumbprint", Kind::Base64url),
        req("thumbprint_uri", Kind::String),
    ],
    rules: &[],
};

// RFC 7515 §5.2 validation through `jws::verify_compact` (a string `jws`,
// RFC 7515 §7.1) or `jws::verify_json` (an object, §7.2), with the
// options of ADR 0026: allow-list, detached payload (Appendix F), limits.
const JWS_VERIFY_INPUT: Shape = Shape {
    def: "jws_verify_input",
    members: &[
        req("jws", Kind::Jws),
        req("key", Kind::Object),
        req("allowed_algs", Kind::AlgList),
        opt("detached_payload_b64u", Kind::Base64url),
        opt("max_input_len", Kind::Count),
        opt("max_signatures", Kind::Count),
    ],
    rules: &[],
};
const JWS_VERIFY_OK: Shape = Shape {
    def: "jws_verify_ok",
    members: &[
        req("payload_b64u", Kind::Base64url),
        req("alg", Kind::String),
        req("signature_index", Kind::Count),
    ],
    rules: &[],
};

/// The signer of a `jws.sign` vector: its JWS Protected Header as exact
/// octets (RFC 7515 §5.1 step 3; RFC 7515 A.1's CRLF header can only be
/// given this way), its JWS Unprotected Header (§7.2.1), and its key.
const JWS_SIGNER: Shape = Shape {
    def: "jws_signer",
    members: &[
        opt("protected_b64u", Kind::Base64url),
        opt("header", Kind::Object),
        req("key", Kind::Object),
    ],
    rules: &[],
};
// RFC 7515 §5.1 through `jws::sign_compact` (§7.1), `jws::sign_flattened`
// (§7.2.2) or `jws::sign_general` (§7.2.1), attached or detached
// (Appendix F).
const JWS_SIGN_INPUT: Shape = Shape {
    def: "jws_sign_input",
    members: &[
        req(
            "serialization",
            Kind::Enum(&["compact", "flattened", "general"]),
        ),
        req("payload_b64u", Kind::Base64url),
        req("detached", Kind::Bool),
        req("signers", Kind::List(&JWS_SIGNER)),
    ],
    rules: &[
        // RFC 7515 §7.1: one signature over a JWS Protected Header only.
        Rule::Signers(SignerRule {
            serialization: "compact",
            max_signers: 1,
            requires: &["protected_b64u"],
            forbids: &["header"],
        }),
        // RFC 7515 §7.2.2: one signature.
        Rule::Signers(SignerRule {
            serialization: "flattened",
            max_signers: 1,
            requires: &[],
            forbids: &[],
        }),
    ],
};
/// A deterministic signature's exact output: a string for compact, an
/// object for JSON, compared as JSON values (member order ignored,
/// RFC 8259 §4).
const JWS_SIGN_EXACT: Shape = Shape {
    def: "jws_sign_exact",
    members: &[req("jws", Kind::Jws)],
    rules: &[],
};
const JWS_VERIFY_WITH: Shape = Shape {
    def: "jws_verify_with",
    members: &[req("key", Kind::Object), req("allowed_algs", Kind::AlgList)],
    rules: &[],
};
/// A randomized signature (ECDSA): the runner verifies its own output with
/// `verify_with` and checks the payload, instead of comparing bytes.
const JWS_SIGN_ROUND_TRIP: Shape = Shape {
    def: "jws_sign_roundtrip",
    members: &[req("verify_with", Kind::Nested(&JWS_VERIFY_WITH))],
    rules: &[],
};

// ---------------------------------------------------------------------------
// jwe.* shapes (RFC 7516). Kept apart from the jws.* ones so later edits to
// either merge mechanically.
// ---------------------------------------------------------------------------

/// One recipient of a `jwe.encrypt` vector (RFC 7516 §5.1 steps 1-8): its
/// `alg`, its key, its Per-Recipient Unprotected Header (§7.2.1, JSON only)
/// and the key management options of RFC 7518 §4.6.1.2-§4.6.1.3 (`apu`,
/// `apv`) and §4.8.1.1-§4.8.1.2 (`p2s` length, `p2c`).
const JWE_RECIPIENT: Shape = Shape {
    def: "jwe_recipient",
    members: &[
        req("alg", Kind::String),
        req("key", Kind::Object),
        opt("header", Kind::Object),
        opt("apu_b64u", Kind::Base64url),
        opt("apv_b64u", Kind::Base64url),
        opt("p2c", Kind::Count),
        opt("p2s_len", Kind::Count),
    ],
    rules: &[],
};
// RFC 7516 §5.1 through `Encryptor::encrypt_compact` (§7.1),
// `encrypt_json` (§7.2), or, with `rng_b64u` or `protected_b64u`,
// `encrypt_reproducible` (feature `insecure-test-vectors`).
const JWE_ENCRYPT_INPUT: Shape = Shape {
    def: "jwe_encrypt_input",
    members: &[
        req(
            "serialization",
            Kind::Enum(&["compact", "flattened", "general"]),
        ),
        req("enc", Kind::String),
        req("plaintext_b64u", Kind::Base64url),
        req("recipients", Kind::List(&JWE_RECIPIENT)),
        opt("protected", Kind::Object),
        opt("protected_b64u", Kind::Base64url),
        opt("unprotected", Kind::Object),
        opt("aad_b64u", Kind::Base64url),
        opt("compress", Kind::Bool),
        opt("rng_b64u", Kind::Base64url),
    ],
    rules: &[],
};
/// A reproducible encryption's exact output: a string for compact, an
/// object for JSON, compared as JSON values (member order ignored,
/// RFC 8259 §4).
const JWE_ENCRYPT_EXACT: Shape = Shape {
    def: "jwe_encrypt_exact",
    members: &[req("jwe", Kind::Jwe)],
    rules: &[],
};
const JWE_DECRYPT_WITH: Shape = Shape {
    def: "jwe_decrypt_with",
    members: &[
        req("key", Kind::Object),
        req("allowed_algs", Kind::AlgList),
        req("allowed_enc", Kind::AlgList),
    ],
    rules: &[],
};
/// A randomized encryption: the runner decrypts its own output with
/// `decrypt_with` and checks the plaintext, instead of comparing bytes.
const JWE_ENCRYPT_ROUND_TRIP: Shape = Shape {
    def: "jwe_encrypt_roundtrip",
    members: &[req("decrypt_with", Kind::Nested(&JWE_DECRYPT_WITH))],
    rules: &[],
};
// RFC 7516 §5.2 through `jwe::decrypt_compact` (a string `jwe`, §7.1) or
// `jwe::decrypt_json` (an object, §7.2), with a `DecryptPolicy` (RFC 8725
// §3.1, ADR 0007, ADR 0023, ADR 0017, ADR 0026 §7).
const JWE_DECRYPT_INPUT: Shape = Shape {
    def: "jwe_decrypt_input",
    members: &[
        req("jwe", Kind::Jwe),
        req("key", Kind::Object),
        req("allowed_algs", Kind::AlgList),
        req("allowed_enc", Kind::AlgList),
        opt("understood_crit", Kind::StringList),
        opt("max_input_len", Kind::Count),
        opt("max_recipients", Kind::Count),
        opt("max_pbes2_count", Kind::Count),
        opt("max_decompressed_len", Kind::Count),
    ],
    rules: &[],
};
const JWE_DECRYPT_OK: Shape = Shape {
    def: "jwe_decrypt_ok",
    members: &[
        req("plaintext_b64u", Kind::Base64url),
        req("recipient", Kind::Count),
    ],
    rules: &[],
};

// ADR 0018 §3 PEM import through `Jwk::from_pem`: the label selects the
// structure (RFC 7468 §2), the key type comes from the DER.
const KEYS_IMPORT_PEM_INPUT: Shape = Shape {
    def: "keys_import_pem_input",
    members: &[req("pem", Kind::String)],
    rules: &[],
};
/// The imported JWK, compared as a JSON value (member order ignored).
const KEYS_IMPORT_PEM_OK: Shape = Shape {
    def: "keys_import_pem_ok",
    members: &[req("jwk", Kind::Object)],
    rules: &[],
};
/// The `format` names of the keys.* operations, in schema order, and the
/// library format each selects.
const KEY_FORMATS: &[(&str, KeyFormat)] = &[
    ("pkcs8", KeyFormat::Pkcs8),
    ("sec1", KeyFormat::Sec1),
    ("spki", KeyFormat::Spki),
    ("pkcs1", KeyFormat::Pkcs1),
];
/// The `format` enum of the keys.* operations: the names of [`KEY_FORMATS`].
const KEY_FORMAT_NAMES: &[&str] = &["pkcs8", "sec1", "spki", "pkcs1"];
// ADR 0018 §3 PEM export through `Jwk::from_object` then `Jwk::to_pem`.
const KEYS_EXPORT_PEM_INPUT: Shape = Shape {
    def: "keys_export_pem_input",
    members: &[
        req("jwk", Kind::Object),
        req("format", Kind::Enum(KEY_FORMAT_NAMES)),
    ],
    rules: &[],
};
/// The exact PEM text, compared as a string.
const KEYS_EXPORT_PEM_OK: Shape = Shape {
    def: "keys_export_pem_ok",
    members: &[req("pem", Kind::String)],
    rules: &[],
};
// ADR 0018 §3 DER import through `Jwk::from_der`: the caller names the
// structure, there is no format sniffing (ADR 0007), and the key type comes
// from the DER (ADR 0018 §2).
const KEYS_IMPORT_DER_INPUT: Shape = Shape {
    def: "keys_import_der_input",
    members: &[
        req("der_b64u", Kind::Base64url),
        req("format", Kind::Enum(KEY_FORMAT_NAMES)),
    ],
    rules: &[],
};
/// The imported JWK, compared as a JSON value (member order ignored).
const KEYS_IMPORT_DER_OK: Shape = Shape {
    def: "keys_import_der_ok",
    members: &[req("jwk", Kind::Object)],
    rules: &[],
};
// ADR 0018 §3 DER export through `Jwk::from_object` then `Jwk::to_der`.
const KEYS_EXPORT_DER_INPUT: Shape = Shape {
    def: "keys_export_der_input",
    members: &[
        req("jwk", Kind::Object),
        req("format", Kind::Enum(KEY_FORMAT_NAMES)),
    ],
    rules: &[],
};
/// The exact DER, as canonical base64url, compared as a string.
const KEYS_EXPORT_DER_OK: Shape = Shape {
    def: "keys_export_der_ok",
    members: &[req("der_b64u", Kind::Base64url)],
    rules: &[],
};
// ADR 0018 §5 generation through `keys::generate_for`: a JWS `alg`, a JWE
// `alg` or a JWE `enc` name, any string (unknown names are under test).
const KEYS_GENERATE_FOR_INPUT: Shape = Shape {
    def: "keys_generate_for_input",
    members: &[req("alg", Kind::String)],
    rules: &[],
};
/// What a generated key is, without its random material: `kty`, `crv`
/// (EC and OKP), the `alg` it is bound to (RFC 7517 §4.4) and the length
/// of `k` in octets (`oct`). Compared as a JSON value, so a member the
/// generated key has and the vector omits fails too.
const KEYS_GENERATED_SHAPE: Shape = Shape {
    def: "keys_generated_shape",
    members: &[
        req("kty", Kind::Enum(&["EC", "OKP", "oct"])),
        opt("crv", Kind::String),
        req("alg", Kind::String),
        opt("k_octets", Kind::Count),
    ],
    rules: &[],
};
/// A generated key is random, so only its shape is expected; the runner
/// checks the rest itself (see [`generated_shape`]).
const KEYS_GENERATE_FOR_OK: Shape = Shape {
    def: "keys_generate_for_ok",
    members: &[
        req("shape", Kind::Nested(&KEYS_GENERATED_SHAPE)),
        opt("use_with", Kind::Nested(&KEYS_USE_WITH)),
    ],
    rules: &[],
};
/// A use round trip of a generated key (ADR 0034 §6), checked by the
/// runner (see [`check_use_with`]): a JWS `alg` alone, or a JWE `alg` and
/// `enc`.
const KEYS_USE_WITH: Shape = Shape {
    def: "keys_use_with",
    members: &[req("alg", Kind::String), opt("enc", Kind::String)],
    rules: &[],
};
// ADR 0018 §5 generation through `keys::generate` (ADR 0030
// `jwk_generate_oct`, `jwk_generate_ec`, `jwk_generate_okp`): an `oct` key
// of `len_bytes` octets (RFC 7518 §6.4.1), or a key pair on a curve
// polyjose generates (RFC 7518 §6.2, RFC 8812 §3.1, RFC 8037 §2).
const KEYS_GENERATE_OCT_INPUT: Shape = Shape {
    def: "keys_generate_oct_input",
    members: &[req("len_bytes", Kind::Count)],
    rules: &[],
};
/// The EC curves of [`EC_CURVES`], by their RFC 7518 §6.2.1.1 names.
const EC_CURVE_NAMES: &[&str] = &["P-256", "P-384", "P-521", "secp256k1"];
const KEYS_GENERATE_EC_INPUT: Shape = Shape {
    def: "keys_generate_ec_input",
    members: &[req("crv", Kind::Enum(EC_CURVE_NAMES))],
    rules: &[],
};
/// The OKP curves of [`OKP_CURVES`], by their RFC 8037 §2 names.
const OKP_CURVE_NAMES: &[&str] = &["Ed25519", "X25519"];
const KEYS_GENERATE_OKP_INPUT: Shape = Shape {
    def: "keys_generate_okp_input",
    members: &[req("crv", Kind::Enum(OKP_CURVE_NAMES))],
    rules: &[],
};
/// What a key of `keys::generate` is, without its random material: as
/// [`KEYS_GENERATED_SHAPE`], without `alg` (such a key is bound to none).
const KEYS_GENERATED_KEY: Shape = Shape {
    def: "keys_generated_key",
    members: &[
        req("kty", Kind::Enum(&["EC", "OKP", "oct"])),
        opt("crv", Kind::String),
        opt("k_octets", Kind::Count),
    ],
    rules: &[],
};
/// A generated key's shape and its use round trip, both required.
const KEYS_GENERATE_OK: Shape = Shape {
    def: "keys_generate_ok",
    members: &[
        req("shape", Kind::Nested(&KEYS_GENERATED_KEY)),
        req("use_with", Kind::Nested(&KEYS_USE_WITH)),
    ],
    rules: &[],
};

// ---------------------------------------------------------------------------
// jwt.* shapes (RFC 7519; ADR 0027, ADR 0028, ADR 0029). Platform-neutral:
// every member is a JSON value each binding's own validate call takes as
// is, with no Rust type in it.
// ---------------------------------------------------------------------------

/// How `typ` is checked (RFC 7515 §4.1.9, RFC 8725 §3.11–§3.12;
/// ADR 0027 §5): `default` (absent or `JWT`), `exact` (`value` required),
/// or `any` (no check). `value` is allowed with `exact` only.
const JWT_TYP: Shape = Shape {
    def: "jwt_typ",
    members: &[
        req("mode", Kind::Enum(&["default", "exact", "any"])),
        opt("value", Kind::String),
    ],
    rules: &[Rule::OnlyWhen {
        member: "mode",
        value: "exact",
        dependent: "value",
    }],
};
/// The JWT validation policy (RFC 7519 §4.1, §7.2; RFC 8725 §3; ADR 0027
/// §3–§5, ADR 0029 §4). Every member is optional; an absent member keeps
/// the library default, which the runner never restates.
const JWT_POLICY: Shape = Shape {
    def: "jwt_policy",
    members: &[
        // RFC 7519 §4.1.1, RFC 8725 §3.8: one accepted issuer or a list.
        opt("issuer", Kind::StringOrList),
        // RFC 7519 §4.1.3, RFC 8725 §3.9.
        opt("audience", Kind::StringList),
        // RFC 7519 §4.1.2.
        opt("subject", Kind::String),
        // RFC 7519 §4.1.4-§4.1.5: whole seconds, at most 600 (ADR 0027 §3).
        opt("leeway", Kind::Count),
        // RFC 7519 §4.1.6: makes `iat` required (ADR 0027 §3).
        opt("max_age", Kind::Count),
        // RFC 7519 §4: required claim names (ADR 0027 §4).
        opt("require", Kind::StringList),
        // ADR 0007, ADR 0027 §3: the explicit opt-out of a required `exp`.
        opt("allow_missing_exp", Kind::Bool),
        // RFC 7519 §4.1.3, ADR 0027 §4: the explicit opt-out.
        opt("ignore_audience", Kind::Bool),
        opt("typ", Kind::Nested(&JWT_TYP)),
        // RFC 9068 §4 (ADR 0027 §5).
        opt("profile", Kind::Enum(&["access_token"])),
        // ADR 0029 §4.
        opt("max_key_candidates", Kind::Count),
    ],
    rules: &[],
};
/// The outer JWE layer of a nested JWT (RFC 7519 §5.2, §7.2 step 8;
/// RFC 8725 §3.3; ADR 0027 §7): the caller's decryption key and both
/// allow-lists, and the PBES2 bound (ADR 0023).
const JWT_DECRYPT: Shape = Shape {
    def: "jwt_decrypt",
    members: &[
        req("key", Kind::Object),
        req("allowed_algs", Kind::AlgList),
        req("allowed_enc", Kind::AlgList),
        opt("max_pbes2_count", Kind::Count),
    ],
    rules: &[],
};
// RFC 7519 §7.2 through `jwt::verify`, or `jwt::decrypt_nested` with
// `decrypt`: the time `now` as a FixedClock (ADR 0028 §4), the allow-list
// (RFC 8725 §3.1), and exactly one key source (ADR 0029 §1).
const JWT_VALIDATE_INPUT: Shape = Shape {
    def: "jwt_validate_input",
    members: &[
        req("token", Kind::String),
        req("now", Kind::Seconds),
        req("allowed_algs", Kind::AlgList),
        opt("key", Kind::Object),
        opt("jwks", Kind::Object),
        opt("policy", Kind::Nested(&JWT_POLICY)),
        opt("decrypt", Kind::Nested(&JWT_DECRYPT)),
    ],
    rules: &[Rule::ExactlyOne(&["key", "jwks"])],
};
/// The validated JWT: its Claims Set (compared as a JSON value: member
/// order ignored, numbers as doubles), the `alg` that verified, and, when
/// verified through `jwks`, the index of the member that did (ADR 0029
/// §4). `key_index` is present exactly when the input has `jwks`.
const JWT_VALIDATE_OK: Shape = Shape {
    def: "jwt_validate_ok",
    members: &[
        req("claims", Kind::Object),
        req("alg", Kind::String),
        opt("key_index", Kind::Count),
    ],
    rules: &[],
};
/// How a `jwt.issue` vector validates the token it issued: the members of
/// [`JWT_VALIDATE_INPUT`] other than `token`, with the same rules.
const JWT_ISSUE_VALIDATE: Shape = Shape {
    def: "jwt_issue_validate",
    members: &[
        req("now", Kind::Seconds),
        req("allowed_algs", Kind::AlgList),
        opt("key", Kind::Object),
        opt("jwks", Kind::Object),
        opt("policy", Kind::Nested(&JWT_POLICY)),
        opt("decrypt", Kind::Nested(&JWT_DECRYPT)),
    ],
    rules: &[Rule::ExactlyOne(&["key", "jwks"])],
};
/// The JWE layer of a nested JWT to issue (RFC 7519 §7.1 step 5, §11.2;
/// ADR 0027 §7): one recipient's key management `alg`, its JWK, and the
/// content encryption `enc`.
const JWT_ENCRYPT: Shape = Shape {
    def: "jwt_encrypt",
    members: &[
        req("alg", Kind::String),
        req("enc", Kind::String),
        req("key", Kind::Object),
    ],
    rules: &[],
};
// RFC 7519 §7.1 through `jwt::sign` (ADR 0027 §8), then, with `encrypt`,
// `jwt::encrypt_nested` (§7). `typ`: absent is the library default (JWT),
// a string sets it, null omits it (RFC 7519 §5.1).
const JWT_ISSUE_INPUT: Shape = Shape {
    def: "jwt_issue_input",
    members: &[
        req("claims", Kind::Object),
        req("alg", Kind::String),
        req("key", Kind::Object),
        opt("typ", Kind::StringOrNull),
        opt("encrypt", Kind::Nested(&JWT_ENCRYPT)),
        opt("validate", Kind::Nested(&JWT_ISSUE_VALIDATE)),
    ],
    rules: &[],
};
/// A deterministic signed JWT's exact token (HMAC, EdDSA; RFC 7515 §7.1),
/// compared as a string.
const JWT_ISSUE_EXACT: Shape = Shape {
    def: "jwt_issue_exact",
    members: &[req("token", Kind::String)],
    rules: &[],
};
/// A token the runner checks itself: its compact shape, and the round trip
/// through `validate` (see [`check_jwt_issue`] for when that is required).
const JWT_ISSUE_VALIDATED: Shape = Shape {
    def: "jwt_issue_validated",
    members: &[],
    rules: &[],
};

/// The operations this runner implements.
const SPECS: &[OpSpec] = &[
    OpSpec {
        name: "b64url.encode",
        input: &B64URL_ENCODE_INPUT,
        ok: &[&B64URL_ENCODE_OK],
        can_fail: false,
    },
    OpSpec {
        name: "b64url.decode",
        input: &B64URL_DECODE_INPUT,
        ok: &[&B64URL_DECODE_OK],
        can_fail: true,
    },
    OpSpec {
        name: "jwk.thumbprint",
        input: &JWK_THUMBPRINT_INPUT,
        ok: &[&JWK_THUMBPRINT_OK],
        can_fail: true,
    },
    OpSpec {
        name: "jws.sign",
        input: &JWS_SIGN_INPUT,
        ok: &[&JWS_SIGN_EXACT, &JWS_SIGN_ROUND_TRIP],
        can_fail: true,
    },
    OpSpec {
        name: "jws.verify",
        input: &JWS_VERIFY_INPUT,
        ok: &[&JWS_VERIFY_OK],
        can_fail: true,
    },
    OpSpec {
        name: "jwe.encrypt",
        input: &JWE_ENCRYPT_INPUT,
        ok: &[&JWE_ENCRYPT_EXACT, &JWE_ENCRYPT_ROUND_TRIP],
        can_fail: true,
    },
    OpSpec {
        name: "jwe.decrypt",
        input: &JWE_DECRYPT_INPUT,
        ok: &[&JWE_DECRYPT_OK],
        can_fail: true,
    },
    OpSpec {
        name: "keys.import_pem",
        input: &KEYS_IMPORT_PEM_INPUT,
        ok: &[&KEYS_IMPORT_PEM_OK],
        can_fail: true,
    },
    OpSpec {
        name: "keys.export_pem",
        input: &KEYS_EXPORT_PEM_INPUT,
        ok: &[&KEYS_EXPORT_PEM_OK],
        can_fail: true,
    },
    OpSpec {
        name: "keys.import_der",
        input: &KEYS_IMPORT_DER_INPUT,
        ok: &[&KEYS_IMPORT_DER_OK],
        can_fail: true,
    },
    OpSpec {
        name: "keys.export_der",
        input: &KEYS_EXPORT_DER_INPUT,
        ok: &[&KEYS_EXPORT_DER_OK],
        can_fail: true,
    },
    OpSpec {
        name: "keys.generate_for",
        input: &KEYS_GENERATE_FOR_INPUT,
        ok: &[&KEYS_GENERATE_FOR_OK],
        can_fail: true,
    },
    OpSpec {
        name: "keys.generate_oct",
        input: &KEYS_GENERATE_OCT_INPUT,
        ok: &[&KEYS_GENERATE_OK],
        can_fail: true,
    },
    OpSpec {
        name: "keys.generate_ec",
        input: &KEYS_GENERATE_EC_INPUT,
        ok: &[&KEYS_GENERATE_OK],
        can_fail: false,
    },
    OpSpec {
        name: "keys.generate_okp",
        input: &KEYS_GENERATE_OKP_INPUT,
        ok: &[&KEYS_GENERATE_OK],
        can_fail: false,
    },
    OpSpec {
        name: "jwt.validate",
        input: &JWT_VALIDATE_INPUT,
        ok: &[&JWT_VALIDATE_OK],
        can_fail: true,
    },
    OpSpec {
        name: "jwt.issue",
        input: &JWT_ISSUE_INPUT,
        ok: &[&JWT_ISSUE_EXACT, &JWT_ISSUE_VALIDATED],
        can_fail: true,
    },
];

fn spec(operation: &str) -> Option<&'static OpSpec> {
    SPECS.iter().find(|s| s.name == operation)
}

/// What a vector expects.
#[derive(Debug)]
enum Expect {
    /// Success with these output members (`ok` removed).
    Ok(Object),
    /// Failure with this stable error code.
    Err(String),
}

/// A schema-valid vector.
#[derive(Debug)]
struct Vector {
    operation: String,
    input: Object,
    expect: Expect,
    /// The cargo features it needs (top-level `features`), deduplicated.
    features: Vec<&'static str>,
    /// The cargo features it must run without (top-level
    /// `features_absent`, ADR 0056), deduplicated, none in `features`.
    features_absent: Vec<&'static str>,
}

/// A schema violation: the JSON pointer and what is wrong there.
fn violation(pointer: &str, problem: impl std::fmt::Display) -> String {
    format!("schema: {pointer}: {problem}")
}

fn is_text(s: &str) -> bool {
    !s.is_empty() && s.chars().any(|c| !c.is_whitespace())
}

fn is_hex(s: &str) -> bool {
    s.len().is_multiple_of(2) && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_base64url_alphabet(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// `$defs/count`: `{"type": "integer", "minimum": 0, "maximum": COUNT_MAX}`.
fn is_count(value: &Value) -> bool {
    value.as_u64().is_some_and(|n| n <= COUNT_MAX)
}

/// `$defs/seconds`: `{"type": "integer", "minimum": -SECONDS_MAX,
/// "maximum": SECONDS_MAX}`.
fn is_seconds(value: &Value) -> bool {
    value.as_i64().is_some_and(|n| n.abs() <= SECONDS_MAX)
}

/// Checks that `object` has exactly the `allowed` members, all of which are
/// required.
fn exact_members(object: &Object, allowed: &[&str], pointer: &str) -> Result<(), String> {
    for (name, _) in object {
        if !allowed.contains(&name) {
            return Err(violation(
                &format!("{pointer}/{name}"),
                "unknown member (additionalProperties is false)",
            ));
        }
    }
    for name in allowed {
        if !object.contains(name) {
            return Err(violation(
                &format!("{pointer}/{name}"),
                "required member is missing",
            ));
        }
    }
    Ok(())
}

fn check_kind(value: &Value, kind: Kind, pointer: &str) -> Result<(), String> {
    match (kind, value) {
        (Kind::Nested(shape), Value::Object(object)) => {
            return check_shape(object, shape, false, pointer);
        }
        (Kind::List(shape), Value::Array(items)) if !items.is_empty() => {
            for (i, item) in items.iter().enumerate() {
                let at = format!("{pointer}/{i}");
                let object = item
                    .as_object()
                    .ok_or_else(|| violation(&at, "must be an object"))?;
                check_shape(object, shape, false, &at)?;
            }
            return Ok(());
        }
        _ => {}
    }
    let ok = match kind {
        Kind::Object => value.as_object().is_some(),
        Kind::String => value.as_str().is_some(),
        Kind::Hex => value.as_str().is_some_and(is_hex),
        Kind::Base64url => value.as_str().is_some_and(is_base64url_alphabet),
        Kind::Enum(values) => value.as_str().is_some_and(|s| values.contains(&s)),
        Kind::Count => is_count(value),
        Kind::Jws => value.as_str().is_some() || value.as_object().is_some(),
        Kind::AlgList | Kind::StringList => value
            .as_array()
            .is_some_and(|items| items.iter().all(|item| item.as_str().is_some())),
        Kind::Jwe => value.as_str().is_some() || value.as_object().is_some(),
        Kind::Bool => value.as_bool().is_some(),
        Kind::Seconds => is_seconds(value),
        Kind::StringOrList => {
            value.as_str().is_some()
                || value
                    .as_array()
                    .is_some_and(|items| items.iter().all(|item| item.as_str().is_some()))
        }
        Kind::StringOrNull => value.as_str().is_some() || value.is_null(),
        // Matched above when the value has the right type.
        Kind::Nested(_) | Kind::List(_) => false,
    };
    if ok {
        Ok(())
    } else {
        let wanted = match kind {
            Kind::Object => "an object".to_owned(),
            Kind::String => "a string".to_owned(),
            Kind::Hex => format!("a string matching {HEX_PATTERN}"),
            Kind::Base64url => format!("a string matching {BASE64URL_PATTERN}"),
            Kind::Enum(values) => format!("one of {values:?}"),
            Kind::Count => format!("an integer from 0 to {COUNT_MAX}"),
            Kind::Jws => "a string (compact) or an object (JSON serialization)".to_owned(),
            Kind::AlgList | Kind::StringList => "an array of strings".to_owned(),
            Kind::Jwe => "a string (compact) or an object (JSON serialization)".to_owned(),
            Kind::Bool => "a boolean".to_owned(),
            Kind::Seconds => format!("an integer from -{SECONDS_MAX} to {SECONDS_MAX}"),
            Kind::StringOrList => "a string or an array of strings".to_owned(),
            Kind::StringOrNull => "a string or null".to_owned(),
            Kind::Nested(shape) => format!("an object ({})", shape.def),
            Kind::List(shape) => format!("a non-empty array of objects ({})", shape.def),
        };
        Err(violation(pointer, format!("must be {wanted}")))
    }
}

/// Checks `object` against `shape`, plus `"ok"` when `ok` is set (a
/// success expectation, whose `ok` is already known to be `true`).
fn check_shape(object: &Object, shape: &Shape, ok: bool, pointer: &str) -> Result<(), String> {
    for (name, _) in object {
        let known = (ok && name == "ok") || shape.members.iter().any(|m| m.name == name);
        if !known {
            return Err(violation(
                &format!("{pointer}/{name}"),
                "unknown member (additionalProperties is false)",
            ));
        }
    }
    for member in shape.members {
        let at = format!("{pointer}/{}", member.name);
        match object.get(member.name) {
            Some(value) => check_kind(value, member.kind, &at)?,
            None if member.required => return Err(violation(&at, "required member is missing")),
            None => {}
        }
    }
    for rule in shape.rules {
        check_rule(object, rule, pointer)?;
    }
    Ok(())
}

/// Applies a [`Rule`] to an object whose members are valid.
fn check_rule(object: &Object, rule: &Rule, pointer: &str) -> Result<(), String> {
    match rule {
        Rule::Signers(rule) => check_signer_rule(object, rule, pointer),
        Rule::ExactlyOne(names) => {
            let present: Vec<&str> = names
                .iter()
                .copied()
                .filter(|n| object.contains(n))
                .collect();
            if present.len() == 1 {
                return Ok(());
            }
            let names = names
                .iter()
                .map(|n| format!("`{n}`"))
                .collect::<Vec<_>>()
                .join(", ");
            Err(violation(
                pointer,
                format!(
                    "needs exactly one of {names} (oneOf), has {}",
                    present.len()
                ),
            ))
        }
        Rule::OnlyWhen {
            member,
            value,
            dependent,
        } => {
            let selected = object.get(member).and_then(Value::as_str) == Some(*value);
            let at = format!("{pointer}/{dependent}");
            match (selected, object.contains(dependent)) {
                (true, false) => Err(violation(
                    &at,
                    format!("required when `{member}` is \"{value}\""),
                )),
                (false, true) => Err(violation(
                    &at,
                    format!("allowed only when `{member}` is \"{value}\""),
                )),
                _ => Ok(()),
            }
        }
    }
}

/// Applies a [`SignerRule`] to a `jws_sign_input` whose members are valid.
fn check_signer_rule(object: &Object, rule: &SignerRule, pointer: &str) -> Result<(), String> {
    if object.get("serialization").and_then(Value::as_str) != Some(rule.serialization) {
        return Ok(());
    }
    let signers = object
        .get("signers")
        .and_then(Value::as_array)
        .expect("checked as a member");
    let what = format!("a {} JWS", rule.serialization);
    if signers.len() > rule.max_signers {
        return Err(violation(
            &format!("{pointer}/signers"),
            format!("{what} has at most {} signer", rule.max_signers),
        ));
    }
    for (i, signer) in signers.iter().enumerate() {
        let signer = signer.as_object().expect("checked as a member");
        for name in rule.requires {
            if !signer.contains(name) {
                return Err(violation(
                    &format!("{pointer}/signers/{i}/{name}"),
                    format!("required for {what}"),
                ));
            }
        }
        for name in rule.forbids {
            if signer.contains(name) {
                return Err(violation(
                    &format!("{pointer}/signers/{i}/{name}"),
                    format!("not allowed in {what}"),
                ));
            }
        }
    }
    Ok(())
}

/// Checks a success expectation against the operation's success shapes:
/// it must match exactly one (schema `oneOf`).
fn check_ok(expect: &Object, spec: &OpSpec) -> Result<(), String> {
    if let [shape] = spec.ok {
        return check_shape(expect, shape, true, "/expect");
    }
    let results: Vec<(&str, Result<(), String>)> = spec
        .ok
        .iter()
        .map(|shape| (shape.def, check_shape(expect, shape, true, "/expect")))
        .collect();
    match results.iter().filter(|(_, r)| r.is_ok()).count() {
        1 => Ok(()),
        0 => Err(violation(
            "/expect",
            format!(
                "matches none of the success forms: {}",
                results
                    .iter()
                    .map(|(def, r)| format!("{def} ({})", r.as_ref().unwrap_err()))
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
        )),
        _ => Err(violation(
            "/expect",
            "matches more than one success form (oneOf)",
        )),
    }
}

/// The vector's `source`, if it is usable, for failure messages.
fn usable_source(value: &Value) -> Option<String> {
    value
        .get("source")
        .and_then(Value::as_str)
        .filter(|s| is_text(s))
        .map(str::to_owned)
}

/// Checks one parsed vector file against the rules of `schema.json`.
fn validate(value: &Value) -> Result<Vector, String> {
    let root = value
        .as_object()
        .ok_or_else(|| violation("", "a vector file must hold one JSON object"))?;
    for (name, _) in root {
        if !TOP_LEVEL.contains(&name) && !TOP_LEVEL_OPTIONAL.contains(&name) {
            return Err(violation(
                &format!("/{name}"),
                "unknown member (additionalProperties is false)",
            ));
        }
    }
    for name in TOP_LEVEL {
        if !root.contains(name) {
            return Err(violation(&format!("/{name}"), "required member is missing"));
        }
    }
    let features = vector_features(root, "features")?;
    let features_absent = vector_features(root, "features_absent")?;
    if root.contains("features_absent") && features_absent.is_empty() {
        return Err(violation(
            "/features_absent",
            "must not be empty (minItems 1)",
        ));
    }
    // ADR 0056 §3: a name can't be both needed and forbidden.
    if let Some(both) = features.iter().find(|f| features_absent.contains(f)) {
        return Err(violation(
            "/features_absent",
            format!("\"{both}\" is listed in `features` too"),
        ));
    }
    for name in ["source", "description"] {
        let text = root.get(name).and_then(Value::as_str);
        if !text.is_some_and(is_text) {
            return Err(violation(
                &format!("/{name}"),
                "must be a string with a non-whitespace character",
            ));
        }
    }
    let operation = root
        .get("operation")
        .and_then(Value::as_str)
        .ok_or_else(|| violation("/operation", "must be a string"))?;
    if !OPERATIONS.contains(&operation) {
        return Err(violation(
            "/operation",
            format!("unknown operation `{operation}` (not in schema.json)"),
        ));
    }
    let input = root
        .get("input")
        .and_then(Value::as_object)
        .ok_or_else(|| violation("/input", "must be an object"))?;
    let expect = root
        .get("expect")
        .and_then(Value::as_object)
        .ok_or_else(|| violation("/expect", "must be an object"))?;
    let ok = expect
        .get("ok")
        .ok_or_else(|| violation("/expect/ok", "required member is missing"))?
        .as_bool()
        .ok_or_else(|| violation("/expect/ok", "must be a boolean"))?;

    let mut outputs = expect.clone();
    outputs.remove("ok");
    let expect = match spec(operation) {
        // Reserved operation: the schema constrains only `"ok"`, and
        // `execute` fails it, so the expectation is never compared.
        None if ok => Expect::Ok(outputs),
        None => Expect::Err(String::new()),
        Some(spec) => {
            check_shape(input, spec.input, false, "/input")?;
            if ok {
                check_ok(expect, spec)?;
                Expect::Ok(outputs)
            } else if !spec.can_fail {
                return Err(violation(
                    "/expect",
                    format!("`{operation}` cannot fail, so only {{\"ok\": true, ...}} is allowed"),
                ));
            } else {
                exact_members(expect, &["ok", "error"], "/expect")?;
                let code = expect
                    .get("error")
                    .and_then(Value::as_str)
                    .filter(|c| Error::CODES.contains(c))
                    .ok_or_else(|| violation("/expect/error", "must be one of Error::CODES"))?;
                Expect::Err(code.to_owned())
            }
        }
    };
    if operation == "jwe.encrypt" && spec(operation).is_some() {
        check_jwe_encrypt_features(input, &features, &features_absent)?;
    }
    if operation == "jwt.issue" {
        check_jwt_issue(input, &expect)?;
    }
    Ok(Vector {
        operation: operation.to_owned(),
        input: input.clone(),
        expect,
        features,
        features_absent,
    })
}

/// The top-level `features` or `features_absent` (`member`): an array of
/// [`FEATURES`] names, each at most once (schema: `uniqueItems`).
fn vector_features(root: &Object, member: &str) -> Result<Vec<&'static str>, String> {
    let Some(value) = root.get(member) else {
        return Ok(Vec::new());
    };
    let items = value
        .as_array()
        .ok_or_else(|| violation(&format!("/{member}"), "must be an array"))?;
    let mut features = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let feature = item
            .as_str()
            .and_then(|s| FEATURES.iter().map(|(name, _)| name).find(|f| **f == s))
            .ok_or_else(|| {
                violation(
                    &format!("/{member}/{i}"),
                    format!("must be one of {:?}", feature_names()),
                )
            })?;
        if features.contains(feature) {
            return Err(violation(
                &format!("/{member}/{i}"),
                "listed twice (uniqueItems)",
            ));
        }
        features.push(*feature);
    }
    Ok(features)
}

/// A `jwe.encrypt` vector declares the features its inputs need, so it is
/// SKIPPED, never failed or silently weakened, where they are off:
/// `rng_b64u` and `protected_b64u` need `fixed-rng` (cargo feature
/// `insecure-test-vectors`)
/// (`Encryptor::encrypt_reproducible`, ADR 0041 §3), `compress` needs
/// `deflate` (ADR 0017) listed in `features`, or in `features_absent` to
/// pin `UnsupportedAlgorithm` without it (ADR 0056 §4, ADR 0030 §4).
fn check_jwe_encrypt_features(
    input: &Object,
    features: &[&str],
    features_absent: &[&str],
) -> Result<(), String> {
    for (member, feature) in [("rng_b64u", "fixed-rng"), ("protected_b64u", "fixed-rng")] {
        if input.contains(member) && !features.contains(&feature) {
            return Err(violation(
                "/features",
                format!("`input/{member}` needs \"{feature}\" listed in `features`"),
            ));
        }
    }
    if input.contains("compress")
        && !features.contains(&"deflate")
        && !features_absent.contains(&"deflate")
    {
        return Err(violation(
            "/features",
            "`input/compress` needs \"deflate\" listed in `features` or `features_absent`",
        ));
    }
    Ok(())
}

/// The rules of a `jwt.issue` vector that tie its input to its
/// expectation (conformance/README.md), checked with the schema:
///
/// - with `encrypt` the token is randomized (the CEK, IV and any ephemeral
///   key come from the OS CSPRNG, RFC 7516 §5.1), so there is no exact
///   `token` to expect;
/// - `{"ok": true}` without `token` is checked by validating the issued
///   token with `validate`, which it therefore needs. Only with `encrypt`
///   may `validate` be left out, for a recipient whose key polyjose cannot
///   decrypt with (RSA-OAEP-256, ADR 0021); then only the token's compact
///   shape is checked;
/// - `validate` is used only on success, so a failure vector has none.
fn check_jwt_issue(input: &Object, expect: &Expect) -> Result<(), String> {
    let encrypt = input.contains("encrypt");
    let validate = input.contains("validate");
    match expect {
        Expect::Ok(want) if want.contains("token") && encrypt => Err(violation(
            "/expect/token",
            "an encrypted token is randomized (RFC 7516 §5.1), so with `encrypt` \
             expect {\"ok\": true} and give `validate`",
        )),
        Expect::Ok(want) if !want.contains("token") && !validate && !encrypt => Err(violation(
            "/input/validate",
            "required when the expectation has no `token`: the runner validates \
             the token it issued (only `encrypt` may go without)",
        )),
        Expect::Err(_) if validate => Err(violation(
            "/input/validate",
            "used only when the issue succeeds, so a failure vector has none",
        )),
        _ => Ok(()),
    }
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("validated hex"))
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn input_str<'a>(input: &'a Object, name: &str) -> &'a str {
    input.get(name).and_then(Value::as_str).expect("validated")
}

fn input_object<'a>(object: &'a Object, name: &str) -> &'a Object {
    object
        .get(name)
        .and_then(Value::as_object)
        .expect("validated")
}

/// A `*_b64u` member's octets. The runner decodes them to hand them to the
/// library, so a value that does not decode is a broken vector, never an
/// outcome (the codec has its own `b64url.*` vectors).
fn input_bytes(object: &Object, name: &str) -> Result<Vec<u8>, String> {
    let text = object.get(name).and_then(Value::as_str).expect("validated");
    b64url_decode(text).map_err(|e| {
        format!(
            "`{name}` is not canonical base64url ({}); the runner must decode it",
            e.code()
        )
    })
}

/// An optional `$defs/count` member, as a `usize`.
fn input_count(object: &Object, name: &str) -> Option<usize> {
    object
        .get(name)
        .and_then(Value::as_u64)
        .map(|n| usize::try_from(n).expect("validated: at most u32::MAX"))
}

/// `allowed_algs`, mapped name by name: an unknown name becomes
/// `SigningAlg::Unknown`, which `VerifyOptions::new` refuses.
fn input_algs(object: &Object) -> Vec<SigningAlg> {
    object
        .get("allowed_algs")
        .and_then(Value::as_array)
        .expect("validated")
        .iter()
        .map(|alg| SigningAlg::from(alg.as_str().expect("validated")))
        .collect()
}

/// One signer's inputs, built from the vector.
struct SignerParts {
    key: Jwk,
    protected: Option<ProtectedHeader>,
    unprotected: Option<Header>,
}

/// Builds each signer, in order: import `key`, then decode and parse
/// `protected_b64u` (RFC 7515 §5.1 step 3, kept verbatim), then parse
/// `header` (§7.2.1). The first error is the outcome.
fn signer_parts(input: &Object) -> Result<Vec<SignerParts>, Error> {
    let signers = input
        .get("signers")
        .and_then(Value::as_array)
        .expect("validated");
    let mut parts = Vec::with_capacity(signers.len());
    for signer in signers {
        let signer = signer.as_object().expect("validated");
        let key = Jwk::from_object(input_object(signer, "key"))?;
        let protected = match signer.get("protected_b64u").and_then(Value::as_str) {
            Some(encoded) => Some(ProtectedHeader::from_encoded(encoded)?),
            None => None,
        };
        let unprotected = match signer.get("header") {
            Some(header) => Some(Header::from_json(header.to_json().as_bytes())?),
            None => None,
        };
        parts.push(SignerParts {
            key,
            protected,
            unprotected,
        });
    }
    Ok(parts)
}

/// `jws.sign` (RFC 7515 §5.1): build the signers (see [`signer_parts`]),
/// then sign in the requested serialization. An exact expectation gets the
/// output as `jws` (a string for compact; JSON output parsed, so it is
/// compared as a JSON value). A round-trip expectation is checked here
/// (see [`check_round_trip`]) and echoed back on success.
fn run_jws_sign(
    input: &Object,
    expect: &Expect,
    out: &mut Object,
) -> Result<Result<(), Error>, String> {
    let serialization = input_str(input, "serialization");
    let payload = input_bytes(input, "payload_b64u")?;
    let detached = input
        .get("detached")
        .and_then(Value::as_bool)
        .expect("validated");
    let parts = match signer_parts(input) {
        Ok(parts) => parts,
        Err(e) => return Ok(Err(e)),
    };
    let opts = SignOptions::new().detached(detached);
    let signed = if serialization == "compact" {
        // Schema: exactly one signer, with a protected header.
        let only = &parts[0];
        let protected = only.protected.as_ref().expect("validated");
        jws::sign_compact(protected, &payload, &only.key, &opts)
    } else {
        let signers: Vec<Signer<'_>> = parts
            .iter()
            .map(|part| {
                let mut signer = Signer::new(&part.key);
                if let Some(protected) = &part.protected {
                    signer = signer.protected(protected.clone());
                }
                if let Some(unprotected) = &part.unprotected {
                    signer = signer.unprotected(unprotected.clone());
                }
                signer
            })
            .collect();
        if serialization == "flattened" {
            jws::sign_flattened(&signers[0], &payload, &opts)
        } else {
            jws::sign_general(&signers, &payload, &opts)
        }
    };
    let text = match signed {
        Ok(text) => text,
        Err(e) => return Ok(Err(e)),
    };
    let jws = if serialization == "compact" {
        Value::from(text.as_str())
    } else {
        json::parse(text.as_bytes())
            .map_err(|e| format!("the signed JSON JWS does not parse: {}", e.code()))?
    };
    let verify_with = match expect {
        Expect::Ok(want) => want.get("verify_with").and_then(Value::as_object),
        Expect::Err(_) => None,
    };
    match verify_with {
        Some(verify_with) => {
            check_round_trip(
                serialization,
                &jws,
                &text,
                &payload,
                detached,
                parts.len(),
                verify_with,
            )?;
            out.insert("verify_with", verify_with.clone());
        }
        None => {
            out.insert("jws", jws);
        }
    }
    Ok(Ok(()))
}

/// Checks a randomized signature by round trip: the output has the shape
/// of the requested serialization (RFC 7515 §7.1, §7.2.1, §7.2.2), verifies
/// with `verify_with` (with the payload supplied separately when detached,
/// Appendix F), and yields the signed payload. Any failure is the vector's.
fn check_round_trip(
    serialization: &str,
    jws: &Value,
    text: &str,
    payload: &[u8],
    detached: bool,
    signers: usize,
    verify_with: &Object,
) -> Result<(), String> {
    let shape_ok = match serialization {
        "compact" => text.split('.').count() == 3,
        "flattened" => jws.get("signature").is_some() && jws.get("signatures").is_none(),
        _ => jws
            .get("signatures")
            .and_then(Value::as_array)
            .is_some_and(|all| all.len() == signers),
    };
    if !shape_ok {
        return Err(format!(
            "round trip: the output is not a {serialization} JWS with {signers} signature(s)"
        ));
    }
    let key = Jwk::from_object(input_object(verify_with, "key"))
        .map_err(|e| format!("round trip: verify_with.key does not import ({})", e.code()))?;
    let algs = input_algs(verify_with);
    let mut opts = VerifyOptions::new(&algs).map_err(|e| {
        format!(
            "round trip: verify_with.allowed_algs is refused ({})",
            e.code()
        )
    })?;
    if detached {
        opts = opts.detached_payload(payload);
    }
    let verified = match jws.as_str() {
        Some(compact) => jws::verify_compact(compact, &key, &opts),
        None => jws::verify_json(text, &key, &opts),
    }
    .map_err(|e| {
        format!(
            "round trip: the signed JWS does not verify with verify_with ({})",
            e.code()
        )
    })?;
    if *verified.payload != payload {
        return Err("round trip: the verified payload is not the signed one".to_owned());
    }
    Ok(())
}

/// `jws.verify` (RFC 7515 §5.2). The steps run in the order
/// conformance/README.md fixes for every runner, and the first error is
/// the outcome: import `key` (RFC 7517), build the options from
/// `allowed_algs` and the optional members, then verify. A string `jws`
/// goes to `verify_compact` (RFC 7515 §7.1); an object goes, as its JSON
/// text, to `verify_json` (§7.2).
fn run_jws_verify(input: &Object, out: &mut Object) -> Result<Result<(), Error>, String> {
    let key = match Jwk::from_object(input_object(input, "key")) {
        Ok(key) => key,
        Err(e) => return Ok(Err(e)),
    };
    let algs = input_algs(input);
    let detached = match input.get("detached_payload_b64u") {
        Some(_) => Some(input_bytes(input, "detached_payload_b64u")?),
        None => None,
    };
    let mut opts = match VerifyOptions::new(&algs) {
        Ok(opts) => opts,
        Err(e) => return Ok(Err(e)),
    };
    if let Some(payload) = &detached {
        opts = opts.detached_payload(payload);
    }
    if let Some(n) = input_count(input, "max_input_len") {
        opts = opts.max_input_len(n);
    }
    if let Some(n) = input_count(input, "max_signatures") {
        opts = opts.max_signatures(n);
    }
    let jws = input.get("jws").expect("validated");
    let result = match jws.as_str() {
        Some(compact) => jws::verify_compact(compact, &key, &opts),
        None => jws::verify_json(&jws.to_json(), &key, &opts),
    };
    let verified = match result {
        Ok(verified) => verified,
        Err(e) => return Ok(Err(e)),
    };
    let index = u64::try_from(verified.signature_index).expect("an index fits u64");
    out.insert("payload_b64u", b64url_encode(&verified.payload));
    out.insert("alg", verified.alg.as_str());
    out.insert(
        "signature_index",
        Number::from_u64(index).expect("an index is a safe integer"),
    );
    Ok(Ok(()))
}

// ---------------------------------------------------------------------------
// jwe.* handlers (RFC 7516), kept apart from the jws.* ones.
// ---------------------------------------------------------------------------

/// A list member (`allowed_algs`, `allowed_enc`, `understood_crit`) as
/// strings, in order.
fn input_names<'a>(object: &'a Object, name: &str) -> Vec<&'a str> {
    object
        .get(name)
        .and_then(Value::as_array)
        .expect("validated")
        .iter()
        .map(|v| v.as_str().expect("validated"))
        .collect()
}

/// A `DecryptPolicy` from `allowed_algs` and `allowed_enc`, mapped name by
/// name (an unknown or unimplemented name is kept, and fails later as
/// `UnsupportedAlgorithm`), with the optional limits of `object`.
fn jwe_policy(object: &Object) -> Result<DecryptPolicy, Error> {
    let algs: Vec<KeyMgmtAlg> = input_names(object, "allowed_algs")
        .into_iter()
        .map(KeyMgmtAlg::from)
        .collect();
    let encs: Vec<ContentEncAlg> = input_names(object, "allowed_enc")
        .into_iter()
        .map(ContentEncAlg::from)
        .collect();
    let mut policy = DecryptPolicy::new(&algs, &encs)?;
    if object.contains("understood_crit") {
        policy = policy.understood_crit(&input_names(object, "understood_crit"));
    }
    if let Some(n) = input_count(object, "max_input_len") {
        policy = policy.max_input_len(n);
    }
    if let Some(n) = input_count(object, "max_recipients") {
        policy = policy.max_recipients(n);
    }
    if let Some(n) = input_count(object, "max_pbes2_count") {
        policy = policy.max_pbes2_count(u32::try_from(n).expect("validated: a u32"));
    }
    if let Some(n) = input_count(object, "max_decompressed_len") {
        policy = policy.max_decompressed_len(n);
    }
    Ok(policy)
}

/// Decrypts `jwe` (a compact string, or a JSON JWE object passed as its
/// text) with `key` under `policy`.
fn jwe_decrypt(jwe: &Value, key: &Jwk, policy: &DecryptPolicy) -> polyjose::Result<jwe::Decrypted> {
    match jwe.as_str() {
        Some(compact) => jwe::decrypt_compact(compact, key, policy),
        None => jwe::decrypt_json(&jwe.to_json(), key, policy),
    }
}

/// `encrypt_reproducible` with the vector's injected bytes. Every byte must
/// be drawn: a leftover means the draw order (`jwe::random`) differs from
/// the vector's.
#[cfg(feature = "insecure-test-vectors")]
fn jwe_encrypt_reproducible(
    encryptor: &Encryptor,
    plaintext: &[u8],
    form: jwe::Serialization,
    rng_bytes: Vec<u8>,
    protected_b64u: Option<&str>,
) -> Result<Result<String, Error>, String> {
    let mut rng = polyjose::insecure_test_vectors::FixedRng::new(rng_bytes);
    let result = encryptor.encrypt_reproducible(plaintext, form, &mut rng, protected_b64u);
    if result.is_ok() && rng.remaining() != 0 {
        return Err(format!(
            "`rng_b64u` has {} byte(s) the encryption did not draw",
            rng.remaining()
        ));
    }
    Ok(result)
}

/// Never reached: such a vector declares `insecure-test-vectors` and is
/// SKIPPED in this build.
#[cfg(not(feature = "insecure-test-vectors"))]
fn jwe_encrypt_reproducible(
    _encryptor: &Encryptor,
    _plaintext: &[u8],
    _form: jwe::Serialization,
    _rng_bytes: Vec<u8>,
    _protected_b64u: Option<&str>,
) -> Result<Result<String, Error>, String> {
    unreachable!(
        "a vector with rng_b64u or protected_b64u is skipped without insecure-test-vectors"
    )
}

/// `Encryptor::compress` (RFC 7516 §4.1.3). It exists in every build:
/// without `deflate` the encryption then fails with `UnsupportedAlgorithm`
/// (ADR 0017 §5, ADR 0030 §4), which a `features_absent: ["deflate"]`
/// vector pins (ADR 0056).
fn jwe_compress(encryptor: Encryptor) -> Encryptor {
    encryptor.compress()
}

/// The recipients of a `jwe.encrypt` vector, in order: for each, import
/// `key`, then parse `header`. The first error is the outcome.
fn jwe_recipients(input: &Object) -> Result<Result<Vec<Recipient>, Error>, String> {
    let items = input
        .get("recipients")
        .and_then(Value::as_array)
        .expect("validated");
    let mut recipients = Vec::with_capacity(items.len());
    for item in items {
        let item = item.as_object().expect("validated");
        let key = match Jwk::from_object(input_object(item, "key")) {
            Ok(key) => key,
            Err(e) => return Ok(Err(e)),
        };
        let mut recipient = Recipient::new(KeyMgmtAlg::from(input_str(item, "alg")), &key);
        if let Some(header) = item.get("header") {
            match Header::from_json(header.to_json().as_bytes()) {
                Ok(header) => recipient = recipient.header(header),
                Err(e) => return Ok(Err(e)),
            }
        }
        if item.contains("apu_b64u") {
            recipient = recipient.apu(input_bytes(item, "apu_b64u")?);
        }
        if item.contains("apv_b64u") {
            recipient = recipient.apv(input_bytes(item, "apv_b64u")?);
        }
        if let Some(n) = input_count(item, "p2c") {
            recipient = recipient.p2c(u32::try_from(n).expect("validated: a u32"));
        }
        if let Some(n) = input_count(item, "p2s_len") {
            recipient = recipient.p2s_len(n);
        }
        recipients.push(recipient);
    }
    Ok(Ok(recipients))
}

/// `jwe.encrypt` (RFC 7516 §5.1). The steps run in the order
/// conformance/README.md fixes: the recipients ([`jwe_recipients`]), then
/// `protected`, then `unprotected`, then the call; the first error is the
/// outcome. With `rng_b64u` or `protected_b64u` the call is
/// `encrypt_reproducible` (feature `insecure-test-vectors`); otherwise
/// `encrypt_compact` or `encrypt_json`, on the OS CSPRNG. An exact
/// expectation gets the output as `jwe` (a string for compact; JSON parsed,
/// so compared as a JSON value); a round trip is checked here
/// ([`check_jwe_round_trip`]) and echoed back on success.
fn run_jwe_encrypt(
    input: &Object,
    expect: &Expect,
    out: &mut Object,
) -> Result<Result<(), Error>, String> {
    let serialization = input_str(input, "serialization");
    let plaintext = input_bytes(input, "plaintext_b64u")?;
    let recipients = match jwe_recipients(input)? {
        Ok(recipients) => recipients,
        Err(e) => return Ok(Err(e)),
    };
    let count = recipients.len();
    let mut encryptor = Encryptor::new(ContentEncAlg::from(input_str(input, "enc")));
    for (member, shared) in [("protected", false), ("unprotected", true)] {
        let Some(header) = input.get(member) else {
            continue;
        };
        let header = match Header::from_json(header.to_json().as_bytes()) {
            Ok(header) => header,
            Err(e) => return Ok(Err(e)),
        };
        encryptor = if shared {
            encryptor.shared_unprotected_header(header)
        } else {
            encryptor.protected_header(header)
        };
    }
    if input.contains("aad_b64u") {
        encryptor = encryptor.aad(input_bytes(input, "aad_b64u")?);
    }
    if input.get("compress").and_then(Value::as_bool) == Some(true) {
        encryptor = jwe_compress(encryptor);
    }
    for recipient in recipients {
        encryptor = encryptor.recipient(recipient);
    }
    let form = match serialization {
        "compact" => jwe::Serialization::Compact,
        "flattened" => jwe::Serialization::Json(JsonForm::Flattened),
        _ => jwe::Serialization::Json(JsonForm::General),
    };
    let encrypted = if input.contains("rng_b64u") || input.contains("protected_b64u") {
        let rng_bytes = match input.get("rng_b64u") {
            Some(_) => input_bytes(input, "rng_b64u")?,
            None => Vec::new(),
        };
        let protected_b64u = input.get("protected_b64u").and_then(Value::as_str);
        jwe_encrypt_reproducible(&encryptor, &plaintext, form, rng_bytes, protected_b64u)?
    } else {
        match form {
            jwe::Serialization::Compact => encryptor.encrypt_compact(&plaintext),
            jwe::Serialization::Json(json_form) => encryptor.encrypt_json(&plaintext, json_form),
        }
    };
    let text = match encrypted {
        Ok(text) => text,
        Err(e) => return Ok(Err(e)),
    };
    let jwe = if serialization == "compact" {
        Value::from(text.as_str())
    } else {
        json::parse(text.as_bytes())
            .map_err(|e| format!("the encrypted JSON JWE does not parse: {}", e.code()))?
    };
    let decrypt_with = match expect {
        Expect::Ok(want) => want.get("decrypt_with").and_then(Value::as_object),
        Expect::Err(_) => None,
    };
    match decrypt_with {
        Some(decrypt_with) => {
            check_jwe_round_trip(serialization, &jwe, &plaintext, count, decrypt_with)?;
            out.insert("decrypt_with", decrypt_with.clone());
        }
        None => {
            out.insert("jwe", jwe);
        }
    }
    Ok(Ok(()))
}

/// Checks a randomized encryption by round trip: the output has the shape
/// of the requested serialization (five compact parts, RFC 7516 §7.1;
/// `ciphertext` without `recipients` for flattened, §7.2.2; one
/// `recipients` entry per recipient for general, §7.2.1), decrypts with
/// `decrypt_with`, and yields the plaintext. Any failure is the vector's.
fn check_jwe_round_trip(
    serialization: &str,
    jwe: &Value,
    plaintext: &[u8],
    recipients: usize,
    decrypt_with: &Object,
) -> Result<(), String> {
    let shape_ok = match serialization {
        "compact" => jwe.as_str().is_some_and(|t| t.split('.').count() == 5),
        "flattened" => jwe.get("ciphertext").is_some() && jwe.get("recipients").is_none(),
        _ => jwe
            .get("recipients")
            .and_then(Value::as_array)
            .is_some_and(|all| all.len() == recipients),
    };
    if !shape_ok {
        return Err(format!(
            "round trip: the output is not a {serialization} JWE with {recipients} recipient(s)"
        ));
    }
    let key = Jwk::from_object(input_object(decrypt_with, "key")).map_err(|e| {
        format!(
            "round trip: decrypt_with.key does not import ({})",
            e.code()
        )
    })?;
    let policy = jwe_policy(decrypt_with).map_err(|e| {
        format!(
            "round trip: decrypt_with's lists are refused ({})",
            e.code()
        )
    })?;
    let decrypted = jwe_decrypt(jwe, &key, &policy).map_err(|e| {
        format!(
            "round trip: the encrypted JWE does not decrypt with decrypt_with ({})",
            e.code()
        )
    })?;
    if decrypted.plaintext() != plaintext {
        return Err("round trip: the decrypted plaintext is not the encrypted one".to_owned());
    }
    Ok(())
}

/// `jwe.decrypt` (RFC 7516 §5.2). The steps run in the order
/// conformance/README.md fixes for every runner, and the first error is
/// the outcome: import `key` (RFC 7517), build the policy from
/// `allowed_algs`, `allowed_enc` and the optional members, then decrypt.
/// A string `jwe` goes to `decrypt_compact` (RFC 7516 §7.1); an object
/// goes, as its JSON text, to `decrypt_json` (§7.2).
fn run_jwe_decrypt(input: &Object, out: &mut Object) -> Result<Result<(), Error>, String> {
    let key = match Jwk::from_object(input_object(input, "key")) {
        Ok(key) => key,
        Err(e) => return Ok(Err(e)),
    };
    let policy = match jwe_policy(input) {
        Ok(policy) => policy,
        Err(e) => return Ok(Err(e)),
    };
    let decrypted = match jwe_decrypt(input.get("jwe").expect("validated"), &key, &policy) {
        Ok(decrypted) => decrypted,
        Err(e) => return Ok(Err(e)),
    };
    let index = u64::try_from(decrypted.recipient()).expect("an index fits u64");
    out.insert("plaintext_b64u", b64url_encode(decrypted.plaintext()));
    out.insert(
        "recipient",
        Number::from_u64(index).expect("an index is a safe integer"),
    );
    Ok(Ok(()))
}

/// The library format a validated `format` member names.
fn input_format(input: &Object) -> KeyFormat {
    let name = input_str(input, "format");
    KEY_FORMATS
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, f)| *f)
        .expect("validated")
}

/// The outcome of a PEM or DER import: the JWK as an object. An `oct`
/// result fails the vector whatever it expects: PEM and DER never carry one
/// (RFC 8725 §2.1, ADR 0018 §3).
fn imported(result: Result<Jwk, Error>, out: &mut Object) -> Result<Result<(), Error>, String> {
    let key = match result {
        Ok(key) => key,
        Err(e) => return Ok(Err(e)),
    };
    let jwk = key.to_object();
    if jwk.get("kty").and_then(Value::as_str) == Some("oct") {
        return Err("a PEM or DER import returned an oct key (RFC 8725 §2.1)".to_owned());
    }
    out.insert("jwk", Value::from(jwk));
    Ok(Ok(()))
}

/// `keys.import_pem`: `Jwk::from_pem`, and the JWK as an object.
fn run_keys_import_pem(input: &Object, out: &mut Object) -> Result<Result<(), Error>, String> {
    imported(Jwk::from_pem(input_str(input, "pem")), out)
}

/// `keys.import_der`: decode `der_b64u` (a broken vector if it is not
/// canonical), then `Jwk::from_der` in `format`, and the JWK as an object.
fn run_keys_import_der(input: &Object, out: &mut Object) -> Result<Result<(), Error>, String> {
    let der = input_bytes(input, "der_b64u")?;
    imported(Jwk::from_der(&der, input_format(input)), out)
}

/// `keys.export_pem`: the JWK import (`Jwk::from_object`), whose error is
/// the outcome, then `Jwk::to_pem` in `format`.
fn run_keys_export_pem(input: &Object, out: &mut Object) -> Result<Result<(), Error>, String> {
    let format = input_format(input);
    let key = match Jwk::from_object(input_object(input, "jwk")) {
        Ok(key) => key,
        Err(e) => return Ok(Err(e)),
    };
    match key.to_pem(format) {
        Ok(pem) => {
            out.insert("pem", pem.as_str());
            Ok(Ok(()))
        }
        Err(e) => Ok(Err(e)),
    }
}

/// `keys.export_der`: the JWK import (`Jwk::from_object`), whose error is
/// the outcome, then `Jwk::to_der` in `format`, as canonical base64url.
fn run_keys_export_der(input: &Object, out: &mut Object) -> Result<Result<(), Error>, String> {
    let format = input_format(input);
    let key = match Jwk::from_object(input_object(input, "jwk")) {
        Ok(key) => key,
        Err(e) => return Ok(Err(e)),
    };
    match key.to_der(format) {
        Ok(der) => {
            out.insert("der_b64u", b64url_encode(&der));
            Ok(Ok(()))
        }
        Err(e) => Ok(Err(e)),
    }
}

/// The identifier `name` registers. RFC 7518 §7.1 keeps JWS `alg`, JWE
/// `alg` and JWE `enc` values in one registry whose names are unique
/// (case-sensitive), so at most one of the three enums knows `name`. A name
/// none of them knows stays `SigningAlg::Unknown`, which generation refuses
/// with `UnsupportedAlgorithm`.
fn jose_alg(name: &str) -> JoseAlg {
    let signing = SigningAlg::from(name);
    if signing.is_known() {
        return signing.into();
    }
    let key_mgmt = KeyMgmtAlg::from(name);
    if key_mgmt.is_known() {
        return key_mgmt.into();
    }
    let enc = ContentEncAlg::from(name);
    if enc.is_known() {
        return enc.into();
    }
    signing.into()
}

/// The members a generated private key has: those RFC 7518 §6.2.1–§6.2.2
/// (EC), RFC 8037 §2 (OKP) or RFC 7518 §6.4.1 (oct) define, plus the `alg`
/// it is bound to (RFC 7517 §4.4). Sorted.
fn generated_members(kty: &str) -> Option<&'static [&'static str]> {
    match kty {
        "EC" => Some(&["alg", "crv", "d", "kty", "x", "y"]),
        "OKP" => Some(&["alg", "crv", "d", "kty", "x"]),
        "oct" => Some(&["alg", "k", "kty"]),
        _ => None,
    }
}

/// [`generated_members`] for a key bound to no algorithm (`keys::generate`):
/// the same members without `alg`. Sorted.
fn unbound_members(kty: &str) -> Option<&'static [&'static str]> {
    match kty {
        "EC" => Some(&["crv", "d", "kty", "x", "y"]),
        "OKP" => Some(&["crv", "d", "kty", "x"]),
        "oct" => Some(&["k", "kty"]),
        _ => None,
    }
}

/// The shape of a generated key, after checking what a shape cannot say:
/// the key is private, has exactly the members of
/// [`generated_members`], and imports back (`Jwk::from_object`) to the
/// same JWK. Any failure there fails the vector.
fn generated_shape(key: &Jwk) -> Result<Object, String> {
    shape_of(key, generated_members)
}

/// [`generated_shape`] with the member list `members` gives per `kty`.
fn shape_of(
    key: &Jwk,
    members: fn(&str) -> Option<&'static [&'static str]>,
) -> Result<Object, String> {
    if key.is_public() {
        return Err("generate_for returned a public key".to_owned());
    }
    let jwk = key.to_object();
    let kty = jwk.get("kty").and_then(Value::as_str).unwrap_or_default();
    let mut names: Vec<&str> = jwk.iter().map(|(name, _)| name).collect();
    names.sort_unstable();
    match members(kty) {
        Some(expected) if names == expected => {}
        _ => {
            return Err(format!(
                "generate_for returned a JWK with members {names:?}"
            ));
        }
    }
    let again = Jwk::from_object(&jwk)
        .map_err(|e| format!("the generated JWK does not import ({})", e.code()))?;
    if again.to_object() != jwk {
        return Err("the generated JWK imports as a different key".to_owned());
    }
    let mut shape = Object::new();
    for name in ["kty", "crv", "alg"] {
        if let Some(value) = jwk.get(name) {
            shape.insert(name, value.clone());
        }
    }
    if let Some(k) = jwk.get("k").and_then(Value::as_str) {
        let octets = b64url_decode(k).map_err(|e| format!("generated k: {}", e.code()))?;
        let octets = u64::try_from(octets.len()).expect("a length fits u64");
        shape.insert(
            "k_octets",
            Number::from_u64(octets).expect("a key length is a safe integer"),
        );
    }
    Ok(shape)
}

/// `keys.generate_for`: resolve `alg` (see [`jose_alg`]), generate, and
/// return the key's shape (see [`generated_shape`]), after its use round
/// trip when the vector has `use_with` (see [`check_use_with`]).
fn run_keys_generate_for(
    input: &Object,
    expect: &Expect,
    out: &mut Object,
) -> Result<Result<(), Error>, String> {
    let key = match generate_for(jose_alg(input_str(input, "alg"))) {
        Ok(key) => key,
        Err(e) => return Ok(Err(e)),
    };
    out.insert("shape", generated_shape(&key)?);
    echo_use_with(&key, expect, out)?;
    Ok(Ok(()))
}

/// The curve a validated `crv` names, from the curves the core generates.
fn input_spec(operation: &str, input: &Object) -> KeySpec {
    match operation {
        "keys.generate_oct" => KeySpec::Oct {
            bytes: input_count(input, "len_bytes").expect("validated"),
        },
        "keys.generate_ec" => {
            let crv = input_str(input, "crv");
            KeySpec::Ec(
                EC_CURVES
                    .into_iter()
                    .find(|c| c.as_str() == crv)
                    .expect("validated: one of EC_CURVE_NAMES"),
            )
        }
        _ => {
            let crv = input_str(input, "crv");
            KeySpec::Okp(
                OKP_CURVES
                    .into_iter()
                    .find(|c| c.as_str() == crv)
                    .expect("validated: one of OKP_CURVE_NAMES"),
            )
        }
    }
}

/// The EC curves `keys::generate` takes (RFC 7518 §6.2.1.1, RFC 8812 §3.1),
/// in [`EC_CURVE_NAMES`] order.
const EC_CURVES: [EcCurve; 4] = [
    EcCurve::P256,
    EcCurve::P384,
    EcCurve::P521,
    EcCurve::Secp256k1,
];
/// The OKP curves `keys::generate` takes (RFC 8037 §2), in
/// [`OKP_CURVE_NAMES`] order.
const OKP_CURVES: [OkpCurve; 2] = [OkpCurve::Ed25519, OkpCurve::X25519];

/// `keys.generate_oct`, `keys.generate_ec`, `keys.generate_okp` (ADR 0018
/// §5; ADR 0030 `jwk_generate_oct`/`_ec`/`_okp`): generate with
/// `keys::generate`, check the key (private, exactly the RFC members, no
/// `alg`, imports back), return its shape, and run its use round trip.
fn run_keys_generate(
    operation: &str,
    input: &Object,
    expect: &Expect,
    out: &mut Object,
) -> Result<Result<(), Error>, String> {
    let key = match generate(input_spec(operation, input)) {
        Ok(key) => key,
        Err(e) => return Ok(Err(e)),
    };
    out.insert("shape", shape_of(&key, unbound_members)?);
    echo_use_with(&key, expect, out)?;
    Ok(Ok(()))
}

/// Runs the expectation's `use_with` round trip on `key`, if it has one,
/// and echoes it back as an output, as `verify_with` is.
fn echo_use_with(key: &Jwk, expect: &Expect, out: &mut Object) -> Result<(), String> {
    if let Expect::Ok(want) = expect
        && let Some(use_with) = want.get("use_with").and_then(Value::as_object)
    {
        check_use_with(key, use_with)?;
        out.insert("use_with", use_with.clone());
    }
    Ok(())
}

/// The payload or plaintext of every `use_with` round trip: `polyjose`.
const USE_WITH_PAYLOAD: &[u8] = b"polyjose";

/// The `use_with` round trip of a generated key (ADR 0034 §6), any failure
/// failing the vector. The other side uses the key's public key, or the
/// key itself for `oct` (RFC 7518 §6.4).
///
/// - Without `enc`: a compact JWS (RFC 7515 §7.1) of [`USE_WITH_PAYLOAD`]
///   under the protected header `{"alg": alg}`, signed with `key` and
///   verified with allow-list `[alg]` (RFC 7515 §5.1–§5.2).
/// - With `enc`: a compact JWE (RFC 7516 §7.1) of it to one recipient with
///   `alg`, decrypted with `key` and allow-lists `[alg]` and `[enc]`
///   (RFC 7516 §5.1–§5.2).
fn check_use_with(key: &Jwk, use_with: &Object) -> Result<(), String> {
    let alg = input_str(use_with, "alg");
    let other = key.to_public().unwrap_or_else(|| key.clone());
    let fail = |what: &str, e: Error| format!("use_with: {what} ({})", e.code());
    match use_with.get("enc").and_then(Value::as_str) {
        None => {
            let header = format!(r#"{{"alg":{}}}"#, Value::from(alg).to_json());
            let protected = ProtectedHeader::from_encoded(&b64url_encode(header.as_bytes()))
                .map_err(|e| fail("the protected header is refused", e))?;
            let token = jws::sign_compact(&protected, USE_WITH_PAYLOAD, key, &SignOptions::new())
                .map_err(|e| fail("the key does not sign", e))?;
            let algs = [SigningAlg::from(alg)];
            let opts =
                VerifyOptions::new(&algs).map_err(|e| fail("the allow-list is refused", e))?;
            let verified = jws::verify_compact(&token, &other, &opts)
                .map_err(|e| fail("the signature does not verify", e))?;
            if verified.payload.as_slice() != USE_WITH_PAYLOAD {
                return Err("use_with: the verified payload is not the signed one".to_owned());
            }
        }
        Some(enc) => {
            let token = Encryptor::new(ContentEncAlg::from(enc))
                .recipient(Recipient::new(KeyMgmtAlg::from(alg), &other))
                .encrypt_compact(USE_WITH_PAYLOAD)
                .map_err(|e| fail("encryption to the key fails", e))?;
            let policy = DecryptPolicy::new(&[KeyMgmtAlg::from(alg)], &[ContentEncAlg::from(enc)])
                .map_err(|e| fail("the allow-lists are refused", e))?;
            let decrypted = jwe::decrypt_compact(&token, key, &policy)
                .map_err(|e| fail("the key does not decrypt", e))?;
            if decrypted.plaintext() != USE_WITH_PAYLOAD {
                return Err("use_with: the decrypted plaintext is not the encrypted one".to_owned());
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// jwt.* handlers (RFC 7519), kept apart from the jws.* and jwe.* ones.
// ---------------------------------------------------------------------------

/// The verification keys of a `jwt.*` vector: `key` (one JWK) or `jwks`
/// (a JWK Set, RFC 7517 §5; ADR 0029 §1). The schema allows exactly one.
enum JwtKeys {
    One(Box<Jwk>),
    Set(Box<JwkSet>),
}

impl JwtKeys {
    fn keys(&self) -> Keys<'_> {
        match self {
            JwtKeys::One(key) => Keys::One(key),
            JwtKeys::Set(set) => Keys::Set(set),
        }
    }
}

/// Everything a JWT validation takes except the token, built from a
/// `jwt.validate` input or a `jwt.issue` `validate` object.
struct JwtValidation {
    /// `now` (ADR 0028 §4): the only clock the runner ever builds, so
    /// every platform gives the same verdict on every day.
    clock: FixedClock,
    algs: Vec<SigningAlg>,
    keys: JwtKeys,
    /// `decrypt`: the outer JWE layer's key and policy (ADR 0027 §7).
    decrypt: Option<(Jwk, DecryptPolicy)>,
    policy: Option<Object>,
}

/// Builds a [`JwtValidation`] in the order conformance/README.md fixes,
/// the outer layer first: `decrypt.key` (RFC 7517), then `decrypt`'s
/// allow-lists and bound, then `key` or `jwks` (RFC 7517 §4, §5). The first
/// error is the vector's outcome, so a JWK or JWK Set import error is its
/// result (for example ADR 0021's RSA private key, `UnsupportedAlgorithm`).
fn jwt_validation(object: &Object) -> Result<JwtValidation, Error> {
    let decrypt = match object.get("decrypt").and_then(Value::as_object) {
        Some(decrypt) => {
            let key = Jwk::from_object(input_object(decrypt, "key"))?;
            Some((key, jwe_policy(decrypt)?))
        }
        None => None,
    };
    let keys = match object.get("jwks").and_then(Value::as_object) {
        Some(set) => JwtKeys::Set(Box::new(JwkSet::from_object(set)?)),
        None => JwtKeys::One(Box::new(Jwk::from_object(input_object(object, "key"))?)),
    };
    let now = object
        .get("now")
        .and_then(Value::as_i64)
        .expect("validated");
    Ok(JwtValidation {
        clock: FixedClock(now),
        algs: input_algs(object),
        keys,
        decrypt,
        policy: object.get("policy").and_then(Value::as_object).cloned(),
    })
}

/// A `policy` member's strings: one string, or an array of them.
fn policy_names<'a>(policy: &'a Object, name: &str) -> Vec<&'a str> {
    match policy.get(name) {
        None => Vec::new(),
        Some(value) => match value.as_str() {
            Some(one) => vec![one],
            None => input_names(policy, name),
        },
    }
}

/// The JWT [`Policy`] for `clock`, `algs` and the vector's `policy`
/// (RFC 7519 §4.1, §7.2; RFC 8725 §3; ADR 0027 §3–§5, ADR 0029 §4). It
/// takes a [`FixedClock`] and nothing else, so the runner can never hand
/// the library a wall clock (ADR 0028 §4).
///
/// `profile: "access_token"` starts from `Policy::access_token` with the
/// `issuer` and `audience` lists (RFC 9068 §4); otherwise from
/// `Policy::new`, adding them. Each other member present calls its builder
/// method once; an absent member keeps the library default. The library's
/// refusals (an empty or `none` allow-list, a leeway over 600 s, an access
/// token policy without issuer or audience) are the vector's outcome.
///
/// A `typ` of mode `default` with `profile` is a broken vector (the outer
/// `Err`): the profile requires `at+jwt` (RFC 9068 §4), and no policy can
/// mean both.
fn jwt_policy<'a>(
    clock: &'a FixedClock,
    algs: &'a [SigningAlg],
    policy: Option<&Object>,
) -> Result<Result<Policy<'a>, Error>, String> {
    let empty = Object::new();
    let policy = policy.unwrap_or(&empty);
    let issuers = policy_names(policy, "issuer");
    let audiences = policy_names(policy, "audience");
    let typ = policy.get("typ").and_then(Value::as_object);
    let typ_mode = typ.map(|typ| input_str(typ, "mode"));
    let profile = policy.contains("profile");
    if profile && typ_mode == Some("default") {
        return Err(
            "`policy/typ/mode` \"default\" contradicts `policy/profile` \"access_token\", \
             which requires typ at+jwt (RFC 9068 §4)"
                .to_owned(),
        );
    }
    let built = if profile {
        Policy::access_token(clock, algs, &issuers, &audiences)
    } else {
        Policy::new(clock, algs).map(|p| p.issuers(&issuers).audiences(&audiences))
    };
    let mut built = match built {
        Ok(built) => built,
        Err(e) => return Ok(Err(e)),
    };
    if let Some(subject) = policy.get("subject").and_then(Value::as_str) {
        built = built.subject(subject);
    }
    if let Some(secs) = input_count(policy, "leeway") {
        match built.leeway(u32::try_from(secs).expect("validated: a u32")) {
            Ok(with) => built = with,
            Err(e) => return Ok(Err(e)),
        }
    }
    if let Some(secs) = input_count(policy, "max_age") {
        built = built.max_age(u32::try_from(secs).expect("validated: a u32"));
    }
    if policy.contains("require") {
        for claim in input_names(policy, "require") {
            built = built.require(claim);
        }
    }
    if policy.get("allow_missing_exp").and_then(Value::as_bool) == Some(true) {
        built = built.allow_missing_exp();
    }
    if policy.get("ignore_audience").and_then(Value::as_bool) == Some(true) {
        built = built.ignore_audience();
    }
    match typ_mode {
        Some("exact") => {
            built = built.expect_typ(input_str(typ.expect("present"), "value"));
        }
        Some("any") => built = built.any_typ(),
        // `default`, or absent: the library default (ADR 0027 §5).
        _ => {}
    }
    if let Some(n) = input_count(policy, "max_key_candidates") {
        built = built.max_key_candidates(n);
    }
    Ok(Ok(built))
}

/// Verifies `token` under `validation` and `policy`: `jwt::verify` for a
/// signed JWT, or `jwt::decrypt_nested` when the vector has `decrypt`
/// (RFC 7519 §7.2; ADR 0027 §7), whose inner JWT is the result.
fn jwt_verify(
    token: &str,
    validation: &JwtValidation,
    policy: &Policy<'_>,
) -> polyjose::Result<VerifiedJwt> {
    match &validation.decrypt {
        Some((key, decrypt_policy)) => {
            jwt::decrypt_nested(token, key, decrypt_policy, validation.keys.keys(), policy)
                .map(|nested| nested.inner)
        }
        None => jwt::verify(token, validation.keys.keys(), policy),
    }
}

/// The validated Claims Set as a JSON value (the library's own
/// serialization, ADR 0027 §1, read back), for comparison as JSON.
fn claims_value(verified: &VerifiedJwt) -> Result<Value, String> {
    json::parse(verified.claims.to_json().as_bytes()).map_err(|e| {
        format!(
            "the validated claims do not serialize as JSON: {}",
            e.code()
        )
    })
}

/// `jwt.validate` (RFC 7519 §7.2). The steps run in the order
/// conformance/README.md fixes for every runner, and the first error is
/// the outcome: build the inputs ([`jwt_validation`]), then the policy
/// ([`jwt_policy`]), then validate.
fn run_jwt_validate(input: &Object, out: &mut Object) -> Result<Result<(), Error>, String> {
    let validation = match jwt_validation(input) {
        Ok(validation) => validation,
        Err(e) => return Ok(Err(e)),
    };
    let policy = match jwt_policy(
        &validation.clock,
        &validation.algs,
        validation.policy.as_ref(),
    )? {
        Ok(policy) => policy,
        Err(e) => return Ok(Err(e)),
    };
    let verified = match jwt_verify(input_str(input, "token"), &validation, &policy) {
        Ok(verified) => verified,
        Err(e) => return Ok(Err(e)),
    };
    out.insert("claims", claims_value(&verified)?);
    out.insert("alg", verified.alg.as_str());
    if let Some(index) = verified.key_index {
        let index = u64::try_from(index).expect("an index fits u64");
        out.insert(
            "key_index",
            Number::from_u64(index).expect("an index is a safe integer"),
        );
    }
    Ok(Ok(()))
}

/// `jwt.issue` (RFC 7519 §7.1). The steps run in the order
/// conformance/README.md fixes, the first error being the outcome: import
/// `key` (RFC 7517), parse `claims` (RFC 7519 §4; ADR 0027 §1–§2), import
/// `encrypt.key`, sign with `alg` and `typ` (ADR 0027 §8), then encrypt
/// (ADR 0027 §7). The output must be a compact JWS (three parts, RFC 7515
/// §7.1) or, with `encrypt`, a compact JWE (five, RFC 7516 §7.1). An exact
/// expectation gets it as `token`; with `validate`, it is also validated
/// ([`check_jwt_issue_round_trip`]), any failure there failing the vector.
fn run_jwt_issue(
    input: &Object,
    expect: &Expect,
    out: &mut Object,
) -> Result<Result<(), Error>, String> {
    let key = match Jwk::from_object(input_object(input, "key")) {
        Ok(key) => key,
        Err(e) => return Ok(Err(e)),
    };
    let claims_in = input.get("claims").expect("validated");
    let claims = match Claims::from_json(claims_in.to_json().as_bytes()) {
        Ok(claims) => claims,
        Err(e) => return Ok(Err(e)),
    };
    let encryptor = match input.get("encrypt").and_then(Value::as_object) {
        Some(encrypt) => {
            let recipient_key = match Jwk::from_object(input_object(encrypt, "key")) {
                Ok(key) => key,
                Err(e) => return Ok(Err(e)),
            };
            let recipient =
                Recipient::new(KeyMgmtAlg::from(input_str(encrypt, "alg")), &recipient_key);
            Some(
                Encryptor::new(ContentEncAlg::from(input_str(encrypt, "enc"))).recipient(recipient),
            )
        }
        None => None,
    };
    let alg = input_str(input, "alg");
    let mut opts = IssueOptions::new(SigningAlg::from(alg));
    match input.get("typ") {
        Some(Value::Null) => opts = opts.no_typ(),
        Some(typ) => opts = opts.typ(typ.as_str().expect("validated")),
        None => {}
    }
    let signed = match jwt::sign(&claims, &opts, &key) {
        Ok(signed) => signed,
        Err(e) => return Ok(Err(e)),
    };
    let (token, parts) = match &encryptor {
        Some(encryptor) => match jwt::encrypt_nested(&signed, encryptor) {
            Ok(token) => (token, 5),
            Err(e) => return Ok(Err(e)),
        },
        None => (signed, 3),
    };
    if token.split('.').count() != parts {
        return Err(format!(
            "the issued token is not {parts} compact parts: {token}"
        ));
    }
    if let Some(validate) = input.get("validate").and_then(Value::as_object) {
        check_jwt_issue_round_trip(&token, alg, claims_in, validate)?;
    }
    if matches!(expect, Expect::Ok(want) if want.contains("token")) {
        out.insert("token", token);
    }
    Ok(Ok(()))
}

/// Validates an issued token with the vector's `validate` (RFC 7519 §7.2):
/// it must validate, with the `alg` it was signed with and the Claims Set
/// it was issued with (compared as JSON values). Any failure, including a
/// `validate` the library refuses, fails the vector.
fn check_jwt_issue_round_trip(
    token: &str,
    alg: &str,
    claims: &Value,
    validate: &Object,
) -> Result<(), String> {
    let validation = jwt_validation(validate)
        .map_err(|e| format!("round trip: `validate` does not import ({})", e.code()))?;
    let policy = jwt_policy(
        &validation.clock,
        &validation.algs,
        validation.policy.as_ref(),
    )?
    .map_err(|e| format!("round trip: `validate/policy` is refused ({})", e.code()))?;
    let verified = jwt_verify(token, &validation, &policy).map_err(|e| {
        format!(
            "round trip: the issued token does not validate with `validate` ({})",
            e.code()
        )
    })?;
    if verified.alg.as_str() != alg {
        return Err(format!(
            "round trip: validated with alg {}, issued with {alg}",
            verified.alg.as_str()
        ));
    }
    let validated = claims_value(&verified)?;
    if validated != *claims {
        return Err(format!(
            "round trip: validated claims {} are not the issued {}",
            validated.to_json(),
            claims.to_json()
        ));
    }
    Ok(())
}

/// Runs the operation through the public API: the success outputs, or the
/// library's error.
fn execute(vector: &Vector) -> Result<Result<Object, Error>, String> {
    let input = &vector.input;
    let mut out = Object::new();
    match vector.operation.as_str() {
        "b64url.encode" => {
            out.insert(
                "b64u",
                b64url_encode(&hex_decode(input_str(input, "bytes_hex"))),
            );
        }
        "b64url.decode" => match b64url_decode(input_str(input, "b64u")) {
            Ok(bytes) => {
                out.insert("bytes_hex", hex_encode(&bytes));
            }
            Err(e) => return Ok(Err(e)),
        },
        "jwk.thumbprint" => {
            // `hash` is validated to be "sha-256", the only one implemented.
            let jwk = input
                .get("jwk")
                .and_then(Value::as_object)
                .expect("validated");
            match Jwk::from_object(jwk) {
                Ok(key) => {
                    out.insert("thumbprint", key.thumbprint_sha256());
                    out.insert("thumbprint_uri", key.thumbprint_uri_sha256());
                }
                Err(e) => return Ok(Err(e)),
            }
        }
        "jws.sign" => {
            if let Err(e) = run_jws_sign(input, &vector.expect, &mut out)? {
                return Ok(Err(e));
            }
        }
        "jws.verify" => {
            if let Err(e) = run_jws_verify(input, &mut out)? {
                return Ok(Err(e));
            }
        }
        "jwe.encrypt" => {
            if let Err(e) = run_jwe_encrypt(input, &vector.expect, &mut out)? {
                return Ok(Err(e));
            }
        }
        "jwe.decrypt" => {
            if let Err(e) = run_jwe_decrypt(input, &mut out)? {
                return Ok(Err(e));
            }
        }
        "keys.import_pem" => {
            if let Err(e) = run_keys_import_pem(input, &mut out)? {
                return Ok(Err(e));
            }
        }
        "keys.export_pem" => {
            if let Err(e) = run_keys_export_pem(input, &mut out)? {
                return Ok(Err(e));
            }
        }
        "keys.import_der" => {
            if let Err(e) = run_keys_import_der(input, &mut out)? {
                return Ok(Err(e));
            }
        }
        "keys.export_der" => {
            if let Err(e) = run_keys_export_der(input, &mut out)? {
                return Ok(Err(e));
            }
        }
        "keys.generate_for" => {
            if let Err(e) = run_keys_generate_for(input, &vector.expect, &mut out)? {
                return Ok(Err(e));
            }
        }
        "keys.generate_oct" | "keys.generate_ec" | "keys.generate_okp" => {
            if let Err(e) = run_keys_generate(&vector.operation, input, &vector.expect, &mut out)? {
                return Ok(Err(e));
            }
        }
        "jwt.validate" => {
            if let Err(e) = run_jwt_validate(input, &mut out)? {
                return Ok(Err(e));
            }
        }
        "jwt.issue" => {
            if let Err(e) = run_jwt_issue(input, &vector.expect, &mut out)? {
                return Ok(Err(e));
            }
        }
        other => {
            return Err(format!(
                "operation `{other}` is not implemented by the Rust runner; a vector is never skipped"
            ));
        }
    }
    Ok(Ok(out))
}

/// Compares the outcome with the expectation: on success the outputs must
/// be exactly the expected members (an optional output, such as
/// `jwt.validate`'s `key_index`, can't be left out unnoticed), each equal as
/// a JSON value (RFC 8259: object member order ignored, numbers compared
/// as doubles, RFC 7493 §2.2).
fn compare(expect: &Expect, outcome: &Result<Object, Error>) -> Result<(), String> {
    match (expect, outcome) {
        (Expect::Ok(want), Ok(got)) => {
            for (name, value) in want {
                let got_value = got.get(name);
                if got_value != Some(value) {
                    return Err(format!(
                        "`{name}`: expected {}, got {}",
                        value.to_json(),
                        got_value.map_or("nothing".to_owned(), Value::to_json)
                    ));
                }
            }
            for (name, value) in got {
                if !want.contains(name) {
                    return Err(format!(
                        "`{name}`: expected nothing, got {}",
                        value.to_json()
                    ));
                }
            }
            Ok(())
        }
        (Expect::Ok(_), Err(e)) => Err(format!("expected success, got error {}", e.code())),
        (Expect::Err(code), Ok(got)) => Err(format!(
            "expected error {code}, but the operation succeeded with {}",
            got.to_json()
        )),
        (Expect::Err(code), Err(e)) if e.code() == code => Ok(()),
        (Expect::Err(code), Err(e)) => {
            Err(format!("expected error {code}, got error {}", e.code()))
        }
    }
}

/// A vector that did not fail.
#[derive(Debug)]
enum Passed {
    /// It ran and met its expectation.
    Ran {
        operation: String,
        /// Whether it expects a failure (`"ok": false`).
        negative: bool,
    },
    /// It needs `missing`, which this build does not enable, or must run
    /// without `present`, which it enables (ADR 0056); it was validated but
    /// not run, and never counts as passing.
    Skipped {
        missing: Vec<&'static str>,
        present: Vec<&'static str>,
    },
}

impl Passed {
    /// A skip's results-file `reason` (ADR 0034 §3, ADR 0056 §2):
    /// `feature:`, the missing names in `features` order, then each
    /// enabled `features_absent` name as `!<name>` in its order.
    fn skip_reason(missing: &[&str], present: &[&str]) -> String {
        let names: Vec<String> = missing
            .iter()
            .map(|f| (*f).to_owned())
            .chain(present.iter().map(|f| format!("!{f}")))
            .collect();
        format!("feature:{}", names.join(","))
    }
}

/// Parses a vector file. Vector files are trusted test data, so they get a
/// 4 MiB input limit (conformance/README.md), room for a JWS just over the
/// library's 1 MiB default (ADR 0026 §7); every other JSON limit, and the
/// library under test, keep their defaults.
fn parse_vector_file(bytes: &[u8]) -> polyjose::Result<Value> {
    let mut limits = json::Limits::DEFAULT;
    limits.max_input_len = 4 * 1024 * 1024;
    json::parse_with_limits(bytes, &limits)
}

/// Checks one vector file: parse, validate, run, compare. Returns what
/// passed (or was skipped for a missing feature), or a failure message
/// naming the file and the `source`.
fn check_vector(name: &str, bytes: &[u8]) -> Result<Passed, String> {
    check_vector_with(name, bytes, &enabled_features())
}

/// [`check_vector`] with `enabled` as the build's features.
fn check_vector_with(name: &str, bytes: &[u8], enabled: &[&str]) -> Result<Passed, String> {
    check_vector_traced(name, bytes, enabled, &mut Trace::default())
}

/// What a results file records of one vector besides its status
/// (ADR 0034 §2). Filled in as [`check_vector_traced`] goes; recording
/// never changes how the vector is evaluated.
#[derive(Debug, Default)]
struct Trace {
    /// The vector's `source`, when usable (ADR 0034 §1: reported
    /// alongside the id).
    source: Option<String>,
    /// The vector's `operation`, when the file parses and names one.
    op: Option<String>,
    /// The operation's outcome, when it returned one: success, or the
    /// library's error code.
    actual: Option<Result<(), &'static str>>,
}

/// [`check_vector_with`], recording into `trace` the vector's `source`,
/// `operation` and, once the operation has run, its outcome.
fn check_vector_traced(
    name: &str,
    bytes: &[u8],
    enabled: &[&str],
    trace: &mut Trace,
) -> Result<Passed, String> {
    let value = parse_vector_file(bytes)
        .map_err(|e| format!("{name}: not a valid JSON text ({e}); see conformance/schema.json"))?;
    trace.source = usable_source(&value);
    trace.op = value
        .get("operation")
        .and_then(Value::as_str)
        .filter(|op| is_text(op))
        .map(str::to_owned);
    let source = usable_source(&value).unwrap_or_else(|| "<missing>".to_owned());
    let fail = |problem: String| format!("{name} (source: {source}): {problem}");
    let vector = validate(&value).map_err(fail)?;
    let missing: Vec<&'static str> = vector
        .features
        .iter()
        .copied()
        .filter(|f| !enabled.contains(f))
        .collect();
    let present: Vec<&'static str> = vector
        .features_absent
        .iter()
        .copied()
        .filter(|f| enabled.contains(f))
        .collect();
    if !missing.is_empty() || !present.is_empty() {
        return Ok(Passed::Skipped { missing, present });
    }
    let outcome = catch_unwind(AssertUnwindSafe(|| execute(&vector)))
        .map_err(|_| fail("panicked while running".to_owned()))?
        .map_err(fail)?;
    trace.actual = Some(outcome.as_ref().map(|_| ()).map_err(Error::code));
    compare(&vector.expect, &outcome).map_err(fail)?;
    Ok(Passed::Ran {
        negative: matches!(vector.expect, Expect::Err(_)),
        operation: vector.operation,
    })
}

/// Every check over a vectors directory.
#[derive(Debug, Default)]
struct Report {
    files: usize,
    /// Passing vectors per operation.
    passed: BTreeMap<String, usize>,
    /// Passing failure (`"ok": false`) vectors per operation.
    passed_negative: BTreeMap<String, usize>,
    /// `SKIPPED (needs feature ...)` lines, one per skipped vector file.
    skipped: Vec<String>,
    failures: Vec<String>,
    /// One results-file entry per vector file, in file order (ADR 0034
    /// §2; see [`result_entry`]).
    results: Vec<Object>,
    /// Whether every vector file was found: false when the walk itself
    /// failed (an unreadable directory, a symbolic link) or found nothing,
    /// so the results would not cover every vector.
    complete: bool,
}

/// A vector's id (ADR 0034 §1 as amended by ADR 0045 §4): its path under
/// the vectors directory, `/`-separated on every platform, then `#0`, as
/// every file holds one vector.
fn vector_id(relative: &Path) -> String {
    let parts: Vec<String> = relative
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    format!("{}#0", parts.join("/"))
}

/// One results-file entry (`conformance/schema/results.schema.json`):
/// `id`, then `source` and `op` when known, `status`, `actual` for a vector
/// that ran, and `reason` for a skip (`feature:` and the missing feature
/// names, in the vector's order, ADR 0034 §3) or a failure (its message).
fn result_entry(id: String, trace: Trace, result: &Result<Passed, String>) -> Object {
    let mut entry = Object::new();
    entry.insert("id", id);
    if let Some(source) = trace.source {
        entry.insert("source", source);
    }
    if let Some(op) = trace.op {
        entry.insert("op", op);
    }
    let status = match result {
        Ok(Passed::Ran { .. }) => "pass",
        Ok(Passed::Skipped { .. }) => "skipped",
        Err(_) => "fail",
    };
    entry.insert("status", status);
    // A skipped vector never ran, so it has no outcome.
    if let Some(actual) = trace.actual {
        let mut outcome = Object::new();
        outcome.insert("ok", actual.is_ok());
        if let Err(code) = actual {
            outcome.insert("error", code);
        }
        entry.insert("actual", outcome);
    }
    match result {
        Ok(Passed::Ran { .. }) => {}
        Ok(Passed::Skipped { missing, present }) => {
            entry.insert("reason", Passed::skip_reason(missing, present));
        }
        Err(message) => {
            entry.insert("reason", message.as_str());
        }
    }
    entry
}

/// Every `*.json` file under `dir`, recursively, sorted. A symbolic link is
/// a failure: vectors must be regular files every platform reads the same.
fn collect(dir: &Path, files: &mut Vec<PathBuf>, failures: &mut Vec<String>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            failures.push(format!("{}: cannot read directory: {e}", dir.display()));
            return;
        }
    };
    for entry in entries {
        let (path, file_type) = match entry.and_then(|e| Ok((e.path(), e.file_type()?))) {
            Ok(pair) => pair,
            Err(e) => {
                failures.push(format!("{}: cannot read entry: {e}", dir.display()));
                continue;
            }
        };
        if file_type.is_symlink() {
            failures.push(format!(
                "{}: symbolic links are not allowed",
                path.display()
            ));
        } else if file_type.is_dir() {
            collect(&path, files, failures);
        } else if path.extension().is_some_and(|e| e == "json") {
            files.push(path);
        }
    }
}

fn run_dir(dir: &Path) -> Report {
    run_dir_with(dir, &enabled_features())
}

/// [`run_dir`] with `enabled` as the build's features.
fn run_dir_with(dir: &Path, enabled: &[&str]) -> Report {
    let mut report = Report::default();
    let mut files = Vec::new();
    collect(dir, &mut files, &mut report.failures);
    files.sort();
    report.files = files.len();
    if files.is_empty() {
        report
            .failures
            .push(format!("{}: no vector files (*.json) found", dir.display()));
    }
    report.complete = report.failures.is_empty();
    for path in files {
        let relative = path.strip_prefix(dir).unwrap_or(&path);
        let name = relative.display().to_string();
        let mut trace = Trace::default();
        let result = std::fs::read(&path)
            .map_err(|e| format!("{name}: cannot read: {e}"))
            .and_then(|bytes| check_vector_traced(&name, &bytes, enabled, &mut trace));
        report
            .results
            .push(result_entry(vector_id(relative), trace, &result));
        match result {
            Ok(Passed::Ran {
                operation,
                negative,
            }) => {
                if negative {
                    *report.passed_negative.entry(operation.clone()).or_default() += 1;
                }
                *report.passed.entry(operation).or_default() += 1;
            }
            Ok(Passed::Skipped { missing, present }) => {
                let cargo = |names: &[&str]| {
                    names
                        .iter()
                        .map(|f| format!("`{}`", cargo_feature(f)))
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                let mut why = Vec::new();
                if !missing.is_empty() {
                    why.push(format!("needs feature {}", cargo(&missing)));
                }
                if !present.is_empty() {
                    why.push(format!("needs feature {} off", cargo(&present)));
                }
                report
                    .skipped
                    .push(format!("{name}: SKIPPED ({})", why.join("; ")));
            }
            Err(msg) => report.failures.push(msg),
        }
    }
    report
}

fn conformance_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance")
}

/// Where every runner writes its results file (ADR 0034 §2):
/// `target/conformance/` at the repository root, whatever `CARGO_TARGET_DIR`
/// says, so `scripts/conformance-parity.sh` finds every runner's file in
/// one place.
fn results_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/conformance")
}

/// This build's results file name. Only the default-features build is the
/// reference run, `rust-core.json` (ADR 0034 §4); a build with features
/// writes `rust-core-<features>.json` (`rust-core-fixed-rng.json`,
/// `rust-core-deflate-fixed-rng.json`, ...), which the parity check
/// ignores.
fn results_file_name(enabled: &[&str]) -> String {
    if enabled.is_empty() {
        format!("{RUST_CORE}.json")
    } else {
        format!("{RUST_CORE}-{}.json", enabled.join("-"))
    }
}

/// The results file text (`conformance/schema/results.schema.json`): the
/// runner, the crate version, the enabled `features`, `Error::CODES`
/// (ADR 0034 §8) and the results, one per line so a file can be searched
/// by id.
fn results_document(enabled: &[&str], results: &[Object]) -> String {
    let strings = |items: &[&str]| -> Value {
        Value::from(items.iter().map(|s| Value::from(*s)).collect::<Vec<_>>())
    };
    let header: [(&str, Value); 4] = [
        ("runner", Value::from(RUST_CORE)),
        ("polyjose", Value::from(env!("CARGO_PKG_VERSION"))),
        ("features", strings(enabled)),
        ("error_codes", strings(Error::CODES)),
    ];
    let mut text = String::from("{\n");
    for (name, value) in &header {
        text.push_str(&format!(
            "  {}: {},\n",
            Value::from(*name).to_json(),
            value.to_json()
        ));
    }
    text.push_str("  \"results\": [");
    for (i, result) in results.iter().enumerate() {
        text.push_str(if i == 0 { "\n    " } else { ",\n    " });
        text.push_str(&result.to_json());
    }
    text.push_str(if results.is_empty() {
        "]\n}\n"
    } else {
        "\n  ]\n}\n"
    });
    text
}

/// Writes `report`'s results to `dir/file`, replacing any earlier file
/// atomically (a temporary file, then a rename), and returns its path. A
/// report whose walk was incomplete is not written: any earlier file is
/// removed instead, so a run that could not see every vector leaves no
/// stale or partial reference behind (the parity check then fails on the
/// missing file).
fn write_results(
    dir: &Path,
    file: &str,
    enabled: &[&str],
    report: &Report,
) -> Result<Option<PathBuf>, String> {
    let path = dir.join(file);
    if !report.complete {
        return match std::fs::remove_file(&path) {
            Ok(()) => Ok(None),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("{}: cannot remove: {e}", path.display())),
        };
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: cannot create: {e}", dir.display()))?;
    let temporary = dir.join(format!(".{file}.{}.tmp", std::process::id()));
    std::fs::write(&temporary, results_document(enabled, &report.results))
        .map_err(|e| format!("{}: cannot write: {e}", temporary.display()))?;
    std::fs::rename(&temporary, &path)
        .map_err(|e| format!("{}: cannot write: {e}", path.display()))?;
    Ok(Some(path))
}

/// The shared vectors: every file must be schema-valid and pass. The run
/// also writes this build's results file (ADR 0034 §2, §4; see
/// [`results_file_name`]), checked against `results.schema.json`, before
/// any assertion, so a failing run is recorded too.
#[test]
fn conformance_vectors() {
    let report = run_dir(&conformance_dir().join("vectors"));
    let enabled = enabled_features();
    let written = write_results(
        &results_dir(),
        &results_file_name(&enabled),
        &enabled,
        &report,
    )
    .unwrap_or_else(|e| panic!("results file: {e}"));
    if let Some(path) = written {
        let text = std::fs::read(&path).unwrap();
        if let Err(e) = check_results_text(&text) {
            panic!("{}: not valid per results.schema.json: {e}", path.display());
        }
    }
    assert!(
        report.failures.is_empty(),
        "{} of {} conformance vector file(s) failed:\n  {}",
        report.failures.len(),
        report.files,
        report.failures.join("\n  ")
    );
    let passed: usize = report.passed.values().sum();
    eprintln!(
        "conformance: {passed} of {} vectors passed {:?}; {} skipped",
        report.files,
        report.passed,
        report.skipped.len()
    );
    for line in &report.skipped {
        eprintln!("  {line}");
    }
    assert_eq!(
        passed + report.skipped.len(),
        report.files,
        "every vector file either passes or is skipped for a named feature"
    );
}

/// Every implemented operation has vectors, and every operation that can
/// fail has both success and failure vectors.
#[test]
fn every_implemented_operation_has_vectors() {
    let report = run_dir(&conformance_dir().join("vectors"));
    for spec in SPECS {
        let all = report.passed.get(spec.name).copied().unwrap_or(0);
        let negative = report.passed_negative.get(spec.name).copied().unwrap_or(0);
        assert!(all > negative, "{}: no passing success vectors", spec.name);
        assert!(
            !spec.can_fail || negative > 0,
            "{}: no passing failure vectors",
            spec.name
        );
    }
}

// ---------------------------------------------------------------------------
// schema.json and this runner must say the same thing.
// ---------------------------------------------------------------------------

fn schema() -> Value {
    let bytes = std::fs::read(conformance_dir().join("schema.json")).unwrap();
    json::parse(&bytes).expect("schema.json is I-JSON")
}

fn parse(json: &str) -> Value {
    json::parse(json.as_bytes()).unwrap()
}

fn at<'a>(value: &'a Value, path: &[&str]) -> &'a Value {
    path.iter().fold(value, |v, name| {
        v.get(name)
            .unwrap_or_else(|| panic!("schema.json: no member {path:?}"))
    })
}

fn strings(value: &Value) -> Vec<&str> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect()
}

fn member_names(value: &Value) -> Vec<&str> {
    value.as_object().unwrap().iter().map(|(n, _)| n).collect()
}

/// The value without its `description` annotation.
fn annotated(value: &Value) -> Value {
    let mut object = value.as_object().unwrap().clone();
    object.remove("description");
    Value::from(object)
}

/// How `kind` is spelled in the schema.
fn schema_kind(kind: Kind) -> Value {
    if let Some(def) = kind.def() {
        return parse(&format!(r##"{{"$ref":"#/$defs/{def}"}}"##));
    }
    match kind {
        Kind::Hex
        | Kind::Base64url
        | Kind::Count
        | Kind::Jws
        | Kind::AlgList
        | Kind::Jwe
        | Kind::Nested(_)
        | Kind::Seconds => {
            unreachable!("a $ref kind")
        }
        Kind::StringList => parse(r#"{"type":"array","items":{"type":"string"}}"#),
        Kind::StringOrList => parse(r#"{"type":["string","array"],"items":{"type":"string"}}"#),
        Kind::StringOrNull => parse(r#"{"type":["string","null"]}"#),
        Kind::Bool => parse(r#"{"type":"boolean"}"#),
        Kind::List(shape) => parse(&format!(
            r##"{{"type":"array","minItems":1,"items":{{"$ref":"#/$defs/{}"}}}}"##,
            shape.def
        )),
        Kind::String => parse(r#"{"type":"string"}"#),
        Kind::Object => parse(r#"{"type":"object"}"#),
        Kind::Enum(values) => {
            let mut object = Object::new();
            object.insert(
                "enum",
                values.iter().map(|v| Value::from(*v)).collect::<Vec<_>>(),
            );
            Value::from(object)
        }
    }
}

/// How a [`Rule`] is spelled in the schema's `allOf`.
fn schema_rule(rule: &Rule) -> Value {
    match rule {
        Rule::Signers(rule) => schema_signer_rule(rule),
        Rule::ExactlyOne(names) => {
            let alternatives: Vec<String> = names
                .iter()
                .map(|n| format!(r#"{{"required":["{n}"]}}"#))
                .collect();
            parse(&format!(r#"{{"oneOf":[{}]}}"#, alternatives.join(",")))
        }
        Rule::OnlyWhen {
            member,
            value,
            dependent,
        } => parse(&format!(
            r#"{{"if":{{"properties":{{"{member}":{{"const":"{value}"}}}}}},"then":{{"required":["{dependent}"]}},"else":{{"properties":{{"{dependent}":false}}}}}}"#
        )),
    }
}

/// How a [`SignerRule`] is spelled in the schema's `allOf`.
fn schema_signer_rule(rule: &SignerRule) -> Value {
    let mut signers = format!(r#""maxItems":{}"#, rule.max_signers);
    if !rule.requires.is_empty() || !rule.forbids.is_empty() {
        let required: Vec<Value> = rule.requires.iter().map(|n| Value::from(*n)).collect();
        let forbidden: Vec<String> = rule
            .forbids
            .iter()
            .map(|n| format!(r#""{n}":false"#))
            .collect();
        signers.push_str(&format!(
            r#","items":{{"required":{},"properties":{{{}}}}}"#,
            Value::from(required).to_json(),
            forbidden.join(",")
        ));
    }
    parse(&format!(
        r#"{{"if":{{"properties":{{"serialization":{{"const":"{}"}}}}}},"then":{{"properties":{{"signers":{{{signers}}}}}}}}}"#,
        rule.serialization
    ))
}

/// `$ref` target name of `{"$ref": "#/$defs/<name>"}`.
fn def_ref<'a>(value: &'a Value, used: &mut Vec<String>) -> &'a str {
    let target = value.get("$ref").and_then(Value::as_str).unwrap();
    let name = target.strip_prefix("#/$defs/").unwrap();
    used.push(name.to_owned());
    name
}

/// A `$defs` object definition: exactly the keywords checked here, closed,
/// and its members (after `ok: {"const": true}` when `ok` is set) are
/// `shape`'s, in order, with the same kinds and the same `required` list.
fn check_def(defs: &Value, shape: &Shape, ok: bool, used: &mut Vec<String>) {
    let name = shape.def;
    used.push(name.to_owned());
    let def = at(defs, &[name]);
    let mut keywords = vec!["type", "required", "additionalProperties", "properties"];
    if !shape.rules.is_empty() {
        keywords.push("allOf");
        let rules: Vec<Value> = shape.rules.iter().map(schema_rule).collect();
        assert_eq!(*at(def, &["allOf"]), Value::from(rules), "{name}: allOf");
    }
    assert_eq!(member_names(&annotated(def)), keywords, "{name}: keywords");
    let mut names: Vec<&str> = shape.members.iter().map(|m| m.name).collect();
    let mut required: Vec<&str> = shape
        .members
        .iter()
        .filter(|m| m.required)
        .map(|m| m.name)
        .collect();
    if ok {
        names.insert(0, "ok");
        required.insert(0, "ok");
        assert_eq!(
            *at(def, &["properties", "ok"]),
            parse(r#"{"const":true}"#),
            "{name}"
        );
    }
    assert_eq!(at(def, &["type"]).as_str(), Some("object"), "{name}");
    assert_eq!(
        at(def, &["additionalProperties"]).as_bool(),
        Some(false),
        "{name}"
    );
    assert_eq!(strings(at(def, &["required"])), required, "{name}");
    assert_eq!(member_names(at(def, &["properties"])), names, "{name}");
    for member in shape.members {
        used.extend(member.kind.def().map(str::to_owned));
        if let Kind::Nested(inner) | Kind::List(inner) = member.kind {
            check_def(defs, inner, false, used);
        }
        let property = at(def, &["properties", member.name]);
        assert_eq!(
            annotated(property),
            schema_kind(member.kind),
            "{name}/{}",
            member.name
        );
    }
}

/// Drift guard: the hand-written validator implements exactly schema.json.
#[test]
fn schema_and_runner_agree() {
    let schema = schema();
    let defs = at(&schema, &["$defs"]);
    let mut used = Vec::new();

    assert_eq!(
        at(&schema, &["$schema"]).as_str(),
        Some("https://json-schema.org/draft/2020-12/schema")
    );
    // Root keywords: annotations plus exactly the constraints checked below.
    assert_eq!(
        member_names(&schema),
        [
            "$schema",
            "title",
            "description",
            "type",
            "required",
            "additionalProperties",
            "properties",
            "allOf",
            "$defs"
        ]
    );
    assert_eq!(at(&schema, &["type"]).as_str(), Some("object"));
    assert_eq!(
        at(&schema, &["additionalProperties"]).as_bool(),
        Some(false)
    );
    assert_eq!(strings(at(&schema, &["required"])), TOP_LEVEL);
    let mut properties = TOP_LEVEL.to_vec();
    properties.extend(TOP_LEVEL_OPTIONAL);
    assert_eq!(member_names(at(&schema, &["properties"])), properties);
    let mut features = Object::new();
    features.insert(
        "enum",
        feature_names()
            .into_iter()
            .map(Value::from)
            .collect::<Vec<_>>(),
    );
    let mut expected = parse(r#"{"type":"array","uniqueItems":true}"#)
        .into_object()
        .unwrap();
    expected.insert("items", features);
    assert_eq!(
        annotated(at(&schema, &["properties", "features"])),
        Value::from(expected.clone()),
        "features"
    );
    // ADR 0056: the same names, at least one.
    let mut absent = parse(r#"{"type":"array","minItems":1,"uniqueItems":true}"#)
        .into_object()
        .unwrap();
    absent.insert("items", expected.get("items").unwrap().clone());
    assert_eq!(
        annotated(at(&schema, &["properties", "features_absent"])),
        Value::from(absent),
        "features_absent"
    );
    for name in ["source", "description"] {
        let property = annotated(at(&schema, &["properties", name]));
        assert_eq!(property, parse(r##"{"$ref":"#/$defs/text"}"##));
        def_ref(&property, &mut used);
    }
    assert_eq!(
        *at(defs, &["text"]),
        parse(&format!(
            r#"{{"type":"string","minLength":1,"pattern":{}}}"#,
            Value::from(TEXT_PATTERN).to_json()
        ))
    );
    assert_eq!(
        member_names(at(&schema, &["properties", "operation"])),
        ["enum"]
    );
    assert_eq!(
        strings(at(&schema, &["properties", "operation", "enum"])),
        OPERATIONS
    );
    assert_eq!(
        *at(&schema, &["properties", "input"]),
        parse(r#"{"type":"object"}"#)
    );
    assert_eq!(
        *at(&schema, &["properties", "expect"]),
        parse(r#"{"type":"object","required":["ok"],"properties":{"ok":{"type":"boolean"}}}"#)
    );

    for (name, pattern) in [("hex", HEX_PATTERN), ("base64url", BASE64URL_PATTERN)] {
        assert_eq!(
            annotated(at(defs, &[name])),
            parse(&format!(
                r#"{{"type":"string","pattern":{}}}"#,
                Value::from(pattern).to_json()
            )),
            "{name}"
        );
    }
    assert_eq!(
        member_names(&annotated(at(defs, &["error_code"]))),
        ["enum"]
    );
    assert_eq!(strings(at(defs, &["error_code", "enum"])), Error::CODES);
    assert_eq!(
        annotated(at(defs, &["failure"])),
        parse(
            r##"{"type":"object","required":["ok","error"],"additionalProperties":false,
                "properties":{"ok":{"const":false},"error":{"$ref":"#/$defs/error_code"}}}"##
        )
    );
    used.extend(["error_code"].map(str::to_owned));
    assert_eq!(
        annotated(at(defs, &["count"])),
        parse(&format!(
            r#"{{"type":"integer","minimum":0,"maximum":{COUNT_MAX}}}"#
        ))
    );
    assert_eq!(
        annotated(at(defs, &["seconds"])),
        parse(&format!(
            r#"{{"type":"integer","minimum":-{SECONDS_MAX},"maximum":{SECONDS_MAX}}}"#
        ))
    );
    assert_eq!(
        annotated(at(defs, &["jws"])),
        parse(r#"{"type":["string","object"]}"#)
    );
    assert_eq!(
        annotated(at(defs, &["alg_list"])),
        parse(r#"{"type":"array","items":{"type":"string"}}"#)
    );
    assert_eq!(
        annotated(at(defs, &["jwe"])),
        parse(r#"{"type":["string","object"]}"#)
    );

    let rules = at(&schema, &["allOf"]).as_array().unwrap();
    assert_eq!(
        rules.len(),
        SPECS.len(),
        "one if/then rule per implemented operation"
    );
    for (rule, spec) in rules.iter().zip(SPECS) {
        assert_eq!(member_names(rule), ["if", "then"]);
        assert_eq!(
            *at(rule, &["if"]),
            parse(&format!(
                r#"{{"required":["operation"],"properties":{{"operation":{{"const":"{}"}}}}}}"#,
                spec.name
            ))
        );
        let then = at(rule, &["then"]);
        assert_eq!(member_names(then), ["properties"], "{}", spec.name);
        assert_eq!(member_names(at(then, &["properties"])), ["input", "expect"]);
        let input = def_ref(at(then, &["properties", "input"]), &mut used);
        assert_eq!(input, spec.input.def, "{}", spec.name);
        check_def(defs, spec.input, false, &mut used);

        // The success forms, then `failure` if the operation can fail: one
        // `$ref`, or a `oneOf` of them in that order.
        let mut alternatives: Vec<&str> = spec.ok.iter().map(|s| s.def).collect();
        if spec.can_fail {
            alternatives.push("failure");
        }
        let expect = at(then, &["properties", "expect"]);
        let refs: Vec<&str> = if alternatives.len() == 1 {
            assert_eq!(member_names(expect), ["$ref"], "{}", spec.name);
            vec![def_ref(expect, &mut used)]
        } else {
            assert_eq!(member_names(expect), ["oneOf"], "{}", spec.name);
            at(expect, &["oneOf"])
                .as_array()
                .unwrap()
                .iter()
                .map(|alternative| def_ref(alternative, &mut used))
                .collect()
        };
        assert_eq!(refs, alternatives, "{}", spec.name);
        for shape in spec.ok {
            check_def(defs, shape, true, &mut used);
        }
    }

    // No stale definitions.
    let mut defined: Vec<&str> = member_names(defs);
    defined.sort_unstable();
    used.sort();
    used.dedup();
    assert_eq!(defined, used, "every $defs entry is used");
}

/// The hand-written checks implement the schema's patterns.
#[test]
fn hand_written_checks_match_the_patterns() {
    // ^([0-9a-f]{2})*$
    for (s, ok) in [
        ("", true),
        ("00", true),
        ("0aff", true),
        ("0", false),
        ("0A", false),
        ("0g", false),
        ("00 ", false),
    ] {
        assert_eq!(is_hex(s), ok, "{s:?}");
    }
    // ^[A-Za-z0-9_-]*$
    for (s, ok) in [
        ("", true),
        ("AZaz09-_", true),
        ("Zg==", false),
        ("+/", false),
        ("a b", false),
        ("é", false),
    ] {
        assert_eq!(is_base64url_alphabet(s), ok, "{s:?}");
    }
    // minLength 1 and \S
    for (s, ok) in [
        ("", false),
        (" ", false),
        ("\t\r\n", false),
        ("x", true),
        (" RFC 4648 ", true),
    ] {
        assert_eq!(is_text(s), ok, "{s:?}");
    }
    // {"type": "integer", "minimum": 0, "maximum": 4294967295}
    for (json, ok) in [
        ("0", true),
        ("16", true),
        ("4294967295", true),
        ("1.0", true), // JSON Schema: an integer value is an integer
        ("4294967296", false),
        ("-1", false),
        ("1.5", false),
        ("\"1\"", false),
        ("null", false),
    ] {
        assert_eq!(is_count(&parse(json)), ok, "{json}");
    }
    // {"type": "integer", "minimum": -9007199254740991,
    //  "maximum": 9007199254740991}
    for (json, ok) in [
        ("0", true),
        ("-1", true),
        ("1300819380", true),
        ("9007199254740991", true),
        ("-9007199254740991", true),
        ("1.0", true),
        ("9007199254740992", false),
        ("-9007199254740992", false),
        ("1.5", false),
        ("\"1\"", false),
        ("null", false),
    ] {
        assert_eq!(is_seconds(&parse(json)), ok, "{json}");
    }
}

// ---------------------------------------------------------------------------
// Tests of the runner itself (criteria 1-3). Fixtures live in memory or in a
// temporary directory, never under conformance/vectors/.
// ---------------------------------------------------------------------------

const SOURCE: &str = "runner self-test 7f3a";

fn vector(operation: &str, input: &str, expect: &str) -> String {
    format!(
        r#"{{"source":"{SOURCE}","description":"self-test","operation":"{operation}","input":{input},"expect":{expect}}}"#
    )
}

fn fails_naming_source(name: &str, json: &str, needle: &str) {
    match check_vector(name, json.as_bytes()) {
        Ok(passed) => panic!("{name}: expected a failure, but it passed: {passed:?}: {json}"),
        Err(msg) => {
            assert!(msg.contains(name), "file name missing from {msg:?}");
            assert!(msg.contains(SOURCE), "source missing from {msg:?}");
            assert!(msg.contains(needle), "{needle:?} missing from {msg:?}");
        }
    }
}

#[test]
fn valid_vectors_pass() {
    let cases = [
        vector(
            "b64url.encode",
            r#"{"bytes_hex":"666f6f"}"#,
            r#"{"ok":true,"b64u":"Zm9v"}"#,
        ),
        vector(
            "b64url.decode",
            r#"{"b64u":"Zm9v"}"#,
            r#"{"ok":true,"bytes_hex":"666f6f"}"#,
        ),
        vector(
            "b64url.decode",
            r#"{"b64u":"Zg=="}"#,
            r#"{"ok":false,"error":"InvalidBase64"}"#,
        ),
        vector(
            "jwk.thumbprint",
            r#"{"hash":"sha-256","jwk":{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}}"#,
            r#"{"ok":true,"thumbprint":"kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k","thumbprint_uri":"urn:ietf:params:oauth:jwk-thumbprint:sha-256:kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"}"#,
        ),
        vector(
            "jwk.thumbprint",
            r#"{"hash":"sha-256","jwk":{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg=="}}"#,
            r#"{"ok":false,"error":"InvalidBase64"}"#,
        ),
        // RFC 8410 §10.1; member order of the expected JWK does not matter.
        vector(
            "keys.import_pem",
            &format!(r#"{{"pem":{}}}"#, Value::from(RFC8410_10_1_PEM).to_json()),
            r#"{"ok":true,"jwk":{"x":"Gb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE","crv":"Ed25519","kty":"OKP"}}"#,
        ),
        vector(
            "keys.import_pem",
            r#"{"pem":"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"}"#,
            r#"{"ok":false,"error":"UnsupportedAlgorithm"}"#,
        ),
        vector(
            "keys.export_pem",
            r#"{"format":"spki","jwk":{"kty":"OKP","crv":"Ed25519","x":"Gb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE"}}"#,
            &format!(
                r#"{{"ok":true,"pem":{}}}"#,
                Value::from(RFC8410_10_1_PEM).to_json()
            ),
        ),
        vector(
            "keys.export_pem",
            r#"{"format":"pkcs8","jwk":{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}}"#,
            r#"{"ok":false,"error":"UnsupportedAlgorithm"}"#,
        ),
        vector(
            "keys.import_der",
            &format!(r#"{{"format":"spki","der_b64u":"{RFC8410_10_1_DER}"}}"#),
            r#"{"ok":true,"jwk":{"x":"Gb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE","crv":"Ed25519","kty":"OKP"}}"#,
        ),
        // RFC 5958 §2: an SPKI is not a OneAsymmetricKey.
        vector(
            "keys.import_der",
            &format!(r#"{{"format":"pkcs8","der_b64u":"{RFC8410_10_1_DER}"}}"#),
            r#"{"ok":false,"error":"InvalidKey"}"#,
        ),
        vector(
            "keys.export_der",
            r#"{"format":"spki","jwk":{"kty":"OKP","crv":"Ed25519","x":"Gb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE"}}"#,
            &format!(r#"{{"ok":true,"der_b64u":"{RFC8410_10_1_DER}"}}"#),
        ),
        vector(
            "keys.export_der",
            r#"{"format":"spki","jwk":{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}}"#,
            r#"{"ok":false,"error":"UnsupportedAlgorithm"}"#,
        ),
        // RFC 7518 §3.4 and §3.2; generated keys are compared by shape.
        vector(
            "keys.generate_for",
            r#"{"alg":"ES256"}"#,
            r#"{"ok":true,"shape":{"alg":"ES256","crv":"P-256","kty":"EC"}}"#,
        ),
        vector(
            "keys.generate_for",
            r#"{"alg":"HS256"}"#,
            r#"{"ok":true,"shape":{"kty":"oct","alg":"HS256","k_octets":32}}"#,
        ),
        // A JWE `enc` name resolves too (RFC 7518 §7.1, one registry).
        vector(
            "keys.generate_for",
            r#"{"alg":"A128CBC-HS256"}"#,
            r#"{"ok":true,"shape":{"kty":"oct","alg":"A128CBC-HS256","k_octets":32}}"#,
        ),
        vector(
            "keys.generate_for",
            r#"{"alg":"RS256"}"#,
            r#"{"ok":false,"error":"UnsupportedAlgorithm"}"#,
        ),
    ];
    for json in cases {
        assert!(
            check_vector("ok.json", json.as_bytes()).is_ok(),
            "{:?}",
            check_vector("ok.json", json.as_bytes())
        );
    }
}

/// RFC 8410 §10.1, the Ed25519 public key as SPKI.
const RFC8410_10_1_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n-----END PUBLIC KEY-----\n";
/// The DER of [`RFC8410_10_1_PEM`], as canonical base64url.
const RFC8410_10_1_DER: &str = "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE";

/// The keys.* vectors are checked like every other: a wrong expectation,
/// a format outside the enum and a missing member all fail the run.
#[test]
fn keys_vectors_fail_when_wrong_or_malformed() {
    let pem = Value::from(RFC8410_10_1_PEM).to_json();
    let jwk = r#"{"kty":"OKP","crv":"Ed25519","x":"Gb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE"}"#;
    for (name, json, needle) in [
        (
            "import-wrong-jwk.json",
            vector(
                "keys.import_pem",
                &format!(r#"{{"pem":{pem}}}"#),
                r#"{"ok":true,"jwk":{"kty":"OKP","crv":"X25519","x":"Gb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE"}}"#,
            ),
            "`jwk`",
        ),
        (
            "import-wrong-code.json",
            vector(
                "keys.import_pem",
                &format!(r#"{{"pem":{pem}}}"#),
                r#"{"ok":false,"error":"InvalidKey"}"#,
            ),
            "expected error InvalidKey",
        ),
        (
            "export-bad-format.json",
            vector(
                "keys.export_pem",
                &format!(r#"{{"jwk":{jwk},"format":"der"}}"#),
                r#"{"ok":false,"error":"UnsupportedAlgorithm"}"#,
            ),
            "/input/format",
        ),
        (
            "export-no-format.json",
            vector(
                "keys.export_pem",
                &format!(r#"{{"jwk":{jwk}}}"#),
                r#"{"ok":false,"error":"UnsupportedAlgorithm"}"#,
            ),
            "/input/format",
        ),
        (
            "export-wrong-pem.json",
            vector(
                "keys.export_pem",
                &format!(r#"{{"jwk":{jwk},"format":"spki"}}"#),
                r#"{"ok":true,"pem":"-----BEGIN PUBLIC KEY-----\n"}"#,
            ),
            "`pem`",
        ),
        (
            "import-der-wrong-jwk.json",
            vector(
                "keys.import_der",
                &format!(r#"{{"der_b64u":"{RFC8410_10_1_DER}","format":"spki"}}"#),
                r#"{"ok":true,"jwk":{"kty":"OKP","crv":"X25519","x":"Gb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE"}}"#,
            ),
            "`jwk`",
        ),
        (
            "import-der-padded.json",
            vector(
                "keys.import_der",
                &format!(r#"{{"der_b64u":"{RFC8410_10_1_DER}=","format":"spki"}}"#),
                r#"{"ok":false,"error":"InvalidKey"}"#,
            ),
            "/input/der_b64u",
        ),
        (
            // The last character carries non-zero pad bits (RFC 4648 §3.5):
            // the runner cannot decode it, so the vector is broken.
            "import-der-non-canonical.json",
            vector(
                "keys.import_der",
                &format!(
                    r#"{{"der_b64u":"{}F","format":"spki"}}"#,
                    &RFC8410_10_1_DER[..RFC8410_10_1_DER.len() - 1]
                ),
                r#"{"ok":false,"error":"InvalidKey"}"#,
            ),
            "not canonical base64url",
        ),
        (
            "import-der-no-format.json",
            vector(
                "keys.import_der",
                &format!(r#"{{"der_b64u":"{RFC8410_10_1_DER}"}}"#),
                r#"{"ok":false,"error":"InvalidKey"}"#,
            ),
            "/input/format",
        ),
        (
            "import-der-pem-member.json",
            vector(
                "keys.import_der",
                &format!(r#"{{"pem":{pem},"format":"spki"}}"#),
                r#"{"ok":false,"error":"InvalidKey"}"#,
            ),
            "/input/pem",
        ),
        (
            "export-der-wrong-der.json",
            vector(
                "keys.export_der",
                &format!(r#"{{"jwk":{jwk},"format":"spki"}}"#),
                r#"{"ok":true,"der_b64u":"MCowBQYDK2VwAyEA"}"#,
            ),
            "`der_b64u`",
        ),
        (
            "export-der-padded.json",
            vector(
                "keys.export_der",
                &format!(r#"{{"jwk":{jwk},"format":"spki"}}"#),
                &format!(r#"{{"ok":true,"der_b64u":"{RFC8410_10_1_DER}="}}"#),
            ),
            "/expect/der_b64u",
        ),
        (
            "export-der-pem-output.json",
            vector(
                "keys.export_der",
                &format!(r#"{{"jwk":{jwk},"format":"spki"}}"#),
                &format!(r#"{{"ok":true,"pem":{pem}}}"#),
            ),
            "/expect/pem",
        ),
        (
            "export-der-bad-format.json",
            vector(
                "keys.export_der",
                &format!(r#"{{"jwk":{jwk},"format":"pem"}}"#),
                r#"{"ok":false,"error":"UnsupportedAlgorithm"}"#,
            ),
            "/input/format",
        ),
        (
            "import-extra-member.json",
            vector(
                "keys.import_pem",
                &format!(r#"{{"pem":{pem},"format":"spki"}}"#),
                r#"{"ok":false,"error":"InvalidKey"}"#,
            ),
            "/input/format",
        ),
    ] {
        fails_naming_source(name, &json, needle);
    }
}

/// `keys.generate_for` is compared by shape only, but exactly: a wrong or
/// missing shape member, an extra one and a malformed input all fail.
#[test]
fn generate_for_vectors_fail_when_wrong_or_malformed() {
    for (name, input, expect, needle) in [
        (
            "wrong-curve.json",
            r#"{"alg":"ES256"}"#,
            r#"{"ok":true,"shape":{"kty":"EC","crv":"P-384","alg":"ES256"}}"#,
            "`shape`",
        ),
        (
            "no-curve.json",
            r#"{"alg":"ES256"}"#,
            r#"{"ok":true,"shape":{"kty":"EC","alg":"ES256"}}"#,
            "`shape`",
        ),
        (
            "wrong-length.json",
            r#"{"alg":"A256GCM"}"#,
            r#"{"ok":true,"shape":{"kty":"oct","alg":"A256GCM","k_octets":16}}"#,
            "`shape`",
        ),
        (
            "key-material.json",
            r#"{"alg":"HS256"}"#,
            r#"{"ok":true,"shape":{"kty":"oct","alg":"HS256","k_octets":32,"k":"AA"}}"#,
            "/expect/shape/k",
        ),
        (
            "rsa-shape.json",
            r#"{"alg":"RS256"}"#,
            r#"{"ok":true,"shape":{"kty":"RSA","alg":"RS256"}}"#,
            "/expect/shape/kty",
        ),
        (
            "jwk-output.json",
            r#"{"alg":"HS256"}"#,
            r#"{"ok":true,"jwk":{"kty":"oct"}}"#,
            "/expect/jwk",
        ),
        (
            "no-alg.json",
            r#"{"enc":"A128GCM"}"#,
            r#"{"ok":false,"error":"UnsupportedAlgorithm"}"#,
            "/input/enc",
        ),
        (
            "curve-required.json",
            r#"{"alg":"ECDH-ES"}"#,
            r#"{"ok":true,"shape":{"kty":"EC","crv":"P-256","alg":"ECDH-ES"}}"#,
            "expected success, got error InvalidKey",
        ),
    ] {
        let json = vector("keys.generate_for", input, expect);
        fails_naming_source(&format!("generate-{name}"), &json, needle);
    }
}

/// The generator operations (ADR 0030 `jwk_generate_oct`/`_ec`/`_okp`) and
/// `use_with`: each generated key has its RFC shape and survives its use
/// round trip (ADR 0034 §6); the core's length refusal is the outcome.
#[test]
fn generate_vectors_pass() {
    assert_passes(&[
        vector(
            "keys.generate_oct",
            r#"{"len_bytes":32}"#,
            r#"{"ok":true,"shape":{"kty":"oct","k_octets":32},"use_with":{"alg":"HS256"}}"#,
        ),
        vector(
            "keys.generate_oct",
            r#"{"len_bytes":16}"#,
            r#"{"ok":true,"shape":{"kty":"oct","k_octets":16},"use_with":{"alg":"A128KW","enc":"A128GCM"}}"#,
        ),
        vector(
            "keys.generate_oct",
            r#"{"len_bytes":15}"#,
            r#"{"ok":false,"error":"InvalidKey"}"#,
        ),
        vector(
            "keys.generate_ec",
            r#"{"crv":"P-256"}"#,
            r#"{"ok":true,"shape":{"kty":"EC","crv":"P-256"},"use_with":{"alg":"ES256"}}"#,
        ),
        vector(
            "keys.generate_ec",
            r#"{"crv":"P-384"}"#,
            r#"{"ok":true,"shape":{"kty":"EC","crv":"P-384"},"use_with":{"alg":"ECDH-ES+A192KW","enc":"A192GCM"}}"#,
        ),
        vector(
            "keys.generate_okp",
            r#"{"crv":"Ed25519"}"#,
            r#"{"ok":true,"shape":{"kty":"OKP","crv":"Ed25519"},"use_with":{"alg":"EdDSA"}}"#,
        ),
        vector(
            "keys.generate_okp",
            r#"{"crv":"X25519"}"#,
            r#"{"ok":true,"shape":{"kty":"OKP","crv":"X25519"},"use_with":{"alg":"ECDH-ES","enc":"A128GCM"}}"#,
        ),
        vector(
            "keys.generate_for",
            r#"{"alg":"ES256"}"#,
            r#"{"ok":true,"shape":{"kty":"EC","crv":"P-256","alg":"ES256"},"use_with":{"alg":"ES256"}}"#,
        ),
        vector(
            "keys.generate_for",
            r#"{"alg":"A256GCM"}"#,
            r#"{"ok":true,"shape":{"kty":"oct","alg":"A256GCM","k_octets":32},"use_with":{"alg":"dir","enc":"A256GCM"}}"#,
        ),
    ]);
}

/// Generator vectors that are schema-invalid, or whose shape or use round
/// trip doesn't hold, fail naming their source.
#[test]
fn generate_vectors_fail_when_wrong_or_malformed() {
    let p256 = r#"{"crv":"P-256"}"#;
    for (name, operation, input, expect, needle) in [
        (
            "no-use-with.json",
            "keys.generate_ec",
            p256,
            r#"{"ok":true,"shape":{"kty":"EC","crv":"P-256"}}"#,
            "/expect/use_with",
        ),
        (
            "alg-in-shape.json",
            "keys.generate_ec",
            p256,
            r#"{"ok":true,"shape":{"kty":"EC","crv":"P-256","alg":"ES256"},"use_with":{"alg":"ES256"}}"#,
            "/expect/shape/alg",
        ),
        (
            "unknown-curve.json",
            "keys.generate_ec",
            r#"{"crv":"P-192"}"#,
            r#"{"ok":true,"shape":{"kty":"EC","crv":"P-192"},"use_with":{"alg":"ES256"}}"#,
            "/input/crv",
        ),
        (
            "okp-curve-on-ec.json",
            "keys.generate_ec",
            r#"{"crv":"Ed25519"}"#,
            r#"{"ok":true,"shape":{"kty":"OKP","crv":"Ed25519"},"use_with":{"alg":"EdDSA"}}"#,
            "/input/crv",
        ),
        (
            "ec-cannot-fail.json",
            "keys.generate_ec",
            p256,
            r#"{"ok":false,"error":"InvalidKey"}"#,
            "cannot fail",
        ),
        (
            "use-with-member.json",
            "keys.generate_ec",
            p256,
            r#"{"ok":true,"shape":{"kty":"EC","crv":"P-256"},"use_with":{"alg":"ES256","kid":"1"}}"#,
            "/expect/use_with/kid",
        ),
        (
            "use-with-wrong-alg.json",
            "keys.generate_ec",
            p256,
            r#"{"ok":true,"shape":{"kty":"EC","crv":"P-256"},"use_with":{"alg":"ES384"}}"#,
            "use_with: the key does not sign",
        ),
        (
            "use-with-wrong-family.json",
            "keys.generate_okp",
            r#"{"crv":"X25519"}"#,
            r#"{"ok":true,"shape":{"kty":"OKP","crv":"X25519"},"use_with":{"alg":"EdDSA"}}"#,
            "use_with",
        ),
        (
            "wrong-length.json",
            "keys.generate_oct",
            r#"{"len_bytes":32}"#,
            r#"{"ok":true,"shape":{"kty":"oct","k_octets":16},"use_with":{"alg":"HS256"}}"#,
            "`shape`",
        ),
        (
            "length-not-a-count.json",
            "keys.generate_oct",
            r#"{"len_bytes":-1}"#,
            r#"{"ok":false,"error":"InvalidKey"}"#,
            "/input/len_bytes",
        ),
        (
            "for-use-with-wrong.json",
            "keys.generate_for",
            r#"{"alg":"HS256"}"#,
            r#"{"ok":true,"shape":{"kty":"oct","alg":"HS256","k_octets":32},"use_with":{"alg":"HS512"}}"#,
            "use_with",
        ),
    ] {
        fails_naming_source(
            &format!("generate-{name}"),
            &vector(operation, input, expect),
            needle,
        );
    }
}

/// The checks a shape cannot express catch a public key, a member RFC 7518
/// §6 does not define for a generated key (here `kid`) and a missing `alg`;
/// a well-formed private key yields its shape.
#[test]
fn generated_shape_checks_what_a_shape_cannot_say() {
    let jwk = |json: &str| Jwk::from_json(json.as_bytes()).unwrap();
    let public = jwk(A3_PUBLIC);
    assert!(generated_shape(&public).unwrap_err().contains("public key"));
    let with_kid = jwk(r#"{"kty":"oct","alg":"A128KW","kid":"1","k":"GawgguFyGrWKav7AX4VKUg"}"#);
    assert!(generated_shape(&with_kid).unwrap_err().contains("members"));
    let no_alg = jwk(A3_PRIVATE);
    assert!(generated_shape(&no_alg).unwrap_err().contains("members"));
    let bound = jwk(&A3_PRIVATE.replace(r#""kty":"EC""#, r#""kty":"EC","alg":"ES256""#));
    assert_eq!(
        Value::from(generated_shape(&bound).unwrap()),
        parse(r#"{"kty":"EC","crv":"P-256","alg":"ES256"}"#)
    );
    let oct = jwk(r#"{"kty":"oct","alg":"A128KW","k":"GawgguFyGrWKav7AX4VKUg"}"#);
    assert_eq!(
        Value::from(generated_shape(&oct).unwrap()),
        parse(r#"{"kty":"oct","alg":"A128KW","k_octets":16}"#)
    );
}

/// Criterion 1: an operation the schema does not know fails the run.
#[test]
fn unknown_operation_fails() {
    let json = vector("b64url.frobnicate", r#"{"b64u":""}"#, r#"{"ok":true}"#);
    fails_naming_source("unknown-op.json", &json, "unknown operation");
}

/// Criterion 1: an operation the schema reserves but this runner does not
/// implement fails the run too; it is never skipped.
#[test]
fn reserved_but_unimplemented_operations_fail() {
    // jwe.* were reserved until 0003 T09 implemented them, jwt.validate
    // until 0004 T10. With nothing reserved now, `validate` lets no such
    // vector through, so the runner's fallback is driven directly.
    let reserved = Vector {
        operation: "jwt.reserved".to_owned(),
        input: Object::new(),
        expect: Expect::Ok(Object::new()),
        features: Vec::new(),
        features_absent: Vec::new(),
    };
    let problem = execute(&reserved).unwrap_err();
    assert!(problem.contains("not implemented"), "{problem}");
    assert!(problem.contains("never skipped"), "{problem}");
}

/// Criterion 2: every way of breaking the schema fails the run, and the
/// message names the source whenever the vector has a usable one.
#[test]
fn schema_invalid_vectors_fail() {
    let encode_ok = r#"{"ok":true,"b64u":"Zm9v"}"#;
    let cases: &[(&str, String, &str)] = &[
        (
            "extra top-level member",
            vector("b64url.encode", r#"{"bytes_hex":"666f6f"}"#, encode_ok)
                .replace(r#""operation""#, r#""comment":"x","operation""#),
            "/comment: unknown member",
        ),
        (
            "blank description",
            vector("b64url.encode", r#"{"bytes_hex":"666f6f"}"#, encode_ok)
                .replace(r#""self-test""#, r#"" \t""#),
            "/description",
        ),
        (
            "description not a string",
            vector("b64url.encode", r#"{"bytes_hex":"666f6f"}"#, encode_ok)
                .replace(r#""self-test""#, "7"),
            "/description",
        ),
        (
            "missing input",
            vector("b64url.encode", r#"{"bytes_hex":"666f6f"}"#, encode_ok)
                .replace(r#""input":{"bytes_hex":"666f6f"},"#, ""),
            "/input: required member is missing",
        ),
        (
            "input not an object",
            vector("b64url.encode", r#""666f6f""#, encode_ok),
            "/input",
        ),
        (
            "unknown input member",
            vector(
                "b64url.encode",
                r#"{"bytes_hex":"666f6f","bytes":"foo"}"#,
                encode_ok,
            ),
            "/input/bytes: unknown member",
        ),
        (
            "missing input member",
            vector("b64url.encode", "{}", encode_ok),
            "/input/bytes_hex: required member is missing",
        ),
        (
            "uppercase hex",
            vector("b64url.encode", r#"{"bytes_hex":"666F6F"}"#, encode_ok),
            "/input/bytes_hex",
        ),
        (
            "odd-length hex",
            vector("b64url.encode", r#"{"bytes_hex":"666f6"}"#, encode_ok),
            "/input/bytes_hex",
        ),
        (
            "non-hex digit",
            vector("b64url.encode", r#"{"bytes_hex":"66zz"}"#, encode_ok),
            "/input/bytes_hex",
        ),
        (
            "base64url output with padding",
            vector(
                "b64url.encode",
                r#"{"bytes_hex":"66"}"#,
                r#"{"ok":true,"b64u":"Zg=="}"#,
            ),
            "/expect/b64u",
        ),
        (
            "missing ok",
            vector("b64url.encode", r#"{"bytes_hex":"66"}"#, r#"{"b64u":"Zg"}"#),
            "/expect/ok: required member is missing",
        ),
        (
            "ok not a boolean",
            vector(
                "b64url.encode",
                r#"{"bytes_hex":"66"}"#,
                r#"{"ok":"true","b64u":"Zg"}"#,
            ),
            "/expect/ok",
        ),
        (
            "encode cannot expect a failure",
            vector(
                "b64url.encode",
                r#"{"bytes_hex":"66"}"#,
                r#"{"ok":false,"error":"InvalidBase64"}"#,
            ),
            "cannot fail",
        ),
        (
            "success with an error member",
            vector(
                "b64url.decode",
                r#"{"b64u":"Zg"}"#,
                r#"{"ok":true,"bytes_hex":"66","error":"InvalidBase64"}"#,
            ),
            "/expect/error: unknown member",
        ),
        (
            "failure with an output member",
            vector(
                "b64url.decode",
                r#"{"b64u":"Zg"}"#,
                r#"{"ok":false,"error":"InvalidBase64","bytes_hex":"66"}"#,
            ),
            "/expect/bytes_hex: unknown member",
        ),
        (
            "failure without an error code",
            vector("b64url.decode", r#"{"b64u":"Zg=="}"#, r#"{"ok":false}"#),
            "/expect/error: required member is missing",
        ),
        (
            "unknown error code",
            vector(
                "b64url.decode",
                r#"{"b64u":"Zg=="}"#,
                r#"{"ok":false,"error":"BadBase64"}"#,
            ),
            "/expect/error",
        ),
        (
            "decode input not a string",
            vector(
                "b64url.decode",
                r#"{"b64u":["Zg"]}"#,
                r#"{"ok":true,"bytes_hex":"66"}"#,
            ),
            "/input/b64u",
        ),
        (
            "unsupported thumbprint hash",
            vector(
                "jwk.thumbprint",
                r#"{"hash":"sha-1","jwk":{"kty":"oct","k":"AA"}}"#,
                r#"{"ok":false,"error":"InvalidKey"}"#,
            ),
            "/input/hash",
        ),
        (
            "jwk not an object",
            vector(
                "jwk.thumbprint",
                r#"{"hash":"sha-256","jwk":"{\"kty\":\"oct\"}"}"#,
                r#"{"ok":false,"error":"InvalidKey"}"#,
            ),
            "/input/jwk",
        ),
        (
            "thumbprint success missing the URI",
            vector(
                "jwk.thumbprint",
                r#"{"hash":"sha-256","jwk":{"kty":"oct","k":"AA"}}"#,
                r#"{"ok":true,"thumbprint":"AA"}"#,
            ),
            "/expect/thumbprint_uri: required member is missing",
        ),
        (
            "operation not a string",
            vector("b64url.encode", r#"{"bytes_hex":"66"}"#, encode_ok)
                .replace(r#""b64url.encode""#, r#"["b64url.encode"]"#),
            "/operation",
        ),
    ];
    for (what, json, needle) in cases {
        let name = format!("invalid ({what}).json");
        fails_naming_source(&name, json, needle);
    }
}

/// A vector without a usable `source` is schema-invalid; the message still
/// names the file and says the source is missing.
#[test]
fn vectors_without_a_source_fail() {
    let valid = vector(
        "b64url.encode",
        r#"{"bytes_hex":"66"}"#,
        r#"{"ok":true,"b64u":"Zg"}"#,
    );
    let source_member = format!(r#""source":"{SOURCE}","#);
    let cases = [
        valid.replace(&source_member, ""),
        valid.replace(&source_member, r#""source":"","#),
        valid.replace(&source_member, r#""source":"   ","#),
        valid.replace(&source_member, r#""source":null,"#),
    ];
    for json in cases {
        let msg = check_vector("no-source.json", json.as_bytes()).unwrap_err();
        assert!(msg.contains("no-source.json"), "{msg}");
        assert!(msg.contains("/source"), "{msg}");
    }
}

/// Files that are not one JSON object fail, naming the file.
#[test]
fn unparseable_files_fail() {
    let duplicate = vector(
        "b64url.encode",
        r#"{"bytes_hex":"66"}"#,
        r#"{"ok":true,"b64u":"Zg"}"#,
    )
    .replace(r#""input""#, r#""source":"again","input""#);
    for json in ["", "[]", "{", "\"vector\"", duplicate.as_str()] {
        let msg = check_vector("broken.json", json.as_bytes()).unwrap_err();
        assert!(msg.contains("broken.json"), "{msg}");
    }
}

/// Criterion 3: a vector whose expectation the library does not meet fails,
/// and the message names the file and the source.
#[test]
fn failing_vectors_fail_naming_their_source() {
    let cases = [
        (
            "wrong encoding",
            vector(
                "b64url.encode",
                r#"{"bytes_hex":"666f6f"}"#,
                r#"{"ok":true,"b64u":"Zm9w"}"#,
            ),
            "Zm9w",
        ),
        (
            "wrong decoded bytes",
            vector(
                "b64url.decode",
                r#"{"b64u":"Zm9v"}"#,
                r#"{"ok":true,"bytes_hex":"666f70"}"#,
            ),
            "666f70",
        ),
        (
            "expected success, got an error",
            vector(
                "b64url.decode",
                r#"{"b64u":"Zg=="}"#,
                r#"{"ok":true,"bytes_hex":"66"}"#,
            ),
            "InvalidBase64",
        ),
        (
            "expected an error, got success",
            vector(
                "b64url.decode",
                r#"{"b64u":"Zg"}"#,
                r#"{"ok":false,"error":"InvalidBase64"}"#,
            ),
            "succeeded",
        ),
        (
            "wrong error code",
            vector(
                "b64url.decode",
                r#"{"b64u":"Zg=="}"#,
                r#"{"ok":false,"error":"InvalidKey"}"#,
            ),
            "InvalidKey",
        ),
        (
            "wrong thumbprint URI",
            vector(
                "jwk.thumbprint",
                r#"{"hash":"sha-256","jwk":{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}}"#,
                r#"{"ok":true,"thumbprint":"kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k","thumbprint_uri":"urn:ietf:params:oauth:jwk-thumbprint:sha-512:kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"}"#,
            ),
            "thumbprint_uri",
        ),
    ];
    for (what, json, needle) in cases {
        let name = format!("failing ({what}).json");
        fails_naming_source(&name, &json, needle);
    }
}

// ---------------------------------------------------------------------------
// jws.* self-tests, on RFC 7515 Appendix A values (the vector files under
// conformance/vectors/jws-rfc7515/ cite them).
// ---------------------------------------------------------------------------

/// RFC 7515 A.1 HMAC key.
const A1_KEY: &str = r#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#;
/// RFC 7515 A.1 protected header `{"typ":"JWT",\r\n "alg":"HS256"}`.
const A1_PROTECTED: &str = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9";
/// RFC 7515 A.1 payload (also A.2, A.3, A.5, A.6, A.7).
const PAYLOAD: &str = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
/// RFC 7515 A.1 HS256 signature.
const A1_SIGNATURE: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
/// RFC 7515 A.3 P-256 key, public and private.
const A3_PUBLIC: &str = r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#;
/// RFC 7515 A.3 protected header `{"alg":"ES256"}` and signature.
const A3_PROTECTED: &str = "eyJhbGciOiJFUzI1NiJ9";
const A3_SIGNATURE: &str =
    "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";
/// RFC 7515 A.5 unsecured JWS.
const A5_JWS: &str = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.";
/// An RSA private JWK, which JWK import refuses (ADR 0021).
const RSA_PRIVATE: &str = r#"{"kty":"RSA","n":"AQAB","e":"AQAB","d":"AQAB"}"#;

fn a1_compact() -> String {
    format!("{A1_PROTECTED}.{PAYLOAD}.{A1_SIGNATURE}")
}

/// RFC 7515 A.7, the flattened JSON Serialization.
fn a7_flattened() -> String {
    format!(
        r#"{{"payload":"{PAYLOAD}","protected":"{A3_PROTECTED}","header":{{"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"}},"signature":"{A3_SIGNATURE}"}}"#
    )
}

/// A general JSON JWS whose signatures are A.1's (HS256) and A.3's (ES256).
fn general_hs256_es256() -> String {
    format!(
        r#"{{"payload":"{PAYLOAD}","signatures":[{{"protected":"{A1_PROTECTED}","signature":"{A1_SIGNATURE}"}},{{"protected":"{A3_PROTECTED}","signature":"{A3_SIGNATURE}"}}]}}"#
    )
}

fn verify_input(jws: &str, key: &str, algs: &str, extra: &str) -> String {
    format!(r#"{{"jws":{jws},"key":{key},"allowed_algs":{algs}{extra}}}"#)
}

fn verified(alg: &str, index: u32) -> String {
    format!(r#"{{"ok":true,"payload_b64u":"{PAYLOAD}","alg":"{alg}","signature_index":{index}}}"#)
}

fn quoted(s: &str) -> String {
    format!("\"{s}\"")
}

fn assert_passes(cases: &[String]) {
    for json in cases {
        let result = check_vector("ok.json", json.as_bytes());
        assert!(result.is_ok(), "{result:?}\n  for {json}");
    }
}

/// Every `jws.verify` input form runs: compact, flattened and general,
/// detached, limits, and errors from JWK import and the allow-list.
#[test]
fn jws_verify_vectors_pass() {
    let a1 = quoted(&a1_compact());
    let detached = quoted(&format!("{A1_PROTECTED}..{A1_SIGNATURE}"));
    let fails = |code: &str| format!(r#"{{"ok":false,"error":"{code}"}}"#);
    assert_passes(&[
        vector(
            "jws.verify",
            &verify_input(&a1, A1_KEY, r#"["HS256"]"#, ""),
            &verified("HS256", 0),
        ),
        vector(
            "jws.verify",
            &verify_input(&a7_flattened(), A3_PUBLIC, r#"["ES256"]"#, ""),
            &verified("ES256", 0),
        ),
        // The first signature that verifies with the key wins (ADR 0026 §3).
        vector(
            "jws.verify",
            &verify_input(
                &general_hs256_es256(),
                A3_PUBLIC,
                r#"["HS256","ES256"]"#,
                "",
            ),
            &verified("ES256", 1),
        ),
        vector(
            "jws.verify",
            &verify_input(
                &detached,
                A1_KEY,
                r#"["HS256"]"#,
                &format!(r#","detached_payload_b64u":"{PAYLOAD}""#),
            ),
            &verified("HS256", 0),
        ),
        vector(
            "jws.verify",
            &verify_input(&quoted(A5_JWS), A1_KEY, r#"["HS256"]"#, ""),
            &fails("AlgorithmNotAllowed"),
        ),
        // The allow-list is refused before anything is verified.
        vector(
            "jws.verify",
            &verify_input(&a1, A1_KEY, "[]", ""),
            &fails("AlgorithmNotAllowed"),
        ),
        vector(
            "jws.verify",
            &verify_input(&a1, A1_KEY, r#"["none"]"#, ""),
            &fails("AlgorithmNotAllowed"),
        ),
        // A JWK import error is the vector's outcome.
        vector(
            "jws.verify",
            &verify_input(&a1, RSA_PRIVATE, r#"["RS256"]"#, ""),
            &fails("UnsupportedAlgorithm"),
        ),
        vector(
            "jws.verify",
            &verify_input(&a1, A1_KEY, r#"["HS256"]"#, r#","max_input_len":10"#),
            &fails("InvalidFormat"),
        ),
        vector(
            "jws.verify",
            &verify_input(
                &general_hs256_es256(),
                A3_PUBLIC,
                r#"["HS256","ES256"]"#,
                r#","max_signatures":1"#,
            ),
            &fails("InvalidFormat"),
        ),
        vector(
            "jws.verify",
            &verify_input(
                &general_hs256_es256(),
                A3_PUBLIC,
                r#"["HS256","ES256"]"#,
                r#","max_signatures":2,"max_input_len":4294967295"#,
            ),
            &verified("ES256", 1),
        ),
    ]);
}

/// A `jws.verify` vector that breaks the schema fails the run.
#[test]
fn jws_verify_schema_violations_fail() {
    let a1 = quoted(&a1_compact());
    let input = |extra: &str| verify_input(&a1, A1_KEY, r#"["HS256"]"#, extra);
    let ok = verified("HS256", 0);
    let cases: Vec<(&str, String, &str)> = vec![
        (
            "misspelled member",
            vector(
                "jws.verify",
                &format!(r#"{{"jws":{a1},"key":{A1_KEY},"allowed_alg":["HS256"]}}"#),
                &ok,
            ),
            "/input/allowed_alg: unknown member",
        ),
        (
            "missing allowed_algs",
            vector(
                "jws.verify",
                &format!(r#"{{"jws":{a1},"key":{A1_KEY}}}"#),
                &ok,
            ),
            "/input/allowed_algs: required member is missing",
        ),
        (
            "jws a number",
            vector(
                "jws.verify",
                &verify_input("7", A1_KEY, r#"["HS256"]"#, ""),
                &ok,
            ),
            "/input/jws",
        ),
        (
            "jws an array",
            vector(
                "jws.verify",
                &verify_input(&format!("[{a1}]"), A1_KEY, r#"["HS256"]"#, ""),
                &ok,
            ),
            "/input/jws",
        ),
        (
            "key a string",
            vector(
                "jws.verify",
                &verify_input(&a1, &quoted("k"), r#"["HS256"]"#, ""),
                &ok,
            ),
            "/input/key",
        ),
        (
            "allowed_algs a string",
            vector(
                "jws.verify",
                &verify_input(&a1, A1_KEY, r#""HS256""#, ""),
                &ok,
            ),
            "/input/allowed_algs",
        ),
        (
            "allowed_algs with a number",
            vector(
                "jws.verify",
                &verify_input(&a1, A1_KEY, r#"["HS256",256]"#, ""),
                &ok,
            ),
            "/input/allowed_algs",
        ),
        (
            "negative max_signatures",
            vector("jws.verify", &input(r#","max_signatures":-1"#), &ok),
            "/input/max_signatures",
        ),
        (
            "fractional max_signatures",
            vector("jws.verify", &input(r#","max_signatures":1.5"#), &ok),
            "/input/max_signatures",
        ),
        (
            "max_input_len above u32",
            vector("jws.verify", &input(r#","max_input_len":4294967296"#), &ok),
            "/input/max_input_len",
        ),
        (
            "max_input_len a string",
            vector("jws.verify", &input(r#","max_input_len":"10""#), &ok),
            "/input/max_input_len",
        ),
        (
            "padded detached payload",
            vector(
                "jws.verify",
                &input(r#","detached_payload_b64u":"Zg==""#),
                &ok,
            ),
            "/input/detached_payload_b64u",
        ),
        (
            "success without signature_index",
            vector(
                "jws.verify",
                &input(""),
                &format!(r#"{{"ok":true,"payload_b64u":"{PAYLOAD}","alg":"HS256"}}"#),
            ),
            "/expect/signature_index: required member is missing",
        ),
        (
            "signature_index a string",
            vector(
                "jws.verify",
                &input(""),
                &ok.replace(r#""signature_index":0"#, r#""signature_index":"0""#),
            ),
            "/expect/signature_index",
        ),
        (
            "success with a sign output",
            vector(
                "jws.verify",
                &input(""),
                &ok.replace(r#""ok":true"#, &format!(r#""ok":true,"jws":{a1}"#)),
            ),
            "/expect/jws: unknown member",
        ),
        (
            "failure with an output member",
            vector(
                "jws.verify",
                &input(""),
                r#"{"ok":false,"error":"InvalidSignature","alg":"HS256"}"#,
            ),
            "/expect/alg: unknown member",
        ),
    ];
    for (what, json, needle) in cases {
        fails_naming_source(&format!("invalid ({what}).json"), &json, needle);
    }
}

/// A `jws.verify` vector the library does not meet fails, naming the file
/// and the source.
#[test]
fn jws_verify_mismatches_fail() {
    let a1 = quoted(&a1_compact());
    let input = verify_input(&a1, A1_KEY, r#"["HS256"]"#, "");
    let cases = [
        (
            "wrong signature_index",
            vector("jws.verify", &input, &verified("HS256", 1)),
            "signature_index",
        ),
        (
            "wrong alg",
            vector("jws.verify", &input, &verified("HS384", 0)),
            "HS384",
        ),
        (
            "wrong payload",
            vector(
                "jws.verify",
                &input,
                &verified("HS256", 0).replace(PAYLOAD, "UGF5bG9hZA"),
            ),
            "payload_b64u",
        ),
        (
            "tampered signature",
            vector(
                "jws.verify",
                &input.replace(A1_SIGNATURE, &A1_SIGNATURE.replace('d', "e")),
                &verified("HS256", 0),
            ),
            "InvalidSignature",
        ),
        (
            "expected an error, got success",
            vector(
                "jws.verify",
                &input,
                r#"{"ok":false,"error":"InvalidSignature"}"#,
            ),
            "succeeded",
        ),
        // The runner decodes bytes it passes to the library; a value that
        // does not decode is the vector's fault, never an outcome.
        (
            "detached payload that does not decode",
            vector(
                "jws.verify",
                &verify_input(
                    &quoted(&format!("{A1_PROTECTED}..{A1_SIGNATURE}")),
                    A1_KEY,
                    r#"["HS256"]"#,
                    r#","detached_payload_b64u":"Zh""#,
                ),
                r#"{"ok":false,"error":"InvalidBase64"}"#,
            ),
            "detached_payload_b64u",
        ),
    ];
    for (what, json, needle) in cases {
        fails_naming_source(&format!("failing ({what}).json"), &json, needle);
    }
}

/// RFC 7515 A.3 P-256 private key.
const A3_PRIVATE: &str = r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"}"#;
/// Another P-256 public key (RFC 7517 A.1), which verifies nothing A.3 signs.
const OTHER_P256: &str = r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}"#;

fn sign_input(serialization: &str, detached: bool, signers: &[String]) -> String {
    format!(
        r#"{{"serialization":"{serialization}","payload_b64u":"{PAYLOAD}","detached":{detached},"signers":[{}]}}"#,
        signers.join(",")
    )
}

fn signer(protected: Option<&str>, header: Option<&str>, key: &str) -> String {
    let mut members = Vec::new();
    if let Some(protected) = protected {
        members.push(format!(r#""protected_b64u":"{protected}""#));
    }
    if let Some(header) = header {
        members.push(format!(r#""header":{header}"#));
    }
    members.push(format!(r#""key":{key}"#));
    format!("{{{}}}", members.join(","))
}

fn signed(jws: &str) -> String {
    format!(r#"{{"ok":true,"jws":{jws}}}"#)
}

fn round_trip(key: &str, algs: &str) -> String {
    format!(r#"{{"ok":true,"verify_with":{{"key":{key},"allowed_algs":{algs}}}}}"#)
}

/// Every `jws.sign` form runs: exact and round-trip expectations, all three
/// serializations, several signers, unprotected headers, detached output,
/// and errors from JWK import and header parsing.
#[test]
fn jws_sign_vectors_pass() {
    let hs256 = signer(Some(A1_PROTECTED), None, A1_KEY);
    let es256 = signer(Some(A3_PROTECTED), None, A3_PRIVATE);
    let fails = |code: &str| format!(r#"{{"ok":false,"error":"{code}"}}"#);
    assert_passes(&[
        vector(
            "jws.sign",
            &sign_input("compact", false, std::slice::from_ref(&hs256)),
            &signed(&quoted(&a1_compact())),
        ),
        // Appendix F: the payload part is empty.
        vector(
            "jws.sign",
            &sign_input("compact", true, std::slice::from_ref(&hs256)),
            &signed(&quoted(&format!("{A1_PROTECTED}..{A1_SIGNATURE}"))),
        ),
        // JSON output is compared as JSON: member order does not matter.
        vector(
            "jws.sign",
            &sign_input("flattened", false, std::slice::from_ref(&hs256)),
            &signed(&format!(
                r#"{{"signature":"{A1_SIGNATURE}","protected":"{A1_PROTECTED}","payload":"{PAYLOAD}"}}"#
            )),
        ),
        // Two signers; the unprotected header is not signed, so both MACs
        // are A.1's.
        vector(
            "jws.sign",
            &sign_input(
                "general",
                false,
                &[
                    hs256.clone(),
                    signer(Some(A1_PROTECTED), Some(r#"{"kid":"k2"}"#), A1_KEY),
                ],
            ),
            &signed(&format!(
                r#"{{"payload":"{PAYLOAD}","signatures":[{{"protected":"{A1_PROTECTED}","signature":"{A1_SIGNATURE}"}},{{"protected":"{A1_PROTECTED}","header":{{"kid":"k2"}},"signature":"{A1_SIGNATURE}"}}]}}"#
            )),
        ),
        vector(
            "jws.sign",
            &sign_input("compact", false, std::slice::from_ref(&es256)),
            &round_trip(A3_PUBLIC, r#"["ES256"]"#),
        ),
        vector(
            "jws.sign",
            &sign_input("flattened", true, std::slice::from_ref(&es256)),
            &round_trip(A3_PUBLIC, r#"["ES256"]"#),
        ),
        // A multi-signer round trip verifies the signature the key fits.
        vector(
            "jws.sign",
            &sign_input("general", false, &[hs256.clone(), es256.clone()]),
            &round_trip(A3_PUBLIC, r#"["ES256"]"#),
        ),
        // No protected header (RFC 7515 §7.2.1; RFC 7520 §4.7).
        vector(
            "jws.sign",
            &sign_input(
                "flattened",
                false,
                &[signer(None, Some(r#"{"alg":"HS256"}"#), A1_KEY)],
            ),
            &round_trip(A1_KEY, r#"["HS256"]"#),
        ),
        // A JWK import error is the vector's outcome (ADR 0021).
        vector(
            "jws.sign",
            &sign_input(
                "compact",
                false,
                &[signer(Some(A1_PROTECTED), None, RSA_PRIVATE)],
            ),
            &fails("UnsupportedAlgorithm"),
        ),
        // So are header errors: "foo" is not a JSON object, and kid must be
        // a string (RFC 7515 §4.1.4).
        vector(
            "jws.sign",
            &sign_input("compact", false, &[signer(Some("Zm9v"), None, A1_KEY)]),
            &fails("InvalidJson"),
        ),
        vector(
            "jws.sign",
            &sign_input(
                "flattened",
                false,
                &[signer(Some(A1_PROTECTED), Some(r#"{"kid":5}"#), A1_KEY)],
            ),
            &fails("InvalidHeader"),
        ),
        // Without a protected header, alg is missing.
        vector(
            "jws.sign",
            &sign_input("general", false, &[signer(None, None, A1_KEY)]),
            &fails("InvalidHeader"),
        ),
    ]);
}

/// A `jws.sign` vector that breaks the schema, including its
/// per-serialization rules, fails the run.
#[test]
fn jws_sign_schema_violations_fail() {
    let hs256 = signer(Some(A1_PROTECTED), None, A1_KEY);
    let one = |serialization: &str| sign_input(serialization, false, std::slice::from_ref(&hs256));
    let ok = signed(&quoted(&a1_compact()));
    let cases: Vec<(&str, String, &str)> = vec![
        (
            "compact with two signers",
            vector(
                "jws.sign",
                &sign_input("compact", false, &[hs256.clone(), hs256.clone()]),
                &ok,
            ),
            "/input/signers: a compact JWS has at most 1 signer",
        ),
        (
            "flattened with two signers",
            vector(
                "jws.sign",
                &sign_input("flattened", false, &[hs256.clone(), hs256.clone()]),
                &ok,
            ),
            "/input/signers: a flattened JWS has at most 1 signer",
        ),
        (
            "compact with only a key",
            vector(
                "jws.sign",
                &sign_input("compact", false, &[signer(None, None, A1_KEY)]),
                &ok,
            ),
            "/input/signers/0/protected_b64u: required for a compact JWS",
        ),
        (
            "compact with an unprotected header",
            vector(
                "jws.sign",
                &sign_input(
                    "compact",
                    false,
                    &[signer(Some(A1_PROTECTED), Some("{}"), A1_KEY)],
                ),
                &ok,
            ),
            "/input/signers/0/header: not allowed in a compact JWS",
        ),
        (
            "no signers",
            vector("jws.sign", &sign_input("general", false, &[]), &ok),
            "/input/signers",
        ),
        (
            "signers not an array",
            vector(
                "jws.sign",
                &one("general").replace(&format!("[{hs256}]"), &hs256),
                &ok,
            ),
            "/input/signers",
        ),
        (
            "signer not an object",
            vector(
                "jws.sign",
                &sign_input("general", false, &[quoted(A1_PROTECTED)]),
                &ok,
            ),
            "/input/signers/0",
        ),
        (
            "misspelled signer member",
            vector(
                "jws.sign",
                &one("compact").replace("protected_b64u", "protected"),
                &ok,
            ),
            "/input/signers/0/protected: unknown member",
        ),
        (
            "signer without a key",
            vector(
                "jws.sign",
                &one("compact").replace(&format!(r#","key":{A1_KEY}"#), ""),
                &ok,
            ),
            "/input/signers/0/key: required member is missing",
        ),
        (
            "padded protected header",
            vector(
                "jws.sign",
                &one("compact").replace(A1_PROTECTED, "eyJhbGciOiJIUzI1NiJ9=="),
                &ok,
            ),
            "/input/signers/0/protected_b64u",
        ),
        (
            "unknown serialization",
            vector("jws.sign", &one("json"), &ok),
            "/input/serialization",
        ),
        (
            "detached a string",
            vector(
                "jws.sign",
                &one("compact").replace(r#""detached":false"#, r#""detached":"false""#),
                &ok,
            ),
            "/input/detached",
        ),
        (
            "detached missing",
            vector(
                "jws.sign",
                &one("compact").replace(r#""detached":false,"#, ""),
                &ok,
            ),
            "/input/detached: required member is missing",
        ),
        (
            "misspelled input member",
            vector(
                "jws.sign",
                &one("compact").replace("payload_b64u", "payload"),
                &ok,
            ),
            "/input/payload: unknown member",
        ),
        (
            "both success forms",
            vector(
                "jws.sign",
                &one("compact"),
                &round_trip(A1_KEY, r#"["HS256"]"#).replace(
                    r#""ok":true"#,
                    &format!(r#""ok":true,"jws":"{}""#, a1_compact()),
                ),
            ),
            "matches none of the success forms",
        ),
        (
            "neither success form",
            vector("jws.sign", &one("compact"), r#"{"ok":true}"#),
            "matches none of the success forms",
        ),
        (
            "misspelled verify_with member",
            vector(
                "jws.sign",
                &one("compact"),
                &round_trip(A1_KEY, r#"["HS256"]"#).replace("allowed_algs", "allowed_alg"),
            ),
            "/expect/verify_with/allowed_alg: unknown member",
        ),
        (
            "verify_with without allowed_algs",
            vector(
                "jws.sign",
                &one("compact"),
                &format!(r#"{{"ok":true,"verify_with":{{"key":{A1_KEY}}}}}"#),
            ),
            "/expect/verify_with/allowed_algs: required member is missing",
        ),
        (
            "jws a number",
            vector("jws.sign", &one("compact"), &signed("7")),
            "/expect/jws",
        ),
        (
            "failure with an output",
            vector(
                "jws.sign",
                &one("compact"),
                &format!(
                    r#"{{"ok":false,"error":"InvalidKey","jws":"{}"}}"#,
                    a1_compact()
                ),
            ),
            "/expect/jws: unknown member",
        ),
    ];
    for (what, json, needle) in cases {
        fails_naming_source(&format!("invalid ({what}).json"), &json, needle);
    }
}

/// A `jws.sign` vector the library does not meet fails, naming the file and
/// the source; so does a round trip whose verification fails.
#[test]
fn jws_sign_mismatches_fail() {
    let hs256 = sign_input(
        "compact",
        false,
        &[signer(Some(A1_PROTECTED), None, A1_KEY)],
    );
    let es256 = sign_input(
        "compact",
        false,
        &[signer(Some(A3_PROTECTED), None, A3_PRIVATE)],
    );
    let cases = [
        (
            "wrong signature",
            vector(
                "jws.sign",
                &hs256,
                &signed(&quoted(&a1_compact().replace('d', "e"))),
            ),
            "`jws`",
        ),
        (
            "flattened output expected for compact",
            vector(
                "jws.sign",
                &hs256,
                &signed(&format!(
                    r#"{{"payload":"{PAYLOAD}","protected":"{A1_PROTECTED}","signature":"{A1_SIGNATURE}"}}"#
                )),
            ),
            "`jws`",
        ),
        (
            "round trip with another key",
            vector("jws.sign", &es256, &round_trip(OTHER_P256, r#"["ES256"]"#)),
            "round trip",
        ),
        (
            "round trip with another algorithm",
            vector("jws.sign", &es256, &round_trip(A3_PUBLIC, r#"["ES384"]"#)),
            "AlgorithmNotAllowed",
        ),
        (
            "round trip with a key that does not import",
            vector("jws.sign", &es256, &round_trip(RSA_PRIVATE, r#"["ES256"]"#)),
            "verify_with",
        ),
        (
            "expected an error, got success",
            vector("jws.sign", &hs256, r#"{"ok":false,"error":"InvalidKey"}"#),
            "succeeded",
        ),
        (
            "payload that does not decode",
            vector(
                "jws.sign",
                &hs256.replace(PAYLOAD, "Zh"),
                &signed(&quoted(&a1_compact())),
            ),
            "payload_b64u",
        ),
    ];
    for (what, json, needle) in cases {
        fails_naming_source(&format!("failing ({what}).json"), &json, needle);
    }
}

// ---------------------------------------------------------------------------
// Binding readiness: the WASM, Node, Kotlin and Swift runners (features
// 0006-0009) must read the jws.* vectors with their platform JSON parsers,
// unchanged (ADR 0034).
// ---------------------------------------------------------------------------

/// The number tokens of a JSON text, as written (outside strings).
fn number_tokens(text: &str) -> Vec<&str> {
    let mut tokens = Vec::new();
    let (mut in_string, mut escaped, mut start) = (false, false, None);
    for (i, c) in text.char_indices() {
        if in_string {
            match (escaped, c) {
                (true, _) => escaped = false,
                (false, '\\') => escaped = true,
                (false, '"') => in_string = false,
                _ => {}
            }
            continue;
        }
        // A number starts with '-' or a digit (RFC 8259 §6); `true` and
        // `false` hold an `e` but never start one.
        let begins = c.is_ascii_digit() || c == '-';
        let continues = begins || matches!(c, '+' | '.' | 'e' | 'E');
        match (start, begins, continues) {
            (None, true, _) => start = Some(i),
            (Some(s), _, false) => {
                tokens.push(&text[s..i]);
                start = None;
            }
            _ => {}
        }
        in_string = c == '"';
    }
    if let Some(s) = start {
        tokens.push(&text[s..]);
    }
    tokens
}

/// Every member of `value`, at any depth, with its JSON pointer.
fn members_deep<'a>(
    value: &'a Value,
    pointer: String,
    out: &mut Vec<(String, &'a str, &'a Value)>,
) {
    if let Some(object) = value.as_object() {
        for (name, member) in object {
            let at = format!("{pointer}/{name}");
            out.push((at.clone(), name, member));
            members_deep(member, at, out);
        }
    } else if let Some(items) = value.as_array() {
        for (i, item) in items.iter().enumerate() {
            members_deep(item, format!("{pointer}/{i}"), out);
        }
    }
}

/// Whether a vector file uses only what every binding's JSON parser reads
/// exactly:
///
/// - every number is written as a plain integer (no fraction or exponent,
///   which JavaScript, Kotlin and Swift parsers may read as a double) of
///   magnitude at most 2^32 - 1, so no binding needs a 64-bit-only type
///   (ADR 0030 `u32`);
/// - octets are base64url text (`*_b64u`), never raw bytes or `*_hex`, and
///   every one the runner decodes is canonical (`protected_b64u` is passed
///   to the library as text, so it may be anything the schema allows);
/// - in a `keys.*` vector, every base64url JWK member (`x`, `y`, `d`, `n`,
///   `e`, `k`; RFC 7518 §6, RFC 8037 §2) of a `jwk` object is canonical, so
///   a binding's base64url decoder reads the key the vector means.
fn binding_ready(text: &str) -> Result<(), String> {
    binding_ready_with(text, Numbers::Count)
}

/// Which numbers a binding-ready vector may contain.
#[derive(Debug, Clone, Copy)]
enum Numbers {
    /// `jws.*`, `jwe.*`, `keys.*`: plain integers of magnitude at most
    /// 2^32 − 1 (ADR 0030 `u32`).
    Count,
    /// `jwt.*`: plain integers within ±(2^53 − 1), the NumericDate and
    /// clock range (RFC 7493 §2.2; ADR 0027 §2, ADR 0028 §1), and
    /// non-integral decimals (`1300819380.5`, a fractional NumericDate,
    /// RFC 7519 §2) of magnitude within it. Every binding's JSON reads
    /// these exactly: JavaScript's numbers are doubles, which hold every
    /// integer of that range. An integral value is written as a plain
    /// integer (never `1.0` or `1e3`), so a binding reads `now` and every
    /// other integer member as an integer.
    Safe,
}

/// Whether the number token `token` (as written) is one `numbers` allows.
fn allowed_number(token: &str, numbers: Numbers) -> bool {
    let unsigned = token.strip_prefix('-').unwrap_or(token);
    let (int, frac) = match unsigned.split_once('.') {
        Some((int, frac)) => (int, Some(frac)),
        None => (unsigned, None),
    };
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if !digits(int) || frac.is_some_and(|f| !digits(f)) {
        return false; // an exponent, or not a number at all
    }
    match (numbers, frac) {
        (Numbers::Count, None) => token
            .parse::<i64>()
            .is_ok_and(|n| n.unsigned_abs() <= COUNT_MAX),
        (Numbers::Count, Some(_)) => false,
        (Numbers::Safe, None) => token
            .parse::<i64>()
            .is_ok_and(|n| n.unsigned_abs() <= SECONDS_MAX.unsigned_abs()),
        // Compared as the double every binding reads: within range, and
        // not integral (an integral value is written as an integer).
        (Numbers::Safe, Some(_)) => token
            .parse::<f64>()
            .is_ok_and(|v| v.is_finite() && v.abs() <= SECONDS_MAX as f64 && v.fract() != 0.0),
    }
}

/// [`binding_ready`] with the number rule `numbers`.
fn binding_ready_with(text: &str, numbers: Numbers) -> Result<(), String> {
    for token in number_tokens(text) {
        if !allowed_number(token, numbers) {
            return Err(match numbers {
                Numbers::Count => format!(
                    "number {token} is not a plain integer of magnitude at most {COUNT_MAX}"
                ),
                Numbers::Safe => format!(
                    "number {token} is not a plain integer, or a non-integral decimal, \
                     of magnitude at most {SECONDS_MAX}"
                ),
            });
        }
    }
    let value =
        parse_vector_file(text.as_bytes()).map_err(|e| format!("not JSON ({})", e.code()))?;
    let keys_vector = value
        .get("operation")
        .and_then(Value::as_str)
        .is_some_and(|op| op.starts_with("keys."));
    let mut members = Vec::new();
    members_deep(&value, String::new(), &mut members);
    for (pointer, name, member) in members {
        let jwk_member = pointer
            .rsplit_once('/')
            .is_some_and(|(parent, _)| parent.ends_with("/jwk"));
        if keys_vector && jwk_member && JWK_B64U_MEMBERS.contains(&name) {
            let canonical = member
                .as_str()
                .is_some_and(|s| b64url_decode(s).is_ok_and(|b| b64url_encode(&b) == s));
            if !canonical {
                return Err(format!("{pointer}: not canonical base64url"));
            }
        }
        if name.ends_with("_hex") {
            return Err(format!(
                "{pointer}: raw bytes; jws.* vectors write octets as *_b64u"
            ));
        }
        if name.ends_with("_b64u") && name != "protected_b64u" {
            let canonical = member
                .as_str()
                .is_some_and(|s| b64url_decode(s).is_ok_and(|b| b64url_encode(&b) == s));
            if !canonical {
                return Err(format!("{pointer}: not canonical base64url"));
            }
        }
    }
    Ok(())
}

/// The base64url members of a JWK (RFC 7518 §6.2–§6.4, RFC 8037 §2).
const JWK_B64U_MEMBERS: &[&str] = &["x", "y", "d", "n", "e", "k"];

/// The vectors the binding-readiness rule covers: everything under a
/// `jws-*` directory, a `third_party/**/jws/` directory or `keys/`, and any
/// jws.* or keys.* vector elsewhere.
fn needs_binding_readiness(relative: &Path, text: &str) -> bool {
    let parts: Vec<String> = relative
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    let jws_dir = parts
        .first()
        .is_some_and(|first| first.starts_with("jws-") || first == "keys");
    let third_party_jws = parts.first().is_some_and(|first| first == "third_party")
        && parts[..parts.len() - 1].iter().any(|part| part == "jws");
    let jws_operation = parse_vector_file(text.as_bytes()).is_ok_and(|v| {
        v.get("operation")
            .and_then(Value::as_str)
            .is_some_and(|op| op.starts_with("jws.") || op.starts_with("keys."))
    });
    jws_dir || third_party_jws || jws_operation
}

/// Every JWS and keys vector is binding-ready (see [`binding_ready`]).
#[test]
fn jws_and_keys_vectors_are_binding_ready() {
    let dir = conformance_dir().join("vectors");
    let (mut files, mut failures) = (Vec::new(), Vec::new());
    collect(&dir, &mut files, &mut failures);
    let mut checked = 0;
    for path in files {
        let relative = path.strip_prefix(&dir).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        if !needs_binding_readiness(relative, &text) {
            continue;
        }
        checked += 1;
        if let Err(problem) = binding_ready(&text) {
            failures.push(format!("{}: {problem}", relative.display()));
        }
    }
    assert!(
        failures.is_empty(),
        "not binding-ready:\n  {}",
        failures.join("\n  ")
    );
    assert!(
        checked >= 19,
        "only {checked} JWS and keys vector files found"
    );
}

/// The readiness check rejects what a binding could misread, and nothing
/// else; the vector selection matches the documented directories.
#[test]
fn binding_readiness_check_works() {
    for ok in [
        r#"{"a":0,"b":16,"c":-1,"d":4294967295,"e":[1,2]}"#,
        r#"{"s":"1.5e3 inside a string","t":"a\"1.0\\","n":7}"#,
        r#"{"payload_b64u":"Zm9v","protected_b64u":"Zh","x":{"detached_payload_b64u":""}}"#,
        r#"{"detached":false,"ok":true,"v":null,"n":12}"#,
        r#"{"operation":"keys.export_pem","input":{"jwk":{"kty":"oct","k":"Zm9v"}}}"#,
        // Outside keys.*, a `jwk` object's members are not checked here.
        r#"{"operation":"jws.verify","x":{"jwk":{"k":"Zh"}}}"#,
    ] {
        assert_eq!(binding_ready(ok), Ok(()), "{ok}");
    }
    for (bad, needle) in [
        (r#"{"n":1.0}"#, "1.0"),
        (r#"{"n":1e3}"#, "1e3"),
        (r#"{"n":0.5}"#, "0.5"),
        (r#"{"n":-0.0}"#, "-0.0"),
        (r#"{"n":4294967296}"#, "4294967296"),
        (r#"{"n":-4294967296}"#, "-4294967296"),
        (r#"{"a":[{"n":9007199254740993}]}"#, "9007199254740993"),
        (r#"{"input":{"bytes_hex":"00"}}"#, "/input/bytes_hex"),
        (r#"{"payload_b64u":"Zh"}"#, "/payload_b64u"),
        (
            r#"{"x":[{"detached_payload_b64u":"Zg=="}]}"#,
            "/x/0/detached_payload_b64u",
        ),
        (
            r#"{"operation":"keys.export_pem","input":{"jwk":{"kty":"oct","k":"Zh"}}}"#,
            "/input/jwk/k",
        ),
        (
            r#"{"operation":"keys.import_pem","expect":{"jwk":{"x":"Zg=="}}}"#,
            "/expect/jwk/x",
        ),
    ] {
        let problem = binding_ready(bad).unwrap_err();
        assert!(problem.contains(needle), "{bad}: {problem}");
    }
    let verify = r#"{"operation":"jws.verify"}"#;
    let import = r#"{"operation":"keys.import_pem"}"#;
    let other = r#"{"operation":"b64url.encode"}"#;
    for (path, text, covered) in [
        ("jws-rfc7515/a.json", other, true),
        ("jws-negative/deep/a.json", other, true),
        ("third_party/rfc7520/jws/a.json", other, true),
        ("third_party/rfc7520/jwe/a.json", other, false),
        ("third_party/jws.json", other, false),
        ("b64url/a.json", other, false),
        ("binding-surface/a.json", verify, true),
        ("keys/a.json", other, true),
        ("keys-extra/a.json", other, false),
        ("elsewhere/a.json", import, true),
    ] {
        assert_eq!(
            needs_binding_readiness(Path::new(path), text),
            covered,
            "{path}"
        );
    }
}

/// A temporary directory, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        let path =
            std::env::temp_dir().join(format!("polyjose-conformance-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        TempDir(path)
    }

    fn write(&self, relative: &str, contents: &str) {
        let path = self.0.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The directory walk finds nested files, ignores non-JSON files, and
/// collects every failure before reporting instead of stopping at the first.
#[test]
fn run_dir_collects_every_failure() {
    let dir = TempDir::new("collect");
    let ok = vector(
        "b64url.encode",
        r#"{"bytes_hex":"66"}"#,
        r#"{"ok":true,"b64u":"Zg"}"#,
    );
    dir.write("a/ok.json", &ok);
    dir.write("third_party/deep/ok.json", &ok);
    dir.write("third_party/LICENSE", "not a vector");
    dir.write(
        "a/unknown-op.json",
        &vector("jws.frobnicate", "{}", r#"{"ok":true}"#),
    );
    dir.write("b/invalid.json", &ok.replace(r#""66""#, r#""6""#));
    dir.write(
        "b/failing.json",
        &ok.replace(r#""b64u":"Zg""#, r#""b64u":"Zh""#),
    );
    let report = run_dir(&dir.0);
    assert_eq!(report.files, 5, "{report:?}");
    assert_eq!(report.failures.len(), 3, "{report:?}");
    for file in ["unknown-op.json", "invalid.json", "failing.json"] {
        assert!(
            report
                .failures
                .iter()
                .any(|f| f.contains(file) && f.contains(SOURCE)),
            "{file} not reported with its source: {report:?}"
        );
    }
}

/// An empty or missing directory fails, so a broken path cannot pass
/// vacuously.
#[test]
fn run_dir_fails_when_there_is_nothing_to_run() {
    let empty = TempDir::new("empty");
    empty.write("README.md", "no vectors here");
    let report = run_dir(&empty.0);
    assert_eq!(report.files, 0);
    assert!(
        report
            .failures
            .iter()
            .any(|f| f.contains("no vector files")),
        "{report:?}"
    );

    let missing = empty.0.join("does-not-exist");
    let report = run_dir(&missing);
    assert!(!report.failures.is_empty(), "{report:?}");
}

// ---------------------------------------------------------------------------
// jwe.* self-tests and the `features` member (0003 T09), on RFC 7516 A.3
// (the vector files under conformance/vectors/jwe/ cite it).
// ---------------------------------------------------------------------------

/// RFC 7516 A.3.3 key and A.3.7 compact JWE.
const JWE_A3_KEY: &str = r#"{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}"#;
const JWE_A3: &str = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.U0m_YmjN04DJvceFICbCVQ";
/// "Live long and prosper." (RFC 7516 A.3).
const JWE_A3_PLAINTEXT_B64U: &str = "TGl2ZSBsb25nIGFuZCBwcm9zcGVyLg";
const JWE_A3_POLICY: &str = r#""allowed_algs":["A128KW"],"allowed_enc":["A128CBC-HS256"]"#;

fn jwe_decrypt_input(jwe: &str, key: &str, extra: &str) -> String {
    format!(r#"{{"jwe":"{jwe}","key":{key},{JWE_A3_POLICY}{extra}}}"#)
}

fn jwe_encrypt_input(serialization: &str, recipients: &str, extra: &str) -> String {
    format!(
        r#"{{"serialization":"{serialization}","enc":"A128CBC-HS256","plaintext_b64u":"{JWE_A3_PLAINTEXT_B64U}","recipients":{recipients}{extra}}}"#
    )
}

fn jwe_a3_recipient() -> String {
    format!(r#"[{{"alg":"A128KW","key":{JWE_A3_KEY}}}]"#)
}

fn jwe_decrypt_with() -> String {
    format!(r#"{{"ok":true,"decrypt_with":{{"key":{JWE_A3_KEY},{JWE_A3_POLICY}}}}}"#)
}

fn with_features(vector: &str, features: &str) -> String {
    vector.replacen(
        r#""operation""#,
        &format!(r#""features":{features},"operation""#),
        1,
    )
}

/// Every `jwe.*` input form runs: decrypt success and failure (from the
/// key import, the policy and the library), and encrypt round trips and
/// refusals.
#[test]
fn jwe_vectors_pass() {
    let decrypted =
        format!(r#"{{"ok":true,"plaintext_b64u":"{JWE_A3_PLAINTEXT_B64U}","recipient":0}}"#);
    let cases = [
        vector(
            "jwe.decrypt",
            &jwe_decrypt_input(JWE_A3, JWE_A3_KEY, ""),
            &decrypted,
        ),
        vector(
            "jwe.decrypt",
            &jwe_decrypt_input(
                JWE_A3,
                JWE_A3_KEY,
                r#","understood_crit":["x"],"max_input_len":1000,"max_recipients":1,"max_pbes2_count":1000,"max_decompressed_len":0"#,
            ),
            &decrypted,
        ),
        vector(
            "jwe.decrypt",
            &jwe_decrypt_input(JWE_A3, JWE_A3_KEY, r#","max_input_len":10"#),
            r#"{"ok":false,"error":"InvalidFormat"}"#,
        ),
        vector(
            "jwe.decrypt",
            &jwe_decrypt_input(JWE_A3, r#"{"kty":"oct","k":"Zg=="}"#, ""),
            r#"{"ok":false,"error":"InvalidBase64"}"#,
        ),
        vector(
            "jwe.decrypt",
            &jwe_decrypt_input(JWE_A3, JWE_A3_KEY, "").replace(r#"["A128KW"]"#, "[]"),
            r#"{"ok":false,"error":"AlgorithmNotAllowed"}"#,
        ),
        vector(
            "jwe.decrypt",
            &jwe_decrypt_input(JWE_A3, JWE_A3_KEY, "").replace(r#""jwe":"eyJ"#, r#""jwe":"x.eyJ"#),
            r#"{"ok":false,"error":"InvalidFormat"}"#,
        ),
        vector(
            "jwe.encrypt",
            &jwe_encrypt_input("compact", &jwe_a3_recipient(), ""),
            &jwe_decrypt_with(),
        ),
        vector(
            "jwe.encrypt",
            &jwe_encrypt_input("compact", &jwe_a3_recipient(), r#","aad_b64u":"YQ""#),
            r#"{"ok":false,"error":"InvalidFormat"}"#,
        ),
        vector(
            "jwe.encrypt",
            &jwe_encrypt_input(
                "compact",
                r#"[{"alg":"A128KW","key":{"kty":"oct","k":"Zg=="}}]"#,
                "",
            ),
            r#"{"ok":false,"error":"InvalidBase64"}"#,
        ),
        vector(
            "jwe.encrypt",
            &jwe_encrypt_input("compact", &jwe_a3_recipient(), r#","protected":{"kid":7}"#),
            r#"{"ok":false,"error":"InvalidHeader"}"#,
        ),
    ];
    assert_passes(&cases);
}

/// A `jwe.*` vector that breaks the schema fails the run.
#[test]
fn jwe_schema_violations_fail() {
    let ok = r#"{"ok":true,"plaintext_b64u":"","recipient":0}"#;
    let input = jwe_decrypt_input(JWE_A3, JWE_A3_KEY, "");
    let encrypt = jwe_encrypt_input("compact", &jwe_a3_recipient(), "");
    let cases: Vec<(&str, String, &str)> = vec![
        (
            "decrypt without allowed_enc",
            vector(
                "jwe.decrypt",
                &input.replace(r#","allowed_enc":["A128CBC-HS256"]"#, ""),
                ok,
            ),
            "/input/allowed_enc: required member is missing",
        ),
        (
            "decrypt with an unknown member",
            vector(
                "jwe.decrypt",
                &input.replace(r#""jwe""#, r#""token":1,"jwe""#),
                ok,
            ),
            "/input/token: unknown member",
        ),
        (
            "decrypt jwe of the wrong type",
            vector(
                "jwe.decrypt",
                &input.replace(&format!(r#""{JWE_A3}""#), "7"),
                ok,
            ),
            "/input/jwe: must be a string (compact) or an object",
        ),
        (
            "decrypt understood_crit not strings",
            vector(
                "jwe.decrypt",
                &jwe_decrypt_input(JWE_A3, JWE_A3_KEY, r#","understood_crit":[1]"#),
                ok,
            ),
            "/input/understood_crit: must be an array of strings",
        ),
        (
            "decrypt ok without recipient",
            vector("jwe.decrypt", &input, r#"{"ok":true,"plaintext_b64u":""}"#),
            "/expect/recipient: required member is missing",
        ),
        (
            "encrypt recipient with an unknown member",
            vector(
                "jwe.encrypt",
                &jwe_encrypt_input(
                    "compact",
                    &format!(r#"[{{"alg":"A128KW","key":{JWE_A3_KEY},"kid":"a"}}]"#),
                    "",
                ),
                &jwe_decrypt_with(),
            ),
            "/input/recipients/0/kid: unknown member",
        ),
        (
            "encrypt with no recipients",
            vector(
                "jwe.encrypt",
                &jwe_encrypt_input("compact", "[]", ""),
                &jwe_decrypt_with(),
            ),
            "/input/recipients: must be a non-empty array",
        ),
        (
            "encrypt with an unknown serialization",
            vector(
                "jwe.encrypt",
                &jwe_encrypt_input("json", &jwe_a3_recipient(), ""),
                &jwe_decrypt_with(),
            ),
            "/input/serialization: must be one of",
        ),
        (
            "encrypt expecting both forms",
            vector(
                "jwe.encrypt",
                &encrypt,
                &format!(
                    r#"{{"ok":true,"jwe":"a","decrypt_with":{{"key":{JWE_A3_KEY},{JWE_A3_POLICY}}}}}"#
                ),
            ),
            "matches none of the success forms",
        ),
        (
            "rng_b64u without its feature",
            vector(
                "jwe.encrypt",
                &jwe_encrypt_input("compact", &jwe_a3_recipient(), r#","rng_b64u":"AA""#),
                r#"{"ok":true,"jwe":"x"}"#,
            ),
            "needs \"fixed-rng\" listed in `features`",
        ),
        (
            "protected_b64u with only another feature",
            with_features(
                &vector(
                    "jwe.encrypt",
                    &jwe_encrypt_input(
                        "compact",
                        &jwe_a3_recipient(),
                        r#","protected_b64u":"e30""#,
                    ),
                    r#"{"ok":true,"jwe":"x"}"#,
                ),
                r#"["deflate"]"#,
            ),
            "needs \"fixed-rng\"",
        ),
        (
            "compress without its feature",
            vector(
                "jwe.encrypt",
                &jwe_encrypt_input("compact", &jwe_a3_recipient(), r#","compress":true"#),
                &jwe_decrypt_with(),
            ),
            "needs \"deflate\" listed in `features`",
        ),
        (
            "an unknown feature",
            with_features(&vector("jwe.decrypt", &input, ok), r#"["sha1"]"#),
            "/features/0: must be one of",
        ),
        (
            "a feature listed twice",
            with_features(
                &vector("jwe.decrypt", &input, ok),
                r#"["deflate","deflate"]"#,
            ),
            "/features/1: listed twice",
        ),
        (
            "features not an array",
            with_features(&vector("jwe.decrypt", &input, ok), r#""deflate""#),
            "/features: must be an array",
        ),
    ];
    for (what, json, needle) in &cases {
        fails_naming_source(&format!("schema ({what}).json"), json, needle);
    }
}

/// A `jwe.*` vector the library does not meet fails, naming the file and
/// the source; so does a round trip whose decryption fails.
#[test]
fn jwe_mismatches_fail() {
    let other_key = r#"{"kty":"oct","k":"BwcHBwcHBwcHBwcHBwcHBw"}"#;
    let cases = [
        (
            "wrong plaintext",
            vector(
                "jwe.decrypt",
                &jwe_decrypt_input(JWE_A3, JWE_A3_KEY, ""),
                r#"{"ok":true,"plaintext_b64u":"AA","recipient":0}"#,
            ),
            "`plaintext_b64u`: expected",
        ),
        (
            "wrong error",
            vector(
                "jwe.decrypt",
                &jwe_decrypt_input(JWE_A3, other_key, ""),
                r#"{"ok":false,"error":"InvalidKey"}"#,
            ),
            "expected error InvalidKey, got error DecryptionFailed",
        ),
        (
            "round trip with the wrong key",
            vector(
                "jwe.encrypt",
                &jwe_encrypt_input("compact", &jwe_a3_recipient(), ""),
                &format!(r#"{{"ok":true,"decrypt_with":{{"key":{other_key},{JWE_A3_POLICY}}}}}"#),
            ),
            "does not decrypt with decrypt_with (DecryptionFailed)",
        ),
        (
            "round trip with a key that does not import",
            vector(
                "jwe.encrypt",
                &jwe_encrypt_input("compact", &jwe_a3_recipient(), ""),
                &format!(
                    r#"{{"ok":true,"decrypt_with":{{"key":{{"kty":"oct"}},{JWE_A3_POLICY}}}}}"#
                ),
            ),
            "decrypt_with.key does not import",
        ),
        (
            "an exact expectation of a randomized encryption",
            vector(
                "jwe.encrypt",
                &jwe_encrypt_input("compact", &jwe_a3_recipient(), ""),
                &format!(r#"{{"ok":true,"jwe":"{JWE_A3}"}}"#),
            ),
            "`jwe`: expected",
        ),
    ];
    for (what, json, needle) in &cases {
        fails_naming_source(&format!("failing ({what}).json"), json, needle);
    }
}

/// The reproducible path (feature `insecure-test-vectors`): the A.3 output
/// exactly, and every injected byte must be drawn, so a vector pins the
/// draw order (CEK, recipients, IV).
#[cfg(feature = "insecure-test-vectors")]
#[test]
fn jwe_reproducible_vectors_pin_the_draw_order() {
    // A.3.2 CEK then A.3.4 IV.
    let rng = "BNMfxVSd_P4LZJ36P6pqzmt81C1vawnbyLEA8I-cLM8DFjwMK0NoaWxsaWNvdGhl";
    let protected = JWE_A3.split('.').next().unwrap();
    let exact = format!(r#"{{"ok":true,"jwe":"{JWE_A3}"}}"#);
    let input = |rng: &str| {
        jwe_encrypt_input(
            "compact",
            &jwe_a3_recipient(),
            &format!(r#","protected_b64u":"{protected}","rng_b64u":"{rng}""#),
        )
    };
    let features = r#"["fixed-rng"]"#;
    assert_passes(&[with_features(
        &vector("jwe.encrypt", &input(rng), &exact),
        features,
    )]);
    fails_naming_source(
        "leftover.json",
        &with_features(
            &vector("jwe.encrypt", &input(&format!("{rng}AAAA")), &exact),
            features,
        ),
        "byte(s) the encryption did not draw",
    );
    // IV before CEK: another output.
    let swapped = "AxY8DCtDaGlsbGljb3RoZQTTH8VUnfz-C2Sd-j-qas5rfNQtb2sJ28ixAPCPnCzP";
    fails_naming_source(
        "swapped.json",
        &with_features(&vector("jwe.encrypt", &input(swapped), &exact), features),
        "`jwe`: expected",
    );
}

/// A vector needing a feature the build lacks is reported SKIPPED with the
/// feature's name, is never counted as passing, and is still validated.
#[test]
fn vectors_needing_a_disabled_feature_are_skipped_by_name() {
    let needs = with_features(
        &vector(
            "jwe.decrypt",
            &jwe_decrypt_input(JWE_A3, JWE_A3_KEY, ""),
            r#"{"ok":false,"error":"InvalidKey"}"#,
        ),
        r#"["deflate","fixed-rng"]"#,
    );
    // Its expectation is wrong, but with the features off it does not run.
    match check_vector_with("needs.json", needs.as_bytes(), &[]) {
        Ok(Passed::Skipped { missing, present }) => {
            assert_eq!(missing, ["deflate", "fixed-rng"]);
            assert!(present.is_empty());
        }
        other => panic!("expected SKIPPED, got {other:?}"),
    }
    match check_vector_with("needs.json", needs.as_bytes(), &["fixed-rng"]) {
        Ok(Passed::Skipped { missing, .. }) => assert_eq!(missing, ["deflate"]),
        other => panic!("expected SKIPPED, got {other:?}"),
    }
    // With the features on, it runs, and fails.
    assert!(check_vector_with("needs.json", needs.as_bytes(), &feature_names()).is_err());
    // A schema-invalid vector fails even when it would be skipped.
    let invalid = needs.replace(r#""allowed_enc""#, r#""allowed_encs""#);
    assert!(check_vector_with("invalid.json", invalid.as_bytes(), &[]).is_err());

    let dir = TempDir::new("skip");
    dir.write("a/needs.json", &needs);
    dir.write(
        "a/runs.json",
        &vector(
            "b64url.encode",
            r#"{"bytes_hex":"66"}"#,
            r#"{"ok":true,"b64u":"Zg"}"#,
        ),
    );
    let report = run_dir_with(&dir.0, &[]);
    assert!(report.failures.is_empty(), "{report:?}");
    assert_eq!(report.files, 2);
    assert_eq!(report.passed.values().sum::<usize>(), 1, "{report:?}");
    assert_eq!(report.passed.get("jwe.decrypt"), None, "{report:?}");
    assert_eq!(
        report.skipped,
        ["a/needs.json: SKIPPED (needs feature `deflate`, `insecure-test-vectors`)"]
    );
    assert_eq!(
        enabled_features().len(),
        usize::from(cfg!(feature = "deflate"))
            + usize::from(cfg!(feature = "insecure-test-vectors"))
    );
}

/// `features_absent` (ADR 0056): a vector that must run without a feature
/// the build enables is SKIPPED with `feature:!<name>`, after the missing
/// `features` names; it is never counted as passing, and it is still
/// validated.
#[test]
fn vectors_forbidding_an_enabled_feature_are_skipped_by_name() {
    let forbids = |absent: &str| {
        vector(
            "jwe.decrypt",
            &jwe_decrypt_input(JWE_A3, JWE_A3_KEY, ""),
            r#"{"ok":false,"error":"InvalidKey"}"#,
        )
        .replacen(
            r#""operation""#,
            &format!(r#""features_absent":{absent},"operation""#),
            1,
        )
    };
    let both = forbids(r#"["deflate","fixed-rng"]"#);
    // Its expectation is wrong, but with the features on it does not run.
    match check_vector_with("forbids.json", both.as_bytes(), &feature_names()) {
        Ok(Passed::Skipped { missing, present }) => {
            assert!(missing.is_empty());
            assert_eq!(present, ["deflate", "fixed-rng"]);
        }
        other => panic!("expected SKIPPED, got {other:?}"),
    }
    match check_vector_with("forbids.json", both.as_bytes(), &["fixed-rng"]) {
        Ok(Passed::Skipped { present, .. }) => assert_eq!(present, ["fixed-rng"]),
        other => panic!("expected SKIPPED, got {other:?}"),
    }
    // With the features off, it runs, and fails.
    assert!(check_vector_with("forbids.json", both.as_bytes(), &[]).is_err());
    // A schema-invalid vector fails even when it would be skipped.
    let invalid = both.replace(r#""allowed_enc""#, r#""allowed_encs""#);
    assert!(check_vector_with("invalid.json", invalid.as_bytes(), &feature_names()).is_err());

    // Needed and forbidden at once: the missing names first (ADR 0056 §2).
    let mixed = with_features(&forbids(r#"["deflate"]"#), r#"["fixed-rng"]"#);
    let dir = TempDir::new("skip-absent");
    dir.write("a/forbids.json", &forbids(r#"["deflate","fixed-rng"]"#));
    dir.write("a/mixed.json", &mixed);
    dir.write(
        "a/runs.json",
        &vector(
            "b64url.encode",
            r#"{"bytes_hex":"66"}"#,
            r#"{"ok":true,"b64u":"Zg"}"#,
        ),
    );
    let report = run_dir_with(&dir.0, &["deflate"]);
    assert!(report.failures.is_empty(), "{report:?}");
    assert_eq!(report.passed.values().sum::<usize>(), 1, "{report:?}");
    assert_eq!(
        report.skipped,
        [
            "a/forbids.json: SKIPPED (needs feature `deflate` off)",
            "a/mixed.json: SKIPPED (needs feature `insecure-test-vectors`; needs feature `deflate` off)",
        ]
    );
    let reasons: Vec<Option<&str>> = report
        .results
        .iter()
        .map(|entry| entry.get("reason").and_then(Value::as_str))
        .collect();
    assert_eq!(
        reasons,
        [
            Some("feature:!deflate"),
            Some("feature:fixed-rng,!deflate"),
            None
        ]
    );
    for entry in &report.results[..2] {
        assert_eq!(entry.get("status").and_then(Value::as_str), Some("skipped"));
        assert!(entry.get("actual").is_none(), "{entry:?}");
    }
}

/// The schema rules of `features_absent` (ADR 0056 §1, §3, §4): known
/// names, each once, at least one, none also in `features`; and a
/// `compress` vector may list `deflate` in either.
#[test]
fn features_absent_is_strict() {
    let input = jwe_decrypt_input(JWE_A3, JWE_A3_KEY, "");
    let ok = &format!(r#"{{"ok":true,"plaintext_b64u":"{JWE_A3_PLAINTEXT_B64U}","recipient":0}}"#);
    let absent = |vector: &str, list: &str| {
        vector.replacen(
            r#""operation""#,
            &format!(r#""features_absent":{list},"operation""#),
            1,
        )
    };
    let decrypt = vector("jwe.decrypt", &input, ok);
    for (what, json, needle) in [
        (
            "an unknown name",
            absent(&decrypt, r#"["sha1"]"#),
            "/features_absent/0: must be one of",
        ),
        (
            "a name listed twice",
            absent(&decrypt, r#"["deflate","deflate"]"#),
            "/features_absent/1: listed twice",
        ),
        (
            "an empty list",
            absent(&decrypt, "[]"),
            "/features_absent: must not be empty",
        ),
        (
            "not an array",
            absent(&decrypt, r#""deflate""#),
            "/features_absent: must be an array",
        ),
        (
            "a name in both lists",
            absent(&with_features(&decrypt, r#"["deflate"]"#), r#"["deflate"]"#),
            "/features_absent: \"deflate\" is listed in `features` too",
        ),
        (
            "a misspelled member",
            decrypt.replacen(
                r#""operation""#,
                r#""feature_absent":["deflate"],"operation""#,
                1,
            ),
            "/feature_absent: unknown member",
        ),
        (
            "compress with only fixed-rng absent",
            absent(
                &vector(
                    "jwe.encrypt",
                    &jwe_encrypt_input("compact", &jwe_a3_recipient(), r#","compress":true"#),
                    r#"{"ok":false,"error":"UnsupportedAlgorithm"}"#,
                ),
                r#"["fixed-rng"]"#,
            ),
            "needs \"deflate\" listed in `features` or `features_absent`",
        ),
    ] {
        fails_naming_source(&format!("schema ({what}).json"), &json, needle);
    }
    // `compress` with `deflate` absent: UnsupportedAlgorithm without the
    // codec (ADR 0017 §5, ADR 0030 §4), skipped where it is built in.
    let compress = absent(
        &vector(
            "jwe.encrypt",
            &jwe_encrypt_input("compact", &jwe_a3_recipient(), r#","compress":true"#),
            r#"{"ok":false,"error":"UnsupportedAlgorithm"}"#,
        ),
        r#"["deflate"]"#,
    );
    match check_vector("compress.json", compress.as_bytes()) {
        Ok(Passed::Skipped { present, .. }) => {
            assert!(cfg!(feature = "deflate"));
            assert_eq!(present, ["deflate"]);
        }
        Ok(Passed::Ran { negative, .. }) => {
            assert!(!cfg!(feature = "deflate") && negative);
        }
        Err(e) => panic!("{e}"),
    }
}

/// Every JWE vector is binding-ready (see [`binding_ready`]): the bindings
/// run the `jwe.*` vectors too (features 0006-0009), except those needing
/// `insecure-test-vectors`, which no binding enables (ADR 0005).
#[test]
fn jwe_vectors_are_binding_ready() {
    let dir = conformance_dir().join("vectors");
    let (mut files, mut failures) = (Vec::new(), Vec::new());
    collect(&dir, &mut files, &mut failures);
    let mut checked = 0;
    for path in files {
        let relative = path.strip_prefix(&dir).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let is_jwe = relative
            .components()
            .next()
            .is_some_and(|c| c.as_os_str() == "jwe")
            || json::parse(text.as_bytes()).is_ok_and(|v| {
                v.get("operation")
                    .and_then(Value::as_str)
                    .is_some_and(|op| op.starts_with("jwe."))
            });
        if !is_jwe {
            continue;
        }
        checked += 1;
        if let Err(problem) = binding_ready(&text) {
            failures.push(format!("{}: {problem}", relative.display()));
        }
    }
    assert!(
        failures.is_empty(),
        "not binding-ready:\n  {}",
        failures.join("\n  ")
    );
    assert!(checked >= 60, "only {checked} JWE vector files found");
}

// ---------------------------------------------------------------------------
// jwt.* self-tests (0004 T10), on the RFC 7519 §3.1 JWT (= RFC 7515 A.1) and
// the RFC 7515 A.3 ES256 JWS over the same claims. The vector files under
// conformance/vectors/jwt/ cite them.
// ---------------------------------------------------------------------------

/// The RFC 7519 §3.1 Claims Set, as the library returns it.
const JWT_CLAIMS: &str = r#"{"iss":"joe","exp":1300819380,"http://example.com/is_root":true}"#;
/// RFC 7519 §3.1's `iat`-free example is valid 60 s before its `exp`.
const JWT_NOW: &str = "1300819320";

/// RFC 7515 A.3, an ES256 JWS (no `typ`) over the §3.1 claims.
fn a3_compact() -> String {
    format!("{A3_PROTECTED}.{PAYLOAD}.{A3_SIGNATURE}")
}

/// A `jwt.validate` input: `token`, `now` [`JWT_NOW`], `allowed_algs`, the
/// key source `keys` (`"key":{...}` or `"jwks":{...}`) and `extra` members
/// (each with a leading comma).
fn jwt_validate_input(token: &str, algs: &str, keys: &str, extra: &str) -> String {
    format!(
        r#"{{"token":{},"now":{JWT_NOW},"allowed_algs":{algs},{keys}{extra}}}"#,
        quoted(token)
    )
}

/// The §3.1 JWT with its HS256 key and `extra` input members.
fn jwt_hs256(extra: &str) -> String {
    jwt_validate_input(
        &a1_compact(),
        r#"["HS256"]"#,
        &format!(r#""key":{A1_KEY}"#),
        extra,
    )
}

/// A `jwt.validate` success with the §3.1 claims, `alg` and `extra`
/// expectation members.
fn jwt_validated(alg: &str, extra: &str) -> String {
    format!(r#"{{"ok":true,"claims":{JWT_CLAIMS},"alg":"{alg}"{extra}}}"#)
}

fn failure(code: &str) -> String {
    format!(r#"{{"ok":false,"error":"{code}"}}"#)
}

/// Every `jwt.validate` input form runs, through `key` and `jwks`, and
/// every policy member reaches the library: each case below differs from
/// the passing §3.1 one by that member alone, so its outcome proves it.
#[test]
fn jwt_validate_vectors_pass() {
    let ok = jwt_validated("HS256", "");
    let jwks = format!(r#""jwks":{{"keys":[{OTHER_P256},{A3_PUBLIC}]}}"#);
    let cases = [
        vector("jwt.validate", &jwt_hs256(""), &ok),
        // Claims compare as JSON: member order and number spelling aside.
        vector(
            "jwt.validate",
            &jwt_hs256(""),
            r#"{"ok":true,"alg":"HS256","claims":{"http://example.com/is_root":true,"exp":1300819380.0,"iss":"joe"}}"#,
        ),
        // `now` is the only clock: at the expiry instant with no leeway the
        // token is expired, and before it, it is not.
        vector(
            "jwt.validate",
            &jwt_hs256(r#","policy":{"leeway":0}"#).replace(JWT_NOW, "1300819380"),
            &failure("TokenExpired"),
        ),
        vector(
            "jwt.validate",
            &jwt_hs256(r#","policy":{"leeway":0}"#).replace(JWT_NOW, "1300819379"),
            &ok,
        ),
        vector(
            "jwt.validate",
            &jwt_hs256("").replace(JWT_NOW, "-9007199254740991"),
            &ok,
        ),
        vector(
            "jwt.validate",
            &jwt_hs256("").replace(r#"["HS256"]"#, r#"["HS384"]"#),
            &failure("AlgorithmNotAllowed"),
        ),
        vector(
            "jwt.validate",
            &jwt_hs256("").replace(r#"["HS256"]"#, "[]"),
            &failure("AlgorithmNotAllowed"),
        ),
        vector(
            "jwt.validate",
            &jwt_hs256("").replace(r#"["HS256"]"#, r#"["none"]"#),
            &failure("AlgorithmNotAllowed"),
        ),
        // issuer: a string or a list (RFC 7519 §4.1.1).
        vector(
            "jwt.validate",
            &jwt_hs256(r#","policy":{"issuer":"joe"}"#),
            &ok,
        ),
        vector(
            "jwt.validate",
            &jwt_hs256(r#","policy":{"issuer":["bob","joe"]}"#),
            &ok,
        ),
        vector(
            "jwt.validate",
            &jwt_hs256(r#","policy":{"issuer":"bob"}"#),
            &failure("InvalidClaim"),
        ),
        vector(
            "jwt.validate",
            &jwt_hs256(r#","policy":{"issuer":[]}"#),
            &ok,
        ),
        vector(
            "jwt.validate",
            &jwt_hs256(r#","policy":{"audience":["joe"]}"#),
            &failure("InvalidClaim"),
        ),
        vector(
            "jwt.validate",
            &jwt_hs256(r#","policy":{"subject":"joe"}"#),
            &failure("InvalidClaim"),
        ),
        vector(
            "jwt.validate",
            &jwt_hs256(r#","policy":{"leeway":601}"#),
            &failure("InvalidClaim"),
        ),
        vector(
            "jwt.validate",
            &jwt_hs256(r#","policy":{"max_age":300}"#),
            &failure("InvalidClaim"),
        ),
        vector(
            "jwt.validate",
            &jwt_hs256(r#","policy":{"require":["iss","jti"]}"#),
            &failure("InvalidClaim"),
        ),
        vector(
            "jwt.validate",
            &jwt_hs256(r#","policy":{"require":[]}"#),
            &ok,
        ),
        vector(
            "jwt.validate",
            &jwt_hs256(r#","policy":{"allow_missing_exp":true,"ignore_audience":true}"#),
            &ok,
        ),
        vector(
            "jwt.validate",
            &jwt_hs256(r#","policy":{"allow_missing_exp":false,"ignore_audience":false}"#),
            &ok,
        ),
        // typ: the §3.1 header says JWT (RFC 7519 §5.1).
        vector(
            "jwt.validate",
            &jwt_hs256(r#","policy":{"typ":{"mode":"default"}}"#),
            &ok,
        ),
        vector(
            "jwt.validate",
            &jwt_hs256(r#","policy":{"typ":{"mode":"exact","value":"application/JWT"}}"#),
            &ok,
        ),
        vector(
            "jwt.validate",
            &jwt_hs256(r#","policy":{"typ":{"mode":"exact","value":"at+jwt"}}"#),
            &failure("InvalidHeader"),
        ),
        vector(
            "jwt.validate",
            &jwt_hs256(r#","policy":{"typ":{"mode":"any"}}"#),
            &ok,
        ),
        // RFC 9068 §4: typ JWT is not at+jwt, checked before any claim.
        vector(
            "jwt.validate",
            &jwt_hs256(r#","policy":{"profile":"access_token","issuer":"joe","audience":["api"]}"#),
            &failure("InvalidHeader"),
        ),
        vector(
            "jwt.validate",
            &jwt_hs256(r#","policy":{"profile":"access_token","audience":["api"]}"#),
            &failure("InvalidClaim"),
        ),
        // profile, then a typ mode that overrides its at+jwt.
        vector(
            "jwt.validate",
            &jwt_hs256(
                r#","policy":{"profile":"access_token","issuer":"joe","audience":["api"],"typ":{"mode":"any"}}"#,
            ),
            &failure("InvalidClaim"),
        ),
        // jwks (ADR 0029): the kid-less A.3 token tries member 0, then
        // verifies with member 1.
        vector(
            "jwt.validate",
            &jwt_validate_input(&a3_compact(), r#"["ES256"]"#, &jwks, ""),
            &jwt_validated("ES256", r#","key_index":1"#),
        ),
        vector(
            "jwt.validate",
            &jwt_validate_input(
                &a3_compact(),
                r#"["ES256"]"#,
                &jwks,
                r#","policy":{"max_key_candidates":1}"#,
            ),
            &failure("NoMatchingKey"),
        ),
        // A JWK or JWK Set import error is the outcome.
        vector(
            "jwt.validate",
            &jwt_validate_input(
                &a1_compact(),
                r#"["HS256"]"#,
                r#""key":{"kty":"oct","k":"Zg=="}"#,
                "",
            ),
            &failure("InvalidBase64"),
        ),
        vector(
            "jwt.validate",
            &jwt_validate_input(&a1_compact(), r#"["HS256"]"#, r#""jwks":{"keys":"x"}"#, ""),
            &failure("InvalidKey"),
        ),
        // An invalid member is skipped at import (RFC 7517 §5), so the set
        // has no candidate left: NoMatchingKey (ADR 0029 §4).
        vector(
            "jwt.validate",
            &jwt_validate_input(
                &a1_compact(),
                r#"["HS256"]"#,
                r#""jwks":{"keys":[{"kty":"oct","k":"Zg=="}]}"#,
                "",
            ),
            &failure("NoMatchingKey"),
        ),
    ];
    assert_passes(&cases);
}

/// The step order of conformance/README.md: `decrypt.key`, then
/// `decrypt`'s lists, then `key` or `jwks`, then the policy, the first
/// error being the outcome. Each case breaks two steps with different
/// codes and expects the earlier one, so none depends on the library's own
/// JWE or JWT processing order.
#[test]
fn jwt_validate_runs_its_steps_in_order() {
    let broken_set = r#""jwks":{"keys":"x"}"#; // InvalidKey
    let decrypt = |key: &str, enc: &str| {
        format!(r#","decrypt":{{"key":{key},"allowed_algs":["A128KW"],"allowed_enc":{enc}}}"#)
    };
    let cases = [
        // decrypt.key (InvalidBase64) before jwks (InvalidKey).
        vector(
            "jwt.validate",
            &jwt_validate_input(
                &a1_compact(),
                r#"["HS256"]"#,
                broken_set,
                &decrypt(r#"{"kty":"oct","k":"Zg=="}"#, r#"["A128GCM"]"#),
            ),
            &failure("InvalidBase64"),
        ),
        // decrypt.key (InvalidBase64) before decrypt's lists
        // (AlgorithmNotAllowed).
        vector(
            "jwt.validate",
            &jwt_hs256(&decrypt(r#"{"kty":"oct","k":"Zg=="}"#, "[]")),
            &failure("InvalidBase64"),
        ),
        // decrypt's lists (AlgorithmNotAllowed) before jwks (InvalidKey).
        vector(
            "jwt.validate",
            &jwt_validate_input(
                &a1_compact(),
                r#"["HS256"]"#,
                broken_set,
                &decrypt(JWE_A3_KEY, "[]"),
            ),
            &failure("AlgorithmNotAllowed"),
        ),
        // jwks (InvalidKey) before the policy (InvalidClaim, leeway).
        vector(
            "jwt.validate",
            &jwt_validate_input(
                &a1_compact(),
                r#"["HS256"]"#,
                broken_set,
                r#","policy":{"leeway":601}"#,
            ),
            &failure("InvalidKey"),
        ),
        // The allow-list (AlgorithmNotAllowed) before the leeway
        // (InvalidClaim): both are the policy's, built in that order.
        vector(
            "jwt.validate",
            &jwt_hs256(r#","policy":{"leeway":601}"#).replace(r#"["HS256"]"#, "[]"),
            &failure("AlgorithmNotAllowed"),
        ),
    ];
    assert_passes(&cases);
}

/// The runner's strictness (criterion 2): a misspelled member, a missing
/// `now`, both `key` and `jwks`, and every other way of breaking the
/// `jwt.validate` schema fail the run, naming the member.
#[test]
fn jwt_validate_schema_violations_fail() {
    let ok = jwt_validated("HS256", "");
    let with_policy = |policy: &str| jwt_hs256(&format!(r#","policy":{policy}"#));
    let decrypt = r#","decrypt":{"key":{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"},"allowed_algs":["A128KW"],"allowed_enc":["A128GCM"]}"#;
    let cases: &[(&str, String, &str)] = &[
        (
            "misspelled allowed_algs",
            jwt_hs256("").replace(r#""allowed_algs""#, r#""allowed_alg""#),
            "/input/allowed_alg: unknown member",
        ),
        (
            "missing now",
            jwt_hs256("").replace(&format!(r#""now":{JWT_NOW},"#), ""),
            "/input/now: required member is missing",
        ),
        (
            "missing token",
            jwt_hs256("").replace(&format!(r#""token":"{}","#, a1_compact()), ""),
            "/input/token: required member is missing",
        ),
        (
            "missing allowed_algs",
            jwt_hs256("").replace(r#""allowed_algs":["HS256"],"#, ""),
            "/input/allowed_algs: required member is missing",
        ),
        (
            "both key and jwks",
            jwt_hs256(&format!(r#","jwks":{{"keys":[{A1_KEY}]}}"#)),
            "/input: needs exactly one of `key`, `jwks` (oneOf), has 2",
        ),
        (
            "neither key nor jwks",
            jwt_validate_input(&a1_compact(), r#"["HS256"]"#, r#""policy":{}"#, ""),
            "/input: needs exactly one of `key`, `jwks` (oneOf), has 0",
        ),
        (
            "now as a string",
            jwt_hs256("").replace(JWT_NOW, &quoted(JWT_NOW)),
            "/input/now",
        ),
        (
            "fractional now",
            jwt_hs256("").replace(JWT_NOW, "1300819320.5"),
            "/input/now",
        ),
        (
            "now above 2^53 - 1",
            jwt_hs256("").replace(JWT_NOW, "9007199254740992"),
            "/input/now",
        ),
        (
            "now below -(2^53 - 1)",
            jwt_hs256("").replace(JWT_NOW, "-9007199254740992"),
            "/input/now",
        ),
        (
            "token not a string",
            jwt_hs256("").replace(&quoted(&a1_compact()), "[]"),
            "/input/token",
        ),
        (
            "key not an object",
            jwt_hs256("").replace(A1_KEY, &quoted("k")),
            "/input/key",
        ),
        (
            "jwks not an object",
            jwt_validate_input(&a1_compact(), r#"["HS256"]"#, r#""jwks":[]"#, ""),
            "/input/jwks",
        ),
        (
            "misspelled policy member",
            with_policy(r#"{"audiences":["joe"]}"#),
            "/input/policy/audiences: unknown member",
        ),
        ("policy not an object", with_policy("[]"), "/input/policy"),
        (
            "issuer a number",
            with_policy(r#"{"issuer":7}"#),
            "/input/policy/issuer",
        ),
        (
            "issuer list with a number",
            with_policy(r#"{"issuer":["joe",7]}"#),
            "/input/policy/issuer",
        ),
        (
            "audience a string",
            with_policy(r#"{"audience":"joe"}"#),
            "/input/policy/audience",
        ),
        (
            "negative leeway",
            with_policy(r#"{"leeway":-1}"#),
            "/input/policy/leeway",
        ),
        (
            "max_age a string",
            with_policy(r#"{"max_age":"300"}"#),
            "/input/policy/max_age",
        ),
        (
            "require a string",
            with_policy(r#"{"require":"jti"}"#),
            "/input/policy/require",
        ),
        (
            "allow_missing_exp a string",
            with_policy(r#"{"allow_missing_exp":"true"}"#),
            "/input/policy/allow_missing_exp",
        ),
        (
            "unknown profile",
            with_policy(r#"{"profile":"id_token"}"#),
            "/input/policy/profile",
        ),
        (
            "typ a string",
            with_policy(r#"{"typ":"JWT"}"#),
            "/input/policy/typ",
        ),
        (
            "unknown typ mode",
            with_policy(r#"{"typ":{"mode":"strict"}}"#),
            "/input/policy/typ/mode",
        ),
        (
            "typ without a mode",
            with_policy(r#"{"typ":{"value":"JWT"}}"#),
            "/input/policy/typ/mode: required member is missing",
        ),
        (
            "exact typ without a value",
            with_policy(r#"{"typ":{"mode":"exact"}}"#),
            "/input/policy/typ/value: required when `mode` is \"exact\"",
        ),
        (
            "a value with typ mode any",
            with_policy(r#"{"typ":{"mode":"any","value":"JWT"}}"#),
            "/input/policy/typ/value: allowed only when `mode` is \"exact\"",
        ),
        (
            "unknown typ member",
            with_policy(r#"{"typ":{"mode":"any","strict":true}}"#),
            "/input/policy/typ/strict: unknown member",
        ),
        (
            "max_key_candidates negative",
            with_policy(r#"{"max_key_candidates":-1}"#),
            "/input/policy/max_key_candidates",
        ),
        (
            "decrypt without allowed_enc",
            jwt_hs256(&decrypt.replace(r#","allowed_enc":["A128GCM"]"#, "")),
            "/input/decrypt/allowed_enc: required member is missing",
        ),
        (
            "misspelled decrypt member",
            jwt_hs256(&decrypt.replace(r#"["A128GCM"]}"#, r#"["A128GCM"],"max_p2c":1}"#)),
            "/input/decrypt/max_p2c: unknown member",
        ),
        (
            "decrypt key not an object",
            jwt_hs256(&decrypt.replace(r#"{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}"#, "\"k\"")),
            "/input/decrypt/key",
        ),
    ];
    for (what, input, needle) in cases {
        let json = vector("jwt.validate", input, &ok);
        fails_naming_source(&format!("invalid ({what}).json"), &json, needle);
    }
    let input = jwt_hs256("");
    let expectations: &[(&str, String, &str)] = &[
        (
            "success without claims",
            r#"{"ok":true,"alg":"HS256"}"#.to_owned(),
            "/expect/claims: required member is missing",
        ),
        (
            "success without alg",
            format!(r#"{{"ok":true,"claims":{JWT_CLAIMS}}}"#),
            "/expect/alg: required member is missing",
        ),
        (
            "claims not an object",
            r#"{"ok":true,"claims":[],"alg":"HS256"}"#.to_owned(),
            "/expect/claims",
        ),
        (
            "key_index a string",
            jwt_validated("HS256", r#","key_index":"0""#),
            "/expect/key_index",
        ),
        (
            "unknown success member",
            jwt_validated("HS256", r#","kid":"a""#),
            "/expect/kid: unknown member",
        ),
        (
            "failure with claims",
            format!(r#"{{"ok":false,"error":"TokenExpired","claims":{JWT_CLAIMS}}}"#),
            "/expect/claims: unknown member",
        ),
        ("unknown error code", failure("Expired"), "/expect/error"),
    ];
    for (what, expect, needle) in expectations {
        let json = vector("jwt.validate", &input, expect);
        fails_naming_source(&format!("invalid ({what}).json"), &json, needle);
    }
}

/// A `jwt.validate` vector whose expectation the library does not meet
/// fails, naming what differs; `key_index` is compared both ways.
#[test]
fn jwt_validate_mismatches_fail() {
    let jwks = format!(r#""jwks":{{"keys":[{OTHER_P256},{A3_PUBLIC}]}}"#);
    let via_set = jwt_validate_input(&a3_compact(), r#"["ES256"]"#, &jwks, "");
    let cases = [
        (
            "wrong claims",
            vector(
                "jwt.validate",
                &jwt_hs256(""),
                &jwt_validated("HS256", "").replace("1300819380", "1300819381"),
            ),
            "`claims`: expected",
        ),
        (
            "an extra claim",
            vector(
                "jwt.validate",
                &jwt_hs256(""),
                &jwt_validated("HS256", "").replace(r#""iss":"joe""#, r#""iss":"joe","sub":"x""#),
            ),
            "`claims`: expected",
        ),
        (
            "wrong alg",
            vector("jwt.validate", &jwt_hs256(""), &jwt_validated("HS384", "")),
            "`alg`: expected \"HS384\"",
        ),
        (
            "key_index left out for a jwks",
            vector("jwt.validate", &via_set, &jwt_validated("ES256", "")),
            "`key_index`: expected nothing, got 1",
        ),
        (
            "wrong key_index",
            vector(
                "jwt.validate",
                &via_set,
                &jwt_validated("ES256", r#","key_index":0"#),
            ),
            "`key_index`: expected 0, got 1",
        ),
        (
            "key_index for a single key",
            vector(
                "jwt.validate",
                &jwt_hs256(""),
                &jwt_validated("HS256", r#","key_index":0"#),
            ),
            "`key_index`: expected 0, got nothing",
        ),
        (
            "expected success, but expired",
            vector(
                "jwt.validate",
                &jwt_hs256("").replace(JWT_NOW, "1300819440"),
                &jwt_validated("HS256", ""),
            ),
            "expected success, got error TokenExpired",
        ),
        (
            "wrong error code",
            vector(
                "jwt.validate",
                &jwt_hs256("").replace(JWT_NOW, "1300819440"),
                &failure("InvalidClaim"),
            ),
            "expected error InvalidClaim, got error TokenExpired",
        ),
        (
            "expected an error, but valid",
            vector("jwt.validate", &jwt_hs256(""), &failure("TokenExpired")),
            "succeeded",
        ),
        (
            "profile with typ mode default",
            vector(
                "jwt.validate",
                &jwt_hs256(
                    r#","policy":{"profile":"access_token","issuer":"joe","audience":["a"],"typ":{"mode":"default"}}"#,
                ),
                &failure("InvalidHeader"),
            ),
            "contradicts `policy/profile`",
        ),
    ];
    for (what, json, needle) in cases {
        fails_naming_source(&format!("failing ({what}).json"), &json, needle);
    }
}

/// The §3.1 claims issued with HS256 and `extra` input members.
fn jwt_issue_input(alg: &str, key: &str, extra: &str) -> String {
    format!(r#"{{"claims":{JWT_CLAIMS},"alg":"{alg}","key":{key}{extra}}}"#)
}

/// A `validate` member checking the issued token with `key`.
fn jwt_issue_validate(algs: &str, key: &str, extra: &str) -> String {
    format!(r#","validate":{{"now":{JWT_NOW},"allowed_algs":{algs},"key":{key}{extra}}}"#)
}

/// The exact HS256 token of the §3.1 claims with `{"alg":"HS256",
/// "typ":"JWT"}`, as conformance/vectors/jwt/rfc7519/3-1-hs256-issue-exact.json
/// derives it independently.
const JWT_ISSUED_HS256: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.d6nMDXnJZfNNj-1o1e75s6d0six0lkLp5hSrGaz4o9A";

/// Every `jwt.issue` input and expectation form runs: exact, validated
/// round trips (with `typ` set, defaulted and omitted, ES256 randomized),
/// and the import, claims and signing errors.
#[test]
fn jwt_issue_vectors_pass() {
    let hs = |extra: &str| jwt_issue_input("HS256", A1_KEY, extra);
    let hs_validate = |extra: &str| jwt_issue_validate(r#"["HS256"]"#, A1_KEY, extra);
    let exact = format!(r#"{{"ok":true,"token":"{JWT_ISSUED_HS256}"}}"#);
    let validated = r#"{"ok":true}"#;
    let cases = [
        vector("jwt.issue", &hs(""), &exact),
        // An exact token with `validate` is also validated.
        vector("jwt.issue", &hs(&hs_validate("")), &exact),
        vector("jwt.issue", &hs(&hs_validate("")), validated),
        // typ null omits it (RFC 7519 §5.1), and the default mode accepts
        // that; an explicit typ needs the matching mode (RFC 8725 §3.11).
        vector(
            "jwt.issue",
            &hs(&format!(r#","typ":null{}"#, hs_validate(""))),
            validated,
        ),
        vector(
            "jwt.issue",
            &hs(&format!(
                r#","typ":"secevent+jwt"{}"#,
                hs_validate(r#","policy":{"typ":{"mode":"exact","value":"secevent+jwt"}}"#)
            )),
            validated,
        ),
        // ECDSA is randomized: only a round trip can check it.
        vector(
            "jwt.issue",
            &jwt_issue_input(
                "ES256",
                A3_PRIVATE,
                &jwt_issue_validate(r#"["ES256"]"#, A3_PUBLIC, ""),
            ),
            validated,
        ),
        // Validation through a JWK Set.
        vector(
            "jwt.issue",
            &jwt_issue_input(
                "ES256",
                A3_PRIVATE,
                &format!(
                    r#","validate":{{"now":{JWT_NOW},"allowed_algs":["ES256"],"jwks":{{"keys":[{OTHER_P256},{A3_PUBLIC}]}}}}"#
                ),
            ),
            validated,
        ),
        // Errors, in step order: key import, claims, signing.
        vector(
            "jwt.issue",
            &jwt_issue_input("HS256", r#"{"kty":"oct","k":"Zg=="}"#, ""),
            &failure("InvalidBase64"),
        ),
        vector(
            "jwt.issue",
            &hs("").replace(r#""exp":1300819380"#, r#""exp":"1300819380""#),
            &failure("InvalidClaim"),
        ),
        vector(
            "jwt.issue",
            &jwt_issue_input("none", A1_KEY, ""),
            &failure("AlgorithmNotAllowed"),
        ),
        vector(
            "jwt.issue",
            &jwt_issue_input("HS257", A1_KEY, ""),
            &failure("UnsupportedAlgorithm"),
        ),
        vector(
            "jwt.issue",
            &jwt_issue_input("ES384", A3_PRIVATE, ""),
            &failure("KeyAlgorithmMismatch"),
        ),
        // An `encrypt.key` import error is the outcome, before signing.
        vector(
            "jwt.issue",
            &jwt_issue_input(
                "none",
                A1_KEY,
                r#","encrypt":{"alg":"A128KW","enc":"A128GCM","key":{"kty":"oct","k":"Zg=="}}"#,
            ),
            &failure("InvalidBase64"),
        ),
    ];
    assert_passes(&cases);
}

/// The `jwt.issue` schema and its cross-member rules fail the run, naming
/// the member.
#[test]
fn jwt_issue_schema_violations_fail() {
    let exact = format!(r#"{{"ok":true,"token":"{JWT_ISSUED_HS256}"}}"#);
    let validated = r#"{"ok":true}"#.to_owned();
    let validate = jwt_issue_validate(r#"["HS256"]"#, A1_KEY, "");
    let encrypt = r#","encrypt":{"alg":"A128KW","enc":"A128GCM","key":{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}}"#;
    let hs = |extra: &str| jwt_issue_input("HS256", A1_KEY, extra);
    let cases: &[(&str, String, String, &str)] = &[
        (
            "misspelled member",
            hs("").replace(r#""claims""#, r#""claim""#),
            exact.clone(),
            "/input/claim: unknown member",
        ),
        (
            "missing alg",
            hs("").replace(r#""alg":"HS256","#, ""),
            exact.clone(),
            "/input/alg: required member is missing",
        ),
        (
            "claims not an object",
            hs("").replace(JWT_CLAIMS, "[]"),
            exact.clone(),
            "/input/claims",
        ),
        (
            "typ a number",
            hs(r#","typ":1"#),
            exact.clone(),
            "/input/typ",
        ),
        (
            "encrypt without enc",
            hs(&encrypt.replace(r#""enc":"A128GCM","#, "")),
            validated.clone(),
            "/input/encrypt/enc: required member is missing",
        ),
        (
            "validate with a token",
            hs(&validate.replace(r#""now""#, r#""token":"a.b.c","now""#)),
            validated.clone(),
            "/input/validate/token: unknown member",
        ),
        (
            "validate without now",
            hs(&validate.replace(&format!(r#""now":{JWT_NOW},"#), "")),
            validated.clone(),
            "/input/validate/now: required member is missing",
        ),
        (
            "validate with both key and jwks",
            hs(&validate.replace(r#""key""#, r#""jwks":{"keys":[]},"key""#)),
            validated.clone(),
            "/input/validate: needs exactly one of `key`, `jwks` (oneOf), has 2",
        ),
        (
            "validate with a misspelled policy member",
            hs(&jwt_issue_validate(
                r#"["HS256"]"#,
                A1_KEY,
                r#","policy":{"leway":0}"#,
            )),
            validated.clone(),
            "/input/validate/policy/leway: unknown member",
        ),
        (
            "an exact token with encrypt",
            hs(encrypt),
            exact.clone(),
            "/expect/token: an encrypted token is randomized",
        ),
        (
            "validated without validate or encrypt",
            hs(""),
            validated.clone(),
            "/input/validate: required when the expectation has no `token`",
        ),
        (
            "a failure with validate",
            hs(&validate),
            failure("AlgorithmNotAllowed"),
            "/input/validate: used only when the issue succeeds",
        ),
        (
            "token not a string",
            hs(""),
            r#"{"ok":true,"token":7}"#.to_owned(),
            "/expect",
        ),
        (
            "an unknown success member",
            hs(""),
            format!(r#"{{"ok":true,"token":"{JWT_ISSUED_HS256}","kid":"a"}}"#),
            "/expect",
        ),
    ];
    for (what, input, expect, needle) in cases {
        let json = vector("jwt.issue", input, expect);
        fails_naming_source(&format!("invalid ({what}).json"), &json, needle);
    }
}

/// A `jwt.issue` vector whose expectation the library does not meet fails:
/// a wrong exact token, and every way a round trip can fail.
#[test]
fn jwt_issue_mismatches_fail() {
    let hs = |extra: &str| jwt_issue_input("HS256", A1_KEY, extra);
    let validated = r#"{"ok":true}"#;
    let cases = [
        (
            "wrong exact token",
            vector(
                "jwt.issue",
                &hs(""),
                &format!(r#"{{"ok":true,"token":"{}"}}"#, a1_compact()),
            ),
            "`token`: expected",
        ),
        (
            "round trip with the wrong key",
            vector(
                "jwt.issue",
                // RFC 7515 A.1's key with its first octets changed.
                &hs(&jwt_issue_validate(
                    r#"["HS256"]"#,
                    &A1_KEY.replace("AyM1", "ByM1"),
                    "",
                )),
                validated,
            ),
            "round trip: the issued token does not validate with `validate` (InvalidSignature)",
        ),
        (
            "round trip after expiry",
            vector(
                "jwt.issue",
                &hs(&jwt_issue_validate(r#"["HS256"]"#, A1_KEY, "").replace(JWT_NOW, "1300819440")),
                validated,
            ),
            "(TokenExpired)",
        ),
        (
            "round trip with a refused policy",
            vector(
                "jwt.issue",
                &hs(&jwt_issue_validate(
                    r#"["HS256"]"#,
                    A1_KEY,
                    r#","policy":{"leeway":601}"#,
                )),
                validated,
            ),
            "round trip: `validate/policy` is refused (InvalidClaim)",
        ),
        (
            "round trip with a key that does not import",
            vector(
                "jwt.issue",
                &hs(&jwt_issue_validate(
                    r#"["HS256"]"#,
                    r#"{"kty":"oct","k":"Zg=="}"#,
                    "",
                )),
                validated,
            ),
            "round trip: `validate` does not import (InvalidBase64)",
        ),
        (
            "round trip with typ omitted but exact typ required",
            vector(
                "jwt.issue",
                &hs(&format!(
                    r#","typ":null{}"#,
                    jwt_issue_validate(
                        r#"["HS256"]"#,
                        A1_KEY,
                        r#","policy":{"typ":{"mode":"exact","value":"JWT"}}"#
                    )
                )),
                validated,
            ),
            "(InvalidHeader)",
        ),
        (
            "expected an error, but issued",
            vector("jwt.issue", &hs(""), &failure("UnsupportedAlgorithm")),
            "succeeded",
        ),
    ];
    for (what, json, needle) in cases {
        fails_naming_source(&format!("failing ({what}).json"), &json, needle);
    }
}

/// The JWT vectors the binding-readiness rule covers: everything under
/// `jwt/`, and any `jwt.*` vector elsewhere.
fn needs_jwt_binding_readiness(relative: &Path, text: &str) -> bool {
    let jwt_dir = relative
        .components()
        .next()
        .is_some_and(|c| c.as_os_str() == "jwt");
    let jwt_operation = parse_vector_file(text.as_bytes()).is_ok_and(|v| {
        v.get("operation")
            .and_then(Value::as_str)
            .is_some_and(|op| op.starts_with("jwt."))
    });
    jwt_dir || jwt_operation
}

/// Criterion 4: every JWT vector is binding-ready (see
/// [`binding_ready_with`] and [`Numbers::Safe`]): no integer outside
/// ±(2^53 − 1) in the vector JSON itself. Out-of-range values under test
/// live inside base64url token payloads, never in the JSON.
#[test]
fn jwt_vectors_are_binding_ready() {
    let dir = conformance_dir().join("vectors");
    let (mut files, mut failures) = (Vec::new(), Vec::new());
    collect(&dir, &mut files, &mut failures);
    let mut checked = 0;
    for path in files {
        let relative = path.strip_prefix(&dir).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        if !needs_jwt_binding_readiness(relative, &text) {
            continue;
        }
        checked += 1;
        if let Err(problem) = binding_ready_with(&text, Numbers::Safe) {
            failures.push(format!("{}: {problem}", relative.display()));
        }
    }
    assert!(
        failures.is_empty(),
        "not binding-ready:\n  {}",
        failures.join("\n  ")
    );
    assert!(checked >= 12, "only {checked} JWT vector files found");
}

/// The JWT readiness rule accepts every number a binding reads exactly,
/// and nothing else; the vector selection is `jwt/` and `jwt.*`.
#[test]
fn jwt_binding_readiness_check_works() {
    for ok in [
        r#"{"now":1300819320,"exp":-100,"n":0}"#,
        r#"{"now":9007199254740991,"then":-9007199254740991}"#,
        // A fractional NumericDate (RFC 7519 §2) in expected claims.
        r#"{"claims":{"exp":1300819380.5,"nbf":-0.25}}"#,
        r#"{"typ":null,"ok":true,"s":"9007199254740993 inside a string"}"#,
    ] {
        assert_eq!(binding_ready_with(ok, Numbers::Safe), Ok(()), "{ok}");
    }
    for (bad, needle) in [
        (r#"{"now":9007199254740992}"#, "9007199254740992"),
        (r#"{"now":-9007199254740992}"#, "-9007199254740992"),
        (
            r#"{"a":[{"exp":18446744073709551616}]}"#,
            "18446744073709551616",
        ),
        // An integral value is written as a plain integer.
        (r#"{"now":1300819320.0}"#, "1300819320.0"),
        (r#"{"exp":1e3}"#, "1e3"),
        (r#"{"exp":1.5e3}"#, "1.5e3"),
        (r#"{"exp":9007199254740991.5}"#, "9007199254740991.5"),
        (r#"{"input":{"bytes_hex":"00"}}"#, "/input/bytes_hex"),
        (r#"{"payload_b64u":"Zh"}"#, "/payload_b64u"),
    ] {
        let problem = binding_ready_with(bad, Numbers::Safe).unwrap_err();
        assert!(problem.contains(needle), "{bad}: {problem}");
    }
    // The jws/keys rule stays as strict as before.
    assert!(binding_ready_with(r#"{"now":1300819320}"#, Numbers::Count).is_ok());
    assert!(binding_ready_with(r#"{"now":4294967296}"#, Numbers::Count).is_err());
    assert!(binding_ready_with(r#"{"exp":0.5}"#, Numbers::Count).is_err());
    let validate = r#"{"operation":"jwt.validate"}"#;
    let other = r#"{"operation":"b64url.encode"}"#;
    for (path, text, covered) in [
        ("jwt/rfc7519/a.json", other, true),
        ("jwt/a.json", other, true),
        ("elsewhere/a.json", validate, true),
        ("jwt-extra/a.json", other, false),
        ("jws-rfc7515/jwt/a.json", other, false),
    ] {
        assert_eq!(
            needs_jwt_binding_readiness(Path::new(path), text),
            covered,
            "{path}"
        );
    }
}

/// Criterion 2 (ADR 0028 §4): the runner's only clock is the `FixedClock`
/// it builds from `now`. `jwt_policy` takes a `&FixedClock`, so the types
/// already keep any other clock out of the library call; this scan of the
/// runner's own source keeps a later edit from reading the wall clock
/// another way. The names are assembled at run time so this test does not
/// match itself.
#[test]
fn jwt_runner_never_reads_the_wall_clock() {
    let source = include_str!("conformance.rs");
    let forbidden = [
        ["System", "Clock"].concat(),
        ["System", "Time"].concat(),
        ["Instant", "::"].concat(),
        ["UNIX", "_EPOCH"].concat(),
    ];
    for name in &forbidden {
        assert!(!source.contains(name.as_str()), "the runner names {name}");
    }
    let fixed = ["FixedClock", "(now)"].concat();
    assert_eq!(
        source.matches(fixed.as_str()).count(),
        1,
        "one clock, from `now`"
    );
    // And `now` decides: the RFC 7519 §3.1 JWT expired in 2011, so it is
    // valid only because the runner's clock is `now`.
    let valid = vector("jwt.validate", &jwt_hs256(""), &jwt_validated("HS256", ""));
    assert!(check_vector("clock.json", valid.as_bytes()).is_ok());
}

// ---------------------------------------------------------------------------
// Results files (ADR 0034 §2): conformance/schema/results.schema.json and a
// validator for it.
// ---------------------------------------------------------------------------

/// `conformance/schema/results.schema.json`, parsed by `serde_json`, the
/// dev-only JSON oracle (ADR 0016 §5), so a results file is checked by a
/// parser independent of the writer's.
fn results_schema() -> serde_json::Value {
    let bytes = std::fs::read(conformance_dir().join("schema/results.schema.json")).unwrap();
    serde_json::from_slice(&bytes).expect("results.schema.json is JSON")
}

/// The JSON Schema keywords [`check_against`] implements. A schema node
/// with any other keyword fails [`results_schema_keywords`], so the
/// validator can never skip a rule the schema states.
const RESULTS_SCHEMA_KEYWORDS: &[&str] = &[
    "$schema",
    "title",
    "description",
    "$defs",
    "$ref",
    "type",
    "required",
    "additionalProperties",
    "properties",
    "items",
    "enum",
    "const",
    "minLength",
    "minItems",
    "uniqueItems",
    "pattern",
    "oneOf",
];

/// `$defs/id/pattern`: a path under `conformance/vectors/` (no leading `/`,
/// no `\`, no `#`) of a `.json` file, then `#0` (ADR 0045 §4).
const RESULT_ID_PATTERN: &str = "^[^#/\\\\][^#\\\\]*\\.json#0$";

/// `$defs/skipped/properties/reason/pattern`: `feature:` and the missing
/// feature names, comma-separated (ADR 0034 §3).
const SKIP_REASON_PATTERN: &str = "^feature:!?[a-z0-9-]+(,!?[a-z0-9-]+)*$";

/// [`RESULT_ID_PATTERN`], by hand (no regex crate, ADR 0016).
fn is_result_id(s: &str) -> bool {
    let Some(path) = s.strip_suffix("#0") else {
        return false;
    };
    let first_ok = path
        .chars()
        .next()
        .is_some_and(|c| !matches!(c, '#' | '/' | '\\'));
    first_ok
        && !path.contains(['#', '\\'])
        && path
            .strip_suffix(".json")
            .is_some_and(|stem| !stem.is_empty())
}

/// [`SKIP_REASON_PATTERN`], by hand: each name may carry a `!` (a
/// `features_absent` name the build enables, ADR 0056 §2).
fn is_skip_reason(s: &str) -> bool {
    s.strip_prefix("feature:").is_some_and(|names| {
        names.split(',').all(|name| {
            let name = name.strip_prefix('!').unwrap_or(name);
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
    })
}

/// The predicate of a `pattern` the results schema uses; `None` for any
/// other, which [`check_against`] refuses rather than ignores.
fn results_pattern(pattern: &str) -> Option<fn(&str) -> bool> {
    match pattern {
        RESULT_ID_PATTERN => Some(is_result_id),
        SKIP_REASON_PATTERN => Some(is_skip_reason),
        _ => None,
    }
}

/// Every keyword of every schema node in `schema` is one
/// [`RESULTS_SCHEMA_KEYWORDS`] names, and every `pattern` one
/// [`results_pattern`] knows. `enum` and `const` hold values, not schemas.
fn results_schema_keywords(schema: &serde_json::Value, pointer: &str) -> Result<(), String> {
    let node = schema
        .as_object()
        .ok_or_else(|| format!("{pointer}: a schema node must be an object"))?;
    for (keyword, value) in node {
        if !RESULTS_SCHEMA_KEYWORDS.contains(&keyword.as_str()) {
            return Err(format!("{pointer}: unsupported keyword `{keyword}`"));
        }
        let here = format!("{pointer}/{keyword}");
        match keyword.as_str() {
            "properties" | "$defs" => {
                for (name, sub) in value.as_object().ok_or(format!("{here}: not an object"))? {
                    results_schema_keywords(sub, &format!("{here}/{name}"))?;
                }
            }
            "items" => results_schema_keywords(value, &here)?,
            "oneOf" => {
                for (i, sub) in value
                    .as_array()
                    .ok_or(format!("{here}: not an array"))?
                    .iter()
                    .enumerate()
                {
                    results_schema_keywords(sub, &format!("{here}/{i}"))?;
                }
            }
            "additionalProperties" if value != &serde_json::Value::Bool(false) => {
                return Err(format!("{here}: only `false` is supported"));
            }
            "pattern" => {
                let pattern = value.as_str().ok_or(format!("{here}: not a string"))?;
                if results_pattern(pattern).is_none() {
                    return Err(format!("{here}: no hand-written check for {pattern:?}"));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// The JSON Schema type name of `value` (`integer` for a whole number).
fn json_type(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(n) if n.is_i64() || n.is_u64() => "integer",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// Validates `value` against the schema node `schema` of the schema
/// document `root` (JSON Schema 2020-12, restricted to
/// [`RESULTS_SCHEMA_KEYWORDS`]). The error names the JSON pointer of the
/// first violation.
fn check_against(
    root: &serde_json::Value,
    schema: &serde_json::Value,
    value: &serde_json::Value,
    pointer: &str,
) -> Result<(), String> {
    let at = |problem: String| Err(format!("{pointer}: {problem}"));
    if let Some(reference) = schema.get("$ref").and_then(serde_json::Value::as_str) {
        let name = reference
            .strip_prefix("#/$defs/")
            .ok_or(format!("{pointer}: unsupported $ref {reference}"))?;
        let target = root
            .get("$defs")
            .and_then(|defs| defs.get(name))
            .ok_or(format!("{pointer}: no $defs/{name}"))?;
        check_against(root, target, value, pointer)?;
    }
    if let Some(kind) = schema.get("type").and_then(serde_json::Value::as_str) {
        let actual = json_type(value);
        if actual != kind && !(kind == "number" && actual == "integer") {
            return at(format!("must be of type {kind}, is {actual}"));
        }
    }
    if let Some(allowed) = schema.get("enum").and_then(serde_json::Value::as_array)
        && !allowed.contains(value)
    {
        return at(format!(
            "must be one of {}",
            serde_json::Value::from(allowed.clone())
        ));
    }
    if let Some(constant) = schema.get("const")
        && value != constant
    {
        return at(format!("must be {constant}"));
    }
    if let (Some(min), Some(s)) = (
        schema.get("minLength").and_then(serde_json::Value::as_u64),
        value.as_str(),
    ) && (s.chars().count() as u64) < min
    {
        return at(format!("must have at least {min} character(s)"));
    }
    if let (Some(pattern), Some(s)) = (
        schema.get("pattern").and_then(serde_json::Value::as_str),
        value.as_str(),
    ) {
        let matches = results_pattern(pattern).ok_or(format!("{pointer}: pattern {pattern:?}"))?;
        if !matches(s) {
            return at(format!("{s:?} must match {pattern}"));
        }
    }
    if let Some(items) = value.as_array() {
        if let Some(min) = schema.get("minItems").and_then(serde_json::Value::as_u64)
            && (items.len() as u64) < min
        {
            return at(format!("must have at least {min} item(s)"));
        }
        if schema.get("uniqueItems") == Some(&serde_json::Value::Bool(true)) {
            for (i, item) in items.iter().enumerate() {
                if items[..i].contains(item) {
                    return at(format!("item {i} repeats an earlier one (uniqueItems)"));
                }
            }
        }
        if let Some(item_schema) = schema.get("items") {
            for (i, item) in items.iter().enumerate() {
                check_against(root, item_schema, item, &format!("{pointer}/{i}"))?;
            }
        }
    }
    if let Some(object) = value.as_object() {
        if let Some(required) = schema.get("required").and_then(serde_json::Value::as_array) {
            for name in required.iter().filter_map(serde_json::Value::as_str) {
                if !object.contains_key(name) {
                    return at(format!("missing required member `{name}`"));
                }
            }
        }
        let properties = schema
            .get("properties")
            .and_then(serde_json::Value::as_object);
        for (name, member) in object {
            match properties.and_then(|p| p.get(name)) {
                Some(member_schema) => {
                    check_against(root, member_schema, member, &format!("{pointer}/{name}"))?;
                }
                None if schema.get("additionalProperties")
                    == Some(&serde_json::Value::Bool(false)) =>
                {
                    return at(format!("unknown member `{name}`"));
                }
                None => {}
            }
        }
    }
    if let Some(branches) = schema.get("oneOf").and_then(serde_json::Value::as_array) {
        let errors: Vec<String> = branches
            .iter()
            .filter_map(|branch| check_against(root, branch, value, pointer).err())
            .collect();
        let matched = branches.len() - errors.len();
        if matched != 1 {
            return at(format!(
                "must match exactly one oneOf branch, matches {matched} ({})",
                errors.join("; ")
            ));
        }
    }
    Ok(())
}

/// Validates a results file's text against `results.schema.json`, parsing
/// it with `serde_json`.
fn check_results_text(text: &[u8]) -> Result<(), String> {
    let value: serde_json::Value =
        serde_json::from_slice(text).map_err(|e| format!("not JSON: {e}"))?;
    let schema = results_schema();
    check_against(&schema, &schema, &value, "")
}

/// The schema uses only what the validator implements, so no rule of it is
/// silently ignored; and the two hand-written patterns accept and refuse
/// what their regular expressions do.
#[test]
fn results_schema_uses_only_supported_keywords() {
    results_schema_keywords(&results_schema(), "").unwrap();
    for (id, ok) in [
        ("jws-rfc7515/a1.json#0", true),
        ("a.json#0", true),
        ("third_party/rfc7520/jws/4-1.json#0", true),
        ("a.json#1", false),
        ("a.json", false),
        (".json#0", false),
        ("/a.json#0", false),
        ("a\\b.json#0", false),
        ("a#b.json#0", false),
        ("a.jsonx#0", false),
        ("", false),
    ] {
        assert_eq!(is_result_id(id), ok, "{id:?}");
    }
    for (reason, ok) in [
        ("feature:deflate", true),
        ("feature:deflate,fixed-rng", true),
        ("feature:!deflate", true),
        ("feature:fixed-rng,!deflate", true),
        ("feature:!deflate,!fixed-rng", true),
        ("feature:!", false),
        ("feature:!!deflate", false),
        ("feature:deflate!", false),
        ("feature:", false),
        ("feature:deflate,", false),
        ("feature:Deflate", false),
        ("feature: deflate", false),
        ("deflate", false),
    ] {
        assert_eq!(is_skip_reason(reason), ok, "{reason:?}");
    }
    // An unknown keyword or pattern is refused, not ignored.
    let unknown: serde_json::Value =
        serde_json::from_str(r#"{"type":"string","maxLength":3}"#).unwrap();
    assert!(results_schema_keywords(&unknown, "").is_err());
    let pattern: serde_json::Value =
        serde_json::from_str(r#"{"type":"string","pattern":"^a$"}"#).unwrap();
    assert!(results_schema_keywords(&pattern, "").is_err());
}

/// The schema's `features` enum is the runner's [`FEATURES`] table, in
/// schema order, and its `runner` enum names the reference run first
/// (ADR 0034 §2, §4).
#[test]
fn results_schema_agrees_with_the_runner() {
    let schema = results_schema();
    let features: Vec<&str> = schema["properties"]["features"]["items"]["enum"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(features, feature_names());
    let runners = schema["properties"]["runner"]["enum"].as_array().unwrap();
    assert_eq!(runners.first().and_then(|r| r.as_str()), Some(RUST_CORE));
}

/// The runner name of this file's results (ADR 0034 §2).
const RUST_CORE: &str = "rust-core";

/// A minimal results file with one result of each status.
const RESULTS_EXAMPLE: &str = r#"{"runner":"node","polyjose":"0.1.0","features":[],"error_codes":["InvalidBase64","InvalidKey"],"results":[{"id":"a/b.json#0","source":"RFC 4648 §10","op":"b64url.decode","status":"pass","actual":{"ok":false,"error":"InvalidBase64"}},{"id":"a/c.json#0","op":"jwe.encrypt","status":"skipped","reason":"feature:fixed-rng"},{"id":"a/d.json#0","status":"fail","reason":"not JSON"},{"id":"a/e.json#0","op":"jws.verify","status":"fail","actual":{"ok":true},"reason":"expected error InvalidKey"}]}"#;

/// The validator accepts a valid results file and refuses each way one can
/// break the schema (so the check of the reference file is not vacuous).
#[test]
fn results_validator_refuses_invalid_files() {
    check_results_text(RESULTS_EXAMPLE.as_bytes()).unwrap();
    check_results_text(br#"{"runner":"rust-core","polyjose":"0.1.0","features":["deflate","fixed-rng"],"error_codes":["X"],"results":[]}"#).unwrap();
    for (old, new, problem) in [
        (
            r#""runner":"node","#,
            "",
            "missing required member `runner`",
        ),
        (r#""runner":"node""#, r#""runner":"node-x86_64""#, "/runner"),
        (r#""features":[]"#, r#""features":["zlib"]"#, "/features/0"),
        (
            r#""features":[]"#,
            r#""features":["deflate","deflate"]"#,
            "uniqueItems",
        ),
        (
            r#""error_codes":["InvalidBase64","InvalidKey"]"#,
            r#""error_codes":[]"#,
            "at least 1 item",
        ),
        (r#""InvalidKey"]"#, r#""InvalidBase64"]"#, "uniqueItems"),
        (r#""polyjose":"0.1.0""#, r#""polyjose":"""#, "/polyjose"),
        (
            r#""results":["#,
            r#""extra":1,"results":["#,
            "unknown member `extra`",
        ),
        (r#""a/b.json#0""#, r#""a/b.json""#, "/results/0"),
        (r#""a/b.json#0""#, r#""a/b.json#1""#, "/results/0"),
        (r#""status":"pass""#, r#""status":"passed""#, "/results/0"),
        (
            r#","actual":{"ok":false,"error":"InvalidBase64"}}"#,
            "}",
            "/results/0",
        ),
        (
            r#""actual":{"ok":false,"error":"InvalidBase64"}"#,
            r#""actual":{"ok":false}"#,
            "/results/0",
        ),
        (
            r#""actual":{"ok":false,"error":"InvalidBase64"}"#,
            r#""actual":{"ok":true,"error":"InvalidBase64"}"#,
            "/results/0",
        ),
        (
            r#""actual":{"ok":false,"error":"InvalidBase64"}"#,
            r#""actual":{"ok":false,"error":"InvalidBase64"},"reason":"x""#,
            "/results/0",
        ),
        (
            r#""reason":"feature:fixed-rng""#,
            r#""reason":"fixed-rng""#,
            "/results/1",
        ),
        (
            r#""reason":"feature:fixed-rng""#,
            r#""reason":"feature:fixed-rng","actual":{"ok":true}"#,
            "/results/1",
        ),
        (r#""op":"jwe.encrypt","#, "", "/results/1"),
        (
            r#""status":"fail","reason":"not JSON""#,
            r#""status":"fail""#,
            "/results/2",
        ),
    ] {
        assert_eq!(RESULTS_EXAMPLE.matches(old).count(), 1, "{old}");
        let broken = RESULTS_EXAMPLE.replacen(old, new, 1);
        let err = check_results_text(broken.as_bytes()).expect_err(&broken);
        assert!(err.contains(problem), "{old} -> {new}: {err}");
    }
}

/// `run_dir` records one result per vector file (ADR 0034 §2): the id is
/// the path under the directory plus `#0` (ADR 0045 §4); a vector that ran
/// records its outcome as `actual`, passing or not; a skip names the
/// missing features in the vector's order; a broken file fails with a
/// reason, and with `op` when it names one.
#[test]
fn run_dir_records_one_result_per_vector() {
    let dir = TempDir::new("results");
    let encode = vector(
        "b64url.encode",
        r#"{"bytes_hex":"66"}"#,
        r#"{"ok":true,"b64u":"Zg"}"#,
    );
    dir.write("a/ok.json", &encode);
    dir.write(
        "a/negative.json",
        &vector(
            "b64url.decode",
            r#"{"b64u":"Zg="}"#,
            r#"{"ok":false,"error":"InvalidBase64"}"#,
        ),
    );
    dir.write(
        "b/wrong.json",
        &vector(
            "b64url.decode",
            r#"{"b64u":"Zg="}"#,
            r#"{"ok":false,"error":"InvalidKey"}"#,
        ),
    );
    dir.write(
        "b/needs.json",
        &with_features(
            &vector(
                "jwe.decrypt",
                &jwe_decrypt_input(JWE_A3, JWE_A3_KEY, ""),
                r#"{"ok":false,"error":"InvalidKey"}"#,
            ),
            r#"["fixed-rng","deflate"]"#,
        ),
    );
    dir.write("c/invalid.json", &encode.replace(r#""66""#, r#""6""#));
    dir.write(
        "c/unknown.json",
        &vector("jws.frobnicate", "{}", r#"{"ok":true}"#),
    );
    dir.write("c/broken.json", "{");
    dir.write("c/LICENSE", "not a vector");
    let report = run_dir_with(&dir.0, &[]);
    assert!(report.complete, "{report:?}");
    let got: Vec<String> = report.results.iter().map(Object::to_json).collect();
    let expected = [
        format!(
            r#"{{"id":"a/negative.json#0","source":"{SOURCE}","op":"b64url.decode","status":"pass","actual":{{"ok":false,"error":"InvalidBase64"}}}}"#
        ),
        format!(
            r#"{{"id":"a/ok.json#0","source":"{SOURCE}","op":"b64url.encode","status":"pass","actual":{{"ok":true}}}}"#
        ),
        format!(
            r#"{{"id":"b/needs.json#0","source":"{SOURCE}","op":"jwe.decrypt","status":"skipped","reason":"feature:fixed-rng,deflate"}}"#
        ),
    ];
    assert_eq!(got.len(), 7, "{got:#?}");
    assert_eq!(got[..3], expected, "{got:#?}");
    let fails: Vec<&Object> = report.results[3..].iter().collect();
    let ids: Vec<&str> = fails
        .iter()
        .map(|r| r.get("id").and_then(Value::as_str).unwrap())
        .collect();
    assert_eq!(
        ids,
        [
            "b/wrong.json#0",
            "c/broken.json#0",
            "c/invalid.json#0",
            "c/unknown.json#0"
        ]
    );
    for result in &fails {
        assert_eq!(result.get("status").and_then(Value::as_str), Some("fail"));
        let reason = result.get("reason").and_then(Value::as_str).unwrap();
        assert!(report.failures.iter().any(|f| f == reason), "{reason}");
    }
    // The wrong expectation ran: its outcome is recorded.
    assert_eq!(
        fails[0].get("actual").map(Value::to_json).as_deref(),
        Some(r#"{"ok":false,"error":"InvalidBase64"}"#)
    );
    // The unparseable file names no op; the others name theirs. None of the
    // three ran, so none has an outcome.
    let ops: Vec<Option<&str>> = fails[1..]
        .iter()
        .map(|r| r.get("op").and_then(Value::as_str))
        .collect();
    assert_eq!(ops, [None, Some("b64url.encode"), Some("jws.frobnicate")]);
    assert!(fails[1..].iter().all(|r| !r.contains("actual")));
    // Each entry is schema-valid.
    let document = format!(
        r#"{{"runner":"rust-core","polyjose":"0.1.0","features":[],"error_codes":["X"],"results":[{}]}}"#,
        got.join(",")
    );
    check_results_text(document.as_bytes()).unwrap();

    // A walk that finds nothing is incomplete, so no results file is
    // written from it.
    let empty = TempDir::new("results-empty");
    let report = run_dir_with(&empty.0, &[]);
    assert!(!report.complete && report.results.is_empty(), "{report:?}");
}

/// The writer names the file by the build's features (ADR 0034 §4: only
/// the default build is the `rust-core` reference), writes a file that
/// validates against `results.schema.json`, one result per line, and
/// removes an earlier file instead of writing when the walk was incomplete.
#[test]
fn results_writer_writes_the_reference_file() {
    assert_eq!(results_file_name(&[]), "rust-core.json");
    assert_eq!(
        results_file_name(&["fixed-rng"]),
        "rust-core-fixed-rng.json"
    );
    assert_eq!(
        results_file_name(&["deflate", "fixed-rng"]),
        "rust-core-deflate-fixed-rng.json"
    );

    let vectors = TempDir::new("writer-vectors");
    vectors.write(
        "x/ok.json",
        &vector(
            "b64url.encode",
            r#"{"bytes_hex":"66"}"#,
            r#"{"ok":true,"b64u":"Zg"}"#,
        ),
    );
    vectors.write(
        "x/needs.json",
        &with_features(
            &vector(
                "jwe.decrypt",
                &jwe_decrypt_input(JWE_A3, JWE_A3_KEY, ""),
                r#"{"ok":false,"error":"InvalidKey"}"#,
            ),
            r#"["deflate"]"#,
        ),
    );
    let out = TempDir::new("writer-out");
    let target = out.0.join("conformance");
    let report = run_dir_with(&vectors.0, &[]);
    let path = write_results(&target, "rust-core.json", &[], &report)
        .unwrap()
        .expect("a complete report is written");
    let text = std::fs::read_to_string(&path).unwrap();
    check_results_text(text.as_bytes()).unwrap();
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(value["runner"], "rust-core");
    assert_eq!(value["polyjose"], env!("CARGO_PKG_VERSION"));
    assert_eq!(value["features"], serde_json::json!([]));
    assert_eq!(value["error_codes"], serde_json::json!(Error::CODES));
    assert_eq!(value["results"].as_array().unwrap().len(), 2);
    // Files are sorted by path, so x/needs.json comes first.
    assert_eq!(value["results"][0]["reason"], "feature:deflate");
    assert_eq!(value["results"][1]["id"], "x/ok.json#0");
    assert_eq!(
        text.lines().filter(|l| l.contains(r#""id":"#)).count(),
        2,
        "one result per line: {text}"
    );
    assert!(
        std::fs::read_dir(&target).unwrap().count() == 1,
        "no temporary file left"
    );

    // With features, the features are recorded.
    let path = write_results(&target, "rust-core-deflate.json", &["deflate"], &report)
        .unwrap()
        .unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    check_results_text(text.as_bytes()).unwrap();
    assert!(text.contains(r#""features": ["deflate"]"#), "{text}");

    // An incomplete walk removes the earlier file and writes nothing.
    let incomplete = run_dir_with(&out.0.join("missing"), &[]);
    assert_eq!(
        write_results(&target, "rust-core.json", &[], &incomplete).unwrap(),
        None
    );
    assert!(!target.join("rust-core.json").exists());
    assert_eq!(
        write_results(&target, "rust-core.json", &[], &incomplete).unwrap(),
        None,
        "nothing to remove is fine"
    );
}
