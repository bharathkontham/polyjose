//! 0015 T05: `JwkSet::select` and `JwkSet::matching` against a test-side
//! oracle written from the text of ADR 0054 §2, through the public API only
//! (ADR 0008 layer 2).
//!
//! **The oracle is independent on purpose.** [`oracle`] restates the five
//! checks of ADR 0054 §2 over the *generated description* of each member
//! ([`MemberSpec`]), never over the imported [`Jwk`] and never through a
//! crate helper. Its family table ([`serves`]), its `alg` mode table
//! ([`alg_mode`]) and its `use` operation table ([`use_ops`]) are
//! restatements of RFC 7518 §3.1 / §4.1, RFC 8037 §3, RFC 8812 §3 and
//! RFC 7517 §4.2–§4.3, written for this file. A mistake shared with the
//! core's tables would therefore show up as a disagreement, not be hidden
//! by it.
//!
//! Properties (each ≤ 1,000 cases, pipeline rule 8, ADR 0009):
//!
//! 1. **Soundness:** every `(i, k)` from `matching` satisfies the oracle,
//!    and `k` is `keys()[i]`.
//! 2. **Completeness:** every member the oracle accepts is yielded, in
//!    index order (ADR 0054 §4).
//! 3. **`select` agrees with `matching`:** 0 → `NoMatchingKey`, 1 → that
//!    `(i, k)`, ≥ 2 → `MultipleMatchingKeys` (ADR 0054 §4).
//! 4. **Family safety** (ADR 0054 §2.1, §2.2, §7; RFC 8725 §3.1), checked on
//!    the *imported* key's material and `alg`.
//! 5. **Monotonicity:** adding a criterion never adds a match, and removing
//!    a set member never adds a match for the remaining indexes.
//!
//! **Generators.** Keys come only from committed fixtures (RFC 7517 App. A,
//! RFC 7515 App. A, RFC 7520, RFC 7468, RFC 8037 App. A, and
//! `conformance/tools/jwt-oracle/keys.json`); polyjose generates none.
//! Members get an optional `kid` from {`a`, `b`, `A`}, an optional `alg`
//! the key can serve, an optional `use` and an optional `key_ops` subset
//! consistent with that `use`. Low-weight arms (0015 F01, review
//! SHOULD-FIX 1) also give a member an unregistered `alg`
//! ([`UNREGISTERED_ALG`]), an unregistered `use` ([`UNREGISTERED_USE`]) or
//! an extra unregistered `key_ops` entry ([`UNREGISTERED_OP`]), so the
//! fail-closed paths of ADR 0054 §2.2–§2.4 are reached. Each is kept on
//! import, none is skipped
//! ([`unregistered_member_values_import_as_unknown`]). Selectors combine an optional `alg` (every
//! implemented JWS and JWE key management algorithm), `kid` and `key_use`.
//! **No selector carries a `key_op`:** how `key_op` combines with `alg` is
//! an open owner question (feature 0015 backlog.md), so it is not
//! generated here. No assertion depends on wall-clock timing.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

use std::collections::HashSet;
use std::sync::OnceLock;

use polyjose::Error;
use polyjose::json::{Object, Value, parse};
use polyjose::jwa::{KeyMgmtAlg, SigningAlg};
use polyjose::jwk::{
    EcCurve, Jwk, JwkSelector, JwkSet, KeyAlg, KeyMaterial, KeyOp, KeyType, KeyUse, OkpCurve,
};
use proptest::collection::vec;
use proptest::option;
use proptest::prelude::*;
use proptest::sample::{Index, select, subsequence};
use proptest::strategy::ValueTree;
use proptest::test_runner::TestRunner;

// ---------------------------------------------------------------------------
// Fixed keys (committed fixtures only)
// ---------------------------------------------------------------------------

/// `conformance/tools/jwt-oracle/keys.json`: fixed test keys, each with its
/// published source.
const JWT_ORACLE_KEYS: &str = include_str!("../../../conformance/tools/jwt-oracle/keys.json");
/// RFC 7517 Appendix A.1, the P-256 public key (`kid` "1"; the fixture
/// keeps only the key members).
const RFC7517_A1_EC: &str = include_str!("data/keys/rfc/rfc7517-a1-ec-p256-spki.jwk.json");
/// RFC 7517 Appendix A.1, the RSA-2048 public key (`kid` "2011-04-29").
const RFC7517_A1_RSA: &str = include_str!("data/keys/rfc/rfc7517-a1-rsa-spki.jwk.json");
/// RFC 7468 Figure 12, the secp256k1 private key, as a JWK.
const RFC7468_SECP256K1: &str =
    include_str!("data/keys/rfc/rfc7468-fig12-secp256k1-pkcs8.jwk.json");
/// RFC 8037 Appendix A.6 (RFC 7748 §6.1), the X25519 private key.
const RFC8037_A6_X25519: &str = include_str!("data/keys/rfc/rfc8037-a6-x25519-pkcs8.jwk.json");

/// The key family a member belongs to: its `kty`, and its `crv` where it
/// has one (RFC 7518 §6, RFC 8037 §2, RFC 8812 §3.1). A test-side type,
/// not the crate's `KeyMaterial`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    Oct,
    Rsa,
    P256,
    P384,
    P521,
    Secp256k1,
    Ed25519,
    X25519,
}

/// One fixed key: its family and its key members only (no `kid`, `use`,
/// `alg` or `key_ops`).
struct PoolKey {
    label: &'static str,
    family: Family,
    members: Object,
}

/// The key members of a fixture JWK, with every optional member removed so
/// that the generator alone decides them.
fn key_members(json: &str) -> Object {
    let mut object = parse(json.as_bytes()).unwrap().into_object().unwrap();
    for optional in ["kid", "use", "alg", "key_ops"] {
        object.remove(optional);
    }
    object
}

/// The `jwk` object of entry `name` of `keys.json`.
fn oracle_key(name: &str) -> Object {
    let file = parse(JWT_ORACLE_KEYS.as_bytes()).unwrap();
    let jwk = file
        .get("keys")
        .and_then(|keys| keys.get(name))
        .and_then(|entry| entry.get("jwk"))
        .unwrap_or_else(|| panic!("keys.json has no {name}"));
    key_members(&jwk.to_json())
}

/// The fixed key pool: oct of 16, 32 and 64 octets, P-256 (public and
/// private), P-384, P-521, secp256k1, Ed25519, X25519 and RSA-2048 public.
fn pool() -> &'static [PoolKey] {
    static POOL: OnceLock<Vec<PoolKey>> = OnceLock::new();
    POOL.get_or_init(|| {
        let key = |label, family, members| PoolKey {
            label,
            family,
            members,
        };
        vec![
            key("oct-16", Family::Oct, oracle_key("oct-16")),
            key("oct-32", Family::Oct, oracle_key("oct-32")),
            // RFC 7515 App. A.1.1.
            key("oct-64", Family::Oct, oracle_key("oct-64")),
            key(
                "P-256 (RFC 7517 A.1)",
                Family::P256,
                key_members(RFC7517_A1_EC),
            ),
            // RFC 7515 App. A.3.1.
            key("P-256 private", Family::P256, oracle_key("p256")),
            // RFC 7520 §5.4.1.
            key("P-384 private", Family::P384, oracle_key("p384")),
            // RFC 7515 App. A.4.1.
            key("P-521 private", Family::P521, oracle_key("p521")),
            key(
                "secp256k1 private",
                Family::Secp256k1,
                key_members(RFC7468_SECP256K1),
            ),
            // RFC 8037 App. A.1.
            key("Ed25519 private", Family::Ed25519, oracle_key("ed25519")),
            key(
                "X25519 private",
                Family::X25519,
                key_members(RFC8037_A6_X25519),
            ),
            key(
                "RSA-2048 (RFC 7517 A.1)",
                Family::Rsa,
                key_members(RFC7517_A1_RSA),
            ),
        ]
    })
}

// ---------------------------------------------------------------------------
// The test-side restatement of the algorithm tables
// ---------------------------------------------------------------------------

/// Every JWS algorithm polyjose implements except `none`
/// (RFC 7518 §3.1, RFC 8037 §3.1, RFC 8812 §3.2, RFC 9864 §2.2), restated.
/// [`alg_tables_cover_every_implemented_algorithm`] pins it to
/// `SigningAlg::KNOWN`.
const JWS_ALGS: &[&str] = &[
    "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "ES256K",
    "PS256", "PS384", "PS512", "EdDSA", "Ed25519",
];

/// Every JWE key management algorithm polyjose implements (RFC 7518 §4.1,
/// without `RSA1_5` and `RSA-OAEP`, ADRs 0021 and 0022), restated.
const KEY_MGMT_ALGS: &[&str] = &[
    "RSA-OAEP-256",
    "A128KW",
    "A192KW",
    "A256KW",
    "dir",
    "ECDH-ES",
    "ECDH-ES+A128KW",
    "ECDH-ES+A192KW",
    "ECDH-ES+A256KW",
    "A128GCMKW",
    "A192GCMKW",
    "A256GCMKW",
    "PBES2-HS256+A128KW",
    "PBES2-HS384+A192KW",
    "PBES2-HS512+A256KW",
];

/// The JWE content encryption algorithms (RFC 7518 §5.1). An `oct` JWK may
/// name one as its `alg` for `dir` (RFC 7518 §4.5, RFC 7520 §5.6.1).
const CONTENT_ENC_ALGS: &[&str] = &[
    "A128CBC-HS256",
    "A192CBC-HS384",
    "A256CBC-HS512",
    "A128GCM",
    "A192GCM",
    "A256GCM",
];

/// The selector algorithms that take a symmetric key, as ADR 0054 §2.1
/// lists them: HS*, A*KW, A*GCMKW, `dir` and PBES2. Every other selector
/// `alg` takes an asymmetric key. Kept apart from [`serves`] so the family
/// safety property checks the ADR's partition directly.
const SYMMETRIC_ALGS: &[&str] = &[
    "HS256",
    "HS384",
    "HS512",
    "A128KW",
    "A192KW",
    "A256KW",
    "A128GCMKW",
    "A192GCMKW",
    "A256GCMKW",
    "dir",
    "PBES2-HS256+A128KW",
    "PBES2-HS384+A192KW",
    "PBES2-HS512+A256KW",
];

/// Whether a key of `family` serves the JWS or JWE key management `alg`
/// (ADR 0054 §2.1). A test-side restatement of the registries, written for
/// this file and not read from the crate:
///
/// - HMAC (RFC 7518 §3.2), AES key wrap (§4.4), `dir` (§4.5), AES-GCM key
///   wrap (§4.7) and PBES2 (§4.8) take a symmetric `oct` key (§6.4);
/// - RSASSA-PKCS1-v1_5 (§3.3), RSASSA-PSS (§3.5) and RSAES-OAEP (§4.3)
///   take an `RSA` key;
/// - ES256 / ES384 / ES512 take P-256 / P-384 / P-521 (§3.4), and ES256K
///   takes secp256k1 (RFC 8812 §3.2);
/// - EdDSA (RFC 8037 §3.1) and Ed25519 (RFC 9864 §2.2) take `OKP` Ed25519;
/// - ECDH-ES and ECDH-ES+A*KW take P-256, P-384, P-521 (RFC 7518 §4.6) or
///   `OKP` X25519 (RFC 8037 §3.2). Not secp256k1 and not Ed25519
///   (ADR 0054 §2.1).
fn serves(family: Family, alg: &str) -> bool {
    match alg {
        "HS256" | "HS384" | "HS512" | "A128KW" | "A192KW" | "A256KW" | "dir" | "A128GCMKW"
        | "A192GCMKW" | "A256GCMKW" | "PBES2-HS256+A128KW" | "PBES2-HS384+A192KW"
        | "PBES2-HS512+A256KW" => family == Family::Oct,
        "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" | "RSA-OAEP-256" => {
            family == Family::Rsa
        }
        "ES256" => family == Family::P256,
        "ES384" => family == Family::P384,
        "ES512" => family == Family::P521,
        "ES256K" => family == Family::Secp256k1,
        "EdDSA" | "Ed25519" => family == Family::Ed25519,
        "ECDH-ES" | "ECDH-ES+A128KW" | "ECDH-ES+A192KW" | "ECDH-ES+A256KW" => matches!(
            family,
            Family::P256 | Family::P384 | Family::P521 | Family::X25519
        ),
        other => panic!("not a selector alg: {other}"),
    }
}

/// The JWE key management mode of an `alg` (RFC 7516 §2), as ADR 0054
/// §2.4 groups them for `key_ops`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Mode {
    /// A JWS algorithm.
    Jws,
    /// Key encryption (`RSA-OAEP-256`) or key wrapping (A*KW, A*GCMKW,
    /// PBES2; RFC 7518 §4.4, §4.7, §4.8).
    KeyEncryptionOrWrapping,
    /// Direct encryption (`dir`, RFC 7518 §4.5).
    Direct,
    /// Key agreement: ECDH-ES (direct key agreement) and ECDH-ES+A*KW (key
    /// agreement with key wrapping), RFC 7518 §4.6. In both modes the
    /// recipient's JWK only derives a key (RFC 7518 §4.6.2); for
    /// ECDH-ES+A*KW the wrapping key is the derived key, not the JWK.
    KeyAgreement,
}

/// The mode of a selector `alg` (RFC 7516 §2, RFC 7518 §3.1 / §4.1).
fn alg_mode(alg: &str) -> Mode {
    if JWS_ALGS.contains(&alg) {
        return Mode::Jws;
    }
    match alg {
        "dir" => Mode::Direct,
        "ECDH-ES" | "ECDH-ES+A128KW" | "ECDH-ES+A192KW" | "ECDH-ES+A256KW" => Mode::KeyAgreement,
        _ if KEY_MGMT_ALGS.contains(&alg) => Mode::KeyEncryptionOrWrapping,
        other => panic!("not a selector alg: {other}"),
    }
}

/// The operations an `alg` performs in either direction (ADR 0054 §2.4).
fn mode_ops(mode: Mode) -> &'static [&'static str] {
    match mode {
        Mode::Jws => &["sign", "verify"],
        Mode::KeyEncryptionOrWrapping => &["wrapKey", "unwrapKey"],
        Mode::Direct => &["encrypt", "decrypt"],
        Mode::KeyAgreement => &["deriveKey"],
    }
}

/// The `use` an `alg` implies: JWS → `sig`, JWE key management → `enc`
/// (ADR 0054 §2.3).
fn alg_use(alg: &str) -> &'static str {
    if alg_mode(alg) == Mode::Jws {
        "sig"
    } else {
        "enc"
    }
}

/// The registered `key_ops` values of a `use` (RFC 7517 §4.2, §4.3): `sig`
/// for signatures and MACs; `enc` for encryption, key wrapping ("a kind of
/// encryption") and key agreement.
fn use_ops(key_use: &str) -> &'static [&'static str] {
    match key_use {
        "sig" => &["sign", "verify"],
        "enc" => &[
            "encrypt",
            "decrypt",
            "wrapKey",
            "unwrapKey",
            "deriveKey",
            "deriveBits",
        ],
        other => panic!("not a use: {other}"),
    }
}

/// A member `alg` in no registry polyjose knows. RFC 7517 §4.4 lets a JWK
/// carry any `alg` ("collision-resistant name"); `Jwk::from_object` keeps
/// one it does not know as `KeyAlg::Unknown` rather than refusing the key
/// (only `RSA1_5` and `RSA-OAEP` are refused, ADRs 0021, 0022), so the
/// member is in the set and selection must refuse it (ADR 0054 §2.2).
const UNREGISTERED_ALG: &str = "x-unregistered";

/// A member `use` other than `sig` and `enc`. RFC 7517 §4.2: "Other values
/// MAY be used"; it is kept as `KeyUse::Unknown` and never conflicts with
/// `key_ops` on import (RFC 7517 §4.3 gives it no meaning to compare).
const UNREGISTERED_USE: &str = "x-other";

/// A `key_ops` entry outside the RFC 7517 §4.3 registry. RFC 7517 §4.3:
/// "Other values MAY be used"; it is kept as `KeyOp::Unknown` and never
/// conflicts with `use` on import.
const UNREGISTERED_OP: &str = "x-op";

/// The registered `use` values (RFC 7517 §4.2).
const REGISTERED_USES: &[&str] = &["sig", "enc"];

/// The registered `key_ops` values (RFC 7517 §4.3).
const REGISTERED_OPS: &[&str] = &[
    "sign",
    "verify",
    "encrypt",
    "decrypt",
    "wrapKey",
    "unwrapKey",
    "deriveKey",
    "deriveBits",
];

/// Whether a member `alg` names a JWS, JWE key management or content
/// encryption algorithm in this file's restated lists (RFC 7518 §3.1,
/// §4.1, §5.1; RFC 8037 §3.1; RFC 8812 §3.2; RFC 9864 §2.2). Anything else,
/// such as [`UNREGISTERED_ALG`], is unregistered for ADR 0054 §2.2.
fn is_registered_alg(alg: &str) -> bool {
    JWS_ALGS.contains(&alg) || KEY_MGMT_ALGS.contains(&alg) || CONTENT_ENC_ALGS.contains(&alg)
}

/// The `alg` values a member of `family` may carry (RFC 7517 §4.4): every
/// JWS and JWE key management `alg` it serves, plus, for `oct`, the content
/// encryption algorithms (`dir` keys, RFC 7518 §4.5).
fn member_algs(family: Family) -> Vec<&'static str> {
    let mut algs: Vec<&'static str> = JWS_ALGS
        .iter()
        .chain(KEY_MGMT_ALGS)
        .copied()
        .filter(|alg| serves(family, alg))
        .collect();
    if family == Family::Oct {
        algs.extend_from_slice(CONTENT_ENC_ALGS);
    }
    algs
}

// ---------------------------------------------------------------------------
// Members, sets and selectors
// ---------------------------------------------------------------------------

/// The `kid` alphabet of members and selectors. `a` and `A` differ only in
/// case, which RFC 7517 §4.5 makes significant.
const KIDS: &[&str] = &["a", "b", "A"];

/// One generated set member: a pool key plus its optional members.
#[derive(Clone, Debug)]
struct MemberSpec {
    key: usize,
    kid: Option<&'static str>,
    alg: Option<&'static str>,
    key_use: Option<&'static str>,
    key_ops: Option<Vec<&'static str>>,
}

impl MemberSpec {
    fn family(&self) -> Family {
        pool()[self.key].family
    }

    fn to_object(&self) -> Object {
        let mut object = pool()[self.key].members.clone();
        if let Some(kid) = self.kid {
            object.insert("kid", kid);
        }
        if let Some(alg) = self.alg {
            object.insert("alg", alg);
        }
        if let Some(key_use) = self.key_use {
            object.insert("use", key_use);
        }
        if let Some(ops) = &self.key_ops {
            let ops: Vec<Value> = ops.iter().map(|op| Value::from(*op)).collect();
            object.insert("key_ops", ops);
        }
        object
    }
}

/// A member: a pool key, an optional `kid`, an optional `alg` it serves, an
/// optional `use`, and optional `key_ops` drawn from the operations of one
/// `use` (the member's own `use` if it is registered), so that `use` and
/// `key_ops` are consistent (RFC 7517 §4.3).
///
/// Low-weight arms (about one member in ten each) instead give the member
/// [`UNREGISTERED_ALG`] as its `alg`, [`UNREGISTERED_USE`] as its `use`, or
/// append [`UNREGISTERED_OP`] to its `key_ops`. None makes the member
/// invalid: RFC 7517 §4.2–§4.4 allow other values, and an unregistered
/// `use` or operation has no meaning to conflict with (RFC 7517 §4.3), so
/// every generated member still imports (ADR 0041 §2 skips only invalid
/// members; [`every_generated_member_imports`]).
fn member() -> impl Strategy<Value = MemberSpec> {
    (0..pool().len()).prop_flat_map(|key| {
        let algs = member_algs(pool()[key].family);
        (
            Just(key),
            option::of(select(KIDS)),
            prop_oneof![
                9 => option::of(select(algs)),
                1 => Just(Some(UNREGISTERED_ALG)),
            ],
            prop_oneof![
                9 => option::of(select(&["sig", "enc"][..])),
                1 => Just(Some(UNREGISTERED_USE)),
            ],
            select(&["sig", "enc"][..]),
        )
            .prop_flat_map(|(key, kid, alg, key_use, ops_use)| {
                // An unregistered `use` constrains no operation (RFC 7517
                // §4.3), so its `key_ops` come from either registered use.
                let ops = use_ops(
                    key_use
                        .filter(|u| *u != UNREGISTERED_USE)
                        .unwrap_or(ops_use),
                );
                (
                    Just(key),
                    Just(kid),
                    Just(alg),
                    Just(key_use),
                    option::of((
                        subsequence(ops, 0..=ops.len()),
                        proptest::bool::weighted(0.1),
                    )),
                )
            })
            .prop_map(|(key, kid, alg, key_use, key_ops)| MemberSpec {
                key,
                kid,
                alg,
                key_use,
                key_ops: key_ops.map(|(mut ops, extra)| {
                    if extra {
                        ops.push(UNREGISTERED_OP);
                    }
                    ops
                }),
            })
    })
}

/// A set of 0–8 members.
fn members() -> impl Strategy<Value = Vec<MemberSpec>> {
    vec(member(), 0..=8)
}

/// The JWK Set JSON of `members`, in order (RFC 7517 §5).
fn set_json(members: &[MemberSpec]) -> String {
    let keys: Vec<Value> = members.iter().map(|m| Value::from(m.to_object())).collect();
    let mut set = Object::new();
    set.insert("keys", keys);
    set.to_json()
}

/// Imports `members` with `JwkSet::from_json`.
fn import(members: &[MemberSpec]) -> JwkSet {
    JwkSet::from_json(set_json(members).as_bytes()).unwrap()
}

/// A generated selector. `key_op` is deliberately absent (module doc).
#[derive(Clone, Copy, Debug, Default)]
struct Sel {
    alg: Option<&'static str>,
    kid: Option<&'static str>,
    key_use: Option<&'static str>,
}

impl Sel {
    /// The selector, built through the public setters (ADR 0054 §1).
    fn build(&self) -> JwkSelector {
        let mut selector = JwkSelector::new();
        if let Some(alg) = self.alg {
            selector = selector.alg(KeyAlg::from(alg)).unwrap();
        }
        if let Some(kid) = self.kid {
            selector = selector.kid(kid);
        }
        if let Some(key_use) = self.key_use {
            selector = selector.key_use(KeyUse::from(key_use)).unwrap();
        }
        selector
    }
}

/// Every selector `alg`: each implemented JWS and JWE key management
/// algorithm.
fn selector_algs() -> Vec<&'static str> {
    JWS_ALGS.iter().chain(KEY_MGMT_ALGS).copied().collect()
}

fn selector_alg() -> impl Strategy<Value = &'static str> {
    select(selector_algs())
}

/// A selector: optional `alg`, `kid` and `key_use`.
fn selector() -> impl Strategy<Value = Sel> {
    (
        option::of(selector_alg()),
        option::of(select(KIDS)),
        option::of(select(&["sig", "enc"][..])),
    )
        .prop_map(|(alg, kid, key_use)| Sel { alg, kid, key_use })
}

// ---------------------------------------------------------------------------
// The oracle: ADR 0054 §2, restated from its text
// ---------------------------------------------------------------------------

/// The ADR 0054 §2 check that rejected a member.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Check {
    /// §2.1: the member's `kty`/`crv` does not serve the selector `alg`.
    Family,
    /// §2.2: the member's `alg` is present and is not the selector `alg`
    /// (nor, for `dir`, a content encryption algorithm).
    JwkAlg,
    /// §2.3: the selector's parts disagree on the use, or the member's
    /// `use` is present and is not the effective use.
    Purpose,
    /// §2.4: the member's `key_ops` holds none of the required operations.
    KeyOps,
    /// §2.5 (§1.2): the member's `kid` is absent or not exactly the
    /// selector's.
    Kid,
}

/// Whether `member` matches `sel`, per ADR 0054 §2: all five checks hold,
/// in order, and an absent selector part skips its check. `Err` names the
/// first check that fails.
fn oracle(member: &MemberSpec, sel: &Sel) -> Result<(), Check> {
    // §2.1 Family: with an `alg`, the member's kty/crv must serve it.
    if let Some(alg) = sel.alg
        && !serves(member.family(), alg)
    {
        return Err(Check::Family);
    }

    // §2.2 JWK `alg`: absent or exactly equal (RFC 7517 §4.4,
    // RFC 8725 §3.1); for `dir`, a content encryption `alg` also matches.
    if let (Some(alg), Some(member_alg)) = (sel.alg, member.alg) {
        // An unregistered member `alg` is present, can never be "exactly
        // equal" to a selector `alg` (§1.1 admits only implemented ones),
        // and is not a content encryption algorithm, so the `dir`
        // exception cannot apply: it fails §2.2 whenever the selector has
        // an `alg`.
        if !is_registered_alg(member_alg) {
            return Err(Check::JwkAlg);
        }
        let dir_exception = alg == "dir" && CONTENT_ENC_ALGS.contains(&member_alg);
        if member_alg != alg && !dir_exception {
            return Err(Check::JwkAlg);
        }
    }

    // §2.3 Purpose: the effective use U is `key_use`, else (no `key_op` is
    // ever generated) the use the `alg` implies. Parts that disagree match
    // nothing. With a U, the member's `use` must be absent or U.
    let implied = sel.alg.map(alg_use);
    let effective = match (sel.key_use, implied) {
        (Some(given), Some(implied)) if given != implied => return Err(Check::Purpose),
        (Some(given), _) => Some(given),
        (None, implied) => implied,
    };
    if let (Some(effective), Some(member_use)) = (effective, member.key_use) {
        // U is always `sig` or `enc` (it comes from `key_use`, which §1.1
        // limits to those, or from the `alg`). An unregistered member
        // `use` is present and is neither, so it fails §2.3 whenever a U
        // exists. Without a U, `use` is not checked, and it may match.
        if !REGISTERED_USES.contains(&member_use) {
            return Err(Check::Purpose);
        }
        if member_use != effective {
            return Err(Check::Purpose);
        }
    }

    // §2.4 `key_ops`: if present, it must contain (no `key_op` given) one
    // operation the `alg` performs in either direction; else, with a U, one
    // registered operation of U; otherwise it is not checked.
    if let Some(ops) = &member.key_ops {
        let required = match (sel.alg, effective) {
            (Some(alg), _) => Some(mode_ops(alg_mode(alg))),
            (None, Some(effective)) => Some(use_ops(effective)),
            (None, None) => None,
        };
        // Every operation §2.4 can require is a registered one (the `alg`
        // rows and the ops of U are both drawn from RFC 7517 §4.3), so an
        // unregistered entry never satisfies §2.4: only the member's
        // registered entries are considered. A `key_ops` holding only
        // unregistered values fails whenever something is required.
        if let Some(required) = required
            && !ops
                .iter()
                .filter(|op| REGISTERED_OPS.contains(op))
                .any(|op| required.contains(op))
        {
            return Err(Check::KeyOps);
        }
    }

    // §2.5 `kid`: exact, case-sensitive equality (RFC 7517 §4.5).
    if let Some(kid) = sel.kid
        && member.kid != Some(kid)
    {
        return Err(Check::Kid);
    }

    Ok(())
}

/// The indexes of the members the oracle accepts, in set order.
fn oracle_indexes(members: &[MemberSpec], sel: &Sel) -> Vec<usize> {
    members
        .iter()
        .enumerate()
        .filter(|(_, m)| oracle(m, sel).is_ok())
        .map(|(i, _)| i)
        .collect()
}

// ---------------------------------------------------------------------------
// Generator sanity
// ---------------------------------------------------------------------------

/// The restated algorithm lists are exactly the algorithms polyjose
/// implements, and the selector accepts each one (ADR 0054 §1.1), so the
/// properties draw from every implemented `SigningAlg` and `KeyMgmtAlg`.
#[test]
fn alg_tables_cover_every_implemented_algorithm() {
    let signing: Vec<&str> = SigningAlg::KNOWN
        .iter()
        .filter(|alg| **alg != SigningAlg::None)
        .map(SigningAlg::as_str)
        .collect();
    assert_eq!(signing, JWS_ALGS);
    let key_mgmt: Vec<&str> = KeyMgmtAlg::KNOWN.iter().map(KeyMgmtAlg::as_str).collect();
    assert_eq!(key_mgmt, KEY_MGMT_ALGS);
    for alg in selector_algs() {
        assert!(JwkSelector::new().alg(KeyAlg::from(alg)).is_ok(), "{alg}");
        assert!(
            pool().iter().any(|key| serves(key.family, alg)),
            "the pool has no key for {alg}"
        );
    }
}

/// A member of pool key `key` with no optional members.
fn bare(key: usize) -> MemberSpec {
    MemberSpec {
        key,
        kid: None,
        alg: None,
        key_use: None,
        key_ops: None,
    }
}

fn by_alg(alg: &'static str) -> Sel {
    Sel {
        alg: Some(alg),
        ..Sel::default()
    }
}

/// The oracle reproduces the consequences ADR 0054 spells out in its own
/// text, so the properties compare the crate with the ADR and not with a
/// misreading of it.
#[test]
fn oracle_follows_the_adr_0054_examples() {
    for (key, pool_key) in pool().iter().enumerate() {
        let member = bare(key);
        // §1.3: the empty selector matches every member.
        assert_eq!(oracle(&member, &Sel::default()), Ok(()));
        for alg in selector_algs() {
            let verdict = oracle(&member, &by_alg(alg));
            // §2.1: an `oct` key never for an asymmetric alg, an asymmetric
            // key never for HS*, A*KW, A*GCMKW, dir or PBES2.
            if (pool_key.family == Family::Oct) != SYMMETRIC_ALGS.contains(&alg) {
                assert_eq!(verdict, Err(Check::Family), "{} {alg}", pool_key.label);
            }
            // §2.1: X25519 never matches EdDSA; Ed25519 and secp256k1
            // never match ECDH-ES.
            if pool_key.family == Family::X25519 && alg == "EdDSA"
                || matches!(pool_key.family, Family::Ed25519 | Family::Secp256k1)
                    && alg_mode(alg) == Mode::KeyAgreement
            {
                assert_eq!(verdict, Err(Check::Family), "{} {alg}", pool_key.label);
            }
            // §2.3: `alg: ES256` with `key_use: enc` matches nothing.
            let disagreeing = Sel {
                alg: Some("ES256"),
                key_use: Some("enc"),
                ..Sel::default()
            };
            assert!(oracle(&member, &disagreeing).is_err());
        }
    }

    let ed25519 = pool()
        .iter()
        .position(|k| k.family == Family::Ed25519)
        .unwrap();
    let oct = pool().iter().position(|k| k.family == Family::Oct).unwrap();
    // §2.2: `EdDSA` ≠ `Ed25519`.
    let eddsa_member = MemberSpec {
        alg: Some("EdDSA"),
        ..bare(ed25519)
    };
    assert_eq!(
        oracle(&eddsa_member, &by_alg("Ed25519")),
        Err(Check::JwkAlg)
    );
    assert_eq!(oracle(&eddsa_member, &by_alg("EdDSA")), Ok(()));
    // §2.2: the `dir` exception for a content encryption `alg`.
    let a256gcm = MemberSpec {
        alg: Some("A256GCM"),
        ..bare(oct)
    };
    assert_eq!(oracle(&a256gcm, &by_alg("dir")), Ok(()));
    assert_eq!(oracle(&a256gcm, &by_alg("A256KW")), Err(Check::JwkAlg));
    // RFC 7517 A.3 with `alg: A128KW` (settled for T02): the `A128KW` key
    // and the bare HMAC key both match, so `select` is ambiguous.
    let a128kw = MemberSpec {
        alg: Some("A128KW"),
        ..bare(oct)
    };
    assert_eq!(oracle(&a128kw, &by_alg("A128KW")), Ok(()));
    assert_eq!(oracle(&bare(oct), &by_alg("A128KW")), Ok(()));
    // §2.2-§2.4 for unregistered member values (0015 F01).
    let unregistered_alg = MemberSpec {
        alg: Some(UNREGISTERED_ALG),
        ..bare(oct)
    };
    let unregistered_use = MemberSpec {
        key_use: Some(UNREGISTERED_USE),
        ..bare(oct)
    };
    let only_unregistered_op = MemberSpec {
        key_ops: Some(vec![UNREGISTERED_OP]),
        ..bare(oct)
    };
    let by_use = |key_use| Sel {
        key_use: Some(key_use),
        ..Sel::default()
    };
    let by_kid = Sel {
        kid: Some("a"),
        ..Sel::default()
    };
    for alg in selector_algs()
        .into_iter()
        .filter(|a| serves(Family::Oct, a))
    {
        // §2.2: with any selector `alg` the oct key serves, `dir` included.
        assert_eq!(
            oracle(&unregistered_alg, &by_alg(alg)),
            Err(Check::JwkAlg),
            "{alg}"
        );
        // §2.3: the `alg` implies a U.
        assert_eq!(
            oracle(&unregistered_use, &by_alg(alg)),
            Err(Check::Purpose),
            "{alg}"
        );
        // §2.4: the `alg`'s operations are required.
        assert_eq!(
            oracle(&only_unregistered_op, &by_alg(alg)),
            Err(Check::KeyOps),
            "{alg}"
        );
    }
    for key_use in REGISTERED_USES {
        // §2.2 needs a selector `alg`; without one the member `alg` is not
        // checked.
        assert_eq!(oracle(&unregistered_alg, &by_use(key_use)), Ok(()));
        // §2.3: `key_use` is U.
        assert_eq!(
            oracle(&unregistered_use, &by_use(key_use)),
            Err(Check::Purpose)
        );
        // §2.4: a registered operation of U is required.
        assert_eq!(
            oracle(&only_unregistered_op, &by_use(key_use)),
            Err(Check::KeyOps)
        );
        // An extra unregistered op beside one of U still matches.
        let with_extra = MemberSpec {
            key_ops: Some(vec![use_ops(key_use)[0], UNREGISTERED_OP]),
            ..bare(oct)
        };
        assert_eq!(oracle(&with_extra, &by_use(key_use)), Ok(()));
    }
    // No `alg` and no U: §2.2, §2.3 and §2.4 are all skipped.
    for sel in [Sel::default(), by_kid] {
        for member in [&unregistered_alg, &unregistered_use, &only_unregistered_op] {
            let member = MemberSpec {
                kid: Some("a"),
                ..member.clone()
            };
            assert_eq!(oracle(&member, &sel), Ok(()), "{member:?} {sel:?}");
        }
    }

    // §1.2: no `kid` never matches a `kid`; `a` ≠ `A`.
    let kid_a = Sel {
        kid: Some("a"),
        ..Sel::default()
    };
    assert_eq!(oracle(&bare(oct), &kid_a), Err(Check::Kid));
    let upper = MemberSpec {
        kid: Some("A"),
        ..bare(oct)
    };
    assert_eq!(oracle(&upper, &kid_a), Err(Check::Kid));
}

/// The generators reach every oracle verdict, so agreement in the
/// properties below is not vacuous: each §2 check rejects some member, and
/// the `key_ops` check (§2.4) rejects some member under every `alg` mode,
/// including key agreement with key wrapping. Deterministic seed; counts
/// only, no timing.
#[test]
fn generators_reach_every_oracle_verdict() {
    let mut runner = TestRunner::deterministic();
    let strategy = (members(), selector());
    let mut checks = HashSet::new();
    let mut key_ops_modes = HashSet::new();
    let mut ecdh_kw_key_ops = false;
    let mut accepted = 0usize;
    for _ in 0..1000 {
        let (members, sel) = strategy.new_tree(&mut runner).unwrap().current();
        for member in &members {
            match oracle(member, &sel) {
                Ok(()) => accepted += 1,
                Err(check) => {
                    checks.insert(check);
                    if check == Check::KeyOps {
                        let alg = sel.alg.unwrap_or("none");
                        if alg != "none" {
                            key_ops_modes.insert(alg_mode(alg));
                        }
                        ecdh_kw_key_ops |= alg.starts_with("ECDH-ES+");
                    }
                }
            }
        }
    }
    assert!(accepted > 0);
    for check in [
        Check::Family,
        Check::JwkAlg,
        Check::Purpose,
        Check::KeyOps,
        Check::Kid,
    ] {
        assert!(checks.contains(&check), "no member rejected by {check:?}");
    }
    for mode in [
        Mode::Jws,
        Mode::KeyEncryptionOrWrapping,
        Mode::Direct,
        Mode::KeyAgreement,
    ] {
        assert!(
            key_ops_modes.contains(&mode),
            "no key_ops rejection under {mode:?}"
        );
    }
    assert!(ecdh_kw_key_ops, "no key_ops rejection under ECDH-ES+A*KW");
}

/// How the crate imports each unregistered value, through the public API,
/// on every pool key: kept verbatim as `Unknown`, never skipped and never
/// an error (RFC 7517 §4.2–§4.4 "Other values MAY be used"; ADR 0041 §2
/// skips only invalid members; ADR 0054 §3 leaves import unchanged). The
/// oracle's §2.2–§2.4 rules for these values rely on this.
///
/// For contrast, a *registered* `alg` that the key's family cannot serve is
/// refused by `Jwk::from_object` (`KeyAlgorithmMismatch`, RFC 7517 §4.4,
/// RFC 8725 §3.1) and so skipped by the set (ADR 0041 §2). Such a member
/// never reaches selection, which is why [`member`] has no arm for it.
#[test]
fn unregistered_member_values_import_as_unknown() {
    for (key, pool_key) in pool().iter().enumerate() {
        let spec = MemberSpec {
            key,
            kid: Some("a"),
            alg: Some(UNREGISTERED_ALG),
            key_use: Some(UNREGISTERED_USE),
            key_ops: Some(vec!["sign", UNREGISTERED_OP]),
        };
        let set = import(std::slice::from_ref(&spec));
        assert_eq!(set.skipped(), 0, "{}", pool_key.label);
        let jwk = &set.keys()[0];
        assert_eq!(
            jwk.alg(),
            Some(&KeyAlg::Unknown(UNREGISTERED_ALG.to_owned())),
            "{}",
            pool_key.label
        );
        assert_eq!(
            jwk.key_use(),
            Some(&KeyUse::Unknown(UNREGISTERED_USE.to_owned())),
            "{}",
            pool_key.label
        );
        assert_eq!(
            jwk.key_ops(),
            Some(&[KeyOp::Sign, KeyOp::Unknown(UNREGISTERED_OP.to_owned())][..]),
            "{}",
            pool_key.label
        );
        // An extra unregistered op beside a registered `use` is no conflict
        // either (RFC 7517 §4.3).
        for registered in ["sig", "enc"] {
            let spec = MemberSpec {
                key_use: Some(registered),
                key_ops: Some(vec![UNREGISTERED_OP]),
                ..spec.clone()
            };
            assert_eq!(
                import(&[spec]).skipped(),
                0,
                "{} {registered}",
                pool_key.label
            );
        }
    }
    let oct = pool().iter().position(|k| k.family == Family::Oct).unwrap();
    let mismatched = MemberSpec {
        alg: Some("ES256"),
        ..bare(oct)
    };
    let set = import(&[mismatched]);
    assert_eq!((set.len(), set.skipped()), (0, 1));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Every generated member is a valid JWK, so the set skips none and
    /// `keys()[i]` is generated member `i` (ADR 0054 §3, ADR 0041 §2). This
    /// includes the unregistered `alg`, `use` and `key_ops` arms, each kept
    /// as `Unknown` ([`unregistered_member_values_import_as_unknown`]).
    #[test]
    fn every_generated_member_imports(members in members()) {
        let set = import(&members);
        prop_assert_eq!(set.skipped(), 0, "{}", set_json(&members));
        prop_assert_eq!(set.len(), members.len());
        for (member, key) in members.iter().zip(set.keys()) {
            prop_assert_eq!(key.kid(), member.kid, "{}", pool()[member.key].label);
        }
    }
}

// ---------------------------------------------------------------------------
// Soundness and completeness (ADR 0054 §2, §4)
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// Soundness: every `(i, k)` that `matching` yields is a member the
    /// oracle accepts, and `k` is `keys()[i]` (ADR 0054 §2, §4).
    #[test]
    fn matching_is_sound(members in members(), sel in selector()) {
        let set = import(&members);
        let selector = sel.build();
        for (i, key) in set.matching(&selector) {
            prop_assert!(i < members.len(), "index {} out of range", i);
            prop_assert!(core::ptr::eq(key, &set.keys()[i]), "matching gave a key that is not keys()[{}]", i);
            prop_assert_eq!(
                oracle(&members[i], &sel),
                Ok(()),
                "member {} ({}) matched {:?} in {}",
                i,
                pool()[members[i].key].label,
                sel,
                set_json(&members)
            );
        }
    }

    /// Completeness: `matching` yields every member the oracle accepts,
    /// each once, in index order (ADR 0054 §4 "every match in set order").
    #[test]
    fn matching_is_complete(members in members(), sel in selector()) {
        let set = import(&members);
        let selector = sel.build();
        let found: Vec<usize> = set.matching(&selector).map(|(i, _)| i).collect();
        let expected = oracle_indexes(&members, &sel);
        prop_assert_eq!(
            &found,
            &expected,
            "{:?} on {}: oracle verdicts {:?}",
            sel,
            set_json(&members),
            members.iter().map(|m| oracle(m, &sel)).collect::<Vec<_>>()
        );
    }
}

// ---------------------------------------------------------------------------
// select agrees with matching (ADR 0054 §4)
// ---------------------------------------------------------------------------

/// The deterministic generators give every `select` outcome: no match, one
/// match and several (by the oracle's count), so the agreement property
/// exercises each branch. Counts only, no timing.
#[test]
fn generators_reach_every_select_outcome() {
    let mut runner = TestRunner::deterministic();
    let strategy = (members(), selector());
    let mut outcomes = [0usize; 3];
    for _ in 0..1000 {
        let (members, sel) = strategy.new_tree(&mut runner).unwrap().current();
        outcomes[oracle_indexes(&members, &sel).len().min(2)] += 1;
    }
    assert!(
        outcomes.iter().all(|n| *n > 0),
        "outcomes (0, 1, ≥2): {outcomes:?}"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// `select` is `matching` reduced to one answer: zero matches →
    /// `NoMatchingKey` (an empty set included), one → `Ok` with that
    /// `(i, k)`, two or more → `MultipleMatchingKeys` (ADR 0054 §4,
    /// RFC 7517 §5.1: set order implies no preference).
    #[test]
    fn select_agrees_with_matching(members in members(), sel in selector()) {
        let set = import(&members);
        let selector = sel.build();
        let all: Vec<(usize, *const Jwk)> = set
            .matching(&selector)
            .map(|(i, key)| (i, core::ptr::from_ref(key)))
            .collect();
        let selected = set.select(&selector).map(|(i, key)| (i, core::ptr::from_ref(key)));
        match all.len() {
            0 => prop_assert_eq!(selected, Err(Error::NoMatchingKey)),
            1 => prop_assert_eq!(selected, Ok(all[0])),
            _ => prop_assert_eq!(selected, Err(Error::MultipleMatchingKeys)),
        }
    }
}

// ---------------------------------------------------------------------------
// Family safety (ADR 0054 §2.1, §2.2, §7; RFC 8725 §3.1)
// ---------------------------------------------------------------------------

/// The family of an *imported* key, read from its material (RFC 7518 §6,
/// RFC 8037 §2), independent of the generator's description.
fn imported_family(key: &Jwk) -> Family {
    match key.material() {
        KeyMaterial::Oct(_) => Family::Oct,
        KeyMaterial::Rsa(_) => Family::Rsa,
        KeyMaterial::Ec(ec) => match ec.crv() {
            EcCurve::P256 => Family::P256,
            EcCurve::P384 => Family::P384,
            EcCurve::P521 => Family::P521,
            EcCurve::Secp256k1 => Family::Secp256k1,
            _ => panic!("a curve outside the pool"),
        },
        KeyMaterial::Okp(okp) => match okp.crv() {
            OkpCurve::Ed25519 => Family::Ed25519,
            OkpCurve::X25519 => Family::X25519,
            _ => panic!("a curve outside the pool"),
        },
        _ => panic!("a key type outside the pool"),
    }
}

/// A key selected for `alg` is of a family that serves `alg` and carries
/// no other `alg` (ADR 0054 §2.1, §2.2, §7; RFC 8725 §3.1 "each key MUST
/// be used with exactly one algorithm").
fn assert_family_safe(key: &Jwk, alg: &str) -> Result<(), TestCaseError> {
    let family = imported_family(key);
    prop_assert!(serves(family, alg), "{:?} key selected for {}", family, alg);
    // The ADR's partition, checked directly: never `oct` for an asymmetric
    // alg, never an asymmetric key for HS*, A*KW, A*GCMKW, dir or PBES2.
    prop_assert_eq!(
        key.key_type() == KeyType::Oct,
        SYMMETRIC_ALGS.contains(&alg),
        "{:?} key selected for {}",
        key.key_type(),
        alg
    );
    // X25519 never for EdDSA; Ed25519 and secp256k1 never for ECDH-ES.
    if family == Family::X25519 {
        prop_assert!(alg != "EdDSA" && alg != "Ed25519", "X25519 for {}", alg);
    }
    if matches!(family, Family::Ed25519 | Family::Secp256k1) {
        prop_assert!(!alg.starts_with("ECDH-ES"), "{:?} for {}", family, alg);
    }
    // §2.2: a JWK `alg`, when present, is the selector `alg`; the one
    // exception is `dir` with a content encryption `alg` (RFC 7518 §4.5).
    if let Some(jwk_alg) = key.alg() {
        let dir_exception = alg == "dir" && matches!(jwk_alg, KeyAlg::ContentEnc(_));
        prop_assert!(
            jwk_alg.as_str() == alg || dir_exception,
            "a key with alg {} selected for {}",
            jwk_alg,
            alg
        );
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// For every selector with an `alg`, every key `matching` yields, and
    /// the key `select` returns, is family safe.
    #[test]
    fn selection_by_alg_is_family_safe(
        members in members(),
        alg in selector_alg(),
        kid in option::of(select(KIDS)),
        key_use in option::of(select(&["sig", "enc"][..])),
    ) {
        let set = import(&members);
        let selector = Sel { alg: Some(alg), kid, key_use }.build();
        for (_, key) in set.matching(&selector) {
            assert_family_safe(key, alg)?;
        }
        if let Ok((_, key)) = set.select(&selector) {
            assert_family_safe(key, alg)?;
        }
    }
}

// ---------------------------------------------------------------------------
// Monotonicity (ADR 0054 §2)
// ---------------------------------------------------------------------------

/// The indexes `matching` yields for `sel` on `set`.
fn matched(set: &JwkSet, sel: &Sel) -> Vec<usize> {
    set.matching(&sel.build()).map(|(i, _)| i).collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// Adding criteria never adds a match: `matching(s + c) ⊆ matching(s)`,
    /// where `s` is a generated selector with some of its parts dropped and
    /// `s + c` is the whole selector. Each part only adds a check
    /// (ADR 0054 §2: "an absent selector part skips its check").
    #[test]
    fn adding_a_criterion_never_adds_a_match(
        members in members(),
        full in selector(),
        drop in (any::<bool>(), any::<bool>(), any::<bool>()),
    ) {
        let fewer = Sel {
            alg: if drop.0 { None } else { full.alg },
            kid: if drop.1 { None } else { full.kid },
            key_use: if drop.2 { None } else { full.key_use },
        };
        let set = import(&members);
        let narrow = matched(&set, &full);
        let wide = matched(&set, &fewer);
        for i in &narrow {
            prop_assert!(wide.contains(i), "{:?} matched {} but {:?} did not", full, i, fewer);
        }
    }

    /// Removing a set member never adds a match for the remaining members:
    /// each match in the smaller set, mapped back to its original index, is
    /// a match in the whole set. Because ADR 0054 §2 decides each member on
    /// its own, the matches are in fact exactly the original ones minus the
    /// removed member, which is asserted too.
    #[test]
    fn removing_a_member_never_adds_a_match(
        members in vec(member(), 1..=8),
        removed in any::<Index>(),
        sel in selector(),
    ) {
        let removed = removed.index(members.len());
        let mut fewer = members.clone();
        fewer.remove(removed);
        let whole = matched(&import(&members), &sel);
        let remaining: Vec<usize> = matched(&import(&fewer), &sel)
            .into_iter()
            .map(|i| if i < removed { i } else { i + 1 })
            .collect();
        for i in &remaining {
            prop_assert!(whole.contains(i), "removing member {} added a match at {}", removed, i);
        }
        let expected: Vec<usize> = whole.into_iter().filter(|i| *i != removed).collect();
        prop_assert_eq!(remaining, expected);
    }
}
