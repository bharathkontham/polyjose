//! 0015 T05: JWK thumbprint properties for every `ThumbprintHash`, through
//! the public API only (ADR 0008 layer 2).
//!
//! Properties (each ≤ 1,000 cases, pipeline rule 8, ADR 0009), for SHA-256,
//! SHA-384 and SHA-512 alike (ADR 0054 §8):
//!
//! 1. **Optional members never count** (RFC 7638 §3.2.2): adding, removing
//!    or reordering `kid`, `use`, `alg`, `key_ops` and unknown members
//!    leaves the thumbprint unchanged. Anchored to the RFC 7638 §3.1 and
//!    RFC 8037 App. A.3 SHA-256 values.
//! 2. **Private and public agree** (RFC 7638 §3.2.1): a private EC or OKP
//!    key and its `to_public()` have equal thumbprints.
//! 3. **Format** (RFC 7638 §3, RFC 7515 §2): 43, 64 or 86 base64url
//!    characters with no padding.
//! 4. **URI** (RFC 9278 §3): `urn:ietf:params:oauth:jwk-thumbprint:` +
//!    `hash_name()` + `:` + the thumbprint.
//! 5. **Hashes differ:** the three hashes give pairwise different values.
//!
//! Keys come only from committed fixtures (RFC 7517 App. A, RFC 7515
//! App. A, RFC 7520, RFC 7468, RFC 8037 App. A, and
//! `conformance/tools/jwt-oracle/keys.json`); polyjose generates none. No
//! assertion depends on wall-clock timing.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

use std::sync::OnceLock;

use polyjose::json::{Number, Object, Value, parse};
use polyjose::jwk::{Jwk, ThumbprintHash};
use proptest::collection::vec;
use proptest::option;
use proptest::prelude::*;
use proptest::sample::{select, subsequence};

// ---------------------------------------------------------------------------
// Fixed keys (committed fixtures only)
// ---------------------------------------------------------------------------

/// `conformance/tools/jwt-oracle/keys.json`: fixed test keys, each with its
/// published source.
const JWT_ORACLE_KEYS: &str = include_str!("../../../conformance/tools/jwt-oracle/keys.json");
/// RFC 7517 Appendix A.1, the P-256 public key.
const RFC7517_A1_EC: &str = include_str!("data/keys/rfc/rfc7517-a1-ec-p256-spki.jwk.json");
/// RFC 7517 Appendix A.1, the RSA-2048 public key; also the key of
/// RFC 7638 §3.1.
const RFC7517_A1_RSA: &str = include_str!("data/keys/rfc/rfc7517-a1-rsa-spki.jwk.json");
/// RFC 7468 Figure 12, the secp256k1 private key, as a JWK.
const RFC7468_SECP256K1: &str =
    include_str!("data/keys/rfc/rfc7468-fig12-secp256k1-pkcs8.jwk.json");
/// RFC 8037 Appendix A.6 (RFC 7748 §6.1), the X25519 private key.
const RFC8037_A6_X25519: &str = include_str!("data/keys/rfc/rfc8037-a6-x25519-pkcs8.jwk.json");

/// Every thumbprint hash (ADR 0054 §8), with its IANA Named Information
/// name (RFC 9278 §4) and its base64url length: ⌈8n / 6⌉ characters for an
/// n-octet digest without padding (RFC 7515 §2).
const HASHES: [(ThumbprintHash, &str, usize); 3] = [
    (ThumbprintHash::Sha256, "sha-256", 43),
    (ThumbprintHash::Sha384, "sha-384", 64),
    (ThumbprintHash::Sha512, "sha-512", 86),
];

/// One fixed key: its required members only, and the `alg` values a JWK of
/// its family may carry (RFC 7517 §4.4), so that a decorated key imports.
struct PoolKey {
    label: &'static str,
    members: Object,
    algs: &'static [&'static str],
    /// An EC or OKP key with its private `d` (RFC 7638 §3.2.1).
    private: bool,
}

/// The key members of a fixture JWK, with every optional member removed.
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

const OCT_ALGS: &[&str] = &["HS256", "HS512", "A128KW", "A256GCMKW", "dir", "A256GCM"];
const ECDH_ALGS: &[&str] = &["ECDH-ES", "ECDH-ES+A128KW"];

/// The fixed key pool: oct of 16, 32 and 64 octets, P-256 (public and
/// private), P-384, P-521, secp256k1, Ed25519, X25519 and RSA-2048 public.
fn pool() -> &'static [PoolKey] {
    static POOL: OnceLock<Vec<PoolKey>> = OnceLock::new();
    POOL.get_or_init(|| {
        let key = |label, members, algs, private| PoolKey {
            label,
            members,
            algs,
            private,
        };
        vec![
            key("oct-16", oracle_key("oct-16"), OCT_ALGS, false),
            key("oct-32", oracle_key("oct-32"), OCT_ALGS, false),
            // RFC 7515 App. A.1.1.
            key("oct-64", oracle_key("oct-64"), OCT_ALGS, false),
            key(
                "P-256 (RFC 7517 A.1)",
                key_members(RFC7517_A1_EC),
                &["ES256", "ECDH-ES"],
                false,
            ),
            // RFC 7515 App. A.3.1.
            key(
                "P-256 private",
                oracle_key("p256"),
                &["ES256", "ECDH-ES+A256KW"],
                true,
            ),
            // RFC 7520 §5.4.1.
            key(
                "P-384 private",
                oracle_key("p384"),
                &["ES384", "ECDH-ES"],
                true,
            ),
            // RFC 7515 App. A.4.1.
            key(
                "P-521 private",
                oracle_key("p521"),
                &["ES512", "ECDH-ES"],
                true,
            ),
            key(
                "secp256k1 private",
                key_members(RFC7468_SECP256K1),
                &["ES256K"],
                true,
            ),
            // RFC 8037 App. A.1.
            key(
                "Ed25519 private",
                oracle_key("ed25519"),
                &["EdDSA", "Ed25519"],
                true,
            ),
            key(
                "X25519 private",
                key_members(RFC8037_A6_X25519),
                ECDH_ALGS,
                true,
            ),
            key(
                "RSA-2048 (RFC 7517 A.1)",
                key_members(RFC7517_A1_RSA),
                &["RS256", "PS384", "RSA-OAEP-256"],
                false,
            ),
        ]
    })
}

/// The pool key labelled `label`, imported with its required members only.
fn bare(label: &str) -> Jwk {
    let key = pool().iter().find(|k| k.label == label).unwrap();
    Jwk::from_json(key.members.to_json().as_bytes()).unwrap()
}

// ---------------------------------------------------------------------------
// Decorated keys
// ---------------------------------------------------------------------------

/// Member names polyjose gives no meaning to for any key type (RFC 7517
/// §4: "Additional members can be present"), so a JWK with them imports
/// and keeps them as other parameters.
const UNKNOWN_NAMES: &[&str] = &["ext", "iat", "note", "x-custom", "status"];

/// The registered `key_ops` values of each `use` (RFC 7517 §4.2, §4.3).
fn use_ops(key_use: &str) -> &'static [&'static str] {
    match key_use {
        "sig" => &["sign", "verify"],
        _ => &[
            "encrypt",
            "decrypt",
            "wrapKey",
            "unwrapKey",
            "deriveKey",
            "deriveBits",
        ],
    }
}

/// A JSON value for an unknown member: a string, an integer or a boolean.
fn unknown_value() -> impl Strategy<Value = Value> {
    prop_oneof![
        "[ -~]{0,12}".prop_map(Value::from),
        any::<i32>().prop_map(|n| Value::from(Number::from_i64(i64::from(n)).unwrap())),
        any::<bool>().prop_map(Value::from),
    ]
}

/// A pool key plus optional members, in a random member order.
#[derive(Clone, Debug)]
struct Decorated {
    key: usize,
    /// Every member, key members and optional ones, in serialization order.
    members: Vec<(String, Value)>,
}

impl Decorated {
    fn jwk(&self) -> Jwk {
        let mut object = Object::new();
        for (name, value) in &self.members {
            object.insert(name.clone(), value.clone());
        }
        Jwk::from_json(object.to_json().as_bytes()).unwrap()
    }

    fn bare(&self) -> Jwk {
        Jwk::from_json(pool()[self.key].members.to_json().as_bytes()).unwrap()
    }
}

/// A key of `pool()[key]` with an optional `kid`, `use`, `alg`, `key_ops`
/// (consistent with the `use`, RFC 7517 §4.3) and up to three unknown
/// members, all its members shuffled.
fn decorated_of(key: usize) -> impl Strategy<Value = Decorated> {
    let pool_key = &pool()[key];
    (
        option::of("[ -~]{0,12}"),
        option::of(select(pool_key.algs)),
        select(&["sig", "enc"][..]),
        any::<bool>(),
        option::of(subsequence(&["sign", "verify"][..], 1..=2)),
        option::of(subsequence(use_ops("enc"), 1..=6)),
        subsequence(UNKNOWN_NAMES, 0..=3),
        vec(unknown_value(), 3),
    )
        .prop_flat_map(
            move |(kid, alg, key_use, with_use, sig_ops, enc_ops, unknown, values)| {
                let mut members: Vec<(String, Value)> = pool()[key]
                    .members
                    .iter()
                    .map(|(name, value)| (name.to_owned(), value.clone()))
                    .collect();
                if let Some(kid) = kid {
                    members.push(("kid".to_owned(), Value::from(kid)));
                }
                if let Some(alg) = alg {
                    members.push(("alg".to_owned(), Value::from(alg)));
                }
                if with_use {
                    members.push(("use".to_owned(), Value::from(key_use)));
                }
                let ops = if key_use == "sig" { sig_ops } else { enc_ops };
                if let Some(ops) = ops {
                    let ops: Vec<Value> = ops.into_iter().map(Value::from).collect();
                    members.push(("key_ops".to_owned(), Value::from(ops)));
                }
                for (name, value) in unknown.into_iter().zip(values) {
                    members.push((name.to_owned(), value));
                }
                Just(members).prop_shuffle()
            },
        )
        .prop_map(move |members| Decorated { key, members })
}

/// A decorated key of any pool key.
fn decorated() -> impl Strategy<Value = Decorated> {
    (0..pool().len()).prop_flat_map(decorated_of)
}

// ---------------------------------------------------------------------------
// Optional members never count (RFC 7638 §3.2.2)
// ---------------------------------------------------------------------------

/// The bare-key reference the invariance property compares with is the
/// RFC's own value where one is published: RFC 7638 §3.1 (the RFC 7517 A.1
/// RSA key) and RFC 8037 App. A.3 (the Ed25519 key, here with its private
/// `d`, RFC 7638 §3.2.1).
#[test]
fn bare_keys_give_the_published_sha256_thumbprints() {
    assert_eq!(
        bare("RSA-2048 (RFC 7517 A.1)").thumbprint(ThumbprintHash::Sha256),
        "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
    );
    assert_eq!(
        bare("Ed25519 private").thumbprint(ThumbprintHash::Sha256),
        "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// Adding `kid`, `use`, `alg`, `key_ops` and unknown members, and
    /// reordering every member, never changes the thumbprint under any
    /// hash: only the required members count (RFC 7638 §3.2, §3.2.2), in
    /// lexicographic order (§3.3).
    #[test]
    fn optional_members_and_order_never_change_the_thumbprint(key in decorated()) {
        let decorated = key.jwk();
        let bare = key.bare();
        // The decorations survive import, so the comparison is not vacuous.
        let kid = key.members.iter().find(|(name, _)| name == "kid").map(|(_, v)| v.as_str().unwrap());
        prop_assert_eq!(decorated.kid(), kid);
        let unknown = key.members.iter().filter(|(name, _)| UNKNOWN_NAMES.contains(&name.as_str())).count();
        prop_assert_eq!(decorated.other_params().len(), unknown);
        for (hash, _, _) in HASHES {
            prop_assert_eq!(
                decorated.thumbprint(hash),
                bare.thumbprint(hash),
                "{} under {:?}",
                pool()[key.key].label,
                hash
            );
        }
    }

    /// Two independent decorations of one key, so members are removed as
    /// well as added between the two, give equal thumbprints.
    #[test]
    fn two_decorations_of_one_key_agree(
        (first, second) in (0..pool().len()).prop_flat_map(|key| (decorated_of(key), decorated_of(key))),
    ) {
        let (first, second) = (first.jwk(), second.jwk());
        for (hash, _, _) in HASHES {
            prop_assert_eq!(first.thumbprint(hash), second.thumbprint(hash));
        }
    }
}

// ---------------------------------------------------------------------------
// Private and public agree (RFC 7638 §3.2.1)
// ---------------------------------------------------------------------------

/// The pool indexes of the private EC and OKP keys.
fn private_keys() -> Vec<usize> {
    (0..pool().len()).filter(|i| pool()[*i].private).collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// A private EC or OKP key and its public half have equal thumbprints
    /// under every hash: the private `d` is not a required member
    /// (RFC 7638 §3.2.1, RFC 7518 §6.2.1, RFC 8037 §2).
    #[test]
    fn a_private_key_and_its_public_half_agree(
        key in select(private_keys()).prop_flat_map(decorated_of),
    ) {
        let private = key.jwk();
        prop_assert!(!private.is_public(), "{}", pool()[key.key].label);
        let public = private.to_public().unwrap();
        prop_assert!(public.is_public());
        for (hash, _, _) in HASHES {
            prop_assert_eq!(private.thumbprint(hash), public.thumbprint(hash));
        }
    }
}

// ---------------------------------------------------------------------------
// Format, URI and distinct hashes (RFC 7638 §3, RFC 9278 §3, ADR 0054 §8)
// ---------------------------------------------------------------------------

/// Whether `c` is in the base64url alphabet (RFC 4648 §5): no `+`, `/` or
/// `=` padding (RFC 7515 §2).
fn is_base64url(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

/// The names and the default are those ADR 0054 §8 fixes, and the
/// SHA-256 shorthands are `thumbprint(Sha256)` (ADR 0054 §8).
#[test]
fn hash_names_and_default() {
    for (hash, name, _) in HASHES {
        assert_eq!(hash.hash_name(), name);
        assert_eq!(ThumbprintHash::from_name(name), Ok(hash));
    }
    // RFC 9278 §5: SHA-256 is the mandatory-to-implement default.
    assert_eq!(ThumbprintHash::default(), ThumbprintHash::Sha256);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// A thumbprint is the unpadded base64url of the digest: 43, 64 or 86
    /// characters for SHA-256, SHA-384 or SHA-512 (RFC 7638 §3,
    /// RFC 7515 §2, ADR 0054 §8.1).
    #[test]
    fn thumbprints_are_unpadded_base64url_of_the_digest_length(key in decorated()) {
        let jwk = key.jwk();
        for (hash, _, length) in HASHES {
            let thumbprint = jwk.thumbprint(hash);
            prop_assert_eq!(thumbprint.len(), length, "{:?}", hash);
            prop_assert!(thumbprint.chars().all(is_base64url), "{:?}: {}", hash, thumbprint);
        }
    }

    /// The URI is `urn:ietf:params:oauth:jwk-thumbprint:` + the IANA hash
    /// name + `:` + the thumbprint (RFC 9278 §3, §4; ADR 0054 §8.3), and
    /// the SHA-256 shorthands equal the general forms.
    #[test]
    fn thumbprint_uri_is_the_urn_of_the_thumbprint(key in decorated()) {
        let jwk = key.jwk();
        for (hash, _, _) in HASHES {
            let expected = format!(
                "urn:ietf:params:oauth:jwk-thumbprint:{}:{}",
                hash.hash_name(),
                jwk.thumbprint(hash)
            );
            prop_assert_eq!(jwk.thumbprint_uri(hash), expected);
        }
        prop_assert_eq!(jwk.thumbprint_sha256(), jwk.thumbprint(ThumbprintHash::Sha256));
        prop_assert_eq!(jwk.thumbprint_uri_sha256(), jwk.thumbprint_uri(ThumbprintHash::Sha256));
    }

    /// The three hashes give pairwise different thumbprints and URIs for
    /// every key (ADR 0054 §8).
    #[test]
    fn the_three_hashes_give_pairwise_different_values(key in decorated()) {
        let jwk = key.jwk();
        for (i, (first, _, _)) in HASHES.iter().enumerate() {
            for (second, _, _) in &HASHES[i + 1..] {
                prop_assert_ne!(jwk.thumbprint(*first), jwk.thumbprint(*second));
                prop_assert_ne!(jwk.thumbprint_uri(*first), jwk.thumbprint_uri(*second));
            }
        }
    }
}
