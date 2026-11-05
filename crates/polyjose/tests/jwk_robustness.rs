//! JWK import robustness (ADR 0008 layer 2): no input makes `Jwk` parsing
//! panic, every failure is one of the stable key-import codes, whatever
//! parses re-serializes to the same JSON object, and well-formed keys of
//! every type are accepted.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

use polyjose::Error;
use polyjose::json::{self, Number, Object, Value};
use polyjose::jwk::{Jwk, KeyMaterial, KeyOp};
use polyjose::util::b64url_encode;
use proptest::prelude::*;

/// RFC 7517 Appendix A.2 EC private key, the seed for byte mutations.
const EC_PRIVATE: &str = r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE","use":"enc","key_ops":["deriveKey"],"kid":"1"}"#;

/// Names that steer generation into the typed members, the RSA private
/// members and unknown ones.
const NAMES: &[&str] = &[
    "kty", "crv", "x", "y", "d", "n", "e", "k", "use", "key_ops", "alg", "kid", "x5u", "x5c",
    "x5t", "x5t#S256", "p", "q", "dp", "dq", "qi", "oth", "ext", "",
];

/// String values that steer generation into accepted keys.
const WORDS: &[&str] = &[
    "oct",
    "RSA",
    "EC",
    "OKP",
    "ec",
    "P-256",
    "P-384",
    "P-521",
    "secp256k1",
    "Ed25519",
    "X25519",
    "Ed448",
    "sig",
    "enc",
    "x-use",
    "sign",
    "verify",
    "encrypt",
    "wrapKey",
    "deriveBits",
    "ES256",
    "RS256",
    "A128KW",
    "AQAB",
    "AA",
    "AQ",
    "",
];

/// Base64url strings of the octet lengths the key types use.
fn sized_b64() -> impl Strategy<Value = String> {
    (
        prop::sample::select(&[1usize, 16, 31, 32, 33, 48, 66, 255, 256, 257][..]),
        any::<u8>(),
        any::<u8>(),
    )
        .prop_map(|(len, first, fill)| {
            let mut bytes = vec![fill | 1; len];
            bytes[0] = first;
            b64url_encode(&bytes)
        })
}

fn name() -> impl Strategy<Value = String> {
    prop_oneof![
        6 => prop::sample::select(NAMES).prop_map(str::to_owned),
        1 => "\\PC{0,6}",
    ]
}

fn leaf() -> impl Strategy<Value = Value> {
    prop_oneof![
        1 => Just(Value::Null),
        1 => any::<bool>().prop_map(Value::from),
        1 => (-3i64..70_000).prop_filter_map("exact", |i| Number::from_i64(i).map(Value::from)),
        4 => prop::sample::select(WORDS).prop_map(Value::from),
        4 => sized_b64().prop_map(Value::from),
        1 => "[A-Za-z0-9_=+/-]{0,12}".prop_map(Value::from),
    ]
}

fn value() -> impl Strategy<Value = Value> {
    leaf().prop_recursive(2, 16, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(Value::from),
            prop::collection::vec((name(), inner), 0..4).prop_map(|members| {
                let mut o = Object::new();
                for (n, v) in members {
                    o.insert(n, v);
                }
                Value::from(o)
            }),
        ]
    })
}

fn jwk_object() -> impl Strategy<Value = Object> {
    prop::collection::vec((name(), value()), 0..10).prop_map(|members| {
        let mut o = Object::new();
        for (n, v) in members {
            o.insert(n, v);
        }
        o
    })
}

/// Exercises every accessor; none may panic, and none may leak `d`.
fn use_everything(jwk: &Jwk) {
    let _ = (
        jwk.key_type(),
        jwk.key_use(),
        jwk.key_ops(),
        jwk.alg(),
        jwk.kid(),
    );
    let _ = (
        jwk.x5u(),
        jwk.x5c(),
        jwk.x5t(),
        jwk.x5t_s256(),
        jwk.is_public(),
    );
    for op in [KeyOp::Sign, KeyOp::Verify, KeyOp::Encrypt, KeyOp::DeriveKey] {
        let _ = jwk.permits(&op);
    }
    let _ = format!("{jwk:?}");
    if let KeyMaterial::Rsa(key) = jwk.material() {
        assert!(key.modulus_bits() >= 2048);
    }
    if let Some(public) = jwk.to_public() {
        assert!(public.is_public());
        let object = public.to_object();
        assert!(!object.contains("d") && !object.contains("k"));
    }
}

fn is_import_error(e: &Error) -> bool {
    matches!(
        e,
        Error::InvalidKey(_) | Error::InvalidBase64 | Error::UnsupportedAlgorithm
    )
}

/// A well-formed key of a random type with random member octets.
fn valid_key() -> impl Strategy<Value = Object> {
    let ec = (
        prop::sample::select(
            &[
                ("P-256", 32usize),
                ("P-384", 48),
                ("P-521", 66),
                ("secp256k1", 32),
            ][..],
        ),
        any::<bool>(),
        any::<[u8; 3]>(),
    )
        .prop_map(|((crv, len), private, [x, y, d])| {
            let mut o = Object::new();
            o.insert("kty", "EC");
            o.insert("crv", crv);
            o.insert("x", b64url_encode(&vec![x; len]));
            o.insert("y", b64url_encode(&vec![y; len]));
            if private {
                o.insert("d", b64url_encode(&vec![d; len]));
            }
            o
        });
    let okp = (
        prop::sample::select(&["Ed25519", "X25519"][..]),
        any::<bool>(),
        any::<[u8; 32]>(),
    )
        .prop_map(|(crv, private, bytes)| {
            let mut o = Object::new();
            o.insert("kty", "OKP");
            o.insert("crv", crv);
            o.insert("x", b64url_encode(&bytes));
            if private {
                o.insert("d", b64url_encode(&bytes));
            }
            o
        });
    let rsa =
        (256usize..=520, 0x80u8..=0xff, any::<u8>(), 0u32..3).prop_map(|(len, first, fill, e)| {
            let mut n = vec![fill; len];
            n[0] = first;
            n[len - 1] |= 1;
            let mut o = Object::new();
            o.insert("kty", "RSA");
            o.insert("n", b64url_encode(&n));
            o.insert("e", ["Aw", "EQ", "AQAB"][e as usize]);
            o
        });
    let oct = prop::collection::vec(any::<u8>(), 1..100).prop_map(|k| {
        let mut o = Object::new();
        o.insert("kty", "oct");
        o.insert("k", b64url_encode(&k));
        o
    });
    (
        prop_oneof![ec, okp, rsa, oct],
        prop::option::of("[a-z0-9-]{0,10}"),
    )
        .prop_map(|(mut o, kid)| {
            if let Some(kid) = kid {
                o.insert("kid", kid);
            }
            o
        })
}

/// A well-formed key with random members added or overwritten: a mix of
/// accepted keys (with unknown and common members) and near misses.
fn edited_key() -> impl Strategy<Value = Object> {
    (valid_key(), prop::collection::vec((name(), value()), 0..4)).prop_map(|(mut o, edits)| {
        for (n, v) in edits {
            o.insert(n, v);
        }
        o
    })
}

/// Objects of either kind.
fn any_object() -> impl Strategy<Value = Object> {
    prop_oneof![jwk_object(), edited_key()]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        match Jwk::from_json(&bytes) {
            Ok(jwk) => use_everything(&jwk),
            Err(e) => prop_assert!(matches!(e, Error::InvalidJson(_)) || is_import_error(&e), "{e:?}"),
        }
    }

    #[test]
    fn mutated_keys_never_panic(
        edits in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..8)
    ) {
        let mut bytes = EC_PRIVATE.as_bytes().to_vec();
        for (at, byte) in edits {
            let i = at.index(bytes.len());
            bytes[i] = byte;
        }
        match Jwk::from_json(&bytes) {
            Ok(jwk) => use_everything(&jwk),
            Err(e) => prop_assert!(matches!(e, Error::InvalidJson(_)) || is_import_error(&e), "{e:?}"),
        }
    }

    #[test]
    fn arbitrary_objects_import_or_fail_with_a_key_error(object in any_object()) {
        match Jwk::from_object(&object) {
            Ok(jwk) => {
                use_everything(&jwk);
                // Whatever is accepted writes back the same members.
                prop_assert_eq!(Value::from(jwk.to_object()), Value::from(object.clone()));
                let again = Jwk::from_json(jwk.to_json().as_bytes()).unwrap();
                prop_assert_eq!(Value::from(again.to_object()), Value::from(object));
            }
            // A JSON object can only fail the key rules.
            Err(e) => prop_assert!(is_import_error(&e), "{e:?}"),
        }
    }

    #[test]
    fn well_formed_keys_are_accepted_and_round_trip(object in valid_key()) {
        let text = object.to_json();
        let jwk = Jwk::from_json(text.as_bytes());
        prop_assert!(jwk.is_ok(), "{:?}", jwk.err());
        let jwk = jwk.unwrap();
        use_everything(&jwk);
        let out = jwk.to_json();
        prop_assert_eq!(out.as_str(), text.as_str());
        prop_assert_eq!(
            json::parse(jwk.to_json().as_bytes()).unwrap(),
            Value::from(object)
        );
    }
}
