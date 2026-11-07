//! `JwkSet::select` and `JwkSet::matching` (ADR 0054 §1–§4), black-box
//! through the public API: the RFC 7517 Appendix A sets, a JWE round trip
//! proving a selected key passes JWE key binding (ADR 0054 §2, "Not part
//! of selection"; RFC 7516 §5), and the ADR 0057 §1 `key_op` + `alg` rule
//! for every mode. The binding selector has no `key_op` (ADR 0030 §4), so
//! these tables, not shared `jwks.select` vectors, are its vectors
//! (ADR 0057 §1).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

use polyjose::Error;
use polyjose::jwa::{ContentEncAlg, KeyMgmtAlg};
use polyjose::jwe::{DecryptPolicy, Encryptor, Recipient, decrypt_compact};
use polyjose::jwk::{Jwk, JwkSelector, JwkSet, KeyAlg, KeyOp, KeyUse};

/// RFC 7517 Appendix A.1 (line breaks inside values removed).
const RFC7517_A1: &str = r#"{"keys":
  [
    {"kty":"EC",
     "crv":"P-256",
     "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
     "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
     "use":"enc",
     "kid":"1"},
    {"kty":"RSA",
     "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
     "e":"AQAB",
     "alg":"RS256",
     "kid":"2011-04-29"}
  ]
}"#;

/// RFC 7517 Appendix A.3, symmetric keys.
const RFC7517_A3: &str = r#"{"keys":
  [
    {"kty":"oct",
     "alg":"A128KW",
     "k":"GawgguFyGrWKav7AX4VKUg"},
    {"kty":"oct",
     "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
     "kid":"HMAC key used in JWS spec Appendix A.1 example"}
  ]
}"#;

/// RFC 7517 Appendix A.3 plus one member: a `kid` on the A128KW key. A.3
/// as published gives that key no `kid`.
const RFC7517_A3_WITH_KW_KID: &str = r#"{"keys":
  [
    {"kty":"oct",
     "alg":"A128KW",
     "k":"GawgguFyGrWKav7AX4VKUg",
     "kid":"a128kw"},
    {"kty":"oct",
     "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
     "kid":"HMAC key used in JWS spec Appendix A.1 example"}
  ]
}"#;

fn set(json: &str) -> JwkSet {
    JwkSet::from_json(json.as_bytes()).unwrap()
}

fn by_alg(alg: &str) -> JwkSelector {
    JwkSelector::new().alg(KeyAlg::from(alg)).unwrap()
}

/// The index `select` returns.
fn selected(set: &JwkSet, selector: &JwkSelector) -> Result<usize, Error> {
    set.select(selector).map(|(index, key)| {
        assert!(core::ptr::eq(key, &set.keys()[index]));
        index
    })
}

#[test]
fn rfc7517_a1_select_by_kid_and_by_alg() {
    let a1 = set(RFC7517_A1);
    // By `kid` (RFC 7517 §4.5): the EC key.
    let (index, key) = a1.select(&JwkSelector::new().kid("1")).unwrap();
    assert_eq!((index, key.kid()), (0, Some("1")));
    // By `alg: ES256`: the only P-256 key is `use: enc` (RFC 7517 §4.2),
    // so no key may sign or verify ES256.
    assert_eq!(selected(&a1, &by_alg("ES256")), Err(Error::NoMatchingKey));
    // The same key is the one ECDH-ES key.
    assert_eq!(selected(&a1, &by_alg("ECDH-ES")), Ok(0));
    // `alg: RS256` with `kid: "2011-04-29"`: the RSA key.
    let (index, key) = a1.select(&by_alg("RS256").kid("2011-04-29")).unwrap();
    assert_eq!((index, key.kid()), (1, Some("2011-04-29")));
    // The RSA key's own `alg` is RS256 (RFC 7517 §4.4), so not PS256.
    assert_eq!(selected(&a1, &by_alg("PS256")), Err(Error::NoMatchingKey));
    // A `kid` alone may return any family; two keys, no criterion: ambiguous.
    assert_eq!(selected(&a1, &JwkSelector::new().kid("2011-04-29")), Ok(1));
    assert_eq!(
        selected(&a1, &JwkSelector::new()),
        Err(Error::MultipleMatchingKeys)
    );
    let all: Vec<usize> = a1.matching(&JwkSelector::new()).map(|(i, _)| i).collect();
    assert_eq!(all, [0, 1]);
}

#[test]
fn rfc7517_a3_select_by_alg() {
    let a3 = set(RFC7517_A3);
    // `alg: HS256`: the first member's own `alg` (A128KW) rules it out
    // (RFC 7517 §4.4), so the HMAC key is selected.
    let (index, key) = a3.select(&by_alg("HS256")).unwrap();
    assert_eq!(
        (index, key.kid()),
        (1, Some("HMAC key used in JWS spec Appendix A.1 example"))
    );
    // The empty selector matches both (RFC 7517 §5.1: no order of
    // preference).
    assert_eq!(
        selected(&a3, &JwkSelector::new()),
        Err(Error::MultipleMatchingKeys)
    );
    // `alg: A128KW` is ambiguous too. The HMAC member has no `alg`, `use`
    // or `key_ops`, so an `oct` key may serve A128KW (ADR 0054 §2 items
    // 1-4), and selection checks no key size: its 64-octet `k` is refused
    // only at use, by JWE key binding (ADR 0054 §2, "Not part of
    // selection").
    assert_eq!(
        selected(&a3, &by_alg("A128KW")),
        Err(Error::MultipleMatchingKeys)
    );
    // A `kid` disambiguates: the HMAC key's own `kid` picks it.
    let hmac = by_alg("A128KW").kid("HMAC key used in JWS spec Appendix A.1 example");
    assert_eq!(selected(&a3, &hmac), Ok(1));
    // With a `kid` on the A128KW member, that `kid` picks it.
    let with_kid = set(RFC7517_A3_WITH_KW_KID);
    let (index, key) = with_kid.select(&by_alg("A128KW").kid("a128kw")).unwrap();
    assert_eq!(
        (index, key.alg()),
        (0, Some(&KeyAlg::KeyMgmt(KeyMgmtAlg::A128KW)))
    );
}

/// RFC 7748 §6.1, Bob's X25519 key pair (RFC 8037 Appendix A.6 uses its
/// public key), as the recipient's `use: enc` key.
const BOB_X25519_PRIVATE: &str = r#"{"kty":"OKP","crv":"X25519","x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08","d":"XasIfmJKikt54X-Lg4AO5m87sSkmGLb9HC-LJ_-I4Os","use":"enc","kid":"bob-enc"}"#;
/// RFC 8037 Appendix A.1, the Ed25519 private key, as the recipient's
/// `use: sig` key.
const BOB_ED25519_PRIVATE: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","use":"sig","kid":"bob-sig"}"#;
/// RFC 7517 Appendix A.1, the P-256 public key, as a `use: sig` key.
const P256_SIG: &str = r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","use":"sig","kid":"p256-sig"}"#;
/// RFC 7517 Appendix A.3, the A128KW key.
const OCT_A128KW: &str = r#"{"kty":"oct","alg":"A128KW","k":"GawgguFyGrWKav7AX4VKUg","kid":"kw"}"#;

/// ADR 0054 §2: the key selected for `ECDH-ES+A128KW` from a mixed set
/// encrypts (RFC 7516 §5.1), and the private half selected from the
/// recipient's own set decrypts (RFC 7516 §5.2). Both pass JWE key binding
/// (family, JWK `alg`, `use`, `key_ops`, ADR 0026 §2 step 8 as applied to
/// JWE).
#[test]
fn a_selected_x25519_key_round_trips_ecdh_es_a128kw() {
    let alg = KeyMgmtAlg::EcdhEsA128KW;
    let enc = ContentEncAlg::A128GCM;

    // The recipient's set: its private keys. Publishing it would leak `d`;
    // the sender gets the `to_public` form of each (ADR 0054 §3).
    let recipient_json =
        format!(r#"{{"keys":[{BOB_ED25519_PRIVATE},{BOB_X25519_PRIVATE},{OCT_A128KW}]}}"#);
    let recipient = set(&recipient_json);
    assert_eq!(recipient.len(), 3);
    let published: Vec<String> = recipient
        .keys()
        .iter()
        .filter_map(Jwk::to_public)
        .map(|key| key.to_json().to_string())
        .collect();
    assert_eq!(published.len(), 2, "the oct key has no public part");
    let sender_json = format!(
        r#"{{"keys":[{P256_SIG},{},{OCT_A128KW},{}]}}"#,
        published[0], published[1]
    );
    let sender = set(&sender_json);
    assert_eq!(sender.len(), 4);

    // The sender selects by `alg` alone: only the X25519 key serves
    // ECDH-ES (RFC 8037 §3.2), and the P-256 key is `use: sig`.
    let selector = JwkSelector::new()
        .alg(KeyAlg::KeyMgmt(alg.clone()))
        .unwrap();
    let (index, public) = sender.select(&selector).unwrap();
    assert_eq!((index, public.kid()), (3, Some("bob-enc")));
    assert!(public.is_public());
    let token = Encryptor::new(enc.clone())
        .recipient(Recipient::new(alg.clone(), public))
        .encrypt_compact(b"selected, then bound")
        .unwrap();

    // The recipient selects its private half by `alg`, `use` and `kid`.
    let selector = selector.key_use(KeyUse::Enc).unwrap().kid("bob-enc");
    let (index, private) = recipient.select(&selector).unwrap();
    assert_eq!(index, 1);
    assert!(!private.is_public());
    let policy = DecryptPolicy::new(&[alg], &[enc]).unwrap();
    let decrypted = decrypt_compact(&token, private, &policy).unwrap();
    assert_eq!(decrypted.plaintext(), b"selected, then bound");

    // The Ed25519 key never serves ECDH-ES, even by its `kid`.
    let wrong = JwkSelector::new()
        .alg(KeyAlg::KeyMgmt(KeyMgmtAlg::EcdhEsA128KW))
        .unwrap()
        .kid("bob-sig");
    assert_eq!(selected(&recipient, &wrong), Err(Error::NoMatchingKey));
}

/// One key per mode, each with `key_ops` naming the operations of its mode
/// (RFC 7517 §4.3) and a `kid` naming the mode. The `oct` keys are the
/// RFC 7517 A.3 keys, the X25519 key is Bob's (RFC 8037 A.6) and the
/// P-256 key is RFC 7517 A.1's.
fn one_key_per_mode() -> JwkSet {
    let set = set(r#"{"keys":[
        {"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg","key_ops":["wrapKey","unwrapKey"],"kid":"wrap"},
        {"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg","key_ops":["encrypt","decrypt"],"kid":"dir"},
        {"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow","key_ops":["sign","verify"],"kid":"mac"},
        {"kty":"OKP","crv":"X25519","x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08","key_ops":["deriveKey"],"kid":"agree"},
        {"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","key_ops":["verify"],"kid":"sig"}
    ]}"#);
    assert_eq!((set.len(), set.skipped()), (5, 0));
    set
}

/// ADR 0057 §1: with both an `alg` and a `key_op`, the `key_op` must be
/// one of the operations the `alg` performs in either direction, or the
/// selector matches nothing (`NoMatchingKey`, not a selector error):
/// - JWS: `sign`, `verify`
/// - key encryption and key wrapping: `wrapKey`, `unwrapKey`
/// - `dir`: `encrypt`, `decrypt`
/// - key agreement (ECDH-ES and ECDH-ES+A\*KW): `deriveKey`
///
/// A coherent pair then checks the member's `key_ops` as `Jwk::permits`.
#[test]
fn adr_0057_key_op_must_be_an_operation_of_the_alg() {
    let set = one_key_per_mode();
    let no = Err(Error::NoMatchingKey);
    #[rustfmt::skip]
    let cases: &[(&str, KeyOp, Result<usize, Error>)] = &[
        // JWS.
        ("HS256", KeyOp::Sign, Ok(2)),
        ("HS256", KeyOp::Verify, Ok(2)),
        ("HS256", KeyOp::WrapKey, no.clone()),
        ("ES256", KeyOp::Verify, Ok(4)),
        ("ES256", KeyOp::Sign, no.clone()), // coherent; the key's key_ops has only verify
        ("ES256", KeyOp::Encrypt, no.clone()),
        ("ES256", KeyOp::DeriveKey, no.clone()),
        // Key wrapping and key encryption.
        ("A128KW", KeyOp::WrapKey, Ok(0)),
        ("A128KW", KeyOp::UnwrapKey, Ok(0)),
        ("A128KW", KeyOp::Encrypt, no.clone()), // the dir key permits encrypt
        ("A128KW", KeyOp::Decrypt, no.clone()),
        ("A128KW", KeyOp::DeriveKey, no.clone()),
        ("A128GCMKW", KeyOp::WrapKey, Ok(0)),
        ("A128GCMKW", KeyOp::Encrypt, no.clone()),
        ("PBES2-HS256+A128KW", KeyOp::UnwrapKey, Ok(0)),
        ("PBES2-HS256+A128KW", KeyOp::Decrypt, no.clone()),
        // Direct encryption.
        ("dir", KeyOp::Encrypt, Ok(1)),
        ("dir", KeyOp::Decrypt, Ok(1)),
        ("dir", KeyOp::WrapKey, no.clone()), // the wrap key permits wrapKey
        ("dir", KeyOp::UnwrapKey, no.clone()),
        // Key agreement.
        ("ECDH-ES", KeyOp::DeriveKey, Ok(3)),
        ("ECDH-ES+A128KW", KeyOp::DeriveKey, Ok(3)),
        ("ECDH-ES+A256KW", KeyOp::DeriveKey, Ok(3)),
        ("ECDH-ES+A128KW", KeyOp::WrapKey, no.clone()),
        ("ECDH-ES", KeyOp::DeriveBits, no.clone()),
        ("ECDH-ES", KeyOp::Encrypt, no.clone()),
    ];
    for (alg, op, expected) in cases {
        let alg_first = by_alg(alg).key_op(op.clone()).unwrap();
        let op_first = JwkSelector::new()
            .key_op(op.clone())
            .unwrap()
            .alg(KeyAlg::from(*alg))
            .unwrap();
        // The setters accept either pair in either order (ADR 0057 §1).
        assert_eq!(alg_first, op_first, "{alg} + {op}");
        for selector in [&alg_first, &op_first] {
            assert_eq!(&selected(&set, selector), expected, "{alg} + {op}");
            let matching: Vec<usize> = set.matching(selector).map(|(i, _)| i).collect();
            let expected_matching: Vec<usize> = expected.iter().copied().collect();
            assert_eq!(matching, expected_matching, "{alg} + {op}");
        }
    }
    // Without an `alg`, `key_op` alone is unchanged: `Jwk::permits`.
    let by_op = |op: KeyOp| JwkSelector::new().key_op(op).unwrap();
    assert_eq!(selected(&set, &by_op(KeyOp::Encrypt)), Ok(1));
    assert_eq!(selected(&set, &by_op(KeyOp::WrapKey)), Ok(0));
    assert_eq!(selected(&set, &by_op(KeyOp::DeriveKey)), Ok(3));
    assert_eq!(
        selected(&set, &by_op(KeyOp::Verify)),
        Err(Error::MultipleMatchingKeys)
    );
    assert_eq!(selected(&set, &by_op(KeyOp::DeriveBits)), no);
}

/// ADR 0057 §1, the behaviour change: under ADR 0054 §2.4 as first
/// written, `alg: A128KW` with `key_op: encrypt` selected a key with
/// `key_ops: ["encrypt"]`, which A128KW key binding then refused. Now
/// selection refuses it first, and agrees with the operation.
#[test]
fn adr_0057_the_formerly_selected_a128kw_encrypt_key_is_not_returned() {
    let k = "GawgguFyGrWKav7AX4VKUg";
    let set = set(&format!(
        r#"{{"keys":[{{"kty":"oct","k":"{k}","key_ops":["encrypt"],"kid":"e"}}]}}"#
    ));
    let a128kw_encrypt = by_alg("A128KW").key_op(KeyOp::Encrypt).unwrap();
    assert_eq!(selected(&set, &a128kw_encrypt), Err(Error::NoMatchingKey));
    assert_eq!(set.matching(&a128kw_encrypt).count(), 0);

    // The key it used to return: A128KW key binding refuses it, since
    // wrapping is `wrapKey`, not `encrypt` (RFC 7517 §4.3).
    let key = &set.keys()[0];
    let refused = Encryptor::new(ContentEncAlg::A128GCM)
        .recipient(Recipient::new(KeyMgmtAlg::A128KW, key))
        .encrypt_compact(b"never wrapped");
    assert_eq!(refused.unwrap_err(), Error::KeyAlgorithmMismatch);
    // Its own operation still finds it, with or without the `alg`.
    assert_eq!(
        selected(&set, &by_alg("dir").key_op(KeyOp::Encrypt).unwrap()),
        Ok(0)
    );
    let encrypt = JwkSelector::new().key_op(KeyOp::Encrypt).unwrap();
    assert_eq!(selected(&set, &encrypt), Ok(0));
}
