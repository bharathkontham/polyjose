//! `JwkSet::select` and `JwkSet::matching` (ADR 0054 §1–§4), black-box
//! through the public API: the RFC 7517 Appendix A sets, and a JWE round
//! trip proving a selected key passes JWE key binding (ADR 0054 §2,
//! "Not part of selection"; RFC 7516 §5).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

use polyjose::Error;
use polyjose::jwa::{ContentEncAlg, KeyMgmtAlg};
use polyjose::jwe::{DecryptPolicy, Encryptor, Recipient, decrypt_compact};
use polyjose::jwk::{Jwk, JwkSelector, JwkSet, KeyAlg, KeyUse};

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
