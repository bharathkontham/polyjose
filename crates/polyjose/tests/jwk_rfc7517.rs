//! RFC 7517 Appendix A and B keys: every key parses and re-serializes to
//! equal JSON members, except the RSA private key of Appendix A.2, which is
//! rejected with `UnsupportedAlgorithm` (ADR 0021).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

use polyjose::Error;
use polyjose::json::{self, Value};
use polyjose::jwa::{KeyMgmtAlg, SigningAlg};
use polyjose::jwk::{EcCurve, Jwk, KeyAlg, KeyMaterial, KeyOp, KeyType, KeyUse};
use polyjose::util::b64url_decode;

/// RFC 7517 Appendix A.1 (line breaks inside values removed).
const A1: &str = r#"{"keys":
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

/// RFC 7517 Appendix A.2 (line breaks inside values removed).
const A2: &str = r#"{"keys":
  [
    {"kty":"EC",
     "crv":"P-256",
     "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
     "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
     "d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
     "use":"enc",
     "kid":"1"},
    {"kty":"RSA",
     "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
     "e":"AQAB",
     "d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
     "p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
     "q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
     "dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
     "dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
     "qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
     "alg":"RS256",
     "kid":"2011-04-29"}
  ]
}"#;

/// RFC 7517 Appendix A.3 (line breaks inside values removed).
const A3: &str = r#"{"keys":
  [
    {"kty":"oct",
     "alg":"A128KW",
     "k":"GawgguFyGrWKav7AX4VKUg"},
    {"kty":"oct",
     "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
     "kid":"HMAC key used in JWS spec Appendix A.1 example"}
  ]
}"#;

/// RFC 7517 Appendix B (line breaks inside values removed).
const B: &str = r#"{"kty":"RSA",
 "use":"sig",
 "kid":"1b94c",
 "n":"vrjOfz9Ccdgx5nQudyhdoR17V-IubWMeOZCwX_jj0hgAsz2J_pqYW08PLbK_PdiVGKPrqzmDIsLI7sA25VEnHU1uCLNwBuUiCO11_-7dYbsr4iJmG0Qu2j8DsVyT1azpJC_NG84Ty5KKthuCaPod7iI7w0LK9orSMhBEwwZDCxTWq4aYWAchc8t-emd9qOvWtVMDC2BXksRngh6X5bUYLy6AyHKvj-nUy1wgzjYQDwHMTplCoLtU-o-8SNnZ1tmRoGE9uJkBLdh5gFENabWnU5m1ZqZPdwS-qo-meMvVfJb6jJVWRpl2SUtCnYG2C32qvbWbjZ_jBPD5eunqsIo1vQ",
 "e":"AQAB",
 "x5c":
  ["MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA=="]
}"#;

/// The `keys` members of a JWK Set document, as raw JSON values.
fn set_members(set: &str) -> Vec<Value> {
    let set = json::parse(set.as_bytes()).expect("RFC set is valid JSON");
    set.get("keys")
        .and_then(Value::as_array)
        .expect("RFC set has keys")
        .to_vec()
}

fn import(member: &Value) -> Result<Jwk, Error> {
    Jwk::from_object(member.as_object().expect("set member is an object"))
}

/// Parses `member`, checks that both serializations are the same JSON
/// object as the input (member order aside), and returns the key.
fn round_trip(member: &Value) -> Jwk {
    let jwk = import(member).expect("RFC key is accepted");
    assert_eq!(&Value::from(jwk.to_object()), member);
    let reparsed = json::parse(jwk.to_json().as_bytes()).expect("to_json is valid JSON");
    assert_eq!(&reparsed, member);
    // Bytes in, the same object out, through from_json too.
    let again = Jwk::from_json(jwk.to_json().as_bytes()).expect("output re-imports");
    assert_eq!(&Value::from(again.to_object()), member);
    jwk
}

#[test]
fn a1_public_keys_round_trip() {
    let keys = set_members(A1);
    assert_eq!(keys.len(), 2);

    let ec = round_trip(&keys[0]);
    assert_eq!(ec.key_type(), KeyType::Ec);
    assert!(ec.is_public());
    assert_eq!(ec.key_use(), Some(&KeyUse::Enc));
    assert_eq!(ec.kid(), Some("1"));
    assert_eq!(ec.alg(), None);
    let KeyMaterial::Ec(point) = ec.material() else {
        panic!("not EC")
    };
    assert_eq!(point.crv(), EcCurve::P256);
    assert!(!point.is_private());
    assert_eq!(
        point.x(),
        b64url_decode("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4").unwrap()
    );
    assert_eq!(point.y().len(), 32);

    let rsa = round_trip(&keys[1]);
    assert_eq!(rsa.key_type(), KeyType::Rsa);
    assert!(rsa.is_public());
    assert_eq!(rsa.alg(), Some(&KeyAlg::Signing(SigningAlg::RS256)));
    assert_eq!(rsa.kid(), Some("2011-04-29"));
    let KeyMaterial::Rsa(key) = rsa.material() else {
        panic!("not RSA")
    };
    assert_eq!(key.modulus_bits(), 2048);
    assert_eq!(key.e(), [1, 0, 1]);
}

#[test]
fn a2_ec_private_key_round_trips_and_rsa_private_key_is_unsupported() {
    let keys = set_members(A2);
    assert_eq!(keys.len(), 2);

    let ec = round_trip(&keys[0]);
    assert!(!ec.is_public());
    let KeyMaterial::Ec(point) = ec.material() else {
        panic!("not EC")
    };
    assert!(point.is_private());
    // Its public part is exactly the A.1 public key.
    let public = ec.to_public().expect("EC has a public part");
    assert!(public.is_public());
    assert_eq!(Value::from(public.to_object()), set_members(A1)[0]);

    // ADR 0021: RSA private JWKs are not supported in 0.1.0.
    assert_eq!(import(&keys[1]).err(), Some(Error::UnsupportedAlgorithm));
}

#[test]
fn a3_symmetric_keys_round_trip() {
    let keys = set_members(A3);
    assert_eq!(keys.len(), 2);

    let kw = round_trip(&keys[0]);
    assert_eq!(kw.key_type(), KeyType::Oct);
    assert!(!kw.is_public());
    assert!(kw.to_public().is_none());
    assert_eq!(kw.alg(), Some(&KeyAlg::KeyMgmt(KeyMgmtAlg::A128KW)));
    let KeyMaterial::Oct(k) = kw.material() else {
        panic!("not oct")
    };
    assert_eq!(k.len(), 16);

    let hmac = round_trip(&keys[1]);
    assert_eq!(
        hmac.kid(),
        Some("HMAC key used in JWS spec Appendix A.1 example")
    );
    let KeyMaterial::Oct(k) = hmac.material() else {
        panic!("not oct")
    };
    assert_eq!(k.len(), 64);
}

#[test]
fn b_x5c_key_round_trips_with_its_chain_carried() {
    let member = json::parse(B.as_bytes()).unwrap();
    let jwk = round_trip(&member);
    assert_eq!(jwk.key_type(), KeyType::Rsa);
    assert_eq!(jwk.key_use(), Some(&KeyUse::Sig));
    assert_eq!(jwk.kid(), Some("1b94c"));
    let chain = jwk.x5c().expect("x5c is carried");
    assert_eq!(chain.len(), 1);
    assert!(chain[0].starts_with("MIIDQjCCAiqgAwIBAgIGATz/FuLi"));
    assert!(chain[0].ends_with("VfOWA=="));
    assert!(jwk.permits(&KeyOp::Verify));
    assert!(!jwk.permits(&KeyOp::Encrypt));
    let KeyMaterial::Rsa(key) = jwk.material() else {
        panic!("not RSA")
    };
    assert_eq!(key.modulus_bits(), 2048);
    // `to_public` of a public key keeps every typed member.
    let public = jwk.to_public().expect("RSA is public");
    assert_eq!(Value::from(public.to_object()), member);
}

#[test]
fn unknown_and_x509_members_are_preserved() {
    let json = br#"{"kty":"EC","crv":"P-256",
        "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
        "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
        "ext":true,"x-vendor":{"tier":[1,2.5,null,"a"]},
        "x5u":"https://example.com/cert.pem",
        "x5t":"not-checked","x5t#S256":"not-checked-either",
        "key_ops":["deriveKey","x-custom"],"alg":"ECDH-ES"}"#;
    let member = json::parse(json).unwrap();
    let jwk = round_trip(&member);
    assert_eq!(jwk.x5u(), Some("https://example.com/cert.pem"));
    assert_eq!(jwk.x5t(), Some("not-checked"));
    assert_eq!(jwk.x5t_s256(), Some("not-checked-either"));
    assert_eq!(
        jwk.key_ops(),
        Some(&[KeyOp::DeriveKey, KeyOp::Unknown("x-custom".into())][..])
    );
    assert_eq!(jwk.other_params().len(), 2);
    assert_eq!(
        jwk.other_params().get("ext").and_then(Value::as_bool),
        Some(true)
    );
    // The public view drops unknown members, keeps the typed ones.
    let public = jwk.to_public().unwrap();
    assert!(public.other_params().is_empty());
    assert_eq!(public.x5t(), Some("not-checked"));
    assert_eq!(public.key_ops(), jwk.key_ops());
}
