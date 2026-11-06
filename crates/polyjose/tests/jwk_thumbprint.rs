//! JWK Thumbprints (RFC 7638 §3, §7) and Thumbprint URIs (RFC 9278 §3-§5)
//! through the public API. Expected values not printed in an RFC were derived
//! independently with Python `hashlib`/`base64` over the hand-written
//! RFC 7638 §3.3 input, never with polyjose.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

use polyjose::Error;
use polyjose::jwk::Jwk;

/// RFC 7638 §3.1 modulus.
const RSA_N: &str = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
const RSA_TP: &str = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";
const URI_PREFIX: &str = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:";

fn jwk(json: &str) -> Jwk {
    Jwk::from_json(json.as_bytes()).unwrap_or_else(|e| panic!("rejected {json}: {e:?}"))
}

#[test]
fn rfc7638_3_1_example_with_alg_and_kid() {
    let key = jwk(&format!(
        r#"{{"kty":"RSA","n":"{RSA_N}","e":"AQAB","alg":"RS256","kid":"2011-04-29"}}"#
    ));
    assert_eq!(key.thumbprint_sha256(), RSA_TP);
}

#[test]
fn rfc9278_uri_format_and_example() {
    let key = jwk(&format!(r#"{{"kty":"RSA","n":"{RSA_N}","e":"AQAB"}}"#));
    let uri = key.thumbprint_uri_sha256();
    assert_eq!(uri, format!("{URI_PREFIX}{RSA_TP}"));
    // RFC 9278 §6 example, verbatim.
    assert_eq!(
        uri,
        "urn:ietf:params:oauth:jwk-thumbprint:sha-256:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
    );
}

#[test]
fn rfc8037_a3_ed25519() {
    let key = jwk(
        r#"{"kty":"OKP","crv":"Ed25519","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
        "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#,
    );
    // RFC 8037 A.3: 90facafea9b1556698540f70c0117a22ea37bd5cf3ed3c47093c1707282b4b89
    assert_eq!(
        key.thumbprint_sha256(),
        "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
    );
}

/// Every key type that has a private form: private == public thumbprint.
#[test]
fn private_equals_public_for_every_private_form() {
    let x25519_pub =
        r#""kty":"OKP","crv":"X25519","x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08""#;
    let ed_pub = r#""kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo""#;
    let p256 = r#""kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM""#;
    // The P-384 and secp256k1 generators G (SEC 2): import checks that a
    // point is on its curve (ADR 0041 §4).
    let p384 = r#""kty":"EC","crv":"P-384","x":"qofKIr6LBTeOscce8yCtdG4dO2KLp5uYWfdB4IJUKjhVAvJdv1UpbDpUXjhydgq3","y":"NhfeSpYmLG9dnpi_kpLcKfj0Hb0omhR86doxE7XwuMAKYLHOHX6BnXpDHXyQ6g5f""#;
    let k256 = r#""kty":"EC","crv":"secp256k1","x":"eb5mfvncu6xVoGKVzocLBwKb_NstzijZWfKBWxb4F5g","y":"SDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj_sQ1Lg""#;
    let p521 = r#""kty":"EC","crv":"P-521","x":"AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt","y":"AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1""#;
    // Each `d` is the private key of its point, since import checks the
    // pair (ADR 0043 §3): RFC 8037 A.1, RFC 7517 A.2, d = 1 for the
    // generators, RFC 7520 §3.2. X25519 pairs are not checked yet (feature
    // 0003); the RFC 7748 §6.1 key pair is used anyway.
    let d32 = "BwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSY";
    let ed_d = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";
    let p256_d = "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE";
    let one32 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE";
    let one48 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB";
    let d66 =
        "AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt";
    let cases = [
        (
            x25519_pub,
            d32,
            "giQqigT_IKcuzHl0FVJ3k5ts3_TWNAxvsC08UZsfcM8",
        ),
        (ed_pub, ed_d, "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"),
        (p256, p256_d, "cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s"),
        (p384, one48, "-W6Wzot_wuerYbKBVKfGEks3iY2EALna-hBqObnPuJE"),
        (k256, one32, "2JF8vg9etJzjFwZwmkvhBLLZ0bfMVVOPivYR5lFtcec"),
        (p521, d66, "dHri3SADZkrush5HU_50AoRhcKFryN-PI6jPBtPL55M"),
    ];
    for (public, d, expected) in cases {
        let public_key = jwk(&format!("{{{public}}}"));
        let private_key = jwk(&format!(r#"{{{public},"d":"{d}"}}"#));
        assert!(public_key.is_public() && !private_key.is_public());
        assert_eq!(public_key.thumbprint_sha256(), expected, "{public}");
        assert_eq!(private_key.thumbprint_sha256(), expected, "{public}");
        assert_eq!(
            private_key.thumbprint_uri_sha256(),
            format!("{URI_PREFIX}{expected}")
        );
    }
}

/// RSA has a private form too, but ADR 0021 rejects it until feature 0002:
/// the private thumbprint cannot be taken, and nothing leaks a path around it.
#[test]
fn rsa_private_form_is_rejected_not_hashed() {
    let json = format!(r#"{{"kty":"RSA","n":"{RSA_N}","e":"AQAB","d":"AQAB"}}"#);
    assert_eq!(
        Jwk::from_json(json.as_bytes()).err(),
        Some(Error::UnsupportedAlgorithm)
    );
}

/// RFC 7638 §3.2: EC coordinates keep their full fixed length, leading zero
/// octets included (P-256 with x[0] = 0, P-384 with two zero octets).
#[test]
fn ec_coordinates_keep_leading_zero_octets() {
    // 379·G on P-256, whose x begins with a zero octet (a real point:
    // import checks that it is on the curve, ADR 0041 §4).
    let p256 = jwk(
        r#"{"kty":"EC","crv":"P-256","x":"AFVDiUrz0A7X10Cr29dclrBod7eH219w7qeLkKjXwAo","y":"u0yFo9jqKe-q-iRAaRLdhNWxTcMr9lbvbGvVil2UP5I"}"#,
    );
    assert_eq!(
        p256.thumbprint_sha256(),
        "7Yxe6c_3bAa6kiaK1G-BZmi9EeNsUmlcbdnrtLeuK4E"
    );
}

/// RFC 7638 §3.3 / §7: only the exact required members, sorted, no whitespace.
/// Whitespace, member order and extra members in the input never matter, and
/// a missing required member yields no thumbprint at all.
#[test]
fn layout_of_the_input_does_not_matter_and_required_members_do() {
    let spaced = jwk(
        "{ \"kid\" : \"a\",\n \"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\t\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\"use\":\"enc\" , \"crv\" : \"P-256\" , \"kty\":\"EC\" }",
    );
    assert_eq!(
        spaced.thumbprint_sha256(),
        "cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s"
    );
    // A missing required member is a parse error: no partial thumbprint.
    assert!(
        Jwk::from_json(
            br#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4"}"#
        )
        .is_err()
    );
}

/// RFC 7638 §7: the thumbprint is unique only if the representation is
/// validated. Every non-canonical spelling is rejected before hashing, so no
/// second thumbprint exists for the same key.
#[test]
fn non_canonical_representations_are_rejected() {
    // RSA n with a leading zero octet (non-minimal Base64urlUInt).
    let mut n = vec![0u8];
    n.extend(decode(RSA_N));
    let leading_zero_n = format!(
        r#"{{"kty":"RSA","n":"{}","e":"AQAB"}}"#,
        polyjose::util::b64url_encode(&n)
    );
    assert!(Jwk::from_json(leading_zero_n.as_bytes()).is_err());
    // e = 00 01 00 01 (leading zeros), "AAEAAQ".
    let leading_zero_e = format!(r#"{{"kty":"RSA","n":"{RSA_N}","e":"AAEAAQ"}}"#);
    assert!(Jwk::from_json(leading_zero_e.as_bytes()).is_err());
    // Padded base64url.
    let padded = r#"{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg=="}"#;
    assert!(Jwk::from_json(padded.as_bytes()).is_err());
    // Non-zero trailing bits ("GawgguFyGrWKav7AX4VKUh" differs in pad bits).
    let trailing = r#"{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUh"}"#;
    assert!(Jwk::from_json(trailing.as_bytes()).is_err());
    // P-521 coordinate of 65 octets instead of 66.
    let short = polyjose::util::b64url_encode(&[1u8; 65]);
    let p521 = format!(r#"{{"kty":"EC","crv":"P-521","x":"{short}","y":"{short}"}}"#);
    assert!(Jwk::from_json(p521.as_bytes()).is_err());
}

fn decode(s: &str) -> Vec<u8> {
    polyjose::util::b64url_decode(s).expect("valid base64url")
}

/// RFC 7638 §3.2: `kty` and `crv` are hashed, so the same octets under another
/// type or curve have another thumbprint.
#[test]
fn kty_and_crv_are_part_of_the_input() {
    // The same 32 octets as an X25519 and as an Ed25519 key: RFC 8037 A.2's
    // `x`, a valid key of both kinds (ADR 0043 §1 rejects Ed25519 points
    // with a torsion component, such as RFC 8037 A.6 Bob's X25519 octets).
    let both = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
    let as_x25519 = jwk(&format!(r#"{{"kty":"OKP","crv":"X25519","x":"{both}"}}"#));
    let as_ed25519 = jwk(&format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{both}"}}"#));
    assert_ne!(
        as_x25519.thumbprint_sha256(),
        as_ed25519.thumbprint_sha256()
    );
    let x = "3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08";
    let a = jwk(&format!(r#"{{"kty":"OKP","crv":"X25519","x":"{x}"}}"#));
    assert_eq!(
        a.thumbprint_sha256(),
        "giQqigT_IKcuzHl0FVJ3k5ts3_TWNAxvsC08UZsfcM8"
    );
}

#[test]
fn oct_thumbprints_cover_only_k_and_kty() {
    let aes = jwk(r#"{"kty":"oct","alg":"A128KW","k":"GawgguFyGrWKav7AX4VKUg","kid":"x"}"#);
    assert_eq!(
        aes.thumbprint_sha256(),
        "k1JnWRfC-5zzmL72vXIuBgTLfVROXBakS4OmGcrMCoc"
    );
    let hmac = jwk(
        r#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#,
    );
    assert_eq!(
        hmac.thumbprint_sha256(),
        "y_x3gCJnL6oKGBBIXScabduwxTVy2Wd2bzRVEUbdUzc"
    );
}

/// The thumbprint and URI never reveal key material through `Debug`.
#[test]
fn debug_of_an_oct_key_does_not_contain_k() {
    let key = jwk(r#"{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}"#);
    let _ = key.thumbprint_sha256();
    assert!(!format!("{key:?}").contains("GawgguFyGrWKav7AX4VKUg"));
}
