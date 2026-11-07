//! The JWK and key operations of the binding surface (ADR 0030 §4, "JWK"), through the public
//! surface API only, with RFC appendix values (feature 0013 T06).
//!
//! Every expected error code is the core's (ADR 0030 §5); where the surface itself rejects a
//! string (an unknown hash, curve or format name), the code is the one ADR 0030 §5 fixes.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

use polyjose_surface::records::JwkSelector;
use polyjose_surface::{SecretBytes, SecretString, SurfaceError, jwk, keys, util};

/// RFC 7517 Appendix A.2: the P-256 private key (with `use` and `kid`).
const RFC7517_A2_P256_PRIVATE: &str = r#"{"kty":"EC",
    "crv":"P-256",
    "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
    "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
    "d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
    "use":"enc",
    "kid":"1"}"#;

/// RFC 7517 Appendix A.1: the public half of [`RFC7517_A2_P256_PRIVATE`], in core member order.
const RFC7517_A1_P256_PUBLIC: &str = r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","use":"enc","kid":"1"}"#;

/// RFC 8037 Appendix A.1: the Ed25519 private key, `d` before `x` as the RFC prints it.
const RFC8037_A1_ED25519_PRIVATE: &str = r#"{"kty":"OKP","crv":"Ed25519",
    "d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
    "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;

/// RFC 8037 Appendix A.2: the Ed25519 public key.
const RFC8037_A2_ED25519_PUBLIC: &str =
    r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;

/// RFC 8037 Appendix A.3: the RFC 7638 thumbprint of the RFC 8037 A.1/A.2 key.
const RFC8037_A3_THUMBPRINT: &str = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";

/// RFC 7748 §6.1 / RFC 8037 Appendix A.6: Bob's X25519 private key.
const X25519_BOB_PRIVATE: &str = r#"{"kty":"OKP","crv":"X25519","kid":"Bob",
    "x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08",
    "d":"XasIfmJKikt54X-Lg4AO5m87sSkmGLb9HC-LJ_-I4Os"}"#;

/// RFC 7638 §3.1: the RSA public key of the thumbprint example.
const RFC7638_RSA: &str = r#"{"kty":"RSA",
    "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
    "e":"AQAB",
    "alg":"RS256",
    "kid":"2011-04-29"}"#;

/// RFC 7638 §3.1: the thumbprint of [`RFC7638_RSA`].
const RFC7638_THUMBPRINT: &str = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

/// RFC 9278 §3 (example in §6): the thumbprint URI of [`RFC7638_RSA`].
const RFC9278_URI: &str =
    "urn:ietf:params:oauth:jwk-thumbprint:sha-256:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

/// RFC 7517 Appendix A.3: the HMAC key of RFC 7515 Appendix A.1.
const RFC7517_A3_OCT: &str = r#"{"kty":"oct",
    "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
    "kid":"HMAC key used in JWS spec Appendix A.1 example"}"#;

/// RFC 7517 Appendix A.2: the RSA private key (RFC 7517 A.2 with `alg` and `kid`). RSA private
/// keys are not supported (ADR 0021).
const RFC7517_A2_RSA_PRIVATE: &str = r#"{"kty":"RSA",
    "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
    "e":"AQAB",
    "d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
    "p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
    "q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
    "dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
    "dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
    "qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
    "alg":"RS256",
    "kid":"2011-04-29"}"#;

/// The code of a failed surface call.
fn code<T: std::fmt::Debug>(result: Result<T, SurfaceError>) -> &'static str {
    result.unwrap_err().code()
}

// --- jwk_parse --------------------------------------------------------------------------------

#[test]
fn parse_returns_the_core_reserialization_in_core_member_order() {
    // RFC 7517 §4 / RFC 8037 §2: whitespace dropped, `kty` and the key-type members first, then
    // `use`, `kid` (Jwk::to_object order).
    let parsed: SecretString = jwk::jwk_parse(RFC7517_A2_P256_PRIVATE).unwrap();
    assert_eq!(
        parsed.as_str(),
        r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE","use":"enc","kid":"1"}"#
    );
    let parsed = jwk::jwk_parse(RFC8037_A1_ED25519_PRIVATE).unwrap();
    assert_eq!(
        parsed.as_str(),
        r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"}"#
    );
    // Parsing is idempotent: the core form parses to itself.
    assert_eq!(
        jwk::jwk_parse(parsed.as_str()).unwrap().as_str(),
        parsed.as_str()
    );
}

#[test]
fn parse_keeps_public_rsa_and_oct_keys() {
    let rsa = jwk::jwk_parse(RFC7638_RSA).unwrap();
    assert!(rsa.as_str().starts_with(r#"{"kty":"RSA","n":"0vx7"#));
    assert!(
        rsa.as_str()
            .ends_with(r#""e":"AQAB","alg":"RS256","kid":"2011-04-29"}"#)
    );
    let oct = jwk::jwk_parse(RFC7517_A3_OCT).unwrap();
    assert_eq!(
        oct.as_str(),
        r#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow","kid":"HMAC key used in JWS spec Appendix A.1 example"}"#
    );
}

#[test]
fn parse_rejects_an_rsa_private_key_as_unsupported() {
    // ADR 0021: RSA is public-key only.
    assert_eq!(
        code(jwk::jwk_parse(RFC7517_A2_RSA_PRIVATE)),
        "UnsupportedAlgorithm"
    );
}

#[test]
fn parse_reports_the_core_codes_for_bad_input() {
    // I-JSON (RFC 7493 §2.3): duplicate member names are rejected by the core parser.
    let duplicate = r#"{"kty":"oct","k":"c2VjcmV0","k":"c2VjcmV0"}"#;
    for (input, expected) in [
        ("", "InvalidJson"),
        ("[]", "InvalidJson"),
        ("{\"kty\":", "InvalidJson"),
        (duplicate, "InvalidJson"),
        (r#"{"crv":"P-256"}"#, "InvalidKey"),
        (r#"{"kty":"oct","k":"c2VjcmV0="}"#, "InvalidBase64"),
        (
            r#"{"kty":"EC","crv":"P-224","x":"AA","y":"AA"}"#,
            "UnsupportedAlgorithm",
        ),
    ] {
        assert_eq!(code(jwk::jwk_parse(input)), expected, "{input}");
    }
}

// --- jwk_to_public ----------------------------------------------------------------------------

#[test]
fn to_public_of_rfc7517_a2_is_rfc7517_a1() {
    let public: String = jwk::jwk_to_public(RFC7517_A2_P256_PRIVATE).unwrap();
    assert_eq!(public, RFC7517_A1_P256_PUBLIC);
}

#[test]
fn to_public_of_okp_private_keys_drops_d() {
    assert_eq!(
        jwk::jwk_to_public(RFC8037_A1_ED25519_PRIVATE).unwrap(),
        RFC8037_A2_ED25519_PUBLIC
    );
    assert_eq!(
        jwk::jwk_to_public(X25519_BOB_PRIVATE).unwrap(),
        r#"{"kty":"OKP","crv":"X25519","x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08","kid":"Bob"}"#
    );
}

#[test]
fn to_public_of_a_public_key_is_its_core_form() {
    assert_eq!(
        jwk::jwk_to_public(RFC7517_A1_P256_PUBLIC).unwrap(),
        RFC7517_A1_P256_PUBLIC
    );
    let rsa = jwk::jwk_to_public(RFC7638_RSA).unwrap();
    assert_eq!(rsa, jwk::jwk_parse(RFC7638_RSA).unwrap().as_str());
}

#[test]
fn to_public_drops_unknown_members() {
    // The core never publishes a member it cannot classify (Jwk::to_public).
    let with_extra = r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A","note":"x"}"#;
    assert_eq!(
        jwk::jwk_to_public(with_extra).unwrap(),
        RFC8037_A2_ED25519_PUBLIC
    );
}

#[test]
fn to_public_of_an_oct_key_is_unsupported() {
    // RFC 7518 §6.4: an `oct` key has no public part. The core's `Jwk::to_public` returns `None`
    // (no code of its own); the surface reports `UnsupportedAlgorithm`, the code the core gives
    // for exporting an `oct` key's public half as SPKI (ADR 0018 §3 format matrix).
    assert_eq!(
        code(jwk::jwk_to_public(RFC7517_A3_OCT)),
        "UnsupportedAlgorithm"
    );
}

#[test]
fn to_public_reports_parse_errors_with_the_core_codes() {
    assert_eq!(code(jwk::jwk_to_public("{")), "InvalidJson");
    assert_eq!(
        code(jwk::jwk_to_public(RFC7517_A2_RSA_PRIVATE)),
        "UnsupportedAlgorithm"
    );
}

// --- jwk_thumbprint / jwk_thumbprint_uri ------------------------------------------------------

/// The RFC 7638 §3.1 key's thumbprint with SHA-384 (RFC 7638 §3.4). No RFC prints it: the core's
/// known answer (ADR 0054 §8.4), recomputed for this test with Python's `hashlib.sha384` over the
/// hand-built RFC 7638 §3.3 input `{"e":"AQAB","kty":"RSA","n":"…"}`.
const RFC7638_THUMBPRINT_SHA384: &str =
    "R9_OfJjSjaw8Fuum86UzK5ixTdN9bo9BaqPSiseq89DWfmqCdpSgUHus-cxDUNc8";

/// As [`RFC7638_THUMBPRINT_SHA384`], with SHA-512 (`hashlib.sha512`).
const RFC7638_THUMBPRINT_SHA512: &str =
    "DpvEwocfn3FjeWWQjcJHzWrpKTIymKwgoL1xVgQcud48-qZDSRCr1zfWZQdHAJn_ciqXqPTSARyg-L-NyNGpVA";

/// The RFC 8037 A.2 key's thumbprint with SHA-384 (RFC 7638 §3.4): the core's known answer,
/// recomputed with `hashlib.sha384` over `{"crv":"Ed25519","kty":"OKP","x":"…"}` (RFC 8037 A.3's
/// input).
const RFC8037_THUMBPRINT_SHA384: &str =
    "ePy6LSb6I7JWK2uWQyYJQ4DBrwGE4QoxPl6INUviCtqplTLCwzo6fD9Eaw69Wvtt";

/// As [`RFC8037_THUMBPRINT_SHA384`], with SHA-512 (`hashlib.sha512`).
const RFC8037_THUMBPRINT_SHA512: &str =
    "SfSqAgfmPYvpuNzfHCiQXi6Mr51GG78hHopngoabsV9xvLR0hcUfVCoJLfyzi08Dbnds6kmcAt23CpNV-8qLTg";

/// The nine hash names the core's `ThumbprintHash::from_name` accepts (ADR 0054 §8.2), each with
/// the IANA Named Information name the URI carries (RFC 9278 §4) and the RFC 7638 §3.1 key's
/// thumbprint.
const HASH_NAMES: [(&str, &str, &str); 9] = [
    ("sha-256", "sha-256", RFC7638_THUMBPRINT),
    ("SHA-256", "sha-256", RFC7638_THUMBPRINT),
    ("sha256", "sha-256", RFC7638_THUMBPRINT),
    ("sha-384", "sha-384", RFC7638_THUMBPRINT_SHA384),
    ("SHA-384", "sha-384", RFC7638_THUMBPRINT_SHA384),
    ("sha384", "sha-384", RFC7638_THUMBPRINT_SHA384),
    ("sha-512", "sha-512", RFC7638_THUMBPRINT_SHA512),
    ("SHA-512", "sha-512", RFC7638_THUMBPRINT_SHA512),
    ("sha512", "sha-512", RFC7638_THUMBPRINT_SHA512),
];

#[test]
fn thumbprint_reproduces_rfc7638_section_3_1() {
    assert_eq!(
        jwk::jwk_thumbprint(RFC7638_RSA, Some("SHA-256")).unwrap(),
        RFC7638_THUMBPRINT
    );
}

#[test]
fn thumbprint_uri_reproduces_rfc9278() {
    assert_eq!(
        jwk::jwk_thumbprint_uri(RFC7638_RSA, Some("SHA-256")).unwrap(),
        RFC9278_URI
    );
}

#[test]
fn no_hash_is_the_core_default_sha_256() {
    // ADR 0054 §9 / ADR 0030 §3: an absent `hash` is the core's `ThumbprintHash::default()`,
    // SHA-256, the RFC 9278 §5 mandatory-to-implement hash (RFC 7638 §3.1, RFC 9278 §6).
    assert_eq!(
        jwk::jwk_thumbprint(RFC7638_RSA, None).unwrap(),
        RFC7638_THUMBPRINT
    );
    assert_eq!(
        jwk::jwk_thumbprint_uri(RFC7638_RSA, None).unwrap(),
        RFC9278_URI
    );
    assert_eq!(
        jwk::jwk_thumbprint(RFC8037_A2_ED25519_PUBLIC, None).unwrap(),
        RFC8037_A3_THUMBPRINT
    );
}

#[test]
fn every_core_hash_name_gives_its_hash_and_the_iana_name_in_the_uri() {
    // RFC 7638 §3.4 (the hash is the application's choice), ADR 0054 §8.2 (nine exact names)
    // and §8.3 / RFC 9278 §3-§4 (the URI always carries the IANA name).
    for (name, iana, thumbprint) in HASH_NAMES {
        assert_eq!(
            jwk::jwk_thumbprint(RFC7638_RSA, Some(name)).unwrap(),
            thumbprint,
            "{name}"
        );
        assert_eq!(
            jwk::jwk_thumbprint_uri(RFC7638_RSA, Some(name)).unwrap(),
            format!("urn:ietf:params:oauth:jwk-thumbprint:{iana}:{thumbprint}"),
            "{name}"
        );
    }
}

#[test]
fn thumbprint_lengths_are_those_of_the_hash() {
    // RFC 7638 §3 output, base64url without padding (RFC 7515 §2): 32, 48 and 64 octets.
    for (name, len) in [("sha-256", 43), ("sha-384", 64), ("sha-512", 86)] {
        assert_eq!(
            jwk::jwk_thumbprint(RFC7638_RSA, Some(name)).unwrap().len(),
            len
        );
    }
}

#[test]
fn thumbprint_of_a_private_key_is_that_of_its_public_key() {
    // RFC 7638 §3.2.1, RFC 8037 Appendix A.3, for every hash.
    for key in [RFC8037_A1_ED25519_PRIVATE, RFC8037_A2_ED25519_PUBLIC] {
        for (hash, iana, thumbprint) in [
            ("SHA-256", "sha-256", RFC8037_A3_THUMBPRINT),
            ("SHA-384", "sha-384", RFC8037_THUMBPRINT_SHA384),
            ("SHA-512", "sha-512", RFC8037_THUMBPRINT_SHA512),
        ] {
            assert_eq!(
                jwk::jwk_thumbprint(key, Some(hash)).unwrap(),
                thumbprint,
                "{hash}"
            );
            assert_eq!(
                jwk::jwk_thumbprint_uri(key, Some(hash)).unwrap(),
                format!("urn:ietf:params:oauth:jwk-thumbprint:{iana}:{thumbprint}")
            );
        }
    }
    for hash in [None, Some("SHA-384"), Some("SHA-512")] {
        assert_eq!(
            jwk::jwk_thumbprint(RFC7517_A2_P256_PRIVATE, hash).unwrap(),
            jwk::jwk_thumbprint(RFC7517_A1_P256_PUBLIC, hash).unwrap()
        );
    }
}

#[test]
fn every_other_hash_name_is_unsupported() {
    // ADR 0054 §8.2: the core matches exactly nine names, so SHA-1 in any spelling (ADR 0022),
    // truncated and SHA-3 hashes, other case forms and padded names fail with
    // `UnsupportedAlgorithm` (ADR 0030 §5), the core's code.
    for hash in [
        "SHA-1",
        "sha-1",
        "sha1",
        "SHA1",
        "sha-256-128",
        "sha3-256",
        "Sha-256",
        "SHA256",
        "Sha256",
        "SHA-384 ",
        " sha-512",
        "sha_256",
        "",
        "MD5",
    ] {
        assert_eq!(
            code(jwk::jwk_thumbprint(RFC7638_RSA, Some(hash))),
            "UnsupportedAlgorithm",
            "{hash:?}"
        );
        assert_eq!(
            code(jwk::jwk_thumbprint_uri(RFC7638_RSA, Some(hash))),
            "UnsupportedAlgorithm",
            "{hash:?}"
        );
    }
}

#[test]
fn an_unknown_hash_is_reported_before_the_key_is_parsed() {
    // The hash name is checked first, so a bad key with a bad hash reports the hash.
    assert_eq!(
        code(jwk::jwk_thumbprint("{", Some("SHA-1"))),
        "UnsupportedAlgorithm"
    );
    assert_eq!(
        code(jwk::jwk_thumbprint_uri("{", Some("SHA-1"))),
        "UnsupportedAlgorithm"
    );
}

#[test]
fn thumbprint_reports_key_errors_with_the_core_codes() {
    for hash in [None, Some("SHA-256"), Some("sha-512")] {
        assert_eq!(code(jwk::jwk_thumbprint("{", hash)), "InvalidJson");
        assert_eq!(code(jwk::jwk_thumbprint_uri("{", hash)), "InvalidJson");
        // The RSA private key is rejected before any hash is computed (ADR 0021).
        assert_eq!(
            code(jwk::jwk_thumbprint(RFC7517_A2_RSA_PRIVATE, hash)),
            "UnsupportedAlgorithm"
        );
    }
}

#[test]
fn thumbprint_of_an_oct_key_hashes_k() {
    // RFC 7638 §3.2: the required members of an `oct` key are `k` and `kty`.
    assert_eq!(
        jwk::jwk_thumbprint(RFC7517_A3_OCT, Some("SHA-256")).unwrap(),
        "y_x3gCJnL6oKGBBIXScabduwxTVy2Wd2bzRVEUbdUzc"
    );
}

#[test]
fn the_surface_has_no_hash_name_table_of_its_own() {
    // feature 0015 plan, "0013 T14 wiring note": the surface parses with the core's
    // `ThumbprintHash::from_name` (or takes `ThumbprintHash::default()`), so no hash name may
    // appear in its code outside comments.
    let source = include_str!("../src/jwk.rs");
    let code = code_without_comments(source);
    for name in [
        "sha-256", "sha-384", "sha-512", "sha256", "sha384", "sha512",
    ] {
        assert!(
            !code.to_ascii_lowercase().contains(name),
            "bindings/surface/src/jwk.rs names the hash {name} outside a comment"
        );
    }
    assert!(code.contains("ThumbprintHash::from_name"));
    assert!(code.contains("ThumbprintHash::default()"));
}

// --- jwks_select ------------------------------------------------------------------------------

#[test]
fn jwks_select_is_unsupported_until_the_core_selects() {
    // T06 interim rule (lead, 2026-11-07): the core has no general `JwkSet::select` yet
    // (feature 0015, task T14), so every call fails with `UnsupportedAlgorithm`.
    let jwks = format!(r#"{{"keys":[{RFC7517_A1_P256_PUBLIC},{RFC8037_A2_ED25519_PUBLIC}]}}"#);
    let selector = JwkSelector {
        kid: Some("1".to_owned()),
        alg: None,
        key_use: Some("enc".to_owned()),
    };
    assert_eq!(
        code(jwk::jwks_select(&jwks, &selector)),
        "UnsupportedAlgorithm"
    );
    assert_eq!(
        code(jwk::jwks_select(&jwks, &JwkSelector::default())),
        "UnsupportedAlgorithm"
    );
}

// --- jwk_generate_oct -------------------------------------------------------------------------

/// The `k` octets of a generated `oct` JWK, which the core writes as `{"kty":"oct","k":"…"}`
/// followed by `alg` when set (Jwk::to_object order).
fn oct_k(jwk: &SecretString) -> Vec<u8> {
    let rest = jwk.as_str().strip_prefix(r#"{"kty":"oct","k":""#).unwrap();
    let end = rest.find('"').unwrap();
    util::base64url_decode(&rest[..end]).unwrap()
}

#[test]
fn generate_oct_accepts_the_core_range() {
    // RFC 7518 §6.4.1; ADR 0018 §5: 16 to 512 octets, from the OS CSPRNG (ADR 0005).
    for len in [16, 17, 32, 64, 511, 512] {
        let key: SecretString = keys::jwk_generate_oct(len).unwrap();
        assert_eq!(oct_k(&key).len(), len as usize, "{len}");
        assert!(!key.as_str().contains(r#""alg""#), "no alg member: {len}");
        // The result is a valid JWK in core form.
        assert_eq!(jwk::jwk_parse(key.as_str()).unwrap().as_str(), key.as_str());
    }
}

#[test]
fn generate_oct_draws_fresh_randomness() {
    let a = keys::jwk_generate_oct(32).unwrap();
    let b = keys::jwk_generate_oct(32).unwrap();
    assert_ne!(oct_k(&a), oct_k(&b));
}

#[test]
fn generate_oct_rejects_other_lengths_with_invalid_key() {
    for len in [0, 1, 15, 513, 4096, u32::MAX] {
        assert_eq!(code(keys::jwk_generate_oct(len)), "InvalidKey", "{len}");
    }
}

// --- jwk_generate_ec / jwk_generate_okp -------------------------------------------------------

#[test]
fn generate_ec_accepts_exactly_the_four_curves() {
    // RFC 7518 §6.2.1.1, RFC 8812 §3.1; ADR 0030 §4.
    for crv in ["P-256", "P-384", "P-521", "secp256k1"] {
        let key = keys::jwk_generate_ec(crv).unwrap();
        let prefix = format!(r#"{{"kty":"EC","crv":"{crv}","x":""#);
        assert!(key.as_str().starts_with(&prefix), "{crv}");
        assert!(key.as_str().contains(r#","d":""#), "{crv} is private");
        assert_eq!(jwk::jwk_parse(key.as_str()).unwrap().as_str(), key.as_str());
        assert!(!jwk::jwk_to_public(key.as_str()).unwrap().contains(r#""d""#));
    }
}

#[test]
fn generate_ec_rejects_other_curve_names() {
    for crv in [
        "P-224",
        "p-256",
        "P256",
        "secp256r1",
        "Ed25519",
        "X25519",
        "brainpoolP256r1",
        "",
        "P-256 ",
    ] {
        assert_eq!(
            code(keys::jwk_generate_ec(crv)),
            "UnsupportedAlgorithm",
            "{crv:?}"
        );
    }
}

#[test]
fn generate_okp_accepts_exactly_ed25519_and_x25519() {
    // RFC 8037 §2; ADR 0030 §4.
    for crv in ["Ed25519", "X25519"] {
        let key = keys::jwk_generate_okp(crv).unwrap();
        let prefix = format!(r#"{{"kty":"OKP","crv":"{crv}","x":""#);
        assert!(key.as_str().starts_with(&prefix), "{crv}");
        assert!(key.as_str().contains(r#","d":""#), "{crv} is private");
        assert_eq!(jwk::jwk_parse(key.as_str()).unwrap().as_str(), key.as_str());
    }
}

#[test]
fn generate_okp_rejects_other_curve_names() {
    // Ed448 and X448 are registered (RFC 8037 §5) but out of scope (ADR 0006).
    for crv in ["Ed448", "X448", "ed25519", "x25519", "P-256", "EdDSA", ""] {
        assert_eq!(
            code(keys::jwk_generate_okp(crv)),
            "UnsupportedAlgorithm",
            "{crv:?}"
        );
    }
}

// --- jwk_generate_for_alg ---------------------------------------------------------------------

#[test]
fn generate_for_alg_follows_the_core_table() {
    // The 0005 `generate_for` table (RFC 7518 §3.2, §3.4, §4.4, §4.7, §5.2.3-§5.2.5, §5.3;
    // RFC 8812 §3.2; RFC 8037 §3.1; RFC 9864), with `alg` bound (RFC 7517 §4.4).
    for (alg, len) in [
        ("HS256", 32),
        ("HS384", 48),
        ("HS512", 64),
        ("A128KW", 16),
        ("A192KW", 24),
        ("A256KW", 32),
        ("A128GCMKW", 16),
        ("A192GCMKW", 24),
        ("A256GCMKW", 32),
        ("A128GCM", 16),
        ("A192GCM", 24),
        ("A256GCM", 32),
        ("A128CBC-HS256", 32),
        ("A192CBC-HS384", 48),
        ("A256CBC-HS512", 64),
    ] {
        let key = keys::jwk_generate_for_alg(alg).unwrap();
        assert_eq!(oct_k(&key).len(), len, "{alg}");
        assert!(
            key.as_str().ends_with(&format!(r#","alg":"{alg}"}}"#)),
            "{alg}"
        );
    }
    for (alg, kty, crv) in [
        ("ES256", "EC", "P-256"),
        ("ES384", "EC", "P-384"),
        ("ES512", "EC", "P-521"),
        ("ES256K", "EC", "secp256k1"),
        ("EdDSA", "OKP", "Ed25519"),
        ("Ed25519", "OKP", "Ed25519"),
    ] {
        let key = keys::jwk_generate_for_alg(alg).unwrap();
        let prefix = format!(r#"{{"kty":"{kty}","crv":"{crv}","x":""#);
        assert!(key.as_str().starts_with(&prefix), "{alg}");
        assert!(
            key.as_str().ends_with(&format!(r#","alg":"{alg}"}}"#)),
            "{alg}"
        );
    }
}

#[test]
fn generate_for_alg_rejects_what_the_core_rejects() {
    // ADR 0021 (no RSA key generation), ADR 0022 (`RSA-OAEP`), passwords are not generated
    // (`PBES2-*`), `dir` depends on `enc`, `none` has no key, names are case-sensitive
    // (RFC 7515 §4.1.1), and unknown names are unsupported.
    for alg in [
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "RSA-OAEP-256",
        "RSA-OAEP",
        "RSA1_5",
        "PBES2-HS256+A128KW",
        "PBES2-HS384+A192KW",
        "PBES2-HS512+A256KW",
        "dir",
        "none",
        "Ed448",
        "es256",
        "",
    ] {
        assert_eq!(
            code(keys::jwk_generate_for_alg(alg)),
            "UnsupportedAlgorithm",
            "{alg:?}"
        );
    }
}

#[test]
fn generate_for_alg_leaves_the_ecdh_es_curve_to_the_caller() {
    // The core decides: ECDH-ES works on several curves, so a request without one is
    // `InvalidKey("curve required")`, never a default curve (0005 `generate_for`).
    for alg in [
        "ECDH-ES",
        "ECDH-ES+A128KW",
        "ECDH-ES+A192KW",
        "ECDH-ES+A256KW",
    ] {
        assert_eq!(code(keys::jwk_generate_for_alg(alg)), "InvalidKey", "{alg}");
    }
}

// --- jwk_from_pem / jwk_from_der / jwk_to_pem / jwk_to_der ------------------------------------

/// One committed 0005 key fixture (OpenSSL 4.1.0, `crates/polyjose/tests/data/keys/openssl`): its
/// PEM, its DER, the format both are in, and the JWK the core reads from them.
struct Fixture {
    name: &'static str,
    format: &'static str,
    pem: &'static str,
    der: &'static [u8],
    jwk: &'static str,
}

macro_rules! fixture {
    ($name:literal, $format:literal) => {
        fixture!($name, $name, $format)
    };
    ($name:literal, $file:literal, $format:literal) => {
        Fixture {
            name: $name,
            format: $format,
            pem: include_str!(concat!(
                "../../../crates/polyjose/tests/data/keys/openssl/",
                $file,
                ".pem"
            )),
            der: include_bytes!(concat!(
                "../../../crates/polyjose/tests/data/keys/openssl/",
                $file,
                ".der"
            )),
            jwk: include_str!(concat!(
                "../../../crates/polyjose/tests/data/keys/openssl/expected/",
                $file,
                ".jwk.json"
            )),
        }
    };
}

/// Every 0005 fixture type: EC on the four curves in PKCS#8 (RFC 5958 §2), SEC1 (RFC 5915 §3)
/// and SPKI (RFC 5280 §4.1.2.7); Ed25519 and X25519 in PKCS#8 and SPKI (RFC 8410 §4, §7); the
/// RSA public key in SPKI and PKCS#1 (RFC 8017 App. A.1.1).
fn fixtures() -> [Fixture; 18] {
    [
        fixture!("ec-p256-pkcs8", "pkcs8"),
        fixture!("ec-p256-sec1", "sec1"),
        fixture!("ec-p256-spki", "spki"),
        fixture!("ec-p384-pkcs8", "pkcs8"),
        fixture!("ec-p384-sec1", "sec1"),
        fixture!("ec-p384-spki", "spki"),
        fixture!("ec-p521-pkcs8", "pkcs8"),
        fixture!("ec-p521-sec1", "sec1"),
        fixture!("ec-p521-spki", "spki"),
        fixture!("ec-secp256k1-pkcs8", "pkcs8"),
        fixture!("ec-secp256k1-sec1", "sec1"),
        fixture!("ec-secp256k1-spki", "spki"),
        fixture!("ed25519-pkcs8", "pkcs8"),
        fixture!("ed25519-spki", "spki"),
        fixture!("x25519-pkcs8", "pkcs8"),
        fixture!("x25519-spki", "spki"),
        fixture!("rsa2048-spki", "spki"),
        fixture!("rsa2048-pkcs1-pub", "pkcs1"),
    ]
}

#[test]
fn from_pem_reads_every_fixture_type_to_its_jwk() {
    for f in fixtures() {
        let key: SecretString = keys::jwk_from_pem(f.pem).unwrap();
        assert_eq!(
            key.as_str(),
            jwk::jwk_parse(f.jwk).unwrap().as_str(),
            "{}",
            f.name
        );
    }
}

#[test]
fn from_der_reads_every_fixture_type_to_its_jwk() {
    for f in fixtures() {
        let key: SecretString = keys::jwk_from_der(f.der, f.format).unwrap();
        assert_eq!(
            key.as_str(),
            jwk::jwk_parse(f.jwk).unwrap().as_str(),
            "{}",
            f.name
        );
    }
}

#[test]
fn every_fixture_type_round_trips_byte_for_byte() {
    // ADR 0018 §3: export writes the layout OpenSSL writes, so PEM -> JWK -> PEM and
    // DER -> JWK -> DER reproduce the fixture exactly (RFC 7468 §2 for the PEM framing).
    for f in fixtures() {
        let key = keys::jwk_from_pem(f.pem).unwrap();
        let pem: SecretString = keys::jwk_to_pem(key.as_str(), f.format).unwrap();
        assert_eq!(pem.as_str(), f.pem, "{}", f.name);
        let der: SecretBytes = keys::jwk_to_der(key.as_str(), f.format).unwrap();
        assert_eq!(der.as_bytes(), f.der, "{}", f.name);
        let again = keys::jwk_from_der(der.as_bytes(), f.format).unwrap();
        assert_eq!(again.as_str(), key.as_str(), "{}", f.name);
    }
}

#[test]
fn a_private_key_exports_its_public_half_as_spki() {
    // RFC 5280 §4.1.2.7: SPKI holds the public key; each curve's fixtures are one key.
    for f in fixtures().iter().filter(|f| f.format == "pkcs8") {
        let spki_name = f.name.replace("pkcs8", "spki");
        let spki = fixtures()
            .into_iter()
            .find(|g| g.name == spki_name)
            .unwrap();
        let pem = keys::jwk_to_pem(f.jwk, "spki").unwrap();
        assert_eq!(pem.as_str(), spki.pem, "{}", f.name);
        let public = jwk::jwk_to_public(f.jwk).unwrap();
        assert_eq!(
            keys::jwk_from_pem(spki.pem).unwrap().as_str(),
            public,
            "{}",
            f.name
        );
    }
}

#[test]
fn generated_keys_round_trip_through_pkcs8() {
    for key in [
        keys::jwk_generate_ec("P-256").unwrap(),
        keys::jwk_generate_ec("secp256k1").unwrap(),
        keys::jwk_generate_okp("Ed25519").unwrap(),
        keys::jwk_generate_okp("X25519").unwrap(),
    ] {
        let der = keys::jwk_to_der(key.as_str(), "pkcs8").unwrap();
        let back = keys::jwk_from_der(der.as_bytes(), "pkcs8").unwrap();
        assert_eq!(back.as_str(), key.as_str());
    }
}

#[test]
fn only_the_four_format_names_are_accepted() {
    // ADR 0030 §4 names `pkcs8`, `sec1`, `spki` and `pkcs1`, matched exactly; anything else is
    // `UnsupportedAlgorithm` (ADR 0030 §5), checked before the key or the DER is looked at.
    let f = &fixtures()[0];
    for format in [
        "PKCS8",
        "pkcs#8",
        "PKCS#8",
        "der",
        "pem",
        "x509",
        "spki ",
        "",
        "jwk",
        "pkcs1-private",
    ] {
        assert_eq!(
            code(keys::jwk_from_der(f.der, format)),
            "UnsupportedAlgorithm",
            "{format:?}"
        );
        assert_eq!(
            code(keys::jwk_to_pem(f.jwk, format)),
            "UnsupportedAlgorithm",
            "{format:?}"
        );
        assert_eq!(
            code(keys::jwk_to_der(f.jwk, format)),
            "UnsupportedAlgorithm",
            "{format:?}"
        );
        assert_eq!(
            code(keys::jwk_from_der(b"", format)),
            "UnsupportedAlgorithm",
            "{format:?}"
        );
        assert_eq!(
            code(keys::jwk_to_pem("{", format)),
            "UnsupportedAlgorithm",
            "{format:?}"
        );
        assert_eq!(
            code(keys::jwk_to_der("{", format)),
            "UnsupportedAlgorithm",
            "{format:?}"
        );
    }
}

#[test]
fn import_rejects_what_the_core_rejects() {
    for (name, pem, expected) in [
        // ADR 0021: RSA private keys in any form.
        (
            "rsa private pkcs8",
            include_str!(
                "../../../crates/polyjose/tests/data/keys/openssl/reject-rsa2048-private-pkcs8.pem"
            ),
            "UnsupportedAlgorithm",
        ),
        (
            "rsa private pkcs1",
            include_str!(
                "../../../crates/polyjose/tests/data/keys/openssl/reject-rsa2048-private-pkcs1.pem"
            ),
            "UnsupportedAlgorithm",
        ),
        // ADR 0018 §4: encrypted keys are out of scope (RFC 5958 §3).
        (
            "encrypted pkcs8",
            include_str!(
                "../../../crates/polyjose/tests/data/keys/openssl/reject-ec-p256-pkcs8-encrypted.pem"
            ),
            "UnsupportedAlgorithm",
        ),
        // RFC 7468 §5: a certificate is not a key.
        (
            "certificate",
            include_str!(
                "../../../crates/polyjose/tests/data/keys/openssl/reject-ec-p256-cert.pem"
            ),
            "UnsupportedAlgorithm",
        ),
        (
            "not pem",
            "-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n",
            "InvalidKey",
        ),
        ("empty", "", "InvalidKey"),
    ] {
        assert_eq!(code(keys::jwk_from_pem(pem)), expected, "{name}");
    }
    let spki = &fixtures()[2];
    assert_eq!(spki.format, "spki");
    // DER of another structure than the named format (ADR 0018 §3: no sniffing).
    assert_eq!(code(keys::jwk_from_der(spki.der, "pkcs8")), "InvalidKey");
    assert_eq!(code(keys::jwk_from_der(spki.der, "sec1")), "InvalidKey");
    assert_eq!(code(keys::jwk_from_der(b"", "spki")), "InvalidKey");
    assert_eq!(
        code(keys::jwk_from_der(
            include_bytes!(
                "../../../crates/polyjose/tests/data/keys/openssl/reject-rsa2048-private-pkcs8.der"
            ),
            "pkcs8"
        )),
        "UnsupportedAlgorithm"
    );
}

#[test]
fn export_rejects_what_the_core_rejects() {
    // ADR 0018 §3 format matrix, in the core's check order.
    let ec_private = fixtures()[0].jwk;
    for (name, key, format, expected) in [
        ("oct pkcs8", RFC7517_A3_OCT, "pkcs8", "UnsupportedAlgorithm"),
        ("oct spki", RFC7517_A3_OCT, "spki", "UnsupportedAlgorithm"),
        (
            "ed25519 sec1",
            RFC8037_A1_ED25519_PRIVATE,
            "sec1",
            "UnsupportedAlgorithm",
        ),
        ("ec pkcs1", ec_private, "pkcs1", "UnsupportedAlgorithm"),
        (
            "ec public pkcs8",
            RFC7517_A1_P256_PUBLIC,
            "pkcs8",
            "InvalidKey",
        ),
        (
            "ec public sec1",
            RFC7517_A1_P256_PUBLIC,
            "sec1",
            "InvalidKey",
        ),
        ("rsa pkcs8", RFC7638_RSA, "pkcs8", "InvalidKey"),
        (
            "rsa private",
            RFC7517_A2_RSA_PRIVATE,
            "spki",
            "UnsupportedAlgorithm",
        ),
        ("bad json", "{", "spki", "InvalidJson"),
    ] {
        assert_eq!(code(keys::jwk_to_pem(key, format)), expected, "{name}");
        assert_eq!(code(keys::jwk_to_der(key, format)), expected, "{name}");
    }
}

// --- Defaults stay in the core (ADR 0030 §3) --------------------------------------------------

/// The core defaults no surface code may restate (ADR 0030 §3): the PBES2 bound (10,000,
/// ADR 0023), the DEFLATE cap (250,000, ADR 0017), the input limits (1 MiB = 1,048,576, and
/// 1,000,000) and the signature and recipient counts (16, ADR 0026 §7). 16 is also the core's
/// shortest generated `oct` key.
const CORE_DEFAULTS: [u128; 5] = [10_000, 1_000_000, 250_000, 1_048_576, 16];

/// `source` with its comments (line, doc and nested block comments) replaced by a space, and
/// string, raw-string and character literals kept, so a `//` inside a string is not a comment.
fn code_without_comments(source: &str) -> String {
    let c: Vec<char> = source.chars().collect();
    let mut out = String::with_capacity(source.len());
    let mut i = 0;
    let ident = |ch: char| ch.is_alphanumeric() || ch == '_';
    while i < c.len() {
        let next = c.get(i + 1).copied();
        if c[i] == '/' && next == Some('/') {
            while i < c.len() && c[i] != '\n' {
                i += 1;
            }
            out.push(' ');
        } else if c[i] == '/' && next == Some('*') {
            let mut depth = 0;
            while i < c.len() {
                if c[i] == '/' && c.get(i + 1) == Some(&'*') {
                    depth += 1;
                    i += 2;
                } else if c[i] == '*' && c.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
            out.push(' ');
        } else if c[i] == 'r'
            && (i == 0 || !ident(c[i - 1]))
            && matches!(next, Some('"') | Some('#'))
            && {
                let hashes = c[i + 1..].iter().take_while(|&&ch| ch == '#').count();
                c.get(i + 1 + hashes) == Some(&'"')
            }
        {
            // A raw string r#"..."#: ends at a quote followed by the same number of hashes.
            let hashes = c[i + 1..].iter().take_while(|&&ch| ch == '#').count();
            let start = i;
            i += 2 + hashes;
            while i < c.len() {
                if c[i] == '"'
                    && c[i + 1..]
                        .iter()
                        .take(hashes)
                        .filter(|&&ch| ch == '#')
                        .count()
                        == hashes
                {
                    i += 1 + hashes;
                    break;
                }
                i += 1;
            }
            out.extend(&c[start..i.min(c.len())]);
        } else if c[i] == '"' {
            let start = i;
            i += 1;
            while i < c.len() && c[i] != '"' {
                i += if c[i] == '\\' { 2 } else { 1 };
            }
            i += 1;
            out.extend(&c[start..i.min(c.len())]);
        } else if c[i] == '\'' && next == Some('\\') {
            // An escaped character literal such as '\n' or '\''.
            let start = i;
            i += 3;
            while i < c.len() && c[i] != '\'' {
                i += 1;
            }
            i += 1;
            out.extend(&c[start..i.min(c.len())]);
        } else if c[i] == '\'' && c.get(i + 2) == Some(&'\'') {
            out.extend(&c[i..i + 3]);
            i += 3;
        } else {
            out.push(c[i]);
            i += 1;
        }
    }
    out
}

/// The value of every integer literal in `code`, in any radix, with `_` separators and type
/// suffixes removed (`16`, `0x10`, `16usize`, `1_048_576_u32`).
fn integer_literals(code: &str) -> Vec<u128> {
    let c: Vec<char> = code.chars().collect();
    let mut values = Vec::new();
    let mut i = 0;
    while i < c.len() {
        let starts = c[i].is_ascii_digit()
            && (i == 0 || !(c[i - 1].is_alphanumeric() || c[i - 1] == '_' || c[i - 1] == '.'));
        if !starts {
            i += 1;
            continue;
        }
        let start = i;
        while i < c.len() && (c[i].is_ascii_alphanumeric() || c[i] == '_') {
            i += 1;
        }
        let token: String = c[start..i].iter().filter(|&&ch| ch != '_').collect();
        let (radix, digits) = match token.get(..2) {
            Some("0x") => (16, &token[2..]),
            Some("0o") => (8, &token[2..]),
            Some("0b") => (2, &token[2..]),
            _ => (10, token.as_str()),
        };
        let end = digits.find(['u', 'i']).unwrap_or(digits.len());
        if let Ok(value) = u128::from_str_radix(&digits[..end], radix) {
            values.push(value);
        }
    }
    values
}

#[test]
fn the_literal_scanner_ignores_comments_and_reads_every_radix() {
    let sample = r##"
        // 16 in a line comment
        /// 1048576 in a doc comment
        /* 10000 /* nested 250000 */ still 16 */
        let url = "https://example.com"; let a = 16usize;
        let b = r#"// not a comment"#; let c = 0x10; let d = 1_048_576_u32;
        let e: &'static str = "x"; let f = '\''; let g = 'a'; let h = 1000000i64;
        let p256 = "P-256"; let size = u16::MAX; let k = 7;
    "##;
    let code = code_without_comments(sample);
    assert!(code.contains("https://example.com"));
    assert!(code.contains("// not a comment"));
    assert!(!code.contains("in a line comment"));
    assert!(!code.contains("still"));
    // Digits inside string literals count: they are code, not comments ("P-256" gives 256).
    assert_eq!(
        integer_literals(&code),
        [16, 16, 1_048_576, 1_000_000, 256, 7]
    );
}

#[test]
fn no_surface_source_restates_a_core_default() {
    // Every file of `bindings/surface/src`, not only this task's: the rule is the surface's
    // (ADR 0030 §1, §3; feature 0013 T06-T08 acceptance criteria).
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .collect();
    files.sort();
    assert!(
        files.len() >= 9,
        "expected the surface modules in {}",
        dir.display()
    );
    for path in files {
        let source = std::fs::read_to_string(&path).unwrap();
        let code = code_without_comments(&source);
        for value in integer_literals(&code) {
            assert!(
                !CORE_DEFAULTS.contains(&value),
                "{} restates the core default {value} outside a comment (ADR 0030 §3)",
                path.display()
            );
        }
    }
}

// --- No input in errors (ADR 0030 §5) ---------------------------------------------------------

/// A distinctive value standing in for key material (the surface's and the core's marker style).
const MARKER: &str = "pj-SECRET-marker-7f3a";

fn assert_no_marker<T: std::fmt::Debug>(what: &str, result: Result<T, SurfaceError>) {
    let err = result.expect_err(what);
    let encoded = util::base64url_encode(MARKER.as_bytes());
    for rendered in [
        err.code().to_owned(),
        err.message().to_owned(),
        err.to_string(),
        format!("{err:?}"),
        format!("{err:#?}"),
    ] {
        for needle in [MARKER, encoded.as_str()] {
            assert!(
                !rendered.contains(needle),
                "{what}: error leaks input: {rendered}"
            );
        }
    }
}

#[test]
fn no_failing_path_puts_a_marked_private_member_into_its_error() {
    let marked_b64 = util::base64url_encode(MARKER.as_bytes());
    // Private members holding the marker: as raw text (21 characters, a length no base64url
    // has), base64url-encoded in a well-formed `oct` key (which parses, then fails later), in an
    // RSA private key (ADR 0021), and next to a JSON syntax error, where a quoting parser would
    // echo it.
    let marked_ec = format!(
        r#"{{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","d":"{MARKER}"}}"#
    );
    let marked_okp =
        format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{MARKER}","d":"{marked_b64}"}}"#);
    let marked_oct = format!(r#"{{"kty":"oct","k":"{marked_b64}"}}"#);
    let marked_oct_raw = format!(r#"{{"kty":"oct","k":"{MARKER}"}}"#);
    let marked_rsa =
        RFC7517_A2_RSA_PRIVATE.replace(r#""kid":"2011-04-29""#, &format!(r#""p2":"{marked_b64}""#));
    let marked_json = format!(r#"{{"kty":"oct","k":"{MARKER}" {MARKER}}}"#);
    let marked_keys = [
        &marked_ec,
        &marked_okp,
        &marked_oct_raw,
        &marked_rsa,
        &marked_json,
    ];

    for key in marked_keys {
        assert_no_marker("jwk_parse", jwk::jwk_parse(key));
        assert_no_marker("jwk_to_public", jwk::jwk_to_public(key));
        assert_no_marker("jwk_thumbprint", jwk::jwk_thumbprint(key, Some("SHA-256")));
        assert_no_marker("jwk_thumbprint", jwk::jwk_thumbprint(key, None));
        assert_no_marker(
            "jwk_thumbprint_uri",
            jwk::jwk_thumbprint_uri(key, Some("SHA-512")),
        );
        for format in ["pkcs8", "sec1", "spki", "pkcs1"] {
            assert_no_marker("jwk_to_pem", keys::jwk_to_pem(key, format));
            assert_no_marker("jwk_to_der", keys::jwk_to_der(key, format));
        }
    }

    // A well-formed secret key on the paths that fail after parsing.
    assert_no_marker("jwk_to_public oct", jwk::jwk_to_public(&marked_oct));
    for format in ["pkcs8", "spki", MARKER] {
        assert_no_marker("jwk_to_pem oct", keys::jwk_to_pem(&marked_oct, format));
        assert_no_marker("jwk_to_der oct", keys::jwk_to_der(&marked_oct, format));
    }
    for hash in ["SHA-1", "Sha-384", MARKER] {
        assert_no_marker(
            "jwk_thumbprint hash",
            jwk::jwk_thumbprint(&marked_oct, Some(hash)),
        );
        assert_no_marker(
            "jwk_thumbprint_uri hash",
            jwk::jwk_thumbprint_uri(&marked_oct, Some(hash)),
        );
    }

    // JWK Sets holding the marked keys.
    let jwks = format!(r#"{{"keys":[{marked_oct},{marked_ec}]}}"#);
    let selector = JwkSelector {
        kid: Some(MARKER.to_owned()),
        alg: Some(MARKER.to_owned()),
        key_use: Some(MARKER.to_owned()),
    };
    assert_no_marker("jwks_select", jwk::jwks_select(&jwks, &selector));
    assert_no_marker(
        "jwks_select",
        jwk::jwks_select(&marked_json, &JwkSelector::default()),
    );

    // PEM and DER carrying the marker: in the base64 body, in the label, and as the DER itself.
    let pem_body = format!("-----BEGIN PRIVATE KEY-----\n{MARKER}\n-----END PRIVATE KEY-----\n");
    let pem_label = format!("-----BEGIN {MARKER}-----\nMAA=\n-----END {MARKER}-----\n");
    for pem in [pem_body.as_str(), pem_label.as_str(), MARKER] {
        assert_no_marker("jwk_from_pem", keys::jwk_from_pem(pem));
    }
    for format in ["pkcs8", "sec1", "spki", "pkcs1", MARKER] {
        assert_no_marker(
            "jwk_from_der",
            keys::jwk_from_der(MARKER.as_bytes(), format),
        );
    }

    // Marked names on the generation paths.
    assert_no_marker("jwk_generate_ec", keys::jwk_generate_ec(MARKER));
    assert_no_marker("jwk_generate_okp", keys::jwk_generate_okp(MARKER));
    assert_no_marker("jwk_generate_for_alg", keys::jwk_generate_for_alg(MARKER));
}
