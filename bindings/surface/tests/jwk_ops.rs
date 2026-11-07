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

#[test]
fn thumbprint_reproduces_rfc7638_section_3_1() {
    assert_eq!(
        jwk::jwk_thumbprint(RFC7638_RSA, "SHA-256").unwrap(),
        RFC7638_THUMBPRINT
    );
}

#[test]
fn thumbprint_uri_reproduces_rfc9278() {
    assert_eq!(
        jwk::jwk_thumbprint_uri(RFC7638_RSA, "SHA-256").unwrap(),
        RFC9278_URI
    );
}

#[test]
fn thumbprint_of_a_private_key_is_that_of_its_public_key() {
    // RFC 7638 §3.2.1, RFC 8037 Appendix A.3.
    for key in [RFC8037_A1_ED25519_PRIVATE, RFC8037_A2_ED25519_PUBLIC] {
        assert_eq!(
            jwk::jwk_thumbprint(key, "SHA-256").unwrap(),
            RFC8037_A3_THUMBPRINT
        );
        assert_eq!(
            jwk::jwk_thumbprint_uri(key, "SHA-256").unwrap(),
            format!("urn:ietf:params:oauth:jwk-thumbprint:sha-256:{RFC8037_A3_THUMBPRINT}")
        );
    }
    assert_eq!(
        jwk::jwk_thumbprint(RFC7517_A2_P256_PRIVATE, "SHA-256").unwrap(),
        jwk::jwk_thumbprint(RFC7517_A1_P256_PUBLIC, "SHA-256").unwrap()
    );
}

#[test]
fn every_hash_but_sha_256_is_unsupported_for_now() {
    // ADR 0022 (no SHA-1) and the T06 interim rule (lead, 2026-11-07): only SHA-256 until the
    // core gains SHA-384/SHA-512 thumbprints (feature 0015, task T14). Names are exact: the
    // RFC 9278 §4 lower-case form and other spellings are not ADR 0030 §4 hash names.
    for hash in [
        "SHA-384", "SHA-512", "SHA-1", "sha-256", "SHA256", "sha256", " SHA-256", "SHA-256 ", "",
        "MD5",
    ] {
        assert_eq!(
            code(jwk::jwk_thumbprint(RFC7638_RSA, hash)),
            "UnsupportedAlgorithm",
            "{hash:?}"
        );
        assert_eq!(
            code(jwk::jwk_thumbprint_uri(RFC7638_RSA, hash)),
            "UnsupportedAlgorithm",
            "{hash:?}"
        );
    }
}

#[test]
fn an_unknown_hash_is_reported_before_the_key_is_parsed() {
    // The hash name is checked first, so a bad key with a bad hash reports the hash.
    assert_eq!(
        code(jwk::jwk_thumbprint("{", "SHA-1")),
        "UnsupportedAlgorithm"
    );
    assert_eq!(
        code(jwk::jwk_thumbprint_uri("{", "SHA-1")),
        "UnsupportedAlgorithm"
    );
}

#[test]
fn thumbprint_reports_key_errors_with_the_core_codes() {
    assert_eq!(code(jwk::jwk_thumbprint("{", "SHA-256")), "InvalidJson");
    assert_eq!(code(jwk::jwk_thumbprint_uri("{", "SHA-256")), "InvalidJson");
    // The RSA private key is rejected before any hash is computed (ADR 0021).
    assert_eq!(
        code(jwk::jwk_thumbprint(RFC7517_A2_RSA_PRIVATE, "SHA-256")),
        "UnsupportedAlgorithm"
    );
}

#[test]
fn thumbprint_of_an_oct_key_hashes_k() {
    // RFC 7638 §3.2: the required members of an `oct` key are `k` and `kty`.
    assert_eq!(
        jwk::jwk_thumbprint(RFC7517_A3_OCT, "SHA-256").unwrap(),
        "y_x3gCJnL6oKGBBIXScabduwxTVy2Wd2bzRVEUbdUzc"
    );
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
