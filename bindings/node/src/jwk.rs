//! The JWK operations (ADR 0030 §4, "JWK"): `jwkParse`, `jwkToPublic`, `jwkThumbprint`,
//! `jwkThumbprintUri`, `jwksSelect` (RFC 7517, RFC 7638, RFC 9278).
//!
//! Each `#[napi]` function copies its arguments into a task on the JS thread and returns a Promise
//! (the private `task` module). JWKs and JWK Sets may be private, so they are held in `Zeroizing` fields;
//! a result that can be private (`jwkParse`, `jwksSelect`) is created from the surface's
//! `SecretString` (ADR 0030 §7).

use napi::bindgen_prelude::AsyncTask;
use napi_derive::napi;
use polyjose_surface::SecretString;
use polyjose_surface::jwk as op;
use polyjose_surface::records as surface;
use zeroize::Zeroizing;

use crate::records::JwkSelector;
use crate::task::surface_task;

surface_task! {
    /// `jwkParse`: the JWK validated and re-serialized by the core (RFC 7517 §4, RFC 7518 §6,
    /// RFC 8037 §2).
    JwkParseTask { jwk: Zeroizing<String> } -> SecretString
        = |t| op::jwk_parse(&t.jwk)
}

/// Validates `jwk` and returns it re-serialized by the core, members in core order (RFC 7517 §4,
/// RFC 7518 §6, RFC 8037 §2). Resolves to JWK JSON text.
#[napi]
pub fn jwk_parse(jwk: String) -> AsyncTask<JwkParseTask> {
    AsyncTask::new(JwkParseTask {
        jwk: Zeroizing::new(jwk),
    })
}

surface_task! {
    /// `jwkToPublic`: the JWK with its private members removed (RFC 7517 §4, RFC 7518 §6.2.2,
    /// §6.3.2, RFC 8037 §2). The result holds no secret.
    JwkToPublicTask { jwk: Zeroizing<String> } -> String
        = |t| op::jwk_to_public(&t.jwk)
}

/// The public form of `jwk` (RFC 7517 §4, RFC 7518 §6.2.2, §6.3.2, RFC 8037 §2); an `oct` key
/// has none and rejects with `UnsupportedAlgorithm`. Resolves to JWK JSON text.
#[napi]
pub fn jwk_to_public(jwk: String) -> AsyncTask<JwkToPublicTask> {
    AsyncTask::new(JwkToPublicTask {
        jwk: Zeroizing::new(jwk),
    })
}

surface_task! {
    /// `jwkThumbprint`: the RFC 7638 §3 thumbprint, base64url (RFC 7515 §2).
    JwkThumbprintTask { jwk: Zeroizing<String>, hash: Option<String> } -> String
        = |t| op::jwk_thumbprint(&t.jwk, t.hash.as_deref())
}

/// The JWK Thumbprint of `jwk` under `hash`, base64url-encoded (RFC 7638 §3, RFC 9278 §5).
///
/// `hash` is optional and passed on unchanged (ADR 0054 §9; ADR 0030 §1, §3: the adapter has no
/// default). Absent, `undefined` or `null` is `None`, the core default SHA-256 (RFC 9278 §5). A
/// name is parsed by the core: `sha-256`, `SHA-256`, `sha256` and the same forms for 384 and 512,
/// exactly (ADR 0054 §8.2); any other, SHA-1 among them, rejects with `UnsupportedAlgorithm`
/// (ADR 0022). The JWK is imported first, so an invalid key is reported before an invalid name
/// (ADR 0057 §2). Resolves to a string of 43, 64 or 86 characters.
#[napi]
pub fn jwk_thumbprint(jwk: String, hash: Option<String>) -> AsyncTask<JwkThumbprintTask> {
    AsyncTask::new(JwkThumbprintTask {
        jwk: Zeroizing::new(jwk),
        hash,
    })
}

surface_task! {
    /// `jwkThumbprintUri`: the RFC 9278 §3 thumbprint URI.
    JwkThumbprintUriTask { jwk: Zeroizing<String>, hash: Option<String> } -> String
        = |t| op::jwk_thumbprint_uri(&t.jwk, t.hash.as_deref())
}

/// The JWK Thumbprint URI of `jwk` under `hash`,
/// `urn:ietf:params:oauth:jwk-thumbprint:<hash>:<thumbprint>` (RFC 9278 §3), `<hash>` being the
/// IANA name (`sha-256`, `sha-384`, `sha-512`, RFC 9278 §4) whichever spelling was passed.
/// `hash` is as for `jwkThumbprint` (ADR 0054 §9, ADR 0057 §2). Resolves to a string.
#[napi]
pub fn jwk_thumbprint_uri(jwk: String, hash: Option<String>) -> AsyncTask<JwkThumbprintUriTask> {
    AsyncTask::new(JwkThumbprintUriTask {
        jwk: Zeroizing::new(jwk),
        hash,
    })
}

surface_task! {
    /// `jwksSelect`: the member of a JWK Set that the selector picks (RFC 7517 §5).
    JwksSelectTask { jwks: Zeroizing<String>, selector: surface::JwkSelector } -> SecretString
        = |t| op::jwks_select(&t.jwks, &t.selector)
}

/// The member of the JWK Set `jwks` that `selector` picks (RFC 7517 §5, §4.2, §4.4, §4.5;
/// ADR 0029). Resolves to JWK JSON text.
#[napi]
pub fn jwks_select(jwks: String, selector: JwkSelector) -> AsyncTask<JwksSelectTask> {
    AsyncTask::new(JwksSelectTask {
        jwks: Zeroizing::new(jwks),
        selector: selector.into(),
    })
}

#[cfg(test)]
mod tests {
    use napi::ScopedTask;

    use polyjose_surface::SurfaceResult;

    use super::*;
    use crate::tests::{RFC7517_A2_P256_PRIVATE, wipes_on_drop};

    /// RFC 7638 §3.1: the RSA public key of the thumbprint example.
    const RFC7638_RSA: &str = r#"{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","alg":"RS256","kid":"2011-04-29"}"#;

    fn jwk(text: &str) -> Zeroizing<String> {
        Zeroizing::new(text.to_owned())
    }

    /// RFC 7638 §3.1: the thumbprint of [`RFC7638_RSA`] under SHA-256.
    const RFC7638_SHA256: &str = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

    fn thumbprint(hash: Option<&str>) -> SurfaceResult<String> {
        let mut task = JwkThumbprintTask {
            jwk: jwk(RFC7638_RSA),
            hash: hash.map(str::to_owned),
        };
        task.compute().unwrap()
    }

    fn thumbprint_uri(hash: Option<&str>) -> SurfaceResult<String> {
        let mut task = JwkThumbprintUriTask {
            jwk: jwk(RFC7638_RSA),
            hash: hash.map(str::to_owned),
        };
        task.compute().unwrap()
    }

    #[test]
    fn thumbprint_reproduces_rfc7638_section_3_1_and_rfc9278() {
        assert_eq!(thumbprint(Some("SHA-256")).unwrap(), RFC7638_SHA256);
        assert_eq!(
            thumbprint_uri(Some("SHA-256")).unwrap(),
            format!("urn:ietf:params:oauth:jwk-thumbprint:sha-256:{RFC7638_SHA256}")
        );
    }

    #[test]
    fn an_absent_hash_reaches_the_surface_as_none() {
        // ADR 0054 §9, ADR 0030 §3: the adapter has no default; `None` is the core's, SHA-256
        // (RFC 9278 §5). So an absent hash gives exactly the surface's `None` answer.
        assert_eq!(thumbprint(None), op::jwk_thumbprint(RFC7638_RSA, None));
        assert_eq!(thumbprint(None).unwrap(), RFC7638_SHA256);
        assert_eq!(
            thumbprint_uri(None).unwrap(),
            op::jwk_thumbprint_uri(RFC7638_RSA, None).unwrap()
        );
    }

    #[test]
    fn a_hash_name_is_passed_on_as_written() {
        // ADR 0054 §8.2: the core parses the name; the URI always carries the IANA name
        // (RFC 9278 §3, §4). The values are conformance/vectors/jwk-thumbprint/
        // hash-alias-sha384-rfc7638-3-1-rsa.json.
        let sha384 = "R9_OfJjSjaw8Fuum86UzK5ixTdN9bo9BaqPSiseq89DWfmqCdpSgUHus-cxDUNc8";
        for name in ["sha-384", "SHA-384", "sha384"] {
            assert_eq!(thumbprint(Some(name)).unwrap(), sha384, "{name}");
            assert_eq!(
                thumbprint_uri(Some(name)).unwrap(),
                format!("urn:ietf:params:oauth:jwk-thumbprint:sha-384:{sha384}"),
                "{name}"
            );
        }
    }

    #[test]
    fn sha1_and_unknown_hash_names_are_unsupported() {
        // ADR 0022, ADR 0054 §8.2: exact names only, so neither SHA-1 nor a case variant nor
        // the empty string is defaulted by anyone.
        for name in ["SHA-1", "sha-1", "Sha-256", ""] {
            assert_eq!(
                thumbprint(Some(name)).unwrap_err().code(),
                "UnsupportedAlgorithm",
                "{name:?}"
            );
            assert_eq!(
                thumbprint_uri(Some(name)).unwrap_err().code(),
                "UnsupportedAlgorithm",
                "{name:?}"
            );
        }
    }

    #[test]
    fn the_key_is_imported_before_the_hash_is_parsed() {
        // ADR 0057 §2: an invalid key with an invalid hash name is the import error
        // (conformance/vectors/jwk-thumbprint/hash-reject-invalid-key-p256-off-curve.json).
        let off_curve = r#"{"kty":"EC","crv":"P-256","x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfQ"}"#;
        let mut task = JwkThumbprintTask {
            jwk: jwk(off_curve),
            hash: Some("SHA-1".into()),
        };
        assert_eq!(task.compute().unwrap().unwrap_err().code(), "InvalidKey");
        let mut task = JwkThumbprintUriTask {
            jwk: jwk("{"),
            hash: Some("SHA-1".into()),
        };
        assert_eq!(task.compute().unwrap().unwrap_err().code(), "InvalidJson");
    }

    #[test]
    fn parse_and_to_public_reproduce_rfc7517_appendix_a() {
        let mut parse = JwkParseTask {
            jwk: jwk(RFC7517_A2_P256_PRIVATE),
        };
        let parsed = parse.compute().unwrap().unwrap();
        assert!(
            parsed
                .as_str()
                .contains(r#""d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE""#)
        );
        let mut public = JwkToPublicTask {
            jwk: jwk(RFC7517_A2_P256_PRIVATE),
        };
        assert_eq!(
            public.compute().unwrap().unwrap(),
            r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","use":"enc","kid":"1"}"#
        );
    }

    #[test]
    fn invalid_jwk_rejects_with_the_core_code() {
        let mut parse = JwkParseTask {
            jwk: jwk(r#"{"kty":"oct"}"#),
        };
        assert_eq!(parse.compute().unwrap().unwrap_err().code(), "InvalidKey");
        let mut parse = JwkParseTask { jwk: jwk("{") };
        assert_eq!(parse.compute().unwrap().unwrap_err().code(), "InvalidJson");
    }

    #[test]
    fn jwks_select_passes_the_surface_result_through() {
        // The merged surface's jwks_select is a stub until 0013 T14; the adapter passes its
        // answer through unchanged.
        let selector = surface::JwkSelector::default();
        let expected = op::jwks_select(r#"{"keys":[]}"#, &selector).map(|_| ());
        let mut task = JwksSelectTask {
            jwks: jwk(r#"{"keys":[]}"#),
            selector,
        };
        assert_eq!(task.compute().unwrap().map(|_| ()), expected);
    }

    #[test]
    fn jwk_inputs_are_held_in_zeroizing_owners() {
        let task = JwkParseTask { jwk: jwk("") };
        wipes_on_drop(&task.jwk);
        let task = JwksSelectTask {
            jwks: jwk(""),
            selector: surface::JwkSelector::default(),
        };
        wipes_on_drop(&task.jwks);
    }
}
