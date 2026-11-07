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
    JwkThumbprintTask { jwk: Zeroizing<String>, hash: String } -> String
        = |t| op::jwk_thumbprint(&t.jwk, &t.hash)
}

/// The JWK Thumbprint of `jwk` under `hash` (`SHA-256`), base64url-encoded (RFC 7638 §3,
/// RFC 9278 §5). Any other hash name rejects with `UnsupportedAlgorithm` (ADR 0022). Resolves
/// to a string.
#[napi]
pub fn jwk_thumbprint(jwk: String, hash: String) -> AsyncTask<JwkThumbprintTask> {
    AsyncTask::new(JwkThumbprintTask {
        jwk: Zeroizing::new(jwk),
        hash,
    })
}

surface_task! {
    /// `jwkThumbprintUri`: the RFC 9278 §3 thumbprint URI.
    JwkThumbprintUriTask { jwk: Zeroizing<String>, hash: String } -> String
        = |t| op::jwk_thumbprint_uri(&t.jwk, &t.hash)
}

/// The JWK Thumbprint URI of `jwk` under `hash`,
/// `urn:ietf:params:oauth:jwk-thumbprint:sha-256:…` (RFC 9278 §3). Resolves to a string.
#[napi]
pub fn jwk_thumbprint_uri(jwk: String, hash: String) -> AsyncTask<JwkThumbprintUriTask> {
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

    use super::*;
    use crate::tests::{RFC7517_A2_P256_PRIVATE, wipes_on_drop};

    /// RFC 7638 §3.1: the RSA public key of the thumbprint example.
    const RFC7638_RSA: &str = r#"{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","alg":"RS256","kid":"2011-04-29"}"#;

    fn jwk(text: &str) -> Zeroizing<String> {
        Zeroizing::new(text.to_owned())
    }

    #[test]
    fn thumbprint_reproduces_rfc7638_section_3_1_and_rfc9278() {
        let mut task = JwkThumbprintTask {
            jwk: jwk(RFC7638_RSA),
            hash: "SHA-256".into(),
        };
        assert_eq!(
            task.compute().unwrap().unwrap(),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
        let mut task = JwkThumbprintUriTask {
            jwk: jwk(RFC7638_RSA),
            hash: "SHA-256".into(),
        };
        assert_eq!(
            task.compute().unwrap().unwrap(),
            "urn:ietf:params:oauth:jwk-thumbprint:sha-256:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }

    #[test]
    fn sha1_thumbprint_is_unsupported() {
        let mut task = JwkThumbprintTask {
            jwk: jwk(RFC7638_RSA),
            hash: "SHA-1".into(),
        };
        let err = task.compute().unwrap().unwrap_err();
        assert_eq!(err.code(), "UnsupportedAlgorithm");
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
