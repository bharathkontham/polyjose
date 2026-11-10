//! The JWT operations (ADR 0030 §4, "JWT"): `jwtSign`, `jwtVerify`, `jwtVerifyWithJwks`,
//! `jwtEncryptNested`, `jwtDecryptNested`, `jwtDecryptNestedWithJwks` (RFC 7519, RFC 8725,
//! RFC 9068; ADR 0027, 0028, 0029).
//!
//! One key or a JWK Set is chosen by which function is called, and signed and nested JWTs have
//! separate entry points (ADR 0027 §7). Keys, JWK Sets, claims and tokens are copied into
//! `Zeroizing` task fields on the JS thread (ADR 0030 §7). `now` comes from the facade
//! (ADR 0028 §4); the adapter passes whatever arrives, and reads no clock.

use napi::bindgen_prelude::{AsyncTask, Object};
use napi_derive::napi;
use polyjose_surface::jwt as op;
use polyjose_surface::records as surface;
use zeroize::Zeroizing;

use crate::records::{JweDecryptOptions, JweEncryptOptions, JwtSignOptions, JwtVerifyOptions};
use crate::task::surface_task;

surface_task! {
    /// `jwtSign`: a signed JWT, a JWS Compact Serialization (RFC 7519 §7.1).
    JwtSignTask {
        claims: Zeroizing<String>,
        key: Zeroizing<String>,
        options: surface::JwtSignOptions,
    } -> String
        = |t| op::jwt_sign(&t.claims, &t.key, &t.options)
}

/// Signs the JWT Claims Set `claims` (JSON text) with the JWK `key` (RFC 7519 §7.1). RS* and PS*
/// sign with an RSA private key (ADR 0067 §2). Resolves to the token.
#[napi]
pub fn jwt_sign(claims: String, key: String, options: JwtSignOptions) -> AsyncTask<JwtSignTask> {
    AsyncTask::new(JwtSignTask {
        claims: Zeroizing::new(claims),
        key: Zeroizing::new(key),
        options: options.into(),
    })
}

surface_task! {
    /// `jwtVerify`: verifies and validates a signed JWT with one key (RFC 7519 §7.2).
    JwtVerifyTask {
        token: Zeroizing<String>,
        key: Zeroizing<String>,
        options: surface::JwtVerifyOptions,
    } -> surface::JwtVerified
        = |t| op::jwt_verify(&t.token, &t.key, &t.options)
}

/// Verifies the signed JWT `token` with the JWK `key` and validates its claims under `options`
/// (RFC 7519 §7.2, RFC 8725 §3; ADR 0027 §9 fixes the error order). Resolves to `{ claims,
/// header, alg, keyIndex?, kid? }`.
#[napi]
pub fn jwt_verify(
    token: String,
    key: String,
    options: JwtVerifyOptions,
) -> AsyncTask<JwtVerifyTask> {
    AsyncTask::new(JwtVerifyTask {
        token: Zeroizing::new(token),
        key: Zeroizing::new(key),
        options: options.into(),
    })
}

surface_task! {
    /// `jwtVerifyWithJwks`: verifies and validates a signed JWT with a JWK Set (RFC 7519 §7.2,
    /// ADR 0029).
    JwtVerifyWithJwksTask {
        token: Zeroizing<String>,
        jwks: Zeroizing<String>,
        options: surface::JwtVerifyOptions,
    } -> surface::JwtVerified
        = |t| op::jwt_verify_with_jwks(&t.token, &t.jwks, &t.options)
}

/// Verifies the signed JWT `token` with a member of the JWK Set `jwks` (RFC 7517 §5, ADR 0029;
/// no member verifying rejects with `NoMatchingKey`). Resolves like [`jwt_verify`].
#[napi]
pub fn jwt_verify_with_jwks(
    token: String,
    jwks: String,
    options: JwtVerifyOptions,
) -> AsyncTask<JwtVerifyWithJwksTask> {
    AsyncTask::new(JwtVerifyWithJwksTask {
        token: Zeroizing::new(token),
        jwks: Zeroizing::new(jwks),
        options: options.into(),
    })
}

surface_task! {
    /// `jwtEncryptNested`: a nested JWT, the signed JWT inside a compact JWE (RFC 7519 §5.2).
    JwtEncryptNestedTask {
        signed_jwt: Zeroizing<String>,
        options: surface::JweEncryptOptions,
    } -> String
        = |t| op::jwt_encrypt_nested(&t.signed_jwt, &t.options)
}

/// Encrypts the signed JWT `signedJwt` into a compact JWE for the single recipient of `options`,
/// `cty: "JWT"` set by the core (RFC 7519 §5.2, §7.1 step 5). Resolves to the token.
#[napi]
pub fn jwt_encrypt_nested(
    signed_jwt: String,
    #[napi(ts_arg_type = "JweEncryptOptions")] options: Object<'_>,
) -> napi::Result<AsyncTask<JwtEncryptNestedTask>> {
    // review-security.md L1: napi has converted every argument; only reading the record can run
    // JS, so the byte argument is copied first and the strings are in their owners before it.
    let signed_jwt = Zeroizing::new(signed_jwt);
    let options = JweEncryptOptions::read(&options)?;
    Ok(AsyncTask::new(JwtEncryptNestedTask {
        signed_jwt,
        options,
    }))
}

surface_task! {
    /// `jwtDecryptNested`: decrypts a nested JWT and verifies the inner one with one key
    /// (RFC 7519 §7.2 step 8).
    JwtDecryptNestedTask {
        token: Zeroizing<String>,
        decrypt_key: Zeroizing<String>,
        decrypt_options: surface::JweDecryptOptions,
        key: Zeroizing<String>,
        verify_options: surface::JwtVerifyOptions,
    } -> surface::JwtNestedVerified
        = |t| op::jwt_decrypt_nested(
            &t.token,
            &t.decrypt_key,
            &t.decrypt_options,
            &t.key,
            &t.verify_options,
        )
}

/// Decrypts the nested JWT `token` with `decryptKey` under `decryptOptions`, then verifies the
/// inner JWT with `key` under `verifyOptions` (RFC 7519 §7.2 step 8, RFC 8725 §3). Resolves to
/// `{ inner, outerHeader, recipientIndex }`.
#[napi]
pub fn jwt_decrypt_nested(
    token: String,
    decrypt_key: String,
    decrypt_options: JweDecryptOptions,
    key: String,
    verify_options: JwtVerifyOptions,
) -> AsyncTask<JwtDecryptNestedTask> {
    AsyncTask::new(JwtDecryptNestedTask {
        token: Zeroizing::new(token),
        decrypt_key: Zeroizing::new(decrypt_key),
        decrypt_options: decrypt_options.into(),
        key: Zeroizing::new(key),
        verify_options: verify_options.into(),
    })
}

surface_task! {
    /// `jwtDecryptNestedWithJwks`: decrypts a nested JWT and verifies the inner one with a JWK
    /// Set (RFC 7519 §7.2 step 8, ADR 0029).
    JwtDecryptNestedWithJwksTask {
        token: Zeroizing<String>,
        decrypt_key: Zeroizing<String>,
        decrypt_options: surface::JweDecryptOptions,
        jwks: Zeroizing<String>,
        verify_options: surface::JwtVerifyOptions,
    } -> surface::JwtNestedVerified
        = |t| op::jwt_decrypt_nested_with_jwks(
            &t.token,
            &t.decrypt_key,
            &t.decrypt_options,
            &t.jwks,
            &t.verify_options,
        )
}

/// Like [`jwt_decrypt_nested`], verifying the inner JWT with a member of the JWK Set `jwks`
/// (ADR 0029).
#[napi]
pub fn jwt_decrypt_nested_with_jwks(
    token: String,
    decrypt_key: String,
    decrypt_options: JweDecryptOptions,
    jwks: String,
    verify_options: JwtVerifyOptions,
) -> AsyncTask<JwtDecryptNestedWithJwksTask> {
    AsyncTask::new(JwtDecryptNestedWithJwksTask {
        token: Zeroizing::new(token),
        decrypt_key: Zeroizing::new(decrypt_key),
        decrypt_options: decrypt_options.into(),
        jwks: Zeroizing::new(jwks),
        verify_options: verify_options.into(),
    })
}

#[cfg(test)]
mod tests {
    use napi::ScopedTask;
    use polyjose_surface::SecretString;

    use super::*;
    use crate::tests::wipes_on_drop;

    /// RFC 7515 Appendix A.1's HMAC key, the key of the RFC 7519 §3.1 example.
    const OCT: &str = r#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#;
    /// The RFC 7519 §3.1 example JWT (RFC 7515 Appendix A.1's JWS).
    const RFC7519_3_1: &str = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    /// The `exp` of the RFC 7519 §3.1 example, and 60 s before it.
    const EXP: i64 = 1_300_819_380;
    const BEFORE_EXP: i64 = 1_300_819_320;
    /// A 128-bit key for the nested JWE (A128KW).
    const KEK: &str = r#"{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}"#;

    fn secret(text: &str) -> Zeroizing<String> {
        Zeroizing::new(text.to_owned())
    }

    fn hs256_at(now: i64) -> surface::JwtVerifyOptions {
        surface::JwtVerifyOptions {
            now: Some(now),
            ..surface::JwtVerifyOptions::new(vec!["HS256".into()])
        }
    }

    fn a128kw() -> surface::JweDecryptOptions {
        surface::JweDecryptOptions::new(vec!["A128KW".into()], vec!["A128GCM".into()])
    }

    fn nested(signed_jwt: &str) -> String {
        let mut encrypt = JwtEncryptNestedTask {
            signed_jwt: secret(signed_jwt),
            options: surface::JweEncryptOptions::new(
                "A128GCM".into(),
                vec![surface::JweRecipient::new(
                    "A128KW".into(),
                    SecretString::from(KEK.to_owned()),
                )],
            ),
        };
        encrypt.compute().unwrap().unwrap()
    }

    #[test]
    fn verify_validates_the_rfc7519_section_3_1_example() {
        let mut task = JwtVerifyTask {
            token: secret(RFC7519_3_1),
            key: secret(OCT),
            options: hs256_at(BEFORE_EXP),
        };
        let verified = task.compute().unwrap().unwrap();
        assert_eq!(verified.alg, "HS256");
        assert!(verified.claims.contains(r#""iss":"joe""#));
    }

    #[test]
    fn verify_failures_carry_the_core_codes() {
        let mut expired = JwtVerifyTask {
            token: secret(RFC7519_3_1),
            key: secret(OCT),
            options: hs256_at(EXP + 3600),
        };
        assert_eq!(
            expired.compute().unwrap().unwrap_err().code(),
            "TokenExpired"
        );
        let mut empty_set = JwtVerifyWithJwksTask {
            token: secret(RFC7519_3_1),
            jwks: secret(r#"{"keys":[]}"#),
            options: hs256_at(BEFORE_EXP),
        };
        assert_eq!(
            empty_set.compute().unwrap().unwrap_err().code(),
            "NoMatchingKey"
        );
    }

    #[test]
    fn sign_then_verify_with_a_jwk_set() {
        let mut sign = JwtSignTask {
            claims: secret(r#"{"sub":"alice","exp":1300819380}"#),
            key: secret(OCT),
            options: surface::JwtSignOptions::new("HS256".into()),
        };
        let token = sign.compute().unwrap().unwrap();
        let mut verify = JwtVerifyWithJwksTask {
            token: Zeroizing::new(token),
            jwks: Zeroizing::new(format!(r#"{{"keys":[{OCT}]}}"#)),
            options: hs256_at(BEFORE_EXP),
        };
        let verified = verify.compute().unwrap().unwrap();
        assert_eq!(verified.key_index, Some(0));
        assert!(verified.claims.contains(r#""sub":"alice""#));
    }

    /// RFC 7515 Appendix A.2's RSA private key (`jwt/rfc7519/a2-rs256-issue-exact.json`).
    const RSA_PRIVATE: &str = include_str!(
        "../../../crates/polyjose/tests/data/keys/rfc/rfc7515-a2-rsa-private.jwk.json"
    );

    #[test]
    fn rsa_signing_runs_through_the_task_and_needs_crt_members() {
        // ADR 0067 §2: RS256 and PS256 sign with the private key; the task verifies its own
        // token with the same key's public half (RFC 7515 §5.2).
        for alg in ["RS256", "PS256"] {
            let mut sign = JwtSignTask {
                claims: secret(r#"{"sub":"alice","exp":1300819380}"#),
                key: secret(RSA_PRIVATE),
                options: surface::JwtSignOptions::new(alg.into()),
            };
            let token = sign.compute().unwrap().unwrap();
            let mut verify = JwtVerifyTask {
                token: Zeroizing::new(token),
                key: secret(RSA_PRIVATE),
                options: {
                    let mut o = surface::JwtVerifyOptions::new(vec![alg.into()]);
                    o.now = Some(BEFORE_EXP);
                    o
                },
            };
            let verified = verify.compute().unwrap().unwrap();
            assert_eq!(verified.alg, alg);
            assert!(verified.claims.contains(r#""sub":"alice""#));
        }
        // A private key without its CRT members (RFC 7518 §6.3.2) is InvalidKey (ADR 0067 §3).
        let mut sign = JwtSignTask {
            claims: secret(r#"{"sub":"alice"}"#),
            key: secret(r#"{"kty":"RSA","n":"AQAB","e":"AQAB","d":"AQAB"}"#),
            options: surface::JwtSignOptions::new("RS256".into()),
        };
        assert_eq!(sign.compute().unwrap().unwrap_err().code(), "InvalidKey");
    }

    #[test]
    fn nested_jwt_round_trips_with_a_key_and_a_set() {
        let token = nested(RFC7519_3_1);
        let mut one_key = JwtDecryptNestedTask {
            token: secret(&token),
            decrypt_key: secret(KEK),
            decrypt_options: a128kw(),
            key: secret(OCT),
            verify_options: hs256_at(BEFORE_EXP),
        };
        let verified = one_key.compute().unwrap().unwrap();
        assert!(verified.inner.claims.contains(r#""iss":"joe""#));
        assert!(verified.outer_header.contains(r#""cty":"JWT""#));

        let mut with_set = JwtDecryptNestedWithJwksTask {
            token: secret(&token),
            decrypt_key: secret(KEK),
            decrypt_options: a128kw(),
            jwks: Zeroizing::new(format!(r#"{{"keys":[{OCT}]}}"#)),
            verify_options: hs256_at(BEFORE_EXP),
        };
        assert_eq!(with_set.compute().unwrap().unwrap().recipient_index, 0);
    }

    #[test]
    fn nested_jwt_with_a_disallowed_enc_is_rejected() {
        let mut task = JwtDecryptNestedTask {
            token: secret(&nested(RFC7519_3_1)),
            decrypt_key: secret(KEK),
            decrypt_options: surface::JweDecryptOptions::new(
                vec!["A128KW".into()],
                vec!["A256GCM".into()],
            ),
            key: secret(OCT),
            verify_options: hs256_at(BEFORE_EXP),
        };
        assert_eq!(
            task.compute().unwrap().unwrap_err().code(),
            "AlgorithmNotAllowed"
        );
    }

    #[test]
    fn jwt_inputs_are_held_in_zeroizing_owners() {
        let sign = JwtSignTask {
            claims: secret(""),
            key: secret(""),
            options: surface::JwtSignOptions::new("HS256".into()),
        };
        wipes_on_drop(&sign.claims);
        wipes_on_drop(&sign.key);
        let task = JwtDecryptNestedWithJwksTask {
            token: secret(""),
            decrypt_key: secret(""),
            decrypt_options: a128kw(),
            jwks: secret(""),
            verify_options: hs256_at(0),
        };
        wipes_on_drop(&task.token);
        wipes_on_drop(&task.decrypt_key);
        wipes_on_drop(&task.jwks);
    }
}
