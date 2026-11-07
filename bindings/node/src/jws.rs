//! The JWS operations (ADR 0030 §4, "JWS"): `jwsSignCompact`, `jwsSignFlattened`,
//! `jwsSignGeneral`, `jwsVerifyCompact`, `jwsVerifyJson` (RFC 7515, RFC 7797, RFC 8037).
//!
//! Payloads are treated as secret (ADR 0049 §4) and keys may be private: both are copied into
//! `Zeroizing` task fields (or surface records holding `SecretString`/`SecretBytes`) on the JS
//! thread. A verified payload resolves as a `Uint8Array` copied from the surface's zeroizing
//! buffer. Verification takes the caller's `allowedAlgs` and nothing else (RFC 8725 §3.1,
//! ADR 0007).

use napi::bindgen_prelude::AsyncTask;
use napi_derive::napi;
use polyjose_surface::jws as op;
use polyjose_surface::records as surface;
use zeroize::Zeroizing;

use crate::records::{JwsSignOptions, JwsSigner, JwsVerifyOptions};
use crate::task::surface_task;

surface_task! {
    /// `jwsSignCompact`: a JWS Compact Serialization (RFC 7515 §7.1).
    JwsSignCompactTask {
        payload: Zeroizing<Vec<u8>>,
        key: Zeroizing<String>,
        options: surface::JwsSignOptions,
    } -> String
        = |t| op::jws_sign_compact(&t.payload, &t.key, &t.options)
}

/// Signs `payload` with the JWK `key` into a JWS Compact Serialization (RFC 7515 §5.1, §7.1),
/// detached on request (RFC 7515 Appendix F). Resolves to the token.
#[napi]
pub fn jws_sign_compact(
    payload: &[u8],
    key: String,
    options: JwsSignOptions,
) -> AsyncTask<JwsSignCompactTask> {
    AsyncTask::new(JwsSignCompactTask {
        payload: Zeroizing::new(payload.to_vec()),
        key: Zeroizing::new(key),
        options: options.into(),
    })
}

surface_task! {
    /// `jwsSignFlattened`: a flattened JWS JSON Serialization (RFC 7515 §7.2.2).
    JwsSignFlattenedTask {
        payload: Zeroizing<Vec<u8>>,
        signer: surface::JwsSigner,
        detached: bool,
    } -> String
        = |t| op::jws_sign_flattened(&t.payload, &t.signer, t.detached)
}

/// Signs `payload` for one signer into a flattened JWS JSON Serialization (RFC 7515 §7.2.2).
/// Resolves to JSON text.
#[napi]
pub fn jws_sign_flattened(
    payload: &[u8],
    signer: JwsSigner,
    detached: bool,
) -> AsyncTask<JwsSignFlattenedTask> {
    AsyncTask::new(JwsSignFlattenedTask {
        payload: Zeroizing::new(payload.to_vec()),
        signer: signer.into(),
        detached,
    })
}

surface_task! {
    /// `jwsSignGeneral`: a general JWS JSON Serialization (RFC 7515 §7.2.1).
    JwsSignGeneralTask {
        payload: Zeroizing<Vec<u8>>,
        signers: Vec<surface::JwsSigner>,
        detached: bool,
    } -> String
        = |t| op::jws_sign_general(&t.payload, &t.signers, t.detached)
}

/// Signs `payload` for every signer into a general JWS JSON Serialization (RFC 7515 §7.2.1).
/// Resolves to JSON text.
#[napi]
pub fn jws_sign_general(
    payload: &[u8],
    signers: Vec<JwsSigner>,
    detached: bool,
) -> AsyncTask<JwsSignGeneralTask> {
    AsyncTask::new(JwsSignGeneralTask {
        payload: Zeroizing::new(payload.to_vec()),
        signers: signers.into_iter().map(Into::into).collect(),
        detached,
    })
}

surface_task! {
    /// `jwsVerifyCompact`: verifies a JWS Compact Serialization (RFC 7515 §5.2).
    JwsVerifyCompactTask {
        token: Zeroizing<String>,
        key: Zeroizing<String>,
        options: surface::JwsVerifyOptions,
    } -> surface::JwsVerified
        = |t| op::jws_verify_compact(&t.token, &t.key, &t.options)
}

/// Verifies the compact JWS `token` with the JWK `key` under `options.allowedAlgs` (RFC 7515
/// §5.2, RFC 8725 §3.1). Resolves to `{ alg, payload, protectedHeader?, unprotectedHeader?,
/// signatureIndex }`.
#[napi]
pub fn jws_verify_compact(
    token: String,
    key: String,
    options: JwsVerifyOptions<'_>,
) -> AsyncTask<JwsVerifyCompactTask> {
    AsyncTask::new(JwsVerifyCompactTask {
        token: Zeroizing::new(token),
        key: Zeroizing::new(key),
        options: options.into(),
    })
}

surface_task! {
    /// `jwsVerifyJson`: verifies a flattened or general JWS JSON Serialization (RFC 7515 §5.2,
    /// §7.2).
    JwsVerifyJsonTask {
        jws: Zeroizing<String>,
        key: Zeroizing<String>,
        options: surface::JwsVerifyOptions,
    } -> surface::JwsVerified
        = |t| op::jws_verify_json(&t.jws, &t.key, &t.options)
}

/// Verifies the JWS JSON Serialization `jws` (flattened or general) with the JWK `key` under
/// `options.allowedAlgs` (RFC 7515 §5.2, §7.2, RFC 8725 §3.1). Resolves like
/// [`jws_verify_compact`].
#[napi]
pub fn jws_verify_json(
    jws: String,
    key: String,
    options: JwsVerifyOptions<'_>,
) -> AsyncTask<JwsVerifyJsonTask> {
    AsyncTask::new(JwsVerifyJsonTask {
        jws: Zeroizing::new(jws),
        key: Zeroizing::new(key),
        options: options.into(),
    })
}

#[cfg(test)]
mod tests {
    use napi::ScopedTask;
    use polyjose_surface::SecretString;

    use super::*;
    use crate::tests::wipes_on_drop;

    /// RFC 7515 Appendix A.1: the HMAC key, protected header octets, payload and JWS.
    const A1_KEY: &str = r#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#;
    const A1_PROTECTED_B64U: &str = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9";
    const A1_PAYLOAD: &[u8] =
        b"{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";
    const A1_JWS: &str = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    fn secret(text: &str) -> Zeroizing<String> {
        Zeroizing::new(text.to_owned())
    }

    fn a1_signer() -> surface::JwsSigner {
        surface::JwsSigner {
            protected_b64u: Some(A1_PROTECTED_B64U.into()),
            ..surface::JwsSigner::new(SecretString::from(A1_KEY.to_owned()))
        }
    }

    fn hs256() -> surface::JwsVerifyOptions {
        surface::JwsVerifyOptions::new(vec!["HS256".into()])
    }

    #[test]
    fn sign_compact_reproduces_rfc7515_appendix_a1() {
        let mut task = JwsSignCompactTask {
            payload: Zeroizing::new(A1_PAYLOAD.to_vec()),
            key: secret(A1_KEY),
            options: surface::JwsSignOptions {
                protected_b64u: Some(A1_PROTECTED_B64U.into()),
                ..Default::default()
            },
        };
        assert_eq!(task.compute().unwrap().unwrap(), A1_JWS);
    }

    #[test]
    fn verify_compact_reproduces_rfc7515_appendix_a1() {
        let mut task = JwsVerifyCompactTask {
            token: secret(A1_JWS),
            key: secret(A1_KEY),
            options: hs256(),
        };
        let verified = task.compute().unwrap().unwrap();
        assert_eq!(verified.alg, "HS256");
        assert_eq!(verified.payload.as_bytes(), A1_PAYLOAD);
        assert_eq!(verified.signature_index, 0);
    }

    #[test]
    fn verify_failures_carry_the_core_codes() {
        let mut empty_list = JwsVerifyCompactTask {
            token: secret(A1_JWS),
            key: secret(A1_KEY),
            options: surface::JwsVerifyOptions::new(Vec::new()),
        };
        assert_eq!(
            empty_list.compute().unwrap().unwrap_err().code(),
            "AlgorithmNotAllowed"
        );
        let tampered = format!("{}A", &A1_JWS[..A1_JWS.len() - 1]);
        let mut bad_signature = JwsVerifyCompactTask {
            token: secret(&tampered),
            key: secret(A1_KEY),
            options: hs256(),
        };
        assert_eq!(
            bad_signature.compute().unwrap().unwrap_err().code(),
            "InvalidSignature"
        );
    }

    #[test]
    fn json_forms_sign_and_verify_with_rfc7515_appendix_a1() {
        let mut flattened = JwsSignFlattenedTask {
            payload: Zeroizing::new(A1_PAYLOAD.to_vec()),
            signer: a1_signer(),
            detached: false,
        };
        let jws = flattened.compute().unwrap().unwrap();
        assert!(jws.contains(r#""signature":"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk""#));

        let mut general = JwsSignGeneralTask {
            payload: Zeroizing::new(A1_PAYLOAD.to_vec()),
            signers: vec![a1_signer(), a1_signer()],
            detached: false,
        };
        let jws = general.compute().unwrap().unwrap();
        let mut verify = JwsVerifyJsonTask {
            jws: Zeroizing::new(jws),
            key: secret(A1_KEY),
            options: hs256(),
        };
        let verified = verify.compute().unwrap().unwrap();
        assert_eq!(verified.payload.as_bytes(), A1_PAYLOAD);
    }

    #[test]
    fn sign_header_misuse_is_invalid_header() {
        // Neither header form (ADR 0030 §4).
        let mut task = JwsSignCompactTask {
            payload: Zeroizing::new(A1_PAYLOAD.to_vec()),
            key: secret(A1_KEY),
            options: surface::JwsSignOptions::default(),
        };
        assert_eq!(task.compute().unwrap().unwrap_err().code(), "InvalidHeader");
    }

    #[test]
    fn jws_inputs_are_held_in_zeroizing_owners() {
        let sign = JwsSignCompactTask {
            payload: Zeroizing::new(Vec::new()),
            key: secret(""),
            options: surface::JwsSignOptions::default(),
        };
        wipes_on_drop(&sign.payload);
        wipes_on_drop(&sign.key);
        let general = JwsSignGeneralTask {
            payload: Zeroizing::new(Vec::new()),
            signers: vec![a1_signer()],
            detached: false,
        };
        wipes_on_drop(&general.signers[0].key);
        let verify = JwsVerifyJsonTask {
            jws: secret(""),
            key: secret(""),
            options: hs256(),
        };
        wipes_on_drop(&verify.jws);
        wipes_on_drop(&verify.key);
    }
}
