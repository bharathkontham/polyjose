//! The JWE operations (ADR 0030 §4, "JWE"): `jweEncryptCompact`, `jweEncryptJson`,
//! `jweDecryptCompact`, `jweDecryptJson` (RFC 7516, RFC 7518 §4–5).
//!
//! Plaintext, `aad` and keys are secret (ADR 0030 §7, ADR 0050 §4): they are copied into
//! `Zeroizing` task fields or surface records holding `SecretString`/`SecretBytes` on the JS
//! thread. Decrypted plaintext and `aad` resolve as `Uint8Array`s copied from the surface's
//! zeroizing buffers. Decryption takes the caller's `allowedAlgs` and `allowedEnc` and nothing
//! else (RFC 8725 §3.1, ADR 0007).

use napi::bindgen_prelude::{AsyncTask, Object, Uint8ArraySlice};
use napi_derive::napi;
use polyjose_surface::jwe as op;
use polyjose_surface::records as surface;
use zeroize::Zeroizing;

use crate::records::{JweDecryptOptions, JweEncryptOptions};
use crate::task::surface_task;

surface_task! {
    /// `jweEncryptCompact`: a JWE Compact Serialization (RFC 7516 §7.1).
    JweEncryptCompactTask {
        plaintext: Zeroizing<Vec<u8>>,
        options: surface::JweEncryptOptions,
    } -> String
        = |t| op::jwe_encrypt_compact(&t.plaintext, &t.options)
}

/// Encrypts `plaintext` for the single recipient of `options` into a JWE Compact Serialization
/// (RFC 7516 §5.1, §7.1). Resolves to the token.
#[napi]
pub fn jwe_encrypt_compact(
    plaintext: Uint8ArraySlice<'_>,
    #[napi(ts_arg_type = "JweEncryptOptions")] options: Object<'_>,
) -> napi::Result<AsyncTask<JweEncryptCompactTask>> {
    // review-security.md L1: napi has converted every argument; only reading the record can run
    // JS, so the byte argument is copied first and the strings are in their owners before it.
    let plaintext = Zeroizing::new(plaintext.to_vec());
    let options = JweEncryptOptions::read(&options)?;
    Ok(AsyncTask::new(JweEncryptCompactTask { plaintext, options }))
}

surface_task! {
    /// `jweEncryptJson`: a JWE JSON Serialization, `general` or `flattened` (RFC 7516 §7.2).
    JweEncryptJsonTask {
        plaintext: Zeroizing<Vec<u8>>,
        options: surface::JweEncryptOptions,
        form: String,
    } -> String
        = |t| op::jwe_encrypt_json(&t.plaintext, &t.options, &t.form)
}

/// Encrypts `plaintext` for the recipients of `options` into a JWE JSON Serialization of `form`
/// (`general`, RFC 7516 §7.2.1, or `flattened`, §7.2.2). Resolves to JSON text.
#[napi]
pub fn jwe_encrypt_json(
    plaintext: Uint8ArraySlice<'_>,
    #[napi(ts_arg_type = "JweEncryptOptions")] options: Object<'_>,
    form: String,
) -> napi::Result<AsyncTask<JweEncryptJsonTask>> {
    // review-security.md L1: napi has converted every argument; only reading the record can run
    // JS, so the byte argument is copied first and the strings are in their owners before it.
    let plaintext = Zeroizing::new(plaintext.to_vec());
    let options = JweEncryptOptions::read(&options)?;
    Ok(AsyncTask::new(JweEncryptJsonTask {
        plaintext,
        options,
        form,
    }))
}

surface_task! {
    /// `jweDecryptCompact`: decrypts a JWE Compact Serialization (RFC 7516 §5.2).
    JweDecryptCompactTask {
        token: Zeroizing<String>,
        key: Zeroizing<String>,
        options: surface::JweDecryptOptions,
    } -> surface::JweDecrypted
        = |t| op::jwe_decrypt_compact(&t.token, &t.key, &t.options)
}

/// Decrypts the compact JWE `token` with the JWK `key` under `options.allowedAlgs` and
/// `options.allowedEnc` (RFC 7516 §5.2, RFC 8725 §3.1). Resolves to `{ plaintext, header,
/// protectedHeader?, sharedUnprotectedHeader?, recipientHeader?, aad?, recipientIndex }`.
#[napi]
pub fn jwe_decrypt_compact(
    token: String,
    key: String,
    options: JweDecryptOptions,
) -> AsyncTask<JweDecryptCompactTask> {
    AsyncTask::new(JweDecryptCompactTask {
        token: Zeroizing::new(token),
        key: Zeroizing::new(key),
        options: options.into(),
    })
}

surface_task! {
    /// `jweDecryptJson`: decrypts a flattened or general JWE JSON Serialization (RFC 7516 §5.2,
    /// §7.2).
    JweDecryptJsonTask {
        jwe: Zeroizing<String>,
        key: Zeroizing<String>,
        options: surface::JweDecryptOptions,
    } -> surface::JweDecrypted
        = |t| op::jwe_decrypt_json(&t.jwe, &t.key, &t.options)
}

/// Decrypts the JWE JSON Serialization `jwe` with the JWK `key` (RFC 7516 §5.2, §7.2,
/// RFC 8725 §3.1). Resolves like [`jwe_decrypt_compact`].
#[napi]
pub fn jwe_decrypt_json(
    jwe: String,
    key: String,
    options: JweDecryptOptions,
) -> AsyncTask<JweDecryptJsonTask> {
    AsyncTask::new(JweDecryptJsonTask {
        jwe: Zeroizing::new(jwe),
        key: Zeroizing::new(key),
        options: options.into(),
    })
}

#[cfg(test)]
mod tests {
    use napi::ScopedTask;
    use polyjose_surface::{SecretBytes, SecretString};

    use super::*;
    use crate::tests::wipes_on_drop;

    /// RFC 7516 Appendix A.3: the A.3.3 key, the A.3.7 compact JWE and its plaintext.
    const A3_KEY: &str = r#"{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}"#;
    const A3_JWE: &str = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.U0m_YmjN04DJvceFICbCVQ";
    const A3_PLAINTEXT: &[u8] = b"Live long and prosper.";

    fn secret(text: &str) -> Zeroizing<String> {
        Zeroizing::new(text.to_owned())
    }

    fn a128kw() -> surface::JweDecryptOptions {
        surface::JweDecryptOptions::new(vec!["A128KW".into()], vec!["A128CBC-HS256".into()])
    }

    fn a128kw_encrypt() -> surface::JweEncryptOptions {
        surface::JweEncryptOptions {
            aad: Some(SecretBytes::from(b"aad".to_vec())),
            ..surface::JweEncryptOptions::new(
                "A128CBC-HS256".into(),
                vec![surface::JweRecipient::new(
                    "A128KW".into(),
                    SecretString::from(A3_KEY.to_owned()),
                )],
            )
        }
    }

    #[test]
    fn decrypt_compact_reproduces_rfc7516_appendix_a3() {
        let mut task = JweDecryptCompactTask {
            token: secret(A3_JWE),
            key: secret(A3_KEY),
            options: a128kw(),
        };
        let decrypted = task.compute().unwrap().unwrap();
        assert_eq!(decrypted.plaintext.as_bytes(), A3_PLAINTEXT);
        assert_eq!(decrypted.recipient_index, 0);
    }

    #[test]
    fn decrypt_failures_carry_the_core_codes() {
        let mut not_allowed = JweDecryptCompactTask {
            token: secret(A3_JWE),
            key: secret(A3_KEY),
            options: surface::JweDecryptOptions::new(vec!["dir".into()], vec!["A128GCM".into()]),
        };
        assert_eq!(
            not_allowed.compute().unwrap().unwrap_err().code(),
            "AlgorithmNotAllowed"
        );
        let mut wrong_key = JweDecryptCompactTask {
            token: secret(A3_JWE),
            key: secret(r#"{"kty":"oct","k":"AAECAwQFBgcICQoLDA0ODw"}"#),
            options: a128kw(),
        };
        assert_eq!(
            wrong_key.compute().unwrap().unwrap_err().code(),
            "DecryptionFailed"
        );
    }

    #[test]
    fn json_round_trip_keeps_plaintext_and_aad() {
        let mut encrypt = JweEncryptJsonTask {
            plaintext: Zeroizing::new(A3_PLAINTEXT.to_vec()),
            options: a128kw_encrypt(),
            form: "general".into(),
        };
        let jwe = encrypt.compute().unwrap().unwrap();
        let mut decrypt = JweDecryptJsonTask {
            jwe: Zeroizing::new(jwe),
            key: secret(A3_KEY),
            options: a128kw(),
        };
        let decrypted = decrypt.compute().unwrap().unwrap();
        assert_eq!(decrypted.plaintext.as_bytes(), A3_PLAINTEXT);
        assert_eq!(
            decrypted.aad.as_ref().map(SecretBytes::as_bytes),
            Some(&b"aad"[..])
        );
    }

    #[test]
    fn compact_round_trip_and_unknown_form() {
        let mut encrypt = JweEncryptCompactTask {
            plaintext: Zeroizing::new(A3_PLAINTEXT.to_vec()),
            options: surface::JweEncryptOptions {
                aad: None,
                ..a128kw_encrypt()
            },
        };
        let token = encrypt.compute().unwrap().unwrap();
        let mut decrypt = JweDecryptCompactTask {
            token: Zeroizing::new(token),
            key: secret(A3_KEY),
            options: a128kw(),
        };
        assert_eq!(
            decrypt.compute().unwrap().unwrap().plaintext.as_bytes(),
            A3_PLAINTEXT
        );

        let mut bad_form = JweEncryptJsonTask {
            plaintext: Zeroizing::new(A3_PLAINTEXT.to_vec()),
            options: a128kw_encrypt(),
            form: "compact".into(),
        };
        assert_eq!(
            bad_form.compute().unwrap().unwrap_err().code(),
            "UnsupportedAlgorithm"
        );
    }

    #[test]
    fn jwe_inputs_are_held_in_zeroizing_owners() {
        let encrypt = JweEncryptCompactTask {
            plaintext: Zeroizing::new(Vec::new()),
            options: a128kw_encrypt(),
        };
        wipes_on_drop(&encrypt.plaintext);
        wipes_on_drop(&encrypt.options.recipients[0].key);
        wipes_on_drop(&encrypt.options.aad);
        let decrypt = JweDecryptJsonTask {
            jwe: secret(""),
            key: secret(""),
            options: a128kw(),
        };
        wipes_on_drop(&decrypt.jwe);
        wipes_on_drop(&decrypt.key);
    }
}
