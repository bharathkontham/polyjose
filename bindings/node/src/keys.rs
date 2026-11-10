//! The key operations (ADR 0030 §4, "JWK"): `jwkGenerateOct`, `jwkGenerateEc`,
//! `jwkGenerateOkp`, `jwkGenerateForAlg`, `jwkFromPem`, `jwkFromDer`, `jwkToPem`, `jwkToDer`
//! (RFC 7518 §6, RFC 8037 §2, RFC 7468, RFC 5958, RFC 5915, RFC 5280, RFC 8017).
//!
//! Generated keys and imported/exported key encodings are secret (ADR 0030 §7): inputs are held
//! in `Zeroizing` task fields, and results are created from the surface's
//! `SecretString`/`SecretBytes`.

use napi::bindgen_prelude::AsyncTask;
use napi_derive::napi;
use polyjose_surface::keys as op;
use polyjose_surface::{SecretBytes, SecretString};
use zeroize::Zeroizing;

use crate::task::surface_task;

surface_task! {
    /// `jwkGenerateOct`: a new `oct` JWK of `len_bytes` random octets (RFC 7518 §6.4).
    JwkGenerateOctTask { len_bytes: u32 } -> SecretString
        = |t| op::jwk_generate_oct(t.len_bytes)
}

/// Generates an `oct` JWK of `lenBytes` octets (16..=512) from the OS CSPRNG (RFC 7518 §6.4,
/// ADR 0005); out of range rejects with `InvalidKey`. Resolves to JWK JSON text.
#[napi]
pub fn jwk_generate_oct(len_bytes: u32) -> AsyncTask<JwkGenerateOctTask> {
    AsyncTask::new(JwkGenerateOctTask { len_bytes })
}

surface_task! {
    /// `jwkGenerateEc`: a new EC private JWK on `crv` (RFC 7518 §6.2, RFC 8812 §3.1).
    JwkGenerateEcTask { crv: String } -> SecretString
        = |t| op::jwk_generate_ec(&t.crv)
}

/// Generates an EC private JWK on `crv` (`P-256`, `P-384`, `P-521`, `secp256k1`) (RFC 7518
/// §6.2, RFC 8812 §3.1); another name rejects with `UnsupportedAlgorithm`. Resolves to JWK JSON
/// text.
#[napi]
pub fn jwk_generate_ec(crv: String) -> AsyncTask<JwkGenerateEcTask> {
    AsyncTask::new(JwkGenerateEcTask { crv })
}

surface_task! {
    /// `jwkGenerateOkp`: a new OKP private JWK on `crv` (RFC 8037 §2).
    JwkGenerateOkpTask { crv: String } -> SecretString
        = |t| op::jwk_generate_okp(&t.crv)
}

/// Generates an OKP private JWK on `crv` (`Ed25519`, `X25519`) (RFC 8037 §2); another name
/// rejects with `UnsupportedAlgorithm`. Resolves to JWK JSON text.
#[napi]
pub fn jwk_generate_okp(crv: String) -> AsyncTask<JwkGenerateOkpTask> {
    AsyncTask::new(JwkGenerateOkpTask { crv })
}

surface_task! {
    /// `jwkGenerateForAlg`: a new JWK suited to `alg`, with `alg` set (RFC 7517 §4.4).
    JwkGenerateForAlgTask { alg: String } -> SecretString
        = |t| op::jwk_generate_for_alg(&t.alg)
}

/// Generates a JWK for the JWS `alg`, JWE `alg` or `enc` name, with `alg` set (RFC 7517 §4.4,
/// RFC 7518 §3.1, §4.1, §5.1). RSA rejects with `UnsupportedAlgorithm` (no RSA key generation,
/// ADR 0067 §3). Resolves to JWK JSON text.
#[napi]
pub fn jwk_generate_for_alg(alg: String) -> AsyncTask<JwkGenerateForAlgTask> {
    AsyncTask::new(JwkGenerateForAlgTask { alg })
}

surface_task! {
    /// `jwkFromPem`: the JWK of a PEM key (RFC 7468).
    JwkFromPemTask { pem: Zeroizing<String> } -> SecretString
        = |t| op::jwk_from_pem(&t.pem)
}

/// Imports a PEM key (`PRIVATE KEY`, `EC PRIVATE KEY`, `RSA PRIVATE KEY`, `PUBLIC KEY`,
/// `RSA PUBLIC KEY`; RFC 7468 §10, §11, §13, RFC 8017 App. A.1) as a JWK; an RSA private key
/// imports with all its members (ADR 0067 §2). Resolves to JWK JSON text.
#[napi]
pub fn jwk_from_pem(pem: String) -> AsyncTask<JwkFromPemTask> {
    AsyncTask::new(JwkFromPemTask {
        pem: Zeroizing::new(pem),
    })
}

surface_task! {
    /// `jwkFromDer`: the JWK of a DER key in `format`.
    JwkFromDerTask { der: Zeroizing<Vec<u8>>, format: String } -> SecretString
        = |t| op::jwk_from_der(&t.der, &t.format)
}

/// Imports a DER key in `format` (`pkcs8` RFC 5958, `sec1` RFC 5915, `spki` RFC 5280 §4.1,
/// `pkcs1` RFC 8017 Appendix A.1.1) as a JWK; another format rejects with
/// `UnsupportedAlgorithm`. The borrowed bytes are copied on the JS thread. Resolves to JWK JSON
/// text.
#[napi]
pub fn jwk_from_der(der: &[u8], format: String) -> AsyncTask<JwkFromDerTask> {
    AsyncTask::new(JwkFromDerTask {
        der: Zeroizing::new(der.to_vec()),
        format,
    })
}

surface_task! {
    /// `jwkToPem`: the JWK as a PEM key in `format` (RFC 7468).
    JwkToPemTask { jwk: Zeroizing<String>, format: String } -> SecretString
        = |t| op::jwk_to_pem(&t.jwk, &t.format)
}

/// Exports `jwk` as PEM in `format` (`pkcs8`, `sec1`, `spki`, `pkcs1`; RFC 7468). A private key
/// exports secret text (ADR 0030 §7). Resolves to a string.
#[napi]
pub fn jwk_to_pem(jwk: String, format: String) -> AsyncTask<JwkToPemTask> {
    AsyncTask::new(JwkToPemTask {
        jwk: Zeroizing::new(jwk),
        format,
    })
}

surface_task! {
    /// `jwkToDer`: the JWK as a DER key in `format`.
    JwkToDerTask { jwk: Zeroizing<String>, format: String } -> SecretBytes
        = |t| op::jwk_to_der(&t.jwk, &t.format)
}

/// Exports `jwk` as DER in `format` (`pkcs8`, `sec1`, `spki`, `pkcs1`). A private key exports
/// secret octets (ADR 0030 §7). Resolves to a `Uint8Array`.
#[napi]
pub fn jwk_to_der(jwk: String, format: String) -> AsyncTask<JwkToDerTask> {
    AsyncTask::new(JwkToDerTask {
        jwk: Zeroizing::new(jwk),
        format,
    })
}

#[cfg(test)]
mod tests {
    use napi::ScopedTask;

    use super::*;
    use crate::tests::{RFC7517_A2_P256_PRIVATE, wipes_on_drop};

    const P256_D: &str = r#""d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE""#;

    #[test]
    fn generated_keys_have_the_requested_type() {
        let mut oct = JwkGenerateOctTask { len_bytes: 32 };
        assert!(
            oct.compute()
                .unwrap()
                .unwrap()
                .as_str()
                .contains(r#""kty":"oct""#)
        );
        let mut ec = JwkGenerateEcTask {
            crv: "P-256".into(),
        };
        assert!(
            ec.compute()
                .unwrap()
                .unwrap()
                .as_str()
                .contains(r#""crv":"P-256""#)
        );
        let mut okp = JwkGenerateOkpTask {
            crv: "Ed25519".into(),
        };
        assert!(
            okp.compute()
                .unwrap()
                .unwrap()
                .as_str()
                .contains(r#""crv":"Ed25519""#)
        );
        let mut for_alg = JwkGenerateForAlgTask {
            alg: "ES256".into(),
        };
        assert!(
            for_alg
                .compute()
                .unwrap()
                .unwrap()
                .as_str()
                .contains(r#""alg":"ES256""#)
        );
    }

    #[test]
    fn generation_failures_carry_the_adr_0030_codes() {
        let mut oct = JwkGenerateOctTask { len_bytes: 8 };
        assert_eq!(oct.compute().unwrap().unwrap_err().code(), "InvalidKey");
        let mut ec = JwkGenerateEcTask {
            crv: "P-192".into(),
        };
        assert_eq!(
            ec.compute().unwrap().unwrap_err().code(),
            "UnsupportedAlgorithm"
        );
        let mut rsa = JwkGenerateForAlgTask {
            alg: "RS256".into(),
        };
        assert_eq!(
            rsa.compute().unwrap().unwrap_err().code(),
            "UnsupportedAlgorithm"
        );
    }

    #[test]
    fn pem_and_der_round_trip_a_private_key() {
        let mut to_pem = JwkToPemTask {
            jwk: Zeroizing::new(RFC7517_A2_P256_PRIVATE.to_owned()),
            format: "pkcs8".into(),
        };
        let pem = to_pem.compute().unwrap().unwrap();
        assert!(pem.as_str().starts_with("-----BEGIN PRIVATE KEY-----"));
        let mut from_pem = JwkFromPemTask {
            pem: Zeroizing::new(pem.as_str().to_owned()),
        };
        assert!(
            from_pem
                .compute()
                .unwrap()
                .unwrap()
                .as_str()
                .contains(P256_D)
        );

        let mut to_der = JwkToDerTask {
            jwk: Zeroizing::new(RFC7517_A2_P256_PRIVATE.to_owned()),
            format: "sec1".into(),
        };
        let der = to_der.compute().unwrap().unwrap();
        let mut from_der = JwkFromDerTask {
            der: Zeroizing::new(der.as_bytes().to_vec()),
            format: "sec1".into(),
        };
        assert!(
            from_der
                .compute()
                .unwrap()
                .unwrap()
                .as_str()
                .contains(P256_D)
        );
    }

    #[test]
    fn unknown_format_is_unsupported() {
        let mut to_der = JwkToDerTask {
            jwk: Zeroizing::new(RFC7517_A2_P256_PRIVATE.to_owned()),
            format: "pem".into(),
        };
        assert_eq!(
            to_der.compute().unwrap().unwrap_err().code(),
            "UnsupportedAlgorithm"
        );
        let mut from_pem = JwkFromPemTask {
            pem: Zeroizing::new("not a pem".to_owned()),
        };
        assert!(from_pem.compute().unwrap().is_err());
    }

    #[test]
    fn key_inputs_are_held_in_zeroizing_owners() {
        let task = JwkFromPemTask {
            pem: Zeroizing::new(String::new()),
        };
        wipes_on_drop(&task.pem);
        let task = JwkFromDerTask {
            der: Zeroizing::new(Vec::new()),
            format: String::new(),
        };
        wipes_on_drop(&task.der);
        let task = JwkToPemTask {
            jwk: Zeroizing::new(String::new()),
            format: String::new(),
        };
        wipes_on_drop(&task.jwk);
        let task = JwkToDerTask {
            jwk: Zeroizing::new(String::new()),
            format: String::new(),
        };
        wipes_on_drop(&task.jwk);
    }
}
