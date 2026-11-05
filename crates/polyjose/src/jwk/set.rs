//! JWK Set (RFC 7517 §5) and verification key selection (ADR 0029 §2).

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

    use crate::jwa::SigningAlg;
    use crate::jwk::Jwk;

    /// RFC 7517 Appendix A.1, the P-256 public key.
    const EC_P256: &str = r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}"#;
    /// RFC 7517 Appendix A.1, the 2048-bit RSA public key.
    const RSA_2048: &str = r#"{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"}"#;
    /// RFC 7517 Appendix A.3, the HMAC key.
    const OCT: &str = r#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#;
    /// RFC 8037 Appendix A.2, the Ed25519 public key.
    const ED25519: &str =
        r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
    /// RFC 8037 Appendix A.6, the X25519 public key (a key agreement key).
    const X25519: &str =
        r#"{"kty":"OKP","crv":"X25519","x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"}"#;

    /// An EC public key on `crv`, with coordinates of the right length (the
    /// family table does not look at the point).
    fn ec(crv: &str, len: usize) -> Jwk {
        let coordinate = crate::util::b64url_encode(&vec![7u8; len]);
        let json = format!(r#"{{"kty":"EC","crv":"{crv}","x":"{coordinate}","y":"{coordinate}"}}"#);
        Jwk::from_json(json.as_bytes()).unwrap()
    }

    fn jwk(json: &str) -> Jwk {
        Jwk::from_json(json.as_bytes()).unwrap()
    }

    /// ADR 0026 §2 step 8: the whole alg → key family table, every row
    /// against every key kind.
    #[test]
    fn family_table_matches_adr_0026_step_8() {
        let keys = [
            ("oct", jwk(OCT)),
            ("RSA", jwk(RSA_2048)),
            ("P-256", jwk(EC_P256)),
            ("P-384", ec("P-384", 48)),
            ("P-521", ec("P-521", 66)),
            ("secp256k1", ec("secp256k1", 32)),
            ("Ed25519", jwk(ED25519)),
            ("X25519", jwk(X25519)),
        ];
        let table: &[(SigningAlg, &str)] = &[
            (SigningAlg::HS256, "oct"),
            (SigningAlg::HS384, "oct"),
            (SigningAlg::HS512, "oct"),
            (SigningAlg::RS256, "RSA"),
            (SigningAlg::RS384, "RSA"),
            (SigningAlg::RS512, "RSA"),
            (SigningAlg::PS256, "RSA"),
            (SigningAlg::PS384, "RSA"),
            (SigningAlg::PS512, "RSA"),
            (SigningAlg::ES256, "P-256"),
            (SigningAlg::ES384, "P-384"),
            (SigningAlg::ES512, "P-521"),
            (SigningAlg::ES256K, "secp256k1"),
            (SigningAlg::EdDSA, "Ed25519"),
            (SigningAlg::Ed25519, "Ed25519"),
        ];
        // The table covers every known algorithm except `none`.
        assert_eq!(table.len() + 1, SigningAlg::KNOWN.len());
        for (alg, family) in table {
            for (kind, key) in &keys {
                assert_eq!(
                    key.material().serves_signing_alg(alg),
                    kind == family,
                    "{alg} with a {kind} key"
                );
            }
        }
        // `none` and unknown algorithms are served by no key (RFC 8725 §3.1).
        for alg in [
            SigningAlg::None,
            SigningAlg::from("Ed448"),
            SigningAlg::from("hs256"),
        ] {
            for (kind, key) in &keys {
                assert!(
                    !key.material().serves_signing_alg(&alg),
                    "{alg} with {kind}"
                );
            }
        }
    }
}
