//! DER byte templates of every supported AlgorithmIdentifier
//! (RFC 5280 §4.1.1.2), and the OBJECT IDENTIFIERs used to classify the
//! unsupported ones.
//!
//! A PKCS#8 `privateKeyAlgorithm` or an SPKI `algorithm` is accepted only
//! if it equals one of the [`ALGORITHM_IDENTIFIERS`] byte for byte (ADR 0018
//! §2, the approach of ring's PKCS#8 reader). Any other parameters fail by
//! construction: NULL where RFC 8410 §3 requires absence, absence where
//! RFC 3279 §2.3.1 requires NULL, a specifiedCurve where RFC 5480 §2.1.1
//! requires a namedCurve. The OIDs alone let the classifier tell those cases
//! apart in the order of ADR 0018 §4 (unknown OID, then unsupported EC
//! parameters, then malformed parameters).
//!
//! Every constant is a complete DER element (tag, length, contents).
//! The OIDs come from RFC 5480 §2.1.1 and §2.1.1.1, SEC 2 v2 App. A.2.1
//! (secp256k1), RFC 8410 §3, RFC 8017 App. A.1 / RFC 3279 §2.3.1, RFC 4055
//! §3.1 and RFC 5639 §4.1 (brainpoolP256r1). Each is checked against the
//! committed OpenSSL fixtures.

use super::types::AlgId;
use crate::jwk::EcCurve;

/// id-ecPublicKey, 1.2.840.10045.2.1 (RFC 5480 §2.1.1).
pub(crate) const OID_EC_PUBLIC_KEY: &[u8] = &[0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
/// secp256r1 (P-256), 1.2.840.10045.3.1.7 (RFC 5480 §2.1.1.1).
pub(crate) const OID_P256: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
/// secp384r1 (P-384), 1.3.132.0.34 (RFC 5480 §2.1.1.1).
pub(crate) const OID_P384: &[u8] = &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22];
/// secp521r1 (P-521), 1.3.132.0.35 (RFC 5480 §2.1.1.1).
pub(crate) const OID_P521: &[u8] = &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23];
/// secp256k1, 1.3.132.0.10 (SEC 2 v2 App. A.2.1; no RFC assigns it, and
/// RFC 7468 §10 Figure 12 carries it).
pub(crate) const OID_SECP256K1: &[u8] = &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A];
/// id-X25519, 1.3.101.110 (RFC 8410 §3).
pub(crate) const OID_X25519: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x6E];
/// id-Ed25519, 1.3.101.112 (RFC 8410 §3).
pub(crate) const OID_ED25519: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x70];
/// rsaEncryption, 1.2.840.113549.1.1.1 (RFC 8017 App. A.1, RFC 3279
/// §2.3.1).
pub(crate) const OID_RSA_ENCRYPTION: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
];

/// id-RSASSA-PSS, 1.2.840.113549.1.1.10 (RFC 4055 §3.1). Classification
/// only: such keys are unsupported (ADR 0018 §4).
pub(crate) const OID_RSASSA_PSS: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A,
];
/// id-X448, 1.3.101.111 (RFC 8410 §3). Classification only: unsupported
/// (ADR 0006).
pub(crate) const OID_X448: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x6F];
/// id-Ed448, 1.3.101.113 (RFC 8410 §3). Classification only: unsupported
/// (ADR 0006).
pub(crate) const OID_ED448: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x71];
/// brainpoolP256r1, 1.3.36.3.3.2.8.1.1.7 (RFC 5639 §4.1). Classification
/// only: not a JOSE curve (ADR 0006), so an id-ecPublicKey namedCurve that
/// is not one of the four supported ones is unsupported, not malformed.
pub(crate) const OID_BRAINPOOL_P256R1: &[u8] = &[
    0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07,
];

/// `SEQUENCE { id-ecPublicKey, secp256r1 }` (RFC 5480 §2.1.1: namedCurve).
pub(crate) const ALG_EC_P256: &[u8] = &[
    0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48,
    0xCE, 0x3D, 0x03, 0x01, 0x07,
];
/// `SEQUENCE { id-ecPublicKey, secp384r1 }` (RFC 5480 §2.1.1).
pub(crate) const ALG_EC_P384: &[u8] = &[
    0x30, 0x10, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x05, 0x2B, 0x81, 0x04,
    0x00, 0x22,
];
/// `SEQUENCE { id-ecPublicKey, secp521r1 }` (RFC 5480 §2.1.1).
pub(crate) const ALG_EC_P521: &[u8] = &[
    0x30, 0x10, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x05, 0x2B, 0x81, 0x04,
    0x00, 0x23,
];
/// `SEQUENCE { id-ecPublicKey, secp256k1 }` (RFC 5480 §2.1.1, SEC 2 v2
/// App. A.2.1).
pub(crate) const ALG_EC_SECP256K1: &[u8] = &[
    0x30, 0x10, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x05, 0x2B, 0x81, 0x04,
    0x00, 0x0A,
];
/// `SEQUENCE { id-X25519 }`: "the parameters MUST be absent" (RFC 8410 §3).
pub(crate) const ALG_X25519: &[u8] = &[0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x6E];
/// `SEQUENCE { id-Ed25519 }`: parameters absent (RFC 8410 §3).
pub(crate) const ALG_ED25519: &[u8] = &[0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70];
/// `SEQUENCE { rsaEncryption, NULL }`: the parameters "MUST have ASN.1 type
/// NULL" (RFC 3279 §2.3.1; RFC 8017 App. A.1).
pub(crate) const ALG_RSA_ENCRYPTION: &[u8] = &[
    0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00,
];

/// Every supported AlgorithmIdentifier and the key algorithm it names.
pub(crate) const ALGORITHM_IDENTIFIERS: [(AlgId, &[u8]); 7] = [
    (AlgId::Ec(EcCurve::P256), ALG_EC_P256),
    (AlgId::Ec(EcCurve::P384), ALG_EC_P384),
    (AlgId::Ec(EcCurve::P521), ALG_EC_P521),
    (AlgId::Ec(EcCurve::Secp256k1), ALG_EC_SECP256K1),
    (AlgId::X25519, ALG_X25519),
    (AlgId::Ed25519, ALG_ED25519),
    (AlgId::RsaEncryption, ALG_RSA_ENCRYPTION),
];

/// The DER AlgorithmIdentifier to write for `alg` (RFC 5280 §4.1.1.2), the
/// same bytes OpenSSL 4 emits.
pub(crate) fn algorithm_identifier(alg: AlgId) -> &'static [u8] {
    match alg {
        AlgId::Ec(EcCurve::P256) => ALG_EC_P256,
        AlgId::Ec(EcCurve::P384) => ALG_EC_P384,
        AlgId::Ec(EcCurve::P521) => ALG_EC_P521,
        AlgId::Ec(EcCurve::Secp256k1) => ALG_EC_SECP256K1,
        AlgId::X25519 => ALG_X25519,
        AlgId::Ed25519 => ALG_ED25519,
        AlgId::RsaEncryption => ALG_RSA_ENCRYPTION,
    }
}

/// The namedCurve OID of an EC curve (RFC 5480 §2.1.1.1), for the SEC1
/// `[0]` parameters (RFC 5915 §3).
pub(crate) fn named_curve(crv: EcCurve) -> &'static [u8] {
    match crv {
        EcCurve::P256 => OID_P256,
        EcCurve::P384 => OID_P384,
        EcCurve::P521 => OID_P521,
        EcCurve::Secp256k1 => OID_SECP256K1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// A committed fixture as DER: `.der` files as they are, `.pem` files
    /// decoded by the `pem-rfc7468` oracle (dev-dependency only).
    fn fixture(dir: &str, name: &str) -> Vec<u8> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/keys")
            .join(dir)
            .join(name);
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        if name.ends_with(".pem") {
            let text = String::from_utf8(bytes).expect("PEM is ASCII");
            pem_rfc7468::decode_vec(text.as_bytes())
                .expect("fixture PEM decodes")
                .1
        } else {
            bytes
        }
    }

    /// The contents of the outermost SEQUENCE (X.690 §8.9), for the short
    /// and long length forms the fixtures use.
    fn outer_contents(der: &[u8]) -> &[u8] {
        assert_eq!(der[0], 0x30, "outer SEQUENCE");
        let (header, len) = match der[1] {
            n @ 0..=0x7F => (2, usize::from(n)),
            0x81 => (3, usize::from(der[2])),
            0x82 => (4, usize::from(der[2]) << 8 | usize::from(der[3])),
            other => panic!("unexpected length octet {other:#x}"),
        };
        assert_eq!(der.len(), header + len, "one element, no trailing data");
        &der[header..]
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// The OpenSSL fixtures of each supported algorithm: an SPKI and a
    /// PKCS#8 key (for RSA, PKCS#8 is tested in `rsa.rs`).
    const FIXTURES: [(AlgId, &str, Option<&str>); 7] = [
        (
            AlgId::Ec(EcCurve::P256),
            "ec-p256-spki.der",
            Some("ec-p256-pkcs8.der"),
        ),
        (
            AlgId::Ec(EcCurve::P384),
            "ec-p384-spki.der",
            Some("ec-p384-pkcs8.der"),
        ),
        (
            AlgId::Ec(EcCurve::P521),
            "ec-p521-spki.der",
            Some("ec-p521-pkcs8.der"),
        ),
        (
            AlgId::Ec(EcCurve::Secp256k1),
            "ec-secp256k1-spki.der",
            Some("ec-secp256k1-pkcs8.der"),
        ),
        (AlgId::X25519, "x25519-spki.der", Some("x25519-pkcs8.der")),
        (
            AlgId::Ed25519,
            "ed25519-spki.der",
            Some("ed25519-pkcs8.der"),
        ),
        (AlgId::RsaEncryption, "rsa2048-spki.der", None),
    ];

    #[test]
    fn each_template_is_the_algorithm_identifier_of_its_openssl_fixtures() {
        for (alg, spki, pkcs8) in FIXTURES {
            let template = algorithm_identifier(alg);
            // SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey }
            // (RFC 5280 §4.1.2.7): the template opens the SEQUENCE.
            let der = fixture("openssl", spki);
            assert!(outer_contents(&der).starts_with(template), "{spki}");
            // OneAsymmetricKey ::= SEQUENCE { version, privateKeyAlgorithm, ... }
            // (RFC 5958 §2), version v1 = `02 01 00`.
            if let Some(pkcs8) = pkcs8 {
                let der = fixture("openssl", pkcs8);
                let contents = outer_contents(&der);
                assert_eq!(&contents[..3], [0x02, 0x01, 0x00], "{pkcs8}: version v1");
                assert!(contents[3..].starts_with(template), "{pkcs8}");
            }
        }
    }

    #[test]
    fn templates_are_their_oids_and_parameters() {
        let sequence = |parts: &[&[u8]]| {
            let body = parts.concat();
            let mut der = vec![0x30, u8::try_from(body.len()).expect("short form")];
            der.extend_from_slice(&body);
            der
        };
        for crv in [
            EcCurve::P256,
            EcCurve::P384,
            EcCurve::P521,
            EcCurve::Secp256k1,
        ] {
            assert_eq!(
                algorithm_identifier(AlgId::Ec(crv)),
                sequence(&[OID_EC_PUBLIC_KEY, named_curve(crv)]),
                "{crv}"
            );
        }
        assert_eq!(ALG_X25519, sequence(&[OID_X25519]));
        assert_eq!(ALG_ED25519, sequence(&[OID_ED25519]));
        assert_eq!(
            ALG_RSA_ENCRYPTION,
            sequence(&[OID_RSA_ENCRYPTION, &[0x05, 0x00]])
        );
    }

    #[test]
    fn the_table_and_the_lookup_agree() {
        for (alg, template) in ALGORITHM_IDENTIFIERS {
            assert_eq!(algorithm_identifier(alg), template);
        }
        // No template is a prefix of another, so a byte comparison picks at
        // most one.
        for (i, (_, a)) in ALGORITHM_IDENTIFIERS.iter().enumerate() {
            for (_, b) in &ALGORITHM_IDENTIFIERS[i + 1..] {
                assert!(!a.starts_with(b) && !b.starts_with(a));
            }
        }
    }

    #[test]
    fn named_curve_oids_appear_in_the_sec1_fixtures() {
        // ECPrivateKey `[0]` parameters (RFC 5915 §3): A0 len namedCurve.
        for (crv, file) in [
            (EcCurve::P256, "ec-p256-sec1.der"),
            (EcCurve::P384, "ec-p384-sec1.der"),
            (EcCurve::P521, "ec-p521-sec1.der"),
            (EcCurve::Secp256k1, "ec-secp256k1-sec1.der"),
        ] {
            let oid = named_curve(crv);
            let mut tagged = vec![0xA0, u8::try_from(oid.len()).expect("short")];
            tagged.extend_from_slice(oid);
            assert!(contains(&fixture("openssl", file), &tagged), "{file}");
        }
    }

    #[test]
    fn classification_oids_appear_in_the_reject_fixtures() {
        for (oid, file) in [
            (OID_RSASSA_PSS, "reject-rsapss2048-spki.pem"),
            (OID_ED448, "reject-ed448-spki.pem"),
            (OID_ED448, "reject-ed448-pkcs8.pem"),
            (OID_X448, "reject-x448-pkcs8.pem"),
            (OID_BRAINPOOL_P256R1, "reject-ec-brainpoolp256r1-spki.pem"),
            (OID_BRAINPOOL_P256R1, "reject-ec-brainpoolp256r1-pkcs8.pem"),
        ] {
            let der = fixture("openssl", file);
            assert!(contains(&der, oid), "{file}");
            // None of them matches a supported template.
            for (_, template) in ALGORITHM_IDENTIFIERS {
                assert!(!contains(&der, template), "{file}");
            }
        }
        // The brainpool key is still id-ecPublicKey: only its namedCurve
        // makes it unsupported (ADR 0018 §4 step 2).
        let brainpool = fixture("openssl", "reject-ec-brainpoolp256r1-spki.pem");
        assert!(outer_contents(&brainpool)[2..].starts_with(OID_EC_PUBLIC_KEY));
    }

    #[test]
    fn the_rsa_template_is_also_what_rsa_private_keys_carry() {
        // An RSA private PKCS#8 key names rsaEncryption with NULL too; it is
        // rejected after classification (ADR 0021).
        let der = fixture("openssl", "reject-rsa2048-private-pkcs8.der");
        assert!(outer_contents(&der)[3..].starts_with(ALG_RSA_ENCRYPTION));
    }
}
