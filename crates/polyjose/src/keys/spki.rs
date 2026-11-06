//! SubjectPublicKeyInfo (RFC 5280 §4.1.2.7) with its AlgorithmIdentifier
//! (RFC 5280 §4.1.1.2), read into and written from `SpkiParts`. The
//! AlgorithmIdentifier is classified against the byte templates in `oid.rs`,
//! in the order of ADR 0018 §4.

use zeroize::Zeroizing;

use super::der::{self, Element, Reader, Writer};
use super::oid;
use super::types::{AlgId, SpkiParts};
use crate::error::{Error, Result};
use crate::jwk::EcCurve;

/// The EC curves polyjose supports (RFC 7518 §6.2.1.1, RFC 8812 §3.1).
const CURVES: [EcCurve; 4] = [
    EcCurve::P256,
    EcCurve::P384,
    EcCurve::P521,
    EcCurve::Secp256k1,
];

/// Reads an AlgorithmIdentifier (RFC 5280 §4.1.1.2) and classifies it; see
/// [`classify`].
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "called by pkcs8.rs once the key mappers (T05-T07) call pkcs8::decode"
    )
)]
pub(crate) fn read_algorithm_identifier(reader: &mut Reader<'_>) -> Result<AlgId> {
    classify(reader.expect(der::SEQUENCE)?)
}

/// Classifies an AlgorithmIdentifier (RFC 5280 §4.1.1.2:
/// `SEQUENCE { algorithm OBJECT IDENTIFIER, parameters ANY OPTIONAL }`).
///
/// It is accepted only if its whole encoding equals one of the templates in
/// `oid.rs` byte for byte (ADR 0018 §2). Otherwise it is parsed only to
/// choose the error, in the order of ADR 0018 §4:
///
/// 0. Not a well-formed AlgorithmIdentifier: an OID that breaks X.690
///    §8.19.2, more than one parameters element, or parameters that are not
///    DER: `InvalidKey`.
/// 1. An OID polyjose does not support, such as id-Ed448 or id-X448
///    (RFC 8410 §3), id-RSASSA-PSS (RFC 4055 §3.1) or DSA:
///    `UnsupportedAlgorithm`.
/// 2. id-ecPublicKey with a specifiedCurve (a SEQUENCE; RFC 5480 §2.1.1
///    says it "MUST NOT be used in PKIX") or a namedCurve outside the JOSE
///    set, such as brainpoolP256r1 (RFC 5639 §4.1) or secp224r1:
///    `UnsupportedAlgorithm`.
/// 3. A supported OID whose parameters differ from its template: NULL or
///    anything else on id-Ed25519/id-X25519, where "the parameters MUST be
///    absent" (RFC 8410 §3); anything but NULL on rsaEncryption, where they
///    "MUST have ASN.1 type NULL" (RFC 3279 §2.3.1); absent or NULL
///    (implicitCurve) EC parameters, which "MUST always be present" as a
///    namedCurve (RFC 5480 §2.1.1): `InvalidKey`.
fn classify(element: Element<'_>) -> Result<AlgId> {
    if let Some((alg, _)) = oid::ALGORITHM_IDENTIFIERS
        .iter()
        .find(|(_, template)| *template == element.encoding)
    {
        return Ok(*alg);
    }
    let mut fields = Reader::new(element.contents)?;
    let algorithm = fields.oid()?;
    let parameters = if fields.is_empty() {
        None
    } else {
        Some(fields.element()?)
    };
    fields.finish()?;
    if let Some(parameters) = parameters {
        der::check_well_formed(parameters.encoding, false)?;
    }
    let mismatch = Err(Error::InvalidKey(
        "AlgorithmIdentifier parameters do not match the algorithm",
    ));
    match algorithm {
        oid::OID_EC_PUBLIC_KEY => match parameters {
            // specifiedCurve (step 2).
            Some(curve) if curve.tag == der::SEQUENCE => Err(Error::UnsupportedAlgorithm),
            Some(curve) if curve.tag == der::OID => match curve.encoding {
                // A namedCurve outside the JOSE set (step 2):
                // brainpoolP256r1, secp224r1, ...
                oid::OID_BRAINPOOL_P256R1 => Err(Error::UnsupportedAlgorithm),
                named if CURVES.iter().any(|crv| oid::named_curve(*crv) == named) => mismatch,
                _ => Err(Error::UnsupportedAlgorithm),
            },
            // Absent, NULL (implicitCurve) or any other type (step 3).
            _ => mismatch,
        },
        oid::OID_ED25519 | oid::OID_X25519 | oid::OID_RSA_ENCRYPTION => mismatch,
        // Step 1: the unsupported OIDs polyjose knows by name, and every
        // other one.
        oid::OID_ED448 | oid::OID_X448 | oid::OID_RSASSA_PSS => Err(Error::UnsupportedAlgorithm),
        _ => Err(Error::UnsupportedAlgorithm),
    }
}

/// Decodes a DER SubjectPublicKeyInfo (RFC 5280 §4.1.2.7):
/// `SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }`,
/// one element with no trailing data (X.690 §8.1.1).
///
/// The algorithm is classified ([`classify`]) before the key is read. The
/// key must be whole octets (RFC 5480 §2.2, RFC 8410 §4, RFC 3279 §2.3.1;
/// X.690 §8.6.2.2) and is returned as a sub-slice of `der`. Its contents
/// (an EC point, an Ed25519/X25519 key, an RSAPublicKey) are left to the
/// key mappers.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "called by the key mappers (T05-T07) and the facade (T08)"
    )
)]
pub(crate) fn decode(der: &[u8]) -> Result<SpkiParts<'_>> {
    let mut outer = Reader::new(der)?;
    let mut fields = outer.sequence()?;
    outer.finish()?;
    let alg = read_algorithm_identifier(&mut fields)?;
    let subject_public_key = fields.bit_string()?;
    fields.finish()?;
    Ok(SpkiParts {
        alg,
        subject_public_key,
    })
}

/// Encodes a SubjectPublicKeyInfo (RFC 5280 §4.1.2.7) in DER: the
/// `oid.rs` template of `parts.alg` and the key in a BIT STRING with no
/// unused bits, the layout OpenSSL 4 emits (ADR 0018 §3).
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "called by the key mappers (T05-T07) and the facade (T08)"
    )
)]
pub(crate) fn encode(parts: &SpkiParts<'_>) -> Result<Zeroizing<Vec<u8>>> {
    let algorithm = oid::algorithm_identifier(parts.alg);
    let body = algorithm.len() + der::bit_string_len(parts.subject_public_key.len());
    let mut writer = Writer::new(der::encoded_len(body))?;
    writer.header(der::SEQUENCE, body)?;
    writer.raw(algorithm)?;
    writer.bit_string(der::BIT_STRING, parts.subject_public_key)?;
    writer.finish()
}

#[cfg(test)]
mod tests {
    use super::super::der::fixtures;
    use super::super::oid;
    use super::*;
    use crate::jwk::EcCurve;

    fn classify_bytes(algorithm_identifier: &[u8]) -> Result<AlgId> {
        let mut reader = Reader::new(algorithm_identifier)?;
        let alg = read_algorithm_identifier(&mut reader)?;
        reader.finish()?;
        Ok(alg)
    }

    /// `SEQUENCE { parts... }` in the short form.
    fn sequence(parts: &[&[u8]]) -> Vec<u8> {
        let body = parts.concat();
        let mut out = vec![0x30, u8::try_from(body.len()).unwrap()];
        out.extend_from_slice(&body);
        out
    }

    fn is_invalid<T>(result: &Result<T>) -> bool {
        matches!(result, Err(Error::InvalidKey(_)))
    }

    fn is_unsupported<T>(result: &Result<T>) -> bool {
        matches!(result, Err(Error::UnsupportedAlgorithm))
    }

    #[test]
    fn every_template_classifies_to_its_algorithm() {
        for (alg, template) in oid::ALGORITHM_IDENTIFIERS {
            assert_eq!(classify_bytes(template).unwrap(), alg);
        }
    }

    #[test]
    fn unknown_or_unsupported_oids_are_unsupported() {
        // ADR 0018 §4 step 1: Ed448 and X448 (RFC 8410 §3), RSASSA-PSS
        // (RFC 4055 §3.1), DSA (RFC 3279 §2.3.2, 1.2.840.10040.4.1), with
        // or without parameters.
        let dsa = [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x01];
        for alg in [
            sequence(&[oid::OID_ED448]),
            sequence(&[oid::OID_X448]),
            sequence(&[oid::OID_RSASSA_PSS]),
            sequence(&[oid::OID_RSASSA_PSS, &sequence(&[])]),
            sequence(&[&dsa, &sequence(&[&[0x02, 0x01, 0x01]])]),
            sequence(&[oid::OID_ED448, &[0x05, 0x00]]),
        ] {
            assert!(is_unsupported(&classify_bytes(&alg)), "{alg:02x?}");
        }
    }

    #[test]
    fn unsupported_ec_parameters_are_unsupported() {
        // ADR 0018 §4 step 2: a specifiedCurve (a SEQUENCE; RFC 5480
        // §2.1.1 "MUST NOT be used in PKIX") or a namedCurve outside the
        // JOSE set: brainpoolP256r1 (RFC 5639), secp224r1 (1.3.132.0.33).
        let secp224r1 = [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x21];
        for alg in [
            sequence(&[oid::OID_EC_PUBLIC_KEY, &sequence(&[&[0x02, 0x01, 0x01]])]),
            sequence(&[oid::OID_EC_PUBLIC_KEY, oid::OID_BRAINPOOL_P256R1]),
            sequence(&[oid::OID_EC_PUBLIC_KEY, &secp224r1]),
        ] {
            assert!(is_unsupported(&classify_bytes(&alg)), "{alg:02x?}");
        }
    }

    #[test]
    fn supported_oids_with_other_parameters_are_invalid() {
        // ADR 0018 §4 step 3: NULL where RFC 8410 §3 requires absence,
        // absence (or anything but NULL) where RFC 3279 §2.3.1 requires
        // NULL, a missing or NULL (implicitCurve) EC parameter where RFC
        // 5480 §2.1.1 requires a namedCurve, and extra fields.
        for alg in [
            sequence(&[oid::OID_ED25519, &[0x05, 0x00]]),
            sequence(&[oid::OID_X25519, &[0x05, 0x00]]),
            sequence(&[oid::OID_X25519, oid::OID_P256]),
            sequence(&[oid::OID_RSA_ENCRYPTION]),
            sequence(&[oid::OID_RSA_ENCRYPTION, &[0x02, 0x01, 0x00]]),
            sequence(&[oid::OID_EC_PUBLIC_KEY]),
            sequence(&[oid::OID_EC_PUBLIC_KEY, &[0x05, 0x00]]),
            sequence(&[oid::OID_EC_PUBLIC_KEY, &[0x02, 0x01, 0x00]]),
        ] {
            assert!(is_invalid(&classify_bytes(&alg)), "{alg:02x?}");
        }
    }

    #[test]
    fn malformed_algorithm_identifiers_are_invalid_whatever_the_oid() {
        // RFC 5280 §4.1.1.2: SEQUENCE { algorithm OID, parameters ANY
        // OPTIONAL }; DER rules apply to unknown parameters too.
        for alg in [
            sequence(&[]),
            sequence(&[&[0x05, 0x00]]),
            sequence(&[oid::OID_ED448, &[0x05, 0x00], &[0x05, 0x00]]),
            sequence(&[oid::OID_P256, oid::OID_P256, oid::OID_P256]),
            sequence(&[&[0x06, 0x04, 0x2B, 0x80, 0x65, 0x70]]),
            sequence(&[oid::OID_RSASSA_PSS, &sequence(&[&[0x02, 0x02, 0x00, 0x01]])]),
            sequence(&[oid::OID_EC_PUBLIC_KEY, &sequence(&[&[0x24, 0x00]])]),
            vec![0x31, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70],
        ] {
            assert!(is_invalid(&classify_bytes(&alg)), "{alg:02x?}");
        }
    }

    /// Each positive SPKI fixture (by stem: its `.der` and `.pem` forms are
    /// both tested where both exist), its algorithm and the octet length of
    /// its subjectPublicKey: an EC point (RFC 5480 §2.2; 1 + 2 × field
    /// octets uncompressed, 1 + field octets compressed), a 32-octet Ed25519
    /// or X25519 key (RFC 8410 §4), or an RSAPublicKey (RFC 8017
    /// App. A.1.1), with the RSA modulus size in bits.
    const POSITIVE: [(&str, &str, AlgId, usize, Option<usize>); 19] = [
        (
            "openssl",
            "ec-p256-spki",
            AlgId::Ec(EcCurve::P256),
            65,
            None,
        ),
        (
            "openssl",
            "ec-p256-spki-compressed",
            AlgId::Ec(EcCurve::P256),
            33,
            None,
        ),
        (
            "openssl",
            "ec-p384-spki",
            AlgId::Ec(EcCurve::P384),
            97,
            None,
        ),
        (
            "openssl",
            "ec-p384-spki-compressed",
            AlgId::Ec(EcCurve::P384),
            49,
            None,
        ),
        (
            "openssl",
            "ec-p521-spki",
            AlgId::Ec(EcCurve::P521),
            133,
            None,
        ),
        (
            "openssl",
            "ec-p521-spki-compressed",
            AlgId::Ec(EcCurve::P521),
            67,
            None,
        ),
        (
            "openssl",
            "ec-secp256k1-spki",
            AlgId::Ec(EcCurve::Secp256k1),
            65,
            None,
        ),
        (
            "openssl",
            "ec-secp256k1-spki-compressed",
            AlgId::Ec(EcCurve::Secp256k1),
            33,
            None,
        ),
        ("openssl", "ed25519-spki", AlgId::Ed25519, 32, None),
        ("openssl", "x25519-spki", AlgId::X25519, 32, None),
        (
            "openssl",
            "rsa2048-spki",
            AlgId::RsaEncryption,
            270,
            Some(2048),
        ),
        (
            "openssl",
            "rsa3072-spki",
            AlgId::RsaEncryption,
            398,
            Some(3072),
        ),
        (
            "openssl",
            "rsa4096-spki",
            AlgId::RsaEncryption,
            526,
            Some(4096),
        ),
        (
            "rfc",
            "rfc7468-fig15-p384-spki",
            AlgId::Ec(EcCurve::P384),
            97,
            None,
        ),
        (
            "rfc",
            "rfc7517-a1-ec-p256-spki",
            AlgId::Ec(EcCurve::P256),
            65,
            None,
        ),
        (
            "rfc",
            "rfc7517-a1-rsa-spki",
            AlgId::RsaEncryption,
            270,
            Some(2048),
        ),
        ("rfc", "rfc8037-a2-ed25519-spki", AlgId::Ed25519, 32, None),
        ("rfc", "rfc8037-a6-x25519-bob-spki", AlgId::X25519, 32, None),
        ("rfc", "rfc8037-a6-x25519-spki", AlgId::X25519, 32, None),
    ];

    /// The RFC 8410 §10.1 Ed25519 SPKI, listed apart because its stem has a
    /// dot.
    const RFC8410_SPKI: (&str, &str, AlgId, usize, Option<usize>) =
        ("rfc", "rfc8410-10.1-ed25519-spki", AlgId::Ed25519, 32, None);

    /// Every positive SPKI fixture file with its expectations.
    fn positive() -> Vec<(&'static str, String, AlgId, usize, Option<usize>)> {
        let mut out = Vec::new();
        for (dir, stem, alg, octets, bits) in POSITIVE.into_iter().chain([RFC8410_SPKI]) {
            let files = fixtures::files(dir, |name| {
                name.strip_suffix(".der")
                    .or_else(|| name.strip_suffix(".pem"))
                    == Some(stem)
            });
            assert!(!files.is_empty(), "{dir}/{stem}");
            out.extend(files.into_iter().map(|file| (dir, file, alg, octets, bits)));
        }
        out
    }

    /// The modulus of an RSAPublicKey (RFC 8017 App. A.1.1), in bits.
    fn modulus_bits(rsa_public_key: &[u8]) -> usize {
        let mut outer = Reader::new(rsa_public_key).unwrap();
        let mut fields = outer.sequence().unwrap();
        outer.finish().unwrap();
        let n = fields.unsigned_integer().unwrap();
        fields.unsigned_integer().unwrap();
        fields.finish().unwrap();
        n.len() * 8 - n[0].leading_zeros() as usize
    }

    #[test]
    fn decodes_every_positive_spki_fixture() {
        for (dir, file, alg, octets, bits) in positive() {
            let der = fixtures::load(dir, &file);
            let parts = decode(&der).unwrap_or_else(|e| panic!("{file}: {e:?}"));
            assert_eq!(parts.alg, alg, "{file}");
            assert_eq!(parts.subject_public_key.len(), octets, "{file}");
            if let Some(bits) = bits {
                assert_eq!(modulus_bits(parts.subject_public_key), bits, "{file}");
            }
        }
    }

    #[test]
    fn the_positive_table_covers_every_spki_fixture() {
        // Every OpenSSL `*-spki*` fixture that is not a `reject-*` file,
        // and every RFC SPKI vector, is in POSITIVE.
        for (dir, keep) in [
            (
                "openssl",
                (|name: &str| name.contains("-spki") && !name.starts_with("reject-"))
                    as fn(&str) -> bool,
            ),
            ("rfc", |name: &str| {
                name.contains("-spki") && !name.starts_with("reject-")
            }),
        ] {
            let listed = positive();
            for file in fixtures::files(dir, keep) {
                assert!(
                    listed.iter().any(|(d, f, ..)| *d == dir && *f == file),
                    "{dir}/{file} missing from POSITIVE"
                );
            }
        }
    }

    #[test]
    fn re_encoding_gives_the_input_bytes() {
        // ADR 0018 §3: export in the layout OpenSSL 4 emits, so
        // encode(decode(x)) == x for every positive fixture.
        for (dir, file, ..) in positive() {
            let der = fixtures::load(dir, &file);
            let parts = decode(&der).unwrap();
            assert_eq!(&encode(&parts).unwrap()[..], &der[..], "{file}");
        }
    }

    #[test]
    fn subject_public_key_borrows_the_input() {
        let der = fixtures::load("rfc", "rfc7517-a1-ec-p256-spki.der");
        let parts = decode(&der).unwrap();
        assert!(
            der.as_ptr_range()
                .contains(&parts.subject_public_key.as_ptr())
        );
        assert_eq!(parts.subject_public_key, &der[der.len() - 65..]);
    }

    #[test]
    fn unused_bits_and_extra_fields_are_invalid() {
        // N30: RFC 5480 §2.2 / X.690 §8.6.2.2, the key is whole octets.
        // N38: RFC 5280 §4.1.2.7, SubjectPublicKeyInfo has exactly two
        // fields.
        for id in ["N30", "N38"] {
            assert!(is_invalid(&decode(&fixtures::negative(id))), "{id}");
        }
    }

    #[test]
    fn classifies_the_spki_negative_vectors() {
        // ADR 0018 §4: N33 (secp224r1) step 2; N32 (no parameters), N37
        // (NULL parameters) and N60 (rsaEncryption without NULL) step 3.
        assert!(is_unsupported(&decode(&fixtures::negative("N33"))));
        for id in ["N32", "N37", "N60"] {
            assert!(is_invalid(&decode(&fixtures::negative(id))), "{id}");
        }
    }

    #[test]
    fn classifies_the_unsupported_openssl_spki_fixtures() {
        for file in [
            "reject-ed448-spki.pem",
            "reject-rsapss2048-spki.pem",
            "reject-ec-brainpoolp256r1-spki.pem",
            "reject-ec-p256-explicit-spki.pem",
        ] {
            let der = fixtures::load("openssl", file);
            let result = decode(&der);
            assert!(is_unsupported(&result), "{file}: {:?}", result.err());
        }
    }

    #[test]
    fn the_container_does_not_judge_key_contents() {
        // Point validity (N31, N34-N36) and the RSAPublicKey inside
        // rsaEncryption (N61-N64, N66) are the key mappers' checks: the
        // container is well-formed, so it decodes.
        for id in [
            "N31", "N34", "N35", "N36", "N61", "N62", "N63", "N64", "N66",
        ] {
            let der = fixtures::negative(id);
            assert!(decode(&der).is_ok(), "{id}");
        }
    }

    #[test]
    fn framing_errors_are_invalid() {
        let der = fixtures::load("rfc", "rfc7517-a1-ec-p256-spki.der");
        assert!(is_invalid(&decode(&der[..der.len() - 1])));
        let mut trailing = der.clone();
        trailing.push(0x00);
        assert!(is_invalid(&decode(&trailing)));
        assert!(is_invalid(&decode(&[])));
        // The subjectPublicKey as an OCTET STRING instead of a BIT STRING.
        let mut octet = der.clone();
        octet[der.len() - 68] = 0x04;
        assert!(is_invalid(&decode(&octet)));
    }

    #[test]
    fn encode_writes_the_template_and_the_key() {
        let key = [0x11; 32];
        let parts = SpkiParts {
            alg: AlgId::X25519,
            subject_public_key: &key,
        };
        let der = encode(&parts).unwrap();
        // RFC 8410 §4: 30 2a 30 05 06 03 2b 65 6e 03 21 00 ‖ key.
        let mut expected = vec![0x30, 0x2A];
        expected.extend_from_slice(oid::ALG_X25519);
        expected.extend_from_slice(&[0x03, 0x21, 0x00]);
        expected.extend_from_slice(&key);
        assert_eq!(&der[..], &expected[..]);
    }

    mod properties {
        use std::sync::OnceLock;

        use proptest::prelude::*;
        use proptest::sample::Index;

        use super::super::super::der::fixtures;
        use super::{decode, encode, positive};

        /// The positive SPKI fixtures, loaded once.
        fn corpus() -> &'static [Vec<u8>] {
            static CORPUS: OnceLock<Vec<Vec<u8>>> = OnceLock::new();
            CORPUS.get_or_init(|| {
                positive()
                    .into_iter()
                    .map(|(dir, file, ..)| fixtures::load(dir, &file))
                    .collect()
            })
        }

        /// Never panics, and canonical: whatever decodes re-encodes to
        /// exactly the input (X.690 §10).
        fn canonical(input: &[u8]) -> Result<(), TestCaseError> {
            if let Ok(parts) = decode(input) {
                let again = encode(&parts);
                prop_assert!(again.is_ok());
                prop_assert_eq!(&again.unwrap()[..], input);
            }
            Ok(())
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(1_000))]

            #[test]
            fn arbitrary_bytes_fail_or_are_canonical(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
                canonical(&bytes)?;
            }

            #[test]
            fn templated_keys_fail_or_are_canonical(
                template in any::<Index>(),
                key in proptest::collection::vec(any::<u8>(), 0..160),
            ) {
                // A real AlgorithmIdentifier and an arbitrary BIT STRING body:
                // these decode whenever the BIT STRING is well-formed.
                let (_, algorithm) = *template.get(&super::super::super::oid::ALGORITHM_IDENTIFIERS);
                let mut body = algorithm.to_vec();
                body.push(0x03);
                body.extend_from_slice(&super::length(key.len()));
                body.extend_from_slice(&key);
                let mut der = vec![0x30];
                der.extend_from_slice(&super::length(body.len()));
                der.extend_from_slice(&body);
                // X.690 §8.6.2: an initial octet of 0 is a valid key BIT STRING.
                prop_assert_eq!(decode(&der).is_ok(), key.first() == Some(&0));
                canonical(&der)?;
            }

            #[test]
            fn single_byte_mutations_never_panic(fixture in any::<Index>(), at in any::<Index>(), byte in any::<u8>()) {
                let mut der = fixture.get(corpus()).clone();
                let i = at.index(der.len());
                der[i] = byte;
                canonical(&der)?;
            }
        }
    }

    /// DER length octets for `len` (X.690 §8.1.3), for building test input.
    fn length(len: usize) -> Vec<u8> {
        match len {
            0..=0x7F => vec![u8::try_from(len).unwrap()],
            0x80..=0xFF => vec![0x81, u8::try_from(len).unwrap()],
            _ => vec![0x82, u8::try_from(len >> 8).unwrap(), (len & 0xFF) as u8],
        }
    }
}
