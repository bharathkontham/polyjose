//! PKCS#8 private keys: OneAsymmetricKey / PrivateKeyInfo (RFC 5958 §2,
//! RFC 5208 §5), versions v1(0) and v2(1) with the `[0]` attributes and the
//! `[1]` publicKey, read into and written from `Pkcs8Parts`.
//! EncryptedPrivateKeyInfo (RFC 5958 §3) is rejected as unsupported
//! (ADR 0018 §4).

use zeroize::Zeroizing;

use super::der::{self, Reader, Writer};
use super::oid;
use super::spki;
use super::types::Pkcs8Parts;
use crate::error::{Error, Result};

/// `version` v1(0): PrivateKeyInfo, no publicKey (RFC 5958 §2, RFC 5208
/// §5).
const V1: u8 = 0;
/// `version` v2(1): OneAsymmetricKey with a publicKey (RFC 5958 §2).
const V2: u8 = 1;

/// Decodes a DER OneAsymmetricKey (RFC 5958 §2):
///
/// ```text
/// OneAsymmetricKey ::= SEQUENCE {
///   version                   Version,
///   privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
///   privateKey                PrivateKey,          -- OCTET STRING
///   attributes            [0] Attributes OPTIONAL, -- IMPLICIT SET OF
///   ...,
///   [[2: publicKey        [1] PublicKey OPTIONAL ]], -- IMPLICIT BIT STRING
///   ... }
/// ```
///
/// - One element, no trailing data (X.690 §8.1.1), and no fields beyond
///   publicKey: polyjose knows no later version.
/// - An EncryptedPrivateKeyInfo (RFC 5958 §3) starts with a SEQUENCE where
///   this starts with the version INTEGER. Only its exact shape, `SEQUENCE {
///   SEQUENCE, OCTET STRING }`, is unsupported (ADR 0018 §4), and nothing
///   inside it is parsed; any other leading SEQUENCE is `InvalidKey`
///   (`check_encrypted_shape`).
/// - `version` is v1(0) or v2(1), and "If publicKey is present, then version
///   is set to v2 else version is set to v1" (RFC 5958 §2).
/// - The algorithm is classified first (`spki::read_algorithm_identifier`,
///   ADR 0018 §4). rsaEncryption is an RSA private key, whose privateKey
///   `keys::rsa::from_pkcs8` decodes as an RSAPrivateKey (RFC 8017 App. A.1.2,
///   ADR 0067).
/// - The attributes must be well-formed DER (a SET OF Attribute) and are
///   then ignored (ADR 0018 §3).
/// - privateKey and publicKey are returned as sub-slices of `der`, whose
///   buffer the caller must zeroize; the publicKey has no unused bits.
/// - Input that is not PKCS#8, such as a PKCS#1 RSAPrivateKey (RFC 8017
///   App. A.1.2) under a `PRIVATE KEY` label, is `InvalidKey`: it is the
///   wrong structure for the format (ADR 0018 §3; the `RSA PRIVATE KEY`
///   label and `KeyFormat::Pkcs1` read it, ADR 0067).
pub(crate) fn decode(der: &[u8]) -> Result<Pkcs8Parts<'_>> {
    decode_with_attributes(der).map(|(parts, _)| parts)
}

/// [`decode`], also returning the whole `[0]` attributes element, so tests
/// can check that the codec is canonical for keys that carry attributes.
fn decode_with_attributes(der: &[u8]) -> Result<(Pkcs8Parts<'_>, Option<&[u8]>)> {
    let mut outer = Reader::new(der)?;
    let mut fields = outer.sequence()?;
    outer.finish()?;
    if fields.peek_tag() == Some(der::SEQUENCE) {
        check_encrypted_shape(fields)?;
        return Err(Error::UnsupportedAlgorithm);
    }
    let version = fields.small_unsigned()?;
    if version != V1 && version != V2 {
        return Err(Error::InvalidKey("PKCS#8 version is not v1 or v2"));
    }
    let alg = spki::read_algorithm_identifier(&mut fields)?;
    let private_key = fields.octet_string()?;
    let attributes = fields.optional(der::CONTEXT_0)?;
    if let Some(attributes) = attributes {
        check_attributes(attributes.contents)?;
    }
    let public_key = if fields.peek_tag() == Some(der::CONTEXT_1_PRIMITIVE) {
        Some(fields.implicit_bit_string(der::CONTEXT_1_PRIMITIVE)?)
    } else {
        None
    };
    fields.finish()?;
    if (version == V2) != public_key.is_some() {
        return Err(Error::InvalidKey(
            "PKCS#8 version does not match the publicKey",
        ));
    }
    let parts = Pkcs8Parts {
        version,
        alg,
        private_key,
        public_key,
    };
    Ok((parts, attributes.map(|attributes| attributes.encoding)))
}

/// Checks that `fields`, the contents of an outer SEQUENCE whose first
/// element is a SEQUENCE, have the EncryptedPrivateKeyInfo shape (RFC 5958
/// §3):
///
/// ```text
/// EncryptedPrivateKeyInfo ::= SEQUENCE {
///   encryptionAlgorithm  EncryptionAlgorithmIdentifier, -- a SEQUENCE
///   encryptedData        EncryptedData }                -- OCTET STRING
/// ```
///
/// - `Ok` means exactly that shape: a well-formed encrypted key, which the
///   caller reports as `UnsupportedAlgorithm` (ADR 0018 §4).
/// - Only the framing of the two elements is read (X.690 §8.1, §10.1, and a
///   primitive OCTET STRING, §10.2). Neither the AlgorithmIdentifier's
///   contents nor the ciphertext is ever parsed.
/// - Anything else, such as an SPKI (`SEQUENCE { AlgorithmIdentifier, BIT
///   STRING }`, RFC 5280 §4.1.2.7), a missing encryptedData or a third
///   element (X.690 §8.1.1), is malformed PKCS#8: `InvalidKey` with the
///   reader's static detail.
fn check_encrypted_shape(mut fields: Reader<'_>) -> Result<()> {
    fields.expect(der::SEQUENCE)?;
    fields.octet_string()?;
    fields.finish()
}

/// Checks the contents of `[0] Attributes`, an IMPLICIT `SET OF Attribute`
/// (RFC 5958 §2), where `Attribute ::= SEQUENCE { attrType OBJECT
/// IDENTIFIER, attrValues SET OF AttributeValue }` (RFC 5652 §5.3). Every
/// value must be well-formed DER (`der::check_well_formed`), and the SET
/// OF sorted (X.690 §11.6). The attributes are then ignored (ADR 0018 §3).
fn check_attributes(contents: &[u8]) -> Result<()> {
    der::check_well_formed(contents, true)?;
    let mut set = Reader::new(contents)?;
    while !set.is_empty() {
        let mut attribute = set.sequence()?;
        attribute.oid()?;
        attribute.expect(der::SET)?;
        attribute.finish()?;
    }
    Ok(())
}

/// Encodes a OneAsymmetricKey (RFC 5958 §2) in DER, without attributes:
/// v1 without a publicKey, or v2 with one, in the layout OpenSSL 4 emits
/// (ADR 0018 §3).
///
/// `parts.version` must agree with `parts.public_key` (RFC 5958 §2). The
/// output is zeroized on drop.
pub(crate) fn encode(parts: &Pkcs8Parts<'_>) -> Result<Zeroizing<Vec<u8>>> {
    encode_with_attributes(parts, None)
}

/// [`encode`], with `attributes` (a whole `[0]` element as
/// [`decode_with_attributes`] returns it) written after privateKey.
fn encode_with_attributes(
    parts: &Pkcs8Parts<'_>,
    attributes: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>> {
    let version = if parts.public_key.is_some() { V2 } else { V1 };
    if parts.version != version {
        return Err(Error::InvalidKey(
            "PKCS#8 version does not match the publicKey",
        ));
    }
    let algorithm = oid::algorithm_identifier(parts.alg);
    let attributes = attributes.unwrap_or(&[]);
    let public_key_len = parts
        .public_key
        .map_or(0, |key| der::bit_string_len(key.len()));
    let body = der::unsigned_integer_len(&[version])
        + algorithm.len()
        + der::encoded_len(parts.private_key.len())
        + attributes.len()
        + public_key_len;
    let mut writer = Writer::new(der::encoded_len(body))?;
    writer.header(der::SEQUENCE, body)?;
    writer.unsigned_integer(&[version])?;
    writer.raw(algorithm)?;
    writer.element(der::OCTET_STRING, parts.private_key)?;
    writer.raw(attributes)?;
    if let Some(key) = parts.public_key {
        writer.bit_string(der::CONTEXT_1_PRIMITIVE, key)?;
    }
    writer.finish()
}

#[cfg(test)]
mod tests {
    use super::super::der::fixtures;
    use super::super::types::AlgId;
    use super::*;
    use crate::jwk::EcCurve;

    fn is_invalid<T>(result: &Result<T>) -> bool {
        matches!(result, Err(Error::InvalidKey(_)))
    }

    fn is_unsupported<T>(result: &Result<T>) -> bool {
        matches!(result, Err(Error::UnsupportedAlgorithm))
    }

    /// RFC 8037 App. A.1 as PKCS#8 v1: `30 2e 02 01 00 30 05 06 03 2b 65 70
    /// 04 22 04 20 ‖ d` (RFC 8410 §7).
    fn ed25519_v1() -> Vec<u8> {
        fixtures::load("rfc", "rfc8037-a1-ed25519-pkcs8.der")
    }

    #[test]
    fn framing_vectors_n01_to_n12_are_invalid() {
        // X.690 §10.1, §8.1.3, §8.1.2.4, §8.3.2, §10.2, §8.1.1 (manifest).
        let framing: Vec<_> = fixtures::negatives()
            .into_iter()
            .filter(|n| {
                matches!(
                    n.id.as_str(),
                    "N01"
                        | "N02"
                        | "N03"
                        | "N04"
                        | "N05"
                        | "N06"
                        | "N07"
                        | "N08"
                        | "N09"
                        | "N10"
                        | "N11"
                        | "N12"
                )
            })
            .collect();
        assert_eq!(framing.len(), 12);
        for vector in framing {
            assert_eq!(vector.expect, "InvalidKey", "{}", vector.id);
            let der = fixtures::load("negative", &vector.file);
            let result = decode(&der);
            assert!(is_invalid(&result), "{}: {:?}", vector.id, result.err());
        }
    }

    #[test]
    fn container_vectors_are_invalid() {
        // N22: OID subidentifier not minimal (X.690 §8.19.2). N23: version
        // 2 (RFC 5958 §2 has v1(0) and v2(1)). N24: v1 with a publicKey
        // ("If publicKey is present, then version is set to v2", §2).
        for id in ["N22", "N23", "N24"] {
            let der = fixtures::negative(id);
            let result = decode(&der);
            assert!(is_invalid(&result), "{id}: {:?}", result.err());
        }
    }

    #[test]
    fn v2_without_a_public_key_is_invalid() {
        // RFC 5958 §2: "... else version is set to v1".
        let mut der = ed25519_v1();
        assert_eq!(&der[2..5], &[0x02, 0x01, 0x00]);
        der[4] = 0x01;
        assert!(is_invalid(&decode(&der)));
    }

    #[test]
    fn the_private_key_must_be_a_primitive_octet_string() {
        // RFC 5958 §2: PrivateKey ::= OCTET STRING; X.690 §10.2.
        let mut der = ed25519_v1();
        assert_eq!(der[12], 0x04);
        der[12] = 0x02; // INTEGER: well-formed (04 20 ... is minimal), wrong type
        assert!(is_invalid(&decode(&der)));
        der[12] = 0x03; // BIT STRING
        assert!(is_invalid(&decode(&der)));
        let n05 = fixtures::negative("N05"); // constructed OCTET STRING
        assert!(is_invalid(&decode(&n05)));
    }

    #[test]
    fn rfc8410_v2_with_attributes_and_public_key_decodes() {
        // RFC 8410 §10.3: version 1, id-Ed25519, CurvePrivateKey (34 octets
        // with its own OCTET STRING header), one attribute (ignored) and a
        // 32-octet [1] publicKey.
        let der = fixtures::load("rfc", "rfc8410-10.3-ed25519-pkcs8-v2-attr-pub.pem");
        let (parts, attributes) = decode_with_attributes(&der).unwrap();
        assert_eq!(parts.version, 1);
        assert_eq!(parts.alg, AlgId::Ed25519);
        assert_eq!(parts.private_key.len(), 34);
        assert_eq!(&parts.private_key[..2], &[0x04, 0x20]);
        assert_eq!(parts.public_key.map(<[u8]>::len), Some(32));
        let attributes = attributes.unwrap();
        assert_eq!(attributes[0], 0xA0);
        assert_eq!(attributes.len(), 33);
        // RFC 8410 §10.1 is the matching public key (research.md §8).
        let spki = fixtures::load("rfc", "rfc8410-10.1-ed25519-spki.pem");
        assert_eq!(parts.public_key.unwrap(), &spki[spki.len() - 32..]);
    }

    /// The RFC 8410 §10.3 v2 key with its `[0]` attributes replaced by
    /// `attributes` (a whole element, or nothing).
    fn v2_with_attributes(attributes: &[u8]) -> Vec<u8> {
        let der = fixtures::load("rfc", "rfc8410-10.3-ed25519-pkcs8-v2-attr-pub.pem");
        let (parts, _) = decode_with_attributes(&der).unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&[0x02, 0x01, 0x01]);
        body.extend_from_slice(super::super::oid::ALG_ED25519);
        body.extend_from_slice(&[0x04, 0x22]);
        body.extend_from_slice(parts.private_key);
        body.extend_from_slice(attributes);
        body.extend_from_slice(&[0x81, 0x21, 0x00]);
        body.extend_from_slice(parts.public_key.unwrap());
        let mut out = vec![0x30, u8::try_from(body.len()).unwrap()];
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn attributes_must_be_well_formed_der() {
        // ADR 0018 §3: checked as well-formed DER, then ignored.
        // Attributes ::= SET OF Attribute (RFC 5958 §2); Attribute ::=
        // SEQUENCE { attrType OBJECT IDENTIFIER, attrValues SET OF
        // AttributeValue } (RFC 5652 §5.3).
        let oid = [0x06, 0x03, 0x2A, 0x03, 0x04];
        let attribute = |values: &[u8]| {
            let mut set = vec![0x31, u8::try_from(values.len()).unwrap()];
            set.extend_from_slice(values);
            let mut seq = vec![0x30, u8::try_from(oid.len() + set.len()).unwrap()];
            seq.extend_from_slice(&oid);
            seq.extend_from_slice(&set);
            seq
        };
        let tagged = |contents: &[u8]| {
            let mut out = vec![0xA0, u8::try_from(contents.len()).unwrap()];
            out.extend_from_slice(contents);
            out
        };
        // Accepted: none, an empty SET OF, one and two (sorted) attributes.
        for ok in [
            vec![],
            tagged(&[]),
            tagged(&attribute(&[0x0C, 0x01, 0x41])),
            tagged(
                &[
                    attribute(&[0x02, 0x01, 0x01]),
                    attribute(&[0x02, 0x01, 0x02]),
                ]
                .concat(),
            ),
        ] {
            let der = v2_with_attributes(&ok);
            let (parts, attributes) = decode_with_attributes(&der).unwrap();
            assert_eq!(parts.version, 1);
            assert_eq!(attributes.unwrap_or(&[]), &ok[..]);
        }
        for bad in [
            // Not DER inside: a constructed UTF8String, a non-minimal INTEGER.
            tagged(&attribute(&[0x2C, 0x03, 0x0C, 0x01, 0x41])),
            tagged(&attribute(&[0x02, 0x02, 0x00, 0x01])),
            // Not sorted (X.690 §11.6).
            tagged(
                &[
                    attribute(&[0x02, 0x01, 0x02]),
                    attribute(&[0x02, 0x01, 0x01]),
                ]
                .concat(),
            ),
            // Not an Attribute: no SET of values, a bare NULL.
            tagged(&[0x30, 0x05, 0x06, 0x03, 0x2A, 0x03, 0x04]),
            tagged(&[0x05, 0x00]),
            // The IMPLICIT [0] SET OF is constructed; a primitive [0] is not it.
            vec![0x80, 0x00],
        ] {
            let der = v2_with_attributes(&bad);
            assert!(is_invalid(&decode(&der)), "{bad:02x?}");
        }
    }

    #[test]
    fn fields_out_of_order_are_invalid() {
        // RFC 5958 §2 order: version, privateKeyAlgorithm, privateKey,
        // [0] attributes, [1] publicKey; nothing after it.
        let der = fixtures::load("rfc", "rfc8410-10.3-ed25519-pkcs8-v2-attr-pub.pem");
        let (parts, attributes) = decode_with_attributes(&der).unwrap();
        let attributes = attributes.unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&[0x02, 0x01, 0x01]);
        body.extend_from_slice(super::super::oid::ALG_ED25519);
        body.extend_from_slice(&[0x04, 0x22]);
        body.extend_from_slice(parts.private_key);
        body.extend_from_slice(&[0x81, 0x21, 0x00]);
        body.extend_from_slice(parts.public_key.unwrap());
        body.extend_from_slice(attributes);
        let mut swapped = vec![0x30, u8::try_from(body.len()).unwrap()];
        swapped.extend_from_slice(&body);
        assert!(is_invalid(&decode(&swapped)));
        // A second publicKey.
        let mut twice = v2_with_attributes(&[]);
        twice.extend_from_slice(&[0x81, 0x02, 0x00, 0x00]);
        twice[1] += 4;
        assert!(is_invalid(&decode(&twice)));
    }

    #[test]
    fn classifies_the_pkcs8_vectors() {
        // ADR 0018 §4: N21 (id-Ed448) step 1; N20 (NULL parameters on
        // id-Ed25519) step 3.
        assert!(is_unsupported(&decode(&fixtures::negative("N21"))));
        assert!(is_invalid(&decode(&fixtures::negative("N20"))));
        for file in [
            "reject-ed448-pkcs8.pem",
            "reject-x448-pkcs8.pem",
            "reject-rsapss2048-private-pkcs8.pem",
            "reject-ec-brainpoolp256r1-pkcs8.pem",
            "reject-ec-p256-explicit-pkcs8.pem",
        ] {
            let der = fixtures::load("openssl", file);
            let result = decode(&der);
            assert!(is_unsupported(&result), "{file}: {:?}", result.err());
        }
    }

    #[test]
    fn rsa_private_keys_decode_as_rsa_encryption_containers() {
        // ADR 0067: a PKCS#8 rsaEncryption key (RFC 5958 §2, RFC 3279
        // §2.3.1) is an RSA private key; the container hands its privateKey
        // to `keys::rsa::from_pkcs8`, which reads the RSAPrivateKey (RFC 8017
        // App. A.1.2).
        for der in [
            fixtures::load("openssl", "reject-rsa2048-private-pkcs8.der"),
            fixtures::load("openssl", "reject-rsa4096-private-pkcs8.pem"),
        ] {
            let parts = decode(&der).unwrap();
            assert_eq!((parts.version, parts.alg), (0, AlgId::RsaEncryption));
            assert!(parts.public_key.is_none());
            assert!(super::super::pkcs1::decode_private(parts.private_key).is_ok());
        }
        // The container does not judge the privateKey contents: garbage
        // there is the RSA mapper's InvalidKey, not the container's.
        let mut body = vec![0x02, 0x01, 0x00];
        body.extend_from_slice(super::super::oid::ALG_RSA_ENCRYPTION);
        body.extend_from_slice(&[0x04, 0x03, 0x30, 0x80, 0xFF]);
        let mut der = vec![0x30, u8::try_from(body.len()).unwrap()];
        der.extend_from_slice(&body);
        assert_eq!(decode(&der).unwrap().alg, AlgId::RsaEncryption);
        assert!(is_invalid(&crate::jwk::Jwk::from_der(
            &der,
            super::super::KeyFormat::Pkcs8
        )));
    }

    /// `SEQUENCE { version, field × count }` with a one-octet long-form
    /// length where needed.
    fn version_then(version: &[u8], field: &[u8], count: usize) -> Vec<u8> {
        let mut body = version.to_vec();
        for _ in 0..count {
            body.extend_from_slice(field);
        }
        let mut der = vec![0x30];
        match u8::try_from(body.len()).unwrap() {
            len @ 0..=0x7F => der.push(len),
            len => der.extend_from_slice(&[0x81, len]),
        }
        der.extend_from_slice(&body);
        der
    }

    #[test]
    fn a_pkcs1_rsa_private_key_read_as_pkcs8_is_invalid() {
        // ADR 0067 (amending ADR 0018 §3): a PKCS#1 RSAPrivateKey (RFC 8017
        // App. A.1.2) given as PKCS#8 fails the RFC 5958 §2 parse at the
        // AlgorithmIdentifier: the wrong structure for the format.
        for (dir, file) in [
            ("openssl", "reject-rsa2048-private-pkcs1.der"),
            ("openssl", "reject-rsa2048-3prime-private-pkcs1.pem"),
            ("rfc", "reject-rfc9500-testRSA2048-private-pkcs1.pem"),
        ] {
            let der = fixtures::load(dir, file);
            let result = decode(&der);
            assert!(is_invalid(&result), "{file}: {:?}", result.err());
        }
    }

    #[test]
    fn rsa_private_key_shapes_are_invalid_pkcs8() {
        // ADR 0067: whatever the eight INTEGERs hold (empty, X.690 §8.3.1;
        // not minimal, §8.3.2), an RSAPrivateKey shape is not PKCS#8.
        let two_prime: &[u8] = &[0x02, 0x01, 0x00];
        let multi: &[u8] = &[0x02, 0x01, 0x01];
        for (version, field) in [
            (two_prime, &[0x02, 0x00][..]),
            (multi, &[0x02, 0x02, 0x00, 0x01][..]),
            (two_prime, &[0x02, 0x02, 0xFF, 0x80][..]),
        ] {
            let der = version_then(version, field, 8);
            let result = decode(&der);
            assert!(is_invalid(&result), "{:?}", result.err());
        }
    }

    #[test]
    fn near_rsa_private_shapes_stay_invalid_pkcs8() {
        // Not an RSAPrivateKey (RFC 8017 App. A.1.2), so plain malformed
        // PKCS#8 (ADR 0018 §4): too few INTEGERs, a version outside 0/1,
        // a non-INTEGER field, trailing data.
        let two_prime: &[u8] = &[0x02, 0x01, 0x00];
        let small: &[u8] = &[0x02, 0x01, 0x05];
        let mut trailing = version_then(two_prime, small, 8);
        trailing.push(0x00);
        let mut octet_last = version_then(two_prime, small, 7);
        octet_last[1] += 3;
        octet_last.extend_from_slice(&[0x04, 0x01, 0x00]);
        for (what, der) in [
            ("version alone", version_then(two_prime, small, 0)),
            ("seven INTEGERs", version_then(two_prime, small, 7)),
            ("version 2", version_then(&[0x02, 0x01, 0x02], small, 8)),
            ("an OCTET STRING as the eighth", octet_last),
            ("trailing data", trailing),
        ] {
            assert!(is_invalid(&decode(&der)), "{what}");
        }
    }

    #[test]
    fn encrypted_private_key_info_is_unsupported_and_not_parsed() {
        // RFC 5958 §3: EncryptedPrivateKeyInfo starts with a SEQUENCE (its
        // AlgorithmIdentifier) where OneAsymmetricKey has the version
        // INTEGER.
        for (dir, file) in [
            ("openssl", "reject-ec-p256-pkcs8-encrypted.der"),
            ("openssl", "reject-ec-p256-pkcs8-encrypted.pem"),
            ("openssl", "reject-ed25519-pkcs8-encrypted.pem"),
            ("openssl", "reject-rsa2048-pkcs8-encrypted.pem"),
        ] {
            let der = fixtures::load(dir, file);
            assert_eq!(&der[..1], &[0x30]);
            let result = decode(&der);
            assert!(is_unsupported(&result), "{file}: {:?}", result.err());
        }
        // Only the framing of the two components is read: BER and garbage
        // inside encryptedData or inside the AlgorithmIdentifier give the
        // same answer.
        for input in [
            // SEQUENCE { SEQUENCE {}, OCTET STRING {} }
            &[0x30, 0x04, 0x30, 0x00, 0x04, 0x00][..],
            // encryptedData holding an indefinite length and garbage.
            &[
                0x30, 0x09, 0x30, 0x00, 0x04, 0x05, 0x30, 0x80, 0xFF, 0x00, 0x1F,
            ],
            // encryptionAlgorithm holding no OID, an indefinite length and
            // garbage.
            &[0x30, 0x08, 0x30, 0x04, 0x02, 0x80, 0xFF, 0xFF, 0x04, 0x00],
        ] {
            assert!(is_unsupported(&decode(input)), "{input:02x?}");
        }
        // A real encrypted key whose ciphertext is flipped: encryptedData is
        // the last element, so its last 32 octets are all ciphertext.
        let mut der = fixtures::load("openssl", "reject-ec-p256-pkcs8-encrypted.der");
        let len = der.len();
        for byte in &mut der[len - 32..] {
            *byte ^= 0xFF;
        }
        assert!(is_unsupported(&decode(&der)));
        // The outer framing is still checked.
        assert!(is_invalid(&decode(&[0x30, 0x02, 0x30, 0x00, 0x00])));
    }

    /// `SEQUENCE { parts }` with a short- or long-form length.
    fn seq(parts: &[&[u8]]) -> Vec<u8> {
        let contents = parts.concat();
        let mut out = vec![der::SEQUENCE];
        match contents.len() {
            len @ 0..=0x7F => out.push(u8::try_from(len).unwrap()),
            len @ 0x80..=0xFF => out.extend_from_slice(&[0x81, u8::try_from(len).unwrap()]),
            len => {
                let len = u16::try_from(len).unwrap().to_be_bytes();
                out.extend_from_slice(&[0x82, len[0], len[1]]);
            }
        }
        out.extend_from_slice(&contents);
        out
    }

    #[test]
    fn only_the_encrypted_private_key_info_shape_is_unsupported() {
        // RFC 5958 §3: EncryptedPrivateKeyInfo is exactly `SEQUENCE {
        // AlgorithmIdentifier (a SEQUENCE), OCTET STRING }`. Anything else
        // that starts with an inner SEQUENCE is malformed PKCS#8, so
        // InvalidKey (ADR 0018 §4).
        let alg: &[u8] = &[0x30, 0x00];
        let data: &[u8] = &[0x04, 0x01, 0x00];
        for (what, input) in [
            (
                "an SPKI: BIT STRING second",
                seq(&[alg, &[0x03, 0x01, 0x00]]),
            ),
            ("no encryptedData", seq(&[alg])),
            ("an INTEGER second", seq(&[alg, &[0x02, 0x01, 0x00]])),
            ("a SEQUENCE second", seq(&[alg, alg])),
            ("a constructed OCTET STRING", seq(&[alg, &[0x24, 0x00]])),
            ("a third element", seq(&[alg, data, data])),
            ("a trailing NULL", seq(&[alg, data, &[0x05, 0x00]])),
            ("a stray octet", seq(&[alg, data, &[0x00]])),
            (
                "an indefinite-length AlgorithmIdentifier",
                seq(&[&[0x30, 0x80, 0x00, 0x00], data]),
            ),
            (
                "an AlgorithmIdentifier longer than its SEQUENCE",
                seq(&[&[0x30, 0x05], data]),
            ),
            ("non-SEQUENCE first: OCTET STRING", seq(&[data, alg])),
            ("non-SEQUENCE first: SET", seq(&[&[0x31, 0x00], data])),
            ("non-SEQUENCE first: [0]", seq(&[&[0xA0, 0x00], data])),
        ] {
            let result = decode(&input);
            assert!(is_invalid(&result), "{what}: {:?}", result.err());
        }
    }

    #[test]
    fn encrypted_private_key_info_with_trailing_bytes_is_invalid() {
        // X.690 §8.1.1 and RFC 5958 §3: nothing after encryptedData, and
        // nothing after the outer SEQUENCE.
        let der = fixtures::load("openssl", "reject-ec-p256-pkcs8-encrypted.der");
        assert!(is_unsupported(&decode(&der)));
        let after = [&der[..], &[0x00]].concat();
        assert!(is_invalid(&decode(&after)));
        let mut outer = Reader::new(&der).unwrap();
        let mut fields = outer.sequence().unwrap();
        let alg = fields.expect(der::SEQUENCE).unwrap().encoding;
        let data = fields.expect(der::OCTET_STRING).unwrap().encoding;
        assert!(fields.is_empty());
        assert!(is_unsupported(&decode(&seq(&[alg, data]))));
        for tail in [&[0x05, 0x00][..], &[0x04, 0x00], &[0x00]] {
            let inside = seq(&[alg, data, tail]);
            assert!(is_invalid(&decode(&inside)), "{tail:02x?}");
        }
    }

    #[test]
    fn spki_fixtures_are_invalid_pkcs8() {
        // An SPKI (RFC 5280 §4.1.2.7) is `SEQUENCE { AlgorithmIdentifier,
        // BIT STRING }`: malformed as PKCS#8, not an encrypted key.
        let mut checked = 0;
        for dir in ["openssl", "rfc"] {
            for file in fixtures::files(dir, |n| {
                n.ends_with("-spki.der") && !n.starts_with("reject-")
            }) {
                let der = fixtures::load(dir, &file);
                let result = decode(&der);
                assert!(is_invalid(&result), "{dir}/{file}: {:?}", result.err());
                checked += 1;
            }
        }
        assert!(checked >= 10, "{checked} SPKI fixtures");
    }

    /// Every positive PKCS#8 fixture, with its algorithm, version and
    /// private key length (34 for an RFC 8410 CurvePrivateKey; an RFC 5915
    /// ECPrivateKey varies, so `None`).
    fn positive() -> Vec<(&'static str, String, AlgId, u8, Option<usize>)> {
        let mut out = Vec::new();
        for (dir, prefix, alg, version, len) in [
            (
                "openssl",
                "ec-p256-pkcs8",
                AlgId::Ec(EcCurve::P256),
                0,
                None,
            ),
            (
                "openssl",
                "ec-p384-pkcs8",
                AlgId::Ec(EcCurve::P384),
                0,
                None,
            ),
            (
                "openssl",
                "ec-p521-pkcs8",
                AlgId::Ec(EcCurve::P521),
                0,
                None,
            ),
            (
                "openssl",
                "ec-secp256k1-pkcs8",
                AlgId::Ec(EcCurve::Secp256k1),
                0,
                None,
            ),
            ("openssl", "ed25519-pkcs8", AlgId::Ed25519, 0, Some(34)),
            ("openssl", "x25519-pkcs8", AlgId::X25519, 0, Some(34)),
            (
                "rfc",
                "rfc7468-fig12-secp256k1-pkcs8",
                AlgId::Ec(EcCurve::Secp256k1),
                0,
                None,
            ),
            (
                "rfc",
                "rfc7517-a2-ec-p256-pkcs8",
                AlgId::Ec(EcCurve::P256),
                0,
                None,
            ),
            (
                "rfc",
                "rfc8037-a1-ed25519-pkcs8",
                AlgId::Ed25519,
                0,
                Some(34),
            ),
            ("rfc", "rfc8037-a6-x25519-pkcs8", AlgId::X25519, 0, Some(34)),
            (
                "rfc",
                "rfc8410-10.3-ed25519-pkcs8-v1",
                AlgId::Ed25519,
                0,
                Some(34),
            ),
            (
                "rfc",
                "rfc8410-10.3-ed25519-pkcs8-v2-attr-pub",
                AlgId::Ed25519,
                1,
                Some(34),
            ),
        ] {
            let files = fixtures::files(dir, |name| {
                name.strip_suffix(".der")
                    .or_else(|| name.strip_suffix(".pem"))
                    == Some(prefix)
            });
            assert!(!files.is_empty(), "{dir}/{prefix}");
            out.extend(files.into_iter().map(|file| (dir, file, alg, version, len)));
        }
        out
    }

    #[test]
    fn decodes_every_positive_pkcs8_fixture() {
        for (dir, file, alg, version, len) in positive() {
            let der = fixtures::load(dir, &file);
            let parts = decode(&der).unwrap_or_else(|e| panic!("{file}: {e:?}"));
            assert_eq!(parts.alg, alg, "{file}");
            assert_eq!(parts.version, version, "{file}");
            assert_eq!(parts.public_key.is_some(), version == 1, "{file}");
            match len {
                Some(len) => assert_eq!(parts.private_key.len(), len, "{file}"),
                // ECPrivateKey ::= SEQUENCE (RFC 5915 §3).
                None => assert_eq!(parts.private_key[0], 0x30, "{file}"),
            }
            assert!(der.as_ptr_range().contains(&parts.private_key.as_ptr()));
        }
    }

    #[test]
    fn the_positive_list_covers_every_pkcs8_fixture() {
        let listed = positive();
        for dir in ["openssl", "rfc"] {
            for file in fixtures::files(dir, |n| n.contains("pkcs8") && !n.starts_with("reject-")) {
                assert!(
                    listed.iter().any(|(d, f, ..)| *d == dir && *f == file),
                    "{dir}/{file} missing"
                );
            }
        }
    }

    #[test]
    fn re_encoding_gives_the_input_bytes() {
        // ADR 0018 §3: byte-identical round trips. The attributes are not
        // part of Pkcs8Parts (they are ignored), so the v2 vector round-trips
        // through the attribute-preserving codec, and `encode` writes it
        // without them.
        for (dir, file, ..) in positive() {
            let der = fixtures::load(dir, &file);
            let (parts, attributes) = decode_with_attributes(&der).unwrap();
            assert_eq!(
                &encode_with_attributes(&parts, attributes).unwrap()[..],
                &der[..],
                "{file}"
            );
            if attributes.is_none() {
                assert_eq!(&encode(&parts).unwrap()[..], &der[..], "{file}");
            } else {
                let plain = encode(&parts).unwrap();
                assert_eq!(&plain[..], &v2_with_attributes(&[])[..]);
                let again = decode(&plain).unwrap();
                assert_eq!(again.private_key, parts.private_key);
                assert_eq!(again.public_key, parts.public_key);
            }
        }
    }

    #[test]
    fn encode_refuses_inconsistent_or_unsupported_parts() {
        let key = [0x04, 0x20, 0x11, 0x11];
        let public = [0x22; 32];
        let v1_with_public = Pkcs8Parts {
            version: 0,
            alg: AlgId::Ed25519,
            private_key: &key,
            public_key: Some(&public),
        };
        assert!(is_invalid(&encode(&v1_with_public)));
        let v2_without_public = Pkcs8Parts {
            version: 1,
            public_key: None,
            ..v1_with_public
        };
        assert!(is_invalid(&encode(&v2_without_public)));
        // ADR 0067: rsaEncryption is written like any other algorithm
        // (RFC 5958 §2); the RSAPrivateKey inside is `rsa.rs`'s.
        let rsa = Pkcs8Parts {
            version: 0,
            alg: AlgId::RsaEncryption,
            private_key: &key,
            public_key: None,
        };
        let encoded = encode(&rsa).unwrap();
        let back = decode(&encoded).unwrap();
        assert_eq!(
            (back.alg, back.private_key),
            (AlgId::RsaEncryption, &key[..])
        );
        let v2 = Pkcs8Parts {
            version: 1,
            ..v1_with_public
        };
        let der = encode(&v2).unwrap();
        let back = decode(&der).unwrap();
        assert_eq!((back.version, back.alg), (1, AlgId::Ed25519));
        assert_eq!(back.private_key, &key);
        assert_eq!(back.public_key, Some(&public[..]));
    }

    mod properties {
        use proptest::prelude::*;
        use proptest::sample::Index;

        use super::super::super::der::fixtures;
        use super::{decode_with_attributes, encode_with_attributes, positive};

        /// The positive PKCS#8 fixtures, loaded when the strategy is built
        /// (once per property, without global state).
        fn corpus() -> Vec<Vec<u8>> {
            positive()
                .into_iter()
                .map(|(dir, file, ..)| fixtures::load(dir, &file))
                .collect()
        }

        /// Never panics, and canonical: whatever decodes re-encodes to
        /// exactly the input (DER has one encoding per value, X.690 §10).
        fn canonical(input: &[u8]) -> Result<(), TestCaseError> {
            if let Ok((parts, attributes)) = decode_with_attributes(input) {
                let again = encode_with_attributes(&parts, attributes);
                prop_assert!(again.is_ok());
                prop_assert_eq!(&again.unwrap()[..], input);
            }
            Ok(())
        }

        /// `contents` in a SEQUENCE with a correct header, so the cases get
        /// past the outer framing.
        fn framed(contents: &[u8]) -> Vec<u8> {
            let mut out = vec![0x30];
            match contents.len() {
                len @ 0..=0x7F => out.push(u8::try_from(len).unwrap()),
                len => out.extend_from_slice(&[0x81, u8::try_from(len).unwrap()]),
            }
            out.extend_from_slice(contents);
            out
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(1_000))]

            #[test]
            fn arbitrary_bytes_fail_or_are_canonical(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
                canonical(&bytes)?;
            }

            #[test]
            fn arbitrary_sequences_fail_or_are_canonical(bytes in proptest::collection::vec(any::<u8>(), 0..200)) {
                canonical(&framed(&bytes))?;
            }

            #[test]
            fn single_byte_mutations_never_panic(fixture in proptest::sample::select(corpus()), at in any::<Index>(), byte in any::<u8>()) {
                let mut der = fixture;
                let i = at.index(der.len());
                der[i] = byte;
                canonical(&der)?;
            }
        }
    }

    /// Secret hygiene of every failure path: errors are a static detail or
    /// `UnsupportedAlgorithm`, never input bytes (ADR 0018 §4; the T02
    /// contract), checked with marker-filled keys.
    ///
    /// **What these tests cannot detect.** They read what is observable from
    /// safe Rust: error values, `Debug`/`Display` text and buffers they own.
    /// They cannot see:
    ///
    /// - by-value stack copies, such as a `[u8; N]` or `FieldBytes` moved or
    ///   passed by value, or a spilled register, which leave no trace a test
    ///   can read back after the frame is gone;
    /// - copies made inside upstream crates (the curve and dalek crates'
    ///   scalar, sampling and hashing temporaries), which polyjose cannot reach.
    ///
    /// Those copies are documented as best-effort where they arise
    /// (`okp::x25519_public`, `okp::ed25519_public`, `ec::public_key`,
    /// `generate::generate_ec_secret`), and reviewed, not tested.
    mod hygiene {
        use std::collections::BTreeSet;

        use super::super::super::der::{self, fixtures};
        use super::super::super::{oid, spki};
        use super::*;

        /// The marker octet in every key position. It would show up in a
        /// leaked `Debug` as `165`, or in hex as `a5`.
        const M: u8 = 0xA5;

        fn leaks(text: &str) -> bool {
            let lower = text.to_ascii_lowercase();
            lower.contains("a5") || lower.contains("165") || text.contains(char::from(M))
        }

        /// `SEQUENCE { parts }` with a correct short- or long-form length.
        fn seq(parts: &[&[u8]]) -> Vec<u8> {
            tlv(0x30, &parts.concat())
        }

        fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
            let mut out = vec![tag];
            match contents.len() {
                len @ 0..=0x7F => out.push(u8::try_from(len).unwrap()),
                len => out.extend_from_slice(&[0x81, u8::try_from(len).unwrap()]),
            }
            out.extend_from_slice(contents);
            out
        }

        /// An Ed25519 PKCS#8 key whose CurvePrivateKey is all marker.
        fn ed(version: &[u8], alg: &[u8], private_key: &[u8], tail: &[u8]) -> Vec<u8> {
            seq(&[version, alg, private_key, tail])
        }

        fn key() -> Vec<u8> {
            tlv(0x04, &tlv(0x04, &[M; 32]))
        }

        const V0: &[u8] = &[0x02, 0x01, 0x00];

        /// The inputs that reach each `InvalidKey` detail through
        /// `pkcs8::decode` (`P`) or `spki::decode` (`S`).
        fn cases() -> Vec<(char, Vec<u8>, &'static str)> {
            let good = ed(V0, oid::ALG_ED25519, &key(), &[]);
            let with = |i: usize, b: u8| {
                let mut v = good.clone();
                v[i] = b;
                v
            };
            let spki_with = |alg: &[u8], bits: &[u8]| seq(&[alg, bits]);
            let ed448_params = |params: &[u8]| seq(&[oid::OID_ED448, params]);
            let mut deep = vec![0x05, 0x00];
            for _ in 0..=der::MAX_DEPTH {
                deep = seq(&[&deep]);
            }
            let attribute = |value: &[u8]| seq(&[&[0x06, 0x01, 0x2A][..], &tlv(0x31, value)]);
            let unsorted = tlv(
                0xA0,
                &[attribute(&[0x04, 0x01, M]), attribute(&[0x04, 0x01, 0x01])].concat(),
            );
            let public = tlv(0x81, &[&[0x00][..], &[M; 32]].concat());
            vec![
                ('P', vec![M; der::MAX_INPUT_LEN + 1], "DER input too large"),
                ('P', vec![0x30], "DER truncated"),
                ('P', with(0, 0x3F), "DER high-tag-number form"),
                ('P', with(1, 0x80), "DER indefinite length"),
                (
                    'P',
                    [&[0x30, 0x81, 0x2E][..], &good[2..]].concat(),
                    "DER length not minimal",
                ),
                (
                    'P',
                    [&[0x30, 0x85][..], &good[2..]].concat(),
                    "DER length too long",
                ),
                ('P', with(1, 0x2F), "DER length exceeds input"),
                ('P', [&good[..], &[M]].concat(), "DER trailing data"),
                ('P', with(12, 0x02), "DER unexpected tag"),
                (
                    'P',
                    ed(&[0x02, 0x00], oid::ALG_ED25519, &key(), &[]),
                    "DER INTEGER empty",
                ),
                (
                    'P',
                    ed(&[0x02, 0x02, 0x00, 0x00], oid::ALG_ED25519, &key(), &[]),
                    "DER INTEGER not minimal",
                ),
                (
                    'P',
                    ed(&[0x02, 0x01, M], oid::ALG_ED25519, &key(), &[]),
                    "DER INTEGER negative",
                ),
                (
                    'P',
                    ed(&[0x02, 0x02, 0x01, M], oid::ALG_ED25519, &key(), &[]),
                    "DER INTEGER out of range",
                ),
                ('P', with(12, 0x24), "DER constructed string"),
                (
                    'P',
                    ed(&[0x02, 0x01, 0x02], oid::ALG_ED25519, &key(), &[]),
                    "PKCS#8 version is not v1 or v2",
                ),
                (
                    'P',
                    ed(V0, oid::ALG_ED25519, &key(), &public),
                    "PKCS#8 version does not match the publicKey",
                ),
                (
                    'P',
                    ed(V0, oid::ALG_ED25519, &key(), &unsorted),
                    "DER SET OF not sorted",
                ),
                (
                    'P',
                    ed(
                        V0,
                        &[0x30, 0x06, 0x06, 0x04, 0x2B, 0x80, 0x65, 0x70],
                        &key(),
                        &[],
                    ),
                    "DER OBJECT IDENTIFIER malformed",
                ),
                (
                    'P',
                    ed(V0, &seq(&[oid::OID_ED25519, &[0x05, 0x00]]), &key(), &[]),
                    "AlgorithmIdentifier parameters do not match the algorithm",
                ),
                (
                    'S',
                    spki_with(oid::ALG_X25519, &[0x03, 0x00]),
                    "DER BIT STRING empty",
                ),
                (
                    'S',
                    spki_with(
                        oid::ALG_X25519,
                        &tlv(0x03, &[&[0x01][..], &[M; 32]].concat()),
                    ),
                    "DER BIT STRING has unused bits",
                ),
                (
                    'S',
                    spki_with(&ed448_params(&[0x05, 0x01, M]), &[0x03, 0x01, 0x00]),
                    "DER NULL not empty",
                ),
                (
                    'S',
                    spki_with(&ed448_params(&deep), &[0x03, 0x01, 0x00]),
                    "DER nesting too deep",
                ),
                (
                    'S',
                    spki_with(&ed448_params(&[0x00, 0x00]), &[0x03, 0x01, 0x00]),
                    "DER end-of-contents",
                ),
                (
                    'S',
                    spki_with(&ed448_params(&[0x01, 0x01, M]), &[0x03, 0x01, 0x00]),
                    "DER BOOLEAN not canonical",
                ),
                (
                    'S',
                    spki_with(&ed448_params(&[0x03, 0x02, 0x01, M]), &[0x03, 0x01, 0x00]),
                    "DER BIT STRING malformed",
                ),
            ]
        }

        /// Only the writer can fail with these, which its own tests cover.
        const WRITER_ONLY: [&str; 2] = ["DER output too large", "DER output length mismatch"];

        /// Every `InvalidKey("...")` literal in the non-test part of `source`.
        fn details(source: &str) -> Vec<String> {
            let code = source.split("\n#[cfg(test)]").next().unwrap();
            code.split("InvalidKey(")
                .skip(1)
                .filter_map(|rest| {
                    let rest = rest.trim_start().strip_prefix('"')?;
                    Some(rest[..rest.find('"').unwrap()].to_owned())
                })
                .collect()
        }

        fn error_of(which: char, input: &[u8]) -> Error {
            match which {
                'P' => decode(input).map(|_| ()).unwrap_err(),
                _ => spki::decode(input).map(|_| ()).unwrap_err(),
            }
        }

        #[test]
        fn every_failure_path_reports_a_static_detail_without_key_bytes() {
            let mut seen = BTreeSet::new();
            for (which, input, expected) in cases() {
                let error = error_of(which, &input);
                assert_eq!(error, Error::InvalidKey(expected), "{expected}");
                for text in [
                    format!("{error}"),
                    format!("{error:?}"),
                    format!("{error:#?}"),
                ] {
                    assert!(!leaks(&text), "{text}");
                }
                seen.insert(expected.to_owned());
            }
            let all: BTreeSet<String> = [
                include_str!("der.rs"),
                include_str!("pkcs8.rs"),
                include_str!("spki.rs"),
            ]
            .into_iter()
            .flat_map(details)
            .collect();
            assert!(all.len() > 20, "{all:?}");
            let expected: BTreeSet<String> = all
                .iter()
                .filter(|d| !WRITER_ONLY.contains(&d.as_str()))
                .cloned()
                .collect();
            assert_eq!(seen, expected, "a decoder failure path has no marker case");
        }

        #[test]
        fn unsupported_inputs_report_nothing_but_the_code() {
            // Ed448 and an encrypted key, marker-filled. (An rsaEncryption
            // key is supported since ADR 0067; `rsa.rs` tests its errors.)
            for input in [
                ed(V0, &seq(&[oid::OID_ED448]), &key(), &[]),
                seq(&[&seq(&[&[0x06, 0x01, M][..]]), &tlv(0x04, &[M; 48])]),
            ] {
                let error = decode(&input).map(|_| ()).unwrap_err();
                assert_eq!(error, Error::UnsupportedAlgorithm);
                assert!(!leaks(&format!("{error:?} {error}")));
            }
        }

        #[test]
        fn every_committed_rejection_reports_a_known_static_detail() {
            let all: BTreeSet<String> = [
                include_str!("der.rs"),
                include_str!("pkcs8.rs"),
                include_str!("spki.rs"),
            ]
            .into_iter()
            .flat_map(details)
            .collect();
            let mut inputs: Vec<Vec<u8>> = fixtures::negatives()
                .iter()
                .filter(|n| n.file.ends_with(".der"))
                .map(|n| fixtures::load("negative", &n.file))
                .collect();
            inputs.extend(
                // The legacy `Proc-Type: 4,ENCRYPTED` PEMs (RFC 1421 headers)
                // are a PEM-level rejection with no DER to give here.
                fixtures::files("openssl", |n| {
                    n.starts_with("reject-") && !n.contains("legacy-encrypted")
                })
                .iter()
                .map(|f| fixtures::load("openssl", f)),
            );
            for input in inputs {
                for which in ['P', 'S'] {
                    let result = match which {
                        'P' => decode(&input).map(|_| ()),
                        _ => spki::decode(&input).map(|_| ()),
                    };
                    match result {
                        Ok(()) | Err(Error::UnsupportedAlgorithm) => {}
                        Err(Error::InvalidKey(detail)) => assert!(all.contains(detail), "{detail}"),
                        Err(other) => panic!("unexpected error {other:?}"),
                    }
                }
            }
        }
    }
}

/// Adversarial checks added by the tester (T02): length boundaries, the
/// 64 KiB cap through the containers, and `finish()` at every nesting level.
#[cfg(test)]
mod tester_adversarial {
    use super::super::oid;
    use super::super::spki;
    use super::super::types::AlgId;
    use super::*;

    fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
        let len = contents.len();
        let mut out = vec![tag];
        match len {
            0..=0x7F => out.push(len as u8),
            0x80..=0xFF => out.extend_from_slice(&[0x81, len as u8]),
            _ => out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]),
        }
        out.extend_from_slice(contents);
        out
    }

    /// v1 Ed25519 PKCS#8 whose privateKey OCTET STRING holds `key_len` octets.
    fn ed25519_with_key_len(key_len: usize) -> Vec<u8> {
        let body = [
            &[0x02, 0x01, 0x00][..],
            oid::ALG_ED25519,
            &tlv(0x04, &vec![0x5A; key_len]),
        ]
        .concat();
        tlv(0x30, &body)
    }

    #[test]
    fn length_forms_at_the_short_and_long_boundaries() {
        // X.690 §10.1: 127 is short form, 128 and 255 one long-form octet,
        // 256 two. Each is accepted in its minimal form only.
        for key_len in [100, 105, 106, 107, 108, 120, 200, 247, 248, 249, 300, 1000] {
            let der = ed25519_with_key_len(key_len);
            let parts = decode(&der).unwrap();
            assert_eq!(parts.private_key.len(), key_len);
            assert_eq!(encode(&parts).unwrap().as_slice(), &der[..], "{key_len}");
        }
        // The privateKey OCTET STRING at exactly 127, 128, 255, 256 octets.
        for key_len in [127usize, 128, 255, 256] {
            let der = ed25519_with_key_len(key_len);
            assert_eq!(decode(&der).unwrap().private_key.len(), key_len);
        }
        // Non-minimal spellings of 128 and 256 for the OCTET STRING length.
        for (header, key_len) in [
            (vec![0x04, 0x82, 0x00, 0x80], 128usize),
            (vec![0x04, 0x83, 0x00, 0x01, 0x00], 256),
            (vec![0x04, 0x81, 0x7F], 127),
        ] {
            let body = [
                &[0x02, 0x01, 0x00][..],
                oid::ALG_ED25519,
                &header,
                &vec![0x5A; key_len],
            ]
            .concat();
            let der = tlv(0x30, &body);
            assert!(
                matches!(
                    decode(&der),
                    Err(Error::InvalidKey("DER length not minimal"))
                ),
                "{header:02x?}"
            );
        }
        // 0x80 0x81 as the outer length: indefinite / a zero long-form count.
        let good = ed25519_with_key_len(32);
        let mut indefinite = good.clone();
        indefinite[1] = 0x80;
        assert!(matches!(decode(&indefinite), Err(Error::InvalidKey(_))));
        let mut leading = vec![0x30, 0x81, 0x00];
        leading.extend_from_slice(&good[2..]);
        assert!(matches!(decode(&leading), Err(Error::InvalidKey(_))));
    }

    #[test]
    fn the_64_kib_boundary_through_pkcs8() {
        // 4 (outer header) + 3 + 7 + 4 (OCTET header) + 65,518 = 65,536.
        let at_cap = ed25519_with_key_len(65_518);
        assert_eq!(at_cap.len(), der::MAX_INPUT_LEN);
        assert_eq!(decode(&at_cap).unwrap().private_key.len(), 65_518);
        assert_eq!(encode(&decode(&at_cap).unwrap()).unwrap().len(), 65_536);
        let over = ed25519_with_key_len(65_519);
        assert_eq!(over.len(), der::MAX_INPUT_LEN + 1);
        assert!(matches!(
            decode(&over),
            Err(Error::InvalidKey("DER input too large"))
        ));
        // The writer refuses to produce what the reader would refuse.
        let parts = Pkcs8Parts {
            version: 0,
            alg: AlgId::Ed25519,
            private_key: &vec![0u8; 65_519],
            public_key: None,
        };
        assert!(matches!(encode(&parts), Err(Error::InvalidKey(_))));
    }

    /// Re-wraps `fields` as a PKCS#8 SEQUENCE.
    fn pkcs8_of(fields: &[&[u8]]) -> Vec<u8> {
        tlv(0x30, &fields.concat())
    }

    #[test]
    fn leftovers_are_rejected_at_every_nesting_level() {
        let version = [0x02, 0x01, 0x00];
        let key = tlv(0x04, &tlv(0x04, &[0x5A; 32]));
        // Level 1: a byte inside the outer SEQUENCE after privateKey.
        let der = pkcs8_of(&[&version, oid::ALG_ED25519, &key, &[0x00]]);
        assert!(matches!(decode(&der), Err(Error::InvalidKey(_))));
        // Level 2: a byte inside the AlgorithmIdentifier, after a NULL.
        let alg = tlv(
            0x30,
            &[&[0x06, 0x03, 0x2B, 0x65, 0x70][..], &[0x05, 0x00, 0x00]].concat(),
        );
        let der = pkcs8_of(&[&version, &alg, &key]);
        assert!(matches!(decode(&der), Err(Error::InvalidKey(_))));
        // Level 2, unsupported OID: a second parameters element is malformed.
        let alg = tlv(
            0x30,
            &[oid::OID_ED448, &[0x05, 0x00][..], &[0x05, 0x00]].concat(),
        );
        let der = pkcs8_of(&[&version, &alg, &key]);
        assert!(matches!(decode(&der), Err(Error::InvalidKey(_))));
        // Level 2, supported curve: a second parameters element.
        let alg = tlv(
            0x30,
            &[
                oid::OID_EC_PUBLIC_KEY,
                oid::named_curve(crate::jwk::EcCurve::P256),
                &[0x05, 0x00],
            ]
            .concat(),
        );
        let der = pkcs8_of(&[&version, &alg, &key]);
        assert!(matches!(decode(&der), Err(Error::InvalidKey(_))));
        // Level 3: a byte inside an Attribute, after its SET of values.
        let attribute = tlv(
            0x30,
            &[&[0x06, 0x01, 0x2A][..], &[0x31, 0x00], &[0x05, 0x00]].concat(),
        );
        let attrs = tlv(0xA0, &attribute);
        let der = pkcs8_of(&[
            &[0x02, 0x01, 0x01],
            oid::ALG_ED25519,
            &key,
            &attrs,
            &tlv(0x81, &[&[0x00][..], &[0x5A; 32]].concat()),
        ]);
        assert!(matches!(decode(&der), Err(Error::InvalidKey(_))));
        // The same Attribute without the leftover is accepted.
        let attribute = tlv(0x30, &[&[0x06, 0x01, 0x2A][..], &[0x31, 0x00]].concat());
        let attrs = tlv(0xA0, &attribute);
        let der = pkcs8_of(&[
            &[0x02, 0x01, 0x01],
            oid::ALG_ED25519,
            &key,
            &attrs,
            &tlv(0x81, &[&[0x00][..], &[0x5A; 32]].concat()),
        ]);
        assert!(decode(&der).is_ok());
        // SPKI: level 1 and level 2.
        let bits = [0x03, 0x02, 0x00, 0x5A];
        let der = tlv(0x30, &[oid::ALG_X25519, &bits, &[0x00]].concat());
        assert!(matches!(spki::decode(&der), Err(Error::InvalidKey(_))));
        let alg = tlv(
            0x30,
            &[&[0x06, 0x03, 0x2B, 0x65, 0x6E][..], &[0x00]].concat(),
        );
        let der = tlv(0x30, &[&alg[..], &bits].concat());
        assert!(matches!(spki::decode(&der), Err(Error::InvalidKey(_))));
        // A second element after the BIT STRING inside the SPKI.
        let der = tlv(0x30, &[oid::ALG_X25519, &bits, &bits].concat());
        assert!(matches!(spki::decode(&der), Err(Error::InvalidKey(_))));
    }

    #[test]
    fn parameter_nesting_is_capped_at_the_stack_depth() {
        // Unsupported-algorithm parameters are walked iteratively: exactly
        // MAX_DEPTH levels of SEQUENCE around a NULL are well-formed (and the
        // OID is then unsupported), one more is InvalidKey, never a panic.
        let nest = |levels: usize| {
            let mut v = vec![0x05, 0x00];
            for _ in 0..levels {
                v = tlv(0x30, &v);
            }
            v
        };
        for (levels, ok) in [
            (der::MAX_DEPTH, true),
            (der::MAX_DEPTH + 1, false),
            (3_000, false),
        ] {
            let alg = tlv(0x30, &[oid::OID_ED448, &nest(levels)[..]].concat());
            let der = tlv(0x30, &[&alg[..], &[0x03, 0x01, 0x00]].concat());
            let result = spki::decode(&der);
            if ok {
                assert!(
                    matches!(result, Err(Error::UnsupportedAlgorithm)),
                    "{levels}: {result:?}"
                );
            } else {
                assert!(
                    matches!(result, Err(Error::InvalidKey("DER nesting too deep"))),
                    "{levels}"
                );
            }
        }
    }
}
