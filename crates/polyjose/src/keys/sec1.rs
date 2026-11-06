//! The SEC1 ECPrivateKey structure (RFC 5915 §3), standalone as `EC PRIVATE
//! KEY` (RFC 5915 §4) with `[0]` namedCurve and `[1]` publicKey, and inside
//! PKCS#8 (RFC 5915 §1).
//!
//! RFC 5915 App. A defines the module with EXPLICIT TAGS (erratum 3962
//! fixes a typo in it), so `[0]` is the constructed 0xA0 wrapping a whole
//! OBJECT IDENTIFIER and `[1]` the constructed 0xA1 wrapping a whole BIT
//! STRING (X.690 §8.14.2). The codec only frames the structure: whether the
//! curve agrees with a PKCS#8 AlgorithmIdentifier, whether the private key
//! has the curve's length and whether it matches the public key is left to
//! `ec.rs` and `Jwk::from_object`.

use core::fmt;

use zeroize::Zeroizing;

use super::der::{self, Reader, Writer};
use super::oid;
use crate::error::{Error, Result};
use crate::jwk::EcCurve;

/// `version` ecPrivkeyVer1(1), the only version (RFC 5915 §3).
const EC_PRIVKEY_VER1: u8 = 1;

/// The curves a `[0]` namedCurve may name (RFC 5480 §2.1.1.1; SEC 2 v2
/// App. A.2.1 for secp256k1; RFC 7518 §6.2.1.1, RFC 8812 §3.1).
const CURVES: [EcCurve; 4] = [
    EcCurve::P256,
    EcCurve::P384,
    EcCurve::P521,
    EcCurve::Secp256k1,
];

/// The fields of an ECPrivateKey (RFC 5915 §3), borrowed from the decoded
/// DER:
///
/// ```text
/// ECPrivateKey ::= SEQUENCE {
///   version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
///   privateKey     OCTET STRING,
///   parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
///   publicKey  [1] BIT STRING OPTIONAL
/// }
/// ```
///
/// `private_key` borrows from the caller's buffer, which must be a
/// zeroizing one. `Debug` redacts it and shows only the length of
/// `public_key`.
#[derive(Clone, Copy)]
pub(crate) struct EcPrivateKey<'a> {
    /// The contents of the `privateKey` OCTET STRING: the scalar d,
    /// big-endian (RFC 5915 §3). Secret. Its length is not checked here.
    pub(crate) private_key: &'a [u8],
    /// The `[0]` namedCurve, if present (RFC 5915 §3, RFC 5480 §2.1.1).
    pub(crate) parameters: Option<EcCurve>,
    /// The `[1]` publicKey BIT STRING contents without the unused-bits
    /// octet: a SEC1 point (RFC 5915 §3, RFC 5480 §2.2), not yet decoded.
    pub(crate) public_key: Option<&'a [u8]>,
}

impl fmt::Debug for EcPrivateKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcPrivateKey")
            .field("private_key", &"<redacted>")
            .field("parameters", &self.parameters)
            .field("public_key_len", &self.public_key.map(<[u8]>::len))
            .finish()
    }
}

/// Decodes a DER ECPrivateKey (RFC 5915 §3), standalone or from the
/// privateKey of a PKCS#8 OneAsymmetricKey (RFC 5915 §1):
///
/// - One SEQUENCE and no trailing data (X.690 §8.1.1); BER is rejected
///   (ADR 0018 §2, a deliberate deviation from RFC 5915 §3's SHOULD).
/// - `version` must be ecPrivkeyVer1(1) (RFC 5915 §3).
/// - `[0]` is EXPLICIT (RFC 5915 App. A): 0xA0 holding exactly one
///   namedCurve OBJECT IDENTIFIER. An IMPLICIT 0x80 is not a `[0]` at all
///   and fails as trailing data.
/// - The `[0]` ECParameters is a CHOICE (RFC 5480 §2.1.1), classified in
///   the order of ADR 0018 §4: a namedCurve outside the JOSE set or a
///   specifiedCurve (a SEQUENCE, which "MUST NOT be used in PKIX") is
///   `UnsupportedAlgorithm`; implicitCurve (NULL), which also "MUST NOT be
///   used", or any other element is `InvalidKey`.
/// - `[1]` is EXPLICIT: 0xA1 holding exactly one BIT STRING with no unused
///   bits (X.690 §8.6.2.2). The point inside is not decoded here.
///
/// # Errors
///
/// [`Error::InvalidKey`] with a static detail for malformed input, and
/// [`Error::UnsupportedAlgorithm`] for unsupported parameters. No input
/// octet reaches an error.
pub(crate) fn decode(der: &[u8]) -> Result<EcPrivateKey<'_>> {
    let mut outer = Reader::new(der)?;
    let mut fields = outer.sequence()?;
    outer.finish()?;
    if fields.small_unsigned()? != EC_PRIVKEY_VER1 {
        return Err(Error::InvalidKey("ECPrivateKey version is not 1"));
    }
    let private_key = fields.octet_string()?;
    let parameters = match fields.optional(der::CONTEXT_0)? {
        Some(element) => Some(read_parameters(element.contents)?),
        None => None,
    };
    let public_key = match fields.optional(der::CONTEXT_1)? {
        Some(element) => {
            let mut inner = Reader::new(element.contents)?;
            let point = inner.bit_string()?;
            inner.finish()?;
            Some(point)
        }
        None => None,
    };
    fields.finish()?;
    Ok(EcPrivateKey {
        private_key,
        parameters,
        public_key,
    })
}

/// Reads the contents of the EXPLICIT `[0]`: exactly one ECParameters
/// (RFC 5915 §3, RFC 5480 §2.1.1), classified as on [`decode`].
fn read_parameters(contents: &[u8]) -> Result<EcCurve> {
    let mut inner = Reader::new(contents)?;
    let curve = match inner.peek_tag() {
        Some(der::OID) => {
            let named = inner.oid()?;
            CURVES
                .iter()
                .find(|crv| oid::named_curve(**crv) == named)
                .copied()
                .ok_or(Error::UnsupportedAlgorithm)
        }
        Some(der::SEQUENCE) => {
            // specifiedCurve: well-formed DER, then unsupported.
            let specified = inner.element()?;
            der::check_well_formed(specified.encoding, false)?;
            Err(Error::UnsupportedAlgorithm)
        }
        _ => {
            inner.element()?;
            Err(Error::InvalidKey(
                "ECPrivateKey parameters are not a namedCurve",
            ))
        }
    };
    inner.finish()?;
    curve
}

/// Encodes an ECPrivateKey (RFC 5915 §3) in DER: version 1, `privateKey`,
/// then the EXPLICIT `[0]` namedCurve when `key.parameters` is set and the
/// EXPLICIT `[1]` publicKey BIT STRING when `key.public_key` is set, in the
/// layout OpenSSL 4 emits (ADR 0018 §3).
///
/// Standalone SEC1 is written with both (RFC 5915 §3: parameters "MUST
/// always" and publicKey "SHOULD always" be included); the ECPrivateKey
/// inside PKCS#8 without `[0]` (RFC 5915 erratum 5008). The fields are
/// written as given: their lengths and consistency are the caller's. The
/// output is zeroized on drop.
///
/// # Errors
///
/// [`Error::InvalidKey`] only if the encoding would exceed
/// [`der::MAX_INPUT_LEN`].
pub(crate) fn encode(key: &EcPrivateKey<'_>) -> Result<Zeroizing<Vec<u8>>> {
    let version = [EC_PRIVKEY_VER1];
    let named = key.parameters.map(oid::named_curve);
    let parameters_len = named.map_or(0, |named| der::encoded_len(named.len()));
    let public_key_len = key.public_key.map_or(0, |point| {
        der::encoded_len(der::bit_string_len(point.len()))
    });
    let body = der::unsigned_integer_len(&version)
        + der::encoded_len(key.private_key.len())
        + parameters_len
        + public_key_len;
    let mut writer = Writer::new(der::encoded_len(body))?;
    writer.header(der::SEQUENCE, body)?;
    writer.unsigned_integer(&version)?;
    writer.element(der::OCTET_STRING, key.private_key)?;
    if let Some(named) = named {
        writer.element(der::CONTEXT_0, named)?;
    }
    if let Some(point) = key.public_key {
        writer.header(der::CONTEXT_1, der::bit_string_len(point.len()))?;
        writer.bit_string(der::BIT_STRING, point)?;
    }
    writer.finish()
}

#[cfg(test)]
mod tests {
    use super::super::der::fixtures;
    use super::*;

    fn invalid(result: Result<EcPrivateKey<'_>>) -> &'static str {
        match result {
            Err(Error::InvalidKey(detail)) => detail,
            other => panic!("expected InvalidKey, got {other:?}"),
        }
    }

    #[test]
    fn rfc7517_a2_sec1_has_curve_key_and_point() {
        // RFC 7517 App. A.2, built as SEC1 with [0] and [1] (research.md §8).
        let der = fixtures::load("rfc", "rfc7517-a2-ec-p256-sec1.der");
        let key = decode(&der).unwrap();
        assert_eq!(key.parameters, Some(EcCurve::P256));
        assert_eq!(key.private_key.len(), 32);
        let point = key.public_key.unwrap();
        assert_eq!((point.len(), point[0]), (65, 0x04));
    }

    #[test]
    fn openssl_sec1_files_decode_for_every_curve() {
        for (name, crv, len) in [
            ("p256", EcCurve::P256, 32),
            ("p384", EcCurve::P384, 48),
            ("p521", EcCurve::P521, 66),
            ("secp256k1", EcCurve::Secp256k1, 32),
        ] {
            let der = fixtures::load("openssl", &format!("ec-{name}-sec1.der"));
            let key = decode(&der).unwrap();
            assert_eq!(key.parameters, Some(crv), "{name}");
            assert_eq!(key.private_key.len(), len, "{name}");
            assert_eq!(key.public_key.map(<[u8]>::len), Some(1 + 2 * len), "{name}");

            let der = fixtures::load("openssl", &format!("ec-{name}-sec1-nopub.pem"));
            let key = decode(&der).unwrap();
            assert_eq!(key.parameters, Some(crv), "{name}");
            assert!(key.public_key.is_none(), "{name}");
        }
    }

    #[test]
    fn rfc7468_fig12_inner_key_has_no_parameters() {
        // RFC 7468 §10 Fig. 12: the ECPrivateKey inside PKCS#8 omits [0]
        // (RFC 5915 erratum 5008). Its privateKey starts at the OCTET
        // STRING after the AlgorithmIdentifier; the PKCS#8 codec finds it.
        let der = fixtures::load("rfc", "rfc7468-fig12-secp256k1-pkcs8.pem");
        let parts = super::super::pkcs8::decode(&der).unwrap();
        let key = decode(parts.private_key).unwrap();
        assert_eq!(key.parameters, None);
        assert_eq!(key.private_key.len(), 32);
    }

    #[test]
    fn version_0_is_invalid() {
        // N40: RFC 5915 §3 version ecPrivkeyVer1(1).
        assert_eq!(
            invalid(decode(&fixtures::negative("N40"))),
            "ECPrivateKey version is not 1"
        );
    }

    #[test]
    fn implicit_parameters_tag_is_invalid() {
        // N47: RFC 5915 App. A uses EXPLICIT TAGS; an IMPLICIT [0] (0x80)
        // is no [0] at all and is left over after privateKey.
        assert!(matches!(
            decode(&fixtures::negative("N47")),
            Err(Error::InvalidKey(_))
        ));
    }

    #[test]
    fn missing_parameters_decode_as_none() {
        // N46: whether [0] is required is the caller's decision (RFC 5915
        // §3 standalone vs §1 / erratum 5008 inside PKCS#8).
        let der = fixtures::negative("N46");
        assert_eq!(decode(&der).unwrap().parameters, None);
    }

    #[test]
    fn explicit_curve_parameters_are_unsupported() {
        // RFC 5480 §2.1.1: specifiedCurve "MUST NOT be used in PKIX"
        // (ADR 0018 §4 step 2). OpenSSL `ecparam -param_enc explicit`.
        let der = fixtures::load("openssl", "reject-ec-p256-explicit-sec1.pem");
        assert_eq!(decode(&der).unwrap_err(), Error::UnsupportedAlgorithm);
    }

    /// The RFC 7517 A.2 key with its `[0]` contents replaced by `params`
    /// (lengths patched; every replacement is short-form).
    fn with_parameters(params: &[u8]) -> Vec<u8> {
        let der = fixtures::load("rfc", "rfc7517-a2-ec-p256-sec1.der");
        // 30 77 | 02 01 01 | 04 20 d(32) | a0 0a <oid 10> | a1 44 ...
        let (head, rest) = der.split_at(2 + 3 + 34);
        assert_eq!(rest[..2], [0xA0, 0x0A]);
        let tail = &rest[12..];
        let mut body = head[2..].to_vec();
        body.extend_from_slice(&[0xA0, u8::try_from(params.len()).unwrap()]);
        body.extend_from_slice(params);
        body.extend_from_slice(tail);
        let mut out = vec![0x30, u8::try_from(body.len()).unwrap()];
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn parameters_choice_is_classified() {
        // A namedCurve outside the JOSE set: secp224r1 (1.3.132.0.33).
        let secp224r1 = [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x21];
        assert_eq!(
            decode(&with_parameters(&secp224r1)).unwrap_err(),
            Error::UnsupportedAlgorithm
        );
        // implicitCurve NULL (RFC 5480 §2.1.1: MUST NOT be used).
        assert_eq!(
            invalid(decode(&with_parameters(&[0x05, 0x00]))),
            "ECPrivateKey parameters are not a namedCurve"
        );
        // Two namedCurves in one [0], and an empty [0].
        let two = [oid::OID_P256, oid::OID_P256].concat();
        assert!(matches!(
            decode(&with_parameters(&two)),
            Err(Error::InvalidKey(_))
        ));
        assert!(matches!(
            decode(&with_parameters(&[])),
            Err(Error::InvalidKey(_))
        ));
        // Each supported curve OID maps to its curve.
        for crv in CURVES {
            let key = with_parameters(oid::named_curve(crv));
            assert_eq!(decode(&key).unwrap().parameters, Some(crv));
        }
    }

    #[test]
    fn public_key_wrapper_must_be_one_whole_bit_string() {
        let der = fixtures::load("rfc", "rfc7517-a2-ec-p256-sec1.der");
        // ... a1 44 03 42 00 04 x y; `at` is the unused-bits octet.
        let at = der.len() - 66;
        assert_eq!(der[at - 4..=at], [0xA1, 0x44, 0x03, 0x42, 0x00]);
        let mut bad = der.clone();
        bad[at] = 0x01;
        assert_eq!(invalid(decode(&bad)), "DER BIT STRING has unused bits");
        // An IMPLICIT [1] (0x81) instead of the EXPLICIT one.
        let mut implicit = der[..at - 4].to_vec();
        implicit.extend_from_slice(&[0x81, 0x42]);
        implicit.extend_from_slice(&der[at..]);
        implicit[1] -= 2;
        assert!(matches!(decode(&implicit), Err(Error::InvalidKey(_))));
    }

    #[test]
    fn encode_reproduces_every_committed_sec1_file() {
        // Standalone SEC1 with [0] and [1] (RFC 9500 §2.3, RFC 7517 A.2
        // built, OpenSSL `pkey -traditional`), and without [1] (OpenSSL
        // `ec -no_public`): decode then encode is the identity.
        let mut files = vec![
            ("rfc", "rfc7517-a2-ec-p256-sec1.der".to_owned()),
            ("rfc", "rfc9500-testECCP256-sec1.pem".to_owned()),
            ("rfc", "rfc9500-testECCP384-sec1.pem".to_owned()),
            ("rfc", "rfc9500-testECCP521-sec1.pem".to_owned()),
        ];
        for name in ["p256", "p384", "p521", "secp256k1"] {
            files.push(("openssl", format!("ec-{name}-sec1.der")));
            files.push(("openssl", format!("ec-{name}-sec1-nopub.pem")));
        }
        for (dir, file) in files {
            let der = fixtures::load(dir, &file);
            let key = decode(&der).unwrap();
            assert_eq!(*encode(&key).unwrap(), der, "{file}");
        }
    }

    #[test]
    fn encode_reproduces_the_pkcs8_inner_keys() {
        // Inside PKCS#8 the ECPrivateKey has [1] but no [0] (RFC 7468
        // Fig. 12, OpenSSL 4; RFC 5915 erratum 5008).
        let mut files = vec![
            ("rfc", "rfc7468-fig12-secp256k1-pkcs8.pem".to_owned()),
            ("rfc", "rfc7517-a2-ec-p256-pkcs8.der".to_owned()),
        ];
        for name in ["p256", "p384", "p521", "secp256k1"] {
            files.push(("openssl", format!("ec-{name}-pkcs8.der")));
        }
        for (dir, file) in files {
            let der = fixtures::load(dir, &file);
            let parts = super::super::pkcs8::decode(&der).unwrap();
            let key = decode(parts.private_key).unwrap();
            assert_eq!(key.parameters, None, "{file}");
            assert!(key.public_key.is_some(), "{file}");
            assert_eq!(*encode(&key).unwrap(), parts.private_key, "{file}");
        }
    }

    #[test]
    fn encode_matches_the_sec1_oracle() {
        // Differential check against the RustCrypto `sec1` crate (a
        // dev-dependency oracle only, ADR 0016 §5, ADR 0018 §1).
        use sec1::der::Decode as _;
        let der = fixtures::load("openssl", "ec-p521-sec1.der");
        let oracle = sec1::EcPrivateKey::from_der(&der).unwrap();
        let key = decode(&der).unwrap();
        assert_eq!(key.private_key, oracle.private_key);
        assert_eq!(key.public_key, oracle.public_key);
        assert_eq!(
            oracle
                .parameters
                .and_then(|p| p.named_curve())
                .map(|o| o.to_string()),
            Some("1.3.132.0.35".to_owned())
        );
    }

    #[test]
    fn encode_writes_long_form_lengths() {
        // A P-521 SEC1 body exceeds 127 octets, so the outer length is long
        // form (X.690 §8.1.3.5); the inner [0], [1] stay short form.
        let der = fixtures::load("rfc", "rfc9500-testECCP521-sec1.pem");
        let encoded = encode(&decode(&der).unwrap()).unwrap();
        assert_eq!(encoded[..3], [0x30, 0x81, 0xDC]);
    }

    #[test]
    fn debug_redacts_the_private_key() {
        let marker = [0xA5u8; 32];
        let key = EcPrivateKey {
            private_key: &marker,
            parameters: Some(EcCurve::P256),
            public_key: Some(&marker),
        };
        let shown = format!("{key:?} {key:#?}");
        assert!(shown.contains("<redacted>"), "{shown}");
        assert!(shown.contains("public_key_len: Some(32)"), "{shown}");
        assert!(!shown.contains("165") && !shown.to_ascii_lowercase().contains("a5"));
    }
}
