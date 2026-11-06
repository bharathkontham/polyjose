//! Types shared by the keys module: the public format and generation
//! selectors, and the crate-internal classification of key containers.

use core::fmt;

use crate::jwa::{ContentEncAlg, KeyMgmtAlg, SigningAlg};
use crate::jwk::{EcCurve, OkpCurve};

/// A binary key encoding, for DER input and for export (ADR 0018 §3).
///
/// The same structures are wrapped in PEM (RFC 7468 §2) by the PEM entry
/// points, whose label names the structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyFormat {
    /// PKCS#8 OneAsymmetricKey (RFC 5958 §2; PrivateKeyInfo, RFC 5208 §5):
    /// an EC or OKP private key. PEM label `PRIVATE KEY` (RFC 7468 §10).
    Pkcs8,
    /// SEC1 ECPrivateKey (RFC 5915 §3): an EC private key. PEM label
    /// `EC PRIVATE KEY` (RFC 5915 §4).
    Sec1,
    /// SubjectPublicKeyInfo (RFC 5280 §4.1.2.7): an EC, OKP or RSA public
    /// key. PEM label `PUBLIC KEY` (RFC 7468 §13).
    Spki,
    /// PKCS#1 RSAPublicKey (RFC 8017 App. A.1.1): an RSA public key. PEM
    /// label `RSA PUBLIC KEY` (OpenSSL's; no RFC defines it). RSA private
    /// keys are not supported in any format (ADR 0021).
    Pkcs1,
}

/// What to generate: a key type and its size or curve (ADR 0018 §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeySpec {
    /// A symmetric `oct` key (RFC 7518 §6.4) of `bytes` random octets.
    /// The RFC 7518 sizes per algorithm are 16 to 64 octets (§3.2, §4.4,
    /// §4.7, §5.2.3–§5.2.5, §5.3); generation accepts 16 to 512.
    Oct {
        /// The key length in octets.
        bytes: usize,
    },
    /// An `EC` key pair (RFC 7518 §6.2, RFC 8812 §3.1) on this curve.
    Ec(EcCurve),
    /// An `OKP` key pair (RFC 8037 §2) on this curve.
    Okp(OkpCurve),
}

/// Any JOSE algorithm identifier: a JWS `alg`, a JWE `alg` or a JWE `enc`
/// (RFC 7518 §3.1, §4.1, §5.1).
///
/// It lets one entry point take any of the three [`crate::jwa`] enums, so
/// that both `SigningAlg::ES256` and `ContentEncAlg::A256GCM` convert into
/// it with `From`/`Into`.
///
/// ```
/// use polyjose::jwa::{ContentEncAlg, SigningAlg};
/// use polyjose::keys::JoseAlg;
///
/// assert_eq!(JoseAlg::from(SigningAlg::ES256), JoseAlg::Signing(SigningAlg::ES256));
/// let enc: JoseAlg = ContentEncAlg::A256GCM.into();
/// assert_eq!(enc, JoseAlg::ContentEnc(ContentEncAlg::A256GCM));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum JoseAlg {
    /// A JWS `alg` (RFC 7515 §4.1.1, RFC 7518 §3.1).
    Signing(SigningAlg),
    /// A JWE key management `alg` (RFC 7516 §4.1.1, RFC 7518 §4.1).
    KeyMgmt(KeyMgmtAlg),
    /// A JWE content encryption `enc` (RFC 7516 §4.1.2, RFC 7518 §5.1).
    ContentEnc(ContentEncAlg),
}

impl From<SigningAlg> for JoseAlg {
    fn from(alg: SigningAlg) -> Self {
        JoseAlg::Signing(alg)
    }
}

impl From<KeyMgmtAlg> for JoseAlg {
    fn from(alg: KeyMgmtAlg) -> Self {
        JoseAlg::KeyMgmt(alg)
    }
}

impl From<ContentEncAlg> for JoseAlg {
    fn from(enc: ContentEncAlg) -> Self {
        JoseAlg::ContentEnc(enc)
    }
}

/// The key algorithm a PKCS#8 or SPKI AlgorithmIdentifier names, once it has
/// matched one of the byte templates in `oid.rs` (ADR 0018 §2, §4).
///
/// Crate-internal: it classifies containers, unlike the public JWK `alg`
/// member type [`crate::jwk::KeyAlg`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum AlgId {
    /// id-ecPublicKey with a namedCurve (RFC 5480 §2.1.1, §2.1.1.1; SEC 2 v2
    /// App. A.2.1 for secp256k1).
    Ec(EcCurve),
    /// id-Ed25519, parameters absent (RFC 8410 §3).
    Ed25519,
    /// id-X25519, parameters absent (RFC 8410 §3).
    X25519,
    /// rsaEncryption with NULL parameters (RFC 3279 §2.3.1, RFC 8017
    /// App. A.1). Only RSA public keys are supported (ADR 0021).
    RsaEncryption,
}

/// The label of a PEM block (RFC 7468 §2): the text between `-----BEGIN `
/// and `-----`, which names the structure inside.
///
/// The label only selects which structure to parse. The key type always comes
/// from that structure's DER, never from the label (ADR 0018 §2).
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "used by the PEM codec in pem.rs")
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Label {
    /// `PRIVATE KEY`: PKCS#8 OneAsymmetricKey (RFC 7468 §10, RFC 5958 §2).
    PrivateKey,
    /// `PUBLIC KEY`: SubjectPublicKeyInfo (RFC 7468 §13, RFC 5280 §4.1).
    PublicKey,
    /// `EC PRIVATE KEY`: SEC1 ECPrivateKey (RFC 5915 §3, §4).
    EcPrivateKey,
    /// `RSA PUBLIC KEY`: PKCS#1 RSAPublicKey (RFC 8017 App. A.1.1). OpenSSL's
    /// label; no RFC defines it.
    RsaPublic,
    /// `RSA PRIVATE KEY`: PKCS#1 RSAPrivateKey (RFC 8017 App. A.1.2), the
    /// OpenSSL format RFC 9500 §2.1 uses. Recognized only to reject it as
    /// unsupported (ADR 0021).
    RsaPrivate,
    /// `ENCRYPTED PRIVATE KEY`: EncryptedPrivateKeyInfo (RFC 7468 §11,
    /// RFC 5958 §3). Recognized only to reject it as unsupported
    /// (ADR 0018 §4).
    EncryptedPrivateKey,
    /// Any other label, such as `CERTIFICATE` (RFC 7468 §5): unsupported.
    Other,
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "used by the PEM codec in pem.rs")
)]
impl Label {
    /// Each known label and its exact text. Labels are case-sensitive
    /// (RFC 7468 §2, erratum 4508).
    const KNOWN: [(Label, &'static str); 6] = [
        (Label::PrivateKey, "PRIVATE KEY"),
        (Label::PublicKey, "PUBLIC KEY"),
        (Label::EcPrivateKey, "EC PRIVATE KEY"),
        (Label::RsaPublic, "RSA PUBLIC KEY"),
        (Label::RsaPrivate, "RSA PRIVATE KEY"),
        (Label::EncryptedPrivateKey, "ENCRYPTED PRIVATE KEY"),
    ];

    /// The exact label text (RFC 7468 §10, §11, §13; RFC 5915 §4; OpenSSL's
    /// `RSA PUBLIC KEY`/`RSA PRIVATE KEY`), or `None` for [`Label::Other`],
    /// which stands for any label.
    pub(crate) fn as_str(self) -> Option<&'static str> {
        Self::KNOWN
            .iter()
            .find(|(label, _)| *label == self)
            .map(|(_, text)| *text)
    }

    /// The label whose text is exactly `text`, or [`Label::Other`]. Checking
    /// that `text` is a syntactically valid label (RFC 7468 §3) is the
    /// caller's job.
    pub(crate) fn from_text(text: &str) -> Label {
        Self::KNOWN
            .iter()
            .find(|(_, known)| *known == text)
            .map_or(Label::Other, |(label, _)| *label)
    }
}

/// The fields of a PKCS#8 OneAsymmetricKey (RFC 5958 §2) that polyjose
/// uses, borrowed from the decoded DER. The `[0]` attributes are checked as
/// well-formed DER and then ignored (ADR 0018 §3).
///
/// It borrows `private_key` from the caller's buffer, which must be a
/// zeroizing one. `Debug` prints neither key: `private_key` is redacted and
/// `public_key` shows only its length.
#[derive(Clone, Copy)]
pub(crate) struct Pkcs8Parts<'a> {
    /// `version`: v1(0), or v2(1) when `public_key` is present (RFC 5958 §2).
    pub(crate) version: u8,
    /// The classified `privateKeyAlgorithm` (RFC 5958 §2).
    pub(crate) alg: AlgId,
    /// The contents of the `privateKey` OCTET STRING: an ECPrivateKey
    /// (RFC 5915 §3) or a CurvePrivateKey (RFC 8410 §7). Secret.
    pub(crate) private_key: &'a [u8],
    /// The `[1]` publicKey BIT STRING contents without the unused-bits octet
    /// (RFC 5958 §2), present only in v2.
    pub(crate) public_key: Option<&'a [u8]>,
}

impl fmt::Debug for Pkcs8Parts<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pkcs8Parts")
            .field("version", &self.version)
            .field("alg", &self.alg)
            .field("private_key", &"<redacted>")
            .field("public_key", &self.public_key.map(Octets))
            .finish()
    }
}

/// The fields of a SubjectPublicKeyInfo (RFC 5280 §4.1.2.7), borrowed from
/// the decoded DER. `Debug` shows only the key's length.
#[derive(Clone, Copy)]
pub(crate) struct SpkiParts<'a> {
    /// The classified `algorithm` (RFC 5280 §4.1.1.2).
    pub(crate) alg: AlgId,
    /// The `subjectPublicKey` BIT STRING contents without the unused-bits
    /// octet, which must be 0 for every supported key (RFC 5480 §2.2,
    /// RFC 8410 §4, RFC 3279 §2.3.1).
    pub(crate) subject_public_key: &'a [u8],
}

impl fmt::Debug for SpkiParts<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpkiParts")
            .field("alg", &self.alg)
            .field("subject_public_key", &Octets(self.subject_public_key))
            .finish()
    }
}

/// Prints a byte string as `"<N octets>"`, never its content.
struct Octets<'a>(&'a [u8]);

impl fmt::Debug for Octets<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"<{} octets>\"", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A byte pattern that would show up in a derived `Debug` as `165`.
    const MARKER: [u8; 32] = [0xA5; 32];

    #[test]
    fn pkcs8_parts_debug_never_shows_key_bytes() {
        let parts = Pkcs8Parts {
            version: 1,
            alg: AlgId::Ed25519,
            private_key: &MARKER,
            public_key: Some(&MARKER),
        };
        for debug in [format!("{parts:?}"), format!("{parts:#?}")] {
            assert!(!debug.contains("165"), "{debug}");
            assert!(!debug.to_ascii_lowercase().contains("a5"), "{debug}");
            assert!(debug.contains("<redacted>"), "{debug}");
        }
        assert_eq!(
            format!("{parts:?}"),
            r#"Pkcs8Parts { version: 1, alg: Ed25519, private_key: "<redacted>", public_key: Some("<32 octets>") }"#
        );
    }

    #[test]
    fn parts_borrow_the_decoded_der() {
        let parts = Pkcs8Parts {
            version: 0,
            alg: AlgId::X25519,
            private_key: &MARKER[..16],
            public_key: None,
        };
        assert_eq!(parts.private_key, &MARKER[..16]);
        assert_eq!(parts.public_key, None);
        let spki = SpkiParts {
            alg: AlgId::RsaEncryption,
            subject_public_key: &MARKER[..3],
        };
        assert_eq!(spki.subject_public_key.len(), 3);
        assert_eq!(
            format!(
                "{:?}",
                [
                    spki.alg,
                    parts.alg,
                    AlgId::Ed25519,
                    AlgId::Ec(EcCurve::Secp256k1)
                ]
            ),
            "[RsaEncryption, X25519, Ed25519, Ec(Secp256k1)]"
        );
    }

    #[test]
    fn spki_parts_debug_shows_only_the_length() {
        let parts = SpkiParts {
            alg: AlgId::Ec(EcCurve::P256),
            subject_public_key: &MARKER,
        };
        let debug = format!("{parts:?}");
        assert!(!debug.contains("165"), "{debug}");
        assert_eq!(
            debug,
            r#"SpkiParts { alg: Ec(P256), subject_public_key: "<32 octets>" }"#
        );
    }

    #[test]
    fn labels_are_the_exact_rfc_7468_and_openssl_texts() {
        let table = [
            (Label::PrivateKey, "PRIVATE KEY"),
            (Label::PublicKey, "PUBLIC KEY"),
            (Label::EcPrivateKey, "EC PRIVATE KEY"),
            (Label::RsaPublic, "RSA PUBLIC KEY"),
            (Label::RsaPrivate, "RSA PRIVATE KEY"),
            (Label::EncryptedPrivateKey, "ENCRYPTED PRIVATE KEY"),
        ];
        for (label, text) in table {
            assert_eq!(label.as_str(), Some(text));
            assert_eq!(Label::from_text(text), label);
        }
        assert_eq!(Label::Other.as_str(), None);
        // Case-sensitive (RFC 7468 §2, erratum 4508), and no trimming.
        for other in [
            "CERTIFICATE",
            "private key",
            "PRIVATE  KEY",
            " PRIVATE KEY",
            "DSA PRIVATE KEY",
            "",
        ] {
            assert_eq!(Label::from_text(other), Label::Other, "{other:?}");
        }
    }

    #[test]
    fn jose_alg_wraps_each_algorithm_enum() {
        assert_eq!(
            JoseAlg::from(SigningAlg::EdDSA),
            JoseAlg::Signing(SigningAlg::EdDSA)
        );
        assert_eq!(
            JoseAlg::from(KeyMgmtAlg::A128KW),
            JoseAlg::KeyMgmt(KeyMgmtAlg::A128KW)
        );
        assert_eq!(
            JoseAlg::from(ContentEncAlg::A128CbcHs256),
            JoseAlg::ContentEnc(ContentEncAlg::A128CbcHs256)
        );
        // Unknown values stay unknown; generation decides what to do with
        // them.
        let unknown: JoseAlg = SigningAlg::from("Ed448").into();
        assert_eq!(
            unknown,
            JoseAlg::Signing(SigningAlg::Unknown("Ed448".into()))
        );
    }

    #[test]
    fn the_same_name_in_two_registries_stays_distinct() {
        // The three enums are separate namespaces (RFC 7518 §7.1 registers
        // `alg` and `enc` values in one registry, with distinct usage
        // locations), so a JWS and a JWE identifier never compare equal.
        assert_ne!(
            JoseAlg::from(SigningAlg::from("A128GCM")),
            JoseAlg::from(ContentEncAlg::A128GCM)
        );
    }
}
