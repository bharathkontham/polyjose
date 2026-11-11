//! The public PEM/DER entry points on `Jwk` (ADR 0018 §3): `from_pem`, where
//! the label selects the structure (RFC 7468 §2), `from_der` with an explicit
//! `KeyFormat`, and `to_pem`/`to_der`. `oct` keys never cross PEM/DER, so
//! text can never become an HMAC secret (RFC 8725 §2.1).
//!
//! # Format matrix (ADR 0018 §3)
//!
//! | Format | Private key | Public key | `oct` |
//! |---|---|---|---|
//! | [`KeyFormat::Spki`] | exports its public half | yes | `UnsupportedAlgorithm` |
//! | [`KeyFormat::Pkcs8`] | EC, OKP, RSA | `InvalidKey("private key required")` | `UnsupportedAlgorithm` |
//! | [`KeyFormat::Sec1`] | EC only | `InvalidKey("private key required")` | `UnsupportedAlgorithm` |
//! | [`KeyFormat::Pkcs1`] | RSA: imports RSAPrivateKey; export is `InvalidKey` | RSA only | `UnsupportedAlgorithm` |
//!
//! On export the checks run in this order, the first failure being the
//! result:
//!
//! 1. an `oct` key is `UnsupportedAlgorithm` in every format;
//! 2. a key type the format cannot hold at all is `UnsupportedAlgorithm`:
//!    a non-EC key in SEC1 (RFC 5915 §3 holds only EC keys), a non-RSA key
//!    in PKCS#1 (RFC 8017 App. A.1);
//! 3. a public key in a private-key format (PKCS#8, SEC1) is
//!    `InvalidKey("private key required")`, and an RSA private key in
//!    PKCS#1 is `InvalidKey` with [`PKCS1_PRIVATE`]'s detail.
//!
//! PKCS#1 export writes the RSAPublicKey (RFC 8017 App. A.1.1), as
//! `RSA PUBLIC KEY`, of an RSA public key only. An RSA private key is
//! exported as PKCS#8 (ADR 0067, PRD 0003 R3); its PKCS#1 export is refused
//! rather than silently dropping the private members (feature 0020
//! review), so the caller writes the public half with [`Jwk::to_public`]
//! first, or uses SPKI, which is a public-key format.
//!
//! The dispatch to the per-family mappers (`okp`, `ec`, `super::rsa`) is on
//! the container's classified [`AlgId`], from a structural DER parse, never
//! on the PEM label alone (ADR 0018 §2).

use zeroize::Zeroizing;

use super::types::{AlgId, KeyFormat, Label};
use super::{ec, okp, pem, pkcs8, spki};
use crate::error::{Error, Result};
use crate::jwk::{Jwk, KeyMaterial};

/// The static detail for exporting a public key in a private-key format
/// (PKCS#8, SEC1): the plan.md format matrix wording.
const PRIVATE_KEY_REQUIRED: &str = "private key required";

/// The static detail for exporting an RSA private key as PKCS#1, which
/// polyjose writes as the RSAPublicKey only (RFC 8017 App. A.1.1).
const PKCS1_PRIVATE: &str = "pkcs1 export writes the public key; call to_public first";

/// The structure a PEM label names (RFC 7468 §2: the label "determines the
/// type of message encoded"), or `None` for a label polyjose does not
/// import.
///
/// `pem::decode` already refuses [`Label::EncryptedPrivateKey`] and
/// [`Label::Other`] from the BEGIN line, so the `None` arm is defence in
/// depth. The two PKCS#1 labels both map to [`KeyFormat::Pkcs1`];
/// [`Jwk::from_pem`] then reads the one structure each label names.
fn label_format(label: Label) -> Option<KeyFormat> {
    match label {
        // RFC 7468 §10: PKCS#8 PrivateKeyInfo / OneAsymmetricKey.
        Label::PrivateKey => Some(KeyFormat::Pkcs8),
        // RFC 7468 §13: SubjectPublicKeyInfo.
        Label::PublicKey => Some(KeyFormat::Spki),
        // RFC 5915 §4: SEC1 ECPrivateKey.
        Label::EcPrivateKey => Some(KeyFormat::Sec1),
        // OpenSSL's labels for the RFC 8017 App. A.1.1 RSAPublicKey and the
        // App. A.1.2 RSAPrivateKey (RFC 9500 §2.1 uses the latter).
        Label::RsaPublic | Label::RsaPrivate => Some(KeyFormat::Pkcs1),
        // RFC 7468 §11 (encrypted, ADR 0018 §4), anything else (RFC 7468
        // §5, e.g. CERTIFICATE).
        Label::EncryptedPrivateKey | Label::Other => None,
    }
}

/// The PEM label of each export format (RFC 7468 §10, §13; RFC 5915 §4;
/// OpenSSL's `RSA PUBLIC KEY`).
fn format_label(format: KeyFormat) -> Label {
    match format {
        KeyFormat::Pkcs8 => Label::PrivateKey,
        KeyFormat::Spki => Label::PublicKey,
        KeyFormat::Sec1 => Label::EcPrivateKey,
        KeyFormat::Pkcs1 => Label::RsaPublic,
    }
}

impl Jwk {
    /// Imports a key from one strict RFC 7468 PEM block.
    ///
    /// The label selects the structure (RFC 7468 §2; ADR 0018 §3):
    ///
    /// | Label | Structure |
    /// |---|---|
    /// | `PRIVATE KEY` | PKCS#8 (RFC 5958 §2; RFC 7468 §10): EC, OKP or RSA private key |
    /// | `PUBLIC KEY` | SPKI (RFC 5280 §4.1.2.7; RFC 7468 §13): EC, OKP or RSA public key |
    /// | `EC PRIVATE KEY` | SEC1 ECPrivateKey (RFC 5915 §3, §4) |
    /// | `RSA PUBLIC KEY` | PKCS#1 RSAPublicKey (RFC 8017 App. A.1.1) |
    /// | `RSA PRIVATE KEY` | PKCS#1 two-prime RSAPrivateKey (RFC 8017 App. A.1.2) |
    ///
    /// The body is then imported exactly as [`Jwk::from_der`] does for that
    /// format, so the key type always comes from the DER (ADR 0018 §2). The
    /// grammar is strict (ADR 0018 §2): one block with only whitespace around
    /// it, matching labels, no headers, 64-character lines, canonical padded
    /// base64 (RFC 4648 §4), LF, CRLF or CR line endings.
    ///
    /// The result never has `kty` `oct` (RFC 8725 §2.1, ADR 0018 §3) and no
    /// `alg` member: a PEM key does not name its JOSE algorithm.
    ///
    /// ```
    /// use polyjose::jwk::Jwk;
    ///
    /// // RFC 8410 §10.1, the Ed25519 public key.
    /// let pem = "-----BEGIN PUBLIC KEY-----\n\
    ///            MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n\
    ///            -----END PUBLIC KEY-----\n";
    /// let jwk = Jwk::from_pem(pem)?;
    /// assert!(jwk.is_public());
    /// # Ok::<(), polyjose::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// - [`Error::UnsupportedAlgorithm`] for well-formed input polyjose does
    ///   not support (ADR 0018 §4):
    ///   - **encrypted keys are out of scope**: `ENCRYPTED PRIVATE KEY`
    ///     (RFC 5958 §3, RFC 7468 §11) and legacy `Proc-Type: 4,ENCRYPTED`
    ///     PEM (RFC 1421 §4.6.1.1), refused before the body is decoded;
    ///   - multi-prime RSA private keys (RFC 8017 App. A.1.2 version
    ///     multi; ADR 0067 §3);
    ///   - other labels such as `CERTIFICATE` (RFC 7468 §5);
    ///   - id-RSASSA-PSS, Ed448/X448, specifiedCurve and non-JOSE curves.
    /// - [`Error::InvalidKey`] for malformed or non-canonical PEM or DER
    ///   (BER, trailing data, a label around the wrong structure), and for
    ///   keys that fail JWK validation (off-curve points, out-of-range
    ///   scalars, inconsistent embedded public keys, an RSA modulus outside
    ///   2048–8192 bits: `jwk::RSA_MODULUS_BITS`, RFC 7518 §3.3, ADR 0026
    ///   §2 step 8; RSA private members that are not the key of `n` and
    ///   `e`, ADR 0043).
    ///
    /// Error details are static strings and never contain input bytes.
    pub fn from_pem(pem: &str) -> Result<Jwk> {
        let (label, der) = pem::decode(pem)?;
        let format = label_format(label).ok_or(Error::UnsupportedAlgorithm)?;
        // RFC 7468 §2: the label names the structure, so each PKCS#1 label
        // reads only its own one (RFC 8017 App. A.1.1 or App. A.1.2).
        match label {
            Label::RsaPublic => super::rsa::from_pkcs1_public(&der),
            Label::RsaPrivate => super::rsa::from_pkcs1_private(&der),
            _ => Jwk::from_der(&der, format),
        }
    }

    /// Imports a key from DER in the format the caller names.
    ///
    /// There is no format sniffing: the caller states which structure the
    /// octets hold (misuse resistance, ADR 0007), and anything else is
    /// rejected. Inside that format the key type comes from the structural
    /// parse (ADR 0018 §2):
    ///
    /// - [`KeyFormat::Pkcs8`]: a OneAsymmetricKey (RFC 5958 §2), v1 or v2,
    ///   whose AlgorithmIdentifier is id-ecPublicKey with a JOSE namedCurve
    ///   (RFC 5480 §2.1.1; inner RFC 5915 ECPrivateKey), id-Ed25519 /
    ///   id-X25519 (RFC 8410 §3, §7), or rsaEncryption with NULL parameters
    ///   (RFC 3279 §2.3.1; inner two-prime RSAPrivateKey, RFC 8017
    ///   App. A.1.2; v1 only).
    /// - [`KeyFormat::Sec1`]: an ECPrivateKey (RFC 5915 §3) with its `[0]`
    ///   namedCurve.
    /// - [`KeyFormat::Spki`]: a SubjectPublicKeyInfo (RFC 5280 §4.1.2.7)
    ///   holding an EC point, uncompressed or compressed (RFC 5480 §2.2), an
    ///   Ed25519/X25519 key (RFC 8410 §4) or an RSAPublicKey (RFC 3279
    ///   §2.3.1).
    /// - [`KeyFormat::Pkcs1`]: an RSAPublicKey (RFC 8017 App. A.1.1) or a
    ///   two-prime RSAPrivateKey (App. A.1.2), told apart by shape.
    ///
    /// DER only (X.690 §10), at most 64 KiB, with nothing after the
    /// outermost element. Every key is validated by [`Jwk::from_object`]
    /// before it is returned. The result never has `kty` `oct` and no `alg`.
    ///
    /// # Errors
    ///
    /// As [`Jwk::from_pem`]: [`Error::UnsupportedAlgorithm`] for encrypted
    /// PKCS#8 (RFC 5958 §3; **encrypted keys are out of scope**),
    /// multi-prime RSA keys (ADR 0067 §3), a v2 PKCS#8 RSA key with a
    /// publicKey, and unsupported algorithms or curves;
    /// [`Error::InvalidKey`] for everything malformed or invalid, including
    /// DER of another format than `format` (a PKCS#1 RSAPrivateKey given as
    /// [`KeyFormat::Pkcs8`] or [`KeyFormat::Sec1`] among them), an RSA
    /// modulus outside 2048–8192 bits (`jwk::RSA_MODULUS_BITS`; RFC 7518
    /// §3.3, ADR 0026 §2 step 8) and RSA private members inconsistent with
    /// `n` and `e` (ADR 0043).
    pub fn from_der(der: &[u8], format: KeyFormat) -> Result<Jwk> {
        match format {
            KeyFormat::Pkcs8 => {
                // Encrypted PKCS#8 fails inside decode, before privateKey is
                // opened (ADR 0018 §4).
                let parts = pkcs8::decode(der)?;
                match parts.alg {
                    AlgId::Ec(_) => ec::from_pkcs8(parts),
                    AlgId::Ed25519 | AlgId::X25519 => okp::from_pkcs8(parts),
                    AlgId::RsaEncryption => super::rsa::from_pkcs8(parts),
                }
            }
            KeyFormat::Spki => {
                let parts = spki::decode(der)?;
                match parts.alg {
                    AlgId::Ec(_) => ec::from_spki(parts),
                    AlgId::Ed25519 | AlgId::X25519 => okp::from_spki(parts),
                    AlgId::RsaEncryption => super::rsa::from_spki(parts),
                }
            }
            KeyFormat::Sec1 => ec::from_sec1(der),
            KeyFormat::Pkcs1 => super::rsa::from_pkcs1(der),
        }
    }

    /// Exports the key as DER in `format`, in the byte layout OpenSSL 4
    /// writes, so a round trip of an OpenSSL key is byte-identical (ADR 0018
    /// §3):
    ///
    /// - [`KeyFormat::Pkcs8`]: PKCS#8 v1 without attributes or publicKey
    ///   (RFC 5958 §2). EC: the inner ECPrivateKey with `[1]` and no `[0]`
    ///   (RFC 5915 §3, erratum 5008). OKP: the CurvePrivateKey (RFC 8410 §7).
    ///   RSA: rsaEncryption + NULL and the two-prime RSAPrivateKey
    ///   (RFC 8017 App. A.1.2).
    /// - [`KeyFormat::Sec1`]: ECPrivateKey with `[0]` namedCurve and `[1]`
    ///   uncompressed publicKey (RFC 5915 §3).
    /// - [`KeyFormat::Spki`]: SubjectPublicKeyInfo of the public half; EC
    ///   points uncompressed (RFC 5480 §2.2), OKP raw (RFC 8410 §4), RSA as
    ///   rsaEncryption + NULL (RFC 3279 §2.3.1).
    /// - [`KeyFormat::Pkcs1`]: RSAPublicKey (RFC 8017 App. A.1.1) of an RSA
    ///   public key. A private key is refused (export it as PKCS#8, or call
    ///   [`Jwk::to_public`] first).
    ///
    /// Only the key material is exported: `kid`, `use`, `key_ops`, `alg` and
    /// the `x5*` members have no place in these structures. The output is
    /// [`Zeroizing`], since PKCS#8 and SEC1 hold the private key.
    ///
    /// # Errors
    ///
    /// In this order (see the module's format matrix):
    ///
    /// 1. [`Error::UnsupportedAlgorithm`] for an `oct` key, in every format
    ///    (RFC 8725 §2.1, ADR 0018 §3);
    /// 2. [`Error::UnsupportedAlgorithm`] for a non-EC key in
    ///    [`KeyFormat::Sec1`] and a non-RSA key in [`KeyFormat::Pkcs1`];
    /// 3. [`Error::InvalidKey`]`("private key required")` for a public key
    ///    in [`KeyFormat::Pkcs8`] or [`KeyFormat::Sec1`], and
    ///    [`Error::InvalidKey`]`("pkcs1 export writes the public key; call
    ///    to_public first")` for an RSA private key in [`KeyFormat::Pkcs1`].
    pub fn to_der(&self, format: KeyFormat) -> Result<Zeroizing<Vec<u8>>> {
        let private_format = matches!(format, KeyFormat::Pkcs8 | KeyFormat::Sec1);
        match (self.material(), format) {
            (KeyMaterial::Oct(_), _) => Err(Error::UnsupportedAlgorithm),
            (KeyMaterial::Rsa(_) | KeyMaterial::Okp(_), KeyFormat::Sec1)
            | (KeyMaterial::Ec(_) | KeyMaterial::Okp(_), KeyFormat::Pkcs1) => {
                Err(Error::UnsupportedAlgorithm)
            }
            _ if private_format && self.is_public() => Err(Error::InvalidKey(PRIVATE_KEY_REQUIRED)),
            (KeyMaterial::Rsa(_), KeyFormat::Pkcs1) if !self.is_public() => {
                Err(Error::InvalidKey(PKCS1_PRIVATE))
            }
            (KeyMaterial::Ec(key), KeyFormat::Pkcs8) => ec::to_pkcs8(key),
            (KeyMaterial::Ec(key), KeyFormat::Sec1) => ec::to_sec1(key),
            (KeyMaterial::Ec(key), KeyFormat::Spki) => ec::to_spki(key),
            (KeyMaterial::Okp(key), KeyFormat::Pkcs8) => okp::to_pkcs8(key),
            (KeyMaterial::Okp(key), KeyFormat::Spki) => okp::to_spki(key),
            (KeyMaterial::Rsa(key), KeyFormat::Spki) => super::rsa::to_spki(key),
            (KeyMaterial::Rsa(key), KeyFormat::Pkcs1) => super::rsa::to_pkcs1(key),
            (KeyMaterial::Rsa(key), KeyFormat::Pkcs8) => super::rsa::to_pkcs8(key),
        }
    }

    /// Exports the key as a strict RFC 7468 PEM block: [`Jwk::to_der`] in
    /// `format`, wrapped with the format's label (`PRIVATE KEY`, RFC 7468
    /// §10; `PUBLIC KEY`, §13; `EC PRIVATE KEY`, RFC 5915 §4; `RSA PUBLIC
    /// KEY`), 64-character lines and LF line endings, ending in a newline.
    /// [`Jwk::from_pem`] reads it back to the same key.
    ///
    /// ```
    /// use polyjose::jwk::Jwk;
    /// use polyjose::keys::{KeyFormat, KeySpec, generate};
    /// use polyjose::jwk::OkpCurve;
    ///
    /// let key = generate(KeySpec::Okp(OkpCurve::Ed25519))?;
    /// let pem = key.to_pem(KeyFormat::Pkcs8)?;
    /// assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
    /// let public = Jwk::from_pem(&key.to_pem(KeyFormat::Spki)?)?;
    /// assert!(public.is_public());
    /// # Ok::<(), polyjose::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Those of [`Jwk::to_der`].
    pub fn to_pem(&self, format: KeyFormat) -> Result<Zeroizing<String>> {
        let der = self.to_der(format)?;
        pem::encode(format_label(format), &der)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_import_label_maps_to_its_format_and_back() {
        for format in [
            KeyFormat::Pkcs8,
            KeyFormat::Spki,
            KeyFormat::Sec1,
            KeyFormat::Pkcs1,
        ] {
            assert_eq!(label_format(format_label(format)), Some(format));
        }
        // ADR 0067: `RSA PRIVATE KEY` is PKCS#1 too (RFC 8017 App. A.1.2).
        assert_eq!(label_format(Label::RsaPrivate), Some(KeyFormat::Pkcs1));
        for label in [Label::EncryptedPrivateKey, Label::Other] {
            assert_eq!(label_format(label), None, "{label:?}");
        }
    }

    #[test]
    fn a_pkcs1_rsa_private_key_imports_only_as_pkcs1() {
        // ADR 0067 (amending ADR 0018 §3's "RSA private, any format" row):
        // the PKCS#1 RSAPrivateKey (RFC 8017 App. A.1.2) imports as
        // `KeyFormat::Pkcs1` and under `RSA PRIVATE KEY`; as PKCS#8
        // (RFC 7468 §10) or SEC1 (RFC 5915 §4), by format or by label, it is
        // the wrong structure: InvalidKey.
        let der = super::super::der::fixtures::load("openssl", "reject-rsa2048-private-pkcs1.der");
        let imported = Jwk::from_der(&der, KeyFormat::Pkcs1).unwrap();
        assert!(!imported.is_public() && imported.alg().is_none());
        let pem = pem::encode(Label::RsaPrivate, &der).unwrap();
        assert_eq!(*Jwk::from_pem(&pem).unwrap().to_json(), *imported.to_json());
        for format in [KeyFormat::Pkcs8, KeyFormat::Sec1, KeyFormat::Spki] {
            assert!(
                matches!(Jwk::from_der(&der, format), Err(Error::InvalidKey(_))),
                "{format:?}"
            );
        }
        for label in [Label::PrivateKey, Label::EcPrivateKey, Label::RsaPublic] {
            let text = pem::encode(label, &der).unwrap();
            assert!(
                matches!(Jwk::from_pem(&text), Err(Error::InvalidKey(_))),
                "{label:?}"
            );
        }
        // The public key under `RSA PRIVATE KEY` is the wrong structure too
        // (RFC 7468 §2: the label names the structure).
        let public = super::super::der::fixtures::load("openssl", "rsa2048-pkcs1-pub.der");
        let text = pem::encode(Label::RsaPrivate, &public).unwrap();
        assert!(matches!(Jwk::from_pem(&text), Err(Error::InvalidKey(_))));
        // Export: PKCS#8 holds the private key, SPKI the public half (the
        // module's format matrix).
        let pkcs8 = imported.to_der(KeyFormat::Pkcs8).unwrap();
        let back = Jwk::from_der(&pkcs8, KeyFormat::Pkcs8).unwrap();
        assert_eq!(*back.to_json(), *imported.to_json());
        let public = imported.to_public().unwrap();
        assert_eq!(
            public.to_der(KeyFormat::Pkcs8).err(),
            Some(Error::InvalidKey(PRIVATE_KEY_REQUIRED))
        );
    }

    #[test]
    fn pkcs1_export_writes_a_public_key_and_refuses_a_private_one() {
        // RFC 8017 App. A.1.1: PKCS#1 export is the RSAPublicKey, so a
        // private key is InvalidKey with a static detail (feature 0020
        // review), in DER and in PEM, rather than its public half written
        // silently; its public half (`to_public`) exports as before.
        let der = super::super::der::fixtures::load("openssl", "reject-rsa2048-private-pkcs1.der");
        let private = Jwk::from_der(&der, KeyFormat::Pkcs1).unwrap();
        assert!(!private.is_public());
        let refused = Some(Error::InvalidKey(PKCS1_PRIVATE));
        assert_eq!(private.to_der(KeyFormat::Pkcs1).err(), refused);
        assert_eq!(private.to_pem(KeyFormat::Pkcs1).err(), refused);
        assert_eq!(
            PKCS1_PRIVATE,
            "pkcs1 export writes the public key; call to_public first"
        );
        let public = private.to_public().unwrap();
        let pkcs1 = public.to_der(KeyFormat::Pkcs1).unwrap();
        assert_eq!(
            &pkcs1[..],
            &super::super::der::fixtures::load("openssl", "rsa2048-pkcs1-pub.der")[..]
        );
        assert!(
            public
                .to_pem(KeyFormat::Pkcs1)
                .unwrap()
                .starts_with("-----BEGIN RSA PUBLIC KEY-----\n")
        );
        // The earlier checks still come first: an EC private key in PKCS#1
        // is UnsupportedAlgorithm, not this InvalidKey.
        let ec = Jwk::from_json(
            br#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"}"#,
        )
        .unwrap();
        assert_eq!(
            ec.to_der(KeyFormat::Pkcs1).err(),
            Some(Error::UnsupportedAlgorithm)
        );
    }
}
