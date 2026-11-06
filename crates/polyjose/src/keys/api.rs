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
//! | [`KeyFormat::Pkcs8`] | EC, OKP | `InvalidKey("private key required")` | `UnsupportedAlgorithm` |
//! | [`KeyFormat::Sec1`] | EC only | `InvalidKey("private key required")` | `UnsupportedAlgorithm` |
//! | [`KeyFormat::Pkcs1`] | — | RSA only | `UnsupportedAlgorithm` |
//!
//! On export the checks run in this order, the first failure being the
//! result:
//!
//! 1. an `oct` key is `UnsupportedAlgorithm` in every format;
//! 2. a key type the format cannot hold at all is `UnsupportedAlgorithm`:
//!    a non-EC key in SEC1 (RFC 5915 §3 holds only EC keys), a non-RSA key
//!    in PKCS#1 (RFC 8017 App. A.1);
//! 3. a public key in a private-key format (PKCS#8, SEC1) is
//!    `InvalidKey("private key required")`. RSA keys are always public
//!    (ADR 0021), so an RSA key in PKCS#8 is this case.
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

/// The structure a PEM label names (RFC 7468 §2: the label "determines the
/// type of message encoded"), or `None` for a label polyjose does not
/// import.
///
/// `pem::decode` already refuses [`Label::EncryptedPrivateKey`],
/// [`Label::RsaPrivate`] and [`Label::Other`] from the BEGIN line, so the
/// `None` arm is defence in depth.
fn label_format(label: Label) -> Option<KeyFormat> {
    match label {
        // RFC 7468 §10: PKCS#8 PrivateKeyInfo / OneAsymmetricKey.
        Label::PrivateKey => Some(KeyFormat::Pkcs8),
        // RFC 7468 §13: SubjectPublicKeyInfo.
        Label::PublicKey => Some(KeyFormat::Spki),
        // RFC 5915 §4: SEC1 ECPrivateKey.
        Label::EcPrivateKey => Some(KeyFormat::Sec1),
        // OpenSSL's label for the RFC 8017 App. A.1.1 RSAPublicKey.
        Label::RsaPublic => Some(KeyFormat::Pkcs1),
        // RFC 7468 §11 (encrypted, ADR 0018 §4), RSA private keys (ADR
        // 0021), anything else (RFC 7468 §5, e.g. CERTIFICATE).
        Label::EncryptedPrivateKey | Label::RsaPrivate | Label::Other => None,
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
    /// | `PRIVATE KEY` | PKCS#8 (RFC 5958 §2; RFC 7468 §10): EC or OKP private key |
    /// | `PUBLIC KEY` | SPKI (RFC 5280 §4.1.2.7; RFC 7468 §13): EC, OKP or RSA public key |
    /// | `EC PRIVATE KEY` | SEC1 ECPrivateKey (RFC 5915 §3, §4) |
    /// | `RSA PUBLIC KEY` | PKCS#1 RSAPublicKey (RFC 8017 App. A.1.1) |
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
    ///   - RSA private keys in any form (`RSA PRIVATE KEY`, or rsaEncryption
    ///     inside `PRIVATE KEY`; ADR 0021);
    ///   - other labels such as `CERTIFICATE` (RFC 7468 §5);
    ///   - id-RSASSA-PSS, Ed448/X448, specifiedCurve and non-JOSE curves.
    /// - [`Error::InvalidKey`] for malformed or non-canonical PEM or DER
    ///   (BER, trailing data, a label around the wrong structure), and for
    ///   keys that fail JWK validation (off-curve points, out-of-range
    ///   scalars, inconsistent embedded public keys, RSA under 2048 bits).
    ///
    /// Error details are static strings and never contain input bytes.
    pub fn from_pem(pem: &str) -> Result<Jwk> {
        let (label, der) = pem::decode(pem)?;
        let format = label_format(label).ok_or(Error::UnsupportedAlgorithm)?;
        Jwk::from_der(&der, format)
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
    ///   (RFC 5480 §2.1.1; inner RFC 5915 ECPrivateKey) or id-Ed25519 /
    ///   id-X25519 (RFC 8410 §3, §7).
    /// - [`KeyFormat::Sec1`]: an ECPrivateKey (RFC 5915 §3) with its `[0]`
    ///   namedCurve.
    /// - [`KeyFormat::Spki`]: a SubjectPublicKeyInfo (RFC 5280 §4.1.2.7)
    ///   holding an EC point, uncompressed or compressed (RFC 5480 §2.2), an
    ///   Ed25519/X25519 key (RFC 8410 §4) or an RSAPublicKey (RFC 3279
    ///   §2.3.1).
    /// - [`KeyFormat::Pkcs1`]: an RSAPublicKey (RFC 8017 App. A.1.1).
    ///
    /// DER only (X.690 §10), at most 64 KiB, with nothing after the
    /// outermost element. Every key is validated by [`Jwk::from_object`]
    /// before it is returned. The result never has `kty` `oct` and no `alg`.
    ///
    /// # Errors
    ///
    /// As [`Jwk::from_pem`]: [`Error::UnsupportedAlgorithm`] for encrypted
    /// PKCS#8 (RFC 5958 §3; **encrypted keys are out of scope**), RSA
    /// private keys (ADR 0021) and unsupported algorithms or curves;
    /// [`Error::InvalidKey`] for everything malformed or invalid, including
    /// DER of another format than `format`.
    pub fn from_der(der: &[u8], format: KeyFormat) -> Result<Jwk> {
        match format {
            KeyFormat::Pkcs8 => {
                // Encrypted PKCS#8 and rsaEncryption fail inside decode,
                // before privateKey is opened (ADR 0018 §4, ADR 0021).
                let parts = pkcs8::decode(der)?;
                match parts.alg {
                    AlgId::Ec(_) => ec::from_pkcs8(parts),
                    AlgId::Ed25519 | AlgId::X25519 => okp::from_pkcs8(parts),
                    AlgId::RsaEncryption => Err(Error::UnsupportedAlgorithm),
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
    /// - [`KeyFormat::Sec1`]: ECPrivateKey with `[0]` namedCurve and `[1]`
    ///   uncompressed publicKey (RFC 5915 §3).
    /// - [`KeyFormat::Spki`]: SubjectPublicKeyInfo of the public half; EC
    ///   points uncompressed (RFC 5480 §2.2), OKP raw (RFC 8410 §4), RSA as
    ///   rsaEncryption + NULL (RFC 3279 §2.3.1).
    /// - [`KeyFormat::Pkcs1`]: RSAPublicKey (RFC 8017 App. A.1.1).
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
    ///    in [`KeyFormat::Pkcs8`] or [`KeyFormat::Sec1`].
    pub fn to_der(&self, format: KeyFormat) -> Result<Zeroizing<Vec<u8>>> {
        let private_format = matches!(format, KeyFormat::Pkcs8 | KeyFormat::Sec1);
        match (self.material(), format) {
            (KeyMaterial::Oct(_), _) => Err(Error::UnsupportedAlgorithm),
            (KeyMaterial::Rsa(_) | KeyMaterial::Okp(_), KeyFormat::Sec1)
            | (KeyMaterial::Ec(_) | KeyMaterial::Okp(_), KeyFormat::Pkcs1) => {
                Err(Error::UnsupportedAlgorithm)
            }
            _ if private_format && self.is_public() => Err(Error::InvalidKey(PRIVATE_KEY_REQUIRED)),
            (KeyMaterial::Ec(key), KeyFormat::Pkcs8) => ec::to_pkcs8(key),
            (KeyMaterial::Ec(key), KeyFormat::Sec1) => ec::to_sec1(key),
            (KeyMaterial::Ec(key), KeyFormat::Spki) => ec::to_spki(key),
            (KeyMaterial::Okp(key), KeyFormat::Pkcs8) => okp::to_pkcs8(key),
            (KeyMaterial::Okp(key), KeyFormat::Spki) => okp::to_spki(key),
            (KeyMaterial::Rsa(key), KeyFormat::Spki) => super::rsa::to_spki(key),
            (KeyMaterial::Rsa(key), KeyFormat::Pkcs1) => super::rsa::to_pkcs1(key),
            // RSA keys are always public, so RSA + PKCS#8 was refused above.
            (KeyMaterial::Rsa(_), KeyFormat::Pkcs8) => Err(Error::InvalidKey(PRIVATE_KEY_REQUIRED)),
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
        for label in [Label::EncryptedPrivateKey, Label::RsaPrivate, Label::Other] {
            assert_eq!(label_format(label), None, "{label:?}");
        }
    }
}
