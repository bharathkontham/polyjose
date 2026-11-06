//! Types shared by the keys module: the public format and generation
//! selectors, and the crate-internal classification of key containers.

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

#[cfg(test)]
mod tests {
    use super::*;

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
