//! Ed25519 and X25519 keys (RFC 8037 §2) to and from PKCS#8 and SPKI
//! (RFC 8410 §3, §4, §7): parameters absent, and the private key as a
//! CurvePrivateKey OCTET STRING inside the PKCS#8 privateKey.

use zeroize::Zeroizing;

use super::jwk_build;
use super::spki;
use super::types::{AlgId, Pkcs8Parts, SpkiParts};
use crate::error::{Error, Result};
use crate::jwk::{Jwk, OkpCurve, OkpKey};

/// The length of an Ed25519 or X25519 public or private key: 32 octets
/// (RFC 8032 §5.1.5, RFC 7748 §5; RFC 8037 §2).
const KEY_LEN: usize = 32;

/// The curve an RFC 8410 §3 AlgorithmIdentifier names: id-Ed25519 or
/// id-X25519. The container's classified algorithm alone decides `crv`, so
/// a key labelled id-X25519 is never read as Ed25519, or the reverse.
fn curve(alg: AlgId) -> Result<OkpCurve> {
    match alg {
        AlgId::Ed25519 => Ok(OkpCurve::Ed25519),
        AlgId::X25519 => Ok(OkpCurve::X25519),
        AlgId::Ec(_) | AlgId::RsaEncryption => Err(Error::InvalidKey("the key is not an OKP key")),
    }
}

/// The RFC 8410 §3 AlgorithmIdentifier of `crv`.
fn alg_id(crv: OkpCurve) -> AlgId {
    match crv {
        OkpCurve::Ed25519 => AlgId::Ed25519,
        OkpCurve::X25519 => AlgId::X25519,
    }
}

/// Imports a PKCS#8 Ed25519 or X25519 private key.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "called by the PEM/DER facade (T08)")
)]
pub(crate) fn from_pkcs8(parts: Pkcs8Parts<'_>) -> Result<Jwk> {
    let _ = curve(parts.alg)?;
    Err(Error::InvalidKey("not implemented"))
}

/// Exports an Ed25519 or X25519 private key as PKCS#8 v1.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "called by the PEM/DER facade (T08)")
)]
pub(crate) fn to_pkcs8(key: &OkpKey) -> Result<Zeroizing<Vec<u8>>> {
    let _ = key;
    Err(Error::InvalidKey("not implemented"))
}

/// Imports a SubjectPublicKeyInfo (RFC 5280 §4.1.2.7) that `spki::decode`
/// classified as id-Ed25519 or id-X25519 (RFC 8410 §3), as a public OKP
/// JWK (RFC 8037 §2) with `crv` from the AlgorithmIdentifier and `x` the
/// subjectPublicKey.
///
/// RFC 8410 §4: "The public key value is the BIT STRING
/// subjectPublicKey", the raw key of RFC 8032 §5.1.5 (Ed25519) or RFC 7748
/// §5 (X25519), 32 octets. The JWK is built through
/// [`jwk_build::okp_jwk`], so an Ed25519 key must also decode canonically,
/// not be of small order and have no torsion component (RFC 8032 §5.1.3;
/// ADR 0041 §4, ADR 0043 §1).
///
/// # Errors
///
/// [`Error::InvalidKey`] if the key is not 32 octets, is an invalid Ed25519
/// key, or `parts` is not an OKP key.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "called by the PEM/DER facade (T08)")
)]
pub(crate) fn from_spki(parts: SpkiParts<'_>) -> Result<Jwk> {
    let crv = curve(parts.alg)?;
    if parts.subject_public_key.len() != KEY_LEN {
        return Err(Error::InvalidKey("OKP subjectPublicKey is not 32 octets"));
    }
    jwk_build::okp_jwk(crv, parts.subject_public_key, None, None)
}

/// Exports the public key `x` of an Ed25519 or X25519 key (private or
/// public) as a DER SubjectPublicKeyInfo: the RFC 8410 §3 AlgorithmIdentifier
/// with parameters absent and `x` as the BIT STRING (RFC 8410 §4), the
/// layout of RFC 8410 §10.1 and OpenSSL 4 (ADR 0018 §3).
///
/// # Errors
///
/// None in practice: [`Error::InvalidKey`] only if the DER writer's planned
/// length were wrong.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "called by the PEM/DER facade (T08)")
)]
pub(crate) fn to_spki(key: &OkpKey) -> Result<Zeroizing<Vec<u8>>> {
    spki::encode(&SpkiParts {
        alg: alg_id(key.crv()),
        subject_public_key: key.x(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk::KeyMaterial;
    use crate::keys::der::fixtures;
    use crate::keys::pem;
    use crate::keys::pkcs8;
    use crate::keys::types::Label;

    /// The JWK of a committed `.jwk.json` fixture.
    fn jwk_fixture(dir: &str, file: &str) -> Jwk {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/keys")
            .join(dir)
            .join(file);
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        Jwk::from_json(&bytes).unwrap_or_else(|e| panic!("{file}: {e:?}"))
    }

    fn assert_same_key(actual: &Jwk, expected: &Jwk, what: &str) {
        assert_eq!(*actual.to_json(), *expected.to_json(), "{what}");
    }

    fn okp(jwk: &Jwk) -> &OkpKey {
        let KeyMaterial::Okp(key) = jwk.material() else {
            panic!("an OKP key")
        };
        key
    }

    /// `der` through the PKCS#8 container (T02) and this mapper.
    fn import_pkcs8(der: &[u8]) -> Result<Jwk> {
        from_pkcs8(pkcs8::decode(der)?)
    }

    /// `der` through the SPKI container (T02) and this mapper.
    fn import_spki(der: &[u8]) -> Result<Jwk> {
        from_spki(spki::decode(der)?)
    }

    /// The SPKI fixtures of RFC 8410 §10.1 and RFC 8037 A.2 and A.6 (the
    /// A.6 ephemeral key is RFC 7748 §6.1 Alice's, `bob` is Bob's): each
    /// imports to its `.jwk.json` and exports back to the same DER.
    #[test]
    fn rfc_spki_vectors_import_and_export_byte_for_byte() {
        let names = fixtures::files("rfc", |name| {
            (name.starts_with("rfc8037-") || name.starts_with("rfc8410-")) && name.contains("spki")
        });
        assert_eq!(names.len(), 7, "{names:?}");
        for name in names {
            let der = fixtures::load("rfc", &name);
            let stem = name.rsplit_once('.').unwrap().0;
            let jwk = import_spki(&der).unwrap_or_else(|e| panic!("{name}: {e:?}"));
            assert!(jwk.is_public(), "{name}");
            assert_same_key(
                &jwk,
                &jwk_fixture("rfc", &format!("{stem}.jwk.json")),
                &name,
            );
            assert_eq!(*to_spki(okp(&jwk)).unwrap(), der, "{name}");
        }
    }

    /// RFC 8410 §10.1: the SPKI decodes to this `x`.
    #[test]
    fn rfc8410_10_1_public_key() {
        let der = fixtures::load("rfc", "rfc8410-10.1-ed25519-spki.pem");
        let jwk = import_spki(&der).unwrap();
        let expected = Jwk::from_json(
            br#"{"kty":"OKP","crv":"Ed25519","x":"Gb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE"}"#,
        )
        .unwrap();
        assert_same_key(&jwk, &expected, "RFC 8410 §10.1");
    }

    /// The PKCS#8 fixtures of RFC 8410 §10.3 (v1, and v2 with an attribute
    /// and the publicKey) and RFC 8037 A.1 and A.6: each imports to its
    /// `.jwk.json`, with `x` derived from `d` where the container has no
    /// publicKey, and exports back to the same DER, except that the v2 key
    /// exports as the §10.3 v1 key (ADR 0018 §3).
    #[test]
    fn rfc_pkcs8_vectors_import_and_export_byte_for_byte() {
        let names = fixtures::files("rfc", |name| {
            (name.starts_with("rfc8037-") || name.starts_with("rfc8410-")) && name.contains("pkcs8")
        });
        assert_eq!(names.len(), 6, "{names:?}");
        for name in names {
            let der = fixtures::load("rfc", &name);
            let stem = name.rsplit_once('.').unwrap().0;
            let jwk = import_pkcs8(&der).unwrap_or_else(|e| panic!("{name}: {e:?}"));
            assert!(!jwk.is_public(), "{name}");
            assert_same_key(
                &jwk,
                &jwk_fixture("rfc", &format!("{stem}.jwk.json")),
                &name,
            );
            let exported = if name.contains("-v2-") {
                fixtures::load("rfc", "rfc8410-10.3-ed25519-pkcs8-v1.pem")
            } else {
                der
            };
            assert_eq!(*to_pkcs8(okp(&jwk)).unwrap(), exported, "{name}");
        }
    }

    /// RFC 8410 §10.3: the v1 key and the v2 key (attribute and publicKey)
    /// are the same JWK, whose `x` is the §10.1 public key, and the JWK
    /// exports to the v1 bytes exactly; its SPKI is the §10.1 bytes.
    #[test]
    fn rfc8410_10_3_v1_and_v2_are_one_key() {
        let v1 = fixtures::load("rfc", "rfc8410-10.3-ed25519-pkcs8-v1.pem");
        let v2 = fixtures::load("rfc", "rfc8410-10.3-ed25519-pkcs8-v2-attr-pub.pem");
        assert_eq!(pkcs8::decode(&v2).unwrap().version, 1);
        let from_v1 = import_pkcs8(&v1).unwrap();
        let from_v2 = import_pkcs8(&v2).unwrap();
        assert_same_key(&from_v1, &from_v2, "v1 and v2");
        assert_same_key(
            &from_v1,
            &jwk_fixture("rfc", "rfc8410-10.3-ed25519-pkcs8-v1.jwk.json"),
            "§10.3",
        );
        assert_eq!(*to_pkcs8(okp(&from_v2)).unwrap(), v1);
        assert_eq!(
            *to_spki(okp(&from_v2)).unwrap(),
            fixtures::load("rfc", "rfc8410-10.1-ed25519-spki.pem")
        );
    }

    /// The OpenSSL 4 keys (`openssl/OPENSSL_VERSION`), as DER and as PEM,
    /// import to `openssl/expected/*.jwk.json` and export back
    /// byte-identical (ADR 0018 §3): the DER, and the PEM text through the
    /// RFC 7468 encoder (T03).
    #[test]
    fn openssl_keys_round_trip_byte_identical() {
        let names = fixtures::files("openssl", |name| {
            name.starts_with("ed25519-") || name.starts_with("x25519-")
        });
        assert_eq!(names.len(), 8, "{names:?}");
        for name in names {
            let der = fixtures::load("openssl", &name);
            let stem = name.rsplit_once('.').unwrap().0;
            let (jwk, exported, label) = if name.contains("pkcs8") {
                let jwk = import_pkcs8(&der).unwrap_or_else(|e| panic!("{name}: {e:?}"));
                let exported = to_pkcs8(okp(&jwk)).unwrap();
                (jwk, exported, Label::PrivateKey)
            } else {
                let jwk = import_spki(&der).unwrap_or_else(|e| panic!("{name}: {e:?}"));
                let exported = to_spki(okp(&jwk)).unwrap();
                (jwk, exported, Label::PublicKey)
            };
            assert_same_key(
                &jwk,
                &jwk_fixture("openssl/expected", &format!("{stem}.jwk.json")),
                &name,
            );
            assert_eq!(*exported, der, "{name}");
            if name.ends_with(".pem") {
                let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/data/keys/openssl")
                    .join(&name);
                let text = std::fs::read_to_string(path).unwrap();
                assert_eq!(*pem::encode(label, &exported).unwrap(), text, "{name}");
            }
        }
    }
}
