//! Ed25519 and X25519 keys (RFC 8037 §2) to and from PKCS#8 and SPKI
//! (RFC 8410 §3, §4, §7): parameters absent, and the private key as a
//! CurvePrivateKey OCTET STRING inside the PKCS#8 privateKey.

use zeroize::Zeroizing;

use super::types::{AlgId, SpkiParts};
use crate::error::{Error, Result};
use crate::jwk::{Jwk, OkpCurve, OkpKey};

/// The curve an RFC 8410 §3 AlgorithmIdentifier names: id-Ed25519 or
/// id-X25519. The container's classified algorithm alone decides `crv`.
fn curve(alg: AlgId) -> Result<OkpCurve> {
    match alg {
        AlgId::Ed25519 => Ok(OkpCurve::Ed25519),
        AlgId::X25519 => Ok(OkpCurve::X25519),
        AlgId::Ec(_) | AlgId::RsaEncryption => Err(Error::InvalidKey("the key is not an OKP key")),
    }
}

/// Imports a SubjectPublicKeyInfo of an Ed25519 or X25519 public key.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "called by the PEM/DER facade (T08)")
)]
pub(crate) fn from_spki(parts: SpkiParts<'_>) -> Result<Jwk> {
    let _ = curve(parts.alg)?;
    Err(Error::InvalidKey("not implemented"))
}

/// Exports the public key of an Ed25519 or X25519 key as SPKI.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "called by the PEM/DER facade (T08)")
)]
pub(crate) fn to_spki(key: &OkpKey) -> Result<Zeroizing<Vec<u8>>> {
    let _ = key;
    Err(Error::InvalidKey("not implemented"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk::KeyMaterial;
    use crate::keys::der::fixtures;
    use crate::keys::spki;

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
            assert_same_key(&jwk, &jwk_fixture("rfc", &format!("{stem}.jwk.json")), &name);
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
}
