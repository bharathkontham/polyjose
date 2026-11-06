//! Ed25519 and X25519 keys (RFC 8037 §2) to and from PKCS#8 and SPKI
//! (RFC 8410 §3, §4, §7): parameters absent, and the private key as a
//! CurvePrivateKey OCTET STRING inside the PKCS#8 privateKey.

use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use super::der::{self, Reader, Writer};
use super::jwk_build;
use super::pkcs8;
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

/// `version` v1(0) of a OneAsymmetricKey without publicKey (RFC 5958 §2),
/// the only version exported (ADR 0018 §3).
const PKCS8_V1: u8 = 0;

/// Reads `CurvePrivateKey ::= OCTET STRING` (RFC 8410 §7), the whole
/// contents of the PKCS#8 privateKey OCTET STRING, so the key is
/// `04 20 ‖ 32 octets` inside `04 22`. RFC 8410 §7: "the private key is
/// wrapped in an OCTET STRING"; its value is the 32-octet Ed25519 seed
/// (RFC 8032 §5.1.5) or X25519 scalar (RFC 7748 §5), stored as is, never
/// clamped.
///
/// The key is copied only into the returned [`Zeroizing`] array; the
/// caller's buffer is zeroizing too (T02 contract).
fn curve_private_key(private_key: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let mut reader = Reader::new(private_key)?;
    let key = reader.octet_string()?;
    reader.finish()?;
    if key.len() != KEY_LEN {
        return Err(Error::InvalidKey("CurvePrivateKey is not 32 octets"));
    }
    let mut d = Zeroizing::new([0u8; KEY_LEN]);
    d.copy_from_slice(key);
    Ok(d)
}

/// The Ed25519 public key of the seed `d`: A = [s]B from SHA-512(`d`)
/// (RFC 8032 §5.1.5), computed by ed25519-dalek. The `SigningKey` is wiped
/// on drop (its `zeroize` feature).
fn ed25519_public(d: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    ed25519_dalek::SigningKey::from_bytes(d)
        .verifying_key()
        .to_bytes()
}

/// The X25519 public key of the scalar `d`: X25519(`d`, 9) (RFC 7748 §6.1;
/// x25519-dalek clamps the scalar as RFC 7748 §5 requires). The
/// `StaticSecret` the scalar is moved into is wiped on drop (its `zeroize`
/// feature).
fn x25519_public(d: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    let secret = x25519_dalek::StaticSecret::from(*d);
    x25519_dalek::PublicKey::from(&secret).to_bytes()
}

/// Imports a PKCS#8 OneAsymmetricKey (RFC 5958 §2) that `pkcs8::decode`
/// classified as id-Ed25519 or id-X25519 (RFC 8410 §3), as a private OKP
/// JWK (RFC 8037 §2): `crv` from the privateKeyAlgorithm, `d` the
/// CurvePrivateKey (RFC 8410 §7) and `x` its public key.
///
/// - **v1, no publicKey:** `x` is derived from `d`, by ed25519-dalek for
///   Ed25519 (RFC 8032 §5.1.5) or x25519-dalek for X25519 (RFC 7748 §6.1).
/// - **v2, with publicKey** (RFC 5958 §2; RFC 8410 §7, §10.3): the
///   publicKey must be 32 octets and the public key of `d` (ADR 0018 §3,
///   ADR 0043 §3).
///   - Ed25519: the embedded key is passed as `x` together with `d` to
///     [`jwk_build::okp_jwk`], whose [`Jwk::from_object`] rejects a `d` that
///     does not derive `x`, in constant time (ADR 0043 §3), and an `x` with
///     a torsion component (ADR 0043 §1). The derivation is not repeated
///     here.
///   - X25519: `jwk.rs` does not check that `d` derives `x` yet (feature
///     0003 adds it with X25519 key agreement), so the derived key is
///     compared with the embedded one here, with `subtle`'s constant-time
///     equality since it is computed from the secret. That check becomes
///     redundant, but harmless, once `jwk.rs` has it (ADR 0043 §3). The
///     comparison is of the octets: an embedded key that is a non-canonical
///     encoding of the derived u-coordinate (RFC 7748 §5) is rejected too.
///
/// Attributes have already been checked and are ignored (ADR 0018 §3); the
/// JWK has no `alg` member.
///
/// # Errors
///
/// [`Error::InvalidKey`] if the privateKey is not a 32-octet
/// CurvePrivateKey, the publicKey is not 32 octets or not the public key
/// of `d`, the key fails JWK validation, or `parts` is not an OKP key.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "called by the PEM/DER facade (T08)")
)]
pub(crate) fn from_pkcs8(parts: Pkcs8Parts<'_>) -> Result<Jwk> {
    let crv = curve(parts.alg)?;
    let d = curve_private_key(parts.private_key)?;
    let embedded: Option<[u8; KEY_LEN]> = parts
        .public_key
        .map(|key| {
            key.try_into()
                .map_err(|_| Error::InvalidKey("PKCS#8 publicKey is not 32 octets"))
        })
        .transpose()?;
    let x = match crv {
        // Checked against `d` by `Jwk::from_object` (ADR 0043 §3).
        OkpCurve::Ed25519 => embedded.unwrap_or_else(|| ed25519_public(&d)),
        OkpCurve::X25519 => {
            let derived = x25519_public(&d);
            if embedded.is_some_and(|embedded| !bool::from(derived[..].ct_eq(&embedded[..]))) {
                return Err(Error::InvalidKey(
                    "X25519 PKCS#8 publicKey does not match the private key",
                ));
            }
            derived
        }
    };
    jwk_build::okp_jwk(crv, &x, Some(d.as_slice()), None)
}

/// Exports an Ed25519 or X25519 private key as a DER PKCS#8 v1
/// PrivateKeyInfo without attributes or publicKey (RFC 5958 §2,
/// RFC 8410 §7): `d` as the CurvePrivateKey OCTET STRING inside the
/// privateKey OCTET STRING. That is the layout of RFC 8410 §10.3's first
/// key and of OpenSSL 4 (ADR 0018 §3). Every buffer holding `d` is
/// zeroizing.
///
/// # Errors
///
/// [`Error::InvalidKey`]`("private key required")` for a public key.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "called by the PEM/DER facade (T08)")
)]
pub(crate) fn to_pkcs8(key: &OkpKey) -> Result<Zeroizing<Vec<u8>>> {
    let d = key.d().ok_or(Error::InvalidKey("private key required"))?;
    let mut writer = Writer::new(der::encoded_len(d.len()))?;
    writer.element(der::OCTET_STRING, d)?;
    let curve_private_key = writer.finish()?;
    pkcs8::encode(&Pkcs8Parts {
        version: PKCS8_V1,
        alg: alg_id(key.crv()),
        private_key: &curve_private_key,
        public_key: None,
    })
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
    use crate::jwk::{EcCurve, KeyMaterial};
    use crate::keys::der::fixtures;
    use crate::keys::pem;
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

    /// The PKCS#8 negative vectors on an RFC 8037 A.1 or RFC 8410 §10.3
    /// base (N20–N27), end to end through `pkcs8::decode` and this mapper,
    /// fail with their manifest code. N20–N24 are container errors (T02);
    /// N25 (a 31-octet CurvePrivateKey), N26 (a CurvePrivateKey that is
    /// not an OCTET STRING, RFC 8410 §7) and N27 (a v2 publicKey that is
    /// not the key of `d`, ADR 0043 §3) are rejected here and in `jwk.rs`.
    #[test]
    fn okp_pkcs8_negative_vectors_fail_with_the_manifest_code() {
        let vectors: Vec<_> = fixtures::negatives()
            .into_iter()
            .filter(|n| n.id.starts_with("N2"))
            .collect();
        let ids: Vec<&str> = vectors.iter().map(|n| n.id.as_str()).collect();
        assert_eq!(
            ids,
            ["N20", "N21", "N22", "N23", "N24", "N25", "N26", "N27"]
        );
        for vector in vectors {
            let err = import_pkcs8(&fixtures::load("negative", &vector.file)).unwrap_err();
            assert_eq!(err.code(), vector.expect, "{}: {err:?}", vector.id);
        }
        // The three this task owns fail for the reason named in the
        // manifest, not on an earlier container check.
        let reason = |id: &str| import_pkcs8(&fixtures::negative(id)).unwrap_err();
        assert_eq!(
            reason("N25"),
            Error::InvalidKey("CurvePrivateKey is not 32 octets")
        );
        assert!(
            matches!(reason("N26"), Error::InvalidKey(detail) if detail.contains("tag")),
            "{:?}",
            reason("N26")
        );
        // N27's flipped octet leaves no valid Ed25519 point: `jwk.rs`
        // rejects it before the pair check, which is tested below with a
        // valid point.
        assert!(
            matches!(reason("N27"), Error::InvalidKey(detail) if detail.starts_with("Ed25519")),
            "{:?}",
            reason("N27")
        );
    }

    /// Ed448 and X448 (RFC 8410 §3) are out of scope (ADR 0006): OpenSSL's
    /// keys fail with `UnsupportedAlgorithm` end to end, through T02's
    /// classification, and so does an encrypted Ed25519 PKCS#8 (RFC 5958
    /// §3, ADR 0018 §4).
    #[test]
    fn ed448_x448_and_encrypted_keys_are_unsupported() {
        let names = fixtures::files("openssl", |name| {
            name.starts_with("reject-ed448-")
                || name.starts_with("reject-x448-")
                || name.starts_with("reject-ed25519-")
        });
        assert_eq!(names.len(), 4, "{names:?}");
        for name in names {
            let der = fixtures::load("openssl", &name);
            let result = if name.contains("spki") {
                import_spki(&der)
            } else {
                import_pkcs8(&der)
            };
            assert_eq!(result.unwrap_err(), Error::UnsupportedAlgorithm, "{name}");
        }
    }

    /// RFC 8410 §4, RFC 8032 §5.1.5, RFC 7748 §5: an OKP subjectPublicKey
    /// is exactly 32 octets.
    #[test]
    fn spki_keys_that_are_not_32_octets_are_rejected() {
        for alg in [AlgId::Ed25519, AlgId::X25519] {
            for len in [0, 1, 31, 33, 57, 64] {
                let key = vec![0x09; len];
                let der = spki::encode(&SpkiParts {
                    alg,
                    subject_public_key: &key,
                })
                .unwrap();
                assert_eq!(
                    import_spki(&der).unwrap_err(),
                    Error::InvalidKey("OKP subjectPublicKey is not 32 octets"),
                    "{alg:?} {len}"
                );
            }
        }
    }

    /// The RFC 8037 A.6 X25519 key (RFC 7748 §6.1 Alice) as a v2 PKCS#8
    /// with `public_key` (RFC 5958 §2), built from the committed v1 DER.
    fn x25519_v2(public_key: &[u8]) -> Zeroizing<Vec<u8>> {
        let v1 = fixtures::load("rfc", "rfc8037-a6-x25519-pkcs8.der");
        let parts = pkcs8::decode(&v1).unwrap();
        pkcs8::encode(&Pkcs8Parts {
            version: 1,
            public_key: Some(public_key),
            ..parts
        })
        .unwrap()
    }

    /// ADR 0043 §3, ADR 0018 §3: a v2 X25519 publicKey must be X25519(d, 9)
    /// (RFC 7748 §6.1). `jwk.rs` does not check X25519 pairs yet, so this
    /// mapper does: Alice's own public key is accepted, Bob's, one with a
    /// flipped bit, and one with the high bit set (which RFC 7748 §5 masks
    /// when a u-coordinate is used, so it is a different encoding) are not.
    #[test]
    fn x25519_v2_public_key_must_be_the_key_of_d() {
        let jwk = jwk_fixture("rfc", "rfc8037-a6-x25519-pkcs8.jwk.json");
        let alice = okp(&jwk).x().to_vec();
        let accepted = import_pkcs8(&x25519_v2(&alice)).unwrap();
        assert_same_key(&accepted, &jwk, "v2 with Alice's public key");
        // Exported as v1, without the publicKey (ADR 0018 §3).
        assert_eq!(
            *to_pkcs8(okp(&accepted)).unwrap(),
            fixtures::load("rfc", "rfc8037-a6-x25519-pkcs8.der")
        );

        let bob = okp(&jwk_fixture("rfc", "rfc8037-a6-x25519-bob-spki.jwk.json"))
            .x()
            .to_vec();
        let mut flipped = alice.clone();
        flipped[0] ^= 0x01;
        let mut high_bit = alice.clone();
        high_bit[31] |= 0x80;
        assert_ne!(high_bit, alice);
        for (what, key) in [("Bob's", bob), ("flipped", flipped), ("high bit", high_bit)] {
            assert_eq!(
                import_pkcs8(&x25519_v2(&key)).unwrap_err(),
                Error::InvalidKey("X25519 PKCS#8 publicKey does not match the private key"),
                "{what}"
            );
        }
    }

    /// RFC 5958 §2 and RFC 8410 §7: a v2 publicKey is the 32-octet key; any
    /// other length is rejected before it is compared, for both curves.
    #[test]
    fn v2_public_keys_that_are_not_32_octets_are_rejected() {
        let ed25519 = fixtures::load("rfc", "rfc8037-a1-ed25519-pkcs8.der");
        for len in [0, 31, 33, 64] {
            let key = vec![0x5A; len];
            let ed = pkcs8::encode(&Pkcs8Parts {
                version: 1,
                public_key: Some(&key),
                ..pkcs8::decode(&ed25519).unwrap()
            })
            .unwrap();
            for der in [&ed[..], &x25519_v2(&key)[..]] {
                assert_eq!(
                    import_pkcs8(der).unwrap_err(),
                    Error::InvalidKey("PKCS#8 publicKey is not 32 octets"),
                    "{len}"
                );
            }
        }
    }

    /// RFC 8410 §7: the privateKey is exactly one CurvePrivateKey OCTET
    /// STRING (X.690 §8.1.1: nothing after it), of 32 octets.
    #[test]
    fn malformed_curve_private_keys_are_rejected() {
        let a1 = fixtures::load("rfc", "rfc8037-a1-ed25519-pkcs8.der");
        let parts = pkcs8::decode(&a1).unwrap();
        let seed = &parts.private_key[2..];
        let mut trailing = parts.private_key.to_vec();
        trailing.extend_from_slice(&[0x05, 0x00]);
        let mut long = vec![0x04, 0x21];
        long.extend_from_slice(seed);
        long.push(0x00);
        let cases: [(&str, &[u8]); 5] = [
            ("empty", &[]),
            ("bare seed", seed),
            ("trailing NULL", &trailing),
            ("33 octets", &long),
            ("empty OCTET STRING", &[0x04, 0x00]),
        ];
        for (what, private_key) in cases {
            let err = from_pkcs8(Pkcs8Parts {
                private_key,
                ..parts
            })
            .unwrap_err();
            assert!(matches!(err, Error::InvalidKey(_)), "{what}: {err:?}");
        }
    }

    /// The mappers take only OKP containers; T08 dispatches on the
    /// classified algorithm, and anything else is an error, not a panic.
    #[test]
    fn non_okp_containers_are_rejected() {
        let a1 = fixtures::load("rfc", "rfc8037-a1-ed25519-pkcs8.der");
        let parts = pkcs8::decode(&a1).unwrap();
        let spki_der = fixtures::load("rfc", "rfc8037-a2-ed25519-spki.der");
        let public = spki::decode(&spki_der).unwrap();
        for alg in [AlgId::Ec(EcCurve::P256), AlgId::RsaEncryption] {
            let not_okp = Error::InvalidKey("the key is not an OKP key");
            assert_eq!(
                from_pkcs8(Pkcs8Parts { alg, ..parts }).unwrap_err(),
                not_okp
            );
            assert_eq!(from_spki(SpkiParts { alg, ..public }).unwrap_err(), not_okp);
        }
    }

    /// The plan's export table (T08): a public key has no PKCS#8 encoding.
    #[test]
    fn a_public_key_has_no_pkcs8_export() {
        let jwk = jwk_fixture("rfc", "rfc8037-a2-ed25519-spki.jwk.json");
        assert_eq!(
            to_pkcs8(okp(&jwk)).unwrap_err(),
            Error::InvalidKey("private key required")
        );
    }

    /// ADR 0043 §3, ADR 0018 §3: the RFC 8410 §10.3 v2 key with the valid
    /// RFC 8037 A.1 public key in place of its own is rejected by
    /// `Jwk::from_object` (in constant time, `ed25519_private_matches`).
    #[test]
    fn ed25519_v2_public_key_of_another_key_is_rejected() {
        let v2 = fixtures::load("rfc", "rfc8410-10.3-ed25519-pkcs8-v2-attr-pub.pem");
        let other = okp(&jwk_fixture("rfc", "rfc8037-a2-ed25519-spki.jwk.json"))
            .x()
            .to_vec();
        let der = pkcs8::encode(&Pkcs8Parts {
            public_key: Some(&other),
            ..pkcs8::decode(&v2).unwrap()
        })
        .unwrap();
        assert_eq!(
            import_pkcs8(&der).unwrap_err(),
            Error::InvalidKey("Ed25519 private key d does not match x")
        );
    }

    /// Wycheproof `ed25519_test.json` tcId 160 public key 15deb307…b2c23b
    /// (`MixedOrderPublicKey`): canonical, not of small order, with a
    /// torsion component (the same vector as `jws/eddsa.rs`).
    const MIXED_ORDER: &str = "Fd6zBynrPkZciPEbV9DI026w9nDDsi0vgOpgSe6ywjs";

    /// ADR 0043 §1: an Ed25519 SPKI whose key has a torsion component is
    /// rejected through `Jwk::from_object`. The same 32 octets are a valid
    /// X25519 key, where torsion is neutralised by clamping (ADR 0043 §2).
    #[test]
    fn ed25519_spki_with_a_torsion_component_is_rejected() {
        let key = crate::util::b64url_decode(MIXED_ORDER).unwrap();
        let spki_of = |alg| {
            spki::encode(&SpkiParts {
                alg,
                subject_public_key: &key,
            })
            .unwrap()
        };
        assert_eq!(
            import_spki(&spki_of(AlgId::Ed25519)).unwrap_err(),
            Error::InvalidKey("Ed25519 public key is invalid")
        );
        let x25519 = import_spki(&spki_of(AlgId::X25519)).unwrap();
        assert_eq!(okp(&x25519).crv(), OkpCurve::X25519);
        assert_eq!(okp(&x25519).x(), key.as_slice());
    }

    /// `der` with its one RFC 8410 §3 AlgorithmIdentifier template `from`
    /// replaced by `to` (both 7 octets, so no length changes).
    fn relabel(der: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
        assert_eq!(from.len(), to.len());
        let at = der
            .windows(from.len())
            .position(|window| window == from)
            .expect("the template is in the DER");
        let mut out = der.to_vec();
        out[at..at + to.len()].copy_from_slice(to);
        out
    }

    /// RFC 8410 §3: the AlgorithmIdentifier alone decides `crv`. The same
    /// 32 private octets relabelled from id-Ed25519 to id-X25519 (or back)
    /// import as the other curve, with `x` derived by that curve's
    /// primitive (RFC 8032 §5.1.5, RFC 7748 §6.1); a key is never accepted
    /// under the curve it is not labelled with. A v2 Ed25519 key relabelled
    /// X25519 fails, since its Ed25519 publicKey is not X25519(d, 9).
    #[test]
    fn swapped_algorithm_identifiers_change_crv_and_x() {
        use crate::keys::oid::{ALG_ED25519, ALG_X25519};
        let cases = [
            (
                "rfc8037-a1-ed25519-pkcs8.der",
                OkpCurve::Ed25519,
                ALG_ED25519,
                ALG_X25519,
            ),
            (
                "rfc8037-a6-x25519-pkcs8.der",
                OkpCurve::X25519,
                ALG_X25519,
                ALG_ED25519,
            ),
        ];
        for (name, crv, from, to) in cases {
            let der = fixtures::load("rfc", name);
            let original = import_pkcs8(&der).unwrap();
            assert_eq!(okp(&original).crv(), crv, "{name}");
            let swapped = import_pkcs8(&relabel(&der, from, to)).unwrap();
            let (original, swapped) = (okp(&original), okp(&swapped));
            assert_ne!(swapped.crv(), crv, "{name}");
            assert_eq!(swapped.d(), original.d(), "{name}");
            assert_ne!(swapped.x(), original.x(), "{name}");
            let d: &[u8; KEY_LEN] = swapped.d().unwrap().try_into().unwrap();
            let expected = match swapped.crv() {
                OkpCurve::Ed25519 => ed25519_public(d),
                OkpCurve::X25519 => x25519_public(d),
            };
            assert_eq!(swapped.x(), expected, "{name}");
        }

        let v2 = fixtures::load("rfc", "rfc8410-10.3-ed25519-pkcs8-v2-attr-pub.pem");
        assert_eq!(
            import_pkcs8(&relabel(&v2, ALG_ED25519, ALG_X25519)).unwrap_err(),
            Error::InvalidKey("X25519 PKCS#8 publicKey does not match the private key")
        );

        // SPKI: the same octets under the other label are read as that
        // curve's key. Ed25519's A.2 key is a valid X25519 key (any 32
        // octets are, RFC 7748 §5); Alice's X25519 key (RFC 7748 §6.1) is
        // no valid Ed25519 point (RFC 8032 §5.1.3), so it is rejected.
        let ed = fixtures::load("rfc", "rfc8037-a2-ed25519-spki.der");
        let as_x25519 = import_spki(&relabel(&ed, ALG_ED25519, ALG_X25519)).unwrap();
        assert_eq!(okp(&as_x25519).crv(), OkpCurve::X25519);
        let x = fixtures::load("rfc", "rfc8037-a6-x25519-spki.der");
        assert_eq!(
            import_spki(&relabel(&x, ALG_X25519, ALG_ED25519)).unwrap_err(),
            Error::InvalidKey("Ed25519 public key is invalid")
        );
    }

    /// The private key is read only into a `Zeroizing<[u8; 32]>`.
    #[test]
    fn the_private_key_is_held_in_a_zeroizing_array() {
        let der = fixtures::load("rfc", "rfc8037-a1-ed25519-pkcs8.der");
        let parts = pkcs8::decode(&der).unwrap();
        let d: Zeroizing<[u8; KEY_LEN]> = curve_private_key(parts.private_key).unwrap();
        assert_eq!(d.as_slice(), &parts.private_key[2..]);
    }

    /// Errors carry no key bytes (ADR 0007, ADR 0018 §4): a marker used as
    /// the private and public key of rejected containers appears in no
    /// error's `Display` or `Debug`, in any encoding.
    #[test]
    fn errors_carry_no_key_bytes() {
        use crate::keys::oid::ALG_ED25519;
        const MARKER: &[u8; KEY_LEN] = b"POLYJOSE-MARKER-0123456789-ABCDE";
        let ed25519_other = okp(&jwk_fixture("rfc", "rfc8037-a2-ed25519-spki.jwk.json"))
            .x()
            .to_vec();
        let curve_private_key = |key: &[u8]| {
            let mut out = vec![0x04, u8::try_from(key.len()).unwrap()];
            out.extend_from_slice(key);
            out
        };
        let pkcs8_of = |alg, private: &[u8], public: Option<&[u8]>| {
            let private_key = curve_private_key(private);
            pkcs8::encode(&Pkcs8Parts {
                version: u8::from(public.is_some()),
                alg,
                private_key: &private_key,
                public_key: public,
            })
            .unwrap()
        };
        let spki_of = |key: &[u8]| {
            spki::encode(&SpkiParts {
                alg: AlgId::Ed25519,
                subject_public_key: key,
            })
            .unwrap()
        };
        let mut long = MARKER.to_vec();
        long.push(b'!');
        let errors = [
            import_pkcs8(&pkcs8_of(AlgId::X25519, MARKER, Some(MARKER))).unwrap_err(),
            import_pkcs8(&pkcs8_of(AlgId::Ed25519, MARKER, Some(&ed25519_other))).unwrap_err(),
            import_pkcs8(&pkcs8_of(AlgId::Ed25519, MARKER, Some(MARKER))).unwrap_err(),
            import_pkcs8(&pkcs8_of(AlgId::Ed25519, &MARKER[..31], None)).unwrap_err(),
            import_pkcs8(&pkcs8_of(AlgId::X25519, MARKER, Some(&long))).unwrap_err(),
            import_spki(&spki_of(MARKER)).unwrap_err(),
            import_spki(&spki_of(&long)).unwrap_err(),
            import_pkcs8(&relabel(
                &pkcs8_of(AlgId::Ed25519, MARKER, None),
                ALG_ED25519,
                &[0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x71],
            ))
            .unwrap_err(),
        ];
        let hex = |bytes: &[u8]| -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() };
        let forbidden = [
            "MARKER".to_owned(),
            hex(&MARKER[..8]),
            hex(&MARKER[..8]).to_uppercase(),
            crate::util::b64url_encode(&MARKER[..9]),
            format!("{:?}", &MARKER[..4]),
        ];
        for err in errors {
            for text in [format!("{err}"), format!("{err:?}")] {
                for needle in &forbidden {
                    assert!(!text.contains(needle.as_str()), "{text} contains {needle}");
                }
            }
        }
    }

    mod properties {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            /// Any 32 octets are an Ed25519 seed and an X25519 scalar
            /// (RFC 8032 §5.1.5, RFC 7748 §5). Each private JWK exports
            /// to exactly the RFC 8410 §10.3 v1 layout around `d` and the
            /// §10.1 SPKI layout around `x`, and both import back to the
            /// same key; a v2 key carrying the derived `x` does too.
            #[test]
            fn every_key_round_trips(d in any::<[u8; KEY_LEN]>()) {
                for (crv, oid_last) in [(OkpCurve::Ed25519, 0x70), (OkpCurve::X25519, 0x6E)] {
                    let x = match crv {
                        OkpCurve::Ed25519 => ed25519_public(&d),
                        OkpCurve::X25519 => x25519_public(&d),
                    };
                    let jwk = jwk_build::okp_jwk(crv, &x, Some(&d), None).unwrap();
                    let key = okp(&jwk);

                    let pkcs8_der = to_pkcs8(key).unwrap();
                    let mut expected = vec![
                        0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65,
                        oid_last, 0x04, 0x22, 0x04, 0x20,
                    ];
                    expected.extend_from_slice(&d);
                    prop_assert_eq!(&pkcs8_der[..], &expected[..]);
                    let back = import_pkcs8(&pkcs8_der).unwrap();
                    prop_assert_eq!(&*back.to_json(), &*jwk.to_json());

                    let v2 = pkcs8::encode(&Pkcs8Parts {
                        version: 1,
                        public_key: Some(&x),
                        ..pkcs8::decode(&pkcs8_der).unwrap()
                    })
                    .unwrap();
                    let back = import_pkcs8(&v2).unwrap();
                    prop_assert_eq!(&*back.to_json(), &*jwk.to_json());

                    let spki_der = to_spki(key).unwrap();
                    let mut expected = vec![
                        0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, oid_last, 0x03, 0x21,
                        0x00,
                    ];
                    expected.extend_from_slice(&x);
                    prop_assert_eq!(&spki_der[..], &expected[..]);
                    let public = import_spki(&spki_der).unwrap();
                    prop_assert_eq!(&*public.to_json(), &*jwk.to_public().unwrap().to_json());
                }
            }
        }
    }
}
