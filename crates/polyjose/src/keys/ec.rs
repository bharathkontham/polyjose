//! EC keys on P-256, P-384, P-521 and secp256k1 (RFC 7518 §6.2, RFC 8812
//! §3.1) to and from SPKI (RFC 5480 §2.1.1 namedCurve, §2.2 uncompressed or
//! compressed points) and PKCS#8, whose privateKey holds an RFC 5915
//! ECPrivateKey (RFC 5915 §1; without `[0]`, per erratum 5008).
//!
//! # Validation
//!
//! Points and scalars are decoded and checked only by the curve crates
//! (`p256`, `p384`, `p521`, `k256`), never by polyjose arithmetic:
//!
//! - an embedded point (SPKI subjectPublicKey, SEC1 `[1]`, PKCS#8 v2
//!   `[1]`) by `PublicKey::from_sec1_bytes`, which decompresses a
//!   compressed point and rejects the identity and points off the curve;
//! - a private key without an embedded point by `SecretKey::from_bytes`,
//!   which range-checks d ∈ [1, n − 1] in constant time, and
//!   `SecretKey::public_key`, which derives Q = d·G (SEC 1 v2 §3.2.1).
//!
//! Every key is then built by `keys::jwk_build::ec_jwk`, so it passes the
//! full [`Jwk::from_object`] validation: exact lengths (RFC 7518 §6.2.1.2,
//! §6.2.2.1), the point on its curve (ADR 0041 §4), d in range, and d·G =
//! (`x`, `y`) compared in constant time (ADR 0043 §3). An embedded point
//! that is not the private key's own is rejected there, not here.
//!
//! # Secrets
//!
//! The private scalar is only ever borrowed: from the caller's (zeroizing)
//! DER buffer on import, from [`EcKey::d`] on export. The curve crate's
//! `SecretKey` wipes itself on drop, and every encoding is written into a
//! [`Zeroizing`] buffer. Errors are static strings with no input octet.

use p256::elliptic_curve::sec1::{FromSec1Point, ModulusSize, ToSec1Point};
use p256::elliptic_curve::{AffinePoint, CurveArithmetic, FieldBytesSize, PublicKey};
use zeroize::Zeroizing;

use super::jwk_build;
use super::spki;
use super::types::{AlgId, SpkiParts};
use crate::error::{Error, Result};
use crate::jwk::{EcCurve, EcKey, Jwk};

/// Detail for an EC point that the curve crate does not accept.
const POINT_INVALID: &str = "EC point is invalid";

/// The affine coordinates of a valid point, each the curve's full
/// coordinate length (RFC 7518 §6.2.1.2–§6.2.1.3). Public values.
struct Coordinates {
    x: Vec<u8>,
    y: Vec<u8>,
}

/// Decodes the SEC1 point `octets` of `crv` (SEC 1 v2 §2.3.4) as RFC 5480
/// §2.2 allows: "The uncompressed form is indicated by 0x04 and the
/// compressed form is indicated by either 0x02 or 0x03 … The public key MUST
/// be rejected if any other value is included in the first octet." So the
/// identity (0x00), the hybrid forms (0x06, 0x07) and the compact form
/// (0x05), which the curve crates would decode, fail here first. The curve
/// crate checks the length for the curve, decompresses, and rejects points
/// off the curve and the identity.
fn decode_point(crv: EcCurve, octets: &[u8]) -> Result<Coordinates> {
    if !matches!(octets.first(), Some(0x02..=0x04)) {
        return Err(Error::InvalidKey(POINT_INVALID));
    }
    match crv {
        EcCurve::P256 => decode_point_on::<p256::NistP256>(octets),
        EcCurve::P384 => decode_point_on::<p384::NistP384>(octets),
        EcCurve::P521 => decode_point_on::<p521::NistP521>(octets),
        EcCurve::Secp256k1 => decode_point_on::<k256::Secp256k1>(octets),
    }
}

/// See [`decode_point`]: `PublicKey::from_sec1_bytes` on the curve `C`.
fn decode_point_on<C>(octets: &[u8]) -> Result<Coordinates>
where
    C: CurveArithmetic,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: ModulusSize,
{
    let public =
        PublicKey::<C>::from_sec1_bytes(octets).map_err(|_| Error::InvalidKey(POINT_INVALID))?;
    coordinates(&public)
}

/// The affine coordinates of `public`, from its uncompressed SEC1
/// encoding (SEC 1 v2 §2.3.3).
fn coordinates<C>(public: &PublicKey<C>) -> Result<Coordinates>
where
    C: CurveArithmetic,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: ModulusSize,
{
    let point = public.to_sec1_point(false);
    // A PublicKey is never the identity, the only point without
    // coordinates.
    match (point.x(), point.y()) {
        (Some(x), Some(y)) => Ok(Coordinates {
            x: x.to_vec(),
            y: y.to_vec(),
        }),
        _ => Err(Error::InvalidKey(POINT_INVALID)),
    }
}

/// The uncompressed SEC1 point of `key`: `0x04 ‖ x ‖ y` (SEC 1 v2 §2.3.3),
/// the only form polyjose writes (RFC 5480 §2.2 "MUST be supported";
/// ADR 0018 §3). `x` and `y` were validated as full-length coordinates of
/// a point on the curve when the JWK was built.
fn uncompressed_point(key: &EcKey) -> Vec<u8> {
    let mut point = Vec::with_capacity(1 + key.x().len() + key.y().len());
    point.push(0x04);
    point.extend_from_slice(key.x());
    point.extend_from_slice(key.y());
    point
}

/// The curve of an id-ecPublicKey AlgorithmIdentifier (RFC 5480 §2.1.1).
/// The facade dispatches on the algorithm, so anything else is a caller
/// error, reported as `InvalidKey`.
fn ec_curve(alg: AlgId) -> Result<EcCurve> {
    match alg {
        AlgId::Ec(crv) => Ok(crv),
        AlgId::Ed25519 | AlgId::X25519 | AlgId::RsaEncryption => {
            Err(Error::InvalidKey("not an EC key"))
        }
    }
}

/// Imports an EC public key from a decoded SubjectPublicKeyInfo
/// (RFC 5280 §4.1.2.7) whose algorithm is id-ecPublicKey with a namedCurve
/// (RFC 5480 §2.1.1). The subjectPublicKey is the SEC1 point, uncompressed
/// or compressed (RFC 5480 §2.2), and becomes a public JWK with `crv`, `x`
/// and `y` (RFC 7518 §6.2.1) and no `alg`.
///
/// # Errors
///
/// [`Error::InvalidKey`] if `parts.alg` is not an EC curve, or the point
/// has another first octet than 0x02/0x03/0x04, has the wrong length for
/// the curve, is not on the curve or is the identity.
#[cfg_attr(not(test), expect(dead_code, reason = "called by the facade (T08)"))]
pub(crate) fn from_spki(parts: SpkiParts<'_>) -> Result<Jwk> {
    let crv = ec_curve(parts.alg)?;
    let point = decode_point(crv, parts.subject_public_key)?;
    jwk_build::ec_jwk(crv, &point.x, &point.y, None, None)
}

/// Exports the public part of `key` as a DER SubjectPublicKeyInfo:
/// id-ecPublicKey with the key's namedCurve (RFC 5480 §2.1.1) and the
/// uncompressed point (RFC 5480 §2.2; ADR 0018 §3), byte for byte what
/// OpenSSL 4 writes. A private key exports its public part.
///
/// # Errors
///
/// None in practice; [`Error::InvalidKey`] only if the DER writer refuses.
#[cfg_attr(not(test), expect(dead_code, reason = "called by the facade (T08)"))]
pub(crate) fn to_spki(key: &EcKey) -> Result<Zeroizing<Vec<u8>>> {
    let point = uncompressed_point(key);
    spki::encode(&SpkiParts {
        alg: AlgId::Ec(key.crv()),
        subject_public_key: &point,
    })
}

#[cfg(test)]
mod tests {
    use super::super::der::fixtures;
    use super::*;
    use crate::jwk::KeyMaterial;

    /// The four curves and their fixture names.
    const CURVES: [(&str, EcCurve); 4] = [
        ("p256", EcCurve::P256),
        ("p384", EcCurve::P384),
        ("p521", EcCurve::P521),
        ("secp256k1", EcCurve::Secp256k1),
    ];

    /// The JWK of a committed `.jwk.json` file.
    fn expected(dir: &str, file: &str) -> Jwk {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/keys")
            .join(dir)
            .join(file);
        Jwk::from_json(&std::fs::read(&path).unwrap()).unwrap()
    }

    fn assert_same(actual: &Jwk, expected: &Jwk, what: &str) {
        assert_eq!(*actual.to_json(), *expected.to_json(), "{what}");
    }

    fn ec_key(jwk: &Jwk) -> &EcKey {
        match jwk.material() {
            KeyMaterial::Ec(key) => key,
            _ => panic!("an EC key"),
        }
    }

    fn import_spki(der: &[u8]) -> Result<Jwk> {
        spki::decode(der).and_then(from_spki)
    }

    mod spki_form {
        use super::*;

        #[test]
        fn rfc_spki_vectors_round_trip() {
            // RFC 7517 App. A.1 (built, research.md §8) and RFC 7468 §13
            // Fig. 15 (P-384, verbatim).
            for (file, json) in [
                (
                    "rfc7517-a1-ec-p256-spki.der",
                    "rfc7517-a1-ec-p256-spki.jwk.json",
                ),
                (
                    "rfc7468-fig15-p384-spki.pem",
                    "rfc7468-fig15-p384-spki.jwk.json",
                ),
            ] {
                let der = fixtures::load("rfc", file);
                let jwk = import_spki(&der).unwrap();
                assert!(jwk.is_public(), "{file}");
                assert_same(&jwk, &expected("rfc", json), file);
                assert_eq!(*to_spki(ec_key(&jwk)).unwrap(), der, "{file}");
            }
        }

        #[test]
        fn openssl_spki_round_trips_and_compressed_exports_uncompressed() {
            for (name, _) in CURVES {
                let der = fixtures::load("openssl", &format!("ec-{name}-spki.der"));
                let want = expected("openssl/expected", &format!("ec-{name}-spki.jwk.json"));
                let jwk = import_spki(&der).unwrap();
                assert_same(&jwk, &want, name);
                assert_eq!(*to_spki(ec_key(&jwk)).unwrap(), der, "{name}");

                // RFC 5480 §2.2: compressed MAY be read; uncompressed is
                // what polyjose writes (ADR 0018 §3).
                let compressed =
                    fixtures::load("openssl", &format!("ec-{name}-spki-compressed.pem"));
                let jwk = import_spki(&compressed).unwrap();
                assert_same(&jwk, &want, name);
                assert_eq!(*to_spki(ec_key(&jwk)).unwrap(), der, "{name}");
            }
        }

        #[test]
        fn bad_points_are_invalid() {
            // N31 off-curve, N34 short, N35 hybrid 0x06 (RFC 5480 §2.2
            // MUST NOT), N36 identity.
            for id in ["N31", "N34", "N35", "N36"] {
                let result = import_spki(&fixtures::negative(id));
                assert!(
                    matches!(result, Err(Error::InvalidKey(_))),
                    "{id}: {:?}",
                    result.err()
                );
            }
        }

        /// The SPKI of `point` under the AlgorithmIdentifier of `crv`.
        fn spki_of(crv: EcCurve, point: &[u8]) -> Vec<u8> {
            spki::encode(&SpkiParts {
                alg: AlgId::Ec(crv),
                subject_public_key: point,
            })
            .unwrap()
            .to_vec()
        }

        #[test]
        fn only_the_rfc5480_first_octets_are_accepted() {
            // RFC 5480 §2.2: "The public key MUST be rejected if any other
            // value is included in the first octet." The compact form
            // (0x05 ‖ x), which the curve crates can decode, and 0x07.
            let der = fixtures::load("openssl", "ec-p256-spki.der");
            let jwk = import_spki(&der).unwrap();
            let key = ec_key(&jwk);
            for tag in [0x00, 0x01, 0x05, 0x07, 0xFF] {
                let mut point = vec![tag];
                point.extend_from_slice(key.x());
                assert_eq!(
                    import_spki(&spki_of(EcCurve::P256, &point)).unwrap_err(),
                    Error::InvalidKey(POINT_INVALID),
                    "{tag:#04x}"
                );
            }
            assert_eq!(
                import_spki(&spki_of(EcCurve::P256, &[])).unwrap_err(),
                Error::InvalidKey(POINT_INVALID)
            );
        }

        #[test]
        fn a_point_for_another_curve_size_is_invalid() {
            // A compressed and an uncompressed P-256 point under the P-384
            // and P-521 AlgorithmIdentifiers, and a P-384 point under P-256.
            let p256 = fixtures::load("openssl", "ec-p256-spki-compressed.pem");
            let p256_point = spki::decode(&p256).unwrap().subject_public_key.to_vec();
            let p384 = fixtures::load("openssl", "ec-p384-spki.der");
            let p384_point = spki::decode(&p384).unwrap().subject_public_key.to_vec();
            let p256_full = fixtures::load("openssl", "ec-p256-spki.der");
            let p256_uncompressed = spki::decode(&p256_full)
                .unwrap()
                .subject_public_key
                .to_vec();
            for (crv, point) in [
                (EcCurve::P384, &p256_point),
                (EcCurve::P521, &p256_point),
                (EcCurve::P384, &p256_uncompressed),
                (EcCurve::P256, &p384_point),
                (EcCurve::Secp256k1, &p384_point),
            ] {
                assert!(
                    matches!(import_spki(&spki_of(crv, point)), Err(Error::InvalidKey(_))),
                    "{crv:?}"
                );
            }
        }

        #[test]
        fn a_p256_point_is_not_a_secp256k1_point() {
            // Same sizes, different curve: the curve crate rejects it as
            // off the curve.
            let der = fixtures::load("openssl", "ec-p256-spki.der");
            let point = spki::decode(&der).unwrap().subject_public_key.to_vec();
            assert_eq!(
                import_spki(&spki_of(EcCurve::Secp256k1, &point)).unwrap_err(),
                Error::InvalidKey(POINT_INVALID)
            );
        }

        #[test]
        fn a_non_ec_algorithm_is_refused() {
            let der = fixtures::load("rfc", "rfc8037-a2-ed25519-spki.der");
            assert_eq!(
                import_spki(&der).unwrap_err(),
                Error::InvalidKey("not an EC key")
            );
        }

        #[test]
        fn unsupported_curves_and_explicit_parameters_are_unsupported() {
            // ADR 0018 §4 step 2: brainpoolP256r1 and specifiedCurve.
            for file in [
                "reject-ec-brainpoolp256r1-spki.pem",
                "reject-ec-p256-explicit-spki.pem",
            ] {
                let der = fixtures::load("openssl", file);
                assert_eq!(
                    import_spki(&der).unwrap_err(),
                    Error::UnsupportedAlgorithm,
                    "{file}"
                );
            }
        }

        #[test]
        fn a_private_key_exports_its_public_part() {
            let jwk = expected("openssl/expected", "ec-p384-sec1.jwk.json");
            let der = fixtures::load("openssl", "ec-p384-spki.der");
            assert_eq!(*to_spki(ec_key(&jwk)).unwrap(), der);
        }
    }
}
