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
use p256::elliptic_curve::{
    AffinePoint, CurveArithmetic, FieldBytes, FieldBytesSize, PublicKey, SecretKey,
};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use super::jwk_build;
use super::pkcs8;
use super::sec1::{self, EcPrivateKey};
use super::spki;
use super::types::{AlgId, Pkcs8Parts, SpkiParts};
use crate::error::{Error, Result};
use crate::jwk::{EcCurve, EcKey, Jwk};

/// Detail for an EC point that the curve crate does not accept.
const POINT_INVALID: &str = "EC point is invalid";
/// Detail for a privateKey that is not ⌈log₂(n)/8⌉ octets (RFC 5915 §3).
const PRIVATE_KEY_LENGTH: &str = "EC privateKey has the wrong length for the curve";
/// Detail for a private scalar outside [1, n − 1] (SEC 1 v2 §3.2.1).
const SCALAR_INVALID: &str = "EC private key d is out of range";
/// Detail for exporting a public key in a private-key format.
const NOT_PRIVATE: &str = "EC key has no private part";

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

/// The private JWK of the scalar `d` on `crv`, with the embedded public
/// point if the container has one (RFC 5915 §3 `[1]`, RFC 5958 §2 `[1]`).
///
/// - `d` must be ⌈log₂(n)/8⌉ octets (RFC 5915 §3), which for all four
///   curves is the coordinate length the JWK `d` needs (RFC 7518
///   §6.2.2.1).
/// - With an embedded point, the point is decoded by the curve crate
///   ([`decode_point`]; it may be compressed) and passed with `d` to
///   `jwk_build::ec_jwk`, whose `Jwk::from_object` rejects a `d` out of
///   range or a point that is not d·G (ADR 0043 §3, ADR 0018 §3
///   consistency). The comparison is not repeated here.
/// - Without one, the point is derived from `d` ([`derive_public`]).
fn private_jwk(crv: EcCurve, d: &[u8], embedded: Option<&[u8]>) -> Result<Jwk> {
    if d.len() != crv.coordinate_len() {
        return Err(Error::InvalidKey(PRIVATE_KEY_LENGTH));
    }
    let point = match embedded {
        Some(octets) => decode_point(crv, octets)?,
        None => derive_public(crv, d)?,
    };
    jwk_build::ec_jwk(crv, &point.x, &point.y, Some(d), None)
}

/// The public point Q = d·G of the scalar `d` on `crv` (SEC 1 v2 §3.2.1).
/// `SecretKey::from_bytes` rejects 0 and every value ≥ n in constant time,
/// and `SecretKey::public_key` multiplies in the curve crate's
/// constant-time arithmetic. The `SecretKey` is wiped on drop.
fn derive_public(crv: EcCurve, d: &[u8]) -> Result<Coordinates> {
    match crv {
        EcCurve::P256 => derive_public_on::<p256::NistP256>(d),
        EcCurve::P384 => derive_public_on::<p384::NistP384>(d),
        EcCurve::P521 => derive_public_on::<p521::NistP521>(d),
        EcCurve::Secp256k1 => derive_public_on::<k256::Secp256k1>(d),
    }
}

/// See [`derive_public`], on the curve `C`.
fn derive_public_on<C>(d: &[u8]) -> Result<Coordinates>
where
    C: CurveArithmetic,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: ModulusSize,
{
    let d = <&FieldBytes<C>>::try_from(d).map_err(|_| Error::InvalidKey(PRIVATE_KEY_LENGTH))?;
    let secret = SecretKey::<C>::from_bytes(d).map_err(|_| Error::InvalidKey(SCALAR_INVALID))?;
    coordinates(&secret.public_key())
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

/// Imports a standalone SEC1 `EC PRIVATE KEY` (RFC 5915 §3, §4) from DER,
/// as a private JWK with `crv`, `x`, `y` and `d` (RFC 7518 §6.2) and no
/// `alg`.
///
/// - The structure is decoded by `sec1::decode` (version 1, EXPLICIT
///   `[0]`/`[1]`, DER only).
/// - The `[0]` namedCurve is required: "Implementations that conform to
///   this document MUST always include the parameters field" (RFC 5915
///   §3).
/// - The privateKey must have the curve's length, and the `[1]` publicKey,
///   when present, must be d·G; without it the point is derived from d
///   (see [`private_jwk`]).
///
/// # Errors
///
/// - [`Error::UnsupportedAlgorithm`] for a namedCurve outside P-256,
///   P-384, P-521 and secp256k1, or a specifiedCurve (RFC 5480 §2.1.1).
/// - [`Error::InvalidKey`] for malformed DER, a missing `[0]`, a wrong
///   version or length, d out of range, an invalid point, or a point that
///   is not d·G.
#[cfg_attr(not(test), expect(dead_code, reason = "called by the facade (T08)"))]
pub(crate) fn from_sec1(der: &[u8]) -> Result<Jwk> {
    let key = sec1::decode(der)?;
    let crv = key.parameters.ok_or(Error::InvalidKey(
        "EC PRIVATE KEY has no namedCurve parameters",
    ))?;
    private_jwk(crv, key.private_key, key.public_key)
}

/// Exports the private `key` as a DER SEC1 `EC PRIVATE KEY` (RFC 5915 §3)
/// with the `[0]` namedCurve and the `[1]` uncompressed publicKey
/// (ADR 0018 §3), byte for byte what OpenSSL 4 writes. The output is
/// zeroized on drop.
///
/// # Errors
///
/// [`Error::InvalidKey`] if `key` has no `d`.
#[cfg_attr(not(test), expect(dead_code, reason = "called by the facade (T08)"))]
pub(crate) fn to_sec1(key: &EcKey) -> Result<Zeroizing<Vec<u8>>> {
    let d = key.d().ok_or(Error::InvalidKey(NOT_PRIVATE))?;
    let point = uncompressed_point(key);
    sec1::encode(&EcPrivateKey {
        private_key: d,
        parameters: Some(key.crv()),
        public_key: Some(&point),
    })
}

/// Imports an EC private key from a decoded PKCS#8 OneAsymmetricKey
/// (RFC 5958 §2) whose privateKeyAlgorithm is id-ecPublicKey with a
/// namedCurve (RFC 5480 §2.1.1), as a private JWK with `crv`, `x`, `y` and
/// `d` (RFC 7518 §6.2) and no `alg`.
///
/// - The privateKey OCTET STRING holds an ECPrivateKey (RFC 5915 §1, §3),
///   decoded by `sec1::decode`. Anything else, such as an RFC 8410
///   CurvePrivateKey, is `InvalidKey`.
/// - The inner `[0]` may be absent (RFC 5915 erratum 5008; RFC 7468
///   Fig. 12 and OpenSSL omit it) or must name the AlgorithmIdentifier's
///   curve (RFC 5915 §1; ADR 0018 §3).
/// - The embedded public key is the inner `[1]` (RFC 5915 §3) or the v2
///   `[1]` publicKey (RFC 5958 §2). When both are present they must be the
///   same point. It must be d·G, checked by `Jwk::from_object`
///   (ADR 0043 §3); without one, the point is derived from d.
///
/// # Errors
///
/// [`Error::InvalidKey`] if `parts.alg` is not an EC curve, the inner
/// structure is malformed or names another curve, the privateKey has the
/// wrong length, d is out of range, a point is invalid, or the points
/// disagree with each other or with d.
#[cfg_attr(not(test), expect(dead_code, reason = "called by the facade (T08)"))]
pub(crate) fn from_pkcs8(parts: Pkcs8Parts<'_>) -> Result<Jwk> {
    let crv = ec_curve(parts.alg)?;
    let inner = sec1::decode(parts.private_key)?;
    if inner.parameters.is_some_and(|named| named != crv) {
        return Err(Error::InvalidKey(
            "ECPrivateKey parameters disagree with the PKCS#8 algorithm",
        ));
    }
    let embedded = match (parts.public_key, inner.public_key) {
        (Some(outer), Some(nested)) => {
            // Both are public values; compared as decoded points, so a
            // compressed and an uncompressed encoding of one point agree.
            let (a, b) = (decode_point(crv, outer)?, decode_point(crv, nested)?);
            if !bool::from(a.x.as_slice().ct_eq(&b.x) & a.y.as_slice().ct_eq(&b.y)) {
                return Err(Error::InvalidKey(
                    "PKCS#8 publicKey and ECPrivateKey publicKey differ",
                ));
            }
            Some(outer)
        }
        (outer, nested) => outer.or(nested),
    };
    private_jwk(crv, inner.private_key, embedded)
}

/// Exports the private `key` as a DER PKCS#8 v1 PrivateKeyInfo (RFC 5958
/// §2, RFC 5208 §5): id-ecPublicKey with the key's namedCurve (RFC 5480
/// §2.1.1), and an ECPrivateKey with the `[1]` uncompressed publicKey and
/// no `[0]` (RFC 5915 §1 and erratum 5008; ADR 0018 §3), byte for byte what
/// OpenSSL 4 writes. The output is zeroized on drop.
///
/// # Errors
///
/// [`Error::InvalidKey`] if `key` has no `d`.
#[cfg_attr(not(test), expect(dead_code, reason = "called by the facade (T08)"))]
pub(crate) fn to_pkcs8(key: &EcKey) -> Result<Zeroizing<Vec<u8>>> {
    let d = key.d().ok_or(Error::InvalidKey(NOT_PRIVATE))?;
    let point = uncompressed_point(key);
    let inner = sec1::encode(&EcPrivateKey {
        private_key: d,
        parameters: None,
        public_key: Some(&point),
    })?;
    pkcs8::encode(&Pkcs8Parts {
        // v1(0): no outer publicKey (RFC 5958 §2).
        version: 0,
        alg: AlgId::Ec(key.crv()),
        private_key: &inner,
        public_key: None,
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

    mod sec1_form {
        use super::*;

        fn invalid(result: Result<Jwk>) -> &'static str {
            match result {
                Err(Error::InvalidKey(detail)) => detail,
                other => panic!("expected InvalidKey, got {other:?}"),
            }
        }

        #[test]
        fn rfc_sec1_vectors_round_trip() {
            // RFC 7517 App. A.2 (built) and RFC 9500 §2.3 testECCP256/384/521
            // (verbatim).
            for (file, json) in [
                (
                    "rfc7517-a2-ec-p256-sec1.der",
                    "rfc7517-a2-ec-p256-sec1.jwk.json",
                ),
                (
                    "rfc9500-testECCP256-sec1.pem",
                    "rfc9500-testECCP256-sec1.jwk.json",
                ),
                (
                    "rfc9500-testECCP384-sec1.pem",
                    "rfc9500-testECCP384-sec1.jwk.json",
                ),
                (
                    "rfc9500-testECCP521-sec1.pem",
                    "rfc9500-testECCP521-sec1.jwk.json",
                ),
            ] {
                let der = fixtures::load("rfc", file);
                let jwk = from_sec1(&der).unwrap();
                assert!(!jwk.is_public(), "{file}");
                assert_same(&jwk, &expected("rfc", json), file);
                assert_eq!(*to_sec1(ec_key(&jwk)).unwrap(), der, "{file}");
            }
        }

        #[test]
        fn rfc9500_p521_y_is_66_octets() {
            // research.md §3: RFC 9500's C array shows qy as 65 octets, the
            // DER point holds 66 (00 F6 2A ...), and RFC 7518 §6.2.1.3 wants
            // the full coordinate length.
            let der = fixtures::load("rfc", "rfc9500-testECCP521-sec1.pem");
            let jwk = from_sec1(&der).unwrap();
            let key = ec_key(&jwk);
            assert_eq!((key.x().len(), key.y().len()), (66, 66));
            assert_eq!(key.y()[..2], [0x00, 0xF6]);
            assert_eq!(key.d().map(<[u8]>::len), Some(66));
        }

        #[test]
        fn openssl_sec1_round_trips_and_nopub_gains_its_public_key() {
            for (name, _) in CURVES {
                let der = fixtures::load("openssl", &format!("ec-{name}-sec1.der"));
                let want = expected("openssl/expected", &format!("ec-{name}-sec1.jwk.json"));
                let jwk = from_sec1(&der).unwrap();
                assert_same(&jwk, &want, name);
                assert_eq!(*to_sec1(ec_key(&jwk)).unwrap(), der, "{name}");

                // Without [1] the point is derived from d, and export always
                // writes it (ADR 0018 §3).
                let nopub = fixtures::load("openssl", &format!("ec-{name}-sec1-nopub.pem"));
                let jwk = from_sec1(&nopub).unwrap();
                let want_nopub = expected(
                    "openssl/expected",
                    &format!("ec-{name}-sec1-nopub.jwk.json"),
                );
                assert_same(&jwk, &want_nopub, name);
                assert_eq!(*to_sec1(ec_key(&jwk)).unwrap(), der, "{name}");
            }
        }

        #[test]
        fn sec1_rejections_are_invalid() {
            // N40 version 0, N41 d = 0, N42 d = n, N43 31-octet d, N44
            // [1] ≠ d·G, N45 [0] curve ≠ key curve, N46 no [0], N47 IMPLICIT
            // [0] (RFC 5915 §3, App. A; SEC 1 v2 §3.2.1; ADR 0043 §3).
            for id in ["N40", "N41", "N42", "N43", "N44", "N45", "N46", "N47"] {
                let result = from_sec1(&fixtures::negative(id));
                assert!(
                    matches!(result, Err(Error::InvalidKey(_))),
                    "{id}: {:?}",
                    result.err()
                );
            }
        }

        #[test]
        fn each_rejection_fails_for_its_own_reason() {
            let detail = |id| invalid(from_sec1(&fixtures::negative(id)));
            assert_eq!(detail("N40"), "ECPrivateKey version is not 1");
            assert_eq!(detail("N41"), SCALAR_INVALID);
            assert_eq!(detail("N42"), SCALAR_INVALID);
            assert_eq!(detail("N43"), PRIVATE_KEY_LENGTH);
            // N44 flips the last octet of y, which leaves the curve.
            assert_eq!(detail("N44"), POINT_INVALID);
            assert_eq!(detail("N45"), PRIVATE_KEY_LENGTH);
            assert_eq!(detail("N46"), "EC PRIVATE KEY has no namedCurve parameters");
            assert_eq!(detail("N47"), "DER trailing data");
        }

        /// SEC1 for `d` on `crv` with an optional embedded point.
        fn sec1_of(crv: EcCurve, d: &[u8], point: Option<&[u8]>) -> Vec<u8> {
            sec1::encode(&EcPrivateKey {
                private_key: d,
                parameters: Some(crv),
                public_key: point,
            })
            .unwrap()
            .to_vec()
        }

        #[test]
        fn out_of_range_scalars_are_invalid_with_or_without_a_point() {
            // n − 1 is the largest valid scalar; n and 0xFF…FF are not
            // (SEC 1 v2 §3.2.1). P-256 n from SEC 2 v2 §2.4.2.
            let n = [
                0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2,
                0xFC, 0x63, 0x25, 0x51,
            ];
            let mut n_minus_1 = n;
            n_minus_1[31] -= 1;
            let jwk = from_sec1(&sec1_of(EcCurve::P256, &n_minus_1, None)).unwrap();
            let point = uncompressed_point(ec_key(&jwk));
            assert!(from_sec1(&sec1_of(EcCurve::P256, &n_minus_1, Some(&point))).is_ok());
            for d in [n, [0xFF; 32], [0; 32]] {
                assert_eq!(
                    invalid(from_sec1(&sec1_of(EcCurve::P256, &d, None))),
                    SCALAR_INVALID
                );
                assert!(matches!(
                    from_sec1(&sec1_of(EcCurve::P256, &d, Some(&point))),
                    Err(Error::InvalidKey(_))
                ));
            }
        }

        #[test]
        fn a_compressed_embedded_point_is_accepted() {
            // RFC 5915 §3 publicKey is a SEC1 point (RFC 5480 §2.2), which
            // may be compressed; export writes it uncompressed.
            let der = fixtures::load("openssl", "ec-p384-sec1.der");
            let jwk = from_sec1(&der).unwrap();
            let key = ec_key(&jwk);
            let compressed = fixtures::load("openssl", "ec-p384-spki-compressed.pem");
            let point = spki::decode(&compressed)
                .unwrap()
                .subject_public_key
                .to_vec();
            assert_eq!(point.len(), 49);
            let rebuilt = sec1_of(EcCurve::P384, key.d().unwrap(), Some(&point));
            let again = from_sec1(&rebuilt).unwrap();
            assert_same(&again, &jwk, "compressed [1]");
            assert_eq!(*to_sec1(ec_key(&again)).unwrap(), der);
        }

        #[test]
        fn the_valid_point_of_another_key_is_rejected_by_jwk_rs() {
            // ADR 0043 §3: the embedded [1] is passed through with d, and
            // Jwk::from_object rejects the pair. RFC 7517 A.2's d with RFC
            // 9500 testECCP256's point, both valid P-256 values.
            let a2 = from_sec1(&fixtures::load("rfc", "rfc7517-a2-ec-p256-sec1.der")).unwrap();
            let other = from_sec1(&fixtures::load("rfc", "rfc9500-testECCP256-sec1.pem")).unwrap();
            let point = uncompressed_point(ec_key(&other));
            let mixed = sec1_of(EcCurve::P256, ec_key(&a2).d().unwrap(), Some(&point));
            assert_eq!(
                invalid(from_sec1(&mixed)),
                "EC private key d does not match x and y"
            );
        }

        #[test]
        fn bad_embedded_points_are_invalid() {
            let der = fixtures::load("openssl", "ec-p256-sec1.der");
            let jwk = from_sec1(&der).unwrap();
            let d = ec_key(&jwk).d().unwrap().to_vec();
            let mut identity_or_hybrid = vec![vec![0x00], uncompressed_point(ec_key(&jwk))];
            identity_or_hybrid[1][0] = 0x06;
            for point in identity_or_hybrid {
                assert_eq!(
                    invalid(from_sec1(&sec1_of(EcCurve::P256, &d, Some(&point)))),
                    POINT_INVALID
                );
            }
        }

        #[test]
        fn explicit_parameters_are_unsupported() {
            let der = fixtures::load("openssl", "reject-ec-p256-explicit-sec1.pem");
            assert_eq!(from_sec1(&der).unwrap_err(), Error::UnsupportedAlgorithm);
        }

        #[test]
        fn a_public_key_has_no_sec1_form() {
            let jwk = expected("openssl/expected", "ec-p256-spki.jwk.json");
            assert_eq!(
                to_sec1(ec_key(&jwk)).unwrap_err(),
                Error::InvalidKey(NOT_PRIVATE)
            );
        }
    }

    mod pkcs8_form {
        use super::*;

        fn import(der: &[u8]) -> Result<Jwk> {
            pkcs8::decode(der).and_then(from_pkcs8)
        }

        fn invalid(result: Result<Jwk>) -> &'static str {
            match result {
                Err(Error::InvalidKey(detail)) => detail,
                other => panic!("expected InvalidKey, got {other:?}"),
            }
        }

        /// PKCS#8 for `d` on `crv` with the inner `[0]`/`[1]` and the outer
        /// v2 `[1]` as given.
        fn pkcs8_of(
            crv: EcCurve,
            d: &[u8],
            inner_curve: Option<EcCurve>,
            inner_point: Option<&[u8]>,
            outer_point: Option<&[u8]>,
        ) -> Vec<u8> {
            let inner = sec1::encode(&EcPrivateKey {
                private_key: d,
                parameters: inner_curve,
                public_key: inner_point,
            })
            .unwrap();
            pkcs8::encode(&Pkcs8Parts {
                version: u8::from(outer_point.is_some()),
                alg: AlgId::Ec(crv),
                private_key: &inner,
                public_key: outer_point,
            })
            .unwrap()
            .to_vec()
        }

        #[test]
        fn rfc_pkcs8_vectors_round_trip() {
            // RFC 7517 App. A.2 (built) and RFC 7468 §10 Fig. 12
            // (secp256k1, inner ECPrivateKey without [0], verbatim).
            for (file, json) in [
                (
                    "rfc7517-a2-ec-p256-pkcs8.der",
                    "rfc7517-a2-ec-p256-pkcs8.jwk.json",
                ),
                (
                    "rfc7468-fig12-secp256k1-pkcs8.pem",
                    "rfc7468-fig12-secp256k1-pkcs8.jwk.json",
                ),
            ] {
                let der = fixtures::load("rfc", file);
                let jwk = import(&der).unwrap();
                assert_same(&jwk, &expected("rfc", json), file);
                assert_eq!(*to_pkcs8(ec_key(&jwk)).unwrap(), der, "{file}");
            }
        }

        #[test]
        fn openssl_pkcs8_round_trips() {
            for (name, _) in CURVES {
                let der = fixtures::load("openssl", &format!("ec-{name}-pkcs8.der"));
                let want = expected("openssl/expected", &format!("ec-{name}-pkcs8.jwk.json"));
                let jwk = import(&der).unwrap();
                assert_same(&jwk, &want, name);
                assert_eq!(*to_pkcs8(ec_key(&jwk)).unwrap(), der, "{name}");
            }
        }

        #[test]
        fn consistency_rejections_are_invalid() {
            // N50: inner [0] P-384 under a P-256 AlgorithmIdentifier
            // (RFC 5915 §1). N51: an RFC 8410 CurvePrivateKey body under
            // id-ecPublicKey (RFC 5915 §3). N52: the inner [1] of another
            // valid key (ADR 0043 §3).
            let detail = |id| invalid(import(&fixtures::negative(id)));
            assert_eq!(
                detail("N50"),
                "ECPrivateKey parameters disagree with the PKCS#8 algorithm"
            );
            assert_eq!(detail("N51"), "DER unexpected tag");
            assert_eq!(detail("N52"), "EC private key d does not match x and y");
        }

        #[test]
        fn inner_parameters_absent_or_matching_are_accepted() {
            // RFC 5915 erratum 5008: absent; RFC 5915 §3: present and equal.
            // Export always omits [0], as OpenSSL does.
            for (name, crv) in CURVES {
                let der = fixtures::load("openssl", &format!("ec-{name}-pkcs8.der"));
                let jwk = import(&der).unwrap();
                let key = ec_key(&jwk);
                let point = uncompressed_point(key);
                let with_curve = pkcs8_of(crv, key.d().unwrap(), Some(crv), Some(&point), None);
                let again = import(&with_curve).unwrap();
                assert_same(&again, &jwk, name);
                assert_eq!(*to_pkcs8(ec_key(&again)).unwrap(), der, "{name}");
                // And without [1]: the point is derived.
                let bare = pkcs8_of(crv, key.d().unwrap(), None, None, None);
                assert_same(&import(&bare).unwrap(), &jwk, name);
            }
        }

        #[test]
        fn v2_public_keys_must_agree() {
            let a2 = import(&fixtures::load("rfc", "rfc7517-a2-ec-p256-pkcs8.der")).unwrap();
            let other = from_sec1(&fixtures::load("rfc", "rfc9500-testECCP256-sec1.pem")).unwrap();
            let key = ec_key(&a2);
            let d = key.d().unwrap();
            let point = uncompressed_point(key);
            let other_point = uncompressed_point(ec_key(&other));
            let crv = EcCurve::P256;

            // Outer only, and outer and inner equal: accepted.
            assert_same(
                &import(&pkcs8_of(crv, d, None, None, Some(&point))).unwrap(),
                &a2,
                "outer",
            );
            assert_same(
                &import(&pkcs8_of(crv, d, None, Some(&point), Some(&point))).unwrap(),
                &a2,
                "both",
            );
            // One compressed, one uncompressed encoding of the same point.
            let mut compressed = vec![0x02 | (key.y()[31] & 1)];
            compressed.extend_from_slice(key.x());
            assert_same(
                &import(&pkcs8_of(crv, d, None, Some(&compressed), Some(&point))).unwrap(),
                &a2,
                "mixed forms",
            );
            // Outer and inner disagree.
            assert_eq!(
                invalid(import(&pkcs8_of(
                    crv,
                    d,
                    None,
                    Some(&point),
                    Some(&other_point)
                ))),
                "PKCS#8 publicKey and ECPrivateKey publicKey differ"
            );
            // Outer only, of another key: jwk.rs rejects it.
            assert_eq!(
                invalid(import(&pkcs8_of(crv, d, None, None, Some(&other_point)))),
                "EC private key d does not match x and y"
            );
            // Both of another key, agreeing with each other.
            assert_eq!(
                invalid(import(&pkcs8_of(
                    crv,
                    d,
                    None,
                    Some(&other_point),
                    Some(&other_point)
                ))),
                "EC private key d does not match x and y"
            );
        }

        #[test]
        fn unsupported_curves_and_explicit_parameters_are_unsupported() {
            for file in [
                "reject-ec-brainpoolp256r1-pkcs8.pem",
                "reject-ec-p256-explicit-pkcs8.pem",
            ] {
                let der = fixtures::load("openssl", file);
                assert_eq!(
                    import(&der).unwrap_err(),
                    Error::UnsupportedAlgorithm,
                    "{file}"
                );
            }
            // An unsupported curve in the inner [0] fails as unsupported too.
            let jwk = expected("openssl/expected", "ec-p256-pkcs8.jwk.json");
            let d = ec_key(&jwk).d().unwrap().to_vec();
            let mut der = pkcs8_of(EcCurve::P256, &d, Some(EcCurve::P256), None, None);
            let named = super::super::super::oid::OID_P256;
            let at = der.windows(named.len()).rposition(|w| w == named).unwrap();
            // 30 L | 02 01 00 | 30 13 <alg> | 04 L | 30 L | 02 01 01 |
            // 04 20 d | a0 0a <OID>: every length is short form. secp224r1
            // (1.3.132.0.33) is shorter; replace the OID and fix the outer,
            // OCTET STRING, ECPrivateKey and [0] lengths.
            assert_eq!((der[26], der[28], der[at - 2]), (0x04, 0x30, 0xA0));
            let secp224r1 = [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x21];
            let shrink = u8::try_from(named.len() - secp224r1.len()).unwrap();
            der.splice(at..at + named.len(), secp224r1);
            for offset in [1, 27, 29, at - 1] {
                der[offset] -= shrink;
            }
            assert_eq!(import(&der).unwrap_err(), Error::UnsupportedAlgorithm);
        }

        #[test]
        fn a_non_ec_algorithm_is_refused() {
            let der = fixtures::load("rfc", "rfc8037-a1-ed25519-pkcs8.der");
            assert_eq!(
                import(&der).unwrap_err(),
                Error::InvalidKey("not an EC key")
            );
        }

        #[test]
        fn a_public_key_has_no_pkcs8_form() {
            let jwk = expected("openssl/expected", "ec-p256-spki.jwk.json");
            assert_eq!(
                to_pkcs8(ec_key(&jwk)).unwrap_err(),
                Error::InvalidKey(NOT_PRIVATE)
            );
        }
    }
}
