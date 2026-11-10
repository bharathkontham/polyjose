//! EC keys on P-256, P-384, P-521 and secp256k1 (RFC 7518 §6.2, RFC 8812
//! §3.1) to and from SPKI (RFC 5480 §2.1.1 namedCurve, §2.2 uncompressed or
//! compressed points) and PKCS#8, whose privateKey holds an RFC 5915
//! ECPrivateKey (RFC 5915 §1; without `[0]`, per erratum 5008).
//!
//! # Crate-internal API (for the facade, T08)
//!
//! | Function | Input | Output |
//! |---|---|---|
//! | [`from_pkcs8`] | `Pkcs8Parts` from `pkcs8::decode`, `alg` = `AlgId::Ec(_)` | private JWK |
//! | [`from_sec1`] | DER of a standalone `EC PRIVATE KEY` | private JWK |
//! | [`from_spki`] | `SpkiParts` from `spki::decode`, `alg` = `AlgId::Ec(_)` | public JWK |
//! | [`to_pkcs8`] | private [`EcKey`] | PKCS#8 v1 DER, inner `[1]`, no `[0]` |
//! | [`to_sec1`] | private [`EcKey`] | SEC1 DER with `[0]` and `[1]` |
//! | [`to_spki`] | any [`EcKey`] | SPKI DER, uncompressed point |
//!
//! The export forms are those of ADR 0018 §3, in OpenSSL 4's byte layout.
//! The facade dispatches on the classified algorithm, so a non-EC `AlgId`
//! is refused as `InvalidKey`, and exporting a public key in a private
//! form is `InvalidKey` too. Imported JWKs carry no `alg` member.
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
//! `SecretKey` wipes itself on drop, the scalar copy of the public-key
//! derivation is zeroized ([`public_key`]), and every encoding is written
//! into a [`Zeroizing`] buffer. Copies inside the curve crates are
//! best-effort, as [`public_key`] and [`derive_public`] document. Errors
//! are static strings with no input octet.

use p256::elliptic_curve::sec1::{FromSec1Point, ModulusSize, ToSec1Point};
use p256::elliptic_curve::{
    AffinePoint, CurveArithmetic, FieldBytes, FieldBytesSize, NonZeroScalar, PublicKey, SecretKey,
};
use subtle::ConstantTimeEq as _;
use zeroize::{Zeroize as _, Zeroizing};

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
///   §6.2.2.1). This is checked first.
/// - `embedded` then yields the embedded point, decoded by the curve crate
///   ([`decode_point`]; it may be compressed). It is a closure so that the
///   caller decodes each point once and a wrong length is still reported
///   before a bad point. The point is passed with `d` to
///   `jwk_build::ec_jwk`, whose `Jwk::from_object` rejects a `d` out of
///   range or a point that is not d·G (ADR 0043 §3, ADR 0018 §3
///   consistency). The comparison is not repeated here.
/// - Without one, the point is derived from `d` ([`derive_public`]).
fn private_jwk(
    crv: EcCurve,
    d: &[u8],
    embedded: impl FnOnce() -> Result<Option<Coordinates>>,
) -> Result<Jwk> {
    if d.len() != crv.coordinate_len() {
        return Err(Error::InvalidKey(PRIVATE_KEY_LENGTH));
    }
    let point = match embedded()? {
        Some(point) => point,
        None => derive_public(crv, d)?,
    };
    jwk_build::ec_jwk(crv, &point.x, &point.y, Some(d), None)
}

/// [`decode_point`] on the embedded point, if there is one.
fn decode_embedded(crv: EcCurve, octets: Option<&[u8]>) -> Result<Option<Coordinates>> {
    octets.map(|octets| decode_point(crv, octets)).transpose()
}

/// The public point Q = d·G of the scalar `d` on `crv` (SEC 1 v2 §3.2.1).
/// `SecretKey::from_bytes` rejects 0 and every value ≥ n in constant time,
/// and [`public_key`] multiplies in the curve crate's constant-time
/// arithmetic. The `SecretKey` is wiped on drop.
///
/// Best-effort: elliptic-curve 0.14.3's `SecretKey::from_bytes` returns
/// the decoded `ScalarValue` by value through a `CtOption`
/// (`ScalarValue::from_bytes`, `into_option`); any copy those moves leave
/// is upstream and not wiped.
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
    coordinates(&public_key(&secret))
}

/// Q = d·G for `secret` (SEC 1 v2 §3.2.1 step 2): the same point as
/// elliptic-curve's `SecretKey::public_key`, without its unwiped scalar.
///
/// EC import ([`derive_public`]) and key generation
/// (`generate::ec_jwk_from_secret`) both derive Q through it. The JWK
/// d·G consistency check in `jwk.rs` (ADR 0043 §3) still calls
/// `SecretKey::public_key` directly, with its unwiped temporary.
///
/// # Secrets (best-effort)
///
/// elliptic-curve 0.14.3's `SecretKey::public_key` is
/// `PublicKey::from_secret_scalar(&self.to_nonzero_scalar())`, and
/// `NonZeroScalar` has no `Drop`, so that temporary is never wiped. Here
/// the `NonZeroScalar` is a named copy that [`public_key_from_copy`]
/// zeroizes after the multiplication. Copies made inside
/// `ProjectivePoint::mul_by_generator` (the curve crate's arithmetic) are
/// out of polyjose's reach and not wiped.
pub(super) fn public_key<C: CurveArithmetic>(secret: &SecretKey<C>) -> PublicKey<C> {
    let mut scalar = secret.to_nonzero_scalar();
    public_key_from_copy(&mut scalar)
}

/// [`public_key`] of the scalar in `scalar`, which is zeroized once the
/// point is computed. elliptic-curve's `impl Zeroize for NonZeroScalar`
/// overwrites the value and then stores one, to keep the type non-zero.
fn public_key_from_copy<C: CurveArithmetic>(scalar: &mut NonZeroScalar<C>) -> PublicKey<C> {
    let public = PublicKey::from_secret_scalar(scalar);
    scalar.zeroize();
    public
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
/// - The structure is decoded by `sec1::decode_standalone` (version 1,
///   EXPLICIT `[0]`/`[1]`, DER only).
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
///   A PKCS#1 RSAPrivateKey given as SEC1 is malformed SEC1, `InvalidKey`
///   (ADR 0067).
/// - [`Error::InvalidKey`] for malformed DER, a missing `[0]`, a wrong
///   version or length, d out of range, an invalid point, or a point that
///   is not d·G.
pub(crate) fn from_sec1(der: &[u8]) -> Result<Jwk> {
    let key = sec1::decode_standalone(der)?;
    let crv = key.parameters.ok_or(Error::InvalidKey(
        "EC PRIVATE KEY has no namedCurve parameters",
    ))?;
    private_jwk(crv, key.private_key, || {
        decode_embedded(crv, key.public_key)
    })
}

/// Exports the private `key` as a DER SEC1 `EC PRIVATE KEY` (RFC 5915 §3)
/// with the `[0]` namedCurve and the `[1]` uncompressed publicKey
/// (ADR 0018 §3), byte for byte what OpenSSL 4 writes. The output is
/// zeroized on drop.
///
/// # Errors
///
/// [`Error::InvalidKey`] if `key` has no `d`.
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
pub(crate) fn from_pkcs8(parts: Pkcs8Parts<'_>) -> Result<Jwk> {
    let crv = ec_curve(parts.alg)?;
    let inner = sec1::decode(parts.private_key)?;
    if inner.parameters.is_some_and(|named| named != crv) {
        return Err(Error::InvalidKey(
            "ECPrivateKey parameters disagree with the PKCS#8 algorithm",
        ));
    }
    match (parts.public_key, inner.public_key) {
        (Some(outer), Some(nested)) => {
            // Both are public values; compared as decoded points, so a
            // compressed and an uncompressed encoding of one point agree.
            let (a, b) = (decode_point(crv, outer)?, decode_point(crv, nested)?);
            if !bool::from(a.x.as_slice().ct_eq(&b.x) & a.y.as_slice().ct_eq(&b.y)) {
                return Err(Error::InvalidKey(
                    "PKCS#8 publicKey and ECPrivateKey publicKey differ",
                ));
            }
            private_jwk(crv, inner.private_key, || Ok(Some(a)))
        }
        (outer, nested) => private_jwk(crv, inner.private_key, || {
            decode_embedded(crv, outer.or(nested))
        }),
    }
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

    /// [`public_key`] gives the curve crate's own `SecretKey::public_key`
    /// point, and [`public_key_from_copy`] wipes the scalar it multiplies
    /// with: read back, the copy is `NonZeroScalar`'s wiped value, one
    /// (elliptic-curve's `Zeroize` writes 1 to keep the type's invariant).
    fn check_public_key_wipes_its_scalar<C>(crv: EcCurve)
    where
        C: CurveArithmetic,
    {
        use p256::elliptic_curve::Field;
        let fixture = expected("rfc", &format!("{}.jwk.json", rfc_fixture(crv)));
        let d = ec_key(&fixture).d().unwrap();
        let secret = SecretKey::<C>::from_slice(d).unwrap();
        assert_eq!(public_key(&secret), secret.public_key(), "{crv:?}");

        let mut copy = secret.to_nonzero_scalar();
        assert_eq!(public_key_from_copy(&mut copy), secret.public_key());
        let one = NonZeroScalar::<C>::new(<p256::elliptic_curve::Scalar<C> as Field>::ONE).unwrap();
        assert!(copy == one, "{crv:?}: the scalar copy is wiped");
        assert!(one != secret.to_nonzero_scalar(), "{crv:?}: d is not one");
    }

    /// The RFC fixture of a private key on `crv` (RFC 7517 A.2, RFC 9500
    /// §2.3, RFC 7468 Figure 12).
    fn rfc_fixture(crv: EcCurve) -> &'static str {
        match crv {
            EcCurve::P256 => "rfc7517-a2-ec-p256-pkcs8",
            EcCurve::P384 => "rfc9500-testECCP384-sec1",
            EcCurve::P521 => "rfc9500-testECCP521-sec1",
            EcCurve::Secp256k1 => "rfc7468-fig12-secp256k1-pkcs8",
        }
    }

    #[test]
    fn public_key_wipes_its_copy_of_the_scalar() {
        check_public_key_wipes_its_scalar::<p256::NistP256>(EcCurve::P256);
        check_public_key_wipes_its_scalar::<p384::NistP384>(EcCurve::P384);
        check_public_key_wipes_its_scalar::<p521::NistP521>(EcCurve::P521);
        check_public_key_wipes_its_scalar::<k256::Secp256k1>(EcCurve::Secp256k1);
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

    mod round_trip {
        use super::*;
        use crate::keys::generate::generate_ec;
        use crate::rng::CryptoRngAdapter;

        /// Keys generated per curve (T06 acceptance criterion).
        const KEYS_PER_CURVE: usize = 16;

        #[test]
        fn generated_keys_survive_every_form() {
            // JWK → SEC1/PKCS#8/SPKI → JWK is the identity for T04's keys,
            // and every import passed the typed-JWK validation (ADR 0041
            // §4, ADR 0043 §3) because it went through Jwk::from_object.
            for (name, crv) in CURVES {
                for _ in 0..KEYS_PER_CURVE {
                    let jwk = generate_ec(crv, &mut CryptoRngAdapter::os()).unwrap();
                    let key = ec_key(&jwk);

                    let sec1_der = to_sec1(key).unwrap();
                    assert_same(&from_sec1(&sec1_der).unwrap(), &jwk, name);

                    let pkcs8_der = to_pkcs8(key).unwrap();
                    let parts = pkcs8::decode(&pkcs8_der).unwrap();
                    assert_same(&from_pkcs8(parts).unwrap(), &jwk, name);

                    let spki_der = to_spki(key).unwrap();
                    let public = spki::decode(&spki_der).and_then(from_spki).unwrap();
                    assert_same(&public, &jwk.to_public().unwrap(), name);
                }
            }
        }

        #[test]
        fn exports_parse_with_the_rustcrypto_oracles() {
            // Differential check of the three export forms against the
            // `sec1`, `pkcs8` and `spki` crates (dev-dependency oracles,
            // ADR 0016 §5, ADR 0018 §1).
            for (name, crv) in CURVES {
                let jwk = generate_ec(crv, &mut CryptoRngAdapter::os()).unwrap();
                let key = ec_key(&jwk);
                let point = uncompressed_point(key);
                let named = |p: &::sec1::EcParameters| p.named_curve().map(|o| o.to_string());
                let curve_oid = match crv {
                    EcCurve::P256 => "1.2.840.10045.3.1.7",
                    EcCurve::P384 => "1.3.132.0.34",
                    EcCurve::P521 => "1.3.132.0.35",
                    EcCurve::Secp256k1 => "1.3.132.0.10",
                };

                let sec1_der = to_sec1(key).unwrap();
                let oracle = ::sec1::EcPrivateKey::try_from(sec1_der.as_slice()).unwrap();
                assert_eq!(Some(oracle.private_key), key.d(), "{name}");
                assert_eq!(oracle.public_key, Some(point.as_slice()), "{name}");
                assert_eq!(
                    oracle.parameters.as_ref().and_then(named).as_deref(),
                    Some(curve_oid),
                    "{name}"
                );

                let pkcs8_der = to_pkcs8(key).unwrap();
                let info = ::pkcs8::PrivateKeyInfoRef::try_from(pkcs8_der.as_slice()).unwrap();
                assert!(info.public_key.is_none(), "{name}: v1");
                let inner = ::sec1::EcPrivateKey::try_from(info.private_key.as_bytes()).unwrap();
                assert!(inner.parameters.is_none(), "{name}: no inner [0]");
                assert_eq!(Some(inner.private_key), key.d(), "{name}");
                assert_eq!(inner.public_key, Some(point.as_slice()), "{name}");

                let spki_der = to_spki(key).unwrap();
                let info = ::spki::SubjectPublicKeyInfoRef::try_from(spki_der.as_slice()).unwrap();
                assert_eq!(
                    info.subject_public_key.raw_bytes(),
                    point.as_slice(),
                    "{name}"
                );
                assert_eq!(
                    info.algorithm.oid.to_string(),
                    "1.2.840.10045.2.1",
                    "{name}"
                );
            }
        }
    }

    /// Secret hygiene of EC import and export: every failure path reports
    /// a static detail or a bare code, never key octets, and an imported
    /// key's `Debug` leaves out `d` (ADR 0007, ADR 0018 §4), checked with
    /// marker-filled scalars and points. The scalar copy of the public-key
    /// derivation is checked by `public_key_wipes_its_copy_of_the_scalar`.
    ///
    /// **What these tests cannot detect.** They read what is observable from
    /// safe Rust: error values, `Debug`/`Display` text and buffers they own.
    /// They cannot see:
    ///
    /// - by-value stack copies, such as a `[u8; N]` or `FieldBytes` moved or
    ///   passed by value, or a spilled register, which leave no trace a test
    ///   can read back after the frame is gone;
    /// - copies made inside upstream crates (the curve and dalek crates'
    ///   scalar, sampling and hashing temporaries), which polyjose cannot reach.
    ///
    /// Those copies are documented as best-effort where they arise
    /// (`okp::x25519_public`, `okp::ed25519_public`, `ec::public_key`,
    /// `generate::generate_ec_secret`), and reviewed, not tested.
    mod hygiene {
        use std::collections::BTreeSet;

        use proptest::prelude::*;

        use super::*;

        /// The marker octet in every secret position. A leak would show up
        /// as `165` in a derived `Debug` or as `a5` in hex.
        const M: u8 = 0xA5;

        fn leaks(text: &str) -> bool {
            let lower = text.to_ascii_lowercase();
            lower.contains("a5") || lower.contains("165") || text.contains(char::from(M))
        }

        /// Every static detail the non-test code of `source` can return:
        /// `InvalidKey("…")` literals and `const …: &str = "…"` details.
        fn details(source: &str) -> Vec<String> {
            let code = source.split("\n#[cfg(test)]").next().unwrap();
            let literal = |rest: &str| {
                let rest = rest.trim_start().strip_prefix('"')?;
                Some(rest[..rest.find('"').unwrap()].to_owned())
            };
            let calls = code.split("InvalidKey(").skip(1).filter_map(literal);
            let consts = code.split(": &str = ").skip(1).filter_map(literal);
            calls.chain(consts).collect()
        }

        fn sec1_der(crv: Option<EcCurve>, d: &[u8], point: Option<&[u8]>) -> Zeroizing<Vec<u8>> {
            sec1::encode(&EcPrivateKey {
                private_key: d,
                parameters: crv,
                public_key: point,
            })
            .unwrap()
        }

        fn pkcs8_parts<'a>(inner: &'a [u8], outer: Option<&'a [u8]>) -> Pkcs8Parts<'a> {
            Pkcs8Parts {
                version: u8::from(outer.is_some()),
                alg: AlgId::Ec(EcCurve::P256),
                private_key: inner,
                public_key: outer,
            }
        }

        /// One failing call per detail, every secret position filled with
        /// the marker.
        fn cases() -> Vec<(Error, &'static str)> {
            let p256 = Some(EcCurve::P256);
            let d = [M; 32];
            let other = from_sec1(&fixtures::load("rfc", "rfc9500-testECCP256-sec1.pem")).unwrap();
            let other_point = uncompressed_point(ec_key(&other));
            let a2 = from_sec1(&fixtures::load("rfc", "rfc7517-a2-ec-p256-sec1.der")).unwrap();
            let a2_point = uncompressed_point(ec_key(&a2));
            let mut marker_point = vec![0x04];
            marker_point.extend_from_slice(&[M; 64]);
            let mut version_0 = sec1_der(p256, &d, None).to_vec();
            assert_eq!(version_0[2..5], [0x02, 0x01, 0x01]);
            version_0[4] = 0x00;
            let mut null_params = sec1_der(p256, &d, None).to_vec();
            let at = null_params.len() - 10;
            null_params.splice(at.., [0x05, 0x00]);
            null_params[at - 1] = 2;
            null_params[1] -= 8;
            let p384_inner = sec1_der(Some(EcCurve::P384), &d, None);
            let both_inner = sec1_der(None, &d, Some(&a2_point));
            let marker_inner = sec1_der(None, &d, None);
            let point_spki = SpkiParts {
                alg: AlgId::Ec(EcCurve::P256),
                subject_public_key: &marker_point,
            };
            let ed25519 = SpkiParts {
                alg: AlgId::Ed25519,
                subject_public_key: &[M; 32],
            };
            let public = expected("openssl/expected", "ec-p256-spki.jwk.json");
            let err = |result: Result<Jwk>| result.unwrap_err();
            vec![
                (err(from_sec1(&version_0)), "ECPrivateKey version is not 1"),
                (
                    err(from_sec1(&null_params)),
                    "ECPrivateKey parameters are not a namedCurve",
                ),
                (
                    err(from_sec1(&sec1_der(None, &d, None))),
                    "EC PRIVATE KEY has no namedCurve parameters",
                ),
                (
                    err(from_sec1(&sec1_der(p256, &d[..31], None))),
                    PRIVATE_KEY_LENGTH,
                ),
                (
                    err(from_sec1(&sec1_der(p256, &[0; 32], None))),
                    SCALAR_INVALID,
                ),
                (
                    err(from_sec1(&sec1_der(p256, &d, Some(&marker_point)))),
                    POINT_INVALID,
                ),
                (
                    err(from_sec1(&sec1_der(p256, &d, Some(&other_point)))),
                    "EC private key d does not match x and y",
                ),
                (
                    err(from_pkcs8(pkcs8_parts(&p384_inner, None))),
                    "ECPrivateKey parameters disagree with the PKCS#8 algorithm",
                ),
                (
                    err(from_pkcs8(pkcs8_parts(&both_inner, Some(&other_point)))),
                    "PKCS#8 publicKey and ECPrivateKey publicKey differ",
                ),
                (
                    err(from_pkcs8(pkcs8_parts(&marker_inner, Some(&marker_point)))),
                    POINT_INVALID,
                ),
                (err(from_spki(point_spki)), POINT_INVALID),
                (err(from_spki(ed25519)), "not an EC key"),
                (to_sec1(ec_key(&public)).unwrap_err(), NOT_PRIVATE),
                (to_pkcs8(ec_key(&public)).unwrap_err(), NOT_PRIVATE),
            ]
        }

        #[test]
        fn every_failure_path_reports_a_static_detail_without_key_bytes() {
            let mut seen = BTreeSet::new();
            for (error, detail) in cases() {
                assert_eq!(error, Error::InvalidKey(detail), "{detail}");
                for text in [
                    format!("{error}"),
                    format!("{error:?}"),
                    format!("{error:#?}"),
                ] {
                    assert!(!leaks(&text), "{text}");
                }
                seen.insert(detail.to_owned());
            }
            let all: BTreeSet<String> = [include_str!("ec.rs"), include_str!("sec1.rs")]
                .into_iter()
                .flat_map(details)
                .collect();
            assert!(all.len() >= 10, "{all:?}");
            let missing: Vec<_> = all.difference(&seen).collect();
            assert!(missing.is_empty(), "no marker case for {missing:?}");
        }

        #[test]
        fn imported_keys_keep_d_out_of_debug() {
            // The JWK's own Debug redacts d (jwk.rs); the marker-free RFC
            // key's d must not appear in it in any form.
            let jwk = from_sec1(&fixtures::load("rfc", "rfc7517-a2-ec-p256-sec1.der")).unwrap();
            let d = crate::util::b64url_encode(ec_key(&jwk).d().unwrap());
            let shown = format!("{jwk:?} {jwk:#?}");
            assert!(!shown.contains(&d), "{shown}");
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(1_000))]

            /// Arbitrary input to every import path returns a result,
            /// never panics, and fails only with the two key error codes.
            #[test]
            fn arbitrary_input_never_panics(input in proptest::collection::vec(any::<u8>(), 0..160)) {
                let ok_or_key_error = |result: Result<Jwk>| matches!(
                    result,
                    Ok(_) | Err(Error::InvalidKey(_) | Error::UnsupportedAlgorithm)
                );
                prop_assert!(ok_or_key_error(from_sec1(&input)));
                prop_assert!(ok_or_key_error(from_pkcs8(pkcs8_parts(&input, None))));
                prop_assert!(ok_or_key_error(from_pkcs8(pkcs8_parts(&input, Some(&input)))));
                for crv in [EcCurve::P256, EcCurve::P384, EcCurve::P521, EcCurve::Secp256k1] {
                    let parts = SpkiParts { alg: AlgId::Ec(crv), subject_public_key: &input };
                    prop_assert!(ok_or_key_error(from_spki(parts)));
                }
            }

            /// Bit flips in a valid SEC1 key either still import to a
            /// valid key or fail with a key error.
            #[test]
            fn mutated_sec1_never_panics(at in 0usize..121, bit in 0u8..8) {
                let mut der = fixtures::load("rfc", "rfc7517-a2-ec-p256-sec1.der");
                der[at] ^= 1 << bit;
                prop_assert!(matches!(
                    from_sec1(&der),
                    Ok(_) | Err(Error::InvalidKey(_) | Error::UnsupportedAlgorithm)
                ));
            }
        }
    }

    /// Tester probes (T06-r1): gaps found against the acceptance criteria.
    mod tester_probes {
        use super::*;

        const CURVE_OIDS: [(&str, EcCurve); 4] = CURVES;

        /// 30 L | 02 01 01 | 04 20 d | a0 L <parameters-element>
        fn raw_sec1(d: &[u8], params: &[u8]) -> Vec<u8> {
            let mut body = vec![0x02, 0x01, 0x01, 0x04, u8::try_from(d.len()).unwrap()];
            body.extend_from_slice(d);
            body.push(0xA0);
            body.push(u8::try_from(params.len()).unwrap());
            body.extend_from_slice(params);
            let mut der = vec![0x30, u8::try_from(body.len()).unwrap()];
            der.extend(body);
            der
        }

        fn a2_d() -> Vec<u8> {
            let a2 = from_sec1(&fixtures::load("rfc", "rfc7517-a2-ec-p256-sec1.der")).unwrap();
            ec_key(&a2).d().unwrap().to_vec()
        }

        #[test]
        fn brainpool_and_explicit_sec1_are_unsupported() {
            // No brainpool SEC1 fixture exists: build one with the
            // brainpoolP256r1 namedCurve in [0] (RFC 5639 §4.1).
            let mut oid = vec![0x06, 0x09];
            oid.extend_from_slice(&[0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07]);
            assert_eq!(
                from_sec1(&raw_sec1(&a2_d(), &oid)).unwrap_err(),
                Error::UnsupportedAlgorithm
            );
            // specifiedCurve in [0], and as the inner [0] of PKCS#8.
            let specified = [0x30, 0x03, 0x02, 0x01, 0x01];
            assert_eq!(
                from_sec1(&raw_sec1(&a2_d(), &specified)).unwrap_err(),
                Error::UnsupportedAlgorithm
            );
            let jwk = expected("openssl/expected", "ec-p256-pkcs8.jwk.json");
            let inner = raw_sec1(ec_key(&jwk).d().unwrap(), &specified);
            let parts = Pkcs8Parts {
                version: 0,
                alg: AlgId::Ec(EcCurve::P256),
                private_key: &inner,
                public_key: None,
            };
            assert_eq!(from_pkcs8(parts).unwrap_err(), Error::UnsupportedAlgorithm);
            // implicitCurve NULL as the inner [0] of PKCS#8 is InvalidKey.
            let inner = raw_sec1(ec_key(&jwk).d().unwrap(), &[0x05, 0x00]);
            let parts = Pkcs8Parts {
                version: 0,
                alg: AlgId::Ec(EcCurve::P256),
                private_key: &inner,
                public_key: None,
            };
            assert!(matches!(from_pkcs8(parts), Err(Error::InvalidKey(_))));
        }

        #[test]
        fn first_octet_gate_on_every_curve_and_form() {
            for (name, crv) in CURVE_OIDS {
                let der = fixtures::load("openssl", &format!("ec-{name}-sec1.der"));
                let jwk = from_sec1(&der).unwrap();
                let key = ec_key(&jwk);
                let d = key.d().unwrap().to_vec();
                let full = uncompressed_point(key);
                let sec1_of = |point: &[u8]| {
                    sec1::encode(&EcPrivateKey {
                        private_key: &d,
                        parameters: Some(crv),
                        public_key: Some(point),
                    })
                    .unwrap()
                    .to_vec()
                };
                let spki_of = |point: &[u8]| {
                    spki::encode(&SpkiParts {
                        alg: AlgId::Ec(crv),
                        subject_public_key: point,
                    })
                    .unwrap()
                    .to_vec()
                };
                // 0x02, 0x03 (compressed) and 0x04 are accepted.
                let mut comp = vec![0x02 | (key.y()[key.y().len() - 1] & 1)];
                comp.extend_from_slice(key.x());
                for point in [&full, &comp] {
                    assert!(from_sec1(&sec1_of(point)).is_ok(), "{name}");
                    assert!(spki::decode(&spki_of(point)).and_then(from_spki).is_ok());
                }
                // 0x00, 0x05, 0x06, 0x07 are rejected at full and compact
                // lengths, in SPKI and in SEC1 [1].
                for tag in [0x00u8, 0x05, 0x06, 0x07] {
                    for base in [&full, &comp] {
                        let mut point = base.clone();
                        point[0] = tag;
                        assert!(
                            matches!(
                                spki::decode(&spki_of(&point)).and_then(from_spki),
                                Err(Error::InvalidKey(_))
                            ),
                            "{name} {tag:#x} spki"
                        );
                        assert!(
                            matches!(from_sec1(&sec1_of(&point)), Err(Error::InvalidKey(_))),
                            "{name} {tag:#x} sec1"
                        );
                    }
                }
            }
        }

        #[test]
        fn rejection_order_is_length_then_point_then_range_when_a_point_is_embedded() {
            // Observed behaviour, pinned: wrong length beats a bad point; with an
            // embedded point the point is decoded before d's range is checked
            // (jwk.rs), without one d's range is checked first. All InvalidKey.
            let jwk = from_sec1(&fixtures::load("rfc", "rfc7517-a2-ec-p256-sec1.der")).unwrap();
            let mut bad_point = uncompressed_point(ec_key(&jwk));
            bad_point[64] ^= 1;
            let sec1_of = |d: &[u8], p: Option<&[u8]>| {
                sec1::encode(&EcPrivateKey {
                    private_key: d,
                    parameters: Some(EcCurve::P256),
                    public_key: p,
                })
                .unwrap()
                .to_vec()
            };
            let detail = |der: Vec<u8>| match from_sec1(&der) {
                Err(Error::InvalidKey(d)) => d,
                other => panic!("{other:?}"),
            };
            assert_eq!(
                detail(sec1_of(&[0; 31], Some(&bad_point))),
                PRIVATE_KEY_LENGTH
            );
            // d = 0 with a bad point and no point.
            assert_eq!(detail(sec1_of(&[0; 32], None)), SCALAR_INVALID);
            assert_eq!(detail(sec1_of(&[0; 32], Some(&bad_point))), POINT_INVALID);
        }
    }
}
