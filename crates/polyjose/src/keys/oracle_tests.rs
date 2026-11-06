//! Differential tests of the owned DER and PEM codecs against the RustCrypto
//! formats crates (`der`, `spki`, `pkcs8`, `sec1`, `pkcs1`, `pem-rfc7468`),
//! which are dev-dependencies only (ADR 0016 §5, ADR 0018 §1), and
//! canonicality properties: whatever is accepted re-encodes byte for byte
//! (X.690 §10, RFC 7468 §3).
//!
//! The oracle of a key container is the formats crate's `from_der` for its
//! structure, plus the primitive crates' own point and scalar decoding
//! (`p256`/`p384`/`p521`/`k256` `PublicKey::from_sec1_bytes` and
//! `SecretKey::from_slice`, `ed25519-dalek`, `x25519-dalek`) for what the
//! structure carries. The oracle validates only what it can determine: a
//! key whose algorithm or curve it does not know, or whose curve is
//! missing, is accepted as parsed. Every place polyjose is stricter than
//! that oracle is listed in this file with its ADR 0018 reason, and the
//! lists are exact: a listed case the oracle starts rejecting fails too.
//!
//! # Where polyjose and the oracles differ (all deliberate)
//!
//! - **polyjose stricter, key containers:** the negative vectors in
//!   `NEGATIVE_STRICTER_THAN_ORACLE` (template-exact AlgorithmIdentifiers,
//!   unsupported OIDs and curves, minimal OID subidentifiers, exact scalar
//!   lengths, the SEC1 `[0]` requirement, embedded-key and curve
//!   consistency, RSA key strength, no RSA private keys) and the `reject-*`
//!   fixtures in `REJECT_FIXTURES_STRICTER_THAN_ORACLE`. Each entry carries
//!   its ADR 0018 reason; the lists are exact.
//! - **polyjose stricter, PEM:** no explanatory text before the block, only
//!   the exact upper-case key labels, any other label refused from the
//!   BEGIN line (`PEM_VECTOR_DIFFERENCES`).
//! - **polyjose more lenient, PEM:** any whitespace around the block
//!   (ADR 0018 §2); `check_pem` proves the trimmed block decodes alike in
//!   `pem-rfc7468`, so this is the only leniency.
//! - **DER readers:** a BIT STRING key must have no unused bits; OBJECT
//!   IDENTIFIERs `const-oid` cannot represent (arc 2.40+, subidentifiers
//!   above 2^32 − 1, more than 39 octets) are read but only ever compared
//!   with templates (`oid_beyond_const_oid`, T02 tester's note).
//! - **Encodings:** none. polyjose's SPKI, SEC1, PKCS#8 and PEM output is
//!   byte for byte what the formats crates write, including the PKCS#8
//!   ECPrivateKey without `[0]`, which RustCrypto's `elliptic-curve` writes
//!   too.
//!
//! The oracle crates are reached by absolute paths (`::der`, `::pkcs8`,
//! `::spki`, `::sec1`, `::pkcs1`), polyjose's own codecs by `super::` paths,
//! so the two are never confused. Only the public-key types of `pkcs1` are
//! used (ADR 0021).

use ::der::asn1::{ObjectIdentifier, OctetStringRef};
use ::der::{Decode as _, Encode as _};
use p256::elliptic_curve::sec1::{FromSec1Point, ModulusSize, ToSec1Point};
use p256::elliptic_curve::{AffinePoint, CurveArithmetic, FieldBytesSize, PublicKey, SecretKey};

use super::der::{Reader, fixtures};
use super::oid;
use super::types::{AlgId, Label};
use crate::error::{Error, Result};
use crate::jwk::{EcCurve, Jwk, KeyMaterial, OkpCurve};

// ---------------------------------------------------------------------------
// Containers, polyjose's decoders and the oracles
// ---------------------------------------------------------------------------

/// The four DER containers of ADR 0018 §3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// PKCS#8 OneAsymmetricKey (RFC 5958 §2).
    Pkcs8,
    /// SubjectPublicKeyInfo (RFC 5280 §4.1.2.7).
    Spki,
    /// SEC1 ECPrivateKey (RFC 5915 §3).
    Sec1,
    /// PKCS#1 RSAPublicKey (RFC 8017 App. A.1.1).
    Pkcs1,
}

impl Kind {
    const ALL: [Kind; 4] = [Kind::Pkcs8, Kind::Spki, Kind::Sec1, Kind::Pkcs1];

    /// The container a fixture file holds, from its name.
    fn of_file(name: &str) -> Kind {
        if name.contains("pkcs8") {
            Kind::Pkcs8
        } else if name.contains("spki") {
            Kind::Spki
        } else if name.contains("sec1") {
            Kind::Sec1
        } else if name.contains("pkcs1") {
            Kind::Pkcs1
        } else {
            panic!("{name}: no container in the name")
        }
    }

    /// The container a PEM label announces (RFC 7468 §10, §13; RFC 5915 §4;
    /// OpenSSL's `RSA PUBLIC KEY`), for the labels polyjose decodes.
    fn of_label(label: Label) -> Option<Kind> {
        match label {
            Label::PrivateKey => Some(Kind::Pkcs8),
            Label::PublicKey => Some(Kind::Spki),
            Label::EcPrivateKey => Some(Kind::Sec1),
            Label::RsaPublic => Some(Kind::Pkcs1),
            Label::RsaPrivate | Label::EncryptedPrivateKey | Label::Other => None,
        }
    }
}

/// polyjose's whole import path for one container, as the facade (T08)
/// will run it: the container codec, then the key mapper of its classified
/// algorithm, which builds the JWK through `Jwk::from_object`.
fn our_import(kind: Kind, der: &[u8]) -> Result<Jwk> {
    match kind {
        Kind::Pkcs8 => {
            let parts = super::pkcs8::decode(der)?;
            match parts.alg {
                AlgId::Ec(_) => super::ec::from_pkcs8(parts),
                AlgId::Ed25519 | AlgId::X25519 => super::okp::from_pkcs8(parts),
                // pkcs8::decode already refuses it (ADR 0021).
                AlgId::RsaEncryption => Err(Error::UnsupportedAlgorithm),
            }
        }
        Kind::Spki => {
            let parts = super::spki::decode(der)?;
            match parts.alg {
                AlgId::Ec(_) => super::ec::from_spki(parts),
                AlgId::Ed25519 | AlgId::X25519 => super::okp::from_spki(parts),
                AlgId::RsaEncryption => super::rsa::from_spki(parts),
            }
        }
        Kind::Sec1 => super::ec::from_sec1(der),
        Kind::Pkcs1 => super::rsa::from_pkcs1(der),
    }
}

/// The fields of a container that both sides can name, as owned octets.
///
/// `algorithm` is the whole AlgorithmIdentifier encoding (RFC 5280
/// §4.1.1.2), so it compares the OID and the parameters at once. The
/// PKCS#8 `[0]` attributes are not compared: polyjose checks and ignores
/// them (ADR 0018 §3) and the `pkcs8` oracle skips them.
#[derive(Debug, Default, PartialEq, Eq)]
struct Fields {
    /// PKCS#8 `version` (RFC 5958 §2).
    version: Option<u8>,
    /// PKCS#8 `privateKeyAlgorithm` or SPKI `algorithm`.
    algorithm: Option<Vec<u8>>,
    /// PKCS#8 `privateKey` OCTET STRING contents.
    private_key: Option<Vec<u8>>,
    /// PKCS#8 `[1]` publicKey or SPKI `subjectPublicKey`, whole octets.
    public_key: Option<Vec<u8>>,
    /// The SEC1 ECPrivateKey: standalone, or inside a PKCS#8 EC key.
    ec: Option<EcFields>,
    /// The RFC 8410 §7 CurvePrivateKey inside a PKCS#8 OKP key.
    curve_private_key: Option<Vec<u8>>,
    /// The RSAPublicKey modulus and exponent magnitudes (RFC 8017 A.1.1).
    rsa: Option<(Vec<u8>, Vec<u8>)>,
}

/// The fields of an ECPrivateKey (RFC 5915 §3).
#[derive(Debug, PartialEq, Eq)]
struct EcFields {
    private_key: Vec<u8>,
    /// The `[0]` namedCurve OBJECT IDENTIFIER, whole encoding.
    parameters: Option<Vec<u8>>,
    /// The `[1]` publicKey, whole octets.
    public_key: Option<Vec<u8>>,
}

/// [`Fields`] as polyjose's codecs read them.
fn our_fields(kind: Kind, der: &[u8]) -> Result<Fields> {
    let mut fields = Fields::default();
    match kind {
        Kind::Pkcs8 => {
            let parts = super::pkcs8::decode(der)?;
            fields.version = Some(parts.version);
            fields.algorithm = Some(oid::algorithm_identifier(parts.alg).to_vec());
            fields.private_key = Some(parts.private_key.to_vec());
            fields.public_key = parts.public_key.map(<[u8]>::to_vec);
            match parts.alg {
                AlgId::Ec(_) => fields.ec = Some(our_ec_fields(parts.private_key)?),
                AlgId::Ed25519 | AlgId::X25519 => {
                    let mut reader = Reader::new(parts.private_key)?;
                    let d = reader.octet_string()?;
                    reader.finish()?;
                    fields.curve_private_key = Some(d.to_vec());
                }
                AlgId::RsaEncryption => return Err(Error::UnsupportedAlgorithm),
            }
        }
        Kind::Spki => {
            let parts = super::spki::decode(der)?;
            fields.algorithm = Some(oid::algorithm_identifier(parts.alg).to_vec());
            fields.public_key = Some(parts.subject_public_key.to_vec());
            if parts.alg == AlgId::RsaEncryption {
                let key = super::pkcs1::decode_public(parts.subject_public_key)?;
                fields.rsa = Some((key.n.to_vec(), key.e.to_vec()));
            }
        }
        Kind::Sec1 => fields.ec = Some(our_ec_fields(der)?),
        Kind::Pkcs1 => {
            let key = super::pkcs1::decode(der)?;
            fields.rsa = Some((key.n.to_vec(), key.e.to_vec()));
        }
    }
    Ok(fields)
}

fn our_ec_fields(der: &[u8]) -> Result<EcFields> {
    let key = super::sec1::decode(der)?;
    Ok(EcFields {
        private_key: key.private_key.to_vec(),
        parameters: key.parameters.map(|crv| oid::named_curve(crv).to_vec()),
        public_key: key.public_key.map(<[u8]>::to_vec),
    })
}

// The OIDs, written out from their RFCs (not from `oid.rs`), so the oracle
// side does not borrow polyjose's byte templates.
/// id-ecPublicKey (RFC 5480 §2.1.1).
const ID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// secp256r1 (RFC 5480 §2.1.1.1).
const SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
/// secp384r1 (RFC 5480 §2.1.1.1).
const SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
/// secp521r1 (RFC 5480 §2.1.1.1).
const SECP521R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");
/// secp256k1 (SEC 2 v2 App. A.2.1; RFC 8812 §3.1).
const SECP256K1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.10");
/// id-X25519 (RFC 8410 §3).
const ID_X25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.110");
/// id-Ed25519 (RFC 8410 §3).
const ID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
/// rsaEncryption (RFC 3279 §2.3.1, RFC 8017 App. A.1).
const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

fn curve_oid(crv: EcCurve) -> ObjectIdentifier {
    match crv {
        EcCurve::P256 => SECP256R1,
        EcCurve::P384 => SECP384R1,
        EcCurve::P521 => SECP521R1,
        EcCurve::Secp256k1 => SECP256K1,
    }
}

fn curve_of_oid(named: &ObjectIdentifier) -> Option<EcCurve> {
    [
        EcCurve::P256,
        EcCurve::P384,
        EcCurve::P521,
        EcCurve::Secp256k1,
    ]
    .into_iter()
    .find(|crv| curve_oid(*crv) == *named)
}

/// An oracle error, as text. Only the oracle's own message, never input.
type OracleResult<T> = core::result::Result<T, String>;

fn oracle_err(e: impl core::fmt::Display) -> String {
    e.to_string()
}

/// [`Fields`] as the formats crates read them: `pkcs8::PrivateKeyInfoRef`,
/// `spki::SubjectPublicKeyInfoRef`, `sec1::EcPrivateKey` and
/// `pkcs1::RsaPublicKeyRef`, each through its strict `from_der`. A BIT
/// STRING key must be whole octets (`BitStringRef::as_bytes`), as the
/// RustCrypto key crates require too.
fn oracle_fields(kind: Kind, der: &[u8]) -> OracleResult<Fields> {
    let mut fields = Fields::default();
    match kind {
        Kind::Pkcs8 => {
            let info = ::pkcs8::PrivateKeyInfoRef::from_der(der).map_err(oracle_err)?;
            fields.version = Some(u8::from(info.version()));
            fields.algorithm = Some(info.algorithm.to_der().map_err(oracle_err)?);
            let private_key = info.private_key.as_bytes();
            fields.private_key = Some(private_key.to_vec());
            fields.public_key = info
                .public_key
                .map(|key| key.as_bytes().map(<[u8]>::to_vec).ok_or("unused bits"))
                .transpose()?;
            let alg = info.algorithm.oid;
            if alg == ID_EC_PUBLIC_KEY {
                fields.ec = Some(oracle_ec_fields(private_key)?);
            } else if alg == ID_ED25519 || alg == ID_X25519 {
                let d = <&OctetStringRef>::from_der(private_key).map_err(oracle_err)?;
                fields.curve_private_key = Some(d.as_bytes().to_vec());
            }
        }
        Kind::Spki => {
            let info = ::spki::SubjectPublicKeyInfoRef::from_der(der).map_err(oracle_err)?;
            fields.algorithm = Some(info.algorithm.to_der().map_err(oracle_err)?);
            let key = info.subject_public_key.as_bytes().ok_or("unused bits")?;
            fields.public_key = Some(key.to_vec());
            if info.algorithm.oid == RSA_ENCRYPTION {
                fields.rsa = Some(oracle_rsa(key)?);
            }
        }
        Kind::Sec1 => fields.ec = Some(oracle_ec_fields(der)?),
        Kind::Pkcs1 => fields.rsa = Some(oracle_rsa(der)?),
    }
    Ok(fields)
}

fn oracle_ec_fields(der: &[u8]) -> OracleResult<EcFields> {
    let key = ::sec1::EcPrivateKey::from_der(der).map_err(oracle_err)?;
    let parameters = key
        .parameters
        .map(|parameters| {
            parameters
                .named_curve()
                .ok_or_else(|| "not a namedCurve".to_owned())
                .and_then(|named| named.to_der().map_err(oracle_err))
        })
        .transpose()?;
    Ok(EcFields {
        private_key: key.private_key.to_vec(),
        parameters,
        public_key: key.public_key.map(<[u8]>::to_vec),
    })
}

fn oracle_rsa(der: &[u8]) -> OracleResult<(Vec<u8>, Vec<u8>)> {
    let key = ::pkcs1::RsaPublicKeyRef::from_der(der).map_err(oracle_err)?;
    Ok((
        key.modulus.as_bytes().to_vec(),
        key.public_exponent.as_bytes().to_vec(),
    ))
}

/// The key values of a JWK, or of what the oracle decoded.
#[derive(Debug, PartialEq, Eq)]
enum Values {
    Ec {
        crv: EcCurve,
        x: Vec<u8>,
        y: Vec<u8>,
        d: Option<Vec<u8>>,
    },
    Okp {
        crv: OkpCurve,
        x: Vec<u8>,
        d: Option<Vec<u8>>,
    },
    Rsa {
        n: Vec<u8>,
        e: Vec<u8>,
    },
}

fn values_of(jwk: &Jwk) -> Values {
    match jwk.material() {
        KeyMaterial::Ec(key) => Values::Ec {
            crv: key.crv(),
            x: key.x().to_vec(),
            y: key.y().to_vec(),
            d: key.d().map(<[u8]>::to_vec),
        },
        KeyMaterial::Okp(key) => Values::Okp {
            crv: key.crv(),
            x: key.x().to_vec(),
            d: key.d().map(<[u8]>::to_vec),
        },
        KeyMaterial::Rsa(key) => Values::Rsa {
            n: key.n().to_vec(),
            e: key.e().to_vec(),
        },
        other => panic!("not a PEM/DER key type: {:?}", other.key_type()),
    }
}

/// The algorithm an AlgorithmIdentifier names, as the oracle sees it: the
/// OID, and for id-ecPublicKey the namedCurve if the parameters hold one.
enum OracleAlg {
    /// id-ecPublicKey; `None` when the parameters are absent, not an OID,
    /// or a curve outside the JOSE set.
    Ec(Option<EcCurve>),
    Ed25519,
    X25519,
    Rsa,
    Other,
}

fn oracle_alg(algorithm: &[u8]) -> OracleResult<OracleAlg> {
    let alg = ::spki::AlgorithmIdentifierRef::from_der(algorithm).map_err(oracle_err)?;
    Ok(if alg.oid == ID_EC_PUBLIC_KEY {
        let named = alg
            .parameters
            .and_then(|parameters| parameters.decode_as::<ObjectIdentifier>().ok());
        OracleAlg::Ec(named.as_ref().and_then(curve_of_oid))
    } else if alg.oid == ID_ED25519 {
        OracleAlg::Ed25519
    } else if alg.oid == ID_X25519 {
        OracleAlg::X25519
    } else if alg.oid == RSA_ENCRYPTION {
        OracleAlg::Rsa
    } else {
        OracleAlg::Other
    })
}

/// Affine coordinates (x, y), each the curve's full coordinate length.
type Affine = (Vec<u8>, Vec<u8>);

/// A SEC1 point through the curve crate (SEC 1 v2 §2.3.4):
/// `PublicKey::from_sec1_bytes`, then its affine coordinates.
fn point_on<C>(octets: &[u8]) -> OracleResult<Affine>
where
    C: CurveArithmetic,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: ModulusSize,
{
    let public = PublicKey::<C>::from_sec1_bytes(octets).map_err(|_| "point rejected")?;
    affine(&public)
}

fn affine<C>(public: &PublicKey<C>) -> OracleResult<Affine>
where
    C: CurveArithmetic,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: ModulusSize,
{
    let point = public.to_sec1_point(false);
    match (point.x(), point.y()) {
        (Some(x), Some(y)) => Ok((x.to_vec(), y.to_vec())),
        _ => Err("identity".to_owned()),
    }
}

/// A private scalar through the curve crate: `SecretKey::from_slice`
/// (which left-pads short inputs and range-checks d ∈ [1, n − 1]), then
/// its canonical bytes and d·G.
fn secret_on<C>(d: &[u8]) -> OracleResult<(Vec<u8>, Affine)>
where
    C: CurveArithmetic,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: ModulusSize,
{
    let secret = SecretKey::<C>::from_slice(d).map_err(|_| "scalar rejected")?;
    Ok((secret.to_bytes().to_vec(), affine(&secret.public_key())?))
}

fn oracle_point(crv: EcCurve, octets: &[u8]) -> OracleResult<Affine> {
    match crv {
        EcCurve::P256 => point_on::<p256::NistP256>(octets),
        EcCurve::P384 => point_on::<p384::NistP384>(octets),
        EcCurve::P521 => point_on::<p521::NistP521>(octets),
        EcCurve::Secp256k1 => point_on::<k256::Secp256k1>(octets),
    }
}

fn oracle_secret(crv: EcCurve, d: &[u8]) -> OracleResult<(Vec<u8>, Affine)> {
    match crv {
        EcCurve::P256 => secret_on::<p256::NistP256>(d),
        EcCurve::P384 => secret_on::<p384::NistP384>(d),
        EcCurve::P521 => secret_on::<p521::NistP521>(d),
        EcCurve::Secp256k1 => secret_on::<k256::Secp256k1>(d),
    }
}

/// An EC private key as the oracle sees it: the scalar through the curve
/// crate, and the embedded point (if any) through the curve crate, without
/// checking that the two agree (that is polyjose policy, ADR 0018 §3).
fn oracle_ec_private(crv: EcCurve, d: &[u8], embedded: Option<&[u8]>) -> OracleResult<Values> {
    let (d, derived) = oracle_secret(crv, d)?;
    let (x, y) = match embedded {
        Some(octets) => oracle_point(crv, octets)?,
        None => derived,
    };
    Ok(Values::Ec {
        crv,
        x,
        y,
        d: Some(d),
    })
}

/// An Ed25519 or X25519 key as the oracle sees it: the 32-octet secret
/// (RFC 8032 §5.1.5, RFC 7748 §5) and the embedded or derived public key,
/// an Ed25519 one through `VerifyingKey::from_bytes` (RFC 8032 §5.1.3).
fn oracle_okp(crv: OkpCurve, d: Option<&[u8]>, x: Option<&[u8]>) -> OracleResult<Values> {
    let d: Option<[u8; 32]> = d
        .map(|d| d.try_into().map_err(|_| "secret is not 32 octets"))
        .transpose()?;
    let x: Option<[u8; 32]> = x
        .map(|x| x.try_into().map_err(|_| "public key is not 32 octets"))
        .transpose()?;
    let x = match (crv, x, d) {
        (OkpCurve::Ed25519, Some(x), _) => ed25519_dalek::VerifyingKey::from_bytes(&x)
            .map_err(oracle_err)?
            .to_bytes(),
        (OkpCurve::Ed25519, None, Some(d)) => ed25519_dalek::SigningKey::from_bytes(&d)
            .verifying_key()
            .to_bytes(),
        (OkpCurve::X25519, Some(x), _) => x,
        (OkpCurve::X25519, None, Some(d)) => {
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(d)).to_bytes()
        }
        (_, None, None) => return Err("no key".to_owned()),
    };
    Ok(Values::Okp {
        crv,
        x: x.to_vec(),
        d: d.map(|d| d.to_vec()),
    })
}

/// The oracle's verdict on a container: `Err` if the formats crate or a
/// primitive rejects it, `Ok(None)` if it parsed but names an algorithm or
/// curve the oracle cannot check, `Ok(Some(values))` otherwise.
fn oracle_key(kind: Kind, der: &[u8]) -> OracleResult<Option<Values>> {
    let fields = oracle_fields(kind, der)?;
    let alg = match &fields.algorithm {
        Some(algorithm) => Some(oracle_alg(algorithm)?),
        None => None,
    };
    let values = match (kind, alg) {
        (Kind::Pkcs8, Some(OracleAlg::Ec(Some(crv)))) => {
            let ec = fields.ec.as_ref().ok_or("no ECPrivateKey")?;
            let embedded = fields.public_key.as_deref().or(ec.public_key.as_deref());
            Some(oracle_ec_private(crv, &ec.private_key, embedded)?)
        }
        (Kind::Pkcs8, Some(OracleAlg::Ed25519)) => Some(oracle_okp(
            OkpCurve::Ed25519,
            fields.curve_private_key.as_deref(),
            fields.public_key.as_deref(),
        )?),
        (Kind::Pkcs8, Some(OracleAlg::X25519)) => Some(oracle_okp(
            OkpCurve::X25519,
            fields.curve_private_key.as_deref(),
            fields.public_key.as_deref(),
        )?),
        (Kind::Spki, Some(OracleAlg::Ec(Some(crv)))) => {
            let (x, y) = oracle_point(crv, fields.public_key.as_deref().unwrap_or_default())?;
            Some(Values::Ec { crv, x, y, d: None })
        }
        (Kind::Spki, Some(OracleAlg::Ed25519)) => Some(oracle_okp(
            OkpCurve::Ed25519,
            None,
            fields.public_key.as_deref(),
        )?),
        (Kind::Spki, Some(OracleAlg::X25519)) => Some(oracle_okp(
            OkpCurve::X25519,
            None,
            fields.public_key.as_deref(),
        )?),
        (Kind::Spki, Some(OracleAlg::Rsa)) | (Kind::Pkcs1, None) => {
            let (n, e) = fields.rsa.ok_or("no RSAPublicKey")?;
            Some(Values::Rsa { n, e })
        }
        (Kind::Sec1, None) => {
            let ec = fields.ec.as_ref().ok_or("no ECPrivateKey")?;
            let named = match &ec.parameters {
                Some(named) => Some(ObjectIdentifier::from_der(named).map_err(oracle_err)?),
                None => None,
            };
            match named.as_ref().and_then(curve_of_oid) {
                Some(crv) => Some(oracle_ec_private(
                    crv,
                    &ec.private_key,
                    ec.public_key.as_deref(),
                )?),
                None => None,
            }
        }
        // An unknown OID or curve, a curve missing from the parameters, or
        // an RSA private key in PKCS#8: parsed, not checkable.
        _ => None,
    };
    Ok(values)
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A fixture's raw bytes.
fn raw(dir: &str, name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/keys")
        .join(dir)
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The positive key fixtures (OpenSSL 4 output and RFC vectors): every
/// `.der`/`.pem` file in `openssl/` and `rfc/` not named `reject-*`.
fn positive_fixtures() -> Vec<(&'static str, String)> {
    ["openssl", "rfc"]
        .into_iter()
        .flat_map(|dir| {
            fixtures::files(dir, |name| !name.starts_with("reject-"))
                .into_iter()
                .map(move |name| (dir, name))
        })
        .collect()
}

/// A positive fixture as DER. A PEM file is decoded by both `pem::decode`
/// and `pem-rfc7468`, which must agree on the label and the octets.
fn load_positive(dir: &str, name: &str) -> Vec<u8> {
    let bytes = raw(dir, name);
    if !name.ends_with(".pem") {
        return bytes;
    }
    let text = core::str::from_utf8(&bytes).unwrap();
    let (label, der) = super::pem::decode(text).unwrap_or_else(|e| panic!("{name}: {e:?}"));
    let (oracle_label, oracle_der) =
        pem_rfc7468::decode_vec(&bytes).unwrap_or_else(|e| panic!("{name}: oracle: {e}"));
    assert_eq!(label.as_str(), Some(oracle_label), "{dir}/{name}: label");
    assert_eq!(*der, oracle_der, "{dir}/{name}: octets");
    assert_eq!(
        Kind::of_label(label),
        Some(Kind::of_file(name)),
        "{dir}/{name}: label and container"
    );
    der.to_vec()
}

// ---------------------------------------------------------------------------
// Acceptance agreement
// ---------------------------------------------------------------------------

/// Every positive fixture decodes in the oracle crates too, with the same
/// AlgorithmIdentifier (OID and parameters), private key octets, public key
/// bits, SEC1 `[0]`/`[1]` and RSA modulus and exponent as polyjose's codecs
/// read; and the key polyjose imports has the values the primitive crates
/// decode from the same octets.
#[test]
fn positive_fixtures_decode_to_the_same_fields_in_the_oracles() {
    let fixtures = positive_fixtures();
    for (dir, name) in &fixtures {
        let der = load_positive(dir, name);
        let kind = Kind::of_file(name);
        let ours = our_fields(kind, &der).unwrap_or_else(|e| panic!("{dir}/{name}: {e:?}"));
        let theirs = oracle_fields(kind, &der).unwrap_or_else(|e| panic!("{dir}/{name}: {e}"));
        assert_eq!(ours, theirs, "{dir}/{name}");

        let jwk = our_import(kind, &der).unwrap_or_else(|e| panic!("{dir}/{name}: {e:?}"));
        let values = oracle_key(kind, &der)
            .unwrap_or_else(|e| panic!("{dir}/{name}: oracle: {e}"))
            .unwrap_or_else(|| panic!("{dir}/{name}: the oracle cannot check it"));
        assert_eq!(values_of(&jwk), values, "{dir}/{name}");
    }
    // 47 OpenSSL files and 28 RFC files; a guard against a vacuous pass if
    // the layout changes.
    assert_eq!(fixtures.len(), 75, "{fixtures:?}");
}

// ---------------------------------------------------------------------------
// No laxer than the oracle
// ---------------------------------------------------------------------------

/// One entry of `negative/manifest.json`, with the fixture it mutates.
struct NegativeEntry {
    id: String,
    file: String,
    base: String,
    expect: String,
}

fn negative_entries() -> Vec<NegativeEntry> {
    let manifest = crate::json::parse(&raw("negative", "manifest.json")).unwrap();
    let field = |entry: &crate::json::Value, name: &str| {
        entry
            .get(name)
            .and_then(crate::json::Value::as_str)
            .unwrap()
            .to_owned()
    };
    manifest
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| NegativeEntry {
            id: field(entry, "id"),
            file: field(entry, "file"),
            base: field(entry, "base"),
            expect: field(entry, "expect"),
        })
        .collect()
}

/// The container a negative DER vector is, from the fixture it mutates.
/// N67 turns the RFC 7517 RSA SPKI into a PKCS#8 with rsaEncryption; N68
/// and N69 are a PKCS#1 RSAPrivateKey read as PKCS#8 and as SEC1 (ADR 0018
/// §3, ADR 0021).
fn negative_kind(entry: &NegativeEntry) -> Kind {
    match entry.id.as_str() {
        "N67" | "N68" => Kind::Pkcs8,
        "N69" => Kind::Sec1,
        _ => Kind::of_file(&entry.base),
    }
}

/// Whether a negative vector's base is an RSA private key fixture in
/// `openssl/` (N68, N69, P17, P18): such a vector has no private key the
/// marker test could look for, and its octets are checked by
/// `rsa_private_key_octets_never_reach_an_error` instead.
fn has_rsa_private_base(entry: &NegativeEntry) -> bool {
    entry.base.starts_with("reject-rsa") && entry.base.contains("-private-")
}

/// Whether `result` is the error code a manifest `expect` names.
fn has_code<T>(result: &Result<T>, expect: &str) -> bool {
    matches!(
        (result, expect),
        (Err(Error::InvalidKey(_)), "InvalidKey")
            | (Err(Error::UnsupportedAlgorithm), "UnsupportedAlgorithm")
    )
}

/// The negative DER vectors the oracle of this file accepts, each a place
/// where polyjose is deliberately stricter, with the reason. The oracle
/// accepts what the formats crate parses and the primitive crates can
/// decode; the rules below are polyjose policy on top (ADR 0018).
const NEGATIVE_STRICTER_THAN_ORACLE: &[(&str, &str)] = &[
    (
        "N20",
        "id-Ed25519 with NULL parameters: RFC 8410 §3 \"the parameters MUST be absent\"; \
         AlgorithmIdentifiers match their template byte for byte (ADR 0018 §2, §4 step 3)",
    ),
    (
        "N21",
        "id-Ed448: not a JOSE curve, UnsupportedAlgorithm (ADR 0018 §4 step 1)",
    ),
    (
        "N22",
        "OID subidentifier with a leading 0x80 octet: X.690 §8.19.2 requires the fewest \
         octets; const-oid 0.10 decodes it (ADR 0018 §2 minimal OID subidentifiers)",
    ),
    (
        "N32",
        "id-ecPublicKey without parameters: RFC 5480 §2.1.1 parameters \"MUST always be \
         present\" as a namedCurve (ADR 0018 §4 step 3)",
    ),
    (
        "N33",
        "namedCurve secp224r1: not a JOSE curve, UnsupportedAlgorithm (ADR 0018 §4 step 2)",
    ),
    (
        "N37",
        "id-ecPublicKey with NULL (implicitCurve) parameters: RFC 5480 §2.1.1 \"MUST NOT be \
         used in PKIX\" (ADR 0018 §4 step 3)",
    ),
    (
        "N43",
        "a 31-octet EC privateKey: RFC 5915 §3 fixes ceiling(log2(n)/8) octets and RFC 7518 \
         §6.2.2.1 the full coordinate length; SecretKey::from_slice left-pads it \
         (ADR 0018 §2 strict acceptance, §3 validation)",
    ),
    (
        "N46",
        "standalone EC PRIVATE KEY without [0]: RFC 5915 §3 \"MUST always include the \
         parameters field\"; without it the curve is unknown (ADR 0018 §3 table)",
    ),
    (
        "N50",
        "inner ECPrivateKey [0] names another curve than the PKCS#8 AlgorithmIdentifier: \
         RFC 5915 §1 and ADR 0018 §3 consistency (\"SEC1 [0] must equal the PKCS#8 \
         AlgorithmIdentifier curve\")",
    ),
    (
        "N52",
        "inner ECPrivateKey [1] is another key's point: an embedded publicKey must be the \
         one derived from the private key (ADR 0018 §3 consistency, ADR 0043 §3)",
    ),
    (
        "N60",
        "rsaEncryption without NULL parameters: RFC 3279 §2.3.1 \"MUST have ASN.1 type \
         NULL\" (ADR 0018 §4 step 3)",
    ),
    (
        "N63",
        "publicExponent 1: RFC 8017 §3.1 needs an odd e with 3 <= e < n, checked by \
         Jwk::from_object (ADR 0018 §3 validation); the oracle has no RSA primitive",
    ),
    (
        "N64",
        "a 1024-bit modulus: RFC 7518 §3.3 and §4.2 need at least 2048 bits (ADR 0007, \
         ADR 0018 §3 validation); the oracle has no RSA primitive",
    ),
    (
        "N67",
        "PKCS#8 with rsaEncryption: no RSA private keys, UnsupportedAlgorithm before \
         privateKey is opened (ADR 0021, ADR 0018 §4)",
    ),
];

/// Every `negative/` DER vector (50, N01–N69) is rejected by polyjose's import
/// path with its manifest error code; the ones the oracle accepts are
/// exactly [`NEGATIVE_STRICTER_THAN_ORACLE`].
#[test]
fn negative_vectors_are_rejected_and_every_oracle_acceptance_is_listed() {
    let mut oracle_accepts = Vec::new();
    let mut count = 0;
    for entry in negative_entries()
        .iter()
        .filter(|e| e.file.ends_with(".der"))
    {
        let der = raw("negative", &entry.file);
        let kind = negative_kind(entry);
        let ours = our_import(kind, &der);
        assert!(
            has_code(&ours, &entry.expect),
            "{}: expected {}, got {:?}",
            entry.id,
            entry.expect,
            ours.map(|_| "a key")
        );
        if let Ok(values) = oracle_key(kind, &der) {
            oracle_accepts.push((entry.id.clone(), values.is_some()));
        }
        count += 1;
    }
    let listed: Vec<&str> = NEGATIVE_STRICTER_THAN_ORACLE
        .iter()
        .map(|(id, _)| *id)
        .collect();
    let accepted: Vec<&str> = oracle_accepts.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(accepted, listed, "{oracle_accepts:?}");
    // N01–N12, N20–N27, N30–N38, N40–N47, N50–N52, N60–N69.
    assert_eq!(count, 50);
}

/// polyjose's verdict on a `reject-*` fixture through the whole path: PEM
/// (label classified from the BEGIN line, ADR 0018 §2), then the container
/// the label names; a `.der` file goes straight to the container in its
/// name.
fn our_import_file(name: &str, bytes: &[u8]) -> Result<Jwk> {
    if !name.ends_with(".pem") {
        return our_import(Kind::of_file(name), bytes);
    }
    let text = core::str::from_utf8(bytes).map_err(|_| Error::InvalidKey("not UTF-8"))?;
    let (label, der) = super::pem::decode(text)?;
    let kind = Kind::of_label(label).ok_or(Error::UnsupportedAlgorithm)?;
    our_import(kind, &der)
}

/// The oracle's verdict on the same file: `pem-rfc7468`, then the formats
/// crate of the label. `Ok(false)` when the PEM decodes but its label names
/// a structure without a key oracle here (`CERTIFICATE`, `ENCRYPTED
/// PRIVATE KEY`, `RSA PRIVATE KEY`).
fn oracle_file(name: &str, bytes: &[u8]) -> OracleResult<bool> {
    if !name.ends_with(".pem") {
        return oracle_key(Kind::of_file(name), bytes).map(|_| true);
    }
    let (label, der) = pem_rfc7468::decode_vec(bytes).map_err(oracle_err)?;
    match Kind::of_label(Label::from_text(label)) {
        Some(kind) => oracle_key(kind, &der).map(|_| true),
        None => Ok(false),
    }
}

// The reasons polyjose rejects what the oracle accepts in `reject-*`.
const WHY_CURVE: &str = "a namedCurve outside the JOSE set (RFC 7518 §6.2.1.1, RFC 8812 §3.1): UnsupportedAlgorithm (ADR 0018 §4 step 2)";
const WHY_CERT: &str = "a CERTIFICATE label names no key structure: refused from the BEGIN line, UnsupportedAlgorithm (ADR 0018 §2, §4); pem-rfc7468 decodes any label";
const WHY_EXPLICIT: &str = "specifiedCurve parameters: RFC 5480 §2.1.1 \"MUST NOT be used in PKIX\", UnsupportedAlgorithm (ADR 0018 §4 step 2)";
const WHY_ENC: &str = "ENCRYPTED PRIVATE KEY (RFC 5958 §3): encrypted PKCS#8 is unsupported, refused from the BEGIN line (ADR 0018 §2, §4)";
const WHY_X448: &str =
    "Ed448/X448 (RFC 8410 §3): not JOSE curves in 0.1.0, UnsupportedAlgorithm (ADR 0018 §4 step 1)";
const WHY_RSA1024: &str = "a 1024-bit RSA modulus: RFC 7518 §3.3 and §4.2 need at least 2048 bits (ADR 0007, ADR 0018 §3 validation); the oracle has no RSA primitive";
const WHY_RSAPRIV: &str =
    "an RSA private key: unsupported, UnsupportedAlgorithm (ADR 0021, ADR 0018 §4)";
const WHY_RSAPRIVPEM: &str = "RSA PRIVATE KEY: no RSA private keys, refused from the BEGIN line so the body is never decoded (ADR 0021, ADR 0018 §2)";
const WHY_PSS: &str = "id-RSASSA-PSS (RFC 4055 §3.1): an unsupported key OID, UnsupportedAlgorithm (ADR 0018 §4 step 1)";

/// The `reject-*` fixtures the oracle accepts, each a place where polyjose
/// is deliberately stricter: whole classes of keys it does not support.
const REJECT_FIXTURES_STRICTER_THAN_ORACLE: &[(&str, &str)] = &[
    ("reject-ec-brainpoolp256r1-pkcs8.pem", WHY_CURVE),
    ("reject-ec-brainpoolp256r1-spki.pem", WHY_CURVE),
    ("reject-ec-p256-cert.pem", WHY_CERT),
    ("reject-ec-p256-explicit-pkcs8.pem", WHY_EXPLICIT),
    ("reject-ec-p256-explicit-spki.pem", WHY_EXPLICIT),
    ("reject-ec-p256-pkcs8-encrypted.pem", WHY_ENC),
    ("reject-ed25519-pkcs8-encrypted.pem", WHY_ENC),
    ("reject-ed448-pkcs8.pem", WHY_X448),
    ("reject-ed448-spki.pem", WHY_X448),
    ("reject-rsa1024-pkcs1-pub.pem", WHY_RSA1024),
    ("reject-rsa1024-private-pkcs8.pem", WHY_RSAPRIV),
    ("reject-rsa1024-spki.pem", WHY_RSA1024),
    ("reject-rsa2048-3prime-private-pkcs1.pem", WHY_RSAPRIVPEM),
    ("reject-rsa2048-3prime-private-pkcs8.pem", WHY_RSAPRIV),
    ("reject-rsa2048-pkcs8-encrypted.pem", WHY_ENC),
    ("reject-rsa2048-private-pkcs1.pem", WHY_RSAPRIVPEM),
    ("reject-rsa2048-private-pkcs8.der", WHY_RSAPRIV),
    ("reject-rsa2048-private-pkcs8.pem", WHY_RSAPRIV),
    ("reject-rsa3072-private-pkcs8.pem", WHY_RSAPRIV),
    ("reject-rsa4096-private-pkcs8.pem", WHY_RSAPRIV),
    ("reject-rsapss2048-private-pkcs8.pem", WHY_PSS),
    ("reject-rsapss2048-spki.pem", WHY_PSS),
    ("reject-x448-pkcs8.pem", WHY_X448),
    (
        "reject-rfc9500-testRSA1024-private-pkcs1.pem",
        WHY_RSAPRIVPEM,
    ),
    (
        "reject-rfc9500-testRSA2048-private-pkcs1.pem",
        WHY_RSAPRIVPEM,
    ),
    (
        "reject-rfc9500-testRSA4096-private-pkcs1.pem",
        WHY_RSAPRIVPEM,
    ),
];

/// Every `reject-*` fixture (OpenSSL and RFC) is rejected by polyjose with
/// the error code its name implies; the ones the oracle accepts are exactly
/// [`REJECT_FIXTURES_STRICTER_THAN_ORACLE`].
#[test]
fn reject_fixtures_are_rejected_and_every_oracle_acceptance_is_listed() {
    let mut oracle_accepts = Vec::new();
    let mut count = 0;
    for dir in ["openssl", "rfc"] {
        for name in fixtures::files(dir, |name| name.starts_with("reject-")) {
            let bytes = raw(dir, &name);
            let ours = our_import_file(&name, &bytes);
            // A weak RSA key and broken PEM armor are malformed input;
            // everything else, the RFC 8410 §10.2 certificate included (its
            // label is refused before its 66-character lines are read), is
            // a well-formed but unsupported key (ADR 0018 §2, §4; ADR 0021).
            let expect = if name.contains("rsa1024-pkcs1-pub")
                || name.contains("rsa1024-spki")
                || name.contains("six-dash")
            {
                "InvalidKey"
            } else {
                "UnsupportedAlgorithm"
            };
            assert!(
                has_code(&ours, expect),
                "{dir}/{name}: expected {expect}, got {:?}",
                ours.map(|_| "a key")
            );
            if let Ok(checked) = oracle_file(&name, &bytes) {
                oracle_accepts.push((name.clone(), checked));
            }
            count += 1;
        }
    }
    let listed: Vec<&str> = REJECT_FIXTURES_STRICTER_THAN_ORACLE
        .iter()
        .map(|(name, _)| *name)
        .collect();
    let accepted: Vec<&str> = oracle_accepts.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(accepted, listed, "{oracle_accepts:?}");
    assert_eq!(count, 33);
}

// ---------------------------------------------------------------------------
// Generated keys
// ---------------------------------------------------------------------------

/// The id-ecPublicKey AlgorithmIdentifier of `crv` (RFC 5480 §2.1.1), built
/// by the `spki` oracle.
fn oracle_ec_algorithm(curve: &ObjectIdentifier) -> ::spki::AlgorithmIdentifierRef<'_> {
    ::spki::AlgorithmIdentifierRef {
        oid: ID_EC_PUBLIC_KEY,
        parameters: Some(curve.into()),
    }
}

/// Test randomness for key generation: `len` octets expanded from a
/// 32-octet proptest seed as SHA-512(seed ‖ counter) blocks, so a failing
/// case replays from its seed. It feeds `FixedRng` through the crate's one
/// RNG adapter (ADR 0005, ADR 0018 §5); no second RNG type is introduced.
fn seed_stream(seed: &[u8; 32], len: usize) -> Vec<u8> {
    use sha2::Digest as _;
    let mut stream = Vec::with_capacity(len + 64);
    let mut counter = 0u64;
    while stream.len() < len {
        let block = sha2::Sha512::new()
            .chain_update(seed)
            .chain_update(counter.to_be_bytes())
            .finalize();
        stream.extend_from_slice(&block);
        counter += 1;
    }
    stream.truncate(len);
    stream
}

/// A key from T04's `generate_ec`, drawn from [`seed_stream`] through the
/// crate's one RNG adapter.
///
/// The curve crates draw a scalar as a whole field-size octet string and
/// redraw unless it is below n (`primefield` `try_random`). For P-521 that
/// is 66 octets of which about 2^521 of 2^528 values pass, so a key takes
/// 128 draws on average and a short stream can run dry. The stream is
/// retried longer (always the same prefix, so still a function of the
/// seed): 16 KiB first, then 1 MiB (15,887 draws, dry with probability
/// below 2^-170).
fn generated_ec(crv: EcCurve, seed: &[u8; 32]) -> Jwk {
    for len in [16 * 1024, 1024 * 1024] {
        let mut fixed = crate::rng::insecure_test_vectors::FixedRng::new(seed_stream(seed, len));
        let rng = &mut crate::rng::CryptoRngAdapter::fixed(&mut fixed);
        match super::generate::generate_ec(crv, rng) {
            Err(Error::RandomnessUnavailable) => continue,
            other => return other.unwrap(),
        }
    }
    panic!("{crv:?}: 1 MiB of seed stream ran dry")
}

/// A key from T04's `generate_okp`, seeded as [`generated_ec`]; it takes
/// exactly 32 octets (RFC 8032 §5.1.5, RFC 7748 §5).
fn generated_okp(crv: OkpCurve, seed: &[u8; 32]) -> Jwk {
    let mut fixed = crate::rng::insecure_test_vectors::FixedRng::new(seed_stream(seed, 32));
    super::generate::generate_okp(crv, &mut crate::rng::CryptoRngAdapter::fixed(&mut fixed))
        .unwrap()
}

/// A generated EC key's SPKI, SEC1 and PKCS#8 encodings decode in the
/// oracles to the key's own values, re-import to the same key, and equal
/// byte for byte what the formats crates encode from the same values:
///
/// - SPKI: id-ecPublicKey + namedCurve and the uncompressed point (RFC 5480
///   §2.1.1, §2.2);
/// - SEC1: version 1, privateKey, `[0]` namedCurve and `[1]` publicKey
///   (RFC 5915 §3);
/// - PKCS#8 v1 whose ECPrivateKey has `[1]` and no `[0]`, the layout of
///   OpenSSL 4 and of RustCrypto's own `elliptic-curve` 0.14.3
///   `SecretKey::to_pkcs8_der` (`parameters: None`), so there is no
///   difference to list. The variant with `[0]` inside, which RFC 5915 §3's
///   "MUST always include" asks for and erratum 5008 drops, is not what
///   polyjose writes, but polyjose reads it to the same key (ADR 0018 §3).
fn check_generated_ec(jwk: &Jwk) {
    let KeyMaterial::Ec(key) = jwk.material() else {
        panic!("an EC key")
    };
    let values = values_of(jwk);
    let crv = key.crv();
    let d = key.d().unwrap();
    let point = [&[0x04][..], key.x(), key.y()].concat();
    let curve = curve_oid(crv);

    let spki = super::ec::to_spki(key).unwrap();
    let oracle_spki = ::spki::SubjectPublicKeyInfoRef {
        algorithm: oracle_ec_algorithm(&curve),
        subject_public_key: ::der::asn1::BitStringRef::from_bytes(&point).unwrap(),
    }
    .to_der()
    .unwrap();
    assert_eq!(*spki, oracle_spki, "SPKI");
    let public = Values::Ec {
        crv,
        x: key.x().to_vec(),
        y: key.y().to_vec(),
        d: None,
    };
    assert_eq!(oracle_key(Kind::Spki, &spki), Ok(Some(public)));

    let sec1 = super::ec::to_sec1(key).unwrap();
    let oracle_sec1 = ::sec1::EcPrivateKey {
        private_key: d,
        parameters: Some(::sec1::EcParameters::NamedCurve(curve)),
        public_key: Some(&point),
    }
    .to_der()
    .unwrap();
    assert_eq!(*sec1, oracle_sec1, "SEC1");
    assert_eq!(
        oracle_key(Kind::Sec1, &sec1).as_ref(),
        Ok(&Some(values_ec(jwk)))
    );

    let pkcs8 = super::ec::to_pkcs8(key).unwrap();
    let oracle_pkcs8 = |parameters: Option<::sec1::EcParameters>| {
        let inner = ::sec1::EcPrivateKey {
            private_key: d,
            parameters,
            public_key: Some(&point),
        }
        .to_der()
        .unwrap();
        ::pkcs8::PrivateKeyInfoRef::new(
            oracle_ec_algorithm(&curve),
            OctetStringRef::new(&inner).unwrap(),
        )
        .to_der()
        .unwrap()
    };
    assert_eq!(*pkcs8, oracle_pkcs8(None), "PKCS#8");
    assert_eq!(
        oracle_key(Kind::Pkcs8, &pkcs8).as_ref(),
        Ok(&Some(values_ec(jwk)))
    );
    let with_curve = oracle_pkcs8(Some(::sec1::EcParameters::NamedCurve(curve)));
    assert_ne!(*pkcs8, with_curve);
    assert_eq!(
        values_of(&our_import(Kind::Pkcs8, &with_curve).unwrap()),
        values
    );

    for (kind, der) in [(Kind::Sec1, &sec1), (Kind::Pkcs8, &pkcs8)] {
        assert_eq!(
            values_of(&our_import(kind, der).unwrap()),
            values,
            "{kind:?}"
        );
    }
    assert!(our_import(Kind::Spki, &spki).unwrap().is_public());
}

/// [`values_of`] of an EC key, so the call sites read as what they check.
fn values_ec(jwk: &Jwk) -> Values {
    values_of(jwk)
}

/// A generated Ed25519 or X25519 key's SPKI and PKCS#8 encodings decode in
/// the oracles to the key's values, re-import to the same key, and equal
/// byte for byte what the formats crates encode: the RFC 8410 §3
/// AlgorithmIdentifier with parameters absent, the key as the BIT STRING
/// (§4), and the CurvePrivateKey OCTET STRING inside the PKCS#8 v1
/// privateKey (§7, the §10.3 layout).
fn check_generated_okp(jwk: &Jwk) {
    let KeyMaterial::Okp(key) = jwk.material() else {
        panic!("an OKP key")
    };
    let values = values_of(jwk);
    let algorithm = ::spki::AlgorithmIdentifierRef {
        oid: match key.crv() {
            OkpCurve::Ed25519 => ID_ED25519,
            OkpCurve::X25519 => ID_X25519,
        },
        parameters: None,
    };

    let spki = super::okp::to_spki(key).unwrap();
    let oracle_spki = ::spki::SubjectPublicKeyInfoRef {
        algorithm,
        subject_public_key: ::der::asn1::BitStringRef::from_bytes(key.x()).unwrap(),
    }
    .to_der()
    .unwrap();
    assert_eq!(*spki, oracle_spki, "SPKI");
    let public = Values::Okp {
        crv: key.crv(),
        x: key.x().to_vec(),
        d: None,
    };
    assert_eq!(oracle_key(Kind::Spki, &spki), Ok(Some(public)));

    let pkcs8 = super::okp::to_pkcs8(key).unwrap();
    let curve_private_key = OctetStringRef::new(key.d().unwrap())
        .unwrap()
        .to_der()
        .unwrap();
    let oracle_pkcs8 = ::pkcs8::PrivateKeyInfoRef::new(
        algorithm,
        OctetStringRef::new(&curve_private_key).unwrap(),
    )
    .to_der()
    .unwrap();
    assert_eq!(*pkcs8, oracle_pkcs8, "PKCS#8");
    assert_eq!(
        oracle_key(Kind::Pkcs8, &pkcs8).as_ref(),
        Ok(&Some(values_of(jwk)))
    );

    assert_eq!(values_of(&our_import(Kind::Pkcs8, &pkcs8).unwrap()), values);
    assert!(our_import(Kind::Spki, &spki).unwrap().is_public());
}

mod generated {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        // ≤ 256 cases per curve (task T09).
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn p256_keys_encode_and_decode_like_the_oracles(seed in any::<[u8; 32]>()) {
            check_generated_ec(&generated_ec(EcCurve::P256, &seed));
        }

        #[test]
        fn p384_keys_encode_and_decode_like_the_oracles(seed in any::<[u8; 32]>()) {
            check_generated_ec(&generated_ec(EcCurve::P384, &seed));
        }

        #[test]
        fn p521_keys_encode_and_decode_like_the_oracles(seed in any::<[u8; 32]>()) {
            check_generated_ec(&generated_ec(EcCurve::P521, &seed));
        }

        #[test]
        fn secp256k1_keys_encode_and_decode_like_the_oracles(seed in any::<[u8; 32]>()) {
            check_generated_ec(&generated_ec(EcCurve::Secp256k1, &seed));
        }

        #[test]
        fn ed25519_keys_encode_and_decode_like_the_oracles(seed in any::<[u8; 32]>()) {
            check_generated_okp(&generated_okp(OkpCurve::Ed25519, &seed));
        }

        #[test]
        fn x25519_keys_encode_and_decode_like_the_oracles(seed in any::<[u8; 32]>()) {
            check_generated_okp(&generated_okp(OkpCurve::X25519, &seed));
        }
    }
}

// ---------------------------------------------------------------------------
// DER reader against `der`
// ---------------------------------------------------------------------------

/// A minimal DER length (X.690 §8.1.3.4, §8.1.3.5, §10.1).
fn der_length(len: usize) -> Vec<u8> {
    match len {
        0..=0x7F => vec![len as u8],
        _ => {
            let octets: Vec<u8> = len
                .to_be_bytes()
                .into_iter()
                .skip_while(|octet| *octet == 0)
                .collect();
            [&[0x80 | octets.len() as u8][..], &octets].concat()
        }
    }
}

/// One TLV with a minimal length.
fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    [&[tag][..], &der_length(contents.len()), contents].concat()
}

/// Reads exactly one element of `input` with `read`, requiring nothing
/// after it, as the oracle's `from_der` does.
fn read_one<'a, T>(input: &'a [u8], read: impl FnOnce(&mut Reader<'a>) -> Result<T>) -> Result<T> {
    let mut reader = Reader::new(input)?;
    let value = read(&mut reader)?;
    reader.finish()?;
    Ok(value)
}

/// The OBJECT IDENTIFIER contents octets polyjose's reader accepts (every
/// subidentifier minimal, X.690 §8.19.2) but `const-oid` 0.10 cannot
/// represent: a first subidentifier of 120 or more (arc 2.40 and above,
/// including any multi-octet first subidentifier), a subidentifier above
/// 2^32 − 1 (const-oid rejects some of these and wraps others), or more
/// than 39 contents octets. polyjose only compares OIDs
/// with the byte templates of `oid.rs` and checks the OIDs inside PKCS#8
/// attributes and unsupported parameters for well-formedness, so a wider OID
/// is never interpreted (ADR 0018 §2): this is a documented, harmless
/// difference (T02 tester, backlog).
fn oid_beyond_const_oid(contents: &[u8]) -> bool {
    let mut wide = false;
    let mut value = 0u128;
    for &octet in &contents[1..] {
        value = (value << 7) | u128::from(octet & 0x7F);
        wide |= value > u128::from(u32::MAX);
        if octet & 0x80 == 0 {
            value = 0;
        }
        // Long runs only grow; cap so the shift cannot overflow.
        value &= u128::from(u64::MAX);
    }
    contents.len() > 39 || contents[0] >= 0x78 || wide
}

/// Whether some subidentifier starts with the padding octet 0x80, which
/// X.690 §8.19.2 forbids and polyjose rejects (N22) but `const-oid` 0.10
/// decodes.
fn oid_has_padded_subidentifier(contents: &[u8]) -> bool {
    let mut at_start = true;
    contents.iter().any(|&octet| {
        let padded = at_start && octet == 0x80;
        at_start = octet & 0x80 == 0;
        padded
    })
}

/// Compares polyjose's typed readers with `der`'s strict `from_der` on one
/// encoding. Both must agree on acceptance, and where both accept, on the
/// value, and `der` must re-encode it to exactly `input`. The documented
/// differences:
///
/// - BIT STRING: polyjose reads only keys, which are whole octets
///   (RFC 5480 §2.2, RFC 8410 §4, RFC 3279 §2.3.1, RFC 5958 §2), so it
///   rejects a non-zero unused-bits count that `der` accepts (ADR 0018 §2,
///   N30).
/// - OBJECT IDENTIFIER: see [`oid_beyond_const_oid`] (polyjose accepts) and
///   [`oid_has_padded_subidentifier`] (polyjose rejects).
fn compare_typed_readers(input: &[u8]) {
    use ::der::asn1::{BitStringRef, IntRef, Null, UintRef};

    let ours = read_one(input, |r| r.integer());
    let theirs = IntRef::from_der(input);
    assert_eq!(ours.is_ok(), theirs.is_ok(), "INTEGER {input:02x?}");
    if let Ok(int) = theirs {
        assert_eq!(int.to_der().unwrap(), input, "INTEGER re-encoding");
    }

    let ours = read_one(input, |r| r.unsigned_integer());
    let theirs = UintRef::from_der(input);
    assert_eq!(
        ours.ok(),
        theirs.ok().map(|uint| uint.as_bytes()),
        "unsigned INTEGER {input:02x?}"
    );

    let ours = read_one(input, |r| r.octet_string());
    let theirs = <&OctetStringRef>::from_der(input);
    assert_eq!(
        ours.ok(),
        theirs.ok().map(OctetStringRef::as_bytes),
        "OCTET STRING {input:02x?}"
    );

    let ours = read_one(input, |r| r.bit_string());
    let theirs = BitStringRef::from_der(input);
    match (&ours, &theirs) {
        (Ok(octets), Ok(bits)) => {
            assert_eq!(bits.unused_bits(), 0, "BIT STRING {input:02x?}");
            assert_eq!(Some(*octets), bits.as_bytes(), "BIT STRING {input:02x?}");
            assert_eq!(bits.to_der().unwrap(), input, "BIT STRING re-encoding");
        }
        (Err(_), Ok(bits)) => assert_ne!(bits.unused_bits(), 0, "BIT STRING {input:02x?}"),
        (Ok(_), Err(_)) => panic!("BIT STRING laxer than der: {input:02x?}"),
        (Err(_), Err(_)) => {}
    }

    let ours = read_one(input, |r| r.null());
    assert_eq!(
        ours.is_ok(),
        Null::from_der(input).is_ok(),
        "NULL {input:02x?}"
    );

    let ours = read_one(input, |r| r.oid());
    let theirs = <ObjectIdentifier>::from_der(input);
    match (&ours, &theirs) {
        (Ok(encoding), Ok(oid)) => assert_eq!(oid.to_der().unwrap(), *encoding, "OID"),
        (Ok(_), Err(_)) => assert!(
            oid_beyond_const_oid(&input[2..]),
            "OID laxer than der: {input:02x?}"
        ),
        (Err(_), Ok(_)) => assert!(
            oid_has_padded_subidentifier(oid_contents(input)),
            "OID stricter than der, undocumented: {input:02x?}"
        ),
        (Err(_), Err(_)) => {}
    }
}

/// The contents octets of a short-form TLV whose framing `der` accepted.
fn oid_contents(input: &[u8]) -> &[u8] {
    &input[2..]
}

/// The documented OBJECT IDENTIFIER differences, one example each.
#[test]
fn oid_reader_differences_with_const_oid_are_the_documented_ones() {
    // polyjose accepts, const-oid 0.10 cannot represent (harmless, see
    // `oid_beyond_const_oid`).
    let wider = [
        // 2.40: first subidentifier 120 (X.690 §8.19.4 allows it).
        tlv(0x06, &[0x78]),
        // 2.999 (RFC 9500 uses 2.999-style test arcs): a two-octet first
        // subidentifier.
        tlv(0x06, &[0x88, 0x37]),
        // 1.3.(2^42 − 1): a six-octet subidentifier, above 2^32 − 1.
        // (const-oid 0.10 decodes a five-octet one above 2^32 − 1, such as
        // 90 80 80 80 00, by wrapping it; that is the oracle's leniency.)
        tlv(0x06, &[0x2B, 0x9F, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F]),
        // 40 contents octets.
        tlv(0x06, &[0x2B; 40]),
    ];
    for input in &wider {
        let contents = &input[1 + der_length(input.len() - 2).len()..];
        assert!(read_one(input, |r| r.oid()).is_ok(), "{input:02x?}");
        assert!(<ObjectIdentifier>::from_der(input).is_err(), "{input:02x?}");
        assert!(oid_beyond_const_oid(contents), "{input:02x?}");
    }
    // polyjose rejects, const-oid accepts: a padded subidentifier
    // (X.690 §8.19.2; N22, listed in NEGATIVE_STRICTER_THAN_ORACLE).
    let padded = tlv(0x06, &[0x2B, 0x80, 0x65, 0x70]);
    assert!(read_one(&padded, |r| r.oid()).is_err());
    assert!(<ObjectIdentifier>::from_der(&padded).is_ok());
    // The supported OIDs read alike.
    for template in [
        oid::OID_EC_PUBLIC_KEY,
        oid::OID_P256,
        oid::OID_P384,
        oid::OID_P521,
        oid::OID_SECP256K1,
        oid::OID_X25519,
        oid::OID_ED25519,
        oid::OID_RSA_ENCRYPTION,
    ] {
        compare_typed_readers(template);
    }
}

mod reader {
    use proptest::collection::vec;
    use proptest::prelude::*;

    use super::*;

    /// One element with a chosen tag, a length in one of several forms
    /// (minimal, non-minimal long form, too long, too short, indefinite)
    /// and contents biased toward the octets that decide INTEGER and BIT
    /// STRING minimality and OID padding.
    fn element() -> impl Strategy<Value = Vec<u8>> {
        let tag = prop::sample::select(vec![
            0x02u8, 0x03, 0x04, 0x05, 0x06, 0x22, 0x23, 0x24, 0x25, 0x26, 0x1F, 0x30, 0x81,
        ]);
        let lead = prop::sample::select(vec![
            vec![],
            vec![0x00],
            vec![0xFF],
            vec![0x80],
            vec![0x00, 0x80],
            vec![0xFF, 0x7F],
            vec![0x07],
            vec![0x2B],
            vec![0x2B, 0x80],
        ]);
        (
            tag,
            lead,
            vec(any::<u8>(), 0..40),
            0u8..6,
            vec(any::<u8>(), 0..2),
        )
            .prop_map(|(tag, lead, rest, form, trailing)| {
                let contents = [lead, rest].concat();
                let len = contents.len();
                let length = match form {
                    0 | 1 => der_length(len),
                    2 => [&[0x81][..], &[len as u8]].concat(),
                    3 => der_length(len + 1),
                    4 => der_length(len.saturating_sub(1)),
                    _ => vec![0x80],
                };
                let mut out = [&[tag][..], &length, &contents].concat();
                if form == 1 {
                    out.extend_from_slice(&trailing);
                }
                out
            })
    }

    /// Arbitrary OBJECT IDENTIFIERs: base-128 subidentifiers (X.690
    /// §8.19.2) of any width, sometimes padded with a leading 0x80.
    fn object_identifier() -> impl Strategy<Value = Vec<u8>> {
        let arc = prop_oneof![0u64..128, 128u64..1 << 21, any::<u64>()];
        (vec((arc, any::<bool>()), 1..6), 0u8..128).prop_map(|(arcs, root)| {
            let mut contents = vec![root];
            for (value, pad) in arcs {
                let mut groups = Vec::new();
                let mut v = value;
                loop {
                    groups.push((v & 0x7F) as u8);
                    v >>= 7;
                    if v == 0 {
                        break;
                    }
                }
                if pad && groups.len() < 10 {
                    groups.push(0);
                }
                for (i, group) in groups.iter().enumerate().rev() {
                    contents.push(if i == 0 { *group } else { group | 0x80 });
                }
            }
            tlv(0x06, &contents)
        })
    }

    proptest! {
        // ≤ 1,000 cases per property (pipeline rule 8).
        #![proptest_config(ProptestConfig::with_cases(1000))]

        #[test]
        fn typed_readers_agree_with_der(input in element()) {
            compare_typed_readers(&input);
        }

        #[test]
        fn oid_reader_agrees_with_const_oid_but_for_documented_cases(
            input in object_identifier()
        ) {
            compare_typed_readers(&input);
        }
    }
}

// ---------------------------------------------------------------------------
// Canonicality of mutated containers
// ---------------------------------------------------------------------------

/// Every length field of `buf` that polyjose's reader can frame, as
/// (offset of the length octets, their count, the length), walking into
/// constructed elements and into OCTET STRING and BIT STRING contents (the
/// PKCS#8 privateKey and the SPKI RSAPublicKey hold DER too).
fn length_fields(buf: &[u8]) -> Vec<(usize, usize, usize)> {
    let mut out = Vec::new();
    let mut stack = vec![(0usize, buf.len(), 0u8)];
    while let Some((start, end, depth)) = stack.pop() {
        let Ok(mut reader) = Reader::new(&buf[start..end]) else {
            continue;
        };
        let mut at = start;
        while let Ok(element) = reader.element() {
            let header = element.encoding.len() - element.contents.len();
            out.push((at + 1, header - 1, element.contents.len()));
            let contents = at + header;
            let contents_end = contents + element.contents.len();
            if depth < 8 {
                if element.tag & 0x20 != 0 || element.tag == 0x04 {
                    stack.push((contents, contents_end, depth + 1));
                } else if matches!(element.tag, 0x03 | 0x81) && contents < contents_end {
                    stack.push((contents + 1, contents_end, depth + 1));
                }
            }
            at = contents_end;
        }
    }
    out
}

/// One mutation of a DER buffer.
#[derive(Debug, Clone)]
enum Mutation {
    /// Flip one bit.
    Flip(proptest::sample::Index, u8),
    /// Insert one octet.
    Insert(proptest::sample::Index, u8),
    /// Delete one octet.
    Delete(proptest::sample::Index),
    /// Rewrite one length field: 0 non-minimal long form (X.690 §10.1),
    /// 1 one too long, 2 one too short, 3 indefinite (§8.1.3.6).
    Length(proptest::sample::Index, u8),
}

fn apply(seed: &[u8], mutations: &[Mutation]) -> Vec<u8> {
    let mut m = seed.to_vec();
    for mutation in mutations {
        match mutation {
            Mutation::Flip(at, bit) if !m.is_empty() => {
                let i = at.index(m.len());
                m[i] ^= 1 << bit;
            }
            Mutation::Insert(at, octet) => m.insert(at.index(m.len() + 1), *octet),
            Mutation::Delete(at) if !m.is_empty() => {
                m.remove(at.index(m.len()));
            }
            Mutation::Length(at, form) => {
                let fields = length_fields(&m);
                if fields.is_empty() {
                    continue;
                }
                let (start, count, len) = fields[at.index(fields.len())];
                let replacement = match form {
                    0 if len < 0x80 => vec![0x81, len as u8],
                    0 => {
                        let mut long = der_length(len);
                        long[0] += 1;
                        long.insert(1, 0x00);
                        long
                    }
                    1 => der_length(len + 1),
                    2 => der_length(len.saturating_sub(1)),
                    _ => vec![0x80],
                };
                m.splice(start..start + count, replacement);
            }
            _ => {}
        }
    }
    m
}

/// `der` without its PKCS#8 `[0]` attributes element, which polyjose
/// checks and then ignores (ADR 0018 §3), so never re-encodes.
fn without_attributes(der: &[u8]) -> Vec<u8> {
    let mut outer = Reader::new(der).unwrap();
    let mut fields = outer.sequence().unwrap();
    let mut body = Vec::new();
    while let Ok(element) = fields.element() {
        if element.tag != super::der::CONTEXT_0 {
            body.extend_from_slice(element.encoding);
        }
    }
    tlv(super::der::SEQUENCE, &body)
}

/// The canonicality property on one buffer:
///
/// - whenever a container codec accepts it, encoding what it decoded gives
///   exactly the input (X.690 §10: one encoding per value), PKCS#8
///   attributes aside;
/// - whenever polyjose's codecs accept it, the formats crates accept it
///   with the same fields, and whenever polyjose's import accepts it, the
///   oracle accepts it: polyjose is never laxer (research.md §4);
/// - nothing panics (a panic fails the property).
///
/// Returns whether any container codec accepted `m`.
fn check_canonical(m: &[u8]) -> bool {
    let accepted = Kind::ALL.iter().any(|kind| our_fields(*kind, m).is_ok());
    if let Ok(parts) = super::pkcs8::decode(m) {
        assert_eq!(
            *super::pkcs8::encode(&parts).unwrap(),
            without_attributes(m)
        );
        if let (AlgId::Ec(_), Ok(inner)) = (parts.alg, super::sec1::decode(parts.private_key)) {
            assert_eq!(*super::sec1::encode(&inner).unwrap(), parts.private_key);
        }
    }
    if let Ok(parts) = super::spki::decode(m) {
        assert_eq!(*super::spki::encode(&parts).unwrap(), m);
    }
    if let Ok(key) = super::sec1::decode(m) {
        assert_eq!(*super::sec1::encode(&key).unwrap(), m);
    }
    if let Ok(key) = super::pkcs1::decode(m) {
        assert_eq!(*super::pkcs1::encode_public(key.n, key.e).unwrap(), m);
    }
    if let Ok(key) = super::pkcs1::decode_public(m) {
        assert_eq!(*super::pkcs1::encode_public(key.n, key.e).unwrap(), m);
    }
    for kind in Kind::ALL {
        if let Ok(fields) = our_fields(kind, m) {
            assert_eq!(oracle_fields(kind, m), Ok(fields), "{kind:?} {m:02x?}");
        }
        if our_import(kind, m).is_ok() {
            assert!(
                oracle_key(kind, m).is_ok(),
                "{kind:?} laxer than the oracle: {m:02x?}"
            );
        }
    }
    accepted
}

/// Over random mutations of the positive fixtures (bit flips, octet
/// insertions and deletions, length-octet rewrites), whatever polyjose
/// accepts re-encodes to exactly the input and is accepted by the oracle
/// with the same fields, and nothing panics. 1,000 cases (pipeline rule 8);
/// this is not a substitute for fuzzing (feature 0012).
#[test]
fn mutated_containers_re_encode_exactly_when_accepted() {
    use proptest::collection::vec;
    use proptest::prelude::*;
    use proptest::test_runner::{Config, TestRunner};

    let mut seeds: Vec<Vec<u8>> = positive_fixtures()
        .iter()
        .map(|(dir, name)| load_positive(dir, name))
        .collect();
    seeds.sort();
    seeds.dedup();
    // The unmutated seeds hold the property too.
    for seed in &seeds {
        assert!(check_canonical(seed));
    }
    let mutation = prop_oneof![
        (any::<proptest::sample::Index>(), 0u8..8).prop_map(|(at, bit)| Mutation::Flip(at, bit)),
        (any::<proptest::sample::Index>(), any::<u8>())
            .prop_map(|(at, octet)| Mutation::Insert(at, octet)),
        any::<proptest::sample::Index>().prop_map(Mutation::Delete),
        (any::<proptest::sample::Index>(), 0u8..4)
            .prop_map(|(at, form)| Mutation::Length(at, form)),
    ];
    let strategy = (0..seeds.len(), vec(mutation, 1..4));
    let mut runner = TestRunner::new(Config::with_cases(1000));
    let accepted = core::cell::Cell::new(0u32);
    runner
        .run(&strategy, |(seed, mutations)| {
            if check_canonical(&apply(&seeds[seed], &mutations)) {
                accepted.set(accepted.get() + 1);
            }
            Ok(())
        })
        .unwrap();
    // Not vacuous: a flip inside a key value, an RSA modulus or an EC
    // point keeps the container well-formed. About 14% of cases are
    // accepted (measured); 5% leaves a margin of over 8 standard
    // deviations.
    assert!(accepted.get() >= 50, "only {} accepted", accepted.get());
}

// ---------------------------------------------------------------------------
// PEM against `pem-rfc7468`
// ---------------------------------------------------------------------------

/// The labels polyjose writes (RFC 7468 §10, §13; RFC 5915 §4; OpenSSL's
/// `RSA PUBLIC KEY`).
const WRITTEN_LABELS: [Label; 4] = [
    Label::PrivateKey,
    Label::PublicKey,
    Label::EcPrivateKey,
    Label::RsaPublic,
];

/// polyjose's PEM verdict: the label text and the octets.
fn our_pem(text: &[u8]) -> Option<(&'static str, Vec<u8>)> {
    let text = core::str::from_utf8(text).ok()?;
    let (label, der) = super::pem::decode(text).ok()?;
    Some((label.as_str()?, der.to_vec()))
}

/// `pem-rfc7468`'s strict decoder's verdict (RFC 7468 §3 Figure 3, with
/// its preamble handling and 64-column lines).
fn oracle_pem(text: &[u8]) -> Option<(String, Vec<u8>)> {
    pem_rfc7468::decode_vec(text)
        .ok()
        .map(|(label, der)| (label.to_owned(), der))
}

/// `text` without the whitespace around it (SP, HTAB, CR, LF).
fn trim_pem(text: &[u8]) -> &[u8] {
    let is_ws = |c: &u8| matches!(c, b' ' | b'\t' | b'\r' | b'\n');
    let start = text.iter().position(|c| !is_ws(c)).unwrap_or(text.len());
    let end = text
        .iter()
        .rposition(|c| !is_ws(c))
        .map_or(start, |i| i + 1);
    &text[start..end]
}

/// The PEM differential on one text:
///
/// - Whatever polyjose accepts, `pem-rfc7468` accepts with the same label
///   and octets, except surrounding whitespace: polyjose takes any SP,
///   HTAB, CR and LF before the BEGIN line and after the END line
///   (ADR 0018 §2, "optionally surrounded by whitespace"), where
///   `pem-rfc7468` wants the BEGIN line at the start or after an LF and at
///   most one eol after the END line. For those texts the oracle must
///   accept the trimmed block, so surrounding whitespace is the only way
///   polyjose is more lenient.
/// - What `pem-rfc7468` rejects polyjose rejects, by the same argument.
/// - polyjose never panics.
///
/// Where `pem-rfc7468` accepts and polyjose rejects, polyjose is stricter
/// on purpose (see [`PEM_VECTOR_DIFFERENCES`]).
fn check_pem(text: &[u8]) {
    let Some(ours) = our_pem(text) else {
        return;
    };
    let theirs = oracle_pem(text).or_else(|| oracle_pem(trim_pem(text)));
    let theirs = theirs.unwrap_or_else(|| {
        panic!(
            "PEM laxer than pem-rfc7468: {:?}",
            String::from_utf8_lossy(text)
        )
    });
    assert_eq!((ours.0, &ours.1), (theirs.0.as_str(), &theirs.1));
}

/// How polyjose and `pem-rfc7468` disagree on the PEM vectors (`negative/`
/// P01–P18 and A01–A03, the RFC 8410 rejection files): (vector, polyjose
/// accepts, `pem-rfc7468` accepts, reason). Every other vector gets the
/// same verdict from both, and the same label and octets where both
/// accept.
const PEM_VECTOR_DIFFERENCES: &[(&str, bool, bool, &str)] = &[
    (
        "A03",
        true,
        false,
        "blank lines after the END line: polyjose takes any whitespace around the block \
         (ADR 0018 §2); pem-rfc7468 at most one eol. The trimmed block decodes alike \
         (check_pem)",
    ),
    (
        "P07",
        false,
        true,
        "explanatory text before the BEGIN line: rejected (ADR 0018 §2; RFC 7468 §2 \
         permits it, §3 lets the parser choose); pem-rfc7468 skips a preamble",
    ),
    (
        "P10",
        false,
        true,
        "a lower-case label: RFC 7468 §2 labels are \"formally case-sensitive, \
         uppercase\" and polyjose knows only the exact upper-case labels (ADR 0018 §2); \
         pem-rfc7468 takes any labelchar",
    ),
    (
        "P13",
        false,
        true,
        "label DSA PRIVATE KEY: names no supported structure, UnsupportedAlgorithm from \
         the BEGIN line (ADR 0018 §2, §4); pem-rfc7468 decodes any label",
    ),
];

#[test]
fn pem_vectors_differ_from_pem_rfc7468_only_as_listed() {
    let mut vectors: Vec<(String, Vec<u8>)> = negative_entries()
        .into_iter()
        .filter(|entry| entry.file.ends_with(".pem"))
        .map(|entry| (entry.id, raw("negative", &entry.file)))
        .collect();
    for name in fixtures::files("rfc", |name| name.starts_with("reject-rfc8410")) {
        let bytes = raw("rfc", &name);
        vectors.push((name, bytes));
    }
    let mut differences = Vec::new();
    for (id, text) in &vectors {
        let ours = our_pem(text);
        let theirs = oracle_pem(text);
        match (&ours, &theirs) {
            (Some(ours), Some(theirs)) => {
                assert_eq!((ours.0, &ours.1), (theirs.0.as_str(), &theirs.1), "{id}");
            }
            (None, None) => {}
            _ => differences.push((id.clone(), ours.is_some(), theirs.is_some())),
        }
        check_pem(text);
    }
    let listed: Vec<(String, bool, bool)> = PEM_VECTOR_DIFFERENCES
        .iter()
        .map(|(id, ours, theirs, _)| ((*id).to_owned(), *ours, *theirs))
        .collect();
    assert_eq!(differences, listed);
    // A01–A03, P01–P18 and the two RFC 8410 files.
    assert_eq!(vectors.len(), 23);
}

mod pem_properties {
    use proptest::collection::vec;
    use proptest::prelude::*;

    use super::*;

    /// One textual mutation of a PEM document.
    #[derive(Debug, Clone)]
    enum Edit {
        Replace(prop::sample::Index, u8),
        Insert(prop::sample::Index, u8),
        Delete(prop::sample::Index),
        Prefix(Vec<u8>),
        Suffix(Vec<u8>),
        /// Every LF becomes CRLF (0) or CR (1), RFC 7468 §3 `eol`.
        LineEndings(u8),
    }

    /// The characters that matter to the grammar: eol and whitespace,
    /// hyphen-minus, base64 alphabet and padding, a header colon, a
    /// lower-case letter and NUL.
    const ALPHABET: &[u8] = b"\n\r \t-AZaz09+/=:x\0";

    fn interesting() -> impl Strategy<Value = u8> {
        prop::sample::select(ALPHABET)
    }

    fn edit() -> impl Strategy<Value = Edit> {
        prop_oneof![
            (any::<prop::sample::Index>(), interesting()).prop_map(|(at, c)| Edit::Replace(at, c)),
            (any::<prop::sample::Index>(), interesting()).prop_map(|(at, c)| Edit::Insert(at, c)),
            any::<prop::sample::Index>().prop_map(Edit::Delete),
            vec(interesting(), 1..4).prop_map(Edit::Prefix),
            vec(interesting(), 1..4).prop_map(Edit::Suffix),
            (0u8..2).prop_map(Edit::LineEndings),
        ]
    }

    fn apply_edits(text: &[u8], edits: &[Edit]) -> Vec<u8> {
        let mut t = text.to_vec();
        for edit in edits {
            match edit {
                Edit::Replace(at, c) if !t.is_empty() => {
                    let i = at.index(t.len());
                    t[i] = *c;
                }
                Edit::Insert(at, c) => t.insert(at.index(t.len() + 1), *c),
                Edit::Delete(at) if !t.is_empty() => {
                    t.remove(at.index(t.len()));
                }
                Edit::Prefix(p) => t.splice(0..0, p.iter().copied()).for_each(drop),
                Edit::Suffix(p) => t.extend_from_slice(p),
                Edit::LineEndings(form) => {
                    let eol: &[u8] = if *form == 0 { b"\r\n" } else { b"\r" };
                    t = t
                        .iter()
                        .flat_map(|&c| if c == b'\n' { eol.to_vec() } else { vec![c] })
                        .collect();
                }
                _ => {}
            }
        }
        t
    }

    /// The PEM seeds: every positive `.pem` fixture and the accepted
    /// variants A01–A03.
    fn seeds() -> Vec<Vec<u8>> {
        let mut seeds: Vec<Vec<u8>> = positive_fixtures()
            .into_iter()
            .filter(|(_, name)| name.ends_with(".pem"))
            .map(|(dir, name)| raw(dir, &name))
            .collect();
        seeds.extend(
            negative_entries()
                .into_iter()
                .filter(|entry| entry.id.starts_with('A'))
                .map(|entry| raw("negative", &entry.file)),
        );
        seeds
    }

    proptest! {
        // ≤ 1,000 cases per property (pipeline rule 8).
        #![proptest_config(ProptestConfig::with_cases(1000))]

        /// `pem::encode` writes exactly what `pem-rfc7468`'s encoder writes
        /// with LF line endings (RFC 7468 §2: 64-column lines, the same
        /// label on the END line), its strict decoder reads it back to the
        /// same label and octets, and so does `pem::decode`.
        #[test]
        fn encoded_pem_is_what_pem_rfc7468_writes_and_reads(
            der in vec(any::<u8>(), 1..700),
            label in prop::sample::select(WRITTEN_LABELS.to_vec()),
        ) {
            let text = super::super::pem::encode(label, &der).unwrap();
            let label_text = label.as_str().unwrap();
            let oracle = pem_rfc7468::encode_string(label_text, pem_rfc7468::LineEnding::LF, &der)
                .unwrap();
            prop_assert_eq!(text.as_str(), oracle.as_str());
            let (decoded_label, decoded) = pem_rfc7468::decode_vec(text.as_bytes()).unwrap();
            prop_assert_eq!(decoded_label, label_text);
            prop_assert_eq!(&decoded, &der);
            let (our_label, our_der) = super::super::pem::decode(&text).unwrap();
            prop_assert_eq!(our_label, label);
            prop_assert_eq!(&*our_der, &der);
        }
    }

    /// Over random edits of real PEM documents, polyjose accepts nothing
    /// `pem-rfc7468` rejects except for surrounding whitespace, decodes to
    /// the same label and octets, and never panics (see `check_pem`).
    #[test]
    fn edited_pem_is_never_laxer_than_pem_rfc7468() {
        use proptest::test_runner::{Config, TestRunner};

        let seeds = seeds();
        for seed in &seeds {
            check_pem(seed);
        }
        let strategy = (0..seeds.len(), vec(edit(), 1..4));
        let mut runner = TestRunner::new(Config::with_cases(1000));
        let accepted = core::cell::Cell::new(0u32);
        runner
            .run(&strategy, |(seed, edits)| {
                let text = apply_edits(&seeds[seed], &edits);
                check_pem(&text);
                if our_pem(&text).is_some() {
                    accepted.set(accepted.get() + 1);
                }
                Ok(())
            })
            .unwrap();
        // Not vacuous: whitespace and eol edits keep many documents valid,
        // about 11% of cases (measured); 5% is over 5 standard deviations
        // below.
        assert!(accepted.get() >= 50, "only {} accepted", accepted.get());
    }
}

// ---------------------------------------------------------------------------
// Secret hygiene
// ---------------------------------------------------------------------------

/// What carries a private key between the codecs is either borrowed or
/// wiped on drop (CLAUDE.md secrets rule, ADR 0018 §5), checked at compile
/// time:
///
/// - the owned buffers every decoder and encoder returns are `Zeroizing`
///   (`ZeroizeOnDrop`): the DER of `pem::decode`, and the DER and PEM of
///   every private-key encoder;
/// - the intermediate views `Pkcs8Parts` and `sec1::EcPrivateKey` are
///   `Copy`, so they cannot own a buffer: they only borrow the caller's
///   zeroizing one (T02 contract);
/// - the JWK types that hold `d` are `ZeroizeOnDrop`.
const _: () = {
    const fn zeroize_on_drop<T: zeroize::ZeroizeOnDrop + ?Sized>() {}
    const fn borrowed_view<T: Copy>() {}
    zeroize_on_drop::<zeroize::Zeroizing<Vec<u8>>>();
    zeroize_on_drop::<zeroize::Zeroizing<String>>();
    zeroize_on_drop::<Jwk>();
    zeroize_on_drop::<KeyMaterial>();
    zeroize_on_drop::<crate::jwk::EcKey>();
    zeroize_on_drop::<crate::jwk::OkpKey>();
    borrowed_view::<super::types::Pkcs8Parts<'_>>();
    borrowed_view::<super::sec1::EcPrivateKey<'_>>();
};

/// The signatures that tie those types to the functions: each function
/// that returns private-key octets returns them `Zeroizing`.
type Secret = Result<zeroize::Zeroizing<Vec<u8>>>;
type LabelledSecret = Result<(Label, zeroize::Zeroizing<Vec<u8>>)>;
const _: fn(&str) -> LabelledSecret = super::pem::decode;
const _: fn(Label, &[u8]) -> Result<zeroize::Zeroizing<String>> = super::pem::encode;
const _: fn(&super::types::Pkcs8Parts<'_>) -> Secret = super::pkcs8::encode;
const _: fn(&super::sec1::EcPrivateKey<'_>) -> Secret = super::sec1::encode;
const _: fn(&crate::jwk::EcKey) -> Secret = super::ec::to_pkcs8;
const _: fn(&crate::jwk::EcKey) -> Secret = super::ec::to_sec1;
const _: fn(&crate::jwk::OkpKey) -> Secret = super::okp::to_pkcs8;

/// An ASCII marker: it would show in output verbatim, in hex, or as the
/// decimal list of a derived `Debug`.
const MARKER: &[u8; 16] = b"POLYJOSE-MARKER!";

/// A private scalar or seed of `len` octets made of the marker. For P-521
/// (66 octets) it starts `00 01`, below the group order; every other
/// marker value starts with 0x50, below n for all four curves.
fn marker_secret(len: usize) -> Vec<u8> {
    let (prefix, rest): (&[u8], usize) = if len == 66 {
        (&[0x00, 0x01], 64)
    } else {
        (&[], len)
    };
    [prefix, &MARKER.repeat(rest.div_ceil(16))[..rest]].concat()
}

/// Every way a secret could show up in text: the marker; for each 8-octet
/// window, its lower- and upper-case hex, the decimal and hex lists of a
/// derived `Debug`, and the ASCII text; and every 11-character window of
/// its base64url and base64 encodings (8 octets are under 11 characters).
fn leak_forms(secret: &[u8]) -> Vec<String> {
    use core::fmt::Write as _;
    let mut forms = vec![String::from_utf8_lossy(MARKER).into_owned()];
    for window in secret.windows(8) {
        let mut lower = String::new();
        for octet in window {
            write!(lower, "{octet:02x}").unwrap();
        }
        forms.push(lower.to_uppercase());
        forms.push(lower);
        let decimal = format!("{window:?}");
        forms.push(decimal[1..decimal.len() - 1].to_owned());
        let hex = format!("{window:02x?}");
        forms.push(hex[1..hex.len() - 1].to_owned());
        if window.iter().all(u8::is_ascii_graphic) {
            forms.push(String::from_utf8_lossy(window).into_owned());
        }
    }
    let base64url = crate::util::b64url_encode(secret);
    let mut base64 = String::new();
    crate::util::b64_encode_append(secret, &mut base64);
    for encoded in [base64url, base64] {
        let chars: Vec<char> = encoded.chars().collect();
        for window in chars.windows(11) {
            forms.push(window.iter().collect());
        }
    }
    forms
}

/// Runs `der` through every DER decoder and key mapper and adds the
/// `Debug` and `Display` text of every error, and the `Debug` text of every
/// decoded view and JWK, to `out`. `import` limits the key mappers, which
/// do curve arithmetic, to the one container (all four if `None`).
fn render_der(der: &[u8], import: Option<Kind>, out: &mut std::collections::BTreeSet<String>) {
    fn push<T>(
        out: &mut std::collections::BTreeSet<String>,
        result: &Result<T>,
        ok: Option<String>,
    ) {
        match result {
            Err(error) => {
                out.insert(format!("{error:?}"));
                out.insert(format!("{error}"));
            }
            Ok(_) => {
                out.extend(ok);
            }
        }
    }
    let pkcs8 = super::pkcs8::decode(der);
    push(
        out,
        &pkcs8,
        pkcs8.as_ref().ok().map(|parts| format!("{parts:?}")),
    );
    if let Ok(parts) = &pkcs8 {
        let inner = super::sec1::decode(parts.private_key);
        push(
            out,
            &inner,
            inner.as_ref().ok().map(|key| format!("{key:?}")),
        );
    }
    let spki = super::spki::decode(der);
    push(
        out,
        &spki,
        spki.as_ref().ok().map(|parts| format!("{parts:?}")),
    );
    let sec1 = super::sec1::decode(der);
    push(out, &sec1, sec1.as_ref().ok().map(|key| format!("{key:?}")));
    push(out, &super::pkcs1::decode(der), None);
    push(out, &super::pkcs1::decode_public(der), None);
    let kinds: Vec<Kind> = import.map_or(Kind::ALL.to_vec(), |kind| vec![kind]);
    for kind in kinds {
        let jwk = our_import(kind, der);
        push(out, &jwk, jwk.as_ref().ok().map(|jwk| format!("{jwk:?}")));
    }
}

/// `text` through `pem::decode`, rendered as [`render_der`] does.
fn render_pem(text: &[u8], out: &mut std::collections::BTreeSet<String>) {
    if let Ok(text) = core::str::from_utf8(text) {
        match super::pem::decode(text) {
            Err(error) => {
                out.insert(format!("{error:?}"));
                out.insert(format!("{error}"));
            }
            Ok((label, der)) => {
                out.insert(format!("{label:?}"));
                if let Some(kind) = Kind::of_label(label) {
                    render_der(&der, Some(kind), out);
                }
            }
        }
    }
}

/// The private key of a DER container, as polyjose imports it.
fn private_key_of(kind: Kind, der: &[u8]) -> Option<Vec<u8>> {
    match values_of(&our_import(kind, der).ok()?) {
        Values::Ec { d, .. } | Values::Okp { d, .. } => d,
        Values::Rsa { .. } => None,
    }
}

/// Valid private keys whose secret is the marker: Ed25519 and X25519
/// PKCS#8 v1 and v2, and EC SEC1 and PKCS#8 on the four curves, each with
/// its secret.
fn marker_keys() -> Vec<(Kind, Vec<u8>, Vec<u8>)> {
    let mut keys = Vec::new();
    for alg in [AlgId::Ed25519, AlgId::X25519] {
        let d = marker_secret(32);
        let curve_private_key = tlv(super::der::OCTET_STRING, &d);
        let v1 = super::pkcs8::encode(&super::types::Pkcs8Parts {
            version: 0,
            alg,
            private_key: &curve_private_key,
            public_key: None,
        })
        .unwrap();
        let Values::Okp { x, .. } = values_of(&our_import(Kind::Pkcs8, &v1).unwrap()) else {
            panic!("an OKP key")
        };
        let v2 = super::pkcs8::encode(&super::types::Pkcs8Parts {
            version: 1,
            alg,
            private_key: &curve_private_key,
            public_key: Some(&x),
        })
        .unwrap();
        keys.push((Kind::Pkcs8, v1.to_vec(), d.clone()));
        keys.push((Kind::Pkcs8, v2.to_vec(), d));
    }
    for crv in [
        EcCurve::P256,
        EcCurve::P384,
        EcCurve::P521,
        EcCurve::Secp256k1,
    ] {
        let d = marker_secret(crv.coordinate_len());
        let bare = super::sec1::encode(&super::sec1::EcPrivateKey {
            private_key: &d,
            parameters: Some(crv),
            public_key: None,
        })
        .unwrap();
        let jwk = super::ec::from_sec1(&bare).unwrap();
        let KeyMaterial::Ec(key) = jwk.material() else {
            panic!("an EC key")
        };
        keys.push((
            Kind::Sec1,
            super::ec::to_sec1(key).unwrap().to_vec(),
            d.clone(),
        ));
        keys.push((Kind::Pkcs8, super::ec::to_pkcs8(key).unwrap().to_vec(), d));
    }
    keys
}

/// No error and no decoded view reachable from the key fixtures, the
/// negative vectors, the marker keys, every truncation of them and every
/// one-bit flip of the marker keys and negative vectors, through
/// `pem::decode`, `pkcs8::decode`, `spki::decode`, `sec1::decode`,
/// `pkcs1::decode` and the `okp`, `ec` and `rsa` mappers, shows the marker
/// or any 8-octet window of the input's private key in its `Debug` or
/// `Display` text (CLAUDE.md: key material never in errors or `Debug`).
#[test]
fn no_error_or_debug_output_shows_private_key_octets() {
    use std::collections::BTreeSet;

    // (container, DER, its private key if known, flip every bit too); no
    // container means PEM text.
    type Input = (Option<Kind>, Vec<u8>, Option<Vec<u8>>, bool);
    let mut inputs: Vec<Input> = Vec::new();
    for (kind, der, d) in marker_keys() {
        let text = super::pem::encode(
            if kind == Kind::Sec1 {
                Label::EcPrivateKey
            } else {
                Label::PrivateKey
            },
            &der,
        )
        .unwrap();
        inputs.push((None, text.as_bytes().to_vec(), Some(d.clone()), false));
        inputs.push((Some(kind), der, Some(d), true));
    }
    for (dir, name) in positive_fixtures() {
        let kind = Kind::of_file(&name);
        let der = load_positive(dir, &name);
        let d = private_key_of(kind, &der);
        if name.ends_with(".pem") {
            inputs.push((None, raw(dir, &name), d.clone(), false));
        }
        inputs.push((Some(kind), der, d, false));
    }
    for entry in negative_entries() {
        if has_rsa_private_base(&entry) {
            continue;
        }
        let bytes = raw("negative", &entry.file);
        let base_kind = Kind::of_file(&entry.base);
        let d = private_key_of(base_kind, &load_positive("rfc", &entry.base));
        if entry.file.ends_with(".pem") {
            inputs.push((None, bytes, d, false));
        } else {
            inputs.push((Some(negative_kind(&entry)), bytes, d, true));
        }
    }
    for dir in ["openssl", "rfc"] {
        for name in fixtures::files(dir, |name| name.starts_with("reject-")) {
            let bytes = raw(dir, &name);
            let kind = (!name.ends_with(".pem")).then(|| Kind::of_file(&name));
            inputs.push((kind, bytes, None, false));
        }
    }

    // Rendered text, grouped by the secret it must not show.
    let mut rendered: Vec<(Vec<u8>, BTreeSet<String>)> = Vec::new();
    let mut details = BTreeSet::new();
    for (kind, bytes, secret, flip) in &inputs {
        let mut out = BTreeSet::new();
        let mut variants: Vec<Vec<u8>> = (0..=bytes.len()).map(|n| bytes[..n].to_vec()).collect();
        if *flip {
            for i in 0..bytes.len() {
                for bit in [0x01, 0x80] {
                    let mut flipped = bytes.clone();
                    flipped[i] ^= bit;
                    variants.push(flipped);
                }
            }
        }
        for variant in &variants {
            match kind {
                Some(kind) => render_der(variant, Some(*kind), &mut out),
                None => render_pem(variant, &mut out),
            }
        }
        details.extend(out.iter().filter(|s| s.starts_with("invalid key")).cloned());
        rendered.push((secret.clone().unwrap_or_default(), out));
    }
    for (secret, texts) in &rendered {
        let forms = leak_forms(secret);
        for text in texts {
            for form in &forms {
                assert!(!text.contains(form.as_str()), "{text:?} shows {form:?}");
            }
        }
    }
    // Not vacuous: the inputs reach many distinct error paths.
    assert!(details.len() >= 40, "{details:#?}");
}

/// RSA private keys are refused (ADR 0021), but the refusal must not echo
/// them either: every `reject-*rsa*private*` fixture, and every `negative/`
/// vector built from one (N68, N69 and P17, P18: a PKCS#1 RSAPrivateKey read
/// as PKCS#8 or SEC1, ADR 0018 §3), goes through the PEM and DER decoders
/// and the importers, and no error or `Debug` output may show any 8-octet
/// window (hex, decimal, ASCII, base64) of its DER past the first 40 octets
/// (the framing and the public modulus header).
#[test]
fn rsa_private_key_octets_never_reach_an_error() {
    use std::collections::BTreeSet;

    let check = |name: &str, bytes: &[u8]| {
        let der = if name.ends_with(".pem") {
            ::pem_rfc7468::decode_vec(bytes).unwrap().1
        } else {
            bytes.to_vec()
        };
        let mut out = BTreeSet::new();
        if name.ends_with(".pem") {
            render_pem(bytes, &mut out);
        }
        render_der(&der, None, &mut out);
        for n in (0..=der.len()).step_by(7) {
            render_der(&der[..n], None, &mut out);
        }
        let forms = leak_forms(&der[40..]);
        for text in &out {
            for form in &forms {
                assert!(
                    !text.contains(form.as_str()),
                    "{name}: {text:?} shows {form:?}"
                );
            }
        }
    };
    let mut checked = 0;
    for dir in ["openssl", "rfc"] {
        let names = fixtures::files(dir, |name| {
            name.starts_with("reject-") && name.contains("rsa") && name.contains("private")
        });
        for name in names {
            check(&name, &raw(dir, &name));
            checked += 1;
        }
    }
    let relabelled: Vec<NegativeEntry> = negative_entries()
        .into_iter()
        .filter(has_rsa_private_base)
        .collect();
    let ids: Vec<&str> = relabelled.iter().map(|entry| entry.id.as_str()).collect();
    assert_eq!(ids, ["N68", "N69", "P17", "P18"]);
    for entry in &relabelled {
        check(&entry.file, &raw("negative", &entry.file));
        checked += 1;
    }
    assert!(checked >= 14, "only {checked} RSA private inputs");
}
