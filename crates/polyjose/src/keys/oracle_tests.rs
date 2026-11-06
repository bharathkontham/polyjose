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
