//! JSON Web Key (RFC 7517): typed `oct`, `RSA`, `EC` and `OKP` keys.
//!
//! [`Jwk::from_json`][from_json] reads a key from untrusted bytes through
//! polyjose's own JSON parser ([`crate::json`], ADR 0016), and
//! [`Jwk::from_object`][from_object] reads one from an already-parsed
//! object, such as a JOSE Header's `jwk` or `epk`. The key-type members
//! become typed, validated [`KeyMaterial`](crate::jwk::KeyMaterial); the common members become typed
//! fields; every other member is kept unchanged.
//!
//! ```
//! use polyjose::jwk::{EcCurve, Jwk, KeyMaterial, KeyOp, KeyUse};
//!
//! // RFC 7517 Appendix A.2, the EC private key.
//! let jwk = Jwk::from_json(br#"{"kty":"EC","crv":"P-256",
//!     "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
//!     "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
//!     "d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
//!     "use":"enc","kid":"1"}"#)?;
//! assert_eq!(jwk.kid(), Some("1"));
//! assert_eq!(jwk.key_use(), Some(&KeyUse::Enc));
//! assert!(jwk.permits(&KeyOp::DeriveKey) && !jwk.permits(&KeyOp::Verify));
//! let KeyMaterial::Ec(key) = jwk.material() else { unreachable!() };
//! assert_eq!(key.crv(), EcCurve::P256);
//!
//! // Debug never shows private members.
//! assert!(format!("{jwk:?}").contains(r#"d: "<redacted>""#));
//!
//! // The public part has no `d`.
//! let public = jwk.to_public().expect("EC keys have a public part");
//! assert!(public.is_public());
//! assert!(!public.to_json().contains("\"d\""));
//! # Ok::<(), polyjose::Error>(())
//! ```
//!
//! # What import checks
//!
//! Validation is structural: polyjose has no curve or RSA arithmetic until
//! feature 0002, so on-curve checks for EC points (ADR 0007) are made
//! there (0002 T01), as are small-order Ed25519 keys (ADR 0026 §6) and the
//! 8192-bit RSA ceiling (ADR 0026 §2 step 8).
//!
//! - **`kty`** must be present and is case-sensitive (RFC 7517 §4.1).
//!   `oct`, `RSA`, `EC` and `OKP` are supported.
//! - **`EC`** (RFC 7518 §6.2, RFC 8812 §3.1): `crv` is `P-256`, `P-384`,
//!   `P-521` or `secp256k1`; `x` and `y` are present and exactly 32, 48,
//!   66 or 32 octets; `d`, if present, has the same length
//!   (RFC 7518 §6.2.1.2–§6.2.2.1).
//! - **`OKP`** (RFC 8037 §2): `crv` is `Ed25519` or `X25519` (Ed448 and
//!   X448 are out of scope, ADR 0006); `x`, and `d` if present, are 32
//!   octets.
//! - **`RSA`**, public keys only (RFC 7518 §6.3.1, ADR 0021): `n` and `e`
//!   are minimal Base64urlUInt values, non-empty with no leading zero octet
//!   (RFC 7518 §2, §6.3.1.1); `n` is odd (RFC 8017 §3.1) and at least
//!   2048 bits (RFC 7518 §3.3, ADR 0007); `e` is odd with 3 ≤ e < n
//!   (RFC 8017 §3.1). A key with **any** private member (`d`, `p`, `q`,
//!   `dp`, `dq`, `qi`, `oth`, RFC 7518 §6.3.2) is rejected before anything
//!   else is read.
//! - **`oct`** (RFC 7518 §6.4): `k` is present and not empty.
//! - Every binary member is canonical unpadded base64url (RFC 7515 §2),
//!   so each key has one encoding and re-serializes to the same strings.
//! - **Common members** have their JSON types: `kid`, `use`, `alg`, `x5u`,
//!   `x5t` and `x5t#S256` are strings, `key_ops` and `x5c` are arrays of
//!   strings (RFC 7517 §4.2–§4.9). X.509 members are carried, never
//!   fetched, decoded or validated (ADR 0006, ADR 0022).
//! - **`key_ops`** has no duplicate values (RFC 7517 §4.3, a MUST).
//! - **`use` and `key_ops`**, when both are present, are consistent
//!   (RFC 7517 §4.3, a MUST): `sig` allows only `sign`/`verify`, and `enc`
//!   only `encrypt`, `decrypt`, `wrapKey`, `unwrapKey`, `deriveKey` and
//!   `deriveBits` (RFC 7517 §4.2 puts key wrapping and key agreement under
//!   `enc`). `key_ops` alone may combine unrelated operations: RFC 7517
//!   §4.3 only says they "SHOULD NOT" be, and WebCrypto exports such keys.
//! - **Unregistered `use` and `key_ops` values** are allowed (RFC 7517
//!   §4.2–§4.3: "Other values MAY be used") and kept verbatim as
//!   [`KeyUse::Unknown`](crate::jwk::KeyUse::Unknown) / [`KeyOp::Unknown`](crate::jwk::KeyOp::Unknown). polyjose gives them no
//!   meaning, so they never conflict on import, and an unregistered `use`
//!   makes [`Jwk::permits`][permits] refuse every operation (fail closed).
//! - **Unknown members** are ignored, as RFC 7517 §4 requires, and kept in
//!   [`Jwk::other_params`][other_params] so the key re-serializes to the
//!   same members.
//!
//! # Error codes
//!
//! One rule decides between the two key codes (ADR 0018 Q3):
//!
//! - [`UnsupportedAlgorithm`](crate::Error::UnsupportedAlgorithm): well-formed, but not supported in
//!   0.1.0. An unknown `kty`; an `EC` or `OKP` `crv` not listed above
//!   (including another key type's curve); an RSA private key (ADR 0021).
//! - [`InvalidKey`](crate::Error::InvalidKey): malformed. A missing or wrongly typed member,
//!   a wrong length, a non-minimal or out-of-range RSA value, an empty `k`,
//!   duplicate `key_ops`, or inconsistent `use`/`key_ops`.
//! - [`InvalidBase64`](crate::Error::InvalidBase64): a binary member is not canonical unpadded
//!   base64url (the code RFC 7515 §2 decoding uses everywhere).
//! - [`InvalidJson`](crate::Error::InvalidJson) ([`Jwk::from_json`][from_json] only): not one
//!   I-JSON object, or a member name occurs twice (RFC 7517 §4).
//!
//! Every detail is a fixed string; no error contains input or key bytes
//! (ADR 0007). No input makes import panic.
//!
//! # Secrets
//!
//! The secret members, `oct` `k` and `EC`/`OKP` `d`, are decoded straight
//! into [`Zeroizing`](zeroize::Zeroizing) buffers of their exact size, so they are wiped when
//! the key is dropped and never reallocated. `Debug` prints them as
//! `"<redacted>"` and shows only the names of unknown members.
//! [`Jwk::to_json`][to_json] returns a [`Zeroizing<String>`](zeroize::Zeroizing), and
//! [`Jwk::to_object`][to_object] an [`Object`](crate::json::Object), which wipes its strings on
//! drop. [`Jwk::to_public`][to_public] drops `d` and every unknown member.
//!
//! [from_json]: crate::jwk::Jwk::from_json
//! [from_object]: crate::jwk::Jwk::from_object
//! [to_json]: crate::jwk::Jwk::to_json
//! [to_object]: crate::jwk::Jwk::to_object
//! [to_public]: crate::jwk::Jwk::to_public
//! [permits]: crate::jwk::Jwk::permits
//! [other_params]: crate::jwk::Jwk::other_params

use core::fmt;

use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::error::{Error, Result};
use crate::json::{self, Object, Value};
use crate::jwa::{ContentEncAlg, KeyMgmtAlg, SigningAlg};
use crate::util::{b64url_decode, b64url_encode};

mod set;
pub use set::JwkSet;

/// The `kty` (key type) values polyjose supports (RFC 7517 §4.1,
/// RFC 7518 §6.1, RFC 8037 §2).
///
/// `kty` is a case-sensitive string (RFC 7517 §4.1), so `"ec"` is not
/// `EC`. Any other value is rejected on import with
/// [`Error::UnsupportedAlgorithm`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyType {
    /// `oct`: a symmetric key (RFC 7518 §6.4).
    Oct,
    /// `RSA`: an RSA public key (RFC 7518 §6.3.1). RSA private keys are not
    /// supported in 0.1.0 (ADR 0021).
    Rsa,
    /// `EC`: an elliptic curve key (RFC 7518 §6.2, RFC 8812 §3.1).
    Ec,
    /// `OKP`: an octet key pair (RFC 8037 §2).
    Okp,
}

impl KeyType {
    /// The `kty` string, exactly as registered (RFC 7518 §7.4.2,
    /// RFC 8037 §5).
    pub fn as_str(self) -> &'static str {
        match self {
            KeyType::Oct => "oct",
            KeyType::Rsa => "RSA",
            KeyType::Ec => "EC",
            KeyType::Okp => "OKP",
        }
    }

    /// The key type whose registered name is exactly `kty`.
    fn from_name(kty: &str) -> Option<KeyType> {
        match kty {
            "oct" => Some(KeyType::Oct),
            "RSA" => Some(KeyType::Rsa),
            "EC" => Some(KeyType::Ec),
            "OKP" => Some(KeyType::Okp),
            _ => None,
        }
    }
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The `crv` values polyjose supports for `kty` `EC`.
///
/// The `crv` value is a case-sensitive string (RFC 7518 §6.2.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EcCurve {
    /// `P-256` (RFC 7518 §6.2.1.1).
    P256,
    /// `P-384` (RFC 7518 §6.2.1.1).
    P384,
    /// `P-521` (RFC 7518 §6.2.1.1).
    P521,
    /// `secp256k1` (RFC 8812 §3.1).
    Secp256k1,
}

impl EcCurve {
    /// The `crv` string, exactly as registered (RFC 7518 §7.6.2,
    /// RFC 8812 §4.4).
    pub fn as_str(self) -> &'static str {
        match self {
            EcCurve::P256 => "P-256",
            EcCurve::P384 => "P-384",
            EcCurve::P521 => "P-521",
            EcCurve::Secp256k1 => "secp256k1",
        }
    }

    /// The length in octets of `x`, `y` and `d` for this curve.
    ///
    /// `x` and `y` are the full size of a field element
    /// (RFC 7518 §6.2.1.2–§6.2.1.3, RFC 8812 §3.1: "exactly 256 bits"), and
    /// `d` is ⌈log₂(n)/8⌉ octets for the group order n
    /// (RFC 7518 §6.2.2.1). For these four curves both are 32, 48, 66 and
    /// 32 octets.
    pub fn coordinate_len(self) -> usize {
        match self {
            EcCurve::P256 | EcCurve::Secp256k1 => 32,
            EcCurve::P384 => 48,
            EcCurve::P521 => 66,
        }
    }

    fn from_name(crv: &str) -> Option<EcCurve> {
        match crv {
            "P-256" => Some(EcCurve::P256),
            "P-384" => Some(EcCurve::P384),
            "P-521" => Some(EcCurve::P521),
            "secp256k1" => Some(EcCurve::Secp256k1),
            _ => None,
        }
    }
}

impl fmt::Display for EcCurve {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The `crv` values polyjose supports for `kty` `OKP` (RFC 8037 §2).
///
/// `Ed448` and `X448` are registered (RFC 8037 §5) but out of scope for
/// 0.1.0 (ADR 0006), so they are rejected on import like any unknown curve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OkpCurve {
    /// `Ed25519`: EdDSA signing keys (RFC 8037 §3.1).
    Ed25519,
    /// `X25519`: ECDH-ES key agreement keys (RFC 8037 §3.2).
    X25519,
}

impl OkpCurve {
    /// The `crv` string, exactly as registered (RFC 8037 §5).
    pub fn as_str(self) -> &'static str {
        match self {
            OkpCurve::Ed25519 => "Ed25519",
            OkpCurve::X25519 => "X25519",
        }
    }

    /// The length in octets of `x` and `d`: 32 for both curves (an Ed25519
    /// key is 32 octets, RFC 8032 §5.1.5; an X25519 key is 32 octets,
    /// RFC 7748 §5; RFC 8037 §2 encodes them unchanged).
    pub fn key_len(self) -> usize {
        match self {
            OkpCurve::Ed25519 | OkpCurve::X25519 => 32,
        }
    }

    fn from_name(crv: &str) -> Option<OkpCurve> {
        match crv {
            "Ed25519" => Some(OkpCurve::Ed25519),
            "X25519" => Some(OkpCurve::X25519),
            _ => None,
        }
    }
}

impl fmt::Display for OkpCurve {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The `use` (public key use) member (RFC 7517 §4.2).
///
/// `use` is a case-sensitive string. RFC 7517 §4.2 defines `sig` and
/// `enc`, and "other values MAY be used": they are kept verbatim as
/// [`KeyUse::Unknown`]. polyjose gives an unknown value no meaning, so a key
/// carrying one is never selected for a polyjose operation (see
/// [`Jwk::permits`]).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyUse {
    /// `sig`: signature (RFC 7517 §4.2).
    Sig,
    /// `enc`: encryption, which also covers key wrapping and key agreement
    /// (RFC 7517 §4.2).
    Enc,
    /// Any other value, preserved verbatim (RFC 7517 §4.2).
    Unknown(String),
}

impl KeyUse {
    /// The `use` string, exactly as it appears in the JWK.
    pub fn as_str(&self) -> &str {
        match self {
            KeyUse::Sig => "sig",
            KeyUse::Enc => "enc",
            KeyUse::Unknown(s) => s,
        }
    }
}

impl From<&str> for KeyUse {
    fn from(s: &str) -> KeyUse {
        match s {
            "sig" => KeyUse::Sig,
            "enc" => KeyUse::Enc,
            _ => KeyUse::Unknown(s.to_owned()),
        }
    }
}

impl fmt::Display for KeyUse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One `key_ops` (key operations) value (RFC 7517 §4.3).
///
/// The values are case-sensitive strings. Values other than the eight
/// RFC 7517 §4.3 defines "MAY be used": they are kept verbatim as
/// [`KeyOp::Unknown`] and polyjose gives them no meaning.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyOp {
    /// `sign`: compute a digital signature or MAC.
    Sign,
    /// `verify`: verify a digital signature or MAC.
    Verify,
    /// `encrypt`: encrypt content.
    Encrypt,
    /// `decrypt`: decrypt content and validate decryption.
    Decrypt,
    /// `wrapKey`: encrypt a key.
    WrapKey,
    /// `unwrapKey`: decrypt a key and validate decryption.
    UnwrapKey,
    /// `deriveKey`: derive a key.
    DeriveKey,
    /// `deriveBits`: derive bits not to be used as a key.
    DeriveBits,
    /// Any other value, preserved verbatim (RFC 7517 §4.3).
    Unknown(String),
}

impl KeyOp {
    /// The operation string, exactly as it appears in the JWK.
    pub fn as_str(&self) -> &str {
        match self {
            KeyOp::Sign => "sign",
            KeyOp::Verify => "verify",
            KeyOp::Encrypt => "encrypt",
            KeyOp::Decrypt => "decrypt",
            KeyOp::WrapKey => "wrapKey",
            KeyOp::UnwrapKey => "unwrapKey",
            KeyOp::DeriveKey => "deriveKey",
            KeyOp::DeriveBits => "deriveBits",
            KeyOp::Unknown(s) => s,
        }
    }

    /// The `use` value this operation belongs to, if it is a registered
    /// operation.
    ///
    /// `sign` and `verify` are signature operations. `encrypt`, `decrypt`,
    /// `wrapKey`, `unwrapKey`, `deriveKey` and `deriveBits` are encryption
    /// operations, because RFC 7517 §4.2 says key wrapping "is a kind of
    /// encryption" and that `enc` "is also to be used for public keys used
    /// for key agreement operations". Unknown operations have no use.
    fn key_use(&self) -> Option<KeyUse> {
        match self {
            KeyOp::Sign | KeyOp::Verify => Some(KeyUse::Sig),
            KeyOp::Encrypt
            | KeyOp::Decrypt
            | KeyOp::WrapKey
            | KeyOp::UnwrapKey
            | KeyOp::DeriveKey
            | KeyOp::DeriveBits => Some(KeyUse::Enc),
            KeyOp::Unknown(_) => None,
        }
    }
}

impl From<&str> for KeyOp {
    fn from(s: &str) -> KeyOp {
        match s {
            "sign" => KeyOp::Sign,
            "verify" => KeyOp::Verify,
            "encrypt" => KeyOp::Encrypt,
            "decrypt" => KeyOp::Decrypt,
            "wrapKey" => KeyOp::WrapKey,
            "unwrapKey" => KeyOp::UnwrapKey,
            "deriveKey" => KeyOp::DeriveKey,
            "deriveBits" => KeyOp::DeriveBits,
            _ => KeyOp::Unknown(s.to_owned()),
        }
    }
}

impl fmt::Display for KeyOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The `alg` (algorithm) member of a JWK (RFC 7517 §4.4).
///
/// A JWK `alg` names a value from the IANA "JSON Web Signature and
/// Encryption Algorithms" registry (RFC 7517 §4.4), which holds JWS `alg`,
/// JWE `alg` and JWE `enc` names (RFC 7518 §7.1). The three sets of names
/// are disjoint, so each string maps to at most one family. Any other
/// string, including registered names polyjose does not implement
/// (`RSA-OAEP`, `RSA1_5`, `Ed448`), is kept verbatim as
/// [`KeyAlg::Unknown`] and round-trips unchanged (see [`crate::jwa`]).
///
/// The comparison with a header `alg` is exact: `EdDSA` and `Ed25519` are
/// different values (RFC 9864 §2.2, ADR 0026 §2 step 8).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyAlg {
    /// A JWS algorithm (RFC 7518 §3.1).
    Signing(SigningAlg),
    /// A JWE key management algorithm (RFC 7518 §4.1).
    KeyMgmt(KeyMgmtAlg),
    /// A JWE content encryption algorithm (RFC 7518 §5.1), as used on `oct`
    /// keys for `dir` (RFC 7518 §4.5).
    ContentEnc(ContentEncAlg),
    /// Any other value, preserved verbatim.
    Unknown(String),
}

impl KeyAlg {
    /// The `alg` string, exactly as it appears in the JWK.
    pub fn as_str(&self) -> &str {
        match self {
            KeyAlg::Signing(a) => a.as_str(),
            KeyAlg::KeyMgmt(a) => a.as_str(),
            KeyAlg::ContentEnc(a) => a.as_str(),
            KeyAlg::Unknown(s) => s,
        }
    }
}

impl From<&str> for KeyAlg {
    fn from(s: &str) -> KeyAlg {
        let signing = SigningAlg::from(s);
        if signing.is_known() {
            return KeyAlg::Signing(signing);
        }
        let key_mgmt = KeyMgmtAlg::from(s);
        if key_mgmt.is_known() {
            return KeyAlg::KeyMgmt(key_mgmt);
        }
        let content_enc = ContentEncAlg::from(s);
        if content_enc.is_known() {
            return KeyAlg::ContentEnc(content_enc);
        }
        KeyAlg::Unknown(s.to_owned())
    }
}

impl fmt::Display for KeyAlg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Detail for a JWK that is valid JSON but not a JSON object.
const NOT_AN_OBJECT: &str = "a JWK must be a JSON object";

/// The placeholder `Debug` prints instead of private key material.
const REDACTED: &str = "<redacted>";

/// The members every key type shares (RFC 7517 §4.1–§4.9).
const COMMON_MEMBERS: &[&str] = &[
    "kty", "use", "key_ops", "alg", "kid", "x5u", "x5c", "x5t", "x5t#S256",
];

/// A symmetric key (`kty` `oct`, RFC 7518 §6.4).
///
/// The key value `k` is secret. It is held in a buffer that is wiped on
/// drop, and `Debug` prints `"<redacted>"` instead of it.
#[derive(Clone)]
pub struct OctKey {
    k: Zeroizing<Vec<u8>>,
}

impl OctKey {
    /// The length of the key value in octets (public: it is visible in the
    /// encoded JWK).
    pub fn len(&self) -> usize {
        self.k.len()
    }

    /// Always `false`: an empty `k` is rejected on import.
    pub fn is_empty(&self) -> bool {
        self.k.is_empty()
    }

    /// The secret key value (RFC 7518 §6.4.1).
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "read by the HMAC, AES and dir features")
    )]
    pub(crate) fn k(&self) -> &[u8] {
        &self.k
    }
}

impl fmt::Debug for OctKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OctKey").field("k", &REDACTED).finish()
    }
}

/// The only secret, `k`, is a [`Zeroizing`] buffer.
impl ZeroizeOnDrop for OctKey {}

/// An RSA public key (`kty` `RSA`, RFC 7518 §6.3.1).
///
/// RSA private keys are not supported in 0.1.0: a JWK with any private
/// member is rejected with [`Error::UnsupportedAlgorithm`] (ADR 0021).
///
/// Validation is structural: `n` and `e` are minimal Base64urlUInt values
/// (RFC 7518 §2), `n` is odd and at least 2048 bits (RFC 8017 §3.1,
/// RFC 7518 §3.3, ADR 0007), and `e` is odd with 3 ≤ e < n
/// (RFC 8017 §3.1). The modulus upper bound of 8192 bits is enforced
/// where the key is used (ADR 0026 §2 step 8).
#[derive(Clone)]
pub struct RsaPublicKey {
    n: Vec<u8>,
    e: Vec<u8>,
}

impl RsaPublicKey {
    /// `n`: the modulus, big-endian, without leading zero octets
    /// (RFC 7518 §6.3.1.1).
    pub fn n(&self) -> &[u8] {
        &self.n
    }

    /// `e`: the public exponent, big-endian, without leading zero octets
    /// (RFC 7518 §6.3.1.2).
    pub fn e(&self) -> &[u8] {
        &self.e
    }

    /// The size of the modulus in bits (at least 2048).
    pub fn modulus_bits(&self) -> usize {
        // `n` is non-empty with a non-zero first octet (checked on import),
        // so this is 8 bits per octet minus the first octet's leading zeros.
        let top = self.n.first().copied().unwrap_or(0);
        (self.n.len() * 8).saturating_sub(top.leading_zeros() as usize)
    }
}

impl fmt::Debug for RsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaPublicKey")
            .field("n", &b64url_encode(&self.n))
            .field("e", &b64url_encode(&self.e))
            .finish()
    }
}

/// An elliptic curve key (`kty` `EC`, RFC 7518 §6.2, RFC 8812 §3.1): a
/// public point (`x`, `y`) and, for a private key, the scalar `d`.
///
/// Validation is structural: the curve is supported and every member has
/// its exact length. Whether the point is on the curve (ADR 0007) is
/// checked when the curve arithmetic arrives (feature 0002 T01).
///
/// `d` is held in a buffer that is wiped on drop, and `Debug` prints
/// `"<redacted>"` instead of it.
#[derive(Clone)]
pub struct EcKey {
    crv: EcCurve,
    x: Vec<u8>,
    y: Vec<u8>,
    d: Option<Zeroizing<Vec<u8>>>,
}

impl EcKey {
    /// `crv`: the curve (RFC 7518 §6.2.1.1).
    pub fn crv(&self) -> EcCurve {
        self.crv
    }

    /// `x`: the x coordinate, [`EcCurve::coordinate_len`] octets
    /// (RFC 7518 §6.2.1.2).
    pub fn x(&self) -> &[u8] {
        &self.x
    }

    /// `y`: the y coordinate, [`EcCurve::coordinate_len`] octets
    /// (RFC 7518 §6.2.1.3).
    pub fn y(&self) -> &[u8] {
        &self.y
    }

    /// Whether the private scalar `d` is present (RFC 7518 §6.2.2).
    pub fn is_private(&self) -> bool {
        self.d.is_some()
    }

    /// The private scalar `d`, if present (RFC 7518 §6.2.2.1).
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "read by the ES* signing and ECDH-ES features")
    )]
    pub(crate) fn d(&self) -> Option<&[u8]> {
        self.d.as_deref().map(Vec::as_slice)
    }

    /// The public part: the same point without `d`.
    fn to_public(&self) -> EcKey {
        EcKey {
            crv: self.crv,
            x: self.x.clone(),
            y: self.y.clone(),
            d: None,
        }
    }
}

impl fmt::Debug for EcKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("EcKey");
        s.field("crv", &self.crv)
            .field("x", &b64url_encode(&self.x))
            .field("y", &b64url_encode(&self.y));
        if self.d.is_some() {
            s.field("d", &REDACTED);
        }
        s.finish()
    }
}

/// The only secret, `d`, is a [`Zeroizing`] buffer.
impl ZeroizeOnDrop for EcKey {}

/// An octet key pair (`kty` `OKP`, RFC 8037 §2): the public key `x` and,
/// for a private key, `d`.
///
/// Validation is structural: the curve is supported and `x` and `d` have
/// their exact length. Small-order Ed25519 keys are rejected where the
/// key is used (ADR 0026 §6).
///
/// `d` is held in a buffer that is wiped on drop, and `Debug` prints
/// `"<redacted>"` instead of it.
#[derive(Clone)]
pub struct OkpKey {
    crv: OkpCurve,
    x: Vec<u8>,
    d: Option<Zeroizing<Vec<u8>>>,
}

impl OkpKey {
    /// `crv`: the subtype of the key (RFC 8037 §2).
    pub fn crv(&self) -> OkpCurve {
        self.crv
    }

    /// `x`: the public key, [`OkpCurve::key_len`] octets (RFC 8037 §2).
    pub fn x(&self) -> &[u8] {
        &self.x
    }

    /// Whether the private key `d` is present (RFC 8037 §2).
    pub fn is_private(&self) -> bool {
        self.d.is_some()
    }

    /// The private key `d`, if present (RFC 8037 §2).
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "read by the EdDSA signing and ECDH-ES features")
    )]
    pub(crate) fn d(&self) -> Option<&[u8]> {
        self.d.as_deref().map(Vec::as_slice)
    }

    /// The public part: the same key without `d`.
    fn to_public(&self) -> OkpKey {
        OkpKey {
            crv: self.crv,
            x: self.x.clone(),
            d: None,
        }
    }
}

impl fmt::Debug for OkpKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("OkpKey");
        s.field("crv", &self.crv)
            .field("x", &b64url_encode(&self.x));
        if self.d.is_some() {
            s.field("d", &REDACTED);
        }
        s.finish()
    }
}

/// The only secret, `d`, is a [`Zeroizing`] buffer.
impl ZeroizeOnDrop for OkpKey {}

/// The key-type-specific part of a [`Jwk`] (RFC 7518 §6, RFC 8037 §2).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum KeyMaterial {
    /// `kty` `oct` (RFC 7518 §6.4).
    Oct(OctKey),
    /// `kty` `RSA`, public keys only (RFC 7518 §6.3.1, ADR 0021).
    Rsa(RsaPublicKey),
    /// `kty` `EC` (RFC 7518 §6.2, RFC 8812 §3.1).
    Ec(EcKey),
    /// `kty` `OKP` (RFC 8037 §2).
    Okp(OkpKey),
}

impl KeyMaterial {
    /// The `kty` of this key.
    pub fn key_type(&self) -> KeyType {
        match self {
            KeyMaterial::Oct(_) => KeyType::Oct,
            KeyMaterial::Rsa(_) => KeyType::Rsa,
            KeyMaterial::Ec(_) => KeyType::Ec,
            KeyMaterial::Okp(_) => KeyType::Okp,
        }
    }

    /// Whether this key is of the family JWS `alg` requires: the key
    /// binding table of ADR 0026 §2 step 8, the **only** copy of it. JWS
    /// key binding (feature 0002) and JWK Set candidate selection
    /// (ADR 0029 §2 item 1, [`JwkSet::verification_candidates`]) both call
    /// this; nothing else may restate the table.
    ///
    /// | `alg` | key |
    /// |---|---|
    /// | `HS256`, `HS384`, `HS512` (RFC 7518 §3.2) | `oct` |
    /// | `RS*`, `PS*` (RFC 7518 §3.3, §3.5) | `RSA` |
    /// | `ES256` / `ES384` / `ES512` (RFC 7518 §3.4) | `EC` `P-256` / `P-384` / `P-521` |
    /// | `ES256K` (RFC 8812 §3.2) | `EC` `secp256k1` |
    /// | `EdDSA` (RFC 8037 §3.1), `Ed25519` (RFC 9864 §2.2) | `OKP` `Ed25519` |
    ///
    /// `none` and unknown algorithms are served by no key (RFC 8725 §3.1).
    /// `X25519` keys are key agreement keys (RFC 8037 §3.2) and serve no
    /// JWS algorithm. Only the family is checked here; the JWK `alg`,
    /// `use` and `key_ops` members and key strength are separate checks.
    pub(crate) fn serves_signing_alg(&self, alg: &SigningAlg) -> bool {
        use SigningAlg as A;
        match (alg, self) {
            (A::HS256 | A::HS384 | A::HS512, KeyMaterial::Oct(_)) => true,
            (
                A::RS256 | A::RS384 | A::RS512 | A::PS256 | A::PS384 | A::PS512,
                KeyMaterial::Rsa(_),
            ) => true,
            (A::ES256, KeyMaterial::Ec(key)) => key.crv == EcCurve::P256,
            (A::ES384, KeyMaterial::Ec(key)) => key.crv == EcCurve::P384,
            (A::ES512, KeyMaterial::Ec(key)) => key.crv == EcCurve::P521,
            (A::ES256K, KeyMaterial::Ec(key)) => key.crv == EcCurve::Secp256k1,
            (A::EdDSA | A::Ed25519, KeyMaterial::Okp(key)) => key.crv == OkpCurve::Ed25519,
            // Every variant is listed (no `_` for `alg`), so a new
            // algorithm does not compile until it has a row above.
            (
                A::HS256
                | A::HS384
                | A::HS512
                | A::RS256
                | A::RS384
                | A::RS512
                | A::PS256
                | A::PS384
                | A::PS512
                | A::ES256
                | A::ES384
                | A::ES512
                | A::ES256K
                | A::EdDSA
                | A::Ed25519
                | A::None
                | A::Unknown(_),
                _,
            ) => false,
        }
    }
}

/// Every secret in the material is a [`Zeroizing`] buffer.
impl ZeroizeOnDrop for KeyMaterial {}

/// A JSON Web Key (RFC 7517 §4) with typed, validated key material.
///
/// Build one with [`Jwk::from_json`] (untrusted bytes) or
/// [`Jwk::from_object`] (an already-parsed object, such as a header's
/// `jwk` or `epk`). Serialize it with [`Jwk::to_object`] or
/// [`Jwk::to_json`].
#[derive(Clone)]
pub struct Jwk {
    material: KeyMaterial,
    key_use: Option<KeyUse>,
    key_ops: Option<Vec<KeyOp>>,
    alg: Option<KeyAlg>,
    kid: Option<String>,
    x5u: Option<String>,
    x5c: Option<Vec<String>>,
    x5t: Option<String>,
    x5t_s256: Option<String>,
    /// Members polyjose does not understand, in input order
    /// (RFC 7517 §4: they "MUST be ignored", and they are kept so the key
    /// re-serializes unchanged). Never a name of a typed member.
    other: Object,
}

impl Jwk {
    /// Parses a JWK from its UTF-8 JSON bytes.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidJson`] if the bytes are not one I-JSON object,
    ///   including a member name that occurs twice (RFC 7517 §4 lets a
    ///   parser reject duplicates, and polyjose does), or the
    ///   [`json::Limits`] are exceeded.
    /// - Every error of [`Jwk::from_object`].
    ///
    /// No error contains any part of the input.
    pub fn from_json(bytes: &[u8]) -> Result<Jwk> {
        let object = json::parse(bytes)?
            .into_object()
            .ok_or(Error::InvalidJson(NOT_AN_OBJECT))?;
        Jwk::from_object(&object)
    }

    /// Builds a JWK from a JSON object, validating it.
    ///
    /// # Errors
    ///
    /// - [`Error::UnsupportedAlgorithm`] if the key is well-formed but of a
    ///   kind polyjose 0.1.0 does not support (ADR 0018 Q3).
    /// - [`Error::InvalidBase64`] if a key member is not canonical unpadded
    ///   base64url (RFC 7515 §2, RFC 7518 §6).
    /// - [`Error::InvalidKey`] if the key is malformed.
    ///
    /// No error contains any part of the input or of the key.
    pub fn from_object(object: &Object) -> Result<Jwk> {
        let material = match key_kind(object)? {
            KeyKind::Oct => KeyMaterial::Oct(parse_oct(object)?),
            KeyKind::Rsa => KeyMaterial::Rsa(parse_rsa(object)?),
            KeyKind::Ec(crv) => KeyMaterial::Ec(parse_ec(object, crv)?),
            KeyKind::Okp(crv) => KeyMaterial::Okp(parse_okp(object, crv)?),
        };
        let kty = material.key_type();
        let key_use = optional_str(object, "use", "use must be a string")?.map(KeyUse::from);
        let key_ops = parse_key_ops(object)?;
        check_use_matches_key_ops(key_use.as_ref(), key_ops.as_deref())?;
        let alg = optional_str(object, "alg", "alg must be a string")?.map(KeyAlg::from);
        let kid = optional_str(object, "kid", "kid must be a string")?.map(str::to_owned);
        let x5u = optional_str(object, "x5u", "x5u must be a string")?.map(str::to_owned);
        let x5c = parse_x5c(object)?;
        let x5t = optional_str(object, "x5t", "x5t must be a string")?.map(str::to_owned);
        let x5t_s256 =
            optional_str(object, "x5t#S256", "x5t#S256 must be a string")?.map(str::to_owned);
        let typed = type_members(kty);
        let mut other = Object::new();
        for (name, value) in object {
            if !COMMON_MEMBERS.contains(&name) && !typed.contains(&name) {
                other.insert(name, value.clone());
            }
        }
        Ok(Jwk {
            material,
            key_use,
            key_ops,
            alg,
            kid,
            x5u,
            x5c,
            x5t,
            x5t_s256,
            other,
        })
    }

    /// The key as a JSON object: `kty`, the key-type members, then `use`,
    /// `key_ops`, `alg`, `kid`, `x5u`, `x5c`, `x5t`, `x5t#S256` when set,
    /// then the [`other_params`](Jwk::other_params) in their order.
    ///
    /// Binary members are written in canonical unpadded base64url
    /// (RFC 7515 §2), so a key read with [`Jwk::from_object`] writes back
    /// the same member values. The object may contain private key members;
    /// like every [`Object`] it wipes its strings when dropped.
    pub fn to_object(&self) -> Object {
        let mut o = Object::new();
        o.insert("kty", self.key_type().as_str());
        match &self.material {
            KeyMaterial::Oct(key) => {
                o.insert("k", b64url_encode(&key.k));
            }
            KeyMaterial::Rsa(key) => {
                o.insert("n", b64url_encode(&key.n));
                o.insert("e", b64url_encode(&key.e));
            }
            KeyMaterial::Ec(key) => {
                o.insert("crv", key.crv.as_str());
                o.insert("x", b64url_encode(&key.x));
                o.insert("y", b64url_encode(&key.y));
                if let Some(d) = &key.d {
                    o.insert("d", b64url_encode(d));
                }
            }
            KeyMaterial::Okp(key) => {
                o.insert("crv", key.crv.as_str());
                o.insert("x", b64url_encode(&key.x));
                if let Some(d) = &key.d {
                    o.insert("d", b64url_encode(d));
                }
            }
        }
        if let Some(v) = &self.key_use {
            o.insert("use", v.as_str());
        }
        if let Some(ops) = &self.key_ops {
            let ops: Vec<Value> = ops.iter().map(|op| Value::from(op.as_str())).collect();
            o.insert("key_ops", ops);
        }
        if let Some(v) = &self.alg {
            o.insert("alg", v.as_str());
        }
        if let Some(v) = &self.kid {
            o.insert("kid", v.as_str());
        }
        if let Some(v) = &self.x5u {
            o.insert("x5u", v.as_str());
        }
        if let Some(certs) = &self.x5c {
            let certs: Vec<Value> = certs.iter().map(|c| Value::from(c.as_str())).collect();
            o.insert("x5c", certs);
        }
        if let Some(v) = &self.x5t {
            o.insert("x5t", v.as_str());
        }
        if let Some(v) = &self.x5t_s256 {
            o.insert("x5t#S256", v.as_str());
        }
        for (name, value) in &self.other {
            o.insert(name, value.clone());
        }
        o
    }

    /// The key as compact JSON (see [`Jwk::to_object`] for the member
    /// order).
    ///
    /// The string is a [`Zeroizing<String>`] whatever the key, because it
    /// may contain private key members (`k`, `d`) and is wiped when dropped.
    pub fn to_json(&self) -> Zeroizing<String> {
        Zeroizing::new(self.to_object().to_json())
    }

    /// The public part of the key, or `None` for an `oct` key, which has
    /// no public part (RFC 7518 §6.4).
    ///
    /// The result has no private members (`d`), keeps `kid`, `use`,
    /// `key_ops`, `alg`, `x5u`, `x5c`, `x5t` and `x5t#S256` unchanged, and
    /// drops the [`other_params`](Jwk::other_params): polyjose cannot tell
    /// whether an unknown member is secret, so it never publishes one.
    /// `key_ops` is not rewritten: a private key's `["sign"]` stays
    /// `["sign"]`, which [`Jwk::permits`] then refuses for `verify`.
    pub fn to_public(&self) -> Option<Jwk> {
        let material = match &self.material {
            KeyMaterial::Oct(_) => return None,
            KeyMaterial::Rsa(key) => KeyMaterial::Rsa(key.clone()),
            KeyMaterial::Ec(key) => KeyMaterial::Ec(key.to_public()),
            KeyMaterial::Okp(key) => KeyMaterial::Okp(key.to_public()),
        };
        Some(Jwk {
            material,
            key_use: self.key_use.clone(),
            key_ops: self.key_ops.clone(),
            alg: self.alg.clone(),
            kid: self.kid.clone(),
            x5u: self.x5u.clone(),
            x5c: self.x5c.clone(),
            x5t: self.x5t.clone(),
            x5t_s256: self.x5t_s256.clone(),
            other: Object::new(),
        })
    }

    /// Whether the key is a public key: `RSA`, or `EC`/`OKP` without `d`.
    /// An `oct` key is secret by nature (RFC 7518 §6.4) and never public.
    pub fn is_public(&self) -> bool {
        match &self.material {
            KeyMaterial::Oct(_) => false,
            KeyMaterial::Rsa(_) => true,
            KeyMaterial::Ec(key) => !key.is_private(),
            KeyMaterial::Okp(key) => !key.is_private(),
        }
    }

    /// The required members of RFC 7638 §3.2 for this key type, with `kty`,
    /// in lexicographic order (RFC 7638 §3.3) and in canonical form:
    /// `crv`, `kty`, `x`, `y` for `EC`; `crv`, `kty`, `x` for `OKP`
    /// (RFC 8037 §2); `e`, `kty`, `n` for `RSA`; `k`, `kty` for `oct`.
    ///
    /// Binary members are re-encoded from the decoded octets, so they are
    /// canonical base64url, and `n`/`e` are minimal Base64urlUInt
    /// (RFC 7638 §3.2). A private key yields the same members as its
    /// public key. The `oct` result contains the secret `k`; the object
    /// wipes it on drop.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "used by JWK thumbprints (feature 0001 T06)")
    )]
    pub(crate) fn thumbprint_members(&self) -> Object {
        let mut o = Object::new();
        match &self.material {
            KeyMaterial::Oct(key) => {
                o.insert("k", b64url_encode(&key.k));
                o.insert("kty", KeyType::Oct.as_str());
            }
            KeyMaterial::Rsa(key) => {
                o.insert("e", b64url_encode(&key.e));
                o.insert("kty", KeyType::Rsa.as_str());
                o.insert("n", b64url_encode(&key.n));
            }
            KeyMaterial::Ec(key) => {
                o.insert("crv", key.crv.as_str());
                o.insert("kty", KeyType::Ec.as_str());
                o.insert("x", b64url_encode(&key.x));
                o.insert("y", b64url_encode(&key.y));
            }
            KeyMaterial::Okp(key) => {
                o.insert("crv", key.crv.as_str());
                o.insert("kty", KeyType::Okp.as_str());
                o.insert("x", b64url_encode(&key.x));
            }
        }
        o
    }

    /// The key type (`kty`, RFC 7517 §4.1).
    pub fn key_type(&self) -> KeyType {
        self.material.key_type()
    }

    /// The typed key material (RFC 7518 §6, RFC 8037 §2).
    pub fn material(&self) -> &KeyMaterial {
        &self.material
    }

    /// `use`: the intended use of the public key (RFC 7517 §4.2).
    pub fn key_use(&self) -> Option<&KeyUse> {
        self.key_use.as_ref()
    }

    /// `key_ops`: the operations the key is intended for (RFC 7517 §4.3),
    /// in their original order and without duplicates.
    pub fn key_ops(&self) -> Option<&[KeyOp]> {
        self.key_ops.as_deref()
    }

    /// `alg`: the algorithm intended for use with the key (RFC 7517 §4.4).
    pub fn alg(&self) -> Option<&KeyAlg> {
        self.alg.as_ref()
    }

    /// `kid`: the key ID, a case-sensitive string (RFC 7517 §4.5).
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// `x5u`: X.509 URL (RFC 7517 §4.6). Carried, never fetched.
    pub fn x5u(&self) -> Option<&str> {
        self.x5u.as_deref()
    }

    /// `x5c`: X.509 certificate chain, base64 (not base64url) DER strings
    /// (RFC 7517 §4.7). Carried, never decoded or validated (ADR 0006).
    pub fn x5c(&self) -> Option<&[String]> {
        self.x5c.as_deref()
    }

    /// `x5t`: base64url SHA-1 certificate thumbprint (RFC 7517 §4.8).
    /// Carried verbatim, never decoded, computed or checked (ADR 0022).
    pub fn x5t(&self) -> Option<&str> {
        self.x5t.as_deref()
    }

    /// `x5t#S256`: base64url SHA-256 certificate thumbprint
    /// (RFC 7517 §4.9). Carried verbatim, never decoded or checked
    /// (ADR 0006).
    pub fn x5t_s256(&self) -> Option<&str> {
        self.x5t_s256.as_deref()
    }

    /// Members polyjose does not understand, preserved in input order
    /// (RFC 7517 §4: they "MUST be ignored").
    pub fn other_params(&self) -> &Object {
        &self.other
    }

    /// Whether the key's `use` and `key_ops` allow `op`.
    ///
    /// - `use`, if present, must be the use `op` belongs to: `sig` for
    ///   `sign`/`verify`, `enc` for the encryption, key wrapping and key
    ///   agreement operations (RFC 7517 §4.2). An unregistered `use` allows
    ///   nothing, since polyjose cannot know what it means.
    /// - `key_ops`, if present, must contain `op` (RFC 7517 §4.3).
    ///
    /// A key with neither member allows every operation; the algorithm
    /// binding is checked separately (`alg`, `kty`, `crv`). This is the
    /// `use`/`key_ops` part of JWS key binding (ADR 0026 §2 step 8) and of
    /// JWK Set candidate selection (ADR 0029 §2).
    ///
    /// ```
    /// use polyjose::jwk::{Jwk, KeyOp};
    ///
    /// let jwk = Jwk::from_json(br#"{"kty":"oct","k":"AAEC","use":"sig"}"#)?;
    /// assert!(jwk.permits(&KeyOp::Verify));
    /// assert!(!jwk.permits(&KeyOp::Encrypt));
    /// # Ok::<(), polyjose::Error>(())
    /// ```
    pub fn permits(&self, op: &KeyOp) -> bool {
        let use_ok = self
            .key_use
            .as_ref()
            .is_none_or(|key_use| op.key_use().as_ref() == Some(key_use));
        let ops_ok = self.key_ops.as_ref().is_none_or(|ops| ops.contains(op));
        use_ok && ops_ok
    }
}

/// Prints the key material (with private members as `"<redacted>"`), the
/// common members, and only the *names* of the unknown members, whose
/// values could be secret.
impl fmt::Debug for Jwk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Jwk")
            .field("material", &self.material)
            .field("use", &self.key_use)
            .field("key_ops", &self.key_ops)
            .field("alg", &self.alg)
            .field("kid", &self.kid)
            .field("x5u", &self.x5u)
            .field("x5c", &self.x5c)
            .field("x5t", &self.x5t)
            .field("x5t#S256", &self.x5t_s256)
            .field("other_names", &MemberNames(&self.other))
            .finish()
    }
}

/// Debug-prints the member names of an object, never its values.
struct MemberNames<'a>(&'a Object);

impl fmt::Debug for MemberNames<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(|(name, _)| name))
            .finish()
    }
}

/// Every secret in a `Jwk` (its key material and any unknown member) is
/// wiped on drop.
impl ZeroizeOnDrop for Jwk {}

/// The member names a key type defines, besides `kty`.
fn type_members(kty: KeyType) -> &'static [&'static str] {
    match kty {
        KeyType::Oct => &["k"],
        KeyType::Rsa => &["n", "e"],
        KeyType::Ec => &["crv", "x", "y", "d"],
        KeyType::Okp => &["crv", "x", "d"],
    }
}

/// The string value of member `name`, which must be present.
fn required_str<'a>(
    object: &'a Object,
    name: &str,
    missing: &'static str,
    not_string: &'static str,
) -> Result<&'a str> {
    optional_str(object, name, not_string)?.ok_or(Error::InvalidKey(missing))
}

/// The string value of member `name`, if present.
fn optional_str<'a>(
    object: &'a Object,
    name: &str,
    not_string: &'static str,
) -> Result<Option<&'a str>> {
    match object.get(name) {
        None => Ok(None),
        Some(value) => value
            .as_str()
            .map(Some)
            .ok_or(Error::InvalidKey(not_string)),
    }
}

/// Decodes the secret base64url member `name`, which must be present.
/// The decoded octets go straight into a wiped-on-drop buffer.
fn required_secret(
    object: &Object,
    name: &str,
    missing: &'static str,
    not_string: &'static str,
) -> Result<Zeroizing<Vec<u8>>> {
    let encoded = required_str(object, name, missing, not_string)?;
    Ok(Zeroizing::new(b64url_decode(encoded)?))
}

/// Decodes the secret base64url member `name`, if present.
fn optional_secret(
    object: &Object,
    name: &str,
    not_string: &'static str,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    match optional_str(object, name, not_string)? {
        None => Ok(None),
        Some(encoded) => Ok(Some(Zeroizing::new(b64url_decode(encoded)?))),
    }
}

/// `kty` `oct` (RFC 7518 §6.4).
fn parse_oct(object: &Object) -> Result<OctKey> {
    // RFC 7518 §6.4.1: `k` is the base64url-encoded key value. An empty
    // key is no key: it would make every MAC forgeable.
    let k = required_secret(object, "k", "k is missing", "k must be a string")?;
    if k.is_empty() {
        return Err(Error::InvalidKey("k must not be empty"));
    }
    Ok(OctKey { k })
}

/// What `kty` (and, for `EC`/`OKP`, `crv`) say the key is.
#[derive(Clone, Copy)]
enum KeyKind {
    Oct,
    Rsa,
    Ec(EcCurve),
    Okp(OkpCurve),
}

/// Reads `kty` and, for `EC` and `OKP`, `crv`.
///
/// - `kty` MUST be present and is a case-sensitive string (RFC 7517 §4.1);
///   missing or not a string → [`Error::InvalidKey`].
/// - A `kty` other than `oct`, `RSA`, `EC` and `OKP` →
///   [`Error::UnsupportedAlgorithm`].
/// - For `EC` and `OKP`, `crv` MUST be present (RFC 7518 §6.2.1,
///   RFC 8037 §2) and is case-sensitive (RFC 7518 §6.2.1.1); missing or not
///   a string → [`Error::InvalidKey`]. A curve other than P-256, P-384,
///   P-521, secp256k1 (RFC 7518 §6.2.1.1, RFC 8812 §3.1) for `EC`, or
///   Ed25519, X25519 for `OKP` (RFC 8037 §2; Ed448/X448 are out of scope,
///   ADR 0006) → [`Error::UnsupportedAlgorithm`].
///
/// "Well-formed but not supported" is `UnsupportedAlgorithm`, and
/// "malformed" is `InvalidKey`, as ADR 0018 Q3 decides for key import.
fn key_kind(object: &Object) -> Result<KeyKind> {
    let kty = required_str(object, "kty", "kty is missing", "kty must be a string")?;
    let kty = KeyType::from_name(kty).ok_or(Error::UnsupportedAlgorithm)?;
    let crv = || required_str(object, "crv", "crv is missing", "crv must be a string");
    Ok(match kty {
        KeyType::Oct => KeyKind::Oct,
        KeyType::Rsa => KeyKind::Rsa,
        KeyType::Ec => KeyKind::Ec(EcCurve::from_name(crv()?).ok_or(Error::UnsupportedAlgorithm)?),
        KeyType::Okp => {
            KeyKind::Okp(OkpCurve::from_name(crv()?).ok_or(Error::UnsupportedAlgorithm)?)
        }
    })
}

/// Whether `object` is a key whose `kty`, or `EC`/`OKP` `crv`, is a string
/// polyjose does not support: the members RFC 7517 §5 says a JWK Set
/// reader SHOULD ignore, and ADR 0029 §3 skips. Malformed members are not
/// included (the set skips them separately), nor are RSA private keys
/// (they fail the set, ADR 0021).
pub(crate) fn is_unsupported_key_kind(object: &Object) -> bool {
    matches!(key_kind(object), Err(Error::UnsupportedAlgorithm))
}

/// The RSA private key members (RFC 7518 §6.3.2).
const RSA_PRIVATE_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth"];

/// Decodes the Base64urlUInt member `name` (RFC 7518 §2): canonical
/// base64url of the big-endian octets, non-empty, and "the minimum number
/// of octets needed to represent the value", so no leading zero octet
/// unless the value is zero (`AA`).
fn required_uint(
    object: &Object,
    name: &str,
    missing: &'static str,
    not_string: &'static str,
    not_minimal: &'static str,
) -> Result<Vec<u8>> {
    let octets = b64url_decode(required_str(object, name, missing, not_string)?)?;
    match octets.as_slice() {
        [] => Err(Error::InvalidKey(not_minimal)),
        [0, _, ..] => Err(Error::InvalidKey(not_minimal)),
        _ => Ok(octets),
    }
}

/// `kty` `RSA`, public keys only (RFC 7518 §6.3.1, ADR 0021).
fn parse_rsa(object: &Object) -> Result<RsaPublicKey> {
    // ADR 0021: an RSA private JWK is not supported in 0.1.0. Any private
    // member (RFC 7518 §6.3.2), whatever its value, rejects the key before
    // anything else is read, so the outcome does not depend on the rest.
    if RSA_PRIVATE_MEMBERS.iter().any(|name| object.contains(name)) {
        return Err(Error::UnsupportedAlgorithm);
    }
    let n = required_uint(
        object,
        "n",
        "n is missing",
        "n must be a string",
        "n is not a minimal Base64urlUInt",
    )?;
    // RFC 7518 §3.3/§4.2 and ADR 0007: at least 2048 bits. `n` has no
    // leading zero octet, so 256 octets is 2048 bits exactly when the top
    // bit is set. RFC 8017 §3.1: n is a product of odd primes, so odd.
    let (Some(&first), Some(&last)) = (n.first(), n.last()) else {
        return Err(Error::InvalidKey("n is not a minimal Base64urlUInt"));
    };
    if n.len() < 256 || (n.len() == 256 && first < 0x80) {
        return Err(Error::InvalidKey("RSA modulus is shorter than 2048 bits"));
    }
    if last & 1 == 0 {
        return Err(Error::InvalidKey("RSA modulus must be odd"));
    }
    let e = required_uint(
        object,
        "e",
        "e is missing",
        "e must be a string",
        "e is not a minimal Base64urlUInt",
    )?;
    // RFC 8017 §3.1: 3 ≤ e ≤ n − 1, and e is odd (it is coprime to the
    // even λ(n)). With minimal encodings, e < n compares lengths first.
    let e_odd = e.last().is_some_and(|last| last & 1 == 1);
    if !e_odd || e.as_slice() == [1] {
        return Err(Error::InvalidKey(
            "RSA exponent must be odd and greater than 1",
        ));
    }
    if e.len() > n.len() || (e.len() == n.len() && e >= n) {
        return Err(Error::InvalidKey(
            "RSA exponent must be less than the modulus",
        ));
    }
    Ok(RsaPublicKey { n, e })
}

/// `kty` `EC` (RFC 7518 §6.2, RFC 8812 §3.1).
fn parse_ec(object: &Object, crv: EcCurve) -> Result<EcKey> {
    let len = crv.coordinate_len();
    // RFC 7518 §6.2.1.2–§6.2.1.3: `x` and `y` MUST be the full size of a
    // coordinate (RFC 8812 §3.1: "exactly 256 bits, with any leading zeros
    // preserved"). `y` is required for all four curves (RFC 7518 §6.2.1);
    // compressed points are not defined for JWK (RFC 8812 §3.1).
    let x = b64url_decode(required_str(
        object,
        "x",
        "x is missing",
        "x must be a string",
    )?)?;
    if x.len() != len {
        return Err(Error::InvalidKey("x has the wrong length for crv"));
    }
    let y = b64url_decode(required_str(
        object,
        "y",
        "y is missing",
        "y must be a string",
    )?)?;
    if y.len() != len {
        return Err(Error::InvalidKey("y has the wrong length for crv"));
    }
    // RFC 7518 §6.2.2.1: `d` MUST be ⌈log₂(n)/8⌉ octets.
    let d = optional_secret(object, "d", "d must be a string")?;
    if d.as_ref().is_some_and(|d| d.len() != len) {
        return Err(Error::InvalidKey("d has the wrong length for crv"));
    }
    Ok(EcKey { crv, x, y, d })
}

/// `kty` `OKP` (RFC 8037 §2).
fn parse_okp(object: &Object, crv: OkpCurve) -> Result<OkpKey> {
    let len = crv.key_len();
    // RFC 8037 §2: `x` MUST be present; RFC 8032 §5.1.5 and RFC 7748 §5
    // fix its length at 32 octets.
    let x = b64url_decode(required_str(
        object,
        "x",
        "x is missing",
        "x must be a string",
    )?)?;
    if x.len() != len {
        return Err(Error::InvalidKey("x has the wrong length for crv"));
    }
    // RFC 8037 §2: `d` is present for private keys only.
    let d = optional_secret(object, "d", "d must be a string")?;
    if d.as_ref().is_some_and(|d| d.len() != len) {
        return Err(Error::InvalidKey("d has the wrong length for crv"));
    }
    Ok(OkpKey { crv, x, d })
}

/// RFC 7517 §4.3: if both `use` and `key_ops` are present, "the
/// information they convey MUST be consistent". `sig` is consistent only
/// with `sign`/`verify`, and `enc` only with the encryption, key wrapping
/// and key agreement operations (RFC 7517 §4.2). An unregistered `use` or
/// operation has no meaning polyjose could compare, so it never conflicts;
/// such keys are never selected for a polyjose operation instead
/// ([`Jwk::permits`]).
fn check_use_matches_key_ops(key_use: Option<&KeyUse>, key_ops: Option<&[KeyOp]>) -> Result<()> {
    let (Some(key_use @ (KeyUse::Sig | KeyUse::Enc)), Some(ops)) = (key_use, key_ops) else {
        return Ok(());
    };
    for op in ops {
        if op.key_use().is_some_and(|op_use| op_use != *key_use) {
            return Err(Error::InvalidKey("use and key_ops are inconsistent"));
        }
    }
    Ok(())
}

/// `key_ops` (RFC 7517 §4.3): an array of case-sensitive strings with no
/// duplicate values.
fn parse_key_ops(object: &Object) -> Result<Option<Vec<KeyOp>>> {
    const NOT_STRINGS: &str = "key_ops must be an array of strings";
    let Some(value) = object.get("key_ops") else {
        return Ok(None);
    };
    let items = value.as_array().ok_or(Error::InvalidKey(NOT_STRINGS))?;
    let mut ops: Vec<KeyOp> = Vec::with_capacity(items.len());
    for item in items {
        let op = KeyOp::from(item.as_str().ok_or(Error::InvalidKey(NOT_STRINGS))?);
        // RFC 7517 §4.3: "Duplicate key operation values MUST NOT be
        // present in the array." Values compare as exact strings.
        if ops.contains(&op) {
            return Err(Error::InvalidKey("key_ops must not contain duplicates"));
        }
        ops.push(op);
    }
    Ok(Some(ops))
}

/// `x5c` (RFC 7517 §4.7): an array of strings. The certificates are not
/// decoded or validated (ADR 0006).
fn parse_x5c(object: &Object) -> Result<Option<Vec<String>>> {
    const NOT_STRINGS: &str = "x5c must be an array of strings";
    let Some(value) = object.get("x5c") else {
        return Ok(None);
    };
    let items = value.as_array().ok_or(Error::InvalidKey(NOT_STRINGS))?;
    items
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or(Error::InvalidKey(NOT_STRINGS))
        })
        .collect::<Result<Vec<String>>>()
        .map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_type_names_round_trip_case_sensitively() {
        for kty in [KeyType::Oct, KeyType::Rsa, KeyType::Ec, KeyType::Okp] {
            assert_eq!(KeyType::from_name(kty.as_str()), Some(kty));
            assert_eq!(kty.to_string(), kty.as_str());
        }
        for other in ["ec", "rsa", "OCT", "okp", "", "EC "] {
            assert_eq!(KeyType::from_name(other), None, "{other}");
        }
    }

    #[test]
    fn curve_names_and_lengths() {
        let ec = [
            (EcCurve::P256, "P-256", 32),
            (EcCurve::P384, "P-384", 48),
            (EcCurve::P521, "P-521", 66),
            (EcCurve::Secp256k1, "secp256k1", 32),
        ];
        for (crv, name, len) in ec {
            assert_eq!(crv.as_str(), name);
            assert_eq!(crv.to_string(), name);
            assert_eq!(crv.coordinate_len(), len);
            assert_eq!(EcCurve::from_name(name), Some(crv));
        }
        for (crv, name) in [(OkpCurve::Ed25519, "Ed25519"), (OkpCurve::X25519, "X25519")] {
            assert_eq!(crv.as_str(), name);
            assert_eq!(crv.to_string(), name);
            assert_eq!(crv.key_len(), 32);
            assert_eq!(OkpCurve::from_name(name), Some(crv));
        }
        for other in ["p-256", "P256", "Ed25519", "secp256r1", ""] {
            assert_eq!(EcCurve::from_name(other), None, "{other}");
        }
        for other in ["Ed448", "X448", "ed25519", "P-256", ""] {
            assert_eq!(OkpCurve::from_name(other), None, "{other}");
        }
    }

    #[test]
    fn use_values_round_trip_and_keep_unknown_verbatim() {
        assert_eq!(KeyUse::from("sig"), KeyUse::Sig);
        assert_eq!(KeyUse::from("enc"), KeyUse::Enc);
        for s in ["sig", "enc", "Sig", "tls", ""] {
            assert_eq!(KeyUse::from(s).as_str(), s);
            assert_eq!(KeyUse::from(s).to_string(), s);
        }
        assert_eq!(KeyUse::from("SIG"), KeyUse::Unknown("SIG".into()));
    }

    #[test]
    fn key_op_values_round_trip_and_classify() {
        let registered = [
            ("sign", KeyOp::Sign, Some(KeyUse::Sig)),
            ("verify", KeyOp::Verify, Some(KeyUse::Sig)),
            ("encrypt", KeyOp::Encrypt, Some(KeyUse::Enc)),
            ("decrypt", KeyOp::Decrypt, Some(KeyUse::Enc)),
            ("wrapKey", KeyOp::WrapKey, Some(KeyUse::Enc)),
            ("unwrapKey", KeyOp::UnwrapKey, Some(KeyUse::Enc)),
            ("deriveKey", KeyOp::DeriveKey, Some(KeyUse::Enc)),
            ("deriveBits", KeyOp::DeriveBits, Some(KeyUse::Enc)),
        ];
        for (s, op, key_use) in registered {
            assert_eq!(KeyOp::from(s), op);
            assert_eq!(op.as_str(), s);
            assert_eq!(op.to_string(), s);
            assert_eq!(op.key_use(), key_use);
        }
        let unknown = KeyOp::from("wrapkey");
        assert_eq!(unknown, KeyOp::Unknown("wrapkey".into()));
        assert_eq!(unknown.as_str(), "wrapkey");
        assert_eq!(unknown.key_use(), None);
    }

    #[test]
    fn alg_maps_to_its_family_or_unknown() {
        assert_eq!(KeyAlg::from("RS256"), KeyAlg::Signing(SigningAlg::RS256));
        assert_eq!(
            KeyAlg::from("Ed25519"),
            KeyAlg::Signing(SigningAlg::Ed25519)
        );
        assert_eq!(KeyAlg::from("EdDSA"), KeyAlg::Signing(SigningAlg::EdDSA));
        assert_eq!(KeyAlg::from("A128KW"), KeyAlg::KeyMgmt(KeyMgmtAlg::A128KW));
        assert_eq!(
            KeyAlg::from("A256GCM"),
            KeyAlg::ContentEnc(ContentEncAlg::A256GCM)
        );
        for s in ["RSA-OAEP", "RSA1_5", "Ed448", "hs256", "", "x-custom"] {
            assert_eq!(KeyAlg::from(s), KeyAlg::Unknown(s.to_owned()), "{s}");
        }
        for s in [
            "HS256",
            "ECDH-ES+A128KW",
            "A128CBC-HS256",
            "none",
            "RSA-OAEP",
        ] {
            assert_eq!(KeyAlg::from(s).as_str(), s);
            assert_eq!(KeyAlg::from(s).to_string(), s);
        }
    }

    // RFC 7517 Appendix A.2 (EC P-256 private key).
    const EC_PRIVATE: &str = r#"{"kty":"EC","crv":"P-256",
        "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
        "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
        "d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
        "use":"enc","kid":"1"}"#;
    const EC_D: &str = "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE";
    // RFC 8037 Appendix A.1 (Ed25519 private key).
    const OKP_PRIVATE: &str = r#"{"kty":"OKP","crv":"Ed25519",
        "d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
        "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
    const OKP_D: &str = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";
    // RFC 7517 Appendix A.3 (HMAC key).
    const OCT_K: &str =
        "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";
    // RFC 7638 §3.1 (RSA public key).
    const RSA_N: &str = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";

    fn parse(json: &str) -> Jwk {
        match Jwk::from_json(json.as_bytes()) {
            Ok(jwk) => jwk,
            Err(e) => panic!("valid test key rejected: {e}"),
        }
    }

    fn object(json: &str) -> Object {
        json::parse(json.as_bytes())
            .ok()
            .and_then(Value::into_object)
            .unwrap_or_default()
    }

    fn oct_json() -> String {
        format!(r#"{{"kty":"oct","k":"{OCT_K}","x-secret":"hunter2"}}"#)
    }

    fn rsa_json() -> String {
        format!(r#"{{"kty":"RSA","n":"{RSA_N}","e":"AQAB","alg":"RS256","kid":"2011-04-29"}}"#)
    }

    #[test]
    fn debug_redacts_private_members_and_unknown_values() {
        for (json, secret) in [
            (EC_PRIVATE.to_owned(), EC_D),
            (OKP_PRIVATE.to_owned(), OKP_D),
            (oct_json(), OCT_K),
        ] {
            let jwk = parse(&json);
            let debug = format!("{jwk:?}");
            assert!(debug.contains("\"<redacted>\""), "{debug}");
            assert!(!debug.contains(secret), "{debug}");
            assert!(!debug.contains("hunter2"), "{debug}");
            let material = format!("{:?}", jwk.material());
            assert!(material.contains("\"<redacted>\""), "{material}");
            assert!(!material.contains(secret), "{material}");
        }
        // Unknown members show their names only.
        let debug = format!("{:?}", parse(&oct_json()));
        assert!(debug.contains("other_names: [\"x-secret\"]"), "{debug}");
        // Public members are printed (they are not secret), and a public key
        // has no `d` entry at all.
        let public = parse(EC_PRIVATE).to_public().map(|k| format!("{k:?}"));
        let public = public.unwrap_or_default();
        assert!(
            public.contains("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4"),
            "{public}"
        );
        assert!(!public.contains("<redacted>"), "{public}");
        let rsa = format!("{:?}", parse(&rsa_json()));
        assert!(rsa.contains("AQAB") && rsa.contains(RSA_N), "{rsa}");
    }

    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    #[test]
    fn secrets_live_in_zeroizing_buffers() {
        assert_zeroize_on_drop::<OctKey>();
        assert_zeroize_on_drop::<EcKey>();
        assert_zeroize_on_drop::<OkpKey>();
        assert_zeroize_on_drop::<KeyMaterial>();
        assert_zeroize_on_drop::<Jwk>();
        // The secret fields are `Zeroizing` buffers (checked by type), and
        // they hold the decoded octets.
        let oct = parse(&oct_json());
        let KeyMaterial::Oct(key) = oct.material() else {
            panic!("not oct");
        };
        let k: &Zeroizing<Vec<u8>> = &key.k;
        assert_eq!(k.as_slice(), b64url_decode(OCT_K).unwrap_or_default());
        assert_eq!(key.k(), k.as_slice());
        assert_eq!(key.len(), 64);
        assert!(!key.is_empty());
        let ec = parse(EC_PRIVATE);
        let KeyMaterial::Ec(key) = ec.material() else {
            panic!("not EC");
        };
        let d: &Option<Zeroizing<Vec<u8>>> = &key.d;
        assert_eq!(d.as_deref().map(Vec::len), Some(32));
        assert_eq!(key.d().map(<[u8]>::to_vec), b64url_decode(EC_D).ok());
        let okp = parse(OKP_PRIVATE);
        let KeyMaterial::Okp(key) = okp.material() else {
            panic!("not OKP");
        };
        let d: &Option<Zeroizing<Vec<u8>>> = &key.d;
        assert_eq!(d.as_deref().map(Vec::len), Some(32));
        assert_eq!(key.d().map(<[u8]>::to_vec), b64url_decode(OKP_D).ok());
        // Serialized private keys come back in a wiped-on-drop string.
        let json: Zeroizing<String> = okp.to_json();
        assert!(json.contains(OKP_D));
    }

    #[test]
    fn decoded_secret_buffers_have_exact_capacity() {
        // No spare capacity: a buffer that never grew left no stale copy.
        let ec = parse(EC_PRIVATE);
        if let KeyMaterial::Ec(key) = ec.material() {
            assert_eq!(key.d.as_ref().map(|d| d.capacity()), Some(32));
        }
        let oct = parse(&oct_json());
        if let KeyMaterial::Oct(key) = oct.material() {
            assert_eq!(key.k.capacity(), 64);
        }
    }

    #[test]
    fn to_public_drops_d_and_unknown_members() {
        let ec = parse(EC_PRIVATE);
        assert!(!ec.is_public());
        let public = ec.to_public();
        let public = public.as_ref();
        assert!(public.is_some_and(Jwk::is_public));
        let KeyMaterial::Ec(key) = public.map(Jwk::material).unwrap_or(ec.material()) else {
            panic!("not EC");
        };
        assert!(key.d().is_none() && !key.is_private());
        assert_eq!(public.and_then(Jwk::kid), Some("1"));
        let okp = parse(OKP_PRIVATE).to_public();
        assert!(okp.as_ref().is_some_and(Jwk::is_public));
        assert!(okp.is_some_and(|k| !k.to_json().contains(OKP_D)));
        assert!(parse(&oct_json()).to_public().is_none());
        assert!(!parse(&oct_json()).is_public());
        let rsa = parse(&format!(
            r#"{{"kty":"RSA","n":"{RSA_N}","e":"AQAB","ext":true}}"#
        ));
        assert!(rsa.is_public());
        let rsa_public = rsa.to_public();
        assert!(rsa_public.is_some_and(|k| k.other_params().is_empty() && k.is_public()));
    }

    #[test]
    fn thumbprint_members_are_the_rfc_7638_required_set_in_order() {
        let names = |jwk: &Jwk| -> Vec<String> {
            jwk.thumbprint_members()
                .iter()
                .map(|(n, _)| n.to_owned())
                .collect()
        };
        let ec = parse(EC_PRIVATE);
        assert_eq!(names(&ec), ["crv", "kty", "x", "y"]);
        let okp = parse(OKP_PRIVATE);
        assert_eq!(names(&okp), ["crv", "kty", "x"]);
        let rsa = parse(&rsa_json());
        assert_eq!(names(&rsa), ["e", "kty", "n"]);
        let oct = parse(&oct_json());
        assert_eq!(names(&oct), ["k", "kty"]);
        // RFC 7638 §3.1: the exact JSON hashed for the example RSA key.
        assert_eq!(
            rsa.thumbprint_members().to_json(),
            format!(r#"{{"e":"AQAB","kty":"RSA","n":"{RSA_N}"}}"#)
        );
        // RFC 8037 Appendix A.3: the exact JSON hashed for the Ed25519 key.
        assert_eq!(
            okp.thumbprint_members().to_json(),
            r#"{"crv":"Ed25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#
        );
        // A private key and its public key give the same members.
        let ec_public = ec.to_public().map(|k| k.thumbprint_members());
        assert_eq!(ec_public, Some(ec.thumbprint_members()));
        assert_eq!(
            oct.thumbprint_members().to_json(),
            format!(r#"{{"k":"{OCT_K}","kty":"oct"}}"#)
        );
    }

    #[test]
    fn unsupported_key_kind_matches_import() {
        let skipped = [
            r#"{"kty":"oct2"}"#,
            r#"{"kty":"ec","crv":"P-256"}"#,
            r#"{"kty":"AKP","alg":"ML-DSA-44"}"#,
            r#"{"kty":"EC","crv":"P-192","x":"AA","y":"AA"}"#,
            r#"{"kty":"EC","crv":"Ed25519","x":"AA"}"#,
            r#"{"kty":"OKP","crv":"Ed448","x":"AA"}"#,
            r#"{"kty":"OKP","crv":"X448","x":"AA"}"#,
        ];
        for json in skipped {
            assert!(is_unsupported_key_kind(&object(json)), "{json}");
            assert_eq!(
                Jwk::from_json(json.as_bytes()).err(),
                Some(Error::UnsupportedAlgorithm)
            );
        }
        let kept = [
            r#"{}"#,
            r#"{"kty":1}"#,
            r#"{"kty":"EC"}"#,
            r#"{"kty":"OKP","crv":7}"#,
            r#"{"kty":"oct","k":""}"#,
            // RSA private keys fail a whole set (ADR 0029 §3), so they are
            // not "unsupported kind" even though import says
            // UnsupportedAlgorithm.
            r#"{"kty":"RSA","n":"AQAB","e":"AQAB","d":"AQAB"}"#,
            EC_PRIVATE,
        ];
        for json in kept {
            assert!(!is_unsupported_key_kind(&object(json)), "{json}");
        }
    }

    #[test]
    fn modulus_bits_counts_from_the_top_set_bit() {
        let KeyMaterial::Rsa(key) = parse(&rsa_json()).material().clone() else {
            panic!("not RSA");
        };
        assert_eq!(key.modulus_bits(), 2048);
        assert_eq!(key.n().len(), 256);
        assert_eq!(key.e(), [1, 0, 1]);
        let n = RsaPublicKey {
            n: vec![0x01, 0xff, 0xff],
            e: vec![3],
        };
        assert_eq!(n.modulus_bits(), 17);
    }
}
