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
//! # JWK Sets
//!
//! [`JwkSet`](crate::jwk::JwkSet) reads a JWK Set (RFC 7517 §5), keeping
//! the supported, valid keys in order and skipping the rest; private keys,
//! RSA ones included, are kept as imported (ADR 0067 §4).
//! [`JwkSet::verification_candidates`](crate::jwk::JwkSet::verification_candidates)
//! picks the keys that may verify a JWS by family, `alg`, `use`, `key_ops`
//! and `kid` (ADR 0029 §2).
//! [`JwkSelector`](crate::jwk::JwkSelector) holds validated `kid`, `alg`,
//! `use` and `key_ops` criteria for picking keys from a set (ADR 0054 §1).
//!
//! # Thumbprints
//!
//! [`Jwk::thumbprint`][thumbprint] and [`Jwk::thumbprint_uri`][thumbprint_uri]
//! give the RFC 7638 §3 thumbprint and the RFC 9278 §3 URI with SHA-256,
//! SHA-384 or SHA-512, chosen by [`ThumbprintHash`](crate::jwk::ThumbprintHash)
//! (ADR 0054 §8).
//!
//! # What import checks
//!
//! Validation is structural, plus the curve checks the primitives provide
//! (ADR 0041 §4, ADR 0043, ADR 0007): EC points must be on their curve, EC
//! private scalars in range, Ed25519 public keys valid, and a private key
//! must be the key of its own public part. An RSA modulus must be
//! 2048..=8192 bits (RFC 7518 §3.3, ADR 0007, ADR 0026 §2 step 8), so every
//! RSA key, from JSON, PEM or DER, is in range when it is imported.
//!
//! - **`kty`** must be present and is case-sensitive (RFC 7517 §4.1).
//!   `oct`, `RSA`, `EC` and `OKP` are supported.
//! - **`EC`** (RFC 7518 §6.2, RFC 8812 §3.1): `crv` is `P-256`, `P-384`,
//!   `P-521` or `secp256k1`; `x` and `y` are present and exactly 32, 48,
//!   66 or 32 octets; `d`, if present, has the same length
//!   (RFC 7518 §6.2.1.2–§6.2.2.1). Then (`x`, `y`) must be a point on the
//!   curve, with reduced coordinates, other than the identity (SEC 1 v2
//!   §3.2.2.1), and `d` must be in [1, n − 1] for the group order n
//!   (SEC 1 v2 §3.2.1), both checked by the curve crate (ADR 0041 §4).
//!   Last, `d` must be the private key of the point: d·G = (`x`, `y`)
//!   (SEC 1 v2 §3.2.1; ADR 0043 §3).
//! - **`OKP`** (RFC 8037 §2): `crv` is `Ed25519` or `X25519` (Ed448 and
//!   X448 are out of scope, ADR 0006); `x`, and `d` if present, are 32
//!   octets. An `Ed25519` `x` must decode canonically to a point
//!   (RFC 8032 §5.1.3) that is not of small order (ADR 0026 §6,
//!   ADR 0041 §4) and has no torsion component (ADR 0043 §1), and a `d`
//!   must derive that `x` (RFC 8032 §5.1.5, RFC 8037 §2; ADR 0043 §3). An
//!   `X25519` `x` has no further check: every 32-octet string is a valid
//!   u-coordinate (RFC 7748 §5), and torsion is neutralised by clamping
//!   (ADR 0043 §2). An `X25519` `d` must derive `x`: `x` = X25519(`d`, 9)
//!   (RFC 7748 §6.1, RFC 8037 §2; ADR 0043 §3).
//! - **`RSA`** (RFC 7518 §6.3): `n` and `e` are minimal Base64urlUInt
//!   values, non-empty with no leading zero octet (RFC 7518 §2,
//!   §6.3.1.1); `n` is odd (RFC 8017 §3.1) and 2048 to 8192 bits
//!   (RFC 7518 §3.3, ADR 0007, ADR 0026 §2 step 8); `e` is odd with
//!   3 ≤ e < n (RFC 8017 §3.1). A private key (ADR 0067) has all of `d`,
//!   `p`, `q`, `dp`, `dq` and `qi` (RFC 7518 §6.3.2), each a minimal
//!   Base64urlUInt, and must be the key of `n` and `e` (ADR 0043):
//!   n = p·q, d < n, d·e ≡ 1 mod (p − 1) and (q − 1), and `dp`, `dq`,
//!   `qi` the CRT values of `d`, `p`, `q`. A key with `oth` (more than two
//!   primes, §6.3.2.7) is rejected before anything else is read.
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
//! - **`alg`** (RFC 7517 §4.4), checked last, once the key is well-formed:
//!   - `RSA1_5` (ADR 0021) and `RSA-OAEP` (SHA-1, ADR 0022), exactly as
//!     registered, are rejected on every key type.
//!   - A known JWS `alg`, JWE `alg` or JWE `enc` must be one the key's
//!     family serves (RFC 8725 §3.1: one key, one algorithm): the JWS table
//!     of ADR 0026 §2 step 8 (`HS*` → `oct`, `RS*`/`PS*` → `RSA`, `ES256`
//!     → `P-256`, ...; `none` → no key), `RSA-OAEP-256` → `RSA`; `A*KW`,
//!     `A*GCMKW`, `dir` and `PBES2-*` → `oct`; `ECDH-ES` and
//!     `ECDH-ES+A*KW` → `EC` `P-256`/`P-384`/`P-521` or `OKP` `X25519`
//!     (not `secp256k1` or `Ed25519`, ADR 0006); any `enc` → `oct`
//!     (RFC 7518 §4.5). Each table exists once, on `KeyMaterial`; JWS
//!     (0002) and JWE (0003) key binding reuse them.
//!   - Any other value (unregistered, or registered but not shipped, such
//!     as `Ed448`) is kept verbatim as
//!     [`KeyAlg::Unknown`](crate::jwk::KeyAlg::Unknown) and round-trips
//!     unchanged. It matches no header `alg`, so the key is unusable for
//!     any operation that checks the JWK `alg`.
//!
//! # Check order
//!
//! When a key has several problems, the first in this order decides the
//! error, so the result does not depend on member order:
//!
//! 1. `kty`, then the `EC`/`OKP` `crv` (unsupported → `UnsupportedAlgorithm`).
//! 2. For `RSA`, `oth` (→ `UnsupportedAlgorithm`, ADR 0067 §3), before
//!    anything else is read.
//! 3. Every structural check: the key-type members (for `EC`, the lengths
//!    of `x`, `y` and `d` first, then the point, then the scalar, then
//!    whether `d` derives the point; for `OKP`, the lengths, then the
//!    `Ed25519` `x`, then whether `d` derives it), then `use`, `key_ops` (and their
//!    consistency), `alg`'s type, `kid`, `x5u`, `x5c`, `x5t`, `x5t#S256`
//!    (→ `InvalidKey` or `InvalidBase64`).
//! 4. The `alg` value: `RSA1_5`/`RSA-OAEP` (→ `UnsupportedAlgorithm`), then
//!    the family (→ `KeyAlgorithmMismatch`).
//!
//! A malformed key is always reported as malformed, whatever its `alg`
//! (ADR 0018 Q3: "unsupported" presumes "well-formed").
//!
//! # Error codes
//!
//! One rule decides between the two key codes (ADR 0018 Q3):
//!
//! - [`UnsupportedAlgorithm`](crate::Error::UnsupportedAlgorithm): well-formed, but not supported.
//!   An unknown `kty`; an `EC` or `OKP` `crv` not listed above
//!   (including another key type's curve); a multi-prime RSA key (`oth`,
//!   ADR 0067 §3); an `alg` of `RSA1_5` or `RSA-OAEP` (ADRs 0021, 0022).
//! - [`KeyAlgorithmMismatch`](crate::Error::KeyAlgorithmMismatch): a
//!   well-formed key whose known `alg` its family cannot serve
//!   (RFC 7517 §4.4, RFC 8725 §3.1).
//! - [`InvalidKey`](crate::Error::InvalidKey): malformed. A missing or wrongly typed member,
//!   a wrong length, a non-minimal or out-of-range RSA value, an EC point
//!   off its curve, an EC `d` outside [1, n − 1], an invalid, small-order
//!   or mixed-order Ed25519 key, an EC or Ed25519 `d` that is not the
//!   private key of the public part, an empty `k`, duplicate `key_ops`, or
//!   inconsistent `use`/`key_ops`.
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
//! The secret members, `oct` `k`, `EC`/`OKP` `d` and the `RSA` private
//! members (`d`, `p`, `q`, `dp`, `dq`, `qi`), are decoded straight
//! into [`Zeroizing`](zeroize::Zeroizing) buffers of their exact size, so they are wiped when
//! the key is dropped and never reallocated. `Debug` prints them as
//! `"<redacted>"` and shows only the names of unknown members.
//! [`Jwk::to_json`][to_json] returns a [`Zeroizing<String>`](zeroize::Zeroizing), and
//! [`Jwk::to_object`][to_object] an [`Object`](crate::json::Object), which wipes its strings on
//! drop. [`Jwk::to_public`][to_public] drops `d` and every unknown member.
//!
//! **Timing.** JSON parsing, which runs before any base64url decoding of
//! the private members, is not constant-time: the parser branches on the
//! bytes it reads, including the base64url text of `k` and `d`. So the
//! length and structure of a JWK (its member names, value types and string
//! lengths) are observable. The base64url decoding of the secret members
//! is constant-time with respect to their content (best effort at the
//! source level, as for any pure-Rust code): only their length, which the
//! JSON already reveals, affects it.
//!
//! [from_json]: crate::jwk::Jwk::from_json
//! [from_object]: crate::jwk::Jwk::from_object
//! [to_json]: crate::jwk::Jwk::to_json
//! [to_object]: crate::jwk::Jwk::to_object
//! [to_public]: crate::jwk::Jwk::to_public
//! [permits]: crate::jwk::Jwk::permits
//! [other_params]: crate::jwk::Jwk::other_params
//! [thumbprint]: crate::jwk::Jwk::thumbprint
//! [thumbprint_uri]: crate::jwk::Jwk::thumbprint_uri

use core::cmp::Ordering;
use core::fmt;
use core::ops::RangeInclusive;
use std::collections::BTreeSet;

use p256::elliptic_curve::sec1::{FromSec1Point, ModulusSize, Sec1Point, ToSec1Point};
use p256::elliptic_curve::{
    AffinePoint, Curve, CurveArithmetic, FieldBytes, FieldBytesSize, PublicKey, SecretKey,
};
use subtle::ConstantTimeEq as _;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::error::{Error, Result};
use crate::json::{self, Object, Value};
use crate::jwa::{ContentEncAlg, KeyMgmtAlg, SigningAlg};
use crate::util::{b64url_decode, b64url_encode};

mod set;
mod thumbprint;
pub(crate) mod x25519_consistency;

pub use set::{JwkSelector, JwkSet};
pub use thumbprint::ThumbprintHash;
use x25519_consistency::{X25519_PRIVATE_MISMATCH, x25519_private_matches};

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
    /// `RSA`: an RSA key, public (RFC 7518 §6.3.1) or private (§6.3.2;
    /// ADR 0067).
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
/// [`Jwk::from_object`] then rejects `RSA1_5` and `RSA-OAEP` with
/// [`Error::UnsupportedAlgorithm`] (ADRs 0021, 0022), and a known value the
/// key's family cannot serve with [`Error::KeyAlgorithmMismatch`]
/// (RFC 7517 §4.4), so an imported [`Jwk`] never holds either. Other
/// `Unknown` values are kept.
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

/// The RSA modulus sizes polyjose accepts, in bits: at least 2048
/// (RFC 7518 §3.3, §3.5 and, for RSA-OAEP-256, §4.3: "A key of size 2048
/// bits or larger MUST be used"; ADR 0007) and at most 8192, the `rsa`
/// crate's own maximum (ADR 0026 §2 step 8).
///
/// This is the crate's one definition. JWK import checks it, so every RSA
/// key (JSON, PEM or DER) is in range at the trust boundary, and the JWS
/// RSA family passes it to the `rsa` crate when it builds a key.
pub(crate) const RSA_MODULUS_BITS: RangeInclusive<usize> = 2048..=8192;

/// An RSA key (`kty` `RSA`, RFC 7518 §6.3): the public members `n` and `e`
/// (§6.3.1) and, for a private key, the private members `d`, `p`, `q`,
/// `dp`, `dq` and `qi` (§6.3.2). The type keeps its 0.1.0 name, from when
/// RSA keys were public only; [`RsaPublicKey::is_private`] tells the two
/// apart, as [`EcKey::is_private`] does for EC keys (ADR 0067 §2).
///
/// Validation of the public members is structural: `n` and `e` are minimal
/// Base64urlUInt values (RFC 7518 §2), `n` is odd (RFC 8017 §3.1) and 2048
/// to 8192 bits (RFC 7518 §3.3, ADR 0007, ADR 0026 §2 step 8), and `e` is
/// odd with 3 ≤ e < n (RFC 8017 §3.1).
///
/// A private key must carry all six private members, each a minimal
/// Base64urlUInt (RFC 7518 §6.3.2: "If the producer includes any of the
/// other private key parameters, then all of the others MUST be present";
/// a key with `d` alone is refused, ADR 0067 §3). It must be a two-prime
/// key (`oth` is [`Error::UnsupportedAlgorithm`]) and consistent with its
/// public part (ADR 0043, ADR 0067 §2): `n` = `p`·`q`, `d`·`e` ≡ 1 mod
/// (`p` − 1) and (`q` − 1), d < n (RFC 8017 §3.2), and `dp`, `dq` and `qi`
/// the CRT values of `d`, `p` and `q` (RFC 7518 §6.3.2.4–§6.3.2.6).
///
/// The private members are held in buffers that are wiped on drop, and
/// `Debug` prints `"<redacted>"` instead of them.
#[derive(Clone)]
pub struct RsaPublicKey {
    n: Vec<u8>,
    e: Vec<u8>,
    private: Option<RsaPrivateParts>,
}

/// The private members of an RSA private JWK (RFC 7518 §6.3.2), each the
/// big-endian magnitude of a minimal Base64urlUInt, in a buffer wiped on
/// drop. Crate-internal: the RSA files read them to build the `rsa`
/// crate's key (ADR 0067 §6).
#[derive(Clone)]
pub(crate) struct RsaPrivateParts {
    /// `d`, the private exponent (RFC 7518 §6.3.2.1).
    pub(crate) d: Zeroizing<Vec<u8>>,
    /// `p`, the first prime factor (RFC 7518 §6.3.2.2).
    pub(crate) p: Zeroizing<Vec<u8>>,
    /// `q`, the second prime factor (RFC 7518 §6.3.2.3).
    pub(crate) q: Zeroizing<Vec<u8>>,
    /// `dp`, d mod (p − 1) (RFC 7518 §6.3.2.4).
    pub(crate) dp: Zeroizing<Vec<u8>>,
    /// `dq`, d mod (q − 1) (RFC 7518 §6.3.2.5).
    pub(crate) dq: Zeroizing<Vec<u8>>,
    /// `qi`, q⁻¹ mod p (RFC 7518 §6.3.2.6).
    pub(crate) qi: Zeroizing<Vec<u8>>,
}

impl RsaPrivateParts {
    /// The members with their JWK names, in RFC 7518 §6.3.2 order.
    pub(crate) fn members(&self) -> [(&'static str, &[u8]); 6] {
        [
            ("d", &self.d),
            ("p", &self.p),
            ("q", &self.q),
            ("dp", &self.dp),
            ("dq", &self.dq),
            ("qi", &self.qi),
        ]
    }
}

/// Every member is a [`Zeroizing`] buffer.
impl ZeroizeOnDrop for RsaPrivateParts {}

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

    /// The size of the modulus in bits (2048 to 8192).
    pub fn modulus_bits(&self) -> usize {
        bit_len(&self.n)
    }

    /// Whether the private members are present (RFC 7518 §6.3.2): an RSA
    /// private key, which signs (RS*/PS*) and decrypts (RSA-OAEP-256).
    pub fn is_private(&self) -> bool {
        self.private.is_some()
    }

    /// The private members, if present (RFC 7518 §6.3.2).
    pub(crate) fn private(&self) -> Option<&RsaPrivateParts> {
        self.private.as_ref()
    }

    /// The public part: the same `n` and `e` without the private members.
    fn to_public(&self) -> RsaPublicKey {
        RsaPublicKey {
            n: self.n.clone(),
            e: self.e.clone(),
            private: None,
        }
    }
}

impl fmt::Debug for RsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("RsaPublicKey");
        s.field("n", &b64url_encode(&self.n))
            .field("e", &b64url_encode(&self.e));
        if let Some(private) = &self.private {
            for (name, _) in private.members() {
                s.field(name, &REDACTED);
            }
        }
        s.finish()
    }
}

/// The only secrets, the private members, are [`Zeroizing`] buffers.
impl ZeroizeOnDrop for RsaPublicKey {}

/// An elliptic curve key (`kty` `EC`, RFC 7518 §6.2, RFC 8812 §3.1): a
/// public point (`x`, `y`) and, for a private key, the scalar `d`.
///
/// The curve is supported, every member has its exact length, the point is
/// on the curve and is not the identity, and `d` is in [1, n − 1]
/// (ADR 0007, ADR 0041 §4), and `d` is the private key of (`x`, `y`)
/// (ADR 0043 §3).
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
/// The curve is supported and `x` and `d` have their exact length. An
/// `Ed25519` `x` must also decode canonically, not be of small order and
/// have no torsion component (RFC 8032 §5.1.3, ADR 0026 §6, ADR 0041 §4,
/// ADR 0043 §1), and an `Ed25519` `d` must derive `x` (ADR 0043 §3). An
/// `X25519` `x` can be any 32 octets (RFC 7748 §5), and an `X25519` `d`
/// must derive `x` (RFC 7748 §6.1, ADR 0043 §3).
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
    /// `kty` `RSA` (RFC 7518 §6.3), public or private (ADR 0067).
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

    /// Whether this key is of the family JWE key management `alg`
    /// requires: the **only** copy of this table. JWK import uses it for a
    /// JWK `alg` (RFC 7517 §4.4); JWE key binding (feature 0003) must call
    /// it, not restate it.
    ///
    /// | `alg` | key |
    /// |---|---|
    /// | `RSA-OAEP-256` (RFC 7518 §4.3; ADR 0067) | `RSA` |
    /// | `A128KW`, `A192KW`, `A256KW` (RFC 7518 §4.4) | `oct` |
    /// | `dir` (RFC 7518 §4.5) | `oct` |
    /// | `A128GCMKW`, `A192GCMKW`, `A256GCMKW` (RFC 7518 §4.7) | `oct` |
    /// | `PBES2-HS256+A128KW`, `-HS384+A192KW`, `-HS512+A256KW` (RFC 7518 §4.8) | `oct` (the password octets as `k`) |
    /// | `ECDH-ES`, `ECDH-ES+A128KW`, `+A192KW`, `+A256KW` (RFC 7518 §4.6) | `EC` `P-256` / `P-384` / `P-521` (RFC 7518 §4.6, §6.2.1.1), or `OKP` `X25519` (RFC 8037 §3.2) |
    ///
    /// - ECDH-ES is offered on exactly the curves ADR 0006 lists. RFC 8812
    ///   §3.3 leaves secp256k1 key agreement undefined ("beyond the scope of
    ///   this specification"), and `Ed25519` is a signature curve
    ///   (RFC 8037 §3.1; §3.2 names only X25519 and X448 for ECDH-ES), so
    ///   neither serves it.
    /// - PBES2 (RFC 7518 §4.8) is keyed by a password, an "octet sequence"
    ///   (UTF-8 if it is text). No RFC names a JWK form for it, but `oct`
    ///   represents "a symmetric key (or another key whose value is a
    ///   single octet sequence)" (RFC 7518 §6.4), so a JWK with a PBES2
    ///   `alg` must be `oct`, with the password as `k`.
    ///
    /// `RSA-OAEP` (SHA-1, ADR 0022), `RSA1_5` (ADR 0021) and unknown values
    /// are [`KeyMgmtAlg::Unknown`] and served by no key. Only the family is
    /// checked here; key length and the JWK `use`/`key_ops` are separate.
    pub(crate) fn serves_key_mgmt_alg(&self, alg: &KeyMgmtAlg) -> bool {
        use KeyMgmtAlg as A;
        match (alg, self) {
            (A::RsaOaep256, KeyMaterial::Rsa(_)) => true,
            (
                A::A128KW
                | A::A192KW
                | A::A256KW
                | A::Dir
                | A::A128GCMKW
                | A::A192GCMKW
                | A::A256GCMKW
                | A::Pbes2Hs256A128KW
                | A::Pbes2Hs384A192KW
                | A::Pbes2Hs512A256KW,
                KeyMaterial::Oct(_),
            ) => true,
            (
                A::EcdhEs | A::EcdhEsA128KW | A::EcdhEsA192KW | A::EcdhEsA256KW,
                KeyMaterial::Ec(key),
            ) => matches!(key.crv, EcCurve::P256 | EcCurve::P384 | EcCurve::P521),
            (
                A::EcdhEs | A::EcdhEsA128KW | A::EcdhEsA192KW | A::EcdhEsA256KW,
                KeyMaterial::Okp(key),
            ) => key.crv == OkpCurve::X25519,
            // Every variant is listed (no `_` for `alg`), so a new
            // algorithm does not compile until it has a row above.
            (
                A::RsaOaep256
                | A::A128KW
                | A::A192KW
                | A::A256KW
                | A::Dir
                | A::EcdhEs
                | A::EcdhEsA128KW
                | A::EcdhEsA192KW
                | A::EcdhEsA256KW
                | A::A128GCMKW
                | A::A192GCMKW
                | A::A256GCMKW
                | A::Pbes2Hs256A128KW
                | A::Pbes2Hs384A192KW
                | A::Pbes2Hs512A256KW
                | A::Unknown(_),
                _,
            ) => false,
        }
    }

    /// Whether this key is of the family a JWE content encryption `enc`
    /// requires: the **only** copy of this rule, which feature 0003's `dir`
    /// key binding must call too.
    ///
    /// Every `enc` (RFC 7518 §5.1: `A128CBC-HS256`, `A192CBC-HS384`,
    /// `A256CBC-HS512`, §5.2; `A128GCM`, `A192GCM`, `A256GCM`, §5.3) is
    /// keyed by a symmetric CEK. A JWK names one as its `alg` when it is
    /// used directly as the CEK with `dir` (RFC 7518 §4.5), so only an
    /// `oct` key (RFC 7518 §6.4) serves it. Unknown values are served by no
    /// key. Key length is a separate check.
    pub(crate) fn serves_content_enc_alg(&self, enc: &ContentEncAlg) -> bool {
        use ContentEncAlg as E;
        match (enc, self) {
            (
                E::A128CbcHs256
                | E::A192CbcHs384
                | E::A256CbcHs512
                | E::A128GCM
                | E::A192GCM
                | E::A256GCM,
                KeyMaterial::Oct(_),
            ) => true,
            // Every variant is listed (no `_` for `enc`), so a new
            // algorithm does not compile until it has a row above.
            (
                E::A128CbcHs256
                | E::A192CbcHs384
                | E::A256CbcHs512
                | E::A128GCM
                | E::A192GCM
                | E::A256GCM
                | E::Unknown(_),
                _,
            ) => false,
        }
    }
}

/// Registered `alg` names that polyjose deliberately does not implement and
/// that therefore fail JWK import with [`Error::UnsupportedAlgorithm`]:
/// `RSA1_5` (RFC 7518 §4.2; ADR 0021, not shipped in either direction) and
/// `RSA-OAEP` (RFC 7518 §4.3, SHA-1; ADR 0022). They parse as
/// [`KeyAlg::Unknown`]; the match is exact and case-sensitive
/// (RFC 7518 §7.1 names), so `rsa1_5` stays an unknown value.
const UNSUPPORTED_KEY_ALGS: &[&str] = &["RSA1_5", "RSA-OAEP"];

/// The JWK `alg` check of import (RFC 7517 §4.4: `alg` "identifies the
/// algorithm intended for use with the key"), run after every structural
/// check of the key:
///
/// 1. `RSA1_5` or `RSA-OAEP` → [`Error::UnsupportedAlgorithm`], whatever
///    the key ([`UNSUPPORTED_KEY_ALGS`]).
/// 2. A known JWS `alg`, JWE `alg` or `enc` that the key's family cannot
///    serve → [`Error::KeyAlgorithmMismatch`] (RFC 8725 §3.1: a key is used
///    with one algorithm), by the single tables
///    [`KeyMaterial::serves_signing_alg`] (ADR 0026 §2 step 8),
///    [`KeyMaterial::serves_key_mgmt_alg`] and
///    [`KeyMaterial::serves_content_enc_alg`]. `none` is served by no key.
/// 3. Any other value is kept as [`KeyAlg::Unknown`]: it is not an error
///    here, and it never matches a header `alg`, so the key is unusable for
///    any polyjose operation that checks the JWK `alg`.
fn check_alg_binding(material: &KeyMaterial, alg: &KeyAlg) -> Result<()> {
    let serves = match alg {
        KeyAlg::Signing(alg) => material.serves_signing_alg(alg),
        KeyAlg::KeyMgmt(alg) => material.serves_key_mgmt_alg(alg),
        KeyAlg::ContentEnc(enc) => material.serves_content_enc_alg(enc),
        KeyAlg::Unknown(name) if UNSUPPORTED_KEY_ALGS.contains(&name.as_str()) => {
            return Err(Error::UnsupportedAlgorithm);
        }
        KeyAlg::Unknown(_) => true,
    };
    if serves {
        Ok(())
    } else {
        Err(Error::KeyAlgorithmMismatch)
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
    /// - [`Error::UnsupportedAlgorithm`] if a well-formed key's `alg` is
    ///   `RSA1_5` or `RSA-OAEP` (ADRs 0021, 0022), and
    ///   [`Error::KeyAlgorithmMismatch`] if it is a known algorithm the
    ///   key's family cannot serve (RFC 7517 §4.4).
    ///
    /// The checks run in the [check order](crate::jwk#check-order) of the
    /// module docs.
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
        // RFC 7517 §4.4: last, once the key is known to be well-formed, so
        // a malformed key is always `InvalidKey`/`InvalidBase64` whatever
        // its `alg` (ADR 0018 Q3: "unsupported" presumes "well-formed").
        if let Some(alg) = &alg {
            check_alg_binding(&material, alg)?;
        }
        let typed = type_members(kty);
        // RFC 7517 §4: members not understood "MUST be ignored"; polyjose
        // keeps them. They are a subset of `object`'s members, whose names
        // are unique, so they are wrapped as they are: inserting them one by
        // one would re-check every name, O(n²) on untrusted input.
        let other = Object::from_unique_members(
            object
                .iter()
                .filter(|(name, _)| !COMMON_MEMBERS.contains(name) && !typed.contains(name))
                .map(|(name, value)| member(name, value.clone()))
                .collect(),
        );
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
        // Each name below is written at most once, and `other` holds only
        // names that are neither common members nor this key type's members
        // (see `from_object`), so the names are unique and need no
        // per-member duplicate check, which would be O(n²) in `other`.
        let mut o = Vec::with_capacity(COMMON_MEMBERS.len() + 4 + self.other.len());
        o.push(member("kty", self.key_type().as_str()));
        match &self.material {
            KeyMaterial::Oct(key) => {
                o.push(member("k", b64url_encode(&key.k)));
            }
            KeyMaterial::Rsa(key) => {
                o.push(member("n", b64url_encode(&key.n)));
                o.push(member("e", b64url_encode(&key.e)));
                if let Some(private) = &key.private {
                    for (name, value) in private.members() {
                        o.push(member(name, b64url_encode(value)));
                    }
                }
            }
            KeyMaterial::Ec(key) => {
                o.push(member("crv", key.crv.as_str()));
                o.push(member("x", b64url_encode(&key.x)));
                o.push(member("y", b64url_encode(&key.y)));
                if let Some(d) = &key.d {
                    o.push(member("d", b64url_encode(d)));
                }
            }
            KeyMaterial::Okp(key) => {
                o.push(member("crv", key.crv.as_str()));
                o.push(member("x", b64url_encode(&key.x)));
                if let Some(d) = &key.d {
                    o.push(member("d", b64url_encode(d)));
                }
            }
        }
        if let Some(v) = &self.key_use {
            o.push(member("use", v.as_str()));
        }
        if let Some(ops) = &self.key_ops {
            let ops: Vec<Value> = ops.iter().map(|op| Value::from(op.as_str())).collect();
            o.push(member("key_ops", ops));
        }
        if let Some(v) = &self.alg {
            o.push(member("alg", v.as_str()));
        }
        if let Some(v) = &self.kid {
            o.push(member("kid", v.as_str()));
        }
        if let Some(v) = &self.x5u {
            o.push(member("x5u", v.as_str()));
        }
        if let Some(certs) = &self.x5c {
            let certs: Vec<Value> = certs.iter().map(|c| Value::from(c.as_str())).collect();
            o.push(member("x5c", certs));
        }
        if let Some(v) = &self.x5t {
            o.push(member("x5t", v.as_str()));
        }
        if let Some(v) = &self.x5t_s256 {
            o.push(member("x5t#S256", v.as_str()));
        }
        o.extend(
            self.other
                .iter()
                .map(|(name, value)| member(name, value.clone())),
        );
        Object::from_unique_members(o)
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
            KeyMaterial::Rsa(key) => KeyMaterial::Rsa(key.to_public()),
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

    /// Whether the key is a public key: `RSA`, `EC` or `OKP` without its
    /// private members (`d`, and for `RSA` also `p`, `q`, `dp`, `dq`,
    /// `qi`). An `oct` key is secret by nature (RFC 7518 §6.4) and never
    /// public.
    pub fn is_public(&self) -> bool {
        match &self.material {
            KeyMaterial::Oct(_) => false,
            KeyMaterial::Rsa(key) => !key.is_private(),
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

#[cfg(test)]
impl Jwk {
    /// Test builds only: an `OKP` key that skips every import check, so a
    /// family can prove its own defence-in-depth checks on a key import
    /// would refuse (ADR 0043 §3: signing keeps its own check).
    pub(crate) fn okp_unchecked(crv: OkpCurve, x: &[u8], d: Option<&[u8]>) -> Jwk {
        Jwk {
            material: KeyMaterial::Okp(OkpKey {
                crv,
                x: x.to_vec(),
                d: d.map(|d| Zeroizing::new(d.to_vec())),
            }),
            key_use: None,
            key_ops: None,
            alg: None,
            kid: None,
            x5u: None,
            x5c: None,
            x5t: None,
            x5t_s256: None,
            other: Object::new(),
        }
    }
}

/// One JSON object member. The name is a [`Zeroizing<String>`] like every
/// name an [`Object`] owns; a `String` value moves into the [`Value`]
/// without a copy.
fn member(name: &str, value: impl Into<Value>) -> (Zeroizing<String>, Value) {
    (Zeroizing::new(name.to_owned()), value.into())
}

/// The member names a key type defines, besides `kty`.
fn type_members(kty: KeyType) -> &'static [&'static str] {
    match kty {
        KeyType::Oct => &["k"],
        KeyType::Rsa => &["n", "e", "d", "p", "q", "dp", "dq", "qi"],
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
/// included (the set skips them separately).
pub(crate) fn is_unsupported_key_kind(object: &Object) -> bool {
    matches!(key_kind(object), Err(Error::UnsupportedAlgorithm))
}

/// The private members of a two-prime RSA key (RFC 7518 §6.3.2.1–§6.3.2.6),
/// in RFC order. `oth` (§6.3.2.7, more than two primes) is not supported.
const RSA_PRIVATE_MEMBERS: [&str; 6] = ["d", "p", "q", "dp", "dq", "qi"];

/// Detail for an RSA private key that lacks some private members.
const RSA_PRIVATE_INCOMPLETE: &str = "RSA private key must have d, p, q, dp, dq and qi";

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

/// [`required_uint`] for a secret member: decoded straight into a
/// [`Zeroizing`] buffer (RFC 7518 §6.3.2: each private member is a
/// Base64urlUInt). Only the first octet is looked at for minimality, and
/// the detail names the rule, never the value (ADR 0007).
fn required_secret_uint(
    object: &Object,
    name: &str,
    not_minimal: &'static str,
) -> Result<Zeroizing<Vec<u8>>> {
    let octets = required_secret(
        object,
        name,
        RSA_PRIVATE_INCOMPLETE,
        "RSA private key members must be strings",
    )?;
    match octets.as_slice() {
        [] | [0, _, ..] => Err(Error::InvalidKey(not_minimal)),
        _ => Ok(octets),
    }
}

/// The bit length of the big-endian unsigned integer `octets`: 8 bits per
/// octet minus the leading zeros of the first (RFC 8017 §4.2 OS2IP). Zero
/// for no octets. Saturates rather than overflows, so an input too long to
/// count (on a 32-bit target) reads as at least `usize::MAX - 7` bits.
fn bit_len(octets: &[u8]) -> usize {
    let top = octets.first().copied().unwrap_or(0);
    octets
        .len()
        .saturating_mul(8)
        .saturating_sub(top.leading_zeros() as usize)
}

/// `kty` `RSA`: a public key (RFC 7518 §6.3.1) or a two-prime private key
/// (RFC 7518 §6.3.2, ADR 0067).
///
/// # Errors
///
/// [`Error::UnsupportedAlgorithm`] for `oth`, a key with more than two
/// primes (RFC 7518 §6.3.2.7; ADR 0067 §3);
/// [`Error::InvalidKey`], with a static detail and no input, for a modulus
/// outside [`RSA_MODULUS_BITS`] (RFC 7518 §3.3, ADR 0007, ADR 0026 §2
/// step 8), a private key without all of `d`, `p`, `q`, `dp`, `dq` and
/// `qi`, a private key inconsistent with `n` and `e` (ADR 0043), and every
/// other check below; [`Error::InvalidBase64`] for a member that is not
/// canonical base64url.
fn parse_rsa(object: &Object) -> Result<RsaPublicKey> {
    // ADR 0067 §3: multi-prime keys (RFC 7518 §6.3.2.7 `oth`) are not
    // supported. Checked before anything else is read, so the outcome
    // does not depend on the rest.
    if object.contains("oth") {
        return Err(Error::UnsupportedAlgorithm);
    }
    let n = required_uint(
        object,
        "n",
        "n is missing",
        "n must be a string",
        "n is not a minimal Base64urlUInt",
    )?;
    // RFC 7518 §3.3/§4.2 and ADR 0007: at least 2048 bits; ADR 0026 §2
    // step 8: at most 8192, the `rsa` crate's maximum. Checked on `n`
    // alone, before `e` is read: a length comparison, no arithmetic.
    // RFC 8017 §3.1: n is a product of odd primes, so odd.
    let Some(&last) = n.last() else {
        return Err(Error::InvalidKey("n is not a minimal Base64urlUInt"));
    };
    let bits = bit_len(&n);
    if bits < *RSA_MODULUS_BITS.start() {
        return Err(Error::InvalidKey("RSA modulus is shorter than 2048 bits"));
    }
    if bits > *RSA_MODULUS_BITS.end() {
        return Err(Error::InvalidKey("RSA modulus is longer than 8192 bits"));
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
    let private = parse_rsa_private(object)?;
    if let Some(private) = &private {
        // ADR 0043, ADR 0067 §2: last, the private members must be the
        // key of `n` and `e`, checked by the `rsa` crate's arithmetic.
        crate::keys::rsa::check_private(&n, &e, private)?;
    }
    Ok(RsaPublicKey { n, e, private })
}

/// The private members of an RSA JWK (RFC 7518 §6.3.2), or `None` for a
/// public key (no member present). RFC 7518 §6.3.2: "d" is REQUIRED for a
/// private key, and the others "SHOULD be included by producers"; "If the
/// producer includes any of the other private key parameters, then all of
/// the others MUST be present". polyjose requires all six (ADR 0067 §3), so
/// any one without the rest, `d` alone included, is [`Error::InvalidKey`].
fn parse_rsa_private(object: &Object) -> Result<Option<RsaPrivateParts>> {
    let present = RSA_PRIVATE_MEMBERS
        .iter()
        .filter(|name| object.contains(name))
        .count();
    if present == 0 {
        return Ok(None);
    }
    if present != RSA_PRIVATE_MEMBERS.len() {
        return Err(Error::InvalidKey(RSA_PRIVATE_INCOMPLETE));
    }
    Ok(Some(RsaPrivateParts {
        d: required_secret_uint(object, "d", "d is not a minimal Base64urlUInt")?,
        p: required_secret_uint(object, "p", "p is not a minimal Base64urlUInt")?,
        q: required_secret_uint(object, "q", "q is not a minimal Base64urlUInt")?,
        dp: required_secret_uint(object, "dp", "dp is not a minimal Base64urlUInt")?,
        dq: required_secret_uint(object, "dq", "dq is not a minimal Base64urlUInt")?,
        qi: required_secret_uint(object, "qi", "qi is not a minimal Base64urlUInt")?,
    }))
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
    // ADR 0041 §4, ADR 0007: the arithmetic checks, once every member is
    // well-formed. The point first, then the scalar.
    if !ec_point_is_valid(crv, &x, &y) {
        return Err(Error::InvalidKey(EC_POINT_INVALID));
    }
    if d.as_ref().is_some_and(|d| !ec_scalar_is_valid(crv, d)) {
        return Err(Error::InvalidKey(EC_SCALAR_INVALID));
    }
    // ADR 0043 §3: last, a private key must be the key of its own point.
    if d.as_ref()
        .is_some_and(|d| !ec_private_matches(crv, &x, &y, d))
    {
        return Err(Error::InvalidKey(EC_PRIVATE_MISMATCH));
    }
    Ok(EcKey { crv, x, y, d })
}

/// Detail for an `EC` public point that is not on its curve.
const EC_POINT_INVALID: &str = "EC point is not on the curve";
/// Detail for an `EC` private scalar outside [1, n − 1].
const EC_SCALAR_INVALID: &str = "EC private key d is out of range";
/// Detail for an `EC` private scalar `d` whose public point is not
/// (`x`, `y`).
const EC_PRIVATE_MISMATCH: &str = "EC private key d does not match x and y";
/// Detail for an `OKP` `Ed25519` `x` that is not a usable public key.
const ED25519_PUBLIC_INVALID: &str = "Ed25519 public key is invalid";
/// Detail for an `OKP` `Ed25519` `d` whose public key is not `x`.
const ED25519_PRIVATE_MISMATCH: &str = "Ed25519 private key d does not match x";

/// Whether (`x`, `y`) is a point of `crv` other than the identity
/// (ADR 0041 §4, ADR 0007; SEC 1 v2 §3.2.2.1 public key validation).
///
/// RFC 7518 §6.2.1.2–§6.2.1.3 give the coordinates as full-length
/// big-endian field elements, which are exactly the octets of an
/// uncompressed SEC 1 point (SEC 1 v2 §2.3.3) without its `0x04` tag. The
/// curve crate decodes that point and checks, in its own constant-time
/// arithmetic, that both coordinates are reduced field elements (0 ≤ x, y
/// < p, SEC 1 §2.3.4) and satisfy the curve equation. The identity has no
/// affine coordinates, so it cannot be spelled as (`x`, `y`): `(0, 0)` is
/// off every one of these curves (b ≠ 0), and `PublicKey` rejects the
/// identity in any case. The lengths were checked by the caller; a wrong
/// length is treated as invalid here too.
fn ec_point_is_valid(crv: EcCurve, x: &[u8], y: &[u8]) -> bool {
    match crv {
        EcCurve::P256 => point_on_curve::<p256::NistP256>(x, y),
        EcCurve::P384 => point_on_curve::<p384::NistP384>(x, y),
        EcCurve::P521 => point_on_curve::<p521::NistP521>(x, y),
        EcCurve::Secp256k1 => point_on_curve::<k256::Secp256k1>(x, y),
    }
}

/// Whether `d` is a private scalar of `crv` in [1, n − 1] (ADR 0041 §4;
/// SEC 1 v2 §3.2.1: "an integer d in the interval [1, n − 1]";
/// RFC 7518 §6.2.2.1). `d` is borrowed from its wiped-on-drop buffer, and
/// the `SecretKey` the curve crate builds from it is wiped when dropped.
fn ec_scalar_is_valid(crv: EcCurve, d: &[u8]) -> bool {
    match crv {
        EcCurve::P256 => scalar_in_range::<p256::NistP256>(d),
        EcCurve::P384 => scalar_in_range::<p384::NistP384>(d),
        EcCurve::P521 => scalar_in_range::<p521::NistP521>(d),
        EcCurve::Secp256k1 => scalar_in_range::<k256::Secp256k1>(d),
    }
}

/// Whether the valid scalar `d` is the private key of the valid point
/// (`x`, `y`) of `crv`: Q = d·G (SEC 1 v2 §3.2.1; RFC 7518 §6.2.2.1: `d`
/// is "the Elliptic Curve private key value" of the key's point). A
/// mismatched pair would sign for a key other than the published one
/// (ADR 0043 §3, the class behind RUSTSEC-2022-0093). The caller has
/// checked the point and the range of `d`; anything else is a mismatch.
fn ec_private_matches(crv: EcCurve, x: &[u8], y: &[u8], d: &[u8]) -> bool {
    match crv {
        EcCurve::P256 => private_matches_point::<p256::NistP256>(x, y, d),
        EcCurve::P384 => private_matches_point::<p384::NistP384>(x, y, d),
        EcCurve::P521 => private_matches_point::<p521::NistP521>(x, y, d),
        EcCurve::Secp256k1 => private_matches_point::<k256::Secp256k1>(x, y, d),
    }
}

/// See [`ec_private_matches`]: the curve crate derives d·G
/// (`SecretKey::public_key`, in its constant-time arithmetic) and the two
/// points are compared with `subtle`'s constant-time equality, since the
/// derived point is computed from the secret. `d` is borrowed from its
/// wiped-on-drop buffer, and the `SecretKey` built from it is wiped when
/// dropped.
fn private_matches_point<C>(x: &[u8], y: &[u8], d: &[u8]) -> bool
where
    C: CurveArithmetic,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: ModulusSize,
{
    let (Ok(x), Ok(y), Ok(d)) = (
        <&FieldBytes<C>>::try_from(x),
        <&FieldBytes<C>>::try_from(y),
        <&FieldBytes<C>>::try_from(d),
    ) else {
        return false;
    };
    let Ok(secret) = SecretKey::<C>::from_bytes(d) else {
        return false;
    };
    let point = Sec1Point::<C>::from_affine_coordinates(x, y, false);
    let Some(public) = PublicKey::<C>::from_sec1_point(&point).into_option() else {
        return false;
    };
    bool::from(
        secret
            .public_key()
            .to_projective()
            .ct_eq(&public.to_projective()),
    )
}

/// See [`ec_point_is_valid`]: `PublicKey::from_sec1_point` on the
/// uncompressed SEC 1 point (`0x04` ‖ `x` ‖ `y`).
fn point_on_curve<C>(x: &[u8], y: &[u8]) -> bool
where
    C: CurveArithmetic,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: ModulusSize,
{
    let (Ok(x), Ok(y)) = (<&FieldBytes<C>>::try_from(x), <&FieldBytes<C>>::try_from(y)) else {
        return false;
    };
    let point = Sec1Point::<C>::from_affine_coordinates(x, y, false);
    PublicKey::<C>::from_sec1_point(&point)
        .into_option()
        .is_some()
}

/// See [`ec_scalar_is_valid`]: `SecretKey::from_bytes` rejects 0 and every
/// value ≥ n.
fn scalar_in_range<C: Curve>(d: &[u8]) -> bool {
    <&FieldBytes<C>>::try_from(d).is_ok_and(|d| SecretKey::<C>::from_bytes(d).is_ok())
}

/// Whether `x` is a usable Ed25519 public key (ADR 0041 §4, ADR 0026 §6):
///
/// - it decodes to a curve point (RFC 8032 §5.1.3 steps 2–4), which
///   `VerifyingKey::from_bytes` checks;
/// - the encoding is canonical (RFC 8032 §5.1.3 step 1: "If the resulting
///   y >= p, decoding fails"). `from_bytes` follows the more lenient
///   ZIP-215 rules and accepts y ≥ p, so the decoded point is re-encoded
///   by ed25519-dalek (`VerifyingKey::from(EdwardsPoint)`) and must give
///   back the same 32 octets;
/// - the point is not of small order (`VerifyingKey::is_weak`), since a
///   small-order key "can be used to generate a signature that's valid for
///   almost every message";
/// - the point has no torsion component, that is it lies in the subgroup
///   of prime order L (`EdwardsPoint::is_torsion_free`, ADR 0043 §1). A
///   mixed-order key passes RFC 8032 §5.1.7 and `verify_strict`, but
///   implementations disagree on it and honest keys (RFC 8032 §5.1.5:
///   A = \[s\]B) never have one.
pub(crate) fn ed25519_public_is_valid(x: &[u8]) -> bool {
    let Ok(bytes) = <&[u8; ed25519_dalek::PUBLIC_KEY_LENGTH]>::try_from(x) else {
        return false;
    };
    let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(bytes) else {
        return false;
    };
    let point = key.to_edwards();
    let canonical = ed25519_dalek::VerifyingKey::from(point).to_bytes() == *bytes;
    canonical && !key.is_weak() && point.is_torsion_free()
}

/// Whether the 32-octet seed `d` is the private key of the Ed25519 public
/// key `x` (RFC 8037 §2: `d` is the private key of `x`; RFC 8032 §5.1.5
/// derives the public key from the seed). A mismatched pair would sign for
/// a key other than the published one, the root of RUSTSEC-2022-0093
/// (ADR 0043 §3). ed25519-dalek derives the key (`SigningKey::from_bytes`,
/// `SigningKey::verifying_key`); the `SigningKey` is wiped on drop (its
/// `zeroize` feature), `d` is borrowed from its wiped-on-drop buffer, and
/// the comparison uses `subtle`'s constant-time equality, since the
/// derived key is computed from the secret.
fn ed25519_private_matches(x: &[u8], d: &[u8]) -> bool {
    let Ok(seed) = <&ed25519_dalek::SecretKey>::try_from(d) else {
        return false;
    };
    let signing_key = ed25519_dalek::SigningKey::from_bytes(seed);
    bool::from(signing_key.verifying_key().as_bytes()[..].ct_eq(x))
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
    // ADR 0041 §4: the arithmetic check of `x`, once the members are
    // well-formed. An Ed25519 `d` is any 32-octet seed (RFC 8032 §5.1.5),
    // so it has no range to check. An X25519 `x` keeps the length check
    // only: every 32-octet string is a valid u-coordinate (RFC 7748 §5
    // masks the top bit, and "Implementations MUST accept non-canonical
    // values and process them as if they had been reduced modulo the field
    // prime"), so it has no decoding failure. Torsion components are normal
    // for X25519 and clamping neutralises them (ADR 0043 §2). A small-order
    // input shows up as an all-zero shared secret, which ECDH-ES checks
    // where it computes one (RFC 7748 §6.1, feature 0003).
    if crv == OkpCurve::Ed25519 && !ed25519_public_is_valid(&x) {
        return Err(Error::InvalidKey(ED25519_PUBLIC_INVALID));
    }
    // ADR 0043 §3: last, a private key must be the key of its own `x`:
    // Ed25519 per RFC 8032 §5.1.5, X25519 per RFC 7748 §6.1 (x = X25519(d, 9)).
    if crv == OkpCurve::Ed25519 && d.as_ref().is_some_and(|d| !ed25519_private_matches(&x, d)) {
        return Err(Error::InvalidKey(ED25519_PRIVATE_MISMATCH));
    }
    if crv == OkpCurve::X25519 && d.as_ref().is_some_and(|d| !x25519_private_matches(&x, d)) {
        return Err(Error::InvalidKey(X25519_PRIVATE_MISMATCH));
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
    // The values seen so far, borrowed from `items` (nothing is copied). A
    // set keeps the duplicate check O(n log n) on untrusted input, where a
    // scan of `ops` per value would be O(n²).
    let mut seen = BTreeSet::new();
    for item in items {
        let name = item.as_str().ok_or(Error::InvalidKey(NOT_STRINGS))?;
        // RFC 7517 §4.3: "Duplicate key operation values MUST NOT be
        // present in the array." Values compare as exact strings.
        if !seen.insert(KeyOpName(name)) {
            return Err(Error::InvalidKey("key_ops must not contain duplicates"));
        }
        ops.push(KeyOp::from(name));
    }
    Ok(Some(ops))
}

/// A `key_ops` value in the duplicate check: ordered as an exact,
/// case-sensitive string (RFC 7517 §4.3). A type of its own only so that
/// test builds can count its comparisons.
#[derive(PartialEq, Eq)]
struct KeyOpName<'a>(&'a str);

impl Ord for KeyOpName<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        #[cfg(test)]
        key_op_comparisons::tick();
        self.0.cmp(other.0)
    }
}

impl PartialOrd for KeyOpName<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Test-only, per-thread count of the value comparisons the `key_ops`
/// duplicate check makes ([`KeyOpName`]'s ordering), so a regression test can bound its work on
/// untrusted input deterministically, without wall-clock timing. It lives in
/// the test-only `crate::test_counters` and is not compiled into non-test builds.
#[cfg(test)]
use crate::test_counters::key_op_comparisons;

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

    /// ADR 0067 §3: `oth` (RFC 7518 §6.3.2.7) is refused before anything
    /// else is read, whatever the rest of the key says; a private key that
    /// lacks some of `d`, `p`, `q`, `dp`, `dq`, `qi` is malformed
    /// (RFC 7518 §6.3.2: "all of the others MUST be present").
    /// The RSA private JWK of RFC 7515 Appendix A.2.1, as an object.
    fn rsa_private_object() -> Object {
        object(include_str!(
            "../tests/data/keys/rfc/rfc7515-a2-rsa-private.jwk.json"
        ))
    }

    /// The RFC 7515 A.2 private JWK with member `name` set to `value`
    /// (JSON text).
    fn rsa_private_with(name: &str, value: &str) -> String {
        let mut o = rsa_private_object();
        o.insert(name, json::parse(value.as_bytes()).unwrap());
        o.to_json()
    }

    #[test]
    fn an_rsa_private_jwk_imports_with_its_members_in_rfc_order() {
        // RFC 7518 §6.3.2, ADR 0067 §2: all six private members, kept in
        // zeroizing buffers and written back after `n` and `e` in RFC order.
        let jwk = Jwk::from_object(&rsa_private_object()).unwrap();
        let KeyMaterial::Rsa(key) = jwk.material() else {
            panic!("RSA")
        };
        assert!(key.is_private() && !jwk.is_public());
        assert_eq!(key.modulus_bits(), 2048);
        let members = |jwk: &Jwk| -> Vec<String> {
            let mut names: Vec<String> =
                jwk.to_object().iter().map(|(n, _)| n.to_owned()).collect();
            names.sort();
            names
        };
        assert_eq!(
            members(&jwk),
            ["d", "dp", "dq", "e", "kty", "n", "p", "q", "qi"]
        );
        let json = jwk.to_json();
        let order: Vec<usize> = [
            "\"n\"", "\"e\"", "\"d\"", "\"p\"", "\"q\"", "\"dp\"", "\"dq\"", "\"qi\"",
        ]
        .iter()
        .map(|name| json.find(name).unwrap())
        .collect();
        assert!(order.windows(2).all(|w| w[0] < w[1]), "{order:?}");
        // The round trip is exact (RFC 7515 §2: one encoding per value).
        assert_eq!(*Jwk::from_json(json.as_bytes()).unwrap().to_json(), *json);
        // The public part has `n` and `e` only, and the same thumbprint
        // members (RFC 7638 §3.2).
        let public = jwk.to_public().unwrap();
        assert!(public.is_public());
        assert_eq!(members(&public), ["e", "kty", "n"]);
        assert_eq!(
            public.thumbprint_members().to_json(),
            jwk.thumbprint_members().to_json()
        );
    }

    #[test]
    fn rsa_private_members_never_show_in_debug_or_errors() {
        // ADR 0007, ADR 0067 §2: Debug prints each private member as
        // "<redacted>"; no error quotes a member.
        let jwk = Jwk::from_object(&rsa_private_object()).unwrap();
        let debug = format!("{jwk:?} {jwk:#?}");
        let object = rsa_private_object();
        for name in RSA_PRIVATE_MEMBERS {
            let value = object.get(name).and_then(Value::as_str).unwrap();
            assert!(!debug.contains(&value[..16]), "{name}");
            assert!(
                debug.contains(&format!("{name}: \"<redacted>\"")),
                "{name}: {debug}"
            );
        }
        for (name, value) in [("d", r#""AAAB""#), ("qi", r#""AQAB""#), ("p", r#""AQAB""#)] {
            let error = Jwk::from_json(rsa_private_with(name, value).as_bytes()).unwrap_err();
            let text = format!("{error:?} {error}");
            for member in RSA_PRIVATE_MEMBERS {
                let value = object.get(member).and_then(Value::as_str).unwrap();
                assert!(!text.contains(&value[..16]), "{text}");
            }
        }
        // The private members are wiped on drop (ZeroizeOnDrop markers).
        fn wipes<T: zeroize::ZeroizeOnDrop>() {}
        wipes::<RsaPublicKey>();
        wipes::<RsaPrivateParts>();
    }

    #[test]
    fn rsa_private_members_must_be_minimal_and_the_key_of_n_and_e() {
        // RFC 7518 §2: Base64urlUInt "MUST utilize the minimum number of
        // octets"; ADR 0043, ADR 0067 §2: the private key must be the key
        // of `n` and `e` (n = p·q, d·e ≡ 1 mod p − 1 and q − 1, and the
        // CRT members are those of d, p and q).
        let a2 = rsa_private_object();
        let member = |name: &str| a2.get(name).and_then(Value::as_str).unwrap().to_owned();
        let padded = |name: &str| {
            let mut octets = vec![0];
            octets.extend(b64url_decode(&member(name)).unwrap());
            format!("\"{}\"", b64url_encode(&octets))
        };
        for name in RSA_PRIVATE_MEMBERS {
            assert!(
                matches!(
                    Jwk::from_json(rsa_private_with(name, &padded(name)).as_bytes()),
                    Err(Error::InvalidKey(detail)) if detail.contains("not a minimal Base64urlUInt")
                ),
                "{name}"
            );
            assert_eq!(
                Jwk::from_json(rsa_private_with(name, "7").as_bytes()).err(),
                Some(Error::InvalidKey("RSA private key members must be strings")),
                "{name}"
            );
            assert_eq!(
                Jwk::from_json(rsa_private_with(name, r#""*""#).as_bytes()).err(),
                Some(Error::InvalidBase64),
                "{name}"
            );
        }
        let mismatch = Error::InvalidKey("RSA private key does not match n and e");
        let crt = Error::InvalidKey("RSA private key dp, dq or qi does not match d, p and q");
        // p and q swapped: n = q·p still, but qi is then q⁻¹ mod p of the
        // other order, so the CRT values disagree.
        let swapped = {
            let mut o = rsa_private_object();
            o.insert("p", member("q"));
            o.insert("q", member("p"));
            o.to_json()
        };
        // Another prime is no factor of n; `d` of another key fails d·e ≡ 1.
        let rfc7520 = object(include_str!(
            "../tests/data/keys/rfc/rfc7520-3.4-rsa-private.jwk.json"
        ));
        let other_member = |name: &str| {
            rfc7520
                .get(name)
                .and_then(Value::as_str)
                .unwrap()
                .to_owned()
        };
        for (what, json, expected) in [
            ("p and q swapped", swapped, &crt),
            (
                "another key's p",
                rsa_private_with("p", &format!("\"{}\"", other_member("p"))),
                &mismatch,
            ),
            (
                "another key's d",
                rsa_private_with("d", &format!("\"{}\"", other_member("d"))),
                &mismatch,
            ),
            (
                "another key's dp",
                rsa_private_with("dp", &format!("\"{}\"", other_member("dp"))),
                &crt,
            ),
            (
                "another key's qi",
                rsa_private_with("qi", &format!("\"{}\"", other_member("qi"))),
                &crt,
            ),
            ("d = 1", rsa_private_with("d", r#""AQ""#), &mismatch),
        ] {
            assert_eq!(
                Jwk::from_json(json.as_bytes()).err().as_ref(),
                Some(expected),
                "{what}"
            );
        }
        // The modulus range holds for private keys too (RFC 7518 §3.3).
        let short = rsa_private_with("n", &format!("\"{}\"", b64url_encode(&[0xff; 128])));
        assert_eq!(
            Jwk::from_json(short.as_bytes()).err(),
            Some(Error::InvalidKey("RSA modulus is shorter than 2048 bits"))
        );
    }

    #[test]
    fn rsa_oth_is_unsupported_and_partial_private_keys_are_invalid() {
        for json in [
            r#"{"kty":"RSA","oth":null,"alg":"RSA1_5"}"#.to_owned(),
            r#"{"kty":"RSA","n":"x","oth":[]}"#.to_owned(),
            format!(r#"{{"kty":"RSA","n":"{RSA_N}","e":"AQAB","d":"AQAB","oth":[]}}"#),
        ] {
            assert_eq!(
                Jwk::from_json(json.as_bytes()).err(),
                Some(Error::UnsupportedAlgorithm),
                "{json}"
            );
        }
        for json in [
            format!(r#"{{"kty":"RSA","n":"{RSA_N}","e":"AQAB","d":"AQAB"}}"#),
            format!(r#"{{"kty":"RSA","n":"{RSA_N}","e":"AQAB","qi":"AQAB","alg":"RS256"}}"#),
            format!(
                r#"{{"kty":"RSA","n":"{RSA_N}","e":"AQAB","d":"AQ","p":"AQ","q":"AQ","dp":"AQ","dq":"AQ"}}"#
            ),
        ] {
            assert_eq!(
                Jwk::from_json(json.as_bytes()).err(),
                Some(Error::InvalidKey(RSA_PRIVATE_INCOMPLETE)),
                "{json}"
            );
        }
    }

    #[test]
    fn the_key_op_counter_sees_the_duplicate_check() {
        let two = object(r#"{"kty":"oct","k":"AA","key_ops":["sign","verify"]}"#);
        let (ops, count) = key_op_comparisons::count(|| parse_key_ops(&two));
        assert_eq!(ops, Ok(Some(vec![KeyOp::Sign, KeyOp::Verify])));
        assert!(count >= 1, "the second value is checked against the first");
        let none = object(r#"{"kty":"oct","k":"AA"}"#);
        assert_eq!(
            key_op_comparisons::count(|| parse_key_ops(&none)),
            (Ok(None), 0)
        );
    }

    /// `c · n · ⌈log2 n⌉` with `c = 4`: the most work an O(n log n) import
    /// path may do on `n` members or values. Quadratic code needs about
    /// `n² / 2`, which for `n = 10 000` is about 90 times this.
    fn n_log_n_bound(n: usize) -> u64 {
        let n = n as u64;
        4 * n * u64::from(u64::BITS - n.leading_zeros())
    }

    /// An `oct` JWK with `unknown` extra members `u0`, `u1`, ... (RFC 7517
    /// §4: unknown members "MUST be ignored", so they are kept).
    fn oct_with_unknown_members(unknown: usize) -> String {
        let mut json = format!(r#"{{"kty":"oct","k":"{OCT_K}""#);
        for i in 0..unknown {
            json.push_str(&format!(r#","u{i}":{i}"#));
        }
        json.push('}');
        json
    }

    /// An `oct` JWK whose `key_ops` holds `ops` (RFC 7517 §4.3).
    fn oct_with_key_ops(ops: impl Iterator<Item = String>) -> String {
        let ops: Vec<String> = ops.map(|op| format!(r#""{op}""#)).collect();
        format!(
            r#"{{"kty":"oct","k":"{OCT_K}","key_ops":[{}]}}"#,
            ops.join(",")
        )
    }

    /// DoS regression (0001 security review, F01): importing a JWK with the
    /// most members the default `json::Limits` allow is not quadratic.
    #[test]
    fn import_with_10_000_members_is_n_log_n() {
        const N: usize = 10_000;
        let json = oct_with_unknown_members(N - 2);
        let (jwk, count) = Object::count_name_comparisons(|| Jwk::from_json(json.as_bytes()));
        let jwk = jwk.expect("a JWK with unknown members imports");
        assert_eq!(jwk.other_params().len(), N - 2);
        assert!(count <= n_log_n_bound(N), "{count} comparisons");
    }

    /// DoS regression (F01): writing such a key back out is not quadratic,
    /// and writes every member, in order.
    #[test]
    fn to_object_with_10_000_members_is_n_log_n() {
        const N: usize = 10_000;
        let json = oct_with_unknown_members(N - 2);
        let jwk = parse(&json);
        let (written, count) = Object::count_name_comparisons(|| jwk.to_object());
        assert!(count <= n_log_n_bound(N), "{count} comparisons");
        assert_eq!(written.len(), N);
        assert_eq!(written.to_json(), json);
    }

    /// RFC 7517 §4.3: values are checked in order, so the first problem
    /// decides the error; they compare as exact, case-sensitive strings.
    #[test]
    fn key_ops_errors_follow_value_order() {
        const DUPLICATES: Error = Error::InvalidKey("key_ops must not contain duplicates");
        const NOT_STRINGS: Error = Error::InvalidKey("key_ops must be an array of strings");
        let ops = |list: &str| parse_key_ops(&object(&format!(r#"{{"key_ops":{list}}}"#)));
        assert_eq!(ops(r#"["sign","sign",5]"#), Err(DUPLICATES));
        assert_eq!(ops(r#"["sign",5,"sign"]"#), Err(NOT_STRINGS));
        assert_eq!(ops(r#"["x-op","verify","x-op"]"#), Err(DUPLICATES));
        assert_eq!(
            ops(r#"["sign","Sign","x-op","X-op"]"#),
            Ok(Some(vec![
                KeyOp::Sign,
                KeyOp::Unknown("Sign".to_owned()),
                KeyOp::Unknown("x-op".to_owned()),
                KeyOp::Unknown("X-op".to_owned()),
            ]))
        );
        assert_eq!(ops("[]"), Ok(Some(Vec::new())));
    }

    /// DoS regression (F01): the RFC 7517 §4.3 duplicate check on a
    /// `key_ops` with the most values the default `json::Limits` allow.
    #[test]
    fn key_ops_duplicate_check_is_n_log_n() {
        const N: usize = 10_000;
        let distinct = oct_with_key_ops((0..N).map(|i| format!("op{i}")));
        let (jwk, count) = key_op_comparisons::count(|| Jwk::from_json(distinct.as_bytes()));
        let jwk = jwk.expect("distinct key_ops values import");
        assert_eq!(jwk.key_ops().map(<[KeyOp]>::len), Some(N));
        assert!(count <= n_log_n_bound(N), "{count} comparisons");

        // The duplicate is found however late it comes.
        let late_duplicate = oct_with_key_ops(
            (0..N - 1)
                .map(|i| format!("op{i}"))
                .chain(["op0".to_owned()]),
        );
        let (result, count) =
            key_op_comparisons::count(|| Jwk::from_json(late_duplicate.as_bytes()));
        assert_eq!(
            result.err(),
            Some(Error::InvalidKey("key_ops must not contain duplicates"))
        );
        assert!(count <= n_log_n_bound(N), "{count} comparisons");
    }

    /// One key of each kind, by label, for the family tables. EC and OKP
    /// coordinates only need the right length (the tables read `crv`).
    fn family_keys() -> Vec<(&'static str, KeyMaterial)> {
        let ec = |crv: EcCurve| {
            let len = crv.coordinate_len();
            KeyMaterial::Ec(EcKey {
                crv,
                x: vec![7; len],
                y: vec![7; len],
                d: None,
            })
        };
        let okp = |crv: OkpCurve| {
            KeyMaterial::Okp(OkpKey {
                crv,
                x: vec![7; 32],
                d: None,
            })
        };
        vec![
            ("oct", parse(&oct_json()).material().clone()),
            ("RSA", parse(&rsa_json()).material().clone()),
            ("P-256", ec(EcCurve::P256)),
            ("P-384", ec(EcCurve::P384)),
            ("P-521", ec(EcCurve::P521)),
            ("secp256k1", ec(EcCurve::Secp256k1)),
            ("Ed25519", okp(OkpCurve::Ed25519)),
            ("X25519", okp(OkpCurve::X25519)),
        ]
    }

    /// RFC 7518 §4.3–§4.8, RFC 8037 §3.2, ADR 0006: the JWE `alg` → key
    /// family table, every row against every key kind, written out here
    /// independently of `serves_key_mgmt_alg`.
    #[test]
    fn key_mgmt_family_table() {
        const ECDH: &[&str] = &["P-256", "P-384", "P-521", "X25519"];
        let table: &[(KeyMgmtAlg, &[&str])] = &[
            (KeyMgmtAlg::RsaOaep256, &["RSA"]),
            (KeyMgmtAlg::A128KW, &["oct"]),
            (KeyMgmtAlg::A192KW, &["oct"]),
            (KeyMgmtAlg::A256KW, &["oct"]),
            (KeyMgmtAlg::Dir, &["oct"]),
            (KeyMgmtAlg::EcdhEs, ECDH),
            (KeyMgmtAlg::EcdhEsA128KW, ECDH),
            (KeyMgmtAlg::EcdhEsA192KW, ECDH),
            (KeyMgmtAlg::EcdhEsA256KW, ECDH),
            (KeyMgmtAlg::A128GCMKW, &["oct"]),
            (KeyMgmtAlg::A192GCMKW, &["oct"]),
            (KeyMgmtAlg::A256GCMKW, &["oct"]),
            (KeyMgmtAlg::Pbes2Hs256A128KW, &["oct"]),
            (KeyMgmtAlg::Pbes2Hs384A192KW, &["oct"]),
            (KeyMgmtAlg::Pbes2Hs512A256KW, &["oct"]),
            (KeyMgmtAlg::from("RSA-OAEP"), &[]),
            (KeyMgmtAlg::from("RSA1_5"), &[]),
            (KeyMgmtAlg::from("x-future"), &[]),
        ];
        for alg in KeyMgmtAlg::KNOWN {
            assert!(table.iter().any(|(a, _)| a == alg), "{alg} not in table");
        }
        for (alg, kinds) in table {
            for (kind, key) in family_keys() {
                assert_eq!(
                    key.serves_key_mgmt_alg(alg),
                    kinds.contains(&kind),
                    "{alg} on {kind}"
                );
            }
        }
    }

    /// RFC 7518 §5.1 with §4.5: every `enc` binds to `oct` only.
    #[test]
    fn content_enc_family_table() {
        for enc in ContentEncAlg::KNOWN {
            for (kind, key) in family_keys() {
                assert_eq!(
                    key.serves_content_enc_alg(enc),
                    kind == "oct",
                    "{enc} on {kind}"
                );
            }
        }
        for (_, key) in family_keys() {
            assert!(!key.serves_content_enc_alg(&ContentEncAlg::from("A128CBC")));
        }
    }

    /// The import check: the two unsupported names first (any key), then
    /// the family tables; other unknown values pass.
    #[test]
    fn alg_binding_check() {
        for (kind, key) in family_keys() {
            for name in UNSUPPORTED_KEY_ALGS {
                assert_eq!(
                    check_alg_binding(&key, &KeyAlg::from(*name)),
                    Err(Error::UnsupportedAlgorithm),
                    "{name} on {kind}"
                );
            }
            for unknown in ["x-future", "rsa1_5", "Ed448", ""] {
                assert_eq!(check_alg_binding(&key, &KeyAlg::from(unknown)), Ok(()));
            }
            let none = KeyAlg::Signing(SigningAlg::None);
            assert_eq!(
                check_alg_binding(&key, &none),
                Err(Error::KeyAlgorithmMismatch)
            );
        }
        let oct = parse(&oct_json());
        let oct = oct.material();
        assert_eq!(check_alg_binding(oct, &KeyAlg::from("HS256")), Ok(()));
        assert_eq!(check_alg_binding(oct, &KeyAlg::from("A256GCM")), Ok(()));
        assert_eq!(check_alg_binding(oct, &KeyAlg::from("dir")), Ok(()));
        assert_eq!(
            check_alg_binding(oct, &KeyAlg::from("ES256")),
            Err(Error::KeyAlgorithmMismatch)
        );
        assert_eq!(UNSUPPORTED_KEY_ALGS, ["RSA1_5", "RSA-OAEP"]);
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
            private: None,
        };
        assert_eq!(n.modulus_bits(), 17);
    }

    #[test]
    fn bit_len_counts_from_the_top_set_bit() {
        assert_eq!(bit_len(&[]), 0);
        assert_eq!(bit_len(&[0]), 0);
        assert_eq!(bit_len(&[1]), 1);
        assert_eq!(bit_len(&[0x80, 0]), 16);
        assert_eq!(bit_len(&[0x01, 0, 0]), 17);
    }

    #[test]
    fn the_rsa_modulus_details_match_rsa_modulus_bits() {
        // The details are static strings (ADR 0007), so they spell the
        // bounds out; this pins them to the constant.
        assert_eq!(RSA_MODULUS_BITS, 2048..=8192);
        let key = |n: &[u8]| {
            let n = b64url_encode(n);
            Jwk::from_json(format!(r#"{{"kty":"RSA","n":"{n}","e":"AQAB"}}"#).as_bytes())
        };
        let mut n = vec![0xff; 1024];
        assert!(key(&n).is_ok(), "8192 bits");
        n.insert(0, 0x01);
        assert_eq!(
            key(&n).err(),
            Some(Error::InvalidKey("RSA modulus is longer than 8192 bits"))
        );
        assert_eq!(
            key(&[0xff; 255]).err(),
            Some(Error::InvalidKey("RSA modulus is shorter than 2048 bits"))
        );
    }
}
