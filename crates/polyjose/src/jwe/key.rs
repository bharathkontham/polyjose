//! The JWE key model: a [`Jwk`] bound to one key management algorithm and
//! one direction (RFC 7517 §4, RFC 7518 §6, RFC 8037 §2, RFC 8725 §3.1).
//!
//! [`RecipientKey::from_jwk`] enforces, before any cryptography runs, the
//! family binding (`KeyMaterial::serves_key_mgmt_alg`), the JWK `alg`,
//! `use` and `key_ops` (RFC 7517 §4.2–§4.4) and the key size the `alg`
//! needs. Filled in by T05.
//!
//! RSA keys are held as their validated `n` and `e` only (ADR 0021: public
//! keys, encryption only); this file never names the `rsa` crate.

use core::fmt;

use zeroize::Zeroizing;

use crate::jwa::{ContentEncAlg, KeyMgmtAlg};
use crate::jwk::Jwk;
use crate::{Error, Result};

/// Which way a key is used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Direction {
    /// Encrypting to a recipient (RFC 7516 §5.1): public or symmetric keys.
    Encrypt,
    /// Decrypting as a recipient (RFC 7516 §5.2): private or symmetric keys.
    Decrypt,
}

/// A key ready for one key management algorithm and direction.
///
/// Secret variants wipe their bytes on drop (`Zeroizing`, and the
/// `ZeroizeOnDrop` secret types of `p256`/`p384`/`p521` and
/// `x25519-dalek`). `Debug` prints the variant name only.
pub(crate) enum RecipientKey {
    /// `dir`, A*KW, A*GCMKW: the symmetric key `k` (RFC 7518 §6.4).
    Symmetric(Zeroizing<Vec<u8>>),
    /// PBES2: the password, carried as an `oct` key's `k` (RFC 7518 §4.8).
    Password(Zeroizing<Vec<u8>>),
    /// RSA-OAEP-256 encryption: the validated modulus and public exponent,
    /// big-endian (RFC 7518 §6.3.1, §4.3; ADR 0021).
    RsaPublic { n: Vec<u8>, e: Vec<u8> },
    /// ECDH-ES on P-256 (RFC 7518 §4.6): the recipient's public key.
    P256Public(p256::PublicKey),
    /// ECDH-ES on P-256: our private key.
    P256Secret(p256::SecretKey),
    /// ECDH-ES on P-384: the recipient's public key.
    P384Public(p384::PublicKey),
    /// ECDH-ES on P-384: our private key.
    P384Secret(p384::SecretKey),
    /// ECDH-ES on P-521: the recipient's public key.
    P521Public(p521::PublicKey),
    /// ECDH-ES on P-521: our private key.
    P521Secret(p521::SecretKey),
    /// ECDH-ES on X25519 (RFC 8037 §3.2): the recipient's public key.
    X25519Public(x25519_dalek::PublicKey),
    /// ECDH-ES on X25519: our private key.
    X25519Secret(x25519_dalek::StaticSecret),
}

impl RecipientKey {
    /// Binds `jwk` to `alg` (with `enc`, which fixes the `dir` key length,
    /// RFC 7518 §4.5) for `direction`.
    ///
    /// # Errors
    ///
    /// Following the plan.md error contract:
    /// [`Error::KeyAlgorithmMismatch`] when the key's family cannot serve
    /// `alg` or its JWK `alg`/`use`/`key_ops` forbid it;
    /// [`Error::InvalidKey`] on encrypt for a key of the wrong size;
    /// [`Error::UnsupportedAlgorithm`] for an RSA private key (ADR 0021) or
    /// an unimplemented `alg`.
    pub(crate) fn from_jwk(
        _jwk: &Jwk,
        _alg: &KeyMgmtAlg,
        _enc: &ContentEncAlg,
        _direction: Direction,
    ) -> Result<Self> {
        Err(Error::UnsupportedAlgorithm)
    }
}

impl fmt::Debug for RecipientKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            RecipientKey::Symmetric(_) => "Symmetric",
            RecipientKey::Password(_) => "Password",
            RecipientKey::RsaPublic { .. } => "RsaPublic",
            RecipientKey::P256Public(_) => "P256Public",
            RecipientKey::P256Secret(_) => "P256Secret",
            RecipientKey::P384Public(_) => "P384Public",
            RecipientKey::P384Secret(_) => "P384Secret",
            RecipientKey::P521Public(_) => "P521Public",
            RecipientKey::P521Secret(_) => "P521Secret",
            RecipientKey::X25519Public(_) => "X25519Public",
            RecipientKey::X25519Secret(_) => "X25519Secret",
        };
        write!(f, "RecipientKey::{name}(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_names_the_variant_only() {
        let key = RecipientKey::Symmetric(Zeroizing::new(vec![0xC5; 16]));
        assert_eq!(format!("{key:?}"), "RecipientKey::Symmetric(<redacted>)");
        let key = RecipientKey::X25519Secret(x25519_dalek::StaticSecret::from([0xC5; 32]));
        let debug = format!("{key:?}");
        assert_eq!(debug, "RecipientKey::X25519Secret(<redacted>)");
        assert!(!debug.contains("197"));
    }
}
