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

use super::{content, keymgmt};
use crate::jwa::{ContentEncAlg, KeyMgmtAlg};
use crate::jwk::{Jwk, KeyMaterial, OctKey};
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
    /// RFC 7518 §4.5) for `direction`, before any cryptography runs.
    ///
    /// The key itself was validated when the [`Jwk`] was imported
    /// (`Jwk::from_object`: exact member lengths, EC points on their curve
    /// and not the identity, `d` in [1, n − 1], RSA moduli of at least 2048
    /// bits, RSA private keys refused; ADR 0041 §4, ADR 0021). The
    /// private-to-public consistency of ADR 0043 is an import check too.
    /// None of that is repeated here. In this order:
    ///
    /// 1. **Support** → [`Error::UnsupportedAlgorithm`]: `alg` must be
    ///    implemented in `direction` (`keymgmt::supported`: RSA-OAEP-256 is
    ///    encrypt only, ADR 0021; `RSA-OAEP` and `RSA1_5` are not
    ///    implemented, ADRs 0021, 0022), and for `dir` the `enc` must be
    ///    known, since it fixes the key length (RFC 7518 §4.5).
    /// 2. **Family** → [`Error::KeyAlgorithmMismatch`]: the key's `kty` and
    ///    `crv` must serve `alg`, by the single table
    ///    `KeyMaterial::serves_key_mgmt_alg` (RFC 7518 §4.1, RFC 8037 §3.2,
    ///    RFC 8725 §3.1).
    /// 3. **Size** of an `oct` key: A*KW and A*GCMKW need exactly the AES
    ///    key size the `alg` names (RFC 7518 §4.4, §4.7), and `dir` on
    ///    encrypt needs exactly the CEK length of `enc` (RFC 7518 §4.5,
    ///    §5.2.3–§5.2.5, §5.3). A wrong size is [`Error::InvalidKey`] on
    ///    encrypt (the caller's key is unusable) and
    ///    [`Error::KeyAlgorithmMismatch`] on decrypt (the key is not a
    ///    candidate; plan.md error contract). On decrypt the `dir` length
    ///    is *not* checked here: `enc` comes from the attacker-controlled
    ///    header, so a mismatch is the `dir` key management's
    ///    [`Error::DecryptionFailed`].
    ///
    /// # Errors
    ///
    /// As listed above; no error carries key material (ADR 0007).
    pub(crate) fn from_jwk(
        jwk: &Jwk,
        alg: &KeyMgmtAlg,
        enc: &ContentEncAlg,
        direction: Direction,
    ) -> Result<Self> {
        if !keymgmt::supported(alg, direction) {
            return Err(Error::UnsupportedAlgorithm);
        }
        if *alg == KeyMgmtAlg::Dir {
            // RFC 7518 §4.5: the shared key is the CEK of `enc`.
            content::cek_len(enc)?;
        }
        if !jwk.material().serves_key_mgmt_alg(alg) {
            return Err(Error::KeyAlgorithmMismatch);
        }
        match jwk.material() {
            KeyMaterial::Oct(key) => oct_key(key, alg, enc, direction),
            _ => Err(Error::UnsupportedAlgorithm),
        }
    }
}

/// The error for a key of the wrong size or form: [`Error::InvalidKey`]
/// with `detail` on encrypt, where the caller supplied an unusable key,
/// and [`Error::KeyAlgorithmMismatch`] on decrypt, where the key is simply
/// not a candidate for the recipient (plan.md error contract).
fn unusable(direction: Direction, detail: &'static str) -> Error {
    match direction {
        Direction::Encrypt => Error::InvalidKey(detail),
        Direction::Decrypt => Error::KeyAlgorithmMismatch,
    }
}

/// The AES key size in octets that a key wrapping `alg` requires: 16, 24
/// or 32 for the 128-, 192- and 256-bit variants of A*KW (RFC 7518 §4.4)
/// and A*GCMKW (RFC 7518 §4.7). `None` for every other `alg`.
fn wrapping_key_len(alg: &KeyMgmtAlg) -> Option<usize> {
    match alg {
        KeyMgmtAlg::A128KW | KeyMgmtAlg::A128GCMKW => Some(16),
        KeyMgmtAlg::A192KW | KeyMgmtAlg::A192GCMKW => Some(24),
        KeyMgmtAlg::A256KW | KeyMgmtAlg::A256GCMKW => Some(32),
        _ => None,
    }
}

/// An `oct` key (RFC 7518 §6.4) for an `alg` it serves: the A*KW, A*GCMKW
/// or `dir` key, or the PBES2 password (RFC 7518 §4.8: "the password",
/// carried as `k`, of any length).
fn oct_key(
    key: &OctKey,
    alg: &KeyMgmtAlg,
    enc: &ContentEncAlg,
    direction: Direction,
) -> Result<RecipientKey> {
    let k = || Zeroizing::new(key.k().to_vec());
    match alg {
        KeyMgmtAlg::Pbes2Hs256A128KW
        | KeyMgmtAlg::Pbes2Hs384A192KW
        | KeyMgmtAlg::Pbes2Hs512A256KW => Ok(RecipientKey::Password(k())),
        KeyMgmtAlg::Dir => {
            // RFC 7518 §4.5: the key is used directly as the CEK, so on
            // encrypt it must be exactly the CEK length of `enc`.
            if direction == Direction::Encrypt && key.len() != content::cek_len(enc)? {
                return Err(Error::InvalidKey(
                    "dir key length must equal the enc key length",
                ));
            }
            Ok(RecipientKey::Symmetric(k()))
        }
        _ => match wrapping_key_len(alg) {
            Some(len) if key.len() == len => Ok(RecipientKey::Symmetric(k())),
            Some(_) => Err(unusable(
                direction,
                "AES key wrap key length does not match alg",
            )),
            None => Err(Error::KeyAlgorithmMismatch),
        },
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
    use crate::util::b64url_encode;
    use Direction::{Decrypt, Encrypt};
    use KeyMgmtAlg as A;

    const MISMATCH: Error = Error::KeyAlgorithmMismatch;

    fn jwk(json: &str) -> Jwk {
        Jwk::from_json(json.as_bytes()).unwrap_or_else(|e| panic!("{e}: {json}"))
    }

    /// An `oct` key of `len` octets (0x5a each) with extra members.
    fn oct(len: usize, extra: &str) -> Jwk {
        let k = b64url_encode(&vec![0x5a; len]);
        jwk(&format!(r#"{{"kty":"oct","k":"{k}"{extra}}}"#))
    }

    /// The variant name `Debug` prints, or the error.
    fn bind(key: &Jwk, alg: &KeyMgmtAlg, enc: &ContentEncAlg, d: Direction) -> Result<String> {
        RecipientKey::from_jwk(key, alg, enc, d).map(|k| format!("{k:?}"))
    }

    fn variant(name: &str) -> Result<String> {
        Ok(format!("RecipientKey::{name}(<redacted>)"))
    }

    const GCM128: ContentEncAlg = ContentEncAlg::A128GCM;

    /// RFC 7518 §4.4, §4.7: A128/192/256KW and A128/192/256GCMKW use a
    /// 128-, 192- or 256-bit AES key.
    const WRAP_SIZES: [(KeyMgmtAlg, usize); 6] = [
        (A::A128KW, 16),
        (A::A192KW, 24),
        (A::A256KW, 32),
        (A::A128GCMKW, 16),
        (A::A192GCMKW, 24),
        (A::A256GCMKW, 32),
    ];

    #[test]
    fn oct_keys_are_symmetric_for_wrapping_and_dir_and_a_password_for_pbes2() {
        for (alg, len) in &WRAP_SIZES {
            for d in [Encrypt, Decrypt] {
                assert_eq!(
                    bind(&oct(*len, ""), alg, &GCM128, d),
                    variant("Symmetric"),
                    "{alg}"
                );
            }
        }
        for d in [Encrypt, Decrypt] {
            assert_eq!(
                bind(&oct(16, ""), &A::Dir, &GCM128, d),
                variant("Symmetric")
            );
        }
        // RFC 7518 §4.8: PBES2 takes a password of any length; RFC 7520
        // §5.3's is 30 octets.
        let pbes2 = [
            A::Pbes2Hs256A128KW,
            A::Pbes2Hs384A192KW,
            A::Pbes2Hs512A256KW,
        ];
        for alg in &pbes2 {
            for (len, d) in [(1, Encrypt), (30, Decrypt), (100, Encrypt)] {
                assert_eq!(
                    bind(&oct(len, ""), alg, &GCM128, d),
                    variant("Password"),
                    "{alg}"
                );
            }
        }
    }

    #[test]
    fn symmetric_and_password_keys_hold_k_exactly() {
        let key = jwk(r#"{"kty":"oct","k":"GZy6sIZ6wl9NJOKB-jnmVQ"}"#);
        // RFC 7520 §5.8.1 (Figure 151), the A128KW key.
        let k = [
            0x19, 0x9c, 0xba, 0xb0, 0x86, 0x7a, 0xc2, 0x5f, 0x4d, 0x24, 0xe2, 0x81, 0xfa, 0x39,
            0xe6, 0x55,
        ];
        let symmetric = RecipientKey::from_jwk(&key, &A::A128KW, &GCM128, Encrypt);
        assert!(matches!(symmetric, Ok(RecipientKey::Symmetric(ref s)) if **s == k));
        let password = RecipientKey::from_jwk(&key, &A::Pbes2Hs256A128KW, &GCM128, Decrypt);
        assert!(matches!(password, Ok(RecipientKey::Password(ref p)) if **p == k));
    }

    #[test]
    fn a_wrapping_key_of_the_wrong_size_is_invalid_on_encrypt_and_a_mismatch_on_decrypt() {
        for (alg, len) in &WRAP_SIZES {
            for wrong in [1, 15, 16, 17, 24, 31, 32, 33, 64] {
                if wrong == *len {
                    continue;
                }
                let key = oct(wrong, "");
                let encrypt = bind(&key, alg, &GCM128, Encrypt);
                assert!(
                    matches!(encrypt, Err(Error::InvalidKey(_))),
                    "{alg} {wrong}"
                );
                assert_eq!(
                    bind(&key, alg, &GCM128, Decrypt),
                    Err(MISMATCH),
                    "{alg} {wrong}"
                );
            }
        }
    }

    #[test]
    fn a_dir_key_must_be_the_cek_length_on_encrypt_only() {
        // RFC 7518 §5.2.3-§5.2.5 (CBC-HS: 32, 48, 64), §5.3 (GCM: 16, 24, 32).
        let sizes = [
            (ContentEncAlg::A128CbcHs256, 32),
            (ContentEncAlg::A192CbcHs384, 48),
            (ContentEncAlg::A256CbcHs512, 64),
            (ContentEncAlg::A128GCM, 16),
            (ContentEncAlg::A192GCM, 24),
            (ContentEncAlg::A256GCM, 32),
        ];
        for (enc, len) in &sizes {
            assert_eq!(
                bind(&oct(*len, ""), &A::Dir, enc, Encrypt),
                variant("Symmetric")
            );
            for wrong in [len - 1, len + 1, 1] {
                let key = oct(wrong, "");
                let encrypt = bind(&key, &A::Dir, enc, Encrypt);
                assert!(
                    matches!(encrypt, Err(Error::InvalidKey(_))),
                    "{enc} {wrong}"
                );
                // On decrypt `enc` comes from the header, so the length is
                // checked inside key management, where every failure is
                // DecryptionFailed (plan.md error contract).
                assert_eq!(bind(&key, &A::Dir, enc, Decrypt), variant("Symmetric"));
            }
        }
    }

    #[test]
    fn dir_with_an_unknown_enc_is_unsupported() {
        let enc = ContentEncAlg::from("A128GCM-ish");
        for d in [Encrypt, Decrypt] {
            assert_eq!(
                bind(&oct(16, ""), &A::Dir, &enc, d),
                Err(Error::UnsupportedAlgorithm)
            );
        }
    }

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
