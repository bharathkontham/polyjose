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

use p256::elliptic_curve::{Curve, FieldBytes, SecretKey};
use zeroize::Zeroizing;

use super::{content, keymgmt};
use crate::jwa::{ContentEncAlg, KeyMgmtAlg};
use crate::jwk::{EcCurve, EcKey, Jwk, KeyMaterial, OctKey, OkpCurve, OkpKey, RsaPublicKey};
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
            KeyMaterial::Ec(key) => ec_key(key, direction),
            KeyMaterial::Okp(key) => okp_key(key, direction),
            KeyMaterial::Rsa(key) => rsa_key(key, direction),
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

/// Detail for an EC key the curve crate refuses although import accepted
/// it (not expected: import ran the same checks, ADR 0041 §4).
const EC_KEY_UNUSABLE: &str = "EC key is not usable for ECDH-ES";

/// An `EC` key (RFC 7518 §6.2) for ECDH-ES (RFC 7518 §4.6), on P-256,
/// P-384 or P-521 (the curves `serves_key_mgmt_alg` admits).
///
/// - **Encrypt** uses the recipient's public key, so a public key, or the
///   public part (`x`, `y`) of a private key, gives `P*Public`. The point
///   is the uncompressed SEC 1 encoding `0x04 ‖ x ‖ y` (SEC 1 v2 §2.3.3) of
///   the full-length coordinates (RFC 7518 §6.2.1.2–§6.2.1.3), decoded by
///   `PublicKey::from_sec1_bytes`.
/// - **Decrypt** needs the private key `d` (RFC 7518 §6.2.2.1), so a
///   public key is [`Error::KeyAlgorithmMismatch`]; `d` gives `P*Secret`
///   through `SecretKey::from_bytes`.
fn ec_key(key: &EcKey, direction: Direction) -> Result<RecipientKey> {
    let unusable = || unusable(direction, EC_KEY_UNUSABLE);
    match direction {
        Direction::Encrypt => {
            let point = [&[0x04][..], key.x(), key.y()].concat();
            match key.crv() {
                EcCurve::P256 => p256::PublicKey::from_sec1_bytes(&point)
                    .map(RecipientKey::P256Public)
                    .map_err(|_| unusable()),
                EcCurve::P384 => p384::PublicKey::from_sec1_bytes(&point)
                    .map(RecipientKey::P384Public)
                    .map_err(|_| unusable()),
                EcCurve::P521 => p521::PublicKey::from_sec1_bytes(&point)
                    .map(RecipientKey::P521Public)
                    .map_err(|_| unusable()),
                _ => Err(Error::KeyAlgorithmMismatch),
            }
        }
        Direction::Decrypt => {
            let d = key.d().ok_or(Error::KeyAlgorithmMismatch)?;
            match key.crv() {
                EcCurve::P256 => secret::<p256::NistP256>(d)
                    .map(RecipientKey::P256Secret)
                    .ok_or_else(unusable),
                EcCurve::P384 => secret::<p384::NistP384>(d)
                    .map(RecipientKey::P384Secret)
                    .ok_or_else(unusable),
                EcCurve::P521 => secret::<p521::NistP521>(d)
                    .map(RecipientKey::P521Secret)
                    .ok_or_else(unusable),
                _ => Err(Error::KeyAlgorithmMismatch),
            }
        }
    }
}

/// `SecretKey::from_bytes` on `d`, exactly the field length
/// (RFC 7518 §6.2.2.1). The result wipes itself on drop.
fn secret<C: Curve>(d: &[u8]) -> Option<SecretKey<C>> {
    let d = <&FieldBytes<C>>::try_from(d).ok()?;
    SecretKey::<C>::from_bytes(d).ok()
}

/// Detail for an X25519 key of the wrong length (not expected: import
/// checks it, RFC 8037 §2).
const X25519_KEY_UNUSABLE: &str = "X25519 key is not 32 octets";

/// An `OKP` key (RFC 8037 §2) for ECDH-ES: `X25519` only (RFC 8037 §3.2;
/// `Ed25519` "MUST NOT be used for ECDH-ES" and never reaches here).
///
/// - **Encrypt** uses the recipient's 32-octet public key `x`
///   (RFC 7748 §5), also from a private key, giving `X25519Public`.
/// - **Decrypt** needs the 32-octet private key `d`, giving
///   `X25519Secret`; a public key is [`Error::KeyAlgorithmMismatch`].
///
/// Every 32-octet `x` is a valid input (RFC 7748 §5), and a small-order one
/// is caught as an all-zero shared secret where ECDH-ES computes it
/// (RFC 7748 §6.1, ADR 0043 §2), so nothing more is checked here.
fn okp_key(key: &OkpKey, direction: Direction) -> Result<RecipientKey> {
    if key.crv() != OkpCurve::X25519 {
        return Err(Error::KeyAlgorithmMismatch);
    }
    let unusable = || unusable(direction, X25519_KEY_UNUSABLE);
    match direction {
        Direction::Encrypt => {
            let x = <[u8; 32]>::try_from(key.x()).map_err(|_| unusable())?;
            Ok(RecipientKey::X25519Public(x25519_dalek::PublicKey::from(x)))
        }
        Direction::Decrypt => {
            let d = key.d().ok_or(Error::KeyAlgorithmMismatch)?;
            // The copy is wiped when it goes out of scope; the
            // `StaticSecret` wipes its own on drop (`zeroize` feature).
            let d = Zeroizing::new(<[u8; 32]>::try_from(d).map_err(|_| unusable())?);
            Ok(RecipientKey::X25519Secret(
                x25519_dalek::StaticSecret::from(*d),
            ))
        }
    }
}

/// The largest RSA modulus polyjose uses, in bits: the `rsa` crate's own
/// maximum, as for JWS (ADR 0026 §2 step 8). Import already refuses fewer
/// than 2048 bits (RFC 7518 §4.2–§4.3, ADR 0007).
const RSA_MAX_BITS: usize = 8192;

/// An `RSA` public key (RFC 7518 §6.3.1) for RSA-OAEP-256 encryption
/// (RFC 7518 §4.3), held as its validated `n` and `e`, big-endian.
///
/// Only encryption reaches here: RSA-OAEP-256 decryption is
/// [`Error::UnsupportedAlgorithm`] (ADR 0021), and an RSA private JWK
/// never imports. A modulus above [`RSA_MAX_BITS`] is
/// [`Error::InvalidKey`].
fn rsa_key(key: &RsaPublicKey, direction: Direction) -> Result<RecipientKey> {
    if direction == Direction::Decrypt {
        return Err(Error::UnsupportedAlgorithm);
    }
    if key.modulus_bits() > RSA_MAX_BITS {
        return Err(Error::InvalidKey("RSA modulus must be 2048 to 8192 bits"));
    }
    Ok(RecipientKey::RsaPublic {
        n: key.n().to_vec(),
        e: key.e().to_vec(),
    })
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

    /// RFC 7520 §3.2 (Figure 2), the P-521 private key, without its
    /// `use: sig`.
    const RFC7520_P521: &str = r#""kty":"EC","kid":"bilbo.baggins@hobbiton.example","crv":"P-521","x":"AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt","y":"AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1""#;
    const RFC7520_P521_D: &str =
        "AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt";

    fn p521(extra: &str) -> Jwk {
        jwk(&format!("{{{RFC7520_P521}{extra}}}"))
    }

    fn p521_private(extra: &str) -> Jwk {
        p521(&format!(r#","d":"{RFC7520_P521_D}"{extra}"#))
    }

    /// RFC 7520 §3.3 (Figure 3), the RSA 2048-bit public key, without its
    /// `use: sig`.
    fn rsa(extra: &str) -> Jwk {
        jwk(&format!(
            r#"{{"kty":"RSA","kid":"bilbo.baggins@hobbiton.example","n":"n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw","e":"AQAB"{extra}}}"#
        ))
    }

    /// RFC 7748 §6.1 Bob's X25519 key pair (RFC 8037 §A.6 uses its public
    /// key).
    const X25519_BOB: &str =
        r#""kty":"OKP","crv":"X25519","x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08""#;
    const X25519_BOB_D: &str = "XasIfmJKikt54X-Lg4AO5m87sSkmGLb9HC-LJ_-I4Os";

    fn x25519(extra: &str) -> Jwk {
        jwk(&format!("{{{X25519_BOB}{extra}}}"))
    }

    fn x25519_private(extra: &str) -> Jwk {
        x25519(&format!(r#","d":"{X25519_BOB_D}"{extra}"#))
    }

    const ECDH: [KeyMgmtAlg; 4] = [A::EcdhEs, A::EcdhEsA128KW, A::EcdhEsA192KW, A::EcdhEsA256KW];

    /// RFC 7520 §5.5.1 (Figure 108), the P-256 key of the ECDH-ES example.
    const RFC7520_P256: &str = r#""kty":"EC","kid":"meriadoc.brandybuck@buckland.example","use":"enc","crv":"P-256","x":"Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0","y":"HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw""#;
    const RFC7520_P256_D: &str = "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8";
    /// RFC 7520 §5.4.1 (Figure 72), the P-384 key of the ECDH-ES+A128KW
    /// example.
    const RFC7520_P384: &str = r#""kty":"EC","kid":"peregrin.took@tuckborough.example","use":"enc","crv":"P-384","x":"YU4rRUzdmVqmRtWOs2OpDE_T5fsNIodcG8G5FWPrTPMyxpzsSOGaQLpe2FpxBmu2","y":"A8-yxCHxkfBz3hKZfI1jUYMjUhsEveZ9THuwFjH2sCNdtksRJU7D5-SkgaFL1ETP""#;
    const RFC7520_P384_D: &str = "iTx2pk7wW-GqJkHcEkFQb2EFyYcO7RugmaW3mRrQVAOUiPommT0IdnYK2xDlZh-j";

    /// The JWK, its uncompressed SEC 1 point and its `d`, for each curve.
    fn ec_cases() -> [(Jwk, Jwk, Vec<u8>, Vec<u8>); 3] {
        let case = |members: &str, d: &str| {
            let public = jwk(&format!("{{{members}}}"));
            let private = jwk(&format!(r#"{{{members},"d":"{d}"}}"#));
            let KeyMaterial::Ec(ec) = public.material() else {
                panic!("not EC")
            };
            let point = [&[0x04][..], ec.x(), ec.y()].concat();
            let d = crate::util::b64url_decode(d).unwrap_or_default();
            (public, private, point, d)
        };
        [
            case(RFC7520_P256, RFC7520_P256_D),
            case(RFC7520_P384, RFC7520_P384_D),
            case(RFC7520_P521, RFC7520_P521_D),
        ]
    }

    /// The curve, whether the variant is secret, and its uncompressed SEC 1
    /// point (public) or `d` (secret).
    fn ec_parts(key: &RecipientKey) -> (&'static str, bool, Vec<u8>) {
        use p256::elliptic_curve::sec1::ToSec1Point;
        match key {
            RecipientKey::P256Public(k) => {
                ("P-256", false, k.to_sec1_point(false).as_bytes().to_vec())
            }
            RecipientKey::P384Public(k) => {
                ("P-384", false, k.to_sec1_point(false).as_bytes().to_vec())
            }
            RecipientKey::P521Public(k) => {
                ("P-521", false, k.to_sec1_point(false).as_bytes().to_vec())
            }
            RecipientKey::P256Secret(k) => ("P-256", true, k.to_bytes().to_vec()),
            RecipientKey::P384Secret(k) => ("P-384", true, k.to_bytes().to_vec()),
            RecipientKey::P521Secret(k) => ("P-521", true, k.to_bytes().to_vec()),
            _ => ("other", false, Vec::new()),
        }
    }

    #[test]
    fn an_ec_key_encrypts_to_its_public_point_and_decrypts_with_d() {
        for ((public, private, point, d), crv) in ec_cases().iter().zip(["P-256", "P-384", "P-521"])
        {
            for alg in &ECDH {
                // A public key, or a private key through its public part
                // (RFC 7518 §4.6: the sender needs only the recipient's
                // public key).
                for key in [public, private] {
                    let bound = RecipientKey::from_jwk(key, alg, &GCM128, Encrypt);
                    let bound = bound.unwrap_or_else(|e| panic!("{crv} {alg}: {e}"));
                    assert_eq!(ec_parts(&bound), (crv, false, point.clone()), "{alg}");
                }
                let bound = RecipientKey::from_jwk(private, alg, &GCM128, Decrypt);
                let bound = bound.unwrap_or_else(|e| panic!("{crv} {alg}: {e}"));
                assert_eq!(ec_parts(&bound), (crv, true, d.clone()), "{alg}");
            }
        }
    }

    #[test]
    fn an_ec_secret_derives_the_jwk_point() {
        // A fixture check: the RFC 7520 key pairs are consistent, so the
        // secret variant and the public variant describe the same key.
        use p256::elliptic_curve::sec1::ToSec1Point;
        for (_, private, point, _) in &ec_cases() {
            let derived = match RecipientKey::from_jwk(private, &A::EcdhEs, &GCM128, Decrypt) {
                Ok(RecipientKey::P256Secret(k)) => {
                    k.public_key().to_sec1_point(false).as_bytes().to_vec()
                }
                Ok(RecipientKey::P384Secret(k)) => {
                    k.public_key().to_sec1_point(false).as_bytes().to_vec()
                }
                Ok(RecipientKey::P521Secret(k)) => {
                    k.public_key().to_sec1_point(false).as_bytes().to_vec()
                }
                other => panic!("{other:?}"),
            };
            assert_eq!(&derived, point);
        }
    }

    #[test]
    fn a_public_ec_key_cannot_decrypt() {
        // RFC 7518 §4.6: the recipient needs its private key.
        for (public, ..) in &ec_cases() {
            for alg in &ECDH {
                assert_eq!(bind(public, alg, &GCM128, Decrypt), Err(MISMATCH), "{alg}");
            }
        }
    }

    #[test]
    fn secp256k1_does_not_serve_ecdh_es() {
        // RFC 8812 §3.3 leaves secp256k1 key agreement undefined, and
        // RFC 7518 §4.6 lists P-256, P-384 and P-521 only.
        let k256 = jwk(
            r#"{"kty":"EC","crv":"secp256k1","x":"eb5mfvncu6xVoGKVzocLBwKb_NstzijZWfKBWxb4F5g","y":"SDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj_sQ1Lg","d":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE"}"#,
        );
        for alg in &ECDH {
            for d in [Encrypt, Decrypt] {
                assert_eq!(bind(&k256, alg, &GCM128, d), Err(MISMATCH), "{alg}");
            }
        }
    }

    #[test]
    fn an_x25519_key_encrypts_to_x_and_decrypts_with_d() {
        let x = crate::util::b64url_decode("3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08")
            .unwrap_or_default();
        let d = crate::util::b64url_decode(X25519_BOB_D).unwrap_or_default();
        for alg in &ECDH {
            for key in [x25519(""), x25519_private("")] {
                let bound = RecipientKey::from_jwk(&key, alg, &GCM128, Encrypt);
                assert!(
                    matches!(bound, Ok(RecipientKey::X25519Public(ref p)) if p.as_bytes()[..] == x[..]),
                    "{alg}"
                );
            }
            let bound = RecipientKey::from_jwk(&x25519_private(""), alg, &GCM128, Decrypt);
            let Ok(RecipientKey::X25519Secret(secret)) = bound else {
                panic!("{alg}: {bound:?}")
            };
            assert_eq!(secret.to_bytes()[..], d[..], "{alg}");
            // RFC 7748 §6.1: Bob's private key gives Bob's public key.
            let public = x25519_dalek::PublicKey::from(&secret);
            assert_eq!(public.as_bytes()[..], x[..], "{alg}");
        }
    }

    #[test]
    fn a_public_x25519_key_cannot_decrypt() {
        for alg in &ECDH {
            assert_eq!(
                bind(&x25519(""), alg, &GCM128, Decrypt),
                Err(MISMATCH),
                "{alg}"
            );
        }
    }

    #[test]
    fn ed25519_does_not_serve_ecdh_es() {
        // RFC 8037 §3.2: "The Ed25519 and Ed448 subtypes MUST NOT be used
        // for ECDH-ES".
        let ed25519 = jwk(
            r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"}"#,
        );
        for alg in &ECDH {
            for d in [Encrypt, Decrypt] {
                assert_eq!(bind(&ed25519, alg, &GCM128, d), Err(MISMATCH), "{alg}");
            }
        }
    }

    /// An RSA public key with a `bits`-bit modulus (all ones: odd and
    /// minimal) and e = 65537. Structurally valid only.
    fn rsa_bits(bits: usize) -> Jwk {
        let mut n = vec![0xff; bits.div_ceil(8)];
        n[0] >>= (8 - bits % 8) % 8;
        let n = b64url_encode(&n);
        jwk(&format!(r#"{{"kty":"RSA","n":"{n}","e":"AQAB"}}"#))
    }

    #[test]
    fn an_rsa_public_key_serves_rsa_oaep_256_encrypt_with_its_n_and_e() {
        let key = rsa("");
        let KeyMaterial::Rsa(material) = key.material() else {
            panic!("not RSA")
        };
        let bound = RecipientKey::from_jwk(&key, &A::RsaOaep256, &GCM128, Encrypt);
        assert!(matches!(
            bound,
            Ok(RecipientKey::RsaPublic { ref n, ref e }) if n == material.n() && *e == [1, 0, 1]
        ));
    }

    #[test]
    fn rsa_oaep_256_decrypt_is_unsupported() {
        // ADR 0021: no RSA private-key operation.
        assert_eq!(
            bind(&rsa(""), &A::RsaOaep256, &GCM128, Decrypt),
            Err(Error::UnsupportedAlgorithm)
        );
    }

    #[test]
    fn an_rsa_modulus_must_be_2048_to_8192_bits() {
        // RFC 7518 §4.3 (via §4.2): "A key of size 2048 bits or larger MUST
        // be used"; 8192 is the `rsa` crate's maximum (ADR 0026 §2 step 8).
        // Import already refuses < 2048 (ADR 0007).
        for bits in [2048, 3072, 4096, 8192] {
            assert_eq!(
                bind(&rsa_bits(bits), &A::RsaOaep256, &GCM128, Encrypt),
                variant("RsaPublic"),
                "{bits}"
            );
        }
        for bits in [8193, 16384] {
            let bound = bind(&rsa_bits(bits), &A::RsaOaep256, &GCM128, Encrypt);
            assert!(matches!(bound, Err(Error::InvalidKey(_))), "{bits}");
        }
    }
}
