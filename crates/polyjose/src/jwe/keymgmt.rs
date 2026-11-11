//! The key management dispatcher (RFC 7516 §5.1 steps 2–8, §5.2 steps
//! 6–12; RFC 7518 §4).
//!
//! [`encrypt_key`] and [`decrypt_key`] route an `alg` to its family file
//! (`dir`, `aes_kw`, `aes_gcm_kw`, `rsa_oaep`, `pbes2`, `ecdh_es`). Each
//! family implements the same two signatures, so filling one in never
//! touches this file.
//!
//! On decrypt, `core` maps every error from here to
//! [`Error::DecryptionFailed`] (the plan.md error contract): by the time
//! key management runs, the `alg`, `enc` and key family have been checked,
//! and nothing a key management failure reveals may distinguish one cause
//! from another (RFC 7516 §11.4, §11.5).

use super::api::DecryptPolicy;
use super::content::Cek;
use super::key::{Direction, RecipientKey};
use super::random::RandomSource;
use super::{aes_gcm_kw, aes_kw, dir, ecdh_es, pbes2, rsa_oaep};
use crate::header::Header;
use crate::json::Object;
use crate::jwa::{ContentEncAlg, KeyMgmtAlg};
use crate::{Error, Result};

/// The key management modes of RFC 7516 §2: how the CEK is determined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// The CEK is encrypted to the recipient's public key (RSA-OAEP-256).
    KeyEncryption,
    /// The CEK is wrapped with a symmetric key (A*KW, A*GCMKW, PBES2).
    KeyWrapping,
    /// The CEK is the output of key agreement (ECDH-ES).
    DirectAgreement,
    /// Key agreement yields a key that wraps the CEK (ECDH-ES+A*KW).
    AgreementWithWrapping,
    /// The shared symmetric key is the CEK (`dir`).
    DirectEncryption,
}

impl Mode {
    /// Whether the CEK is random (RFC 7516 §5.1 step 2) rather than
    /// determined by key management (`dir`, ECDH-ES; §5.1 steps 5–6), in
    /// which case the JWE Encrypted Key is empty.
    pub(crate) fn has_random_cek(self) -> bool {
        matches!(
            self,
            Mode::KeyEncryption | Mode::KeyWrapping | Mode::AgreementWithWrapping
        )
    }
}

/// The mode of `alg` (RFC 7516 §2, RFC 7518 §4.1), or `None` for an
/// algorithm polyjose does not implement.
pub(crate) fn mode(alg: &KeyMgmtAlg) -> Option<Mode> {
    use KeyMgmtAlg as A;
    match alg {
        A::RsaOaep256 => Some(Mode::KeyEncryption),
        A::A128KW
        | A::A192KW
        | A::A256KW
        | A::A128GCMKW
        | A::A192GCMKW
        | A::A256GCMKW
        | A::Pbes2Hs256A128KW
        | A::Pbes2Hs384A192KW
        | A::Pbes2Hs512A256KW => Some(Mode::KeyWrapping),
        A::EcdhEs => Some(Mode::DirectAgreement),
        A::EcdhEsA128KW | A::EcdhEsA192KW | A::EcdhEsA256KW => Some(Mode::AgreementWithWrapping),
        A::Dir => Some(Mode::DirectEncryption),
        A::Unknown(_) => None,
    }
}

/// Whether polyjose implements `alg` in `direction`: every known `alg`
/// both ways, `RSA-OAEP-256` included since ADR 0067. `RSA-OAEP`
/// (ADR 0022), `RSA1_5` (ADR 0021, ADR 0067 §3) and unknown names are
/// [`KeyMgmtAlg::Unknown`] and unsupported both ways. This is the support
/// check that precedes the allow-list (plan.md error contract).
pub(crate) fn supported(alg: &KeyMgmtAlg, direction: Direction) -> bool {
    let _ = direction;
    !matches!(alg, KeyMgmtAlg::Unknown(_))
}

/// Per-recipient encryption options (RFC 7518 §4.6.1.2–§4.6.1.3,
/// §4.8.1.1–§4.8.1.2). A family ignores the ones it does not use.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RecipientOptions {
    /// ECDH-ES `apu` (Agreement PartyUInfo), raw bytes.
    pub(crate) apu: Option<Vec<u8>>,
    /// ECDH-ES `apv` (Agreement PartyVInfo), raw bytes.
    pub(crate) apv: Option<Vec<u8>>,
    /// PBES2 `p2c`, the iteration count; `None` is the encrypt default,
    /// 10,000 (ADR 0023).
    pub(crate) p2c: Option<u32>,
    /// PBES2 salt input length in bytes; `None` is 16. At least 8
    /// (RFC 7518 §4.8.1.1).
    pub(crate) p2s_len: Option<usize>,
}

/// What key management produced for one recipient.
#[derive(Debug)]
pub(crate) struct KeyOutput {
    /// The JWE Encrypted Key (RFC 7516 §5.1 steps 4–6): empty for `dir`
    /// and ECDH-ES.
    pub(crate) encrypted_key: Vec<u8>,
    /// The header parameters the algorithm defines (`epk`, `apu`, `apv`,
    /// `iv`, `tag`, `p2s`, `p2c`), for the caller to place (RFC 7518
    /// §4.6.1, §4.7.1, §4.8.1).
    pub(crate) header_params: Object,
    /// The CEK, when key management determines it (`dir`, ECDH-ES; RFC 7516
    /// §5.1 step 5); `None` when the random CEK passed in is used.
    pub(crate) cek: Option<Cek>,
}

/// Runs key management for one recipient on encrypt (RFC 7516 §5.1 steps
/// 3–7). `cek` is the message's random CEK for the modes that wrap or
/// encrypt one ([`Mode::has_random_cek`]), and `None` otherwise.
///
/// # Errors
///
/// [`Error::UnsupportedAlgorithm`] for an `alg` polyjose does not
/// implement; otherwise the family's error.
pub(crate) fn encrypt_key(
    alg: &KeyMgmtAlg,
    key: &RecipientKey,
    enc: &ContentEncAlg,
    cek: Option<&Cek>,
    options: &RecipientOptions,
    rng: &mut dyn RandomSource,
) -> Result<KeyOutput> {
    use KeyMgmtAlg as A;
    match alg {
        A::Dir => dir::encrypt_key(alg, key, enc, cek, options, rng),
        A::A128KW | A::A192KW | A::A256KW => aes_kw::encrypt_key(alg, key, enc, cek, options, rng),
        A::A128GCMKW | A::A192GCMKW | A::A256GCMKW => {
            aes_gcm_kw::encrypt_key(alg, key, enc, cek, options, rng)
        }
        A::RsaOaep256 => rsa_oaep::encrypt_key(alg, key, enc, cek, options, rng),
        A::Pbes2Hs256A128KW | A::Pbes2Hs384A192KW | A::Pbes2Hs512A256KW => {
            pbes2::encrypt_key(alg, key, enc, cek, options, rng)
        }
        A::EcdhEs | A::EcdhEsA128KW | A::EcdhEsA192KW | A::EcdhEsA256KW => {
            ecdh_es::encrypt_key(alg, key, enc, cek, options, rng)
        }
        A::Unknown(_) => Err(Error::UnsupportedAlgorithm),
    }
}

/// Runs key management for one recipient on decrypt (RFC 7516 §5.2 steps
/// 6–12) and returns the CEK. `header` is the union of the JOSE Header
/// parts for this recipient (§5.2 step 4).
///
/// `pbes2_budget` is the decrypt call's PBKDF2 budget, shared by all its
/// candidates (ADR 0050 §2); only the PBES2 family reads it.
///
/// # Errors
///
/// [`Error::UnsupportedAlgorithm`] for an `alg` polyjose does not decrypt;
/// otherwise the family's error, which `core` reports as
/// [`Error::DecryptionFailed`].
pub(crate) fn decrypt_key(
    alg: &KeyMgmtAlg,
    key: &RecipientKey,
    enc: &ContentEncAlg,
    header: &Header,
    encrypted_key: &[u8],
    policy: &DecryptPolicy,
    pbes2_budget: &mut pbes2::Budget,
) -> Result<Cek> {
    use KeyMgmtAlg as A;
    match alg {
        A::Dir => dir::decrypt_key(alg, key, enc, header, encrypted_key, policy),
        A::A128KW | A::A192KW | A::A256KW => {
            aes_kw::decrypt_key(alg, key, enc, header, encrypted_key, policy)
        }
        A::A128GCMKW | A::A192GCMKW | A::A256GCMKW => {
            aes_gcm_kw::decrypt_key(alg, key, enc, header, encrypted_key, policy)
        }
        A::Pbes2Hs256A128KW | A::Pbes2Hs384A192KW | A::Pbes2Hs512A256KW => {
            pbes2::decrypt_key(alg, key, enc, header, encrypted_key, pbes2_budget)
        }
        A::EcdhEs | A::EcdhEsA128KW | A::EcdhEsA192KW | A::EcdhEsA256KW => {
            ecdh_es::decrypt_key(alg, key, enc, header, encrypted_key, policy)
        }
        A::RsaOaep256 => rsa_oaep::decrypt_key(alg, key, enc, header, encrypted_key, policy),
        A::Unknown(_) => Err(Error::UnsupportedAlgorithm),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_known_alg_has_its_rfc_7516_mode() {
        use KeyMgmtAlg as A;
        let expected = [
            (A::RsaOaep256, Mode::KeyEncryption),
            (A::A128KW, Mode::KeyWrapping),
            (A::A192KW, Mode::KeyWrapping),
            (A::A256KW, Mode::KeyWrapping),
            (A::Dir, Mode::DirectEncryption),
            (A::EcdhEs, Mode::DirectAgreement),
            (A::EcdhEsA128KW, Mode::AgreementWithWrapping),
            (A::EcdhEsA192KW, Mode::AgreementWithWrapping),
            (A::EcdhEsA256KW, Mode::AgreementWithWrapping),
            (A::A128GCMKW, Mode::KeyWrapping),
            (A::A192GCMKW, Mode::KeyWrapping),
            (A::A256GCMKW, Mode::KeyWrapping),
            (A::Pbes2Hs256A128KW, Mode::KeyWrapping),
            (A::Pbes2Hs384A192KW, Mode::KeyWrapping),
            (A::Pbes2Hs512A256KW, Mode::KeyWrapping),
        ];
        assert_eq!(expected.len(), A::KNOWN.len());
        for (alg, m) in expected {
            assert_eq!(mode(&alg), Some(m), "{alg}");
        }
        for name in ["RSA-OAEP", "RSA1_5", "ECDH-1PU", ""] {
            assert_eq!(mode(&A::from(name)), None, "{name}");
        }
        let random: Vec<bool> = [
            Mode::KeyEncryption,
            Mode::KeyWrapping,
            Mode::AgreementWithWrapping,
            Mode::DirectAgreement,
            Mode::DirectEncryption,
        ]
        .map(Mode::has_random_cek)
        .to_vec();
        assert_eq!(random, [true, true, true, false, false]);
    }

    #[test]
    fn every_known_alg_is_supported_both_ways_and_unknown_is_not() {
        // ADR 0067: RSA-OAEP-256 decrypts too; RSA-OAEP (ADR 0022) and
        // RSA1_5 (ADR 0067 §3) are unknown both ways.
        for alg in KeyMgmtAlg::KNOWN {
            assert!(supported(alg, Direction::Encrypt), "{alg}");
            assert!(supported(alg, Direction::Decrypt), "{alg}");
        }
        for name in ["RSA-OAEP", "RSA1_5", "nope"] {
            let alg = KeyMgmtAlg::from(name);
            assert!(!supported(&alg, Direction::Encrypt), "{name}");
            assert!(!supported(&alg, Direction::Decrypt), "{name}");
        }
    }

    #[test]
    fn rsa1_5_is_unsupported_and_rsa_oaep_256_needs_an_rsa_private_key() {
        let key = RecipientKey::RsaPublic {
            n: vec![0xC1; 256],
            e: vec![1, 0, 1],
        };
        let policy = DecryptPolicy::new(&[KeyMgmtAlg::RsaOaep256], &[ContentEncAlg::A128GCM])
            .unwrap_or_else(|e| panic!("{e}"));
        let enc = ContentEncAlg::A128GCM;
        let header = Header::new();
        let mut budget = pbes2::Budget::new(&policy);
        let rsa1_5 = KeyMgmtAlg::from("RSA1_5");
        let result = decrypt_key(
            &rsa1_5,
            &key,
            &enc,
            &header,
            &[0; 256],
            &policy,
            &mut budget,
        );
        assert_eq!(result.map(|_| ()), Err(Error::UnsupportedAlgorithm));
        // ADR 0067: RSA-OAEP-256 reaches `rsa_oaep`, which needs the
        // private key; key binding never hands it a public one.
        let result = decrypt_key(
            &KeyMgmtAlg::RsaOaep256,
            &key,
            &enc,
            &header,
            &[0; 256],
            &policy,
            &mut budget,
        );
        assert_eq!(result.map(|_| ()), Err(Error::KeyAlgorithmMismatch));
        let mut rng = super::super::random::OsRandom;
        let unknown = KeyMgmtAlg::from("RSA-OAEP");
        let options = RecipientOptions::default();
        let result = encrypt_key(&unknown, &key, &enc, None, &options, &mut rng);
        assert_eq!(result.map(|_| ()), Err(Error::UnsupportedAlgorithm));
    }
}
