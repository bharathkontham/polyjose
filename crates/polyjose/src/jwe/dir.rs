//! `dir`: direct use of a shared symmetric key as the CEK (RFC 7518
//! §4.5). The JWE Encrypted Key is empty on encrypt and must be empty on
//! decrypt (RFC 7516 §5.1 step 6, §5.2 step 10).
//!
//! The key must be exactly the CEK length of `enc` (RFC 7518 §4.5,
//! §5.2.3–§5.2.5, §5.3). On encrypt `RecipientKey::from_jwk` has already
//! checked that; on decrypt it has not, because `enc` comes from the
//! attacker-controlled header, so the check is here and fails as
//! [`Error::DecryptionFailed`] like every other key management failure
//! (RFC 7516 §11.4–§11.5, the plan.md error contract).

use super::api::DecryptPolicy;
use super::content::{Cek, cek_len};
use super::key::RecipientKey;
use super::keymgmt::{KeyOutput, RecipientOptions};
use super::random::RandomSource;
use crate::header::Header;
use crate::json::Object;
use crate::jwa::{ContentEncAlg, KeyMgmtAlg};
use crate::{Error, Result};

/// Detail for a `dir` key whose length is not the CEK length of `enc`.
const DIR_KEY_SIZE: &str = "dir key length must equal the enc key length";

/// Key management on encrypt (RFC 7516 §5.1 steps 3–7) for `dir`: the
/// shared symmetric key is the CEK (§5.1 step 5, RFC 7518 §4.5), the JWE
/// Encrypted Key is the empty octet sequence (§5.1 step 6), and no header
/// parameter is defined. Nothing is drawn from `rng`, and a random CEK is
/// never passed in (`dir` has none, `Mode::has_random_cek`).
///
/// # Errors
///
/// - [`Error::UnsupportedAlgorithm`] for an `alg` other than `dir` or an
///   unknown `enc`;
/// - [`Error::KeyAlgorithmMismatch`] for a key that is not symmetric
///   (RFC 7518 §6.4, RFC 8725 §3.1);
/// - [`Error::InvalidKey`] if the key is not exactly `cek_len(enc)` bytes,
///   or a CEK is passed in (`dir` defines the CEK itself).
pub(super) fn encrypt_key(
    alg: &KeyMgmtAlg,
    key: &RecipientKey,
    enc: &ContentEncAlg,
    cek: Option<&Cek>,
    _options: &RecipientOptions,
    _rng: &mut dyn RandomSource,
) -> Result<KeyOutput> {
    if *alg != KeyMgmtAlg::Dir {
        return Err(Error::UnsupportedAlgorithm);
    }
    let RecipientKey::Symmetric(k) = key else {
        return Err(Error::KeyAlgorithmMismatch);
    };
    if k.len() != cek_len(enc)? {
        return Err(Error::InvalidKey(DIR_KEY_SIZE));
    }
    if cek.is_some() {
        return Err(Error::InvalidKey("dir takes no random CEK"));
    }
    Ok(KeyOutput {
        encrypted_key: Vec::new(),
        header_params: Object::new(),
        cek: Some(Cek::from_slice(k)),
    })
}

/// Key management on decrypt (RFC 7516 §5.2 steps 6–12) for `dir`: the
/// shared symmetric key is the CEK (§5.2 step 11), which must have the
/// length `enc` requires (§5.2 step 9, RFC 7518 §4.5), and the JWE
/// Encrypted Key must be empty (§5.2 step 10: "verify that the JWE
/// Encrypted Key value is an empty octet sequence").
///
/// # Errors
///
/// [`Error::DecryptionFailed`], whatever the cause: an `alg` other than
/// `dir`, a key that is not symmetric or not `cek_len(enc)` bytes, an
/// unknown `enc`, or a non-empty encrypted key. No cause can be told from
/// another (RFC 7516 §11.4–§11.5).
pub(super) fn decrypt_key(
    alg: &KeyMgmtAlg,
    key: &RecipientKey,
    enc: &ContentEncAlg,
    _header: &Header,
    encrypted_key: &[u8],
    _policy: &DecryptPolicy,
) -> Result<Cek> {
    let RecipientKey::Symmetric(k) = key else {
        return Err(Error::DecryptionFailed);
    };
    let usable = *alg == KeyMgmtAlg::Dir
        && encrypted_key.is_empty()
        && cek_len(enc).is_ok_and(|len| len == k.len());
    if usable {
        Ok(Cek::from_slice(k))
    } else {
        Err(Error::DecryptionFailed)
    }
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::*;
    use crate::rng::insecure_test_vectors::FixedRng;

    fn sym(len: usize) -> RecipientKey {
        RecipientKey::Symmetric(Zeroizing::new((0..len).map(|i| i as u8).collect()))
    }

    fn policy() -> DecryptPolicy {
        DecryptPolicy::new(&[KeyMgmtAlg::Dir], &[ContentEncAlg::A128GCM])
            .unwrap_or_else(|e| panic!("{e}"))
    }

    #[test]
    fn encrypt_uses_the_key_as_the_cek_with_an_empty_encrypted_key() {
        // RFC 7516 §5.1 steps 5-6, RFC 7518 §4.5. Nothing is drawn.
        let mut rng = FixedRng::new(Vec::new());
        let options = RecipientOptions::default();
        for enc in ContentEncAlg::KNOWN {
            let len = cek_len(enc).unwrap_or_else(|e| panic!("{e}"));
            let out = encrypt_key(&KeyMgmtAlg::Dir, &sym(len), enc, None, &options, &mut rng)
                .unwrap_or_else(|e| panic!("{enc}: {e}"));
            assert!(out.encrypted_key.is_empty(), "{enc}");
            assert!(out.header_params.is_empty(), "{enc}");
            let cek = out.cek.unwrap_or_else(|| panic!("{enc}: no CEK"));
            assert_eq!(cek.len(), len, "{enc}");
            assert_eq!(cek.as_bytes()[len - 1], (len - 1) as u8, "{enc}");
        }
    }

    #[test]
    fn encrypt_rejects_a_key_of_the_wrong_length_or_kind() {
        let mut rng = FixedRng::new(Vec::new());
        let options = RecipientOptions::default();
        let enc = ContentEncAlg::A128GCM;
        let dir = KeyMgmtAlg::Dir;
        for len in [0, 15, 17, 32] {
            let result = encrypt_key(&dir, &sym(len), &enc, None, &options, &mut rng);
            assert_eq!(result.map(|_| ()), Err(Error::InvalidKey(DIR_KEY_SIZE)));
        }
        let password = RecipientKey::Password(Zeroizing::new(vec![0; 16]));
        let result = encrypt_key(&dir, &password, &enc, None, &options, &mut rng);
        assert_eq!(result.map(|_| ()), Err(Error::KeyAlgorithmMismatch));
        let cek = Cek::from_slice(&[0; 16]);
        let result = encrypt_key(&dir, &sym(16), &enc, Some(&cek), &options, &mut rng);
        assert!(matches!(result, Err(Error::InvalidKey(_))));
        let result = encrypt_key(
            &KeyMgmtAlg::A128KW,
            &sym(16),
            &enc,
            None,
            &options,
            &mut rng,
        );
        assert_eq!(result.map(|_| ()), Err(Error::UnsupportedAlgorithm));
        let unknown = ContentEncAlg::from("A128CTR");
        let result = encrypt_key(&dir, &sym(16), &unknown, None, &options, &mut rng);
        assert_eq!(result.map(|_| ()), Err(Error::UnsupportedAlgorithm));
    }

    #[test]
    fn decrypt_returns_the_key_as_the_cek() {
        let header = Header::new();
        for enc in ContentEncAlg::KNOWN {
            let len = cek_len(enc).unwrap_or_else(|e| panic!("{e}"));
            let cek = decrypt_key(&KeyMgmtAlg::Dir, &sym(len), enc, &header, &[], &policy())
                .unwrap_or_else(|e| panic!("{enc}: {e}"));
            assert_eq!(cek.len(), len, "{enc}");
        }
    }

    #[test]
    fn every_decrypt_failure_is_decryption_failed() {
        // RFC 7516 §5.2 steps 9-10, §11.5: one detail-free error.
        let header = Header::new();
        let p = policy();
        let enc = ContentEncAlg::A128GCM;
        let dir = KeyMgmtAlg::Dir;
        let password = RecipientKey::Password(Zeroizing::new(vec![0; 16]));
        let unknown = ContentEncAlg::from("A128CTR");
        let cases: [(&KeyMgmtAlg, &RecipientKey, &ContentEncAlg, &[u8]); 6] = [
            (&dir, &sym(16), &enc, &[0]),               // non-empty encrypted key
            (&dir, &sym(16), &enc, &[0; 24]),           // a wrapped key, as A128KW
            (&dir, &sym(32), &enc, &[]),                // A256GCM key, A128GCM enc
            (&dir, &password, &enc, &[]),               // not a symmetric key
            (&dir, &sym(16), &unknown, &[]),            // unknown enc
            (&KeyMgmtAlg::A128KW, &sym(16), &enc, &[]), // not dir
        ];
        for (alg, key, enc, encrypted_key) in cases {
            let result = decrypt_key(alg, key, enc, &header, encrypted_key, &p);
            assert_eq!(result.map(|_| ()), Err(Error::DecryptionFailed));
        }
    }
}
