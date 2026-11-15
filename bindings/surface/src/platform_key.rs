//! Platform-held keys at the binding boundary (ADR 0070, ADR 0071 §5).
//!
//! [`PlatformKey`] is the surface's mirror of the core [`polyjose::PlatformKey`], in the
//! surface's string and byte types: a key that the operating system holds and never exports (the
//! Secure Enclave, the Keychain, the Android Keystore, a smart card, a KMS) performs one
//! private-key step for polyjose. The UniFFI adapter implements it over the host object, so Kotlin
//! and Swift code can pass a key of its own to the six `…_with_platform_key` operations:
//!
//! | Operation | Module | Core sibling |
//! |---|---|---|
//! | `jws_sign_compact_with_platform_key` | [`jws`](crate::jws) | RFC 7515 §5.1, §7.1 |
//! | `jwt_sign_with_platform_key` | [`jwt`](crate::jwt) | RFC 7519 §7.1 |
//! | `jwe_decrypt_compact_with_platform_key` | [`jwe`](crate::jwe) | RFC 7516 §5.2, §7.1 |
//! | `jwe_decrypt_json_with_platform_key` | [`jwe`](crate::jwe) | RFC 7516 §5.2, §7.2 |
//! | `jwt_decrypt_nested_with_platform_key` | [`jwt`](crate::jwt) | RFC 7519 §5.2, §7.2 step 8 |
//! | `jwt_decrypt_nested_with_platform_key_and_jwks` | [`jwt`](crate::jwt) | as above, ADR 0029 |
//!
//! Each is one call into the core's `*_with_platform_key` sibling, which runs every check of
//! ADR 0071 §2–§4 around the callback: the allow-lists before the key is touched, the binding
//! of the requested algorithm to `algorithms()` and the public JWK (RFC 8725 §3.1), the strict
//! DER reading and the verify-after-sign of every signature, and the RFC 7516 §11.5 substitute
//! CEK. The surface adds no check, default or ordering of its own (ADR 0030 §1).
//!
//! **Secrets (ADR 0071 §8).** The private key never crosses. Z and the CEK come back as
//! [`SecretBytes`], which the core then owns as `Zeroizing` without a copy; the signing input,
//! which holds the payload, is lent to the key as `&[u8]`.

use zeroize::Zeroizing;

use crate::secret::SecretBytes;

/// A private key held by the platform, which performs one private-key step for polyjose and never
/// exports the key (ADR 0070, ADR 0071 §1, §5): the surface form of [`polyjose::PlatformKey`].
///
/// The methods and their contract are the core trait's: read its documentation, in particular
/// **the error contract** (ADR 0071 §4): [`PlatformKeyError::NotFound`] and
/// [`PlatformKeyError::UserAuthenticationRequired`] only for a condition that does not depend on
/// the input (no such key; the user has not authenticated or cancelled), every other failure
/// [`PlatformKeyError::Failed`]. polyjose treats every implementation as untrusted: it can make a
/// call fail, but it cannot make polyjose return a token that does not verify under
/// [`public_jwk`](Self::public_jwk), skip an allow-list, or turn a decryption failure into a
/// distinguishable error, except by breaking that contract (ADR 0071, Consequences).
pub trait PlatformKey: Send + Sync {
    /// The key's public JWK as JSON text (RFC 7517 §4; RFC 7518 §6.2.1, §6.3.1), public members
    /// only; the core imports it and refuses a private member as `InvalidKey` (ADR 0071 §2).
    fn public_jwk(&self) -> Result<String, PlatformKeyError>;

    /// The JOSE algorithm names this key may be used with (RFC 7518 §3.1, §4.1): not empty, all
    /// of the key's family. Any other algorithm is `KeyAlgorithmMismatch` (RFC 8725 §3.1).
    fn algorithms(&self) -> Result<Vec<String>, PlatformKeyError>;

    /// Signs the JWS Signing Input (RFC 7515 §5.1 step 5) with `alg`: the ASN.1 DER
    /// `Ecdsa-Sig-Value` for ES256/ES384/ES512 (RFC 3279 §2.2.3), the signature octets for
    /// RS\* and PS\* (RFC 7518 §3.3, §3.5). The implementation hashes the input itself.
    fn sign(&self, alg: &str, signing_input: &[u8]) -> Result<Vec<u8>, PlatformKeyError>;

    /// ECDH with the JWE `epk`, already validated by the core, as the uncompressed SEC 1 point
    /// `0x04 ‖ X ‖ Y`; returns Z, the x-coordinate of the shared point (RFC 7518 §4.6.2).
    fn agree(&self, peer_public_key: &[u8]) -> Result<SecretBytes, PlatformKeyError>;

    /// RSAES-OAEP decryption of the JWE Encrypted Key for `alg` `RSA-OAEP-256` (RFC 7518 §4.3);
    /// returns the CEK. Any failure, a padding error included, must be
    /// [`PlatformKeyError::Failed`] (RFC 7516 §11.5).
    fn decrypt_key(&self, alg: &str, encrypted_key: &[u8])
    -> Result<SecretBytes, PlatformKeyError>;
}

/// Why a [`PlatformKey`] could not perform an operation (ADR 0071 §1, §6): the surface form of
/// [`polyjose::PlatformKeyError`], with no payload, so no host text can reach a polyjose error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformKeyError {
    /// No usable key: none under that name, or permanently invalidated. Reported as
    /// `KeyNotFound`.
    NotFound,
    /// The user has not authenticated, cancelled, or cannot. Reported as
    /// `UserAuthenticationRequired`.
    UserAuthenticationRequired,
    /// Any other failure: `PlatformKeyFailed` when signing, `DecryptionFailed` when decrypting
    /// (RFC 7516 §11.5).
    Failed,
}

/// Variant for variant (ADR 0071 §1).
impl From<PlatformKeyError> for polyjose::PlatformKeyError {
    fn from(e: PlatformKeyError) -> Self {
        match e {
            PlatformKeyError::NotFound => Self::NotFound,
            PlatformKeyError::UserAuthenticationRequired => Self::UserAuthenticationRequired,
            PlatformKeyError::Failed => Self::Failed,
        }
    }
}

/// A surface [`PlatformKey`] seen as the core trait, for one call: the only conversion between
/// the two (ADR 0030 §1). Z and the CEK move from the surface's [`SecretBytes`] into the core's
/// `Zeroizing` owner without a copy (ADR 0071 §8).
pub(crate) struct CoreKey<'a>(pub(crate) &'a dyn PlatformKey);

impl polyjose::PlatformKey for CoreKey<'_> {
    fn public_jwk(&self) -> Result<String, polyjose::PlatformKeyError> {
        Ok(self.0.public_jwk()?)
    }

    fn algorithms(&self) -> Result<Vec<String>, polyjose::PlatformKeyError> {
        Ok(self.0.algorithms()?)
    }

    fn sign(&self, alg: &str, signing_input: &[u8]) -> Result<Vec<u8>, polyjose::PlatformKeyError> {
        Ok(self.0.sign(alg, signing_input)?)
    }

    fn agree(
        &self,
        peer_public_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, polyjose::PlatformKeyError> {
        Ok(self.0.agree(peer_public_key)?.into_zeroizing())
    }

    fn decrypt_key(
        &self,
        alg: &str,
        encrypted_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, polyjose::PlatformKeyError> {
        Ok(self.0.decrypt_key(alg, encrypted_key)?.into_zeroizing())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_error_maps_to_the_core_variant_of_the_same_name() {
        for (surface, core) in [
            (
                PlatformKeyError::NotFound,
                polyjose::PlatformKeyError::NotFound,
            ),
            (
                PlatformKeyError::UserAuthenticationRequired,
                polyjose::PlatformKeyError::UserAuthenticationRequired,
            ),
            (PlatformKeyError::Failed, polyjose::PlatformKeyError::Failed),
        ] {
            assert_eq!(polyjose::PlatformKeyError::from(surface), core);
        }
    }

    /// A key that returns fixed values, to check that the bridge passes them through unchanged.
    struct Fixed;

    impl PlatformKey for Fixed {
        fn public_jwk(&self) -> Result<String, PlatformKeyError> {
            Ok("{}".to_owned())
        }
        fn algorithms(&self) -> Result<Vec<String>, PlatformKeyError> {
            Err(PlatformKeyError::UserAuthenticationRequired)
        }
        fn sign(&self, alg: &str, signing_input: &[u8]) -> Result<Vec<u8>, PlatformKeyError> {
            Ok([alg.as_bytes(), signing_input].concat())
        }
        fn agree(&self, peer_public_key: &[u8]) -> Result<SecretBytes, PlatformKeyError> {
            Ok(SecretBytes::from(peer_public_key.to_vec()))
        }
        fn decrypt_key(&self, _: &str, _: &[u8]) -> Result<SecretBytes, PlatformKeyError> {
            Err(PlatformKeyError::NotFound)
        }
    }

    #[test]
    fn the_bridge_passes_values_and_errors_through() {
        use polyjose::PlatformKey as _;
        let key = CoreKey(&Fixed);
        assert_eq!(key.public_jwk().unwrap(), "{}");
        assert_eq!(
            key.algorithms(),
            Err(polyjose::PlatformKeyError::UserAuthenticationRequired)
        );
        assert_eq!(key.sign("ES256", b".x").unwrap(), b"ES256.x");
        assert_eq!(key.agree(b"\x04z").unwrap().as_slice(), b"\x04z");
        assert_eq!(
            key.decrypt_key("RSA-OAEP-256", b"k"),
            Err(polyjose::PlatformKeyError::NotFound)
        );
    }

    #[test]
    fn z_moves_into_the_core_owner_without_a_copy() {
        // ADR 0071 §8: the buffer the key returned is the one the core wipes.
        let returned = SecretBytes::from(vec![7u8; 32]);
        let at = returned.as_bytes().as_ptr();
        assert_eq!(returned.into_zeroizing().as_ptr(), at);
    }
}
