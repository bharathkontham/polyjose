//! Platform-held keys: a private key the operating system holds and never
//! exports (ADR 0070, ADR 0071).
//!
//! An app passes a [`PlatformKey`] where it would pass a private JWK, to
//! the `*_with_platform_key` siblings of the sign and decrypt functions:
//!
//! | Operation | Sibling |
//! |---|---|
//! | JWS compact (RFC 7515 §7.1) | [`jws::sign_compact_with_platform_key`](crate::jws::sign_compact_with_platform_key) |
//! | JWS flattened / general JSON (RFC 7515 §7.2) | [`jws::sign_flattened_with_platform_key`](crate::jws::sign_flattened_with_platform_key), [`jws::sign_general_with_platform_key`](crate::jws::sign_general_with_platform_key) |
//! | JWT (RFC 7519 §7.1) | [`jwt::sign_with_platform_key`](crate::jwt::sign_with_platform_key) |
//! | JWE compact / JSON (RFC 7516 §5.2) | [`jwe::decrypt_compact_with_platform_key`](crate::jwe::decrypt_compact_with_platform_key), [`jwe::decrypt_json_with_platform_key`](crate::jwe::decrypt_json_with_platform_key) |
//! | Nested JWT (RFC 7519 §11.2) | [`jwt::decrypt_nested_with_platform_key`](crate::jwt::decrypt_nested_with_platform_key) |
//!
//! # What the platform does, and what polyjose still does (ADR 0070 §2)
//!
//! Only the private-key step is delegated: an ECDSA, RSASSA-PKCS1-v1_5 or
//! RSASSA-PSS signature ([`PlatformKey::sign`]), an ECDH agreement
//! ([`PlatformKey::agree`]), or an RSA-OAEP-256 decryption of the JWE
//! Encrypted Key ([`PlatformKey::decrypt_key`]). polyjose keeps every
//! other step in pure Rust, and runs these checks around the callback
//! (ADR 0071 §2–§4):
//!
//! 1. Everything the JWK path checks before it touches the key: header
//!    rules, `crit`, and for decryption the caller's allow-lists
//!    (RFC 8725 §3.1, ADR 0007). An algorithm outside the allow-list
//!    never reaches the key, not even [`PlatformKey::public_jwk`].
//! 2. The algorithm must be one a platform key may serve (signing: ES256,
//!    ES384, ES512, RS256, RS384, RS512, PS256, PS384, PS512; decryption:
//!    ECDH-ES and ECDH-ES+A128KW/A192KW/A256KW on P-256, P-384 and P-521,
//!    and RSA-OAEP-256). Anything else is
//!    [`Error::UnsupportedAlgorithm`], before the key is called.
//! 3. [`PlatformKey::public_jwk`] and [`PlatformKey::algorithms`] are read
//!    once per call. The JWK must import ([`Jwk::from_json`]: on-curve
//!    points, an RSA modulus of 2048 to 8192 bits) and hold public members
//!    only; a private member is [`Error::InvalidKey`] and the text is
//!    wiped.
//! 4. Key binding (RFC 8725 §3.1): the algorithm is in `algorithms()`, is
//!    served by the JWK's `kty` and `crv`, equals the JWK `alg` when it has
//!    one, and the JWK `use` is `sig` for signing or `enc` for decryption
//!    when it has one. `key_ops` is not consulted: on a public JWK it
//!    names public-key operations (RFC 7517 §4.3). A mismatch is
//!    [`Error::KeyAlgorithmMismatch`].
//! 5. **Signing:** an ES\* result must be a strict DER `Ecdsa-Sig-Value`,
//!    converted to fixed-width R‖S with low S (RFC 7518 §3.4, ADR 0026
//!    §5); an RS\*/PS\* result must be exactly the modulus length. Every
//!    signature is then verified against the public JWK, always, before
//!    it is returned. A malformed or non-verifying result is
//!    [`Error::PlatformKeyFailed`].
//! 6. **ECDH-ES:** the `epk` is validated exactly as on the JWK path
//!    before [`PlatformKey::agree`] is called, which receives the
//!    uncompressed point `0x04 ‖ X ‖ Y`; Z must be the field size
//!    (RFC 7518 §4.6).
//! 7. **RSA-OAEP-256:** the random substitute CEK is drawn before
//!    [`PlatformKey::decrypt_key`] is called, and any failure leaves it in
//!    place (RFC 7516 §11.5).
//!
//! # Errors from the key
//!
//! [`PlatformKeyError::NotFound`] is [`Error::KeyNotFound`] and
//! [`PlatformKeyError::UserAuthenticationRequired`] is
//! [`Error::UserAuthenticationRequired`], from every method, on every
//! operation. [`PlatformKeyError::Failed`] is
//! [`Error::PlatformKeyFailed`] when signing and
//! [`Error::DecryptionFailed`] when decrypting (ADR 0071 §4, RFC 7516
//! §11.5).
//!
//! # Secrets (ADR 0070 §2, ADR 0071 §8)
//!
//! The private key never reaches polyjose. Z and the CEK do, because the
//! Concat KDF and content decryption run here: they arrive in
//! [`Zeroizing`] buffers and are wiped when polyjose drops them. The JWS
//! Signing Input, which contains the payload, is passed to the key.

use core::fmt;

use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::jwa::{KeyMgmtAlg, SigningAlg};
use crate::jwk::{EcCurve, Jwk, KeyAlg, KeyMaterial, KeyUse};

/// A private key held by the platform (the Secure Enclave, the Apple
/// Keychain, the Android Keystore, a smart card, a KMS) that performs one
/// private-key step for polyjose and never exports the key (ADR 0070,
/// ADR 0071 §1).
///
/// polyjose treats an implementation as untrusted: it can make a call
/// fail, but every check of the [module docs](self) still runs, and a
/// signature that does not verify under [`public_jwk`](Self::public_jwk)
/// is never returned (ADR 0071 §3).
///
/// # The error contract (ADR 0071 §4)
///
/// An implementation may return [`PlatformKeyError::NotFound`] or
/// [`PlatformKeyError::UserAuthenticationRequired`] **only** for a
/// condition that does not depend on its input: there is no such key, or
/// the user has not authenticated or cancelled. polyjose reports those two
/// as themselves on decryption too, so returning one for a malformed
/// ciphertext would turn a decryption failure into a distinguishable
/// error, the oracle RFC 7516 §11.5 forbids. Every other failure must be
/// [`PlatformKeyError::Failed`].
///
/// A method is called at most once per signature or recipient, and may
/// block (for example while a system prompt is shown).
///
/// ```
/// use polyjose::{PlatformKey, PlatformKeyError};
/// use zeroize::Zeroizing;
///
/// /// A key that is never there.
/// struct Missing;
///
/// impl PlatformKey for Missing {
///     fn public_jwk(&self) -> Result<String, PlatformKeyError> {
///         Err(PlatformKeyError::NotFound)
///     }
///     fn algorithms(&self) -> Result<Vec<String>, PlatformKeyError> {
///         Err(PlatformKeyError::NotFound)
///     }
///     fn sign(&self, _alg: &str, _input: &[u8]) -> Result<Vec<u8>, PlatformKeyError> {
///         Err(PlatformKeyError::NotFound)
///     }
///     fn agree(&self, _peer: &[u8]) -> Result<Zeroizing<Vec<u8>>, PlatformKeyError> {
///         Err(PlatformKeyError::NotFound)
///     }
///     fn decrypt_key(&self, _alg: &str, _ek: &[u8]) -> Result<Zeroizing<Vec<u8>>, PlatformKeyError> {
///         Err(PlatformKeyError::NotFound)
///     }
/// }
///
/// let key: &dyn PlatformKey = &Missing;
/// assert_eq!(key.algorithms(), Err(PlatformKeyError::NotFound));
/// ```
pub trait PlatformKey: Send + Sync {
    /// The key's public JWK as JSON text (RFC 7517 §4): `kty` `EC` with
    /// `crv` `P-256`, `P-384` or `P-521` (RFC 7518 §6.2.1), or `kty` `RSA`
    /// (RFC 7518 §6.3.1). Public members only; `kid`, `alg` and `use` are
    /// optional and, when present, bind the key (RFC 7517 §4.2, §4.4,
    /// §4.5).
    ///
    /// polyjose imports it with [`Jwk::from_json`] and refuses one with a
    /// private member as [`Error::InvalidKey`].
    ///
    /// # Errors
    ///
    /// See [the error contract](PlatformKey#the-error-contract-adr-0071-4).
    fn public_jwk(&self) -> core::result::Result<String, PlatformKeyError>;

    /// The JOSE algorithm names this key may be used with (RFC 7518 §3.1,
    /// §4.1): not empty, all of the key's own family, for example
    /// `["ES256"]` or `["RSA-OAEP-256"]`. An algorithm not listed is
    /// [`Error::KeyAlgorithmMismatch`] (RFC 8725 §3.1).
    ///
    /// # Errors
    ///
    /// See [the error contract](PlatformKey#the-error-contract-adr-0071-4).
    fn algorithms(&self) -> core::result::Result<Vec<String>, PlatformKeyError>;

    /// Signs `signing_input`, the JWS Signing Input (RFC 7515 §5.1 step 5),
    /// with `alg`: for `ES256`/`ES384`/`ES512` ECDSA with SHA-256/384/512,
    /// returning the ASN.1 DER `Ecdsa-Sig-Value` (RFC 3279 §2.2.3), which
    /// is what the Apple Security framework and `java.security.Signature`
    /// return; for `RS*` RSASSA-PKCS1-v1_5 and for `PS*` RSASSA-PSS with
    /// MGF1 and a salt the size of the hash (RFC 7518 §3.3, §3.5),
    /// returning the signature octets. The implementation hashes the input
    /// itself.
    ///
    /// # Errors
    ///
    /// See [the error contract](PlatformKey#the-error-contract-adr-0071-4).
    fn sign(
        &self,
        alg: &str,
        signing_input: &[u8],
    ) -> core::result::Result<Vec<u8>, PlatformKeyError>;

    /// ECDH (RFC 7518 §4.6.2: Z) with `peer_public_key`, the JWE `epk`
    /// that polyjose has already validated, as an uncompressed SEC 1 point
    /// `0x04 ‖ X ‖ Y` (SEC 1 v2 §2.3.3). Returns the shared secret Z, the
    /// x-coordinate of the shared point: 32, 48 or 66 octets for P-256,
    /// P-384 and P-521.
    ///
    /// # Errors
    ///
    /// See [the error contract](PlatformKey#the-error-contract-adr-0071-4).
    fn agree(
        &self,
        peer_public_key: &[u8],
    ) -> core::result::Result<Zeroizing<Vec<u8>>, PlatformKeyError>;

    /// Decrypts the JWE Encrypted Key with `alg`, which is `RSA-OAEP-256`
    /// (RFC 7518 §4.3: RSAES-OAEP with SHA-256, MGF1 with SHA-256 and the
    /// empty label), returning the CEK.
    ///
    /// Any failure, including a padding error, must be
    /// [`PlatformKeyError::Failed`]: polyjose then goes on with a random
    /// CEK, so the failure looks like any other decryption failure
    /// (RFC 7516 §11.5).
    ///
    /// # Errors
    ///
    /// See [the error contract](PlatformKey#the-error-contract-adr-0071-4).
    fn decrypt_key(
        &self,
        alg: &str,
        encrypted_key: &[u8],
    ) -> core::result::Result<Zeroizing<Vec<u8>>, PlatformKeyError>;
}

/// Why a [`PlatformKey`] could not perform an operation (ADR 0071 §1, §6).
///
/// It carries no payload, so no platform text, tag or alias can reach a
/// polyjose error or log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformKeyError {
    /// No usable key: none under that name, or the platform has
    /// permanently invalidated it. Reported as [`Error::KeyNotFound`].
    NotFound,
    /// The key needs the user to authenticate, and they have not,
    /// cancelled, or cannot. Reported as
    /// [`Error::UserAuthenticationRequired`].
    UserAuthenticationRequired,
    /// Any other failure. Reported as [`Error::PlatformKeyFailed`] when
    /// signing and [`Error::DecryptionFailed`] when decrypting
    /// (RFC 7516 §11.5).
    Failed,
}

/// Fixed text per variant; no platform detail exists to print.
impl fmt::Display for PlatformKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PlatformKeyError::NotFound => "platform key not found",
            PlatformKeyError::UserAuthenticationRequired => "user authentication required",
            PlatformKeyError::Failed => "platform key operation failed",
        })
    }
}

impl std::error::Error for PlatformKeyError {}

/// The mapping used when **signing** (ADR 0071 §6): `NotFound` →
/// [`Error::KeyNotFound`], `UserAuthenticationRequired` →
/// [`Error::UserAuthenticationRequired`], `Failed` →
/// [`Error::PlatformKeyFailed`]. Decryption maps `Failed` to
/// [`Error::DecryptionFailed`] instead (RFC 7516 §11.5).
impl From<PlatformKeyError> for Error {
    fn from(e: PlatformKeyError) -> Error {
        match e {
            PlatformKeyError::NotFound => Error::KeyNotFound,
            PlatformKeyError::UserAuthenticationRequired => Error::UserAuthenticationRequired,
            PlatformKeyError::Failed => Error::PlatformKeyFailed,
        }
    }
}

/// The mapping used when **decrypting** (ADR 0071 §4): `NotFound` and
/// `UserAuthenticationRequired` as themselves, `Failed` as
/// [`Error::DecryptionFailed`] (RFC 7516 §11.5).
pub(crate) fn decrypt_error(e: PlatformKeyError) -> Error {
    match e {
        PlatformKeyError::Failed => Error::DecryptionFailed,
        other => Error::from(other),
    }
}

/// Hides every decryption failure as [`Error::DecryptionFailed`]
/// (RFC 7516 §11.4–§11.5) except the two platform-key errors ADR 0071 §4
/// reports as themselves. No JWK path produces those two, so for a JWK
/// this is exactly `|_| DecryptionFailed`.
pub(crate) fn conceal(e: Error) -> Error {
    match e {
        Error::KeyNotFound | Error::UserAuthenticationRequired => e,
        _ => Error::DecryptionFailed,
    }
}

/// Whether `e` ends a multi-recipient decryption at once (ADR 0071 §4:
/// a cancelled prompt is not followed by another prompt).
pub(crate) fn stops_decryption(e: &Error) -> bool {
    matches!(e, Error::KeyNotFound | Error::UserAuthenticationRequired)
}

/// The signing algorithms a platform key may serve (ADR 0071 §2):
/// ES256/384/512 (RFC 7518 §3.4), RS256/384/512 (§3.3), PS256/384/512
/// (§3.5).
pub(crate) fn serves_signing(alg: &SigningAlg) -> bool {
    use SigningAlg as A;
    matches!(
        alg,
        A::ES256
            | A::ES384
            | A::ES512
            | A::RS256
            | A::RS384
            | A::RS512
            | A::PS256
            | A::PS384
            | A::PS512
    )
}

/// The key management algorithms a platform key may serve (ADR 0071 §2):
/// ECDH-ES and ECDH-ES+A128KW/A192KW/A256KW (RFC 7518 §4.6) and
/// RSA-OAEP-256 (RFC 7518 §4.3).
pub(crate) fn serves_key_mgmt(alg: &KeyMgmtAlg) -> bool {
    use KeyMgmtAlg as A;
    matches!(
        alg,
        A::EcdhEs | A::EcdhEsA128KW | A::EcdhEsA192KW | A::EcdhEsA256KW | A::RsaOaep256
    )
}

/// Detail for a public JWK that holds a private member.
const PRIVATE_MEMBER: &str = "a platform key's public JWK must hold public members only";

/// A platform key's public side, read once per call (ADR 0071 §2 item 2).
pub(crate) struct PublicView {
    /// The imported public JWK.
    pub(crate) jwk: Jwk,
    /// [`PlatformKey::algorithms`].
    algorithms: Vec<String>,
}

impl PublicView {
    /// Reads [`PlatformKey::public_jwk`] then [`PlatformKey::algorithms`]
    /// and checks the JWK (ADR 0071 §2 item 2). `failed` is what
    /// [`PlatformKeyError::Failed`] becomes for the operation.
    ///
    /// # Errors
    ///
    /// [`Error::KeyNotFound`] / [`Error::UserAuthenticationRequired`] /
    /// `failed` from the key; every error of [`Jwk::from_json`]
    /// ([`Error::InvalidKey`] for an off-curve point or an RSA modulus
    /// outside 2048..=8192 bits); [`Error::InvalidKey`] for a private
    /// member (`d`, the RSA private members, an `oct` key).
    pub(crate) fn read(key: &dyn PlatformKey, failed: Error) -> Result<PublicView> {
        let map = |e: PlatformKeyError| match e {
            PlatformKeyError::Failed => failed.clone(),
            other => Error::from(other),
        };
        // Wiped on drop: it may hold a private member by mistake.
        let text = Zeroizing::new(key.public_jwk().map_err(map)?);
        // The imported key wipes its own material on drop (`Jwk` is
        // `ZeroizeOnDrop`), so a refused private key leaves no copy.
        let jwk = Jwk::from_json(text.as_bytes())?;
        if !jwk.is_public() {
            return Err(Error::InvalidKey(PRIVATE_MEMBER));
        }
        let algorithms = key.algorithms().map_err(map)?;
        Ok(PublicView { jwk, algorithms })
    }

    /// Whether `name` is in [`PlatformKey::algorithms`].
    fn lists(&self, name: &str) -> bool {
        self.algorithms.iter().any(|a| a == name)
    }

    /// Key binding for signing with `alg` (ADR 0071 §2 item 3; RFC 8725
    /// §3.1): listed, served by the JWK's family by the single table
    /// `KeyMaterial::serves_signing_alg` (ADR 0026 §2 step 8), equal to
    /// the JWK `alg` (RFC 7517 §4.4) and `use` `sig` (RFC 7517 §4.2) when
    /// present.
    ///
    /// # Errors
    ///
    /// [`Error::KeyAlgorithmMismatch`].
    pub(crate) fn bind_signing(&self, alg: &SigningAlg) -> Result<()> {
        let jwk_alg_ok = self
            .jwk
            .alg()
            .is_none_or(|a| matches!(a, KeyAlg::Signing(s) if s == alg));
        let use_ok = self.jwk.key_use().is_none_or(|u| *u == KeyUse::Sig);
        if self.lists(alg.as_str())
            && self.jwk.material().serves_signing_alg(alg)
            && jwk_alg_ok
            && use_ok
        {
            Ok(())
        } else {
            Err(Error::KeyAlgorithmMismatch)
        }
    }

    /// The platform key kind for decrypting with `alg`, after key binding
    /// (ADR 0071 §2 item 3): an X25519 (or other `OKP`) key is
    /// [`Error::UnsupportedAlgorithm`] (ADR 0071 §2: ECDH-ES on P-256,
    /// P-384 and P-521 only); otherwise `alg` must be listed, served by the
    /// JWK's family by the single table `KeyMaterial::serves_key_mgmt_alg`,
    /// equal to the JWK `alg` (RFC 7517 §4.4) and `use` `enc` (RFC 7517
    /// §4.2) when present.
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedAlgorithm`] or [`Error::KeyAlgorithmMismatch`].
    pub(crate) fn bind_key_mgmt(&self, alg: &KeyMgmtAlg) -> Result<DecryptKind> {
        let kind = match self.jwk.material() {
            KeyMaterial::Okp(_) => return Err(Error::UnsupportedAlgorithm),
            KeyMaterial::Ec(ec) => DecryptKind::Ec(ec.crv()),
            KeyMaterial::Rsa(_) => DecryptKind::Rsa,
            KeyMaterial::Oct(_) => return Err(Error::KeyAlgorithmMismatch),
        };
        let jwk_alg_ok = self
            .jwk
            .alg()
            .is_none_or(|a| matches!(a, KeyAlg::KeyMgmt(k) if k == alg));
        let use_ok = self.jwk.key_use().is_none_or(|u| *u == KeyUse::Enc);
        if self.lists(alg.as_str())
            && self.jwk.material().serves_key_mgmt_alg(alg)
            && jwk_alg_ok
            && use_ok
        {
            Ok(kind)
        } else {
            Err(Error::KeyAlgorithmMismatch)
        }
    }
}

/// Prints the type only: the view is public, but nothing about a platform
/// key is printed (ADR 0071 §7).
impl fmt::Debug for PublicView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PublicView(<redacted>)")
    }
}

/// What a bound platform key decrypts with (ADR 0071 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DecryptKind {
    /// ECDH-ES on this curve (RFC 7518 §4.6): P-256, P-384 or P-521.
    Ec(EcCurve),
    /// RSA-OAEP-256 (RFC 7518 §4.3).
    Rsa,
}

/// A platform key for one decrypt call, with its [`PublicView`] read at
/// most once, and only when a recipient first needs it (ADR 0071 §2
/// item 2). Signing reads the view up front instead.
pub(crate) struct Session<'k> {
    /// The key.
    pub(crate) key: &'k dyn PlatformKey,
    /// The view, once read.
    view: Option<Box<PublicView>>,
}

impl<'k> Session<'k> {
    /// A session for decrypting: `Failed` is [`Error::DecryptionFailed`]
    /// (RFC 7516 §11.5).
    pub(crate) fn decrypting(key: &'k dyn PlatformKey) -> Self {
        Session { key, view: None }
    }

    /// The view, reading it on first use.
    ///
    /// # Errors
    ///
    /// As [`PublicView::read`]. A failed read is not cached: the caller
    /// stops at its error.
    pub(crate) fn view(&mut self) -> Result<&PublicView> {
        let view = match self.view.take() {
            Some(view) => view,
            None => Box::new(PublicView::read(self.key, Error::DecryptionFailed)?),
        };
        Ok(self.view.insert(view))
    }
}

/// Prints the type only (ADR 0071 §7).
impl fmt::Debug for Session<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Session(<platform key>)")
    }
}

/// The JWS Signature a platform key produced for `alg` over
/// `signing_input`, checked and in JWS form (ADR 0071 §3).
///
/// - ES\*: the result must be a strict DER `Ecdsa-Sig-Value`; it becomes
///   fixed-width R‖S with low S (RFC 7518 §3.4, ADR 0026 §5).
/// - RS\*/PS\*: the result must be exactly the modulus length (RFC 8017
///   §8.1.1, §8.2.1: the signature is k octets).
/// - Always, then: verified against the view's public JWK with polyjose's
///   own verify (RFC 7515 §5.2 step 8). There is no switch to skip it.
///
/// `verify` is the family verify (`jws::alg::FAMILIES.verify` in
/// production) and `to_fixed` the DER converter of `jws::ecdsa`.
///
/// # Errors
///
/// [`Error::KeyNotFound`] / [`Error::UserAuthenticationRequired`] from the
/// key; [`Error::PlatformKeyFailed`] for `Failed`, a malformed result or
/// one that does not verify.
pub(crate) fn sign_checked(
    alg: &SigningAlg,
    key: &dyn PlatformKey,
    view: &PublicView,
    signing_input: &[u8],
    to_fixed: fn(&SigningAlg, &[u8]) -> Result<Vec<u8>>,
    verify: fn(&SigningAlg, &Jwk, &[u8], &[u8]) -> Result<()>,
) -> Result<Vec<u8>> {
    let produced = key.sign(alg.as_str(), signing_input)?;
    let signature = match view.jwk.material() {
        KeyMaterial::Ec(_) => to_fixed(alg, &produced).map_err(|_| Error::PlatformKeyFailed)?,
        KeyMaterial::Rsa(rsa) if produced.len() == rsa.modulus_bits().div_ceil(8) => produced,
        _ => return Err(Error::PlatformKeyFailed),
    };
    verify(alg, &view.jwk, signing_input, &signature).map_err(|_| Error::PlatformKeyFailed)?;
    Ok(signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MARKER: &str = "pj-SECRET-marker-5e21";

    /// A key whose every answer holds [`MARKER`].
    struct Marked;

    impl PlatformKey for Marked {
        fn public_jwk(&self) -> core::result::Result<String, PlatformKeyError> {
            Ok(format!(
                r#"{{"kty":"EC","crv":"P-256","kid":"{MARKER}","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}}"#
            ))
        }
        fn algorithms(&self) -> core::result::Result<Vec<String>, PlatformKeyError> {
            Ok(vec![MARKER.to_owned()])
        }
        fn sign(&self, _: &str, _: &[u8]) -> core::result::Result<Vec<u8>, PlatformKeyError> {
            Ok(MARKER.as_bytes().to_vec())
        }
        fn agree(&self, _: &[u8]) -> core::result::Result<Zeroizing<Vec<u8>>, PlatformKeyError> {
            Ok(Zeroizing::new(MARKER.as_bytes().to_vec()))
        }
        fn decrypt_key(
            &self,
            _: &str,
            _: &[u8],
        ) -> core::result::Result<Zeroizing<Vec<u8>>, PlatformKeyError> {
            Ok(Zeroizing::new(MARKER.as_bytes().to_vec()))
        }
    }

    #[test]
    fn debug_of_the_internal_types_prints_nothing_of_the_key() {
        // ADR 0071 §7: the type name only.
        let mut session = Session::decrypting(&Marked);
        assert!(!format!("{session:?}").contains(MARKER));
        let view = session.view().unwrap();
        assert_eq!(view.jwk.kid(), Some(MARKER));
        assert_eq!(format!("{view:?}"), "PublicView(<redacted>)");
        assert_eq!(format!("{session:?}"), "Session(<platform key>)");
    }

    #[test]
    fn signing_and_decrypting_map_failed_differently() {
        // ADR 0071 §4, §6; RFC 7516 §11.5.
        use PlatformKeyError as P;
        assert_eq!(Error::from(P::NotFound), Error::KeyNotFound);
        assert_eq!(
            Error::from(P::UserAuthenticationRequired),
            Error::UserAuthenticationRequired
        );
        assert_eq!(Error::from(P::Failed), Error::PlatformKeyFailed);
        assert_eq!(decrypt_error(P::NotFound), Error::KeyNotFound);
        assert_eq!(
            decrypt_error(P::UserAuthenticationRequired),
            Error::UserAuthenticationRequired
        );
        assert_eq!(decrypt_error(P::Failed), Error::DecryptionFailed);
        // `conceal` keeps exactly the two codes and hides everything else.
        for e in [Error::KeyNotFound, Error::UserAuthenticationRequired] {
            assert_eq!(conceal(e.clone()), e);
            assert!(stops_decryption(&e));
        }
        for e in [
            Error::PlatformKeyFailed,
            Error::InvalidKey("x"),
            Error::RandomnessUnavailable,
            Error::KeyAlgorithmMismatch,
        ] {
            assert_eq!(conceal(e.clone()), Error::DecryptionFailed);
            assert!(!stops_decryption(&e));
        }
    }

    #[test]
    fn the_served_algorithm_sets_are_those_of_adr_0071() {
        let signing: Vec<&str> = SigningAlg::KNOWN
            .iter()
            .filter(|a| serves_signing(a))
            .map(SigningAlg::as_str)
            .collect();
        assert_eq!(
            signing,
            [
                "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"
            ]
        );
        let key_mgmt: Vec<&str> = KeyMgmtAlg::KNOWN
            .iter()
            .filter(|a| serves_key_mgmt(a))
            .map(KeyMgmtAlg::as_str)
            .collect();
        assert_eq!(
            key_mgmt,
            [
                "RSA-OAEP-256",
                "ECDH-ES",
                "ECDH-ES+A128KW",
                "ECDH-ES+A192KW",
                "ECDH-ES+A256KW"
            ]
        );
    }
}
