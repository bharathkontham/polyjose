//! The platform key interface (ADR 0071 §5): [`PlatformKey`], a UniFFI foreign trait that Kotlin
//! (`interface PlatformKey`) and Swift (`protocol PlatformKey`) code implements, and the error it
//! throws, [`PlatformKeyError`] (Kotlin `PlatformKeyException`, Swift `PlatformKeyError`).
//!
//! A host object is passed to the six `…_with_platform_key` exports of [`jws`](crate::jws),
//! [`jwe`](crate::jwe) and [`jwt`](crate::jwt). Rust holds a reference to it for the duration of
//! one call only. The adapter wraps it in a `HostKey`, the surface's
//! [`polyjose_surface::platform_key::PlatformKey`], and every check of ADR 0071 §2–§4 then runs
//! in the core around each method call. polyjose treats the implementation as untrusted.
//!
//! **Unexpected host errors.** A method that throws anything other than a `PlatformKeyError`
//! (a Kotlin `IllegalStateException`, a Swift `NSError`) reaches Rust as UniFFI's
//! [`uniffi::UnexpectedUniFFICallbackError`], whose `reason` holds the host exception's text.
//! It becomes [`PlatformKeyError::Failed`] and the text is dropped, never copied into a polyjose
//! message (ADR 0071 §5, ADR 0030 §5). So such a call fails with `PlatformKeyFailed` when signing
//! and `DecryptionFailed` when decrypting, and never panics.
//!
//! # Secrets that cross the boundary (ADR 0071 §8; counted from the uniffi_core 0.32.2 source)
//!
//! The private key never crosses. Three values do, and each leaves Rust-heap copies that polyjose
//! cannot wipe, of the class ADR 0058 §1 measured for byte results. The counts are from the
//! source of uniffi_core 0.32.2 (with bytes 1.12.1), read as ADR 0058 did, for one call of one
//! method; "full" holds the whole value, "partial" a prefix of it:
//!
//! - **The JWS Signing Input, Rust → host** ([`PlatformKey::sign`]; it holds the payload, which
//!   ADR 0030 §7 treats as secret): **2 full copies, plus up to log2(C/8) partial ones.**
//!   - `HostKey` copies the lent `&[u8]` into the owned `Vec<u8>` the foreign trait takes.
//!     The generated method lowers it with `Lower for Vec<T>`: `lower_into_rust_buffer` starts a
//!     `Vec::new()`, writes an `i32` length and then each octet (`put_u8`, which bytes' `BufMut`
//!     makes an `extend_from_slice`), so the buffer grows by amortised doubling from 8 octets, and
//!     every reallocation that moves it frees a block holding a prefix of the input (the partial
//!     copies: at most log2(C/8) growth steps, C the final capacity, the next power of two at or
//!     above n + 4; whether a step moves depends on the allocator, ADR 0058). `for item in obj`
//!     consumes the owned vector, which is freed unwiped after the write: full copy 1.
//!   - The final buffer goes to the host as a `RustBuffer`. The generated Kotlin and Swift lift it
//!     into a `ByteArray` or `Data` and free it with `rustbuffer_free`, which is
//!     `RustBuffer::destroy`, a plain `Vec` drop: full copy 2.
//! - **Z (ECDH, [`PlatformKey::agree`]) and the CEK (RSA-OAEP-256,
//!   [`PlatformKey::decrypt_key`]), host → Rust: 1 full copy each.**
//!   - The host lowers its `ByteArray` or `Data` into a `RustBuffer` that Rust allocated
//!     (`rustbuffer_alloc`, or `rustbuffer_from_bytes`, which copies the host bytes once into a
//!     new `Vec`), exactly sized, with no growth.
//!   - `LiftReturn` lifts it with `Lift for Vec<T>`: `try_lift_from_rust_buffer` takes the buffer
//!     back as a `Vec` (`destroy_into_vec`), reads the octets into a `Vec::with_capacity(len)`
//!     (no growth) and drops the buffer's `Vec` unwiped: the 1 full copy.
//!   - The lifted vector is the value the adapter receives. It is moved, uncopied, into a
//!     [`SecretBytes`] (a `Zeroizing` owner) in the same expression that receives it, the first
//!     statement after the callback returns, and from there into the core's `Zeroizing` buffer
//!     (ADR 0071 §8; `bindings/surface/tests/surface_api.rs` asserts the type).
//! - Not secret: the algorithm name, the public JWK text, the algorithm list, the `epk` point and
//!   the JWE Encrypted Key.
//!
//! The host's own copies come on top (ADR 0030 §7.4): the `ByteArray`/`Data` the host method
//! receives or returns, and in Swift the `[UInt8]` that `lowerIntoRustBuffer` builds. An error
//! thrown by the host carries no secret: a `PlatformKeyError` has no payload, and the `reason` of
//! an unexpected error is the host's own text, which is dropped. The marginal exposure is small:
//! the same call returns the token or the plaintext, which already leaves such copies (ADR 0058).

use std::sync::Arc;

use polyjose_surface::SecretBytes;
use polyjose_surface::platform_key as surface;

/// Why a [`PlatformKey`] could not perform an operation (ADR 0071 §1, §5, §6). Kotlin throws it
/// as `PlatformKeyException` (`NotFound`, `UserAuthenticationRequired`, `Failed`), Swift as
/// `PlatformKeyError` (`.notFound`, `.userAuthenticationRequired`, `.failed`).
///
/// No variant has a payload, so no host text, tag or alias can reach a polyjose error. (It is not
/// a UniFFI `flat_error`: UniFFI cannot lift a flat error from a foreign method.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Error)]
pub enum PlatformKeyError {
    /// No usable key: none under that name, or the platform has permanently invalidated it.
    /// Reported as `KeyNotFound`. Only for a condition that does not depend on the input
    /// (ADR 0071 §4).
    NotFound,
    /// The key needs the user to authenticate, and they have not, cancelled, or cannot. Reported
    /// as `UserAuthenticationRequired`. Only for a condition that does not depend on the input
    /// (ADR 0071 §4).
    UserAuthenticationRequired,
    /// Any other failure, a padding error included. Reported as `PlatformKeyFailed` when signing
    /// and `DecryptionFailed` when decrypting (RFC 7516 §11.5).
    Failed,
}

/// Fixed text per variant (ADR 0030 §5): the error has nothing else to print.
impl core::fmt::Display for PlatformKeyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::NotFound => "platform key not found",
            Self::UserAuthenticationRequired => "user authentication required",
            Self::Failed => "platform key operation failed",
        })
    }
}

impl std::error::Error for PlatformKeyError {}

/// Any other exception a host method throws (ADR 0071 §5). The exception's text, in `reason`,
/// is dropped here and never reaches a polyjose message or printed form.
impl From<uniffi::UnexpectedUniFFICallbackError> for PlatformKeyError {
    fn from(_unexpected: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Failed
    }
}

/// Variant for variant.
impl From<PlatformKeyError> for surface::PlatformKeyError {
    fn from(e: PlatformKeyError) -> Self {
        match e {
            PlatformKeyError::NotFound => Self::NotFound,
            PlatformKeyError::UserAuthenticationRequired => Self::UserAuthenticationRequired,
            PlatformKeyError::Failed => Self::Failed,
        }
    }
}

/// A private key held by the platform, implemented by host code, which performs one private-key
/// step for polyjose and never exports the key (ADR 0070, ADR 0071 §1, §5). Kotlin:
/// `interface PlatformKey`; Swift: `protocol PlatformKey`.
///
/// The contract is the core's `polyjose::PlatformKey`: see its documentation, in particular the
/// error contract of ADR 0071 §4. A method is called at most once per signature or recipient,
/// on the caller's thread, and may block (for example while a system prompt is shown).
#[uniffi::export(foreign)]
pub trait PlatformKey: Send + Sync {
    /// The key's public JWK as JSON text, public members only (RFC 7517 §4; RFC 7518 §6.2.1,
    /// §6.3.1). A private member is `InvalidKey` (ADR 0071 §2).
    fn public_jwk(&self) -> Result<String, PlatformKeyError>;

    /// The JOSE algorithm names the key may be used with, all of its family, for example
    /// `["ES256"]` or `["RSA-OAEP-256"]` (RFC 7518 §3.1, §4.1; RFC 8725 §3.1).
    fn algorithms(&self) -> Result<Vec<String>, PlatformKeyError>;

    /// Signs the JWS Signing Input (RFC 7515 §5.1 step 5) with `alg`, hashing it itself: the
    /// ASN.1 DER `Ecdsa-Sig-Value` for ES256/ES384/ES512 (RFC 3279 §2.2.3), which is what
    /// `java.security.Signature` and `SecKeyCreateSignature` return; the signature octets for
    /// RS\* and PS\* (RFC 7518 §3.3, §3.5). polyjose verifies the result before it is used.
    fn sign(&self, alg: String, signing_input: Vec<u8>) -> Result<Vec<u8>, PlatformKeyError>;

    /// ECDH with the validated JWE `epk`, an uncompressed SEC 1 point `0x04 ‖ X ‖ Y`; returns Z,
    /// the x-coordinate of the shared point: 32, 48 or 66 octets (RFC 7518 §4.6.2).
    fn agree(&self, peer_public_key: Vec<u8>) -> Result<Vec<u8>, PlatformKeyError>;

    /// RSAES-OAEP-256 decryption of the JWE Encrypted Key (RFC 7518 §4.3: SHA-256, MGF1 with
    /// SHA-256, empty label); returns the CEK. Every failure must be `Failed` (RFC 7516 §11.5).
    fn decrypt_key(&self, alg: String, encrypted_key: Vec<u8>)
    -> Result<Vec<u8>, PlatformKeyError>;
}

/// A host [`PlatformKey`] seen as the surface trait, for one call: the conversion every
/// `…_with_platform_key` export makes (ADR 0030 §1). See the module docs for the copies each
/// method leaves (ADR 0071 §8).
pub(crate) struct HostKey(pub(crate) Arc<dyn PlatformKey>);

impl surface::PlatformKey for HostKey {
    fn public_jwk(&self) -> Result<String, surface::PlatformKeyError> {
        Ok(self.0.public_jwk()?)
    }

    fn algorithms(&self) -> Result<Vec<String>, surface::PlatformKeyError> {
        Ok(self.0.algorithms()?)
    }

    fn sign(&self, alg: &str, signing_input: &[u8]) -> Result<Vec<u8>, surface::PlatformKeyError> {
        Ok(self.0.sign(alg.to_owned(), signing_input.to_vec())?)
    }

    fn agree(&self, peer_public_key: &[u8]) -> Result<SecretBytes, surface::PlatformKeyError> {
        // ADR 0071 §8: Z is in a zeroizing owner from the statement that receives it.
        Ok(self
            .0
            .agree(peer_public_key.to_vec())
            .map(SecretBytes::from)?)
    }

    fn decrypt_key(
        &self,
        alg: &str,
        encrypted_key: &[u8],
    ) -> Result<SecretBytes, surface::PlatformKeyError> {
        // ADR 0071 §8: the CEK is in a zeroizing owner from the statement that receives it.
        Ok(self
            .0
            .decrypt_key(alg.to_owned(), encrypted_key.to_vec())
            .map(SecretBytes::from)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MARKER: &str = "host-secret-marker-7f3a";

    #[test]
    fn an_unexpected_host_error_is_failed_and_its_text_is_dropped() {
        let unexpected = uniffi::UnexpectedUniFFICallbackError::new(format!(
            "java.lang.IllegalStateException: {MARKER}"
        ));
        let e = PlatformKeyError::from(unexpected);
        assert_eq!(e, PlatformKeyError::Failed);
        assert!(!format!("{e}").contains(MARKER));
        assert!(!format!("{e:?}").contains(MARKER));
    }

    #[test]
    fn every_error_maps_to_the_surface_variant_of_the_same_name() {
        for (ffi, surface) in [
            (
                PlatformKeyError::NotFound,
                surface::PlatformKeyError::NotFound,
            ),
            (
                PlatformKeyError::UserAuthenticationRequired,
                surface::PlatformKeyError::UserAuthenticationRequired,
            ),
            (PlatformKeyError::Failed, surface::PlatformKeyError::Failed),
        ] {
            assert_eq!(surface::PlatformKeyError::from(ffi), surface);
        }
    }
}
