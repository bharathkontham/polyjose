//! X25519 private-key consistency at JWK import (ADR 0043 §3): a private
//! `OKP` `X25519` JWK's `d` must derive its `x`.
//!
//! RFC 8037 §2 makes `d` "the private key" and `x` "the public key" of one
//! key pair, and RFC 7748 §6.1 defines the public key as X25519(`d`, 9):
//! the X25519 function of the private key and the base point u = 9. A
//! mismatched pair would decrypt as one key while claiming to be another
//! (its thumbprint and `kid` matching are on `x`), so `Jwk::from_object`
//! rejects it with `InvalidKey`, as it does for Ed25519 and EC (ADR 0043
//! §3, amending ADR 0041 §4).
//!
//! The helper lives here, next to the other x25519-dalek code of
//! feature 0003; `jwk.rs` calls it once, from its `OKP` import
//! validation.
//!
//! Only consistency is checked. A public `x` with a torsion component or
//! of low order stays valid (ADR 0043 §2, RFC 7748 §5), so nothing here
//! looks at `x` beyond comparing it.

use subtle::ConstantTimeEq as _;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// The `InvalidKey` detail for an `X25519` private key whose `d` does not
/// derive `x` (ADR 0043 §3). Fixed text: no part of the key (ADR 0007).
pub(crate) const X25519_PRIVATE_MISMATCH: &str = "X25519 private key d does not match x";

/// Whether the 32-octet private key `d` derives the 32-octet public key
/// `x`: `x` = X25519(`d`, 9) (RFC 7748 §6.1; RFC 8037 §2; ADR 0043 §3).
///
/// - x25519-dalek derives the public key (`PublicKey::from(&StaticSecret)`),
///   clamping `d` first (RFC 7748 §5 `decodeScalar25519`), so two `d` that
///   differ only in the clamped bits are the same key.
/// - The derived key is compared with `x` octet for octet, with `subtle`'s
///   constant-time equality, since it is computed from the secret. The
///   derived key is always the canonical encoding (top bit clear, below
///   2^255 − 19), so an `x` that only RFC 7748 §5's input masking would
///   map to it is a mismatch: it is not the public key `d` produces, and it
///   would not have that key's RFC 7638 thumbprint.
/// - A `d` or `x` of any other length is a mismatch (import checks the
///   lengths before calling this, RFC 8037 §2).
///
/// The copy of `d` is a [`Zeroizing`] buffer and the `StaticSecret` wipes
/// itself on drop (the `zeroize` feature of the pinned x25519-dalek).
pub(crate) fn x25519_private_matches(x: &[u8], d: &[u8]) -> bool {
    if x.len() != 32 || d.len() != 32 {
        return false;
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(d);
    let secret = StaticSecret::from(*seed);
    bool::from(PublicKey::from(&secret).as_bytes()[..].ct_eq(x))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

    use super::*;
    use crate::jwa::{ContentEncAlg, KeyMgmtAlg};
    use crate::jwe::key::{Direction, RecipientKey};
    use crate::jwk::Jwk;
    use crate::util::b64url_encode;
    use crate::{Error, Result};

    /// RFC 7748 §6.1, as printed (hex).
    const ALICE_PRIVATE: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    const ALICE_PUBLIC: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    const BOB_PRIVATE: &str = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
    const BOB_PUBLIC: &str = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";

    /// 32 bytes from 64 lowercase hex digits.
    fn hex32(text: &str) -> [u8; 32] {
        assert_eq!(text.len(), 64, "{text:?} is not 32 bytes of hex");
        let mut out = [0u8; 32];
        for (byte, pair) in out.iter_mut().zip(text.as_bytes().chunks(2)) {
            *byte = u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap();
        }
        out
    }

    #[test]
    fn rfc7748_6_1_key_pairs_match() {
        for (d, x) in [(ALICE_PRIVATE, ALICE_PUBLIC), (BOB_PRIVATE, BOB_PUBLIC)] {
            assert!(x25519_private_matches(&hex32(x), &hex32(d)), "{x}");
        }
    }

    #[test]
    fn another_keys_public_key_does_not_match() {
        assert!(!x25519_private_matches(
            &hex32(BOB_PUBLIC),
            &hex32(ALICE_PRIVATE)
        ));
        assert!(!x25519_private_matches(
            &hex32(ALICE_PUBLIC),
            &hex32(BOB_PRIVATE)
        ));
    }

    #[test]
    fn clamped_bits_of_d_are_ignored() {
        // RFC 7748 §5 decodeScalar25519: bits 0–2 cleared, bit 255
        // cleared, bit 254 set.
        let mut d = hex32(ALICE_PRIVATE);
        d[0] ^= 0x07;
        d[31] ^= 0xc0;
        assert!(x25519_private_matches(&hex32(ALICE_PUBLIC), &d));
    }

    #[test]
    fn the_top_bit_of_x_is_compared() {
        // RFC 7748 §5 masks bit 255 of an input u-coordinate, but the
        // derived key never has it set: a different encoding, a mismatch.
        let mut x = hex32(ALICE_PUBLIC);
        x[31] |= 0x80;
        assert!(!x25519_private_matches(&x, &hex32(ALICE_PRIVATE)));
    }

    #[test]
    fn wrong_lengths_do_not_match() {
        let (x, d) = (hex32(ALICE_PUBLIC), hex32(ALICE_PRIVATE));
        assert!(!x25519_private_matches(&x[..31], &d));
        assert!(!x25519_private_matches(&x, &d[..31]));
        assert!(!x25519_private_matches(&[x.as_slice(), &[0]].concat(), &d));
        assert!(!x25519_private_matches(&x, &[d.as_slice(), &[0]].concat()));
        assert!(!x25519_private_matches(&[], &[]));
    }

    /// The secret types this helper relies on wipe themselves.
    #[test]
    fn the_secret_copies_are_wiped_on_drop() {
        fn wiped_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        wiped_on_drop::<StaticSecret>();
        wiped_on_drop::<Zeroizing<[u8; 32]>>();
    }

    /// The JWE recipient key path (0003 T05) binds only imported keys, so
    /// the import check is what keeps a mismatched X25519 pair away from
    /// ECDH-ES decryption: the RFC 7748 §6.1 Bob key binds for decrypt,
    /// the same `x` with Alice's `d` never becomes a `Jwk`.
    #[test]
    fn jwe_recipient_binding_sees_only_consistent_keys() {
        let jwk = |d: &str| -> Result<Jwk> {
            let (x, d) = (b64url_encode(&hex32(BOB_PUBLIC)), b64url_encode(&hex32(d)));
            let json = format!(r#"{{"kty":"OKP","crv":"X25519","x":"{x}","d":"{d}"}}"#);
            Jwk::from_json(json.as_bytes())
        };
        let bob = jwk(BOB_PRIVATE).unwrap();
        let bound = RecipientKey::from_jwk(
            &bob,
            &KeyMgmtAlg::EcdhEs,
            &ContentEncAlg::A128GCM,
            Direction::Decrypt,
        );
        let Ok(RecipientKey::X25519Secret(secret)) = bound else {
            panic!("Bob's private key did not bind for ECDH-ES decrypt");
        };
        assert_eq!(PublicKey::from(&secret).to_bytes(), hex32(BOB_PUBLIC));
        assert_eq!(
            jwk(ALICE_PRIVATE).err(),
            Some(Error::InvalidKey(X25519_PRIVATE_MISMATCH))
        );
    }
}
